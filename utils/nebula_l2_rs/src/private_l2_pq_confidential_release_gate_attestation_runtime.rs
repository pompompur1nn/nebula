use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialReleaseGateAttestationRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str = "private-l2-pq-confidential-release-gate-attestation-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_RELEASE_GATE_ATTESTATION_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "nebula-stable-fnv1a-release-gate-attestation-v1";
pub const PQ_ATTESTATION_SUITE: &str = "ml-dsa-87+slh-dsa-shake-256f-release-gate-attestation-v1";
pub const DEFAULT_CHAIN_ID: &str = "nebula-monero-private-l2-devnet";
pub const DEFAULT_RELEASE_ID: &str = "nebula-l2-pq-private-devnet-release-wave";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_LATENCY_P95_MS: u64 = 250;
pub const DEFAULT_MAX_FEE_BPS: u64 = 30;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_MODULE_LOC: u64 = 1_000;
pub const DEFAULT_MIN_RELEASE_SCORE_BPS: u64 = 7_750;
pub const DEFAULT_REQUIRED_ATTESTERS: u16 = 3;
pub const DEFAULT_REQUIRED_OPERATOR_CATALOG_COPIES: u16 = 2;
pub const DEFAULT_MAX_GATES: usize = 262_144;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 524_288;
pub const DEFAULT_MAX_DECISIONS: usize = 131_072;
pub const DEFAULT_MAX_WORKER_EVIDENCE: usize = 131_072;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReleaseGateDomain {
    QuantumResistance,
    Speed,
    DefiSmartContracts,
    LowFees,
    Privacy,
    MoneroBridge,
    OperatorVisibility,
    WalletDeveloperApi,
    RuntimeReadiness,
}

impl ReleaseGateDomain {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::QuantumResistance => "quantum_resistance",
            Self::Speed => "speed",
            Self::DefiSmartContracts => "defi_smart_contracts",
            Self::LowFees => "low_fees",
            Self::Privacy => "privacy",
            Self::MoneroBridge => "monero_bridge",
            Self::OperatorVisibility => "operator_visibility",
            Self::WalletDeveloperApi => "wallet_developer_api",
            Self::RuntimeReadiness => "runtime_readiness",
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self.as_str())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum GateKind {
    RuntimeModule,
    DevnetState,
    OperatorCatalog,
    PublicRecord,
    PqSecurity,
    PerformanceEnvelope,
    DefiSafety,
    FeeEnvelope,
    PrivacyFloor,
    BridgeRecovery,
    DeferredCheck,
}

impl GateKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RuntimeModule => "runtime_module",
            Self::DevnetState => "devnet_state",
            Self::OperatorCatalog => "operator_catalog",
            Self::PublicRecord => "public_record",
            Self::PqSecurity => "pq_security",
            Self::PerformanceEnvelope => "performance_envelope",
            Self::DefiSafety => "defi_safety",
            Self::FeeEnvelope => "fee_envelope",
            Self::PrivacyFloor => "privacy_floor",
            Self::BridgeRecovery => "bridge_recovery",
            Self::DeferredCheck => "deferred_check",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum GateStatus {
    Drafting,
    Landed,
    Wired,
    DeferredCheck,
    Ready,
    Blocked,
}

impl GateStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Drafting => "drafting",
            Self::Landed => "landed",
            Self::Wired => "wired",
            Self::DeferredCheck => "deferred_check",
            Self::Ready => "ready",
            Self::Blocked => "blocked",
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self.as_str())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttestationStatus {
    Proposed,
    Accepted,
    NeedsRemediation,
    Rejected,
}

impl AttestationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Accepted => "accepted",
            Self::NeedsRemediation => "needs_remediation",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReleaseDecisionStatus {
    Hold,
    DeferredChecks,
    Candidate,
    Ready,
}

impl ReleaseDecisionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hold => "hold",
            Self::DeferredChecks => "deferred_checks",
            Self::Candidate => "candidate",
            Self::Ready => "ready",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RemediationKind {
    AddRuntimeCoverage,
    WireDevnetRoot,
    WireOperatorCatalog,
    IncreasePqMargin,
    ReduceLatency,
    ReduceFee,
    RaisePrivacyFloor,
    RunDeferredChecks,
    ResolveBridgeGap,
}

impl RemediationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AddRuntimeCoverage => "add_runtime_coverage",
            Self::WireDevnetRoot => "wire_devnet_root",
            Self::WireOperatorCatalog => "wire_operator_catalog",
            Self::IncreasePqMargin => "increase_pq_margin",
            Self::ReduceLatency => "reduce_latency",
            Self::ReduceFee => "reduce_fee",
            Self::RaisePrivacyFloor => "raise_privacy_floor",
            Self::RunDeferredChecks => "run_deferred_checks",
            Self::ResolveBridgeGap => "resolve_bridge_gap",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub release_id: String,
    pub min_pq_security_bits: u16,
    pub max_latency_p95_ms: u64,
    pub max_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_module_loc: u64,
    pub min_release_score_bps: u64,
    pub required_attesters: u16,
    pub required_operator_catalog_copies: u16,
    pub max_gates: usize,
    pub max_attestations: usize,
    pub max_decisions: usize,
    pub max_worker_evidence: usize,
    pub required_domains: BTreeSet<ReleaseGateDomain>,
}

impl Config {
    pub fn devnet() -> Self {
        let mut required_domains = BTreeSet::new();
        required_domains.insert(ReleaseGateDomain::QuantumResistance);
        required_domains.insert(ReleaseGateDomain::Speed);
        required_domains.insert(ReleaseGateDomain::DefiSmartContracts);
        required_domains.insert(ReleaseGateDomain::LowFees);
        required_domains.insert(ReleaseGateDomain::Privacy);
        Self {
            chain_id: DEFAULT_CHAIN_ID.to_string(),
            release_id: DEFAULT_RELEASE_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_latency_p95_ms: DEFAULT_MAX_LATENCY_P95_MS,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_module_loc: DEFAULT_MIN_MODULE_LOC,
            min_release_score_bps: DEFAULT_MIN_RELEASE_SCORE_BPS,
            required_attesters: DEFAULT_REQUIRED_ATTESTERS,
            required_operator_catalog_copies: DEFAULT_REQUIRED_OPERATOR_CATALOG_COPIES,
            max_gates: DEFAULT_MAX_GATES,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_decisions: DEFAULT_MAX_DECISIONS,
            max_worker_evidence: DEFAULT_MAX_WORKER_EVIDENCE,
            required_domains,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "release_id": self.release_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_latency_p95_ms": self.max_latency_p95_ms,
            "max_fee_bps": self.max_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_module_loc": self.min_module_loc,
            "min_release_score_bps": self.min_release_score_bps,
            "required_attesters": self.required_attesters,
            "required_operator_catalog_copies": self.required_operator_catalog_copies,
            "max_gates": self.max_gates,
            "max_attestations": self.max_attestations,
            "max_decisions": self.max_decisions,
            "max_worker_evidence": self.max_worker_evidence,
            "required_domains": self.required_domains.iter().map(ReleaseGateDomain::as_str).collect::<Vec<_>>(),
        })
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("release_id", &self.release_id)?;
        require(
            self.min_pq_security_bits >= 128,
            "min_pq_security_bits must be at least 128",
        )?;
        require(self.max_latency_p95_ms > 0, "latency cap must be nonzero")?;
        require(self.max_fee_bps <= MAX_BPS, "fee cap exceeds MAX_BPS")?;
        require(
            self.min_privacy_set_size > 0,
            "privacy set floor must be nonzero",
        )?;
        require(self.min_module_loc > 0, "module LOC floor must be nonzero")?;
        require(
            self.min_release_score_bps <= MAX_BPS,
            "release score exceeds MAX_BPS",
        )?;
        require(
            self.required_attesters > 0,
            "required_attesters must be nonzero",
        )?;
        require(
            self.required_operator_catalog_copies > 0,
            "operator catalog copies must be nonzero",
        )?;
        require(self.max_gates > 0, "max_gates must be nonzero")?;
        require(
            self.max_attestations > 0,
            "max_attestations must be nonzero",
        )?;
        require(self.max_decisions > 0, "max_decisions must be nonzero")?;
        require(
            self.max_worker_evidence > 0,
            "max_worker_evidence must be nonzero",
        )?;
        require(
            !self.required_domains.is_empty(),
            "required_domains must be non-empty",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateInput {
    pub domain: ReleaseGateDomain,
    pub kind: GateKind,
    pub module_name: String,
    pub evidence_root: String,
    pub status: GateStatus,
    pub pq_security_bits: u16,
    pub latency_p95_ms: u64,
    pub fee_bps: u64,
    pub privacy_set_size: u64,
    pub module_loc: u64,
    pub operator_catalog_copies: u16,
    pub deferred_check: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateRecord {
    pub gate_id: String,
    pub domain: ReleaseGateDomain,
    pub kind: GateKind,
    pub module_name: String,
    pub evidence_root: String,
    pub status: GateStatus,
    pub pq_security_bits: u16,
    pub latency_p95_ms: u64,
    pub fee_bps: u64,
    pub privacy_set_size: u64,
    pub module_loc: u64,
    pub operator_catalog_copies: u16,
    pub deferred_check: bool,
    pub score_bps: u64,
    pub remediation_count: u64,
    pub record_root: String,
}

impl GateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "domain": self.domain.as_str(),
            "kind": self.kind.as_str(),
            "module_name": self.module_name,
            "evidence_root": self.evidence_root,
            "status": self.status.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "latency_p95_ms": self.latency_p95_ms,
            "fee_bps": self.fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "module_loc": self.module_loc,
            "operator_catalog_copies": self.operator_catalog_copies,
            "deferred_check": self.deferred_check,
            "score_bps": self.score_bps,
            "remediation_count": self.remediation_count,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationInput {
    pub gate_id: String,
    pub attester_id: String,
    pub attestation_root: String,
    pub pq_signature_root: String,
    pub status: AttestationStatus,
    pub privacy_budget_bps: u64,
    pub disclosure_label: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationRecord {
    pub attestation_id: String,
    pub gate_id: String,
    pub attester_id: String,
    pub attestation_root: String,
    pub pq_signature_root: String,
    pub status: AttestationStatus,
    pub privacy_budget_bps: u64,
    pub disclosure_label: String,
    pub accepted: bool,
    pub record_root: String,
}

impl AttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "gate_id": self.gate_id,
            "attester_id": self.attester_id,
            "attestation_root": self.attestation_root,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str(),
            "privacy_budget_bps": self.privacy_budget_bps,
            "disclosure_label": self.disclosure_label,
            "accepted": self.accepted,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerEvidenceInput {
    pub worker_id: String,
    pub worker_label: String,
    pub owned_file: String,
    pub module_name: String,
    pub loc: u64,
    pub feature_domain: ReleaseGateDomain,
    pub output_root: String,
    pub no_check_policy: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerEvidenceRecord {
    pub evidence_id: String,
    pub worker_id: String,
    pub worker_label: String,
    pub owned_file: String,
    pub module_name: String,
    pub loc: u64,
    pub feature_domain: ReleaseGateDomain,
    pub output_root: String,
    pub no_check_policy: bool,
    pub accepted_for_wave: bool,
    pub record_root: String,
}

impl WorkerEvidenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "worker_id": self.worker_id,
            "worker_label": self.worker_label,
            "owned_file": self.owned_file,
            "module_name": self.module_name,
            "loc": self.loc,
            "feature_domain": self.feature_domain.as_str(),
            "output_root": self.output_root,
            "no_check_policy": self.no_check_policy,
            "accepted_for_wave": self.accepted_for_wave,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemediationRecord {
    pub remediation_id: String,
    pub gate_id: String,
    pub kind: RemediationKind,
    pub severity_bps: u64,
    pub owner: String,
    pub note: String,
    pub resolved: bool,
    pub record_root: String,
}

impl RemediationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "remediation_id": self.remediation_id,
            "gate_id": self.gate_id,
            "kind": self.kind.as_str(),
            "severity_bps": self.severity_bps,
            "owner": self.owner,
            "note": self.note,
            "resolved": self.resolved,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub decision_id: String,
    pub release_id: String,
    pub status: ReleaseDecisionStatus,
    pub score_bps: u64,
    pub required_score_bps: u64,
    pub gate_count: u64,
    pub ready_gate_count: u64,
    pub deferred_gate_count: u64,
    pub remediation_count: u64,
    pub accepted_attestation_count: u64,
    pub worker_wave_loc: u64,
    pub missing_domains: Vec<String>,
    pub state_root: String,
    pub record_root: String,
}

impl DecisionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "decision_id": self.decision_id,
            "release_id": self.release_id,
            "status": self.status.as_str(),
            "score_bps": self.score_bps,
            "required_score_bps": self.required_score_bps,
            "gate_count": self.gate_count,
            "ready_gate_count": self.ready_gate_count,
            "deferred_gate_count": self.deferred_gate_count,
            "remediation_count": self.remediation_count,
            "accepted_attestation_count": self.accepted_attestation_count,
            "worker_wave_loc": self.worker_wave_loc,
            "missing_domains": self.missing_domains,
            "state_root": self.state_root,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub gates: u64,
    pub gates_ready: u64,
    pub gates_deferred: u64,
    pub gates_blocked: u64,
    pub attestations: u64,
    pub accepted_attestations: u64,
    pub remediations: u64,
    pub open_remediations: u64,
    pub worker_evidence: u64,
    pub worker_wave_loc: u64,
    pub decisions: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "gates": self.gates,
            "gates_ready": self.gates_ready,
            "gates_deferred": self.gates_deferred,
            "gates_blocked": self.gates_blocked,
            "attestations": self.attestations,
            "accepted_attestations": self.accepted_attestations,
            "remediations": self.remediations,
            "open_remediations": self.open_remediations,
            "worker_evidence": self.worker_evidence,
            "worker_wave_loc": self.worker_wave_loc,
            "decisions": self.decisions,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub gates_root: String,
    pub attestations_root: String,
    pub remediations_root: String,
    pub worker_evidence_root: String,
    pub decisions_root: String,
    pub counters_root: String,
    pub config_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config) -> Self {
        let config_root = record_root("RELEASE-GATE-CONFIG", &config.public_record());
        let counters_root = record_root(
            "RELEASE-GATE-COUNTERS",
            &Counters::default().public_record(),
        );
        let gates_root = deterministic_id("RELEASE-GATE-GATES-EMPTY", &[]);
        let attestations_root = deterministic_id("RELEASE-GATE-ATTESTATIONS-EMPTY", &[]);
        let remediations_root = deterministic_id("RELEASE-GATE-REMEDIATIONS-EMPTY", &[]);
        let worker_evidence_root = deterministic_id("RELEASE-GATE-WORKER-EVIDENCE-EMPTY", &[]);
        let decisions_root = deterministic_id("RELEASE-GATE-DECISIONS-EMPTY", &[]);
        let state_root = deterministic_id(
            "RELEASE-GATE-STATE",
            &[
                config_root.clone(),
                counters_root.clone(),
                gates_root.clone(),
                attestations_root.clone(),
                remediations_root.clone(),
                worker_evidence_root.clone(),
                decisions_root.clone(),
            ],
        );
        Self {
            gates_root,
            attestations_root,
            remediations_root,
            worker_evidence_root,
            decisions_root,
            counters_root,
            config_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "gates_root": self.gates_root,
            "attestations_root": self.attestations_root,
            "remediations_root": self.remediations_root,
            "worker_evidence_root": self.worker_evidence_root,
            "decisions_root": self.decisions_root,
            "counters_root": self.counters_root,
            "config_root": self.config_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub gates: BTreeMap<String, GateRecord>,
    pub attestations: BTreeMap<String, AttestationRecord>,
    pub remediations: BTreeMap<String, RemediationRecord>,
    pub worker_evidence: BTreeMap<String, WorkerEvidenceRecord>,
    pub decisions: BTreeMap<String, DecisionRecord>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let roots = Roots::empty(&config);
        Ok(Self {
            config,
            gates: BTreeMap::new(),
            attestations: BTreeMap::new(),
            remediations: BTreeMap::new(),
            worker_evidence: BTreeMap::new(),
            decisions: BTreeMap::new(),
            counters: Counters::default(),
            roots,
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).into_state_or_default();
        state.seed_devnet();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let _ = state.add_worker_evidence(WorkerEvidenceInput {
            worker_id: "local-release-gate".to_string(),
            worker_label: "local".to_string(),
            owned_file: "private_l2_pq_confidential_release_gate_attestation_runtime.rs"
                .to_string(),
            module_name: "private_l2_pq_confidential_release_gate_attestation_runtime".to_string(),
            loc: 1_000,
            feature_domain: ReleaseGateDomain::OperatorVisibility,
            output_root: deterministic_id(
                "LOCAL-RELEASE-GATE-OUTPUT",
                &[PROTOCOL_VERSION.to_string()],
            ),
            no_check_policy: true,
        });
        let _ = state.decide_release("demo-release-decision");
        state
    }

    pub fn add_gate(&mut self, input: GateInput) -> Result<String> {
        ensure_capacity("gates", self.gates.len(), self.config.max_gates)?;
        validate_gate_input(&self.config, &input)?;
        let sequence = self.counters.gates.saturating_add(1);
        let gate_id = gate_id(sequence, &input);
        let score_bps = gate_score_bps(&self.config, &input);
        let mut record = GateRecord {
            gate_id: gate_id.clone(),
            domain: input.domain,
            kind: input.kind,
            module_name: input.module_name,
            evidence_root: input.evidence_root,
            status: input.status,
            pq_security_bits: input.pq_security_bits,
            latency_p95_ms: input.latency_p95_ms,
            fee_bps: input.fee_bps,
            privacy_set_size: input.privacy_set_size,
            module_loc: input.module_loc,
            operator_catalog_copies: input.operator_catalog_copies,
            deferred_check: input.deferred_check,
            score_bps,
            remediation_count: 0,
            record_root: String::new(),
        };
        record.record_root = record_root("RELEASE-GATE-RECORD", &record.public_record());
        self.gates.insert(gate_id.clone(), record);
        self.rebuild_counters_and_roots();
        self.open_remediations_for_gate(&gate_id)?;
        self.rebuild_counters_and_roots();
        Ok(gate_id)
    }

    pub fn add_attestation(&mut self, input: AttestationInput) -> Result<String> {
        ensure_capacity(
            "attestations",
            self.attestations.len(),
            self.config.max_attestations,
        )?;
        require(
            self.gates.contains_key(&input.gate_id),
            "attestation gate_id must exist",
        )?;
        require_non_empty("attester_id", &input.attester_id)?;
        require_non_empty("attestation_root", &input.attestation_root)?;
        require_non_empty("pq_signature_root", &input.pq_signature_root)?;
        require(
            input.privacy_budget_bps <= MAX_BPS,
            "privacy budget exceeds MAX_BPS",
        )?;
        let sequence = self.counters.attestations.saturating_add(1);
        let attestation_id = deterministic_id(
            "RELEASE-GATE-ATTESTATION-ID",
            &[
                sequence.to_string(),
                input.gate_id.clone(),
                input.attester_id.clone(),
                input.attestation_root.clone(),
                input.pq_signature_root.clone(),
            ],
        );
        let accepted = input.status == AttestationStatus::Accepted;
        let mut record = AttestationRecord {
            attestation_id: attestation_id.clone(),
            gate_id: input.gate_id,
            attester_id: input.attester_id,
            attestation_root: input.attestation_root,
            pq_signature_root: input.pq_signature_root,
            status: input.status,
            privacy_budget_bps: input.privacy_budget_bps,
            disclosure_label: input.disclosure_label,
            accepted,
            record_root: String::new(),
        };
        record.record_root = record_root("RELEASE-GATE-ATTESTATION", &record.public_record());
        self.attestations.insert(attestation_id.clone(), record);
        self.rebuild_counters_and_roots();
        Ok(attestation_id)
    }

    pub fn add_worker_evidence(&mut self, input: WorkerEvidenceInput) -> Result<String> {
        ensure_capacity(
            "worker_evidence",
            self.worker_evidence.len(),
            self.config.max_worker_evidence,
        )?;
        require_non_empty("worker_id", &input.worker_id)?;
        require_non_empty("worker_label", &input.worker_label)?;
        require_non_empty("owned_file", &input.owned_file)?;
        require_non_empty("module_name", &input.module_name)?;
        require_non_empty("output_root", &input.output_root)?;
        let sequence = self.counters.worker_evidence.saturating_add(1);
        let evidence_id = deterministic_id(
            "RELEASE-GATE-WORKER-EVIDENCE-ID",
            &[
                sequence.to_string(),
                input.worker_id.clone(),
                input.owned_file.clone(),
                input.output_root.clone(),
            ],
        );
        let accepted_for_wave = input.loc >= self.config.min_module_loc && input.no_check_policy;
        let mut record = WorkerEvidenceRecord {
            evidence_id: evidence_id.clone(),
            worker_id: input.worker_id,
            worker_label: input.worker_label,
            owned_file: input.owned_file,
            module_name: input.module_name,
            loc: input.loc,
            feature_domain: input.feature_domain,
            output_root: input.output_root,
            no_check_policy: input.no_check_policy,
            accepted_for_wave,
            record_root: String::new(),
        };
        record.record_root = record_root("RELEASE-GATE-WORKER-EVIDENCE", &record.public_record());
        self.worker_evidence.insert(evidence_id.clone(), record);
        self.rebuild_counters_and_roots();
        Ok(evidence_id)
    }

    pub fn decide_release(&mut self, decision_label: &str) -> Result<String> {
        require_non_empty("decision_label", decision_label)?;
        ensure_capacity("decisions", self.decisions.len(), self.config.max_decisions)?;
        let missing_domains = self.missing_required_domains();
        let gate_count = self.gates.len() as u64;
        let ready_gate_count = self
            .gates
            .values()
            .filter(|gate| gate.status == GateStatus::Ready || gate.status == GateStatus::Wired)
            .count() as u64;
        let deferred_gate_count = self
            .gates
            .values()
            .filter(|gate| gate.deferred_check || gate.status == GateStatus::DeferredCheck)
            .count() as u64;
        let score_bps = self.release_score_bps();
        let accepted_attestation_count = self
            .attestations
            .values()
            .filter(|attestation| attestation.accepted)
            .count() as u64;
        let remediation_count = self
            .remediations
            .values()
            .filter(|remediation| !remediation.resolved)
            .count() as u64;
        let worker_wave_loc = self
            .worker_evidence
            .values()
            .filter(|evidence| evidence.accepted_for_wave)
            .fold(0_u64, |acc, evidence| acc.saturating_add(evidence.loc));
        let status = if !missing_domains.is_empty() || remediation_count > 0 {
            ReleaseDecisionStatus::Hold
        } else if deferred_gate_count > 0 {
            ReleaseDecisionStatus::DeferredChecks
        } else if score_bps >= self.config.min_release_score_bps
            && accepted_attestation_count >= u64::from(self.config.required_attesters)
        {
            ReleaseDecisionStatus::Ready
        } else {
            ReleaseDecisionStatus::Candidate
        };
        let sequence = self.counters.decisions.saturating_add(1);
        let decision_id = deterministic_id(
            "RELEASE-GATE-DECISION-ID",
            &[
                sequence.to_string(),
                decision_label.to_string(),
                self.roots.state_root.clone(),
                score_bps.to_string(),
            ],
        );
        let mut decision = DecisionRecord {
            decision_id: decision_id.clone(),
            release_id: self.config.release_id.clone(),
            status,
            score_bps,
            required_score_bps: self.config.min_release_score_bps,
            gate_count,
            ready_gate_count,
            deferred_gate_count,
            remediation_count,
            accepted_attestation_count,
            worker_wave_loc,
            missing_domains,
            state_root: self.roots.state_root.clone(),
            record_root: String::new(),
        };
        decision.record_root = record_root("RELEASE-GATE-DECISION", &decision.public_record());
        self.decisions.insert(decision_id.clone(), decision);
        self.rebuild_counters_and_roots();
        Ok(decision_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_attestation_suite": PQ_ATTESTATION_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "gates": self.gates.values().map(GateRecord::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(AttestationRecord::public_record).collect::<Vec<_>>(),
            "remediations": self.remediations.values().map(RemediationRecord::public_record).collect::<Vec<_>>(),
            "worker_evidence": self.worker_evidence.values().map(WorkerEvidenceRecord::public_record).collect::<Vec<_>>(),
            "decisions": self.decisions.values().map(DecisionRecord::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        require(self.gates.len() <= self.config.max_gates, "too many gates")?;
        require(
            self.attestations.len() <= self.config.max_attestations,
            "too many attestations",
        )?;
        require(
            self.worker_evidence.len() <= self.config.max_worker_evidence,
            "too much worker evidence",
        )?;
        for gate in self.gates.values() {
            require_non_empty("gate_id", &gate.gate_id)?;
            require_non_empty("gate_evidence_root", &gate.evidence_root)?;
            require(
                gate.score_bps <= MAX_BPS,
                "gate score must not exceed MAX_BPS",
            )?;
        }
        for attestation in self.attestations.values() {
            require(
                self.gates.contains_key(&attestation.gate_id),
                "attestation references missing gate",
            )?;
            require_non_empty("attestation_id", &attestation.attestation_id)?;
            require_non_empty("pq_signature_root", &attestation.pq_signature_root)?;
        }
        for remediation in self.remediations.values() {
            require(
                self.gates.contains_key(&remediation.gate_id),
                "remediation references missing gate",
            )?;
            require(
                remediation.severity_bps <= MAX_BPS,
                "remediation severity exceeds MAX_BPS",
            )?;
        }
        Ok(())
    }

    fn seed_devnet(&mut self) {
        let gates = vec![
            GateInput {
                domain: ReleaseGateDomain::QuantumResistance,
                kind: GateKind::PqSecurity,
                module_name: "private_l2_pq_confidential_pq_key_rotation_migration_runtime"
                    .to_string(),
                evidence_root: deterministic_id(
                    "DEVNET-PQ-KEY-ROTATION",
                    &[PROTOCOL_VERSION.to_string()],
                ),
                status: GateStatus::Wired,
                pq_security_bits: 256,
                latency_p95_ms: 180,
                fee_bps: 12,
                privacy_set_size: 65_536,
                module_loc: 2_107,
                operator_catalog_copies: 2,
                deferred_check: true,
            },
            GateInput {
                domain: ReleaseGateDomain::Speed,
                kind: GateKind::PerformanceEnvelope,
                module_name: "private_l2_fast_pq_confidential_execution_load_shedding_runtime"
                    .to_string(),
                evidence_root: deterministic_id(
                    "DEVNET-FAST-LOAD-SHEDDING",
                    &[PROTOCOL_VERSION.to_string()],
                ),
                status: GateStatus::Wired,
                pq_security_bits: 256,
                latency_p95_ms: 140,
                fee_bps: 10,
                privacy_set_size: 65_536,
                module_loc: 2_835,
                operator_catalog_copies: 2,
                deferred_check: true,
            },
            GateInput {
                domain: ReleaseGateDomain::DefiSmartContracts,
                kind: GateKind::DefiSafety,
                module_name: "private_l2_pq_confidential_token_contract_governance_audit_runtime"
                    .to_string(),
                evidence_root: deterministic_id(
                    "DEVNET-TOKEN-GOVERNANCE-AUDIT",
                    &[PROTOCOL_VERSION.to_string()],
                ),
                status: GateStatus::Wired,
                pq_security_bits: 256,
                latency_p95_ms: 210,
                fee_bps: 18,
                privacy_set_size: 65_536,
                module_loc: 2_722,
                operator_catalog_copies: 2,
                deferred_check: true,
            },
            GateInput {
                domain: ReleaseGateDomain::LowFees,
                kind: GateKind::FeeEnvelope,
                module_name: "private_l2_low_fee_pq_confidential_fee_derivative_hedging_runtime"
                    .to_string(),
                evidence_root: deterministic_id(
                    "DEVNET-FEE-HEDGE",
                    &[PROTOCOL_VERSION.to_string()],
                ),
                status: GateStatus::Wired,
                pq_security_bits: 256,
                latency_p95_ms: 220,
                fee_bps: 8,
                privacy_set_size: 65_536,
                module_loc: 1_881,
                operator_catalog_copies: 2,
                deferred_check: true,
            },
            GateInput {
                domain: ReleaseGateDomain::Privacy,
                kind: GateKind::PrivacyFloor,
                module_name: "monero_l2_pq_private_viewkey_recovery_rotation_runtime".to_string(),
                evidence_root: deterministic_id(
                    "DEVNET-VIEWKEY-RECOVERY",
                    &[PROTOCOL_VERSION.to_string()],
                ),
                status: GateStatus::Wired,
                pq_security_bits: 256,
                latency_p95_ms: 230,
                fee_bps: 13,
                privacy_set_size: 131_072,
                module_loc: 3_274,
                operator_catalog_copies: 2,
                deferred_check: true,
            },
        ];
        for gate in gates {
            let _ = self.add_gate(gate);
        }
        let gate_ids = self.gates.keys().cloned().collect::<Vec<_>>();
        for gate_id in gate_ids {
            let _ = self.add_attestation(AttestationInput {
                gate_id,
                attester_id: "operator-progress-panel".to_string(),
                attestation_root: deterministic_id(
                    "DEVNET-PANEL-ATTESTATION",
                    &[PROTOCOL_VERSION.to_string()],
                ),
                pq_signature_root: deterministic_id(
                    "DEVNET-PANEL-PQ-SIGNATURE",
                    &[PQ_ATTESTATION_SUITE.to_string()],
                ),
                status: AttestationStatus::Accepted,
                privacy_budget_bps: 50,
                disclosure_label: "public-progress-summary".to_string(),
            });
        }
    }

    fn open_remediations_for_gate(&mut self, gate_id: &str) -> Result<()> {
        let gate = match self.gates.get(gate_id) {
            Some(gate) => gate.clone(),
            None => return Ok(()),
        };
        let mut findings = Vec::new();
        if gate.module_loc < self.config.min_module_loc {
            findings.push((
                RemediationKind::AddRuntimeCoverage,
                1_500,
                "module LOC below release floor",
            ));
        }
        if gate.operator_catalog_copies < self.config.required_operator_catalog_copies {
            findings.push((
                RemediationKind::WireOperatorCatalog,
                1_000,
                "operator catalog copies missing",
            ));
        }
        if gate.pq_security_bits < self.config.min_pq_security_bits {
            findings.push((
                RemediationKind::IncreasePqMargin,
                2_500,
                "PQ security margin below release floor",
            ));
        }
        if gate.latency_p95_ms > self.config.max_latency_p95_ms {
            findings.push((
                RemediationKind::ReduceLatency,
                1_500,
                "latency envelope above release cap",
            ));
        }
        if gate.fee_bps > self.config.max_fee_bps {
            findings.push((
                RemediationKind::ReduceFee,
                1_500,
                "fee envelope above release cap",
            ));
        }
        if gate.privacy_set_size < self.config.min_privacy_set_size {
            findings.push((
                RemediationKind::RaisePrivacyFloor,
                2_000,
                "privacy set below release floor",
            ));
        }
        if gate.deferred_check {
            findings.push((
                RemediationKind::RunDeferredChecks,
                500,
                "compile/fmt/test gates intentionally deferred",
            ));
        }
        for (kind, severity_bps, note) in findings {
            ensure_capacity(
                "remediations",
                self.remediations.len(),
                self.config.max_gates,
            )?;
            let sequence = self.counters.remediations.saturating_add(1);
            let remediation_id = deterministic_id(
                "RELEASE-GATE-REMEDIATION-ID",
                &[
                    sequence.to_string(),
                    gate_id.to_string(),
                    kind.as_str().to_string(),
                    note.to_string(),
                ],
            );
            let mut record = RemediationRecord {
                remediation_id: remediation_id.clone(),
                gate_id: gate_id.to_string(),
                kind,
                severity_bps,
                owner: gate.module_name.clone(),
                note: note.to_string(),
                resolved: false,
                record_root: String::new(),
            };
            record.record_root = record_root("RELEASE-GATE-REMEDIATION", &record.public_record());
            self.remediations.insert(remediation_id, record);
        }
        if let Some(updated_gate) = self.gates.get_mut(gate_id) {
            updated_gate.remediation_count = self
                .remediations
                .values()
                .filter(|remediation| remediation.gate_id == gate_id && !remediation.resolved)
                .count() as u64;
            updated_gate.record_root =
                record_root("RELEASE-GATE-RECORD", &updated_gate.public_record());
        }
        Ok(())
    }

    fn missing_required_domains(&self) -> Vec<String> {
        let mut covered = BTreeSet::new();
        for gate in self.gates.values() {
            if gate.status != GateStatus::Blocked {
                covered.insert(gate.domain.clone());
            }
        }
        self.config
            .required_domains
            .iter()
            .filter(|domain| !covered.contains(*domain))
            .map(|domain| domain.as_str().to_string())
            .collect()
    }

    fn release_score_bps(&self) -> u64 {
        if self.gates.is_empty() {
            return 0;
        }
        let total = self
            .gates
            .values()
            .fold(0_u64, |acc, gate| acc.saturating_add(gate.score_bps));
        let average = total / self.gates.len() as u64;
        let attestation_bonus = self
            .attestations
            .values()
            .filter(|attestation| attestation.accepted)
            .count() as u64
            * 50;
        let open_remediation_penalty = self
            .remediations
            .values()
            .filter(|remediation| !remediation.resolved)
            .fold(0_u64, |acc, remediation| {
                acc.saturating_add(remediation.severity_bps / 10)
            });
        average
            .saturating_add(attestation_bonus)
            .saturating_sub(open_remediation_penalty)
            .min(MAX_BPS)
    }

    fn rebuild_counters_and_roots(&mut self) {
        self.counters.gates = self.gates.len() as u64;
        self.counters.gates_ready = self
            .gates
            .values()
            .filter(|gate| gate.status == GateStatus::Ready || gate.status == GateStatus::Wired)
            .count() as u64;
        self.counters.gates_deferred = self
            .gates
            .values()
            .filter(|gate| gate.deferred_check || gate.status == GateStatus::DeferredCheck)
            .count() as u64;
        self.counters.gates_blocked = self
            .gates
            .values()
            .filter(|gate| gate.status == GateStatus::Blocked)
            .count() as u64;
        self.counters.attestations = self.attestations.len() as u64;
        self.counters.accepted_attestations = self
            .attestations
            .values()
            .filter(|attestation| attestation.accepted)
            .count() as u64;
        self.counters.remediations = self.remediations.len() as u64;
        self.counters.open_remediations = self
            .remediations
            .values()
            .filter(|remediation| !remediation.resolved)
            .count() as u64;
        self.counters.worker_evidence = self.worker_evidence.len() as u64;
        self.counters.worker_wave_loc = self
            .worker_evidence
            .values()
            .filter(|evidence| evidence.accepted_for_wave)
            .fold(0_u64, |acc, evidence| acc.saturating_add(evidence.loc));
        self.counters.decisions = self.decisions.len() as u64;

        self.roots.config_root = record_root("RELEASE-GATE-CONFIG", &self.config.public_record());
        self.roots.counters_root =
            record_root("RELEASE-GATE-COUNTERS", &self.counters.public_record());
        self.roots.gates_root =
            map_root("RELEASE-GATE-GATES", &self.gates, GateRecord::public_record);
        self.roots.attestations_root = map_root(
            "RELEASE-GATE-ATTESTATIONS",
            &self.attestations,
            AttestationRecord::public_record,
        );
        self.roots.remediations_root = map_root(
            "RELEASE-GATE-REMEDIATIONS",
            &self.remediations,
            RemediationRecord::public_record,
        );
        self.roots.worker_evidence_root = map_root(
            "RELEASE-GATE-WORKER-EVIDENCE",
            &self.worker_evidence,
            WorkerEvidenceRecord::public_record,
        );
        self.roots.decisions_root = map_root(
            "RELEASE-GATE-DECISIONS",
            &self.decisions,
            DecisionRecord::public_record,
        );
        self.roots.state_root = deterministic_id(
            "RELEASE-GATE-STATE",
            &[
                self.roots.config_root.clone(),
                self.roots.counters_root.clone(),
                self.roots.gates_root.clone(),
                self.roots.attestations_root.clone(),
                self.roots.remediations_root.clone(),
                self.roots.worker_evidence_root.clone(),
                self.roots.decisions_root.clone(),
            ],
        );
    }
}

trait StateFallback {
    fn into_state_or_default(self) -> State;
}

impl StateFallback for Result<State> {
    fn into_state_or_default(self) -> State {
        match self {
            Ok(state) => state,
            Err(_) => State {
                config: Config::devnet(),
                gates: BTreeMap::new(),
                attestations: BTreeMap::new(),
                remediations: BTreeMap::new(),
                worker_evidence: BTreeMap::new(),
                decisions: BTreeMap::new(),
                counters: Counters::default(),
                roots: Roots::empty(&Config::devnet()),
            },
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn gate_id(sequence: u64, input: &GateInput) -> String {
    deterministic_id(
        "RELEASE-GATE-ID",
        &[
            sequence.to_string(),
            input.domain.as_str().to_string(),
            input.kind.as_str().to_string(),
            input.module_name.clone(),
            input.evidence_root.clone(),
        ],
    )
}

pub fn gate_score_bps(config: &Config, input: &GateInput) -> u64 {
    let mut score = 0_u64;
    if input.pq_security_bits >= config.min_pq_security_bits {
        score = score.saturating_add(2_000);
    }
    if input.latency_p95_ms <= config.max_latency_p95_ms {
        score = score.saturating_add(1_500);
    }
    if input.fee_bps <= config.max_fee_bps {
        score = score.saturating_add(1_500);
    }
    if input.privacy_set_size >= config.min_privacy_set_size {
        score = score.saturating_add(1_500);
    }
    if input.module_loc >= config.min_module_loc {
        score = score.saturating_add(1_000);
    }
    if input.operator_catalog_copies >= config.required_operator_catalog_copies {
        score = score.saturating_add(1_000);
    }
    if matches!(input.status, GateStatus::Ready | GateStatus::Wired) {
        score = score.saturating_add(1_000);
    }
    if input.deferred_check {
        score = score.saturating_sub(500);
    }
    score.min(MAX_BPS)
}

pub fn validate_gate_input(config: &Config, input: &GateInput) -> Result<()> {
    require_non_empty("module_name", &input.module_name)?;
    require_non_empty("evidence_root", &input.evidence_root)?;
    require(
        input.pq_security_bits >= 128,
        "gate pq security below minimum supported floor",
    )?;
    require(input.fee_bps <= MAX_BPS, "fee_bps exceeds MAX_BPS")?;
    require(
        input.operator_catalog_copies <= 16,
        "operator catalog copy count is above release policy",
    )?;
    if input.domain == ReleaseGateDomain::QuantumResistance {
        require(
            input.pq_security_bits >= config.min_pq_security_bits,
            "quantum gate must meet configured PQ floor",
        )?;
    }
    Ok(())
}

pub fn record_root(domain: &str, record: &Value) -> String {
    deterministic_id(domain, &[record.to_string()])
}

pub fn map_root<T>(
    domain: &str,
    records: &BTreeMap<String, T>,
    public_record: impl Fn(&T) -> Value,
) -> String {
    let mut parts = Vec::new();
    for (key, value) in records {
        parts.push(key.clone());
        parts.push(public_record(value).to_string());
    }
    deterministic_id(domain, &parts)
}

pub fn deterministic_id(domain: &str, parts: &[String]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    mix_bytes(&mut hash, domain.as_bytes());
    for part in parts {
        mix_bytes(&mut hash, &[0xff]);
        mix_bytes(&mut hash, part.as_bytes());
    }
    format!("{domain}-{:016x}", hash)
}

fn mix_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x100000001b3);
    }
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    require(
        !value.trim().is_empty(),
        &format!("{label} must be non-empty"),
    )
}

fn ensure_capacity(label: &str, len: usize, max: usize) -> Result<()> {
    require(len < max, &format!("{label} capacity reached"))
}
