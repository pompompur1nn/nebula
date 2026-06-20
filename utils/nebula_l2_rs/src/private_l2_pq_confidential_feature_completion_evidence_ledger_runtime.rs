use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialFeatureCompletionEvidenceLedgerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "private-l2-pq-confidential-feature-completion-evidence-ledger-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_FEATURE_COMPLETION_EVIDENCE_LEDGER_RUNTIME_PROTOCOL_VERSION:
    &str = PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "nebula-stable-fnv1a-domain-json-v1";
pub const PQ_EVIDENCE_SUITE: &str = "ml-dsa-87+slh-dsa-shake-256f-feature-evidence-v1";
pub const DEFAULT_CHAIN_ID: &str = "nebula-monero-private-l2-devnet";
pub const DEFAULT_RELEASE_GATE_ID: &str = "pq-private-l2-feature-completion-release-gate";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_TARGET_LATENCY_MS: u64 = 250;
pub const DEFAULT_MAX_FEE_BPS: u64 = 30;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_REQUIRED_SCORE_BPS: u64 = 7_500;
pub const DEFAULT_REQUIRED_LOC_WAVE: u64 = 100_000;
pub const DEFAULT_MAX_EVIDENCE_ITEMS: usize = 1_048_576;
pub const DEFAULT_MAX_WORKER_WAVES: usize = 16_384;
pub const DEFAULT_MAX_REMEDIATIONS: usize = 262_144;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FeaturePriority {
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

impl FeaturePriority {
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
pub enum EvidenceKind {
    RuntimeModule,
    DevnetRoot,
    OperatorCatalog,
    PublicRecord,
    WorkerWave,
    ReleaseGate,
    Remediation,
}

impl EvidenceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RuntimeModule => "runtime_module",
            Self::DevnetRoot => "devnet_root",
            Self::OperatorCatalog => "operator_catalog",
            Self::PublicRecord => "public_record",
            Self::WorkerWave => "worker_wave",
            Self::ReleaseGate => "release_gate",
            Self::Remediation => "remediation",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum GateStatus {
    Missing,
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
            Self::Missing => "missing",
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub release_gate_id: String,
    pub min_pq_security_bits: u16,
    pub target_latency_ms: u64,
    pub max_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub required_score_bps: u64,
    pub required_loc_wave: u64,
    pub max_evidence_items: usize,
    pub max_worker_waves: usize,
    pub max_remediations: usize,
    pub required_priorities: BTreeSet<FeaturePriority>,
}

impl Config {
    pub fn devnet() -> Self {
        let mut required_priorities = BTreeSet::new();
        required_priorities.insert(FeaturePriority::QuantumResistance);
        required_priorities.insert(FeaturePriority::Speed);
        required_priorities.insert(FeaturePriority::DefiSmartContracts);
        required_priorities.insert(FeaturePriority::LowFees);
        required_priorities.insert(FeaturePriority::Privacy);
        Self {
            chain_id: DEFAULT_CHAIN_ID.to_string(),
            release_gate_id: DEFAULT_RELEASE_GATE_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_latency_ms: DEFAULT_TARGET_LATENCY_MS,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            required_score_bps: DEFAULT_REQUIRED_SCORE_BPS,
            required_loc_wave: DEFAULT_REQUIRED_LOC_WAVE,
            max_evidence_items: DEFAULT_MAX_EVIDENCE_ITEMS,
            max_worker_waves: DEFAULT_MAX_WORKER_WAVES,
            max_remediations: DEFAULT_MAX_REMEDIATIONS,
            required_priorities,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "release_gate_id": self.release_gate_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_latency_ms": self.target_latency_ms,
            "max_fee_bps": self.max_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "required_score_bps": self.required_score_bps,
            "required_loc_wave": self.required_loc_wave,
            "max_evidence_items": self.max_evidence_items,
            "max_worker_waves": self.max_worker_waves,
            "max_remediations": self.max_remediations,
            "required_priorities": self.required_priorities.iter().map(FeaturePriority::as_str).collect::<Vec<_>>(),
        })
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("release_gate_id", &self.release_gate_id)?;
        require(
            self.min_pq_security_bits >= 128,
            "min_pq_security_bits must be at least 128",
        )?;
        require(self.target_latency_ms > 0, "target latency must be nonzero")?;
        require(self.max_fee_bps <= MAX_BPS, "max fee bps above MAX_BPS")?;
        require(
            self.required_score_bps <= MAX_BPS,
            "required score bps above MAX_BPS",
        )?;
        require(
            self.min_privacy_set_size > 0,
            "min privacy set size must be nonzero",
        )?;
        require(
            !self.required_priorities.is_empty(),
            "required priority set must be non-empty",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub evidence_items: u64,
    pub worker_waves: u64,
    pub criteria: u64,
    pub remediations: u64,
    pub wired_items: u64,
    pub deferred_checks: u64,
    pub ready_gates: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_items": self.evidence_items,
            "worker_waves": self.worker_waves,
            "criteria": self.criteria,
            "remediations": self.remediations,
            "wired_items": self.wired_items,
            "deferred_checks": self.deferred_checks,
            "ready_gates": self.ready_gates,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub evidence_root: String,
    pub priority_root: String,
    pub worker_wave_root: String,
    pub criterion_root: String,
    pub remediation_root: String,
    pub counter_root: String,
    pub score_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "evidence_root": self.evidence_root,
            "priority_root": self.priority_root,
            "worker_wave_root": self.worker_wave_root,
            "criterion_root": self.criterion_root,
            "remediation_root": self.remediation_root,
            "counter_root": self.counter_root,
            "score_root": self.score_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeatureEvidenceInput {
    pub priority: FeaturePriority,
    pub kind: EvidenceKind,
    pub domain: String,
    pub module_name: String,
    pub state_root: String,
    pub status: GateStatus,
    pub score_delta_bps: u64,
    pub pq_security_bits: u16,
    pub latency_ms: u64,
    pub fee_bps: u64,
    pub privacy_set_size: u64,
    pub smart_contract_surface: bool,
    pub landed_loc: u64,
    pub note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeatureEvidence {
    pub evidence_id: String,
    pub priority: FeaturePriority,
    pub kind: EvidenceKind,
    pub domain: String,
    pub module_name: String,
    pub state_root: String,
    pub status: GateStatus,
    pub score_delta_bps: u64,
    pub pq_security_bits: u16,
    pub latency_ms: u64,
    pub fee_bps: u64,
    pub privacy_set_size: u64,
    pub smart_contract_surface: bool,
    pub landed_loc: u64,
    pub note: String,
}

impl FeatureEvidence {
    pub fn from_input(sequence: u64, input: FeatureEvidenceInput) -> Result<Self> {
        require_non_empty("domain", &input.domain)?;
        require_non_empty("module_name", &input.module_name)?;
        require_non_empty("state_root", &input.state_root)?;
        require(input.score_delta_bps <= MAX_BPS, "score_delta_bps too high")?;
        require(input.fee_bps <= MAX_BPS, "fee_bps too high")?;
        let evidence_id = feature_evidence_id(sequence, &input);
        Ok(Self {
            evidence_id,
            priority: input.priority,
            kind: input.kind,
            domain: input.domain,
            module_name: input.module_name,
            state_root: input.state_root,
            status: input.status,
            score_delta_bps: input.score_delta_bps,
            pq_security_bits: input.pq_security_bits,
            latency_ms: input.latency_ms,
            fee_bps: input.fee_bps,
            privacy_set_size: input.privacy_set_size,
            smart_contract_surface: input.smart_contract_surface,
            landed_loc: input.landed_loc,
            note: input.note,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "priority": self.priority.as_str(),
            "kind": self.kind.as_str(),
            "domain": self.domain,
            "module_name": self.module_name,
            "state_root": self.state_root,
            "status": self.status.as_str(),
            "score_delta_bps": self.score_delta_bps,
            "pq_security_bits": self.pq_security_bits,
            "latency_ms": self.latency_ms,
            "fee_bps": self.fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "smart_contract_surface": self.smart_contract_surface,
            "landed_loc": self.landed_loc,
            "note": self.note,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerWaveRecord {
    pub wave_id: String,
    pub label: String,
    pub worker_count: u64,
    pub landed_loc: u64,
    pub target_loc: u64,
    pub checks_deferred: bool,
    pub owned_files: Vec<String>,
    pub priority_roots: BTreeMap<FeaturePriority, String>,
}

impl WorkerWaveRecord {
    pub fn new(
        sequence: u64,
        label: impl Into<String>,
        worker_count: u64,
        landed_loc: u64,
        target_loc: u64,
        checks_deferred: bool,
        owned_files: Vec<String>,
        priority_roots: BTreeMap<FeaturePriority, String>,
    ) -> Result<Self> {
        let label = label.into();
        require_non_empty("wave label", &label)?;
        require(worker_count > 0, "worker_count must be nonzero")?;
        require(target_loc > 0, "target_loc must be nonzero")?;
        for file in &owned_files {
            require_non_empty("owned file", file)?;
        }
        let wave_id = deterministic_id(
            "FEATURE-EVIDENCE-WORKER-WAVE",
            &[
                sequence.to_string(),
                label.clone(),
                worker_count.to_string(),
                landed_loc.to_string(),
                target_loc.to_string(),
            ],
        );
        Ok(Self {
            wave_id,
            label,
            worker_count,
            landed_loc,
            target_loc,
            checks_deferred,
            owned_files,
            priority_roots,
        })
    }

    pub fn public_record(&self) -> Value {
        let priority_roots = self
            .priority_roots
            .iter()
            .map(|(priority, root)| json!({"priority": priority.as_str(), "root": root}))
            .collect::<Vec<_>>();
        json!({
            "wave_id": self.wave_id,
            "label": self.label,
            "worker_count": self.worker_count,
            "landed_loc": self.landed_loc,
            "target_loc": self.target_loc,
            "checks_deferred": self.checks_deferred,
            "owned_files": self.owned_files,
            "priority_roots": priority_roots,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateCriterion {
    pub criterion_id: String,
    pub priority: FeaturePriority,
    pub label: String,
    pub target_bps: u64,
    pub current_bps: u64,
    pub status: GateStatus,
    pub evidence_root: String,
}

impl GateCriterion {
    pub fn public_record(&self) -> Value {
        json!({
            "criterion_id": self.criterion_id,
            "priority": self.priority.as_str(),
            "label": self.label,
            "target_bps": self.target_bps,
            "current_bps": self.current_bps,
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemediationAction {
    pub remediation_id: String,
    pub priority: FeaturePriority,
    pub label: String,
    pub status: GateStatus,
    pub blocking_root: String,
    pub owner_hint: String,
    pub note: String,
}

impl RemediationAction {
    pub fn new(
        sequence: u64,
        priority: FeaturePriority,
        label: impl Into<String>,
        status: GateStatus,
        blocking_root: impl Into<String>,
        owner_hint: impl Into<String>,
        note: impl Into<String>,
    ) -> Result<Self> {
        let label = label.into();
        let blocking_root = blocking_root.into();
        let owner_hint = owner_hint.into();
        let note = note.into();
        require_non_empty("remediation label", &label)?;
        require_non_empty("blocking root", &blocking_root)?;
        let remediation_id = deterministic_id(
            "FEATURE-EVIDENCE-REMEDIATION",
            &[
                sequence.to_string(),
                priority.as_str().to_string(),
                label.clone(),
                blocking_root.clone(),
            ],
        );
        Ok(Self {
            remediation_id,
            priority,
            label,
            status,
            blocking_root,
            owner_hint,
            note,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "remediation_id": self.remediation_id,
            "priority": self.priority.as_str(),
            "label": self.label,
            "status": self.status.as_str(),
            "blocking_root": self.blocking_root,
            "owner_hint": self.owner_hint,
            "note": self.note,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PriorityScore {
    pub priority: FeaturePriority,
    pub score_bps: u64,
    pub evidence_count: u64,
    pub landed_loc: u64,
    pub best_pq_security_bits: u16,
    pub best_latency_ms: u64,
    pub best_fee_bps: u64,
    pub best_privacy_set_size: u64,
    pub has_smart_contract_surface: bool,
    pub status: GateStatus,
}

impl PriorityScore {
    pub fn empty(priority: FeaturePriority) -> Self {
        Self {
            priority,
            score_bps: 0,
            evidence_count: 0,
            landed_loc: 0,
            best_pq_security_bits: 0,
            best_latency_ms: u64::MAX,
            best_fee_bps: MAX_BPS,
            best_privacy_set_size: 0,
            has_smart_contract_surface: false,
            status: GateStatus::Missing,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "priority": self.priority.as_str(),
            "score_bps": self.score_bps,
            "evidence_count": self.evidence_count,
            "landed_loc": self.landed_loc,
            "best_pq_security_bits": self.best_pq_security_bits,
            "best_latency_ms": if self.best_latency_ms == u64::MAX { 0 } else { self.best_latency_ms },
            "best_fee_bps": self.best_fee_bps,
            "best_privacy_set_size": self.best_privacy_set_size,
            "has_smart_contract_surface": self.has_smart_contract_surface,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub evidence: BTreeMap<String, FeatureEvidence>,
    pub worker_waves: BTreeMap<String, WorkerWaveRecord>,
    pub criteria: BTreeMap<String, GateCriterion>,
    pub remediations: BTreeMap<String, RemediationAction>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            evidence: BTreeMap::new(),
            worker_waves: BTreeMap::new(),
            criteria: BTreeMap::new(),
            remediations: BTreeMap::new(),
        };
        state.seed_devnet();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    fn seed_devnet(&mut self) {
        let inputs = vec![
            FeatureEvidenceInput {
                priority: FeaturePriority::QuantumResistance,
                kind: EvidenceKind::RuntimeModule,
                domain: "pq-auth-and-root-ingestion".to_string(),
                module_name: "private_l2_pq_confidential_cross_runtime_live_root_ingestion_runtime"
                    .to_string(),
                state_root: deterministic_id("DEVNET-EVIDENCE-ROOT", &["live-root".to_string()]),
                status: GateStatus::Wired,
                score_delta_bps: 850,
                pq_security_bits: 256,
                latency_ms: 260,
                fee_bps: 12,
                privacy_set_size: 65_536,
                smart_contract_surface: false,
                landed_loc: 1_752,
                note: "Live root ingestion feeds readiness gates with PQ attestations.".to_string(),
            },
            FeatureEvidenceInput {
                priority: FeaturePriority::Speed,
                kind: EvidenceKind::RuntimeModule,
                domain: "developer-rpc-fast-paths".to_string(),
                module_name: "private_l2_pq_confidential_developer_rpc_gateway_runtime".to_string(),
                state_root: deterministic_id(
                    "DEVNET-EVIDENCE-ROOT",
                    &["developer-rpc".to_string()],
                ),
                status: GateStatus::Wired,
                score_delta_bps: 720,
                pq_security_bits: 256,
                latency_ms: 180,
                fee_bps: 18,
                privacy_set_size: 65_536,
                smart_contract_surface: true,
                landed_loc: 3_279,
                note: "Developer RPC exposes roots-only fast responses and PQ auth envelopes."
                    .to_string(),
            },
            FeatureEvidenceInput {
                priority: FeaturePriority::DefiSmartContracts,
                kind: EvidenceKind::RuntimeModule,
                domain: "defi-contract-stress".to_string(),
                module_name: "private_l2_pq_confidential_defi_contract_stress_harness_runtime"
                    .to_string(),
                state_root: deterministic_id("DEVNET-EVIDENCE-ROOT", &["defi-stress".to_string()]),
                status: GateStatus::Wired,
                score_delta_bps: 780,
                pq_security_bits: 256,
                latency_ms: 240,
                fee_bps: 18,
                privacy_set_size: 131_072,
                smart_contract_surface: true,
                landed_loc: 1_697,
                note: "DeFi stress harness covers AMM, lending, perps, vaults, and callbacks."
                    .to_string(),
            },
            FeatureEvidenceInput {
                priority: FeaturePriority::LowFees,
                kind: EvidenceKind::RuntimeModule,
                domain: "fee-spike-resilience".to_string(),
                module_name: "private_l2_low_fee_pq_confidential_fee_spike_resilience_runtime"
                    .to_string(),
                state_root: deterministic_id("DEVNET-EVIDENCE-ROOT", &["fee-spike".to_string()]),
                status: GateStatus::Wired,
                score_delta_bps: 790,
                pq_security_bits: 256,
                latency_ms: 220,
                fee_bps: 9,
                privacy_set_size: 65_536,
                smart_contract_surface: true,
                landed_loc: 2_549,
                note: "Fee-spike runtime covers sponsor pools, auctions, repricing, and fee caps."
                    .to_string(),
            },
            FeatureEvidenceInput {
                priority: FeaturePriority::Privacy,
                kind: EvidenceKind::RuntimeModule,
                domain: "privacy-regression-audit".to_string(),
                module_name: "private_l2_pq_confidential_privacy_regression_audit_runtime"
                    .to_string(),
                state_root: deterministic_id(
                    "DEVNET-EVIDENCE-ROOT",
                    &["privacy-audit".to_string()],
                ),
                status: GateStatus::Wired,
                score_delta_bps: 820,
                pq_security_bits: 256,
                latency_ms: 300,
                fee_bps: 15,
                privacy_set_size: 131_072,
                smart_contract_surface: true,
                landed_loc: 2_079,
                note: "Privacy audit tracks anonymity floors, disclosure budgets, and redaction."
                    .to_string(),
            },
        ];
        for input in inputs {
            let _ = self.record_evidence(input);
        }
        let mut priority_roots = BTreeMap::new();
        for score in self.priority_scores() {
            priority_roots.insert(score.priority.clone(), score_root(&score));
        }
        let wave = WorkerWaveRecord::new(
            self.counters.worker_waves,
            "initial-gpt-5.5-runtime-wave",
            6,
            23_837,
            self.config.required_loc_wave,
            true,
            vec![
                "private_l2_pq_confidential_developer_rpc_gateway_runtime.rs".to_string(),
                "private_l2_pq_confidential_cross_runtime_live_root_ingestion_runtime.rs"
                    .to_string(),
                "monero_l2_pq_private_bridge_stress_scenario_runtime.rs".to_string(),
                "private_l2_low_fee_pq_confidential_fee_spike_resilience_runtime.rs".to_string(),
                "private_l2_pq_confidential_defi_contract_stress_harness_runtime.rs".to_string(),
                "private_l2_pq_confidential_privacy_regression_audit_runtime.rs".to_string(),
            ],
            priority_roots,
        );
        if let Ok(wave) = wave {
            self.worker_waves.insert(wave.wave_id.clone(), wave);
            self.counters.worker_waves = self.counters.worker_waves.saturating_add(1);
            self.counters.deferred_checks = self.counters.deferred_checks.saturating_add(1);
        }
        self.recompute_criteria();
    }

    pub fn record_evidence(&mut self, input: FeatureEvidenceInput) -> Result<String> {
        ensure_capacity(
            "evidence",
            self.evidence.len(),
            self.config.max_evidence_items,
        )?;
        let evidence = FeatureEvidence::from_input(self.counters.evidence_items, input)?;
        let evidence_id = evidence.evidence_id.clone();
        if evidence.status == GateStatus::Wired {
            self.counters.wired_items = self.counters.wired_items.saturating_add(1);
        }
        if evidence.status == GateStatus::DeferredCheck {
            self.counters.deferred_checks = self.counters.deferred_checks.saturating_add(1);
        }
        self.evidence.insert(evidence_id.clone(), evidence);
        self.counters.evidence_items = self.counters.evidence_items.saturating_add(1);
        Ok(evidence_id)
    }

    pub fn record_worker_wave(&mut self, wave: WorkerWaveRecord) -> Result<String> {
        ensure_capacity(
            "worker_waves",
            self.worker_waves.len(),
            self.config.max_worker_waves,
        )?;
        require_non_empty("wave_id", &wave.wave_id)?;
        let wave_id = wave.wave_id.clone();
        if wave.checks_deferred {
            self.counters.deferred_checks = self.counters.deferred_checks.saturating_add(1);
        }
        self.worker_waves.insert(wave_id.clone(), wave);
        self.counters.worker_waves = self.counters.worker_waves.saturating_add(1);
        Ok(wave_id)
    }

    pub fn add_remediation(&mut self, action: RemediationAction) -> Result<String> {
        ensure_capacity(
            "remediations",
            self.remediations.len(),
            self.config.max_remediations,
        )?;
        require_non_empty("remediation_id", &action.remediation_id)?;
        let remediation_id = action.remediation_id.clone();
        self.remediations.insert(remediation_id.clone(), action);
        self.counters.remediations = self.counters.remediations.saturating_add(1);
        Ok(remediation_id)
    }

    pub fn priority_scores(&self) -> Vec<PriorityScore> {
        let mut scores = BTreeMap::<FeaturePriority, PriorityScore>::new();
        for priority in &self.config.required_priorities {
            scores.insert(priority.clone(), PriorityScore::empty(priority.clone()));
        }
        for evidence in self.evidence.values() {
            let entry = scores
                .entry(evidence.priority.clone())
                .or_insert_with(|| PriorityScore::empty(evidence.priority.clone()));
            entry.evidence_count = entry.evidence_count.saturating_add(1);
            entry.landed_loc = entry.landed_loc.saturating_add(evidence.landed_loc);
            entry.score_bps = entry
                .score_bps
                .saturating_add(evidence.score_delta_bps)
                .min(MAX_BPS);
            entry.best_pq_security_bits =
                entry.best_pq_security_bits.max(evidence.pq_security_bits);
            if evidence.latency_ms > 0 {
                entry.best_latency_ms = entry.best_latency_ms.min(evidence.latency_ms);
            }
            entry.best_fee_bps = entry.best_fee_bps.min(evidence.fee_bps);
            entry.best_privacy_set_size =
                entry.best_privacy_set_size.max(evidence.privacy_set_size);
            entry.has_smart_contract_surface |= evidence.smart_contract_surface;
            entry.status = stronger_status(&entry.status, &evidence.status);
        }
        scores.into_values().collect()
    }

    pub fn recompute_criteria(&mut self) {
        self.criteria.clear();
        self.counters.criteria = 0;
        self.counters.ready_gates = 0;
        for score in self.priority_scores() {
            let current_bps = score.score_bps.min(MAX_BPS);
            let status = if current_bps >= self.config.required_score_bps
                && score.status == GateStatus::Wired
            {
                GateStatus::Ready
            } else if score.evidence_count == 0 {
                GateStatus::Missing
            } else {
                GateStatus::DeferredCheck
            };
            if status == GateStatus::Ready {
                self.counters.ready_gates = self.counters.ready_gates.saturating_add(1);
            }
            let evidence_root = score_root(&score);
            let criterion_id = deterministic_id(
                "FEATURE-EVIDENCE-CRITERION",
                &[
                    self.config.release_gate_id.clone(),
                    score.priority.as_str().to_string(),
                    current_bps.to_string(),
                    evidence_root.clone(),
                ],
            );
            let criterion = GateCriterion {
                criterion_id: criterion_id.clone(),
                priority: score.priority,
                label: "feature completion release gate".to_string(),
                target_bps: self.config.required_score_bps,
                current_bps,
                status,
                evidence_root,
            };
            self.criteria.insert(criterion_id, criterion);
            self.counters.criteria = self.counters.criteria.saturating_add(1);
        }
    }

    pub fn release_gate_status(&self) -> GateStatus {
        if self.criteria.is_empty() {
            return GateStatus::Missing;
        }
        if self
            .criteria
            .values()
            .all(|criterion| criterion.status == GateStatus::Ready)
        {
            GateStatus::Ready
        } else if self
            .criteria
            .values()
            .any(|criterion| criterion.status == GateStatus::Missing)
        {
            GateStatus::Missing
        } else {
            GateStatus::DeferredCheck
        }
    }

    pub fn total_landed_loc(&self) -> u64 {
        self.worker_waves
            .values()
            .map(|wave| wave.landed_loc)
            .fold(0_u64, u64::saturating_add)
    }

    pub fn roots(&self) -> Roots {
        let config_root = record_root("FEATURE-EVIDENCE-CONFIG", &self.config.public_record());
        let evidence_root = map_root(
            "FEATURE-EVIDENCE-ITEMS",
            &self.evidence,
            FeatureEvidence::public_record,
        );
        let priority_root = list_root(
            "FEATURE-EVIDENCE-PRIORITY-SCORES",
            &self
                .priority_scores()
                .iter()
                .map(PriorityScore::public_record)
                .collect::<Vec<_>>(),
        );
        let worker_wave_root = map_root(
            "FEATURE-EVIDENCE-WORKER-WAVES",
            &self.worker_waves,
            WorkerWaveRecord::public_record,
        );
        let criterion_root = map_root(
            "FEATURE-EVIDENCE-CRITERIA",
            &self.criteria,
            GateCriterion::public_record,
        );
        let remediation_root = map_root(
            "FEATURE-EVIDENCE-REMEDIATIONS",
            &self.remediations,
            RemediationAction::public_record,
        );
        let counter_root = record_root("FEATURE-EVIDENCE-COUNTERS", &self.counters.public_record());
        let score_root = record_root(
            "FEATURE-EVIDENCE-RELEASE-SCORE",
            &json!({
                "release_gate_id": self.config.release_gate_id,
                "status": self.release_gate_status().as_str(),
                "total_landed_loc": self.total_landed_loc(),
                "required_loc_wave": self.config.required_loc_wave,
            }),
        );
        let state_root = record_root(
            "FEATURE-EVIDENCE-STATE",
            &json!({
                "chain_id": self.config.chain_id,
                "protocol_version": PROTOCOL_VERSION,
                "config_root": config_root,
                "evidence_root": evidence_root,
                "priority_root": priority_root,
                "worker_wave_root": worker_wave_root,
                "criterion_root": criterion_root,
                "remediation_root": remediation_root,
                "counter_root": counter_root,
                "score_root": score_root,
            }),
        );
        Roots {
            config_root,
            evidence_root,
            priority_root,
            worker_wave_root,
            criterion_root,
            remediation_root,
            counter_root,
            score_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_evidence_suite": PQ_EVIDENCE_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "release_gate_status": self.release_gate_status().as_str(),
            "total_landed_loc": self.total_landed_loc(),
            "roots": self.roots().public_record(),
            "priority_scores": self.priority_scores().iter().map(PriorityScore::public_record).collect::<Vec<_>>(),
            "criteria": self.criteria.values().map(GateCriterion::public_record).collect::<Vec<_>>(),
            "worker_waves": self.worker_waves.values().map(WorkerWaveRecord::public_record).collect::<Vec<_>>(),
            "evidence": self.evidence.values().map(FeatureEvidence::public_record).collect::<Vec<_>>(),
            "remediations": self.remediations.values().map(RemediationAction::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        require(
            self.evidence.len() <= self.config.max_evidence_items,
            "too many evidence items",
        )?;
        require(
            self.worker_waves.len() <= self.config.max_worker_waves,
            "too many worker waves",
        )?;
        require(
            self.remediations.len() <= self.config.max_remediations,
            "too many remediations",
        )?;
        for evidence in self.evidence.values() {
            require_non_empty("evidence_id", &evidence.evidence_id)?;
            require_non_empty("evidence_state_root", &evidence.state_root)?;
        }
        for criterion in self.criteria.values() {
            require_non_empty("criterion_id", &criterion.criterion_id)?;
            require_non_empty("criterion_evidence_root", &criterion.evidence_root)?;
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn feature_evidence_id(sequence: u64, input: &FeatureEvidenceInput) -> String {
    deterministic_id(
        "FEATURE-EVIDENCE-ID",
        &[
            sequence.to_string(),
            input.priority.as_str().to_string(),
            input.kind.as_str().to_string(),
            input.domain.clone(),
            input.module_name.clone(),
            input.state_root.clone(),
        ],
    )
}

pub fn score_root(score: &PriorityScore) -> String {
    record_root("FEATURE-EVIDENCE-PRIORITY-SCORE", &score.public_record())
}

pub fn record_root(domain: &str, record: &Value) -> String {
    deterministic_id(domain, &[record.to_string()])
}

pub fn list_root(domain: &str, records: &[Value]) -> String {
    let mut parts = Vec::new();
    for record in records {
        parts.push(record.to_string());
    }
    deterministic_id(domain, &parts)
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

fn stronger_status(left: &GateStatus, right: &GateStatus) -> GateStatus {
    if status_rank(right) >= status_rank(left) {
        right.clone()
    } else {
        left.clone()
    }
}

fn status_rank(status: &GateStatus) -> u8 {
    match status {
        GateStatus::Missing => 0,
        GateStatus::Drafting => 1,
        GateStatus::Landed => 2,
        GateStatus::DeferredCheck => 3,
        GateStatus::Wired => 4,
        GateStatus::Ready => 5,
        GateStatus::Blocked => 6,
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
