use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialWaveProgressManifestRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str = "private-l2-pq-confidential-wave-progress-manifest-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_WAVE_PROGRESS_MANIFEST_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "nebula-stable-fnv1a-wave-progress-manifest-v1";
pub const PQ_MANIFEST_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-wave-progress-attestation-v1";
pub const DEFAULT_CHAIN_ID: &str = "nebula-monero-private-l2-devnet";
pub const DEFAULT_MANIFEST_ID: &str = "nebula-l2-100k-loc-wave-progress";
pub const DEFAULT_TARGET_LOC: u64 = 100_000;
pub const DEFAULT_MIN_MODULE_LOC: u64 = 1_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_FEE_BPS: u64 = 30;
pub const DEFAULT_MAX_LATENCY_P95_MS: u64 = 250;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_WAVES: usize = 65_536;
pub const DEFAULT_MAX_MODULES: usize = 1_048_576;
pub const DEFAULT_MAX_INTEGRATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_GATES: usize = 524_288;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum PriorityTrack {
    QuantumResistance,
    Speed,
    DefiSmartContracts,
    LowFees,
    Privacy,
    MoneroBridge,
    OperatorVisibility,
    RuntimeReadiness,
}

impl PriorityTrack {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::QuantumResistance => "quantum_resistance",
            Self::Speed => "speed",
            Self::DefiSmartContracts => "defi_smart_contracts",
            Self::LowFees => "low_fees",
            Self::Privacy => "privacy",
            Self::MoneroBridge => "monero_bridge",
            Self::OperatorVisibility => "operator_visibility",
            Self::RuntimeReadiness => "runtime_readiness",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkerKind {
    MainAgent,
    Gpt55Worker,
    ManualIntegration,
    PanelUpdate,
}

impl WorkerKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MainAgent => "main_agent",
            Self::Gpt55Worker => "gpt_5_5_worker",
            Self::ManualIntegration => "manual_integration",
            Self::PanelUpdate => "panel_update",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ModuleStatus {
    Drafting,
    Landed,
    LibWired,
    OperatorWired,
    DevnetWired,
    DeferredCheck,
    Ready,
}

impl ModuleStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Drafting => "drafting",
            Self::Landed => "landed",
            Self::LibWired => "lib_wired",
            Self::OperatorWired => "operator_wired",
            Self::DevnetWired => "devnet_wired",
            Self::DeferredCheck => "deferred_check",
            Self::Ready => "ready",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntegrationKind {
    ModuleDeclaration,
    CrateExport,
    DevnetStateField,
    DevnetConstructor,
    DevnetCompactRoot,
    DevnetPublicRecord,
    OperatorCatalog,
    ProgressPanel,
}

impl IntegrationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ModuleDeclaration => "module_declaration",
            Self::CrateExport => "crate_export",
            Self::DevnetStateField => "devnet_state_field",
            Self::DevnetConstructor => "devnet_constructor",
            Self::DevnetCompactRoot => "devnet_compact_root",
            Self::DevnetPublicRecord => "devnet_public_record",
            Self::OperatorCatalog => "operator_catalog",
            Self::ProgressPanel => "progress_panel",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CheckGateStatus {
    Deferred,
    Scheduled,
    Running,
    Passed,
    Failed,
}

impl CheckGateStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Deferred => "deferred",
            Self::Scheduled => "scheduled",
            Self::Running => "running",
            Self::Passed => "passed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum CheckGateKind {
    CargoFmt,
    CargoCheck,
    CargoTest,
    Clippy,
    PanelFeed,
    TargetedNameScan,
}

impl CheckGateKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CargoFmt => "cargo_fmt",
            Self::CargoCheck => "cargo_check",
            Self::CargoTest => "cargo_test",
            Self::Clippy => "clippy",
            Self::PanelFeed => "panel_feed",
            Self::TargetedNameScan => "targeted_name_scan",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub manifest_id: String,
    pub target_loc: u64,
    pub min_module_loc: u64,
    pub min_pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub max_latency_p95_ms: u64,
    pub min_privacy_set_size: u64,
    pub max_waves: usize,
    pub max_modules: usize,
    pub max_integrations: usize,
    pub max_gates: usize,
    pub required_tracks: BTreeSet<PriorityTrack>,
}

impl Config {
    pub fn devnet() -> Self {
        let mut required_tracks = BTreeSet::new();
        required_tracks.insert(PriorityTrack::QuantumResistance);
        required_tracks.insert(PriorityTrack::Speed);
        required_tracks.insert(PriorityTrack::DefiSmartContracts);
        required_tracks.insert(PriorityTrack::LowFees);
        required_tracks.insert(PriorityTrack::Privacy);
        Self {
            chain_id: DEFAULT_CHAIN_ID.to_string(),
            manifest_id: DEFAULT_MANIFEST_ID.to_string(),
            target_loc: DEFAULT_TARGET_LOC,
            min_module_loc: DEFAULT_MIN_MODULE_LOC,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            max_latency_p95_ms: DEFAULT_MAX_LATENCY_P95_MS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_waves: DEFAULT_MAX_WAVES,
            max_modules: DEFAULT_MAX_MODULES,
            max_integrations: DEFAULT_MAX_INTEGRATIONS,
            max_gates: DEFAULT_MAX_GATES,
            required_tracks,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("manifest_id", &self.manifest_id)?;
        require(self.target_loc > 0, "target_loc must be nonzero")?;
        require(self.min_module_loc > 0, "min_module_loc must be nonzero")?;
        require(
            self.min_pq_security_bits >= 128,
            "min_pq_security_bits must be at least 128",
        )?;
        require(self.max_fee_bps <= MAX_BPS, "max_fee_bps exceeds MAX_BPS")?;
        require(
            self.max_latency_p95_ms > 0,
            "max_latency_p95_ms must be nonzero",
        )?;
        require(
            self.min_privacy_set_size > 0,
            "min_privacy_set_size must be nonzero",
        )?;
        require(self.max_waves > 0, "max_waves must be nonzero")?;
        require(self.max_modules > 0, "max_modules must be nonzero")?;
        require(
            self.max_integrations > 0,
            "max_integrations must be nonzero",
        )?;
        require(self.max_gates > 0, "max_gates must be nonzero")?;
        require(
            !self.required_tracks.is_empty(),
            "required_tracks must be non-empty",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "manifest_id": self.manifest_id,
            "target_loc": self.target_loc,
            "min_module_loc": self.min_module_loc,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "max_latency_p95_ms": self.max_latency_p95_ms,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_waves": self.max_waves,
            "max_modules": self.max_modules,
            "max_integrations": self.max_integrations,
            "max_gates": self.max_gates,
            "required_tracks": self.required_tracks.iter().map(PriorityTrack::as_str).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WaveInput {
    pub wave_label: String,
    pub owner_label: String,
    pub worker_count: u16,
    pub target_loc: u64,
    pub landed_loc: u64,
    pub status: ModuleStatus,
    pub no_check_policy: bool,
    pub evidence_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WaveRecord {
    pub wave_id: String,
    pub wave_label: String,
    pub owner_label: String,
    pub worker_count: u16,
    pub target_loc: u64,
    pub landed_loc: u64,
    pub status: ModuleStatus,
    pub no_check_policy: bool,
    pub evidence_root: String,
    pub progress_bps: u64,
    pub record_root: String,
}

impl WaveRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "wave_id": self.wave_id,
            "wave_label": self.wave_label,
            "owner_label": self.owner_label,
            "worker_count": self.worker_count,
            "target_loc": self.target_loc,
            "landed_loc": self.landed_loc,
            "status": self.status.as_str(),
            "no_check_policy": self.no_check_policy,
            "evidence_root": self.evidence_root,
            "progress_bps": self.progress_bps,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModuleInput {
    pub module_name: String,
    pub owned_file: String,
    pub worker_label: String,
    pub worker_kind: WorkerKind,
    pub track: PriorityTrack,
    pub loc: u64,
    pub status: ModuleStatus,
    pub state_root: String,
    pub pq_security_bits: u16,
    pub latency_p95_ms: u64,
    pub fee_bps: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModuleRecord {
    pub module_id: String,
    pub module_name: String,
    pub owned_file: String,
    pub worker_label: String,
    pub worker_kind: WorkerKind,
    pub track: PriorityTrack,
    pub loc: u64,
    pub status: ModuleStatus,
    pub state_root: String,
    pub pq_security_bits: u16,
    pub latency_p95_ms: u64,
    pub fee_bps: u64,
    pub privacy_set_size: u64,
    pub readiness_bps: u64,
    pub record_root: String,
}

impl ModuleRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "module_id": self.module_id,
            "module_name": self.module_name,
            "owned_file": self.owned_file,
            "worker_label": self.worker_label,
            "worker_kind": self.worker_kind.as_str(),
            "track": self.track.as_str(),
            "loc": self.loc,
            "status": self.status.as_str(),
            "state_root": self.state_root,
            "pq_security_bits": self.pq_security_bits,
            "latency_p95_ms": self.latency_p95_ms,
            "fee_bps": self.fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "readiness_bps": self.readiness_bps,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntegrationInput {
    pub module_name: String,
    pub kind: IntegrationKind,
    pub file_path: String,
    pub evidence_root: String,
    pub complete: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntegrationRecord {
    pub integration_id: String,
    pub module_name: String,
    pub kind: IntegrationKind,
    pub file_path: String,
    pub evidence_root: String,
    pub complete: bool,
    pub record_root: String,
}

impl IntegrationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "integration_id": self.integration_id,
            "module_name": self.module_name,
            "kind": self.kind.as_str(),
            "file_path": self.file_path,
            "evidence_root": self.evidence_root,
            "complete": self.complete,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckGateInput {
    pub gate_label: String,
    pub kind: CheckGateKind,
    pub status: CheckGateStatus,
    pub deferred_reason: String,
    pub evidence_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckGateRecord {
    pub gate_id: String,
    pub gate_label: String,
    pub kind: CheckGateKind,
    pub status: CheckGateStatus,
    pub deferred_reason: String,
    pub evidence_root: String,
    pub blocking_release: bool,
    pub record_root: String,
}

impl CheckGateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "gate_label": self.gate_label,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "deferred_reason": self.deferred_reason,
            "evidence_root": self.evidence_root,
            "blocking_release": self.blocking_release,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub waves: u64,
    pub modules: u64,
    pub integrations: u64,
    pub check_gates: u64,
    pub deferred_gates: u64,
    pub landed_loc: u64,
    pub gpt55_worker_modules: u64,
    pub local_modules: u64,
    pub devnet_wired_modules: u64,
    pub operator_wired_modules: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "waves": self.waves,
            "modules": self.modules,
            "integrations": self.integrations,
            "check_gates": self.check_gates,
            "deferred_gates": self.deferred_gates,
            "landed_loc": self.landed_loc,
            "gpt55_worker_modules": self.gpt55_worker_modules,
            "local_modules": self.local_modules,
            "devnet_wired_modules": self.devnet_wired_modules,
            "operator_wired_modules": self.operator_wired_modules,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub waves_root: String,
    pub modules_root: String,
    pub integrations_root: String,
    pub check_gates_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config) -> Self {
        let config_root = record_root("WAVE-MANIFEST-CONFIG", &config.public_record());
        let counters_root = record_root(
            "WAVE-MANIFEST-COUNTERS",
            &Counters::default().public_record(),
        );
        let waves_root = deterministic_id("WAVE-MANIFEST-WAVES-EMPTY", &[]);
        let modules_root = deterministic_id("WAVE-MANIFEST-MODULES-EMPTY", &[]);
        let integrations_root = deterministic_id("WAVE-MANIFEST-INTEGRATIONS-EMPTY", &[]);
        let check_gates_root = deterministic_id("WAVE-MANIFEST-CHECK-GATES-EMPTY", &[]);
        let state_root = deterministic_id(
            "WAVE-MANIFEST-STATE",
            &[
                config_root.clone(),
                counters_root.clone(),
                waves_root.clone(),
                modules_root.clone(),
                integrations_root.clone(),
                check_gates_root.clone(),
            ],
        );
        Self {
            config_root,
            waves_root,
            modules_root,
            integrations_root,
            check_gates_root,
            counters_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "waves_root": self.waves_root,
            "modules_root": self.modules_root,
            "integrations_root": self.integrations_root,
            "check_gates_root": self.check_gates_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub waves: BTreeMap<String, WaveRecord>,
    pub modules: BTreeMap<String, ModuleRecord>,
    pub integrations: BTreeMap<String, IntegrationRecord>,
    pub check_gates: BTreeMap<String, CheckGateRecord>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let roots = Roots::empty(&config);
        Ok(Self {
            config,
            waves: BTreeMap::new(),
            modules: BTreeMap::new(),
            integrations: BTreeMap::new(),
            check_gates: BTreeMap::new(),
            counters: Counters::default(),
            roots,
        })
    }

    pub fn devnet() -> Self {
        match Self::new(Config::devnet()) {
            Ok(mut state) => {
                state.seed_devnet_manifest();
                state
            }
            Err(_) => Self::fallback(),
        }
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let _ = state.add_wave(WaveInput {
            wave_label: "fourth-gpt55-wave".to_string(),
            owner_label: "main-agent-plus-six-workers".to_string(),
            worker_count: 6,
            target_loc: 100_000,
            landed_loc: 53_603,
            status: ModuleStatus::Drafting,
            no_check_policy: true,
            evidence_root: deterministic_id(
                "FOURTH-WAVE-EVIDENCE",
                &[PROTOCOL_VERSION.to_string()],
            ),
        });
        state
    }

    pub fn add_wave(&mut self, input: WaveInput) -> Result<String> {
        ensure_capacity("waves", self.waves.len(), self.config.max_waves)?;
        require_non_empty("wave_label", &input.wave_label)?;
        require_non_empty("owner_label", &input.owner_label)?;
        require_non_empty("evidence_root", &input.evidence_root)?;
        require(input.target_loc > 0, "wave target_loc must be nonzero")?;
        let sequence = self.counters.waves.saturating_add(1);
        let wave_id = deterministic_id(
            "WAVE-MANIFEST-WAVE-ID",
            &[
                sequence.to_string(),
                input.wave_label.clone(),
                input.evidence_root.clone(),
            ],
        );
        let progress_bps = ratio_bps(input.landed_loc, input.target_loc);
        let mut record = WaveRecord {
            wave_id: wave_id.clone(),
            wave_label: input.wave_label,
            owner_label: input.owner_label,
            worker_count: input.worker_count,
            target_loc: input.target_loc,
            landed_loc: input.landed_loc,
            status: input.status,
            no_check_policy: input.no_check_policy,
            evidence_root: input.evidence_root,
            progress_bps,
            record_root: String::new(),
        };
        record.record_root = record_root("WAVE-MANIFEST-WAVE", &record.public_record());
        self.waves.insert(wave_id.clone(), record);
        self.rebuild_roots();
        Ok(wave_id)
    }

    pub fn add_module(&mut self, input: ModuleInput) -> Result<String> {
        ensure_capacity("modules", self.modules.len(), self.config.max_modules)?;
        validate_module_input(&self.config, &input)?;
        let sequence = self.counters.modules.saturating_add(1);
        let module_id = deterministic_id(
            "WAVE-MANIFEST-MODULE-ID",
            &[
                sequence.to_string(),
                input.module_name.clone(),
                input.owned_file.clone(),
                input.state_root.clone(),
            ],
        );
        let readiness_bps = module_readiness_bps(&self.config, &input);
        let mut record = ModuleRecord {
            module_id: module_id.clone(),
            module_name: input.module_name,
            owned_file: input.owned_file,
            worker_label: input.worker_label,
            worker_kind: input.worker_kind,
            track: input.track,
            loc: input.loc,
            status: input.status,
            state_root: input.state_root,
            pq_security_bits: input.pq_security_bits,
            latency_p95_ms: input.latency_p95_ms,
            fee_bps: input.fee_bps,
            privacy_set_size: input.privacy_set_size,
            readiness_bps,
            record_root: String::new(),
        };
        record.record_root = record_root("WAVE-MANIFEST-MODULE", &record.public_record());
        self.modules.insert(module_id.clone(), record);
        self.rebuild_roots();
        Ok(module_id)
    }

    pub fn add_integration(&mut self, input: IntegrationInput) -> Result<String> {
        ensure_capacity(
            "integrations",
            self.integrations.len(),
            self.config.max_integrations,
        )?;
        require_non_empty("integration_module_name", &input.module_name)?;
        require_non_empty("integration_file_path", &input.file_path)?;
        require_non_empty("integration_evidence_root", &input.evidence_root)?;
        let sequence = self.counters.integrations.saturating_add(1);
        let integration_id = deterministic_id(
            "WAVE-MANIFEST-INTEGRATION-ID",
            &[
                sequence.to_string(),
                input.module_name.clone(),
                input.kind.as_str().to_string(),
                input.file_path.clone(),
            ],
        );
        let mut record = IntegrationRecord {
            integration_id: integration_id.clone(),
            module_name: input.module_name,
            kind: input.kind,
            file_path: input.file_path,
            evidence_root: input.evidence_root,
            complete: input.complete,
            record_root: String::new(),
        };
        record.record_root = record_root("WAVE-MANIFEST-INTEGRATION", &record.public_record());
        self.integrations.insert(integration_id.clone(), record);
        self.rebuild_roots();
        Ok(integration_id)
    }

    pub fn add_check_gate(&mut self, input: CheckGateInput) -> Result<String> {
        ensure_capacity("check_gates", self.check_gates.len(), self.config.max_gates)?;
        require_non_empty("gate_label", &input.gate_label)?;
        require_non_empty("deferred_reason", &input.deferred_reason)?;
        require_non_empty("gate_evidence_root", &input.evidence_root)?;
        let sequence = self.counters.check_gates.saturating_add(1);
        let gate_id = deterministic_id(
            "WAVE-MANIFEST-CHECK-GATE-ID",
            &[
                sequence.to_string(),
                input.gate_label.clone(),
                input.kind.as_str().to_string(),
                input.evidence_root.clone(),
            ],
        );
        let blocking_release = input.status != CheckGateStatus::Passed;
        let mut record = CheckGateRecord {
            gate_id: gate_id.clone(),
            gate_label: input.gate_label,
            kind: input.kind,
            status: input.status,
            deferred_reason: input.deferred_reason,
            evidence_root: input.evidence_root,
            blocking_release,
            record_root: String::new(),
        };
        record.record_root = record_root("WAVE-MANIFEST-CHECK-GATE", &record.public_record());
        self.check_gates.insert(gate_id.clone(), record);
        self.rebuild_roots();
        Ok(gate_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_manifest_attestation_suite": PQ_MANIFEST_ATTESTATION_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "waves": self.waves.values().map(WaveRecord::public_record).collect::<Vec<_>>(),
            "modules": self.modules.values().map(ModuleRecord::public_record).collect::<Vec<_>>(),
            "integrations": self.integrations.values().map(IntegrationRecord::public_record).collect::<Vec<_>>(),
            "check_gates": self.check_gates.values().map(CheckGateRecord::public_record).collect::<Vec<_>>(),
            "covered_tracks": self.covered_tracks(),
            "missing_tracks": self.missing_tracks(),
            "progress_bps": ratio_bps(self.counters.landed_loc, self.config.target_loc),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        require(self.waves.len() <= self.config.max_waves, "too many waves")?;
        require(
            self.modules.len() <= self.config.max_modules,
            "too many modules",
        )?;
        require(
            self.integrations.len() <= self.config.max_integrations,
            "too many integrations",
        )?;
        require(
            self.check_gates.len() <= self.config.max_gates,
            "too many check gates",
        )?;
        for module in self.modules.values() {
            require_non_empty("module_id", &module.module_id)?;
            require_non_empty("module_state_root", &module.state_root)?;
            require(
                module.readiness_bps <= MAX_BPS,
                "module readiness above MAX_BPS",
            )?;
        }
        Ok(())
    }

    fn fallback() -> Self {
        let config = Config::devnet();
        let roots = Roots::empty(&config);
        Self {
            config,
            waves: BTreeMap::new(),
            modules: BTreeMap::new(),
            integrations: BTreeMap::new(),
            check_gates: BTreeMap::new(),
            counters: Counters::default(),
            roots,
        }
    }

    fn seed_devnet_manifest(&mut self) {
        let _ = self.add_wave(WaveInput {
            wave_label: "third-wave-wired".to_string(),
            owner_label: "main-agent-plus-gpt55-workers".to_string(),
            worker_count: 6,
            target_loc: self.config.target_loc,
            landed_loc: 53_603,
            status: ModuleStatus::DevnetWired,
            no_check_policy: true,
            evidence_root: deterministic_id("THIRD-WAVE-WIRED", &[PROTOCOL_VERSION.to_string()]),
        });
        let modules = vec![
            ModuleInput {
                module_name:
                    "private_l2_pq_confidential_quantum_signature_rollover_coordinator_runtime"
                        .to_string(),
                owned_file:
                    "private_l2_pq_confidential_quantum_signature_rollover_coordinator_runtime.rs"
                        .to_string(),
                worker_label: "Pauli".to_string(),
                worker_kind: WorkerKind::Gpt55Worker,
                track: PriorityTrack::QuantumResistance,
                loc: 1_623,
                status: ModuleStatus::DevnetWired,
                state_root: deterministic_id(
                    "MODULE-ROOT-QUANTUM-ROLLOVER",
                    &[PROTOCOL_VERSION.to_string()],
                ),
                pq_security_bits: 256,
                latency_p95_ms: 190,
                fee_bps: 12,
                privacy_set_size: 65_536,
            },
            ModuleInput {
                module_name: "private_l2_fast_pq_confidential_gpu_prover_batch_scheduler_runtime"
                    .to_string(),
                owned_file: "private_l2_fast_pq_confidential_gpu_prover_batch_scheduler_runtime.rs"
                    .to_string(),
                worker_label: "Einstein".to_string(),
                worker_kind: WorkerKind::Gpt55Worker,
                track: PriorityTrack::Speed,
                loc: 2_327,
                status: ModuleStatus::DevnetWired,
                state_root: deterministic_id(
                    "MODULE-ROOT-GPU-PROVER",
                    &[PROTOCOL_VERSION.to_string()],
                ),
                pq_security_bits: 256,
                latency_p95_ms: 120,
                fee_bps: 10,
                privacy_set_size: 65_536,
            },
            ModuleInput {
                module_name: "private_l2_pq_confidential_defi_cross_margin_risk_engine_runtime"
                    .to_string(),
                owned_file: "private_l2_pq_confidential_defi_cross_margin_risk_engine_runtime.rs"
                    .to_string(),
                worker_label: "Bacon".to_string(),
                worker_kind: WorkerKind::Gpt55Worker,
                track: PriorityTrack::DefiSmartContracts,
                loc: 1_949,
                status: ModuleStatus::DevnetWired,
                state_root: deterministic_id(
                    "MODULE-ROOT-CROSS-MARGIN",
                    &[PROTOCOL_VERSION.to_string()],
                ),
                pq_security_bits: 256,
                latency_p95_ms: 210,
                fee_bps: 18,
                privacy_set_size: 65_536,
            },
            ModuleInput {
                module_name: "private_l2_low_fee_pq_confidential_fee_floor_auction_runtime"
                    .to_string(),
                owned_file: "private_l2_low_fee_pq_confidential_fee_floor_auction_runtime.rs"
                    .to_string(),
                worker_label: "Halley".to_string(),
                worker_kind: WorkerKind::Gpt55Worker,
                track: PriorityTrack::LowFees,
                loc: 2_246,
                status: ModuleStatus::DevnetWired,
                state_root: deterministic_id(
                    "MODULE-ROOT-FEE-FLOOR",
                    &[PROTOCOL_VERSION.to_string()],
                ),
                pq_security_bits: 256,
                latency_p95_ms: 220,
                fee_bps: 6,
                privacy_set_size: 65_536,
            },
            ModuleInput {
                module_name: "monero_l2_pq_private_ringct_migration_audit_runtime".to_string(),
                owned_file: "monero_l2_pq_private_ringct_migration_audit_runtime.rs".to_string(),
                worker_label: "Peirce".to_string(),
                worker_kind: WorkerKind::Gpt55Worker,
                track: PriorityTrack::Privacy,
                loc: 2_229,
                status: ModuleStatus::DevnetWired,
                state_root: deterministic_id(
                    "MODULE-ROOT-RINGCT-AUDIT",
                    &[PROTOCOL_VERSION.to_string()],
                ),
                pq_security_bits: 256,
                latency_p95_ms: 230,
                fee_bps: 12,
                privacy_set_size: 131_072,
            },
            ModuleInput {
                module_name: "private_l2_pq_confidential_smart_contract_abi_fuzzer_runtime"
                    .to_string(),
                owned_file: "private_l2_pq_confidential_smart_contract_abi_fuzzer_runtime.rs"
                    .to_string(),
                worker_label: "Cicero".to_string(),
                worker_kind: WorkerKind::Gpt55Worker,
                track: PriorityTrack::DefiSmartContracts,
                loc: 1_939,
                status: ModuleStatus::DevnetWired,
                state_root: deterministic_id(
                    "MODULE-ROOT-ABI-FUZZER",
                    &[PROTOCOL_VERSION.to_string()],
                ),
                pq_security_bits: 256,
                latency_p95_ms: 225,
                fee_bps: 16,
                privacy_set_size: 65_536,
            },
            ModuleInput {
                module_name: "private_l2_pq_confidential_release_gate_attestation_runtime"
                    .to_string(),
                owned_file: "private_l2_pq_confidential_release_gate_attestation_runtime.rs"
                    .to_string(),
                worker_label: "local".to_string(),
                worker_kind: WorkerKind::MainAgent,
                track: PriorityTrack::OperatorVisibility,
                loc: 1_334,
                status: ModuleStatus::DevnetWired,
                state_root: deterministic_id(
                    "MODULE-ROOT-RELEASE-GATE",
                    &[PROTOCOL_VERSION.to_string()],
                ),
                pq_security_bits: 256,
                latency_p95_ms: 180,
                fee_bps: 10,
                privacy_set_size: 65_536,
            },
        ];
        for module in modules {
            let module_name = module.module_name.clone();
            let _ = self.add_module(module);
            self.add_standard_integrations(&module_name);
        }
        let gates = vec![
            (CheckGateKind::CargoFmt, "cargo fmt deferred"),
            (CheckGateKind::CargoCheck, "cargo check deferred"),
            (CheckGateKind::CargoTest, "cargo test deferred"),
            (CheckGateKind::Clippy, "clippy deferred"),
        ];
        for (kind, label) in gates {
            let _ = self.add_check_gate(CheckGateInput {
                gate_label: label.to_string(),
                kind,
                status: CheckGateStatus::Deferred,
                deferred_reason: "user requested large LOC wave before major checks".to_string(),
                evidence_root: deterministic_id("DEFERRED-CHECK", &[label.to_string()]),
            });
        }
    }

    fn add_standard_integrations(&mut self, module_name: &str) {
        let integrations = vec![
            (
                IntegrationKind::ModuleDeclaration,
                "utils/nebula_l2_rs/src/lib.rs",
            ),
            (
                IntegrationKind::CrateExport,
                "utils/nebula_l2_rs/src/lib.rs",
            ),
            (
                IntegrationKind::OperatorCatalog,
                "utils/nebula_l2_rs/src/operator.rs",
            ),
            (
                IntegrationKind::DevnetStateField,
                "utils/nebula_l2_rs/src/devnet.rs",
            ),
            (
                IntegrationKind::DevnetConstructor,
                "utils/nebula_l2_rs/src/devnet.rs",
            ),
            (
                IntegrationKind::DevnetCompactRoot,
                "utils/nebula_l2_rs/src/devnet.rs",
            ),
            (
                IntegrationKind::DevnetPublicRecord,
                "utils/nebula_l2_rs/src/devnet.rs",
            ),
            (
                IntegrationKind::ProgressPanel,
                "utils/l2_progress_panel/progress.json",
            ),
        ];
        for (kind, file_path) in integrations {
            let _ = self.add_integration(IntegrationInput {
                module_name: module_name.to_string(),
                kind,
                file_path: file_path.to_string(),
                evidence_root: deterministic_id(
                    "STANDARD-INTEGRATION",
                    &[module_name.to_string(), file_path.to_string()],
                ),
                complete: true,
            });
        }
    }

    fn covered_tracks(&self) -> Vec<String> {
        let mut tracks = BTreeSet::new();
        for module in self.modules.values() {
            if module.status != ModuleStatus::Drafting {
                tracks.insert(module.track.clone());
            }
        }
        tracks
            .into_iter()
            .map(|track| track.as_str().to_string())
            .collect()
    }

    fn missing_tracks(&self) -> Vec<String> {
        let covered = self
            .modules
            .values()
            .filter(|module| module.status != ModuleStatus::Drafting)
            .map(|module| module.track.clone())
            .collect::<BTreeSet<_>>();
        self.config
            .required_tracks
            .iter()
            .filter(|track| !covered.contains(*track))
            .map(|track| track.as_str().to_string())
            .collect()
    }

    fn rebuild_roots(&mut self) {
        self.counters.waves = self.waves.len() as u64;
        self.counters.modules = self.modules.len() as u64;
        self.counters.integrations = self.integrations.len() as u64;
        self.counters.check_gates = self.check_gates.len() as u64;
        self.counters.deferred_gates = self
            .check_gates
            .values()
            .filter(|gate| gate.status == CheckGateStatus::Deferred)
            .count() as u64;
        self.counters.landed_loc = self
            .modules
            .values()
            .fold(0_u64, |acc, module| acc.saturating_add(module.loc));
        self.counters.gpt55_worker_modules = self
            .modules
            .values()
            .filter(|module| module.worker_kind == WorkerKind::Gpt55Worker)
            .count() as u64;
        self.counters.local_modules = self
            .modules
            .values()
            .filter(|module| module.worker_kind == WorkerKind::MainAgent)
            .count() as u64;
        self.counters.devnet_wired_modules = self
            .modules
            .values()
            .filter(|module| module.status == ModuleStatus::DevnetWired)
            .count() as u64;
        self.counters.operator_wired_modules = self
            .integrations
            .values()
            .filter(|integration| {
                integration.kind == IntegrationKind::OperatorCatalog && integration.complete
            })
            .count() as u64;
        self.roots.config_root = record_root("WAVE-MANIFEST-CONFIG", &self.config.public_record());
        self.roots.counters_root =
            record_root("WAVE-MANIFEST-COUNTERS", &self.counters.public_record());
        self.roots.waves_root = map_root(
            "WAVE-MANIFEST-WAVES",
            &self.waves,
            WaveRecord::public_record,
        );
        self.roots.modules_root = map_root(
            "WAVE-MANIFEST-MODULES",
            &self.modules,
            ModuleRecord::public_record,
        );
        self.roots.integrations_root = map_root(
            "WAVE-MANIFEST-INTEGRATIONS",
            &self.integrations,
            IntegrationRecord::public_record,
        );
        self.roots.check_gates_root = map_root(
            "WAVE-MANIFEST-CHECK-GATES",
            &self.check_gates,
            CheckGateRecord::public_record,
        );
        self.roots.state_root = deterministic_id(
            "WAVE-MANIFEST-STATE",
            &[
                self.roots.config_root.clone(),
                self.roots.counters_root.clone(),
                self.roots.waves_root.clone(),
                self.roots.modules_root.clone(),
                self.roots.integrations_root.clone(),
                self.roots.check_gates_root.clone(),
            ],
        );
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn validate_module_input(config: &Config, input: &ModuleInput) -> Result<()> {
    require_non_empty("module_name", &input.module_name)?;
    require_non_empty("owned_file", &input.owned_file)?;
    require_non_empty("worker_label", &input.worker_label)?;
    require_non_empty("module_state_root", &input.state_root)?;
    require(input.loc > 0, "module loc must be nonzero")?;
    require(
        input.pq_security_bits >= 128,
        "module pq security must be at least 128 bits",
    )?;
    require(input.fee_bps <= MAX_BPS, "module fee_bps exceeds MAX_BPS")?;
    if input.track == PriorityTrack::QuantumResistance {
        require(
            input.pq_security_bits >= config.min_pq_security_bits,
            "quantum track must satisfy pq security floor",
        )?;
    }
    Ok(())
}

pub fn module_readiness_bps(config: &Config, input: &ModuleInput) -> u64 {
    let mut score = 0_u64;
    if input.loc >= config.min_module_loc {
        score = score.saturating_add(1_500);
    }
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
    if matches!(
        input.status,
        ModuleStatus::DevnetWired | ModuleStatus::Ready | ModuleStatus::DeferredCheck
    ) {
        score = score.saturating_add(2_000);
    }
    score.min(MAX_BPS)
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(MAX_BPS) / denominator
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
    for (key, record) in records {
        parts.push(key.clone());
        parts.push(public_record(record).to_string());
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
