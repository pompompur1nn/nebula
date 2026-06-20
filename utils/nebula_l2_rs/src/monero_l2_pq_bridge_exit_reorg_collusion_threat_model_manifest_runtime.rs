use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitReorgCollusionThreatModelManifestRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_REORG_COLLUSION_THREAT_MODEL_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-reorg-collusion-threat-model-manifest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_REORG_COLLUSION_THREAT_MODEL_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const THREAT_MODEL_MANIFEST_SUITE: &str =
    "monero-l2-pq-bridge-exit-reorg-collusion-threat-model-manifest-v1";
pub const DEFAULT_MIN_THREAT_RECORDS: u64 = 7;
pub const DEFAULT_MONERO_FINALITY_DEPTH: u64 = 18;
pub const DEFAULT_DEEP_REORG_DEPTH: u64 = 54;
pub const DEFAULT_COLLUSION_THRESHOLD_BPS: u64 = 6_667;
pub const DEFAULT_MIN_WATCHER_WEIGHT: u64 = 5;
pub const DEFAULT_EXIT_RESERVE_BPS: u64 = 11_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 72;
pub const DEFAULT_SEQUENCER_SHUTDOWN_ESCAPE_BLOCKS: u64 = 36;
pub const DEFAULT_MAX_MANIFESTS: usize = 256;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatSurface {
    MoneroReorg,
    WatcherCollusion,
    LiquidityExhaustion,
    MetadataLeakage,
    NoBaseLayerVerifier,
    PqAuthorityCompromise,
    SequencerShutdown,
}

impl ThreatSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroReorg => "monero_reorg",
            Self::WatcherCollusion => "watcher_collusion",
            Self::LiquidityExhaustion => "liquidity_exhaustion",
            Self::MetadataLeakage => "metadata_leakage",
            Self::NoBaseLayerVerifier => "no_base_layer_verifier",
            Self::PqAuthorityCompromise => "pq_authority_compromise",
            Self::SequencerShutdown => "sequencer_shutdown",
        }
    }

    pub fn all() -> [Self; 7] {
        [
            Self::MoneroReorg,
            Self::WatcherCollusion,
            Self::LiquidityExhaustion,
            Self::MetadataLeakage,
            Self::NoBaseLayerVerifier,
            Self::PqAuthorityCompromise,
            Self::SequencerShutdown,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlClass {
    FinalityQuarantine,
    WatcherBondSlashing,
    LiquidityBackstop,
    PrivacyMinimization,
    DeferredVerifierDisclosure,
    PqRotationAndRevocation,
    ForcedExitEscape,
}

impl ControlClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FinalityQuarantine => "finality_quarantine",
            Self::WatcherBondSlashing => "watcher_bond_slashing",
            Self::LiquidityBackstop => "liquidity_backstop",
            Self::PrivacyMinimization => "privacy_minimization",
            Self::DeferredVerifierDisclosure => "deferred_verifier_disclosure",
            Self::PqRotationAndRevocation => "pq_rotation_and_revocation",
            Self::ForcedExitEscape => "forced_exit_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatSeverity {
    Critical,
    High,
    Medium,
}

impl ThreatSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResidualRisk {
    AcceptedDevnet,
    Watch,
    Blocked,
}

impl ResidualRisk {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AcceptedDevnet => "accepted_devnet",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestGateStatus {
    Ready,
    Watch,
    Blocked,
}

impl ManifestGateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub manifest_suite: String,
    pub min_threat_records: u64,
    pub monero_finality_depth: u64,
    pub deep_reorg_depth: u64,
    pub collusion_threshold_bps: u64,
    pub min_watcher_weight: u64,
    pub exit_reserve_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub challenge_window_blocks: u64,
    pub sequencer_shutdown_escape_blocks: u64,
    pub monero_base_layer_verifier_available: bool,
    pub cargo_checks_deferred: bool,
    pub runtime_tests_deferred: bool,
    pub release_readiness_deferred: bool,
    pub release_remediation_deferred: bool,
    pub production_release_allowed: bool,
    pub max_manifests: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            manifest_suite: THREAT_MODEL_MANIFEST_SUITE.to_string(),
            min_threat_records: DEFAULT_MIN_THREAT_RECORDS,
            monero_finality_depth: DEFAULT_MONERO_FINALITY_DEPTH,
            deep_reorg_depth: DEFAULT_DEEP_REORG_DEPTH,
            collusion_threshold_bps: DEFAULT_COLLUSION_THRESHOLD_BPS,
            min_watcher_weight: DEFAULT_MIN_WATCHER_WEIGHT,
            exit_reserve_bps: DEFAULT_EXIT_RESERVE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            sequencer_shutdown_escape_blocks: DEFAULT_SEQUENCER_SHUTDOWN_ESCAPE_BLOCKS,
            monero_base_layer_verifier_available: false,
            cargo_checks_deferred: true,
            runtime_tests_deferred: true,
            release_readiness_deferred: true,
            release_remediation_deferred: true,
            production_release_allowed: false,
            max_manifests: DEFAULT_MAX_MANIFESTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "manifest_suite": self.manifest_suite,
            "min_threat_records": self.min_threat_records,
            "monero_finality_depth": self.monero_finality_depth,
            "deep_reorg_depth": self.deep_reorg_depth,
            "collusion_threshold_bps": self.collusion_threshold_bps,
            "min_watcher_weight": self.min_watcher_weight,
            "exit_reserve_bps": self.exit_reserve_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "challenge_window_blocks": self.challenge_window_blocks,
            "sequencer_shutdown_escape_blocks": self.sequencer_shutdown_escape_blocks,
            "monero_base_layer_verifier_available": self.monero_base_layer_verifier_available,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "runtime_tests_deferred": self.runtime_tests_deferred,
            "release_readiness_deferred": self.release_readiness_deferred,
            "release_remediation_deferred": self.release_remediation_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_manifests": self.max_manifests,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ManifestCounters {
    pub total_threats: u64,
    pub critical_threats: u64,
    pub blocked_threats: u64,
    pub watch_threats: u64,
    pub devnet_accepted_threats: u64,
    pub release_blockers: u64,
    pub production_blockers: u64,
    pub controls_count: u64,
    pub evidence_links_count: u64,
}

impl ManifestCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "total_threats": self.total_threats,
            "critical_threats": self.critical_threats,
            "blocked_threats": self.blocked_threats,
            "watch_threats": self.watch_threats,
            "devnet_accepted_threats": self.devnet_accepted_threats,
            "release_blockers": self.release_blockers,
            "production_blockers": self.production_blockers,
            "controls_count": self.controls_count,
            "evidence_links_count": self.evidence_links_count,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ThreatControl {
    pub control_id: String,
    pub class: ControlClass,
    pub requirement: String,
    pub mechanism: String,
    pub verification_source: String,
    pub control_root: String,
}

impl ThreatControl {
    pub fn new(
        class: ControlClass,
        requirement: impl Into<String>,
        mechanism: impl Into<String>,
        verification_source: impl Into<String>,
    ) -> Self {
        let requirement = requirement.into();
        let mechanism = mechanism.into();
        let verification_source = verification_source.into();
        let control_root =
            threat_control_root(class, &requirement, &mechanism, &verification_source);
        let control_id = threat_control_id(class, &control_root);
        Self {
            control_id,
            class,
            requirement,
            mechanism,
            verification_source,
            control_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "control_id": self.control_id,
            "class": self.class.as_str(),
            "requirement": self.requirement,
            "mechanism": self.mechanism,
            "verification_source": self.verification_source,
            "control_root": self.control_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("threat_control", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ThreatRecord {
    pub threat_id: String,
    pub surface: ThreatSurface,
    pub severity: ThreatSeverity,
    pub residual_risk: ResidualRisk,
    pub title: String,
    pub assumption: String,
    pub failure_mode: String,
    pub safety_claim: String,
    pub detection: String,
    pub mitigation: String,
    pub remediation: String,
    pub evidence_links: Vec<String>,
    pub controls: Vec<ThreatControl>,
    pub release_blocker: bool,
    pub production_blocker: bool,
    pub evidence_root: String,
    pub control_root: String,
    pub threat_root: String,
}

impl ThreatRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        surface: ThreatSurface,
        severity: ThreatSeverity,
        residual_risk: ResidualRisk,
        title: impl Into<String>,
        assumption: impl Into<String>,
        failure_mode: impl Into<String>,
        safety_claim: impl Into<String>,
        detection: impl Into<String>,
        mitigation: impl Into<String>,
        remediation: impl Into<String>,
        evidence_links: Vec<String>,
        controls: Vec<ThreatControl>,
        release_blocker: bool,
        production_blocker: bool,
    ) -> Self {
        let title = title.into();
        let assumption = assumption.into();
        let failure_mode = failure_mode.into();
        let safety_claim = safety_claim.into();
        let detection = detection.into();
        let mitigation = mitigation.into();
        let remediation = remediation.into();
        let evidence_root = evidence_links_root(&evidence_links);
        let control_root = controls_root(&controls);
        let threat_root = threat_record_root(
            surface,
            severity,
            residual_risk,
            &title,
            &assumption,
            &failure_mode,
            &safety_claim,
            &detection,
            &mitigation,
            &remediation,
            &evidence_root,
            &control_root,
            release_blocker,
            production_blocker,
        );
        let threat_id = threat_record_id(surface, &threat_root);
        Self {
            threat_id,
            surface,
            severity,
            residual_risk,
            title,
            assumption,
            failure_mode,
            safety_claim,
            detection,
            mitigation,
            remediation,
            evidence_links,
            controls,
            release_blocker,
            production_blocker,
            evidence_root,
            control_root,
            threat_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "threat_id": self.threat_id,
            "surface": self.surface.as_str(),
            "severity": self.severity.as_str(),
            "residual_risk": self.residual_risk.as_str(),
            "title": self.title,
            "assumption": self.assumption,
            "failure_mode": self.failure_mode,
            "safety_claim": self.safety_claim,
            "detection": self.detection,
            "mitigation": self.mitigation,
            "remediation": self.remediation,
            "evidence_links": self.evidence_links,
            "controls": self.controls.iter().map(ThreatControl::public_record).collect::<Vec<_>>(),
            "release_blocker": self.release_blocker,
            "production_blocker": self.production_blocker,
            "evidence_root": self.evidence_root,
            "control_root": self.control_root,
            "threat_root": self.threat_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("threat_record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ThreatModelManifest {
    pub manifest_id: String,
    pub status: ManifestGateStatus,
    pub readiness_label: String,
    pub source_spine_root: String,
    pub source_simulation_root: String,
    pub source_safety_case_root: String,
    pub source_readiness_root: String,
    pub source_remediation_root: String,
    pub config_root: String,
    pub threat_root: String,
    pub counters_root: String,
    pub gate_root: String,
    pub release_summary: String,
    pub production_summary: String,
}

impl ThreatModelManifest {
    pub fn public_record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "source_spine_root": self.source_spine_root,
            "source_simulation_root": self.source_simulation_root,
            "source_safety_case_root": self.source_safety_case_root,
            "source_readiness_root": self.source_readiness_root,
            "source_remediation_root": self.source_remediation_root,
            "config_root": self.config_root,
            "threat_root": self.threat_root,
            "counters_root": self.counters_root,
            "gate_root": self.gate_root,
            "release_summary": self.release_summary,
            "production_summary": self.production_summary,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("manifest", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub threats: BTreeMap<String, ThreatRecord>,
    pub counters: ManifestCounters,
    pub manifest: ThreatModelManifest,
    pub state_root: String,
}

impl State {
    pub fn new(
        config: Config,
        source_spine_root: impl Into<String>,
        source_simulation_root: impl Into<String>,
        source_safety_case_root: impl Into<String>,
        source_readiness_root: impl Into<String>,
        source_remediation_root: impl Into<String>,
    ) -> Result<Self> {
        let source_spine_root = source_spine_root.into();
        let source_simulation_root = source_simulation_root.into();
        let source_safety_case_root = source_safety_case_root.into();
        let source_readiness_root = source_readiness_root.into();
        let source_remediation_root = source_remediation_root.into();
        ensure(
            config.collusion_threshold_bps <= MAX_BPS,
            "collusion threshold exceeds bps max",
        )?;
        ensure(
            config.exit_reserve_bps >= MAX_BPS,
            "exit reserve must cover at least one full notional",
        )?;
        ensure(config.max_manifests > 0, "max manifests must be positive")?;

        let threat_vec = devnet_threat_records(&config);
        ensure(
            threat_vec.len() as u64 >= config.min_threat_records,
            "threat manifest is missing required surfaces",
        )?;
        let mut threats = BTreeMap::new();
        for threat in threat_vec {
            threats.insert(threat.threat_id.clone(), threat);
        }
        let counters = ManifestCounters::from_threats(&threats);
        let config_root = config.state_root();
        let threat_root = threats_root(&threats);
        let counters_root = counters.state_root();
        let status = aggregate_status(&config, &counters);
        let readiness_label = readiness_label(status, &config, &counters).to_string();
        let release_summary = release_summary(status, &counters);
        let production_summary = production_summary(&config, &counters);
        let gate_root = manifest_gate_root(
            status,
            &readiness_label,
            &source_spine_root,
            &source_simulation_root,
            &source_safety_case_root,
            &source_readiness_root,
            &source_remediation_root,
            &config_root,
            &threat_root,
            &counters_root,
        );
        let manifest_id = manifest_id(&gate_root, &threat_root);
        let manifest = ThreatModelManifest {
            manifest_id,
            status,
            readiness_label,
            source_spine_root,
            source_simulation_root,
            source_safety_case_root,
            source_readiness_root,
            source_remediation_root,
            config_root,
            threat_root,
            counters_root,
            gate_root,
            release_summary,
            production_summary,
        };
        let state_root = state_root_value(&config, &threats, &counters, &manifest);
        Ok(Self {
            config,
            threats,
            counters,
            manifest,
            state_root,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let source_spine_root =
            source_reference_root("trust_minimized_bridge_exit_spine", "devnet");
        let source_simulation_root =
            source_reference_root("reorg_watcher_collusion_simulation", "devnet");
        let source_safety_case_root = source_reference_root("end_to_end_safety_case", "devnet");
        let source_readiness_root = source_reference_root("release_readiness_integrator", "devnet");
        let source_remediation_root =
            source_reference_root("release_remediation_planner", "devnet");
        match Self::new(
            config,
            source_spine_root,
            source_simulation_root,
            source_safety_case_root,
            source_readiness_root,
            source_remediation_root,
        ) {
            Ok(state) => state,
            Err(_) => empty_blocked_devnet_state(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "threats": self.threats.values().map(ThreatRecord::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "manifest": self.manifest.public_record(),
            "state_root": self.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }
}

impl ManifestCounters {
    pub fn from_threats(threats: &BTreeMap<String, ThreatRecord>) -> Self {
        let mut counters = Self::default();
        counters.total_threats = threats.len() as u64;
        for threat in threats.values() {
            if threat.severity == ThreatSeverity::Critical {
                counters.critical_threats = counters.critical_threats.saturating_add(1);
            }
            match threat.residual_risk {
                ResidualRisk::Blocked => {
                    counters.blocked_threats = counters.blocked_threats.saturating_add(1)
                }
                ResidualRisk::Watch => {
                    counters.watch_threats = counters.watch_threats.saturating_add(1)
                }
                ResidualRisk::AcceptedDevnet => {
                    counters.devnet_accepted_threats =
                        counters.devnet_accepted_threats.saturating_add(1)
                }
            }
            if threat.release_blocker {
                counters.release_blockers = counters.release_blockers.saturating_add(1);
            }
            if threat.production_blocker {
                counters.production_blockers = counters.production_blockers.saturating_add(1);
            }
            counters.controls_count = counters
                .controls_count
                .saturating_add(threat.controls.len() as u64);
            counters.evidence_links_count = counters
                .evidence_links_count
                .saturating_add(threat.evidence_links.len() as u64);
        }
        counters
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn devnet_threat_records(config: &Config) -> Vec<ThreatRecord> {
    vec![
        ThreatRecord::new(
            ThreatSurface::MoneroReorg,
            ThreatSeverity::Critical,
            ResidualRisk::Watch,
            "Monero reorg invalidates a certified lock or release path",
            format!(
                "watchers treat {} confirmations as normal finality and {} blocks as deep reorg stress",
                config.monero_finality_depth, config.deep_reorg_depth
            ),
            "a reorg removes or replaces a lock transaction after watcher certification",
            "release remains quarantined unless the watcher certificate survives reorg challenge evidence",
            "header-depth adapter, reorg watcher collusion simulation, and challenge transcript roots",
            "quarantine below finality, extend deep-reorg challenge window, and bind release to transcript root",
            "materialize live Monero header adapter evidence before production release",
            evidence_links("reorg_watcher_collusion_simulation", "end_to_end_safety_case"),
            vec![ThreatControl::new(
                ControlClass::FinalityQuarantine,
                "certified deposits must remain challengeable through the deep reorg window",
                "delay settlement until finality depth and challenge transcript agree",
                "monero_l2_pq_bridge_exit_reorg_watcher_collusion_simulation_runtime",
            )],
            false,
            true,
        ),
        ThreatRecord::new(
            ThreatSurface::WatcherCollusion,
            ThreatSeverity::Critical,
            ResidualRisk::Blocked,
            "Watcher quorum colludes to certify false or stale evidence",
            format!(
                "collusion at or above {} bps can satisfy the nominal watcher quorum",
                config.collusion_threshold_bps
            ),
            "bonded watchers coordinate equivocation, delayed liveness evidence, or false finality",
            "collusion must be slashable and must block release when certificate roots disagree",
            "watcher quorum root, equivocation evidence root, and collusion simulation case roots",
            "require independent watcher weight, slashing settlement, and crosschecked certificate roots",
            "wire live slashing settlement and independent watcher set readiness before clearing gate",
            evidence_links("reorg_watcher_collusion_simulation", "trust_minimized_bridge_exit_spine"),
            vec![ThreatControl::new(
                ControlClass::WatcherBondSlashing,
                "quorum evidence must be slashable when challenged",
                "derive release authority from watcher roots and slash equivocation roots",
                "monero_l2_pq_bridge_exit_watcher_bond_slashing_runtime",
            )],
            true,
            true,
        ),
        ThreatRecord::new(
            ThreatSurface::LiquidityExhaustion,
            ThreatSeverity::High,
            ResidualRisk::Watch,
            "Exit liquidity is exhausted during reorg or shutdown pressure",
            format!(
                "reserve target is {} bps with forced-exit challenge window {} blocks",
                config.exit_reserve_bps, config.challenge_window_blocks
            ),
            "claims queue exceeds reserve, delaying user withdrawal while adverse events compound",
            "liquidity shortfall is visible, rate limited, and routed to reserve release remediation",
            "liquidity reserve release reports, claim queue roots, and remediation plan roots",
            "reserve above full notional, queue throttling, reserve release adapter, and user-first remediation",
            "complete reserve release live adapter and liquidity exhaustion runbook",
            evidence_links("release_readiness_integrator", "release_remediation_planner"),
            vec![ThreatControl::new(
                ControlClass::LiquidityBackstop,
                "forced exits must not silently consume more reserve than policy allows",
                "publish reserve roots and block production release on uncovered claims",
                "monero_l2_pq_bridge_exit_liquidity_reserve_release_runtime",
            )],
            false,
            true,
        ),
        ThreatRecord::new(
            ThreatSurface::MetadataLeakage,
            ThreatSeverity::High,
            ResidualRisk::Watch,
            "Bridge metadata links private receipts, watcher timing, and exit claims",
            format!(
                "privacy set must stay at or above {} members for manifest acceptance",
                config.min_privacy_set_size
            ),
            "amount buckets, timing, view tags, or watcher identities correlate deposit and exit",
            "public records expose roots and counters while private payloads remain undisclosed",
            "wallet receipt privacy fixtures, safety case privacy requirements, and metadata leak cases",
            "use roots-only disclosure, privacy set thresholds, scanner isolation, and delayed release labels",
            "promote metadata leakage probes into release-readiness evidence",
            evidence_links("wallet_receipt_privacy_fixture", "end_to_end_safety_case"),
            vec![ThreatControl::new(
                ControlClass::PrivacyMinimization,
                "manifest records must avoid direct user metadata and raw receipt payloads",
                "hash evidence, disclose roots, and count coverage without publishing private fields",
                "monero_l2_pq_bridge_exit_wallet_receipt_privacy_fixture_runtime",
            )],
            false,
            true,
        ),
        ThreatRecord::new(
            ThreatSurface::NoBaseLayerVerifier,
            ThreatSeverity::Critical,
            ResidualRisk::Blocked,
            "No Monero base-layer verifier exists for trustless release validation",
            "base-layer verification is explicitly unavailable in devnet manifest configuration",
            "release correctness depends on adapters, watcher attestations, and challenge evidence",
            "production release remains blocked until the limitation is disclosed or replaced by verifier evidence",
            "safety case base-layer limitation, release readiness gate, and remediation roots",
            "fail closed, label deferred verifier limitation, and require production gate blocker",
            "deliver a verifier, audited adapter substitute, or explicit release-blocking acceptance memo",
            evidence_links("end_to_end_safety_case", "release_readiness_integrator"),
            vec![ThreatControl::new(
                ControlClass::DeferredVerifierDisclosure,
                "absence of base-layer verifier must be a first-class release blocker",
                "record the limitation in public manifest roots and remediation actions",
                "monero_l2_pq_bridge_exit_end_to_end_safety_case_runtime",
            )],
            true,
            true,
        ),
        ThreatRecord::new(
            ThreatSurface::PqAuthorityCompromise,
            ThreatSeverity::Critical,
            ResidualRisk::Blocked,
            "PQ authority compromise signs hazardous release or rotation state",
            format!(
                "control plane requires at least {} PQ security bits",
                config.min_pq_security_bits
            ),
            "authority key compromise authorizes stale, forged, or unilateral release records",
            "authority signatures must be crosschecked, rotatable, and unable to bypass challenge roots",
            "PQ authority verification, key manager adapter, safety case, and remediation roots",
            "split authority roots, rotate compromised keys, revoke stale roots, and block unilateral release",
            "complete PQ authority compromise drill and key manager live readiness",
            evidence_links("pq_authority_key_manager", "authority_crosscheck_verifier"),
            vec![ThreatControl::new(
                ControlClass::PqRotationAndRevocation,
                "compromised PQ authority must be containable without unilateral release",
                "bind authority root to challenge, watcher, and release readiness roots",
                "monero_l2_pq_bridge_exit_pq_authority_key_manager_adapter_runtime",
            )],
            true,
            true,
        ),
        ThreatRecord::new(
            ThreatSurface::SequencerShutdown,
            ThreatSeverity::High,
            ResidualRisk::Watch,
            "Sequencer shutdown blocks normal exit progression",
            format!(
                "forced-exit escape must arm within {} blocks",
                config.sequencer_shutdown_escape_blocks
            ),
            "sequencer stops ordering exits, withholding liveness and settlement progress",
            "users can force exit through an always-available path with challenge-before-settlement semantics",
            "trust-minimized bridge exit spine, forced-exit playbook, and release remediation roots",
            "forced exit escape, liveness timers, claim queue publication, and user recovery playbook",
            "finish user-facing forced-exit recovery answer and readiness gate evidence",
            evidence_links("trust_minimized_bridge_exit_spine", "forced_exit_user_recovery_playbook"),
            vec![ThreatControl::new(
                ControlClass::ForcedExitEscape,
                "sequencer downtime must not prevent users from entering forced exit",
                "arm forced exit by timer and settle only after challenge window closes",
                "monero_l2_pq_trust_minimized_bridge_exit_spine_runtime",
            )],
            false,
            true,
        ),
    ]
}

fn aggregate_status(config: &Config, counters: &ManifestCounters) -> ManifestGateStatus {
    if counters.blocked_threats > 0
        || counters.release_blockers > 0
        || !config.monero_base_layer_verifier_available
    {
        ManifestGateStatus::Blocked
    } else if counters.watch_threats > 0
        || config.cargo_checks_deferred
        || config.runtime_tests_deferred
        || config.release_readiness_deferred
        || config.release_remediation_deferred
    {
        ManifestGateStatus::Watch
    } else {
        ManifestGateStatus::Ready
    }
}

fn readiness_label(
    status: ManifestGateStatus,
    config: &Config,
    counters: &ManifestCounters,
) -> &'static str {
    match status {
        ManifestGateStatus::Blocked if !config.monero_base_layer_verifier_available => {
            "threat_model_blocked_no_monero_base_layer_verifier"
        }
        ManifestGateStatus::Blocked if counters.release_blockers > 0 => {
            "threat_model_blocked_release_safety"
        }
        ManifestGateStatus::Blocked => "threat_model_blocked",
        ManifestGateStatus::Watch => "threat_model_watch_deferred_evidence",
        ManifestGateStatus::Ready => "threat_model_ready",
    }
}

fn release_summary(status: ManifestGateStatus, counters: &ManifestCounters) -> String {
    format!(
        "status={} total_threats={} release_blockers={} watch_threats={}",
        status.as_str(),
        counters.total_threats,
        counters.release_blockers,
        counters.watch_threats
    )
}

fn production_summary(config: &Config, counters: &ManifestCounters) -> String {
    format!(
        "production_allowed={} production_blockers={} base_layer_verifier={}",
        bool_str(config.production_release_allowed),
        counters.production_blockers,
        bool_str(config.monero_base_layer_verifier_available)
    )
}

fn evidence_links(primary: &str, secondary: &str) -> Vec<String> {
    vec![
        format!("conceptual:{primary}"),
        format!("conceptual:{secondary}"),
        "conceptual:release_readiness_and_remediation".to_string(),
    ]
}

pub fn threat_control_id(class: ControlClass, control_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-REORG-COLLUSION-THREAT-CONTROL-ID",
        &[HashPart::Str(class.as_str()), HashPart::Str(control_root)],
        32,
    )
}

pub fn threat_control_root(
    class: ControlClass,
    requirement: &str,
    mechanism: &str,
    verification_source: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-REORG-COLLUSION-THREAT-CONTROL-ROOT",
        &[
            HashPart::Str(class.as_str()),
            HashPart::Str(requirement),
            HashPart::Str(mechanism),
            HashPart::Str(verification_source),
        ],
        32,
    )
}

pub fn evidence_links_root(evidence_links: &[String]) -> String {
    let leaves = evidence_links
        .iter()
        .map(|link| {
            domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-THREAT-EVIDENCE-LINK",
                &[HashPart::Str(link)],
                32,
            )
        })
        .collect::<Vec<_>>();
    merkle_root(&leaves)
}

pub fn controls_root(controls: &[ThreatControl]) -> String {
    let leaves = controls
        .iter()
        .map(ThreatControl::state_root)
        .collect::<Vec<_>>();
    merkle_root(&leaves)
}

#[allow(clippy::too_many_arguments)]
pub fn threat_record_root(
    surface: ThreatSurface,
    severity: ThreatSeverity,
    residual_risk: ResidualRisk,
    title: &str,
    assumption: &str,
    failure_mode: &str,
    safety_claim: &str,
    detection: &str,
    mitigation: &str,
    remediation: &str,
    evidence_root: &str,
    control_root: &str,
    release_blocker: bool,
    production_blocker: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-REORG-COLLUSION-THREAT-RECORD-ROOT",
        &[
            HashPart::Str(surface.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Str(residual_risk.as_str()),
            HashPart::Str(title),
            HashPart::Str(assumption),
            HashPart::Str(failure_mode),
            HashPart::Str(safety_claim),
            HashPart::Str(detection),
            HashPart::Str(mitigation),
            HashPart::Str(remediation),
            HashPart::Str(evidence_root),
            HashPart::Str(control_root),
            HashPart::Str(bool_str(release_blocker)),
            HashPart::Str(bool_str(production_blocker)),
        ],
        32,
    )
}

pub fn threat_record_id(surface: ThreatSurface, threat_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-REORG-COLLUSION-THREAT-RECORD-ID",
        &[HashPart::Str(surface.as_str()), HashPart::Str(threat_root)],
        32,
    )
}

pub fn threats_root(threats: &BTreeMap<String, ThreatRecord>) -> String {
    let leaves = threats
        .values()
        .map(ThreatRecord::state_root)
        .collect::<Vec<_>>();
    merkle_root(&leaves)
}

#[allow(clippy::too_many_arguments)]
pub fn manifest_gate_root(
    status: ManifestGateStatus,
    readiness_label: &str,
    source_spine_root: &str,
    source_simulation_root: &str,
    source_safety_case_root: &str,
    source_readiness_root: &str,
    source_remediation_root: &str,
    config_root: &str,
    threat_root: &str,
    counters_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-REORG-COLLUSION-THREAT-MANIFEST-GATE-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_spine_root),
            HashPart::Str(source_simulation_root),
            HashPart::Str(source_safety_case_root),
            HashPart::Str(source_readiness_root),
            HashPart::Str(source_remediation_root),
            HashPart::Str(config_root),
            HashPart::Str(threat_root),
            HashPart::Str(counters_root),
        ],
        32,
    )
}

pub fn manifest_id(gate_root: &str, threat_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-REORG-COLLUSION-THREAT-MANIFEST-ID",
        &[HashPart::Str(gate_root), HashPart::Str(threat_root)],
        32,
    )
}

pub fn source_reference_root(source_kind: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-REORG-COLLUSION-THREAT-SOURCE-REFERENCE",
        &[HashPart::Str(source_kind), HashPart::Str(label)],
        32,
    )
}

pub fn state_root_value(
    config: &Config,
    threats: &BTreeMap<String, ThreatRecord>,
    counters: &ManifestCounters,
    manifest: &ThreatModelManifest,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-REORG-COLLUSION-THREAT-MANIFEST-STATE",
        &[
            HashPart::Str(&config.state_root()),
            HashPart::Str(&threats_root(threats)),
            HashPart::Str(&counters.state_root()),
            HashPart::Str(&manifest.state_root()),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-REORG-COLLUSION-THREAT-MANIFEST-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

pub fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn empty_blocked_devnet_state() -> State {
    let config = Config::devnet();
    let threats = BTreeMap::new();
    let counters = ManifestCounters::default();
    let config_root = config.state_root();
    let threat_root = threats_root(&threats);
    let counters_root = counters.state_root();
    let gate_root = manifest_gate_root(
        ManifestGateStatus::Blocked,
        "threat_model_blocked_empty_devnet",
        "",
        "",
        "",
        "",
        "",
        &config_root,
        &threat_root,
        &counters_root,
    );
    let manifest = ThreatModelManifest {
        manifest_id: manifest_id(&gate_root, &threat_root),
        status: ManifestGateStatus::Blocked,
        readiness_label: "threat_model_blocked_empty_devnet".to_string(),
        source_spine_root: String::new(),
        source_simulation_root: String::new(),
        source_safety_case_root: String::new(),
        source_readiness_root: String::new(),
        source_remediation_root: String::new(),
        config_root,
        threat_root,
        counters_root,
        gate_root,
        release_summary: "status=blocked total_threats=0 release_blockers=0 watch_threats=0"
            .to_string(),
        production_summary:
            "production_allowed=false production_blockers=0 base_layer_verifier=false".to_string(),
    };
    let state_root = state_root_value(&config, &threats, &counters, &manifest);
    State {
        config,
        threats,
        counters,
        manifest,
        state_root,
    }
}
