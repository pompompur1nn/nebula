use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitVerticalSliceFailureInjectionMatrixRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_VERTICAL_SLICE_FAILURE_INJECTION_MATRIX_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-vertical-slice-failure-injection-matrix-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_VERTICAL_SLICE_FAILURE_INJECTION_MATRIX_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const MATRIX_SUITE: &str =
    "monero-l2-pq-bridge-exit-vertical-slice-failure-injection-matrix-v1";
pub const DEVNET_MATRIX_LABEL: &str = "devnet-monero-private-l2-bridge-exit-security-spine";
pub const DEFAULT_MIN_REQUIRED_CASES: u64 = 8;
pub const DEFAULT_MIN_USER_ESCAPE_CASES: u64 = 8;
pub const DEFAULT_MAX_CASES: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionKind {
    SequencerShutdown,
    WatcherCollusion,
    MoneroReorg,
    LiquidityExhaustion,
    PqAuthorityCompromise,
    MetadataLeak,
    StaleWalletScanHints,
    DisputedExitExecution,
}

impl InjectionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerShutdown => "sequencer_shutdown",
            Self::WatcherCollusion => "watcher_collusion",
            Self::MoneroReorg => "monero_reorg",
            Self::LiquidityExhaustion => "liquidity_exhaustion",
            Self::PqAuthorityCompromise => "pq_authority_compromise",
            Self::MetadataLeak => "metadata_leak",
            Self::StaleWalletScanHints => "stale_wallet_scan_hints",
            Self::DisputedExitExecution => "disputed_exit_execution",
        }
    }

    pub fn threat_surface(self) -> &'static str {
        match self {
            Self::SequencerShutdown => "liveness_and_censorship",
            Self::WatcherCollusion => "quorum_integrity",
            Self::MoneroReorg => "base_layer_finality",
            Self::LiquidityExhaustion => "exit_liquidity_accounting",
            Self::PqAuthorityCompromise => "post_quantum_authority_control_plane",
            Self::MetadataLeak => "privacy_metadata_minimization",
            Self::StaleWalletScanHints => "wallet_scan_freshness",
            Self::DisputedExitExecution => "challenge_before_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionStatus {
    Contained,
    Watch,
    Failed,
}

impl InjectionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contained => "contained",
            Self::Watch => "watch",
            Self::Failed => "failed",
        }
    }

    pub fn is_contained(self) -> bool {
        matches!(self, Self::Contained)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserEscapeOutcome {
    ForcedExitAvailable,
    ChallengeBlocksSettlement,
    ReorgQuarantine,
    LiquidityBackstopRequired,
    AuthorityRotationRequired,
    PrivacyBudgetQuarantine,
    WalletRescanRequired,
}

impl UserEscapeOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ForcedExitAvailable => "forced_exit_available",
            Self::ChallengeBlocksSettlement => "challenge_blocks_settlement",
            Self::ReorgQuarantine => "reorg_quarantine",
            Self::LiquidityBackstopRequired => "liquidity_backstop_required",
            Self::AuthorityRotationRequired => "authority_rotation_required",
            Self::PrivacyBudgetQuarantine => "privacy_budget_quarantine",
            Self::WalletRescanRequired => "wallet_rescan_required",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionGate {
    CargoChecksDeferred,
    SecurityAuditDeferred,
    MoneroFinalityHarnessDeferred,
    LiquidityBackstopProofDeferred,
    PqAuthorityCeremonyDeferred,
    PrivacyLeakageReviewDeferred,
    WalletHintFreshnessHarnessDeferred,
    DisputeExecutionHarnessDeferred,
}

impl ProductionGate {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoChecksDeferred => "cargo_checks_deferred",
            Self::SecurityAuditDeferred => "security_audit_deferred",
            Self::MoneroFinalityHarnessDeferred => "monero_finality_harness_deferred",
            Self::LiquidityBackstopProofDeferred => "liquidity_backstop_proof_deferred",
            Self::PqAuthorityCeremonyDeferred => "pq_authority_ceremony_deferred",
            Self::PrivacyLeakageReviewDeferred => "privacy_leakage_review_deferred",
            Self::WalletHintFreshnessHarnessDeferred => "wallet_hint_freshness_harness_deferred",
            Self::DisputeExecutionHarnessDeferred => "dispute_execution_harness_deferred",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixVerdict {
    EscapePathDocumented,
    Watch,
    Failed,
}

impl MatrixVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EscapePathDocumented => "escape_path_documented",
            Self::Watch => "watch",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub matrix_suite: String,
    pub label: String,
    pub min_required_cases: u64,
    pub min_user_escape_cases: u64,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub max_cases: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            matrix_suite: MATRIX_SUITE.to_string(),
            label: DEVNET_MATRIX_LABEL.to_string(),
            min_required_cases: DEFAULT_MIN_REQUIRED_CASES,
            min_user_escape_cases: DEFAULT_MIN_USER_ESCAPE_CASES,
            cargo_checks_deferred: true,
            production_release_allowed: false,
            max_cases: DEFAULT_MAX_CASES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "matrix_suite": self.matrix_suite,
            "label": self.label,
            "min_required_cases": self.min_required_cases,
            "min_user_escape_cases": self.min_user_escape_cases,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_cases": self.max_cases,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FailureInjectionCase {
    pub case_id: String,
    pub kind: InjectionKind,
    pub status: InjectionStatus,
    pub injected_failure: String,
    pub expected_user_escape_outcome: UserEscapeOutcome,
    pub observed_spine_response: String,
    pub blocked_production_gates: Vec<ProductionGate>,
    pub invariant: String,
    pub operator_action: String,
    pub user_action: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub evidence_root: String,
    pub release_gate_root: String,
    pub case_root: String,
}

impl FailureInjectionCase {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        case_id: impl Into<String>,
        kind: InjectionKind,
        status: InjectionStatus,
        injected_failure: impl Into<String>,
        expected_user_escape_outcome: UserEscapeOutcome,
        observed_spine_response: impl Into<String>,
        blocked_production_gates: Vec<ProductionGate>,
        invariant: impl Into<String>,
        operator_action: impl Into<String>,
        user_action: impl Into<String>,
        pre_state_root: impl Into<String>,
        post_state_root: impl Into<String>,
    ) -> Self {
        let case_id = case_id.into();
        let injected_failure = injected_failure.into();
        let observed_spine_response = observed_spine_response.into();
        let invariant = invariant.into();
        let operator_action = operator_action.into();
        let user_action = user_action.into();
        let pre_state_root = pre_state_root.into();
        let post_state_root = post_state_root.into();
        let gate_values = blocked_production_gates
            .iter()
            .map(|gate| Value::String(gate.as_str().to_string()))
            .collect::<Vec<_>>();
        let release_gate_root = merkle_root("failure_injection_case_release_gates", &gate_values);
        let evidence_root = domain_hash(
            "failure_injection_case_evidence",
            &[
                HashPart::Str(&case_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(status.as_str()),
                HashPart::Str(&injected_failure),
                HashPart::Str(expected_user_escape_outcome.as_str()),
                HashPart::Str(&observed_spine_response),
                HashPart::Str(&invariant),
                HashPart::Str(&operator_action),
                HashPart::Str(&user_action),
                HashPart::Str(&pre_state_root),
                HashPart::Str(&post_state_root),
                HashPart::Str(&release_gate_root),
            ],
            32,
        );
        let case_root = domain_hash(
            "failure_injection_case",
            &[
                HashPart::Str(&case_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(status.as_str()),
                HashPart::Str(expected_user_escape_outcome.as_str()),
                HashPart::Str(&evidence_root),
                HashPart::Str(&release_gate_root),
            ],
            32,
        );

        Self {
            case_id,
            kind,
            status,
            injected_failure,
            expected_user_escape_outcome,
            observed_spine_response,
            blocked_production_gates,
            invariant,
            operator_action,
            user_action,
            pre_state_root,
            post_state_root,
            evidence_root,
            release_gate_root,
            case_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "kind": self.kind.as_str(),
            "threat_surface": self.kind.threat_surface(),
            "status": self.status.as_str(),
            "injected_failure": self.injected_failure,
            "expected_user_escape_outcome": self.expected_user_escape_outcome.as_str(),
            "observed_spine_response": self.observed_spine_response,
            "blocked_production_gates": self.blocked_production_gates.iter().map(|gate| gate.as_str()).collect::<Vec<_>>(),
            "invariant": self.invariant,
            "operator_action": self.operator_action,
            "user_action": self.user_action,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "evidence_root": self.evidence_root,
            "release_gate_root": self.release_gate_root,
            "case_root": self.case_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("failure_injection_case", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub total_cases: u64,
    pub contained_cases: u64,
    pub watch_cases: u64,
    pub failed_cases: u64,
    pub user_escape_cases: u64,
    pub blocked_gate_count: u64,
}

impl Counters {
    pub fn from_cases(cases: &BTreeMap<String, FailureInjectionCase>) -> Self {
        let total_cases = cases.len() as u64;
        let contained_cases = cases
            .values()
            .filter(|case| case.status.is_contained())
            .count() as u64;
        let watch_cases = cases
            .values()
            .filter(|case| matches!(case.status, InjectionStatus::Watch))
            .count() as u64;
        let failed_cases = cases
            .values()
            .filter(|case| matches!(case.status, InjectionStatus::Failed))
            .count() as u64;
        let user_escape_cases = cases
            .values()
            .filter(|case| {
                matches!(
                    case.expected_user_escape_outcome,
                    UserEscapeOutcome::ForcedExitAvailable
                        | UserEscapeOutcome::ChallengeBlocksSettlement
                        | UserEscapeOutcome::ReorgQuarantine
                        | UserEscapeOutcome::LiquidityBackstopRequired
                        | UserEscapeOutcome::AuthorityRotationRequired
                        | UserEscapeOutcome::PrivacyBudgetQuarantine
                        | UserEscapeOutcome::WalletRescanRequired
                )
            })
            .count() as u64;
        let blocked_gate_count = cases
            .values()
            .map(|case| case.blocked_production_gates.len() as u64)
            .sum();

        Self {
            total_cases,
            contained_cases,
            watch_cases,
            failed_cases,
            user_escape_cases,
            blocked_gate_count,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_cases": self.total_cases,
            "contained_cases": self.contained_cases,
            "watch_cases": self.watch_cases,
            "failed_cases": self.failed_cases,
            "user_escape_cases": self.user_escape_cases,
            "blocked_gate_count": self.blocked_gate_count,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub cases_root: String,
    pub counters_root: String,
    pub blocked_gates_root: String,
    pub expected_user_escape_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn new(
        config: &Config,
        cases: &BTreeMap<String, FailureInjectionCase>,
        counters: &Counters,
    ) -> Self {
        let config_root = config.state_root();
        let case_records = cases
            .values()
            .map(FailureInjectionCase::public_record)
            .collect::<Vec<_>>();
        let cases_root = merkle_root("failure_injection_matrix_cases", &case_records);
        let gate_records = cases
            .values()
            .flat_map(|case| {
                case.blocked_production_gates.iter().map(|gate| {
                    json!({
                        "case_id": case.case_id,
                        "gate": gate.as_str(),
                    })
                })
            })
            .collect::<Vec<_>>();
        let blocked_gates_root =
            merkle_root("failure_injection_matrix_blocked_gates", &gate_records);
        let escape_records = cases
            .values()
            .map(|case| {
                json!({
                    "case_id": case.case_id,
                    "expected_user_escape_outcome": case.expected_user_escape_outcome.as_str(),
                    "user_action": case.user_action,
                })
            })
            .collect::<Vec<_>>();
        let expected_user_escape_root =
            merkle_root("failure_injection_matrix_user_escape", &escape_records);
        let counters_root = counters.state_root();
        let mut roots = Self {
            config_root,
            cases_root,
            counters_root,
            blocked_gates_root,
            expected_user_escape_root,
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "cases_root": self.cases_root,
            "counters_root": self.counters_root,
            "blocked_gates_root": self.blocked_gates_root,
            "expected_user_escape_root": self.expected_user_escape_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert(
                "state_root".to_string(),
                Value::String(self.state_root.clone()),
            );
        }
        record
    }

    pub fn compute_state_root(&self) -> String {
        record_root("roots", &self.public_record_without_state_root())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MatrixReport {
    pub report_id: String,
    pub verdict: MatrixVerdict,
    pub expected_user_escape_outcome: String,
    pub blocked_production_gates: Vec<String>,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub matrix_root: String,
}

impl MatrixReport {
    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "verdict": self.verdict.as_str(),
            "expected_user_escape_outcome": self.expected_user_escape_outcome,
            "blocked_production_gates": self.blocked_production_gates,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "matrix_root": self.matrix_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("matrix_report", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub cases: BTreeMap<String, FailureInjectionCase>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        let cases = devnet_cases(&config)?;
        Self::from_cases(config, cases)
    }

    pub fn from_cases(
        config: Config,
        cases: BTreeMap<String, FailureInjectionCase>,
    ) -> Result<Self> {
        if cases.len() > config.max_cases {
            return Err("failure injection matrix exceeds configured case capacity".to_string());
        }
        let counters = Counters::from_cases(&cases);
        if counters.total_cases < config.min_required_cases {
            return Err("failure injection matrix lacks required case coverage".to_string());
        }
        if counters.user_escape_cases < config.min_user_escape_cases {
            return Err("failure injection matrix lacks required user escape coverage".to_string());
        }
        let roots = Roots::new(&config, &cases, &counters);
        Ok(Self {
            config,
            cases,
            counters,
            roots,
        })
    }

    pub fn devnet() -> Result<Self> {
        Self::new(Config::devnet())
    }

    pub fn verdict(&self) -> MatrixVerdict {
        if self.counters.failed_cases > 0 {
            MatrixVerdict::Failed
        } else if self.counters.watch_cases > 0 {
            MatrixVerdict::Watch
        } else {
            MatrixVerdict::EscapePathDocumented
        }
    }

    pub fn blocked_production_gates(&self) -> Vec<String> {
        let mut gates = self
            .cases
            .values()
            .flat_map(|case| {
                case.blocked_production_gates
                    .iter()
                    .map(|gate| gate.as_str())
            })
            .collect::<Vec<_>>();
        gates.sort_unstable();
        gates.dedup();
        gates.into_iter().map(str::to_string).collect()
    }

    pub fn matrix_report(&self) -> MatrixReport {
        MatrixReport {
            report_id: "devnet-failure-injection-matrix-report".to_string(),
            verdict: self.verdict(),
            expected_user_escape_outcome:
                "every injected failure preserves a documented non-custodial escape path"
                    .to_string(),
            blocked_production_gates: self.blocked_production_gates(),
            cargo_checks_deferred: self.config.cargo_checks_deferred,
            production_release_allowed: self.config.production_release_allowed,
            matrix_root: self.state_root(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "cases": self.cases.values().map(FailureInjectionCase::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "report": self.matrix_report().public_record(),
            "cargo_checks_deferred": self.config.cargo_checks_deferred,
            "production_release_allowed": self.config.production_release_allowed,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "failure_injection_matrix_state",
            &[
                HashPart::Str(&self.roots.config_root),
                HashPart::Str(&self.roots.cases_root),
                HashPart::Str(&self.roots.counters_root),
                HashPart::Str(&self.roots.blocked_gates_root),
                HashPart::Str(&self.roots.expected_user_escape_root),
                HashPart::Str(self.verdict().as_str()),
                HashPart::U64(self.counters.total_cases),
                HashPart::U64(self.counters.user_escape_cases),
            ],
            32,
        )
    }
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("monero_l2_pq_bridge_exit_failure_injection_matrix:{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}

pub fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("monero_l2_pq_bridge_exit_failure_injection_matrix:{domain}"),
        parts,
        32,
    )
}

fn synthetic_root(label: &str, height: u64) -> String {
    root_from_parts(
        "synthetic_observation",
        &[HashPart::Str(label), HashPart::U64(height)],
    )
}

fn devnet_cases(config: &Config) -> Result<BTreeMap<String, FailureInjectionCase>> {
    let cases = vec![
        FailureInjectionCase::new(
            "fi-001-sequencer-shutdown",
            InjectionKind::SequencerShutdown,
            InjectionStatus::Contained,
            "sequencer stops publishing exit batches after accepting a bridge-bound private transfer",
            UserEscapeOutcome::ForcedExitAvailable,
            "forced-exit clock arms from the last anchored private receipt and settlement waits for user proof",
            vec![
                ProductionGate::CargoChecksDeferred,
                ProductionGate::SecurityAuditDeferred,
                ProductionGate::DisputeExecutionHarnessDeferred,
            ],
            "sequencer liveness is never required for a user to reveal the minimum exit witness",
            "freeze sequencer promotion and publish liveness incident root",
            "submit forced-exit request with receipt root and burn nullifier",
            synthetic_root("sequencer-online-private-transfer-accepted", 1_700),
            synthetic_root("sequencer-offline-forced-exit-armed", 1_724),
        ),
        FailureInjectionCase::new(
            "fi-002-watcher-collusion",
            InjectionKind::WatcherCollusion,
            InjectionStatus::Contained,
            "colluding watcher subset signs a shallow or inconsistent Monero custody observation",
            UserEscapeOutcome::ChallengeBlocksSettlement,
            "quorum transcript is rejected until independent weight and finality roots match policy",
            vec![
                ProductionGate::CargoChecksDeferred,
                ProductionGate::SecurityAuditDeferred,
                ProductionGate::MoneroFinalityHarnessDeferred,
            ],
            "watcher attestations cannot release custody without threshold weight and finality evidence",
            "slash equivocation bond and rotate watcher admission set",
            "open challenge with honest finality certificate and hold settlement",
            synthetic_root("watcher-quorum-honest-baseline", 2_048),
            synthetic_root("watcher-collusion-challenge-held", 2_052),
        ),
        FailureInjectionCase::new(
            "fi-003-monero-reorg",
            InjectionKind::MoneroReorg,
            InjectionStatus::Contained,
            "Monero custody lock is reorganized below the bridge finality threshold",
            UserEscapeOutcome::ReorgQuarantine,
            "deposit and exit lanes enter quarantine and refuse mint or release until re-anchored",
            vec![
                ProductionGate::CargoChecksDeferred,
                ProductionGate::MoneroFinalityHarnessDeferred,
                ProductionGate::SecurityAuditDeferred,
            ],
            "base-layer reorg cannot mint spendable private L2 value or release exit liquidity",
            "publish reorg window and require replacement finality proof",
            "wait for re-anchored custody proof before retrying exit",
            synthetic_root("monero-finality-before-reorg", 3_120),
            synthetic_root("monero-reorg-quarantine", 3_122),
        ),
        FailureInjectionCase::new(
            "fi-004-liquidity-exhaustion",
            InjectionKind::LiquidityExhaustion,
            InjectionStatus::Contained,
            "available exit liquidity falls below the pending private withdrawal queue",
            UserEscapeOutcome::LiquidityBackstopRequired,
            "queue ordering is preserved, fee extraction is capped, and backstop lane becomes mandatory",
            vec![
                ProductionGate::CargoChecksDeferred,
                ProductionGate::LiquidityBackstopProofDeferred,
                ProductionGate::SecurityAuditDeferred,
            ],
            "liquidity shortage must be visible without allowing queue jumps or inflated fees",
            "activate backstop provider proof and freeze discretionary releases",
            "keep claim in ordered queue or move to forced-exit backstop lane",
            synthetic_root("liquidity-sufficient-queue", 4_096),
            synthetic_root("liquidity-exhausted-backstop-required", 4_101),
        ),
        FailureInjectionCase::new(
            "fi-005-pq-authority-compromise",
            InjectionKind::PqAuthorityCompromise,
            InjectionStatus::Contained,
            "PQ authority key signs a release bundle outside the rooted ceremony transcript",
            UserEscapeOutcome::AuthorityRotationRequired,
            "release is blocked, authority root is marked compromised, and rotation ceremony is required",
            vec![
                ProductionGate::CargoChecksDeferred,
                ProductionGate::PqAuthorityCeremonyDeferred,
                ProductionGate::SecurityAuditDeferred,
            ],
            "a compromised authority cannot unilaterally bypass watcher, dispute, or custody roots",
            "revoke authority root and publish replacement ceremony commitment",
            "challenge unauthorized release and retry after authority rotation",
            synthetic_root("pq-authority-root-healthy", 5_300),
            synthetic_root("pq-authority-compromise-rotation-required", 5_301),
        ),
        FailureInjectionCase::new(
            "fi-006-metadata-leak",
            InjectionKind::MetadataLeak,
            InjectionStatus::Contained,
            "exit receipt reveals linkable wallet timing, amount bucket, or scan cohort metadata",
            UserEscapeOutcome::PrivacyBudgetQuarantine,
            "receipt publication is quarantined and privacy budget review blocks production release",
            vec![
                ProductionGate::CargoChecksDeferred,
                ProductionGate::PrivacyLeakageReviewDeferred,
                ProductionGate::SecurityAuditDeferred,
            ],
            "metadata leakage cannot become an accepted bridge-exit receipt without review",
            "rotate receipt salt policy and publish redacted leakage assessment",
            "request redacted receipt regeneration before exposing wallet-specific hints",
            synthetic_root("metadata-budget-within-policy", 6_144),
            synthetic_root("metadata-leak-quarantined", 6_145),
        ),
        FailureInjectionCase::new(
            "fi-007-stale-wallet-scan-hints",
            InjectionKind::StaleWalletScanHints,
            InjectionStatus::Contained,
            "wallet receives scan hints from a stale viewtag cache after a reorg or delayed shard update",
            UserEscapeOutcome::WalletRescanRequired,
            "hint freshness check fails closed and requires rescan from the last safe anchor",
            vec![
                ProductionGate::CargoChecksDeferred,
                ProductionGate::WalletHintFreshnessHarnessDeferred,
                ProductionGate::SecurityAuditDeferred,
            ],
            "stale hints cannot convince a wallet that an exit was settled or lost",
            "invalidate stale hint shard and publish replacement freshness root",
            "rescan from safe anchor and ignore stale hint receipts",
            synthetic_root("wallet-hints-fresh", 7_000),
            synthetic_root("wallet-hints-stale-rescan-required", 7_004),
        ),
        FailureInjectionCase::new(
            "fi-008-disputed-exit-execution",
            InjectionKind::DisputedExitExecution,
            InjectionStatus::Contained,
            "executor attempts to settle an exit while an open challenge references the same nullifier",
            UserEscapeOutcome::ChallengeBlocksSettlement,
            "settlement is blocked until challenge resolution root clears the disputed nullifier",
            vec![
                ProductionGate::CargoChecksDeferred,
                ProductionGate::DisputeExecutionHarnessDeferred,
                ProductionGate::SecurityAuditDeferred,
            ],
            "disputed exits cannot execute before challenge finalization",
            "halt executor lane and publish challenge arbitration root",
            "track challenge receipt and retry settlement after final resolution",
            synthetic_root("exit-undisputed-ready", 8_080),
            synthetic_root("exit-disputed-execution-blocked", 8_081),
        ),
    ];

    if cases.len() < config.min_required_cases as usize {
        return Err("devnet failure injection seed lacks required cases".to_string());
    }

    Ok(cases
        .into_iter()
        .map(|case| (case.case_id.clone(), case))
        .collect())
}
