use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceReleaseBlockerGateInvocationRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_GATE_INVOCATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-release-blocker-gate-invocation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_GATE_INVOCATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const GATE_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-release-blocker-gates-v1";
pub const DEFAULT_MAX_INVOCATIONS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseBlockerGateKind {
    CargoDeferred,
    RuntimeDeferred,
    LiveFeedNotSwapped,
    ForcedExitNotExecuted,
    IndependentAuditOpen,
    PrivacyReviewOpen,
    PqKeyVerificationPending,
    ReserveProofHandoffPending,
    ProductionReleaseHeld,
}

impl ReleaseBlockerGateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoDeferred => "cargo_deferred",
            Self::RuntimeDeferred => "runtime_deferred",
            Self::LiveFeedNotSwapped => "live_feed_not_swapped",
            Self::ForcedExitNotExecuted => "forced_exit_not_executed",
            Self::IndependentAuditOpen => "independent_audit_open",
            Self::PrivacyReviewOpen => "privacy_review_open",
            Self::PqKeyVerificationPending => "pq_key_verification_pending",
            Self::ReserveProofHandoffPending => "reserve_proof_handoff_pending",
            Self::ProductionReleaseHeld => "production_release_held",
        }
    }

    pub fn all() -> [Self; 9] {
        [
            Self::CargoDeferred,
            Self::RuntimeDeferred,
            Self::LiveFeedNotSwapped,
            Self::ForcedExitNotExecuted,
            Self::IndependentAuditOpen,
            Self::PrivacyReviewOpen,
            Self::PqKeyVerificationPending,
            Self::ReserveProofHandoffPending,
            Self::ProductionReleaseHeld,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    NoGo,
}

impl GateDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoGo => "no_go",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub gate_suite: String,
    pub vertical_slice: String,
    pub max_invocations: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            gate_suite: GATE_SUITE.to_string(),
            vertical_slice: "monero_l2_pq_bridge_exit_canonical_vertical_slice".to_string(),
            max_invocations: DEFAULT_MAX_INVOCATIONS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "gate_suite": self.gate_suite,
            "vertical_slice": self.vertical_slice,
            "max_invocations": self.max_invocations,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseBlockerGateInvocation {
    pub invocation_id: String,
    pub sequence: u64,
    pub kind: ReleaseBlockerGateKind,
    pub decision: GateDecision,
    pub reason: String,
    pub source_status: String,
    pub required_clearance: String,
    pub expected_no_go_root: String,
}

impl ReleaseBlockerGateInvocation {
    pub fn new(
        sequence: u64,
        kind: ReleaseBlockerGateKind,
        reason: impl Into<String>,
        source_status: impl Into<String>,
        required_clearance: impl Into<String>,
    ) -> Self {
        let decision = GateDecision::NoGo;
        let reason = reason.into();
        let source_status = source_status.into();
        let required_clearance = required_clearance.into();
        let expected_no_go_root = no_go_root(
            sequence,
            kind,
            decision,
            &reason,
            &source_status,
            &required_clearance,
        );
        let invocation_id = invocation_id(sequence, kind, &expected_no_go_root);
        Self {
            invocation_id,
            sequence,
            kind,
            decision,
            reason,
            source_status,
            required_clearance,
            expected_no_go_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "invocation_id": self.invocation_id,
            "sequence": self.sequence,
            "kind": self.kind.as_str(),
            "decision": self.decision.as_str(),
            "reason": self.reason,
            "source_status": self.source_status,
            "required_clearance": self.required_clearance,
            "expected_no_go_root": self.expected_no_go_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_blocker_gate_invocation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InvocationReport {
    pub report_id: String,
    pub decision: GateDecision,
    pub invocation_count: u64,
    pub no_go_count: u64,
    pub invocation_root: String,
    pub expected_no_go_root: String,
    pub invocations: BTreeMap<String, ReleaseBlockerGateInvocation>,
}

impl InvocationReport {
    pub fn public_record(&self) -> Value {
        let invocations = self
            .invocations
            .values()
            .map(ReleaseBlockerGateInvocation::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "decision": self.decision.as_str(),
            "invocation_count": self.invocation_count,
            "no_go_count": self.no_go_count,
            "invocation_root": self.invocation_root,
            "expected_no_go_root": self.expected_no_go_root,
            "invocations": invocations,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("invocation_report", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub reports_run: u64,
    pub invocations_recorded: u64,
    pub no_go_decisions: u64,
    pub release_holds: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "invocations_recorded": self.invocations_recorded,
            "no_go_decisions": self.no_go_decisions,
            "release_holds": self.release_holds,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub report_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-EMPTY-REPORTS",
                &[],
            ),
            counters_root: counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "report_root": self.report_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-INVOCATION-STATE",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.report_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub latest_report: Option<InvocationReport>,
    pub report_history: Vec<InvocationReport>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        let mut state = Self {
            config,
            latest_report: None,
            report_history: Vec::new(),
            counters,
            roots,
        };
        state
            .invoke_release_blocker_gates()
            .expect("devnet release-blocker gate invocation");
        state
    }

    pub fn invoke_release_blocker_gates(&mut self) -> Result<String> {
        let invocations = deterministic_invocations();
        if invocations.len() > self.config.max_invocations {
            return Err("release-blocker invocation count exceeds configured maximum".to_string());
        }

        let invocation_records = invocations
            .values()
            .map(ReleaseBlockerGateInvocation::public_record)
            .collect::<Vec<_>>();
        let no_go_records = invocations
            .values()
            .map(|invocation| {
                json!({
                    "kind": invocation.kind.as_str(),
                    "expected_no_go_root": invocation.expected_no_go_root,
                })
            })
            .collect::<Vec<_>>();
        let invocation_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-INVOCATION",
            &invocation_records,
        );
        let expected_no_go_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-EXPECTED-NO-GO",
            &no_go_records,
        );
        let report_id = report_id(&invocation_root, &expected_no_go_root);
        let invocation_count = invocations.len() as u64;
        let report = InvocationReport {
            report_id,
            decision: GateDecision::NoGo,
            invocation_count,
            no_go_count: invocation_count,
            invocation_root,
            expected_no_go_root,
            invocations,
        };

        self.counters.reports_run = self.counters.reports_run.saturating_add(1);
        self.counters.invocations_recorded = self
            .counters
            .invocations_recorded
            .saturating_add(report.invocation_count);
        self.counters.no_go_decisions = self
            .counters
            .no_go_decisions
            .saturating_add(report.no_go_count);
        self.counters.release_holds = self.counters.release_holds.saturating_add(1);
        self.latest_report = Some(report.clone());
        self.report_history.push(report);
        if self.report_history.len() > self.config.max_invocations {
            let overflow = self.report_history.len() - self.config.max_invocations;
            self.report_history.drain(0..overflow);
        }
        self.refresh_roots();
        Ok(self.roots.state_root.clone())
    }

    pub fn public_record(&self) -> Value {
        let report_history = self
            .report_history
            .iter()
            .map(InvocationReport::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "latest_report": self.latest_report.as_ref().map(InvocationReport::public_record),
            "report_history": report_history,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn refresh_roots(&mut self) {
        let report_records = self
            .report_history
            .iter()
            .map(InvocationReport::public_record)
            .collect::<Vec<_>>();
        let mut roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-REPORT",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        self.roots = roots;
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn deterministic_invocations() -> BTreeMap<String, ReleaseBlockerGateInvocation> {
    let invocations = vec![
        ReleaseBlockerGateInvocation::new(
            1,
            ReleaseBlockerGateKind::CargoDeferred,
            "cargo-family verification was explicitly deferred for the forced-exit vertical slice",
            "cargo_check_clippy_test_not_run",
            "run and archive cargo-family verification evidence",
        ),
        ReleaseBlockerGateInvocation::new(
            2,
            ReleaseBlockerGateKind::RuntimeDeferred,
            "runtime execution evidence is deferred until the release-blocker clears",
            "runtime_replay_not_executed",
            "execute deterministic runtime replay against the canonical vertical slice",
        ),
        ReleaseBlockerGateInvocation::new(
            3,
            ReleaseBlockerGateKind::LiveFeedNotSwapped,
            "the bridge exit path still uses fixture feed roots instead of live feed roots",
            "fixture_feed_active",
            "swap to live feed roots and bind the feed handoff record",
        ),
        ReleaseBlockerGateInvocation::new(
            4,
            ReleaseBlockerGateKind::ForcedExitNotExecuted,
            "the canonical forced-exit path has not produced execution evidence",
            "forced_exit_execution_missing",
            "execute forced exit and publish the resulting transcript root",
        ),
        ReleaseBlockerGateInvocation::new(
            5,
            ReleaseBlockerGateKind::IndependentAuditOpen,
            "independent audit signoff remains open",
            "audit_signoff_open",
            "attach independent audit completion root",
        ),
        ReleaseBlockerGateInvocation::new(
            6,
            ReleaseBlockerGateKind::PrivacyReviewOpen,
            "privacy review signoff remains open for exit metadata exposure",
            "privacy_review_open",
            "attach privacy review completion root",
        ),
        ReleaseBlockerGateInvocation::new(
            7,
            ReleaseBlockerGateKind::PqKeyVerificationPending,
            "post-quantum key verification has not been completed for release",
            "pq_key_verification_pending",
            "verify PQ key bundle and bind verification root",
        ),
        ReleaseBlockerGateInvocation::new(
            8,
            ReleaseBlockerGateKind::ReserveProofHandoffPending,
            "reserve proof ownership and handoff evidence remain pending",
            "reserve_proof_handoff_pending",
            "publish reserve proof handoff root",
        ),
        ReleaseBlockerGateInvocation::new(
            9,
            ReleaseBlockerGateKind::ProductionReleaseHeld,
            "production release is held until every blocker clears",
            "production_release_held",
            "clear all release blockers and recompute go decision roots",
        ),
    ];
    invocations
        .into_iter()
        .map(|invocation| (invocation.kind.as_str().to_string(), invocation))
        .collect()
}

fn no_go_root(
    sequence: u64,
    kind: ReleaseBlockerGateKind,
    decision: GateDecision,
    reason: &str,
    source_status: &str,
    required_clearance: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-NO-GO",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(sequence as i128),
            HashPart::Str(kind.as_str()),
            HashPart::Str(decision.as_str()),
            HashPart::Str(reason),
            HashPart::Str(source_status),
            HashPart::Str(required_clearance),
        ],
        32,
    )
}

fn invocation_id(sequence: u64, kind: ReleaseBlockerGateKind, expected_no_go_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-INVOCATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(sequence as i128),
            HashPart::Str(kind.as_str()),
            HashPart::Str(expected_no_go_root),
        ],
        32,
    )
}

fn report_id(invocation_root: &str, expected_no_go_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-REPORT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(invocation_root),
            HashPart::Str(expected_no_go_root),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}
