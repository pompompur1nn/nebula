use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeHandlerBoundExecutionManifestRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_HANDLER_BOUND_EXECUTION_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-user-escape-handler-bound-execution-manifest-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_HANDLER_BOUND_EXECUTION_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const HANDLER_BOUND_EXECUTION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-handler-bound-execution-suite-v1";
pub const DEFAULT_ESCAPE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-handler-bound-execution-devnet-v1";
pub const DEFAULT_HANDLER_BINDING_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-live-handler-binding-devnet-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_MIN_HANDLER_QUORUM_BPS: u64 = 7_000;
pub const DEFAULT_MIN_WATCHER_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_MIN_PQ_QUORUM_BPS: u64 = 7_500;
pub const DEFAULT_MAX_EXECUTION_LAG_BLOCKS: u64 = 12;
pub const DEFAULT_MAX_METADATA_UNITS: u64 = 2;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLane {
    DepositLock,
    PrivateNote,
    SettlementReceipt,
    ReleaseVerification,
    AdversarialGap,
    WalletRunbook,
    RuntimeExecutionGate,
}

impl ExecutionLane {
    pub fn all() -> [Self; 7] {
        [
            Self::DepositLock,
            Self::PrivateNote,
            Self::SettlementReceipt,
            Self::ReleaseVerification,
            Self::AdversarialGap,
            Self::WalletRunbook,
            Self::RuntimeExecutionGate,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DepositLock => "deposit_lock",
            Self::PrivateNote => "private_note",
            Self::SettlementReceipt => "settlement_receipt",
            Self::ReleaseVerification => "release_verification",
            Self::AdversarialGap => "adversarial_gap",
            Self::WalletRunbook => "wallet_runbook",
            Self::RuntimeExecutionGate => "runtime_execution_gate",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::DepositLock => "Deposit lock execution",
            Self::PrivateNote => "Private note execution",
            Self::SettlementReceipt => "Settlement receipt execution",
            Self::ReleaseVerification => "Release verification execution",
            Self::AdversarialGap => "Adversarial gap execution",
            Self::WalletRunbook => "Wallet runbook execution",
            Self::RuntimeExecutionGate => "Runtime execution gate",
        }
    }

    pub fn weight_bps(&self) -> u64 {
        match self {
            Self::DepositLock => 1_600,
            Self::PrivateNote => 1_500,
            Self::SettlementReceipt => 1_400,
            Self::ReleaseVerification => 1_700,
            Self::AdversarialGap => 1_100,
            Self::WalletRunbook => 1_100,
            Self::RuntimeExecutionGate => 1_600,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Executable,
    Held,
    Rejected,
    Missing,
}

impl ExecutionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Executable => "executable",
            Self::Held => "held",
            Self::Rejected => "rejected",
            Self::Missing => "missing",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionVerdict {
    Ready,
    HeldForRuntime,
    Rejected,
}

impl ExecutionVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::HeldForRuntime => "held_for_runtime",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub vertical_slice_id: String,
    pub escape_id: String,
    pub handler_binding_id: String,
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
    pub execution_height: u64,
    pub min_handler_quorum_bps: u64,
    pub min_watcher_quorum_bps: u64,
    pub min_pq_quorum_bps: u64,
    pub max_execution_lag_blocks: u64,
    pub max_metadata_units: u64,
    pub cargo_runtime_execution_allowed: bool,
    pub live_feed_execution_allowed: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            escape_id: DEFAULT_ESCAPE_ID.to_string(),
            handler_binding_id: DEFAULT_HANDLER_BINDING_ID.to_string(),
            l2_reference_height: 1_065_229,
            monero_reference_height: 3_161_070,
            execution_height: 10_500,
            min_handler_quorum_bps: DEFAULT_MIN_HANDLER_QUORUM_BPS,
            min_watcher_quorum_bps: DEFAULT_MIN_WATCHER_QUORUM_BPS,
            min_pq_quorum_bps: DEFAULT_MIN_PQ_QUORUM_BPS,
            max_execution_lag_blocks: DEFAULT_MAX_EXECUTION_LAG_BLOCKS,
            max_metadata_units: DEFAULT_MAX_METADATA_UNITS,
            cargo_runtime_execution_allowed: false,
            live_feed_execution_allowed: false,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "vertical_slice_id": self.vertical_slice_id,
            "escape_id": self.escape_id,
            "handler_binding_id": self.handler_binding_id,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "execution_height": self.execution_height,
            "min_handler_quorum_bps": self.min_handler_quorum_bps,
            "min_watcher_quorum_bps": self.min_watcher_quorum_bps,
            "min_pq_quorum_bps": self.min_pq_quorum_bps,
            "max_execution_lag_blocks": self.max_execution_lag_blocks,
            "max_metadata_units": self.max_metadata_units,
            "cargo_runtime_execution_allowed": bool_label(self.cargo_runtime_execution_allowed),
            "live_feed_execution_allowed": bool_label(self.live_feed_execution_allowed),
            "production_release_allowed": bool_label(self.production_release_allowed),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("handler_bound_execution_config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionRequirement {
    pub lane: ExecutionLane,
    pub requirement_id: String,
    pub required_binding_roots: Vec<String>,
    pub required_output_roots: Vec<String>,
    pub min_handler_quorum_bps: u64,
    pub min_watcher_quorum_bps: u64,
    pub min_pq_quorum_bps: u64,
    pub max_execution_lag_blocks: u64,
    pub max_metadata_units: u64,
    pub fail_closed: bool,
    pub note: String,
}

impl ExecutionRequirement {
    pub fn new(lane: ExecutionLane, config: &Config) -> Self {
        Self {
            lane,
            requirement_id: stable_id("execution_requirement", lane.as_str()),
            required_binding_roots: required_binding_roots(lane),
            required_output_roots: required_output_roots(lane),
            min_handler_quorum_bps: config.min_handler_quorum_bps,
            min_watcher_quorum_bps: config.min_watcher_quorum_bps,
            min_pq_quorum_bps: config.min_pq_quorum_bps,
            max_execution_lag_blocks: config.max_execution_lag_blocks,
            max_metadata_units: config.max_metadata_units,
            fail_closed: true,
            note: requirement_note(lane).to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "lane_label": self.lane.label(),
            "requirement_id": self.requirement_id,
            "required_binding_roots": self.required_binding_roots,
            "required_output_roots": self.required_output_roots,
            "min_handler_quorum_bps": self.min_handler_quorum_bps,
            "min_watcher_quorum_bps": self.min_watcher_quorum_bps,
            "min_pq_quorum_bps": self.min_pq_quorum_bps,
            "max_execution_lag_blocks": self.max_execution_lag_blocks,
            "max_metadata_units": self.max_metadata_units,
            "fail_closed": bool_label(self.fail_closed),
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("handler_bound_execution_requirement", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionRecord {
    pub lane: ExecutionLane,
    pub execution_id: String,
    pub status: ExecutionStatus,
    pub handler_binding_root: String,
    pub input_root: String,
    pub output_root: String,
    pub replay_root: String,
    pub source_height: u64,
    pub execution_lag_blocks: u64,
    pub handler_quorum_bps: u64,
    pub watcher_quorum_bps: u64,
    pub pq_quorum_bps: u64,
    pub metadata_units: u64,
    pub wallet_replayable: bool,
    pub note: String,
}

impl ExecutionRecord {
    pub fn devnet(lane: ExecutionLane, config: &Config) -> Self {
        let handler_binding_root = handler_binding_root(lane, config);
        let input_root = execution_input_root(lane, config, &handler_binding_root);
        let output_root = execution_output_root(lane, config, &input_root);
        let replay_root = execution_replay_root(lane, config, &output_root);
        let status = match lane {
            ExecutionLane::RuntimeExecutionGate => ExecutionStatus::Held,
            _ => ExecutionStatus::Executable,
        };
        Self {
            lane,
            execution_id: stable_id("execution_record", lane.as_str()),
            status,
            handler_binding_root,
            input_root,
            output_root,
            replay_root,
            source_height: config
                .execution_height
                .saturating_sub(execution_lag_blocks(lane)),
            execution_lag_blocks: execution_lag_blocks(lane),
            handler_quorum_bps: handler_quorum_bps(lane, config),
            watcher_quorum_bps: watcher_quorum_bps(lane, config),
            pq_quorum_bps: pq_quorum_bps(lane, config),
            metadata_units: metadata_units(lane),
            wallet_replayable: wallet_replayable(lane),
            note: execution_note(lane).to_string(),
        }
    }

    pub fn runtime_gate(config: &Config) -> Self {
        let mut record = Self::devnet(ExecutionLane::RuntimeExecutionGate, config);
        record.status = if config.cargo_runtime_execution_allowed
            && config.live_feed_execution_allowed
            && config.production_release_allowed
        {
            ExecutionStatus::Executable
        } else {
            ExecutionStatus::Held
        };
        record.note =
            "handler-bound execution gate holds until cargo/runtime and live feed execution are allowed"
                .to_string();
        record
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "execution_id": self.execution_id,
            "status": self.status.as_str(),
            "handler_binding_root": self.handler_binding_root,
            "input_root": self.input_root,
            "output_root": self.output_root,
            "replay_root": self.replay_root,
            "source_height": self.source_height,
            "execution_lag_blocks": self.execution_lag_blocks,
            "handler_quorum_bps": self.handler_quorum_bps,
            "watcher_quorum_bps": self.watcher_quorum_bps,
            "pq_quorum_bps": self.pq_quorum_bps,
            "metadata_units": self.metadata_units,
            "wallet_replayable": bool_label(self.wallet_replayable),
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("handler_bound_execution_record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionFinding {
    pub lane: ExecutionLane,
    pub finding_id: String,
    pub status: ExecutionStatus,
    pub severity_bps: u64,
    pub reason: String,
    pub requirement_root: String,
    pub execution_root: String,
}

impl ExecutionFinding {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "finding_id": self.finding_id,
            "status": self.status.as_str(),
            "severity_bps": self.severity_bps,
            "reason": self.reason,
            "requirement_root": self.requirement_root,
            "execution_root": self.execution_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("handler_bound_execution_finding", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneSummary {
    pub lane: ExecutionLane,
    pub status: ExecutionStatus,
    pub finding_count: u64,
    pub severity_bps: u64,
    pub lane_weight_bps: u64,
    pub lane_root: String,
}

impl LaneSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "finding_count": self.finding_count,
            "severity_bps": self.severity_bps,
            "lane_weight_bps": self.lane_weight_bps,
            "lane_root": self.lane_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionRoots {
    pub config_root: String,
    pub requirement_root: String,
    pub execution_root: String,
    pub finding_root: String,
    pub lane_summary_root: String,
    pub manifest_root: String,
}

impl ExecutionRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "requirement_root": self.requirement_root,
            "execution_root": self.execution_root,
            "finding_root": self.finding_root,
            "lane_summary_root": self.lane_summary_root,
            "manifest_root": self.manifest_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionAnswer {
    pub escape_id: String,
    pub verdict: ExecutionVerdict,
    pub executable_lane_count: u64,
    pub held_lane_count: u64,
    pub rejected_lane_count: u64,
    pub missing_lane_count: u64,
    pub finding_count: u64,
    pub severity_bps: u64,
    pub manifest_root: String,
    pub answer_root: String,
}

impl ExecutionAnswer {
    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "verdict": self.verdict.as_str(),
            "executable_lane_count": self.executable_lane_count,
            "held_lane_count": self.held_lane_count,
            "rejected_lane_count": self.rejected_lane_count,
            "missing_lane_count": self.missing_lane_count,
            "finding_count": self.finding_count,
            "severity_bps": self.severity_bps,
            "manifest_root": self.manifest_root,
            "answer_root": self.answer_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub requirements: Vec<ExecutionRequirement>,
    pub executions: Vec<ExecutionRecord>,
    pub findings: Vec<ExecutionFinding>,
    pub lane_summaries: Vec<LaneSummary>,
    pub roots: ExecutionRoots,
    pub answer: ExecutionAnswer,
    pub hold_reasons: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        Self::from_config(config)
    }

    pub fn from_config(config: Config) -> Self {
        let requirements = ExecutionLane::all()
            .into_iter()
            .map(|lane| ExecutionRequirement::new(lane, &config))
            .collect::<Vec<_>>();
        let executions = ExecutionLane::all()
            .into_iter()
            .map(|lane| {
                if lane == ExecutionLane::RuntimeExecutionGate {
                    ExecutionRecord::runtime_gate(&config)
                } else {
                    ExecutionRecord::devnet(lane, &config)
                }
            })
            .collect::<Vec<_>>();
        let findings = evaluate_findings(&config, &requirements, &executions);
        let lane_summaries = summarize_lanes(&requirements, &executions, &findings);
        let roots = execution_roots(
            &config,
            &requirements,
            &executions,
            &findings,
            &lane_summaries,
        );
        let answer = execution_answer(&config, &lane_summaries, &findings, &roots);
        let hold_reasons = hold_reasons(&requirements, &executions, &findings, &answer);
        Self {
            config,
            requirements,
            executions,
            findings,
            lane_summaries,
            roots,
            answer,
            hold_reasons,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "suite": HANDLER_BOUND_EXECUTION_SUITE,
            "config": self.config.public_record(),
            "requirements": self.requirements.iter().map(ExecutionRequirement::public_record).collect::<Vec<_>>(),
            "executions": self.executions.iter().map(ExecutionRecord::public_record).collect::<Vec<_>>(),
            "findings": self.findings.iter().map(ExecutionFinding::public_record).collect::<Vec<_>>(),
            "lane_summaries": self.lane_summaries.iter().map(LaneSummary::public_record).collect::<Vec<_>>(),
            "roots": self.roots.public_record(),
            "answer": self.answer.public_record(),
            "hold_reasons": self.hold_reasons,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.manifest_root.clone()
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

fn evaluate_findings(
    config: &Config,
    requirements: &[ExecutionRequirement],
    executions: &[ExecutionRecord],
) -> Vec<ExecutionFinding> {
    let mut findings = Vec::new();
    for requirement in requirements {
        match executions
            .iter()
            .find(|execution| execution.lane == requirement.lane)
        {
            Some(execution) => {
                push_finding_if(
                    &mut findings,
                    requirement,
                    execution,
                    execution.status == ExecutionStatus::Missing,
                    "handler-bound execution record is missing",
                    10_000,
                    ExecutionStatus::Missing,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    execution,
                    execution.status == ExecutionStatus::Rejected,
                    "handler-bound execution rejected by lane verifier",
                    10_000,
                    ExecutionStatus::Rejected,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    execution,
                    execution.execution_lag_blocks > requirement.max_execution_lag_blocks,
                    "handler-bound execution output is stale",
                    6_000,
                    ExecutionStatus::Held,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    execution,
                    execution.handler_quorum_bps < requirement.min_handler_quorum_bps,
                    "handler quorum below execution threshold",
                    7_000,
                    ExecutionStatus::Held,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    execution,
                    execution.watcher_quorum_bps < requirement.min_watcher_quorum_bps,
                    "watcher quorum below execution threshold",
                    7_000,
                    ExecutionStatus::Held,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    execution,
                    execution.pq_quorum_bps < requirement.min_pq_quorum_bps,
                    "post-quantum quorum below execution threshold",
                    7_500,
                    ExecutionStatus::Held,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    execution,
                    execution.metadata_units > requirement.max_metadata_units,
                    "execution output exceeds metadata leakage budget",
                    8_000,
                    ExecutionStatus::Held,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    execution,
                    !execution.wallet_replayable,
                    "wallet cannot replay this execution locally",
                    9_000,
                    ExecutionStatus::Held,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    execution,
                    execution.lane == ExecutionLane::RuntimeExecutionGate
                        && (!config.cargo_runtime_execution_allowed
                            || !config.live_feed_execution_allowed
                            || !config.production_release_allowed),
                    "cargo/runtime, live feed, or production release gate is still closed",
                    5_000,
                    ExecutionStatus::Held,
                );
            }
            None => {
                let missing = ExecutionRecord {
                    lane: requirement.lane,
                    execution_id: stable_id("missing_execution_record", requirement.lane.as_str()),
                    status: ExecutionStatus::Missing,
                    handler_binding_root: "missing".to_string(),
                    input_root: "missing".to_string(),
                    output_root: "missing".to_string(),
                    replay_root: "missing".to_string(),
                    source_height: 0,
                    execution_lag_blocks: u64::MAX,
                    handler_quorum_bps: 0,
                    watcher_quorum_bps: 0,
                    pq_quorum_bps: 0,
                    metadata_units: 0,
                    wallet_replayable: false,
                    note: "required execution record is missing".to_string(),
                };
                push_finding_if(
                    &mut findings,
                    requirement,
                    &missing,
                    true,
                    "required handler-bound execution lane is missing",
                    10_000,
                    ExecutionStatus::Missing,
                );
            }
        }
    }
    findings
}

fn push_finding_if(
    findings: &mut Vec<ExecutionFinding>,
    requirement: &ExecutionRequirement,
    execution: &ExecutionRecord,
    condition: bool,
    reason: &str,
    severity_bps: u64,
    status: ExecutionStatus,
) {
    if condition {
        let finding_id = domain_hash(
            "monero-l2-pq-bridge-exit-user-escape-handler-bound-execution-finding-id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(requirement.lane.as_str()),
                HashPart::Str(&requirement.requirement_id),
                HashPart::Str(&execution.execution_id),
                HashPart::Str(reason),
            ],
            16,
        );
        findings.push(ExecutionFinding {
            lane: requirement.lane,
            finding_id,
            status,
            severity_bps,
            reason: reason.to_string(),
            requirement_root: requirement.state_root(),
            execution_root: execution.state_root(),
        });
    }
}

fn summarize_lanes(
    requirements: &[ExecutionRequirement],
    executions: &[ExecutionRecord],
    findings: &[ExecutionFinding],
) -> Vec<LaneSummary> {
    requirements
        .iter()
        .map(|requirement| {
            let lane_findings = findings
                .iter()
                .filter(|finding| finding.lane == requirement.lane)
                .collect::<Vec<_>>();
            let execution = executions.iter().find(|item| item.lane == requirement.lane);
            let status = lane_status(execution, &lane_findings);
            let severity_bps = lane_findings
                .iter()
                .map(|finding| finding.severity_bps)
                .sum::<u64>()
                .min(10_000);
            let execution_root = match execution {
                Some(item) => item.state_root(),
                None => "missing".to_string(),
            };
            let lane_root = record_root(
                "handler_bound_execution_lane_summary_root",
                &json!({
                    "lane": requirement.lane.as_str(),
                    "requirement_root": requirement.state_root(),
                    "execution_root": execution_root,
                    "finding_roots": lane_findings.iter().map(|finding| finding.state_root()).collect::<Vec<_>>(),
                    "status": status.as_str(),
                    "severity_bps": severity_bps,
                }),
            );
            LaneSummary {
                lane: requirement.lane,
                status,
                finding_count: lane_findings.len() as u64,
                severity_bps,
                lane_weight_bps: requirement.lane.weight_bps(),
                lane_root,
            }
        })
        .collect()
}

fn lane_status(
    execution: Option<&ExecutionRecord>,
    lane_findings: &[&ExecutionFinding],
) -> ExecutionStatus {
    match execution {
        Some(item) => {
            if lane_findings
                .iter()
                .any(|finding| finding.status == ExecutionStatus::Rejected)
            {
                ExecutionStatus::Rejected
            } else if lane_findings
                .iter()
                .any(|finding| finding.status == ExecutionStatus::Missing)
            {
                ExecutionStatus::Missing
            } else if !lane_findings.is_empty() || item.status == ExecutionStatus::Held {
                ExecutionStatus::Held
            } else {
                item.status
            }
        }
        None => ExecutionStatus::Missing,
    }
}

fn execution_roots(
    config: &Config,
    requirements: &[ExecutionRequirement],
    executions: &[ExecutionRecord],
    findings: &[ExecutionFinding],
    lane_summaries: &[LaneSummary],
) -> ExecutionRoots {
    let config_root = config.state_root();
    let requirement_root = merkle_root(
        "monero-l2-pq-bridge-exit-user-escape-handler-bound-execution-requirements",
        &requirements
            .iter()
            .map(ExecutionRequirement::public_record)
            .collect::<Vec<_>>(),
    );
    let execution_root = merkle_root(
        "monero-l2-pq-bridge-exit-user-escape-handler-bound-execution-records",
        &executions
            .iter()
            .map(ExecutionRecord::public_record)
            .collect::<Vec<_>>(),
    );
    let finding_root = merkle_root(
        "monero-l2-pq-bridge-exit-user-escape-handler-bound-execution-findings",
        &findings
            .iter()
            .map(ExecutionFinding::public_record)
            .collect::<Vec<_>>(),
    );
    let lane_summary_root = merkle_root(
        "monero-l2-pq-bridge-exit-user-escape-handler-bound-execution-lane-summaries",
        &lane_summaries
            .iter()
            .map(LaneSummary::public_record)
            .collect::<Vec<_>>(),
    );
    let manifest_root = record_root(
        "handler_bound_execution_manifest_root",
        &json!({
            "protocol_version": PROTOCOL_VERSION,
            "suite": HANDLER_BOUND_EXECUTION_SUITE,
            "chain_id": config.chain_id,
            "escape_id": config.escape_id,
            "handler_binding_id": config.handler_binding_id,
            "config_root": config_root,
            "requirement_root": requirement_root,
            "execution_root": execution_root,
            "finding_root": finding_root,
            "lane_summary_root": lane_summary_root,
        }),
    );
    ExecutionRoots {
        config_root,
        requirement_root,
        execution_root,
        finding_root,
        lane_summary_root,
        manifest_root,
    }
}

fn execution_answer(
    config: &Config,
    lane_summaries: &[LaneSummary],
    findings: &[ExecutionFinding],
    roots: &ExecutionRoots,
) -> ExecutionAnswer {
    let executable_lane_count = lane_summaries
        .iter()
        .filter(|summary| summary.status == ExecutionStatus::Executable)
        .count() as u64;
    let held_lane_count = lane_summaries
        .iter()
        .filter(|summary| summary.status == ExecutionStatus::Held)
        .count() as u64;
    let rejected_lane_count = lane_summaries
        .iter()
        .filter(|summary| summary.status == ExecutionStatus::Rejected)
        .count() as u64;
    let missing_lane_count = lane_summaries
        .iter()
        .filter(|summary| summary.status == ExecutionStatus::Missing)
        .count() as u64;
    let severity_bps = findings
        .iter()
        .map(|finding| finding.severity_bps)
        .sum::<u64>()
        .min(10_000);
    let verdict = if rejected_lane_count > 0 || missing_lane_count > 0 {
        ExecutionVerdict::Rejected
    } else if held_lane_count > 0
        || !config.cargo_runtime_execution_allowed
        || !config.live_feed_execution_allowed
        || !config.production_release_allowed
    {
        ExecutionVerdict::HeldForRuntime
    } else {
        ExecutionVerdict::Ready
    };
    let answer_root = record_root(
        "handler_bound_execution_answer_root",
        &json!({
            "escape_id": config.escape_id,
            "verdict": verdict.as_str(),
            "executable_lane_count": executable_lane_count,
            "held_lane_count": held_lane_count,
            "rejected_lane_count": rejected_lane_count,
            "missing_lane_count": missing_lane_count,
            "finding_count": findings.len(),
            "severity_bps": severity_bps,
            "manifest_root": roots.manifest_root,
        }),
    );
    ExecutionAnswer {
        escape_id: config.escape_id.clone(),
        verdict,
        executable_lane_count,
        held_lane_count,
        rejected_lane_count,
        missing_lane_count,
        finding_count: findings.len() as u64,
        severity_bps,
        manifest_root: roots.manifest_root.clone(),
        answer_root,
    }
}

fn hold_reasons(
    requirements: &[ExecutionRequirement],
    executions: &[ExecutionRecord],
    findings: &[ExecutionFinding],
    answer: &ExecutionAnswer,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert(
        "handler_bound_execution_answer".to_string(),
        format!(
            "handler-bound execution verdict is {} with {} findings",
            answer.verdict.as_str(),
            answer.finding_count
        ),
    );
    map.insert(
        "runtime_execution_gate".to_string(),
        "handler-bound execution remains held until cargo/runtime and live feed checks are allowed"
            .to_string(),
    );
    for requirement in requirements {
        if !executions
            .iter()
            .any(|execution| execution.lane == requirement.lane)
        {
            map.insert(
                format!("missing_{}", requirement.lane.as_str()),
                "required handler-bound execution record is missing".to_string(),
            );
        }
    }
    for finding in findings {
        map.insert(
            format!("finding_{}_{}", finding.lane.as_str(), finding.finding_id),
            finding.reason.clone(),
        );
    }
    map
}

fn required_binding_roots(lane: ExecutionLane) -> Vec<String> {
    match lane {
        ExecutionLane::DepositLock => vec![
            "deposit_lock_handler_binding_root",
            "monero_watcher_adapter_root",
            "custody_policy_handler_root",
        ],
        ExecutionLane::PrivateNote => vec![
            "private_note_handler_binding_root",
            "encrypted_note_state_reader_root",
            "nullifier_separation_handler_root",
        ],
        ExecutionLane::SettlementReceipt => vec![
            "settlement_receipt_handler_binding_root",
            "receipt_ingester_root",
            "withdrawal_claim_link_root",
        ],
        ExecutionLane::ReleaseVerification => vec![
            "release_verification_handler_binding_root",
            "pq_custody_attestation_root",
            "liquidity_release_handler_root",
        ],
        ExecutionLane::AdversarialGap => vec![
            "adversarial_gap_handler_binding_root",
            "reorg_gap_handler_root",
            "metadata_leak_gap_handler_root",
        ],
        ExecutionLane::WalletRunbook => vec![
            "wallet_runbook_handler_binding_root",
            "wallet_scan_export_handler_root",
            "local_recovery_replay_handler_root",
        ],
        ExecutionLane::RuntimeExecutionGate => vec![
            "runtime_gate_handler_binding_root",
            "cargo_runtime_gate_handler_root",
            "live_feed_gate_handler_root",
        ],
    }
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn required_output_roots(lane: ExecutionLane) -> Vec<String> {
    match lane {
        ExecutionLane::DepositLock => vec![
            "deposit_execution_verdict_root",
            "lock_claim_continuity_root",
        ],
        ExecutionLane::PrivateNote => {
            vec!["private_note_execution_verdict_root", "privacy_budget_root"]
        }
        ExecutionLane::SettlementReceipt => vec![
            "settlement_execution_verdict_root",
            "claim_receipt_link_root",
        ],
        ExecutionLane::ReleaseVerification => {
            vec!["release_execution_verdict_root", "release_hold_root"]
        }
        ExecutionLane::AdversarialGap => {
            vec!["adversarial_execution_verdict_root", "fail_closed_gap_root"]
        }
        ExecutionLane::WalletRunbook => {
            vec!["wallet_execution_verdict_root", "wallet_replay_export_root"]
        }
        ExecutionLane::RuntimeExecutionGate => {
            vec!["runtime_execution_gate_root", "cargo_deferred_root"]
        }
    }
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn requirement_note(lane: ExecutionLane) -> &'static str {
    match lane {
        ExecutionLane::DepositLock => {
            "deposit execution must consume handler-bound watcher and custody roots before exit release"
        }
        ExecutionLane::PrivateNote => {
            "private note execution must preserve encrypted state and nullifier separation"
        }
        ExecutionLane::SettlementReceipt => {
            "settlement execution must preserve continuity from receipt to withdrawal claim"
        }
        ExecutionLane::ReleaseVerification => {
            "release execution must bind verifier, PQ custody, broadcast, and liquidity outputs"
        }
        ExecutionLane::AdversarialGap => {
            "adversarial execution must turn live failure evidence into hold or reject decisions"
        }
        ExecutionLane::WalletRunbook => {
            "wallet execution must remain locally replayable by the escaping user"
        }
        ExecutionLane::RuntimeExecutionGate => {
            "runtime gate must remain held until cargo/runtime and live-feed execution are allowed"
        }
    }
}

fn execution_note(lane: ExecutionLane) -> &'static str {
    match lane {
        ExecutionLane::DepositLock => {
            "deposit handler-bound execution is deterministic and held for runtime"
        }
        ExecutionLane::PrivateNote => "private note handler-bound execution is privacy-preserving",
        ExecutionLane::SettlementReceipt => {
            "settlement handler-bound execution links receipt to claim"
        }
        ExecutionLane::ReleaseVerification => {
            "release handler-bound execution binds release verifier outputs"
        }
        ExecutionLane::AdversarialGap => {
            "adversarial handler-bound execution records fail-closed decisions"
        }
        ExecutionLane::WalletRunbook => "wallet handler-bound execution is locally replayable",
        ExecutionLane::RuntimeExecutionGate => "runtime execution gate is intentionally held",
    }
}

fn handler_binding_root(lane: ExecutionLane, config: &Config) -> String {
    record_root(
        "handler_bound_execution_handler_binding_root",
        &json!({
            "chain_id": config.chain_id,
            "handler_binding_id": config.handler_binding_id,
            "escape_id": config.escape_id,
            "lane": lane.as_str(),
            "execution_height": config.execution_height,
            "binding_roots": required_binding_roots(lane),
        }),
    )
}

fn execution_input_root(
    lane: ExecutionLane,
    config: &Config,
    handler_binding_root: &str,
) -> String {
    record_root(
        "handler_bound_execution_input_root",
        &json!({
            "chain_id": config.chain_id,
            "escape_id": config.escape_id,
            "lane": lane.as_str(),
            "handler_binding_root": handler_binding_root,
            "monero_reference_height": config.monero_reference_height,
            "l2_reference_height": config.l2_reference_height,
        }),
    )
}

fn execution_output_root(lane: ExecutionLane, config: &Config, input_root: &str) -> String {
    record_root(
        "handler_bound_execution_output_root",
        &json!({
            "chain_id": config.chain_id,
            "escape_id": config.escape_id,
            "lane": lane.as_str(),
            "input_root": input_root,
            "output_roots": required_output_roots(lane),
        }),
    )
}

fn execution_replay_root(lane: ExecutionLane, config: &Config, output_root: &str) -> String {
    record_root(
        "handler_bound_execution_replay_root",
        &json!({
            "chain_id": config.chain_id,
            "escape_id": config.escape_id,
            "lane": lane.as_str(),
            "output_root": output_root,
            "wallet_replayable": bool_label(wallet_replayable(lane)),
        }),
    )
}

fn execution_lag_blocks(lane: ExecutionLane) -> u64 {
    match lane {
        ExecutionLane::DepositLock => 3,
        ExecutionLane::PrivateNote => 4,
        ExecutionLane::SettlementReceipt => 5,
        ExecutionLane::ReleaseVerification => 6,
        ExecutionLane::AdversarialGap => 7,
        ExecutionLane::WalletRunbook => 4,
        ExecutionLane::RuntimeExecutionGate => 0,
    }
}

fn handler_quorum_bps(lane: ExecutionLane, config: &Config) -> u64 {
    match lane {
        ExecutionLane::AdversarialGap => config.min_handler_quorum_bps + 100,
        ExecutionLane::RuntimeExecutionGate => config.min_handler_quorum_bps,
        _ => config.min_handler_quorum_bps + 400,
    }
}

fn watcher_quorum_bps(lane: ExecutionLane, config: &Config) -> u64 {
    match lane {
        ExecutionLane::DepositLock | ExecutionLane::AdversarialGap => {
            config.min_watcher_quorum_bps + 400
        }
        _ => config.min_watcher_quorum_bps + 100,
    }
}

fn pq_quorum_bps(lane: ExecutionLane, config: &Config) -> u64 {
    match lane {
        ExecutionLane::PrivateNote
        | ExecutionLane::ReleaseVerification
        | ExecutionLane::WalletRunbook => config.min_pq_quorum_bps + 300,
        _ => config.min_pq_quorum_bps,
    }
}

fn metadata_units(lane: ExecutionLane) -> u64 {
    match lane {
        ExecutionLane::AdversarialGap => 2,
        ExecutionLane::RuntimeExecutionGate => 0,
        _ => 1,
    }
}

fn wallet_replayable(lane: ExecutionLane) -> bool {
    !matches!(lane, ExecutionLane::RuntimeExecutionGate)
}

fn stable_id(kind: &str, label: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-user-escape-handler-bound-execution-stable-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        16,
    )
}

fn record_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(value),
        ],
        32,
    )
}

fn bool_label(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
