use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeLiveHandlerBindingManifestRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_LIVE_HANDLER_BINDING_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-user-escape-live-handler-binding-manifest-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_LIVE_HANDLER_BINDING_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const LIVE_HANDLER_BINDING_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-live-handler-binding-suite-v1";
pub const DEFAULT_ESCAPE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-live-handler-binding-devnet-v1";
pub const DEFAULT_LIVE_INPUT_HARNESS_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-live-input-devnet-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_MIN_HANDLER_QUORUM_BPS: u64 = 7_000;
pub const DEFAULT_MIN_WATCHER_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_MIN_PQ_QUORUM_BPS: u64 = 7_500;
pub const DEFAULT_MAX_HANDLER_LAG_BLOCKS: u64 = 12;
pub const DEFAULT_MAX_METADATA_UNITS: u64 = 2;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandlerBindingLane {
    DepositLock,
    PrivateNote,
    SettlementReceipt,
    ReleaseVerification,
    AdversarialGap,
    WalletRunbook,
    RuntimeExecutionGate,
}

impl HandlerBindingLane {
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
            Self::DepositLock => "Deposit watcher handler binding",
            Self::PrivateNote => "Private note reader handler binding",
            Self::SettlementReceipt => "Settlement receipt ingester binding",
            Self::ReleaseVerification => "Release verifier handler binding",
            Self::AdversarialGap => "Adversarial feed handler binding",
            Self::WalletRunbook => "Wallet replay handler binding",
            Self::RuntimeExecutionGate => "Runtime execution handler gate",
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
pub enum HandlerBindingStatus {
    Bound,
    Held,
    Rejected,
    Missing,
}

impl HandlerBindingStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::Held => "held",
            Self::Rejected => "rejected",
            Self::Missing => "missing",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingVerdict {
    Ready,
    HeldForHandlers,
    Rejected,
}

impl BindingVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::HeldForHandlers => "held_for_handlers",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub vertical_slice_id: String,
    pub escape_id: String,
    pub live_input_harness_id: String,
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
    pub binding_height: u64,
    pub min_handler_quorum_bps: u64,
    pub min_watcher_quorum_bps: u64,
    pub min_pq_quorum_bps: u64,
    pub max_handler_lag_blocks: u64,
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
            live_input_harness_id: DEFAULT_LIVE_INPUT_HARNESS_ID.to_string(),
            l2_reference_height: 1_060_425,
            monero_reference_height: 3_161_020,
            binding_height: 10_420,
            min_handler_quorum_bps: DEFAULT_MIN_HANDLER_QUORUM_BPS,
            min_watcher_quorum_bps: DEFAULT_MIN_WATCHER_QUORUM_BPS,
            min_pq_quorum_bps: DEFAULT_MIN_PQ_QUORUM_BPS,
            max_handler_lag_blocks: DEFAULT_MAX_HANDLER_LAG_BLOCKS,
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
            "live_input_harness_id": self.live_input_harness_id,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "binding_height": self.binding_height,
            "min_handler_quorum_bps": self.min_handler_quorum_bps,
            "min_watcher_quorum_bps": self.min_watcher_quorum_bps,
            "min_pq_quorum_bps": self.min_pq_quorum_bps,
            "max_handler_lag_blocks": self.max_handler_lag_blocks,
            "max_metadata_units": self.max_metadata_units,
            "cargo_runtime_execution_allowed": bool_label(self.cargo_runtime_execution_allowed),
            "live_feed_execution_allowed": bool_label(self.live_feed_execution_allowed),
            "production_release_allowed": bool_label(self.production_release_allowed),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live_handler_binding_config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandlerBindingRequirement {
    pub lane: HandlerBindingLane,
    pub requirement_id: String,
    pub required_handlers: Vec<String>,
    pub required_live_input_roots: Vec<String>,
    pub min_handler_quorum_bps: u64,
    pub min_watcher_quorum_bps: u64,
    pub min_pq_quorum_bps: u64,
    pub max_handler_lag_blocks: u64,
    pub max_metadata_units: u64,
    pub fail_closed: bool,
    pub note: String,
}

impl HandlerBindingRequirement {
    pub fn new(
        lane: HandlerBindingLane,
        config: &Config,
        required_handlers: Vec<String>,
        required_live_input_roots: Vec<String>,
    ) -> Self {
        Self {
            lane,
            requirement_id: stable_id("handler_binding_requirement", lane.as_str()),
            required_handlers,
            required_live_input_roots,
            min_handler_quorum_bps: config.min_handler_quorum_bps,
            min_watcher_quorum_bps: config.min_watcher_quorum_bps,
            min_pq_quorum_bps: config.min_pq_quorum_bps,
            max_handler_lag_blocks: config.max_handler_lag_blocks,
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
            "required_handlers": self.required_handlers,
            "required_live_input_roots": self.required_live_input_roots,
            "min_handler_quorum_bps": self.min_handler_quorum_bps,
            "min_watcher_quorum_bps": self.min_watcher_quorum_bps,
            "min_pq_quorum_bps": self.min_pq_quorum_bps,
            "max_handler_lag_blocks": self.max_handler_lag_blocks,
            "max_metadata_units": self.max_metadata_units,
            "fail_closed": bool_label(self.fail_closed),
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live_handler_binding_requirement", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandlerBindingRecord {
    pub lane: HandlerBindingLane,
    pub binding_id: String,
    pub status: HandlerBindingStatus,
    pub handler_root: String,
    pub live_input_root: String,
    pub replay_export_root: String,
    pub source_height: u64,
    pub handler_lag_blocks: u64,
    pub handler_quorum_bps: u64,
    pub watcher_quorum_bps: u64,
    pub pq_quorum_bps: u64,
    pub metadata_units: u64,
    pub wallet_replayable: bool,
    pub note: String,
}

impl HandlerBindingRecord {
    pub fn devnet(lane: HandlerBindingLane, config: &Config) -> Self {
        let handler_root = handler_root(lane, config);
        let live_input_root = live_input_root(lane, config);
        let replay_export_root = replay_export_root(lane, config, &handler_root, &live_input_root);
        let status = match lane {
            HandlerBindingLane::RuntimeExecutionGate => HandlerBindingStatus::Held,
            _ => HandlerBindingStatus::Bound,
        };
        Self {
            lane,
            binding_id: stable_id("handler_binding_record", lane.as_str()),
            status,
            handler_root,
            live_input_root,
            replay_export_root,
            source_height: config
                .binding_height
                .saturating_sub(handler_lag_blocks(lane)),
            handler_lag_blocks: handler_lag_blocks(lane),
            handler_quorum_bps: handler_quorum_bps(lane, config),
            watcher_quorum_bps: watcher_quorum_bps(lane, config),
            pq_quorum_bps: pq_quorum_bps(lane, config),
            metadata_units: metadata_units(lane),
            wallet_replayable: wallet_replayable(lane),
            note: binding_note(lane).to_string(),
        }
    }

    pub fn runtime_gate(config: &Config) -> Self {
        let mut record = Self::devnet(HandlerBindingLane::RuntimeExecutionGate, config);
        record.status = if config.cargo_runtime_execution_allowed
            && config.live_feed_execution_allowed
            && config.production_release_allowed
        {
            HandlerBindingStatus::Bound
        } else {
            HandlerBindingStatus::Held
        };
        record.note =
            "handler binding runtime gate holds until cargo/runtime and live feed checks are allowed"
                .to_string();
        record
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "binding_id": self.binding_id,
            "status": self.status.as_str(),
            "handler_root": self.handler_root,
            "live_input_root": self.live_input_root,
            "replay_export_root": self.replay_export_root,
            "source_height": self.source_height,
            "handler_lag_blocks": self.handler_lag_blocks,
            "handler_quorum_bps": self.handler_quorum_bps,
            "watcher_quorum_bps": self.watcher_quorum_bps,
            "pq_quorum_bps": self.pq_quorum_bps,
            "metadata_units": self.metadata_units,
            "wallet_replayable": bool_label(self.wallet_replayable),
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live_handler_binding_record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandlerBindingFinding {
    pub lane: HandlerBindingLane,
    pub finding_id: String,
    pub status: HandlerBindingStatus,
    pub severity_bps: u64,
    pub reason: String,
    pub requirement_root: String,
    pub binding_root: String,
}

impl HandlerBindingFinding {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "finding_id": self.finding_id,
            "status": self.status.as_str(),
            "severity_bps": self.severity_bps,
            "reason": self.reason,
            "requirement_root": self.requirement_root,
            "binding_root": self.binding_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live_handler_binding_finding", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneSummary {
    pub lane: HandlerBindingLane,
    pub status: HandlerBindingStatus,
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
pub struct BindingRoots {
    pub config_root: String,
    pub requirement_root: String,
    pub binding_root: String,
    pub finding_root: String,
    pub lane_summary_root: String,
    pub manifest_root: String,
}

impl BindingRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "requirement_root": self.requirement_root,
            "binding_root": self.binding_root,
            "finding_root": self.finding_root,
            "lane_summary_root": self.lane_summary_root,
            "manifest_root": self.manifest_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BindingAnswer {
    pub escape_id: String,
    pub verdict: BindingVerdict,
    pub bound_lane_count: u64,
    pub held_lane_count: u64,
    pub rejected_lane_count: u64,
    pub missing_lane_count: u64,
    pub finding_count: u64,
    pub severity_bps: u64,
    pub manifest_root: String,
    pub answer_root: String,
}

impl BindingAnswer {
    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "verdict": self.verdict.as_str(),
            "bound_lane_count": self.bound_lane_count,
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
    pub requirements: Vec<HandlerBindingRequirement>,
    pub bindings: Vec<HandlerBindingRecord>,
    pub findings: Vec<HandlerBindingFinding>,
    pub lane_summaries: Vec<LaneSummary>,
    pub roots: BindingRoots,
    pub answer: BindingAnswer,
    pub hold_reasons: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        Self::from_config(config)
    }

    pub fn from_config(config: Config) -> Self {
        let requirements = HandlerBindingLane::all()
            .into_iter()
            .map(|lane| {
                HandlerBindingRequirement::new(
                    lane,
                    &config,
                    required_handlers(lane),
                    required_live_input_roots(lane),
                )
            })
            .collect::<Vec<_>>();
        let bindings = HandlerBindingLane::all()
            .into_iter()
            .map(|lane| {
                if lane == HandlerBindingLane::RuntimeExecutionGate {
                    HandlerBindingRecord::runtime_gate(&config)
                } else {
                    HandlerBindingRecord::devnet(lane, &config)
                }
            })
            .collect::<Vec<_>>();
        let findings = evaluate_findings(&config, &requirements, &bindings);
        let lane_summaries = summarize_lanes(&requirements, &bindings, &findings);
        let roots = binding_roots(
            &config,
            &requirements,
            &bindings,
            &findings,
            &lane_summaries,
        );
        let answer = binding_answer(&config, &lane_summaries, &findings, &roots);
        let hold_reasons = hold_reasons(&requirements, &bindings, &findings, &answer);
        Self {
            config,
            requirements,
            bindings,
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
            "suite": LIVE_HANDLER_BINDING_SUITE,
            "config": self.config.public_record(),
            "requirements": self.requirements.iter().map(HandlerBindingRequirement::public_record).collect::<Vec<_>>(),
            "bindings": self.bindings.iter().map(HandlerBindingRecord::public_record).collect::<Vec<_>>(),
            "findings": self.findings.iter().map(HandlerBindingFinding::public_record).collect::<Vec<_>>(),
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
    requirements: &[HandlerBindingRequirement],
    bindings: &[HandlerBindingRecord],
) -> Vec<HandlerBindingFinding> {
    let mut findings = Vec::new();
    for requirement in requirements {
        match bindings
            .iter()
            .find(|binding| binding.lane == requirement.lane)
        {
            Some(binding) => {
                push_finding_if(
                    &mut findings,
                    requirement,
                    binding,
                    binding.status == HandlerBindingStatus::Missing,
                    "handler binding record is missing",
                    10_000,
                    HandlerBindingStatus::Missing,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    binding,
                    binding.status == HandlerBindingStatus::Rejected,
                    "handler binding rejected by lane verifier",
                    10_000,
                    HandlerBindingStatus::Rejected,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    binding,
                    binding.handler_lag_blocks > requirement.max_handler_lag_blocks,
                    "handler output is stale for this live-input package",
                    6_000,
                    HandlerBindingStatus::Held,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    binding,
                    binding.handler_quorum_bps < requirement.min_handler_quorum_bps,
                    "handler quorum below binding threshold",
                    7_000,
                    HandlerBindingStatus::Held,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    binding,
                    binding.watcher_quorum_bps < requirement.min_watcher_quorum_bps,
                    "watcher quorum below live-handler threshold",
                    7_000,
                    HandlerBindingStatus::Held,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    binding,
                    binding.pq_quorum_bps < requirement.min_pq_quorum_bps,
                    "post-quantum attestation quorum below handler threshold",
                    7_500,
                    HandlerBindingStatus::Held,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    binding,
                    binding.metadata_units > requirement.max_metadata_units,
                    "handler export exceeds metadata leakage budget",
                    8_000,
                    HandlerBindingStatus::Held,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    binding,
                    !binding.wallet_replayable,
                    "wallet cannot replay this handler-fed observation locally",
                    9_000,
                    HandlerBindingStatus::Held,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    binding,
                    binding.lane == HandlerBindingLane::RuntimeExecutionGate
                        && (!config.cargo_runtime_execution_allowed
                            || !config.live_feed_execution_allowed
                            || !config.production_release_allowed),
                    "cargo/runtime, live feed, or production release gate is still closed",
                    5_000,
                    HandlerBindingStatus::Held,
                );
            }
            None => {
                let missing = HandlerBindingRecord {
                    lane: requirement.lane,
                    binding_id: stable_id("missing_handler_binding", requirement.lane.as_str()),
                    status: HandlerBindingStatus::Missing,
                    handler_root: "missing".to_string(),
                    live_input_root: "missing".to_string(),
                    replay_export_root: "missing".to_string(),
                    source_height: 0,
                    handler_lag_blocks: u64::MAX,
                    handler_quorum_bps: 0,
                    watcher_quorum_bps: 0,
                    pq_quorum_bps: 0,
                    metadata_units: 0,
                    wallet_replayable: false,
                    note: "required handler binding is missing".to_string(),
                };
                push_finding_if(
                    &mut findings,
                    requirement,
                    &missing,
                    true,
                    "required live-handler binding lane is missing",
                    10_000,
                    HandlerBindingStatus::Missing,
                );
            }
        }
    }
    findings
}

fn push_finding_if(
    findings: &mut Vec<HandlerBindingFinding>,
    requirement: &HandlerBindingRequirement,
    binding: &HandlerBindingRecord,
    condition: bool,
    reason: &str,
    severity_bps: u64,
    status: HandlerBindingStatus,
) {
    if condition {
        let finding_id = domain_hash(
            "monero-l2-pq-bridge-exit-user-escape-live-handler-binding-finding-id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(requirement.lane.as_str()),
                HashPart::Str(&requirement.requirement_id),
                HashPart::Str(&binding.binding_id),
                HashPart::Str(reason),
            ],
            16,
        );
        findings.push(HandlerBindingFinding {
            lane: requirement.lane,
            finding_id,
            status,
            severity_bps,
            reason: reason.to_string(),
            requirement_root: requirement.state_root(),
            binding_root: binding.state_root(),
        });
    }
}

fn summarize_lanes(
    requirements: &[HandlerBindingRequirement],
    bindings: &[HandlerBindingRecord],
    findings: &[HandlerBindingFinding],
) -> Vec<LaneSummary> {
    requirements
        .iter()
        .map(|requirement| {
            let lane_findings = findings
                .iter()
                .filter(|finding| finding.lane == requirement.lane)
                .collect::<Vec<_>>();
            let binding = bindings.iter().find(|item| item.lane == requirement.lane);
            let status = lane_status(binding, &lane_findings);
            let severity_bps = lane_findings
                .iter()
                .map(|finding| finding.severity_bps)
                .sum::<u64>()
                .min(10_000);
            let binding_root = match binding {
                Some(item) => item.state_root(),
                None => "missing".to_string(),
            };
            let lane_root = record_root(
                "live_handler_binding_lane_summary_root",
                &json!({
                    "lane": requirement.lane.as_str(),
                    "requirement_root": requirement.state_root(),
                    "binding_root": binding_root,
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
    binding: Option<&HandlerBindingRecord>,
    lane_findings: &[&HandlerBindingFinding],
) -> HandlerBindingStatus {
    match binding {
        Some(item) => {
            if lane_findings
                .iter()
                .any(|finding| finding.status == HandlerBindingStatus::Rejected)
            {
                HandlerBindingStatus::Rejected
            } else if lane_findings
                .iter()
                .any(|finding| finding.status == HandlerBindingStatus::Missing)
            {
                HandlerBindingStatus::Missing
            } else if !lane_findings.is_empty() || item.status == HandlerBindingStatus::Held {
                HandlerBindingStatus::Held
            } else {
                item.status
            }
        }
        None => HandlerBindingStatus::Missing,
    }
}

fn binding_roots(
    config: &Config,
    requirements: &[HandlerBindingRequirement],
    bindings: &[HandlerBindingRecord],
    findings: &[HandlerBindingFinding],
    lane_summaries: &[LaneSummary],
) -> BindingRoots {
    let config_root = config.state_root();
    let requirement_root = merkle_root(
        "monero-l2-pq-bridge-exit-user-escape-live-handler-binding-requirements",
        &requirements
            .iter()
            .map(HandlerBindingRequirement::public_record)
            .collect::<Vec<_>>(),
    );
    let binding_root = merkle_root(
        "monero-l2-pq-bridge-exit-user-escape-live-handler-binding-records",
        &bindings
            .iter()
            .map(HandlerBindingRecord::public_record)
            .collect::<Vec<_>>(),
    );
    let finding_root = merkle_root(
        "monero-l2-pq-bridge-exit-user-escape-live-handler-binding-findings",
        &findings
            .iter()
            .map(HandlerBindingFinding::public_record)
            .collect::<Vec<_>>(),
    );
    let lane_summary_root = merkle_root(
        "monero-l2-pq-bridge-exit-user-escape-live-handler-binding-lane-summaries",
        &lane_summaries
            .iter()
            .map(LaneSummary::public_record)
            .collect::<Vec<_>>(),
    );
    let manifest_root = record_root(
        "live_handler_binding_manifest_root",
        &json!({
            "protocol_version": PROTOCOL_VERSION,
            "suite": LIVE_HANDLER_BINDING_SUITE,
            "chain_id": config.chain_id,
            "escape_id": config.escape_id,
            "live_input_harness_id": config.live_input_harness_id,
            "config_root": config_root,
            "requirement_root": requirement_root,
            "binding_root": binding_root,
            "finding_root": finding_root,
            "lane_summary_root": lane_summary_root,
        }),
    );
    BindingRoots {
        config_root,
        requirement_root,
        binding_root,
        finding_root,
        lane_summary_root,
        manifest_root,
    }
}

fn binding_answer(
    config: &Config,
    lane_summaries: &[LaneSummary],
    findings: &[HandlerBindingFinding],
    roots: &BindingRoots,
) -> BindingAnswer {
    let bound_lane_count = lane_summaries
        .iter()
        .filter(|summary| summary.status == HandlerBindingStatus::Bound)
        .count() as u64;
    let held_lane_count = lane_summaries
        .iter()
        .filter(|summary| summary.status == HandlerBindingStatus::Held)
        .count() as u64;
    let rejected_lane_count = lane_summaries
        .iter()
        .filter(|summary| summary.status == HandlerBindingStatus::Rejected)
        .count() as u64;
    let missing_lane_count = lane_summaries
        .iter()
        .filter(|summary| summary.status == HandlerBindingStatus::Missing)
        .count() as u64;
    let severity_bps = findings
        .iter()
        .map(|finding| finding.severity_bps)
        .sum::<u64>()
        .min(10_000);
    let verdict = if rejected_lane_count > 0 || missing_lane_count > 0 {
        BindingVerdict::Rejected
    } else if held_lane_count > 0
        || !config.cargo_runtime_execution_allowed
        || !config.live_feed_execution_allowed
        || !config.production_release_allowed
    {
        BindingVerdict::HeldForHandlers
    } else {
        BindingVerdict::Ready
    };
    let answer_root = record_root(
        "live_handler_binding_answer_root",
        &json!({
            "escape_id": config.escape_id,
            "verdict": verdict.as_str(),
            "bound_lane_count": bound_lane_count,
            "held_lane_count": held_lane_count,
            "rejected_lane_count": rejected_lane_count,
            "missing_lane_count": missing_lane_count,
            "finding_count": findings.len(),
            "severity_bps": severity_bps,
            "manifest_root": roots.manifest_root,
        }),
    );
    BindingAnswer {
        escape_id: config.escape_id.clone(),
        verdict,
        bound_lane_count,
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
    requirements: &[HandlerBindingRequirement],
    bindings: &[HandlerBindingRecord],
    findings: &[HandlerBindingFinding],
    answer: &BindingAnswer,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert(
        "live_handler_binding_answer".to_string(),
        format!(
            "live handler binding verdict is {} with {} findings",
            answer.verdict.as_str(),
            answer.finding_count
        ),
    );
    map.insert(
        "runtime_execution_gate".to_string(),
        "handler binding gate remains held until cargo/runtime execution and live feed checks are allowed"
            .to_string(),
    );
    for requirement in requirements {
        if !bindings
            .iter()
            .any(|binding| binding.lane == requirement.lane)
        {
            map.insert(
                format!("missing_{}", requirement.lane.as_str()),
                "required handler binding record is missing".to_string(),
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

fn required_handlers(lane: HandlerBindingLane) -> Vec<String> {
    match lane {
        HandlerBindingLane::DepositLock => vec![
            "monero_watcher_adapter",
            "confirmation_reorg_handler",
            "deposit_address_claim_handler",
            "watcher_quorum_handler",
            "bridge_custody_policy_handler",
        ],
        HandlerBindingLane::PrivateNote => vec![
            "encrypted_note_state_reader",
            "nullifier_key_image_separation_handler",
            "private_transfer_receipt_handler",
            "metadata_budget_handler",
            "wallet_scan_hint_handler",
        ],
        HandlerBindingLane::SettlementReceipt => vec![
            "settlement_receipt_ingester",
            "amount_commitment_handler",
            "fee_bound_handler",
            "challenge_dispute_clock_handler",
            "withdrawal_claim_link_handler",
        ],
        HandlerBindingLane::ReleaseVerification => vec![
            "release_verifier_output_handler",
            "pq_custody_attestation_handler",
            "monero_broadcast_handler",
            "liquidity_release_handler",
            "challenge_window_handler",
        ],
        HandlerBindingLane::AdversarialGap => vec![
            "deposit_reorg_gap_handler",
            "watcher_collusion_gap_handler",
            "sequencer_halt_gap_handler",
            "liquidity_exhaustion_gap_handler",
            "metadata_leak_gap_handler",
        ],
        HandlerBindingLane::WalletRunbook => vec![
            "wallet_scan_export_handler",
            "proof_collection_handler",
            "forced_exit_claim_builder",
            "pq_authorization_exporter",
            "local_recovery_replay_handler",
        ],
        HandlerBindingLane::RuntimeExecutionGate => vec![
            "cargo_runtime_gate_handler",
            "live_feed_gate_handler",
            "forced_exit_harness_gate_handler",
        ],
    }
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn required_live_input_roots(lane: HandlerBindingLane) -> Vec<String> {
    match lane {
        HandlerBindingLane::DepositLock => vec![
            "deposit_lock_live_input_root",
            "monero_lock_tx_observation_root",
            "confirmation_reorg_observation_root",
        ],
        HandlerBindingLane::PrivateNote => vec![
            "private_note_live_input_root",
            "encrypted_note_commitment_root",
            "nullifier_key_image_separation_root",
        ],
        HandlerBindingLane::SettlementReceipt => vec![
            "settlement_receipt_live_input_root",
            "private_action_receipt_root",
            "withdrawal_claim_root",
        ],
        HandlerBindingLane::ReleaseVerification => vec![
            "release_verification_live_input_root",
            "pq_custody_verifier_root",
            "liquidity_verifier_root",
        ],
        HandlerBindingLane::AdversarialGap => vec![
            "adversarial_gap_live_input_root",
            "reorg_observation_root",
            "metadata_leak_observation_root",
        ],
        HandlerBindingLane::WalletRunbook => vec![
            "wallet_runbook_live_input_root",
            "wallet_scan_export_root",
            "release_verification_replay_root",
        ],
        HandlerBindingLane::RuntimeExecutionGate => vec![
            "runtime_execution_gate_live_input_root",
            "cargo_runtime_gate_root",
            "live_feed_gate_root",
        ],
    }
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn requirement_note(lane: HandlerBindingLane) -> &'static str {
    match lane {
        HandlerBindingLane::DepositLock => {
            "deposit handlers must bind watcher observations into the live input harness"
        }
        HandlerBindingLane::PrivateNote => {
            "private note handlers must bind encrypted state without leaking note metadata"
        }
        HandlerBindingLane::SettlementReceipt => {
            "settlement handlers must bind receipt ingestion to withdrawal claim continuity"
        }
        HandlerBindingLane::ReleaseVerification => {
            "release handlers must bind verifier outputs to PQ custody, liquidity, and broadcast evidence"
        }
        HandlerBindingLane::AdversarialGap => {
            "adversarial handlers must bind live failure observations to fail-closed release decisions"
        }
        HandlerBindingLane::WalletRunbook => {
            "wallet handlers must bind scan exports and replay data to a locally reproducible runbook"
        }
        HandlerBindingLane::RuntimeExecutionGate => {
            "runtime gate handlers must remain held until cargo/runtime and live-feed checks are allowed"
        }
    }
}

fn binding_note(lane: HandlerBindingLane) -> &'static str {
    match lane {
        HandlerBindingLane::DepositLock => "devnet deposit handlers are bound to live input roots",
        HandlerBindingLane::PrivateNote => "devnet private note handlers preserve redacted replay",
        HandlerBindingLane::SettlementReceipt => {
            "devnet settlement handlers link receipts to claims"
        }
        HandlerBindingLane::ReleaseVerification => "devnet release handlers bind verifier outputs",
        HandlerBindingLane::AdversarialGap => {
            "devnet adversarial handlers bind fail-closed evidence"
        }
        HandlerBindingLane::WalletRunbook => {
            "devnet wallet handlers export replayable runbook inputs"
        }
        HandlerBindingLane::RuntimeExecutionGate => "runtime handler gate is intentionally held",
    }
}

fn handler_root(lane: HandlerBindingLane, config: &Config) -> String {
    record_root(
        "live_handler_binding_handler_root",
        &json!({
            "chain_id": config.chain_id,
            "vertical_slice_id": config.vertical_slice_id,
            "escape_id": config.escape_id,
            "lane": lane.as_str(),
            "binding_height": config.binding_height,
            "handlers": required_handlers(lane),
        }),
    )
}

fn live_input_root(lane: HandlerBindingLane, config: &Config) -> String {
    record_root(
        "live_handler_binding_live_input_root",
        &json!({
            "chain_id": config.chain_id,
            "live_input_harness_id": config.live_input_harness_id,
            "lane": lane.as_str(),
            "binding_height": config.binding_height,
            "live_input_roots": required_live_input_roots(lane),
        }),
    )
}

fn replay_export_root(
    lane: HandlerBindingLane,
    config: &Config,
    handler_root: &str,
    live_input_root: &str,
) -> String {
    record_root(
        "live_handler_binding_replay_export_root",
        &json!({
            "chain_id": config.chain_id,
            "escape_id": config.escape_id,
            "lane": lane.as_str(),
            "handler_root": handler_root,
            "live_input_root": live_input_root,
            "wallet_replayable": bool_label(wallet_replayable(lane)),
        }),
    )
}

fn handler_lag_blocks(lane: HandlerBindingLane) -> u64 {
    match lane {
        HandlerBindingLane::DepositLock => 3,
        HandlerBindingLane::PrivateNote => 4,
        HandlerBindingLane::SettlementReceipt => 5,
        HandlerBindingLane::ReleaseVerification => 7,
        HandlerBindingLane::AdversarialGap => 8,
        HandlerBindingLane::WalletRunbook => 4,
        HandlerBindingLane::RuntimeExecutionGate => 0,
    }
}

fn handler_quorum_bps(lane: HandlerBindingLane, config: &Config) -> u64 {
    match lane {
        HandlerBindingLane::AdversarialGap => config.min_handler_quorum_bps + 100,
        HandlerBindingLane::RuntimeExecutionGate => config.min_handler_quorum_bps,
        _ => config.min_handler_quorum_bps + 400,
    }
}

fn watcher_quorum_bps(lane: HandlerBindingLane, config: &Config) -> u64 {
    match lane {
        HandlerBindingLane::DepositLock | HandlerBindingLane::AdversarialGap => {
            config.min_watcher_quorum_bps + 400
        }
        _ => config.min_watcher_quorum_bps + 100,
    }
}

fn pq_quorum_bps(lane: HandlerBindingLane, config: &Config) -> u64 {
    match lane {
        HandlerBindingLane::PrivateNote
        | HandlerBindingLane::ReleaseVerification
        | HandlerBindingLane::WalletRunbook => config.min_pq_quorum_bps + 300,
        _ => config.min_pq_quorum_bps,
    }
}

fn metadata_units(lane: HandlerBindingLane) -> u64 {
    match lane {
        HandlerBindingLane::AdversarialGap => 2,
        HandlerBindingLane::RuntimeExecutionGate => 0,
        _ => 1,
    }
}

fn wallet_replayable(lane: HandlerBindingLane) -> bool {
    !matches!(lane, HandlerBindingLane::RuntimeExecutionGate)
}

fn stable_id(kind: &str, label: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-user-escape-live-handler-binding-stable-id",
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
