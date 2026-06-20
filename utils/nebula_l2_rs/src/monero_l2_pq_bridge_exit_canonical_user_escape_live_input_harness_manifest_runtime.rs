use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeLiveInputHarnessManifestRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_LIVE_INPUT_HARNESS_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-user-escape-live-input-harness-manifest-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_LIVE_INPUT_HARNESS_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const LIVE_INPUT_HARNESS_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-live-input-harness-suite-v1";
pub const DEFAULT_ESCAPE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-live-input-devnet-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_MIN_MONERO_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MIN_WATCHER_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_MIN_PQ_QUORUM_BPS: u64 = 7_500;
pub const DEFAULT_MAX_METADATA_UNITS: u64 = 2;
pub const DEFAULT_MAX_FEE_BPS: u64 = 25;
pub const DEFAULT_MAX_INPUT_AGE_BLOCKS: u64 = 36;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveInputLane {
    DepositLock,
    PrivateNote,
    SettlementReceipt,
    ReleaseVerification,
    AdversarialGap,
    WalletRunbook,
    RuntimeExecutionGate,
}

impl LiveInputLane {
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
            Self::DepositLock => "Monero deposit lock live input",
            Self::PrivateNote => "Private note state live input",
            Self::SettlementReceipt => "Settlement receipt live input",
            Self::ReleaseVerification => "Release verification live input",
            Self::AdversarialGap => "Adversarial gap live input",
            Self::WalletRunbook => "Wallet runbook live input",
            Self::RuntimeExecutionGate => "Runtime execution gate input",
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
pub enum LiveInputStatus {
    Ready,
    Held,
    Rejected,
    Missing,
}

impl LiveInputStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Held => "held",
            Self::Rejected => "rejected",
            Self::Missing => "missing",
        }
    }

    pub fn blocks_escape(&self) -> bool {
        !matches!(self, Self::Ready)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessVerdict {
    Ready,
    HeldForLiveInput,
    Rejected,
}

impl HarnessVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::HeldForLiveInput => "held_for_live_input",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub vertical_slice_id: String,
    pub escape_id: String,
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
    pub input_build_height: u64,
    pub min_monero_confirmations: u64,
    pub min_watcher_quorum_bps: u64,
    pub min_pq_quorum_bps: u64,
    pub max_metadata_units: u64,
    pub max_fee_bps: u64,
    pub max_input_age_blocks: u64,
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
            l2_reference_height: 1_056_261,
            monero_reference_height: 3_160_980,
            input_build_height: 10_340,
            min_monero_confirmations: DEFAULT_MIN_MONERO_CONFIRMATIONS,
            min_watcher_quorum_bps: DEFAULT_MIN_WATCHER_QUORUM_BPS,
            min_pq_quorum_bps: DEFAULT_MIN_PQ_QUORUM_BPS,
            max_metadata_units: DEFAULT_MAX_METADATA_UNITS,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            max_input_age_blocks: DEFAULT_MAX_INPUT_AGE_BLOCKS,
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
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "input_build_height": self.input_build_height,
            "min_monero_confirmations": self.min_monero_confirmations,
            "min_watcher_quorum_bps": self.min_watcher_quorum_bps,
            "min_pq_quorum_bps": self.min_pq_quorum_bps,
            "max_metadata_units": self.max_metadata_units,
            "max_fee_bps": self.max_fee_bps,
            "max_input_age_blocks": self.max_input_age_blocks,
            "cargo_runtime_execution_allowed": bool_label(self.cargo_runtime_execution_allowed),
            "live_feed_execution_allowed": bool_label(self.live_feed_execution_allowed),
            "production_release_allowed": bool_label(self.production_release_allowed),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live_input_harness_config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiveInputRequirement {
    pub lane: LiveInputLane,
    pub requirement_id: String,
    pub required_source_roots: Vec<String>,
    pub min_freshness_height: u64,
    pub min_watcher_quorum_bps: u64,
    pub min_pq_quorum_bps: u64,
    pub max_metadata_units: u64,
    pub max_fee_bps: u64,
    pub fail_closed: bool,
    pub note: String,
}

impl LiveInputRequirement {
    pub fn new(lane: LiveInputLane, config: &Config, required_source_roots: Vec<String>) -> Self {
        let min_freshness_height = config
            .input_build_height
            .saturating_sub(config.max_input_age_blocks);
        Self {
            lane,
            requirement_id: stable_id("live_input_requirement", lane.as_str()),
            required_source_roots,
            min_freshness_height,
            min_watcher_quorum_bps: config.min_watcher_quorum_bps,
            min_pq_quorum_bps: config.min_pq_quorum_bps,
            max_metadata_units: config.max_metadata_units,
            max_fee_bps: config.max_fee_bps,
            fail_closed: true,
            note: requirement_note(lane).to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "lane_label": self.lane.label(),
            "requirement_id": self.requirement_id,
            "required_source_roots": self.required_source_roots,
            "min_freshness_height": self.min_freshness_height,
            "min_watcher_quorum_bps": self.min_watcher_quorum_bps,
            "min_pq_quorum_bps": self.min_pq_quorum_bps,
            "max_metadata_units": self.max_metadata_units,
            "max_fee_bps": self.max_fee_bps,
            "fail_closed": bool_label(self.fail_closed),
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live_input_requirement", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiveInputArtifact {
    pub lane: LiveInputLane,
    pub artifact_id: String,
    pub status: LiveInputStatus,
    pub source_root: String,
    pub observed_root: String,
    pub source_height: u64,
    pub watcher_quorum_bps: u64,
    pub pq_quorum_bps: u64,
    pub metadata_units: u64,
    pub fee_bps: u64,
    pub wallet_replayable: bool,
    pub note: String,
}

impl LiveInputArtifact {
    pub fn devnet(lane: LiveInputLane, config: &Config) -> Self {
        let source_root = source_root(lane, config);
        let observed_root = observed_root(lane, config, &source_root);
        let status = match lane {
            LiveInputLane::RuntimeExecutionGate => LiveInputStatus::Held,
            _ => LiveInputStatus::Ready,
        };
        Self {
            lane,
            artifact_id: stable_id("live_input_artifact", lane.as_str()),
            status,
            source_root,
            observed_root,
            source_height: config.input_build_height.saturating_sub(lane_age(lane)),
            watcher_quorum_bps: lane_watcher_quorum_bps(lane, config),
            pq_quorum_bps: lane_pq_quorum_bps(lane, config),
            metadata_units: lane_metadata_units(lane),
            fee_bps: lane_fee_bps(lane),
            wallet_replayable: wallet_replayable(lane),
            note: artifact_note(lane).to_string(),
        }
    }

    pub fn runtime_gate(config: &Config) -> Self {
        let mut artifact = Self::devnet(LiveInputLane::RuntimeExecutionGate, config);
        artifact.status = if config.cargo_runtime_execution_allowed
            && config.live_feed_execution_allowed
            && config.production_release_allowed
        {
            LiveInputStatus::Ready
        } else {
            LiveInputStatus::Held
        };
        artifact.note =
            "runtime gate holds until cargo/runtime, live feed, and production release gates all open"
                .to_string();
        artifact
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "artifact_id": self.artifact_id,
            "status": self.status.as_str(),
            "source_root": self.source_root,
            "observed_root": self.observed_root,
            "source_height": self.source_height,
            "watcher_quorum_bps": self.watcher_quorum_bps,
            "pq_quorum_bps": self.pq_quorum_bps,
            "metadata_units": self.metadata_units,
            "fee_bps": self.fee_bps,
            "wallet_replayable": bool_label(self.wallet_replayable),
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live_input_artifact", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiveInputFinding {
    pub lane: LiveInputLane,
    pub finding_id: String,
    pub status: LiveInputStatus,
    pub severity_bps: u64,
    pub reason: String,
    pub requirement_root: String,
    pub artifact_root: String,
}

impl LiveInputFinding {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "finding_id": self.finding_id,
            "status": self.status.as_str(),
            "severity_bps": self.severity_bps,
            "reason": self.reason,
            "requirement_root": self.requirement_root,
            "artifact_root": self.artifact_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live_input_finding", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneSummary {
    pub lane: LiveInputLane,
    pub status: LiveInputStatus,
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

    pub fn state_root(&self) -> String {
        record_root("live_input_lane_summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HarnessRoots {
    pub config_root: String,
    pub requirement_root: String,
    pub artifact_root: String,
    pub finding_root: String,
    pub lane_summary_root: String,
    pub harness_root: String,
}

impl HarnessRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "requirement_root": self.requirement_root,
            "artifact_root": self.artifact_root,
            "finding_root": self.finding_root,
            "lane_summary_root": self.lane_summary_root,
            "harness_root": self.harness_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HarnessAnswer {
    pub escape_id: String,
    pub verdict: HarnessVerdict,
    pub ready_lane_count: u64,
    pub held_lane_count: u64,
    pub rejected_lane_count: u64,
    pub missing_lane_count: u64,
    pub finding_count: u64,
    pub severity_bps: u64,
    pub harness_root: String,
    pub answer_root: String,
}

impl HarnessAnswer {
    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "verdict": self.verdict.as_str(),
            "ready_lane_count": self.ready_lane_count,
            "held_lane_count": self.held_lane_count,
            "rejected_lane_count": self.rejected_lane_count,
            "missing_lane_count": self.missing_lane_count,
            "finding_count": self.finding_count,
            "severity_bps": self.severity_bps,
            "harness_root": self.harness_root,
            "answer_root": self.answer_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live_input_harness_answer", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub requirements: Vec<LiveInputRequirement>,
    pub artifacts: Vec<LiveInputArtifact>,
    pub findings: Vec<LiveInputFinding>,
    pub lane_summaries: Vec<LaneSummary>,
    pub roots: HarnessRoots,
    pub answer: HarnessAnswer,
    pub hold_reasons: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        Self::from_config(config)
    }

    pub fn from_config(config: Config) -> Self {
        let requirements = LiveInputLane::all()
            .into_iter()
            .map(|lane| LiveInputRequirement::new(lane, &config, required_source_roots(lane)))
            .collect::<Vec<_>>();
        let artifacts = LiveInputLane::all()
            .into_iter()
            .map(|lane| {
                if lane == LiveInputLane::RuntimeExecutionGate {
                    LiveInputArtifact::runtime_gate(&config)
                } else {
                    LiveInputArtifact::devnet(lane, &config)
                }
            })
            .collect::<Vec<_>>();
        let findings = evaluate_findings(&config, &requirements, &artifacts);
        let lane_summaries = summarize_lanes(&requirements, &artifacts, &findings);
        let roots = harness_roots(
            &config,
            &requirements,
            &artifacts,
            &findings,
            &lane_summaries,
        );
        let answer = harness_answer(&config, &lane_summaries, &findings, &roots);
        let hold_reasons = hold_reasons(&requirements, &artifacts, &findings, &answer);
        Self {
            config,
            requirements,
            artifacts,
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
            "suite": LIVE_INPUT_HARNESS_SUITE,
            "config": self.config.public_record(),
            "requirements": self.requirements.iter().map(LiveInputRequirement::public_record).collect::<Vec<_>>(),
            "artifacts": self.artifacts.iter().map(LiveInputArtifact::public_record).collect::<Vec<_>>(),
            "findings": self.findings.iter().map(LiveInputFinding::public_record).collect::<Vec<_>>(),
            "lane_summaries": self.lane_summaries.iter().map(LaneSummary::public_record).collect::<Vec<_>>(),
            "roots": self.roots.public_record(),
            "answer": self.answer.public_record(),
            "hold_reasons": self.hold_reasons,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.harness_root.clone()
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
    requirements: &[LiveInputRequirement],
    artifacts: &[LiveInputArtifact],
) -> Vec<LiveInputFinding> {
    let mut findings = Vec::new();
    for requirement in requirements {
        match artifacts
            .iter()
            .find(|artifact| artifact.lane == requirement.lane)
        {
            Some(artifact) => {
                push_finding_if(
                    &mut findings,
                    requirement,
                    artifact,
                    artifact.status == LiveInputStatus::Missing,
                    "live input artifact is missing",
                    10_000,
                    LiveInputStatus::Missing,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    artifact,
                    artifact.status == LiveInputStatus::Rejected,
                    "live input artifact rejected by lane verifier",
                    10_000,
                    LiveInputStatus::Rejected,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    artifact,
                    artifact.source_height < requirement.min_freshness_height,
                    "live input source is stale for this escape package",
                    6_000,
                    LiveInputStatus::Held,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    artifact,
                    artifact.watcher_quorum_bps < requirement.min_watcher_quorum_bps,
                    "watcher quorum below live input threshold",
                    7_000,
                    LiveInputStatus::Held,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    artifact,
                    artifact.pq_quorum_bps < requirement.min_pq_quorum_bps,
                    "post-quantum attestation quorum below threshold",
                    7_500,
                    LiveInputStatus::Held,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    artifact,
                    artifact.metadata_units > requirement.max_metadata_units,
                    "metadata leakage budget exceeded",
                    8_000,
                    LiveInputStatus::Held,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    artifact,
                    artifact.fee_bps > requirement.max_fee_bps,
                    "forced-exit fee bound exceeded",
                    4_000,
                    LiveInputStatus::Held,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    artifact,
                    !artifact.wallet_replayable,
                    "wallet cannot replay this live input locally",
                    9_000,
                    LiveInputStatus::Held,
                );
                push_finding_if(
                    &mut findings,
                    requirement,
                    artifact,
                    artifact.lane == LiveInputLane::RuntimeExecutionGate
                        && (!config.cargo_runtime_execution_allowed
                            || !config.live_feed_execution_allowed
                            || !config.production_release_allowed),
                    "runtime execution, live feed, or production release gate is still closed",
                    5_000,
                    LiveInputStatus::Held,
                );
            }
            None => {
                let missing = LiveInputArtifact {
                    lane: requirement.lane,
                    artifact_id: stable_id(
                        "missing_live_input_artifact",
                        requirement.lane.as_str(),
                    ),
                    status: LiveInputStatus::Missing,
                    source_root: "missing".to_string(),
                    observed_root: "missing".to_string(),
                    source_height: 0,
                    watcher_quorum_bps: 0,
                    pq_quorum_bps: 0,
                    metadata_units: 0,
                    fee_bps: 0,
                    wallet_replayable: false,
                    note: "required live input artifact is missing".to_string(),
                };
                push_finding_if(
                    &mut findings,
                    requirement,
                    &missing,
                    true,
                    "required live input lane is missing",
                    10_000,
                    LiveInputStatus::Missing,
                );
            }
        }
    }
    findings
}

fn push_finding_if(
    findings: &mut Vec<LiveInputFinding>,
    requirement: &LiveInputRequirement,
    artifact: &LiveInputArtifact,
    condition: bool,
    reason: &str,
    severity_bps: u64,
    status: LiveInputStatus,
) {
    if condition {
        let finding_id = domain_hash(
            "monero-l2-pq-bridge-exit-user-escape-live-input-finding-id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(requirement.lane.as_str()),
                HashPart::Str(&requirement.requirement_id),
                HashPart::Str(&artifact.artifact_id),
                HashPart::Str(reason),
            ],
            16,
        );
        findings.push(LiveInputFinding {
            lane: requirement.lane,
            finding_id,
            status,
            severity_bps,
            reason: reason.to_string(),
            requirement_root: requirement.state_root(),
            artifact_root: artifact.state_root(),
        });
    }
}

fn summarize_lanes(
    requirements: &[LiveInputRequirement],
    artifacts: &[LiveInputArtifact],
    findings: &[LiveInputFinding],
) -> Vec<LaneSummary> {
    requirements
        .iter()
        .map(|requirement| {
            let lane_findings = findings
                .iter()
                .filter(|finding| finding.lane == requirement.lane)
                .collect::<Vec<_>>();
            let artifact = artifacts.iter().find(|item| item.lane == requirement.lane);
            let status = lane_status(artifact, &lane_findings);
            let severity_bps = lane_findings
                .iter()
                .map(|finding| finding.severity_bps)
                .sum::<u64>()
                .min(10_000);
            let artifact_root = match artifact {
                Some(item) => item.state_root(),
                None => "missing".to_string(),
            };
            let lane_root = record_root(
                "live_input_lane_summary_root",
                &json!({
                    "lane": requirement.lane.as_str(),
                    "requirement_root": requirement.state_root(),
                    "artifact_root": artifact_root,
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
    artifact: Option<&LiveInputArtifact>,
    lane_findings: &[&LiveInputFinding],
) -> LiveInputStatus {
    match artifact {
        Some(item) => {
            if lane_findings
                .iter()
                .any(|finding| finding.status == LiveInputStatus::Rejected)
            {
                LiveInputStatus::Rejected
            } else if lane_findings
                .iter()
                .any(|finding| finding.status == LiveInputStatus::Missing)
            {
                LiveInputStatus::Missing
            } else if !lane_findings.is_empty() || item.status == LiveInputStatus::Held {
                LiveInputStatus::Held
            } else {
                item.status
            }
        }
        None => LiveInputStatus::Missing,
    }
}

fn harness_roots(
    config: &Config,
    requirements: &[LiveInputRequirement],
    artifacts: &[LiveInputArtifact],
    findings: &[LiveInputFinding],
    lane_summaries: &[LaneSummary],
) -> HarnessRoots {
    let config_root = config.state_root();
    let requirement_root = merkle_root(
        "monero-l2-pq-bridge-exit-user-escape-live-input-requirements",
        &requirements
            .iter()
            .map(LiveInputRequirement::public_record)
            .collect::<Vec<_>>(),
    );
    let artifact_root = merkle_root(
        "monero-l2-pq-bridge-exit-user-escape-live-input-artifacts",
        &artifacts
            .iter()
            .map(LiveInputArtifact::public_record)
            .collect::<Vec<_>>(),
    );
    let finding_root = merkle_root(
        "monero-l2-pq-bridge-exit-user-escape-live-input-findings",
        &findings
            .iter()
            .map(LiveInputFinding::public_record)
            .collect::<Vec<_>>(),
    );
    let lane_summary_root = merkle_root(
        "monero-l2-pq-bridge-exit-user-escape-live-input-lane-summaries",
        &lane_summaries
            .iter()
            .map(LaneSummary::public_record)
            .collect::<Vec<_>>(),
    );
    let harness_root = record_root(
        "live_input_harness_root",
        &json!({
            "protocol_version": PROTOCOL_VERSION,
            "suite": LIVE_INPUT_HARNESS_SUITE,
            "chain_id": config.chain_id,
            "escape_id": config.escape_id,
            "config_root": config_root,
            "requirement_root": requirement_root,
            "artifact_root": artifact_root,
            "finding_root": finding_root,
            "lane_summary_root": lane_summary_root,
        }),
    );
    HarnessRoots {
        config_root,
        requirement_root,
        artifact_root,
        finding_root,
        lane_summary_root,
        harness_root,
    }
}

fn harness_answer(
    config: &Config,
    lane_summaries: &[LaneSummary],
    findings: &[LiveInputFinding],
    roots: &HarnessRoots,
) -> HarnessAnswer {
    let ready_lane_count = lane_summaries
        .iter()
        .filter(|summary| summary.status == LiveInputStatus::Ready)
        .count() as u64;
    let held_lane_count = lane_summaries
        .iter()
        .filter(|summary| summary.status == LiveInputStatus::Held)
        .count() as u64;
    let rejected_lane_count = lane_summaries
        .iter()
        .filter(|summary| summary.status == LiveInputStatus::Rejected)
        .count() as u64;
    let missing_lane_count = lane_summaries
        .iter()
        .filter(|summary| summary.status == LiveInputStatus::Missing)
        .count() as u64;
    let severity_bps = findings
        .iter()
        .map(|finding| finding.severity_bps)
        .sum::<u64>()
        .min(10_000);
    let verdict = if rejected_lane_count > 0 || missing_lane_count > 0 {
        HarnessVerdict::Rejected
    } else if held_lane_count > 0
        || !config.cargo_runtime_execution_allowed
        || !config.live_feed_execution_allowed
        || !config.production_release_allowed
    {
        HarnessVerdict::HeldForLiveInput
    } else {
        HarnessVerdict::Ready
    };
    let answer_root = record_root(
        "live_input_harness_answer_root",
        &json!({
            "escape_id": config.escape_id,
            "verdict": verdict.as_str(),
            "ready_lane_count": ready_lane_count,
            "held_lane_count": held_lane_count,
            "rejected_lane_count": rejected_lane_count,
            "missing_lane_count": missing_lane_count,
            "finding_count": findings.len(),
            "severity_bps": severity_bps,
            "harness_root": roots.harness_root,
        }),
    );
    HarnessAnswer {
        escape_id: config.escape_id.clone(),
        verdict,
        ready_lane_count,
        held_lane_count,
        rejected_lane_count,
        missing_lane_count,
        finding_count: findings.len() as u64,
        severity_bps,
        harness_root: roots.harness_root.clone(),
        answer_root,
    }
}

fn hold_reasons(
    requirements: &[LiveInputRequirement],
    artifacts: &[LiveInputArtifact],
    findings: &[LiveInputFinding],
    answer: &HarnessAnswer,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert(
        "live_input_harness_answer".to_string(),
        format!(
            "live input harness verdict is {} with {} findings",
            answer.verdict.as_str(),
            answer.finding_count
        ),
    );
    map.insert(
        "runtime_execution_gate".to_string(),
        "runtime gate remains held until cargo/runtime execution and live feed checks are allowed"
            .to_string(),
    );
    for requirement in requirements {
        if !artifacts
            .iter()
            .any(|artifact| artifact.lane == requirement.lane)
        {
            map.insert(
                format!("missing_{}", requirement.lane.as_str()),
                "required live input artifact is missing".to_string(),
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

fn required_source_roots(lane: LiveInputLane) -> Vec<String> {
    match lane {
        LiveInputLane::DepositLock => vec![
            "monero_lock_tx_observation_root",
            "deposit_address_commitment_root",
            "confirmation_reorg_observation_root",
            "bridge_custody_policy_observation_root",
        ],
        LiveInputLane::PrivateNote => vec![
            "encrypted_note_commitment_root",
            "note_tree_observation_root",
            "nullifier_key_image_separation_root",
            "metadata_budget_observation_root",
        ],
        LiveInputLane::SettlementReceipt => vec![
            "settlement_receipt_observation_root",
            "private_action_receipt_root",
            "withdrawal_claim_root",
            "challenge_dispute_clock_root",
        ],
        LiveInputLane::ReleaseVerification => vec![
            "release_verification_manifest_root",
            "wallet_release_verifier_root",
            "monero_broadcast_verifier_root",
            "pq_custody_verifier_root",
            "liquidity_verifier_root",
        ],
        LiveInputLane::AdversarialGap => vec![
            "deposit_reorg_observation_root",
            "watcher_collusion_observation_root",
            "sequencer_halt_observation_root",
            "liquidity_exhaustion_observation_root",
            "metadata_leak_observation_root",
        ],
        LiveInputLane::WalletRunbook => vec![
            "wallet_scan_export_root",
            "proof_collection_runbook_root",
            "forced_exit_claim_build_root",
            "release_verification_replay_root",
        ],
        LiveInputLane::RuntimeExecutionGate => vec![
            "cargo_runtime_gate_root",
            "live_feed_gate_root",
            "forced_exit_harness_gate_root",
        ],
    }
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn requirement_note(lane: LiveInputLane) -> &'static str {
    match lane {
        LiveInputLane::DepositLock => {
            "deposit live input must bind observed Monero lock, confirmation, reorg, custody, and wallet claim data"
        }
        LiveInputLane::PrivateNote => {
            "private note live input must bind note state while preserving nullifier and key-image separation"
        }
        LiveInputLane::SettlementReceipt => {
            "settlement live input must preserve continuity from private action receipt to withdrawal claim"
        }
        LiveInputLane::ReleaseVerification => {
            "release verification live input must bind wallet, broadcast, PQ custody, and liquidity verifier outputs"
        }
        LiveInputLane::AdversarialGap => {
            "adversarial live input must show failure observations hold or reject release"
        }
        LiveInputLane::WalletRunbook => {
            "wallet runbook live input must make the user escape procedure locally replayable"
        }
        LiveInputLane::RuntimeExecutionGate => {
            "runtime gate must remain held until cargo/runtime and live-feed execution are allowed"
        }
    }
}

fn artifact_note(lane: LiveInputLane) -> &'static str {
    match lane {
        LiveInputLane::DepositLock => {
            "devnet deposit observation input is ready for harness binding"
        }
        LiveInputLane::PrivateNote => "devnet private note input is redacted and wallet-replayable",
        LiveInputLane::SettlementReceipt => {
            "devnet settlement receipt input is linked to the withdrawal claim"
        }
        LiveInputLane::ReleaseVerification => {
            "devnet release verification input binds verifier verdict roots"
        }
        LiveInputLane::AdversarialGap => "devnet adversarial gap input records fail-closed cases",
        LiveInputLane::WalletRunbook => "devnet wallet runbook input is locally replayable",
        LiveInputLane::RuntimeExecutionGate => "runtime execution gate is intentionally held",
    }
}

fn source_root(lane: LiveInputLane, config: &Config) -> String {
    record_root(
        "live_input_source_root",
        &json!({
            "chain_id": config.chain_id,
            "vertical_slice_id": config.vertical_slice_id,
            "escape_id": config.escape_id,
            "lane": lane.as_str(),
            "input_build_height": config.input_build_height,
            "suite": LIVE_INPUT_HARNESS_SUITE,
        }),
    )
}

fn observed_root(lane: LiveInputLane, config: &Config, source_root: &str) -> String {
    record_root(
        "live_input_observed_root",
        &json!({
            "chain_id": config.chain_id,
            "escape_id": config.escape_id,
            "lane": lane.as_str(),
            "source_root": source_root,
            "monero_reference_height": config.monero_reference_height,
            "l2_reference_height": config.l2_reference_height,
        }),
    )
}

fn lane_age(lane: LiveInputLane) -> u64 {
    match lane {
        LiveInputLane::DepositLock => 4,
        LiveInputLane::PrivateNote => 5,
        LiveInputLane::SettlementReceipt => 6,
        LiveInputLane::ReleaseVerification => 8,
        LiveInputLane::AdversarialGap => 10,
        LiveInputLane::WalletRunbook => 7,
        LiveInputLane::RuntimeExecutionGate => 0,
    }
}

fn lane_watcher_quorum_bps(lane: LiveInputLane, config: &Config) -> u64 {
    match lane {
        LiveInputLane::AdversarialGap => config.min_watcher_quorum_bps + 200,
        LiveInputLane::RuntimeExecutionGate => config.min_watcher_quorum_bps,
        _ => config.min_watcher_quorum_bps + 500,
    }
}

fn lane_pq_quorum_bps(lane: LiveInputLane, config: &Config) -> u64 {
    match lane {
        LiveInputLane::PrivateNote
        | LiveInputLane::ReleaseVerification
        | LiveInputLane::WalletRunbook => config.min_pq_quorum_bps + 300,
        _ => config.min_pq_quorum_bps,
    }
}

fn lane_metadata_units(lane: LiveInputLane) -> u64 {
    match lane {
        LiveInputLane::AdversarialGap => 2,
        LiveInputLane::RuntimeExecutionGate => 0,
        _ => 1,
    }
}

fn lane_fee_bps(lane: LiveInputLane) -> u64 {
    match lane {
        LiveInputLane::SettlementReceipt => 18,
        LiveInputLane::ReleaseVerification => 20,
        LiveInputLane::RuntimeExecutionGate => 0,
        _ => 12,
    }
}

fn wallet_replayable(lane: LiveInputLane) -> bool {
    !matches!(lane, LiveInputLane::RuntimeExecutionGate)
}

fn stable_id(kind: &str, label: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-user-escape-live-input-stable-id",
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
