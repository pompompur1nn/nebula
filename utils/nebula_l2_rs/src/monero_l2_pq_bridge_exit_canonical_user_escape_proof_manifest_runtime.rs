use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeProofManifestRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_PROOF_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-user-escape-proof-manifest-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_PROOF_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const USER_ESCAPE_PROOF_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-proof-suite-v1";
pub const DEFAULT_ESCAPE_ID: &str = "monero-l2-pq-bridge-exit-canonical-user-escape-devnet-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_MIN_MONERO_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MIN_WATCHER_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_MIN_PQ_QUORUM_BPS: u64 = 7_500;
pub const DEFAULT_MAX_METADATA_UNITS: u64 = 2;
pub const DEFAULT_MAX_FEE_BPS: u64 = 25;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeProofLane {
    DepositLock,
    PrivateNoteTransfer,
    SettlementReceipt,
    ReleaseVerification,
    AdversarialProof,
    WalletRunbook,
    RuntimeExecutionGate,
}

impl EscapeProofLane {
    pub fn all() -> [Self; 7] {
        [
            Self::DepositLock,
            Self::PrivateNoteTransfer,
            Self::SettlementReceipt,
            Self::ReleaseVerification,
            Self::AdversarialProof,
            Self::WalletRunbook,
            Self::RuntimeExecutionGate,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DepositLock => "deposit_lock",
            Self::PrivateNoteTransfer => "private_note_transfer",
            Self::SettlementReceipt => "settlement_receipt",
            Self::ReleaseVerification => "release_verification",
            Self::AdversarialProof => "adversarial_proof",
            Self::WalletRunbook => "wallet_runbook",
            Self::RuntimeExecutionGate => "runtime_execution_gate",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::DepositLock => "Monero deposit lock proof",
            Self::PrivateNoteTransfer => "Private note transfer proof",
            Self::SettlementReceipt => "Settlement receipt proof",
            Self::ReleaseVerification => "Release verification proof",
            Self::AdversarialProof => "Adversarial proof gaps",
            Self::WalletRunbook => "Wallet escape runbook proof",
            Self::RuntimeExecutionGate => "Runtime execution gate",
        }
    }

    pub fn weight_bps(&self) -> u64 {
        match self {
            Self::DepositLock => 1_600,
            Self::PrivateNoteTransfer => 1_500,
            Self::SettlementReceipt => 1_400,
            Self::ReleaseVerification => 1_800,
            Self::AdversarialProof => 1_200,
            Self::WalletRunbook => 1_000,
            Self::RuntimeExecutionGate => 1_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeProofStatus {
    Proven,
    Watch,
    Held,
    Rejected,
}

impl EscapeProofStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Watch => "watch",
            Self::Held => "held",
            Self::Rejected => "rejected",
        }
    }

    pub fn blocks_escape(&self) -> bool {
        !matches!(self, Self::Proven)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserEscapeVerdict {
    Ready,
    HeldForRuntime,
    Rejected,
}

impl UserEscapeVerdict {
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
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
    pub deposit_observed_height: u64,
    pub proof_build_height: u64,
    pub min_monero_confirmations: u64,
    pub min_watcher_quorum_bps: u64,
    pub min_pq_quorum_bps: u64,
    pub max_metadata_units: u64,
    pub max_fee_bps: u64,
    pub cargo_runtime_execution_allowed: bool,
    pub live_feed_execution_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            escape_id: DEFAULT_ESCAPE_ID.to_string(),
            l2_reference_height: 1_052_551,
            monero_reference_height: 3_160_940,
            deposit_observed_height: 10_120,
            proof_build_height: 10_260,
            min_monero_confirmations: DEFAULT_MIN_MONERO_CONFIRMATIONS,
            min_watcher_quorum_bps: DEFAULT_MIN_WATCHER_QUORUM_BPS,
            min_pq_quorum_bps: DEFAULT_MIN_PQ_QUORUM_BPS,
            max_metadata_units: DEFAULT_MAX_METADATA_UNITS,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            cargo_runtime_execution_allowed: false,
            live_feed_execution_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "vertical_slice_id": self.vertical_slice_id,
            "escape_id": self.escape_id,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "deposit_observed_height": self.deposit_observed_height,
            "proof_build_height": self.proof_build_height,
            "min_monero_confirmations": self.min_monero_confirmations,
            "min_watcher_quorum_bps": self.min_watcher_quorum_bps,
            "min_pq_quorum_bps": self.min_pq_quorum_bps,
            "max_metadata_units": self.max_metadata_units,
            "max_fee_bps": self.max_fee_bps,
            "cargo_runtime_execution_allowed": bool_label(self.cargo_runtime_execution_allowed),
            "live_feed_execution_allowed": bool_label(self.live_feed_execution_allowed),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("user_escape_proof_config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EscapeProofRequirement {
    pub lane: EscapeProofLane,
    pub requirement_id: String,
    pub expected_root: String,
    pub required_status: EscapeProofStatus,
    pub fail_closed: bool,
    pub required_evidence: Vec<String>,
    pub note: String,
}

impl EscapeProofRequirement {
    pub fn new(lane: EscapeProofLane, config: &Config, required_evidence: Vec<String>) -> Self {
        Self {
            lane,
            requirement_id: stable_id("user_escape_requirement", lane.as_str()),
            expected_root: expected_lane_root(lane, config),
            required_status: EscapeProofStatus::Proven,
            fail_closed: true,
            required_evidence,
            note: requirement_note(lane).to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "lane_label": self.lane.label(),
            "requirement_id": self.requirement_id,
            "expected_root": self.expected_root,
            "required_status": self.required_status.as_str(),
            "fail_closed": bool_label(self.fail_closed),
            "required_evidence": self.required_evidence,
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("user_escape_requirement", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EscapeProofArtifact {
    pub lane: EscapeProofLane,
    pub artifact_id: String,
    pub supplied_root: String,
    pub expected_root: String,
    pub status: EscapeProofStatus,
    pub blocker_count: u64,
    pub watcher_quorum_bps: u64,
    pub pq_quorum_bps: u64,
    pub confirmations: u64,
    pub metadata_units: u64,
    pub fee_bps: u64,
    pub redacted_payload_root: String,
}

impl EscapeProofArtifact {
    pub fn proven(lane: EscapeProofLane, config: &Config) -> Self {
        let expected_root = expected_lane_root(lane, config);
        let artifact_id = stable_id("user_escape_artifact", lane.as_str());
        let redacted_payload_root = record_root(
            "user_escape_artifact_redacted_payload",
            &json!({
                "lane": lane.as_str(),
                "escape_id": config.escape_id,
                "expected_root": expected_root,
                "visibility": "redacted",
            }),
        );
        Self {
            lane,
            artifact_id,
            supplied_root: expected_root.clone(),
            expected_root,
            status: EscapeProofStatus::Proven,
            blocker_count: 0,
            watcher_quorum_bps: config.min_watcher_quorum_bps,
            pq_quorum_bps: config.min_pq_quorum_bps,
            confirmations: config.min_monero_confirmations,
            metadata_units: config.max_metadata_units,
            fee_bps: config.max_fee_bps,
            redacted_payload_root,
        }
    }

    pub fn held_runtime_gate(config: &Config) -> Self {
        let lane = EscapeProofLane::RuntimeExecutionGate;
        let expected_root = expected_lane_root(lane, config);
        let supplied_root = record_root(
            "user_escape_runtime_gate_supplied_root",
            &json!({
                "lane": lane.as_str(),
                "expected_root": expected_root,
                "cargo_runtime_execution_allowed": bool_label(config.cargo_runtime_execution_allowed),
                "live_feed_execution_allowed": bool_label(config.live_feed_execution_allowed),
            }),
        );
        let redacted_payload_root = record_root(
            "user_escape_runtime_gate_payload",
            &json!({
                "lane": lane.as_str(),
                "hold": "cargo_runtime_and_live_feed_execution_deferred",
            }),
        );
        Self {
            lane,
            artifact_id: stable_id("user_escape_runtime_gate_artifact", lane.as_str()),
            supplied_root,
            expected_root,
            status: EscapeProofStatus::Held,
            blocker_count: 1,
            watcher_quorum_bps: 0,
            pq_quorum_bps: 0,
            confirmations: 0,
            metadata_units: config.max_metadata_units,
            fee_bps: 0,
            redacted_payload_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "lane_label": self.lane.label(),
            "artifact_id": self.artifact_id,
            "supplied_root": self.supplied_root,
            "expected_root": self.expected_root,
            "status": self.status.as_str(),
            "blocker_count": self.blocker_count,
            "watcher_quorum_bps": self.watcher_quorum_bps,
            "pq_quorum_bps": self.pq_quorum_bps,
            "confirmations": self.confirmations,
            "metadata_units": self.metadata_units,
            "fee_bps": self.fee_bps,
            "redacted_payload_root": self.redacted_payload_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("user_escape_artifact", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EscapeProofGap {
    pub lane: EscapeProofLane,
    pub gap_id: String,
    pub requirement_id: String,
    pub status: EscapeProofStatus,
    pub severity_bps: u64,
    pub reason: String,
    pub expected_root: String,
    pub supplied_root: String,
}

impl EscapeProofGap {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "lane_label": self.lane.label(),
            "gap_id": self.gap_id,
            "requirement_id": self.requirement_id,
            "status": self.status.as_str(),
            "severity_bps": self.severity_bps,
            "reason": self.reason,
            "expected_root": self.expected_root,
            "supplied_root": self.supplied_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("user_escape_gap", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneSummary {
    pub lane: EscapeProofLane,
    pub status: EscapeProofStatus,
    pub gap_count: u64,
    pub blocker_count: u64,
    pub severity_bps: u64,
    pub lane_weight_bps: u64,
    pub lane_root: String,
}

impl LaneSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "lane_label": self.lane.label(),
            "status": self.status.as_str(),
            "gap_count": self.gap_count,
            "blocker_count": self.blocker_count,
            "severity_bps": self.severity_bps,
            "lane_weight_bps": self.lane_weight_bps,
            "lane_root": self.lane_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EscapeProofRoots {
    pub config_root: String,
    pub requirement_root: String,
    pub artifact_root: String,
    pub gap_root: String,
    pub lane_summary_root: String,
    pub proof_package_root: String,
    pub escape_answer_root: String,
    pub manifest_id: String,
}

impl EscapeProofRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "requirement_root": self.requirement_root,
            "artifact_root": self.artifact_root,
            "gap_root": self.gap_root,
            "lane_summary_root": self.lane_summary_root,
            "proof_package_root": self.proof_package_root,
            "escape_answer_root": self.escape_answer_root,
            "manifest_id": self.manifest_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserEscapeAnswer {
    pub escape_id: String,
    pub verdict: UserEscapeVerdict,
    pub proven_lane_count: u64,
    pub held_lane_count: u64,
    pub rejected_lane_count: u64,
    pub blocker_count: u64,
    pub severity_bps: u64,
    pub proof_package_root: String,
    pub answer_root: String,
}

impl UserEscapeAnswer {
    pub fn public_record(&self) -> Value {
        json!({
            "escape_id": self.escape_id,
            "verdict": self.verdict.as_str(),
            "proven_lane_count": self.proven_lane_count,
            "held_lane_count": self.held_lane_count,
            "rejected_lane_count": self.rejected_lane_count,
            "blocker_count": self.blocker_count,
            "severity_bps": self.severity_bps,
            "proof_package_root": self.proof_package_root,
            "answer_root": self.answer_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub requirements: Vec<EscapeProofRequirement>,
    pub artifacts: Vec<EscapeProofArtifact>,
    pub gaps: Vec<EscapeProofGap>,
    pub lane_summaries: Vec<LaneSummary>,
    pub roots: EscapeProofRoots,
    pub escape_answer: UserEscapeAnswer,
    pub hold_map: BTreeMap<String, String>,
}

impl State {
    pub fn new(
        config: Config,
        requirements: Vec<EscapeProofRequirement>,
        artifacts: Vec<EscapeProofArtifact>,
    ) -> Self {
        let gaps = evaluate_gaps(&config, &requirements, &artifacts);
        let lane_summaries = summarize_lanes(&requirements, &artifacts, &gaps);
        let roots = escape_roots(&config, &requirements, &artifacts, &gaps, &lane_summaries);
        let escape_answer = user_escape_answer(&config, &lane_summaries, &gaps, &roots);
        let hold_map = hold_map(&requirements, &artifacts, &gaps, &escape_answer);
        Self {
            config,
            requirements,
            artifacts,
            gaps,
            lane_summaries,
            roots,
            escape_answer,
            hold_map,
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let requirements = default_requirements(&config);
        let artifacts = default_artifacts(&config);
        Self::new(config, requirements, artifacts)
    }

    pub fn validate(&self) -> Result<UserEscapeAnswer> {
        let missing = missing_lanes(&self.requirements, &self.artifacts);
        if !missing.is_empty() {
            return Err(format!(
                "missing user escape proof lanes: {}",
                missing.join(",")
            ));
        }
        if self.requirements.len() != EscapeProofLane::all().len() {
            return Err("user escape proof requirement count mismatch".to_string());
        }
        let blocker_count = self.gaps.len() as u64;
        if blocker_count != self.escape_answer.blocker_count {
            return Err(format!(
                "user escape blocker count mismatch: gaps={} answer={}",
                blocker_count, self.escape_answer.blocker_count
            ));
        }
        Ok(self.escape_answer.clone())
    }

    pub fn user_escape_ready(&self) -> bool {
        self.escape_answer.verdict == UserEscapeVerdict::Ready
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "requirements": self.requirements.iter().map(EscapeProofRequirement::public_record).collect::<Vec<_>>(),
            "artifacts": self.artifacts.iter().map(EscapeProofArtifact::public_record).collect::<Vec<_>>(),
            "gaps": self.gaps.iter().map(EscapeProofGap::public_record).collect::<Vec<_>>(),
            "lane_summaries": self.lane_summaries.iter().map(LaneSummary::public_record).collect::<Vec<_>>(),
            "roots": self.roots.public_record(),
            "escape_answer": self.escape_answer.public_record(),
            "hold_map": self.hold_map,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("user_escape_proof_manifest_state", &self.public_record())
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
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

pub fn default_requirements(config: &Config) -> Vec<EscapeProofRequirement> {
    EscapeProofLane::all()
        .into_iter()
        .map(|lane| EscapeProofRequirement::new(lane, config, required_evidence(lane)))
        .collect()
}

pub fn default_artifacts(config: &Config) -> Vec<EscapeProofArtifact> {
    vec![
        EscapeProofArtifact::proven(EscapeProofLane::DepositLock, config),
        EscapeProofArtifact::proven(EscapeProofLane::PrivateNoteTransfer, config),
        EscapeProofArtifact::proven(EscapeProofLane::SettlementReceipt, config),
        EscapeProofArtifact::proven(EscapeProofLane::ReleaseVerification, config),
        EscapeProofArtifact::proven(EscapeProofLane::AdversarialProof, config),
        EscapeProofArtifact::proven(EscapeProofLane::WalletRunbook, config),
        EscapeProofArtifact::held_runtime_gate(config),
    ]
}

fn evaluate_gaps(
    config: &Config,
    requirements: &[EscapeProofRequirement],
    artifacts: &[EscapeProofArtifact],
) -> Vec<EscapeProofGap> {
    let mut gaps = Vec::new();
    for requirement in requirements {
        match artifacts
            .iter()
            .find(|artifact| artifact.lane == requirement.lane)
        {
            Some(artifact) => {
                push_gap_if(
                    &mut gaps,
                    requirement,
                    artifact,
                    artifact.expected_root != requirement.expected_root
                        || artifact.supplied_root != requirement.expected_root,
                    "proof_root_mismatch",
                    3_000,
                );
                push_gap_if(
                    &mut gaps,
                    requirement,
                    artifact,
                    artifact.status.blocks_escape(),
                    "proof_status_not_proven",
                    3_400,
                );
                push_gap_if(
                    &mut gaps,
                    requirement,
                    artifact,
                    artifact.watcher_quorum_bps < config.min_watcher_quorum_bps
                        && requirement.lane != EscapeProofLane::RuntimeExecutionGate,
                    "watcher_quorum_shortfall",
                    1_800,
                );
                push_gap_if(
                    &mut gaps,
                    requirement,
                    artifact,
                    artifact.pq_quorum_bps < config.min_pq_quorum_bps
                        && requires_pq_quorum(requirement.lane),
                    "pq_quorum_shortfall",
                    2_200,
                );
                push_gap_if(
                    &mut gaps,
                    requirement,
                    artifact,
                    artifact.metadata_units > config.max_metadata_units,
                    "metadata_budget_exceeded",
                    2_400,
                );
                push_gap_if(
                    &mut gaps,
                    requirement,
                    artifact,
                    artifact.fee_bps > config.max_fee_bps,
                    "fee_bound_exceeded",
                    900,
                );
            }
            None => gaps.push(EscapeProofGap {
                lane: requirement.lane,
                gap_id: stable_id("missing_user_escape_lane", requirement.lane.as_str()),
                requirement_id: requirement.requirement_id.clone(),
                status: EscapeProofStatus::Rejected,
                severity_bps: 5_000,
                reason: "required user escape proof lane is missing".to_string(),
                expected_root: requirement.expected_root.clone(),
                supplied_root: "missing".to_string(),
            }),
        }
    }
    gaps
}

fn push_gap_if(
    gaps: &mut Vec<EscapeProofGap>,
    requirement: &EscapeProofRequirement,
    artifact: &EscapeProofArtifact,
    condition: bool,
    reason: &str,
    severity_bps: u64,
) {
    if condition {
        let gap_id = domain_hash(
            "monero-l2-pq-bridge-exit-user-escape-proof-gap-id",
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
        gaps.push(EscapeProofGap {
            lane: requirement.lane,
            gap_id,
            requirement_id: requirement.requirement_id.clone(),
            status: artifact.status,
            severity_bps,
            reason: reason.to_string(),
            expected_root: requirement.expected_root.clone(),
            supplied_root: artifact.supplied_root.clone(),
        });
    }
}

fn summarize_lanes(
    requirements: &[EscapeProofRequirement],
    artifacts: &[EscapeProofArtifact],
    gaps: &[EscapeProofGap],
) -> Vec<LaneSummary> {
    requirements
        .iter()
        .map(|requirement| {
            let lane_gaps = gaps
                .iter()
                .filter(|gap| gap.lane == requirement.lane)
                .collect::<Vec<_>>();
            let artifact = artifacts.iter().find(|item| item.lane == requirement.lane);
            let status = lane_status(requirement, artifact, &lane_gaps);
            let severity_bps = lane_gaps
                .iter()
                .map(|gap| gap.severity_bps)
                .sum::<u64>()
                .min(10_000);
            let artifact_root = match artifact {
                Some(item) => item.state_root(),
                None => "missing".to_string(),
            };
            let lane_root = record_root(
                "user_escape_lane_summary",
                &json!({
                    "lane": requirement.lane.as_str(),
                    "requirement_root": requirement.state_root(),
                    "artifact_root": artifact_root,
                    "gap_roots": lane_gaps.iter().map(|gap| gap.state_root()).collect::<Vec<_>>(),
                    "status": status.as_str(),
                    "severity_bps": severity_bps,
                }),
            );
            LaneSummary {
                lane: requirement.lane,
                status,
                gap_count: lane_gaps.len() as u64,
                blocker_count: lane_gaps.len() as u64,
                severity_bps,
                lane_weight_bps: requirement.lane.weight_bps(),
                lane_root,
            }
        })
        .collect()
}

fn lane_status(
    requirement: &EscapeProofRequirement,
    artifact: Option<&EscapeProofArtifact>,
    lane_gaps: &[&EscapeProofGap],
) -> EscapeProofStatus {
    if artifact.is_none() {
        EscapeProofStatus::Rejected
    } else if lane_gaps
        .iter()
        .any(|gap| gap.status == EscapeProofStatus::Rejected)
    {
        EscapeProofStatus::Rejected
    } else if !lane_gaps.is_empty() && requirement.fail_closed {
        EscapeProofStatus::Held
    } else {
        match artifact {
            Some(item) => item.status,
            None => EscapeProofStatus::Rejected,
        }
    }
}

fn escape_roots(
    config: &Config,
    requirements: &[EscapeProofRequirement],
    artifacts: &[EscapeProofArtifact],
    gaps: &[EscapeProofGap],
    lane_summaries: &[LaneSummary],
) -> EscapeProofRoots {
    let config_root = config.state_root();
    let requirement_root = merkle_root(
        "monero-l2-pq-bridge-exit-user-escape-proof-requirements",
        &requirements
            .iter()
            .map(EscapeProofRequirement::public_record)
            .collect::<Vec<_>>(),
    );
    let artifact_root = merkle_root(
        "monero-l2-pq-bridge-exit-user-escape-proof-artifacts",
        &artifacts
            .iter()
            .map(EscapeProofArtifact::public_record)
            .collect::<Vec<_>>(),
    );
    let gap_root = merkle_root(
        "monero-l2-pq-bridge-exit-user-escape-proof-gaps",
        &gaps
            .iter()
            .map(EscapeProofGap::public_record)
            .collect::<Vec<_>>(),
    );
    let lane_summary_root = merkle_root(
        "monero-l2-pq-bridge-exit-user-escape-proof-lane-summaries",
        &lane_summaries
            .iter()
            .map(LaneSummary::public_record)
            .collect::<Vec<_>>(),
    );
    let proof_package_root = domain_hash(
        "monero-l2-pq-bridge-exit-user-escape-proof-package-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config_root),
            HashPart::Str(&requirement_root),
            HashPart::Str(&artifact_root),
            HashPart::Str(&gap_root),
            HashPart::Str(&lane_summary_root),
        ],
        32,
    );
    let escape_answer_root = domain_hash(
        "monero-l2-pq-bridge-exit-user-escape-proof-answer-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.escape_id),
            HashPart::Str(&proof_package_root),
            HashPart::U64(config.proof_build_height),
        ],
        32,
    );
    let manifest_id = domain_hash(
        "monero-l2-pq-bridge-exit-user-escape-proof-manifest-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.vertical_slice_id),
            HashPart::Str(&config.escape_id),
            HashPart::Str(&escape_answer_root),
        ],
        16,
    );
    EscapeProofRoots {
        config_root,
        requirement_root,
        artifact_root,
        gap_root,
        lane_summary_root,
        proof_package_root,
        escape_answer_root,
        manifest_id,
    }
}

fn user_escape_answer(
    config: &Config,
    lane_summaries: &[LaneSummary],
    gaps: &[EscapeProofGap],
    roots: &EscapeProofRoots,
) -> UserEscapeAnswer {
    let proven_lane_count = lane_summaries
        .iter()
        .filter(|summary| summary.status == EscapeProofStatus::Proven)
        .count() as u64;
    let held_lane_count = lane_summaries
        .iter()
        .filter(|summary| {
            summary.status == EscapeProofStatus::Held || summary.status == EscapeProofStatus::Watch
        })
        .count() as u64;
    let rejected_lane_count = lane_summaries
        .iter()
        .filter(|summary| summary.status == EscapeProofStatus::Rejected)
        .count() as u64;
    let severity_bps = gaps
        .iter()
        .map(|gap| gap.severity_bps)
        .sum::<u64>()
        .min(10_000);
    let verdict = if rejected_lane_count > 0 {
        UserEscapeVerdict::Rejected
    } else if held_lane_count > 0 || !config.cargo_runtime_execution_allowed {
        UserEscapeVerdict::HeldForRuntime
    } else {
        UserEscapeVerdict::Ready
    };
    let answer_root = record_root(
        "user_escape_answer",
        &json!({
            "escape_id": config.escape_id,
            "verdict": verdict.as_str(),
            "proven_lane_count": proven_lane_count,
            "held_lane_count": held_lane_count,
            "rejected_lane_count": rejected_lane_count,
            "blocker_count": gaps.len(),
            "severity_bps": severity_bps,
            "proof_package_root": roots.proof_package_root,
        }),
    );
    UserEscapeAnswer {
        escape_id: config.escape_id.clone(),
        verdict,
        proven_lane_count,
        held_lane_count,
        rejected_lane_count,
        blocker_count: gaps.len() as u64,
        severity_bps,
        proof_package_root: roots.proof_package_root.clone(),
        answer_root,
    }
}

fn hold_map(
    requirements: &[EscapeProofRequirement],
    artifacts: &[EscapeProofArtifact],
    gaps: &[EscapeProofGap],
    answer: &UserEscapeAnswer,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert(
        "user_escape_answer".to_string(),
        format!(
            "user escape verdict is {} with {} proof blockers",
            answer.verdict.as_str(),
            answer.blocker_count
        ),
    );
    map.insert(
        "cargo_runtime_execution".to_string(),
        "proof package is deterministic only until cargo/runtime execution is allowed".to_string(),
    );
    for requirement in requirements {
        if !artifacts
            .iter()
            .any(|artifact| artifact.lane == requirement.lane)
        {
            map.insert(
                format!("missing_{}", requirement.lane.as_str()),
                "required user escape proof artifact is missing".to_string(),
            );
        }
    }
    for gap in gaps {
        map.insert(
            format!("gap_{}_{}", gap.lane.as_str(), gap.gap_id),
            gap.reason.clone(),
        );
    }
    map
}

fn missing_lanes(
    requirements: &[EscapeProofRequirement],
    artifacts: &[EscapeProofArtifact],
) -> Vec<String> {
    requirements
        .iter()
        .filter(|requirement| {
            !artifacts
                .iter()
                .any(|artifact| artifact.lane == requirement.lane)
        })
        .map(|requirement| requirement.lane.as_str().to_string())
        .collect()
}

fn required_evidence(lane: EscapeProofLane) -> Vec<String> {
    match lane {
        EscapeProofLane::DepositLock => vec![
            "monero_lock_tx_commitment",
            "deposit_address_commitment",
            "confirmation_reorg_window",
            "bridge_custody_policy_root",
        ],
        EscapeProofLane::PrivateNoteTransfer => vec![
            "encrypted_note_commitment",
            "note_tree_root",
            "nullifier_key_image_separation",
            "metadata_budget_root",
        ],
        EscapeProofLane::SettlementReceipt => vec![
            "settlement_receipt_root",
            "private_action_receipt_root",
            "withdrawal_claim_root",
            "challenge_dispute_clock",
        ],
        EscapeProofLane::ReleaseVerification => vec![
            "release_verification_manifest_root",
            "wallet_verifier_root",
            "monero_broadcast_verifier_root",
            "pq_custody_verifier_root",
            "liquidity_verifier_root",
        ],
        EscapeProofLane::AdversarialProof => vec![
            "deposit_reorg_case",
            "watcher_collusion_case",
            "sequencer_halt_case",
            "metadata_leak_case",
        ],
        EscapeProofLane::WalletRunbook => vec![
            "wallet_scan_step_root",
            "proof_collection_step_root",
            "forced_exit_claim_step_root",
            "release_verification_step_root",
        ],
        EscapeProofLane::RuntimeExecutionGate => vec![
            "cargo_runtime_gate",
            "live_feed_gate",
            "forced_exit_harness_gate",
        ],
    }
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn requirement_note(lane: EscapeProofLane) -> &'static str {
    match lane {
        EscapeProofLane::DepositLock => {
            "deposit lock proof must bind Monero lock, bridge custody, confirmation, and wallet claim evidence"
        }
        EscapeProofLane::PrivateNoteTransfer => {
            "private note proof must bind encrypted state while preserving nullifier and key-image separation"
        }
        EscapeProofLane::SettlementReceipt => {
            "settlement proof must preserve continuity from private action receipt to withdrawal claim"
        }
        EscapeProofLane::ReleaseVerification => {
            "release verification proof must bind lane verifiers into one user-exit verdict"
        }
        EscapeProofLane::AdversarialProof => {
            "adversarial proof must show known failure modes hold or reject release"
        }
        EscapeProofLane::WalletRunbook => {
            "wallet runbook proof must make the user escape procedure reproducible"
        }
        EscapeProofLane::RuntimeExecutionGate => {
            "runtime gate must remain held until cargo/runtime and live-feed execution are allowed"
        }
    }
}

fn requires_pq_quorum(lane: EscapeProofLane) -> bool {
    matches!(
        lane,
        EscapeProofLane::PrivateNoteTransfer
            | EscapeProofLane::ReleaseVerification
            | EscapeProofLane::WalletRunbook
    )
}

fn expected_lane_root(lane: EscapeProofLane, config: &Config) -> String {
    record_root(
        "user_escape_expected_lane_root",
        &json!({
            "chain_id": config.chain_id,
            "vertical_slice_id": config.vertical_slice_id,
            "escape_id": config.escape_id,
            "lane": lane.as_str(),
            "proof_build_height": config.proof_build_height,
            "suite": USER_ESCAPE_PROOF_SUITE,
        }),
    )
}

fn stable_id(kind: &str, label: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-user-escape-proof-stable-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        16,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-user-escape-proof-record-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
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
