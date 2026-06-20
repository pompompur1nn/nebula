use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceRuntimeReleaseVerificationManifestRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_RELEASE_VERIFICATION_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-vertical-slice-runtime-release-verification-manifest-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_RELEASE_VERIFICATION_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const RELEASE_VERIFICATION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-release-verification-suite-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_USER_EXIT_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-user-exit-release-verification-devnet-v1";
pub const DEFAULT_MIN_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_MIN_PQ_QUORUM_BPS: u64 = 7_500;
pub const DEFAULT_MIN_WATCHER_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_MAX_METADATA_UNITS: u64 = 2;
pub const DEFAULT_FRESHNESS_LIMIT_BLOCKS: u64 = 36;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseVerificationLane {
    ReceiptManifest,
    WalletRelease,
    MoneroBroadcast,
    PqCustody,
    LiquiditySettlement,
    ChallengeWindow,
    LiveFeed,
    PrivacyBoundary,
    Adversarial,
    ReleaseBlocker,
}

impl ReleaseVerificationLane {
    pub fn all() -> [Self; 10] {
        [
            Self::ReceiptManifest,
            Self::WalletRelease,
            Self::MoneroBroadcast,
            Self::PqCustody,
            Self::LiquiditySettlement,
            Self::ChallengeWindow,
            Self::LiveFeed,
            Self::PrivacyBoundary,
            Self::Adversarial,
            Self::ReleaseBlocker,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReceiptManifest => "receipt_manifest",
            Self::WalletRelease => "wallet_release",
            Self::MoneroBroadcast => "monero_broadcast",
            Self::PqCustody => "pq_custody",
            Self::LiquiditySettlement => "liquidity_settlement",
            Self::ChallengeWindow => "challenge_window",
            Self::LiveFeed => "live_feed",
            Self::PrivacyBoundary => "privacy_boundary",
            Self::Adversarial => "adversarial",
            Self::ReleaseBlocker => "release_blocker",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::ReceiptManifest => "Release receipt manifest",
            Self::WalletRelease => "Wallet release verification",
            Self::MoneroBroadcast => "Monero broadcast verification",
            Self::PqCustody => "PQ custody verification",
            Self::LiquiditySettlement => "Liquidity settlement verification",
            Self::ChallengeWindow => "Challenge window verification",
            Self::LiveFeed => "Live feed verification",
            Self::PrivacyBoundary => "Privacy boundary verification",
            Self::Adversarial => "Adversarial verification",
            Self::ReleaseBlocker => "Release blocker verification",
        }
    }

    pub fn weight_bps(&self) -> u64 {
        match self {
            Self::ReceiptManifest => 1_000,
            Self::WalletRelease => 1_100,
            Self::MoneroBroadcast => 1_200,
            Self::PqCustody => 1_300,
            Self::LiquiditySettlement => 1_100,
            Self::ChallengeWindow => 900,
            Self::LiveFeed => 1_000,
            Self::PrivacyBoundary => 900,
            Self::Adversarial => 900,
            Self::ReleaseBlocker => 600,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseVerificationStatus {
    Accepted,
    Watch,
    Quarantined,
    Blocked,
}

impl ReleaseVerificationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Watch => "watch",
            Self::Quarantined => "quarantined",
            Self::Blocked => "blocked",
        }
    }

    pub fn blocks_user_exit(&self) -> bool {
        !matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserExitVerdict {
    Ready,
    Held,
    Rejected,
}

impl UserExitVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Held => "held",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub vertical_slice_id: String,
    pub user_exit_id: String,
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
    pub release_receipt_height: u64,
    pub verification_height: u64,
    pub challenge_window_close_height: u64,
    pub dispute_window_close_height: u64,
    pub reorg_watch_close_height: u64,
    pub freshness_limit_blocks: u64,
    pub min_confirmations: u64,
    pub min_pq_quorum_bps: u64,
    pub min_watcher_quorum_bps: u64,
    pub max_metadata_units: u64,
    pub require_live_feed: bool,
    pub require_security_review_gate: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            user_exit_id: DEFAULT_USER_EXIT_ID.to_string(),
            l2_reference_height: 1_048_514,
            monero_reference_height: 3_160_880,
            release_receipt_height: 10_220,
            verification_height: 10_244,
            challenge_window_close_height: 10_190,
            dispute_window_close_height: 10_210,
            reorg_watch_close_height: 10_238,
            freshness_limit_blocks: DEFAULT_FRESHNESS_LIMIT_BLOCKS,
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            min_pq_quorum_bps: DEFAULT_MIN_PQ_QUORUM_BPS,
            min_watcher_quorum_bps: DEFAULT_MIN_WATCHER_QUORUM_BPS,
            max_metadata_units: DEFAULT_MAX_METADATA_UNITS,
            require_live_feed: true,
            require_security_review_gate: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "vertical_slice_id": self.vertical_slice_id,
            "user_exit_id": self.user_exit_id,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "release_receipt_height": self.release_receipt_height,
            "verification_height": self.verification_height,
            "challenge_window_close_height": self.challenge_window_close_height,
            "dispute_window_close_height": self.dispute_window_close_height,
            "reorg_watch_close_height": self.reorg_watch_close_height,
            "freshness_limit_blocks": self.freshness_limit_blocks,
            "min_confirmations": self.min_confirmations,
            "min_pq_quorum_bps": self.min_pq_quorum_bps,
            "min_watcher_quorum_bps": self.min_watcher_quorum_bps,
            "max_metadata_units": self.max_metadata_units,
            "require_live_feed": bool_label(self.require_live_feed),
            "require_security_review_gate": bool_label(self.require_security_review_gate),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_verification_config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerificationRequirement {
    pub lane: ReleaseVerificationLane,
    pub requirement_id: String,
    pub expected_root: String,
    pub required: bool,
    pub fail_closed: bool,
    pub min_confirmations: u64,
    pub min_quorum_bps: u64,
    pub max_metadata_units: u64,
    pub freshness_limit_blocks: u64,
    pub note: String,
}

impl VerificationRequirement {
    pub fn new(
        lane: ReleaseVerificationLane,
        config: &Config,
        min_confirmations: u64,
        min_quorum_bps: u64,
        max_metadata_units: u64,
        note: &str,
    ) -> Self {
        let requirement_id = stable_id("release_verification_requirement", lane.as_str());
        let expected_root = expected_lane_root(lane, config);
        Self {
            lane,
            requirement_id,
            expected_root,
            required: true,
            fail_closed: true,
            min_confirmations,
            min_quorum_bps,
            max_metadata_units,
            freshness_limit_blocks: config.freshness_limit_blocks,
            note: note.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "lane_label": self.lane.label(),
            "requirement_id": self.requirement_id,
            "expected_root": self.expected_root,
            "required": bool_label(self.required),
            "fail_closed": bool_label(self.fail_closed),
            "min_confirmations": self.min_confirmations,
            "min_quorum_bps": self.min_quorum_bps,
            "max_metadata_units": self.max_metadata_units,
            "freshness_limit_blocks": self.freshness_limit_blocks,
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_verification_requirement", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerificationEvidence {
    pub lane: ReleaseVerificationLane,
    pub evidence_id: String,
    pub supplied_root: String,
    pub expected_root: String,
    pub observed_height: u64,
    pub source_height: u64,
    pub confirmations: u64,
    pub quorum_bps: u64,
    pub metadata_units: u64,
    pub blocker_count: u64,
    pub status_hint: ReleaseVerificationStatus,
    pub redacted_payload_root: String,
}

impl VerificationEvidence {
    pub fn accepted(
        lane: ReleaseVerificationLane,
        config: &Config,
        confirmations: u64,
        quorum_bps: u64,
        metadata_units: u64,
    ) -> Self {
        let expected_root = expected_lane_root(lane, config);
        let evidence_id = stable_id("release_verification_evidence", lane.as_str());
        let redacted_payload_root = record_root(
            "release_verification_redacted_payload",
            &json!({
                "lane": lane.as_str(),
                "user_exit_id": config.user_exit_id,
                "expected_root": expected_root,
                "metadata_units": metadata_units,
            }),
        );
        Self {
            lane,
            evidence_id,
            supplied_root: expected_root.clone(),
            expected_root,
            observed_height: config.verification_height,
            source_height: config.release_receipt_height,
            confirmations,
            quorum_bps,
            metadata_units,
            blocker_count: 0,
            status_hint: ReleaseVerificationStatus::Accepted,
            redacted_payload_root,
        }
    }

    pub fn blocked(lane: ReleaseVerificationLane, config: &Config, blocker_count: u64) -> Self {
        let expected_root = expected_lane_root(lane, config);
        let supplied_root = record_root(
            "release_verification_blocked_supplied_root",
            &json!({
                "lane": lane.as_str(),
                "expected_root": expected_root,
                "blocker_count": blocker_count,
            }),
        );
        let evidence_id = stable_id("release_verification_blocked_evidence", lane.as_str());
        let redacted_payload_root = record_root(
            "release_verification_blocked_payload",
            &json!({
                "lane": lane.as_str(),
                "blocker_count": blocker_count,
                "release_status": "blocked",
            }),
        );
        Self {
            lane,
            evidence_id,
            supplied_root,
            expected_root,
            observed_height: config.verification_height,
            source_height: config.verification_height.saturating_sub(72),
            confirmations: 0,
            quorum_bps: 0,
            metadata_units: config.max_metadata_units.saturating_add(1),
            blocker_count,
            status_hint: ReleaseVerificationStatus::Blocked,
            redacted_payload_root,
        }
    }

    pub fn age_blocks(&self) -> u64 {
        self.observed_height.saturating_sub(self.source_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "lane_label": self.lane.label(),
            "evidence_id": self.evidence_id,
            "supplied_root": self.supplied_root,
            "expected_root": self.expected_root,
            "observed_height": self.observed_height,
            "source_height": self.source_height,
            "age_blocks": self.age_blocks(),
            "confirmations": self.confirmations,
            "quorum_bps": self.quorum_bps,
            "metadata_units": self.metadata_units,
            "blocker_count": self.blocker_count,
            "status_hint": self.status_hint.as_str(),
            "redacted_payload_root": self.redacted_payload_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_verification_evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerificationFinding {
    pub lane: ReleaseVerificationLane,
    pub finding_id: String,
    pub requirement_id: String,
    pub status: ReleaseVerificationStatus,
    pub reason: String,
    pub severity_bps: u64,
    pub blocks_user_exit: bool,
    pub evidence_root: String,
}

impl VerificationFinding {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "lane_label": self.lane.label(),
            "finding_id": self.finding_id,
            "requirement_id": self.requirement_id,
            "status": self.status.as_str(),
            "reason": self.reason,
            "severity_bps": self.severity_bps,
            "blocks_user_exit": bool_label(self.blocks_user_exit),
            "evidence_root": self.evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_verification_finding", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneSummary {
    pub lane: ReleaseVerificationLane,
    pub status: ReleaseVerificationStatus,
    pub finding_count: u64,
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
            "finding_count": self.finding_count,
            "blocker_count": self.blocker_count,
            "severity_bps": self.severity_bps,
            "lane_weight_bps": self.lane_weight_bps,
            "lane_root": self.lane_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseVerificationRoots {
    pub config_root: String,
    pub requirement_root: String,
    pub evidence_root: String,
    pub finding_root: String,
    pub lane_summary_root: String,
    pub release_verification_root: String,
    pub user_exit_answer_root: String,
    pub manifest_id: String,
}

impl ReleaseVerificationRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "requirement_root": self.requirement_root,
            "evidence_root": self.evidence_root,
            "finding_root": self.finding_root,
            "lane_summary_root": self.lane_summary_root,
            "release_verification_root": self.release_verification_root,
            "user_exit_answer_root": self.user_exit_answer_root,
            "manifest_id": self.manifest_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserExitAnswer {
    pub user_exit_id: String,
    pub verdict: UserExitVerdict,
    pub ready_lane_count: u64,
    pub held_lane_count: u64,
    pub rejected_lane_count: u64,
    pub blocker_count: u64,
    pub severity_bps: u64,
    pub release_verification_root: String,
    pub answer_root: String,
}

impl UserExitAnswer {
    pub fn public_record(&self) -> Value {
        json!({
            "user_exit_id": self.user_exit_id,
            "verdict": self.verdict.as_str(),
            "ready_lane_count": self.ready_lane_count,
            "held_lane_count": self.held_lane_count,
            "rejected_lane_count": self.rejected_lane_count,
            "blocker_count": self.blocker_count,
            "severity_bps": self.severity_bps,
            "release_verification_root": self.release_verification_root,
            "answer_root": self.answer_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub requirements: Vec<VerificationRequirement>,
    pub evidence: Vec<VerificationEvidence>,
    pub findings: Vec<VerificationFinding>,
    pub lane_summaries: Vec<LaneSummary>,
    pub roots: ReleaseVerificationRoots,
    pub user_exit_answer: UserExitAnswer,
    pub hold_map: BTreeMap<String, String>,
}

impl State {
    pub fn new(
        config: Config,
        requirements: Vec<VerificationRequirement>,
        evidence: Vec<VerificationEvidence>,
    ) -> Self {
        let findings = evaluate_findings(&config, &requirements, &evidence);
        let lane_summaries = summarize_lanes(&requirements, &evidence, &findings);
        let roots = release_verification_roots(
            &config,
            &requirements,
            &evidence,
            &findings,
            &lane_summaries,
        );
        let user_exit_answer = user_exit_answer(&config, &lane_summaries, &findings, &roots);
        let hold_map = release_hold_map(&requirements, &evidence, &findings, &user_exit_answer);
        Self {
            config,
            requirements,
            evidence,
            findings,
            lane_summaries,
            roots,
            user_exit_answer,
            hold_map,
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let requirements = default_requirements(&config);
        let evidence = default_evidence(&config);
        Self::new(config, requirements, evidence)
    }

    pub fn validate(&self) -> Result<UserExitAnswer> {
        let missing_lanes = missing_required_lanes(&self.requirements, &self.evidence);
        if !missing_lanes.is_empty() {
            return Err(format!(
                "missing release verification lanes: {}",
                missing_lanes.join(",")
            ));
        }
        if self.requirements.is_empty() {
            return Err("release verification manifest has no requirements".to_string());
        }
        let blocker_count = self
            .findings
            .iter()
            .filter(|finding| finding.blocks_user_exit)
            .count() as u64;
        if blocker_count != self.user_exit_answer.blocker_count {
            return Err(format!(
                "release verification blocker count mismatch: findings={} answer={}",
                blocker_count, self.user_exit_answer.blocker_count
            ));
        }
        Ok(self.user_exit_answer.clone())
    }

    pub fn user_exit_ready(&self) -> bool {
        self.user_exit_answer.verdict == UserExitVerdict::Ready
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "requirements": self.requirements.iter().map(VerificationRequirement::public_record).collect::<Vec<_>>(),
            "evidence": self.evidence.iter().map(VerificationEvidence::public_record).collect::<Vec<_>>(),
            "findings": self.findings.iter().map(VerificationFinding::public_record).collect::<Vec<_>>(),
            "lane_summaries": self.lane_summaries.iter().map(LaneSummary::public_record).collect::<Vec<_>>(),
            "roots": self.roots.public_record(),
            "user_exit_answer": self.user_exit_answer.public_record(),
            "hold_map": self.hold_map,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_verification_manifest_state", &self.public_record())
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

pub fn default_requirements(config: &Config) -> Vec<VerificationRequirement> {
    ReleaseVerificationLane::all()
        .into_iter()
        .map(|lane| {
            let min_confirmations = match lane {
                ReleaseVerificationLane::MoneroBroadcast | ReleaseVerificationLane::LiveFeed => {
                    config.min_confirmations
                }
                ReleaseVerificationLane::ChallengeWindow => 1,
                _ => 0,
            };
            let min_quorum_bps = match lane {
                ReleaseVerificationLane::PqCustody => config.min_pq_quorum_bps,
                ReleaseVerificationLane::LiveFeed
                | ReleaseVerificationLane::MoneroBroadcast
                | ReleaseVerificationLane::ReleaseBlocker => config.min_watcher_quorum_bps,
                _ => 0,
            };
            let max_metadata_units = match lane {
                ReleaseVerificationLane::PrivacyBoundary
                | ReleaseVerificationLane::WalletRelease => config.max_metadata_units,
                _ => config.max_metadata_units.saturating_add(4),
            };
            VerificationRequirement::new(
                lane,
                config,
                min_confirmations,
                min_quorum_bps,
                max_metadata_units,
                requirement_note(lane),
            )
        })
        .collect()
}

pub fn default_evidence(config: &Config) -> Vec<VerificationEvidence> {
    vec![
        VerificationEvidence::accepted(
            ReleaseVerificationLane::ReceiptManifest,
            config,
            0,
            10_000,
            0,
        ),
        VerificationEvidence::accepted(
            ReleaseVerificationLane::WalletRelease,
            config,
            0,
            10_000,
            1,
        ),
        VerificationEvidence::accepted(
            ReleaseVerificationLane::MoneroBroadcast,
            config,
            config.min_confirmations,
            config.min_watcher_quorum_bps,
            1,
        ),
        VerificationEvidence::accepted(
            ReleaseVerificationLane::PqCustody,
            config,
            0,
            config.min_pq_quorum_bps,
            0,
        ),
        VerificationEvidence::accepted(
            ReleaseVerificationLane::LiquiditySettlement,
            config,
            0,
            config.min_watcher_quorum_bps,
            1,
        ),
        VerificationEvidence::accepted(
            ReleaseVerificationLane::ChallengeWindow,
            config,
            1,
            config.min_watcher_quorum_bps,
            0,
        ),
        VerificationEvidence::accepted(
            ReleaseVerificationLane::LiveFeed,
            config,
            config.min_confirmations,
            config.min_watcher_quorum_bps,
            1,
        ),
        VerificationEvidence::accepted(
            ReleaseVerificationLane::PrivacyBoundary,
            config,
            0,
            10_000,
            config.max_metadata_units,
        ),
        VerificationEvidence::accepted(
            ReleaseVerificationLane::Adversarial,
            config,
            0,
            config.min_watcher_quorum_bps,
            1,
        ),
        VerificationEvidence::blocked(ReleaseVerificationLane::ReleaseBlocker, config, 1),
    ]
}

fn evaluate_findings(
    config: &Config,
    requirements: &[VerificationRequirement],
    evidence: &[VerificationEvidence],
) -> Vec<VerificationFinding> {
    let mut findings = Vec::new();
    for requirement in requirements {
        match evidence.iter().find(|item| item.lane == requirement.lane) {
            Some(item) => {
                push_root_finding(&mut findings, requirement, item);
                push_freshness_finding(&mut findings, requirement, item);
                push_confirmation_finding(&mut findings, requirement, item);
                push_quorum_finding(&mut findings, requirement, item);
                push_privacy_finding(&mut findings, requirement, item);
                push_status_finding(&mut findings, requirement, item);
                push_window_finding(&mut findings, config, requirement, item);
            }
            None => findings.push(missing_finding(requirement)),
        }
    }
    findings
}

fn push_root_finding(
    findings: &mut Vec<VerificationFinding>,
    requirement: &VerificationRequirement,
    evidence: &VerificationEvidence,
) {
    let passed = evidence.supplied_root == requirement.expected_root
        && evidence.expected_root == requirement.expected_root;
    push_finding(
        findings,
        requirement,
        evidence,
        "root_match",
        passed,
        ReleaseVerificationStatus::Blocked,
        "release verification evidence root must match the expected lane root",
        3_000,
    );
}

fn push_freshness_finding(
    findings: &mut Vec<VerificationFinding>,
    requirement: &VerificationRequirement,
    evidence: &VerificationEvidence,
) {
    let passed = evidence.age_blocks() <= requirement.freshness_limit_blocks;
    push_finding(
        findings,
        requirement,
        evidence,
        "freshness",
        passed,
        ReleaseVerificationStatus::Watch,
        "release verification evidence is older than the lane freshness limit",
        1_400,
    );
}

fn push_confirmation_finding(
    findings: &mut Vec<VerificationFinding>,
    requirement: &VerificationRequirement,
    evidence: &VerificationEvidence,
) {
    let passed = evidence.confirmations >= requirement.min_confirmations;
    push_finding(
        findings,
        requirement,
        evidence,
        "confirmation_depth",
        passed,
        ReleaseVerificationStatus::Watch,
        "release verification evidence has insufficient confirmation depth",
        1_200,
    );
}

fn push_quorum_finding(
    findings: &mut Vec<VerificationFinding>,
    requirement: &VerificationRequirement,
    evidence: &VerificationEvidence,
) {
    let passed = evidence.quorum_bps >= requirement.min_quorum_bps;
    push_finding(
        findings,
        requirement,
        evidence,
        "quorum",
        passed,
        ReleaseVerificationStatus::Blocked,
        "release verification evidence has insufficient watcher or PQ quorum",
        2_100,
    );
}

fn push_privacy_finding(
    findings: &mut Vec<VerificationFinding>,
    requirement: &VerificationRequirement,
    evidence: &VerificationEvidence,
) {
    let passed = evidence.metadata_units <= requirement.max_metadata_units;
    push_finding(
        findings,
        requirement,
        evidence,
        "privacy_budget",
        passed,
        ReleaseVerificationStatus::Quarantined,
        "release verification evidence exceeds the metadata disclosure budget",
        2_400,
    );
}

fn push_status_finding(
    findings: &mut Vec<VerificationFinding>,
    requirement: &VerificationRequirement,
    evidence: &VerificationEvidence,
) {
    let passed = !evidence.status_hint.blocks_user_exit() && evidence.blocker_count == 0;
    push_finding(
        findings,
        requirement,
        evidence,
        "status_hint",
        passed,
        evidence.status_hint,
        "release verification lane reports an exit hold or blocker",
        3_500,
    );
}

fn push_window_finding(
    findings: &mut Vec<VerificationFinding>,
    config: &Config,
    requirement: &VerificationRequirement,
    evidence: &VerificationEvidence,
) {
    let passed = match requirement.lane {
        ReleaseVerificationLane::ChallengeWindow => {
            config.verification_height >= config.challenge_window_close_height
                && config.verification_height >= config.dispute_window_close_height
        }
        ReleaseVerificationLane::MoneroBroadcast | ReleaseVerificationLane::LiveFeed => {
            config.verification_height >= config.reorg_watch_close_height
                && evidence.confirmations >= config.min_confirmations
        }
        _ => true,
    };
    push_finding(
        findings,
        requirement,
        evidence,
        "release_window",
        passed,
        ReleaseVerificationStatus::Watch,
        "release verification is inside an unresolved challenge, dispute, or reorg watch window",
        1_800,
    );
}

fn push_finding(
    findings: &mut Vec<VerificationFinding>,
    requirement: &VerificationRequirement,
    evidence: &VerificationEvidence,
    kind: &str,
    passed: bool,
    failed_status: ReleaseVerificationStatus,
    failed_reason: &str,
    severity_bps: u64,
) {
    let status = if passed {
        ReleaseVerificationStatus::Accepted
    } else {
        failed_status
    };
    let reason = if passed {
        format!("{}_accepted", kind)
    } else {
        failed_reason.to_string()
    };
    let finding_id = domain_hash(
        "monero-l2-pq-bridge-exit-release-verification-finding-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(requirement.lane.as_str()),
            HashPart::Str(kind),
            HashPart::Str(&evidence.evidence_id),
        ],
        16,
    );
    findings.push(VerificationFinding {
        lane: requirement.lane,
        finding_id,
        requirement_id: requirement.requirement_id.clone(),
        status,
        reason,
        severity_bps: if passed { 0 } else { severity_bps },
        blocks_user_exit: !passed && requirement.fail_closed,
        evidence_root: evidence.state_root(),
    });
}

fn missing_finding(requirement: &VerificationRequirement) -> VerificationFinding {
    let finding_id = domain_hash(
        "monero-l2-pq-bridge-exit-release-verification-missing-finding-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(requirement.lane.as_str()),
            HashPart::Str(&requirement.requirement_id),
        ],
        16,
    );
    VerificationFinding {
        lane: requirement.lane,
        finding_id,
        requirement_id: requirement.requirement_id.clone(),
        status: ReleaseVerificationStatus::Blocked,
        reason: "required release verification lane is missing".to_string(),
        severity_bps: 5_000,
        blocks_user_exit: true,
        evidence_root: requirement.state_root(),
    }
}

fn summarize_lanes(
    requirements: &[VerificationRequirement],
    evidence: &[VerificationEvidence],
    findings: &[VerificationFinding],
) -> Vec<LaneSummary> {
    let mut summaries = Vec::new();
    for requirement in requirements {
        let lane_findings = findings
            .iter()
            .filter(|finding| finding.lane == requirement.lane)
            .collect::<Vec<_>>();
        let blocker_count = lane_findings
            .iter()
            .filter(|finding| finding.blocks_user_exit)
            .count() as u64;
        let severity_bps = lane_findings
            .iter()
            .map(|finding| finding.severity_bps)
            .sum::<u64>()
            .min(10_000);
        let status = lane_status(blocker_count, severity_bps, &lane_findings);
        let evidence_roots = evidence
            .iter()
            .filter(|item| item.lane == requirement.lane)
            .map(VerificationEvidence::state_root)
            .collect::<Vec<_>>();
        let lane_root = record_root(
            "release_verification_lane_summary",
            &json!({
                "lane": requirement.lane.as_str(),
                "requirement_root": requirement.state_root(),
                "finding_roots": lane_findings.iter().map(|finding| finding.state_root()).collect::<Vec<_>>(),
                "evidence_roots": evidence_roots,
                "blocker_count": blocker_count,
                "severity_bps": severity_bps,
            }),
        );
        summaries.push(LaneSummary {
            lane: requirement.lane,
            status,
            finding_count: lane_findings.len() as u64,
            blocker_count,
            severity_bps,
            lane_weight_bps: requirement.lane.weight_bps(),
            lane_root,
        });
    }
    summaries
}

fn lane_status(
    blocker_count: u64,
    severity_bps: u64,
    findings: &[&VerificationFinding],
) -> ReleaseVerificationStatus {
    if blocker_count > 0 && severity_bps >= 3_500 {
        ReleaseVerificationStatus::Blocked
    } else if blocker_count > 0 {
        ReleaseVerificationStatus::Quarantined
    } else if findings
        .iter()
        .any(|finding| finding.status == ReleaseVerificationStatus::Watch)
    {
        ReleaseVerificationStatus::Watch
    } else {
        ReleaseVerificationStatus::Accepted
    }
}

fn release_verification_roots(
    config: &Config,
    requirements: &[VerificationRequirement],
    evidence: &[VerificationEvidence],
    findings: &[VerificationFinding],
    lane_summaries: &[LaneSummary],
) -> ReleaseVerificationRoots {
    let config_root = config.state_root();
    let requirement_root = merkle_root(
        "monero-l2-pq-bridge-exit-release-verification-requirements",
        &requirements
            .iter()
            .map(VerificationRequirement::public_record)
            .collect::<Vec<_>>(),
    );
    let evidence_root = merkle_root(
        "monero-l2-pq-bridge-exit-release-verification-evidence",
        &evidence
            .iter()
            .map(VerificationEvidence::public_record)
            .collect::<Vec<_>>(),
    );
    let finding_root = merkle_root(
        "monero-l2-pq-bridge-exit-release-verification-findings",
        &findings
            .iter()
            .map(VerificationFinding::public_record)
            .collect::<Vec<_>>(),
    );
    let lane_summary_root = merkle_root(
        "monero-l2-pq-bridge-exit-release-verification-lane-summaries",
        &lane_summaries
            .iter()
            .map(LaneSummary::public_record)
            .collect::<Vec<_>>(),
    );
    let release_verification_root = domain_hash(
        "monero-l2-pq-bridge-exit-release-verification-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config_root),
            HashPart::Str(&requirement_root),
            HashPart::Str(&evidence_root),
            HashPart::Str(&finding_root),
            HashPart::Str(&lane_summary_root),
        ],
        32,
    );
    let user_exit_answer_root = domain_hash(
        "monero-l2-pq-bridge-exit-release-verification-user-exit-answer-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.user_exit_id),
            HashPart::Str(&release_verification_root),
            HashPart::U64(config.verification_height),
        ],
        32,
    );
    let manifest_id = domain_hash(
        "monero-l2-pq-bridge-exit-release-verification-manifest-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.vertical_slice_id),
            HashPart::Str(&config.user_exit_id),
            HashPart::Str(&user_exit_answer_root),
        ],
        16,
    );
    ReleaseVerificationRoots {
        config_root,
        requirement_root,
        evidence_root,
        finding_root,
        lane_summary_root,
        release_verification_root,
        user_exit_answer_root,
        manifest_id,
    }
}

fn user_exit_answer(
    config: &Config,
    lane_summaries: &[LaneSummary],
    findings: &[VerificationFinding],
    roots: &ReleaseVerificationRoots,
) -> UserExitAnswer {
    let ready_lane_count = lane_summaries
        .iter()
        .filter(|summary| summary.status == ReleaseVerificationStatus::Accepted)
        .count() as u64;
    let rejected_lane_count = lane_summaries
        .iter()
        .filter(|summary| summary.status == ReleaseVerificationStatus::Blocked)
        .count() as u64;
    let held_lane_count = lane_summaries
        .iter()
        .filter(|summary| {
            summary.status == ReleaseVerificationStatus::Watch
                || summary.status == ReleaseVerificationStatus::Quarantined
        })
        .count() as u64;
    let blocker_count = findings
        .iter()
        .filter(|finding| finding.blocks_user_exit)
        .count() as u64;
    let severity_bps = findings
        .iter()
        .map(|finding| finding.severity_bps)
        .sum::<u64>()
        .min(10_000);
    let verdict = if rejected_lane_count > 0 || blocker_count > 0 {
        UserExitVerdict::Rejected
    } else if held_lane_count > 0 {
        UserExitVerdict::Held
    } else {
        UserExitVerdict::Ready
    };
    let answer_root = record_root(
        "release_verification_user_exit_answer",
        &json!({
            "user_exit_id": config.user_exit_id,
            "verdict": verdict.as_str(),
            "ready_lane_count": ready_lane_count,
            "held_lane_count": held_lane_count,
            "rejected_lane_count": rejected_lane_count,
            "blocker_count": blocker_count,
            "severity_bps": severity_bps,
            "release_verification_root": roots.release_verification_root,
        }),
    );
    UserExitAnswer {
        user_exit_id: config.user_exit_id.clone(),
        verdict,
        ready_lane_count,
        held_lane_count,
        rejected_lane_count,
        blocker_count,
        severity_bps,
        release_verification_root: roots.release_verification_root.clone(),
        answer_root,
    }
}

fn release_hold_map(
    requirements: &[VerificationRequirement],
    evidence: &[VerificationEvidence],
    findings: &[VerificationFinding],
    answer: &UserExitAnswer,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert(
        "cargo_runtime_execution".to_string(),
        "release verification remains a deterministic manifest until cargo/runtime execution is allowed".to_string(),
    );
    map.insert(
        "user_exit_answer".to_string(),
        format!(
            "user exit verdict is {} with {} release blockers",
            answer.verdict.as_str(),
            answer.blocker_count
        ),
    );
    for requirement in requirements {
        if !evidence.iter().any(|item| item.lane == requirement.lane) {
            map.insert(
                format!("missing_{}", requirement.lane.as_str()),
                "required release verification evidence is missing".to_string(),
            );
        }
    }
    for finding in findings.iter().filter(|finding| finding.blocks_user_exit) {
        map.insert(
            format!("blocker_{}_{}", finding.lane.as_str(), finding.finding_id),
            finding.reason.clone(),
        );
    }
    map
}

fn missing_required_lanes(
    requirements: &[VerificationRequirement],
    evidence: &[VerificationEvidence],
) -> Vec<String> {
    requirements
        .iter()
        .filter(|requirement| requirement.required)
        .filter(|requirement| !evidence.iter().any(|item| item.lane == requirement.lane))
        .map(|requirement| requirement.lane.as_str().to_string())
        .collect()
}

fn requirement_note(lane: ReleaseVerificationLane) -> &'static str {
    match lane {
        ReleaseVerificationLane::ReceiptManifest => {
            "receipt manifest must bind all release receipt lanes into one user-exit claim"
        }
        ReleaseVerificationLane::WalletRelease => {
            "wallet release verification must bind local recovery, nullifier, claim, and redacted receipt roots"
        }
        ReleaseVerificationLane::MoneroBroadcast => {
            "Monero broadcast verification must prove observed release transaction finality without leaking wallet metadata"
        }
        ReleaseVerificationLane::PqCustody => {
            "PQ custody verification must bind signer quorum, key epoch, transcript domain, and withdrawal authority"
        }
        ReleaseVerificationLane::LiquiditySettlement => {
            "liquidity settlement verification must prove reserve coverage, fee caps, queue ordering, and shortfall handling"
        }
        ReleaseVerificationLane::ChallengeWindow => {
            "challenge and dispute windows must close before an irreversible user release answer is accepted"
        }
        ReleaseVerificationLane::LiveFeed => {
            "live feed verification must bind Monero header, reorg, reserve, and watcher observations"
        }
        ReleaseVerificationLane::PrivacyBoundary => {
            "privacy verification must keep release receipt payloads inside wallet metadata disclosure budgets"
        }
        ReleaseVerificationLane::Adversarial => {
            "adversarial verification must reject replayed, forged, stale, colluding, or privacy-breaking evidence"
        }
        ReleaseVerificationLane::ReleaseBlocker => {
            "release blocker verification must fail closed while any critical lane remains unresolved"
        }
    }
}

fn expected_lane_root(lane: ReleaseVerificationLane, config: &Config) -> String {
    record_root(
        "release_verification_expected_lane_root",
        &json!({
            "chain_id": config.chain_id,
            "vertical_slice_id": config.vertical_slice_id,
            "user_exit_id": config.user_exit_id,
            "lane": lane.as_str(),
            "release_receipt_height": config.release_receipt_height,
            "verification_height": config.verification_height,
            "suite": RELEASE_VERIFICATION_SUITE,
        }),
    )
}

fn stable_id(kind: &str, label: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-release-verification-stable-id",
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
        "monero-l2-pq-bridge-exit-release-verification-record-root",
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
