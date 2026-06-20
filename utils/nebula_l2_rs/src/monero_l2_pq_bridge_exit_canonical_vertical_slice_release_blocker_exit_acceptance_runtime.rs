use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceReleaseBlockerExitAcceptanceRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_EXIT_ACCEPTANCE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-release-blocker-exit-acceptance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_EXIT_ACCEPTANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const EXIT_ACCEPTANCE_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-release-blocker-exit-acceptance-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_EXIT_CANDIDATE_ID: &str =
    "monero-l2-pq-bridge-exit-acceptance-candidate-devnet-v1";
pub const REQUIRED_LANE_COUNT: usize = 9;
pub const DEFAULT_MIN_RECEIPT_CONFIRMATIONS: u64 = 12;
pub const DEFAULT_MIN_LIVE_FEED_QUORUM: u16 = 4;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_PRIVACY_LEAKAGE_UNITS: u16 = 2;
pub const DEFAULT_MIN_LIQUIDITY_COVERAGE_BPS: u16 = 10_000;
pub const DEFAULT_DISPUTE_WINDOW_CLOSE_HEIGHT: u64 = 9_910;
pub const DEFAULT_CHALLENGE_WINDOW_CLOSE_HEIGHT: u64 = 9_940;
pub const DEFAULT_OBSERVED_HEIGHT: u64 = 9_900;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceLane {
    WalletRecovery,
    ForcedRelease,
    PqAuthority,
    PrivacyBounds,
    ObservedReceipts,
    LiveFeeds,
    Liquidity,
    DisputeWindow,
    ChallengeWindow,
}

impl AcceptanceLane {
    pub fn all() -> [Self; REQUIRED_LANE_COUNT] {
        [
            Self::WalletRecovery,
            Self::ForcedRelease,
            Self::PqAuthority,
            Self::PrivacyBounds,
            Self::ObservedReceipts,
            Self::LiveFeeds,
            Self::Liquidity,
            Self::DisputeWindow,
            Self::ChallengeWindow,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRecovery => "wallet_recovery",
            Self::ForcedRelease => "forced_release",
            Self::PqAuthority => "pq_authority",
            Self::PrivacyBounds => "privacy_bounds",
            Self::ObservedReceipts => "observed_receipts",
            Self::LiveFeeds => "live_feeds",
            Self::Liquidity => "liquidity",
            Self::DisputeWindow => "dispute_window",
            Self::ChallengeWindow => "challenge_window",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceStatus {
    Clear,
    EvidenceMissing,
    EvidenceMismatched,
    Stale,
    ThresholdShortfall,
    WindowOpen,
    HoldOpen,
}

impl AcceptanceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Clear => "clear",
            Self::EvidenceMissing => "evidence_missing",
            Self::EvidenceMismatched => "evidence_mismatched",
            Self::Stale => "stale",
            Self::ThresholdShortfall => "threshold_shortfall",
            Self::WindowOpen => "window_open",
            Self::HoldOpen => "hold_open",
        }
    }

    pub fn blocks_acceptance(self) -> bool {
        self != Self::Clear
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerSeverity {
    Informational,
    Watch,
    Major,
    Critical,
    ReleaseStop,
}

impl BlockerSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Watch => "watch",
            Self::Major => "major",
            Self::Critical => "critical",
            Self::ReleaseStop => "release_stop",
        }
    }

    pub fn score(self) -> u64 {
        match self {
            Self::Informational => 1,
            Self::Watch => 2,
            Self::Major => 3,
            Self::Critical => 4,
            Self::ReleaseStop => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    RecoveryBinding,
    ForcedReleaseInstruction,
    PqAuthorization,
    PrivacyReview,
    ReceiptObservation,
    LiveFeedObservation,
    LiquiditySnapshot,
    DisputeClock,
    ChallengeClock,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecoveryBinding => "recovery_binding",
            Self::ForcedReleaseInstruction => "forced_release_instruction",
            Self::PqAuthorization => "pq_authorization",
            Self::PrivacyReview => "privacy_review",
            Self::ReceiptObservation => "receipt_observation",
            Self::LiveFeedObservation => "live_feed_observation",
            Self::LiquiditySnapshot => "liquidity_snapshot",
            Self::DisputeClock => "dispute_clock",
            Self::ChallengeClock => "challenge_clock",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceDecision {
    Accepted,
    Blocked,
}

impl AcceptanceDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
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
    pub acceptance_suite: String,
    pub vertical_slice_id: String,
    pub exit_candidate_id: String,
    pub required_lane_count: usize,
    pub min_receipt_confirmations: u64,
    pub min_live_feed_quorum: u16,
    pub min_pq_security_bits: u16,
    pub max_privacy_leakage_units: u16,
    pub min_liquidity_coverage_bps: u16,
    pub dispute_window_close_height: u64,
    pub challenge_window_close_height: u64,
    pub observed_height: u64,
    pub requires_public_record: bool,
    pub production_acceptance_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            acceptance_suite: EXIT_ACCEPTANCE_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            exit_candidate_id: DEFAULT_EXIT_CANDIDATE_ID.to_string(),
            required_lane_count: REQUIRED_LANE_COUNT,
            min_receipt_confirmations: DEFAULT_MIN_RECEIPT_CONFIRMATIONS,
            min_live_feed_quorum: DEFAULT_MIN_LIVE_FEED_QUORUM,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_privacy_leakage_units: DEFAULT_MAX_PRIVACY_LEAKAGE_UNITS,
            min_liquidity_coverage_bps: DEFAULT_MIN_LIQUIDITY_COVERAGE_BPS,
            dispute_window_close_height: DEFAULT_DISPUTE_WINDOW_CLOSE_HEIGHT,
            challenge_window_close_height: DEFAULT_CHALLENGE_WINDOW_CLOSE_HEIGHT,
            observed_height: DEFAULT_OBSERVED_HEIGHT,
            requires_public_record: true,
            production_acceptance_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "acceptance_suite": self.acceptance_suite,
            "vertical_slice_id": self.vertical_slice_id,
            "exit_candidate_id": self.exit_candidate_id,
            "required_lane_count": self.required_lane_count,
            "min_receipt_confirmations": self.min_receipt_confirmations,
            "min_live_feed_quorum": self.min_live_feed_quorum,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_privacy_leakage_units": self.max_privacy_leakage_units,
            "min_liquidity_coverage_bps": self.min_liquidity_coverage_bps,
            "dispute_window_close_height": self.dispute_window_close_height,
            "challenge_window_close_height": self.challenge_window_close_height,
            "observed_height": self.observed_height,
            "requires_public_record": self.requires_public_record,
            "production_acceptance_allowed": self.production_acceptance_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AcceptanceEvidence {
    pub lane: AcceptanceLane,
    pub kind: EvidenceKind,
    pub expected_root: String,
    pub observed_root: String,
    pub observed_height: u64,
    pub confirmations: u64,
    pub quorum: u16,
    pub security_bits: u16,
    pub leakage_units: u16,
    pub liquidity_coverage_bps: u16,
    pub window_close_height: u64,
    pub note: String,
}

impl AcceptanceEvidence {
    pub fn devnet(lane: AcceptanceLane, sequence: u64, config: &Config) -> Self {
        let kind = evidence_kind(lane);
        let expected_root = evidence_root("expected", lane, kind, sequence, config);
        let observed_root = observed_evidence_root(lane, kind, sequence, config);
        let (confirmations, quorum, security_bits, leakage_units, liquidity_coverage_bps) =
            lane_measurements(lane, config);
        let window_close_height = lane_window_close_height(lane, config);
        Self {
            lane,
            kind,
            expected_root,
            observed_root,
            observed_height: config.observed_height,
            confirmations,
            quorum,
            security_bits,
            leakage_units,
            liquidity_coverage_bps,
            window_close_height,
            note: lane_evidence_note(lane).to_string(),
        }
    }

    pub fn roots_match(&self) -> bool {
        self.expected_root == self.observed_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "kind": self.kind.as_str(),
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "observed_height": self.observed_height,
            "confirmations": self.confirmations,
            "quorum": self.quorum,
            "security_bits": self.security_bits,
            "leakage_units": self.leakage_units,
            "liquidity_coverage_bps": self.liquidity_coverage_bps,
            "window_close_height": self.window_close_height,
            "roots_match": self.roots_match(),
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ACCEPTANCE-EVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AcceptanceBlocker {
    pub lane: AcceptanceLane,
    pub status: AcceptanceStatus,
    pub severity: BlockerSeverity,
    pub reason_code: String,
    pub reason: String,
    pub clearance_requirement: String,
    pub evidence_root: String,
    pub blocks_acceptance: bool,
}

impl AcceptanceBlocker {
    pub fn from_evidence(evidence: &AcceptanceEvidence, config: &Config) -> Self {
        let status = lane_status(evidence, config);
        let severity = lane_severity(evidence.lane, status);
        Self {
            lane: evidence.lane,
            status,
            severity,
            reason_code: reason_code(evidence.lane, status).to_string(),
            reason: blocker_reason(evidence, status, config),
            clearance_requirement: clearance_requirement(evidence.lane, status).to_string(),
            evidence_root: evidence.state_root(),
            blocks_acceptance: status.blocks_acceptance(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "severity_score": self.severity.score(),
            "reason_code": self.reason_code,
            "reason": self.reason,
            "clearance_requirement": self.clearance_requirement,
            "evidence_root": self.evidence_root,
            "blocks_acceptance": self.blocks_acceptance,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ACCEPTANCE-BLOCKER", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LaneSummary {
    pub lane: AcceptanceLane,
    pub status: AcceptanceStatus,
    pub severity: BlockerSeverity,
    pub evidence_root: String,
    pub blocker_root: String,
    pub metric_root: String,
    pub release_acceptance_blocked: bool,
}

impl LaneSummary {
    pub fn new(evidence: &AcceptanceEvidence, blocker: &AcceptanceBlocker) -> Self {
        Self {
            lane: evidence.lane,
            status: blocker.status,
            severity: blocker.severity,
            evidence_root: evidence.state_root(),
            blocker_root: blocker.state_root(),
            metric_root: lane_metric_root(evidence),
            release_acceptance_blocked: blocker.blocks_acceptance,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "evidence_root": self.evidence_root,
            "blocker_root": self.blocker_root,
            "metric_root": self.metric_root,
            "release_acceptance_blocked": self.release_acceptance_blocked,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("LANE-SUMMARY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AcceptanceSummary {
    pub decision: AcceptanceDecision,
    pub total_lanes: u64,
    pub blocked_lanes: u64,
    pub clear_lanes: u64,
    pub release_stop_lanes: u64,
    pub max_severity_score: u64,
    pub reason_root: String,
    pub evidence_root: String,
    pub blocker_root: String,
    pub lane_summary_root: String,
    pub severity_counts: BTreeMap<String, u64>,
    pub lane_roots: BTreeMap<String, String>,
    pub decision_reason: String,
}

impl AcceptanceSummary {
    pub fn from_lanes(
        evidence: &[AcceptanceEvidence],
        blockers: &[AcceptanceBlocker],
        lanes: &[LaneSummary],
        config: &Config,
    ) -> Self {
        let blocked_lanes = blockers
            .iter()
            .filter(|blocker| blocker.blocks_acceptance)
            .count() as u64;
        let release_stop_lanes = blockers
            .iter()
            .filter(|blocker| blocker.severity == BlockerSeverity::ReleaseStop)
            .count() as u64;
        let max_severity_score = blockers
            .iter()
            .map(|blocker| blocker.severity.score())
            .max()
            .unwrap_or(0);
        let decision = if blocked_lanes == 0 && config.production_acceptance_allowed {
            AcceptanceDecision::Accepted
        } else {
            AcceptanceDecision::Blocked
        };
        let evidence_root = list_root(
            "ACCEPTANCE-EVIDENCE-LIST",
            evidence.iter().map(AcceptanceEvidence::state_root),
        );
        let blocker_root = list_root(
            "ACCEPTANCE-BLOCKER-LIST",
            blockers.iter().map(AcceptanceBlocker::state_root),
        );
        let lane_summary_root = list_root(
            "LANE-SUMMARY-LIST",
            lanes.iter().map(LaneSummary::state_root),
        );
        let reason_root = list_root(
            "BLOCKER-REASON-LIST",
            blockers.iter().map(|blocker| {
                short_hash(
                    "BLOCKER-REASON",
                    &[
                        HashPart::Str(blocker.lane.as_str()),
                        HashPart::Str(blocker.status.as_str()),
                        HashPart::Str(&blocker.reason_code),
                        HashPart::Str(&blocker.clearance_requirement),
                    ],
                )
            }),
        );
        Self {
            decision,
            total_lanes: lanes.len() as u64,
            blocked_lanes,
            clear_lanes: lanes.len() as u64 - blocked_lanes,
            release_stop_lanes,
            max_severity_score,
            reason_root,
            evidence_root,
            blocker_root,
            lane_summary_root,
            severity_counts: severity_counts(blockers),
            lane_roots: lane_roots(lanes),
            decision_reason: decision_reason(decision, blocked_lanes, release_stop_lanes, config),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "decision": self.decision.as_str(),
            "total_lanes": self.total_lanes,
            "blocked_lanes": self.blocked_lanes,
            "clear_lanes": self.clear_lanes,
            "release_stop_lanes": self.release_stop_lanes,
            "max_severity_score": self.max_severity_score,
            "reason_root": self.reason_root,
            "evidence_root": self.evidence_root,
            "blocker_root": self.blocker_root,
            "lane_summary_root": self.lane_summary_root,
            "severity_counts": self.severity_counts,
            "lane_roots": self.lane_roots,
            "decision_reason": self.decision_reason,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ACCEPTANCE-SUMMARY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub evidence: Vec<AcceptanceEvidence>,
    pub blockers: Vec<AcceptanceBlocker>,
    pub lane_summaries: Vec<LaneSummary>,
    pub summary: AcceptanceSummary,
    pub audit_roots: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let evidence = AcceptanceLane::all()
            .iter()
            .enumerate()
            .map(|(index, lane)| AcceptanceEvidence::devnet(*lane, index as u64 + 1, &config))
            .collect::<Vec<_>>();
        let blockers = evidence
            .iter()
            .map(|item| AcceptanceBlocker::from_evidence(item, &config))
            .collect::<Vec<_>>();
        let lane_summaries = evidence
            .iter()
            .zip(blockers.iter())
            .map(|(item, blocker)| LaneSummary::new(item, blocker))
            .collect::<Vec<_>>();
        let summary = AcceptanceSummary::from_lanes(&evidence, &blockers, &lane_summaries, &config);
        let audit_roots = audit_roots(&config, &evidence, &blockers, &lane_summaries, &summary);
        Self {
            config,
            evidence,
            blockers,
            lane_summaries,
            summary,
            audit_roots,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.config.required_lane_count != REQUIRED_LANE_COUNT {
            return Err("required lane count drifted from runtime constant".to_string());
        }
        if self.evidence.len() != self.config.required_lane_count {
            return Err("evidence lane count does not match config".to_string());
        }
        if self.blockers.len() != self.evidence.len() {
            return Err("blocker lane count does not match evidence".to_string());
        }
        if self.lane_summaries.len() != self.evidence.len() {
            return Err("lane summary count does not match evidence".to_string());
        }
        for lane in AcceptanceLane::all() {
            if !self.evidence.iter().any(|item| item.lane == lane) {
                return Err(format!("missing evidence for lane {}", lane.as_str()));
            }
            if !self.blockers.iter().any(|item| item.lane == lane) {
                return Err(format!("missing blocker for lane {}", lane.as_str()));
            }
            if !self.lane_summaries.iter().any(|item| item.lane == lane) {
                return Err(format!("missing lane summary for lane {}", lane.as_str()));
            }
        }
        Ok(())
    }

    pub fn decision(&self) -> AcceptanceDecision {
        self.summary.decision
    }

    pub fn blocked_reasons(&self) -> Vec<String> {
        self.blockers
            .iter()
            .filter(|blocker| blocker.blocks_acceptance)
            .map(|blocker| blocker.reason.clone())
            .collect()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "evidence": self.evidence.iter().map(AcceptanceEvidence::public_record).collect::<Vec<_>>(),
            "blockers": self.blockers.iter().map(AcceptanceBlocker::public_record).collect::<Vec<_>>(),
            "lane_summaries": self.lane_summaries.iter().map(LaneSummary::public_record).collect::<Vec<_>>(),
            "summary": self.summary.public_record(),
            "audit_roots": self.audit_roots,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        acceptance_state_root(
            &self.config.state_root(),
            &self.summary.evidence_root,
            &self.summary.blocker_root,
            &self.summary.lane_summary_root,
            &self.summary.state_root(),
            &record_root("AUDIT-ROOTS", &json!(self.audit_roots)),
        )
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

pub fn evaluate_exit_acceptance(
    evidence: Vec<AcceptanceEvidence>,
    config: Config,
) -> MoneroL2PqBridgeExitCanonicalVerticalSliceReleaseBlockerExitAcceptanceRuntimeResult<State> {
    if evidence.len() != config.required_lane_count {
        return Err(
            "exit acceptance evidence count does not match required lane count".to_string(),
        );
    }
    let blockers = evidence
        .iter()
        .map(|item| AcceptanceBlocker::from_evidence(item, &config))
        .collect::<Vec<_>>();
    let lane_summaries = evidence
        .iter()
        .zip(blockers.iter())
        .map(|(item, blocker)| LaneSummary::new(item, blocker))
        .collect::<Vec<_>>();
    let summary = AcceptanceSummary::from_lanes(&evidence, &blockers, &lane_summaries, &config);
    let audit_roots = audit_roots(&config, &evidence, &blockers, &lane_summaries, &summary);
    let state = State {
        config,
        evidence,
        blockers,
        lane_summaries,
        summary,
        audit_roots,
    };
    state.validate()?;
    Ok(state)
}

fn evidence_kind(lane: AcceptanceLane) -> EvidenceKind {
    match lane {
        AcceptanceLane::WalletRecovery => EvidenceKind::RecoveryBinding,
        AcceptanceLane::ForcedRelease => EvidenceKind::ForcedReleaseInstruction,
        AcceptanceLane::PqAuthority => EvidenceKind::PqAuthorization,
        AcceptanceLane::PrivacyBounds => EvidenceKind::PrivacyReview,
        AcceptanceLane::ObservedReceipts => EvidenceKind::ReceiptObservation,
        AcceptanceLane::LiveFeeds => EvidenceKind::LiveFeedObservation,
        AcceptanceLane::Liquidity => EvidenceKind::LiquiditySnapshot,
        AcceptanceLane::DisputeWindow => EvidenceKind::DisputeClock,
        AcceptanceLane::ChallengeWindow => EvidenceKind::ChallengeClock,
    }
}

fn lane_measurements(lane: AcceptanceLane, config: &Config) -> (u64, u16, u16, u16, u16) {
    match lane {
        AcceptanceLane::WalletRecovery => (
            config.min_receipt_confirmations,
            config.min_live_feed_quorum,
            config.min_pq_security_bits,
            1,
            config.min_liquidity_coverage_bps,
        ),
        AcceptanceLane::ForcedRelease => (
            config.min_receipt_confirmations - 2,
            config.min_live_feed_quorum,
            config.min_pq_security_bits,
            1,
            config.min_liquidity_coverage_bps,
        ),
        AcceptanceLane::PqAuthority => (
            config.min_receipt_confirmations,
            config.min_live_feed_quorum,
            config.min_pq_security_bits - 64,
            1,
            config.min_liquidity_coverage_bps,
        ),
        AcceptanceLane::PrivacyBounds => (
            config.min_receipt_confirmations,
            config.min_live_feed_quorum,
            config.min_pq_security_bits,
            config.max_privacy_leakage_units + 1,
            config.min_liquidity_coverage_bps,
        ),
        AcceptanceLane::ObservedReceipts => (
            config.min_receipt_confirmations - 1,
            config.min_live_feed_quorum,
            config.min_pq_security_bits,
            1,
            config.min_liquidity_coverage_bps,
        ),
        AcceptanceLane::LiveFeeds => (
            config.min_receipt_confirmations,
            config.min_live_feed_quorum - 1,
            config.min_pq_security_bits,
            1,
            config.min_liquidity_coverage_bps,
        ),
        AcceptanceLane::Liquidity => (
            config.min_receipt_confirmations,
            config.min_live_feed_quorum,
            config.min_pq_security_bits,
            1,
            config.min_liquidity_coverage_bps - 750,
        ),
        AcceptanceLane::DisputeWindow => (
            config.min_receipt_confirmations,
            config.min_live_feed_quorum,
            config.min_pq_security_bits,
            1,
            config.min_liquidity_coverage_bps,
        ),
        AcceptanceLane::ChallengeWindow => (
            config.min_receipt_confirmations,
            config.min_live_feed_quorum,
            config.min_pq_security_bits,
            1,
            config.min_liquidity_coverage_bps,
        ),
    }
}

fn lane_window_close_height(lane: AcceptanceLane, config: &Config) -> u64 {
    match lane {
        AcceptanceLane::DisputeWindow => config.dispute_window_close_height,
        AcceptanceLane::ChallengeWindow => config.challenge_window_close_height,
        _ => config.observed_height,
    }
}

fn lane_status(evidence: &AcceptanceEvidence, config: &Config) -> AcceptanceStatus {
    if !evidence.roots_match() {
        return AcceptanceStatus::EvidenceMismatched;
    }
    match evidence.lane {
        AcceptanceLane::WalletRecovery => AcceptanceStatus::Clear,
        AcceptanceLane::ForcedRelease => {
            if evidence.confirmations < config.min_receipt_confirmations {
                AcceptanceStatus::EvidenceMissing
            } else {
                AcceptanceStatus::Clear
            }
        }
        AcceptanceLane::PqAuthority => {
            if evidence.security_bits < config.min_pq_security_bits {
                AcceptanceStatus::ThresholdShortfall
            } else {
                AcceptanceStatus::Clear
            }
        }
        AcceptanceLane::PrivacyBounds => {
            if evidence.leakage_units > config.max_privacy_leakage_units {
                AcceptanceStatus::HoldOpen
            } else {
                AcceptanceStatus::Clear
            }
        }
        AcceptanceLane::ObservedReceipts => {
            if evidence.confirmations < config.min_receipt_confirmations {
                AcceptanceStatus::Stale
            } else {
                AcceptanceStatus::Clear
            }
        }
        AcceptanceLane::LiveFeeds => {
            if evidence.quorum < config.min_live_feed_quorum {
                AcceptanceStatus::ThresholdShortfall
            } else {
                AcceptanceStatus::Clear
            }
        }
        AcceptanceLane::Liquidity => {
            if evidence.liquidity_coverage_bps < config.min_liquidity_coverage_bps {
                AcceptanceStatus::ThresholdShortfall
            } else {
                AcceptanceStatus::Clear
            }
        }
        AcceptanceLane::DisputeWindow | AcceptanceLane::ChallengeWindow => {
            if evidence.observed_height < evidence.window_close_height {
                AcceptanceStatus::WindowOpen
            } else {
                AcceptanceStatus::Clear
            }
        }
    }
}

fn lane_severity(lane: AcceptanceLane, status: AcceptanceStatus) -> BlockerSeverity {
    if status == AcceptanceStatus::Clear {
        return BlockerSeverity::Informational;
    }
    match lane {
        AcceptanceLane::WalletRecovery => BlockerSeverity::ReleaseStop,
        AcceptanceLane::ForcedRelease => BlockerSeverity::ReleaseStop,
        AcceptanceLane::PqAuthority => BlockerSeverity::ReleaseStop,
        AcceptanceLane::PrivacyBounds => BlockerSeverity::Critical,
        AcceptanceLane::ObservedReceipts => BlockerSeverity::Critical,
        AcceptanceLane::LiveFeeds => BlockerSeverity::Major,
        AcceptanceLane::Liquidity => BlockerSeverity::Critical,
        AcceptanceLane::DisputeWindow => BlockerSeverity::Major,
        AcceptanceLane::ChallengeWindow => BlockerSeverity::Major,
    }
}

fn reason_code(lane: AcceptanceLane, status: AcceptanceStatus) -> &'static str {
    match (lane, status) {
        (_, AcceptanceStatus::Clear) => "exit_acceptance_lane_clear",
        (AcceptanceLane::WalletRecovery, _) => "wallet_recovery_binding_not_canonical",
        (AcceptanceLane::ForcedRelease, AcceptanceStatus::EvidenceMissing) => {
            "forced_release_receipt_not_final"
        }
        (AcceptanceLane::ForcedRelease, _) => "forced_release_instruction_not_accepted",
        (AcceptanceLane::PqAuthority, _) => "pq_authority_below_required_security",
        (AcceptanceLane::PrivacyBounds, _) => "privacy_bounds_not_closed",
        (AcceptanceLane::ObservedReceipts, AcceptanceStatus::Stale) => "observed_receipt_stale",
        (AcceptanceLane::ObservedReceipts, _) => "observed_receipt_not_canonical",
        (AcceptanceLane::LiveFeeds, _) => "live_feed_quorum_shortfall",
        (AcceptanceLane::Liquidity, _) => "liquidity_coverage_shortfall",
        (AcceptanceLane::DisputeWindow, _) => "dispute_window_still_open",
        (AcceptanceLane::ChallengeWindow, _) => "challenge_window_still_open",
    }
}

fn blocker_reason(
    evidence: &AcceptanceEvidence,
    status: AcceptanceStatus,
    config: &Config,
) -> String {
    match (evidence.lane, status) {
        (_, AcceptanceStatus::Clear) => {
            format!(
                "{} lane is clear for exit acceptance",
                evidence.lane.as_str()
            )
        }
        (AcceptanceLane::ForcedRelease, AcceptanceStatus::EvidenceMissing) => format!(
            "forced release has {} confirmations, below required {}",
            evidence.confirmations, config.min_receipt_confirmations
        ),
        (AcceptanceLane::PqAuthority, AcceptanceStatus::ThresholdShortfall) => format!(
            "pq authority has {} security bits, below required {}",
            evidence.security_bits, config.min_pq_security_bits
        ),
        (AcceptanceLane::PrivacyBounds, AcceptanceStatus::HoldOpen) => format!(
            "privacy leakage units {} exceed maximum {}",
            evidence.leakage_units, config.max_privacy_leakage_units
        ),
        (AcceptanceLane::ObservedReceipts, AcceptanceStatus::Stale) => format!(
            "observed receipt has {} confirmations, below required {}",
            evidence.confirmations, config.min_receipt_confirmations
        ),
        (AcceptanceLane::LiveFeeds, AcceptanceStatus::ThresholdShortfall) => format!(
            "live feed quorum {} is below required {}",
            evidence.quorum, config.min_live_feed_quorum
        ),
        (AcceptanceLane::Liquidity, AcceptanceStatus::ThresholdShortfall) => format!(
            "liquidity coverage {} bps is below required {} bps",
            evidence.liquidity_coverage_bps, config.min_liquidity_coverage_bps
        ),
        (AcceptanceLane::DisputeWindow, AcceptanceStatus::WindowOpen) => format!(
            "dispute window closes at height {}, current observed height is {}",
            evidence.window_close_height, evidence.observed_height
        ),
        (AcceptanceLane::ChallengeWindow, AcceptanceStatus::WindowOpen) => format!(
            "challenge window closes at height {}, current observed height is {}",
            evidence.window_close_height, evidence.observed_height
        ),
        (_, AcceptanceStatus::EvidenceMismatched) => format!(
            "{} expected root does not match observed root",
            evidence.lane.as_str()
        ),
        (_, AcceptanceStatus::EvidenceMissing) => {
            format!("{} evidence is missing", evidence.lane.as_str())
        }
        (_, AcceptanceStatus::Stale) => format!("{} evidence is stale", evidence.lane.as_str()),
        (_, AcceptanceStatus::ThresholdShortfall) => {
            format!("{} threshold is below requirement", evidence.lane.as_str())
        }
        (_, AcceptanceStatus::WindowOpen) => {
            format!("{} settlement window remains open", evidence.lane.as_str())
        }
        (_, AcceptanceStatus::HoldOpen) => {
            format!("{} hold remains open", evidence.lane.as_str())
        }
    }
}

fn clearance_requirement(lane: AcceptanceLane, status: AcceptanceStatus) -> &'static str {
    match (lane, status) {
        (_, AcceptanceStatus::Clear) => "retain accepted evidence root in canonical exit record",
        (AcceptanceLane::WalletRecovery, _) => {
            "bind recovered wallet note, nullifier, and view-key transcript to exit candidate"
        }
        (AcceptanceLane::ForcedRelease, _) => {
            "publish forced release instruction with final receipt confirmations"
        }
        (AcceptanceLane::PqAuthority, _) => {
            "refresh post-quantum withdrawal authority quorum at required security level"
        }
        (AcceptanceLane::PrivacyBounds, _) => {
            "complete privacy review with leakage units inside configured bound"
        }
        (AcceptanceLane::ObservedReceipts, _) => {
            "ingest canonical observed receipt with required confirmations and matching root"
        }
        (AcceptanceLane::LiveFeeds, _) => {
            "restore live feed quorum for headers, receipts, reserves, and release blockers"
        }
        (AcceptanceLane::Liquidity, _) => {
            "prove liquidity coverage at or above required basis-point threshold"
        }
        (AcceptanceLane::DisputeWindow, _) => {
            "wait until dispute window close height is observed and recorded"
        }
        (AcceptanceLane::ChallengeWindow, _) => {
            "wait until challenge window close height is observed and recorded"
        }
    }
}

fn lane_evidence_note(lane: AcceptanceLane) -> &'static str {
    match lane {
        AcceptanceLane::WalletRecovery => "wallet recovery transcript is bound to candidate",
        AcceptanceLane::ForcedRelease => "forced release instruction awaits finality",
        AcceptanceLane::PqAuthority => "post-quantum authority rotation is measured",
        AcceptanceLane::PrivacyBounds => "privacy leakage bound is evaluated",
        AcceptanceLane::ObservedReceipts => "observed receipt finality is counted",
        AcceptanceLane::LiveFeeds => "live feed quorum is sampled",
        AcceptanceLane::Liquidity => "liquidity coverage snapshot is sampled",
        AcceptanceLane::DisputeWindow => "dispute close height is compared to observation",
        AcceptanceLane::ChallengeWindow => "challenge close height is compared to observation",
    }
}

fn decision_reason(
    decision: AcceptanceDecision,
    blocked_lanes: u64,
    release_stop_lanes: u64,
    config: &Config,
) -> String {
    if !config.production_acceptance_allowed {
        return format!(
            "exit acceptance blocked: production acceptance flag disabled with {} blocked lanes",
            blocked_lanes
        );
    }
    match decision {
        AcceptanceDecision::Accepted => {
            "exit acceptance accepted: all release-blocker lanes are clear".to_string()
        }
        AcceptanceDecision::Blocked => format!(
            "exit acceptance blocked: {} lanes blocked, {} release-stop lanes",
            blocked_lanes, release_stop_lanes
        ),
    }
}

fn severity_counts(blockers: &[AcceptanceBlocker]) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for blocker in blockers {
        let entry = counts
            .entry(blocker.severity.as_str().to_string())
            .or_insert(0);
        *entry += 1;
    }
    counts
}

fn lane_roots(lanes: &[LaneSummary]) -> BTreeMap<String, String> {
    lanes
        .iter()
        .map(|lane| (lane.lane.as_str().to_string(), lane.state_root()))
        .collect::<BTreeMap<_, _>>()
}

fn audit_roots(
    config: &Config,
    evidence: &[AcceptanceEvidence],
    blockers: &[AcceptanceBlocker],
    lanes: &[LaneSummary],
    summary: &AcceptanceSummary,
) -> BTreeMap<String, String> {
    let mut roots = BTreeMap::new();
    roots.insert("config".to_string(), config.state_root());
    roots.insert("evidence".to_string(), summary.evidence_root.clone());
    roots.insert("blockers".to_string(), summary.blocker_root.clone());
    roots.insert(
        "lane_summaries".to_string(),
        summary.lane_summary_root.clone(),
    );
    roots.insert("summary".to_string(), summary.state_root());
    roots.insert(
        "blocked_reason_index".to_string(),
        list_root(
            "BLOCKED-REASON-INDEX",
            blockers
                .iter()
                .filter(|blocker| blocker.blocks_acceptance)
                .map(AcceptanceBlocker::state_root),
        ),
    );
    roots.insert(
        "metric_index".to_string(),
        list_root(
            "METRIC-INDEX",
            evidence.iter().map(lane_metric_root).collect::<Vec<_>>(),
        ),
    );
    roots.insert(
        "lane_index".to_string(),
        list_root("LANE-INDEX", lanes.iter().map(LaneSummary::state_root)),
    );
    roots
}

fn evidence_root(
    family: &str,
    lane: AcceptanceLane,
    kind: EvidenceKind,
    sequence: u64,
    config: &Config,
) -> String {
    domain_hash(
        "EXIT-ACCEPTANCE-EVIDENCE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(family),
            HashPart::Str(config.exit_candidate_id.as_str()),
            HashPart::Str(lane.as_str()),
            HashPart::Str(kind.as_str()),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn observed_evidence_root(
    lane: AcceptanceLane,
    kind: EvidenceKind,
    sequence: u64,
    config: &Config,
) -> String {
    let family = match lane {
        AcceptanceLane::WalletRecovery => "expected",
        AcceptanceLane::ForcedRelease => "forced-release-pending-finality",
        AcceptanceLane::PqAuthority => "pq-authority-shortfall",
        AcceptanceLane::PrivacyBounds => "privacy-bound-open",
        AcceptanceLane::ObservedReceipts => "observed-receipt-stale",
        AcceptanceLane::LiveFeeds => "live-feed-shortfall",
        AcceptanceLane::Liquidity => "liquidity-shortfall",
        AcceptanceLane::DisputeWindow => "dispute-window-open",
        AcceptanceLane::ChallengeWindow => "challenge-window-open",
    };
    evidence_root(family, lane, kind, sequence, config)
}

fn lane_metric_root(evidence: &AcceptanceEvidence) -> String {
    domain_hash(
        "EXIT-ACCEPTANCE-LANE-METRIC",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(evidence.lane.as_str()),
            HashPart::Str(evidence.kind.as_str()),
            HashPart::U64(evidence.observed_height),
            HashPart::U64(evidence.confirmations),
            HashPart::Int(evidence.quorum as i128),
            HashPart::Int(evidence.security_bits as i128),
            HashPart::Int(evidence.leakage_units as i128),
            HashPart::Int(evidence.liquidity_coverage_bps as i128),
            HashPart::U64(evidence.window_close_height),
            HashPart::Str(bool_str(evidence.roots_match())),
        ],
        32,
    )
}

fn acceptance_state_root(
    config_root: &str,
    evidence_root: &str,
    blocker_root: &str,
    lane_summary_root: &str,
    summary_root: &str,
    audit_root: &str,
) -> String {
    domain_hash(
        "EXIT-ACCEPTANCE-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(config_root),
            HashPart::Str(evidence_root),
            HashPart::Str(blocker_root),
            HashPart::Str(lane_summary_root),
            HashPart::Str(summary_root),
            HashPart::Str(audit_root),
        ],
        32,
    )
}

fn short_hash(label: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(label, parts, 16)
}

fn list_root<I>(label: &str, roots: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let items = roots.into_iter().collect::<Vec<_>>();
    domain_hash(
        "EXIT-ACCEPTANCE-LIST",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(&merkle_root(&items)),
            HashPart::Int(items.len() as i128),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "EXIT-ACCEPTANCE-CANONICAL-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
