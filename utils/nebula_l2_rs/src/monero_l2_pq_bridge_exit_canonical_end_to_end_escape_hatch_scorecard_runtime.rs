use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalEndToEndEscapeHatchScorecardRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_END_TO_END_ESCAPE_HATCH_SCORECARD_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-end-to-end-escape-hatch-scorecard-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_END_TO_END_ESCAPE_HATCH_SCORECARD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SCORECARD_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-end-to-end-escape-hatch-scorecard-v1";
pub const DEFAULT_MIN_TOTAL_SCORE: u64 = 760;
pub const DEFAULT_MIN_USER_ESCAPE_SCORE: u64 = 850;
pub const DEFAULT_MAX_OPERATOR_DEPENDENCE_BPS: u64 = 1_000;
pub const DEFAULT_MIN_WATCHER_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 64;
pub const DEFAULT_MIN_RESERVE_COVER_BPS: u64 = 10_000;
pub const DEFAULT_MAX_CHALLENGE_LATENCY_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_STAGES: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeStage {
    DepositLock,
    PrivateNote,
    PrivateMovementOrContractAction,
    SettlementReceipt,
    ForcedExit,
    Release,
}

impl EscapeStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLock => "deposit_lock",
            Self::PrivateNote => "private_note",
            Self::PrivateMovementOrContractAction => "private_movement_or_contract_action",
            Self::SettlementReceipt => "settlement_receipt",
            Self::ForcedExit => "forced_exit",
            Self::Release => "release",
        }
    }

    pub fn is_user_escape_critical(self) -> bool {
        matches!(
            self,
            Self::DepositLock | Self::SettlementReceipt | Self::ForcedExit | Self::Release
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    Passing,
    Watch,
    Deferred,
    Blocked,
}

impl StageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passing => "passing",
            Self::Watch => "watch",
            Self::Deferred => "deferred",
            Self::Blocked => "blocked",
        }
    }

    pub fn blocks_user_escape(self) -> bool {
        matches!(self, Self::Blocked)
    }

    pub fn blocks_production(self) -> bool {
        matches!(self, Self::Watch | Self::Deferred | Self::Blocked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeBlocker {
    OperatorCooperationRequired,
    WatcherQuorumInsufficient,
    PrivacyEvidenceWeak,
    ReserveCoverageWeak,
    ChallengePathTooSlow,
    CargoRuntimeDeferred,
    ProductionSignoffDeferred,
    CanonicalContinuityMissing,
}

impl EscapeBlocker {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OperatorCooperationRequired => "operator_cooperation_required",
            Self::WatcherQuorumInsufficient => "watcher_quorum_insufficient",
            Self::PrivacyEvidenceWeak => "privacy_evidence_weak",
            Self::ReserveCoverageWeak => "reserve_coverage_weak",
            Self::ChallengePathTooSlow => "challenge_path_too_slow",
            Self::CargoRuntimeDeferred => "cargo_runtime_deferred",
            Self::ProductionSignoffDeferred => "production_signoff_deferred",
            Self::CanonicalContinuityMissing => "canonical_continuity_missing",
        }
    }

    pub fn owner_lane(self) -> &'static str {
        match self {
            Self::OperatorCooperationRequired => "escape_contract",
            Self::WatcherQuorumInsufficient => "watcher_quorum",
            Self::PrivacyEvidenceWeak => "privacy_review",
            Self::ReserveCoverageWeak => "liquidity_reserve",
            Self::ChallengePathTooSlow => "challenge_release",
            Self::CargoRuntimeDeferred => "runtime_harness",
            Self::ProductionSignoffDeferred => "security_audit",
            Self::CanonicalContinuityMissing => "canonical_transcript",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeVerdict {
    UserCanEscapeUnderMisbehavior,
    UserEscapeWatchListed,
    UserEscapeBlocked,
}

impl EscapeVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserCanEscapeUnderMisbehavior => "user_can_escape_under_misbehavior",
            Self::UserEscapeWatchListed => "user_escape_watch_listed",
            Self::UserEscapeBlocked => "user_escape_blocked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub scorecard_suite: String,
    pub min_total_score: u64,
    pub min_user_escape_score: u64,
    pub max_operator_dependence_bps: u64,
    pub min_watcher_quorum_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_reserve_cover_bps: u64,
    pub max_challenge_latency_blocks: u64,
    pub cargo_runtime_deferred: bool,
    pub production_release_allowed: bool,
    pub max_stages: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            scorecard_suite: SCORECARD_SUITE.to_string(),
            min_total_score: DEFAULT_MIN_TOTAL_SCORE,
            min_user_escape_score: DEFAULT_MIN_USER_ESCAPE_SCORE,
            max_operator_dependence_bps: DEFAULT_MAX_OPERATOR_DEPENDENCE_BPS,
            min_watcher_quorum_bps: DEFAULT_MIN_WATCHER_QUORUM_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_reserve_cover_bps: DEFAULT_MIN_RESERVE_COVER_BPS,
            max_challenge_latency_blocks: DEFAULT_MAX_CHALLENGE_LATENCY_BLOCKS,
            cargo_runtime_deferred: true,
            production_release_allowed: false,
            max_stages: DEFAULT_MAX_STAGES,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StageEvidence {
    pub stage: EscapeStage,
    pub status: StageStatus,
    pub label: String,
    pub source_runtime: String,
    pub source_root: String,
    pub prior_root: String,
    pub next_root: String,
    pub operator_dependence_bps: u64,
    pub watcher_quorum_bps: u64,
    pub privacy_set_size: u64,
    pub reserve_cover_bps: u64,
    pub challenge_latency_blocks: u64,
    pub user_can_self_serve: String,
    pub continuity_preserved: String,
}

impl StageEvidence {
    pub fn evidence_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-e2e-escape-stage-evidence",
            &[
                HashPart::Str(self.stage.as_str()),
                HashPart::Str(self.status.as_str()),
                HashPart::Str(&self.label),
                HashPart::Str(&self.source_runtime),
                HashPart::Str(&self.source_root),
                HashPart::Str(&self.prior_root),
                HashPart::Str(&self.next_root),
                HashPart::U64(self.operator_dependence_bps),
                HashPart::U64(self.watcher_quorum_bps),
                HashPart::U64(self.privacy_set_size),
                HashPart::U64(self.reserve_cover_bps),
                HashPart::U64(self.challenge_latency_blocks),
                HashPart::Str(&self.user_can_self_serve),
                HashPart::Str(&self.continuity_preserved),
            ],
            32,
        )
    }

    pub fn user_self_serves(&self) -> bool {
        self.user_can_self_serve == "yes"
    }

    pub fn continuity_is_preserved(&self) -> bool {
        self.continuity_preserved == "yes"
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StageAssessment {
    pub stage: EscapeStage,
    pub status: StageStatus,
    pub score: u64,
    pub evidence_root: String,
    pub answer_root: String,
    pub blocker: Option<EscapeBlocker>,
    pub user_escape_lane: String,
    pub production_lane: String,
    pub remediation: String,
    pub assessment_root: String,
}

impl StageAssessment {
    pub fn blocks_user_escape(&self) -> bool {
        self.stage.is_user_escape_critical()
            && (self.status.blocks_user_escape() || self.user_escape_lane == "blocked")
    }

    pub fn blocks_production(&self) -> bool {
        self.status.blocks_production() || self.blocker.is_some() || self.production_lane != "ready"
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScoreCounters {
    pub total_stages: u64,
    pub passing_stages: u64,
    pub watch_stages: u64,
    pub deferred_stages: u64,
    pub blocked_stages: u64,
    pub user_escape_blockers: u64,
    pub production_blockers: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EscapeAnswer {
    pub verdict: EscapeVerdict,
    pub user_escape_answer: String,
    pub operator_cooperation_requirement: String,
    pub watcher_quorum_answer: String,
    pub privacy_answer: String,
    pub reserve_answer: String,
    pub challenge_answer: String,
    pub cargo_runtime_deferral_blocker: String,
    pub production_readiness_score: u64,
    pub answer_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub evidence: Vec<StageEvidence>,
    pub assessments: Vec<StageAssessment>,
    pub counters: ScoreCounters,
    pub blockers: Vec<EscapeBlocker>,
    pub owner_lanes: BTreeMap<String, String>,
    pub scorecard_id: String,
    pub score: u64,
    pub answer: EscapeAnswer,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self::from_evidence(config.clone(), default_evidence(&config))
    }

    pub fn from_evidence(config: Config, evidence: Vec<StageEvidence>) -> Self {
        let limited_evidence = evidence
            .into_iter()
            .take(config.max_stages)
            .collect::<Vec<_>>();
        let mut counters = ScoreCounters {
            total_stages: limited_evidence.len() as u64,
            ..ScoreCounters::default()
        };
        let mut blockers = Vec::new();
        let mut owner_lanes = BTreeMap::new();
        let mut assessments = Vec::new();

        for item in &limited_evidence {
            let assessment = assess_stage(&config, item);
            match assessment.status {
                StageStatus::Passing => counters.passing_stages += 1,
                StageStatus::Watch => counters.watch_stages += 1,
                StageStatus::Deferred => counters.deferred_stages += 1,
                StageStatus::Blocked => counters.blocked_stages += 1,
            }
            if assessment.blocks_user_escape() {
                counters.user_escape_blockers += 1;
            }
            if assessment.blocks_production() {
                counters.production_blockers += 1;
            }
            if let Some(blocker) = assessment.blocker {
                if !blockers.contains(&blocker) {
                    blockers.push(blocker);
                }
                owner_lanes.insert(
                    assessment.stage.as_str().to_string(),
                    blocker.owner_lane().to_string(),
                );
            } else {
                owner_lanes.insert(
                    assessment.stage.as_str().to_string(),
                    assessment.stage.as_str().to_string(),
                );
            }
            assessments.push(assessment);
        }

        if config.cargo_runtime_deferred && !blockers.contains(&EscapeBlocker::CargoRuntimeDeferred)
        {
            blockers.push(EscapeBlocker::CargoRuntimeDeferred);
        }
        if !config.production_release_allowed
            && !blockers.contains(&EscapeBlocker::ProductionSignoffDeferred)
        {
            blockers.push(EscapeBlocker::ProductionSignoffDeferred);
        }
        blockers.sort();

        let user_escape_score = user_escape_score(&assessments);
        let score = production_score(&config, &assessments, &counters, &blockers);
        let verdict = derive_verdict(&config, user_escape_score, &counters);
        let answer = build_answer(&config, verdict, score, &limited_evidence, &blockers);
        let scorecard_id = scorecard_id(
            &config.chain_id,
            verdict,
            score,
            &evidence_root(&limited_evidence),
            &assessment_root(&assessments),
            &blocker_root(&blockers),
        );

        Self {
            config,
            evidence: limited_evidence,
            assessments,
            counters,
            blockers,
            owner_lanes,
            scorecard_id,
            score,
            answer,
        }
    }

    pub fn ingest(&mut self, evidence: StageEvidence) -> Result<()> {
        if self.evidence.len() >= self.config.max_stages {
            return Err("canonical end-to-end escape hatch scorecard capacity reached".to_string());
        }
        self.evidence.push(evidence);
        *self = Self::from_evidence(self.config.clone(), self.evidence.clone());
        Ok(())
    }

    pub fn user_escape_clear(&self) -> bool {
        self.answer.verdict == EscapeVerdict::UserCanEscapeUnderMisbehavior
            && self.counters.user_escape_blockers == 0
    }

    pub fn production_blocked(&self) -> bool {
        !self.blockers.is_empty() || self.score < self.config.min_total_score
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-canonical-e2e-escape-scorecard-state",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(&self.scorecard_id),
                HashPart::Str(&self.answer.answer_root),
                HashPart::Str(&evidence_root(&self.evidence)),
                HashPart::Str(&assessment_root(&self.assessments)),
                HashPart::Str(&blocker_root(&self.blockers)),
                HashPart::U64(self.score),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let evidence = self
            .evidence
            .iter()
            .map(public_evidence_record)
            .collect::<Vec<_>>();
        let assessments = self
            .assessments
            .iter()
            .map(public_assessment_record)
            .collect::<Vec<_>>();
        let blockers = self
            .blockers
            .iter()
            .map(|blocker| {
                json!({
                    "kind": blocker.as_str(),
                    "owner_lane": blocker.owner_lane(),
                })
            })
            .collect::<Vec<_>>();

        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "scorecard_suite": SCORECARD_SUITE,
            "chain_id": self.config.chain_id,
            "state_root": self.state_root(),
            "scorecard_id": self.scorecard_id,
            "score": self.score,
            "answer": {
                "verdict": self.answer.verdict.as_str(),
                "user_escape_answer": self.answer.user_escape_answer,
                "operator_cooperation_requirement": self.answer.operator_cooperation_requirement,
                "watcher_quorum_answer": self.answer.watcher_quorum_answer,
                "privacy_answer": self.answer.privacy_answer,
                "reserve_answer": self.answer.reserve_answer,
                "challenge_answer": self.answer.challenge_answer,
                "cargo_runtime_deferral_blocker": self.answer.cargo_runtime_deferral_blocker,
                "production_readiness_score": self.answer.production_readiness_score,
                "answer_root": self.answer.answer_root,
            },
            "counters": {
                "total_stages": self.counters.total_stages,
                "passing_stages": self.counters.passing_stages,
                "watch_stages": self.counters.watch_stages,
                "deferred_stages": self.counters.deferred_stages,
                "blocked_stages": self.counters.blocked_stages,
                "user_escape_blockers": self.counters.user_escape_blockers,
                "production_blockers": self.counters.production_blockers,
            },
            "blockers": blockers,
            "owner_lanes": self.owner_lanes,
            "evidence": evidence,
            "assessments": assessments,
        })
    }
}

pub fn devnet() -> State {
    State::new(Config::default())
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn default_evidence(config: &Config) -> Vec<StageEvidence> {
    let seed = seed_root(&config.chain_id);
    let deposit = stage_root(EscapeStage::DepositLock, &seed, 10);
    let note = stage_root(EscapeStage::PrivateNote, &deposit, 20);
    let movement = stage_root(EscapeStage::PrivateMovementOrContractAction, &note, 30);
    let receipt = stage_root(EscapeStage::SettlementReceipt, &movement, 40);
    let forced_exit = stage_root(EscapeStage::ForcedExit, &receipt, 50);
    let release = stage_root(EscapeStage::Release, &forced_exit, 60);

    vec![
        stage_evidence(
            EscapeStage::DepositLock,
            StageStatus::Passing,
            "monero deposit lock is finality checked and mints the first private note",
            "monero_l2_pq_bridge_exit_canonical_deposit_lock_vector_runtime",
            "canonical-deposit-lock-vector-root",
            &seed,
            &note,
            0,
            7_200,
            96,
            10_000,
            180,
            "yes",
            "yes",
        ),
        stage_evidence(
            EscapeStage::PrivateNote,
            StageStatus::Passing,
            "locked value becomes wallet-recoverable private note state",
            "monero_l2_pq_bridge_exit_canonical_private_note_transfer_vector_runtime",
            "canonical-private-note-vector-root",
            &deposit,
            &movement,
            0,
            7_200,
            96,
            10_000,
            180,
            "yes",
            "yes",
        ),
        stage_evidence(
            EscapeStage::PrivateMovementOrContractAction,
            StageStatus::Watch,
            "private movement and one contract action preserve receipt continuity",
            "monero_l2_pq_bridge_exit_adversarial_vertical_slice_corridor_runtime",
            "canonical-private-action-corridor-root",
            &note,
            &receipt,
            500,
            7_200,
            80,
            10_000,
            240,
            "yes",
            "yes",
        ),
        stage_evidence(
            EscapeStage::SettlementReceipt,
            StageStatus::Passing,
            "settlement receipt binds private action output to the exit claim lane",
            "monero_l2_pq_bridge_exit_canonical_settlement_exit_vector_runtime",
            "canonical-settlement-exit-vector-root",
            &movement,
            &forced_exit,
            0,
            7_200,
            96,
            10_000,
            240,
            "yes",
            "yes",
        ),
        stage_evidence(
            EscapeStage::ForcedExit,
            StageStatus::Watch,
            "wallet-local receipt package can force exit when operator and watchers misbehave",
            "monero_l2_pq_bridge_exit_canonical_wallet_force_exit_runbook_runtime",
            "canonical-wallet-force-exit-runbook-root",
            &receipt,
            &release,
            0,
            6_900,
            80,
            10_000,
            600,
            "yes",
            "yes",
        ),
        stage_evidence(
            EscapeStage::Release,
            StageStatus::Watch,
            "release path uses reserve and challenge evidence without operator cooperation",
            "monero_l2_pq_bridge_exit_canonical_challenge_release_vector_runtime",
            "canonical-challenge-release-vector-root",
            &forced_exit,
            &release,
            0,
            6_900,
            80,
            10_000,
            600,
            "yes",
            "yes",
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
pub fn stage_evidence(
    stage: EscapeStage,
    status: StageStatus,
    label: &str,
    source_runtime: &str,
    source_root: &str,
    prior_root: &str,
    next_root: &str,
    operator_dependence_bps: u64,
    watcher_quorum_bps: u64,
    privacy_set_size: u64,
    reserve_cover_bps: u64,
    challenge_latency_blocks: u64,
    user_can_self_serve: &str,
    continuity_preserved: &str,
) -> StageEvidence {
    StageEvidence {
        stage,
        status,
        label: label.to_string(),
        source_runtime: source_runtime.to_string(),
        source_root: source_root.to_string(),
        prior_root: prior_root.to_string(),
        next_root: next_root.to_string(),
        operator_dependence_bps,
        watcher_quorum_bps,
        privacy_set_size,
        reserve_cover_bps,
        challenge_latency_blocks,
        user_can_self_serve: user_can_self_serve.to_string(),
        continuity_preserved: continuity_preserved.to_string(),
    }
}

pub fn assess_stage(config: &Config, evidence: &StageEvidence) -> StageAssessment {
    let blocker = derive_blocker(config, evidence);
    let status = if blocker == Some(EscapeBlocker::CanonicalContinuityMissing)
        || blocker == Some(EscapeBlocker::OperatorCooperationRequired)
    {
        StageStatus::Blocked
    } else {
        evidence.status
    };
    let score = stage_score(config, evidence, status, blocker);
    let evidence_root = evidence.evidence_root();
    let answer_root = stage_answer_root(evidence, status, score, blocker);
    let user_escape_lane = if evidence.stage.is_user_escape_critical()
        && (status.blocks_user_escape() || !evidence.user_self_serves())
    {
        "blocked"
    } else if evidence.stage.is_user_escape_critical() {
        "critical_clear"
    } else {
        "supporting"
    }
    .to_string();
    let production_lane = if status.blocks_production() || blocker.is_some() {
        "blocked"
    } else {
        "ready"
    }
    .to_string();
    let remediation = remediation_hint(evidence.stage, status, blocker);
    let assessment_root = stage_assessment_root(
        evidence.stage,
        status,
        score,
        &evidence_root,
        &answer_root,
        blocker,
    );

    StageAssessment {
        stage: evidence.stage,
        status,
        score,
        evidence_root,
        answer_root,
        blocker,
        user_escape_lane,
        production_lane,
        remediation,
        assessment_root,
    }
}

pub fn derive_blocker(config: &Config, evidence: &StageEvidence) -> Option<EscapeBlocker> {
    if !evidence.continuity_is_preserved() {
        return Some(EscapeBlocker::CanonicalContinuityMissing);
    }
    if evidence.stage.is_user_escape_critical() && !evidence.user_self_serves() {
        return Some(EscapeBlocker::OperatorCooperationRequired);
    }
    if evidence.operator_dependence_bps > config.max_operator_dependence_bps {
        return Some(EscapeBlocker::OperatorCooperationRequired);
    }
    if evidence.watcher_quorum_bps < config.min_watcher_quorum_bps {
        return Some(EscapeBlocker::WatcherQuorumInsufficient);
    }
    if evidence.privacy_set_size < config.min_privacy_set_size {
        return Some(EscapeBlocker::PrivacyEvidenceWeak);
    }
    if evidence.reserve_cover_bps < config.min_reserve_cover_bps {
        return Some(EscapeBlocker::ReserveCoverageWeak);
    }
    if evidence.challenge_latency_blocks > config.max_challenge_latency_blocks {
        return Some(EscapeBlocker::ChallengePathTooSlow);
    }
    None
}

pub fn stage_score(
    config: &Config,
    evidence: &StageEvidence,
    status: StageStatus,
    blocker: Option<EscapeBlocker>,
) -> u64 {
    let mut score = match status {
        StageStatus::Passing => 1_000,
        StageStatus::Watch => 850,
        StageStatus::Deferred => 650,
        StageStatus::Blocked => 0,
    };

    if blocker.is_some() {
        score = score.saturating_sub(240);
    }
    if evidence.operator_dependence_bps > 0 {
        score = score.saturating_sub(evidence.operator_dependence_bps / 20);
    }
    if evidence.privacy_set_size < config.min_privacy_set_size.saturating_mul(2) {
        score = score.saturating_sub(40);
    }
    if config.cargo_runtime_deferred && evidence.status != StageStatus::Passing {
        score = score.saturating_sub(50);
    }

    score
}

pub fn production_score(
    config: &Config,
    assessments: &[StageAssessment],
    counters: &ScoreCounters,
    blockers: &[EscapeBlocker],
) -> u64 {
    if assessments.is_empty() {
        return 0;
    }

    let base = assessments.iter().map(|item| item.score).sum::<u64>() / assessments.len() as u64;
    let mut score = base
        .saturating_sub(counters.user_escape_blockers.saturating_mul(300))
        .saturating_sub(counters.production_blockers.saturating_mul(35))
        .saturating_sub(blockers.len() as u64 * 25);

    if config.cargo_runtime_deferred {
        score = score.saturating_sub(75);
    }
    if !config.production_release_allowed {
        score = score.saturating_sub(75);
    }
    score
}

pub fn user_escape_score(assessments: &[StageAssessment]) -> u64 {
    let critical_scores = assessments
        .iter()
        .filter(|item| item.stage.is_user_escape_critical())
        .map(|item| item.score)
        .collect::<Vec<_>>();

    if critical_scores.is_empty() {
        return 0;
    }

    critical_scores.iter().sum::<u64>() / critical_scores.len() as u64
}

pub fn derive_verdict(config: &Config, score: u64, counters: &ScoreCounters) -> EscapeVerdict {
    if counters.user_escape_blockers > 0 || counters.blocked_stages > 0 {
        return EscapeVerdict::UserEscapeBlocked;
    }
    if score >= config.min_user_escape_score
        && counters.deferred_stages == 0
        && counters.total_stages >= 6
    {
        return EscapeVerdict::UserCanEscapeUnderMisbehavior;
    }
    EscapeVerdict::UserEscapeWatchListed
}

pub fn build_answer(
    config: &Config,
    verdict: EscapeVerdict,
    score: u64,
    evidence: &[StageEvidence],
    blockers: &[EscapeBlocker],
) -> EscapeAnswer {
    let max_operator_dependence = evidence
        .iter()
        .map(|item| item.operator_dependence_bps)
        .max()
        .unwrap_or(0);
    let min_watcher_quorum = evidence
        .iter()
        .map(|item| item.watcher_quorum_bps)
        .min()
        .unwrap_or(0);
    let min_privacy_set = evidence
        .iter()
        .map(|item| item.privacy_set_size)
        .min()
        .unwrap_or(0);
    let min_reserve_cover = evidence
        .iter()
        .map(|item| item.reserve_cover_bps)
        .min()
        .unwrap_or(0);
    let max_challenge_latency = evidence
        .iter()
        .map(|item| item.challenge_latency_blocks)
        .max()
        .unwrap_or(0);

    let user_escape_answer = match verdict {
        EscapeVerdict::UserCanEscapeUnderMisbehavior => {
            "yes: devnet evidence says a user can deposit, transact privately, settle, force exit, and release without honest operator cooperation"
        }
        EscapeVerdict::UserEscapeWatchListed => {
            "mostly: user-critical continuity is clear, but production-grade proof is watch-listed by runtime and review deferrals"
        }
        EscapeVerdict::UserEscapeBlocked => {
            "no: at least one user-critical escape stage is blocked"
        }
    }
    .to_string();
    let operator_cooperation_requirement = format!(
        "operator cooperation dependence peaks at {} bps against a {} bps cap",
        max_operator_dependence, config.max_operator_dependence_bps
    );
    let watcher_quorum_answer = format!(
        "minimum watcher quorum is {} bps against a {} bps threshold",
        min_watcher_quorum, config.min_watcher_quorum_bps
    );
    let privacy_answer = format!(
        "minimum private anonymity set is {} notes against a {} note floor",
        min_privacy_set, config.min_privacy_set_size
    );
    let reserve_answer = format!(
        "minimum reserve cover is {} bps against a {} bps release requirement",
        min_reserve_cover, config.min_reserve_cover_bps
    );
    let challenge_answer = format!(
        "maximum challenge latency is {} blocks against a {} block cap",
        max_challenge_latency, config.max_challenge_latency_blocks
    );
    let cargo_runtime_deferral_blocker = if config.cargo_runtime_deferred {
        "cargo/runtime execution is deferred by wave policy and blocks production readiness"
            .to_string()
    } else {
        "cargo/runtime execution is available for this scorecard".to_string()
    };
    let answer_root = answer_root(
        verdict,
        score,
        &user_escape_answer,
        &operator_cooperation_requirement,
        &watcher_quorum_answer,
        &privacy_answer,
        &reserve_answer,
        &challenge_answer,
        &cargo_runtime_deferral_blocker,
        blockers,
    );

    EscapeAnswer {
        verdict,
        user_escape_answer,
        operator_cooperation_requirement,
        watcher_quorum_answer,
        privacy_answer,
        reserve_answer,
        challenge_answer,
        cargo_runtime_deferral_blocker,
        production_readiness_score: score,
        answer_root,
    }
}

pub fn public_evidence_record(evidence: &StageEvidence) -> Value {
    json!({
        "stage": evidence.stage.as_str(),
        "status": evidence.status.as_str(),
        "label": evidence.label,
        "source_runtime": evidence.source_runtime,
        "source_root": evidence.source_root,
        "prior_root": evidence.prior_root,
        "next_root": evidence.next_root,
        "operator_dependence_bps": evidence.operator_dependence_bps,
        "watcher_quorum_bps": evidence.watcher_quorum_bps,
        "privacy_set_size": evidence.privacy_set_size,
        "reserve_cover_bps": evidence.reserve_cover_bps,
        "challenge_latency_blocks": evidence.challenge_latency_blocks,
        "user_can_self_serve": evidence.user_can_self_serve,
        "continuity_preserved": evidence.continuity_preserved,
        "evidence_root": evidence.evidence_root(),
    })
}

pub fn public_assessment_record(assessment: &StageAssessment) -> Value {
    json!({
        "stage": assessment.stage.as_str(),
        "status": assessment.status.as_str(),
        "score": assessment.score,
        "evidence_root": assessment.evidence_root,
        "answer_root": assessment.answer_root,
        "blocker": assessment.blocker.map(|blocker| blocker.as_str()),
        "user_escape_lane": assessment.user_escape_lane,
        "production_lane": assessment.production_lane,
        "remediation": assessment.remediation,
        "assessment_root": assessment.assessment_root,
    })
}

pub fn seed_root(chain_id: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-e2e-escape-seed",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(SCORECARD_SUITE),
        ],
        32,
    )
}

pub fn stage_root(stage: EscapeStage, prior_root: &str, order: u64) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-e2e-escape-stage",
        &[
            HashPart::Str(stage.as_str()),
            HashPart::Str(prior_root),
            HashPart::U64(order),
        ],
        32,
    )
}

pub fn stage_answer_root(
    evidence: &StageEvidence,
    status: StageStatus,
    score: u64,
    blocker: Option<EscapeBlocker>,
) -> String {
    let blocker_label = blocker.map(|item| item.as_str()).unwrap_or("none");
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-e2e-escape-stage-answer",
        &[
            HashPart::Str(evidence.stage.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::U64(score),
            HashPart::Str(blocker_label),
            HashPart::Str(&evidence.evidence_root()),
        ],
        32,
    )
}

pub fn stage_assessment_root(
    stage: EscapeStage,
    status: StageStatus,
    score: u64,
    evidence_root: &str,
    answer_root: &str,
    blocker: Option<EscapeBlocker>,
) -> String {
    let blocker_label = blocker.map(|item| item.as_str()).unwrap_or("none");
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-e2e-escape-stage-assessment",
        &[
            HashPart::Str(stage.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::U64(score),
            HashPart::Str(evidence_root),
            HashPart::Str(answer_root),
            HashPart::Str(blocker_label),
        ],
        32,
    )
}

pub fn evidence_root(evidence: &[StageEvidence]) -> String {
    let leaves = evidence
        .iter()
        .map(StageEvidence::evidence_root)
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-canonical-e2e-escape-evidence",
        leaves.as_slice(),
    )
}

pub fn assessment_root(assessments: &[StageAssessment]) -> String {
    let leaves = assessments
        .iter()
        .map(|item| item.assessment_root.clone())
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-canonical-e2e-escape-assessments",
        leaves.as_slice(),
    )
}

pub fn blocker_root(blockers: &[EscapeBlocker]) -> String {
    let leaves = blockers
        .iter()
        .map(|item| item.as_str().to_string())
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-canonical-e2e-escape-blockers",
        leaves.as_slice(),
    )
}

pub fn answer_root(
    verdict: EscapeVerdict,
    score: u64,
    user_escape_answer: &str,
    operator_answer: &str,
    watcher_answer: &str,
    privacy_answer: &str,
    reserve_answer: &str,
    challenge_answer: &str,
    cargo_answer: &str,
    blockers: &[EscapeBlocker],
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-e2e-escape-answer",
        &[
            HashPart::Str(verdict.as_str()),
            HashPart::U64(score),
            HashPart::Str(user_escape_answer),
            HashPart::Str(operator_answer),
            HashPart::Str(watcher_answer),
            HashPart::Str(privacy_answer),
            HashPart::Str(reserve_answer),
            HashPart::Str(challenge_answer),
            HashPart::Str(cargo_answer),
            HashPart::Str(&blocker_root(blockers)),
        ],
        32,
    )
}

pub fn scorecard_id(
    chain_id: &str,
    verdict: EscapeVerdict,
    score: u64,
    evidence_root: &str,
    assessment_root: &str,
    blocker_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-canonical-e2e-escape-scorecard-id",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(verdict.as_str()),
            HashPart::U64(score),
            HashPart::Str(evidence_root),
            HashPart::Str(assessment_root),
            HashPart::Str(blocker_root),
        ],
        16,
    )
}

pub fn remediation_hint(
    stage: EscapeStage,
    status: StageStatus,
    blocker: Option<EscapeBlocker>,
) -> String {
    if status == StageStatus::Passing && blocker.is_none() {
        return format!("{} escape evidence is clear", stage.as_str());
    }

    match blocker {
        Some(EscapeBlocker::OperatorCooperationRequired) => {
            "remove operator cooperation from the wallet-local escape path"
        }
        Some(EscapeBlocker::WatcherQuorumInsufficient) => {
            "raise PQ watcher quorum weight or quarantine the weak epoch"
        }
        Some(EscapeBlocker::PrivacyEvidenceWeak) => {
            "increase private set coverage and bind privacy regression roots"
        }
        Some(EscapeBlocker::ReserveCoverageWeak) => {
            "bind reserve, backstop, or partial-release evidence above the cover floor"
        }
        Some(EscapeBlocker::ChallengePathTooSlow) => {
            "shorten challenge response latency or widen user-safe liquidity coverage"
        }
        Some(EscapeBlocker::CargoRuntimeDeferred) => {
            "resume runtime harness execution and bind the result root"
        }
        Some(EscapeBlocker::ProductionSignoffDeferred) => {
            "collect security and privacy release signoff after runtime roots exist"
        }
        Some(EscapeBlocker::CanonicalContinuityMissing) => {
            "restore deposit-to-release continuity roots before scoring escape"
        }
        None => "replace watch or deferred evidence with executable canonical roots",
    }
    .to_string()
}
