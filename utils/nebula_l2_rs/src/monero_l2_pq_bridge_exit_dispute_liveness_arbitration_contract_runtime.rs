use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitDisputeLivenessArbitrationContractRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_DISPUTE_LIVENESS_ARBITRATION_CONTRACT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-dispute-liveness-arbitration-contract-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_DISPUTE_LIVENESS_ARBITRATION_CONTRACT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ARBITRATION_SUITE: &str =
    "monero-l2-pq-bridge-exit-dispute-liveness-arbitration-contract-v1";
pub const DEFAULT_CURRENT_HEIGHT: u64 = 4_200_384;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_LIVENESS_TIMEOUT_BLOCKS: u64 = 144;
pub const DEFAULT_CENSORSHIP_TIMEOUT_BLOCKS: u64 = 288;
pub const DEFAULT_EMERGENCY_RELEASE_DELAY_BLOCKS: u64 = 1_440;
pub const DEFAULT_MIN_WATCHER_QUORUM: u64 = 5;
pub const DEFAULT_COLLUSION_THRESHOLD_BPS: u64 = 6_667;
pub const DEFAULT_ESCAPE_ROOT_CONFIRMATIONS: u64 = 12;
pub const DEFAULT_MIN_ARBITRATIONS: u64 = 6;
pub const DEFAULT_MAX_CASES: usize = 256;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArbitrationTrigger {
    SequencerLivenessFailure,
    WatcherQuorumFailure,
    WatcherCollusionEvidence,
    CensorshipTimerExpired,
    ChallengeWindowDispute,
    SlashingSettlementReference,
    ReleaseBlockerOverride,
    EmergencyUserEscape,
}

impl ArbitrationTrigger {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerLivenessFailure => "sequencer_liveness_failure",
            Self::WatcherQuorumFailure => "watcher_quorum_failure",
            Self::WatcherCollusionEvidence => "watcher_collusion_evidence",
            Self::CensorshipTimerExpired => "censorship_timer_expired",
            Self::ChallengeWindowDispute => "challenge_window_dispute",
            Self::SlashingSettlementReference => "slashing_settlement_reference",
            Self::ReleaseBlockerOverride => "release_blocker_override",
            Self::EmergencyUserEscape => "emergency_user_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArbitrationStatus {
    Open,
    QuorumPending,
    ChallengeWindowActive,
    ReleaseBlocked,
    EmergencyReleaseReady,
    UserEscapeApproved,
    Rejected,
}

impl ArbitrationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::QuorumPending => "quorum_pending",
            Self::ChallengeWindowActive => "challenge_window_active",
            Self::ReleaseBlocked => "release_blocked",
            Self::EmergencyReleaseReady => "emergency_release_ready",
            Self::UserEscapeApproved => "user_escape_approved",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherEvidenceKind {
    HonestQuorum,
    MissingQuorum,
    Equivocation,
    CollusionBundle,
    WithheldLivenessProof,
    CensorshipReceipt,
    ReorgMismatch,
}

impl WatcherEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HonestQuorum => "honest_quorum",
            Self::MissingQuorum => "missing_quorum",
            Self::Equivocation => "equivocation",
            Self::CollusionBundle => "collusion_bundle",
            Self::WithheldLivenessProof => "withheld_liveness_proof",
            Self::CensorshipReceipt => "censorship_receipt",
            Self::ReorgMismatch => "reorg_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeOutcome {
    NotReady,
    ReleaseClaim,
    EmergencyRelease,
    UserEscapeRoot,
    Quarantined,
}

impl EscapeOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotReady => "not_ready",
            Self::ReleaseClaim => "release_claim",
            Self::EmergencyRelease => "emergency_release",
            Self::UserEscapeRoot => "user_escape_root",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArbitrationReportStatus {
    Passed,
    Watch,
    Failed,
}

impl ArbitrationReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
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
    pub arbitration_suite: String,
    pub current_height: u64,
    pub challenge_window_blocks: u64,
    pub liveness_timeout_blocks: u64,
    pub censorship_timeout_blocks: u64,
    pub emergency_release_delay_blocks: u64,
    pub min_watcher_quorum: u64,
    pub collusion_threshold_bps: u64,
    pub escape_root_confirmations: u64,
    pub min_arbitrations: u64,
    pub fail_closed_on_collusion: bool,
    pub require_slashing_reference: bool,
    pub release_blocker_clearing_required: bool,
    pub claim_queue_hold_required: bool,
    pub max_cases: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            arbitration_suite: ARBITRATION_SUITE.to_string(),
            current_height: DEFAULT_CURRENT_HEIGHT,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            liveness_timeout_blocks: DEFAULT_LIVENESS_TIMEOUT_BLOCKS,
            censorship_timeout_blocks: DEFAULT_CENSORSHIP_TIMEOUT_BLOCKS,
            emergency_release_delay_blocks: DEFAULT_EMERGENCY_RELEASE_DELAY_BLOCKS,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            collusion_threshold_bps: DEFAULT_COLLUSION_THRESHOLD_BPS,
            escape_root_confirmations: DEFAULT_ESCAPE_ROOT_CONFIRMATIONS,
            min_arbitrations: DEFAULT_MIN_ARBITRATIONS,
            fail_closed_on_collusion: true,
            require_slashing_reference: true,
            release_blocker_clearing_required: true,
            claim_queue_hold_required: true,
            max_cases: DEFAULT_MAX_CASES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "arbitration_suite": self.arbitration_suite,
            "current_height": self.current_height,
            "challenge_window_blocks": self.challenge_window_blocks,
            "liveness_timeout_blocks": self.liveness_timeout_blocks,
            "censorship_timeout_blocks": self.censorship_timeout_blocks,
            "emergency_release_delay_blocks": self.emergency_release_delay_blocks,
            "min_watcher_quorum": self.min_watcher_quorum,
            "collusion_threshold_bps": self.collusion_threshold_bps,
            "escape_root_confirmations": self.escape_root_confirmations,
            "min_arbitrations": self.min_arbitrations,
            "fail_closed_on_collusion": self.fail_closed_on_collusion,
            "require_slashing_reference": self.require_slashing_reference,
            "release_blocker_clearing_required": self.release_blocker_clearing_required,
            "claim_queue_hold_required": self.claim_queue_hold_required,
            "max_cases": self.max_cases,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitDisputeInput {
    pub dispute_id: String,
    pub release_claim_id: String,
    pub transfer_id: String,
    pub user_escape_id: String,
    pub opened_at_height: u64,
    pub last_sequencer_progress_height: u64,
    pub last_watcher_progress_height: u64,
    pub watcher_votes: u64,
    pub watcher_total: u64,
    pub collusion_bps: u64,
    pub censorship_reports: u64,
    pub reorg_depth: u64,
    pub claim_queue_root: String,
    pub release_blocker_root: String,
    pub slashing_reference_root: String,
    pub reorg_collusion_simulation_root: String,
    pub watcher_bond_root: String,
    pub user_escape_leaf_root: String,
}

impl ForcedExitDisputeInput {
    pub fn public_record(&self) -> Value {
        json!({
            "dispute_id": self.dispute_id,
            "release_claim_id": self.release_claim_id,
            "transfer_id": self.transfer_id,
            "user_escape_id": self.user_escape_id,
            "opened_at_height": self.opened_at_height,
            "last_sequencer_progress_height": self.last_sequencer_progress_height,
            "last_watcher_progress_height": self.last_watcher_progress_height,
            "watcher_votes": self.watcher_votes,
            "watcher_total": self.watcher_total,
            "collusion_bps": self.collusion_bps,
            "censorship_reports": self.censorship_reports,
            "reorg_depth": self.reorg_depth,
            "claim_queue_root": self.claim_queue_root,
            "release_blocker_root": self.release_blocker_root,
            "slashing_reference_root": self.slashing_reference_root,
            "reorg_collusion_simulation_root": self.reorg_collusion_simulation_root,
            "watcher_bond_root": self.watcher_bond_root,
            "user_escape_leaf_root": self.user_escape_leaf_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("forced_exit_dispute_input", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherQuorumEvidence {
    pub evidence_id: String,
    pub kind: WatcherEvidenceKind,
    pub dispute_id: String,
    pub watcher_votes: u64,
    pub watcher_total: u64,
    pub quorum_met: bool,
    pub collusion_bps: u64,
    pub collusion_threshold_bps: u64,
    pub liveness_delay_blocks: u64,
    pub censorship_delay_blocks: u64,
    pub reorg_depth: u64,
    pub watcher_bond_root: String,
    pub slashing_reference_root: String,
    pub simulation_root: String,
    pub evidence_root: String,
}

impl WatcherQuorumEvidence {
    pub fn from_input(config: &Config, input: &ForcedExitDisputeInput) -> Self {
        let liveness_delay_blocks = config
            .current_height
            .saturating_sub(input.last_watcher_progress_height);
        let censorship_delay_blocks = config
            .current_height
            .saturating_sub(input.last_sequencer_progress_height);
        let quorum_met =
            input.watcher_votes >= config.min_watcher_quorum && input.watcher_votes > 0;
        let kind = watcher_evidence_kind(
            config,
            quorum_met,
            input.collusion_bps,
            liveness_delay_blocks,
            censorship_delay_blocks,
            input.reorg_depth,
        );
        let evidence_root = watcher_evidence_root(
            kind,
            &input.dispute_id,
            input.watcher_votes,
            input.watcher_total,
            input.collusion_bps,
            liveness_delay_blocks,
            censorship_delay_blocks,
            &input.watcher_bond_root,
            &input.slashing_reference_root,
            &input.reorg_collusion_simulation_root,
        );
        let evidence_id = watcher_evidence_id(&input.dispute_id, kind, &evidence_root);
        Self {
            evidence_id,
            kind,
            dispute_id: input.dispute_id.clone(),
            watcher_votes: input.watcher_votes,
            watcher_total: input.watcher_total,
            quorum_met,
            collusion_bps: input.collusion_bps,
            collusion_threshold_bps: config.collusion_threshold_bps,
            liveness_delay_blocks,
            censorship_delay_blocks,
            reorg_depth: input.reorg_depth,
            watcher_bond_root: input.watcher_bond_root.clone(),
            slashing_reference_root: input.slashing_reference_root.clone(),
            simulation_root: input.reorg_collusion_simulation_root.clone(),
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "dispute_id": self.dispute_id,
            "watcher_votes": self.watcher_votes,
            "watcher_total": self.watcher_total,
            "quorum_met": self.quorum_met,
            "collusion_bps": self.collusion_bps,
            "collusion_threshold_bps": self.collusion_threshold_bps,
            "liveness_delay_blocks": self.liveness_delay_blocks,
            "censorship_delay_blocks": self.censorship_delay_blocks,
            "reorg_depth": self.reorg_depth,
            "watcher_bond_root": self.watcher_bond_root,
            "slashing_reference_root": self.slashing_reference_root,
            "simulation_root": self.simulation_root,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("watcher_quorum_evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LivenessTimerRecord {
    pub timer_id: String,
    pub dispute_id: String,
    pub challenge_window_start: u64,
    pub challenge_window_end: u64,
    pub liveness_deadline: u64,
    pub censorship_deadline: u64,
    pub emergency_release_height: u64,
    pub challenge_window_elapsed: bool,
    pub liveness_expired: bool,
    pub censorship_expired: bool,
    pub emergency_release_ready: bool,
    pub timer_root: String,
}

impl LivenessTimerRecord {
    pub fn from_input(config: &Config, input: &ForcedExitDisputeInput) -> Self {
        let challenge_window_start = input.opened_at_height;
        let challenge_window_end =
            challenge_window_start.saturating_add(config.challenge_window_blocks);
        let liveness_deadline = input
            .last_watcher_progress_height
            .saturating_add(config.liveness_timeout_blocks);
        let censorship_deadline = input
            .last_sequencer_progress_height
            .saturating_add(config.censorship_timeout_blocks);
        let emergency_release_height =
            challenge_window_end.saturating_add(config.emergency_release_delay_blocks);
        let challenge_window_elapsed = config.current_height >= challenge_window_end;
        let liveness_expired = config.current_height >= liveness_deadline;
        let censorship_expired = config.current_height >= censorship_deadline;
        let emergency_release_ready = config.current_height >= emergency_release_height;
        let timer_root = liveness_timer_root(
            &input.dispute_id,
            challenge_window_start,
            challenge_window_end,
            liveness_deadline,
            censorship_deadline,
            emergency_release_height,
            bool_str(challenge_window_elapsed),
            bool_str(liveness_expired),
            bool_str(censorship_expired),
            bool_str(emergency_release_ready),
        );
        let timer_id = liveness_timer_id(&input.dispute_id, &timer_root);
        Self {
            timer_id,
            dispute_id: input.dispute_id.clone(),
            challenge_window_start,
            challenge_window_end,
            liveness_deadline,
            censorship_deadline,
            emergency_release_height,
            challenge_window_elapsed,
            liveness_expired,
            censorship_expired,
            emergency_release_ready,
            timer_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "timer_id": self.timer_id,
            "dispute_id": self.dispute_id,
            "challenge_window_start": self.challenge_window_start,
            "challenge_window_end": self.challenge_window_end,
            "liveness_deadline": self.liveness_deadline,
            "censorship_deadline": self.censorship_deadline,
            "emergency_release_height": self.emergency_release_height,
            "challenge_window_elapsed": self.challenge_window_elapsed,
            "liveness_expired": self.liveness_expired,
            "censorship_expired": self.censorship_expired,
            "emergency_release_ready": self.emergency_release_ready,
            "timer_root": self.timer_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("liveness_timer_record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EmergencyReleaseCondition {
    pub condition_id: String,
    pub dispute_id: String,
    pub release_claim_id: String,
    pub release_blocker_root: String,
    pub claim_queue_root: String,
    pub slashing_reference_root: String,
    pub challenge_window_elapsed: bool,
    pub liveness_expired: bool,
    pub censorship_expired: bool,
    pub quorum_met: bool,
    pub collusion_detected: bool,
    pub release_blocker_cleared: bool,
    pub slashing_reference_present: bool,
    pub emergency_release_allowed: bool,
    pub condition_root: String,
}

impl EmergencyReleaseCondition {
    pub fn from_parts(
        config: &Config,
        input: &ForcedExitDisputeInput,
        evidence: &WatcherQuorumEvidence,
        timer: &LivenessTimerRecord,
    ) -> Self {
        let collusion_detected = evidence.collusion_bps >= config.collusion_threshold_bps;
        let release_blocker_cleared = !config.release_blocker_clearing_required
            || input.release_blocker_root == labeled_root("cleared", &input.release_claim_id);
        let slashing_reference_present =
            !config.require_slashing_reference || input.slashing_reference_root.len() >= 32;
        let emergency_release_allowed = timer.challenge_window_elapsed
            && timer.emergency_release_ready
            && (timer.liveness_expired || timer.censorship_expired)
            && (!config.fail_closed_on_collusion || !collusion_detected)
            && release_blocker_cleared
            && slashing_reference_present;
        let condition_root = emergency_condition_root(
            &input.dispute_id,
            &input.release_claim_id,
            &input.release_blocker_root,
            &input.claim_queue_root,
            &input.slashing_reference_root,
            bool_str(timer.challenge_window_elapsed),
            bool_str(timer.liveness_expired),
            bool_str(timer.censorship_expired),
            bool_str(evidence.quorum_met),
            bool_str(collusion_detected),
            bool_str(release_blocker_cleared),
            bool_str(emergency_release_allowed),
        );
        let condition_id = emergency_condition_id(&input.release_claim_id, &condition_root);
        Self {
            condition_id,
            dispute_id: input.dispute_id.clone(),
            release_claim_id: input.release_claim_id.clone(),
            release_blocker_root: input.release_blocker_root.clone(),
            claim_queue_root: input.claim_queue_root.clone(),
            slashing_reference_root: input.slashing_reference_root.clone(),
            challenge_window_elapsed: timer.challenge_window_elapsed,
            liveness_expired: timer.liveness_expired,
            censorship_expired: timer.censorship_expired,
            quorum_met: evidence.quorum_met,
            collusion_detected,
            release_blocker_cleared,
            slashing_reference_present,
            emergency_release_allowed,
            condition_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "condition_id": self.condition_id,
            "dispute_id": self.dispute_id,
            "release_claim_id": self.release_claim_id,
            "release_blocker_root": self.release_blocker_root,
            "claim_queue_root": self.claim_queue_root,
            "slashing_reference_root": self.slashing_reference_root,
            "challenge_window_elapsed": self.challenge_window_elapsed,
            "liveness_expired": self.liveness_expired,
            "censorship_expired": self.censorship_expired,
            "quorum_met": self.quorum_met,
            "collusion_detected": self.collusion_detected,
            "release_blocker_cleared": self.release_blocker_cleared,
            "slashing_reference_present": self.slashing_reference_present,
            "emergency_release_allowed": self.emergency_release_allowed,
            "condition_root": self.condition_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("emergency_release_condition", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserEscapeOutcomeRoot {
    pub outcome_id: String,
    pub dispute_id: String,
    pub release_claim_id: String,
    pub user_escape_id: String,
    pub outcome: EscapeOutcome,
    pub escape_available_height: u64,
    pub escape_confirmed_height: u64,
    pub claim_queue_hold_root: String,
    pub release_blocker_clearance_root: String,
    pub user_escape_leaf_root: String,
    pub outcome_root: String,
}

impl UserEscapeOutcomeRoot {
    pub fn from_parts(
        config: &Config,
        input: &ForcedExitDisputeInput,
        condition: &EmergencyReleaseCondition,
        timer: &LivenessTimerRecord,
    ) -> Self {
        let escape_available_height = timer
            .emergency_release_height
            .saturating_add(config.escape_root_confirmations);
        let escape_confirmed_height = config.current_height.max(escape_available_height);
        let outcome = if condition.collusion_detected && config.fail_closed_on_collusion {
            EscapeOutcome::Quarantined
        } else if condition.emergency_release_allowed
            && config.current_height >= escape_available_height
        {
            EscapeOutcome::UserEscapeRoot
        } else if condition.emergency_release_allowed {
            EscapeOutcome::EmergencyRelease
        } else if timer.challenge_window_elapsed && condition.quorum_met {
            EscapeOutcome::ReleaseClaim
        } else {
            EscapeOutcome::NotReady
        };
        let claim_queue_hold_root = claim_queue_hold_root(
            &input.release_claim_id,
            &input.claim_queue_root,
            bool_str(config.claim_queue_hold_required),
            outcome.as_str(),
        );
        let release_blocker_clearance_root = release_blocker_clearance_root(
            &input.release_claim_id,
            &input.release_blocker_root,
            &condition.condition_root,
            bool_str(condition.release_blocker_cleared),
        );
        let outcome_root = user_escape_outcome_root(
            outcome,
            &input.dispute_id,
            &input.release_claim_id,
            &input.user_escape_id,
            escape_available_height,
            escape_confirmed_height,
            &claim_queue_hold_root,
            &release_blocker_clearance_root,
            &input.user_escape_leaf_root,
        );
        let outcome_id = user_escape_outcome_id(&input.user_escape_id, outcome, &outcome_root);
        Self {
            outcome_id,
            dispute_id: input.dispute_id.clone(),
            release_claim_id: input.release_claim_id.clone(),
            user_escape_id: input.user_escape_id.clone(),
            outcome,
            escape_available_height,
            escape_confirmed_height,
            claim_queue_hold_root,
            release_blocker_clearance_root,
            user_escape_leaf_root: input.user_escape_leaf_root.clone(),
            outcome_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "outcome_id": self.outcome_id,
            "dispute_id": self.dispute_id,
            "release_claim_id": self.release_claim_id,
            "user_escape_id": self.user_escape_id,
            "outcome": self.outcome,
            "escape_available_height": self.escape_available_height,
            "escape_confirmed_height": self.escape_confirmed_height,
            "claim_queue_hold_root": self.claim_queue_hold_root,
            "release_blocker_clearance_root": self.release_blocker_clearance_root,
            "user_escape_leaf_root": self.user_escape_leaf_root,
            "outcome_root": self.outcome_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("user_escape_outcome_root", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ArbitrationCase {
    pub case_id: String,
    pub trigger: ArbitrationTrigger,
    pub status: ArbitrationStatus,
    pub dispute_input: ForcedExitDisputeInput,
    pub watcher_evidence: WatcherQuorumEvidence,
    pub liveness_timer: LivenessTimerRecord,
    pub emergency_condition: EmergencyReleaseCondition,
    pub user_escape_outcome: UserEscapeOutcomeRoot,
    pub blocker_root: String,
    pub slashing_root: String,
    pub case_root: String,
}

impl ArbitrationCase {
    pub fn from_input(config: &Config, input: ForcedExitDisputeInput) -> Self {
        let watcher_evidence = WatcherQuorumEvidence::from_input(config, &input);
        let liveness_timer = LivenessTimerRecord::from_input(config, &input);
        let emergency_condition = EmergencyReleaseCondition::from_parts(
            config,
            &input,
            &watcher_evidence,
            &liveness_timer,
        );
        let user_escape_outcome = UserEscapeOutcomeRoot::from_parts(
            config,
            &input,
            &emergency_condition,
            &liveness_timer,
        );
        let trigger = arbitration_trigger(&watcher_evidence, &liveness_timer, &emergency_condition);
        let status = arbitration_status(&watcher_evidence, &liveness_timer, &emergency_condition);
        let blocker_root = arbitration_blocker_root(
            status,
            &input.release_blocker_root,
            &emergency_condition.condition_root,
            &user_escape_outcome.outcome_root,
        );
        let slashing_root = arbitration_slashing_reference_root(
            trigger,
            &input.slashing_reference_root,
            &watcher_evidence.evidence_root,
            &input.watcher_bond_root,
        );
        let case_root = arbitration_case_root(
            trigger,
            status,
            &input.dispute_id,
            &input.release_claim_id,
            &watcher_evidence.evidence_root,
            &liveness_timer.timer_root,
            &emergency_condition.condition_root,
            &user_escape_outcome.outcome_root,
            &blocker_root,
            &slashing_root,
        );
        let case_id = arbitration_case_id(&input.dispute_id, trigger, &case_root);
        Self {
            case_id,
            trigger,
            status,
            dispute_input: input,
            watcher_evidence,
            liveness_timer,
            emergency_condition,
            user_escape_outcome,
            blocker_root,
            slashing_root,
            case_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "trigger": self.trigger,
            "status": self.status,
            "dispute_input": self.dispute_input.public_record(),
            "watcher_evidence": self.watcher_evidence.public_record(),
            "liveness_timer": self.liveness_timer.public_record(),
            "emergency_condition": self.emergency_condition.public_record(),
            "user_escape_outcome": self.user_escape_outcome.public_record(),
            "blocker_root": self.blocker_root,
            "slashing_root": self.slashing_root,
            "case_root": self.case_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("arbitration_case", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ArbitrationReport {
    pub report_id: String,
    pub status: ArbitrationReportStatus,
    pub readiness_label: String,
    pub case_count: u64,
    pub open_count: u64,
    pub blocked_count: u64,
    pub emergency_ready_count: u64,
    pub user_escape_count: u64,
    pub collusion_count: u64,
    pub source_root: String,
    pub case_root: String,
    pub evidence_root: String,
    pub timer_root: String,
    pub condition_root: String,
    pub outcome_root: String,
    pub blocker_root: String,
    pub slashing_root: String,
    pub report_root: String,
}

impl ArbitrationReport {
    pub fn from_cases(config: &Config, cases: &[ArbitrationCase]) -> Self {
        let counters = arbitration_counters(cases);
        let status = report_status(config, cases.len() as u64, &counters);
        let readiness_label = readiness_label(status, &counters).to_string();
        let case_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-CASE-MERKLE",
            &cases
                .iter()
                .map(ArbitrationCase::public_record)
                .collect::<Vec<_>>(),
        );
        let evidence_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-EVIDENCE-MERKLE",
            &cases
                .iter()
                .map(|case| case.watcher_evidence.public_record())
                .collect::<Vec<_>>(),
        );
        let timer_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-TIMER-MERKLE",
            &cases
                .iter()
                .map(|case| case.liveness_timer.public_record())
                .collect::<Vec<_>>(),
        );
        let condition_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-CONDITION-MERKLE",
            &cases
                .iter()
                .map(|case| case.emergency_condition.public_record())
                .collect::<Vec<_>>(),
        );
        let outcome_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-OUTCOME-MERKLE",
            &cases
                .iter()
                .map(|case| case.user_escape_outcome.public_record())
                .collect::<Vec<_>>(),
        );
        let blocker_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-BLOCKER-MERKLE",
            &cases
                .iter()
                .map(|case| json!({"case_id": case.case_id, "blocker_root": case.blocker_root}))
                .collect::<Vec<_>>(),
        );
        let slashing_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-SLASHING-MERKLE",
            &cases
                .iter()
                .map(|case| json!({"case_id": case.case_id, "slashing_root": case.slashing_root}))
                .collect::<Vec<_>>(),
        );
        let source_root = arbitration_source_root(
            &config.state_root(),
            &case_root,
            &evidence_root,
            &timer_root,
            &condition_root,
            &outcome_root,
            &blocker_root,
            &slashing_root,
        );
        let report_root = arbitration_report_root(
            status,
            &readiness_label,
            counters.case_count,
            counters.blocked_count,
            counters.user_escape_count,
            &source_root,
            &case_root,
            &outcome_root,
        );
        let report_id = arbitration_report_id(&config.chain_id, &report_root);
        Self {
            report_id,
            status,
            readiness_label,
            case_count: counters.case_count,
            open_count: counters.open_count,
            blocked_count: counters.blocked_count,
            emergency_ready_count: counters.emergency_ready_count,
            user_escape_count: counters.user_escape_count,
            collusion_count: counters.collusion_count,
            source_root,
            case_root,
            evidence_root,
            timer_root,
            condition_root,
            outcome_root,
            blocker_root,
            slashing_root,
            report_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "status": self.status,
            "readiness_label": self.readiness_label,
            "case_count": self.case_count,
            "open_count": self.open_count,
            "blocked_count": self.blocked_count,
            "emergency_ready_count": self.emergency_ready_count,
            "user_escape_count": self.user_escape_count,
            "collusion_count": self.collusion_count,
            "source_root": self.source_root,
            "case_root": self.case_root,
            "evidence_root": self.evidence_root,
            "timer_root": self.timer_root,
            "condition_root": self.condition_root,
            "outcome_root": self.outcome_root,
            "blocker_root": self.blocker_root,
            "slashing_root": self.slashing_root,
            "report_root": self.report_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("arbitration_report", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub cases: BTreeMap<String, ArbitrationCase>,
    pub report: ArbitrationReport,
}

impl State {
    pub fn new(config: Config, inputs: Vec<ForcedExitDisputeInput>) -> Result<Self> {
        ensure(
            config.collusion_threshold_bps <= MAX_BPS,
            "collusion threshold exceeds max bps",
        )?;
        ensure(
            config.min_watcher_quorum > 0,
            "watcher quorum must be nonzero",
        )?;
        ensure(
            inputs.len() <= config.max_cases,
            "too many arbitration inputs",
        )?;
        let mut cases = BTreeMap::new();
        for input in inputs {
            let case = ArbitrationCase::from_input(&config, input);
            cases.insert(case.case_id.clone(), case);
        }
        let case_values = cases.values().cloned().collect::<Vec<_>>();
        let report = ArbitrationReport::from_cases(&config, &case_values);
        Ok(Self {
            config,
            cases,
            report,
        })
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet(), devnet_inputs()).unwrap_or_else(empty_devnet_state)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "cases": self.cases.values().map(ArbitrationCase::public_record).collect::<Vec<_>>(),
            "report": self.report.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
    }

    pub fn counters(&self) -> BTreeMap<String, u64> {
        let counters = arbitration_counters(&self.cases.values().cloned().collect::<Vec<_>>());
        BTreeMap::from([
            ("case_count".to_string(), counters.case_count),
            ("open_count".to_string(), counters.open_count),
            ("blocked_count".to_string(), counters.blocked_count),
            (
                "emergency_ready_count".to_string(),
                counters.emergency_ready_count,
            ),
            ("user_escape_count".to_string(), counters.user_escape_count),
            ("collusion_count".to_string(), counters.collusion_count),
        ])
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ArbitrationCounters {
    pub case_count: u64,
    pub open_count: u64,
    pub blocked_count: u64,
    pub emergency_ready_count: u64,
    pub user_escape_count: u64,
    pub collusion_count: u64,
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

pub fn devnet_inputs() -> Vec<ForcedExitDisputeInput> {
    let cleared = labeled_root("cleared", "release-claim-devnet-001");
    vec![
        ForcedExitDisputeInput {
            dispute_id: "dispute-sequencer-liveness-001".to_string(),
            release_claim_id: "release-claim-devnet-001".to_string(),
            transfer_id: "forced-exit-transfer-001".to_string(),
            user_escape_id: "user-escape-001".to_string(),
            opened_at_height: 4_198_800,
            last_sequencer_progress_height: 4_198_880,
            last_watcher_progress_height: 4_198_920,
            watcher_votes: 5,
            watcher_total: 7,
            collusion_bps: 1_250,
            censorship_reports: 2,
            reorg_depth: 2,
            claim_queue_root: labeled_root("claim-queue", "release-claim-devnet-001"),
            release_blocker_root: cleared,
            slashing_reference_root: labeled_root("slashing-reference", "release-claim-devnet-001"),
            reorg_collusion_simulation_root: labeled_root(
                "reorg-collusion-simulation",
                "release-claim-devnet-001",
            ),
            watcher_bond_root: labeled_root("watcher-bond", "release-claim-devnet-001"),
            user_escape_leaf_root: labeled_root("escape-leaf", "release-claim-devnet-001"),
        },
        ForcedExitDisputeInput {
            dispute_id: "dispute-collusion-002".to_string(),
            release_claim_id: "release-claim-devnet-002".to_string(),
            transfer_id: "forced-exit-transfer-002".to_string(),
            user_escape_id: "user-escape-002".to_string(),
            opened_at_height: 4_199_960,
            last_sequencer_progress_height: 4_200_100,
            last_watcher_progress_height: 4_200_080,
            watcher_votes: 4,
            watcher_total: 7,
            collusion_bps: 7_500,
            censorship_reports: 1,
            reorg_depth: 8,
            claim_queue_root: labeled_root("claim-queue", "release-claim-devnet-002"),
            release_blocker_root: labeled_root("blocked", "release-claim-devnet-002"),
            slashing_reference_root: labeled_root("slashing-reference", "release-claim-devnet-002"),
            reorg_collusion_simulation_root: labeled_root(
                "reorg-collusion-simulation",
                "release-claim-devnet-002",
            ),
            watcher_bond_root: labeled_root("watcher-bond", "release-claim-devnet-002"),
            user_escape_leaf_root: labeled_root("escape-leaf", "release-claim-devnet-002"),
        },
        ForcedExitDisputeInput {
            dispute_id: "dispute-censorship-003".to_string(),
            release_claim_id: "release-claim-devnet-003".to_string(),
            transfer_id: "forced-exit-transfer-003".to_string(),
            user_escape_id: "user-escape-003".to_string(),
            opened_at_height: 4_199_700,
            last_sequencer_progress_height: 4_199_720,
            last_watcher_progress_height: 4_200_300,
            watcher_votes: 6,
            watcher_total: 8,
            collusion_bps: 500,
            censorship_reports: 5,
            reorg_depth: 0,
            claim_queue_root: labeled_root("claim-queue", "release-claim-devnet-003"),
            release_blocker_root: labeled_root("cleared", "release-claim-devnet-003"),
            slashing_reference_root: labeled_root("slashing-reference", "release-claim-devnet-003"),
            reorg_collusion_simulation_root: labeled_root(
                "reorg-collusion-simulation",
                "release-claim-devnet-003",
            ),
            watcher_bond_root: labeled_root("watcher-bond", "release-claim-devnet-003"),
            user_escape_leaf_root: labeled_root("escape-leaf", "release-claim-devnet-003"),
        },
    ]
}

pub fn watcher_evidence_kind(
    config: &Config,
    quorum_met: bool,
    collusion_bps: u64,
    liveness_delay_blocks: u64,
    censorship_delay_blocks: u64,
    reorg_depth: u64,
) -> WatcherEvidenceKind {
    if collusion_bps >= config.collusion_threshold_bps {
        WatcherEvidenceKind::CollusionBundle
    } else if !quorum_met {
        WatcherEvidenceKind::MissingQuorum
    } else if censorship_delay_blocks >= config.censorship_timeout_blocks {
        WatcherEvidenceKind::CensorshipReceipt
    } else if liveness_delay_blocks >= config.liveness_timeout_blocks {
        WatcherEvidenceKind::WithheldLivenessProof
    } else if reorg_depth > 0 {
        WatcherEvidenceKind::ReorgMismatch
    } else {
        WatcherEvidenceKind::HonestQuorum
    }
}

pub fn arbitration_trigger(
    evidence: &WatcherQuorumEvidence,
    timer: &LivenessTimerRecord,
    condition: &EmergencyReleaseCondition,
) -> ArbitrationTrigger {
    if condition.emergency_release_allowed {
        ArbitrationTrigger::EmergencyUserEscape
    } else if evidence.collusion_bps >= evidence.collusion_threshold_bps {
        ArbitrationTrigger::WatcherCollusionEvidence
    } else if !evidence.quorum_met {
        ArbitrationTrigger::WatcherQuorumFailure
    } else if timer.censorship_expired {
        ArbitrationTrigger::CensorshipTimerExpired
    } else if timer.liveness_expired {
        ArbitrationTrigger::SequencerLivenessFailure
    } else if !timer.challenge_window_elapsed {
        ArbitrationTrigger::ChallengeWindowDispute
    } else if !condition.release_blocker_cleared {
        ArbitrationTrigger::ReleaseBlockerOverride
    } else {
        ArbitrationTrigger::SlashingSettlementReference
    }
}

pub fn arbitration_status(
    evidence: &WatcherQuorumEvidence,
    timer: &LivenessTimerRecord,
    condition: &EmergencyReleaseCondition,
) -> ArbitrationStatus {
    if condition.collusion_detected {
        ArbitrationStatus::ReleaseBlocked
    } else if condition.emergency_release_allowed {
        ArbitrationStatus::EmergencyReleaseReady
    } else if !evidence.quorum_met {
        ArbitrationStatus::QuorumPending
    } else if !timer.challenge_window_elapsed {
        ArbitrationStatus::ChallengeWindowActive
    } else if !condition.release_blocker_cleared {
        ArbitrationStatus::ReleaseBlocked
    } else if timer.liveness_expired || timer.censorship_expired {
        ArbitrationStatus::UserEscapeApproved
    } else {
        ArbitrationStatus::Open
    }
}

pub fn arbitration_counters(cases: &[ArbitrationCase]) -> ArbitrationCounters {
    let mut counters = ArbitrationCounters {
        case_count: cases.len() as u64,
        open_count: 0,
        blocked_count: 0,
        emergency_ready_count: 0,
        user_escape_count: 0,
        collusion_count: 0,
    };
    for case in cases {
        if matches!(
            case.status,
            ArbitrationStatus::Open | ArbitrationStatus::ChallengeWindowActive
        ) {
            counters.open_count = counters.open_count.saturating_add(1);
        }
        if matches!(
            case.status,
            ArbitrationStatus::ReleaseBlocked | ArbitrationStatus::Rejected
        ) {
            counters.blocked_count = counters.blocked_count.saturating_add(1);
        }
        if matches!(case.status, ArbitrationStatus::EmergencyReleaseReady) {
            counters.emergency_ready_count = counters.emergency_ready_count.saturating_add(1);
        }
        if matches!(
            case.user_escape_outcome.outcome,
            EscapeOutcome::EmergencyRelease | EscapeOutcome::UserEscapeRoot
        ) {
            counters.user_escape_count = counters.user_escape_count.saturating_add(1);
        }
        if case.emergency_condition.collusion_detected {
            counters.collusion_count = counters.collusion_count.saturating_add(1);
        }
    }
    counters
}

pub fn report_status(
    config: &Config,
    case_count: u64,
    counters: &ArbitrationCounters,
) -> ArbitrationReportStatus {
    if case_count < config.min_arbitrations || counters.blocked_count > 0 {
        ArbitrationReportStatus::Failed
    } else if counters.open_count > 0 || counters.collusion_count > 0 {
        ArbitrationReportStatus::Watch
    } else {
        ArbitrationReportStatus::Passed
    }
}

pub fn readiness_label(
    status: ArbitrationReportStatus,
    counters: &ArbitrationCounters,
) -> &'static str {
    match status {
        ArbitrationReportStatus::Passed => "arbitration_ready",
        ArbitrationReportStatus::Watch if counters.emergency_ready_count > 0 => {
            "emergency_release_watch"
        }
        ArbitrationReportStatus::Watch => "liveness_watch",
        ArbitrationReportStatus::Failed if counters.blocked_count > 0 => {
            "release_blocked_or_colluding"
        }
        ArbitrationReportStatus::Failed => "insufficient_arbitration_coverage",
    }
}

#[allow(clippy::too_many_arguments)]
pub fn watcher_evidence_root(
    kind: WatcherEvidenceKind,
    dispute_id: &str,
    watcher_votes: u64,
    watcher_total: u64,
    collusion_bps: u64,
    liveness_delay_blocks: u64,
    censorship_delay_blocks: u64,
    watcher_bond_root: &str,
    slashing_reference_root: &str,
    simulation_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-WATCHER-EVIDENCE",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(dispute_id),
            HashPart::U64(watcher_votes),
            HashPart::U64(watcher_total),
            HashPart::U64(collusion_bps),
            HashPart::U64(liveness_delay_blocks),
            HashPart::U64(censorship_delay_blocks),
            HashPart::Str(watcher_bond_root),
            HashPart::Str(slashing_reference_root),
            HashPart::Str(simulation_root),
        ],
        32,
    )
}

pub fn watcher_evidence_id(
    dispute_id: &str,
    kind: WatcherEvidenceKind,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-WATCHER-EVIDENCE-ID",
        &[
            HashPart::Str(dispute_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn liveness_timer_root(
    dispute_id: &str,
    challenge_window_start: u64,
    challenge_window_end: u64,
    liveness_deadline: u64,
    censorship_deadline: u64,
    emergency_release_height: u64,
    challenge_window_elapsed: &str,
    liveness_expired: &str,
    censorship_expired: &str,
    emergency_release_ready: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-TIMER",
        &[
            HashPart::Str(dispute_id),
            HashPart::U64(challenge_window_start),
            HashPart::U64(challenge_window_end),
            HashPart::U64(liveness_deadline),
            HashPart::U64(censorship_deadline),
            HashPart::U64(emergency_release_height),
            HashPart::Str(challenge_window_elapsed),
            HashPart::Str(liveness_expired),
            HashPart::Str(censorship_expired),
            HashPart::Str(emergency_release_ready),
        ],
        32,
    )
}

pub fn liveness_timer_id(dispute_id: &str, timer_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-TIMER-ID",
        &[HashPart::Str(dispute_id), HashPart::Str(timer_root)],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn emergency_condition_root(
    dispute_id: &str,
    release_claim_id: &str,
    release_blocker_root: &str,
    claim_queue_root: &str,
    slashing_reference_root: &str,
    challenge_window_elapsed: &str,
    liveness_expired: &str,
    censorship_expired: &str,
    quorum_met: &str,
    collusion_detected: &str,
    release_blocker_cleared: &str,
    emergency_release_allowed: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-EMERGENCY-CONDITION",
        &[
            HashPart::Str(dispute_id),
            HashPart::Str(release_claim_id),
            HashPart::Str(release_blocker_root),
            HashPart::Str(claim_queue_root),
            HashPart::Str(slashing_reference_root),
            HashPart::Str(challenge_window_elapsed),
            HashPart::Str(liveness_expired),
            HashPart::Str(censorship_expired),
            HashPart::Str(quorum_met),
            HashPart::Str(collusion_detected),
            HashPart::Str(release_blocker_cleared),
            HashPart::Str(emergency_release_allowed),
        ],
        32,
    )
}

pub fn emergency_condition_id(release_claim_id: &str, condition_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-EMERGENCY-CONDITION-ID",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(condition_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn user_escape_outcome_root(
    outcome: EscapeOutcome,
    dispute_id: &str,
    release_claim_id: &str,
    user_escape_id: &str,
    escape_available_height: u64,
    escape_confirmed_height: u64,
    claim_queue_hold_root: &str,
    release_blocker_clearance_root: &str,
    user_escape_leaf_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-USER-ESCAPE-OUTCOME",
        &[
            HashPart::Str(outcome.as_str()),
            HashPart::Str(dispute_id),
            HashPart::Str(release_claim_id),
            HashPart::Str(user_escape_id),
            HashPart::U64(escape_available_height),
            HashPart::U64(escape_confirmed_height),
            HashPart::Str(claim_queue_hold_root),
            HashPart::Str(release_blocker_clearance_root),
            HashPart::Str(user_escape_leaf_root),
        ],
        32,
    )
}

pub fn user_escape_outcome_id(
    user_escape_id: &str,
    outcome: EscapeOutcome,
    outcome_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-USER-ESCAPE-OUTCOME-ID",
        &[
            HashPart::Str(user_escape_id),
            HashPart::Str(outcome.as_str()),
            HashPart::Str(outcome_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn arbitration_case_root(
    trigger: ArbitrationTrigger,
    status: ArbitrationStatus,
    dispute_id: &str,
    release_claim_id: &str,
    evidence_root: &str,
    timer_root: &str,
    condition_root: &str,
    outcome_root: &str,
    blocker_root: &str,
    slashing_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-CASE",
        &[
            HashPart::Str(trigger.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(dispute_id),
            HashPart::Str(release_claim_id),
            HashPart::Str(evidence_root),
            HashPart::Str(timer_root),
            HashPart::Str(condition_root),
            HashPart::Str(outcome_root),
            HashPart::Str(blocker_root),
            HashPart::Str(slashing_root),
        ],
        32,
    )
}

pub fn arbitration_case_id(
    dispute_id: &str,
    trigger: ArbitrationTrigger,
    case_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-CASE-ID",
        &[
            HashPart::Str(dispute_id),
            HashPart::Str(trigger.as_str()),
            HashPart::Str(case_root),
        ],
        32,
    )
}

pub fn arbitration_blocker_root(
    status: ArbitrationStatus,
    release_blocker_root: &str,
    condition_root: &str,
    outcome_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-BLOCKER-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(release_blocker_root),
            HashPart::Str(condition_root),
            HashPart::Str(outcome_root),
        ],
        32,
    )
}

pub fn arbitration_slashing_reference_root(
    trigger: ArbitrationTrigger,
    slashing_reference_root: &str,
    evidence_root: &str,
    watcher_bond_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-SLASHING-REFERENCE",
        &[
            HashPart::Str(trigger.as_str()),
            HashPart::Str(slashing_reference_root),
            HashPart::Str(evidence_root),
            HashPart::Str(watcher_bond_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn arbitration_source_root(
    config_root: &str,
    case_root: &str,
    evidence_root: &str,
    timer_root: &str,
    condition_root: &str,
    outcome_root: &str,
    blocker_root: &str,
    slashing_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-SOURCE",
        &[
            HashPart::Str(config_root),
            HashPart::Str(case_root),
            HashPart::Str(evidence_root),
            HashPart::Str(timer_root),
            HashPart::Str(condition_root),
            HashPart::Str(outcome_root),
            HashPart::Str(blocker_root),
            HashPart::Str(slashing_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn arbitration_report_root(
    status: ArbitrationReportStatus,
    readiness_label: &str,
    case_count: u64,
    blocked_count: u64,
    user_escape_count: u64,
    source_root: &str,
    case_root: &str,
    outcome_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-REPORT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::U64(case_count),
            HashPart::U64(blocked_count),
            HashPart::U64(user_escape_count),
            HashPart::Str(source_root),
            HashPart::Str(case_root),
            HashPart::Str(outcome_root),
        ],
        32,
    )
}

pub fn arbitration_report_id(chain_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-REPORT-ID",
        &[HashPart::Str(chain_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn claim_queue_hold_root(
    release_claim_id: &str,
    claim_queue_root: &str,
    hold_required: &str,
    outcome: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-CLAIM-QUEUE-HOLD",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(claim_queue_root),
            HashPart::Str(hold_required),
            HashPart::Str(outcome),
        ],
        32,
    )
}

pub fn release_blocker_clearance_root(
    release_claim_id: &str,
    release_blocker_root: &str,
    condition_root: &str,
    cleared: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-RELEASE-BLOCKER-CLEARANCE",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(release_blocker_root),
            HashPart::Str(condition_root),
            HashPart::Str(cleared),
        ],
        32,
    )
}

pub fn labeled_root(label: &str, seed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-LABELED-ROOT",
        &[HashPart::Str(label), HashPart::Str(seed)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DISPUTE-LIVENESS-ARBITRATION-RECORD",
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

fn empty_devnet_state(error: String) -> State {
    let config = Config::devnet();
    let report_root = record_root("empty_devnet_error", &json!({ "error": error }));
    let report = ArbitrationReport {
        report_id: arbitration_report_id(&config.chain_id, &report_root),
        status: ArbitrationReportStatus::Failed,
        readiness_label: "empty_devnet_error".to_string(),
        case_count: 0,
        open_count: 0,
        blocked_count: 0,
        emergency_ready_count: 0,
        user_escape_count: 0,
        collusion_count: 0,
        source_root: report_root.clone(),
        case_root: report_root.clone(),
        evidence_root: report_root.clone(),
        timer_root: report_root.clone(),
        condition_root: report_root.clone(),
        outcome_root: report_root.clone(),
        blocker_root: report_root.clone(),
        slashing_root: report_root.clone(),
        report_root,
    };
    State {
        config,
        cases: BTreeMap::new(),
        report,
    }
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
