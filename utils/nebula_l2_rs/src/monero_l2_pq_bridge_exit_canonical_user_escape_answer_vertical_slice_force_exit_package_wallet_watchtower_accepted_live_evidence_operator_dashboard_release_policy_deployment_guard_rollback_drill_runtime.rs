use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageWalletWatchtowerAcceptedLiveEvidenceOperatorDashboardReleasePolicyDeploymentGuardRollbackDrillRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_WALLET_WATCHTOWER_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-wallet-watchtower-accepted-live-evidence-operator-dashboard-release-policy-deployment-guard-rollback-drill-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_WALLET_WATCHTOWER_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ROLLBACK_DRILL_SUITE: &str = "wallet-watchtower-deployment-guard-rollback-drill-v1";
pub const DEFAULT_HEIGHT: u64 = 4_280_672;
pub const DEFAULT_WAVE84_HEIGHT: u64 = 4_280_640;
pub const DEFAULT_DRILL_WINDOW_START: u64 = 4_280_656;
pub const DEFAULT_DRILL_WINDOW_END: u64 = 4_280_720;
pub const DEFAULT_MIN_OPERATOR_ACKS: u16 = 2;
pub const DEFAULT_MIN_WALLET_TRANSCRIPTS: u16 = 2;
pub const DEFAULT_MIN_WATCHTOWER_REPLAYS: u16 = 2;
pub const DEFAULT_MIN_ESCAPE_CONFIRMATIONS: u16 = 2;
pub const DEFAULT_MAX_TRANSCRIPT_AGE_BLOCKS: u64 = 64;
pub const DEFAULT_MAX_REPLAY_AGE_BLOCKS: u64 = 32;
pub const DEFAULT_ABORT_CONFIRMATIONS: u64 = 12;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillLane {
    Wave84DeploymentGuard,
    WalletRollbackTranscript,
    WatchtowerAbortReplay,
    UserEscapeHoldUnhold,
    OperatorAcknowledgement,
    ReleaseFailClosed,
    RollbackVerdict,
}

impl DrillLane {
    pub fn all() -> Vec<Self> {
        vec![
            Self::Wave84DeploymentGuard,
            Self::WalletRollbackTranscript,
            Self::WatchtowerAbortReplay,
            Self::UserEscapeHoldUnhold,
            Self::OperatorAcknowledgement,
            Self::ReleaseFailClosed,
            Self::RollbackVerdict,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wave84DeploymentGuard => "wave84_deployment_guard",
            Self::WalletRollbackTranscript => "wallet_rollback_transcript",
            Self::WatchtowerAbortReplay => "watchtower_abort_replay",
            Self::UserEscapeHoldUnhold => "user_escape_hold_unhold",
            Self::OperatorAcknowledgement => "operator_acknowledgement",
            Self::ReleaseFailClosed => "release_fail_closed",
            Self::RollbackVerdict => "rollback_verdict",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Accepted,
    Warning,
    Missing,
    Rejected,
    Stale,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Warning => "warning",
            Self::Missing => "missing",
            Self::Rejected => "rejected",
            Self::Stale => "stale",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Accepted | Self::Warning)
    }

    pub fn blocks(self) -> bool {
        matches!(self, Self::Missing | Self::Rejected | Self::Stale)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStepKind {
    SnapshotDeploymentGuard,
    HoldWalletRelease,
    RewindWalletTranscript,
    AbortWatchtowerReplay,
    ReplayWatchtowerCheckpoint,
    ConfirmUserEscapeHold,
    ConfirmUserEscapeUnhold,
    OperatorAcknowledge,
    ReleaseHold,
    ReleaseUnhold,
}

impl RollbackStepKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SnapshotDeploymentGuard => "snapshot_deployment_guard",
            Self::HoldWalletRelease => "hold_wallet_release",
            Self::RewindWalletTranscript => "rewind_wallet_transcript",
            Self::AbortWatchtowerReplay => "abort_watchtower_replay",
            Self::ReplayWatchtowerCheckpoint => "replay_watchtower_checkpoint",
            Self::ConfirmUserEscapeHold => "confirm_user_escape_hold",
            Self::ConfirmUserEscapeUnhold => "confirm_user_escape_unhold",
            Self::OperatorAcknowledge => "operator_acknowledge",
            Self::ReleaseHold => "release_hold",
            Self::ReleaseUnhold => "release_unhold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserEscapeActionKind {
    HoldEscapeWindow,
    PublishHoldNotice,
    ConfirmExitPackageAvailable,
    FreezeWalletSpendPath,
    UnholdEscapeWindow,
    PublishUnholdNotice,
}

impl UserEscapeActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HoldEscapeWindow => "hold_escape_window",
            Self::PublishHoldNotice => "publish_hold_notice",
            Self::ConfirmExitPackageAvailable => "confirm_exit_package_available",
            Self::FreezeWalletSpendPath => "freeze_wallet_spend_path",
            Self::UnholdEscapeWindow => "unhold_escape_window",
            Self::PublishUnholdNotice => "publish_unhold_notice",
        }
    }

    pub fn is_hold(self) -> bool {
        matches!(
            self,
            Self::HoldEscapeWindow
                | Self::PublishHoldNotice
                | Self::ConfirmExitPackageAvailable
                | Self::FreezeWalletSpendPath
        )
    }

    pub fn is_unhold(self) -> bool {
        matches!(self, Self::UnholdEscapeWindow | Self::PublishUnholdNotice)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchtowerRollbackKind {
    AbortPendingReplay,
    RewindCheckpoint,
    ReplayAcceptedEvidence,
    SealAbortRoot,
    SealReplayRoot,
}

impl WatchtowerRollbackKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AbortPendingReplay => "abort_pending_replay",
            Self::RewindCheckpoint => "rewind_checkpoint",
            Self::ReplayAcceptedEvidence => "replay_accepted_evidence",
            Self::SealAbortRoot => "seal_abort_root",
            Self::SealReplayRoot => "seal_replay_root",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseHoldState {
    Held,
    UnholdCandidate,
    Unheld,
    FailClosed,
}

impl ReleaseHoldState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::UnholdCandidate => "unhold_candidate",
            Self::Unheld => "unheld",
            Self::FailClosed => "fail_closed",
        }
    }

    pub fn deployment_allowed(self) -> bool {
        matches!(self, Self::Unheld)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorAckKind {
    WalletRollbackReviewed,
    WatchtowerAbortReviewed,
    UserEscapeReviewed,
    FailClosedReviewed,
    ReleaseUnholdReviewed,
}

impl OperatorAckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRollbackReviewed => "wallet_rollback_reviewed",
            Self::WatchtowerAbortReviewed => "watchtower_abort_reviewed",
            Self::UserEscapeReviewed => "user_escape_reviewed",
            Self::FailClosedReviewed => "fail_closed_reviewed",
            Self::ReleaseUnholdReviewed => "release_unhold_reviewed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillBlockerKind {
    MissingWave84Root,
    MissingWalletTranscript,
    StaleWalletTranscript,
    WalletRollbackMismatch,
    MissingWatchtowerAbortRoot,
    MissingWatchtowerReplayRoot,
    StaleWatchtowerReplay,
    MissingUserEscapeHold,
    MissingUserEscapeUnhold,
    OperatorAcknowledgementMissing,
    ReleaseHoldNotFailClosed,
    ReleaseUnholdWithoutQuorum,
    AbortConfirmationTooLow,
}

impl DrillBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingWave84Root => "missing_wave84_root",
            Self::MissingWalletTranscript => "missing_wallet_transcript",
            Self::StaleWalletTranscript => "stale_wallet_transcript",
            Self::WalletRollbackMismatch => "wallet_rollback_mismatch",
            Self::MissingWatchtowerAbortRoot => "missing_watchtower_abort_root",
            Self::MissingWatchtowerReplayRoot => "missing_watchtower_replay_root",
            Self::StaleWatchtowerReplay => "stale_watchtower_replay",
            Self::MissingUserEscapeHold => "missing_user_escape_hold",
            Self::MissingUserEscapeUnhold => "missing_user_escape_unhold",
            Self::OperatorAcknowledgementMissing => "operator_acknowledgement_missing",
            Self::ReleaseHoldNotFailClosed => "release_hold_not_fail_closed",
            Self::ReleaseUnholdWithoutQuorum => "release_unhold_without_quorum",
            Self::AbortConfirmationTooLow => "abort_confirmation_too_low",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillDecisionKind {
    DrillAccepted,
    HoldRelease,
    ContinueFailClosed,
    AbortRollback,
}

impl DrillDecisionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DrillAccepted => "drill_accepted",
            Self::HoldRelease => "hold_release",
            Self::ContinueFailClosed => "continue_fail_closed",
            Self::AbortRollback => "abort_rollback",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::DrillAccepted)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub rollback_drill_suite: String,
    pub current_height: u64,
    pub wave84_height: u64,
    pub drill_window_start: u64,
    pub drill_window_end: u64,
    pub min_operator_acks: u16,
    pub min_wallet_transcripts: u16,
    pub min_watchtower_replays: u16,
    pub min_escape_confirmations: u16,
    pub max_transcript_age_blocks: u64,
    pub max_replay_age_blocks: u64,
    pub min_abort_confirmations: u64,
    pub require_fail_closed_hold: bool,
    pub require_unhold_after_fail_closed: bool,
    pub require_wave84_root_match: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            rollback_drill_suite: ROLLBACK_DRILL_SUITE.to_string(),
            current_height: DEFAULT_HEIGHT,
            wave84_height: DEFAULT_WAVE84_HEIGHT,
            drill_window_start: DEFAULT_DRILL_WINDOW_START,
            drill_window_end: DEFAULT_DRILL_WINDOW_END,
            min_operator_acks: DEFAULT_MIN_OPERATOR_ACKS,
            min_wallet_transcripts: DEFAULT_MIN_WALLET_TRANSCRIPTS,
            min_watchtower_replays: DEFAULT_MIN_WATCHTOWER_REPLAYS,
            min_escape_confirmations: DEFAULT_MIN_ESCAPE_CONFIRMATIONS,
            max_transcript_age_blocks: DEFAULT_MAX_TRANSCRIPT_AGE_BLOCKS,
            max_replay_age_blocks: DEFAULT_MAX_REPLAY_AGE_BLOCKS,
            min_abort_confirmations: DEFAULT_ABORT_CONFIRMATIONS,
            require_fail_closed_hold: true,
            require_unhold_after_fail_closed: true,
            require_wave84_root_match: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("hash_suite", &self.hash_suite)?;
        ensure_non_empty("rollback_drill_suite", &self.rollback_drill_suite)?;
        ensure(
            self.drill_window_start <= self.current_height,
            "drill window must have started",
        )?;
        ensure(
            self.current_height <= self.drill_window_end,
            "drill window must still be open",
        )?;
        ensure(
            self.wave84_height <= self.current_height,
            "wave84 height cannot exceed current height",
        )?;
        ensure(
            self.min_operator_acks > 0,
            "minimum operator acknowledgements must be positive",
        )?;
        ensure(
            self.min_wallet_transcripts > 0,
            "minimum wallet transcripts must be positive",
        )?;
        ensure(
            self.min_watchtower_replays > 0,
            "minimum watchtower replays must be positive",
        )?;
        ensure(
            self.min_escape_confirmations > 0,
            "minimum escape confirmations must be positive",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "rollback_drill_suite": self.rollback_drill_suite,
            "current_height": self.current_height,
            "wave84_height": self.wave84_height,
            "drill_window_start": self.drill_window_start,
            "drill_window_end": self.drill_window_end,
            "min_operator_acks": self.min_operator_acks,
            "min_wallet_transcripts": self.min_wallet_transcripts,
            "min_watchtower_replays": self.min_watchtower_replays,
            "min_escape_confirmations": self.min_escape_confirmations,
            "max_transcript_age_blocks": self.max_transcript_age_blocks,
            "max_replay_age_blocks": self.max_replay_age_blocks,
            "min_abort_confirmations": self.min_abort_confirmations,
            "require_fail_closed_hold": self.require_fail_closed_hold,
            "require_unhold_after_fail_closed": self.require_unhold_after_fail_closed,
            "require_wave84_root_match": self.require_wave84_root_match,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE85-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Wave84DeploymentGuardBinding {
    pub release_id: String,
    pub force_exit_id: String,
    pub deployment_guard_root: String,
    pub wallet_scan_root: String,
    pub user_escape_root: String,
    pub watchtower_replay_root: String,
    pub rollback_abort_root: String,
    pub operator_approval_root: String,
    pub production_state_root: String,
    pub decision_root: String,
    pub deploy_allowed: bool,
    pub fail_closed: bool,
}

impl Wave84DeploymentGuardBinding {
    pub fn sample() -> Self {
        Self {
            release_id: "release-2026-06-wallet-watchtower-guard".to_string(),
            force_exit_id: "force-exit-package-canonical-devnet-85".to_string(),
            deployment_guard_root: sample_root("wave84-deployment-guard-root"),
            wallet_scan_root: sample_root("wave84-wallet-scan-root"),
            user_escape_root: sample_root("wave84-user-escape-root"),
            watchtower_replay_root: sample_root("wave84-watchtower-replay-root"),
            rollback_abort_root: sample_root("wave84-rollback-abort-root"),
            operator_approval_root: sample_root("wave84-operator-approval-root"),
            production_state_root: sample_root("wave84-production-state-root"),
            decision_root: sample_root("wave84-decision-root"),
            deploy_allowed: false,
            fail_closed: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("release_id", &self.release_id)?;
        ensure_non_empty("force_exit_id", &self.force_exit_id)?;
        ensure_root("deployment_guard_root", &self.deployment_guard_root)?;
        ensure_root("wallet_scan_root", &self.wallet_scan_root)?;
        ensure_root("user_escape_root", &self.user_escape_root)?;
        ensure_root("watchtower_replay_root", &self.watchtower_replay_root)?;
        ensure_root("rollback_abort_root", &self.rollback_abort_root)?;
        ensure_root("operator_approval_root", &self.operator_approval_root)?;
        ensure_root("production_state_root", &self.production_state_root)?;
        ensure_root("decision_root", &self.decision_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "release_id": self.release_id,
            "force_exit_id": self.force_exit_id,
            "deployment_guard_root": self.deployment_guard_root,
            "wallet_scan_root": self.wallet_scan_root,
            "user_escape_root": self.user_escape_root,
            "watchtower_replay_root": self.watchtower_replay_root,
            "rollback_abort_root": self.rollback_abort_root,
            "operator_approval_root": self.operator_approval_root,
            "production_state_root": self.production_state_root,
            "decision_root": self.decision_root,
            "deploy_allowed": self.deploy_allowed,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE85-WAVE84-BINDING", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletRollbackTranscript {
    pub wallet_id: String,
    pub operator_id: String,
    pub previous_wallet_root: String,
    pub guarded_wallet_root: String,
    pub rollback_transcript_root: String,
    pub rewind_receipt_root: String,
    pub transcript_height: u64,
    pub rollback_step: RollbackStepKind,
    pub status: EvidenceStatus,
}

impl WalletRollbackTranscript {
    pub fn new(
        wallet_id: &str,
        operator_id: &str,
        previous_wallet_root: &str,
        guarded_wallet_root: &str,
        transcript_height: u64,
        status: EvidenceStatus,
    ) -> Self {
        let rollback_transcript_root = domain_hash(
            "WAVE85-WALLET-ROLLBACK-TRANSCRIPT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(wallet_id),
                HashPart::Str(operator_id),
                HashPart::Str(previous_wallet_root),
                HashPart::Str(guarded_wallet_root),
                HashPart::U64(transcript_height),
                HashPart::Str(status.as_str()),
            ],
            32,
        );
        let rewind_receipt_root = domain_hash(
            "WAVE85-WALLET-REWIND-RECEIPT",
            &[
                HashPart::Str(wallet_id),
                HashPart::Str(operator_id),
                HashPart::Str(&rollback_transcript_root),
            ],
            32,
        );
        Self {
            wallet_id: wallet_id.to_string(),
            operator_id: operator_id.to_string(),
            previous_wallet_root: previous_wallet_root.to_string(),
            guarded_wallet_root: guarded_wallet_root.to_string(),
            rollback_transcript_root,
            rewind_receipt_root,
            transcript_height,
            rollback_step: RollbackStepKind::RewindWalletTranscript,
            status,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("wallet_id", &self.wallet_id)?;
        ensure_non_empty("operator_id", &self.operator_id)?;
        ensure_root("previous_wallet_root", &self.previous_wallet_root)?;
        ensure_root("guarded_wallet_root", &self.guarded_wallet_root)?;
        ensure_root("rollback_transcript_root", &self.rollback_transcript_root)?;
        ensure_root("rewind_receipt_root", &self.rewind_receipt_root)?;
        Ok(())
    }

    pub fn is_fresh(&self, current_height: u64, max_age: u64) -> bool {
        current_height.saturating_sub(self.transcript_height) <= max_age
    }

    pub fn accepted_fresh(&self, current_height: u64, max_age: u64) -> bool {
        self.status.accepted() && self.is_fresh(current_height, max_age)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "wallet_id": self.wallet_id,
            "operator_id": self.operator_id,
            "previous_wallet_root": self.previous_wallet_root,
            "guarded_wallet_root": self.guarded_wallet_root,
            "rollback_transcript_root": self.rollback_transcript_root,
            "rewind_receipt_root": self.rewind_receipt_root,
            "transcript_height": self.transcript_height,
            "rollback_step": self.rollback_step.as_str(),
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE85-WALLET-TRANSCRIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatchtowerRollbackEvidence {
    pub tower_id: String,
    pub operator_id: String,
    pub rollback_kind: WatchtowerRollbackKind,
    pub pre_abort_checkpoint_root: String,
    pub abort_root: String,
    pub replay_root: String,
    pub replay_receipt_root: String,
    pub evidence_height: u64,
    pub abort_confirmations: u64,
    pub status: EvidenceStatus,
}

impl WatchtowerRollbackEvidence {
    pub fn new(
        tower_id: &str,
        operator_id: &str,
        rollback_kind: WatchtowerRollbackKind,
        pre_abort_checkpoint_root: &str,
        evidence_height: u64,
        abort_confirmations: u64,
        status: EvidenceStatus,
    ) -> Self {
        let abort_root = domain_hash(
            "WAVE85-WATCHTOWER-ABORT-ROOT",
            &[
                HashPart::Str(tower_id),
                HashPart::Str(operator_id),
                HashPart::Str(rollback_kind.as_str()),
                HashPart::Str(pre_abort_checkpoint_root),
                HashPart::U64(evidence_height),
            ],
            32,
        );
        let replay_root = domain_hash(
            "WAVE85-WATCHTOWER-REPLAY-ROOT",
            &[
                HashPart::Str(tower_id),
                HashPart::Str(operator_id),
                HashPart::Str(&abort_root),
                HashPart::U64(abort_confirmations),
                HashPart::Str(status.as_str()),
            ],
            32,
        );
        let replay_receipt_root = domain_hash(
            "WAVE85-WATCHTOWER-REPLAY-RECEIPT",
            &[
                HashPart::Str(tower_id),
                HashPart::Str(&abort_root),
                HashPart::Str(&replay_root),
            ],
            32,
        );
        Self {
            tower_id: tower_id.to_string(),
            operator_id: operator_id.to_string(),
            rollback_kind,
            pre_abort_checkpoint_root: pre_abort_checkpoint_root.to_string(),
            abort_root,
            replay_root,
            replay_receipt_root,
            evidence_height,
            abort_confirmations,
            status,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("tower_id", &self.tower_id)?;
        ensure_non_empty("operator_id", &self.operator_id)?;
        ensure_root("pre_abort_checkpoint_root", &self.pre_abort_checkpoint_root)?;
        ensure_root("abort_root", &self.abort_root)?;
        ensure_root("replay_root", &self.replay_root)?;
        ensure_root("replay_receipt_root", &self.replay_receipt_root)?;
        Ok(())
    }

    pub fn accepted_fresh(&self, config: &Config) -> bool {
        self.status.accepted()
            && config.current_height.saturating_sub(self.evidence_height)
                <= config.max_replay_age_blocks
            && self.abort_confirmations >= config.min_abort_confirmations
    }

    pub fn public_record(&self) -> Value {
        json!({
            "tower_id": self.tower_id,
            "operator_id": self.operator_id,
            "rollback_kind": self.rollback_kind.as_str(),
            "pre_abort_checkpoint_root": self.pre_abort_checkpoint_root,
            "abort_root": self.abort_root,
            "replay_root": self.replay_root,
            "replay_receipt_root": self.replay_receipt_root,
            "evidence_height": self.evidence_height,
            "abort_confirmations": self.abort_confirmations,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE85-WATCHTOWER-ROLLBACK", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserEscapeDrillAction {
    pub action_id: String,
    pub user_escape_id: String,
    pub operator_id: String,
    pub action_kind: UserEscapeActionKind,
    pub wave84_escape_root: String,
    pub action_root: String,
    pub notice_root: String,
    pub action_height: u64,
    pub status: EvidenceStatus,
}

impl UserEscapeDrillAction {
    pub fn new(
        action_id: &str,
        user_escape_id: &str,
        operator_id: &str,
        action_kind: UserEscapeActionKind,
        wave84_escape_root: &str,
        action_height: u64,
        status: EvidenceStatus,
    ) -> Self {
        let action_root = domain_hash(
            "WAVE85-USER-ESCAPE-ACTION",
            &[
                HashPart::Str(action_id),
                HashPart::Str(user_escape_id),
                HashPart::Str(operator_id),
                HashPart::Str(action_kind.as_str()),
                HashPart::Str(wave84_escape_root),
                HashPart::U64(action_height),
                HashPart::Str(status.as_str()),
            ],
            32,
        );
        let notice_root = domain_hash(
            "WAVE85-USER-ESCAPE-NOTICE",
            &[
                HashPart::Str(action_id),
                HashPart::Str(user_escape_id),
                HashPart::Str(&action_root),
            ],
            32,
        );
        Self {
            action_id: action_id.to_string(),
            user_escape_id: user_escape_id.to_string(),
            operator_id: operator_id.to_string(),
            action_kind,
            wave84_escape_root: wave84_escape_root.to_string(),
            action_root,
            notice_root,
            action_height,
            status,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("action_id", &self.action_id)?;
        ensure_non_empty("user_escape_id", &self.user_escape_id)?;
        ensure_non_empty("operator_id", &self.operator_id)?;
        ensure_root("wave84_escape_root", &self.wave84_escape_root)?;
        ensure_root("action_root", &self.action_root)?;
        ensure_root("notice_root", &self.notice_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "action_id": self.action_id,
            "user_escape_id": self.user_escape_id,
            "operator_id": self.operator_id,
            "action_kind": self.action_kind.as_str(),
            "wave84_escape_root": self.wave84_escape_root,
            "action_root": self.action_root,
            "notice_root": self.notice_root,
            "action_height": self.action_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE85-USER-ESCAPE-DRILL-ACTION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorAcknowledgement {
    pub ack_id: String,
    pub operator_id: String,
    pub ack_kind: OperatorAckKind,
    pub wallet_transcript_root: String,
    pub watchtower_rollback_root: String,
    pub user_escape_action_root: String,
    pub release_hold_root: String,
    pub acknowledged_height: u64,
    pub status: EvidenceStatus,
}

impl OperatorAcknowledgement {
    pub fn new(
        ack_id: &str,
        operator_id: &str,
        ack_kind: OperatorAckKind,
        wallet_transcript_root: &str,
        watchtower_rollback_root: &str,
        user_escape_action_root: &str,
        release_hold_root: &str,
        acknowledged_height: u64,
        status: EvidenceStatus,
    ) -> Self {
        Self {
            ack_id: ack_id.to_string(),
            operator_id: operator_id.to_string(),
            ack_kind,
            wallet_transcript_root: wallet_transcript_root.to_string(),
            watchtower_rollback_root: watchtower_rollback_root.to_string(),
            user_escape_action_root: user_escape_action_root.to_string(),
            release_hold_root: release_hold_root.to_string(),
            acknowledged_height,
            status,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("ack_id", &self.ack_id)?;
        ensure_non_empty("operator_id", &self.operator_id)?;
        ensure_root("wallet_transcript_root", &self.wallet_transcript_root)?;
        ensure_root("watchtower_rollback_root", &self.watchtower_rollback_root)?;
        ensure_root("user_escape_action_root", &self.user_escape_action_root)?;
        ensure_root("release_hold_root", &self.release_hold_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ack_id": self.ack_id,
            "operator_id": self.operator_id,
            "ack_kind": self.ack_kind.as_str(),
            "wallet_transcript_root": self.wallet_transcript_root,
            "watchtower_rollback_root": self.watchtower_rollback_root,
            "user_escape_action_root": self.user_escape_action_root,
            "release_hold_root": self.release_hold_root,
            "acknowledged_height": self.acknowledged_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE85-OPERATOR-ACK", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseHoldUnholdDrillState {
    pub release_id: String,
    pub hold_state: ReleaseHoldState,
    pub fail_closed_root: String,
    pub hold_action_root: String,
    pub unhold_action_root: String,
    pub release_policy_root: String,
    pub drill_height: u64,
    pub hold_asserted: bool,
    pub unhold_asserted: bool,
    pub status: EvidenceStatus,
}

impl ReleaseHoldUnholdDrillState {
    pub fn new(
        release_id: &str,
        hold_state: ReleaseHoldState,
        release_policy_root: &str,
        drill_height: u64,
        hold_asserted: bool,
        unhold_asserted: bool,
        status: EvidenceStatus,
    ) -> Self {
        let fail_closed_root = domain_hash(
            "WAVE85-RELEASE-FAIL-CLOSED",
            &[
                HashPart::Str(release_id),
                HashPart::Str(hold_state.as_str()),
                HashPart::Str(release_policy_root),
                HashPart::U64(drill_height),
                HashPart::Str(bool_str(hold_asserted)),
                HashPart::Str(bool_str(unhold_asserted)),
            ],
            32,
        );
        let hold_action_root = domain_hash(
            "WAVE85-RELEASE-HOLD-ACTION",
            &[
                HashPart::Str(release_id),
                HashPart::Str(&fail_closed_root),
                HashPart::Str(bool_str(hold_asserted)),
            ],
            32,
        );
        let unhold_action_root = domain_hash(
            "WAVE85-RELEASE-UNHOLD-ACTION",
            &[
                HashPart::Str(release_id),
                HashPart::Str(&fail_closed_root),
                HashPart::Str(bool_str(unhold_asserted)),
            ],
            32,
        );
        Self {
            release_id: release_id.to_string(),
            hold_state,
            fail_closed_root,
            hold_action_root,
            unhold_action_root,
            release_policy_root: release_policy_root.to_string(),
            drill_height,
            hold_asserted,
            unhold_asserted,
            status,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("release_id", &self.release_id)?;
        ensure_root("fail_closed_root", &self.fail_closed_root)?;
        ensure_root("hold_action_root", &self.hold_action_root)?;
        ensure_root("unhold_action_root", &self.unhold_action_root)?;
        ensure_root("release_policy_root", &self.release_policy_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "release_id": self.release_id,
            "hold_state": self.hold_state.as_str(),
            "fail_closed_root": self.fail_closed_root,
            "hold_action_root": self.hold_action_root,
            "unhold_action_root": self.unhold_action_root,
            "release_policy_root": self.release_policy_root,
            "drill_height": self.drill_height,
            "hold_asserted": self.hold_asserted,
            "unhold_asserted": self.unhold_asserted,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE85-RELEASE-HOLD-UNHOLD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DrillBlocker {
    pub blocker_kind: DrillBlockerKind,
    pub lane: DrillLane,
    pub subject_id: String,
    pub evidence_root: String,
    pub message: String,
}

impl DrillBlocker {
    pub fn new(
        blocker_kind: DrillBlockerKind,
        lane: DrillLane,
        subject_id: &str,
        evidence_root: &str,
        message: &str,
    ) -> Self {
        Self {
            blocker_kind,
            lane,
            subject_id: subject_id.to_string(),
            evidence_root: evidence_root.to_string(),
            message: message.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_kind": self.blocker_kind.as_str(),
            "lane": self.lane.as_str(),
            "subject_id": self.subject_id,
            "evidence_root": self.evidence_root,
            "message": self.message,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE85-DRILL-BLOCKER", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DrillStep {
    pub step_id: String,
    pub step_kind: RollbackStepKind,
    pub lane: DrillLane,
    pub input_root: String,
    pub output_root: String,
    pub accepted: bool,
}

impl DrillStep {
    pub fn new(
        step_id: &str,
        step_kind: RollbackStepKind,
        lane: DrillLane,
        input_root: &str,
        output_root: &str,
        accepted: bool,
    ) -> Self {
        Self {
            step_id: step_id.to_string(),
            step_kind,
            lane,
            input_root: input_root.to_string(),
            output_root: output_root.to_string(),
            accepted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "step_id": self.step_id,
            "step_kind": self.step_kind.as_str(),
            "lane": self.lane.as_str(),
            "input_root": self.input_root,
            "output_root": self.output_root,
            "accepted": self.accepted,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE85-DRILL-STEP", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DrillRoots {
    pub config_root: String,
    pub wave84_binding_root: String,
    pub wallet_transcript_root: String,
    pub watchtower_abort_root: String,
    pub watchtower_replay_root: String,
    pub user_escape_hold_root: String,
    pub user_escape_unhold_root: String,
    pub operator_ack_root: String,
    pub release_hold_unhold_root: String,
    pub drill_step_root: String,
    pub blocker_root: String,
    pub rollback_drill_root: String,
}

impl DrillRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "wave84_binding_root": self.wave84_binding_root,
            "wallet_transcript_root": self.wallet_transcript_root,
            "watchtower_abort_root": self.watchtower_abort_root,
            "watchtower_replay_root": self.watchtower_replay_root,
            "user_escape_hold_root": self.user_escape_hold_root,
            "user_escape_unhold_root": self.user_escape_unhold_root,
            "operator_ack_root": self.operator_ack_root,
            "release_hold_unhold_root": self.release_hold_unhold_root,
            "drill_step_root": self.drill_step_root,
            "blocker_root": self.blocker_root,
            "rollback_drill_root": self.rollback_drill_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DrillDecision {
    pub decision: DrillDecisionKind,
    pub drill_accepted: bool,
    pub release_remains_held: bool,
    pub fail_closed: bool,
    pub blocker_count: usize,
    pub accepted_wallet_transcripts: usize,
    pub accepted_watchtower_replays: usize,
    pub accepted_escape_actions: usize,
    pub operator_ack_count: usize,
    pub decision_root: String,
}

impl DrillDecision {
    pub fn public_record(&self) -> Value {
        json!({
            "decision": self.decision.as_str(),
            "drill_accepted": self.drill_accepted,
            "release_remains_held": self.release_remains_held,
            "fail_closed": self.fail_closed,
            "blocker_count": self.blocker_count,
            "accepted_wallet_transcripts": self.accepted_wallet_transcripts,
            "accepted_watchtower_replays": self.accepted_watchtower_replays,
            "accepted_escape_actions": self.accepted_escape_actions,
            "operator_ack_count": self.operator_ack_count,
            "decision_root": self.decision_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub drill_id: String,
    pub wave84_binding: Wave84DeploymentGuardBinding,
    pub wallet_transcripts: BTreeMap<String, WalletRollbackTranscript>,
    pub watchtower_rollbacks: BTreeMap<String, WatchtowerRollbackEvidence>,
    pub user_escape_actions: BTreeMap<String, UserEscapeDrillAction>,
    pub operator_acknowledgements: BTreeMap<String, OperatorAcknowledgement>,
    pub release_hold_state: ReleaseHoldUnholdDrillState,
    pub drill_steps: Vec<DrillStep>,
    pub blockers: Vec<DrillBlocker>,
    pub roots: DrillRoots,
    pub decision: DrillDecision,
}

impl State {
    pub fn new(
        config: Config,
        drill_id: &str,
        wave84_binding: Wave84DeploymentGuardBinding,
        wallet_transcripts: Vec<WalletRollbackTranscript>,
        watchtower_rollbacks: Vec<WatchtowerRollbackEvidence>,
        user_escape_actions: Vec<UserEscapeDrillAction>,
        operator_acknowledgements: Vec<OperatorAcknowledgement>,
        release_hold_state: ReleaseHoldUnholdDrillState,
    ) -> Result<Self> {
        config.validate()?;
        ensure_non_empty("drill_id", drill_id)?;
        wave84_binding.validate()?;
        release_hold_state.validate()?;

        let wallet_transcripts = collect_wallet_transcripts(wallet_transcripts)?;
        let watchtower_rollbacks = collect_watchtower_rollbacks(watchtower_rollbacks)?;
        let user_escape_actions = collect_user_escape_actions(user_escape_actions)?;
        let operator_acknowledgements =
            collect_operator_acknowledgements(operator_acknowledgements)?;
        let drill_steps = derive_drill_steps(
            &wave84_binding,
            &wallet_transcripts,
            &watchtower_rollbacks,
            &user_escape_actions,
            &release_hold_state,
        );
        let blockers = derive_blockers(
            &config,
            &wave84_binding,
            &wallet_transcripts,
            &watchtower_rollbacks,
            &user_escape_actions,
            &operator_acknowledgements,
            &release_hold_state,
        );
        let roots = build_roots(
            &config,
            &wave84_binding,
            &wallet_transcripts,
            &watchtower_rollbacks,
            &user_escape_actions,
            &operator_acknowledgements,
            &release_hold_state,
            &drill_steps,
            &blockers,
        );
        let decision = build_decision(
            &config,
            &wallet_transcripts,
            &watchtower_rollbacks,
            &user_escape_actions,
            &operator_acknowledgements,
            &release_hold_state,
            &blockers,
            &roots,
        );

        Ok(Self {
            config,
            drill_id: drill_id.to_string(),
            wave84_binding,
            wallet_transcripts,
            watchtower_rollbacks,
            user_escape_actions,
            operator_acknowledgements,
            release_hold_state,
            drill_steps,
            blockers,
            roots,
            decision,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let wave84_binding = Wave84DeploymentGuardBinding::sample();
        let release_hold_state = ReleaseHoldUnholdDrillState::new(
            &wave84_binding.release_id,
            ReleaseHoldState::Unheld,
            &sample_root("wave84-release-policy-root"),
            config.current_height,
            true,
            true,
            EvidenceStatus::Accepted,
        );
        let wallet_transcripts = vec![
            WalletRollbackTranscript::new(
                "wallet-alpha",
                "operator-alice",
                &sample_root("wallet-alpha-previous"),
                &sample_root("wallet-alpha-guarded"),
                config.current_height - 4,
                EvidenceStatus::Accepted,
            ),
            WalletRollbackTranscript::new(
                "wallet-beta",
                "operator-bob",
                &sample_root("wallet-beta-previous"),
                &sample_root("wallet-beta-guarded"),
                config.current_height - 5,
                EvidenceStatus::Accepted,
            ),
            WalletRollbackTranscript::new(
                "wallet-gamma",
                "operator-carol",
                &sample_root("wallet-gamma-previous"),
                &sample_root("wallet-gamma-guarded"),
                config.current_height - 6,
                EvidenceStatus::Warning,
            ),
        ];
        let watchtower_rollbacks = vec![
            WatchtowerRollbackEvidence::new(
                "tower-east",
                "operator-alice",
                WatchtowerRollbackKind::AbortPendingReplay,
                &sample_root("tower-east-pre-abort"),
                config.current_height - 3,
                config.min_abort_confirmations,
                EvidenceStatus::Accepted,
            ),
            WatchtowerRollbackEvidence::new(
                "tower-west",
                "operator-bob",
                WatchtowerRollbackKind::ReplayAcceptedEvidence,
                &sample_root("tower-west-pre-abort"),
                config.current_height - 4,
                config.min_abort_confirmations + 2,
                EvidenceStatus::Accepted,
            ),
        ];
        let user_escape_actions = vec![
            UserEscapeDrillAction::new(
                "escape-hold-alpha",
                "escape-alpha",
                "operator-alice",
                UserEscapeActionKind::HoldEscapeWindow,
                &wave84_binding.user_escape_root,
                config.current_height - 3,
                EvidenceStatus::Accepted,
            ),
            UserEscapeDrillAction::new(
                "escape-hold-beta",
                "escape-beta",
                "operator-bob",
                UserEscapeActionKind::PublishHoldNotice,
                &wave84_binding.user_escape_root,
                config.current_height - 3,
                EvidenceStatus::Accepted,
            ),
            UserEscapeDrillAction::new(
                "escape-unhold-alpha",
                "escape-alpha",
                "operator-alice",
                UserEscapeActionKind::UnholdEscapeWindow,
                &wave84_binding.user_escape_root,
                config.current_height - 1,
                EvidenceStatus::Accepted,
            ),
            UserEscapeDrillAction::new(
                "escape-unhold-beta",
                "escape-beta",
                "operator-bob",
                UserEscapeActionKind::PublishUnholdNotice,
                &wave84_binding.user_escape_root,
                config.current_height - 1,
                EvidenceStatus::Accepted,
            ),
        ];
        let operator_acknowledgements = vec![
            OperatorAcknowledgement::new(
                "ack-alice",
                "operator-alice",
                OperatorAckKind::ReleaseUnholdReviewed,
                &wallet_transcripts[0].rollback_transcript_root,
                &watchtower_rollbacks[0].replay_root,
                &user_escape_actions[0].action_root,
                &release_hold_state.unhold_action_root,
                config.current_height,
                EvidenceStatus::Accepted,
            ),
            OperatorAcknowledgement::new(
                "ack-bob",
                "operator-bob",
                OperatorAckKind::ReleaseUnholdReviewed,
                &wallet_transcripts[1].rollback_transcript_root,
                &watchtower_rollbacks[1].replay_root,
                &user_escape_actions[2].action_root,
                &release_hold_state.unhold_action_root,
                config.current_height,
                EvidenceStatus::Accepted,
            ),
        ];
        match Self::new(
            config,
            "wave85-wallet-watchtower-rollback-drill-devnet",
            wave84_binding,
            wallet_transcripts,
            watchtower_rollbacks,
            user_escape_actions,
            operator_acknowledgements,
            release_hold_state,
        ) {
            Ok(state) => state,
            Err(_) => Self::fallback_held(),
        }
    }

    fn fallback_held() -> Self {
        let config = Config::devnet();
        let wave84_binding = Wave84DeploymentGuardBinding::sample();
        let release_hold_state = ReleaseHoldUnholdDrillState::new(
            &wave84_binding.release_id,
            ReleaseHoldState::FailClosed,
            &sample_root("fallback-release-policy-root"),
            config.current_height,
            true,
            false,
            EvidenceStatus::Missing,
        );
        let blockers = vec![
            DrillBlocker::new(
                DrillBlockerKind::OperatorAcknowledgementMissing,
                DrillLane::OperatorAcknowledgement,
                "fallback-operator-ack",
                &release_hold_state.hold_action_root,
                "operator acknowledgement is missing in fallback rollback drill",
            ),
            DrillBlocker::new(
                DrillBlockerKind::ReleaseUnholdWithoutQuorum,
                DrillLane::ReleaseFailClosed,
                &wave84_binding.release_id,
                &release_hold_state.unhold_action_root,
                "release stays held until rollback drill quorum is restored",
            ),
        ];
        let drill_steps = vec![DrillStep::new(
            "fallback-release-hold",
            RollbackStepKind::ReleaseHold,
            DrillLane::ReleaseFailClosed,
            &wave84_binding.production_state_root,
            &release_hold_state.hold_action_root,
            true,
        )];
        let roots = DrillRoots {
            config_root: sample_root("fallback-config-root"),
            wave84_binding_root: sample_root("fallback-wave84-binding-root"),
            wallet_transcript_root: sample_root("fallback-wallet-transcript-root"),
            watchtower_abort_root: sample_root("fallback-watchtower-abort-root"),
            watchtower_replay_root: sample_root("fallback-watchtower-replay-root"),
            user_escape_hold_root: release_hold_state.hold_action_root.clone(),
            user_escape_unhold_root: release_hold_state.unhold_action_root.clone(),
            operator_ack_root: sample_root("fallback-operator-ack-root"),
            release_hold_unhold_root: release_hold_state.state_root(),
            drill_step_root: sample_root("fallback-drill-step-root"),
            blocker_root: sample_root("fallback-blocker-root"),
            rollback_drill_root: sample_root("fallback-rollback-drill-root"),
        };
        let decision = DrillDecision {
            decision: DrillDecisionKind::ContinueFailClosed,
            drill_accepted: false,
            release_remains_held: true,
            fail_closed: true,
            blocker_count: blockers.len(),
            accepted_wallet_transcripts: 0,
            accepted_watchtower_replays: 0,
            accepted_escape_actions: 0,
            operator_ack_count: 0,
            decision_root: sample_root("fallback-decision-root"),
        };
        Self {
            config,
            drill_id: "fallback-wallet-watchtower-rollback-drill".to_string(),
            wave84_binding,
            wallet_transcripts: BTreeMap::new(),
            watchtower_rollbacks: BTreeMap::new(),
            user_escape_actions: BTreeMap::new(),
            operator_acknowledgements: BTreeMap::new(),
            release_hold_state,
            drill_steps,
            blockers,
            roots,
            decision,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "drill_id": self.drill_id,
            "wave84_binding": self.wave84_binding.public_record(),
            "wallet_transcripts": self.wallet_transcripts.values().map(WalletRollbackTranscript::public_record).collect::<Vec<_>>(),
            "watchtower_rollbacks": self.watchtower_rollbacks.values().map(WatchtowerRollbackEvidence::public_record).collect::<Vec<_>>(),
            "user_escape_actions": self.user_escape_actions.values().map(UserEscapeDrillAction::public_record).collect::<Vec<_>>(),
            "operator_acknowledgements": self.operator_acknowledgements.values().map(OperatorAcknowledgement::public_record).collect::<Vec<_>>(),
            "release_hold_state": self.release_hold_state.public_record(),
            "drill_steps": self.drill_steps.iter().map(DrillStep::public_record).collect::<Vec<_>>(),
            "blockers": self.blockers.iter().map(DrillBlocker::public_record).collect::<Vec<_>>(),
            "roots": self.roots.public_record(),
            "decision": self.decision.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "WAVE85-ROLLBACK-DRILL-STATE",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(&self.config.protocol_version),
                HashPart::Str(&self.drill_id),
                HashPart::Str(&self.roots.rollback_drill_root),
                HashPart::Str(&self.decision.decision_root),
            ],
            32,
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

fn collect_wallet_transcripts(
    wallet_transcripts: Vec<WalletRollbackTranscript>,
) -> Result<BTreeMap<String, WalletRollbackTranscript>> {
    let mut map = BTreeMap::new();
    for transcript in wallet_transcripts {
        transcript.validate()?;
        ensure(
            map.insert(transcript.wallet_id.clone(), transcript)
                .is_none(),
            "duplicate wallet rollback transcript",
        )?;
    }
    Ok(map)
}

fn collect_watchtower_rollbacks(
    watchtower_rollbacks: Vec<WatchtowerRollbackEvidence>,
) -> Result<BTreeMap<String, WatchtowerRollbackEvidence>> {
    let mut map = BTreeMap::new();
    for rollback in watchtower_rollbacks {
        rollback.validate()?;
        ensure(
            map.insert(rollback.tower_id.clone(), rollback).is_none(),
            "duplicate watchtower rollback evidence",
        )?;
    }
    Ok(map)
}

fn collect_user_escape_actions(
    user_escape_actions: Vec<UserEscapeDrillAction>,
) -> Result<BTreeMap<String, UserEscapeDrillAction>> {
    let mut map = BTreeMap::new();
    for action in user_escape_actions {
        action.validate()?;
        ensure(
            map.insert(action.action_id.clone(), action).is_none(),
            "duplicate user escape drill action",
        )?;
    }
    Ok(map)
}

fn collect_operator_acknowledgements(
    operator_acknowledgements: Vec<OperatorAcknowledgement>,
) -> Result<BTreeMap<String, OperatorAcknowledgement>> {
    let mut map = BTreeMap::new();
    for acknowledgement in operator_acknowledgements {
        acknowledgement.validate()?;
        ensure(
            map.insert(acknowledgement.ack_id.clone(), acknowledgement)
                .is_none(),
            "duplicate operator acknowledgement",
        )?;
    }
    Ok(map)
}

fn derive_drill_steps(
    wave84: &Wave84DeploymentGuardBinding,
    wallet_transcripts: &BTreeMap<String, WalletRollbackTranscript>,
    watchtower_rollbacks: &BTreeMap<String, WatchtowerRollbackEvidence>,
    user_escape_actions: &BTreeMap<String, UserEscapeDrillAction>,
    release_hold_state: &ReleaseHoldUnholdDrillState,
) -> Vec<DrillStep> {
    let mut steps = Vec::new();
    steps.push(DrillStep::new(
        "snapshot-wave84-deployment-guard",
        RollbackStepKind::SnapshotDeploymentGuard,
        DrillLane::Wave84DeploymentGuard,
        &wave84.deployment_guard_root,
        &wave84.decision_root,
        wave84.fail_closed,
    ));
    steps.push(DrillStep::new(
        "release-fail-closed-hold",
        RollbackStepKind::ReleaseHold,
        DrillLane::ReleaseFailClosed,
        &wave84.production_state_root,
        &release_hold_state.hold_action_root,
        release_hold_state.hold_asserted,
    ));
    for transcript in wallet_transcripts.values() {
        steps.push(DrillStep::new(
            &format!("wallet-rollback-{}", transcript.wallet_id),
            RollbackStepKind::RewindWalletTranscript,
            DrillLane::WalletRollbackTranscript,
            &transcript.guarded_wallet_root,
            &transcript.rollback_transcript_root,
            transcript.status.accepted(),
        ));
    }
    for rollback in watchtower_rollbacks.values() {
        steps.push(DrillStep::new(
            &format!("watchtower-abort-{}", rollback.tower_id),
            RollbackStepKind::AbortWatchtowerReplay,
            DrillLane::WatchtowerAbortReplay,
            &rollback.pre_abort_checkpoint_root,
            &rollback.abort_root,
            rollback.status.accepted(),
        ));
        steps.push(DrillStep::new(
            &format!("watchtower-replay-{}", rollback.tower_id),
            RollbackStepKind::ReplayWatchtowerCheckpoint,
            DrillLane::WatchtowerAbortReplay,
            &rollback.abort_root,
            &rollback.replay_root,
            rollback.status.accepted(),
        ));
    }
    for action in user_escape_actions.values() {
        let step_kind = if action.action_kind.is_hold() {
            RollbackStepKind::ConfirmUserEscapeHold
        } else {
            RollbackStepKind::ConfirmUserEscapeUnhold
        };
        steps.push(DrillStep::new(
            &format!("user-escape-{}", action.action_id),
            step_kind,
            DrillLane::UserEscapeHoldUnhold,
            &action.wave84_escape_root,
            &action.action_root,
            action.status.accepted(),
        ));
    }
    steps.push(DrillStep::new(
        "release-fail-closed-unhold",
        RollbackStepKind::ReleaseUnhold,
        DrillLane::ReleaseFailClosed,
        &release_hold_state.hold_action_root,
        &release_hold_state.unhold_action_root,
        release_hold_state.unhold_asserted,
    ));
    steps
}

fn derive_blockers(
    config: &Config,
    wave84: &Wave84DeploymentGuardBinding,
    wallet_transcripts: &BTreeMap<String, WalletRollbackTranscript>,
    watchtower_rollbacks: &BTreeMap<String, WatchtowerRollbackEvidence>,
    user_escape_actions: &BTreeMap<String, UserEscapeDrillAction>,
    operator_acknowledgements: &BTreeMap<String, OperatorAcknowledgement>,
    release_hold_state: &ReleaseHoldUnholdDrillState,
) -> Vec<DrillBlocker> {
    let mut blockers = Vec::new();
    if config.require_wave84_root_match && wave84.deploy_allowed {
        blockers.push(DrillBlocker::new(
            DrillBlockerKind::MissingWave84Root,
            DrillLane::Wave84DeploymentGuard,
            &wave84.release_id,
            &wave84.deployment_guard_root,
            "rollback drill expects a held or fail-closed Wave 84 guard binding",
        ));
    }
    if accepted_wallet_transcripts(config, wallet_transcripts)
        < usize::from(config.min_wallet_transcripts)
    {
        blockers.push(DrillBlocker::new(
            DrillBlockerKind::MissingWalletTranscript,
            DrillLane::WalletRollbackTranscript,
            "wallet_transcripts",
            &wave84.wallet_scan_root,
            "not enough accepted fresh wallet rollback transcript roots",
        ));
    }
    for transcript in wallet_transcripts.values() {
        if !transcript.is_fresh(config.current_height, config.max_transcript_age_blocks) {
            blockers.push(DrillBlocker::new(
                DrillBlockerKind::StaleWalletTranscript,
                DrillLane::WalletRollbackTranscript,
                &transcript.wallet_id,
                &transcript.rollback_transcript_root,
                "wallet rollback transcript exceeds configured age",
            ));
        }
        if transcript.status.blocks() {
            blockers.push(DrillBlocker::new(
                DrillBlockerKind::WalletRollbackMismatch,
                DrillLane::WalletRollbackTranscript,
                &transcript.wallet_id,
                &transcript.rollback_transcript_root,
                "wallet rollback transcript status blocks the drill",
            ));
        }
    }
    if accepted_watchtower_replays(config, watchtower_rollbacks)
        < usize::from(config.min_watchtower_replays)
    {
        blockers.push(DrillBlocker::new(
            DrillBlockerKind::MissingWatchtowerReplayRoot,
            DrillLane::WatchtowerAbortReplay,
            "watchtower_rollbacks",
            &wave84.watchtower_replay_root,
            "not enough accepted watchtower replay rollback roots",
        ));
    }
    for rollback in watchtower_rollbacks.values() {
        if rollback.abort_root.trim().is_empty() {
            blockers.push(DrillBlocker::new(
                DrillBlockerKind::MissingWatchtowerAbortRoot,
                DrillLane::WatchtowerAbortReplay,
                &rollback.tower_id,
                &rollback.replay_root,
                "watchtower rollback is missing abort root",
            ));
        }
        if config
            .current_height
            .saturating_sub(rollback.evidence_height)
            > config.max_replay_age_blocks
        {
            blockers.push(DrillBlocker::new(
                DrillBlockerKind::StaleWatchtowerReplay,
                DrillLane::WatchtowerAbortReplay,
                &rollback.tower_id,
                &rollback.replay_root,
                "watchtower rollback replay evidence exceeds configured age",
            ));
        }
        if rollback.abort_confirmations < config.min_abort_confirmations {
            blockers.push(DrillBlocker::new(
                DrillBlockerKind::AbortConfirmationTooLow,
                DrillLane::WatchtowerAbortReplay,
                &rollback.tower_id,
                &rollback.abort_root,
                "watchtower abort root has too few confirmations",
            ));
        }
    }
    let hold_count = user_escape_actions
        .values()
        .filter(|action| action.status.accepted() && action.action_kind.is_hold())
        .count();
    let unhold_count = user_escape_actions
        .values()
        .filter(|action| action.status.accepted() && action.action_kind.is_unhold())
        .count();
    if hold_count < usize::from(config.min_escape_confirmations) {
        blockers.push(DrillBlocker::new(
            DrillBlockerKind::MissingUserEscapeHold,
            DrillLane::UserEscapeHoldUnhold,
            "user_escape_hold_actions",
            &wave84.user_escape_root,
            "not enough accepted user escape hold confirmations",
        ));
    }
    if config.require_unhold_after_fail_closed
        && unhold_count < usize::from(config.min_escape_confirmations)
    {
        blockers.push(DrillBlocker::new(
            DrillBlockerKind::MissingUserEscapeUnhold,
            DrillLane::UserEscapeHoldUnhold,
            "user_escape_unhold_actions",
            &wave84.user_escape_root,
            "not enough accepted user escape unhold confirmations",
        ));
    }
    if operator_ack_quorum(operator_acknowledgements) < usize::from(config.min_operator_acks) {
        blockers.push(DrillBlocker::new(
            DrillBlockerKind::OperatorAcknowledgementMissing,
            DrillLane::OperatorAcknowledgement,
            "operator_acknowledgements",
            &wave84.operator_approval_root,
            "not enough distinct accepted operator rollback drill acknowledgements",
        ));
    }
    if config.require_fail_closed_hold
        && (!release_hold_state.hold_asserted
            || release_hold_state.hold_state != ReleaseHoldState::Unheld)
    {
        blockers.push(DrillBlocker::new(
            DrillBlockerKind::ReleaseHoldNotFailClosed,
            DrillLane::ReleaseFailClosed,
            &release_hold_state.release_id,
            &release_hold_state.fail_closed_root,
            "release hold/unhold drill did not prove fail-closed hold before unhold",
        ));
    }
    if release_hold_state.unhold_asserted
        && operator_ack_quorum(operator_acknowledgements) < usize::from(config.min_operator_acks)
    {
        blockers.push(DrillBlocker::new(
            DrillBlockerKind::ReleaseUnholdWithoutQuorum,
            DrillLane::ReleaseFailClosed,
            &release_hold_state.release_id,
            &release_hold_state.unhold_action_root,
            "release unhold was asserted before operator acknowledgement quorum",
        ));
    }
    blockers
}

fn build_roots(
    config: &Config,
    wave84: &Wave84DeploymentGuardBinding,
    wallet_transcripts: &BTreeMap<String, WalletRollbackTranscript>,
    watchtower_rollbacks: &BTreeMap<String, WatchtowerRollbackEvidence>,
    user_escape_actions: &BTreeMap<String, UserEscapeDrillAction>,
    operator_acknowledgements: &BTreeMap<String, OperatorAcknowledgement>,
    release_hold_state: &ReleaseHoldUnholdDrillState,
    drill_steps: &[DrillStep],
    blockers: &[DrillBlocker],
) -> DrillRoots {
    let config_root = config.state_root();
    let wave84_binding_root = wave84.state_root();
    let wallet_transcript_root = merkle_root(
        "WAVE85-ROOT-WALLET-TRANSCRIPTS",
        &wallet_transcripts
            .values()
            .map(WalletRollbackTranscript::public_record)
            .collect::<Vec<_>>(),
    );
    let watchtower_abort_root = merkle_root(
        "WAVE85-ROOT-WATCHTOWER-ABORTS",
        &watchtower_rollbacks
            .values()
            .map(|rollback| {
                json!({
                    "tower_id": rollback.tower_id,
                    "abort_root": rollback.abort_root,
                    "abort_confirmations": rollback.abort_confirmations,
                    "status": rollback.status.as_str(),
                })
            })
            .collect::<Vec<_>>(),
    );
    let watchtower_replay_root = merkle_root(
        "WAVE85-ROOT-WATCHTOWER-REPLAYS",
        &watchtower_rollbacks
            .values()
            .map(WatchtowerRollbackEvidence::public_record)
            .collect::<Vec<_>>(),
    );
    let user_escape_hold_root = merkle_root(
        "WAVE85-ROOT-USER-ESCAPE-HOLDS",
        &user_escape_actions
            .values()
            .filter(|action| action.action_kind.is_hold())
            .map(UserEscapeDrillAction::public_record)
            .collect::<Vec<_>>(),
    );
    let user_escape_unhold_root = merkle_root(
        "WAVE85-ROOT-USER-ESCAPE-UNHOLDS",
        &user_escape_actions
            .values()
            .filter(|action| action.action_kind.is_unhold())
            .map(UserEscapeDrillAction::public_record)
            .collect::<Vec<_>>(),
    );
    let operator_ack_root = merkle_root(
        "WAVE85-ROOT-OPERATOR-ACKS",
        &operator_acknowledgements
            .values()
            .map(OperatorAcknowledgement::public_record)
            .collect::<Vec<_>>(),
    );
    let release_hold_unhold_root = release_hold_state.state_root();
    let drill_step_root = merkle_root(
        "WAVE85-ROOT-DRILL-STEPS",
        &drill_steps
            .iter()
            .map(DrillStep::public_record)
            .collect::<Vec<_>>(),
    );
    let blocker_root = merkle_root(
        "WAVE85-ROOT-DRILL-BLOCKERS",
        &blockers
            .iter()
            .map(DrillBlocker::public_record)
            .collect::<Vec<_>>(),
    );
    let rollback_drill_root = domain_hash(
        "WAVE85-ROLLBACK-DRILL-ROOT",
        &[
            HashPart::Str(&config.chain_id),
            HashPart::Str(&config.protocol_version),
            HashPart::U64(config.current_height),
            HashPart::Str(&config_root),
            HashPart::Str(&wave84_binding_root),
            HashPart::Str(&wallet_transcript_root),
            HashPart::Str(&watchtower_abort_root),
            HashPart::Str(&watchtower_replay_root),
            HashPart::Str(&user_escape_hold_root),
            HashPart::Str(&user_escape_unhold_root),
            HashPart::Str(&operator_ack_root),
            HashPart::Str(&release_hold_unhold_root),
            HashPart::Str(&drill_step_root),
            HashPart::Str(&blocker_root),
        ],
        32,
    );
    DrillRoots {
        config_root,
        wave84_binding_root,
        wallet_transcript_root,
        watchtower_abort_root,
        watchtower_replay_root,
        user_escape_hold_root,
        user_escape_unhold_root,
        operator_ack_root,
        release_hold_unhold_root,
        drill_step_root,
        blocker_root,
        rollback_drill_root,
    }
}

fn build_decision(
    config: &Config,
    wallet_transcripts: &BTreeMap<String, WalletRollbackTranscript>,
    watchtower_rollbacks: &BTreeMap<String, WatchtowerRollbackEvidence>,
    user_escape_actions: &BTreeMap<String, UserEscapeDrillAction>,
    operator_acknowledgements: &BTreeMap<String, OperatorAcknowledgement>,
    release_hold_state: &ReleaseHoldUnholdDrillState,
    blockers: &[DrillBlocker],
    roots: &DrillRoots,
) -> DrillDecision {
    let accepted_wallet_transcripts = accepted_wallet_transcripts(config, wallet_transcripts);
    let accepted_watchtower_replays = accepted_watchtower_replays(config, watchtower_rollbacks);
    let accepted_escape_actions = user_escape_actions
        .values()
        .filter(|action| action.status.accepted())
        .count();
    let operator_ack_count = operator_ack_quorum(operator_acknowledgements);
    let fail_closed = release_hold_state.hold_asserted
        && release_hold_state.status.accepted()
        && !release_hold_state.hold_state.deployment_allowed();
    let release_remains_held = !release_hold_state.unhold_asserted
        || matches!(
            release_hold_state.hold_state,
            ReleaseHoldState::Held | ReleaseHoldState::FailClosed
        );
    let drill_accepted = blockers.is_empty()
        && release_hold_state.unhold_asserted
        && release_hold_state.status.accepted()
        && accepted_wallet_transcripts >= usize::from(config.min_wallet_transcripts)
        && accepted_watchtower_replays >= usize::from(config.min_watchtower_replays)
        && operator_ack_count >= usize::from(config.min_operator_acks);
    let decision = if drill_accepted {
        DrillDecisionKind::DrillAccepted
    } else if blockers.iter().any(|blocker| {
        matches!(
            blocker.blocker_kind,
            DrillBlockerKind::MissingWatchtowerAbortRoot
                | DrillBlockerKind::WalletRollbackMismatch
                | DrillBlockerKind::AbortConfirmationTooLow
        )
    }) {
        DrillDecisionKind::AbortRollback
    } else if fail_closed {
        DrillDecisionKind::ContinueFailClosed
    } else {
        DrillDecisionKind::HoldRelease
    };
    let decision_root = domain_hash(
        "WAVE85-ROLLBACK-DRILL-DECISION",
        &[
            HashPart::Str(decision.as_str()),
            HashPart::Str(bool_str(drill_accepted)),
            HashPart::Str(bool_str(release_remains_held)),
            HashPart::Str(bool_str(fail_closed)),
            HashPart::U64(blockers.len() as u64),
            HashPart::U64(accepted_wallet_transcripts as u64),
            HashPart::U64(accepted_watchtower_replays as u64),
            HashPart::U64(accepted_escape_actions as u64),
            HashPart::U64(operator_ack_count as u64),
            HashPart::Str(&roots.rollback_drill_root),
        ],
        32,
    );
    DrillDecision {
        decision,
        drill_accepted,
        release_remains_held,
        fail_closed,
        blocker_count: blockers.len(),
        accepted_wallet_transcripts,
        accepted_watchtower_replays,
        accepted_escape_actions,
        operator_ack_count,
        decision_root,
    }
}

fn accepted_wallet_transcripts(
    config: &Config,
    wallet_transcripts: &BTreeMap<String, WalletRollbackTranscript>,
) -> usize {
    wallet_transcripts
        .values()
        .filter(|transcript| {
            transcript.accepted_fresh(config.current_height, config.max_transcript_age_blocks)
        })
        .count()
}

fn accepted_watchtower_replays(
    config: &Config,
    watchtower_rollbacks: &BTreeMap<String, WatchtowerRollbackEvidence>,
) -> usize {
    watchtower_rollbacks
        .values()
        .filter(|rollback| rollback.accepted_fresh(config))
        .count()
}

fn operator_ack_quorum(
    operator_acknowledgements: &BTreeMap<String, OperatorAcknowledgement>,
) -> usize {
    let mut operators = BTreeSet::new();
    for acknowledgement in operator_acknowledgements.values() {
        if acknowledgement.status.accepted() {
            operators.insert(acknowledgement.operator_id.clone());
        }
    }
    operators.len()
}

fn sample_root(label: &str) -> String {
    domain_hash(
        "WAVE85-ROLLBACK-DRILL-SAMPLE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
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

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn ensure_non_empty(label: &str, value: &str) -> Result<()> {
    ensure(
        !value.trim().is_empty(),
        &format!("{label} must be non-empty"),
    )
}

fn ensure_root(label: &str, value: &str) -> Result<()> {
    ensure_non_empty(label, value)?;
    ensure(value.len() >= 32, &format!("{label} must be root-like"))
}
