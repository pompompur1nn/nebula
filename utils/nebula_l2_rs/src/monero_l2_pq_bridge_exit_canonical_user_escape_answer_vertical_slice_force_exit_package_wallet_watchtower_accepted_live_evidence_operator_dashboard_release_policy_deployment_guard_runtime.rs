use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageWalletWatchtowerAcceptedLiveEvidenceOperatorDashboardReleasePolicyDeploymentGuardRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_WALLET_WATCHTOWER_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-wallet-watchtower-accepted-live-evidence-operator-dashboard-release-policy-deployment-guard-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_WALLET_WATCHTOWER_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const DEPLOYMENT_GUARD_SUITE: &str = "wallet-watchtower-release-policy-deployment-guard-v1";
pub const DEFAULT_HEIGHT: u64 = 4_280_640;
pub const DEFAULT_DEPLOYMENT_WINDOW_START: u64 = 4_280_632;
pub const DEFAULT_DEPLOYMENT_WINDOW_END: u64 = 4_280_704;
pub const DEFAULT_MIN_OPERATOR_APPROVALS: u16 = 2;
pub const DEFAULT_MIN_WATCHTOWER_REPLAY_CONFIRMATIONS: u64 = 12;
pub const DEFAULT_MAX_REPLAY_AGE_BLOCKS: u64 = 48;
pub const DEFAULT_MAX_WALLET_SCAN_AGE_BLOCKS: u64 = 96;
pub const DEFAULT_ESCAPE_NOTICE_BLOCKS: u64 = 32;
pub const DEFAULT_ROLLBACK_PROOF_COUNT: u16 = 2;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardLane {
    WalletHoldCriteria,
    WalletUnholdCriteria,
    DeployBlockers,
    RollbackAbortRoots,
    UserEscapeActions,
    WatchtowerReplay,
    OperatorDashboard,
    ProductionState,
}

impl GuardLane {
    pub fn all() -> Vec<Self> {
        vec![
            Self::WalletHoldCriteria,
            Self::WalletUnholdCriteria,
            Self::DeployBlockers,
            Self::RollbackAbortRoots,
            Self::UserEscapeActions,
            Self::WatchtowerReplay,
            Self::OperatorDashboard,
            Self::ProductionState,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletHoldCriteria => "wallet_hold_criteria",
            Self::WalletUnholdCriteria => "wallet_unhold_criteria",
            Self::DeployBlockers => "deploy_blockers",
            Self::RollbackAbortRoots => "rollback_abort_roots",
            Self::UserEscapeActions => "user_escape_actions",
            Self::WatchtowerReplay => "watchtower_replay",
            Self::OperatorDashboard => "operator_dashboard",
            Self::ProductionState => "production_state",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardDecisionKind {
    DeployAllowed,
    HoldWallet,
    AbortDeployment,
    RollbackRequired,
    FailClosed,
}

impl GuardDecisionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeployAllowed => "deploy_allowed",
            Self::HoldWallet => "hold_wallet",
            Self::AbortDeployment => "abort_deployment",
            Self::RollbackRequired => "rollback_required",
            Self::FailClosed => "fail_closed",
        }
    }

    pub fn allows_deploy(self) -> bool {
        matches!(self, Self::DeployAllowed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldCriterionKind {
    WalletScanGapExceeded,
    WalletEvidenceStale,
    WatchtowerReplayStale,
    WatchtowerReplayMismatch,
    UserEscapeNotConfirmed,
    DashboardApprovalMissing,
    RollbackProofMissing,
    DeploymentWindowClosed,
    ReleasePolicyNoGo,
    ProductionStateNotFailClosed,
}

impl HoldCriterionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScanGapExceeded => "wallet_scan_gap_exceeded",
            Self::WalletEvidenceStale => "wallet_evidence_stale",
            Self::WatchtowerReplayStale => "watchtower_replay_stale",
            Self::WatchtowerReplayMismatch => "watchtower_replay_mismatch",
            Self::UserEscapeNotConfirmed => "user_escape_not_confirmed",
            Self::DashboardApprovalMissing => "dashboard_approval_missing",
            Self::RollbackProofMissing => "rollback_proof_missing",
            Self::DeploymentWindowClosed => "deployment_window_closed",
            Self::ReleasePolicyNoGo => "release_policy_no_go",
            Self::ProductionStateNotFailClosed => "production_state_not_fail_closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnholdCriterionKind {
    WalletScanFresh,
    WatchtowerReplayFresh,
    UserEscapeConfirmed,
    RollbackProofReady,
    DashboardQuorumAccepted,
    DeploymentWindowOpen,
    ReleasePolicyGo,
    ProductionFailClosedArmed,
}

impl UnholdCriterionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScanFresh => "wallet_scan_fresh",
            Self::WatchtowerReplayFresh => "watchtower_replay_fresh",
            Self::UserEscapeConfirmed => "user_escape_confirmed",
            Self::RollbackProofReady => "rollback_proof_ready",
            Self::DashboardQuorumAccepted => "dashboard_quorum_accepted",
            Self::DeploymentWindowOpen => "deployment_window_open",
            Self::ReleasePolicyGo => "release_policy_go",
            Self::ProductionFailClosedArmed => "production_fail_closed_armed",
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

    pub fn blocks_deploy(self) -> bool {
        matches!(self, Self::Missing | Self::Rejected | Self::Stale)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeActionKind {
    PublishNotice,
    ConfirmWalletPath,
    ConfirmForceExitPath,
    ConfirmAbortWindow,
    ConfirmReplayReceipt,
}

impl EscapeActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublishNotice => "publish_notice",
            Self::ConfirmWalletPath => "confirm_wallet_path",
            Self::ConfirmForceExitPath => "confirm_force_exit_path",
            Self::ConfirmAbortWindow => "confirm_abort_window",
            Self::ConfirmReplayReceipt => "confirm_replay_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackProofKind {
    AbortRoot,
    PreviousReleaseRoot,
    StateSnapshotRoot,
    WatchtowerFreezeRoot,
    WalletRewindRoot,
}

impl RollbackProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AbortRoot => "abort_root",
            Self::PreviousReleaseRoot => "previous_release_root",
            Self::StateSnapshotRoot => "state_snapshot_root",
            Self::WatchtowerFreezeRoot => "watchtower_freeze_root",
            Self::WalletRewindRoot => "wallet_rewind_root",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployBlockerKind {
    ReleasePolicyNoGo,
    DeploymentWindowNotOpen,
    WalletHoldActive,
    WalletUnholdNotMet,
    WatchtowerReplayMissing,
    WatchtowerReplayUnderConfirmed,
    WatchtowerReplayStale,
    WatchtowerReplayRootMismatch,
    UserEscapeActionMissing,
    UserEscapeActionUnconfirmed,
    RollbackProofMissing,
    DashboardApprovalMissing,
    DashboardRootMismatch,
    OperatorRejected,
    ProductionNotFailClosed,
    AbortRootMissing,
}

impl DeployBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleasePolicyNoGo => "release_policy_no_go",
            Self::DeploymentWindowNotOpen => "deployment_window_not_open",
            Self::WalletHoldActive => "wallet_hold_active",
            Self::WalletUnholdNotMet => "wallet_unhold_not_met",
            Self::WatchtowerReplayMissing => "watchtower_replay_missing",
            Self::WatchtowerReplayUnderConfirmed => "watchtower_replay_under_confirmed",
            Self::WatchtowerReplayStale => "watchtower_replay_stale",
            Self::WatchtowerReplayRootMismatch => "watchtower_replay_root_mismatch",
            Self::UserEscapeActionMissing => "user_escape_action_missing",
            Self::UserEscapeActionUnconfirmed => "user_escape_action_unconfirmed",
            Self::RollbackProofMissing => "rollback_proof_missing",
            Self::DashboardApprovalMissing => "dashboard_approval_missing",
            Self::DashboardRootMismatch => "dashboard_root_mismatch",
            Self::OperatorRejected => "operator_rejected",
            Self::ProductionNotFailClosed => "production_not_fail_closed",
            Self::AbortRootMissing => "abort_root_missing",
        }
    }

    pub fn lane(self) -> GuardLane {
        match self {
            Self::ReleasePolicyNoGo => GuardLane::DeployBlockers,
            Self::DeploymentWindowNotOpen => GuardLane::DeployBlockers,
            Self::WalletHoldActive => GuardLane::WalletHoldCriteria,
            Self::WalletUnholdNotMet => GuardLane::WalletUnholdCriteria,
            Self::WatchtowerReplayMissing
            | Self::WatchtowerReplayUnderConfirmed
            | Self::WatchtowerReplayStale
            | Self::WatchtowerReplayRootMismatch => GuardLane::WatchtowerReplay,
            Self::UserEscapeActionMissing | Self::UserEscapeActionUnconfirmed => {
                GuardLane::UserEscapeActions
            }
            Self::RollbackProofMissing | Self::AbortRootMissing => GuardLane::RollbackAbortRoots,
            Self::DashboardApprovalMissing
            | Self::DashboardRootMismatch
            | Self::OperatorRejected => GuardLane::OperatorDashboard,
            Self::ProductionNotFailClosed => GuardLane::ProductionState,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub deployment_guard_suite: String,
    pub current_height: u64,
    pub deployment_window_start: u64,
    pub deployment_window_end: u64,
    pub min_operator_approvals: u16,
    pub min_watchtower_replay_confirmations: u64,
    pub max_replay_age_blocks: u64,
    pub max_wallet_scan_age_blocks: u64,
    pub escape_notice_blocks: u64,
    pub min_rollback_proofs: u16,
    pub require_release_policy_go: bool,
    pub require_dashboard_root_match: bool,
    pub require_abort_root: bool,
    pub fail_closed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            deployment_guard_suite: DEPLOYMENT_GUARD_SUITE.to_string(),
            current_height: DEFAULT_HEIGHT,
            deployment_window_start: DEFAULT_DEPLOYMENT_WINDOW_START,
            deployment_window_end: DEFAULT_DEPLOYMENT_WINDOW_END,
            min_operator_approvals: DEFAULT_MIN_OPERATOR_APPROVALS,
            min_watchtower_replay_confirmations: DEFAULT_MIN_WATCHTOWER_REPLAY_CONFIRMATIONS,
            max_replay_age_blocks: DEFAULT_MAX_REPLAY_AGE_BLOCKS,
            max_wallet_scan_age_blocks: DEFAULT_MAX_WALLET_SCAN_AGE_BLOCKS,
            escape_notice_blocks: DEFAULT_ESCAPE_NOTICE_BLOCKS,
            min_rollback_proofs: DEFAULT_ROLLBACK_PROOF_COUNT,
            require_release_policy_go: true,
            require_dashboard_root_match: true,
            require_abort_root: true,
            fail_closed: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure(
            self.schema_version == SCHEMA_VERSION,
            "schema version is not supported",
        )?;
        ensure(
            self.deployment_window_start <= self.deployment_window_end,
            "deployment window start must not exceed deployment window end",
        )?;
        ensure(
            self.min_operator_approvals > 0,
            "minimum operator approvals must be non-zero",
        )?;
        ensure(
            self.min_watchtower_replay_confirmations > 0,
            "minimum watchtower replay confirmations must be non-zero",
        )?;
        ensure(
            self.max_replay_age_blocks > 0,
            "watchtower replay age window must be non-zero",
        )?;
        ensure(
            self.max_wallet_scan_age_blocks > 0,
            "wallet scan age window must be non-zero",
        )?;
        ensure(
            self.escape_notice_blocks > 0,
            "escape notice blocks must be non-zero",
        )?;
        ensure(
            self.min_rollback_proofs > 0,
            "minimum rollback proof count must be non-zero",
        )?;
        Ok(())
    }

    pub fn deployment_window_open(&self) -> bool {
        self.current_height >= self.deployment_window_start
            && self.current_height <= self.deployment_window_end
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "deployment_guard_suite": self.deployment_guard_suite,
            "current_height": self.current_height,
            "deployment_window_start": self.deployment_window_start,
            "deployment_window_end": self.deployment_window_end,
            "min_operator_approvals": self.min_operator_approvals,
            "min_watchtower_replay_confirmations": self.min_watchtower_replay_confirmations,
            "max_replay_age_blocks": self.max_replay_age_blocks,
            "max_wallet_scan_age_blocks": self.max_wallet_scan_age_blocks,
            "escape_notice_blocks": self.escape_notice_blocks,
            "min_rollback_proofs": self.min_rollback_proofs,
            "require_release_policy_go": self.require_release_policy_go,
            "require_dashboard_root_match": self.require_dashboard_root_match,
            "require_abort_root": self.require_abort_root,
            "fail_closed": self.fail_closed,
            "deployment_window_open": self.deployment_window_open(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE84-DEPLOYMENT-GUARD-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Wave83GoNoGoBinding {
    pub binding_id: String,
    pub release_policy_root: String,
    pub dashboard_root: String,
    pub lane_binding_root: String,
    pub coordinator_approval_root: String,
    pub blocker_root: String,
    pub decision_root: String,
    pub observed_at_height: u64,
    pub release_allowed: bool,
    pub fail_closed: bool,
}

impl Wave83GoNoGoBinding {
    pub fn accepted(binding_id: &str, height: u64) -> Self {
        let seed = json!({
            "binding_id": binding_id,
            "height": height,
            "lane": "wallet_watchtower",
            "suite": DEPLOYMENT_GUARD_SUITE,
        });
        let release_policy_root = record_root("WAVE84-SAMPLE-WAVE83-RELEASE-POLICY", &seed);
        let dashboard_root = record_root("WAVE84-SAMPLE-WAVE83-DASHBOARD", &seed);
        let lane_binding_root = record_root("WAVE84-SAMPLE-WAVE83-LANES", &seed);
        let coordinator_approval_root = record_root("WAVE84-SAMPLE-WAVE83-COORDINATORS", &seed);
        let blocker_root = merkle_root("WAVE84-SAMPLE-WAVE83-NO-BLOCKERS", &[]);
        let decision_root = domain_hash(
            "WAVE84-SAMPLE-WAVE83-DECISION",
            &[
                HashPart::Str(binding_id),
                HashPart::U64(height),
                HashPart::Str(&release_policy_root),
                HashPart::Str(&dashboard_root),
                HashPart::Str(&lane_binding_root),
                HashPart::Str(&coordinator_approval_root),
                HashPart::Str(&blocker_root),
            ],
            32,
        );
        Self {
            binding_id: binding_id.to_string(),
            release_policy_root,
            dashboard_root,
            lane_binding_root,
            coordinator_approval_root,
            blocker_root,
            decision_root,
            observed_at_height: height,
            release_allowed: true,
            fail_closed: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("binding_id", &self.binding_id)?;
        ensure_root("release_policy_root", &self.release_policy_root)?;
        ensure_root("dashboard_root", &self.dashboard_root)?;
        ensure_root("lane_binding_root", &self.lane_binding_root)?;
        ensure_root("coordinator_approval_root", &self.coordinator_approval_root)?;
        ensure_root("blocker_root", &self.blocker_root)?;
        ensure_root("decision_root", &self.decision_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "release_policy_root": self.release_policy_root,
            "dashboard_root": self.dashboard_root,
            "lane_binding_root": self.lane_binding_root,
            "coordinator_approval_root": self.coordinator_approval_root,
            "blocker_root": self.blocker_root,
            "decision_root": self.decision_root,
            "observed_at_height": self.observed_at_height,
            "release_allowed": self.release_allowed,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE84-WAVE83-GO-NO-GO-BINDING", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletScanConfirmation {
    pub wallet_id: String,
    pub scan_receipt_root: String,
    pub accepted_live_evidence_root: String,
    pub last_scanned_height: u64,
    pub accepted_at_height: u64,
    pub scan_gap_blocks: u64,
    pub status: EvidenceStatus,
}

impl WalletScanConfirmation {
    pub fn accepted(wallet_id: &str, current_height: u64, scan_gap_blocks: u64) -> Self {
        let seed = json!({
            "wallet_id": wallet_id,
            "current_height": current_height,
            "scan_gap_blocks": scan_gap_blocks,
        });
        Self {
            wallet_id: wallet_id.to_string(),
            scan_receipt_root: record_root("WAVE84-WALLET-SCAN-RECEIPT", &seed),
            accepted_live_evidence_root: record_root("WAVE84-WALLET-LIVE-EVIDENCE", &seed),
            last_scanned_height: current_height.saturating_sub(scan_gap_blocks),
            accepted_at_height: current_height.saturating_sub(4),
            scan_gap_blocks,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn fresh_at(&self, height: u64, max_age: u64) -> bool {
        self.accepted_at_height <= height
            && height.saturating_sub(self.accepted_at_height) <= max_age
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("wallet_id", &self.wallet_id)?;
        ensure_root("scan_receipt_root", &self.scan_receipt_root)?;
        ensure_root(
            "accepted_live_evidence_root",
            &self.accepted_live_evidence_root,
        )?;
        ensure(
            self.last_scanned_height <= self.accepted_at_height,
            "wallet scan height must not exceed accepted height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "wallet_id": self.wallet_id,
            "scan_receipt_root": self.scan_receipt_root,
            "accepted_live_evidence_root": self.accepted_live_evidence_root,
            "last_scanned_height": self.last_scanned_height,
            "accepted_at_height": self.accepted_at_height,
            "scan_gap_blocks": self.scan_gap_blocks,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE84-WALLET-SCAN-CONFIRMATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserEscapeConfirmation {
    pub action_id: String,
    pub action_kind: EscapeActionKind,
    pub user_notice_root: String,
    pub force_exit_root: String,
    pub wallet_path_root: String,
    pub acknowledged_at_height: u64,
    pub expires_at_height: u64,
    pub status: EvidenceStatus,
}

impl UserEscapeConfirmation {
    pub fn confirmed(
        action_id: &str,
        action_kind: EscapeActionKind,
        current_height: u64,
        notice_blocks: u64,
    ) -> Self {
        let seed = json!({
            "action_id": action_id,
            "action_kind": action_kind.as_str(),
            "current_height": current_height,
        });
        Self {
            action_id: action_id.to_string(),
            action_kind,
            user_notice_root: record_root("WAVE84-USER-ESCAPE-NOTICE", &seed),
            force_exit_root: record_root("WAVE84-USER-ESCAPE-FORCE-EXIT", &seed),
            wallet_path_root: record_root("WAVE84-USER-ESCAPE-WALLET-PATH", &seed),
            acknowledged_at_height: current_height.saturating_sub(3),
            expires_at_height: current_height.saturating_add(notice_blocks),
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn confirmed_at(&self, height: u64) -> bool {
        self.status.accepted()
            && self.acknowledged_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("action_id", &self.action_id)?;
        ensure_root("user_notice_root", &self.user_notice_root)?;
        ensure_root("force_exit_root", &self.force_exit_root)?;
        ensure_root("wallet_path_root", &self.wallet_path_root)?;
        ensure(
            self.acknowledged_at_height <= self.expires_at_height,
            "escape acknowledgement must not exceed expiry",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "action_id": self.action_id,
            "action_kind": self.action_kind.as_str(),
            "user_notice_root": self.user_notice_root,
            "force_exit_root": self.force_exit_root,
            "wallet_path_root": self.wallet_path_root,
            "acknowledged_at_height": self.acknowledged_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE84-USER-ESCAPE-CONFIRMATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatchtowerReplayEvidence {
    pub replay_id: String,
    pub watchtower_id: String,
    pub expected_wallet_root: String,
    pub observed_wallet_root: String,
    pub replay_receipt_root: String,
    pub replayed_at_height: u64,
    pub confirmations: u64,
    pub status: EvidenceStatus,
}

impl WatchtowerReplayEvidence {
    pub fn accepted(
        replay_id: &str,
        watchtower_id: &str,
        wallet_root: &str,
        height: u64,
        confirmations: u64,
    ) -> Self {
        let seed = json!({
            "replay_id": replay_id,
            "watchtower_id": watchtower_id,
            "wallet_root": wallet_root,
            "height": height,
            "confirmations": confirmations,
        });
        Self {
            replay_id: replay_id.to_string(),
            watchtower_id: watchtower_id.to_string(),
            expected_wallet_root: wallet_root.to_string(),
            observed_wallet_root: wallet_root.to_string(),
            replay_receipt_root: record_root("WAVE84-WATCHTOWER-REPLAY-RECEIPT", &seed),
            replayed_at_height: height.saturating_sub(5),
            confirmations,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn root_matches(&self) -> bool {
        self.expected_wallet_root == self.observed_wallet_root
    }

    pub fn fresh_at(&self, height: u64, max_age: u64) -> bool {
        self.replayed_at_height <= height
            && height.saturating_sub(self.replayed_at_height) <= max_age
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("replay_id", &self.replay_id)?;
        ensure_non_empty("watchtower_id", &self.watchtower_id)?;
        ensure_root("expected_wallet_root", &self.expected_wallet_root)?;
        ensure_root("observed_wallet_root", &self.observed_wallet_root)?;
        ensure_root("replay_receipt_root", &self.replay_receipt_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "replay_id": self.replay_id,
            "watchtower_id": self.watchtower_id,
            "expected_wallet_root": self.expected_wallet_root,
            "observed_wallet_root": self.observed_wallet_root,
            "replay_receipt_root": self.replay_receipt_root,
            "replayed_at_height": self.replayed_at_height,
            "confirmations": self.confirmations,
            "status": self.status.as_str(),
            "root_matches": self.root_matches(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE84-WATCHTOWER-REPLAY-EVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RollbackAbortProof {
    pub proof_id: String,
    pub proof_kind: RollbackProofKind,
    pub abort_root: String,
    pub rollback_target_root: String,
    pub operator_witness_root: String,
    pub produced_at_height: u64,
    pub status: EvidenceStatus,
}

impl RollbackAbortProof {
    pub fn accepted(proof_id: &str, proof_kind: RollbackProofKind, height: u64) -> Self {
        let seed = json!({
            "proof_id": proof_id,
            "proof_kind": proof_kind.as_str(),
            "height": height,
        });
        Self {
            proof_id: proof_id.to_string(),
            proof_kind,
            abort_root: record_root("WAVE84-ROLLBACK-ABORT-ROOT", &seed),
            rollback_target_root: record_root("WAVE84-ROLLBACK-TARGET-ROOT", &seed),
            operator_witness_root: record_root("WAVE84-ROLLBACK-OPERATOR-WITNESS", &seed),
            produced_at_height: height.saturating_sub(2),
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("proof_id", &self.proof_id)?;
        ensure_root("abort_root", &self.abort_root)?;
        ensure_root("rollback_target_root", &self.rollback_target_root)?;
        ensure_root("operator_witness_root", &self.operator_witness_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "proof_kind": self.proof_kind.as_str(),
            "abort_root": self.abort_root,
            "rollback_target_root": self.rollback_target_root,
            "operator_witness_root": self.operator_witness_root,
            "produced_at_height": self.produced_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE84-ROLLBACK-ABORT-PROOF", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorDashboardApproval {
    pub approval_id: String,
    pub operator_id: String,
    pub dashboard_root: String,
    pub release_policy_root: String,
    pub deployment_guard_root: String,
    pub approved_at_height: u64,
    pub status: EvidenceStatus,
}

impl OperatorDashboardApproval {
    pub fn accepted(
        approval_id: &str,
        operator_id: &str,
        dashboard_root: &str,
        release_policy_root: &str,
        height: u64,
    ) -> Self {
        let seed = json!({
            "approval_id": approval_id,
            "operator_id": operator_id,
            "dashboard_root": dashboard_root,
            "release_policy_root": release_policy_root,
            "height": height,
        });
        Self {
            approval_id: approval_id.to_string(),
            operator_id: operator_id.to_string(),
            dashboard_root: dashboard_root.to_string(),
            release_policy_root: release_policy_root.to_string(),
            deployment_guard_root: record_root("WAVE84-OPERATOR-DEPLOYMENT-GUARD", &seed),
            approved_at_height: height,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("approval_id", &self.approval_id)?;
        ensure_non_empty("operator_id", &self.operator_id)?;
        ensure_root("dashboard_root", &self.dashboard_root)?;
        ensure_root("release_policy_root", &self.release_policy_root)?;
        ensure_root("deployment_guard_root", &self.deployment_guard_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "approval_id": self.approval_id,
            "operator_id": self.operator_id,
            "dashboard_root": self.dashboard_root,
            "release_policy_root": self.release_policy_root,
            "deployment_guard_root": self.deployment_guard_root,
            "approved_at_height": self.approved_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE84-OPERATOR-DASHBOARD-APPROVAL", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProductionDeploymentState {
    pub deployment_id: String,
    pub environment: String,
    pub requested_release_root: String,
    pub deployed_release_root: String,
    pub fail_closed_armed: bool,
    pub wallet_hold_active: bool,
    pub abort_root_armed: bool,
    pub rollback_root_armed: bool,
    pub deployment_started_at_height: u64,
    pub status: EvidenceStatus,
}

impl ProductionDeploymentState {
    pub fn fail_closed(deployment_id: &str, release_root: &str, height: u64) -> Self {
        Self {
            deployment_id: deployment_id.to_string(),
            environment: "production".to_string(),
            requested_release_root: release_root.to_string(),
            deployed_release_root: release_root.to_string(),
            fail_closed_armed: true,
            wallet_hold_active: false,
            abort_root_armed: true,
            rollback_root_armed: true,
            deployment_started_at_height: height,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn deployment_roots_match(&self) -> bool {
        self.requested_release_root == self.deployed_release_root
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("deployment_id", &self.deployment_id)?;
        ensure_non_empty("environment", &self.environment)?;
        ensure_root("requested_release_root", &self.requested_release_root)?;
        ensure_root("deployed_release_root", &self.deployed_release_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "deployment_id": self.deployment_id,
            "environment": self.environment,
            "requested_release_root": self.requested_release_root,
            "deployed_release_root": self.deployed_release_root,
            "fail_closed_armed": self.fail_closed_armed,
            "wallet_hold_active": self.wallet_hold_active,
            "abort_root_armed": self.abort_root_armed,
            "rollback_root_armed": self.rollback_root_armed,
            "deployment_started_at_height": self.deployment_started_at_height,
            "status": self.status.as_str(),
            "deployment_roots_match": self.deployment_roots_match(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE84-PRODUCTION-DEPLOYMENT-STATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GuardCriterion {
    pub criterion_id: String,
    pub lane: GuardLane,
    pub evidence_root: String,
    pub satisfied: bool,
    pub reason: String,
}

impl GuardCriterion {
    pub fn new(
        criterion_id: &str,
        lane: GuardLane,
        evidence_root: &str,
        satisfied: bool,
        reason: &str,
    ) -> Self {
        Self {
            criterion_id: criterion_id.to_string(),
            lane,
            evidence_root: evidence_root.to_string(),
            satisfied,
            reason: reason.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "criterion_id": self.criterion_id,
            "lane": self.lane.as_str(),
            "evidence_root": self.evidence_root,
            "satisfied": self.satisfied,
            "reason": self.reason,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE84-GUARD-CRITERION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeploymentBlocker {
    pub blocker_id: String,
    pub blocker_kind: DeployBlockerKind,
    pub lane: GuardLane,
    pub evidence_root: String,
    pub observed_at_height: u64,
    pub message: String,
}

impl DeploymentBlocker {
    pub fn new(
        blocker_kind: DeployBlockerKind,
        subject: &str,
        evidence_root: &str,
        observed_at_height: u64,
        message: &str,
    ) -> Self {
        let blocker_id = domain_hash(
            "WAVE84-DEPLOYMENT-BLOCKER-ID",
            &[
                HashPart::Str(blocker_kind.as_str()),
                HashPart::Str(subject),
                HashPart::Str(evidence_root),
                HashPart::U64(observed_at_height),
            ],
            16,
        );
        Self {
            blocker_id,
            blocker_kind,
            lane: blocker_kind.lane(),
            evidence_root: evidence_root.to_string(),
            observed_at_height,
            message: message.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "blocker_kind": self.blocker_kind.as_str(),
            "lane": self.lane.as_str(),
            "evidence_root": self.evidence_root,
            "observed_at_height": self.observed_at_height,
            "message": self.message,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE84-DEPLOYMENT-BLOCKER", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GuardRoots {
    pub wave83_binding_root: String,
    pub wallet_scan_root: String,
    pub user_escape_root: String,
    pub watchtower_replay_root: String,
    pub rollback_abort_root: String,
    pub operator_approval_root: String,
    pub production_state_root: String,
    pub hold_criteria_root: String,
    pub unhold_criteria_root: String,
    pub blocker_root: String,
    pub deployment_guard_root: String,
}

impl GuardRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "wave83_binding_root": self.wave83_binding_root,
            "wallet_scan_root": self.wallet_scan_root,
            "user_escape_root": self.user_escape_root,
            "watchtower_replay_root": self.watchtower_replay_root,
            "rollback_abort_root": self.rollback_abort_root,
            "operator_approval_root": self.operator_approval_root,
            "production_state_root": self.production_state_root,
            "hold_criteria_root": self.hold_criteria_root,
            "unhold_criteria_root": self.unhold_criteria_root,
            "blocker_root": self.blocker_root,
            "deployment_guard_root": self.deployment_guard_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeploymentGuardDecision {
    pub decision: GuardDecisionKind,
    pub deploy_allowed: bool,
    pub fail_closed: bool,
    pub wallet_hold_active: bool,
    pub rollback_required: bool,
    pub abort_required: bool,
    pub blocker_count: usize,
    pub operator_approval_count: usize,
    pub watchtower_replay_count: usize,
    pub user_escape_count: usize,
    pub decision_root: String,
}

impl DeploymentGuardDecision {
    pub fn public_record(&self) -> Value {
        json!({
            "decision": self.decision.as_str(),
            "deploy_allowed": self.deploy_allowed,
            "fail_closed": self.fail_closed,
            "wallet_hold_active": self.wallet_hold_active,
            "rollback_required": self.rollback_required,
            "abort_required": self.abort_required,
            "blocker_count": self.blocker_count,
            "operator_approval_count": self.operator_approval_count,
            "watchtower_replay_count": self.watchtower_replay_count,
            "user_escape_count": self.user_escape_count,
            "decision_root": self.decision_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub release_id: String,
    pub force_exit_id: String,
    pub wave83_binding: Wave83GoNoGoBinding,
    pub wallet_scans: BTreeMap<String, WalletScanConfirmation>,
    pub user_escape_confirmations: BTreeMap<String, UserEscapeConfirmation>,
    pub watchtower_replays: BTreeMap<String, WatchtowerReplayEvidence>,
    pub rollback_abort_proofs: BTreeMap<String, RollbackAbortProof>,
    pub operator_approvals: BTreeMap<String, OperatorDashboardApproval>,
    pub production_state: ProductionDeploymentState,
    pub hold_criteria: Vec<GuardCriterion>,
    pub unhold_criteria: Vec<GuardCriterion>,
    pub blockers: Vec<DeploymentBlocker>,
    pub roots: GuardRoots,
    pub decision: DeploymentGuardDecision,
}

impl State {
    pub fn new(
        config: Config,
        release_id: &str,
        force_exit_id: &str,
        wave83_binding: Wave83GoNoGoBinding,
        wallet_scans: Vec<WalletScanConfirmation>,
        user_escape_confirmations: Vec<UserEscapeConfirmation>,
        watchtower_replays: Vec<WatchtowerReplayEvidence>,
        rollback_abort_proofs: Vec<RollbackAbortProof>,
        operator_approvals: Vec<OperatorDashboardApproval>,
        production_state: ProductionDeploymentState,
    ) -> Result<Self> {
        config.validate()?;
        ensure_non_empty("release_id", release_id)?;
        ensure_non_empty("force_exit_id", force_exit_id)?;
        wave83_binding.validate()?;
        production_state.validate()?;

        let mut wallet_map = BTreeMap::new();
        for scan in wallet_scans {
            scan.validate()?;
            wallet_map.insert(scan.wallet_id.clone(), scan);
        }
        let mut escape_map = BTreeMap::new();
        for escape in user_escape_confirmations {
            escape.validate()?;
            escape_map.insert(escape.action_id.clone(), escape);
        }
        let mut replay_map = BTreeMap::new();
        for replay in watchtower_replays {
            replay.validate()?;
            replay_map.insert(replay.replay_id.clone(), replay);
        }
        let mut rollback_map = BTreeMap::new();
        for proof in rollback_abort_proofs {
            proof.validate()?;
            rollback_map.insert(proof.proof_id.clone(), proof);
        }
        let mut approval_map = BTreeMap::new();
        for approval in operator_approvals {
            approval.validate()?;
            approval_map.insert(approval.approval_id.clone(), approval);
        }

        let hold_criteria = derive_hold_criteria(
            &config,
            &wave83_binding,
            &wallet_map,
            &escape_map,
            &replay_map,
            &rollback_map,
            &approval_map,
            &production_state,
        );
        let unhold_criteria = derive_unhold_criteria(
            &config,
            &wave83_binding,
            &wallet_map,
            &escape_map,
            &replay_map,
            &rollback_map,
            &approval_map,
            &production_state,
        );
        let blockers = derive_blockers(
            &config,
            &wave83_binding,
            &wallet_map,
            &escape_map,
            &replay_map,
            &rollback_map,
            &approval_map,
            &production_state,
        );
        let roots = build_roots(
            &config,
            &wave83_binding,
            &wallet_map,
            &escape_map,
            &replay_map,
            &rollback_map,
            &approval_map,
            &production_state,
            &hold_criteria,
            &unhold_criteria,
            &blockers,
        );
        let decision = build_decision(
            &config,
            &production_state,
            &escape_map,
            &replay_map,
            &approval_map,
            &blockers,
            &roots,
        );

        Ok(Self {
            config,
            release_id: release_id.to_string(),
            force_exit_id: force_exit_id.to_string(),
            wave83_binding,
            wallet_scans: wallet_map,
            user_escape_confirmations: escape_map,
            watchtower_replays: replay_map,
            rollback_abort_proofs: rollback_map,
            operator_approvals: approval_map,
            production_state,
            hold_criteria,
            unhold_criteria,
            blockers,
            roots,
            decision,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let release_id = "wave84-wallet-watchtower-deployment-guard";
        let force_exit_id = "force-exit-package-wave84-canonical-user-escape";
        let wave83_binding = Wave83GoNoGoBinding::accepted(
            "wave83-wallet-watchtower-dashboard-go-no-go",
            config.current_height.saturating_sub(6),
        );
        let wallet_a =
            WalletScanConfirmation::accepted("canonical-wallet-alpha", config.current_height, 3);
        let wallet_b =
            WalletScanConfirmation::accepted("canonical-wallet-beta", config.current_height, 4);
        let wallet_root = merkle_root(
            "WAVE84-DEVNET-WALLET-ROOTS",
            &[wallet_a.public_record(), wallet_b.public_record()],
        );
        let user_escape_confirmations = vec![
            UserEscapeConfirmation::confirmed(
                "escape-notice-alpha",
                EscapeActionKind::PublishNotice,
                config.current_height,
                config.escape_notice_blocks,
            ),
            UserEscapeConfirmation::confirmed(
                "escape-force-exit-alpha",
                EscapeActionKind::ConfirmForceExitPath,
                config.current_height,
                config.escape_notice_blocks,
            ),
            UserEscapeConfirmation::confirmed(
                "escape-wallet-alpha",
                EscapeActionKind::ConfirmWalletPath,
                config.current_height,
                config.escape_notice_blocks,
            ),
        ];
        let watchtower_replays = vec![
            WatchtowerReplayEvidence::accepted(
                "watchtower-replay-alpha",
                "watchtower-alpha",
                &wallet_root,
                config.current_height,
                14,
            ),
            WatchtowerReplayEvidence::accepted(
                "watchtower-replay-beta",
                "watchtower-beta",
                &wallet_root,
                config.current_height,
                13,
            ),
            WatchtowerReplayEvidence::accepted(
                "watchtower-replay-gamma",
                "watchtower-gamma",
                &wallet_root,
                config.current_height,
                12,
            ),
        ];
        let rollback_abort_proofs = vec![
            RollbackAbortProof::accepted(
                "rollback-abort-root",
                RollbackProofKind::AbortRoot,
                config.current_height,
            ),
            RollbackAbortProof::accepted(
                "rollback-previous-release-root",
                RollbackProofKind::PreviousReleaseRoot,
                config.current_height,
            ),
            RollbackAbortProof::accepted(
                "rollback-watchtower-freeze-root",
                RollbackProofKind::WatchtowerFreezeRoot,
                config.current_height,
            ),
        ];
        let operator_approvals = vec![
            OperatorDashboardApproval::accepted(
                "operator-approval-alpha",
                "operator-alpha",
                &wave83_binding.dashboard_root,
                &wave83_binding.release_policy_root,
                config.current_height,
            ),
            OperatorDashboardApproval::accepted(
                "operator-approval-beta",
                "operator-beta",
                &wave83_binding.dashboard_root,
                &wave83_binding.release_policy_root,
                config.current_height,
            ),
            OperatorDashboardApproval::accepted(
                "operator-approval-gamma",
                "operator-gamma",
                &wave83_binding.dashboard_root,
                &wave83_binding.release_policy_root,
                config.current_height,
            ),
        ];
        let production_state = ProductionDeploymentState::fail_closed(
            "production-wave84-wallet-watchtower",
            &wave83_binding.release_policy_root,
            config.current_height,
        );
        match Self::new(
            config,
            release_id,
            force_exit_id,
            wave83_binding,
            vec![wallet_a, wallet_b],
            user_escape_confirmations,
            watchtower_replays,
            rollback_abort_proofs,
            operator_approvals,
            production_state,
        ) {
            Ok(state) => state,
            Err(_) => Self::fallback(),
        }
    }

    pub fn fallback() -> Self {
        let config = Config::devnet();
        let wave83_binding = Wave83GoNoGoBinding::accepted(
            "fallback-wave83-wallet-watchtower",
            config.current_height,
        );
        let production_state = ProductionDeploymentState {
            deployment_id: "fallback-production-wallet-watchtower".to_string(),
            environment: "production".to_string(),
            requested_release_root: wave83_binding.release_policy_root.clone(),
            deployed_release_root: sample_root("fallback-deployed-release-mismatch"),
            fail_closed_armed: true,
            wallet_hold_active: true,
            abort_root_armed: true,
            rollback_root_armed: true,
            deployment_started_at_height: config.current_height,
            status: EvidenceStatus::Warning,
        };
        let wallet = WalletScanConfirmation::accepted("fallback-wallet", config.current_height, 2);
        let blockers = vec![DeploymentBlocker::new(
            DeployBlockerKind::WalletHoldActive,
            "fallback-production-wallet-watchtower",
            &production_state.state_root(),
            config.current_height,
            "fallback state keeps production deployment fail-closed while wallet hold is active",
        )];
        let hold_criteria = vec![GuardCriterion::new(
            HoldCriterionKind::ProductionStateNotFailClosed.as_str(),
            GuardLane::ProductionState,
            &production_state.state_root(),
            true,
            "fallback guard holds deployment until full Wave 84 evidence is rebuilt",
        )];
        let unhold_criteria = Vec::new();
        let mut wallet_map = BTreeMap::new();
        wallet_map.insert(wallet.wallet_id.clone(), wallet);
        let escape_map = BTreeMap::new();
        let replay_map = BTreeMap::new();
        let rollback_map = BTreeMap::new();
        let approval_map = BTreeMap::new();
        let roots = build_roots(
            &config,
            &wave83_binding,
            &wallet_map,
            &escape_map,
            &replay_map,
            &rollback_map,
            &approval_map,
            &production_state,
            &hold_criteria,
            &unhold_criteria,
            &blockers,
        );
        let decision = build_decision(
            &config,
            &production_state,
            &escape_map,
            &replay_map,
            &approval_map,
            &blockers,
            &roots,
        );
        Self {
            config,
            release_id: "fallback-wave84-wallet-watchtower-deployment-guard".to_string(),
            force_exit_id: "fallback-force-exit".to_string(),
            wave83_binding,
            wallet_scans: wallet_map,
            user_escape_confirmations: escape_map,
            watchtower_replays: replay_map,
            rollback_abort_proofs: rollback_map,
            operator_approvals: approval_map,
            production_state,
            hold_criteria,
            unhold_criteria,
            blockers,
            roots,
            decision,
        }
    }

    pub fn wallet_scan_root(&self) -> String {
        merkle_root(
            "WAVE84-DEPLOYMENT-GUARD-WALLET-SCANS",
            &self
                .wallet_scans
                .values()
                .map(WalletScanConfirmation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn watchtower_replay_root(&self) -> String {
        merkle_root(
            "WAVE84-DEPLOYMENT-GUARD-WATCHTOWER-REPLAYS",
            &self
                .watchtower_replays
                .values()
                .map(WatchtowerReplayEvidence::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn user_escape_root(&self) -> String {
        merkle_root(
            "WAVE84-DEPLOYMENT-GUARD-USER-ESCAPES",
            &self
                .user_escape_confirmations
                .values()
                .map(UserEscapeConfirmation::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn rollback_abort_root(&self) -> String {
        merkle_root(
            "WAVE84-DEPLOYMENT-GUARD-ROLLBACK-ABORT-PROOFS",
            &self
                .rollback_abort_proofs
                .values()
                .map(RollbackAbortProof::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn operator_approval_root(&self) -> String {
        merkle_root(
            "WAVE84-DEPLOYMENT-GUARD-OPERATOR-APPROVALS",
            &self
                .operator_approvals
                .values()
                .map(OperatorDashboardApproval::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "release_id": self.release_id,
            "force_exit_id": self.force_exit_id,
            "config": self.config.public_record(),
            "wave83_binding": self.wave83_binding.public_record(),
            "production_state": self.production_state.public_record(),
            "roots": self.roots.public_record(),
            "decision": self.decision.public_record(),
            "wallet_scans": self.wallet_scans.values().map(WalletScanConfirmation::public_record).collect::<Vec<_>>(),
            "user_escape_confirmations": self.user_escape_confirmations.values().map(UserEscapeConfirmation::public_record).collect::<Vec<_>>(),
            "watchtower_replays": self.watchtower_replays.values().map(WatchtowerReplayEvidence::public_record).collect::<Vec<_>>(),
            "rollback_abort_proofs": self.rollback_abort_proofs.values().map(RollbackAbortProof::public_record).collect::<Vec<_>>(),
            "operator_approvals": self.operator_approvals.values().map(OperatorDashboardApproval::public_record).collect::<Vec<_>>(),
            "hold_criteria": self.hold_criteria.iter().map(GuardCriterion::public_record).collect::<Vec<_>>(),
            "unhold_criteria": self.unhold_criteria.iter().map(GuardCriterion::public_record).collect::<Vec<_>>(),
            "blockers": self.blockers.iter().map(DeploymentBlocker::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE84-DEPLOYMENT-GUARD-STATE", &self.public_record())
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

fn derive_hold_criteria(
    config: &Config,
    wave83: &Wave83GoNoGoBinding,
    wallets: &BTreeMap<String, WalletScanConfirmation>,
    escapes: &BTreeMap<String, UserEscapeConfirmation>,
    replays: &BTreeMap<String, WatchtowerReplayEvidence>,
    rollbacks: &BTreeMap<String, RollbackAbortProof>,
    approvals: &BTreeMap<String, OperatorDashboardApproval>,
    production: &ProductionDeploymentState,
) -> Vec<GuardCriterion> {
    let mut criteria = Vec::new();
    criteria.push(GuardCriterion::new(
        HoldCriterionKind::ReleasePolicyNoGo.as_str(),
        GuardLane::DeployBlockers,
        &wave83.state_root(),
        config.require_release_policy_go && !wave83.release_allowed,
        "hold if Wave 83 release policy dashboard go-no-go decision is not go",
    ));
    criteria.push(GuardCriterion::new(
        HoldCriterionKind::DeploymentWindowClosed.as_str(),
        GuardLane::DeployBlockers,
        &config.state_root(),
        !config.deployment_window_open(),
        "hold if the explicit deployment window is closed",
    ));
    for wallet in wallets.values() {
        criteria.push(GuardCriterion::new(
            HoldCriterionKind::WalletEvidenceStale.as_str(),
            GuardLane::WalletHoldCriteria,
            &wallet.state_root(),
            !wallet.fresh_at(config.current_height, config.max_wallet_scan_age_blocks),
            "hold if accepted wallet scan evidence exceeds freshness policy",
        ));
        criteria.push(GuardCriterion::new(
            HoldCriterionKind::WalletScanGapExceeded.as_str(),
            GuardLane::WalletHoldCriteria,
            &wallet.state_root(),
            wallet.status.blocks_deploy(),
            "hold if wallet scan evidence is missing, stale, or rejected",
        ));
    }
    for replay in replays.values() {
        criteria.push(GuardCriterion::new(
            HoldCriterionKind::WatchtowerReplayStale.as_str(),
            GuardLane::WatchtowerReplay,
            &replay.state_root(),
            !replay.fresh_at(config.current_height, config.max_replay_age_blocks),
            "hold if watchtower replay evidence is outside freshness policy",
        ));
        criteria.push(GuardCriterion::new(
            HoldCriterionKind::WatchtowerReplayMismatch.as_str(),
            GuardLane::WatchtowerReplay,
            &replay.state_root(),
            !replay.root_matches(),
            "hold if watchtower replay observed wallet root differs from expected wallet root",
        ));
    }
    criteria.push(GuardCriterion::new(
        HoldCriterionKind::UserEscapeNotConfirmed.as_str(),
        GuardLane::UserEscapeActions,
        &merkle_root(
            "WAVE84-HOLD-ESCAPE-ROOT",
            &escapes
                .values()
                .map(UserEscapeConfirmation::public_record)
                .collect::<Vec<_>>(),
        ),
        escapes
            .values()
            .any(|escape| !escape.confirmed_at(config.current_height)),
        "hold if any user escape action is not confirmed within its live window",
    ));
    criteria.push(GuardCriterion::new(
        HoldCriterionKind::RollbackProofMissing.as_str(),
        GuardLane::RollbackAbortRoots,
        &merkle_root(
            "WAVE84-HOLD-ROLLBACK-ROOT",
            &rollbacks
                .values()
                .map(RollbackAbortProof::public_record)
                .collect::<Vec<_>>(),
        ),
        rollbacks.len() < usize::from(config.min_rollback_proofs),
        "hold if rollback and abort proof quorum is incomplete",
    ));
    criteria.push(GuardCriterion::new(
        HoldCriterionKind::DashboardApprovalMissing.as_str(),
        GuardLane::OperatorDashboard,
        &merkle_root(
            "WAVE84-HOLD-APPROVAL-ROOT",
            &approvals
                .values()
                .map(OperatorDashboardApproval::public_record)
                .collect::<Vec<_>>(),
        ),
        approval_quorum(config, wave83, approvals) < usize::from(config.min_operator_approvals),
        "hold if operator dashboard approval quorum is incomplete",
    ));
    criteria.push(GuardCriterion::new(
        HoldCriterionKind::ProductionStateNotFailClosed.as_str(),
        GuardLane::ProductionState,
        &production.state_root(),
        !production.fail_closed_armed || production.wallet_hold_active,
        "hold if production is not fail-closed or still has a wallet hold active",
    ));
    criteria
}

fn derive_unhold_criteria(
    config: &Config,
    wave83: &Wave83GoNoGoBinding,
    wallets: &BTreeMap<String, WalletScanConfirmation>,
    escapes: &BTreeMap<String, UserEscapeConfirmation>,
    replays: &BTreeMap<String, WatchtowerReplayEvidence>,
    rollbacks: &BTreeMap<String, RollbackAbortProof>,
    approvals: &BTreeMap<String, OperatorDashboardApproval>,
    production: &ProductionDeploymentState,
) -> Vec<GuardCriterion> {
    vec![
        GuardCriterion::new(
            UnholdCriterionKind::WalletScanFresh.as_str(),
            GuardLane::WalletUnholdCriteria,
            &merkle_root(
                "WAVE84-UNHOLD-WALLET-ROOT",
                &wallets
                    .values()
                    .map(WalletScanConfirmation::public_record)
                    .collect::<Vec<_>>(),
            ),
            !wallets.is_empty()
                && wallets.values().all(|wallet| {
                    wallet.status.accepted()
                        && wallet.fresh_at(config.current_height, config.max_wallet_scan_age_blocks)
                }),
            "unhold requires every wallet scan to be accepted and fresh",
        ),
        GuardCriterion::new(
            UnholdCriterionKind::WatchtowerReplayFresh.as_str(),
            GuardLane::WatchtowerReplay,
            &merkle_root(
                "WAVE84-UNHOLD-REPLAY-ROOT",
                &replays
                    .values()
                    .map(WatchtowerReplayEvidence::public_record)
                    .collect::<Vec<_>>(),
            ),
            !replays.is_empty()
                && replays.values().all(|replay| {
                    replay.status.accepted()
                        && replay.root_matches()
                        && replay.confirmations >= config.min_watchtower_replay_confirmations
                        && replay.fresh_at(config.current_height, config.max_replay_age_blocks)
                }),
            "unhold requires fresh, root-matching watchtower replay evidence",
        ),
        GuardCriterion::new(
            UnholdCriterionKind::UserEscapeConfirmed.as_str(),
            GuardLane::UserEscapeActions,
            &merkle_root(
                "WAVE84-UNHOLD-ESCAPE-ROOT",
                &escapes
                    .values()
                    .map(UserEscapeConfirmation::public_record)
                    .collect::<Vec<_>>(),
            ),
            !escapes.is_empty()
                && escapes
                    .values()
                    .all(|escape| escape.confirmed_at(config.current_height)),
            "unhold requires confirmed user escape action roots",
        ),
        GuardCriterion::new(
            UnholdCriterionKind::RollbackProofReady.as_str(),
            GuardLane::RollbackAbortRoots,
            &merkle_root(
                "WAVE84-UNHOLD-ROLLBACK-ROOT",
                &rollbacks
                    .values()
                    .map(RollbackAbortProof::public_record)
                    .collect::<Vec<_>>(),
            ),
            rollback_ready(config, rollbacks),
            "unhold requires rollback and abort roots to be armed",
        ),
        GuardCriterion::new(
            UnholdCriterionKind::DashboardQuorumAccepted.as_str(),
            GuardLane::OperatorDashboard,
            &merkle_root(
                "WAVE84-UNHOLD-APPROVAL-ROOT",
                &approvals
                    .values()
                    .map(OperatorDashboardApproval::public_record)
                    .collect::<Vec<_>>(),
            ),
            approval_quorum(config, wave83, approvals)
                >= usize::from(config.min_operator_approvals),
            "unhold requires operator dashboard approval quorum",
        ),
        GuardCriterion::new(
            UnholdCriterionKind::DeploymentWindowOpen.as_str(),
            GuardLane::DeployBlockers,
            &config.state_root(),
            config.deployment_window_open(),
            "unhold requires deployment height to be inside the allowed window",
        ),
        GuardCriterion::new(
            UnholdCriterionKind::ReleasePolicyGo.as_str(),
            GuardLane::DeployBlockers,
            &wave83.state_root(),
            wave83.release_allowed && wave83.fail_closed,
            "unhold requires Wave 83 go decision and fail-closed go-no-go binding",
        ),
        GuardCriterion::new(
            UnholdCriterionKind::ProductionFailClosedArmed.as_str(),
            GuardLane::ProductionState,
            &production.state_root(),
            production.fail_closed_armed
                && production.abort_root_armed
                && production.rollback_root_armed
                && production.deployment_roots_match(),
            "unhold requires production fail-closed state with rollback and abort roots armed",
        ),
    ]
}

fn derive_blockers(
    config: &Config,
    wave83: &Wave83GoNoGoBinding,
    wallets: &BTreeMap<String, WalletScanConfirmation>,
    escapes: &BTreeMap<String, UserEscapeConfirmation>,
    replays: &BTreeMap<String, WatchtowerReplayEvidence>,
    rollbacks: &BTreeMap<String, RollbackAbortProof>,
    approvals: &BTreeMap<String, OperatorDashboardApproval>,
    production: &ProductionDeploymentState,
) -> Vec<DeploymentBlocker> {
    let mut blockers = Vec::new();
    if config.require_release_policy_go && !wave83.release_allowed {
        blockers.push(DeploymentBlocker::new(
            DeployBlockerKind::ReleasePolicyNoGo,
            &wave83.binding_id,
            &wave83.state_root(),
            config.current_height,
            "Wave 83 dashboard go-no-go binding does not allow release",
        ));
    }
    if !config.deployment_window_open() {
        blockers.push(DeploymentBlocker::new(
            DeployBlockerKind::DeploymentWindowNotOpen,
            "deployment_window",
            &config.state_root(),
            config.current_height,
            "current height is outside explicit deployment window",
        ));
    }
    if wallets.is_empty() {
        blockers.push(DeploymentBlocker::new(
            DeployBlockerKind::WalletUnholdNotMet,
            "wallet_scan_set",
            &config.state_root(),
            config.current_height,
            "no wallet scan confirmations are present",
        ));
    }
    for wallet in wallets.values() {
        if wallet.status.blocks_deploy()
            || !wallet.fresh_at(config.current_height, config.max_wallet_scan_age_blocks)
        {
            blockers.push(DeploymentBlocker::new(
                DeployBlockerKind::WalletHoldActive,
                &wallet.wallet_id,
                &wallet.state_root(),
                config.current_height,
                "wallet scan evidence is not accepted and fresh",
            ));
        }
    }
    if replays.is_empty() {
        blockers.push(DeploymentBlocker::new(
            DeployBlockerKind::WatchtowerReplayMissing,
            "watchtower_replay_set",
            &config.state_root(),
            config.current_height,
            "no watchtower replay evidence is present",
        ));
    }
    for replay in replays.values() {
        if replay.confirmations < config.min_watchtower_replay_confirmations {
            blockers.push(DeploymentBlocker::new(
                DeployBlockerKind::WatchtowerReplayUnderConfirmed,
                &replay.replay_id,
                &replay.state_root(),
                config.current_height,
                "watchtower replay evidence is under-confirmed",
            ));
        }
        if !replay.fresh_at(config.current_height, config.max_replay_age_blocks) {
            blockers.push(DeploymentBlocker::new(
                DeployBlockerKind::WatchtowerReplayStale,
                &replay.replay_id,
                &replay.state_root(),
                config.current_height,
                "watchtower replay evidence is stale",
            ));
        }
        if !replay.root_matches() {
            blockers.push(DeploymentBlocker::new(
                DeployBlockerKind::WatchtowerReplayRootMismatch,
                &replay.replay_id,
                &replay.state_root(),
                config.current_height,
                "watchtower replay evidence root mismatch",
            ));
        }
    }
    if escapes.is_empty() {
        blockers.push(DeploymentBlocker::new(
            DeployBlockerKind::UserEscapeActionMissing,
            "user_escape_set",
            &config.state_root(),
            config.current_height,
            "no user escape action confirmations are present",
        ));
    }
    for escape in escapes.values() {
        if !escape.confirmed_at(config.current_height) {
            blockers.push(DeploymentBlocker::new(
                DeployBlockerKind::UserEscapeActionUnconfirmed,
                &escape.action_id,
                &escape.state_root(),
                config.current_height,
                "user escape action root is not confirmed for deployment",
            ));
        }
    }
    if rollbacks.len() < usize::from(config.min_rollback_proofs) {
        blockers.push(DeploymentBlocker::new(
            DeployBlockerKind::RollbackProofMissing,
            "rollback_abort_set",
            &config.state_root(),
            config.current_height,
            "rollback and abort proof quorum is incomplete",
        ));
    }
    if config.require_abort_root
        && !rollbacks.values().any(|proof| {
            proof.proof_kind == RollbackProofKind::AbortRoot && proof.status.accepted()
        })
    {
        blockers.push(DeploymentBlocker::new(
            DeployBlockerKind::AbortRootMissing,
            "abort_root",
            &config.state_root(),
            config.current_height,
            "required abort root proof is missing",
        ));
    }
    if approval_quorum(config, wave83, approvals) < usize::from(config.min_operator_approvals) {
        blockers.push(DeploymentBlocker::new(
            DeployBlockerKind::DashboardApprovalMissing,
            "operator_dashboard_approvals",
            &wave83.dashboard_root,
            config.current_height,
            "operator dashboard approval quorum is incomplete",
        ));
    }
    for approval in approvals.values() {
        if config.require_dashboard_root_match && approval.dashboard_root != wave83.dashboard_root {
            blockers.push(DeploymentBlocker::new(
                DeployBlockerKind::DashboardRootMismatch,
                &approval.approval_id,
                &approval.state_root(),
                config.current_height,
                "operator approval signs a different dashboard root",
            ));
        }
        if approval.status.blocks_deploy() {
            blockers.push(DeploymentBlocker::new(
                DeployBlockerKind::OperatorRejected,
                &approval.approval_id,
                &approval.state_root(),
                config.current_height,
                "operator dashboard approval is rejected, missing, or stale",
            ));
        }
    }
    if !production.fail_closed_armed
        || !production.abort_root_armed
        || !production.rollback_root_armed
        || !production.deployment_roots_match()
    {
        blockers.push(DeploymentBlocker::new(
            DeployBlockerKind::ProductionNotFailClosed,
            &production.deployment_id,
            &production.state_root(),
            config.current_height,
            "production deployment state is not fail-closed with rollback and abort roots armed",
        ));
    }
    if production.wallet_hold_active {
        blockers.push(DeploymentBlocker::new(
            DeployBlockerKind::WalletHoldActive,
            &production.deployment_id,
            &production.state_root(),
            config.current_height,
            "production wallet hold remains active",
        ));
    }
    blockers
}

fn build_roots(
    config: &Config,
    wave83: &Wave83GoNoGoBinding,
    wallets: &BTreeMap<String, WalletScanConfirmation>,
    escapes: &BTreeMap<String, UserEscapeConfirmation>,
    replays: &BTreeMap<String, WatchtowerReplayEvidence>,
    rollbacks: &BTreeMap<String, RollbackAbortProof>,
    approvals: &BTreeMap<String, OperatorDashboardApproval>,
    production: &ProductionDeploymentState,
    hold_criteria: &[GuardCriterion],
    unhold_criteria: &[GuardCriterion],
    blockers: &[DeploymentBlocker],
) -> GuardRoots {
    let wave83_binding_root = wave83.state_root();
    let wallet_scan_root = merkle_root(
        "WAVE84-ROOT-WALLET-SCANS",
        &wallets
            .values()
            .map(WalletScanConfirmation::public_record)
            .collect::<Vec<_>>(),
    );
    let user_escape_root = merkle_root(
        "WAVE84-ROOT-USER-ESCAPES",
        &escapes
            .values()
            .map(UserEscapeConfirmation::public_record)
            .collect::<Vec<_>>(),
    );
    let watchtower_replay_root = merkle_root(
        "WAVE84-ROOT-WATCHTOWER-REPLAYS",
        &replays
            .values()
            .map(WatchtowerReplayEvidence::public_record)
            .collect::<Vec<_>>(),
    );
    let rollback_abort_root = merkle_root(
        "WAVE84-ROOT-ROLLBACK-ABORTS",
        &rollbacks
            .values()
            .map(RollbackAbortProof::public_record)
            .collect::<Vec<_>>(),
    );
    let operator_approval_root = merkle_root(
        "WAVE84-ROOT-OPERATOR-APPROVALS",
        &approvals
            .values()
            .map(OperatorDashboardApproval::public_record)
            .collect::<Vec<_>>(),
    );
    let production_state_root = production.state_root();
    let hold_criteria_root = merkle_root(
        "WAVE84-ROOT-HOLD-CRITERIA",
        &hold_criteria
            .iter()
            .map(GuardCriterion::public_record)
            .collect::<Vec<_>>(),
    );
    let unhold_criteria_root = merkle_root(
        "WAVE84-ROOT-UNHOLD-CRITERIA",
        &unhold_criteria
            .iter()
            .map(GuardCriterion::public_record)
            .collect::<Vec<_>>(),
    );
    let blocker_root = merkle_root(
        "WAVE84-ROOT-DEPLOYMENT-BLOCKERS",
        &blockers
            .iter()
            .map(DeploymentBlocker::public_record)
            .collect::<Vec<_>>(),
    );
    let deployment_guard_root = domain_hash(
        "WAVE84-DEPLOYMENT-GUARD-ROOT",
        &[
            HashPart::Str(&config.chain_id),
            HashPart::Str(&config.protocol_version),
            HashPart::U64(config.current_height),
            HashPart::Str(&wave83_binding_root),
            HashPart::Str(&wallet_scan_root),
            HashPart::Str(&user_escape_root),
            HashPart::Str(&watchtower_replay_root),
            HashPart::Str(&rollback_abort_root),
            HashPart::Str(&operator_approval_root),
            HashPart::Str(&production_state_root),
            HashPart::Str(&hold_criteria_root),
            HashPart::Str(&unhold_criteria_root),
            HashPart::Str(&blocker_root),
        ],
        32,
    );
    GuardRoots {
        wave83_binding_root,
        wallet_scan_root,
        user_escape_root,
        watchtower_replay_root,
        rollback_abort_root,
        operator_approval_root,
        production_state_root,
        hold_criteria_root,
        unhold_criteria_root,
        blocker_root,
        deployment_guard_root,
    }
}

fn build_decision(
    config: &Config,
    production: &ProductionDeploymentState,
    escapes: &BTreeMap<String, UserEscapeConfirmation>,
    replays: &BTreeMap<String, WatchtowerReplayEvidence>,
    approvals: &BTreeMap<String, OperatorDashboardApproval>,
    blockers: &[DeploymentBlocker],
    roots: &GuardRoots,
) -> DeploymentGuardDecision {
    let blocker_count = blockers.len();
    let wallet_hold_active = production.wallet_hold_active
        || blockers
            .iter()
            .any(|blocker| blocker.lane == GuardLane::WalletHoldCriteria);
    let rollback_required = blockers.iter().any(|blocker| {
        matches!(
            blocker.blocker_kind,
            DeployBlockerKind::ProductionNotFailClosed | DeployBlockerKind::RollbackProofMissing
        )
    });
    let abort_required = blockers.iter().any(|blocker| {
        matches!(
            blocker.blocker_kind,
            DeployBlockerKind::ReleasePolicyNoGo
                | DeployBlockerKind::AbortRootMissing
                | DeployBlockerKind::DeploymentWindowNotOpen
        )
    });
    let deploy_allowed = blocker_count == 0 && config.fail_closed && production.fail_closed_armed;
    let decision = if deploy_allowed {
        GuardDecisionKind::DeployAllowed
    } else if rollback_required {
        GuardDecisionKind::RollbackRequired
    } else if abort_required {
        GuardDecisionKind::AbortDeployment
    } else if wallet_hold_active {
        GuardDecisionKind::HoldWallet
    } else {
        GuardDecisionKind::FailClosed
    };
    let decision_root = domain_hash(
        "WAVE84-DEPLOYMENT-GUARD-DECISION",
        &[
            HashPart::Str(decision.as_str()),
            HashPart::U64(blocker_count as u64),
            HashPart::U64(approvals.len() as u64),
            HashPart::U64(replays.len() as u64),
            HashPart::U64(escapes.len() as u64),
            HashPart::Str(&roots.deployment_guard_root),
        ],
        32,
    );
    DeploymentGuardDecision {
        decision,
        deploy_allowed: decision.allows_deploy(),
        fail_closed: !deploy_allowed && config.fail_closed,
        wallet_hold_active,
        rollback_required,
        abort_required,
        blocker_count,
        operator_approval_count: approvals.len(),
        watchtower_replay_count: replays.len(),
        user_escape_count: escapes.len(),
        decision_root,
    }
}

fn approval_quorum(
    config: &Config,
    wave83: &Wave83GoNoGoBinding,
    approvals: &BTreeMap<String, OperatorDashboardApproval>,
) -> usize {
    let mut operators = BTreeSet::new();
    for approval in approvals.values() {
        if approval.status.accepted()
            && approval.release_policy_root == wave83.release_policy_root
            && (!config.require_dashboard_root_match
                || approval.dashboard_root == wave83.dashboard_root)
        {
            operators.insert(approval.operator_id.clone());
        }
    }
    operators.len()
}

fn rollback_ready(config: &Config, rollbacks: &BTreeMap<String, RollbackAbortProof>) -> bool {
    if rollbacks.len() < usize::from(config.min_rollback_proofs) {
        return false;
    }
    if config.require_abort_root
        && !rollbacks.values().any(|proof| {
            proof.proof_kind == RollbackProofKind::AbortRoot && proof.status.accepted()
        })
    {
        return false;
    }
    rollbacks.values().all(|proof| proof.status.accepted())
}

fn sample_root(label: &str) -> String {
    domain_hash(
        "WAVE84-DEPLOYMENT-GUARD-SAMPLE",
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
