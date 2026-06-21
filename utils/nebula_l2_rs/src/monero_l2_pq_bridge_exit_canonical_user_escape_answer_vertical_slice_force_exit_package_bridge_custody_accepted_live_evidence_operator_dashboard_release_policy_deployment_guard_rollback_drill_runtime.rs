use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageBridgeCustodyAcceptedLiveEvidenceOperatorDashboardReleasePolicyDeploymentGuardRollbackDrillRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_BRIDGE_CUSTODY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-bridge-custody-accepted-live-evidence-operator-dashboard-release-policy-deployment-guard-rollback-drill-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_BRIDGE_CUSTODY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ROLLBACK_DRILL_SUITE: &str =
    "monero-l2-pq-bridge-custody-deployment-guard-rollback-drill-v1";
pub const DEFAULT_WAVE: u64 = 85;
pub const DEFAULT_SOURCE_WAVE: u64 = 84;
pub const DEFAULT_DRILL_HEIGHT: u64 = 1_445_216;
pub const DEFAULT_RELEASE_HEIGHT: u64 = 2_913_168;
pub const DEFAULT_MIN_OPERATOR_ACKS: u64 = 5;
pub const DEFAULT_MIN_OPERATOR_WEIGHT: u64 = 82;
pub const DEFAULT_MIN_SIGNER_ABORTS: u64 = 4;
pub const DEFAULT_MIN_SIGNER_ABORT_WEIGHT: u64 = 67;
pub const DEFAULT_MIN_RELEASE_ABORT_PROOFS: u64 = 3;
pub const DEFAULT_MIN_RESERVE_ROLLBACKS: u64 = 3;
pub const DEFAULT_MIN_CHALLENGE_ROLLBACK_BLOCKS: u64 = 96;
pub const DEFAULT_MIN_HOLD_UNHOLD_TRANSITIONS: u64 = 4;
pub const DEFAULT_MAX_SOURCE_GUARD_AGE_BLOCKS: u64 = 160;
pub const DEFAULT_ROLLBACK_REHEARSAL_ROUNDS: u64 = 3;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Accepted,
    Pending,
    Rejected,
    Expired,
    Blocked,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Pending => "pending",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Blocked => "blocked",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }

    pub fn blocks(self) -> bool {
        matches!(self, Self::Rejected | Self::Expired | Self::Blocked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackDrillPhase {
    SourceGuardBound,
    CustodyTranscriptRollback,
    SignerAbortIssued,
    ReleaseObservationRolledBack,
    ReserveHandoffRolledBack,
    ChallengeWindowRolledBack,
    OperatorAccepted,
    HoldUnholdVerified,
    FailClosed,
}

impl RollbackDrillPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceGuardBound => "source_guard_bound",
            Self::CustodyTranscriptRollback => "custody_transcript_rollback",
            Self::SignerAbortIssued => "signer_abort_issued",
            Self::ReleaseObservationRolledBack => "release_observation_rolled_back",
            Self::ReserveHandoffRolledBack => "reserve_handoff_rolled_back",
            Self::ChallengeWindowRolledBack => "challenge_window_rolled_back",
            Self::OperatorAccepted => "operator_accepted",
            Self::HoldUnholdVerified => "hold_unhold_verified",
            Self::FailClosed => "fail_closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerAbortCommandKind {
    StopCosign,
    RevokeSession,
    FreezeKeyShare,
    PublishAbortRoot,
    AcknowledgeHold,
}

impl SignerAbortCommandKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StopCosign => "stop_cosign",
            Self::RevokeSession => "revoke_session",
            Self::FreezeKeyShare => "freeze_key_share",
            Self::PublishAbortRoot => "publish_abort_root",
            Self::AcknowledgeHold => "acknowledge_hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseRollbackMarkerKind {
    TxBroadcastSuppressed,
    MempoolAbsenceObserved,
    RingMemberWatchReset,
    ViewKeyScanRewound,
    ReleaseReceiptInvalidated,
}

impl ReleaseRollbackMarkerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TxBroadcastSuppressed => "tx_broadcast_suppressed",
            Self::MempoolAbsenceObserved => "mempool_absence_observed",
            Self::RingMemberWatchReset => "ring_member_watch_reset",
            Self::ViewKeyScanRewound => "view_key_scan_rewound",
            Self::ReleaseReceiptInvalidated => "release_receipt_invalidated",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveRollbackKind {
    HandoffEnvelopeRevoked,
    ReserveDebitSuppressed,
    OperatorSessionClosed,
    AccountingMirrorRewound,
    ReplacementHandoffQueued,
}

impl ReserveRollbackKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HandoffEnvelopeRevoked => "handoff_envelope_revoked",
            Self::ReserveDebitSuppressed => "reserve_debit_suppressed",
            Self::OperatorSessionClosed => "operator_session_closed",
            Self::AccountingMirrorRewound => "accounting_mirror_rewound",
            Self::ReplacementHandoffQueued => "replacement_handoff_queued",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldUnholdAction {
    HoldAsserted,
    UnholdAttempted,
    UnholdDenied,
    HoldReasserted,
    FailClosedVerified,
}

impl HoldUnholdAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HoldAsserted => "hold_asserted",
            Self::UnholdAttempted => "unhold_attempted",
            Self::UnholdDenied => "unhold_denied",
            Self::HoldReasserted => "hold_reasserted",
            Self::FailClosedVerified => "fail_closed_verified",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRole {
    CustodyLead,
    ReleaseCoordinator,
    IncidentCommander,
    MoneroObserver,
    ReserveOperator,
    DashboardOperator,
}

impl OperatorRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CustodyLead => "custody_lead",
            Self::ReleaseCoordinator => "release_coordinator",
            Self::IncidentCommander => "incident_commander",
            Self::MoneroObserver => "monero_observer",
            Self::ReserveOperator => "reserve_operator",
            Self::DashboardOperator => "dashboard_operator",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackBlockerKind {
    SourceDeploymentGuardRootMissing,
    SourceDeploymentGuardStale,
    SourceDeploymentGuardRejected,
    CustodyTranscriptRootMissing,
    CustodyRollbackTranscriptRootMissing,
    SignerAbortQuorumLow,
    SignerAbortWeightLow,
    ReleaseAbortProofsLow,
    ReleaseRollbackMarkerMissing,
    ReserveRollbackRootMissing,
    ReserveRollbackCountLow,
    ChallengeRollbackInsufficient,
    OperatorAcknowledgementQuorumLow,
    OperatorAcknowledgementWeightLow,
    HoldUnholdTransitionCountLow,
    ReleaseUnheldDuringDrill,
    FailClosedStateMissing,
    DrillVerdictRejected,
}

impl RollbackBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceDeploymentGuardRootMissing => "source_deployment_guard_root_missing",
            Self::SourceDeploymentGuardStale => "source_deployment_guard_stale",
            Self::SourceDeploymentGuardRejected => "source_deployment_guard_rejected",
            Self::CustodyTranscriptRootMissing => "custody_transcript_root_missing",
            Self::CustodyRollbackTranscriptRootMissing => {
                "custody_rollback_transcript_root_missing"
            }
            Self::SignerAbortQuorumLow => "signer_abort_quorum_low",
            Self::SignerAbortWeightLow => "signer_abort_weight_low",
            Self::ReleaseAbortProofsLow => "release_abort_proofs_low",
            Self::ReleaseRollbackMarkerMissing => "release_rollback_marker_missing",
            Self::ReserveRollbackRootMissing => "reserve_rollback_root_missing",
            Self::ReserveRollbackCountLow => "reserve_rollback_count_low",
            Self::ChallengeRollbackInsufficient => "challenge_rollback_insufficient",
            Self::OperatorAcknowledgementQuorumLow => "operator_acknowledgement_quorum_low",
            Self::OperatorAcknowledgementWeightLow => "operator_acknowledgement_weight_low",
            Self::HoldUnholdTransitionCountLow => "hold_unhold_transition_count_low",
            Self::ReleaseUnheldDuringDrill => "release_unheld_during_drill",
            Self::FailClosedStateMissing => "fail_closed_state_missing",
            Self::DrillVerdictRejected => "drill_verdict_rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub rollback_drill_suite: String,
    pub drill_id: String,
    pub source_deployment_guard_id: String,
    pub release_policy_id: String,
    pub bridge_custody_lane_id: String,
    pub wave: u64,
    pub source_wave: u64,
    pub drill_height: u64,
    pub release_height: u64,
    pub max_source_guard_age_blocks: u64,
    pub min_operator_acknowledgements: u64,
    pub min_operator_weight: u64,
    pub min_signer_abort_commands: u64,
    pub min_signer_abort_weight: u64,
    pub min_release_abort_proofs: u64,
    pub min_reserve_rollback_count: u64,
    pub min_challenge_rollback_blocks: u64,
    pub min_hold_unhold_transitions: u64,
    pub rollback_rehearsal_rounds: u64,
    pub require_source_deployment_guard_root: bool,
    pub require_custody_rollback_transcript: bool,
    pub require_signer_abort_commands: bool,
    pub require_release_abort_proofs: bool,
    pub require_release_rollback_markers: bool,
    pub require_reserve_rollback: bool,
    pub require_challenge_window_rollback: bool,
    pub require_operator_acknowledgements: bool,
    pub require_hold_unhold_verdict: bool,
    pub require_fail_closed_release: bool,
    pub fail_closed: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            rollback_drill_suite: ROLLBACK_DRILL_SUITE.to_string(),
            drill_id: runtime_id("wave-85-bridge-custody-rollback-drill"),
            source_deployment_guard_id: runtime_id(
                "wave-84-bridge-custody-release-policy-deployment-guard",
            ),
            release_policy_id: runtime_id("force-exit-package-bridge-custody-release-policy"),
            bridge_custody_lane_id: "bridge_custody".to_string(),
            wave: DEFAULT_WAVE,
            source_wave: DEFAULT_SOURCE_WAVE,
            drill_height: DEFAULT_DRILL_HEIGHT,
            release_height: DEFAULT_RELEASE_HEIGHT,
            max_source_guard_age_blocks: DEFAULT_MAX_SOURCE_GUARD_AGE_BLOCKS,
            min_operator_acknowledgements: DEFAULT_MIN_OPERATOR_ACKS,
            min_operator_weight: DEFAULT_MIN_OPERATOR_WEIGHT,
            min_signer_abort_commands: DEFAULT_MIN_SIGNER_ABORTS,
            min_signer_abort_weight: DEFAULT_MIN_SIGNER_ABORT_WEIGHT,
            min_release_abort_proofs: DEFAULT_MIN_RELEASE_ABORT_PROOFS,
            min_reserve_rollback_count: DEFAULT_MIN_RESERVE_ROLLBACKS,
            min_challenge_rollback_blocks: DEFAULT_MIN_CHALLENGE_ROLLBACK_BLOCKS,
            min_hold_unhold_transitions: DEFAULT_MIN_HOLD_UNHOLD_TRANSITIONS,
            rollback_rehearsal_rounds: DEFAULT_ROLLBACK_REHEARSAL_ROUNDS,
            require_source_deployment_guard_root: true,
            require_custody_rollback_transcript: true,
            require_signer_abort_commands: true,
            require_release_abort_proofs: true,
            require_release_rollback_markers: true,
            require_reserve_rollback: true,
            require_challenge_window_rollback: true,
            require_operator_acknowledgements: true,
            require_hold_unhold_verdict: true,
            require_fail_closed_release: true,
            fail_closed: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("rollback_drill_suite", &self.rollback_drill_suite)?;
        ensure_non_empty("drill_id", &self.drill_id)?;
        ensure_non_empty(
            "source_deployment_guard_id",
            &self.source_deployment_guard_id,
        )?;
        ensure_non_empty("release_policy_id", &self.release_policy_id)?;
        ensure_non_empty("bridge_custody_lane_id", &self.bridge_custody_lane_id)?;
        ensure(
            self.wave > self.source_wave,
            "rollback drill wave must follow source wave",
        )?;
        ensure(self.drill_height > 0, "drill height must be non-zero")?;
        ensure(self.release_height > 0, "release height must be non-zero")?;
        ensure(
            self.max_source_guard_age_blocks > 0,
            "source guard age window must be non-zero",
        )?;
        ensure(
            self.min_operator_acknowledgements > 0,
            "operator acknowledgement threshold must be non-zero",
        )?;
        ensure(
            self.min_operator_weight > 0,
            "operator acknowledgement weight threshold must be non-zero",
        )?;
        ensure(
            self.min_signer_abort_commands > 0,
            "signer abort command threshold must be non-zero",
        )?;
        ensure(
            self.min_signer_abort_weight > 0,
            "signer abort weight threshold must be non-zero",
        )?;
        ensure(
            self.min_release_abort_proofs > 0,
            "release abort proof threshold must be non-zero",
        )?;
        ensure(
            self.min_reserve_rollback_count > 0,
            "reserve rollback threshold must be non-zero",
        )?;
        ensure(
            self.min_challenge_rollback_blocks > 0,
            "challenge rollback window must be non-zero",
        )?;
        ensure(
            self.min_hold_unhold_transitions > 0,
            "hold/unhold transition threshold must be non-zero",
        )?;
        ensure(
            self.rollback_rehearsal_rounds > 0,
            "rollback rehearsal rounds must be non-zero",
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
            "drill_id": self.drill_id,
            "source_deployment_guard_id": self.source_deployment_guard_id,
            "release_policy_id": self.release_policy_id,
            "bridge_custody_lane_id": self.bridge_custody_lane_id,
            "wave": self.wave,
            "source_wave": self.source_wave,
            "drill_height": self.drill_height,
            "release_height": self.release_height,
            "max_source_guard_age_blocks": self.max_source_guard_age_blocks,
            "min_operator_acknowledgements": self.min_operator_acknowledgements,
            "min_operator_weight": self.min_operator_weight,
            "min_signer_abort_commands": self.min_signer_abort_commands,
            "min_signer_abort_weight": self.min_signer_abort_weight,
            "min_release_abort_proofs": self.min_release_abort_proofs,
            "min_reserve_rollback_count": self.min_reserve_rollback_count,
            "min_challenge_rollback_blocks": self.min_challenge_rollback_blocks,
            "min_hold_unhold_transitions": self.min_hold_unhold_transitions,
            "rollback_rehearsal_rounds": self.rollback_rehearsal_rounds,
            "require_source_deployment_guard_root": self.require_source_deployment_guard_root,
            "require_custody_rollback_transcript": self.require_custody_rollback_transcript,
            "require_signer_abort_commands": self.require_signer_abort_commands,
            "require_release_abort_proofs": self.require_release_abort_proofs,
            "require_release_rollback_markers": self.require_release_rollback_markers,
            "require_reserve_rollback": self.require_reserve_rollback,
            "require_challenge_window_rollback": self.require_challenge_window_rollback,
            "require_operator_acknowledgements": self.require_operator_acknowledgements,
            "require_hold_unhold_verdict": self.require_hold_unhold_verdict,
            "require_fail_closed_release": self.require_fail_closed_release,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceDeploymentGuard {
    pub guard_id: String,
    pub observed_height: u64,
    pub deployment_guard_root: String,
    pub custody_evidence_root: String,
    pub signer_handoff_root: String,
    pub release_observation_root: String,
    pub reserve_handoff_root: String,
    pub challenge_clearance_root: String,
    pub hold_unhold_root: String,
    pub operator_dashboard_root: String,
    pub decision_root: String,
    pub status: EvidenceStatus,
}

impl SourceDeploymentGuard {
    pub fn devnet(config: &Config) -> Self {
        let observed_height = config.drill_height.saturating_sub(24);
        let deployment_guard_root = source_guard_component_root(config, "deployment-guard");
        let custody_evidence_root = source_guard_component_root(config, "custody-evidence");
        let signer_handoff_root = source_guard_component_root(config, "signer-handoff");
        let release_observation_root = source_guard_component_root(config, "release-observation");
        let reserve_handoff_root = source_guard_component_root(config, "reserve-handoff");
        let challenge_clearance_root = source_guard_component_root(config, "challenge-clearance");
        let hold_unhold_root = source_guard_component_root(config, "hold-unhold");
        let operator_dashboard_root = source_guard_component_root(config, "operator-dashboard");
        let decision_root = merkle_root(
            "ROLLBACK-DRILL-SOURCE-GUARD-DECISION",
            &[
                json!({"deployment_guard_root": deployment_guard_root}),
                json!({"custody_evidence_root": custody_evidence_root}),
                json!({"signer_handoff_root": signer_handoff_root}),
                json!({"release_observation_root": release_observation_root}),
                json!({"reserve_handoff_root": reserve_handoff_root}),
                json!({"challenge_clearance_root": challenge_clearance_root}),
                json!({"hold_unhold_root": hold_unhold_root}),
                json!({"operator_dashboard_root": operator_dashboard_root}),
            ],
        );
        Self {
            guard_id: config.source_deployment_guard_id.clone(),
            observed_height,
            deployment_guard_root,
            custody_evidence_root,
            signer_handoff_root,
            release_observation_root,
            reserve_handoff_root,
            challenge_clearance_root,
            hold_unhold_root,
            operator_dashboard_root,
            decision_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn stale(&self, config: &Config) -> bool {
        config.drill_height.saturating_sub(self.observed_height)
            > config.max_source_guard_age_blocks
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.status.accepted()
            && !self.stale(config)
            && !self.deployment_guard_root.is_empty()
            && !self.custody_evidence_root.is_empty()
            && !self.signer_handoff_root.is_empty()
            && !self.release_observation_root.is_empty()
            && !self.reserve_handoff_root.is_empty()
            && !self.challenge_clearance_root.is_empty()
            && !self.hold_unhold_root.is_empty()
            && !self.operator_dashboard_root.is_empty()
            && !self.decision_root.is_empty()
    }

    pub fn blockers(&self, config: &Config) -> Vec<RollbackBlockerKind> {
        let mut blockers = Vec::new();
        if config.require_source_deployment_guard_root && self.deployment_guard_root.is_empty() {
            blockers.push(RollbackBlockerKind::SourceDeploymentGuardRootMissing);
        }
        if self.stale(config) {
            blockers.push(RollbackBlockerKind::SourceDeploymentGuardStale);
        }
        if self.status.blocks() || !self.status.accepted() {
            blockers.push(RollbackBlockerKind::SourceDeploymentGuardRejected);
        }
        blockers
    }

    pub fn public_record(&self) -> Value {
        json!({
            "guard_id": self.guard_id,
            "observed_height": self.observed_height,
            "deployment_guard_root": self.deployment_guard_root,
            "custody_evidence_root": self.custody_evidence_root,
            "signer_handoff_root": self.signer_handoff_root,
            "release_observation_root": self.release_observation_root,
            "reserve_handoff_root": self.reserve_handoff_root,
            "challenge_clearance_root": self.challenge_clearance_root,
            "hold_unhold_root": self.hold_unhold_root,
            "operator_dashboard_root": self.operator_dashboard_root,
            "decision_root": self.decision_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-SOURCE-GUARD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CustodyRollbackTranscript {
    pub transcript_id: String,
    pub ceremony_round: u64,
    pub pre_rollback_transcript_root: String,
    pub rollback_transcript_root: String,
    pub custody_binding_root: String,
    pub release_hold_root: String,
    pub abort_notice_root: String,
    pub replay_receipt_root: String,
    pub operator_view_root: String,
    pub status: EvidenceStatus,
}

impl CustodyRollbackTranscript {
    pub fn devnet(config: &Config, ceremony_round: u64, label: &str) -> Self {
        let transcript_id =
            evidence_id(config, "custody-rollback-transcript", label, ceremony_round);
        let pre_rollback_transcript_root =
            transcript_component_root(config, &transcript_id, "pre-rollback-transcript");
        let rollback_transcript_root =
            transcript_component_root(config, &transcript_id, "rollback-transcript");
        let custody_binding_root =
            transcript_component_root(config, &transcript_id, "custody-binding");
        let release_hold_root = transcript_component_root(config, &transcript_id, "release-hold");
        let abort_notice_root = transcript_component_root(config, &transcript_id, "abort-notice");
        let replay_receipt_root =
            transcript_component_root(config, &transcript_id, "replay-receipt");
        let operator_view_root = merkle_root(
            "ROLLBACK-DRILL-CUSTODY-TRANSCRIPT-OPERATOR-VIEW",
            &[
                json!({"pre_rollback_transcript_root": pre_rollback_transcript_root}),
                json!({"rollback_transcript_root": rollback_transcript_root}),
                json!({"custody_binding_root": custody_binding_root}),
                json!({"release_hold_root": release_hold_root}),
                json!({"abort_notice_root": abort_notice_root}),
                json!({"replay_receipt_root": replay_receipt_root}),
            ],
        );
        Self {
            transcript_id,
            ceremony_round,
            pre_rollback_transcript_root,
            rollback_transcript_root,
            custody_binding_root,
            release_hold_root,
            abort_notice_root,
            replay_receipt_root,
            operator_view_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self) -> bool {
        self.status.accepted()
            && !self.pre_rollback_transcript_root.is_empty()
            && !self.rollback_transcript_root.is_empty()
            && !self.custody_binding_root.is_empty()
            && !self.release_hold_root.is_empty()
            && !self.abort_notice_root.is_empty()
            && !self.replay_receipt_root.is_empty()
    }

    pub fn blockers(&self, config: &Config) -> Vec<RollbackBlockerKind> {
        let mut blockers = Vec::new();
        if config.require_custody_rollback_transcript
            && self.pre_rollback_transcript_root.is_empty()
        {
            blockers.push(RollbackBlockerKind::CustodyTranscriptRootMissing);
        }
        if config.require_custody_rollback_transcript && self.rollback_transcript_root.is_empty() {
            blockers.push(RollbackBlockerKind::CustodyRollbackTranscriptRootMissing);
        }
        if self.status.blocks() || !self.status.accepted() {
            blockers.push(RollbackBlockerKind::DrillVerdictRejected);
        }
        blockers
    }

    pub fn public_record(&self) -> Value {
        json!({
            "transcript_id": self.transcript_id,
            "ceremony_round": self.ceremony_round,
            "pre_rollback_transcript_root": self.pre_rollback_transcript_root,
            "rollback_transcript_root": self.rollback_transcript_root,
            "custody_binding_root": self.custody_binding_root,
            "release_hold_root": self.release_hold_root,
            "abort_notice_root": self.abort_notice_root,
            "replay_receipt_root": self.replay_receipt_root,
            "operator_view_root": self.operator_view_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-CUSTODY-TRANSCRIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignerAbortCommand {
    pub command_id: String,
    pub signer_id: String,
    pub command_kind: SignerAbortCommandKind,
    pub signer_weight: u64,
    pub issued_at_height: u64,
    pub command_root: String,
    pub signed_abort_root: String,
    pub session_revoke_root: String,
    pub custody_transcript_root: String,
    pub dashboard_receipt_root: String,
    pub status: EvidenceStatus,
}

impl SignerAbortCommand {
    pub fn devnet(
        config: &Config,
        ordinal: u64,
        signer_id: &str,
        command_kind: SignerAbortCommandKind,
        signer_weight: u64,
    ) -> Self {
        let command_id = evidence_id(config, "signer-abort-command", signer_id, ordinal);
        let command_root = signer_abort_component_root(config, &command_id, "command");
        let signed_abort_root = signer_abort_component_root(config, &command_id, "signed-abort");
        let session_revoke_root =
            signer_abort_component_root(config, &command_id, "session-revoke");
        let custody_transcript_root =
            signer_abort_component_root(config, &command_id, "custody-transcript");
        let dashboard_receipt_root =
            signer_abort_component_root(config, &command_id, "dashboard-receipt");
        Self {
            command_id,
            signer_id: signer_id.to_string(),
            command_kind,
            signer_weight,
            issued_at_height: config.drill_height + ordinal,
            command_root,
            signed_abort_root,
            session_revoke_root,
            custody_transcript_root,
            dashboard_receipt_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self) -> bool {
        self.status.accepted()
            && !self.command_root.is_empty()
            && !self.signed_abort_root.is_empty()
            && !self.session_revoke_root.is_empty()
            && !self.custody_transcript_root.is_empty()
            && !self.dashboard_receipt_root.is_empty()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "command_id": self.command_id,
            "signer_id": self.signer_id,
            "command_kind": self.command_kind.as_str(),
            "signer_weight": self.signer_weight,
            "issued_at_height": self.issued_at_height,
            "command_root": self.command_root,
            "signed_abort_root": self.signed_abort_root,
            "session_revoke_root": self.session_revoke_root,
            "custody_transcript_root": self.custody_transcript_root,
            "dashboard_receipt_root": self.dashboard_receipt_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-SIGNER-ABORT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseTxAbortProof {
    pub proof_id: String,
    pub release_txid: String,
    pub proof_ordinal: u64,
    pub abort_intent_root: String,
    pub preimage_withheld_root: String,
    pub signer_refusal_root: String,
    pub broadcast_suppression_root: String,
    pub observation_rollback_root: String,
    pub status: EvidenceStatus,
}

impl ReleaseTxAbortProof {
    pub fn devnet(config: &Config, proof_ordinal: u64, release_txid: &str) -> Self {
        let proof_id = evidence_id(
            config,
            "release-tx-abort-proof",
            release_txid,
            proof_ordinal,
        );
        let abort_intent_root = release_abort_component_root(config, &proof_id, "abort-intent");
        let preimage_withheld_root =
            release_abort_component_root(config, &proof_id, "preimage-withheld");
        let signer_refusal_root = release_abort_component_root(config, &proof_id, "signer-refusal");
        let broadcast_suppression_root =
            release_abort_component_root(config, &proof_id, "broadcast-suppression");
        let observation_rollback_root =
            release_abort_component_root(config, &proof_id, "observation-rollback");
        Self {
            proof_id,
            release_txid: release_txid.to_string(),
            proof_ordinal,
            abort_intent_root,
            preimage_withheld_root,
            signer_refusal_root,
            broadcast_suppression_root,
            observation_rollback_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self) -> bool {
        self.status.accepted()
            && !self.abort_intent_root.is_empty()
            && !self.preimage_withheld_root.is_empty()
            && !self.signer_refusal_root.is_empty()
            && !self.broadcast_suppression_root.is_empty()
            && !self.observation_rollback_root.is_empty()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "release_txid": self.release_txid,
            "proof_ordinal": self.proof_ordinal,
            "abort_intent_root": self.abort_intent_root,
            "preimage_withheld_root": self.preimage_withheld_root,
            "signer_refusal_root": self.signer_refusal_root,
            "broadcast_suppression_root": self.broadcast_suppression_root,
            "observation_rollback_root": self.observation_rollback_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-RELEASE-ABORT-PROOF", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseObservationRollbackMarker {
    pub marker_id: String,
    pub marker_kind: ReleaseRollbackMarkerKind,
    pub release_txid: String,
    pub observed_at_height: u64,
    pub previous_observation_root: String,
    pub rollback_marker_root: String,
    pub monitor_receipt_root: String,
    pub dashboard_cell_root: String,
    pub status: EvidenceStatus,
}

impl ReleaseObservationRollbackMarker {
    pub fn devnet(
        config: &Config,
        ordinal: u64,
        marker_kind: ReleaseRollbackMarkerKind,
        release_txid: &str,
    ) -> Self {
        let marker_id = evidence_id(
            config,
            "release-observation-rollback",
            marker_kind.as_str(),
            ordinal,
        );
        let previous_observation_root =
            release_marker_component_root(config, &marker_id, "previous-observation");
        let rollback_marker_root = release_marker_component_root(config, &marker_id, "rollback");
        let monitor_receipt_root =
            release_marker_component_root(config, &marker_id, "monitor-receipt");
        let dashboard_cell_root =
            release_marker_component_root(config, &marker_id, "dashboard-cell");
        Self {
            marker_id,
            marker_kind,
            release_txid: release_txid.to_string(),
            observed_at_height: config.release_height + ordinal,
            previous_observation_root,
            rollback_marker_root,
            monitor_receipt_root,
            dashboard_cell_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self) -> bool {
        self.status.accepted()
            && !self.previous_observation_root.is_empty()
            && !self.rollback_marker_root.is_empty()
            && !self.monitor_receipt_root.is_empty()
            && !self.dashboard_cell_root.is_empty()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "marker_id": self.marker_id,
            "marker_kind": self.marker_kind.as_str(),
            "release_txid": self.release_txid,
            "observed_at_height": self.observed_at_height,
            "previous_observation_root": self.previous_observation_root,
            "rollback_marker_root": self.rollback_marker_root,
            "monitor_receipt_root": self.monitor_receipt_root,
            "dashboard_cell_root": self.dashboard_cell_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-RELEASE-MARKER", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveRollbackEvidence {
    pub rollback_id: String,
    pub reserve_operator_id: String,
    pub rollback_kind: ReserveRollbackKind,
    pub sequence: u64,
    pub source_handoff_root: String,
    pub revoked_handoff_root: String,
    pub reserve_accounting_root: String,
    pub replacement_queue_root: String,
    pub operator_receipt_root: String,
    pub status: EvidenceStatus,
}

impl ReserveRollbackEvidence {
    pub fn devnet(
        config: &Config,
        sequence: u64,
        reserve_operator_id: &str,
        rollback_kind: ReserveRollbackKind,
    ) -> Self {
        let rollback_id = evidence_id(config, "reserve-rollback", reserve_operator_id, sequence);
        let source_handoff_root = reserve_component_root(config, &rollback_id, "source-handoff");
        let revoked_handoff_root = reserve_component_root(config, &rollback_id, "revoked-handoff");
        let reserve_accounting_root =
            reserve_component_root(config, &rollback_id, "reserve-accounting");
        let replacement_queue_root =
            reserve_component_root(config, &rollback_id, "replacement-queue");
        let operator_receipt_root =
            reserve_component_root(config, &rollback_id, "operator-receipt");
        Self {
            rollback_id,
            reserve_operator_id: reserve_operator_id.to_string(),
            rollback_kind,
            sequence,
            source_handoff_root,
            revoked_handoff_root,
            reserve_accounting_root,
            replacement_queue_root,
            operator_receipt_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self) -> bool {
        self.status.accepted()
            && !self.source_handoff_root.is_empty()
            && !self.revoked_handoff_root.is_empty()
            && !self.reserve_accounting_root.is_empty()
            && !self.replacement_queue_root.is_empty()
            && !self.operator_receipt_root.is_empty()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rollback_id": self.rollback_id,
            "reserve_operator_id": self.reserve_operator_id,
            "rollback_kind": self.rollback_kind.as_str(),
            "sequence": self.sequence,
            "source_handoff_root": self.source_handoff_root,
            "revoked_handoff_root": self.revoked_handoff_root,
            "reserve_accounting_root": self.reserve_accounting_root,
            "replacement_queue_root": self.replacement_queue_root,
            "operator_receipt_root": self.operator_receipt_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-RESERVE-ROLLBACK", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeWindowRollback {
    pub challenge_id: String,
    pub source_clearance_root: String,
    pub rollback_window_root: String,
    pub dispute_reopen_root: String,
    pub answer_hold_root: String,
    pub elapsed_rollback_blocks: u64,
    pub active_challenges_after_rollback: u64,
    pub status: EvidenceStatus,
}

impl ChallengeWindowRollback {
    pub fn devnet(config: &Config) -> Self {
        let challenge_id = evidence_id(config, "challenge-window-rollback", "bridge-custody", 1);
        let source_clearance_root =
            challenge_component_root(config, &challenge_id, "source-clearance");
        let rollback_window_root =
            challenge_component_root(config, &challenge_id, "rollback-window");
        let dispute_reopen_root = challenge_component_root(config, &challenge_id, "dispute-reopen");
        let answer_hold_root = challenge_component_root(config, &challenge_id, "answer-hold");
        Self {
            challenge_id,
            source_clearance_root,
            rollback_window_root,
            dispute_reopen_root,
            answer_hold_root,
            elapsed_rollback_blocks: config.min_challenge_rollback_blocks + 12,
            active_challenges_after_rollback: 0,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.status.accepted()
            && self.elapsed_rollback_blocks >= config.min_challenge_rollback_blocks
            && self.active_challenges_after_rollback == 0
            && !self.source_clearance_root.is_empty()
            && !self.rollback_window_root.is_empty()
            && !self.dispute_reopen_root.is_empty()
            && !self.answer_hold_root.is_empty()
    }

    pub fn blockers(&self, config: &Config) -> Vec<RollbackBlockerKind> {
        let mut blockers = Vec::new();
        if config.require_challenge_window_rollback && !self.accepted(config) {
            blockers.push(RollbackBlockerKind::ChallengeRollbackInsufficient);
        }
        blockers
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "source_clearance_root": self.source_clearance_root,
            "rollback_window_root": self.rollback_window_root,
            "dispute_reopen_root": self.dispute_reopen_root,
            "answer_hold_root": self.answer_hold_root,
            "elapsed_rollback_blocks": self.elapsed_rollback_blocks,
            "active_challenges_after_rollback": self.active_challenges_after_rollback,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-CHALLENGE-WINDOW", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorAcknowledgement {
    pub acknowledgement_id: String,
    pub operator_id: String,
    pub role: OperatorRole,
    pub acknowledgement_weight: u64,
    pub acknowledged_at_height: u64,
    pub source_guard_root: String,
    pub rollback_drill_root: String,
    pub dashboard_cell_root: String,
    pub signed_statement_root: String,
    pub status: EvidenceStatus,
}

impl OperatorAcknowledgement {
    pub fn devnet(
        config: &Config,
        ordinal: u64,
        operator_id: &str,
        role: OperatorRole,
        acknowledgement_weight: u64,
    ) -> Self {
        let acknowledgement_id = evidence_id(config, "operator-ack", operator_id, ordinal);
        let source_guard_root =
            operator_component_root(config, &acknowledgement_id, role, "source-guard");
        let rollback_drill_root =
            operator_component_root(config, &acknowledgement_id, role, "rollback-drill");
        let dashboard_cell_root =
            operator_component_root(config, &acknowledgement_id, role, "dashboard-cell");
        let signed_statement_root =
            operator_component_root(config, &acknowledgement_id, role, "signed-statement");
        Self {
            acknowledgement_id,
            operator_id: operator_id.to_string(),
            role,
            acknowledgement_weight,
            acknowledged_at_height: config.drill_height + 20 + ordinal,
            source_guard_root,
            rollback_drill_root,
            dashboard_cell_root,
            signed_statement_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self) -> bool {
        self.status.accepted()
            && !self.source_guard_root.is_empty()
            && !self.rollback_drill_root.is_empty()
            && !self.dashboard_cell_root.is_empty()
            && !self.signed_statement_root.is_empty()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "acknowledgement_id": self.acknowledgement_id,
            "operator_id": self.operator_id,
            "role": self.role.as_str(),
            "acknowledgement_weight": self.acknowledgement_weight,
            "acknowledged_at_height": self.acknowledged_at_height,
            "source_guard_root": self.source_guard_root,
            "rollback_drill_root": self.rollback_drill_root,
            "dashboard_cell_root": self.dashboard_cell_root,
            "signed_statement_root": self.signed_statement_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-OPERATOR-ACK", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HoldUnholdDrillStep {
    pub step_id: String,
    pub step_index: u64,
    pub action: HoldUnholdAction,
    pub release_held_before: bool,
    pub release_held_after: bool,
    pub unhold_allowed: bool,
    pub fail_closed: bool,
    pub evidence_root: String,
    pub dashboard_cell_root: String,
}

impl HoldUnholdDrillStep {
    pub fn devnet(config: &Config, step_index: u64, action: HoldUnholdAction) -> Self {
        let step_id = evidence_id(config, "hold-unhold-step", action.as_str(), step_index);
        let release_held_before = !matches!(action, HoldUnholdAction::HoldAsserted);
        let release_held_after = true;
        let unhold_allowed = false;
        let fail_closed = true;
        let evidence_root = hold_unhold_component_root(config, &step_id, "evidence");
        let dashboard_cell_root = hold_unhold_component_root(config, &step_id, "dashboard-cell");
        Self {
            step_id,
            step_index,
            action,
            release_held_before,
            release_held_after,
            unhold_allowed,
            fail_closed,
            evidence_root,
            dashboard_cell_root,
        }
    }

    pub fn accepted(&self) -> bool {
        self.release_held_after
            && !self.unhold_allowed
            && self.fail_closed
            && !self.evidence_root.is_empty()
            && !self.dashboard_cell_root.is_empty()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "step_id": self.step_id,
            "step_index": self.step_index,
            "action": self.action.as_str(),
            "release_held_before": self.release_held_before,
            "release_held_after": self.release_held_after,
            "unhold_allowed": self.unhold_allowed,
            "fail_closed": self.fail_closed,
            "evidence_root": self.evidence_root,
            "dashboard_cell_root": self.dashboard_cell_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROLLBACK-DRILL-HOLD-UNHOLD-STEP", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RollbackBlocker {
    pub blocker_id: String,
    pub kind: RollbackBlockerKind,
    pub subject: String,
    pub evidence_root: String,
}

impl RollbackBlocker {
    pub fn new(
        config: &Config,
        kind: RollbackBlockerKind,
        subject: &str,
        evidence_root: String,
    ) -> Self {
        Self {
            blocker_id: evidence_id(
                config,
                "rollback-blocker",
                kind.as_str(),
                subject.len() as u64,
            ),
            kind,
            subject: subject.to_string(),
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "kind": self.kind.as_str(),
            "subject": self.subject,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RollbackDrillVerdict {
    pub release_held: bool,
    pub unhold_allowed: bool,
    pub fail_closed: bool,
    pub accepted: bool,
    pub blocker_count: usize,
    pub custody_transcript_count: usize,
    pub signer_abort_count: u64,
    pub signer_abort_weight: u64,
    pub release_abort_proof_count: u64,
    pub reserve_rollback_count: u64,
    pub operator_acknowledgement_count: u64,
    pub operator_acknowledgement_weight: u64,
    pub hold_unhold_transition_count: u64,
    pub evidence_root: String,
    pub blocker_root: String,
    pub verdict_root: String,
}

impl RollbackDrillVerdict {
    pub fn public_record(&self) -> Value {
        json!({
            "release_held": self.release_held,
            "unhold_allowed": self.unhold_allowed,
            "fail_closed": self.fail_closed,
            "accepted": self.accepted,
            "blocker_count": self.blocker_count,
            "custody_transcript_count": self.custody_transcript_count,
            "signer_abort_count": self.signer_abort_count,
            "signer_abort_weight": self.signer_abort_weight,
            "release_abort_proof_count": self.release_abort_proof_count,
            "reserve_rollback_count": self.reserve_rollback_count,
            "operator_acknowledgement_count": self.operator_acknowledgement_count,
            "operator_acknowledgement_weight": self.operator_acknowledgement_weight,
            "hold_unhold_transition_count": self.hold_unhold_transition_count,
            "evidence_root": self.evidence_root,
            "blocker_root": self.blocker_root,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub source_deployment_guard: SourceDeploymentGuard,
    pub custody_rollback_transcripts: Vec<CustodyRollbackTranscript>,
    pub signer_abort_commands: Vec<SignerAbortCommand>,
    pub release_abort_proofs: Vec<ReleaseTxAbortProof>,
    pub release_rollback_markers: Vec<ReleaseObservationRollbackMarker>,
    pub reserve_rollbacks: Vec<ReserveRollbackEvidence>,
    pub challenge_window_rollback: ChallengeWindowRollback,
    pub operator_acknowledgements: Vec<OperatorAcknowledgement>,
    pub hold_unhold_steps: Vec<HoldUnholdDrillStep>,
    pub phase_roots: BTreeMap<String, String>,
    pub blockers: Vec<RollbackBlocker>,
    pub verdict: RollbackDrillVerdict,
}

impl State {
    pub fn new(
        config: Config,
        source_deployment_guard: SourceDeploymentGuard,
        custody_rollback_transcripts: Vec<CustodyRollbackTranscript>,
        signer_abort_commands: Vec<SignerAbortCommand>,
        release_abort_proofs: Vec<ReleaseTxAbortProof>,
        release_rollback_markers: Vec<ReleaseObservationRollbackMarker>,
        reserve_rollbacks: Vec<ReserveRollbackEvidence>,
        challenge_window_rollback: ChallengeWindowRollback,
        operator_acknowledgements: Vec<OperatorAcknowledgement>,
        hold_unhold_steps: Vec<HoldUnholdDrillStep>,
    ) -> Result<Self> {
        config.validate()?;
        let phase_roots = build_phase_roots(
            &config,
            &source_deployment_guard,
            &custody_rollback_transcripts,
            &signer_abort_commands,
            &release_abort_proofs,
            &release_rollback_markers,
            &reserve_rollbacks,
            &challenge_window_rollback,
            &operator_acknowledgements,
            &hold_unhold_steps,
        );
        let evidence_root = merkle_root(
            "ROLLBACK-DRILL-EVIDENCE-ROOT",
            &phase_roots
                .iter()
                .map(|(phase, root)| json!({"phase": phase, "root": root}))
                .collect::<Vec<_>>(),
        );
        let blocker_kinds = evaluate_blocker_kinds(
            &config,
            &source_deployment_guard,
            &custody_rollback_transcripts,
            &signer_abort_commands,
            &release_abort_proofs,
            &release_rollback_markers,
            &reserve_rollbacks,
            &challenge_window_rollback,
            &operator_acknowledgements,
            &hold_unhold_steps,
        );
        let blockers = unique_blockers(&config, blocker_kinds, &evidence_root);
        let blocker_root = merkle_root(
            "ROLLBACK-DRILL-BLOCKER-ROOT",
            &blockers
                .iter()
                .map(RollbackBlocker::public_record)
                .collect::<Vec<_>>(),
        );
        let signer_abort_count = accepted_signer_abort_count(&signer_abort_commands);
        let signer_abort_weight = accepted_signer_abort_weight(&signer_abort_commands);
        let release_abort_proof_count = accepted_release_abort_proof_count(&release_abort_proofs);
        let reserve_rollback_count = accepted_reserve_rollback_count(&reserve_rollbacks);
        let operator_acknowledgement_count =
            accepted_operator_acknowledgement_count(&operator_acknowledgements);
        let operator_acknowledgement_weight =
            accepted_operator_acknowledgement_weight(&operator_acknowledgements);
        let hold_unhold_transition_count =
            accepted_hold_unhold_transition_count(&hold_unhold_steps);
        let release_held =
            hold_unhold_steps.iter().all(|step| step.release_held_after) && config.fail_closed;
        let unhold_allowed = hold_unhold_steps.iter().any(|step| step.unhold_allowed);
        let fail_closed =
            config.fail_closed && hold_unhold_steps.iter().all(|step| step.fail_closed);
        let accepted = blockers.is_empty() && release_held && !unhold_allowed && fail_closed;
        let verdict_root = domain_hash(
            "ROLLBACK-DRILL-VERDICT",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.drill_id),
                HashPart::Str(&evidence_root),
                HashPart::Str(&blocker_root),
                HashPart::U64(signer_abort_count),
                HashPart::U64(signer_abort_weight),
                HashPart::U64(operator_acknowledgement_count),
                HashPart::U64(operator_acknowledgement_weight),
                HashPart::Str(if accepted { "accepted" } else { "blocked" }),
            ],
            32,
        );
        let verdict = RollbackDrillVerdict {
            release_held,
            unhold_allowed,
            fail_closed,
            accepted,
            blocker_count: blockers.len(),
            custody_transcript_count: custody_rollback_transcripts.len(),
            signer_abort_count,
            signer_abort_weight,
            release_abort_proof_count,
            reserve_rollback_count,
            operator_acknowledgement_count,
            operator_acknowledgement_weight,
            hold_unhold_transition_count,
            evidence_root,
            blocker_root,
            verdict_root,
        };
        Ok(Self {
            config,
            source_deployment_guard,
            custody_rollback_transcripts,
            signer_abort_commands,
            release_abort_proofs,
            release_rollback_markers,
            reserve_rollbacks,
            challenge_window_rollback,
            operator_acknowledgements,
            hold_unhold_steps,
            phase_roots,
            blockers,
            verdict,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let source_deployment_guard = SourceDeploymentGuard::devnet(&config);
        let custody_rollback_transcripts = vec![
            CustodyRollbackTranscript::devnet(&config, 1, "custody-round-alpha"),
            CustodyRollbackTranscript::devnet(&config, 2, "custody-round-bravo"),
            CustodyRollbackTranscript::devnet(&config, 3, "custody-round-charlie"),
        ];
        let signer_abort_commands = vec![
            SignerAbortCommand::devnet(
                &config,
                1,
                "custody-signer-alpha",
                SignerAbortCommandKind::StopCosign,
                18,
            ),
            SignerAbortCommand::devnet(
                &config,
                2,
                "custody-signer-bravo",
                SignerAbortCommandKind::RevokeSession,
                17,
            ),
            SignerAbortCommand::devnet(
                &config,
                3,
                "custody-signer-charlie",
                SignerAbortCommandKind::FreezeKeyShare,
                16,
            ),
            SignerAbortCommand::devnet(
                &config,
                4,
                "custody-signer-delta",
                SignerAbortCommandKind::PublishAbortRoot,
                16,
            ),
            SignerAbortCommand::devnet(
                &config,
                5,
                "custody-signer-echo",
                SignerAbortCommandKind::AcknowledgeHold,
                8,
            ),
        ];
        let release_abort_proofs = vec![
            ReleaseTxAbortProof::devnet(&config, 1, "monero-release-tx-alpha"),
            ReleaseTxAbortProof::devnet(&config, 2, "monero-release-tx-bravo"),
            ReleaseTxAbortProof::devnet(&config, 3, "monero-release-tx-charlie"),
        ];
        let release_rollback_markers = vec![
            ReleaseObservationRollbackMarker::devnet(
                &config,
                1,
                ReleaseRollbackMarkerKind::TxBroadcastSuppressed,
                "monero-release-tx-alpha",
            ),
            ReleaseObservationRollbackMarker::devnet(
                &config,
                2,
                ReleaseRollbackMarkerKind::MempoolAbsenceObserved,
                "monero-release-tx-alpha",
            ),
            ReleaseObservationRollbackMarker::devnet(
                &config,
                3,
                ReleaseRollbackMarkerKind::RingMemberWatchReset,
                "monero-release-tx-bravo",
            ),
            ReleaseObservationRollbackMarker::devnet(
                &config,
                4,
                ReleaseRollbackMarkerKind::ViewKeyScanRewound,
                "monero-release-tx-bravo",
            ),
            ReleaseObservationRollbackMarker::devnet(
                &config,
                5,
                ReleaseRollbackMarkerKind::ReleaseReceiptInvalidated,
                "monero-release-tx-charlie",
            ),
        ];
        let reserve_rollbacks = vec![
            ReserveRollbackEvidence::devnet(
                &config,
                1,
                "reserve-operator-alpha",
                ReserveRollbackKind::HandoffEnvelopeRevoked,
            ),
            ReserveRollbackEvidence::devnet(
                &config,
                2,
                "reserve-operator-bravo",
                ReserveRollbackKind::ReserveDebitSuppressed,
            ),
            ReserveRollbackEvidence::devnet(
                &config,
                3,
                "reserve-operator-charlie",
                ReserveRollbackKind::OperatorSessionClosed,
            ),
            ReserveRollbackEvidence::devnet(
                &config,
                4,
                "reserve-operator-delta",
                ReserveRollbackKind::AccountingMirrorRewound,
            ),
            ReserveRollbackEvidence::devnet(
                &config,
                5,
                "reserve-operator-echo",
                ReserveRollbackKind::ReplacementHandoffQueued,
            ),
        ];
        let challenge_window_rollback = ChallengeWindowRollback::devnet(&config);
        let operator_acknowledgements = vec![
            OperatorAcknowledgement::devnet(
                &config,
                1,
                "operator-custody-lead",
                OperatorRole::CustodyLead,
                20,
            ),
            OperatorAcknowledgement::devnet(
                &config,
                2,
                "operator-release-coordinator",
                OperatorRole::ReleaseCoordinator,
                20,
            ),
            OperatorAcknowledgement::devnet(
                &config,
                3,
                "operator-incident-commander",
                OperatorRole::IncidentCommander,
                18,
            ),
            OperatorAcknowledgement::devnet(
                &config,
                4,
                "operator-monero-observer",
                OperatorRole::MoneroObserver,
                14,
            ),
            OperatorAcknowledgement::devnet(
                &config,
                5,
                "operator-reserve",
                OperatorRole::ReserveOperator,
                12,
            ),
            OperatorAcknowledgement::devnet(
                &config,
                6,
                "operator-dashboard",
                OperatorRole::DashboardOperator,
                8,
            ),
        ];
        let hold_unhold_steps = vec![
            HoldUnholdDrillStep::devnet(&config, 1, HoldUnholdAction::HoldAsserted),
            HoldUnholdDrillStep::devnet(&config, 2, HoldUnholdAction::UnholdAttempted),
            HoldUnholdDrillStep::devnet(&config, 3, HoldUnholdAction::UnholdDenied),
            HoldUnholdDrillStep::devnet(&config, 4, HoldUnholdAction::HoldReasserted),
            HoldUnholdDrillStep::devnet(&config, 5, HoldUnholdAction::FailClosedVerified),
        ];
        match Self::new(
            config,
            source_deployment_guard,
            custody_rollback_transcripts,
            signer_abort_commands,
            release_abort_proofs,
            release_rollback_markers,
            reserve_rollbacks,
            challenge_window_rollback,
            operator_acknowledgements,
            hold_unhold_steps,
        ) {
            Ok(state) => state,
            Err(_) => Self::fallback(),
        }
    }

    pub fn fallback() -> Self {
        let config = Config::devnet();
        let source_deployment_guard = SourceDeploymentGuard {
            guard_id: config.source_deployment_guard_id.clone(),
            observed_height: config.drill_height,
            deployment_guard_root: source_guard_component_root(
                &config,
                "fallback-deployment-guard",
            ),
            custody_evidence_root: source_guard_component_root(&config, "fallback-custody"),
            signer_handoff_root: source_guard_component_root(&config, "fallback-signer"),
            release_observation_root: source_guard_component_root(&config, "fallback-release"),
            reserve_handoff_root: source_guard_component_root(&config, "fallback-reserve"),
            challenge_clearance_root: source_guard_component_root(&config, "fallback-challenge"),
            hold_unhold_root: source_guard_component_root(&config, "fallback-hold"),
            operator_dashboard_root: source_guard_component_root(&config, "fallback-dashboard"),
            decision_root: source_guard_component_root(&config, "fallback-decision"),
            status: EvidenceStatus::Accepted,
        };
        let custody_rollback_transcripts = vec![CustodyRollbackTranscript::devnet(
            &config,
            1,
            "fallback-custody-round",
        )];
        let signer_abort_commands = vec![SignerAbortCommand::devnet(
            &config,
            1,
            "fallback-signer",
            SignerAbortCommandKind::AcknowledgeHold,
            DEFAULT_MIN_SIGNER_ABORT_WEIGHT,
        )];
        let release_abort_proofs = vec![ReleaseTxAbortProof::devnet(
            &config,
            1,
            "fallback-release-tx",
        )];
        let release_rollback_markers = vec![ReleaseObservationRollbackMarker::devnet(
            &config,
            1,
            ReleaseRollbackMarkerKind::ReleaseReceiptInvalidated,
            "fallback-release-tx",
        )];
        let reserve_rollbacks = vec![ReserveRollbackEvidence::devnet(
            &config,
            1,
            "fallback-reserve",
            ReserveRollbackKind::HandoffEnvelopeRevoked,
        )];
        let challenge_window_rollback = ChallengeWindowRollback::devnet(&config);
        let operator_acknowledgements = vec![OperatorAcknowledgement::devnet(
            &config,
            1,
            "fallback-operator",
            OperatorRole::IncidentCommander,
            DEFAULT_MIN_OPERATOR_WEIGHT,
        )];
        let hold_unhold_steps = vec![HoldUnholdDrillStep::devnet(
            &config,
            1,
            HoldUnholdAction::FailClosedVerified,
        )];
        let phase_roots = build_phase_roots(
            &config,
            &source_deployment_guard,
            &custody_rollback_transcripts,
            &signer_abort_commands,
            &release_abort_proofs,
            &release_rollback_markers,
            &reserve_rollbacks,
            &challenge_window_rollback,
            &operator_acknowledgements,
            &hold_unhold_steps,
        );
        let evidence_root = merkle_root(
            "ROLLBACK-DRILL-FALLBACK-EVIDENCE",
            &phase_roots
                .iter()
                .map(|(phase, root)| json!({"phase": phase, "root": root}))
                .collect::<Vec<_>>(),
        );
        let blockers = vec![RollbackBlocker::new(
            &config,
            RollbackBlockerKind::FailClosedStateMissing,
            "fallback",
            evidence_root.clone(),
        )];
        let blocker_root = merkle_root(
            "ROLLBACK-DRILL-FALLBACK-BLOCKERS",
            &blockers
                .iter()
                .map(RollbackBlocker::public_record)
                .collect::<Vec<_>>(),
        );
        let verdict_root = domain_hash(
            "ROLLBACK-DRILL-FALLBACK-VERDICT",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.drill_id),
                HashPart::Str(&evidence_root),
                HashPart::Str(&blocker_root),
            ],
            32,
        );
        let verdict = RollbackDrillVerdict {
            release_held: true,
            unhold_allowed: false,
            fail_closed: true,
            accepted: false,
            blocker_count: blockers.len(),
            custody_transcript_count: custody_rollback_transcripts.len(),
            signer_abort_count: accepted_signer_abort_count(&signer_abort_commands),
            signer_abort_weight: accepted_signer_abort_weight(&signer_abort_commands),
            release_abort_proof_count: accepted_release_abort_proof_count(&release_abort_proofs),
            reserve_rollback_count: accepted_reserve_rollback_count(&reserve_rollbacks),
            operator_acknowledgement_count: accepted_operator_acknowledgement_count(
                &operator_acknowledgements,
            ),
            operator_acknowledgement_weight: accepted_operator_acknowledgement_weight(
                &operator_acknowledgements,
            ),
            hold_unhold_transition_count: accepted_hold_unhold_transition_count(&hold_unhold_steps),
            evidence_root,
            blocker_root,
            verdict_root,
        };
        Self {
            config,
            source_deployment_guard,
            custody_rollback_transcripts,
            signer_abort_commands,
            release_abort_proofs,
            release_rollback_markers,
            reserve_rollbacks,
            challenge_window_rollback,
            operator_acknowledgements,
            hold_unhold_steps,
            phase_roots,
            blockers,
            verdict,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure(
            self.source_deployment_guard.accepted(&self.config),
            "source deployment guard root is not accepted",
        )?;
        ensure(
            self.custody_rollback_transcripts
                .iter()
                .all(CustodyRollbackTranscript::accepted),
            "custody rollback transcripts are incomplete",
        )?;
        ensure(
            self.verdict.signer_abort_count >= self.config.min_signer_abort_commands,
            "signer abort command quorum is below threshold",
        )?;
        ensure(
            self.verdict.signer_abort_weight >= self.config.min_signer_abort_weight,
            "signer abort command weight is below threshold",
        )?;
        ensure(
            self.verdict.release_abort_proof_count >= self.config.min_release_abort_proofs,
            "release abort proof count is below threshold",
        )?;
        ensure(
            self.release_rollback_markers
                .iter()
                .all(ReleaseObservationRollbackMarker::accepted),
            "release rollback markers are incomplete",
        )?;
        ensure(
            self.verdict.reserve_rollback_count >= self.config.min_reserve_rollback_count,
            "reserve rollback count is below threshold",
        )?;
        ensure(
            self.challenge_window_rollback.accepted(&self.config),
            "challenge window rollback is incomplete",
        )?;
        ensure(
            self.verdict.operator_acknowledgement_count
                >= self.config.min_operator_acknowledgements,
            "operator acknowledgement count is below threshold",
        )?;
        ensure(
            self.verdict.operator_acknowledgement_weight >= self.config.min_operator_weight,
            "operator acknowledgement weight is below threshold",
        )?;
        ensure(
            self.verdict.hold_unhold_transition_count >= self.config.min_hold_unhold_transitions,
            "hold/unhold transition count is below threshold",
        )?;
        ensure(
            self.verdict.release_held,
            "release was not held during drill",
        )?;
        ensure(
            !self.verdict.unhold_allowed,
            "unhold was allowed during drill",
        )?;
        ensure(self.verdict.fail_closed, "fail-closed state is missing")?;
        ensure(self.verdict.accepted, "rollback drill verdict is blocked")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "source_deployment_guard": self.source_deployment_guard.public_record(),
            "custody_rollback_transcripts": self.custody_rollback_transcripts.iter().map(CustodyRollbackTranscript::public_record).collect::<Vec<_>>(),
            "signer_abort_commands": self.signer_abort_commands.iter().map(SignerAbortCommand::public_record).collect::<Vec<_>>(),
            "release_abort_proofs": self.release_abort_proofs.iter().map(ReleaseTxAbortProof::public_record).collect::<Vec<_>>(),
            "release_rollback_markers": self.release_rollback_markers.iter().map(ReleaseObservationRollbackMarker::public_record).collect::<Vec<_>>(),
            "reserve_rollbacks": self.reserve_rollbacks.iter().map(ReserveRollbackEvidence::public_record).collect::<Vec<_>>(),
            "challenge_window_rollback": self.challenge_window_rollback.public_record(),
            "operator_acknowledgements": self.operator_acknowledgements.iter().map(OperatorAcknowledgement::public_record).collect::<Vec<_>>(),
            "hold_unhold_steps": self.hold_unhold_steps.iter().map(HoldUnholdDrillStep::public_record).collect::<Vec<_>>(),
            "phase_roots": self.phase_roots,
            "blockers": self.blockers.iter().map(RollbackBlocker::public_record).collect::<Vec<_>>(),
            "verdict": self.verdict.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "ROLLBACK-DRILL-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.drill_id),
                HashPart::Str(&self.config.source_deployment_guard_id),
                HashPart::Str(&self.verdict.evidence_root),
                HashPart::Str(&self.verdict.blocker_root),
                HashPart::Str(&self.verdict.verdict_root),
                HashPart::Json(&self.state_record()),
            ],
            32,
        )
    }

    fn state_record(&self) -> Value {
        json!({
            "config_root": self.config.state_root(),
            "source_deployment_guard_root": self.source_deployment_guard.state_root(),
            "phase_roots": self.phase_roots,
            "verdict_root": self.verdict.verdict_root,
            "blocker_root": self.verdict.blocker_root,
        })
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

fn build_phase_roots(
    config: &Config,
    source_deployment_guard: &SourceDeploymentGuard,
    custody_rollback_transcripts: &[CustodyRollbackTranscript],
    signer_abort_commands: &[SignerAbortCommand],
    release_abort_proofs: &[ReleaseTxAbortProof],
    release_rollback_markers: &[ReleaseObservationRollbackMarker],
    reserve_rollbacks: &[ReserveRollbackEvidence],
    challenge_window_rollback: &ChallengeWindowRollback,
    operator_acknowledgements: &[OperatorAcknowledgement],
    hold_unhold_steps: &[HoldUnholdDrillStep],
) -> BTreeMap<String, String> {
    let mut roots = BTreeMap::new();
    roots.insert(
        RollbackDrillPhase::SourceGuardBound.as_str().to_string(),
        source_deployment_guard.state_root(),
    );
    roots.insert(
        RollbackDrillPhase::CustodyTranscriptRollback
            .as_str()
            .to_string(),
        merkle_root(
            "ROLLBACK-DRILL-CUSTODY-TRANSCRIPT-ROOT",
            &custody_rollback_transcripts
                .iter()
                .map(CustodyRollbackTranscript::public_record)
                .collect::<Vec<_>>(),
        ),
    );
    roots.insert(
        RollbackDrillPhase::SignerAbortIssued.as_str().to_string(),
        merkle_root(
            "ROLLBACK-DRILL-SIGNER-ABORT-ROOT",
            &signer_abort_commands
                .iter()
                .map(SignerAbortCommand::public_record)
                .collect::<Vec<_>>(),
        ),
    );
    roots.insert(
        RollbackDrillPhase::ReleaseObservationRolledBack
            .as_str()
            .to_string(),
        merkle_root(
            "ROLLBACK-DRILL-RELEASE-OBSERVATION-ROOT",
            &[
                json!({
                    "abort_proofs": release_abort_proofs.iter().map(ReleaseTxAbortProof::public_record).collect::<Vec<_>>(),
                }),
                json!({
                    "rollback_markers": release_rollback_markers.iter().map(ReleaseObservationRollbackMarker::public_record).collect::<Vec<_>>(),
                }),
            ],
        ),
    );
    roots.insert(
        RollbackDrillPhase::ReserveHandoffRolledBack
            .as_str()
            .to_string(),
        merkle_root(
            "ROLLBACK-DRILL-RESERVE-ROLLBACK-ROOT",
            &reserve_rollbacks
                .iter()
                .map(ReserveRollbackEvidence::public_record)
                .collect::<Vec<_>>(),
        ),
    );
    roots.insert(
        RollbackDrillPhase::ChallengeWindowRolledBack
            .as_str()
            .to_string(),
        challenge_window_rollback.state_root(),
    );
    roots.insert(
        RollbackDrillPhase::OperatorAccepted.as_str().to_string(),
        merkle_root(
            "ROLLBACK-DRILL-OPERATOR-ACK-ROOT",
            &operator_acknowledgements
                .iter()
                .map(OperatorAcknowledgement::public_record)
                .collect::<Vec<_>>(),
        ),
    );
    roots.insert(
        RollbackDrillPhase::HoldUnholdVerified.as_str().to_string(),
        merkle_root(
            "ROLLBACK-DRILL-HOLD-UNHOLD-ROOT",
            &hold_unhold_steps
                .iter()
                .map(HoldUnholdDrillStep::public_record)
                .collect::<Vec<_>>(),
        ),
    );
    roots.insert(
        RollbackDrillPhase::FailClosed.as_str().to_string(),
        domain_hash(
            "ROLLBACK-DRILL-FAIL-CLOSED-ROOT",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.drill_id),
                HashPart::Str(if config.fail_closed {
                    "fail-closed"
                } else {
                    "open"
                }),
                HashPart::U64(accepted_hold_unhold_transition_count(hold_unhold_steps)),
            ],
            32,
        ),
    );
    roots
}

fn evaluate_blocker_kinds(
    config: &Config,
    source_deployment_guard: &SourceDeploymentGuard,
    custody_rollback_transcripts: &[CustodyRollbackTranscript],
    signer_abort_commands: &[SignerAbortCommand],
    release_abort_proofs: &[ReleaseTxAbortProof],
    release_rollback_markers: &[ReleaseObservationRollbackMarker],
    reserve_rollbacks: &[ReserveRollbackEvidence],
    challenge_window_rollback: &ChallengeWindowRollback,
    operator_acknowledgements: &[OperatorAcknowledgement],
    hold_unhold_steps: &[HoldUnholdDrillStep],
) -> Vec<(RollbackBlockerKind, String)> {
    let mut blockers = Vec::new();
    blockers.extend(
        source_deployment_guard
            .blockers(config)
            .into_iter()
            .map(|kind| (kind, "source_deployment_guard".to_string())),
    );
    for transcript in custody_rollback_transcripts {
        blockers.extend(
            transcript
                .blockers(config)
                .into_iter()
                .map(|kind| (kind, transcript.transcript_id.clone())),
        );
    }
    if config.require_signer_abort_commands
        && accepted_signer_abort_count(signer_abort_commands) < config.min_signer_abort_commands
    {
        blockers.push((
            RollbackBlockerKind::SignerAbortQuorumLow,
            "signer_abort_commands".to_string(),
        ));
    }
    if config.require_signer_abort_commands
        && accepted_signer_abort_weight(signer_abort_commands) < config.min_signer_abort_weight
    {
        blockers.push((
            RollbackBlockerKind::SignerAbortWeightLow,
            "signer_abort_commands".to_string(),
        ));
    }
    if config.require_release_abort_proofs
        && accepted_release_abort_proof_count(release_abort_proofs)
            < config.min_release_abort_proofs
    {
        blockers.push((
            RollbackBlockerKind::ReleaseAbortProofsLow,
            "release_abort_proofs".to_string(),
        ));
    }
    if config.require_release_rollback_markers
        && release_rollback_markers
            .iter()
            .any(|marker| !marker.accepted())
    {
        blockers.push((
            RollbackBlockerKind::ReleaseRollbackMarkerMissing,
            "release_rollback_markers".to_string(),
        ));
    }
    if config.require_reserve_rollback
        && reserve_rollbacks
            .iter()
            .any(|rollback| !rollback.accepted())
    {
        blockers.push((
            RollbackBlockerKind::ReserveRollbackRootMissing,
            "reserve_rollbacks".to_string(),
        ));
    }
    if config.require_reserve_rollback
        && accepted_reserve_rollback_count(reserve_rollbacks) < config.min_reserve_rollback_count
    {
        blockers.push((
            RollbackBlockerKind::ReserveRollbackCountLow,
            "reserve_rollbacks".to_string(),
        ));
    }
    blockers.extend(
        challenge_window_rollback
            .blockers(config)
            .into_iter()
            .map(|kind| (kind, "challenge_window_rollback".to_string())),
    );
    if config.require_operator_acknowledgements
        && accepted_operator_acknowledgement_count(operator_acknowledgements)
            < config.min_operator_acknowledgements
    {
        blockers.push((
            RollbackBlockerKind::OperatorAcknowledgementQuorumLow,
            "operator_acknowledgements".to_string(),
        ));
    }
    if config.require_operator_acknowledgements
        && accepted_operator_acknowledgement_weight(operator_acknowledgements)
            < config.min_operator_weight
    {
        blockers.push((
            RollbackBlockerKind::OperatorAcknowledgementWeightLow,
            "operator_acknowledgements".to_string(),
        ));
    }
    if config.require_hold_unhold_verdict
        && accepted_hold_unhold_transition_count(hold_unhold_steps)
            < config.min_hold_unhold_transitions
    {
        blockers.push((
            RollbackBlockerKind::HoldUnholdTransitionCountLow,
            "hold_unhold_steps".to_string(),
        ));
    }
    if config.require_hold_unhold_verdict
        && hold_unhold_steps.iter().any(|step| step.unhold_allowed)
    {
        blockers.push((
            RollbackBlockerKind::ReleaseUnheldDuringDrill,
            "hold_unhold_steps".to_string(),
        ));
    }
    if config.require_fail_closed_release
        && (!config.fail_closed || hold_unhold_steps.iter().any(|step| !step.fail_closed))
    {
        blockers.push((
            RollbackBlockerKind::FailClosedStateMissing,
            "hold_unhold_steps".to_string(),
        ));
    }
    blockers
}

fn unique_blockers(
    config: &Config,
    blockers: Vec<(RollbackBlockerKind, String)>,
    evidence_root: &str,
) -> Vec<RollbackBlocker> {
    let mut seen = BTreeSet::new();
    blockers
        .into_iter()
        .filter(|(kind, subject)| seen.insert((*kind, subject.clone())))
        .map(|(kind, subject)| {
            RollbackBlocker::new(config, kind, &subject, evidence_root.to_string())
        })
        .collect()
}

fn accepted_signer_abort_count(commands: &[SignerAbortCommand]) -> u64 {
    commands.iter().filter(|command| command.accepted()).count() as u64
}

fn accepted_signer_abort_weight(commands: &[SignerAbortCommand]) -> u64 {
    commands
        .iter()
        .filter(|command| command.accepted())
        .map(|command| command.signer_weight)
        .sum()
}

fn accepted_release_abort_proof_count(proofs: &[ReleaseTxAbortProof]) -> u64 {
    proofs.iter().filter(|proof| proof.accepted()).count() as u64
}

fn accepted_reserve_rollback_count(rollbacks: &[ReserveRollbackEvidence]) -> u64 {
    rollbacks
        .iter()
        .filter(|rollback| rollback.accepted())
        .count() as u64
}

fn accepted_operator_acknowledgement_count(acks: &[OperatorAcknowledgement]) -> u64 {
    acks.iter().filter(|ack| ack.accepted()).count() as u64
}

fn accepted_operator_acknowledgement_weight(acks: &[OperatorAcknowledgement]) -> u64 {
    acks.iter()
        .filter(|ack| ack.accepted())
        .map(|ack| ack.acknowledgement_weight)
        .sum()
}

fn accepted_hold_unhold_transition_count(steps: &[HoldUnholdDrillStep]) -> u64 {
    steps.iter().filter(|step| step.accepted()).count() as u64
}

fn runtime_id(label: &str) -> String {
    domain_hash(
        "ROLLBACK-DRILL-ID",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        16,
    )
}

fn evidence_id(config: &Config, kind: &str, subject: &str, ordinal: u64) -> String {
    domain_hash(
        "ROLLBACK-DRILL-EVIDENCE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.drill_id),
            HashPart::Str(kind),
            HashPart::Str(subject),
            HashPart::U64(ordinal),
        ],
        16,
    )
}

fn source_guard_component_root(config: &Config, component: &str) -> String {
    domain_hash(
        "ROLLBACK-DRILL-SOURCE-GUARD-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.drill_id),
            HashPart::Str(&config.source_deployment_guard_id),
            HashPart::Str(component),
            HashPart::U64(config.source_wave),
        ],
        32,
    )
}

fn transcript_component_root(config: &Config, transcript_id: &str, component: &str) -> String {
    domain_hash(
        "ROLLBACK-DRILL-TRANSCRIPT-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.drill_id),
            HashPart::Str(transcript_id),
            HashPart::Str(component),
        ],
        32,
    )
}

fn signer_abort_component_root(config: &Config, command_id: &str, component: &str) -> String {
    domain_hash(
        "ROLLBACK-DRILL-SIGNER-ABORT-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.drill_id),
            HashPart::Str(command_id),
            HashPart::Str(component),
        ],
        32,
    )
}

fn release_abort_component_root(config: &Config, proof_id: &str, component: &str) -> String {
    domain_hash(
        "ROLLBACK-DRILL-RELEASE-ABORT-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.drill_id),
            HashPart::Str(proof_id),
            HashPart::Str(component),
            HashPart::U64(config.release_height),
        ],
        32,
    )
}

fn release_marker_component_root(config: &Config, marker_id: &str, component: &str) -> String {
    domain_hash(
        "ROLLBACK-DRILL-RELEASE-MARKER-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.drill_id),
            HashPart::Str(marker_id),
            HashPart::Str(component),
            HashPart::U64(config.release_height),
        ],
        32,
    )
}

fn reserve_component_root(config: &Config, rollback_id: &str, component: &str) -> String {
    domain_hash(
        "ROLLBACK-DRILL-RESERVE-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.drill_id),
            HashPart::Str(rollback_id),
            HashPart::Str(component),
        ],
        32,
    )
}

fn challenge_component_root(config: &Config, challenge_id: &str, component: &str) -> String {
    domain_hash(
        "ROLLBACK-DRILL-CHALLENGE-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.drill_id),
            HashPart::Str(challenge_id),
            HashPart::Str(component),
            HashPart::U64(config.drill_height),
        ],
        32,
    )
}

fn operator_component_root(
    config: &Config,
    acknowledgement_id: &str,
    role: OperatorRole,
    component: &str,
) -> String {
    domain_hash(
        "ROLLBACK-DRILL-OPERATOR-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.drill_id),
            HashPart::Str(acknowledgement_id),
            HashPart::Str(role.as_str()),
            HashPart::Str(component),
        ],
        32,
    )
}

fn hold_unhold_component_root(config: &Config, step_id: &str, component: &str) -> String {
    domain_hash(
        "ROLLBACK-DRILL-HOLD-UNHOLD-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.drill_id),
            HashPart::Str(step_id),
            HashPart::Str(component),
        ],
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
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

fn ensure_non_empty(field: &str, value: &str) -> Result<()> {
    ensure(
        !value.trim().is_empty(),
        &format!("{} must not be empty", field),
    )
}
