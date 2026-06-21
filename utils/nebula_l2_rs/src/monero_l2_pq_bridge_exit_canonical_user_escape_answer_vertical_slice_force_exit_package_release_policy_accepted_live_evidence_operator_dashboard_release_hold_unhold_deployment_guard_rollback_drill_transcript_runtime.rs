use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageReleasePolicyAcceptedLiveEvidenceOperatorDashboardReleaseHoldUnholdDeploymentGuardRollbackDrillTranscriptRuntimeResult<
    T,
> = Result<T>;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RELEASE_POLICY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_HOLD_UNHOLD_DEPLOYMENT_GUARD_ROLLBACK_DRILL_TRANSCRIPT_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-force-exit-release-policy-accepted-live-evidence-operator-dashboard-release-hold-unhold-deployment-guard-rollback-drill-transcript-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RELEASE_POLICY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_HOLD_UNHOLD_DEPLOYMENT_GUARD_ROLLBACK_DRILL_TRANSCRIPT_RUNTIME_PROTOCOL_VERSION;
pub const DEFAULT_HEIGHT: u64 = 96_000;
pub const DEFAULT_MAX_TRANSCRIPT_AGE_BLOCKS: u64 = 48;
pub const DEFAULT_MIN_OPERATOR_WEIGHT: u64 = 80;
pub const DEFAULT_MIN_DRILL_SCORE: u64 = 94;
pub const DEFAULT_MIN_ROLLBACK_SCORE: u64 = 96;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptLane {
    CompileRuntime,
    RuntimeReplay,
    AuditSecurity,
    BridgeCustody,
    WalletWatchtower,
    PqReservePrivacy,
}

impl TranscriptLane {
    pub fn all() -> Vec<Self> {
        vec![
            Self::CompileRuntime,
            Self::RuntimeReplay,
            Self::AuditSecurity,
            Self::BridgeCustody,
            Self::WalletWatchtower,
            Self::PqReservePrivacy,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CompileRuntime => "compile_runtime",
            Self::RuntimeReplay => "runtime_replay",
            Self::AuditSecurity => "audit_security",
            Self::BridgeCustody => "bridge_custody",
            Self::WalletWatchtower => "wallet_watchtower",
            Self::PqReservePrivacy => "pq_reserve_privacy",
        }
    }

    pub fn rollback_drill_module(self) -> &'static str {
        match self {
            Self::CompileRuntime => "compile_runtime_deployment_guard_rollback_drill",
            Self::RuntimeReplay => "runtime_replay_deployment_guard_rollback_drill",
            Self::AuditSecurity => "audit_security_deployment_guard_rollback_drill",
            Self::BridgeCustody => "bridge_custody_deployment_guard_rollback_drill",
            Self::WalletWatchtower => "wallet_watchtower_deployment_guard_rollback_drill",
            Self::PqReservePrivacy => "pq_reserve_privacy_deployment_guard_rollback_drill",
        }
    }

    pub fn required_transcript_steps(self) -> Vec<&'static str> {
        match self {
            Self::CompileRuntime => vec![
                "freeze_release_candidate",
                "replay_rustfmt_receipt",
                "record_deferred_cargo_blockers",
                "abort_compile_deploy",
                "restore_release_hold",
            ],
            Self::RuntimeReplay => vec![
                "freeze_replay_window",
                "replay_expected_receipts",
                "record_replay_mismatch_hold",
                "abort_replay_deploy",
                "restore_replay_hold",
            ],
            Self::AuditSecurity => vec![
                "freeze_audit_signoff",
                "reopen_security_findings",
                "replay_privacy_boundary",
                "abort_security_deploy",
                "restore_security_hold",
            ],
            Self::BridgeCustody => vec![
                "freeze_custody_release",
                "replay_signer_quorum",
                "record_monero_release_abort",
                "rollback_reserve_handoff",
                "restore_custody_hold",
            ],
            Self::WalletWatchtower => vec![
                "freeze_wallet_release",
                "replay_watchtower_window",
                "record_user_escape_hold",
                "abort_wallet_deploy",
                "restore_wallet_hold",
            ],
            Self::PqReservePrivacy => vec![
                "freeze_pq_release",
                "replay_pq_rotation",
                "rollback_reserve_coverage",
                "replay_privacy_boundary",
                "restore_privacy_hold",
            ],
        }
    }

    pub fn requires_private_transcript(self) -> bool {
        matches!(
            self,
            Self::AuditSecurity | Self::WalletWatchtower | Self::PqReservePrivacy
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillStatus {
    Missing,
    Draft,
    Held,
    Replayed,
    Accepted,
    Rejected,
    Expired,
}

impl DrillStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Draft => "draft",
            Self::Held => "held",
            Self::Replayed => "replayed",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorDecision {
    Pending,
    AcknowledgeHold,
    ApproveUnholdAfterReceipts,
    RejectUnhold,
}

impl OperatorDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::AcknowledgeHold => "acknowledge_hold",
            Self::ApproveUnholdAfterReceipts => "approve_unhold_after_receipts",
            Self::RejectUnhold => "reject_unhold",
        }
    }

    pub fn contributes_weight(self) -> bool {
        matches!(
            self,
            Self::AcknowledgeHold | Self::ApproveUnholdAfterReceipts
        )
    }

    pub fn blocks_unhold(self) -> bool {
        matches!(self, Self::Pending | Self::RejectUnhold)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptBlockerKind {
    MissingLaneTranscript,
    DuplicateLaneTranscript,
    StaleLaneTranscript,
    DrillNotAccepted,
    RollbackScoreTooLow,
    DrillScoreTooLow,
    MissingDeploymentGuardRoot,
    MissingRollbackCommandRoot,
    MissingAbortReceiptRoot,
    MissingRunbookTranscriptRoot,
    MissingOperatorAckRoot,
    MissingPrivateTranscriptRoot,
    MissingExpectedReceiptRoot,
    OperatorWeightTooLow,
    OperatorRejectedUnhold,
    OperatorPendingUnhold,
    HeavyGateReceiptsDeferred,
    ReleaseStillHeld,
}

impl TranscriptBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingLaneTranscript => "missing_lane_transcript",
            Self::DuplicateLaneTranscript => "duplicate_lane_transcript",
            Self::StaleLaneTranscript => "stale_lane_transcript",
            Self::DrillNotAccepted => "drill_not_accepted",
            Self::RollbackScoreTooLow => "rollback_score_too_low",
            Self::DrillScoreTooLow => "drill_score_too_low",
            Self::MissingDeploymentGuardRoot => "missing_deployment_guard_root",
            Self::MissingRollbackCommandRoot => "missing_rollback_command_root",
            Self::MissingAbortReceiptRoot => "missing_abort_receipt_root",
            Self::MissingRunbookTranscriptRoot => "missing_runbook_transcript_root",
            Self::MissingOperatorAckRoot => "missing_operator_ack_root",
            Self::MissingPrivateTranscriptRoot => "missing_private_transcript_root",
            Self::MissingExpectedReceiptRoot => "missing_expected_receipt_root",
            Self::OperatorWeightTooLow => "operator_weight_too_low",
            Self::OperatorRejectedUnhold => "operator_rejected_unhold",
            Self::OperatorPendingUnhold => "operator_pending_unhold",
            Self::HeavyGateReceiptsDeferred => "heavy_gate_receipts_deferred",
            Self::ReleaseStillHeld => "release_still_held",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub transcript_policy_id: String,
    pub required_lanes: Vec<TranscriptLane>,
    pub max_transcript_age_blocks: u64,
    pub min_operator_weight: u64,
    pub min_drill_score: u64,
    pub min_rollback_score: u64,
    pub require_deployment_guard_root: bool,
    pub require_rollback_command_root: bool,
    pub require_abort_receipt_root: bool,
    pub require_runbook_transcript_root: bool,
    pub require_expected_receipt_root: bool,
    pub require_private_transcripts: bool,
    pub keep_release_held_while_receipts_deferred: bool,
    pub fail_closed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            transcript_policy_id: transcript_policy_id("devnet-rollback-drill-transcript"),
            required_lanes: TranscriptLane::all(),
            max_transcript_age_blocks: DEFAULT_MAX_TRANSCRIPT_AGE_BLOCKS,
            min_operator_weight: DEFAULT_MIN_OPERATOR_WEIGHT,
            min_drill_score: DEFAULT_MIN_DRILL_SCORE,
            min_rollback_score: DEFAULT_MIN_ROLLBACK_SCORE,
            require_deployment_guard_root: true,
            require_rollback_command_root: true,
            require_abort_receipt_root: true,
            require_runbook_transcript_root: true,
            require_expected_receipt_root: true,
            require_private_transcripts: true,
            keep_release_held_while_receipts_deferred: true,
            fail_closed: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("transcript_policy_id", &self.transcript_policy_id)?;
        ensure(
            !self.required_lanes.is_empty(),
            "at least one rollback transcript lane is required",
        )?;
        ensure(
            self.max_transcript_age_blocks > 0,
            "transcript age window must be non-zero",
        )?;
        ensure(
            self.min_operator_weight > 0,
            "operator weight must be non-zero",
        )?;
        ensure(
            self.min_drill_score > 0,
            "drill score threshold must be non-zero",
        )?;
        ensure(
            self.min_rollback_score > 0,
            "rollback score threshold must be non-zero",
        )?;
        let mut seen = BTreeSet::new();
        for lane in &self.required_lanes {
            ensure(seen.insert(*lane), "duplicate rollback transcript lane")?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "transcript_policy_id": self.transcript_policy_id,
            "required_lanes": self.required_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "max_transcript_age_blocks": self.max_transcript_age_blocks,
            "min_operator_weight": self.min_operator_weight,
            "min_drill_score": self.min_drill_score,
            "min_rollback_score": self.min_rollback_score,
            "require_deployment_guard_root": self.require_deployment_guard_root,
            "require_rollback_command_root": self.require_rollback_command_root,
            "require_abort_receipt_root": self.require_abort_receipt_root,
            "require_runbook_transcript_root": self.require_runbook_transcript_root,
            "require_expected_receipt_root": self.require_expected_receipt_root,
            "require_private_transcripts": self.require_private_transcripts,
            "keep_release_held_while_receipts_deferred": self.keep_release_held_while_receipts_deferred,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "rollback-drill-transcript-config",
            &[
                HashPart::Str(&self.transcript_policy_id),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LaneDrillTranscript {
    pub lane: TranscriptLane,
    pub transcript_id: String,
    pub deployment_guard_root: String,
    pub rollback_command_root: String,
    pub abort_receipt_root: String,
    pub runbook_transcript_root: String,
    pub expected_receipt_root: String,
    pub operator_ack_root: String,
    pub private_transcript_root: String,
    pub heavy_gate_receipt_root: String,
    pub step_roots: BTreeMap<String, String>,
    pub status: DrillStatus,
    pub drill_score: u64,
    pub rollback_score: u64,
    pub observed_at_height: u64,
    pub hold_unhold_note: String,
}

impl LaneDrillTranscript {
    pub fn new(
        lane: TranscriptLane,
        transcript_id: impl Into<String>,
        observed_at_height: u64,
    ) -> Self {
        let transcript_id = transcript_id.into();
        let step_roots = lane
            .required_transcript_steps()
            .into_iter()
            .map(|step| {
                (
                    step.to_string(),
                    transcript_root(lane, &transcript_id, step, observed_at_height),
                )
            })
            .collect::<BTreeMap<_, _>>();
        Self {
            lane,
            transcript_id: transcript_id.clone(),
            deployment_guard_root: transcript_root(
                lane,
                &transcript_id,
                "deployment-guard",
                observed_at_height,
            ),
            rollback_command_root: transcript_root(
                lane,
                &transcript_id,
                "rollback-command",
                observed_at_height,
            ),
            abort_receipt_root: transcript_root(
                lane,
                &transcript_id,
                "abort-receipt",
                observed_at_height,
            ),
            runbook_transcript_root: transcript_root(
                lane,
                &transcript_id,
                "runbook-transcript",
                observed_at_height,
            ),
            expected_receipt_root: transcript_root(
                lane,
                &transcript_id,
                "expected-receipt",
                observed_at_height,
            ),
            operator_ack_root: transcript_root(
                lane,
                &transcript_id,
                "operator-ack",
                observed_at_height,
            ),
            private_transcript_root: transcript_root(
                lane,
                &transcript_id,
                "private-transcript",
                observed_at_height,
            ),
            heavy_gate_receipt_root: String::new(),
            step_roots,
            status: DrillStatus::Held,
            drill_score: DEFAULT_MIN_DRILL_SCORE,
            rollback_score: DEFAULT_MIN_ROLLBACK_SCORE,
            observed_at_height,
            hold_unhold_note: format!(
                "{} rollback transcript keeps release held until live heavy-gate receipts are attached",
                lane.as_str()
            ),
        }
    }

    pub fn with_status(mut self, status: DrillStatus) -> Self {
        self.status = status;
        self
    }

    pub fn with_heavy_gate_receipt(mut self, receipt_root: impl Into<String>) -> Self {
        self.heavy_gate_receipt_root = receipt_root.into();
        if !self.heavy_gate_receipt_root.is_empty() {
            self.status = DrillStatus::Accepted;
            self.hold_unhold_note =
                "rollback drill transcript can unhold after live heavy-gate receipt binding"
                    .to_string();
        }
        self
    }

    pub fn stale(&self, height: u64, max_age: u64) -> bool {
        height.saturating_sub(self.observed_at_height) > max_age
    }

    pub fn missing_roots(&self, config: &Config) -> Vec<TranscriptBlockerKind> {
        let mut blockers = Vec::new();
        if config.require_deployment_guard_root && self.deployment_guard_root.is_empty() {
            blockers.push(TranscriptBlockerKind::MissingDeploymentGuardRoot);
        }
        if config.require_rollback_command_root && self.rollback_command_root.is_empty() {
            blockers.push(TranscriptBlockerKind::MissingRollbackCommandRoot);
        }
        if config.require_abort_receipt_root && self.abort_receipt_root.is_empty() {
            blockers.push(TranscriptBlockerKind::MissingAbortReceiptRoot);
        }
        if config.require_runbook_transcript_root && self.runbook_transcript_root.is_empty() {
            blockers.push(TranscriptBlockerKind::MissingRunbookTranscriptRoot);
        }
        if config.require_expected_receipt_root && self.expected_receipt_root.is_empty() {
            blockers.push(TranscriptBlockerKind::MissingExpectedReceiptRoot);
        }
        if self.operator_ack_root.is_empty() {
            blockers.push(TranscriptBlockerKind::MissingOperatorAckRoot);
        }
        if config.require_private_transcripts
            && self.lane.requires_private_transcript()
            && self.private_transcript_root.is_empty()
        {
            blockers.push(TranscriptBlockerKind::MissingPrivateTranscriptRoot);
        }
        blockers
    }

    pub fn blockers(&self, config: &Config, height: u64) -> Vec<TranscriptBlockerKind> {
        let mut blockers = self.missing_roots(config);
        if self.stale(height, config.max_transcript_age_blocks) {
            blockers.push(TranscriptBlockerKind::StaleLaneTranscript);
        }
        if !self.status.accepted() {
            blockers.push(TranscriptBlockerKind::DrillNotAccepted);
        }
        if self.drill_score < config.min_drill_score {
            blockers.push(TranscriptBlockerKind::DrillScoreTooLow);
        }
        if self.rollback_score < config.min_rollback_score {
            blockers.push(TranscriptBlockerKind::RollbackScoreTooLow);
        }
        if config.keep_release_held_while_receipts_deferred
            && self.heavy_gate_receipt_root.is_empty()
        {
            blockers.push(TranscriptBlockerKind::HeavyGateReceiptsDeferred);
            blockers.push(TranscriptBlockerKind::ReleaseStillHeld);
        }
        blockers
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "rollback_drill_module": self.lane.rollback_drill_module(),
            "transcript_id": self.transcript_id,
            "deployment_guard_root": self.deployment_guard_root,
            "rollback_command_root": self.rollback_command_root,
            "abort_receipt_root": self.abort_receipt_root,
            "runbook_transcript_root": self.runbook_transcript_root,
            "expected_receipt_root": self.expected_receipt_root,
            "operator_ack_root": self.operator_ack_root,
            "private_transcript_root": self.private_transcript_root,
            "heavy_gate_receipt_root": self.heavy_gate_receipt_root,
            "step_roots": self.step_roots,
            "status": self.status.as_str(),
            "drill_score": self.drill_score,
            "rollback_score": self.rollback_score,
            "observed_at_height": self.observed_at_height,
            "hold_unhold_note": self.hold_unhold_note,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "rollback-drill-transcript-lane",
            &[
                HashPart::Str(self.lane.as_str()),
                HashPart::Str(&self.transcript_id),
                HashPart::U64(self.observed_at_height),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorTranscriptSignoff {
    pub operator_id: String,
    pub decision: OperatorDecision,
    pub weight: u64,
    pub transcript_root: String,
    pub rollback_root: String,
    pub signed_at_height: u64,
    pub note: String,
}

impl OperatorTranscriptSignoff {
    pub fn acknowledgement(operator_id: impl Into<String>, weight: u64, height: u64) -> Self {
        let operator_id = operator_id.into();
        Self {
            operator_id: operator_id.clone(),
            decision: OperatorDecision::AcknowledgeHold,
            weight,
            transcript_root: operator_root(&operator_id, height, "transcript"),
            rollback_root: operator_root(&operator_id, height, "rollback"),
            signed_at_height: height,
            note: format!(
                "{operator_id} acknowledges rollback transcript and keeps release held until heavy-gate receipts arrive"
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "decision": self.decision.as_str(),
            "weight": self.weight,
            "transcript_root": self.transcript_root,
            "rollback_root": self.rollback_root,
            "signed_at_height": self.signed_at_height,
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "rollback-drill-transcript-operator-signoff",
            &[
                HashPart::Str(&self.operator_id),
                HashPart::Str(self.decision.as_str()),
                HashPart::U64(self.weight),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HoldUnholdSummary {
    pub release_can_unhold: bool,
    pub release_remains_held: bool,
    pub transcript_count: usize,
    pub accepted_transcript_count: usize,
    pub operator_weight: u64,
    pub blocker_count: usize,
    pub transcript_root: String,
    pub operator_root: String,
    pub blocker_root: String,
    pub summary_root: String,
}

impl HoldUnholdSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "release_can_unhold": self.release_can_unhold,
            "release_remains_held": self.release_remains_held,
            "transcript_count": self.transcript_count,
            "accepted_transcript_count": self.accepted_transcript_count,
            "operator_weight": self.operator_weight,
            "blocker_count": self.blocker_count,
            "transcript_root": self.transcript_root,
            "operator_root": self.operator_root,
            "blocker_root": self.blocker_root,
            "summary_root": self.summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub lane_transcripts: Vec<LaneDrillTranscript>,
    pub operator_signoffs: Vec<OperatorTranscriptSignoff>,
    pub blockers: BTreeMap<String, Vec<TranscriptBlockerKind>>,
    pub transcript_root: String,
    pub operator_root: String,
    pub blocker_root: String,
    pub summary: HoldUnholdSummary,
}

impl State {
    pub fn new(
        config: Config,
        height: u64,
        lane_transcripts: Vec<LaneDrillTranscript>,
        operator_signoffs: Vec<OperatorTranscriptSignoff>,
    ) -> Result<Self> {
        config.validate()?;
        let blockers = evaluate_blockers(&config, height, &lane_transcripts, &operator_signoffs);
        let transcript_root = merkle_root(
            "rollback-drill-transcript-lanes",
            &lane_transcripts
                .iter()
                .map(LaneDrillTranscript::public_record)
                .collect::<Vec<_>>(),
        );
        let operator_root = merkle_root(
            "rollback-drill-transcript-operators",
            &operator_signoffs
                .iter()
                .map(OperatorTranscriptSignoff::public_record)
                .collect::<Vec<_>>(),
        );
        let blocker_root = merkle_root(
            "rollback-drill-transcript-blockers",
            &blockers
                .iter()
                .map(|(subject, blockers)| {
                    json!({
                        "subject": subject,
                        "blockers": blockers.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
                    })
                })
                .collect::<Vec<_>>(),
        );
        let accepted_transcript_count = lane_transcripts
            .iter()
            .filter(|transcript| transcript.status.accepted())
            .count();
        let operator_weight = operator_signoffs
            .iter()
            .filter(|signoff| signoff.decision.contributes_weight())
            .map(|signoff| signoff.weight)
            .sum::<u64>();
        let blocker_count = blockers.values().map(Vec::len).sum::<usize>();
        let release_can_unhold = blocker_count == 0
            && accepted_transcript_count == config.required_lanes.len()
            && operator_weight >= config.min_operator_weight;
        let release_remains_held = config.fail_closed || !release_can_unhold;
        let summary_root = domain_hash(
            "rollback-drill-transcript-summary",
            &[
                HashPart::Str(&config.transcript_policy_id),
                HashPart::U64(height),
                HashPart::U64(accepted_transcript_count as u64),
                HashPart::U64(operator_weight),
                HashPart::U64(blocker_count as u64),
                HashPart::Str(&transcript_root),
                HashPart::Str(&operator_root),
                HashPart::Str(&blocker_root),
            ],
            32,
        );
        let summary = HoldUnholdSummary {
            release_can_unhold,
            release_remains_held,
            transcript_count: lane_transcripts.len(),
            accepted_transcript_count,
            operator_weight,
            blocker_count,
            transcript_root: transcript_root.clone(),
            operator_root: operator_root.clone(),
            blocker_root: blocker_root.clone(),
            summary_root,
        };
        Ok(Self {
            config,
            height,
            lane_transcripts,
            operator_signoffs,
            blockers,
            transcript_root,
            operator_root,
            blocker_root,
            summary,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let height = DEFAULT_HEIGHT;
        let lane_transcripts = TranscriptLane::all()
            .into_iter()
            .enumerate()
            .map(|(index, lane)| {
                LaneDrillTranscript::new(
                    lane,
                    format!("wave85-{}-rollback-transcript", lane.as_str()),
                    height.saturating_sub(4 + index as u64),
                )
                .with_status(DrillStatus::Replayed)
            })
            .collect::<Vec<_>>();
        let operator_signoffs = vec![
            OperatorTranscriptSignoff::acknowledgement("rollback-operator-alpha", 30, height),
            OperatorTranscriptSignoff::acknowledgement("rollback-operator-beta", 30, height),
            OperatorTranscriptSignoff::acknowledgement("rollback-operator-gamma", 25, height),
        ];
        match Self::new(config, height, lane_transcripts, operator_signoffs) {
            Ok(state) => state,
            Err(_) => Self::fallback(),
        }
    }

    pub fn fallback() -> Self {
        let config = Config {
            transcript_policy_id: "fallback-rollback-drill-transcript".to_string(),
            required_lanes: vec![TranscriptLane::CompileRuntime],
            max_transcript_age_blocks: DEFAULT_MAX_TRANSCRIPT_AGE_BLOCKS,
            min_operator_weight: DEFAULT_MIN_OPERATOR_WEIGHT,
            min_drill_score: DEFAULT_MIN_DRILL_SCORE,
            min_rollback_score: DEFAULT_MIN_ROLLBACK_SCORE,
            require_deployment_guard_root: true,
            require_rollback_command_root: true,
            require_abort_receipt_root: true,
            require_runbook_transcript_root: true,
            require_expected_receipt_root: true,
            require_private_transcripts: true,
            keep_release_held_while_receipts_deferred: true,
            fail_closed: true,
        };
        let lane = LaneDrillTranscript::new(
            TranscriptLane::CompileRuntime,
            "fallback-compile-rollback-transcript",
            DEFAULT_HEIGHT,
        );
        let operator = OperatorTranscriptSignoff::acknowledgement(
            "fallback-rollback-operator",
            0,
            DEFAULT_HEIGHT,
        );
        let mut blockers = BTreeMap::new();
        blockers.insert(
            TranscriptLane::CompileRuntime.as_str().to_string(),
            vec![
                TranscriptBlockerKind::DrillNotAccepted,
                TranscriptBlockerKind::HeavyGateReceiptsDeferred,
                TranscriptBlockerKind::ReleaseStillHeld,
            ],
        );
        let transcript_root = merkle_root(
            "rollback-drill-transcript-fallback-lanes",
            &[lane.public_record()],
        );
        let operator_root = merkle_root(
            "rollback-drill-transcript-fallback-operators",
            &[operator.public_record()],
        );
        let blocker_root = merkle_root(
            "rollback-drill-transcript-fallback-blockers",
            &[json!({
                "subject": TranscriptLane::CompileRuntime.as_str(),
                "blockers": ["drill_not_accepted", "heavy_gate_receipts_deferred", "release_still_held"],
            })],
        );
        let summary_root = domain_hash(
            "rollback-drill-transcript-fallback-summary",
            &[
                HashPart::Str(&config.transcript_policy_id),
                HashPart::Str(&transcript_root),
                HashPart::Str(&operator_root),
                HashPart::Str(&blocker_root),
            ],
            32,
        );
        Self {
            config,
            height: DEFAULT_HEIGHT,
            lane_transcripts: vec![lane],
            operator_signoffs: vec![operator],
            blockers,
            transcript_root: transcript_root.clone(),
            operator_root: operator_root.clone(),
            blocker_root: blocker_root.clone(),
            summary: HoldUnholdSummary {
                release_can_unhold: false,
                release_remains_held: true,
                transcript_count: 1,
                accepted_transcript_count: 0,
                operator_weight: 0,
                blocker_count: 3,
                transcript_root,
                operator_root,
                blocker_root,
                summary_root,
            },
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "transcript_root": self.transcript_root,
            "operator_root": self.operator_root,
            "blocker_root": self.blocker_root,
            "summary": self.summary.public_record(),
            "lane_transcripts": self.lane_transcripts.iter().map(LaneDrillTranscript::public_record).collect::<Vec<_>>(),
            "operator_signoffs": self.operator_signoffs.iter().map(OperatorTranscriptSignoff::public_record).collect::<Vec<_>>(),
            "blockers": self.blockers.iter().map(|(subject, blockers)| {
                json!({
                    "subject": subject,
                    "blockers": blockers.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
                })
            }).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "rollback-drill-transcript-state",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.transcript_policy_id),
                HashPart::U64(self.height),
                HashPart::Str(&self.transcript_root),
                HashPart::Str(&self.operator_root),
                HashPart::Str(&self.blocker_root),
                HashPart::Str(&self.summary.summary_root),
                HashPart::Json(&self.public_record()),
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

fn evaluate_blockers(
    config: &Config,
    height: u64,
    lane_transcripts: &[LaneDrillTranscript],
    operator_signoffs: &[OperatorTranscriptSignoff],
) -> BTreeMap<String, Vec<TranscriptBlockerKind>> {
    let mut blockers = BTreeMap::<String, Vec<TranscriptBlockerKind>>::new();
    let mut seen = BTreeSet::new();
    for transcript in lane_transcripts {
        let key = transcript.lane.as_str().to_string();
        if !seen.insert(transcript.lane) {
            blockers
                .entry(key.clone())
                .or_default()
                .push(TranscriptBlockerKind::DuplicateLaneTranscript);
        }
        let lane_blockers = transcript.blockers(config, height);
        if !lane_blockers.is_empty() {
            blockers.entry(key).or_default().extend(lane_blockers);
        }
    }
    for lane in &config.required_lanes {
        if !seen.contains(lane) {
            blockers
                .entry(lane.as_str().to_string())
                .or_default()
                .push(TranscriptBlockerKind::MissingLaneTranscript);
        }
    }
    let operator_weight = operator_signoffs
        .iter()
        .filter(|signoff| signoff.decision.contributes_weight())
        .map(|signoff| signoff.weight)
        .sum::<u64>();
    if operator_weight < config.min_operator_weight {
        blockers
            .entry("operator_quorum".to_string())
            .or_default()
            .push(TranscriptBlockerKind::OperatorWeightTooLow);
    }
    for signoff in operator_signoffs {
        if signoff.decision.blocks_unhold() {
            let blocker = match signoff.decision {
                OperatorDecision::RejectUnhold => TranscriptBlockerKind::OperatorRejectedUnhold,
                OperatorDecision::Pending => TranscriptBlockerKind::OperatorPendingUnhold,
                OperatorDecision::AcknowledgeHold
                | OperatorDecision::ApproveUnholdAfterReceipts => {
                    TranscriptBlockerKind::OperatorPendingUnhold
                }
            };
            blockers
                .entry(signoff.operator_id.clone())
                .or_default()
                .push(blocker);
        }
    }
    blockers
}

fn transcript_policy_id(label: &str) -> String {
    domain_hash(
        "rollback-drill-transcript-id",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        16,
    )
}

fn transcript_root(
    lane: TranscriptLane,
    transcript_id: &str,
    domain: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "rollback-drill-transcript-root",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(transcript_id),
            HashPart::Str(domain),
            HashPart::U64(observed_at_height),
        ],
        32,
    )
}

fn operator_root(operator_id: &str, height: u64, domain: &str) -> String {
    domain_hash(
        "rollback-drill-transcript-operator-root",
        &[
            HashPart::Str(operator_id),
            HashPart::U64(height),
            HashPart::Str(domain),
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

fn ensure_non_empty(name: &str, value: &str) -> Result<()> {
    ensure(
        !value.trim().is_empty(),
        &format!("{name} must not be empty"),
    )
}
