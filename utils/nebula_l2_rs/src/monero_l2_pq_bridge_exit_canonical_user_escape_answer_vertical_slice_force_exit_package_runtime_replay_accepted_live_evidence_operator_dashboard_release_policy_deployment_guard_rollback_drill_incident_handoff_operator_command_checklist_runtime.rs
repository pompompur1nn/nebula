use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageRuntimeReplayAcceptedLiveEvidenceOperatorDashboardReleasePolicyDeploymentGuardRollbackDrillIncidentHandoffOperatorCommandChecklistRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RUNTIME_REPLAY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_INCIDENT_HANDOFF_OPERATOR_COMMAND_CHECKLIST_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-runtime-replay-accepted-live-evidence-operator-dashboard-release-policy-deployment-guard-rollback-drill-incident-handoff-operator-command-checklist-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RUNTIME_REPLAY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_INCIDENT_HANDOFF_OPERATOR_COMMAND_CHECKLIST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const COMMAND_CHECKLIST_SUITE: &str = "runtime-replay-operator-command-checklist-v1";
pub const DEFAULT_INCIDENT_HEIGHT: u64 = 86_087;
pub const DEFAULT_TARGET_HEIGHT: u64 = 86_060;
pub const DEFAULT_MAX_REPLAY_WINDOW_BLOCKS: u64 = 128;
pub const DEFAULT_MIN_CHECKLIST_ITEMS: u16 = 6;
pub const DEFAULT_MIN_TARGET_RECEIPTS: u16 = 3;
pub const DEFAULT_MIN_DEFERRED_PLACEHOLDERS: u16 = 3;
pub const DEFAULT_MIN_OWNER_ACKS: u16 = 4;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistPhase {
    ReplayWindowBound,
    TargetHeightReceipts,
    MismatchBlockers,
    DeferredHeavyGate,
    CommandRoomOwners,
    ReplayAuthority,
}

impl ChecklistPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReplayWindowBound => "replay_window_bound",
            Self::TargetHeightReceipts => "target_height_receipts",
            Self::MismatchBlockers => "mismatch_blockers",
            Self::DeferredHeavyGate => "deferred_heavy_gate",
            Self::CommandRoomOwners => "command_room_owners",
            Self::ReplayAuthority => "replay_authority",
        }
    }

    pub fn ordinal(self) -> u8 {
        match self {
            Self::ReplayWindowBound => 0,
            Self::TargetHeightReceipts => 1,
            Self::MismatchBlockers => 2,
            Self::DeferredHeavyGate => 3,
            Self::CommandRoomOwners => 4,
            Self::ReplayAuthority => 5,
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::ReplayWindowBound,
            Self::TargetHeightReceipts,
            Self::MismatchBlockers,
            Self::DeferredHeavyGate,
            Self::CommandRoomOwners,
            Self::ReplayAuthority,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistVerdict {
    Ready,
    Blocked,
    MismatchBlocked,
    FailClosed,
}

impl ChecklistVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Blocked => "blocked",
            Self::MismatchBlocked => "mismatch_blocked",
            Self::FailClosed => "fail_closed",
        }
    }

    pub fn release_allowed(self) -> bool {
        matches!(self, Self::Ready)
    }

    pub fn fail_closed(self) -> bool {
        !self.release_allowed()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub incident_height: u64,
    pub target_height: u64,
    pub max_replay_window_blocks: u64,
    pub min_checklist_items: u16,
    pub min_target_receipts: u16,
    pub min_deferred_placeholders: u16,
    pub min_owner_acks: u16,
    pub require_fail_closed_replay_authority: bool,
    pub require_privacy_safe_public_record: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            incident_height: DEFAULT_INCIDENT_HEIGHT,
            target_height: DEFAULT_TARGET_HEIGHT,
            max_replay_window_blocks: DEFAULT_MAX_REPLAY_WINDOW_BLOCKS,
            min_checklist_items: DEFAULT_MIN_CHECKLIST_ITEMS,
            min_target_receipts: DEFAULT_MIN_TARGET_RECEIPTS,
            min_deferred_placeholders: DEFAULT_MIN_DEFERRED_PLACEHOLDERS,
            min_owner_acks: DEFAULT_MIN_OWNER_ACKS,
            require_fail_closed_replay_authority: true,
            require_privacy_safe_public_record: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure(
            self.incident_height >= self.target_height,
            "incident height must be at or after target height",
        )?;
        ensure(
            self.incident_height.saturating_sub(self.target_height)
                <= self.max_replay_window_blocks,
            "target height is outside replay checklist window",
        )?;
        ensure(
            self.min_checklist_items > 0,
            "minimum checklist item count must be non-zero",
        )?;
        ensure(
            self.min_target_receipts > 0,
            "minimum target-height receipt count must be non-zero",
        )?;
        ensure(
            self.min_deferred_placeholders > 0,
            "minimum deferred heavy gate placeholder count must be non-zero",
        )?;
        ensure(
            self.min_owner_acks > 0,
            "minimum command-room owner acknowledgement count must be non-zero",
        )
    }

    pub fn canonical(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "incident_height": self.incident_height,
            "target_height": self.target_height,
            "max_replay_window_blocks": self.max_replay_window_blocks,
            "min_checklist_items": self.min_checklist_items,
            "min_target_receipts": self.min_target_receipts,
            "min_deferred_placeholders": self.min_deferred_placeholders,
            "min_owner_acks": self.min_owner_acks,
            "require_fail_closed_replay_authority": self.require_fail_closed_replay_authority,
            "require_privacy_safe_public_record": self.require_privacy_safe_public_record,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "runtime-replay-operator-command-checklist:config",
            &[HashPart::Json(&self.canonical())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayHandoffRoots {
    pub handoff_root: String,
    pub replay_transcript_root: String,
    pub target_height_root: String,
    pub deferred_gate_root: String,
    pub command_room_ack_root: String,
    pub blocker_root: String,
    pub decision_root: String,
    pub source_state_root: String,
    pub release_allowed: bool,
    pub fail_closed: bool,
}

impl ReplayHandoffRoots {
    pub fn validate(&self) -> Result<()> {
        ensure_root("handoff_root", &self.handoff_root)?;
        ensure_root("replay_transcript_root", &self.replay_transcript_root)?;
        ensure_root("target_height_root", &self.target_height_root)?;
        ensure_root("deferred_gate_root", &self.deferred_gate_root)?;
        ensure_root("command_room_ack_root", &self.command_room_ack_root)?;
        ensure_root("blocker_root", &self.blocker_root)?;
        ensure_root("decision_root", &self.decision_root)?;
        ensure_root("source_state_root", &self.source_state_root)?;
        ensure(
            self.fail_closed != self.release_allowed,
            "handoff roots must carry exactly one release authority state",
        )
    }

    pub fn canonical(&self) -> Value {
        json!({
            "handoff_root": self.handoff_root,
            "replay_transcript_root": self.replay_transcript_root,
            "target_height_root": self.target_height_root,
            "deferred_gate_root": self.deferred_gate_root,
            "command_room_ack_root": self.command_room_ack_root,
            "blocker_root": self.blocker_root,
            "decision_root": self.decision_root,
            "source_state_root": self.source_state_root,
            "release_allowed": self.release_allowed,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "handoff_binding_root": self.root(),
            "source_state_root": self.source_state_root,
            "release_allowed": self.release_allowed,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "runtime-replay-operator-command-checklist:handoff-roots",
            &[HashPart::Json(&self.canonical())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChecklistItem {
    pub item_id: String,
    pub phase: ChecklistPhase,
    pub handoff_root: String,
    pub replay_window_root: String,
    pub checklist_commitment_root: String,
    pub target_height: u64,
    pub required: bool,
    pub completed: bool,
    pub operator_visible: bool,
}

impl ChecklistItem {
    pub fn validate(&self, config: &Config, handoff_roots: &ReplayHandoffRoots) -> Result<()> {
        ensure_non_empty("checklist item id", &self.item_id)?;
        ensure_root("handoff_root", &self.handoff_root)?;
        ensure_root("replay_window_root", &self.replay_window_root)?;
        ensure_root("checklist_commitment_root", &self.checklist_commitment_root)?;
        ensure(
            self.handoff_root == handoff_roots.handoff_root,
            "checklist item handoff root must match bound handoff",
        )?;
        ensure(
            self.replay_window_root == handoff_roots.replay_transcript_root,
            "checklist item replay window root must match handoff replay transcript root",
        )?;
        ensure(
            self.target_height == config.target_height,
            "checklist item target height must match config target height",
        )
    }

    pub fn blocks_release(&self) -> bool {
        self.required && (!self.completed || !self.operator_visible)
    }

    pub fn canonical(&self) -> Value {
        json!({
            "item_id": self.item_id,
            "phase": self.phase.as_str(),
            "phase_ordinal": self.phase.ordinal(),
            "handoff_root": self.handoff_root,
            "replay_window_root": self.replay_window_root,
            "checklist_commitment_root": self.checklist_commitment_root,
            "target_height": self.target_height,
            "required": self.required,
            "completed": self.completed,
            "operator_visible": self.operator_visible,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "item_root": self.root(),
            "phase": self.phase.as_str(),
            "phase_ordinal": self.phase.ordinal(),
            "target_height": self.target_height,
            "required": self.required,
            "completed": self.completed,
            "operator_visible": self.operator_visible,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "runtime-replay-operator-command-checklist:item",
            &[HashPart::Json(&self.canonical())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TargetHeightReceipt {
    pub receipt_id: String,
    pub target_height: u64,
    pub receipt_root: String,
    pub checkpoint_root: String,
    pub handoff_target_height_root: String,
    pub observed_height: u64,
    pub matches_target: bool,
    pub accepted: bool,
}

impl TargetHeightReceipt {
    pub fn validate(&self, config: &Config, handoff_roots: &ReplayHandoffRoots) -> Result<()> {
        ensure_non_empty("target receipt id", &self.receipt_id)?;
        ensure_root("receipt_root", &self.receipt_root)?;
        ensure_root("checkpoint_root", &self.checkpoint_root)?;
        ensure_root(
            "handoff_target_height_root",
            &self.handoff_target_height_root,
        )?;
        ensure(
            self.target_height == config.target_height,
            "target receipt height must match config target height",
        )?;
        ensure(
            self.handoff_target_height_root == handoff_roots.target_height_root,
            "target receipt root must match handoff target-height root",
        )?;
        ensure(
            self.observed_height >= config.target_height,
            "target receipt observed height must cover target height",
        )?;
        ensure(
            self.observed_height <= config.incident_height,
            "target receipt observed height must not exceed incident height",
        )
    }

    pub fn blocks_release(&self) -> bool {
        !self.matches_target || !self.accepted
    }

    pub fn canonical(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "target_height": self.target_height,
            "receipt_root": self.receipt_root,
            "checkpoint_root": self.checkpoint_root,
            "handoff_target_height_root": self.handoff_target_height_root,
            "observed_height": self.observed_height,
            "matches_target": self.matches_target,
            "accepted": self.accepted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "target_receipt_root": self.root(),
            "target_height": self.target_height,
            "observed_height": self.observed_height,
            "matches_target": self.matches_target,
            "accepted": self.accepted,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "runtime-replay-operator-command-checklist:target-height-receipt",
            &[HashPart::Json(&self.canonical())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MismatchBlocker {
    pub blocker_id: String,
    pub phase: ChecklistPhase,
    pub planned_root: String,
    pub observed_root: String,
    pub blocker_root: String,
    pub active: bool,
    pub fail_closed: bool,
}

impl MismatchBlocker {
    pub fn new(
        blocker_id: &str,
        phase: ChecklistPhase,
        planned_root: &str,
        observed_root: &str,
        active: bool,
    ) -> Self {
        let blocker_root = domain_hash(
            "runtime-replay-operator-command-checklist:mismatch-blocker",
            &[
                HashPart::Str(blocker_id),
                HashPart::Str(phase.as_str()),
                HashPart::Str(planned_root),
                HashPart::Str(observed_root),
                HashPart::Str(bool_str(active)),
            ],
            32,
        );
        Self {
            blocker_id: blocker_id.to_string(),
            phase,
            planned_root: planned_root.to_string(),
            observed_root: observed_root.to_string(),
            blocker_root,
            active,
            fail_closed: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("mismatch blocker id", &self.blocker_id)?;
        ensure_root("planned_root", &self.planned_root)?;
        ensure_root("observed_root", &self.observed_root)?;
        ensure_root("blocker_root", &self.blocker_root)?;
        ensure(self.fail_closed, "mismatch blocker must be fail-closed")
    }

    pub fn blocks_release(&self) -> bool {
        self.active || self.planned_root != self.observed_root
    }

    pub fn canonical(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "phase": self.phase.as_str(),
            "phase_ordinal": self.phase.ordinal(),
            "planned_root": self.planned_root,
            "observed_root": self.observed_root,
            "blocker_root": self.blocker_root,
            "active": self.active,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_root": self.blocker_root,
            "phase": self.phase.as_str(),
            "active": self.active,
            "fail_closed": self.fail_closed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeferredHeavyGatePlaceholder {
    pub gate_id: String,
    pub handoff_deferred_gate_root: String,
    pub placeholder_root: String,
    pub policy_root: String,
    pub target_height: u64,
    pub heavy_gate_deferred: bool,
    pub fail_closed_until_executed: bool,
}

impl DeferredHeavyGatePlaceholder {
    pub fn validate(&self, config: &Config, handoff_roots: &ReplayHandoffRoots) -> Result<()> {
        ensure_non_empty("deferred heavy gate id", &self.gate_id)?;
        ensure_root(
            "handoff_deferred_gate_root",
            &self.handoff_deferred_gate_root,
        )?;
        ensure_root("placeholder_root", &self.placeholder_root)?;
        ensure_root("policy_root", &self.policy_root)?;
        ensure(
            self.handoff_deferred_gate_root == handoff_roots.deferred_gate_root,
            "heavy gate placeholder must bind handoff deferred gate root",
        )?;
        ensure(
            self.target_height == config.target_height,
            "heavy gate placeholder target height must match config target height",
        )
    }

    pub fn armed(&self) -> bool {
        self.heavy_gate_deferred && self.fail_closed_until_executed
    }

    pub fn canonical(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "handoff_deferred_gate_root": self.handoff_deferred_gate_root,
            "placeholder_root": self.placeholder_root,
            "policy_root": self.policy_root,
            "target_height": self.target_height,
            "heavy_gate_deferred": self.heavy_gate_deferred,
            "fail_closed_until_executed": self.fail_closed_until_executed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "placeholder_binding_root": self.root(),
            "target_height": self.target_height,
            "heavy_gate_deferred": self.heavy_gate_deferred,
            "fail_closed_until_executed": self.fail_closed_until_executed,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "runtime-replay-operator-command-checklist:deferred-heavy-gate",
            &[HashPart::Json(&self.canonical())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandRoomOwnerAck {
    pub owner_id: String,
    pub role_root: String,
    pub command_room_ack_root: String,
    pub checklist_root: String,
    pub target_height: u64,
    pub acknowledged: bool,
    pub accepts_fail_closed_authority: bool,
}

impl CommandRoomOwnerAck {
    pub fn validate(&self, config: &Config, handoff_roots: &ReplayHandoffRoots) -> Result<()> {
        ensure_non_empty("command-room owner id", &self.owner_id)?;
        ensure_root("role_root", &self.role_root)?;
        ensure_root("command_room_ack_root", &self.command_room_ack_root)?;
        ensure_root("checklist_root", &self.checklist_root)?;
        ensure(
            self.command_room_ack_root == handoff_roots.command_room_ack_root,
            "owner acknowledgement must bind handoff command-room acknowledgement root",
        )?;
        ensure(
            self.target_height == config.target_height,
            "owner acknowledgement target height must match config target height",
        )
    }

    pub fn blocks_release(&self) -> bool {
        !self.acknowledged || !self.accepts_fail_closed_authority
    }

    pub fn canonical(&self) -> Value {
        json!({
            "owner_id": self.owner_id,
            "role_root": self.role_root,
            "command_room_ack_root": self.command_room_ack_root,
            "checklist_root": self.checklist_root,
            "target_height": self.target_height,
            "acknowledged": self.acknowledged,
            "accepts_fail_closed_authority": self.accepts_fail_closed_authority,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "owner_ack_root": self.root(),
            "target_height": self.target_height,
            "acknowledged": self.acknowledged,
            "accepts_fail_closed_authority": self.accepts_fail_closed_authority,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "runtime-replay-operator-command-checklist:owner-ack",
            &[HashPart::Json(&self.canonical())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayAuthority {
    pub authority_id: String,
    pub handoff_decision_root: String,
    pub checklist_root: String,
    pub authority_root: String,
    pub target_height: u64,
    pub release_allowed: bool,
    pub fail_closed: bool,
}

impl ReplayAuthority {
    pub fn validate(
        &self,
        config: &Config,
        handoff_roots: &ReplayHandoffRoots,
        checklist_root: &str,
    ) -> Result<()> {
        ensure_non_empty("replay authority id", &self.authority_id)?;
        ensure_root("handoff_decision_root", &self.handoff_decision_root)?;
        ensure_root("checklist_root", &self.checklist_root)?;
        ensure_root("authority_root", &self.authority_root)?;
        ensure_root("computed checklist root", checklist_root)?;
        ensure(
            self.handoff_decision_root == handoff_roots.decision_root,
            "replay authority must bind handoff decision root",
        )?;
        ensure(
            self.checklist_root == checklist_root,
            "replay authority checklist root must match computed checklist root",
        )?;
        ensure(
            self.target_height == config.target_height,
            "replay authority target height must match config target height",
        )?;
        ensure(
            self.fail_closed != self.release_allowed,
            "replay authority must carry exactly one release state",
        )?;
        if config.require_fail_closed_replay_authority {
            ensure(
                self.fail_closed && !self.release_allowed,
                "config requires replay authority to fail closed",
            )?;
        }
        Ok(())
    }

    pub fn canonical(&self) -> Value {
        json!({
            "authority_id": self.authority_id,
            "handoff_decision_root": self.handoff_decision_root,
            "checklist_root": self.checklist_root,
            "authority_root": self.authority_root,
            "target_height": self.target_height,
            "release_allowed": self.release_allowed,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "authority_root": self.authority_root,
            "target_height": self.target_height,
            "release_allowed": self.release_allowed,
            "fail_closed": self.fail_closed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChecklistCounters {
    pub checklist_item_count: u64,
    pub completed_checklist_item_count: u64,
    pub operator_visible_item_count: u64,
    pub target_receipt_count: u64,
    pub accepted_target_receipt_count: u64,
    pub mismatch_blocker_count: u64,
    pub active_mismatch_blocker_count: u64,
    pub deferred_placeholder_count: u64,
    pub armed_deferred_placeholder_count: u64,
    pub owner_ack_count: u64,
    pub acknowledged_owner_count: u64,
    pub fail_closed_owner_count: u64,
}

impl ChecklistCounters {
    pub fn canonical(&self) -> Value {
        json!({
            "checklist_item_count": self.checklist_item_count,
            "completed_checklist_item_count": self.completed_checklist_item_count,
            "operator_visible_item_count": self.operator_visible_item_count,
            "target_receipt_count": self.target_receipt_count,
            "accepted_target_receipt_count": self.accepted_target_receipt_count,
            "mismatch_blocker_count": self.mismatch_blocker_count,
            "active_mismatch_blocker_count": self.active_mismatch_blocker_count,
            "deferred_placeholder_count": self.deferred_placeholder_count,
            "armed_deferred_placeholder_count": self.armed_deferred_placeholder_count,
            "owner_ack_count": self.owner_ack_count,
            "acknowledged_owner_count": self.acknowledged_owner_count,
            "fail_closed_owner_count": self.fail_closed_owner_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChecklistDecision {
    pub verdict: ChecklistVerdict,
    pub release_allowed: bool,
    pub fail_closed: bool,
    pub decision_root: String,
}

impl ChecklistDecision {
    pub fn validate(&self) -> Result<()> {
        ensure_root("decision_root", &self.decision_root)?;
        ensure(
            self.verdict.release_allowed() == self.release_allowed,
            "checklist decision release allowance must match verdict",
        )?;
        ensure(
            self.fail_closed == !self.release_allowed,
            "checklist decision fail-closed flag must oppose release allowance",
        )
    }

    pub fn canonical(&self) -> Value {
        json!({
            "verdict": self.verdict.as_str(),
            "release_allowed": self.release_allowed,
            "fail_closed": self.fail_closed,
            "decision_root": self.decision_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub command_checklist_suite: String,
    pub config: Config,
    pub handoff_roots: ReplayHandoffRoots,
    pub checklist_items: Vec<ChecklistItem>,
    pub target_height_receipts: Vec<TargetHeightReceipt>,
    pub mismatch_blockers: Vec<MismatchBlocker>,
    pub deferred_heavy_gate_placeholders: Vec<DeferredHeavyGatePlaceholder>,
    pub command_room_owner_acks: Vec<CommandRoomOwnerAck>,
    pub replay_authority: ReplayAuthority,
    pub counters: ChecklistCounters,
    pub handoff_binding_root: String,
    pub checklist_item_root: String,
    pub target_receipt_root: String,
    pub mismatch_blocker_root: String,
    pub deferred_heavy_gate_root: String,
    pub command_room_owner_ack_root: String,
    pub authority_root: String,
    pub checklist_root: String,
    pub decision: ChecklistDecision,
}

impl State {
    pub fn new(
        config: Config,
        handoff_roots: ReplayHandoffRoots,
        checklist_items: Vec<ChecklistItem>,
        target_height_receipts: Vec<TargetHeightReceipt>,
        mismatch_blockers: Vec<MismatchBlocker>,
        deferred_heavy_gate_placeholders: Vec<DeferredHeavyGatePlaceholder>,
        command_room_owner_acks: Vec<CommandRoomOwnerAck>,
    ) -> Result<Self> {
        config.validate()?;
        handoff_roots.validate()?;
        validate_checklist_items(&config, &handoff_roots, &checklist_items)?;
        validate_target_height_receipts(&config, &handoff_roots, &target_height_receipts)?;
        validate_mismatch_blockers(&mismatch_blockers)?;
        validate_deferred_heavy_gate_placeholders(
            &config,
            &handoff_roots,
            &deferred_heavy_gate_placeholders,
        )?;
        validate_command_room_owner_acks(&config, &handoff_roots, &command_room_owner_acks)?;

        let handoff_binding_root = handoff_roots.root();
        let checklist_item_root = merkle_root(
            "runtime-replay-operator-command-checklist:items",
            &checklist_items
                .iter()
                .map(ChecklistItem::canonical)
                .collect::<Vec<_>>(),
        );
        let target_receipt_root = merkle_root(
            "runtime-replay-operator-command-checklist:target-receipts",
            &target_height_receipts
                .iter()
                .map(TargetHeightReceipt::canonical)
                .collect::<Vec<_>>(),
        );
        let mismatch_blocker_root = merkle_root(
            "runtime-replay-operator-command-checklist:mismatch-blockers",
            &mismatch_blockers
                .iter()
                .map(MismatchBlocker::canonical)
                .collect::<Vec<_>>(),
        );
        let deferred_heavy_gate_root = merkle_root(
            "runtime-replay-operator-command-checklist:deferred-heavy-gates",
            &deferred_heavy_gate_placeholders
                .iter()
                .map(DeferredHeavyGatePlaceholder::canonical)
                .collect::<Vec<_>>(),
        );
        let command_room_owner_ack_root = merkle_root(
            "runtime-replay-operator-command-checklist:owner-acks",
            &command_room_owner_acks
                .iter()
                .map(CommandRoomOwnerAck::canonical)
                .collect::<Vec<_>>(),
        );
        let counters = count_checklist(
            &checklist_items,
            &target_height_receipts,
            &mismatch_blockers,
            &deferred_heavy_gate_placeholders,
            &command_room_owner_acks,
        );
        let checklist_root = domain_hash(
            "runtime-replay-operator-command-checklist:state",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(SCHEMA_VERSION),
                HashPart::Str(&config.root()),
                HashPart::Str(&handoff_binding_root),
                HashPart::Str(&checklist_item_root),
                HashPart::Str(&target_receipt_root),
                HashPart::Str(&mismatch_blocker_root),
                HashPart::Str(&deferred_heavy_gate_root),
                HashPart::Str(&command_room_owner_ack_root),
                HashPart::Json(&counters.canonical()),
            ],
            32,
        );
        let replay_authority = replay_authority(
            &config,
            &handoff_roots,
            &checklist_root,
            has_release_blocker(
                &config,
                &handoff_roots,
                &checklist_items,
                &target_height_receipts,
                &mismatch_blockers,
                &deferred_heavy_gate_placeholders,
                &command_room_owner_acks,
            ),
        );
        replay_authority.validate(&config, &handoff_roots, &checklist_root)?;
        let authority_root = replay_authority.authority_root.clone();

        let verdict = checklist_verdict(
            &config,
            &handoff_roots,
            &checklist_items,
            &target_height_receipts,
            &mismatch_blockers,
            &deferred_heavy_gate_placeholders,
            &command_room_owner_acks,
        );
        let decision_root = domain_hash(
            "runtime-replay-operator-command-checklist:decision",
            &[
                HashPart::Str(verdict.as_str()),
                HashPart::Str(bool_str(verdict.release_allowed())),
                HashPart::Str(bool_str(verdict.fail_closed())),
                HashPart::Str(&checklist_root),
                HashPart::Str(&authority_root),
            ],
            32,
        );
        let decision = ChecklistDecision {
            verdict,
            release_allowed: verdict.release_allowed(),
            fail_closed: verdict.fail_closed(),
            decision_root,
        };
        decision.validate()?;

        let state = Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            command_checklist_suite: COMMAND_CHECKLIST_SUITE.to_string(),
            config,
            handoff_roots,
            checklist_items,
            target_height_receipts,
            mismatch_blockers,
            deferred_heavy_gate_placeholders,
            command_room_owner_acks,
            replay_authority,
            counters,
            handoff_binding_root,
            checklist_item_root,
            target_receipt_root,
            mismatch_blocker_root,
            deferred_heavy_gate_root,
            command_room_owner_ack_root,
            authority_root,
            checklist_root,
            decision,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> Result<()> {
        ensure(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        ensure(
            self.schema_version == SCHEMA_VERSION,
            "schema version mismatch",
        )?;
        ensure(self.hash_suite == HASH_SUITE, "hash suite mismatch")?;
        ensure(
            self.command_checklist_suite == COMMAND_CHECKLIST_SUITE,
            "command checklist suite mismatch",
        )?;
        self.config.validate()?;
        self.handoff_roots.validate()?;
        validate_checklist_items(&self.config, &self.handoff_roots, &self.checklist_items)?;
        validate_target_height_receipts(
            &self.config,
            &self.handoff_roots,
            &self.target_height_receipts,
        )?;
        validate_mismatch_blockers(&self.mismatch_blockers)?;
        validate_deferred_heavy_gate_placeholders(
            &self.config,
            &self.handoff_roots,
            &self.deferred_heavy_gate_placeholders,
        )?;
        validate_command_room_owner_acks(
            &self.config,
            &self.handoff_roots,
            &self.command_room_owner_acks,
        )?;
        ensure_root("handoff_binding_root", &self.handoff_binding_root)?;
        ensure_root("checklist_item_root", &self.checklist_item_root)?;
        ensure_root("target_receipt_root", &self.target_receipt_root)?;
        ensure_root("mismatch_blocker_root", &self.mismatch_blocker_root)?;
        ensure_root("deferred_heavy_gate_root", &self.deferred_heavy_gate_root)?;
        ensure_root(
            "command_room_owner_ack_root",
            &self.command_room_owner_ack_root,
        )?;
        ensure_root("authority_root", &self.authority_root)?;
        ensure_root("checklist_root", &self.checklist_root)?;
        self.replay_authority
            .validate(&self.config, &self.handoff_roots, &self.checklist_root)?;
        self.decision.validate()?;
        ensure(
            self.replay_authority.fail_closed == self.decision.fail_closed,
            "replay authority and checklist decision must agree on fail-closed state",
        )?;
        ensure(
            self.decision.fail_closed || !has_any_release_blocker(self),
            "checklist with blockers must remain fail-closed",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "command_checklist_suite": self.command_checklist_suite,
            "chain_id": self.config.chain_id,
            "incident_height": self.config.incident_height,
            "target_height": self.config.target_height,
            "config_root": self.config.root(),
            "handoff_binding_root": self.handoff_binding_root,
            "handoff_public": self.handoff_roots.public_record(),
            "checklist_item_root": self.checklist_item_root,
            "target_receipt_root": self.target_receipt_root,
            "mismatch_blocker_root": self.mismatch_blocker_root,
            "deferred_heavy_gate_root": self.deferred_heavy_gate_root,
            "command_room_owner_ack_root": self.command_room_owner_ack_root,
            "authority_root": self.authority_root,
            "checklist_root": self.checklist_root,
            "decision_root": self.decision.decision_root,
            "release_allowed": self.decision.release_allowed,
            "fail_closed": self.decision.fail_closed,
            "verdict": self.decision.verdict.as_str(),
            "counters": self.counters.canonical(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "runtime-replay-operator-command-checklist:public-state-root",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn fail_closed(&self) -> bool {
        self.decision.fail_closed
    }
}

pub fn devnet() -> Result<Runtime> {
    let config = Config::default();
    let handoff_roots = devnet_handoff_roots(&config);
    let checklist_items = ChecklistPhase::all()
        .into_iter()
        .map(|phase| checklist_item(phase, &config, &handoff_roots))
        .collect::<Vec<_>>();
    let target_height_receipts = vec![
        target_height_receipt("finalized-target", &config, &handoff_roots, 0),
        target_height_receipt("operator-target", &config, &handoff_roots, 1),
        target_height_receipt("dashboard-target", &config, &handoff_roots, 2),
    ];
    let mismatch_blockers = vec![
        MismatchBlocker::new(
            "replay-window-root-match",
            ChecklistPhase::ReplayWindowBound,
            &handoff_roots.replay_transcript_root,
            &handoff_roots.replay_transcript_root,
            false,
        ),
        MismatchBlocker::new(
            "target-height-root-match",
            ChecklistPhase::TargetHeightReceipts,
            &handoff_roots.target_height_root,
            &handoff_roots.target_height_root,
            false,
        ),
    ];
    let deferred_heavy_gate_placeholders = vec![
        deferred_placeholder("runtime-heavy-gate", &config, &handoff_roots, 0),
        deferred_placeholder("dashboard-heavy-gate", &config, &handoff_roots, 1),
        deferred_placeholder("release-policy-heavy-gate", &config, &handoff_roots, 2),
    ];
    let command_room_owner_acks = vec![
        owner_ack("incident-commander", &config, &handoff_roots, 0),
        owner_ack("release-captain", &config, &handoff_roots, 1),
        owner_ack("bridge-ops", &config, &handoff_roots, 2),
        owner_ack("security-ops", &config, &handoff_roots, 3),
    ];

    State::new(
        config,
        handoff_roots,
        checklist_items,
        target_height_receipts,
        mismatch_blockers,
        deferred_heavy_gate_placeholders,
        command_room_owner_acks,
    )
}

fn validate_checklist_items(
    config: &Config,
    handoff_roots: &ReplayHandoffRoots,
    items: &[ChecklistItem],
) -> Result<()> {
    ensure(
        items.len() >= usize::from(config.min_checklist_items),
        "insufficient replay command checklist items",
    )?;
    let mut ids = BTreeSet::new();
    let mut phases = BTreeSet::new();
    for item in items {
        item.validate(config, handoff_roots)?;
        ensure(
            ids.insert(item.item_id.clone()),
            "duplicate replay command checklist item id",
        )?;
        phases.insert(item.phase);
    }
    for phase in ChecklistPhase::all() {
        ensure(
            phases.contains(&phase),
            "replay command checklist must cover every phase",
        )?;
    }
    Ok(())
}

fn validate_target_height_receipts(
    config: &Config,
    handoff_roots: &ReplayHandoffRoots,
    receipts: &[TargetHeightReceipt],
) -> Result<()> {
    ensure(
        receipts.len() >= usize::from(config.min_target_receipts),
        "insufficient target-height receipts",
    )?;
    let mut ids = BTreeSet::new();
    for receipt in receipts {
        receipt.validate(config, handoff_roots)?;
        ensure(
            ids.insert(receipt.receipt_id.clone()),
            "duplicate target-height receipt id",
        )?;
    }
    Ok(())
}

fn validate_mismatch_blockers(blockers: &[MismatchBlocker]) -> Result<()> {
    let mut ids = BTreeSet::new();
    for blocker in blockers {
        blocker.validate()?;
        ensure(
            ids.insert(blocker.blocker_id.clone()),
            "duplicate mismatch blocker id",
        )?;
    }
    Ok(())
}

fn validate_deferred_heavy_gate_placeholders(
    config: &Config,
    handoff_roots: &ReplayHandoffRoots,
    placeholders: &[DeferredHeavyGatePlaceholder],
) -> Result<()> {
    ensure(
        placeholders.len() >= usize::from(config.min_deferred_placeholders),
        "insufficient deferred heavy gate placeholders",
    )?;
    let mut ids = BTreeSet::new();
    for placeholder in placeholders {
        placeholder.validate(config, handoff_roots)?;
        ensure(
            ids.insert(placeholder.gate_id.clone()),
            "duplicate deferred heavy gate placeholder id",
        )?;
    }
    Ok(())
}

fn validate_command_room_owner_acks(
    config: &Config,
    handoff_roots: &ReplayHandoffRoots,
    acks: &[CommandRoomOwnerAck],
) -> Result<()> {
    ensure(
        acks.len() >= usize::from(config.min_owner_acks),
        "insufficient command-room owner acknowledgements",
    )?;
    let mut ids = BTreeSet::new();
    for ack in acks {
        ack.validate(config, handoff_roots)?;
        ensure(
            ids.insert(ack.owner_id.clone()),
            "duplicate command-room owner acknowledgement id",
        )?;
    }
    Ok(())
}

fn count_checklist(
    items: &[ChecklistItem],
    receipts: &[TargetHeightReceipt],
    blockers: &[MismatchBlocker],
    placeholders: &[DeferredHeavyGatePlaceholder],
    acks: &[CommandRoomOwnerAck],
) -> ChecklistCounters {
    ChecklistCounters {
        checklist_item_count: items.len() as u64,
        completed_checklist_item_count: items.iter().filter(|item| item.completed).count() as u64,
        operator_visible_item_count: items.iter().filter(|item| item.operator_visible).count()
            as u64,
        target_receipt_count: receipts.len() as u64,
        accepted_target_receipt_count: receipts.iter().filter(|receipt| receipt.accepted).count()
            as u64,
        mismatch_blocker_count: blockers.len() as u64,
        active_mismatch_blocker_count: blockers
            .iter()
            .filter(|blocker| blocker.blocks_release())
            .count() as u64,
        deferred_placeholder_count: placeholders.len() as u64,
        armed_deferred_placeholder_count: placeholders
            .iter()
            .filter(|placeholder| placeholder.armed())
            .count() as u64,
        owner_ack_count: acks.len() as u64,
        acknowledged_owner_count: acks.iter().filter(|ack| ack.acknowledged).count() as u64,
        fail_closed_owner_count: acks
            .iter()
            .filter(|ack| ack.accepts_fail_closed_authority)
            .count() as u64,
    }
}

fn checklist_verdict(
    config: &Config,
    handoff_roots: &ReplayHandoffRoots,
    items: &[ChecklistItem],
    receipts: &[TargetHeightReceipt],
    blockers: &[MismatchBlocker],
    placeholders: &[DeferredHeavyGatePlaceholder],
    acks: &[CommandRoomOwnerAck],
) -> ChecklistVerdict {
    if blockers.iter().any(MismatchBlocker::blocks_release)
        || receipts.iter().any(TargetHeightReceipt::blocks_release)
    {
        return ChecklistVerdict::MismatchBlocked;
    }
    if has_release_blocker(
        config,
        handoff_roots,
        items,
        receipts,
        blockers,
        placeholders,
        acks,
    ) {
        ChecklistVerdict::FailClosed
    } else {
        ChecklistVerdict::Ready
    }
}

fn has_release_blocker(
    config: &Config,
    handoff_roots: &ReplayHandoffRoots,
    items: &[ChecklistItem],
    receipts: &[TargetHeightReceipt],
    blockers: &[MismatchBlocker],
    placeholders: &[DeferredHeavyGatePlaceholder],
    acks: &[CommandRoomOwnerAck],
) -> bool {
    config.require_fail_closed_replay_authority
        || handoff_roots.fail_closed
        || !handoff_roots.release_allowed
        || items.iter().any(ChecklistItem::blocks_release)
        || receipts.iter().any(TargetHeightReceipt::blocks_release)
        || blockers.iter().any(MismatchBlocker::blocks_release)
        || placeholders.iter().any(|placeholder| !placeholder.armed())
        || acks.iter().any(CommandRoomOwnerAck::blocks_release)
}

fn has_any_release_blocker(state: &State) -> bool {
    has_release_blocker(
        &state.config,
        &state.handoff_roots,
        &state.checklist_items,
        &state.target_height_receipts,
        &state.mismatch_blockers,
        &state.deferred_heavy_gate_placeholders,
        &state.command_room_owner_acks,
    )
}

fn replay_authority(
    config: &Config,
    handoff_roots: &ReplayHandoffRoots,
    checklist_root: &str,
    blocked: bool,
) -> ReplayAuthority {
    let fail_closed = blocked || config.require_fail_closed_replay_authority;
    let release_allowed = !fail_closed;
    let authority_root = domain_hash(
        "runtime-replay-operator-command-checklist:replay-authority",
        &[
            HashPart::Str(&handoff_roots.decision_root),
            HashPart::Str(checklist_root),
            HashPart::U64(config.target_height),
            HashPart::Str(bool_str(release_allowed)),
            HashPart::Str(bool_str(fail_closed)),
        ],
        32,
    );
    ReplayAuthority {
        authority_id: "fail-closed-replay-authority".to_string(),
        handoff_decision_root: handoff_roots.decision_root.clone(),
        checklist_root: checklist_root.to_string(),
        authority_root,
        target_height: config.target_height,
        release_allowed,
        fail_closed,
    }
}

fn devnet_handoff_roots(config: &Config) -> ReplayHandoffRoots {
    let handoff_root = sample_root("wave-86-handoff", config.incident_height);
    let replay_transcript_root = sample_root("wave-86-replay-transcripts", config.target_height);
    let target_height_root = sample_root("wave-86-target-height", config.target_height);
    let deferred_gate_root = sample_root("wave-86-deferred-gates", config.target_height);
    let command_room_ack_root = sample_root("wave-86-command-room-acks", config.incident_height);
    let blocker_root = sample_root("wave-86-blockers", config.incident_height);
    let decision_root = sample_root("wave-86-decision", config.incident_height);
    let source_state_root = domain_hash(
        "runtime-replay-operator-command-checklist:devnet-source-state",
        &[
            HashPart::Str(&handoff_root),
            HashPart::Str(&replay_transcript_root),
            HashPart::Str(&target_height_root),
            HashPart::Str(&deferred_gate_root),
            HashPart::Str(&command_room_ack_root),
            HashPart::Str(&blocker_root),
            HashPart::Str(&decision_root),
        ],
        32,
    );
    ReplayHandoffRoots {
        handoff_root,
        replay_transcript_root,
        target_height_root,
        deferred_gate_root,
        command_room_ack_root,
        blocker_root,
        decision_root,
        source_state_root,
        release_allowed: false,
        fail_closed: true,
    }
}

fn checklist_item(
    phase: ChecklistPhase,
    config: &Config,
    handoff_roots: &ReplayHandoffRoots,
) -> ChecklistItem {
    ChecklistItem {
        item_id: phase.as_str().to_string(),
        phase,
        handoff_root: handoff_roots.handoff_root.clone(),
        replay_window_root: handoff_roots.replay_transcript_root.clone(),
        checklist_commitment_root: sample_root(phase.as_str(), config.target_height),
        target_height: config.target_height,
        required: true,
        completed: true,
        operator_visible: true,
    }
}

fn target_height_receipt(
    label: &str,
    config: &Config,
    handoff_roots: &ReplayHandoffRoots,
    offset: u64,
) -> TargetHeightReceipt {
    TargetHeightReceipt {
        receipt_id: label.to_string(),
        target_height: config.target_height,
        receipt_root: sample_root(label, config.target_height + offset),
        checkpoint_root: sample_root("target-checkpoint", config.target_height + offset),
        handoff_target_height_root: handoff_roots.target_height_root.clone(),
        observed_height: config.target_height + offset,
        matches_target: true,
        accepted: true,
    }
}

fn deferred_placeholder(
    label: &str,
    config: &Config,
    handoff_roots: &ReplayHandoffRoots,
    offset: u64,
) -> DeferredHeavyGatePlaceholder {
    DeferredHeavyGatePlaceholder {
        gate_id: label.to_string(),
        handoff_deferred_gate_root: handoff_roots.deferred_gate_root.clone(),
        placeholder_root: sample_root(label, config.target_height + offset),
        policy_root: sample_root("heavy-gate-policy", config.target_height + offset),
        target_height: config.target_height,
        heavy_gate_deferred: true,
        fail_closed_until_executed: true,
    }
}

fn owner_ack(
    label: &str,
    config: &Config,
    handoff_roots: &ReplayHandoffRoots,
    offset: u64,
) -> CommandRoomOwnerAck {
    CommandRoomOwnerAck {
        owner_id: label.to_string(),
        role_root: sample_root("owner-role", offset),
        command_room_ack_root: handoff_roots.command_room_ack_root.clone(),
        checklist_root: sample_root("owner-checklist-view", config.incident_height + offset),
        target_height: config.target_height,
        acknowledged: true,
        accepts_fail_closed_authority: true,
    }
}

fn sample_root(label: &str, height: u64) -> String {
    domain_hash(
        "runtime-replay-operator-command-checklist:sample-root",
        &[HashPart::Str(label), HashPart::U64(height)],
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
    ensure(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        &format!("{label} must be a 32-byte lowercase hex root"),
    )?;
    ensure(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        &format!("{label} must use lowercase hex"),
    )
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
