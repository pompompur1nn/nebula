use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;
pub type MoneroL2PqBridgeExitForceExitWave87OperatorCommandChecklistTranscriptRuntimeResult<T> =
    Result<T>;

pub const MONERO_L2_PQ_BRIDGE_EXIT_FORCE_EXIT_WAVE87_OPERATOR_COMMAND_CHECKLIST_TRANSCRIPT_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-force-exit-wave87-operator-command-checklist-transcript-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_FORCE_EXIT_WAVE87_OPERATOR_COMMAND_CHECKLIST_TRANSCRIPT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CHECKLIST_SUITE: &str = "monero-l2-pq-force-exit-operator-command-checklist-handoff-v1";
pub const DEFAULT_RELEASE_EPOCH: u64 = 87;
pub const DEFAULT_INCIDENT_HANDOFF_EPOCH: u64 = 86;
pub const DEFAULT_CHECKLIST_HEIGHT: u64 = 870_000;
pub const DEFAULT_MAX_CHECKLIST_AGE_BLOCKS: u64 = 72;
pub const DEFAULT_MIN_COMMAND_WEIGHT: u64 = 95;
pub const DEFAULT_MIN_ACCEPTED_LANES: u16 = 6;
pub const DEFAULT_MIN_CHECKLIST_ITEMS_PER_LANE: u16 = 7;
pub const DEFAULT_MIN_BRIDGE_CUSTODY_DRILL_RECEIPTS: u16 = 4;
pub const DEFAULT_MIN_PRIVACY_REVIEW_RECEIPTS: u16 = 4;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistLane {
    CompileRuntime,
    RuntimeReplay,
    AuditSecurity,
    BridgeCustody,
    WalletWatchtower,
    PqReservePrivacy,
}

impl ChecklistLane {
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

    pub fn command_owner(self) -> &'static str {
        match self {
            Self::CompileRuntime => "runtime-release-lead",
            Self::RuntimeReplay => "runtime-replay-lead",
            Self::AuditSecurity => "security-incident-lead",
            Self::BridgeCustody => "bridge-custody-lead",
            Self::WalletWatchtower => "wallet-watchtower-lead",
            Self::PqReservePrivacy => "pq-reserve-privacy-lead",
        }
    }

    pub fn requires_bridge_custody(self) -> bool {
        matches!(self, Self::BridgeCustody | Self::PqReservePrivacy)
    }

    pub fn requires_privacy_review(self) -> bool {
        matches!(
            self,
            Self::AuditSecurity | Self::WalletWatchtower | Self::PqReservePrivacy
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistItemKind {
    IncidentHandoffRoot,
    CommandOwnerAck,
    ReleaseHoldAuthority,
    AbortCommandReady,
    RollbackReplayEvidence,
    DeferredHeavyGatePlaceholder,
    BridgeCustodyTransfer,
    ReserveLiabilityCheck,
    WatchtowerNotice,
    PrivacyLeakBudgetCheck,
    PqSignerPolicyCheck,
}

impl ChecklistItemKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IncidentHandoffRoot => "incident_handoff_root",
            Self::CommandOwnerAck => "command_owner_ack",
            Self::ReleaseHoldAuthority => "release_hold_authority",
            Self::AbortCommandReady => "abort_command_ready",
            Self::RollbackReplayEvidence => "rollback_replay_evidence",
            Self::DeferredHeavyGatePlaceholder => "deferred_heavy_gate_placeholder",
            Self::BridgeCustodyTransfer => "bridge_custody_transfer",
            Self::ReserveLiabilityCheck => "reserve_liability_check",
            Self::WatchtowerNotice => "watchtower_notice",
            Self::PrivacyLeakBudgetCheck => "privacy_leak_budget_check",
            Self::PqSignerPolicyCheck => "pq_signer_policy_check",
        }
    }

    pub fn required_for_lane(self, lane: ChecklistLane) -> bool {
        match self {
            Self::IncidentHandoffRoot
            | Self::CommandOwnerAck
            | Self::ReleaseHoldAuthority
            | Self::AbortCommandReady
            | Self::RollbackReplayEvidence
            | Self::DeferredHeavyGatePlaceholder => true,
            Self::BridgeCustodyTransfer | Self::ReserveLiabilityCheck => {
                lane.requires_bridge_custody()
            }
            Self::WatchtowerNotice => matches!(lane, ChecklistLane::WalletWatchtower),
            Self::PrivacyLeakBudgetCheck => lane.requires_privacy_review(),
            Self::PqSignerPolicyCheck => matches!(lane, ChecklistLane::PqReservePrivacy),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistStatus {
    Missing,
    Draft,
    Held,
    AcceptedWithHold,
    ReadyAfterHeavyGate,
    Rejected,
    Expired,
}

impl ChecklistStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Draft => "draft",
            Self::Held => "held",
            Self::AcceptedWithHold => "accepted_with_hold",
            Self::ReadyAfterHeavyGate => "ready_after_heavy_gate",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::AcceptedWithHold | Self::ReadyAfterHeavyGate)
    }

    pub fn release_blocking(self) -> bool {
        !matches!(self, Self::ReadyAfterHeavyGate)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandDecision {
    AcknowledgeHold,
    AcceptChecklist,
    AcceptCustodyHandoff,
    AcceptPrivacyHold,
    RequestMoreEvidence,
    RejectUnhold,
    ApproveOnlyAfterHeavyGates,
}

impl CommandDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AcknowledgeHold => "acknowledge_hold",
            Self::AcceptChecklist => "accept_checklist",
            Self::AcceptCustodyHandoff => "accept_custody_handoff",
            Self::AcceptPrivacyHold => "accept_privacy_hold",
            Self::RequestMoreEvidence => "request_more_evidence",
            Self::RejectUnhold => "reject_unhold",
            Self::ApproveOnlyAfterHeavyGates => "approve_only_after_heavy_gates",
        }
    }

    pub fn contributes_weight(self) -> bool {
        matches!(
            self,
            Self::AcknowledgeHold
                | Self::AcceptChecklist
                | Self::AcceptCustodyHandoff
                | Self::AcceptPrivacyHold
                | Self::ApproveOnlyAfterHeavyGates
        )
    }

    pub fn blocks_unhold(self) -> bool {
        !matches!(self, Self::ApproveOnlyAfterHeavyGates)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandBlockerKind {
    MissingLaneChecklist,
    DuplicateLaneChecklist,
    EmptyRoot,
    StaleChecklist,
    MissingIncidentHandoffRoot,
    MissingCommandOwnerAck,
    MissingReleaseHoldAuthority,
    MissingAbortCommand,
    MissingRollbackReplayEvidence,
    DeferredHeavyGate,
    MissingBridgeCustodyTransfer,
    MissingReserveLiabilityCheck,
    MissingWatchtowerNotice,
    MissingPrivacyLeakBudget,
    MissingPqSignerPolicy,
    AcceptedLaneCountTooLow,
    ChecklistItemCountTooLow,
    CommandWeightTooLow,
    BridgeCustodyDrillReceiptsTooLow,
    PrivacyReviewReceiptsTooLow,
    OperatorRequestedMoreEvidence,
    OperatorRejectedUnhold,
    ReleaseHoldStillActive,
    FailClosedRequired,
}

impl CommandBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingLaneChecklist => "missing_lane_checklist",
            Self::DuplicateLaneChecklist => "duplicate_lane_checklist",
            Self::EmptyRoot => "empty_root",
            Self::StaleChecklist => "stale_checklist",
            Self::MissingIncidentHandoffRoot => "missing_incident_handoff_root",
            Self::MissingCommandOwnerAck => "missing_command_owner_ack",
            Self::MissingReleaseHoldAuthority => "missing_release_hold_authority",
            Self::MissingAbortCommand => "missing_abort_command",
            Self::MissingRollbackReplayEvidence => "missing_rollback_replay_evidence",
            Self::DeferredHeavyGate => "deferred_heavy_gate",
            Self::MissingBridgeCustodyTransfer => "missing_bridge_custody_transfer",
            Self::MissingReserveLiabilityCheck => "missing_reserve_liability_check",
            Self::MissingWatchtowerNotice => "missing_watchtower_notice",
            Self::MissingPrivacyLeakBudget => "missing_privacy_leak_budget",
            Self::MissingPqSignerPolicy => "missing_pq_signer_policy",
            Self::AcceptedLaneCountTooLow => "accepted_lane_count_too_low",
            Self::ChecklistItemCountTooLow => "checklist_item_count_too_low",
            Self::CommandWeightTooLow => "command_weight_too_low",
            Self::BridgeCustodyDrillReceiptsTooLow => "bridge_custody_drill_receipts_too_low",
            Self::PrivacyReviewReceiptsTooLow => "privacy_review_receipts_too_low",
            Self::OperatorRequestedMoreEvidence => "operator_requested_more_evidence",
            Self::OperatorRejectedUnhold => "operator_rejected_unhold",
            Self::ReleaseHoldStillActive => "release_hold_still_active",
            Self::FailClosedRequired => "fail_closed_required",
        }
    }

    pub fn severity(self) -> u8 {
        match self {
            Self::DeferredHeavyGate | Self::ReleaseHoldStillActive | Self::FailClosedRequired => 2,
            Self::CommandWeightTooLow
            | Self::BridgeCustodyDrillReceiptsTooLow
            | Self::PrivacyReviewReceiptsTooLow
            | Self::OperatorRequestedMoreEvidence
            | Self::OperatorRejectedUnhold => 3,
            _ => 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub checklist_suite: String,
    pub release_epoch: u64,
    pub incident_handoff_epoch: u64,
    pub checklist_height: u64,
    pub release_channel: String,
    pub command_room_id: String,
    pub checklist_policy_id: String,
    pub max_checklist_age_blocks: u64,
    pub min_command_weight: u64,
    pub min_accepted_lanes: u16,
    pub min_checklist_items_per_lane: u16,
    pub min_bridge_custody_drill_receipts: u16,
    pub min_privacy_review_receipts: u16,
    pub required_lanes: Vec<ChecklistLane>,
    pub require_bridge_custody_drill: bool,
    pub require_privacy_review_drill: bool,
    pub require_deferred_heavy_gate_root: bool,
    pub require_release_hold_active: bool,
    pub require_fail_closed_default: bool,
    pub allow_unhold_without_heavy_gates: bool,
}

impl Default for Config {
    fn default() -> Self {
        let command_room_id = stable_id("command-room", "wave-87-checklist", 1);
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            checklist_suite: CHECKLIST_SUITE.to_string(),
            release_epoch: DEFAULT_RELEASE_EPOCH,
            incident_handoff_epoch: DEFAULT_INCIDENT_HANDOFF_EPOCH,
            checklist_height: DEFAULT_CHECKLIST_HEIGHT,
            release_channel: "devnet-force-exit-operator-command-checklist".to_string(),
            command_room_id: command_room_id.clone(),
            checklist_policy_id: stable_id("checklist-policy", &command_room_id, 1),
            max_checklist_age_blocks: DEFAULT_MAX_CHECKLIST_AGE_BLOCKS,
            min_command_weight: DEFAULT_MIN_COMMAND_WEIGHT,
            min_accepted_lanes: DEFAULT_MIN_ACCEPTED_LANES,
            min_checklist_items_per_lane: DEFAULT_MIN_CHECKLIST_ITEMS_PER_LANE,
            min_bridge_custody_drill_receipts: DEFAULT_MIN_BRIDGE_CUSTODY_DRILL_RECEIPTS,
            min_privacy_review_receipts: DEFAULT_MIN_PRIVACY_REVIEW_RECEIPTS,
            required_lanes: ChecklistLane::all(),
            require_bridge_custody_drill: true,
            require_privacy_review_drill: true,
            require_deferred_heavy_gate_root: true,
            require_release_hold_active: true,
            require_fail_closed_default: true,
            allow_unhold_without_heavy_gates: false,
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
        ensure_non_empty("hash_suite", &self.hash_suite)?;
        ensure_non_empty("checklist_suite", &self.checklist_suite)?;
        ensure_non_empty("release_channel", &self.release_channel)?;
        ensure_non_empty("command_room_id", &self.command_room_id)?;
        ensure_non_empty("checklist_policy_id", &self.checklist_policy_id)?;
        ensure(self.schema_version > 0, "schema version must be non-zero")?;
        ensure(self.release_epoch > 0, "release epoch must be non-zero")?;
        ensure(
            self.release_epoch > self.incident_handoff_epoch,
            "checklist epoch must follow incident handoff epoch",
        )?;
        ensure(
            self.checklist_height > 0,
            "checklist height must be non-zero",
        )?;
        ensure(
            self.max_checklist_age_blocks > 0,
            "max checklist age must be non-zero",
        )?;
        ensure(
            self.min_command_weight > 0,
            "min command weight must be non-zero",
        )?;
        ensure(
            self.min_accepted_lanes > 0,
            "min accepted lanes must be non-zero",
        )?;
        ensure(
            !self.required_lanes.is_empty(),
            "required lanes must be non-empty",
        )?;
        let mut seen = BTreeSet::new();
        for lane in &self.required_lanes {
            ensure(seen.insert(*lane), "required lanes must be unique")?;
        }
        if self.require_fail_closed_default {
            ensure(
                !self.allow_unhold_without_heavy_gates,
                "fail-closed mode cannot allow unhold without heavy gates",
            )?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "checklist_suite": self.checklist_suite,
            "release_epoch": self.release_epoch,
            "incident_handoff_epoch": self.incident_handoff_epoch,
            "checklist_height": self.checklist_height,
            "release_channel": self.release_channel,
            "command_room_id": self.command_room_id,
            "checklist_policy_id": self.checklist_policy_id,
            "max_checklist_age_blocks": self.max_checklist_age_blocks,
            "min_command_weight": self.min_command_weight,
            "min_accepted_lanes": self.min_accepted_lanes,
            "min_checklist_items_per_lane": self.min_checklist_items_per_lane,
            "min_bridge_custody_drill_receipts": self.min_bridge_custody_drill_receipts,
            "min_privacy_review_receipts": self.min_privacy_review_receipts,
            "required_lanes": self.required_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "require_bridge_custody_drill": self.require_bridge_custody_drill,
            "require_privacy_review_drill": self.require_privacy_review_drill,
            "require_deferred_heavy_gate_root": self.require_deferred_heavy_gate_root,
            "require_release_hold_active": self.require_release_hold_active,
            "require_fail_closed_default": self.require_fail_closed_default,
            "allow_unhold_without_heavy_gates": self.allow_unhold_without_heavy_gates,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChecklistItem {
    pub item_id: String,
    pub lane: ChecklistLane,
    pub kind: ChecklistItemKind,
    pub evidence_root: String,
    pub owner_id: String,
    pub completed: bool,
    pub release_blocking: bool,
    pub privacy_safe: bool,
}

impl ChecklistItem {
    pub fn devnet(lane: ChecklistLane, kind: ChecklistItemKind, ordinal: u64) -> Self {
        let label = format!("{}-{}", lane.as_str(), kind.as_str());
        let release_blocking = matches!(kind, ChecklistItemKind::DeferredHeavyGatePlaceholder);
        Self {
            item_id: stable_id("checklist-item", &label, ordinal),
            lane,
            kind,
            evidence_root: sample_root("checklist-item-evidence", &label, ordinal),
            owner_id: lane.command_owner().to_string(),
            completed: !release_blocking,
            release_blocking,
            privacy_safe: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("item_id", &self.item_id)?;
        ensure_non_empty("evidence_root", &self.evidence_root)?;
        ensure_non_empty("owner_id", &self.owner_id)?;
        ensure(self.privacy_safe, "checklist item must be privacy safe")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "item_id": self.item_id,
            "lane": self.lane.as_str(),
            "kind": self.kind.as_str(),
            "evidence_root": self.evidence_root,
            "owner_id": self.owner_id,
            "completed": self.completed,
            "release_blocking": self.release_blocking,
            "privacy_safe": self.privacy_safe,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("checklist-item", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneCommandChecklist {
    pub lane: ChecklistLane,
    pub command_owner: String,
    pub incident_handoff_root: String,
    pub checklist_root: String,
    pub release_hold_authority_root: String,
    pub abort_command_root: String,
    pub rollback_replay_root: String,
    pub bridge_custody_transfer_root: Option<String>,
    pub reserve_liability_root: Option<String>,
    pub watchtower_notice_root: Option<String>,
    pub privacy_leak_budget_root: Option<String>,
    pub pq_signer_policy_root: Option<String>,
    pub deferred_heavy_gate_root: String,
    pub observed_at_height: u64,
    pub item_count: u16,
    pub accepted_item_count: u16,
    pub status: ChecklistStatus,
    pub fail_closed: bool,
}

impl LaneCommandChecklist {
    pub fn devnet(lane: ChecklistLane, config: &Config, ordinal: u64) -> Self {
        let label = lane.as_str();
        let observed_at_height = config
            .checklist_height
            .saturating_sub(config.max_checklist_age_blocks / 3)
            .saturating_add(ordinal);
        let item_count = config.min_checklist_items_per_lane.saturating_add(
            if lane.requires_bridge_custody() { 2 } else { 0 }
                + if lane.requires_privacy_review() { 1 } else { 0 },
        );
        Self {
            lane,
            command_owner: lane.command_owner().to_string(),
            incident_handoff_root: sample_root("incident-handoff-root", label, ordinal),
            checklist_root: sample_root("operator-command-checklist-root", label, ordinal),
            release_hold_authority_root: sample_root("release-hold-authority", label, ordinal),
            abort_command_root: sample_root("abort-command-root", label, ordinal),
            rollback_replay_root: sample_root("rollback-replay-evidence", label, ordinal),
            bridge_custody_transfer_root: lane
                .requires_bridge_custody()
                .then(|| sample_root("bridge-custody-transfer", label, ordinal)),
            reserve_liability_root: lane
                .requires_bridge_custody()
                .then(|| sample_root("reserve-liability-root", label, ordinal)),
            watchtower_notice_root: matches!(lane, ChecklistLane::WalletWatchtower)
                .then(|| sample_root("watchtower-notice-root", label, ordinal)),
            privacy_leak_budget_root: lane
                .requires_privacy_review()
                .then(|| sample_root("privacy-leak-budget", label, ordinal)),
            pq_signer_policy_root: matches!(lane, ChecklistLane::PqReservePrivacy)
                .then(|| sample_root("pq-signer-policy", label, ordinal)),
            deferred_heavy_gate_root: sample_root("deferred-heavy-gate-root", label, ordinal),
            observed_at_height,
            item_count,
            accepted_item_count: config.min_checklist_items_per_lane,
            status: ChecklistStatus::AcceptedWithHold,
            fail_closed: true,
        }
    }

    pub fn validate(&self, config: &Config, height: u64) -> Result<()> {
        ensure_non_empty("command_owner", &self.command_owner)?;
        ensure_non_empty("incident_handoff_root", &self.incident_handoff_root)?;
        ensure_non_empty("checklist_root", &self.checklist_root)?;
        ensure_non_empty(
            "release_hold_authority_root",
            &self.release_hold_authority_root,
        )?;
        ensure_non_empty("abort_command_root", &self.abort_command_root)?;
        ensure_non_empty("rollback_replay_root", &self.rollback_replay_root)?;
        ensure_non_empty("deferred_heavy_gate_root", &self.deferred_heavy_gate_root)?;
        ensure(
            self.observed_at_height <= height,
            "checklist cannot be observed after state height",
        )?;
        ensure(
            self.item_count >= config.min_checklist_items_per_lane,
            "checklist item count below minimum",
        )?;
        if self.lane.requires_bridge_custody() {
            ensure(
                option_root_present(&self.bridge_custody_transfer_root),
                "bridge custody lane requires transfer root",
            )?;
            ensure(
                option_root_present(&self.reserve_liability_root),
                "bridge custody lane requires reserve liability root",
            )?;
        }
        if self.lane.requires_privacy_review() {
            ensure(
                option_root_present(&self.privacy_leak_budget_root),
                "privacy lane requires privacy leak budget root",
            )?;
        }
        Ok(())
    }

    pub fn blockers(&self, config: &Config, height: u64) -> Vec<CommandBlockerKind> {
        let mut blockers = Vec::new();
        if self
            .observed_at_height
            .saturating_add(config.max_checklist_age_blocks)
            < height
        {
            blockers.push(CommandBlockerKind::StaleChecklist);
        }
        if config.require_deferred_heavy_gate_root {
            blockers.push(CommandBlockerKind::DeferredHeavyGate);
        }
        if self.lane.requires_bridge_custody() {
            if !option_root_present(&self.bridge_custody_transfer_root) {
                blockers.push(CommandBlockerKind::MissingBridgeCustodyTransfer);
            }
            if !option_root_present(&self.reserve_liability_root) {
                blockers.push(CommandBlockerKind::MissingReserveLiabilityCheck);
            }
        }
        if matches!(self.lane, ChecklistLane::WalletWatchtower)
            && !option_root_present(&self.watchtower_notice_root)
        {
            blockers.push(CommandBlockerKind::MissingWatchtowerNotice);
        }
        if self.lane.requires_privacy_review()
            && !option_root_present(&self.privacy_leak_budget_root)
        {
            blockers.push(CommandBlockerKind::MissingPrivacyLeakBudget);
        }
        if matches!(self.lane, ChecklistLane::PqReservePrivacy)
            && !option_root_present(&self.pq_signer_policy_root)
        {
            blockers.push(CommandBlockerKind::MissingPqSignerPolicy);
        }
        if self.item_count < config.min_checklist_items_per_lane {
            blockers.push(CommandBlockerKind::ChecklistItemCountTooLow);
        }
        if self.status.release_blocking() {
            blockers.push(CommandBlockerKind::ReleaseHoldStillActive);
        }
        if config.require_fail_closed_default && self.fail_closed {
            blockers.push(CommandBlockerKind::FailClosedRequired);
        }
        blockers
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "command_owner": self.command_owner,
            "incident_handoff_root": self.incident_handoff_root,
            "checklist_root": self.checklist_root,
            "release_hold_authority_root": self.release_hold_authority_root,
            "abort_command_root": self.abort_command_root,
            "rollback_replay_root": self.rollback_replay_root,
            "bridge_custody_transfer_root": self.bridge_custody_transfer_root,
            "reserve_liability_root": self.reserve_liability_root,
            "watchtower_notice_root": self.watchtower_notice_root,
            "privacy_leak_budget_root": self.privacy_leak_budget_root,
            "pq_signer_policy_root": self.pq_signer_policy_root,
            "deferred_heavy_gate_root": self.deferred_heavy_gate_root,
            "observed_at_height": self.observed_at_height,
            "item_count": self.item_count,
            "accepted_item_count": self.accepted_item_count,
            "status": self.status.as_str(),
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("lane-command-checklist", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeCustodyDrillReceipt {
    pub receipt_id: String,
    pub lane: ChecklistLane,
    pub custody_root: String,
    pub reserve_root: String,
    pub release_cap_root: String,
    pub signer_ack_root: String,
    pub observed_at_height: u64,
    pub release_paused: bool,
    pub privacy_safe: bool,
}

impl BridgeCustodyDrillReceipt {
    pub fn devnet(lane: ChecklistLane, config: &Config, ordinal: u64) -> Self {
        let label = format!("{}-custody-drill", lane.as_str());
        Self {
            receipt_id: stable_id("bridge-custody-drill", &label, ordinal),
            lane,
            custody_root: sample_root("custody-root", &label, ordinal),
            reserve_root: sample_root("reserve-root", &label, ordinal),
            release_cap_root: sample_root("release-cap-root", &label, ordinal),
            signer_ack_root: sample_root("signer-ack-root", &label, ordinal),
            observed_at_height: config
                .checklist_height
                .saturating_sub(4)
                .saturating_add(ordinal),
            release_paused: true,
            privacy_safe: true,
        }
    }

    pub fn validate(&self, height: u64) -> Result<()> {
        ensure_non_empty("receipt_id", &self.receipt_id)?;
        ensure_non_empty("custody_root", &self.custody_root)?;
        ensure_non_empty("reserve_root", &self.reserve_root)?;
        ensure_non_empty("release_cap_root", &self.release_cap_root)?;
        ensure_non_empty("signer_ack_root", &self.signer_ack_root)?;
        ensure(
            self.observed_at_height <= height,
            "custody drill cannot be observed after state height",
        )?;
        ensure(self.privacy_safe, "custody drill must be privacy safe")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "lane": self.lane.as_str(),
            "custody_root": self.custody_root,
            "reserve_root": self.reserve_root,
            "release_cap_root": self.release_cap_root,
            "signer_ack_root": self.signer_ack_root,
            "observed_at_height": self.observed_at_height,
            "release_paused": self.release_paused,
            "privacy_safe": self.privacy_safe,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("bridge-custody-drill", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorCommandSignoff {
    pub operator_id: String,
    pub role: String,
    pub lane_scope: Option<ChecklistLane>,
    pub weight: u64,
    pub decision: CommandDecision,
    pub signed_checklist_root: String,
    pub signed_at_height: u64,
}

impl OperatorCommandSignoff {
    pub fn devnet(
        operator_id: &str,
        role: &str,
        lane_scope: Option<ChecklistLane>,
        weight: u64,
        decision: CommandDecision,
        config: &Config,
        ordinal: u64,
    ) -> Self {
        Self {
            operator_id: operator_id.to_string(),
            role: role.to_string(),
            lane_scope,
            weight,
            decision,
            signed_checklist_root: sample_root("operator-command-signoff", operator_id, ordinal),
            signed_at_height: config
                .checklist_height
                .saturating_sub(6)
                .saturating_add(ordinal),
        }
    }

    pub fn validate(&self, height: u64) -> Result<()> {
        ensure_non_empty("operator_id", &self.operator_id)?;
        ensure_non_empty("role", &self.role)?;
        ensure_non_empty("signed_checklist_root", &self.signed_checklist_root)?;
        ensure(self.weight > 0, "command signoff weight must be non-zero")?;
        ensure(
            self.signed_at_height <= height,
            "command signoff cannot be after state height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "operator_id": self.operator_id,
            "role": self.role,
            "lane_scope": self.lane_scope.map(|lane| lane.as_str()),
            "weight": self.weight,
            "decision": self.decision.as_str(),
            "signed_checklist_root": self.signed_checklist_root,
            "signed_at_height": self.signed_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("operator-command-signoff", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandChecklistSummary {
    pub state: String,
    pub accepted_lane_count: u16,
    pub checklist_item_count: u16,
    pub bridge_custody_drill_count: u16,
    pub blocker_count: u16,
    pub max_blocker_severity: u8,
    pub command_weight: u64,
    pub release_hold_active: bool,
    pub fail_closed: bool,
    pub command_ready: bool,
    pub summary_root: String,
}

impl CommandChecklistSummary {
    pub fn build(
        config: &Config,
        lane_checklists: &[LaneCommandChecklist],
        checklist_items: &[ChecklistItem],
        custody_drills: &[BridgeCustodyDrillReceipt],
        operator_signoffs: &[OperatorCommandSignoff],
        blockers: &BTreeMap<String, Vec<CommandBlockerKind>>,
    ) -> Self {
        let accepted_lane_count = lane_checklists
            .iter()
            .filter(|lane| lane.status.accepted())
            .count() as u16;
        let checklist_item_count = checklist_items.len() as u16;
        let bridge_custody_drill_count = custody_drills.len() as u16;
        let blocker_count = blockers.values().map(|items| items.len()).sum::<usize>() as u16;
        let max_blocker_severity = match blockers
            .values()
            .flat_map(|items| items.iter())
            .map(|blocker| blocker.severity())
            .max()
        {
            Some(severity) => severity,
            None => 0,
        };
        let command_weight = operator_signoffs
            .iter()
            .filter(|signoff| signoff.decision.contributes_weight())
            .map(|signoff| signoff.weight)
            .sum::<u64>();
        let release_hold_active = lane_checklists
            .iter()
            .any(|lane| lane.status.release_blocking());
        let fail_closed = config.require_fail_closed_default || release_hold_active;
        let command_ready = blocker_count == 0
            && accepted_lane_count >= config.min_accepted_lanes
            && command_weight >= config.min_command_weight
            && !release_hold_active;
        let state = if command_ready {
            "ready_for_unhold"
        } else if fail_closed {
            "held_fail_closed"
        } else {
            "pending_command_review"
        }
        .to_string();
        let summary_root = domain_hash(
            "operator-command-checklist-summary-root",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.checklist_policy_id),
                HashPart::U64(accepted_lane_count as u64),
                HashPart::U64(checklist_item_count as u64),
                HashPart::U64(bridge_custody_drill_count as u64),
                HashPart::U64(blocker_count as u64),
                HashPart::U64(command_weight),
                HashPart::Json(&json!({
                    "release_hold_active": release_hold_active,
                    "fail_closed": fail_closed,
                    "command_ready": command_ready,
                })),
            ],
            32,
        );
        Self {
            state,
            accepted_lane_count,
            checklist_item_count,
            bridge_custody_drill_count,
            blocker_count,
            max_blocker_severity,
            command_weight,
            release_hold_active,
            fail_closed,
            command_ready,
            summary_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "state": self.state,
            "accepted_lane_count": self.accepted_lane_count,
            "checklist_item_count": self.checklist_item_count,
            "bridge_custody_drill_count": self.bridge_custody_drill_count,
            "blocker_count": self.blocker_count,
            "max_blocker_severity": self.max_blocker_severity,
            "command_weight": self.command_weight,
            "release_hold_active": self.release_hold_active,
            "fail_closed": self.fail_closed,
            "command_ready": self.command_ready,
            "summary_root": self.summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub lane_checklists: Vec<LaneCommandChecklist>,
    pub checklist_items: Vec<ChecklistItem>,
    pub custody_drill_receipts: Vec<BridgeCustodyDrillReceipt>,
    pub operator_signoffs: Vec<OperatorCommandSignoff>,
    pub blockers: BTreeMap<String, Vec<CommandBlockerKind>>,
    pub lane_checklist_root: String,
    pub checklist_item_root: String,
    pub custody_drill_root: String,
    pub operator_root: String,
    pub blocker_root: String,
    pub summary: CommandChecklistSummary,
}

impl State {
    pub fn new(
        config: Config,
        height: u64,
        lane_checklists: Vec<LaneCommandChecklist>,
        checklist_items: Vec<ChecklistItem>,
        custody_drill_receipts: Vec<BridgeCustodyDrillReceipt>,
        operator_signoffs: Vec<OperatorCommandSignoff>,
    ) -> Result<Self> {
        config.validate()?;
        ensure(height > 0, "state height must be non-zero")?;
        ensure(
            !lane_checklists.is_empty(),
            "state must include lane checklists",
        )?;
        ensure(
            !checklist_items.is_empty(),
            "state must include checklist items",
        )?;
        ensure(
            !operator_signoffs.is_empty(),
            "state must include operator signoffs",
        )?;
        for lane in &lane_checklists {
            lane.validate(&config, height)?;
        }
        for item in &checklist_items {
            item.validate()?;
        }
        for receipt in &custody_drill_receipts {
            receipt.validate(height)?;
        }
        for signoff in &operator_signoffs {
            signoff.validate(height)?;
        }
        let blockers = evaluate_blockers(
            &config,
            height,
            &lane_checklists,
            &checklist_items,
            &custody_drill_receipts,
            &operator_signoffs,
        );
        let lane_checklist_root = roots_root(
            "operator-command-lane-checklists",
            lane_checklists.iter().map(LaneCommandChecklist::state_root),
        );
        let checklist_item_root = roots_root(
            "operator-command-checklist-items",
            checklist_items.iter().map(ChecklistItem::state_root),
        );
        let custody_drill_root = roots_root(
            "operator-command-custody-drills",
            custody_drill_receipts
                .iter()
                .map(BridgeCustodyDrillReceipt::state_root),
        );
        let operator_root = roots_root(
            "operator-command-signoffs",
            operator_signoffs
                .iter()
                .map(OperatorCommandSignoff::state_root),
        );
        let blocker_root = blockers_root(&blockers);
        let summary = CommandChecklistSummary::build(
            &config,
            &lane_checklists,
            &checklist_items,
            &custody_drill_receipts,
            &operator_signoffs,
            &blockers,
        );
        Ok(Self {
            config,
            height,
            lane_checklists,
            checklist_items,
            custody_drill_receipts,
            operator_signoffs,
            blockers,
            lane_checklist_root,
            checklist_item_root,
            custody_drill_root,
            operator_root,
            blocker_root,
            summary,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let height = config.checklist_height;
        let lanes = ChecklistLane::all();
        let lane_checklists = lanes
            .iter()
            .enumerate()
            .map(|(index, lane)| LaneCommandChecklist::devnet(*lane, &config, one_based(index)))
            .collect::<Vec<_>>();
        let mut checklist_items = Vec::new();
        for (lane_index, lane) in lanes.iter().enumerate() {
            let ordinal_base = one_based(lane_index) * 20;
            let kinds = [
                ChecklistItemKind::IncidentHandoffRoot,
                ChecklistItemKind::CommandOwnerAck,
                ChecklistItemKind::ReleaseHoldAuthority,
                ChecklistItemKind::AbortCommandReady,
                ChecklistItemKind::RollbackReplayEvidence,
                ChecklistItemKind::DeferredHeavyGatePlaceholder,
                ChecklistItemKind::BridgeCustodyTransfer,
                ChecklistItemKind::ReserveLiabilityCheck,
                ChecklistItemKind::WatchtowerNotice,
                ChecklistItemKind::PrivacyLeakBudgetCheck,
                ChecklistItemKind::PqSignerPolicyCheck,
            ];
            for (kind_index, kind) in kinds.into_iter().enumerate() {
                if kind.required_for_lane(*lane) {
                    checklist_items.push(ChecklistItem::devnet(
                        *lane,
                        kind,
                        ordinal_base + one_based(kind_index),
                    ));
                }
            }
        }
        let custody_drill_receipts = vec![
            BridgeCustodyDrillReceipt::devnet(ChecklistLane::BridgeCustody, &config, 1),
            BridgeCustodyDrillReceipt::devnet(ChecklistLane::BridgeCustody, &config, 2),
            BridgeCustodyDrillReceipt::devnet(ChecklistLane::PqReservePrivacy, &config, 3),
            BridgeCustodyDrillReceipt::devnet(ChecklistLane::PqReservePrivacy, &config, 4),
        ];
        let operator_signoffs = vec![
            OperatorCommandSignoff::devnet(
                "runtime-release-lead",
                "compile-runtime-owner",
                Some(ChecklistLane::CompileRuntime),
                18,
                CommandDecision::AcceptChecklist,
                &config,
                1,
            ),
            OperatorCommandSignoff::devnet(
                "runtime-replay-lead",
                "runtime-replay-owner",
                Some(ChecklistLane::RuntimeReplay),
                15,
                CommandDecision::AcceptChecklist,
                &config,
                2,
            ),
            OperatorCommandSignoff::devnet(
                "security-incident-lead",
                "audit-security-owner",
                Some(ChecklistLane::AuditSecurity),
                20,
                CommandDecision::AcceptPrivacyHold,
                &config,
                3,
            ),
            OperatorCommandSignoff::devnet(
                "bridge-custody-lead",
                "bridge-custody-owner",
                Some(ChecklistLane::BridgeCustody),
                22,
                CommandDecision::AcceptCustodyHandoff,
                &config,
                4,
            ),
            OperatorCommandSignoff::devnet(
                "wallet-watchtower-lead",
                "wallet-watchtower-owner",
                Some(ChecklistLane::WalletWatchtower),
                16,
                CommandDecision::AcknowledgeHold,
                &config,
                5,
            ),
            OperatorCommandSignoff::devnet(
                "pq-reserve-privacy-lead",
                "pq-reserve-privacy-owner",
                Some(ChecklistLane::PqReservePrivacy),
                22,
                CommandDecision::AcceptPrivacyHold,
                &config,
                6,
            ),
            OperatorCommandSignoff::devnet(
                "release-captain",
                "incident-command",
                None,
                25,
                CommandDecision::RequestMoreEvidence,
                &config,
                7,
            ),
        ];
        match Self::new(
            config,
            height,
            lane_checklists,
            checklist_items,
            custody_drill_receipts,
            operator_signoffs,
        ) {
            Ok(state) => state,
            Err(reason) => build_devnet_fail_closed_fallback(reason),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "lane_checklist_root": self.lane_checklist_root,
            "checklist_item_root": self.checklist_item_root,
            "custody_drill_root": self.custody_drill_root,
            "operator_root": self.operator_root,
            "blocker_root": self.blocker_root,
            "summary": self.summary.public_record(),
            "lane_checklists": self.lane_checklists.iter().map(LaneCommandChecklist::public_record).collect::<Vec<_>>(),
            "checklist_items": self.checklist_items.iter().map(ChecklistItem::public_record).collect::<Vec<_>>(),
            "custody_drill_receipts": self.custody_drill_receipts.iter().map(BridgeCustodyDrillReceipt::public_record).collect::<Vec<_>>(),
            "operator_signoffs": self.operator_signoffs.iter().map(OperatorCommandSignoff::public_record).collect::<Vec<_>>(),
            "blockers": self.blockers.iter().map(|(subject, blockers)| {
                let max_severity = match blockers.iter().map(|blocker| blocker.severity()).max() {
                    Some(severity) => severity,
                    None => 0,
                };
                json!({
                    "subject": subject,
                    "blockers": blockers.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
                    "max_severity": max_severity,
                })
            }).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "operator-command-checklist-state-root",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.checklist_policy_id),
                HashPart::U64(self.height),
                HashPart::Str(&self.lane_checklist_root),
                HashPart::Str(&self.checklist_item_root),
                HashPart::Str(&self.custody_drill_root),
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
    lane_checklists: &[LaneCommandChecklist],
    checklist_items: &[ChecklistItem],
    custody_drill_receipts: &[BridgeCustodyDrillReceipt],
    operator_signoffs: &[OperatorCommandSignoff],
) -> BTreeMap<String, Vec<CommandBlockerKind>> {
    let mut blockers = BTreeMap::<String, Vec<CommandBlockerKind>>::new();
    let mut seen = BTreeSet::new();
    for checklist in lane_checklists {
        let key = checklist.lane.as_str().to_string();
        if !seen.insert(checklist.lane) {
            blockers
                .entry(key.clone())
                .or_default()
                .push(CommandBlockerKind::DuplicateLaneChecklist);
        }
        let lane_blockers = checklist.blockers(config, height);
        if !lane_blockers.is_empty() {
            blockers.entry(key).or_default().extend(lane_blockers);
        }
    }
    for lane in &config.required_lanes {
        if !seen.contains(lane) {
            blockers
                .entry(lane.as_str().to_string())
                .or_default()
                .push(CommandBlockerKind::MissingLaneChecklist);
        }
    }
    let accepted_lane_count = lane_checklists
        .iter()
        .filter(|checklist| checklist.status.accepted())
        .count() as u16;
    if accepted_lane_count < config.min_accepted_lanes {
        blockers
            .entry("lane_quorum".to_string())
            .or_default()
            .push(CommandBlockerKind::AcceptedLaneCountTooLow);
    }
    for lane in &config.required_lanes {
        let item_count = checklist_items
            .iter()
            .filter(|item| item.lane == *lane)
            .count() as u16;
        if item_count < config.min_checklist_items_per_lane {
            blockers
                .entry(lane.as_str().to_string())
                .or_default()
                .push(CommandBlockerKind::ChecklistItemCountTooLow);
        }
    }
    let command_weight = operator_signoffs
        .iter()
        .filter(|signoff| signoff.decision.contributes_weight())
        .map(|signoff| signoff.weight)
        .sum::<u64>();
    if command_weight < config.min_command_weight {
        blockers
            .entry("command_quorum".to_string())
            .or_default()
            .push(CommandBlockerKind::CommandWeightTooLow);
    }
    let bridge_drill_count = custody_drill_receipts.len() as u16;
    if config.require_bridge_custody_drill
        && bridge_drill_count < config.min_bridge_custody_drill_receipts
    {
        blockers
            .entry("bridge_custody_drills".to_string())
            .or_default()
            .push(CommandBlockerKind::BridgeCustodyDrillReceiptsTooLow);
    }
    let privacy_review_count = operator_signoffs
        .iter()
        .filter(|signoff| match signoff.lane_scope {
            Some(lane) => lane.requires_privacy_review(),
            None => false,
        })
        .count() as u16;
    if config.require_privacy_review_drill
        && privacy_review_count < config.min_privacy_review_receipts
    {
        blockers
            .entry("privacy_review".to_string())
            .or_default()
            .push(CommandBlockerKind::PrivacyReviewReceiptsTooLow);
    }
    for signoff in operator_signoffs {
        if signoff.decision.blocks_unhold() {
            let blocker = match signoff.decision {
                CommandDecision::RejectUnhold => CommandBlockerKind::OperatorRejectedUnhold,
                CommandDecision::RequestMoreEvidence => {
                    CommandBlockerKind::OperatorRequestedMoreEvidence
                }
                CommandDecision::AcknowledgeHold
                | CommandDecision::AcceptChecklist
                | CommandDecision::AcceptCustodyHandoff
                | CommandDecision::AcceptPrivacyHold
                | CommandDecision::ApproveOnlyAfterHeavyGates => {
                    CommandBlockerKind::ReleaseHoldStillActive
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

fn build_devnet_fail_closed_fallback(reason: String) -> State {
    let config = Config::devnet();
    let height = config.checklist_height;
    let lane_checklists = ChecklistLane::all()
        .into_iter()
        .enumerate()
        .map(|(index, lane)| LaneCommandChecklist {
            status: ChecklistStatus::Held,
            fail_closed: true,
            item_count: 0,
            accepted_item_count: 0,
            ..LaneCommandChecklist::devnet(lane, &config, one_based(index))
        })
        .collect::<Vec<_>>();
    let checklist_items = vec![ChecklistItem::devnet(
        ChecklistLane::CompileRuntime,
        ChecklistItemKind::ReleaseHoldAuthority,
        1,
    )];
    let custody_drill_receipts = vec![BridgeCustodyDrillReceipt::devnet(
        ChecklistLane::BridgeCustody,
        &config,
        1,
    )];
    let operator_signoffs = vec![OperatorCommandSignoff::devnet(
        "release-captain",
        "incident-command",
        None,
        1,
        CommandDecision::RequestMoreEvidence,
        &config,
        1,
    )];
    let mut blockers = evaluate_blockers(
        &config,
        height,
        &lane_checklists,
        &checklist_items,
        &custody_drill_receipts,
        &operator_signoffs,
    );
    blockers
        .entry("fallback".to_string())
        .or_default()
        .push(CommandBlockerKind::FailClosedRequired);
    blockers
        .entry("fallback_reason".to_string())
        .or_default()
        .push(if reason.trim().is_empty() {
            CommandBlockerKind::EmptyRoot
        } else {
            CommandBlockerKind::ReleaseHoldStillActive
        });
    let lane_checklist_root = roots_root(
        "operator-command-lane-checklists",
        lane_checklists.iter().map(LaneCommandChecklist::state_root),
    );
    let checklist_item_root = roots_root(
        "operator-command-checklist-items",
        checklist_items.iter().map(ChecklistItem::state_root),
    );
    let custody_drill_root = roots_root(
        "operator-command-custody-drills",
        custody_drill_receipts
            .iter()
            .map(BridgeCustodyDrillReceipt::state_root),
    );
    let operator_root = roots_root(
        "operator-command-signoffs",
        operator_signoffs
            .iter()
            .map(OperatorCommandSignoff::state_root),
    );
    let blocker_root = blockers_root(&blockers);
    let summary = CommandChecklistSummary::build(
        &config,
        &lane_checklists,
        &checklist_items,
        &custody_drill_receipts,
        &operator_signoffs,
        &blockers,
    );
    State {
        config,
        height,
        lane_checklists,
        checklist_items,
        custody_drill_receipts,
        operator_signoffs,
        blockers,
        lane_checklist_root,
        checklist_item_root,
        custody_drill_root,
        operator_root,
        blocker_root,
        summary,
    }
}

fn option_root_present(root: &Option<String>) -> bool {
    match root {
        Some(value) => !value.trim().is_empty(),
        None => false,
    }
}

fn blockers_root(blockers: &BTreeMap<String, Vec<CommandBlockerKind>>) -> String {
    let leaves = blockers
        .iter()
        .map(|(subject, blocker_list)| {
            let max_severity = match blocker_list.iter().map(|blocker| blocker.severity()).max() {
                Some(severity) => severity,
                None => 0,
            };
            json!({
                "subject": subject,
                "blockers": blocker_list.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
                "max_severity": max_severity,
            })
        })
        .collect::<Vec<_>>();
    merkle_root("operator-command-checklist-blockers", &leaves)
}

fn roots_root<I>(label: &str, roots: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let leaves = roots.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-OPERATOR-COMMAND-CHECKLIST-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn stable_id(kind: &str, label: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-OPERATOR-COMMAND-CHECKLIST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

fn sample_root(kind: &str, label: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-OPERATOR-COMMAND-CHECKLIST-SAMPLE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

fn one_based(index: usize) -> u64 {
    index as u64 + 1
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
