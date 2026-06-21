use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageWalletWatchtowerAcceptedLiveEvidenceOperatorDashboardReleasePolicyDeploymentGuardRollbackDrillIncidentHandoffOperatorCommandChecklistRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_WALLET_WATCHTOWER_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_INCIDENT_HANDOFF_OPERATOR_COMMAND_CHECKLIST_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-wallet-watchtower-accepted-live-evidence-operator-dashboard-release-policy-deployment-guard-rollback-drill-incident-handoff-operator-command-checklist-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_WALLET_WATCHTOWER_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_INCIDENT_HANDOFF_OPERATOR_COMMAND_CHECKLIST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CHECKLIST_SUITE: &str =
    "wallet-watchtower-incident-handoff-operator-command-checklist-v1";
pub const DEFAULT_WAVE: u64 = 87;
pub const DEFAULT_SOURCE_WAVE: u64 = 86;
pub const DEFAULT_HEIGHT: u64 = 4_280_736;
pub const DEFAULT_MAX_HANDOFF_AGE_BLOCKS: u64 = 72;
pub const DEFAULT_MIN_WALLET_WARNINGS: u64 = 3;
pub const DEFAULT_MIN_WATCHTOWER_AUDITS: u64 = 2;
pub const DEFAULT_MIN_WATCHTOWER_CHALLENGES: u64 = 2;
pub const DEFAULT_MIN_SETTLEMENT_BLOCKERS: u64 = 1;
pub const DEFAULT_MIN_DISCLOSURE_GUARDS: u64 = 3;
pub const DEFAULT_MIN_ESCAPE_NOTIFICATIONS: u64 = 3;
pub const DEFAULT_MIN_COMMAND_AUTHORITIES: u64 = 3;
pub const DEFAULT_MAX_OPEN_SETTLEMENTS: u64 = 0;
pub const DEFAULT_MAX_PRIVATE_DISCLOSURES: u64 = 0;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistStatus {
    Accepted,
    Pending,
    Rejected,
    Stale,
    Blocked,
}

impl ChecklistStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Pending => "pending",
            Self::Rejected => "rejected",
            Self::Stale => "stale",
            Self::Blocked => "blocked",
        }
    }

    pub fn counts(self) -> bool {
        matches!(self, Self::Accepted)
    }

    pub fn blocks(self) -> bool {
        matches!(self, Self::Rejected | Self::Stale | Self::Blocked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Finalized,
    PendingChallengeWindow,
    Delayed,
    Disputed,
    Unknown,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Finalized => "finalized",
            Self::PendingChallengeWindow => "pending_challenge_window",
            Self::Delayed => "delayed",
            Self::Disputed => "disputed",
            Self::Unknown => "unknown",
        }
    }

    pub fn blocks_release(self) -> bool {
        !matches!(self, Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchtowerRootKind {
    Audit,
    Challenge,
}

impl WatchtowerRootKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::Challenge => "challenge",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureScope {
    WalletWarning,
    WatchtowerAudit,
    WatchtowerChallenge,
    SettlementStatus,
    UserEscapeNotification,
    OperatorCommand,
}

impl DisclosureScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletWarning => "wallet_warning",
            Self::WatchtowerAudit => "watchtower_audit",
            Self::WatchtowerChallenge => "watchtower_challenge",
            Self::SettlementStatus => "settlement_status",
            Self::UserEscapeNotification => "user_escape_notification",
            Self::OperatorCommand => "operator_command",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandAuthority {
    IncidentCommander,
    WalletLead,
    WatchtowerLead,
    SettlementLead,
    ReleaseManager,
}

impl CommandAuthority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IncidentCommander => "incident_commander",
            Self::WalletLead => "wallet_lead",
            Self::WatchtowerLead => "watchtower_lead",
            Self::SettlementLead => "settlement_lead",
            Self::ReleaseManager => "release_manager",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerKind {
    SourceHandoffRootMissing,
    SourceHandoffStale,
    WalletWarningMissing,
    WatchtowerAuditRootMissing,
    WatchtowerChallengeRootMissing,
    SettlementStatusOpen,
    SettlementBlockerMissing,
    DisclosureGuardMissing,
    PrivateDisclosureRequested,
    UserEscapeNotificationMissing,
    CommandAuthorityMissing,
    CommandAuthorityOpen,
    ChecklistEvidenceRejected,
    FailClosedNotAsserted,
}

impl BlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceHandoffRootMissing => "source_handoff_root_missing",
            Self::SourceHandoffStale => "source_handoff_stale",
            Self::WalletWarningMissing => "wallet_warning_missing",
            Self::WatchtowerAuditRootMissing => "watchtower_audit_root_missing",
            Self::WatchtowerChallengeRootMissing => "watchtower_challenge_root_missing",
            Self::SettlementStatusOpen => "settlement_status_open",
            Self::SettlementBlockerMissing => "settlement_blocker_missing",
            Self::DisclosureGuardMissing => "disclosure_guard_missing",
            Self::PrivateDisclosureRequested => "private_disclosure_requested",
            Self::UserEscapeNotificationMissing => "user_escape_notification_missing",
            Self::CommandAuthorityMissing => "command_authority_missing",
            Self::CommandAuthorityOpen => "command_authority_open",
            Self::ChecklistEvidenceRejected => "checklist_evidence_rejected",
            Self::FailClosedNotAsserted => "fail_closed_not_asserted",
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
    pub wave: u64,
    pub source_wave: u64,
    pub current_height: u64,
    pub max_handoff_age_blocks: u64,
    pub operator_checklist_id: String,
    pub source_handoff_root: String,
    pub source_wallet_warning_root: String,
    pub source_watchtower_challenge_root: String,
    pub source_watchtower_audit_root: String,
    pub source_settlement_evidence_root: String,
    pub source_disclosure_warning_root: String,
    pub min_wallet_warning_items: u64,
    pub min_watchtower_audit_roots: u64,
    pub min_watchtower_challenge_roots: u64,
    pub min_settlement_blockers: u64,
    pub min_disclosure_guards: u64,
    pub min_escape_notifications: u64,
    pub min_command_authorities: u64,
    pub max_open_settlements: u64,
    pub max_private_disclosures: u64,
    pub fail_closed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            checklist_suite: CHECKLIST_SUITE.to_string(),
            wave: DEFAULT_WAVE,
            source_wave: DEFAULT_SOURCE_WAVE,
            current_height: DEFAULT_HEIGHT,
            max_handoff_age_blocks: DEFAULT_MAX_HANDOFF_AGE_BLOCKS,
            operator_checklist_id: stable_id("operator-checklist", "wave87-devnet"),
            source_handoff_root: source_root("wave86-incident-handoff-root"),
            source_wallet_warning_root: source_root("wave86-user-warning-root"),
            source_watchtower_challenge_root: source_root("wave86-watchtower-challenge-root"),
            source_watchtower_audit_root: source_root("wave86-watchtower-audit-root"),
            source_settlement_evidence_root: source_root("wave86-settlement-evidence-root"),
            source_disclosure_warning_root: source_root("wave86-disclosure-warning-root"),
            min_wallet_warning_items: DEFAULT_MIN_WALLET_WARNINGS,
            min_watchtower_audit_roots: DEFAULT_MIN_WATCHTOWER_AUDITS,
            min_watchtower_challenge_roots: DEFAULT_MIN_WATCHTOWER_CHALLENGES,
            min_settlement_blockers: DEFAULT_MIN_SETTLEMENT_BLOCKERS,
            min_disclosure_guards: DEFAULT_MIN_DISCLOSURE_GUARDS,
            min_escape_notifications: DEFAULT_MIN_ESCAPE_NOTIFICATIONS,
            min_command_authorities: DEFAULT_MIN_COMMAND_AUTHORITIES,
            max_open_settlements: DEFAULT_MAX_OPEN_SETTLEMENTS,
            max_private_disclosures: DEFAULT_MAX_PRIVATE_DISCLOSURES,
            fail_closed: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        ensure(
            self.schema_version == SCHEMA_VERSION,
            "schema version mismatch",
        )?;
        ensure(self.wave > self.source_wave, "wave must follow source wave")?;
        ensure_root("source_handoff_root", &self.source_handoff_root)?;
        ensure_root(
            "source_wallet_warning_root",
            &self.source_wallet_warning_root,
        )?;
        ensure_root(
            "source_watchtower_challenge_root",
            &self.source_watchtower_challenge_root,
        )?;
        ensure_root(
            "source_watchtower_audit_root",
            &self.source_watchtower_audit_root,
        )?;
        ensure_root(
            "source_settlement_evidence_root",
            &self.source_settlement_evidence_root,
        )?;
        ensure_root(
            "source_disclosure_warning_root",
            &self.source_disclosure_warning_root,
        )?;
        ensure(
            self.max_handoff_age_blocks > 0,
            "handoff age window must be positive",
        )?;
        ensure(
            self.min_wallet_warning_items > 0,
            "wallet warning threshold must be positive",
        )?;
        ensure(
            self.min_watchtower_audit_roots > 0,
            "watchtower audit threshold must be positive",
        )?;
        ensure(
            self.min_watchtower_challenge_roots > 0,
            "watchtower challenge threshold must be positive",
        )?;
        ensure(
            self.min_settlement_blockers > 0,
            "settlement blocker threshold must be positive",
        )?;
        ensure(
            self.min_disclosure_guards > 0,
            "disclosure guard threshold must be positive",
        )?;
        ensure(
            self.min_escape_notifications > 0,
            "escape notification threshold must be positive",
        )?;
        ensure(
            self.min_command_authorities > 0,
            "command authority threshold must be positive",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "checklist_suite": self.checklist_suite,
            "wave": self.wave,
            "source_wave": self.source_wave,
            "current_height": self.current_height,
            "max_handoff_age_blocks": self.max_handoff_age_blocks,
            "operator_checklist_id": self.operator_checklist_id,
            "source_handoff_root": self.source_handoff_root,
            "source_wallet_warning_root": self.source_wallet_warning_root,
            "source_watchtower_challenge_root": self.source_watchtower_challenge_root,
            "source_watchtower_audit_root": self.source_watchtower_audit_root,
            "source_settlement_evidence_root": self.source_settlement_evidence_root,
            "source_disclosure_warning_root": self.source_disclosure_warning_root,
            "min_wallet_warning_items": self.min_wallet_warning_items,
            "min_watchtower_audit_roots": self.min_watchtower_audit_roots,
            "min_watchtower_challenge_roots": self.min_watchtower_challenge_roots,
            "min_settlement_blockers": self.min_settlement_blockers,
            "min_disclosure_guards": self.min_disclosure_guards,
            "min_escape_notifications": self.min_escape_notifications,
            "min_command_authorities": self.min_command_authorities,
            "max_open_settlements": self.max_open_settlements,
            "max_private_disclosures": self.max_private_disclosures,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE87-CHECKLIST-CONFIG", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandoffRootWitness {
    pub witness_id: String,
    pub observed_height: u64,
    pub incident_handoff_root: String,
    pub wallet_warning_root: String,
    pub watchtower_challenge_root: String,
    pub watchtower_audit_root: String,
    pub settlement_evidence_root: String,
    pub disclosure_warning_root: String,
    pub status: ChecklistStatus,
}

impl HandoffRootWitness {
    pub fn devnet(config: &Config) -> Self {
        Self {
            witness_id: stable_id("handoff-root-witness", &config.operator_checklist_id),
            observed_height: config.current_height.saturating_sub(12),
            incident_handoff_root: config.source_handoff_root.clone(),
            wallet_warning_root: config.source_wallet_warning_root.clone(),
            watchtower_challenge_root: config.source_watchtower_challenge_root.clone(),
            watchtower_audit_root: config.source_watchtower_audit_root.clone(),
            settlement_evidence_root: config.source_settlement_evidence_root.clone(),
            disclosure_warning_root: config.source_disclosure_warning_root.clone(),
            status: ChecklistStatus::Accepted,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.status.counts()
            && self.incident_handoff_root == config.source_handoff_root
            && self.wallet_warning_root == config.source_wallet_warning_root
            && self.watchtower_challenge_root == config.source_watchtower_challenge_root
            && self.watchtower_audit_root == config.source_watchtower_audit_root
            && self.settlement_evidence_root == config.source_settlement_evidence_root
            && self.disclosure_warning_root == config.source_disclosure_warning_root
            && evidence_fresh(config, self.observed_height)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("witness_id", &self.witness_id)?;
        ensure_root("incident_handoff_root", &self.incident_handoff_root)?;
        ensure_root("wallet_warning_root", &self.wallet_warning_root)?;
        ensure_root("watchtower_challenge_root", &self.watchtower_challenge_root)?;
        ensure_root("watchtower_audit_root", &self.watchtower_audit_root)?;
        ensure_root("settlement_evidence_root", &self.settlement_evidence_root)?;
        ensure_root("disclosure_warning_root", &self.disclosure_warning_root)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "witness_id": self.witness_id,
            "observed_height": self.observed_height,
            "incident_handoff_root": self.incident_handoff_root,
            "wallet_warning_root": self.wallet_warning_root,
            "watchtower_challenge_root": self.watchtower_challenge_root,
            "watchtower_audit_root": self.watchtower_audit_root,
            "settlement_evidence_root": self.settlement_evidence_root,
            "disclosure_warning_root": self.disclosure_warning_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE87-HANDOFF-ROOT-WITNESS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletWarningChecklistItem {
    pub item_id: String,
    pub source_warning_root: String,
    pub wallet_cohort_root: String,
    pub warning_template_root: String,
    pub operator_ack_root: String,
    pub issued_height: u64,
    pub status: ChecklistStatus,
}

impl WalletWarningChecklistItem {
    pub fn devnet(config: &Config, ordinal: u64) -> Self {
        let item_id = evidence_id(config, "wallet-warning", ordinal);
        Self {
            source_warning_root: config.source_wallet_warning_root.clone(),
            wallet_cohort_root: component_root(config, "wallet-cohort", &item_id),
            warning_template_root: component_root(config, "wallet-warning-template", &item_id),
            operator_ack_root: component_root(config, "wallet-warning-ack", &item_id),
            issued_height: config
                .current_height
                .saturating_sub(8)
                .saturating_add(ordinal),
            item_id,
            status: ChecklistStatus::Accepted,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.status.counts()
            && self.source_warning_root == config.source_wallet_warning_root
            && evidence_fresh(config, self.issued_height)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("item_id", &self.item_id)?;
        ensure_root("source_warning_root", &self.source_warning_root)?;
        ensure_root("wallet_cohort_root", &self.wallet_cohort_root)?;
        ensure_root("warning_template_root", &self.warning_template_root)?;
        ensure_root("operator_ack_root", &self.operator_ack_root)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "item_id": self.item_id,
            "source_warning_root": self.source_warning_root,
            "wallet_cohort_root": self.wallet_cohort_root,
            "warning_template_root": self.warning_template_root,
            "operator_ack_root": self.operator_ack_root,
            "issued_height": self.issued_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE87-WALLET-WARNING-CHECKLIST", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatchtowerChecklistRoot {
    pub root_id: String,
    pub kind: WatchtowerRootKind,
    pub source_root: String,
    pub audit_or_challenge_root: String,
    pub tower_commitment_root: String,
    pub observed_height: u64,
    pub status: ChecklistStatus,
}

impl WatchtowerChecklistRoot {
    pub fn devnet(config: &Config, kind: WatchtowerRootKind, ordinal: u64) -> Self {
        let root_id = evidence_id(config, kind.as_str(), ordinal);
        let source_root = match kind {
            WatchtowerRootKind::Audit => config.source_watchtower_audit_root.clone(),
            WatchtowerRootKind::Challenge => config.source_watchtower_challenge_root.clone(),
        };
        Self {
            root_id: root_id.clone(),
            kind,
            source_root,
            audit_or_challenge_root: component_root(config, kind.as_str(), &root_id),
            tower_commitment_root: component_root(config, "tower-commitment", &root_id),
            observed_height: config
                .current_height
                .saturating_sub(7)
                .saturating_add(ordinal),
            status: ChecklistStatus::Accepted,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        let planned = match self.kind {
            WatchtowerRootKind::Audit => &config.source_watchtower_audit_root,
            WatchtowerRootKind::Challenge => &config.source_watchtower_challenge_root,
        };
        self.status.counts()
            && &self.source_root == planned
            && evidence_fresh(config, self.observed_height)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("root_id", &self.root_id)?;
        ensure_root("source_root", &self.source_root)?;
        ensure_root("audit_or_challenge_root", &self.audit_or_challenge_root)?;
        ensure_root("tower_commitment_root", &self.tower_commitment_root)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "root_id": self.root_id,
            "kind": self.kind.as_str(),
            "source_root": self.source_root,
            "audit_or_challenge_root": self.audit_or_challenge_root,
            "tower_commitment_root": self.tower_commitment_root,
            "observed_height": self.observed_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE87-WATCHTOWER-CHECKLIST-ROOT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementStatusBlocker {
    pub blocker_id: String,
    pub source_settlement_root: String,
    pub settlement_status: SettlementStatus,
    pub blocker_root: String,
    pub operator_hold_root: String,
    pub observed_height: u64,
    pub status: ChecklistStatus,
}

impl SettlementStatusBlocker {
    pub fn devnet(config: &Config, ordinal: u64, settlement_status: SettlementStatus) -> Self {
        let blocker_id = evidence_id(config, "settlement-blocker", ordinal);
        Self {
            blocker_id: blocker_id.clone(),
            source_settlement_root: config.source_settlement_evidence_root.clone(),
            settlement_status,
            blocker_root: component_root(config, "settlement-blocker", &blocker_id),
            operator_hold_root: component_root(config, "settlement-hold", &blocker_id),
            observed_height: config
                .current_height
                .saturating_sub(6)
                .saturating_add(ordinal),
            status: ChecklistStatus::Accepted,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.status.counts()
            && self.source_settlement_root == config.source_settlement_evidence_root
            && evidence_fresh(config, self.observed_height)
    }

    pub fn open(&self) -> bool {
        self.settlement_status.blocks_release()
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("blocker_id", &self.blocker_id)?;
        ensure_root("source_settlement_root", &self.source_settlement_root)?;
        ensure_root("blocker_root", &self.blocker_root)?;
        ensure_root("operator_hold_root", &self.operator_hold_root)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "source_settlement_root": self.source_settlement_root,
            "settlement_status": self.settlement_status.as_str(),
            "blocker_root": self.blocker_root,
            "operator_hold_root": self.operator_hold_root,
            "observed_height": self.observed_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE87-SETTLEMENT-STATUS-BLOCKER", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScopedDisclosureSafeguard {
    pub safeguard_id: String,
    pub scope: DisclosureScope,
    pub source_disclosure_root: String,
    pub redaction_root: String,
    pub disclosure_manifest_root: String,
    pub public_fields_only: bool,
    pub status: ChecklistStatus,
}

impl ScopedDisclosureSafeguard {
    pub fn devnet(config: &Config, ordinal: u64, scope: DisclosureScope) -> Self {
        let safeguard_id = evidence_id(config, "disclosure-safeguard", ordinal);
        Self {
            safeguard_id: safeguard_id.clone(),
            scope,
            source_disclosure_root: config.source_disclosure_warning_root.clone(),
            redaction_root: component_root(config, "disclosure-redaction", &safeguard_id),
            disclosure_manifest_root: component_root(config, "disclosure-manifest", &safeguard_id),
            public_fields_only: true,
            status: ChecklistStatus::Accepted,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.status.counts()
            && self.public_fields_only
            && self.source_disclosure_root == config.source_disclosure_warning_root
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("safeguard_id", &self.safeguard_id)?;
        ensure_root("source_disclosure_root", &self.source_disclosure_root)?;
        ensure_root("redaction_root", &self.redaction_root)?;
        ensure_root("disclosure_manifest_root", &self.disclosure_manifest_root)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "safeguard_id": self.safeguard_id,
            "scope": self.scope.as_str(),
            "source_disclosure_root": self.source_disclosure_root,
            "redaction_root": self.redaction_root,
            "disclosure_manifest_root": self.disclosure_manifest_root,
            "public_fields_only": self.public_fields_only,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE87-SCOPED-DISCLOSURE-SAFEGUARD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserEscapeNotificationRoot {
    pub notification_id: String,
    pub source_warning_root: String,
    pub notification_root: String,
    pub delivery_cohort_root: String,
    pub acknowledgement_root: String,
    pub observed_height: u64,
    pub status: ChecklistStatus,
}

impl UserEscapeNotificationRoot {
    pub fn devnet(config: &Config, ordinal: u64) -> Self {
        let notification_id = evidence_id(config, "user-escape-notification", ordinal);
        Self {
            notification_id: notification_id.clone(),
            source_warning_root: config.source_wallet_warning_root.clone(),
            notification_root: component_root(config, "escape-notification", &notification_id),
            delivery_cohort_root: component_root(
                config,
                "escape-delivery-cohort",
                &notification_id,
            ),
            acknowledgement_root: component_root(config, "escape-ack", &notification_id),
            observed_height: config
                .current_height
                .saturating_sub(4)
                .saturating_add(ordinal),
            status: ChecklistStatus::Accepted,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.status.counts()
            && self.source_warning_root == config.source_wallet_warning_root
            && evidence_fresh(config, self.observed_height)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("notification_id", &self.notification_id)?;
        ensure_root("source_warning_root", &self.source_warning_root)?;
        ensure_root("notification_root", &self.notification_root)?;
        ensure_root("delivery_cohort_root", &self.delivery_cohort_root)?;
        ensure_root("acknowledgement_root", &self.acknowledgement_root)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "notification_id": self.notification_id,
            "source_warning_root": self.source_warning_root,
            "notification_root": self.notification_root,
            "delivery_cohort_root": self.delivery_cohort_root,
            "acknowledgement_root": self.acknowledgement_root,
            "observed_height": self.observed_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE87-USER-ESCAPE-NOTIFICATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommandAuthorityCheck {
    pub authority_id: String,
    pub authority: CommandAuthority,
    pub command_root: String,
    pub signer_quorum_root: String,
    pub fail_closed_root: String,
    pub command_window_closed: bool,
    pub fail_closed: bool,
    pub status: ChecklistStatus,
}

impl CommandAuthorityCheck {
    pub fn devnet(config: &Config, ordinal: u64, authority: CommandAuthority) -> Self {
        let authority_id = evidence_id(config, "command-authority", ordinal);
        Self {
            authority_id: authority_id.clone(),
            authority,
            command_root: component_root(config, "operator-command", &authority_id),
            signer_quorum_root: component_root(config, "command-signer-quorum", &authority_id),
            fail_closed_root: component_root(config, "command-fail-closed", &authority_id),
            command_window_closed: true,
            fail_closed: true,
            status: ChecklistStatus::Accepted,
        }
    }

    pub fn accepted(&self) -> bool {
        self.status.counts() && self.command_window_closed && self.fail_closed
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("authority_id", &self.authority_id)?;
        ensure_root("command_root", &self.command_root)?;
        ensure_root("signer_quorum_root", &self.signer_quorum_root)?;
        ensure_root("fail_closed_root", &self.fail_closed_root)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "authority_id": self.authority_id,
            "authority": self.authority.as_str(),
            "command_root": self.command_root,
            "signer_quorum_root": self.signer_quorum_root,
            "fail_closed_root": self.fail_closed_root,
            "command_window_closed": self.command_window_closed,
            "fail_closed": self.fail_closed,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE87-COMMAND-AUTHORITY-CHECK", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChecklistBlocker {
    pub blocker_id: String,
    pub kind: BlockerKind,
    pub subject: String,
    pub evidence_root: String,
}

impl ChecklistBlocker {
    pub fn new(config: &Config, kind: BlockerKind, subject: &str, evidence_root: &str) -> Self {
        let blocker_id = domain_hash(
            "WAVE87-CHECKLIST-BLOCKER-ID",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.operator_checklist_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(subject),
                HashPart::Str(evidence_root),
            ],
            16,
        );
        Self {
            blocker_id,
            kind,
            subject: subject.to_string(),
            evidence_root: evidence_root.to_string(),
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

    pub fn state_root(&self) -> String {
        record_root("WAVE87-CHECKLIST-BLOCKER", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChecklistCounters {
    pub wallet_warning_items: u64,
    pub watchtower_audit_roots: u64,
    pub watchtower_challenge_roots: u64,
    pub settlement_blockers: u64,
    pub open_settlements: u64,
    pub disclosure_guards: u64,
    pub private_disclosures: u64,
    pub escape_notifications: u64,
    pub command_authorities: u64,
    pub open_command_authorities: u64,
    pub rejected_records: u64,
}

impl ChecklistCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "wallet_warning_items": self.wallet_warning_items,
            "watchtower_audit_roots": self.watchtower_audit_roots,
            "watchtower_challenge_roots": self.watchtower_challenge_roots,
            "settlement_blockers": self.settlement_blockers,
            "open_settlements": self.open_settlements,
            "disclosure_guards": self.disclosure_guards,
            "private_disclosures": self.private_disclosures,
            "escape_notifications": self.escape_notifications,
            "command_authorities": self.command_authorities,
            "open_command_authorities": self.open_command_authorities,
            "rejected_records": self.rejected_records,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE87-CHECKLIST-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChecklistVerdict {
    pub operator_checklist_id: String,
    pub evidence_root: String,
    pub blocker_root: String,
    pub counters_root: String,
    pub command_authority_root: String,
    pub fail_closed: bool,
    pub deployment_blocked: bool,
    pub accepted: bool,
    pub verdict_root: String,
}

impl ChecklistVerdict {
    pub fn from_state(state: &State, blockers: &[ChecklistBlocker]) -> Self {
        let evidence_root = state.evidence_root();
        let blocker_root = list_root(
            "WAVE87-CHECKLIST-BLOCKER-ROOT",
            blockers.iter().map(ChecklistBlocker::state_root),
        );
        let counters = state.counters();
        let counters_root = counters.state_root();
        let command_authority_root = list_root(
            "WAVE87-CHECKLIST-COMMAND-AUTHORITY-ROOT",
            state
                .command_authority_checks
                .iter()
                .map(CommandAuthorityCheck::state_root),
        );
        let accepted = state.config.fail_closed && blockers.is_empty();
        let deployment_blocked = !accepted;
        let fail_closed = deployment_blocked || !accepted;
        let verdict_root = domain_hash(
            "WAVE87-CHECKLIST-VERDICT",
            &[
                HashPart::Str(&state.config.operator_checklist_id),
                HashPart::Str(&evidence_root),
                HashPart::Str(&blocker_root),
                HashPart::Str(&counters_root),
                HashPart::Str(&command_authority_root),
                HashPart::Str(bool_str(fail_closed)),
                HashPart::Str(bool_str(deployment_blocked)),
                HashPart::Str(bool_str(accepted)),
            ],
            32,
        );
        Self {
            operator_checklist_id: state.config.operator_checklist_id.clone(),
            evidence_root,
            blocker_root,
            counters_root,
            command_authority_root,
            fail_closed,
            deployment_blocked,
            accepted,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "operator_checklist_id": self.operator_checklist_id,
            "evidence_root": self.evidence_root,
            "blocker_root": self.blocker_root,
            "counters_root": self.counters_root,
            "command_authority_root": self.command_authority_root,
            "fail_closed": self.fail_closed,
            "deployment_blocked": self.deployment_blocked,
            "accepted": self.accepted,
            "verdict_root": self.verdict_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("WAVE87-CHECKLIST-VERDICT-STATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub handoff_root_witness: HandoffRootWitness,
    pub wallet_warning_items: Vec<WalletWarningChecklistItem>,
    pub watchtower_roots: Vec<WatchtowerChecklistRoot>,
    pub settlement_blockers: Vec<SettlementStatusBlocker>,
    pub disclosure_safeguards: Vec<ScopedDisclosureSafeguard>,
    pub escape_notifications: Vec<UserEscapeNotificationRoot>,
    pub command_authority_checks: Vec<CommandAuthorityCheck>,
}

impl State {
    pub fn new(
        config: Config,
        handoff_root_witness: HandoffRootWitness,
        wallet_warning_items: Vec<WalletWarningChecklistItem>,
        watchtower_roots: Vec<WatchtowerChecklistRoot>,
        settlement_blockers: Vec<SettlementStatusBlocker>,
        disclosure_safeguards: Vec<ScopedDisclosureSafeguard>,
        escape_notifications: Vec<UserEscapeNotificationRoot>,
        command_authority_checks: Vec<CommandAuthorityCheck>,
    ) -> Result<Self> {
        let state = Self {
            config,
            handoff_root_witness,
            wallet_warning_items,
            watchtower_roots,
            settlement_blockers,
            disclosure_safeguards,
            escape_notifications,
            command_authority_checks,
        };
        state.validate_shape()?;
        Ok(state)
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let handoff_root_witness = HandoffRootWitness::devnet(&config);
        let wallet_warning_items = (1..=DEFAULT_MIN_WALLET_WARNINGS)
            .map(|index| WalletWarningChecklistItem::devnet(&config, index))
            .collect::<Vec<_>>();
        let watchtower_roots = vec![
            WatchtowerChecklistRoot::devnet(&config, WatchtowerRootKind::Audit, 1),
            WatchtowerChecklistRoot::devnet(&config, WatchtowerRootKind::Audit, 2),
            WatchtowerChecklistRoot::devnet(&config, WatchtowerRootKind::Challenge, 1),
            WatchtowerChecklistRoot::devnet(&config, WatchtowerRootKind::Challenge, 2),
        ];
        let settlement_blockers = vec![SettlementStatusBlocker::devnet(
            &config,
            1,
            SettlementStatus::Finalized,
        )];
        let disclosure_safeguards = vec![
            ScopedDisclosureSafeguard::devnet(&config, 1, DisclosureScope::WalletWarning),
            ScopedDisclosureSafeguard::devnet(&config, 2, DisclosureScope::WatchtowerAudit),
            ScopedDisclosureSafeguard::devnet(&config, 3, DisclosureScope::WatchtowerChallenge),
            ScopedDisclosureSafeguard::devnet(&config, 4, DisclosureScope::UserEscapeNotification),
        ];
        let escape_notifications = (1..=DEFAULT_MIN_ESCAPE_NOTIFICATIONS)
            .map(|index| UserEscapeNotificationRoot::devnet(&config, index))
            .collect::<Vec<_>>();
        let command_authority_checks = vec![
            CommandAuthorityCheck::devnet(&config, 1, CommandAuthority::IncidentCommander),
            CommandAuthorityCheck::devnet(&config, 2, CommandAuthority::WalletLead),
            CommandAuthorityCheck::devnet(&config, 3, CommandAuthority::WatchtowerLead),
            CommandAuthorityCheck::devnet(&config, 4, CommandAuthority::SettlementLead),
        ];
        match Self::new(
            config,
            handoff_root_witness,
            wallet_warning_items,
            watchtower_roots,
            settlement_blockers,
            disclosure_safeguards,
            escape_notifications,
            command_authority_checks,
        ) {
            Ok(state) => state,
            Err(error) => Self::fail_closed_fallback(error),
        }
    }

    pub fn fail_closed_fallback(error: String) -> Self {
        let config = Config::devnet();
        let handoff_root_witness = HandoffRootWitness {
            witness_id: stable_id("handoff-root-witness", "fail-closed"),
            observed_height: config.current_height,
            incident_handoff_root: config.source_handoff_root.clone(),
            wallet_warning_root: config.source_wallet_warning_root.clone(),
            watchtower_challenge_root: config.source_watchtower_challenge_root.clone(),
            watchtower_audit_root: config.source_watchtower_audit_root.clone(),
            settlement_evidence_root: config.source_settlement_evidence_root.clone(),
            disclosure_warning_root: config.source_disclosure_warning_root.clone(),
            status: ChecklistStatus::Blocked,
        };
        let command_authority_checks = vec![CommandAuthorityCheck {
            authority_id: stable_id("command-authority", "fail-closed"),
            authority: CommandAuthority::IncidentCommander,
            command_root: source_root(&format!("fail-closed-command-{error}")),
            signer_quorum_root: source_root("fail-closed-signer-quorum"),
            fail_closed_root: source_root("fail-closed-authority"),
            command_window_closed: false,
            fail_closed: true,
            status: ChecklistStatus::Blocked,
        }];
        Self {
            config,
            handoff_root_witness,
            wallet_warning_items: Vec::new(),
            watchtower_roots: Vec::new(),
            settlement_blockers: Vec::new(),
            disclosure_safeguards: Vec::new(),
            escape_notifications: Vec::new(),
            command_authority_checks,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_shape()?;
        ensure(
            self.handoff_root_witness.accepted(&self.config),
            "source handoff roots are not accepted",
        )?;
        ensure(
            self.blockers().is_empty(),
            "operator checklist is fail-closed",
        )
    }

    pub fn validate_shape(&self) -> Result<()> {
        self.config.validate()?;
        self.handoff_root_witness.validate()?;
        validate_records(
            &self.wallet_warning_items,
            WalletWarningChecklistItem::validate,
        )?;
        validate_records(&self.watchtower_roots, WatchtowerChecklistRoot::validate)?;
        validate_records(&self.settlement_blockers, SettlementStatusBlocker::validate)?;
        validate_records(
            &self.disclosure_safeguards,
            ScopedDisclosureSafeguard::validate,
        )?;
        validate_records(
            &self.escape_notifications,
            UserEscapeNotificationRoot::validate,
        )?;
        validate_records(
            &self.command_authority_checks,
            CommandAuthorityCheck::validate,
        )
    }

    pub fn counters(&self) -> ChecklistCounters {
        ChecklistCounters {
            wallet_warning_items: self.wallet_warning_count(),
            watchtower_audit_roots: self.watchtower_kind_count(WatchtowerRootKind::Audit),
            watchtower_challenge_roots: self.watchtower_kind_count(WatchtowerRootKind::Challenge),
            settlement_blockers: self.settlement_blocker_count(),
            open_settlements: self.open_settlement_count(),
            disclosure_guards: self.disclosure_guard_count(),
            private_disclosures: self.private_disclosure_count(),
            escape_notifications: self.escape_notification_count(),
            command_authorities: self.command_authority_count(),
            open_command_authorities: self.open_command_authority_count(),
            rejected_records: self.rejected_record_count(),
        }
    }

    pub fn wallet_warning_count(&self) -> u64 {
        self.wallet_warning_items
            .iter()
            .filter(|item| item.accepted(&self.config))
            .count() as u64
    }

    pub fn watchtower_kind_count(&self, kind: WatchtowerRootKind) -> u64 {
        self.watchtower_roots
            .iter()
            .filter(|root| root.kind == kind && root.accepted(&self.config))
            .count() as u64
    }

    pub fn settlement_blocker_count(&self) -> u64 {
        self.settlement_blockers
            .iter()
            .filter(|blocker| blocker.accepted(&self.config))
            .count() as u64
    }

    pub fn open_settlement_count(&self) -> u64 {
        self.settlement_blockers
            .iter()
            .filter(|blocker| blocker.accepted(&self.config) && blocker.open())
            .count() as u64
    }

    pub fn disclosure_guard_count(&self) -> u64 {
        self.disclosure_safeguards
            .iter()
            .filter(|guard| guard.accepted(&self.config))
            .count() as u64
    }

    pub fn private_disclosure_count(&self) -> u64 {
        self.disclosure_safeguards
            .iter()
            .filter(|guard| !guard.public_fields_only)
            .count() as u64
    }

    pub fn escape_notification_count(&self) -> u64 {
        self.escape_notifications
            .iter()
            .filter(|notification| notification.accepted(&self.config))
            .count() as u64
    }

    pub fn command_authority_count(&self) -> u64 {
        self.command_authority_checks
            .iter()
            .filter(|check| check.accepted())
            .map(|check| check.authority.as_str())
            .collect::<BTreeSet<_>>()
            .len() as u64
    }

    pub fn open_command_authority_count(&self) -> u64 {
        self.command_authority_checks
            .iter()
            .filter(|check| !check.command_window_closed || !check.fail_closed)
            .count() as u64
    }

    pub fn rejected_record_count(&self) -> u64 {
        let wallet = self
            .wallet_warning_items
            .iter()
            .filter(|item| item.status.blocks())
            .count();
        let watchtower = self
            .watchtower_roots
            .iter()
            .filter(|root| root.status.blocks())
            .count();
        let settlement = self
            .settlement_blockers
            .iter()
            .filter(|blocker| blocker.status.blocks())
            .count();
        let disclosure = self
            .disclosure_safeguards
            .iter()
            .filter(|guard| guard.status.blocks())
            .count();
        let escape = self
            .escape_notifications
            .iter()
            .filter(|notification| notification.status.blocks())
            .count();
        let command = self
            .command_authority_checks
            .iter()
            .filter(|check| check.status.blocks())
            .count();
        (wallet + watchtower + settlement + disclosure + escape + command) as u64
    }

    pub fn evidence_root(&self) -> String {
        merkle_root(
            "WAVE87-CHECKLIST-EVIDENCE-ROOT",
            &[
                json!({"config_root": self.config.state_root()}),
                json!({"handoff_root_witness": self.handoff_root_witness.state_root()}),
                json!({"wallet_warning_root": list_root("WAVE87-WALLET-WARNING-ROOT", self.wallet_warning_items.iter().map(WalletWarningChecklistItem::state_root))}),
                json!({"watchtower_root": list_root("WAVE87-WATCHTOWER-ROOT", self.watchtower_roots.iter().map(WatchtowerChecklistRoot::state_root))}),
                json!({"settlement_blocker_root": list_root("WAVE87-SETTLEMENT-BLOCKER-ROOT", self.settlement_blockers.iter().map(SettlementStatusBlocker::state_root))}),
                json!({"disclosure_guard_root": list_root("WAVE87-DISCLOSURE-GUARD-ROOT", self.disclosure_safeguards.iter().map(ScopedDisclosureSafeguard::state_root))}),
                json!({"escape_notification_root": list_root("WAVE87-ESCAPE-NOTIFICATION-ROOT", self.escape_notifications.iter().map(UserEscapeNotificationRoot::state_root))}),
                json!({"command_authority_root": list_root("WAVE87-COMMAND-AUTHORITY-ROOT", self.command_authority_checks.iter().map(CommandAuthorityCheck::state_root))}),
                json!({"counters_root": self.counters().state_root()}),
            ],
        )
    }

    pub fn blockers(&self) -> Vec<ChecklistBlocker> {
        unique_blockers(&self.config, self.blocker_kinds(), &self.evidence_root())
    }

    pub fn verdict(&self) -> ChecklistVerdict {
        let blockers = self.blockers();
        ChecklistVerdict::from_state(self, &blockers)
    }

    pub fn public_record(&self) -> Value {
        let blockers = self.blockers();
        let verdict = ChecklistVerdict::from_state(self, &blockers);
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "handoff_root_witness": self.handoff_root_witness.public_record(),
            "wallet_warning_items": self.wallet_warning_items.iter().map(WalletWarningChecklistItem::public_record).collect::<Vec<_>>(),
            "watchtower_roots": self.watchtower_roots.iter().map(WatchtowerChecklistRoot::public_record).collect::<Vec<_>>(),
            "settlement_blockers": self.settlement_blockers.iter().map(SettlementStatusBlocker::public_record).collect::<Vec<_>>(),
            "disclosure_safeguards": self.disclosure_safeguards.iter().map(ScopedDisclosureSafeguard::public_record).collect::<Vec<_>>(),
            "escape_notifications": self.escape_notifications.iter().map(UserEscapeNotificationRoot::public_record).collect::<Vec<_>>(),
            "command_authority_checks": self.command_authority_checks.iter().map(CommandAuthorityCheck::public_record).collect::<Vec<_>>(),
            "counters": self.counters().public_record(),
            "evidence_root": self.evidence_root(),
            "blockers": blockers.iter().map(ChecklistBlocker::public_record).collect::<Vec<_>>(),
            "verdict": verdict.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "WAVE87-CHECKLIST-STATE",
            &json!({
                "config_root": self.config.state_root(),
                "evidence_root": self.evidence_root(),
                "verdict_root": self.verdict().state_root(),
            }),
        )
    }

    fn blocker_kinds(&self) -> Vec<(BlockerKind, String)> {
        let counters = self.counters();
        let mut blockers = Vec::new();
        if !self.handoff_root_witness.accepted(&self.config) {
            blockers.push((
                BlockerKind::SourceHandoffRootMissing,
                "handoff_root_witness".to_string(),
            ));
            if !evidence_fresh(&self.config, self.handoff_root_witness.observed_height) {
                blockers.push((
                    BlockerKind::SourceHandoffStale,
                    "handoff_root_witness".to_string(),
                ));
            }
        }
        if counters.wallet_warning_items < self.config.min_wallet_warning_items {
            blockers.push((
                BlockerKind::WalletWarningMissing,
                "wallet_warning_items".to_string(),
            ));
        }
        if counters.watchtower_audit_roots < self.config.min_watchtower_audit_roots {
            blockers.push((
                BlockerKind::WatchtowerAuditRootMissing,
                "watchtower_roots".to_string(),
            ));
        }
        if counters.watchtower_challenge_roots < self.config.min_watchtower_challenge_roots {
            blockers.push((
                BlockerKind::WatchtowerChallengeRootMissing,
                "watchtower_roots".to_string(),
            ));
        }
        if counters.settlement_blockers < self.config.min_settlement_blockers {
            blockers.push((
                BlockerKind::SettlementBlockerMissing,
                "settlement_blockers".to_string(),
            ));
        }
        if counters.open_settlements > self.config.max_open_settlements {
            blockers.push((
                BlockerKind::SettlementStatusOpen,
                "settlement_blockers".to_string(),
            ));
        }
        if counters.disclosure_guards < self.config.min_disclosure_guards {
            blockers.push((
                BlockerKind::DisclosureGuardMissing,
                "disclosure_safeguards".to_string(),
            ));
        }
        if counters.private_disclosures > self.config.max_private_disclosures {
            blockers.push((
                BlockerKind::PrivateDisclosureRequested,
                "disclosure_safeguards".to_string(),
            ));
        }
        if counters.escape_notifications < self.config.min_escape_notifications {
            blockers.push((
                BlockerKind::UserEscapeNotificationMissing,
                "escape_notifications".to_string(),
            ));
        }
        if counters.command_authorities < self.config.min_command_authorities {
            blockers.push((
                BlockerKind::CommandAuthorityMissing,
                "command_authority_checks".to_string(),
            ));
        }
        if counters.open_command_authorities > 0 {
            blockers.push((
                BlockerKind::CommandAuthorityOpen,
                "command_authority_checks".to_string(),
            ));
        }
        if counters.rejected_records > 0 {
            blockers.push((
                BlockerKind::ChecklistEvidenceRejected,
                "operator_checklist".to_string(),
            ));
        }
        if !self.config.fail_closed {
            blockers.push((
                BlockerKind::FailClosedNotAsserted,
                "operator_checklist".to_string(),
            ));
        }
        blockers
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

fn unique_blockers(
    config: &Config,
    blockers: Vec<(BlockerKind, String)>,
    evidence_root: &str,
) -> Vec<ChecklistBlocker> {
    let mut seen = BTreeSet::new();
    blockers
        .into_iter()
        .filter(|(kind, subject)| seen.insert((*kind, subject.clone())))
        .map(|(kind, subject)| ChecklistBlocker::new(config, kind, &subject, evidence_root))
        .collect()
}

fn validate_records<T, F>(records: &[T], validate: F) -> Result<()>
where
    F: Fn(&T) -> Result<()>,
{
    for record in records {
        validate(record)?;
    }
    Ok(())
}

fn evidence_fresh(config: &Config, observed_height: u64) -> bool {
    observed_height <= config.current_height
        && config.current_height.saturating_sub(observed_height) <= config.max_handoff_age_blocks
}

fn list_root<I>(domain: &str, roots: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let leaves = roots
        .into_iter()
        .map(|root| json!({"root": root}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
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

fn source_root(label: &str) -> String {
    domain_hash(
        "WAVE87-CHECKLIST-SOURCE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn component_root(config: &Config, kind: &str, record_id: &str) -> String {
    domain_hash(
        "WAVE87-CHECKLIST-COMPONENT-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.operator_checklist_id),
            HashPart::Str(kind),
            HashPart::Str(record_id),
            HashPart::U64(config.current_height),
        ],
        32,
    )
}

fn stable_id(prefix: &str, label: &str) -> String {
    format!(
        "{}-{}",
        prefix,
        domain_hash(
            "WAVE87-CHECKLIST-STABLE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(prefix),
                HashPart::Str(label),
            ],
            16,
        )
    )
}

fn evidence_id(config: &Config, kind: &str, ordinal: u64) -> String {
    domain_hash(
        "WAVE87-CHECKLIST-EVIDENCE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.operator_checklist_id),
            HashPart::Str(kind),
            HashPart::U64(ordinal),
        ],
        16,
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
