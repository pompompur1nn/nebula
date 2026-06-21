use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageCompileRuntimeAcceptedLiveEvidenceOperatorDashboardReleasePolicyDeploymentGuardRollbackDrillIncidentHandoffOperatorCommandChecklistRuntimeResult<
    T,
> = Result<T>;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_COMPILE_RUNTIME_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_INCIDENT_HANDOFF_OPERATOR_COMMAND_CHECKLIST_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-compile-runtime-accepted-live-evidence-operator-dashboard-release-policy-deployment-guard-rollback-drill-incident-handoff-operator-command-checklist-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_COMPILE_RUNTIME_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_INCIDENT_HANDOFF_OPERATOR_COMMAND_CHECKLIST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CHECKLIST_SUITE: &str =
    "monero-l2-pq-force-exit-compile-runtime-operator-command-checklist-v1";
pub const DEFAULT_RELEASE_EPOCH: u64 = 87;
pub const DEFAULT_SOURCE_HANDOFF_EPOCH: u64 = 86;
pub const DEFAULT_CHECKLIST_HEIGHT: u64 = 870_000;
pub const DEFAULT_HANDOFF_HEIGHT: u64 = 860_000;
pub const DEFAULT_MAX_HANDOFF_AGE_BLOCKS: u64 = 12_000;
pub const DEFAULT_MIN_CHECKLIST_ITEMS: u16 = 7;
pub const DEFAULT_MIN_BLOCKER_RECEIPTS: u16 = 4;
pub const DEFAULT_MIN_OWNER_SIGNOFFS: u16 = 4;
pub const DEFAULT_MIN_RELEASE_FREEZE_ITEMS: u16 = 3;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub checklist_suite: String,
    pub release_epoch: u64,
    pub source_handoff_epoch: u64,
    pub checklist_height: u64,
    pub handoff_height: u64,
    pub release_channel: String,
    pub command_room_label: String,
    pub deployment_environment: String,
    pub max_handoff_age_blocks: u64,
    pub min_checklist_items: u16,
    pub min_blocker_receipts: u16,
    pub min_owner_signoffs: u16,
    pub min_release_freeze_items: u16,
    pub require_wave_86_handoff_roots: bool,
    pub require_release_freeze: bool,
    pub require_rustfmt_receipt: bool,
    pub require_compile_blocker_receipt: bool,
    pub require_deferred_cargo_gate_placeholders: bool,
    pub require_command_room_owner_signoffs: bool,
    pub require_fail_closed_deployment_authority: bool,
    pub allow_production_deploy: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            checklist_suite: CHECKLIST_SUITE.to_string(),
            release_epoch: DEFAULT_RELEASE_EPOCH,
            source_handoff_epoch: DEFAULT_SOURCE_HANDOFF_EPOCH,
            checklist_height: DEFAULT_CHECKLIST_HEIGHT,
            handoff_height: DEFAULT_HANDOFF_HEIGHT,
            release_channel: "devnet-compile-runtime-command-checklist".to_string(),
            command_room_label: "wave-87-compile-runtime-command-room".to_string(),
            deployment_environment: "devnet-production-shadow".to_string(),
            max_handoff_age_blocks: DEFAULT_MAX_HANDOFF_AGE_BLOCKS,
            min_checklist_items: DEFAULT_MIN_CHECKLIST_ITEMS,
            min_blocker_receipts: DEFAULT_MIN_BLOCKER_RECEIPTS,
            min_owner_signoffs: DEFAULT_MIN_OWNER_SIGNOFFS,
            min_release_freeze_items: DEFAULT_MIN_RELEASE_FREEZE_ITEMS,
            require_wave_86_handoff_roots: true,
            require_release_freeze: true,
            require_rustfmt_receipt: true,
            require_compile_blocker_receipt: true,
            require_deferred_cargo_gate_placeholders: true,
            require_command_room_owner_signoffs: true,
            require_fail_closed_deployment_authority: true,
            allow_production_deploy: false,
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
        ensure_non_empty("command_room_label", &self.command_room_label)?;
        ensure_non_empty("deployment_environment", &self.deployment_environment)?;
        ensure(self.schema_version > 0, "schema version must be non-zero")?;
        ensure(self.release_epoch > 0, "release epoch must be non-zero")?;
        ensure(
            self.source_handoff_epoch > 0,
            "source handoff epoch must be non-zero",
        )?;
        ensure(
            self.release_epoch > self.source_handoff_epoch,
            "checklist epoch must follow handoff epoch",
        )?;
        ensure(
            self.checklist_height > self.handoff_height,
            "checklist height must follow handoff height",
        )?;
        ensure(
            self.checklist_height - self.handoff_height <= self.max_handoff_age_blocks,
            "wave 86 handoff roots are too old for checklist binding",
        )?;
        ensure(
            self.min_checklist_items > 0,
            "minimum checklist items must be non-zero",
        )?;
        ensure(
            self.min_blocker_receipts > 0,
            "minimum blocker receipts must be non-zero",
        )?;
        ensure(
            self.min_owner_signoffs > 0,
            "minimum owner signoffs must be non-zero",
        )?;
        ensure(
            self.min_release_freeze_items > 0,
            "minimum release-freeze items must be non-zero",
        )?;
        if self.require_fail_closed_deployment_authority {
            ensure(
                !self.allow_production_deploy,
                "fail-closed deployment authority cannot allow production deploy",
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
            "source_handoff_epoch": self.source_handoff_epoch,
            "checklist_height": self.checklist_height,
            "handoff_height": self.handoff_height,
            "release_channel": self.release_channel,
            "command_room_label": self.command_room_label,
            "deployment_environment": self.deployment_environment,
            "max_handoff_age_blocks": self.max_handoff_age_blocks,
            "min_checklist_items": self.min_checklist_items,
            "min_blocker_receipts": self.min_blocker_receipts,
            "min_owner_signoffs": self.min_owner_signoffs,
            "min_release_freeze_items": self.min_release_freeze_items,
            "require_wave_86_handoff_roots": self.require_wave_86_handoff_roots,
            "require_release_freeze": self.require_release_freeze,
            "require_rustfmt_receipt": self.require_rustfmt_receipt,
            "require_compile_blocker_receipt": self.require_compile_blocker_receipt,
            "require_deferred_cargo_gate_placeholders": self.require_deferred_cargo_gate_placeholders,
            "require_command_room_owner_signoffs": self.require_command_room_owner_signoffs,
            "require_fail_closed_deployment_authority": self.require_fail_closed_deployment_authority,
            "allow_production_deploy": self.allow_production_deploy,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistItemKind {
    BindWave86HandoffRoot,
    ReleaseFreezeNotice,
    RustfmtReceipt,
    CompileBlockerReceipt,
    DeferredCargoCheckGate,
    DeferredCargoTestGate,
    DeferredCargoClippyGate,
    CommandRoomOwnerSignoff,
    DeploymentAuthorityHold,
}

impl ChecklistItemKind {
    pub fn all() -> Vec<Self> {
        vec![
            Self::BindWave86HandoffRoot,
            Self::ReleaseFreezeNotice,
            Self::RustfmtReceipt,
            Self::CompileBlockerReceipt,
            Self::DeferredCargoCheckGate,
            Self::DeferredCargoTestGate,
            Self::DeferredCargoClippyGate,
            Self::CommandRoomOwnerSignoff,
            Self::DeploymentAuthorityHold,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::BindWave86HandoffRoot => "bind_wave_86_handoff_root",
            Self::ReleaseFreezeNotice => "release_freeze_notice",
            Self::RustfmtReceipt => "rustfmt_receipt",
            Self::CompileBlockerReceipt => "compile_blocker_receipt",
            Self::DeferredCargoCheckGate => "deferred_cargo_check_gate",
            Self::DeferredCargoTestGate => "deferred_cargo_test_gate",
            Self::DeferredCargoClippyGate => "deferred_cargo_clippy_gate",
            Self::CommandRoomOwnerSignoff => "command_room_owner_signoff",
            Self::DeploymentAuthorityHold => "deployment_authority_hold",
        }
    }

    pub fn release_freeze_item(self) -> bool {
        matches!(
            self,
            Self::ReleaseFreezeNotice | Self::CompileBlockerReceipt | Self::DeploymentAuthorityHold
        )
    }

    pub fn deferred_cargo_gate(self) -> bool {
        matches!(
            self,
            Self::DeferredCargoCheckGate
                | Self::DeferredCargoTestGate
                | Self::DeferredCargoClippyGate
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerRole {
    ReleaseCaptain,
    CompileRuntimeOwner,
    IncidentCommander,
    DeploymentAuthority,
}

impl OwnerRole {
    pub fn all() -> Vec<Self> {
        vec![
            Self::ReleaseCaptain,
            Self::CompileRuntimeOwner,
            Self::IncidentCommander,
            Self::DeploymentAuthority,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseCaptain => "release_captain",
            Self::CompileRuntimeOwner => "compile_runtime_owner",
            Self::IncidentCommander => "incident_commander",
            Self::DeploymentAuthority => "deployment_authority",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerKind {
    Wave86HandoffRootRequired,
    ReleaseFreezeRequired,
    RustfmtReceiptMissing,
    CompileReceiptBlocksRelease,
    DeferredCargoGatePending,
    OwnerSignoffQuorumMissing,
    DeploymentAuthorityFailClosed,
    ProductionDeployDisabled,
}

impl BlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wave86HandoffRootRequired => "wave_86_handoff_root_required",
            Self::ReleaseFreezeRequired => "release_freeze_required",
            Self::RustfmtReceiptMissing => "rustfmt_receipt_missing",
            Self::CompileReceiptBlocksRelease => "compile_receipt_blocks_release",
            Self::DeferredCargoGatePending => "deferred_cargo_gate_pending",
            Self::OwnerSignoffQuorumMissing => "owner_signoff_quorum_missing",
            Self::DeploymentAuthorityFailClosed => "deployment_authority_fail_closed",
            Self::ProductionDeployDisabled => "production_deploy_disabled",
        }
    }

    pub fn severity(self) -> u8 {
        match self {
            Self::DeploymentAuthorityFailClosed | Self::ProductionDeployDisabled => 3,
            Self::CompileReceiptBlocksRelease | Self::DeferredCargoGatePending => 2,
            _ => 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Wave86HandoffRoots {
    pub source_epoch: u64,
    pub observed_height: u64,
    pub incident_handoff_root: String,
    pub release_hold_root: String,
    pub blocker_root: String,
    pub operator_ack_root: String,
    pub evidence_bundle_root: String,
    pub accepted_live_evidence_root: String,
    pub source_root: String,
}

impl Wave86HandoffRoots {
    pub fn devnet(config: &Config) -> Self {
        let incident_handoff_root = sample_root("wave-86-incident-handoff", "compile-runtime", 1);
        let release_hold_root = sample_root("wave-86-release-hold", "compile-runtime", 2);
        let blocker_root = sample_root("wave-86-blockers", "compile-runtime", 3);
        let operator_ack_root = sample_root("wave-86-operator-acks", "compile-runtime", 4);
        let evidence_bundle_root = roots_root(
            "wave-86-handoff-evidence-bundle",
            [
                incident_handoff_root.clone(),
                release_hold_root.clone(),
                blocker_root.clone(),
                operator_ack_root.clone(),
            ],
        );
        let accepted_live_evidence_root =
            sample_root("wave-86-accepted-live-evidence", "compile-runtime", 5);
        let source_root = roots_root(
            "wave-86-handoff-roots",
            [
                evidence_bundle_root.clone(),
                accepted_live_evidence_root.clone(),
            ],
        );
        Self {
            source_epoch: config.source_handoff_epoch,
            observed_height: config.handoff_height,
            incident_handoff_root,
            release_hold_root,
            blocker_root,
            operator_ack_root,
            evidence_bundle_root,
            accepted_live_evidence_root,
            source_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "source_epoch": self.source_epoch,
            "observed_height": self.observed_height,
            "incident_handoff_root": self.incident_handoff_root,
            "release_hold_root": self.release_hold_root,
            "blocker_root": self.blocker_root,
            "operator_ack_root": self.operator_ack_root,
            "evidence_bundle_root": self.evidence_bundle_root,
            "accepted_live_evidence_root": self.accepted_live_evidence_root,
            "source_root": self.source_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("wave-86-handoff-roots", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("wave 86 incident handoff root", &self.incident_handoff_root)?;
        ensure_non_empty("wave 86 release hold root", &self.release_hold_root)?;
        ensure_non_empty("wave 86 blocker root", &self.blocker_root)?;
        ensure_non_empty("wave 86 operator ack root", &self.operator_ack_root)?;
        ensure_non_empty("wave 86 evidence bundle root", &self.evidence_bundle_root)?;
        ensure_non_empty(
            "wave 86 accepted live evidence root",
            &self.accepted_live_evidence_root,
        )?;
        ensure_non_empty("wave 86 source root", &self.source_root)?;
        ensure(self.source_epoch > 0, "source epoch must be non-zero")?;
        ensure(
            self.observed_height > 0,
            "source observed height must be non-zero",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChecklistItem {
    pub kind: ChecklistItemKind,
    pub label: String,
    pub source_root: String,
    pub commitment_root: String,
    pub receipt_root: String,
    pub release_freeze_item: bool,
    pub deferred_cargo_gate: bool,
    pub satisfied: bool,
    pub fail_closed: bool,
}

impl ChecklistItem {
    pub fn devnet(kind: ChecklistItemKind, source: &Wave86HandoffRoots, ordinal: u64) -> Self {
        let label = kind.as_str().to_string();
        let source_root = match kind {
            ChecklistItemKind::BindWave86HandoffRoot => source.source_root.clone(),
            ChecklistItemKind::ReleaseFreezeNotice => source.release_hold_root.clone(),
            ChecklistItemKind::CompileBlockerReceipt => source.blocker_root.clone(),
            ChecklistItemKind::CommandRoomOwnerSignoff => source.operator_ack_root.clone(),
            _ => sample_root("checklist-item-source", &label, ordinal),
        };
        let commitment_root = sample_root("checklist-item-commitment", &label, ordinal);
        let receipt_root = roots_root(
            "operator-command-checklist-item",
            [source_root.clone(), commitment_root.clone()],
        );
        let deferred_cargo_gate = kind.deferred_cargo_gate();
        let satisfied = !deferred_cargo_gate;
        Self {
            kind,
            label,
            source_root,
            commitment_root,
            receipt_root,
            release_freeze_item: kind.release_freeze_item(),
            deferred_cargo_gate,
            satisfied,
            fail_closed: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "label": self.label,
            "source_root": self.source_root,
            "commitment_root": self.commitment_root,
            "receipt_root": self.receipt_root,
            "release_freeze_item": self.release_freeze_item,
            "deferred_cargo_gate": self.deferred_cargo_gate,
            "satisfied": self.satisfied,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("checklist-item", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("checklist item label", &self.label)?;
        ensure_non_empty("checklist item source root", &self.source_root)?;
        ensure_non_empty("checklist item commitment root", &self.commitment_root)?;
        ensure_non_empty("checklist item receipt root", &self.receipt_root)?;
        ensure(self.fail_closed, "checklist item must be fail-closed")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlockerReceipt {
    pub kind: BlockerKind,
    pub label: String,
    pub blocker_root: String,
    pub commitment_root: String,
    pub fail_closed: bool,
}

impl BlockerReceipt {
    pub fn devnet(kind: BlockerKind, ordinal: u64) -> Self {
        let label = kind.as_str().to_string();
        Self {
            kind,
            label: label.clone(),
            blocker_root: sample_root("operator-command-blocker", &label, ordinal),
            commitment_root: sample_root("operator-command-blocker-commitment", &label, ordinal),
            fail_closed: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "label": self.label,
            "blocker_root": self.blocker_root,
            "commitment_root": self.commitment_root,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("blocker-receipt", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("blocker label", &self.label)?;
        ensure_non_empty("blocker root", &self.blocker_root)?;
        ensure_non_empty("blocker commitment root", &self.commitment_root)?;
        ensure(self.fail_closed, "blocker receipt must be fail-closed")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OwnerSignoff {
    pub role: OwnerRole,
    pub owner_label: String,
    pub command_room_root: String,
    pub checklist_root: String,
    pub signoff_root: String,
    pub acknowledged_release_freeze: bool,
    pub acknowledged_fail_closed: bool,
}

impl OwnerSignoff {
    pub fn devnet(role: OwnerRole, config: &Config, ordinal: u64) -> Self {
        let owner_label = format!("owner-{}", role.as_str().replace('_', "-"));
        let command_room_root = sample_root("command-room-owner", role.as_str(), ordinal);
        let checklist_root = sample_root("owner-checklist-view", role.as_str(), ordinal);
        let signoff_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-OPERATOR-COMMAND-CHECKLIST-OWNER-SIGNOFF",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.command_room_label),
                HashPart::Str(role.as_str()),
                HashPart::Str(&owner_label),
                HashPart::U64(config.checklist_height),
                HashPart::Str(&command_room_root),
                HashPart::Str(&checklist_root),
            ],
            32,
        );
        Self {
            role,
            owner_label,
            command_room_root,
            checklist_root,
            signoff_root,
            acknowledged_release_freeze: true,
            acknowledged_fail_closed: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "role": self.role.as_str(),
            "owner_label": self.owner_label,
            "command_room_root": self.command_room_root,
            "checklist_root": self.checklist_root,
            "signoff_root": self.signoff_root,
            "acknowledged_release_freeze": self.acknowledged_release_freeze,
            "acknowledged_fail_closed": self.acknowledged_fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("owner-signoff", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("owner label", &self.owner_label)?;
        ensure_non_empty("command room root", &self.command_room_root)?;
        ensure_non_empty("owner checklist root", &self.checklist_root)?;
        ensure_non_empty("owner signoff root", &self.signoff_root)?;
        ensure(
            self.acknowledged_release_freeze,
            "owner must acknowledge release freeze",
        )?;
        ensure(
            self.acknowledged_fail_closed,
            "owner must acknowledge fail-closed deployment authority",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeploymentAuthority {
    pub label: String,
    pub authority_root: String,
    pub release_freeze_root: String,
    pub blocker_root: String,
    pub production_deploy_allowed: bool,
    pub fail_closed: bool,
}

impl DeploymentAuthority {
    pub fn build(config: &Config, release_freeze_root: String, blocker_root: String) -> Self {
        let label = "fail-closed-deployment-authority".to_string();
        let authority_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-OPERATOR-COMMAND-CHECKLIST-DEPLOYMENT-AUTHORITY",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.command_room_label),
                HashPart::Str(&release_freeze_root),
                HashPart::Str(&blocker_root),
                HashPart::Json(&json!({
                    "allow_production_deploy": config.allow_production_deploy,
                    "require_fail_closed_deployment_authority": config.require_fail_closed_deployment_authority,
                })),
            ],
            32,
        );
        Self {
            label,
            authority_root,
            release_freeze_root,
            blocker_root,
            production_deploy_allowed: config.allow_production_deploy,
            fail_closed: config.require_fail_closed_deployment_authority
                || !config.allow_production_deploy,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "label": self.label,
            "authority_root": self.authority_root,
            "release_freeze_root": self.release_freeze_root,
            "blocker_root": self.blocker_root,
            "production_deploy_allowed": self.production_deploy_allowed,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("deployment-authority", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("deployment authority label", &self.label)?;
        ensure_non_empty("deployment authority root", &self.authority_root)?;
        ensure_non_empty("release freeze root", &self.release_freeze_root)?;
        ensure_non_empty("deployment blocker root", &self.blocker_root)?;
        ensure(self.fail_closed, "deployment authority must be fail-closed")?;
        ensure(
            !self.production_deploy_allowed,
            "deployment authority must not allow production deploy",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChecklistSummary {
    pub state: String,
    pub checklist_item_count: usize,
    pub satisfied_item_count: usize,
    pub release_freeze_item_count: usize,
    pub deferred_cargo_gate_count: usize,
    pub blocker_receipt_count: usize,
    pub owner_signoff_count: usize,
    pub blocker_count: usize,
    pub max_blocker_severity: u8,
    pub release_frozen: bool,
    pub fail_closed: bool,
    pub production_deploy_allowed: bool,
    pub checklist_package_root: String,
}

impl ChecklistSummary {
    pub fn build(
        config: &Config,
        checklist_items: &[ChecklistItem],
        blocker_receipts: &[BlockerReceipt],
        owner_signoffs: &[OwnerSignoff],
        blockers: &BTreeMap<String, Vec<BlockerKind>>,
        deployment_authority: &DeploymentAuthority,
    ) -> Self {
        let blocker_count = blockers.values().map(Vec::len).sum::<usize>();
        let max_blocker_severity = match blockers
            .values()
            .flat_map(|items| items.iter().map(|item| item.severity()))
            .max()
        {
            Some(severity) => severity,
            None => 0,
        };
        let release_freeze_item_count = checklist_items
            .iter()
            .filter(|item| item.release_freeze_item)
            .count();
        let deferred_cargo_gate_count = checklist_items
            .iter()
            .filter(|item| item.deferred_cargo_gate)
            .count();
        let satisfied_item_count = checklist_items.iter().filter(|item| item.satisfied).count();
        let release_frozen =
            config.require_release_freeze || release_freeze_item_count > 0 || blocker_count > 0;
        let fail_closed = deployment_authority.fail_closed || blocker_count > 0;
        let production_deploy_allowed =
            config.allow_production_deploy && !release_frozen && !fail_closed;
        let state = if production_deploy_allowed {
            "deploy_allowed"
        } else if fail_closed {
            "held_fail_closed"
        } else {
            "release_frozen"
        }
        .to_string();
        let checklist_package_root = roots_root(
            "operator-command-checklist-package",
            [
                roots_root(
                    "operator-command-checklist-items",
                    checklist_items.iter().map(ChecklistItem::state_root),
                ),
                roots_root(
                    "operator-command-checklist-blocker-receipts",
                    blocker_receipts.iter().map(BlockerReceipt::state_root),
                ),
                roots_root(
                    "operator-command-checklist-owner-signoffs",
                    owner_signoffs.iter().map(OwnerSignoff::state_root),
                ),
                blockers_root(blockers),
                deployment_authority.state_root(),
            ],
        );
        Self {
            state,
            checklist_item_count: checklist_items.len(),
            satisfied_item_count,
            release_freeze_item_count,
            deferred_cargo_gate_count,
            blocker_receipt_count: blocker_receipts.len(),
            owner_signoff_count: owner_signoffs.len(),
            blocker_count,
            max_blocker_severity,
            release_frozen,
            fail_closed,
            production_deploy_allowed,
            checklist_package_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "state": self.state,
            "checklist_item_count": self.checklist_item_count,
            "satisfied_item_count": self.satisfied_item_count,
            "release_freeze_item_count": self.release_freeze_item_count,
            "deferred_cargo_gate_count": self.deferred_cargo_gate_count,
            "blocker_receipt_count": self.blocker_receipt_count,
            "owner_signoff_count": self.owner_signoff_count,
            "blocker_count": self.blocker_count,
            "max_blocker_severity": self.max_blocker_severity,
            "release_frozen": self.release_frozen,
            "fail_closed": self.fail_closed,
            "production_deploy_allowed": self.production_deploy_allowed,
            "checklist_package_root": self.checklist_package_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("checklist-summary", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure(self.release_frozen, "summary must keep release frozen")?;
        ensure(self.fail_closed, "summary must be fail-closed")?;
        ensure(
            !self.production_deploy_allowed,
            "summary must not allow production deploy",
        )?;
        ensure_non_empty("checklist package root", &self.checklist_package_root)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub wave_86_roots: Wave86HandoffRoots,
    pub checklist_items: Vec<ChecklistItem>,
    pub blocker_receipts: Vec<BlockerReceipt>,
    pub owner_signoffs: Vec<OwnerSignoff>,
    pub blockers: BTreeMap<String, Vec<BlockerKind>>,
    pub checklist_item_root: String,
    pub blocker_receipt_root: String,
    pub owner_signoff_root: String,
    pub blocker_root: String,
    pub release_freeze_root: String,
    pub deployment_authority: DeploymentAuthority,
    pub summary: ChecklistSummary,
}

impl State {
    pub fn new(
        config: Config,
        wave_86_roots: Wave86HandoffRoots,
        checklist_items: Vec<ChecklistItem>,
        blocker_receipts: Vec<BlockerReceipt>,
        owner_signoffs: Vec<OwnerSignoff>,
    ) -> Result<Self> {
        config.validate()?;
        wave_86_roots.validate()?;
        ensure(
            !checklist_items.is_empty(),
            "state must include checklist items",
        )?;
        ensure(
            !blocker_receipts.is_empty(),
            "state must include blocker receipts",
        )?;
        ensure(
            !owner_signoffs.is_empty(),
            "state must include owner signoffs",
        )?;
        for item in &checklist_items {
            item.validate()?;
        }
        for receipt in &blocker_receipts {
            receipt.validate()?;
        }
        for signoff in &owner_signoffs {
            signoff.validate()?;
        }
        validate_unique_roots(
            "checklist receipt roots",
            checklist_items.iter().map(|item| &item.receipt_root),
        )?;
        validate_unique_roots(
            "blocker receipt roots",
            blocker_receipts.iter().map(|receipt| &receipt.blocker_root),
        )?;
        validate_unique_roots(
            "owner signoff roots",
            owner_signoffs.iter().map(|signoff| &signoff.signoff_root),
        )?;
        let blockers = evaluate_blockers(
            &config,
            &wave_86_roots,
            &checklist_items,
            &blocker_receipts,
            &owner_signoffs,
        );
        let checklist_item_root = roots_root(
            "operator-command-checklist-items",
            checklist_items.iter().map(ChecklistItem::state_root),
        );
        let blocker_receipt_root = roots_root(
            "operator-command-checklist-blocker-receipts",
            blocker_receipts.iter().map(BlockerReceipt::state_root),
        );
        let owner_signoff_root = roots_root(
            "operator-command-checklist-owner-signoffs",
            owner_signoffs.iter().map(OwnerSignoff::state_root),
        );
        let blocker_root = blockers_root(&blockers);
        let release_freeze_root = roots_root(
            "operator-command-checklist-release-freeze",
            checklist_items
                .iter()
                .filter(|item| item.release_freeze_item)
                .map(ChecklistItem::state_root),
        );
        let deployment_authority =
            DeploymentAuthority::build(&config, release_freeze_root.clone(), blocker_root.clone());
        deployment_authority.validate()?;
        let summary = ChecklistSummary::build(
            &config,
            &checklist_items,
            &blocker_receipts,
            &owner_signoffs,
            &blockers,
            &deployment_authority,
        );
        summary.validate()?;
        Ok(Self {
            config,
            wave_86_roots,
            checklist_items,
            blocker_receipts,
            owner_signoffs,
            blockers,
            checklist_item_root,
            blocker_receipt_root,
            owner_signoff_root,
            blocker_root,
            release_freeze_root,
            deployment_authority,
            summary,
        })
    }

    pub fn devnet() -> Self {
        match Self::try_devnet() {
            Ok(state) => state,
            Err(reason) => fallback_state(reason),
        }
    }

    pub fn try_devnet() -> Result<Self> {
        let config = Config::devnet();
        let wave_86_roots = Wave86HandoffRoots::devnet(&config);
        let checklist_items = ChecklistItemKind::all()
            .into_iter()
            .enumerate()
            .map(|(index, kind)| ChecklistItem::devnet(kind, &wave_86_roots, one_based(index)))
            .collect::<Vec<_>>();
        let blocker_receipts = [
            BlockerKind::ReleaseFreezeRequired,
            BlockerKind::CompileReceiptBlocksRelease,
            BlockerKind::DeferredCargoGatePending,
            BlockerKind::DeploymentAuthorityFailClosed,
            BlockerKind::ProductionDeployDisabled,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, kind)| BlockerReceipt::devnet(kind, one_based(index)))
        .collect::<Vec<_>>();
        let owner_signoffs = OwnerRole::all()
            .into_iter()
            .enumerate()
            .map(|(index, role)| OwnerSignoff::devnet(role, &config, one_based(index)))
            .collect::<Vec<_>>();
        Self::new(
            config,
            wave_86_roots,
            checklist_items,
            blocker_receipts,
            owner_signoffs,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "wave_86_roots": self.wave_86_roots.public_record(),
            "checklist_item_root": self.checklist_item_root,
            "blocker_receipt_root": self.blocker_receipt_root,
            "owner_signoff_root": self.owner_signoff_root,
            "blocker_root": self.blocker_root,
            "release_freeze_root": self.release_freeze_root,
            "deployment_authority": self.deployment_authority.public_record(),
            "summary": self.summary.public_record(),
            "checklist_items": self.checklist_items.iter().map(ChecklistItem::public_record).collect::<Vec<_>>(),
            "blocker_receipts": self.blocker_receipts.iter().map(BlockerReceipt::public_record).collect::<Vec<_>>(),
            "owner_signoffs": self.owner_signoffs.iter().map(OwnerSignoff::public_record).collect::<Vec<_>>(),
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
            "MONERO-L2-PQ-BRIDGE-OPERATOR-COMMAND-CHECKLIST-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.release_channel),
                HashPart::U64(self.config.release_epoch),
                HashPart::U64(self.config.checklist_height),
                HashPart::Str(&self.wave_86_roots.source_root),
                HashPart::Str(&self.summary.checklist_package_root),
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
    wave_86_roots: &Wave86HandoffRoots,
    checklist_items: &[ChecklistItem],
    blocker_receipts: &[BlockerReceipt],
    owner_signoffs: &[OwnerSignoff],
) -> BTreeMap<String, Vec<BlockerKind>> {
    let mut blockers = BTreeMap::<String, Vec<BlockerKind>>::new();
    let mut seen_kinds = BTreeSet::new();
    for item in checklist_items {
        seen_kinds.insert(item.kind);
        if item.deferred_cargo_gate {
            push_blocker(
                &mut blockers,
                item.kind.as_str(),
                BlockerKind::DeferredCargoGatePending,
            );
        }
        if !item.satisfied {
            push_blocker(
                &mut blockers,
                item.kind.as_str(),
                BlockerKind::CompileReceiptBlocksRelease,
            );
        }
    }
    if config.require_wave_86_handoff_roots && wave_86_roots.source_root.trim().is_empty() {
        push_blocker(
            &mut blockers,
            "wave_86_roots",
            BlockerKind::Wave86HandoffRootRequired,
        );
    }
    if config.require_release_freeze {
        push_blocker(
            &mut blockers,
            "release_freeze",
            BlockerKind::ReleaseFreezeRequired,
        );
    }
    if config.require_rustfmt_receipt && !seen_kinds.contains(&ChecklistItemKind::RustfmtReceipt) {
        push_blocker(&mut blockers, "rustfmt", BlockerKind::RustfmtReceiptMissing);
    }
    if config.require_compile_blocker_receipt
        && !seen_kinds.contains(&ChecklistItemKind::CompileBlockerReceipt)
    {
        push_blocker(
            &mut blockers,
            "compile_receipt",
            BlockerKind::CompileReceiptBlocksRelease,
        );
    }
    let release_freeze_item_count = checklist_items
        .iter()
        .filter(|item| item.release_freeze_item)
        .count();
    if release_freeze_item_count < usize::from(config.min_release_freeze_items) {
        push_blocker(
            &mut blockers,
            "release_freeze",
            BlockerKind::ReleaseFreezeRequired,
        );
    }
    if checklist_items.len() < usize::from(config.min_checklist_items) {
        push_blocker(
            &mut blockers,
            "checklist_items",
            BlockerKind::ReleaseFreezeRequired,
        );
    }
    if blocker_receipts.len() < usize::from(config.min_blocker_receipts) {
        push_blocker(
            &mut blockers,
            "blocker_receipts",
            BlockerKind::CompileReceiptBlocksRelease,
        );
    }
    if config.require_command_room_owner_signoffs
        && owner_signoffs.len() < usize::from(config.min_owner_signoffs)
    {
        push_blocker(
            &mut blockers,
            "owner_signoffs",
            BlockerKind::OwnerSignoffQuorumMissing,
        );
    }
    if config.require_fail_closed_deployment_authority {
        push_blocker(
            &mut blockers,
            "deployment_authority",
            BlockerKind::DeploymentAuthorityFailClosed,
        );
    }
    if !config.allow_production_deploy {
        push_blocker(
            &mut blockers,
            "production_deploy",
            BlockerKind::ProductionDeployDisabled,
        );
    }
    blockers
}

fn fallback_state(reason: String) -> State {
    let config = Config::default();
    let wave_86_roots = Wave86HandoffRoots::devnet(&config);
    let checklist_items = vec![ChecklistItem::devnet(
        ChecklistItemKind::DeploymentAuthorityHold,
        &wave_86_roots,
        1,
    )];
    let blocker_receipts = vec![BlockerReceipt::devnet(
        BlockerKind::DeploymentAuthorityFailClosed,
        1,
    )];
    let owner_signoffs = vec![OwnerSignoff::devnet(
        OwnerRole::DeploymentAuthority,
        &config,
        1,
    )];
    let mut blockers = evaluate_blockers(
        &config,
        &wave_86_roots,
        &checklist_items,
        &blocker_receipts,
        &owner_signoffs,
    );
    push_blocker(
        &mut blockers,
        "fallback",
        BlockerKind::DeploymentAuthorityFailClosed,
    );
    if !reason.trim().is_empty() {
        push_blocker(
            &mut blockers,
            "fallback_reason",
            BlockerKind::ProductionDeployDisabled,
        );
    }
    let checklist_item_root = roots_root(
        "operator-command-checklist-items",
        checklist_items.iter().map(ChecklistItem::state_root),
    );
    let blocker_receipt_root = roots_root(
        "operator-command-checklist-blocker-receipts",
        blocker_receipts.iter().map(BlockerReceipt::state_root),
    );
    let owner_signoff_root = roots_root(
        "operator-command-checklist-owner-signoffs",
        owner_signoffs.iter().map(OwnerSignoff::state_root),
    );
    let blocker_root = blockers_root(&blockers);
    let release_freeze_root = roots_root(
        "operator-command-checklist-release-freeze",
        checklist_items
            .iter()
            .filter(|item| item.release_freeze_item)
            .map(ChecklistItem::state_root),
    );
    let deployment_authority =
        DeploymentAuthority::build(&config, release_freeze_root.clone(), blocker_root.clone());
    let summary = ChecklistSummary::build(
        &config,
        &checklist_items,
        &blocker_receipts,
        &owner_signoffs,
        &blockers,
        &deployment_authority,
    );
    State {
        config,
        wave_86_roots,
        checklist_items,
        blocker_receipts,
        owner_signoffs,
        blockers,
        checklist_item_root,
        blocker_receipt_root,
        owner_signoff_root,
        blocker_root,
        release_freeze_root,
        deployment_authority,
        summary,
    }
}

fn push_blocker(
    blockers: &mut BTreeMap<String, Vec<BlockerKind>>,
    subject: &str,
    blocker: BlockerKind,
) {
    blockers
        .entry(subject.to_string())
        .or_default()
        .push(blocker);
}

fn validate_unique_roots<'a, I>(label: &str, roots: I) -> Result<()>
where
    I: IntoIterator<Item = &'a String>,
{
    let mut seen = BTreeSet::new();
    for root in roots {
        ensure_non_empty(label, root)?;
        ensure(seen.insert(root), &format!("{label} must be unique"))?;
    }
    Ok(())
}

fn blockers_root(blockers: &BTreeMap<String, Vec<BlockerKind>>) -> String {
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
