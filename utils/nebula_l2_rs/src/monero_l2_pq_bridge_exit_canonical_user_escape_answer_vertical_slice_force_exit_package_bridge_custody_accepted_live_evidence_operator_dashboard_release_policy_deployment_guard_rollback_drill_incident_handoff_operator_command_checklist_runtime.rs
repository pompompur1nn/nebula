use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageBridgeCustodyAcceptedLiveEvidenceOperatorDashboardReleasePolicyDeploymentGuardRollbackDrillIncidentHandoffOperatorCommandChecklistRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_BRIDGE_CUSTODY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_INCIDENT_HANDOFF_OPERATOR_COMMAND_CHECKLIST_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-bridge-custody-accepted-live-evidence-operator-dashboard-release-policy-deployment-guard-rollback-drill-incident-handoff-operator-command-checklist-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_BRIDGE_CUSTODY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_INCIDENT_HANDOFF_OPERATOR_COMMAND_CHECKLIST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const OPERATOR_COMMAND_CHECKLIST_SUITE: &str =
    "monero-l2-pq-bridge-custody-operator-command-checklist-v1";
pub const DEFAULT_WAVE: u64 = 87;
pub const DEFAULT_SOURCE_WAVE: u64 = 86;
pub const DEFAULT_HANDOFF_HEIGHT: u64 = 1_445_376;
pub const DEFAULT_MAX_SOURCE_HANDOFF_AGE_BLOCKS: u64 = 96;
pub const DEFAULT_MIN_CHECKLIST_ITEM_COUNT: u64 = 3;
pub const DEFAULT_MIN_RELEASE_CAP_COUNT: u64 = 3;
pub const DEFAULT_MIN_RESERVE_LIABILITY_COUNT: u64 = 3;
pub const DEFAULT_MIN_SIGNER_ACKNOWLEDGEMENT_COUNT: u64 = 4;
pub const DEFAULT_MIN_SIGNER_ACKNOWLEDGEMENT_WEIGHT: u64 = 67;
pub const DEFAULT_MIN_RELEASE_AUTHORITY_COUNT: u64 = 3;

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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistItemKind {
    CustodyTransferAccepted,
    ReserveLiabilityMatched,
    ReleaseCapsDrilled,
    SignerCustodyAcknowledged,
}

impl ChecklistItemKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CustodyTransferAccepted => "custody_transfer_accepted",
            Self::ReserveLiabilityMatched => "reserve_liability_matched",
            Self::ReleaseCapsDrilled => "release_caps_drilled",
            Self::SignerCustodyAcknowledged => "signer_custody_acknowledged",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseCapKind {
    PerIncidentCap,
    PerEpochCap,
    SignerOverrideCap,
    ManualReleaseCap,
}

impl ReleaseCapKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PerIncidentCap => "per_incident_cap",
            Self::PerEpochCap => "per_epoch_cap",
            Self::SignerOverrideCap => "signer_override_cap",
            Self::ManualReleaseCap => "manual_release_cap",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityRole {
    CustodyLead,
    IncidentCommander,
    ReleaseCoordinator,
    ReserveOperator,
    SignerQuorum,
}

impl AuthorityRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CustodyLead => "custody_lead",
            Self::IncidentCommander => "incident_commander",
            Self::ReleaseCoordinator => "release_coordinator",
            Self::ReserveOperator => "reserve_operator",
            Self::SignerQuorum => "signer_quorum",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistBlockerKind {
    SourceHandoffRootMissing,
    SourceHandoffStale,
    SourceHandoffNotFailClosed,
    ChecklistItemRootMissing,
    ReleaseCapRootMissing,
    ReleaseCapExceeded,
    ReserveLiabilityRootMissing,
    ReserveLiabilityMismatch,
    SignerCustodyAcknowledgementQuorumLow,
    SignerCustodyAcknowledgementWeightLow,
    BridgeReleaseAuthorityMissing,
    BridgeReleaseAuthorityOpen,
    ChecklistVerdictRejected,
}

impl ChecklistBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceHandoffRootMissing => "source_handoff_root_missing",
            Self::SourceHandoffStale => "source_handoff_stale",
            Self::SourceHandoffNotFailClosed => "source_handoff_not_fail_closed",
            Self::ChecklistItemRootMissing => "checklist_item_root_missing",
            Self::ReleaseCapRootMissing => "release_cap_root_missing",
            Self::ReleaseCapExceeded => "release_cap_exceeded",
            Self::ReserveLiabilityRootMissing => "reserve_liability_root_missing",
            Self::ReserveLiabilityMismatch => "reserve_liability_mismatch",
            Self::SignerCustodyAcknowledgementQuorumLow => "signer_acknowledgement_quorum_low",
            Self::SignerCustodyAcknowledgementWeightLow => "signer_acknowledgement_weight_low",
            Self::BridgeReleaseAuthorityMissing => "bridge_release_authority_missing",
            Self::BridgeReleaseAuthorityOpen => "bridge_release_authority_open",
            Self::ChecklistVerdictRejected => "checklist_verdict_rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub operator_command_checklist_suite: String,
    pub operator_command_checklist_id: String,
    pub source_handoff_id: String,
    pub bridge_custody_lane_id: String,
    pub release_policy_id: String,
    pub wave: u64,
    pub source_wave: u64,
    pub handoff_height: u64,
    pub max_source_handoff_age_blocks: u64,
    pub min_checklist_item_count: u64,
    pub min_release_cap_count: u64,
    pub min_reserve_liability_count: u64,
    pub min_signer_acknowledgement_count: u64,
    pub min_signer_acknowledgement_weight: u64,
    pub min_release_authorities: u64,
    pub require_source_handoff_fail_closed: bool,
    pub require_release_caps_zeroed: bool,
    pub require_reserve_liability_match: bool,
    pub require_signer_custody_acknowledgements: bool,
    pub require_bridge_release_authority_closed: bool,
    pub fail_closed: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            operator_command_checklist_suite: OPERATOR_COMMAND_CHECKLIST_SUITE.to_string(),
            operator_command_checklist_id: runtime_id(
                "wave-87-bridge-custody-operator-command-checklist",
            ),
            source_handoff_id: runtime_id("wave-86-bridge-custody-incident-handoff"),
            bridge_custody_lane_id: "bridge_custody".to_string(),
            release_policy_id: runtime_id("force-exit-package-bridge-custody-release-policy"),
            wave: DEFAULT_WAVE,
            source_wave: DEFAULT_SOURCE_WAVE,
            handoff_height: DEFAULT_HANDOFF_HEIGHT,
            max_source_handoff_age_blocks: DEFAULT_MAX_SOURCE_HANDOFF_AGE_BLOCKS,
            min_checklist_item_count: DEFAULT_MIN_CHECKLIST_ITEM_COUNT,
            min_release_cap_count: DEFAULT_MIN_RELEASE_CAP_COUNT,
            min_reserve_liability_count: DEFAULT_MIN_RESERVE_LIABILITY_COUNT,
            min_signer_acknowledgement_count: DEFAULT_MIN_SIGNER_ACKNOWLEDGEMENT_COUNT,
            min_signer_acknowledgement_weight: DEFAULT_MIN_SIGNER_ACKNOWLEDGEMENT_WEIGHT,
            min_release_authorities: DEFAULT_MIN_RELEASE_AUTHORITY_COUNT,
            require_source_handoff_fail_closed: true,
            require_release_caps_zeroed: true,
            require_reserve_liability_match: true,
            require_signer_custody_acknowledgements: true,
            require_bridge_release_authority_closed: true,
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
        ensure_non_empty(
            "operator_command_checklist_suite",
            &self.operator_command_checklist_suite,
        )?;
        ensure_non_empty(
            "operator_command_checklist_id",
            &self.operator_command_checklist_id,
        )?;
        ensure_non_empty("source_handoff_id", &self.source_handoff_id)?;
        ensure_non_empty("bridge_custody_lane_id", &self.bridge_custody_lane_id)?;
        ensure_non_empty("release_policy_id", &self.release_policy_id)?;
        ensure(
            self.wave > self.source_wave,
            "handoff wave must follow source wave",
        )?;
        ensure(self.handoff_height > 0, "handoff height must be non-zero")?;
        ensure(
            self.max_source_handoff_age_blocks > 0,
            "handoff age window must be non-zero",
        )?;
        ensure(
            self.min_checklist_item_count > 0,
            "checklist item threshold must be non-zero",
        )?;
        ensure(
            self.min_release_cap_count > 0,
            "release cap threshold must be non-zero",
        )?;
        ensure(
            self.min_reserve_liability_count > 0,
            "reserve liability threshold must be non-zero",
        )?;
        ensure(
            self.min_signer_acknowledgement_count > 0,
            "signer receipt threshold must be non-zero",
        )?;
        ensure(
            self.min_signer_acknowledgement_weight > 0,
            "signer receipt weight must be non-zero",
        )?;
        ensure(
            self.min_release_authorities > 0,
            "release authority threshold must be non-zero",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "operator_command_checklist_suite": self.operator_command_checklist_suite,
            "operator_command_checklist_id": self.operator_command_checklist_id,
            "source_handoff_id": self.source_handoff_id,
            "bridge_custody_lane_id": self.bridge_custody_lane_id,
            "release_policy_id": self.release_policy_id,
            "wave": self.wave,
            "source_wave": self.source_wave,
            "handoff_height": self.handoff_height,
            "max_source_handoff_age_blocks": self.max_source_handoff_age_blocks,
            "min_checklist_item_count": self.min_checklist_item_count,
            "min_release_cap_count": self.min_release_cap_count,
            "min_reserve_liability_count": self.min_reserve_liability_count,
            "min_signer_acknowledgement_count": self.min_signer_acknowledgement_count,
            "min_signer_acknowledgement_weight": self.min_signer_acknowledgement_weight,
            "min_release_authorities": self.min_release_authorities,
            "require_source_handoff_fail_closed": self.require_source_handoff_fail_closed,
            "require_release_caps_zeroed": self.require_release_caps_zeroed,
            "require_reserve_liability_match": self.require_reserve_liability_match,
            "require_signer_custody_acknowledgements": self.require_signer_custody_acknowledgements,
            "require_bridge_release_authority_closed": self.require_bridge_release_authority_closed,
            "fail_closed": self.fail_closed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("OPERATOR-COMMAND-CHECKLIST-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceHandoffRoots {
    pub handoff_id: String,
    pub observed_height: u64,
    pub handoff_state_root: String,
    pub custody_transfer_root: String,
    pub release_cap_drill_root: String,
    pub reserve_liability_root: String,
    pub operator_command_root: String,
    pub handoff_fail_closed_root: String,
    pub fail_closed: bool,
    pub status: EvidenceStatus,
}

impl SourceHandoffRoots {
    pub fn devnet(config: &Config) -> Self {
        let observed_height = config.handoff_height.saturating_sub(24);
        let custody_transfer_root = source_component_root(config, "custody-transfer");
        let release_cap_drill_root = source_component_root(config, "release-cap-drill");
        let reserve_liability_root = source_component_root(config, "reserve-liability");
        let operator_command_root = source_component_root(config, "operator-command");
        let handoff_fail_closed_root = source_component_root(config, "fail-closed");
        let handoff_state_root = merkle_root(
            "OPERATOR-COMMAND-CHECKLIST-SOURCE-HANDOFF",
            &[
                json!({"custody_transfer_root": custody_transfer_root}),
                json!({"release_cap_drill_root": release_cap_drill_root}),
                json!({"reserve_liability_root": reserve_liability_root}),
                json!({"operator_command_root": operator_command_root}),
                json!({"handoff_fail_closed_root": handoff_fail_closed_root}),
            ],
        );
        Self {
            handoff_id: config.source_handoff_id.clone(),
            observed_height,
            handoff_state_root,
            custody_transfer_root,
            release_cap_drill_root,
            reserve_liability_root,
            operator_command_root,
            handoff_fail_closed_root,
            fail_closed: true,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.status.accepted()
            && !self.handoff_state_root.is_empty()
            && !self.handoff_fail_closed_root.is_empty()
            && (!config.require_source_handoff_fail_closed || self.fail_closed)
            && config.handoff_height.saturating_sub(self.observed_height)
                <= config.max_source_handoff_age_blocks
    }

    pub fn public_record(&self) -> Value {
        json!({
            "handoff_id": self.handoff_id,
            "observed_height": self.observed_height,
            "handoff_state_root": self.handoff_state_root,
            "custody_transfer_root": self.custody_transfer_root,
            "release_cap_drill_root": self.release_cap_drill_root,
            "reserve_liability_root": self.reserve_liability_root,
            "operator_command_root": self.operator_command_root,
            "handoff_fail_closed_root": self.handoff_fail_closed_root,
            "fail_closed": self.fail_closed,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "OPERATOR-COMMAND-CHECKLIST-SOURCE-HANDOFF-STATE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChecklistItem {
    pub item_id: String,
    pub item_kind: ChecklistItemKind,
    pub checklist_item_root: String,
    pub source_handoff_root: String,
    pub operator_ack_root: String,
    pub enforced: bool,
    pub status: EvidenceStatus,
}

impl ChecklistItem {
    pub fn devnet(config: &Config, ordinal: u64, item_kind: ChecklistItemKind) -> Self {
        let item_id = evidence_id(config, "checklist-item", item_kind.as_str(), ordinal);
        let checklist_item_root = component_root(config, "checklist-item", &item_id);
        let source_handoff_root = component_root(config, "handoff", &item_id);
        let operator_ack_root = component_root(config, "dashboard-ack", &item_id);
        Self {
            item_id,
            item_kind,
            checklist_item_root,
            source_handoff_root,
            operator_ack_root,
            enforced: true,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self) -> bool {
        self.status.accepted()
            && self.enforced
            && !self.checklist_item_root.is_empty()
            && !self.source_handoff_root.is_empty()
            && !self.operator_ack_root.is_empty()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "item_id": self.item_id,
            "item_kind": self.item_kind.as_str(),
            "checklist_item_root": self.checklist_item_root,
            "source_handoff_root": self.source_handoff_root,
            "operator_ack_root": self.operator_ack_root,
            "enforced": self.enforced,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "OPERATOR-COMMAND-CHECKLIST-CHECKLIST-ITEM",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseCap {
    pub cap_id: String,
    pub cap_kind: ReleaseCapKind,
    pub cap_limit_atomic_units: u64,
    pub consumed_atomic_units: u64,
    pub cap_root: String,
    pub policy_binding_root: String,
    pub status: EvidenceStatus,
}

impl ReleaseCap {
    pub fn devnet(config: &Config, ordinal: u64, cap_kind: ReleaseCapKind) -> Self {
        let cap_id = evidence_id(config, "release-cap", cap_kind.as_str(), ordinal);
        let cap_root = component_root(config, "release-cap", &cap_id);
        let policy_binding_root = component_root(config, "policy-binding", &cap_id);
        Self {
            cap_id,
            cap_kind,
            cap_limit_atomic_units: 0,
            consumed_atomic_units: 0,
            cap_root,
            policy_binding_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.status.accepted()
            && !self.cap_root.is_empty()
            && !self.policy_binding_root.is_empty()
            && (!config.require_release_caps_zeroed
                || self.consumed_atomic_units <= self.cap_limit_atomic_units)
            && (!config.require_release_caps_zeroed || self.cap_limit_atomic_units == 0)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "cap_kind": self.cap_kind.as_str(),
            "cap_limit_atomic_units": self.cap_limit_atomic_units,
            "consumed_atomic_units": self.consumed_atomic_units,
            "cap_root": self.cap_root,
            "policy_binding_root": self.policy_binding_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "OPERATOR-COMMAND-CHECKLIST-RELEASE-CAP",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveLiabilityRoot {
    pub liability_id: String,
    pub reserve_operator_id: String,
    pub reserve_root: String,
    pub liability_root: String,
    pub checklist_item_root: String,
    pub balance_matches_liability: bool,
    pub status: EvidenceStatus,
}

impl ReserveLiabilityRoot {
    pub fn devnet(config: &Config, ordinal: u64, reserve_operator_id: &str) -> Self {
        let liability_id = evidence_id(config, "reserve-liability", reserve_operator_id, ordinal);
        let reserve_root = component_root(config, "reserve-root", &liability_id);
        let liability_root = component_root(config, "liability-root", &liability_id);
        let checklist_item_root = component_root(config, "checklist-item-root", &liability_id);
        Self {
            liability_id,
            reserve_operator_id: reserve_operator_id.to_string(),
            reserve_root,
            liability_root,
            checklist_item_root,
            balance_matches_liability: true,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.status.accepted()
            && !self.reserve_root.is_empty()
            && !self.liability_root.is_empty()
            && !self.checklist_item_root.is_empty()
            && (!config.require_reserve_liability_match || self.balance_matches_liability)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "liability_id": self.liability_id,
            "reserve_operator_id": self.reserve_operator_id,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
            "checklist_item_root": self.checklist_item_root,
            "balance_matches_liability": self.balance_matches_liability,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "OPERATOR-COMMAND-CHECKLIST-RESERVE-LIABILITY",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignerCustodyAcknowledgement {
    pub receipt_id: String,
    pub signer_id: String,
    pub signer_weight: u64,
    pub custody_acknowledgement_root: String,
    pub checklist_item_ack_root: String,
    pub command_revoke_root: String,
    pub accepted_live_evidence_root: String,
    pub status: EvidenceStatus,
}

impl SignerCustodyAcknowledgement {
    pub fn devnet(config: &Config, ordinal: u64, signer_id: &str, signer_weight: u64) -> Self {
        let receipt_id = evidence_id(config, "signer-custody-acknowledgement", signer_id, ordinal);
        let custody_acknowledgement_root =
            component_root(config, "signer-custody-acknowledgement", &receipt_id);
        let checklist_item_ack_root = component_root(config, "checklist-item-ack", &receipt_id);
        let command_revoke_root = component_root(config, "command-revoke", &receipt_id);
        let accepted_live_evidence_root =
            component_root(config, "accepted-live-evidence", &receipt_id);
        Self {
            receipt_id,
            signer_id: signer_id.to_string(),
            signer_weight,
            custody_acknowledgement_root,
            checklist_item_ack_root,
            command_revoke_root,
            accepted_live_evidence_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self) -> bool {
        self.status.accepted()
            && self.signer_weight > 0
            && !self.custody_acknowledgement_root.is_empty()
            && !self.checklist_item_ack_root.is_empty()
            && !self.command_revoke_root.is_empty()
            && !self.accepted_live_evidence_root.is_empty()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "signer_id": self.signer_id,
            "signer_weight": self.signer_weight,
            "custody_acknowledgement_root": self.custody_acknowledgement_root,
            "checklist_item_ack_root": self.checklist_item_ack_root,
            "command_revoke_root": self.command_revoke_root,
            "accepted_live_evidence_root": self.accepted_live_evidence_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "OPERATOR-COMMAND-CHECKLIST-SIGNER-CUSTODY-ACK",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeReleaseAuthority {
    pub authority_id: String,
    pub from_role: AuthorityRole,
    pub to_role: AuthorityRole,
    pub revocation_root: String,
    pub acceptance_root: String,
    pub dashboard_release_authority_root: String,
    pub bridge_pause_asserted: bool,
    pub status: EvidenceStatus,
}

impl BridgeReleaseAuthority {
    pub fn devnet(
        config: &Config,
        ordinal: u64,
        from_role: AuthorityRole,
        to_role: AuthorityRole,
    ) -> Self {
        let subject = format!("{}-{}", from_role.as_str(), to_role.as_str());
        let authority_id = evidence_id(config, "command-release-authority", &subject, ordinal);
        let revocation_root = component_root(config, "authority-revocation", &authority_id);
        let acceptance_root = component_root(config, "authority-acceptance", &authority_id);
        let dashboard_release_authority_root =
            component_root(config, "dashboard-release-authority", &authority_id);
        Self {
            authority_id,
            from_role,
            to_role,
            revocation_root,
            acceptance_root,
            dashboard_release_authority_root,
            bridge_pause_asserted: true,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn accepted(&self, config: &Config) -> bool {
        self.status.accepted()
            && !self.revocation_root.is_empty()
            && !self.acceptance_root.is_empty()
            && !self.dashboard_release_authority_root.is_empty()
            && (!config.require_bridge_release_authority_closed || self.bridge_pause_asserted)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "authority_id": self.authority_id,
            "from_role": self.from_role.as_str(),
            "to_role": self.to_role.as_str(),
            "revocation_root": self.revocation_root,
            "acceptance_root": self.acceptance_root,
            "dashboard_release_authority_root": self.dashboard_release_authority_root,
            "bridge_pause_asserted": self.bridge_pause_asserted,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "OPERATOR-COMMAND-CHECKLIST-RELEASE-AUTHORITY",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChecklistBlocker {
    pub blocker_id: String,
    pub kind: ChecklistBlockerKind,
    pub subject: String,
    pub evidence_root: String,
}

impl ChecklistBlocker {
    pub fn new(
        config: &Config,
        kind: ChecklistBlockerKind,
        subject: &str,
        evidence_root: &str,
    ) -> Self {
        let blocker_id = domain_hash(
            "OPERATOR-COMMAND-CHECKLIST-BLOCKER-ID",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.operator_command_checklist_id),
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
        record_root("OPERATOR-COMMAND-CHECKLIST-BLOCKER", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChecklistVerdict {
    pub operator_command_checklist_id: String,
    pub checklist_item_count: u64,
    pub release_cap_count: u64,
    pub reserve_liability_count: u64,
    pub signer_acknowledgement_count: u64,
    pub signer_acknowledgement_weight: u64,
    pub release_authority_count: u64,
    pub evidence_root: String,
    pub blocker_root: String,
    pub fail_closed: bool,
    pub accepted: bool,
}

impl ChecklistVerdict {
    pub fn from_state(config: &Config, state: &State, blockers: &[ChecklistBlocker]) -> Self {
        let evidence_root = state.evidence_root();
        let blocker_root = list_root(
            "OPERATOR-COMMAND-CHECKLIST-BLOCKER-ROOT",
            blockers.iter().map(ChecklistBlocker::state_root),
        );
        let accepted = config.fail_closed && blockers.is_empty();
        Self {
            operator_command_checklist_id: config.operator_command_checklist_id.clone(),
            checklist_item_count: state.checklist_item_count(),
            release_cap_count: state.release_cap_count(config),
            reserve_liability_count: state.reserve_liability_count(config),
            signer_acknowledgement_count: state.signer_acknowledgement_count(),
            signer_acknowledgement_weight: state.signer_acknowledgement_weight(),
            release_authority_count: state.release_authority_count(config),
            evidence_root,
            blocker_root,
            fail_closed: config.fail_closed && !accepted,
            accepted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "operator_command_checklist_id": self.operator_command_checklist_id,
            "checklist_item_count": self.checklist_item_count,
            "release_cap_count": self.release_cap_count,
            "reserve_liability_count": self.reserve_liability_count,
            "signer_acknowledgement_count": self.signer_acknowledgement_count,
            "signer_acknowledgement_weight": self.signer_acknowledgement_weight,
            "release_authority_count": self.release_authority_count,
            "evidence_root": self.evidence_root,
            "blocker_root": self.blocker_root,
            "fail_closed": self.fail_closed,
            "accepted": self.accepted,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("OPERATOR-COMMAND-CHECKLIST-VERDICT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub source_handoff_roots: SourceHandoffRoots,
    pub checklist_items: Vec<ChecklistItem>,
    pub release_caps: Vec<ReleaseCap>,
    pub reserve_liability_roots: Vec<ReserveLiabilityRoot>,
    pub signer_custody_acknowledgements: Vec<SignerCustodyAcknowledgement>,
    pub bridge_release_authorities: Vec<BridgeReleaseAuthority>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        Self {
            source_handoff_roots: SourceHandoffRoots::devnet(&config),
            checklist_items: vec![
                ChecklistItem::devnet(&config, 1, ChecklistItemKind::CustodyTransferAccepted),
                ChecklistItem::devnet(&config, 2, ChecklistItemKind::ReserveLiabilityMatched),
                ChecklistItem::devnet(&config, 3, ChecklistItemKind::ReleaseCapsDrilled),
                ChecklistItem::devnet(&config, 4, ChecklistItemKind::SignerCustodyAcknowledged),
            ],
            release_caps: vec![
                ReleaseCap::devnet(&config, 1, ReleaseCapKind::PerIncidentCap),
                ReleaseCap::devnet(&config, 2, ReleaseCapKind::PerEpochCap),
                ReleaseCap::devnet(&config, 3, ReleaseCapKind::SignerOverrideCap),
                ReleaseCap::devnet(&config, 4, ReleaseCapKind::ManualReleaseCap),
            ],
            reserve_liability_roots: vec![
                ReserveLiabilityRoot::devnet(&config, 1, "reserve-operator-alpha"),
                ReserveLiabilityRoot::devnet(&config, 2, "reserve-operator-bravo"),
                ReserveLiabilityRoot::devnet(&config, 3, "reserve-operator-charlie"),
            ],
            signer_custody_acknowledgements: vec![
                SignerCustodyAcknowledgement::devnet(&config, 1, "custody-signer-alpha", 18),
                SignerCustodyAcknowledgement::devnet(&config, 2, "custody-signer-bravo", 17),
                SignerCustodyAcknowledgement::devnet(&config, 3, "custody-signer-charlie", 16),
                SignerCustodyAcknowledgement::devnet(&config, 4, "custody-signer-delta", 16),
                SignerCustodyAcknowledgement::devnet(&config, 5, "custody-signer-echo", 8),
            ],
            bridge_release_authorities: vec![
                BridgeReleaseAuthority::devnet(
                    &config,
                    1,
                    AuthorityRole::ReleaseCoordinator,
                    AuthorityRole::IncidentCommander,
                ),
                BridgeReleaseAuthority::devnet(
                    &config,
                    2,
                    AuthorityRole::CustodyLead,
                    AuthorityRole::SignerQuorum,
                ),
                BridgeReleaseAuthority::devnet(
                    &config,
                    3,
                    AuthorityRole::ReserveOperator,
                    AuthorityRole::IncidentCommander,
                ),
            ],
            config,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure(
            self.source_handoff_roots.accepted(&self.config),
            "source handoff is not accepted fail-closed source evidence",
        )?;
        ensure(
            self.checklist_item_count() >= self.config.min_checklist_item_count,
            "checklist item count is below threshold",
        )?;
        ensure(
            self.release_cap_count(&self.config) >= self.config.min_release_cap_count,
            "release cap count is below threshold",
        )?;
        ensure(
            self.reserve_liability_count(&self.config) >= self.config.min_reserve_liability_count,
            "reserve liability root count is below threshold",
        )?;
        ensure(
            self.signer_acknowledgement_count() >= self.config.min_signer_acknowledgement_count,
            "signer custody acknowledgement quorum is below threshold",
        )?;
        ensure(
            self.signer_acknowledgement_weight() >= self.config.min_signer_acknowledgement_weight,
            "signer custody acknowledgement weight is below threshold",
        )?;
        ensure(
            self.release_authority_count(&self.config) >= self.config.min_release_authorities,
            "bridge release authority count is below threshold",
        )?;
        ensure(
            self.blockers().is_empty(),
            "operator command checklist is fail-closed by command checklist blockers",
        )?;
        Ok(())
    }

    pub fn checklist_item_count(&self) -> u64 {
        self.checklist_items
            .iter()
            .filter(|hold| hold.accepted())
            .count() as u64
    }

    pub fn release_cap_count(&self, config: &Config) -> u64 {
        self.release_caps
            .iter()
            .filter(|cap| cap.accepted(config))
            .count() as u64
    }

    pub fn reserve_liability_count(&self, config: &Config) -> u64 {
        self.reserve_liability_roots
            .iter()
            .filter(|root| root.accepted(config))
            .count() as u64
    }

    pub fn signer_acknowledgement_count(&self) -> u64 {
        self.signer_custody_acknowledgements
            .iter()
            .filter(|receipt| receipt.accepted())
            .count() as u64
    }

    pub fn signer_acknowledgement_weight(&self) -> u64 {
        self.signer_custody_acknowledgements
            .iter()
            .filter(|receipt| receipt.accepted())
            .map(|receipt| receipt.signer_weight)
            .sum()
    }

    pub fn release_authority_count(&self, config: &Config) -> u64 {
        self.bridge_release_authorities
            .iter()
            .filter(|authority| authority.accepted(config))
            .count() as u64
    }

    pub fn evidence_root(&self) -> String {
        merkle_root(
            "OPERATOR-COMMAND-CHECKLIST-EVIDENCE-ROOT",
            &[
                json!({"config_root": self.config.state_root()}),
                json!({"source_handoff_roots_root": self.source_handoff_roots.state_root()}),
                json!({"checklist_item_root": list_root("OPERATOR-COMMAND-CHECKLIST-CHECKLIST-ITEM-ROOT", self.checklist_items.iter().map(ChecklistItem::state_root))}),
                json!({"release_cap_root": list_root("OPERATOR-COMMAND-CHECKLIST-RELEASE-CAP-ROOT", self.release_caps.iter().map(ReleaseCap::state_root))}),
                json!({"reserve_liability_root": list_root("OPERATOR-COMMAND-CHECKLIST-RESERVE-LIABILITY-ROOT", self.reserve_liability_roots.iter().map(ReserveLiabilityRoot::state_root))}),
                json!({"signer_acknowledgement_root": list_root("OPERATOR-COMMAND-CHECKLIST-SIGNER-CUSTODY-ACK-ROOT", self.signer_custody_acknowledgements.iter().map(SignerCustodyAcknowledgement::state_root))}),
                json!({"authority_authority_root": list_root("OPERATOR-COMMAND-CHECKLIST-AUTHORITY-ROOT", self.bridge_release_authorities.iter().map(BridgeReleaseAuthority::state_root))}),
            ],
        )
    }

    pub fn blockers(&self) -> Vec<ChecklistBlocker> {
        unique_blockers(&self.config, self.blocker_kinds(), &self.evidence_root())
    }

    pub fn verdict(&self) -> ChecklistVerdict {
        let blockers = self.blockers();
        ChecklistVerdict::from_state(&self.config, self, &blockers)
    }

    pub fn public_record(&self) -> Value {
        let blockers = self.blockers();
        let verdict = ChecklistVerdict::from_state(&self.config, self, &blockers);
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "source_handoff_roots": self.source_handoff_roots.public_record(),
            "checklist_items": self.checklist_items.iter().map(ChecklistItem::public_record).collect::<Vec<_>>(),
            "release_caps": self.release_caps.iter().map(ReleaseCap::public_record).collect::<Vec<_>>(),
            "reserve_liability_roots": self.reserve_liability_roots.iter().map(ReserveLiabilityRoot::public_record).collect::<Vec<_>>(),
            "signer_custody_acknowledgements": self.signer_custody_acknowledgements.iter().map(SignerCustodyAcknowledgement::public_record).collect::<Vec<_>>(),
            "bridge_release_authorities": self.bridge_release_authorities.iter().map(BridgeReleaseAuthority::public_record).collect::<Vec<_>>(),
            "evidence_root": self.evidence_root(),
            "blockers": blockers.iter().map(ChecklistBlocker::public_record).collect::<Vec<_>>(),
            "verdict": verdict.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "OPERATOR-COMMAND-CHECKLIST-STATE",
            &json!({
                "config_root": self.config.state_root(),
                "evidence_root": self.evidence_root(),
                "verdict_root": self.verdict().state_root(),
            }),
        )
    }

    fn blocker_kinds(&self) -> Vec<(ChecklistBlockerKind, String)> {
        let mut blockers = Vec::new();
        if !self.source_handoff_roots.accepted(&self.config) {
            if self.source_handoff_roots.handoff_state_root.is_empty() {
                blockers.push((
                    ChecklistBlockerKind::SourceHandoffRootMissing,
                    "source_handoff_roots".to_string(),
                ));
            }
            if self
                .config
                .handoff_height
                .saturating_sub(self.source_handoff_roots.observed_height)
                > self.config.max_source_handoff_age_blocks
            {
                blockers.push((
                    ChecklistBlockerKind::SourceHandoffStale,
                    "source_handoff_roots".to_string(),
                ));
            }
            if self.config.require_source_handoff_fail_closed
                && !self.source_handoff_roots.fail_closed
            {
                blockers.push((
                    ChecklistBlockerKind::SourceHandoffNotFailClosed,
                    "source_handoff_roots".to_string(),
                ));
            }
        }
        if self.checklist_item_count() < self.config.min_checklist_item_count
            || self.checklist_items.iter().any(|hold| !hold.accepted())
        {
            blockers.push((
                ChecklistBlockerKind::ChecklistItemRootMissing,
                "checklist_items".to_string(),
            ));
        }
        if self.release_cap_count(&self.config) < self.config.min_release_cap_count {
            blockers.push((
                ChecklistBlockerKind::ReleaseCapRootMissing,
                "release_caps".to_string(),
            ));
        }
        if self
            .release_caps
            .iter()
            .any(|cap| cap.consumed_atomic_units > cap.cap_limit_atomic_units)
        {
            blockers.push((
                ChecklistBlockerKind::ReleaseCapExceeded,
                "release_caps".to_string(),
            ));
        }
        if self.reserve_liability_count(&self.config) < self.config.min_reserve_liability_count {
            blockers.push((
                ChecklistBlockerKind::ReserveLiabilityRootMissing,
                "reserve_liability_roots".to_string(),
            ));
        }
        if self.reserve_liability_roots.iter().any(|root| {
            self.config.require_reserve_liability_match && !root.balance_matches_liability
        }) {
            blockers.push((
                ChecklistBlockerKind::ReserveLiabilityMismatch,
                "reserve_liability_roots".to_string(),
            ));
        }
        if self.config.require_signer_custody_acknowledgements
            && self.signer_acknowledgement_count() < self.config.min_signer_acknowledgement_count
        {
            blockers.push((
                ChecklistBlockerKind::SignerCustodyAcknowledgementQuorumLow,
                "signer_custody_acknowledgements".to_string(),
            ));
        }
        if self.config.require_signer_custody_acknowledgements
            && self.signer_acknowledgement_weight() < self.config.min_signer_acknowledgement_weight
        {
            blockers.push((
                ChecklistBlockerKind::SignerCustodyAcknowledgementWeightLow,
                "signer_custody_acknowledgements".to_string(),
            ));
        }
        if self.release_authority_count(&self.config) < self.config.min_release_authorities {
            blockers.push((
                ChecklistBlockerKind::BridgeReleaseAuthorityMissing,
                "bridge_release_authorities".to_string(),
            ));
        }
        if self
            .bridge_release_authorities
            .iter()
            .any(|authority| !authority.bridge_pause_asserted)
        {
            blockers.push((
                ChecklistBlockerKind::BridgeReleaseAuthorityOpen,
                "bridge_release_authorities".to_string(),
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
    blockers: Vec<(ChecklistBlockerKind, String)>,
    evidence_root: &str,
) -> Vec<ChecklistBlocker> {
    let mut seen = BTreeSet::new();
    blockers
        .into_iter()
        .filter(|(kind, subject)| seen.insert((*kind, subject.clone())))
        .map(|(kind, subject)| ChecklistBlocker::new(config, kind, &subject, evidence_root))
        .collect()
}

fn runtime_id(label: &str) -> String {
    domain_hash(
        "OPERATOR-COMMAND-CHECKLIST-ID",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        16,
    )
}

fn evidence_id(config: &Config, kind: &str, subject: &str, ordinal: u64) -> String {
    domain_hash(
        "OPERATOR-COMMAND-CHECKLIST-EVIDENCE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.operator_command_checklist_id),
            HashPart::Str(kind),
            HashPart::Str(subject),
            HashPart::U64(ordinal),
        ],
        16,
    )
}

fn source_component_root(config: &Config, component: &str) -> String {
    domain_hash(
        "OPERATOR-COMMAND-CHECKLIST-SOURCE-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.operator_command_checklist_id),
            HashPart::Str(&config.source_handoff_id),
            HashPart::Str(component),
            HashPart::U64(config.source_wave),
        ],
        32,
    )
}

fn component_root(config: &Config, kind: &str, evidence_id: &str) -> String {
    domain_hash(
        "OPERATOR-COMMAND-CHECKLIST-COMPONENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.operator_command_checklist_id),
            HashPart::Str(kind),
            HashPart::Str(evidence_id),
            HashPart::U64(config.handoff_height),
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
