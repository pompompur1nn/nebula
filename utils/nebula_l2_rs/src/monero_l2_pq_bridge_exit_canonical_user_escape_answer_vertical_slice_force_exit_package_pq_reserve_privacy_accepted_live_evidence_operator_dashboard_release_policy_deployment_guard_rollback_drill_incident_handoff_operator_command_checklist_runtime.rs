use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackagePqReservePrivacyAcceptedLiveEvidenceOperatorDashboardReleasePolicyDeploymentGuardRollbackDrillIncidentHandoffOperatorCommandChecklistRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_PQ_RESERVE_PRIVACY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_INCIDENT_HANDOFF_OPERATOR_COMMAND_CHECKLIST_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-force-exit-pq-reserve-privacy-operator-command-checklist-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_PQ_RESERVE_PRIVACY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_DASHBOARD_RELEASE_POLICY_DEPLOYMENT_GUARD_ROLLBACK_DRILL_INCIDENT_HANDOFF_OPERATOR_COMMAND_CHECKLIST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CHECKLIST_SUITE: &str =
    "wave-87-pq-reserve-privacy-operator-command-checklist-fail-closed-v1";
pub const DEFAULT_WAVE_NUMBER: u16 = 87;
pub const DEFAULT_SOURCE_WAVE_NUMBER: u16 = 86;
pub const DEFAULT_RELEASE_EPOCH: u64 = 87;
pub const DEFAULT_KEY_EPOCH: u64 = 86;
pub const DEFAULT_HEIGHT: u64 = 870_000;
pub const DEFAULT_MAX_HANDOFF_AGE_BLOCKS: u64 = 96;
pub const DEFAULT_MIN_PQ_SIGNER_POLICIES: u16 = 3;
pub const DEFAULT_MIN_RESERVE_ATTESTATIONS: u16 = 3;
pub const DEFAULT_MIN_AMOUNT_BUCKET_GUARDS: u16 = 4;
pub const DEFAULT_MIN_KEY_ROTATION_ITEMS: u16 = 2;
pub const DEFAULT_MIN_PRIVACY_SIGNOFFS: u16 = 3;
pub const DEFAULT_MIN_RELEASE_AUTHORITIES: u16 = 2;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u16 = 10_500;
pub const DEFAULT_MAX_PRIVACY_BUDGET_BPS: u16 = 2_000;
pub const DEFAULT_MAX_BUCKET_EXPOSURE_BPS: u16 = 1_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistKind {
    PqSignerPolicy,
    ReserveAttestation,
    AmountBucketPrivacy,
    KeyRotationReadiness,
    PrivacyBudgetSignoff,
    ReleaseAuthority,
}

impl ChecklistKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqSignerPolicy => "pq_signer_policy",
            Self::ReserveAttestation => "reserve_attestation",
            Self::AmountBucketPrivacy => "amount_bucket_privacy",
            Self::KeyRotationReadiness => "key_rotation_readiness",
            Self::PrivacyBudgetSignoff => "privacy_budget_signoff",
            Self::ReleaseAuthority => "release_authority",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecklistStatus {
    Pending,
    Accepted,
    Blocked,
    Deferred,
}

impl ChecklistStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Blocked => "blocked",
            Self::Deferred => "deferred",
        }
    }

    pub fn accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerKind {
    MissingWave86HandoffRoot,
    StaleWave86HandoffRoot,
    PqSignerPolicyQuorumShortfall,
    ReserveAttestationQuorumShortfall,
    ReserveCoverageShortfall,
    AmountBucketGuardShortfall,
    AmountBucketExposureExceeded,
    KeyRotationNotReady,
    PrivacyBudgetExceeded,
    PrivacySignoffShortfall,
    ReleaseAuthorityShortfall,
    ReleaseAuthorityNotFailClosed,
    ChecklistItemBlocked,
    DuplicateChecklistItem,
}

impl BlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingWave86HandoffRoot => "missing_wave_86_handoff_root",
            Self::StaleWave86HandoffRoot => "stale_wave_86_handoff_root",
            Self::PqSignerPolicyQuorumShortfall => "pq_signer_policy_quorum_shortfall",
            Self::ReserveAttestationQuorumShortfall => "reserve_attestation_quorum_shortfall",
            Self::ReserveCoverageShortfall => "reserve_coverage_shortfall",
            Self::AmountBucketGuardShortfall => "amount_bucket_guard_shortfall",
            Self::AmountBucketExposureExceeded => "amount_bucket_exposure_exceeded",
            Self::KeyRotationNotReady => "key_rotation_not_ready",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::PrivacySignoffShortfall => "privacy_signoff_shortfall",
            Self::ReleaseAuthorityShortfall => "release_authority_shortfall",
            Self::ReleaseAuthorityNotFailClosed => "release_authority_not_fail_closed",
            Self::ChecklistItemBlocked => "checklist_item_blocked",
            Self::DuplicateChecklistItem => "duplicate_checklist_item",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseDecision {
    FailClosedHold,
    ReadyAfterHumanAuthority,
}

impl ReleaseDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailClosedHold => "fail_closed_hold",
            Self::ReadyAfterHumanAuthority => "ready_after_human_authority",
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
    pub wave_number: u16,
    pub source_wave_number: u16,
    pub release_epoch: u64,
    pub key_epoch: u64,
    pub max_handoff_age_blocks: u64,
    pub min_pq_signer_policies: u16,
    pub min_reserve_attestations: u16,
    pub min_amount_bucket_guards: u16,
    pub min_key_rotation_items: u16,
    pub min_privacy_signoffs: u16,
    pub min_release_authorities: u16,
    pub min_reserve_coverage_bps: u16,
    pub max_privacy_budget_bps: u16,
    pub max_bucket_exposure_bps: u16,
    pub require_fail_closed_release_authority: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            checklist_suite: CHECKLIST_SUITE.to_string(),
            wave_number: DEFAULT_WAVE_NUMBER,
            source_wave_number: DEFAULT_SOURCE_WAVE_NUMBER,
            release_epoch: DEFAULT_RELEASE_EPOCH,
            key_epoch: DEFAULT_KEY_EPOCH,
            max_handoff_age_blocks: DEFAULT_MAX_HANDOFF_AGE_BLOCKS,
            min_pq_signer_policies: DEFAULT_MIN_PQ_SIGNER_POLICIES,
            min_reserve_attestations: DEFAULT_MIN_RESERVE_ATTESTATIONS,
            min_amount_bucket_guards: DEFAULT_MIN_AMOUNT_BUCKET_GUARDS,
            min_key_rotation_items: DEFAULT_MIN_KEY_ROTATION_ITEMS,
            min_privacy_signoffs: DEFAULT_MIN_PRIVACY_SIGNOFFS,
            min_release_authorities: DEFAULT_MIN_RELEASE_AUTHORITIES,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            max_privacy_budget_bps: DEFAULT_MAX_PRIVACY_BUDGET_BPS,
            max_bucket_exposure_bps: DEFAULT_MAX_BUCKET_EXPOSURE_BPS,
            require_fail_closed_release_authority: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("hash_suite", &self.hash_suite)?;
        ensure_non_empty("checklist_suite", &self.checklist_suite)?;
        ensure(self.schema_version > 0, "schema version must be non-zero")?;
        ensure(
            self.wave_number > self.source_wave_number,
            "checklist wave must follow source handoff wave",
        )?;
        ensure(self.release_epoch > 0, "release epoch must be non-zero")?;
        ensure(self.key_epoch > 0, "key epoch must be non-zero")?;
        ensure(
            self.max_handoff_age_blocks > 0,
            "max handoff age must be non-zero",
        )?;
        ensure_bps_at_least(
            "min_reserve_coverage_bps",
            self.min_reserve_coverage_bps,
            10_000,
        )?;
        ensure_bps("max_privacy_budget_bps", self.max_privacy_budget_bps)?;
        ensure_bps("max_bucket_exposure_bps", self.max_bucket_exposure_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "checklist_suite": self.checklist_suite,
            "wave_number": self.wave_number,
            "source_wave_number": self.source_wave_number,
            "release_epoch": self.release_epoch,
            "key_epoch": self.key_epoch,
            "max_handoff_age_blocks": self.max_handoff_age_blocks,
            "min_pq_signer_policies": self.min_pq_signer_policies,
            "min_reserve_attestations": self.min_reserve_attestations,
            "min_amount_bucket_guards": self.min_amount_bucket_guards,
            "min_key_rotation_items": self.min_key_rotation_items,
            "min_privacy_signoffs": self.min_privacy_signoffs,
            "min_release_authorities": self.min_release_authorities,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "max_privacy_budget_bps": self.max_privacy_budget_bps,
            "max_bucket_exposure_bps": self.max_bucket_exposure_bps,
            "require_fail_closed_release_authority": self.require_fail_closed_release_authority,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Wave86HandoffRoot {
    pub lane: String,
    pub handoff_root: String,
    pub blocker_root: String,
    pub summary_root: String,
    pub source_height: u64,
    pub accepted: bool,
}

impl Wave86HandoffRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane,
            "handoff_root": self.handoff_root,
            "blocker_root": self.blocker_root,
            "summary_root": self.summary_root,
            "source_height": self.source_height,
            "accepted": self.accepted,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("wave-86-handoff-root", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("lane", &self.lane)?;
        ensure_root("handoff_root", &self.handoff_root)?;
        ensure_root("blocker_root", &self.blocker_root)?;
        ensure_root("summary_root", &self.summary_root)?;
        ensure(self.source_height > 0, "source height must be non-zero")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChecklistItem {
    pub item_id: String,
    pub kind: ChecklistKind,
    pub source_handoff_root: String,
    pub evidence_root: String,
    pub status: ChecklistStatus,
    pub operator_role: String,
    pub fail_closed: bool,
    pub observed_at_height: u64,
}

impl ChecklistItem {
    pub fn public_record(&self) -> Value {
        json!({
            "item_id": self.item_id,
            "kind": self.kind.as_str(),
            "source_handoff_root": self.source_handoff_root,
            "evidence_root": self.evidence_root,
            "status": self.status.as_str(),
            "operator_role": self.operator_role,
            "fail_closed": self.fail_closed,
            "observed_at_height": self.observed_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("checklist-item", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("item_id", &self.item_id)?;
        ensure_root("source_handoff_root", &self.source_handoff_root)?;
        ensure_root("evidence_root", &self.evidence_root)?;
        ensure_non_empty("operator_role", &self.operator_role)?;
        ensure(
            self.observed_at_height > 0,
            "item observed height must be non-zero",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveAttestationCheck {
    pub attestation_id: String,
    pub reserve_root: String,
    pub liability_root: String,
    pub coverage_bps: u16,
    pub freshness_height: u64,
    pub accepted: bool,
}

impl ReserveAttestationCheck {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
            "coverage_bps": self.coverage_bps,
            "freshness_height": self.freshness_height,
            "accepted": self.accepted,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("reserve-attestation-check", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("attestation_id", &self.attestation_id)?;
        ensure_root("reserve_root", &self.reserve_root)?;
        ensure_root("liability_root", &self.liability_root)?;
        ensure_bps_at_least("coverage_bps", self.coverage_bps, 1)?;
        ensure(
            self.freshness_height > 0,
            "attestation freshness height must be non-zero",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AmountBucketPrivacyGuard {
    pub bucket_id: String,
    pub bucket_commitment_root: String,
    pub exposure_bps: u16,
    pub min_bucket_size: u16,
    pub release_suppressed: bool,
}

impl AmountBucketPrivacyGuard {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "bucket_commitment_root": self.bucket_commitment_root,
            "exposure_bps": self.exposure_bps,
            "min_bucket_size": self.min_bucket_size,
            "release_suppressed": self.release_suppressed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("amount-bucket-privacy-guard", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("bucket_id", &self.bucket_id)?;
        ensure_root("bucket_commitment_root", &self.bucket_commitment_root)?;
        ensure_bps("exposure_bps", self.exposure_bps)?;
        ensure(self.min_bucket_size > 1, "min bucket size must exceed one")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyRotationReadiness {
    pub rotation_id: String,
    pub next_epoch: u64,
    pub readiness_root: String,
    pub old_epoch_disabled_root: String,
    pub quorum_ready: bool,
}

impl KeyRotationReadiness {
    pub fn public_record(&self) -> Value {
        json!({
            "rotation_id": self.rotation_id,
            "next_epoch": self.next_epoch,
            "readiness_root": self.readiness_root,
            "old_epoch_disabled_root": self.old_epoch_disabled_root,
            "quorum_ready": self.quorum_ready,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("key-rotation-readiness", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("rotation_id", &self.rotation_id)?;
        ensure(self.next_epoch > 0, "next key epoch must be non-zero")?;
        ensure_root("readiness_root", &self.readiness_root)?;
        ensure_root("old_epoch_disabled_root", &self.old_epoch_disabled_root)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBudgetSignoff {
    pub signoff_id: String,
    pub reviewer_role: String,
    pub budget_root: String,
    pub budget_bps: u16,
    pub accepted: bool,
}

impl PrivacyBudgetSignoff {
    pub fn public_record(&self) -> Value {
        json!({
            "signoff_id": self.signoff_id,
            "reviewer_role": self.reviewer_role,
            "budget_root": self.budget_root,
            "budget_bps": self.budget_bps,
            "accepted": self.accepted,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("privacy-budget-signoff", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("signoff_id", &self.signoff_id)?;
        ensure_non_empty("reviewer_role", &self.reviewer_role)?;
        ensure_root("budget_root", &self.budget_root)?;
        ensure_bps("budget_bps", self.budget_bps)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseAuthority {
    pub authority_id: String,
    pub role: String,
    pub command_policy_root: String,
    pub fail_closed_ack_root: String,
    pub can_unblock_release: bool,
}

impl ReleaseAuthority {
    pub fn public_record(&self) -> Value {
        json!({
            "authority_id": self.authority_id,
            "role": self.role,
            "command_policy_root": self.command_policy_root,
            "fail_closed_ack_root": self.fail_closed_ack_root,
            "can_unblock_release": self.can_unblock_release,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release-authority", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("authority_id", &self.authority_id)?;
        ensure_non_empty("role", &self.role)?;
        ensure_root("command_policy_root", &self.command_policy_root)?;
        ensure_root("fail_closed_ack_root", &self.fail_closed_ack_root)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChecklistSummary {
    pub decision: ReleaseDecision,
    pub fail_closed: bool,
    pub accepted_item_count: u16,
    pub blocker_count: u16,
    pub pq_signer_policy_count: u16,
    pub reserve_attestation_count: u16,
    pub amount_bucket_guard_count: u16,
    pub key_rotation_ready_count: u16,
    pub privacy_signoff_count: u16,
    pub release_authority_count: u16,
    pub summary_root: String,
}

impl ChecklistSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "decision": self.decision.as_str(),
            "fail_closed": self.fail_closed,
            "accepted_item_count": self.accepted_item_count,
            "blocker_count": self.blocker_count,
            "pq_signer_policy_count": self.pq_signer_policy_count,
            "reserve_attestation_count": self.reserve_attestation_count,
            "amount_bucket_guard_count": self.amount_bucket_guard_count,
            "key_rotation_ready_count": self.key_rotation_ready_count,
            "privacy_signoff_count": self.privacy_signoff_count,
            "release_authority_count": self.release_authority_count,
            "summary_root": self.summary_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub wave_86_handoff_roots: Vec<Wave86HandoffRoot>,
    pub checklist_items: Vec<ChecklistItem>,
    pub reserve_attestation_checks: Vec<ReserveAttestationCheck>,
    pub amount_bucket_guards: Vec<AmountBucketPrivacyGuard>,
    pub key_rotation_readiness: Vec<KeyRotationReadiness>,
    pub privacy_budget_signoffs: Vec<PrivacyBudgetSignoff>,
    pub release_authorities: Vec<ReleaseAuthority>,
    pub blockers: BTreeMap<String, Vec<BlockerKind>>,
    pub wave_86_root: String,
    pub checklist_root: String,
    pub reserve_attestation_root: String,
    pub amount_bucket_root: String,
    pub key_rotation_root: String,
    pub privacy_budget_root: String,
    pub release_authority_root: String,
    pub blocker_root: String,
    pub summary: ChecklistSummary,
}

impl State {
    pub fn new(
        config: Config,
        height: u64,
        wave_86_handoff_roots: Vec<Wave86HandoffRoot>,
        checklist_items: Vec<ChecklistItem>,
        reserve_attestation_checks: Vec<ReserveAttestationCheck>,
        amount_bucket_guards: Vec<AmountBucketPrivacyGuard>,
        key_rotation_readiness: Vec<KeyRotationReadiness>,
        privacy_budget_signoffs: Vec<PrivacyBudgetSignoff>,
        release_authorities: Vec<ReleaseAuthority>,
    ) -> Result<Self> {
        config.validate()?;
        ensure(height > 0, "state height must be non-zero")?;
        ensure(
            !wave_86_handoff_roots.is_empty(),
            "wave 86 handoff roots must be non-empty",
        )?;
        ensure(
            !checklist_items.is_empty(),
            "checklist items must be non-empty",
        )?;
        for root in &wave_86_handoff_roots {
            root.validate()?;
        }
        for item in &checklist_items {
            item.validate()?;
        }
        for check in &reserve_attestation_checks {
            check.validate()?;
        }
        for guard in &amount_bucket_guards {
            guard.validate()?;
        }
        for readiness in &key_rotation_readiness {
            readiness.validate()?;
        }
        for signoff in &privacy_budget_signoffs {
            signoff.validate()?;
        }
        for authority in &release_authorities {
            authority.validate()?;
        }
        let blockers = evaluate_blockers(
            &config,
            height,
            &wave_86_handoff_roots,
            &checklist_items,
            &reserve_attestation_checks,
            &amount_bucket_guards,
            &key_rotation_readiness,
            &privacy_budget_signoffs,
            &release_authorities,
        );
        let wave_86_root = roots_root(
            "wave-86-handoff-roots",
            wave_86_handoff_roots
                .iter()
                .map(Wave86HandoffRoot::state_root),
        );
        let checklist_root = roots_root(
            "operator-command-checklist-items",
            checklist_items.iter().map(ChecklistItem::state_root),
        );
        let reserve_attestation_root = roots_root(
            "reserve-attestation-checks",
            reserve_attestation_checks
                .iter()
                .map(ReserveAttestationCheck::state_root),
        );
        let amount_bucket_root = roots_root(
            "amount-bucket-privacy-guards",
            amount_bucket_guards
                .iter()
                .map(AmountBucketPrivacyGuard::state_root),
        );
        let key_rotation_root = roots_root(
            "key-rotation-readiness",
            key_rotation_readiness
                .iter()
                .map(KeyRotationReadiness::state_root),
        );
        let privacy_budget_root = roots_root(
            "privacy-budget-signoffs",
            privacy_budget_signoffs
                .iter()
                .map(PrivacyBudgetSignoff::state_root),
        );
        let release_authority_root = roots_root(
            "release-authorities",
            release_authorities.iter().map(ReleaseAuthority::state_root),
        );
        let blocker_root = blockers_root(&blockers);
        let summary = ChecklistSummary::build(
            &config,
            &checklist_items,
            &reserve_attestation_checks,
            &amount_bucket_guards,
            &key_rotation_readiness,
            &privacy_budget_signoffs,
            &release_authorities,
            &blockers,
        );
        Ok(Self {
            config,
            height,
            wave_86_handoff_roots,
            checklist_items,
            reserve_attestation_checks,
            amount_bucket_guards,
            key_rotation_readiness,
            privacy_budget_signoffs,
            release_authorities,
            blockers,
            wave_86_root,
            checklist_root,
            reserve_attestation_root,
            amount_bucket_root,
            key_rotation_root,
            privacy_budget_root,
            release_authority_root,
            blocker_root,
            summary,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let height = DEFAULT_HEIGHT;
        let wave_86_handoff_roots = devnet_wave_86_roots(height);
        let maybe_source_root = wave_86_handoff_roots
            .iter()
            .find(|root| root.lane == "pq_reserve_privacy")
            .map(|root| root.handoff_root.clone());
        let source_root = match maybe_source_root {
            Some(root) => root,
            None => sample_root("wave-86-handoff", "pq-reserve-privacy", 1),
        };
        let checklist_items = devnet_checklist_items(&config, height, &source_root);
        let reserve_attestation_checks = vec![
            reserve_attestation_check("primary-reserve", 10_900, height - 9, true, 1),
            reserve_attestation_check("challenge-holdback", 10_700, height - 8, true, 2),
            reserve_attestation_check("emergency-backstop", 10_600, height - 7, true, 3),
        ];
        let amount_bucket_guards = vec![
            amount_bucket_guard("bucket-low", 640, 32, true, 1),
            amount_bucket_guard("bucket-mid", 780, 32, true, 2),
            amount_bucket_guard("bucket-high", 900, 24, true, 3),
            amount_bucket_guard("bucket-tail", 960, 16, true, 4),
        ];
        let key_rotation_readiness = vec![
            key_rotation_readiness("pq-signer-next-epoch", config.release_epoch, true, 1),
            key_rotation_readiness("reserve-attestor-next-epoch", config.release_epoch, true, 2),
        ];
        let privacy_budget_signoffs = vec![
            privacy_budget_signoff("privacy-lead", 1_400, true, 1),
            privacy_budget_signoff("security-lead", 1_600, true, 2),
            privacy_budget_signoff("release-captain", 1_700, true, 3),
        ];
        let release_authorities = vec![
            release_authority("incident-commander", false, 1),
            release_authority("pq-reserve-privacy-lead", false, 2),
        ];
        match Self::new(
            config,
            height,
            wave_86_handoff_roots,
            checklist_items,
            reserve_attestation_checks,
            amount_bucket_guards,
            key_rotation_readiness,
            privacy_budget_signoffs,
            release_authorities,
        ) {
            Ok(state) => state,
            Err(reason) => build_fail_closed_fallback(reason),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "wave_86_root": self.wave_86_root,
            "checklist_root": self.checklist_root,
            "reserve_attestation_root": self.reserve_attestation_root,
            "amount_bucket_root": self.amount_bucket_root,
            "key_rotation_root": self.key_rotation_root,
            "privacy_budget_root": self.privacy_budget_root,
            "release_authority_root": self.release_authority_root,
            "blocker_root": self.blocker_root,
            "summary": self.summary.public_record(),
            "wave_86_handoff_roots": self.wave_86_handoff_roots.iter().map(Wave86HandoffRoot::public_record).collect::<Vec<_>>(),
            "checklist_items": self.checklist_items.iter().map(ChecklistItem::public_record).collect::<Vec<_>>(),
            "reserve_attestation_checks": self.reserve_attestation_checks.iter().map(ReserveAttestationCheck::public_record).collect::<Vec<_>>(),
            "amount_bucket_guards": self.amount_bucket_guards.iter().map(AmountBucketPrivacyGuard::public_record).collect::<Vec<_>>(),
            "key_rotation_readiness": self.key_rotation_readiness.iter().map(KeyRotationReadiness::public_record).collect::<Vec<_>>(),
            "privacy_budget_signoffs": self.privacy_budget_signoffs.iter().map(PrivacyBudgetSignoff::public_record).collect::<Vec<_>>(),
            "release_authorities": self.release_authorities.iter().map(ReleaseAuthority::public_record).collect::<Vec<_>>(),
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
            "PQ-RESERVE-PRIVACY-OPERATOR-COMMAND-CHECKLIST-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.checklist_suite),
                HashPart::U64(self.height),
                HashPart::Str(&self.wave_86_root),
                HashPart::Str(&self.checklist_root),
                HashPart::Str(&self.reserve_attestation_root),
                HashPart::Str(&self.amount_bucket_root),
                HashPart::Str(&self.key_rotation_root),
                HashPart::Str(&self.privacy_budget_root),
                HashPart::Str(&self.release_authority_root),
                HashPart::Str(&self.blocker_root),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure(self.height > 0, "state height must be non-zero")?;
        ensure_root("wave_86_root", &self.wave_86_root)?;
        ensure_root("checklist_root", &self.checklist_root)?;
        ensure_root("reserve_attestation_root", &self.reserve_attestation_root)?;
        ensure_root("amount_bucket_root", &self.amount_bucket_root)?;
        ensure_root("key_rotation_root", &self.key_rotation_root)?;
        ensure_root("privacy_budget_root", &self.privacy_budget_root)?;
        ensure_root("release_authority_root", &self.release_authority_root)?;
        ensure_root("blocker_root", &self.blocker_root)?;
        for root in &self.wave_86_handoff_roots {
            root.validate()?;
        }
        for item in &self.checklist_items {
            item.validate()?;
        }
        if self.config.require_fail_closed_release_authority {
            ensure(self.fail_closed(), "release authority must fail closed")?;
        }
        Ok(())
    }

    pub fn fail_closed(&self) -> bool {
        self.summary.fail_closed
            || self
                .release_authorities
                .iter()
                .any(|authority| !authority.can_unblock_release)
    }
}

impl ChecklistSummary {
    fn build(
        config: &Config,
        checklist_items: &[ChecklistItem],
        reserve_attestation_checks: &[ReserveAttestationCheck],
        amount_bucket_guards: &[AmountBucketPrivacyGuard],
        key_rotation_readiness: &[KeyRotationReadiness],
        privacy_budget_signoffs: &[PrivacyBudgetSignoff],
        release_authorities: &[ReleaseAuthority],
        blockers: &BTreeMap<String, Vec<BlockerKind>>,
    ) -> Self {
        let accepted_item_count = count_u16(
            checklist_items
                .iter()
                .filter(|item| item.status.accepted())
                .count(),
        );
        let pq_signer_policy_count = count_kind(checklist_items, ChecklistKind::PqSignerPolicy);
        let reserve_attestation_count = count_u16(
            reserve_attestation_checks
                .iter()
                .filter(|item| item.accepted)
                .count(),
        );
        let amount_bucket_guard_count = count_u16(
            amount_bucket_guards
                .iter()
                .filter(|guard| guard.release_suppressed)
                .count(),
        );
        let key_rotation_ready_count = count_u16(
            key_rotation_readiness
                .iter()
                .filter(|item| item.quorum_ready && item.next_epoch >= config.release_epoch)
                .count(),
        );
        let privacy_signoff_count = count_u16(
            privacy_budget_signoffs
                .iter()
                .filter(|signoff| signoff.accepted)
                .count(),
        );
        let release_authority_count = count_u16(
            release_authorities
                .iter()
                .filter(|authority| authority.can_unblock_release)
                .count(),
        );
        let blocker_count = count_u16(blockers.values().map(Vec::len).sum::<usize>());
        let fail_closed =
            blocker_count > 0 || release_authority_count < config.min_release_authorities;
        let decision = if fail_closed {
            ReleaseDecision::FailClosedHold
        } else {
            ReleaseDecision::ReadyAfterHumanAuthority
        };
        let summary_root = domain_hash(
            "PQ-RESERVE-PRIVACY-OPERATOR-COMMAND-CHECKLIST-SUMMARY",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(blocker_count as u64),
                HashPart::U64(accepted_item_count as u64),
                HashPart::U64(release_authority_count as u64),
                HashPart::Json(&json!({
                    "decision": decision.as_str(),
                    "fail_closed": fail_closed,
                    "pq_signer_policy_count": pq_signer_policy_count,
                    "reserve_attestation_count": reserve_attestation_count,
                    "amount_bucket_guard_count": amount_bucket_guard_count,
                    "key_rotation_ready_count": key_rotation_ready_count,
                    "privacy_signoff_count": privacy_signoff_count,
                })),
            ],
            32,
        );
        Self {
            decision,
            fail_closed,
            accepted_item_count,
            blocker_count,
            pq_signer_policy_count,
            reserve_attestation_count,
            amount_bucket_guard_count,
            key_rotation_ready_count,
            privacy_signoff_count,
            release_authority_count,
            summary_root,
        }
    }
}

pub fn devnet() -> Runtime {
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
    wave_86_handoff_roots: &[Wave86HandoffRoot],
    checklist_items: &[ChecklistItem],
    reserve_attestation_checks: &[ReserveAttestationCheck],
    amount_bucket_guards: &[AmountBucketPrivacyGuard],
    key_rotation_readiness: &[KeyRotationReadiness],
    privacy_budget_signoffs: &[PrivacyBudgetSignoff],
    release_authorities: &[ReleaseAuthority],
) -> BTreeMap<String, Vec<BlockerKind>> {
    let mut blockers = BTreeMap::<String, Vec<BlockerKind>>::new();
    if wave_86_handoff_roots.is_empty() {
        blockers
            .entry("wave_86_handoff".to_string())
            .or_default()
            .push(BlockerKind::MissingWave86HandoffRoot);
    }
    for root in wave_86_handoff_roots {
        if !root.accepted {
            blockers
                .entry(root.lane.clone())
                .or_default()
                .push(BlockerKind::MissingWave86HandoffRoot);
        }
        if height.saturating_sub(root.source_height) > config.max_handoff_age_blocks {
            blockers
                .entry(root.lane.clone())
                .or_default()
                .push(BlockerKind::StaleWave86HandoffRoot);
        }
    }

    let mut seen_items = BTreeSet::new();
    for item in checklist_items {
        if !seen_items.insert(item.item_id.clone()) {
            blockers
                .entry(item.item_id.clone())
                .or_default()
                .push(BlockerKind::DuplicateChecklistItem);
        }
        if !item.status.accepted() || item.fail_closed {
            blockers
                .entry(item.item_id.clone())
                .or_default()
                .push(BlockerKind::ChecklistItemBlocked);
        }
    }

    push_count_blocker(
        &mut blockers,
        "pq_signer_policy",
        BlockerKind::PqSignerPolicyQuorumShortfall,
        count_kind(checklist_items, ChecklistKind::PqSignerPolicy),
        config.min_pq_signer_policies,
    );
    push_count_blocker(
        &mut blockers,
        "reserve_attestation",
        BlockerKind::ReserveAttestationQuorumShortfall,
        count_u16(
            reserve_attestation_checks
                .iter()
                .filter(|item| item.accepted)
                .count(),
        ),
        config.min_reserve_attestations,
    );
    push_count_blocker(
        &mut blockers,
        "amount_bucket_privacy",
        BlockerKind::AmountBucketGuardShortfall,
        count_u16(
            amount_bucket_guards
                .iter()
                .filter(|guard| guard.release_suppressed)
                .count(),
        ),
        config.min_amount_bucket_guards,
    );
    push_count_blocker(
        &mut blockers,
        "key_rotation",
        BlockerKind::KeyRotationNotReady,
        count_u16(
            key_rotation_readiness
                .iter()
                .filter(|item| item.quorum_ready && item.next_epoch >= config.release_epoch)
                .count(),
        ),
        config.min_key_rotation_items,
    );
    push_count_blocker(
        &mut blockers,
        "privacy_budget",
        BlockerKind::PrivacySignoffShortfall,
        count_u16(
            privacy_budget_signoffs
                .iter()
                .filter(|signoff| signoff.accepted)
                .count(),
        ),
        config.min_privacy_signoffs,
    );
    push_count_blocker(
        &mut blockers,
        "release_authority",
        BlockerKind::ReleaseAuthorityShortfall,
        count_u16(
            release_authorities
                .iter()
                .filter(|authority| authority.can_unblock_release)
                .count(),
        ),
        config.min_release_authorities,
    );

    for check in reserve_attestation_checks {
        if check.coverage_bps < config.min_reserve_coverage_bps || !check.accepted {
            blockers
                .entry(check.attestation_id.clone())
                .or_default()
                .push(BlockerKind::ReserveCoverageShortfall);
        }
    }
    for guard in amount_bucket_guards {
        if guard.exposure_bps > config.max_bucket_exposure_bps || !guard.release_suppressed {
            blockers
                .entry(guard.bucket_id.clone())
                .or_default()
                .push(BlockerKind::AmountBucketExposureExceeded);
        }
    }
    for readiness in key_rotation_readiness {
        if !readiness.quorum_ready || readiness.next_epoch < config.release_epoch {
            blockers
                .entry(readiness.rotation_id.clone())
                .or_default()
                .push(BlockerKind::KeyRotationNotReady);
        }
    }
    for signoff in privacy_budget_signoffs {
        if signoff.budget_bps > config.max_privacy_budget_bps || !signoff.accepted {
            blockers
                .entry(signoff.signoff_id.clone())
                .or_default()
                .push(BlockerKind::PrivacyBudgetExceeded);
        }
    }
    if config.require_fail_closed_release_authority {
        for authority in release_authorities {
            if !authority.can_unblock_release {
                blockers
                    .entry(authority.authority_id.clone())
                    .or_default()
                    .push(BlockerKind::ReleaseAuthorityNotFailClosed);
            }
        }
    }
    blockers
}

fn devnet_wave_86_roots(height: u64) -> Vec<Wave86HandoffRoot> {
    [
        "compile_runtime",
        "runtime_replay",
        "audit_security",
        "bridge_custody",
        "wallet_watchtower",
        "pq_reserve_privacy",
    ]
    .into_iter()
    .enumerate()
    .map(|(index, lane)| {
        let ordinal = one_based(index);
        Wave86HandoffRoot {
            lane: lane.to_string(),
            handoff_root: sample_root("wave-86-handoff", lane, ordinal),
            blocker_root: sample_root("wave-86-blocker", lane, ordinal),
            summary_root: sample_root("wave-86-summary", lane, ordinal),
            source_height: height.saturating_sub(24).saturating_add(ordinal),
            accepted: true,
        }
    })
    .collect()
}

fn devnet_checklist_items(config: &Config, height: u64, source_root: &str) -> Vec<ChecklistItem> {
    let kinds = [
        ChecklistKind::PqSignerPolicy,
        ChecklistKind::PqSignerPolicy,
        ChecklistKind::PqSignerPolicy,
        ChecklistKind::ReserveAttestation,
        ChecklistKind::ReserveAttestation,
        ChecklistKind::ReserveAttestation,
        ChecklistKind::AmountBucketPrivacy,
        ChecklistKind::AmountBucketPrivacy,
        ChecklistKind::AmountBucketPrivacy,
        ChecklistKind::AmountBucketPrivacy,
        ChecklistKind::KeyRotationReadiness,
        ChecklistKind::KeyRotationReadiness,
        ChecklistKind::PrivacyBudgetSignoff,
        ChecklistKind::PrivacyBudgetSignoff,
        ChecklistKind::PrivacyBudgetSignoff,
        ChecklistKind::ReleaseAuthority,
        ChecklistKind::ReleaseAuthority,
    ];
    kinds
        .into_iter()
        .enumerate()
        .map(|(index, kind)| checklist_item(config, kind, source_root, height, one_based(index)))
        .collect()
}

fn checklist_item(
    config: &Config,
    kind: ChecklistKind,
    source_root: &str,
    height: u64,
    ordinal: u64,
) -> ChecklistItem {
    let item_id = stable_id("checklist-item", kind.as_str(), ordinal);
    let evidence_root = domain_hash(
        "PQ-RESERVE-PRIVACY-CHECKLIST-ITEM-EVIDENCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&item_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(source_root),
            HashPart::U64(config.release_epoch),
        ],
        32,
    );
    ChecklistItem {
        item_id,
        kind,
        source_handoff_root: source_root.to_string(),
        evidence_root,
        status: ChecklistStatus::Accepted,
        operator_role: operator_role(kind).to_string(),
        fail_closed: matches!(kind, ChecklistKind::ReleaseAuthority),
        observed_at_height: height.saturating_sub(4).saturating_add(ordinal),
    }
}

fn reserve_attestation_check(
    label: &str,
    coverage_bps: u16,
    freshness_height: u64,
    accepted: bool,
    ordinal: u64,
) -> ReserveAttestationCheck {
    ReserveAttestationCheck {
        attestation_id: stable_id("reserve-attestation", label, ordinal),
        reserve_root: sample_root("reserve-root", label, ordinal),
        liability_root: sample_root("liability-root", label, ordinal),
        coverage_bps,
        freshness_height,
        accepted,
    }
}

fn amount_bucket_guard(
    label: &str,
    exposure_bps: u16,
    min_bucket_size: u16,
    release_suppressed: bool,
    ordinal: u64,
) -> AmountBucketPrivacyGuard {
    AmountBucketPrivacyGuard {
        bucket_id: stable_id("amount-bucket", label, ordinal),
        bucket_commitment_root: sample_root("amount-bucket-commitment", label, ordinal),
        exposure_bps,
        min_bucket_size,
        release_suppressed,
    }
}

fn key_rotation_readiness(
    label: &str,
    next_epoch: u64,
    quorum_ready: bool,
    ordinal: u64,
) -> KeyRotationReadiness {
    KeyRotationReadiness {
        rotation_id: stable_id("key-rotation", label, ordinal),
        next_epoch,
        readiness_root: sample_root("key-rotation-readiness", label, ordinal),
        old_epoch_disabled_root: sample_root("old-key-epoch-disabled", label, ordinal),
        quorum_ready,
    }
}

fn privacy_budget_signoff(
    reviewer_role: &str,
    budget_bps: u16,
    accepted: bool,
    ordinal: u64,
) -> PrivacyBudgetSignoff {
    PrivacyBudgetSignoff {
        signoff_id: stable_id("privacy-budget-signoff", reviewer_role, ordinal),
        reviewer_role: reviewer_role.to_string(),
        budget_root: sample_root("privacy-budget", reviewer_role, ordinal),
        budget_bps,
        accepted,
    }
}

fn release_authority(role: &str, can_unblock_release: bool, ordinal: u64) -> ReleaseAuthority {
    ReleaseAuthority {
        authority_id: stable_id("release-authority", role, ordinal),
        role: role.to_string(),
        command_policy_root: sample_root("command-policy", role, ordinal),
        fail_closed_ack_root: sample_root("fail-closed-ack", role, ordinal),
        can_unblock_release,
    }
}

fn build_fail_closed_fallback(reason: String) -> State {
    let config = Config::devnet();
    let height = DEFAULT_HEIGHT;
    let source_root = sample_root("fallback-wave-86-handoff", "pq-reserve-privacy", 1);
    let wave_86_handoff_roots = vec![Wave86HandoffRoot {
        lane: "pq_reserve_privacy".to_string(),
        handoff_root: source_root.clone(),
        blocker_root: sample_root("fallback-blocker", "pq-reserve-privacy", 1),
        summary_root: sample_root("fallback-summary", "pq-reserve-privacy", 1),
        source_height: height,
        accepted: false,
    }];
    let checklist_items = vec![ChecklistItem {
        item_id: stable_id("fallback-checklist-item", "fail-closed", 1),
        kind: ChecklistKind::ReleaseAuthority,
        source_handoff_root: source_root,
        evidence_root: sample_root("fallback-evidence", "fail-closed", 1),
        status: ChecklistStatus::Blocked,
        operator_role: "incident-command".to_string(),
        fail_closed: true,
        observed_at_height: height,
    }];
    let reserve_attestation_checks = Vec::new();
    let amount_bucket_guards = Vec::new();
    let key_rotation_readiness = Vec::new();
    let privacy_budget_signoffs = Vec::new();
    let release_authorities = vec![ReleaseAuthority {
        authority_id: stable_id("fallback-release-authority", "fail-closed", 1),
        role: "incident-command".to_string(),
        command_policy_root: sample_root("fallback-command-policy", "fail-closed", 1),
        fail_closed_ack_root: if reason.trim().is_empty() {
            sample_root("fallback-empty-reason", "fail-closed", 1)
        } else {
            sample_root("fallback-reason", "fail-closed", 1)
        },
        can_unblock_release: false,
    }];
    let blockers = evaluate_blockers(
        &config,
        height,
        &wave_86_handoff_roots,
        &checklist_items,
        &reserve_attestation_checks,
        &amount_bucket_guards,
        &key_rotation_readiness,
        &privacy_budget_signoffs,
        &release_authorities,
    );
    let wave_86_root = roots_root(
        "wave-86-handoff-roots",
        wave_86_handoff_roots
            .iter()
            .map(Wave86HandoffRoot::state_root),
    );
    let checklist_root = roots_root(
        "operator-command-checklist-items",
        checklist_items.iter().map(ChecklistItem::state_root),
    );
    let reserve_attestation_root = roots_root(
        "reserve-attestation-checks",
        reserve_attestation_checks
            .iter()
            .map(ReserveAttestationCheck::state_root),
    );
    let amount_bucket_root = roots_root(
        "amount-bucket-privacy-guards",
        amount_bucket_guards
            .iter()
            .map(AmountBucketPrivacyGuard::state_root),
    );
    let key_rotation_root = roots_root(
        "key-rotation-readiness",
        key_rotation_readiness
            .iter()
            .map(KeyRotationReadiness::state_root),
    );
    let privacy_budget_root = roots_root(
        "privacy-budget-signoffs",
        privacy_budget_signoffs
            .iter()
            .map(PrivacyBudgetSignoff::state_root),
    );
    let release_authority_root = roots_root(
        "release-authorities",
        release_authorities.iter().map(ReleaseAuthority::state_root),
    );
    let blocker_root = blockers_root(&blockers);
    let summary = ChecklistSummary::build(
        &config,
        &checklist_items,
        &reserve_attestation_checks,
        &amount_bucket_guards,
        &key_rotation_readiness,
        &privacy_budget_signoffs,
        &release_authorities,
        &blockers,
    );
    State {
        config,
        height,
        wave_86_handoff_roots,
        checklist_items,
        reserve_attestation_checks,
        amount_bucket_guards,
        key_rotation_readiness,
        privacy_budget_signoffs,
        release_authorities,
        blockers,
        wave_86_root,
        checklist_root,
        reserve_attestation_root,
        amount_bucket_root,
        key_rotation_root,
        privacy_budget_root,
        release_authority_root,
        blocker_root,
        summary,
    }
}

fn operator_role(kind: ChecklistKind) -> &'static str {
    match kind {
        ChecklistKind::PqSignerPolicy => "pq-signer-policy-lead",
        ChecklistKind::ReserveAttestation => "reserve-attestation-lead",
        ChecklistKind::AmountBucketPrivacy => "privacy-bucket-reviewer",
        ChecklistKind::KeyRotationReadiness => "key-rotation-lead",
        ChecklistKind::PrivacyBudgetSignoff => "privacy-budget-reviewer",
        ChecklistKind::ReleaseAuthority => "incident-release-authority",
    }
}

fn push_count_blocker(
    blockers: &mut BTreeMap<String, Vec<BlockerKind>>,
    subject: &str,
    kind: BlockerKind,
    observed: u16,
    required: u16,
) {
    if observed < required {
        blockers.entry(subject.to_string()).or_default().push(kind);
    }
}

fn count_kind(items: &[ChecklistItem], kind: ChecklistKind) -> u16 {
    count_u16(
        items
            .iter()
            .filter(|item| item.kind == kind && item.status.accepted())
            .count(),
    )
}

fn count_u16(count: usize) -> u16 {
    if count > u16::MAX as usize {
        u16::MAX
    } else {
        count as u16
    }
}

fn roots_root<I>(label: &str, roots: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let leaves = roots
        .into_iter()
        .filter(|root| !root.trim().is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn blockers_root(blockers: &BTreeMap<String, Vec<BlockerKind>>) -> String {
    let leaves = blockers
        .iter()
        .map(|(subject, blocker_list)| {
            json!({
                "subject": subject,
                "blockers": blocker_list.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root("operator-command-checklist-blockers", &leaves)
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "PQ-RESERVE-PRIVACY-OPERATOR-COMMAND-CHECKLIST-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}

fn stable_id(kind: &str, label: &str, ordinal: u64) -> String {
    domain_hash(
        "PQ-RESERVE-PRIVACY-OPERATOR-COMMAND-CHECKLIST-ID",
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
        "PQ-RESERVE-PRIVACY-OPERATOR-COMMAND-CHECKLIST-SAMPLE-ROOT",
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

fn ensure_root(label: &str, value: &str) -> Result<()> {
    ensure_non_empty(label, value)?;
    ensure(value.len() >= 32, &format!("{label} must be root-like"))
}

fn ensure_bps(label: &str, value: u16) -> Result<()> {
    ensure(value <= 10_000, &format!("{label} must be <= 10000"))
}

fn ensure_bps_at_least(label: &str, value: u16, floor: u16) -> Result<()> {
    ensure(value >= floor, &format!("{label} must be >= {floor}"))
}
