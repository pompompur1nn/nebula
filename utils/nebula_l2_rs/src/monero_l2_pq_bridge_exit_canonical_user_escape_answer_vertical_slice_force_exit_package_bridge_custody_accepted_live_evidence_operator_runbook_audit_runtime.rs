use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageBridgeCustodyAcceptedLiveEvidenceOperatorRunbookAuditRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_BRIDGE_CUSTODY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_RUNBOOK_AUDIT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-bridge-custody-accepted-live-evidence-operator-runbook-audit-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_BRIDGE_CUSTODY_ACCEPTED_LIVE_EVIDENCE_OPERATOR_RUNBOOK_AUDIT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RUNBOOK_AUDIT_SUITE: &str =
    "monero-l2-pq-bridge-custody-accepted-live-evidence-operator-runbook-audit-v1";
pub const DEFAULT_RUNBOOK_ID: &str =
    "bridge-custody-accepted-live-evidence-operator-runbook-devnet-0001";
pub const DEFAULT_RELEASE_DASHBOARD_ID: &str =
    "release-dashboard-force-exit-package-custody-readiness-devnet-0001";
pub const DEFAULT_ACCEPTANCE_EPOCH: u64 = 82;
pub const DEFAULT_MONERO_RELEASE_HEIGHT: u64 = 2_912_880;
pub const DEFAULT_L2_RELEASE_HEIGHT: u64 = 1_444_208;
pub const DEFAULT_REQUIRED_SIGNER_COUNT: u64 = 4;
pub const DEFAULT_REQUIRED_QUORUM_WEIGHT: u64 = 67;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_RESERVE_HANDOFF_MIN_CONFIRMATIONS: u64 = 12;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunbookStepKind {
    CustodySignerQuorum,
    MoneroReleaseObservation,
    ReserveHandoffConfirmation,
    ChallengeWindowChecklist,
    FailClosedBlockerReview,
    ReleaseDashboardReadiness,
}

impl RunbookStepKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CustodySignerQuorum => "custody_signer_quorum",
            Self::MoneroReleaseObservation => "monero_release_observation",
            Self::ReserveHandoffConfirmation => "reserve_handoff_confirmation",
            Self::ChallengeWindowChecklist => "challenge_window_checklist",
            Self::FailClosedBlockerReview => "fail_closed_blocker_review",
            Self::ReleaseDashboardReadiness => "release_dashboard_readiness",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Accepted,
    Pending,
    Rejected,
    Blocked,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Pending => "pending",
            Self::Rejected => "rejected",
            Self::Blocked => "blocked",
        }
    }

    pub fn permits_release(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DashboardReadiness {
    Ready,
    HeldForReview,
    FailClosed,
}

impl DashboardReadiness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::HeldForReview => "held_for_review",
            Self::FailClosed => "fail_closed",
        }
    }

    pub fn permits_release(self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub runbook_audit_suite: String,
    pub runbook_id: String,
    pub release_dashboard_id: String,
    pub acceptance_epoch: u64,
    pub monero_release_height: u64,
    pub l2_release_height: u64,
    pub required_signer_count: u64,
    pub required_quorum_weight: u64,
    pub challenge_window_blocks: u64,
    pub reserve_handoff_min_confirmations: u64,
    pub require_dual_pq_signatures: bool,
    pub require_monero_release_observation: bool,
    pub require_reserve_handoff: bool,
    pub require_challenge_window_clear: bool,
    pub fail_closed_on_blocker: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            runbook_audit_suite: RUNBOOK_AUDIT_SUITE.to_string(),
            runbook_id: DEFAULT_RUNBOOK_ID.to_string(),
            release_dashboard_id: DEFAULT_RELEASE_DASHBOARD_ID.to_string(),
            acceptance_epoch: DEFAULT_ACCEPTANCE_EPOCH,
            monero_release_height: DEFAULT_MONERO_RELEASE_HEIGHT,
            l2_release_height: DEFAULT_L2_RELEASE_HEIGHT,
            required_signer_count: DEFAULT_REQUIRED_SIGNER_COUNT,
            required_quorum_weight: DEFAULT_REQUIRED_QUORUM_WEIGHT,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            reserve_handoff_min_confirmations: DEFAULT_RESERVE_HANDOFF_MIN_CONFIRMATIONS,
            require_dual_pq_signatures: true,
            require_monero_release_observation: true,
            require_reserve_handoff: true,
            require_challenge_window_clear: true,
            fail_closed_on_blocker: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "runbook_audit_suite": self.runbook_audit_suite,
            "runbook_id": self.runbook_id,
            "release_dashboard_id": self.release_dashboard_id,
            "acceptance_epoch": self.acceptance_epoch,
            "monero_release_height": self.monero_release_height,
            "l2_release_height": self.l2_release_height,
            "required_signer_count": self.required_signer_count,
            "required_quorum_weight": self.required_quorum_weight,
            "challenge_window_blocks": self.challenge_window_blocks,
            "reserve_handoff_min_confirmations": self.reserve_handoff_min_confirmations,
            "require_dual_pq_signatures": self.require_dual_pq_signatures,
            "require_monero_release_observation": self.require_monero_release_observation,
            "require_reserve_handoff": self.require_reserve_handoff,
            "require_challenge_window_clear": self.require_challenge_window_clear,
            "fail_closed_on_blocker": self.fail_closed_on_blocker,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CustodySignerQuorumStep {
    pub step_id: String,
    pub signer_id: String,
    pub ordinal: u64,
    pub quorum_weight: u64,
    pub ml_dsa_attestation_root: String,
    pub slh_dsa_attestation_root: String,
    pub custody_acceptance_root: String,
    pub live_evidence_import_root: String,
    pub operator_ack_root: String,
    pub status: EvidenceStatus,
}

impl CustodySignerQuorumStep {
    pub fn devnet(config: &Config, ordinal: u64, signer_id: &str, quorum_weight: u64) -> Self {
        let step_id = step_id(
            config,
            RunbookStepKind::CustodySignerQuorum,
            ordinal,
            signer_id,
        );
        let ml_dsa_attestation_root =
            signer_attestation_root(config, signer_id, ordinal, "ml-dsa-87", quorum_weight);
        let slh_dsa_attestation_root = signer_attestation_root(
            config,
            signer_id,
            ordinal,
            "slh-dsa-shake-256f",
            quorum_weight,
        );
        let custody_acceptance_root = custody_acceptance_root(
            config,
            signer_id,
            ordinal,
            &ml_dsa_attestation_root,
            &slh_dsa_attestation_root,
        );
        let live_evidence_import_root = live_evidence_import_root(
            config,
            signer_id,
            RunbookStepKind::CustodySignerQuorum,
            &custody_acceptance_root,
        );
        let operator_ack_root = operator_ack_root(config, &step_id, &live_evidence_import_root);
        Self {
            step_id,
            signer_id: signer_id.to_string(),
            ordinal,
            quorum_weight,
            ml_dsa_attestation_root,
            slh_dsa_attestation_root,
            custody_acceptance_root,
            live_evidence_import_root,
            operator_ack_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "step_id": self.step_id,
            "signer_id": self.signer_id,
            "ordinal": self.ordinal,
            "quorum_weight": self.quorum_weight,
            "ml_dsa_attestation_root": self.ml_dsa_attestation_root,
            "slh_dsa_attestation_root": self.slh_dsa_attestation_root,
            "custody_acceptance_root": self.custody_acceptance_root,
            "live_evidence_import_root": self.live_evidence_import_root,
            "operator_ack_root": self.operator_ack_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("custody_signer_quorum_step", &self.public_record())
    }

    pub fn is_accepted(&self) -> bool {
        self.status.permits_release()
            && !self.ml_dsa_attestation_root.is_empty()
            && !self.slh_dsa_attestation_root.is_empty()
            && !self.custody_acceptance_root.is_empty()
            && !self.live_evidence_import_root.is_empty()
            && !self.operator_ack_root.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MoneroReleaseObservationReview {
    pub review_id: String,
    pub monero_release_txid: String,
    pub observed_height: u64,
    pub release_view_key_root: String,
    pub output_scan_root: String,
    pub amount_commitment_root: String,
    pub release_destination_root: String,
    pub observation_witness_root: String,
    pub reviewer_ack_root: String,
    pub status: EvidenceStatus,
}

impl MoneroReleaseObservationReview {
    pub fn devnet(config: &Config) -> Self {
        let review_id = step_id(
            config,
            RunbookStepKind::MoneroReleaseObservation,
            1,
            "monero-release-observer",
        );
        let monero_release_txid = domain_hash(
            "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-MONERO-RELEASE-TXID",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.runbook_id),
                HashPart::U64(config.monero_release_height),
            ],
        );
        let release_view_key_root = release_view_key_root(config, &monero_release_txid);
        let output_scan_root = output_scan_root(config, &monero_release_txid);
        let amount_commitment_root = amount_commitment_root(config, &monero_release_txid);
        let release_destination_root = release_destination_root(config, &monero_release_txid);
        let observation_witness_root = observation_witness_root(
            config,
            &release_view_key_root,
            &output_scan_root,
            &amount_commitment_root,
            &release_destination_root,
        );
        let reviewer_ack_root = operator_ack_root(config, &review_id, &observation_witness_root);
        Self {
            review_id,
            monero_release_txid,
            observed_height: config.monero_release_height,
            release_view_key_root,
            output_scan_root,
            amount_commitment_root,
            release_destination_root,
            observation_witness_root,
            reviewer_ack_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "review_id": self.review_id,
            "monero_release_txid": self.monero_release_txid,
            "observed_height": self.observed_height,
            "release_view_key_root": self.release_view_key_root,
            "output_scan_root": self.output_scan_root,
            "amount_commitment_root": self.amount_commitment_root,
            "release_destination_root": self.release_destination_root,
            "observation_witness_root": self.observation_witness_root,
            "reviewer_ack_root": self.reviewer_ack_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("monero_release_observation_review", &self.public_record())
    }

    pub fn is_accepted(&self) -> bool {
        self.status.permits_release()
            && !self.monero_release_txid.is_empty()
            && !self.release_view_key_root.is_empty()
            && !self.output_scan_root.is_empty()
            && !self.amount_commitment_root.is_empty()
            && !self.release_destination_root.is_empty()
            && !self.observation_witness_root.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveHandoffConfirmation {
    pub confirmation_id: String,
    pub reserve_operator_id: String,
    pub handoff_height: u64,
    pub reserve_balance_root: String,
    pub custody_delta_root: String,
    pub emergency_recovery_root: String,
    pub reserve_ack_root: String,
    pub min_confirmations_observed: u64,
    pub status: EvidenceStatus,
}

impl ReserveHandoffConfirmation {
    pub fn devnet(config: &Config) -> Self {
        let confirmation_id = step_id(
            config,
            RunbookStepKind::ReserveHandoffConfirmation,
            1,
            "reserve-handoff",
        );
        let reserve_operator_id = "reserve-operator-devnet-primary".to_string();
        let handoff_height = config.l2_release_height + config.reserve_handoff_min_confirmations;
        let reserve_balance_root = reserve_balance_root(config, &reserve_operator_id);
        let custody_delta_root = custody_delta_root(config, &reserve_operator_id);
        let emergency_recovery_root = emergency_recovery_root(config, &reserve_operator_id);
        let reserve_ack_root = reserve_ack_root(
            config,
            &confirmation_id,
            &reserve_balance_root,
            &custody_delta_root,
            &emergency_recovery_root,
        );
        Self {
            confirmation_id,
            reserve_operator_id,
            handoff_height,
            reserve_balance_root,
            custody_delta_root,
            emergency_recovery_root,
            reserve_ack_root,
            min_confirmations_observed: config.reserve_handoff_min_confirmations,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "confirmation_id": self.confirmation_id,
            "reserve_operator_id": self.reserve_operator_id,
            "handoff_height": self.handoff_height,
            "reserve_balance_root": self.reserve_balance_root,
            "custody_delta_root": self.custody_delta_root,
            "emergency_recovery_root": self.emergency_recovery_root,
            "reserve_ack_root": self.reserve_ack_root,
            "min_confirmations_observed": self.min_confirmations_observed,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("reserve_handoff_confirmation", &self.public_record())
    }

    pub fn is_accepted(&self, config: &Config) -> bool {
        self.status.permits_release()
            && self.min_confirmations_observed >= config.reserve_handoff_min_confirmations
            && !self.reserve_balance_root.is_empty()
            && !self.custody_delta_root.is_empty()
            && !self.emergency_recovery_root.is_empty()
            && !self.reserve_ack_root.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeWindowChecklist {
    pub checklist_id: String,
    pub challenge_window_start_height: u64,
    pub challenge_window_end_height: u64,
    pub current_observed_height: u64,
    pub dispute_scan_root: String,
    pub watchtower_ack_root: String,
    pub timeout_proof_root: String,
    pub no_pending_challenge_root: String,
    pub checklist_ack_root: String,
    pub status: EvidenceStatus,
}

impl ChallengeWindowChecklist {
    pub fn devnet(config: &Config) -> Self {
        let checklist_id = step_id(
            config,
            RunbookStepKind::ChallengeWindowChecklist,
            1,
            "challenge-window",
        );
        let challenge_window_start_height = config.l2_release_height;
        let challenge_window_end_height =
            challenge_window_start_height + config.challenge_window_blocks;
        let current_observed_height = challenge_window_end_height + 1;
        let dispute_scan_root = dispute_scan_root(config, challenge_window_start_height);
        let watchtower_ack_root = watchtower_ack_root(config, &dispute_scan_root);
        let timeout_proof_root = timeout_proof_root(config, challenge_window_end_height);
        let no_pending_challenge_root =
            no_pending_challenge_root(config, &dispute_scan_root, &timeout_proof_root);
        let checklist_ack_root =
            operator_ack_root(config, &checklist_id, &no_pending_challenge_root);
        Self {
            checklist_id,
            challenge_window_start_height,
            challenge_window_end_height,
            current_observed_height,
            dispute_scan_root,
            watchtower_ack_root,
            timeout_proof_root,
            no_pending_challenge_root,
            checklist_ack_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "checklist_id": self.checklist_id,
            "challenge_window_start_height": self.challenge_window_start_height,
            "challenge_window_end_height": self.challenge_window_end_height,
            "current_observed_height": self.current_observed_height,
            "dispute_scan_root": self.dispute_scan_root,
            "watchtower_ack_root": self.watchtower_ack_root,
            "timeout_proof_root": self.timeout_proof_root,
            "no_pending_challenge_root": self.no_pending_challenge_root,
            "checklist_ack_root": self.checklist_ack_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("challenge_window_checklist", &self.public_record())
    }

    pub fn is_clear(&self, config: &Config) -> bool {
        self.status.permits_release()
            && self.challenge_window_end_height
                >= self.challenge_window_start_height + config.challenge_window_blocks
            && self.current_observed_height > self.challenge_window_end_height
            && !self.dispute_scan_root.is_empty()
            && !self.watchtower_ack_root.is_empty()
            && !self.timeout_proof_root.is_empty()
            && !self.no_pending_challenge_root.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FailClosedBlocker {
    pub blocker_id: String,
    pub blocker_kind: String,
    pub severity: u64,
    pub evidence_root: String,
    pub remediation_root: String,
    pub cleared_root: String,
    pub status: EvidenceStatus,
}

impl FailClosedBlocker {
    pub fn cleared(config: &Config, ordinal: u64, blocker_kind: &str) -> Self {
        let blocker_id = step_id(
            config,
            RunbookStepKind::FailClosedBlockerReview,
            ordinal,
            blocker_kind,
        );
        let evidence_root = blocker_evidence_root(config, blocker_kind, ordinal);
        let remediation_root = blocker_remediation_root(config, blocker_kind, &evidence_root);
        let cleared_root = blocker_cleared_root(config, blocker_kind, &remediation_root);
        Self {
            blocker_id,
            blocker_kind: blocker_kind.to_string(),
            severity: 0,
            evidence_root,
            remediation_root,
            cleared_root,
            status: EvidenceStatus::Accepted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "blocker_kind": self.blocker_kind,
            "severity": self.severity,
            "evidence_root": self.evidence_root,
            "remediation_root": self.remediation_root,
            "cleared_root": self.cleared_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("fail_closed_blocker", &self.public_record())
    }

    pub fn is_cleared(&self) -> bool {
        self.status.permits_release()
            && self.severity == 0
            && !self.evidence_root.is_empty()
            && !self.remediation_root.is_empty()
            && !self.cleared_root.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseDashboardBinding {
    pub dashboard_id: String,
    pub readiness: DashboardReadiness,
    pub custody_quorum_root: String,
    pub monero_release_observation_root: String,
    pub reserve_handoff_root: String,
    pub challenge_window_root: String,
    pub fail_closed_blocker_root: String,
    pub live_evidence_import_root: String,
    pub release_readiness_root: String,
    pub operator_runbook_audit_root: String,
}

impl ReleaseDashboardBinding {
    pub fn from_parts(
        config: &Config,
        counters: &Counters,
        roots: &Roots,
        blockers_clear: bool,
    ) -> Self {
        let readiness = if config.fail_closed_on_blocker && !blockers_clear {
            DashboardReadiness::FailClosed
        } else if counters.accepted_signer_count < config.required_signer_count
            || counters.accepted_quorum_weight < config.required_quorum_weight
            || counters.accepted_review_count < counters.required_review_count
        {
            DashboardReadiness::HeldForReview
        } else {
            DashboardReadiness::Ready
        };
        let live_evidence_import_root = release_dashboard_live_import_root(
            config,
            &roots.custody_quorum_root,
            &roots.monero_release_observation_root,
            &roots.reserve_handoff_root,
            &roots.challenge_window_root,
            &roots.fail_closed_blocker_root,
        );
        let release_readiness_root = release_readiness_root(
            config,
            readiness,
            &live_evidence_import_root,
            &roots.audit_trail_root,
        );
        let operator_runbook_audit_root = operator_runbook_audit_root(
            config,
            &release_readiness_root,
            &roots.operator_ack_root,
            &roots.counters_root,
        );
        Self {
            dashboard_id: config.release_dashboard_id.clone(),
            readiness,
            custody_quorum_root: roots.custody_quorum_root.clone(),
            monero_release_observation_root: roots.monero_release_observation_root.clone(),
            reserve_handoff_root: roots.reserve_handoff_root.clone(),
            challenge_window_root: roots.challenge_window_root.clone(),
            fail_closed_blocker_root: roots.fail_closed_blocker_root.clone(),
            live_evidence_import_root,
            release_readiness_root,
            operator_runbook_audit_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "dashboard_id": self.dashboard_id,
            "readiness": self.readiness.as_str(),
            "custody_quorum_root": self.custody_quorum_root,
            "monero_release_observation_root": self.monero_release_observation_root,
            "reserve_handoff_root": self.reserve_handoff_root,
            "challenge_window_root": self.challenge_window_root,
            "fail_closed_blocker_root": self.fail_closed_blocker_root,
            "live_evidence_import_root": self.live_evidence_import_root,
            "release_readiness_root": self.release_readiness_root,
            "operator_runbook_audit_root": self.operator_runbook_audit_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_dashboard_binding", &self.public_record())
    }

    pub fn permits_release(&self) -> bool {
        self.readiness.permits_release()
            && !self.live_evidence_import_root.is_empty()
            && !self.release_readiness_root.is_empty()
            && !self.operator_runbook_audit_root.is_empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub required_signer_count: u64,
    pub accepted_signer_count: u64,
    pub required_quorum_weight: u64,
    pub accepted_quorum_weight: u64,
    pub required_review_count: u64,
    pub accepted_review_count: u64,
    pub blocker_count: u64,
    pub cleared_blocker_count: u64,
    pub fail_closed_blocker_count: u64,
}

impl Counters {
    pub fn from_parts(
        config: &Config,
        signers: &[CustodySignerQuorumStep],
        monero_review: &MoneroReleaseObservationReview,
        reserve_handoff: &ReserveHandoffConfirmation,
        challenge_window: &ChallengeWindowChecklist,
        blockers: &[FailClosedBlocker],
    ) -> Self {
        let accepted_signer_count =
            signers.iter().filter(|signer| signer.is_accepted()).count() as u64;
        let accepted_quorum_weight = signers
            .iter()
            .filter(|signer| signer.is_accepted())
            .map(|signer| signer.quorum_weight)
            .sum();
        let monero_accepted =
            !config.require_monero_release_observation || monero_review.is_accepted();
        let reserve_accepted =
            !config.require_reserve_handoff || reserve_handoff.is_accepted(config);
        let challenge_accepted =
            !config.require_challenge_window_clear || challenge_window.is_clear(config);
        let accepted_review_count =
            count_true(&[monero_accepted, reserve_accepted, challenge_accepted]);
        let blocker_count = blockers.len() as u64;
        let cleared_blocker_count = blockers
            .iter()
            .filter(|blocker| blocker.is_cleared())
            .count() as u64;
        let fail_closed_blocker_count = blockers
            .iter()
            .filter(|blocker| !blocker.is_cleared())
            .count() as u64;
        Self {
            required_signer_count: config.required_signer_count,
            accepted_signer_count,
            required_quorum_weight: config.required_quorum_weight,
            accepted_quorum_weight,
            required_review_count: 3,
            accepted_review_count,
            blocker_count,
            cleared_blocker_count,
            fail_closed_blocker_count,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "required_signer_count": self.required_signer_count,
            "accepted_signer_count": self.accepted_signer_count,
            "required_quorum_weight": self.required_quorum_weight,
            "accepted_quorum_weight": self.accepted_quorum_weight,
            "required_review_count": self.required_review_count,
            "accepted_review_count": self.accepted_review_count,
            "blocker_count": self.blocker_count,
            "cleared_blocker_count": self.cleared_blocker_count,
            "fail_closed_blocker_count": self.fail_closed_blocker_count,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub custody_quorum_root: String,
    pub monero_release_observation_root: String,
    pub reserve_handoff_root: String,
    pub challenge_window_root: String,
    pub fail_closed_blocker_root: String,
    pub release_dashboard_binding_root: String,
    pub audit_trail_root: String,
    pub operator_ack_root: String,
    pub counters_root: String,
}

impl Roots {
    pub fn from_parts(
        config: &Config,
        signers: &[CustodySignerQuorumStep],
        monero_review: &MoneroReleaseObservationReview,
        reserve_handoff: &ReserveHandoffConfirmation,
        challenge_window: &ChallengeWindowChecklist,
        blockers: &[FailClosedBlocker],
        counters: &Counters,
    ) -> Self {
        let config_root = config.state_root();
        let custody_quorum_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-SIGNER-QUORUM",
            &signers
                .iter()
                .map(CustodySignerQuorumStep::public_record)
                .collect::<Vec<_>>(),
        );
        let monero_release_observation_root = monero_review.state_root();
        let reserve_handoff_root = reserve_handoff.state_root();
        let challenge_window_root = challenge_window.state_root();
        let fail_closed_blocker_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-FAIL-CLOSED-BLOCKERS",
            &blockers
                .iter()
                .map(FailClosedBlocker::public_record)
                .collect::<Vec<_>>(),
        );
        let audit_trail_root = audit_trail_root(
            config,
            &custody_quorum_root,
            &monero_release_observation_root,
            &reserve_handoff_root,
            &challenge_window_root,
            &fail_closed_blocker_root,
        );
        let operator_ack_root = operator_ack_root(config, &config.runbook_id, &audit_trail_root);
        let counters_root = counters.state_root();
        let release_dashboard_binding_root = empty_root("RELEASE-DASHBOARD-BINDING-PENDING");
        Self {
            config_root,
            custody_quorum_root,
            monero_release_observation_root,
            reserve_handoff_root,
            challenge_window_root,
            fail_closed_blocker_root,
            release_dashboard_binding_root,
            audit_trail_root,
            operator_ack_root,
            counters_root,
        }
    }

    pub fn with_release_dashboard_binding_root(
        mut self,
        release_dashboard_binding_root: String,
    ) -> Self {
        self.release_dashboard_binding_root = release_dashboard_binding_root;
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "custody_quorum_root": self.custody_quorum_root,
            "monero_release_observation_root": self.monero_release_observation_root,
            "reserve_handoff_root": self.reserve_handoff_root,
            "challenge_window_root": self.challenge_window_root,
            "fail_closed_blocker_root": self.fail_closed_blocker_root,
            "release_dashboard_binding_root": self.release_dashboard_binding_root,
            "audit_trail_root": self.audit_trail_root,
            "operator_ack_root": self.operator_ack_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub custody_signer_quorum_steps: Vec<CustodySignerQuorumStep>,
    pub monero_release_observation_review: MoneroReleaseObservationReview,
    pub reserve_handoff_confirmation: ReserveHandoffConfirmation,
    pub challenge_window_checklist: ChallengeWindowChecklist,
    pub fail_closed_blockers: Vec<FailClosedBlocker>,
    pub release_dashboard_binding: ReleaseDashboardBinding,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn new(
        config: Config,
        custody_signer_quorum_steps: Vec<CustodySignerQuorumStep>,
        monero_release_observation_review: MoneroReleaseObservationReview,
        reserve_handoff_confirmation: ReserveHandoffConfirmation,
        challenge_window_checklist: ChallengeWindowChecklist,
        fail_closed_blockers: Vec<FailClosedBlocker>,
    ) -> Result<Self> {
        Ok(build_state(
            config,
            custody_signer_quorum_steps,
            monero_release_observation_review,
            reserve_handoff_confirmation,
            challenge_window_checklist,
            fail_closed_blockers,
        ))
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "custody_signer_quorum_steps": self
                .custody_signer_quorum_steps
                .iter()
                .map(CustodySignerQuorumStep::public_record)
                .collect::<Vec<_>>(),
            "monero_release_observation_review": self.monero_release_observation_review.public_record(),
            "reserve_handoff_confirmation": self.reserve_handoff_confirmation.public_record(),
            "challenge_window_checklist": self.challenge_window_checklist.public_record(),
            "fail_closed_blockers": self
                .fail_closed_blockers
                .iter()
                .map(FailClosedBlocker::public_record)
                .collect::<Vec<_>>(),
            "release_dashboard_binding": self.release_dashboard_binding.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-AUDIT-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.roots.state_root()),
                HashPart::Str(&self.counters.state_root()),
                HashPart::Str(&self.release_dashboard_binding.state_root()),
            ],
        )
    }

    pub fn release_ready(&self) -> bool {
        self.release_dashboard_binding.permits_release()
            && self.counters.accepted_signer_count >= self.config.required_signer_count
            && self.counters.accepted_quorum_weight >= self.config.required_quorum_weight
            && self.counters.accepted_review_count >= self.counters.required_review_count
            && self.counters.fail_closed_blocker_count == 0
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let custody_signer_quorum_steps = vec![
        CustodySignerQuorumStep::devnet(&config, 1, "custody-signer-alpha", 20),
        CustodySignerQuorumStep::devnet(&config, 2, "custody-signer-beta", 18),
        CustodySignerQuorumStep::devnet(&config, 3, "custody-signer-gamma", 17),
        CustodySignerQuorumStep::devnet(&config, 4, "custody-signer-delta", 16),
    ];
    let monero_release_observation_review = MoneroReleaseObservationReview::devnet(&config);
    let reserve_handoff_confirmation = ReserveHandoffConfirmation::devnet(&config);
    let challenge_window_checklist = ChallengeWindowChecklist::devnet(&config);
    let fail_closed_blockers = vec![
        FailClosedBlocker::cleared(&config, 1, "custody-quorum-missing-signature"),
        FailClosedBlocker::cleared(&config, 2, "monero-release-observation-conflict"),
        FailClosedBlocker::cleared(&config, 3, "reserve-handoff-confirmation-gap"),
        FailClosedBlocker::cleared(&config, 4, "challenge-window-open-dispute"),
    ];
    build_state(
        config,
        custody_signer_quorum_steps,
        monero_release_observation_review,
        reserve_handoff_confirmation,
        challenge_window_checklist,
        fail_closed_blockers,
    )
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn build_state(
    config: Config,
    custody_signer_quorum_steps: Vec<CustodySignerQuorumStep>,
    monero_release_observation_review: MoneroReleaseObservationReview,
    reserve_handoff_confirmation: ReserveHandoffConfirmation,
    challenge_window_checklist: ChallengeWindowChecklist,
    fail_closed_blockers: Vec<FailClosedBlocker>,
) -> State {
    let counters = Counters::from_parts(
        &config,
        &custody_signer_quorum_steps,
        &monero_release_observation_review,
        &reserve_handoff_confirmation,
        &challenge_window_checklist,
        &fail_closed_blockers,
    );
    let roots = Roots::from_parts(
        &config,
        &custody_signer_quorum_steps,
        &monero_release_observation_review,
        &reserve_handoff_confirmation,
        &challenge_window_checklist,
        &fail_closed_blockers,
        &counters,
    );
    let release_dashboard_binding = ReleaseDashboardBinding::from_parts(
        &config,
        &counters,
        &roots,
        counters.fail_closed_blocker_count == 0,
    );
    let roots = roots.with_release_dashboard_binding_root(release_dashboard_binding.state_root());
    State {
        config,
        custody_signer_quorum_steps,
        monero_release_observation_review,
        reserve_handoff_confirmation,
        challenge_window_checklist,
        fail_closed_blockers,
        release_dashboard_binding,
        counters,
        roots,
    }
}

fn count_true(values: &[bool]) -> u64 {
    values.iter().filter(|value| **value).count() as u64
}

fn step_id(config: &Config, kind: RunbookStepKind, ordinal: u64, subject: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-STEP-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.runbook_id),
            HashPart::Str(kind.as_str()),
            HashPart::U64(ordinal),
            HashPart::Str(subject),
        ],
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-RECORD",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
    )
}

fn empty_root(label: &str) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-EMPTY",
        &[json!({
            "label": label,
            "protocol_version": PROTOCOL_VERSION,
        })],
    )
}

fn signer_attestation_root(
    config: &Config,
    signer_id: &str,
    ordinal: u64,
    signature_scheme: &str,
    quorum_weight: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-SIGNER-ATTESTATION",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.runbook_id),
            HashPart::Str(signer_id),
            HashPart::U64(ordinal),
            HashPart::Str(signature_scheme),
            HashPart::U64(quorum_weight),
            HashPart::U64(config.acceptance_epoch),
        ],
    )
}

fn custody_acceptance_root(
    config: &Config,
    signer_id: &str,
    ordinal: u64,
    ml_dsa_root: &str,
    slh_dsa_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-CUSTODY-ACCEPTANCE",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.runbook_id),
            HashPart::Str(signer_id),
            HashPart::U64(ordinal),
            HashPart::Str(ml_dsa_root),
            HashPart::Str(slh_dsa_root),
        ],
    )
}

fn live_evidence_import_root(
    config: &Config,
    subject: &str,
    kind: RunbookStepKind,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-LIVE-EVIDENCE-IMPORT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.runbook_id),
            HashPart::Str(subject),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_root),
            HashPart::U64(config.acceptance_epoch),
        ],
    )
}

fn operator_ack_root(config: &Config, subject: &str, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-OPERATOR-ACK",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.runbook_id),
            HashPart::Str(subject),
            HashPart::Str(evidence_root),
            HashPart::U64(config.acceptance_epoch),
        ],
    )
}

fn release_view_key_root(config: &Config, txid: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-RELEASE-VIEW-KEY",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.release_dashboard_id),
            HashPart::Str(txid),
        ],
    )
}

fn output_scan_root(config: &Config, txid: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-OUTPUT-SCAN",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.release_dashboard_id),
            HashPart::Str(txid),
            HashPart::U64(config.monero_release_height),
        ],
    )
}

fn amount_commitment_root(config: &Config, txid: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-AMOUNT-COMMITMENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.runbook_id),
            HashPart::Str(txid),
        ],
    )
}

fn release_destination_root(config: &Config, txid: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-RELEASE-DESTINATION",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.release_dashboard_id),
            HashPart::Str(txid),
            HashPart::U64(config.l2_release_height),
        ],
    )
}

fn observation_witness_root(
    config: &Config,
    release_view_key_root: &str,
    output_scan_root: &str,
    amount_commitment_root: &str,
    release_destination_root: &str,
) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-OBSERVATION-WITNESS",
        &[
            json!({"kind": "release_view_key", "root": release_view_key_root}),
            json!({"kind": "output_scan", "root": output_scan_root}),
            json!({"kind": "amount_commitment", "root": amount_commitment_root}),
            json!({"kind": "release_destination", "root": release_destination_root}),
            json!({"kind": "runbook", "root": config.runbook_id}),
        ],
    )
}

fn reserve_balance_root(config: &Config, reserve_operator_id: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-RESERVE-BALANCE",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.runbook_id),
            HashPart::Str(reserve_operator_id),
            HashPart::U64(config.l2_release_height),
        ],
    )
}

fn custody_delta_root(config: &Config, reserve_operator_id: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-CUSTODY-DELTA",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.runbook_id),
            HashPart::Str(reserve_operator_id),
            HashPart::U64(config.acceptance_epoch),
        ],
    )
}

fn emergency_recovery_root(config: &Config, reserve_operator_id: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-EMERGENCY-RECOVERY",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.release_dashboard_id),
            HashPart::Str(reserve_operator_id),
        ],
    )
}

fn reserve_ack_root(
    config: &Config,
    confirmation_id: &str,
    reserve_balance_root: &str,
    custody_delta_root: &str,
    emergency_recovery_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-RESERVE-ACK",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(confirmation_id),
            HashPart::Str(reserve_balance_root),
            HashPart::Str(custody_delta_root),
            HashPart::Str(emergency_recovery_root),
            HashPart::U64(config.reserve_handoff_min_confirmations),
        ],
    )
}

fn dispute_scan_root(config: &Config, start_height: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-DISPUTE-SCAN",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.runbook_id),
            HashPart::U64(start_height),
            HashPart::U64(config.challenge_window_blocks),
        ],
    )
}

fn watchtower_ack_root(config: &Config, dispute_scan_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-WATCHTOWER-ACK",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.release_dashboard_id),
            HashPart::Str(dispute_scan_root),
        ],
    )
}

fn timeout_proof_root(config: &Config, end_height: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-TIMEOUT-PROOF",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.runbook_id),
            HashPart::U64(end_height),
        ],
    )
}

fn no_pending_challenge_root(
    config: &Config,
    dispute_scan_root: &str,
    timeout_proof_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-NO-PENDING-CHALLENGE",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.release_dashboard_id),
            HashPart::Str(dispute_scan_root),
            HashPart::Str(timeout_proof_root),
        ],
    )
}

fn blocker_evidence_root(config: &Config, blocker_kind: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-BLOCKER-EVIDENCE",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.runbook_id),
            HashPart::Str(blocker_kind),
            HashPart::U64(ordinal),
        ],
    )
}

fn blocker_remediation_root(config: &Config, blocker_kind: &str, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-BLOCKER-REMEDIATION",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.runbook_id),
            HashPart::Str(blocker_kind),
            HashPart::Str(evidence_root),
        ],
    )
}

fn blocker_cleared_root(config: &Config, blocker_kind: &str, remediation_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-BLOCKER-CLEARED",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.release_dashboard_id),
            HashPart::Str(blocker_kind),
            HashPart::Str(remediation_root),
        ],
    )
}

fn audit_trail_root(
    config: &Config,
    custody_quorum_root: &str,
    monero_release_observation_root: &str,
    reserve_handoff_root: &str,
    challenge_window_root: &str,
    fail_closed_blocker_root: &str,
) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-AUDIT-TRAIL",
        &[
            json!({"kind": "config", "root": config.state_root()}),
            json!({"kind": "custody_quorum", "root": custody_quorum_root}),
            json!({"kind": "monero_release_observation", "root": monero_release_observation_root}),
            json!({"kind": "reserve_handoff", "root": reserve_handoff_root}),
            json!({"kind": "challenge_window", "root": challenge_window_root}),
            json!({"kind": "fail_closed_blocker", "root": fail_closed_blocker_root}),
        ],
    )
}

fn release_dashboard_live_import_root(
    config: &Config,
    custody_quorum_root: &str,
    monero_release_observation_root: &str,
    reserve_handoff_root: &str,
    challenge_window_root: &str,
    fail_closed_blocker_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-DASHBOARD-LIVE-IMPORT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.release_dashboard_id),
            HashPart::Str(custody_quorum_root),
            HashPart::Str(monero_release_observation_root),
            HashPart::Str(reserve_handoff_root),
            HashPart::Str(challenge_window_root),
            HashPart::Str(fail_closed_blocker_root),
        ],
    )
}

fn release_readiness_root(
    config: &Config,
    readiness: DashboardReadiness,
    live_evidence_import_root: &str,
    audit_trail_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-RELEASE-READINESS",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.release_dashboard_id),
            HashPart::Str(readiness.as_str()),
            HashPart::Str(live_evidence_import_root),
            HashPart::Str(audit_trail_root),
        ],
    )
}

fn operator_runbook_audit_root(
    config: &Config,
    release_readiness_root: &str,
    operator_ack_root: &str,
    counters_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-CUSTODY-RUNBOOK-OPERATOR-AUDIT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.runbook_id),
            HashPart::Str(release_readiness_root),
            HashPart::Str(operator_ack_root),
            HashPart::Str(counters_root),
        ],
    )
}
