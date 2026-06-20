use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_canonical_end_to_end_escape_hatch_scorecard_runtime as scorecard,
    monero_l2_pq_bridge_exit_canonical_user_escape_security_review_final_release_acceptance_execution_receipt_runtime as acceptance_receipt,
    monero_l2_pq_bridge_exit_end_to_end_safety_case_runtime as safety_case, CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeSafetyAnswerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SAFETY_ANSWER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-safety-answer-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_SAFETY_ANSWER_RUNTIME_PROTOCOL_VERSION;

const DOMAIN: &str = "monero-l2-pq-bridge-exit-canonical-user-escape-safety-answer";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub answer_suite: String,
    pub answer_policy: String,
    pub min_answer_lanes: u64,
    pub min_blocker_cases: u64,
    pub require_end_to_end_safety_case: u64,
    pub require_escape_scorecard: u64,
    pub require_acceptance_execution_receipt: u64,
    pub require_wallet_force_exit: u64,
    pub require_operator_independent_escape: u64,
    pub require_pq_authority: u64,
    pub require_privacy_boundary: u64,
    pub require_release_hold: u64,
    pub production_release_allowed: u64,
    pub max_public_metadata_units: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            answer_suite: "monero-l2-pq-bridge-exit-user-escape-safety-answer-v1".to_string(),
            answer_policy: "conditional-user-escape-production-held-v1".to_string(),
            min_answer_lanes: 9,
            min_blocker_cases: 8,
            require_end_to_end_safety_case: 1,
            require_escape_scorecard: 1,
            require_acceptance_execution_receipt: 1,
            require_wallet_force_exit: 1,
            require_operator_independent_escape: 1,
            require_pq_authority: 1,
            require_privacy_boundary: 1,
            require_release_hold: 1,
            production_release_allowed: 0,
            max_public_metadata_units: 0,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "answer_suite": self.answer_suite,
            "answer_policy": self.answer_policy,
            "min_answer_lanes": self.min_answer_lanes,
            "min_blocker_cases": self.min_blocker_cases,
            "require_end_to_end_safety_case": self.require_end_to_end_safety_case,
            "require_escape_scorecard": self.require_escape_scorecard,
            "require_acceptance_execution_receipt": self.require_acceptance_execution_receipt,
            "require_wallet_force_exit": self.require_wallet_force_exit,
            "require_operator_independent_escape": self.require_operator_independent_escape,
            "require_pq_authority": self.require_pq_authority,
            "require_privacy_boundary": self.require_privacy_boundary,
            "require_release_hold": self.require_release_hold,
            "production_release_allowed": self.production_release_allowed,
            "max_public_metadata_units": self.max_public_metadata_units,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnswerLane {
    UserQuestion,
    EndToEndSafetyCase,
    EscapeScorecard,
    AcceptanceExecutionReceipt,
    WalletForceExit,
    OperatorIndependence,
    PqControlPlane,
    PrivacyBoundary,
    ProductionReleaseHold,
}

impl AnswerLane {
    pub fn ordered() -> [Self; 9] {
        [
            Self::UserQuestion,
            Self::EndToEndSafetyCase,
            Self::EscapeScorecard,
            Self::AcceptanceExecutionReceipt,
            Self::WalletForceExit,
            Self::OperatorIndependence,
            Self::PqControlPlane,
            Self::PrivacyBoundary,
            Self::ProductionReleaseHold,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserQuestion => "user_question",
            Self::EndToEndSafetyCase => "end_to_end_safety_case",
            Self::EscapeScorecard => "escape_scorecard",
            Self::AcceptanceExecutionReceipt => "acceptance_execution_receipt",
            Self::WalletForceExit => "wallet_force_exit",
            Self::OperatorIndependence => "operator_independence",
            Self::PqControlPlane => "pq_control_plane",
            Self::PrivacyBoundary => "privacy_boundary",
            Self::ProductionReleaseHold => "production_release_hold",
        }
    }

    pub fn owner_lane(self) -> &'static str {
        match self {
            Self::UserQuestion => "safety_answer_owner",
            Self::EndToEndSafetyCase => "e2e_safety_case_owner",
            Self::EscapeScorecard => "escape_scorecard_owner",
            Self::AcceptanceExecutionReceipt => "acceptance_receipt_owner",
            Self::WalletForceExit => "wallet_recovery_owner",
            Self::OperatorIndependence => "sequencer_failure_owner",
            Self::PqControlPlane => "pq_authority_owner",
            Self::PrivacyBoundary => "privacy_boundary_owner",
            Self::ProductionReleaseHold => "release_governance_owner",
        }
    }

    pub fn answer_claim(self) -> &'static str {
        match self {
            Self::UserQuestion => {
                "Can a user get in, transact privately, and force their way out if everyone else misbehaves?"
            }
            Self::EndToEndSafetyCase => {
                "The end-to-end safety case must cover the bridge/exit journey and blockers."
            }
            Self::EscapeScorecard => {
                "The escape scorecard must report no user-escape blockers."
            }
            Self::AcceptanceExecutionReceipt => {
                "The final acceptance execution receipt must bind release-held evidence roots."
            }
            Self::WalletForceExit => {
                "Wallet-local recovery roots must support forced exit without operator cooperation."
            }
            Self::OperatorIndependence => {
                "Every force-exit-critical step must be operator independent."
            }
            Self::PqControlPlane => {
                "PQ authority, custody, and crosscheck roots must protect release authorization."
            }
            Self::PrivacyBoundary => {
                "Public answer material must be roots-only and export no wallet linkage metadata."
            }
            Self::ProductionReleaseHold => {
                "Production release must remain held while cargo/runtime/audit gates are deferred."
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnswerBlockerKind {
    CargoRuntimeDeferred,
    SecurityAuditDeferred,
    ProductionReleaseHeld,
    MoneroBaseLayerVerifierAbsent,
    LiveEvidenceMissing,
    ReserveOrLiquidityNeedsLiveProof,
    PrivacyAuditNeedsClosure,
    ReleaseGovernanceNeedsExecution,
}

impl AnswerBlockerKind {
    pub fn ordered() -> [Self; 8] {
        [
            Self::CargoRuntimeDeferred,
            Self::SecurityAuditDeferred,
            Self::ProductionReleaseHeld,
            Self::MoneroBaseLayerVerifierAbsent,
            Self::LiveEvidenceMissing,
            Self::ReserveOrLiquidityNeedsLiveProof,
            Self::PrivacyAuditNeedsClosure,
            Self::ReleaseGovernanceNeedsExecution,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoRuntimeDeferred => "cargo_runtime_deferred",
            Self::SecurityAuditDeferred => "security_audit_deferred",
            Self::ProductionReleaseHeld => "production_release_held",
            Self::MoneroBaseLayerVerifierAbsent => "monero_base_layer_verifier_absent",
            Self::LiveEvidenceMissing => "live_evidence_missing",
            Self::ReserveOrLiquidityNeedsLiveProof => "reserve_or_liquidity_needs_live_proof",
            Self::PrivacyAuditNeedsClosure => "privacy_audit_needs_closure",
            Self::ReleaseGovernanceNeedsExecution => "release_governance_needs_execution",
        }
    }

    pub fn clearance(self) -> &'static str {
        match self {
            Self::CargoRuntimeDeferred => {
                "run cargo/runtime gates and bind execution roots into the acceptance receipt"
            }
            Self::SecurityAuditDeferred => {
                "attach signed security and privacy audit closure receipts"
            }
            Self::ProductionReleaseHeld => {
                "execute live release governance and explicitly unhold only after all roots pass"
            }
            Self::MoneroBaseLayerVerifierAbsent => {
                "keep trust-minimized watcher/quorum evidence explicit because Monero has no base-layer verifier"
            }
            Self::LiveEvidenceMissing => {
                "replace devnet/simulated roots with captured live Monero, wallet, and bridge evidence"
            }
            Self::ReserveOrLiquidityNeedsLiveProof => {
                "bind live reserve/liquidity sufficiency proofs before production release"
            }
            Self::PrivacyAuditNeedsClosure => {
                "close metadata, linkage, wallet-scan, and receipt privacy review"
            }
            Self::ReleaseGovernanceNeedsExecution => {
                "execute final acceptance and release governance receipts against live evidence"
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceBundle {
    pub safety_case_state_root: String,
    pub safety_case_report_root: String,
    pub safety_case_evidence_root: String,
    pub safety_case_blocker_root: String,
    pub safety_case_verdict: String,
    pub safety_case_readiness_label: String,
    pub safety_case_evidence_items: u64,
    pub safety_case_proven_items: u64,
    pub safety_case_watch_items: u64,
    pub safety_case_failed_items: u64,
    pub safety_case_deferred_gates: u64,
    pub safety_case_production_blockers: u64,
    pub scorecard_state_root: String,
    pub scorecard_answer_root: String,
    pub scorecard_verdict: String,
    pub scorecard_score: u64,
    pub scorecard_user_escape_clear: u64,
    pub scorecard_production_blocked: u64,
    pub scorecard_user_escape_blockers: u64,
    pub scorecard_production_blockers: u64,
    pub scorecard_deferred_stages: u64,
    pub acceptance_receipt_state_root: String,
    pub acceptance_receipt_binding_root: String,
    pub acceptance_receipt_hold_root: String,
    pub acceptance_receipt_blocker_root: String,
    pub acceptance_receipt_verdict_root: String,
    pub acceptance_receipt_status: String,
    pub acceptance_wallet_force_exit_supported: u64,
    pub acceptance_operator_independent_count: u64,
    pub acceptance_force_exit_critical_count: u64,
    pub acceptance_heavy_gates_executed: u64,
    pub acceptance_cargo_deferred_count: u64,
    pub acceptance_audit_deferred_count: u64,
    pub acceptance_production_blocker_count: u64,
    pub acceptance_privacy_boundary_count: u64,
    pub pq_authority_root: String,
    pub wallet_recovery_root: String,
    pub privacy_boundary_root: String,
    pub source_root: String,
}

impl SourceBundle {
    pub fn devnet() -> Self {
        let safety = safety_case::devnet();
        let scorecard = scorecard::devnet();
        let receipt = acceptance_receipt::devnet();
        Self::from_states(&safety, &scorecard, &receipt)
    }

    pub fn from_states(
        safety: &safety_case::State,
        scorecard: &scorecard::State,
        receipt: &acceptance_receipt::State,
    ) -> Self {
        let report = safety.latest_report.as_ref();
        let safety_case_report_root = match report {
            Some(report) => report.roots.report_root.clone(),
            None => record_root("missing-safety-report", &json!({"present": 0_u64})),
        };
        let safety_case_evidence_root = match report {
            Some(report) => report.roots.evidence_root.clone(),
            None => record_root("missing-safety-evidence", &json!({"present": 0_u64})),
        };
        let safety_case_blocker_root = match report {
            Some(report) => report.roots.blocker_root.clone(),
            None => record_root("missing-safety-blocker", &json!({"present": 0_u64})),
        };
        let safety_case_verdict = match report {
            Some(report) => report.verdict.as_str().to_string(),
            None => "missing".to_string(),
        };
        let safety_case_readiness_label = match report {
            Some(report) => report.readiness_label.clone(),
            None => "missing".to_string(),
        };
        let safety_case_evidence_items = report.map(|report| report.evidence_items).unwrap_or(0);
        let safety_case_proven_items = report.map(|report| report.proven_items).unwrap_or(0);
        let safety_case_watch_items = report.map(|report| report.watch_items).unwrap_or(0);
        let safety_case_failed_items = report.map(|report| report.failed_items).unwrap_or(1);
        let safety_case_deferred_gates = report.map(|report| report.deferred_gates).unwrap_or(1);
        let safety_case_production_blockers =
            report.map(|report| report.production_blockers).unwrap_or(1);
        let source_root = source_bundle_root(safety, scorecard, receipt);

        Self {
            safety_case_state_root: safety.state_root(),
            safety_case_report_root,
            safety_case_evidence_root,
            safety_case_blocker_root,
            safety_case_verdict,
            safety_case_readiness_label,
            safety_case_evidence_items,
            safety_case_proven_items,
            safety_case_watch_items,
            safety_case_failed_items,
            safety_case_deferred_gates,
            safety_case_production_blockers,
            scorecard_state_root: scorecard.state_root(),
            scorecard_answer_root: scorecard.answer.answer_root.clone(),
            scorecard_verdict: scorecard.answer.verdict.as_str().to_string(),
            scorecard_score: scorecard.score,
            scorecard_user_escape_clear: bool_to_u64(scorecard.user_escape_clear()),
            scorecard_production_blocked: bool_to_u64(scorecard.production_blocked()),
            scorecard_user_escape_blockers: scorecard.counters.user_escape_blockers,
            scorecard_production_blockers: scorecard.counters.production_blockers,
            scorecard_deferred_stages: scorecard.counters.deferred_stages,
            acceptance_receipt_state_root: receipt.state_root(),
            acceptance_receipt_binding_root: receipt.execution_receipt_binding_root.clone(),
            acceptance_receipt_hold_root: receipt.execution_hold_root.clone(),
            acceptance_receipt_blocker_root: receipt.execution_blocker_root.clone(),
            acceptance_receipt_verdict_root: receipt.verdict.verdict_root.clone(),
            acceptance_receipt_status: receipt.verdict.verdict_status.clone(),
            acceptance_wallet_force_exit_supported: receipt.verdict.wallet_force_exit_supported,
            acceptance_operator_independent_count: receipt
                .verdict
                .operator_independent_critical_count,
            acceptance_force_exit_critical_count: receipt.verdict.force_exit_critical_count,
            acceptance_heavy_gates_executed: receipt.verdict.heavy_gates_executed_count,
            acceptance_cargo_deferred_count: receipt.verdict.cargo_deferred_count,
            acceptance_audit_deferred_count: receipt.verdict.audit_deferred_count,
            acceptance_production_blocker_count: receipt.verdict.production_blocker_count,
            acceptance_privacy_boundary_count: receipt.verdict.privacy_boundary_count,
            pq_authority_root: receipt.source.pq_authority_root.clone(),
            wallet_recovery_root: receipt.source.execution_wallet_recovery_root.clone(),
            privacy_boundary_root: receipt.source.execution_encrypted_root.clone(),
            source_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "safety_case_state_root": self.safety_case_state_root,
            "safety_case_report_root": self.safety_case_report_root,
            "safety_case_evidence_root": self.safety_case_evidence_root,
            "safety_case_blocker_root": self.safety_case_blocker_root,
            "safety_case_verdict": self.safety_case_verdict,
            "safety_case_readiness_label": self.safety_case_readiness_label,
            "safety_case_evidence_items": self.safety_case_evidence_items,
            "safety_case_proven_items": self.safety_case_proven_items,
            "safety_case_watch_items": self.safety_case_watch_items,
            "safety_case_failed_items": self.safety_case_failed_items,
            "safety_case_deferred_gates": self.safety_case_deferred_gates,
            "safety_case_production_blockers": self.safety_case_production_blockers,
            "scorecard_state_root": self.scorecard_state_root,
            "scorecard_answer_root": self.scorecard_answer_root,
            "scorecard_verdict": self.scorecard_verdict,
            "scorecard_score": self.scorecard_score,
            "scorecard_user_escape_clear": self.scorecard_user_escape_clear,
            "scorecard_production_blocked": self.scorecard_production_blocked,
            "scorecard_user_escape_blockers": self.scorecard_user_escape_blockers,
            "scorecard_production_blockers": self.scorecard_production_blockers,
            "scorecard_deferred_stages": self.scorecard_deferred_stages,
            "acceptance_receipt_state_root": self.acceptance_receipt_state_root,
            "acceptance_receipt_binding_root": self.acceptance_receipt_binding_root,
            "acceptance_receipt_hold_root": self.acceptance_receipt_hold_root,
            "acceptance_receipt_blocker_root": self.acceptance_receipt_blocker_root,
            "acceptance_receipt_verdict_root": self.acceptance_receipt_verdict_root,
            "acceptance_receipt_status": self.acceptance_receipt_status,
            "acceptance_wallet_force_exit_supported": self.acceptance_wallet_force_exit_supported,
            "acceptance_operator_independent_count": self.acceptance_operator_independent_count,
            "acceptance_force_exit_critical_count": self.acceptance_force_exit_critical_count,
            "acceptance_heavy_gates_executed": self.acceptance_heavy_gates_executed,
            "acceptance_cargo_deferred_count": self.acceptance_cargo_deferred_count,
            "acceptance_audit_deferred_count": self.acceptance_audit_deferred_count,
            "acceptance_production_blocker_count": self.acceptance_production_blocker_count,
            "acceptance_privacy_boundary_count": self.acceptance_privacy_boundary_count,
            "pq_authority_root": self.pq_authority_root,
            "wallet_recovery_root": self.wallet_recovery_root,
            "privacy_boundary_root": self.privacy_boundary_root,
            "source_root": self.source_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("source-bundle", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswerCheck {
    pub ordinal: u64,
    pub lane: AnswerLane,
    pub owner_lane: String,
    pub claim: String,
    pub observed: String,
    pub source_root: String,
    pub evidence_root: String,
    pub answer_root: String,
    pub blocker_root: String,
    pub release_held: u64,
    pub check_root: String,
}

impl AnswerCheck {
    pub fn devnet(config: &Config, source: &SourceBundle, lane: AnswerLane, ordinal: u64) -> Self {
        let source_root = lane_source_root(source, lane);
        let observed = lane_observed(source, lane);
        let evidence_root = lane_evidence_root(config, source, lane, &source_root, &observed);
        let answer_root = lane_answer_root(config, source, lane, &evidence_root);
        let blocker_root = lane_blocker_root(config, source, lane, &answer_root);
        let check_root = answer_check_root(
            config,
            source,
            lane,
            ordinal,
            &source_root,
            &evidence_root,
            &answer_root,
            &blocker_root,
        );
        Self {
            ordinal,
            lane,
            owner_lane: lane.owner_lane().to_string(),
            claim: lane.answer_claim().to_string(),
            observed,
            source_root,
            evidence_root,
            answer_root,
            blocker_root,
            release_held: config.require_release_hold,
            check_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ordinal": self.ordinal,
            "lane": self.lane.as_str(),
            "owner_lane": self.owner_lane,
            "claim": self.claim,
            "observed": self.observed,
            "source_root": self.source_root,
            "evidence_root": self.evidence_root,
            "answer_root": self.answer_root,
            "blocker_root": self.blocker_root,
            "release_held": self.release_held,
            "check_root": self.check_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnswerBlockerCase {
    pub ordinal: u64,
    pub kind: AnswerBlockerKind,
    pub source_root: String,
    pub blocker_root: String,
    pub clearance: String,
    pub owner_lane: String,
    pub case_root: String,
}

impl AnswerBlockerCase {
    pub fn devnet(
        config: &Config,
        source: &SourceBundle,
        kind: AnswerBlockerKind,
        ordinal: u64,
    ) -> Self {
        let source_root = blocker_source_root(source, kind);
        let blocker_root = answer_blocker_root(config, source, kind, &source_root);
        let owner_lane = blocker_owner_lane(kind).to_string();
        let case_root = answer_blocker_case_root(
            config,
            source,
            kind,
            ordinal,
            &source_root,
            &blocker_root,
            &owner_lane,
        );
        Self {
            ordinal,
            kind,
            source_root,
            blocker_root,
            clearance: kind.clearance().to_string(),
            owner_lane,
            case_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ordinal": self.ordinal,
            "kind": self.kind.as_str(),
            "source_root": self.source_root,
            "blocker_root": self.blocker_root,
            "clearance": self.clearance,
            "owner_lane": self.owner_lane,
            "case_root": self.case_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyAnswerVerdict {
    pub answer_lane_count: u64,
    pub blocker_case_count: u64,
    pub user_escape_supported: u64,
    pub production_blocked: u64,
    pub release_held_count: u64,
    pub safety_case_watch_or_proven: u64,
    pub scorecard_clear_count: u64,
    pub acceptance_receipt_wallet_count: u64,
    pub operator_independent_count: u64,
    pub pq_authority_bound: u64,
    pub privacy_boundary_bound: u64,
    pub deferred_gate_count: u64,
    pub production_blocker_count: u64,
    pub answer_status: String,
    pub user_answer: String,
    pub production_answer: String,
    pub verdict_root: String,
}

impl SafetyAnswerVerdict {
    pub fn new(
        config: &Config,
        source: &SourceBundle,
        checks: &[AnswerCheck],
        blockers: &[AnswerBlockerCase],
    ) -> Self {
        let answer_lane_count = checks.len() as u64;
        let blocker_case_count = blockers.len() as u64;
        let release_held_count = checks
            .iter()
            .filter(|check| check.release_held == 1)
            .count() as u64;
        let safety_case_watch_or_proven = bool_to_u64(
            source.safety_case_verdict == "proven" || source.safety_case_verdict == "watch",
        );
        let scorecard_clear_count = source.scorecard_user_escape_clear;
        let acceptance_receipt_wallet_count = source.acceptance_wallet_force_exit_supported;
        let operator_independent_count = bool_to_u64(
            source.acceptance_force_exit_critical_count > 0
                && source.acceptance_operator_independent_count
                    >= source.acceptance_force_exit_critical_count,
        );
        let pq_authority_bound = bool_to_u64(!source.pq_authority_root.is_empty());
        let privacy_boundary_bound = bool_to_u64(
            !source.privacy_boundary_root.is_empty()
                && source.acceptance_privacy_boundary_count
                    >= source.acceptance_force_exit_critical_count,
        );
        let deferred_gate_count = source.safety_case_deferred_gates
            + source.acceptance_cargo_deferred_count
            + source.acceptance_audit_deferred_count
            + source.scorecard_deferred_stages;
        let production_blocker_count = source.safety_case_production_blockers
            + source.scorecard_production_blockers
            + source.acceptance_production_blocker_count
            + source.scorecard_production_blocked;
        let user_escape_supported = bool_to_u64(
            safety_case_watch_or_proven == 1
                && scorecard_clear_count == config.require_wallet_force_exit
                && acceptance_receipt_wallet_count == config.require_wallet_force_exit
                && operator_independent_count == config.require_operator_independent_escape
                && pq_authority_bound == config.require_pq_authority
                && source.scorecard_user_escape_blockers == 0,
        );
        let production_blocked = bool_to_u64(
            config.production_release_allowed == 0
                || deferred_gate_count > 0
                || production_blocker_count > 0,
        );
        let privacy_boundary_bound = if config.max_public_metadata_units == 0 {
            privacy_boundary_bound
        } else {
            0
        };
        let answer_status = if answer_lane_count >= config.min_answer_lanes
            && blocker_case_count >= config.min_blocker_cases
            && release_held_count == answer_lane_count
            && user_escape_supported == 1
            && production_blocked == 1
            && privacy_boundary_bound == config.require_privacy_boundary
        {
            "conditional_user_escape_supported_production_release_blocked"
        } else if production_blocked == 1 {
            "user_escape_watchlisted_production_release_blocked"
        } else {
            "user_escape_answer_gap"
        }
        .to_string();
        let user_answer = if user_escape_supported == 1 {
            "current devnet evidence says the user escape path is conditionally supported by wallet-replayable, operator-independent, PQ-bound roots"
        } else {
            "current evidence is not enough to answer yes for user escape under full misbehavior"
        }
        .to_string();
        let production_answer = if production_blocked == 1 {
            "production release remains blocked until live cargo/runtime, audit, Monero evidence, reserve, and release-governance execution roots replace deferred evidence"
        } else {
            "production release would require an explicit unhold path; this devnet answer does not grant it"
        }
        .to_string();
        let verdict_root = domain_hash(
            &format!("{DOMAIN}:verdict"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.answer_policy),
                HashPart::Str(&source.safety_case_report_root),
                HashPart::Str(&source.scorecard_answer_root),
                HashPart::Str(&source.acceptance_receipt_binding_root),
                HashPart::U64(answer_lane_count),
                HashPart::U64(blocker_case_count),
                HashPart::U64(user_escape_supported),
                HashPart::U64(production_blocked),
                HashPart::U64(release_held_count),
                HashPart::U64(safety_case_watch_or_proven),
                HashPart::U64(scorecard_clear_count),
                HashPart::U64(acceptance_receipt_wallet_count),
                HashPart::U64(operator_independent_count),
                HashPart::U64(pq_authority_bound),
                HashPart::U64(privacy_boundary_bound),
                HashPart::U64(deferred_gate_count),
                HashPart::U64(production_blocker_count),
                HashPart::Str(&answer_status),
            ],
            32,
        );
        Self {
            answer_lane_count,
            blocker_case_count,
            user_escape_supported,
            production_blocked,
            release_held_count,
            safety_case_watch_or_proven,
            scorecard_clear_count,
            acceptance_receipt_wallet_count,
            operator_independent_count,
            pq_authority_bound,
            privacy_boundary_bound,
            deferred_gate_count,
            production_blocker_count,
            answer_status,
            user_answer,
            production_answer,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "answer_lane_count": self.answer_lane_count,
            "blocker_case_count": self.blocker_case_count,
            "user_escape_supported": self.user_escape_supported,
            "production_blocked": self.production_blocked,
            "release_held_count": self.release_held_count,
            "safety_case_watch_or_proven": self.safety_case_watch_or_proven,
            "scorecard_clear_count": self.scorecard_clear_count,
            "acceptance_receipt_wallet_count": self.acceptance_receipt_wallet_count,
            "operator_independent_count": self.operator_independent_count,
            "pq_authority_bound": self.pq_authority_bound,
            "privacy_boundary_bound": self.privacy_boundary_bound,
            "deferred_gate_count": self.deferred_gate_count,
            "production_blocker_count": self.production_blocker_count,
            "answer_status": self.answer_status,
            "user_answer": self.user_answer,
            "production_answer": self.production_answer,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub source: SourceBundle,
    pub answer_checks: Vec<AnswerCheck>,
    pub blocker_cases: Vec<AnswerBlockerCase>,
    pub verdict: SafetyAnswerVerdict,
    pub answer_check_root: String,
    pub blocker_case_root: String,
    pub user_answer_root: String,
    pub production_hold_root: String,
    pub safety_answer_root: String,
}

impl State {
    pub fn new(config: Config, source: SourceBundle) -> Result<Self> {
        validate_config(&config)?;
        validate_source(&config, &source)?;
        let answer_checks = AnswerLane::ordered()
            .iter()
            .enumerate()
            .map(|(index, lane)| AnswerCheck::devnet(&config, &source, *lane, index as u64 + 1))
            .collect::<Vec<_>>();
        let blocker_cases = AnswerBlockerKind::ordered()
            .iter()
            .enumerate()
            .map(|(index, kind)| {
                AnswerBlockerCase::devnet(&config, &source, *kind, index as u64 + 1)
            })
            .collect::<Vec<_>>();
        let verdict = SafetyAnswerVerdict::new(&config, &source, &answer_checks, &blocker_cases);
        let answer_check_root = answer_check_vector_root(&answer_checks);
        let blocker_case_root = blocker_case_vector_root(&blocker_cases);
        let user_answer_root =
            aggregate_user_answer_root(&config, &source, &answer_check_root, &verdict);
        let production_hold_root =
            aggregate_production_hold_root(&config, &source, &blocker_case_root, &verdict);
        let safety_answer_root = safety_answer_root(
            &config,
            &source,
            &answer_check_root,
            &blocker_case_root,
            &user_answer_root,
            &production_hold_root,
            &verdict,
        );
        Ok(Self {
            config,
            source,
            answer_checks,
            blocker_cases,
            verdict,
            answer_check_root,
            blocker_case_root,
            user_answer_root,
            production_hold_root,
            safety_answer_root,
        })
    }

    pub fn devnet() -> Self {
        match Self::new(Config::default(), SourceBundle::devnet()) {
            Ok(state) => state,
            Err(reason) => fallback_state(reason),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_user_escape_safety_answer_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "source": self.source.public_record(),
            "answer_check_root": self.answer_check_root,
            "blocker_case_root": self.blocker_case_root,
            "user_answer_root": self.user_answer_root,
            "production_hold_root": self.production_hold_root,
            "safety_answer_root": self.safety_answer_root,
            "verdict": self.verdict.public_record(),
            "answer_checks": self
                .answer_checks
                .iter()
                .map(AnswerCheck::public_record)
                .collect::<Vec<_>>(),
            "blocker_cases": self
                .blocker_cases
                .iter()
                .map(AnswerBlockerCase::public_record)
                .collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "state",
            &json!({
                "chain_id": CHAIN_ID,
                "protocol_version": PROTOCOL_VERSION,
                "config_root": self.config.state_root(),
                "source_root": self.source.state_root(),
                "answer_check_root": self.answer_check_root,
                "blocker_case_root": self.blocker_case_root,
                "user_answer_root": self.user_answer_root,
                "production_hold_root": self.production_hold_root,
                "safety_answer_root": self.safety_answer_root,
                "verdict_root": self.verdict.verdict_root,
            }),
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

fn validate_config(config: &Config) -> Result<()> {
    if config.chain_id != CHAIN_ID {
        return Err("user escape safety answer chain id mismatch".to_string());
    }
    if config.min_answer_lanes < AnswerLane::ordered().len() as u64 {
        return Err("user escape safety answer requires every answer lane".to_string());
    }
    if config.min_blocker_cases < AnswerBlockerKind::ordered().len() as u64 {
        return Err("user escape safety answer requires every blocker case".to_string());
    }
    if config.require_end_to_end_safety_case != 1
        || config.require_escape_scorecard != 1
        || config.require_acceptance_execution_receipt != 1
    {
        return Err("user escape safety answer requires all source artifacts".to_string());
    }
    if config.require_wallet_force_exit != 1
        || config.require_operator_independence != 1
        || config.require_pq_authority != 1
        || config.require_privacy_boundary != 1
        || config.require_release_hold != 1
    {
        return Err(
            "user escape safety answer requires the bridge exit safety invariants".to_string(),
        );
    }
    if config.production_release_allowed != 0 {
        return Err("user escape safety answer cannot allow production release".to_string());
    }
    if config.max_public_metadata_units != 0 {
        return Err("user escape safety answer must remain roots-only".to_string());
    }
    Ok(())
}

fn validate_source(_config: &Config, source: &SourceBundle) -> Result<()> {
    if source.safety_case_report_root.is_empty() || source.scorecard_answer_root.is_empty() {
        return Err("user escape safety answer missing safety or scorecard roots".to_string());
    }
    if source.acceptance_receipt_binding_root.is_empty() {
        return Err("user escape safety answer missing acceptance receipt root".to_string());
    }
    Ok(())
}

fn lane_source_root(source: &SourceBundle, lane: AnswerLane) -> String {
    match lane {
        AnswerLane::UserQuestion => source.source_root.clone(),
        AnswerLane::EndToEndSafetyCase => source.safety_case_report_root.clone(),
        AnswerLane::EscapeScorecard => source.scorecard_answer_root.clone(),
        AnswerLane::AcceptanceExecutionReceipt => source.acceptance_receipt_binding_root.clone(),
        AnswerLane::WalletForceExit => source.wallet_recovery_root.clone(),
        AnswerLane::OperatorIndependence => source.acceptance_receipt_verdict_root.clone(),
        AnswerLane::PqControlPlane => source.pq_authority_root.clone(),
        AnswerLane::PrivacyBoundary => source.privacy_boundary_root.clone(),
        AnswerLane::ProductionReleaseHold => source.acceptance_receipt_hold_root.clone(),
    }
}

fn lane_observed(source: &SourceBundle, lane: AnswerLane) -> String {
    match lane {
        AnswerLane::UserQuestion => "root-bound user escape safety answer requested".to_string(),
        AnswerLane::EndToEndSafetyCase => format!(
            "verdict={} readiness={} evidence={} deferred={} blockers={}",
            source.safety_case_verdict,
            source.safety_case_readiness_label,
            source.safety_case_evidence_items,
            source.safety_case_deferred_gates,
            source.safety_case_production_blockers
        ),
        AnswerLane::EscapeScorecard => format!(
            "verdict={} score={} user_clear={} user_blockers={} production_blocked={}",
            source.scorecard_verdict,
            source.scorecard_score,
            source.scorecard_user_escape_clear,
            source.scorecard_user_escape_blockers,
            source.scorecard_production_blocked
        ),
        AnswerLane::AcceptanceExecutionReceipt => format!(
            "status={} wallet={} deferred={} production_blockers={}",
            source.acceptance_receipt_status,
            source.acceptance_wallet_force_exit_supported,
            source.acceptance_cargo_deferred_count + source.acceptance_audit_deferred_count,
            source.acceptance_production_blocker_count
        ),
        AnswerLane::WalletForceExit => format!(
            "wallet_root={} wallet_force_exit={}",
            source.wallet_recovery_root, source.acceptance_wallet_force_exit_supported
        ),
        AnswerLane::OperatorIndependence => format!(
            "operator_independent={} force_exit_critical={}",
            source.acceptance_operator_independent_count,
            source.acceptance_force_exit_critical_count
        ),
        AnswerLane::PqControlPlane => format!("pq_authority_root={}", source.pq_authority_root),
        AnswerLane::PrivacyBoundary => format!(
            "privacy_root={} privacy_lanes={}",
            source.privacy_boundary_root, source.acceptance_privacy_boundary_count
        ),
        AnswerLane::ProductionReleaseHold => format!(
            "held=1 production_blockers={} deferred={}",
            source.safety_case_production_blockers
                + source.scorecard_production_blockers
                + source.acceptance_production_blocker_count,
            source.safety_case_deferred_gates
                + source.scorecard_deferred_stages
                + source.acceptance_cargo_deferred_count
                + source.acceptance_audit_deferred_count
        ),
    }
}

fn lane_evidence_root(
    config: &Config,
    source: &SourceBundle,
    lane: AnswerLane,
    source_root: &str,
    observed: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:lane-evidence"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.answer_suite),
            HashPart::Str(lane.as_str()),
            HashPart::Str(source_root),
            HashPart::Str(observed),
            HashPart::Str(&source.source_root),
        ],
        32,
    )
}

fn lane_answer_root(
    config: &Config,
    source: &SourceBundle,
    lane: AnswerLane,
    evidence_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:lane-answer"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.answer_policy),
            HashPart::Str(lane.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Str(&source.safety_case_report_root),
            HashPart::Str(&source.scorecard_answer_root),
            HashPart::Str(&source.acceptance_receipt_binding_root),
            HashPart::U64(config.production_release_allowed),
        ],
        32,
    )
}

fn lane_blocker_root(
    config: &Config,
    source: &SourceBundle,
    lane: AnswerLane,
    answer_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:lane-blocker"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(answer_root),
            HashPart::Str(&source.safety_case_blocker_root),
            HashPart::Str(&source.acceptance_receipt_blocker_root),
            HashPart::U64(config.require_release_hold),
            HashPart::U64(config.production_release_allowed),
        ],
        32,
    )
}

fn answer_check_root(
    config: &Config,
    source: &SourceBundle,
    lane: AnswerLane,
    ordinal: u64,
    source_root: &str,
    evidence_root: &str,
    answer_root: &str,
    blocker_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:answer-check"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.answer_suite),
            HashPart::U64(ordinal),
            HashPart::Str(lane.as_str()),
            HashPart::Str(lane.owner_lane()),
            HashPart::Str(source_root),
            HashPart::Str(evidence_root),
            HashPart::Str(answer_root),
            HashPart::Str(blocker_root),
            HashPart::Str(&source.source_root),
        ],
        32,
    )
}

fn blocker_source_root(source: &SourceBundle, kind: AnswerBlockerKind) -> String {
    match kind {
        AnswerBlockerKind::CargoRuntimeDeferred => source.acceptance_receipt_blocker_root.clone(),
        AnswerBlockerKind::SecurityAuditDeferred => source.safety_case_blocker_root.clone(),
        AnswerBlockerKind::ProductionReleaseHeld => source.acceptance_receipt_hold_root.clone(),
        AnswerBlockerKind::MoneroBaseLayerVerifierAbsent => source.safety_case_report_root.clone(),
        AnswerBlockerKind::LiveEvidenceMissing => source.acceptance_receipt_binding_root.clone(),
        AnswerBlockerKind::ReserveOrLiquidityNeedsLiveProof => {
            source.safety_case_evidence_root.clone()
        }
        AnswerBlockerKind::PrivacyAuditNeedsClosure => source.privacy_boundary_root.clone(),
        AnswerBlockerKind::ReleaseGovernanceNeedsExecution => {
            source.acceptance_receipt_verdict_root.clone()
        }
    }
}

fn blocker_owner_lane(kind: AnswerBlockerKind) -> &'static str {
    match kind {
        AnswerBlockerKind::CargoRuntimeDeferred => "runtime_harness",
        AnswerBlockerKind::SecurityAuditDeferred => "security_audit",
        AnswerBlockerKind::ProductionReleaseHeld => "release_governance",
        AnswerBlockerKind::MoneroBaseLayerVerifierAbsent => "monero_evidence_policy",
        AnswerBlockerKind::LiveEvidenceMissing => "live_adapter",
        AnswerBlockerKind::ReserveOrLiquidityNeedsLiveProof => "liquidity_reserve",
        AnswerBlockerKind::PrivacyAuditNeedsClosure => "privacy_review",
        AnswerBlockerKind::ReleaseGovernanceNeedsExecution => "final_acceptance_execution",
    }
}

fn answer_blocker_root(
    config: &Config,
    source: &SourceBundle,
    kind: AnswerBlockerKind,
    source_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:answer-blocker"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(source_root),
            HashPart::Str(kind.clearance()),
            HashPart::Str(&source.safety_case_blocker_root),
            HashPart::Str(&source.acceptance_receipt_blocker_root),
            HashPart::U64(config.production_release_allowed),
        ],
        32,
    )
}

fn answer_blocker_case_root(
    config: &Config,
    source: &SourceBundle,
    kind: AnswerBlockerKind,
    ordinal: u64,
    source_root: &str,
    blocker_root: &str,
    owner_lane: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:answer-blocker-case"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.answer_suite),
            HashPart::U64(ordinal),
            HashPart::Str(kind.as_str()),
            HashPart::Str(source_root),
            HashPart::Str(blocker_root),
            HashPart::Str(owner_lane),
            HashPart::Str(&source.source_root),
        ],
        32,
    )
}

fn answer_check_vector_root(checks: &[AnswerCheck]) -> String {
    let leaves = checks
        .iter()
        .map(AnswerCheck::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:answer-checks"), &leaves)
}

fn blocker_case_vector_root(cases: &[AnswerBlockerCase]) -> String {
    let leaves = cases
        .iter()
        .map(AnswerBlockerCase::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:blocker-cases"), &leaves)
}

fn aggregate_user_answer_root(
    config: &Config,
    source: &SourceBundle,
    answer_check_root: &str,
    verdict: &SafetyAnswerVerdict,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:aggregate-user-answer"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.answer_policy),
            HashPart::Str(answer_check_root),
            HashPart::Str(&source.scorecard_answer_root),
            HashPart::Str(&source.wallet_recovery_root),
            HashPart::Str(&source.acceptance_receipt_binding_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(verdict.user_escape_supported),
        ],
        32,
    )
}

fn aggregate_production_hold_root(
    config: &Config,
    source: &SourceBundle,
    blocker_case_root: &str,
    verdict: &SafetyAnswerVerdict,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:aggregate-production-hold"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.answer_policy),
            HashPart::Str(blocker_case_root),
            HashPart::Str(&source.safety_case_blocker_root),
            HashPart::Str(&source.acceptance_receipt_hold_root),
            HashPart::Str(&source.acceptance_receipt_blocker_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(verdict.production_blocked),
            HashPart::U64(config.production_release_allowed),
        ],
        32,
    )
}

fn safety_answer_root(
    config: &Config,
    source: &SourceBundle,
    answer_check_root: &str,
    blocker_case_root: &str,
    user_answer_root: &str,
    production_hold_root: &str,
    verdict: &SafetyAnswerVerdict,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:safety-answer-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.answer_suite),
            HashPart::Str(&source.safety_case_state_root),
            HashPart::Str(&source.scorecard_state_root),
            HashPart::Str(&source.acceptance_receipt_state_root),
            HashPart::Str(answer_check_root),
            HashPart::Str(blocker_case_root),
            HashPart::Str(user_answer_root),
            HashPart::Str(production_hold_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(config.production_release_allowed),
        ],
        32,
    )
}

fn source_bundle_root(
    safety: &safety_case::State,
    scorecard: &scorecard::State,
    receipt: &acceptance_receipt::State,
) -> String {
    let safety_report_root = safety
        .latest_report
        .as_ref()
        .map(|report| report.roots.report_root.as_str())
        .unwrap_or("missing");
    let safety_state_root = safety.state_root();
    let scorecard_state_root = scorecard.state_root();
    let receipt_state_root = receipt.state_root();
    domain_hash(
        &format!("{DOMAIN}:source-bundle"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&safety_state_root),
            HashPart::Str(safety_report_root),
            HashPart::Str(&scorecard_state_root),
            HashPart::Str(&scorecard.answer.answer_root),
            HashPart::Str(&receipt_state_root),
            HashPart::Str(&receipt.execution_receipt_binding_root),
            HashPart::Str(&receipt.verdict.verdict_root),
            HashPart::U64(bool_to_u64(scorecard.user_escape_clear())),
            HashPart::U64(receipt.verdict.wallet_force_exit_supported),
            HashPart::U64(receipt.verdict.production_blocker_count),
        ],
        32,
    )
}

fn bool_to_u64(value: bool) -> u64 {
    if value {
        1
    } else {
        0
    }
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:record"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn fallback_state(reason: String) -> State {
    let config = Config::default();
    let reason_ref = reason.as_str();
    let source = SourceBundle {
        safety_case_state_root: record_root(
            "fallback-safety-state",
            &json!({"reason": reason_ref}),
        ),
        safety_case_report_root: record_root(
            "fallback-safety-report",
            &json!({"reason": reason_ref}),
        ),
        safety_case_evidence_root: record_root(
            "fallback-safety-evidence",
            &json!({"reason": reason_ref}),
        ),
        safety_case_blocker_root: record_root(
            "fallback-safety-blocker",
            &json!({"reason": reason_ref}),
        ),
        safety_case_verdict: "missing".to_string(),
        safety_case_readiness_label: "fallback".to_string(),
        safety_case_evidence_items: 0,
        safety_case_proven_items: 0,
        safety_case_watch_items: 0,
        safety_case_failed_items: 1,
        safety_case_deferred_gates: 1,
        safety_case_production_blockers: 1,
        scorecard_state_root: record_root(
            "fallback-scorecard-state",
            &json!({"reason": reason_ref}),
        ),
        scorecard_answer_root: record_root(
            "fallback-scorecard-answer",
            &json!({"reason": reason_ref}),
        ),
        scorecard_verdict: "missing".to_string(),
        scorecard_score: 0,
        scorecard_user_escape_clear: 0,
        scorecard_production_blocked: 1,
        scorecard_user_escape_blockers: 1,
        scorecard_production_blockers: 1,
        scorecard_deferred_stages: 1,
        acceptance_receipt_state_root: record_root(
            "fallback-acceptance-state",
            &json!({"reason": reason_ref}),
        ),
        acceptance_receipt_binding_root: record_root(
            "fallback-acceptance-binding",
            &json!({"reason": reason_ref}),
        ),
        acceptance_receipt_hold_root: record_root(
            "fallback-acceptance-hold",
            &json!({"reason": reason_ref}),
        ),
        acceptance_receipt_blocker_root: record_root(
            "fallback-acceptance-blocker",
            &json!({"reason": reason_ref}),
        ),
        acceptance_receipt_verdict_root: record_root(
            "fallback-acceptance-verdict",
            &json!({"reason": reason_ref}),
        ),
        acceptance_receipt_status: "fallback_release_held".to_string(),
        acceptance_wallet_force_exit_supported: 0,
        acceptance_operator_independent_count: 0,
        acceptance_force_exit_critical_count: 1,
        acceptance_heavy_gates_executed: 0,
        acceptance_cargo_deferred_count: 1,
        acceptance_audit_deferred_count: 1,
        acceptance_production_blocker_count: 1,
        acceptance_privacy_boundary_count: 0,
        pq_authority_root: record_root("fallback-pq-authority", &json!({"reason": reason_ref})),
        wallet_recovery_root: record_root(
            "fallback-wallet-recovery",
            &json!({"reason": reason_ref}),
        ),
        privacy_boundary_root: record_root(
            "fallback-privacy-boundary",
            &json!({"reason": reason_ref}),
        ),
        source_root: record_root("fallback-source", &json!({"reason": reason_ref})),
    };
    let answer_checks = Vec::new();
    let blocker_cases = Vec::new();
    let verdict = SafetyAnswerVerdict::new(&config, &source, &answer_checks, &blocker_cases);
    let answer_check_root = answer_check_vector_root(&answer_checks);
    let blocker_case_root = blocker_case_vector_root(&blocker_cases);
    let user_answer_root =
        aggregate_user_answer_root(&config, &source, &answer_check_root, &verdict);
    let production_hold_root =
        aggregate_production_hold_root(&config, &source, &blocker_case_root, &verdict);
    let safety_answer_root = safety_answer_root(
        &config,
        &source,
        &answer_check_root,
        &blocker_case_root,
        &user_answer_root,
        &production_hold_root,
        &verdict,
    );
    State {
        config,
        source,
        answer_checks,
        blocker_cases,
        verdict,
        answer_check_root,
        blocker_case_root,
        user_answer_root,
        production_hold_root,
        safety_answer_root,
    }
}
