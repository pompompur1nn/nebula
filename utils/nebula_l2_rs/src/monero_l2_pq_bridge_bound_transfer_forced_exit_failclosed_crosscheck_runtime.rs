use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_bound_transfer_forced_exit_scenario_runtime::{
        ClaimKind, ClaimStatus, ScenarioClaim, ScenarioStatus, ScenarioStep, ScenarioTranscript,
        State as TransferForcedExitScenarioState, StepKind,
    },
    monero_l2_pq_bridge_bound_transfer_forced_exit_static_verifier_runtime::{
        ReportStatus as StaticReportStatus, State as TransferForcedExitStaticVerifierState,
        StaticCheckKind, StaticCheckStatus,
    },
    monero_l2_pq_bridge_exit_adversarial_scenario_matrix_runtime::{
        MatrixStatus, State as AdversarialMatrixState,
    },
    monero_l2_pq_bridge_exit_authority_crosscheck_verifier_runtime::{
        CrossCheckReportStatus as AuthorityReportStatus, State as AuthorityCrosscheckState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeBoundTransferForcedExitFailclosedCrosscheckRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_BOUND_TRANSFER_FORCED_EXIT_FAILCLOSED_CROSSCHECK_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-bound-transfer-forced-exit-failclosed-crosscheck-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_BOUND_TRANSFER_FORCED_EXIT_FAILCLOSED_CROSSCHECK_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CROSSCHECK_SUITE: &str =
    "monero-l2-pq-bridge-bound-transfer-forced-exit-failclosed-crosschecks-v1";
pub const DEFAULT_MIN_FAILCLOSED_PROBES: u64 = 7;
pub const DEFAULT_MIN_STATIC_CHECKS: u64 = 12;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailClosedCheckKind {
    SourceRootsPresent,
    ScenarioTranscriptProven,
    StaticVerifierPassed,
    AuthorityCrosscheckPassed,
    AdversarialMatrixPassed,
    PreSealStepRootTamperRejected,
    ClaimRootTamperRejected,
    ExitClaimRootTamperRejected,
    BrokenSealLinkRejected,
    SettlementBeforeChallengeRejected,
    MissingSealStepRejected,
    MissingForcedExitClaimRejected,
    FinalRootMismatchRejected,
    PrivacyFeePqSurfacePreserved,
    CountersConsistent,
}

impl FailClosedCheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceRootsPresent => "source_roots_present",
            Self::ScenarioTranscriptProven => "scenario_transcript_proven",
            Self::StaticVerifierPassed => "static_verifier_passed",
            Self::AuthorityCrosscheckPassed => "authority_crosscheck_passed",
            Self::AdversarialMatrixPassed => "adversarial_matrix_passed",
            Self::PreSealStepRootTamperRejected => "pre_seal_step_root_tamper_rejected",
            Self::ClaimRootTamperRejected => "claim_root_tamper_rejected",
            Self::ExitClaimRootTamperRejected => "exit_claim_root_tamper_rejected",
            Self::BrokenSealLinkRejected => "broken_seal_link_rejected",
            Self::SettlementBeforeChallengeRejected => "settlement_before_challenge_rejected",
            Self::MissingSealStepRejected => "missing_seal_step_rejected",
            Self::MissingForcedExitClaimRejected => "missing_forced_exit_claim_rejected",
            Self::FinalRootMismatchRejected => "final_root_mismatch_rejected",
            Self::PrivacyFeePqSurfacePreserved => "privacy_fee_pq_surface_preserved",
            Self::CountersConsistent => "counters_consistent",
        }
    }

    pub fn all() -> [Self; 15] {
        [
            Self::SourceRootsPresent,
            Self::ScenarioTranscriptProven,
            Self::StaticVerifierPassed,
            Self::AuthorityCrosscheckPassed,
            Self::AdversarialMatrixPassed,
            Self::PreSealStepRootTamperRejected,
            Self::ClaimRootTamperRejected,
            Self::ExitClaimRootTamperRejected,
            Self::BrokenSealLinkRejected,
            Self::SettlementBeforeChallengeRejected,
            Self::MissingSealStepRejected,
            Self::MissingForcedExitClaimRejected,
            Self::FinalRootMismatchRejected,
            Self::PrivacyFeePqSurfacePreserved,
            Self::CountersConsistent,
        ]
    }

    pub fn is_failclosed_probe(self) -> bool {
        matches!(
            self,
            Self::PreSealStepRootTamperRejected
                | Self::ClaimRootTamperRejected
                | Self::ExitClaimRootTamperRejected
                | Self::BrokenSealLinkRejected
                | Self::SettlementBeforeChallengeRejected
                | Self::MissingSealStepRejected
                | Self::MissingForcedExitClaimRejected
                | Self::FinalRootMismatchRejected
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailClosedCheckStatus {
    Passed,
    Watch,
    Failed,
}

impl FailClosedCheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Watch => "watch",
            Self::Failed => "failed",
        }
    }

    pub fn passes(self) -> bool {
        matches!(self, Self::Passed | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailClosedReportStatus {
    Passed,
    Watch,
    Failed,
}

impl FailClosedReportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Watch => "watch",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub crosscheck_suite: String,
    pub min_failclosed_probes: u64,
    pub min_static_checks: u64,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            crosscheck_suite: CROSSCHECK_SUITE.to_string(),
            min_failclosed_probes: DEFAULT_MIN_FAILCLOSED_PROBES,
            min_static_checks: DEFAULT_MIN_STATIC_CHECKS,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "crosscheck_suite": self.crosscheck_suite,
            "min_failclosed_probes": self.min_failclosed_probes,
            "min_static_checks": self.min_static_checks,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FailClosedCheckEvidence {
    pub check_id: String,
    pub kind: FailClosedCheckKind,
    pub status: FailClosedCheckStatus,
    pub requirement: String,
    pub observed: String,
    pub evidence_root: String,
    pub failclosed_action: String,
    pub remediation: String,
}

impl FailClosedCheckEvidence {
    pub fn new(
        scenario_id: &str,
        kind: FailClosedCheckKind,
        status: FailClosedCheckStatus,
        requirement: impl Into<String>,
        observed: impl Into<String>,
        evidence_record: Value,
        failclosed_action: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        let evidence_root = evidence_root(scenario_id, kind.as_str(), &evidence_record);
        let check_id = failclosed_check_id(scenario_id, kind, &evidence_root);
        Self {
            check_id,
            kind,
            status,
            requirement: requirement.into(),
            observed: observed.into(),
            evidence_root,
            failclosed_action: failclosed_action.into(),
            remediation: remediation.into(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "requirement": self.requirement,
            "observed": self.observed,
            "evidence_root": self.evidence_root,
            "failclosed_action": self.failclosed_action,
            "remediation": self.remediation,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("failclosed_check", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FailClosedReport {
    pub report_id: String,
    pub scenario_id: String,
    pub status: FailClosedReportStatus,
    pub scenario_state_root: String,
    pub static_verifier_root: String,
    pub authority_crosscheck_root: String,
    pub adversarial_matrix_root: String,
    pub transcript_root: String,
    pub passed_checks: u64,
    pub watch_checks: u64,
    pub failed_checks: u64,
    pub failclosed_probe_count: u64,
    pub rejected_probe_count: u64,
    pub checks: BTreeMap<String, FailClosedCheckEvidence>,
    pub roots: FailClosedReportRoots,
}

impl FailClosedReport {
    pub fn public_record(&self) -> Value {
        let checks = self
            .checks
            .values()
            .map(FailClosedCheckEvidence::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "scenario_id": self.scenario_id,
            "status": self.status.as_str(),
            "scenario_state_root": self.scenario_state_root,
            "static_verifier_root": self.static_verifier_root,
            "authority_crosscheck_root": self.authority_crosscheck_root,
            "adversarial_matrix_root": self.adversarial_matrix_root,
            "transcript_root": self.transcript_root,
            "passed_checks": self.passed_checks,
            "watch_checks": self.watch_checks,
            "failed_checks": self.failed_checks,
            "failclosed_probe_count": self.failclosed_probe_count,
            "rejected_probe_count": self.rejected_probe_count,
            "checks": checks,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FailClosedReportRoots {
    pub check_root: String,
    pub probe_root: String,
    pub report_root: String,
}

impl FailClosedReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "check_root": self.check_root,
            "probe_root": self.probe_root,
            "report_root": self.report_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub reports_run: u64,
    pub reports_passed: u64,
    pub reports_watch: u64,
    pub reports_failed: u64,
    pub checks_run: u64,
    pub checks_passed: u64,
    pub checks_watch: u64,
    pub checks_failed: u64,
    pub failclosed_probes_run: u64,
    pub failclosed_probes_rejected: u64,
    pub root_tamper_rejections: u64,
    pub ordering_rejections: u64,
    pub missing_surface_rejections: u64,
    pub bundles_verified: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_passed": self.reports_passed,
            "reports_watch": self.reports_watch,
            "reports_failed": self.reports_failed,
            "checks_run": self.checks_run,
            "checks_passed": self.checks_passed,
            "checks_watch": self.checks_watch,
            "checks_failed": self.checks_failed,
            "failclosed_probes_run": self.failclosed_probes_run,
            "failclosed_probes_rejected": self.failclosed_probes_rejected,
            "root_tamper_rejections": self.root_tamper_rejections,
            "ordering_rejections": self.ordering_rejections,
            "missing_surface_rejections": self.missing_surface_rejections,
            "bundles_verified": self.bundles_verified,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub report_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-FAILCLOSED-EMPTY-REPORTS",
                &[],
            ),
            counters_root: counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "report_root": self.report_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-FAILCLOSED-CROSSCHECK-STATE",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.report_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub latest_report: Option<FailClosedReport>,
    pub report_history: Vec<FailClosedReport>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        let mut state = Self {
            config,
            latest_report: None,
            report_history: Vec::new(),
            counters,
            roots,
        };
        let scenario =
            crate::monero_l2_pq_bridge_bound_transfer_forced_exit_scenario_runtime::devnet();
        let static_verifier =
            crate::monero_l2_pq_bridge_bound_transfer_forced_exit_static_verifier_runtime::devnet();
        let authority =
            crate::monero_l2_pq_bridge_exit_authority_crosscheck_verifier_runtime::devnet();
        let adversarial =
            crate::monero_l2_pq_bridge_exit_adversarial_scenario_matrix_runtime::devnet();
        state
            .verify_failclosed_bundle(&scenario, &static_verifier, &authority, &adversarial)
            .expect("devnet bridge-bound transfer forced-exit failclosed cross-check");
        state
    }

    pub fn verify_failclosed_bundle(
        &mut self,
        scenario: &TransferForcedExitScenarioState,
        static_verifier: &TransferForcedExitStaticVerifierState,
        authority: &AuthorityCrosscheckState,
        adversarial: &AdversarialMatrixState,
    ) -> Result<String> {
        let transcript = latest_transcript(scenario)?;
        let scenario_id = transcript.scenario_id.clone();
        let mut checks = BTreeMap::new();
        for check in evaluate_failclosed_checks(
            &self.config,
            scenario,
            static_verifier,
            authority,
            adversarial,
            transcript,
        ) {
            checks.insert(check.kind.as_str().to_string(), check);
        }
        ensure(
            FailClosedCheckKind::all()
                .iter()
                .all(|kind| checks.contains_key(kind.as_str())),
            "failclosed cross-check omitted a required bridge-bound transfer forced-exit check",
        )?;

        let passed_checks = checks
            .values()
            .filter(|check| check.status == FailClosedCheckStatus::Passed)
            .count() as u64;
        let watch_checks = checks
            .values()
            .filter(|check| check.status == FailClosedCheckStatus::Watch)
            .count() as u64;
        let failed_checks = checks
            .values()
            .filter(|check| check.status == FailClosedCheckStatus::Failed)
            .count() as u64;
        let failclosed_probe_count = checks
            .values()
            .filter(|check| check.kind.is_failclosed_probe())
            .count() as u64;
        let rejected_probe_count = checks
            .values()
            .filter(|check| {
                check.kind.is_failclosed_probe() && check.status == FailClosedCheckStatus::Passed
            })
            .count() as u64;
        let status = aggregate_report_status(&self.config, &checks, rejected_probe_count);
        let check_records = checks
            .values()
            .map(FailClosedCheckEvidence::public_record)
            .collect::<Vec<_>>();
        let probe_records = checks
            .values()
            .filter(|check| check.kind.is_failclosed_probe())
            .map(FailClosedCheckEvidence::public_record)
            .collect::<Vec<_>>();
        let check_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-FAILCLOSED-CHECKS",
            &check_records,
        );
        let probe_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-FAILCLOSED-PROBES",
            &probe_records,
        );
        let scenario_state_root = scenario.state_root();
        let static_verifier_root = static_verifier.state_root();
        let authority_crosscheck_root = authority.state_root();
        let adversarial_matrix_root = adversarial.state_root();
        let report_root = report_root(
            &scenario_id,
            status,
            &scenario_state_root,
            &static_verifier_root,
            &authority_crosscheck_root,
            &adversarial_matrix_root,
            &transcript.transcript_root,
            &check_root,
            &probe_root,
        );
        let report_id = failclosed_report_id(&scenario_id, &report_root);
        let report = FailClosedReport {
            report_id: report_id.clone(),
            scenario_id,
            status,
            scenario_state_root,
            static_verifier_root,
            authority_crosscheck_root,
            adversarial_matrix_root,
            transcript_root: transcript.transcript_root.clone(),
            passed_checks,
            watch_checks,
            failed_checks,
            failclosed_probe_count,
            rejected_probe_count,
            checks,
            roots: FailClosedReportRoots {
                check_root,
                probe_root,
                report_root,
            },
        };
        self.record_report(report);
        Ok(report_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "crosscheck_suite": self.config.crosscheck_suite,
            "latest_report": self.latest_report.as_ref().map(FailClosedReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: FailClosedReport) {
        self.counters.reports_run += 1;
        self.counters.checks_run += report.checks.len() as u64;
        self.counters.checks_passed += report.passed_checks;
        self.counters.checks_watch += report.watch_checks;
        self.counters.checks_failed += report.failed_checks;
        self.counters.failclosed_probes_run += report.failclosed_probe_count;
        self.counters.failclosed_probes_rejected += report.rejected_probe_count;
        self.counters.root_tamper_rejections += report
            .checks
            .values()
            .filter(|check| {
                matches!(
                    check.kind,
                    FailClosedCheckKind::PreSealStepRootTamperRejected
                        | FailClosedCheckKind::ClaimRootTamperRejected
                        | FailClosedCheckKind::ExitClaimRootTamperRejected
                        | FailClosedCheckKind::BrokenSealLinkRejected
                        | FailClosedCheckKind::FinalRootMismatchRejected
                ) && check.status.passes()
            })
            .count() as u64;
        self.counters.ordering_rejections += report
            .checks
            .values()
            .filter(|check| {
                check.kind == FailClosedCheckKind::SettlementBeforeChallengeRejected
                    && check.status.passes()
            })
            .count() as u64;
        self.counters.missing_surface_rejections += report
            .checks
            .values()
            .filter(|check| {
                matches!(
                    check.kind,
                    FailClosedCheckKind::MissingSealStepRejected
                        | FailClosedCheckKind::MissingForcedExitClaimRejected
                ) && check.status.passes()
            })
            .count() as u64;
        match report.status {
            FailClosedReportStatus::Passed => {
                self.counters.reports_passed += 1;
                self.counters.bundles_verified += 1;
            }
            FailClosedReportStatus::Watch => self.counters.reports_watch += 1,
            FailClosedReportStatus::Failed => self.counters.reports_failed += 1,
        }
        self.latest_report = Some(report.clone());
        self.report_history.push(report);
        if self.report_history.len() > self.config.max_reports {
            self.report_history.remove(0);
        }
        self.refresh_roots();
    }

    fn refresh_roots(&mut self) {
        let report_records = self
            .report_history
            .iter()
            .map(FailClosedReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-FAILCLOSED-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

pub fn evaluate_failclosed_checks(
    config: &Config,
    scenario: &TransferForcedExitScenarioState,
    static_verifier: &TransferForcedExitStaticVerifierState,
    authority: &AuthorityCrosscheckState,
    adversarial: &AdversarialMatrixState,
    transcript: &ScenarioTranscript,
) -> Vec<FailClosedCheckEvidence> {
    vec![
        source_roots_present(
            scenario,
            static_verifier,
            authority,
            adversarial,
            transcript,
        ),
        scenario_transcript_proven(config, scenario, transcript),
        static_verifier_passed(config, scenario, static_verifier, transcript),
        authority_crosscheck_passed(authority, scenario, static_verifier, adversarial),
        adversarial_matrix_passed(adversarial, authority),
        pre_seal_step_root_tamper_rejected(scenario, static_verifier, transcript),
        claim_root_tamper_rejected(scenario, static_verifier, transcript),
        exit_claim_root_tamper_rejected(scenario, static_verifier, transcript),
        broken_seal_link_rejected(scenario, transcript),
        settlement_before_challenge_rejected(scenario, transcript),
        missing_seal_step_rejected(scenario, transcript),
        missing_forced_exit_claim_rejected(scenario, transcript),
        final_root_mismatch_rejected(scenario, static_verifier, transcript),
        privacy_fee_pq_surface_preserved(scenario, static_verifier, transcript),
        counters_consistent(scenario, static_verifier, transcript),
    ]
}

fn source_roots_present(
    scenario: &TransferForcedExitScenarioState,
    static_verifier: &TransferForcedExitStaticVerifierState,
    authority: &AuthorityCrosscheckState,
    adversarial: &AdversarialMatrixState,
    transcript: &ScenarioTranscript,
) -> FailClosedCheckEvidence {
    let roots = [
        scenario.state_root(),
        static_verifier.state_root(),
        authority.state_root(),
        adversarial.state_root(),
        transcript.transcript_root.clone(),
    ];
    let all_present = roots.iter().all(|root| !root.is_empty());
    let status = if all_present {
        FailClosedCheckStatus::Passed
    } else {
        FailClosedCheckStatus::Failed
    };
    FailClosedCheckEvidence::new(
        &transcript.scenario_id,
        FailClosedCheckKind::SourceRootsPresent,
        status,
        "scenario, static verifier, authority cross-check, adversarial matrix, and transcript roots must be present",
        format!("source_roots_present={all_present} roots={}", roots.len()),
        json!({
            "scenario_state_root": roots[0],
            "static_verifier_root": roots[1],
            "authority_crosscheck_root": roots[2],
            "adversarial_matrix_root": roots[3],
            "transcript_root": roots[4],
        }),
        "reject_bundle_with_missing_root",
        "rerun the scenario, static verifier, authority cross-check, and adversarial matrix before accepting transfer-exit evidence",
    )
}

fn scenario_transcript_proven(
    config: &Config,
    scenario: &TransferForcedExitScenarioState,
    transcript: &ScenarioTranscript,
) -> FailClosedCheckEvidence {
    let pre_seal_steps = pre_seal_steps(scenario, &transcript.scenario_id);
    let claims = scenario_claims(scenario, &transcript.scenario_id);
    let proven_claims = claims
        .iter()
        .filter(|claim| claim.status == ClaimStatus::Proven)
        .count() as u64;
    let status_ok = transcript.status == ScenarioStatus::Proven;
    let coverage_ok = pre_seal_steps.len() as u64 >= config.min_static_checks
        && proven_claims >= scenario.config.min_proven_claims;
    let roots_ok = recompute_step_root(&pre_seal_steps) == transcript.step_root
        && recompute_claim_root(&claims) == transcript.claim_root;
    let status = if status_ok && coverage_ok && roots_ok {
        FailClosedCheckStatus::Passed
    } else {
        FailClosedCheckStatus::Failed
    };
    FailClosedCheckEvidence::new(
        &transcript.scenario_id,
        FailClosedCheckKind::ScenarioTranscriptProven,
        status,
        "latest bridge-bound private transfer forced-exit transcript must be proven and root-consistent",
        format!(
            "status={} pre_seal_steps={} proven_claims={} roots_ok={}",
            transcript.status.as_str(),
            pre_seal_steps.len(),
            proven_claims,
            roots_ok
        ),
        json!({
            "scenario_state_root": scenario.state_root(),
            "transcript_id": transcript.transcript_id,
            "transcript_root": transcript.transcript_root,
            "step_root": transcript.step_root,
            "claim_root": transcript.claim_root,
            "proven_claims": proven_claims,
            "coverage_ok": coverage_ok,
            "roots_ok": roots_ok,
        }),
        "reject_unproven_transfer_exit_transcript",
        "seal a proven transfer-to-forced-exit transcript with matching step and claim roots",
    )
}

fn static_verifier_passed(
    config: &Config,
    scenario: &TransferForcedExitScenarioState,
    static_verifier: &TransferForcedExitStaticVerifierState,
    transcript: &ScenarioTranscript,
) -> FailClosedCheckEvidence {
    let latest = static_verifier.latest_report.as_ref();
    let static_passed = latest.is_some_and(|report| report.status == StaticReportStatus::Passed);
    let no_failed_static_checks = latest.is_some_and(|report| report.failed_checks == 0);
    let all_static_checks_present = latest.is_some_and(|report| {
        StaticCheckKind::all()
            .iter()
            .all(|kind| report.checks.contains_key(kind.as_str()))
            && report.checks.len() as u64 >= config.min_static_checks
    });
    let all_static_checks_passed = latest.is_some_and(|report| {
        report
            .checks
            .values()
            .all(|check| check.status == StaticCheckStatus::Passed)
    });
    let roots_match = latest.is_some_and(|report| {
        report.scenario_id == transcript.scenario_id
            && report.scenario_state_root == scenario.state_root()
            && report.transcript_root == transcript.transcript_root
            && report.recomputed_pre_seal_step_root == transcript.step_root
            && report.recomputed_claim_root == transcript.claim_root
    });
    let status = if static_passed
        && no_failed_static_checks
        && all_static_checks_present
        && all_static_checks_passed
        && roots_match
    {
        FailClosedCheckStatus::Passed
    } else {
        FailClosedCheckStatus::Failed
    };
    FailClosedCheckEvidence::new(
        &transcript.scenario_id,
        FailClosedCheckKind::StaticVerifierPassed,
        status,
        "static verifier must pass all bridge-bound transfer forced-exit transcript checks and bind the same roots",
        format!(
            "static_passed={static_passed} no_failed_static_checks={no_failed_static_checks} checks_present={all_static_checks_present} roots_match={roots_match}"
        ),
        json!({
            "static_verifier_root": static_verifier.state_root(),
            "latest_report": latest.map(|report| report.public_record()),
            "all_static_checks_passed": all_static_checks_passed,
            "expected_static_checks": StaticCheckKind::all().map(StaticCheckKind::as_str),
        }),
        "reject_bundle_without_static_verifier_pass",
        "rerun static verification and require passed pre-seal root, claim root, ordering, final-root, privacy, fee, and PQ checks",
    )
}

fn authority_crosscheck_passed(
    authority: &AuthorityCrosscheckState,
    scenario: &TransferForcedExitScenarioState,
    static_verifier: &TransferForcedExitStaticVerifierState,
    adversarial: &AdversarialMatrixState,
) -> FailClosedCheckEvidence {
    let latest = authority.latest_report.as_ref();
    let authority_passed = latest.is_some_and(|report| {
        report.status == AuthorityReportStatus::Passed && report.failed_checks == 0
    });
    let source_bridge_roots_present = latest.is_some_and(|report| {
        !report.authority_state_root.is_empty()
            && !report.scenario_state_root.is_empty()
            && !report.transcript_verifier_root.is_empty()
            && !report.adversarial_matrix_root.is_empty()
            && !report.spine_root.is_empty()
    });
    let bridge_spine_supports_transfer_bundle = latest.is_some()
        && !scenario.state_root().is_empty()
        && !static_verifier.state_root().is_empty()
        && !adversarial.state_root().is_empty();
    let status =
        if authority_passed && source_bridge_roots_present && bridge_spine_supports_transfer_bundle
        {
            FailClosedCheckStatus::Passed
        } else {
            FailClosedCheckStatus::Watch
        };
    FailClosedCheckEvidence::new(
        latest
            .map(|report| report.report_id.as_str())
            .unwrap_or("missing-authority-crosscheck"),
        FailClosedCheckKind::AuthorityCrosscheckPassed,
        status,
        "broader bridge authority cross-check must already pass before the transfer forced-exit adapter is trusted",
        format!(
            "authority_passed={authority_passed} source_roots_present={source_bridge_roots_present} transfer_bundle_roots_present={bridge_spine_supports_transfer_bundle}"
        ),
        json!({
            "authority_crosscheck_root": authority.state_root(),
            "latest_report": latest.map(|report| report.public_record()),
            "transfer_scenario_root": scenario.state_root(),
            "transfer_static_root": static_verifier.state_root(),
            "adversarial_root": adversarial.state_root(),
        }),
        "degrade_transfer_exit_bundle_to_watch_until_authority_layer_is_green",
        "connect the transfer forced-exit transcript to the authority bundle once the bridge authority cross-check is rerun with transfer evidence",
    )
}

fn adversarial_matrix_passed(
    adversarial: &AdversarialMatrixState,
    authority: &AuthorityCrosscheckState,
) -> FailClosedCheckEvidence {
    let matrix_passed = adversarial.matrix_status == MatrixStatus::Passed;
    let no_failed_cases = adversarial.counters.cases_failed == 0;
    let enough_failclosed_cases =
        adversarial.counters.fail_closed_cases >= adversarial.config.min_cases;
    let authority_available = authority.latest_report.is_some();
    let status =
        if matrix_passed && no_failed_cases && enough_failclosed_cases && authority_available {
            FailClosedCheckStatus::Passed
        } else if no_failed_cases && enough_failclosed_cases {
            FailClosedCheckStatus::Watch
        } else {
            FailClosedCheckStatus::Failed
        };
    FailClosedCheckEvidence::new(
        "bridge-bound-transfer-exit-adversarial-matrix",
        FailClosedCheckKind::AdversarialMatrixPassed,
        status,
        "adversarial bridge matrix must fail closed for watcher quorum, reorg, fee, replay, liquidity, and challenge settlement probes",
        format!(
            "matrix_status={} cases_failed={} failclosed_cases={} authority_available={}",
            adversarial.matrix_status.as_str(),
            adversarial.counters.cases_failed,
            adversarial.counters.fail_closed_cases,
            authority_available
        ),
        json!({
            "adversarial_matrix_root": adversarial.state_root(),
            "matrix_status": adversarial.matrix_status.as_str(),
            "case_count": adversarial.cases.len(),
            "counters": adversarial.counters.public_record(),
            "authority_crosscheck_root": authority.state_root(),
        }),
        "reject_transfer_exit_if_adversarial_matrix_has_failed_case",
        "rerun or extend adversarial matrix until all critical bridge threat cases fail closed",
    )
}

fn pre_seal_step_root_tamper_rejected(
    scenario: &TransferForcedExitScenarioState,
    static_verifier: &TransferForcedExitStaticVerifierState,
    transcript: &ScenarioTranscript,
) -> FailClosedCheckEvidence {
    let steps = pre_seal_steps(scenario, &transcript.scenario_id);
    let real_root = recompute_step_root(&steps);
    let tampered_root = tampered_step_root(
        &steps,
        StepKind::ExitClaimPrepared,
        "forged-exit-claim-evidence-root",
    );
    let static_root_matches = static_verifier
        .latest_report
        .as_ref()
        .is_some_and(|report| {
            report.recomputed_pre_seal_step_root == real_root
                && report.recomputed_pre_seal_step_root == transcript.step_root
        });
    let rejected = real_root == transcript.step_root
        && static_root_matches
        && tampered_root != real_root
        && tampered_root != transcript.step_root;
    let status = if rejected {
        FailClosedCheckStatus::Passed
    } else {
        FailClosedCheckStatus::Failed
    };
    FailClosedCheckEvidence::new(
        &transcript.scenario_id,
        FailClosedCheckKind::PreSealStepRootTamperRejected,
        status,
        "changing any pre-seal step evidence must change the recomputed step root and be rejected",
        format!(
            "real_step_root_matches={} tampered_root_differs={} static_root_matches={}",
            real_root == transcript.step_root,
            tampered_root != real_root,
            static_root_matches
        ),
        json!({
            "real_step_root": real_root,
            "tampered_step_root": tampered_root,
            "transcript_step_root": transcript.step_root,
            "tampered_step_kind": StepKind::ExitClaimPrepared.as_str(),
        }),
        "reject_tampered_pre_seal_step_root",
        "only accept step roots recomputed from the exact sealed pre-exit transcript",
    )
}

fn claim_root_tamper_rejected(
    scenario: &TransferForcedExitScenarioState,
    static_verifier: &TransferForcedExitStaticVerifierState,
    transcript: &ScenarioTranscript,
) -> FailClosedCheckEvidence {
    let claims = scenario_claims(scenario, &transcript.scenario_id);
    let real_root = recompute_claim_root(&claims);
    let tampered_root = tampered_claim_root(
        &claims,
        ClaimKind::TransferReceiptAnchoredBySpine,
        "forged-transfer-receipt-anchor",
    );
    let static_root_matches = static_verifier
        .latest_report
        .as_ref()
        .is_some_and(|report| {
            report.recomputed_claim_root == real_root
                && report.recomputed_claim_root == transcript.claim_root
        });
    let rejected = real_root == transcript.claim_root
        && static_root_matches
        && tampered_root != real_root
        && tampered_root != transcript.claim_root;
    let status = if rejected {
        FailClosedCheckStatus::Passed
    } else {
        FailClosedCheckStatus::Failed
    };
    FailClosedCheckEvidence::new(
        &transcript.scenario_id,
        FailClosedCheckKind::ClaimRootTamperRejected,
        status,
        "changing any proven transfer receipt claim must change the claim root and be rejected",
        format!(
            "real_claim_root_matches={} tampered_root_differs={} static_root_matches={}",
            real_root == transcript.claim_root,
            tampered_root != real_root,
            static_root_matches
        ),
        json!({
            "real_claim_root": real_root,
            "tampered_claim_root": tampered_root,
            "transcript_claim_root": transcript.claim_root,
            "tampered_claim_kind": ClaimKind::TransferReceiptAnchoredBySpine.as_str(),
        }),
        "reject_tampered_claim_root",
        "only accept claim roots recomputed from the exact bridge-bound transfer forced-exit claim set",
    )
}

fn exit_claim_root_tamper_rejected(
    scenario: &TransferForcedExitScenarioState,
    static_verifier: &TransferForcedExitStaticVerifierState,
    transcript: &ScenarioTranscript,
) -> FailClosedCheckEvidence {
    let claims = scenario_claims(scenario, &transcript.scenario_id);
    let exit_claim = claims
        .iter()
        .find(|claim| claim.kind == ClaimKind::ExitClaimMatchesTransferReceipt);
    let real_root = recompute_claim_root(&claims);
    let tampered_root = tampered_claim_root(
        &claims,
        ClaimKind::ExitClaimMatchesTransferReceipt,
        "forged-exit-claim-transfer-binding",
    );
    let static_root_matches = static_verifier
        .latest_report
        .as_ref()
        .is_some_and(|report| {
            report.recomputed_claim_root == real_root
                && report.recomputed_claim_root == transcript.claim_root
        });
    let rejected = exit_claim.is_some_and(|claim| claim.status == ClaimStatus::Proven)
        && real_root == transcript.claim_root
        && static_root_matches
        && tampered_root != real_root
        && tampered_root != transcript.claim_root;
    let status = if rejected {
        FailClosedCheckStatus::Passed
    } else {
        FailClosedCheckStatus::Failed
    };
    FailClosedCheckEvidence::new(
        &transcript.scenario_id,
        FailClosedCheckKind::ExitClaimRootTamperRejected,
        status,
        "the exit claim that binds transfer receipt to forced-exit withdrawal evidence must be root-bound",
        format!(
            "exit_claim_present={} real_claim_root_matches={} tampered_root_differs={}",
            exit_claim.is_some(),
            real_root == transcript.claim_root,
            tampered_root != real_root
        ),
        json!({
            "exit_claim": exit_claim.map(|claim| claim.public_record()),
            "real_claim_root": real_root,
            "tampered_exit_claim_root": tampered_root,
            "static_root_matches": static_root_matches,
        }),
        "reject_tampered_transfer_exit_claim",
        "keep the forced-exit request derived from the exact transfer receipt claim root",
    )
}

fn broken_seal_link_rejected(
    scenario: &TransferForcedExitScenarioState,
    transcript: &ScenarioTranscript,
) -> FailClosedCheckEvidence {
    let seal_steps = seal_steps(scenario, &transcript.scenario_id);
    let last_pre_seal = pre_seal_steps(scenario, &transcript.scenario_id)
        .into_iter()
        .max_by_key(|step| step.sequence);
    let seal_step = seal_steps.first().copied();
    let seal_after_exit = seal_step
        .zip(last_pre_seal)
        .is_some_and(|(seal, last)| seal.sequence > last.sequence);
    let seal_root = seal_step
        .map(|step| step.state_root())
        .unwrap_or_else(|| "missing-seal-step-root".to_string());
    let tampered_seal_root = seal_step
        .map(|step| tampered_single_step_root(step, "forged-transcript-id"))
        .unwrap_or_else(|| "missing-tampered-seal-step-root".to_string());
    let rejected = seal_steps.len() == 1 && seal_after_exit && tampered_seal_root != seal_root;
    let status = if rejected {
        FailClosedCheckStatus::Passed
    } else {
        FailClosedCheckStatus::Failed
    };
    FailClosedCheckEvidence::new(
        &transcript.scenario_id,
        FailClosedCheckKind::BrokenSealLinkRejected,
        status,
        "changing the transcript seal evidence must change the seal step root and invalidate the sealed transcript link",
        format!(
            "seal_steps={} seal_after_exit={} tampered_seal_differs={}",
            seal_steps.len(),
            seal_after_exit,
            tampered_seal_root != seal_root
        ),
        json!({
            "seal_step_root": seal_root,
            "tampered_seal_step_root": tampered_seal_root,
            "transcript_id": transcript.transcript_id,
            "transcript_root": transcript.transcript_root,
        }),
        "reject_broken_transcript_seal",
        "seal the transcript after all transfer, challenge, settlement, and readiness evidence is present",
    )
}

fn settlement_before_challenge_rejected(
    scenario: &TransferForcedExitScenarioState,
    transcript: &ScenarioTranscript,
) -> FailClosedCheckEvidence {
    let steps = pre_seal_steps(scenario, &transcript.scenario_id);
    let real_order = ordered(
        &steps,
        &[
            StepKind::ForcedExitArmed,
            StepKind::ChallengeOpened,
            StepKind::ChallengeResolved,
            StepKind::TransferReadinessRechecked,
            StepKind::ExitSettled,
        ],
    );
    let challenge = step_by_kind(&steps, StepKind::ChallengeResolved);
    let settled = step_by_kind(&steps, StepKind::ExitSettled);
    let tampered_order_rejected = challenge.zip(settled).is_some_and(|(challenge, settled)| {
        let forged_settle_sequence = challenge.sequence.saturating_sub(1);
        settled.sequence > challenge.sequence && forged_settle_sequence <= challenge.sequence
    });
    let status = if real_order && tampered_order_rejected {
        FailClosedCheckStatus::Passed
    } else {
        FailClosedCheckStatus::Failed
    };
    FailClosedCheckEvidence::new(
        &transcript.scenario_id,
        FailClosedCheckKind::SettlementBeforeChallengeRejected,
        status,
        "settlement must remain after challenge resolution and transfer readiness recheck",
        format!(
            "real_order={real_order} tampered_settlement_before_resolution_rejected={tampered_order_rejected}"
        ),
        json!({
            "challenge_resolved_sequence": challenge.map(|step| step.sequence),
            "settled_sequence": settled.map(|step| step.sequence),
            "ordered_path": real_order,
            "required_order": [
                StepKind::ForcedExitArmed.as_str(),
                StepKind::ChallengeOpened.as_str(),
                StepKind::ChallengeResolved.as_str(),
                StepKind::TransferReadinessRechecked.as_str(),
                StepKind::ExitSettled.as_str(),
            ],
        }),
        "reject_settlement_before_challenge_resolution",
        "require challenge resolution and transfer readiness recheck before final exit settlement",
    )
}

fn missing_seal_step_rejected(
    scenario: &TransferForcedExitScenarioState,
    transcript: &ScenarioTranscript,
) -> FailClosedCheckEvidence {
    let steps = pre_seal_steps(scenario, &transcript.scenario_id);
    let seals = seal_steps(scenario, &transcript.scenario_id);
    let missing_seal_would_fail = seals.is_empty()
        || !ordered(
            &steps,
            &[
                StepKind::BridgeBoundTransferSubmitted,
                StepKind::ExitClaimPrepared,
                StepKind::ForcedExitRequestedFromTransferClaim,
                StepKind::ForcedExitArmed,
                StepKind::ExitSettled,
            ],
        );
    let real_seal_present = seals.len() == 1;
    let rejected = real_seal_present && !missing_seal_would_fail;
    let status = if rejected {
        FailClosedCheckStatus::Passed
    } else {
        FailClosedCheckStatus::Failed
    };
    FailClosedCheckEvidence::new(
        &transcript.scenario_id,
        FailClosedCheckKind::MissingSealStepRejected,
        status,
        "a transcript without its final seal step must not be accepted as the public bridge-bound transfer-exit evidence",
        format!(
            "real_seal_present={real_seal_present} missing_seal_rejected={}",
            !missing_seal_would_fail
        ),
        json!({
            "seal_steps": seals.iter().map(|step| step.public_record()).collect::<Vec<_>>(),
            "pre_seal_step_count": steps.len(),
            "transcript_root": transcript.transcript_root,
        }),
        "reject_unsealed_transfer_exit_transcript",
        "record exactly one transcript seal after final settlement and readiness evidence",
    )
}

fn missing_forced_exit_claim_rejected(
    scenario: &TransferForcedExitScenarioState,
    transcript: &ScenarioTranscript,
) -> FailClosedCheckEvidence {
    let claims = scenario_claims(scenario, &transcript.scenario_id);
    let forced_claim = claims
        .iter()
        .find(|claim| claim.kind == ClaimKind::ForcedExitRequestDerivedFromClaim);
    let required_claims = required_claim_kinds();
    let present_claims = claims
        .iter()
        .map(|claim| claim.kind)
        .collect::<BTreeSet<_>>();
    let missing_after_removal = required_claims.iter().any(|kind| {
        *kind == ClaimKind::ForcedExitRequestDerivedFromClaim && present_claims.contains(kind)
    });
    let rejected = forced_claim.is_some_and(|claim| claim.status == ClaimStatus::Proven)
        && missing_after_removal;
    let status = if rejected {
        FailClosedCheckStatus::Passed
    } else {
        FailClosedCheckStatus::Failed
    };
    FailClosedCheckEvidence::new(
        &transcript.scenario_id,
        FailClosedCheckKind::MissingForcedExitClaimRejected,
        status,
        "forced-exit request must be derived from the prepared transfer claim and present in the proven claim set",
        format!(
            "forced_claim_present={} forced_claim_proven={} missing_claim_probe_rejected={missing_after_removal}",
            forced_claim.is_some(),
            forced_claim.is_some_and(|claim| claim.status == ClaimStatus::Proven)
        ),
        json!({
            "forced_exit_claim": forced_claim.map(|claim| claim.public_record()),
            "required_claims": required_claims.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "present_claims": present_claims.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
        }),
        "reject_transfer_exit_without_derived_forced_exit_claim",
        "preserve the claim proving the forced-exit request consumed the bridge-bound transfer exit claim",
    )
}

fn final_root_mismatch_rejected(
    scenario: &TransferForcedExitScenarioState,
    static_verifier: &TransferForcedExitStaticVerifierState,
    transcript: &ScenarioTranscript,
) -> FailClosedCheckEvidence {
    let steps = pre_seal_steps(scenario, &transcript.scenario_id);
    let settled = step_by_kind(&steps, StepKind::ExitSettled);
    let final_roots_match_step = settled.is_some_and(|step| {
        step.spine_root_after == transcript.final_spine_root
            && step.transfer_runtime_root_after == transcript.final_transfer_runtime_root
    });
    let static_roots_match = static_verifier
        .latest_report
        .as_ref()
        .is_some_and(|report| {
            report.final_spine_root == transcript.final_spine_root
                && report.final_transfer_runtime_root == transcript.final_transfer_runtime_root
        });
    let tampered_spine_root = tamper_root(&transcript.final_spine_root, "forged-final-spine-root");
    let tampered_transfer_root = tamper_root(
        &transcript.final_transfer_runtime_root,
        "forged-final-transfer-runtime-root",
    );
    let rejected = final_roots_match_step
        && static_roots_match
        && tampered_spine_root != transcript.final_spine_root
        && tampered_transfer_root != transcript.final_transfer_runtime_root;
    let status = if rejected {
        FailClosedCheckStatus::Passed
    } else {
        FailClosedCheckStatus::Failed
    };
    FailClosedCheckEvidence::new(
        &transcript.scenario_id,
        FailClosedCheckKind::FinalRootMismatchRejected,
        status,
        "final spine and transfer runtime roots must match the settled step and static verifier report",
        format!(
            "final_roots_match_step={final_roots_match_step} static_roots_match={static_roots_match} tampered_roots_rejected={rejected}"
        ),
        json!({
            "settled_step": settled.map(|step| step.public_record()),
            "transcript_final_spine_root": transcript.final_spine_root,
            "transcript_final_transfer_runtime_root": transcript.final_transfer_runtime_root,
            "tampered_spine_root": tampered_spine_root,
            "tampered_transfer_runtime_root": tampered_transfer_root,
        }),
        "reject_final_root_mismatch",
        "derive final bridge and transfer runtime roots from the settled transcript and static verifier report",
    )
}

fn privacy_fee_pq_surface_preserved(
    scenario: &TransferForcedExitScenarioState,
    static_verifier: &TransferForcedExitStaticVerifierState,
    transcript: &ScenarioTranscript,
) -> FailClosedCheckEvidence {
    let claims = scenario_claims(scenario, &transcript.scenario_id);
    let privacy_claim = claims
        .iter()
        .find(|claim| claim.kind == ClaimKind::RootsOnlyTranscript);
    let fee_pq_claim = claims
        .iter()
        .find(|claim| claim.kind == ClaimKind::LowFeePrivacyPqBounds);
    let static_privacy_check = static_verifier.latest_report.as_ref().and_then(|report| {
        report
            .checks
            .get(StaticCheckKind::PrivacyFeePqSurface.as_str())
    });
    let privacy_ok = privacy_claim.is_some_and(|claim| claim.status == ClaimStatus::Proven)
        && fee_pq_claim.is_some_and(|claim| claim.status == ClaimStatus::Proven)
        && static_privacy_check.is_some_and(|check| check.status == StaticCheckStatus::Passed)
        && transcript.privacy_set_size_observed >= scenario.config.min_privacy_set_size;
    let status = if privacy_ok {
        FailClosedCheckStatus::Passed
    } else {
        FailClosedCheckStatus::Failed
    };
    FailClosedCheckEvidence::new(
        &transcript.scenario_id,
        FailClosedCheckKind::PrivacyFeePqSurfacePreserved,
        status,
        "transfer forced-exit evidence must expose roots only while preserving privacy floor, low-fee bound, and PQ authorization claims",
        format!(
            "privacy_claim={} fee_pq_claim={} static_privacy_check={} privacy_set_size={}",
            privacy_claim.is_some(),
            fee_pq_claim.is_some(),
            static_privacy_check
                .map(|check| check.status.as_str())
                .unwrap_or("missing"),
            transcript.privacy_set_size_observed
        ),
        json!({
            "privacy_claim": privacy_claim.map(|claim| claim.public_record()),
            "fee_pq_claim": fee_pq_claim.map(|claim| claim.public_record()),
            "static_privacy_check": static_privacy_check.map(|check| check.public_record()),
            "privacy_set_size_observed": transcript.privacy_set_size_observed,
            "min_privacy_set_size": scenario.config.min_privacy_set_size,
        }),
        "reject_transfer_exit_surface_with_privacy_fee_or_pq_gap",
        "keep public records limited to roots while requiring low-fee and PQ authorization bounds",
    )
}

fn counters_consistent(
    scenario: &TransferForcedExitScenarioState,
    static_verifier: &TransferForcedExitStaticVerifierState,
    transcript: &ScenarioTranscript,
) -> FailClosedCheckEvidence {
    let claims = scenario_claims(scenario, &transcript.scenario_id);
    let pre_seal = pre_seal_steps(scenario, &transcript.scenario_id);
    let proven_claims = claims
        .iter()
        .filter(|claim| claim.status == ClaimStatus::Proven)
        .count() as u64;
    let watch_claims = claims
        .iter()
        .filter(|claim| claim.status == ClaimStatus::Watch)
        .count() as u64;
    let failed_claims = claims
        .iter()
        .filter(|claim| claim.status == ClaimStatus::Failed)
        .count() as u64;
    let scenario_counters_ok = scenario.counters.steps_recorded == scenario.steps.len() as u64
        && scenario.counters.claims_recorded == scenario.claims.len() as u64
        && scenario.counters.transcripts_sealed == scenario.transcripts.len() as u64
        && transcript.step_count == pre_seal.len() as u64
        && transcript.proven_claim_count == proven_claims
        && transcript.watch_claim_count == watch_claims
        && transcript.failed_claim_count == failed_claims;
    let static_counters_ok = static_verifier.counters.reports_run as usize
        == static_verifier.report_history.len()
        && static_verifier
            .latest_report
            .as_ref()
            .is_some_and(|report| report.failed_checks == 0);
    let status = if scenario_counters_ok && static_counters_ok {
        FailClosedCheckStatus::Passed
    } else {
        FailClosedCheckStatus::Failed
    };
    FailClosedCheckEvidence::new(
        &transcript.scenario_id,
        FailClosedCheckKind::CountersConsistent,
        status,
        "scenario and verifier counters must agree with actual steps, claims, transcripts, and reports",
        format!(
            "scenario_counters_ok={scenario_counters_ok} static_counters_ok={static_counters_ok}"
        ),
        json!({
            "scenario_counters": scenario.counters.public_record(),
            "scenario_steps": scenario.steps.len(),
            "scenario_claims": scenario.claims.len(),
            "scenario_transcripts": scenario.transcripts.len(),
            "transcript_step_count": transcript.step_count,
            "pre_seal_step_count": pre_seal.len(),
            "proven_claims": proven_claims,
            "watch_claims": watch_claims,
            "failed_claims": failed_claims,
            "static_counters": static_verifier.counters.public_record(),
            "static_report_history_len": static_verifier.report_history.len(),
        }),
        "reject_bundle_with_counter_drift",
        "refresh counters from the canonical scenario and verifier collections before publishing the report",
    )
}

fn latest_transcript(scenario: &TransferForcedExitScenarioState) -> Result<&ScenarioTranscript> {
    scenario
        .transcripts
        .values()
        .next_back()
        .ok_or_else(|| "scenario state has no transfer forced-exit transcript".to_string())
}

fn pre_seal_steps<'a>(
    scenario: &'a TransferForcedExitScenarioState,
    scenario_id: &str,
) -> Vec<&'a ScenarioStep> {
    scenario
        .steps
        .iter()
        .filter(|step| {
            step.scenario_id == scenario_id && step.kind != StepKind::ScenarioTranscriptSealed
        })
        .collect()
}

fn seal_steps<'a>(
    scenario: &'a TransferForcedExitScenarioState,
    scenario_id: &str,
) -> Vec<&'a ScenarioStep> {
    scenario
        .steps
        .iter()
        .filter(|step| {
            step.scenario_id == scenario_id && step.kind == StepKind::ScenarioTranscriptSealed
        })
        .collect()
}

fn scenario_claims<'a>(
    scenario: &'a TransferForcedExitScenarioState,
    scenario_id: &str,
) -> Vec<&'a ScenarioClaim> {
    scenario
        .claims
        .values()
        .filter(|claim| claim.scenario_id == scenario_id)
        .collect()
}

fn recompute_step_root(steps: &[&ScenarioStep]) -> String {
    let records = steps
        .iter()
        .map(|step| step.public_record())
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SCENARIO-STEPS",
        &records,
    )
}

fn recompute_claim_root(claims: &[&ScenarioClaim]) -> String {
    let records = claims
        .iter()
        .map(|claim| claim.public_record())
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SCENARIO-CLAIMS",
        &records,
    )
}

fn tampered_step_root(steps: &[&ScenarioStep], kind: StepKind, tamper_label: &str) -> String {
    let records = steps
        .iter()
        .map(|step| {
            if step.kind == kind {
                let mut record = step.public_record();
                record["evidence_root"] = json!(tamper_root(&step.evidence_root, tamper_label));
                record
            } else {
                step.public_record()
            }
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SCENARIO-STEPS",
        &records,
    )
}

fn tampered_single_step_root(step: &ScenarioStep, tamper_label: &str) -> String {
    let mut record = step.public_record();
    record["evidence_root"] = json!(tamper_root(&step.evidence_root, tamper_label));
    record_root("tampered_scenario_step", &record)
}

fn tampered_claim_root(claims: &[&ScenarioClaim], kind: ClaimKind, tamper_label: &str) -> String {
    let records = claims
        .iter()
        .map(|claim| {
            if claim.kind == kind {
                let mut record = claim.public_record();
                record["evidence_root"] = json!(tamper_root(&claim.evidence_root, tamper_label));
                record
            } else {
                claim.public_record()
            }
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SCENARIO-CLAIMS",
        &records,
    )
}

fn step_by_kind<'a>(steps: &'a [&'a ScenarioStep], kind: StepKind) -> Option<&'a ScenarioStep> {
    steps.iter().copied().find(|step| step.kind == kind)
}

fn ordered(steps: &[&ScenarioStep], kinds: &[StepKind]) -> bool {
    let mut previous = 0;
    for kind in kinds {
        let Some(step) = step_by_kind(steps, *kind) else {
            return false;
        };
        if step.sequence <= previous {
            return false;
        }
        previous = step.sequence;
    }
    true
}

fn required_claim_kinds() -> BTreeSet<ClaimKind> {
    [
        ClaimKind::BridgeMintedNoteConsumed,
        ClaimKind::TransferReceiptRecordedBySpine,
        ClaimKind::TransferReceiptAnchoredBySpine,
        ClaimKind::ExitClaimMatchesTransferReceipt,
        ClaimKind::ForcedExitRequestDerivedFromClaim,
        ClaimKind::LivenessFailureCanArmForcedExit,
        ClaimKind::ChallengeWindowDoesNotBlockSettlement,
        ClaimKind::SettlementReleasesAfterChallengeResolution,
        ClaimKind::LowFeePrivacyPqBounds,
        ClaimKind::RootsOnlyTranscript,
    ]
    .into_iter()
    .collect()
}

fn aggregate_report_status(
    config: &Config,
    checks: &BTreeMap<String, FailClosedCheckEvidence>,
    rejected_probe_count: u64,
) -> FailClosedReportStatus {
    if checks
        .values()
        .any(|check| check.status == FailClosedCheckStatus::Failed)
    {
        FailClosedReportStatus::Failed
    } else if rejected_probe_count < config.min_failclosed_probes
        || checks
            .values()
            .any(|check| check.status == FailClosedCheckStatus::Watch)
    {
        FailClosedReportStatus::Watch
    } else {
        FailClosedReportStatus::Passed
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn failclosed_report_id(scenario_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-FAILCLOSED-REPORT-ID",
        &[HashPart::Str(scenario_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn failclosed_check_id(
    scenario_id: &str,
    kind: FailClosedCheckKind,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-FAILCLOSED-CHECK-ID",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn evidence_root(scenario_id: &str, label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-FAILCLOSED-EVIDENCE",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn report_root(
    scenario_id: &str,
    status: FailClosedReportStatus,
    scenario_state_root: &str,
    static_verifier_root: &str,
    authority_crosscheck_root: &str,
    adversarial_matrix_root: &str,
    transcript_root: &str,
    check_root: &str,
    probe_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-FAILCLOSED-REPORT-ROOT",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(status.as_str()),
            HashPart::Str(scenario_state_root),
            HashPart::Str(static_verifier_root),
            HashPart::Str(authority_crosscheck_root),
            HashPart::Str(adversarial_matrix_root),
            HashPart::Str(transcript_root),
            HashPart::Str(check_root),
            HashPart::Str(probe_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-FAILCLOSED-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

pub fn tamper_root(root: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-FAILCLOSED-TAMPER",
        &[HashPart::Str(root), HashPart::Str(label)],
        32,
    )
}

pub fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
