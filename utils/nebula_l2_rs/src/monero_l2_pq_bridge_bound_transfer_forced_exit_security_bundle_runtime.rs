use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_bound_transfer_forced_exit_failclosed_crosscheck_runtime::{
        FailClosedCheckKind, FailClosedCheckStatus, FailClosedReportStatus,
        State as TransferForcedExitFailclosedState,
    },
    monero_l2_pq_bridge_bound_transfer_forced_exit_scenario_runtime::{
        ClaimKind, ClaimStatus, ScenarioClaim, ScenarioStatus, ScenarioStep, ScenarioTranscript,
        State as TransferForcedExitScenarioState, StepKind,
    },
    monero_l2_pq_bridge_bound_transfer_forced_exit_static_verifier_runtime::{
        ReportStatus as StaticReportStatus, State as TransferForcedExitStaticVerifierState,
        StaticCheckKind, StaticCheckStatus,
    },
    monero_l2_pq_bridge_exit_adversarial_scenario_matrix_runtime::{
        AdversarialCaseKind, CaseStatus as AdversarialCaseStatus, MatrixStatus,
        State as AdversarialMatrixState,
    },
    monero_l2_pq_bridge_exit_authority_crosscheck_verifier_runtime::{
        CrossCheckReportStatus as AuthorityReportStatus, State as AuthorityCrosscheckState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeBoundTransferForcedExitSecurityBundleRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_BOUND_TRANSFER_FORCED_EXIT_SECURITY_BUNDLE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-bound-transfer-forced-exit-security-bundle-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_BOUND_TRANSFER_FORCED_EXIT_SECURITY_BUNDLE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const BUNDLE_SUITE: &str = "monero-l2-pq-bridge-bound-transfer-forced-exit-security-bundle-v1";
pub const DEFAULT_MIN_STATIC_CHECKS: u64 = 12;
pub const DEFAULT_MIN_FAILCLOSED_PROBES: u64 = 7;
pub const DEFAULT_MIN_ADVERSARIAL_CASES: u64 = 8;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityBundleCheckKind {
    SourceRootsPresent,
    TransferTranscriptProven,
    StaticVerifierAccepted,
    FailclosedReportAccepted,
    AuthorityCrosscheckAccepted,
    AdversarialMatrixAccepted,
    ExitClaimEscapePathCovered,
    ChallengeSettlementOrderingCovered,
    RootContinuityAcrossBundle,
    PrivacyFeePqSurfaceCovered,
    MoneroThreatCoveragePresent,
    UserEscapeInvariantCovered,
    WatcherSequencerAuthoritySeparation,
    CountersConsistent,
    VerifiedReadinessClassified,
}

impl SecurityBundleCheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceRootsPresent => "source_roots_present",
            Self::TransferTranscriptProven => "transfer_transcript_proven",
            Self::StaticVerifierAccepted => "static_verifier_accepted",
            Self::FailclosedReportAccepted => "failclosed_report_accepted",
            Self::AuthorityCrosscheckAccepted => "authority_crosscheck_accepted",
            Self::AdversarialMatrixAccepted => "adversarial_matrix_accepted",
            Self::ExitClaimEscapePathCovered => "exit_claim_escape_path_covered",
            Self::ChallengeSettlementOrderingCovered => "challenge_settlement_ordering_covered",
            Self::RootContinuityAcrossBundle => "root_continuity_across_bundle",
            Self::PrivacyFeePqSurfaceCovered => "privacy_fee_pq_surface_covered",
            Self::MoneroThreatCoveragePresent => "monero_threat_coverage_present",
            Self::UserEscapeInvariantCovered => "user_escape_invariant_covered",
            Self::WatcherSequencerAuthoritySeparation => "watcher_sequencer_authority_separation",
            Self::CountersConsistent => "counters_consistent",
            Self::VerifiedReadinessClassified => "verified_readiness_classified",
        }
    }

    pub fn all() -> [Self; 15] {
        [
            Self::SourceRootsPresent,
            Self::TransferTranscriptProven,
            Self::StaticVerifierAccepted,
            Self::FailclosedReportAccepted,
            Self::AuthorityCrosscheckAccepted,
            Self::AdversarialMatrixAccepted,
            Self::ExitClaimEscapePathCovered,
            Self::ChallengeSettlementOrderingCovered,
            Self::RootContinuityAcrossBundle,
            Self::PrivacyFeePqSurfaceCovered,
            Self::MoneroThreatCoveragePresent,
            Self::UserEscapeInvariantCovered,
            Self::WatcherSequencerAuthoritySeparation,
            Self::CountersConsistent,
            Self::VerifiedReadinessClassified,
        ]
    }

    pub fn is_critical(self) -> bool {
        !matches!(self, Self::VerifiedReadinessClassified)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityBundleCheckStatus {
    Passed,
    Watch,
    Failed,
}

impl SecurityBundleCheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Watch => "watch",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityBundleReportStatus {
    Passed,
    Watch,
    Failed,
}

impl SecurityBundleReportStatus {
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
    pub bundle_suite: String,
    pub min_static_checks: u64,
    pub min_failclosed_probes: u64,
    pub min_adversarial_cases: u64,
    pub cargo_checks_deferred: bool,
    pub runtime_tests_deferred: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            bundle_suite: BUNDLE_SUITE.to_string(),
            min_static_checks: DEFAULT_MIN_STATIC_CHECKS,
            min_failclosed_probes: DEFAULT_MIN_FAILCLOSED_PROBES,
            min_adversarial_cases: DEFAULT_MIN_ADVERSARIAL_CASES,
            cargo_checks_deferred: true,
            runtime_tests_deferred: true,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "bundle_suite": self.bundle_suite,
            "min_static_checks": self.min_static_checks,
            "min_failclosed_probes": self.min_failclosed_probes,
            "min_adversarial_cases": self.min_adversarial_cases,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "runtime_tests_deferred": self.runtime_tests_deferred,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecurityBundleCheckEvidence {
    pub check_id: String,
    pub kind: SecurityBundleCheckKind,
    pub status: SecurityBundleCheckStatus,
    pub requirement: String,
    pub observed: String,
    pub evidence_root: String,
    pub release_effect: String,
    pub remediation: String,
}

impl SecurityBundleCheckEvidence {
    pub fn new(
        scenario_id: &str,
        kind: SecurityBundleCheckKind,
        status: SecurityBundleCheckStatus,
        requirement: impl Into<String>,
        observed: impl Into<String>,
        evidence_record: Value,
        release_effect: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        let evidence_root = evidence_root(scenario_id, kind.as_str(), &evidence_record);
        let check_id = security_bundle_check_id(scenario_id, kind, &evidence_root);
        Self {
            check_id,
            kind,
            status,
            requirement: requirement.into(),
            observed: observed.into(),
            evidence_root,
            release_effect: release_effect.into(),
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
            "release_effect": self.release_effect,
            "remediation": self.remediation,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("security_bundle_check", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecurityBundleReport {
    pub report_id: String,
    pub scenario_id: String,
    pub status: SecurityBundleReportStatus,
    pub readiness_label: String,
    pub scenario_state_root: String,
    pub static_verifier_root: String,
    pub failclosed_crosscheck_root: String,
    pub authority_crosscheck_root: String,
    pub adversarial_matrix_root: String,
    pub transcript_root: String,
    pub passed_checks: u64,
    pub watch_checks: u64,
    pub failed_checks: u64,
    pub critical_checks_passed: u64,
    pub critical_checks_total: u64,
    pub checks: BTreeMap<String, SecurityBundleCheckEvidence>,
    pub roots: SecurityBundleReportRoots,
}

impl SecurityBundleReport {
    pub fn public_record(&self) -> Value {
        let checks = self
            .checks
            .values()
            .map(SecurityBundleCheckEvidence::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "scenario_id": self.scenario_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "scenario_state_root": self.scenario_state_root,
            "static_verifier_root": self.static_verifier_root,
            "failclosed_crosscheck_root": self.failclosed_crosscheck_root,
            "authority_crosscheck_root": self.authority_crosscheck_root,
            "adversarial_matrix_root": self.adversarial_matrix_root,
            "transcript_root": self.transcript_root,
            "passed_checks": self.passed_checks,
            "watch_checks": self.watch_checks,
            "failed_checks": self.failed_checks,
            "critical_checks_passed": self.critical_checks_passed,
            "critical_checks_total": self.critical_checks_total,
            "checks": checks,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecurityBundleReportRoots {
    pub check_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl SecurityBundleReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "check_root": self.check_root,
            "source_root": self.source_root,
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
    pub critical_checks_passed: u64,
    pub bridge_exit_bundles_classified: u64,
    pub deferred_verification_watches: u64,
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
            "critical_checks_passed": self.critical_checks_passed,
            "bridge_exit_bundles_classified": self.bridge_exit_bundles_classified,
            "deferred_verification_watches": self.deferred_verification_watches,
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
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SECURITY-BUNDLE-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SECURITY-BUNDLE-STATE",
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
    pub latest_report: Option<SecurityBundleReport>,
    pub report_history: Vec<SecurityBundleReport>,
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
        let failclosed =
            crate::monero_l2_pq_bridge_bound_transfer_forced_exit_failclosed_crosscheck_runtime::devnet(
            );
        let authority =
            crate::monero_l2_pq_bridge_exit_authority_crosscheck_verifier_runtime::devnet();
        let adversarial =
            crate::monero_l2_pq_bridge_exit_adversarial_scenario_matrix_runtime::devnet();
        state
            .verify_security_bundle(
                &scenario,
                &static_verifier,
                &failclosed,
                &authority,
                &adversarial,
            )
            .expect("devnet bridge-bound transfer forced-exit security bundle");
        state
    }

    pub fn verify_security_bundle(
        &mut self,
        scenario: &TransferForcedExitScenarioState,
        static_verifier: &TransferForcedExitStaticVerifierState,
        failclosed: &TransferForcedExitFailclosedState,
        authority: &AuthorityCrosscheckState,
        adversarial: &AdversarialMatrixState,
    ) -> Result<String> {
        let transcript = latest_transcript(scenario)?;
        let scenario_id = transcript.scenario_id.clone();
        let mut checks = BTreeMap::new();
        for check in evaluate_security_bundle_checks(
            &self.config,
            scenario,
            static_verifier,
            failclosed,
            authority,
            adversarial,
            transcript,
        ) {
            checks.insert(check.kind.as_str().to_string(), check);
        }
        ensure(
            SecurityBundleCheckKind::all()
                .iter()
                .all(|kind| checks.contains_key(kind.as_str())),
            "security bundle omitted a required bridge-bound transfer forced-exit check",
        )?;

        let passed_checks = checks
            .values()
            .filter(|check| check.status == SecurityBundleCheckStatus::Passed)
            .count() as u64;
        let watch_checks = checks
            .values()
            .filter(|check| check.status == SecurityBundleCheckStatus::Watch)
            .count() as u64;
        let failed_checks = checks
            .values()
            .filter(|check| check.status == SecurityBundleCheckStatus::Failed)
            .count() as u64;
        let critical_checks_total = SecurityBundleCheckKind::all()
            .iter()
            .filter(|kind| kind.is_critical())
            .count() as u64;
        let critical_checks_passed = checks
            .values()
            .filter(|check| {
                check.kind.is_critical() && check.status == SecurityBundleCheckStatus::Passed
            })
            .count() as u64;
        let status = aggregate_report_status(&checks);
        let readiness_label = readiness_label(status, &self.config).to_string();
        let check_records = checks
            .values()
            .map(SecurityBundleCheckEvidence::public_record)
            .collect::<Vec<_>>();
        let check_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SECURITY-BUNDLE-CHECKS",
            &check_records,
        );
        let source_root = source_root(
            &scenario.state_root(),
            &static_verifier.state_root(),
            &failclosed.state_root(),
            &authority.state_root(),
            &adversarial.state_root(),
            &transcript.transcript_root,
        );
        let report_root = report_root(
            &scenario_id,
            status,
            &readiness_label,
            &source_root,
            &check_root,
        );
        let report_id = security_bundle_report_id(&scenario_id, &report_root);
        let report = SecurityBundleReport {
            report_id: report_id.clone(),
            scenario_id,
            status,
            readiness_label,
            scenario_state_root: scenario.state_root(),
            static_verifier_root: static_verifier.state_root(),
            failclosed_crosscheck_root: failclosed.state_root(),
            authority_crosscheck_root: authority.state_root(),
            adversarial_matrix_root: adversarial.state_root(),
            transcript_root: transcript.transcript_root.clone(),
            passed_checks,
            watch_checks,
            failed_checks,
            critical_checks_passed,
            critical_checks_total,
            checks,
            roots: SecurityBundleReportRoots {
                check_root,
                source_root,
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
            "bundle_suite": self.config.bundle_suite,
            "latest_report": self.latest_report.as_ref().map(SecurityBundleReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: SecurityBundleReport) {
        self.counters.reports_run += 1;
        self.counters.checks_run += report.checks.len() as u64;
        self.counters.checks_passed += report.passed_checks;
        self.counters.checks_watch += report.watch_checks;
        self.counters.checks_failed += report.failed_checks;
        self.counters.critical_checks_passed += report.critical_checks_passed;
        self.counters.bridge_exit_bundles_classified += 1;
        self.counters.deferred_verification_watches += report
            .checks
            .values()
            .filter(|check| {
                check.kind == SecurityBundleCheckKind::VerifiedReadinessClassified
                    && check.status == SecurityBundleCheckStatus::Watch
            })
            .count() as u64;
        match report.status {
            SecurityBundleReportStatus::Passed => self.counters.reports_passed += 1,
            SecurityBundleReportStatus::Watch => self.counters.reports_watch += 1,
            SecurityBundleReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(SecurityBundleReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SECURITY-BUNDLE-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

pub fn evaluate_security_bundle_checks(
    config: &Config,
    scenario: &TransferForcedExitScenarioState,
    static_verifier: &TransferForcedExitStaticVerifierState,
    failclosed: &TransferForcedExitFailclosedState,
    authority: &AuthorityCrosscheckState,
    adversarial: &AdversarialMatrixState,
    transcript: &ScenarioTranscript,
) -> Vec<SecurityBundleCheckEvidence> {
    vec![
        source_roots_present(
            scenario,
            static_verifier,
            failclosed,
            authority,
            adversarial,
            transcript,
        ),
        transfer_transcript_proven(config, scenario, transcript),
        static_verifier_accepted(config, scenario, static_verifier, transcript),
        failclosed_report_accepted(config, failclosed, transcript),
        authority_crosscheck_accepted(authority, failclosed, transcript),
        adversarial_matrix_accepted(config, adversarial, authority),
        exit_claim_escape_path_covered(scenario, failclosed, transcript),
        challenge_settlement_ordering_covered(scenario, failclosed, adversarial, transcript),
        root_continuity_across_bundle(
            scenario,
            static_verifier,
            failclosed,
            authority,
            adversarial,
            transcript,
        ),
        privacy_fee_pq_surface_covered(scenario, static_verifier, failclosed, transcript),
        monero_threat_coverage_present(config, adversarial, authority),
        user_escape_invariant_covered(scenario, failclosed, transcript),
        watcher_sequencer_authority_separation(authority, adversarial, failclosed, transcript),
        counters_consistent(
            scenario,
            static_verifier,
            failclosed,
            authority,
            adversarial,
            transcript,
        ),
        verified_readiness_classified(config, failclosed, authority, adversarial, transcript),
    ]
}

fn source_roots_present(
    scenario: &TransferForcedExitScenarioState,
    static_verifier: &TransferForcedExitStaticVerifierState,
    failclosed: &TransferForcedExitFailclosedState,
    authority: &AuthorityCrosscheckState,
    adversarial: &AdversarialMatrixState,
    transcript: &ScenarioTranscript,
) -> SecurityBundleCheckEvidence {
    let scenario_state_root = scenario.state_root();
    let static_verifier_root = static_verifier.state_root();
    let failclosed_crosscheck_root = failclosed.state_root();
    let authority_crosscheck_root = authority.state_root();
    let adversarial_matrix_root = adversarial.state_root();
    let transcript_root = transcript.transcript_root.clone();
    let roots = [
        &scenario_state_root,
        &static_verifier_root,
        &failclosed_crosscheck_root,
        &authority_crosscheck_root,
        &adversarial_matrix_root,
        &transcript_root,
    ];
    let all_present = roots.iter().all(|root| !root.is_empty());
    let status = if all_present {
        SecurityBundleCheckStatus::Passed
    } else {
        SecurityBundleCheckStatus::Failed
    };
    SecurityBundleCheckEvidence::new(
        &transcript.scenario_id,
        SecurityBundleCheckKind::SourceRootsPresent,
        status,
        "all bridge-bound transfer forced-exit source roots must be present before bundle classification",
        format!("all_present={all_present} source_roots={}", roots.len()),
        json!({
            "scenario_state_root": scenario_state_root,
            "static_verifier_root": static_verifier_root,
            "failclosed_crosscheck_root": failclosed_crosscheck_root,
            "authority_crosscheck_root": authority_crosscheck_root,
            "adversarial_matrix_root": adversarial_matrix_root,
            "transcript_root": transcript_root,
        }),
        "block_bundle_with_missing_source_root",
        "rebuild scenario, static verifier, fail-closed verifier, authority cross-check, and adversarial matrix roots",
    )
}

fn transfer_transcript_proven(
    config: &Config,
    scenario: &TransferForcedExitScenarioState,
    transcript: &ScenarioTranscript,
) -> SecurityBundleCheckEvidence {
    let steps = pre_seal_steps(scenario, &transcript.scenario_id);
    let claims = scenario_claims(scenario, &transcript.scenario_id);
    let proven_claims = claims
        .iter()
        .filter(|claim| claim.status == ClaimStatus::Proven)
        .count() as u64;
    let roots_match = recompute_step_root(&steps) == transcript.step_root
        && recompute_claim_root(&claims) == transcript.claim_root;
    let proven = transcript.status == ScenarioStatus::Proven
        && transcript.step_count >= config.min_static_checks
        && proven_claims >= scenario.config.min_proven_claims
        && roots_match;
    let status = if proven {
        SecurityBundleCheckStatus::Passed
    } else {
        SecurityBundleCheckStatus::Failed
    };
    SecurityBundleCheckEvidence::new(
        &transcript.scenario_id,
        SecurityBundleCheckKind::TransferTranscriptProven,
        status,
        "deposit-to-private-transfer-to-forced-exit transcript must be proven and root-consistent",
        format!(
            "status={} steps={} proven_claims={} roots_match={roots_match}",
            transcript.status.as_str(),
            transcript.step_count,
            proven_claims
        ),
        json!({
            "transcript": transcript.public_record(),
            "scenario_state_root": scenario.state_root(),
            "recomputed_step_root": recompute_step_root(&steps),
            "recomputed_claim_root": recompute_claim_root(&claims),
        }),
        "block_bundle_if_vertical_slice_is_not_proven",
        "rerun the bridge-bound transfer forced-exit scenario and seal a proven roots-only transcript",
    )
}

fn static_verifier_accepted(
    config: &Config,
    scenario: &TransferForcedExitScenarioState,
    static_verifier: &TransferForcedExitStaticVerifierState,
    transcript: &ScenarioTranscript,
) -> SecurityBundleCheckEvidence {
    let latest = static_verifier.latest_report.as_ref();
    let accepted = latest.is_some_and(|report| {
        report.status == StaticReportStatus::Passed
            && report.failed_checks == 0
            && report.scenario_state_root == scenario.state_root()
            && report.transcript_root == transcript.transcript_root
            && report.checks.len() as u64 >= config.min_static_checks
            && StaticCheckKind::all()
                .iter()
                .all(|kind| report.checks.contains_key(kind.as_str()))
            && report
                .checks
                .values()
                .all(|check| check.status == StaticCheckStatus::Passed)
    });
    let status = if accepted {
        SecurityBundleCheckStatus::Passed
    } else {
        SecurityBundleCheckStatus::Failed
    };
    SecurityBundleCheckEvidence::new(
        &transcript.scenario_id,
        SecurityBundleCheckKind::StaticVerifierAccepted,
        status,
        "static verifier must accept the same transcript, step root, claim root, final roots, and privacy/PQ/fee surface",
        format!(
            "static_report_present={} accepted={accepted}",
            latest.is_some()
        ),
        json!({
            "static_verifier_root": static_verifier.state_root(),
            "latest_report": latest.map(|report| report.public_record()),
            "expected_checks": StaticCheckKind::all().map(StaticCheckKind::as_str),
        }),
        "block_bundle_without_static_verifier_pass",
        "rerun static verifier against the exact bridge-bound transfer forced-exit scenario root",
    )
}

fn failclosed_report_accepted(
    config: &Config,
    failclosed: &TransferForcedExitFailclosedState,
    transcript: &ScenarioTranscript,
) -> SecurityBundleCheckEvidence {
    let latest = failclosed.latest_report.as_ref();
    let status_is_acceptable = latest.is_some_and(|report| {
        matches!(
            report.status,
            FailClosedReportStatus::Passed | FailClosedReportStatus::Watch
        )
    });
    let probes_ok = latest.is_some_and(|report| {
        report.failed_checks == 0
            && report.rejected_probe_count >= config.min_failclosed_probes
            && report.failclosed_probe_count >= config.min_failclosed_probes
            && report.transcript_root == transcript.transcript_root
    });
    let required_probe_checks = [
        FailClosedCheckKind::PreSealStepRootTamperRejected,
        FailClosedCheckKind::ClaimRootTamperRejected,
        FailClosedCheckKind::ExitClaimRootTamperRejected,
        FailClosedCheckKind::SettlementBeforeChallengeRejected,
        FailClosedCheckKind::MissingForcedExitClaimRejected,
        FailClosedCheckKind::FinalRootMismatchRejected,
    ];
    let required_checks_passed = latest.is_some_and(|report| {
        required_probe_checks.iter().all(|kind| {
            report
                .checks
                .get(kind.as_str())
                .is_some_and(|check| check.status == FailClosedCheckStatus::Passed)
        })
    });
    let accepted = status_is_acceptable && probes_ok && required_checks_passed;
    let status = if accepted {
        SecurityBundleCheckStatus::Passed
    } else {
        SecurityBundleCheckStatus::Failed
    };
    SecurityBundleCheckEvidence::new(
        &transcript.scenario_id,
        SecurityBundleCheckKind::FailclosedReportAccepted,
        status,
        "fail-closed report must reject bad roots, bad ordering, missing claims, and final-root mismatch for this transcript",
        format!(
            "status_acceptable={status_is_acceptable} probes_ok={probes_ok} required_checks_passed={required_checks_passed}"
        ),
        json!({
            "failclosed_crosscheck_root": failclosed.state_root(),
            "latest_report": latest.map(|report| report.public_record()),
            "required_probe_checks": required_probe_checks.map(FailClosedCheckKind::as_str),
        }),
        "block_bundle_without_failclosed_probe_coverage",
        "rerun the fail-closed cross-check and require rejected tamper, ordering, missing-claim, and final-root probes",
    )
}

fn authority_crosscheck_accepted(
    authority: &AuthorityCrosscheckState,
    failclosed: &TransferForcedExitFailclosedState,
    transcript: &ScenarioTranscript,
) -> SecurityBundleCheckEvidence {
    let latest = authority.latest_report.as_ref();
    let authority_accepted = latest.is_some_and(|report| {
        matches!(
            report.status,
            AuthorityReportStatus::Passed | AuthorityReportStatus::Watch
        ) && report.failed_checks == 0
    });
    let failclosed_available = failclosed.latest_report.as_ref().is_some_and(|report| {
        report.transcript_root == transcript.transcript_root && report.failed_checks == 0
    });
    let status = if authority_accepted && failclosed_available {
        SecurityBundleCheckStatus::Passed
    } else {
        SecurityBundleCheckStatus::Failed
    };
    SecurityBundleCheckEvidence::new(
        &transcript.scenario_id,
        SecurityBundleCheckKind::AuthorityCrosscheckAccepted,
        status,
        "bridge authority cross-check must be green enough to carry transfer forced-exit evidence into the authority bundle",
        format!(
            "authority_accepted={authority_accepted} failclosed_available={failclosed_available}"
        ),
        json!({
            "authority_crosscheck_root": authority.state_root(),
            "authority_latest_report": latest.map(|report| report.public_record()),
            "failclosed_crosscheck_root": failclosed.state_root(),
        }),
        "block_bundle_without_authority_evidence",
        "extend authority cross-check roots to consume the transfer fail-closed report directly in the next pass",
    )
}

fn adversarial_matrix_accepted(
    config: &Config,
    adversarial: &AdversarialMatrixState,
    authority: &AuthorityCrosscheckState,
) -> SecurityBundleCheckEvidence {
    let matrix_ok = adversarial.matrix_status == MatrixStatus::Passed
        && adversarial.counters.cases_failed == 0
        && adversarial.counters.fail_closed_cases >= config.min_adversarial_cases
        && adversarial.cases.len() as u64 >= config.min_adversarial_cases;
    let authority_present = authority.latest_report.is_some();
    let status = if matrix_ok && authority_present {
        SecurityBundleCheckStatus::Passed
    } else {
        SecurityBundleCheckStatus::Failed
    };
    SecurityBundleCheckEvidence::new(
        "bridge-bound-transfer-forced-exit-security-bundle",
        SecurityBundleCheckKind::AdversarialMatrixAccepted,
        status,
        "adversarial matrix must pass all critical bridge threat cases before transfer exit evidence is treated as coherent",
        format!(
            "matrix_status={} cases={} failclosed_cases={} authority_present={authority_present}",
            adversarial.matrix_status.as_str(),
            adversarial.cases.len(),
            adversarial.counters.fail_closed_cases
        ),
        json!({
            "adversarial_matrix_root": adversarial.state_root(),
            "matrix_status": adversarial.matrix_status.as_str(),
            "cases": adversarial.cases.values().map(|case| case.public_record()).collect::<Vec<_>>(),
            "counters": adversarial.counters.public_record(),
        }),
        "block_bundle_without_adversarial_matrix_pass",
        "rerun adversarial matrix and keep watcher, finality, privacy, fee, liquidity, replay, and challenge cases fail-closed",
    )
}

fn exit_claim_escape_path_covered(
    scenario: &TransferForcedExitScenarioState,
    failclosed: &TransferForcedExitFailclosedState,
    transcript: &ScenarioTranscript,
) -> SecurityBundleCheckEvidence {
    let claims = scenario_claims(scenario, &transcript.scenario_id);
    let transfer_claim = claim_by_kind(&claims, ClaimKind::ExitClaimMatchesTransferReceipt);
    let forced_exit_claim = claim_by_kind(&claims, ClaimKind::ForcedExitRequestDerivedFromClaim);
    let failclosed_latest = failclosed.latest_report.as_ref();
    let exit_claim_probe =
        failclosed_check_passed(failclosed, FailClosedCheckKind::ExitClaimRootTamperRejected);
    let missing_forced_probe = failclosed_check_passed(
        failclosed,
        FailClosedCheckKind::MissingForcedExitClaimRejected,
    );
    let covered = transfer_claim.is_some_and(|claim| claim.status == ClaimStatus::Proven)
        && forced_exit_claim.is_some_and(|claim| claim.status == ClaimStatus::Proven)
        && exit_claim_probe
        && missing_forced_probe;
    let status = if covered {
        SecurityBundleCheckStatus::Passed
    } else {
        SecurityBundleCheckStatus::Failed
    };
    SecurityBundleCheckEvidence::new(
        &transcript.scenario_id,
        SecurityBundleCheckKind::ExitClaimEscapePathCovered,
        status,
        "prepared transfer exit claim must be proven, consumed by forced exit, and protected by fail-closed probes",
        format!(
            "transfer_claim={} forced_exit_claim={} exit_claim_probe={exit_claim_probe} missing_forced_probe={missing_forced_probe}",
            transfer_claim.is_some(),
            forced_exit_claim.is_some()
        ),
        json!({
            "transfer_exit_claim": transfer_claim.map(|claim| claim.public_record()),
            "forced_exit_claim": forced_exit_claim.map(|claim| claim.public_record()),
            "failclosed_report": failclosed_latest.map(|report| report.public_record()),
        }),
        "block_bundle_without_user_escape_claim",
        "preserve both transfer-exit claim and derived forced-exit request evidence in the sealed transcript",
    )
}

fn challenge_settlement_ordering_covered(
    scenario: &TransferForcedExitScenarioState,
    failclosed: &TransferForcedExitFailclosedState,
    adversarial: &AdversarialMatrixState,
    transcript: &ScenarioTranscript,
) -> SecurityBundleCheckEvidence {
    let steps = pre_seal_steps(scenario, &transcript.scenario_id);
    let order_ok = ordered(
        &steps,
        &[
            StepKind::ForcedExitArmed,
            StepKind::ChallengeOpened,
            StepKind::ChallengeResolved,
            StepKind::TransferReadinessRechecked,
            StepKind::ExitSettled,
        ],
    );
    let failclosed_probe = failclosed_check_passed(
        failclosed,
        FailClosedCheckKind::SettlementBeforeChallengeRejected,
    );
    let adversarial_premature =
        has_adversarial_case(adversarial, AdversarialCaseKind::PrematureForcedSettlement);
    let adversarial_open_challenge = has_adversarial_case(
        adversarial,
        AdversarialCaseKind::OpenChallengeBlocksSettlement,
    );
    let covered =
        order_ok && failclosed_probe && adversarial_premature && adversarial_open_challenge;
    let status = if covered {
        SecurityBundleCheckStatus::Passed
    } else {
        SecurityBundleCheckStatus::Failed
    };
    SecurityBundleCheckEvidence::new(
        &transcript.scenario_id,
        SecurityBundleCheckKind::ChallengeSettlementOrderingCovered,
        status,
        "settlement must be after forced-exit arming, challenge open/resolution, and readiness recheck, with adversarial probes",
        format!(
            "order_ok={order_ok} failclosed_probe={failclosed_probe} premature_case={adversarial_premature} open_challenge_case={adversarial_open_challenge}"
        ),
        json!({
            "ordered_steps": steps.iter().map(|step| step.public_record()).collect::<Vec<_>>(),
            "adversarial_matrix_root": adversarial.state_root(),
        }),
        "block_bundle_on_bad_challenge_settlement_order",
        "keep settlement ordering and adversarial challenge blocking probes tied to the transfer forced-exit transcript",
    )
}

fn root_continuity_across_bundle(
    scenario: &TransferForcedExitScenarioState,
    static_verifier: &TransferForcedExitStaticVerifierState,
    failclosed: &TransferForcedExitFailclosedState,
    authority: &AuthorityCrosscheckState,
    adversarial: &AdversarialMatrixState,
    transcript: &ScenarioTranscript,
) -> SecurityBundleCheckEvidence {
    let static_roots_ok = static_verifier
        .latest_report
        .as_ref()
        .is_some_and(|report| {
            report.scenario_state_root == scenario.state_root()
                && report.transcript_root == transcript.transcript_root
                && report.final_spine_root == transcript.final_spine_root
                && report.final_transfer_runtime_root == transcript.final_transfer_runtime_root
        });
    let failclosed_roots_ok = failclosed.latest_report.as_ref().is_some_and(|report| {
        report.scenario_state_root == scenario.state_root()
            && report.static_verifier_root == static_verifier.state_root()
            && report.authority_crosscheck_root == authority.state_root()
            && report.adversarial_matrix_root == adversarial.state_root()
            && report.transcript_root == transcript.transcript_root
    });
    let final_root_probe =
        failclosed_check_passed(failclosed, FailClosedCheckKind::FinalRootMismatchRejected);
    let status = if static_roots_ok && failclosed_roots_ok && final_root_probe {
        SecurityBundleCheckStatus::Passed
    } else {
        SecurityBundleCheckStatus::Failed
    };
    SecurityBundleCheckEvidence::new(
        &transcript.scenario_id,
        SecurityBundleCheckKind::RootContinuityAcrossBundle,
        status,
        "scenario, static verifier, fail-closed report, authority, adversarial, and transcript roots must form one bundle",
        format!(
            "static_roots_ok={static_roots_ok} failclosed_roots_ok={failclosed_roots_ok} final_root_probe={final_root_probe}"
        ),
        json!({
            "scenario_state_root": scenario.state_root(),
            "static_verifier_root": static_verifier.state_root(),
            "failclosed_crosscheck_root": failclosed.state_root(),
            "authority_crosscheck_root": authority.state_root(),
            "adversarial_matrix_root": adversarial.state_root(),
            "transcript_root": transcript.transcript_root,
        }),
        "block_bundle_on_root_continuity_gap",
        "rerun dependent evidence in order so all reports bind the same transcript and final runtime roots",
    )
}

fn privacy_fee_pq_surface_covered(
    scenario: &TransferForcedExitScenarioState,
    static_verifier: &TransferForcedExitStaticVerifierState,
    failclosed: &TransferForcedExitFailclosedState,
    transcript: &ScenarioTranscript,
) -> SecurityBundleCheckEvidence {
    let claims = scenario_claims(scenario, &transcript.scenario_id);
    let roots_only = claim_by_kind(&claims, ClaimKind::RootsOnlyTranscript);
    let low_fee_pq = claim_by_kind(&claims, ClaimKind::LowFeePrivacyPqBounds);
    let static_privacy = static_verifier.latest_report.as_ref().and_then(|report| {
        report
            .checks
            .get(StaticCheckKind::PrivacyFeePqSurface.as_str())
    });
    let failclosed_privacy = failclosed_check_passed(
        failclosed,
        FailClosedCheckKind::PrivacyFeePqSurfacePreserved,
    );
    let covered = roots_only.is_some_and(|claim| claim.status == ClaimStatus::Proven)
        && low_fee_pq.is_some_and(|claim| claim.status == ClaimStatus::Proven)
        && static_privacy.is_some_and(|check| check.status == StaticCheckStatus::Passed)
        && failclosed_privacy
        && transcript.privacy_set_size_observed >= scenario.config.min_privacy_set_size;
    let status = if covered {
        SecurityBundleCheckStatus::Passed
    } else {
        SecurityBundleCheckStatus::Failed
    };
    SecurityBundleCheckEvidence::new(
        &transcript.scenario_id,
        SecurityBundleCheckKind::PrivacyFeePqSurfaceCovered,
        status,
        "public bundle must remain roots-only while preserving privacy set floor, low-fee bound, and PQ authorization evidence",
        format!(
            "roots_only={} low_fee_pq={} static_privacy={} failclosed_privacy={failclosed_privacy} privacy_set={}",
            roots_only.is_some(),
            low_fee_pq.is_some(),
            static_privacy.map(|check| check.status.as_str()).unwrap_or("missing"),
            transcript.privacy_set_size_observed
        ),
        json!({
            "roots_only_claim": roots_only.map(|claim| claim.public_record()),
            "low_fee_pq_claim": low_fee_pq.map(|claim| claim.public_record()),
            "static_privacy_check": static_privacy.map(|check| check.public_record()),
            "privacy_set_size_observed": transcript.privacy_set_size_observed,
            "min_privacy_set_size": scenario.config.min_privacy_set_size,
        }),
        "block_bundle_on_privacy_fee_or_pq_gap",
        "retain roots-only public records and require PQ auth plus low-fee/privacy checks before release",
    )
}

fn monero_threat_coverage_present(
    config: &Config,
    adversarial: &AdversarialMatrixState,
    authority: &AuthorityCrosscheckState,
) -> SecurityBundleCheckEvidence {
    let required_cases = required_adversarial_cases();
    let covered_cases = required_cases
        .iter()
        .filter(|kind| has_adversarial_case(adversarial, **kind))
        .count() as u64;
    let authority_ok = authority.latest_report.as_ref().is_some_and(|report| {
        matches!(
            report.status,
            AuthorityReportStatus::Passed | AuthorityReportStatus::Watch
        ) && report.failed_checks == 0
    });
    let covered = covered_cases == required_cases.len() as u64
        && adversarial.counters.fail_closed_cases >= config.min_adversarial_cases
        && authority_ok;
    let status = if covered {
        SecurityBundleCheckStatus::Passed
    } else {
        SecurityBundleCheckStatus::Failed
    };
    SecurityBundleCheckEvidence::new(
        "monero-threat-coverage",
        SecurityBundleCheckKind::MoneroThreatCoveragePresent,
        status,
        "Monero-specific bridge risks must have fail-closed adversarial coverage before transfer exits are treated as credible",
        format!(
            "covered_cases={covered_cases}/{} failclosed_cases={} authority_ok={authority_ok}",
            required_cases.len(),
            adversarial.counters.fail_closed_cases
        ),
        json!({
            "required_cases": required_cases.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "adversarial_cases": adversarial.cases.values().map(|case| case.public_record()).collect::<Vec<_>>(),
            "authority_crosscheck_root": authority.state_root(),
        }),
        "block_bundle_without_monero_threat_coverage",
        "keep watcher collusion, reorg, metadata, fee, liquidity, replay, and challenge probes in the matrix",
    )
}

fn user_escape_invariant_covered(
    scenario: &TransferForcedExitScenarioState,
    failclosed: &TransferForcedExitFailclosedState,
    transcript: &ScenarioTranscript,
) -> SecurityBundleCheckEvidence {
    let steps = pre_seal_steps(scenario, &transcript.scenario_id);
    let forced_exit_path = ordered(
        &steps,
        &[
            StepKind::ExitClaimPrepared,
            StepKind::ForcedExitRequestedFromTransferClaim,
            StepKind::ForcedExitLivenessObserved,
            StepKind::ForcedExitArmed,
            StepKind::ExitSettled,
        ],
    );
    let exit_claim_probe =
        failclosed_check_passed(failclosed, FailClosedCheckKind::ExitClaimRootTamperRejected);
    let final_root_probe =
        failclosed_check_passed(failclosed, FailClosedCheckKind::FinalRootMismatchRejected);
    let covered = forced_exit_path
        && exit_claim_probe
        && final_root_probe
        && !transcript.settlement_id.is_empty();
    let status = if covered {
        SecurityBundleCheckStatus::Passed
    } else {
        SecurityBundleCheckStatus::Failed
    };
    SecurityBundleCheckEvidence::new(
        &transcript.scenario_id,
        SecurityBundleCheckKind::UserEscapeInvariantCovered,
        status,
        "user escape must be represented as claim-prepared, forced-exit requested, liveness-observed, armed, and settled",
        format!(
            "forced_exit_path={forced_exit_path} exit_claim_probe={exit_claim_probe} final_root_probe={final_root_probe} settlement_id_present={}",
            !transcript.settlement_id.is_empty()
        ),
        json!({
            "settlement_id": transcript.settlement_id,
            "path_id": transcript.path_id,
            "transfer_id": transcript.transfer_id,
            "steps": steps.iter().map(|step| step.public_record()).collect::<Vec<_>>(),
        }),
        "block_bundle_without_user_escape_invariant",
        "preserve the always-available forced-exit route from prepared transfer claim to final settlement",
    )
}

fn watcher_sequencer_authority_separation(
    authority: &AuthorityCrosscheckState,
    adversarial: &AdversarialMatrixState,
    failclosed: &TransferForcedExitFailclosedState,
    transcript: &ScenarioTranscript,
) -> SecurityBundleCheckEvidence {
    let authority_report = authority.latest_report.as_ref();
    let authority_ok = authority_report.is_some_and(|report| report.failed_checks == 0);
    let watcher_case = has_adversarial_case(adversarial, AdversarialCaseKind::WeakPqWatcherQuorum);
    let replay_case = has_adversarial_case(adversarial, AdversarialCaseKind::ReplayNullifier);
    let source_roots = failclosed_check_passed(failclosed, FailClosedCheckKind::SourceRootsPresent);
    let separated = authority_ok && watcher_case && replay_case && source_roots;
    let status = if separated {
        SecurityBundleCheckStatus::Passed
    } else {
        SecurityBundleCheckStatus::Failed
    };
    SecurityBundleCheckEvidence::new(
        &transcript.scenario_id,
        SecurityBundleCheckKind::WatcherSequencerAuthoritySeparation,
        status,
        "watcher quorum, sequencer, authority, and replay defenses must be separate evidence surfaces",
        format!(
            "authority_ok={authority_ok} watcher_case={watcher_case} replay_case={replay_case} failclosed_source_roots={source_roots}"
        ),
        json!({
            "authority_report": authority_report.map(|report| report.public_record()),
            "adversarial_matrix_root": adversarial.state_root(),
            "failclosed_crosscheck_root": failclosed.state_root(),
        }),
        "block_bundle_when_control_plane_evidence_collapses",
        "preserve PQ watcher quorum, sequencer, authority, and replay evidence as independent roots",
    )
}

fn counters_consistent(
    scenario: &TransferForcedExitScenarioState,
    static_verifier: &TransferForcedExitStaticVerifierState,
    failclosed: &TransferForcedExitFailclosedState,
    authority: &AuthorityCrosscheckState,
    adversarial: &AdversarialMatrixState,
    transcript: &ScenarioTranscript,
) -> SecurityBundleCheckEvidence {
    let scenario_ok = scenario.counters.steps_recorded == scenario.steps.len() as u64
        && scenario.counters.claims_recorded == scenario.claims.len() as u64
        && scenario.counters.transcripts_sealed == scenario.transcripts.len() as u64;
    let static_ok = static_verifier.counters.reports_run as usize
        == static_verifier.report_history.len()
        && static_verifier.counters.checks_failed == 0;
    let failclosed_ok = failclosed.counters.reports_run as usize == failclosed.report_history.len()
        && failclosed.counters.checks_failed == 0
        && failclosed.counters.failclosed_probes_rejected >= DEFAULT_MIN_FAILCLOSED_PROBES;
    let authority_ok = authority.counters.reports_run as usize == authority.report_history.len()
        && authority.counters.checks_failed == 0;
    let adversarial_ok = adversarial.counters.cases_run as usize == adversarial.cases.len()
        && adversarial.counters.cases_failed == 0;
    let transcript_ok =
        transcript.step_count == pre_seal_steps(scenario, &transcript.scenario_id).len() as u64;
    let status = if scenario_ok
        && static_ok
        && failclosed_ok
        && authority_ok
        && adversarial_ok
        && transcript_ok
    {
        SecurityBundleCheckStatus::Passed
    } else {
        SecurityBundleCheckStatus::Failed
    };
    SecurityBundleCheckEvidence::new(
        &transcript.scenario_id,
        SecurityBundleCheckKind::CountersConsistent,
        status,
        "all source counters must agree with their report, case, step, claim, and transcript collections",
        format!(
            "scenario_ok={scenario_ok} static_ok={static_ok} failclosed_ok={failclosed_ok} authority_ok={authority_ok} adversarial_ok={adversarial_ok} transcript_ok={transcript_ok}"
        ),
        json!({
            "scenario_counters": scenario.counters.public_record(),
            "static_counters": static_verifier.counters.public_record(),
            "failclosed_counters": failclosed.counters.public_record(),
            "authority_counters": authority.counters.public_record(),
            "adversarial_counters": adversarial.counters.public_record(),
        }),
        "block_bundle_on_counter_drift",
        "refresh counters from canonical collections before publishing the security bundle",
    )
}

fn verified_readiness_classified(
    config: &Config,
    failclosed: &TransferForcedExitFailclosedState,
    authority: &AuthorityCrosscheckState,
    adversarial: &AdversarialMatrixState,
    transcript: &ScenarioTranscript,
) -> SecurityBundleCheckEvidence {
    let all_runtime_roots_present = !failclosed.state_root().is_empty()
        && !authority.state_root().is_empty()
        && !adversarial.state_root().is_empty()
        && !transcript.transcript_root.is_empty();
    let deferred = config.cargo_checks_deferred || config.runtime_tests_deferred;
    let status = if all_runtime_roots_present && deferred {
        SecurityBundleCheckStatus::Watch
    } else if all_runtime_roots_present {
        SecurityBundleCheckStatus::Passed
    } else {
        SecurityBundleCheckStatus::Failed
    };
    SecurityBundleCheckEvidence::new(
        &transcript.scenario_id,
        SecurityBundleCheckKind::VerifiedReadinessClassified,
        status,
        "bundle must explicitly classify verified readiness instead of conflating feature inventory with production readiness",
        format!(
            "runtime_roots_present={all_runtime_roots_present} cargo_deferred={} runtime_tests_deferred={}",
            config.cargo_checks_deferred, config.runtime_tests_deferred
        ),
        json!({
            "cargo_checks_deferred": config.cargo_checks_deferred,
            "runtime_tests_deferred": config.runtime_tests_deferred,
            "failclosed_root": failclosed.state_root(),
            "authority_root": authority.state_root(),
            "adversarial_root": adversarial.state_root(),
        }),
        "classify_as_watch_until_compile_and_runtime_tests_run",
        "run cargo checks, runtime tests, and security/privacy review before promoting the bundle beyond watch",
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

fn claim_by_kind<'a>(
    claims: &'a [&'a ScenarioClaim],
    kind: ClaimKind,
) -> Option<&'a ScenarioClaim> {
    claims.iter().copied().find(|claim| claim.kind == kind)
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

fn failclosed_check_passed(
    failclosed: &TransferForcedExitFailclosedState,
    kind: FailClosedCheckKind,
) -> bool {
    failclosed.latest_report.as_ref().is_some_and(|report| {
        report
            .checks
            .get(kind.as_str())
            .is_some_and(|check| check.status == FailClosedCheckStatus::Passed)
    })
}

fn has_adversarial_case(adversarial: &AdversarialMatrixState, kind: AdversarialCaseKind) -> bool {
    adversarial.cases.values().any(|case| {
        case.kind == kind
            && matches!(
                case.status,
                AdversarialCaseStatus::Passed | AdversarialCaseStatus::Watch
            )
    })
}

fn required_adversarial_cases() -> BTreeSet<AdversarialCaseKind> {
    [
        AdversarialCaseKind::WeakPqWatcherQuorum,
        AdversarialCaseKind::ShallowMoneroFinality,
        AdversarialCaseKind::DepositPrivacyFloor,
        AdversarialCaseKind::PrivateActionFeeCap,
        AdversarialCaseKind::ExitAmountCap,
        AdversarialCaseKind::ReplayNullifier,
        AdversarialCaseKind::PrematureForcedSettlement,
        AdversarialCaseKind::OpenChallengeBlocksSettlement,
    ]
    .into_iter()
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

fn aggregate_report_status(
    checks: &BTreeMap<String, SecurityBundleCheckEvidence>,
) -> SecurityBundleReportStatus {
    if checks
        .values()
        .any(|check| check.status == SecurityBundleCheckStatus::Failed)
    {
        SecurityBundleReportStatus::Failed
    } else if checks
        .values()
        .any(|check| check.status == SecurityBundleCheckStatus::Watch)
    {
        SecurityBundleReportStatus::Watch
    } else {
        SecurityBundleReportStatus::Passed
    }
}

fn readiness_label(status: SecurityBundleReportStatus, config: &Config) -> &'static str {
    match status {
        SecurityBundleReportStatus::Failed => "blocked_by_failed_bridge_exit_evidence",
        SecurityBundleReportStatus::Watch if config.cargo_checks_deferred => {
            "watch_compile_and_runtime_tests_deferred"
        }
        SecurityBundleReportStatus::Watch => "watch_security_review_or_runtime_evidence_needed",
        SecurityBundleReportStatus::Passed => "bridge_bound_transfer_exit_security_bundle_passed",
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

pub fn security_bundle_report_id(scenario_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SECURITY-BUNDLE-REPORT-ID",
        &[HashPart::Str(scenario_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn security_bundle_check_id(
    scenario_id: &str,
    kind: SecurityBundleCheckKind,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SECURITY-BUNDLE-CHECK-ID",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn source_root(
    scenario_state_root: &str,
    static_verifier_root: &str,
    failclosed_crosscheck_root: &str,
    authority_crosscheck_root: &str,
    adversarial_matrix_root: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SECURITY-BUNDLE-SOURCE-ROOT",
        &[
            HashPart::Str(scenario_state_root),
            HashPart::Str(static_verifier_root),
            HashPart::Str(failclosed_crosscheck_root),
            HashPart::Str(authority_crosscheck_root),
            HashPart::Str(adversarial_matrix_root),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

pub fn evidence_root(scenario_id: &str, label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SECURITY-BUNDLE-EVIDENCE",
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
    status: SecurityBundleReportStatus,
    readiness_label: &str,
    source_root: &str,
    check_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SECURITY-BUNDLE-REPORT-ROOT",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(check_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SECURITY-BUNDLE-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
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
