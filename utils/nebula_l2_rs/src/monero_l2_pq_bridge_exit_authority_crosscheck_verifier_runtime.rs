use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_adversarial_scenario_matrix_runtime::{
        AdversarialCaseKind, CaseStatus as AdversarialCaseStatus, MatrixStatus,
        State as AdversarialMatrixState,
    },
    monero_l2_pq_bridge_exit_custody_release_authority_spec_runtime::{
        AuthorityCheckKind, AuthorityDomain, CheckStatus as AuthorityCheckStatus, EvidenceKind,
        FailClosedAction, State as AuthoritySpecState,
    },
    monero_l2_pq_bridge_exit_transcript_static_verifier_runtime::{
        ReportStatus as TranscriptReportStatus, State as TranscriptVerifierState, StaticCheckKind,
        StaticCheckStatus,
    },
    monero_l2_pq_bridge_exit_vertical_slice_scenario_runtime::State as ScenarioState,
    monero_l2_pq_trust_minimized_bridge_exit_spine_runtime::State as BridgeExitSpineState,
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitAuthorityCrosscheckVerifierRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_AUTHORITY_CROSSCHECK_VERIFIER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-authority-crosscheck-verifier-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_AUTHORITY_CROSSCHECK_VERIFIER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CROSSCHECK_SUITE: &str =
    "monero-l2-pq-bridge-authority-vs-transcript-and-adversarial-evidence-v1";
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossCheckKind {
    SourceRootsPresent,
    AuthorityChecksPassed,
    TranscriptVerifierPassed,
    AdversarialMatrixPassed,
    ForcedExitAuthorityCoversScenario,
    ChallengeReleaseAlignment,
    ReplayNullifierAlignment,
    ReserveReleaseAlignment,
    PqControlPlaneAlignment,
    EmergencyUpgradeAlignment,
    PrivacySurfaceAlignment,
    CrossRootContinuity,
}

impl CrossCheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceRootsPresent => "source_roots_present",
            Self::AuthorityChecksPassed => "authority_checks_passed",
            Self::TranscriptVerifierPassed => "transcript_verifier_passed",
            Self::AdversarialMatrixPassed => "adversarial_matrix_passed",
            Self::ForcedExitAuthorityCoversScenario => "forced_exit_authority_covers_scenario",
            Self::ChallengeReleaseAlignment => "challenge_release_alignment",
            Self::ReplayNullifierAlignment => "replay_nullifier_alignment",
            Self::ReserveReleaseAlignment => "reserve_release_alignment",
            Self::PqControlPlaneAlignment => "pq_control_plane_alignment",
            Self::EmergencyUpgradeAlignment => "emergency_upgrade_alignment",
            Self::PrivacySurfaceAlignment => "privacy_surface_alignment",
            Self::CrossRootContinuity => "cross_root_continuity",
        }
    }

    pub fn all() -> [Self; 12] {
        [
            Self::SourceRootsPresent,
            Self::AuthorityChecksPassed,
            Self::TranscriptVerifierPassed,
            Self::AdversarialMatrixPassed,
            Self::ForcedExitAuthorityCoversScenario,
            Self::ChallengeReleaseAlignment,
            Self::ReplayNullifierAlignment,
            Self::ReserveReleaseAlignment,
            Self::PqControlPlaneAlignment,
            Self::EmergencyUpgradeAlignment,
            Self::PrivacySurfaceAlignment,
            Self::CrossRootContinuity,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossCheckStatus {
    Passed,
    Watch,
    Failed,
}

impl CrossCheckStatus {
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
pub enum CrossCheckReportStatus {
    Passed,
    Watch,
    Failed,
}

impl CrossCheckReportStatus {
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
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("authority_crosscheck_config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CrossCheckEvidence {
    pub check_id: String,
    pub kind: CrossCheckKind,
    pub status: CrossCheckStatus,
    pub requirement: String,
    pub observed: String,
    pub authority_root: String,
    pub transcript_root: String,
    pub adversarial_root: String,
    pub evidence_root: String,
    pub remediation: String,
}

impl CrossCheckEvidence {
    pub fn new(
        kind: CrossCheckKind,
        status: CrossCheckStatus,
        requirement: impl Into<String>,
        observed: impl Into<String>,
        roots: EvidenceRoots,
        remediation: impl Into<String>,
    ) -> Self {
        let requirement = requirement.into();
        let observed = observed.into();
        let remediation = remediation.into();
        let evidence_record = json!({
            "kind": kind.as_str(),
            "status": status.as_str(),
            "requirement": requirement,
            "observed": observed,
            "authority_root": roots.authority_root,
            "transcript_root": roots.transcript_root,
            "adversarial_root": roots.adversarial_root,
        });
        let evidence_root = record_root("authority_crosscheck_evidence", &evidence_record);
        let check_id = cross_check_id(kind, &evidence_root);
        Self {
            check_id,
            kind,
            status,
            requirement,
            observed,
            authority_root: roots.authority_root,
            transcript_root: roots.transcript_root,
            adversarial_root: roots.adversarial_root,
            evidence_root,
            remediation,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "requirement": self.requirement,
            "observed": self.observed,
            "authority_root": self.authority_root,
            "transcript_root": self.transcript_root,
            "adversarial_root": self.adversarial_root,
            "evidence_root": self.evidence_root,
            "remediation": self.remediation,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("authority_crosscheck", &self.public_record())
    }
}

#[derive(Clone, Debug)]
pub struct EvidenceRoots {
    pub authority_root: String,
    pub transcript_root: String,
    pub adversarial_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CrossCheckReport {
    pub report_id: String,
    pub status: CrossCheckReportStatus,
    pub authority_state_root: String,
    pub scenario_state_root: String,
    pub transcript_verifier_root: String,
    pub adversarial_matrix_root: String,
    pub spine_root: String,
    pub passed_checks: u64,
    pub watch_checks: u64,
    pub failed_checks: u64,
    pub checks: BTreeMap<String, CrossCheckEvidence>,
    pub roots: CrossCheckReportRoots,
}

impl CrossCheckReport {
    pub fn public_record(&self) -> Value {
        let checks = self
            .checks
            .values()
            .map(CrossCheckEvidence::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "authority_state_root": self.authority_state_root,
            "scenario_state_root": self.scenario_state_root,
            "transcript_verifier_root": self.transcript_verifier_root,
            "adversarial_matrix_root": self.adversarial_matrix_root,
            "spine_root": self.spine_root,
            "passed_checks": self.passed_checks,
            "watch_checks": self.watch_checks,
            "failed_checks": self.failed_checks,
            "checks": checks,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CrossCheckReportRoots {
    pub check_root: String,
    pub report_root: String,
}

impl CrossCheckReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "check_root": self.check_root,
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
    pub bundles_verified: u64,
    pub root_mismatches: u64,
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
            "bundles_verified": self.bundles_verified,
            "root_mismatches": self.root_mismatches,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("authority_crosscheck_counters", &self.public_record())
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
                "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-CROSSCHECK-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-CROSSCHECK-ROOTS",
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
    pub latest_report: Option<CrossCheckReport>,
    pub report_history: Vec<CrossCheckReport>,
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
        let authority =
            crate::monero_l2_pq_bridge_exit_custody_release_authority_spec_runtime::devnet();
        let scenario = crate::monero_l2_pq_bridge_exit_vertical_slice_scenario_runtime::devnet();
        let transcript =
            crate::monero_l2_pq_bridge_exit_transcript_static_verifier_runtime::devnet();
        let adversarial =
            crate::monero_l2_pq_bridge_exit_adversarial_scenario_matrix_runtime::devnet();
        let spine = crate::monero_l2_pq_trust_minimized_bridge_exit_spine_runtime::devnet();
        state
            .verify_bundle(&authority, &scenario, &transcript, &adversarial, &spine)
            .expect("devnet bridge authority cross-check verification");
        state
    }

    pub fn verify_bundle(
        &mut self,
        authority: &AuthoritySpecState,
        scenario: &ScenarioState,
        transcript: &TranscriptVerifierState,
        adversarial: &AdversarialMatrixState,
        spine: &BridgeExitSpineState,
    ) -> Result<String> {
        let mut checks = BTreeMap::new();
        for check in evaluate_cross_checks(authority, scenario, transcript, adversarial, spine) {
            checks.insert(check.kind.as_str().to_string(), check);
        }
        ensure(
            CrossCheckKind::all()
                .iter()
                .all(|kind| checks.contains_key(kind.as_str())),
            "authority cross-check omitted a required bridge verifier check",
        )?;

        let passed_checks = checks
            .values()
            .filter(|check| check.status == CrossCheckStatus::Passed)
            .count() as u64;
        let watch_checks = checks
            .values()
            .filter(|check| check.status == CrossCheckStatus::Watch)
            .count() as u64;
        let failed_checks = checks
            .values()
            .filter(|check| check.status == CrossCheckStatus::Failed)
            .count() as u64;
        let status = aggregate_status(&checks);
        let check_records = checks
            .values()
            .map(CrossCheckEvidence::public_record)
            .collect::<Vec<_>>();
        let check_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-CROSSCHECK-CHECKS",
            &check_records,
        );
        let report_seed = json!({
            "status": status.as_str(),
            "authority_state_root": authority.state_root(),
            "scenario_state_root": scenario.state_root(),
            "transcript_verifier_root": transcript.state_root(),
            "adversarial_matrix_root": adversarial.state_root(),
            "spine_root": spine.state_root(),
            "check_root": check_root,
        });
        let report_root = record_root("authority_crosscheck_report", &report_seed);
        let report_id = cross_report_id(&report_root);
        let report = CrossCheckReport {
            report_id: report_id.clone(),
            status,
            authority_state_root: authority.state_root(),
            scenario_state_root: scenario.state_root(),
            transcript_verifier_root: transcript.state_root(),
            adversarial_matrix_root: adversarial.state_root(),
            spine_root: spine.state_root(),
            passed_checks,
            watch_checks,
            failed_checks,
            checks,
            roots: CrossCheckReportRoots {
                check_root,
                report_root,
            },
        };
        self.record_report(report);
        Ok(report_id)
    }

    fn record_report(&mut self, report: CrossCheckReport) {
        self.counters.reports_run += 1;
        self.counters.checks_run += report.checks.len() as u64;
        self.counters.checks_passed += report.passed_checks;
        self.counters.checks_watch += report.watch_checks;
        self.counters.checks_failed += report.failed_checks;
        if report.failed_checks > 0 {
            self.counters.root_mismatches += report
                .checks
                .values()
                .filter(|check| {
                    check.kind == CrossCheckKind::CrossRootContinuity
                        && check.status == CrossCheckStatus::Failed
                })
                .count() as u64;
        }
        match report.status {
            CrossCheckReportStatus::Passed => {
                self.counters.reports_passed += 1;
                self.counters.bundles_verified += 1;
            }
            CrossCheckReportStatus::Watch => self.counters.reports_watch += 1,
            CrossCheckReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(CrossCheckReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-CROSSCHECK-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "crosscheck_suite": self.config.crosscheck_suite,
            "latest_report": self.latest_report.as_ref().map(CrossCheckReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }
}

pub fn evaluate_cross_checks(
    authority: &AuthoritySpecState,
    scenario: &ScenarioState,
    transcript: &TranscriptVerifierState,
    adversarial: &AdversarialMatrixState,
    spine: &BridgeExitSpineState,
) -> Vec<CrossCheckEvidence> {
    vec![
        source_roots_present(authority, scenario, transcript, adversarial, spine),
        authority_checks_passed(authority, scenario, adversarial),
        transcript_verifier_passed(authority, transcript, adversarial),
        adversarial_matrix_passed(authority, adversarial, transcript),
        forced_exit_authority_covers_scenario(authority, scenario, adversarial),
        challenge_release_alignment(authority, scenario, transcript, adversarial),
        replay_nullifier_alignment(authority, scenario, adversarial),
        reserve_release_alignment(authority, scenario, adversarial),
        pq_control_plane_alignment(authority, adversarial, transcript),
        emergency_upgrade_alignment(authority, adversarial, transcript),
        privacy_surface_alignment(authority, scenario, transcript, adversarial),
        cross_root_continuity(authority, scenario, transcript, adversarial, spine),
    ]
}

fn source_roots_present(
    authority: &AuthoritySpecState,
    scenario: &ScenarioState,
    transcript: &TranscriptVerifierState,
    adversarial: &AdversarialMatrixState,
    spine: &BridgeExitSpineState,
) -> CrossCheckEvidence {
    let ok = !authority.state_root().is_empty()
        && !scenario.state_root().is_empty()
        && !transcript.state_root().is_empty()
        && !adversarial.state_root().is_empty()
        && !spine.state_root().is_empty();
    cross_check(
        CrossCheckKind::SourceRootsPresent,
        if ok {
            CrossCheckStatus::Passed
        } else {
            CrossCheckStatus::Failed
        },
        "authority, transcript, adversarial, scenario, and spine roots must all be present",
        format!(
            "authority={}, scenario={}, transcript={}, adversarial={}, spine={}",
            !authority.state_root().is_empty(),
            !scenario.state_root().is_empty(),
            !transcript.state_root().is_empty(),
            !adversarial.state_root().is_empty(),
            !spine.state_root().is_empty()
        ),
        roots(authority, transcript, adversarial),
        "rerun the bridge evidence bundle before publishing release-gate summaries",
    )
}

fn authority_checks_passed(
    authority: &AuthoritySpecState,
    scenario: &ScenarioState,
    adversarial: &AdversarialMatrixState,
) -> CrossCheckEvidence {
    let failed = authority
        .checks
        .values()
        .filter(|check| check.status == AuthorityCheckStatus::Failed)
        .count();
    let required_present = [
        AuthorityCheckKind::NoUnilateralRelease,
        AuthorityCheckKind::ForcedExitBypassesSequencer,
        AuthorityCheckKind::UpgradeTimelocked,
        AuthorityCheckKind::EmergencyCannotHaltExits,
        AuthorityCheckKind::PqControlPlane,
        AuthorityCheckKind::PrivacyRootsOnly,
        AuthorityCheckKind::ReserveRequiredForRelease,
        AuthorityCheckKind::ChallengeBlocksRelease,
    ]
    .iter()
    .all(|kind| has_authority_check(authority, *kind, AuthorityCheckStatus::Passed));
    let ok = failed == 0 && required_present;
    cross_check(
        CrossCheckKind::AuthorityChecksPassed,
        if ok {
            CrossCheckStatus::Passed
        } else {
            CrossCheckStatus::Failed
        },
        "custody/release authority spec must pass all required bridge authority checks",
        format!(
            "failed_authority_checks={}, required_present={}, scenario_root={}, adversarial_status={}",
            failed,
            required_present,
            scenario.state_root(),
            adversarial.matrix_status.as_str()
        ),
        roots_with_scenario(authority, scenario, adversarial),
        "fix authority checks before trusting transcript or adversarial evidence",
    )
}

fn transcript_verifier_passed(
    authority: &AuthoritySpecState,
    transcript: &TranscriptVerifierState,
    adversarial: &AdversarialMatrixState,
) -> CrossCheckEvidence {
    let latest = transcript.latest_report.as_ref();
    let status = latest.map(|report| report.status);
    let root_checks = latest
        .map(|report| {
            has_static_check(report, StaticCheckKind::TranscriptStepRootMatches)
                && has_static_check(report, StaticCheckKind::TranscriptClaimRootMatches)
                && has_static_check(report, StaticCheckKind::PostExitVerifierLinked)
        })
        .unwrap_or(false);
    let ok = matches!(
        status,
        Some(TranscriptReportStatus::Passed | TranscriptReportStatus::Watch)
    ) && root_checks;
    cross_check(
        CrossCheckKind::TranscriptVerifierPassed,
        if ok {
            CrossCheckStatus::Passed
        } else {
            CrossCheckStatus::Failed
        },
        "vertical-slice transcript verifier must pass root, claim, and post-exit assessment checks",
        format!(
            "transcript_status={}, root_checks={}, authority_checks={}",
            status.map(|status| status.as_str()).unwrap_or("missing"),
            root_checks,
            authority.checks.len()
        ),
        roots(authority, transcript, adversarial),
        "rerun transcript static verification and repair broken scenario roots",
    )
}

fn adversarial_matrix_passed(
    authority: &AuthoritySpecState,
    adversarial: &AdversarialMatrixState,
    transcript: &TranscriptVerifierState,
) -> CrossCheckEvidence {
    let required_cases = [
        AdversarialCaseKind::WeakPqWatcherQuorum,
        AdversarialCaseKind::ShallowMoneroFinality,
        AdversarialCaseKind::DepositPrivacyFloor,
        AdversarialCaseKind::PrivateActionFeeCap,
        AdversarialCaseKind::ExitAmountCap,
        AdversarialCaseKind::ReplayNullifier,
        AdversarialCaseKind::PrematureForcedSettlement,
        AdversarialCaseKind::OpenChallengeBlocksSettlement,
    ];
    let cases_present = required_cases.iter().all(|kind| {
        adversarial.cases.values().any(|case| {
            case.kind == *kind
                && matches!(
                    case.status,
                    AdversarialCaseStatus::Passed | AdversarialCaseStatus::Watch
                )
        })
    });
    let ok = adversarial.matrix_status != MatrixStatus::Failed && cases_present;
    cross_check(
        CrossCheckKind::AdversarialMatrixPassed,
        if ok {
            CrossCheckStatus::Passed
        } else {
            CrossCheckStatus::Failed
        },
        "adversarial matrix must cover required fail-closed bridge threats",
        format!(
            "matrix_status={}, cases_present={}, transcript_reports={}",
            adversarial.matrix_status.as_str(),
            cases_present,
            transcript.report_history.len()
        ),
        roots(authority, transcript, adversarial),
        "add or repair missing fail-closed probes before accepting bridge authority rules",
    )
}

fn forced_exit_authority_covers_scenario(
    authority: &AuthoritySpecState,
    scenario: &ScenarioState,
    adversarial: &AdversarialMatrixState,
) -> CrossCheckEvidence {
    let forced_capability = authority.capabilities.values().any(|capability| {
        capability.domain == AuthorityDomain::ForcedExit
            && capability.fail_closed_action == FailClosedAction::ExitOnly
            && capability
                .required_evidence
                .contains(&EvidenceKind::CensorshipEvidenceRoot)
            && capability
                .required_evidence
                .contains(&EvidenceKind::LivenessFailureRoot)
            && capability
                .required_evidence
                .contains(&EvidenceKind::BurnNullifier)
    });
    let transcript_support = scenario
        .transcripts
        .values()
        .next_back()
        .is_some_and(|transcript| {
            !transcript.forced_exit_available_before_timeout
                && transcript.forced_exit_available_after_timeout
        });
    let adversarial_support =
        has_adversarial_case(adversarial, AdversarialCaseKind::PrematureForcedSettlement)
            && has_adversarial_case(
                adversarial,
                AdversarialCaseKind::OpenChallengeBlocksSettlement,
            );
    let ok = forced_capability && transcript_support && adversarial_support;
    cross_check(
        CrossCheckKind::ForcedExitAuthorityCoversScenario,
        if ok {
            CrossCheckStatus::Passed
        } else {
            CrossCheckStatus::Failed
        },
        "forced-exit authority must match scenario liveness evidence and fail-closed probes",
        format!(
            "forced_capability={}, transcript_support={}, adversarial_support={}",
            forced_capability, transcript_support, adversarial_support
        ),
        roots_with_scenario(authority, scenario, adversarial),
        "align forced-exit authority evidence with timeout, challenge, and settlement probes",
    )
}

fn challenge_release_alignment(
    authority: &AuthoritySpecState,
    scenario: &ScenarioState,
    transcript: &TranscriptVerifierState,
    adversarial: &AdversarialMatrixState,
) -> CrossCheckEvidence {
    let all_release_rules_block = authority
        .release_rules
        .values()
        .all(|rule| rule.blocks_if_open_challenge);
    let authority_check = has_authority_check(
        authority,
        AuthorityCheckKind::ChallengeBlocksRelease,
        AuthorityCheckStatus::Passed,
    );
    let transcript_check = transcript.latest_report.as_ref().is_some_and(|report| {
        has_static_check(report, StaticCheckKind::ChallengeSettlementOrdering)
    });
    let adversarial_check = has_adversarial_case(
        adversarial,
        AdversarialCaseKind::OpenChallengeBlocksSettlement,
    );
    let scenario_has_challenge = scenario
        .transcripts
        .values()
        .next_back()
        .is_some_and(|transcript| !transcript.challenge_id.is_empty());
    let ok = all_release_rules_block
        && authority_check
        && transcript_check
        && adversarial_check
        && scenario_has_challenge;
    cross_check(
        CrossCheckKind::ChallengeReleaseAlignment,
        if ok {
            CrossCheckStatus::Passed
        } else {
            CrossCheckStatus::Failed
        },
        "challenge evidence must block release in authority rules, scenario transcript, and adversarial matrix",
        format!(
            "release_rules_block={}, authority_check={}, transcript_check={}, adversarial_check={}, scenario_has_challenge={}",
            all_release_rules_block, authority_check, transcript_check, adversarial_check, scenario_has_challenge
        ),
        roots_with_scenario(authority, scenario, adversarial),
        "force every release path to block on open challenges and verify transcript ordering",
    )
}

fn replay_nullifier_alignment(
    authority: &AuthoritySpecState,
    scenario: &ScenarioState,
    adversarial: &AdversarialMatrixState,
) -> CrossCheckEvidence {
    let release_rules_require_nullifier = authority.release_rules.values().all(|rule| {
        rule.burns_nullifier_before_release
            && rule
                .release_certificate_evidence
                .contains(&EvidenceKind::BurnNullifier)
    });
    let forced_or_withdrawal_capability = authority.capabilities.values().any(|capability| {
        matches!(
            capability.domain,
            AuthorityDomain::ForcedExit | AuthorityDomain::WithdrawalRelease
        ) && capability
            .required_evidence
            .contains(&EvidenceKind::BurnNullifier)
    });
    let matrix_replay = has_adversarial_case(adversarial, AdversarialCaseKind::ReplayNullifier);
    let scenario_nullifier = scenario.spine.spent_nullifiers.len() >= 1;
    let ok = release_rules_require_nullifier
        && forced_or_withdrawal_capability
        && matrix_replay
        && scenario_nullifier;
    cross_check(
        CrossCheckKind::ReplayNullifierAlignment,
        if ok {
            CrossCheckStatus::Passed
        } else {
            CrossCheckStatus::Failed
        },
        "release authority must require burn nullifier and adversarial replay rejection",
        format!(
            "release_rules_require_nullifier={}, capability_requires_nullifier={}, matrix_replay={}, scenario_nullifiers={}",
            release_rules_require_nullifier,
            forced_or_withdrawal_capability,
            matrix_replay,
            scenario.spine.spent_nullifiers.len()
        ),
        roots_with_scenario(authority, scenario, adversarial),
        "require nullifier evidence before release and keep replay probes in the matrix",
    )
}

fn reserve_release_alignment(
    authority: &AuthoritySpecState,
    scenario: &ScenarioState,
    adversarial: &AdversarialMatrixState,
) -> CrossCheckEvidence {
    let release_blocks_reserve_missing = authority
        .release_rules
        .values()
        .all(|rule| rule.blocks_if_reserve_missing);
    let withdrawal_requires_reserve = authority.capabilities.values().any(|capability| {
        capability.domain == AuthorityDomain::WithdrawalRelease
            && capability
                .required_evidence
                .contains(&EvidenceKind::ReserveProofRoot)
    });
    let authority_check = has_authority_check(
        authority,
        AuthorityCheckKind::ReserveRequiredForRelease,
        AuthorityCheckStatus::Passed,
    );
    let matrix_liquidity = has_adversarial_case(adversarial, AdversarialCaseKind::ExitAmountCap);
    let scenario_reserve_root_present = !scenario.spine.policy.reserve_root.is_empty();
    let ok = release_blocks_reserve_missing
        && withdrawal_requires_reserve
        && authority_check
        && matrix_liquidity
        && scenario_reserve_root_present;
    cross_check(
        CrossCheckKind::ReserveReleaseAlignment,
        if ok {
            CrossCheckStatus::Passed
        } else {
            CrossCheckStatus::Failed
        },
        "release authority must depend on reserve proof and reject liquidity exhaustion paths",
        format!(
            "blocks_reserve_missing={}, withdrawal_requires_reserve={}, authority_check={}, matrix_liquidity={}, reserve_root_present={}",
            release_blocks_reserve_missing,
            withdrawal_requires_reserve,
            authority_check,
            matrix_liquidity,
            scenario_reserve_root_present
        ),
        roots_with_scenario(authority, scenario, adversarial),
        "delay release unless reserve proof and release certificate roots are present",
    )
}

fn pq_control_plane_alignment(
    authority: &AuthoritySpecState,
    adversarial: &AdversarialMatrixState,
    transcript: &TranscriptVerifierState,
) -> CrossCheckEvidence {
    let authority_check = has_authority_check(
        authority,
        AuthorityCheckKind::PqControlPlane,
        AuthorityCheckStatus::Passed,
    );
    let roles_pq = authority
        .roles
        .values()
        .all(|role| role.pq_suite.contains("ML-DSA"));
    let weak_watcher_rejected =
        has_adversarial_case(adversarial, AdversarialCaseKind::WeakPqWatcherQuorum);
    let transcript_passes = transcript
        .latest_report
        .as_ref()
        .is_some_and(|report| report.status != TranscriptReportStatus::Failed);
    let ok = authority_check && roles_pq && weak_watcher_rejected && transcript_passes;
    cross_check(
        CrossCheckKind::PqControlPlaneAlignment,
        if ok {
            CrossCheckStatus::Passed
        } else {
            CrossCheckStatus::Failed
        },
        "PQ control-plane roles must align with weak-watcher rejection and transcript evidence",
        format!(
            "authority_check={}, roles_pq={}, weak_watcher_rejected={}, transcript_passes={}",
            authority_check, roles_pq, weak_watcher_rejected, transcript_passes
        ),
        roots(authority, transcript, adversarial),
        "rotate non-PQ roles and keep watcher-quorum adversarial probes active",
    )
}

fn emergency_upgrade_alignment(
    authority: &AuthoritySpecState,
    adversarial: &AdversarialMatrixState,
    transcript: &TranscriptVerifierState,
) -> CrossCheckEvidence {
    let upgrade_check = has_authority_check(
        authority,
        AuthorityCheckKind::UpgradeTimelocked,
        AuthorityCheckStatus::Passed,
    );
    let emergency_check = has_authority_check(
        authority,
        AuthorityCheckKind::EmergencyCannotHaltExits,
        AuthorityCheckStatus::Passed,
    );
    let upgrade_capability = authority.capabilities.values().any(|capability| {
        capability.domain == AuthorityDomain::UpgradeAuthority
            && capability
                .required_evidence
                .contains(&EvidenceKind::UpgradeTimelockRoot)
            && capability.delay_blocks > 0
    });
    let forced_exit_still_supported =
        has_adversarial_case(adversarial, AdversarialCaseKind::PrematureForcedSettlement)
            && transcript.latest_report.as_ref().is_some_and(|report| {
                has_static_check(report, StaticCheckKind::ForcedExitLivenessClaim)
            });
    let ok = upgrade_check && emergency_check && upgrade_capability && forced_exit_still_supported;
    cross_check(
        CrossCheckKind::EmergencyUpgradeAlignment,
        if ok {
            CrossCheckStatus::Passed
        } else {
            CrossCheckStatus::Failed
        },
        "upgrade and emergency powers must be timelocked and unable to halt exits",
        format!(
            "upgrade_check={}, emergency_check={}, upgrade_capability={}, forced_exit_still_supported={}",
            upgrade_check, emergency_check, upgrade_capability, forced_exit_still_supported
        ),
        roots(authority, transcript, adversarial),
        "require timelock evidence and preserve exit-only mode during emergency actions",
    )
}

fn privacy_surface_alignment(
    authority: &AuthoritySpecState,
    scenario: &ScenarioState,
    transcript: &TranscriptVerifierState,
    adversarial: &AdversarialMatrixState,
) -> CrossCheckEvidence {
    let authority_check = has_authority_check(
        authority,
        AuthorityCheckKind::PrivacyRootsOnly,
        AuthorityCheckStatus::Passed,
    );
    let transcript_check = transcript
        .latest_report
        .as_ref()
        .is_some_and(|report| has_static_check(report, StaticCheckKind::PrivacySurfaceRootsOnly));
    let matrix_privacy =
        has_adversarial_case(adversarial, AdversarialCaseKind::DepositPrivacyFloor);
    let scenario_privacy = scenario
        .transcripts
        .values()
        .next_back()
        .is_some_and(|transcript| {
            transcript.privacy_set_size_observed >= scenario.spine.config.min_privacy_set_size
        });
    let ok = authority_check && transcript_check && matrix_privacy && scenario_privacy;
    cross_check(
        CrossCheckKind::PrivacySurfaceAlignment,
        if ok {
            CrossCheckStatus::Passed
        } else {
            CrossCheckStatus::Failed
        },
        "authority, transcript, scenario, and adversarial matrix must agree on roots-only privacy and privacy floors",
        format!(
            "authority_check={}, transcript_check={}, matrix_privacy={}, scenario_privacy={}",
            authority_check, transcript_check, matrix_privacy, scenario_privacy
        ),
        roots_with_scenario(authority, scenario, adversarial),
        "keep authority records roots-only and reject deposits/actions below privacy floor",
    )
}

fn cross_root_continuity(
    authority: &AuthoritySpecState,
    scenario: &ScenarioState,
    transcript: &TranscriptVerifierState,
    adversarial: &AdversarialMatrixState,
    spine: &BridgeExitSpineState,
) -> CrossCheckEvidence {
    let authority_policy_matches = authority.source_policy_root == spine.policy.state_root();
    let transcript_report_matches = transcript.latest_report.as_ref().is_some_and(|report| {
        report.scenario_state_root == scenario.state_root()
            && report.scenario_transcript_root
                == scenario
                    .transcripts
                    .values()
                    .next_back()
                    .map(|item| item.transcript_root.clone())
                    .unwrap_or_default()
    });
    let scenario_spine_links = scenario
        .transcripts
        .values()
        .next_back()
        .is_some_and(|item| item.final_spine_root == scenario.spine.state_root());
    let matrix_root_present = !adversarial.state_root().is_empty();
    let ok = authority_policy_matches
        && transcript_report_matches
        && scenario_spine_links
        && matrix_root_present;
    cross_check(
        CrossCheckKind::CrossRootContinuity,
        if ok {
            CrossCheckStatus::Passed
        } else {
            CrossCheckStatus::Failed
        },
        "authority policy root, transcript report roots, scenario spine root, and matrix root must be internally linked",
        format!(
            "authority_policy_matches={}, transcript_report_matches={}, scenario_spine_links={}, matrix_root_present={}",
            authority_policy_matches, transcript_report_matches, scenario_spine_links, matrix_root_present
        ),
        roots_with_scenario(authority, scenario, adversarial),
        "rerun authority, transcript, scenario, and adversarial modules from the same bridge evidence bundle",
    )
}

fn cross_check(
    kind: CrossCheckKind,
    status: CrossCheckStatus,
    requirement: &str,
    observed: String,
    roots: EvidenceRoots,
    remediation: &str,
) -> CrossCheckEvidence {
    CrossCheckEvidence::new(kind, status, requirement, observed, roots, remediation)
}

fn roots(
    authority: &AuthoritySpecState,
    transcript: &TranscriptVerifierState,
    adversarial: &AdversarialMatrixState,
) -> EvidenceRoots {
    EvidenceRoots {
        authority_root: authority.state_root(),
        transcript_root: transcript.state_root(),
        adversarial_root: adversarial.state_root(),
    }
}

fn roots_with_scenario(
    authority: &AuthoritySpecState,
    scenario: &ScenarioState,
    adversarial: &AdversarialMatrixState,
) -> EvidenceRoots {
    EvidenceRoots {
        authority_root: authority.state_root(),
        transcript_root: scenario.state_root(),
        adversarial_root: adversarial.state_root(),
    }
}

fn has_authority_check(
    authority: &AuthoritySpecState,
    kind: AuthorityCheckKind,
    status: AuthorityCheckStatus,
) -> bool {
    authority
        .checks
        .values()
        .any(|check| check.kind == kind && check.status == status)
}

fn has_static_check(
    report: &crate::monero_l2_pq_bridge_exit_transcript_static_verifier_runtime::StaticReport,
    kind: StaticCheckKind,
) -> bool {
    report.checks.values().any(|check| {
        check.kind == kind
            && matches!(
                check.status,
                StaticCheckStatus::Passed | StaticCheckStatus::Watch
            )
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

fn aggregate_status(checks: &BTreeMap<String, CrossCheckEvidence>) -> CrossCheckReportStatus {
    if checks
        .values()
        .any(|check| check.status == CrossCheckStatus::Failed)
    {
        CrossCheckReportStatus::Failed
    } else if checks
        .values()
        .any(|check| check.status == CrossCheckStatus::Watch)
    {
        CrossCheckReportStatus::Watch
    } else {
        CrossCheckReportStatus::Passed
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

pub fn cross_report_id(report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-CROSSCHECK-REPORT-ID",
        &[HashPart::Str(report_root)],
        32,
    )
}

pub fn cross_check_id(kind: CrossCheckKind, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-CROSSCHECK-CHECK-ID",
        &[HashPart::Str(kind.as_str()), HashPart::Str(evidence_root)],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-CROSSCHECK-RECORD",
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
