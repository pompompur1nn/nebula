use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_bound_transfer_forced_exit_security_bundle_runtime::{
        SecurityBundleCheckKind, SecurityBundleCheckStatus, SecurityBundleReport,
        SecurityBundleReportStatus, State as TransferSecurityBundleState,
    },
    monero_l2_pq_bridge_exit_authority_crosscheck_verifier_runtime::{
        CrossCheckKind, CrossCheckReport, CrossCheckReportStatus, CrossCheckStatus,
        State as AuthorityCrosscheckState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitAuthorityTransferSecurityBundleRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_AUTHORITY_TRANSFER_SECURITY_BUNDLE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-authority-transfer-security-bundle-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_AUTHORITY_TRANSFER_SECURITY_BUNDLE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ADAPTER_SUITE: &str =
    "monero-l2-pq-bridge-authority-consumes-transfer-forced-exit-security-bundle-v1";
pub const DEFAULT_MIN_AUTHORITY_CHECKS: u64 = 12;
pub const DEFAULT_MIN_SECURITY_BUNDLE_CHECKS: u64 = 15;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityTransferCheckKind {
    SourceRootsPresent,
    SecurityBundleConsumed,
    SecurityBundleBindsAuthorityRoot,
    AuthorityReportAccepted,
    AuthorityChallengeReleaseConsumesBundle,
    AuthorityPqControlPlaneConsumesBundle,
    AuthorityPrivacySurfaceConsumesBundle,
    AuthorityCrossRootContinuityConsumesBundle,
    ExitClaimEscapeAuthorized,
    AdversarialThreatSurfaceInherited,
    WatchReadinessPreserved,
    CounterContinuity,
    ReleaseGateClassified,
    AuditHooksDeclared,
}

impl AuthorityTransferCheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceRootsPresent => "source_roots_present",
            Self::SecurityBundleConsumed => "security_bundle_consumed",
            Self::SecurityBundleBindsAuthorityRoot => "security_bundle_binds_authority_root",
            Self::AuthorityReportAccepted => "authority_report_accepted",
            Self::AuthorityChallengeReleaseConsumesBundle => {
                "authority_challenge_release_consumes_bundle"
            }
            Self::AuthorityPqControlPlaneConsumesBundle => {
                "authority_pq_control_plane_consumes_bundle"
            }
            Self::AuthorityPrivacySurfaceConsumesBundle => {
                "authority_privacy_surface_consumes_bundle"
            }
            Self::AuthorityCrossRootContinuityConsumesBundle => {
                "authority_cross_root_continuity_consumes_bundle"
            }
            Self::ExitClaimEscapeAuthorized => "exit_claim_escape_authorized",
            Self::AdversarialThreatSurfaceInherited => "adversarial_threat_surface_inherited",
            Self::WatchReadinessPreserved => "watch_readiness_preserved",
            Self::CounterContinuity => "counter_continuity",
            Self::ReleaseGateClassified => "release_gate_classified",
            Self::AuditHooksDeclared => "audit_hooks_declared",
        }
    }

    pub fn all() -> [Self; 14] {
        [
            Self::SourceRootsPresent,
            Self::SecurityBundleConsumed,
            Self::SecurityBundleBindsAuthorityRoot,
            Self::AuthorityReportAccepted,
            Self::AuthorityChallengeReleaseConsumesBundle,
            Self::AuthorityPqControlPlaneConsumesBundle,
            Self::AuthorityPrivacySurfaceConsumesBundle,
            Self::AuthorityCrossRootContinuityConsumesBundle,
            Self::ExitClaimEscapeAuthorized,
            Self::AdversarialThreatSurfaceInherited,
            Self::WatchReadinessPreserved,
            Self::CounterContinuity,
            Self::ReleaseGateClassified,
            Self::AuditHooksDeclared,
        ]
    }

    pub fn is_release_blocking(self) -> bool {
        !matches!(
            self,
            Self::WatchReadinessPreserved | Self::ReleaseGateClassified | Self::AuditHooksDeclared
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityTransferCheckStatus {
    Passed,
    Watch,
    Failed,
}

impl AuthorityTransferCheckStatus {
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
pub enum AuthorityTransferReportStatus {
    Passed,
    Watch,
    Failed,
}

impl AuthorityTransferReportStatus {
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
    pub adapter_suite: String,
    pub min_authority_checks: u64,
    pub min_security_bundle_checks: u64,
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
            adapter_suite: ADAPTER_SUITE.to_string(),
            min_authority_checks: DEFAULT_MIN_AUTHORITY_CHECKS,
            min_security_bundle_checks: DEFAULT_MIN_SECURITY_BUNDLE_CHECKS,
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
            "adapter_suite": self.adapter_suite,
            "min_authority_checks": self.min_authority_checks,
            "min_security_bundle_checks": self.min_security_bundle_checks,
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
pub struct AuthorityTransferCheckEvidence {
    pub check_id: String,
    pub kind: AuthorityTransferCheckKind,
    pub status: AuthorityTransferCheckStatus,
    pub requirement: String,
    pub observed: String,
    pub authority_root: String,
    pub security_bundle_root: String,
    pub security_report_root: String,
    pub evidence_root: String,
    pub release_effect: String,
    pub remediation: String,
}

impl AuthorityTransferCheckEvidence {
    pub fn new(
        kind: AuthorityTransferCheckKind,
        status: AuthorityTransferCheckStatus,
        requirement: impl Into<String>,
        observed: impl Into<String>,
        roots: AdapterEvidenceRoots,
        evidence_record: Value,
        release_effect: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        let evidence_root = evidence_root(
            kind,
            &roots.authority_root,
            &roots.security_bundle_root,
            &roots.security_report_root,
            &evidence_record,
        );
        let check_id = authority_transfer_check_id(kind, &evidence_root);
        Self {
            check_id,
            kind,
            status,
            requirement: requirement.into(),
            observed: observed.into(),
            authority_root: roots.authority_root,
            security_bundle_root: roots.security_bundle_root,
            security_report_root: roots.security_report_root,
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
            "authority_root": self.authority_root,
            "security_bundle_root": self.security_bundle_root,
            "security_report_root": self.security_report_root,
            "evidence_root": self.evidence_root,
            "release_effect": self.release_effect,
            "remediation": self.remediation,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("authority_transfer_check", &self.public_record())
    }
}

#[derive(Clone, Debug)]
pub struct AdapterEvidenceRoots {
    pub authority_root: String,
    pub security_bundle_root: String,
    pub security_report_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorityTransferReport {
    pub report_id: String,
    pub status: AuthorityTransferReportStatus,
    pub readiness_label: String,
    pub authority_state_root: String,
    pub authority_report_root: String,
    pub security_bundle_state_root: String,
    pub security_bundle_report_root: String,
    pub scenario_id: String,
    pub transcript_root: String,
    pub passed_checks: u64,
    pub watch_checks: u64,
    pub failed_checks: u64,
    pub release_blocking_checks_passed: u64,
    pub release_blocking_checks_total: u64,
    pub checks: BTreeMap<String, AuthorityTransferCheckEvidence>,
    pub roots: AuthorityTransferReportRoots,
}

impl AuthorityTransferReport {
    pub fn public_record(&self) -> Value {
        let checks = self
            .checks
            .values()
            .map(AuthorityTransferCheckEvidence::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "authority_state_root": self.authority_state_root,
            "authority_report_root": self.authority_report_root,
            "security_bundle_state_root": self.security_bundle_state_root,
            "security_bundle_report_root": self.security_bundle_report_root,
            "scenario_id": self.scenario_id,
            "transcript_root": self.transcript_root,
            "passed_checks": self.passed_checks,
            "watch_checks": self.watch_checks,
            "failed_checks": self.failed_checks,
            "release_blocking_checks_passed": self.release_blocking_checks_passed,
            "release_blocking_checks_total": self.release_blocking_checks_total,
            "checks": checks,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorityTransferReportRoots {
    pub check_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl AuthorityTransferReportRoots {
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
    pub release_blocking_checks_passed: u64,
    pub transfer_security_bundles_consumed: u64,
    pub deferred_release_watches: u64,
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
            "release_blocking_checks_passed": self.release_blocking_checks_passed,
            "transfer_security_bundles_consumed": self.transfer_security_bundles_consumed,
            "deferred_release_watches": self.deferred_release_watches,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-TRANSFER-SECURITY-BUNDLE-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-TRANSFER-SECURITY-BUNDLE-STATE",
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
    pub latest_report: Option<AuthorityTransferReport>,
    pub report_history: Vec<AuthorityTransferReport>,
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
            crate::monero_l2_pq_bridge_exit_authority_crosscheck_verifier_runtime::devnet();
        let security_bundle =
            crate::monero_l2_pq_bridge_bound_transfer_forced_exit_security_bundle_runtime::devnet();
        state
            .verify_authority_transfer_bundle(&authority, &security_bundle)
            .expect("devnet authority transfer security bundle adapter");
        state
    }

    pub fn verify_authority_transfer_bundle(
        &mut self,
        authority: &AuthorityCrosscheckState,
        security_bundle: &TransferSecurityBundleState,
    ) -> Result<String> {
        let security_report = latest_security_report(security_bundle)?;
        let authority_report = latest_authority_report(authority)?;
        let mut checks = BTreeMap::new();
        for check in evaluate_authority_transfer_checks(
            &self.config,
            authority,
            authority_report,
            security_bundle,
            security_report,
        ) {
            checks.insert(check.kind.as_str().to_string(), check);
        }
        ensure(
            AuthorityTransferCheckKind::all()
                .iter()
                .all(|kind| checks.contains_key(kind.as_str())),
            "authority transfer security adapter omitted a required check",
        )?;

        let passed_checks = checks
            .values()
            .filter(|check| check.status == AuthorityTransferCheckStatus::Passed)
            .count() as u64;
        let watch_checks = checks
            .values()
            .filter(|check| check.status == AuthorityTransferCheckStatus::Watch)
            .count() as u64;
        let failed_checks = checks
            .values()
            .filter(|check| check.status == AuthorityTransferCheckStatus::Failed)
            .count() as u64;
        let release_blocking_checks_total = AuthorityTransferCheckKind::all()
            .iter()
            .filter(|kind| kind.is_release_blocking())
            .count() as u64;
        let release_blocking_checks_passed = checks
            .values()
            .filter(|check| {
                check.kind.is_release_blocking()
                    && check.status == AuthorityTransferCheckStatus::Passed
            })
            .count() as u64;
        let status = aggregate_report_status(&checks);
        let readiness_label = readiness_label(status, &self.config, security_report).to_string();
        let check_records = checks
            .values()
            .map(AuthorityTransferCheckEvidence::public_record)
            .collect::<Vec<_>>();
        let check_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-TRANSFER-SECURITY-BUNDLE-CHECKS",
            &check_records,
        );
        let source_root = source_root(
            &authority.state_root(),
            &authority_report.state_root(),
            &security_bundle.state_root(),
            &security_report.state_root(),
            &security_report.transcript_root,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &check_root,
            &security_report.scenario_id,
            &security_report.transcript_root,
        );
        let report_id = authority_transfer_report_id(&security_report.scenario_id, &report_root);
        let report = AuthorityTransferReport {
            report_id: report_id.clone(),
            status,
            readiness_label,
            authority_state_root: authority.state_root(),
            authority_report_root: authority_report.state_root(),
            security_bundle_state_root: security_bundle.state_root(),
            security_bundle_report_root: security_report.state_root(),
            scenario_id: security_report.scenario_id.clone(),
            transcript_root: security_report.transcript_root.clone(),
            passed_checks,
            watch_checks,
            failed_checks,
            release_blocking_checks_passed,
            release_blocking_checks_total,
            checks,
            roots: AuthorityTransferReportRoots {
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
            "adapter_suite": self.config.adapter_suite,
            "latest_report": self.latest_report.as_ref().map(AuthorityTransferReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: AuthorityTransferReport) {
        self.counters.reports_run += 1;
        self.counters.checks_run += report.checks.len() as u64;
        self.counters.checks_passed += report.passed_checks;
        self.counters.checks_watch += report.watch_checks;
        self.counters.checks_failed += report.failed_checks;
        self.counters.release_blocking_checks_passed += report.release_blocking_checks_passed;
        self.counters.transfer_security_bundles_consumed += 1;
        self.counters.deferred_release_watches += report
            .checks
            .values()
            .filter(|check| {
                matches!(
                    check.kind,
                    AuthorityTransferCheckKind::WatchReadinessPreserved
                        | AuthorityTransferCheckKind::ReleaseGateClassified
                ) && check.status == AuthorityTransferCheckStatus::Watch
            })
            .count() as u64;
        match report.status {
            AuthorityTransferReportStatus::Passed => self.counters.reports_passed += 1,
            AuthorityTransferReportStatus::Watch => self.counters.reports_watch += 1,
            AuthorityTransferReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(AuthorityTransferReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-TRANSFER-SECURITY-BUNDLE-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

pub fn evaluate_authority_transfer_checks(
    config: &Config,
    authority: &AuthorityCrosscheckState,
    authority_report: &CrossCheckReport,
    security_bundle: &TransferSecurityBundleState,
    security_report: &SecurityBundleReport,
) -> Vec<AuthorityTransferCheckEvidence> {
    vec![
        source_roots_present(
            authority,
            authority_report,
            security_bundle,
            security_report,
        ),
        security_bundle_consumed(config, authority, security_bundle, security_report),
        security_bundle_binds_authority_root(authority, security_bundle, security_report),
        authority_report_accepted(
            config,
            authority,
            authority_report,
            security_bundle,
            security_report,
        ),
        authority_challenge_release_consumes_bundle(authority_report, security_report),
        authority_pq_control_plane_consumes_bundle(authority_report, security_report),
        authority_privacy_surface_consumes_bundle(authority_report, security_report),
        authority_cross_root_continuity_consumes_bundle(
            authority,
            authority_report,
            security_bundle,
            security_report,
        ),
        exit_claim_escape_authorized(authority_report, security_report),
        adversarial_threat_surface_inherited(authority_report, security_report),
        watch_readiness_preserved(config, security_report),
        counter_continuity(authority, security_bundle, security_report),
        release_gate_classified(config, authority_report, security_report),
        audit_hooks_declared(config, authority_report, security_report),
    ]
}

fn source_roots_present(
    authority: &AuthorityCrosscheckState,
    authority_report: &CrossCheckReport,
    security_bundle: &TransferSecurityBundleState,
    security_report: &SecurityBundleReport,
) -> AuthorityTransferCheckEvidence {
    let roots = evidence_roots(authority, security_bundle, security_report);
    let all_present = !authority.state_root().is_empty()
        && !authority_report.state_root().is_empty()
        && !security_bundle.state_root().is_empty()
        && !security_report.state_root().is_empty()
        && !security_report.transcript_root.is_empty();
    let status = if all_present {
        AuthorityTransferCheckStatus::Passed
    } else {
        AuthorityTransferCheckStatus::Failed
    };
    AuthorityTransferCheckEvidence::new(
        AuthorityTransferCheckKind::SourceRootsPresent,
        status,
        "authority adapter must consume authority report root, security bundle root, security report root, and transcript root",
        format!("all_present={all_present} transcript_root_present={}", !security_report.transcript_root.is_empty()),
        roots,
        json!({
            "authority_state_root": authority.state_root(),
            "authority_report_root": authority_report.state_root(),
            "security_bundle_state_root": security_bundle.state_root(),
            "security_bundle_report_root": security_report.state_root(),
            "transcript_root": security_report.transcript_root,
        }),
        "block_release_if_any_source_root_is_missing",
        "rebuild authority cross-check and transfer security bundle before release classification",
    )
}

fn security_bundle_consumed(
    config: &Config,
    authority: &AuthorityCrosscheckState,
    security_bundle: &TransferSecurityBundleState,
    security_report: &SecurityBundleReport,
) -> AuthorityTransferCheckEvidence {
    let roots = evidence_roots(authority, security_bundle, security_report);
    let status_acceptable = matches!(
        security_report.status,
        SecurityBundleReportStatus::Passed | SecurityBundleReportStatus::Watch
    );
    let checks_complete = security_report.failed_checks == 0
        && security_report.checks.len() as u64 >= config.min_security_bundle_checks
        && SecurityBundleCheckKind::all()
            .iter()
            .all(|kind| security_report.checks.contains_key(kind.as_str()));
    let critical_ok = security_report.critical_checks_passed
        == security_report.critical_checks_total
        && security_report.critical_checks_total > 0;
    let consumed = security_bundle.latest_report.is_some()
        && status_acceptable
        && checks_complete
        && critical_ok;
    let status = if consumed {
        AuthorityTransferCheckStatus::Passed
    } else {
        AuthorityTransferCheckStatus::Failed
    };
    AuthorityTransferCheckEvidence::new(
        AuthorityTransferCheckKind::SecurityBundleConsumed,
        status,
        "authority adapter must consume a complete transfer security bundle report with all release-blocking checks passed",
        format!(
            "status={} checks_complete={checks_complete} critical={}/{}",
            security_report.status.as_str(),
            security_report.critical_checks_passed,
            security_report.critical_checks_total
        ),
        roots,
        json!({
            "security_bundle_report": security_report.public_record(),
            "security_bundle_state_root": security_bundle.state_root(),
        }),
        "block_release_without_complete_transfer_security_bundle",
        "rerun the transfer security bundle until all critical bridge-bound transfer exit checks pass",
    )
}

fn security_bundle_binds_authority_root(
    authority: &AuthorityCrosscheckState,
    security_bundle: &TransferSecurityBundleState,
    security_report: &SecurityBundleReport,
) -> AuthorityTransferCheckEvidence {
    let roots = evidence_roots(authority, security_bundle, security_report);
    let authority_root_matches =
        security_report.authority_crosscheck_root == authority.state_root();
    let authority_check_passed = security_check_passed(
        security_report,
        SecurityBundleCheckKind::AuthorityCrosscheckAccepted,
    );
    let root_continuity_passed = security_check_passed(
        security_report,
        SecurityBundleCheckKind::RootContinuityAcrossBundle,
    );
    let ok = authority_root_matches && authority_check_passed && root_continuity_passed;
    let status = if ok {
        AuthorityTransferCheckStatus::Passed
    } else {
        AuthorityTransferCheckStatus::Failed
    };
    AuthorityTransferCheckEvidence::new(
        AuthorityTransferCheckKind::SecurityBundleBindsAuthorityRoot,
        status,
        "transfer security bundle must bind the exact authority cross-check state root consumed by this adapter",
        format!(
            "authority_root_matches={authority_root_matches} authority_check_passed={authority_check_passed} root_continuity_passed={root_continuity_passed}"
        ),
        roots,
        json!({
            "security_authority_crosscheck_root": security_report.authority_crosscheck_root,
            "actual_authority_state_root": authority.state_root(),
            "security_report_root": security_report.state_root(),
        }),
        "block_release_on_authority_root_mismatch",
        "rerun security bundle after the authority cross-check state root is finalized",
    )
}

fn authority_report_accepted(
    config: &Config,
    authority: &AuthorityCrosscheckState,
    authority_report: &CrossCheckReport,
    security_bundle: &TransferSecurityBundleState,
    security_report: &SecurityBundleReport,
) -> AuthorityTransferCheckEvidence {
    let roots = AdapterEvidenceRoots {
        authority_root: authority.state_root(),
        security_bundle_root: security_bundle.state_root(),
        security_report_root: security_report.state_root(),
    };
    let status_accepted = matches!(
        authority_report.status,
        CrossCheckReportStatus::Passed | CrossCheckReportStatus::Watch
    );
    let checks_complete = authority_report.failed_checks == 0
        && authority_report.checks.len() as u64 >= config.min_authority_checks
        && CrossCheckKind::all()
            .iter()
            .all(|kind| authority_report.checks.contains_key(kind.as_str()));
    let root_matches_state = authority_report.state_root()
        == authority
            .latest_report
            .as_ref()
            .map(CrossCheckReport::state_root)
            .unwrap_or_default();
    let ok = status_accepted && checks_complete && root_matches_state;
    let status = if ok {
        AuthorityTransferCheckStatus::Passed
    } else {
        AuthorityTransferCheckStatus::Failed
    };
    AuthorityTransferCheckEvidence::new(
        AuthorityTransferCheckKind::AuthorityReportAccepted,
        status,
        "authority cross-check report must be complete and accepted before it can consume transfer security evidence",
        format!(
            "authority_status={} checks_complete={checks_complete} root_matches_latest={root_matches_state}",
            authority_report.status.as_str()
        ),
        roots,
        json!({
            "authority_report": authority_report.public_record(),
            "authority_state_root": authority.state_root(),
        }),
        "block_release_without_authority_report",
        "rerun authority cross-check and ensure all bridge authority checks are present and non-failed",
    )
}

fn authority_challenge_release_consumes_bundle(
    authority_report: &CrossCheckReport,
    security_report: &SecurityBundleReport,
) -> AuthorityTransferCheckEvidence {
    let roots = roots_from_reports(authority_report, security_report);
    let authority_release =
        authority_check_passed(authority_report, CrossCheckKind::ChallengeReleaseAlignment);
    let bundle_ordering = security_check_passed(
        security_report,
        SecurityBundleCheckKind::ChallengeSettlementOrderingCovered,
    );
    let bundle_escape = security_check_passed(
        security_report,
        SecurityBundleCheckKind::UserEscapeInvariantCovered,
    );
    let ok = authority_release && bundle_ordering && bundle_escape;
    let status = if ok {
        AuthorityTransferCheckStatus::Passed
    } else {
        AuthorityTransferCheckStatus::Failed
    };
    AuthorityTransferCheckEvidence::new(
        AuthorityTransferCheckKind::AuthorityChallengeReleaseConsumesBundle,
        status,
        "authority challenge release rules must consume transfer bundle challenge ordering and user escape evidence",
        format!(
            "authority_release={authority_release} bundle_ordering={bundle_ordering} bundle_escape={bundle_escape}"
        ),
        roots,
        json!({
            "authority_challenge_release": authority_check_record(authority_report, CrossCheckKind::ChallengeReleaseAlignment),
            "bundle_challenge_ordering": security_check_record(security_report, SecurityBundleCheckKind::ChallengeSettlementOrderingCovered),
            "bundle_user_escape": security_check_record(security_report, SecurityBundleCheckKind::UserEscapeInvariantCovered),
        }),
        "block_release_if_challenge_ordering_is_not_authorized",
        "bind challenge release authority to transfer forced-exit ordering and user escape evidence",
    )
}

fn authority_pq_control_plane_consumes_bundle(
    authority_report: &CrossCheckReport,
    security_report: &SecurityBundleReport,
) -> AuthorityTransferCheckEvidence {
    let roots = roots_from_reports(authority_report, security_report);
    let authority_pq =
        authority_check_passed(authority_report, CrossCheckKind::PqControlPlaneAlignment);
    let bundle_control = security_check_passed(
        security_report,
        SecurityBundleCheckKind::WatcherSequencerAuthoritySeparation,
    );
    let bundle_privacy_pq = security_check_passed(
        security_report,
        SecurityBundleCheckKind::PrivacyFeePqSurfaceCovered,
    );
    let ok = authority_pq && bundle_control && bundle_privacy_pq;
    let status = if ok {
        AuthorityTransferCheckStatus::Passed
    } else {
        AuthorityTransferCheckStatus::Failed
    };
    AuthorityTransferCheckEvidence::new(
        AuthorityTransferCheckKind::AuthorityPqControlPlaneConsumesBundle,
        status,
        "authority PQ control-plane checks must consume transfer bundle watcher, sequencer, privacy, and PQ evidence",
        format!(
            "authority_pq={authority_pq} bundle_control={bundle_control} bundle_privacy_pq={bundle_privacy_pq}"
        ),
        roots,
        json!({
            "authority_pq_control": authority_check_record(authority_report, CrossCheckKind::PqControlPlaneAlignment),
            "bundle_control_plane": security_check_record(security_report, SecurityBundleCheckKind::WatcherSequencerAuthoritySeparation),
            "bundle_privacy_pq": security_check_record(security_report, SecurityBundleCheckKind::PrivacyFeePqSurfaceCovered),
        }),
        "block_release_if_pq_control_plane_is_not_bound",
        "bind watcher quorum, sequencer, authority, replay, privacy, and PQ roots before transfer exit release",
    )
}

fn authority_privacy_surface_consumes_bundle(
    authority_report: &CrossCheckReport,
    security_report: &SecurityBundleReport,
) -> AuthorityTransferCheckEvidence {
    let roots = roots_from_reports(authority_report, security_report);
    let authority_privacy =
        authority_check_passed(authority_report, CrossCheckKind::PrivacySurfaceAlignment);
    let bundle_privacy = security_check_passed(
        security_report,
        SecurityBundleCheckKind::PrivacyFeePqSurfaceCovered,
    );
    let bundle_threats = security_check_passed(
        security_report,
        SecurityBundleCheckKind::MoneroThreatCoveragePresent,
    );
    let ok = authority_privacy && bundle_privacy && bundle_threats;
    let status = if ok {
        AuthorityTransferCheckStatus::Passed
    } else {
        AuthorityTransferCheckStatus::Failed
    };
    AuthorityTransferCheckEvidence::new(
        AuthorityTransferCheckKind::AuthorityPrivacySurfaceConsumesBundle,
        status,
        "authority privacy checks must consume transfer bundle privacy, fee, PQ, and Monero metadata threat evidence",
        format!(
            "authority_privacy={authority_privacy} bundle_privacy={bundle_privacy} bundle_threats={bundle_threats}"
        ),
        roots,
        json!({
            "authority_privacy": authority_check_record(authority_report, CrossCheckKind::PrivacySurfaceAlignment),
            "bundle_privacy": security_check_record(security_report, SecurityBundleCheckKind::PrivacyFeePqSurfaceCovered),
            "bundle_threats": security_check_record(security_report, SecurityBundleCheckKind::MoneroThreatCoveragePresent),
        }),
        "block_release_if_privacy_surface_is_not_authorized",
        "preserve roots-only public transfer exit evidence and require metadata, fee, privacy, and PQ coverage",
    )
}

fn authority_cross_root_continuity_consumes_bundle(
    authority: &AuthorityCrosscheckState,
    authority_report: &CrossCheckReport,
    security_bundle: &TransferSecurityBundleState,
    security_report: &SecurityBundleReport,
) -> AuthorityTransferCheckEvidence {
    let roots = evidence_roots(authority, security_bundle, security_report);
    let authority_cross =
        authority_check_passed(authority_report, CrossCheckKind::CrossRootContinuity);
    let bundle_cross = security_check_passed(
        security_report,
        SecurityBundleCheckKind::RootContinuityAcrossBundle,
    );
    let authority_root_matches =
        security_report.authority_crosscheck_root == authority.state_root();
    let report_root_matches = security_bundle
        .latest_report
        .as_ref()
        .is_some_and(|report| report.state_root() == security_report.state_root());
    let ok = authority_cross && bundle_cross && authority_root_matches && report_root_matches;
    let status = if ok {
        AuthorityTransferCheckStatus::Passed
    } else {
        AuthorityTransferCheckStatus::Failed
    };
    AuthorityTransferCheckEvidence::new(
        AuthorityTransferCheckKind::AuthorityCrossRootContinuityConsumesBundle,
        status,
        "authority cross-root continuity must consume the same transfer security bundle root and authority root",
        format!(
            "authority_cross={authority_cross} bundle_cross={bundle_cross} authority_root_matches={authority_root_matches} report_root_matches={report_root_matches}"
        ),
        roots,
        json!({
            "authority_report_root": authority_report.state_root(),
            "security_bundle_report_root": security_report.state_root(),
            "security_bundle_state_root": security_bundle.state_root(),
            "authority_state_root": authority.state_root(),
        }),
        "block_release_on_cross_root_gap",
        "rerun authority and transfer bundle reports in dependency order until all roots match",
    )
}

fn exit_claim_escape_authorized(
    authority_report: &CrossCheckReport,
    security_report: &SecurityBundleReport,
) -> AuthorityTransferCheckEvidence {
    let roots = roots_from_reports(authority_report, security_report);
    let authority_forced = authority_check_passed(
        authority_report,
        CrossCheckKind::ForcedExitAuthorityCoversScenario,
    );
    let bundle_exit_claim = security_check_passed(
        security_report,
        SecurityBundleCheckKind::ExitClaimEscapePathCovered,
    );
    let bundle_escape = security_check_passed(
        security_report,
        SecurityBundleCheckKind::UserEscapeInvariantCovered,
    );
    let ok = authority_forced && bundle_exit_claim && bundle_escape;
    let status = if ok {
        AuthorityTransferCheckStatus::Passed
    } else {
        AuthorityTransferCheckStatus::Failed
    };
    AuthorityTransferCheckEvidence::new(
        AuthorityTransferCheckKind::ExitClaimEscapeAuthorized,
        status,
        "forced-exit authority must directly authorize the transfer exit claim escape path",
        format!(
            "authority_forced={authority_forced} bundle_exit_claim={bundle_exit_claim} bundle_escape={bundle_escape}"
        ),
        roots,
        json!({
            "authority_forced_exit": authority_check_record(authority_report, CrossCheckKind::ForcedExitAuthorityCoversScenario),
            "bundle_exit_claim": security_check_record(security_report, SecurityBundleCheckKind::ExitClaimEscapePathCovered),
            "bundle_escape": security_check_record(security_report, SecurityBundleCheckKind::UserEscapeInvariantCovered),
        }),
        "block_release_without_forced_exit_claim_authority",
        "bind prepared transfer exit claim, derived forced-exit request, and final settlement roots to authority release rules",
    )
}

fn adversarial_threat_surface_inherited(
    authority_report: &CrossCheckReport,
    security_report: &SecurityBundleReport,
) -> AuthorityTransferCheckEvidence {
    let roots = roots_from_reports(authority_report, security_report);
    let authority_adversarial =
        authority_check_passed(authority_report, CrossCheckKind::AdversarialMatrixPassed);
    let bundle_adversarial = security_check_passed(
        security_report,
        SecurityBundleCheckKind::AdversarialMatrixAccepted,
    );
    let bundle_monero = security_check_passed(
        security_report,
        SecurityBundleCheckKind::MoneroThreatCoveragePresent,
    );
    let ok = authority_adversarial && bundle_adversarial && bundle_monero;
    let status = if ok {
        AuthorityTransferCheckStatus::Passed
    } else {
        AuthorityTransferCheckStatus::Failed
    };
    AuthorityTransferCheckEvidence::new(
        AuthorityTransferCheckKind::AdversarialThreatSurfaceInherited,
        status,
        "authority adapter must inherit bridge adversarial coverage from the transfer security bundle",
        format!(
            "authority_adversarial={authority_adversarial} bundle_adversarial={bundle_adversarial} bundle_monero={bundle_monero}"
        ),
        roots,
        json!({
            "authority_adversarial": authority_check_record(authority_report, CrossCheckKind::AdversarialMatrixPassed),
            "bundle_adversarial": security_check_record(security_report, SecurityBundleCheckKind::AdversarialMatrixAccepted),
            "bundle_monero": security_check_record(security_report, SecurityBundleCheckKind::MoneroThreatCoveragePresent),
        }),
        "block_release_without_adversarial_inheritance",
        "keep adversarial bridge threat coverage attached to any transfer exit authority decision",
    )
}

fn watch_readiness_preserved(
    config: &Config,
    security_report: &SecurityBundleReport,
) -> AuthorityTransferCheckEvidence {
    let roots = roots_from_security(security_report);
    let security_watch = security_report.status == SecurityBundleReportStatus::Watch
        && security_report
            .readiness_label
            .contains("compile_and_runtime_tests_deferred");
    let deferred = config.cargo_checks_deferred || config.runtime_tests_deferred;
    let status = if security_watch && deferred {
        AuthorityTransferCheckStatus::Watch
    } else if !deferred && security_report.status == SecurityBundleReportStatus::Passed {
        AuthorityTransferCheckStatus::Passed
    } else {
        AuthorityTransferCheckStatus::Failed
    };
    AuthorityTransferCheckEvidence::new(
        AuthorityTransferCheckKind::WatchReadinessPreserved,
        status,
        "authority adapter must preserve watch readiness when compile/runtime evidence is intentionally deferred",
        format!(
            "security_status={} readiness_label={} cargo_deferred={} runtime_deferred={}",
            security_report.status.as_str(),
            security_report.readiness_label,
            config.cargo_checks_deferred,
            config.runtime_tests_deferred
        ),
        roots,
        json!({
            "security_status": security_report.status.as_str(),
            "security_readiness_label": security_report.readiness_label,
            "cargo_checks_deferred": config.cargo_checks_deferred,
            "runtime_tests_deferred": config.runtime_tests_deferred,
        }),
        "keep_authority_release_in_watch_until_compile_and_runtime_evidence_exists",
        "run cargo checks, runtime tests, and security review before promoting beyond watch",
    )
}

fn counter_continuity(
    authority: &AuthorityCrosscheckState,
    security_bundle: &TransferSecurityBundleState,
    security_report: &SecurityBundleReport,
) -> AuthorityTransferCheckEvidence {
    let roots = evidence_roots(authority, security_bundle, security_report);
    let authority_ok = authority.counters.reports_run as usize == authority.report_history.len()
        && authority.counters.checks_failed == 0
        && authority.latest_report.is_some();
    let security_ok = security_bundle.counters.reports_run as usize
        == security_bundle.report_history.len()
        && security_bundle.counters.checks_failed == 0
        && security_bundle.counters.bridge_exit_bundles_classified > 0
        && security_bundle.latest_report.is_some();
    let latest_matches = security_bundle
        .latest_report
        .as_ref()
        .is_some_and(|report| report.state_root() == security_report.state_root());
    let ok = authority_ok && security_ok && latest_matches;
    let status = if ok {
        AuthorityTransferCheckStatus::Passed
    } else {
        AuthorityTransferCheckStatus::Failed
    };
    AuthorityTransferCheckEvidence::new(
        AuthorityTransferCheckKind::CounterContinuity,
        status,
        "authority and transfer security bundle counters must agree with their report histories",
        format!(
            "authority_ok={authority_ok} security_ok={security_ok} latest_matches={latest_matches}"
        ),
        roots,
        json!({
            "authority_counters": authority.counters.public_record(),
            "authority_report_history_len": authority.report_history.len(),
            "security_counters": security_bundle.counters.public_record(),
            "security_report_history_len": security_bundle.report_history.len(),
        }),
        "block_release_on_counter_drift",
        "refresh counters from canonical report collections before publishing authority transfer decisions",
    )
}

fn release_gate_classified(
    config: &Config,
    authority_report: &CrossCheckReport,
    security_report: &SecurityBundleReport,
) -> AuthorityTransferCheckEvidence {
    let roots = roots_from_reports(authority_report, security_report);
    let no_failed_sources =
        authority_report.failed_checks == 0 && security_report.failed_checks == 0;
    let deferred = config.cargo_checks_deferred || config.runtime_tests_deferred;
    let release_blocked_by_watch = deferred
        && matches!(
            security_report.status,
            SecurityBundleReportStatus::Watch | SecurityBundleReportStatus::Passed
        );
    let status = if no_failed_sources && release_blocked_by_watch {
        AuthorityTransferCheckStatus::Watch
    } else if no_failed_sources && !deferred {
        AuthorityTransferCheckStatus::Passed
    } else {
        AuthorityTransferCheckStatus::Failed
    };
    AuthorityTransferCheckEvidence::new(
        AuthorityTransferCheckKind::ReleaseGateClassified,
        status,
        "authority transfer adapter must classify release as watch while compile/runtime checks remain deferred",
        format!(
            "no_failed_sources={no_failed_sources} release_blocked_by_watch={release_blocked_by_watch} deferred={deferred}"
        ),
        roots,
        json!({
            "authority_report_status": authority_report.status.as_str(),
            "security_report_status": security_report.status.as_str(),
            "security_readiness_label": security_report.readiness_label,
            "cargo_checks_deferred": config.cargo_checks_deferred,
            "runtime_tests_deferred": config.runtime_tests_deferred,
        }),
        "gate_release_as_watch_until_verification_resumes",
        "keep the bundle useful for audit while preventing accidental production-readiness claims",
    )
}

fn audit_hooks_declared(
    config: &Config,
    authority_report: &CrossCheckReport,
    security_report: &SecurityBundleReport,
) -> AuthorityTransferCheckEvidence {
    let roots = roots_from_reports(authority_report, security_report);
    let hooks = [
        "cargo_check",
        "runtime_tests",
        "cryptographic_review",
        "privacy_leakage_audit",
        "authority_release_simulation",
    ];
    let deferred_truthful = config.cargo_checks_deferred && config.runtime_tests_deferred;
    let source_reports_present = !authority_report.state_root().is_empty()
        && !security_report.state_root().is_empty()
        && !security_report.readiness_label.is_empty();
    let ok = deferred_truthful && source_reports_present && hooks.len() >= 5;
    let status = if ok {
        AuthorityTransferCheckStatus::Passed
    } else {
        AuthorityTransferCheckStatus::Failed
    };
    AuthorityTransferCheckEvidence::new(
        AuthorityTransferCheckKind::AuditHooksDeclared,
        status,
        "adapter must declare the missing verification hooks that keep the authority transfer bundle out of production readiness",
        format!(
            "hooks_declared={} deferred_truthful={deferred_truthful} source_reports_present={source_reports_present}",
            hooks.len()
        ),
        roots,
        json!({
            "required_follow_up_hooks": hooks,
            "authority_report_root": authority_report.state_root(),
            "security_report_root": security_report.state_root(),
            "readiness_label": security_report.readiness_label,
        }),
        "keep_release_gate_watch_until_audit_hooks_are_closed",
        "run compile checks, runtime tests, cryptographic review, privacy audit, and authority release simulations",
    )
}

fn latest_security_report(
    security_bundle: &TransferSecurityBundleState,
) -> Result<&SecurityBundleReport> {
    security_bundle
        .latest_report
        .as_ref()
        .ok_or_else(|| "transfer security bundle has no latest report".to_string())
}

fn latest_authority_report(authority: &AuthorityCrosscheckState) -> Result<&CrossCheckReport> {
    authority
        .latest_report
        .as_ref()
        .ok_or_else(|| "authority cross-check has no latest report".to_string())
}

fn authority_check_passed(report: &CrossCheckReport, kind: CrossCheckKind) -> bool {
    report.checks.get(kind.as_str()).is_some_and(|check| {
        matches!(
            check.status,
            CrossCheckStatus::Passed | CrossCheckStatus::Watch
        )
    })
}

fn security_check_passed(report: &SecurityBundleReport, kind: SecurityBundleCheckKind) -> bool {
    report
        .checks
        .get(kind.as_str())
        .is_some_and(|check| check.status == SecurityBundleCheckStatus::Passed)
}

fn authority_check_record(report: &CrossCheckReport, kind: CrossCheckKind) -> Option<Value> {
    report
        .checks
        .get(kind.as_str())
        .map(|check| check.public_record())
}

fn security_check_record(
    report: &SecurityBundleReport,
    kind: SecurityBundleCheckKind,
) -> Option<Value> {
    report
        .checks
        .get(kind.as_str())
        .map(|check| check.public_record())
}

fn evidence_roots(
    authority: &AuthorityCrosscheckState,
    security_bundle: &TransferSecurityBundleState,
    security_report: &SecurityBundleReport,
) -> AdapterEvidenceRoots {
    AdapterEvidenceRoots {
        authority_root: authority.state_root(),
        security_bundle_root: security_bundle.state_root(),
        security_report_root: security_report.state_root(),
    }
}

fn roots_from_reports(
    authority_report: &CrossCheckReport,
    security_report: &SecurityBundleReport,
) -> AdapterEvidenceRoots {
    AdapterEvidenceRoots {
        authority_root: authority_report.state_root(),
        security_bundle_root: security_report.state_root(),
        security_report_root: security_report.state_root(),
    }
}

fn roots_from_security(security_report: &SecurityBundleReport) -> AdapterEvidenceRoots {
    AdapterEvidenceRoots {
        authority_root: security_report.authority_crosscheck_root.clone(),
        security_bundle_root: security_report.state_root(),
        security_report_root: security_report.state_root(),
    }
}

fn aggregate_report_status(
    checks: &BTreeMap<String, AuthorityTransferCheckEvidence>,
) -> AuthorityTransferReportStatus {
    if checks
        .values()
        .any(|check| check.status == AuthorityTransferCheckStatus::Failed)
    {
        AuthorityTransferReportStatus::Failed
    } else if checks
        .values()
        .any(|check| check.status == AuthorityTransferCheckStatus::Watch)
    {
        AuthorityTransferReportStatus::Watch
    } else {
        AuthorityTransferReportStatus::Passed
    }
}

fn readiness_label(
    status: AuthorityTransferReportStatus,
    config: &Config,
    security_report: &SecurityBundleReport,
) -> &'static str {
    match status {
        AuthorityTransferReportStatus::Failed => "authority_transfer_bundle_blocked",
        AuthorityTransferReportStatus::Watch
            if config.cargo_checks_deferred || config.runtime_tests_deferred =>
        {
            "authority_transfer_release_watch_compile_and_runtime_deferred"
        }
        AuthorityTransferReportStatus::Watch
            if security_report.status == SecurityBundleReportStatus::Watch =>
        {
            "authority_transfer_release_watch_security_bundle_watch"
        }
        AuthorityTransferReportStatus::Watch => "authority_transfer_release_watch_audit_needed",
        AuthorityTransferReportStatus::Passed => "authority_transfer_release_evidence_passed",
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

pub fn authority_transfer_report_id(scenario_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-TRANSFER-SECURITY-BUNDLE-REPORT-ID",
        &[HashPart::Str(scenario_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn authority_transfer_check_id(
    kind: AuthorityTransferCheckKind,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-TRANSFER-SECURITY-BUNDLE-CHECK-ID",
        &[HashPart::Str(kind.as_str()), HashPart::Str(evidence_root)],
        32,
    )
}

pub fn source_root(
    authority_state_root: &str,
    authority_report_root: &str,
    security_bundle_state_root: &str,
    security_bundle_report_root: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-TRANSFER-SECURITY-BUNDLE-SOURCE-ROOT",
        &[
            HashPart::Str(authority_state_root),
            HashPart::Str(authority_report_root),
            HashPart::Str(security_bundle_state_root),
            HashPart::Str(security_bundle_report_root),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

pub fn evidence_root(
    kind: AuthorityTransferCheckKind,
    authority_root: &str,
    security_bundle_root: &str,
    security_report_root: &str,
    record: &Value,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-TRANSFER-SECURITY-BUNDLE-EVIDENCE",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(authority_root),
            HashPart::Str(security_bundle_root),
            HashPart::Str(security_report_root),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn report_root(
    status: AuthorityTransferReportStatus,
    readiness_label: &str,
    source_root: &str,
    check_root: &str,
    scenario_id: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-TRANSFER-SECURITY-BUNDLE-REPORT-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(check_root),
            HashPart::Str(scenario_id),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-AUTHORITY-TRANSFER-SECURITY-BUNDLE-RECORD",
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
