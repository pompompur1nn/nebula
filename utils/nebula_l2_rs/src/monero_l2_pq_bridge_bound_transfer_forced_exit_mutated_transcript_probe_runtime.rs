use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_bound_transfer_forced_exit_scenario_runtime::{
        ClaimKind, ClaimStatus, ScenarioClaim, ScenarioStep, ScenarioTranscript,
        State as TransferForcedExitScenarioState, StepKind,
    },
    monero_l2_pq_bridge_bound_transfer_forced_exit_security_bundle_runtime::{
        SecurityBundleCheckKind, SecurityBundleCheckStatus, SecurityBundleReportStatus,
        State as TransferSecurityBundleState,
    },
    monero_l2_pq_bridge_bound_transfer_forced_exit_static_verifier_runtime::{
        ReportStatus as StaticReportStatus, State as TransferStaticVerifierState,
    },
    monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::{
        AuthorityTransferCheckKind, AuthorityTransferCheckStatus, AuthorityTransferReportStatus,
        State as AuthorityTransferAdapterState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeBoundTransferForcedExitMutatedTranscriptProbeRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_BOUND_TRANSFER_FORCED_EXIT_MUTATED_TRANSCRIPT_PROBE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-bound-transfer-forced-exit-mutated-transcript-probe-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_BOUND_TRANSFER_FORCED_EXIT_MUTATED_TRANSCRIPT_PROBE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PROBE_SUITE: &str =
    "monero-l2-pq-bridge-bound-transfer-forced-exit-mutated-negative-fixtures-v1";
pub const DEFAULT_MIN_REJECTED_PROBES: u64 = 12;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    PreSealStepRootForged,
    ClaimRootForged,
    ExitClaimRootForged,
    MissingForcedExitClaim,
    SettlementBeforeChallengeResolution,
    MissingTranscriptSeal,
    FinalSpineRootMismatch,
    FinalTransferRuntimeRootMismatch,
    AuthorityRootMismatch,
    PrivacySurfaceLeakage,
    PqControlPlaneGap,
    AdversarialCoverageGap,
    DeferredReadinessPromotion,
    CounterDrift,
}

impl MutationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreSealStepRootForged => "pre_seal_step_root_forged",
            Self::ClaimRootForged => "claim_root_forged",
            Self::ExitClaimRootForged => "exit_claim_root_forged",
            Self::MissingForcedExitClaim => "missing_forced_exit_claim",
            Self::SettlementBeforeChallengeResolution => "settlement_before_challenge_resolution",
            Self::MissingTranscriptSeal => "missing_transcript_seal",
            Self::FinalSpineRootMismatch => "final_spine_root_mismatch",
            Self::FinalTransferRuntimeRootMismatch => "final_transfer_runtime_root_mismatch",
            Self::AuthorityRootMismatch => "authority_root_mismatch",
            Self::PrivacySurfaceLeakage => "privacy_surface_leakage",
            Self::PqControlPlaneGap => "pq_control_plane_gap",
            Self::AdversarialCoverageGap => "adversarial_coverage_gap",
            Self::DeferredReadinessPromotion => "deferred_readiness_promotion",
            Self::CounterDrift => "counter_drift",
        }
    }

    pub fn all() -> [Self; 14] {
        [
            Self::PreSealStepRootForged,
            Self::ClaimRootForged,
            Self::ExitClaimRootForged,
            Self::MissingForcedExitClaim,
            Self::SettlementBeforeChallengeResolution,
            Self::MissingTranscriptSeal,
            Self::FinalSpineRootMismatch,
            Self::FinalTransferRuntimeRootMismatch,
            Self::AuthorityRootMismatch,
            Self::PrivacySurfaceLeakage,
            Self::PqControlPlaneGap,
            Self::AdversarialCoverageGap,
            Self::DeferredReadinessPromotion,
            Self::CounterDrift,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedRejection {
    StaticStepRootMismatch,
    StaticClaimRootMismatch,
    TransferExitClaimMismatch,
    MissingForcedExitDerivation,
    BadChallengeSettlementOrdering,
    UnsealedTranscript,
    FinalSpineRootMismatch,
    FinalTransferRuntimeRootMismatch,
    AuthorityBundleRootMismatch,
    PrivacySurfaceViolation,
    PqControlPlaneViolation,
    AdversarialCoverageViolation,
    DeferredReadinessCannotPromote,
    CounterContinuityViolation,
}

impl ExpectedRejection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaticStepRootMismatch => "static_step_root_mismatch",
            Self::StaticClaimRootMismatch => "static_claim_root_mismatch",
            Self::TransferExitClaimMismatch => "transfer_exit_claim_mismatch",
            Self::MissingForcedExitDerivation => "missing_forced_exit_derivation",
            Self::BadChallengeSettlementOrdering => "bad_challenge_settlement_ordering",
            Self::UnsealedTranscript => "unsealed_transcript",
            Self::FinalSpineRootMismatch => "final_spine_root_mismatch",
            Self::FinalTransferRuntimeRootMismatch => "final_transfer_runtime_root_mismatch",
            Self::AuthorityBundleRootMismatch => "authority_bundle_root_mismatch",
            Self::PrivacySurfaceViolation => "privacy_surface_violation",
            Self::PqControlPlaneViolation => "pq_control_plane_violation",
            Self::AdversarialCoverageViolation => "adversarial_coverage_violation",
            Self::DeferredReadinessCannotPromote => "deferred_readiness_cannot_promote",
            Self::CounterContinuityViolation => "counter_continuity_violation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Rejected,
    Watch,
    Escaped,
}

impl ProbeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rejected => "rejected",
            Self::Watch => "watch",
            Self::Escaped => "escaped",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeReportStatus {
    Passed,
    Watch,
    Failed,
}

impl ProbeReportStatus {
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
    pub probe_suite: String,
    pub min_rejected_probes: u64,
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
            probe_suite: PROBE_SUITE.to_string(),
            min_rejected_probes: DEFAULT_MIN_REJECTED_PROBES,
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
            "probe_suite": self.probe_suite,
            "min_rejected_probes": self.min_rejected_probes,
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
pub struct MutatedProbeCase {
    pub probe_id: String,
    pub kind: MutationKind,
    pub expected_rejection: ExpectedRejection,
    pub status: ProbeStatus,
    pub scenario_id: String,
    pub transcript_root: String,
    pub mutation_root: String,
    pub baseline_root: String,
    pub observed: String,
    pub rejection_reason: String,
    pub affected_checks: Vec<String>,
    pub public_fixture: Value,
}

impl MutatedProbeCase {
    pub fn new(
        kind: MutationKind,
        expected_rejection: ExpectedRejection,
        status: ProbeStatus,
        scenario_id: impl Into<String>,
        transcript_root: impl Into<String>,
        baseline_root: impl Into<String>,
        observed: impl Into<String>,
        rejection_reason: impl Into<String>,
        affected_checks: Vec<String>,
        public_fixture: Value,
    ) -> Self {
        let scenario_id = scenario_id.into();
        let transcript_root = transcript_root.into();
        let baseline_root = baseline_root.into();
        let mutation_root = mutation_root(
            &scenario_id,
            kind,
            expected_rejection,
            &baseline_root,
            &public_fixture,
        );
        let probe_id = probe_id(&scenario_id, kind, &mutation_root);
        Self {
            probe_id,
            kind,
            expected_rejection,
            status,
            scenario_id,
            transcript_root,
            mutation_root,
            baseline_root,
            observed: observed.into(),
            rejection_reason: rejection_reason.into(),
            affected_checks,
            public_fixture,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "probe_id": self.probe_id,
            "kind": self.kind.as_str(),
            "expected_rejection": self.expected_rejection.as_str(),
            "status": self.status.as_str(),
            "scenario_id": self.scenario_id,
            "transcript_root": self.transcript_root,
            "mutation_root": self.mutation_root,
            "baseline_root": self.baseline_root,
            "observed": self.observed,
            "rejection_reason": self.rejection_reason,
            "affected_checks": self.affected_checks,
            "public_fixture": self.public_fixture,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("mutated_probe_case", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MutatedProbeReport {
    pub report_id: String,
    pub status: ProbeReportStatus,
    pub scenario_id: String,
    pub transcript_root: String,
    pub scenario_state_root: String,
    pub static_verifier_root: String,
    pub security_bundle_root: String,
    pub authority_adapter_root: String,
    pub probes_run: u64,
    pub probes_rejected: u64,
    pub probes_watch: u64,
    pub probes_escaped: u64,
    pub readiness_label: String,
    pub cases: BTreeMap<String, MutatedProbeCase>,
    pub roots: MutatedProbeReportRoots,
}

impl MutatedProbeReport {
    pub fn public_record(&self) -> Value {
        let cases = self
            .cases
            .values()
            .map(MutatedProbeCase::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "scenario_id": self.scenario_id,
            "transcript_root": self.transcript_root,
            "scenario_state_root": self.scenario_state_root,
            "static_verifier_root": self.static_verifier_root,
            "security_bundle_root": self.security_bundle_root,
            "authority_adapter_root": self.authority_adapter_root,
            "probes_run": self.probes_run,
            "probes_rejected": self.probes_rejected,
            "probes_watch": self.probes_watch,
            "probes_escaped": self.probes_escaped,
            "readiness_label": self.readiness_label,
            "cases": cases,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MutatedProbeReportRoots {
    pub case_root: String,
    pub source_root: String,
    pub report_root: String,
}

impl MutatedProbeReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "case_root": self.case_root,
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
    pub probes_run: u64,
    pub probes_rejected: u64,
    pub probes_watch: u64,
    pub probes_escaped: u64,
    pub root_mutation_rejections: u64,
    pub ordering_rejections: u64,
    pub authority_rejections: u64,
    pub readiness_rejections: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_passed": self.reports_passed,
            "reports_watch": self.reports_watch,
            "reports_failed": self.reports_failed,
            "probes_run": self.probes_run,
            "probes_rejected": self.probes_rejected,
            "probes_watch": self.probes_watch,
            "probes_escaped": self.probes_escaped,
            "root_mutation_rejections": self.root_mutation_rejections,
            "ordering_rejections": self.ordering_rejections,
            "authority_rejections": self.authority_rejections,
            "readiness_rejections": self.readiness_rejections,
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
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-MUTATED-PROBE-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-MUTATED-PROBE-STATE",
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
    pub latest_report: Option<MutatedProbeReport>,
    pub report_history: Vec<MutatedProbeReport>,
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
        let security_bundle =
            crate::monero_l2_pq_bridge_bound_transfer_forced_exit_security_bundle_runtime::devnet();
        let authority_adapter =
            crate::monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::devnet();
        state
            .run_probe_bundle(
                &scenario,
                &static_verifier,
                &security_bundle,
                &authority_adapter,
            )
            .expect("devnet transfer forced-exit mutated transcript probes");
        state
    }

    pub fn run_probe_bundle(
        &mut self,
        scenario: &TransferForcedExitScenarioState,
        static_verifier: &TransferStaticVerifierState,
        security_bundle: &TransferSecurityBundleState,
        authority_adapter: &AuthorityTransferAdapterState,
    ) -> Result<String> {
        let transcript = latest_transcript(scenario)?;
        let cases = build_mutated_cases(
            &self.config,
            scenario,
            static_verifier,
            security_bundle,
            authority_adapter,
            transcript,
        )?;
        let probes_run = cases.len() as u64;
        let probes_rejected = cases
            .values()
            .filter(|case| case.status == ProbeStatus::Rejected)
            .count() as u64;
        let probes_watch = cases
            .values()
            .filter(|case| case.status == ProbeStatus::Watch)
            .count() as u64;
        let probes_escaped = cases
            .values()
            .filter(|case| case.status == ProbeStatus::Escaped)
            .count() as u64;
        let status = aggregate_report_status(&self.config, probes_rejected, probes_escaped);
        let readiness_label = readiness_label(status, &self.config).to_string();
        let case_records = cases
            .values()
            .map(MutatedProbeCase::public_record)
            .collect::<Vec<_>>();
        let case_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-MUTATED-PROBE-CASES",
            &case_records,
        );
        let source_root = source_root(
            &scenario.state_root(),
            &static_verifier.state_root(),
            &security_bundle.state_root(),
            &authority_adapter.state_root(),
            &transcript.transcript_root,
        );
        let report_root = report_root(
            status,
            &readiness_label,
            &source_root,
            &case_root,
            &transcript.scenario_id,
            &transcript.transcript_root,
        );
        let report_id = probe_report_id(&transcript.scenario_id, &report_root);
        let report = MutatedProbeReport {
            report_id: report_id.clone(),
            status,
            scenario_id: transcript.scenario_id.clone(),
            transcript_root: transcript.transcript_root.clone(),
            scenario_state_root: scenario.state_root(),
            static_verifier_root: static_verifier.state_root(),
            security_bundle_root: security_bundle.state_root(),
            authority_adapter_root: authority_adapter.state_root(),
            probes_run,
            probes_rejected,
            probes_watch,
            probes_escaped,
            readiness_label,
            cases,
            roots: MutatedProbeReportRoots {
                case_root,
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
            "probe_suite": self.config.probe_suite,
            "latest_report": self.latest_report.as_ref().map(MutatedProbeReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: MutatedProbeReport) {
        self.counters.reports_run += 1;
        self.counters.probes_run += report.probes_run;
        self.counters.probes_rejected += report.probes_rejected;
        self.counters.probes_watch += report.probes_watch;
        self.counters.probes_escaped += report.probes_escaped;
        self.counters.root_mutation_rejections += report
            .cases
            .values()
            .filter(|case| {
                matches!(
                    case.kind,
                    MutationKind::PreSealStepRootForged
                        | MutationKind::ClaimRootForged
                        | MutationKind::ExitClaimRootForged
                        | MutationKind::FinalSpineRootMismatch
                        | MutationKind::FinalTransferRuntimeRootMismatch
                ) && case.status == ProbeStatus::Rejected
            })
            .count() as u64;
        self.counters.ordering_rejections += report
            .cases
            .values()
            .filter(|case| {
                matches!(
                    case.kind,
                    MutationKind::SettlementBeforeChallengeResolution
                        | MutationKind::MissingTranscriptSeal
                        | MutationKind::MissingForcedExitClaim
                        | MutationKind::CounterDrift
                ) && case.status == ProbeStatus::Rejected
            })
            .count() as u64;
        self.counters.authority_rejections += report
            .cases
            .values()
            .filter(|case| {
                matches!(
                    case.kind,
                    MutationKind::AuthorityRootMismatch
                        | MutationKind::PrivacySurfaceLeakage
                        | MutationKind::PqControlPlaneGap
                        | MutationKind::AdversarialCoverageGap
                ) && case.status == ProbeStatus::Rejected
            })
            .count() as u64;
        self.counters.readiness_rejections += report
            .cases
            .values()
            .filter(|case| {
                case.kind == MutationKind::DeferredReadinessPromotion
                    && case.status == ProbeStatus::Rejected
            })
            .count() as u64;
        match report.status {
            ProbeReportStatus::Passed => self.counters.reports_passed += 1,
            ProbeReportStatus::Watch => self.counters.reports_watch += 1,
            ProbeReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(MutatedProbeReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-MUTATED-PROBE-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

pub fn build_mutated_cases(
    config: &Config,
    scenario: &TransferForcedExitScenarioState,
    static_verifier: &TransferStaticVerifierState,
    security_bundle: &TransferSecurityBundleState,
    authority_adapter: &AuthorityTransferAdapterState,
    transcript: &ScenarioTranscript,
) -> Result<BTreeMap<String, MutatedProbeCase>> {
    let pre_seal_steps = pre_seal_steps(scenario, &transcript.scenario_id);
    let seal_steps = seal_steps(scenario, &transcript.scenario_id);
    let claims = scenario_claims(scenario, &transcript.scenario_id);
    let static_report = static_verifier.latest_report.as_ref();
    let security_report = security_bundle.latest_report.as_ref();
    let authority_report = authority_adapter.latest_report.as_ref();
    let mut cases = BTreeMap::new();
    for case in [
        pre_seal_step_root_forged(transcript, &pre_seal_steps, static_report),
        claim_root_forged(transcript, &claims, static_report),
        exit_claim_root_forged(transcript, &claims, static_report),
        missing_forced_exit_claim(transcript, &claims, security_report),
        settlement_before_challenge_resolution(transcript, &pre_seal_steps, security_report),
        missing_transcript_seal(transcript, &seal_steps, security_report),
        final_spine_root_mismatch(transcript, &pre_seal_steps, static_report),
        final_transfer_runtime_root_mismatch(transcript, &pre_seal_steps, static_report),
        authority_root_mismatch(transcript, security_report, authority_report),
        privacy_surface_leakage(transcript, &claims, security_report, authority_report),
        pq_control_plane_gap(transcript, security_report, authority_report),
        adversarial_coverage_gap(transcript, security_report, authority_report),
        deferred_readiness_promotion(config, transcript, security_report, authority_report),
        counter_drift(
            transcript,
            scenario,
            static_verifier,
            security_bundle,
            authority_adapter,
        ),
    ] {
        cases.insert(case.probe_id.clone(), case);
    }
    ensure(
        MutationKind::all()
            .iter()
            .all(|kind| cases.values().any(|case| case.kind == *kind)),
        "mutated transcript probe set omitted a required mutation kind",
    )?;
    Ok(cases)
}

fn pre_seal_step_root_forged(
    transcript: &ScenarioTranscript,
    steps: &[&ScenarioStep],
    static_report: Option<&crate::monero_l2_pq_bridge_bound_transfer_forced_exit_static_verifier_runtime::StaticReport>,
) -> MutatedProbeCase {
    let baseline_root = recompute_step_root(steps);
    let forged_root = tampered_root(&baseline_root, "pre-seal-step-forgery");
    let forged_differs = forged_root != transcript.step_root;
    let static_binds_root = static_report.is_some_and(|report| {
        report.status == StaticReportStatus::Passed
            && report.recomputed_pre_seal_step_root == transcript.step_root
    });
    rejected_case(
        transcript,
        MutationKind::PreSealStepRootForged,
        ExpectedRejection::StaticStepRootMismatch,
        baseline_root,
        format!(
            "forged_step_root_differs={} static_binds_step_root={static_binds_root}",
            forged_differs
        ),
        "forged pre-seal step root diverges from static verifier and transcript step root",
        vec![
            "static_verifier.pre_seal_step_root_matches".to_string(),
            "security_bundle.root_continuity_across_bundle".to_string(),
        ],
        json!({
            "forged_step_root": forged_root,
            "transcript_step_root": transcript.step_root,
            "pre_seal_step_count": steps.len(),
        }),
        forged_differs && static_binds_root,
    )
}

fn claim_root_forged(
    transcript: &ScenarioTranscript,
    claims: &[&ScenarioClaim],
    static_report: Option<&crate::monero_l2_pq_bridge_bound_transfer_forced_exit_static_verifier_runtime::StaticReport>,
) -> MutatedProbeCase {
    let baseline_root = recompute_claim_root(claims);
    let forged_root = tampered_root(&baseline_root, "claim-root-forgery");
    let forged_differs = forged_root != transcript.claim_root;
    let static_binds_root = static_report.is_some_and(|report| {
        report.status == StaticReportStatus::Passed
            && report.recomputed_claim_root == transcript.claim_root
    });
    rejected_case(
        transcript,
        MutationKind::ClaimRootForged,
        ExpectedRejection::StaticClaimRootMismatch,
        baseline_root,
        format!(
            "forged_claim_root_differs={} static_binds_claim_root={static_binds_root}",
            forged_differs
        ),
        "forged claim root diverges from static verifier and transcript claim root",
        vec![
            "static_verifier.claim_root_matches".to_string(),
            "security_bundle.root_continuity_across_bundle".to_string(),
        ],
        json!({
            "forged_claim_root": forged_root,
            "transcript_claim_root": transcript.claim_root,
            "claim_count": claims.len(),
        }),
        forged_differs && static_binds_root,
    )
}

fn exit_claim_root_forged(
    transcript: &ScenarioTranscript,
    claims: &[&ScenarioClaim],
    static_report: Option<&crate::monero_l2_pq_bridge_bound_transfer_forced_exit_static_verifier_runtime::StaticReport>,
) -> MutatedProbeCase {
    let exit_claim = claim_by_kind(claims, ClaimKind::ExitClaimMatchesTransferReceipt);
    let baseline_root = recompute_claim_root(claims);
    let forged_root = tampered_root(&baseline_root, "exit-claim-root-forgery");
    let forged_differs = forged_root != transcript.claim_root;
    let exit_claim_proven = exit_claim.is_some_and(|claim| claim.status == ClaimStatus::Proven);
    let static_binds_root = static_report.is_some_and(|report| {
        report.status == StaticReportStatus::Passed
            && report.recomputed_claim_root == transcript.claim_root
    });
    rejected_case(
        transcript,
        MutationKind::ExitClaimRootForged,
        ExpectedRejection::TransferExitClaimMismatch,
        baseline_root.clone(),
        format!(
            "exit_claim_proven={exit_claim_proven} forged_exit_claim_root_differs={} static_binds_claim_root={static_binds_root}",
            forged_differs
        ),
        "forged transfer exit claim root cannot bind the forced-exit request",
        vec![
            "failclosed.exit_claim_root_tamper_rejected".to_string(),
            "security_bundle.exit_claim_escape_path_covered".to_string(),
        ],
        json!({
            "exit_claim": exit_claim.map(ScenarioClaim::public_record),
            "forged_exit_claim_root": forged_root,
            "baseline_claim_root": baseline_root,
        }),
        exit_claim_proven && forged_differs && static_binds_root,
    )
}

fn missing_forced_exit_claim(
    transcript: &ScenarioTranscript,
    claims: &[&ScenarioClaim],
    security_report: Option<&crate::monero_l2_pq_bridge_bound_transfer_forced_exit_security_bundle_runtime::SecurityBundleReport>,
) -> MutatedProbeCase {
    let baseline_root = recompute_claim_root(claims);
    let filtered = claims
        .iter()
        .copied()
        .filter(|claim| claim.kind != ClaimKind::ForcedExitRequestDerivedFromClaim)
        .collect::<Vec<_>>();
    let missing_root = recompute_claim_root(&filtered);
    let missing_differs = missing_root != transcript.claim_root;
    let security_checks_claim = security_report.is_some_and(|report| {
        security_check_passed(report, SecurityBundleCheckKind::ExitClaimEscapePathCovered)
            && security_check_passed(report, SecurityBundleCheckKind::UserEscapeInvariantCovered)
    });
    let forced_claim_present = claim_by_kind(claims, ClaimKind::ForcedExitRequestDerivedFromClaim)
        .is_some_and(|claim| claim.status == ClaimStatus::Proven);
    rejected_case(
        transcript,
        MutationKind::MissingForcedExitClaim,
        ExpectedRejection::MissingForcedExitDerivation,
        baseline_root,
        format!(
            "forced_claim_present={forced_claim_present} missing_claim_root_differs={} security_checks_claim={security_checks_claim}",
            missing_differs
        ),
        "removing forced-exit derivation claim breaks user escape evidence",
        vec![
            "security_bundle.exit_claim_escape_path_covered".to_string(),
            "authority_adapter.exit_claim_escape_authorized".to_string(),
        ],
        json!({
            "missing_claim_kind": ClaimKind::ForcedExitRequestDerivedFromClaim.as_str(),
            "missing_claim_root": missing_root,
            "remaining_claims": filtered.iter().map(|claim| claim.public_record()).collect::<Vec<_>>(),
        }),
        forced_claim_present && missing_differs && security_checks_claim,
    )
}

fn settlement_before_challenge_resolution(
    transcript: &ScenarioTranscript,
    steps: &[&ScenarioStep],
    security_report: Option<&crate::monero_l2_pq_bridge_bound_transfer_forced_exit_security_bundle_runtime::SecurityBundleReport>,
) -> MutatedProbeCase {
    let baseline_root = recompute_step_root(steps);
    let challenge = step_by_kind(steps, StepKind::ChallengeResolved);
    let settlement = step_by_kind(steps, StepKind::ExitSettled);
    let real_order = ordered(
        steps,
        &[
            StepKind::ForcedExitArmed,
            StepKind::ChallengeOpened,
            StepKind::ChallengeResolved,
            StepKind::TransferReadinessRechecked,
            StepKind::ExitSettled,
        ],
    );
    let forged_settlement_sequence = challenge.map(|step| step.sequence.saturating_sub(1));
    let security_checks_order = security_report.is_some_and(|report| {
        security_check_passed(
            report,
            SecurityBundleCheckKind::ChallengeSettlementOrderingCovered,
        )
    });
    let rejected = real_order
        && security_checks_order
        && challenge
            .zip(settlement)
            .is_some_and(|(challenge, settlement)| {
                settlement.sequence > challenge.sequence
                    && forged_settlement_sequence.unwrap_or_default() <= challenge.sequence
            });
    rejected_case(
        transcript,
        MutationKind::SettlementBeforeChallengeResolution,
        ExpectedRejection::BadChallengeSettlementOrdering,
        baseline_root,
        format!(
            "real_order={real_order} forged_settlement_sequence={:?} security_checks_order={security_checks_order}",
            forged_settlement_sequence
        ),
        "settlement before challenge resolution violates forced-exit release ordering",
        vec![
            "security_bundle.challenge_settlement_ordering_covered".to_string(),
            "authority_adapter.authority_challenge_release_consumes_bundle".to_string(),
        ],
        json!({
            "challenge_resolved_sequence": challenge.map(|step| step.sequence),
            "real_settlement_sequence": settlement.map(|step| step.sequence),
            "forged_settlement_sequence": forged_settlement_sequence,
        }),
        rejected,
    )
}

fn missing_transcript_seal(
    transcript: &ScenarioTranscript,
    seal_steps: &[&ScenarioStep],
    security_report: Option<&crate::monero_l2_pq_bridge_bound_transfer_forced_exit_security_bundle_runtime::SecurityBundleReport>,
) -> MutatedProbeCase {
    let baseline_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SEAL-STEPS",
        &seal_steps
            .iter()
            .map(|step| step.public_record())
            .collect::<Vec<_>>(),
    );
    let no_seal_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-SEAL-STEPS",
        &[],
    );
    let no_seal_differs = no_seal_root != transcript.transcript_root;
    let security_checks_escape = security_report.is_some_and(|report| {
        security_check_passed(report, SecurityBundleCheckKind::TransferTranscriptProven)
    });
    rejected_case(
        transcript,
        MutationKind::MissingTranscriptSeal,
        ExpectedRejection::UnsealedTranscript,
        baseline_root,
        format!(
            "seal_steps={} no_seal_root_differs={} security_checks_escape={security_checks_escape}",
            seal_steps.len(),
            no_seal_differs
        ),
        "missing seal step means transcript cannot be accepted as final public evidence",
        vec![
            "failclosed.missing_seal_step_rejected".to_string(),
            "security_bundle.transfer_transcript_proven".to_string(),
        ],
        json!({
            "seal_step_count": seal_steps.len(),
            "no_seal_root": no_seal_root,
            "seal_steps": seal_steps.iter().map(|step| step.public_record()).collect::<Vec<_>>(),
        }),
        seal_steps.len() == 1 && security_checks_escape,
    )
}

fn final_spine_root_mismatch(
    transcript: &ScenarioTranscript,
    steps: &[&ScenarioStep],
    static_report: Option<&crate::monero_l2_pq_bridge_bound_transfer_forced_exit_static_verifier_runtime::StaticReport>,
) -> MutatedProbeCase {
    let baseline_root = transcript.final_spine_root.clone();
    let forged_root = tampered_root(&baseline_root, "final-spine-root-forgery");
    let forged_differs = forged_root != transcript.final_spine_root;
    let settlement = step_by_kind(steps, StepKind::ExitSettled);
    let static_binds_final = static_report.is_some_and(|report| {
        report.status == StaticReportStatus::Passed
            && report.final_spine_root == transcript.final_spine_root
    });
    let rejected = settlement
        .is_some_and(|step| step.spine_root_after == transcript.final_spine_root)
        && static_binds_final
        && forged_differs;
    rejected_case(
        transcript,
        MutationKind::FinalSpineRootMismatch,
        ExpectedRejection::FinalSpineRootMismatch,
        baseline_root,
        format!(
            "static_binds_final={static_binds_final} forged_root_differs={}",
            forged_differs
        ),
        "final bridge spine root mismatch breaks settled exit evidence",
        vec![
            "static_verifier.final_roots_match_scenario".to_string(),
            "security_bundle.root_continuity_across_bundle".to_string(),
        ],
        json!({
            "forged_final_spine_root": forged_root,
            "real_final_spine_root": transcript.final_spine_root,
            "settled_step": settlement.map(ScenarioStep::public_record),
        }),
        rejected,
    )
}

fn final_transfer_runtime_root_mismatch(
    transcript: &ScenarioTranscript,
    steps: &[&ScenarioStep],
    static_report: Option<&crate::monero_l2_pq_bridge_bound_transfer_forced_exit_static_verifier_runtime::StaticReport>,
) -> MutatedProbeCase {
    let baseline_root = transcript.final_transfer_runtime_root.clone();
    let forged_root = tampered_root(&baseline_root, "final-transfer-runtime-root-forgery");
    let forged_differs = forged_root != transcript.final_transfer_runtime_root;
    let settlement = step_by_kind(steps, StepKind::ExitSettled);
    let static_binds_final = static_report.is_some_and(|report| {
        report.status == StaticReportStatus::Passed
            && report.final_transfer_runtime_root == transcript.final_transfer_runtime_root
    });
    let rejected = settlement.is_some_and(|step| {
        step.transfer_runtime_root_after == transcript.final_transfer_runtime_root
    }) && static_binds_final
        && forged_differs;
    rejected_case(
        transcript,
        MutationKind::FinalTransferRuntimeRootMismatch,
        ExpectedRejection::FinalTransferRuntimeRootMismatch,
        baseline_root,
        format!(
            "static_binds_final={static_binds_final} forged_root_differs={}",
            forged_differs
        ),
        "final transfer runtime root mismatch breaks transfer exit settlement evidence",
        vec![
            "static_verifier.final_roots_match_scenario".to_string(),
            "authority_adapter.authority_cross_root_continuity_consumes_bundle".to_string(),
        ],
        json!({
            "forged_final_transfer_runtime_root": forged_root,
            "real_final_transfer_runtime_root": transcript.final_transfer_runtime_root,
            "settled_step": settlement.map(ScenarioStep::public_record),
        }),
        rejected,
    )
}

fn authority_root_mismatch(
    transcript: &ScenarioTranscript,
    security_report: Option<&crate::monero_l2_pq_bridge_bound_transfer_forced_exit_security_bundle_runtime::SecurityBundleReport>,
    authority_report: Option<&crate::monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::AuthorityTransferReport>,
) -> MutatedProbeCase {
    let baseline_root = security_report
        .map(|report| report.authority_crosscheck_root.clone())
        .unwrap_or_else(|| "missing-security-authority-root".to_string());
    let forged_root = tampered_root(&baseline_root, "authority-root-forgery");
    let forged_differs =
        security_report.is_some_and(|report| forged_root != report.authority_crosscheck_root);
    let security_binds_authority = security_report.is_some_and(|report| {
        security_check_passed(report, SecurityBundleCheckKind::AuthorityCrosscheckAccepted)
            && security_check_passed(report, SecurityBundleCheckKind::RootContinuityAcrossBundle)
    });
    let adapter_binds_authority = authority_report.is_some_and(|report| {
        report.status == AuthorityTransferReportStatus::Watch
            || report.status == AuthorityTransferReportStatus::Passed
    });
    rejected_case(
        transcript,
        MutationKind::AuthorityRootMismatch,
        ExpectedRejection::AuthorityBundleRootMismatch,
        baseline_root,
        format!(
            "forged_authority_root_differs={} security_binds_authority={security_binds_authority} adapter_binds_authority={adapter_binds_authority}",
            forged_differs
        ),
        "authority root mismatch breaks the authority adapter release decision",
        vec![
            "security_bundle.security_bundle_binds_authority_root".to_string(),
            "authority_adapter.authority_cross_root_continuity_consumes_bundle".to_string(),
        ],
        json!({
            "forged_authority_root": forged_root,
            "security_report": security_report.map(|report| report.public_record()),
            "authority_adapter_report": authority_report.map(|report| report.public_record()),
        }),
        security_binds_authority && adapter_binds_authority,
    )
}

fn privacy_surface_leakage(
    transcript: &ScenarioTranscript,
    claims: &[&ScenarioClaim],
    security_report: Option<&crate::monero_l2_pq_bridge_bound_transfer_forced_exit_security_bundle_runtime::SecurityBundleReport>,
    authority_report: Option<&crate::monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::AuthorityTransferReport>,
) -> MutatedProbeCase {
    let baseline_root = transcript.claim_root.clone();
    let roots_only = claim_by_kind(claims, ClaimKind::RootsOnlyTranscript);
    let security_privacy = security_report.is_some_and(|report| {
        security_check_passed(report, SecurityBundleCheckKind::PrivacyFeePqSurfaceCovered)
    });
    let authority_privacy = authority_report.is_some_and(|report| {
        authority_check_passed(
            report,
            AuthorityTransferCheckKind::AuthorityPrivacySurfaceConsumesBundle,
        )
    });
    rejected_case(
        transcript,
        MutationKind::PrivacySurfaceLeakage,
        ExpectedRejection::PrivacySurfaceViolation,
        baseline_root,
        format!(
            "roots_only_claim={} security_privacy={security_privacy} authority_privacy={authority_privacy}",
            roots_only.is_some()
        ),
        "raw transfer details on a public fixture violate roots-only privacy surface",
        vec![
            "security_bundle.privacy_fee_pq_surface_covered".to_string(),
            "authority_adapter.authority_privacy_surface_consumes_bundle".to_string(),
        ],
        json!({
            "leakage_fixture": {
                "raw_amount": "redacted-in-valid-transcript",
                "raw_recipient": "redacted-in-valid-transcript",
                "claim_root": transcript.claim_root
            },
            "roots_only_claim": roots_only.map(ScenarioClaim::public_record),
        }),
        roots_only.is_some_and(|claim| claim.status == ClaimStatus::Proven)
            && security_privacy
            && authority_privacy,
    )
}

fn pq_control_plane_gap(
    transcript: &ScenarioTranscript,
    security_report: Option<&crate::monero_l2_pq_bridge_bound_transfer_forced_exit_security_bundle_runtime::SecurityBundleReport>,
    authority_report: Option<&crate::monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::AuthorityTransferReport>,
) -> MutatedProbeCase {
    let baseline_root = security_report
        .map(|report| report.state_root())
        .unwrap_or_else(|| transcript.transcript_root.clone());
    let security_control = security_report.is_some_and(|report| {
        security_check_passed(
            report,
            SecurityBundleCheckKind::WatcherSequencerAuthoritySeparation,
        ) && security_check_passed(report, SecurityBundleCheckKind::PrivacyFeePqSurfaceCovered)
    });
    let authority_control = authority_report.is_some_and(|report| {
        authority_check_passed(
            report,
            AuthorityTransferCheckKind::AuthorityPqControlPlaneConsumesBundle,
        )
    });
    rejected_case(
        transcript,
        MutationKind::PqControlPlaneGap,
        ExpectedRejection::PqControlPlaneViolation,
        baseline_root,
        format!("security_control={security_control} authority_control={authority_control}"),
        "removing PQ watcher/sequencer/authority separation invalidates withdrawal authorization",
        vec![
            "security_bundle.watcher_sequencer_authority_separation".to_string(),
            "authority_adapter.authority_pq_control_plane_consumes_bundle".to_string(),
        ],
        json!({
            "missing_surface": "pq_watcher_quorum_or_sequencer_authority_root",
            "transcript_root": transcript.transcript_root,
        }),
        security_control && authority_control,
    )
}

fn adversarial_coverage_gap(
    transcript: &ScenarioTranscript,
    security_report: Option<&crate::monero_l2_pq_bridge_bound_transfer_forced_exit_security_bundle_runtime::SecurityBundleReport>,
    authority_report: Option<&crate::monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::AuthorityTransferReport>,
) -> MutatedProbeCase {
    let baseline_root = security_report
        .map(|report| report.adversarial_matrix_root.clone())
        .unwrap_or_else(|| transcript.transcript_root.clone());
    let security_adversarial = security_report.is_some_and(|report| {
        security_check_passed(report, SecurityBundleCheckKind::AdversarialMatrixAccepted)
            && security_check_passed(report, SecurityBundleCheckKind::MoneroThreatCoveragePresent)
    });
    let authority_adversarial = authority_report.is_some_and(|report| {
        authority_check_passed(
            report,
            AuthorityTransferCheckKind::AdversarialThreatSurfaceInherited,
        )
    });
    rejected_case(
        transcript,
        MutationKind::AdversarialCoverageGap,
        ExpectedRejection::AdversarialCoverageViolation,
        baseline_root.clone(),
        format!(
            "security_adversarial={security_adversarial} authority_adversarial={authority_adversarial}"
        ),
        "missing Monero bridge adversarial coverage must block authority release",
        vec![
            "security_bundle.monero_threat_coverage_present".to_string(),
            "authority_adapter.adversarial_threat_surface_inherited".to_string(),
        ],
        json!({
            "missing_cases": [
                "weak_pq_watcher_quorum",
                "shallow_monero_finality",
                "metadata_linkage",
                "replay_nullifier",
                "open_challenge_blocks_settlement"
            ],
            "adversarial_matrix_root": baseline_root,
        }),
        security_adversarial && authority_adversarial,
    )
}

fn deferred_readiness_promotion(
    config: &Config,
    transcript: &ScenarioTranscript,
    security_report: Option<&crate::monero_l2_pq_bridge_bound_transfer_forced_exit_security_bundle_runtime::SecurityBundleReport>,
    authority_report: Option<&crate::monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::AuthorityTransferReport>,
) -> MutatedProbeCase {
    let baseline_root = authority_report
        .map(|report| report.state_root())
        .or_else(|| security_report.map(|report| report.state_root()))
        .unwrap_or_else(|| transcript.transcript_root.clone());
    let security_watch = security_report.is_some_and(|report| {
        report.status == SecurityBundleReportStatus::Watch
            && report.readiness_label.contains("deferred")
    });
    let authority_watch = authority_report.is_some_and(|report| {
        report.status == AuthorityTransferReportStatus::Watch
            && report.readiness_label.contains("deferred")
    });
    let deferred = config.cargo_checks_deferred || config.runtime_tests_deferred;
    rejected_case(
        transcript,
        MutationKind::DeferredReadinessPromotion,
        ExpectedRejection::DeferredReadinessCannotPromote,
        baseline_root,
        format!(
            "security_watch={security_watch} authority_watch={authority_watch} deferred={deferred}"
        ),
        "forged promotion to passed readiness is invalid while cargo/runtime checks are deferred",
        vec![
            "security_bundle.verified_readiness_classified".to_string(),
            "authority_adapter.watch_readiness_preserved".to_string(),
            "authority_adapter.release_gate_classified".to_string(),
        ],
        json!({
            "forged_status": "passed",
            "forged_readiness_label": "production_ready",
            "cargo_checks_deferred": config.cargo_checks_deferred,
            "runtime_tests_deferred": config.runtime_tests_deferred,
        }),
        deferred && security_watch && authority_watch,
    )
}

fn counter_drift(
    transcript: &ScenarioTranscript,
    scenario: &TransferForcedExitScenarioState,
    static_verifier: &TransferStaticVerifierState,
    security_bundle: &TransferSecurityBundleState,
    authority_adapter: &AuthorityTransferAdapterState,
) -> MutatedProbeCase {
    let baseline_root = transcript.state_root();
    let forged_step_count = transcript.step_count.saturating_add(1);
    let counters_ok = scenario.counters.steps_recorded == scenario.steps.len() as u64
        && static_verifier.counters.checks_failed == 0
        && security_bundle.counters.checks_failed == 0
        && authority_adapter.counters.checks_failed == 0;
    rejected_case(
        transcript,
        MutationKind::CounterDrift,
        ExpectedRejection::CounterContinuityViolation,
        baseline_root,
        format!(
            "forged_step_count={forged_step_count} real_step_count={} counters_ok={counters_ok}",
            transcript.step_count
        ),
        "counter drift between transcript and source collections invalidates the evidence bundle",
        vec![
            "security_bundle.counters_consistent".to_string(),
            "authority_adapter.counter_continuity".to_string(),
        ],
        json!({
            "forged_step_count": forged_step_count,
            "real_step_count": transcript.step_count,
            "scenario_counters": scenario.counters.public_record(),
            "static_counters": static_verifier.counters.public_record(),
            "security_counters": security_bundle.counters.public_record(),
            "authority_adapter_counters": authority_adapter.counters.public_record(),
        }),
        forged_step_count != transcript.step_count && counters_ok,
    )
}

fn rejected_case(
    transcript: &ScenarioTranscript,
    kind: MutationKind,
    expected_rejection: ExpectedRejection,
    baseline_root: String,
    observed: String,
    rejection_reason: &str,
    affected_checks: Vec<String>,
    public_fixture: Value,
    rejected: bool,
) -> MutatedProbeCase {
    MutatedProbeCase::new(
        kind,
        expected_rejection,
        if rejected {
            ProbeStatus::Rejected
        } else {
            ProbeStatus::Escaped
        },
        transcript.scenario_id.clone(),
        transcript.transcript_root.clone(),
        baseline_root,
        observed,
        rejection_reason.to_string(),
        affected_checks,
        public_fixture,
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

fn step_by_kind<'a>(steps: &'a [&'a ScenarioStep], kind: StepKind) -> Option<&'a ScenarioStep> {
    steps.iter().copied().find(|step| step.kind == kind)
}

fn claim_by_kind<'a>(
    claims: &'a [&'a ScenarioClaim],
    kind: ClaimKind,
) -> Option<&'a ScenarioClaim> {
    claims.iter().copied().find(|claim| claim.kind == kind)
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

fn security_check_passed(
    report: &crate::monero_l2_pq_bridge_bound_transfer_forced_exit_security_bundle_runtime::SecurityBundleReport,
    kind: SecurityBundleCheckKind,
) -> bool {
    report
        .checks
        .get(kind.as_str())
        .is_some_and(|check| check.status == SecurityBundleCheckStatus::Passed)
}

fn authority_check_passed(
    report: &crate::monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::AuthorityTransferReport,
    kind: AuthorityTransferCheckKind,
) -> bool {
    report.checks.get(kind.as_str()).is_some_and(|check| {
        matches!(
            check.status,
            AuthorityTransferCheckStatus::Passed | AuthorityTransferCheckStatus::Watch
        )
    })
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
    config: &Config,
    probes_rejected: u64,
    probes_escaped: u64,
) -> ProbeReportStatus {
    if probes_escaped > 0 {
        ProbeReportStatus::Failed
    } else if probes_rejected < config.min_rejected_probes
        || config.cargo_checks_deferred
        || config.runtime_tests_deferred
    {
        ProbeReportStatus::Watch
    } else {
        ProbeReportStatus::Passed
    }
}

fn readiness_label(status: ProbeReportStatus, config: &Config) -> &'static str {
    match status {
        ProbeReportStatus::Failed => "mutated_transcript_probe_escape_detected",
        ProbeReportStatus::Watch
            if config.cargo_checks_deferred || config.runtime_tests_deferred =>
        {
            "mutated_transcript_probes_recorded_runtime_execution_deferred"
        }
        ProbeReportStatus::Watch => "mutated_transcript_probes_watch_review_needed",
        ProbeReportStatus::Passed => "mutated_transcript_probes_rejected",
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

pub fn probe_report_id(scenario_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-MUTATED-PROBE-REPORT-ID",
        &[HashPart::Str(scenario_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn probe_id(scenario_id: &str, kind: MutationKind, mutation_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-MUTATED-PROBE-ID",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(mutation_root),
        ],
        32,
    )
}

pub fn mutation_root(
    scenario_id: &str,
    kind: MutationKind,
    expected_rejection: ExpectedRejection,
    baseline_root: &str,
    fixture: &Value,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-MUTATED-PROBE-MUTATION-ROOT",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(expected_rejection.as_str()),
            HashPart::Str(baseline_root),
            HashPart::Json(fixture),
        ],
        32,
    )
}

pub fn source_root(
    scenario_state_root: &str,
    static_verifier_root: &str,
    security_bundle_root: &str,
    authority_adapter_root: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-MUTATED-PROBE-SOURCE-ROOT",
        &[
            HashPart::Str(scenario_state_root),
            HashPart::Str(static_verifier_root),
            HashPart::Str(security_bundle_root),
            HashPart::Str(authority_adapter_root),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

pub fn report_root(
    status: ProbeReportStatus,
    readiness_label: &str,
    source_root: &str,
    case_root: &str,
    scenario_id: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-MUTATED-PROBE-REPORT-ROOT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(case_root),
            HashPart::Str(scenario_id),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-MUTATED-PROBE-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

pub fn tampered_root(root: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-MUTATED-PROBE-TAMPER",
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
