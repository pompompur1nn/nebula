use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_vertical_slice_scenario_runtime::{
        ClaimKind, ClaimStatus, ScenarioClaim, ScenarioStatus, ScenarioStep, ScenarioTranscript,
        State as ScenarioState, StepKind,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitTranscriptStaticVerifierRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_TRANSCRIPT_STATIC_VERIFIER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-transcript-static-verifier-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_TRANSCRIPT_STATIC_VERIFIER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const VERIFIER_SUITE: &str =
    "monero-l2-pq-bridge-exit-vertical-slice-transcript-static-checks-v1";
pub const DEFAULT_MIN_REQUIRED_STEPS: u64 = 10;
pub const DEFAULT_MIN_REQUIRED_CLAIMS: u64 = 7;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticCheckKind {
    TranscriptPresent,
    StepSequenceComplete,
    RequiredStepCoverage,
    TranscriptStepRootMatches,
    TranscriptClaimRootMatches,
    ScenarioStatusMatchesClaims,
    ForcedExitLivenessClaim,
    ChallengeSettlementOrdering,
    PostExitVerifierLinked,
    PrivacySurfaceRootsOnly,
    FinalSpineRootMatchesScenario,
    CountersConsistent,
}

impl StaticCheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TranscriptPresent => "transcript_present",
            Self::StepSequenceComplete => "step_sequence_complete",
            Self::RequiredStepCoverage => "required_step_coverage",
            Self::TranscriptStepRootMatches => "transcript_step_root_matches",
            Self::TranscriptClaimRootMatches => "transcript_claim_root_matches",
            Self::ScenarioStatusMatchesClaims => "scenario_status_matches_claims",
            Self::ForcedExitLivenessClaim => "forced_exit_liveness_claim",
            Self::ChallengeSettlementOrdering => "challenge_settlement_ordering",
            Self::PostExitVerifierLinked => "post_exit_verifier_linked",
            Self::PrivacySurfaceRootsOnly => "privacy_surface_roots_only",
            Self::FinalSpineRootMatchesScenario => "final_spine_root_matches_scenario",
            Self::CountersConsistent => "counters_consistent",
        }
    }

    pub fn all() -> [Self; 12] {
        [
            Self::TranscriptPresent,
            Self::StepSequenceComplete,
            Self::RequiredStepCoverage,
            Self::TranscriptStepRootMatches,
            Self::TranscriptClaimRootMatches,
            Self::ScenarioStatusMatchesClaims,
            Self::ForcedExitLivenessClaim,
            Self::ChallengeSettlementOrdering,
            Self::PostExitVerifierLinked,
            Self::PrivacySurfaceRootsOnly,
            Self::FinalSpineRootMatchesScenario,
            Self::CountersConsistent,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticCheckStatus {
    Passed,
    Watch,
    Failed,
}

impl StaticCheckStatus {
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
pub enum ReportStatus {
    Passed,
    Watch,
    Failed,
}

impl ReportStatus {
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
    pub verifier_suite: String,
    pub min_required_steps: u64,
    pub min_required_claims: u64,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            verifier_suite: VERIFIER_SUITE.to_string(),
            min_required_steps: DEFAULT_MIN_REQUIRED_STEPS,
            min_required_claims: DEFAULT_MIN_REQUIRED_CLAIMS,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "verifier_suite": self.verifier_suite,
            "min_required_steps": self.min_required_steps,
            "min_required_claims": self.min_required_claims,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-TRANSCRIPT-STATIC-VERIFIER-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StaticCheckEvidence {
    pub check_id: String,
    pub kind: StaticCheckKind,
    pub status: StaticCheckStatus,
    pub requirement: String,
    pub observed: String,
    pub evidence_root: String,
    pub remediation: String,
}

impl StaticCheckEvidence {
    pub fn new(
        scenario_id: &str,
        kind: StaticCheckKind,
        status: StaticCheckStatus,
        requirement: impl Into<String>,
        observed: impl Into<String>,
        evidence_root: String,
        remediation: impl Into<String>,
    ) -> Self {
        let check_id = static_check_id(scenario_id, kind, &evidence_root);
        Self {
            check_id,
            kind,
            status,
            requirement: requirement.into(),
            observed: observed.into(),
            evidence_root,
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
            "remediation": self.remediation,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("static_check", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StaticReport {
    pub report_id: String,
    pub scenario_id: String,
    pub scenario_state_root: String,
    pub scenario_transcript_root: String,
    pub status: ReportStatus,
    pub checks: BTreeMap<String, StaticCheckEvidence>,
    pub passed_checks: u64,
    pub watch_checks: u64,
    pub failed_checks: u64,
    pub recomputed_step_root: String,
    pub recomputed_claim_root: String,
    pub roots: ReportRoots,
}

impl StaticReport {
    pub fn public_record(&self) -> Value {
        let checks = self
            .checks
            .values()
            .map(StaticCheckEvidence::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "scenario_id": self.scenario_id,
            "scenario_state_root": self.scenario_state_root,
            "scenario_transcript_root": self.scenario_transcript_root,
            "status": self.status.as_str(),
            "checks": checks,
            "passed_checks": self.passed_checks,
            "watch_checks": self.watch_checks,
            "failed_checks": self.failed_checks,
            "recomputed_step_root": self.recomputed_step_root,
            "recomputed_claim_root": self.recomputed_claim_root,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReportRoots {
    pub check_root: String,
    pub scenario_state_root: String,
    pub scenario_transcript_root: String,
    pub report_root: String,
}

impl ReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "check_root": self.check_root,
            "scenario_state_root": self.scenario_state_root,
            "scenario_transcript_root": self.scenario_transcript_root,
            "report_root": self.report_root,
        })
    }

    pub fn compute_report_root(
        scenario_id: &str,
        status: ReportStatus,
        check_root: &str,
        scenario_state_root: &str,
        scenario_transcript_root: &str,
    ) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-TRANSCRIPT-STATIC-VERIFIER-REPORT",
            &[
                HashPart::Str(scenario_id),
                HashPart::Str(status.as_str()),
                HashPart::Str(check_root),
                HashPart::Str(scenario_state_root),
                HashPart::Str(scenario_transcript_root),
            ],
            32,
        )
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
    pub transcripts_verified: u64,
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
            "transcripts_verified": self.transcripts_verified,
            "root_mismatches": self.root_mismatches,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("static_verifier_counters", &self.public_record())
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
                "MONERO-L2-PQ-BRIDGE-EXIT-TRANSCRIPT-STATIC-VERIFIER-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-TRANSCRIPT-STATIC-VERIFIER-ROOTS",
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
    pub latest_report: Option<StaticReport>,
    pub report_history: Vec<StaticReport>,
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
        let scenario_state =
            crate::monero_l2_pq_bridge_exit_vertical_slice_scenario_runtime::devnet();
        state
            .verify_scenario_state(&scenario_state)
            .expect("devnet bridge/exit transcript static verification");
        state
    }

    pub fn verify_scenario_state(&mut self, scenario: &ScenarioState) -> Result<String> {
        let transcript = scenario
            .transcripts
            .values()
            .next_back()
            .ok_or_else(|| "scenario state has no transcript to verify".to_string())?;
        let scenario_id = transcript.scenario_id.clone();
        let steps = scenario_steps(scenario, &scenario_id);
        let claims = scenario_claims(scenario, &scenario_id);
        let recomputed_step_root = recompute_step_root(&steps);
        let recomputed_claim_root = recompute_claim_root(&claims);
        let mut checks = BTreeMap::new();

        for check in evaluate_static_checks(
            &self.config,
            scenario,
            transcript,
            &steps,
            &claims,
            &recomputed_step_root,
            &recomputed_claim_root,
        ) {
            checks.insert(check.kind.as_str().to_string(), check);
        }
        ensure(
            StaticCheckKind::all()
                .iter()
                .all(|kind| checks.contains_key(kind.as_str())),
            "static verifier omitted a required bridge/exit transcript check",
        )?;

        let passed_checks = checks
            .values()
            .filter(|check| check.status == StaticCheckStatus::Passed)
            .count() as u64;
        let watch_checks = checks
            .values()
            .filter(|check| check.status == StaticCheckStatus::Watch)
            .count() as u64;
        let failed_checks = checks
            .values()
            .filter(|check| check.status == StaticCheckStatus::Failed)
            .count() as u64;
        let status = aggregate_report_status(&checks);
        let check_records = checks
            .values()
            .map(StaticCheckEvidence::public_record)
            .collect::<Vec<_>>();
        let check_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-TRANSCRIPT-STATIC-VERIFIER-CHECKS",
            &check_records,
        );
        let scenario_state_root = scenario.state_root();
        let scenario_transcript_root = transcript.transcript_root.clone();
        let report_root = ReportRoots::compute_report_root(
            &scenario_id,
            status,
            &check_root,
            &scenario_state_root,
            &scenario_transcript_root,
        );
        let roots = ReportRoots {
            check_root,
            scenario_state_root,
            scenario_transcript_root,
            report_root,
        };
        let report_id = static_report_id(&scenario_id, &roots.report_root);
        let report = StaticReport {
            report_id: report_id.clone(),
            scenario_id,
            scenario_state_root: roots.scenario_state_root.clone(),
            scenario_transcript_root: roots.scenario_transcript_root.clone(),
            status,
            checks,
            passed_checks,
            watch_checks,
            failed_checks,
            recomputed_step_root,
            recomputed_claim_root,
            roots,
        };
        self.record_report(report);
        Ok(report_id)
    }

    fn record_report(&mut self, report: StaticReport) {
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
                    matches!(
                        check.kind,
                        StaticCheckKind::TranscriptStepRootMatches
                            | StaticCheckKind::TranscriptClaimRootMatches
                            | StaticCheckKind::FinalSpineRootMatchesScenario
                    ) && check.status == StaticCheckStatus::Failed
                })
                .count() as u64;
        }
        match report.status {
            ReportStatus::Passed => {
                self.counters.reports_passed += 1;
                self.counters.transcripts_verified += 1;
            }
            ReportStatus::Watch => self.counters.reports_watch += 1,
            ReportStatus::Failed => self.counters.reports_failed += 1,
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
            .map(StaticReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-TRANSCRIPT-STATIC-VERIFIER-REPORTS",
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
            "verifier_suite": self.config.verifier_suite,
            "latest_report": self.latest_report.as_ref().map(StaticReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }
}

pub fn evaluate_static_checks(
    config: &Config,
    scenario: &ScenarioState,
    transcript: &ScenarioTranscript,
    steps: &[&ScenarioStep],
    claims: &[&ScenarioClaim],
    recomputed_step_root: &str,
    recomputed_claim_root: &str,
) -> Vec<StaticCheckEvidence> {
    vec![
        transcript_present(transcript, steps, claims),
        step_sequence_complete(config, transcript, steps),
        required_step_coverage(transcript, steps),
        transcript_step_root_matches(transcript, recomputed_step_root),
        transcript_claim_root_matches(transcript, recomputed_claim_root),
        scenario_status_matches_claims(config, transcript, claims),
        forced_exit_liveness_claim(transcript, claims),
        challenge_settlement_ordering(transcript, steps),
        post_exit_verifier_linked(scenario, transcript, steps),
        privacy_surface_roots_only(scenario, transcript, steps, claims),
        final_spine_root_matches_scenario(scenario, transcript),
        counters_consistent(scenario, transcript, steps, claims),
    ]
}

fn transcript_present(
    transcript: &ScenarioTranscript,
    steps: &[&ScenarioStep],
    claims: &[&ScenarioClaim],
) -> StaticCheckEvidence {
    let ok = !transcript.scenario_id.is_empty() && !steps.is_empty() && !claims.is_empty();
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::TranscriptPresent,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "scenario must expose one transcript with step and claim evidence",
        format!(
            "scenario_id_present={}, steps={}, claims={}",
            !transcript.scenario_id.is_empty(),
            steps.len(),
            claims.len()
        ),
        evidence_root(
            &transcript.scenario_id,
            "transcript-present",
            &json!({"steps": steps.len(), "claims": claims.len()}),
        ),
        "rerun the vertical-slice scenario before verifying release evidence",
    )
}

fn step_sequence_complete(
    config: &Config,
    transcript: &ScenarioTranscript,
    steps: &[&ScenarioStep],
) -> StaticCheckEvidence {
    let mut sequence = steps.iter().map(|step| step.sequence).collect::<Vec<_>>();
    sequence.sort_unstable();
    let monotonic = sequence
        .iter()
        .enumerate()
        .all(|(index, value)| *value == index as u64 + 1);
    let ok = monotonic
        && transcript.step_count == steps.len() as u64
        && transcript.step_count >= config.min_required_steps;
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::StepSequenceComplete,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "vertical slice steps must be contiguous and match transcript count",
        format!(
            "monotonic={}, transcript_step_count={}, actual_steps={}, min_required={}",
            monotonic,
            transcript.step_count,
            steps.len(),
            config.min_required_steps
        ),
        evidence_root(
            &transcript.scenario_id,
            "step-sequence-complete",
            &json!({"sequence": sequence, "transcript_step_count": transcript.step_count}),
        ),
        "rebuild the scenario transcript after any step insertion or removal",
    )
}

fn required_step_coverage(
    transcript: &ScenarioTranscript,
    steps: &[&ScenarioStep],
) -> StaticCheckEvidence {
    let required = required_steps();
    let observed = steps.iter().map(|step| step.kind).collect::<BTreeSet<_>>();
    let missing = required
        .iter()
        .filter(|kind| !observed.contains(kind))
        .map(|kind| kind.as_str())
        .collect::<Vec<_>>();
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::RequiredStepCoverage,
        if missing.is_empty() {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "transcript must cover deposit, private action, forced exit, challenge, settlement, and verifier steps",
        format!("missing_required_steps={}", missing.join(",")),
        evidence_root(
            &transcript.scenario_id,
            "required-step-coverage",
            &json!({"missing": missing, "observed": observed.iter().map(|kind| kind.as_str()).collect::<Vec<_>>()}),
        ),
        "rerun the scenario with the missing bridge/exit step before claiming vertical-slice coverage",
    )
}

fn transcript_step_root_matches(
    transcript: &ScenarioTranscript,
    recomputed_step_root: &str,
) -> StaticCheckEvidence {
    let ok = transcript.step_root == recomputed_step_root;
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::TranscriptStepRootMatches,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "transcript step root must match recomputed step records",
        format!(
            "transcript_step_root={}, recomputed_step_root={}",
            transcript.step_root, recomputed_step_root
        ),
        evidence_root(
            &transcript.scenario_id,
            "transcript-step-root-matches",
            &json!({"transcript": transcript.step_root, "recomputed": recomputed_step_root}),
        ),
        "recompute transcript roots from canonical step records",
    )
}

fn transcript_claim_root_matches(
    transcript: &ScenarioTranscript,
    recomputed_claim_root: &str,
) -> StaticCheckEvidence {
    let ok = transcript.claim_root == recomputed_claim_root;
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::TranscriptClaimRootMatches,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "transcript claim root must match recomputed claim records",
        format!(
            "transcript_claim_root={}, recomputed_claim_root={}",
            transcript.claim_root, recomputed_claim_root
        ),
        evidence_root(
            &transcript.scenario_id,
            "transcript-claim-root-matches",
            &json!({"transcript": transcript.claim_root, "recomputed": recomputed_claim_root}),
        ),
        "recompute transcript roots from canonical claim records",
    )
}

fn scenario_status_matches_claims(
    config: &Config,
    transcript: &ScenarioTranscript,
    claims: &[&ScenarioClaim],
) -> StaticCheckEvidence {
    let proven = claims
        .iter()
        .filter(|claim| claim.status == ClaimStatus::Proven)
        .count() as u64;
    let watch = claims
        .iter()
        .filter(|claim| claim.status == ClaimStatus::Watch)
        .count() as u64;
    let failed = claims
        .iter()
        .filter(|claim| claim.status == ClaimStatus::Failed)
        .count() as u64;
    let status_matches = transcript.proven_claim_count == proven
        && transcript.watch_claim_count == watch
        && transcript.failed_claim_count == failed;
    let outcome_matches = if failed > 0 {
        transcript.status == ScenarioStatus::Failed
    } else if proven >= config.min_required_claims {
        matches!(
            transcript.status,
            ScenarioStatus::Proven | ScenarioStatus::Watch
        )
    } else {
        transcript.status == ScenarioStatus::Watch
    };
    let ok = status_matches && outcome_matches;
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::ScenarioStatusMatchesClaims,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "scenario status and claim counts must agree with canonical claim records",
        format!(
            "status_matches={}, outcome_matches={}, proven={}, watch={}, failed={}",
            status_matches, outcome_matches, proven, watch, failed
        ),
        evidence_root(
            &transcript.scenario_id,
            "scenario-status-matches-claims",
            &json!({
                "transcript_proven": transcript.proven_claim_count,
                "transcript_watch": transcript.watch_claim_count,
                "transcript_failed": transcript.failed_claim_count,
                "actual_proven": proven,
                "actual_watch": watch,
                "actual_failed": failed,
            }),
        ),
        "correct claim counts or downgrade the scenario status before release gating",
    )
}

fn forced_exit_liveness_claim(
    transcript: &ScenarioTranscript,
    claims: &[&ScenarioClaim],
) -> StaticCheckEvidence {
    let claim = claims
        .iter()
        .find(|claim| claim.kind == ClaimKind::AlwaysAvailableForcedExit);
    let ok = !transcript.forced_exit_available_before_timeout
        && transcript.forced_exit_available_after_timeout
        && claim.map(|claim| claim.status.passes()).unwrap_or(false);
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::ForcedExitLivenessClaim,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "forced exit must become available after liveness timeout and have a passing claim",
        format!(
            "before_timeout={}, after_timeout={}, claim_present={}, claim_status={}",
            transcript.forced_exit_available_before_timeout,
            transcript.forced_exit_available_after_timeout,
            claim.is_some(),
            claim
                .map(|claim| claim.status.as_str())
                .unwrap_or("missing")
        ),
        evidence_root(
            &transcript.scenario_id,
            "forced-exit-liveness-claim",
            &json!({
                "before_timeout": transcript.forced_exit_available_before_timeout,
                "after_timeout": transcript.forced_exit_available_after_timeout,
                "claim_status": claim.map(|claim| claim.status.as_str()),
            }),
        ),
        "do not count the scenario as exit-safe until timeout and liveness claim agree",
    )
}

fn challenge_settlement_ordering(
    transcript: &ScenarioTranscript,
    steps: &[&ScenarioStep],
) -> StaticCheckEvidence {
    let opened = step_by_kind(steps, StepKind::ChallengeOpened);
    let resolved = step_by_kind(steps, StepKind::ChallengeResolved);
    let settled = step_by_kind(steps, StepKind::ExitSettled);
    let ok = match (opened, resolved, settled) {
        (Some(opened), Some(resolved), Some(settled)) => {
            opened.height <= resolved.height
                && resolved.height <= settled.height
                && settled.challenge_id.as_ref() == Some(&transcript.challenge_id)
                && settled.settlement_id.as_ref() == Some(&transcript.settlement_id)
        }
        _ => false,
    };
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::ChallengeSettlementOrdering,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "settlement must happen after challenge opening and resolution for adversarial exit paths",
        format!(
            "opened_height={:?}, resolved_height={:?}, settled_height={:?}",
            opened.map(|step| step.height),
            resolved.map(|step| step.height),
            settled.map(|step| step.height)
        ),
        evidence_root(
            &transcript.scenario_id,
            "challenge-settlement-ordering",
            &json!({
                "opened_height": opened.map(|step| step.height),
                "resolved_height": resolved.map(|step| step.height),
                "settled_height": settled.map(|step| step.height),
                "challenge_id": transcript.challenge_id,
                "settlement_id": transcript.settlement_id,
            }),
        ),
        "block settlement until challenge windows are resolved or expired with rooted evidence",
    )
}

fn post_exit_verifier_linked(
    scenario: &ScenarioState,
    transcript: &ScenarioTranscript,
    steps: &[&ScenarioStep],
) -> StaticCheckEvidence {
    let post_step = step_by_kind(steps, StepKind::PostExitAssessed);
    let latest_assessment = scenario
        .verifier
        .latest_assessment
        .as_ref()
        .map(|assessment| assessment.assessment_id.as_str());
    let ok = post_step
        .and_then(|step| step.assessment_id.as_ref())
        .map(|assessment_id| assessment_id == &transcript.post_exit_assessment_id)
        .unwrap_or(false)
        && latest_assessment == Some(transcript.post_exit_assessment_id.as_str());
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::PostExitVerifierLinked,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "post-exit assessment id must link transcript, assessment step, and verifier latest assessment",
        format!(
            "post_step_assessment={:?}, transcript_post_assessment={}, latest_assessment={:?}",
            post_step.and_then(|step| step.assessment_id.as_ref()),
            transcript.post_exit_assessment_id,
            latest_assessment
        ),
        evidence_root(
            &transcript.scenario_id,
            "post-exit-verifier-linked",
            &json!({
                "post_step_assessment": post_step.and_then(|step| step.assessment_id.as_ref()),
                "transcript_post_assessment": transcript.post_exit_assessment_id,
                "latest_assessment": latest_assessment,
            }),
        ),
        "rerun invariant assessment after exit settlement and update transcript linkage",
    )
}

fn privacy_surface_roots_only(
    scenario: &ScenarioState,
    transcript: &ScenarioTranscript,
    steps: &[&ScenarioStep],
    claims: &[&ScenarioClaim],
) -> StaticCheckEvidence {
    let claim = claims
        .iter()
        .find(|claim| claim.kind == ClaimKind::RootsOnlyPrivacyDisclosure);
    let empty_roots = steps
        .iter()
        .filter(|step| step.private_input_root.is_empty() || step.public_evidence_root.is_empty())
        .count();
    let privacy_floor_met =
        transcript.privacy_set_size_observed >= scenario.spine.config.min_privacy_set_size;
    let ok = empty_roots == 0
        && privacy_floor_met
        && claim.map(|claim| claim.status.passes()).unwrap_or(false);
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::PrivacySurfaceRootsOnly,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "public transcript should expose commitments and roots while preserving privacy-set floor",
        format!(
            "empty_roots={}, privacy_floor_met={}, claim_present={}, claim_status={}",
            empty_roots,
            privacy_floor_met,
            claim.is_some(),
            claim
                .map(|claim| claim.status.as_str())
                .unwrap_or("missing")
        ),
        evidence_root(
            &transcript.scenario_id,
            "privacy-surface-roots-only",
            &json!({
                "empty_roots": empty_roots,
                "privacy_set_size": transcript.privacy_set_size_observed,
                "min_privacy_set_size": scenario.spine.config.min_privacy_set_size,
                "claim_status": claim.map(|claim| claim.status.as_str()),
            }),
        ),
        "suppress or re-root transcript records that expose plaintext wallet metadata",
    )
}

fn final_spine_root_matches_scenario(
    scenario: &ScenarioState,
    transcript: &ScenarioTranscript,
) -> StaticCheckEvidence {
    let actual_spine_root = scenario.spine.state_root();
    let ok = transcript.final_spine_root == actual_spine_root
        && scenario.roots.spine_root == actual_spine_root;
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::FinalSpineRootMatchesScenario,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "transcript final spine root must match the scenario state spine root",
        format!(
            "transcript_final={}, scenario_root={}, actual_spine={}",
            transcript.final_spine_root, scenario.roots.spine_root, actual_spine_root
        ),
        evidence_root(
            &transcript.scenario_id,
            "final-spine-root-matches-scenario",
            &json!({
                "transcript_final": transcript.final_spine_root,
                "scenario_root": scenario.roots.spine_root,
                "actual_spine": actual_spine_root,
            }),
        ),
        "recompute scenario roots after the exit path settles",
    )
}

fn counters_consistent(
    scenario: &ScenarioState,
    transcript: &ScenarioTranscript,
    steps: &[&ScenarioStep],
    claims: &[&ScenarioClaim],
) -> StaticCheckEvidence {
    let ok = scenario.counters.steps_recorded == steps.len() as u64
        && scenario.counters.claims_recorded == claims.len() as u64
        && scenario.counters.exits_settled >= 1
        && scenario.counters.verifier_assessments_run >= 2
        && transcript.step_count == steps.len() as u64;
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::CountersConsistent,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "scenario counters must agree with canonical transcript records",
        format!(
            "steps_recorded={}, actual_steps={}, claims_recorded={}, actual_claims={}, exits_settled={}, verifier_assessments={}",
            scenario.counters.steps_recorded,
            steps.len(),
            scenario.counters.claims_recorded,
            claims.len(),
            scenario.counters.exits_settled,
            scenario.counters.verifier_assessments_run
        ),
        evidence_root(
            &transcript.scenario_id,
            "counters-consistent",
            &json!({
                "steps_recorded": scenario.counters.steps_recorded,
                "actual_steps": steps.len(),
                "claims_recorded": scenario.counters.claims_recorded,
                "actual_claims": claims.len(),
                "exits_settled": scenario.counters.exits_settled,
                "verifier_assessments": scenario.counters.verifier_assessments_run,
            }),
        ),
        "rebuild counters from transcript records before publishing operator summaries",
    )
}

fn aggregate_report_status(checks: &BTreeMap<String, StaticCheckEvidence>) -> ReportStatus {
    if checks
        .values()
        .any(|check| check.status == StaticCheckStatus::Failed)
    {
        ReportStatus::Failed
    } else if checks
        .values()
        .any(|check| check.status == StaticCheckStatus::Watch)
    {
        ReportStatus::Watch
    } else {
        ReportStatus::Passed
    }
}

fn scenario_steps<'a>(scenario: &'a ScenarioState, scenario_id: &str) -> Vec<&'a ScenarioStep> {
    let mut steps = scenario
        .steps
        .iter()
        .filter(|step| step.scenario_id == scenario_id)
        .collect::<Vec<_>>();
    steps.sort_by_key(|step| step.sequence);
    steps
}

fn scenario_claims<'a>(scenario: &'a ScenarioState, scenario_id: &str) -> Vec<&'a ScenarioClaim> {
    scenario
        .claims
        .values()
        .filter(|claim| claim.scenario_id == scenario_id)
        .collect::<Vec<_>>()
}

fn recompute_step_root(steps: &[&ScenarioStep]) -> String {
    let records = steps
        .iter()
        .map(|step| step.public_record())
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-SCENARIO-STEPS",
        &records,
    )
}

fn recompute_claim_root(claims: &[&ScenarioClaim]) -> String {
    let records = claims
        .iter()
        .map(|claim| claim.public_record())
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-VERTICAL-SLICE-SCENARIO-CLAIMS",
        &records,
    )
}

fn step_by_kind<'a>(steps: &'a [&'a ScenarioStep], kind: StepKind) -> Option<&'a ScenarioStep> {
    steps.iter().copied().find(|step| step.kind == kind)
}

fn required_steps() -> BTreeSet<StepKind> {
    [
        StepKind::SpineBaselineAssessed,
        StepKind::DepositLockOpened,
        StepKind::DepositCertified,
        StepKind::PrivateNoteMinted,
        StepKind::PrivateActionRecorded,
        StepKind::SettlementReceiptAnchored,
        StepKind::ForcedExitRequested,
        StepKind::LivenessTimeoutObserved,
        StepKind::ForcedExitArmed,
        StepKind::ChallengeOpened,
        StepKind::ChallengeResolved,
        StepKind::ExitSettled,
        StepKind::PostExitAssessed,
    ]
    .into_iter()
    .collect()
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

pub fn static_report_id(scenario_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-TRANSCRIPT-STATIC-VERIFIER-REPORT-ID",
        &[HashPart::Str(scenario_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn static_check_id(scenario_id: &str, kind: StaticCheckKind, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-TRANSCRIPT-STATIC-VERIFIER-CHECK-ID",
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
        "MONERO-L2-PQ-BRIDGE-EXIT-TRANSCRIPT-STATIC-VERIFIER-EVIDENCE",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-TRANSCRIPT-STATIC-VERIFIER-RECORD",
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
