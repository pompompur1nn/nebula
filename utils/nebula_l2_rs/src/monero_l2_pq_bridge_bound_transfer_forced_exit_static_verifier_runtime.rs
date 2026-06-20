use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_bound_transfer_forced_exit_scenario_runtime::{
        ClaimKind, ClaimStatus, ScenarioClaim, ScenarioStatus, ScenarioStep, ScenarioTranscript,
        State as TransferForcedExitScenarioState, StepKind,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeBoundTransferForcedExitStaticVerifierRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_BOUND_TRANSFER_FORCED_EXIT_STATIC_VERIFIER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-bound-transfer-forced-exit-static-verifier-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_BOUND_TRANSFER_FORCED_EXIT_STATIC_VERIFIER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const VERIFIER_SUITE: &str =
    "monero-l2-pq-bridge-bound-transfer-forced-exit-transcript-static-checks-v1";
pub const DEFAULT_MIN_REQUIRED_STEPS: u64 = 12;
pub const DEFAULT_MIN_REQUIRED_CLAIMS: u64 = 8;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticCheckKind {
    TranscriptPresent,
    PreSealStepRootMatches,
    ClaimRootMatches,
    RequiredStepCoverage,
    TransferToExitOrdering,
    SealStepAfterTranscript,
    TransferReceiptClaimCoverage,
    ForcedExitClaimConsumed,
    ChallengeSettlementOrdering,
    FinalRootsMatchScenario,
    PrivacyFeePqSurface,
    CountersConsistent,
}

impl StaticCheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TranscriptPresent => "transcript_present",
            Self::PreSealStepRootMatches => "pre_seal_step_root_matches",
            Self::ClaimRootMatches => "claim_root_matches",
            Self::RequiredStepCoverage => "required_step_coverage",
            Self::TransferToExitOrdering => "transfer_to_exit_ordering",
            Self::SealStepAfterTranscript => "seal_step_after_transcript",
            Self::TransferReceiptClaimCoverage => "transfer_receipt_claim_coverage",
            Self::ForcedExitClaimConsumed => "forced_exit_claim_consumed",
            Self::ChallengeSettlementOrdering => "challenge_settlement_ordering",
            Self::FinalRootsMatchScenario => "final_roots_match_scenario",
            Self::PrivacyFeePqSurface => "privacy_fee_pq_surface",
            Self::CountersConsistent => "counters_consistent",
        }
    }

    pub fn all() -> [Self; 12] {
        [
            Self::TranscriptPresent,
            Self::PreSealStepRootMatches,
            Self::ClaimRootMatches,
            Self::RequiredStepCoverage,
            Self::TransferToExitOrdering,
            Self::SealStepAfterTranscript,
            Self::TransferReceiptClaimCoverage,
            Self::ForcedExitClaimConsumed,
            Self::ChallengeSettlementOrdering,
            Self::FinalRootsMatchScenario,
            Self::PrivacyFeePqSurface,
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
        record_root("config", &self.public_record())
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
        evidence_record: Value,
        remediation: impl Into<String>,
    ) -> Self {
        let evidence_root = evidence_root(scenario_id, kind.as_str(), &evidence_record);
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
    pub transcript_root: String,
    pub status: ReportStatus,
    pub checks: BTreeMap<String, StaticCheckEvidence>,
    pub passed_checks: u64,
    pub watch_checks: u64,
    pub failed_checks: u64,
    pub recomputed_pre_seal_step_root: String,
    pub recomputed_claim_root: String,
    pub final_spine_root: String,
    pub final_transfer_runtime_root: String,
    pub report_root: String,
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
            "transcript_root": self.transcript_root,
            "status": self.status.as_str(),
            "checks": checks,
            "passed_checks": self.passed_checks,
            "watch_checks": self.watch_checks,
            "failed_checks": self.failed_checks,
            "recomputed_pre_seal_step_root": self.recomputed_pre_seal_step_root,
            "recomputed_claim_root": self.recomputed_claim_root,
            "final_spine_root": self.final_spine_root,
            "final_transfer_runtime_root": self.final_transfer_runtime_root,
            "report_root": self.report_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("static_report", &self.public_record())
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
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-STATIC-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-STATIC-VERIFIER-STATE",
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
        let mut state = Self {
            roots: Roots::empty(&config, &counters),
            config,
            latest_report: None,
            report_history: Vec::new(),
            counters,
        };
        let scenario_state =
            crate::monero_l2_pq_bridge_bound_transfer_forced_exit_scenario_runtime::devnet();
        state
            .verify_scenario_state(&scenario_state)
            .expect("devnet bridge-bound transfer forced-exit static verification");
        state
    }

    pub fn verify_scenario_state(
        &mut self,
        scenario: &TransferForcedExitScenarioState,
    ) -> Result<String> {
        let transcript = scenario
            .transcripts
            .values()
            .next_back()
            .ok_or_else(|| "scenario state has no transcript to verify".to_string())?;
        let scenario_id = transcript.scenario_id.clone();
        let pre_seal_steps = pre_seal_steps(scenario, &scenario_id);
        let seal_steps = seal_steps(scenario, &scenario_id);
        let claims = scenario_claims(scenario, &scenario_id);
        let recomputed_step_root = recompute_step_root(&pre_seal_steps);
        let recomputed_claim_root = recompute_claim_root(&claims);
        let mut checks = BTreeMap::new();

        for check in evaluate_static_checks(
            &self.config,
            scenario,
            transcript,
            &pre_seal_steps,
            &seal_steps,
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
            "static verifier omitted a bridge-bound transfer forced-exit check",
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
            "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-STATIC-CHECKS",
            &check_records,
        );
        let scenario_state_root = scenario.state_root();
        let report_root = report_root(
            &scenario_id,
            status,
            &check_root,
            &scenario_state_root,
            &transcript.transcript_root,
            &recomputed_step_root,
            &recomputed_claim_root,
        );
        let report_id = static_report_id(&scenario_id, &report_root);
        let report = StaticReport {
            report_id: report_id.clone(),
            scenario_id,
            scenario_state_root,
            transcript_root: transcript.transcript_root.clone(),
            status,
            checks,
            passed_checks,
            watch_checks,
            failed_checks,
            recomputed_pre_seal_step_root: recomputed_step_root,
            recomputed_claim_root,
            final_spine_root: transcript.final_spine_root.clone(),
            final_transfer_runtime_root: transcript.final_transfer_runtime_root.clone(),
            report_root,
        };
        self.record_report(report);
        Ok(report_id)
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
                        StaticCheckKind::PreSealStepRootMatches
                            | StaticCheckKind::ClaimRootMatches
                            | StaticCheckKind::FinalRootsMatchScenario
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
                "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-STATIC-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

pub fn evaluate_static_checks(
    config: &Config,
    scenario: &TransferForcedExitScenarioState,
    transcript: &ScenarioTranscript,
    pre_seal_steps: &[&ScenarioStep],
    seal_steps: &[&ScenarioStep],
    claims: &[&ScenarioClaim],
    recomputed_step_root: &str,
    recomputed_claim_root: &str,
) -> Vec<StaticCheckEvidence> {
    vec![
        transcript_present(transcript, pre_seal_steps, claims),
        pre_seal_step_root_matches(transcript, recomputed_step_root),
        claim_root_matches(transcript, recomputed_claim_root),
        required_step_coverage(config, transcript, pre_seal_steps),
        transfer_to_exit_ordering(transcript, pre_seal_steps),
        seal_step_after_transcript(transcript, pre_seal_steps, seal_steps),
        transfer_receipt_claim_coverage(transcript, claims),
        forced_exit_claim_consumed(transcript, pre_seal_steps, claims),
        challenge_settlement_ordering(transcript, pre_seal_steps),
        final_roots_match_scenario(scenario, transcript),
        privacy_fee_pq_surface(config, transcript, claims),
        counters_consistent(
            config,
            scenario,
            transcript,
            pre_seal_steps,
            seal_steps,
            claims,
        ),
    ]
}

fn transcript_present(
    transcript: &ScenarioTranscript,
    pre_seal_steps: &[&ScenarioStep],
    claims: &[&ScenarioClaim],
) -> StaticCheckEvidence {
    let ok = !transcript.scenario_id.is_empty()
        && !transcript.transcript_root.is_empty()
        && !pre_seal_steps.is_empty()
        && !claims.is_empty();
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::TranscriptPresent,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "scenario must expose a transcript, pre-seal steps, and claims",
        format!(
            "transcript_root_present={}, pre_seal_steps={}, claims={}",
            !transcript.transcript_root.is_empty(),
            pre_seal_steps.len(),
            claims.len()
        ),
        json!({
            "transcript_id": transcript.transcript_id,
            "pre_seal_steps": pre_seal_steps.len(),
            "claims": claims.len(),
        }),
        "rerun the bridge-bound transfer forced-exit scenario before verification",
    )
}

fn pre_seal_step_root_matches(
    transcript: &ScenarioTranscript,
    recomputed_step_root: &str,
) -> StaticCheckEvidence {
    let ok = transcript.step_root == recomputed_step_root;
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::PreSealStepRootMatches,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "transcript step root must match recomputed pre-seal step records",
        format!(
            "transcript_step_root={}, recomputed_step_root={}",
            transcript.step_root, recomputed_step_root
        ),
        json!({
            "transcript_step_root": transcript.step_root,
            "recomputed_step_root": recomputed_step_root,
        }),
        "recompute transcript roots from canonical pre-seal scenario steps",
    )
}

fn claim_root_matches(
    transcript: &ScenarioTranscript,
    recomputed_claim_root: &str,
) -> StaticCheckEvidence {
    let ok = transcript.claim_root == recomputed_claim_root;
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::ClaimRootMatches,
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
        json!({
            "transcript_claim_root": transcript.claim_root,
            "recomputed_claim_root": recomputed_claim_root,
        }),
        "recompute claim root from canonical bridge-bound transfer forced-exit claims",
    )
}

fn required_step_coverage(
    config: &Config,
    transcript: &ScenarioTranscript,
    steps: &[&ScenarioStep],
) -> StaticCheckEvidence {
    let observed = steps.iter().map(|step| step.kind).collect::<BTreeSet<_>>();
    let required = required_pre_seal_steps();
    let missing = required
        .iter()
        .filter(|kind| !observed.contains(kind))
        .map(|kind| kind.as_str())
        .collect::<Vec<_>>();
    let ok = missing.is_empty()
        && transcript.step_count == steps.len() as u64
        && transcript.step_count >= config.min_required_steps;
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::RequiredStepCoverage,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "transcript must cover bridge source, transfer receipt, forced exit, challenge, and settlement steps",
        format!(
            "missing={:?}, transcript_steps={}, actual_pre_seal_steps={}, min_required={}",
            missing,
            transcript.step_count,
            steps.len(),
            config.min_required_steps
        ),
        json!({
            "missing": missing,
            "transcript_step_count": transcript.step_count,
            "actual_pre_seal_steps": steps.len(),
        }),
        "rebuild the scenario with every bridge-bound transfer forced-exit step before sealing",
    )
}

fn transfer_to_exit_ordering(
    transcript: &ScenarioTranscript,
    steps: &[&ScenarioStep],
) -> StaticCheckEvidence {
    let order = [
        StepKind::TransferSourceDepositOpened,
        StepKind::TransferSourceCertified,
        StepKind::TransferSourceNoteMinted,
        StepKind::BridgeBoundTransferSubmitted,
        StepKind::TransferReceiptAnchored,
        StepKind::ExitClaimPrepared,
        StepKind::ForcedExitRequestedFromTransferClaim,
        StepKind::ForcedExitLivenessObserved,
        StepKind::ForcedExitArmed,
    ];
    let ok = ordered(steps, &order)
        && same_transfer_id(
            steps,
            &[
                StepKind::BridgeBoundTransferSubmitted,
                StepKind::ExitClaimPrepared,
                StepKind::ForcedExitRequestedFromTransferClaim,
                StepKind::ForcedExitArmed,
            ],
            &transcript.transfer_id,
        );
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::TransferToExitOrdering,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "bridge-bound transfer receipt must precede exit-claim consumption and forced-exit arming",
        format!("ordered={}, transfer_id={}", ok, transcript.transfer_id),
        json!({
            "transfer_id": transcript.transfer_id,
            "path_id": transcript.path_id,
            "required_order": order.map(StepKind::as_str),
        }),
        "reorder or rebuild the scenario transcript so exit steps consume the transfer receipt",
    )
}

fn seal_step_after_transcript(
    transcript: &ScenarioTranscript,
    pre_seal_steps: &[&ScenarioStep],
    seal_steps: &[&ScenarioStep],
) -> StaticCheckEvidence {
    let last_pre_seal_sequence = pre_seal_steps
        .iter()
        .map(|step| step.sequence)
        .max()
        .unwrap_or(0);
    let seal = seal_steps.iter().find(|step| {
        step.sequence > last_pre_seal_sequence
            && step.path_id.as_deref() == Some(transcript.path_id.as_str())
            && step.transfer_id.as_deref() == Some(transcript.transfer_id.as_str())
            && step.settlement_id.as_deref() == Some(transcript.settlement_id.as_str())
    });
    let ok = seal.is_some();
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::SealStepAfterTranscript,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "scenario must include a transcript seal marker after the pre-seal transcript root",
        format!(
            "seal_present={}, last_pre_seal_sequence={}",
            seal.is_some(),
            last_pre_seal_sequence
        ),
        json!({
            "last_pre_seal_sequence": last_pre_seal_sequence,
            "seal_sequence": seal.map(|step| step.sequence),
            "transcript_id": transcript.transcript_id,
        }),
        "append a seal step that binds the same path, transfer, and settlement identifiers",
    )
}

fn transfer_receipt_claim_coverage(
    transcript: &ScenarioTranscript,
    claims: &[&ScenarioClaim],
) -> StaticCheckEvidence {
    let required = [
        ClaimKind::BridgeMintedNoteConsumed,
        ClaimKind::TransferReceiptRecordedBySpine,
        ClaimKind::TransferReceiptAnchoredBySpine,
        ClaimKind::ExitClaimMatchesTransferReceipt,
        ClaimKind::RootsOnlyTranscript,
    ];
    let missing = missing_claims(claims, &required);
    let failed = claims
        .iter()
        .filter(|claim| required.contains(&claim.kind) && claim.status == ClaimStatus::Failed)
        .count();
    let ok = missing.is_empty() && failed == 0;
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::TransferReceiptClaimCoverage,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "claims must prove bridge note consumption, transfer receipt anchoring, exit claim binding, and roots-only disclosure",
        format!("missing={:?}, failed={}", missing, failed),
        json!({
            "missing": missing,
            "failed": failed,
            "transfer_id": transcript.transfer_id,
        }),
        "rebuild claims from the transfer receipt and bridge path before relying on the transcript",
    )
}

fn forced_exit_claim_consumed(
    transcript: &ScenarioTranscript,
    steps: &[&ScenarioStep],
    claims: &[&ScenarioClaim],
) -> StaticCheckEvidence {
    let forced_exit_step = step_by_kind(steps, StepKind::ForcedExitRequestedFromTransferClaim);
    let claim_ok = claims.iter().any(|claim| {
        claim.kind == ClaimKind::ForcedExitRequestDerivedFromClaim
            && claim.status == ClaimStatus::Proven
    });
    let ok = forced_exit_step
        .map(|step| {
            step.transfer_id.as_deref() == Some(transcript.transfer_id.as_str())
                && step.path_id.as_deref() == Some(transcript.path_id.as_str())
        })
        .unwrap_or(false)
        && claim_ok;
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::ForcedExitClaimConsumed,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "forced exit request must be derived from the transfer exit claim",
        format!(
            "forced_exit_step_present={}, claim_ok={}",
            forced_exit_step.is_some(),
            claim_ok
        ),
        json!({
            "forced_exit_step": forced_exit_step.map(ScenarioStep::public_record),
            "claim_ok": claim_ok,
        }),
        "derive the withdrawal request from the bridge-bound transfer exit claim before arming forced exit",
    )
}

fn challenge_settlement_ordering(
    transcript: &ScenarioTranscript,
    steps: &[&ScenarioStep],
) -> StaticCheckEvidence {
    let order = [
        StepKind::ForcedExitArmed,
        StepKind::ChallengeOpened,
        StepKind::ChallengeResolved,
        StepKind::TransferReadinessRechecked,
        StepKind::ExitSettled,
    ];
    let ok = ordered(steps, &order)
        && step_by_kind(steps, StepKind::ExitSettled)
            .map(|step| step.settlement_id.as_deref() == Some(transcript.settlement_id.as_str()))
            .unwrap_or(false);
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::ChallengeSettlementOrdering,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "challenge resolution and transfer readiness recheck must precede settlement",
        format!("ordered={}, settlement_id={}", ok, transcript.settlement_id),
        json!({
            "settlement_id": transcript.settlement_id,
            "required_order": order.map(StepKind::as_str),
        }),
        "settle only after challenge resolution and receipt readiness have been rechecked",
    )
}

fn final_roots_match_scenario(
    scenario: &TransferForcedExitScenarioState,
    transcript: &ScenarioTranscript,
) -> StaticCheckEvidence {
    let spine_root = scenario.spine.state_root();
    let transfer_root = scenario.transfer_runtime.state_root();
    let ok = transcript.final_spine_root == spine_root
        && transcript.final_transfer_runtime_root == transfer_root
        && scenario.roots.spine_root == spine_root
        && scenario.roots.transfer_runtime_root == transfer_root;
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::FinalRootsMatchScenario,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "transcript final roots must match current scenario spine and transfer runtime roots",
        format!(
            "transcript_spine={}, actual_spine={}, transcript_transfer={}, actual_transfer={}",
            transcript.final_spine_root,
            spine_root,
            transcript.final_transfer_runtime_root,
            transfer_root
        ),
        json!({
            "transcript_spine": transcript.final_spine_root,
            "actual_spine": spine_root,
            "scenario_spine": scenario.roots.spine_root,
            "transcript_transfer": transcript.final_transfer_runtime_root,
            "actual_transfer": transfer_root,
            "scenario_transfer": scenario.roots.transfer_runtime_root,
        }),
        "refresh scenario roots after settlement and before publishing the transcript",
    )
}

fn privacy_fee_pq_surface(
    config: &Config,
    transcript: &ScenarioTranscript,
    claims: &[&ScenarioClaim],
) -> StaticCheckEvidence {
    let privacy_ok = transcript.privacy_set_size_observed >= DEFAULT_MIN_PRIVACY_SET_SIZE;
    let claim_ok = claims.iter().any(|claim| {
        claim.kind == ClaimKind::LowFeePrivacyPqBounds && claim.status == ClaimStatus::Proven
    });
    let roots_only = claims.iter().any(|claim| {
        claim.kind == ClaimKind::RootsOnlyTranscript && claim.status == ClaimStatus::Proven
    });
    let ok = privacy_ok && claim_ok && roots_only && config.min_required_claims > 0;
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::PrivacyFeePqSurface,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "transcript must preserve privacy floor, low-fee/PQ claim, and roots-only public surface",
        format!(
            "privacy_set={}, privacy_ok={}, low_fee_pq_claim={}, roots_only_claim={}",
            transcript.privacy_set_size_observed, privacy_ok, claim_ok, roots_only
        ),
        json!({
            "privacy_set_size": transcript.privacy_set_size_observed,
            "low_fee_pq_claim": claim_ok,
            "roots_only_claim": roots_only,
        }),
        "rebuild transfer receipt claims so the transcript exposes commitments and roots only",
    )
}

fn counters_consistent(
    config: &Config,
    scenario: &TransferForcedExitScenarioState,
    transcript: &ScenarioTranscript,
    pre_seal_steps: &[&ScenarioStep],
    seal_steps: &[&ScenarioStep],
    claims: &[&ScenarioClaim],
) -> StaticCheckEvidence {
    let proven_claims = claims
        .iter()
        .filter(|claim| claim.status == ClaimStatus::Proven)
        .count() as u64;
    let ok = scenario.counters.steps_recorded == (pre_seal_steps.len() + seal_steps.len()) as u64
        && scenario.counters.claims_recorded == claims.len() as u64
        && transcript.step_count == pre_seal_steps.len() as u64
        && transcript.proven_claim_count == proven_claims
        && proven_claims >= config.min_required_claims
        && scenario.counters.bridge_bound_transfers_submitted >= 1
        && scenario.counters.exit_claims_consumed >= 1
        && scenario.counters.forced_exits_armed >= 1
        && scenario.counters.challenges_resolved >= 1
        && scenario.counters.exits_settled >= 1;
    StaticCheckEvidence::new(
        &transcript.scenario_id,
        StaticCheckKind::CountersConsistent,
        if ok {
            StaticCheckStatus::Passed
        } else {
            StaticCheckStatus::Failed
        },
        "scenario counters must agree with transcript, claims, and forced-exit path execution",
        format!(
            "steps_recorded={}, pre_seal={}, seal={}, claims_recorded={}, claims={}, proven={}, exits_settled={}",
            scenario.counters.steps_recorded,
            pre_seal_steps.len(),
            seal_steps.len(),
            scenario.counters.claims_recorded,
            claims.len(),
            proven_claims,
            scenario.counters.exits_settled
        ),
        json!({
            "steps_recorded": scenario.counters.steps_recorded,
            "pre_seal_steps": pre_seal_steps.len(),
            "seal_steps": seal_steps.len(),
            "claims_recorded": scenario.counters.claims_recorded,
            "claims": claims.len(),
            "proven_claims": proven_claims,
            "exit_claims_consumed": scenario.counters.exit_claims_consumed,
            "forced_exits_armed": scenario.counters.forced_exits_armed,
            "challenges_resolved": scenario.counters.challenges_resolved,
            "exits_settled": scenario.counters.exits_settled,
        }),
        "rebuild counters from canonical scenario records before exporting operator summaries",
    )
}

fn pre_seal_steps<'a>(
    scenario: &'a TransferForcedExitScenarioState,
    scenario_id: &str,
) -> Vec<&'a ScenarioStep> {
    let mut steps = scenario
        .steps
        .iter()
        .filter(|step| {
            step.scenario_id == scenario_id && step.kind != StepKind::ScenarioTranscriptSealed
        })
        .collect::<Vec<_>>();
    steps.sort_by_key(|step| step.sequence);
    steps
}

fn seal_steps<'a>(
    scenario: &'a TransferForcedExitScenarioState,
    scenario_id: &str,
) -> Vec<&'a ScenarioStep> {
    let mut steps = scenario
        .steps
        .iter()
        .filter(|step| {
            step.scenario_id == scenario_id && step.kind == StepKind::ScenarioTranscriptSealed
        })
        .collect::<Vec<_>>();
    steps.sort_by_key(|step| step.sequence);
    steps
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

fn step_by_kind<'a>(steps: &'a [&'a ScenarioStep], kind: StepKind) -> Option<&'a ScenarioStep> {
    steps.iter().copied().find(|step| step.kind == kind)
}

fn ordered(steps: &[&ScenarioStep], kinds: &[StepKind]) -> bool {
    let mut previous = 0;
    for kind in kinds {
        let sequence = match step_by_kind(steps, *kind) {
            Some(step) => step.sequence,
            None => return false,
        };
        if sequence <= previous {
            return false;
        }
        previous = sequence;
    }
    true
}

fn same_transfer_id(steps: &[&ScenarioStep], kinds: &[StepKind], transfer_id: &str) -> bool {
    kinds.iter().all(|kind| {
        step_by_kind(steps, *kind)
            .map(|step| step.transfer_id.as_deref() == Some(transfer_id))
            .unwrap_or(false)
    })
}

fn missing_claims(claims: &[&ScenarioClaim], required: &[ClaimKind]) -> Vec<&'static str> {
    required
        .iter()
        .filter(|kind| !claims.iter().any(|claim| claim.kind == **kind))
        .map(|kind| kind.as_str())
        .collect()
}

fn required_pre_seal_steps() -> BTreeSet<StepKind> {
    [
        StepKind::SpineSeeded,
        StepKind::TransferSourceDepositOpened,
        StepKind::TransferSourceCertified,
        StepKind::TransferSourceNoteMinted,
        StepKind::BridgeBoundTransferSubmitted,
        StepKind::TransferReceiptAnchored,
        StepKind::ExitClaimPrepared,
        StepKind::ForcedExitRequestedFromTransferClaim,
        StepKind::ForcedExitLivenessObserved,
        StepKind::ForcedExitArmed,
        StepKind::ChallengeOpened,
        StepKind::ChallengeResolved,
        StepKind::TransferReadinessRechecked,
        StepKind::ExitSettled,
    ]
    .into_iter()
    .collect()
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
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-STATIC-REPORT-ID",
        &[HashPart::Str(scenario_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn static_check_id(scenario_id: &str, kind: StaticCheckKind, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-STATIC-CHECK-ID",
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
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-STATIC-EVIDENCE",
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
    status: ReportStatus,
    check_root: &str,
    scenario_state_root: &str,
    transcript_root: &str,
    pre_seal_step_root: &str,
    claim_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-STATIC-REPORT-ROOT",
        &[
            HashPart::Str(scenario_id),
            HashPart::Str(status.as_str()),
            HashPart::Str(check_root),
            HashPart::Str(scenario_state_root),
            HashPart::Str(transcript_root),
            HashPart::Str(pre_seal_step_root),
            HashPart::Str(claim_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-BOUND-TRANSFER-FORCED-EXIT-STATIC-RECORD",
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
