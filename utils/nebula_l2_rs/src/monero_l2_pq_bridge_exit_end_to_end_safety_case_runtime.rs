use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_bound_private_transfer_receipt_runtime::{
        ReportStatus as TransferReadinessStatus, State as TransferRuntimeState,
        TransferReadinessReport,
    },
    monero_l2_pq_bridge_bound_transfer_forced_exit_failclosed_crosscheck_runtime::{
        FailClosedReport, FailClosedReportStatus, State as FailClosedState,
    },
    monero_l2_pq_bridge_bound_transfer_forced_exit_mutated_transcript_probe_runtime::{
        MutatedProbeReport, ProbeReportStatus, State as MutatedProbeState,
    },
    monero_l2_pq_bridge_bound_transfer_forced_exit_negative_fixture_test_manifest_runtime::{
        ManifestReportStatus, NegativeFixtureTestManifestReport, State as NegativeManifestState,
    },
    monero_l2_pq_bridge_bound_transfer_forced_exit_scenario_runtime::{
        ScenarioStatus, ScenarioTranscript, State as ForcedExitScenarioState,
    },
    monero_l2_pq_bridge_bound_transfer_forced_exit_security_bundle_runtime::{
        SecurityBundleReport, State as SecurityBundleState,
    },
    monero_l2_pq_bridge_bound_transfer_forced_exit_static_verifier_runtime::{
        ReportStatus as StaticReportStatus, State as StaticVerifierState, StaticReport,
    },
    monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::{
        AuthorityTransferReport, AuthorityTransferReportStatus, State as AuthorityTransferState,
    },
    monero_l2_pq_trust_minimized_bridge_exit_spine_runtime::State as BridgeExitSpineState,
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitEndToEndSafetyCaseRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_END_TO_END_SAFETY_CASE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-end-to-end-safety-case-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_END_TO_END_SAFETY_CASE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SAFETY_CASE_SUITE: &str = "monero-l2-pq-bridge-exit-end-to-end-safety-case-v1";
pub const DEFAULT_MIN_EVIDENCE_ITEMS: u64 = 18;
pub const DEFAULT_MIN_REQUIREMENTS_COVERED: u64 = 15;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyCaseVerdict {
    Proven,
    Watch,
    Failed,
}

impl SafetyCaseVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Watch => "watch",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JourneySegment {
    DepositLockObserved,
    WatcherFinalityCertificate,
    PrivateNoteMinted,
    BridgeBoundTransferSubmitted,
    TransferReceiptAnchored,
    ExitClaimPrepared,
    ForcedExitRequested,
    LivenessFailureArmed,
    ChallengeResolved,
    SettlementReleased,
    TranscriptSealed,
    StaticVerifierAccepted,
    FailClosedProbeAccepted,
    AuthorityReleaseGateAccepted,
    NegativeFixturesDeclared,
    DeferredVerificationGate,
    MoneroBaseLayerLimitation,
    ProductionReleaseGate,
}

impl JourneySegment {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLockObserved => "deposit_lock_observed",
            Self::WatcherFinalityCertificate => "watcher_finality_certificate",
            Self::PrivateNoteMinted => "private_note_minted",
            Self::BridgeBoundTransferSubmitted => "bridge_bound_transfer_submitted",
            Self::TransferReceiptAnchored => "transfer_receipt_anchored",
            Self::ExitClaimPrepared => "exit_claim_prepared",
            Self::ForcedExitRequested => "forced_exit_requested",
            Self::LivenessFailureArmed => "liveness_failure_armed",
            Self::ChallengeResolved => "challenge_resolved",
            Self::SettlementReleased => "settlement_released",
            Self::TranscriptSealed => "transcript_sealed",
            Self::StaticVerifierAccepted => "static_verifier_accepted",
            Self::FailClosedProbeAccepted => "fail_closed_probe_accepted",
            Self::AuthorityReleaseGateAccepted => "authority_release_gate_accepted",
            Self::NegativeFixturesDeclared => "negative_fixtures_declared",
            Self::DeferredVerificationGate => "deferred_verification_gate",
            Self::MoneroBaseLayerLimitation => "monero_base_layer_limitation",
            Self::ProductionReleaseGate => "production_release_gate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyRequirement {
    CustodyLockRelease,
    MoneroFinalityReorgBound,
    PrivateStateReceiptContinuity,
    BridgeMintedNoteSpend,
    ExitClaimWithdrawalBinding,
    AlwaysAvailableForcedExit,
    SequencerCensorshipEscape,
    ChallengeBeforeSettlement,
    AuthorityCannotUnilaterallyRelease,
    PqControlPlaneRooted,
    FailClosedForInvalidEvidence,
    NegativeFixturesExecutable,
    PrivacyMetadataMinimized,
    LowFeeBoundPreserved,
    LiquidityExhaustionVisible,
    RuntimeAndCompileChecks,
    SecurityAudit,
    ProductionReleaseBlocked,
}

impl SafetyRequirement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CustodyLockRelease => "custody_lock_release",
            Self::MoneroFinalityReorgBound => "monero_finality_reorg_bound",
            Self::PrivateStateReceiptContinuity => "private_state_receipt_continuity",
            Self::BridgeMintedNoteSpend => "bridge_minted_note_spend",
            Self::ExitClaimWithdrawalBinding => "exit_claim_withdrawal_binding",
            Self::AlwaysAvailableForcedExit => "always_available_forced_exit",
            Self::SequencerCensorshipEscape => "sequencer_censorship_escape",
            Self::ChallengeBeforeSettlement => "challenge_before_settlement",
            Self::AuthorityCannotUnilaterallyRelease => "authority_cannot_unilaterally_release",
            Self::PqControlPlaneRooted => "pq_control_plane_rooted",
            Self::FailClosedForInvalidEvidence => "fail_closed_for_invalid_evidence",
            Self::NegativeFixturesExecutable => "negative_fixtures_executable",
            Self::PrivacyMetadataMinimized => "privacy_metadata_minimized",
            Self::LowFeeBoundPreserved => "low_fee_bound_preserved",
            Self::LiquidityExhaustionVisible => "liquidity_exhaustion_visible",
            Self::RuntimeAndCompileChecks => "runtime_and_compile_checks",
            Self::SecurityAudit => "security_audit",
            Self::ProductionReleaseBlocked => "production_release_blocked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub safety_case_suite: String,
    pub min_evidence_items: u64,
    pub min_requirements_covered: u64,
    pub cargo_checks_deferred: bool,
    pub runtime_tests_deferred: bool,
    pub security_audit_deferred: bool,
    pub monero_base_layer_verifier_available: bool,
    pub production_release_allowed: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            safety_case_suite: SAFETY_CASE_SUITE.to_string(),
            min_evidence_items: DEFAULT_MIN_EVIDENCE_ITEMS,
            min_requirements_covered: DEFAULT_MIN_REQUIREMENTS_COVERED,
            cargo_checks_deferred: true,
            runtime_tests_deferred: true,
            security_audit_deferred: true,
            monero_base_layer_verifier_available: false,
            production_release_allowed: false,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "safety_case_suite": self.safety_case_suite,
            "min_evidence_items": self.min_evidence_items,
            "min_requirements_covered": self.min_requirements_covered,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "runtime_tests_deferred": self.runtime_tests_deferred,
            "security_audit_deferred": self.security_audit_deferred,
            "monero_base_layer_verifier_available": self.monero_base_layer_verifier_available,
            "production_release_allowed": self.production_release_allowed,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SafetyCaseEvidence {
    pub evidence_id: String,
    pub segment: JourneySegment,
    pub requirement: SafetyRequirement,
    pub verdict: SafetyCaseVerdict,
    pub requirement_statement: String,
    pub observed: String,
    pub evidence_root: String,
    pub supporting_roots: Vec<String>,
    pub public_evidence: Value,
    pub remediation: String,
    pub blocks_production: bool,
}

impl SafetyCaseEvidence {
    pub fn new(
        segment: JourneySegment,
        requirement: SafetyRequirement,
        verdict: SafetyCaseVerdict,
        requirement_statement: impl Into<String>,
        observed: impl Into<String>,
        supporting_roots: Vec<String>,
        public_evidence: Value,
        remediation: impl Into<String>,
        blocks_production: bool,
    ) -> Self {
        let requirement_statement = requirement_statement.into();
        let observed = observed.into();
        let remediation = remediation.into();
        let evidence_root = evidence_root(
            segment,
            requirement,
            verdict,
            &requirement_statement,
            &observed,
            &supporting_roots,
            &public_evidence,
        );
        let evidence_id = safety_case_evidence_id(segment, requirement, &evidence_root);
        Self {
            evidence_id,
            segment,
            requirement,
            verdict,
            requirement_statement,
            observed,
            evidence_root,
            supporting_roots,
            public_evidence,
            remediation,
            blocks_production,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "segment": self.segment.as_str(),
            "requirement": self.requirement.as_str(),
            "verdict": self.verdict.as_str(),
            "requirement_statement": self.requirement_statement,
            "observed": self.observed,
            "evidence_root": self.evidence_root,
            "supporting_roots": self.supporting_roots,
            "public_evidence": self.public_evidence,
            "remediation": self.remediation,
            "blocks_production": self.blocks_production,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("safety_case_evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SafetyCaseReport {
    pub report_id: String,
    pub verdict: SafetyCaseVerdict,
    pub readiness_label: String,
    pub user_question: String,
    pub scenario_id: String,
    pub transfer_id: String,
    pub settlement_id: String,
    pub transcript_root: String,
    pub evidence_items: u64,
    pub proven_items: u64,
    pub watch_items: u64,
    pub failed_items: u64,
    pub requirements_covered: u64,
    pub deferred_gates: u64,
    pub production_blockers: u64,
    pub bridge_spine_state_root: String,
    pub transfer_runtime_state_root: String,
    pub scenario_state_root: String,
    pub static_verifier_state_root: String,
    pub failclosed_state_root: String,
    pub security_bundle_state_root: String,
    pub authority_transfer_state_root: String,
    pub mutated_probe_state_root: String,
    pub negative_manifest_state_root: String,
    pub evidence: BTreeMap<String, SafetyCaseEvidence>,
    pub roots: SafetyCaseReportRoots,
}

impl SafetyCaseReport {
    pub fn public_record(&self) -> Value {
        let evidence = self
            .evidence
            .values()
            .map(SafetyCaseEvidence::public_record)
            .collect::<Vec<_>>();
        json!({
            "report_id": self.report_id,
            "verdict": self.verdict.as_str(),
            "readiness_label": self.readiness_label,
            "user_question": self.user_question,
            "scenario_id": self.scenario_id,
            "transfer_id": self.transfer_id,
            "settlement_id": self.settlement_id,
            "transcript_root": self.transcript_root,
            "evidence_items": self.evidence_items,
            "proven_items": self.proven_items,
            "watch_items": self.watch_items,
            "failed_items": self.failed_items,
            "requirements_covered": self.requirements_covered,
            "deferred_gates": self.deferred_gates,
            "production_blockers": self.production_blockers,
            "bridge_spine_state_root": self.bridge_spine_state_root,
            "transfer_runtime_state_root": self.transfer_runtime_state_root,
            "scenario_state_root": self.scenario_state_root,
            "static_verifier_state_root": self.static_verifier_state_root,
            "failclosed_state_root": self.failclosed_state_root,
            "security_bundle_state_root": self.security_bundle_state_root,
            "authority_transfer_state_root": self.authority_transfer_state_root,
            "mutated_probe_state_root": self.mutated_probe_state_root,
            "negative_manifest_state_root": self.negative_manifest_state_root,
            "evidence": evidence,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.report_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SafetyCaseReportRoots {
    pub evidence_root: String,
    pub source_root: String,
    pub blocker_root: String,
    pub report_root: String,
}

impl SafetyCaseReportRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_root": self.evidence_root,
            "source_root": self.source_root,
            "blocker_root": self.blocker_root,
            "report_root": self.report_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub reports_run: u64,
    pub reports_proven: u64,
    pub reports_watch: u64,
    pub reports_failed: u64,
    pub evidence_items: u64,
    pub proven_items: u64,
    pub watch_items: u64,
    pub failed_items: u64,
    pub requirements_covered: u64,
    pub deferred_gates: u64,
    pub production_blockers: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "reports_run": self.reports_run,
            "reports_proven": self.reports_proven,
            "reports_watch": self.reports_watch,
            "reports_failed": self.reports_failed,
            "evidence_items": self.evidence_items,
            "proven_items": self.proven_items,
            "watch_items": self.watch_items,
            "failed_items": self.failed_items,
            "requirements_covered": self.requirements_covered,
            "deferred_gates": self.deferred_gates,
            "production_blockers": self.production_blockers,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-END-TO-END-SAFETY-CASE-EMPTY-REPORTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-END-TO-END-SAFETY-CASE-STATE",
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
    pub latest_report: Option<SafetyCaseReport>,
    pub report_history: Vec<SafetyCaseReport>,
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
        let bridge_spine = crate::monero_l2_pq_trust_minimized_bridge_exit_spine_runtime::devnet();
        let transfer_runtime =
            crate::monero_l2_pq_bridge_bound_private_transfer_receipt_runtime::devnet();
        let scenario =
            crate::monero_l2_pq_bridge_bound_transfer_forced_exit_scenario_runtime::devnet();
        let static_verifier =
            crate::monero_l2_pq_bridge_bound_transfer_forced_exit_static_verifier_runtime::devnet();
        let failclosed =
            crate::monero_l2_pq_bridge_bound_transfer_forced_exit_failclosed_crosscheck_runtime::devnet();
        let security_bundle =
            crate::monero_l2_pq_bridge_bound_transfer_forced_exit_security_bundle_runtime::devnet();
        let authority_transfer =
            crate::monero_l2_pq_bridge_exit_authority_transfer_security_bundle_runtime::devnet();
        let mutated_probe =
            crate::monero_l2_pq_bridge_bound_transfer_forced_exit_mutated_transcript_probe_runtime::devnet();
        let negative_manifest =
            crate::monero_l2_pq_bridge_bound_transfer_forced_exit_negative_fixture_test_manifest_runtime::devnet();
        state
            .evaluate_bridge_exit_safety_case(
                &bridge_spine,
                &transfer_runtime,
                &scenario,
                &static_verifier,
                &failclosed,
                &security_bundle,
                &authority_transfer,
                &mutated_probe,
                &negative_manifest,
            )
            .expect("devnet bridge exit end-to-end safety case");
        state
    }

    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_bridge_exit_safety_case(
        &mut self,
        bridge_spine: &BridgeExitSpineState,
        transfer_runtime: &TransferRuntimeState,
        scenario: &ForcedExitScenarioState,
        static_verifier: &StaticVerifierState,
        failclosed: &FailClosedState,
        security_bundle: &SecurityBundleState,
        authority_transfer: &AuthorityTransferState,
        mutated_probe: &MutatedProbeState,
        negative_manifest: &NegativeManifestState,
    ) -> Result<String> {
        let transcript = latest_transcript(scenario)?;
        let transfer_report = latest_transfer_report(&scenario.transfer_runtime)?;
        let static_report = latest_static_report(static_verifier)?;
        let failclosed_report = latest_failclosed_report(failclosed)?;
        let security_report = latest_security_report(security_bundle)?;
        let authority_report = latest_authority_report(authority_transfer)?;
        let probe_report = latest_probe_report(mutated_probe)?;
        let manifest_report = latest_manifest_report(negative_manifest)?;

        let evidence = build_evidence(
            &self.config,
            bridge_spine,
            transfer_runtime,
            scenario,
            transcript,
            transfer_report,
            static_verifier,
            static_report,
            failclosed,
            failclosed_report,
            security_bundle,
            security_report,
            authority_transfer,
            authority_report,
            mutated_probe,
            probe_report,
            negative_manifest,
            manifest_report,
        )?;
        ensure(
            evidence.len() as u64 >= self.config.min_evidence_items,
            "bridge exit safety case omitted required journey evidence",
        )?;

        let requirements_covered = evidence
            .values()
            .map(|item| item.requirement)
            .collect::<BTreeSet<_>>()
            .len() as u64;
        ensure(
            requirements_covered >= self.config.min_requirements_covered,
            "bridge exit safety case does not cover enough requirements",
        )?;

        let proven_items = evidence
            .values()
            .filter(|item| item.verdict == SafetyCaseVerdict::Proven)
            .count() as u64;
        let watch_items = evidence
            .values()
            .filter(|item| item.verdict == SafetyCaseVerdict::Watch)
            .count() as u64;
        let failed_items = evidence
            .values()
            .filter(|item| item.verdict == SafetyCaseVerdict::Failed)
            .count() as u64;
        let production_blockers = evidence
            .values()
            .filter(|item| item.blocks_production)
            .count() as u64;
        let deferred_gates = deferred_gate_count(&self.config, &evidence);
        let verdict = aggregate_verdict(
            &self.config,
            failed_items,
            watch_items,
            evidence.len() as u64,
            requirements_covered,
        );
        let readiness_label = readiness_label(verdict, &self.config).to_string();

        let evidence_records = evidence
            .values()
            .map(SafetyCaseEvidence::public_record)
            .collect::<Vec<_>>();
        let evidence_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-END-TO-END-SAFETY-CASE-EVIDENCE",
            &evidence_records,
        );
        let blocker_records = evidence
            .values()
            .filter(|item| item.blocks_production)
            .map(SafetyCaseEvidence::public_record)
            .collect::<Vec<_>>();
        let blocker_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-END-TO-END-SAFETY-CASE-BLOCKERS",
            &blocker_records,
        );
        let source_root = source_root(
            &bridge_spine.state_root(),
            &transfer_runtime.state_root(),
            &scenario.state_root(),
            &static_verifier.state_root(),
            &static_report.state_root(),
            &failclosed.state_root(),
            &failclosed_report.state_root(),
            &security_bundle.state_root(),
            &security_report.state_root(),
            &authority_transfer.state_root(),
            &authority_report.state_root(),
            &mutated_probe.state_root(),
            &probe_report.state_root(),
            &negative_manifest.state_root(),
            &manifest_report.state_root(),
            &transcript.transcript_root,
        );
        let report_root = report_root(
            verdict,
            &readiness_label,
            &source_root,
            &evidence_root,
            &blocker_root,
            &transcript.scenario_id,
            &transcript.transfer_id,
            &transcript.transcript_root,
        );
        let report_id = safety_case_report_id(&transcript.scenario_id, &report_root);
        let report = SafetyCaseReport {
            report_id: report_id.clone(),
            verdict,
            readiness_label,
            user_question:
                "Can a user get in, transact privately, and force their way out safely if everyone else misbehaves?"
                    .to_string(),
            scenario_id: transcript.scenario_id.clone(),
            transfer_id: transcript.transfer_id.clone(),
            settlement_id: transcript.settlement_id.clone(),
            transcript_root: transcript.transcript_root.clone(),
            evidence_items: evidence.len() as u64,
            proven_items,
            watch_items,
            failed_items,
            requirements_covered,
            deferred_gates,
            production_blockers,
            bridge_spine_state_root: bridge_spine.state_root(),
            transfer_runtime_state_root: transfer_runtime.state_root(),
            scenario_state_root: scenario.state_root(),
            static_verifier_state_root: static_verifier.state_root(),
            failclosed_state_root: failclosed.state_root(),
            security_bundle_state_root: security_bundle.state_root(),
            authority_transfer_state_root: authority_transfer.state_root(),
            mutated_probe_state_root: mutated_probe.state_root(),
            negative_manifest_state_root: negative_manifest.state_root(),
            evidence,
            roots: SafetyCaseReportRoots {
                evidence_root,
                source_root,
                blocker_root,
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
            "safety_case_suite": self.config.safety_case_suite,
            "latest_report": self.latest_report.as_ref().map(SafetyCaseReport::public_record),
            "report_history_len": self.report_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_report(&mut self, report: SafetyCaseReport) {
        self.counters.reports_run += 1;
        self.counters.evidence_items += report.evidence_items;
        self.counters.proven_items += report.proven_items;
        self.counters.watch_items += report.watch_items;
        self.counters.failed_items += report.failed_items;
        self.counters.requirements_covered += report.requirements_covered;
        self.counters.deferred_gates += report.deferred_gates;
        self.counters.production_blockers += report.production_blockers;
        match report.verdict {
            SafetyCaseVerdict::Proven => self.counters.reports_proven += 1,
            SafetyCaseVerdict::Watch => self.counters.reports_watch += 1,
            SafetyCaseVerdict::Failed => self.counters.reports_failed += 1,
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
            .map(SafetyCaseReport::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            report_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-END-TO-END-SAFETY-CASE-REPORTS",
                &report_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_evidence(
    config: &Config,
    bridge_spine: &BridgeExitSpineState,
    transfer_runtime: &TransferRuntimeState,
    scenario: &ForcedExitScenarioState,
    transcript: &ScenarioTranscript,
    transfer_report: &TransferReadinessReport,
    static_verifier: &StaticVerifierState,
    static_report: &StaticReport,
    failclosed: &FailClosedState,
    failclosed_report: &FailClosedReport,
    security_bundle: &SecurityBundleState,
    security_report: &SecurityBundleReport,
    authority_transfer: &AuthorityTransferState,
    authority_report: &AuthorityTransferReport,
    mutated_probe: &MutatedProbeState,
    probe_report: &MutatedProbeReport,
    negative_manifest: &NegativeManifestState,
    manifest_report: &NegativeFixtureTestManifestReport,
) -> Result<BTreeMap<String, SafetyCaseEvidence>> {
    let mut evidence = BTreeMap::new();
    let mut insert = |item: SafetyCaseEvidence| {
        evidence.insert(item.evidence_id.clone(), item);
    };

    let transcript_ok = transcript.status == ScenarioStatus::Passed
        && transcript.step_count >= scenario.config.min_steps
        && transcript.proven_claim_count >= scenario.config.min_proven_claims;
    let transfer_ok = transfer_report.status == TransferReadinessStatus::Passed
        && transfer_report.transfer_id == transcript.transfer_id
        && !transfer_report.exit_claim_root.is_empty();
    let static_ok = static_report.status == StaticReportStatus::Passed
        && static_report.transcript_root == transcript.transcript_root;
    let failclosed_ok = failclosed_report.status == FailClosedReportStatus::Passed
        && failclosed_report.failclosed_probe_count == failclosed_report.rejected_probe_count
        && failclosed_report.failclosed_probe_count > 0;
    let security_critical_ok = security_report.critical_checks_passed
        == security_report.critical_checks_total
        && security_report.failed_checks == 0;
    let authority_release_ok = authority_report.release_blocking_checks_passed
        == authority_report.release_blocking_checks_total
        && authority_report.failed_checks == 0;
    let probes_escape_ok = probe_report.probes_escaped == 0 && probe_report.probes_rejected > 0;
    let manifest_declared = manifest_report.entries_declared + manifest_report.entries_deferred
        >= crate::monero_l2_pq_bridge_bound_transfer_forced_exit_negative_fixture_test_manifest_runtime::DEFAULT_MIN_MANIFEST_ENTRIES;

    insert(SafetyCaseEvidence::new(
        JourneySegment::DepositLockObserved,
        SafetyRequirement::CustodyLockRelease,
        bool_verdict(scenario.counters.scenarios_run > 0 && scenario.counters.steps_recorded > 0),
        "a bridge source lock must be observed before private L2 state is minted",
        format!(
            "scenarios_run={} steps_recorded={} deposit_paths_opened={}",
            scenario.counters.scenarios_run,
            scenario.counters.steps_recorded,
            scenario.spine.counters.deposit_paths_opened
        ),
        vec![scenario.state_root(), scenario.roots.spine_root.clone()],
        json!({
            "scenario_id": transcript.scenario_id,
            "initial_bridge_spine_state_root": bridge_spine.state_root(),
            "scenario_spine_root": scenario.roots.spine_root,
        }),
        "materialize deposit-lock fixture tests once cargo/runtime execution resumes",
        !config.production_release_allowed,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::WatcherFinalityCertificate,
        SafetyRequirement::MoneroFinalityReorgBound,
        bool_verdict(
            scenario.spine.counters.deposits_certified > 0
                && scenario.spine.config.monero_finality_depth > 0,
        ),
        "Monero lock evidence must include finality depth before bridge minting",
        format!(
            "deposits_certified={} monero_finality_depth={}",
            scenario.spine.counters.deposits_certified, scenario.spine.config.monero_finality_depth
        ),
        vec![
            scenario.spine.state_root(),
            scenario.roots.spine_root.clone(),
        ],
        json!({
            "finality_depth": scenario.spine.config.monero_finality_depth,
            "watcher_quorums": scenario.spine.counters.watcher_quorums_registered,
        }),
        "add real Monero reorg fixtures and observed-chain adapters",
        true,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::PrivateNoteMinted,
        SafetyRequirement::PrivateStateReceiptContinuity,
        bool_verdict(
            scenario.spine.counters.private_notes_minted > 0
                && transcript.privacy_set_size_observed >= scenario.config.min_privacy_set_size,
        ),
        "the locked source must become a private note with a privacy floor",
        format!(
            "private_notes_minted={} privacy_set_size_observed={} min_privacy_set_size={}",
            scenario.spine.counters.private_notes_minted,
            transcript.privacy_set_size_observed,
            scenario.config.min_privacy_set_size
        ),
        vec![
            scenario.spine.state_root(),
            transcript.transcript_root.clone(),
        ],
        json!({
            "transcript_id": transcript.transcript_id,
            "privacy_set_size_observed": transcript.privacy_set_size_observed,
        }),
        "attach wallet scan and metadata leakage tests to the private note mint path",
        true,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::BridgeBoundTransferSubmitted,
        SafetyRequirement::BridgeMintedNoteSpend,
        bool_verdict(transfer_ok && scenario.counters.bridge_bound_transfers_submitted > 0),
        "the private transfer must spend the bridge-minted note and preserve a prepared exit claim",
        format!(
            "transfer_status={} transfer_id_match={} submitted={}",
            transfer_report.status.as_str(),
            transfer_report.transfer_id == transcript.transfer_id,
            scenario.counters.bridge_bound_transfers_submitted
        ),
        vec![
            scenario.transfer_runtime.state_root(),
            transfer_runtime.state_root(),
            transfer_report.state_root(),
        ],
        json!({
            "transfer_id": transcript.transfer_id,
            "transfer_report_id": transfer_report.report_id,
            "exit_claim_root": transfer_report.exit_claim_root,
        }),
        "promote transfer receipt checks into executable integration tests",
        config.runtime_tests_deferred,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::TransferReceiptAnchored,
        SafetyRequirement::PrivateStateReceiptContinuity,
        bool_verdict(
            transfer_ok
                && scenario.spine.counters.receipts_anchored > 0
                && !transfer_report.transfer_receipt_root.is_empty(),
        ),
        "the transfer receipt must be anchored back into the bridge spine",
        format!(
            "receipts_anchored={} transfer_receipt_root_present={}",
            scenario.spine.counters.receipts_anchored,
            !transfer_report.transfer_receipt_root.is_empty()
        ),
        vec![
            transfer_report.transfer_receipt_root.clone(),
            scenario.spine.state_root(),
        ],
        json!({
            "bridge_spine_root": transfer_report.bridge_spine_root,
            "transfer_receipt_root": transfer_report.transfer_receipt_root,
        }),
        "add receipt-root mismatch negative tests to runtime test files",
        config.runtime_tests_deferred,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::ExitClaimPrepared,
        SafetyRequirement::ExitClaimWithdrawalBinding,
        bool_verdict(transfer_ok && scenario.counters.exit_claims_consumed > 0),
        "the withdrawal/exit request must derive from the prepared transfer exit claim",
        format!(
            "exit_claims_consumed={} exit_claim_root_present={}",
            scenario.counters.exit_claims_consumed,
            !transfer_report.exit_claim_root.is_empty()
        ),
        vec![
            transfer_report.exit_claim_root.clone(),
            transcript.transcript_root.clone(),
        ],
        json!({
            "exit_claim_root": transfer_report.exit_claim_root,
            "scenario_claim_root": transcript.claim_root,
        }),
        "materialize claim-withdrawal binding fixtures from the negative manifest",
        config.runtime_tests_deferred,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::ForcedExitRequested,
        SafetyRequirement::AlwaysAvailableForcedExit,
        bool_verdict(
            scenario.counters.forced_exits_requested > 0
                && scenario.spine.counters.withdrawals_requested > 0,
        ),
        "a user must be able to request exit from a private transfer claim",
        format!(
            "forced_exits_requested={} withdrawals_requested={}",
            scenario.counters.forced_exits_requested, scenario.spine.counters.withdrawals_requested
        ),
        vec![
            scenario.spine.state_root(),
            transcript.transcript_root.clone(),
        ],
        json!({
            "transfer_id": transcript.transfer_id,
            "path_id": transcript.path_id,
        }),
        "connect a wallet-facing forced-exit request harness",
        config.runtime_tests_deferred,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::LivenessFailureArmed,
        SafetyRequirement::SequencerCensorshipEscape,
        bool_verdict(
            scenario.counters.forced_exits_armed > 0
                && scenario.spine.counters.forced_exits_armed > 0,
        ),
        "sequencer/watchtower failure must arm a forced exit after the liveness window",
        format!(
            "scenario_forced_exits_armed={} spine_forced_exits_armed={}",
            scenario.counters.forced_exits_armed, scenario.spine.counters.forced_exits_armed
        ),
        vec![
            scenario.spine.state_root(),
            scenario.roots.step_root.clone(),
        ],
        json!({
            "exit_liveness_window_blocks": scenario.spine.config.exit_liveness_window_blocks,
            "forced_exit_delay_blocks": scenario.spine.config.forced_exit_delay_blocks,
        }),
        "add time-window boundary tests for early/late forced-exit arming",
        config.runtime_tests_deferred,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::ChallengeResolved,
        SafetyRequirement::ChallengeBeforeSettlement,
        bool_verdict(scenario.counters.challenges_resolved > 0 && transcript_ok),
        "challenge resolution must precede final forced-exit settlement",
        format!(
            "challenges_resolved={} transcript_status={}",
            scenario.counters.challenges_resolved,
            transcript.status.as_str()
        ),
        vec![scenario.spine.state_root(), transcript.claim_root.clone()],
        json!({
            "challenge_window_blocks": scenario.spine.config.challenge_window_blocks,
            "settlement_id": transcript.settlement_id,
        }),
        "add invalid settlement-before-challenge executable negative tests",
        config.runtime_tests_deferred,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::SettlementReleased,
        SafetyRequirement::CustodyLockRelease,
        bool_verdict(scenario.counters.exits_settled > 0 && !transcript.settlement_id.is_empty()),
        "the bridge must settle/release only after the authorized exit path completes",
        format!(
            "exits_settled={} settlement_id_present={}",
            scenario.counters.exits_settled,
            !transcript.settlement_id.is_empty()
        ),
        vec![
            scenario.spine.state_root(),
            transcript.transcript_root.clone(),
        ],
        json!({
            "settlement_id": transcript.settlement_id,
            "final_spine_root": transcript.final_spine_root,
        }),
        "connect real liquidity reserve accounting and release adapters",
        true,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::TranscriptSealed,
        SafetyRequirement::PrivateStateReceiptContinuity,
        bool_verdict(transcript_ok && scenario.counters.transcripts_sealed > 0),
        "the end-to-end journey must seal a transcript tying source, transfer, exit, and settlement roots",
        format!(
            "transcripts_sealed={} step_count={} proven_claim_count={}",
            scenario.counters.transcripts_sealed,
            transcript.step_count,
            transcript.proven_claim_count
        ),
        vec![transcript.transcript_root.clone(), scenario.state_root()],
        json!({
            "scenario_id": transcript.scenario_id,
            "transcript_id": transcript.transcript_id,
            "step_root": transcript.step_root,
            "claim_root": transcript.claim_root,
        }),
        "turn transcript sealing into an executable fixture with deterministic roots",
        config.runtime_tests_deferred,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::StaticVerifierAccepted,
        SafetyRequirement::FailClosedForInvalidEvidence,
        bool_verdict(static_ok),
        "static verification must recompute and accept only the sealed transfer-exit transcript",
        format!(
            "static_status={} static_failed_checks={} transcript_match={}",
            static_report.status.as_str(),
            static_report.failed_checks,
            static_report.transcript_root == transcript.transcript_root
        ),
        vec![static_verifier.state_root(), static_report.state_root()],
        json!({
            "static_report_id": static_report.report_id,
            "passed_checks": static_report.passed_checks,
            "failed_checks": static_report.failed_checks,
        }),
        "run cargo tests/checks before promoting static verifier evidence",
        config.cargo_checks_deferred || config.runtime_tests_deferred,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::FailClosedProbeAccepted,
        SafetyRequirement::FailClosedForInvalidEvidence,
        bool_verdict(failclosed_ok),
        "tampered roots, broken ordering, and missing claims must fail closed",
        format!(
            "failclosed_status={} probes={} rejected={}",
            failclosed_report.status.as_str(),
            failclosed_report.failclosed_probe_count,
            failclosed_report.rejected_probe_count
        ),
        vec![failclosed.state_root(), failclosed_report.state_root()],
        json!({
            "failclosed_report_id": failclosed_report.report_id,
            "root_tamper_rejections": failclosed.counters.root_tamper_rejections,
            "ordering_rejections": failclosed.counters.ordering_rejections,
            "missing_surface_rejections": failclosed.counters.missing_surface_rejections,
        }),
        "execute the declared negative fixtures under cargo test",
        config.runtime_tests_deferred,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::AuthorityReleaseGateAccepted,
        SafetyRequirement::AuthorityCannotUnilaterallyRelease,
        watch_if_deferred(
            authority_release_ok,
            authority_report.status == AuthorityTransferReportStatus::Watch,
        ),
        "release authority must consume the transfer security bundle and keep release blocked on unresolved evidence",
        format!(
            "authority_status={} release_blocking_passed={}/{} failed_checks={}",
            authority_report.status.as_str(),
            authority_report.release_blocking_checks_passed,
            authority_report.release_blocking_checks_total,
            authority_report.failed_checks
        ),
        vec![authority_transfer.state_root(), authority_report.state_root()],
        json!({
            "authority_report_id": authority_report.report_id,
            "readiness_label": authority_report.readiness_label,
        }),
        "replace watch-only authority gates with audited signer/quorum enforcement",
        true,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::AuthorityReleaseGateAccepted,
        SafetyRequirement::PqControlPlaneRooted,
        watch_if_deferred(security_critical_ok && authority_release_ok, config.security_audit_deferred),
        "PQ authentication must cover sequencer, watcher, bridge attestation, and withdrawal authorization roots",
        format!(
            "security_critical_passed={}/{} authority_release_passed={}/{} audit_deferred={}",
            security_report.critical_checks_passed,
            security_report.critical_checks_total,
            authority_report.release_blocking_checks_passed,
            authority_report.release_blocking_checks_total,
            config.security_audit_deferred
        ),
        vec![
            security_bundle.state_root(),
            security_report.state_root(),
            authority_transfer.state_root(),
            authority_report.state_root(),
        ],
        json!({
            "security_readiness_label": security_report.readiness_label,
            "authority_readiness_label": authority_report.readiness_label,
        }),
        "run cryptographic design review and signature-suite interop tests",
        true,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::NegativeFixturesDeclared,
        SafetyRequirement::NegativeFixturesExecutable,
        watch_if_deferred(
            manifest_declared
                && manifest_report.status != ManifestReportStatus::Failed
                && manifest_report.entries_blocked == 0,
            manifest_report.entries_deferred > 0 || config.runtime_tests_deferred,
        ),
        "mutated bridge-exit fixtures must map to stable future failing-input tests",
        format!(
            "manifest_status={} entries_declared={} entries_deferred={} entries_blocked={}",
            manifest_report.status.as_str(),
            manifest_report.entries_declared,
            manifest_report.entries_deferred,
            manifest_report.entries_blocked
        ),
        vec![negative_manifest.state_root(), manifest_report.state_root()],
        json!({
            "manifest_report_id": manifest_report.report_id,
            "entry_root": manifest_report.roots.entry_root,
            "scenario_id": manifest_report.scenario_id,
        }),
        "materialize manifest entries under utils/nebula_l2_rs/tests/",
        true,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::FailClosedProbeAccepted,
        SafetyRequirement::FailClosedForInvalidEvidence,
        watch_if_deferred(
            probes_escape_ok && probe_report.status != ProbeReportStatus::Failed,
            probe_report.status == ProbeReportStatus::Watch || config.runtime_tests_deferred,
        ),
        "mutated transcript probes must not escape the safety bundle or authority adapter",
        format!(
            "probe_status={} probes_run={} rejected={} watch={} escaped={}",
            probe_report.status.as_str(),
            probe_report.probes_run,
            probe_report.probes_rejected,
            probe_report.probes_watch,
            probe_report.probes_escaped
        ),
        vec![mutated_probe.state_root(), probe_report.state_root()],
        json!({
            "probe_report_id": probe_report.report_id,
            "case_root": probe_report.roots.case_root,
        }),
        "execute mutation probes in runtime tests instead of manifest-only checks",
        config.runtime_tests_deferred,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::DeferredVerificationGate,
        SafetyRequirement::RuntimeAndCompileChecks,
        if config.cargo_checks_deferred || config.runtime_tests_deferred {
            SafetyCaseVerdict::Watch
        } else {
            SafetyCaseVerdict::Proven
        },
        "compile, clippy, unit, and runtime tests must run before the safety case can be release evidence",
        format!(
            "cargo_checks_deferred={} runtime_tests_deferred={}",
            config.cargo_checks_deferred, config.runtime_tests_deferred
        ),
        vec![scenario.state_root(), static_verifier.state_root(), negative_manifest.state_root()],
        json!({
            "cargo_checks_deferred": config.cargo_checks_deferred,
            "runtime_tests_deferred": config.runtime_tests_deferred,
        }),
        "run cargo check/test/clippy when the user resumes heavier gates",
        true,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::MoneroBaseLayerLimitation,
        SafetyRequirement::MoneroFinalityReorgBound,
        if config.monero_base_layer_verifier_available {
            SafetyCaseVerdict::Proven
        } else {
            SafetyCaseVerdict::Watch
        },
        "Monero does not provide an Ethereum-style on-chain verifier for this L2 safety case",
        format!(
            "monero_base_layer_verifier_available={}",
            config.monero_base_layer_verifier_available
        ),
        vec![bridge_spine.state_root(), scenario.spine.state_root()],
        json!({
            "constraint": "bridge evidence is watcher/quorum/transcript based, not base-layer smart-contract verified",
            "watcher_quorum_root": scenario.spine.roots.watcher_quorum_root,
        }),
        "document the trust boundary and add watcher-collusion/reorg simulations",
        true,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::ProductionReleaseGate,
        SafetyRequirement::ProductionReleaseBlocked,
        if config.production_release_allowed {
            SafetyCaseVerdict::Failed
        } else {
            SafetyCaseVerdict::Watch
        },
        "the current prototype must remain blocked from production release while tests/audits are deferred",
        format!(
            "production_release_allowed={} production_blockers_expected=true",
            config.production_release_allowed
        ),
        vec![
            security_bundle.state_root(),
            authority_transfer.state_root(),
            negative_manifest.state_root(),
        ],
        json!({
            "security_audit_deferred": config.security_audit_deferred,
            "runtime_tests_deferred": config.runtime_tests_deferred,
            "cargo_checks_deferred": config.cargo_checks_deferred,
        }),
        "keep the progress panel readiness honest until verifiable release gates exist",
        !config.production_release_allowed,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::SettlementReleased,
        SafetyRequirement::LiquidityExhaustionVisible,
        SafetyCaseVerdict::Watch,
        "withdrawal liquidity exhaustion must be visible and must not silently strand forced exits",
        format!(
            "exit_liquidity_model_present={} reserve_runtime_connected=false",
            !transfer_report.exit_claim_root.is_empty()
        ),
        vec![
            transfer_report.exit_claim_root.clone(),
            security_report.state_root(),
        ],
        json!({
            "known_gap": "release/liquidity reserve accounting is represented by roots, not a live reserve adapter",
            "exit_claim_root": transfer_report.exit_claim_root,
        }),
        "connect reserve/liquidity accounting to the forced-exit release path",
        true,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::PrivateNoteMinted,
        SafetyRequirement::PrivacyMetadataMinimized,
        watch_if_deferred(
            transcript.privacy_set_size_observed >= scenario.config.min_privacy_set_size
                && security_report.failed_checks == 0,
            config.security_audit_deferred,
        ),
        "public evidence should expose roots and counters, not private note metadata",
        format!(
            "privacy_set_size_observed={} security_failed_checks={} audit_deferred={}",
            transcript.privacy_set_size_observed,
            security_report.failed_checks,
            config.security_audit_deferred
        ),
        vec![
            transcript.transcript_root.clone(),
            security_report.state_root(),
        ],
        json!({
            "public_surfaces": [
                "state roots",
                "receipt roots",
                "claim roots",
                "redacted counters"
            ],
            "privacy_set_size_observed": transcript.privacy_set_size_observed,
        }),
        "run metadata leakage review for deposit, transfer, scan, and withdrawal paths",
        true,
    ));

    insert(SafetyCaseEvidence::new(
        JourneySegment::BridgeBoundTransferSubmitted,
        SafetyRequirement::LowFeeBoundPreserved,
        bool_verdict(
            scenario.transfer_runtime.config.max_transfer_fee_bps
                <= scenario.transfer_runtime.config.max_user_fee_bps,
        ),
        "bridge-bound private transfers must stay inside the low-fee cap while preserving exit readiness",
        format!(
            "max_transfer_fee_bps={} max_user_fee_bps={}",
            scenario.transfer_runtime.config.max_transfer_fee_bps,
            scenario.transfer_runtime.config.max_user_fee_bps
        ),
        vec![scenario.transfer_runtime.state_root(), transfer_report.state_root()],
        json!({
            "max_transfer_fee_bps": scenario.transfer_runtime.config.max_transfer_fee_bps,
            "max_user_fee_bps": scenario.transfer_runtime.config.max_user_fee_bps,
        }),
        "add congestion and reserve-fee stress fixtures against the forced-exit path",
        config.runtime_tests_deferred,
    ));

    Ok(evidence)
}

fn latest_transcript(state: &ForcedExitScenarioState) -> Result<&ScenarioTranscript> {
    state
        .transcripts
        .values()
        .next_back()
        .ok_or_else(|| "forced-exit scenario has no sealed transcript".to_string())
}

fn latest_transfer_report(state: &TransferRuntimeState) -> Result<&TransferReadinessReport> {
    state
        .readiness_reports
        .values()
        .next_back()
        .ok_or_else(|| "transfer runtime has no readiness report".to_string())
}

fn latest_static_report(state: &StaticVerifierState) -> Result<&StaticReport> {
    state
        .latest_report
        .as_ref()
        .ok_or_else(|| "static verifier has no latest report".to_string())
}

fn latest_failclosed_report(state: &FailClosedState) -> Result<&FailClosedReport> {
    state
        .latest_report
        .as_ref()
        .ok_or_else(|| "failclosed crosscheck has no latest report".to_string())
}

fn latest_security_report(state: &SecurityBundleState) -> Result<&SecurityBundleReport> {
    state
        .latest_report
        .as_ref()
        .ok_or_else(|| "security bundle has no latest report".to_string())
}

fn latest_authority_report(state: &AuthorityTransferState) -> Result<&AuthorityTransferReport> {
    state
        .latest_report
        .as_ref()
        .ok_or_else(|| "authority transfer adapter has no latest report".to_string())
}

fn latest_probe_report(state: &MutatedProbeState) -> Result<&MutatedProbeReport> {
    state
        .latest_report
        .as_ref()
        .ok_or_else(|| "mutated transcript probe has no latest report".to_string())
}

fn latest_manifest_report(
    state: &NegativeManifestState,
) -> Result<&NegativeFixtureTestManifestReport> {
    state
        .latest_report
        .as_ref()
        .ok_or_else(|| "negative fixture manifest has no latest report".to_string())
}

fn bool_verdict(condition: bool) -> SafetyCaseVerdict {
    if condition {
        SafetyCaseVerdict::Proven
    } else {
        SafetyCaseVerdict::Failed
    }
}

fn watch_if_deferred(condition: bool, deferred: bool) -> SafetyCaseVerdict {
    if !condition {
        SafetyCaseVerdict::Failed
    } else if deferred {
        SafetyCaseVerdict::Watch
    } else {
        SafetyCaseVerdict::Proven
    }
}

fn aggregate_verdict(
    config: &Config,
    failed_items: u64,
    watch_items: u64,
    evidence_items: u64,
    requirements_covered: u64,
) -> SafetyCaseVerdict {
    if failed_items > 0
        || evidence_items < config.min_evidence_items
        || requirements_covered < config.min_requirements_covered
    {
        SafetyCaseVerdict::Failed
    } else if watch_items > 0
        || config.cargo_checks_deferred
        || config.runtime_tests_deferred
        || config.security_audit_deferred
        || !config.monero_base_layer_verifier_available
        || !config.production_release_allowed
    {
        SafetyCaseVerdict::Watch
    } else {
        SafetyCaseVerdict::Proven
    }
}

fn readiness_label(verdict: SafetyCaseVerdict, config: &Config) -> &'static str {
    match verdict {
        SafetyCaseVerdict::Failed => "bridge_exit_safety_case_failed",
        SafetyCaseVerdict::Watch
            if config.cargo_checks_deferred
                || config.runtime_tests_deferred
                || config.security_audit_deferred =>
        {
            "bridge_exit_safety_case_covered_but_deferred_gates_remain"
        }
        SafetyCaseVerdict::Watch => "bridge_exit_safety_case_watch_trust_boundary_open",
        SafetyCaseVerdict::Proven => "bridge_exit_safety_case_release_gate_ready",
    }
}

fn deferred_gate_count(config: &Config, evidence: &BTreeMap<String, SafetyCaseEvidence>) -> u64 {
    let config_deferred = [
        config.cargo_checks_deferred,
        config.runtime_tests_deferred,
        config.security_audit_deferred,
        !config.monero_base_layer_verifier_available,
        !config.production_release_allowed,
    ]
    .iter()
    .filter(|item| **item)
    .count() as u64;
    config_deferred
        + evidence
            .values()
            .filter(|item| item.verdict == SafetyCaseVerdict::Watch)
            .count() as u64
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

pub fn safety_case_report_id(scenario_id: &str, report_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-END-TO-END-SAFETY-CASE-REPORT-ID",
        &[HashPart::Str(scenario_id), HashPart::Str(report_root)],
        32,
    )
}

pub fn safety_case_evidence_id(
    segment: JourneySegment,
    requirement: SafetyRequirement,
    evidence_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-END-TO-END-SAFETY-CASE-EVIDENCE-ID",
        &[
            HashPart::Str(segment.as_str()),
            HashPart::Str(requirement.as_str()),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn evidence_root(
    segment: JourneySegment,
    requirement: SafetyRequirement,
    verdict: SafetyCaseVerdict,
    requirement_statement: &str,
    observed: &str,
    supporting_roots: &[String],
    public_evidence: &Value,
) -> String {
    let roots = supporting_roots
        .iter()
        .map(|root| json!({ "root": root }))
        .collect::<Vec<_>>();
    let supporting_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-END-TO-END-SAFETY-CASE-SUPPORTING-ROOTS",
        &roots,
    );
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-END-TO-END-SAFETY-CASE-EVIDENCE-ROOT",
        &[
            HashPart::Str(segment.as_str()),
            HashPart::Str(requirement.as_str()),
            HashPart::Str(verdict.as_str()),
            HashPart::Str(requirement_statement),
            HashPart::Str(observed),
            HashPart::Str(&supporting_root),
            HashPart::Json(public_evidence),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn source_root(
    bridge_spine_state_root: &str,
    transfer_runtime_state_root: &str,
    scenario_state_root: &str,
    static_verifier_state_root: &str,
    static_report_root: &str,
    failclosed_state_root: &str,
    failclosed_report_root: &str,
    security_bundle_state_root: &str,
    security_report_root: &str,
    authority_transfer_state_root: &str,
    authority_report_root: &str,
    mutated_probe_state_root: &str,
    probe_report_root: &str,
    negative_manifest_state_root: &str,
    manifest_report_root: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-END-TO-END-SAFETY-CASE-SOURCE-ROOT",
        &[
            HashPart::Str(bridge_spine_state_root),
            HashPart::Str(transfer_runtime_state_root),
            HashPart::Str(scenario_state_root),
            HashPart::Str(static_verifier_state_root),
            HashPart::Str(static_report_root),
            HashPart::Str(failclosed_state_root),
            HashPart::Str(failclosed_report_root),
            HashPart::Str(security_bundle_state_root),
            HashPart::Str(security_report_root),
            HashPart::Str(authority_transfer_state_root),
            HashPart::Str(authority_report_root),
            HashPart::Str(mutated_probe_state_root),
            HashPart::Str(probe_report_root),
            HashPart::Str(negative_manifest_state_root),
            HashPart::Str(manifest_report_root),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

pub fn report_root(
    verdict: SafetyCaseVerdict,
    readiness_label: &str,
    source_root: &str,
    evidence_root: &str,
    blocker_root: &str,
    scenario_id: &str,
    transfer_id: &str,
    transcript_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-END-TO-END-SAFETY-CASE-REPORT-ROOT",
        &[
            HashPart::Str(verdict.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(evidence_root),
            HashPart::Str(blocker_root),
            HashPart::Str(scenario_id),
            HashPart::Str(transfer_id),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-END-TO-END-SAFETY-CASE-RECORD",
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
