use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceReleaseBlockerGateReceiptConformanceRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_GATE_RECEIPT_CONFORMANCE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-release-blocker-gate-receipt-conformance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_GATE_RECEIPT_CONFORMANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CONFORMANCE_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-release-blocker-gate-receipt-conformance-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_RELEASE_CANDIDATE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-release-candidate-devnet-v1";
pub const REQUIRED_CONFORMANCE_CHECKS: usize = 15;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceSubject {
    CargoRuntimeDeferred,
    LiveFeedSwapMissing,
    ForcedExitDrillMissing,
    IndependentAuditOpen,
    PrivacyLeakageReviewOpen,
    PqVerificationPending,
    ReserveProofMissing,
    ProductionReleaseHeld,
    InvocationReceipt,
    PreflightReceipt,
    ExecutionReceipt,
    OperatorEvidence,
    WalletVisibleNoGoRoot,
    FailClosedReceiptRoot,
    ReleaseBlockers,
}

impl ConformanceSubject {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoRuntimeDeferred => "cargo_runtime_deferred",
            Self::LiveFeedSwapMissing => "live_feed_swap_missing",
            Self::ForcedExitDrillMissing => "forced_exit_drill_missing",
            Self::IndependentAuditOpen => "independent_audit_open",
            Self::PrivacyLeakageReviewOpen => "privacy_leakage_review_open",
            Self::PqVerificationPending => "pq_verification_pending",
            Self::ReserveProofMissing => "reserve_proof_missing",
            Self::ProductionReleaseHeld => "production_release_held",
            Self::InvocationReceipt => "invocation_receipt",
            Self::PreflightReceipt => "preflight_receipt",
            Self::ExecutionReceipt => "execution_receipt",
            Self::OperatorEvidence => "operator_evidence",
            Self::WalletVisibleNoGoRoot => "wallet_visible_no_go_root",
            Self::FailClosedReceiptRoot => "fail_closed_receipt_root",
            Self::ReleaseBlockers => "release_blockers",
        }
    }

    pub fn all() -> [Self; REQUIRED_CONFORMANCE_CHECKS] {
        [
            Self::CargoRuntimeDeferred,
            Self::LiveFeedSwapMissing,
            Self::ForcedExitDrillMissing,
            Self::IndependentAuditOpen,
            Self::PrivacyLeakageReviewOpen,
            Self::PqVerificationPending,
            Self::ReserveProofMissing,
            Self::ProductionReleaseHeld,
            Self::InvocationReceipt,
            Self::PreflightReceipt,
            Self::ExecutionReceipt,
            Self::OperatorEvidence,
            Self::WalletVisibleNoGoRoot,
            Self::FailClosedReceiptRoot,
            Self::ReleaseBlockers,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceDecision {
    NoGo,
}

impl ConformanceDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoGo => "no_go",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceStatus {
    MissingRuntimeObservation,
    MissingReleaseEvidence,
}

impl ConformanceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingRuntimeObservation => "missing_runtime_observation",
            Self::MissingReleaseEvidence => "missing_release_evidence",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub conformance_suite: String,
    pub vertical_slice_id: String,
    pub release_candidate_id: String,
    pub required_conformance_checks: usize,
    pub runtime_execution_deferred: bool,
    pub release_execution_allowed: bool,
    pub fail_closed_on_placeholder_roots: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            conformance_suite: CONFORMANCE_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            release_candidate_id: DEFAULT_RELEASE_CANDIDATE_ID.to_string(),
            required_conformance_checks: REQUIRED_CONFORMANCE_CHECKS,
            runtime_execution_deferred: true,
            release_execution_allowed: false,
            fail_closed_on_placeholder_roots: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "conformance_suite": self.conformance_suite,
            "vertical_slice_id": self.vertical_slice_id,
            "release_candidate_id": self.release_candidate_id,
            "required_conformance_checks": self.required_conformance_checks,
            "runtime_execution_deferred": self.runtime_execution_deferred,
            "release_execution_allowed": self.release_execution_allowed,
            "fail_closed_on_placeholder_roots": self.fail_closed_on_placeholder_roots,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConformanceCheck {
    pub check_id: String,
    pub sequence: u64,
    pub subject: ConformanceSubject,
    pub decision: ConformanceDecision,
    pub status: ConformanceStatus,
    pub expected_no_go_root: String,
    pub observed_no_go_root: String,
    pub roots_match: bool,
    pub release_blocking: bool,
    pub required_clearance: String,
    pub conformance_root: String,
}

impl ConformanceCheck {
    pub fn new(
        sequence: u64,
        subject: ConformanceSubject,
        status: ConformanceStatus,
        required_clearance: impl Into<String>,
    ) -> Self {
        let decision = ConformanceDecision::NoGo;
        let required_clearance = required_clearance.into();
        let expected_no_go_root = expected_no_go_root(sequence, subject, &required_clearance);
        let observed_no_go_root = observed_placeholder_root(sequence, subject, status);
        let roots_match = expected_no_go_root == observed_no_go_root;
        let release_blocking = true;
        let conformance_root = conformance_root(
            sequence,
            subject,
            decision,
            status,
            &expected_no_go_root,
            &observed_no_go_root,
            roots_match,
            release_blocking,
            &required_clearance,
        );
        let check_id = check_id(sequence, subject, &conformance_root);

        Self {
            check_id,
            sequence,
            subject,
            decision,
            status,
            expected_no_go_root,
            observed_no_go_root,
            roots_match,
            release_blocking,
            required_clearance,
            conformance_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "sequence": self.sequence,
            "subject": self.subject.as_str(),
            "decision": self.decision.as_str(),
            "status": self.status.as_str(),
            "expected_no_go_root": self.expected_no_go_root,
            "observed_no_go_root": self.observed_no_go_root,
            "roots_match": self.roots_match,
            "release_blocking": self.release_blocking,
            "required_clearance": self.required_clearance,
            "conformance_root": self.conformance_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("conformance_check", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConformanceSummary {
    pub decision: ConformanceDecision,
    pub conformance_check_count: u64,
    pub mismatch_count: u64,
    pub release_blocking_count: u64,
    pub expected_no_go_root: String,
    pub observed_no_go_root: String,
    pub mismatch_root: String,
    pub fail_closed_receipt_root: String,
    pub release_blocker_root: String,
}

impl ConformanceSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "decision": self.decision.as_str(),
            "conformance_check_count": self.conformance_check_count,
            "mismatch_count": self.mismatch_count,
            "release_blocking_count": self.release_blocking_count,
            "expected_no_go_root": self.expected_no_go_root,
            "observed_no_go_root": self.observed_no_go_root,
            "mismatch_root": self.mismatch_root,
            "fail_closed_receipt_root": self.fail_closed_receipt_root,
            "release_blocker_root": self.release_blocker_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("conformance_summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub checks: BTreeMap<String, ConformanceCheck>,
    pub summary: ConformanceSummary,
    pub cargo_runtime_deferred_root: String,
    pub live_feed_swap_missing_root: String,
    pub forced_exit_drill_missing_root: String,
    pub independent_audit_open_root: String,
    pub privacy_leakage_review_open_root: String,
    pub pq_verification_pending_root: String,
    pub reserve_proof_missing_root: String,
    pub production_release_held_root: String,
    pub invocation_receipt_root: String,
    pub preflight_receipt_root: String,
    pub execution_receipt_root: String,
    pub operator_evidence_root: String,
    pub wallet_visible_no_go_root: String,
    pub fail_closed_receipt_root: String,
    pub release_blocker_root: String,
    pub config_root: String,
    pub check_root: String,
    pub expected_no_go_root: String,
    pub observed_no_go_root: String,
    pub mismatch_root: String,
    pub summary_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        let checks = devnet_checks();
        if checks.len() != config.required_conformance_checks {
            return Err("release blocker conformance check cardinality mismatch".to_string());
        }

        let config_root = config.state_root();
        let check_root = check_root(&checks);
        let expected_no_go_root = expected_root(&checks);
        let observed_no_go_root = observed_root(&checks);
        let mismatch_root = mismatch_root(&checks);
        let fail_closed_receipt_root =
            fail_closed_receipt_root(&expected_no_go_root, &observed_no_go_root, &mismatch_root);
        let release_blocker_root = release_blocker_root(&mismatch_root, &fail_closed_receipt_root);
        let summary = ConformanceSummary {
            decision: ConformanceDecision::NoGo,
            conformance_check_count: checks.len() as u64,
            mismatch_count: checks.values().filter(|check| !check.roots_match).count() as u64,
            release_blocking_count: checks
                .values()
                .filter(|check| check.release_blocking)
                .count() as u64,
            expected_no_go_root: expected_no_go_root.clone(),
            observed_no_go_root: observed_no_go_root.clone(),
            mismatch_root: mismatch_root.clone(),
            fail_closed_receipt_root: fail_closed_receipt_root.clone(),
            release_blocker_root: release_blocker_root.clone(),
        };
        let summary_root = summary.state_root();

        let public_record = state_public_record(
            &config,
            &checks,
            &summary,
            &config_root,
            &check_root,
            &expected_no_go_root,
            &observed_no_go_root,
            &mismatch_root,
            &summary_root,
        );
        let public_record_root = record_root("state_public_record", &public_record);
        let state_root = conformance_state_root(
            &config_root,
            &check_root,
            &expected_no_go_root,
            &observed_no_go_root,
            &mismatch_root,
            &fail_closed_receipt_root,
            &release_blocker_root,
            &summary_root,
            &public_record_root,
        );

        Ok(Self {
            cargo_runtime_deferred_root: subject_root(
                &checks,
                ConformanceSubject::CargoRuntimeDeferred,
            ),
            live_feed_swap_missing_root: subject_root(
                &checks,
                ConformanceSubject::LiveFeedSwapMissing,
            ),
            forced_exit_drill_missing_root: subject_root(
                &checks,
                ConformanceSubject::ForcedExitDrillMissing,
            ),
            independent_audit_open_root: subject_root(
                &checks,
                ConformanceSubject::IndependentAuditOpen,
            ),
            privacy_leakage_review_open_root: subject_root(
                &checks,
                ConformanceSubject::PrivacyLeakageReviewOpen,
            ),
            pq_verification_pending_root: subject_root(
                &checks,
                ConformanceSubject::PqVerificationPending,
            ),
            reserve_proof_missing_root: subject_root(
                &checks,
                ConformanceSubject::ReserveProofMissing,
            ),
            production_release_held_root: subject_root(
                &checks,
                ConformanceSubject::ProductionReleaseHeld,
            ),
            invocation_receipt_root: subject_root(&checks, ConformanceSubject::InvocationReceipt),
            preflight_receipt_root: subject_root(&checks, ConformanceSubject::PreflightReceipt),
            execution_receipt_root: subject_root(&checks, ConformanceSubject::ExecutionReceipt),
            operator_evidence_root: subject_root(&checks, ConformanceSubject::OperatorEvidence),
            wallet_visible_no_go_root: subject_root(
                &checks,
                ConformanceSubject::WalletVisibleNoGoRoot,
            ),
            config,
            checks,
            summary,
            fail_closed_receipt_root,
            release_blocker_root,
            config_root,
            check_root,
            expected_no_go_root,
            observed_no_go_root,
            mismatch_root,
            summary_root,
            public_record_root,
            state_root,
        })
    }

    pub fn devnet() -> Self {
        match Self::new(Config::devnet()) {
            Ok(state) => state,
            Err(error) => fallback_state(error),
        }
    }

    pub fn public_record(&self) -> Value {
        state_public_record(
            &self.config,
            &self.checks,
            &self.summary,
            &self.config_root,
            &self.check_root,
            &self.expected_no_go_root,
            &self.observed_no_go_root,
            &self.mismatch_root,
            &self.summary_root,
        )
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
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

fn devnet_checks() -> BTreeMap<String, ConformanceCheck> {
    let records = [
        (
            ConformanceSubject::CargoRuntimeDeferred,
            ConformanceStatus::MissingRuntimeObservation,
            "cargo/runtime execution must be run and sealed before release",
        ),
        (
            ConformanceSubject::LiveFeedSwapMissing,
            ConformanceStatus::MissingRuntimeObservation,
            "live feed adapter swap receipt must replace stub feed evidence",
        ),
        (
            ConformanceSubject::ForcedExitDrillMissing,
            ConformanceStatus::MissingRuntimeObservation,
            "forced-exit drill receipt must be executed against devnet spine",
        ),
        (
            ConformanceSubject::IndependentAuditOpen,
            ConformanceStatus::MissingReleaseEvidence,
            "independent audit signoff receipt must close all open findings",
        ),
        (
            ConformanceSubject::PrivacyLeakageReviewOpen,
            ConformanceStatus::MissingReleaseEvidence,
            "privacy leakage review receipt must be closed and hashed",
        ),
        (
            ConformanceSubject::PqVerificationPending,
            ConformanceStatus::MissingRuntimeObservation,
            "post-quantum verification receipt must be present",
        ),
        (
            ConformanceSubject::ReserveProofMissing,
            ConformanceStatus::MissingReleaseEvidence,
            "reserve proof handoff receipt must be present",
        ),
        (
            ConformanceSubject::ProductionReleaseHeld,
            ConformanceStatus::MissingReleaseEvidence,
            "production release hold must remain until blocker roots match",
        ),
        (
            ConformanceSubject::InvocationReceipt,
            ConformanceStatus::MissingRuntimeObservation,
            "release-blocker invocation receipt must be conformed",
        ),
        (
            ConformanceSubject::PreflightReceipt,
            ConformanceStatus::MissingRuntimeObservation,
            "release-blocker preflight receipt must be conformed",
        ),
        (
            ConformanceSubject::ExecutionReceipt,
            ConformanceStatus::MissingRuntimeObservation,
            "release-blocker execution receipt must be conformed",
        ),
        (
            ConformanceSubject::OperatorEvidence,
            ConformanceStatus::MissingReleaseEvidence,
            "operator evidence receipt must be bound to the no-go decision",
        ),
        (
            ConformanceSubject::WalletVisibleNoGoRoot,
            ConformanceStatus::MissingReleaseEvidence,
            "wallet-visible no-go root must be published before release",
        ),
        (
            ConformanceSubject::FailClosedReceiptRoot,
            ConformanceStatus::MissingRuntimeObservation,
            "fail-closed receipt root must be observed from runtime output",
        ),
        (
            ConformanceSubject::ReleaseBlockers,
            ConformanceStatus::MissingReleaseEvidence,
            "release blocker aggregate must remain no-go until evidence clears",
        ),
    ];

    records
        .into_iter()
        .enumerate()
        .map(|(index, (subject, status, clearance))| {
            let check = ConformanceCheck::new(index as u64 + 1, subject, status, clearance);
            (check.check_id.clone(), check)
        })
        .collect()
}

fn state_public_record(
    config: &Config,
    checks: &BTreeMap<String, ConformanceCheck>,
    summary: &ConformanceSummary,
    config_root: &str,
    check_root: &str,
    expected_no_go_root: &str,
    observed_no_go_root: &str,
    mismatch_root: &str,
    summary_root: &str,
) -> Value {
    let checks = checks
        .values()
        .map(ConformanceCheck::public_record)
        .collect::<Vec<_>>();
    json!({
        "config": config.public_record(),
        "checks": checks,
        "summary": summary.public_record(),
        "config_root": config_root,
        "check_root": check_root,
        "expected_no_go_root": expected_no_go_root,
        "observed_no_go_root": observed_no_go_root,
        "mismatch_root": mismatch_root,
        "summary_root": summary_root,
    })
}

fn check_root(checks: &BTreeMap<String, ConformanceCheck>) -> String {
    let records = checks
        .values()
        .map(ConformanceCheck::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-RECEIPT-CONFORMANCE-CHECK",
        &records,
    )
}

fn expected_root(checks: &BTreeMap<String, ConformanceCheck>) -> String {
    let records = checks
        .values()
        .map(|check| {
            json!({
                "subject": check.subject.as_str(),
                "expected_no_go_root": check.expected_no_go_root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-RECEIPT-CONFORMANCE-EXPECTED",
        &records,
    )
}

fn observed_root(checks: &BTreeMap<String, ConformanceCheck>) -> String {
    let records = checks
        .values()
        .map(|check| {
            json!({
                "subject": check.subject.as_str(),
                "observed_no_go_root": check.observed_no_go_root,
                "status": check.status.as_str(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-RECEIPT-CONFORMANCE-OBSERVED",
        &records,
    )
}

fn mismatch_root(checks: &BTreeMap<String, ConformanceCheck>) -> String {
    let records = checks
        .values()
        .filter(|check| !check.roots_match)
        .map(ConformanceCheck::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-RECEIPT-CONFORMANCE-MISMATCH",
        &records,
    )
}

fn subject_root(
    checks: &BTreeMap<String, ConformanceCheck>,
    subject: ConformanceSubject,
) -> String {
    let records = checks
        .values()
        .filter(|check| check.subject == subject)
        .map(ConformanceCheck::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        &format!(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-RECEIPT-CONFORMANCE-SUBJECT-{}",
            subject.as_str()
        ),
        &records,
    )
}

fn expected_no_go_root(
    sequence: u64,
    subject: ConformanceSubject,
    required_clearance: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-RECEIPT-CONFORMANCE-EXPECTED-NO-GO",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(subject.as_str()),
            HashPart::Str(ConformanceDecision::NoGo.as_str()),
            HashPart::Str(required_clearance),
            HashPart::Str(bool_str(true)),
        ],
        32,
    )
}

fn observed_placeholder_root(
    sequence: u64,
    subject: ConformanceSubject,
    status: ConformanceStatus,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-RECEIPT-CONFORMANCE-OBSERVED-PLACEHOLDER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(subject.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str("runtime-execution-deferred"),
            HashPart::Str(bool_str(false)),
        ],
        32,
    )
}

fn conformance_root(
    sequence: u64,
    subject: ConformanceSubject,
    decision: ConformanceDecision,
    status: ConformanceStatus,
    expected_no_go_root: &str,
    observed_no_go_root: &str,
    roots_match: bool,
    release_blocking: bool,
    required_clearance: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-RECEIPT-CONFORMANCE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(subject.as_str()),
            HashPart::Str(decision.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(expected_no_go_root),
            HashPart::Str(observed_no_go_root),
            HashPart::Str(bool_str(roots_match)),
            HashPart::Str(bool_str(release_blocking)),
            HashPart::Str(required_clearance),
        ],
        32,
    )
}

fn check_id(sequence: u64, subject: ConformanceSubject, conformance_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-RECEIPT-CONFORMANCE-CHECK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(subject.as_str()),
            HashPart::Str(conformance_root),
        ],
        16,
    )
}

fn fail_closed_receipt_root(
    expected_no_go_root: &str,
    observed_no_go_root: &str,
    mismatch_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-RECEIPT-CONFORMANCE-FAIL-CLOSED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(ConformanceDecision::NoGo.as_str()),
            HashPart::Str(expected_no_go_root),
            HashPart::Str(observed_no_go_root),
            HashPart::Str(mismatch_root),
            HashPart::Str(bool_str(true)),
        ],
        32,
    )
}

fn release_blocker_root(mismatch_root: &str, fail_closed_receipt_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-RECEIPT-CONFORMANCE-RELEASE-BLOCKERS",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(ConformanceDecision::NoGo.as_str()),
            HashPart::Str(mismatch_root),
            HashPart::Str(fail_closed_receipt_root),
            HashPart::Str(bool_str(true)),
        ],
        32,
    )
}

fn conformance_state_root(
    config_root: &str,
    check_root: &str,
    expected_no_go_root: &str,
    observed_no_go_root: &str,
    mismatch_root: &str,
    fail_closed_receipt_root: &str,
    release_blocker_root: &str,
    summary_root: &str,
    public_record_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-RECEIPT-CONFORMANCE-STATE",
        &[
            HashPart::Str(config_root),
            HashPart::Str(check_root),
            HashPart::Str(expected_no_go_root),
            HashPart::Str(observed_no_go_root),
            HashPart::Str(mismatch_root),
            HashPart::Str(fail_closed_receipt_root),
            HashPart::Str(release_blocker_root),
            HashPart::Str(summary_root),
            HashPart::Str(public_record_root),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-RECEIPT-CONFORMANCE-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn fallback_state(error: String) -> State {
    let config = Config::devnet();
    let checks = BTreeMap::new();
    let fallback_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-RECEIPT-CONFORMANCE-FALLBACK",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&error),
        ],
        32,
    );
    let summary = ConformanceSummary {
        decision: ConformanceDecision::NoGo,
        conformance_check_count: 0,
        mismatch_count: 0,
        release_blocking_count: 0,
        expected_no_go_root: fallback_root.clone(),
        observed_no_go_root: fallback_root.clone(),
        mismatch_root: fallback_root.clone(),
        fail_closed_receipt_root: fallback_root.clone(),
        release_blocker_root: fallback_root.clone(),
    };
    let config_root = config.state_root();
    let check_root = fallback_root.clone();
    let expected_no_go_root = fallback_root.clone();
    let observed_no_go_root = fallback_root.clone();
    let mismatch_root = fallback_root.clone();
    let fail_closed_receipt_root = fallback_root.clone();
    let release_blocker_root = fallback_root.clone();
    let summary_root = summary.state_root();
    let public_record = state_public_record(
        &config,
        &checks,
        &summary,
        &config_root,
        &check_root,
        &expected_no_go_root,
        &observed_no_go_root,
        &mismatch_root,
        &summary_root,
    );
    let public_record_root = record_root("fallback_state_public_record", &public_record);
    let state_root = conformance_state_root(
        &config_root,
        &check_root,
        &expected_no_go_root,
        &observed_no_go_root,
        &mismatch_root,
        &fail_closed_receipt_root,
        &release_blocker_root,
        &summary_root,
        &public_record_root,
    );

    State {
        config,
        checks,
        summary,
        cargo_runtime_deferred_root: fallback_root.clone(),
        live_feed_swap_missing_root: fallback_root.clone(),
        forced_exit_drill_missing_root: fallback_root.clone(),
        independent_audit_open_root: fallback_root.clone(),
        privacy_leakage_review_open_root: fallback_root.clone(),
        pq_verification_pending_root: fallback_root.clone(),
        reserve_proof_missing_root: fallback_root.clone(),
        production_release_held_root: fallback_root.clone(),
        invocation_receipt_root: fallback_root.clone(),
        preflight_receipt_root: fallback_root.clone(),
        execution_receipt_root: fallback_root.clone(),
        operator_evidence_root: fallback_root.clone(),
        wallet_visible_no_go_root: fallback_root.clone(),
        fail_closed_receipt_root,
        release_blocker_root,
        config_root,
        check_root,
        expected_no_go_root,
        observed_no_go_root,
        mismatch_root,
        summary_root,
        public_record_root,
        state_root,
    }
}
