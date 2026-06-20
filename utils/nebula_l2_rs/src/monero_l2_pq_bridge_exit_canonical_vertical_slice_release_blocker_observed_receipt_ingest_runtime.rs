use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceReleaseBlockerObservedReceiptIngestRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_OBSERVED_RECEIPT_INGEST_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-release-blocker-observed-receipt-ingest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_OBSERVED_RECEIPT_INGEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const INGEST_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-release-blocker-observed-receipt-ingest-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_RELEASE_CANDIDATE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-release-candidate-devnet-v1";
pub const REQUIRED_OBSERVED_RECEIPT_LANES: usize = 8;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedReceiptLane {
    MissingObservedReceipts,
    ConformanceMismatches,
    WalletVisibleDrift,
    OperatorEvidenceMismatch,
    PrivacyAuditHold,
    PqAuditHold,
    FailClosedNoGoReceipts,
    ReleaseGateStatus,
}

impl ObservedReceiptLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingObservedReceipts => "missing_observed_receipts",
            Self::ConformanceMismatches => "conformance_mismatches",
            Self::WalletVisibleDrift => "wallet_visible_drift",
            Self::OperatorEvidenceMismatch => "operator_evidence_mismatch",
            Self::PrivacyAuditHold => "privacy_audit_hold",
            Self::PqAuditHold => "pq_audit_hold",
            Self::FailClosedNoGoReceipts => "fail_closed_no_go_receipts",
            Self::ReleaseGateStatus => "release_gate_status",
        }
    }

    pub fn all() -> [Self; REQUIRED_OBSERVED_RECEIPT_LANES] {
        [
            Self::MissingObservedReceipts,
            Self::ConformanceMismatches,
            Self::WalletVisibleDrift,
            Self::OperatorEvidenceMismatch,
            Self::PrivacyAuditHold,
            Self::PqAuditHold,
            Self::FailClosedNoGoReceipts,
            Self::ReleaseGateStatus,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptExpectation {
    ExpectedNoGo,
    ExpectedAuditHold,
    ExpectedReleaseBlocked,
}

impl ReceiptExpectation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExpectedNoGo => "expected_no_go",
            Self::ExpectedAuditHold => "expected_audit_hold",
            Self::ExpectedReleaseBlocked => "expected_release_blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedReceiptStatus {
    Missing,
    Mismatch,
    DriftDetected,
    EvidenceDiverged,
    AuditHoldOpen,
    FailClosedNoGo,
    ReleaseBlocked,
}

impl ObservedReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Mismatch => "mismatch",
            Self::DriftDetected => "drift_detected",
            Self::EvidenceDiverged => "evidence_diverged",
            Self::AuditHoldOpen => "audit_hold_open",
            Self::FailClosedNoGo => "fail_closed_no_go",
            Self::ReleaseBlocked => "release_blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerSeverity {
    Critical,
    High,
}

impl BlockerSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseGateDecision {
    BlockProductionRelease,
}

impl ReleaseGateDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlockProductionRelease => "block_production_release",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub ingest_suite: String,
    pub vertical_slice_id: String,
    pub release_candidate_id: String,
    pub required_observed_receipt_lanes: usize,
    pub production_release_allowed: bool,
    pub fail_closed_on_missing_observed_receipts: bool,
    pub require_expected_observed_root_match: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            ingest_suite: INGEST_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            release_candidate_id: DEFAULT_RELEASE_CANDIDATE_ID.to_string(),
            required_observed_receipt_lanes: REQUIRED_OBSERVED_RECEIPT_LANES,
            production_release_allowed: false,
            fail_closed_on_missing_observed_receipts: true,
            require_expected_observed_root_match: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "ingest_suite": self.ingest_suite,
            "vertical_slice_id": self.vertical_slice_id,
            "release_candidate_id": self.release_candidate_id,
            "required_observed_receipt_lanes": self.required_observed_receipt_lanes,
            "production_release_allowed": self.production_release_allowed,
            "fail_closed_on_missing_observed_receipts": self.fail_closed_on_missing_observed_receipts,
            "require_expected_observed_root_match": self.require_expected_observed_root_match,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservedReceiptIngestRecord {
    pub record_id: String,
    pub sequence: u64,
    pub lane: ObservedReceiptLane,
    pub expectation: ReceiptExpectation,
    pub status: ObservedReceiptStatus,
    pub severity: BlockerSeverity,
    pub expected_root: String,
    pub observed_root: String,
    pub roots_match: bool,
    pub release_blocking: bool,
    pub required_clearance: String,
    pub ingest_root: String,
}

impl ObservedReceiptIngestRecord {
    pub fn new(
        sequence: u64,
        lane: ObservedReceiptLane,
        expectation: ReceiptExpectation,
        status: ObservedReceiptStatus,
        severity: BlockerSeverity,
        required_clearance: impl Into<String>,
    ) -> Self {
        let required_clearance = required_clearance.into();
        let expected_root = expected_receipt_root(sequence, lane, expectation, &required_clearance);
        let observed_root = observed_receipt_root(sequence, lane, status);
        let roots_match = expected_root == observed_root;
        let release_blocking = true;
        let ingest_root = receipt_ingest_root(
            sequence,
            lane,
            expectation,
            status,
            severity,
            &expected_root,
            &observed_root,
            roots_match,
            release_blocking,
            &required_clearance,
        );
        let record_id = receipt_record_id(sequence, lane, &ingest_root);

        Self {
            record_id,
            sequence,
            lane,
            expectation,
            status,
            severity,
            expected_root,
            observed_root,
            roots_match,
            release_blocking,
            required_clearance,
            ingest_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "sequence": self.sequence,
            "lane": self.lane,
            "expectation": self.expectation,
            "status": self.status,
            "severity": self.severity,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "roots_match": self.roots_match,
            "release_blocking": self.release_blocking,
            "required_clearance": self.required_clearance,
            "ingest_root": self.ingest_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("observed_receipt_ingest_record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseGateSummary {
    pub decision: ReleaseGateDecision,
    pub observed_receipt_count: usize,
    pub missing_observed_receipt_count: usize,
    pub mismatch_count: usize,
    pub release_blocking_count: usize,
    pub critical_blocker_count: usize,
    pub expected_receipt_root: String,
    pub observed_receipt_root: String,
    pub mismatch_root: String,
    pub wallet_visible_drift_root: String,
    pub operator_evidence_mismatch_root: String,
    pub privacy_pq_audit_hold_root: String,
    pub fail_closed_no_go_receipt_root: String,
    pub blocker_severity_root: String,
    pub release_gate_status_root: String,
}

impl ReleaseGateSummary {
    pub fn new(records: &BTreeMap<String, ObservedReceiptIngestRecord>) -> Self {
        let expected_receipt_root = expected_receipts_root(records);
        let observed_receipt_root = observed_receipts_root(records);
        let mismatch_root = mismatch_receipts_root(records);
        let wallet_visible_drift_root = lane_root(
            "wallet_visible_drift",
            records,
            ObservedReceiptLane::WalletVisibleDrift,
        );
        let operator_evidence_mismatch_root = lane_root(
            "operator_evidence_mismatch",
            records,
            ObservedReceiptLane::OperatorEvidenceMismatch,
        );
        let privacy_audit_root = lane_root(
            "privacy_audit_hold",
            records,
            ObservedReceiptLane::PrivacyAuditHold,
        );
        let pq_audit_root = lane_root("pq_audit_hold", records, ObservedReceiptLane::PqAuditHold);
        let privacy_pq_audit_hold_root =
            combined_audit_hold_root(&privacy_audit_root, &pq_audit_root);
        let fail_closed_no_go_receipt_root = lane_root(
            "fail_closed_no_go_receipts",
            records,
            ObservedReceiptLane::FailClosedNoGoReceipts,
        );
        let blocker_severity_root = blocker_severity_root(records);
        let release_gate_status_root = release_gate_status_root(
            &expected_receipt_root,
            &observed_receipt_root,
            &mismatch_root,
            &fail_closed_no_go_receipt_root,
            &blocker_severity_root,
        );
        let missing_observed_receipt_count = records
            .values()
            .filter(|record| record.status == ObservedReceiptStatus::Missing)
            .count();
        let mismatch_count = records
            .values()
            .filter(|record| !record.roots_match)
            .count();
        let release_blocking_count = records
            .values()
            .filter(|record| record.release_blocking)
            .count();
        let critical_blocker_count = records
            .values()
            .filter(|record| record.severity == BlockerSeverity::Critical)
            .count();

        Self {
            decision: ReleaseGateDecision::BlockProductionRelease,
            observed_receipt_count: records.len(),
            missing_observed_receipt_count,
            mismatch_count,
            release_blocking_count,
            critical_blocker_count,
            expected_receipt_root,
            observed_receipt_root,
            mismatch_root,
            wallet_visible_drift_root,
            operator_evidence_mismatch_root,
            privacy_pq_audit_hold_root,
            fail_closed_no_go_receipt_root,
            blocker_severity_root,
            release_gate_status_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "decision": self.decision,
            "observed_receipt_count": self.observed_receipt_count,
            "missing_observed_receipt_count": self.missing_observed_receipt_count,
            "mismatch_count": self.mismatch_count,
            "release_blocking_count": self.release_blocking_count,
            "critical_blocker_count": self.critical_blocker_count,
            "expected_receipt_root": self.expected_receipt_root,
            "observed_receipt_root": self.observed_receipt_root,
            "mismatch_root": self.mismatch_root,
            "wallet_visible_drift_root": self.wallet_visible_drift_root,
            "operator_evidence_mismatch_root": self.operator_evidence_mismatch_root,
            "privacy_pq_audit_hold_root": self.privacy_pq_audit_hold_root,
            "fail_closed_no_go_receipt_root": self.fail_closed_no_go_receipt_root,
            "blocker_severity_root": self.blocker_severity_root,
            "release_gate_status_root": self.release_gate_status_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_gate_summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub records: BTreeMap<String, ObservedReceiptIngestRecord>,
    pub summary: ReleaseGateSummary,
    pub missing_observed_receipts_root: String,
    pub conformance_mismatch_root: String,
    pub wallet_visible_drift_root: String,
    pub operator_evidence_mismatch_root: String,
    pub privacy_audit_hold_root: String,
    pub pq_audit_hold_root: String,
    pub privacy_pq_audit_hold_root: String,
    pub fail_closed_no_go_receipt_root: String,
    pub blocker_severity_root: String,
    pub release_gate_status_root: String,
    pub config_root: String,
    pub record_root: String,
    pub expected_receipt_root: String,
    pub observed_receipt_root: String,
    pub mismatch_root: String,
    pub summary_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        if config.required_observed_receipt_lanes != REQUIRED_OBSERVED_RECEIPT_LANES {
            return Err("observed receipt ingest lane count mismatch".to_string());
        }

        Ok(assemble_state(config, devnet_records()))
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let records = devnet_records();
        assemble_state(config, records)
    }

    pub fn public_record(&self) -> Value {
        state_public_record(
            &self.config,
            &self.records,
            &self.summary,
            &self.missing_observed_receipts_root,
            &self.conformance_mismatch_root,
            &self.privacy_audit_hold_root,
            &self.pq_audit_hold_root,
            &self.config_root,
            &self.record_root,
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

fn devnet_records() -> BTreeMap<String, ObservedReceiptIngestRecord> {
    let mut records = BTreeMap::new();
    for record in [
        ObservedReceiptIngestRecord::new(
            1,
            ObservedReceiptLane::MissingObservedReceipts,
            ReceiptExpectation::ExpectedNoGo,
            ObservedReceiptStatus::Missing,
            BlockerSeverity::Critical,
            "ingest every forced-exit observed receipt before production release",
        ),
        ObservedReceiptIngestRecord::new(
            2,
            ObservedReceiptLane::ConformanceMismatches,
            ReceiptExpectation::ExpectedNoGo,
            ObservedReceiptStatus::Mismatch,
            BlockerSeverity::Critical,
            "observed roots must match conformance receipt roots",
        ),
        ObservedReceiptIngestRecord::new(
            3,
            ObservedReceiptLane::WalletVisibleDrift,
            ReceiptExpectation::ExpectedNoGo,
            ObservedReceiptStatus::DriftDetected,
            BlockerSeverity::Critical,
            "wallet-visible forced-exit state must match expected no-go receipt state",
        ),
        ObservedReceiptIngestRecord::new(
            4,
            ObservedReceiptLane::OperatorEvidenceMismatch,
            ReceiptExpectation::ExpectedNoGo,
            ObservedReceiptStatus::EvidenceDiverged,
            BlockerSeverity::Critical,
            "operator evidence receipt must match canonical exit spine evidence root",
        ),
        ObservedReceiptIngestRecord::new(
            5,
            ObservedReceiptLane::PrivacyAuditHold,
            ReceiptExpectation::ExpectedAuditHold,
            ObservedReceiptStatus::AuditHoldOpen,
            BlockerSeverity::High,
            "privacy leakage audit hold must be closed by independent review",
        ),
        ObservedReceiptIngestRecord::new(
            6,
            ObservedReceiptLane::PqAuditHold,
            ReceiptExpectation::ExpectedAuditHold,
            ObservedReceiptStatus::AuditHoldOpen,
            BlockerSeverity::High,
            "post-quantum verification audit hold must be closed by independent review",
        ),
        ObservedReceiptIngestRecord::new(
            7,
            ObservedReceiptLane::FailClosedNoGoReceipts,
            ReceiptExpectation::ExpectedNoGo,
            ObservedReceiptStatus::FailClosedNoGo,
            BlockerSeverity::Critical,
            "fail-closed no-go receipts must remain visible until every observed root matches",
        ),
        ObservedReceiptIngestRecord::new(
            8,
            ObservedReceiptLane::ReleaseGateStatus,
            ReceiptExpectation::ExpectedReleaseBlocked,
            ObservedReceiptStatus::ReleaseBlocked,
            BlockerSeverity::Critical,
            "production release gate stays blocked until all observed receipt roots match",
        ),
    ] {
        records.insert(record.record_id.clone(), record);
    }
    records
}

fn assemble_state(config: Config, records: BTreeMap<String, ObservedReceiptIngestRecord>) -> State {
    let summary = ReleaseGateSummary::new(&records);
    let missing_observed_receipts_root = lane_root(
        "missing_observed_receipts",
        &records,
        ObservedReceiptLane::MissingObservedReceipts,
    );
    let conformance_mismatch_root = lane_root(
        "conformance_mismatches",
        &records,
        ObservedReceiptLane::ConformanceMismatches,
    );
    let wallet_visible_drift_root = summary.wallet_visible_drift_root.clone();
    let operator_evidence_mismatch_root = summary.operator_evidence_mismatch_root.clone();
    let privacy_audit_hold_root = lane_root(
        "privacy_audit_hold",
        &records,
        ObservedReceiptLane::PrivacyAuditHold,
    );
    let pq_audit_hold_root = lane_root("pq_audit_hold", &records, ObservedReceiptLane::PqAuditHold);
    let privacy_pq_audit_hold_root = summary.privacy_pq_audit_hold_root.clone();
    let fail_closed_no_go_receipt_root = summary.fail_closed_no_go_receipt_root.clone();
    let blocker_severity_root = summary.blocker_severity_root.clone();
    let release_gate_status_root = summary.release_gate_status_root.clone();
    let config_root = config.state_root();
    let record_root = records_root(&records);
    let expected_receipt_root = summary.expected_receipt_root.clone();
    let observed_receipt_root = summary.observed_receipt_root.clone();
    let mismatch_root = summary.mismatch_root.clone();
    let summary_root = summary.state_root();
    let public_record = state_public_record(
        &config,
        &records,
        &summary,
        &missing_observed_receipts_root,
        &conformance_mismatch_root,
        &privacy_audit_hold_root,
        &pq_audit_hold_root,
        &config_root,
        &record_root,
        &summary_root,
    );
    let public_record_root = record_root("state_public_record", &public_record);
    let state_root = observed_receipt_ingest_state_root(
        &config_root,
        &record_root,
        &expected_receipt_root,
        &observed_receipt_root,
        &mismatch_root,
        &fail_closed_no_go_receipt_root,
        &blocker_severity_root,
        &release_gate_status_root,
        &summary_root,
        &public_record_root,
    );

    State {
        config,
        records,
        summary,
        missing_observed_receipts_root,
        conformance_mismatch_root,
        wallet_visible_drift_root,
        operator_evidence_mismatch_root,
        privacy_audit_hold_root,
        pq_audit_hold_root,
        privacy_pq_audit_hold_root,
        fail_closed_no_go_receipt_root,
        blocker_severity_root,
        release_gate_status_root,
        config_root,
        record_root,
        expected_receipt_root,
        observed_receipt_root,
        mismatch_root,
        summary_root,
        public_record_root,
        state_root,
    }
}

fn state_public_record(
    config: &Config,
    records: &BTreeMap<String, ObservedReceiptIngestRecord>,
    summary: &ReleaseGateSummary,
    missing_observed_receipts_root: &str,
    conformance_mismatch_root: &str,
    privacy_audit_hold_root: &str,
    pq_audit_hold_root: &str,
    config_root: &str,
    record_root: &str,
    summary_root: &str,
) -> Value {
    let records = records
        .values()
        .map(ObservedReceiptIngestRecord::public_record)
        .collect::<Vec<_>>();
    json!({
        "config": config.public_record(),
        "records": records,
        "summary": summary.public_record(),
        "roots": {
            "missing_observed_receipts_root": missing_observed_receipts_root,
            "conformance_mismatch_root": conformance_mismatch_root,
            "wallet_visible_drift_root": summary.wallet_visible_drift_root,
            "operator_evidence_mismatch_root": summary.operator_evidence_mismatch_root,
            "privacy_audit_hold_root": privacy_audit_hold_root,
            "pq_audit_hold_root": pq_audit_hold_root,
            "privacy_pq_audit_hold_root": summary.privacy_pq_audit_hold_root,
            "fail_closed_no_go_receipt_root": summary.fail_closed_no_go_receipt_root,
            "blocker_severity_root": summary.blocker_severity_root,
            "release_gate_status_root": summary.release_gate_status_root,
            "config_root": config_root,
            "record_root": record_root,
            "expected_receipt_root": summary.expected_receipt_root,
            "observed_receipt_root": summary.observed_receipt_root,
            "mismatch_root": summary.mismatch_root,
            "summary_root": summary_root,
        },
        "release_gate": {
            "decision": summary.decision,
            "production_release_allowed": config.production_release_allowed,
            "blocked_until_all_observed_roots_match": true,
        },
    })
}

fn records_root(records: &BTreeMap<String, ObservedReceiptIngestRecord>) -> String {
    let leaves = records
        .values()
        .map(ObservedReceiptIngestRecord::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-OBSERVED-RECEIPT-INGEST-RECORDS",
        &leaves,
    )
}

fn expected_receipts_root(records: &BTreeMap<String, ObservedReceiptIngestRecord>) -> String {
    let leaves = records
        .values()
        .map(|record| {
            json!({
                "record_id": record.record_id,
                "sequence": record.sequence,
                "lane": record.lane,
                "expectation": record.expectation,
                "expected_root": record.expected_root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-OBSERVED-RECEIPT-INGEST-EXPECTED",
        &leaves,
    )
}

fn observed_receipts_root(records: &BTreeMap<String, ObservedReceiptIngestRecord>) -> String {
    let leaves = records
        .values()
        .map(|record| {
            json!({
                "record_id": record.record_id,
                "sequence": record.sequence,
                "lane": record.lane,
                "status": record.status,
                "observed_root": record.observed_root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-OBSERVED-RECEIPT-INGEST-OBSERVED",
        &leaves,
    )
}

fn mismatch_receipts_root(records: &BTreeMap<String, ObservedReceiptIngestRecord>) -> String {
    let leaves = records
        .values()
        .filter(|record| !record.roots_match)
        .map(|record| {
            json!({
                "record_id": record.record_id,
                "lane": record.lane,
                "expected_root": record.expected_root,
                "observed_root": record.observed_root,
                "release_blocking": record.release_blocking,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-OBSERVED-RECEIPT-INGEST-MISMATCH",
        &leaves,
    )
}

fn lane_root(
    kind: &str,
    records: &BTreeMap<String, ObservedReceiptIngestRecord>,
    lane: ObservedReceiptLane,
) -> String {
    let leaves = records
        .values()
        .filter(|record| record.lane == lane)
        .map(ObservedReceiptIngestRecord::public_record)
        .collect::<Vec<_>>();
    merkle_root(
        &format!(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-OBSERVED-RECEIPT-INGEST-LANE-{kind}"
        ),
        &leaves,
    )
}

fn blocker_severity_root(records: &BTreeMap<String, ObservedReceiptIngestRecord>) -> String {
    let leaves = records
        .values()
        .map(|record| {
            json!({
                "record_id": record.record_id,
                "lane": record.lane,
                "severity": record.severity,
                "release_blocking": record.release_blocking,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-OBSERVED-RECEIPT-INGEST-BLOCKER-SEVERITY",
        &leaves,
    )
}

fn combined_audit_hold_root(privacy_audit_root: &str, pq_audit_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-OBSERVED-RECEIPT-INGEST-PRIVACY-PQ-AUDIT-HOLD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(privacy_audit_root),
            HashPart::Str(pq_audit_root),
            HashPart::Str(bool_str(true)),
        ],
        32,
    )
}

fn release_gate_status_root(
    expected_receipt_root: &str,
    observed_receipt_root: &str,
    mismatch_root: &str,
    fail_closed_no_go_receipt_root: &str,
    blocker_severity_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-OBSERVED-RECEIPT-INGEST-RELEASE-GATE-STATUS",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(ReleaseGateDecision::BlockProductionRelease.as_str()),
            HashPart::Str(expected_receipt_root),
            HashPart::Str(observed_receipt_root),
            HashPart::Str(mismatch_root),
            HashPart::Str(fail_closed_no_go_receipt_root),
            HashPart::Str(blocker_severity_root),
            HashPart::Str(bool_str(false)),
            HashPart::Str(bool_str(true)),
        ],
        32,
    )
}

fn expected_receipt_root(
    sequence: u64,
    lane: ObservedReceiptLane,
    expectation: ReceiptExpectation,
    required_clearance: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-OBSERVED-RECEIPT-INGEST-EXPECTED-RECEIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(lane.as_str()),
            HashPart::Str(expectation.as_str()),
            HashPart::Str(required_clearance),
            HashPart::Str(bool_str(true)),
        ],
        32,
    )
}

fn observed_receipt_root(
    sequence: u64,
    lane: ObservedReceiptLane,
    status: ObservedReceiptStatus,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-OBSERVED-RECEIPT-INGEST-OBSERVED-RECEIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(lane.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str("observed-runtime-receipt-not-yet-conformant"),
            HashPart::Str(bool_str(false)),
        ],
        32,
    )
}

fn receipt_ingest_root(
    sequence: u64,
    lane: ObservedReceiptLane,
    expectation: ReceiptExpectation,
    status: ObservedReceiptStatus,
    severity: BlockerSeverity,
    expected_root: &str,
    observed_root: &str,
    roots_match: bool,
    release_blocking: bool,
    required_clearance: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-OBSERVED-RECEIPT-INGEST-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(lane.as_str()),
            HashPart::Str(expectation.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Str(expected_root),
            HashPart::Str(observed_root),
            HashPart::Str(bool_str(roots_match)),
            HashPart::Str(bool_str(release_blocking)),
            HashPart::Str(required_clearance),
        ],
        32,
    )
}

fn receipt_record_id(
    sequence: u64,
    lane: ObservedReceiptLane,
    receipt_ingest_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-OBSERVED-RECEIPT-INGEST-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(lane.as_str()),
            HashPart::Str(receipt_ingest_root),
        ],
        16,
    )
}

fn observed_receipt_ingest_state_root(
    config_root: &str,
    record_root: &str,
    expected_receipt_root: &str,
    observed_receipt_root: &str,
    mismatch_root: &str,
    fail_closed_no_go_receipt_root: &str,
    blocker_severity_root: &str,
    release_gate_status_root: &str,
    summary_root: &str,
    public_record_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-OBSERVED-RECEIPT-INGEST-STATE",
        &[
            HashPart::Str(config_root),
            HashPart::Str(record_root),
            HashPart::Str(expected_receipt_root),
            HashPart::Str(observed_receipt_root),
            HashPart::Str(mismatch_root),
            HashPart::Str(fail_closed_no_go_receipt_root),
            HashPart::Str(blocker_severity_root),
            HashPart::Str(release_gate_status_root),
            HashPart::Str(summary_root),
            HashPart::Str(public_record_root),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-OBSERVED-RECEIPT-INGEST-CANONICAL-RECORD",
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
