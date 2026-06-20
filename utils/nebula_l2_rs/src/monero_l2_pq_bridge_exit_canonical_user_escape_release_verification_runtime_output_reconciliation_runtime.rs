use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeReleaseVerificationRuntimeOutputReconciliationRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_RELEASE_VERIFICATION_RUNTIME_OUTPUT_RECONCILIATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-release-verification-runtime-output-reconciliation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_RELEASE_VERIFICATION_RUNTIME_OUTPUT_RECONCILIATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECONCILIATION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-runtime-output-reconciliation-v1";
pub const DEFAULT_NETWORK: &str = "devnet";
pub const DEFAULT_ESCAPE_ID: &str =
    "canonical-user-escape-runtime-output-reconciliation-devnet-0001";
pub const DEFAULT_HANDLER_SESSION_ID: &str =
    "canonical-user-escape-release-verification-handler-bound-execution-session-0001";
pub const DEFAULT_RECONCILIATION_ID: &str =
    "canonical-user-escape-release-verification-runtime-output-reconciliation-devnet-v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchSeverity {
    None,
    Advisory,
    Hold,
    Critical,
}

impl MismatchSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Advisory => "advisory",
            Self::Hold => "hold",
            Self::Critical => "critical",
        }
    }

    pub fn release_blocking(self) -> bool {
        matches!(self, Self::Hold | Self::Critical)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationVerdict {
    Reconciled,
    ReleaseHeld,
    ReleaseRejected,
}

impl ReconciliationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reconciled => "reconciled",
            Self::ReleaseHeld => "release_held",
            Self::ReleaseRejected => "release_rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub reconciliation_suite: String,
    pub network: String,
    pub escape_id: String,
    pub handler_session_id: String,
    pub reconciliation_id: String,
    pub max_advisory_mismatches: u64,
    pub fail_closed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            reconciliation_suite: RECONCILIATION_SUITE.to_string(),
            network: DEFAULT_NETWORK.to_string(),
            escape_id: DEFAULT_ESCAPE_ID.to_string(),
            handler_session_id: DEFAULT_HANDLER_SESSION_ID.to_string(),
            reconciliation_id: DEFAULT_RECONCILIATION_ID.to_string(),
            max_advisory_mismatches: 0,
            fail_closed: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "reconciliation_suite": self.reconciliation_suite,
            "network": self.network,
            "escape_id": self.escape_id,
            "handler_session_id": self.handler_session_id,
            "reconciliation_id": self.reconciliation_id,
            "max_advisory_mismatches": self.max_advisory_mismatches,
            "fail_closed": bool_label(self.fail_closed)
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExpectedReleaseVerificationRoots {
    pub handler_binding_root: String,
    pub release_execution_root: String,
    pub verifier_root: String,
    pub monero_broadcast_root: String,
    pub custody_root: String,
    pub liquidity_root: String,
    pub pq_root: String,
    pub runtime_root: String,
}

impl ExpectedReleaseVerificationRoots {
    pub fn devnet(config: &Config) -> Self {
        Self {
            handler_binding_root: lane_root("expected-handler-binding", &config.escape_id),
            release_execution_root: lane_root("expected-release-execution", &config.escape_id),
            verifier_root: lane_root("expected-release-verifier", &config.escape_id),
            monero_broadcast_root: lane_root("expected-monero-broadcast", &config.escape_id),
            custody_root: lane_root("expected-custody", &config.escape_id),
            liquidity_root: lane_root("expected-liquidity", &config.escape_id),
            pq_root: lane_root("expected-pq-custody", &config.escape_id),
            runtime_root: lane_root("expected-runtime-output", &config.escape_id),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "handler_binding_root": self.handler_binding_root,
            "release_execution_root": self.release_execution_root,
            "verifier_root": self.verifier_root,
            "monero_broadcast_root": self.monero_broadcast_root,
            "custody_root": self.custody_root,
            "liquidity_root": self.liquidity_root,
            "pq_root": self.pq_root,
            "runtime_root": self.runtime_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("expected_release_verification_roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservedRuntimeRoots {
    pub monero_broadcast_root: String,
    pub custody_root: String,
    pub liquidity_root: String,
    pub pq_root: String,
    pub runtime_root: String,
}

impl ObservedRuntimeRoots {
    pub fn devnet(expected: &ExpectedReleaseVerificationRoots) -> Self {
        Self {
            monero_broadcast_root: expected.monero_broadcast_root.clone(),
            custody_root: expected.custody_root.clone(),
            liquidity_root: expected.liquidity_root.clone(),
            pq_root: expected.pq_root.clone(),
            runtime_root: expected.runtime_root.clone(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "monero_broadcast_root": self.monero_broadcast_root,
            "custody_root": self.custody_root,
            "liquidity_root": self.liquidity_root,
            "pq_root": self.pq_root,
            "runtime_root": self.runtime_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("observed_runtime_roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootMismatch {
    pub lane: String,
    pub expected_root: String,
    pub observed_root: String,
    pub severity: MismatchSeverity,
    pub fail_closed: bool,
    pub mismatch_root: String,
}

impl RootMismatch {
    pub fn new(
        lane: &str,
        expected_root: &str,
        observed_root: &str,
        severity: MismatchSeverity,
        fail_closed: bool,
    ) -> Self {
        let mismatch_root = domain_hash(
            "monero-l2-pq-bridge-user-escape-runtime-output-reconciliation-mismatch",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(lane),
                HashPart::Str(expected_root),
                HashPart::Str(observed_root),
                HashPart::Str(severity.as_str()),
                HashPart::Str(bool_label(fail_closed)),
            ],
            32,
        );

        Self {
            lane: lane.to_string(),
            expected_root: expected_root.to_string(),
            observed_root: observed_root.to_string(),
            severity,
            fail_closed,
            mismatch_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "severity": self.severity.as_str(),
            "fail_closed": bool_label(self.fail_closed),
            "mismatch_root": self.mismatch_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("root_mismatch", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FailClosedReleaseHold {
    pub active: bool,
    pub reason: String,
    pub highest_severity: MismatchSeverity,
    pub mismatch_count: u64,
    pub hold_root: String,
}

impl FailClosedReleaseHold {
    pub fn from_mismatches(config: &Config, mismatches: &[RootMismatch]) -> Self {
        let highest_severity = mismatches
            .iter()
            .fold(MismatchSeverity::None, |current, mismatch| {
                current.max(mismatch.severity)
            });
        let mismatch_count = mismatches.len() as u64;
        let active = config.fail_closed
            && (highest_severity.release_blocking()
                || mismatch_count > config.max_advisory_mismatches);
        let reason = if active {
            "fail-closed release hold active until runtime output roots reconcile"
        } else {
            "runtime output roots reconcile with handler-bound release verification records"
        };
        let mismatch_root = mismatch_set_root(mismatches);
        let hold_root = domain_hash(
            "monero-l2-pq-bridge-user-escape-runtime-output-reconciliation-fail-closed-hold",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(bool_label(active)),
                HashPart::Str(reason),
                HashPart::Str(highest_severity.as_str()),
                HashPart::U64(mismatch_count),
                HashPart::Str(&mismatch_root),
            ],
            32,
        );

        Self {
            active,
            reason: reason.to_string(),
            highest_severity,
            mismatch_count,
            hold_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "active": bool_label(self.active),
            "reason": self.reason,
            "highest_severity": self.highest_severity.as_str(),
            "mismatch_count": self.mismatch_count,
            "hold_root": self.hold_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("fail_closed_release_hold", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReconciliationRecord {
    pub verdict: ReconciliationVerdict,
    pub release_permitted: bool,
    pub mismatch_count: u64,
    pub critical_mismatch_count: u64,
    pub hold_mismatch_count: u64,
    pub advisory_mismatch_count: u64,
    pub mismatch_root: String,
    pub fail_closed_hold_root: String,
    pub reconciliation_root: String,
}

impl ReconciliationRecord {
    pub fn from_mismatches(mismatches: &[RootMismatch], hold: &FailClosedReleaseHold) -> Self {
        let critical_mismatch_count = mismatches
            .iter()
            .filter(|mismatch| mismatch.severity == MismatchSeverity::Critical)
            .count() as u64;
        let hold_mismatch_count = mismatches
            .iter()
            .filter(|mismatch| mismatch.severity == MismatchSeverity::Hold)
            .count() as u64;
        let advisory_mismatch_count = mismatches
            .iter()
            .filter(|mismatch| mismatch.severity == MismatchSeverity::Advisory)
            .count() as u64;
        let mismatch_count = mismatches.len() as u64;
        let verdict = if critical_mismatch_count > 0 {
            ReconciliationVerdict::ReleaseRejected
        } else if hold.active {
            ReconciliationVerdict::ReleaseHeld
        } else {
            ReconciliationVerdict::Reconciled
        };
        let release_permitted =
            matches!(verdict, ReconciliationVerdict::Reconciled) && !hold.active;
        let mismatch_root = mismatch_set_root(mismatches);
        let fail_closed_hold_root = hold.hold_root.clone();
        let reconciliation_root = domain_hash(
            "monero-l2-pq-bridge-user-escape-runtime-output-reconciliation-verdict",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(verdict.as_str()),
                HashPart::Str(bool_label(release_permitted)),
                HashPart::U64(mismatch_count),
                HashPart::U64(critical_mismatch_count),
                HashPart::U64(hold_mismatch_count),
                HashPart::U64(advisory_mismatch_count),
                HashPart::Str(&mismatch_root),
                HashPart::Str(&fail_closed_hold_root),
            ],
            32,
        );

        Self {
            verdict,
            release_permitted,
            mismatch_count,
            critical_mismatch_count,
            hold_mismatch_count,
            advisory_mismatch_count,
            mismatch_root,
            fail_closed_hold_root,
            reconciliation_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "verdict": self.verdict.as_str(),
            "release_permitted": bool_label(self.release_permitted),
            "mismatch_count": self.mismatch_count,
            "critical_mismatch_count": self.critical_mismatch_count,
            "hold_mismatch_count": self.hold_mismatch_count,
            "advisory_mismatch_count": self.advisory_mismatch_count,
            "mismatch_root": self.mismatch_root,
            "fail_closed_hold_root": self.fail_closed_hold_root,
            "reconciliation_root": self.reconciliation_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("reconciliation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub expected_roots: ExpectedReleaseVerificationRoots,
    pub observed_roots: ObservedRuntimeRoots,
    pub mismatches: Vec<RootMismatch>,
    pub fail_closed_hold: FailClosedReleaseHold,
    pub reconciliation: ReconciliationRecord,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let expected_roots = ExpectedReleaseVerificationRoots::devnet(&config);
        let observed_roots = ObservedRuntimeRoots::devnet(&expected_roots);
        let mismatches = reconcile_roots(&config, &expected_roots, &observed_roots);
        let fail_closed_hold = FailClosedReleaseHold::from_mismatches(&config, &mismatches);
        let reconciliation = ReconciliationRecord::from_mismatches(&mismatches, &fail_closed_hold);

        Self {
            config,
            expected_roots,
            observed_roots,
            mismatches,
            fail_closed_hold,
            reconciliation,
        }
    }

    pub fn public_record(&self) -> Value {
        let mismatch_records = self
            .mismatches
            .iter()
            .map(RootMismatch::public_record)
            .collect::<Vec<_>>();

        json!({
            "config": self.config.public_record(),
            "expected_roots": self.expected_roots.public_record(),
            "observed_roots": self.observed_roots.public_record(),
            "mismatches": mismatch_records,
            "fail_closed_hold": self.fail_closed_hold.public_record(),
            "reconciliation": self.reconciliation.public_record(),
            "config_root": self.config.state_root(),
            "expected_roots_root": self.expected_roots.state_root(),
            "observed_roots_root": self.observed_roots.state_root(),
            "mismatch_root": self.reconciliation.mismatch_root,
            "fail_closed_hold_root": self.fail_closed_hold.hold_root,
            "reconciliation_root": self.reconciliation.reconciliation_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
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

fn reconcile_roots(
    config: &Config,
    expected: &ExpectedReleaseVerificationRoots,
    observed: &ObservedRuntimeRoots,
) -> Vec<RootMismatch> {
    [
        compare_root(
            config,
            "monero_broadcast",
            &expected.monero_broadcast_root,
            &observed.monero_broadcast_root,
            MismatchSeverity::Critical,
        ),
        compare_root(
            config,
            "custody",
            &expected.custody_root,
            &observed.custody_root,
            MismatchSeverity::Hold,
        ),
        compare_root(
            config,
            "liquidity",
            &expected.liquidity_root,
            &observed.liquidity_root,
            MismatchSeverity::Hold,
        ),
        compare_root(
            config,
            "pq",
            &expected.pq_root,
            &observed.pq_root,
            MismatchSeverity::Critical,
        ),
        compare_root(
            config,
            "runtime",
            &expected.runtime_root,
            &observed.runtime_root,
            MismatchSeverity::Critical,
        ),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
}

fn compare_root(
    config: &Config,
    lane: &str,
    expected_root: &str,
    observed_root: &str,
    severity: MismatchSeverity,
) -> Option<RootMismatch> {
    if expected_root == observed_root {
        None
    } else {
        Some(RootMismatch::new(
            lane,
            expected_root,
            observed_root,
            severity,
            config.fail_closed,
        ))
    }
}

fn mismatch_set_root(mismatches: &[RootMismatch]) -> String {
    let records = mismatches
        .iter()
        .map(RootMismatch::public_record)
        .collect::<Vec<_>>();

    merkle_root(
        "monero-l2-pq-bridge-user-escape-runtime-output-reconciliation-mismatches",
        &records,
    )
}

fn lane_root(lane: &str, escape_id: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-user-escape-runtime-output-reconciliation-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane),
            HashPart::Str(escape_id),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-user-escape-runtime-output-reconciliation-record",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn bool_label(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
