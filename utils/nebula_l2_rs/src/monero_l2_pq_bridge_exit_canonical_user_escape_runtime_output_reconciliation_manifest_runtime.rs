use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeRuntimeOutputReconciliationManifestRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_RUNTIME_OUTPUT_RECONCILIATION_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-runtime-output-reconciliation-manifest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_RUNTIME_OUTPUT_RECONCILIATION_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const RECONCILIATION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-runtime-output-reconciliation-suite-v1";
pub const HANDLER_BOUND_EXECUTION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-handler-bound-execution-suite-v1";
pub const DEFAULT_RECONCILIATION_ID: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-runtime-output-reconciliation-devnet-v1";
pub const DEFAULT_MAX_RUNTIME_LAG_BLOCKS: u64 = 4;
pub const DEFAULT_MIN_MATCH_BPS: u64 = 10_000;
pub const DEFAULT_MAX_METADATA_UNITS: u64 = 2;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-runtime-output-reconciliation-manifest";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationLane {
    DepositLock,
    PrivateNote,
    SettlementReceipt,
    ReleaseVerification,
    AdversarialGap,
    WalletRunbook,
    RuntimeGate,
}

impl ReconciliationLane {
    pub fn all() -> [Self; 7] {
        [
            Self::DepositLock,
            Self::PrivateNote,
            Self::SettlementReceipt,
            Self::ReleaseVerification,
            Self::AdversarialGap,
            Self::WalletRunbook,
            Self::RuntimeGate,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLock => "deposit_lock",
            Self::PrivateNote => "private_note",
            Self::SettlementReceipt => "settlement_receipt",
            Self::ReleaseVerification => "release_verification",
            Self::AdversarialGap => "adversarial_gap",
            Self::WalletRunbook => "wallet_runbook",
            Self::RuntimeGate => "runtime_gate",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::DepositLock => "Deposit lock runtime output reconciliation",
            Self::PrivateNote => "Private note runtime output reconciliation",
            Self::SettlementReceipt => "Settlement receipt runtime output reconciliation",
            Self::ReleaseVerification => "Release verification runtime output reconciliation",
            Self::AdversarialGap => "Adversarial gap runtime output reconciliation",
            Self::WalletRunbook => "Wallet runbook runtime output reconciliation",
            Self::RuntimeGate => "Runtime gate output reconciliation",
        }
    }

    pub fn weight_bps(self) -> u64 {
        match self {
            Self::DepositLock => 1_700,
            Self::PrivateNote => 1_500,
            Self::SettlementReceipt => 1_400,
            Self::ReleaseVerification => 1_700,
            Self::AdversarialGap => 1_100,
            Self::WalletRunbook => 1_000,
            Self::RuntimeGate => 1_600,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeOutputSource {
    HandlerBoundExecution,
    MoneroWatcher,
    PqWatcherQuorum,
    WalletReplay,
    ReserveObserver,
    ReleaseBroadcaster,
    CargoRuntimeHarness,
}

impl RuntimeOutputSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HandlerBoundExecution => "handler_bound_execution",
            Self::MoneroWatcher => "monero_watcher",
            Self::PqWatcherQuorum => "pq_watcher_quorum",
            Self::WalletReplay => "wallet_replay",
            Self::ReserveObserver => "reserve_observer",
            Self::ReleaseBroadcaster => "release_broadcaster",
            Self::CargoRuntimeHarness => "cargo_runtime_harness",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationStatus {
    Matched,
    HeldForRuntimeOutput,
    HeldForMismatch,
    Rejected,
}

impl ReconciliationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::HeldForRuntimeOutput => "held_for_runtime_output",
            Self::HeldForMismatch => "held_for_mismatch",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestVerdict {
    RuntimeReady,
    HeldForRuntimeOutputs,
    HeldForMismatches,
    Rejected,
}

impl ManifestVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeReady => "runtime_ready",
            Self::HeldForRuntimeOutputs => "held_for_runtime_outputs",
            Self::HeldForMismatches => "held_for_mismatches",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchSeverity {
    None,
    Review,
    ReleaseBlocking,
    Slashable,
}

impl MismatchSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Review => "review",
            Self::ReleaseBlocking => "release_blocking",
            Self::Slashable => "slashable",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub reconciliation_suite: String,
    pub handler_bound_execution_suite: String,
    pub reconciliation_id: String,
    pub require_runtime_outputs: bool,
    pub require_monero_watcher_output: bool,
    pub require_pq_quorum_output: bool,
    pub require_wallet_replay_output: bool,
    pub require_reserve_output: bool,
    pub require_release_broadcast_output: bool,
    pub hold_when_cargo_runtime_deferred: bool,
    pub fail_closed: bool,
    pub production_release_allowed: bool,
    pub min_match_bps: u64,
    pub max_runtime_lag_blocks: u64,
    pub max_metadata_units: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            reconciliation_suite: RECONCILIATION_SUITE.to_string(),
            handler_bound_execution_suite: HANDLER_BOUND_EXECUTION_SUITE.to_string(),
            reconciliation_id: DEFAULT_RECONCILIATION_ID.to_string(),
            require_runtime_outputs: true,
            require_monero_watcher_output: true,
            require_pq_quorum_output: true,
            require_wallet_replay_output: true,
            require_reserve_output: true,
            require_release_broadcast_output: true,
            hold_when_cargo_runtime_deferred: true,
            fail_closed: true,
            production_release_allowed: false,
            min_match_bps: DEFAULT_MIN_MATCH_BPS,
            max_runtime_lag_blocks: DEFAULT_MAX_RUNTIME_LAG_BLOCKS,
            max_metadata_units: DEFAULT_MAX_METADATA_UNITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "reconciliation_suite": self.reconciliation_suite,
            "handler_bound_execution_suite": self.handler_bound_execution_suite,
            "reconciliation_id": self.reconciliation_id,
            "require_runtime_outputs": self.require_runtime_outputs,
            "require_monero_watcher_output": self.require_monero_watcher_output,
            "require_pq_quorum_output": self.require_pq_quorum_output,
            "require_wallet_replay_output": self.require_wallet_replay_output,
            "require_reserve_output": self.require_reserve_output,
            "require_release_broadcast_output": self.require_release_broadcast_output,
            "hold_when_cargo_runtime_deferred": self.hold_when_cargo_runtime_deferred,
            "fail_closed": self.fail_closed,
            "production_release_allowed": self.production_release_allowed,
            "min_match_bps": self.min_match_bps,
            "max_runtime_lag_blocks": self.max_runtime_lag_blocks,
            "max_metadata_units": self.max_metadata_units,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeExpectation {
    pub source: RuntimeOutputSource,
    pub expected_root: String,
    pub observed_root: Option<String>,
    pub observation_lag_blocks: u64,
    pub required: bool,
}

impl RuntimeExpectation {
    pub fn devnet(lane: ReconciliationLane, source: RuntimeOutputSource, required: bool) -> Self {
        let expected_root = runtime_hash(
            "EXPECTED_RUNTIME_OUTPUT",
            &[
                HashPart::Str(lane.as_str()),
                HashPart::Str(source.as_str()),
                HashPart::Str(DEFAULT_RECONCILIATION_ID),
            ],
        );
        let observed_root = match source {
            RuntimeOutputSource::HandlerBoundExecution => Some(expected_root.clone()),
            RuntimeOutputSource::CargoRuntimeHarness => None,
            _ => None,
        };

        Self {
            source,
            expected_root,
            observed_root,
            observation_lag_blocks: 0,
            required,
        }
    }

    pub fn matched(&self) -> bool {
        matches!(self.observed_root.as_ref(), Some(root) if root == &self.expected_root)
    }

    pub fn missing(&self) -> bool {
        self.required && self.observed_root.is_none()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "source": self.source.as_str(),
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "observation_lag_blocks": self.observation_lag_blocks,
            "required": self.required,
            "matched": self.matched(),
            "missing": self.missing(),
        })
    }

    pub fn state_root(&self) -> String {
        runtime_hash(
            "RUNTIME_EXPECTATION",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeMismatch {
    pub mismatch_id: String,
    pub lane: ReconciliationLane,
    pub source: RuntimeOutputSource,
    pub expected_root: String,
    pub observed_root: Option<String>,
    pub severity: MismatchSeverity,
    pub release_blocking: bool,
    pub wallet_visible: bool,
}

impl RuntimeMismatch {
    pub fn from_expectation(
        lane: ReconciliationLane,
        expectation: &RuntimeExpectation,
    ) -> Option<Self> {
        if expectation.matched() {
            return None;
        }

        let severity = if expectation.observed_root.is_none() {
            MismatchSeverity::ReleaseBlocking
        } else {
            MismatchSeverity::Slashable
        };
        let mismatch_id = runtime_hash(
            "RUNTIME_MISMATCH_ID",
            &[
                HashPart::Str(lane.as_str()),
                HashPart::Str(expectation.source.as_str()),
                HashPart::Str(&expectation.expected_root),
                HashPart::Json(&json!(expectation.observed_root)),
            ],
        );

        Some(Self {
            mismatch_id,
            lane,
            source: expectation.source,
            expected_root: expectation.expected_root.clone(),
            observed_root: expectation.observed_root.clone(),
            severity,
            release_blocking: true,
            wallet_visible: true,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "mismatch_id": self.mismatch_id,
            "lane": self.lane.as_str(),
            "source": self.source.as_str(),
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "severity": self.severity.as_str(),
            "release_blocking": self.release_blocking,
            "wallet_visible": self.wallet_visible,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_hash("RUNTIME_MISMATCH", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LaneReconciliation {
    pub lane: ReconciliationLane,
    pub label: String,
    pub handler_bound_execution_root: String,
    pub expectations: Vec<RuntimeExpectation>,
    pub mismatch_root: String,
    pub status: ReconciliationStatus,
    pub release_hold_reason: String,
    pub weight_bps: u64,
}

impl LaneReconciliation {
    pub fn devnet(lane: ReconciliationLane, config: &Config) -> Self {
        let handler_bound_execution_root = runtime_hash(
            "HANDLER_BOUND_EXECUTION_ROOT",
            &[
                HashPart::Str(lane.as_str()),
                HashPart::Str(&config.handler_bound_execution_suite),
            ],
        );
        let expectations = lane_expectations(lane, config);
        let mismatches = expectations
            .iter()
            .filter_map(|expectation| RuntimeMismatch::from_expectation(lane, expectation))
            .collect::<Vec<_>>();
        let mismatch_root = merkle_root(
            "RUNTIME_OUTPUT_RECONCILIATION_MISMATCHES",
            &mismatches
                .iter()
                .map(RuntimeMismatch::public_record)
                .collect::<Vec<_>>(),
        );
        let status = if mismatches.is_empty() {
            ReconciliationStatus::Matched
        } else if mismatches
            .iter()
            .any(|mismatch| mismatch.observed_root.is_some())
        {
            ReconciliationStatus::HeldForMismatch
        } else {
            ReconciliationStatus::HeldForRuntimeOutput
        };
        let release_hold_reason = match status {
            ReconciliationStatus::Matched => {
                "lane runtime outputs matched expected roots".to_string()
            }
            ReconciliationStatus::HeldForRuntimeOutput => {
                "missing process-fed runtime outputs keep release held".to_string()
            }
            ReconciliationStatus::HeldForMismatch => {
                "observed runtime output mismatch keeps release held".to_string()
            }
            ReconciliationStatus::Rejected => "runtime output rejected".to_string(),
        };

        Self {
            lane,
            label: lane.label().to_string(),
            handler_bound_execution_root,
            expectations,
            mismatch_root,
            status,
            release_hold_reason,
            weight_bps: lane.weight_bps(),
        }
    }

    pub fn mismatch_records(&self) -> Vec<RuntimeMismatch> {
        self.expectations
            .iter()
            .filter_map(|expectation| RuntimeMismatch::from_expectation(self.lane, expectation))
            .collect()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "label": self.label,
            "handler_bound_execution_root": self.handler_bound_execution_root,
            "expectations": self.expectations.iter().map(RuntimeExpectation::public_record).collect::<Vec<_>>(),
            "mismatch_root": self.mismatch_root,
            "status": self.status.as_str(),
            "release_hold_reason": self.release_hold_reason,
            "weight_bps": self.weight_bps,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_hash(
            "LANE_RECONCILIATION",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManifestBlocker {
    pub blocker_id: String,
    pub lane: ReconciliationLane,
    pub source: RuntimeOutputSource,
    pub reason: String,
    pub severity: MismatchSeverity,
}

impl ManifestBlocker {
    pub fn from_mismatch(mismatch: &RuntimeMismatch) -> Self {
        let reason = if mismatch.observed_root.is_none() {
            format!("missing {} runtime output", mismatch.source.as_str())
        } else {
            format!(
                "{} runtime output does not match expected root",
                mismatch.source.as_str()
            )
        };
        let blocker_id = runtime_hash(
            "MANIFEST_BLOCKER_ID",
            &[
                HashPart::Str(mismatch.lane.as_str()),
                HashPart::Str(mismatch.source.as_str()),
                HashPart::Str(&mismatch.mismatch_id),
            ],
        );

        Self {
            blocker_id,
            lane: mismatch.lane,
            source: mismatch.source,
            reason,
            severity: mismatch.severity,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "lane": self.lane.as_str(),
            "source": self.source.as_str(),
            "reason": self.reason,
            "severity": self.severity.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        runtime_hash("MANIFEST_BLOCKER", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub lanes: Vec<LaneReconciliation>,
    pub blockers: Vec<ManifestBlocker>,
    pub expectation_root: String,
    pub lane_root: String,
    pub blocker_root: String,
    pub matched_weight_bps: u64,
    pub total_weight_bps: u64,
    pub verdict: ManifestVerdict,
    pub production_release_allowed: bool,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let lanes = ReconciliationLane::all()
            .into_iter()
            .map(|lane| LaneReconciliation::devnet(lane, &config))
            .collect::<Vec<_>>();
        Self::from_lanes(config, lanes)
    }

    pub fn from_lanes(config: Config, lanes: Vec<LaneReconciliation>) -> Self {
        let blockers = lanes
            .iter()
            .flat_map(LaneReconciliation::mismatch_records)
            .map(|mismatch| ManifestBlocker::from_mismatch(&mismatch))
            .collect::<Vec<_>>();
        let expectation_root = merkle_root(
            "RUNTIME_OUTPUT_RECONCILIATION_EXPECTATIONS",
            &lanes
                .iter()
                .flat_map(|lane| {
                    lane.expectations
                        .iter()
                        .map(RuntimeExpectation::public_record)
                })
                .collect::<Vec<_>>(),
        );
        let lane_root = merkle_root(
            "RUNTIME_OUTPUT_RECONCILIATION_LANES",
            &lanes
                .iter()
                .map(LaneReconciliation::public_record)
                .collect::<Vec<_>>(),
        );
        let blocker_root = merkle_root(
            "RUNTIME_OUTPUT_RECONCILIATION_BLOCKERS",
            &blockers
                .iter()
                .map(ManifestBlocker::public_record)
                .collect::<Vec<_>>(),
        );
        let total_weight_bps = lanes.iter().map(|lane| lane.weight_bps).sum::<u64>();
        let matched_weight_bps = lanes
            .iter()
            .filter(|lane| lane.status == ReconciliationStatus::Matched)
            .map(|lane| lane.weight_bps)
            .sum::<u64>();
        let verdict = if blockers.is_empty() && matched_weight_bps >= config.min_match_bps {
            ManifestVerdict::RuntimeReady
        } else if blockers
            .iter()
            .any(|blocker| blocker.severity == MismatchSeverity::Slashable)
        {
            ManifestVerdict::HeldForMismatches
        } else {
            ManifestVerdict::HeldForRuntimeOutputs
        };
        let production_release_allowed =
            config.production_release_allowed && verdict == ManifestVerdict::RuntimeReady;

        Self {
            config,
            lanes,
            blockers,
            expectation_root,
            lane_root,
            blocker_root,
            matched_weight_bps,
            total_weight_bps,
            verdict,
            production_release_allowed,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "lanes": self.lanes.iter().map(LaneReconciliation::public_record).collect::<Vec<_>>(),
            "blockers": self.blockers.iter().map(ManifestBlocker::public_record).collect::<Vec<_>>(),
            "expectation_root": self.expectation_root,
            "lane_root": self.lane_root,
            "blocker_root": self.blocker_root,
            "matched_weight_bps": self.matched_weight_bps,
            "total_weight_bps": self.total_weight_bps,
            "verdict": self.verdict.as_str(),
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        runtime_hash(
            "STATE",
            &[
                HashPart::Json(&self.config.public_record()),
                HashPart::Str(&self.expectation_root),
                HashPart::Str(&self.lane_root),
                HashPart::Str(&self.blocker_root),
                HashPart::U64(self.matched_weight_bps),
                HashPart::U64(self.total_weight_bps),
                HashPart::Str(self.verdict.as_str()),
            ],
        )
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

fn lane_expectations(lane: ReconciliationLane, config: &Config) -> Vec<RuntimeExpectation> {
    let mut expectations = vec![RuntimeExpectation::devnet(
        lane,
        RuntimeOutputSource::HandlerBoundExecution,
        true,
    )];

    match lane {
        ReconciliationLane::DepositLock => {
            expectations.push(RuntimeExpectation::devnet(
                lane,
                RuntimeOutputSource::MoneroWatcher,
                config.require_monero_watcher_output,
            ));
            expectations.push(RuntimeExpectation::devnet(
                lane,
                RuntimeOutputSource::PqWatcherQuorum,
                config.require_pq_quorum_output,
            ));
        }
        ReconciliationLane::PrivateNote => {
            expectations.push(RuntimeExpectation::devnet(
                lane,
                RuntimeOutputSource::WalletReplay,
                config.require_wallet_replay_output,
            ));
        }
        ReconciliationLane::SettlementReceipt => {
            expectations.push(RuntimeExpectation::devnet(
                lane,
                RuntimeOutputSource::ReserveObserver,
                config.require_reserve_output,
            ));
        }
        ReconciliationLane::ReleaseVerification => {
            expectations.push(RuntimeExpectation::devnet(
                lane,
                RuntimeOutputSource::ReleaseBroadcaster,
                config.require_release_broadcast_output,
            ));
            expectations.push(RuntimeExpectation::devnet(
                lane,
                RuntimeOutputSource::PqWatcherQuorum,
                config.require_pq_quorum_output,
            ));
        }
        ReconciliationLane::AdversarialGap => {
            expectations.push(RuntimeExpectation::devnet(
                lane,
                RuntimeOutputSource::MoneroWatcher,
                config.require_monero_watcher_output,
            ));
            expectations.push(RuntimeExpectation::devnet(
                lane,
                RuntimeOutputSource::ReserveObserver,
                config.require_reserve_output,
            ));
        }
        ReconciliationLane::WalletRunbook => {
            expectations.push(RuntimeExpectation::devnet(
                lane,
                RuntimeOutputSource::WalletReplay,
                config.require_wallet_replay_output,
            ));
        }
        ReconciliationLane::RuntimeGate => {
            expectations.push(RuntimeExpectation::devnet(
                lane,
                RuntimeOutputSource::CargoRuntimeHarness,
                config.require_runtime_outputs,
            ));
        }
    }

    expectations
}

fn runtime_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        DOMAIN,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Json(&json!(parts
                .iter()
                .map(hash_part_record)
                .collect::<Vec<_>>())),
        ],
        32,
    )
}

fn hash_part_record(part: &HashPart<'_>) -> Value {
    match part {
        HashPart::Bytes(value) => json!({
            "kind": "bytes",
            "value": hex::encode(value),
        }),
        HashPart::Str(value) => json!({
            "kind": "str",
            "value": value,
        }),
        HashPart::U64(value) => json!({
            "kind": "u64",
            "value": value,
        }),
        HashPart::Int(value) => json!({
            "kind": "int",
            "value": value.to_string(),
        }),
        HashPart::Json(value) => json!({
            "kind": "json",
            "value": value,
        }),
    }
}
