use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAdversarialGapRuntimeOutputReconciliationRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ADVERSARIAL_GAP_RUNTIME_OUTPUT_RECONCILIATION_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-user-escape-adversarial-gap-runtime-output-reconciliation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ADVERSARIAL_GAP_RUNTIME_OUTPUT_RECONCILIATION_RUNTIME_PROTOCOL_VERSION;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub lane_id: String,
    pub handler_bound_execution_lane: String,
    pub process_output_lane: String,
    pub reconciliation_policy: String,
    pub required_scenario_count: u64,
    pub reject_on_mismatch: u64,
    pub block_release_on_mismatch: u64,
    pub require_fail_closed_output: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            lane_id: "canonical_user_escape_adversarial_gap_runtime_output_reconciliation"
                .to_string(),
            handler_bound_execution_lane:
                "canonical_user_escape_adversarial_gap_handler_bound_execution".to_string(),
            process_output_lane: "future_process_fed_runtime_outputs".to_string(),
            reconciliation_policy: "deterministic_fail_closed_block_release_on_any_mismatch"
                .to_string(),
            required_scenario_count: 9,
            reject_on_mismatch: 1,
            block_release_on_mismatch: 1,
            require_fail_closed_output: 1,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "handler_bound_execution_lane": self.handler_bound_execution_lane,
            "process_output_lane": self.process_output_lane,
            "reconciliation_policy": self.reconciliation_policy,
            "required_scenario_count": self.required_scenario_count,
            "reject_on_mismatch": self.reject_on_mismatch,
            "block_release_on_mismatch": self.block_release_on_mismatch,
            "require_fail_closed_output": self.require_fail_closed_output,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdversarialScenario {
    Reorg,
    WatcherCollusion,
    SequencerHalt,
    Forgery,
    Pq,
    Liquidity,
    Metadata,
    Bypass,
    WalletMismatch,
}

impl AdversarialScenario {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reorg => "reorg",
            Self::WatcherCollusion => "watcher_collusion",
            Self::SequencerHalt => "sequencer_halt",
            Self::Forgery => "forgery",
            Self::Pq => "pq",
            Self::Liquidity => "liquidity",
            Self::Metadata => "metadata",
            Self::Bypass => "bypass",
            Self::WalletMismatch => "wallet_mismatch",
        }
    }

    pub fn expected_action(self) -> &'static str {
        match self {
            Self::Reorg => "hold_until_canonical_anchor_depth_restored",
            Self::WatcherCollusion => "hold_until_independent_watcher_quorum_rebound",
            Self::SequencerHalt => "hold_for_forced_exit_timeout_execution",
            Self::Forgery => "reject_forged_receipt_transcript",
            Self::Pq => "reject_stale_or_invalid_pq_epoch",
            Self::Liquidity => "hold_until_escape_reserve_replenished",
            Self::Metadata => "hold_for_metadata_redaction_and_reblind",
            Self::Bypass => "reject_challenge_window_bypass",
            Self::WalletMismatch => "reject_wallet_recovery_mismatch",
        }
    }

    pub fn expected_decision(self) -> &'static str {
        match self {
            Self::Reorg
            | Self::WatcherCollusion
            | Self::SequencerHalt
            | Self::Liquidity
            | Self::Metadata => "hold",
            Self::Forgery | Self::Pq | Self::Bypass | Self::WalletMismatch => "reject",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedFailClosedOutput {
    pub scenario: AdversarialScenario,
    pub handler_bound_execution_root: String,
    pub expected_decision: String,
    pub expected_handler_action: String,
    pub expected_release_allowed: u64,
    pub expected_output_digest: String,
}

impl ExpectedFailClosedOutput {
    pub fn new(scenario: AdversarialScenario, handler_bound_execution_root: &str) -> Self {
        let expected_decision = scenario.expected_decision().to_string();
        let expected_handler_action = scenario.expected_action().to_string();
        let expected_release_allowed = 0;
        let expected_output_digest = output_digest(
            scenario,
            handler_bound_execution_root,
            &expected_decision,
            &expected_handler_action,
            expected_release_allowed,
        );

        Self {
            scenario,
            handler_bound_execution_root: handler_bound_execution_root.to_string(),
            expected_decision,
            expected_handler_action,
            expected_release_allowed,
            expected_output_digest,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scenario": self.scenario.as_str(),
            "handler_bound_execution_root": self.handler_bound_execution_root,
            "expected_decision": self.expected_decision,
            "expected_handler_action": self.expected_handler_action,
            "expected_release_allowed": self.expected_release_allowed,
            "expected_output_digest": self.expected_output_digest,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("expected_fail_closed_output", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedRuntimeOutput {
    pub scenario: AdversarialScenario,
    pub handler_bound_execution_root: String,
    pub observed_decision: String,
    pub observed_handler_action: String,
    pub observed_release_allowed: u64,
    pub observed_output_digest: String,
    pub process_feed_root: String,
}

impl ObservedRuntimeOutput {
    pub fn matching(expected: &ExpectedFailClosedOutput, process_feed_label: &str) -> Self {
        let observed_output_digest = output_digest(
            expected.scenario,
            &expected.handler_bound_execution_root,
            &expected.expected_decision,
            &expected.expected_handler_action,
            expected.expected_release_allowed,
        );
        let process_feed_root = domain_hash(
            "MONERO-L2-PQ-ESCAPE-GAP-RUNTIME-OUTPUT-RECONCILIATION-PROCESS-FEED",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(expected.scenario.as_str()),
                HashPart::Str(process_feed_label),
                HashPart::Str(&observed_output_digest),
            ],
            32,
        );

        Self {
            scenario: expected.scenario,
            handler_bound_execution_root: expected.handler_bound_execution_root.clone(),
            observed_decision: expected.expected_decision.clone(),
            observed_handler_action: expected.expected_handler_action.clone(),
            observed_release_allowed: expected.expected_release_allowed,
            observed_output_digest,
            process_feed_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scenario": self.scenario.as_str(),
            "handler_bound_execution_root": self.handler_bound_execution_root,
            "observed_decision": self.observed_decision,
            "observed_handler_action": self.observed_handler_action,
            "observed_release_allowed": self.observed_release_allowed,
            "observed_output_digest": self.observed_output_digest,
            "process_feed_root": self.process_feed_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("observed_runtime_output", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchType {
    None,
    Scenario,
    HandlerBoundExecutionRoot,
    Decision,
    HandlerAction,
    ReleaseAllowed,
    OutputDigest,
    ProcessFeedMissing,
}

impl MismatchType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Scenario => "scenario",
            Self::HandlerBoundExecutionRoot => "handler_bound_execution_root",
            Self::Decision => "decision",
            Self::HandlerAction => "handler_action",
            Self::ReleaseAllowed => "release_allowed",
            Self::OutputDigest => "output_digest",
            Self::ProcessFeedMissing => "process_feed_missing",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    None,
    Recoverable,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Recoverable => "recoverable",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseBlocker {
    None,
    ReconciliationMismatch,
    FailClosedViolation,
    MissingProcessFeed,
}

impl ReleaseBlocker {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ReconciliationMismatch => "reconciliation_mismatch",
            Self::FailClosedViolation => "fail_closed_violation",
            Self::MissingProcessFeed => "missing_process_feed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationVerdict {
    pub scenario: AdversarialScenario,
    pub mismatch_type: MismatchType,
    pub severity: Severity,
    pub release_blocker: ReleaseBlocker,
    pub release_allowed: u64,
    pub verdict_digest: String,
}

impl ReconciliationVerdict {
    pub fn from_outputs(
        expected: &ExpectedFailClosedOutput,
        observed: &ObservedRuntimeOutput,
    ) -> Self {
        let mismatch_type = mismatch_type(expected, observed);
        let release_blocker = release_blocker(mismatch_type, observed.observed_release_allowed);
        let severity = severity(release_blocker, mismatch_type);
        let release_allowed = 0;
        let verdict_digest = domain_hash(
            "MONERO-L2-PQ-ESCAPE-GAP-RUNTIME-OUTPUT-RECONCILIATION-VERDICT-DIGEST",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(expected.scenario.as_str()),
                HashPart::Str(mismatch_type.as_str()),
                HashPart::Str(severity.as_str()),
                HashPart::Str(release_blocker.as_str()),
                HashPart::U64(release_allowed),
            ],
            32,
        );

        Self {
            scenario: expected.scenario,
            mismatch_type,
            severity,
            release_blocker,
            release_allowed,
            verdict_digest,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scenario": self.scenario.as_str(),
            "mismatch_type": self.mismatch_type.as_str(),
            "severity": self.severity.as_str(),
            "release_blocker": self.release_blocker.as_str(),
            "release_allowed": self.release_allowed,
            "verdict_digest": self.verdict_digest,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("reconciliation_verdict", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub expected_outputs: Vec<ExpectedFailClosedOutput>,
    pub observed_outputs: Vec<ObservedRuntimeOutput>,
    pub reconciliation_verdicts: Vec<ReconciliationVerdict>,
    pub expected_output_root: String,
    pub observed_output_root: String,
    pub verdict_root: String,
    pub mismatch_count: u64,
    pub critical_count: u64,
    pub release_blocker_count: u64,
}

impl State {
    pub fn new(
        config: Config,
        expected_outputs: Vec<ExpectedFailClosedOutput>,
        observed_outputs: Vec<ObservedRuntimeOutput>,
    ) -> Self {
        let reconciliation_verdicts = expected_outputs
            .iter()
            .zip(observed_outputs.iter())
            .map(|(expected, observed)| ReconciliationVerdict::from_outputs(expected, observed))
            .collect::<Vec<_>>();
        let expected_values = expected_outputs
            .iter()
            .map(ExpectedFailClosedOutput::public_record)
            .collect::<Vec<_>>();
        let observed_values = observed_outputs
            .iter()
            .map(ObservedRuntimeOutput::public_record)
            .collect::<Vec<_>>();
        let verdict_values = reconciliation_verdicts
            .iter()
            .map(ReconciliationVerdict::public_record)
            .collect::<Vec<_>>();
        let mismatch_count = reconciliation_verdicts
            .iter()
            .filter(|verdict| verdict.mismatch_type != MismatchType::None)
            .count() as u64;
        let critical_count = reconciliation_verdicts
            .iter()
            .filter(|verdict| verdict.severity == Severity::Critical)
            .count() as u64;
        let release_blocker_count = reconciliation_verdicts
            .iter()
            .filter(|verdict| verdict.release_blocker != ReleaseBlocker::None)
            .count() as u64;

        Self {
            config,
            expected_outputs,
            observed_outputs,
            reconciliation_verdicts,
            expected_output_root: merkle_root(
                "MONERO-L2-PQ-ESCAPE-GAP-RUNTIME-OUTPUT-RECONCILIATION-EXPECTED-OUTPUTS",
                &expected_values,
            ),
            observed_output_root: merkle_root(
                "MONERO-L2-PQ-ESCAPE-GAP-RUNTIME-OUTPUT-RECONCILIATION-OBSERVED-OUTPUTS",
                &observed_values,
            ),
            verdict_root: merkle_root(
                "MONERO-L2-PQ-ESCAPE-GAP-RUNTIME-OUTPUT-RECONCILIATION-VERDICTS",
                &verdict_values,
            ),
            mismatch_count,
            critical_count,
            release_blocker_count,
        }
    }

    pub fn devnet() -> Self {
        let expected_outputs = devnet_expected_outputs();
        let observed_outputs = expected_outputs
            .iter()
            .map(|expected| ObservedRuntimeOutput::matching(expected, "devnet_future_process_feed"))
            .collect::<Vec<_>>();

        Self::new(Config::default(), expected_outputs, observed_outputs)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "expected_output_root": self.expected_output_root,
            "observed_output_root": self.observed_output_root,
            "verdict_root": self.verdict_root,
            "mismatch_count": self.mismatch_count,
            "critical_count": self.critical_count,
            "release_blocker_count": self.release_blocker_count,
            "release_allowed": self.release_allowed(),
            "expected_outputs": self
                .expected_outputs
                .iter()
                .map(ExpectedFailClosedOutput::public_record)
                .collect::<Vec<_>>(),
            "observed_outputs": self
                .observed_outputs
                .iter()
                .map(ObservedRuntimeOutput::public_record)
                .collect::<Vec<_>>(),
            "reconciliation_verdicts": self
                .reconciliation_verdicts
                .iter()
                .map(ReconciliationVerdict::public_record)
                .collect::<Vec<_>>(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        let state_record = json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config_root": self.config.state_root(),
            "expected_output_root": self.expected_output_root,
            "observed_output_root": self.observed_output_root,
            "verdict_root": self.verdict_root,
            "mismatch_count": self.mismatch_count,
            "critical_count": self.critical_count,
            "release_blocker_count": self.release_blocker_count,
            "release_allowed": self.release_allowed(),
        });

        domain_hash(
            "MONERO-L2-PQ-ESCAPE-GAP-RUNTIME-OUTPUT-RECONCILIATION-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&state_record),
            ],
            32,
        )
    }

    pub fn release_allowed(&self) -> u64 {
        0
    }

    pub fn validate(&self) -> Result<String> {
        if self.expected_outputs.len() as u64 != self.config.required_scenario_count {
            return Err(
                "runtime output reconciliation requires exactly nine expected outputs".to_string(),
            );
        }
        if self.observed_outputs.len() != self.expected_outputs.len() {
            return Err(
                "runtime output reconciliation observed outputs must match expected outputs"
                    .to_string(),
            );
        }
        if self.reconciliation_verdicts.len() != self.expected_outputs.len() {
            return Err(
                "runtime output reconciliation verdicts must match expected outputs".to_string(),
            );
        }
        if self.release_allowed() != 0 {
            return Err("runtime output reconciliation must fail closed".to_string());
        }
        if self.mismatch_count >= self.config.reject_on_mismatch
            && self.release_blocker_count < self.config.block_release_on_mismatch
        {
            return Err("runtime output reconciliation mismatch must block release".to_string());
        }
        if self.config.require_fail_closed_output != 0 {
            let non_closed_outputs = self
                .observed_outputs
                .iter()
                .filter(|output| output.observed_release_allowed != 0)
                .count();
            if non_closed_outputs != 0 {
                return Err(
                    "runtime output reconciliation observed outputs must fail closed".to_string(),
                );
            }
        }

        Ok(self.state_root())
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

fn mismatch_type(
    expected: &ExpectedFailClosedOutput,
    observed: &ObservedRuntimeOutput,
) -> MismatchType {
    if expected.scenario != observed.scenario {
        MismatchType::Scenario
    } else if expected.handler_bound_execution_root != observed.handler_bound_execution_root {
        MismatchType::HandlerBoundExecutionRoot
    } else if expected.expected_decision != observed.observed_decision {
        MismatchType::Decision
    } else if expected.expected_handler_action != observed.observed_handler_action {
        MismatchType::HandlerAction
    } else if expected.expected_release_allowed != observed.observed_release_allowed {
        MismatchType::ReleaseAllowed
    } else if expected.expected_output_digest != observed.observed_output_digest {
        MismatchType::OutputDigest
    } else if observed.process_feed_root.is_empty() {
        MismatchType::ProcessFeedMissing
    } else {
        MismatchType::None
    }
}

fn release_blocker(mismatch_type: MismatchType, release_allowed: u64) -> ReleaseBlocker {
    if release_allowed != 0 {
        ReleaseBlocker::FailClosedViolation
    } else if mismatch_type == MismatchType::ProcessFeedMissing {
        ReleaseBlocker::MissingProcessFeed
    } else if mismatch_type != MismatchType::None {
        ReleaseBlocker::ReconciliationMismatch
    } else {
        ReleaseBlocker::None
    }
}

fn severity(release_blocker: ReleaseBlocker, mismatch_type: MismatchType) -> Severity {
    match release_blocker {
        ReleaseBlocker::FailClosedViolation | ReleaseBlocker::ReconciliationMismatch => {
            Severity::Critical
        }
        ReleaseBlocker::MissingProcessFeed => Severity::Recoverable,
        ReleaseBlocker::None => {
            if mismatch_type == MismatchType::None {
                Severity::None
            } else {
                Severity::Recoverable
            }
        }
    }
}

fn devnet_expected_outputs() -> Vec<ExpectedFailClosedOutput> {
    vec![
        devnet_expected_output(
            AdversarialScenario::Reorg,
            "monero_anchor_reorg_handler_bound",
        ),
        devnet_expected_output(
            AdversarialScenario::WatcherCollusion,
            "watcher_collusion_handler_bound",
        ),
        devnet_expected_output(
            AdversarialScenario::SequencerHalt,
            "sequencer_halt_handler_bound",
        ),
        devnet_expected_output(AdversarialScenario::Forgery, "forged_receipt_handler_bound"),
        devnet_expected_output(AdversarialScenario::Pq, "stale_pq_epoch_handler_bound"),
        devnet_expected_output(
            AdversarialScenario::Liquidity,
            "liquidity_exhaustion_handler_bound",
        ),
        devnet_expected_output(AdversarialScenario::Metadata, "metadata_leak_handler_bound"),
        devnet_expected_output(
            AdversarialScenario::Bypass,
            "challenge_bypass_handler_bound",
        ),
        devnet_expected_output(
            AdversarialScenario::WalletMismatch,
            "wallet_mismatch_handler_bound",
        ),
    ]
}

fn devnet_expected_output(
    scenario: AdversarialScenario,
    handler_bound_label: &str,
) -> ExpectedFailClosedOutput {
    let handler_bound_execution_root = domain_hash(
        "MONERO-L2-PQ-ESCAPE-GAP-HANDLER-BOUND-DEVNET-ROOT",
        &[
            HashPart::Str(
                "monero-l2-pq-bridge-exit-canonical-user-escape-adversarial-gap-handler-bound-execution-runtime-v1",
            ),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scenario.as_str()),
            HashPart::Str(handler_bound_label),
        ],
        32,
    );

    ExpectedFailClosedOutput::new(scenario, &handler_bound_execution_root)
}

fn output_digest(
    scenario: AdversarialScenario,
    handler_bound_execution_root: &str,
    decision: &str,
    handler_action: &str,
    release_allowed: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-ESCAPE-GAP-RUNTIME-OUTPUT-RECONCILIATION-OUTPUT-DIGEST",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scenario.as_str()),
            HashPart::Str(handler_bound_execution_root),
            HashPart::Str(decision),
            HashPart::Str(handler_action),
            HashPart::U64(release_allowed),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-ESCAPE-GAP-RUNTIME-OUTPUT-RECONCILIATION-RECORD",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
