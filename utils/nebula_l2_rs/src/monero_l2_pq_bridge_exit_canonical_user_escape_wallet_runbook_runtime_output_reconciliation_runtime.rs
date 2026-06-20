use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeWalletRunbookRuntimeOutputReconciliationRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_RUNBOOK_RUNTIME_OUTPUT_RECONCILIATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-wallet-runbook-runtime-output-reconciliation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_RUNBOOK_RUNTIME_OUTPUT_RECONCILIATION_RUNTIME_PROTOCOL_VERSION;

const PROTOCOL_LABEL: &str =
    "monero_l2_pq_bridge_exit_canonical_user_escape_wallet_runbook_runtime_output_reconciliation";
const HASH_SUITE: &str = "SHAKE256-domain-separated-merkle-json-v1";
const RUNBOOK_ID: &str = "devnet-user-escape-package-001";
const WALLET_ID: &str = "escape-wallet-alpha";
const EXECUTION_LANE_ID: &str = "handler-bound-forced-exit-lane-001";
const RECONCILIATION_SESSION_ID: &str = "devnet-wallet-runtime-output-reconciliation-001";
const HANDLER_BINDING_SET_ID: &str = "devnet-user-escape-handler-binding-set-001";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub monero_network: String,
    pub runbook_id: String,
    pub wallet_id: String,
    pub execution_lane_id: String,
    pub reconciliation_session_id: String,
    pub handler_binding_set_id: String,
    pub schema_version: u64,
    pub fail_closed: bool,
    pub process_fed_outputs_required: bool,
    pub privacy_hold_required: bool,
    pub release_allowed_without_match: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            monero_network: "monero-devnet".to_string(),
            runbook_id: RUNBOOK_ID.to_string(),
            wallet_id: WALLET_ID.to_string(),
            execution_lane_id: EXECUTION_LANE_ID.to_string(),
            reconciliation_session_id: RECONCILIATION_SESSION_ID.to_string(),
            handler_binding_set_id: HANDLER_BINDING_SET_ID.to_string(),
            schema_version: 1,
            fail_closed: true,
            process_fed_outputs_required: true,
            privacy_hold_required: true,
            release_allowed_without_match: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "hash_suite": self.hash_suite,
            "monero_network": self.monero_network,
            "runbook_id": self.runbook_id,
            "wallet_id": self.wallet_id,
            "execution_lane_id": self.execution_lane_id,
            "reconciliation_session_id": self.reconciliation_session_id,
            "handler_binding_set_id": self.handler_binding_set_id,
            "schema_version": self.schema_version,
            "fail_closed": self.fail_closed,
            "process_fed_outputs_required": self.process_fed_outputs_required,
            "privacy_hold_required": self.privacy_hold_required,
            "release_allowed_without_match": self.release_allowed_without_match,
        })
    }

    pub fn config_root(&self) -> String {
        runtime_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletReplayStepKind {
    WalletScanExport,
    ProofCollectionImport,
    ForcedExitClaimBuild,
    PqAuthorizationExport,
    LiveFeedCrosscheck,
    ReleaseVerifierReplay,
    LocalRecoveryReplay,
}

impl WalletReplayStepKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScanExport => "wallet_scan_export",
            Self::ProofCollectionImport => "proof_collection_import",
            Self::ForcedExitClaimBuild => "forced_exit_claim_build",
            Self::PqAuthorizationExport => "pq_authorization_export",
            Self::LiveFeedCrosscheck => "live_feed_crosscheck",
            Self::ReleaseVerifierReplay => "release_verifier_replay",
            Self::LocalRecoveryReplay => "local_recovery_replay",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputRootKind {
    HandlerExpected,
    ProcessObserved,
    DeferredPlaceholder,
}

impl OutputRootKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HandlerExpected => "handler_expected",
            Self::ProcessObserved => "process_observed",
            Self::DeferredPlaceholder => "deferred_placeholder",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchSeverity {
    None,
    Blocking,
}

impl MismatchSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Blocking => "blocking",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyHoldReason {
    RuntimeOutputDeferred,
    RootMismatch,
    RedactionBoundaryUnverified,
}

impl PrivacyHoldReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeOutputDeferred => "runtime_output_deferred",
            Self::RootMismatch => "root_mismatch",
            Self::RedactionBoundaryUnverified => "redaction_boundary_unverified",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationVerdictKind {
    Matched,
    WaitingForProcessOutput,
    Mismatch,
    FailClosedHold,
}

impl ReconciliationVerdictKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::WaitingForProcessOutput => "waiting_for_process_output",
            Self::Mismatch => "mismatch",
            Self::FailClosedHold => "fail_closed_hold",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletReplayStep {
    pub ordinal: u64,
    pub step_id: String,
    pub step_kind: WalletReplayStepKind,
    pub handler_stage: String,
    pub replay_command: String,
    pub input_roots: Vec<String>,
    pub handler_bound_output_root: String,
    pub replay_step_root: String,
}

impl WalletReplayStep {
    pub fn public_record(&self) -> Value {
        json!({
            "ordinal": self.ordinal,
            "step_id": self.step_id,
            "step_kind": self.step_kind.as_str(),
            "handler_stage": self.handler_stage,
            "replay_command": self.replay_command,
            "input_roots": self.input_roots,
            "handler_bound_output_root": self.handler_bound_output_root,
            "replay_step_root": self.replay_step_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedOutputRoot {
    pub step_id: String,
    pub ordinal: u64,
    pub root_kind: OutputRootKind,
    pub output_label: String,
    pub expected_root: String,
    pub source_record_root: String,
}

impl ExpectedOutputRoot {
    pub fn from_step(step: &WalletReplayStep) -> Self {
        let source_record_root = runtime_hash(
            "EXPECTED-OUTPUT-SOURCE",
            &[
                HashPart::Str(&step.step_id),
                HashPart::U64(step.ordinal),
                HashPart::Str(&step.handler_bound_output_root),
                HashPart::Str(&step.replay_step_root),
            ],
        );

        Self {
            step_id: step.step_id.clone(),
            ordinal: step.ordinal,
            root_kind: OutputRootKind::HandlerExpected,
            output_label: format!("{}_expected_output_root", step.step_kind.as_str()),
            expected_root: step.handler_bound_output_root.clone(),
            source_record_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "step_id": self.step_id,
            "ordinal": self.ordinal,
            "root_kind": self.root_kind.as_str(),
            "output_label": self.output_label,
            "expected_root": self.expected_root,
            "source_record_root": self.source_record_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedWalletRuntimeOutputRoot {
    pub step_id: String,
    pub ordinal: u64,
    pub root_kind: OutputRootKind,
    pub observed_root: String,
    pub process_feed_id: String,
    pub observed_status: String,
    pub redaction_root: String,
}

impl ObservedWalletRuntimeOutputRoot {
    pub fn deferred(expected: &ExpectedOutputRoot, config: &Config) -> Self {
        let observed_status = "process_fed_output_deferred".to_string();
        let redaction_root = runtime_hash(
            "OBSERVED-REDACTION",
            &[
                HashPart::Str(&expected.step_id),
                HashPart::Str(&expected.expected_root),
                HashPart::Str(&observed_status),
                HashPart::Str("wallet_and_runtime_material_not_public"),
            ],
        );
        let observed_root = runtime_hash(
            "OBSERVED-DEFERRED",
            &[
                HashPart::Str(&config.reconciliation_session_id),
                HashPart::Str(&expected.step_id),
                HashPart::U64(expected.ordinal),
                HashPart::Str(&expected.expected_root),
                HashPart::Str(&redaction_root),
                HashPart::Str(&observed_status),
            ],
        );

        Self {
            step_id: expected.step_id.clone(),
            ordinal: expected.ordinal,
            root_kind: OutputRootKind::DeferredPlaceholder,
            observed_root,
            process_feed_id: "future-process-fed-wallet-runtime-output".to_string(),
            observed_status,
            redaction_root,
        }
    }

    pub fn process_fed(
        expected: &ExpectedOutputRoot,
        observed_root: String,
        process_feed_id: String,
        redaction_root: String,
    ) -> Self {
        Self {
            step_id: expected.step_id.clone(),
            ordinal: expected.ordinal,
            root_kind: OutputRootKind::ProcessObserved,
            observed_root,
            process_feed_id,
            observed_status: "process_fed_output_observed".to_string(),
            redaction_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "step_id": self.step_id,
            "ordinal": self.ordinal,
            "root_kind": self.root_kind.as_str(),
            "observed_root": self.observed_root,
            "process_feed_id": self.process_feed_id,
            "observed_status": self.observed_status,
            "redaction_root": self.redaction_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserVisibleMismatch {
    pub step_id: String,
    pub ordinal: u64,
    pub expected_root: String,
    pub observed_root: String,
    pub severity: MismatchSeverity,
    pub message: String,
    pub mismatch_root: String,
}

impl UserVisibleMismatch {
    pub fn from_roots(
        expected: &ExpectedOutputRoot,
        observed: &ObservedWalletRuntimeOutputRoot,
    ) -> Option<Self> {
        if expected.expected_root == observed.observed_root {
            None
        } else {
            let severity = MismatchSeverity::Blocking;
            let message = if observed.root_kind == OutputRootKind::DeferredPlaceholder {
                "Wallet/runtime output is deferred; release remains held until a matching process-fed root is supplied."
                    .to_string()
            } else {
                "Wallet/runtime output does not match the handler-bound execution root; release remains held."
                    .to_string()
            };
            let mismatch_root = runtime_hash(
                "USER-VISIBLE-MISMATCH",
                &[
                    HashPart::Str(&expected.step_id),
                    HashPart::U64(expected.ordinal),
                    HashPart::Str(&expected.expected_root),
                    HashPart::Str(&observed.observed_root),
                    HashPart::Str(severity.as_str()),
                    HashPart::Str(&message),
                ],
            );

            Some(Self {
                step_id: expected.step_id.clone(),
                ordinal: expected.ordinal,
                expected_root: expected.expected_root.clone(),
                observed_root: observed.observed_root.clone(),
                severity,
                message,
                mismatch_root,
            })
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "step_id": self.step_id,
            "ordinal": self.ordinal,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "severity": self.severity.as_str(),
            "message": self.message,
            "mismatch_root": self.mismatch_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayPrivacyHold {
    pub step_id: String,
    pub ordinal: u64,
    pub hold_reason: PrivacyHoldReason,
    pub release_blocking: bool,
    pub public_redaction_root: String,
    pub hold_root: String,
}

impl ReplayPrivacyHold {
    pub fn for_observed(
        expected: &ExpectedOutputRoot,
        observed: &ObservedWalletRuntimeOutputRoot,
        matched: bool,
    ) -> Self {
        let hold_reason = if observed.root_kind == OutputRootKind::DeferredPlaceholder {
            PrivacyHoldReason::RuntimeOutputDeferred
        } else if matched {
            PrivacyHoldReason::RedactionBoundaryUnverified
        } else {
            PrivacyHoldReason::RootMismatch
        };
        let release_blocking = true;
        let public_redaction_root = runtime_hash(
            "PUBLIC-REDACTION-ROOT",
            &[
                HashPart::Str(&expected.step_id),
                HashPart::Str(&observed.redaction_root),
                HashPart::Str(hold_reason.as_str()),
                HashPart::Str("no_wallet_view_key_or_address_material"),
            ],
        );
        let hold_root = runtime_hash(
            "REPLAY-PRIVACY-HOLD",
            &[
                HashPart::Str(&expected.step_id),
                HashPart::U64(expected.ordinal),
                HashPart::Str(hold_reason.as_str()),
                HashPart::Str(if release_blocking {
                    "release_blocking"
                } else {
                    "release_allowed"
                }),
                HashPart::Str(&public_redaction_root),
            ],
        );

        Self {
            step_id: expected.step_id.clone(),
            ordinal: expected.ordinal,
            hold_reason,
            release_blocking,
            public_redaction_root,
            hold_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "step_id": self.step_id,
            "ordinal": self.ordinal,
            "hold_reason": self.hold_reason.as_str(),
            "release_blocking": self.release_blocking,
            "public_redaction_root": self.public_redaction_root,
            "hold_root": self.hold_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationVerdict {
    pub verdict: ReconciliationVerdictKind,
    pub matched_count: u64,
    pub mismatch_count: u64,
    pub deferred_count: u64,
    pub privacy_hold_count: u64,
    pub release_allowed: bool,
    pub fail_closed: bool,
    pub verdict_root: String,
}

impl ReconciliationVerdict {
    pub fn from_records(
        config: &Config,
        expected: &[ExpectedOutputRoot],
        observed: &[ObservedWalletRuntimeOutputRoot],
        mismatches: &[UserVisibleMismatch],
        privacy_holds: &[ReplayPrivacyHold],
    ) -> Self {
        let matched_count = expected
            .iter()
            .filter(|item| {
                observed.iter().any(|candidate| {
                    candidate.step_id == item.step_id
                        && candidate.observed_root == item.expected_root
                })
            })
            .count() as u64;
        let mismatch_count = mismatches.len() as u64;
        let deferred_count = observed
            .iter()
            .filter(|item| item.root_kind == OutputRootKind::DeferredPlaceholder)
            .count() as u64;
        let privacy_hold_count = privacy_holds
            .iter()
            .filter(|item| item.release_blocking)
            .count() as u64;
        let all_matched = matched_count == expected.len() as u64 && mismatch_count == 0;
        let release_allowed =
            all_matched && privacy_hold_count == 0 && !config.release_allowed_without_match;
        let verdict = if all_matched && release_allowed {
            ReconciliationVerdictKind::Matched
        } else if deferred_count > 0 {
            ReconciliationVerdictKind::WaitingForProcessOutput
        } else if mismatch_count > 0 {
            ReconciliationVerdictKind::Mismatch
        } else {
            ReconciliationVerdictKind::FailClosedHold
        };
        let fail_closed = !release_allowed;
        let verdict_root = runtime_hash(
            "RECONCILIATION-VERDICT",
            &[
                HashPart::Str(verdict.as_str()),
                HashPart::U64(matched_count),
                HashPart::U64(mismatch_count),
                HashPart::U64(deferred_count),
                HashPart::U64(privacy_hold_count),
                HashPart::Str(if release_allowed { "true" } else { "false" }),
                HashPart::Str(if fail_closed { "true" } else { "false" }),
            ],
        );

        Self {
            verdict,
            matched_count,
            mismatch_count,
            deferred_count,
            privacy_hold_count,
            release_allowed,
            fail_closed,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "verdict": self.verdict.as_str(),
            "matched_count": self.matched_count,
            "mismatch_count": self.mismatch_count,
            "deferred_count": self.deferred_count,
            "privacy_hold_count": self.privacy_hold_count,
            "release_allowed": self.release_allowed,
            "fail_closed": self.fail_closed,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub replay_step_root: String,
    pub expected_output_root: String,
    pub observed_output_root: String,
    pub mismatch_root: String,
    pub privacy_hold_root: String,
    pub verdict_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "replay_step_root": self.replay_step_root,
            "expected_output_root": self.expected_output_root,
            "observed_output_root": self.observed_output_root,
            "mismatch_root": self.mismatch_root,
            "privacy_hold_root": self.privacy_hold_root,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub replay_steps: Vec<WalletReplayStep>,
    pub expected_outputs: Vec<ExpectedOutputRoot>,
    pub observed_outputs: Vec<ObservedWalletRuntimeOutputRoot>,
    pub mismatches: Vec<UserVisibleMismatch>,
    pub privacy_holds: Vec<ReplayPrivacyHold>,
    pub verdict: ReconciliationVerdict,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let replay_steps = replay_steps();
        let expected_outputs = replay_steps
            .iter()
            .map(ExpectedOutputRoot::from_step)
            .collect::<Vec<_>>();
        let observed_outputs = expected_outputs
            .iter()
            .map(|expected| ObservedWalletRuntimeOutputRoot::deferred(expected, &config))
            .collect::<Vec<_>>();

        Self::from_parts(config, replay_steps, expected_outputs, observed_outputs)
    }

    pub fn reconcile_with_observed_roots(
        observed_outputs: Vec<ObservedWalletRuntimeOutputRoot>,
    ) -> Result<Self> {
        let config = Config::devnet();
        let replay_steps = replay_steps();
        let expected_outputs = replay_steps
            .iter()
            .map(ExpectedOutputRoot::from_step)
            .collect::<Vec<_>>();

        if observed_outputs.len() != expected_outputs.len() {
            return Err("observed_output_count_mismatch".to_string());
        }

        for expected in &expected_outputs {
            if !observed_outputs.iter().any(|observed| {
                observed.step_id == expected.step_id && observed.ordinal == expected.ordinal
            }) {
                return Err(format!(
                    "missing_observed_output_for_step_{}",
                    expected.step_id
                ));
            }
        }

        Ok(Self::from_parts(
            config,
            replay_steps,
            expected_outputs,
            observed_outputs,
        ))
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.config_root(),
            replay_step_root: merkle_record_root(
                "REPLAY-STEPS",
                self.replay_steps
                    .iter()
                    .map(WalletReplayStep::public_record)
                    .collect::<Vec<_>>(),
            ),
            expected_output_root: merkle_record_root(
                "EXPECTED-OUTPUTS",
                self.expected_outputs
                    .iter()
                    .map(ExpectedOutputRoot::public_record)
                    .collect::<Vec<_>>(),
            ),
            observed_output_root: merkle_record_root(
                "OBSERVED-OUTPUTS",
                self.observed_outputs
                    .iter()
                    .map(ObservedWalletRuntimeOutputRoot::public_record)
                    .collect::<Vec<_>>(),
            ),
            mismatch_root: merkle_record_root(
                "USER-VISIBLE-MISMATCHES",
                self.mismatches
                    .iter()
                    .map(UserVisibleMismatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            privacy_hold_root: merkle_record_root(
                "REPLAY-PRIVACY-HOLDS",
                self.privacy_holds
                    .iter()
                    .map(ReplayPrivacyHold::public_record)
                    .collect::<Vec<_>>(),
            ),
            verdict_root: self.verdict.verdict_root.clone(),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "protocol_label": PROTOCOL_LABEL,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "replay_steps": self.replay_steps
                .iter()
                .map(WalletReplayStep::public_record)
                .collect::<Vec<_>>(),
            "expected_outputs": self.expected_outputs
                .iter()
                .map(ExpectedOutputRoot::public_record)
                .collect::<Vec<_>>(),
            "observed_outputs": self.observed_outputs
                .iter()
                .map(ObservedWalletRuntimeOutputRoot::public_record)
                .collect::<Vec<_>>(),
            "mismatches": self.mismatches
                .iter()
                .map(UserVisibleMismatch::public_record)
                .collect::<Vec<_>>(),
            "privacy_holds": self.privacy_holds
                .iter()
                .map(ReplayPrivacyHold::public_record)
                .collect::<Vec<_>>(),
            "verdict": self.verdict.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(object) = &mut record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        runtime_hash(
            "STATE",
            &[HashPart::Json(&self.public_record_without_root())],
        )
    }

    pub fn verify_fail_closed(&self) -> Result<String> {
        if self.verdict.release_allowed {
            Err("release_unexpectedly_allowed".to_string())
        } else if !self.verdict.fail_closed {
            Err("fail_closed_flag_missing".to_string())
        } else {
            Ok(self.state_root())
        }
    }

    fn from_parts(
        config: Config,
        replay_steps: Vec<WalletReplayStep>,
        expected_outputs: Vec<ExpectedOutputRoot>,
        observed_outputs: Vec<ObservedWalletRuntimeOutputRoot>,
    ) -> Self {
        let mismatches = expected_outputs
            .iter()
            .filter_map(|expected| {
                observed_outputs
                    .iter()
                    .find(|observed| {
                        observed.step_id == expected.step_id && observed.ordinal == expected.ordinal
                    })
                    .and_then(|observed| UserVisibleMismatch::from_roots(expected, observed))
            })
            .collect::<Vec<_>>();
        let privacy_holds = expected_outputs
            .iter()
            .filter_map(|expected| {
                observed_outputs
                    .iter()
                    .find(|observed| {
                        observed.step_id == expected.step_id && observed.ordinal == expected.ordinal
                    })
                    .map(|observed| {
                        ReplayPrivacyHold::for_observed(
                            expected,
                            observed,
                            expected.expected_root == observed.observed_root,
                        )
                    })
            })
            .collect::<Vec<_>>();
        let verdict = ReconciliationVerdict::from_records(
            &config,
            &expected_outputs,
            &observed_outputs,
            &mismatches,
            &privacy_holds,
        );

        Self {
            config,
            replay_steps,
            expected_outputs,
            observed_outputs,
            mismatches,
            privacy_holds,
            verdict,
        }
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

fn replay_steps() -> Vec<WalletReplayStep> {
    let roots = handler_bound_roots();

    vec![
        wallet_step(
            1,
            "wallet_scan_export",
            WalletReplayStepKind::WalletScanExport,
            "wallet_scan_export",
            "wallet escape replay scan --bind-handler-root",
            vec![roots.handler_binding_root.clone()],
            roots.wallet_scan_root.clone(),
        ),
        wallet_step(
            2,
            "proof_collection_import",
            WalletReplayStepKind::ProofCollectionImport,
            "proof_collection",
            "wallet escape replay collect-proofs --from-scan-root",
            vec![roots.wallet_scan_root.clone()],
            roots.proof_collection_root.clone(),
        ),
        wallet_step(
            3,
            "forced_exit_claim_build",
            WalletReplayStepKind::ForcedExitClaimBuild,
            "forced_exit_claim_builder",
            "wallet escape replay build-claim --from-proof-root",
            vec![
                roots.wallet_scan_root.clone(),
                roots.proof_collection_root.clone(),
            ],
            roots.forced_exit_claim_root.clone(),
        ),
        wallet_step(
            4,
            "pq_authorization_export",
            WalletReplayStepKind::PqAuthorizationExport,
            "pq_authorization_exporter",
            "wallet escape replay authorize-pq --from-claim-root",
            vec![roots.forced_exit_claim_root.clone()],
            roots.pq_authorization_root.clone(),
        ),
        wallet_step(
            5,
            "live_feed_crosscheck",
            WalletReplayStepKind::LiveFeedCrosscheck,
            "live_feed_crosscheck",
            "wallet escape replay crosscheck-live-feed --require-quorum",
            vec![
                roots.forced_exit_claim_root.clone(),
                roots.pq_authorization_root.clone(),
            ],
            roots.live_feed_crosscheck_root.clone(),
        ),
        wallet_step(
            6,
            "release_verifier_replay",
            WalletReplayStepKind::ReleaseVerifierReplay,
            "release_verifier_replay",
            "wallet escape replay verify-release --from-crosscheck-root",
            vec![
                roots.live_feed_crosscheck_root.clone(),
                roots.forced_exit_claim_root.clone(),
            ],
            roots.release_verifier_replay_root.clone(),
        ),
        wallet_step(
            7,
            "local_recovery_replay",
            WalletReplayStepKind::LocalRecoveryReplay,
            "local_recovery_replay",
            "wallet escape replay local-recovery --seal-execution-record",
            vec![
                roots.release_verifier_replay_root.clone(),
                roots.pq_authorization_root.clone(),
            ],
            roots.local_recovery_replay_root.clone(),
        ),
    ]
}

fn wallet_step(
    ordinal: u64,
    step_id: &str,
    step_kind: WalletReplayStepKind,
    handler_stage: &str,
    replay_command: &str,
    input_roots: Vec<String>,
    handler_bound_output_root: String,
) -> WalletReplayStep {
    let replay_step_root = runtime_hash(
        "WALLET-REPLAY-STEP",
        &[
            HashPart::U64(ordinal),
            HashPart::Str(step_id),
            HashPart::Str(step_kind.as_str()),
            HashPart::Str(handler_stage),
            HashPart::Str(replay_command),
            HashPart::Json(&json!(input_roots)),
            HashPart::Str(&handler_bound_output_root),
        ],
    );

    WalletReplayStep {
        ordinal,
        step_id: step_id.to_string(),
        step_kind,
        handler_stage: handler_stage.to_string(),
        replay_command: replay_command.to_string(),
        input_roots,
        handler_bound_output_root,
        replay_step_root,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HandlerBoundRoots {
    wallet_scan_root: String,
    proof_collection_root: String,
    forced_exit_claim_root: String,
    pq_authorization_root: String,
    live_feed_crosscheck_root: String,
    release_verifier_replay_root: String,
    local_recovery_replay_root: String,
    handler_binding_root: String,
}

fn handler_bound_roots() -> HandlerBoundRoots {
    let wallet_scan_root = seed_root("wallet-scan", "escape-wallet-alpha-height-17680");
    let proof_collection_root = seed_root("proof-collection", "exit-proof-package-v1");
    let forced_exit_claim_root = seed_root("forced-exit-claim", "claim-package-v1");
    let pq_authorization_root = seed_root("pq-authorization", "wallet-pq-auth-v1");
    let live_feed_crosscheck_root =
        seed_root("live-feed-crosscheck", "operator-watchtower-local-match");
    let release_verifier_replay_root =
        seed_root("release-verifier-replay", "release-receipt-proof-v1");
    let local_recovery_replay_root = seed_root("local-recovery-replay", "wallet-local-replay-v1");
    let handler_binding_root = runtime_hash(
        "HANDLER-BOUND-ROOTS",
        &[HashPart::Json(&json!({
            "wallet_scan_root": wallet_scan_root,
            "proof_collection_root": proof_collection_root,
            "forced_exit_claim_root": forced_exit_claim_root,
            "pq_authorization_root": pq_authorization_root,
            "live_feed_crosscheck_root": live_feed_crosscheck_root,
            "release_verifier_replay_root": release_verifier_replay_root,
            "local_recovery_replay_root": local_recovery_replay_root,
        }))],
    );

    HandlerBoundRoots {
        wallet_scan_root,
        proof_collection_root,
        forced_exit_claim_root,
        pq_authorization_root,
        live_feed_crosscheck_root,
        release_verifier_replay_root,
        local_recovery_replay_root,
        handler_binding_root,
    }
}

fn seed_root(label: &str, value: &str) -> String {
    runtime_hash("SEED", &[HashPart::Str(label), HashPart::Str(value)])
}

fn merkle_record_root(label: &str, records: Vec<Value>) -> String {
    merkle_root(&format!("{PROTOCOL_LABEL}:{label}"), &records)
}

fn runtime_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    let part_record = parts.iter().map(hash_part_record).collect::<Vec<_>>();

    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_LABEL),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&json!(part_record)),
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
