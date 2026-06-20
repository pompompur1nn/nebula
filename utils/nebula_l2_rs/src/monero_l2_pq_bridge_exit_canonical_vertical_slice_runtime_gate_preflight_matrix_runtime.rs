use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceRuntimeGatePreflightMatrixRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_GATE_PREFLIGHT_MATRIX_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-runtime-gate-preflight-matrix-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_GATE_PREFLIGHT_MATRIX_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PREFLIGHT_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-runtime-gate-preflight-v1";
pub const DEFAULT_L2_HEIGHT: u64 = 4_260_128;
pub const DEFAULT_MONERO_HEIGHT: u64 = 3_530_128;
pub const DEFAULT_MIN_PQ_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_000;
pub const DEFAULT_MAX_METADATA_UNITS: u64 = 3;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightGateKind {
    DepositNote,
    PrivateReceipt,
    ContractReceipt,
    WithdrawalClaim,
    FeedReplay,
    AdversarialCases,
    ReleaseBlockers,
    EvidenceAcceptance,
}

impl PreflightGateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositNote => "deposit_note",
            Self::PrivateReceipt => "private_receipt",
            Self::ContractReceipt => "contract_receipt",
            Self::WithdrawalClaim => "withdrawal_claim",
            Self::FeedReplay => "feed_replay",
            Self::AdversarialCases => "adversarial_cases",
            Self::ReleaseBlockers => "release_blockers",
            Self::EvidenceAcceptance => "evidence_acceptance",
        }
    }

    pub fn ordinal(self) -> u64 {
        match self {
            Self::DepositNote => 0,
            Self::PrivateReceipt => 1,
            Self::ContractReceipt => 2,
            Self::WithdrawalClaim => 3,
            Self::FeedReplay => 4,
            Self::AdversarialCases => 5,
            Self::ReleaseBlockers => 6,
            Self::EvidenceAcceptance => 7,
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::DepositNote,
            Self::PrivateReceipt,
            Self::ContractReceipt,
            Self::WithdrawalClaim,
            Self::FeedReplay,
            Self::AdversarialCases,
            Self::ReleaseBlockers,
            Self::EvidenceAcceptance,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightDecision {
    RunnableAfterCargoGate,
    RequiresLiveFeedSwap,
    RequiresRuntimeExecution,
    MustRejectAdversarialInput,
    ReleaseHeld,
}

impl PreflightDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RunnableAfterCargoGate => "runnable_after_cargo_gate",
            Self::RequiresLiveFeedSwap => "requires_live_feed_swap",
            Self::RequiresRuntimeExecution => "requires_runtime_execution",
            Self::MustRejectAdversarialInput => "must_reject_adversarial_input",
            Self::ReleaseHeld => "release_held",
        }
    }

    pub fn is_release_blocking(self) -> bool {
        matches!(
            self,
            Self::RequiresLiveFeedSwap | Self::RequiresRuntimeExecution | Self::ReleaseHeld
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixVerdict {
    HarnessPreflightReady,
    ProductionReleaseBlocked,
}

impl MatrixVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HarnessPreflightReady => "harness_preflight_ready",
            Self::ProductionReleaseBlocked => "production_release_blocked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
    pub min_pq_weight_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub max_metadata_units: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            l2_network: "nebula-devnet".to_string(),
            monero_network: "monero-devnet".to_string(),
            l2_reference_height: DEFAULT_L2_HEIGHT,
            monero_reference_height: DEFAULT_MONERO_HEIGHT,
            min_pq_weight_bps: DEFAULT_MIN_PQ_WEIGHT_BPS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            max_metadata_units: DEFAULT_MAX_METADATA_UNITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "preflight_suite": PREFLIGHT_SUITE,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "min_pq_weight_bps": self.min_pq_weight_bps,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "max_metadata_units": self.max_metadata_units,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreflightCheck {
    pub kind: PreflightGateKind,
    pub decision: PreflightDecision,
    pub invocation_runtime: String,
    pub preflight_runtime: String,
    pub required_inputs: Vec<String>,
    pub release_blockers: Vec<String>,
    pub next_action: String,
    pub input_bundle_root: String,
    pub expected_invocation_root: String,
    pub expected_receipt_root: String,
    pub rejection_root: String,
    pub monero_evidence_root: String,
    pub pq_authority_root: String,
    pub wallet_replay_root: String,
    pub privacy_budget_root: String,
    pub reserve_root: String,
    pub preflight_root: String,
}

impl PreflightCheck {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "ordinal": self.kind.ordinal(),
            "decision": self.decision.as_str(),
            "release_blocking": self.decision.is_release_blocking(),
            "invocation_runtime": self.invocation_runtime,
            "preflight_runtime": self.preflight_runtime,
            "required_inputs": self.required_inputs,
            "release_blockers": self.release_blockers,
            "next_action": self.next_action,
            "input_bundle_root": self.input_bundle_root,
            "expected_invocation_root": self.expected_invocation_root,
            "expected_receipt_root": self.expected_receipt_root,
            "rejection_root": self.rejection_root,
            "monero_evidence_root": self.monero_evidence_root,
            "pq_authority_root": self.pq_authority_root,
            "wallet_replay_root": self.wallet_replay_root,
            "privacy_budget_root": self.privacy_budget_root,
            "reserve_root": self.reserve_root,
            "preflight_root": self.preflight_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("preflight-check", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreflightCounters {
    pub total_gates: u64,
    pub runnable_after_cargo_gate: u64,
    pub live_feed_swaps_required: u64,
    pub runtime_execution_required: u64,
    pub adversarial_rejections_required: u64,
    pub release_holds: u64,
}

impl PreflightCounters {
    pub fn from_checks(checks: &[PreflightCheck]) -> Self {
        let mut counters = Self {
            total_gates: checks.len() as u64,
            runnable_after_cargo_gate: 0,
            live_feed_swaps_required: 0,
            runtime_execution_required: 0,
            adversarial_rejections_required: 0,
            release_holds: 0,
        };
        for check in checks {
            match check.decision {
                PreflightDecision::RunnableAfterCargoGate => {
                    counters.runnable_after_cargo_gate += 1;
                }
                PreflightDecision::RequiresLiveFeedSwap => {
                    counters.live_feed_swaps_required += 1;
                }
                PreflightDecision::RequiresRuntimeExecution => {
                    counters.runtime_execution_required += 1;
                }
                PreflightDecision::MustRejectAdversarialInput => {
                    counters.adversarial_rejections_required += 1;
                }
                PreflightDecision::ReleaseHeld => {
                    counters.release_holds += 1;
                }
            }
        }
        counters
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_gates": self.total_gates,
            "runnable_after_cargo_gate": self.runnable_after_cargo_gate,
            "live_feed_swaps_required": self.live_feed_swaps_required,
            "runtime_execution_required": self.runtime_execution_required,
            "adversarial_rejections_required": self.adversarial_rejections_required,
            "release_holds": self.release_holds,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("preflight-counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreflightMatrixRoots {
    pub check_root: String,
    pub runnable_root: String,
    pub blocker_root: String,
    pub monero_evidence_root: String,
    pub pq_authority_root: String,
    pub wallet_replay_root: String,
    pub privacy_budget_root: String,
    pub reserve_root: String,
    pub counter_root: String,
}

impl PreflightMatrixRoots {
    pub fn from_checks(checks: &[PreflightCheck], counters: &PreflightCounters) -> Self {
        Self {
            check_root: preflight_merkle("checks", checks, PreflightCheck::state_root),
            runnable_root: decision_merkle(
                "runnable",
                checks,
                PreflightDecision::RunnableAfterCargoGate,
            ),
            blocker_root: blocker_merkle(checks),
            monero_evidence_root: lane_merkle("monero-evidence", checks, |check| {
                &check.monero_evidence_root
            }),
            pq_authority_root: lane_merkle("pq-authority", checks, |check| {
                &check.pq_authority_root
            }),
            wallet_replay_root: lane_merkle("wallet-replay", checks, |check| {
                &check.wallet_replay_root
            }),
            privacy_budget_root: lane_merkle("privacy-budget", checks, |check| {
                &check.privacy_budget_root
            }),
            reserve_root: lane_merkle("reserve", checks, |check| &check.reserve_root),
            counter_root: counters.state_root(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "check_root": self.check_root,
            "runnable_root": self.runnable_root,
            "blocker_root": self.blocker_root,
            "monero_evidence_root": self.monero_evidence_root,
            "pq_authority_root": self.pq_authority_root,
            "wallet_replay_root": self.wallet_replay_root,
            "privacy_budget_root": self.privacy_budget_root,
            "reserve_root": self.reserve_root,
            "counter_root": self.counter_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("preflight-matrix-roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreflightMatrixSummary {
    pub matrix_id: String,
    pub verdict: MatrixVerdict,
    pub cargo_runtime_required_next: bool,
    pub live_feed_swap_required_next: bool,
    pub production_release_allowed: bool,
    pub counters: PreflightCounters,
    pub roots: PreflightMatrixRoots,
}

impl PreflightMatrixSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "matrix_id": self.matrix_id,
            "verdict": self.verdict.as_str(),
            "cargo_runtime_required_next": self.cargo_runtime_required_next,
            "live_feed_swap_required_next": self.live_feed_swap_required_next,
            "production_release_allowed": self.production_release_allowed,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("preflight-matrix-summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub checks: Vec<PreflightCheck>,
    pub summary: PreflightMatrixSummary,
    pub release_hold_reasons: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let checks = PreflightGateKind::all()
            .into_iter()
            .map(|kind| default_check(&config, kind))
            .collect::<Vec<_>>();
        let counters = PreflightCounters::from_checks(&checks);
        let roots = PreflightMatrixRoots::from_checks(&checks, &counters);
        let summary = PreflightMatrixSummary {
            matrix_id: matrix_id(&config, &roots),
            verdict: MatrixVerdict::ProductionReleaseBlocked,
            cargo_runtime_required_next: true,
            live_feed_swap_required_next: true,
            production_release_allowed: false,
            counters,
            roots,
        };
        Self {
            config,
            checks,
            summary,
            release_hold_reasons: release_hold_reasons(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "checks": self.checks.iter().map(PreflightCheck::public_record).collect::<Vec<_>>(),
            "summary": self.summary.public_record(),
            "release_hold_reasons": self.release_hold_reasons,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-vertical-slice-runtime-gate-preflight-matrix-state",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.summary.state_root()),
                HashPart::Str(&hold_root(&self.release_hold_reasons)),
            ],
            32,
        )
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
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

fn default_check(config: &Config, kind: PreflightGateKind) -> PreflightCheck {
    let decision = decision_for(kind);
    let required_inputs = required_inputs(kind);
    let release_blockers = release_blockers(kind);
    let payload = json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "kind": kind.as_str(),
        "ordinal": kind.ordinal(),
        "decision": decision.as_str(),
        "l2_reference_height": config.l2_reference_height + kind.ordinal(),
        "monero_reference_height": config.monero_reference_height + kind.ordinal(),
        "required_inputs": required_inputs,
        "release_blockers": release_blockers,
    });
    let input_bundle_root = root_for("input-bundle", kind, &payload);
    let expected_invocation_root = root_for("expected-invocation", kind, &payload);
    let expected_receipt_root = root_for("expected-receipt", kind, &payload);
    let rejection_root = root_for("rejection", kind, &payload);
    let monero_evidence_root = root_for("monero-evidence", kind, &payload);
    let pq_authority_root = root_for("pq-authority", kind, &payload);
    let wallet_replay_root = root_for("wallet-replay", kind, &payload);
    let privacy_budget_root = root_for("privacy-budget", kind, &payload);
    let reserve_root = root_for("reserve", kind, &payload);
    let preflight_root = domain_hash(
        "monero-l2-pq-bridge-exit-runtime-gate-preflight-check",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(decision.as_str()),
            HashPart::Str(&input_bundle_root),
            HashPart::Str(&expected_invocation_root),
            HashPart::Str(&expected_receipt_root),
            HashPart::Str(&rejection_root),
        ],
        32,
    );
    PreflightCheck {
        kind,
        decision,
        invocation_runtime: invocation_runtime(kind).to_string(),
        preflight_runtime: preflight_runtime(kind).to_string(),
        required_inputs,
        release_blockers,
        next_action: next_action(kind).to_string(),
        input_bundle_root,
        expected_invocation_root,
        expected_receipt_root,
        rejection_root,
        monero_evidence_root,
        pq_authority_root,
        wallet_replay_root,
        privacy_budget_root,
        reserve_root,
        preflight_root,
    }
}

fn decision_for(kind: PreflightGateKind) -> PreflightDecision {
    match kind {
        PreflightGateKind::DepositNote
        | PreflightGateKind::PrivateReceipt
        | PreflightGateKind::ContractReceipt
        | PreflightGateKind::WithdrawalClaim => PreflightDecision::RunnableAfterCargoGate,
        PreflightGateKind::FeedReplay => PreflightDecision::RequiresLiveFeedSwap,
        PreflightGateKind::AdversarialCases => PreflightDecision::MustRejectAdversarialInput,
        PreflightGateKind::ReleaseBlockers => PreflightDecision::ReleaseHeld,
        PreflightGateKind::EvidenceAcceptance => PreflightDecision::RequiresRuntimeExecution,
    }
}

fn invocation_runtime(kind: PreflightGateKind) -> &'static str {
    match kind {
        PreflightGateKind::DepositNote => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_deposit_note_gate_invocation_runtime"
        }
        PreflightGateKind::PrivateReceipt => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_private_receipt_gate_invocation_runtime"
        }
        PreflightGateKind::ContractReceipt => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_contract_receipt_gate_invocation_runtime"
        }
        PreflightGateKind::WithdrawalClaim => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_withdrawal_claim_gate_invocation_runtime"
        }
        PreflightGateKind::FeedReplay => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_feed_replay_fixture_runtime"
        }
        PreflightGateKind::AdversarialCases => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_adversarial_gate_invocation_runtime"
        }
        PreflightGateKind::ReleaseBlockers => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_release_blocker_gate_invocation_runtime"
        }
        PreflightGateKind::EvidenceAcceptance => {
            "monero_l2_pq_bridge_exit_canonical_runtime_evidence_acceptance_runtime"
        }
    }
}

fn preflight_runtime(kind: PreflightGateKind) -> &'static str {
    match kind {
        PreflightGateKind::DepositNote => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_deposit_note_gate_preflight_runtime"
        }
        PreflightGateKind::PrivateReceipt => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_private_receipt_gate_preflight_runtime"
        }
        PreflightGateKind::ContractReceipt => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_contract_receipt_gate_preflight_runtime"
        }
        PreflightGateKind::WithdrawalClaim => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_withdrawal_claim_gate_preflight_runtime"
        }
        PreflightGateKind::FeedReplay => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_runtime_gate_preflight_matrix_runtime"
        }
        PreflightGateKind::AdversarialCases => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_adversarial_gate_preflight_runtime"
        }
        PreflightGateKind::ReleaseBlockers => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_release_blocker_gate_preflight_runtime"
        }
        PreflightGateKind::EvidenceAcceptance => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_runtime_gate_preflight_matrix_runtime"
        }
    }
}

fn required_inputs(kind: PreflightGateKind) -> Vec<String> {
    match kind {
        PreflightGateKind::DepositNote => vec![
            "monero_lock_txid",
            "finality_depth",
            "pq_watcher_quorum",
            "note_commitment",
            "wallet_scan_hint",
        ],
        PreflightGateKind::PrivateReceipt => vec![
            "nullifier_root",
            "output_commitment_root",
            "encrypted_receipt_shards",
            "pq_authorization_root",
            "metadata_budget",
        ],
        PreflightGateKind::ContractReceipt => vec![
            "sealed_input_root",
            "encrypted_effect_root",
            "contract_receipt_root",
            "fee_bound_root",
            "exit_replay_root",
        ],
        PreflightGateKind::WithdrawalClaim => vec![
            "claim_authorization_root",
            "settlement_receipt_root",
            "challenge_window_root",
            "reserve_proof_root",
            "wallet_recovery_payload",
        ],
        PreflightGateKind::FeedReplay => vec![
            "monero_header_feed",
            "deposit_feed",
            "reorg_feed",
            "reserve_feed",
            "pq_authority_feed",
        ],
        PreflightGateKind::AdversarialCases => vec![
            "sequencer_outage_case",
            "watcher_collusion_case",
            "withheld_receipt_case",
            "metadata_leak_case",
            "liquidity_exhaustion_case",
        ],
        PreflightGateKind::ReleaseBlockers => vec![
            "cargo_runtime_gate",
            "live_feed_swap_gate",
            "forced_exit_drill_gate",
            "audit_gate",
            "privacy_pq_gate",
        ],
        PreflightGateKind::EvidenceAcceptance => vec![
            "compiled_harness_binary",
            "execution_receipt",
            "negative_case_receipt",
            "audit_signoff_receipt",
            "operator_release_receipt",
        ],
    }
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn release_blockers(kind: PreflightGateKind) -> Vec<String> {
    match kind {
        PreflightGateKind::DepositNote
        | PreflightGateKind::PrivateReceipt
        | PreflightGateKind::ContractReceipt
        | PreflightGateKind::WithdrawalClaim => vec!["cargo_runtime_execution_deferred"],
        PreflightGateKind::FeedReplay => {
            vec!["live_monero_feed_swap_pending", "reorg_feed_replay_pending"]
        }
        PreflightGateKind::AdversarialCases => {
            vec![
                "negative_case_execution_pending",
                "fail_closed_receipt_pending",
            ]
        }
        PreflightGateKind::ReleaseBlockers => vec![
            "cargo_runtime_deferred",
            "independent_audit_open",
            "privacy_review_open",
            "pq_key_verification_pending",
            "reserve_proof_handoff_pending",
        ],
        PreflightGateKind::EvidenceAcceptance => {
            vec![
                "compiled_runtime_evidence_missing",
                "production_release_held",
            ]
        }
    }
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn next_action(kind: PreflightGateKind) -> &'static str {
    match kind {
        PreflightGateKind::DepositNote => {
            "compile and invoke deposit-note gate with fixture-backed Monero lock evidence"
        }
        PreflightGateKind::PrivateReceipt => {
            "compile and invoke private receipt gate with encrypted receipt shards"
        }
        PreflightGateKind::ContractReceipt => {
            "compile and invoke contract receipt gate with sealed input and encrypted effect roots"
        }
        PreflightGateKind::WithdrawalClaim => {
            "compile and invoke withdrawal claim gate with challenge-window and reserve evidence"
        }
        PreflightGateKind::FeedReplay => {
            "swap deterministic feeds for live Monero header deposit reorg reserve and PQ authority feeds"
        }
        PreflightGateKind::AdversarialCases => {
            "run negative cases and require fail-closed rejection receipts"
        }
        PreflightGateKind::ReleaseBlockers => {
            "hold production release until runtime audit privacy PQ reserve and drill gates pass"
        }
        PreflightGateKind::EvidenceAcceptance => {
            "bind runtime execution receipts into the release evidence manifest"
        }
    }
}

fn root_for(kind: &str, gate: PreflightGateKind, payload: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-runtime-gate-preflight-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(gate.as_str()),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn preflight_merkle<F>(label: &str, checks: &[PreflightCheck], root: F) -> String
where
    F: Fn(&PreflightCheck) -> String,
{
    let records = checks
        .iter()
        .map(|check| {
            json!({
                "label": label,
                "kind": check.kind.as_str(),
                "root": root(check),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-bridge-exit-runtime-gate-preflight-{label}"),
        &records,
    )
}

fn decision_merkle(label: &str, checks: &[PreflightCheck], decision: PreflightDecision) -> String {
    let records = checks
        .iter()
        .filter(|check| check.decision == decision)
        .map(|check| {
            json!({
                "label": label,
                "kind": check.kind.as_str(),
                "decision": check.decision.as_str(),
                "preflight_root": check.preflight_root,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-bridge-exit-runtime-gate-preflight-decision-{label}"),
        &records,
    )
}

fn blocker_merkle(checks: &[PreflightCheck]) -> String {
    let records = checks
        .iter()
        .map(|check| {
            json!({
                "kind": check.kind.as_str(),
                "release_blockers": check.release_blockers,
                "decision": check.decision.as_str(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-runtime-gate-preflight-blockers",
        &records,
    )
}

fn lane_merkle<F>(label: &str, checks: &[PreflightCheck], root: F) -> String
where
    F: Fn(&PreflightCheck) -> &String,
{
    let records = checks
        .iter()
        .map(|check| {
            json!({
                "label": label,
                "kind": check.kind.as_str(),
                "root": root(check),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-bridge-exit-runtime-gate-preflight-lane-{label}"),
        &records,
    )
}

fn matrix_id(config: &Config, roots: &PreflightMatrixRoots) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-runtime-gate-preflight-matrix-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(config.l2_reference_height),
            HashPart::U64(config.monero_reference_height),
            HashPart::Str(&roots.check_root),
            HashPart::Str(&roots.blocker_root),
            HashPart::Str(&roots.counter_root),
        ],
        16,
    )
}

fn release_hold_reasons() -> BTreeMap<String, String> {
    [
        (
            "cargo_runtime",
            "compile and execute the preflight harness before release",
        ),
        (
            "live_monero_feeds",
            "replace deterministic feed fixtures with live header deposit reorg reserve and PQ authority feeds",
        ),
        (
            "negative_cases",
            "run adversarial rejection cases and bind fail-closed receipts",
        ),
        (
            "privacy_review",
            "prove wallet scan hints encrypted receipts and metadata budgets do not leak linkable state",
        ),
        (
            "pq_control_plane",
            "verify sequencer watcher bridge upgrade and withdrawal authority keys under PQ policy",
        ),
        (
            "reserve_handoff",
            "bind reserve coverage and liquidity exhaustion recovery receipts before any production release",
        ),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect()
}

fn hold_root(reasons: &BTreeMap<String, String>) -> String {
    let records = reasons
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-runtime-gate-preflight-release-holds",
        &records,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-runtime-gate-preflight-record",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
