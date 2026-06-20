use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceRuntimeGateExecutionReceiptManifestRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_GATE_EXECUTION_RECEIPT_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-runtime-gate-execution-receipt-manifest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_GATE_EXECUTION_RECEIPT_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECEIPT_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-runtime-gate-execution-receipts-v1";
pub const DEFAULT_L2_HEIGHT: u64 = 4_260_192;
pub const DEFAULT_MONERO_HEIGHT: u64 = 3_530_192;
pub const DEFAULT_MIN_PQ_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_000;
pub const DEFAULT_MAX_METADATA_UNITS: u64 = 3;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptGateKind {
    DepositNote,
    PrivateReceipt,
    ContractReceipt,
    WithdrawalClaim,
    FeedReplay,
    AdversarialCases,
    ReleaseBlockers,
    EvidenceAcceptance,
}

impl ReceiptGateKind {
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
pub enum ReceiptStatus {
    ExpectedPassAfterRuntime,
    ExpectedFailClosed,
    RequiresLiveFeedSwap,
    RequiresCargoRuntime,
    ReleaseHeld,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExpectedPassAfterRuntime => "expected_pass_after_runtime",
            Self::ExpectedFailClosed => "expected_fail_closed",
            Self::RequiresLiveFeedSwap => "requires_live_feed_swap",
            Self::RequiresCargoRuntime => "requires_cargo_runtime",
            Self::ReleaseHeld => "release_held",
        }
    }

    pub fn release_blocking(self) -> bool {
        matches!(
            self,
            Self::RequiresLiveFeedSwap | Self::RequiresCargoRuntime | Self::ReleaseHeld
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestVerdict {
    ReceiptEnvelopeReady,
    ProductionReleaseBlocked,
}

impl ManifestVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptEnvelopeReady => "receipt_envelope_ready",
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
            "receipt_suite": RECEIPT_SUITE,
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
pub struct ExecutionReceipt {
    pub kind: ReceiptGateKind,
    pub status: ReceiptStatus,
    pub receipt_id: String,
    pub invocation_runtime: String,
    pub preflight_runtime: String,
    pub execution_receipt_runtime: String,
    pub expected_execution: String,
    pub operator_evidence_root: String,
    pub wallet_visible_root: String,
    pub public_receipt_root: String,
    pub encrypted_receipt_root: String,
    pub fail_closed_receipt_root: String,
    pub expected_invocation_root: String,
    pub expected_preflight_root: String,
    pub observed_runtime_root: String,
    pub monero_evidence_root: String,
    pub pq_authority_root: String,
    pub privacy_budget_root: String,
    pub reserve_root: String,
    pub release_blockers: Vec<String>,
}

impl ExecutionReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "ordinal": self.kind.ordinal(),
            "status": self.status.as_str(),
            "release_blocking": self.status.release_blocking(),
            "receipt_id": self.receipt_id,
            "invocation_runtime": self.invocation_runtime,
            "preflight_runtime": self.preflight_runtime,
            "execution_receipt_runtime": self.execution_receipt_runtime,
            "expected_execution": self.expected_execution,
            "operator_evidence_root": self.operator_evidence_root,
            "wallet_visible_root": self.wallet_visible_root,
            "public_receipt_root": self.public_receipt_root,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "fail_closed_receipt_root": self.fail_closed_receipt_root,
            "expected_invocation_root": self.expected_invocation_root,
            "expected_preflight_root": self.expected_preflight_root,
            "observed_runtime_root": self.observed_runtime_root,
            "monero_evidence_root": self.monero_evidence_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_budget_root": self.privacy_budget_root,
            "reserve_root": self.reserve_root,
            "release_blockers": self.release_blockers,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("execution-receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptCounters {
    pub total_receipts: u64,
    pub expected_pass_after_runtime: u64,
    pub expected_fail_closed: u64,
    pub live_feed_swaps_required: u64,
    pub cargo_runtime_required: u64,
    pub release_holds: u64,
}

impl ReceiptCounters {
    pub fn from_receipts(receipts: &[ExecutionReceipt]) -> Self {
        let mut counters = Self {
            total_receipts: receipts.len() as u64,
            expected_pass_after_runtime: 0,
            expected_fail_closed: 0,
            live_feed_swaps_required: 0,
            cargo_runtime_required: 0,
            release_holds: 0,
        };
        for receipt in receipts {
            match receipt.status {
                ReceiptStatus::ExpectedPassAfterRuntime => {
                    counters.expected_pass_after_runtime += 1;
                }
                ReceiptStatus::ExpectedFailClosed => {
                    counters.expected_fail_closed += 1;
                }
                ReceiptStatus::RequiresLiveFeedSwap => {
                    counters.live_feed_swaps_required += 1;
                }
                ReceiptStatus::RequiresCargoRuntime => {
                    counters.cargo_runtime_required += 1;
                }
                ReceiptStatus::ReleaseHeld => {
                    counters.release_holds += 1;
                }
            }
        }
        counters
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_receipts": self.total_receipts,
            "expected_pass_after_runtime": self.expected_pass_after_runtime,
            "expected_fail_closed": self.expected_fail_closed,
            "live_feed_swaps_required": self.live_feed_swaps_required,
            "cargo_runtime_required": self.cargo_runtime_required,
            "release_holds": self.release_holds,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("receipt-counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptManifestRoots {
    pub receipt_root: String,
    pub pass_root: String,
    pub fail_closed_root: String,
    pub operator_evidence_root: String,
    pub wallet_visible_root: String,
    pub public_receipt_root: String,
    pub encrypted_receipt_root: String,
    pub monero_evidence_root: String,
    pub pq_authority_root: String,
    pub privacy_budget_root: String,
    pub reserve_root: String,
    pub blocker_root: String,
    pub counter_root: String,
}

impl ReceiptManifestRoots {
    pub fn from_receipts(receipts: &[ExecutionReceipt], counters: &ReceiptCounters) -> Self {
        Self {
            receipt_root: receipt_merkle("receipts", receipts, ExecutionReceipt::state_root),
            pass_root: status_merkle(
                "expected-pass",
                receipts,
                ReceiptStatus::ExpectedPassAfterRuntime,
            ),
            fail_closed_root: status_merkle(
                "expected-fail-closed",
                receipts,
                ReceiptStatus::ExpectedFailClosed,
            ),
            operator_evidence_root: lane_merkle("operator-evidence", receipts, |receipt| {
                &receipt.operator_evidence_root
            }),
            wallet_visible_root: lane_merkle("wallet-visible", receipts, |receipt| {
                &receipt.wallet_visible_root
            }),
            public_receipt_root: lane_merkle("public-receipt", receipts, |receipt| {
                &receipt.public_receipt_root
            }),
            encrypted_receipt_root: lane_merkle("encrypted-receipt", receipts, |receipt| {
                &receipt.encrypted_receipt_root
            }),
            monero_evidence_root: lane_merkle("monero-evidence", receipts, |receipt| {
                &receipt.monero_evidence_root
            }),
            pq_authority_root: lane_merkle("pq-authority", receipts, |receipt| {
                &receipt.pq_authority_root
            }),
            privacy_budget_root: lane_merkle("privacy-budget", receipts, |receipt| {
                &receipt.privacy_budget_root
            }),
            reserve_root: lane_merkle("reserve", receipts, |receipt| &receipt.reserve_root),
            blocker_root: blocker_merkle(receipts),
            counter_root: counters.state_root(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_root": self.receipt_root,
            "pass_root": self.pass_root,
            "fail_closed_root": self.fail_closed_root,
            "operator_evidence_root": self.operator_evidence_root,
            "wallet_visible_root": self.wallet_visible_root,
            "public_receipt_root": self.public_receipt_root,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "monero_evidence_root": self.monero_evidence_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_budget_root": self.privacy_budget_root,
            "reserve_root": self.reserve_root,
            "blocker_root": self.blocker_root,
            "counter_root": self.counter_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("receipt-manifest-roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptManifest {
    pub manifest_id: String,
    pub verdict: ManifestVerdict,
    pub cargo_runtime_required_next: bool,
    pub live_feed_swap_required_next: bool,
    pub production_release_allowed: bool,
    pub counters: ReceiptCounters,
    pub roots: ReceiptManifestRoots,
}

impl ReceiptManifest {
    pub fn public_record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "verdict": self.verdict.as_str(),
            "cargo_runtime_required_next": self.cargo_runtime_required_next,
            "live_feed_swap_required_next": self.live_feed_swap_required_next,
            "production_release_allowed": self.production_release_allowed,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("receipt-manifest", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub receipts: Vec<ExecutionReceipt>,
    pub manifest: ReceiptManifest,
    pub release_hold_reasons: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let receipts = ReceiptGateKind::all()
            .into_iter()
            .map(|kind| default_receipt(&config, kind))
            .collect::<Vec<_>>();
        let counters = ReceiptCounters::from_receipts(&receipts);
        let roots = ReceiptManifestRoots::from_receipts(&receipts, &counters);
        let manifest = ReceiptManifest {
            manifest_id: manifest_id(&config, &roots),
            verdict: ManifestVerdict::ProductionReleaseBlocked,
            cargo_runtime_required_next: true,
            live_feed_swap_required_next: true,
            production_release_allowed: false,
            counters,
            roots,
        };
        Self {
            config,
            receipts,
            manifest,
            release_hold_reasons: release_hold_reasons(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "receipts": self.receipts.iter().map(ExecutionReceipt::public_record).collect::<Vec<_>>(),
            "manifest": self.manifest.public_record(),
            "release_hold_reasons": self.release_hold_reasons,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-vertical-slice-runtime-gate-execution-receipt-manifest-state",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.manifest.state_root()),
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

fn default_receipt(config: &Config, kind: ReceiptGateKind) -> ExecutionReceipt {
    let status = status_for(kind);
    let release_blockers = release_blockers(kind);
    let payload = json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "kind": kind.as_str(),
        "ordinal": kind.ordinal(),
        "status": status.as_str(),
        "l2_reference_height": config.l2_reference_height + kind.ordinal(),
        "monero_reference_height": config.monero_reference_height + kind.ordinal(),
        "release_blockers": release_blockers,
    });
    let expected_invocation_root = root_for("expected-invocation", kind, &payload);
    let expected_preflight_root = root_for("expected-preflight", kind, &payload);
    let observed_runtime_root = root_for("observed-runtime-placeholder", kind, &payload);
    let operator_evidence_root = root_for("operator-evidence", kind, &payload);
    let wallet_visible_root = root_for("wallet-visible", kind, &payload);
    let public_receipt_root = root_for("public-receipt", kind, &payload);
    let encrypted_receipt_root = root_for("encrypted-receipt", kind, &payload);
    let fail_closed_receipt_root = root_for("fail-closed-receipt", kind, &payload);
    let monero_evidence_root = root_for("monero-evidence", kind, &payload);
    let pq_authority_root = root_for("pq-authority", kind, &payload);
    let privacy_budget_root = root_for("privacy-budget", kind, &payload);
    let reserve_root = root_for("reserve", kind, &payload);
    let receipt_id = domain_hash(
        "monero-l2-pq-bridge-exit-runtime-gate-execution-receipt-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(&expected_invocation_root),
            HashPart::Str(&expected_preflight_root),
        ],
        16,
    );
    ExecutionReceipt {
        kind,
        status,
        receipt_id,
        invocation_runtime: invocation_runtime(kind).to_string(),
        preflight_runtime: preflight_runtime(kind).to_string(),
        execution_receipt_runtime: execution_receipt_runtime(kind).to_string(),
        expected_execution: expected_execution(kind).to_string(),
        operator_evidence_root,
        wallet_visible_root,
        public_receipt_root,
        encrypted_receipt_root,
        fail_closed_receipt_root,
        expected_invocation_root,
        expected_preflight_root,
        observed_runtime_root,
        monero_evidence_root,
        pq_authority_root,
        privacy_budget_root,
        reserve_root,
        release_blockers,
    }
}

fn status_for(kind: ReceiptGateKind) -> ReceiptStatus {
    match kind {
        ReceiptGateKind::DepositNote
        | ReceiptGateKind::PrivateReceipt
        | ReceiptGateKind::ContractReceipt
        | ReceiptGateKind::WithdrawalClaim => ReceiptStatus::ExpectedPassAfterRuntime,
        ReceiptGateKind::FeedReplay => ReceiptStatus::RequiresLiveFeedSwap,
        ReceiptGateKind::AdversarialCases => ReceiptStatus::ExpectedFailClosed,
        ReceiptGateKind::ReleaseBlockers => ReceiptStatus::ReleaseHeld,
        ReceiptGateKind::EvidenceAcceptance => ReceiptStatus::RequiresCargoRuntime,
    }
}

fn invocation_runtime(kind: ReceiptGateKind) -> &'static str {
    match kind {
        ReceiptGateKind::DepositNote => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_deposit_note_gate_invocation_runtime"
        }
        ReceiptGateKind::PrivateReceipt => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_private_receipt_gate_invocation_runtime"
        }
        ReceiptGateKind::ContractReceipt => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_contract_receipt_gate_invocation_runtime"
        }
        ReceiptGateKind::WithdrawalClaim => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_withdrawal_claim_gate_invocation_runtime"
        }
        ReceiptGateKind::FeedReplay => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_feed_replay_fixture_runtime"
        }
        ReceiptGateKind::AdversarialCases => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_adversarial_gate_invocation_runtime"
        }
        ReceiptGateKind::ReleaseBlockers => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_release_blocker_gate_invocation_runtime"
        }
        ReceiptGateKind::EvidenceAcceptance => {
            "monero_l2_pq_bridge_exit_canonical_runtime_evidence_acceptance_runtime"
        }
    }
}

fn preflight_runtime(kind: ReceiptGateKind) -> &'static str {
    match kind {
        ReceiptGateKind::DepositNote => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_deposit_note_gate_preflight_runtime"
        }
        ReceiptGateKind::PrivateReceipt => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_private_receipt_gate_preflight_runtime"
        }
        ReceiptGateKind::ContractReceipt => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_contract_receipt_gate_preflight_runtime"
        }
        ReceiptGateKind::WithdrawalClaim => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_withdrawal_claim_gate_preflight_runtime"
        }
        ReceiptGateKind::FeedReplay => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_runtime_gate_preflight_matrix_runtime"
        }
        ReceiptGateKind::AdversarialCases => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_adversarial_gate_preflight_runtime"
        }
        ReceiptGateKind::ReleaseBlockers => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_release_blocker_gate_preflight_runtime"
        }
        ReceiptGateKind::EvidenceAcceptance => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_runtime_gate_preflight_matrix_runtime"
        }
    }
}

fn execution_receipt_runtime(kind: ReceiptGateKind) -> &'static str {
    match kind {
        ReceiptGateKind::DepositNote => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_deposit_note_gate_execution_receipt_runtime"
        }
        ReceiptGateKind::PrivateReceipt => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_private_receipt_gate_execution_receipt_runtime"
        }
        ReceiptGateKind::ContractReceipt => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_contract_receipt_gate_execution_receipt_runtime"
        }
        ReceiptGateKind::WithdrawalClaim => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_withdrawal_claim_gate_execution_receipt_runtime"
        }
        ReceiptGateKind::FeedReplay => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_runtime_gate_execution_receipt_manifest_runtime"
        }
        ReceiptGateKind::AdversarialCases => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_adversarial_gate_execution_receipt_runtime"
        }
        ReceiptGateKind::ReleaseBlockers => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_release_blocker_gate_execution_receipt_runtime"
        }
        ReceiptGateKind::EvidenceAcceptance => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_runtime_gate_execution_receipt_manifest_runtime"
        }
    }
}

fn expected_execution(kind: ReceiptGateKind) -> &'static str {
    match kind {
        ReceiptGateKind::DepositNote => {
            "accept Monero lock evidence and mint private L2 note commitment"
        }
        ReceiptGateKind::PrivateReceipt => {
            "accept private transfer receipt and keep wallet-visible data encrypted"
        }
        ReceiptGateKind::ContractReceipt => {
            "accept sealed contract action receipt with encrypted effect root"
        }
        ReceiptGateKind::WithdrawalClaim => {
            "accept withdrawal claim only with challenge reserve and PQ authorization evidence"
        }
        ReceiptGateKind::FeedReplay => {
            "replace deterministic replay feeds with live Monero and PQ authority feeds"
        }
        ReceiptGateKind::AdversarialCases => "emit fail-closed receipts for every adversarial case",
        ReceiptGateKind::ReleaseBlockers => {
            "emit no-go release receipts until all heavy gates pass"
        }
        ReceiptGateKind::EvidenceAcceptance => {
            "bind compiled runtime receipts into the release evidence manifest"
        }
    }
}

fn release_blockers(kind: ReceiptGateKind) -> Vec<String> {
    match kind {
        ReceiptGateKind::DepositNote
        | ReceiptGateKind::PrivateReceipt
        | ReceiptGateKind::ContractReceipt
        | ReceiptGateKind::WithdrawalClaim => vec!["cargo_runtime_execution_deferred"],
        ReceiptGateKind::FeedReplay => vec![
            "live_monero_feed_swap_pending",
            "pq_authority_feed_swap_pending",
        ],
        ReceiptGateKind::AdversarialCases => vec![
            "negative_case_runtime_execution_pending",
            "fail_closed_receipt_not_observed",
        ],
        ReceiptGateKind::ReleaseBlockers => vec![
            "cargo_runtime_deferred",
            "independent_audit_open",
            "privacy_review_open",
            "pq_key_verification_pending",
            "reserve_proof_handoff_pending",
        ],
        ReceiptGateKind::EvidenceAcceptance => vec![
            "compiled_runtime_evidence_missing",
            "operator_release_receipt_missing",
        ],
    }
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn root_for(kind: &str, gate: ReceiptGateKind, payload: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-runtime-gate-execution-receipt-root",
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

fn receipt_merkle<F>(label: &str, receipts: &[ExecutionReceipt], root: F) -> String
where
    F: Fn(&ExecutionReceipt) -> String,
{
    let records = receipts
        .iter()
        .map(|receipt| {
            json!({
                "label": label,
                "kind": receipt.kind.as_str(),
                "root": root(receipt),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-bridge-exit-runtime-gate-execution-receipt-{label}"),
        &records,
    )
}

fn status_merkle(label: &str, receipts: &[ExecutionReceipt], status: ReceiptStatus) -> String {
    let records = receipts
        .iter()
        .filter(|receipt| receipt.status == status)
        .map(|receipt| {
            json!({
                "label": label,
                "kind": receipt.kind.as_str(),
                "status": receipt.status.as_str(),
                "receipt_id": receipt.receipt_id,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-bridge-exit-runtime-gate-execution-receipt-status-{label}"),
        &records,
    )
}

fn lane_merkle<F>(label: &str, receipts: &[ExecutionReceipt], root: F) -> String
where
    F: Fn(&ExecutionReceipt) -> &String,
{
    let records = receipts
        .iter()
        .map(|receipt| {
            json!({
                "label": label,
                "kind": receipt.kind.as_str(),
                "root": root(receipt),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-bridge-exit-runtime-gate-execution-receipt-lane-{label}"),
        &records,
    )
}

fn blocker_merkle(receipts: &[ExecutionReceipt]) -> String {
    let records = receipts
        .iter()
        .map(|receipt| {
            json!({
                "kind": receipt.kind.as_str(),
                "status": receipt.status.as_str(),
                "release_blockers": receipt.release_blockers,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-runtime-gate-execution-receipt-blockers",
        &records,
    )
}

fn manifest_id(config: &Config, roots: &ReceiptManifestRoots) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-runtime-gate-execution-receipt-manifest-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(config.l2_reference_height),
            HashPart::U64(config.monero_reference_height),
            HashPart::Str(&roots.receipt_root),
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
            "execute the receipt harness under cargo before any release",
        ),
        (
            "live_monero_feeds",
            "bind live header deposit reorg reserve and PQ authority feeds into observed receipts",
        ),
        (
            "wallet_privacy",
            "verify wallet-visible receipt roots do not reveal linkable state",
        ),
        (
            "adversarial_receipts",
            "bind fail-closed receipts for sequencer watcher reorg reserve and metadata cases",
        ),
        (
            "audit_receipts",
            "attach independent audit privacy PQ reserve and release signoff receipts",
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
        "monero-l2-pq-bridge-exit-runtime-gate-execution-receipt-release-holds",
        &records,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-runtime-gate-execution-receipt-record",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
