use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceExecutionHarnessRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_EXECUTION_HARNESS_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-execution-harness-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_EXECUTION_HARNESS_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const HARNESS_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-execution-harness-v1";
pub const DEFAULT_L2_HEIGHT: u64 = 4_250_000;
pub const DEFAULT_MONERO_HEIGHT: u64 = 3_525_000;
pub const DEFAULT_MIN_PQ_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_000;
pub const DEFAULT_MAX_METADATA_UNITS: u64 = 3;
pub const DEFAULT_MAX_FEE_ATOMIC: u64 = 35_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessLane {
    FixtureBundle,
    ExpectedRoots,
    WalletReplayCli,
    FeedReplayFixture,
    DepositLockToPrivateNote,
    PrivateTransferReceipt,
    ContractActionReceipt,
    WithdrawalClaim,
    AdversarialAssertions,
    EvidenceAcceptance,
    ReleaseBlockers,
}

impl HarnessLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FixtureBundle => "fixture_bundle",
            Self::ExpectedRoots => "expected_roots",
            Self::WalletReplayCli => "wallet_replay_cli",
            Self::FeedReplayFixture => "feed_replay_fixture",
            Self::DepositLockToPrivateNote => "deposit_lock_to_private_note",
            Self::PrivateTransferReceipt => "private_transfer_receipt",
            Self::ContractActionReceipt => "contract_action_receipt",
            Self::WithdrawalClaim => "withdrawal_claim",
            Self::AdversarialAssertions => "adversarial_assertions",
            Self::EvidenceAcceptance => "evidence_acceptance",
            Self::ReleaseBlockers => "release_blockers",
        }
    }

    pub fn ordinal(self) -> u64 {
        match self {
            Self::FixtureBundle => 0,
            Self::ExpectedRoots => 1,
            Self::WalletReplayCli => 2,
            Self::FeedReplayFixture => 3,
            Self::DepositLockToPrivateNote => 4,
            Self::PrivateTransferReceipt => 5,
            Self::ContractActionReceipt => 6,
            Self::WithdrawalClaim => 7,
            Self::AdversarialAssertions => 8,
            Self::EvidenceAcceptance => 9,
            Self::ReleaseBlockers => 10,
        }
    }

    pub fn all() -> Vec<Self> {
        vec![
            Self::FixtureBundle,
            Self::ExpectedRoots,
            Self::WalletReplayCli,
            Self::FeedReplayFixture,
            Self::DepositLockToPrivateNote,
            Self::PrivateTransferReceipt,
            Self::ContractActionReceipt,
            Self::WithdrawalClaim,
            Self::AdversarialAssertions,
            Self::EvidenceAcceptance,
            Self::ReleaseBlockers,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessStatus {
    Ready,
    Watch,
    Deferred,
    Blocked,
}

impl HarnessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Watch => "watch",
            Self::Deferred => "deferred",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessBlocker {
    CargoRuntimeDeferred,
    LiveFeedSwapDeferred,
    ForcedExitExecutionDeferred,
    AuditOpen,
    ProductionReleaseHeld,
}

impl HarnessBlocker {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoRuntimeDeferred => "cargo_runtime_deferred",
            Self::LiveFeedSwapDeferred => "live_feed_swap_deferred",
            Self::ForcedExitExecutionDeferred => "forced_exit_execution_deferred",
            Self::AuditOpen => "audit_open",
            Self::ProductionReleaseHeld => "production_release_held",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessVerdict {
    HarnessReadyForDeferredRuntimeGate,
    ProductionReleaseBlocked,
}

impl HarnessVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HarnessReadyForDeferredRuntimeGate => "harness_ready_for_deferred_runtime_gate",
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
    pub max_fee_atomic: u64,
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
            max_fee_atomic: DEFAULT_MAX_FEE_ATOMIC,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "harness_suite": HARNESS_SUITE,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "min_pq_weight_bps": self.min_pq_weight_bps,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "max_metadata_units": self.max_metadata_units,
            "max_fee_atomic": self.max_fee_atomic,
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
pub struct HarnessInput {
    pub lane: HarnessLane,
    pub status: HarnessStatus,
    pub fixture_root: String,
    pub expected_root: String,
    pub replay_root: String,
    pub assertion_root: String,
    pub evidence_root: String,
    pub public_root: String,
    pub committed_root: String,
    pub encrypted_wallet_root: String,
    pub pq_authority_root: String,
    pub privacy_root: String,
    pub reserve_root: String,
    pub fail_closed_root: String,
    pub wallet_replayable: bool,
    pub operator_independent: bool,
    pub live_feed_required: bool,
    pub cargo_runtime_required: bool,
    pub blocks_production_release: bool,
    pub pq_weight_bps: u64,
    pub reserve_coverage_bps: u64,
    pub metadata_units: u64,
    pub fee_atomic: u64,
    pub blocker: Option<HarnessBlocker>,
}

impl HarnessInput {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "fixture_root": self.fixture_root,
            "expected_root": self.expected_root,
            "replay_root": self.replay_root,
            "assertion_root": self.assertion_root,
            "evidence_root": self.evidence_root,
            "public_root": self.public_root,
            "committed_root": self.committed_root,
            "encrypted_wallet_root": self.encrypted_wallet_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_root": self.privacy_root,
            "reserve_root": self.reserve_root,
            "fail_closed_root": self.fail_closed_root,
            "wallet_replayable": yes_no(self.wallet_replayable),
            "operator_independent": yes_no(self.operator_independent),
            "live_feed_required": yes_no(self.live_feed_required),
            "cargo_runtime_required": yes_no(self.cargo_runtime_required),
            "blocks_production_release": yes_no(self.blocks_production_release),
            "pq_weight_bps": self.pq_weight_bps,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "metadata_units": self.metadata_units,
            "fee_atomic": self.fee_atomic,
            "blocker": self.blocker.map(HarnessBlocker::as_str).unwrap_or("none"),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(self.lane.as_str(), &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HarnessCounters {
    pub total_lanes: u64,
    pub ready_lanes: u64,
    pub watch_lanes: u64,
    pub deferred_lanes: u64,
    pub blocked_lanes: u64,
    pub production_blockers: u64,
    pub wallet_replayable_lanes: u64,
    pub operator_dependent_lanes: u64,
    pub live_feed_required_lanes: u64,
    pub cargo_runtime_required_lanes: u64,
    pub min_pq_weight_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub max_metadata_units: u64,
    pub max_fee_atomic: u64,
}

impl HarnessCounters {
    pub fn from_inputs(inputs: &[HarnessInput]) -> Self {
        Self {
            total_lanes: inputs.len() as u64,
            ready_lanes: inputs
                .iter()
                .filter(|input| input.status == HarnessStatus::Ready)
                .count() as u64,
            watch_lanes: inputs
                .iter()
                .filter(|input| input.status == HarnessStatus::Watch)
                .count() as u64,
            deferred_lanes: inputs
                .iter()
                .filter(|input| input.status == HarnessStatus::Deferred)
                .count() as u64,
            blocked_lanes: inputs
                .iter()
                .filter(|input| input.status == HarnessStatus::Blocked)
                .count() as u64,
            production_blockers: inputs
                .iter()
                .filter(|input| input.blocks_production_release)
                .count() as u64,
            wallet_replayable_lanes: inputs
                .iter()
                .filter(|input| input.wallet_replayable)
                .count() as u64,
            operator_dependent_lanes: inputs
                .iter()
                .filter(|input| !input.operator_independent)
                .count() as u64,
            live_feed_required_lanes: inputs
                .iter()
                .filter(|input| input.live_feed_required)
                .count() as u64,
            cargo_runtime_required_lanes: inputs
                .iter()
                .filter(|input| input.cargo_runtime_required)
                .count() as u64,
            min_pq_weight_bps: inputs
                .iter()
                .map(|input| input.pq_weight_bps)
                .min()
                .unwrap_or_default(),
            min_reserve_coverage_bps: inputs
                .iter()
                .map(|input| input.reserve_coverage_bps)
                .min()
                .unwrap_or_default(),
            max_metadata_units: inputs
                .iter()
                .map(|input| input.metadata_units)
                .max()
                .unwrap_or_default(),
            max_fee_atomic: inputs
                .iter()
                .map(|input| input.fee_atomic)
                .max()
                .unwrap_or_default(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_lanes": self.total_lanes,
            "ready_lanes": self.ready_lanes,
            "watch_lanes": self.watch_lanes,
            "deferred_lanes": self.deferred_lanes,
            "blocked_lanes": self.blocked_lanes,
            "production_blockers": self.production_blockers,
            "wallet_replayable_lanes": self.wallet_replayable_lanes,
            "operator_dependent_lanes": self.operator_dependent_lanes,
            "live_feed_required_lanes": self.live_feed_required_lanes,
            "cargo_runtime_required_lanes": self.cargo_runtime_required_lanes,
            "min_pq_weight_bps": self.min_pq_weight_bps,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "max_metadata_units": self.max_metadata_units,
            "max_fee_atomic": self.max_fee_atomic,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("harness_counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HarnessRoots {
    pub input_root: String,
    pub fixture_root: String,
    pub expected_root: String,
    pub replay_root: String,
    pub assertion_root: String,
    pub evidence_root: String,
    pub public_root: String,
    pub committed_root: String,
    pub encrypted_wallet_root: String,
    pub pq_authority_root: String,
    pub privacy_root: String,
    pub reserve_root: String,
    pub fail_closed_root: String,
    pub counter_root: String,
    pub blocker_root: String,
}

impl HarnessRoots {
    pub fn from_inputs(inputs: &[HarnessInput], counters: &HarnessCounters) -> Self {
        Self {
            input_root: input_merkle("input", inputs, HarnessInput::public_record),
            fixture_root: lane_merkle("fixture", inputs, |input| &input.fixture_root),
            expected_root: lane_merkle("expected", inputs, |input| &input.expected_root),
            replay_root: lane_merkle("replay", inputs, |input| &input.replay_root),
            assertion_root: lane_merkle("assertion", inputs, |input| &input.assertion_root),
            evidence_root: lane_merkle("evidence", inputs, |input| &input.evidence_root),
            public_root: lane_merkle("public", inputs, |input| &input.public_root),
            committed_root: lane_merkle("committed", inputs, |input| &input.committed_root),
            encrypted_wallet_root: lane_merkle("encrypted_wallet", inputs, |input| {
                &input.encrypted_wallet_root
            }),
            pq_authority_root: lane_merkle("pq_authority", inputs, |input| {
                &input.pq_authority_root
            }),
            privacy_root: lane_merkle("privacy", inputs, |input| &input.privacy_root),
            reserve_root: lane_merkle("reserve", inputs, |input| &input.reserve_root),
            fail_closed_root: lane_merkle("fail_closed", inputs, |input| &input.fail_closed_root),
            counter_root: counters.state_root(),
            blocker_root: blocker_merkle(inputs),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "input_root": self.input_root,
            "fixture_root": self.fixture_root,
            "expected_root": self.expected_root,
            "replay_root": self.replay_root,
            "assertion_root": self.assertion_root,
            "evidence_root": self.evidence_root,
            "public_root": self.public_root,
            "committed_root": self.committed_root,
            "encrypted_wallet_root": self.encrypted_wallet_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_root": self.privacy_root,
            "reserve_root": self.reserve_root,
            "fail_closed_root": self.fail_closed_root,
            "counter_root": self.counter_root,
            "blocker_root": self.blocker_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("harness_roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionHarness {
    pub harness_id: String,
    pub verdict: HarnessVerdict,
    pub ready_for_cargo_runtime: bool,
    pub ready_for_live_feed_swap: bool,
    pub production_release_allowed: bool,
    pub counters: HarnessCounters,
    pub roots: HarnessRoots,
}

impl ExecutionHarness {
    pub fn public_record(&self) -> Value {
        json!({
            "harness_id": self.harness_id,
            "verdict": self.verdict.as_str(),
            "ready_for_cargo_runtime": yes_no(self.ready_for_cargo_runtime),
            "ready_for_live_feed_swap": yes_no(self.ready_for_live_feed_swap),
            "production_release_allowed": yes_no(self.production_release_allowed),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("execution_harness", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub inputs: Vec<HarnessInput>,
    pub harness: ExecutionHarness,
    pub next_required_gates: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let inputs = HarnessLane::all()
            .into_iter()
            .map(|lane| default_input(&config, lane))
            .collect::<Vec<_>>();
        let counters = HarnessCounters::from_inputs(&inputs);
        let roots = HarnessRoots::from_inputs(&inputs, &counters);
        let harness = ExecutionHarness {
            harness_id: harness_id(&config, &roots),
            verdict: HarnessVerdict::ProductionReleaseBlocked,
            ready_for_cargo_runtime: true,
            ready_for_live_feed_swap: false,
            production_release_allowed: false,
            counters,
            roots,
        };
        Self {
            config,
            inputs,
            harness,
            next_required_gates: next_required_gates(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "inputs": self.inputs.iter().map(HarnessInput::public_record).collect::<Vec<_>>(),
            "harness": self.harness.public_record(),
            "next_required_gates": self.next_required_gates,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-vertical-slice-execution-harness-state",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.harness.state_root()),
                HashPart::Str(&gate_root(&self.next_required_gates)),
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

fn default_input(config: &Config, lane: HarnessLane) -> HarnessInput {
    let status = match lane {
        HarnessLane::FeedReplayFixture => HarnessStatus::Watch,
        HarnessLane::EvidenceAcceptance => HarnessStatus::Deferred,
        HarnessLane::ReleaseBlockers => HarnessStatus::Blocked,
        _ => HarnessStatus::Ready,
    };
    let blocker = match lane {
        HarnessLane::FeedReplayFixture => Some(HarnessBlocker::LiveFeedSwapDeferred),
        HarnessLane::EvidenceAcceptance => Some(HarnessBlocker::CargoRuntimeDeferred),
        HarnessLane::AdversarialAssertions => Some(HarnessBlocker::AuditOpen),
        HarnessLane::ReleaseBlockers => Some(HarnessBlocker::ProductionReleaseHeld),
        HarnessLane::WithdrawalClaim => Some(HarnessBlocker::ForcedExitExecutionDeferred),
        _ => None,
    };
    let payload = json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "lane": lane.as_str(),
        "ordinal": lane.ordinal(),
        "l2_height": config.l2_reference_height + lane.ordinal(),
        "monero_height": config.monero_reference_height + lane.ordinal(),
        "wallet_material": "encrypted",
        "operator_material": "not_required",
        "blocker": blocker.map(HarnessBlocker::as_str).unwrap_or("none"),
    });

    HarnessInput {
        lane,
        status,
        fixture_root: root_for("fixture", lane, &payload),
        expected_root: root_for("expected", lane, &payload),
        replay_root: root_for("wallet-replay", lane, &payload),
        assertion_root: root_for("assertion", lane, &payload),
        evidence_root: root_for("evidence", lane, &payload),
        public_root: root_for("public", lane, &payload),
        committed_root: root_for("committed", lane, &payload),
        encrypted_wallet_root: root_for("encrypted-wallet", lane, &payload),
        pq_authority_root: root_for("pq-authority", lane, &payload),
        privacy_root: root_for("privacy", lane, &payload),
        reserve_root: root_for("reserve", lane, &payload),
        fail_closed_root: root_for("fail-closed", lane, &payload),
        wallet_replayable: true,
        operator_independent: true,
        live_feed_required: matches!(lane, HarnessLane::FeedReplayFixture),
        cargo_runtime_required: matches!(lane, HarnessLane::EvidenceAcceptance),
        blocks_production_release: blocker.is_some(),
        pq_weight_bps: config.min_pq_weight_bps + 800,
        reserve_coverage_bps: config.min_reserve_coverage_bps + 1_000,
        metadata_units: if matches!(lane, HarnessLane::ReleaseBlockers) {
            1
        } else {
            0
        },
        fee_atomic: config.max_fee_atomic / 2 + lane.ordinal(),
        blocker,
    }
}

fn root_for(kind: &str, lane: HarnessLane, payload: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-vertical-slice-execution-harness-lane-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(lane.as_str()),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn input_merkle<F>(kind: &str, inputs: &[HarnessInput], mapper: F) -> String
where
    F: Fn(&HarnessInput) -> Value,
{
    let records = inputs.iter().map(mapper).collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-bridge-exit-vertical-slice-harness-{kind}"),
        &records,
    )
}

fn lane_merkle<F>(kind: &str, inputs: &[HarnessInput], mapper: F) -> String
where
    F: Fn(&HarnessInput) -> &String,
{
    let records = inputs
        .iter()
        .map(|input| {
            json!({
                "lane": input.lane.as_str(),
                "root": mapper(input),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-bridge-exit-vertical-slice-harness-{kind}-roots"),
        &records,
    )
}

fn blocker_merkle(inputs: &[HarnessInput]) -> String {
    let records = inputs
        .iter()
        .map(|input| {
            json!({
                "lane": input.lane.as_str(),
                "blocker": input.blocker.map(HarnessBlocker::as_str).unwrap_or("none"),
                "blocks_production_release": yes_no(input.blocks_production_release),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-vertical-slice-harness-blockers",
        &records,
    )
}

fn harness_id(config: &Config, roots: &HarnessRoots) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-vertical-slice-execution-harness-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(config.l2_reference_height),
            HashPart::U64(config.monero_reference_height),
            HashPart::Str(&roots.input_root),
            HashPart::Str(&roots.assertion_root),
            HashPart::Str(&roots.blocker_root),
        ],
        16,
    )
}

fn next_required_gates() -> BTreeMap<String, String> {
    [
        (
            "cargo_runtime",
            "run the vertical-slice harness under cargo/runtime execution",
        ),
        (
            "live_feed_swap",
            "replace deterministic Monero and reserve feed fixtures with live adapters",
        ),
        (
            "forced_exit_execution",
            "execute a wallet-owned withdrawal claim without operator cooperation",
        ),
        (
            "independent_audit",
            "review bridge custody, PQ control plane, privacy leakage, and reserve sufficiency",
        ),
        (
            "production_release",
            "keep release held until the forced-exit harness passes under real gates",
        ),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect()
}

fn gate_root(gates: &BTreeMap<String, String>) -> String {
    let records = gates
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-vertical-slice-execution-harness-next-gates",
        &records,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-vertical-slice-execution-harness-record",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
