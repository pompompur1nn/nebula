use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceRuntimeGateInvocationManifestRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_GATE_INVOCATION_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-runtime-gate-invocation-manifest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_GATE_INVOCATION_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const INVOCATION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-runtime-gate-invocation-v1";
pub const DEFAULT_L2_HEIGHT: u64 = 4_260_000;
pub const DEFAULT_MONERO_HEIGHT: u64 = 3_530_000;
pub const DEFAULT_MIN_PQ_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_000;
pub const DEFAULT_MAX_METADATA_UNITS: u64 = 3;
pub const DEFAULT_MAX_FEE_ATOMIC: u64 = 35_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateInvocationKind {
    DepositNote,
    PrivateReceipt,
    ContractReceipt,
    WithdrawalClaim,
    FeedReplay,
    AdversarialCases,
    ReleaseBlockers,
    EvidenceAcceptance,
}

impl GateInvocationKind {
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
pub enum InvocationStatus {
    ReadyToInvoke,
    RequiresLiveFeedSwap,
    RequiresCargoRuntime,
    ReleaseHeld,
}

impl InvocationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadyToInvoke => "ready_to_invoke",
            Self::RequiresLiveFeedSwap => "requires_live_feed_swap",
            Self::RequiresCargoRuntime => "requires_cargo_runtime",
            Self::ReleaseHeld => "release_held",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationVerdict {
    HarnessCallGraphReady,
    ProductionReleaseBlocked,
}

impl InvocationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HarnessCallGraphReady => "harness_call_graph_ready",
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
            "invocation_suite": INVOCATION_SUITE,
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
pub struct GateInvocation {
    pub kind: GateInvocationKind,
    pub status: InvocationStatus,
    pub call_id: String,
    pub input_bundle_root: String,
    pub expected_root: String,
    pub produced_receipt_root: String,
    pub witness_root: String,
    pub wallet_replay_root: String,
    pub feed_replay_root: String,
    pub pq_authority_root: String,
    pub privacy_root: String,
    pub reserve_root: String,
    pub fail_closed_root: String,
    pub blocker_root: String,
    pub pass_condition_root: String,
    pub reject_condition_root: String,
    pub operator_independent: bool,
    pub wallet_replayable: bool,
    pub live_feed_required: bool,
    pub cargo_runtime_required: bool,
    pub blocks_production_release: bool,
    pub pq_weight_bps: u64,
    pub reserve_coverage_bps: u64,
    pub metadata_units: u64,
    pub fee_atomic: u64,
}

impl GateInvocation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "call_id": self.call_id,
            "input_bundle_root": self.input_bundle_root,
            "expected_root": self.expected_root,
            "produced_receipt_root": self.produced_receipt_root,
            "witness_root": self.witness_root,
            "wallet_replay_root": self.wallet_replay_root,
            "feed_replay_root": self.feed_replay_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_root": self.privacy_root,
            "reserve_root": self.reserve_root,
            "fail_closed_root": self.fail_closed_root,
            "blocker_root": self.blocker_root,
            "pass_condition_root": self.pass_condition_root,
            "reject_condition_root": self.reject_condition_root,
            "operator_independent": yes_no(self.operator_independent),
            "wallet_replayable": yes_no(self.wallet_replayable),
            "live_feed_required": yes_no(self.live_feed_required),
            "cargo_runtime_required": yes_no(self.cargo_runtime_required),
            "blocks_production_release": yes_no(self.blocks_production_release),
            "pq_weight_bps": self.pq_weight_bps,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "metadata_units": self.metadata_units,
            "fee_atomic": self.fee_atomic,
        })
    }

    pub fn state_root(&self) -> String {
        record_root(self.kind.as_str(), &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvocationCounters {
    pub total_invocations: u64,
    pub ready_invocations: u64,
    pub live_feed_required: u64,
    pub cargo_runtime_required: u64,
    pub production_blockers: u64,
    pub operator_dependent_invocations: u64,
    pub wallet_replayable_invocations: u64,
    pub min_pq_weight_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub max_metadata_units: u64,
    pub max_fee_atomic: u64,
}

impl InvocationCounters {
    pub fn from_invocations(invocations: &[GateInvocation]) -> Self {
        Self {
            total_invocations: invocations.len() as u64,
            ready_invocations: invocations
                .iter()
                .filter(|call| call.status == InvocationStatus::ReadyToInvoke)
                .count() as u64,
            live_feed_required: invocations
                .iter()
                .filter(|call| call.live_feed_required)
                .count() as u64,
            cargo_runtime_required: invocations
                .iter()
                .filter(|call| call.cargo_runtime_required)
                .count() as u64,
            production_blockers: invocations
                .iter()
                .filter(|call| call.blocks_production_release)
                .count() as u64,
            operator_dependent_invocations: invocations
                .iter()
                .filter(|call| !call.operator_independent)
                .count() as u64,
            wallet_replayable_invocations: invocations
                .iter()
                .filter(|call| call.wallet_replayable)
                .count() as u64,
            min_pq_weight_bps: invocations
                .iter()
                .map(|call| call.pq_weight_bps)
                .min()
                .unwrap_or_default(),
            min_reserve_coverage_bps: invocations
                .iter()
                .map(|call| call.reserve_coverage_bps)
                .min()
                .unwrap_or_default(),
            max_metadata_units: invocations
                .iter()
                .map(|call| call.metadata_units)
                .max()
                .unwrap_or_default(),
            max_fee_atomic: invocations
                .iter()
                .map(|call| call.fee_atomic)
                .max()
                .unwrap_or_default(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_invocations": self.total_invocations,
            "ready_invocations": self.ready_invocations,
            "live_feed_required": self.live_feed_required,
            "cargo_runtime_required": self.cargo_runtime_required,
            "production_blockers": self.production_blockers,
            "operator_dependent_invocations": self.operator_dependent_invocations,
            "wallet_replayable_invocations": self.wallet_replayable_invocations,
            "min_pq_weight_bps": self.min_pq_weight_bps,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "max_metadata_units": self.max_metadata_units,
            "max_fee_atomic": self.max_fee_atomic,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("invocation_counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvocationManifestRoots {
    pub invocation_root: String,
    pub input_root: String,
    pub expected_root: String,
    pub receipt_root: String,
    pub witness_root: String,
    pub wallet_replay_root: String,
    pub feed_replay_root: String,
    pub pq_authority_root: String,
    pub privacy_root: String,
    pub reserve_root: String,
    pub fail_closed_root: String,
    pub blocker_root: String,
    pub pass_condition_root: String,
    pub reject_condition_root: String,
    pub counter_root: String,
}

impl InvocationManifestRoots {
    pub fn from_invocations(invocations: &[GateInvocation], counters: &InvocationCounters) -> Self {
        Self {
            invocation_root: invocation_merkle(
                "invocation",
                invocations,
                GateInvocation::public_record,
            ),
            input_root: lane_root("input", invocations, |call| &call.input_bundle_root),
            expected_root: lane_root("expected", invocations, |call| &call.expected_root),
            receipt_root: lane_root("receipt", invocations, |call| &call.produced_receipt_root),
            witness_root: lane_root("witness", invocations, |call| &call.witness_root),
            wallet_replay_root: lane_root("wallet_replay", invocations, |call| {
                &call.wallet_replay_root
            }),
            feed_replay_root: lane_root("feed_replay", invocations, |call| &call.feed_replay_root),
            pq_authority_root: lane_root("pq_authority", invocations, |call| {
                &call.pq_authority_root
            }),
            privacy_root: lane_root("privacy", invocations, |call| &call.privacy_root),
            reserve_root: lane_root("reserve", invocations, |call| &call.reserve_root),
            fail_closed_root: lane_root("fail_closed", invocations, |call| &call.fail_closed_root),
            blocker_root: lane_root("blocker", invocations, |call| &call.blocker_root),
            pass_condition_root: lane_root("pass_condition", invocations, |call| {
                &call.pass_condition_root
            }),
            reject_condition_root: lane_root("reject_condition", invocations, |call| {
                &call.reject_condition_root
            }),
            counter_root: counters.state_root(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "invocation_root": self.invocation_root,
            "input_root": self.input_root,
            "expected_root": self.expected_root,
            "receipt_root": self.receipt_root,
            "witness_root": self.witness_root,
            "wallet_replay_root": self.wallet_replay_root,
            "feed_replay_root": self.feed_replay_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_root": self.privacy_root,
            "reserve_root": self.reserve_root,
            "fail_closed_root": self.fail_closed_root,
            "blocker_root": self.blocker_root,
            "pass_condition_root": self.pass_condition_root,
            "reject_condition_root": self.reject_condition_root,
            "counter_root": self.counter_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("invocation_manifest_roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvocationManifest {
    pub manifest_id: String,
    pub verdict: InvocationVerdict,
    pub cargo_runtime_allowed_next: bool,
    pub live_feed_swap_allowed_next: bool,
    pub production_release_allowed: bool,
    pub counters: InvocationCounters,
    pub roots: InvocationManifestRoots,
}

impl InvocationManifest {
    pub fn public_record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "verdict": self.verdict.as_str(),
            "cargo_runtime_allowed_next": yes_no(self.cargo_runtime_allowed_next),
            "live_feed_swap_allowed_next": yes_no(self.live_feed_swap_allowed_next),
            "production_release_allowed": yes_no(self.production_release_allowed),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("invocation_manifest", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub invocations: Vec<GateInvocation>,
    pub manifest: InvocationManifest,
    pub next_gate_actions: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let invocations = GateInvocationKind::all()
            .into_iter()
            .map(|kind| default_invocation(&config, kind))
            .collect::<Vec<_>>();
        let counters = InvocationCounters::from_invocations(&invocations);
        let roots = InvocationManifestRoots::from_invocations(&invocations, &counters);
        let manifest = InvocationManifest {
            manifest_id: manifest_id(&config, &roots),
            verdict: InvocationVerdict::ProductionReleaseBlocked,
            cargo_runtime_allowed_next: true,
            live_feed_swap_allowed_next: false,
            production_release_allowed: false,
            counters,
            roots,
        };
        Self {
            config,
            invocations,
            manifest,
            next_gate_actions: next_gate_actions(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "invocations": self.invocations.iter().map(GateInvocation::public_record).collect::<Vec<_>>(),
            "manifest": self.manifest.public_record(),
            "next_gate_actions": self.next_gate_actions,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-vertical-slice-runtime-gate-invocation-manifest-state",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.manifest.state_root()),
                HashPart::Str(&action_root(&self.next_gate_actions)),
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

fn default_invocation(config: &Config, kind: GateInvocationKind) -> GateInvocation {
    let status = match kind {
        GateInvocationKind::FeedReplay => InvocationStatus::RequiresLiveFeedSwap,
        GateInvocationKind::EvidenceAcceptance => InvocationStatus::RequiresCargoRuntime,
        GateInvocationKind::ReleaseBlockers => InvocationStatus::ReleaseHeld,
        _ => InvocationStatus::ReadyToInvoke,
    };
    let payload = json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "kind": kind.as_str(),
        "ordinal": kind.ordinal(),
        "l2_reference_height": config.l2_reference_height + kind.ordinal(),
        "monero_reference_height": config.monero_reference_height + kind.ordinal(),
        "wallet_material": "encrypted",
        "operator_material": "not_required",
        "status": status.as_str(),
    });
    GateInvocation {
        kind,
        status,
        call_id: domain_hash(
            "monero-l2-pq-bridge-exit-runtime-gate-invocation-call-id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(kind.as_str()),
                HashPart::Json(&payload),
            ],
            16,
        ),
        input_bundle_root: root_for("input-bundle", kind, &payload),
        expected_root: root_for("expected", kind, &payload),
        produced_receipt_root: root_for("produced-receipt", kind, &payload),
        witness_root: root_for("witness", kind, &payload),
        wallet_replay_root: root_for("wallet-replay", kind, &payload),
        feed_replay_root: root_for("feed-replay", kind, &payload),
        pq_authority_root: root_for("pq-authority", kind, &payload),
        privacy_root: root_for("privacy", kind, &payload),
        reserve_root: root_for("reserve", kind, &payload),
        fail_closed_root: root_for("fail-closed", kind, &payload),
        blocker_root: root_for("blocker", kind, &payload),
        pass_condition_root: root_for("pass-condition", kind, &payload),
        reject_condition_root: root_for("reject-condition", kind, &payload),
        operator_independent: true,
        wallet_replayable: true,
        live_feed_required: matches!(kind, GateInvocationKind::FeedReplay),
        cargo_runtime_required: matches!(kind, GateInvocationKind::EvidenceAcceptance),
        blocks_production_release: !matches!(
            kind,
            GateInvocationKind::DepositNote
                | GateInvocationKind::PrivateReceipt
                | GateInvocationKind::ContractReceipt
                | GateInvocationKind::WithdrawalClaim
        ),
        pq_weight_bps: config.min_pq_weight_bps + 800,
        reserve_coverage_bps: config.min_reserve_coverage_bps + 1_200,
        metadata_units: if matches!(kind, GateInvocationKind::ReleaseBlockers) {
            1
        } else {
            0
        },
        fee_atomic: config.max_fee_atomic / 2 + kind.ordinal(),
    }
}

fn root_for(kind: &str, invocation: GateInvocationKind, payload: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-runtime-gate-invocation-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(invocation.as_str()),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn invocation_merkle<F>(kind: &str, invocations: &[GateInvocation], mapper: F) -> String
where
    F: Fn(&GateInvocation) -> Value,
{
    let records = invocations.iter().map(mapper).collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-bridge-exit-runtime-gate-invocation-{kind}"),
        &records,
    )
}

fn lane_root<F>(kind: &str, invocations: &[GateInvocation], mapper: F) -> String
where
    F: Fn(&GateInvocation) -> &String,
{
    let records = invocations
        .iter()
        .map(|call| {
            json!({
                "kind": call.kind.as_str(),
                "root": mapper(call),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-bridge-exit-runtime-gate-invocation-{kind}-roots"),
        &records,
    )
}

fn manifest_id(config: &Config, roots: &InvocationManifestRoots) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-runtime-gate-invocation-manifest-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(config.l2_reference_height),
            HashPart::U64(config.monero_reference_height),
            HashPart::Str(&roots.invocation_root),
            HashPart::Str(&roots.receipt_root),
            HashPart::Str(&roots.reject_condition_root),
        ],
        16,
    )
}

fn next_gate_actions() -> BTreeMap<String, String> {
    [
        (
            "cargo_runtime",
            "invoke the manifest under cargo/runtime and persist receipts",
        ),
        (
            "live_feed_swap",
            "replace feed replay fixtures with live Monero and reserve adapters",
        ),
        (
            "wallet_claim",
            "submit the wallet-owned withdrawal claim without operator cooperation",
        ),
        (
            "adversarial_replay",
            "run fail-closed adversarial invocations against expected roots",
        ),
        (
            "release_hold",
            "keep production release blocked until live execution and audits pass",
        ),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect()
}

fn action_root(actions: &BTreeMap<String, String>) -> String {
    let records = actions
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-runtime-gate-invocation-next-actions",
        &records,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-runtime-gate-invocation-record",
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
