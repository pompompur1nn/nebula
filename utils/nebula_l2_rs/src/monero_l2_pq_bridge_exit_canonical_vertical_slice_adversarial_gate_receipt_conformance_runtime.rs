use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceAdversarialGateReceiptConformanceRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_GATE_RECEIPT_CONFORMANCE_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-gate-receipt-conformance-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_GATE_RECEIPT_CONFORMANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str =
    "2026-06-19.forced-exit.vertical-slice.adversarial-gate-receipt-conformance.v1";
pub const HASH_SUITE: &str = "nebula-l2-devnet-shake256-32";
pub const CONFORMANCE_SUITE: &str = "forced-exit-adversarial-fail-closed-receipt-conformance-v1";
pub const EXECUTION_MODE: &str = "runtime_execution_deferred";
pub const RECEIPT_POLICY: &str = "fail_closed";
pub const RELEASE_POLICY: &str = "production_release_blocked";
pub const REQUIRED_CONFORMANCE_CASES: usize = 16;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-gate-receipt-conformance-runtime";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub conformance_suite: String,
    pub execution_mode: String,
    pub receipt_policy: String,
    pub release_policy: String,
    pub required_conformance_cases: usize,
    pub forced_exit_epoch: u64,
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            conformance_suite: CONFORMANCE_SUITE.to_string(),
            execution_mode: EXECUTION_MODE.to_string(),
            receipt_policy: RECEIPT_POLICY.to_string(),
            release_policy: RELEASE_POLICY.to_string(),
            required_conformance_cases: REQUIRED_CONFORMANCE_CASES,
            forced_exit_epoch: 42,
            l2_reference_height: 4_260_192,
            monero_reference_height: 3_530_192,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "conformance_suite": self.conformance_suite,
            "execution_mode": self.execution_mode,
            "receipt_policy": self.receipt_policy,
            "release_policy": self.release_policy,
            "required_conformance_cases": self.required_conformance_cases,
            "forced_exit_epoch": self.forced_exit_epoch,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceLane {
    SequencerOutage,
    WatcherCollusion,
    MoneroReorg,
    WithheldReceipt,
    StalePqKey,
    ReserveShortfall,
    LiquidityExhaustion,
    MetadataLeak,
    WalletRecovery,
    InvocationReceipt,
    PreflightReceipt,
    ExecutionReceipt,
    OperatorEvidence,
    WalletVisibleNoGo,
    ReleaseBlockers,
    ReceiptBundle,
}

impl ConformanceLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerOutage => "sequencer_outage",
            Self::WatcherCollusion => "watcher_collusion",
            Self::MoneroReorg => "monero_reorg",
            Self::WithheldReceipt => "withheld_receipt",
            Self::StalePqKey => "stale_pq_key",
            Self::ReserveShortfall => "reserve_shortfall",
            Self::LiquidityExhaustion => "liquidity_exhaustion",
            Self::MetadataLeak => "metadata_leak",
            Self::WalletRecovery => "wallet_recovery",
            Self::InvocationReceipt => "invocation_receipt",
            Self::PreflightReceipt => "preflight_receipt",
            Self::ExecutionReceipt => "execution_receipt",
            Self::OperatorEvidence => "operator_evidence",
            Self::WalletVisibleNoGo => "wallet_visible_no_go",
            Self::ReleaseBlockers => "release_blockers",
            Self::ReceiptBundle => "receipt_bundle",
        }
    }

    pub fn ordinal(self) -> u64 {
        match self {
            Self::SequencerOutage => 0,
            Self::WatcherCollusion => 1,
            Self::MoneroReorg => 2,
            Self::WithheldReceipt => 3,
            Self::StalePqKey => 4,
            Self::ReserveShortfall => 5,
            Self::LiquidityExhaustion => 6,
            Self::MetadataLeak => 7,
            Self::WalletRecovery => 8,
            Self::InvocationReceipt => 9,
            Self::PreflightReceipt => 10,
            Self::ExecutionReceipt => 11,
            Self::OperatorEvidence => 12,
            Self::WalletVisibleNoGo => 13,
            Self::ReleaseBlockers => 14,
            Self::ReceiptBundle => 15,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceVerdict {
    DeterministicPlaceholder,
    ReleaseBlockingMismatch,
}

impl ConformanceVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeterministicPlaceholder => "deterministic_placeholder",
            Self::ReleaseBlockingMismatch => "release_blocking_mismatch",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptConformanceEvidence {
    pub lane: ConformanceLane,
    pub evidence_id: String,
    pub expected_fail_closed_root: String,
    pub observed_fail_closed_root: String,
    pub conformance_root: String,
    pub verdict: ConformanceVerdict,
    pub release_blocking: bool,
    pub runtime_execution_deferred: bool,
    pub mismatch_reason: String,
}

impl ReceiptConformanceEvidence {
    pub fn new(lane: ConformanceLane, mismatch_reason: &str) -> Self {
        let evidence_id = evidence_id(lane);
        let expected_fail_closed_root = expected_fail_closed_root(lane, &evidence_id);
        let observed_fail_closed_root = observed_placeholder_root(lane, &evidence_id);
        let verdict = if expected_fail_closed_root == observed_fail_closed_root {
            ConformanceVerdict::DeterministicPlaceholder
        } else {
            ConformanceVerdict::ReleaseBlockingMismatch
        };
        let conformance_record = json!({
            "lane": lane.as_str(),
            "ordinal": lane.ordinal(),
            "evidence_id": evidence_id,
            "expected_fail_closed_root": expected_fail_closed_root,
            "observed_fail_closed_root": observed_fail_closed_root,
            "verdict": verdict.as_str(),
            "release_blocking": true,
            "runtime_execution_deferred": true,
            "mismatch_reason": mismatch_reason,
        });
        let conformance_root = record_root("receipt-conformance-evidence", &conformance_record);

        Self {
            lane,
            evidence_id,
            expected_fail_closed_root,
            observed_fail_closed_root,
            conformance_root,
            verdict,
            release_blocking: true,
            runtime_execution_deferred: true,
            mismatch_reason: mismatch_reason.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "ordinal": self.lane.ordinal(),
            "evidence_id": self.evidence_id,
            "expected_fail_closed_root": self.expected_fail_closed_root,
            "observed_fail_closed_root": self.observed_fail_closed_root,
            "conformance_root": self.conformance_root,
            "verdict": self.verdict.as_str(),
            "release_blocking": self.release_blocking,
            "runtime_execution_deferred": self.runtime_execution_deferred,
            "mismatch_reason": self.mismatch_reason,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub runtime_id: String,
    pub conformance_cases: Vec<ReceiptConformanceEvidence>,
    pub expected_roots: BTreeMap<String, String>,
    pub observed_roots: BTreeMap<String, String>,
    pub conformance_cases_root: String,
    pub expected_roots_root: String,
    pub observed_roots_root: String,
    pub release_blocker_root: String,
    pub production_release_allowed: bool,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let conformance_cases = devnet_conformance_cases();
        let expected_roots = root_map(&conformance_cases, RootSide::Expected);
        let observed_roots = root_map(&conformance_cases, RootSide::Observed);
        let conformance_records = conformance_cases
            .iter()
            .map(ReceiptConformanceEvidence::public_record)
            .collect::<Vec<_>>();
        let expected_records = expected_roots
            .iter()
            .map(|(lane, root)| json!({ "lane": lane, "expected_fail_closed_root": root }))
            .collect::<Vec<_>>();
        let observed_records = observed_roots
            .iter()
            .map(|(lane, root)| json!({ "lane": lane, "observed_fail_closed_root": root }))
            .collect::<Vec<_>>();
        let conformance_cases_root = merkle_root(
            &format!("{DOMAIN}:conformance-cases-root"),
            &conformance_records,
        );
        let expected_roots_root =
            merkle_root(&format!("{DOMAIN}:expected-roots-root"), &expected_records);
        let observed_roots_root =
            merkle_root(&format!("{DOMAIN}:observed-roots-root"), &observed_records);
        let release_blocker_root = release_blocker_root(
            &config,
            &conformance_cases_root,
            &expected_roots_root,
            &observed_roots_root,
        );

        Self {
            config,
            runtime_id: runtime_id(),
            conformance_cases,
            expected_roots,
            observed_roots,
            conformance_cases_root,
            expected_roots_root,
            observed_roots_root,
            release_blocker_root,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        let expected_roots = self
            .expected_roots
            .iter()
            .map(|(lane, root)| json!({ "lane": lane, "expected_fail_closed_root": root }))
            .collect::<Vec<_>>();
        let observed_roots = self
            .observed_roots
            .iter()
            .map(|(lane, root)| json!({ "lane": lane, "observed_fail_closed_root": root }))
            .collect::<Vec<_>>();
        let conformance_cases = self
            .conformance_cases
            .iter()
            .map(ReceiptConformanceEvidence::public_record)
            .collect::<Vec<_>>();

        json!({
            "config": self.config.public_record(),
            "runtime_id": self.runtime_id,
            "conformance_cases": conformance_cases,
            "expected_roots": expected_roots,
            "observed_roots": observed_roots,
            "conformance_cases_root": self.conformance_cases_root,
            "expected_roots_root": self.expected_roots_root,
            "observed_roots_root": self.observed_roots_root,
            "release_blocker_root": self.release_blocker_root,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        let config_record = self.config.public_record();
        domain_hash(
            &format!("{DOMAIN}:state-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(SCHEMA_VERSION),
                HashPart::Json(&config_record),
                HashPart::Str(&self.runtime_id),
                HashPart::Str(&self.conformance_cases_root),
                HashPart::Str(&self.expected_roots_root),
                HashPart::Str(&self.observed_roots_root),
                HashPart::Str(&self.release_blocker_root),
                HashPart::Str("production_release_allowed=false"),
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

#[derive(Clone, Copy)]
enum RootSide {
    Expected,
    Observed,
}

fn root_map(
    conformance_cases: &[ReceiptConformanceEvidence],
    side: RootSide,
) -> BTreeMap<String, String> {
    conformance_cases
        .iter()
        .map(|case| {
            let root = match side {
                RootSide::Expected => case.expected_fail_closed_root.clone(),
                RootSide::Observed => case.observed_fail_closed_root.clone(),
            };
            (case.lane.as_str().to_string(), root)
        })
        .collect()
}

fn runtime_id() -> String {
    domain_hash(
        &format!("{DOMAIN}:runtime-id"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(SCHEMA_VERSION),
            HashPart::Str(CONFORMANCE_SUITE),
        ],
        32,
    )
}

fn evidence_id(lane: ConformanceLane) -> String {
    domain_hash(
        &format!("{DOMAIN}:evidence-id"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(lane.ordinal()),
            HashPart::Str(lane.as_str()),
        ],
        32,
    )
}

fn expected_fail_closed_root(lane: ConformanceLane, evidence_id: &str) -> String {
    let expected_record = json!({
        "lane": lane.as_str(),
        "ordinal": lane.ordinal(),
        "evidence_id": evidence_id,
        "receipt_policy": RECEIPT_POLICY,
        "runtime_execution_deferred": false,
        "expected_receipt_conforms": true,
        "expected_state_mutation": "none",
        "expected_release_policy": RELEASE_POLICY,
    });
    domain_hash(
        &format!("{DOMAIN}:expected-fail-closed-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&expected_record),
        ],
        32,
    )
}

fn observed_placeholder_root(lane: ConformanceLane, evidence_id: &str) -> String {
    let observed_record = json!({
        "lane": lane.as_str(),
        "ordinal": lane.ordinal(),
        "evidence_id": evidence_id,
        "receipt_policy": RECEIPT_POLICY,
        "runtime_execution_deferred": true,
        "observed_receipt_conforms": false,
        "observed_state_mutation": "none",
        "placeholder_kind": "deferred-runtime-release-blocking",
    });
    domain_hash(
        &format!("{DOMAIN}:observed-placeholder-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&observed_record),
        ],
        32,
    )
}

fn release_blocker_root(
    config: &Config,
    conformance_cases_root: &str,
    expected_roots_root: &str,
    observed_roots_root: &str,
) -> String {
    let config_record = config.public_record();
    domain_hash(
        &format!("{DOMAIN}:release-blocker-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&config_record),
            HashPart::Str(conformance_cases_root),
            HashPart::Str(expected_roots_root),
            HashPart::Str(observed_roots_root),
            HashPart::Str("all_observed_roots_are_deterministic_placeholders"),
            HashPart::Str("release_blocking=true"),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:{label}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(SCHEMA_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn devnet_conformance_cases() -> Vec<ReceiptConformanceEvidence> {
    vec![
        ReceiptConformanceEvidence::new(
            ConformanceLane::SequencerOutage,
            "observed sequencer outage receipt root is a deterministic deferred placeholder",
        ),
        ReceiptConformanceEvidence::new(
            ConformanceLane::WatcherCollusion,
            "observed watcher collusion receipt root is a deterministic deferred placeholder",
        ),
        ReceiptConformanceEvidence::new(
            ConformanceLane::MoneroReorg,
            "observed Monero reorg receipt root is a deterministic deferred placeholder",
        ),
        ReceiptConformanceEvidence::new(
            ConformanceLane::WithheldReceipt,
            "observed withheld receipt root is a deterministic deferred placeholder",
        ),
        ReceiptConformanceEvidence::new(
            ConformanceLane::StalePqKey,
            "observed stale PQ key receipt root is a deterministic deferred placeholder",
        ),
        ReceiptConformanceEvidence::new(
            ConformanceLane::ReserveShortfall,
            "observed reserve shortfall receipt root is a deterministic deferred placeholder",
        ),
        ReceiptConformanceEvidence::new(
            ConformanceLane::LiquidityExhaustion,
            "observed liquidity exhaustion receipt root is a deterministic deferred placeholder",
        ),
        ReceiptConformanceEvidence::new(
            ConformanceLane::MetadataLeak,
            "observed metadata leak receipt root is a deterministic deferred placeholder",
        ),
        ReceiptConformanceEvidence::new(
            ConformanceLane::WalletRecovery,
            "observed wallet recovery receipt root is a deterministic deferred placeholder",
        ),
        ReceiptConformanceEvidence::new(
            ConformanceLane::InvocationReceipt,
            "observed invocation receipt root is a deterministic deferred placeholder",
        ),
        ReceiptConformanceEvidence::new(
            ConformanceLane::PreflightReceipt,
            "observed preflight receipt root is a deterministic deferred placeholder",
        ),
        ReceiptConformanceEvidence::new(
            ConformanceLane::ExecutionReceipt,
            "observed execution receipt root is a deterministic deferred placeholder",
        ),
        ReceiptConformanceEvidence::new(
            ConformanceLane::OperatorEvidence,
            "observed operator evidence root is a deterministic deferred placeholder",
        ),
        ReceiptConformanceEvidence::new(
            ConformanceLane::WalletVisibleNoGo,
            "observed wallet-visible no-go root is a deterministic deferred placeholder",
        ),
        ReceiptConformanceEvidence::new(
            ConformanceLane::ReleaseBlockers,
            "observed release blocker root is a deterministic deferred placeholder",
        ),
        ReceiptConformanceEvidence::new(
            ConformanceLane::ReceiptBundle,
            "observed adversarial fail-closed receipt bundle root is a deterministic deferred placeholder",
        ),
    ]
}
