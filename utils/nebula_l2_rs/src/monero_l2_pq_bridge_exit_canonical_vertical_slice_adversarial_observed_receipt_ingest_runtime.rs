use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceAdversarialObservedReceiptIngestRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_OBSERVED_RECEIPT_INGEST_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-observed-receipt-ingest-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_OBSERVED_RECEIPT_INGEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str =
    "2026-06-19.forced-exit.vertical-slice.adversarial-observed-receipt-ingest.v1";
pub const HASH_SUITE: &str = "nebula-l2-devnet-shake256-32";
pub const INGEST_SUITE: &str = "forced-exit-adversarial-observed-negative-receipt-root-ingest-v1";
pub const RELEASE_POLICY: &str = "release_blocked_unless_observed_fail_closed_matches_expected";
pub const REQUIRED_OBSERVED_CASES: usize = 10;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-observed-receipt-ingest-runtime";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub ingest_suite: String,
    pub release_policy: String,
    pub required_observed_cases: usize,
    pub watcher_quorum: u64,
    pub min_finality_depth: u64,
    pub max_fee_probe_piconero: u64,
    pub metadata_budget_bits: u64,
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
            ingest_suite: INGEST_SUITE.to_string(),
            release_policy: RELEASE_POLICY.to_string(),
            required_observed_cases: REQUIRED_OBSERVED_CASES,
            watcher_quorum: 5,
            min_finality_depth: 20,
            max_fee_probe_piconero: 250_000_000,
            metadata_budget_bits: 0,
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
            "ingest_suite": self.ingest_suite,
            "release_policy": self.release_policy,
            "required_observed_cases": self.required_observed_cases,
            "watcher_quorum": self.watcher_quorum,
            "min_finality_depth": self.min_finality_depth,
            "max_fee_probe_piconero": self.max_fee_probe_piconero,
            "metadata_budget_bits": self.metadata_budget_bits,
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
pub enum ObservedReceiptLane {
    StaleFeed,
    WeakWatcherQuorum,
    ReorgFinalityFailure,
    ReplayNullifier,
    MetadataLeak,
    OversizedFeeProbe,
    PrematureSettlement,
    FailClosedReceipt,
    Mismatch,
    ReleaseHold,
}

impl ObservedReceiptLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleFeed => "stale_feed",
            Self::WeakWatcherQuorum => "weak_watcher_quorum",
            Self::ReorgFinalityFailure => "reorg_finality_failure",
            Self::ReplayNullifier => "replay_nullifier",
            Self::MetadataLeak => "metadata_leak",
            Self::OversizedFeeProbe => "oversized_fee_probe",
            Self::PrematureSettlement => "premature_settlement",
            Self::FailClosedReceipt => "fail_closed_receipt",
            Self::Mismatch => "mismatch",
            Self::ReleaseHold => "release_hold",
        }
    }

    pub fn ordinal(self) -> u64 {
        match self {
            Self::StaleFeed => 0,
            Self::WeakWatcherQuorum => 1,
            Self::ReorgFinalityFailure => 2,
            Self::ReplayNullifier => 3,
            Self::MetadataLeak => 4,
            Self::OversizedFeeProbe => 5,
            Self::PrematureSettlement => 6,
            Self::FailClosedReceipt => 7,
            Self::Mismatch => 8,
            Self::ReleaseHold => 9,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedReceiptKind {
    RuntimeNegativeRoot,
    FailClosedReceiptRoot,
    ReleaseHoldRoot,
}

impl ObservedReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeNegativeRoot => "runtime_negative_root",
            Self::FailClosedReceiptRoot => "fail_closed_receipt_root",
            Self::ReleaseHoldRoot => "release_hold_root",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestVerdict {
    ExpectedFailClosedObserved,
    ReleaseBlockingObservedFailure,
    ReleaseBlockingMismatch,
}

impl IngestVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExpectedFailClosedObserved => "expected_fail_closed_observed",
            Self::ReleaseBlockingObservedFailure => "release_blocking_observed_failure",
            Self::ReleaseBlockingMismatch => "release_blocking_mismatch",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservedReceiptImport {
    pub lane: ObservedReceiptLane,
    pub sequence: u64,
    pub case_id: String,
    pub kind: ObservedReceiptKind,
    pub source_feed: String,
    pub expected_fail_closed_root: String,
    pub observed_receipt_root: String,
    pub observed_negative_root: String,
    pub import_root: String,
    pub fail_closed_match: bool,
    pub release_blocking: bool,
    pub release_hold_id: String,
    pub note: String,
}

impl ObservedReceiptImport {
    pub fn new(
        lane: ObservedReceiptLane,
        sequence: u64,
        kind: ObservedReceiptKind,
        source_feed: &str,
        fail_closed_match: bool,
        note: &str,
    ) -> Self {
        let case_id = case_id(lane, sequence);
        let expected_fail_closed_root = expected_fail_closed_root(lane, sequence, &case_id);
        let observed_receipt_root = if fail_closed_match {
            expected_fail_closed_root.clone()
        } else {
            observed_receipt_root(lane, sequence, &case_id, kind)
        };
        let observed_negative_root = observed_negative_root(lane, sequence, &observed_receipt_root);
        let release_blocking = !fail_closed_match;
        let release_hold_id = release_hold_id(lane, sequence, release_blocking);
        let import_record = json!({
            "lane": lane.as_str(),
            "sequence": sequence,
            "case_id": case_id,
            "kind": kind.as_str(),
            "source_feed": source_feed,
            "expected_fail_closed_root": expected_fail_closed_root,
            "observed_receipt_root": observed_receipt_root,
            "observed_negative_root": observed_negative_root,
            "fail_closed_match": fail_closed_match,
            "release_blocking": release_blocking,
            "release_hold_id": release_hold_id,
            "note": note,
        });
        let import_root = record_root("observed-receipt-import", &import_record);

        Self {
            lane,
            sequence,
            case_id,
            kind,
            source_feed: source_feed.to_string(),
            expected_fail_closed_root,
            observed_receipt_root,
            observed_negative_root,
            import_root,
            fail_closed_match,
            release_blocking,
            release_hold_id,
            note: note.to_string(),
        }
    }

    pub fn verdict(&self) -> IngestVerdict {
        if self.fail_closed_match {
            IngestVerdict::ExpectedFailClosedObserved
        } else if self.expected_fail_closed_root == self.observed_receipt_root {
            IngestVerdict::ReleaseBlockingObservedFailure
        } else {
            IngestVerdict::ReleaseBlockingMismatch
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "ordinal": self.lane.ordinal(),
            "sequence": self.sequence,
            "case_id": self.case_id,
            "kind": self.kind.as_str(),
            "source_feed": self.source_feed,
            "expected_fail_closed_root": self.expected_fail_closed_root,
            "observed_receipt_root": self.observed_receipt_root,
            "observed_negative_root": self.observed_negative_root,
            "import_root": self.import_root,
            "fail_closed_match": self.fail_closed_match,
            "release_blocking": self.release_blocking,
            "release_hold_id": self.release_hold_id,
            "verdict": self.verdict().as_str(),
            "note": self.note,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("observed-receipt-import-state", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub lane: ObservedReceiptLane,
    pub case_id: String,
    pub reason: String,
    pub expected_fail_closed_root: String,
    pub observed_receipt_root: String,
    pub release_blocking: bool,
    pub cleared_by_expected_fail_closed_match: bool,
    pub hold_root: String,
}

impl ReleaseHold {
    pub fn from_import(import: &ObservedReceiptImport) -> Self {
        let cleared_by_expected_fail_closed_match = import.fail_closed_match;
        let release_blocking = !cleared_by_expected_fail_closed_match;
        let reason = if release_blocking {
            format!(
                "observed {} receipt did not match expected fail-closed root",
                import.lane.as_str()
            )
        } else {
            format!(
                "observed {} receipt matched expected fail-closed root",
                import.lane.as_str()
            )
        };
        let hold_record = json!({
            "hold_id": import.release_hold_id,
            "lane": import.lane.as_str(),
            "case_id": import.case_id,
            "reason": reason,
            "expected_fail_closed_root": import.expected_fail_closed_root,
            "observed_receipt_root": import.observed_receipt_root,
            "release_blocking": release_blocking,
            "cleared_by_expected_fail_closed_match": cleared_by_expected_fail_closed_match,
        });
        let hold_root = record_root("release-hold", &hold_record);

        Self {
            hold_id: import.release_hold_id.clone(),
            lane: import.lane,
            case_id: import.case_id.clone(),
            reason,
            expected_fail_closed_root: import.expected_fail_closed_root.clone(),
            observed_receipt_root: import.observed_receipt_root.clone(),
            release_blocking,
            cleared_by_expected_fail_closed_match,
            hold_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "lane": self.lane.as_str(),
            "case_id": self.case_id,
            "reason": self.reason,
            "expected_fail_closed_root": self.expected_fail_closed_root,
            "observed_receipt_root": self.observed_receipt_root,
            "release_blocking": self.release_blocking,
            "cleared_by_expected_fail_closed_match": self.cleared_by_expected_fail_closed_match,
            "hold_root": self.hold_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release-hold-state", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IngestRoots {
    pub config_root: String,
    pub import_root: String,
    pub stale_feed_root: String,
    pub weak_watcher_quorum_root: String,
    pub reorg_finality_failure_root: String,
    pub replay_nullifier_root: String,
    pub metadata_leak_root: String,
    pub oversized_fee_probe_root: String,
    pub premature_settlement_root: String,
    pub fail_closed_receipt_root: String,
    pub mismatch_root: String,
    pub release_hold_root: String,
    pub release_blocking_root: String,
}

impl IngestRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "import_root": self.import_root,
            "stale_feed_root": self.stale_feed_root,
            "weak_watcher_quorum_root": self.weak_watcher_quorum_root,
            "reorg_finality_failure_root": self.reorg_finality_failure_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "metadata_leak_root": self.metadata_leak_root,
            "oversized_fee_probe_root": self.oversized_fee_probe_root,
            "premature_settlement_root": self.premature_settlement_root,
            "fail_closed_receipt_root": self.fail_closed_receipt_root,
            "mismatch_root": self.mismatch_root,
            "release_hold_root": self.release_hold_root,
            "release_blocking_root": self.release_blocking_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ingest-roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub runtime_id: String,
    pub imports: Vec<ObservedReceiptImport>,
    pub release_holds: BTreeMap<String, ReleaseHold>,
    pub roots: IngestRoots,
    pub release_blocking_count: u64,
    pub fail_closed_match_count: u64,
    pub production_release_allowed: bool,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let imports = devnet_imports();
        let release_holds = imports
            .iter()
            .map(|import| {
                (
                    import.release_hold_id.clone(),
                    ReleaseHold::from_import(import),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let release_blocking_count = imports
            .iter()
            .filter(|import| import.release_blocking)
            .count() as u64;
        let fail_closed_match_count = imports
            .iter()
            .filter(|import| import.fail_closed_match)
            .count() as u64;
        let roots = build_roots(&config, &imports, &release_holds);

        Self {
            config,
            runtime_id: format!("{DOMAIN}:devnet"),
            imports,
            release_holds,
            roots,
            release_blocking_count,
            fail_closed_match_count,
            production_release_allowed: release_blocking_count == 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "ingest_suite": INGEST_SUITE,
            "runtime_id": self.runtime_id,
            "config": self.config.public_record(),
            "import_count": self.imports.len() as u64,
            "release_hold_count": self.release_holds.len() as u64,
            "release_blocking_count": self.release_blocking_count,
            "fail_closed_match_count": self.fail_closed_match_count,
            "production_release_allowed": self.production_release_allowed,
            "roots": self.roots.public_record(),
            "imports": self.imports.iter().map(ObservedReceiptImport::public_record).collect::<Vec<_>>(),
            "release_holds": self.release_holds.values().map(ReleaseHold::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            &format!("{DOMAIN}:state"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.runtime_id),
                HashPart::Str(&self.roots.state_root()),
                HashPart::Int(self.release_blocking_count as i128),
                HashPart::Int(self.fail_closed_match_count as i128),
                HashPart::Int(bool_int(self.production_release_allowed)),
            ],
            32,
        )
    }

    pub fn require_release_unblocked(&self) -> Result<()> {
        if self.production_release_allowed {
            Ok(())
        } else {
            Err(format!(
                "{} adversarial observed receipt imports remain release-blocking",
                self.release_blocking_count
            ))
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root() -> String {
    State::devnet().state_root()
}

fn devnet_imports() -> Vec<ObservedReceiptImport> {
    vec![
        ObservedReceiptImport::new(
            ObservedReceiptLane::StaleFeed,
            0,
            ObservedReceiptKind::RuntimeNegativeRoot,
            "devnet.observed.watchers.stale-feed",
            false,
            "stale watcher feed must fail closed and remain release-blocking when the root differs",
        ),
        ObservedReceiptImport::new(
            ObservedReceiptLane::WeakWatcherQuorum,
            1,
            ObservedReceiptKind::RuntimeNegativeRoot,
            "devnet.observed.watchers.weak-quorum",
            false,
            "watcher quorum below threshold cannot clear an adversarial receipt",
        ),
        ObservedReceiptImport::new(
            ObservedReceiptLane::ReorgFinalityFailure,
            2,
            ObservedReceiptKind::RuntimeNegativeRoot,
            "devnet.observed.monero.reorg-finality",
            false,
            "monero reorg or finality lag is imported as a negative receipt root",
        ),
        ObservedReceiptImport::new(
            ObservedReceiptLane::ReplayNullifier,
            3,
            ObservedReceiptKind::RuntimeNegativeRoot,
            "devnet.observed.bridge.replay-nullifier",
            false,
            "replayed forced-exit nullifier must not settle",
        ),
        ObservedReceiptImport::new(
            ObservedReceiptLane::MetadataLeak,
            4,
            ObservedReceiptKind::RuntimeNegativeRoot,
            "devnet.observed.privacy.metadata-leak",
            false,
            "metadata leak observation blocks release unless fail-closed evidence matches",
        ),
        ObservedReceiptImport::new(
            ObservedReceiptLane::OversizedFeeProbe,
            5,
            ObservedReceiptKind::RuntimeNegativeRoot,
            "devnet.observed.fees.oversized-probe",
            false,
            "oversized fee probe must be held as adversarial runtime evidence",
        ),
        ObservedReceiptImport::new(
            ObservedReceiptLane::PrematureSettlement,
            6,
            ObservedReceiptKind::RuntimeNegativeRoot,
            "devnet.observed.bridge.premature-settlement",
            false,
            "premature settlement observation cannot clear the forced-exit release gate",
        ),
        ObservedReceiptImport::new(
            ObservedReceiptLane::FailClosedReceipt,
            7,
            ObservedReceiptKind::FailClosedReceiptRoot,
            "devnet.observed.bridge.expected-fail-closed",
            true,
            "the only devnet adversarial import that clears is the expected fail-closed receipt",
        ),
        ObservedReceiptImport::new(
            ObservedReceiptLane::Mismatch,
            8,
            ObservedReceiptKind::RuntimeNegativeRoot,
            "devnet.observed.receipts.mismatch",
            false,
            "mismatched observed receipt root remains release-blocking",
        ),
        ObservedReceiptImport::new(
            ObservedReceiptLane::ReleaseHold,
            9,
            ObservedReceiptKind::ReleaseHoldRoot,
            "devnet.observed.release.hold",
            false,
            "release hold is retained until observed failure equals expected fail-closed behavior",
        ),
    ]
}

fn build_roots(
    config: &Config,
    imports: &[ObservedReceiptImport],
    release_holds: &BTreeMap<String, ReleaseHold>,
) -> IngestRoots {
    IngestRoots {
        config_root: config.state_root(),
        import_root: merkle_root_from_values(
            "observed-receipt-import-root",
            imports
                .iter()
                .map(ObservedReceiptImport::public_record)
                .collect::<Vec<_>>(),
        ),
        stale_feed_root: lane_root(imports, ObservedReceiptLane::StaleFeed),
        weak_watcher_quorum_root: lane_root(imports, ObservedReceiptLane::WeakWatcherQuorum),
        reorg_finality_failure_root: lane_root(imports, ObservedReceiptLane::ReorgFinalityFailure),
        replay_nullifier_root: lane_root(imports, ObservedReceiptLane::ReplayNullifier),
        metadata_leak_root: lane_root(imports, ObservedReceiptLane::MetadataLeak),
        oversized_fee_probe_root: lane_root(imports, ObservedReceiptLane::OversizedFeeProbe),
        premature_settlement_root: lane_root(imports, ObservedReceiptLane::PrematureSettlement),
        fail_closed_receipt_root: lane_root(imports, ObservedReceiptLane::FailClosedReceipt),
        mismatch_root: lane_root(imports, ObservedReceiptLane::Mismatch),
        release_hold_root: merkle_root_from_values(
            "release-hold-root",
            release_holds
                .values()
                .map(ReleaseHold::public_record)
                .collect::<Vec<_>>(),
        ),
        release_blocking_root: merkle_root_from_values(
            "release-blocking-observed-receipt-root",
            imports
                .iter()
                .filter(|import| import.release_blocking)
                .map(ObservedReceiptImport::public_record)
                .collect::<Vec<_>>(),
        ),
    }
}

fn lane_root(imports: &[ObservedReceiptImport], lane: ObservedReceiptLane) -> String {
    merkle_root_from_values(
        &format!("{}-root", lane.as_str()),
        imports
            .iter()
            .filter(|import| import.lane == lane)
            .map(ObservedReceiptImport::public_record)
            .collect::<Vec<_>>(),
    )
}

fn case_id(lane: ObservedReceiptLane, sequence: u64) -> String {
    domain_hash(
        &format!("{DOMAIN}:case-id"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Int(sequence as i128),
        ],
        16,
    )
}

fn expected_fail_closed_root(lane: ObservedReceiptLane, sequence: u64, case_id: &str) -> String {
    domain_hash(
        &format!("{DOMAIN}:expected-fail-closed-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Int(sequence as i128),
            HashPart::Str(case_id),
            HashPart::Str("fail_closed"),
        ],
        32,
    )
}

fn observed_receipt_root(
    lane: ObservedReceiptLane,
    sequence: u64,
    case_id: &str,
    kind: ObservedReceiptKind,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:observed-receipt-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Int(sequence as i128),
            HashPart::Str(case_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str("runtime_observed_negative_case"),
        ],
        32,
    )
}

fn observed_negative_root(
    lane: ObservedReceiptLane,
    sequence: u64,
    observed_receipt_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:observed-negative-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Int(sequence as i128),
            HashPart::Str(observed_receipt_root),
        ],
        32,
    )
}

fn release_hold_id(lane: ObservedReceiptLane, sequence: u64, release_blocking: bool) -> String {
    domain_hash(
        &format!("{DOMAIN}:release-hold-id"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Int(sequence as i128),
            HashPart::Int(bool_int(release_blocking)),
        ],
        16,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:{label}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn merkle_root_from_values(label: &str, values: Vec<Value>) -> String {
    merkle_root(&format!("{DOMAIN}:{label}"), &values)
}

fn bool_int(value: bool) -> i128 {
    if value {
        1
    } else {
        0
    }
}
