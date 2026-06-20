use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceRuntimeGateReceiptConformanceManifestRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_GATE_RECEIPT_CONFORMANCE_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-runtime-gate-receipt-conformance-manifest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_GATE_RECEIPT_CONFORMANCE_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CONFORMANCE_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-runtime-gate-receipt-conformance-v1";
pub const DEFAULT_L2_HEIGHT: u64 = 4_260_256;
pub const DEFAULT_MONERO_HEIGHT: u64 = 3_530_256;
pub const DEFAULT_MIN_PQ_WEIGHT_BPS: u64 = 6_700;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_000;
pub const DEFAULT_MAX_METADATA_UNITS: u64 = 3;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceGateKind {
    DepositNote,
    PrivateReceipt,
    ContractReceipt,
    WithdrawalClaim,
    FeedReplay,
    AdversarialCases,
    ReleaseBlockers,
    EvidenceAcceptance,
}

impl ConformanceGateKind {
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
pub enum ConformanceStatus {
    ExpectedMatchAfterRuntime,
    ObservedRuntimeMissing,
    ExpectedFailClosedAfterRuntime,
    ReleaseHeld,
}

impl ConformanceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExpectedMatchAfterRuntime => "expected_match_after_runtime",
            Self::ObservedRuntimeMissing => "observed_runtime_missing",
            Self::ExpectedFailClosedAfterRuntime => "expected_fail_closed_after_runtime",
            Self::ReleaseHeld => "release_held",
        }
    }

    pub fn release_blocking(self) -> bool {
        matches!(
            self,
            Self::ObservedRuntimeMissing | Self::ReleaseHeld | Self::ExpectedMatchAfterRuntime
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestVerdict {
    ConformanceTargetsReady,
    ProductionReleaseBlocked,
}

impl ManifestVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConformanceTargetsReady => "conformance_targets_ready",
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
            "conformance_suite": CONFORMANCE_SUITE,
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
pub struct ConformanceRecord {
    pub kind: ConformanceGateKind,
    pub status: ConformanceStatus,
    pub conformance_id: String,
    pub invocation_runtime: String,
    pub preflight_runtime: String,
    pub execution_receipt_runtime: String,
    pub conformance_runtime: String,
    pub expected_invocation_root: String,
    pub observed_invocation_root: String,
    pub invocation_matches: bool,
    pub expected_preflight_root: String,
    pub observed_preflight_root: String,
    pub preflight_matches: bool,
    pub expected_receipt_root: String,
    pub observed_receipt_root: String,
    pub receipt_matches: bool,
    pub expected_operator_evidence_root: String,
    pub observed_operator_evidence_root: String,
    pub operator_evidence_matches: bool,
    pub expected_wallet_visible_root: String,
    pub observed_wallet_visible_root: String,
    pub wallet_visible_matches: bool,
    pub expected_fail_closed_root: String,
    pub observed_fail_closed_root: String,
    pub fail_closed_matches: bool,
    pub mismatch_root: String,
    pub release_blockers: Vec<String>,
}

impl ConformanceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "ordinal": self.kind.ordinal(),
            "status": self.status.as_str(),
            "release_blocking": self.status.release_blocking(),
            "conformance_id": self.conformance_id,
            "invocation_runtime": self.invocation_runtime,
            "preflight_runtime": self.preflight_runtime,
            "execution_receipt_runtime": self.execution_receipt_runtime,
            "conformance_runtime": self.conformance_runtime,
            "expected_invocation_root": self.expected_invocation_root,
            "observed_invocation_root": self.observed_invocation_root,
            "invocation_matches": self.invocation_matches,
            "expected_preflight_root": self.expected_preflight_root,
            "observed_preflight_root": self.observed_preflight_root,
            "preflight_matches": self.preflight_matches,
            "expected_receipt_root": self.expected_receipt_root,
            "observed_receipt_root": self.observed_receipt_root,
            "receipt_matches": self.receipt_matches,
            "expected_operator_evidence_root": self.expected_operator_evidence_root,
            "observed_operator_evidence_root": self.observed_operator_evidence_root,
            "operator_evidence_matches": self.operator_evidence_matches,
            "expected_wallet_visible_root": self.expected_wallet_visible_root,
            "observed_wallet_visible_root": self.observed_wallet_visible_root,
            "wallet_visible_matches": self.wallet_visible_matches,
            "expected_fail_closed_root": self.expected_fail_closed_root,
            "observed_fail_closed_root": self.observed_fail_closed_root,
            "fail_closed_matches": self.fail_closed_matches,
            "mismatch_root": self.mismatch_root,
            "release_blockers": self.release_blockers,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("conformance-record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConformanceCounters {
    pub total_records: u64,
    pub runtime_observation_missing: u64,
    pub expected_fail_closed_after_runtime: u64,
    pub release_holds: u64,
    pub matching_lanes: u64,
    pub mismatching_lanes: u64,
}

impl ConformanceCounters {
    pub fn from_records(records: &[ConformanceRecord]) -> Self {
        let mut counters = Self {
            total_records: records.len() as u64,
            runtime_observation_missing: 0,
            expected_fail_closed_after_runtime: 0,
            release_holds: 0,
            matching_lanes: 0,
            mismatching_lanes: 0,
        };
        for record in records {
            match record.status {
                ConformanceStatus::ObservedRuntimeMissing => {
                    counters.runtime_observation_missing += 1;
                }
                ConformanceStatus::ExpectedFailClosedAfterRuntime => {
                    counters.expected_fail_closed_after_runtime += 1;
                }
                ConformanceStatus::ReleaseHeld => {
                    counters.release_holds += 1;
                }
                ConformanceStatus::ExpectedMatchAfterRuntime => {}
            }
            for matched in [
                record.invocation_matches,
                record.preflight_matches,
                record.receipt_matches,
                record.operator_evidence_matches,
                record.wallet_visible_matches,
                record.fail_closed_matches,
            ] {
                if matched {
                    counters.matching_lanes += 1;
                } else {
                    counters.mismatching_lanes += 1;
                }
            }
        }
        counters
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_records": self.total_records,
            "runtime_observation_missing": self.runtime_observation_missing,
            "expected_fail_closed_after_runtime": self.expected_fail_closed_after_runtime,
            "release_holds": self.release_holds,
            "matching_lanes": self.matching_lanes,
            "mismatching_lanes": self.mismatching_lanes,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("conformance-counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConformanceRoots {
    pub record_root: String,
    pub mismatch_root: String,
    pub invocation_root: String,
    pub preflight_root: String,
    pub receipt_root: String,
    pub operator_evidence_root: String,
    pub wallet_visible_root: String,
    pub fail_closed_root: String,
    pub blocker_root: String,
    pub counter_root: String,
}

impl ConformanceRoots {
    pub fn from_records(records: &[ConformanceRecord], counters: &ConformanceCounters) -> Self {
        Self {
            record_root: record_merkle("records", records, ConformanceRecord::state_root),
            mismatch_root: lane_merkle("mismatch", records, |record| &record.mismatch_root),
            invocation_root: pair_merkle(
                "invocation",
                records,
                |record| &record.expected_invocation_root,
                |record| &record.observed_invocation_root,
            ),
            preflight_root: pair_merkle(
                "preflight",
                records,
                |record| &record.expected_preflight_root,
                |record| &record.observed_preflight_root,
            ),
            receipt_root: pair_merkle(
                "receipt",
                records,
                |record| &record.expected_receipt_root,
                |record| &record.observed_receipt_root,
            ),
            operator_evidence_root: pair_merkle(
                "operator-evidence",
                records,
                |record| &record.expected_operator_evidence_root,
                |record| &record.observed_operator_evidence_root,
            ),
            wallet_visible_root: pair_merkle(
                "wallet-visible",
                records,
                |record| &record.expected_wallet_visible_root,
                |record| &record.observed_wallet_visible_root,
            ),
            fail_closed_root: pair_merkle(
                "fail-closed",
                records,
                |record| &record.expected_fail_closed_root,
                |record| &record.observed_fail_closed_root,
            ),
            blocker_root: blocker_merkle(records),
            counter_root: counters.state_root(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_root": self.record_root,
            "mismatch_root": self.mismatch_root,
            "invocation_root": self.invocation_root,
            "preflight_root": self.preflight_root,
            "receipt_root": self.receipt_root,
            "operator_evidence_root": self.operator_evidence_root,
            "wallet_visible_root": self.wallet_visible_root,
            "fail_closed_root": self.fail_closed_root,
            "blocker_root": self.blocker_root,
            "counter_root": self.counter_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("conformance-roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConformanceManifest {
    pub manifest_id: String,
    pub verdict: ManifestVerdict,
    pub cargo_runtime_required_next: bool,
    pub production_release_allowed: bool,
    pub counters: ConformanceCounters,
    pub roots: ConformanceRoots,
}

impl ConformanceManifest {
    pub fn public_record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "verdict": self.verdict.as_str(),
            "cargo_runtime_required_next": self.cargo_runtime_required_next,
            "production_release_allowed": self.production_release_allowed,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("conformance-manifest", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub records: Vec<ConformanceRecord>,
    pub manifest: ConformanceManifest,
    pub release_hold_reasons: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let records = ConformanceGateKind::all()
            .into_iter()
            .map(|kind| default_record(&config, kind))
            .collect::<Vec<_>>();
        let counters = ConformanceCounters::from_records(&records);
        let roots = ConformanceRoots::from_records(&records, &counters);
        let manifest = ConformanceManifest {
            manifest_id: manifest_id(&config, &roots),
            verdict: ManifestVerdict::ProductionReleaseBlocked,
            cargo_runtime_required_next: true,
            production_release_allowed: false,
            counters,
            roots,
        };
        Self {
            config,
            records,
            manifest,
            release_hold_reasons: release_hold_reasons(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "records": self.records.iter().map(ConformanceRecord::public_record).collect::<Vec<_>>(),
            "manifest": self.manifest.public_record(),
            "release_hold_reasons": self.release_hold_reasons,
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-vertical-slice-runtime-gate-receipt-conformance-manifest-state",
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

fn default_record(config: &Config, kind: ConformanceGateKind) -> ConformanceRecord {
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
    let observed_invocation_root = root_for("observed-invocation-placeholder", kind, &payload);
    let expected_preflight_root = root_for("expected-preflight", kind, &payload);
    let observed_preflight_root = root_for("observed-preflight-placeholder", kind, &payload);
    let expected_receipt_root = root_for("expected-receipt", kind, &payload);
    let observed_receipt_root = root_for("observed-receipt-placeholder", kind, &payload);
    let expected_operator_evidence_root = root_for("expected-operator-evidence", kind, &payload);
    let observed_operator_evidence_root =
        root_for("observed-operator-evidence-placeholder", kind, &payload);
    let expected_wallet_visible_root = root_for("expected-wallet-visible", kind, &payload);
    let observed_wallet_visible_root =
        root_for("observed-wallet-visible-placeholder", kind, &payload);
    let expected_fail_closed_root = root_for("expected-fail-closed", kind, &payload);
    let observed_fail_closed_root = root_for("observed-fail-closed-placeholder", kind, &payload);
    let mismatch_root = mismatch_root(
        kind,
        &expected_invocation_root,
        &observed_invocation_root,
        &expected_preflight_root,
        &observed_preflight_root,
        &expected_receipt_root,
        &observed_receipt_root,
    );
    let conformance_id = domain_hash(
        "monero-l2-pq-bridge-exit-runtime-gate-receipt-conformance-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(&mismatch_root),
        ],
        16,
    );
    ConformanceRecord {
        kind,
        status,
        conformance_id,
        invocation_runtime: invocation_runtime(kind).to_string(),
        preflight_runtime: preflight_runtime(kind).to_string(),
        execution_receipt_runtime: execution_receipt_runtime(kind).to_string(),
        conformance_runtime: conformance_runtime(kind).to_string(),
        expected_invocation_root,
        observed_invocation_root,
        invocation_matches: false,
        expected_preflight_root,
        observed_preflight_root,
        preflight_matches: false,
        expected_receipt_root,
        observed_receipt_root,
        receipt_matches: false,
        expected_operator_evidence_root,
        observed_operator_evidence_root,
        operator_evidence_matches: false,
        expected_wallet_visible_root,
        observed_wallet_visible_root,
        wallet_visible_matches: false,
        expected_fail_closed_root,
        observed_fail_closed_root,
        fail_closed_matches: false,
        mismatch_root,
        release_blockers,
    }
}

fn status_for(kind: ConformanceGateKind) -> ConformanceStatus {
    match kind {
        ConformanceGateKind::DepositNote
        | ConformanceGateKind::PrivateReceipt
        | ConformanceGateKind::ContractReceipt
        | ConformanceGateKind::WithdrawalClaim => ConformanceStatus::ExpectedMatchAfterRuntime,
        ConformanceGateKind::FeedReplay | ConformanceGateKind::EvidenceAcceptance => {
            ConformanceStatus::ObservedRuntimeMissing
        }
        ConformanceGateKind::AdversarialCases => ConformanceStatus::ExpectedFailClosedAfterRuntime,
        ConformanceGateKind::ReleaseBlockers => ConformanceStatus::ReleaseHeld,
    }
}

fn invocation_runtime(kind: ConformanceGateKind) -> &'static str {
    match kind {
        ConformanceGateKind::DepositNote => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_deposit_note_gate_invocation_runtime"
        }
        ConformanceGateKind::PrivateReceipt => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_private_receipt_gate_invocation_runtime"
        }
        ConformanceGateKind::ContractReceipt => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_contract_receipt_gate_invocation_runtime"
        }
        ConformanceGateKind::WithdrawalClaim => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_withdrawal_claim_gate_invocation_runtime"
        }
        ConformanceGateKind::FeedReplay => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_feed_replay_fixture_runtime"
        }
        ConformanceGateKind::AdversarialCases => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_adversarial_gate_invocation_runtime"
        }
        ConformanceGateKind::ReleaseBlockers => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_release_blocker_gate_invocation_runtime"
        }
        ConformanceGateKind::EvidenceAcceptance => {
            "monero_l2_pq_bridge_exit_canonical_runtime_evidence_acceptance_runtime"
        }
    }
}

fn preflight_runtime(kind: ConformanceGateKind) -> &'static str {
    match kind {
        ConformanceGateKind::DepositNote => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_deposit_note_gate_preflight_runtime"
        }
        ConformanceGateKind::PrivateReceipt => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_private_receipt_gate_preflight_runtime"
        }
        ConformanceGateKind::ContractReceipt => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_contract_receipt_gate_preflight_runtime"
        }
        ConformanceGateKind::WithdrawalClaim => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_withdrawal_claim_gate_preflight_runtime"
        }
        ConformanceGateKind::FeedReplay => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_runtime_gate_preflight_matrix_runtime"
        }
        ConformanceGateKind::AdversarialCases => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_adversarial_gate_preflight_runtime"
        }
        ConformanceGateKind::ReleaseBlockers => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_release_blocker_gate_preflight_runtime"
        }
        ConformanceGateKind::EvidenceAcceptance => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_runtime_gate_preflight_matrix_runtime"
        }
    }
}

fn execution_receipt_runtime(kind: ConformanceGateKind) -> &'static str {
    match kind {
        ConformanceGateKind::DepositNote => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_deposit_note_gate_execution_receipt_runtime"
        }
        ConformanceGateKind::PrivateReceipt => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_private_receipt_gate_execution_receipt_runtime"
        }
        ConformanceGateKind::ContractReceipt => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_contract_receipt_gate_execution_receipt_runtime"
        }
        ConformanceGateKind::WithdrawalClaim => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_withdrawal_claim_gate_execution_receipt_runtime"
        }
        ConformanceGateKind::FeedReplay => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_runtime_gate_execution_receipt_manifest_runtime"
        }
        ConformanceGateKind::AdversarialCases => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_adversarial_gate_execution_receipt_runtime"
        }
        ConformanceGateKind::ReleaseBlockers => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_release_blocker_gate_execution_receipt_runtime"
        }
        ConformanceGateKind::EvidenceAcceptance => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_runtime_gate_execution_receipt_manifest_runtime"
        }
    }
}

fn conformance_runtime(kind: ConformanceGateKind) -> &'static str {
    match kind {
        ConformanceGateKind::DepositNote => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_deposit_note_gate_receipt_conformance_runtime"
        }
        ConformanceGateKind::PrivateReceipt => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_private_receipt_gate_receipt_conformance_runtime"
        }
        ConformanceGateKind::ContractReceipt => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_contract_receipt_gate_receipt_conformance_runtime"
        }
        ConformanceGateKind::WithdrawalClaim => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_withdrawal_claim_gate_receipt_conformance_runtime"
        }
        ConformanceGateKind::FeedReplay => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_runtime_gate_receipt_conformance_manifest_runtime"
        }
        ConformanceGateKind::AdversarialCases => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_adversarial_gate_receipt_conformance_runtime"
        }
        ConformanceGateKind::ReleaseBlockers => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_release_blocker_gate_receipt_conformance_runtime"
        }
        ConformanceGateKind::EvidenceAcceptance => {
            "monero_l2_pq_bridge_exit_canonical_vertical_slice_runtime_gate_receipt_conformance_manifest_runtime"
        }
    }
}

fn release_blockers(kind: ConformanceGateKind) -> Vec<String> {
    match kind {
        ConformanceGateKind::DepositNote
        | ConformanceGateKind::PrivateReceipt
        | ConformanceGateKind::ContractReceipt
        | ConformanceGateKind::WithdrawalClaim => vec![
            "observed_runtime_receipt_missing",
            "conformance_match_not_proven",
        ],
        ConformanceGateKind::FeedReplay => vec![
            "live_monero_feed_receipt_missing",
            "pq_authority_feed_receipt_missing",
        ],
        ConformanceGateKind::AdversarialCases => vec![
            "fail_closed_receipt_not_observed",
            "negative_case_conformance_not_proven",
        ],
        ConformanceGateKind::ReleaseBlockers => vec![
            "cargo_runtime_deferred",
            "audit_receipt_missing",
            "privacy_receipt_missing",
            "pq_receipt_missing",
            "reserve_receipt_missing",
        ],
        ConformanceGateKind::EvidenceAcceptance => vec![
            "compiled_runtime_evidence_missing",
            "operator_release_receipt_missing",
        ],
    }
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn root_for(kind: &str, gate: ConformanceGateKind, payload: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-runtime-gate-receipt-conformance-root",
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

fn mismatch_root(
    kind: ConformanceGateKind,
    expected_invocation_root: &str,
    observed_invocation_root: &str,
    expected_preflight_root: &str,
    observed_preflight_root: &str,
    expected_receipt_root: &str,
    observed_receipt_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-runtime-gate-receipt-conformance-mismatch",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(expected_invocation_root),
            HashPart::Str(observed_invocation_root),
            HashPart::Str(expected_preflight_root),
            HashPart::Str(observed_preflight_root),
            HashPart::Str(expected_receipt_root),
            HashPart::Str(observed_receipt_root),
        ],
        32,
    )
}

fn record_merkle<F>(label: &str, records: &[ConformanceRecord], root: F) -> String
where
    F: Fn(&ConformanceRecord) -> String,
{
    let leaves = records
        .iter()
        .map(|record| {
            json!({
                "label": label,
                "kind": record.kind.as_str(),
                "root": root(record),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-bridge-exit-runtime-gate-receipt-conformance-{label}"),
        &leaves,
    )
}

fn lane_merkle<F>(label: &str, records: &[ConformanceRecord], root: F) -> String
where
    F: Fn(&ConformanceRecord) -> &String,
{
    let leaves = records
        .iter()
        .map(|record| {
            json!({
                "label": label,
                "kind": record.kind.as_str(),
                "root": root(record),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-bridge-exit-runtime-gate-receipt-conformance-lane-{label}"),
        &leaves,
    )
}

fn pair_merkle<E, O>(label: &str, records: &[ConformanceRecord], expected: E, observed: O) -> String
where
    E: Fn(&ConformanceRecord) -> &String,
    O: Fn(&ConformanceRecord) -> &String,
{
    let leaves = records
        .iter()
        .map(|record| {
            json!({
                "label": label,
                "kind": record.kind.as_str(),
                "expected": expected(record),
                "observed": observed(record),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-bridge-exit-runtime-gate-receipt-conformance-pair-{label}"),
        &leaves,
    )
}

fn blocker_merkle(records: &[ConformanceRecord]) -> String {
    let leaves = records
        .iter()
        .map(|record| {
            json!({
                "kind": record.kind.as_str(),
                "status": record.status.as_str(),
                "release_blockers": record.release_blockers,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-runtime-gate-receipt-conformance-blockers",
        &leaves,
    )
}

fn manifest_id(config: &Config, roots: &ConformanceRoots) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-runtime-gate-receipt-conformance-manifest-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(config.l2_reference_height),
            HashPart::U64(config.monero_reference_height),
            HashPart::Str(&roots.record_root),
            HashPart::Str(&roots.mismatch_root),
            HashPart::Str(&roots.blocker_root),
            HashPart::Str(&roots.counter_root),
        ],
        16,
    )
}

fn release_hold_reasons() -> BTreeMap<String, String> {
    [
        (
            "observed_runtime_receipts",
            "runtime receipts must be observed and matched before release",
        ),
        (
            "wallet_visible_roots",
            "wallet-visible receipt roots must match without leaking linkable metadata",
        ),
        (
            "operator_evidence",
            "operator evidence roots must match invocation preflight and execution receipts",
        ),
        (
            "fail_closed_cases",
            "adversarial and release-blocker no-go receipts must match expected fail-closed roots",
        ),
        (
            "audit_signoff",
            "privacy PQ reserve and release audit receipts must be attached",
        ),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect()
}

fn hold_root(reasons: &BTreeMap<String, String>) -> String {
    let leaves = reasons
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-runtime-gate-receipt-conformance-release-holds",
        &leaves,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-runtime-gate-receipt-conformance-record",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
