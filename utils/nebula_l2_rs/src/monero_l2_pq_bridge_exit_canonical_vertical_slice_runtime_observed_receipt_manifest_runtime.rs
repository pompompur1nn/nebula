use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceRuntimeObservedReceiptManifestRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_OBSERVED_RECEIPT_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-vertical-slice-runtime-observed-receipt-manifest-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_OBSERVED_RECEIPT_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str = "observed-receipt-manifest/1";
pub const HASH_SUITE: &str = "nebula-domain-hash+json-merkle-v1";
pub const OBSERVED_RECEIPT_SUITE: &str = "runtime-observed-root-import+fail-closed-v1";
pub const DEFAULT_RUNTIME_GATE: &str = "cargo-runtime-heavy-gate-deferred";
pub const DEFAULT_RELEASE_CANDIDATE: &str = "bridge-exit-vertical-slice-observed-receipt-rc";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ObservedReceiptLane {
    DepositNote,
    PrivateReceipt,
    ContractReceipt,
    WithdrawalClaim,
    AdversarialCases,
    ReleaseBlockers,
    EvidenceAcceptance,
}

impl ObservedReceiptLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositNote => "deposit_note",
            Self::PrivateReceipt => "private_receipt",
            Self::ContractReceipt => "contract_receipt",
            Self::WithdrawalClaim => "withdrawal_claim",
            Self::AdversarialCases => "adversarial_cases",
            Self::ReleaseBlockers => "release_blockers",
            Self::EvidenceAcceptance => "evidence_acceptance",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::DepositNote => "deposit note observed root",
            Self::PrivateReceipt => "private receipt observed root",
            Self::ContractReceipt => "contract receipt observed root",
            Self::WithdrawalClaim => "withdrawal claim observed root",
            Self::AdversarialCases => "adversarial fail-closed observed root",
            Self::ReleaseBlockers => "release blocker observed root",
            Self::EvidenceAcceptance => "evidence acceptance observed root",
        }
    }

    pub fn requires_wallet_visibility(self) -> bool {
        matches!(
            self,
            Self::DepositNote | Self::PrivateReceipt | Self::WithdrawalClaim
        )
    }

    pub fn requires_fail_closed_receipt(self) -> bool {
        matches!(self, Self::AdversarialCases | Self::ReleaseBlockers)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ObservedReceiptSource {
    RuntimeHarness,
    DevnetRunner,
    OperatorExport,
    WalletReplay,
    AuditorReplay,
}

impl ObservedReceiptSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeHarness => "runtime_harness",
            Self::DevnetRunner => "devnet_runner",
            Self::OperatorExport => "operator_export",
            Self::WalletReplay => "wallet_replay",
            Self::AuditorReplay => "auditor_replay",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ObservedReceiptStatus {
    PendingRuntimeObservation,
    ObservedMatch,
    MissingObservedRoot,
    ObservedMismatch,
    FailClosedMatch,
    ReleaseBlocked,
}

impl ObservedReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingRuntimeObservation => "pending_runtime_observation",
            Self::ObservedMatch => "observed_match",
            Self::MissingObservedRoot => "missing_observed_root",
            Self::ObservedMismatch => "observed_mismatch",
            Self::FailClosedMatch => "fail_closed_match",
            Self::ReleaseBlocked => "release_blocked",
        }
    }

    pub fn blocks_release(self) -> bool {
        !matches!(self, Self::ObservedMatch | Self::FailClosedMatch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestVerdict {
    RuntimeObservedRootsRequired,
    ReleaseBlockedUntilObserved,
    HeavyGateReadyWhenCargoAllowed,
}

impl ManifestVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeObservedRootsRequired => "runtime_observed_roots_required",
            Self::ReleaseBlockedUntilObserved => "release_blocked_until_observed",
            Self::HeavyGateReadyWhenCargoAllowed => "heavy_gate_ready_when_cargo_allowed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub observed_receipt_suite: String,
    pub runtime_gate: String,
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
    pub required_source_count: u64,
    pub release_candidate: String,
    pub mismatch_policy: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            observed_receipt_suite: OBSERVED_RECEIPT_SUITE.to_string(),
            runtime_gate: DEFAULT_RUNTIME_GATE.to_string(),
            l2_reference_height: 73_000,
            monero_reference_height: 3_260_000,
            required_source_count: 3,
            release_candidate: DEFAULT_RELEASE_CANDIDATE.to_string(),
            mismatch_policy: "block release and retain forced-exit evidence".to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "observed_receipt_suite": self.observed_receipt_suite,
            "runtime_gate": self.runtime_gate,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "required_source_count": self.required_source_count,
            "release_candidate": self.release_candidate,
            "mismatch_policy": self.mismatch_policy,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-observed-receipt-manifest-config",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedReceiptImport {
    pub lane: ObservedReceiptLane,
    pub lane_label: String,
    pub expected_receipt_root: String,
    pub conformance_record_root: String,
    pub observed_receipt_root: String,
    pub observed_export_root: String,
    pub source_roots: BTreeMap<String, String>,
    pub wallet_visible_root: String,
    pub operator_evidence_root: String,
    pub pq_authority_root: String,
    pub privacy_budget_root: String,
    pub capture_epoch: u64,
    pub required_source_count: u64,
    pub observed_source_count: u64,
    pub wallet_visible_required: bool,
    pub fail_closed_expected: bool,
    pub expected_matches_observed: bool,
    pub wallet_visible_matches: bool,
    pub operator_evidence_matches: bool,
    pub pq_authority_matches: bool,
    pub privacy_budget_respected: bool,
    pub release_blockers: u64,
    pub status: ObservedReceiptStatus,
}

impl ObservedReceiptImport {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "lane_label": self.lane_label,
            "expected_receipt_root": self.expected_receipt_root,
            "conformance_record_root": self.conformance_record_root,
            "observed_receipt_root": self.observed_receipt_root,
            "observed_export_root": self.observed_export_root,
            "source_roots": self.source_roots,
            "wallet_visible_root": self.wallet_visible_root,
            "operator_evidence_root": self.operator_evidence_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_budget_root": self.privacy_budget_root,
            "capture_epoch": self.capture_epoch,
            "required_source_count": self.required_source_count,
            "observed_source_count": self.observed_source_count,
            "wallet_visible_required": self.wallet_visible_required,
            "fail_closed_expected": self.fail_closed_expected,
            "expected_matches_observed": self.expected_matches_observed,
            "wallet_visible_matches": self.wallet_visible_matches,
            "operator_evidence_matches": self.operator_evidence_matches,
            "pq_authority_matches": self.pq_authority_matches,
            "privacy_budget_respected": self.privacy_budget_respected,
            "release_blockers": self.release_blockers,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-observed-receipt-import",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(self.lane.as_str()),
                HashPart::Str(&self.expected_receipt_root),
                HashPart::Str(&self.conformance_record_root),
                HashPart::Str(&self.observed_receipt_root),
                HashPart::Str(&self.observed_export_root),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedReceiptMismatch {
    pub lane: ObservedReceiptLane,
    pub mismatch_code: String,
    pub expected_root: String,
    pub observed_root: String,
    pub evidence_root: String,
    pub severity: String,
    pub release_effect: String,
}

impl ObservedReceiptMismatch {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "mismatch_code": self.mismatch_code,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "evidence_root": self.evidence_root,
            "severity": self.severity,
            "release_effect": self.release_effect,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-observed-receipt-mismatch",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(self.lane.as_str()),
                HashPart::Str(&self.mismatch_code),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedReceiptCounters {
    pub total_lanes: u64,
    pub observed_matches: u64,
    pub fail_closed_matches: u64,
    pub missing_observed_roots: u64,
    pub mismatched_observed_roots: u64,
    pub wallet_visible_required: u64,
    pub release_blocked_lanes: u64,
    pub source_roots_required: u64,
    pub source_roots_observed: u64,
}

impl ObservedReceiptCounters {
    pub fn from_imports(imports: &[ObservedReceiptImport]) -> Self {
        let mut counters = Self {
            total_lanes: imports.len() as u64,
            observed_matches: 0,
            fail_closed_matches: 0,
            missing_observed_roots: 0,
            mismatched_observed_roots: 0,
            wallet_visible_required: 0,
            release_blocked_lanes: 0,
            source_roots_required: 0,
            source_roots_observed: 0,
        };

        for import in imports {
            counters.source_roots_required += import.required_source_count;
            counters.source_roots_observed += import.observed_source_count;
            if import.wallet_visible_required {
                counters.wallet_visible_required += 1;
            }
            if import.status.blocks_release() {
                counters.release_blocked_lanes += 1;
            }
            match import.status {
                ObservedReceiptStatus::ObservedMatch => counters.observed_matches += 1,
                ObservedReceiptStatus::FailClosedMatch => counters.fail_closed_matches += 1,
                ObservedReceiptStatus::MissingObservedRoot
                | ObservedReceiptStatus::PendingRuntimeObservation => {
                    counters.missing_observed_roots += 1;
                }
                ObservedReceiptStatus::ObservedMismatch => counters.mismatched_observed_roots += 1,
                ObservedReceiptStatus::ReleaseBlocked => counters.release_blocked_lanes += 1,
            }
        }

        counters
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_lanes": self.total_lanes,
            "observed_matches": self.observed_matches,
            "fail_closed_matches": self.fail_closed_matches,
            "missing_observed_roots": self.missing_observed_roots,
            "mismatched_observed_roots": self.mismatched_observed_roots,
            "wallet_visible_required": self.wallet_visible_required,
            "release_blocked_lanes": self.release_blocked_lanes,
            "source_roots_required": self.source_roots_required,
            "source_roots_observed": self.source_roots_observed,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-observed-receipt-counters",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedReceiptRoots {
    pub config_root: String,
    pub import_root: String,
    pub source_root: String,
    pub mismatch_root: String,
    pub lane_status_root: String,
    pub wallet_visible_root: String,
    pub operator_evidence_root: String,
    pub pq_authority_root: String,
    pub release_hold_root: String,
    pub counter_root: String,
}

impl ObservedReceiptRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "import_root": self.import_root,
            "source_root": self.source_root,
            "mismatch_root": self.mismatch_root,
            "lane_status_root": self.lane_status_root,
            "wallet_visible_root": self.wallet_visible_root,
            "operator_evidence_root": self.operator_evidence_root,
            "pq_authority_root": self.pq_authority_root,
            "release_hold_root": self.release_hold_root,
            "counter_root": self.counter_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-observed-receipt-roots",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedReceiptManifest {
    pub manifest_id: String,
    pub config: Config,
    pub imports: Vec<ObservedReceiptImport>,
    pub mismatches: Vec<ObservedReceiptMismatch>,
    pub counters: ObservedReceiptCounters,
    pub roots: ObservedReceiptRoots,
    pub release_holds: BTreeMap<String, String>,
    pub verdict: ManifestVerdict,
}

impl ObservedReceiptManifest {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let imports = observed_imports(&config);
        let mismatches = mismatch_records(&imports);
        let counters = ObservedReceiptCounters::from_imports(&imports);
        let release_holds = release_hold_reasons(&imports);
        let roots = ObservedReceiptRoots {
            config_root: config.state_root(),
            import_root: import_merkle(&imports),
            source_root: source_merkle(&imports),
            mismatch_root: mismatch_merkle(&mismatches),
            lane_status_root: lane_status_merkle(&imports),
            wallet_visible_root: wallet_visible_merkle(&imports),
            operator_evidence_root: operator_evidence_merkle(&imports),
            pq_authority_root: pq_authority_merkle(&imports),
            release_hold_root: hold_root(&release_holds),
            counter_root: counters.state_root(),
        };
        let manifest_id = manifest_id(&config, &roots);
        let verdict = if counters.release_blocked_lanes == 0 {
            ManifestVerdict::HeavyGateReadyWhenCargoAllowed
        } else {
            ManifestVerdict::ReleaseBlockedUntilObserved
        };

        Self {
            manifest_id,
            config,
            imports,
            mismatches,
            counters,
            roots,
            release_holds,
            verdict,
        }
    }

    pub fn public_record(&self) -> Value {
        let import_records = self
            .imports
            .iter()
            .map(ObservedReceiptImport::public_record)
            .collect::<Vec<_>>();
        let mismatch_records = self
            .mismatches
            .iter()
            .map(ObservedReceiptMismatch::public_record)
            .collect::<Vec<_>>();
        json!({
            "manifest_id": self.manifest_id,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "imports": import_records,
            "mismatches": mismatch_records,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "release_holds": self.release_holds,
            "verdict": self.verdict.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-observed-receipt-manifest-state",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.manifest_id),
                HashPart::Str(&self.roots.state_root()),
                HashPart::Json(&self.counters.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub manifest: ObservedReceiptManifest,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let manifest = ObservedReceiptManifest::devnet();
        let state_root = manifest.state_root();
        Self {
            manifest,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "state_root": self.state_root,
            "manifest": self.manifest.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
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

fn observed_imports(config: &Config) -> Vec<ObservedReceiptImport> {
    [
        ObservedReceiptLane::DepositNote,
        ObservedReceiptLane::PrivateReceipt,
        ObservedReceiptLane::ContractReceipt,
        ObservedReceiptLane::WithdrawalClaim,
        ObservedReceiptLane::AdversarialCases,
        ObservedReceiptLane::ReleaseBlockers,
        ObservedReceiptLane::EvidenceAcceptance,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, lane)| default_import(config, lane, index as u64))
    .collect()
}

fn default_import(config: &Config, lane: ObservedReceiptLane, index: u64) -> ObservedReceiptImport {
    let expected_receipt_root = expected_receipt_root(lane);
    let conformance_record_root = conformance_record_root(lane);
    let observed_receipt_root = observed_placeholder_root(lane);
    let observed_export_root = observed_export_root(lane);
    let source_roots = source_roots(lane);
    let wallet_visible_root = wallet_visible_root(lane);
    let operator_evidence_root = operator_evidence_root(lane);
    let pq_authority_root = pq_authority_root(lane);
    let privacy_budget_root = privacy_budget_root(lane);
    let fail_closed_expected = lane.requires_fail_closed_receipt();
    let wallet_visible_required = lane.requires_wallet_visibility();
    let observed_source_count = 0;
    let expected_matches_observed = false;
    let wallet_visible_matches = false;
    let operator_evidence_matches = false;
    let pq_authority_matches = false;
    let privacy_budget_respected = false;
    let release_blockers = release_blocker_count(
        fail_closed_expected,
        wallet_visible_required,
        observed_source_count,
        config.required_source_count,
    );
    let status = status_for(
        fail_closed_expected,
        expected_matches_observed,
        observed_source_count,
        config.required_source_count,
    );

    ObservedReceiptImport {
        lane,
        lane_label: lane.label().to_string(),
        expected_receipt_root,
        conformance_record_root,
        observed_receipt_root,
        observed_export_root,
        source_roots,
        wallet_visible_root,
        operator_evidence_root,
        pq_authority_root,
        privacy_budget_root,
        capture_epoch: config.l2_reference_height + index,
        required_source_count: config.required_source_count,
        observed_source_count,
        wallet_visible_required,
        fail_closed_expected,
        expected_matches_observed,
        wallet_visible_matches,
        operator_evidence_matches,
        pq_authority_matches,
        privacy_budget_respected,
        release_blockers,
        status,
    }
}

fn release_blocker_count(
    fail_closed_expected: bool,
    wallet_visible_required: bool,
    observed_source_count: u64,
    required_source_count: u64,
) -> u64 {
    let mut count = 1;
    if fail_closed_expected {
        count += 1;
    }
    if wallet_visible_required {
        count += 1;
    }
    if observed_source_count < required_source_count {
        count += required_source_count - observed_source_count;
    }
    count
}

fn status_for(
    fail_closed_expected: bool,
    expected_matches_observed: bool,
    observed_source_count: u64,
    required_source_count: u64,
) -> ObservedReceiptStatus {
    if observed_source_count < required_source_count {
        return ObservedReceiptStatus::MissingObservedRoot;
    }
    if expected_matches_observed && fail_closed_expected {
        return ObservedReceiptStatus::FailClosedMatch;
    }
    if expected_matches_observed {
        return ObservedReceiptStatus::ObservedMatch;
    }
    ObservedReceiptStatus::ObservedMismatch
}

fn source_roots(lane: ObservedReceiptLane) -> BTreeMap<String, String> {
    [
        ObservedReceiptSource::RuntimeHarness,
        ObservedReceiptSource::DevnetRunner,
        ObservedReceiptSource::OperatorExport,
        ObservedReceiptSource::WalletReplay,
        ObservedReceiptSource::AuditorReplay,
    ]
    .into_iter()
    .map(|source| {
        (
            source.as_str().to_string(),
            domain_hash(
                "monero-l2-pq-bridge-exit-observed-receipt-source-root",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(lane.as_str()),
                    HashPart::Str(source.as_str()),
                ],
                32,
            ),
        )
    })
    .collect()
}

fn expected_receipt_root(lane: ObservedReceiptLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-observed-receipt-expected-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("expected-from-execution-receipt-and-conformance-waves"),
        ],
        32,
    )
}

fn conformance_record_root(lane: ObservedReceiptLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-observed-receipt-conformance-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("receipt-conformance-record"),
        ],
        32,
    )
}

fn observed_placeholder_root(lane: ObservedReceiptLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-observed-receipt-placeholder-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("runtime-observation-deferred"),
        ],
        32,
    )
}

fn observed_export_root(lane: ObservedReceiptLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-observed-receipt-export-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("observed-export-contract"),
        ],
        32,
    )
}

fn wallet_visible_root(lane: ObservedReceiptLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-observed-receipt-wallet-visible-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("wallet-scan-visible-subset"),
        ],
        32,
    )
}

fn operator_evidence_root(lane: ObservedReceiptLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-observed-receipt-operator-evidence-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("operator-runtime-evidence-export"),
        ],
        32,
    )
}

fn pq_authority_root(lane: ObservedReceiptLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-observed-receipt-pq-authority-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("pq-watcher-sequencer-authority-evidence"),
        ],
        32,
    )
}

fn privacy_budget_root(lane: ObservedReceiptLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-observed-receipt-privacy-budget-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("privacy-budget-and-metadata-bound"),
        ],
        32,
    )
}

fn mismatch_records(imports: &[ObservedReceiptImport]) -> Vec<ObservedReceiptMismatch> {
    imports
        .iter()
        .filter(|import| import.status.blocks_release())
        .map(|import| ObservedReceiptMismatch {
            lane: import.lane,
            mismatch_code: mismatch_code(import).to_string(),
            expected_root: import.expected_receipt_root.clone(),
            observed_root: import.observed_receipt_root.clone(),
            evidence_root: mismatch_evidence_root(import),
            severity: "release_blocking".to_string(),
            release_effect: "retain forced-exit release hold until runtime observation matches"
                .to_string(),
        })
        .collect()
}

fn mismatch_code(import: &ObservedReceiptImport) -> &'static str {
    if import.observed_source_count < import.required_source_count {
        "missing_required_observed_sources"
    } else if !import.expected_matches_observed {
        "observed_root_mismatch"
    } else if !import.wallet_visible_matches && import.wallet_visible_required {
        "wallet_visible_root_mismatch"
    } else if !import.operator_evidence_matches {
        "operator_evidence_root_mismatch"
    } else if !import.pq_authority_matches {
        "pq_authority_root_mismatch"
    } else if !import.privacy_budget_respected {
        "privacy_budget_violation"
    } else {
        "release_hold"
    }
}

fn mismatch_evidence_root(import: &ObservedReceiptImport) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-observed-receipt-mismatch-evidence",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(import.lane.as_str()),
            HashPart::Str(&import.expected_receipt_root),
            HashPart::Str(&import.observed_receipt_root),
            HashPart::Str(import.status.as_str()),
        ],
        32,
    )
}

fn import_merkle(imports: &[ObservedReceiptImport]) -> String {
    let leaves = imports
        .iter()
        .map(|import| import.public_record())
        .collect::<Vec<_>>();
    merkle_root("monero-l2-pq-bridge-exit-observed-receipt-imports", &leaves)
}

fn source_merkle(imports: &[ObservedReceiptImport]) -> String {
    let leaves = imports
        .iter()
        .flat_map(|import| {
            import.source_roots.iter().map(|(source, root)| {
                json!({
                    "lane": import.lane.as_str(),
                    "source": source,
                    "source_root": root,
                })
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-observed-receipt-source-roots",
        &leaves,
    )
}

fn mismatch_merkle(mismatches: &[ObservedReceiptMismatch]) -> String {
    let leaves = mismatches
        .iter()
        .map(|mismatch| {
            json!({
                "mismatch_root": mismatch.state_root(),
                "record": mismatch.public_record(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-observed-receipt-mismatches",
        &leaves,
    )
}

fn lane_status_merkle(imports: &[ObservedReceiptImport]) -> String {
    let leaves = imports
        .iter()
        .map(|import| {
            json!({
                "lane": import.lane.as_str(),
                "status": import.status.as_str(),
                "release_blockers": import.release_blockers,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-observed-receipt-lane-status",
        &leaves,
    )
}

fn wallet_visible_merkle(imports: &[ObservedReceiptImport]) -> String {
    let leaves = imports
        .iter()
        .filter(|import| import.wallet_visible_required)
        .map(|import| {
            json!({
                "lane": import.lane.as_str(),
                "wallet_visible_root": import.wallet_visible_root,
                "wallet_visible_matches": import.wallet_visible_matches,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-observed-receipt-wallet-visible",
        &leaves,
    )
}

fn operator_evidence_merkle(imports: &[ObservedReceiptImport]) -> String {
    let leaves = imports
        .iter()
        .map(|import| {
            json!({
                "lane": import.lane.as_str(),
                "operator_evidence_root": import.operator_evidence_root,
                "operator_evidence_matches": import.operator_evidence_matches,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-observed-receipt-operator-evidence",
        &leaves,
    )
}

fn pq_authority_merkle(imports: &[ObservedReceiptImport]) -> String {
    let leaves = imports
        .iter()
        .map(|import| {
            json!({
                "lane": import.lane.as_str(),
                "pq_authority_root": import.pq_authority_root,
                "pq_authority_matches": import.pq_authority_matches,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-observed-receipt-pq-authority",
        &leaves,
    )
}

fn release_hold_reasons(imports: &[ObservedReceiptImport]) -> BTreeMap<String, String> {
    let mut reasons = BTreeMap::new();
    reasons.insert(
        "runtime_observation".to_string(),
        "runtime-observed receipt roots must replace placeholders before release".to_string(),
    );
    reasons.insert(
        "source_quorum".to_string(),
        "runtime harness devnet operator wallet and audit sources must agree on observed roots"
            .to_string(),
    );
    reasons.insert(
        "wallet_visibility".to_string(),
        "wallet-visible roots must match without exposing linkable metadata".to_string(),
    );
    reasons.insert(
        "pq_authority".to_string(),
        "PQ watcher sequencer and withdrawal authority evidence must match observed receipts"
            .to_string(),
    );
    reasons.insert(
        "fail_closed_cases".to_string(),
        "adversarial and release-blocker lanes must produce expected fail-closed receipts"
            .to_string(),
    );
    for import in imports {
        if import.status.blocks_release() {
            reasons.insert(
                format!("lane_{}", import.lane.as_str()),
                format!(
                    "{} remains {} with {} release blockers",
                    import.lane.label(),
                    import.status.as_str(),
                    import.release_blockers
                ),
            );
        }
    }
    reasons
}

fn hold_root(reasons: &BTreeMap<String, String>) -> String {
    let leaves = reasons
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-observed-receipt-release-holds",
        &leaves,
    )
}

fn manifest_id(config: &Config, roots: &ObservedReceiptRoots) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-observed-receipt-manifest-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(config.l2_reference_height),
            HashPart::U64(config.monero_reference_height),
            HashPart::Str(&roots.config_root),
            HashPart::Str(&roots.import_root),
            HashPart::Str(&roots.source_root),
            HashPart::Str(&roots.mismatch_root),
            HashPart::Str(&roots.release_hold_root),
        ],
        16,
    )
}
