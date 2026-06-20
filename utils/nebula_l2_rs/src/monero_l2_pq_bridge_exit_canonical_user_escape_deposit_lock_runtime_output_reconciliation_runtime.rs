use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeDepositLockRuntimeOutputReconciliationRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_DEPOSIT_LOCK_RUNTIME_OUTPUT_RECONCILIATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-deposit-lock-runtime-output-reconciliation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_DEPOSIT_LOCK_RUNTIME_OUTPUT_RECONCILIATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECONCILIATION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-deposit-lock-runtime-output-reconciliation-v1";
pub const HANDLER_BOUND_EXECUTION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-deposit-lock-handler-bound-execution-v1";
pub const RUNTIME_OUTPUT_SOURCE_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-deposit-lock-process-fed-runtime-output-v1";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_BASE_MONERO_HEIGHT: u64 = 3_512_040;
pub const DEFAULT_L2_REFERENCE_HEIGHT: u64 = 4_224_900;
pub const DEFAULT_MAX_RECONCILIATIONS: usize = 64;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-deposit-lock-runtime-output-reconciliation-runtime";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeOutputKind {
    WatcherRoot,
    CustodyRoot,
    ClaimRoot,
    CargoRuntimeRoot,
    ExecutionSubjectRoot,
    ReleaseIntentRoot,
}

impl RuntimeOutputKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WatcherRoot => "watcher_root",
            Self::CustodyRoot => "custody_root",
            Self::ClaimRoot => "claim_root",
            Self::CargoRuntimeRoot => "cargo_runtime_root",
            Self::ExecutionSubjectRoot => "execution_subject_root",
            Self::ReleaseIntentRoot => "release_intent_root",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationStatus {
    Matched,
    Held,
    Mismatched,
    MissingOutput,
    StaleOutput,
    UntrustedSource,
}

impl ReconciliationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Held => "held",
            Self::Mismatched => "mismatched",
            Self::MissingOutput => "missing_output",
            Self::StaleOutput => "stale_output",
            Self::UntrustedSource => "untrusted_source",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationVerdict {
    Release,
    Hold,
    Reject,
}

impl ReconciliationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Hold => "hold",
            Self::Reject => "reject",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub reconciliation_suite: String,
    pub handler_bound_execution_suite: String,
    pub runtime_output_source_suite: String,
    pub monero_network: String,
    pub l2_network: String,
    pub base_monero_height: u64,
    pub l2_reference_height: u64,
    pub require_trusted_source: bool,
    pub require_all_expected_roots: bool,
    pub reject_mismatch: bool,
    pub hold_stale_outputs: bool,
    pub fail_closed: bool,
    pub production_release_allowed: bool,
    pub max_reconciliations: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            reconciliation_suite: RECONCILIATION_SUITE.to_string(),
            handler_bound_execution_suite: HANDLER_BOUND_EXECUTION_SUITE.to_string(),
            runtime_output_source_suite: RUNTIME_OUTPUT_SOURCE_SUITE.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            base_monero_height: DEFAULT_BASE_MONERO_HEIGHT,
            l2_reference_height: DEFAULT_L2_REFERENCE_HEIGHT,
            require_trusted_source: true,
            require_all_expected_roots: true,
            reject_mismatch: true,
            hold_stale_outputs: true,
            fail_closed: true,
            production_release_allowed: false,
            max_reconciliations: DEFAULT_MAX_RECONCILIATIONS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "reconciliation_suite": self.reconciliation_suite,
            "handler_bound_execution_suite": self.handler_bound_execution_suite,
            "runtime_output_source_suite": self.runtime_output_source_suite,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "base_monero_height": self.base_monero_height,
            "l2_reference_height": self.l2_reference_height,
            "require_trusted_source": self.require_trusted_source,
            "require_all_expected_roots": self.require_all_expected_roots,
            "reject_mismatch": self.reject_mismatch,
            "hold_stale_outputs": self.hold_stale_outputs,
            "fail_closed": self.fail_closed,
            "production_release_allowed": self.production_release_allowed,
            "max_reconciliations": self.max_reconciliations,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeOutputSource {
    pub source_id: String,
    pub process_id: String,
    pub output_batch_id: String,
    pub source_suite: String,
    pub source_root: String,
    pub produced_height: u64,
    pub trusted: bool,
}

impl RuntimeOutputSource {
    pub fn public_record(&self) -> Value {
        json!({
            "source_id": self.source_id,
            "process_id": self.process_id,
            "output_batch_id": self.output_batch_id,
            "source_suite": self.source_suite,
            "source_root": self.source_root,
            "produced_height": self.produced_height,
            "trusted": self.trusted,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExpectedRoot {
    pub root_id: String,
    pub execution_id: String,
    pub binding_id: String,
    pub input_id: String,
    pub output_kind: RuntimeOutputKind,
    pub expected_root: String,
    pub handler_execution_root: String,
    pub required: bool,
}

impl ExpectedRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "root_id": self.root_id,
            "execution_id": self.execution_id,
            "binding_id": self.binding_id,
            "input_id": self.input_id,
            "output_kind": self.output_kind.as_str(),
            "expected_root": self.expected_root,
            "handler_execution_root": self.handler_execution_root,
            "required": self.required,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ObservedRoot {
    pub root_id: String,
    pub source_id: String,
    pub output_kind: RuntimeOutputKind,
    pub observed_root: String,
    pub observed_height: u64,
    pub output_root: String,
    pub present: bool,
}

impl ObservedRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "root_id": self.root_id,
            "source_id": self.source_id,
            "output_kind": self.output_kind.as_str(),
            "observed_root": self.observed_root,
            "observed_height": self.observed_height,
            "output_root": self.output_root,
            "present": self.present,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MismatchRecord {
    pub mismatch_id: String,
    pub root_id: String,
    pub output_kind: RuntimeOutputKind,
    pub expected_root: String,
    pub observed_root: String,
    pub source_id: String,
    pub mismatch_root: String,
}

impl MismatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "mismatch_id": self.mismatch_id,
            "root_id": self.root_id,
            "output_kind": self.output_kind.as_str(),
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "source_id": self.source_id,
            "mismatch_root": self.mismatch_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub execution_id: String,
    pub input_id: String,
    pub status: ReconciliationStatus,
    pub reason_root: String,
    pub release_blocked: bool,
}

impl ReleaseHold {
    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "execution_id": self.execution_id,
            "input_id": self.input_id,
            "status": self.status.as_str(),
            "reason_root": self.reason_root,
            "release_blocked": self.release_blocked,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReconciliationRecord {
    pub reconciliation_id: String,
    pub expected: ExpectedRoot,
    pub observed: ObservedRoot,
    pub source: RuntimeOutputSource,
    pub status: ReconciliationStatus,
    pub verdict: ReconciliationVerdict,
    pub mismatch: Option<MismatchRecord>,
    pub release_hold: Option<ReleaseHold>,
    pub reconciliation_height: u64,
    pub reconciliation_root: String,
}

impl ReconciliationRecord {
    pub fn new(
        config: &Config,
        expected: ExpectedRoot,
        observed: ObservedRoot,
        source: RuntimeOutputSource,
        reconciliation_height: u64,
    ) -> Self {
        let status = reconciliation_status(config, &expected, &observed, &source);
        let verdict = reconciliation_verdict(config, status);
        let mismatch = mismatch_record(&expected, &observed, &source, status);
        let release_hold = release_hold(&expected, status, verdict);
        let reconciliation_root = reconciliation_root(
            &expected,
            &observed,
            &source,
            status,
            verdict,
            mismatch.as_ref(),
            release_hold.as_ref(),
            reconciliation_height,
        );
        let reconciliation_id = domain_hash(
            &format!("{DOMAIN}:reconciliation-id"),
            &[
                HashPart::Str(&expected.root_id),
                HashPart::Str(&observed.source_id),
                HashPart::Str(&reconciliation_root),
            ],
            16,
        );

        Self {
            reconciliation_id,
            expected,
            observed,
            source,
            status,
            verdict,
            mismatch,
            release_hold,
            reconciliation_height,
            reconciliation_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reconciliation_id": self.reconciliation_id,
            "expected": self.expected.public_record(),
            "observed": self.observed.public_record(),
            "source": self.source.public_record(),
            "status": self.status.as_str(),
            "verdict": self.verdict.as_str(),
            "mismatch": self.mismatch.as_ref().map(MismatchRecord::public_record),
            "release_hold": self.release_hold.as_ref().map(ReleaseHold::public_record),
            "reconciliation_height": self.reconciliation_height,
            "reconciliation_root": self.reconciliation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub reconciliations: Vec<ReconciliationRecord>,
    pub released_reconciliation_ids: Vec<String>,
    pub held_reconciliation_ids: Vec<String>,
    pub rejected_reconciliation_ids: Vec<String>,
    pub mismatch_records: Vec<MismatchRecord>,
    pub release_holds: Vec<ReleaseHold>,
    pub observed_roots: BTreeMap<String, String>,
    pub expected_roots: BTreeMap<String, String>,
    pub devnet_data: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config, reconciliations: Vec<ReconciliationRecord>) -> Result<Self> {
        if reconciliations.len() > config.max_reconciliations {
            return Err(
                "runtime output reconciliation count exceeds configured maximum".to_string(),
            );
        }

        let mut released_reconciliation_ids = Vec::new();
        let mut held_reconciliation_ids = Vec::new();
        let mut rejected_reconciliation_ids = Vec::new();
        let mut mismatch_records = Vec::new();
        let mut release_holds = Vec::new();
        let mut observed_roots = BTreeMap::new();
        let mut expected_roots = BTreeMap::new();

        for reconciliation in &reconciliations {
            match reconciliation.verdict {
                ReconciliationVerdict::Release => {
                    released_reconciliation_ids.push(reconciliation.reconciliation_id.clone())
                }
                ReconciliationVerdict::Hold => {
                    held_reconciliation_ids.push(reconciliation.reconciliation_id.clone())
                }
                ReconciliationVerdict::Reject => {
                    rejected_reconciliation_ids.push(reconciliation.reconciliation_id.clone())
                }
            }
            expected_roots.insert(
                reconciliation.expected.root_id.clone(),
                reconciliation.expected.expected_root.clone(),
            );
            observed_roots.insert(
                reconciliation.observed.root_id.clone(),
                reconciliation.observed.observed_root.clone(),
            );
            if let Some(mismatch) = &reconciliation.mismatch {
                mismatch_records.push(mismatch.clone());
            }
            if let Some(hold) = &reconciliation.release_hold {
                release_holds.push(hold.clone());
            }
        }

        Ok(Self {
            config,
            reconciliations,
            released_reconciliation_ids,
            held_reconciliation_ids,
            rejected_reconciliation_ids,
            mismatch_records,
            release_holds,
            observed_roots,
            expected_roots,
            devnet_data: devnet_data(),
        })
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        let reconciliations = self
            .reconciliations
            .iter()
            .map(ReconciliationRecord::public_record)
            .collect::<Vec<_>>();
        let mismatches = self
            .mismatch_records
            .iter()
            .map(MismatchRecord::public_record)
            .collect::<Vec<_>>();
        let release_holds = self
            .release_holds
            .iter()
            .map(ReleaseHold::public_record)
            .collect::<Vec<_>>();

        json!({
            "config": self.config.public_record(),
            "reconciliations": reconciliations,
            "released_reconciliation_ids": self.released_reconciliation_ids,
            "held_reconciliation_ids": self.held_reconciliation_ids,
            "rejected_reconciliation_ids": self.rejected_reconciliation_ids,
            "mismatch_records": mismatches,
            "release_holds": release_holds,
            "observed_roots": self.observed_roots,
            "expected_roots": self.expected_roots,
            "roots": {
                "config_root": self.config.state_root(),
                "reconciliation_root": self.reconciliation_set_root(),
                "released_root": vector_root("RELEASED", &self.released_reconciliation_ids),
                "held_root": vector_root("HELD", &self.held_reconciliation_ids),
                "rejected_root": vector_root("REJECTED", &self.rejected_reconciliation_ids),
                "mismatch_root": self.mismatch_set_root(),
                "release_hold_root": self.release_hold_set_root(),
                "observed_root": map_root("observed_roots", &self.observed_roots),
                "expected_root": map_root("expected_roots", &self.expected_roots),
                "devnet_data_root": self.devnet_data_root(),
            },
            "devnet_data": self.devnet_data,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            &format!("{DOMAIN}:state"),
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn reconciliation_set_root(&self) -> String {
        let records = self
            .reconciliations
            .iter()
            .map(ReconciliationRecord::public_record)
            .collect::<Vec<_>>();
        merkle_root(&format!("{DOMAIN}:reconciliations"), &records)
    }

    pub fn mismatch_set_root(&self) -> String {
        let records = self
            .mismatch_records
            .iter()
            .map(MismatchRecord::public_record)
            .collect::<Vec<_>>();
        merkle_root(&format!("{DOMAIN}:mismatches"), &records)
    }

    pub fn release_hold_set_root(&self) -> String {
        let records = self
            .release_holds
            .iter()
            .map(ReleaseHold::public_record)
            .collect::<Vec<_>>();
        merkle_root(&format!("{DOMAIN}:release-holds"), &records)
    }

    pub fn devnet_data_root(&self) -> String {
        let records = self
            .devnet_data
            .iter()
            .map(|(key, value)| json!({ "key": key, "value": value }))
            .collect::<Vec<_>>();
        merkle_root(&format!("{DOMAIN}:devnet-data"), &records)
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let reconciliations = devnet_reconciliations(&config);
    match State::new(config, reconciliations) {
        Ok(state) => state,
        Err(reason) => fallback_state(reason),
    }
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn devnet_reconciliations(config: &Config) -> Vec<ReconciliationRecord> {
    [
        (RuntimeOutputKind::WatcherRoot, true, true, true, false),
        (RuntimeOutputKind::CustodyRoot, true, true, false, false),
        (RuntimeOutputKind::ClaimRoot, true, false, true, false),
        (
            RuntimeOutputKind::CargoRuntimeRoot,
            false,
            true,
            true,
            false,
        ),
        (
            RuntimeOutputKind::ExecutionSubjectRoot,
            true,
            true,
            true,
            true,
        ),
    ]
    .iter()
    .enumerate()
    .map(|(index, (kind, trusted, present, matches, stale))| {
        let ordinal = index as u64;
        let expected = expected_root(config, ordinal, *kind);
        let source = runtime_output_source(config, ordinal, *trusted, *stale);
        let observed = observed_root(config, &expected, &source, ordinal, *present, *matches);
        ReconciliationRecord::new(
            config,
            expected,
            observed,
            source,
            config.l2_reference_height + ordinal,
        )
    })
    .collect()
}

fn expected_root(config: &Config, ordinal: u64, output_kind: RuntimeOutputKind) -> ExpectedRoot {
    let label = format!("runtime-output-reconciliation-{ordinal}");
    let input_id = domain_hash(
        &format!("{DOMAIN}:input-id"),
        &[HashPart::Str(&label), HashPart::U64(ordinal)],
        16,
    );
    let binding_id = domain_hash(
        &format!("{DOMAIN}:binding-id"),
        &[HashPart::Str(&input_id), HashPart::Str(CHAIN_ID)],
        16,
    );
    let execution_id = domain_hash(
        &format!("{DOMAIN}:execution-id"),
        &[HashPart::Str(&binding_id), HashPart::Str(&input_id)],
        16,
    );
    let handler_execution_root = domain_hash(
        &format!("{DOMAIN}:handler-execution-root"),
        &[
            HashPart::Str(&execution_id),
            HashPart::Str(&binding_id),
            HashPart::Str(&input_id),
            HashPart::U64(config.base_monero_height + ordinal),
        ],
        32,
    );
    let expected_root = domain_hash(
        &format!("{DOMAIN}:expected-root"),
        &[
            HashPart::Str(output_kind.as_str()),
            HashPart::Str(&handler_execution_root),
            HashPart::U64(config.l2_reference_height + ordinal),
        ],
        32,
    );
    let root_id = domain_hash(
        &format!("{DOMAIN}:root-id"),
        &[
            HashPart::Str(&execution_id),
            HashPart::Str(output_kind.as_str()),
            HashPart::Str(&expected_root),
        ],
        16,
    );

    ExpectedRoot {
        root_id,
        execution_id,
        binding_id,
        input_id,
        output_kind,
        expected_root,
        handler_execution_root,
        required: true,
    }
}

fn runtime_output_source(
    config: &Config,
    ordinal: u64,
    trusted: bool,
    stale: bool,
) -> RuntimeOutputSource {
    let process_id = domain_hash(
        &format!("{DOMAIN}:process-id"),
        &[
            HashPart::Str(RUNTIME_OUTPUT_SOURCE_SUITE),
            HashPart::U64(ordinal),
        ],
        16,
    );
    let output_batch_id = domain_hash(
        &format!("{DOMAIN}:output-batch-id"),
        &[HashPart::Str(&process_id), HashPart::U64(ordinal)],
        16,
    );
    let produced_height = if stale {
        config.l2_reference_height.saturating_sub(1)
    } else {
        config.l2_reference_height + ordinal
    };
    let source_root = domain_hash(
        &format!("{DOMAIN}:source-root"),
        &[
            HashPart::Str(&process_id),
            HashPart::Str(&output_batch_id),
            HashPart::Str(bool_str(trusted)),
            HashPart::U64(produced_height),
        ],
        32,
    );
    let source_id = domain_hash(
        &format!("{DOMAIN}:source-id"),
        &[HashPart::Str(&source_root), HashPart::Str(&output_batch_id)],
        16,
    );

    RuntimeOutputSource {
        source_id,
        process_id,
        output_batch_id,
        source_suite: RUNTIME_OUTPUT_SOURCE_SUITE.to_string(),
        source_root,
        produced_height,
        trusted,
    }
}

fn observed_root(
    config: &Config,
    expected: &ExpectedRoot,
    source: &RuntimeOutputSource,
    ordinal: u64,
    present: bool,
    matches_expected: bool,
) -> ObservedRoot {
    let observed_root = if present && matches_expected {
        expected.expected_root.clone()
    } else if present {
        domain_hash(
            &format!("{DOMAIN}:observed-mismatch"),
            &[
                HashPart::Str(&expected.root_id),
                HashPart::Str(&source.source_id),
                HashPart::U64(ordinal),
            ],
            32,
        )
    } else {
        missing_root(expected.output_kind.as_str())
    };
    let observed_height = source.produced_height;
    let output_root = domain_hash(
        &format!("{DOMAIN}:output-root"),
        &[
            HashPart::Str(&source.source_id),
            HashPart::Str(expected.output_kind.as_str()),
            HashPart::Str(&observed_root),
            HashPart::U64(observed_height),
            HashPart::U64(config.l2_reference_height),
        ],
        32,
    );

    ObservedRoot {
        root_id: expected.root_id.clone(),
        source_id: source.source_id.clone(),
        output_kind: expected.output_kind,
        observed_root,
        observed_height,
        output_root,
        present,
    }
}

fn reconciliation_status(
    config: &Config,
    expected: &ExpectedRoot,
    observed: &ObservedRoot,
    source: &RuntimeOutputSource,
) -> ReconciliationStatus {
    if config.require_trusted_source && !source.trusted {
        ReconciliationStatus::UntrustedSource
    } else if config.hold_stale_outputs && observed.observed_height < config.l2_reference_height {
        ReconciliationStatus::StaleOutput
    } else if config.require_all_expected_roots && expected.required && !observed.present {
        ReconciliationStatus::MissingOutput
    } else if expected.expected_root == observed.observed_root {
        ReconciliationStatus::Matched
    } else if config.reject_mismatch {
        ReconciliationStatus::Mismatched
    } else {
        ReconciliationStatus::Held
    }
}

fn reconciliation_verdict(config: &Config, status: ReconciliationStatus) -> ReconciliationVerdict {
    match status {
        ReconciliationStatus::Matched => ReconciliationVerdict::Release,
        ReconciliationStatus::Held | ReconciliationStatus::StaleOutput => {
            ReconciliationVerdict::Hold
        }
        ReconciliationStatus::Mismatched
        | ReconciliationStatus::MissingOutput
        | ReconciliationStatus::UntrustedSource
            if config.fail_closed =>
        {
            ReconciliationVerdict::Reject
        }
        ReconciliationStatus::Mismatched
        | ReconciliationStatus::MissingOutput
        | ReconciliationStatus::UntrustedSource => ReconciliationVerdict::Hold,
    }
}

fn mismatch_record(
    expected: &ExpectedRoot,
    observed: &ObservedRoot,
    source: &RuntimeOutputSource,
    status: ReconciliationStatus,
) -> Option<MismatchRecord> {
    if status != ReconciliationStatus::Mismatched {
        return None;
    }

    let mismatch_root = domain_hash(
        &format!("{DOMAIN}:mismatch-root"),
        &[
            HashPart::Str(&expected.root_id),
            HashPart::Str(expected.output_kind.as_str()),
            HashPart::Str(&expected.expected_root),
            HashPart::Str(&observed.observed_root),
            HashPart::Str(&source.source_id),
        ],
        32,
    );
    let mismatch_id = domain_hash(
        &format!("{DOMAIN}:mismatch-id"),
        &[
            HashPart::Str(&expected.root_id),
            HashPart::Str(&mismatch_root),
        ],
        16,
    );

    Some(MismatchRecord {
        mismatch_id,
        root_id: expected.root_id.clone(),
        output_kind: expected.output_kind,
        expected_root: expected.expected_root.clone(),
        observed_root: observed.observed_root.clone(),
        source_id: source.source_id.clone(),
        mismatch_root,
    })
}

fn release_hold(
    expected: &ExpectedRoot,
    status: ReconciliationStatus,
    verdict: ReconciliationVerdict,
) -> Option<ReleaseHold> {
    if verdict == ReconciliationVerdict::Release {
        return None;
    }

    let reason_root = domain_hash(
        &format!("{DOMAIN}:release-hold-reason"),
        &[
            HashPart::Str(&expected.execution_id),
            HashPart::Str(&expected.input_id),
            HashPart::Str(status.as_str()),
            HashPart::Str(verdict.as_str()),
        ],
        32,
    );
    let hold_id = domain_hash(
        &format!("{DOMAIN}:release-hold-id"),
        &[
            HashPart::Str(&expected.root_id),
            HashPart::Str(&reason_root),
        ],
        16,
    );

    Some(ReleaseHold {
        hold_id,
        execution_id: expected.execution_id.clone(),
        input_id: expected.input_id.clone(),
        status,
        reason_root,
        release_blocked: true,
    })
}

fn reconciliation_root(
    expected: &ExpectedRoot,
    observed: &ObservedRoot,
    source: &RuntimeOutputSource,
    status: ReconciliationStatus,
    verdict: ReconciliationVerdict,
    mismatch: Option<&MismatchRecord>,
    release_hold: Option<&ReleaseHold>,
    reconciliation_height: u64,
) -> String {
    let mismatch_root = match mismatch {
        Some(record) => record.mismatch_root.as_str(),
        None => "none",
    };
    let hold_root = match release_hold {
        Some(record) => record.reason_root.as_str(),
        None => "none",
    };

    domain_hash(
        &format!("{DOMAIN}:reconciliation-root"),
        &[
            HashPart::Str(&expected.root_id),
            HashPart::Str(&expected.expected_root),
            HashPart::Str(&observed.observed_root),
            HashPart::Str(&source.source_root),
            HashPart::Str(status.as_str()),
            HashPart::Str(verdict.as_str()),
            HashPart::Str(mismatch_root),
            HashPart::Str(hold_root),
            HashPart::U64(reconciliation_height),
        ],
        32,
    )
}

fn missing_root(label: &str) -> String {
    domain_hash(
        &format!("{DOMAIN}:missing-root"),
        &[HashPart::Str(label)],
        32,
    )
}

fn vector_root(label: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "label": label, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:{label}"), &leaves)
}

fn map_root(label: &str, map: &BTreeMap<String, String>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:{label}"), &leaves)
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:{label}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn devnet_data() -> BTreeMap<String, Value> {
    let mut data = BTreeMap::new();
    data.insert(
        "reconciliation_lane".to_string(),
        json!({
            "input": "handler_bound_execution_record",
            "future_input": "process_fed_runtime_output",
            "output": "release_or_hold_reconciliation_verdict"
        }),
    );
    data.insert(
        "fail_closed_policy".to_string(),
        json!({
            "untrusted_source": "reject",
            "missing_output": "reject",
            "mismatch": "reject",
            "stale_output": "hold",
            "matched": "release"
        }),
    );
    data
}

fn fallback_state(reason: String) -> State {
    let config = Config::devnet();
    let mut devnet_data = devnet_data();
    devnet_data.insert(
        "construction_error".to_string(),
        json!({
            "reason_root": domain_hash(
                &format!("{DOMAIN}:fallback"),
                &[HashPart::Str(&reason)],
                32
            )
        }),
    );
    State {
        config,
        reconciliations: Vec::new(),
        released_reconciliation_ids: Vec::new(),
        held_reconciliation_ids: Vec::new(),
        rejected_reconciliation_ids: Vec::new(),
        mismatch_records: Vec::new(),
        release_holds: Vec::new(),
        observed_roots: BTreeMap::new(),
        expected_roots: BTreeMap::new(),
        devnet_data,
    }
}
