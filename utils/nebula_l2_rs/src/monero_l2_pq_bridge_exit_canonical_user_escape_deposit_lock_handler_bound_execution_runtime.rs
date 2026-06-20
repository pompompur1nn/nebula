use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeDepositLockHandlerBoundExecutionRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_DEPOSIT_LOCK_HANDLER_BOUND_EXECUTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-deposit-lock-handler-bound-execution-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_DEPOSIT_LOCK_HANDLER_BOUND_EXECUTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const EXECUTION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-deposit-lock-handler-bound-execution-v1";
pub const HANDLER_BINDING_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-deposit-lock-live-handler-binding-v1";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_BASE_MONERO_HEIGHT: u64 = 3_512_040;
pub const DEFAULT_L2_REFERENCE_HEIGHT: u64 = 4_224_900;
pub const DEFAULT_MAX_EXECUTIONS: usize = 64;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-deposit-lock-handler-bound-execution-runtime";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionVerdict {
    Released,
    Held,
    Rejected,
}

impl ExecutionVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Released => "released",
            Self::Held => "held",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionGap {
    None,
    HandlerBinding,
    WatcherRoot,
    CustodyRoot,
    ClaimRoot,
    CargoRuntimeDeferred,
}

impl ExecutionGap {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::HandlerBinding => "handler_binding",
            Self::WatcherRoot => "watcher_root",
            Self::CustodyRoot => "custody_root",
            Self::ClaimRoot => "claim_root",
            Self::CargoRuntimeDeferred => "cargo_runtime_deferred",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub execution_suite: String,
    pub handler_binding_suite: String,
    pub monero_network: String,
    pub l2_network: String,
    pub base_monero_height: u64,
    pub l2_reference_height: u64,
    pub require_bound_handler_record: bool,
    pub require_watcher_root: bool,
    pub require_custody_root: bool,
    pub require_claim_root: bool,
    pub hold_when_cargo_runtime_deferred: bool,
    pub fail_closed: bool,
    pub production_release_allowed: bool,
    pub max_executions: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            execution_suite: EXECUTION_SUITE.to_string(),
            handler_binding_suite: HANDLER_BINDING_SUITE.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            base_monero_height: DEFAULT_BASE_MONERO_HEIGHT,
            l2_reference_height: DEFAULT_L2_REFERENCE_HEIGHT,
            require_bound_handler_record: true,
            require_watcher_root: true,
            require_custody_root: true,
            require_claim_root: true,
            hold_when_cargo_runtime_deferred: true,
            fail_closed: true,
            production_release_allowed: false,
            max_executions: DEFAULT_MAX_EXECUTIONS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "execution_suite": self.execution_suite,
            "handler_binding_suite": self.handler_binding_suite,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "base_monero_height": self.base_monero_height,
            "l2_reference_height": self.l2_reference_height,
            "require_bound_handler_record": self.require_bound_handler_record,
            "require_watcher_root": self.require_watcher_root,
            "require_custody_root": self.require_custody_root,
            "require_claim_root": self.require_claim_root,
            "hold_when_cargo_runtime_deferred": self.hold_when_cargo_runtime_deferred,
            "fail_closed": self.fail_closed,
            "production_release_allowed": self.production_release_allowed,
            "max_executions": self.max_executions,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HandlerBoundInput {
    pub binding_id: String,
    pub input_id: String,
    pub user_escape_package_id: String,
    pub lock_txid: String,
    pub lock_output_index: u64,
    pub deposit_address_commitment: String,
    pub amount_commitment: String,
    pub harness_input_root: String,
    pub live_observation_root: String,
    pub handler_binding_root: String,
    pub bound: bool,
}

impl HandlerBoundInput {
    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "input_id": self.input_id,
            "user_escape_package_id": self.user_escape_package_id,
            "lock_txid": self.lock_txid,
            "lock_output_index": self.lock_output_index,
            "deposit_address_commitment": self.deposit_address_commitment,
            "amount_commitment": self.amount_commitment,
            "harness_input_root": self.harness_input_root,
            "live_observation_root": self.live_observation_root,
            "handler_binding_root": self.handler_binding_root,
            "bound": self.bound,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HandlerBoundRoots {
    pub watcher_root: String,
    pub custody_root: String,
    pub claim_root: String,
    pub cargo_runtime_root: String,
    pub execution_subject_root: String,
    pub cargo_runtime_deferred: bool,
}

impl HandlerBoundRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "watcher_root": self.watcher_root,
            "custody_root": self.custody_root,
            "claim_root": self.claim_root,
            "cargo_runtime_root": self.cargo_runtime_root,
            "execution_subject_root": self.execution_subject_root,
            "cargo_runtime_deferred": self.cargo_runtime_deferred,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionRecord {
    pub execution_id: String,
    pub verdict: ExecutionVerdict,
    pub gap: ExecutionGap,
    pub input: HandlerBoundInput,
    pub roots: HandlerBoundRoots,
    pub execution_height: u64,
    pub l2_reference_height: u64,
    pub release_intent_root: String,
    pub hold_reason_root: String,
    pub execution_root: String,
}

impl ExecutionRecord {
    pub fn new(
        config: &Config,
        input: HandlerBoundInput,
        roots: HandlerBoundRoots,
        execution_height: u64,
        l2_reference_height: u64,
    ) -> Self {
        let gap = execution_gap(config, &input, &roots);
        let verdict = execution_verdict(config, gap);
        let release_intent_root = release_intent_root(&input, &roots, verdict);
        let hold_reason_root = hold_reason_root(gap, &input, &roots);
        let execution_root = execution_root(
            verdict,
            gap,
            &input,
            &roots,
            execution_height,
            l2_reference_height,
            &release_intent_root,
            &hold_reason_root,
        );
        let execution_id = domain_hash(
            &format!("{DOMAIN}:execution-id"),
            &[
                HashPart::Str(&input.binding_id),
                HashPart::Str(&input.input_id),
                HashPart::Str(&execution_root),
            ],
            16,
        );

        Self {
            execution_id,
            verdict,
            gap,
            input,
            roots,
            execution_height,
            l2_reference_height,
            release_intent_root,
            hold_reason_root,
            execution_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "execution_id": self.execution_id,
            "verdict": self.verdict.as_str(),
            "gap": self.gap.as_str(),
            "input": self.input.public_record(),
            "roots": self.roots.public_record(),
            "execution_height": self.execution_height,
            "l2_reference_height": self.l2_reference_height,
            "release_intent_root": self.release_intent_root,
            "hold_reason_root": self.hold_reason_root,
            "execution_root": self.execution_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub executions: Vec<ExecutionRecord>,
    pub released_execution_ids: Vec<String>,
    pub held_execution_ids: Vec<String>,
    pub rejected_execution_ids: Vec<String>,
    pub consumed_roots: BTreeMap<String, String>,
    pub devnet_data: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config, executions: Vec<ExecutionRecord>) -> Result<Self> {
        if executions.len() > config.max_executions {
            return Err("handler-bound execution count exceeds configured maximum".to_string());
        }

        let mut released_execution_ids = Vec::new();
        let mut held_execution_ids = Vec::new();
        let mut rejected_execution_ids = Vec::new();
        let mut consumed_roots = BTreeMap::new();

        for execution in &executions {
            match execution.verdict {
                ExecutionVerdict::Released => {
                    released_execution_ids.push(execution.execution_id.clone())
                }
                ExecutionVerdict::Held => held_execution_ids.push(execution.execution_id.clone()),
                ExecutionVerdict::Rejected => {
                    rejected_execution_ids.push(execution.execution_id.clone())
                }
            }
            consumed_roots.insert(
                format!("{}:watcher", execution.input.input_id),
                execution.roots.watcher_root.clone(),
            );
            consumed_roots.insert(
                format!("{}:custody", execution.input.input_id),
                execution.roots.custody_root.clone(),
            );
            consumed_roots.insert(
                format!("{}:claim", execution.input.input_id),
                execution.roots.claim_root.clone(),
            );
        }

        Ok(Self {
            config,
            executions,
            released_execution_ids,
            held_execution_ids,
            rejected_execution_ids,
            consumed_roots,
            devnet_data: devnet_data(),
        })
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        let executions = self
            .executions
            .iter()
            .map(ExecutionRecord::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "executions": executions,
            "released_execution_ids": self.released_execution_ids,
            "held_execution_ids": self.held_execution_ids,
            "rejected_execution_ids": self.rejected_execution_ids,
            "consumed_roots": self.consumed_roots,
            "roots": {
                "config_root": self.config.state_root(),
                "execution_root": self.execution_set_root(),
                "released_root": vector_root("RELEASED", &self.released_execution_ids),
                "held_root": vector_root("HELD", &self.held_execution_ids),
                "rejected_root": vector_root("REJECTED", &self.rejected_execution_ids),
                "consumed_root": map_root("consumed_roots", &self.consumed_roots),
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

    pub fn execution_set_root(&self) -> String {
        let records = self
            .executions
            .iter()
            .map(ExecutionRecord::public_record)
            .collect::<Vec<_>>();
        merkle_root(&format!("{DOMAIN}:executions"), &records)
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
    let executions = devnet_executions(&config);
    match State::new(config, executions) {
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

pub fn devnet_executions(config: &Config) -> Vec<ExecutionRecord> {
    [
        (true, false, true, true, true),
        (true, true, true, true, true),
        (true, false, false, true, true),
        (false, false, true, true, true),
    ]
    .iter()
    .enumerate()
    .map(
        |(index, (cargo_deferred, missing_watcher, custody_ok, claim_ok, bound))| {
            let ordinal = index as u64;
            let input = handler_bound_input(config, ordinal, *bound);
            let roots = handler_bound_roots(
                &input,
                ordinal,
                *cargo_deferred,
                *missing_watcher,
                *custody_ok,
                *claim_ok,
            );
            ExecutionRecord::new(
                config,
                input,
                roots,
                config.base_monero_height + ordinal,
                config.l2_reference_height + ordinal,
            )
        },
    )
    .collect()
}

fn handler_bound_input(config: &Config, ordinal: u64, bound: bool) -> HandlerBoundInput {
    let label = format!("user-escape-deposit-lock-handler-bound-execution-{ordinal}");
    let lock_txid = domain_hash(
        &format!("{DOMAIN}:lock-txid"),
        &[HashPart::Str(&label), HashPart::U64(ordinal)],
        32,
    );
    let lock_output_index = ordinal;
    let deposit_address_commitment = commitment("deposit-address", &label, ordinal);
    let amount_commitment = commitment("amount", &label, ordinal);
    let live_observation_root = domain_hash(
        &format!("{DOMAIN}:live-observation"),
        &[
            HashPart::Str(&lock_txid),
            HashPart::U64(lock_output_index),
            HashPart::Str(&deposit_address_commitment),
            HashPart::Str(&amount_commitment),
            HashPart::U64(config.base_monero_height + ordinal),
        ],
        32,
    );
    let user_escape_package_id = domain_hash(
        &format!("{DOMAIN}:user-escape-package"),
        &[
            HashPart::Str(&lock_txid),
            HashPart::U64(lock_output_index),
            HashPart::Str(&live_observation_root),
        ],
        16,
    );
    let harness_input_root = domain_hash(
        &format!("{DOMAIN}:harness-input"),
        &[
            HashPart::Str(&user_escape_package_id),
            HashPart::Str(&deposit_address_commitment),
            HashPart::Str(&amount_commitment),
            HashPart::Str(&live_observation_root),
        ],
        32,
    );
    let bound_marker = bool_str(bound);
    let handler_binding_root = domain_hash(
        &format!("{DOMAIN}:handler-binding"),
        &[
            HashPart::Str(&user_escape_package_id),
            HashPart::Str(&harness_input_root),
            HashPart::Str(bound_marker),
        ],
        32,
    );
    let input_id = domain_hash(
        &format!("{DOMAIN}:input-id"),
        &[
            HashPart::Str(&user_escape_package_id),
            HashPart::Str(&harness_input_root),
        ],
        16,
    );
    let binding_id = domain_hash(
        &format!("{DOMAIN}:binding-id"),
        &[
            HashPart::Str(&input_id),
            HashPart::Str(&handler_binding_root),
            HashPart::Str(bound_marker),
        ],
        16,
    );

    HandlerBoundInput {
        binding_id,
        input_id,
        user_escape_package_id,
        lock_txid,
        lock_output_index,
        deposit_address_commitment,
        amount_commitment,
        harness_input_root,
        live_observation_root,
        handler_binding_root,
        bound,
    }
}

fn handler_bound_roots(
    input: &HandlerBoundInput,
    ordinal: u64,
    cargo_runtime_deferred: bool,
    missing_watcher: bool,
    custody_ok: bool,
    claim_ok: bool,
) -> HandlerBoundRoots {
    let watcher_root = conditional_root("watcher", input, ordinal, !missing_watcher);
    let custody_root = conditional_root("custody", input, ordinal, custody_ok);
    let claim_root = conditional_root("claim", input, ordinal, claim_ok);
    let cargo_marker = bool_str(cargo_runtime_deferred);
    let cargo_runtime_root = domain_hash(
        &format!("{DOMAIN}:cargo-runtime"),
        &[
            HashPart::Str(&input.input_id),
            HashPart::Str(&input.handler_binding_root),
            HashPart::Str(cargo_marker),
        ],
        32,
    );
    let execution_subject_root = domain_hash(
        &format!("{DOMAIN}:execution-subject"),
        &[
            HashPart::Str(&input.input_id),
            HashPart::Str(&watcher_root),
            HashPart::Str(&custody_root),
            HashPart::Str(&claim_root),
            HashPart::Str(&cargo_runtime_root),
        ],
        32,
    );

    HandlerBoundRoots {
        watcher_root,
        custody_root,
        claim_root,
        cargo_runtime_root,
        execution_subject_root,
        cargo_runtime_deferred,
    }
}

fn execution_gap(
    config: &Config,
    input: &HandlerBoundInput,
    roots: &HandlerBoundRoots,
) -> ExecutionGap {
    if config.require_bound_handler_record && !input.bound {
        ExecutionGap::HandlerBinding
    } else if config.require_watcher_root && roots.watcher_root == missing_root("watcher") {
        ExecutionGap::WatcherRoot
    } else if config.require_custody_root && roots.custody_root == missing_root("custody") {
        ExecutionGap::CustodyRoot
    } else if config.require_claim_root && roots.claim_root == missing_root("claim") {
        ExecutionGap::ClaimRoot
    } else if config.hold_when_cargo_runtime_deferred && roots.cargo_runtime_deferred {
        ExecutionGap::CargoRuntimeDeferred
    } else {
        ExecutionGap::None
    }
}

fn execution_verdict(config: &Config, gap: ExecutionGap) -> ExecutionVerdict {
    match gap {
        ExecutionGap::None => ExecutionVerdict::Released,
        ExecutionGap::CargoRuntimeDeferred => ExecutionVerdict::Held,
        ExecutionGap::HandlerBinding
        | ExecutionGap::WatcherRoot
        | ExecutionGap::CustodyRoot
        | ExecutionGap::ClaimRoot
            if config.fail_closed =>
        {
            ExecutionVerdict::Rejected
        }
        ExecutionGap::HandlerBinding
        | ExecutionGap::WatcherRoot
        | ExecutionGap::CustodyRoot
        | ExecutionGap::ClaimRoot => ExecutionVerdict::Held,
    }
}

fn execution_root(
    verdict: ExecutionVerdict,
    gap: ExecutionGap,
    input: &HandlerBoundInput,
    roots: &HandlerBoundRoots,
    execution_height: u64,
    l2_reference_height: u64,
    release_intent_root: &str,
    hold_reason_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:execution-root"),
        &[
            HashPart::Str(verdict.as_str()),
            HashPart::Str(gap.as_str()),
            HashPart::Str(&input.binding_id),
            HashPart::Str(&input.input_id),
            HashPart::Str(&input.user_escape_package_id),
            HashPart::Str(&input.handler_binding_root),
            HashPart::Str(&roots.watcher_root),
            HashPart::Str(&roots.custody_root),
            HashPart::Str(&roots.claim_root),
            HashPart::Str(&roots.cargo_runtime_root),
            HashPart::Str(&roots.execution_subject_root),
            HashPart::U64(execution_height),
            HashPart::U64(l2_reference_height),
            HashPart::Str(release_intent_root),
            HashPart::Str(hold_reason_root),
        ],
        32,
    )
}

fn release_intent_root(
    input: &HandlerBoundInput,
    roots: &HandlerBoundRoots,
    verdict: ExecutionVerdict,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:release-intent"),
        &[
            HashPart::Str(&input.user_escape_package_id),
            HashPart::Str(&input.deposit_address_commitment),
            HashPart::Str(&input.amount_commitment),
            HashPart::Str(&roots.execution_subject_root),
            HashPart::Str(verdict.as_str()),
        ],
        32,
    )
}

fn hold_reason_root(
    gap: ExecutionGap,
    input: &HandlerBoundInput,
    roots: &HandlerBoundRoots,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:hold-reason"),
        &[
            HashPart::Str(gap.as_str()),
            HashPart::Str(&input.binding_id),
            HashPart::Str(&roots.cargo_runtime_root),
            HashPart::Str(bool_str(roots.cargo_runtime_deferred)),
        ],
        32,
    )
}

fn conditional_root(label: &str, input: &HandlerBoundInput, ordinal: u64, present: bool) -> String {
    if present {
        domain_hash(
            &format!("{DOMAIN}:{label}"),
            &[
                HashPart::Str(&input.input_id),
                HashPart::Str(&input.handler_binding_root),
                HashPart::U64(ordinal),
            ],
            32,
        )
    } else {
        missing_root(label)
    }
}

fn missing_root(label: &str) -> String {
    domain_hash(
        &format!("{DOMAIN}:missing-root"),
        &[HashPart::Str(label)],
        32,
    )
}

fn commitment(domain: &str, label: &str, ordinal: u64) -> String {
    domain_hash(
        &format!("{DOMAIN}:{domain}"),
        &[HashPart::Str(label), HashPart::U64(ordinal)],
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
        "execution_lane".to_string(),
        json!({
            "input": "handler_bound_deposit_lock_record",
            "consumes": [
                "watcher_root",
                "custody_root",
                "claim_root"
            ],
            "output": "forced_exit_execution_verdict"
        }),
    );
    data.insert(
        "deferred_runtime_policy".to_string(),
        json!({
            "cargo_runtime_deferred": "held",
            "release_requires": [
                "bound_handler_record",
                "watcher_root",
                "custody_root",
                "claim_root",
                "non_deferred_cargo_runtime"
            ]
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
        executions: Vec::new(),
        released_execution_ids: Vec::new(),
        held_execution_ids: Vec::new(),
        rejected_execution_ids: Vec::new(),
        consumed_roots: BTreeMap::new(),
        devnet_data,
    }
}
