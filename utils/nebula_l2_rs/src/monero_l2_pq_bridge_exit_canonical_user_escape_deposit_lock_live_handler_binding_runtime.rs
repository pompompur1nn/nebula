use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeDepositLockLiveHandlerBindingRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_DEPOSIT_LOCK_LIVE_HANDLER_BINDING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-deposit-lock-live-handler-binding-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_DEPOSIT_LOCK_LIVE_HANDLER_BINDING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const HANDLER_BINDING_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-deposit-lock-live-handler-binding-v1";
pub const LIVE_INPUT_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-deposit-lock-live-input-v1";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_BASE_MONERO_HEIGHT: u64 = 3_512_040;
pub const DEFAULT_L2_REFERENCE_HEIGHT: u64 = 4_224_900;
pub const DEFAULT_MIN_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_REORG_WINDOW_BLOCKS: u64 = 6;
pub const DEFAULT_MIN_WATCHER_WEIGHT: u64 = 5;
pub const DEFAULT_MAX_BINDINGS: usize = 64;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-deposit-lock-live-handler-binding-runtime";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingStatus {
    Bound,
    Pending,
    Rejected,
}

impl BindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::Pending => "pending",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandlerBindingGap {
    None,
    WatcherAdapter,
    ConfirmationReorg,
    DepositAddressClaim,
    WatcherQuorum,
    BridgeCustodyPolicy,
}

impl HandlerBindingGap {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::WatcherAdapter => "watcher_adapter",
            Self::ConfirmationReorg => "confirmation_reorg",
            Self::DepositAddressClaim => "deposit_address_claim",
            Self::WatcherQuorum => "watcher_quorum",
            Self::BridgeCustodyPolicy => "bridge_custody_policy",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub handler_binding_suite: String,
    pub live_input_suite: String,
    pub monero_network: String,
    pub l2_network: String,
    pub base_monero_height: u64,
    pub l2_reference_height: u64,
    pub min_confirmations: u64,
    pub reorg_window_blocks: u64,
    pub min_watcher_weight: u64,
    pub require_watcher_adapter_observation: bool,
    pub require_confirmation_reorg_observation: bool,
    pub require_deposit_address_claim: bool,
    pub require_watcher_quorum: bool,
    pub require_bridge_custody_policy: bool,
    pub fail_closed: bool,
    pub production_release_allowed: bool,
    pub max_bindings: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            handler_binding_suite: HANDLER_BINDING_SUITE.to_string(),
            live_input_suite: LIVE_INPUT_SUITE.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            base_monero_height: DEFAULT_BASE_MONERO_HEIGHT,
            l2_reference_height: DEFAULT_L2_REFERENCE_HEIGHT,
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            reorg_window_blocks: DEFAULT_REORG_WINDOW_BLOCKS,
            min_watcher_weight: DEFAULT_MIN_WATCHER_WEIGHT,
            require_watcher_adapter_observation: true,
            require_confirmation_reorg_observation: true,
            require_deposit_address_claim: true,
            require_watcher_quorum: true,
            require_bridge_custody_policy: true,
            fail_closed: true,
            production_release_allowed: false,
            max_bindings: DEFAULT_MAX_BINDINGS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "handler_binding_suite": self.handler_binding_suite,
            "live_input_suite": self.live_input_suite,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "base_monero_height": self.base_monero_height,
            "l2_reference_height": self.l2_reference_height,
            "min_confirmations": self.min_confirmations,
            "reorg_window_blocks": self.reorg_window_blocks,
            "min_watcher_weight": self.min_watcher_weight,
            "require_watcher_adapter_observation": self.require_watcher_adapter_observation,
            "require_confirmation_reorg_observation": self.require_confirmation_reorg_observation,
            "require_deposit_address_claim": self.require_deposit_address_claim,
            "require_watcher_quorum": self.require_watcher_quorum,
            "require_bridge_custody_policy": self.require_bridge_custody_policy,
            "fail_closed": self.fail_closed,
            "production_release_allowed": self.production_release_allowed,
            "max_bindings": self.max_bindings,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveInputRecord {
    pub input_id: String,
    pub observation_id: String,
    pub user_escape_package_id: String,
    pub lock_txid: String,
    pub lock_output_index: u64,
    pub deposit_address_commitment: String,
    pub amount_commitment: String,
    pub live_observation_root: String,
    pub harness_input_root: String,
}

impl LiveInputRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "input_id": self.input_id,
            "observation_id": self.observation_id,
            "user_escape_package_id": self.user_escape_package_id,
            "lock_txid": self.lock_txid,
            "lock_output_index": self.lock_output_index,
            "deposit_address_commitment": self.deposit_address_commitment,
            "amount_commitment": self.amount_commitment,
            "live_observation_root": self.live_observation_root,
            "harness_input_root": self.harness_input_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HandlerObservation {
    pub handler_id: String,
    pub handler_kind: String,
    pub input_id: String,
    pub observed_root: String,
    pub subject_root: String,
    pub handler_sequence: u64,
    pub observed_monero_height: u64,
    pub observed_l2_height: u64,
    pub accepted: bool,
    pub handler_root: String,
}

impl HandlerObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "handler_id": self.handler_id,
            "handler_kind": self.handler_kind,
            "input_id": self.input_id,
            "observed_root": self.observed_root,
            "subject_root": self.subject_root,
            "handler_sequence": self.handler_sequence,
            "observed_monero_height": self.observed_monero_height,
            "observed_l2_height": self.observed_l2_height,
            "accepted": self.accepted,
            "handler_root": self.handler_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HandlerBindingRecord {
    pub binding_id: String,
    pub status: BindingStatus,
    pub gap: HandlerBindingGap,
    pub input: LiveInputRecord,
    pub watcher_adapter: HandlerObservation,
    pub confirmation_reorg: HandlerObservation,
    pub deposit_address_claim: HandlerObservation,
    pub watcher_quorum: HandlerObservation,
    pub bridge_custody_policy: HandlerObservation,
    pub handler_set_root: String,
    pub binding_root: String,
}

impl HandlerBindingRecord {
    pub fn new(config: &Config, input: LiveInputRecord, intended_gap: HandlerBindingGap) -> Self {
        let watcher_adapter = handler_observation(
            config,
            &input,
            "monero_watcher_adapter_output",
            0,
            intended_gap != HandlerBindingGap::WatcherAdapter,
        );
        let confirmation_reorg = handler_observation(
            config,
            &input,
            "confirmation_reorg_handler",
            1,
            intended_gap != HandlerBindingGap::ConfirmationReorg,
        );
        let deposit_address_claim = handler_observation(
            config,
            &input,
            "deposit_address_claim_handler",
            2,
            intended_gap != HandlerBindingGap::DepositAddressClaim,
        );
        let watcher_quorum = handler_observation(
            config,
            &input,
            "watcher_quorum_handler",
            3,
            intended_gap != HandlerBindingGap::WatcherQuorum,
        );
        let bridge_custody_policy = handler_observation(
            config,
            &input,
            "bridge_custody_policy_handler",
            4,
            intended_gap != HandlerBindingGap::BridgeCustodyPolicy,
        );
        let gap = binding_gap(
            config,
            &watcher_adapter,
            &confirmation_reorg,
            &deposit_address_claim,
            &watcher_quorum,
            &bridge_custody_policy,
        );
        let status = binding_status(config, gap);
        let handler_set_root = merkle_root(
            &format!("{DOMAIN}:handler-observations"),
            &handler_records(
                &watcher_adapter,
                &confirmation_reorg,
                &deposit_address_claim,
                &watcher_quorum,
                &bridge_custody_policy,
            ),
        );
        let binding_root = binding_root(status, gap, &input, &handler_set_root);
        let binding_id = domain_hash(
            &format!("{DOMAIN}:binding-id"),
            &[
                HashPart::Str(&input.input_id),
                HashPart::Str(&input.harness_input_root),
                HashPart::Str(&binding_root),
            ],
            16,
        );

        Self {
            binding_id,
            status,
            gap,
            input,
            watcher_adapter,
            confirmation_reorg,
            deposit_address_claim,
            watcher_quorum,
            bridge_custody_policy,
            handler_set_root,
            binding_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "status": self.status.as_str(),
            "gap": self.gap.as_str(),
            "input": self.input.public_record(),
            "watcher_adapter": self.watcher_adapter.public_record(),
            "confirmation_reorg": self.confirmation_reorg.public_record(),
            "deposit_address_claim": self.deposit_address_claim.public_record(),
            "watcher_quorum": self.watcher_quorum.public_record(),
            "bridge_custody_policy": self.bridge_custody_policy.public_record(),
            "handler_set_root": self.handler_set_root,
            "binding_root": self.binding_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub bindings: Vec<HandlerBindingRecord>,
    pub bound_binding_ids: Vec<String>,
    pub pending_binding_ids: Vec<String>,
    pub rejected_binding_ids: Vec<String>,
    pub handler_roots: BTreeMap<String, String>,
    pub devnet_data: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config, bindings: Vec<HandlerBindingRecord>) -> Result<Self> {
        if bindings.len() > config.max_bindings {
            return Err(format!(
                "handler binding count {} exceeds configured max {}",
                bindings.len(),
                config.max_bindings
            ));
        }

        let mut seen_inputs = BTreeMap::<String, String>::new();
        let mut bound_binding_ids = Vec::new();
        let mut pending_binding_ids = Vec::new();
        let mut rejected_binding_ids = Vec::new();
        let mut handler_roots = BTreeMap::new();

        for binding in &bindings {
            if let Some(existing) =
                seen_inputs.insert(binding.input.input_id.clone(), binding.binding_id.clone())
            {
                return Err(format!(
                    "duplicate handler binding input {} conflicts with {}",
                    binding.input.input_id, existing
                ));
            }

            match binding.status {
                BindingStatus::Bound => bound_binding_ids.push(binding.binding_id.clone()),
                BindingStatus::Pending => pending_binding_ids.push(binding.binding_id.clone()),
                BindingStatus::Rejected => rejected_binding_ids.push(binding.binding_id.clone()),
            }
            handler_roots.insert(
                format!("{}:watcher_adapter", binding.input.input_id),
                binding.watcher_adapter.handler_root.clone(),
            );
            handler_roots.insert(
                format!("{}:confirmation_reorg", binding.input.input_id),
                binding.confirmation_reorg.handler_root.clone(),
            );
            handler_roots.insert(
                format!("{}:deposit_address_claim", binding.input.input_id),
                binding.deposit_address_claim.handler_root.clone(),
            );
            handler_roots.insert(
                format!("{}:watcher_quorum", binding.input.input_id),
                binding.watcher_quorum.handler_root.clone(),
            );
            handler_roots.insert(
                format!("{}:bridge_custody_policy", binding.input.input_id),
                binding.bridge_custody_policy.handler_root.clone(),
            );
        }

        Ok(Self {
            config,
            bindings,
            bound_binding_ids,
            pending_binding_ids,
            rejected_binding_ids,
            handler_roots,
            devnet_data: devnet_data(),
        })
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        let bindings = self
            .bindings
            .iter()
            .map(HandlerBindingRecord::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "bindings": bindings,
            "bound_binding_ids": self.bound_binding_ids,
            "pending_binding_ids": self.pending_binding_ids,
            "rejected_binding_ids": self.rejected_binding_ids,
            "handler_roots": self.handler_roots,
            "roots": {
                "config_root": self.config.state_root(),
                "binding_root": self.binding_set_root(),
                "bound_root": vector_root("BOUND", &self.bound_binding_ids),
                "pending_root": vector_root("PENDING", &self.pending_binding_ids),
                "rejected_root": vector_root("REJECTED", &self.rejected_binding_ids),
                "handler_root": map_root("handler_roots", &self.handler_roots),
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

    pub fn binding_set_root(&self) -> String {
        let records = self
            .bindings
            .iter()
            .map(HandlerBindingRecord::public_record)
            .collect::<Vec<_>>();
        merkle_root(&format!("{DOMAIN}:bindings"), &records)
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
    let bindings = devnet_bindings(&config);
    match State::new(config, bindings) {
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

pub fn devnet_bindings(config: &Config) -> Vec<HandlerBindingRecord> {
    [
        HandlerBindingGap::None,
        HandlerBindingGap::ConfirmationReorg,
        HandlerBindingGap::DepositAddressClaim,
        HandlerBindingGap::WatcherQuorum,
        HandlerBindingGap::BridgeCustodyPolicy,
    ]
    .iter()
    .enumerate()
    .map(|(index, gap)| {
        HandlerBindingRecord::new(config, live_input_record(config, index as u64), *gap)
    })
    .collect()
}

fn live_input_record(config: &Config, ordinal: u64) -> LiveInputRecord {
    let label = format!("user-escape-deposit-lock-live-handler-binding-{ordinal}");
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
    let observation_id = domain_hash(
        &format!("{DOMAIN}:observation-id"),
        &[
            HashPart::Str(&lock_txid),
            HashPart::Str(&live_observation_root),
        ],
        16,
    );
    let input_id = domain_hash(
        &format!("{DOMAIN}:input-id"),
        &[
            HashPart::Str(&observation_id),
            HashPart::Str(&harness_input_root),
        ],
        16,
    );

    LiveInputRecord {
        input_id,
        observation_id,
        user_escape_package_id,
        lock_txid,
        lock_output_index,
        deposit_address_commitment,
        amount_commitment,
        live_observation_root,
        harness_input_root,
    }
}

fn handler_observation(
    config: &Config,
    input: &LiveInputRecord,
    handler_kind: &str,
    handler_sequence: u64,
    accepted: bool,
) -> HandlerObservation {
    let observed_monero_height = config.base_monero_height + input.lock_output_index;
    let observed_l2_height = config.l2_reference_height + handler_sequence;
    let accepted_marker = bool_str(accepted);
    let subject_root = domain_hash(
        &format!("{DOMAIN}:handler-subject"),
        &[
            HashPart::Str(handler_kind),
            HashPart::Str(&input.input_id),
            HashPart::Str(&input.harness_input_root),
        ],
        32,
    );
    let observed_root = domain_hash(
        &format!("{DOMAIN}:handler-observed"),
        &[
            HashPart::Str(handler_kind),
            HashPart::Str(&input.live_observation_root),
            HashPart::Str(&subject_root),
            HashPart::Str(accepted_marker),
        ],
        32,
    );
    let handler_root = domain_hash(
        &format!("{DOMAIN}:handler-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(handler_kind),
            HashPart::Str(&input.input_id),
            HashPart::Str(&observed_root),
            HashPart::Str(&subject_root),
            HashPart::U64(handler_sequence),
            HashPart::U64(observed_monero_height),
            HashPart::U64(observed_l2_height),
            HashPart::Str(accepted_marker),
        ],
        32,
    );
    let handler_id = domain_hash(
        &format!("{DOMAIN}:handler-id"),
        &[
            HashPart::Str(handler_kind),
            HashPart::Str(&input.input_id),
            HashPart::Str(&handler_root),
        ],
        16,
    );

    HandlerObservation {
        handler_id,
        handler_kind: handler_kind.to_string(),
        input_id: input.input_id.clone(),
        observed_root,
        subject_root,
        handler_sequence,
        observed_monero_height,
        observed_l2_height,
        accepted,
        handler_root,
    }
}

fn binding_gap(
    config: &Config,
    watcher_adapter: &HandlerObservation,
    confirmation_reorg: &HandlerObservation,
    deposit_address_claim: &HandlerObservation,
    watcher_quorum: &HandlerObservation,
    bridge_custody_policy: &HandlerObservation,
) -> HandlerBindingGap {
    if config.require_watcher_adapter_observation && !watcher_adapter.accepted {
        HandlerBindingGap::WatcherAdapter
    } else if config.require_confirmation_reorg_observation && !confirmation_reorg.accepted {
        HandlerBindingGap::ConfirmationReorg
    } else if config.require_deposit_address_claim && !deposit_address_claim.accepted {
        HandlerBindingGap::DepositAddressClaim
    } else if config.require_watcher_quorum && !watcher_quorum.accepted {
        HandlerBindingGap::WatcherQuorum
    } else if config.require_bridge_custody_policy && !bridge_custody_policy.accepted {
        HandlerBindingGap::BridgeCustodyPolicy
    } else {
        HandlerBindingGap::None
    }
}

fn binding_status(config: &Config, gap: HandlerBindingGap) -> BindingStatus {
    match gap {
        HandlerBindingGap::None => BindingStatus::Bound,
        HandlerBindingGap::ConfirmationReorg => BindingStatus::Pending,
        HandlerBindingGap::WatcherAdapter
        | HandlerBindingGap::DepositAddressClaim
        | HandlerBindingGap::WatcherQuorum
        | HandlerBindingGap::BridgeCustodyPolicy
            if config.fail_closed =>
        {
            BindingStatus::Rejected
        }
        HandlerBindingGap::WatcherAdapter
        | HandlerBindingGap::DepositAddressClaim
        | HandlerBindingGap::WatcherQuorum
        | HandlerBindingGap::BridgeCustodyPolicy => BindingStatus::Pending,
    }
}

fn binding_root(
    status: BindingStatus,
    gap: HandlerBindingGap,
    input: &LiveInputRecord,
    handler_set_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:binding-root"),
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(gap.as_str()),
            HashPart::Str(&input.input_id),
            HashPart::Str(&input.user_escape_package_id),
            HashPart::Str(&input.harness_input_root),
            HashPart::Str(handler_set_root),
        ],
        32,
    )
}

fn handler_records(
    watcher_adapter: &HandlerObservation,
    confirmation_reorg: &HandlerObservation,
    deposit_address_claim: &HandlerObservation,
    watcher_quorum: &HandlerObservation,
    bridge_custody_policy: &HandlerObservation,
) -> Vec<Value> {
    vec![
        watcher_adapter.public_record(),
        confirmation_reorg.public_record(),
        deposit_address_claim.public_record(),
        watcher_quorum.public_record(),
        bridge_custody_policy.public_record(),
    ]
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
        "binding_lane".to_string(),
        json!({
            "input": "deposit_lock_live_input_record",
            "output": "handler_bound_live_input_record",
            "handlers": [
                "monero_watcher_adapter_output",
                "confirmation_reorg_handler",
                "deposit_address_claim_handler",
                "watcher_quorum_handler",
                "bridge_custody_policy_handler"
            ]
        }),
    );
    data.insert(
        "fail_closed_policy".to_string(),
        json!({
            "watcher_adapter_gap": "rejected",
            "confirmation_reorg_gap": "pending",
            "deposit_address_claim_gap": "rejected",
            "watcher_quorum_gap": "rejected",
            "bridge_custody_policy_gap": "rejected"
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
        bindings: Vec::new(),
        bound_binding_ids: Vec::new(),
        pending_binding_ids: Vec::new(),
        rejected_binding_ids: Vec::new(),
        handler_roots: BTreeMap::new(),
        devnet_data,
    }
}
