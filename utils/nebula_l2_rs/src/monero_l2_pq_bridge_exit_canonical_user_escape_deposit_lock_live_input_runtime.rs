use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeDepositLockLiveInputRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_DEPOSIT_LOCK_LIVE_INPUT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-deposit-lock-live-input-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_DEPOSIT_LOCK_LIVE_INPUT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const LIVE_INPUT_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-deposit-lock-live-input-v1";
pub const HARNESS_INPUT_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-harness-input-v1";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_BASE_MONERO_HEIGHT: u64 = 3_512_040;
pub const DEFAULT_L2_REFERENCE_HEIGHT: u64 = 4_224_900;
pub const DEFAULT_MIN_CONFIRMATIONS: u64 = 18;
pub const DEFAULT_REORG_WINDOW_BLOCKS: u64 = 6;
pub const DEFAULT_MIN_WATCHER_WEIGHT: u64 = 5;
pub const DEFAULT_MAX_OBSERVATIONS: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveInputStatus {
    Canonical,
    Pending,
    Rejected,
}

impl LiveInputStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::Pending => "pending",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveInputGap {
    None,
    ConfirmationDepth,
    ReorgWindow,
    WatcherQuorum,
    WalletClaimBinding,
    DuplicateLock,
}

impl LiveInputGap {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ConfirmationDepth => "confirmation_depth",
            Self::ReorgWindow => "reorg_window",
            Self::WatcherQuorum => "watcher_quorum",
            Self::WalletClaimBinding => "wallet_claim_binding",
            Self::DuplicateLock => "duplicate_lock",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub live_input_suite: String,
    pub harness_input_suite: String,
    pub monero_network: String,
    pub l2_network: String,
    pub base_monero_height: u64,
    pub l2_reference_height: u64,
    pub min_confirmations: u64,
    pub reorg_window_blocks: u64,
    pub min_watcher_weight: u64,
    pub require_wallet_claim_binding: bool,
    pub fail_closed: bool,
    pub production_release_allowed: bool,
    pub max_observations: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            live_input_suite: LIVE_INPUT_SUITE.to_string(),
            harness_input_suite: HARNESS_INPUT_SUITE.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            base_monero_height: DEFAULT_BASE_MONERO_HEIGHT,
            l2_reference_height: DEFAULT_L2_REFERENCE_HEIGHT,
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            reorg_window_blocks: DEFAULT_REORG_WINDOW_BLOCKS,
            min_watcher_weight: DEFAULT_MIN_WATCHER_WEIGHT,
            require_wallet_claim_binding: true,
            fail_closed: true,
            production_release_allowed: false,
            max_observations: DEFAULT_MAX_OBSERVATIONS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "live_input_suite": self.live_input_suite,
            "harness_input_suite": self.harness_input_suite,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "base_monero_height": self.base_monero_height,
            "l2_reference_height": self.l2_reference_height,
            "min_confirmations": self.min_confirmations,
            "reorg_window_blocks": self.reorg_window_blocks,
            "min_watcher_weight": self.min_watcher_weight,
            "require_wallet_claim_binding": self.require_wallet_claim_binding,
            "fail_closed": self.fail_closed,
            "production_release_allowed": self.production_release_allowed,
            "max_observations": self.max_observations,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiveDepositLockObservation {
    pub observation_id: String,
    pub feed_id: String,
    pub feed_sequence: u64,
    pub lock_txid: String,
    pub lock_output_index: u64,
    pub deposit_address_commitment: String,
    pub amount_commitment: String,
    pub wallet_claim_binding_root: String,
    pub watcher_quorum_root: String,
    pub block_hash_root: String,
    pub lock_height: u64,
    pub observed_monero_height: u64,
    pub observed_confirmations: u64,
    pub watcher_weight: u64,
    pub observation_root: String,
}

impl LiveDepositLockObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "feed_id": self.feed_id,
            "feed_sequence": self.feed_sequence,
            "lock_txid": self.lock_txid,
            "lock_output_index": self.lock_output_index,
            "deposit_address_commitment": self.deposit_address_commitment,
            "amount_commitment": self.amount_commitment,
            "wallet_claim_binding_root": self.wallet_claim_binding_root,
            "watcher_quorum_root": self.watcher_quorum_root,
            "block_hash_root": self.block_hash_root,
            "lock_height": self.lock_height,
            "observed_monero_height": self.observed_monero_height,
            "observed_confirmations": self.observed_confirmations,
            "watcher_weight": self.watcher_weight,
            "observation_root": self.observation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HarnessInputRecord {
    pub input_id: String,
    pub status: LiveInputStatus,
    pub gap: LiveInputGap,
    pub observation_id: String,
    pub user_escape_package_id: String,
    pub monero_lock_tx_commitment: String,
    pub deposit_address_commitment: String,
    pub amount_commitment: String,
    pub confirmation_root: String,
    pub reorg_window_root: String,
    pub watcher_quorum_root: String,
    pub wallet_claim_binding_root: String,
    pub live_observation_root: String,
    pub harness_input_root: String,
}

impl HarnessInputRecord {
    pub fn from_observation(config: &Config, observation: &LiveDepositLockObservation) -> Self {
        let gap = live_input_gap(config, observation);
        let status = live_input_status(gap);
        let user_escape_package_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-LIVE-INPUT-PACKAGE",
            &[
                HashPart::Str(&observation.lock_txid),
                HashPart::U64(observation.lock_output_index),
                HashPart::Str(&observation.wallet_claim_binding_root),
            ],
            16,
        );
        let monero_lock_tx_commitment = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-LIVE-INPUT-TX",
            &[
                HashPart::Str(&observation.lock_txid),
                HashPart::U64(observation.lock_output_index),
                HashPart::Str(&observation.block_hash_root),
            ],
            32,
        );
        let confirmation_root = confirmation_root(config, observation);
        let reorg_window_root = reorg_window_root(config, observation, gap);
        let harness_input_root = harness_input_root(
            status,
            gap,
            &user_escape_package_id,
            &monero_lock_tx_commitment,
            &observation.deposit_address_commitment,
            &observation.amount_commitment,
            &confirmation_root,
            &reorg_window_root,
            &observation.watcher_quorum_root,
            &observation.wallet_claim_binding_root,
            &observation.observation_root,
        );
        let input_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-LIVE-INPUT-ID",
            &[
                HashPart::Str(&observation.observation_id),
                HashPart::Str(&harness_input_root),
            ],
            16,
        );
        Self {
            input_id,
            status,
            gap,
            observation_id: observation.observation_id.clone(),
            user_escape_package_id,
            monero_lock_tx_commitment,
            deposit_address_commitment: observation.deposit_address_commitment.clone(),
            amount_commitment: observation.amount_commitment.clone(),
            confirmation_root,
            reorg_window_root,
            watcher_quorum_root: observation.watcher_quorum_root.clone(),
            wallet_claim_binding_root: observation.wallet_claim_binding_root.clone(),
            live_observation_root: observation.observation_root.clone(),
            harness_input_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "input_id": self.input_id,
            "status": self.status.as_str(),
            "gap": self.gap.as_str(),
            "observation_id": self.observation_id,
            "user_escape_package_id": self.user_escape_package_id,
            "monero_lock_tx_commitment": self.monero_lock_tx_commitment,
            "deposit_address_commitment": self.deposit_address_commitment,
            "amount_commitment": self.amount_commitment,
            "confirmation_root": self.confirmation_root,
            "reorg_window_root": self.reorg_window_root,
            "watcher_quorum_root": self.watcher_quorum_root,
            "wallet_claim_binding_root": self.wallet_claim_binding_root,
            "live_observation_root": self.live_observation_root,
            "harness_input_root": self.harness_input_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub observations: Vec<LiveDepositLockObservation>,
    pub harness_inputs: Vec<HarnessInputRecord>,
    pub canonical_input_ids: Vec<String>,
    pub pending_input_ids: Vec<String>,
    pub rejected_input_ids: Vec<String>,
    pub devnet_data: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config, observations: Vec<LiveDepositLockObservation>) -> Result<Self> {
        if observations.len() > config.max_observations {
            return Err(format!(
                "observation count {} exceeds configured max {}",
                observations.len(),
                config.max_observations
            ));
        }

        let mut seen_locks = BTreeMap::<String, String>::new();
        let mut harness_inputs = Vec::new();
        let mut canonical_input_ids = Vec::new();
        let mut pending_input_ids = Vec::new();
        let mut rejected_input_ids = Vec::new();

        for observation in &observations {
            let lock_key = format!(
                "{}:{}",
                observation.lock_txid, observation.lock_output_index
            );
            if let Some(existing) = seen_locks.insert(lock_key, observation.observation_id.clone())
            {
                return Err(format!(
                    "duplicate live deposit lock observation {} conflicts with {}",
                    observation.observation_id, existing
                ));
            }

            let input = HarnessInputRecord::from_observation(&config, observation);
            match input.status {
                LiveInputStatus::Canonical => canonical_input_ids.push(input.input_id.clone()),
                LiveInputStatus::Pending => pending_input_ids.push(input.input_id.clone()),
                LiveInputStatus::Rejected => rejected_input_ids.push(input.input_id.clone()),
            }
            harness_inputs.push(input);
        }

        Ok(Self {
            config,
            observations,
            harness_inputs,
            canonical_input_ids,
            pending_input_ids,
            rejected_input_ids,
            devnet_data: devnet_data(),
        })
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn public_record(&self) -> Value {
        let observations = self
            .observations
            .iter()
            .map(LiveDepositLockObservation::public_record)
            .collect::<Vec<_>>();
        let harness_inputs = self
            .harness_inputs
            .iter()
            .map(HarnessInputRecord::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "observations": observations,
            "harness_inputs": harness_inputs,
            "canonical_input_ids": self.canonical_input_ids,
            "pending_input_ids": self.pending_input_ids,
            "rejected_input_ids": self.rejected_input_ids,
            "roots": {
                "config_root": self.config.state_root(),
                "observation_root": self.observation_root(),
                "harness_input_root": self.harness_input_set_root(),
                "canonical_root": vector_root("CANONICAL", &self.canonical_input_ids),
                "pending_root": vector_root("PENDING", &self.pending_input_ids),
                "rejected_root": vector_root("REJECTED", &self.rejected_input_ids),
                "devnet_data_root": self.devnet_data_root(),
            },
            "devnet_data": self.devnet_data,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-LIVE-INPUT-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn observation_root(&self) -> String {
        let records = self
            .observations
            .iter()
            .map(LiveDepositLockObservation::public_record)
            .collect::<Vec<_>>();
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-LIVE-OBSERVATIONS",
            &records,
        )
    }

    pub fn harness_input_set_root(&self) -> String {
        let records = self
            .harness_inputs
            .iter()
            .map(HarnessInputRecord::public_record)
            .collect::<Vec<_>>();
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-LIVE-HARNESS-INPUTS",
            &records,
        )
    }

    pub fn devnet_data_root(&self) -> String {
        let records = self
            .devnet_data
            .iter()
            .map(|(key, value)| json!({ "key": key, "value": value }))
            .collect::<Vec<_>>();
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-LIVE-INPUT-DEVNET-DATA",
            &records,
        )
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let observations = devnet_observations(&config);
    match State::new(config, observations) {
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

pub fn devnet_observations(config: &Config) -> Vec<LiveDepositLockObservation> {
    vec![
        build_observation(config, 0, LiveInputGap::None),
        build_observation(config, 1, LiveInputGap::ConfirmationDepth),
        build_observation(config, 2, LiveInputGap::WatcherQuorum),
        build_observation(config, 3, LiveInputGap::WalletClaimBinding),
    ]
}

fn build_observation(
    config: &Config,
    ordinal: u64,
    intended_gap: LiveInputGap,
) -> LiveDepositLockObservation {
    let label = format!("user-escape-deposit-lock-live-input-{ordinal}");
    let observed_confirmations = match intended_gap {
        LiveInputGap::ConfirmationDepth => config.min_confirmations.saturating_sub(4),
        _ => config.min_confirmations + ordinal,
    };
    let lock_height = config
        .base_monero_height
        .saturating_sub(observed_confirmations);
    let observed_monero_height = config.base_monero_height + ordinal;
    let watcher_weight = match intended_gap {
        LiveInputGap::WatcherQuorum => config.min_watcher_weight.saturating_sub(2),
        _ => config.min_watcher_weight + 1,
    };
    let wallet_claim_binding_root = match intended_gap {
        LiveInputGap::WalletClaimBinding => String::new(),
        _ => commitment("WALLET-CLAIM-BINDING", &label, ordinal),
    };
    let lock_txid = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-LIVE-TXID",
        &[HashPart::Str(&label), HashPart::U64(ordinal)],
        32,
    );
    let deposit_address_commitment = commitment("DEPOSIT-ADDRESS", &label, ordinal);
    let amount_commitment = commitment("AMOUNT", &label, ordinal);
    let watcher_quorum_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-LIVE-WATCHER-QUORUM",
        &[
            HashPart::Str(&label),
            HashPart::U64(watcher_weight),
            HashPart::U64(config.min_watcher_weight),
        ],
        32,
    );
    let block_hash_root = commitment("BLOCK-HASH", &label, ordinal);
    let observation_root = live_observation_root(
        &lock_txid,
        ordinal,
        &deposit_address_commitment,
        &amount_commitment,
        &wallet_claim_binding_root,
        &watcher_quorum_root,
        lock_height,
        observed_monero_height,
        watcher_weight,
    );
    let observation_id = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-LIVE-OBSERVATION-ID",
        &[HashPart::Str(&lock_txid), HashPart::Str(&observation_root)],
        16,
    );

    LiveDepositLockObservation {
        observation_id,
        feed_id: "devnet-monero-deposit-lock-live-input-feed".to_string(),
        feed_sequence: ordinal + 1,
        lock_txid,
        lock_output_index: ordinal,
        deposit_address_commitment,
        amount_commitment,
        wallet_claim_binding_root,
        watcher_quorum_root,
        block_hash_root,
        lock_height,
        observed_monero_height,
        observed_confirmations,
        watcher_weight,
        observation_root,
    }
}

fn live_input_gap(config: &Config, observation: &LiveDepositLockObservation) -> LiveInputGap {
    if observation.observed_confirmations < config.min_confirmations {
        LiveInputGap::ConfirmationDepth
    } else if observation.observed_monero_height
        < observation.lock_height + config.reorg_window_blocks
    {
        LiveInputGap::ReorgWindow
    } else if observation.watcher_weight < config.min_watcher_weight {
        LiveInputGap::WatcherQuorum
    } else if config.require_wallet_claim_binding
        && observation.wallet_claim_binding_root.is_empty()
    {
        LiveInputGap::WalletClaimBinding
    } else {
        LiveInputGap::None
    }
}

fn live_input_status(gap: LiveInputGap) -> LiveInputStatus {
    match gap {
        LiveInputGap::None => LiveInputStatus::Canonical,
        LiveInputGap::ConfirmationDepth | LiveInputGap::ReorgWindow => LiveInputStatus::Pending,
        LiveInputGap::WatcherQuorum
        | LiveInputGap::WalletClaimBinding
        | LiveInputGap::DuplicateLock => LiveInputStatus::Rejected,
    }
}

fn confirmation_root(config: &Config, observation: &LiveDepositLockObservation) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-LIVE-CONFIRMATION",
        &[
            HashPart::Str(&observation.lock_txid),
            HashPart::U64(observation.lock_height),
            HashPart::U64(observation.observed_monero_height),
            HashPart::U64(observation.observed_confirmations),
            HashPart::U64(config.min_confirmations),
        ],
        32,
    )
}

fn reorg_window_root(
    config: &Config,
    observation: &LiveDepositLockObservation,
    gap: LiveInputGap,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-LIVE-REORG-WINDOW",
        &[
            HashPart::Str(&observation.block_hash_root),
            HashPart::U64(config.reorg_window_blocks),
            HashPart::Str(gap.as_str()),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn live_observation_root(
    lock_txid: &str,
    lock_output_index: u64,
    deposit_address_commitment: &str,
    amount_commitment: &str,
    wallet_claim_binding_root: &str,
    watcher_quorum_root: &str,
    lock_height: u64,
    observed_monero_height: u64,
    watcher_weight: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-LIVE-OBSERVATION",
        &[
            HashPart::Str(lock_txid),
            HashPart::U64(lock_output_index),
            HashPart::Str(deposit_address_commitment),
            HashPart::Str(amount_commitment),
            HashPart::Str(wallet_claim_binding_root),
            HashPart::Str(watcher_quorum_root),
            HashPart::U64(lock_height),
            HashPart::U64(observed_monero_height),
            HashPart::U64(watcher_weight),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn harness_input_root(
    status: LiveInputStatus,
    gap: LiveInputGap,
    user_escape_package_id: &str,
    monero_lock_tx_commitment: &str,
    deposit_address_commitment: &str,
    amount_commitment: &str,
    confirmation_root: &str,
    reorg_window_root: &str,
    watcher_quorum_root: &str,
    wallet_claim_binding_root: &str,
    live_observation_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-LIVE-HARNESS-INPUT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(gap.as_str()),
            HashPart::Str(user_escape_package_id),
            HashPart::Str(monero_lock_tx_commitment),
            HashPart::Str(deposit_address_commitment),
            HashPart::Str(amount_commitment),
            HashPart::Str(confirmation_root),
            HashPart::Str(reorg_window_root),
            HashPart::Str(watcher_quorum_root),
            HashPart::Str(wallet_claim_binding_root),
            HashPart::Str(live_observation_root),
        ],
        32,
    )
}

fn commitment(domain: &str, label: &str, ordinal: u64) -> String {
    domain_hash(
        &format!("MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-LIVE-{domain}"),
        &[HashPart::Str(label), HashPart::U64(ordinal)],
        32,
    )
}

fn vector_root(label: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "label": label, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-LIVE-INPUT-{label}"),
        &leaves,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCK-LIVE-INPUT-RECORD",
        &[HashPart::Str(label), HashPart::Json(record)],
        32,
    )
}

fn devnet_data() -> BTreeMap<String, Value> {
    let mut data = BTreeMap::new();
    data.insert(
        "live_input_lane".to_string(),
        json!({
            "source": "real_monero_deposit_lock_observations",
            "output": "canonical_user_escape_harness_input_records",
            "raw_values": "redacted_or_committed",
            "dedupe_key": "lock_txid_plus_output_index"
        }),
    );
    data.insert(
        "fail_closed_policy".to_string(),
        json!({
            "confirmation_depth_gap": "pending",
            "reorg_window_gap": "pending",
            "watcher_quorum_gap": "rejected",
            "wallet_claim_binding_gap": "rejected",
            "duplicate_lock_gap": "rejected"
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
                "MONERO-DEVNET-USER-ESCAPE-DEPOSIT-LOCK-LIVE-INPUT-FALLBACK",
                &[HashPart::Str(&reason)],
                32
            )
        }),
    );
    State {
        config,
        observations: Vec::new(),
        harness_inputs: Vec::new(),
        canonical_input_ids: Vec::new(),
        pending_input_ids: Vec::new(),
        rejected_input_ids: Vec::new(),
        devnet_data,
    }
}
