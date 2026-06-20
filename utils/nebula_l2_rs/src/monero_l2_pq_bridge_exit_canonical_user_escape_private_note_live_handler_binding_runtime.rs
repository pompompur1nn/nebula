use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapePrivateNoteLiveHandlerBindingRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_PRIVATE_NOTE_LIVE_HANDLER_BINDING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-private-note-live-handler-binding-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_PRIVATE_NOTE_LIVE_HANDLER_BINDING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const HANDLER_BINDING_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-private-note-live-handler-binding-v1";
pub const PRIVACY_BOUNDARY: &str = "handler-observation-roots-only";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 744_128;
pub const DEFAULT_INPUT_BATCH_SIZE: u64 = 3;
pub const DEFAULT_MAX_SCAN_HINT_BITS: u16 = 18;
pub const DEFAULT_METADATA_BUDGET_UNITS: u64 = 5;
pub const DEFAULT_HANDLER_COUNT: u64 = 5;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub handler_binding_suite: String,
    pub privacy_boundary: String,
    pub devnet_height: u64,
    pub input_batch_size: u64,
    pub max_scan_hint_bits: u16,
    pub metadata_budget_units: u64,
    pub handler_count: u64,
    pub production_release_allowed: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            handler_binding_suite: HANDLER_BINDING_SUITE.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            devnet_height: DEFAULT_DEVNET_HEIGHT,
            input_batch_size: DEFAULT_INPUT_BATCH_SIZE,
            max_scan_hint_bits: DEFAULT_MAX_SCAN_HINT_BITS,
            metadata_budget_units: DEFAULT_METADATA_BUDGET_UNITS,
            handler_count: DEFAULT_HANDLER_COUNT,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "handler_binding_suite": self.handler_binding_suite,
            "privacy_boundary": self.privacy_boundary,
            "devnet_height": self.devnet_height,
            "input_batch_size": self.input_batch_size,
            "max_scan_hint_bits": self.max_scan_hint_bits,
            "metadata_budget_units": self.metadata_budget_units,
            "handler_count": self.handler_count,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiveInputBinding {
    pub binding_id: String,
    pub live_input_lane_id: String,
    pub note_state_root: String,
    pub nullifier_state_root: String,
    pub transfer_state_root: String,
    pub canonical_input_root: String,
    pub live_input_record_root: String,
    pub binding_root: String,
}

impl LiveInputBinding {
    pub fn devnet(config: &Config) -> Self {
        let live_input_lane_id = "devnet-user-escape-private-note-live-input-0001".to_string();
        let binding_id = "devnet-user-escape-private-note-live-handler-binding-0001".to_string();
        let note_state_root = private_state_root(
            "note_state_root",
            &live_input_lane_id,
            &[
                "encrypted_note_commitment_frontier",
                "membership_witness_anchor",
                "note_metadata_redacted",
            ],
        );
        let nullifier_state_root = private_state_root(
            "nullifier_state_root",
            &live_input_lane_id,
            &[
                "nullifier_set_frontier",
                "key_image_separation_anchor",
                "linkage_metadata_redacted",
            ],
        );
        let transfer_state_root = private_state_root(
            "transfer_state_root",
            &live_input_lane_id,
            &[
                "balanced_transfer_action_anchor",
                "escape_receipt_binding_anchor",
                "amount_and_route_metadata_redacted",
            ],
        );
        let canonical_input_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-INPUT-CANONICAL-INPUT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.protocol_version),
                HashPart::Str(&live_input_lane_id),
                HashPart::Str(&note_state_root),
                HashPart::Str(&nullifier_state_root),
                HashPart::Str(&transfer_state_root),
                HashPart::U64(config.devnet_height),
                HashPart::U64(config.input_batch_size),
            ],
            32,
        );
        let live_input_record_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-INPUT-LANE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&live_input_lane_id),
                HashPart::Str(&note_state_root),
                HashPart::Str(&nullifier_state_root),
                HashPart::Str(&transfer_state_root),
                HashPart::Str(&canonical_input_root),
                HashPart::Str("root-only-no-note-metadata"),
            ],
            32,
        );
        let binding_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-HANDLER-BINDING-INPUT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.protocol_version),
                HashPart::Str(&binding_id),
                HashPart::Str(&live_input_lane_id),
                HashPart::Str(&live_input_record_root),
                HashPart::Str(PRIVACY_BOUNDARY),
            ],
            32,
        );

        Self {
            binding_id,
            live_input_lane_id,
            note_state_root,
            nullifier_state_root,
            transfer_state_root,
            canonical_input_root,
            live_input_record_root,
            binding_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "live_input_lane_id": self.live_input_lane_id,
            "note_state_root": self.note_state_root,
            "nullifier_state_root": self.nullifier_state_root,
            "transfer_state_root": self.transfer_state_root,
            "canonical_input_root": self.canonical_input_root,
            "live_input_record_root": self.live_input_record_root,
            "binding_root": self.binding_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandlerObservation {
    pub handler_id: String,
    pub handler_kind: String,
    pub input_root: String,
    pub observation_root: String,
    pub receipt_root: String,
    pub privacy_guard_root: String,
    pub binding_root: String,
}

impl HandlerObservation {
    pub fn encrypted_note_state_reader(binding: &LiveInputBinding) -> Self {
        Self::bind(
            "encrypted_note_state_reader",
            "devnet-encrypted-note-state-reader",
            &binding.note_state_root,
            &[
                "ciphertext_commitment_frontier_observed",
                "membership_witness_anchor_observed",
                "note_payload_not_decrypted",
            ],
        )
    }

    pub fn nullifier_key_image_separation(binding: &LiveInputBinding) -> Self {
        Self::bind(
            "nullifier_key_image_separation_handler",
            "devnet-nullifier-key-image-separation-handler",
            &binding.nullifier_state_root,
            &[
                "nullifier_frontier_observed",
                "key_image_anchor_separated",
                "spend_linkage_not_exported",
            ],
        )
    }

    pub fn private_transfer_receipt(binding: &LiveInputBinding) -> Self {
        Self::bind(
            "private_transfer_receipt_handler",
            "devnet-private-transfer-receipt-handler",
            &binding.transfer_state_root,
            &[
                "action_receipt_commitment_observed",
                "encrypted_receipt_shards_bound",
                "route_metadata_not_exported",
            ],
        )
    }

    pub fn metadata_budget(config: &Config, binding: &LiveInputBinding) -> Self {
        let budget_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-HANDLER-BINDING-METADATA-BUDGET",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&binding.binding_id),
                HashPart::U64(config.metadata_budget_units),
                HashPart::Str(&binding.live_input_record_root),
            ],
            32,
        );

        Self::bind(
            "metadata_budget_handler",
            "devnet-private-note-metadata-budget-handler",
            &budget_root,
            &[
                "public_fields_counted",
                "private_note_fields_redacted",
                "budget_exhaustion_prevented",
            ],
        )
    }

    pub fn wallet_scan_hint(config: &Config, binding: &LiveInputBinding) -> Self {
        let scan_hint_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-HANDLER-BINDING-SCAN-HINT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&binding.binding_id),
                HashPart::U64(config.max_scan_hint_bits as u64),
                HashPart::Str(&binding.note_state_root),
                HashPart::Str(&binding.transfer_state_root),
            ],
            32,
        );

        Self::bind(
            "wallet_scan_hint_handler",
            "devnet-wallet-scan-hint-handler",
            &scan_hint_root,
            &[
                "view_tag_bucket_observed",
                "locator_hint_padded",
                "recipient_identity_not_exported",
            ],
        )
    }

    fn bind(handler_kind: &str, handler_id: &str, input_root: &str, observations: &[&str]) -> Self {
        let observation_root = observation_root(handler_kind, handler_id, observations);
        let receipt_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-HANDLER-BINDING-RECEIPT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(handler_kind),
                HashPart::Str(handler_id),
                HashPart::Str(input_root),
                HashPart::Str(&observation_root),
            ],
            32,
        );
        let privacy_guard_root = observation_root(
            handler_kind,
            handler_id,
            &[
                "root_only_record_exported",
                "handler_local_metadata_redacted",
                "public_receipt_contains_no_secret_fields",
            ],
        );
        let binding_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-HANDLER-BINDING-HANDLER",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(handler_kind),
                HashPart::Str(handler_id),
                HashPart::Str(input_root),
                HashPart::Str(&observation_root),
                HashPart::Str(&receipt_root),
                HashPart::Str(&privacy_guard_root),
            ],
            32,
        );

        Self {
            handler_id: handler_id.to_string(),
            handler_kind: handler_kind.to_string(),
            input_root: input_root.to_string(),
            observation_root,
            receipt_root,
            privacy_guard_root,
            binding_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "handler_id": self.handler_id,
            "handler_kind": self.handler_kind,
            "input_root": self.input_root,
            "observation_root": self.observation_root,
            "receipt_root": self.receipt_root,
            "privacy_guard_root": self.privacy_guard_root,
            "binding_root": self.binding_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandlerBindingSet {
    pub set_id: String,
    pub live_input: LiveInputBinding,
    pub handlers: Vec<HandlerObservation>,
    pub handler_binding_root: String,
    pub observation_receipt_root: String,
    pub binding_set_root: String,
}

impl HandlerBindingSet {
    pub fn devnet(config: &Config) -> Self {
        let set_id = "devnet-private-note-live-handler-binding-set-0001".to_string();
        let live_input = LiveInputBinding::devnet(config);
        let handlers = vec![
            HandlerObservation::encrypted_note_state_reader(&live_input),
            HandlerObservation::nullifier_key_image_separation(&live_input),
            HandlerObservation::private_transfer_receipt(&live_input),
            HandlerObservation::metadata_budget(config, &live_input),
            HandlerObservation::wallet_scan_hint(config, &live_input),
        ];
        let handler_binding_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-HANDLER-BINDING-HANDLERS",
            handlers
                .iter()
                .map(|handler| Value::String(handler.binding_root.clone()))
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let observation_receipt_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-HANDLER-BINDING-RECEIPTS",
            handlers
                .iter()
                .map(|handler| Value::String(handler.receipt_root.clone()))
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let binding_set_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-HANDLER-BINDING-SET",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.protocol_version),
                HashPart::Str(&set_id),
                HashPart::Str(&live_input.binding_root),
                HashPart::Str(&handler_binding_root),
                HashPart::Str(&observation_receipt_root),
                HashPart::U64(handlers.len() as u64),
                HashPart::Str(PRIVACY_BOUNDARY),
            ],
            32,
        );

        Self {
            set_id,
            live_input,
            handlers,
            handler_binding_root,
            observation_receipt_root,
            binding_set_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "set_id": self.set_id,
            "live_input": self.live_input.public_record(),
            "handlers": self.handlers.iter().map(HandlerObservation::public_record).collect::<Vec<_>>(),
            "handler_binding_root": self.handler_binding_root,
            "observation_receipt_root": self.observation_receipt_root,
            "binding_set_root": self.binding_set_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub binding_set: HandlerBindingSet,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let binding_set = HandlerBindingSet::devnet(&config);
        let state_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-HANDLER-BINDING-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.state_root()),
                HashPart::Str(&binding_set.binding_set_root),
            ],
            32,
        );

        Self {
            config,
            binding_set,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "binding_set": self.binding_set.public_record(),
            "state_root": self.state_root,
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

fn private_state_root(label: &str, lane_id: &str, leaves: &[&str]) -> String {
    let leaf_roots = leaves
        .iter()
        .enumerate()
        .map(|(index, leaf)| {
            domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-INPUT-LEAF",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(label),
                    HashPart::Str(lane_id),
                    HashPart::U64(index as u64),
                    HashPart::Str(leaf),
                ],
                32,
            )
        })
        .map(Value::String)
        .collect::<Vec<_>>();

    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-INPUT-ROOT",
        leaf_roots.as_slice(),
    )
}

fn observation_root(handler_kind: &str, handler_id: &str, observations: &[&str]) -> String {
    let observation_leaves = observations
        .iter()
        .enumerate()
        .map(|(index, observation)| {
            domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-HANDLER-BINDING-OBSERVATION",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(handler_kind),
                    HashPart::Str(handler_id),
                    HashPart::U64(index as u64),
                    HashPart::Str(observation),
                ],
                32,
            )
        })
        .map(Value::String)
        .collect::<Vec<_>>();

    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-HANDLER-BINDING-OBSERVATION-ROOT",
        observation_leaves.as_slice(),
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-HANDLER-BINDING-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
