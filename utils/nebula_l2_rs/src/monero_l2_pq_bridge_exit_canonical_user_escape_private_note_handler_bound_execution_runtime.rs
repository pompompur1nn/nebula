use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapePrivateNoteHandlerBoundExecutionRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_PRIVATE_NOTE_HANDLER_BOUND_EXECUTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-private-note-handler-bound-execution-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_PRIVATE_NOTE_HANDLER_BOUND_EXECUTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const EXECUTION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-private-note-handler-bound-execution-v1";
pub const PRIVACY_BOUNDARY: &str = "handler-bound-roots-only";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 744_192;
pub const DEFAULT_FORCED_EXIT_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_METADATA_BUDGET_UNITS: u64 = 5;
pub const DEFAULT_HANDLER_COUNT: u64 = 5;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub execution_suite: String,
    pub privacy_boundary: String,
    pub execution_height: u64,
    pub forced_exit_window_blocks: u64,
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
            execution_suite: EXECUTION_SUITE.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            execution_height: DEFAULT_DEVNET_HEIGHT,
            forced_exit_window_blocks: DEFAULT_FORCED_EXIT_WINDOW_BLOCKS,
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
            "execution_suite": self.execution_suite,
            "privacy_boundary": self.privacy_boundary,
            "execution_height": self.execution_height,
            "forced_exit_window_blocks": self.forced_exit_window_blocks,
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
pub struct HandlerBoundInput {
    pub execution_id: String,
    pub binding_set_id: String,
    pub encrypted_note_root: String,
    pub nullifier_root: String,
    pub receipt_root: String,
    pub metadata_root: String,
    pub handler_binding_root: String,
    pub handler_receipt_root: String,
    pub canonical_input_root: String,
}

impl HandlerBoundInput {
    pub fn devnet(config: &Config) -> Self {
        let execution_id = "devnet-private-note-handler-bound-execution-0001".to_string();
        let binding_set_id = "devnet-private-note-live-handler-binding-set-0001".to_string();
        let encrypted_note_root = bound_root(
            "encrypted_note_root",
            &execution_id,
            &[
                "encrypted_note_commitment_frontier",
                "membership_witness_anchor",
                "note_payload_not_decrypted",
            ],
        );
        let nullifier_root = bound_root(
            "nullifier_root",
            &execution_id,
            &[
                "nullifier_set_frontier",
                "key_image_domain_separation",
                "no_linkable_plaintext",
            ],
        );
        let receipt_root = bound_root(
            "receipt_root",
            &execution_id,
            &[
                "forced_exit_receipt_commitment",
                "handler_attestation_receipt",
                "settlement_claim_redacted",
            ],
        );
        let metadata_root = bound_root(
            "metadata_root",
            &execution_id,
            &[
                "metadata_budget_enforced",
                "scan_hint_bits_capped",
                "route_metadata_redacted",
            ],
        );
        let handler_binding_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-HANDLER-BOUND-EXECUTION-HANDLER-BINDING",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&binding_set_id),
                HashPart::Str(&encrypted_note_root),
                HashPart::Str(&nullifier_root),
                HashPart::Str(&receipt_root),
                HashPart::Str(&metadata_root),
                HashPart::U64(config.handler_count),
            ],
            32,
        );
        let handler_receipt_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-HANDLER-BOUND-EXECUTION-HANDLER-RECEIPT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&execution_id),
                HashPart::Str(&handler_binding_root),
                HashPart::Str(PRIVACY_BOUNDARY),
            ],
            32,
        );
        let canonical_input_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-HANDLER-BOUND-EXECUTION-CANONICAL-INPUT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.protocol_version),
                HashPart::Str(&execution_id),
                HashPart::Str(&binding_set_id),
                HashPart::Str(&encrypted_note_root),
                HashPart::Str(&nullifier_root),
                HashPart::Str(&receipt_root),
                HashPart::Str(&metadata_root),
                HashPart::Str(&handler_binding_root),
                HashPart::Str(&handler_receipt_root),
                HashPart::U64(config.execution_height),
            ],
            32,
        );

        Self {
            execution_id,
            binding_set_id,
            encrypted_note_root,
            nullifier_root,
            receipt_root,
            metadata_root,
            handler_binding_root,
            handler_receipt_root,
            canonical_input_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "execution_id": self.execution_id,
            "binding_set_id": self.binding_set_id,
            "encrypted_note_root": self.encrypted_note_root,
            "nullifier_root": self.nullifier_root,
            "receipt_root": self.receipt_root,
            "metadata_root": self.metadata_root,
            "handler_binding_root": self.handler_binding_root,
            "handler_receipt_root": self.handler_receipt_root,
            "canonical_input_root": self.canonical_input_root,
        })
    }

    pub fn input_root(&self) -> String {
        record_root("handler_bound_input", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionVerdict {
    pub verdict_id: String,
    pub status: String,
    pub privacy_preserving: bool,
    pub forced_exit_lane: String,
    pub disclosure_policy: String,
    pub accepted_root: String,
    pub rejection_root: String,
    pub execution_root: String,
    pub verdict_root: String,
}

impl ExecutionVerdict {
    pub fn accept(config: &Config, input: &HandlerBoundInput) -> Self {
        let verdict_id = "devnet-private-note-handler-bound-verdict-0001".to_string();
        let status = "accepted".to_string();
        let forced_exit_lane = "canonical-user-escape-private-note".to_string();
        let disclosure_policy = PRIVACY_BOUNDARY.to_string();
        let accepted_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-HANDLER-BOUND-EXECUTION-ACCEPTED",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&input.execution_id),
                HashPart::Str(&input.canonical_input_root),
                HashPart::Str(&input.handler_receipt_root),
                HashPart::U64(config.forced_exit_window_blocks),
                HashPart::Str("private_note_escape_lane_executable"),
            ],
            32,
        );
        let rejection_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-HANDLER-BOUND-EXECUTION-REJECTION",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&input.execution_id),
                HashPart::Str("no_rejection_conditions_observed"),
            ],
            32,
        );
        let execution_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-HANDLER-BOUND-EXECUTION-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.protocol_version),
                HashPart::Str(&input.input_root()),
                HashPart::Str(&accepted_root),
                HashPart::Str(&rejection_root),
                HashPart::Str(PRIVACY_BOUNDARY),
            ],
            32,
        );
        let verdict_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-HANDLER-BOUND-EXECUTION-VERDICT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&verdict_id),
                HashPart::Str(&status),
                HashPart::Str(&forced_exit_lane),
                HashPart::Str(&disclosure_policy),
                HashPart::Str(&execution_root),
            ],
            32,
        );

        Self {
            verdict_id,
            status,
            privacy_preserving: true,
            forced_exit_lane,
            disclosure_policy,
            accepted_root,
            rejection_root,
            execution_root,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "verdict_id": self.verdict_id,
            "status": self.status,
            "privacy_preserving": self.privacy_preserving,
            "forced_exit_lane": self.forced_exit_lane,
            "disclosure_policy": self.disclosure_policy,
            "accepted_root": self.accepted_root,
            "rejection_root": self.rejection_root,
            "execution_root": self.execution_root,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub input: HandlerBoundInput,
    pub verdict: ExecutionVerdict,
    pub public_record_root: String,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let input = HandlerBoundInput::devnet(&config);
        let verdict = ExecutionVerdict::accept(&config, &input);
        let public_record_root = record_root(
            "public_record",
            &json!({
                "config": config.public_record(),
                "input": input.public_record(),
                "verdict": verdict.public_record(),
            }),
        );
        let state_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-HANDLER-BOUND-EXECUTION-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.state_root()),
                HashPart::Str(&input.input_root()),
                HashPart::Str(&verdict.verdict_root),
                HashPart::Str(&public_record_root),
            ],
            32,
        );

        Self {
            config,
            input,
            verdict,
            public_record_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "input": self.input.public_record(),
            "verdict": self.verdict.public_record(),
            "public_record_root": self.public_record_root,
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

fn bound_root(label: &str, execution_id: &str, leaves: &[&str]) -> String {
    let leaf_roots = leaves
        .iter()
        .enumerate()
        .map(|(index, leaf)| {
            domain_hash(
                "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-HANDLER-BOUND-EXECUTION-LEAF",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(label),
                    HashPart::Str(execution_id),
                    HashPart::U64(index as u64),
                    HashPart::Str(leaf),
                ],
                32,
            )
        })
        .map(Value::String)
        .collect::<Vec<_>>();

    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-HANDLER-BOUND-EXECUTION-BOUND-ROOT",
        leaf_roots.as_slice(),
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-HANDLER-BOUND-EXECUTION-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
