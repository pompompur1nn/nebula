use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapePrivateNoteLiveInputRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_PRIVATE_NOTE_LIVE_INPUT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-private-note-live-input-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_PRIVATE_NOTE_LIVE_INPUT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const INPUT_RECORD_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-private-note-live-input-v1";
pub const PRIVACY_BOUNDARY: &str = "root-only-no-note-metadata";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 744_128;
pub const DEFAULT_INPUT_BATCH_SIZE: u64 = 3;
pub const DEFAULT_MAX_SCAN_HINT_BITS: u16 = 18;
pub const DEFAULT_METADATA_BUDGET_UNITS: u64 = 5;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub input_record_suite: String,
    pub privacy_boundary: String,
    pub devnet_height: u64,
    pub input_batch_size: u64,
    pub max_scan_hint_bits: u16,
    pub metadata_budget_units: u64,
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
            input_record_suite: INPUT_RECORD_SUITE.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            devnet_height: DEFAULT_DEVNET_HEIGHT,
            input_batch_size: DEFAULT_INPUT_BATCH_SIZE,
            max_scan_hint_bits: DEFAULT_MAX_SCAN_HINT_BITS,
            metadata_budget_units: DEFAULT_METADATA_BUDGET_UNITS,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "input_record_suite": self.input_record_suite,
            "privacy_boundary": self.privacy_boundary,
            "devnet_height": self.devnet_height,
            "input_batch_size": self.input_batch_size,
            "max_scan_hint_bits": self.max_scan_hint_bits,
            "metadata_budget_units": self.metadata_budget_units,
            "production_release_allowed": self.production_release_allowed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiveInputLane {
    pub lane_id: String,
    pub note_state_root: String,
    pub nullifier_state_root: String,
    pub transfer_state_root: String,
    pub canonical_input_root: String,
    pub record_root: String,
}

impl LiveInputLane {
    pub fn devnet(config: &Config) -> Self {
        let lane_id = "devnet-user-escape-private-note-live-input-0001".to_string();
        let note_state_root = private_state_root(
            "note_state_root",
            &lane_id,
            &[
                "encrypted_note_commitment_frontier",
                "membership_witness_anchor",
                "note_metadata_redacted",
            ],
        );
        let nullifier_state_root = private_state_root(
            "nullifier_state_root",
            &lane_id,
            &[
                "nullifier_set_frontier",
                "key_image_separation_anchor",
                "linkage_metadata_redacted",
            ],
        );
        let transfer_state_root = private_state_root(
            "transfer_state_root",
            &lane_id,
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
                HashPart::Str(&lane_id),
                HashPart::Str(&note_state_root),
                HashPart::Str(&nullifier_state_root),
                HashPart::Str(&transfer_state_root),
                HashPart::U64(config.devnet_height),
                HashPart::U64(config.input_batch_size),
            ],
            32,
        );
        let record_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-INPUT-LANE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&lane_id),
                HashPart::Str(&note_state_root),
                HashPart::Str(&nullifier_state_root),
                HashPart::Str(&transfer_state_root),
                HashPart::Str(&canonical_input_root),
                HashPart::Str(PRIVACY_BOUNDARY),
            ],
            32,
        );

        Self {
            lane_id,
            note_state_root,
            nullifier_state_root,
            transfer_state_root,
            canonical_input_root,
            record_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "note_state_root": self.note_state_root,
            "nullifier_state_root": self.nullifier_state_root,
            "transfer_state_root": self.transfer_state_root,
            "canonical_input_root": self.canonical_input_root,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyGuard {
    pub guard_id: String,
    pub enforced: bool,
    pub evidence_root: String,
}

impl PrivacyGuard {
    pub fn enforced(guard_id: &str, lane_id: &str, evidence: &[&str]) -> Self {
        let evidence_root = private_state_root(guard_id, lane_id, evidence);

        Self {
            guard_id: guard_id.to_string(),
            enforced: true,
            evidence_root,
        }
    }

    pub fn guard_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-INPUT-PRIVACY-GUARD",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.guard_id),
                HashPart::Str(if self.enforced {
                    "enforced"
                } else {
                    "not_enforced"
                }),
                HashPart::Str(&self.evidence_root),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "guard_id": self.guard_id,
            "enforced": self.enforced,
            "evidence_root": self.evidence_root,
            "guard_root": self.guard_root(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HarnessInput {
    pub input_id: String,
    pub lane: LiveInputLane,
    pub privacy_guards: Vec<PrivacyGuard>,
    pub privacy_guard_root: String,
    pub harness_input_root: String,
}

impl HarnessInput {
    pub fn devnet(config: &Config) -> Self {
        let lane = LiveInputLane::devnet(config);
        let input_id = "devnet-canonical-user-escape-private-note-harness-input-0001".to_string();
        let privacy_guards = vec![
            PrivacyGuard::enforced(
                "note_metadata_not_exported",
                &lane.lane_id,
                &[
                    "note_amount_absent",
                    "recipient_absent",
                    "ciphertext_shape_padded",
                ],
            ),
            PrivacyGuard::enforced(
                "nullifier_metadata_not_exported",
                &lane.lane_id,
                &[
                    "key_image_not_exported",
                    "spend_path_absent",
                    "domain_separation_only",
                ],
            ),
            PrivacyGuard::enforced(
                "transfer_metadata_not_exported",
                &lane.lane_id,
                &[
                    "route_absent",
                    "counterparty_absent",
                    "contract_hook_root_only",
                ],
            ),
        ];
        let privacy_guard_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-INPUT-PRIVACY-GUARDS",
            privacy_guards
                .iter()
                .map(PrivacyGuard::guard_root)
                .map(Value::String)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let harness_input_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-INPUT-HARNESS-INPUT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.protocol_version),
                HashPart::Str(&input_id),
                HashPart::Str(&lane.record_root),
                HashPart::Str(&privacy_guard_root),
                HashPart::Str(PRIVACY_BOUNDARY),
            ],
            32,
        );

        Self {
            input_id,
            lane,
            privacy_guards,
            privacy_guard_root,
            harness_input_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "input_id": self.input_id,
            "lane": self.lane.public_record(),
            "privacy_guards": self.privacy_guards.iter().map(PrivacyGuard::public_record).collect::<Vec<_>>(),
            "privacy_guard_root": self.privacy_guard_root,
            "harness_input_root": self.harness_input_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub harness_input: HarnessInput,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let harness_input = HarnessInput::devnet(&config);
        let state_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-LIVE-INPUT-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.protocol_version),
                HashPart::Str(&harness_input.harness_input_root),
            ],
            32,
        );

        Self {
            config,
            harness_input,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "harness_input": self.harness_input.public_record(),
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
