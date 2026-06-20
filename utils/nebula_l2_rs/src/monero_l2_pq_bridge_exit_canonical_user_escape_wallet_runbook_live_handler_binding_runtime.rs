use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeWalletRunbookLiveHandlerBindingRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_RUNBOOK_LIVE_HANDLER_BINDING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-wallet-runbook-live-handler-binding-runtime-v1";

const PROTOCOL_LABEL: &str =
    "monero_l2_pq_bridge_exit_canonical_user_escape_wallet_runbook_live_handler_binding";
const HASH_SUITE: &str = "SHAKE256-domain-separated-merkle-json-v1";
const RUNBOOK_ID: &str = "devnet-user-escape-package-001";
const HARNESS_ID: &str = "devnet-user-escape-live-input-harness-001";
const WALLET_ID: &str = "escape-wallet-alpha";
const HANDLER_BINDING_SET_ID: &str = "devnet-user-escape-handler-binding-set-001";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub monero_network: String,
    pub runbook_id: String,
    pub harness_id: String,
    pub wallet_id: String,
    pub handler_binding_set_id: String,
    pub min_wallet_scan_confirmations: u64,
    pub min_live_feed_confirmations: u64,
    pub max_observation_lag_blocks: u64,
    pub replay_payload_schema_version: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version:
                MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_RUNBOOK_LIVE_HANDLER_BINDING_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            hash_suite: HASH_SUITE.to_string(),
            monero_network: "monero-devnet".to_string(),
            runbook_id: RUNBOOK_ID.to_string(),
            harness_id: HARNESS_ID.to_string(),
            wallet_id: WALLET_ID.to_string(),
            handler_binding_set_id: HANDLER_BINDING_SET_ID.to_string(),
            min_wallet_scan_confirmations: 12,
            min_live_feed_confirmations: 3,
            max_observation_lag_blocks: 6,
            replay_payload_schema_version: 1,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "hash_suite": self.hash_suite,
            "monero_network": self.monero_network,
            "runbook_id": self.runbook_id,
            "harness_id": self.harness_id,
            "wallet_id": self.wallet_id,
            "handler_binding_set_id": self.handler_binding_set_id,
            "min_wallet_scan_confirmations": self.min_wallet_scan_confirmations,
            "min_live_feed_confirmations": self.min_live_feed_confirmations,
            "max_observation_lag_blocks": self.max_observation_lag_blocks,
            "replay_payload_schema_version": self.replay_payload_schema_version,
        })
    }

    pub fn config_root(&self) -> String {
        runtime_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandlerFedObservation {
    pub observation_id: String,
    pub handler_id: String,
    pub live_input_id: String,
    pub stage: String,
    pub observed_height: u64,
    pub handler_payload_root: String,
    pub handler_receipt_root: String,
    pub replay_command_root: String,
}

impl HandlerFedObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "handler_id": self.handler_id,
            "live_input_id": self.live_input_id,
            "stage": self.stage,
            "observed_height": self.observed_height,
            "handler_payload_root": self.handler_payload_root,
            "handler_receipt_root": self.handler_receipt_root,
            "replay_command_root": self.replay_command_root,
        })
    }

    pub fn observation_root(&self) -> String {
        runtime_hash(
            "HANDLER-FED-OBSERVATION",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveInputBinding {
    pub binding_id: String,
    pub live_input_id: String,
    pub wallet_scan_export_observation_id: String,
    pub proof_collection_observation_id: String,
    pub forced_exit_claim_builder_observation_id: String,
    pub pq_authorization_exporter_observation_id: String,
    pub live_feed_crosscheck_observation_id: String,
    pub release_verifier_replay_observation_id: String,
    pub local_recovery_replay_observation_id: String,
    pub canonical_binding_root: String,
}

impl LiveInputBinding {
    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "live_input_id": self.live_input_id,
            "wallet_scan_export_observation_id": self.wallet_scan_export_observation_id,
            "proof_collection_observation_id": self.proof_collection_observation_id,
            "forced_exit_claim_builder_observation_id": self.forced_exit_claim_builder_observation_id,
            "pq_authorization_exporter_observation_id": self.pq_authorization_exporter_observation_id,
            "live_feed_crosscheck_observation_id": self.live_feed_crosscheck_observation_id,
            "release_verifier_replay_observation_id": self.release_verifier_replay_observation_id,
            "local_recovery_replay_observation_id": self.local_recovery_replay_observation_id,
            "canonical_binding_root": self.canonical_binding_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub handler_fed_observation_root: String,
    pub live_input_binding_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "handler_fed_observation_root": self.handler_fed_observation_root,
            "live_input_binding_root": self.live_input_binding_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub handler_fed_observations: Vec<HandlerFedObservation>,
    pub live_input_bindings: Vec<LiveInputBinding>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let live_input_id = deterministic_id("harness-input", "wallet-escape-claim-build");
        let observations = vec![
            handler_observation(
                "wallet-scan-export",
                "wallet_scan_export",
                &live_input_id,
                17_680,
            ),
            handler_observation(
                "proof-collection",
                "proof_collection",
                &live_input_id,
                17_681,
            ),
            handler_observation(
                "forced-exit-claim-builder",
                "forced_exit_claim_builder",
                &live_input_id,
                17_682,
            ),
            handler_observation(
                "pq-authorization-exporter",
                "pq_authorization_exporter",
                &live_input_id,
                17_682,
            ),
            handler_observation(
                "live-feed-crosscheck",
                "live_feed_crosscheck",
                &live_input_id,
                17_683,
            ),
            handler_observation(
                "release-verifier-replay",
                "release_verifier_replay",
                &live_input_id,
                17_724,
            ),
            handler_observation(
                "local-recovery-replay",
                "local_recovery_replay",
                &live_input_id,
                17_725,
            ),
        ];

        let binding = LiveInputBinding {
            binding_id: deterministic_id("live-input-binding", "wallet-escape-claim-build"),
            live_input_id,
            wallet_scan_export_observation_id: observations[0].observation_id.clone(),
            proof_collection_observation_id: observations[1].observation_id.clone(),
            forced_exit_claim_builder_observation_id: observations[2].observation_id.clone(),
            pq_authorization_exporter_observation_id: observations[3].observation_id.clone(),
            live_feed_crosscheck_observation_id: observations[4].observation_id.clone(),
            release_verifier_replay_observation_id: observations[5].observation_id.clone(),
            local_recovery_replay_observation_id: observations[6].observation_id.clone(),
            canonical_binding_root: canonical_binding_root(&observations),
        };

        Self {
            config,
            handler_fed_observations: observations,
            live_input_bindings: vec![binding],
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.config_root(),
            handler_fed_observation_root: merkle_root(
                "USER-ESCAPE-LIVE-HANDLER-BINDING-OBSERVATIONS",
                &self
                    .handler_fed_observations
                    .iter()
                    .map(HandlerFedObservation::public_record)
                    .collect::<Vec<_>>(),
            ),
            live_input_binding_root: merkle_root(
                "USER-ESCAPE-LIVE-HANDLER-BINDING-LIVE-INPUTS",
                &self
                    .live_input_bindings
                    .iter()
                    .map(LiveInputBinding::public_record)
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_RUNBOOK_LIVE_HANDLER_BINDING_RUNTIME_PROTOCOL_VERSION,
            "protocol_label": PROTOCOL_LABEL,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "handler_fed_observations": self.handler_fed_observations
                .iter()
                .map(HandlerFedObservation::public_record)
                .collect::<Vec<_>>(),
            "live_input_bindings": self.live_input_bindings
                .iter()
                .map(LiveInputBinding::public_record)
                .collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(object) = &mut record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        runtime_hash(
            "STATE",
            &[HashPart::Json(&self.public_record_without_root())],
        )
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

fn handler_observation(
    handler_label: &str,
    stage: &str,
    live_input_id: &str,
    observed_height: u64,
) -> HandlerFedObservation {
    let handler_id = deterministic_id("handler", handler_label);
    HandlerFedObservation {
        observation_id: deterministic_id("handler-observation", handler_label),
        handler_id,
        live_input_id: live_input_id.to_string(),
        stage: stage.to_string(),
        observed_height,
        handler_payload_root: sample_root(&format!("{handler_label}-payload")),
        handler_receipt_root: sample_root(&format!("{handler_label}-receipt")),
        replay_command_root: sample_root(&format!("{handler_label}-replay-command")),
    }
}

fn canonical_binding_root(observations: &[HandlerFedObservation]) -> String {
    runtime_hash(
        "CANONICAL-LIVE-HANDLER-BINDING",
        &[HashPart::Json(&json!(observations
            .iter()
            .map(|observation| json!({
                "observation_id": observation.observation_id,
                "stage": observation.stage,
                "observation_root": observation.observation_root(),
            }))
            .collect::<Vec<_>>()))],
    )
}

fn deterministic_id(kind: &str, label: &str) -> String {
    runtime_hash("ID", &[HashPart::Str(kind), HashPart::Str(label)])
}

fn sample_root(label: &str) -> String {
    runtime_hash("SAMPLE-ROOT", &[HashPart::Str(label)])
}

fn runtime_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    let part_record = parts.iter().map(hash_part_record).collect::<Vec<_>>();

    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_LABEL),
            HashPart::Str(
                MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_RUNBOOK_LIVE_HANDLER_BINDING_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Json(&json!(part_record)),
        ],
        32,
    )
}

fn hash_part_record(part: &HashPart<'_>) -> Value {
    match part {
        HashPart::Bytes(value) => json!({
            "kind": "bytes",
            "value": hex::encode(value),
        }),
        HashPart::Str(value) => json!({
            "kind": "str",
            "value": value,
        }),
        HashPart::U64(value) => json!({
            "kind": "u64",
            "value": value,
        }),
        HashPart::Int(value) => json!({
            "kind": "int",
            "value": value.to_string(),
        }),
        HashPart::Json(value) => json!({
            "kind": "json",
            "value": value,
        }),
    }
}
