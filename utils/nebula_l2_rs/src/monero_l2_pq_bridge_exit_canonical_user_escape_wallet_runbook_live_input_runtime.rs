use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeWalletRunbookLiveInputRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_RUNBOOK_LIVE_INPUT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-wallet-runbook-live-input-runtime-v1";

const PROTOCOL_LABEL: &str =
    "monero_l2_pq_bridge_exit_canonical_user_escape_wallet_runbook_live_input";
const HASH_SUITE: &str = "SHAKE256-domain-separated-merkle-json-v1";
const RUNBOOK_ID: &str = "devnet-user-escape-package-001";
const HARNESS_ID: &str = "devnet-user-escape-live-input-harness-001";
const WALLET_ID: &str = "escape-wallet-alpha";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub hash_suite: String,
    pub monero_network: String,
    pub runbook_id: String,
    pub harness_id: String,
    pub wallet_id: String,
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
                MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_RUNBOOK_LIVE_INPUT_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            hash_suite: HASH_SUITE.to_string(),
            monero_network: "monero-devnet".to_string(),
            runbook_id: RUNBOOK_ID.to_string(),
            harness_id: HARNESS_ID.to_string(),
            wallet_id: WALLET_ID.to_string(),
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
pub struct WalletScanObservation {
    pub observation_id: String,
    pub scan_source: String,
    pub wallet_id: String,
    pub scan_epoch: u64,
    pub scan_height: u64,
    pub confirmed_height: u64,
    pub output_commitment_root: String,
    pub nullifier_commitment_root: String,
    pub local_view_root: String,
}

impl WalletScanObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "scan_source": self.scan_source,
            "wallet_id": self.wallet_id,
            "scan_epoch": self.scan_epoch,
            "scan_height": self.scan_height,
            "confirmed_height": self.confirmed_height,
            "output_commitment_root": self.output_commitment_root,
            "nullifier_commitment_root": self.nullifier_commitment_root,
            "local_view_root": self.local_view_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletExportObservation {
    pub observation_id: String,
    pub export_id: String,
    pub wallet_id: String,
    pub export_height: u64,
    pub manifest_root: String,
    pub encrypted_payload_root: String,
    pub redaction_policy_root: String,
    pub pq_authorization_root: String,
}

impl WalletExportObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "export_id": self.export_id,
            "wallet_id": self.wallet_id,
            "export_height": self.export_height,
            "manifest_root": self.manifest_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "redaction_policy_root": self.redaction_policy_root,
            "pq_authorization_root": self.pq_authorization_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookObservation {
    pub observation_id: String,
    pub runbook_id: String,
    pub step_id: String,
    pub observed_height: u64,
    pub readiness_status: String,
    pub evidence_root: String,
    pub user_replay_command_root: String,
}

impl RunbookObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "runbook_id": self.runbook_id,
            "step_id": self.step_id,
            "observed_height": self.observed_height,
            "readiness_status": self.readiness_status,
            "evidence_root": self.evidence_root,
            "user_replay_command_root": self.user_replay_command_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessInputRecord {
    pub input_id: String,
    pub wallet_scan_observation_id: String,
    pub wallet_export_observation_id: String,
    pub runbook_observation_id: String,
    pub replay_label: String,
    pub replay_payload_root: String,
    pub canonical_input_root: String,
}

impl HarnessInputRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "input_id": self.input_id,
            "wallet_scan_observation_id": self.wallet_scan_observation_id,
            "wallet_export_observation_id": self.wallet_export_observation_id,
            "runbook_observation_id": self.runbook_observation_id,
            "replay_label": self.replay_label,
            "replay_payload_root": self.replay_payload_root,
            "canonical_input_root": self.canonical_input_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub wallet_scan_observation_root: String,
    pub wallet_export_observation_root: String,
    pub runbook_observation_root: String,
    pub harness_input_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "wallet_scan_observation_root": self.wallet_scan_observation_root,
            "wallet_export_observation_root": self.wallet_export_observation_root,
            "runbook_observation_root": self.runbook_observation_root,
            "harness_input_root": self.harness_input_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub wallet_scan_observations: Vec<WalletScanObservation>,
    pub wallet_export_observations: Vec<WalletExportObservation>,
    pub runbook_observations: Vec<RunbookObservation>,
    pub harness_inputs: Vec<HarnessInputRecord>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let scan = WalletScanObservation {
            observation_id: deterministic_id("wallet-scan-observation", "epoch-44"),
            scan_source: "local-wallet-scan".to_string(),
            wallet_id: config.wallet_id.clone(),
            scan_epoch: 44,
            scan_height: 17_680,
            confirmed_height: 17_668,
            output_commitment_root: sample_root("wallet-output-commitments"),
            nullifier_commitment_root: sample_root("wallet-nullifier-commitments"),
            local_view_root: sample_root("wallet-local-view"),
        };
        let export = WalletExportObservation {
            observation_id: deterministic_id("wallet-export-observation", "claim-export-001"),
            export_id: deterministic_id("wallet-export", "claim-export-001"),
            wallet_id: config.wallet_id.clone(),
            export_height: 17_680,
            manifest_root: sample_root("wallet-export-manifest"),
            encrypted_payload_root: sample_root("wallet-export-payload"),
            redaction_policy_root: sample_root("wallet-export-redaction-policy"),
            pq_authorization_root: sample_root("wallet-export-pq-authorization"),
        };
        let runbook = RunbookObservation {
            observation_id: deterministic_id("runbook-observation", "forced-exit-claim-build"),
            runbook_id: config.runbook_id.clone(),
            step_id: "forced_exit_claim_build".to_string(),
            observed_height: 17_681,
            readiness_status: "ready".to_string(),
            evidence_root: sample_root("runbook-forced-exit-evidence"),
            user_replay_command_root: sample_root("runbook-user-replay-command"),
        };
        let canonical_input_root = canonical_harness_input_root(&scan, &export, &runbook);
        let input = HarnessInputRecord {
            input_id: deterministic_id("harness-input", "wallet-escape-claim-build"),
            wallet_scan_observation_id: scan.observation_id.clone(),
            wallet_export_observation_id: export.observation_id.clone(),
            runbook_observation_id: runbook.observation_id.clone(),
            replay_label: "local-user-escape-forced-exit-claim-build".to_string(),
            replay_payload_root: sample_root("local-replay-payload"),
            canonical_input_root,
        };

        Self {
            config,
            wallet_scan_observations: vec![scan],
            wallet_export_observations: vec![export],
            runbook_observations: vec![runbook],
            harness_inputs: vec![input],
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.config_root(),
            wallet_scan_observation_root: merkle_root(
                "USER-ESCAPE-LIVE-INPUT-WALLET-SCAN-OBSERVATIONS",
                &self
                    .wallet_scan_observations
                    .iter()
                    .map(WalletScanObservation::public_record)
                    .collect::<Vec<_>>(),
            ),
            wallet_export_observation_root: merkle_root(
                "USER-ESCAPE-LIVE-INPUT-WALLET-EXPORT-OBSERVATIONS",
                &self
                    .wallet_export_observations
                    .iter()
                    .map(WalletExportObservation::public_record)
                    .collect::<Vec<_>>(),
            ),
            runbook_observation_root: merkle_root(
                "USER-ESCAPE-LIVE-INPUT-RUNBOOK-OBSERVATIONS",
                &self
                    .runbook_observations
                    .iter()
                    .map(RunbookObservation::public_record)
                    .collect::<Vec<_>>(),
            ),
            harness_input_root: merkle_root(
                "USER-ESCAPE-LIVE-INPUT-HARNESS-INPUTS",
                &self
                    .harness_inputs
                    .iter()
                    .map(HarnessInputRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_RUNBOOK_LIVE_INPUT_RUNTIME_PROTOCOL_VERSION,
            "protocol_label": PROTOCOL_LABEL,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "wallet_scan_observations": self.wallet_scan_observations
                .iter()
                .map(WalletScanObservation::public_record)
                .collect::<Vec<_>>(),
            "wallet_export_observations": self.wallet_export_observations
                .iter()
                .map(WalletExportObservation::public_record)
                .collect::<Vec<_>>(),
            "runbook_observations": self.runbook_observations
                .iter()
                .map(RunbookObservation::public_record)
                .collect::<Vec<_>>(),
            "harness_inputs": self.harness_inputs
                .iter()
                .map(HarnessInputRecord::public_record)
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

fn canonical_harness_input_root(
    scan: &WalletScanObservation,
    export: &WalletExportObservation,
    runbook: &RunbookObservation,
) -> String {
    runtime_hash(
        "CANONICAL-HARNESS-INPUT",
        &[
            HashPart::Str(&scan.observation_id),
            HashPart::Str(&export.observation_id),
            HashPart::Str(&runbook.observation_id),
            HashPart::Str(&scan.output_commitment_root),
            HashPart::Str(&export.manifest_root),
            HashPart::Str(&runbook.evidence_root),
        ],
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
                MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_WALLET_RUNBOOK_LIVE_INPUT_RUNTIME_PROTOCOL_VERSION,
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
