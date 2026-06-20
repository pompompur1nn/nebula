use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSlicePrivateReceiptGateInvocationRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PRIVATE_RECEIPT_GATE_INVOCATION_RUNTIME_PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-private-receipt-gate-invocation-runtime/v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PRIVATE_RECEIPT_GATE_INVOCATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str =
    "2026-06-19.forced-exit.vertical-slice.private-receipt-gate-invocation.v1";
pub const HASH_SUITE: &str = "nebula-l2-devnet-shake256-32";

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-private-receipt-gate-invocation-runtime";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub gate_id: String,
    pub base_l2_height: u64,
    pub forced_exit_epoch: u64,
    pub min_pq_authorization_weight_bps: u64,
    pub max_fee_cap_piconero: u64,
    pub wallet_reconstruction_shards_required: u64,
    pub encrypted_receipt_shards_required: u64,
    pub fail_closed_on_mismatch: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            gate_id: "devnet-private-transfer-receipt-gate".to_string(),
            base_l2_height: 1_260_144,
            forced_exit_epoch: 44,
            min_pq_authorization_weight_bps: 7_000,
            max_fee_cap_piconero: 42_000_000,
            wallet_reconstruction_shards_required: 3,
            encrypted_receipt_shards_required: 3,
            fail_closed_on_mismatch: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "gate_id": self.gate_id,
            "base_l2_height": self.base_l2_height,
            "forced_exit_epoch": self.forced_exit_epoch,
            "min_pq_authorization_weight_bps": self.min_pq_authorization_weight_bps,
            "max_fee_cap_piconero": self.max_fee_cap_piconero,
            "wallet_reconstruction_shards_required": self.wallet_reconstruction_shards_required,
            "encrypted_receipt_shards_required": self.encrypted_receipt_shards_required,
            "fail_closed_on_mismatch": self.fail_closed_on_mismatch,
            "production_release_allowed": self.production_release_allowed
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateInput {
    pub transfer_id: String,
    pub receipt_id: String,
    pub action_id: String,
    pub note_nullifier_root: String,
    pub output_commitment_root: String,
    pub encrypted_receipt_root: String,
    pub fee_cap_root: String,
    pub pq_authorization_root: String,
    pub wallet_reconstruction_root: String,
    pub forced_exit_compatibility_root: String,
    pub submitted_output_root: String,
    pub invoked_at_height: u64,
}

impl GateInput {
    pub fn devnet(config: &Config) -> Self {
        let transfer_id = "devnet-forced-exit-private-transfer-0001".to_string();
        let receipt_id = "devnet-private-transfer-receipt-gate-invocation-0001".to_string();
        let action_id = "devnet-forced-exit-action-private-note-transfer-0001".to_string();
        let note_nullifier_root = note_nullifier_root(&transfer_id);
        let output_commitment_root = output_commitment_root(&transfer_id);
        let encrypted_receipt_root = encrypted_receipt_root(&receipt_id);
        let fee_cap_root = fee_cap_root(config, &transfer_id);
        let pq_authorization_root = pq_authorization_root(config, &transfer_id);
        let wallet_reconstruction_root = wallet_reconstruction_root(config, &receipt_id);
        let forced_exit_compatibility_root = forced_exit_compatibility_root(config, &transfer_id);
        let submitted_output_root = expected_output_root(
            &note_nullifier_root,
            &output_commitment_root,
            &encrypted_receipt_root,
            &fee_cap_root,
            &pq_authorization_root,
            &wallet_reconstruction_root,
            &forced_exit_compatibility_root,
        );

        Self {
            transfer_id,
            receipt_id,
            action_id,
            note_nullifier_root,
            output_commitment_root,
            encrypted_receipt_root,
            fee_cap_root,
            pq_authorization_root,
            wallet_reconstruction_root,
            forced_exit_compatibility_root,
            submitted_output_root,
            invoked_at_height: config.base_l2_height + 9,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "transfer_id": self.transfer_id,
            "receipt_id": self.receipt_id,
            "action_id": self.action_id,
            "note_nullifier_root": self.note_nullifier_root,
            "output_commitment_root": self.output_commitment_root,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "fee_cap_root": self.fee_cap_root,
            "pq_authorization_root": self.pq_authorization_root,
            "wallet_reconstruction_root": self.wallet_reconstruction_root,
            "forced_exit_compatibility_root": self.forced_exit_compatibility_root,
            "submitted_output_root": self.submitted_output_root,
            "invoked_at_height": self.invoked_at_height
        })
    }

    pub fn state_root(&self) -> String {
        record_root("gate-input", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateOutput {
    pub accepted: bool,
    pub expected_output_root: String,
    pub invocation_receipt_root: String,
    pub deterministic_input_root: String,
    pub fail_closed_rejection_root: String,
}

impl GateOutput {
    pub fn from_input(input: &GateInput, rejections: &[FailClosedRejection]) -> Self {
        let deterministic_input_root = record_root("deterministic-input", &input.public_record());
        let expected_output_root = expected_output_root(
            &input.note_nullifier_root,
            &input.output_commitment_root,
            &input.encrypted_receipt_root,
            &input.fee_cap_root,
            &input.pq_authorization_root,
            &input.wallet_reconstruction_root,
            &input.forced_exit_compatibility_root,
        );
        let fail_closed_rejection_root = rejection_root(rejections);
        let accepted = input.submitted_output_root == expected_output_root && rejections.is_empty();
        let invocation_receipt_root = domain_hash(
            &format!("{DOMAIN}:invocation-receipt"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&input.receipt_id),
                HashPart::Str(&deterministic_input_root),
                HashPart::Str(&expected_output_root),
                HashPart::Str(&fail_closed_rejection_root),
                HashPart::Str(if accepted { "accepted" } else { "rejected" }),
            ],
            32,
        );

        Self {
            accepted,
            expected_output_root,
            invocation_receipt_root,
            deterministic_input_root,
            fail_closed_rejection_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "accepted": self.accepted,
            "expected_output_root": self.expected_output_root,
            "invocation_receipt_root": self.invocation_receipt_root,
            "deterministic_input_root": self.deterministic_input_root,
            "fail_closed_rejection_root": self.fail_closed_rejection_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("gate-output", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FailClosedRejection {
    pub code: String,
    pub rejected_root: String,
    pub expected_root: String,
    pub observed_root: String,
}

impl FailClosedRejection {
    pub fn new(code: &str, expected_root: &str, observed_root: &str) -> Self {
        let rejected_root = domain_hash(
            &format!("{DOMAIN}:fail-closed-rejection"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(code),
                HashPart::Str(expected_root),
                HashPart::Str(observed_root),
            ],
            32,
        );

        Self {
            code: code.to_string(),
            rejected_root,
            expected_root: expected_root.to_string(),
            observed_root: observed_root.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "code": self.code,
            "rejected_root": self.rejected_root,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub input: GateInput,
    pub output: GateOutput,
    pub fail_closed_rejections: Vec<FailClosedRejection>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let input = GateInput::devnet(&config);
        let fail_closed_rejections = Vec::new();
        let output = GateOutput::from_input(&input, &fail_closed_rejections);

        Self {
            config,
            input,
            output,
            fail_closed_rejections,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "config": self.config.public_record(),
            "input": self.input.public_record(),
            "output": self.output.public_record(),
            "fail_closed_rejections": self.fail_closed_rejections.iter().map(FailClosedRejection::public_record).collect::<Vec<_>>(),
            "roots": {
                "config_root": self.config.state_root(),
                "input_root": self.input.state_root(),
                "output_root": self.output.state_root(),
                "rejection_root": self.rejection_root()
            }
        })
    }

    pub fn rejection_root(&self) -> String {
        rejection_root(&self.fail_closed_rejections)
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            &format!("{DOMAIN}:state"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(SCHEMA_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.input.state_root()),
                HashPart::Str(&self.output.state_root()),
                HashPart::Str(&self.rejection_root()),
            ],
            32,
        )
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root() -> String {
    State::devnet().state_root()
}

fn note_nullifier_root(transfer_id: &str) -> String {
    let records = [
        json!({
            "kind": "input_note",
            "index": 0_u64,
            "note_root": leaf_root("input-note", transfer_id, 0),
            "nullifier_root": leaf_root("input-nullifier", transfer_id, 0)
        }),
        json!({
            "kind": "input_note",
            "index": 1_u64,
            "note_root": leaf_root("input-note", transfer_id, 1),
            "nullifier_root": leaf_root("input-nullifier", transfer_id, 1)
        }),
    ];

    merkle_root(&format!("{DOMAIN}:note-nullifier-root"), &records)
}

fn output_commitment_root(transfer_id: &str) -> String {
    let records = [
        json!({"kind": "recipient_output", "index": 0_u64, "commitment": leaf_root("recipient-output", transfer_id, 0)}),
        json!({"kind": "change_output", "index": 1_u64, "commitment": leaf_root("change-output", transfer_id, 1)}),
        json!({"kind": "forced_exit_receipt_output", "index": 2_u64, "commitment": leaf_root("forced-exit-output", transfer_id, 2)}),
    ];

    merkle_root(&format!("{DOMAIN}:output-commitment-root"), &records)
}

fn encrypted_receipt_root(receipt_id: &str) -> String {
    let records = ["recipient", "change", "forced_exit_recovery"]
        .iter()
        .enumerate()
        .map(|(index, audience)| {
            json!({
                "audience": audience,
                "index": index as u64,
                "ciphertext_root": leaf_root("encrypted-receipt-ciphertext", receipt_id, index as u64),
                "view_tag_root": leaf_root("encrypted-receipt-view-tag", receipt_id, index as u64)
            })
        })
        .collect::<Vec<_>>();

    merkle_root(&format!("{DOMAIN}:encrypted-receipt-root"), &records)
}

fn fee_cap_root(config: &Config, transfer_id: &str) -> String {
    let record = json!({
        "transfer_id": transfer_id,
        "max_fee_cap_piconero": config.max_fee_cap_piconero,
        "policy": "forced_exit_low_fee_private_receipt_cap"
    });
    record_root("fee-cap", &record)
}

fn pq_authorization_root(config: &Config, transfer_id: &str) -> String {
    let record = json!({
        "transfer_id": transfer_id,
        "authority_set_root": leaf_root("pq-authority-set", transfer_id, 0),
        "weight_bps": config.min_pq_authorization_weight_bps,
        "threshold_met": true
    });
    record_root("pq-authorization", &record)
}

fn wallet_reconstruction_root(config: &Config, receipt_id: &str) -> String {
    let records = (0..config.wallet_reconstruction_shards_required)
        .map(|index| {
            json!({
                "shard_index": index,
                "reconstruction_hint_root": leaf_root("wallet-reconstruction-hint", receipt_id, index)
            })
        })
        .collect::<Vec<_>>();

    merkle_root(&format!("{DOMAIN}:wallet-reconstruction-root"), &records)
}

fn forced_exit_compatibility_root(config: &Config, transfer_id: &str) -> String {
    let record = json!({
        "transfer_id": transfer_id,
        "forced_exit_epoch": config.forced_exit_epoch,
        "challenge_window_root": leaf_root("forced-exit-challenge-window", transfer_id, config.forced_exit_epoch),
        "settlement_claim_root": leaf_root("forced-exit-settlement-claim", transfer_id, config.forced_exit_epoch)
    });
    record_root("forced-exit-compatibility", &record)
}

fn expected_output_root(
    note_nullifier_root: &str,
    output_commitment_root: &str,
    encrypted_receipt_root: &str,
    fee_cap_root: &str,
    pq_authorization_root: &str,
    wallet_reconstruction_root: &str,
    forced_exit_compatibility_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:expected-output-root"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(note_nullifier_root),
            HashPart::Str(output_commitment_root),
            HashPart::Str(encrypted_receipt_root),
            HashPart::Str(fee_cap_root),
            HashPart::Str(pq_authorization_root),
            HashPart::Str(wallet_reconstruction_root),
            HashPart::Str(forced_exit_compatibility_root),
        ],
        32,
    )
}

fn rejection_root(rejections: &[FailClosedRejection]) -> String {
    let records = rejections
        .iter()
        .map(FailClosedRejection::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:fail-closed-rejections"), &records)
}

fn leaf_root(label: &str, seed: &str, index: u64) -> String {
    domain_hash(
        &format!("{DOMAIN}:{label}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(seed),
            HashPart::U64(index),
        ],
        32,
    )
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
