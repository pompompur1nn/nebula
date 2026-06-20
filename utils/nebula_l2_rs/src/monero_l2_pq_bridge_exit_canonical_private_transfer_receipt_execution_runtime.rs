use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalPrivateTransferReceiptExecutionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PRIVATE_TRANSFER_RECEIPT_EXECUTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-private-transfer-receipt-execution-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PRIVATE_TRANSFER_RECEIPT_EXECUTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const EXECUTION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-private-transfer-receipt-execution-v1";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 622_144;
pub const DEFAULT_LOW_FEE_CAP_ATOMIC: u128 = 28_000_000;
pub const DEFAULT_METADATA_BUDGET_UNITS: u64 = 6;
pub const DEFAULT_MIN_PQ_AUTHORIZATION_WEIGHT_BPS: u64 = 7_000;
pub const DEFAULT_FORCED_EXIT_COMPATIBILITY_DEPTH: u64 = 4;
pub const DEFAULT_WALLET_RECONSTRUCTION_SHARDS: u64 = 3;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub execution_suite: String,
    pub base_l2_height: u64,
    pub low_fee_cap_atomic: u128,
    pub metadata_budget_units: u64,
    pub min_pq_authorization_weight_bps: u64,
    pub forced_exit_compatibility_depth: u64,
    pub wallet_reconstruction_shards: u64,
    pub encrypted_receipt_shards_required: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            execution_suite: EXECUTION_SUITE.to_string(),
            base_l2_height: DEFAULT_DEVNET_HEIGHT,
            low_fee_cap_atomic: DEFAULT_LOW_FEE_CAP_ATOMIC,
            metadata_budget_units: DEFAULT_METADATA_BUDGET_UNITS,
            min_pq_authorization_weight_bps: DEFAULT_MIN_PQ_AUTHORIZATION_WEIGHT_BPS,
            forced_exit_compatibility_depth: DEFAULT_FORCED_EXIT_COMPATIBILITY_DEPTH,
            wallet_reconstruction_shards: DEFAULT_WALLET_RECONSTRUCTION_SHARDS,
            encrypted_receipt_shards_required: true,
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
            "base_l2_height": self.base_l2_height,
            "low_fee_cap_atomic": self.low_fee_cap_atomic.to_string(),
            "metadata_budget_units": self.metadata_budget_units,
            "min_pq_authorization_weight_bps": self.min_pq_authorization_weight_bps,
            "forced_exit_compatibility_depth": self.forced_exit_compatibility_depth,
            "wallet_reconstruction_shards": self.wallet_reconstruction_shards,
            "encrypted_receipt_shards_required": self.encrypted_receipt_shards_required,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateTransferExecution {
    pub transfer_id: String,
    pub action_id: String,
    pub asset_id: String,
    pub input_note_roots: Vec<String>,
    pub input_nullifier_roots: Vec<String>,
    pub output_commitments: Vec<String>,
    pub action_receipt_commitment: String,
    pub encrypted_receipt_shards: Vec<EncryptedReceiptShard>,
    pub low_fee_cap: LowFeeCap,
    pub pq_authorization: PqAuthorization,
    pub metadata_budget: MetadataBudget,
    pub wallet_reconstruction: WalletReconstruction,
    pub forced_exit_compatibility: ForcedExitCompatibility,
    pub executed_at_height: u64,
}

impl PrivateTransferExecution {
    pub fn devnet(config: &Config) -> Self {
        let transfer_id = "devnet-canonical-private-transfer-receipt-exec-0001".to_string();
        let action_id = "devnet-forced-exit-private-note-transfer-action-0001".to_string();
        let asset_id = "xmr-l2-private-note".to_string();
        let amount_root = label_root("amount_commitment", "devnet-private-transfer-action");
        let input_note_roots = vec![
            note_root("input_note", &transfer_id, 0, &asset_id, &amount_root),
            note_root("input_note", &transfer_id, 1, &asset_id, &amount_root),
        ];
        let input_nullifier_roots = vec![
            label_root("input_nullifier", "devnet-private-note-nullifier-0"),
            label_root("input_nullifier", "devnet-private-note-nullifier-1"),
        ];
        let output_commitments = vec![
            note_root("recipient_output", &transfer_id, 0, &asset_id, &amount_root),
            note_root("change_output", &transfer_id, 1, &asset_id, &amount_root),
            note_root(
                "forced_exit_receipt_output",
                &transfer_id,
                2,
                &asset_id,
                &amount_root,
            ),
        ];
        let action_transcript_root = action_transcript_root(
            &transfer_id,
            &action_id,
            &input_note_roots,
            &input_nullifier_roots,
            &output_commitments,
        );
        let encrypted_receipt_shards = vec![
            EncryptedReceiptShard::devnet("recipient", 0, &transfer_id, &action_transcript_root),
            EncryptedReceiptShard::devnet(
                "sender_change",
                1,
                &transfer_id,
                &action_transcript_root,
            ),
            EncryptedReceiptShard::devnet(
                "forced_exit_recovery",
                2,
                &transfer_id,
                &action_transcript_root,
            ),
        ];
        let low_fee_cap = LowFeeCap::devnet(config, &transfer_id);
        let pq_authorization =
            PqAuthorization::devnet(config, &transfer_id, &action_transcript_root);
        let metadata_budget = MetadataBudget::devnet(config, &transfer_id);
        let wallet_reconstruction =
            WalletReconstruction::devnet(config, &transfer_id, &encrypted_receipt_shards);
        let forced_exit_compatibility =
            ForcedExitCompatibility::devnet(config, &transfer_id, &action_transcript_root);
        let action_receipt_commitment = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-ACTION-RECEIPT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&transfer_id),
                HashPart::Str(&action_id),
                HashPart::Str(&action_transcript_root),
                HashPart::Str(&low_fee_cap.cap_root),
                HashPart::Str(&pq_authorization.authorization_root),
                HashPart::Str(&metadata_budget.budget_root),
                HashPart::Str(&wallet_reconstruction.reconstruction_root),
                HashPart::Str(&forced_exit_compatibility.compatibility_root),
            ],
            32,
        );

        Self {
            transfer_id,
            action_id,
            asset_id,
            input_note_roots,
            input_nullifier_roots,
            output_commitments,
            action_receipt_commitment,
            encrypted_receipt_shards,
            low_fee_cap,
            pq_authorization,
            metadata_budget,
            wallet_reconstruction,
            forced_exit_compatibility,
            executed_at_height: config.base_l2_height + 7,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "transfer_id": self.transfer_id,
            "action_id": self.action_id,
            "asset_id": self.asset_id,
            "input_note_roots": self.input_note_roots,
            "input_nullifier_roots": self.input_nullifier_roots,
            "output_commitments": self.output_commitments,
            "action_receipt_commitment": self.action_receipt_commitment,
            "encrypted_receipt_shards": self.encrypted_receipt_shards.iter().map(EncryptedReceiptShard::public_record).collect::<Vec<_>>(),
            "low_fee_cap": self.low_fee_cap.public_record(),
            "pq_authorization": self.pq_authorization.public_record(),
            "metadata_budget": self.metadata_budget.public_record(),
            "wallet_reconstruction": self.wallet_reconstruction.public_record(),
            "forced_exit_compatibility": self.forced_exit_compatibility.public_record(),
            "executed_at_height": self.executed_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("execution", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedReceiptShard {
    pub shard_id: String,
    pub audience: String,
    pub index: u64,
    pub ciphertext_root: String,
    pub view_tag_root: String,
    pub locator_root: String,
}

impl EncryptedReceiptShard {
    pub fn devnet(audience: &str, index: u64, transfer_id: &str, transcript_root: &str) -> Self {
        let shard_id = format!("devnet-{audience}-encrypted-receipt-shard-{index}");
        Self {
            ciphertext_root: encrypted_shard_root("ciphertext", audience, index, transcript_root),
            view_tag_root: encrypted_shard_root("view_tag", audience, index, transfer_id),
            locator_root: encrypted_shard_root("locator", audience, index, transfer_id),
            shard_id,
            audience: audience.to_string(),
            index,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "audience": self.audience,
            "index": self.index,
            "ciphertext_root": self.ciphertext_root,
            "view_tag_root": self.view_tag_root,
            "locator_root": self.locator_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("encrypted_receipt_shard", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeCap {
    pub policy_id: String,
    pub cap_atomic: u128,
    pub cap_root: String,
    pub relayer_rebate_root: String,
}

impl LowFeeCap {
    pub fn devnet(config: &Config, transfer_id: &str) -> Self {
        let policy_id = "devnet-low-fee-private-transfer-exit-cap".to_string();
        let relayer_rebate_root = label_root("relayer_rebate", "devnet-private-receipt-rebate");
        let cap_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-LOW-FEE-CAP",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(transfer_id),
                HashPart::Str(&policy_id),
                HashPart::Int(config.low_fee_cap_atomic as i128),
                HashPart::Str(&relayer_rebate_root),
            ],
            32,
        );
        Self {
            policy_id,
            cap_atomic: config.low_fee_cap_atomic,
            cap_root,
            relayer_rebate_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "cap_atomic": self.cap_atomic.to_string(),
            "cap_root": self.cap_root,
            "relayer_rebate_root": self.relayer_rebate_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAuthorization {
    pub authorization_id: String,
    pub scheme: String,
    pub signer_commitments: Vec<String>,
    pub threshold_weight_bps: u64,
    pub transcript_root: String,
    pub signature_bundle_root: String,
    pub authorization_root: String,
}

impl PqAuthorization {
    pub fn devnet(config: &Config, transfer_id: &str, transcript_root: &str) -> Self {
        let authorization_id = "devnet-pq-private-transfer-receipt-auth-0001".to_string();
        let scheme = "ml-dsa-87-plus-slh-dsa-sha2-256f".to_string();
        let signer_commitments = vec![
            label_root("pq_signer", "wallet-recovery-key-0"),
            label_root("pq_signer", "watcher-committee-key-1"),
            label_root("pq_signer", "bridge-exit-key-2"),
        ];
        let signature_bundle_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-PQ-SIGNATURES",
            &signer_commitments,
        );
        let authorization_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-PQ-AUTHORIZATION",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(transfer_id),
                HashPart::Str(&authorization_id),
                HashPart::Str(&scheme),
                HashPart::Int(config.min_pq_authorization_weight_bps as i128),
                HashPart::Str(transcript_root),
                HashPart::Str(&signature_bundle_root),
            ],
            32,
        );
        Self {
            authorization_id,
            scheme,
            signer_commitments,
            threshold_weight_bps: config.min_pq_authorization_weight_bps,
            transcript_root: transcript_root.to_string(),
            signature_bundle_root,
            authorization_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "scheme": self.scheme,
            "signer_commitments": self.signer_commitments,
            "threshold_weight_bps": self.threshold_weight_bps,
            "transcript_root": self.transcript_root,
            "signature_bundle_root": self.signature_bundle_root,
            "authorization_root": self.authorization_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MetadataBudget {
    pub budget_id: String,
    pub max_units: u64,
    pub used_units: u64,
    pub public_field_root: String,
    pub redaction_root: String,
    pub budget_root: String,
}

impl MetadataBudget {
    pub fn devnet(config: &Config, transfer_id: &str) -> Self {
        let budget_id = "devnet-private-receipt-metadata-budget".to_string();
        let public_field_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-PUBLIC-FIELDS",
            &[
                label_root("public_field", "chain_id"),
                label_root("public_field", "receipt_commitment"),
                label_root("public_field", "low_fee_cap_root"),
                label_root("public_field", "forced_exit_compatibility_root"),
            ],
        );
        let redaction_root = label_root("metadata_redaction", "wallet-local-fields-redacted");
        let budget_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-METADATA-BUDGET",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(transfer_id),
                HashPart::Str(&budget_id),
                HashPart::Int(config.metadata_budget_units as i128),
                HashPart::Int(4),
                HashPart::Str(&public_field_root),
                HashPart::Str(&redaction_root),
            ],
            32,
        );
        Self {
            budget_id,
            max_units: config.metadata_budget_units,
            used_units: 4,
            public_field_root,
            redaction_root,
            budget_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "max_units": self.max_units,
            "used_units": self.used_units,
            "public_field_root": self.public_field_root,
            "redaction_root": self.redaction_root,
            "budget_root": self.budget_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletReconstruction {
    pub reconstruction_id: String,
    pub required_shards: u64,
    pub available_shards: u64,
    pub scan_hint_root: String,
    pub recovery_path_root: String,
    pub reconstruction_root: String,
}

impl WalletReconstruction {
    pub fn devnet(
        config: &Config,
        transfer_id: &str,
        receipt_shards: &[EncryptedReceiptShard],
    ) -> Self {
        let reconstruction_id = "devnet-wallet-reconstruction-private-receipt-0001".to_string();
        let shard_roots = receipt_shards
            .iter()
            .map(EncryptedReceiptShard::state_root)
            .collect::<Vec<_>>();
        let scan_hint_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-WALLET-SCAN-HINT",
            &shard_roots,
        );
        let recovery_path_root =
            label_root("wallet_recovery_path", "view-key-plus-receipt-locator");
        let reconstruction_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-WALLET-RECONSTRUCTION",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(transfer_id),
                HashPart::Str(&reconstruction_id),
                HashPart::Int(config.wallet_reconstruction_shards as i128),
                HashPart::Int(receipt_shards.len() as i128),
                HashPart::Str(&scan_hint_root),
                HashPart::Str(&recovery_path_root),
            ],
            32,
        );
        Self {
            reconstruction_id,
            required_shards: config.wallet_reconstruction_shards,
            available_shards: receipt_shards.len() as u64,
            scan_hint_root,
            recovery_path_root,
            reconstruction_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reconstruction_id": self.reconstruction_id,
            "required_shards": self.required_shards,
            "available_shards": self.available_shards,
            "scan_hint_root": self.scan_hint_root,
            "recovery_path_root": self.recovery_path_root,
            "reconstruction_root": self.reconstruction_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitCompatibility {
    pub compatibility_id: String,
    pub parent_exit_root: String,
    pub claim_binding_root: String,
    pub challenge_window_root: String,
    pub release_authorization_root: String,
    pub compatibility_depth: u64,
    pub compatible: bool,
    pub compatibility_root: String,
}

impl ForcedExitCompatibility {
    pub fn devnet(config: &Config, transfer_id: &str, transcript_root: &str) -> Self {
        let compatibility_id = "devnet-forced-exit-private-transfer-receipt-compat".to_string();
        let parent_exit_root = label_root("forced_exit_parent", "devnet-open-private-exit-root");
        let claim_binding_root = label_root("forced_exit_claim", "devnet-private-note-claim");
        let challenge_window_root = label_root("forced_exit_challenge", "devnet-window-armed");
        let release_authorization_root =
            label_root("forced_exit_release", "devnet-pq-release-auth");
        let compatibility_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-FORCED-EXIT-COMPATIBILITY",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(transfer_id),
                HashPart::Str(&compatibility_id),
                HashPart::Str(transcript_root),
                HashPart::Str(&parent_exit_root),
                HashPart::Str(&claim_binding_root),
                HashPart::Str(&challenge_window_root),
                HashPart::Str(&release_authorization_root),
                HashPart::Int(config.forced_exit_compatibility_depth as i128),
                HashPart::Str("compatible"),
            ],
            32,
        );
        Self {
            compatibility_id,
            parent_exit_root,
            claim_binding_root,
            challenge_window_root,
            release_authorization_root,
            compatibility_depth: config.forced_exit_compatibility_depth,
            compatible: true,
            compatibility_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "compatibility_id": self.compatibility_id,
            "parent_exit_root": self.parent_exit_root,
            "claim_binding_root": self.claim_binding_root,
            "challenge_window_root": self.challenge_window_root,
            "release_authorization_root": self.release_authorization_root,
            "compatibility_depth": self.compatibility_depth,
            "compatible": self.compatible,
            "compatibility_root": self.compatibility_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub execution: PrivateTransferExecution,
    pub input_note_root: String,
    pub input_nullifier_root: String,
    pub output_commitment_root: String,
    pub encrypted_receipt_root: String,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let execution = PrivateTransferExecution::devnet(&config);
        let input_note_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-INPUT-NOTES",
            &execution.input_note_roots,
        );
        let input_nullifier_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-INPUT-NULLIFIERS",
            &execution.input_nullifier_roots,
        );
        let output_commitment_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-OUTPUT-COMMITMENTS",
            &execution.output_commitments,
        );
        let encrypted_receipt_roots = execution
            .encrypted_receipt_shards
            .iter()
            .map(EncryptedReceiptShard::state_root)
            .collect::<Vec<_>>();
        let encrypted_receipt_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-ENCRYPTED-RECEIPTS",
            &encrypted_receipt_roots,
        );
        let state_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-RECEIPT-EXECUTION-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.state_root()),
                HashPart::Str(&execution.state_root()),
                HashPart::Str(&input_note_root),
                HashPart::Str(&input_nullifier_root),
                HashPart::Str(&output_commitment_root),
                HashPart::Str(&encrypted_receipt_root),
            ],
            32,
        );
        Self {
            config,
            execution,
            input_note_root,
            input_nullifier_root,
            output_commitment_root,
            encrypted_receipt_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "execution": self.execution.public_record(),
            "input_note_root": self.input_note_root,
            "input_nullifier_root": self.input_nullifier_root,
            "output_commitment_root": self.output_commitment_root,
            "encrypted_receipt_root": self.encrypted_receipt_root,
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

fn label_root(kind: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-LABEL",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

fn note_root(
    kind: &str,
    transfer_id: &str,
    index: u64,
    asset_id: &str,
    amount_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-NOTE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(transfer_id),
            HashPart::Int(index as i128),
            HashPart::Str(asset_id),
            HashPart::Str(amount_root),
        ],
        32,
    )
}

fn encrypted_shard_root(kind: &str, audience: &str, index: u64, seed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-ENCRYPTED-SHARD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(audience),
            HashPart::Int(index as i128),
            HashPart::Str(seed),
        ],
        32,
    )
}

fn action_transcript_root(
    transfer_id: &str,
    action_id: &str,
    input_note_roots: &[String],
    input_nullifier_roots: &[String],
    output_commitments: &[String],
) -> String {
    let input_note_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-TRANSCRIPT-INPUT-NOTES",
        input_note_roots,
    );
    let input_nullifier_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-TRANSCRIPT-NULLIFIERS",
        input_nullifier_roots,
    );
    let output_commitment_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-TRANSCRIPT-OUTPUTS",
        output_commitments,
    );
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-ACTION-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(transfer_id),
            HashPart::Str(action_id),
            HashPart::Str(&input_note_root),
            HashPart::Str(&input_nullifier_root),
            HashPart::Str(&output_commitment_root),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRIVATE-TRANSFER-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
