use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalContractActionReceiptExecutionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_CONTRACT_ACTION_RECEIPT_EXECUTION_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-contract-action-receipt-execution-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_CONTRACT_ACTION_RECEIPT_EXECUTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-contract-action-receipt-v1";
pub const RECEIPT_SUITE: &str =
    "monero-l2-pq-bridge-exit-private-contract-action-receipt-roots-only-v1";
pub const ENCRYPTED_EFFECT_SUITE: &str =
    "xchacha20poly1305-shake256-note-effect-envelope-commitment-v1";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_CALL_FEE_ATOMIC: u128 = 18_000_000;
pub const DEFAULT_MAX_EXIT_REPLAY_FEE_ATOMIC: u128 = 35_000_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub receipt_suite: String,
    pub encrypted_effect_suite: String,
    pub min_pq_security_bits: u16,
    pub max_call_fee_atomic: u128,
    pub max_exit_replay_fee_atomic: u128,
    pub min_privacy_set_size: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            receipt_suite: RECEIPT_SUITE.to_string(),
            encrypted_effect_suite: ENCRYPTED_EFFECT_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_call_fee_atomic: DEFAULT_MAX_CALL_FEE_ATOMIC,
            max_exit_replay_fee_atomic: DEFAULT_MAX_EXIT_REPLAY_FEE_ATOMIC,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "receipt_suite": self.receipt_suite,
            "encrypted_effect_suite": self.encrypted_effect_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_call_fee_atomic": self.max_call_fee_atomic,
            "max_exit_replay_fee_atomic": self.max_exit_replay_fee_atomic,
            "min_privacy_set_size": self.min_privacy_set_size,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateContractCallCommitment {
    pub call_id: String,
    pub contract_commitment: String,
    pub method_selector_commitment: String,
    pub caller_note_root: String,
    pub input_nullifier_root: String,
    pub argument_ciphertext_root: String,
    pub witness_transcript_root: String,
    pub privacy_set_size: u64,
}

impl PrivateContractCallCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "call_id": self.call_id,
            "contract_commitment": self.contract_commitment,
            "method_selector_commitment": self.method_selector_commitment,
            "caller_note_root": self.caller_note_root,
            "input_nullifier_root": self.input_nullifier_root,
            "argument_ciphertext_root": self.argument_ciphertext_root,
            "witness_transcript_root": self.witness_transcript_root,
            "privacy_set_size": self.privacy_set_size,
        })
    }

    pub fn commitment_root(&self) -> String {
        record_root("PRIVATE-CONTRACT-CALL-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedEffect {
    pub effect_id: String,
    pub recipient_note_commitment: String,
    pub ciphertext_root: String,
    pub scan_hint_root: String,
    pub effect_type_commitment: String,
}

impl EncryptedEffect {
    pub fn public_record(&self) -> Value {
        json!({
            "effect_id": self.effect_id,
            "recipient_note_commitment": self.recipient_note_commitment,
            "ciphertext_root": self.ciphertext_root,
            "scan_hint_root": self.scan_hint_root,
            "effect_type_commitment": self.effect_type_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeBounds {
    pub max_call_fee_atomic: u128,
    pub max_exit_replay_fee_atomic: u128,
    pub charged_fee_atomic: u128,
    pub sponsor_commitment: String,
    pub fee_note_commitment: String,
}

impl FeeBounds {
    pub fn public_record(&self) -> Value {
        json!({
            "max_call_fee_atomic": self.max_call_fee_atomic,
            "max_exit_replay_fee_atomic": self.max_exit_replay_fee_atomic,
            "charged_fee_atomic": self.charged_fee_atomic,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_note_commitment": self.fee_note_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSequencerAuthorization {
    pub sequencer_committee_root: String,
    pub pq_auth_root: String,
    pub watcher_attestation_root: String,
    pub release_authority_root: String,
    pub min_security_bits: u16,
}

impl PqSequencerAuthorization {
    pub fn public_record(&self) -> Value {
        json!({
            "sequencer_committee_root": self.sequencer_committee_root,
            "pq_auth_root": self.pq_auth_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "release_authority_root": self.release_authority_root,
            "min_security_bits": self.min_security_bits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MetadataRedaction {
    pub wallet_metadata_policy: String,
    pub redacted_field_root: String,
    pub public_surface_root: String,
    pub redaction_proof_root: String,
}

impl MetadataRedaction {
    pub fn public_record(&self) -> Value {
        json!({
            "wallet_metadata_policy": self.wallet_metadata_policy,
            "redacted_field_root": self.redacted_field_root,
            "public_surface_root": self.public_surface_root,
            "redaction_proof_root": self.redaction_proof_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ContractActionReceipt {
    pub receipt_id: String,
    pub call_commitment_root: String,
    pub execution_receipt_root_before: String,
    pub execution_receipt_root_after: String,
    pub encrypted_effect_root: String,
    pub fee_bound_root: String,
    pub pq_sequencer_auth_root: String,
    pub metadata_redaction_root: String,
    pub exit_replayable: bool,
    pub exit_replay_window_start_height: u64,
    pub exit_replay_window_end_height: u64,
}

impl ContractActionReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "call_commitment_root": self.call_commitment_root,
            "execution_receipt_root_before": self.execution_receipt_root_before,
            "execution_receipt_root_after": self.execution_receipt_root_after,
            "encrypted_effect_root": self.encrypted_effect_root,
            "fee_bound_root": self.fee_bound_root,
            "pq_sequencer_auth_root": self.pq_sequencer_auth_root,
            "metadata_redaction_root": self.metadata_redaction_root,
            "exit_replayable": self.exit_replayable,
            "exit_replay_window_start_height": self.exit_replay_window_start_height,
            "exit_replay_window_end_height": self.exit_replay_window_end_height,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-ACTION-RECEIPT",
            &[
                HashPart::Str(&self.receipt_id),
                HashPart::Str(&self.call_commitment_root),
                HashPart::Str(&self.execution_receipt_root_before),
                HashPart::Str(&self.execution_receipt_root_after),
                HashPart::Str(&self.encrypted_effect_root),
                HashPart::Str(&self.fee_bound_root),
                HashPart::Str(&self.pq_sequencer_auth_root),
                HashPart::Str(&self.metadata_redaction_root),
                HashPart::Str(if self.exit_replayable {
                    "exit_replayable"
                } else {
                    "exit_not_replayable"
                }),
                HashPart::U64(self.exit_replay_window_start_height),
                HashPart::U64(self.exit_replay_window_end_height),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub private_contract_call_commitments: Vec<PrivateContractCallCommitment>,
    pub encrypted_effects: Vec<EncryptedEffect>,
    pub fee_bounds: FeeBounds,
    pub pq_sequencer_authorization: PqSequencerAuthorization,
    pub metadata_redaction: MetadataRedaction,
    pub receipt: ContractActionReceipt,
    pub call_commitment_root: String,
    pub encrypted_effect_root: String,
    pub execution_receipt_root: String,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let call = PrivateContractCallCommitment {
            call_id: scoped_hash("call-id", "devnet-contract-action-0"),
            contract_commitment: scoped_hash("contract", "exit-settlement-covenant-v1"),
            method_selector_commitment: scoped_hash("selector", "settle_private_exit(bytes32)"),
            caller_note_root: scoped_hash("caller-note-root", "wallet-note-set-17"),
            input_nullifier_root: scoped_hash("input-nullifier-root", "nullifier-set-17"),
            argument_ciphertext_root: scoped_hash("argument-ciphertext", "sealed-call-args-17"),
            witness_transcript_root: scoped_hash("witness-transcript", "private-call-witness-17"),
            privacy_set_size: 131_072,
        };
        let encrypted_effects = vec![
            EncryptedEffect {
                effect_id: scoped_hash("effect-id", "recipient-note"),
                recipient_note_commitment: scoped_hash("recipient-note", "wallet-B-private-note"),
                ciphertext_root: scoped_hash("effect-ciphertext", "recipient-delta"),
                scan_hint_root: scoped_hash("scan-hint", "recipient-view-tag"),
                effect_type_commitment: scoped_hash("effect-kind", "minted-exit-claim-note"),
            },
            EncryptedEffect {
                effect_id: scoped_hash("effect-id", "change-note"),
                recipient_note_commitment: scoped_hash("change-note", "wallet-A-change-note"),
                ciphertext_root: scoped_hash("effect-ciphertext", "change-delta"),
                scan_hint_root: scoped_hash("scan-hint", "change-view-tag"),
                effect_type_commitment: scoped_hash("effect-kind", "private-change-note"),
            },
        ];
        let fee_bounds = FeeBounds {
            max_call_fee_atomic: DEFAULT_MAX_CALL_FEE_ATOMIC,
            max_exit_replay_fee_atomic: DEFAULT_MAX_EXIT_REPLAY_FEE_ATOMIC,
            charged_fee_atomic: 12_500_000,
            sponsor_commitment: scoped_hash("fee-sponsor", "devnet-relayer-3"),
            fee_note_commitment: scoped_hash("fee-note", "sequencer-fee-note-17"),
        };
        let pq_sequencer_authorization = PqSequencerAuthorization {
            sequencer_committee_root: scoped_hash("sequencer-committee", "devnet-pq-committee-1"),
            pq_auth_root: scoped_hash("pq-auth", "sequencer-and-wallet-authorized-call-17"),
            watcher_attestation_root: scoped_hash("watcher-root", "watcher-quorum-2-of-3"),
            release_authority_root: scoped_hash("release-authority", "exit-release-authority-1"),
            min_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        };
        let metadata_redaction = MetadataRedaction {
            wallet_metadata_policy: "roots_only_no_address_amount_or_timing_leak".to_string(),
            redacted_field_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-ACTION-REDACTED-FIELDS",
                &[
                    json!("wallet_address"),
                    json!("plaintext_amount"),
                    json!("contract_arguments"),
                    json!("view_key_hint_material"),
                ],
            ),
            public_surface_root: scoped_hash("public-surface", "receipt-roots-only"),
            redaction_proof_root: scoped_hash("redaction-proof", "metadata-redaction-proof-17"),
        };

        let call_commitment_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-ACTION-CALL-COMMITMENTS",
            &[call.public_record()],
        );
        let encrypted_effect_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-ACTION-ENCRYPTED-EFFECTS",
            &encrypted_effects
                .iter()
                .map(EncryptedEffect::public_record)
                .collect::<Vec<_>>(),
        );
        let fee_bound_root = record_root("FEE-BOUNDS", &fee_bounds.public_record());
        let pq_sequencer_auth_root = record_root(
            "PQ-SEQUENCER-AUTH",
            &pq_sequencer_authorization.public_record(),
        );
        let metadata_redaction_root =
            record_root("METADATA-REDACTION", &metadata_redaction.public_record());
        let execution_receipt_root_before =
            scoped_hash("execution-receipt-before", "pre-action-private-state");
        let execution_receipt_root_after = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-ACTION-EXECUTION-AFTER",
            &[
                HashPart::Str(&call_commitment_root),
                HashPart::Str(&encrypted_effect_root),
                HashPart::Str(&fee_bound_root),
                HashPart::Str(&pq_sequencer_auth_root),
                HashPart::Str(&metadata_redaction_root),
            ],
            32,
        );
        let receipt = ContractActionReceipt {
            receipt_id: scoped_hash("receipt-id", "devnet-contract-action-receipt-17"),
            call_commitment_root: call_commitment_root.clone(),
            execution_receipt_root_before,
            execution_receipt_root_after: execution_receipt_root_after.clone(),
            encrypted_effect_root: encrypted_effect_root.clone(),
            fee_bound_root,
            pq_sequencer_auth_root,
            metadata_redaction_root,
            exit_replayable: true,
            exit_replay_window_start_height: 7_200,
            exit_replay_window_end_height: 7_920,
        };
        let execution_receipt_root = receipt.state_root();
        let mut state = Self {
            config,
            private_contract_call_commitments: vec![call],
            encrypted_effects,
            fee_bounds,
            pq_sequencer_authorization,
            metadata_redaction,
            receipt,
            call_commitment_root,
            encrypted_effect_root,
            execution_receipt_root,
            state_root: String::new(),
        };
        state.state_root = state.compute_state_root();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "private_contract_call_commitment_root": self.call_commitment_root,
            "execution_receipt_root": self.execution_receipt_root,
            "encrypted_effect_root": self.encrypted_effect_root,
            "fee_bound_root": self.receipt.fee_bound_root,
            "pq_sequencer_auth_root": self.receipt.pq_sequencer_auth_root,
            "metadata_redaction_root": self.receipt.metadata_redaction_root,
            "receipt": self.receipt.public_record(),
            "exit_replayable": self.receipt.exit_replayable,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-ACTION-RECEIPT-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.call_commitment_root),
                HashPart::Str(&self.encrypted_effect_root),
                HashPart::Str(&self.execution_receipt_root),
                HashPart::Str(&self.receipt.fee_bound_root),
                HashPart::Str(&self.receipt.pq_sequencer_auth_root),
                HashPart::Str(&self.receipt.metadata_redaction_root),
                HashPart::Str(if self.receipt.exit_replayable {
                    "exit_replayable"
                } else {
                    "exit_not_replayable"
                }),
            ],
            32,
        )
    }

    pub fn state_root(&self) -> String {
        self.compute_state_root()
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

fn scoped_hash(label: &str, seed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-ACTION-DEVNET",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(seed),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CONTRACT-ACTION-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}
