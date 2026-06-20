use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapePrivateNoteTransferProofRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_PRIVATE_NOTE_TRANSFER_PROOF_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-private-note-transfer-proof-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_PRIVATE_NOTE_TRANSFER_PROOF_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PROOF_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-private-note-transfer-proof-v1";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 744_128;
pub const DEFAULT_METADATA_BUDGET_UNITS: u64 = 5;
pub const DEFAULT_MAX_SCAN_HINT_BITS: u16 = 18;
pub const DEFAULT_MIN_ANONYMITY_SET_SIZE: u64 = 8_192;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub proof_suite: String,
    pub devnet_height: u64,
    pub metadata_budget_units: u64,
    pub max_scan_hint_bits: u16,
    pub min_anonymity_set_size: u64,
    pub min_pq_security_bits: u16,
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
            proof_suite: PROOF_SUITE.to_string(),
            devnet_height: DEFAULT_DEVNET_HEIGHT,
            metadata_budget_units: DEFAULT_METADATA_BUDGET_UNITS,
            max_scan_hint_bits: DEFAULT_MAX_SCAN_HINT_BITS,
            min_anonymity_set_size: DEFAULT_MIN_ANONYMITY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "proof_suite": self.proof_suite,
            "devnet_height": self.devnet_height,
            "metadata_budget_units": self.metadata_budget_units,
            "max_scan_hint_bits": self.max_scan_hint_bits,
            "min_anonymity_set_size": self.min_anonymity_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "production_release_allowed": self.production_release_allowed,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateNoteTransferProof {
    pub escape_package_id: String,
    pub encrypted_note_commitment: DeterministicRoot,
    pub note_tree: DeterministicRoot,
    pub nullifier_key_image_separation: DeterministicRoot,
    pub transfer_action: DeterministicRoot,
    pub contract_action_hook: DeterministicRoot,
    pub wallet_scan_hint: DeterministicRoot,
    pub metadata_budget: MetadataBudget,
    pub pq_withdrawal_authorization: DeterministicRoot,
    pub fail_closed_privacy_gaps: Vec<PrivacyGap>,
    pub proof_root: String,
}

impl PrivateNoteTransferProof {
    pub fn devnet(config: &Config) -> Self {
        let escape_package_id = "devnet-user-escape-private-note-transfer-proof-0001".to_string();
        let encrypted_note_commitment = DeterministicRoot::new(
            "encrypted_note_commitment",
            &escape_package_id,
            &[
                "note_ciphertext_root:v1",
                "amount_commitment:hidden",
                "recipient_view_binding:committed",
            ],
        );
        let note_tree = DeterministicRoot::new(
            "note_tree_root",
            &escape_package_id,
            &[
                "pre_transfer_note_leaf",
                "post_transfer_recipient_note_leaf",
                "post_transfer_change_note_leaf",
            ],
        );
        let nullifier_key_image_separation = DeterministicRoot::new(
            "nullifier_key_image_separation",
            &escape_package_id,
            &[
                "l2_nullifier_domain",
                "monero_key_image_domain",
                "cross_domain_reuse_forbidden",
            ],
        );
        let transfer_action = DeterministicRoot::new(
            "transfer_action_root",
            &escape_package_id,
            &[
                "input_note_membership_verified",
                "output_commitments_balanced",
                "escape_receipt_anchor_bound",
            ],
        );
        let contract_action_hook = DeterministicRoot::new(
            "contract_action_hook_root",
            &escape_package_id,
            &[
                "no_contract_call_requested",
                "hook_root_still_bound",
                "silent_bypass_forbidden",
            ],
        );
        let wallet_scan_hint = DeterministicRoot::new(
            "wallet_scan_hint_root",
            &escape_package_id,
            &[
                "view_tag_prefix_only",
                "address_not_disclosed",
                "recovery_hint_encrypted",
            ],
        );
        let metadata_budget = MetadataBudget::devnet(config, &escape_package_id);
        let pq_withdrawal_authorization = DeterministicRoot::new(
            "pq_withdrawal_authorization_binding",
            &escape_package_id,
            &[
                "ml_dsa_authority_commitment",
                "slh_dsa_fallback_commitment",
                "forced_withdrawal_claim_bound",
            ],
        );
        let fail_closed_privacy_gaps = vec![
            PrivacyGap::closed(
                "ciphertext_shape_leakage",
                "fixed_shard_count_and_padding_root",
                &escape_package_id,
            ),
            PrivacyGap::closed(
                "nullifier_key_image_linkage",
                "separate_domains_and_one_way_binding",
                &escape_package_id,
            ),
            PrivacyGap::closed(
                "wallet_scan_hint_overexposure",
                "prefix_budget_and_encrypted_recovery_hint",
                &escape_package_id,
            ),
            PrivacyGap::closed(
                "metadata_budget_overrun",
                "transfer_rejected_when_budget_exceeded",
                &escape_package_id,
            ),
        ];
        let gap_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-TRANSFER-GAPS",
            fail_closed_privacy_gaps
                .iter()
                .map(PrivacyGap::gap_root)
                .map(Value::String)
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let proof_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-TRANSFER-PROOF",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&escape_package_id),
                HashPart::Str(&encrypted_note_commitment.root),
                HashPart::Str(&note_tree.root),
                HashPart::Str(&nullifier_key_image_separation.root),
                HashPart::Str(&transfer_action.root),
                HashPart::Str(&contract_action_hook.root),
                HashPart::Str(&wallet_scan_hint.root),
                HashPart::Str(&metadata_budget.budget_root),
                HashPart::Str(&pq_withdrawal_authorization.root),
                HashPart::Str(&gap_root),
            ],
            32,
        );

        Self {
            escape_package_id,
            encrypted_note_commitment,
            note_tree,
            nullifier_key_image_separation,
            transfer_action,
            contract_action_hook,
            wallet_scan_hint,
            metadata_budget,
            pq_withdrawal_authorization,
            fail_closed_privacy_gaps,
            proof_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "escape_package_id": self.escape_package_id,
            "encrypted_note_commitment": self.encrypted_note_commitment.public_record(),
            "note_tree": self.note_tree.public_record(),
            "nullifier_key_image_separation": self.nullifier_key_image_separation.public_record(),
            "transfer_action": self.transfer_action.public_record(),
            "contract_action_hook": self.contract_action_hook.public_record(),
            "wallet_scan_hint": self.wallet_scan_hint.public_record(),
            "metadata_budget": self.metadata_budget.public_record(),
            "pq_withdrawal_authorization": self.pq_withdrawal_authorization.public_record(),
            "fail_closed_privacy_gaps": self.fail_closed_privacy_gaps.iter().map(PrivacyGap::public_record).collect::<Vec<_>>(),
            "proof_root": self.proof_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicRoot {
    pub label: String,
    pub leaves: Vec<String>,
    pub root: String,
}

impl DeterministicRoot {
    pub fn new(label: &str, package_id: &str, leaves: &[&str]) -> Self {
        let leaf_roots = leaves
            .iter()
            .enumerate()
            .map(|(index, leaf)| {
                domain_hash(
                    "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-TRANSFER-LEAF",
                    &[
                        HashPart::Str(CHAIN_ID),
                        HashPart::Str(label),
                        HashPart::Str(package_id),
                        HashPart::U64(index as u64),
                        HashPart::Str(leaf),
                    ],
                    32,
                )
            })
            .collect::<Vec<_>>();
        let root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-TRANSFER-ROOT",
            leaf_roots
                .into_iter()
                .map(Value::String)
                .collect::<Vec<_>>()
                .as_slice(),
        );

        Self {
            label: label.to_string(),
            leaves: leaves.iter().map(|leaf| (*leaf).to_string()).collect(),
            root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "label": self.label,
            "leaves": self.leaves,
            "root": self.root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MetadataBudget {
    pub allowed_units: u64,
    pub consumed_units: u64,
    pub excess_units: u64,
    pub fail_closed_when_exceeded: bool,
    pub budget_root: String,
}

impl MetadataBudget {
    pub fn devnet(config: &Config, package_id: &str) -> Self {
        let allowed_units = config.metadata_budget_units;
        let consumed_units = 4;
        let excess_units = consumed_units.saturating_sub(allowed_units);
        let fail_closed_when_exceeded = true;
        let budget_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-TRANSFER-METADATA-BUDGET",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(package_id),
                HashPart::U64(allowed_units),
                HashPart::U64(consumed_units),
                HashPart::U64(excess_units),
                HashPart::Str(if fail_closed_when_exceeded {
                    "fail_closed"
                } else {
                    "fail_open"
                }),
            ],
            32,
        );

        Self {
            allowed_units,
            consumed_units,
            excess_units,
            fail_closed_when_exceeded,
            budget_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "allowed_units": self.allowed_units,
            "consumed_units": self.consumed_units,
            "excess_units": self.excess_units,
            "fail_closed_when_exceeded": self.fail_closed_when_exceeded,
            "budget_root": self.budget_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyGap {
    pub gap_id: String,
    pub closure: String,
    pub fail_closed: bool,
    pub root: String,
}

impl PrivacyGap {
    pub fn closed(gap_id: &str, closure: &str, package_id: &str) -> Self {
        let fail_closed = true;
        let root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-TRANSFER-PRIVACY-GAP",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(package_id),
                HashPart::Str(gap_id),
                HashPart::Str(closure),
                HashPart::Str(if fail_closed {
                    "fail_closed"
                } else {
                    "fail_open"
                }),
            ],
            32,
        );

        Self {
            gap_id: gap_id.to_string(),
            closure: closure.to_string(),
            fail_closed,
            root,
        }
    }

    pub fn gap_root(&self) -> String {
        self.root.clone()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "gap_id": self.gap_id,
            "closure": self.closure,
            "fail_closed": self.fail_closed,
            "root": self.root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub proof: PrivateNoteTransferProof,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let proof = PrivateNoteTransferProof::devnet(&config);
        let state_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-USER-ESCAPE-PRIVATE-NOTE-TRANSFER-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.protocol_version),
                HashPart::Str(&proof.proof_root),
            ],
            32,
        );

        Self {
            config,
            proof,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "proof": self.proof.public_record(),
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
