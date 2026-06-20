use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitPrivateTransferMinimalPrimitiveRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_PRIVATE_TRANSFER_MINIMAL_PRIMITIVE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-private-transfer-minimal-primitive-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_PRIVATE_TRANSFER_MINIMAL_PRIMITIVE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PRIMITIVE_SUITE: &str = "monero-l2-pq-bridge-exit-minimal-private-transfer-primitive-v1";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 620_240;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_MAX_FEE_CAP_UNITS: u64 = 40_000;
pub const DEFAULT_MAX_WALLET_SCAN_HINTS: u64 = 4;
pub const DEFAULT_FORCED_EXIT_CONTINUITY_DEPTH: u64 = 3;
pub const DEFAULT_MAX_TRANSFERS: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatus {
    Accepted,
    Watch,
    Rejected,
}

impl TransferStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Watch => "watch",
            Self::Rejected => "rejected",
        }
    }

    pub fn passes(self) -> bool {
        matches!(self, Self::Accepted | Self::Watch)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub primitive_suite: String,
    pub base_l2_height: u64,
    pub min_privacy_set_size: u64,
    pub max_fee_cap_units: u64,
    pub max_wallet_scan_hints: u64,
    pub forced_exit_continuity_depth: u64,
    pub encrypted_receipts_required: bool,
    pub forced_exit_continuity_required: bool,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub max_transfers: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            primitive_suite: PRIMITIVE_SUITE.to_string(),
            base_l2_height: DEFAULT_DEVNET_HEIGHT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_fee_cap_units: DEFAULT_MAX_FEE_CAP_UNITS,
            max_wallet_scan_hints: DEFAULT_MAX_WALLET_SCAN_HINTS,
            forced_exit_continuity_depth: DEFAULT_FORCED_EXIT_CONTINUITY_DEPTH,
            encrypted_receipts_required: true,
            forced_exit_continuity_required: true,
            cargo_checks_deferred: true,
            production_release_allowed: false,
            max_transfers: DEFAULT_MAX_TRANSFERS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "primitive_suite": self.primitive_suite,
            "base_l2_height": self.base_l2_height,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_fee_cap_units": self.max_fee_cap_units,
            "max_wallet_scan_hints": self.max_wallet_scan_hints,
            "forced_exit_continuity_depth": self.forced_exit_continuity_depth,
            "encrypted_receipts_required": self.encrypted_receipts_required,
            "forced_exit_continuity_required": self.forced_exit_continuity_required,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_transfers": self.max_transfers,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateTransferRequest {
    pub transfer_id: String,
    pub input_note_commitments: Vec<String>,
    pub output_note_commitments: Vec<String>,
    pub nullifier_commitments: Vec<String>,
    pub key_image_commitments: Vec<String>,
    pub encrypted_receipt_root: String,
    pub wallet_scan_hint_roots: Vec<String>,
    pub forced_exit_parent_root: String,
    pub forced_exit_next_root: String,
    pub asset_id: String,
    pub amount_commitment_root: String,
    pub balance_proof_root: String,
    pub fee_cap_units: u64,
    pub privacy_set_size: u64,
    pub l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NoteInputCommitmentBinding {
    pub binding_id: String,
    pub transfer_id: String,
    pub input_note_commitment: String,
    pub spend_authority_commitment_root: String,
    pub membership_witness_root: String,
    pub amount_commitment_root: String,
    pub asset_id: String,
    pub leaf_index_commitment: String,
    pub input_position: u64,
}

impl NoteInputCommitmentBinding {
    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "transfer_id": self.transfer_id,
            "input_note_commitment": self.input_note_commitment,
            "spend_authority_commitment_root": self.spend_authority_commitment_root,
            "membership_witness_root": self.membership_witness_root,
            "amount_commitment_root": self.amount_commitment_root,
            "asset_id": self.asset_id,
            "leaf_index_commitment": self.leaf_index_commitment,
            "input_position": self.input_position,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("input_binding", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OutputNoteCommitment {
    pub output_id: String,
    pub transfer_id: String,
    pub output_note_commitment: String,
    pub recipient_view_tag_root: String,
    pub recipient_spend_commitment_root: String,
    pub amount_commitment_root: String,
    pub asset_id: String,
    pub output_position: u64,
    pub note_leaf_index: u64,
}

impl OutputNoteCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "output_id": self.output_id,
            "transfer_id": self.transfer_id,
            "output_note_commitment": self.output_note_commitment,
            "recipient_view_tag_root": self.recipient_view_tag_root,
            "recipient_spend_commitment_root": self.recipient_spend_commitment_root,
            "amount_commitment_root": self.amount_commitment_root,
            "asset_id": self.asset_id,
            "output_position": self.output_position,
            "note_leaf_index": self.note_leaf_index,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("output_note", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NullifierKeyImageCommitment {
    pub nullifier_id: String,
    pub transfer_id: String,
    pub nullifier_commitment: String,
    pub key_image_commitment: String,
    pub input_note_commitment: String,
    pub replay_fence_root: String,
    pub action_domain_root: String,
    pub nullifier_leaf_index: u64,
}

impl NullifierKeyImageCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "transfer_id": self.transfer_id,
            "nullifier_commitment": self.nullifier_commitment,
            "key_image_commitment": self.key_image_commitment,
            "input_note_commitment": self.input_note_commitment,
            "replay_fence_root": self.replay_fence_root,
            "action_domain_root": self.action_domain_root,
            "nullifier_leaf_index": self.nullifier_leaf_index,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("nullifier_key_image", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedReceiptAnchor {
    pub receipt_id: String,
    pub transfer_id: String,
    pub encrypted_receipt_root: String,
    pub ciphertext_bundle_root: String,
    pub receipt_index_root: String,
    pub availability_root: String,
    pub anchored_at_height: u64,
}

impl EncryptedReceiptAnchor {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "transfer_id": self.transfer_id,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "ciphertext_bundle_root": self.ciphertext_bundle_root,
            "receipt_index_root": self.receipt_index_root,
            "availability_root": self.availability_root,
            "anchored_at_height": self.anchored_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("encrypted_receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletScanHint {
    pub hint_id: String,
    pub transfer_id: String,
    pub hint_root: String,
    pub view_tag_root: String,
    pub subaddress_hint_root: String,
    pub receipt_hint_root: String,
    pub scan_window_start: u64,
    pub scan_window_end: u64,
}

impl WalletScanHint {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "transfer_id": self.transfer_id,
            "hint_root": self.hint_root,
            "view_tag_root": self.view_tag_root,
            "subaddress_hint_root": self.subaddress_hint_root,
            "receipt_hint_root": self.receipt_hint_root,
            "scan_window_start": self.scan_window_start,
            "scan_window_end": self.scan_window_end,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("wallet_scan_hint", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeCapGuard {
    pub guard_id: String,
    pub transfer_id: String,
    pub fee_cap_units: u64,
    pub max_fee_cap_units: u64,
    pub fee_asset_id: String,
    pub fee_policy_root: String,
}

impl FeeCapGuard {
    pub fn public_record(&self) -> Value {
        json!({
            "guard_id": self.guard_id,
            "transfer_id": self.transfer_id,
            "fee_cap_units": self.fee_cap_units,
            "max_fee_cap_units": self.max_fee_cap_units,
            "fee_asset_id": self.fee_asset_id,
            "fee_policy_root": self.fee_policy_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("fee_cap_guard", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitContinuityLink {
    pub link_id: String,
    pub transfer_id: String,
    pub parent_exit_root: String,
    pub transfer_receipt_root: String,
    pub next_exit_root: String,
    pub continuity_depth: u64,
    pub liveness_height: u64,
}

impl ForcedExitContinuityLink {
    pub fn public_record(&self) -> Value {
        json!({
            "link_id": self.link_id,
            "transfer_id": self.transfer_id,
            "parent_exit_root": self.parent_exit_root,
            "transfer_receipt_root": self.transfer_receipt_root,
            "next_exit_root": self.next_exit_root,
            "continuity_depth": self.continuity_depth,
            "liveness_height": self.liveness_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("forced_exit_continuity", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateTransferRecord {
    pub transfer_id: String,
    pub status: TransferStatus,
    pub input_binding_root: String,
    pub output_note_root: String,
    pub nullifier_key_image_root: String,
    pub encrypted_receipt_root: String,
    pub wallet_scan_hint_root: String,
    pub fee_cap_guard_root: String,
    pub forced_exit_continuity_root: String,
    pub asset_id: String,
    pub amount_commitment_root: String,
    pub balance_proof_root: String,
    pub privacy_set_size: u64,
    pub l2_height: u64,
    pub rejection_root: String,
}

impl PrivateTransferRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "transfer_id": self.transfer_id,
            "status": self.status.as_str(),
            "input_binding_root": self.input_binding_root,
            "output_note_root": self.output_note_root,
            "nullifier_key_image_root": self.nullifier_key_image_root,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "wallet_scan_hint_root": self.wallet_scan_hint_root,
            "fee_cap_guard_root": self.fee_cap_guard_root,
            "forced_exit_continuity_root": self.forced_exit_continuity_root,
            "asset_id": self.asset_id,
            "amount_commitment_root": self.amount_commitment_root,
            "balance_proof_root": self.balance_proof_root,
            "privacy_set_size": self.privacy_set_size,
            "l2_height": self.l2_height,
            "rejection_root": self.rejection_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("private_transfer", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub input_bindings: BTreeMap<String, NoteInputCommitmentBinding>,
    pub output_notes: BTreeMap<String, OutputNoteCommitment>,
    pub nullifier_key_images: BTreeMap<String, NullifierKeyImageCommitment>,
    pub encrypted_receipts: BTreeMap<String, EncryptedReceiptAnchor>,
    pub wallet_scan_hints: BTreeMap<String, WalletScanHint>,
    pub fee_cap_guards: BTreeMap<String, FeeCapGuard>,
    pub forced_exit_links: BTreeMap<String, ForcedExitContinuityLink>,
    pub transfers: BTreeMap<String, PrivateTransferRecord>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            input_bindings: BTreeMap::new(),
            output_notes: BTreeMap::new(),
            nullifier_key_images: BTreeMap::new(),
            encrypted_receipts: BTreeMap::new(),
            wallet_scan_hints: BTreeMap::new(),
            fee_cap_guards: BTreeMap::new(),
            forced_exit_links: BTreeMap::new(),
            transfers: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        state
            .apply_private_transfer(PrivateTransferRequest::devnet())
            .expect("devnet private transfer fixture must satisfy primitive guards");
        state
    }

    pub fn apply_private_transfer(
        &mut self,
        request: PrivateTransferRequest,
    ) -> Result<PrivateTransferRecord> {
        self.validate_request(&request)?;
        let rejection_root = empty_root("private_transfer_rejection");
        let input_bindings = request
            .input_note_commitments
            .iter()
            .enumerate()
            .map(|(position, input_note_commitment)| {
                NoteInputCommitmentBinding::from_request(
                    &request,
                    position as u64,
                    input_note_commitment,
                )
            })
            .collect::<Vec<_>>();
        let output_notes = request
            .output_note_commitments
            .iter()
            .enumerate()
            .map(|(position, output_note_commitment)| {
                OutputNoteCommitment::from_request(
                    self,
                    &request,
                    position as u64,
                    output_note_commitment,
                )
            })
            .collect::<Vec<_>>();
        let nullifier_key_images = request
            .nullifier_commitments
            .iter()
            .zip(request.key_image_commitments.iter())
            .zip(request.input_note_commitments.iter())
            .enumerate()
            .map(
                |(
                    position,
                    ((nullifier_commitment, key_image_commitment), input_note_commitment),
                )| {
                    NullifierKeyImageCommitment::from_request(
                        self,
                        &request,
                        position as u64,
                        nullifier_commitment,
                        key_image_commitment,
                        input_note_commitment,
                    )
                },
            )
            .collect::<Vec<_>>();
        let encrypted_receipt = EncryptedReceiptAnchor::from_request(&request);
        let wallet_scan_hints = request
            .wallet_scan_hint_roots
            .iter()
            .enumerate()
            .map(|(position, hint_root)| {
                WalletScanHint::from_request(&request, position as u64, hint_root)
            })
            .collect::<Vec<_>>();
        let fee_cap_guard = FeeCapGuard::from_request(&self.config, &request);
        let forced_exit_link = ForcedExitContinuityLink::from_request(&self.config, &request);

        let record = PrivateTransferRecord {
            transfer_id: request.transfer_id.clone(),
            status: TransferStatus::Accepted,
            input_binding_root: merkle_records(
                "input_binding_root",
                &input_bindings
                    .iter()
                    .map(NoteInputCommitmentBinding::public_record)
                    .collect::<Vec<_>>(),
            ),
            output_note_root: merkle_records(
                "output_note_root",
                &output_notes
                    .iter()
                    .map(OutputNoteCommitment::public_record)
                    .collect::<Vec<_>>(),
            ),
            nullifier_key_image_root: merkle_records(
                "nullifier_key_image_root",
                &nullifier_key_images
                    .iter()
                    .map(NullifierKeyImageCommitment::public_record)
                    .collect::<Vec<_>>(),
            ),
            encrypted_receipt_root: encrypted_receipt.state_root(),
            wallet_scan_hint_root: merkle_records(
                "wallet_scan_hint_root",
                &wallet_scan_hints
                    .iter()
                    .map(WalletScanHint::public_record)
                    .collect::<Vec<_>>(),
            ),
            fee_cap_guard_root: fee_cap_guard.state_root(),
            forced_exit_continuity_root: forced_exit_link.state_root(),
            asset_id: request.asset_id.clone(),
            amount_commitment_root: request.amount_commitment_root.clone(),
            balance_proof_root: request.balance_proof_root.clone(),
            privacy_set_size: request.privacy_set_size,
            l2_height: request.l2_height,
            rejection_root,
        };

        for input_binding in input_bindings {
            self.input_bindings
                .insert(input_binding.binding_id.clone(), input_binding);
        }
        for output_note in output_notes {
            self.output_notes
                .insert(output_note.output_id.clone(), output_note);
        }
        for nullifier_key_image in nullifier_key_images {
            self.nullifier_key_images.insert(
                nullifier_key_image.nullifier_id.clone(),
                nullifier_key_image,
            );
        }
        self.encrypted_receipts
            .insert(encrypted_receipt.receipt_id.clone(), encrypted_receipt);
        for wallet_scan_hint in wallet_scan_hints {
            self.wallet_scan_hints
                .insert(wallet_scan_hint.hint_id.clone(), wallet_scan_hint);
        }
        self.fee_cap_guards
            .insert(fee_cap_guard.guard_id.clone(), fee_cap_guard);
        self.forced_exit_links
            .insert(forced_exit_link.link_id.clone(), forced_exit_link);
        self.transfers
            .insert(record.transfer_id.clone(), record.clone());
        self.prune_to_limit();
        Ok(record)
    }

    pub fn validate_request(&self, request: &PrivateTransferRequest) -> Result<()> {
        if request.transfer_id.is_empty() {
            return Err("transfer_id is required".to_string());
        }
        if self.transfers.contains_key(&request.transfer_id) {
            return Err(format!("transfer {} already recorded", request.transfer_id));
        }
        if request.input_note_commitments.is_empty() {
            return Err("at least one input note commitment is required".to_string());
        }
        if request.output_note_commitments.is_empty() {
            return Err("at least one output note commitment is required".to_string());
        }
        if request.nullifier_commitments.len() != request.input_note_commitments.len() {
            return Err("nullifier commitment count must match input note count".to_string());
        }
        if request.key_image_commitments.len() != request.input_note_commitments.len() {
            return Err("key image commitment count must match input note count".to_string());
        }
        if has_duplicates(&request.nullifier_commitments) {
            return Err("duplicate nullifier commitment in transfer".to_string());
        }
        if request
            .nullifier_commitments
            .iter()
            .any(|nullifier| self.nullifier_seen(nullifier))
        {
            return Err("nullifier commitment already spent".to_string());
        }
        if self.config.encrypted_receipts_required && request.encrypted_receipt_root.is_empty() {
            return Err("encrypted receipt root is required".to_string());
        }
        if request.wallet_scan_hint_roots.len() as u64 > self.config.max_wallet_scan_hints {
            return Err("wallet scan hint count exceeds config cap".to_string());
        }
        if request.fee_cap_units > self.config.max_fee_cap_units {
            return Err("fee cap exceeds config maximum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set size below minimum".to_string());
        }
        if self.config.forced_exit_continuity_required
            && (request.forced_exit_parent_root.is_empty()
                || request.forced_exit_next_root.is_empty())
        {
            return Err("forced-exit continuity roots are required".to_string());
        }
        if request.balance_proof_root.is_empty() {
            return Err("balance proof root is required".to_string());
        }
        Ok(())
    }

    pub fn transfer_root(&self) -> String {
        map_root(
            "private_transfer_records",
            self.transfers
                .values()
                .map(PrivateTransferRecord::public_record)
                .collect(),
        )
    }

    pub fn nullifier_root(&self) -> String {
        map_root(
            "private_transfer_nullifier_key_images",
            self.nullifier_key_images
                .values()
                .map(NullifierKeyImageCommitment::public_record)
                .collect(),
        )
    }

    pub fn output_note_root(&self) -> String {
        map_root(
            "private_transfer_output_notes",
            self.output_notes
                .values()
                .map(OutputNoteCommitment::public_record)
                .collect(),
        )
    }

    pub fn encrypted_receipt_root(&self) -> String {
        map_root(
            "private_transfer_encrypted_receipts",
            self.encrypted_receipts
                .values()
                .map(EncryptedReceiptAnchor::public_record)
                .collect(),
        )
    }

    pub fn forced_exit_continuity_root(&self) -> String {
        map_root(
            "private_transfer_forced_exit_links",
            self.forced_exit_links
                .values()
                .map(ForcedExitContinuityLink::public_record)
                .collect(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "input_binding_root": map_root(
                "private_transfer_input_bindings",
                self.input_bindings
                    .values()
                    .map(NoteInputCommitmentBinding::public_record)
                    .collect(),
            ),
            "output_note_root": self.output_note_root(),
            "nullifier_key_image_root": self.nullifier_root(),
            "encrypted_receipt_root": self.encrypted_receipt_root(),
            "wallet_scan_hint_root": map_root(
                "private_transfer_wallet_scan_hints",
                self.wallet_scan_hints
                    .values()
                    .map(WalletScanHint::public_record)
                    .collect(),
            ),
            "fee_cap_guard_root": map_root(
                "private_transfer_fee_cap_guards",
                self.fee_cap_guards
                    .values()
                    .map(FeeCapGuard::public_record)
                    .collect(),
            ),
            "forced_exit_continuity_root": self.forced_exit_continuity_root(),
            "transfer_root": self.transfer_root(),
            "counters": {
                "input_bindings": self.input_bindings.len(),
                "output_notes": self.output_notes.len(),
                "nullifier_key_images": self.nullifier_key_images.len(),
                "encrypted_receipts": self.encrypted_receipts.len(),
                "wallet_scan_hints": self.wallet_scan_hints.len(),
                "fee_cap_guards": self.fee_cap_guards.len(),
                "forced_exit_links": self.forced_exit_links.len(),
                "transfers": self.transfers.len(),
            },
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
    }

    pub fn production_release_allowed(&self) -> bool {
        self.config.production_release_allowed
            && !self.config.cargo_checks_deferred
            && self
                .transfers
                .values()
                .all(|transfer| transfer.status.passes())
    }

    pub fn nullifier_seen(&self, nullifier_commitment: &str) -> bool {
        self.nullifier_key_images
            .values()
            .any(|entry| entry.nullifier_commitment == nullifier_commitment)
    }

    fn prune_to_limit(&mut self) {
        while self.transfers.len() > self.config.max_transfers {
            if let Some(oldest_transfer_id) = self.transfers.keys().next().cloned() {
                self.transfers.remove(&oldest_transfer_id);
            } else {
                break;
            }
        }
    }
}

impl PrivateTransferRequest {
    pub fn devnet() -> Self {
        let transfer_id = "devnet-private-transfer-0001".to_string();
        let asset_id = "xmr-l2-private-note".to_string();
        let amount_commitment_root = label_root("amount", "devnet-locked-value-commitment");
        let input_note_commitments = vec![note_commitment(
            "input",
            &transfer_id,
            0,
            &asset_id,
            &amount_commitment_root,
        )];
        let output_note_commitments = vec![
            note_commitment(
                "output",
                &transfer_id,
                0,
                &asset_id,
                &amount_commitment_root,
            ),
            note_commitment(
                "change",
                &transfer_id,
                1,
                &asset_id,
                &amount_commitment_root,
            ),
        ];
        let nullifier_commitments = vec![label_root("nullifier", "devnet-transfer-input-0")];
        let key_image_commitments = vec![label_root("key_image", "devnet-transfer-input-0")];
        let encrypted_receipt_root = label_root("encrypted_receipt", &transfer_id);
        let wallet_scan_hint_roots = vec![
            label_root("wallet_scan_hint", "recipient-viewtag-0"),
            label_root("wallet_scan_hint", "sender-change-1"),
        ];
        Self {
            transfer_id,
            input_note_commitments,
            output_note_commitments,
            nullifier_commitments,
            key_image_commitments,
            encrypted_receipt_root,
            wallet_scan_hint_roots,
            forced_exit_parent_root: label_root("forced_exit_parent", "devnet-live-exit-queue"),
            forced_exit_next_root: label_root("forced_exit_next", "devnet-after-private-transfer"),
            asset_id,
            amount_commitment_root,
            balance_proof_root: label_root("balance_proof", "input-equals-output-plus-fee-cap"),
            fee_cap_units: 30_000,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            l2_height: DEFAULT_DEVNET_HEIGHT + 1,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "transfer_id": self.transfer_id,
            "input_note_commitments": self.input_note_commitments,
            "output_note_commitments": self.output_note_commitments,
            "nullifier_commitments": self.nullifier_commitments,
            "key_image_commitments": self.key_image_commitments,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "wallet_scan_hint_roots": self.wallet_scan_hint_roots,
            "forced_exit_parent_root": self.forced_exit_parent_root,
            "forced_exit_next_root": self.forced_exit_next_root,
            "asset_id": self.asset_id,
            "amount_commitment_root": self.amount_commitment_root,
            "balance_proof_root": self.balance_proof_root,
            "fee_cap_units": self.fee_cap_units,
            "privacy_set_size": self.privacy_set_size,
            "l2_height": self.l2_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("private_transfer_request", &self.public_record())
    }
}

impl NoteInputCommitmentBinding {
    fn from_request(
        request: &PrivateTransferRequest,
        input_position: u64,
        input_note_commitment: &str,
    ) -> Self {
        let binding_id = domain_hash(
            "PRIVATE-TRANSFER-INPUT-BINDING-ID",
            &[
                HashPart::Str(&request.transfer_id),
                HashPart::Str(input_note_commitment),
                HashPart::U64(input_position),
            ],
            32,
        );
        Self {
            binding_id,
            transfer_id: request.transfer_id.clone(),
            input_note_commitment: input_note_commitment.to_string(),
            spend_authority_commitment_root: label_root("spend_authority", input_note_commitment),
            membership_witness_root: label_root("membership_witness", input_note_commitment),
            amount_commitment_root: request.amount_commitment_root.clone(),
            asset_id: request.asset_id.clone(),
            leaf_index_commitment: label_root("leaf_index", input_note_commitment),
            input_position,
        }
    }
}

impl OutputNoteCommitment {
    fn from_request(
        state: &State,
        request: &PrivateTransferRequest,
        output_position: u64,
        output_note_commitment: &str,
    ) -> Self {
        let output_id = domain_hash(
            "PRIVATE-TRANSFER-OUTPUT-NOTE-ID",
            &[
                HashPart::Str(&request.transfer_id),
                HashPart::Str(output_note_commitment),
                HashPart::U64(output_position),
            ],
            32,
        );
        Self {
            output_id,
            transfer_id: request.transfer_id.clone(),
            output_note_commitment: output_note_commitment.to_string(),
            recipient_view_tag_root: label_root("recipient_view_tag", output_note_commitment),
            recipient_spend_commitment_root: label_root(
                "recipient_spend_commitment",
                output_note_commitment,
            ),
            amount_commitment_root: request.amount_commitment_root.clone(),
            asset_id: request.asset_id.clone(),
            output_position,
            note_leaf_index: state.output_notes.len() as u64 + output_position,
        }
    }
}

impl NullifierKeyImageCommitment {
    fn from_request(
        state: &State,
        request: &PrivateTransferRequest,
        position: u64,
        nullifier_commitment: &str,
        key_image_commitment: &str,
        input_note_commitment: &str,
    ) -> Self {
        let nullifier_id = domain_hash(
            "PRIVATE-TRANSFER-NULLIFIER-KEY-IMAGE-ID",
            &[
                HashPart::Str(&request.transfer_id),
                HashPart::Str(nullifier_commitment),
                HashPart::Str(key_image_commitment),
                HashPart::U64(position),
            ],
            32,
        );
        Self {
            nullifier_id,
            transfer_id: request.transfer_id.clone(),
            nullifier_commitment: nullifier_commitment.to_string(),
            key_image_commitment: key_image_commitment.to_string(),
            input_note_commitment: input_note_commitment.to_string(),
            replay_fence_root: label_root("replay_fence", &request.transfer_id),
            action_domain_root: label_root("action_domain", PRIMITIVE_SUITE),
            nullifier_leaf_index: state.nullifier_key_images.len() as u64 + position,
        }
    }
}

impl EncryptedReceiptAnchor {
    fn from_request(request: &PrivateTransferRequest) -> Self {
        let receipt_id = domain_hash(
            "PRIVATE-TRANSFER-ENCRYPTED-RECEIPT-ID",
            &[
                HashPart::Str(&request.transfer_id),
                HashPart::Str(&request.encrypted_receipt_root),
            ],
            32,
        );
        Self {
            receipt_id,
            transfer_id: request.transfer_id.clone(),
            encrypted_receipt_root: request.encrypted_receipt_root.clone(),
            ciphertext_bundle_root: label_root(
                "ciphertext_bundle",
                &request.encrypted_receipt_root,
            ),
            receipt_index_root: label_root("receipt_index", &request.transfer_id),
            availability_root: label_root("receipt_availability", &request.encrypted_receipt_root),
            anchored_at_height: request.l2_height,
        }
    }
}

impl WalletScanHint {
    fn from_request(request: &PrivateTransferRequest, position: u64, hint_root: &str) -> Self {
        let hint_id = domain_hash(
            "PRIVATE-TRANSFER-WALLET-SCAN-HINT-ID",
            &[
                HashPart::Str(&request.transfer_id),
                HashPart::Str(hint_root),
                HashPart::U64(position),
            ],
            32,
        );
        Self {
            hint_id,
            transfer_id: request.transfer_id.clone(),
            hint_root: hint_root.to_string(),
            view_tag_root: label_root("view_tag", hint_root),
            subaddress_hint_root: label_root("subaddress_hint", hint_root),
            receipt_hint_root: label_root("receipt_hint", &request.encrypted_receipt_root),
            scan_window_start: request.l2_height,
            scan_window_end: request.l2_height + 96,
        }
    }
}

impl FeeCapGuard {
    fn from_request(config: &Config, request: &PrivateTransferRequest) -> Self {
        let guard_id = domain_hash(
            "PRIVATE-TRANSFER-FEE-CAP-GUARD-ID",
            &[
                HashPart::Str(&request.transfer_id),
                HashPart::U64(request.fee_cap_units),
                HashPart::U64(config.max_fee_cap_units),
            ],
            32,
        );
        Self {
            guard_id,
            transfer_id: request.transfer_id.clone(),
            fee_cap_units: request.fee_cap_units,
            max_fee_cap_units: config.max_fee_cap_units,
            fee_asset_id: request.asset_id.clone(),
            fee_policy_root: label_root("fee_policy", "minimal-private-transfer-fee-cap"),
        }
    }
}

impl ForcedExitContinuityLink {
    fn from_request(config: &Config, request: &PrivateTransferRequest) -> Self {
        let transfer_receipt_root = domain_hash(
            "PRIVATE-TRANSFER-FORCED-EXIT-RECEIPT-ROOT",
            &[
                HashPart::Str(&request.transfer_id),
                HashPart::Str(&request.encrypted_receipt_root),
                HashPart::Str(&request.forced_exit_parent_root),
                HashPart::Str(&request.forced_exit_next_root),
            ],
            32,
        );
        let link_id = domain_hash(
            "PRIVATE-TRANSFER-FORCED-EXIT-CONTINUITY-ID",
            &[
                HashPart::Str(&request.transfer_id),
                HashPart::Str(&transfer_receipt_root),
            ],
            32,
        );
        Self {
            link_id,
            transfer_id: request.transfer_id.clone(),
            parent_exit_root: request.forced_exit_parent_root.clone(),
            transfer_receipt_root,
            next_exit_root: request.forced_exit_next_root.clone(),
            continuity_depth: config.forced_exit_continuity_depth,
            liveness_height: request.l2_height + config.forced_exit_continuity_depth,
        }
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

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-TRANSFER-MINIMAL-PRIMITIVE-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn map_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn merkle_records(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn label_root(domain: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-TRANSFER-MINIMAL-PRIMITIVE-LABEL",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}

fn note_commitment(
    domain: &str,
    transfer_id: &str,
    position: u64,
    asset_id: &str,
    amount_commitment_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-TRANSFER-MINIMAL-NOTE-COMMITMENT",
        &[
            HashPart::Str(domain),
            HashPart::Str(transfer_id),
            HashPart::U64(position),
            HashPart::Str(asset_id),
            HashPart::Str(amount_commitment_root),
        ],
        32,
    )
}

fn has_duplicates(values: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().any(|value| !seen.insert(value))
}
