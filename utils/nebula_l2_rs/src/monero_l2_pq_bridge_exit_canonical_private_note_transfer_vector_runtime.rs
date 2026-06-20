use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalPrivateNoteTransferVectorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PRIVATE_NOTE_TRANSFER_VECTOR_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-private-note-transfer-vector-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PRIVATE_NOTE_TRANSFER_VECTOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 181_440;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const NOTE_COMMITMENT_SCHEME: &str = "deposit-minted-private-note-commitment-v1";
pub const TRANSFER_COMMITMENT_SCHEME: &str = "canonical-private-note-transfer-vector-v1";
pub const NULLIFIER_SCHEME: &str = "monero-l2-nullifier-key-image-root-v1";
pub const ENCRYPTED_RECEIPT_SCHEME: &str = "forced-exit-compatible-encrypted-receipt-root-v1";
pub const SCAN_HINT_SCHEME: &str = "view-tag-scan-hint-root-v1";
pub const DEFAULT_MIN_DEPOSIT_CONFIRMATIONS: u64 = 12;
pub const DEFAULT_MIN_ANONYMITY_SET_SIZE: u64 = 4_096;
pub const DEFAULT_TARGET_ANONYMITY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_MAX_NOTE_INPUTS: usize = 16;
pub const DEFAULT_MAX_NOTE_OUTPUTS: usize = 16;
pub const DEFAULT_MAX_TRANSFERS: usize = 262_144;
pub const DEFAULT_MAX_RECEIPTS: usize = 262_144;
pub const DEFAULT_MAX_FEE_BPS: u64 = 40;
pub const DEFAULT_MAX_FIXED_FEE_UNITS: u64 = 25_000;
pub const DEFAULT_MAX_RELAYER_FEE_UNITS: u64 = 75_000;
pub const DEFAULT_FORCED_EXIT_RECEIPT_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_SCAN_HINT_PREFIX_BITS: u16 = 16;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    Minted,
    TransferPending,
    Spent,
    ForcedExitLocked,
    Cancelled,
}

impl NoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minted => "minted",
            Self::TransferPending => "transfer_pending",
            Self::Spent => "spent",
            Self::ForcedExitLocked => "forced_exit_locked",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatus {
    Submitted,
    Accepted,
    Included,
    Finalized,
    ForcedExitLinkable,
    Rejected,
}

impl TransferStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Included => "included",
            Self::Finalized => "finalized",
            Self::ForcedExitLinkable => "forced_exit_linkable",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldVisibility {
    Public,
    Committed,
    Encrypted,
}

impl FieldVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Committed => "committed",
            Self::Encrypted => "encrypted",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub hash_suite: String,
    pub note_commitment_scheme: String,
    pub transfer_commitment_scheme: String,
    pub nullifier_scheme: String,
    pub encrypted_receipt_scheme: String,
    pub scan_hint_scheme: String,
    pub genesis_height: u64,
    pub min_deposit_confirmations: u64,
    pub min_anonymity_set_size: u64,
    pub target_anonymity_set_size: u64,
    pub max_note_inputs: usize,
    pub max_note_outputs: usize,
    pub max_transfers: usize,
    pub max_receipts: usize,
    pub max_fee_bps: u64,
    pub max_fixed_fee_units: u64,
    pub max_relayer_fee_units: u64,
    pub forced_exit_receipt_ttl_blocks: u64,
    pub scan_hint_prefix_bits: u16,
    pub min_pq_security_bits: u16,
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
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            note_commitment_scheme: NOTE_COMMITMENT_SCHEME.to_string(),
            transfer_commitment_scheme: TRANSFER_COMMITMENT_SCHEME.to_string(),
            nullifier_scheme: NULLIFIER_SCHEME.to_string(),
            encrypted_receipt_scheme: ENCRYPTED_RECEIPT_SCHEME.to_string(),
            scan_hint_scheme: SCAN_HINT_SCHEME.to_string(),
            genesis_height: DEVNET_HEIGHT,
            min_deposit_confirmations: DEFAULT_MIN_DEPOSIT_CONFIRMATIONS,
            min_anonymity_set_size: DEFAULT_MIN_ANONYMITY_SET_SIZE,
            target_anonymity_set_size: DEFAULT_TARGET_ANONYMITY_SET_SIZE,
            max_note_inputs: DEFAULT_MAX_NOTE_INPUTS,
            max_note_outputs: DEFAULT_MAX_NOTE_OUTPUTS,
            max_transfers: DEFAULT_MAX_TRANSFERS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            max_fixed_fee_units: DEFAULT_MAX_FIXED_FEE_UNITS,
            max_relayer_fee_units: DEFAULT_MAX_RELAYER_FEE_UNITS,
            forced_exit_receipt_ttl_blocks: DEFAULT_FORCED_EXIT_RECEIPT_TTL_BLOCKS,
            scan_hint_prefix_bits: DEFAULT_SCAN_HINT_PREFIX_BITS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "hash_suite": self.hash_suite,
            "schemes": {
                "note_commitment": self.note_commitment_scheme,
                "transfer_commitment": self.transfer_commitment_scheme,
                "nullifier": self.nullifier_scheme,
                "encrypted_receipt": self.encrypted_receipt_scheme,
                "scan_hint": self.scan_hint_scheme,
            },
            "limits": {
                "min_deposit_confirmations": self.min_deposit_confirmations,
                "min_anonymity_set_size": self.min_anonymity_set_size,
                "target_anonymity_set_size": self.target_anonymity_set_size,
                "max_note_inputs": self.max_note_inputs,
                "max_note_outputs": self.max_note_outputs,
                "max_transfers": self.max_transfers,
                "max_receipts": self.max_receipts,
                "max_fee_bps": self.max_fee_bps,
                "max_fixed_fee_units": self.max_fixed_fee_units,
                "max_relayer_fee_units": self.max_relayer_fee_units,
                "forced_exit_receipt_ttl_blocks": self.forced_exit_receipt_ttl_blocks,
                "scan_hint_prefix_bits": self.scan_hint_prefix_bits,
                "min_pq_security_bits": self.min_pq_security_bits,
            },
            "genesis_height": self.genesis_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositMintedNoteCommitment {
    pub note_id: String,
    pub deposit_id: String,
    pub monero_txid_root: String,
    pub monero_output_commitment_root: String,
    pub amount_commitment: String,
    pub asset_id: String,
    pub owner_public_address_commitment: String,
    pub spend_authority_commitment: String,
    pub view_key_commitment: String,
    pub note_randomness_commitment: String,
    pub encrypted_note_root: String,
    pub scan_hint_root: String,
    pub minted_at_height: u64,
    pub confirmed_at_height: u64,
    pub status: NoteStatus,
}

impl DepositMintedNoteCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "deposit_id": self.deposit_id,
            "monero_txid_root": self.monero_txid_root,
            "monero_output_commitment_root": self.monero_output_commitment_root,
            "amount_commitment": self.amount_commitment,
            "asset_id": self.asset_id,
            "owner_public_address_commitment": self.owner_public_address_commitment,
            "spend_authority_commitment": self.spend_authority_commitment,
            "view_key_commitment": self.view_key_commitment,
            "note_randomness_commitment": self.note_randomness_commitment,
            "encrypted_note_root": self.encrypted_note_root,
            "scan_hint_root": self.scan_hint_root,
            "minted_at_height": self.minted_at_height,
            "confirmed_at_height": self.confirmed_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTransferInput {
    pub input_index: u16,
    pub note_commitment: String,
    pub nullifier_commitment: String,
    pub key_image_commitment: String,
    pub membership_root: String,
    pub membership_path_commitment: String,
    pub amount_commitment: String,
    pub owner_authorization_root: String,
}

impl PrivateTransferInput {
    pub fn public_record(&self) -> Value {
        json!({
            "input_index": self.input_index,
            "note_commitment": self.note_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "key_image_commitment": self.key_image_commitment,
            "membership_root": self.membership_root,
            "membership_path_commitment": self.membership_path_commitment,
            "amount_commitment": self.amount_commitment,
            "owner_authorization_root": self.owner_authorization_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTransferOutput {
    pub output_index: u16,
    pub note_commitment: String,
    pub amount_commitment: String,
    pub recipient_address_commitment: String,
    pub spend_authority_commitment: String,
    pub view_key_commitment: String,
    pub encrypted_note_root: String,
    pub scan_hint_root: String,
    pub forced_exit_tag_root: String,
}

impl PrivateTransferOutput {
    pub fn public_record(&self) -> Value {
        json!({
            "output_index": self.output_index,
            "note_commitment": self.note_commitment,
            "amount_commitment": self.amount_commitment,
            "recipient_address_commitment": self.recipient_address_commitment,
            "spend_authority_commitment": self.spend_authority_commitment,
            "view_key_commitment": self.view_key_commitment,
            "encrypted_note_root": self.encrypted_note_root,
            "scan_hint_root": self.scan_hint_root,
            "forced_exit_tag_root": self.forced_exit_tag_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCap {
    pub asset_id: String,
    pub max_fee_bps: u64,
    pub max_fixed_fee_units: u64,
    pub max_relayer_fee_units: u64,
    pub fee_commitment_root: String,
}

impl FeeCap {
    pub fn public_record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "max_fee_bps": self.max_fee_bps,
            "max_fixed_fee_units": self.max_fixed_fee_units,
            "max_relayer_fee_units": self.max_relayer_fee_units,
            "fee_commitment_root": self.fee_commitment_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudget {
    pub anonymity_set_size: u64,
    pub decoy_count: u32,
    pub scan_hint_bits: u16,
    pub linkability_budget_bps: u64,
    pub pq_security_bits: u16,
    pub budget_commitment_root: String,
}

impl PrivacyBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "anonymity_set_size": self.anonymity_set_size,
            "decoy_count": self.decoy_count,
            "scan_hint_bits": self.scan_hint_bits,
            "linkability_budget_bps": self.linkability_budget_bps,
            "pq_security_bits": self.pq_security_bits,
            "budget_commitment_root": self.budget_commitment_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanHint {
    pub hint_id: String,
    pub transfer_id: String,
    pub output_index: u16,
    pub view_tag_root: String,
    pub encrypted_hint_root: String,
    pub recipient_group_root: String,
    pub hint_prefix_bits: u16,
}

impl ScanHint {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "transfer_id": self.transfer_id,
            "output_index": self.output_index,
            "view_tag_root": self.view_tag_root,
            "encrypted_hint_root": self.encrypted_hint_root,
            "recipient_group_root": self.recipient_group_root,
            "hint_prefix_bits": self.hint_prefix_bits,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedReceipt {
    pub receipt_id: String,
    pub transfer_id: String,
    pub recipient_receipt_root: String,
    pub sender_receipt_root: String,
    pub operator_receipt_root: String,
    pub forced_exit_receipt_link: String,
    pub ciphertext_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "transfer_id": self.transfer_id,
            "recipient_receipt_root": self.recipient_receipt_root,
            "sender_receipt_root": self.sender_receipt_root,
            "operator_receipt_root": self.operator_receipt_root,
            "forced_exit_receipt_link": self.forced_exit_receipt_link,
            "ciphertext_root": self.ciphertext_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldCommitmentSet {
    pub public_fields_root: String,
    pub committed_fields_root: String,
    pub encrypted_fields_root: String,
}

impl FieldCommitmentSet {
    pub fn public_record(&self) -> Value {
        json!({
            "public_fields_root": self.public_fields_root,
            "committed_fields_root": self.committed_fields_root,
            "encrypted_fields_root": self.encrypted_fields_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateNoteTransfer {
    pub transfer_id: String,
    pub transfer_sequence: u64,
    pub input_root: String,
    pub output_root: String,
    pub nullifier_root: String,
    pub key_image_root: String,
    pub encrypted_receipt_root: String,
    pub scan_hint_root: String,
    pub field_commitments: FieldCommitmentSet,
    pub fee_cap: FeeCap,
    pub privacy_budget: PrivacyBudget,
    pub forced_exit_receipt_link: String,
    pub submitted_at_height: u64,
    pub finalized_at_height: u64,
    pub status: TransferStatus,
}

impl PrivateNoteTransfer {
    pub fn public_record(&self) -> Value {
        json!({
            "transfer_id": self.transfer_id,
            "transfer_sequence": self.transfer_sequence,
            "input_root": self.input_root,
            "output_root": self.output_root,
            "nullifier_root": self.nullifier_root,
            "key_image_root": self.key_image_root,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "scan_hint_root": self.scan_hint_root,
            "field_commitments": self.field_commitments.public_record(),
            "fee_cap": self.fee_cap.public_record(),
            "privacy_budget": self.privacy_budget.public_record(),
            "forced_exit_receipt_link": self.forced_exit_receipt_link,
            "submitted_at_height": self.submitted_at_height,
            "finalized_at_height": self.finalized_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub notes: u64,
    pub transfers: u64,
    pub receipts: u64,
    pub scan_hints: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub notes: BTreeMap<String, DepositMintedNoteCommitment>,
    pub transfers: BTreeMap<String, PrivateNoteTransfer>,
    pub inputs: BTreeMap<String, Vec<PrivateTransferInput>>,
    pub outputs: BTreeMap<String, Vec<PrivateTransferOutput>>,
    pub receipts: BTreeMap<String, EncryptedReceipt>,
    pub scan_hints: BTreeMap<String, ScanHint>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub consumed_key_images: BTreeSet<String>,
    pub counters: Counters,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            notes: BTreeMap::new(),
            transfers: BTreeMap::new(),
            inputs: BTreeMap::new(),
            outputs: BTreeMap::new(),
            receipts: BTreeMap::new(),
            scan_hints: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            consumed_key_images: BTreeSet::new(),
            counters: Counters::default(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let note_a = state.mint_deposit_note(
            "deposit-devnet-0001",
            "monero-devnet-tx-root-0001",
            "monero-devnet-output-root-0001",
            "wallet-alice",
            5_000_000_000,
            DEVNET_HEIGHT + 12,
        );
        let note_b = state.mint_deposit_note(
            "deposit-devnet-0002",
            "monero-devnet-tx-root-0002",
            "monero-devnet-output-root-0002",
            "wallet-bob",
            3_000_000_000,
            DEVNET_HEIGHT + 13,
        );
        let _ = state.submit_private_transfer(
            vec![note_a.note_id.clone()],
            vec!["wallet-carol", "wallet-alice-change"],
            "relayer-devnet",
            DEVNET_HEIGHT + 20,
        );
        let _ = state.submit_private_transfer(
            vec![note_b.note_id.clone()],
            vec!["wallet-dave", "wallet-bob-change"],
            "relayer-devnet",
            DEVNET_HEIGHT + 21,
        );
        state
    }

    pub fn mint_deposit_note(
        &mut self,
        deposit_id: &str,
        monero_txid_root: &str,
        monero_output_commitment_root: &str,
        owner_label: &str,
        amount_units: u64,
        confirmed_at_height: u64,
    ) -> DepositMintedNoteCommitment {
        let sequence = self.counters.notes.saturating_add(1);
        let amount_commitment =
            commitment("NOTE-AMOUNT", &[owner_label, &amount_units.to_string()]);
        let note_id = note_id(deposit_id, monero_output_commitment_root, sequence);
        let note = DepositMintedNoteCommitment {
            note_id: note_id.clone(),
            deposit_id: deposit_id.to_string(),
            monero_txid_root: monero_txid_root.to_string(),
            monero_output_commitment_root: monero_output_commitment_root.to_string(),
            amount_commitment,
            asset_id: self.config.asset_id.clone(),
            owner_public_address_commitment: commitment("OWNER-ADDRESS", &[owner_label]),
            spend_authority_commitment: commitment("SPEND-AUTHORITY", &[owner_label, &note_id]),
            view_key_commitment: commitment("VIEW-KEY", &[owner_label, &note_id]),
            note_randomness_commitment: commitment("NOTE-RANDOMNESS", &[deposit_id, &note_id]),
            encrypted_note_root: encrypted_root(
                "DEPOSIT-NOTE",
                &[owner_label, deposit_id, &note_id],
            ),
            scan_hint_root: scan_hint_root(
                owner_label,
                &note_id,
                self.config.scan_hint_prefix_bits,
            ),
            minted_at_height: self.config.genesis_height,
            confirmed_at_height,
            status: NoteStatus::Minted,
        };
        self.notes.insert(note_id, note.clone());
        self.counters.notes = sequence;
        note
    }

    pub fn submit_private_transfer(
        &mut self,
        note_ids: Vec<String>,
        recipient_labels: Vec<&str>,
        relayer_label: &str,
        submitted_at_height: u64,
    ) -> Result<PrivateNoteTransfer> {
        if note_ids.is_empty() {
            return Err("private transfer requires at least one input note".to_string());
        }
        if note_ids.len() > self.config.max_note_inputs {
            return Err("private transfer exceeds configured input bound".to_string());
        }
        if recipient_labels.is_empty() {
            return Err("private transfer requires at least one output note".to_string());
        }
        if recipient_labels.len() > self.config.max_note_outputs {
            return Err("private transfer exceeds configured output bound".to_string());
        }

        let sequence = self.counters.transfers.saturating_add(1);
        let transfer_id = transfer_id(sequence, &note_ids, submitted_at_height);
        let mut input_records = Vec::with_capacity(note_ids.len());
        let mut inputs = Vec::with_capacity(note_ids.len());
        let mut nullifier_records = Vec::with_capacity(note_ids.len());
        let mut key_image_records = Vec::with_capacity(note_ids.len());
        let membership_root = self.note_root();

        for (index, note_id) in note_ids.iter().enumerate() {
            let note = self
                .notes
                .get_mut(note_id)
                .ok_or_else(|| format!("unknown input note {note_id}"))?;
            if note.status != NoteStatus::Minted {
                return Err(format!("input note {note_id} is not spendable"));
            }
            let nullifier = commitment("NULLIFIER", &[note_id, &transfer_id]);
            let key_image = commitment("KEY-IMAGE", &[note_id, &transfer_id]);
            if self.consumed_nullifiers.contains(&nullifier) {
                return Err(format!("nullifier for {note_id} already consumed"));
            }
            if self.consumed_key_images.contains(&key_image) {
                return Err(format!("key image for {note_id} already consumed"));
            }
            let input = PrivateTransferInput {
                input_index: index as u16,
                note_commitment: note_commitment(note),
                nullifier_commitment: nullifier.clone(),
                key_image_commitment: key_image.clone(),
                membership_root: membership_root.clone(),
                membership_path_commitment: commitment("MEMBERSHIP-PATH", &[note_id, &transfer_id]),
                amount_commitment: note.amount_commitment.clone(),
                owner_authorization_root: commitment("OWNER-AUTH", &[note_id, &transfer_id]),
            };
            note.status = NoteStatus::Spent;
            self.consumed_nullifiers.insert(nullifier);
            self.consumed_key_images.insert(key_image);
            input_records.push(input.public_record());
            nullifier_records.push(json!(input.nullifier_commitment));
            key_image_records.push(json!(input.key_image_commitment));
            inputs.push(input);
        }

        let mut output_records = Vec::with_capacity(recipient_labels.len());
        let mut outputs = Vec::with_capacity(recipient_labels.len());
        let mut hint_records = Vec::with_capacity(recipient_labels.len());
        for (index, recipient) in recipient_labels.iter().enumerate() {
            let recipient_label = *recipient;
            let output_note = output_note_commitment(&transfer_id, recipient_label, index as u16);
            let hint = ScanHint {
                hint_id: hint_id(&transfer_id, index as u16),
                transfer_id: transfer_id.clone(),
                output_index: index as u16,
                view_tag_root: commitment("VIEW-TAG", &[recipient_label, &transfer_id]),
                encrypted_hint_root: encrypted_root("SCAN-HINT", &[recipient_label, &transfer_id]),
                recipient_group_root: commitment("RECIPIENT-GROUP", &[recipient_label]),
                hint_prefix_bits: self.config.scan_hint_prefix_bits,
            };
            let output = PrivateTransferOutput {
                output_index: index as u16,
                note_commitment: output_note,
                amount_commitment: commitment("OUTPUT-AMOUNT", &[recipient_label, &transfer_id]),
                recipient_address_commitment: commitment("RECIPIENT-ADDRESS", &[recipient_label]),
                spend_authority_commitment: commitment(
                    "OUTPUT-SPEND-AUTHORITY",
                    &[recipient_label],
                ),
                view_key_commitment: commitment("OUTPUT-VIEW-KEY", &[recipient_label]),
                encrypted_note_root: encrypted_root(
                    "OUTPUT-NOTE",
                    &[recipient_label, &transfer_id],
                ),
                scan_hint_root: hint.view_tag_root.clone(),
                forced_exit_tag_root: commitment(
                    "FORCED-EXIT-TAG",
                    &[recipient_label, &transfer_id],
                ),
            };
            self.scan_hints.insert(hint.hint_id.clone(), hint.clone());
            output_records.push(output.public_record());
            hint_records.push(hint.public_record());
            outputs.push(output);
        }

        let input_root = merkle_root("CANONICAL-PRIVATE-NOTE-TRANSFER-INPUTS", &input_records);
        let output_root = merkle_root("CANONICAL-PRIVATE-NOTE-TRANSFER-OUTPUTS", &output_records);
        let nullifier_root = merkle_root(
            "CANONICAL-PRIVATE-NOTE-TRANSFER-NULLIFIERS",
            &nullifier_records,
        );
        let key_image_root = merkle_root(
            "CANONICAL-PRIVATE-NOTE-TRANSFER-KEY-IMAGES",
            &key_image_records,
        );
        let scan_hint_root =
            merkle_root("CANONICAL-PRIVATE-NOTE-TRANSFER-SCAN-HINTS", &hint_records);
        let forced_exit_receipt_link =
            forced_exit_receipt_link(&transfer_id, &nullifier_root, &key_image_root);
        let receipt = self.encrypted_receipt(
            &transfer_id,
            &forced_exit_receipt_link,
            relayer_label,
            submitted_at_height,
        );
        let encrypted_receipt_root = merkle_root(
            "CANONICAL-PRIVATE-NOTE-TRANSFER-ENCRYPTED-RECEIPTS",
            &[receipt.public_record()],
        );
        let fee_cap = FeeCap {
            asset_id: self.config.asset_id.clone(),
            max_fee_bps: self.config.max_fee_bps,
            max_fixed_fee_units: self.config.max_fixed_fee_units,
            max_relayer_fee_units: self.config.max_relayer_fee_units,
            fee_commitment_root: commitment("FEE-CAP", &[relayer_label, &transfer_id]),
        };
        let privacy_budget = PrivacyBudget {
            anonymity_set_size: self.config.target_anonymity_set_size,
            decoy_count: self.config.target_anonymity_set_size.saturating_sub(1) as u32,
            scan_hint_bits: self.config.scan_hint_prefix_bits,
            linkability_budget_bps: 1,
            pq_security_bits: self.config.min_pq_security_bits,
            budget_commitment_root: commitment("PRIVACY-BUDGET", &[relayer_label, &transfer_id]),
        };
        let fields = field_commitments(
            &transfer_id,
            &input_root,
            &output_root,
            &encrypted_receipt_root,
            &fee_cap,
            &privacy_budget,
        );
        let transfer = PrivateNoteTransfer {
            transfer_id: transfer_id.clone(),
            transfer_sequence: sequence,
            input_root,
            output_root,
            nullifier_root,
            key_image_root,
            encrypted_receipt_root,
            scan_hint_root,
            field_commitments: fields,
            fee_cap,
            privacy_budget,
            forced_exit_receipt_link,
            submitted_at_height,
            finalized_at_height: submitted_at_height.saturating_add(6),
            status: TransferStatus::ForcedExitLinkable,
        };
        self.inputs.insert(transfer_id.clone(), inputs);
        self.outputs.insert(transfer_id.clone(), outputs);
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        self.transfers.insert(transfer_id, transfer.clone());
        self.counters.transfers = sequence;
        self.counters.receipts = self.receipts.len() as u64;
        self.counters.scan_hints = self.scan_hints.len() as u64;
        Ok(transfer)
    }

    pub fn public_record(&self) -> Value {
        let note_records = self
            .notes
            .values()
            .map(DepositMintedNoteCommitment::public_record)
            .collect::<Vec<_>>();
        let transfer_records = self
            .transfers
            .values()
            .map(PrivateNoteTransfer::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(EncryptedReceipt::public_record)
            .collect::<Vec<_>>();
        let hint_records = self
            .scan_hints
            .values()
            .map(ScanHint::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .consumed_nullifiers
            .iter()
            .map(|v| json!(v))
            .collect::<Vec<_>>();
        let key_image_records = self
            .consumed_key_images
            .iter()
            .map(|v| json!(v))
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "roots": {
                "deposit_minted_note_commitment_root": merkle_root("CANONICAL-PRIVATE-NOTE-DEPOSIT-MINTED-NOTES", &note_records),
                "private_transfer_root": merkle_root("CANONICAL-PRIVATE-NOTE-TRANSFERS", &transfer_records),
                "nullifier_commitment_root": merkle_root("CANONICAL-PRIVATE-NOTE-CONSUMED-NULLIFIERS", &nullifier_records),
                "key_image_commitment_root": merkle_root("CANONICAL-PRIVATE-NOTE-CONSUMED-KEY-IMAGES", &key_image_records),
                "encrypted_receipt_root": merkle_root("CANONICAL-PRIVATE-NOTE-RECEIPTS", &receipt_records),
                "scan_hint_root": merkle_root("CANONICAL-PRIVATE-NOTE-SCAN-HINTS", &hint_records),
            },
            "field_visibility": {
                "public": [
                    "chain_id",
                    "protocol_version",
                    "asset_id",
                    "transfer_id",
                    "roots",
                    "fee_caps",
                    "privacy_budget_bounds",
                    "forced_exit_receipt_link"
                ],
                "committed": [
                    "amounts",
                    "owners",
                    "spend_authorities",
                    "membership_paths",
                    "recipient_addresses",
                    "note_randomness"
                ],
                "encrypted": [
                    "recipient_note_payloads",
                    "sender_change_payloads",
                    "receipt_payloads",
                    "scan_hint_payloads"
                ],
            },
            "counters": {
                "notes": self.counters.notes,
                "transfers": self.counters.transfers,
                "receipts": self.counters.receipts,
                "scan_hints": self.counters.scan_hints,
            },
            "devnet_data": {
                "monero_network": self.config.monero_network,
                "l2_network": self.config.l2_network,
                "height": self.config.genesis_height,
            },
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "CANONICAL-PRIVATE-NOTE-TRANSFER-VECTOR-STATE",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(&self.config.protocol_version),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }

    fn note_root(&self) -> String {
        let records = self
            .notes
            .values()
            .map(DepositMintedNoteCommitment::public_record)
            .collect::<Vec<_>>();
        merkle_root("CANONICAL-PRIVATE-NOTE-MEMBERSHIP", &records)
    }

    fn encrypted_receipt(
        &self,
        transfer_id: &str,
        forced_exit_receipt_link: &str,
        relayer_label: &str,
        opened_at_height: u64,
    ) -> EncryptedReceipt {
        EncryptedReceipt {
            receipt_id: receipt_id(transfer_id, opened_at_height),
            transfer_id: transfer_id.to_string(),
            recipient_receipt_root: encrypted_root("RECIPIENT-RECEIPT", &[transfer_id]),
            sender_receipt_root: encrypted_root("SENDER-RECEIPT", &[transfer_id]),
            operator_receipt_root: encrypted_root(
                "OPERATOR-RECEIPT",
                &[relayer_label, transfer_id],
            ),
            forced_exit_receipt_link: forced_exit_receipt_link.to_string(),
            ciphertext_root: encrypted_root("RECEIPT-CIPHERTEXT", &[relayer_label, transfer_id]),
            opened_at_height,
            expires_at_height: opened_at_height
                .saturating_add(self.config.forced_exit_receipt_ttl_blocks),
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

pub fn note_commitment(note: &DepositMintedNoteCommitment) -> String {
    domain_hash(
        "DEPOSIT-MINTED-NOTE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&note.deposit_id),
            HashPart::Str(&note.monero_txid_root),
            HashPart::Str(&note.monero_output_commitment_root),
            HashPart::Str(&note.amount_commitment),
            HashPart::Str(&note.owner_public_address_commitment),
            HashPart::Str(&note.spend_authority_commitment),
            HashPart::Str(&note.view_key_commitment),
            HashPart::Str(&note.note_randomness_commitment),
            HashPart::Int(note.confirmed_at_height as i128),
        ],
        32,
    )
}

pub fn classify_field(field_name: &str) -> FieldVisibility {
    match field_name {
        "chain_id"
        | "protocol_version"
        | "asset_id"
        | "transfer_id"
        | "roots"
        | "forced_exit_receipt_link" => FieldVisibility::Public,
        "encrypted_note_root"
        | "encrypted_receipt_root"
        | "ciphertext_root"
        | "encrypted_hint_root" => FieldVisibility::Encrypted,
        _ => FieldVisibility::Committed,
    }
}

pub fn forced_exit_receipt_link(
    transfer_id: &str,
    nullifier_root: &str,
    key_image_root: &str,
) -> String {
    domain_hash(
        "FORCED-EXIT-COMPATIBLE-RECEIPT-LINK",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(transfer_id),
            HashPart::Str(nullifier_root),
            HashPart::Str(key_image_root),
        ],
        32,
    )
}

fn field_commitments(
    transfer_id: &str,
    input_root: &str,
    output_root: &str,
    encrypted_receipt_root: &str,
    fee_cap: &FeeCap,
    privacy_budget: &PrivacyBudget,
) -> FieldCommitmentSet {
    let public_fields = json!({
        "transfer_id": transfer_id,
        "input_root": input_root,
        "output_root": output_root,
        "fee_cap": fee_cap.public_record(),
        "privacy_budget": privacy_budget.public_record(),
    });
    let committed_fields = json!({
        "amounts": "amount_commitment_root",
        "owners": "owner_commitment_root",
        "membership": "membership_path_commitment_root",
    });
    let encrypted_fields = json!({
        "encrypted_receipt_root": encrypted_receipt_root,
        "payloads": "recipient_sender_operator_ciphertext_roots",
    });
    FieldCommitmentSet {
        public_fields_root: domain_hash(
            "TRANSFER-PUBLIC-FIELDS",
            &[HashPart::Json(&public_fields)],
            32,
        ),
        committed_fields_root: domain_hash(
            "TRANSFER-COMMITTED-FIELDS",
            &[HashPart::Json(&committed_fields)],
            32,
        ),
        encrypted_fields_root: domain_hash(
            "TRANSFER-ENCRYPTED-FIELDS",
            &[HashPart::Json(&encrypted_fields)],
            32,
        ),
    }
}

fn note_id(deposit_id: &str, output_root: &str, sequence: u64) -> String {
    domain_hash(
        "DEPOSIT-MINTED-NOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(deposit_id),
            HashPart::Str(output_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn transfer_id(sequence: u64, note_ids: &[String], submitted_at_height: u64) -> String {
    let note_records = note_ids
        .iter()
        .map(|note_id| json!(note_id))
        .collect::<Vec<_>>();
    let note_root = merkle_root("TRANSFER-ID-NOTE-IDS", &note_records);
    domain_hash(
        "CANONICAL-PRIVATE-NOTE-TRANSFER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&note_root),
            HashPart::U64(submitted_at_height),
        ],
        32,
    )
}

fn output_note_commitment(transfer_id: &str, recipient: &str, output_index: u16) -> String {
    domain_hash(
        "TRANSFER-OUTPUT-NOTE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(transfer_id),
            HashPart::Str(recipient),
            HashPart::U64(output_index as u64),
        ],
        32,
    )
}

fn receipt_id(transfer_id: &str, opened_at_height: u64) -> String {
    domain_hash(
        "ENCRYPTED-TRANSFER-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(transfer_id),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

fn hint_id(transfer_id: &str, output_index: u16) -> String {
    domain_hash(
        "TRANSFER-SCAN-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(transfer_id),
            HashPart::U64(output_index as u64),
        ],
        32,
    )
}

fn scan_hint_root(owner_label: &str, note_id: &str, prefix_bits: u16) -> String {
    domain_hash(
        "DEPOSIT-NOTE-SCAN-HINT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(owner_label),
            HashPart::Str(note_id),
            HashPart::U64(prefix_bits as u64),
        ],
        32,
    )
}

fn commitment(domain: &str, parts: &[&str]) -> String {
    let values = parts.iter().map(|part| json!(part)).collect::<Vec<_>>();
    let root = merkle_root(&format!("{domain}-PARTS"), &values);
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&root),
        ],
        32,
    )
}

fn encrypted_root(domain: &str, parts: &[&str]) -> String {
    let values = parts.iter().map(|part| json!(part)).collect::<Vec<_>>();
    merkle_root(&format!("ENCRYPTED-{domain}-ROOT"), &values)
}
