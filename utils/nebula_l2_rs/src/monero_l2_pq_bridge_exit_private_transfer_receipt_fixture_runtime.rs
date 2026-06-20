use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitPrivateTransferReceiptFixtureRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_PRIVATE_TRANSFER_RECEIPT_FIXTURE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-private-transfer-receipt-fixture-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_PRIVATE_TRANSFER_RECEIPT_FIXTURE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECEIPT_FIXTURE_SUITE: &str =
    "monero-l2-pq-bridge-exit-private-transfer-receipt-fixture-v1";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 620_480;
pub const DEFAULT_MIN_INPUTS: u64 = 1;
pub const DEFAULT_MIN_OUTPUTS: u64 = 2;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_WALLET_SCAN_HINTS: u64 = 4;
pub const DEFAULT_MAX_FEE_CAP_UNITS: u64 = 35_000;
pub const DEFAULT_FORCED_EXIT_CONTINUITY_DEPTH: u64 = 4;
pub const DEFAULT_MAX_FIXTURES: usize = 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureStatus {
    Accepted,
    Watch,
    Rejected,
}

impl FixtureStatus {
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanHintKind {
    RecipientViewTag,
    ChangeViewTag,
    ReceiptLocator,
    ForcedExitRecovery,
}

impl ScanHintKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecipientViewTag => "recipient_view_tag",
            Self::ChangeViewTag => "change_view_tag",
            Self::ReceiptLocator => "receipt_locator",
            Self::ForcedExitRecovery => "forced_exit_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityStage {
    ParentOpen,
    ReceiptBound,
    NextRootPublished,
    EscapeWindowLive,
}

impl ContinuityStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ParentOpen => "parent_open",
            Self::ReceiptBound => "receipt_bound",
            Self::NextRootPublished => "next_root_published",
            Self::EscapeWindowLive => "escape_window_live",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub receipt_fixture_suite: String,
    pub base_l2_height: u64,
    pub min_inputs: u64,
    pub min_outputs: u64,
    pub min_privacy_set_size: u64,
    pub max_wallet_scan_hints: u64,
    pub max_fee_cap_units: u64,
    pub forced_exit_continuity_depth: u64,
    pub encrypted_receipt_roots_required: bool,
    pub forced_exit_continuity_required: bool,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub max_fixtures: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            receipt_fixture_suite: RECEIPT_FIXTURE_SUITE.to_string(),
            base_l2_height: DEFAULT_DEVNET_HEIGHT,
            min_inputs: DEFAULT_MIN_INPUTS,
            min_outputs: DEFAULT_MIN_OUTPUTS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_wallet_scan_hints: DEFAULT_MAX_WALLET_SCAN_HINTS,
            max_fee_cap_units: DEFAULT_MAX_FEE_CAP_UNITS,
            forced_exit_continuity_depth: DEFAULT_FORCED_EXIT_CONTINUITY_DEPTH,
            encrypted_receipt_roots_required: true,
            forced_exit_continuity_required: true,
            cargo_checks_deferred: true,
            production_release_allowed: false,
            max_fixtures: DEFAULT_MAX_FIXTURES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "receipt_fixture_suite": self.receipt_fixture_suite,
            "base_l2_height": self.base_l2_height,
            "min_inputs": self.min_inputs,
            "min_outputs": self.min_outputs,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_wallet_scan_hints": self.max_wallet_scan_hints,
            "max_fee_cap_units": self.max_fee_cap_units,
            "forced_exit_continuity_depth": self.forced_exit_continuity_depth,
            "encrypted_receipt_roots_required": self.encrypted_receipt_roots_required,
            "forced_exit_continuity_required": self.forced_exit_continuity_required,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_fixtures": self.max_fixtures,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReceiptFixtureRequest {
    pub fixture_id: String,
    pub transfer_id: String,
    pub asset_id: String,
    pub note_input_commitments: Vec<String>,
    pub output_note_commitments: Vec<String>,
    pub nullifier_commitments: Vec<String>,
    pub key_image_commitments: Vec<String>,
    pub encrypted_receipt_roots: Vec<String>,
    pub wallet_scan_hint_roots: Vec<String>,
    pub amount_commitment_root: String,
    pub balance_proof_root: String,
    pub fee_policy_root: String,
    pub fee_cap_units: u64,
    pub privacy_set_size: u64,
    pub forced_exit_parent_root: String,
    pub forced_exit_receipt_root: String,
    pub forced_exit_next_root: String,
    pub l2_height: u64,
}

impl ReceiptFixtureRequest {
    pub fn devnet() -> Self {
        let fixture_id = "devnet-private-transfer-receipt-fixture-0001".to_string();
        let transfer_id = "devnet-private-transfer-0001".to_string();
        let asset_id = "xmr-l2-private-note".to_string();
        let amount_commitment_root = label_root("amount_commitment", "devnet-private-transfer");
        let note_input_commitments = vec![note_commitment(
            "input",
            &transfer_id,
            0,
            &asset_id,
            &amount_commitment_root,
        )];
        let output_note_commitments = vec![
            note_commitment(
                "recipient_output",
                &transfer_id,
                0,
                &asset_id,
                &amount_commitment_root,
            ),
            note_commitment(
                "change_output",
                &transfer_id,
                1,
                &asset_id,
                &amount_commitment_root,
            ),
        ];
        let encrypted_receipt_roots = vec![
            label_root("encrypted_receipt", "recipient-ciphertext-bundle"),
            label_root("encrypted_receipt", "sender-change-ciphertext-bundle"),
            label_root(
                "encrypted_receipt",
                "forced-exit-recovery-ciphertext-bundle",
            ),
        ];
        Self {
            fixture_id,
            transfer_id,
            asset_id,
            note_input_commitments,
            output_note_commitments,
            nullifier_commitments: vec![label_root("nullifier", "devnet-input-note-0")],
            key_image_commitments: vec![label_root("key_image", "devnet-input-note-0")],
            encrypted_receipt_roots,
            wallet_scan_hint_roots: vec![
                label_root("wallet_scan_hint", "recipient-viewtag"),
                label_root("wallet_scan_hint", "change-viewtag"),
                label_root("wallet_scan_hint", "receipt-locator"),
            ],
            amount_commitment_root,
            balance_proof_root: label_root("balance_proof", "inputs-equal-outputs-plus-fee"),
            fee_policy_root: label_root("fee_policy", "bridge-exit-private-transfer-cap"),
            fee_cap_units: 30_000,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            forced_exit_parent_root: label_root("forced_exit_parent", "open-escape-root"),
            forced_exit_receipt_root: label_root("forced_exit_receipt", "receipt-bound-root"),
            forced_exit_next_root: label_root("forced_exit_next", "next-escape-root"),
            l2_height: DEFAULT_DEVNET_HEIGHT + 1,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fixture_id": self.fixture_id,
            "transfer_id": self.transfer_id,
            "asset_id": self.asset_id,
            "note_input_commitments": self.note_input_commitments,
            "output_note_commitments": self.output_note_commitments,
            "nullifier_commitments": self.nullifier_commitments,
            "key_image_commitments": self.key_image_commitments,
            "encrypted_receipt_roots": self.encrypted_receipt_roots,
            "wallet_scan_hint_roots": self.wallet_scan_hint_roots,
            "amount_commitment_root": self.amount_commitment_root,
            "balance_proof_root": self.balance_proof_root,
            "fee_policy_root": self.fee_policy_root,
            "fee_cap_units": self.fee_cap_units,
            "privacy_set_size": self.privacy_set_size,
            "forced_exit_parent_root": self.forced_exit_parent_root,
            "forced_exit_receipt_root": self.forced_exit_receipt_root,
            "forced_exit_next_root": self.forced_exit_next_root,
            "l2_height": self.l2_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("receipt_fixture_request", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NoteInputCommitmentFixture {
    pub binding_id: String,
    pub fixture_id: String,
    pub transfer_id: String,
    pub note_input_commitment: String,
    pub input_membership_root: String,
    pub input_authorization_root: String,
    pub amount_commitment_root: String,
    pub asset_id: String,
    pub input_position: u64,
}

impl NoteInputCommitmentFixture {
    pub fn public_record(&self) -> Value {
        json!({
            "binding_id": self.binding_id,
            "fixture_id": self.fixture_id,
            "transfer_id": self.transfer_id,
            "note_input_commitment": self.note_input_commitment,
            "input_membership_root": self.input_membership_root,
            "input_authorization_root": self.input_authorization_root,
            "amount_commitment_root": self.amount_commitment_root,
            "asset_id": self.asset_id,
            "input_position": self.input_position,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("note_input_commitment_fixture", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OutputNoteCommitmentFixture {
    pub output_id: String,
    pub fixture_id: String,
    pub transfer_id: String,
    pub output_note_commitment: String,
    pub output_recipient_root: String,
    pub output_view_tag_root: String,
    pub amount_commitment_root: String,
    pub asset_id: String,
    pub output_position: u64,
    pub output_leaf_index: u64,
}

impl OutputNoteCommitmentFixture {
    pub fn public_record(&self) -> Value {
        json!({
            "output_id": self.output_id,
            "fixture_id": self.fixture_id,
            "transfer_id": self.transfer_id,
            "output_note_commitment": self.output_note_commitment,
            "output_recipient_root": self.output_recipient_root,
            "output_view_tag_root": self.output_view_tag_root,
            "amount_commitment_root": self.amount_commitment_root,
            "asset_id": self.asset_id,
            "output_position": self.output_position,
            "output_leaf_index": self.output_leaf_index,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("output_note_commitment_fixture", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NullifierKeyImageRootFixture {
    pub root_id: String,
    pub fixture_id: String,
    pub transfer_id: String,
    pub nullifier_commitment: String,
    pub key_image_commitment: String,
    pub note_input_commitment: String,
    pub nullifier_root: String,
    pub key_image_root: String,
    pub replay_guard_root: String,
    pub input_position: u64,
}

impl NullifierKeyImageRootFixture {
    pub fn public_record(&self) -> Value {
        json!({
            "root_id": self.root_id,
            "fixture_id": self.fixture_id,
            "transfer_id": self.transfer_id,
            "nullifier_commitment": self.nullifier_commitment,
            "key_image_commitment": self.key_image_commitment,
            "note_input_commitment": self.note_input_commitment,
            "nullifier_root": self.nullifier_root,
            "key_image_root": self.key_image_root,
            "replay_guard_root": self.replay_guard_root,
            "input_position": self.input_position,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("nullifier_key_image_root_fixture", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedReceiptRootFixture {
    pub receipt_id: String,
    pub fixture_id: String,
    pub transfer_id: String,
    pub encrypted_receipt_root: String,
    pub ciphertext_root: String,
    pub receipt_index_root: String,
    pub availability_root: String,
    pub receipt_position: u64,
}

impl EncryptedReceiptRootFixture {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "fixture_id": self.fixture_id,
            "transfer_id": self.transfer_id,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "ciphertext_root": self.ciphertext_root,
            "receipt_index_root": self.receipt_index_root,
            "availability_root": self.availability_root,
            "receipt_position": self.receipt_position,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("encrypted_receipt_root_fixture", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletScanHintFixture {
    pub hint_id: String,
    pub fixture_id: String,
    pub transfer_id: String,
    pub hint_kind: ScanHintKind,
    pub wallet_scan_hint_root: String,
    pub view_tag_root: String,
    pub subaddress_hint_root: String,
    pub receipt_locator_root: String,
    pub scan_window_start: u64,
    pub scan_window_end: u64,
}

impl WalletScanHintFixture {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "fixture_id": self.fixture_id,
            "transfer_id": self.transfer_id,
            "hint_kind": self.hint_kind.as_str(),
            "wallet_scan_hint_root": self.wallet_scan_hint_root,
            "view_tag_root": self.view_tag_root,
            "subaddress_hint_root": self.subaddress_hint_root,
            "receipt_locator_root": self.receipt_locator_root,
            "scan_window_start": self.scan_window_start,
            "scan_window_end": self.scan_window_end,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("wallet_scan_hint_fixture", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeCapGuardFixture {
    pub guard_id: String,
    pub fixture_id: String,
    pub transfer_id: String,
    pub fee_cap_units: u64,
    pub max_fee_cap_units: u64,
    pub fee_policy_root: String,
    pub fee_asset_id: String,
    pub guard_root: String,
}

impl FeeCapGuardFixture {
    pub fn public_record(&self) -> Value {
        json!({
            "guard_id": self.guard_id,
            "fixture_id": self.fixture_id,
            "transfer_id": self.transfer_id,
            "fee_cap_units": self.fee_cap_units,
            "max_fee_cap_units": self.max_fee_cap_units,
            "fee_policy_root": self.fee_policy_root,
            "fee_asset_id": self.fee_asset_id,
            "guard_root": self.guard_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("fee_cap_guard_fixture", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitContinuityRootFixture {
    pub continuity_id: String,
    pub fixture_id: String,
    pub transfer_id: String,
    pub stage: ContinuityStage,
    pub parent_exit_root: String,
    pub receipt_exit_root: String,
    pub next_exit_root: String,
    pub continuity_root: String,
    pub continuity_depth: u64,
    pub liveness_height: u64,
}

impl ForcedExitContinuityRootFixture {
    pub fn public_record(&self) -> Value {
        json!({
            "continuity_id": self.continuity_id,
            "fixture_id": self.fixture_id,
            "transfer_id": self.transfer_id,
            "stage": self.stage.as_str(),
            "parent_exit_root": self.parent_exit_root,
            "receipt_exit_root": self.receipt_exit_root,
            "next_exit_root": self.next_exit_root,
            "continuity_root": self.continuity_root,
            "continuity_depth": self.continuity_depth,
            "liveness_height": self.liveness_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("forced_exit_continuity_root_fixture", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateTransferReceiptFixture {
    pub fixture_id: String,
    pub transfer_id: String,
    pub status: FixtureStatus,
    pub input_commitment_root: String,
    pub output_commitment_root: String,
    pub nullifier_key_image_root: String,
    pub encrypted_receipt_root: String,
    pub wallet_scan_hint_root: String,
    pub fee_cap_guard_root: String,
    pub forced_exit_continuity_root: String,
    pub receipt_spine_root: String,
    pub asset_id: String,
    pub amount_commitment_root: String,
    pub balance_proof_root: String,
    pub privacy_set_size: u64,
    pub l2_height: u64,
    pub rejection_root: String,
}

impl PrivateTransferReceiptFixture {
    pub fn public_record(&self) -> Value {
        json!({
            "fixture_id": self.fixture_id,
            "transfer_id": self.transfer_id,
            "status": self.status.as_str(),
            "input_commitment_root": self.input_commitment_root,
            "output_commitment_root": self.output_commitment_root,
            "nullifier_key_image_root": self.nullifier_key_image_root,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "wallet_scan_hint_root": self.wallet_scan_hint_root,
            "fee_cap_guard_root": self.fee_cap_guard_root,
            "forced_exit_continuity_root": self.forced_exit_continuity_root,
            "receipt_spine_root": self.receipt_spine_root,
            "asset_id": self.asset_id,
            "amount_commitment_root": self.amount_commitment_root,
            "balance_proof_root": self.balance_proof_root,
            "privacy_set_size": self.privacy_set_size,
            "l2_height": self.l2_height,
            "rejection_root": self.rejection_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("private_transfer_receipt_fixture", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub input_commitment_fixtures: BTreeMap<String, NoteInputCommitmentFixture>,
    pub output_commitment_fixtures: BTreeMap<String, OutputNoteCommitmentFixture>,
    pub nullifier_key_image_fixtures: BTreeMap<String, NullifierKeyImageRootFixture>,
    pub encrypted_receipt_fixtures: BTreeMap<String, EncryptedReceiptRootFixture>,
    pub wallet_scan_hint_fixtures: BTreeMap<String, WalletScanHintFixture>,
    pub fee_cap_guard_fixtures: BTreeMap<String, FeeCapGuardFixture>,
    pub forced_exit_continuity_fixtures: BTreeMap<String, ForcedExitContinuityRootFixture>,
    pub receipt_fixtures: BTreeMap<String, PrivateTransferReceiptFixture>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            input_commitment_fixtures: BTreeMap::new(),
            output_commitment_fixtures: BTreeMap::new(),
            nullifier_key_image_fixtures: BTreeMap::new(),
            encrypted_receipt_fixtures: BTreeMap::new(),
            wallet_scan_hint_fixtures: BTreeMap::new(),
            fee_cap_guard_fixtures: BTreeMap::new(),
            forced_exit_continuity_fixtures: BTreeMap::new(),
            receipt_fixtures: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        state
            .apply_fixture(ReceiptFixtureRequest::devnet())
            .expect("devnet private transfer receipt fixture must satisfy guard rails");
        state
    }

    pub fn apply_fixture(
        &mut self,
        request: ReceiptFixtureRequest,
    ) -> Result<PrivateTransferReceiptFixture> {
        self.validate_request(&request)?;

        let input_fixtures = request
            .note_input_commitments
            .iter()
            .enumerate()
            .map(|(position, commitment)| {
                NoteInputCommitmentFixture::from_request(&request, position as u64, commitment)
            })
            .collect::<Vec<_>>();
        let output_fixtures = request
            .output_note_commitments
            .iter()
            .enumerate()
            .map(|(position, commitment)| {
                OutputNoteCommitmentFixture::from_request(
                    self,
                    &request,
                    position as u64,
                    commitment,
                )
            })
            .collect::<Vec<_>>();
        let nullifier_fixtures = request
            .nullifier_commitments
            .iter()
            .zip(request.key_image_commitments.iter())
            .zip(request.note_input_commitments.iter())
            .enumerate()
            .map(|(position, ((nullifier, key_image), input_commitment))| {
                NullifierKeyImageRootFixture::from_request(
                    &request,
                    position as u64,
                    nullifier,
                    key_image,
                    input_commitment,
                )
            })
            .collect::<Vec<_>>();
        let encrypted_receipts = request
            .encrypted_receipt_roots
            .iter()
            .enumerate()
            .map(|(position, receipt_root)| {
                EncryptedReceiptRootFixture::from_request(&request, position as u64, receipt_root)
            })
            .collect::<Vec<_>>();
        let wallet_hints = request
            .wallet_scan_hint_roots
            .iter()
            .enumerate()
            .map(|(position, hint_root)| {
                WalletScanHintFixture::from_request(&request, position as u64, hint_root)
            })
            .collect::<Vec<_>>();
        let fee_guard = FeeCapGuardFixture::from_request(&self.config, &request);
        let continuity = ForcedExitContinuityRootFixture::from_request(&self.config, &request);

        let input_commitment_root = merkle_records(
            "receipt_fixture_input_commitments",
            &input_fixtures
                .iter()
                .map(NoteInputCommitmentFixture::public_record)
                .collect::<Vec<_>>(),
        );
        let output_commitment_root = merkle_records(
            "receipt_fixture_output_commitments",
            &output_fixtures
                .iter()
                .map(OutputNoteCommitmentFixture::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_key_image_root = merkle_records(
            "receipt_fixture_nullifier_key_images",
            &nullifier_fixtures
                .iter()
                .map(NullifierKeyImageRootFixture::public_record)
                .collect::<Vec<_>>(),
        );
        let encrypted_receipt_root = merkle_records(
            "receipt_fixture_encrypted_receipts",
            &encrypted_receipts
                .iter()
                .map(EncryptedReceiptRootFixture::public_record)
                .collect::<Vec<_>>(),
        );
        let wallet_scan_hint_root = merkle_records(
            "receipt_fixture_wallet_scan_hints",
            &wallet_hints
                .iter()
                .map(WalletScanHintFixture::public_record)
                .collect::<Vec<_>>(),
        );
        let fee_cap_guard_root = fee_guard.state_root();
        let forced_exit_continuity_root = continuity.state_root();
        let receipt_spine_root = receipt_spine_root(
            &input_commitment_root,
            &output_commitment_root,
            &nullifier_key_image_root,
            &encrypted_receipt_root,
            &wallet_scan_hint_root,
            &fee_cap_guard_root,
            &forced_exit_continuity_root,
        );

        let fixture = PrivateTransferReceiptFixture {
            fixture_id: request.fixture_id.clone(),
            transfer_id: request.transfer_id.clone(),
            status: FixtureStatus::Accepted,
            input_commitment_root,
            output_commitment_root,
            nullifier_key_image_root,
            encrypted_receipt_root,
            wallet_scan_hint_root,
            fee_cap_guard_root,
            forced_exit_continuity_root,
            receipt_spine_root,
            asset_id: request.asset_id.clone(),
            amount_commitment_root: request.amount_commitment_root.clone(),
            balance_proof_root: request.balance_proof_root.clone(),
            privacy_set_size: request.privacy_set_size,
            l2_height: request.l2_height,
            rejection_root: empty_root("receipt_fixture_rejection"),
        };

        for item in input_fixtures {
            self.input_commitment_fixtures
                .insert(item.binding_id.clone(), item);
        }
        for item in output_fixtures {
            self.output_commitment_fixtures
                .insert(item.output_id.clone(), item);
        }
        for item in nullifier_fixtures {
            self.nullifier_key_image_fixtures
                .insert(item.root_id.clone(), item);
        }
        for item in encrypted_receipts {
            self.encrypted_receipt_fixtures
                .insert(item.receipt_id.clone(), item);
        }
        for item in wallet_hints {
            self.wallet_scan_hint_fixtures
                .insert(item.hint_id.clone(), item);
        }
        self.fee_cap_guard_fixtures
            .insert(fee_guard.guard_id.clone(), fee_guard);
        self.forced_exit_continuity_fixtures
            .insert(continuity.continuity_id.clone(), continuity);
        self.receipt_fixtures
            .insert(fixture.fixture_id.clone(), fixture.clone());
        self.prune_to_limit();
        Ok(fixture)
    }

    pub fn validate_request(&self, request: &ReceiptFixtureRequest) -> Result<()> {
        if request.fixture_id.is_empty() {
            return Err("fixture_id is required".to_string());
        }
        if request.transfer_id.is_empty() {
            return Err("transfer_id is required".to_string());
        }
        if self.receipt_fixtures.contains_key(&request.fixture_id) {
            return Err(format!("fixture {} already recorded", request.fixture_id));
        }
        if request.note_input_commitments.len() < self.config.min_inputs as usize {
            return Err("not enough note input commitments".to_string());
        }
        if request.output_note_commitments.len() < self.config.min_outputs as usize {
            return Err("not enough output note commitments".to_string());
        }
        if request.nullifier_commitments.len() != request.note_input_commitments.len() {
            return Err("nullifier count must match note input count".to_string());
        }
        if request.key_image_commitments.len() != request.note_input_commitments.len() {
            return Err("key image count must match note input count".to_string());
        }
        if has_duplicates(&request.nullifier_commitments) {
            return Err("duplicate nullifier commitment in fixture".to_string());
        }
        if request
            .nullifier_commitments
            .iter()
            .any(|nullifier| self.nullifier_seen(nullifier))
        {
            return Err("nullifier commitment already bound in fixture state".to_string());
        }
        if request.encrypted_receipt_roots.is_empty()
            && self.config.encrypted_receipt_roots_required
        {
            return Err("encrypted receipt roots are required".to_string());
        }
        if request.wallet_scan_hint_roots.len() as u64 > self.config.max_wallet_scan_hints {
            return Err("wallet scan hint count exceeds configured cap".to_string());
        }
        if request.fee_cap_units > self.config.max_fee_cap_units {
            return Err("fee cap exceeds configured maximum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set size below minimum".to_string());
        }
        if request.balance_proof_root.is_empty() {
            return Err("balance proof root is required".to_string());
        }
        if self.config.forced_exit_continuity_required
            && (request.forced_exit_parent_root.is_empty()
                || request.forced_exit_receipt_root.is_empty()
                || request.forced_exit_next_root.is_empty())
        {
            return Err("forced-exit continuity roots are required".to_string());
        }
        Ok(())
    }

    pub fn input_commitment_root(&self) -> String {
        map_root(
            "receipt_fixture_state_input_commitments",
            self.input_commitment_fixtures
                .values()
                .map(NoteInputCommitmentFixture::public_record)
                .collect(),
        )
    }

    pub fn output_commitment_root(&self) -> String {
        map_root(
            "receipt_fixture_state_output_commitments",
            self.output_commitment_fixtures
                .values()
                .map(OutputNoteCommitmentFixture::public_record)
                .collect(),
        )
    }

    pub fn nullifier_key_image_root(&self) -> String {
        map_root(
            "receipt_fixture_state_nullifier_key_images",
            self.nullifier_key_image_fixtures
                .values()
                .map(NullifierKeyImageRootFixture::public_record)
                .collect(),
        )
    }

    pub fn encrypted_receipt_root(&self) -> String {
        map_root(
            "receipt_fixture_state_encrypted_receipts",
            self.encrypted_receipt_fixtures
                .values()
                .map(EncryptedReceiptRootFixture::public_record)
                .collect(),
        )
    }

    pub fn wallet_scan_hint_root(&self) -> String {
        map_root(
            "receipt_fixture_state_wallet_scan_hints",
            self.wallet_scan_hint_fixtures
                .values()
                .map(WalletScanHintFixture::public_record)
                .collect(),
        )
    }

    pub fn fee_cap_guard_root(&self) -> String {
        map_root(
            "receipt_fixture_state_fee_cap_guards",
            self.fee_cap_guard_fixtures
                .values()
                .map(FeeCapGuardFixture::public_record)
                .collect(),
        )
    }

    pub fn forced_exit_continuity_root(&self) -> String {
        map_root(
            "receipt_fixture_state_forced_exit_continuity",
            self.forced_exit_continuity_fixtures
                .values()
                .map(ForcedExitContinuityRootFixture::public_record)
                .collect(),
        )
    }

    pub fn receipt_fixture_root(&self) -> String {
        map_root(
            "receipt_fixture_state_records",
            self.receipt_fixtures
                .values()
                .map(PrivateTransferReceiptFixture::public_record)
                .collect(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "input_commitment_root": self.input_commitment_root(),
            "output_commitment_root": self.output_commitment_root(),
            "nullifier_key_image_root": self.nullifier_key_image_root(),
            "encrypted_receipt_root": self.encrypted_receipt_root(),
            "wallet_scan_hint_root": self.wallet_scan_hint_root(),
            "fee_cap_guard_root": self.fee_cap_guard_root(),
            "forced_exit_continuity_root": self.forced_exit_continuity_root(),
            "receipt_fixture_root": self.receipt_fixture_root(),
            "counters": {
                "input_commitment_fixtures": self.input_commitment_fixtures.len(),
                "output_commitment_fixtures": self.output_commitment_fixtures.len(),
                "nullifier_key_image_fixtures": self.nullifier_key_image_fixtures.len(),
                "encrypted_receipt_fixtures": self.encrypted_receipt_fixtures.len(),
                "wallet_scan_hint_fixtures": self.wallet_scan_hint_fixtures.len(),
                "fee_cap_guard_fixtures": self.fee_cap_guard_fixtures.len(),
                "forced_exit_continuity_fixtures": self.forced_exit_continuity_fixtures.len(),
                "receipt_fixtures": self.receipt_fixtures.len(),
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
                .receipt_fixtures
                .values()
                .all(|fixture| fixture.status.passes())
    }

    pub fn nullifier_seen(&self, nullifier_commitment: &str) -> bool {
        self.nullifier_key_image_fixtures
            .values()
            .any(|entry| entry.nullifier_commitment == nullifier_commitment)
    }

    fn prune_to_limit(&mut self) {
        while self.receipt_fixtures.len() > self.config.max_fixtures {
            if let Some(oldest_fixture_id) = self.receipt_fixtures.keys().next().cloned() {
                self.receipt_fixtures.remove(&oldest_fixture_id);
            } else {
                break;
            }
        }
    }
}

impl NoteInputCommitmentFixture {
    fn from_request(
        request: &ReceiptFixtureRequest,
        input_position: u64,
        note_input_commitment: &str,
    ) -> Self {
        let binding_id = domain_hash(
            "PRIVATE-TRANSFER-RECEIPT-FIXTURE-INPUT-BINDING-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.fixture_id),
                HashPart::Str(&request.transfer_id),
                HashPart::Str(note_input_commitment),
                HashPart::U64(input_position),
            ],
            32,
        );
        Self {
            binding_id,
            fixture_id: request.fixture_id.clone(),
            transfer_id: request.transfer_id.clone(),
            note_input_commitment: note_input_commitment.to_string(),
            input_membership_root: label_root("input_membership", note_input_commitment),
            input_authorization_root: label_root("input_authorization", note_input_commitment),
            amount_commitment_root: request.amount_commitment_root.clone(),
            asset_id: request.asset_id.clone(),
            input_position,
        }
    }
}

impl OutputNoteCommitmentFixture {
    fn from_request(
        state: &State,
        request: &ReceiptFixtureRequest,
        output_position: u64,
        output_note_commitment: &str,
    ) -> Self {
        let output_id = domain_hash(
            "PRIVATE-TRANSFER-RECEIPT-FIXTURE-OUTPUT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.fixture_id),
                HashPart::Str(&request.transfer_id),
                HashPart::Str(output_note_commitment),
                HashPart::U64(output_position),
            ],
            32,
        );
        Self {
            output_id,
            fixture_id: request.fixture_id.clone(),
            transfer_id: request.transfer_id.clone(),
            output_note_commitment: output_note_commitment.to_string(),
            output_recipient_root: label_root("output_recipient", output_note_commitment),
            output_view_tag_root: label_root("output_view_tag", output_note_commitment),
            amount_commitment_root: request.amount_commitment_root.clone(),
            asset_id: request.asset_id.clone(),
            output_position,
            output_leaf_index: state.output_commitment_fixtures.len() as u64 + output_position,
        }
    }
}

impl NullifierKeyImageRootFixture {
    fn from_request(
        request: &ReceiptFixtureRequest,
        input_position: u64,
        nullifier_commitment: &str,
        key_image_commitment: &str,
        note_input_commitment: &str,
    ) -> Self {
        let nullifier_root = label_root("nullifier_root", nullifier_commitment);
        let key_image_root = label_root("key_image_root", key_image_commitment);
        let root_id = domain_hash(
            "PRIVATE-TRANSFER-RECEIPT-FIXTURE-NULLIFIER-KEY-IMAGE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.fixture_id),
                HashPart::Str(nullifier_commitment),
                HashPart::Str(key_image_commitment),
                HashPart::U64(input_position),
            ],
            32,
        );
        Self {
            root_id,
            fixture_id: request.fixture_id.clone(),
            transfer_id: request.transfer_id.clone(),
            nullifier_commitment: nullifier_commitment.to_string(),
            key_image_commitment: key_image_commitment.to_string(),
            note_input_commitment: note_input_commitment.to_string(),
            nullifier_root,
            key_image_root,
            replay_guard_root: label_root("replay_guard", &request.transfer_id),
            input_position,
        }
    }
}

impl EncryptedReceiptRootFixture {
    fn from_request(request: &ReceiptFixtureRequest, receipt_position: u64, root: &str) -> Self {
        let receipt_id = domain_hash(
            "PRIVATE-TRANSFER-RECEIPT-FIXTURE-ENCRYPTED-RECEIPT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.fixture_id),
                HashPart::Str(root),
                HashPart::U64(receipt_position),
            ],
            32,
        );
        Self {
            receipt_id,
            fixture_id: request.fixture_id.clone(),
            transfer_id: request.transfer_id.clone(),
            encrypted_receipt_root: root.to_string(),
            ciphertext_root: label_root("ciphertext_root", root),
            receipt_index_root: label_root("receipt_index", &request.transfer_id),
            availability_root: label_root("receipt_availability", root),
            receipt_position,
        }
    }
}

impl WalletScanHintFixture {
    fn from_request(request: &ReceiptFixtureRequest, position: u64, hint_root: &str) -> Self {
        let hint_kind = match position {
            0 => ScanHintKind::RecipientViewTag,
            1 => ScanHintKind::ChangeViewTag,
            2 => ScanHintKind::ReceiptLocator,
            _ => ScanHintKind::ForcedExitRecovery,
        };
        let hint_id = domain_hash(
            "PRIVATE-TRANSFER-RECEIPT-FIXTURE-WALLET-SCAN-HINT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.fixture_id),
                HashPart::Str(hint_root),
                HashPart::Str(hint_kind.as_str()),
                HashPart::U64(position),
            ],
            32,
        );
        Self {
            hint_id,
            fixture_id: request.fixture_id.clone(),
            transfer_id: request.transfer_id.clone(),
            hint_kind,
            wallet_scan_hint_root: hint_root.to_string(),
            view_tag_root: label_root("view_tag", hint_root),
            subaddress_hint_root: label_root("subaddress_hint", hint_root),
            receipt_locator_root: label_root("receipt_locator", &request.transfer_id),
            scan_window_start: request.l2_height,
            scan_window_end: request.l2_height + 128,
        }
    }
}

impl FeeCapGuardFixture {
    fn from_request(config: &Config, request: &ReceiptFixtureRequest) -> Self {
        let guard_root = domain_hash(
            "PRIVATE-TRANSFER-RECEIPT-FIXTURE-FEE-CAP-GUARD-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.fixture_id),
                HashPart::U64(request.fee_cap_units),
                HashPart::U64(config.max_fee_cap_units),
                HashPart::Str(&request.fee_policy_root),
            ],
            32,
        );
        let guard_id = domain_hash(
            "PRIVATE-TRANSFER-RECEIPT-FIXTURE-FEE-CAP-GUARD-ID",
            &[
                HashPart::Str(&request.transfer_id),
                HashPart::Str(&guard_root),
            ],
            32,
        );
        Self {
            guard_id,
            fixture_id: request.fixture_id.clone(),
            transfer_id: request.transfer_id.clone(),
            fee_cap_units: request.fee_cap_units,
            max_fee_cap_units: config.max_fee_cap_units,
            fee_policy_root: request.fee_policy_root.clone(),
            fee_asset_id: request.asset_id.clone(),
            guard_root,
        }
    }
}

impl ForcedExitContinuityRootFixture {
    fn from_request(config: &Config, request: &ReceiptFixtureRequest) -> Self {
        let stage = ContinuityStage::EscapeWindowLive;
        let continuity_root = domain_hash(
            "PRIVATE-TRANSFER-RECEIPT-FIXTURE-FORCED-EXIT-CONTINUITY-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.fixture_id),
                HashPart::Str(&request.forced_exit_parent_root),
                HashPart::Str(&request.forced_exit_receipt_root),
                HashPart::Str(&request.forced_exit_next_root),
                HashPart::U64(config.forced_exit_continuity_depth),
            ],
            32,
        );
        let continuity_id = domain_hash(
            "PRIVATE-TRANSFER-RECEIPT-FIXTURE-FORCED-EXIT-CONTINUITY-ID",
            &[
                HashPart::Str(&request.transfer_id),
                HashPart::Str(&continuity_root),
            ],
            32,
        );
        Self {
            continuity_id,
            fixture_id: request.fixture_id.clone(),
            transfer_id: request.transfer_id.clone(),
            stage,
            parent_exit_root: request.forced_exit_parent_root.clone(),
            receipt_exit_root: request.forced_exit_receipt_root.clone(),
            next_exit_root: request.forced_exit_next_root.clone(),
            continuity_root,
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

fn receipt_spine_root(
    input_commitment_root: &str,
    output_commitment_root: &str,
    nullifier_key_image_root: &str,
    encrypted_receipt_root: &str,
    wallet_scan_hint_root: &str,
    fee_cap_guard_root: &str,
    forced_exit_continuity_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-TRANSFER-RECEIPT-FIXTURE-SPINE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(input_commitment_root),
            HashPart::Str(output_commitment_root),
            HashPart::Str(nullifier_key_image_root),
            HashPart::Str(encrypted_receipt_root),
            HashPart::Str(wallet_scan_hint_root),
            HashPart::Str(fee_cap_guard_root),
            HashPart::Str(forced_exit_continuity_root),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-TRANSFER-RECEIPT-FIXTURE-RECORD",
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
        "PRIVATE-TRANSFER-RECEIPT-FIXTURE-LABEL",
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
        "PRIVATE-TRANSFER-RECEIPT-FIXTURE-NOTE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
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
