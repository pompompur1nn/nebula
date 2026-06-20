use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitPrivateNoteReceiptLinkageFixtureRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_PRIVATE_NOTE_RECEIPT_LINKAGE_FIXTURE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-private-note-receipt-linkage-fixture-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_PRIVATE_NOTE_RECEIPT_LINKAGE_FIXTURE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const LINKAGE_FIXTURE_SUITE: &str =
    "monero-l2-pq-bridge-exit-private-note-receipt-linkage-fixture-v1";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 621_040;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_SCAN_HINTS: u64 = 4;
pub const DEFAULT_MAX_METADATA_UNITS: u64 = 8;
pub const DEFAULT_MAX_FEE_CAP_UNITS: u64 = 35_000;
pub const DEFAULT_FORCED_EXIT_RECEIPT_DEPTH: u64 = 4;
pub const DEFAULT_MAX_FIXTURES: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkageStatus {
    Accepted,
    Watch,
    Rejected,
}

impl LinkageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Watch => "watch",
            Self::Rejected => "rejected",
        }
    }

    pub fn release_compatible(self) -> bool {
        matches!(self, Self::Accepted | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkageStage {
    DepositMint,
    PrivateTransfer,
    NullifierKeyImage,
    EncryptedReceipt,
    WalletScan,
    ExitClaim,
}

impl LinkageStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositMint => "deposit_mint",
            Self::PrivateTransfer => "private_transfer",
            Self::NullifierKeyImage => "nullifier_key_image",
            Self::EncryptedReceipt => "encrypted_receipt",
            Self::WalletScan => "wallet_scan",
            Self::ExitClaim => "exit_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptAudience {
    SenderChange,
    Recipient,
    WatcherChallenge,
    ForcedExitRecovery,
}

impl ReceiptAudience {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SenderChange => "sender_change",
            Self::Recipient => "recipient",
            Self::WatcherChallenge => "watcher_challenge",
            Self::ForcedExitRecovery => "forced_exit_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeakBlockerKind {
    PublicFieldAllowlist,
    CommitmentOnlyAmount,
    EncryptedReceiptPayload,
    BoundedScanHint,
    NullifierAnonymitySet,
    ForcedExitRedaction,
    FeeCapRootOnly,
}

impl LeakBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicFieldAllowlist => "public_field_allowlist",
            Self::CommitmentOnlyAmount => "commitment_only_amount",
            Self::EncryptedReceiptPayload => "encrypted_receipt_payload",
            Self::BoundedScanHint => "bounded_scan_hint",
            Self::NullifierAnonymitySet => "nullifier_anonymity_set",
            Self::ForcedExitRedaction => "forced_exit_redaction",
            Self::FeeCapRootOnly => "fee_cap_root_only",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub linkage_fixture_suite: String,
    pub base_l2_height: u64,
    pub min_privacy_set_size: u64,
    pub max_scan_hints: u64,
    pub max_metadata_units: u64,
    pub max_fee_cap_units: u64,
    pub forced_exit_receipt_depth: u64,
    pub encrypted_payload_policy: String,
    pub production_release_allowed: String,
    pub cargo_checks_deferred: String,
    pub max_fixtures: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            linkage_fixture_suite: LINKAGE_FIXTURE_SUITE.to_string(),
            base_l2_height: DEFAULT_DEVNET_HEIGHT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_scan_hints: DEFAULT_MAX_SCAN_HINTS,
            max_metadata_units: DEFAULT_MAX_METADATA_UNITS,
            max_fee_cap_units: DEFAULT_MAX_FEE_CAP_UNITS,
            forced_exit_receipt_depth: DEFAULT_FORCED_EXIT_RECEIPT_DEPTH,
            encrypted_payload_policy: "ciphertext_roots_only".to_string(),
            production_release_allowed: "no".to_string(),
            cargo_checks_deferred: "yes".to_string(),
            max_fixtures: DEFAULT_MAX_FIXTURES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "linkage_fixture_suite": self.linkage_fixture_suite,
            "base_l2_height": self.base_l2_height,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_scan_hints": self.max_scan_hints,
            "max_metadata_units": self.max_metadata_units,
            "max_fee_cap_units": self.max_fee_cap_units,
            "forced_exit_receipt_depth": self.forced_exit_receipt_depth,
            "encrypted_payload_policy": self.encrypted_payload_policy,
            "production_release_allowed": self.production_release_allowed,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "max_fixtures": self.max_fixtures,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LinkageFixtureRequest {
    pub fixture_id: String,
    pub deposit_lock_id: String,
    pub transfer_id: String,
    pub exit_claim_id: String,
    pub asset_id: String,
    pub deposit_note_commitment: String,
    pub recipient_note_commitment: String,
    pub change_note_commitment: String,
    pub amount_commitment_root: String,
    pub owner_view_tag_root: String,
    pub spend_authority_commitment_root: String,
    pub transfer_authorization_root: String,
    pub nullifier_commitment: String,
    pub key_image_commitment: String,
    pub encrypted_receipt_roots: Vec<String>,
    pub wallet_scan_hint_roots: Vec<String>,
    pub fee_policy_root: String,
    pub fee_cap_units: u64,
    pub privacy_set_size: u64,
    pub metadata_units: u64,
    pub forced_exit_parent_root: String,
    pub forced_exit_receipt_root: String,
    pub forced_exit_claim_root: String,
    pub deposit_height: u64,
    pub transfer_height: u64,
    pub exit_height: u64,
}

impl LinkageFixtureRequest {
    pub fn devnet() -> Self {
        let fixture_id = "devnet-private-note-receipt-linkage-0001".to_string();
        let deposit_lock_id = "devnet-xmr-lock-bridge-in-0001".to_string();
        let transfer_id = "devnet-private-transfer-after-deposit-0001".to_string();
        let exit_claim_id = "devnet-private-exit-claim-0001".to_string();
        let asset_id = "xmr-l2-private-note".to_string();
        let amount_commitment_root = label_root("amount_commitment", "devnet-locked-xmr-amount");
        let owner_view_tag_root = label_root("owner_view_tag", "wallet-view-tag-set");
        let spend_authority_commitment_root =
            label_root("spend_authority", "wallet-spend-authority-commitment");
        let deposit_note_commitment = note_commitment(
            "deposit_minted",
            &deposit_lock_id,
            0,
            &asset_id,
            &amount_commitment_root,
        );
        let recipient_note_commitment = note_commitment(
            "recipient_output",
            &transfer_id,
            0,
            &asset_id,
            &amount_commitment_root,
        );
        let change_note_commitment = note_commitment(
            "change_output",
            &transfer_id,
            1,
            &asset_id,
            &amount_commitment_root,
        );
        Self {
            fixture_id,
            deposit_lock_id,
            transfer_id,
            exit_claim_id,
            asset_id,
            deposit_note_commitment,
            recipient_note_commitment,
            change_note_commitment,
            amount_commitment_root,
            owner_view_tag_root,
            spend_authority_commitment_root,
            transfer_authorization_root: label_root(
                "transfer_authorization",
                "private-transfer-balance-proof",
            ),
            nullifier_commitment: label_root("nullifier", "deposit-note-spent-on-private-transfer"),
            key_image_commitment: label_root("key_image", "deposit-note-spend-key-image"),
            encrypted_receipt_roots: vec![
                label_root("encrypted_receipt", "recipient-ciphertext"),
                label_root("encrypted_receipt", "sender-change-ciphertext"),
                label_root("encrypted_receipt", "forced-exit-recovery-ciphertext"),
            ],
            wallet_scan_hint_roots: vec![
                label_root("scan_hint", "recipient-view-tag"),
                label_root("scan_hint", "change-view-tag"),
                label_root("scan_hint", "receipt-locator"),
                label_root("scan_hint", "forced-exit-recovery"),
            ],
            fee_policy_root: label_root("fee_policy", "private-transfer-exit-fee-cap"),
            fee_cap_units: 30_000,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            metadata_units: 5,
            forced_exit_parent_root: label_root("forced_exit_parent", "escape-open-root"),
            forced_exit_receipt_root: label_root("forced_exit_receipt", "receipt-compatible-root"),
            forced_exit_claim_root: label_root("forced_exit_claim", "claim-release-root"),
            deposit_height: DEFAULT_DEVNET_HEIGHT,
            transfer_height: DEFAULT_DEVNET_HEIGHT + 3,
            exit_height: DEFAULT_DEVNET_HEIGHT + 12,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fixture_id": self.fixture_id,
            "deposit_lock_id": self.deposit_lock_id,
            "transfer_id": self.transfer_id,
            "exit_claim_id": self.exit_claim_id,
            "asset_id": self.asset_id,
            "deposit_note_commitment": self.deposit_note_commitment,
            "recipient_note_commitment": self.recipient_note_commitment,
            "change_note_commitment": self.change_note_commitment,
            "amount_commitment_root": self.amount_commitment_root,
            "owner_view_tag_root": self.owner_view_tag_root,
            "spend_authority_commitment_root": self.spend_authority_commitment_root,
            "transfer_authorization_root": self.transfer_authorization_root,
            "nullifier_commitment": self.nullifier_commitment,
            "key_image_commitment": self.key_image_commitment,
            "encrypted_receipt_roots": self.encrypted_receipt_roots,
            "wallet_scan_hint_roots": self.wallet_scan_hint_roots,
            "fee_policy_root": self.fee_policy_root,
            "fee_cap_units": self.fee_cap_units,
            "privacy_set_size": self.privacy_set_size,
            "metadata_units": self.metadata_units,
            "forced_exit_parent_root": self.forced_exit_parent_root,
            "forced_exit_receipt_root": self.forced_exit_receipt_root,
            "forced_exit_claim_root": self.forced_exit_claim_root,
            "deposit_height": self.deposit_height,
            "transfer_height": self.transfer_height,
            "exit_height": self.exit_height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("request", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicFieldCommitment {
    pub commitment_id: String,
    pub stage: LinkageStage,
    pub public_fields: Vec<String>,
    pub committed_fields: Vec<String>,
    pub encrypted_fields: Vec<String>,
    pub redacted_fields: Vec<String>,
    pub commitment_root: String,
}

impl PublicFieldCommitment {
    pub fn from_parts(
        fixture_id: &str,
        stage: LinkageStage,
        public_fields: Vec<&str>,
        committed_fields: Vec<&str>,
        encrypted_fields: Vec<&str>,
        redacted_fields: Vec<&str>,
    ) -> Self {
        let public_fields = stringify(public_fields);
        let committed_fields = stringify(committed_fields);
        let encrypted_fields = stringify(encrypted_fields);
        let redacted_fields = stringify(redacted_fields);
        let field_root = merkle_root(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-FIELD-ROOT",
            &[
                json!(public_fields),
                json!(committed_fields),
                json!(encrypted_fields),
                json!(redacted_fields),
            ],
        );
        let commitment_root = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-FIELD-COMMITMENT-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(fixture_id),
                HashPart::Str(stage.as_str()),
                HashPart::Str(&field_root),
            ],
            32,
        );
        let commitment_id = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-FIELD-COMMITMENT-ID",
            &[
                HashPart::Str(fixture_id),
                HashPart::Str(stage.as_str()),
                HashPart::Str(&commitment_root),
            ],
            32,
        );
        Self {
            commitment_id,
            stage,
            public_fields,
            committed_fields,
            encrypted_fields,
            redacted_fields,
            commitment_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "stage": self.stage,
            "public_fields": self.public_fields,
            "committed_fields": self.committed_fields,
            "encrypted_fields": self.encrypted_fields,
            "redacted_fields": self.redacted_fields,
            "commitment_root": self.commitment_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositMintedNoteLink {
    pub link_id: String,
    pub fixture_id: String,
    pub deposit_lock_id: String,
    pub note_commitment: String,
    pub amount_commitment_root: String,
    pub owner_view_tag_root: String,
    pub spend_authority_commitment_root: String,
    pub minted_note_root: String,
    pub note_leaf_index: u64,
    pub deposit_height: u64,
    pub leak_blocker_root: String,
}

impl DepositMintedNoteLink {
    pub fn from_request(request: &LinkageFixtureRequest) -> Self {
        let minted_note_root = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-DEPOSIT-MINTED-NOTE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.fixture_id),
                HashPart::Str(&request.deposit_lock_id),
                HashPart::Str(&request.deposit_note_commitment),
                HashPart::Str(&request.amount_commitment_root),
                HashPart::Str(&request.owner_view_tag_root),
            ],
            32,
        );
        let leak_blocker_root = blocker_root(
            LeakBlockerKind::CommitmentOnlyAmount,
            &request.fixture_id,
            &minted_note_root,
            request.metadata_units,
        );
        let link_id = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-DEPOSIT-LINK-ID",
            &[
                HashPart::Str(&request.deposit_lock_id),
                HashPart::Str(&request.deposit_note_commitment),
                HashPart::Str(&minted_note_root),
            ],
            32,
        );
        Self {
            link_id,
            fixture_id: request.fixture_id.clone(),
            deposit_lock_id: request.deposit_lock_id.clone(),
            note_commitment: request.deposit_note_commitment.clone(),
            amount_commitment_root: request.amount_commitment_root.clone(),
            owner_view_tag_root: request.owner_view_tag_root.clone(),
            spend_authority_commitment_root: request.spend_authority_commitment_root.clone(),
            minted_note_root,
            note_leaf_index: 0,
            deposit_height: request.deposit_height,
            leak_blocker_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "link_id": self.link_id,
            "fixture_id": self.fixture_id,
            "deposit_lock_id": self.deposit_lock_id,
            "note_commitment": self.note_commitment,
            "amount_commitment_root": self.amount_commitment_root,
            "owner_view_tag_root": self.owner_view_tag_root,
            "spend_authority_commitment_root": self.spend_authority_commitment_root,
            "minted_note_root": self.minted_note_root,
            "note_leaf_index": self.note_leaf_index,
            "deposit_height": self.deposit_height,
            "leak_blocker_root": self.leak_blocker_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateTransferNoteContinuity {
    pub continuity_id: String,
    pub fixture_id: String,
    pub transfer_id: String,
    pub input_note_commitment: String,
    pub output_note_commitments: Vec<String>,
    pub transfer_authorization_root: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub continuity_root: String,
    pub transfer_height: u64,
}

impl PrivateTransferNoteContinuity {
    pub fn from_request(request: &LinkageFixtureRequest, deposit: &DepositMintedNoteLink) -> Self {
        let output_note_commitments = vec![
            request.recipient_note_commitment.clone(),
            request.change_note_commitment.clone(),
        ];
        let output_note_root = merkle_root(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-OUTPUT-NOTE-ROOT",
            &output_note_commitments
                .iter()
                .map(|commitment| json!(commitment))
                .collect::<Vec<_>>(),
        );
        let continuity_root = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-PRIVATE-TRANSFER-CONTINUITY-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.fixture_id),
                HashPart::Str(&request.transfer_id),
                HashPart::Str(&deposit.minted_note_root),
                HashPart::Str(&output_note_root),
                HashPart::Str(&request.transfer_authorization_root),
            ],
            32,
        );
        let continuity_id = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-PRIVATE-TRANSFER-CONTINUITY-ID",
            &[
                HashPart::Str(&request.transfer_id),
                HashPart::Str(&request.deposit_note_commitment),
                HashPart::Str(&continuity_root),
            ],
            32,
        );
        Self {
            continuity_id,
            fixture_id: request.fixture_id.clone(),
            transfer_id: request.transfer_id.clone(),
            input_note_commitment: request.deposit_note_commitment.clone(),
            output_note_commitments,
            transfer_authorization_root: request.transfer_authorization_root.clone(),
            input_note_root: deposit.minted_note_root.clone(),
            output_note_root,
            continuity_root,
            transfer_height: request.transfer_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "continuity_id": self.continuity_id,
            "fixture_id": self.fixture_id,
            "transfer_id": self.transfer_id,
            "input_note_commitment": self.input_note_commitment,
            "output_note_commitments": self.output_note_commitments,
            "transfer_authorization_root": self.transfer_authorization_root,
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "continuity_root": self.continuity_root,
            "transfer_height": self.transfer_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NullifierKeyImageLink {
    pub link_id: String,
    pub fixture_id: String,
    pub transfer_id: String,
    pub nullifier_commitment: String,
    pub key_image_commitment: String,
    pub spent_note_commitment: String,
    pub replay_fence_root: String,
    pub anonymity_set_size: u64,
    pub nullifier_key_image_root: String,
    pub duplicate_policy: String,
}

impl NullifierKeyImageLink {
    pub fn from_request(config: &Config, request: &LinkageFixtureRequest) -> Self {
        let replay_fence_root = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-REPLAY-FENCE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.transfer_id),
                HashPart::Str(&request.nullifier_commitment),
                HashPart::Str(&request.key_image_commitment),
            ],
            32,
        );
        let nullifier_key_image_root = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-NULLIFIER-KEY-IMAGE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.fixture_id),
                HashPart::Str(&request.deposit_note_commitment),
                HashPart::Str(&request.nullifier_commitment),
                HashPart::Str(&request.key_image_commitment),
                HashPart::Str(&replay_fence_root),
                HashPart::U64(request.privacy_set_size),
            ],
            32,
        );
        let link_id = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-NULLIFIER-KEY-IMAGE-ID",
            &[
                HashPart::Str(&request.transfer_id),
                HashPart::Str(&nullifier_key_image_root),
            ],
            32,
        );
        Self {
            link_id,
            fixture_id: request.fixture_id.clone(),
            transfer_id: request.transfer_id.clone(),
            nullifier_commitment: request.nullifier_commitment.clone(),
            key_image_commitment: request.key_image_commitment.clone(),
            spent_note_commitment: request.deposit_note_commitment.clone(),
            replay_fence_root,
            anonymity_set_size: request.privacy_set_size.max(config.min_privacy_set_size),
            nullifier_key_image_root,
            duplicate_policy: "reject_duplicate_nullifier_or_key_image".to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "link_id": self.link_id,
            "fixture_id": self.fixture_id,
            "transfer_id": self.transfer_id,
            "nullifier_commitment": self.nullifier_commitment,
            "key_image_commitment": self.key_image_commitment,
            "spent_note_commitment": self.spent_note_commitment,
            "replay_fence_root": self.replay_fence_root,
            "anonymity_set_size": self.anonymity_set_size,
            "nullifier_key_image_root": self.nullifier_key_image_root,
            "duplicate_policy": self.duplicate_policy,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedReceiptLink {
    pub receipt_id: String,
    pub fixture_id: String,
    pub transfer_id: String,
    pub audience: ReceiptAudience,
    pub encrypted_receipt_root: String,
    pub note_continuity_root: String,
    pub nullifier_key_image_root: String,
    pub receipt_commitment_root: String,
    pub payload_policy: String,
    pub public_metadata_root: String,
}

impl EncryptedReceiptLink {
    pub fn from_request(
        config: &Config,
        request: &LinkageFixtureRequest,
        continuity: &PrivateTransferNoteContinuity,
        nullifier: &NullifierKeyImageLink,
        audience: ReceiptAudience,
        encrypted_receipt_root: &str,
    ) -> Self {
        let public_metadata_root = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-RECEIPT-PUBLIC-METADATA-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.fixture_id),
                HashPart::Str(audience.as_str()),
                HashPart::U64(request.transfer_height),
                HashPart::Str(&request.fee_policy_root),
            ],
            32,
        );
        let receipt_commitment_root = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-ENCRYPTED-RECEIPT-COMMITMENT-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.transfer_id),
                HashPart::Str(audience.as_str()),
                HashPart::Str(encrypted_receipt_root),
                HashPart::Str(&continuity.continuity_root),
                HashPart::Str(&nullifier.nullifier_key_image_root),
                HashPart::Str(&public_metadata_root),
            ],
            32,
        );
        let receipt_id = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-ENCRYPTED-RECEIPT-ID",
            &[
                HashPart::Str(&request.transfer_id),
                HashPart::Str(audience.as_str()),
                HashPart::Str(&receipt_commitment_root),
            ],
            32,
        );
        Self {
            receipt_id,
            fixture_id: request.fixture_id.clone(),
            transfer_id: request.transfer_id.clone(),
            audience,
            encrypted_receipt_root: encrypted_receipt_root.to_string(),
            note_continuity_root: continuity.continuity_root.clone(),
            nullifier_key_image_root: nullifier.nullifier_key_image_root.clone(),
            receipt_commitment_root,
            payload_policy: config.encrypted_payload_policy.clone(),
            public_metadata_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "fixture_id": self.fixture_id,
            "transfer_id": self.transfer_id,
            "audience": self.audience,
            "encrypted_receipt_root": self.encrypted_receipt_root,
            "note_continuity_root": self.note_continuity_root,
            "nullifier_key_image_root": self.nullifier_key_image_root,
            "receipt_commitment_root": self.receipt_commitment_root,
            "payload_policy": self.payload_policy,
            "public_metadata_root": self.public_metadata_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletScanObligation {
    pub obligation_id: String,
    pub fixture_id: String,
    pub transfer_id: String,
    pub wallet_scan_hint_root: String,
    pub receipt_commitment_root: String,
    pub scan_window_start: u64,
    pub scan_window_end: u64,
    pub hint_index: u64,
    pub max_hint_count: u64,
    pub scan_obligation_root: String,
    pub leakage_policy: String,
}

impl WalletScanObligation {
    pub fn from_hint(
        config: &Config,
        request: &LinkageFixtureRequest,
        hint_index: u64,
        hint_root: &str,
        receipt_commitment_root: &str,
    ) -> Self {
        let scan_window_start = request.transfer_height;
        let scan_window_end = request.exit_height + config.forced_exit_receipt_depth;
        let scan_obligation_root = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-WALLET-SCAN-OBLIGATION-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.fixture_id),
                HashPart::Str(&request.transfer_id),
                HashPart::Str(hint_root),
                HashPart::Str(receipt_commitment_root),
                HashPart::U64(hint_index),
                HashPart::U64(scan_window_start),
                HashPart::U64(scan_window_end),
            ],
            32,
        );
        let obligation_id = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-WALLET-SCAN-OBLIGATION-ID",
            &[
                HashPart::Str(&request.transfer_id),
                HashPart::U64(hint_index),
                HashPart::Str(&scan_obligation_root),
            ],
            32,
        );
        Self {
            obligation_id,
            fixture_id: request.fixture_id.clone(),
            transfer_id: request.transfer_id.clone(),
            wallet_scan_hint_root: hint_root.to_string(),
            receipt_commitment_root: receipt_commitment_root.to_string(),
            scan_window_start,
            scan_window_end,
            hint_index,
            max_hint_count: config.max_scan_hints,
            scan_obligation_root,
            leakage_policy: "bounded_hint_roots_no_wallet_identifier".to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "obligation_id": self.obligation_id,
            "fixture_id": self.fixture_id,
            "transfer_id": self.transfer_id,
            "wallet_scan_hint_root": self.wallet_scan_hint_root,
            "receipt_commitment_root": self.receipt_commitment_root,
            "scan_window_start": self.scan_window_start,
            "scan_window_end": self.scan_window_end,
            "hint_index": self.hint_index,
            "max_hint_count": self.max_hint_count,
            "scan_obligation_root": self.scan_obligation_root,
            "leakage_policy": self.leakage_policy,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub fixture_id: String,
    pub max_metadata_units: u64,
    pub used_metadata_units: u64,
    pub public_field_count: u64,
    pub committed_field_count: u64,
    pub encrypted_field_count: u64,
    pub redacted_field_count: u64,
    pub budget_root: String,
    pub status: LinkageStatus,
}

impl RedactionBudget {
    pub fn from_commitments(
        config: &Config,
        request: &LinkageFixtureRequest,
        field_commitments: &[PublicFieldCommitment],
    ) -> Self {
        let public_field_count = field_commitments
            .iter()
            .map(|record| record.public_fields.len() as u64)
            .sum();
        let committed_field_count = field_commitments
            .iter()
            .map(|record| record.committed_fields.len() as u64)
            .sum();
        let encrypted_field_count = field_commitments
            .iter()
            .map(|record| record.encrypted_fields.len() as u64)
            .sum();
        let redacted_field_count = field_commitments
            .iter()
            .map(|record| record.redacted_fields.len() as u64)
            .sum();
        let status = if request.metadata_units <= config.max_metadata_units {
            LinkageStatus::Accepted
        } else {
            LinkageStatus::Rejected
        };
        let budget_root = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-REDACTION-BUDGET-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.fixture_id),
                HashPart::U64(config.max_metadata_units),
                HashPart::U64(request.metadata_units),
                HashPart::U64(public_field_count),
                HashPart::U64(committed_field_count),
                HashPart::U64(encrypted_field_count),
                HashPart::U64(redacted_field_count),
            ],
            32,
        );
        let budget_id = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-REDACTION-BUDGET-ID",
            &[
                HashPart::Str(&request.fixture_id),
                HashPart::Str(status.as_str()),
                HashPart::Str(&budget_root),
            ],
            32,
        );
        Self {
            budget_id,
            fixture_id: request.fixture_id.clone(),
            max_metadata_units: config.max_metadata_units,
            used_metadata_units: request.metadata_units,
            public_field_count,
            committed_field_count,
            encrypted_field_count,
            redacted_field_count,
            budget_root,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "fixture_id": self.fixture_id,
            "max_metadata_units": self.max_metadata_units,
            "used_metadata_units": self.used_metadata_units,
            "public_field_count": self.public_field_count,
            "committed_field_count": self.committed_field_count,
            "encrypted_field_count": self.encrypted_field_count,
            "redacted_field_count": self.redacted_field_count,
            "budget_root": self.budget_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeCapRoot {
    pub fee_cap_id: String,
    pub fixture_id: String,
    pub transfer_id: String,
    pub fee_policy_root: String,
    pub fee_cap_units: u64,
    pub max_fee_cap_units: u64,
    pub fee_cap_root: String,
    pub enforcement_policy: String,
    pub status: LinkageStatus,
}

impl FeeCapRoot {
    pub fn from_request(config: &Config, request: &LinkageFixtureRequest) -> Self {
        let status = if request.fee_cap_units <= config.max_fee_cap_units {
            LinkageStatus::Accepted
        } else {
            LinkageStatus::Rejected
        };
        let fee_cap_root = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-FEE-CAP-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.fixture_id),
                HashPart::Str(&request.transfer_id),
                HashPart::Str(&request.fee_policy_root),
                HashPart::U64(request.fee_cap_units),
                HashPart::U64(config.max_fee_cap_units),
            ],
            32,
        );
        let fee_cap_id = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-FEE-CAP-ID",
            &[
                HashPart::Str(&request.transfer_id),
                HashPart::Str(status.as_str()),
                HashPart::Str(&fee_cap_root),
            ],
            32,
        );
        Self {
            fee_cap_id,
            fixture_id: request.fixture_id.clone(),
            transfer_id: request.transfer_id.clone(),
            fee_policy_root: request.fee_policy_root.clone(),
            fee_cap_units: request.fee_cap_units,
            max_fee_cap_units: config.max_fee_cap_units,
            fee_cap_root,
            enforcement_policy: "root_only_fee_cap_no_amount_plaintext".to_string(),
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fee_cap_id": self.fee_cap_id,
            "fixture_id": self.fixture_id,
            "transfer_id": self.transfer_id,
            "fee_policy_root": self.fee_policy_root,
            "fee_cap_units": self.fee_cap_units,
            "max_fee_cap_units": self.max_fee_cap_units,
            "fee_cap_root": self.fee_cap_root,
            "enforcement_policy": self.enforcement_policy,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForcedExitReceiptContinuity {
    pub continuity_id: String,
    pub fixture_id: String,
    pub exit_claim_id: String,
    pub parent_exit_root: String,
    pub receipt_exit_root: String,
    pub claim_exit_root: String,
    pub encrypted_receipt_bundle_root: String,
    pub forced_exit_compatible_receipt_root: String,
    pub continuity_depth: u64,
    pub exit_height: u64,
    pub disclosure_policy: String,
}

impl ForcedExitReceiptContinuity {
    pub fn from_request(
        config: &Config,
        request: &LinkageFixtureRequest,
        receipts: &[EncryptedReceiptLink],
    ) -> Self {
        let encrypted_receipt_bundle_root = merkle_records(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-FORCED-EXIT-RECEIPT-BUNDLE",
            &receipts
                .iter()
                .map(|receipt| json!(receipt.receipt_commitment_root))
                .collect::<Vec<_>>(),
        );
        let forced_exit_compatible_receipt_root = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-FORCED-EXIT-COMPATIBLE-RECEIPT-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.fixture_id),
                HashPart::Str(&request.exit_claim_id),
                HashPart::Str(&request.forced_exit_parent_root),
                HashPart::Str(&request.forced_exit_receipt_root),
                HashPart::Str(&request.forced_exit_claim_root),
                HashPart::Str(&encrypted_receipt_bundle_root),
                HashPart::U64(config.forced_exit_receipt_depth),
            ],
            32,
        );
        let continuity_id = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-FORCED-EXIT-CONTINUITY-ID",
            &[
                HashPart::Str(&request.exit_claim_id),
                HashPart::Str(&forced_exit_compatible_receipt_root),
            ],
            32,
        );
        Self {
            continuity_id,
            fixture_id: request.fixture_id.clone(),
            exit_claim_id: request.exit_claim_id.clone(),
            parent_exit_root: request.forced_exit_parent_root.clone(),
            receipt_exit_root: request.forced_exit_receipt_root.clone(),
            claim_exit_root: request.forced_exit_claim_root.clone(),
            encrypted_receipt_bundle_root,
            forced_exit_compatible_receipt_root,
            continuity_depth: config.forced_exit_receipt_depth,
            exit_height: request.exit_height,
            disclosure_policy: "claim_receipt_roots_without_wallet_or_amount_plaintext".to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "continuity_id": self.continuity_id,
            "fixture_id": self.fixture_id,
            "exit_claim_id": self.exit_claim_id,
            "parent_exit_root": self.parent_exit_root,
            "receipt_exit_root": self.receipt_exit_root,
            "claim_exit_root": self.claim_exit_root,
            "encrypted_receipt_bundle_root": self.encrypted_receipt_bundle_root,
            "forced_exit_compatible_receipt_root": self.forced_exit_compatible_receipt_root,
            "continuity_depth": self.continuity_depth,
            "exit_height": self.exit_height,
            "disclosure_policy": self.disclosure_policy,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MetadataLeakBlocker {
    pub blocker_id: String,
    pub fixture_id: String,
    pub blocker_kind: LeakBlockerKind,
    pub guarded_root: String,
    pub allowed_metadata_units: u64,
    pub observed_metadata_units: u64,
    pub blocker_root: String,
    pub status: LinkageStatus,
}

impl MetadataLeakBlocker {
    pub fn from_parts(
        config: &Config,
        request: &LinkageFixtureRequest,
        blocker_kind: LeakBlockerKind,
        guarded_root: &str,
        observed_metadata_units: u64,
    ) -> Self {
        let status = if observed_metadata_units <= config.max_metadata_units {
            LinkageStatus::Accepted
        } else {
            LinkageStatus::Rejected
        };
        let blocker_root = blocker_root(
            blocker_kind,
            &request.fixture_id,
            guarded_root,
            observed_metadata_units,
        );
        let blocker_id = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-METADATA-LEAK-BLOCKER-ID",
            &[
                HashPart::Str(&request.fixture_id),
                HashPart::Str(blocker_kind.as_str()),
                HashPart::Str(status.as_str()),
                HashPart::Str(&blocker_root),
            ],
            32,
        );
        Self {
            blocker_id,
            fixture_id: request.fixture_id.clone(),
            blocker_kind,
            guarded_root: guarded_root.to_string(),
            allowed_metadata_units: config.max_metadata_units,
            observed_metadata_units,
            blocker_root,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "fixture_id": self.fixture_id,
            "blocker_kind": self.blocker_kind,
            "guarded_root": self.guarded_root,
            "allowed_metadata_units": self.allowed_metadata_units,
            "observed_metadata_units": self.observed_metadata_units,
            "blocker_root": self.blocker_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LinkageVerificationReport {
    pub report_id: String,
    pub fixture_id: String,
    pub status: LinkageStatus,
    pub accepted_count: u64,
    pub watch_count: u64,
    pub rejected_count: u64,
    pub note_continuity_root: String,
    pub receipt_continuity_root: String,
    pub scan_obligation_root: String,
    pub redaction_budget_root: String,
    pub fee_cap_root: String,
    pub leak_blocker_root: String,
    pub report_root: String,
}

impl LinkageVerificationReport {
    pub fn from_state_parts(
        request: &LinkageFixtureRequest,
        transfer: &PrivateTransferNoteContinuity,
        forced_exit: &ForcedExitReceiptContinuity,
        scan_obligations: &[WalletScanObligation],
        redaction_budget: &RedactionBudget,
        fee_cap: &FeeCapRoot,
        blockers: &[MetadataLeakBlocker],
    ) -> Self {
        let scan_obligation_root = merkle_records(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-SCAN-OBLIGATION-ROOT",
            &scan_obligations
                .iter()
                .map(WalletScanObligation::public_record)
                .collect::<Vec<_>>(),
        );
        let leak_blocker_root = merkle_records(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-LEAK-BLOCKER-ROOT",
            &blockers
                .iter()
                .map(MetadataLeakBlocker::public_record)
                .collect::<Vec<_>>(),
        );
        let statuses = blockers
            .iter()
            .map(|blocker| blocker.status)
            .chain([redaction_budget.status, fee_cap.status])
            .collect::<Vec<_>>();
        let accepted_count = statuses
            .iter()
            .filter(|status| matches!(status, LinkageStatus::Accepted))
            .count() as u64;
        let watch_count = statuses
            .iter()
            .filter(|status| matches!(status, LinkageStatus::Watch))
            .count() as u64;
        let rejected_count = statuses
            .iter()
            .filter(|status| matches!(status, LinkageStatus::Rejected))
            .count() as u64;
        let status = if rejected_count == 0 {
            LinkageStatus::Accepted
        } else {
            LinkageStatus::Rejected
        };
        let report_root = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-VERIFICATION-REPORT-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&request.fixture_id),
                HashPart::Str(status.as_str()),
                HashPart::Str(&transfer.continuity_root),
                HashPart::Str(&forced_exit.forced_exit_compatible_receipt_root),
                HashPart::Str(&scan_obligation_root),
                HashPart::Str(&redaction_budget.budget_root),
                HashPart::Str(&fee_cap.fee_cap_root),
                HashPart::Str(&leak_blocker_root),
            ],
            32,
        );
        let report_id = domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-VERIFICATION-REPORT-ID",
            &[
                HashPart::Str(&request.fixture_id),
                HashPart::Str(status.as_str()),
                HashPart::Str(&report_root),
            ],
            32,
        );
        Self {
            report_id,
            fixture_id: request.fixture_id.clone(),
            status,
            accepted_count,
            watch_count,
            rejected_count,
            note_continuity_root: transfer.continuity_root.clone(),
            receipt_continuity_root: forced_exit.forced_exit_compatible_receipt_root.clone(),
            scan_obligation_root,
            redaction_budget_root: redaction_budget.budget_root.clone(),
            fee_cap_root: fee_cap.fee_cap_root.clone(),
            leak_blocker_root,
            report_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "fixture_id": self.fixture_id,
            "status": self.status,
            "accepted_count": self.accepted_count,
            "watch_count": self.watch_count,
            "rejected_count": self.rejected_count,
            "note_continuity_root": self.note_continuity_root,
            "receipt_continuity_root": self.receipt_continuity_root,
            "scan_obligation_root": self.scan_obligation_root,
            "redaction_budget_root": self.redaction_budget_root,
            "fee_cap_root": self.fee_cap_root,
            "leak_blocker_root": self.leak_blocker_root,
            "report_root": self.report_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub request: LinkageFixtureRequest,
    pub field_commitments: BTreeMap<String, PublicFieldCommitment>,
    pub deposit_link: DepositMintedNoteLink,
    pub transfer_continuity: PrivateTransferNoteContinuity,
    pub nullifier_key_image_link: NullifierKeyImageLink,
    pub encrypted_receipts: BTreeMap<String, EncryptedReceiptLink>,
    pub wallet_scan_obligations: BTreeMap<String, WalletScanObligation>,
    pub redaction_budget: RedactionBudget,
    pub fee_cap_root: FeeCapRoot,
    pub forced_exit_receipt_continuity: ForcedExitReceiptContinuity,
    pub metadata_leak_blockers: BTreeMap<String, MetadataLeakBlocker>,
    pub verification_report: LinkageVerificationReport,
    pub state_roots: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        Self::from_request(Config::devnet(), LinkageFixtureRequest::devnet())
    }

    pub fn from_request(config: Config, request: LinkageFixtureRequest) -> Self {
        let field_commitments_vec = field_commitments(&request.fixture_id);
        let deposit_link = DepositMintedNoteLink::from_request(&request);
        let transfer_continuity =
            PrivateTransferNoteContinuity::from_request(&request, &deposit_link);
        let nullifier_key_image_link = NullifierKeyImageLink::from_request(&config, &request);
        let encrypted_receipts_vec = encrypted_receipts(
            &config,
            &request,
            &transfer_continuity,
            &nullifier_key_image_link,
        );
        let receipt_commitment_root = merkle_records(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-RECEIPT-COMMITMENT-ROOT",
            &encrypted_receipts_vec
                .iter()
                .map(|receipt| json!(receipt.receipt_commitment_root))
                .collect::<Vec<_>>(),
        );
        let wallet_scan_obligations_vec = request
            .wallet_scan_hint_roots
            .iter()
            .enumerate()
            .map(|(index, hint_root)| {
                WalletScanObligation::from_hint(
                    &config,
                    &request,
                    index as u64,
                    hint_root,
                    &receipt_commitment_root,
                )
            })
            .collect::<Vec<_>>();
        let redaction_budget =
            RedactionBudget::from_commitments(&config, &request, &field_commitments_vec);
        let fee_cap_root = FeeCapRoot::from_request(&config, &request);
        let forced_exit_receipt_continuity =
            ForcedExitReceiptContinuity::from_request(&config, &request, &encrypted_receipts_vec);
        let metadata_leak_blockers_vec = metadata_leak_blockers(
            &config,
            &request,
            &deposit_link,
            &transfer_continuity,
            &nullifier_key_image_link,
            &receipt_commitment_root,
            &redaction_budget,
            &fee_cap_root,
            &forced_exit_receipt_continuity,
        );
        let verification_report = LinkageVerificationReport::from_state_parts(
            &request,
            &transfer_continuity,
            &forced_exit_receipt_continuity,
            &wallet_scan_obligations_vec,
            &redaction_budget,
            &fee_cap_root,
            &metadata_leak_blockers_vec,
        );
        let field_commitments = map_by(
            field_commitments_vec,
            |record| record.commitment_id.clone(),
            "field_commitments",
        );
        let encrypted_receipts = map_by(
            encrypted_receipts_vec,
            |record| record.receipt_id.clone(),
            "encrypted_receipts",
        );
        let wallet_scan_obligations = map_by(
            wallet_scan_obligations_vec,
            |record| record.obligation_id.clone(),
            "wallet_scan_obligations",
        );
        let metadata_leak_blockers = map_by(
            metadata_leak_blockers_vec,
            |record| record.blocker_id.clone(),
            "metadata_leak_blockers",
        );
        let mut state = Self {
            config,
            request,
            field_commitments,
            deposit_link,
            transfer_continuity,
            nullifier_key_image_link,
            encrypted_receipts,
            wallet_scan_obligations,
            redaction_budget,
            fee_cap_root,
            forced_exit_receipt_continuity,
            metadata_leak_blockers,
            verification_report,
            state_roots: BTreeMap::new(),
        };
        state.state_roots = state.compute_state_roots();
        state
    }

    pub fn validate(&self) -> Result<()> {
        if self.request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below configured floor".to_string());
        }
        if self.request.metadata_units > self.config.max_metadata_units {
            return Err("metadata units exceed redaction budget".to_string());
        }
        if self.request.fee_cap_units > self.config.max_fee_cap_units {
            return Err("fee cap exceeds configured maximum".to_string());
        }
        if self.request.wallet_scan_hint_roots.len() as u64 > self.config.max_scan_hints {
            return Err("wallet scan hint count exceeds configured maximum".to_string());
        }
        if has_duplicates(&self.request.encrypted_receipt_roots) {
            return Err("encrypted receipt roots must be unique".to_string());
        }
        if has_duplicates(&self.request.wallet_scan_hint_roots) {
            return Err("wallet scan hint roots must be unique".to_string());
        }
        if !self.verification_report.status.release_compatible() {
            return Err("verification report is not release compatible".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "request": self.request.public_record(),
            "field_commitments": self.field_commitments.values().map(PublicFieldCommitment::public_record).collect::<Vec<_>>(),
            "deposit_link": self.deposit_link.public_record(),
            "transfer_continuity": self.transfer_continuity.public_record(),
            "nullifier_key_image_link": self.nullifier_key_image_link.public_record(),
            "encrypted_receipts": self.encrypted_receipts.values().map(EncryptedReceiptLink::public_record).collect::<Vec<_>>(),
            "wallet_scan_obligations": self.wallet_scan_obligations.values().map(WalletScanObligation::public_record).collect::<Vec<_>>(),
            "redaction_budget": self.redaction_budget.public_record(),
            "fee_cap_root": self.fee_cap_root.public_record(),
            "forced_exit_receipt_continuity": self.forced_exit_receipt_continuity.public_record(),
            "metadata_leak_blockers": self.metadata_leak_blockers.values().map(MetadataLeakBlocker::public_record).collect::<Vec<_>>(),
            "verification_report": self.verification_report.public_record(),
            "state_roots": self.state_roots,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
    }

    pub fn commitment_spine_root(&self) -> String {
        domain_hash(
            "PRIVATE-NOTE-RECEIPT-LINKAGE-COMMITMENT-SPINE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.deposit_link.minted_note_root),
                HashPart::Str(&self.transfer_continuity.continuity_root),
                HashPart::Str(&self.nullifier_key_image_link.nullifier_key_image_root),
                HashPart::Str(&self.verification_report.receipt_continuity_root),
                HashPart::Str(&self.verification_report.scan_obligation_root),
                HashPart::Str(&self.redaction_budget.budget_root),
                HashPart::Str(&self.fee_cap_root.fee_cap_root),
            ],
            32,
        )
    }

    pub fn compute_state_roots(&self) -> BTreeMap<String, String> {
        let mut roots = BTreeMap::new();
        roots.insert("config".to_string(), self.config.state_root());
        roots.insert("request".to_string(), self.request.state_root());
        roots.insert(
            "field_commitments".to_string(),
            merkle_records(
                "PRIVATE-NOTE-RECEIPT-LINKAGE-FIELD-COMMITMENTS",
                &self
                    .field_commitments
                    .values()
                    .map(PublicFieldCommitment::public_record)
                    .collect::<Vec<_>>(),
            ),
        );
        roots.insert(
            "deposit_link".to_string(),
            record_root("deposit_link", &self.deposit_link.public_record()),
        );
        roots.insert(
            "transfer_continuity".to_string(),
            record_root(
                "transfer_continuity",
                &self.transfer_continuity.public_record(),
            ),
        );
        roots.insert(
            "nullifier_key_image_link".to_string(),
            record_root(
                "nullifier_key_image_link",
                &self.nullifier_key_image_link.public_record(),
            ),
        );
        roots.insert(
            "encrypted_receipts".to_string(),
            merkle_records(
                "PRIVATE-NOTE-RECEIPT-LINKAGE-ENCRYPTED-RECEIPTS",
                &self
                    .encrypted_receipts
                    .values()
                    .map(EncryptedReceiptLink::public_record)
                    .collect::<Vec<_>>(),
            ),
        );
        roots.insert(
            "wallet_scan_obligations".to_string(),
            merkle_records(
                "PRIVATE-NOTE-RECEIPT-LINKAGE-WALLET-SCAN-OBLIGATIONS",
                &self
                    .wallet_scan_obligations
                    .values()
                    .map(WalletScanObligation::public_record)
                    .collect::<Vec<_>>(),
            ),
        );
        roots.insert(
            "redaction_budget".to_string(),
            record_root("redaction_budget", &self.redaction_budget.public_record()),
        );
        roots.insert(
            "fee_cap_root".to_string(),
            record_root("fee_cap_root", &self.fee_cap_root.public_record()),
        );
        roots.insert(
            "forced_exit_receipt_continuity".to_string(),
            record_root(
                "forced_exit_receipt_continuity",
                &self.forced_exit_receipt_continuity.public_record(),
            ),
        );
        roots.insert(
            "metadata_leak_blockers".to_string(),
            merkle_records(
                "PRIVATE-NOTE-RECEIPT-LINKAGE-METADATA-LEAK-BLOCKERS",
                &self
                    .metadata_leak_blockers
                    .values()
                    .map(MetadataLeakBlocker::public_record)
                    .collect::<Vec<_>>(),
            ),
        );
        roots.insert(
            "verification_report".to_string(),
            record_root(
                "verification_report",
                &self.verification_report.public_record(),
            ),
        );
        roots.insert("commitment_spine".to_string(), self.commitment_spine_root());
        roots
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

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-NOTE-RECEIPT-LINKAGE-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

pub fn label_root(domain: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-NOTE-RECEIPT-LINKAGE-LABEL",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn note_commitment(
    domain: &str,
    source_id: &str,
    position: u64,
    asset_id: &str,
    amount_commitment_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-NOTE-RECEIPT-LINKAGE-NOTE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(source_id),
            HashPart::U64(position),
            HashPart::Str(asset_id),
            HashPart::Str(amount_commitment_root),
        ],
        32,
    )
}

pub fn linkage_stage_root(stage: LinkageStage, stage_record: &Value) -> String {
    domain_hash(
        "PRIVATE-NOTE-RECEIPT-LINKAGE-STAGE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(stage.as_str()),
            HashPart::Json(stage_record),
        ],
        32,
    )
}

fn field_commitments(fixture_id: &str) -> Vec<PublicFieldCommitment> {
    vec![
        PublicFieldCommitment::from_parts(
            fixture_id,
            LinkageStage::DepositMint,
            vec!["deposit_lock_id", "note_commitment", "minted_note_root"],
            vec![
                "amount_commitment_root",
                "owner_view_tag_root",
                "spend_authority_commitment_root",
            ],
            vec![],
            vec!["wallet_address", "raw_amount", "monero_tx_private_metadata"],
        ),
        PublicFieldCommitment::from_parts(
            fixture_id,
            LinkageStage::PrivateTransfer,
            vec![
                "transfer_id",
                "input_note_commitment",
                "output_note_commitments",
            ],
            vec!["transfer_authorization_root", "balance_proof_root"],
            vec!["memo", "counterparty_context"],
            vec!["sender_wallet_id", "recipient_wallet_id", "amount_split"],
        ),
        PublicFieldCommitment::from_parts(
            fixture_id,
            LinkageStage::NullifierKeyImage,
            vec![
                "nullifier_commitment",
                "key_image_commitment",
                "replay_fence_root",
            ],
            vec!["spent_note_commitment", "anonymity_set_size"],
            vec![],
            vec!["spend_key", "ring_member_selection", "wallet_scan_path"],
        ),
        PublicFieldCommitment::from_parts(
            fixture_id,
            LinkageStage::EncryptedReceipt,
            vec!["encrypted_receipt_root", "receipt_commitment_root"],
            vec!["note_continuity_root", "nullifier_key_image_root"],
            vec!["receipt_payload", "recovery_payload"],
            vec!["plaintext_amount", "plaintext_recipient", "view_secret"],
        ),
        PublicFieldCommitment::from_parts(
            fixture_id,
            LinkageStage::WalletScan,
            vec![
                "wallet_scan_hint_root",
                "scan_window_start",
                "scan_window_end",
            ],
            vec!["receipt_commitment_root"],
            vec!["view_tag_ciphertext"],
            vec!["subaddress", "wallet_identifier", "scan_match_position"],
        ),
        PublicFieldCommitment::from_parts(
            fixture_id,
            LinkageStage::ExitClaim,
            vec!["exit_claim_id", "forced_exit_compatible_receipt_root"],
            vec!["parent_exit_root", "receipt_exit_root", "claim_exit_root"],
            vec!["recovery_receipt_payload"],
            vec![
                "owner_identity",
                "destination_address",
                "claim_private_note_path",
            ],
        ),
    ]
}

fn encrypted_receipts(
    config: &Config,
    request: &LinkageFixtureRequest,
    continuity: &PrivateTransferNoteContinuity,
    nullifier: &NullifierKeyImageLink,
) -> Vec<EncryptedReceiptLink> {
    let audiences = [
        ReceiptAudience::Recipient,
        ReceiptAudience::SenderChange,
        ReceiptAudience::ForcedExitRecovery,
    ];
    request
        .encrypted_receipt_roots
        .iter()
        .enumerate()
        .map(|(index, root)| {
            EncryptedReceiptLink::from_request(
                config,
                request,
                continuity,
                nullifier,
                audiences
                    .get(index)
                    .copied()
                    .unwrap_or(ReceiptAudience::WatcherChallenge),
                root,
            )
        })
        .collect()
}

fn metadata_leak_blockers(
    config: &Config,
    request: &LinkageFixtureRequest,
    deposit: &DepositMintedNoteLink,
    transfer: &PrivateTransferNoteContinuity,
    nullifier: &NullifierKeyImageLink,
    receipt_commitment_root: &str,
    redaction_budget: &RedactionBudget,
    fee_cap: &FeeCapRoot,
    forced_exit: &ForcedExitReceiptContinuity,
) -> Vec<MetadataLeakBlocker> {
    vec![
        MetadataLeakBlocker::from_parts(
            config,
            request,
            LeakBlockerKind::PublicFieldAllowlist,
            &redaction_budget.budget_root,
            request.metadata_units,
        ),
        MetadataLeakBlocker::from_parts(
            config,
            request,
            LeakBlockerKind::CommitmentOnlyAmount,
            &deposit.minted_note_root,
            1,
        ),
        MetadataLeakBlocker::from_parts(
            config,
            request,
            LeakBlockerKind::NullifierAnonymitySet,
            &nullifier.nullifier_key_image_root,
            1,
        ),
        MetadataLeakBlocker::from_parts(
            config,
            request,
            LeakBlockerKind::EncryptedReceiptPayload,
            receipt_commitment_root,
            1,
        ),
        MetadataLeakBlocker::from_parts(
            config,
            request,
            LeakBlockerKind::BoundedScanHint,
            &transfer.continuity_root,
            request.wallet_scan_hint_roots.len() as u64,
        ),
        MetadataLeakBlocker::from_parts(
            config,
            request,
            LeakBlockerKind::FeeCapRootOnly,
            &fee_cap.fee_cap_root,
            1,
        ),
        MetadataLeakBlocker::from_parts(
            config,
            request,
            LeakBlockerKind::ForcedExitRedaction,
            &forced_exit.forced_exit_compatible_receipt_root,
            2,
        ),
    ]
}

fn blocker_root(
    blocker_kind: LeakBlockerKind,
    fixture_id: &str,
    guarded_root: &str,
    observed_metadata_units: u64,
) -> String {
    domain_hash(
        "PRIVATE-NOTE-RECEIPT-LINKAGE-METADATA-BLOCKER-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(fixture_id),
            HashPart::Str(blocker_kind.as_str()),
            HashPart::Str(guarded_root),
            HashPart::U64(observed_metadata_units),
        ],
        32,
    )
}

fn merkle_records(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

fn stringify(values: Vec<&str>) -> Vec<String> {
    values.into_iter().map(str::to_string).collect()
}

fn map_by<T, F>(records: Vec<T>, key_fn: F, label: &str) -> BTreeMap<String, T>
where
    F: Fn(&T) -> String,
{
    let mut map = BTreeMap::new();
    for record in records {
        let key = key_fn(&record);
        if map.insert(key.clone(), record).is_some() {
            let duplicate_root = domain_hash(
                "PRIVATE-NOTE-RECEIPT-LINKAGE-DUPLICATE-MAP-KEY",
                &[HashPart::Str(label), HashPart::Str(&key)],
                32,
            );
            map.remove(&duplicate_root);
        }
    }
    map
}

fn has_duplicates(values: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().any(|value| !seen.insert(value))
}
