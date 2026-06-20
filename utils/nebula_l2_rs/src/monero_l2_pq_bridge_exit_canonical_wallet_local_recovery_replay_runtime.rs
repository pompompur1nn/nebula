use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalWalletLocalRecoveryReplayRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_WALLET_LOCAL_RECOVERY_REPLAY_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-wallet-local-recovery-replay-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_WALLET_LOCAL_RECOVERY_REPLAY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const REPLAY_SUITE: &str = "monero-l2-pq-bridge-exit-canonical-wallet-local-recovery-replay-v1";
pub const DEFAULT_MIN_SCAN_HINT_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_RECEIPT_SHARDS: u16 = 2;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_METADATA_LEAKAGE_UNITS: u16 = 2;
pub const DEFAULT_FORCE_EXIT_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_OPERATOR_SILENCE_BLOCKS: u64 = 16;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    Complete,
    Reconstructable,
    WatchOnly,
    Blocked,
}

impl RecoveryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Reconstructable => "reconstructable",
            Self::WatchOnly => "watch_only",
            Self::Blocked => "blocked",
        }
    }

    pub fn can_build_claim(self) -> bool {
        matches!(self, Self::Complete | Self::Reconstructable)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupStatus {
    VerifiedLocal,
    VerifiedRemoteEncrypted,
    Partial,
    Missing,
}

impl BackupStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedLocal => "verified_local",
            Self::VerifiedRemoteEncrypted => "verified_remote_encrypted",
            Self::Partial => "partial",
            Self::Missing => "missing",
        }
    }

    pub fn is_usable(self) -> bool {
        matches!(self, Self::VerifiedLocal | Self::VerifiedRemoteEncrypted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanHintKind {
    ViewTag,
    SubaddressWindow,
    ReceiptLocator,
    DecoySetAnchor,
}

impl ScanHintKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewTag => "view_tag",
            Self::SubaddressWindow => "subaddress_window",
            Self::ReceiptLocator => "receipt_locator",
            Self::DecoySetAnchor => "decoy_set_anchor",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptShardStatus {
    Present,
    RecoveredFromBackup,
    PublicCommitmentOnly,
    Missing,
}

impl ReceiptShardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::RecoveredFromBackup => "recovered_from_backup",
            Self::PublicCommitmentOnly => "public_commitment_only",
            Self::Missing => "missing",
        }
    }

    pub fn is_recoverable(self) -> bool {
        matches!(self, Self::Present | Self::RecoveredFromBackup)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeakageField {
    AmountBucket,
    ScanWindow,
    DestinationCommitment,
    TimingBucket,
    WalletLabel,
}

impl LeakageField {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AmountBucket => "amount_bucket",
            Self::ScanWindow => "scan_window",
            Self::DestinationCommitment => "destination_commitment",
            Self::TimingBucket => "timing_bucket",
            Self::WalletLabel => "wallet_label",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayBlocker {
    BackupUnavailable,
    ReceiptThresholdUnavailable,
    ScanHintPrivacyBelowFloor,
    NoteReconstructionFailed,
    NullifierReconstructionFailed,
    PqAuthorizationUnavailable,
    MetadataLeakageExceeded,
    ClaimBuilderIncomplete,
}

impl ReplayBlocker {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BackupUnavailable => "backup_unavailable",
            Self::ReceiptThresholdUnavailable => "receipt_threshold_unavailable",
            Self::ScanHintPrivacyBelowFloor => "scan_hint_privacy_below_floor",
            Self::NoteReconstructionFailed => "note_reconstruction_failed",
            Self::NullifierReconstructionFailed => "nullifier_reconstruction_failed",
            Self::PqAuthorizationUnavailable => "pq_authorization_unavailable",
            Self::MetadataLeakageExceeded => "metadata_leakage_exceeded",
            Self::ClaimBuilderIncomplete => "claim_builder_incomplete",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub replay_suite: String,
    pub min_scan_hint_privacy_set_size: u64,
    pub min_receipt_shards: u16,
    pub min_pq_security_bits: u16,
    pub max_metadata_leakage_units: u16,
    pub force_exit_window_blocks: u64,
    pub max_operator_silence_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            replay_suite: REPLAY_SUITE.to_string(),
            min_scan_hint_privacy_set_size: DEFAULT_MIN_SCAN_HINT_PRIVACY_SET_SIZE,
            min_receipt_shards: DEFAULT_MIN_RECEIPT_SHARDS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_metadata_leakage_units: DEFAULT_MAX_METADATA_LEAKAGE_UNITS,
            force_exit_window_blocks: DEFAULT_FORCE_EXIT_WINDOW_BLOCKS,
            max_operator_silence_blocks: DEFAULT_MAX_OPERATOR_SILENCE_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "replay_suite": self.replay_suite,
            "min_scan_hint_privacy_set_size": self.min_scan_hint_privacy_set_size,
            "min_receipt_shards": self.min_receipt_shards,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_metadata_leakage_units": self.max_metadata_leakage_units,
            "force_exit_window_blocks": self.force_exit_window_blocks,
            "max_operator_silence_blocks": self.max_operator_silence_blocks,
        })
    }

    pub fn root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletScanHint {
    pub hint_id: String,
    pub kind: ScanHintKind,
    pub hint_commitment_root: String,
    pub scan_from_height: u64,
    pub scan_to_height: u64,
    pub privacy_set_size: u64,
    pub reveals_amount: bool,
    pub reveals_destination: bool,
}

impl WalletScanHint {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "kind": self.kind.as_str(),
            "hint_commitment_root": self.hint_commitment_root,
            "scan_from_height": self.scan_from_height,
            "scan_to_height": self.scan_to_height,
            "privacy_set_size": self.privacy_set_size,
            "reveals_amount": self.reveals_amount,
            "reveals_destination": self.reveals_destination,
        })
    }

    pub fn root(&self) -> String {
        record_root("WALLET-SCAN-HINT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedReceiptShard {
    pub shard_id: String,
    pub status: ReceiptShardStatus,
    pub cipher_suite: String,
    pub ciphertext_root: String,
    pub recovery_share_root: String,
    pub holder_commitment_root: String,
    pub opened_at_l2_height: u64,
}

impl EncryptedReceiptShard {
    pub fn public_record(&self) -> Value {
        json!({
            "shard_id": self.shard_id,
            "status": self.status.as_str(),
            "cipher_suite": self.cipher_suite,
            "ciphertext_root": self.ciphertext_root,
            "recovery_share_root": self.recovery_share_root,
            "holder_commitment_root": self.holder_commitment_root,
            "opened_at_l2_height": self.opened_at_l2_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("ENCRYPTED-RECEIPT-SHARD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocalNoteReconstruction {
    pub note_id: String,
    pub note_commitment_root: String,
    pub amount_commitment_root: String,
    pub destination_commitment_root: String,
    pub note_path_root: String,
    pub reconstructed_from_local_view_key: bool,
}

impl LocalNoteReconstruction {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "note_commitment_root": self.note_commitment_root,
            "amount_commitment_root": self.amount_commitment_root,
            "destination_commitment_root": self.destination_commitment_root,
            "note_path_root": self.note_path_root,
            "reconstructed_from_local_view_key": self.reconstructed_from_local_view_key,
        })
    }

    pub fn root(&self) -> String {
        record_root("LOCAL-NOTE-RECONSTRUCTION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocalNullifierReconstruction {
    pub nullifier_id: String,
    pub nullifier_root: String,
    pub key_image_root: String,
    pub spend_key_commitment_root: String,
    pub replay_domain_root: String,
    pub duplicate_seen: bool,
}

impl LocalNullifierReconstruction {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "nullifier_root": self.nullifier_root,
            "key_image_root": self.key_image_root,
            "spend_key_commitment_root": self.spend_key_commitment_root,
            "replay_domain_root": self.replay_domain_root,
            "duplicate_seen": self.duplicate_seen,
        })
    }

    pub fn root(&self) -> String {
        record_root("LOCAL-NULLIFIER-RECONSTRUCTION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqWithdrawalAuthorizationMaterial {
    pub authorization_id: String,
    pub scheme: String,
    pub wallet_authority_root: String,
    pub signature_transcript_root: String,
    pub public_key_commitment_root: String,
    pub security_bits: u16,
    pub expires_at_l2_height: u64,
    pub signer_available_offline: bool,
}

impl PqWithdrawalAuthorizationMaterial {
    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "scheme": self.scheme,
            "wallet_authority_root": self.wallet_authority_root,
            "signature_transcript_root": self.signature_transcript_root,
            "public_key_commitment_root": self.public_key_commitment_root,
            "security_bits": self.security_bits,
            "expires_at_l2_height": self.expires_at_l2_height,
            "signer_available_offline": self.signer_available_offline,
        })
    }

    pub fn root(&self) -> String {
        record_root("PQ-WITHDRAWAL-AUTHORIZATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactedClaimBuilderInputs {
    pub claim_builder_id: String,
    pub forced_exit_claim_id: String,
    pub receipt_root: String,
    pub note_root: String,
    pub nullifier_root: String,
    pub pq_authorization_root: String,
    pub redacted_wallet_state_root: String,
    pub public_input_root: String,
    pub ready: bool,
}

impl RedactedClaimBuilderInputs {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_builder_id": self.claim_builder_id,
            "forced_exit_claim_id": self.forced_exit_claim_id,
            "receipt_root": self.receipt_root,
            "note_root": self.note_root,
            "nullifier_root": self.nullifier_root,
            "pq_authorization_root": self.pq_authorization_root,
            "redacted_wallet_state_root": self.redacted_wallet_state_root,
            "public_input_root": self.public_input_root,
            "ready": self.ready,
        })
    }

    pub fn root(&self) -> String {
        record_root("REDACTED-CLAIM-BUILDER-INPUTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MetadataLeakageBudget {
    pub budget_id: String,
    pub max_units: u16,
    pub used_units: u16,
    pub public_fields: Vec<LeakageField>,
    pub redacted_fields_root: String,
}

impl MetadataLeakageBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "max_units": self.max_units,
            "used_units": self.used_units,
            "public_fields": self.public_fields.iter().map(|field| field.as_str()).collect::<Vec<_>>(),
            "redacted_fields_root": self.redacted_fields_root,
        })
    }

    pub fn within_budget(&self) -> bool {
        self.used_units <= self.max_units
    }

    pub fn root(&self) -> String {
        record_root("METADATA-LEAKAGE-BUDGET", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackupRecoveryStatus {
    pub backup_id: String,
    pub status: BackupStatus,
    pub wallet_backup_root: String,
    pub local_receipt_db_root: String,
    pub recovery_hint_root: String,
    pub last_verified_l2_height: u64,
}

impl BackupRecoveryStatus {
    pub fn public_record(&self) -> Value {
        json!({
            "backup_id": self.backup_id,
            "status": self.status.as_str(),
            "wallet_backup_root": self.wallet_backup_root,
            "local_receipt_db_root": self.local_receipt_db_root,
            "recovery_hint_root": self.recovery_hint_root,
            "last_verified_l2_height": self.last_verified_l2_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("BACKUP-RECOVERY-STATUS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveryReplayRoots {
    pub config_root: String,
    pub scan_hint_root: String,
    pub receipt_shard_root: String,
    pub note_reconstruction_root: String,
    pub nullifier_reconstruction_root: String,
    pub pq_authorization_root: String,
    pub claim_builder_root: String,
    pub metadata_leakage_root: String,
    pub backup_recovery_root: String,
}

impl RecoveryReplayRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "scan_hint_root": self.scan_hint_root,
            "receipt_shard_root": self.receipt_shard_root,
            "note_reconstruction_root": self.note_reconstruction_root,
            "nullifier_reconstruction_root": self.nullifier_reconstruction_root,
            "pq_authorization_root": self.pq_authorization_root,
            "claim_builder_root": self.claim_builder_root,
            "metadata_leakage_root": self.metadata_leakage_root,
            "backup_recovery_root": self.backup_recovery_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub status: RecoveryStatus,
    pub operator_data_withheld: bool,
    pub operator_silence_blocks: u64,
    pub scan_hints: Vec<WalletScanHint>,
    pub receipt_shards: Vec<EncryptedReceiptShard>,
    pub note: LocalNoteReconstruction,
    pub nullifier: LocalNullifierReconstruction,
    pub pq_authorization: PqWithdrawalAuthorizationMaterial,
    pub claim_builder: RedactedClaimBuilderInputs,
    pub metadata_budget: MetadataLeakageBudget,
    pub backup: BackupRecoveryStatus,
    pub blockers: Vec<ReplayBlocker>,
    pub wallet_can_rebuild_forced_exit_claim_without_operator: bool,
    pub answer: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let scan_hints = vec![
            WalletScanHint {
                hint_id: stable_id("scan-hint", "view-tag-window"),
                kind: ScanHintKind::ViewTag,
                hint_commitment_root: fixture_root("scan-hint", "view-tag-window"),
                scan_from_height: 1_248_000,
                scan_to_height: 1_249_440,
                privacy_set_size: 98_304,
                reveals_amount: false,
                reveals_destination: false,
            },
            WalletScanHint {
                hint_id: stable_id("scan-hint", "receipt-locator"),
                kind: ScanHintKind::ReceiptLocator,
                hint_commitment_root: fixture_root("scan-hint", "receipt-locator"),
                scan_from_height: 1_248_360,
                scan_to_height: 1_249_080,
                privacy_set_size: 73_728,
                reveals_amount: false,
                reveals_destination: false,
            },
        ];
        let receipt_shards = vec![
            EncryptedReceiptShard {
                shard_id: stable_id("receipt-shard", "wallet-local-a"),
                status: ReceiptShardStatus::Present,
                cipher_suite: "hybrid-view-key-ml-kem-1024-aead".to_string(),
                ciphertext_root: fixture_root("receipt-ciphertext", "wallet-local-a"),
                recovery_share_root: fixture_root("receipt-share", "wallet-local-a"),
                holder_commitment_root: fixture_root("holder", "wallet-local"),
                opened_at_l2_height: 1_249_020,
            },
            EncryptedReceiptShard {
                shard_id: stable_id("receipt-shard", "encrypted-backup-b"),
                status: ReceiptShardStatus::RecoveredFromBackup,
                cipher_suite: "hybrid-view-key-ml-kem-1024-aead".to_string(),
                ciphertext_root: fixture_root("receipt-ciphertext", "encrypted-backup-b"),
                recovery_share_root: fixture_root("receipt-share", "encrypted-backup-b"),
                holder_commitment_root: fixture_root("holder", "encrypted-backup"),
                opened_at_l2_height: 1_249_021,
            },
        ];
        let note = LocalNoteReconstruction {
            note_id: stable_id("note", "forced-exit-note-7"),
            note_commitment_root: fixture_root("note-commitment", "forced-exit-note-7"),
            amount_commitment_root: fixture_root("amount-commitment", "forced-exit-note-7"),
            destination_commitment_root: fixture_root(
                "destination-commitment",
                "forced-exit-note-7",
            ),
            note_path_root: fixture_root("note-path", "forced-exit-note-7"),
            reconstructed_from_local_view_key: true,
        };
        let nullifier = LocalNullifierReconstruction {
            nullifier_id: stable_id("nullifier", "forced-exit-note-7"),
            nullifier_root: fixture_root("nullifier", "forced-exit-note-7"),
            key_image_root: fixture_root("key-image", "forced-exit-note-7"),
            spend_key_commitment_root: fixture_root("spend-key", "forced-exit-note-7"),
            replay_domain_root: fixture_root("replay-domain", "forced-exit-note-7"),
            duplicate_seen: false,
        };
        let pq_authorization = PqWithdrawalAuthorizationMaterial {
            authorization_id: stable_id("pq-authorization", "forced-exit-note-7"),
            scheme: "ml-dsa-87-with-ml-kem-1024-binding".to_string(),
            wallet_authority_root: fixture_root("wallet-authority", "forced-exit-note-7"),
            signature_transcript_root: fixture_root("signature-transcript", "forced-exit-note-7"),
            public_key_commitment_root: fixture_root("pq-public-key", "forced-exit-note-7"),
            security_bits: 256,
            expires_at_l2_height: 1_249_740,
            signer_available_offline: true,
        };
        let receipt_root = receipt_shards_root(&receipt_shards);
        let note_root = note.root();
        let nullifier_root = nullifier.root();
        let pq_authorization_root = pq_authorization.root();
        let claim_builder = RedactedClaimBuilderInputs {
            claim_builder_id: stable_id("claim-builder", "forced-exit-note-7"),
            forced_exit_claim_id: stable_id("forced-exit-claim", "operator-withheld-data"),
            receipt_root,
            note_root,
            nullifier_root,
            pq_authorization_root,
            redacted_wallet_state_root: fixture_root("redacted-wallet-state", "forced-exit-note-7"),
            public_input_root: fixture_root("public-inputs", "forced-exit-note-7"),
            ready: true,
        };
        let metadata_budget = MetadataLeakageBudget {
            budget_id: stable_id("metadata-budget", "forced-exit-note-7"),
            max_units: config.max_metadata_leakage_units,
            used_units: 2,
            public_fields: vec![LeakageField::AmountBucket, LeakageField::ScanWindow],
            redacted_fields_root: fixture_root("redacted-fields", "forced-exit-note-7"),
        };
        let backup = BackupRecoveryStatus {
            backup_id: stable_id("backup", "wallet-local-recovery"),
            status: BackupStatus::VerifiedLocal,
            wallet_backup_root: fixture_root("wallet-backup", "wallet-local-recovery"),
            local_receipt_db_root: fixture_root("receipt-db", "wallet-local-recovery"),
            recovery_hint_root: fixture_root("recovery-hints", "wallet-local-recovery"),
            last_verified_l2_height: 1_249_024,
        };
        let operator_data_withheld = true;
        let operator_silence_blocks = 24;
        let blockers = derive_blockers(
            &config,
            operator_data_withheld,
            operator_silence_blocks,
            &scan_hints,
            &receipt_shards,
            &note,
            &nullifier,
            &pq_authorization,
            &claim_builder,
            &metadata_budget,
            &backup,
        );
        let status = derive_status(&blockers, &backup, &claim_builder);
        let wallet_can_rebuild_forced_exit_claim_without_operator =
            status.can_build_claim() && blockers.is_empty();
        let answer = recovery_answer(wallet_can_rebuild_forced_exit_claim_without_operator);
        Self {
            config,
            status,
            operator_data_withheld,
            operator_silence_blocks,
            scan_hints,
            receipt_shards,
            note,
            nullifier,
            pq_authorization,
            claim_builder,
            metadata_budget,
            backup,
            blockers,
            wallet_can_rebuild_forced_exit_claim_without_operator,
            answer,
        }
    }

    pub fn roots(&self) -> RecoveryReplayRoots {
        RecoveryReplayRoots {
            config_root: self.config.root(),
            scan_hint_root: scan_hints_root(&self.scan_hints),
            receipt_shard_root: receipt_shards_root(&self.receipt_shards),
            note_reconstruction_root: self.note.root(),
            nullifier_reconstruction_root: self.nullifier.root(),
            pq_authorization_root: self.pq_authorization.root(),
            claim_builder_root: self.claim_builder.root(),
            metadata_leakage_root: self.metadata_budget.root(),
            backup_recovery_root: self.backup.root(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "config": self.config.public_record(),
            "status": self.status.as_str(),
            "operator_data_withheld": self.operator_data_withheld,
            "operator_silence_blocks": self.operator_silence_blocks,
            "roots": self.roots().public_record(),
            "scan_hints": self.scan_hints.iter().map(WalletScanHint::public_record).collect::<Vec<_>>(),
            "receipt_shards": self.receipt_shards.iter().map(EncryptedReceiptShard::public_record).collect::<Vec<_>>(),
            "note": self.note.public_record(),
            "nullifier": self.nullifier.public_record(),
            "pq_authorization": self.pq_authorization.public_record(),
            "claim_builder": self.claim_builder.public_record(),
            "metadata_budget": self.metadata_budget.public_record(),
            "backup": self.backup.public_record(),
            "blockers": self.blockers.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
            "wallet_can_rebuild_forced_exit_claim_without_operator": self.wallet_can_rebuild_forced_exit_claim_without_operator,
            "answer": self.answer,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        record_root("STATE", &self.public_record_without_state_root())
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
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

pub fn derive_blockers(
    config: &Config,
    operator_data_withheld: bool,
    operator_silence_blocks: u64,
    scan_hints: &[WalletScanHint],
    receipt_shards: &[EncryptedReceiptShard],
    note: &LocalNoteReconstruction,
    nullifier: &LocalNullifierReconstruction,
    pq_authorization: &PqWithdrawalAuthorizationMaterial,
    claim_builder: &RedactedClaimBuilderInputs,
    metadata_budget: &MetadataLeakageBudget,
    backup: &BackupRecoveryStatus,
) -> Vec<ReplayBlocker> {
    let mut blockers = Vec::new();
    let recoverable_shards = receipt_shards
        .iter()
        .filter(|shard| shard.status.is_recoverable())
        .count() as u16;
    let scan_hint_floor_met = scan_hints
        .iter()
        .all(|hint| hint.privacy_set_size >= config.min_scan_hint_privacy_set_size);
    let operator_replay_gate =
        !operator_data_withheld || operator_silence_blocks >= config.max_operator_silence_blocks;

    if !backup.status.is_usable() {
        blockers.push(ReplayBlocker::BackupUnavailable);
    }
    if recoverable_shards < config.min_receipt_shards {
        blockers.push(ReplayBlocker::ReceiptThresholdUnavailable);
    }
    if !scan_hint_floor_met {
        blockers.push(ReplayBlocker::ScanHintPrivacyBelowFloor);
    }
    if !note.reconstructed_from_local_view_key {
        blockers.push(ReplayBlocker::NoteReconstructionFailed);
    }
    if nullifier.duplicate_seen {
        blockers.push(ReplayBlocker::NullifierReconstructionFailed);
    }
    if pq_authorization.security_bits < config.min_pq_security_bits
        || !pq_authorization.signer_available_offline
    {
        blockers.push(ReplayBlocker::PqAuthorizationUnavailable);
    }
    if !metadata_budget.within_budget() {
        blockers.push(ReplayBlocker::MetadataLeakageExceeded);
    }
    if !claim_builder.ready || !operator_replay_gate {
        blockers.push(ReplayBlocker::ClaimBuilderIncomplete);
    }
    blockers
}

pub fn derive_status(
    blockers: &[ReplayBlocker],
    backup: &BackupRecoveryStatus,
    claim_builder: &RedactedClaimBuilderInputs,
) -> RecoveryStatus {
    if blockers.is_empty() && backup.status == BackupStatus::VerifiedLocal && claim_builder.ready {
        RecoveryStatus::Complete
    } else if blockers.is_empty() && claim_builder.ready {
        RecoveryStatus::Reconstructable
    } else if backup.status.is_usable() {
        RecoveryStatus::WatchOnly
    } else {
        RecoveryStatus::Blocked
    }
}

pub fn recovery_answer(can_rebuild: bool) -> String {
    if can_rebuild {
        "yes: wallet-local recovery rebuilds the forced-exit claim without operator cooperation"
            .to_string()
    } else {
        "no: wallet-local recovery lacks enough private evidence for a forced-exit claim"
            .to_string()
    }
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-LOCAL-RECOVERY-REPLAY-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

pub fn fixture_root(kind: &str, seed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-LOCAL-RECOVERY-REPLAY-DEVNET-FIXTURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(seed),
        ],
        32,
    )
}

pub fn stable_id(kind: &str, seed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-LOCAL-RECOVERY-REPLAY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(seed),
        ],
        16,
    )
}

pub fn scan_hints_root(scan_hints: &[WalletScanHint]) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-LOCAL-RECOVERY-REPLAY-SCAN-HINTS",
        &scan_hints
            .iter()
            .map(WalletScanHint::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn receipt_shards_root(receipt_shards: &[EncryptedReceiptShard]) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-LOCAL-RECOVERY-REPLAY-RECEIPT-SHARDS",
        &receipt_shards
            .iter()
            .map(EncryptedReceiptShard::public_record)
            .collect::<Vec<_>>(),
    )
}
