use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalWalletReconstructionVectorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_WALLET_RECONSTRUCTION_VECTOR_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-wallet-reconstruction-vector-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_WALLET_RECONSTRUCTION_VECTOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const VECTOR_SUITE: &str = "monero-l2-pq-bridge-exit-canonical-wallet-reconstruction-vector-v1";
pub const DEFAULT_MIN_RECEIPT_SHARDS: u16 = 2;
pub const DEFAULT_MIN_SCAN_HINT_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_METADATA_LEAKAGE_UNITS: u16 = 2;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LOW_FEE_CAP_ATOMIC: u64 = 30_000_000;
pub const DEFAULT_FORCE_EXIT_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_VECTORS: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconstructionStatus {
    Canonical,
    Reconstructable,
    WatchOnly,
    Blocked,
}

impl ReconstructionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::Reconstructable => "reconstructable",
            Self::WatchOnly => "watch_only",
            Self::Blocked => "blocked",
        }
    }

    pub fn can_build_claim(self) -> bool {
        matches!(self, Self::Canonical | Self::Reconstructable)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptCipherSuite {
    MlKem768Aead,
    MlKem1024Aead,
    HybridViewKeyMlKem,
}

impl ReceiptCipherSuite {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlKem768Aead => "ml_kem_768_aead",
            Self::MlKem1024Aead => "ml_kem_1024_aead",
            Self::HybridViewKeyMlKem => "hybrid_view_key_ml_kem",
        }
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
pub enum MetadataField {
    Amount,
    Destination,
    Subaddress,
    ScanWindow,
    Timing,
    WalletLabel,
}

impl MetadataField {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Amount => "amount",
            Self::Destination => "destination",
            Self::Subaddress => "subaddress",
            Self::ScanWindow => "scan_window",
            Self::Timing => "timing",
            Self::WalletLabel => "wallet_label",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRetention {
    WalletSecret,
    WalletEncrypted,
    PublicCommitment,
    ChainReconstructable,
    DevnetFixture,
}

impl EvidenceRetention {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletSecret => "wallet_secret",
            Self::WalletEncrypted => "wallet_encrypted",
            Self::PublicCommitment => "public_commitment",
            Self::ChainReconstructable => "chain_reconstructable",
            Self::DevnetFixture => "devnet_fixture",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconstructionBlocker {
    ReceiptRecoveryBelowThreshold,
    ScanHintPrivacyBelowFloor,
    NoteCommitmentMissing,
    NullifierCommitmentMissing,
    PqAuthorizationWeak,
    RedactionPolicyIncomplete,
    LowFeePathUnavailable,
    ExitClaimInputsIncomplete,
}

impl ReconstructionBlocker {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptRecoveryBelowThreshold => "receipt_recovery_below_threshold",
            Self::ScanHintPrivacyBelowFloor => "scan_hint_privacy_below_floor",
            Self::NoteCommitmentMissing => "note_commitment_missing",
            Self::NullifierCommitmentMissing => "nullifier_commitment_missing",
            Self::PqAuthorizationWeak => "pq_authorization_weak",
            Self::RedactionPolicyIncomplete => "redaction_policy_incomplete",
            Self::LowFeePathUnavailable => "low_fee_path_unavailable",
            Self::ExitClaimInputsIncomplete => "exit_claim_inputs_incomplete",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub vector_suite: String,
    pub min_receipt_shards: u16,
    pub min_scan_hint_privacy_set_size: u64,
    pub max_metadata_leakage_units: u16,
    pub min_pq_security_bits: u16,
    pub low_fee_cap_atomic: u64,
    pub force_exit_window_blocks: u64,
    pub redact_private_metadata_by_default: bool,
    pub require_emergency_low_fee_path: bool,
    pub max_vectors: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            vector_suite: VECTOR_SUITE.to_string(),
            min_receipt_shards: DEFAULT_MIN_RECEIPT_SHARDS,
            min_scan_hint_privacy_set_size: DEFAULT_MIN_SCAN_HINT_PRIVACY_SET_SIZE,
            max_metadata_leakage_units: DEFAULT_MAX_METADATA_LEAKAGE_UNITS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_cap_atomic: DEFAULT_LOW_FEE_CAP_ATOMIC,
            force_exit_window_blocks: DEFAULT_FORCE_EXIT_WINDOW_BLOCKS,
            redact_private_metadata_by_default: true,
            require_emergency_low_fee_path: true,
            max_vectors: DEFAULT_MAX_VECTORS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "vector_suite": self.vector_suite,
            "min_receipt_shards": self.min_receipt_shards,
            "min_scan_hint_privacy_set_size": self.min_scan_hint_privacy_set_size,
            "max_metadata_leakage_units": self.max_metadata_leakage_units,
            "min_pq_security_bits": self.min_pq_security_bits,
            "low_fee_cap_atomic": self.low_fee_cap_atomic,
            "force_exit_window_blocks": self.force_exit_window_blocks,
            "redact_private_metadata_by_default": self.redact_private_metadata_by_default,
            "require_emergency_low_fee_path": self.require_emergency_low_fee_path,
            "max_vectors": self.max_vectors,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedReceipt {
    pub receipt_id: String,
    pub cipher_suite: ReceiptCipherSuite,
    pub ciphertext_root: String,
    pub decryptor_commitment_root: String,
    pub receipt_guard_root: String,
    pub shard_count: u16,
    pub threshold: u16,
    pub receipt_root: String,
}

impl EncryptedReceipt {
    pub fn new(
        config: &Config,
        cipher_suite: ReceiptCipherSuite,
        ciphertext_root: impl Into<String>,
        decryptor_commitment_root: impl Into<String>,
        receipt_guard_root: impl Into<String>,
        shard_count: u16,
    ) -> Self {
        let ciphertext_root = ciphertext_root.into();
        let decryptor_commitment_root = decryptor_commitment_root.into();
        let receipt_guard_root = receipt_guard_root.into();
        let threshold = config.min_receipt_shards.min(shard_count);
        let receipt_root = encrypted_receipt_root(
            cipher_suite,
            &ciphertext_root,
            &decryptor_commitment_root,
            &receipt_guard_root,
            shard_count,
            threshold,
        );
        Self {
            receipt_id: stable_id("encrypted_receipt", &receipt_root),
            cipher_suite,
            ciphertext_root,
            decryptor_commitment_root,
            receipt_guard_root,
            shard_count,
            threshold,
            receipt_root,
        }
    }

    pub fn recoverable(&self) -> bool {
        self.threshold > 0 && self.shard_count >= self.threshold
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "cipher_suite": self.cipher_suite.as_str(),
            "ciphertext_root": self.ciphertext_root,
            "decryptor_commitment_root": self.decryptor_commitment_root,
            "receipt_guard_root": self.receipt_guard_root,
            "shard_count": self.shard_count,
            "threshold": self.threshold,
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanHint {
    pub hint_id: String,
    pub kind: ScanHintKind,
    pub hint_commitment_root: String,
    pub scan_window_start: u64,
    pub scan_window_end: u64,
    pub privacy_set_size: u64,
    pub metadata_leakage_units: u16,
    pub hint_root: String,
}

impl ScanHint {
    pub fn new(
        kind: ScanHintKind,
        hint_commitment_root: impl Into<String>,
        scan_window_start: u64,
        scan_window_end: u64,
        privacy_set_size: u64,
        metadata_leakage_units: u16,
    ) -> Self {
        let hint_commitment_root = hint_commitment_root.into();
        let hint_root = scan_hint_root(
            kind,
            &hint_commitment_root,
            scan_window_start,
            scan_window_end,
            privacy_set_size,
            metadata_leakage_units,
        );
        Self {
            hint_id: stable_id("scan_hint", &hint_root),
            kind,
            hint_commitment_root,
            scan_window_start,
            scan_window_end,
            privacy_set_size,
            metadata_leakage_units,
            hint_root,
        }
    }

    pub fn satisfies_privacy(&self, config: &Config) -> bool {
        self.privacy_set_size >= config.min_scan_hint_privacy_set_size
            && self.metadata_leakage_units <= config.max_metadata_leakage_units
            && self.scan_window_start < self.scan_window_end
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "kind": self.kind.as_str(),
            "hint_commitment_root": self.hint_commitment_root,
            "scan_window_start": self.scan_window_start,
            "scan_window_end": self.scan_window_end,
            "privacy_set_size": self.privacy_set_size,
            "metadata_leakage_units": self.metadata_leakage_units,
            "hint_root": self.hint_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NoteNullifierCommitments {
    pub commitment_id: String,
    pub note_commitment_root: String,
    pub note_path_root: String,
    pub nullifier_root: String,
    pub key_image_root: String,
    pub replay_domain: String,
    pub spent_epoch: u64,
    pub commitment_root: String,
}

impl NoteNullifierCommitments {
    pub fn new(seed: &str, spent_epoch: u64) -> Self {
        let note_commitment_root = fixture_root("note_commitment", seed);
        let note_path_root = fixture_root("note_path", seed);
        let nullifier_root = fixture_root("nullifier", seed);
        let key_image_root = fixture_root("key_image", seed);
        let replay_domain = format!("{CHAIN_ID}:forced-exit:{spent_epoch}");
        let commitment_root = note_nullifier_root(
            &note_commitment_root,
            &note_path_root,
            &nullifier_root,
            &key_image_root,
            &replay_domain,
            spent_epoch,
        );
        Self {
            commitment_id: stable_id("note_nullifier_commitments", &commitment_root),
            note_commitment_root,
            note_path_root,
            nullifier_root,
            key_image_root,
            replay_domain,
            spent_epoch,
            commitment_root,
        }
    }

    pub fn complete(&self) -> bool {
        !self.note_commitment_root.is_empty()
            && !self.note_path_root.is_empty()
            && !self.nullifier_root.is_empty()
            && !self.key_image_root.is_empty()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "note_commitment_root": self.note_commitment_root,
            "note_path_root": self.note_path_root,
            "nullifier_root": self.nullifier_root,
            "key_image_root": self.key_image_root,
            "replay_domain": self.replay_domain,
            "spent_epoch": self.spent_epoch,
            "commitment_root": self.commitment_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqWithdrawalAuthorization {
    pub authorization_id: String,
    pub scheme: String,
    pub wallet_authority_root: String,
    pub destination_commitment_root: String,
    pub amount_commitment_root: String,
    pub signature_transcript_root: String,
    pub security_bits: u16,
    pub expires_at_height: u64,
    pub authorization_root: String,
}

impl PqWithdrawalAuthorization {
    pub fn new(seed: &str, security_bits: u16, expires_at_height: u64) -> Self {
        let scheme = "ml_dsa_87_with_slh_dsa_backstop".to_string();
        let wallet_authority_root = fixture_root("wallet_authority", seed);
        let destination_commitment_root = fixture_root("destination_commitment", seed);
        let amount_commitment_root = fixture_root("amount_commitment", seed);
        let signature_transcript_root = fixture_root("pq_signature_transcript", seed);
        let authorization_root = pq_authorization_root(
            &scheme,
            &wallet_authority_root,
            &destination_commitment_root,
            &amount_commitment_root,
            &signature_transcript_root,
            security_bits,
            expires_at_height,
        );
        Self {
            authorization_id: stable_id("pq_withdrawal_authorization", &authorization_root),
            scheme,
            wallet_authority_root,
            destination_commitment_root,
            amount_commitment_root,
            signature_transcript_root,
            security_bits,
            expires_at_height,
            authorization_root,
        }
    }

    pub fn satisfies_security(&self, config: &Config) -> bool {
        self.security_bits >= config.min_pq_security_bits
    }

    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "scheme": self.scheme,
            "wallet_authority_root": self.wallet_authority_root,
            "destination_commitment_root": self.destination_commitment_root,
            "amount_commitment_root": self.amount_commitment_root,
            "signature_transcript_root": self.signature_transcript_root,
            "security_bits": self.security_bits,
            "expires_at_height": self.expires_at_height,
            "authorization_root": self.authorization_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateMetadataRedaction {
    pub policy_id: String,
    pub public_fields: Vec<String>,
    pub challenge_fields: Vec<String>,
    pub redacted_fields: Vec<MetadataField>,
    pub leakage_budget_units: u16,
    pub policy_root: String,
}

impl PrivateMetadataRedaction {
    pub fn devnet(config: &Config) -> Self {
        let public_fields = vec![
            "vector_id".to_string(),
            "receipt_root".to_string(),
            "note_commitment_root".to_string(),
            "nullifier_root".to_string(),
            "claim_builder_root".to_string(),
        ];
        let challenge_fields = vec![
            "scan_window_commitment".to_string(),
            "decryptor_commitment_root".to_string(),
            "receipt_guard_root".to_string(),
        ];
        let redacted_fields = vec![
            MetadataField::Amount,
            MetadataField::Destination,
            MetadataField::Subaddress,
            MetadataField::Timing,
            MetadataField::WalletLabel,
        ];
        let leakage_budget_units = config.max_metadata_leakage_units;
        let policy_root = redaction_policy_root(
            &public_fields,
            &challenge_fields,
            &redacted_fields,
            leakage_budget_units,
        );
        Self {
            policy_id: stable_id("private_metadata_redaction", &policy_root),
            public_fields,
            challenge_fields,
            redacted_fields,
            leakage_budget_units,
            policy_root,
        }
    }

    pub fn complete(&self) -> bool {
        !self.public_fields.is_empty() && !self.redacted_fields.is_empty()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "public_fields": self.public_fields,
            "challenge_fields": self.challenge_fields,
            "redacted_fields": self.redacted_fields.iter().map(|field| field.as_str()).collect::<Vec<_>>(),
            "leakage_budget_units": self.leakage_budget_units,
            "policy_root": self.policy_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EmergencyLowFeePath {
    pub path_id: String,
    pub sponsor_commitment_root: String,
    pub relay_policy_root: String,
    pub max_fee_atomic: u64,
    pub fee_receipt_root: String,
    pub fallback_batch_root: String,
    pub path_root: String,
}

impl EmergencyLowFeePath {
    pub fn new(seed: &str, max_fee_atomic: u64) -> Self {
        let sponsor_commitment_root = fixture_root("fee_sponsor", seed);
        let relay_policy_root = fixture_root("relay_policy", seed);
        let fee_receipt_root = fixture_root("fee_receipt", seed);
        let fallback_batch_root = fixture_root("fallback_batch", seed);
        let path_root = low_fee_path_root(
            &sponsor_commitment_root,
            &relay_policy_root,
            max_fee_atomic,
            &fee_receipt_root,
            &fallback_batch_root,
        );
        Self {
            path_id: stable_id("emergency_low_fee_path", &path_root),
            sponsor_commitment_root,
            relay_policy_root,
            max_fee_atomic,
            fee_receipt_root,
            fallback_batch_root,
            path_root,
        }
    }

    pub fn satisfies_fee_cap(&self, config: &Config) -> bool {
        self.max_fee_atomic <= config.low_fee_cap_atomic && !self.fee_receipt_root.is_empty()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "path_id": self.path_id,
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "relay_policy_root": self.relay_policy_root,
            "max_fee_atomic": self.max_fee_atomic,
            "fee_receipt_root": self.fee_receipt_root,
            "fallback_batch_root": self.fallback_batch_root,
            "path_root": self.path_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserLocalEvidence {
    pub evidence_id: String,
    pub retention: EvidenceRetention,
    pub wallet_backup_root: String,
    pub local_receipt_db_root: String,
    pub signer_transcript_root: String,
    pub recovery_hint_root: String,
    pub evidence_root: String,
}

impl UserLocalEvidence {
    pub fn new(seed: &str) -> Self {
        let retention = EvidenceRetention::WalletEncrypted;
        let wallet_backup_root = fixture_root("wallet_backup", seed);
        let local_receipt_db_root = fixture_root("local_receipt_db", seed);
        let signer_transcript_root = fixture_root("signer_transcript", seed);
        let recovery_hint_root = fixture_root("recovery_hint", seed);
        let evidence_root = user_local_evidence_root(
            retention,
            &wallet_backup_root,
            &local_receipt_db_root,
            &signer_transcript_root,
            &recovery_hint_root,
        );
        Self {
            evidence_id: stable_id("user_local_evidence", &evidence_root),
            retention,
            wallet_backup_root,
            local_receipt_db_root,
            signer_transcript_root,
            recovery_hint_root,
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "retention": self.retention.as_str(),
            "wallet_backup_root": self.wallet_backup_root,
            "local_receipt_db_root": self.local_receipt_db_root,
            "signer_transcript_root": self.signer_transcript_root,
            "recovery_hint_root": self.recovery_hint_root,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExitClaimBuilderInputs {
    pub builder_id: String,
    pub release_claim_id: String,
    pub vector_id: String,
    pub receipt_root: String,
    pub scan_hint_root: String,
    pub note_nullifier_root: String,
    pub pq_authorization_root: String,
    pub redaction_policy_root: String,
    pub low_fee_path_root: String,
    pub user_local_evidence_root: String,
    pub force_exit_window_end: u64,
    pub builder_root: String,
}

impl ExitClaimBuilderInputs {
    pub fn public_record(&self) -> Value {
        json!({
            "builder_id": self.builder_id,
            "release_claim_id": self.release_claim_id,
            "vector_id": self.vector_id,
            "receipt_root": self.receipt_root,
            "scan_hint_root": self.scan_hint_root,
            "note_nullifier_root": self.note_nullifier_root,
            "pq_authorization_root": self.pq_authorization_root,
            "redaction_policy_root": self.redaction_policy_root,
            "low_fee_path_root": self.low_fee_path_root,
            "user_local_evidence_root": self.user_local_evidence_root,
            "force_exit_window_end": self.force_exit_window_end,
            "builder_root": self.builder_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletReconstructionVector {
    pub vector_id: String,
    pub status: ReconstructionStatus,
    pub wallet_label: String,
    pub release_claim_id: String,
    pub encrypted_receipt: EncryptedReceipt,
    pub scan_hints: Vec<ScanHint>,
    pub note_nullifier: NoteNullifierCommitments,
    pub pq_authorization: PqWithdrawalAuthorization,
    pub redaction: PrivateMetadataRedaction,
    pub low_fee_path: EmergencyLowFeePath,
    pub user_local_evidence: UserLocalEvidence,
    pub claim_builder_inputs: ExitClaimBuilderInputs,
    pub blockers: Vec<ReconstructionBlocker>,
    pub vector_root: String,
}

impl WalletReconstructionVector {
    pub fn devnet(config: &Config, seed: &str, ordinal: u64) -> Self {
        let encrypted_receipt = EncryptedReceipt::new(
            config,
            ReceiptCipherSuite::MlKem1024Aead,
            fixture_root("receipt_ciphertext", seed),
            fixture_root("receipt_decryptor", seed),
            fixture_root("receipt_guard", seed),
            config.min_receipt_shards + 1,
        );
        let scan_hints = vec![
            ScanHint::new(
                ScanHintKind::ViewTag,
                fixture_root("view_tag_hint", seed),
                50_000 + ordinal * 100,
                50_000 + ordinal * 100 + 96,
                config.min_scan_hint_privacy_set_size + ordinal,
                1,
            ),
            ScanHint::new(
                ScanHintKind::ReceiptLocator,
                fixture_root("receipt_locator_hint", seed),
                50_012 + ordinal * 100,
                50_108 + ordinal * 100,
                config.min_scan_hint_privacy_set_size + 32 + ordinal,
                1,
            ),
        ];
        let note_nullifier = NoteNullifierCommitments::new(seed, 40 + ordinal);
        let pq_authorization =
            PqWithdrawalAuthorization::new(seed, config.min_pq_security_bits, 52_000 + ordinal);
        let redaction = PrivateMetadataRedaction::devnet(config);
        let low_fee_path = EmergencyLowFeePath::new(seed, config.low_fee_cap_atomic);
        let user_local_evidence = UserLocalEvidence::new(seed);
        let release_claim_id = format!("canonical-wallet-reconstruction-release-claim-{seed}");
        let vector_seed_root = fixture_root("vector_seed", seed);
        let vector_id = stable_id("wallet_reconstruction_vector", &vector_seed_root);
        let scan_hint_root = scan_hints_root(&scan_hints);
        let force_exit_window_end = 50_000 + ordinal * 100 + config.force_exit_window_blocks;
        let claim_builder_inputs = claim_builder_inputs(
            &release_claim_id,
            &vector_id,
            &encrypted_receipt,
            &scan_hint_root,
            &note_nullifier,
            &pq_authorization,
            &redaction,
            &low_fee_path,
            &user_local_evidence,
            force_exit_window_end,
        );
        let blockers = vector_blockers(
            config,
            &encrypted_receipt,
            &scan_hints,
            &note_nullifier,
            &pq_authorization,
            &redaction,
            &low_fee_path,
            &claim_builder_inputs,
        );
        let status = vector_status(&blockers);
        let vector_root = wallet_vector_root(
            status,
            &vector_id,
            &release_claim_id,
            &encrypted_receipt.receipt_root,
            &scan_hint_root,
            &note_nullifier.commitment_root,
            &pq_authorization.authorization_root,
            &redaction.policy_root,
            &low_fee_path.path_root,
            &user_local_evidence.evidence_root,
            &claim_builder_inputs.builder_root,
            &blockers,
        );
        Self {
            vector_id,
            status,
            wallet_label: format!("devnet-wallet-{seed}"),
            release_claim_id,
            encrypted_receipt,
            scan_hints,
            note_nullifier,
            pq_authorization,
            redaction,
            low_fee_path,
            user_local_evidence,
            claim_builder_inputs,
            blockers,
            vector_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vector_id": self.vector_id,
            "status": self.status.as_str(),
            "wallet_label_commitment": fixture_root("wallet_label_commitment", &self.wallet_label),
            "release_claim_id": self.release_claim_id,
            "encrypted_receipt": self.encrypted_receipt.public_record(),
            "scan_hints": self.scan_hints.iter().map(ScanHint::public_record).collect::<Vec<_>>(),
            "note_nullifier": self.note_nullifier.public_record(),
            "pq_authorization": self.pq_authorization.public_record(),
            "redaction": self.redaction.public_record(),
            "low_fee_path": self.low_fee_path.public_record(),
            "user_local_evidence": self.user_local_evidence.public_record(),
            "claim_builder_inputs": self.claim_builder_inputs.public_record(),
            "blockers": self.blockers.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
            "vector_root": self.vector_root,
        })
    }

    pub fn redacted_public_record(&self) -> Value {
        json!({
            "vector_id": self.vector_id,
            "status": self.status.as_str(),
            "release_claim_id": self.release_claim_id,
            "receipt_root": self.encrypted_receipt.receipt_root,
            "scan_hint_root": scan_hints_root(&self.scan_hints),
            "note_commitment_root": self.note_nullifier.note_commitment_root,
            "nullifier_root": self.note_nullifier.nullifier_root,
            "pq_authorization_root": self.pq_authorization.authorization_root,
            "redaction_policy_root": self.redaction.policy_root,
            "low_fee_path_root": self.low_fee_path.path_root,
            "claim_builder_root": self.claim_builder_inputs.builder_root,
            "vector_root": self.vector_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub vectors_total: u64,
    pub canonical: u64,
    pub reconstructable: u64,
    pub watch_only: u64,
    pub blocked: u64,
    pub claim_buildable: u64,
}

impl Counters {
    pub fn from_vectors(vectors: &[WalletReconstructionVector]) -> Self {
        let mut counters = Self::default();
        counters.vectors_total = vectors.len() as u64;
        for vector in vectors {
            match vector.status {
                ReconstructionStatus::Canonical => counters.canonical += 1,
                ReconstructionStatus::Reconstructable => counters.reconstructable += 1,
                ReconstructionStatus::WatchOnly => counters.watch_only += 1,
                ReconstructionStatus::Blocked => counters.blocked += 1,
            }
            if vector.status.can_build_claim() {
                counters.claim_buildable += 1;
            }
        }
        counters
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vectors_total": self.vectors_total,
            "canonical": self.canonical,
            "reconstructable": self.reconstructable,
            "watch_only": self.watch_only,
            "blocked": self.blocked,
            "claim_buildable": self.claim_buildable,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub vectors: Vec<WalletReconstructionVector>,
    pub counters: Counters,
    pub config_root: String,
    pub vector_root: String,
    pub public_record_root: String,
    pub devnet_data_root: String,
}

impl State {
    pub fn new(config: Config, vectors: Vec<WalletReconstructionVector>) -> Result<Self> {
        ensure(
            vectors.len() <= config.max_vectors,
            "wallet vector capacity exceeded",
        )?;
        let counters = Counters::from_vectors(&vectors);
        let config_root = config.state_root();
        let vector_root = vectors_root(&vectors);
        let devnet_data_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-RECONSTRUCTION-DEVNET-DATA",
            &vectors
                .iter()
                .map(WalletReconstructionVector::public_record)
                .collect::<Vec<_>>(),
        );
        let public_record_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-RECONSTRUCTION-PUBLIC-RECORD",
            &[
                json!({"config_root": config_root}),
                json!({"vector_root": vector_root}),
                json!({"counters": counters.public_record()}),
                json!({"devnet_data_root": devnet_data_root}),
            ],
        );
        Ok(Self {
            config,
            vectors,
            counters,
            config_root,
            vector_root,
            public_record_root,
            devnet_data_root,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let vectors = vec![
            WalletReconstructionVector::devnet(&config, "alpha", 0),
            WalletReconstructionVector::devnet(&config, "beta", 1),
            WalletReconstructionVector::devnet(&config, "gamma", 2),
        ];
        match Self::new(config, vectors) {
            Ok(state) => state,
            Err(_) => Self {
                config: Config::devnet(),
                vectors: Vec::new(),
                counters: Counters::default(),
                config_root: String::new(),
                vector_root: String::new(),
                public_record_root: String::new(),
                devnet_data_root: String::new(),
            },
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "vectors": self.vectors.iter().map(WalletReconstructionVector::redacted_public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "roots": {
                "config_root": self.config_root,
                "vector_root": self.vector_root,
                "public_record_root": self.public_record_root,
                "devnet_data_root": self.devnet_data_root,
                "state_root": self.state_root(),
            }
        })
    }

    pub fn devnet_data(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "vectors": self.vectors.iter().map(WalletReconstructionVector::public_record).collect::<Vec<_>>(),
            "devnet_data_root": self.devnet_data_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-RECONSTRUCTION-STATE",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.vector_root),
                HashPart::Str(&self.public_record_root),
                HashPart::Str(&self.devnet_data_root),
            ],
            32,
        )
    }

    pub fn claim_builder_inputs(&self, vector_id: &str) -> Result<ExitClaimBuilderInputs> {
        self.vectors
            .iter()
            .find(|vector| vector.vector_id == vector_id)
            .filter(|vector| vector.status.can_build_claim())
            .map(|vector| vector.claim_builder_inputs.clone())
            .ok_or_else(|| format!("claim builder inputs unavailable for vector {vector_id}"))
    }

    pub fn blocker_summary(&self) -> BTreeMap<String, u64> {
        blocker_summary(&self.vectors)
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

pub fn devnet_data() -> Value {
    devnet().devnet_data()
}

pub fn blocker_summary(vectors: &[WalletReconstructionVector]) -> BTreeMap<String, u64> {
    let mut summary = BTreeMap::new();
    for vector in vectors {
        for blocker in &vector.blockers {
            *summary.entry(blocker.as_str().to_string()).or_insert(0) += 1;
        }
    }
    summary
}

pub fn required_reconstruction_components() -> Vec<&'static str> {
    vec![
        "encrypted_receipts",
        "scan_hints",
        "note_commitments",
        "nullifier_commitments",
        "pq_withdrawal_authorization",
        "exit_claim_builder_inputs",
        "private_metadata_redaction",
        "emergency_low_fee_path",
        "user_local_evidence",
    ]
}

fn claim_builder_inputs(
    release_claim_id: &str,
    vector_id: &str,
    encrypted_receipt: &EncryptedReceipt,
    scan_hint_root: &str,
    note_nullifier: &NoteNullifierCommitments,
    pq_authorization: &PqWithdrawalAuthorization,
    redaction: &PrivateMetadataRedaction,
    low_fee_path: &EmergencyLowFeePath,
    user_local_evidence: &UserLocalEvidence,
    force_exit_window_end: u64,
) -> ExitClaimBuilderInputs {
    let builder_root = exit_claim_builder_root(
        release_claim_id,
        vector_id,
        &encrypted_receipt.receipt_root,
        scan_hint_root,
        &note_nullifier.commitment_root,
        &pq_authorization.authorization_root,
        &redaction.policy_root,
        &low_fee_path.path_root,
        &user_local_evidence.evidence_root,
        force_exit_window_end,
    );
    ExitClaimBuilderInputs {
        builder_id: stable_id("exit_claim_builder_inputs", &builder_root),
        release_claim_id: release_claim_id.to_string(),
        vector_id: vector_id.to_string(),
        receipt_root: encrypted_receipt.receipt_root.clone(),
        scan_hint_root: scan_hint_root.to_string(),
        note_nullifier_root: note_nullifier.commitment_root.clone(),
        pq_authorization_root: pq_authorization.authorization_root.clone(),
        redaction_policy_root: redaction.policy_root.clone(),
        low_fee_path_root: low_fee_path.path_root.clone(),
        user_local_evidence_root: user_local_evidence.evidence_root.clone(),
        force_exit_window_end,
        builder_root,
    }
}

fn vector_blockers(
    config: &Config,
    receipt: &EncryptedReceipt,
    scan_hints: &[ScanHint],
    note_nullifier: &NoteNullifierCommitments,
    pq_authorization: &PqWithdrawalAuthorization,
    redaction: &PrivateMetadataRedaction,
    low_fee_path: &EmergencyLowFeePath,
    claim_builder: &ExitClaimBuilderInputs,
) -> Vec<ReconstructionBlocker> {
    let mut blockers = Vec::new();
    if !receipt.recoverable() {
        blockers.push(ReconstructionBlocker::ReceiptRecoveryBelowThreshold);
    }
    if scan_hints.is_empty()
        || scan_hints
            .iter()
            .any(|hint| !hint.satisfies_privacy(config))
    {
        blockers.push(ReconstructionBlocker::ScanHintPrivacyBelowFloor);
    }
    if note_nullifier.note_commitment_root.is_empty() {
        blockers.push(ReconstructionBlocker::NoteCommitmentMissing);
    }
    if note_nullifier.nullifier_root.is_empty() || !note_nullifier.complete() {
        blockers.push(ReconstructionBlocker::NullifierCommitmentMissing);
    }
    if !pq_authorization.satisfies_security(config) {
        blockers.push(ReconstructionBlocker::PqAuthorizationWeak);
    }
    if !redaction.complete() {
        blockers.push(ReconstructionBlocker::RedactionPolicyIncomplete);
    }
    if config.require_emergency_low_fee_path && !low_fee_path.satisfies_fee_cap(config) {
        blockers.push(ReconstructionBlocker::LowFeePathUnavailable);
    }
    if claim_builder.builder_root.is_empty() || claim_builder.release_claim_id.is_empty() {
        blockers.push(ReconstructionBlocker::ExitClaimInputsIncomplete);
    }
    blockers
}

fn vector_status(blockers: &[ReconstructionBlocker]) -> ReconstructionStatus {
    if blockers.is_empty() {
        ReconstructionStatus::Canonical
    } else if blockers.len() == 1 && blockers[0] == ReconstructionBlocker::LowFeePathUnavailable {
        ReconstructionStatus::Reconstructable
    } else if blockers.len() <= 2 {
        ReconstructionStatus::WatchOnly
    } else {
        ReconstructionStatus::Blocked
    }
}

fn encrypted_receipt_root(
    cipher_suite: ReceiptCipherSuite,
    ciphertext_root: &str,
    decryptor_commitment_root: &str,
    receipt_guard_root: &str,
    shard_count: u16,
    threshold: u16,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-RECONSTRUCTION-ENCRYPTED-RECEIPT",
        &[
            HashPart::Str(cipher_suite.as_str()),
            HashPart::Str(ciphertext_root),
            HashPart::Str(decryptor_commitment_root),
            HashPart::Str(receipt_guard_root),
            HashPart::U64(shard_count as u64),
            HashPart::U64(threshold as u64),
        ],
        32,
    )
}

fn scan_hint_root(
    kind: ScanHintKind,
    hint_commitment_root: &str,
    scan_window_start: u64,
    scan_window_end: u64,
    privacy_set_size: u64,
    metadata_leakage_units: u16,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-RECONSTRUCTION-SCAN-HINT",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(hint_commitment_root),
            HashPart::U64(scan_window_start),
            HashPart::U64(scan_window_end),
            HashPart::U64(privacy_set_size),
            HashPart::U64(metadata_leakage_units as u64),
        ],
        32,
    )
}

fn scan_hints_root(scan_hints: &[ScanHint]) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-RECONSTRUCTION-SCAN-HINTS",
        &scan_hints
            .iter()
            .map(ScanHint::public_record)
            .collect::<Vec<_>>(),
    )
}

fn note_nullifier_root(
    note_commitment_root: &str,
    note_path_root: &str,
    nullifier_root: &str,
    key_image_root: &str,
    replay_domain: &str,
    spent_epoch: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-RECONSTRUCTION-NOTE-NULLIFIER",
        &[
            HashPart::Str(note_commitment_root),
            HashPart::Str(note_path_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(key_image_root),
            HashPart::Str(replay_domain),
            HashPart::U64(spent_epoch),
        ],
        32,
    )
}

fn pq_authorization_root(
    scheme: &str,
    wallet_authority_root: &str,
    destination_commitment_root: &str,
    amount_commitment_root: &str,
    signature_transcript_root: &str,
    security_bits: u16,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-RECONSTRUCTION-PQ-AUTHORIZATION",
        &[
            HashPart::Str(scheme),
            HashPart::Str(wallet_authority_root),
            HashPart::Str(destination_commitment_root),
            HashPart::Str(amount_commitment_root),
            HashPart::Str(signature_transcript_root),
            HashPart::U64(security_bits as u64),
            HashPart::U64(expires_at_height),
        ],
        32,
    )
}

fn redaction_policy_root(
    public_fields: &[String],
    challenge_fields: &[String],
    redacted_fields: &[MetadataField],
    leakage_budget_units: u16,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-RECONSTRUCTION-REDACTION",
        &[
            HashPart::Json(&json!(public_fields)),
            HashPart::Json(&json!(challenge_fields)),
            HashPart::Json(&json!(redacted_fields
                .iter()
                .map(|field| field.as_str())
                .collect::<Vec<_>>())),
            HashPart::U64(leakage_budget_units as u64),
        ],
        32,
    )
}

fn low_fee_path_root(
    sponsor_commitment_root: &str,
    relay_policy_root: &str,
    max_fee_atomic: u64,
    fee_receipt_root: &str,
    fallback_batch_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-RECONSTRUCTION-LOW-FEE-PATH",
        &[
            HashPart::Str(sponsor_commitment_root),
            HashPart::Str(relay_policy_root),
            HashPart::U64(max_fee_atomic),
            HashPart::Str(fee_receipt_root),
            HashPart::Str(fallback_batch_root),
        ],
        32,
    )
}

fn user_local_evidence_root(
    retention: EvidenceRetention,
    wallet_backup_root: &str,
    local_receipt_db_root: &str,
    signer_transcript_root: &str,
    recovery_hint_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-RECONSTRUCTION-USER-LOCAL-EVIDENCE",
        &[
            HashPart::Str(retention.as_str()),
            HashPart::Str(wallet_backup_root),
            HashPart::Str(local_receipt_db_root),
            HashPart::Str(signer_transcript_root),
            HashPart::Str(recovery_hint_root),
        ],
        32,
    )
}

fn exit_claim_builder_root(
    release_claim_id: &str,
    vector_id: &str,
    receipt_root: &str,
    scan_hint_root: &str,
    note_nullifier_root: &str,
    pq_authorization_root: &str,
    redaction_policy_root: &str,
    low_fee_path_root: &str,
    user_local_evidence_root: &str,
    force_exit_window_end: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-RECONSTRUCTION-CLAIM-BUILDER",
        &[
            HashPart::Str(release_claim_id),
            HashPart::Str(vector_id),
            HashPart::Str(receipt_root),
            HashPart::Str(scan_hint_root),
            HashPart::Str(note_nullifier_root),
            HashPart::Str(pq_authorization_root),
            HashPart::Str(redaction_policy_root),
            HashPart::Str(low_fee_path_root),
            HashPart::Str(user_local_evidence_root),
            HashPart::U64(force_exit_window_end),
        ],
        32,
    )
}

fn wallet_vector_root(
    status: ReconstructionStatus,
    vector_id: &str,
    release_claim_id: &str,
    receipt_root: &str,
    scan_hint_root: &str,
    note_nullifier_root: &str,
    pq_authorization_root: &str,
    redaction_policy_root: &str,
    low_fee_path_root: &str,
    user_local_evidence_root: &str,
    claim_builder_root: &str,
    blockers: &[ReconstructionBlocker],
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-RECONSTRUCTION-VECTOR",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(vector_id),
            HashPart::Str(release_claim_id),
            HashPart::Str(receipt_root),
            HashPart::Str(scan_hint_root),
            HashPart::Str(note_nullifier_root),
            HashPart::Str(pq_authorization_root),
            HashPart::Str(redaction_policy_root),
            HashPart::Str(low_fee_path_root),
            HashPart::Str(user_local_evidence_root),
            HashPart::Str(claim_builder_root),
            HashPart::Json(&json!(blockers
                .iter()
                .map(|blocker| blocker.as_str())
                .collect::<Vec<_>>())),
        ],
        32,
    )
}

fn vectors_root(vectors: &[WalletReconstructionVector]) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-RECONSTRUCTION-VECTORS",
        &vectors
            .iter()
            .map(WalletReconstructionVector::redacted_public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-RECONSTRUCTION-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

pub fn fixture_root(kind: &str, seed: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-RECONSTRUCTION-DEVNET-FIXTURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(seed),
        ],
        32,
    )
}

pub fn stable_id(kind: &str, root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-WALLET-RECONSTRUCTION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(root),
        ],
        16,
    )
}

pub fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
