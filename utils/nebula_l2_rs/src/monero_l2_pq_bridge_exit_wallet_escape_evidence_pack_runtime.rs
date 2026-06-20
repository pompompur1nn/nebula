use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitWalletEscapeEvidencePackRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_WALLET_ESCAPE_EVIDENCE_PACK_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-wallet-escape-evidence-pack-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_WALLET_ESCAPE_EVIDENCE_PACK_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const EVIDENCE_PACK_SUITE: &str = "wallet-local-escape-evidence-packs-for-forced-exit-v1";
pub const RECEIPT_RECOVERY_SUITE: &str = "encrypted-private-receipt-recovery-for-bridge-exit-v1";
pub const CLAIM_BUILDER_SUITE: &str = "wallet-force-exit-claim-builder-input-binding-v1";
pub const REDACTION_SUITE: &str = "wallet-escape-evidence-pack-public-redaction-policy-v1";
pub const DEFAULT_MIN_RECEIPT_SHARDS: u16 = 2;
pub const DEFAULT_MIN_SCAN_HINT_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MAX_SCAN_HINTS_PER_PACK: u16 = 4;
pub const DEFAULT_MAX_METADATA_LEAKAGE_UNITS: u16 = 2;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_FORCE_EXIT_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_LOW_FEE_CAP_ATOMIC: u64 = 35_000_000;
pub const DEFAULT_MAX_PACKS: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidencePackStatus {
    ForceExitReady,
    Reconstructable,
    WatchOnly,
    Blocked,
}

impl EvidencePackStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ForceExitReady => "force_exit_ready",
            Self::Reconstructable => "reconstructable",
            Self::WatchOnly => "watch_only",
            Self::Blocked => "blocked",
        }
    }

    pub fn permits_claim(self) -> bool {
        matches!(self, Self::ForceExitReady | Self::Reconstructable)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    WalletSecret,
    WalletEncrypted,
    PublicCommitment,
    ReconstructableFromChain,
    ReconstructableFromSettlementFixture,
}

impl RetentionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletSecret => "wallet_secret",
            Self::WalletEncrypted => "wallet_encrypted",
            Self::PublicCommitment => "public_commitment",
            Self::ReconstructableFromChain => "reconstructable_from_chain",
            Self::ReconstructableFromSettlementFixture => "reconstructable_from_settlement_fixture",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceItemKind {
    SpendAuthoritySeedCommitment,
    ViewAuthoritySeedCommitment,
    EncryptedReceiptCiphertextRoot,
    ReceiptRecoveryShardRoot,
    ScanHintCommitment,
    ScanWindowCommitment,
    NoteCommitmentPath,
    NullifierCommitment,
    KeyImageCommitment,
    PqWithdrawalAuthorization,
    SettlementReceiptFixtureBinding,
    ForcedWithdrawalFixtureBinding,
    LowFeeEmergencyReceipt,
    PrivacyRedactionPolicy,
}

impl EvidenceItemKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SpendAuthoritySeedCommitment => "spend_authority_seed_commitment",
            Self::ViewAuthoritySeedCommitment => "view_authority_seed_commitment",
            Self::EncryptedReceiptCiphertextRoot => "encrypted_receipt_ciphertext_root",
            Self::ReceiptRecoveryShardRoot => "receipt_recovery_shard_root",
            Self::ScanHintCommitment => "scan_hint_commitment",
            Self::ScanWindowCommitment => "scan_window_commitment",
            Self::NoteCommitmentPath => "note_commitment_path",
            Self::NullifierCommitment => "nullifier_commitment",
            Self::KeyImageCommitment => "key_image_commitment",
            Self::PqWithdrawalAuthorization => "pq_withdrawal_authorization",
            Self::SettlementReceiptFixtureBinding => "settlement_receipt_fixture_binding",
            Self::ForcedWithdrawalFixtureBinding => "forced_withdrawal_fixture_binding",
            Self::LowFeeEmergencyReceipt => "low_fee_emergency_receipt",
            Self::PrivacyRedactionPolicy => "privacy_redaction_policy",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionLevel {
    PublicClaim,
    WatcherChallenge,
    CourtRecovery,
    WalletLocalOnly,
}

impl RedactionLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicClaim => "public_claim",
            Self::WatcherChallenge => "watcher_challenge",
            Self::CourtRecovery => "court_recovery",
            Self::WalletLocalOnly => "wallet_local_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionBlockerKind {
    MissingEncryptedReceiptRecovery,
    ScanHintPrivacyFloorMissing,
    NullifierOrKeyImageUnbound,
    PqAuthorizationMissing,
    SettlementFixtureBindingMissing,
    ForcedWithdrawalFixtureBindingMissing,
    RedactionPolicyMissing,
    LowFeeEmergencyPathUnpriced,
    CargoExecutionNotRun,
}

impl ProductionBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingEncryptedReceiptRecovery => "missing_encrypted_receipt_recovery",
            Self::ScanHintPrivacyFloorMissing => "scan_hint_privacy_floor_missing",
            Self::NullifierOrKeyImageUnbound => "nullifier_or_key_image_unbound",
            Self::PqAuthorizationMissing => "pq_authorization_missing",
            Self::SettlementFixtureBindingMissing => "settlement_fixture_binding_missing",
            Self::ForcedWithdrawalFixtureBindingMissing => {
                "forced_withdrawal_fixture_binding_missing"
            }
            Self::RedactionPolicyMissing => "redaction_policy_missing",
            Self::LowFeeEmergencyPathUnpriced => "low_fee_emergency_path_unpriced",
            Self::CargoExecutionNotRun => "cargo_execution_not_run",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub evidence_pack_suite: String,
    pub receipt_recovery_suite: String,
    pub claim_builder_suite: String,
    pub redaction_suite: String,
    pub min_receipt_shards: u16,
    pub min_scan_hint_privacy_set_size: u64,
    pub max_scan_hints_per_pack: u16,
    pub max_metadata_leakage_units: u16,
    pub min_pq_security_bits: u16,
    pub force_exit_window_blocks: u64,
    pub low_fee_cap_atomic: u64,
    pub require_low_fee_emergency_path: bool,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub max_packs: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            evidence_pack_suite: EVIDENCE_PACK_SUITE.to_string(),
            receipt_recovery_suite: RECEIPT_RECOVERY_SUITE.to_string(),
            claim_builder_suite: CLAIM_BUILDER_SUITE.to_string(),
            redaction_suite: REDACTION_SUITE.to_string(),
            min_receipt_shards: DEFAULT_MIN_RECEIPT_SHARDS,
            min_scan_hint_privacy_set_size: DEFAULT_MIN_SCAN_HINT_PRIVACY_SET_SIZE,
            max_scan_hints_per_pack: DEFAULT_MAX_SCAN_HINTS_PER_PACK,
            max_metadata_leakage_units: DEFAULT_MAX_METADATA_LEAKAGE_UNITS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            force_exit_window_blocks: DEFAULT_FORCE_EXIT_WINDOW_BLOCKS,
            low_fee_cap_atomic: DEFAULT_LOW_FEE_CAP_ATOMIC,
            require_low_fee_emergency_path: true,
            cargo_checks_deferred: true,
            production_release_allowed: false,
            max_packs: DEFAULT_MAX_PACKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "evidence_pack_suite": self.evidence_pack_suite,
            "receipt_recovery_suite": self.receipt_recovery_suite,
            "claim_builder_suite": self.claim_builder_suite,
            "redaction_suite": self.redaction_suite,
            "min_receipt_shards": self.min_receipt_shards,
            "min_scan_hint_privacy_set_size": self.min_scan_hint_privacy_set_size,
            "max_scan_hints_per_pack": self.max_scan_hints_per_pack,
            "max_metadata_leakage_units": self.max_metadata_leakage_units,
            "min_pq_security_bits": self.min_pq_security_bits,
            "force_exit_window_blocks": self.force_exit_window_blocks,
            "low_fee_cap_atomic": self.low_fee_cap_atomic,
            "require_low_fee_emergency_path": self.require_low_fee_emergency_path,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_packs": self.max_packs,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletLocalEvidenceItem {
    pub item_id: String,
    pub kind: EvidenceItemKind,
    pub retention_class: RetentionClass,
    pub redaction_level: RedactionLevel,
    pub label: String,
    pub commitment_root: String,
    pub reconstruct_from: Vec<String>,
    pub retained_material: Vec<String>,
    pub public_disclosure: Vec<String>,
    pub item_root: String,
}

impl WalletLocalEvidenceItem {
    pub fn new(
        kind: EvidenceItemKind,
        retention_class: RetentionClass,
        redaction_level: RedactionLevel,
        label: &str,
        commitment_root: &str,
        reconstruct_from: Vec<String>,
        retained_material: Vec<String>,
        public_disclosure: Vec<String>,
    ) -> Self {
        let item_root = evidence_item_root(
            kind,
            retention_class,
            redaction_level,
            label,
            commitment_root,
            &reconstruct_from,
            &retained_material,
            &public_disclosure,
        );
        let item_id = stable_id("wallet-escape-evidence-item", &[HashPart::Str(&item_root)]);
        Self {
            item_id,
            kind,
            retention_class,
            redaction_level,
            label: label.to_string(),
            commitment_root: commitment_root.to_string(),
            reconstruct_from,
            retained_material,
            public_disclosure,
            item_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "item_id": self.item_id,
            "kind": self.kind.as_str(),
            "retention_class": self.retention_class.as_str(),
            "redaction_level": self.redaction_level.as_str(),
            "label": self.label,
            "commitment_root": self.commitment_root,
            "reconstruct_from": self.reconstruct_from,
            "public_disclosure": self.public_disclosure,
            "item_root": self.item_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EncryptedReceiptRecoveryPlan {
    pub plan_id: String,
    pub ciphertext_root: String,
    pub recovery_shard_root: String,
    pub receipt_guard_root: String,
    pub decryptor_commitment_root: String,
    pub shard_count: u16,
    pub threshold: u16,
    pub recovery_window_start: u64,
    pub recovery_window_end: u64,
    pub plan_root: String,
}

impl EncryptedReceiptRecoveryPlan {
    pub fn new(
        config: &Config,
        ciphertext_root: &str,
        recovery_shard_root: &str,
        receipt_guard_root: &str,
        decryptor_commitment_root: &str,
        shard_count: u16,
        recovery_window_start: u64,
        recovery_window_end: u64,
    ) -> Self {
        let threshold = config.min_receipt_shards.min(shard_count);
        let plan_root = receipt_recovery_root(
            ciphertext_root,
            recovery_shard_root,
            receipt_guard_root,
            decryptor_commitment_root,
            shard_count,
            threshold,
            recovery_window_start,
            recovery_window_end,
        );
        let plan_id = stable_id(
            "wallet-escape-receipt-recovery-plan",
            &[HashPart::Str(&plan_root)],
        );
        Self {
            plan_id,
            ciphertext_root: ciphertext_root.to_string(),
            recovery_shard_root: recovery_shard_root.to_string(),
            receipt_guard_root: receipt_guard_root.to_string(),
            decryptor_commitment_root: decryptor_commitment_root.to_string(),
            shard_count,
            threshold,
            recovery_window_start,
            recovery_window_end,
            plan_root,
        }
    }

    pub fn meets_threshold(&self) -> bool {
        self.shard_count >= self.threshold && self.threshold > 0
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScanHintConstraint {
    pub constraint_id: String,
    pub hint_commitment_root: String,
    pub scan_window_root: String,
    pub hint_count: u16,
    pub privacy_set_size: u64,
    pub metadata_leakage_units: u16,
    pub bounded_hint_labels: Vec<String>,
    pub constraint_root: String,
}

impl ScanHintConstraint {
    pub fn new(
        config: &Config,
        hint_commitment_root: &str,
        scan_window_root: &str,
        hint_count: u16,
        privacy_set_size: u64,
        metadata_leakage_units: u16,
        bounded_hint_labels: Vec<String>,
    ) -> Self {
        let constraint_root = scan_hint_constraint_root(
            hint_commitment_root,
            scan_window_root,
            hint_count,
            privacy_set_size,
            metadata_leakage_units,
            &bounded_hint_labels,
        );
        let constraint_id = stable_id(
            "wallet-escape-scan-hint-constraint",
            &[HashPart::Str(&constraint_root)],
        );
        let hint_count = hint_count.min(config.max_scan_hints_per_pack);
        Self {
            constraint_id,
            hint_commitment_root: hint_commitment_root.to_string(),
            scan_window_root: scan_window_root.to_string(),
            hint_count,
            privacy_set_size,
            metadata_leakage_units,
            bounded_hint_labels,
            constraint_root,
        }
    }

    pub fn satisfies_privacy(&self, config: &Config) -> bool {
        self.hint_count <= config.max_scan_hints_per_pack
            && self.privacy_set_size >= config.min_scan_hint_privacy_set_size
            && self.metadata_leakage_units <= config.max_metadata_leakage_units
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NullifierKeyImageCommitment {
    pub commitment_id: String,
    pub nullifier_root: String,
    pub key_image_root: String,
    pub note_commitment_path_root: String,
    pub replay_domain: String,
    pub spent_state_epoch: u64,
    pub commitment_root: String,
}

impl NullifierKeyImageCommitment {
    pub fn new(
        nullifier_root: &str,
        key_image_root: &str,
        note_commitment_path_root: &str,
        replay_domain: &str,
        spent_state_epoch: u64,
    ) -> Self {
        let commitment_root = nullifier_key_image_root(
            nullifier_root,
            key_image_root,
            note_commitment_path_root,
            replay_domain,
            spent_state_epoch,
        );
        let commitment_id = stable_id(
            "wallet-escape-nullifier-key-image",
            &[HashPart::Str(&commitment_root)],
        );
        Self {
            commitment_id,
            nullifier_root: nullifier_root.to_string(),
            key_image_root: key_image_root.to_string(),
            note_commitment_path_root: note_commitment_path_root.to_string(),
            replay_domain: replay_domain.to_string(),
            spent_state_epoch,
            commitment_root,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqWithdrawalAuthorization {
    pub authorization_id: String,
    pub wallet_authority_commitment: String,
    pub recovery_authority_commitment: String,
    pub destination_commitment: String,
    pub amount_commitment: String,
    pub pq_signature_root: String,
    pub security_bits: u16,
    pub expires_at_height: u64,
    pub authorization_root: String,
}

impl PqWithdrawalAuthorization {
    pub fn new(
        wallet_authority_commitment: &str,
        recovery_authority_commitment: &str,
        destination_commitment: &str,
        amount_commitment: &str,
        pq_signature_root: &str,
        security_bits: u16,
        expires_at_height: u64,
    ) -> Self {
        let authorization_root = pq_authorization_root(
            wallet_authority_commitment,
            recovery_authority_commitment,
            destination_commitment,
            amount_commitment,
            pq_signature_root,
            security_bits,
            expires_at_height,
        );
        let authorization_id = stable_id(
            "wallet-escape-pq-withdrawal-authorization",
            &[HashPart::Str(&authorization_root)],
        );
        Self {
            authorization_id,
            wallet_authority_commitment: wallet_authority_commitment.to_string(),
            recovery_authority_commitment: recovery_authority_commitment.to_string(),
            destination_commitment: destination_commitment.to_string(),
            amount_commitment: amount_commitment.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            security_bits,
            expires_at_height,
            authorization_root,
        }
    }

    pub fn satisfies_security(&self, config: &Config) -> bool {
        self.security_bits >= config.min_pq_security_bits
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForceExitClaimBuilderInputs {
    pub claim_id: String,
    pub pack_id: String,
    pub settlement_fixture_root: String,
    pub forced_withdrawal_fixture_root: String,
    pub wallet_evidence_root: String,
    pub receipt_recovery_root: String,
    pub scan_constraint_root: String,
    pub nullifier_key_image_root: String,
    pub pq_authorization_root: String,
    pub low_fee_receipt_root: String,
    pub redaction_policy_root: String,
    pub force_exit_window_end: u64,
    pub builder_root: String,
}

impl ForceExitClaimBuilderInputs {
    pub fn public_record(&self) -> Value {
        json!({
            "claim_id": self.claim_id,
            "pack_id": self.pack_id,
            "settlement_fixture_root": self.settlement_fixture_root,
            "forced_withdrawal_fixture_root": self.forced_withdrawal_fixture_root,
            "wallet_evidence_root": self.wallet_evidence_root,
            "receipt_recovery_root": self.receipt_recovery_root,
            "scan_constraint_root": self.scan_constraint_root,
            "nullifier_key_image_root": self.nullifier_key_image_root,
            "pq_authorization_root": self.pq_authorization_root,
            "low_fee_receipt_root": self.low_fee_receipt_root,
            "redaction_policy_root": self.redaction_policy_root,
            "force_exit_window_end": self.force_exit_window_end,
            "builder_root": self.builder_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyRedactionPolicy {
    pub policy_id: String,
    pub public_fields: Vec<String>,
    pub challenge_fields: Vec<String>,
    pub wallet_secret_fields: Vec<String>,
    pub redact_amounts: bool,
    pub redact_scan_hints: bool,
    pub redact_destination: bool,
    pub policy_root: String,
}

impl PrivacyRedactionPolicy {
    pub fn devnet() -> Self {
        let public_fields = vec![
            "pack_id".to_string(),
            "claim_id".to_string(),
            "evidence_root".to_string(),
            "settlement_fixture_root".to_string(),
            "forced_withdrawal_fixture_root".to_string(),
        ];
        let challenge_fields = vec![
            "receipt_recovery_root".to_string(),
            "scan_constraint_root".to_string(),
            "nullifier_key_image_root".to_string(),
            "pq_authorization_root".to_string(),
        ];
        let wallet_secret_fields = vec![
            "plaintext_receipt".to_string(),
            "view_key_material".to_string(),
            "spend_key_material".to_string(),
            "raw_scan_hint".to_string(),
        ];
        let policy_root = redaction_policy_root(
            &public_fields,
            &challenge_fields,
            &wallet_secret_fields,
            true,
            true,
            true,
        );
        let policy_id = stable_id(
            "wallet-escape-redaction-policy",
            &[HashPart::Str(&policy_root)],
        );
        Self {
            policy_id,
            public_fields,
            challenge_fields,
            wallet_secret_fields,
            redact_amounts: true,
            redact_scan_hints: true,
            redact_destination: true,
            policy_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "public_fields": self.public_fields,
            "challenge_fields": self.challenge_fields,
            "wallet_secret_fields": self.wallet_secret_fields,
            "redact_amounts": self.redact_amounts,
            "redact_scan_hints": self.redact_scan_hints,
            "redact_destination": self.redact_destination,
            "policy_root": self.policy_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeEmergencyPath {
    pub path_id: String,
    pub fee_sponsor_commitment: String,
    pub max_fee_atomic: u64,
    pub fee_receipt_root: String,
    pub relay_policy_root: String,
    pub path_root: String,
}

impl LowFeeEmergencyPath {
    pub fn new(
        fee_sponsor_commitment: &str,
        max_fee_atomic: u64,
        fee_receipt_root: &str,
        relay_policy_root: &str,
    ) -> Self {
        let path_root = low_fee_path_root(
            fee_sponsor_commitment,
            max_fee_atomic,
            fee_receipt_root,
            relay_policy_root,
        );
        let path_id = stable_id("wallet-escape-low-fee-path", &[HashPart::Str(&path_root)]);
        Self {
            path_id,
            fee_sponsor_commitment: fee_sponsor_commitment.to_string(),
            max_fee_atomic,
            fee_receipt_root: fee_receipt_root.to_string(),
            relay_policy_root: relay_policy_root.to_string(),
            path_root,
        }
    }

    pub fn satisfies_fee_cap(&self, config: &Config) -> bool {
        self.max_fee_atomic <= config.low_fee_cap_atomic
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletEscapeEvidencePack {
    pub pack_id: String,
    pub status: EvidencePackStatus,
    pub wallet_label: String,
    pub release_claim_id: String,
    pub transfer_id: String,
    pub settlement_fixture_root: String,
    pub forced_withdrawal_fixture_root: String,
    pub local_items: Vec<WalletLocalEvidenceItem>,
    pub receipt_recovery: EncryptedReceiptRecoveryPlan,
    pub scan_constraint: ScanHintConstraint,
    pub nullifier_key_image: NullifierKeyImageCommitment,
    pub pq_authorization: PqWithdrawalAuthorization,
    pub redaction_policy: PrivacyRedactionPolicy,
    pub low_fee_path: LowFeeEmergencyPath,
    pub production_blockers: Vec<ProductionBlockerKind>,
    pub wallet_evidence_root: String,
    pub claim_builder_inputs: ForceExitClaimBuilderInputs,
    pub pack_root: String,
}

impl WalletEscapeEvidencePack {
    pub fn new(
        config: &Config,
        wallet_label: &str,
        release_claim_id: &str,
        transfer_id: &str,
        settlement_fixture_root: &str,
        forced_withdrawal_fixture_root: &str,
        ordinal: u64,
    ) -> Self {
        let seed = stable_id(
            "wallet-escape-pack-seed",
            &[
                HashPart::Str(wallet_label),
                HashPart::Str(release_claim_id),
                HashPart::Str(transfer_id),
                HashPart::U64(ordinal),
            ],
        );
        let receipt_recovery = EncryptedReceiptRecoveryPlan::new(
            config,
            &fixture_root("ciphertext", &seed),
            &fixture_root("receipt-shards", &seed),
            &fixture_root("receipt-guard", &seed),
            &fixture_root("decryptor", &seed),
            config.min_receipt_shards + 1,
            4_260_128,
            4_260_128 + config.force_exit_window_blocks,
        );
        let scan_constraint = ScanHintConstraint::new(
            config,
            &fixture_root("scan-hints", &seed),
            &fixture_root("scan-window", &seed),
            3,
            config.min_scan_hint_privacy_set_size * 2,
            config.max_metadata_leakage_units,
            vec![
                "view_tag_bucket".to_string(),
                "subaddress_epoch".to_string(),
                "receipt_guard_prefix".to_string(),
            ],
        );
        let nullifier_key_image = NullifierKeyImageCommitment::new(
            &fixture_root("nullifier", &seed),
            &fixture_root("key-image", &seed),
            &fixture_root("note-path", &seed),
            "monero-l2-pq-bridge-exit-force-exit-devnet",
            42,
        );
        let pq_authorization = PqWithdrawalAuthorization::new(
            &fixture_root("wallet-authority", &seed),
            &fixture_root("recovery-authority", &seed),
            &fixture_root("destination", &seed),
            &fixture_root("amount", &seed),
            &fixture_root("pq-signature", &seed),
            config.min_pq_security_bits,
            4_260_128 + config.force_exit_window_blocks,
        );
        let redaction_policy = PrivacyRedactionPolicy::devnet();
        let low_fee_path = LowFeeEmergencyPath::new(
            &fixture_root("fee-sponsor", &seed),
            config.low_fee_cap_atomic,
            &fixture_root("low-fee-receipt", &seed),
            &fixture_root("relay-policy", &seed),
        );
        let local_items = devnet_evidence_items(&seed, &receipt_recovery, &scan_constraint);
        let wallet_evidence_root = evidence_items_root(&local_items);
        let production_blockers = pack_blockers(
            config,
            &receipt_recovery,
            &scan_constraint,
            &nullifier_key_image,
            &pq_authorization,
            &redaction_policy,
            &low_fee_path,
            settlement_fixture_root,
            forced_withdrawal_fixture_root,
        );
        let status = pack_status(&production_blockers, config.cargo_checks_deferred);
        let pack_id = stable_id(
            "wallet-escape-pack",
            &[
                HashPart::Str(wallet_label),
                HashPart::Str(release_claim_id),
                HashPart::Str(&wallet_evidence_root),
            ],
        );
        let claim_builder_inputs = claim_builder_inputs(
            &pack_id,
            settlement_fixture_root,
            forced_withdrawal_fixture_root,
            &wallet_evidence_root,
            &receipt_recovery,
            &scan_constraint,
            &nullifier_key_image,
            &pq_authorization,
            &redaction_policy,
            &low_fee_path,
            4_260_128 + config.force_exit_window_blocks,
        );
        let pack_root = pack_root(
            status,
            &pack_id,
            release_claim_id,
            transfer_id,
            settlement_fixture_root,
            forced_withdrawal_fixture_root,
            &wallet_evidence_root,
            &claim_builder_inputs.builder_root,
            &production_blockers,
        );
        Self {
            pack_id,
            status,
            wallet_label: wallet_label.to_string(),
            release_claim_id: release_claim_id.to_string(),
            transfer_id: transfer_id.to_string(),
            settlement_fixture_root: settlement_fixture_root.to_string(),
            forced_withdrawal_fixture_root: forced_withdrawal_fixture_root.to_string(),
            local_items,
            receipt_recovery,
            scan_constraint,
            nullifier_key_image,
            pq_authorization,
            redaction_policy,
            low_fee_path,
            production_blockers,
            wallet_evidence_root,
            claim_builder_inputs,
            pack_root,
        }
    }

    pub fn can_build_claim(&self) -> bool {
        self.status.permits_claim()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pack_id": self.pack_id,
            "status": self.status.as_str(),
            "wallet_label": self.wallet_label,
            "release_claim_id": self.release_claim_id,
            "transfer_id": self.transfer_id,
            "settlement_fixture_root": self.settlement_fixture_root,
            "forced_withdrawal_fixture_root": self.forced_withdrawal_fixture_root,
            "wallet_evidence_root": self.wallet_evidence_root,
            "local_items": self.local_items.iter().map(WalletLocalEvidenceItem::public_record).collect::<Vec<_>>(),
            "receipt_recovery_root": self.receipt_recovery.plan_root,
            "scan_constraint_root": self.scan_constraint.constraint_root,
            "nullifier_key_image_root": self.nullifier_key_image.commitment_root,
            "pq_authorization_root": self.pq_authorization.authorization_root,
            "redaction_policy": self.redaction_policy.public_record(),
            "low_fee_path_root": self.low_fee_path.path_root,
            "production_blockers": self.production_blockers.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "claim_builder_inputs": self.claim_builder_inputs.public_record(),
            "pack_root": self.pack_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct EvidencePackCounters {
    pub total_packs: u64,
    pub force_exit_ready: u64,
    pub reconstructable: u64,
    pub watch_only: u64,
    pub blocked: u64,
    pub claim_builders_available: u64,
    pub production_blocker_count: u64,
}

impl EvidencePackCounters {
    pub fn from_packs(packs: &[WalletEscapeEvidencePack]) -> Self {
        let mut counters = Self::default();
        counters.total_packs = packs.len() as u64;
        for pack in packs {
            match pack.status {
                EvidencePackStatus::ForceExitReady => counters.force_exit_ready += 1,
                EvidencePackStatus::Reconstructable => counters.reconstructable += 1,
                EvidencePackStatus::WatchOnly => counters.watch_only += 1,
                EvidencePackStatus::Blocked => counters.blocked += 1,
            }
            if pack.can_build_claim() {
                counters.claim_builders_available += 1;
            }
            counters.production_blocker_count += pack.production_blockers.len() as u64;
        }
        counters
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_packs": self.total_packs,
            "force_exit_ready": self.force_exit_ready,
            "reconstructable": self.reconstructable,
            "watch_only": self.watch_only,
            "blocked": self.blocked,
            "claim_builders_available": self.claim_builders_available,
            "production_blocker_count": self.production_blocker_count,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub packs: Vec<WalletEscapeEvidencePack>,
    pub counters: EvidencePackCounters,
    pub config_root: String,
    pub pack_root: String,
    pub claim_builder_root: String,
    pub counters_root: String,
    pub report_root: String,
}

impl State {
    pub fn new(config: Config, packs: Vec<WalletEscapeEvidencePack>) -> Result<Self> {
        if packs.len() > config.max_packs {
            return Err(format!(
                "wallet escape evidence pack count {} exceeds max {}",
                packs.len(),
                config.max_packs
            ));
        }
        let counters = EvidencePackCounters::from_packs(&packs);
        let config_root = config.state_root();
        let pack_root = packs_root(&packs);
        let claim_builder_root = claim_builders_root(&packs);
        let counters_root = counters.state_root();
        let report_root = merkle_root(
            "wallet-escape-evidence-pack-report",
            &[
                json!({"config_root": config_root}),
                json!({"pack_root": pack_root}),
                json!({"claim_builder_root": claim_builder_root}),
                json!({"counters_root": counters_root}),
            ],
        );
        Ok(Self {
            config,
            packs,
            counters,
            config_root,
            pack_root,
            claim_builder_root,
            counters_root,
            report_root,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let packs = vec![
            WalletEscapeEvidencePack::new(
                &config,
                "wallet-alpha-local-force-exit",
                "release-claim-devnet-alpha",
                "private-transfer-alpha",
                &fixture_root("settlement-exit-claim-fixture", "alpha"),
                &fixture_root("forced-withdrawal-authorization-fixture", "alpha"),
                0,
            ),
            WalletEscapeEvidencePack::new(
                &config,
                "wallet-beta-reconstructable-escape",
                "release-claim-devnet-beta",
                "private-transfer-beta",
                &fixture_root("settlement-exit-claim-fixture", "beta"),
                &fixture_root("forced-withdrawal-authorization-fixture", "beta"),
                1,
            ),
        ];
        Self::new(config, packs).expect("devnet wallet escape evidence packs are bounded")
    }

    pub fn force_exit_claim_inputs(&self, pack_id: &str) -> Result<ForceExitClaimBuilderInputs> {
        self.packs
            .iter()
            .find(|pack| pack.pack_id == pack_id)
            .filter(|pack| pack.can_build_claim())
            .map(|pack| pack.claim_builder_inputs.clone())
            .ok_or_else(|| format!("force-exit claim inputs unavailable for pack {pack_id}"))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "packs": self.packs.iter().map(WalletEscapeEvidencePack::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "roots": {
                "config_root": self.config_root,
                "pack_root": self.pack_root,
                "claim_builder_root": self.claim_builder_root,
                "counters_root": self.counters_root,
                "report_root": self.report_root,
                "state_root": self.state_root(),
            }
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "wallet-escape-evidence-pack-state-root",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.pack_root),
                HashPart::Str(&self.claim_builder_root),
                HashPart::Str(&self.counters_root),
                HashPart::Str(&self.report_root),
            ],
            32,
        )
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

pub fn redacted_public_pack(pack: &WalletEscapeEvidencePack) -> Value {
    json!({
        "pack_id": pack.pack_id,
        "status": pack.status.as_str(),
        "release_claim_id": pack.release_claim_id,
        "transfer_id": pack.transfer_id,
        "settlement_fixture_root": pack.settlement_fixture_root,
        "forced_withdrawal_fixture_root": pack.forced_withdrawal_fixture_root,
        "wallet_evidence_root": pack.wallet_evidence_root,
        "claim_builder_root": pack.claim_builder_inputs.builder_root,
        "redaction_policy_root": pack.redaction_policy.policy_root,
        "pack_root": pack.pack_root,
    })
}

pub fn production_blocker_summary(state: &State) -> BTreeMap<String, u64> {
    let mut summary = BTreeMap::new();
    for pack in &state.packs {
        for blocker in &pack.production_blockers {
            *summary.entry(blocker.as_str().to_string()).or_insert(0) += 1;
        }
    }
    summary
}

fn devnet_evidence_items(
    seed: &str,
    receipt_recovery: &EncryptedReceiptRecoveryPlan,
    scan_constraint: &ScanHintConstraint,
) -> Vec<WalletLocalEvidenceItem> {
    vec![
        WalletLocalEvidenceItem::new(
            EvidenceItemKind::SpendAuthoritySeedCommitment,
            RetentionClass::WalletSecret,
            RedactionLevel::WalletLocalOnly,
            "retain spend authority seed or hardened recovery seed share",
            &fixture_root("spend-authority-seed", seed),
            vec![
                "wallet seed backup".to_string(),
                "hardware signer export".to_string(),
            ],
            vec!["seed commitment opening".to_string()],
            vec!["spend authority commitment only".to_string()],
        ),
        WalletLocalEvidenceItem::new(
            EvidenceItemKind::EncryptedReceiptCiphertextRoot,
            RetentionClass::WalletEncrypted,
            RedactionLevel::WatcherChallenge,
            "retain encrypted receipt ciphertext and decryptor commitment",
            &receipt_recovery.ciphertext_root,
            vec!["encrypted wallet receipt database".to_string()],
            vec![
                "ciphertext bytes".to_string(),
                "decryptor commitment".to_string(),
            ],
            vec![
                "ciphertext root".to_string(),
                "receipt guard root".to_string(),
            ],
        ),
        WalletLocalEvidenceItem::new(
            EvidenceItemKind::ScanHintCommitment,
            RetentionClass::PublicCommitment,
            RedactionLevel::PublicClaim,
            "retain bounded scan hints without raw subaddress disclosure",
            &scan_constraint.hint_commitment_root,
            vec![
                "receipt scan index".to_string(),
                "chain scan window".to_string(),
            ],
            vec!["bounded hint commitments".to_string()],
            vec!["hint root".to_string(), "privacy set size".to_string()],
        ),
        WalletLocalEvidenceItem::new(
            EvidenceItemKind::NullifierCommitment,
            RetentionClass::ReconstructableFromChain,
            RedactionLevel::CourtRecovery,
            "retain nullifier and key-image commitments for replay fencing",
            &fixture_root("nullifier-key-image-item", seed),
            vec![
                "note commitment path".to_string(),
                "spent-state epoch".to_string(),
            ],
            vec![
                "nullifier opening witness".to_string(),
                "key-image witness".to_string(),
            ],
            vec!["nullifier root".to_string(), "key-image root".to_string()],
        ),
        WalletLocalEvidenceItem::new(
            EvidenceItemKind::PqWithdrawalAuthorization,
            RetentionClass::WalletEncrypted,
            RedactionLevel::WatcherChallenge,
            "retain PQ withdrawal authorization over destination and amount commitments",
            &fixture_root("pq-withdrawal-authorization-item", seed),
            vec!["wallet signer transcript".to_string()],
            vec!["PQ signature envelope".to_string()],
            vec![
                "PQ signature root".to_string(),
                "authority commitment".to_string(),
            ],
        ),
    ]
}

fn pack_blockers(
    config: &Config,
    receipt_recovery: &EncryptedReceiptRecoveryPlan,
    scan_constraint: &ScanHintConstraint,
    nullifier_key_image: &NullifierKeyImageCommitment,
    pq_authorization: &PqWithdrawalAuthorization,
    redaction_policy: &PrivacyRedactionPolicy,
    low_fee_path: &LowFeeEmergencyPath,
    settlement_fixture_root: &str,
    forced_withdrawal_fixture_root: &str,
) -> Vec<ProductionBlockerKind> {
    let mut blockers = Vec::new();
    if !receipt_recovery.meets_threshold() {
        blockers.push(ProductionBlockerKind::MissingEncryptedReceiptRecovery);
    }
    if !scan_constraint.satisfies_privacy(config) {
        blockers.push(ProductionBlockerKind::ScanHintPrivacyFloorMissing);
    }
    if nullifier_key_image.nullifier_root.is_empty()
        || nullifier_key_image.key_image_root.is_empty()
    {
        blockers.push(ProductionBlockerKind::NullifierOrKeyImageUnbound);
    }
    if !pq_authorization.satisfies_security(config) {
        blockers.push(ProductionBlockerKind::PqAuthorizationMissing);
    }
    if settlement_fixture_root.is_empty() {
        blockers.push(ProductionBlockerKind::SettlementFixtureBindingMissing);
    }
    if forced_withdrawal_fixture_root.is_empty() {
        blockers.push(ProductionBlockerKind::ForcedWithdrawalFixtureBindingMissing);
    }
    if redaction_policy.policy_root.is_empty() {
        blockers.push(ProductionBlockerKind::RedactionPolicyMissing);
    }
    if config.require_low_fee_emergency_path && !low_fee_path.satisfies_fee_cap(config) {
        blockers.push(ProductionBlockerKind::LowFeeEmergencyPathUnpriced);
    }
    if config.cargo_checks_deferred {
        blockers.push(ProductionBlockerKind::CargoExecutionNotRun);
    }
    blockers
}

fn pack_status(
    blockers: &[ProductionBlockerKind],
    cargo_checks_deferred: bool,
) -> EvidencePackStatus {
    if blockers.is_empty() {
        return EvidencePackStatus::ForceExitReady;
    }
    if cargo_checks_deferred
        && blockers
            .iter()
            .all(|kind| matches!(kind, ProductionBlockerKind::CargoExecutionNotRun))
    {
        return EvidencePackStatus::Reconstructable;
    }
    if blockers.len() <= 2 {
        EvidencePackStatus::WatchOnly
    } else {
        EvidencePackStatus::Blocked
    }
}

fn claim_builder_inputs(
    pack_id: &str,
    settlement_fixture_root: &str,
    forced_withdrawal_fixture_root: &str,
    wallet_evidence_root: &str,
    receipt_recovery: &EncryptedReceiptRecoveryPlan,
    scan_constraint: &ScanHintConstraint,
    nullifier_key_image: &NullifierKeyImageCommitment,
    pq_authorization: &PqWithdrawalAuthorization,
    redaction_policy: &PrivacyRedactionPolicy,
    low_fee_path: &LowFeeEmergencyPath,
    force_exit_window_end: u64,
) -> ForceExitClaimBuilderInputs {
    let builder_root = force_exit_claim_builder_root(
        pack_id,
        settlement_fixture_root,
        forced_withdrawal_fixture_root,
        wallet_evidence_root,
        &receipt_recovery.plan_root,
        &scan_constraint.constraint_root,
        &nullifier_key_image.commitment_root,
        &pq_authorization.authorization_root,
        &low_fee_path.fee_receipt_root,
        &redaction_policy.policy_root,
        force_exit_window_end,
    );
    let claim_id = stable_id(
        "wallet-escape-force-exit-claim",
        &[HashPart::Str(&builder_root)],
    );
    ForceExitClaimBuilderInputs {
        claim_id,
        pack_id: pack_id.to_string(),
        settlement_fixture_root: settlement_fixture_root.to_string(),
        forced_withdrawal_fixture_root: forced_withdrawal_fixture_root.to_string(),
        wallet_evidence_root: wallet_evidence_root.to_string(),
        receipt_recovery_root: receipt_recovery.plan_root.clone(),
        scan_constraint_root: scan_constraint.constraint_root.clone(),
        nullifier_key_image_root: nullifier_key_image.commitment_root.clone(),
        pq_authorization_root: pq_authorization.authorization_root.clone(),
        low_fee_receipt_root: low_fee_path.fee_receipt_root.clone(),
        redaction_policy_root: redaction_policy.policy_root.clone(),
        force_exit_window_end,
        builder_root,
    }
}

fn evidence_item_root(
    kind: EvidenceItemKind,
    retention_class: RetentionClass,
    redaction_level: RedactionLevel,
    label: &str,
    commitment_root: &str,
    reconstruct_from: &[String],
    retained_material: &[String],
    public_disclosure: &[String],
) -> String {
    domain_hash(
        "wallet-escape-evidence-item-root",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(retention_class.as_str()),
            HashPart::Str(redaction_level.as_str()),
            HashPart::Str(label),
            HashPart::Str(commitment_root),
            HashPart::Json(&json!(reconstruct_from)),
            HashPart::Json(&json!(retained_material)),
            HashPart::Json(&json!(public_disclosure)),
        ],
        32,
    )
}

fn evidence_items_root(items: &[WalletLocalEvidenceItem]) -> String {
    merkle_root(
        "wallet-escape-evidence-items",
        &items
            .iter()
            .map(|item| item.public_record())
            .collect::<Vec<_>>(),
    )
}

fn receipt_recovery_root(
    ciphertext_root: &str,
    recovery_shard_root: &str,
    receipt_guard_root: &str,
    decryptor_commitment_root: &str,
    shard_count: u16,
    threshold: u16,
    recovery_window_start: u64,
    recovery_window_end: u64,
) -> String {
    domain_hash(
        "wallet-escape-receipt-recovery-root",
        &[
            HashPart::Str(ciphertext_root),
            HashPart::Str(recovery_shard_root),
            HashPart::Str(receipt_guard_root),
            HashPart::Str(decryptor_commitment_root),
            HashPart::U64(shard_count as u64),
            HashPart::U64(threshold as u64),
            HashPart::U64(recovery_window_start),
            HashPart::U64(recovery_window_end),
        ],
        32,
    )
}

fn scan_hint_constraint_root(
    hint_commitment_root: &str,
    scan_window_root: &str,
    hint_count: u16,
    privacy_set_size: u64,
    metadata_leakage_units: u16,
    bounded_hint_labels: &[String],
) -> String {
    domain_hash(
        "wallet-escape-scan-hint-constraint-root",
        &[
            HashPart::Str(hint_commitment_root),
            HashPart::Str(scan_window_root),
            HashPart::U64(hint_count as u64),
            HashPart::U64(privacy_set_size),
            HashPart::U64(metadata_leakage_units as u64),
            HashPart::Json(&json!(bounded_hint_labels)),
        ],
        32,
    )
}

fn nullifier_key_image_root(
    nullifier_root: &str,
    key_image_root: &str,
    note_commitment_path_root: &str,
    replay_domain: &str,
    spent_state_epoch: u64,
) -> String {
    domain_hash(
        "wallet-escape-nullifier-key-image-root",
        &[
            HashPart::Str(nullifier_root),
            HashPart::Str(key_image_root),
            HashPart::Str(note_commitment_path_root),
            HashPart::Str(replay_domain),
            HashPart::U64(spent_state_epoch),
        ],
        32,
    )
}

fn pq_authorization_root(
    wallet_authority_commitment: &str,
    recovery_authority_commitment: &str,
    destination_commitment: &str,
    amount_commitment: &str,
    pq_signature_root: &str,
    security_bits: u16,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "wallet-escape-pq-withdrawal-authorization-root",
        &[
            HashPart::Str(wallet_authority_commitment),
            HashPart::Str(recovery_authority_commitment),
            HashPart::Str(destination_commitment),
            HashPart::Str(amount_commitment),
            HashPart::Str(pq_signature_root),
            HashPart::U64(security_bits as u64),
            HashPart::U64(expires_at_height),
        ],
        32,
    )
}

fn redaction_policy_root(
    public_fields: &[String],
    challenge_fields: &[String],
    wallet_secret_fields: &[String],
    redact_amounts: bool,
    redact_scan_hints: bool,
    redact_destination: bool,
) -> String {
    domain_hash(
        "wallet-escape-redaction-policy-root",
        &[
            HashPart::Json(&json!(public_fields)),
            HashPart::Json(&json!(challenge_fields)),
            HashPart::Json(&json!(wallet_secret_fields)),
            HashPart::Str(bool_str(redact_amounts)),
            HashPart::Str(bool_str(redact_scan_hints)),
            HashPart::Str(bool_str(redact_destination)),
        ],
        32,
    )
}

fn low_fee_path_root(
    fee_sponsor_commitment: &str,
    max_fee_atomic: u64,
    fee_receipt_root: &str,
    relay_policy_root: &str,
) -> String {
    domain_hash(
        "wallet-escape-low-fee-emergency-path-root",
        &[
            HashPart::Str(fee_sponsor_commitment),
            HashPart::U64(max_fee_atomic),
            HashPart::Str(fee_receipt_root),
            HashPart::Str(relay_policy_root),
        ],
        32,
    )
}

fn force_exit_claim_builder_root(
    pack_id: &str,
    settlement_fixture_root: &str,
    forced_withdrawal_fixture_root: &str,
    wallet_evidence_root: &str,
    receipt_recovery_root: &str,
    scan_constraint_root: &str,
    nullifier_key_image_root: &str,
    pq_authorization_root: &str,
    low_fee_receipt_root: &str,
    redaction_policy_root: &str,
    force_exit_window_end: u64,
) -> String {
    domain_hash(
        "wallet-escape-force-exit-claim-builder-root",
        &[
            HashPart::Str(pack_id),
            HashPart::Str(settlement_fixture_root),
            HashPart::Str(forced_withdrawal_fixture_root),
            HashPart::Str(wallet_evidence_root),
            HashPart::Str(receipt_recovery_root),
            HashPart::Str(scan_constraint_root),
            HashPart::Str(nullifier_key_image_root),
            HashPart::Str(pq_authorization_root),
            HashPart::Str(low_fee_receipt_root),
            HashPart::Str(redaction_policy_root),
            HashPart::U64(force_exit_window_end),
        ],
        32,
    )
}

fn pack_root(
    status: EvidencePackStatus,
    pack_id: &str,
    release_claim_id: &str,
    transfer_id: &str,
    settlement_fixture_root: &str,
    forced_withdrawal_fixture_root: &str,
    wallet_evidence_root: &str,
    claim_builder_root: &str,
    production_blockers: &[ProductionBlockerKind],
) -> String {
    domain_hash(
        "wallet-escape-evidence-pack-root",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(pack_id),
            HashPart::Str(release_claim_id),
            HashPart::Str(transfer_id),
            HashPart::Str(settlement_fixture_root),
            HashPart::Str(forced_withdrawal_fixture_root),
            HashPart::Str(wallet_evidence_root),
            HashPart::Str(claim_builder_root),
            HashPart::Json(&json!(production_blockers
                .iter()
                .map(|kind| kind.as_str())
                .collect::<Vec<_>>())),
        ],
        32,
    )
}

fn packs_root(packs: &[WalletEscapeEvidencePack]) -> String {
    merkle_root(
        "wallet-escape-evidence-packs",
        &packs.iter().map(redacted_public_pack).collect::<Vec<_>>(),
    )
}

fn claim_builders_root(packs: &[WalletEscapeEvidencePack]) -> String {
    merkle_root(
        "wallet-escape-claim-builders",
        &packs
            .iter()
            .map(|pack| pack.claim_builder_inputs.public_record())
            .collect::<Vec<_>>(),
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "wallet-escape-evidence-pack-record-root",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn fixture_root(kind: &str, seed: &str) -> String {
    domain_hash(
        "wallet-escape-evidence-pack-devnet-fixture-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(seed),
        ],
        32,
    )
}

fn stable_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        "wallet-escape-evidence-pack-stable-id",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&domain_hash(domain, parts, 32)),
        ],
        16,
    )
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
