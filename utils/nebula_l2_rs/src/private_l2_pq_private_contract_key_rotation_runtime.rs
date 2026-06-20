use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqPrivateContractKeyRotationRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_PRIVATE_CONTRACT_KEY_ROTATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-private-contract-key-rotation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_PRIVATE_CONTRACT_KEY_ROTATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-key-epoch-v1";
pub const PQ_KEM_SUITE: &str = "ML-KEM-1024+hybrid-x25519-encrypted-rotation-bundle-v1";
pub const STEALTH_SIGNER_SCHEME: &str = "monero-l2-stealth-signer-commitment-root-v1";
pub const REPLAY_FENCE_SCHEME: &str = "contract-key-rotation-nullifier-fence-v1";
pub const LOW_FEE_BATCH_SCHEME: &str = "low-fee-private-contract-key-rotation-batch-v1";
pub const EMERGENCY_RECOVERY_SCHEME: &str = "pq-private-contract-emergency-recovery-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "pq-private-contract-key-rotation-slashing-evidence-v1";
pub const DEVNET_HEIGHT: u64 = 812_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_EPOCH_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_ROTATION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_RECOVERY_DELAY_BLOCKS: u64 = 96;
pub const DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 128;
pub const DEFAULT_MAX_ROTATION_FEE_BPS: u64 = 12;
pub const DEFAULT_SPONSOR_COVERAGE_BPS: u64 = 9_200;
pub const DEFAULT_LOW_FEE_BATCH_TARGET: usize = 256;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: usize = 4_096;
pub const MAX_CONTRACTS: usize = 524_288;
pub const MAX_KEY_EPOCHS: usize = 2_097_152;
pub const MAX_STEALTH_SIGNERS: usize = 4_194_304;
pub const MAX_ROTATION_BUNDLES: usize = 2_097_152;
pub const MAX_RECOVERY_REQUESTS: usize = 524_288;
pub const MAX_REPLAY_FENCES: usize = 8_388_608;
pub const MAX_SPONSOR_RESERVATIONS: usize = 2_097_152;
pub const MAX_BATCHES: usize = 524_288;
pub const MAX_RECEIPTS: usize = 4_194_304;
pub const MAX_SLASHING_EVIDENCE: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractClass {
    SmartAccount,
    PrivateVault,
    ConfidentialAmm,
    IntentRouter,
    BridgeEscrow,
    GovernanceModule,
    Custom,
}

impl ContractClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SmartAccount => "smart_account",
            Self::PrivateVault => "private_vault",
            Self::ConfidentialAmm => "confidential_amm",
            Self::IntentRouter => "intent_router",
            Self::BridgeEscrow => "bridge_escrow",
            Self::GovernanceModule => "governance_module",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatus {
    Registered,
    Active,
    Rotating,
    RecoveryOnly,
    Frozen,
    Retired,
    Slashed,
}

impl ContractStatus {
    pub fn accepts_rotation(self) -> bool {
        matches!(self, Self::Active | Self::Rotating | Self::RecoveryOnly)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::RecoveryOnly => "recovery_only",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithm {
    MlDsa65,
    MlDsa87,
    SlhDsaShake192f,
    SlhDsaShake256f,
    HybridEd25519MlDsa87,
    HybridSecp256k1MlDsa87,
}

impl KeyAlgorithm {
    pub fn pq_security_bits(self) -> u16 {
        match self {
            Self::MlDsa65 => 192,
            Self::MlDsa87 => 256,
            Self::SlhDsaShake192f => 192,
            Self::SlhDsaShake256f => 256,
            Self::HybridEd25519MlDsa87 => 256,
            Self::HybridSecp256k1MlDsa87 => 256,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ml_dsa_65",
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaShake192f => "slh_dsa_shake_192f",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
            Self::HybridEd25519MlDsa87 => "hybrid_ed25519_ml_dsa_87",
            Self::HybridSecp256k1MlDsa87 => "hybrid_secp256k1_ml_dsa_87",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochStatus {
    Proposed,
    SponsorReserved,
    BundleSealed,
    PendingActivation,
    Active,
    Superseded,
    Revoked,
    EmergencyRecovered,
    Slashed,
}

impl EpochStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::SponsorReserved | Self::BundleSealed | Self::PendingActivation | Self::Active
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::SponsorReserved => "sponsor_reserved",
            Self::BundleSealed => "bundle_sealed",
            Self::PendingActivation => "pending_activation",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::EmergencyRecovered => "emergency_recovered",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Submitted,
    ReplayFenced,
    SponsorMatched,
    BatchQueued,
    Settled,
    Rejected,
    Expired,
}

impl BundleStatus {
    pub fn batchable(self) -> bool {
        matches!(self, Self::ReplayFenced | Self::SponsorMatched)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryKind {
    LostSigner,
    CompromisedSigner,
    CiphertextLoss,
    PolicyDeadlock,
    WatchtowerVeto,
    QuantumMigration,
    EmergencyEscape,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    Requested,
    DelayWindow,
    GuardianAttested,
    SponsorReserved,
    Executed,
    Cancelled,
    Expired,
    Slashed,
}

impl RecoveryStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Requested | Self::DelayWindow | Self::GuardianAttested | Self::SponsorReserved
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Matched,
    Consumed,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationBatchStatus {
    Open,
    Sealed,
    Posted,
    Settled,
    Disputed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    ContractRegistered,
    EpochProposed,
    BundleSubmitted,
    ReplayFenceAccepted,
    SponsorReserved,
    BatchSettled,
    EpochActivated,
    EmergencyRecovery,
    EvidenceFiled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingKind {
    EpochEquivocation,
    ReplayFenceReuse,
    InvalidMlDsaProof,
    StaleKeyActivation,
    SponsorFraud,
    RecoveryForgery,
    BundleWithholding,
    PrivacySetDowngrade,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Filed,
    Linked,
    Challenged,
    Accepted,
    Rejected,
    Slashed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub devnet_height: u64,
    pub hash_suite: String,
    pub pq_signature_suite: String,
    pub pq_kem_suite: String,
    pub stealth_signer_scheme: String,
    pub replay_fence_scheme: String,
    pub low_fee_batch_scheme: String,
    pub emergency_recovery_scheme: String,
    pub slashing_evidence_scheme: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub epoch_ttl_blocks: u64,
    pub rotation_ttl_blocks: u64,
    pub recovery_delay_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub max_rotation_fee_bps: u64,
    pub sponsor_coverage_bps: u64,
    pub low_fee_batch_target: usize,
    pub low_fee_batch_limit: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            devnet_height: DEVNET_HEIGHT,
            hash_suite: HASH_SUITE.to_string(),
            pq_signature_suite: PQ_SIGNATURE_SUITE.to_string(),
            pq_kem_suite: PQ_KEM_SUITE.to_string(),
            stealth_signer_scheme: STEALTH_SIGNER_SCHEME.to_string(),
            replay_fence_scheme: REPLAY_FENCE_SCHEME.to_string(),
            low_fee_batch_scheme: LOW_FEE_BATCH_SCHEME.to_string(),
            emergency_recovery_scheme: EMERGENCY_RECOVERY_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            epoch_ttl_blocks: DEFAULT_EPOCH_TTL_BLOCKS,
            rotation_ttl_blocks: DEFAULT_ROTATION_TTL_BLOCKS,
            recovery_delay_blocks: DEFAULT_RECOVERY_DELAY_BLOCKS,
            sponsor_ttl_blocks: DEFAULT_SPONSOR_TTL_BLOCKS,
            max_rotation_fee_bps: DEFAULT_MAX_ROTATION_FEE_BPS,
            sponsor_coverage_bps: DEFAULT_SPONSOR_COVERAGE_BPS,
            low_fee_batch_target: DEFAULT_LOW_FEE_BATCH_TARGET,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "chain_id": self.chain_id,
            "devnet_height": self.devnet_height,
            "emergency_recovery_scheme": self.emergency_recovery_scheme,
            "epoch_ttl_blocks": self.epoch_ttl_blocks,
            "hash_suite": self.hash_suite,
            "low_fee_batch_limit": self.low_fee_batch_limit,
            "low_fee_batch_scheme": self.low_fee_batch_scheme,
            "low_fee_batch_target": self.low_fee_batch_target,
            "max_rotation_fee_bps": self.max_rotation_fee_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "protocol_version": self.protocol_version,
            "pq_kem_suite": self.pq_kem_suite,
            "pq_signature_suite": self.pq_signature_suite,
            "recovery_delay_blocks": self.recovery_delay_blocks,
            "replay_fence_scheme": self.replay_fence_scheme,
            "rotation_ttl_blocks": self.rotation_ttl_blocks,
            "schema_version": self.schema_version,
            "slashing_evidence_scheme": self.slashing_evidence_scheme,
            "sponsor_coverage_bps": self.sponsor_coverage_bps,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "stealth_signer_scheme": self.stealth_signer_scheme,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateContract {
    pub contract_id: String,
    pub class: ContractClass,
    pub owner_commitment: String,
    pub policy_root: String,
    pub current_epoch_id: String,
    pub current_epoch_number: u64,
    pub monero_view_tag_root: String,
    pub l2_address_commitment: String,
    pub status: ContractStatus,
    pub registered_at_height: u64,
    pub updated_at_height: u64,
}

impl PrivateContract {
    pub fn new(
        class: ContractClass,
        owner_commitment: impl Into<String>,
        policy_root: impl Into<String>,
        l2_address_commitment: impl Into<String>,
        height: u64,
    ) -> Self {
        let owner_commitment = owner_commitment.into();
        let policy_root = policy_root.into();
        let l2_address_commitment = l2_address_commitment.into();
        let monero_view_tag_root = id_from_parts(
            "MONERO-VIEW-TAG-ROOT",
            &[
                HashPart::Str(&owner_commitment),
                HashPart::Str(&policy_root),
                HashPart::Str(&l2_address_commitment),
            ],
        );
        let contract_id = id_from_parts(
            "PRIVATE-CONTRACT-ID",
            &[
                HashPart::Str(class.as_str()),
                HashPart::Str(&owner_commitment),
                HashPart::Str(&policy_root),
                HashPart::Str(&l2_address_commitment),
                HashPart::U64(height),
            ],
        );
        let current_epoch_id = id_from_parts(
            "INITIAL-EPOCH-ID",
            &[HashPart::Str(&contract_id), HashPart::U64(0)],
        );
        Self {
            contract_id,
            class,
            owner_commitment,
            policy_root,
            current_epoch_id,
            current_epoch_number: 0,
            monero_view_tag_root,
            l2_address_commitment,
            status: ContractStatus::Registered,
            registered_at_height: height,
            updated_at_height: height,
        }
    }

    pub fn activate(mut self, epoch_id: impl Into<String>, height: u64) -> Self {
        self.current_epoch_id = epoch_id.into();
        self.current_epoch_number = self.current_epoch_number.saturating_add(1);
        self.status = ContractStatus::Active;
        self.updated_at_height = height;
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "class": self.class,
            "contract_id": self.contract_id,
            "current_epoch_id": self.current_epoch_id,
            "current_epoch_number": self.current_epoch_number,
            "l2_address_commitment": self.l2_address_commitment,
            "monero_view_tag_root": self.monero_view_tag_root,
            "owner_commitment": self.owner_commitment,
            "policy_root": self.policy_root,
            "registered_at_height": self.registered_at_height,
            "status": self.status,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("PRIVATE-CONTRACT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyEpoch {
    pub epoch_id: String,
    pub contract_id: String,
    pub epoch_number: u64,
    pub previous_epoch_id: String,
    pub signing_algorithm: KeyAlgorithm,
    pub verification_key_commitment: String,
    pub verification_key_root: String,
    pub stealth_signer_set_root: String,
    pub activation_nullifier: String,
    pub expiry_height: u64,
    pub pq_security_bits: u16,
    pub status: EpochStatus,
    pub created_at_height: u64,
    pub activated_at_height: Option<u64>,
}

impl KeyEpoch {
    pub fn proposed(
        contract: &PrivateContract,
        signing_algorithm: KeyAlgorithm,
        verification_key_commitment: impl Into<String>,
        verification_key_root: impl Into<String>,
        stealth_signer_set_root: impl Into<String>,
        height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let verification_key_commitment = verification_key_commitment.into();
        let verification_key_root = verification_key_root.into();
        let stealth_signer_set_root = stealth_signer_set_root.into();
        let epoch_number = contract.current_epoch_number.saturating_add(1);
        let activation_nullifier = id_from_parts(
            "EPOCH-ACTIVATION-NULLIFIER",
            &[
                HashPart::Str(&contract.contract_id),
                HashPart::Str(&contract.current_epoch_id),
                HashPart::U64(epoch_number),
                HashPart::Str(&verification_key_commitment),
            ],
        );
        let epoch_id = id_from_parts(
            "KEY-EPOCH-ID",
            &[
                HashPart::Str(&contract.contract_id),
                HashPart::U64(epoch_number),
                HashPart::Str(&verification_key_root),
                HashPart::Str(&stealth_signer_set_root),
                HashPart::Str(&activation_nullifier),
            ],
        );
        Self {
            epoch_id,
            contract_id: contract.contract_id.clone(),
            epoch_number,
            previous_epoch_id: contract.current_epoch_id.clone(),
            signing_algorithm,
            verification_key_commitment,
            verification_key_root,
            stealth_signer_set_root,
            activation_nullifier,
            expiry_height: height.saturating_add(ttl_blocks),
            pq_security_bits: signing_algorithm.pq_security_bits(),
            status: EpochStatus::Proposed,
            created_at_height: height,
            activated_at_height: None,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "activated_at_height": self.activated_at_height,
            "activation_nullifier": self.activation_nullifier,
            "contract_id": self.contract_id,
            "created_at_height": self.created_at_height,
            "epoch_id": self.epoch_id,
            "epoch_number": self.epoch_number,
            "expiry_height": self.expiry_height,
            "pq_security_bits": self.pq_security_bits,
            "previous_epoch_id": self.previous_epoch_id,
            "signing_algorithm": self.signing_algorithm,
            "status": self.status,
            "stealth_signer_set_root": self.stealth_signer_set_root,
            "verification_key_commitment": self.verification_key_commitment,
            "verification_key_root": self.verification_key_root,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("KEY-EPOCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StealthSignerCommitment {
    pub signer_commitment_id: String,
    pub contract_id: String,
    pub epoch_id: String,
    pub signer_tag: String,
    pub one_time_address_commitment: String,
    pub monero_subaddress_hint: String,
    pub pq_proof_root: String,
    pub privacy_set_size: u64,
    pub registered_at_height: u64,
}

impl StealthSignerCommitment {
    pub fn new(
        contract_id: impl Into<String>,
        epoch_id: impl Into<String>,
        signer_tag: impl Into<String>,
        one_time_address_commitment: impl Into<String>,
        monero_subaddress_hint: impl Into<String>,
        pq_proof_root: impl Into<String>,
        privacy_set_size: u64,
        height: u64,
    ) -> Self {
        let contract_id = contract_id.into();
        let epoch_id = epoch_id.into();
        let signer_tag = signer_tag.into();
        let one_time_address_commitment = one_time_address_commitment.into();
        let monero_subaddress_hint = monero_subaddress_hint.into();
        let pq_proof_root = pq_proof_root.into();
        let signer_commitment_id = id_from_parts(
            "STEALTH-SIGNER-COMMITMENT-ID",
            &[
                HashPart::Str(&contract_id),
                HashPart::Str(&epoch_id),
                HashPart::Str(&signer_tag),
                HashPart::Str(&one_time_address_commitment),
                HashPart::Str(&pq_proof_root),
            ],
        );
        Self {
            signer_commitment_id,
            contract_id,
            epoch_id,
            signer_tag,
            one_time_address_commitment,
            monero_subaddress_hint,
            pq_proof_root,
            privacy_set_size,
            registered_at_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "epoch_id": self.epoch_id,
            "monero_subaddress_hint": self.monero_subaddress_hint,
            "one_time_address_commitment": self.one_time_address_commitment,
            "pq_proof_root": self.pq_proof_root,
            "privacy_set_size": self.privacy_set_size,
            "registered_at_height": self.registered_at_height,
            "signer_commitment_id": self.signer_commitment_id,
            "signer_tag": self.signer_tag,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("STEALTH-SIGNER", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedRotationBundle {
    pub bundle_id: String,
    pub contract_id: String,
    pub target_epoch_id: String,
    pub previous_epoch_id: String,
    pub ciphertext_root: String,
    pub kem_recipient_root: String,
    pub encrypted_delta_root: String,
    pub pq_authorization_root: String,
    pub replay_nullifier: String,
    pub fee_sponsor_id: Option<String>,
    pub max_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub status: BundleStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedRotationBundle {
    pub fn new(
        epoch: &KeyEpoch,
        ciphertext_root: impl Into<String>,
        kem_recipient_root: impl Into<String>,
        encrypted_delta_root: impl Into<String>,
        pq_authorization_root: impl Into<String>,
        max_fee_micro_units: u64,
        privacy_set_size: u64,
        height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let ciphertext_root = ciphertext_root.into();
        let kem_recipient_root = kem_recipient_root.into();
        let encrypted_delta_root = encrypted_delta_root.into();
        let pq_authorization_root = pq_authorization_root.into();
        let replay_nullifier = id_from_parts(
            "ROTATION-BUNDLE-NULLIFIER",
            &[
                HashPart::Str(&epoch.contract_id),
                HashPart::Str(&epoch.previous_epoch_id),
                HashPart::Str(&epoch.epoch_id),
                HashPart::Str(&ciphertext_root),
            ],
        );
        let bundle_id = id_from_parts(
            "ROTATION-BUNDLE-ID",
            &[
                HashPart::Str(&epoch.contract_id),
                HashPart::Str(&epoch.epoch_id),
                HashPart::Str(&ciphertext_root),
                HashPart::Str(&kem_recipient_root),
                HashPart::Str(&encrypted_delta_root),
                HashPart::Str(&pq_authorization_root),
                HashPart::Str(&replay_nullifier),
            ],
        );
        Self {
            bundle_id,
            contract_id: epoch.contract_id.clone(),
            target_epoch_id: epoch.epoch_id.clone(),
            previous_epoch_id: epoch.previous_epoch_id.clone(),
            ciphertext_root,
            kem_recipient_root,
            encrypted_delta_root,
            pq_authorization_root,
            replay_nullifier,
            fee_sponsor_id: None,
            max_fee_micro_units,
            privacy_set_size,
            status: BundleStatus::Submitted,
            submitted_at_height: height,
            expires_at_height: height.saturating_add(ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "ciphertext_root": self.ciphertext_root,
            "contract_id": self.contract_id,
            "encrypted_delta_root": self.encrypted_delta_root,
            "expires_at_height": self.expires_at_height,
            "fee_sponsor_id": self.fee_sponsor_id,
            "kem_recipient_root": self.kem_recipient_root,
            "max_fee_micro_units": self.max_fee_micro_units,
            "pq_authorization_root": self.pq_authorization_root,
            "previous_epoch_id": self.previous_epoch_id,
            "privacy_set_size": self.privacy_set_size,
            "replay_nullifier": self.replay_nullifier,
            "status": self.status,
            "submitted_at_height": self.submitted_at_height,
            "target_epoch_id": self.target_epoch_id,
        })
    }

    pub fn root(&self) -> String {
        root_from_record("ROTATION-BUNDLE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayFence {
    pub fence_id: String,
    pub contract_id: String,
    pub epoch_id: String,
    pub nullifier: String,
    pub source_bundle_id: String,
    pub accepted_at_height: u64,
}

impl ReplayFence {
    pub fn new(bundle: &EncryptedRotationBundle, height: u64) -> Self {
        let fence_id = id_from_parts(
            "REPLAY-FENCE-ID",
            &[
                HashPart::Str(&bundle.contract_id),
                HashPart::Str(&bundle.target_epoch_id),
                HashPart::Str(&bundle.replay_nullifier),
                HashPart::Str(&bundle.bundle_id),
            ],
        );
        Self {
            fence_id,
            contract_id: bundle.contract_id.clone(),
            epoch_id: bundle.target_epoch_id.clone(),
            nullifier: bundle.replay_nullifier.clone(),
            source_bundle_id: bundle.bundle_id.clone(),
            accepted_at_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "accepted_at_height": self.accepted_at_height,
            "contract_id": self.contract_id,
            "epoch_id": self.epoch_id,
            "fence_id": self.fence_id,
            "nullifier": self.nullifier,
            "source_bundle_id": self.source_bundle_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsorReservation {
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub subject_id: String,
    pub contract_id: String,
    pub reserved_micro_units: u64,
    pub coverage_bps: u64,
    pub privacy_pool_root: String,
    pub status: SponsorReservationStatus,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeSponsorReservation {
    pub fn new(
        sponsor_commitment: impl Into<String>,
        subject_id: impl Into<String>,
        contract_id: impl Into<String>,
        reserved_micro_units: u64,
        coverage_bps: u64,
        privacy_pool_root: impl Into<String>,
        height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let sponsor_commitment = sponsor_commitment.into();
        let subject_id = subject_id.into();
        let contract_id = contract_id.into();
        let privacy_pool_root = privacy_pool_root.into();
        let reservation_id = id_from_parts(
            "FEE-SPONSOR-RESERVATION-ID",
            &[
                HashPart::Str(&sponsor_commitment),
                HashPart::Str(&subject_id),
                HashPart::Str(&contract_id),
                HashPart::U64(reserved_micro_units),
                HashPart::Str(&privacy_pool_root),
            ],
        );
        Self {
            reservation_id,
            sponsor_commitment,
            subject_id,
            contract_id,
            reserved_micro_units,
            coverage_bps,
            privacy_pool_root,
            status: SponsorReservationStatus::Reserved,
            reserved_at_height: height,
            expires_at_height: height.saturating_add(ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "coverage_bps": self.coverage_bps,
            "expires_at_height": self.expires_at_height,
            "privacy_pool_root": self.privacy_pool_root,
            "reservation_id": self.reservation_id,
            "reserved_at_height": self.reserved_at_height,
            "reserved_micro_units": self.reserved_micro_units,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status,
            "subject_id": self.subject_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EmergencyRecoveryRequest {
    pub recovery_id: String,
    pub contract_id: String,
    pub recovery_kind: RecoveryKind,
    pub current_epoch_id: String,
    pub replacement_epoch_id: String,
    pub guardian_set_root: String,
    pub encrypted_recovery_bundle_root: String,
    pub recovery_nullifier: String,
    pub fee_sponsor_id: Option<String>,
    pub status: RecoveryStatus,
    pub requested_at_height: u64,
    pub executable_at_height: u64,
}

impl EmergencyRecoveryRequest {
    pub fn new(
        contract: &PrivateContract,
        recovery_kind: RecoveryKind,
        replacement_epoch_id: impl Into<String>,
        guardian_set_root: impl Into<String>,
        encrypted_recovery_bundle_root: impl Into<String>,
        height: u64,
        delay_blocks: u64,
    ) -> Self {
        let replacement_epoch_id = replacement_epoch_id.into();
        let guardian_set_root = guardian_set_root.into();
        let encrypted_recovery_bundle_root = encrypted_recovery_bundle_root.into();
        let recovery_nullifier = id_from_parts(
            "EMERGENCY-RECOVERY-NULLIFIER",
            &[
                HashPart::Str(&contract.contract_id),
                HashPart::Str(&contract.current_epoch_id),
                HashPart::Str(&replacement_epoch_id),
                HashPart::Str(&encrypted_recovery_bundle_root),
            ],
        );
        let recovery_id = id_from_parts(
            "EMERGENCY-RECOVERY-ID",
            &[
                HashPart::Str(&contract.contract_id),
                HashPart::Str(&replacement_epoch_id),
                HashPart::Str(&guardian_set_root),
                HashPart::Str(&recovery_nullifier),
            ],
        );
        Self {
            recovery_id,
            contract_id: contract.contract_id.clone(),
            recovery_kind,
            current_epoch_id: contract.current_epoch_id.clone(),
            replacement_epoch_id,
            guardian_set_root,
            encrypted_recovery_bundle_root,
            recovery_nullifier,
            fee_sponsor_id: None,
            status: RecoveryStatus::Requested,
            requested_at_height: height,
            executable_at_height: height.saturating_add(delay_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "current_epoch_id": self.current_epoch_id,
            "encrypted_recovery_bundle_root": self.encrypted_recovery_bundle_root,
            "executable_at_height": self.executable_at_height,
            "fee_sponsor_id": self.fee_sponsor_id,
            "guardian_set_root": self.guardian_set_root,
            "recovery_id": self.recovery_id,
            "recovery_kind": self.recovery_kind,
            "recovery_nullifier": self.recovery_nullifier,
            "replacement_epoch_id": self.replacement_epoch_id,
            "requested_at_height": self.requested_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RotationBatch {
    pub batch_id: String,
    pub coordinator_commitment: String,
    pub bundle_ids: Vec<String>,
    pub recovery_ids: Vec<String>,
    pub aggregate_proof_root: String,
    pub fee_market_root: String,
    pub privacy_set_size: u64,
    pub expected_fee_micro_units: u64,
    pub status: RotationBatchStatus,
    pub opened_at_height: u64,
    pub settled_at_height: Option<u64>,
}

impl RotationBatch {
    pub fn new(
        coordinator_commitment: impl Into<String>,
        bundle_ids: Vec<String>,
        recovery_ids: Vec<String>,
        aggregate_proof_root: impl Into<String>,
        fee_market_root: impl Into<String>,
        privacy_set_size: u64,
        expected_fee_micro_units: u64,
        height: u64,
    ) -> Self {
        let coordinator_commitment = coordinator_commitment.into();
        let aggregate_proof_root = aggregate_proof_root.into();
        let fee_market_root = fee_market_root.into();
        let leaves = bundle_ids
            .iter()
            .chain(recovery_ids.iter())
            .map(|id| Value::String(id.clone()))
            .collect::<Vec<_>>();
        let subject_root = merkle_root("KEY-ROTATION-BATCH-SUBJECTS", &leaves);
        let batch_id = id_from_parts(
            "ROTATION-BATCH-ID",
            &[
                HashPart::Str(&coordinator_commitment),
                HashPart::Str(&subject_root),
                HashPart::Str(&aggregate_proof_root),
                HashPart::Str(&fee_market_root),
                HashPart::U64(height),
            ],
        );
        Self {
            batch_id,
            coordinator_commitment,
            bundle_ids,
            recovery_ids,
            aggregate_proof_root,
            fee_market_root,
            privacy_set_size,
            expected_fee_micro_units,
            status: RotationBatchStatus::Open,
            opened_at_height: height,
            settled_at_height: None,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "aggregate_proof_root": self.aggregate_proof_root,
            "batch_id": self.batch_id,
            "bundle_ids": self.bundle_ids,
            "coordinator_commitment": self.coordinator_commitment,
            "expected_fee_micro_units": self.expected_fee_micro_units,
            "fee_market_root": self.fee_market_root,
            "opened_at_height": self.opened_at_height,
            "privacy_set_size": self.privacy_set_size,
            "recovery_ids": self.recovery_ids,
            "settled_at_height": self.settled_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RotationReceipt {
    pub receipt_id: String,
    pub kind: ReceiptKind,
    pub subject_id: String,
    pub contract_id: String,
    pub epoch_id: Option<String>,
    pub state_root_before: String,
    pub state_root_after: String,
    pub public_payload_root: String,
    pub emitted_at_height: u64,
}

impl RotationReceipt {
    pub fn new(
        kind: ReceiptKind,
        subject_id: impl Into<String>,
        contract_id: impl Into<String>,
        epoch_id: Option<String>,
        state_root_before: impl Into<String>,
        state_root_after: impl Into<String>,
        public_payload: &Value,
        height: u64,
    ) -> Self {
        let subject_id = subject_id.into();
        let contract_id = contract_id.into();
        let state_root_before = state_root_before.into();
        let state_root_after = state_root_after.into();
        let public_payload_root = root_from_record("RECEIPT-PAYLOAD", public_payload);
        let receipt_id = id_from_parts(
            "ROTATION-RECEIPT-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(&subject_id),
                HashPart::Str(&contract_id),
                HashPart::Str(epoch_id.as_deref().unwrap_or("none")),
                HashPart::Str(&state_root_before),
                HashPart::Str(&state_root_after),
                HashPart::Str(&public_payload_root),
                HashPart::U64(height),
            ],
        );
        Self {
            receipt_id,
            kind,
            subject_id,
            contract_id,
            epoch_id,
            state_root_before,
            state_root_after,
            public_payload_root,
            emitted_at_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "emitted_at_height": self.emitted_at_height,
            "epoch_id": self.epoch_id,
            "kind": self.kind,
            "public_payload_root": self.public_payload_root,
            "receipt_id": self.receipt_id,
            "state_root_after": self.state_root_after,
            "state_root_before": self.state_root_before,
            "subject_id": self.subject_id,
        })
    }
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractRegistered => "contract_registered",
            Self::EpochProposed => "epoch_proposed",
            Self::BundleSubmitted => "bundle_submitted",
            Self::ReplayFenceAccepted => "replay_fence_accepted",
            Self::SponsorReserved => "sponsor_reserved",
            Self::BatchSettled => "batch_settled",
            Self::EpochActivated => "epoch_activated",
            Self::EmergencyRecovery => "emergency_recovery",
            Self::EvidenceFiled => "evidence_filed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub kind: SlashingKind,
    pub accused_commitment: String,
    pub contract_id: String,
    pub subject_id: String,
    pub evidence_root: String,
    pub disclosure_nullifier: String,
    pub challenger_commitment: String,
    pub slash_bps: u64,
    pub status: EvidenceStatus,
    pub filed_at_height: u64,
}

impl SlashingEvidence {
    pub fn new(
        kind: SlashingKind,
        accused_commitment: impl Into<String>,
        contract_id: impl Into<String>,
        subject_id: impl Into<String>,
        evidence_root: impl Into<String>,
        challenger_commitment: impl Into<String>,
        slash_bps: u64,
        height: u64,
    ) -> Self {
        let accused_commitment = accused_commitment.into();
        let contract_id = contract_id.into();
        let subject_id = subject_id.into();
        let evidence_root = evidence_root.into();
        let challenger_commitment = challenger_commitment.into();
        let disclosure_nullifier = id_from_parts(
            "SLASHING-DISCLOSURE-NULLIFIER",
            &[
                HashPart::Str(&accused_commitment),
                HashPart::Str(&contract_id),
                HashPart::Str(&subject_id),
                HashPart::Str(&evidence_root),
            ],
        );
        let evidence_id = id_from_parts(
            "SLASHING-EVIDENCE-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(&accused_commitment),
                HashPart::Str(&contract_id),
                HashPart::Str(&subject_id),
                HashPart::Str(&evidence_root),
                HashPart::Str(&disclosure_nullifier),
            ],
        );
        Self {
            evidence_id,
            kind,
            accused_commitment,
            contract_id,
            subject_id,
            evidence_root,
            disclosure_nullifier,
            challenger_commitment,
            slash_bps,
            status: EvidenceStatus::Filed,
            filed_at_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "accused_commitment": self.accused_commitment,
            "challenger_commitment": self.challenger_commitment,
            "contract_id": self.contract_id,
            "disclosure_nullifier": self.disclosure_nullifier,
            "evidence_id": self.evidence_id,
            "evidence_root": self.evidence_root,
            "filed_at_height": self.filed_at_height,
            "kind": self.kind,
            "slash_bps": self.slash_bps,
            "status": self.status,
            "subject_id": self.subject_id,
        })
    }
}

impl SlashingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EpochEquivocation => "epoch_equivocation",
            Self::ReplayFenceReuse => "replay_fence_reuse",
            Self::InvalidMlDsaProof => "invalid_ml_dsa_proof",
            Self::StaleKeyActivation => "stale_key_activation",
            Self::SponsorFraud => "sponsor_fraud",
            Self::RecoveryForgery => "recovery_forgery",
            Self::BundleWithholding => "bundle_withholding",
            Self::PrivacySetDowngrade => "privacy_set_downgrade",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateCounters {
    pub contracts: usize,
    pub key_epochs: usize,
    pub active_epochs: usize,
    pub stealth_signers: usize,
    pub rotation_bundles: usize,
    pub emergency_recoveries: usize,
    pub replay_fences: usize,
    pub sponsor_reservations: usize,
    pub batches: usize,
    pub receipts: usize,
    pub slashing_evidence: usize,
}

impl StateCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "active_epochs": self.active_epochs,
            "batches": self.batches,
            "contracts": self.contracts,
            "emergency_recoveries": self.emergency_recoveries,
            "key_epochs": self.key_epochs,
            "receipts": self.receipts,
            "replay_fences": self.replay_fences,
            "rotation_bundles": self.rotation_bundles,
            "slashing_evidence": self.slashing_evidence,
            "sponsor_reservations": self.sponsor_reservations,
            "stealth_signers": self.stealth_signers,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateRoots {
    pub contract_root: String,
    pub epoch_root: String,
    pub active_epoch_root: String,
    pub stealth_signer_root: String,
    pub bundle_root: String,
    pub recovery_root: String,
    pub replay_fence_root: String,
    pub sponsor_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub slashing_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl StateRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "active_epoch_root": self.active_epoch_root,
            "batch_root": self.batch_root,
            "bundle_root": self.bundle_root,
            "contract_root": self.contract_root,
            "epoch_root": self.epoch_root,
            "public_record_root": self.public_record_root,
            "receipt_root": self.receipt_root,
            "recovery_root": self.recovery_root,
            "replay_fence_root": self.replay_fence_root,
            "slashing_root": self.slashing_root,
            "sponsor_root": self.sponsor_root,
            "state_root": self.state_root,
            "stealth_signer_root": self.stealth_signer_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub contracts: BTreeMap<String, PrivateContract>,
    pub key_epochs: BTreeMap<String, KeyEpoch>,
    pub active_epoch_by_contract: BTreeMap<String, String>,
    pub stealth_signers: BTreeMap<String, StealthSignerCommitment>,
    pub rotation_bundles: BTreeMap<String, EncryptedRotationBundle>,
    pub emergency_recoveries: BTreeMap<String, EmergencyRecoveryRequest>,
    pub replay_fences: BTreeMap<String, ReplayFence>,
    pub used_nullifiers: BTreeSet<String>,
    pub sponsor_reservations: BTreeMap<String, FeeSponsorReservation>,
    pub batches: BTreeMap<String, RotationBatch>,
    pub receipts: BTreeMap<String, RotationReceipt>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::empty(Config::devnet());
        let contract = PrivateContract::new(
            ContractClass::SmartAccount,
            seed("devnet-owner-commitment"),
            seed("devnet-policy-root"),
            seed("devnet-l2-address-commitment"),
            DEVNET_HEIGHT,
        );
        let contract_id = contract.contract_id.clone();
        state.contracts.insert(contract_id.clone(), contract);
        let epoch = {
            let contract = state.contracts.get(&contract_id).expect("devnet contract");
            KeyEpoch::proposed(
                contract,
                KeyAlgorithm::MlDsa87,
                seed("devnet-verification-key-commitment"),
                seed("devnet-verification-key-root"),
                seed("devnet-stealth-signer-root"),
                DEVNET_HEIGHT,
                DEFAULT_EPOCH_TTL_BLOCKS,
            )
        };
        let epoch_id = epoch.epoch_id.clone();
        state.key_epochs.insert(epoch_id.clone(), epoch);
        state
            .active_epoch_by_contract
            .insert(contract_id.clone(), epoch_id.clone());
        if let Some(contract) = state.contracts.get_mut(&contract_id) {
            *contract = contract.clone().activate(epoch_id.clone(), DEVNET_HEIGHT);
        }
        if let Some(epoch) = state.key_epochs.get_mut(&epoch_id) {
            epoch.status = EpochStatus::Active;
            epoch.activated_at_height = Some(DEVNET_HEIGHT);
        }
        let signer = StealthSignerCommitment::new(
            contract_id,
            epoch_id,
            "devnet-stealth-signer-0",
            seed("devnet-one-time-address"),
            "subaddr-hint:devnet:0",
            seed("devnet-signer-pq-proof"),
            DEFAULT_MIN_PRIVACY_SET_SIZE,
            DEVNET_HEIGHT,
        );
        state
            .stealth_signers
            .insert(signer.signer_commitment_id.clone(), signer);
        state
    }

    pub fn empty(config: Config) -> Self {
        Self {
            config,
            contracts: BTreeMap::new(),
            key_epochs: BTreeMap::new(),
            active_epoch_by_contract: BTreeMap::new(),
            stealth_signers: BTreeMap::new(),
            rotation_bundles: BTreeMap::new(),
            emergency_recoveries: BTreeMap::new(),
            replay_fences: BTreeMap::new(),
            used_nullifiers: BTreeSet::new(),
            sponsor_reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
        }
    }

    pub fn register_contract(
        &mut self,
        class: ContractClass,
        owner_commitment: impl Into<String>,
        policy_root: impl Into<String>,
        l2_address_commitment: impl Into<String>,
        height: u64,
    ) -> Result<PrivateContract> {
        ensure_capacity(self.contracts.len(), MAX_CONTRACTS, "contracts")?;
        let before = self.state_root();
        let contract = PrivateContract::new(
            class,
            owner_commitment,
            policy_root,
            l2_address_commitment,
            height,
        );
        if self.contracts.contains_key(&contract.contract_id) {
            return Err(format!(
                "contract already registered: {}",
                contract.contract_id
            ));
        }
        self.contracts
            .insert(contract.contract_id.clone(), contract.clone());
        let after = self.state_root();
        self.emit_receipt(
            ReceiptKind::ContractRegistered,
            contract.contract_id.clone(),
            contract.contract_id.clone(),
            None,
            before,
            after,
            contract.public_record(),
            height,
        )?;
        Ok(contract)
    }

    pub fn propose_key_epoch(
        &mut self,
        contract_id: &str,
        signing_algorithm: KeyAlgorithm,
        verification_key_commitment: impl Into<String>,
        verification_key_root: impl Into<String>,
        stealth_signer_set_root: impl Into<String>,
        height: u64,
    ) -> Result<KeyEpoch> {
        ensure_capacity(self.key_epochs.len(), MAX_KEY_EPOCHS, "key epochs")?;
        if signing_algorithm.pq_security_bits() < self.config.min_pq_security_bits {
            return Err("key algorithm does not meet configured PQ security floor".to_string());
        }
        let contract = self
            .contracts
            .get(contract_id)
            .ok_or_else(|| format!("unknown contract: {contract_id}"))?;
        if !contract.status.accepts_rotation() {
            return Err(format!("contract does not accept rotation: {contract_id}"));
        }
        let before = self.state_root();
        let epoch = KeyEpoch::proposed(
            contract,
            signing_algorithm,
            verification_key_commitment,
            verification_key_root,
            stealth_signer_set_root,
            height,
            self.config.epoch_ttl_blocks,
        );
        if self.used_nullifiers.contains(&epoch.activation_nullifier) {
            return Err("activation nullifier already used".to_string());
        }
        self.used_nullifiers
            .insert(epoch.activation_nullifier.clone());
        self.key_epochs
            .insert(epoch.epoch_id.clone(), epoch.clone());
        if let Some(contract) = self.contracts.get_mut(contract_id) {
            contract.status = ContractStatus::Rotating;
            contract.updated_at_height = height;
        }
        let after = self.state_root();
        self.emit_receipt(
            ReceiptKind::EpochProposed,
            epoch.epoch_id.clone(),
            epoch.contract_id.clone(),
            Some(epoch.epoch_id.clone()),
            before,
            after,
            epoch.public_record(),
            height,
        )?;
        Ok(epoch)
    }

    pub fn register_stealth_signer(
        &mut self,
        contract_id: &str,
        epoch_id: &str,
        signer_tag: impl Into<String>,
        one_time_address_commitment: impl Into<String>,
        monero_subaddress_hint: impl Into<String>,
        pq_proof_root: impl Into<String>,
        privacy_set_size: u64,
        height: u64,
    ) -> Result<StealthSignerCommitment> {
        ensure_capacity(
            self.stealth_signers.len(),
            MAX_STEALTH_SIGNERS,
            "stealth signers",
        )?;
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("stealth signer privacy set below configured minimum".to_string());
        }
        require_contract_epoch(self, contract_id, epoch_id)?;
        let signer = StealthSignerCommitment::new(
            contract_id,
            epoch_id,
            signer_tag,
            one_time_address_commitment,
            monero_subaddress_hint,
            pq_proof_root,
            privacy_set_size,
            height,
        );
        self.stealth_signers
            .insert(signer.signer_commitment_id.clone(), signer.clone());
        Ok(signer)
    }

    pub fn submit_rotation_bundle(
        &mut self,
        epoch_id: &str,
        ciphertext_root: impl Into<String>,
        kem_recipient_root: impl Into<String>,
        encrypted_delta_root: impl Into<String>,
        pq_authorization_root: impl Into<String>,
        max_fee_micro_units: u64,
        privacy_set_size: u64,
        height: u64,
    ) -> Result<EncryptedRotationBundle> {
        ensure_capacity(
            self.rotation_bundles.len(),
            MAX_ROTATION_BUNDLES,
            "rotation bundles",
        )?;
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("rotation bundle privacy set below configured minimum".to_string());
        }
        let epoch = self
            .key_epochs
            .get(epoch_id)
            .ok_or_else(|| format!("unknown epoch: {epoch_id}"))?;
        if !matches!(
            epoch.status,
            EpochStatus::Proposed | EpochStatus::SponsorReserved
        ) {
            return Err(format!("epoch is not accepting bundles: {epoch_id}"));
        }
        let before = self.state_root();
        let bundle = EncryptedRotationBundle::new(
            epoch,
            ciphertext_root,
            kem_recipient_root,
            encrypted_delta_root,
            pq_authorization_root,
            max_fee_micro_units,
            privacy_set_size,
            height,
            self.config.rotation_ttl_blocks,
        );
        if self.used_nullifiers.contains(&bundle.replay_nullifier) {
            return Err("rotation replay nullifier already used".to_string());
        }
        self.rotation_bundles
            .insert(bundle.bundle_id.clone(), bundle.clone());
        if let Some(epoch) = self.key_epochs.get_mut(epoch_id) {
            epoch.status = EpochStatus::BundleSealed;
        }
        let after = self.state_root();
        self.emit_receipt(
            ReceiptKind::BundleSubmitted,
            bundle.bundle_id.clone(),
            bundle.contract_id.clone(),
            Some(bundle.target_epoch_id.clone()),
            before,
            after,
            bundle.public_record(),
            height,
        )?;
        Ok(bundle)
    }

    pub fn accept_replay_fence(&mut self, bundle_id: &str, height: u64) -> Result<ReplayFence> {
        ensure_capacity(self.replay_fences.len(), MAX_REPLAY_FENCES, "replay fences")?;
        let before = self.state_root();
        let bundle = self
            .rotation_bundles
            .get(bundle_id)
            .ok_or_else(|| format!("unknown bundle: {bundle_id}"))?
            .clone();
        if self.used_nullifiers.contains(&bundle.replay_nullifier) {
            return Err("replay nullifier already fenced".to_string());
        }
        self.used_nullifiers.insert(bundle.replay_nullifier.clone());
        let fence = ReplayFence::new(&bundle, height);
        self.replay_fences
            .insert(fence.fence_id.clone(), fence.clone());
        if let Some(bundle) = self.rotation_bundles.get_mut(bundle_id) {
            bundle.status = BundleStatus::ReplayFenced;
        }
        let after = self.state_root();
        self.emit_receipt(
            ReceiptKind::ReplayFenceAccepted,
            fence.fence_id.clone(),
            fence.contract_id.clone(),
            Some(fence.epoch_id.clone()),
            before,
            after,
            fence.public_record(),
            height,
        )?;
        Ok(fence)
    }

    pub fn reserve_fee_sponsor(
        &mut self,
        sponsor_commitment: impl Into<String>,
        subject_id: &str,
        contract_id: &str,
        reserved_micro_units: u64,
        coverage_bps: u64,
        privacy_pool_root: impl Into<String>,
        height: u64,
    ) -> Result<FeeSponsorReservation> {
        ensure_capacity(
            self.sponsor_reservations.len(),
            MAX_SPONSOR_RESERVATIONS,
            "sponsor reservations",
        )?;
        if coverage_bps > MAX_BPS {
            return Err("coverage bps exceeds maximum".to_string());
        }
        if coverage_bps < self.config.sponsor_coverage_bps {
            return Err("coverage bps below configured sponsor floor".to_string());
        }
        let before = self.state_root();
        let reservation = FeeSponsorReservation::new(
            sponsor_commitment,
            subject_id,
            contract_id,
            reserved_micro_units,
            coverage_bps,
            privacy_pool_root,
            height,
            self.config.sponsor_ttl_blocks,
        );
        self.sponsor_reservations
            .insert(reservation.reservation_id.clone(), reservation.clone());
        if let Some(bundle) = self.rotation_bundles.get_mut(subject_id) {
            bundle.fee_sponsor_id = Some(reservation.reservation_id.clone());
            bundle.status = BundleStatus::SponsorMatched;
        }
        if let Some(recovery) = self.emergency_recoveries.get_mut(subject_id) {
            recovery.fee_sponsor_id = Some(reservation.reservation_id.clone());
            recovery.status = RecoveryStatus::SponsorReserved;
        }
        if let Some(epoch) = self.key_epochs.get_mut(subject_id) {
            epoch.status = EpochStatus::SponsorReserved;
        }
        let after = self.state_root();
        self.emit_receipt(
            ReceiptKind::SponsorReserved,
            reservation.reservation_id.clone(),
            reservation.contract_id.clone(),
            None,
            before,
            after,
            reservation.public_record(),
            height,
        )?;
        Ok(reservation)
    }

    pub fn request_emergency_recovery(
        &mut self,
        contract_id: &str,
        recovery_kind: RecoveryKind,
        replacement_epoch_id: impl Into<String>,
        guardian_set_root: impl Into<String>,
        encrypted_recovery_bundle_root: impl Into<String>,
        height: u64,
    ) -> Result<EmergencyRecoveryRequest> {
        ensure_capacity(
            self.emergency_recoveries.len(),
            MAX_RECOVERY_REQUESTS,
            "emergency recoveries",
        )?;
        let contract = self
            .contracts
            .get(contract_id)
            .ok_or_else(|| format!("unknown contract: {contract_id}"))?;
        let before = self.state_root();
        let recovery = EmergencyRecoveryRequest::new(
            contract,
            recovery_kind,
            replacement_epoch_id,
            guardian_set_root,
            encrypted_recovery_bundle_root,
            height,
            self.config.recovery_delay_blocks,
        );
        if self.used_nullifiers.contains(&recovery.recovery_nullifier) {
            return Err("recovery nullifier already used".to_string());
        }
        self.used_nullifiers
            .insert(recovery.recovery_nullifier.clone());
        self.emergency_recoveries
            .insert(recovery.recovery_id.clone(), recovery.clone());
        if let Some(contract) = self.contracts.get_mut(contract_id) {
            contract.status = ContractStatus::RecoveryOnly;
            contract.updated_at_height = height;
        }
        let after = self.state_root();
        self.emit_receipt(
            ReceiptKind::EmergencyRecovery,
            recovery.recovery_id.clone(),
            recovery.contract_id.clone(),
            Some(recovery.replacement_epoch_id.clone()),
            before,
            after,
            recovery.public_record(),
            height,
        )?;
        Ok(recovery)
    }

    pub fn open_low_fee_batch(
        &mut self,
        coordinator_commitment: impl Into<String>,
        bundle_ids: Vec<String>,
        recovery_ids: Vec<String>,
        aggregate_proof_root: impl Into<String>,
        fee_market_root: impl Into<String>,
        privacy_set_size: u64,
        expected_fee_micro_units: u64,
        height: u64,
    ) -> Result<RotationBatch> {
        ensure_capacity(self.batches.len(), MAX_BATCHES, "rotation batches")?;
        let item_count = bundle_ids.len().saturating_add(recovery_ids.len());
        if item_count == 0 {
            return Err("batch must contain at least one subject".to_string());
        }
        if item_count > self.config.low_fee_batch_limit {
            return Err("batch exceeds configured low-fee limit".to_string());
        }
        if privacy_set_size < self.config.batch_privacy_set_size {
            return Err("batch privacy set below configured minimum".to_string());
        }
        for bundle_id in &bundle_ids {
            let bundle = self
                .rotation_bundles
                .get(bundle_id)
                .ok_or_else(|| format!("unknown bundle in batch: {bundle_id}"))?;
            if !bundle.status.batchable() {
                return Err(format!("bundle is not batchable: {bundle_id}"));
            }
        }
        for recovery_id in &recovery_ids {
            let recovery = self
                .emergency_recoveries
                .get(recovery_id)
                .ok_or_else(|| format!("unknown recovery in batch: {recovery_id}"))?;
            if !recovery.status.live() {
                return Err(format!("recovery is not batchable: {recovery_id}"));
            }
        }
        let batch = RotationBatch::new(
            coordinator_commitment,
            bundle_ids,
            recovery_ids,
            aggregate_proof_root,
            fee_market_root,
            privacy_set_size,
            expected_fee_micro_units,
            height,
        );
        for bundle_id in &batch.bundle_ids {
            if let Some(bundle) = self.rotation_bundles.get_mut(bundle_id) {
                bundle.status = BundleStatus::BatchQueued;
            }
        }
        for recovery_id in &batch.recovery_ids {
            if let Some(recovery) = self.emergency_recoveries.get_mut(recovery_id) {
                recovery.status = RecoveryStatus::GuardianAttested;
            }
        }
        self.batches.insert(batch.batch_id.clone(), batch.clone());
        Ok(batch)
    }

    pub fn settle_batch(&mut self, batch_id: &str, height: u64) -> Result<RotationBatch> {
        let before = self.state_root();
        let batch = self
            .batches
            .get(batch_id)
            .ok_or_else(|| format!("unknown batch: {batch_id}"))?
            .clone();
        if !matches!(
            batch.status,
            RotationBatchStatus::Open | RotationBatchStatus::Sealed
        ) {
            return Err(format!("batch is not settleable: {batch_id}"));
        }
        for bundle_id in &batch.bundle_ids {
            self.activate_bundle(bundle_id, height)?;
        }
        for recovery_id in &batch.recovery_ids {
            self.execute_recovery(recovery_id, height)?;
        }
        if let Some(stored) = self.batches.get_mut(batch_id) {
            stored.status = RotationBatchStatus::Settled;
            stored.settled_at_height = Some(height);
        }
        let settled = self.batches.get(batch_id).expect("settled batch").clone();
        let after = self.state_root();
        self.emit_receipt(
            ReceiptKind::BatchSettled,
            batch_id.to_string(),
            "batch".to_string(),
            None,
            before,
            after,
            settled.public_record(),
            height,
        )?;
        Ok(settled)
    }

    pub fn activate_bundle(&mut self, bundle_id: &str, height: u64) -> Result<KeyEpoch> {
        let before = self.state_root();
        let bundle = self
            .rotation_bundles
            .get(bundle_id)
            .ok_or_else(|| format!("unknown bundle: {bundle_id}"))?
            .clone();
        let epoch = self
            .key_epochs
            .get(&bundle.target_epoch_id)
            .ok_or_else(|| format!("unknown epoch: {}", bundle.target_epoch_id))?
            .clone();
        if height > epoch.expiry_height {
            return Err("key epoch proposal expired".to_string());
        }
        self.supersede_active_epoch(&epoch.contract_id, height);
        if let Some(epoch_mut) = self.key_epochs.get_mut(&epoch.epoch_id) {
            epoch_mut.status = EpochStatus::Active;
            epoch_mut.activated_at_height = Some(height);
        }
        if let Some(bundle_mut) = self.rotation_bundles.get_mut(bundle_id) {
            bundle_mut.status = BundleStatus::Settled;
        }
        if let Some(contract) = self.contracts.get_mut(&epoch.contract_id) {
            contract.current_epoch_id = epoch.epoch_id.clone();
            contract.current_epoch_number = epoch.epoch_number;
            contract.status = ContractStatus::Active;
            contract.updated_at_height = height;
        }
        self.active_epoch_by_contract
            .insert(epoch.contract_id.clone(), epoch.epoch_id.clone());
        let activated = self
            .key_epochs
            .get(&epoch.epoch_id)
            .expect("activated")
            .clone();
        let after = self.state_root();
        self.emit_receipt(
            ReceiptKind::EpochActivated,
            bundle_id.to_string(),
            activated.contract_id.clone(),
            Some(activated.epoch_id.clone()),
            before,
            after,
            activated.public_record(),
            height,
        )?;
        Ok(activated)
    }

    pub fn execute_recovery(&mut self, recovery_id: &str, height: u64) -> Result<PrivateContract> {
        let before = self.state_root();
        let recovery = self
            .emergency_recoveries
            .get(recovery_id)
            .ok_or_else(|| format!("unknown recovery: {recovery_id}"))?
            .clone();
        if height < recovery.executable_at_height {
            return Err("recovery delay window is still active".to_string());
        }
        if !recovery.status.live() {
            return Err(format!("recovery is not executable: {recovery_id}"));
        }
        self.supersede_active_epoch(&recovery.contract_id, height);
        if let Some(epoch) = self.key_epochs.get_mut(&recovery.replacement_epoch_id) {
            epoch.status = EpochStatus::EmergencyRecovered;
            epoch.activated_at_height = Some(height);
        }
        if let Some(contract) = self.contracts.get_mut(&recovery.contract_id) {
            contract.current_epoch_id = recovery.replacement_epoch_id.clone();
            contract.current_epoch_number = contract.current_epoch_number.saturating_add(1);
            contract.status = ContractStatus::Active;
            contract.updated_at_height = height;
        }
        if let Some(recovery) = self.emergency_recoveries.get_mut(recovery_id) {
            recovery.status = RecoveryStatus::Executed;
        }
        self.active_epoch_by_contract.insert(
            recovery.contract_id.clone(),
            recovery.replacement_epoch_id.clone(),
        );
        let contract = self
            .contracts
            .get(&recovery.contract_id)
            .expect("recovered contract")
            .clone();
        let after = self.state_root();
        self.emit_receipt(
            ReceiptKind::EmergencyRecovery,
            recovery_id.to_string(),
            contract.contract_id.clone(),
            Some(contract.current_epoch_id.clone()),
            before,
            after,
            contract.public_record(),
            height,
        )?;
        Ok(contract)
    }

    pub fn file_slashing_evidence(
        &mut self,
        kind: SlashingKind,
        accused_commitment: impl Into<String>,
        contract_id: impl Into<String>,
        subject_id: impl Into<String>,
        evidence_root: impl Into<String>,
        challenger_commitment: impl Into<String>,
        slash_bps: u64,
        height: u64,
    ) -> Result<SlashingEvidence> {
        ensure_capacity(
            self.slashing_evidence.len(),
            MAX_SLASHING_EVIDENCE,
            "slashing evidence",
        )?;
        if slash_bps > MAX_BPS {
            return Err("slash bps exceeds maximum".to_string());
        }
        let before = self.state_root();
        let evidence = SlashingEvidence::new(
            kind,
            accused_commitment,
            contract_id,
            subject_id,
            evidence_root,
            challenger_commitment,
            slash_bps,
            height,
        );
        if self
            .used_nullifiers
            .contains(&evidence.disclosure_nullifier)
        {
            return Err("slashing disclosure nullifier already used".to_string());
        }
        self.used_nullifiers
            .insert(evidence.disclosure_nullifier.clone());
        self.slashing_evidence
            .insert(evidence.evidence_id.clone(), evidence.clone());
        let after = self.state_root();
        self.emit_receipt(
            ReceiptKind::EvidenceFiled,
            evidence.evidence_id.clone(),
            evidence.contract_id.clone(),
            None,
            before,
            after,
            evidence.public_record(),
            height,
        )?;
        Ok(evidence)
    }

    pub fn counters(&self) -> StateCounters {
        StateCounters {
            contracts: self.contracts.len(),
            key_epochs: self.key_epochs.len(),
            active_epochs: self.active_epoch_by_contract.len(),
            stealth_signers: self.stealth_signers.len(),
            rotation_bundles: self.rotation_bundles.len(),
            emergency_recoveries: self.emergency_recoveries.len(),
            replay_fences: self.replay_fences.len(),
            sponsor_reservations: self.sponsor_reservations.len(),
            batches: self.batches.len(),
            receipts: self.receipts.len(),
            slashing_evidence: self.slashing_evidence.len(),
        }
    }

    pub fn roots(&self) -> StateRoots {
        let contract_root = map_root(
            "CONTRACTS",
            self.contracts.values().map(PrivateContract::public_record),
        );
        let epoch_root = map_root(
            "KEY-EPOCHS",
            self.key_epochs.values().map(KeyEpoch::public_record),
        );
        let active_epoch_root = map_root(
            "ACTIVE-EPOCHS",
            self.active_epoch_by_contract
                .iter()
                .map(|(contract_id, epoch_id)| json!({ "contract_id": contract_id, "epoch_id": epoch_id })),
        );
        let stealth_signer_root = map_root(
            "STEALTH-SIGNERS",
            self.stealth_signers
                .values()
                .map(StealthSignerCommitment::public_record),
        );
        let bundle_root = map_root(
            "ROTATION-BUNDLES",
            self.rotation_bundles
                .values()
                .map(EncryptedRotationBundle::public_record),
        );
        let recovery_root = map_root(
            "EMERGENCY-RECOVERIES",
            self.emergency_recoveries
                .values()
                .map(EmergencyRecoveryRequest::public_record),
        );
        let replay_fence_root = map_root(
            "REPLAY-FENCES",
            self.replay_fences.values().map(ReplayFence::public_record),
        );
        let sponsor_root = map_root(
            "SPONSOR-RESERVATIONS",
            self.sponsor_reservations
                .values()
                .map(FeeSponsorReservation::public_record),
        );
        let batch_root = map_root(
            "BATCHES",
            self.batches.values().map(RotationBatch::public_record),
        );
        let receipt_root = map_root(
            "RECEIPTS",
            self.receipts.values().map(RotationReceipt::public_record),
        );
        let slashing_root = map_root(
            "SLASHING-EVIDENCE",
            self.slashing_evidence
                .values()
                .map(SlashingEvidence::public_record),
        );
        let public_record = json!({
            "active_epoch_root": active_epoch_root,
            "batch_root": batch_root,
            "bundle_root": bundle_root,
            "config_root": self.config.root(),
            "contract_root": contract_root,
            "counters": self.counters().public_record(),
            "epoch_root": epoch_root,
            "protocol_version": PROTOCOL_VERSION,
            "receipt_root": receipt_root,
            "recovery_root": recovery_root,
            "replay_fence_root": replay_fence_root,
            "slashing_root": slashing_root,
            "sponsor_root": sponsor_root,
            "stealth_signer_root": stealth_signer_root,
        });
        let public_record_root = root_from_record("PUBLIC-RECORD", &public_record);
        let state_root = domain_hash(
            "PRIVATE-L2-PQ-PRIVATE-CONTRACT-KEY-ROTATION-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&public_record_root),
                HashPart::Str(&self.config.root()),
            ],
            32,
        );
        StateRoots {
            contract_root: public_record["contract_root"].as_str().unwrap().to_string(),
            epoch_root: public_record["epoch_root"].as_str().unwrap().to_string(),
            active_epoch_root: public_record["active_epoch_root"]
                .as_str()
                .unwrap()
                .to_string(),
            stealth_signer_root: public_record["stealth_signer_root"]
                .as_str()
                .unwrap()
                .to_string(),
            bundle_root: public_record["bundle_root"].as_str().unwrap().to_string(),
            recovery_root: public_record["recovery_root"].as_str().unwrap().to_string(),
            replay_fence_root: public_record["replay_fence_root"]
                .as_str()
                .unwrap()
                .to_string(),
            sponsor_root: public_record["sponsor_root"].as_str().unwrap().to_string(),
            batch_root: public_record["batch_root"].as_str().unwrap().to_string(),
            receipt_root: public_record["receipt_root"].as_str().unwrap().to_string(),
            slashing_root: public_record["slashing_root"].as_str().unwrap().to_string(),
            public_record_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "protocol_version": PROTOCOL_VERSION,
            "roots": self.roots().public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn supersede_active_epoch(&mut self, contract_id: &str, height: u64) {
        if let Some(epoch_id) = self.active_epoch_by_contract.get(contract_id).cloned() {
            if let Some(epoch) = self.key_epochs.get_mut(&epoch_id) {
                if epoch.status == EpochStatus::Active {
                    epoch.status = EpochStatus::Superseded;
                    epoch.activated_at_height.get_or_insert(height);
                }
            }
        }
    }

    fn emit_receipt(
        &mut self,
        kind: ReceiptKind,
        subject_id: String,
        contract_id: String,
        epoch_id: Option<String>,
        state_root_before: String,
        state_root_after: String,
        public_payload: Value,
        height: u64,
    ) -> Result<RotationReceipt> {
        ensure_capacity(self.receipts.len(), MAX_RECEIPTS, "receipts")?;
        let receipt = RotationReceipt::new(
            kind,
            subject_id,
            contract_id,
            epoch_id,
            state_root_before,
            state_root_after,
            &public_payload,
            height,
        );
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONTRACT-KEY-ROTATION-{domain}"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn id_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    let mut all_parts = Vec::with_capacity(parts.len() + 1);
    all_parts.push(HashPart::Str(PROTOCOL_VERSION));
    all_parts.extend(parts.iter().map(clone_hash_part));
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONTRACT-KEY-ROTATION-{domain}"),
        &all_parts,
        32,
    )
}

fn clone_hash_part<'a>(part: &HashPart<'a>) -> HashPart<'a> {
    match part {
        HashPart::Bytes(value) => HashPart::Bytes(value),
        HashPart::Str(value) => HashPart::Str(value),
        HashPart::U64(value) => HashPart::U64(*value),
        HashPart::Int(value) => HashPart::Int(*value),
        HashPart::Json(value) => HashPart::Json(value),
    }
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let records = records.into_iter().collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-PQ-CONTRACT-KEY-ROTATION-{domain}"),
        &records,
    )
}

fn seed(label: &str) -> String {
    id_from_parts("DEVNET-SEED", &[HashPart::Str(label)])
}

fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exhausted"))
    } else {
        Ok(())
    }
}

fn require_contract_epoch(state: &State, contract_id: &str, epoch_id: &str) -> Result<()> {
    state
        .contracts
        .get(contract_id)
        .ok_or_else(|| format!("unknown contract: {contract_id}"))?;
    let epoch = state
        .key_epochs
        .get(epoch_id)
        .ok_or_else(|| format!("unknown epoch: {epoch_id}"))?;
    if epoch.contract_id != contract_id {
        return Err(format!(
            "epoch {epoch_id} is not owned by contract {contract_id}"
        ));
    }
    Ok(())
}
