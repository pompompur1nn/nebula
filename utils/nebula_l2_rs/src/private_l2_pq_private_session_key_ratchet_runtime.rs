use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqPrivateSessionKeyRatchetRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_PRIVATE_SESSION_KEY_RATCHET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-private-session-key-ratchet-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_PRIVATE_SESSION_KEY_RATCHET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_KEM_SUITE: &str = "ML-KEM-1024+hybrid-x25519-session-envelope-v1";
pub const PQ_SIGNATURE_SUITE: &str =
    "ML-DSA-87+Falcon-1024-ready+SLH-DSA-SHAKE-256f-session-auth-v1";
pub const STEALTH_SESSION_PROOF_SCHEME: &str = "monero-l2-stealth-private-session-proof-root-v1";
pub const NULLIFIER_FENCE_SCHEME: &str = "private-session-ratchet-nullifier-fence-v1";
pub const FAST_AUTH_BUNDLE_SCHEME: &str = "pq-private-session-fast-authorization-bundle-v1";
pub const FEE_SPONSOR_RESERVATION_SCHEME: &str =
    "low-fee-private-session-key-ratchet-sponsor-reservation-v1";
pub const SETTLEMENT_RECEIPT_SCHEME: &str = "private-session-ratchet-settlement-receipt-root-v1";
pub const REBATE_SCHEME: &str = "low-fee-private-session-key-ratchet-rebate-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "pq-private-session-key-ratchet-slashing-evidence-v1";
pub const DEVNET_HEIGHT: u64 = 836_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_EPOCH_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_SESSION_TTL_BLOCKS: u64 = 360;
pub const DEFAULT_RATCHET_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 128;
pub const DEFAULT_MAX_AUTH_FEE_BPS: u64 = 10;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const DEFAULT_SPONSOR_COVERAGE_BPS: u64 = 9_300;
pub const DEFAULT_FAST_AUTH_BATCH_TARGET: usize = 512;
pub const DEFAULT_FAST_AUTH_BATCH_LIMIT: usize = 8_192;
pub const MAX_ACCOUNTS: usize = 1_048_576;
pub const MAX_KEY_EPOCHS: usize = 4_194_304;
pub const MAX_SESSION_PROOFS: usize = 8_388_608;
pub const MAX_NULLIFIER_FENCES: usize = 16_777_216;
pub const MAX_AUTH_BUNDLES: usize = 8_388_608;
pub const MAX_SPONSOR_RESERVATIONS: usize = 4_194_304;
pub const MAX_SETTLEMENT_RECEIPTS: usize = 8_388_608;
pub const MAX_REBATES: usize = 4_194_304;
pub const MAX_SLASHING_EVIDENCE: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountClass {
    PrivateSmartAccount,
    TradingSessionAccount,
    VaultSessionAccount,
    ContractWallet,
    TokenController,
    GovernanceDelegate,
    BridgeOperator,
    Custom,
}

impl AccountClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateSmartAccount => "private_smart_account",
            Self::TradingSessionAccount => "trading_session_account",
            Self::VaultSessionAccount => "vault_session_account",
            Self::ContractWallet => "contract_wallet",
            Self::TokenController => "token_controller",
            Self::GovernanceDelegate => "governance_delegate",
            Self::BridgeOperator => "bridge_operator",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    Registered,
    Active,
    Ratcheting,
    SponsorOnly,
    Frozen,
    Retired,
    Slashed,
}

impl AccountStatus {
    pub fn accepts_sessions(self) -> bool {
        matches!(self, Self::Active | Self::Ratcheting | Self::SponsorOnly)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::Ratcheting => "ratcheting",
            Self::SponsorOnly => "sponsor_only",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KemAlgorithm {
    MlKem768,
    MlKem1024,
    HybridX25519MlKem1024,
    HybridSecp256k1MlKem1024,
}

impl KemAlgorithm {
    pub fn pq_security_bits(self) -> u16 {
        match self {
            Self::MlKem768 => 192,
            Self::MlKem1024 => 256,
            Self::HybridX25519MlKem1024 => 256,
            Self::HybridSecp256k1MlKem1024 => 256,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlKem768 => "ml_kem_768",
            Self::MlKem1024 => "ml_kem_1024",
            Self::HybridX25519MlKem1024 => "hybrid_x25519_ml_kem_1024",
            Self::HybridSecp256k1MlKem1024 => "hybrid_secp256k1_ml_kem_1024",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    MlDsa65,
    MlDsa87,
    Falcon512Ready,
    Falcon1024Ready,
    SlhDsaShake256f,
    HybridEd25519MlDsa87,
}

impl SignatureAlgorithm {
    pub fn pq_security_bits(self) -> u16 {
        match self {
            Self::MlDsa65 => 192,
            Self::MlDsa87 => 256,
            Self::Falcon512Ready => 128,
            Self::Falcon1024Ready => 256,
            Self::SlhDsaShake256f => 256,
            Self::HybridEd25519MlDsa87 => 256,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ml_dsa_65",
            Self::MlDsa87 => "ml_dsa_87",
            Self::Falcon512Ready => "falcon_512_ready",
            Self::Falcon1024Ready => "falcon_1024_ready",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
            Self::HybridEd25519MlDsa87 => "hybrid_ed25519_ml_dsa_87",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochStatus {
    Proposed,
    SponsorReserved,
    ProofBound,
    Active,
    Superseded,
    Revoked,
    Expired,
    Slashed,
}

impl EpochStatus {
    pub fn accepts_proofs(self) -> bool {
        matches!(
            self,
            Self::SponsorReserved | Self::ProofBound | Self::Active
        )
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::SponsorReserved | Self::ProofBound | Self::Active | Self::Proposed
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::SponsorReserved => "sponsor_reserved",
            Self::ProofBound => "proof_bound",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionProofStatus {
    Submitted,
    ReplayFenced,
    SponsorMatched,
    Authorized,
    Settled,
    Revoked,
    Expired,
    Slashed,
}

impl SessionProofStatus {
    pub fn authorizable(self) -> bool {
        matches!(
            self,
            Self::ReplayFenced | Self::SponsorMatched | Self::Authorized
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::ReplayFenced => "replay_fenced",
            Self::SponsorMatched => "sponsor_matched",
            Self::Authorized => "authorized",
            Self::Settled => "settled",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthBundleKind {
    ContractCall,
    TokenTransfer,
    DefiSwap,
    LendingAction,
    GovernanceVote,
    BridgeExit,
    BatchPermit,
    Custom,
}

impl AuthBundleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractCall => "contract_call",
            Self::TokenTransfer => "token_transfer",
            Self::DefiSwap => "defi_swap",
            Self::LendingAction => "lending_action",
            Self::GovernanceVote => "governance_vote",
            Self::BridgeExit => "bridge_exit",
            Self::BatchPermit => "batch_permit",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthBundleStatus {
    Prepared,
    ReplayFenced,
    SponsorReserved,
    Authorized,
    Settled,
    Reverted,
    Cancelled,
    Expired,
    Slashed,
}

impl AuthBundleStatus {
    pub fn can_settle(self) -> bool {
        matches!(self, Self::Authorized | Self::SponsorReserved)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::ReplayFenced => "replay_fenced",
            Self::SponsorReserved => "sponsor_reserved",
            Self::Authorized => "authorized",
            Self::Settled => "settled",
            Self::Reverted => "reverted",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Consumed,
    RebateQueued,
    Refunded,
    Expired,
    Slashed,
}

impl SponsorReservationStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Reserved)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::RebateQueued => "rebate_queued",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    EpochActivated,
    SessionAuthorized,
    BundleSettled,
    BundleReverted,
    SponsorConsumed,
    RebatePaid,
    EpochRevoked,
    SlashApplied,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EpochActivated => "epoch_activated",
            Self::SessionAuthorized => "session_authorized",
            Self::BundleSettled => "bundle_settled",
            Self::BundleReverted => "bundle_reverted",
            Self::SponsorConsumed => "sponsor_consumed",
            Self::RebatePaid => "rebate_paid",
            Self::EpochRevoked => "epoch_revoked",
            Self::SlashApplied => "slash_applied",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Paid,
    Expired,
    Slashed,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Paid => "paid",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    ReplayNullifier,
    DoubleRatchet,
    InvalidStealthProof,
    SponsorOverclaim,
    ReceiptMismatch,
    ExpiredAuthorization,
    PrivacySetRegression,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReplayNullifier => "replay_nullifier",
            Self::DoubleRatchet => "double_ratchet",
            Self::InvalidStealthProof => "invalid_stealth_proof",
            Self::SponsorOverclaim => "sponsor_overclaim",
            Self::ReceiptMismatch => "receipt_mismatch",
            Self::ExpiredAuthorization => "expired_authorization",
            Self::PrivacySetRegression => "privacy_set_regression",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub devnet_height: u64,
    pub hash_suite: String,
    pub pq_kem_suite: String,
    pub pq_signature_suite: String,
    pub stealth_session_proof_scheme: String,
    pub nullifier_fence_scheme: String,
    pub fast_auth_bundle_scheme: String,
    pub fee_sponsor_reservation_scheme: String,
    pub settlement_receipt_scheme: String,
    pub rebate_scheme: String,
    pub slashing_evidence_scheme: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub epoch_ttl_blocks: u64,
    pub session_ttl_blocks: u64,
    pub ratchet_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub max_auth_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_coverage_bps: u64,
    pub fast_auth_batch_target: usize,
    pub fast_auth_batch_limit: usize,
    pub max_accounts: usize,
    pub max_key_epochs: usize,
    pub max_session_proofs: usize,
    pub max_nullifier_fences: usize,
    pub max_auth_bundles: usize,
    pub max_sponsor_reservations: usize,
    pub max_settlement_receipts: usize,
    pub max_rebates: usize,
    pub max_slashing_evidence: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            devnet_height: DEVNET_HEIGHT,
            hash_suite: HASH_SUITE.to_string(),
            pq_kem_suite: PQ_KEM_SUITE.to_string(),
            pq_signature_suite: PQ_SIGNATURE_SUITE.to_string(),
            stealth_session_proof_scheme: STEALTH_SESSION_PROOF_SCHEME.to_string(),
            nullifier_fence_scheme: NULLIFIER_FENCE_SCHEME.to_string(),
            fast_auth_bundle_scheme: FAST_AUTH_BUNDLE_SCHEME.to_string(),
            fee_sponsor_reservation_scheme: FEE_SPONSOR_RESERVATION_SCHEME.to_string(),
            settlement_receipt_scheme: SETTLEMENT_RECEIPT_SCHEME.to_string(),
            rebate_scheme: REBATE_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            epoch_ttl_blocks: DEFAULT_EPOCH_TTL_BLOCKS,
            session_ttl_blocks: DEFAULT_SESSION_TTL_BLOCKS,
            ratchet_ttl_blocks: DEFAULT_RATCHET_TTL_BLOCKS,
            sponsor_ttl_blocks: DEFAULT_SPONSOR_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            max_auth_fee_bps: DEFAULT_MAX_AUTH_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_coverage_bps: DEFAULT_SPONSOR_COVERAGE_BPS,
            fast_auth_batch_target: DEFAULT_FAST_AUTH_BATCH_TARGET,
            fast_auth_batch_limit: DEFAULT_FAST_AUTH_BATCH_LIMIT,
            max_accounts: MAX_ACCOUNTS,
            max_key_epochs: MAX_KEY_EPOCHS,
            max_session_proofs: MAX_SESSION_PROOFS,
            max_nullifier_fences: MAX_NULLIFIER_FENCES,
            max_auth_bundles: MAX_AUTH_BUNDLES,
            max_sponsor_reservations: MAX_SPONSOR_RESERVATIONS,
            max_settlement_receipts: MAX_SETTLEMENT_RECEIPTS,
            max_rebates: MAX_REBATES,
            max_slashing_evidence: MAX_SLASHING_EVIDENCE,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_nonempty("chain_id", &self.chain_id)?;
        require_nonempty("protocol_version", &self.protocol_version)?;
        require_bps("max_auth_fee_bps", self.max_auth_fee_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        require_bps("sponsor_coverage_bps", self.sponsor_coverage_bps)?;
        if self.min_pq_security_bits < 128 {
            return Err("min_pq_security_bits must be at least 128".to_string());
        }
        if self.min_privacy_set_size == 0 || self.batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err("batch_privacy_set_size must cover min_privacy_set_size".to_string());
        }
        if self.fast_auth_batch_target == 0
            || self.fast_auth_batch_target > self.fast_auth_batch_limit
        {
            return Err("fast auth batch target must be within limit".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateSmartAccount {
    pub account_id: String,
    pub owner_commitment: String,
    pub account_class: AccountClass,
    pub status: AccountStatus,
    pub policy_root: String,
    pub spending_scope_root: String,
    pub token_scope_root: String,
    pub active_epoch_id: Option<String>,
    pub epoch_counter: u64,
    pub session_counter: u64,
    pub sponsor_allowance: u128,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub metadata: Value,
}

impl PrivateSmartAccount {
    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "owner_commitment": self.owner_commitment,
            "account_class": self.account_class.as_str(),
            "status": self.status.as_str(),
            "policy_root": self.policy_root,
            "spending_scope_root": self.spending_scope_root,
            "token_scope_root": self.token_scope_root,
            "active_epoch_id": self.active_epoch_id,
            "epoch_counter": self.epoch_counter,
            "session_counter": self.session_counter,
            "sponsor_allowance": self.sponsor_allowance.to_string(),
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn commitment(&self) -> String {
        account_commitment(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KeyEpoch {
    pub epoch_id: String,
    pub account_id: String,
    pub parent_epoch_id: Option<String>,
    pub epoch_index: u64,
    pub status: EpochStatus,
    pub kem_algorithm: KemAlgorithm,
    pub signature_algorithm: SignatureAlgorithm,
    pub falcon_ready: bool,
    pub pq_security_bits: u16,
    pub session_key_commitment: String,
    pub ratchet_public_root: String,
    pub encrypted_state_root: String,
    pub stealth_address_root: String,
    pub proof_namespace: String,
    pub nullifier_domain: String,
    pub opens_at_height: u64,
    pub expires_at_height: u64,
    pub activated_at_height: Option<u64>,
    pub superseded_by: Option<String>,
    pub metadata: Value,
}

impl KeyEpoch {
    pub fn public_record(&self) -> Value {
        json!({
            "epoch_id": self.epoch_id,
            "account_id": self.account_id,
            "parent_epoch_id": self.parent_epoch_id,
            "epoch_index": self.epoch_index,
            "status": self.status.as_str(),
            "kem_algorithm": self.kem_algorithm.as_str(),
            "signature_algorithm": self.signature_algorithm.as_str(),
            "falcon_ready": self.falcon_ready,
            "pq_security_bits": self.pq_security_bits,
            "session_key_commitment": self.session_key_commitment,
            "ratchet_public_root": self.ratchet_public_root,
            "encrypted_state_root": self.encrypted_state_root,
            "stealth_address_root": self.stealth_address_root,
            "proof_namespace": self.proof_namespace,
            "nullifier_domain": self.nullifier_domain,
            "opens_at_height": self.opens_at_height,
            "expires_at_height": self.expires_at_height,
            "activated_at_height": self.activated_at_height,
            "superseded_by": self.superseded_by,
            "metadata": self.metadata,
        })
    }

    pub fn commitment(&self) -> String {
        epoch_commitment(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StealthSessionProof {
    pub proof_id: String,
    pub account_id: String,
    pub epoch_id: String,
    pub session_tag: String,
    pub proof_commitment: String,
    pub stealth_address_commitment: String,
    pub view_tag_commitment: String,
    pub allowed_contract_root: String,
    pub allowed_method_root: String,
    pub asset_scope_root: String,
    pub max_fee: u128,
    pub privacy_set_size: u64,
    pub nullifier: String,
    pub status: SessionProofStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub sponsor_reservation_id: Option<String>,
    pub auth_bundle_ids: BTreeSet<String>,
    pub metadata: Value,
}

impl StealthSessionProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "account_id": self.account_id,
            "epoch_id": self.epoch_id,
            "session_tag": self.session_tag,
            "proof_commitment": self.proof_commitment,
            "stealth_address_commitment": self.stealth_address_commitment,
            "view_tag_commitment": self.view_tag_commitment,
            "allowed_contract_root": self.allowed_contract_root,
            "allowed_method_root": self.allowed_method_root,
            "asset_scope_root": self.asset_scope_root,
            "max_fee": self.max_fee.to_string(),
            "privacy_set_size": self.privacy_set_size,
            "nullifier": self.nullifier,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "auth_bundle_ids": self.auth_bundle_ids,
            "metadata": self.metadata,
        })
    }

    pub fn commitment(&self) -> String {
        session_proof_commitment(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub account_id: String,
    pub epoch_id: String,
    pub nullifier: String,
    pub source_id: String,
    pub source_kind: String,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub consumed: bool,
}

impl NullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "account_id": self.account_id,
            "epoch_id": self.epoch_id,
            "nullifier": self.nullifier,
            "source_id": self.source_id,
            "source_kind": self.source_kind,
            "first_seen_height": self.first_seen_height,
            "expires_at_height": self.expires_at_height,
            "consumed": self.consumed,
        })
    }

    pub fn commitment(&self) -> String {
        nullifier_fence_commitment(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FastAuthorizationBundle {
    pub bundle_id: String,
    pub proof_id: String,
    pub account_id: String,
    pub epoch_id: String,
    pub bundle_kind: AuthBundleKind,
    pub status: AuthBundleStatus,
    pub target_contract: String,
    pub method_selector: String,
    pub call_commitment: String,
    pub token_commitment: String,
    pub auth_root: String,
    pub witness_root: String,
    pub nullifier: String,
    pub sponsor_reservation_id: Option<String>,
    pub max_fee: u128,
    pub reserved_fee: u128,
    pub gas_units: u64,
    pub priority_lane: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub settled_receipt_id: Option<String>,
    pub metadata: Value,
}

impl FastAuthorizationBundle {
    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "proof_id": self.proof_id,
            "account_id": self.account_id,
            "epoch_id": self.epoch_id,
            "bundle_kind": self.bundle_kind.as_str(),
            "status": self.status.as_str(),
            "target_contract": self.target_contract,
            "method_selector": self.method_selector,
            "call_commitment": self.call_commitment,
            "token_commitment": self.token_commitment,
            "auth_root": self.auth_root,
            "witness_root": self.witness_root,
            "nullifier": self.nullifier,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "max_fee": self.max_fee.to_string(),
            "reserved_fee": self.reserved_fee.to_string(),
            "gas_units": self.gas_units,
            "priority_lane": self.priority_lane,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "settled_receipt_id": self.settled_receipt_id,
            "metadata": self.metadata,
        })
    }

    pub fn commitment(&self) -> String {
        auth_bundle_commitment(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsorReservation {
    pub reservation_id: String,
    pub account_id: String,
    pub epoch_id: String,
    pub proof_id: Option<String>,
    pub bundle_id: Option<String>,
    pub sponsor_commitment: String,
    pub token_commitment: String,
    pub reserved_amount: u128,
    pub consumed_amount: u128,
    pub rebate_amount: u128,
    pub coverage_bps: u64,
    pub status: SponsorReservationStatus,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl FeeSponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "account_id": self.account_id,
            "epoch_id": self.epoch_id,
            "proof_id": self.proof_id,
            "bundle_id": self.bundle_id,
            "sponsor_commitment": self.sponsor_commitment,
            "token_commitment": self.token_commitment,
            "reserved_amount": self.reserved_amount.to_string(),
            "consumed_amount": self.consumed_amount.to_string(),
            "rebate_amount": self.rebate_amount.to_string(),
            "coverage_bps": self.coverage_bps,
            "status": self.status.as_str(),
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn commitment(&self) -> String {
        sponsor_reservation_commitment(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub bundle_id: String,
    pub proof_id: String,
    pub account_id: String,
    pub epoch_id: String,
    pub receipt_kind: ReceiptKind,
    pub execution_root: String,
    pub state_diff_root: String,
    pub fee_paid: u128,
    pub sponsor_reservation_id: Option<String>,
    pub rebate_id: Option<String>,
    pub settled_at_height: u64,
    pub metadata: Value,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "bundle_id": self.bundle_id,
            "proof_id": self.proof_id,
            "account_id": self.account_id,
            "epoch_id": self.epoch_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "execution_root": self.execution_root,
            "state_diff_root": self.state_diff_root,
            "fee_paid": self.fee_paid.to_string(),
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "rebate_id": self.rebate_id,
            "settled_at_height": self.settled_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn commitment(&self) -> String {
        settlement_receipt_commitment(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub account_id: String,
    pub reservation_id: String,
    pub receipt_id: String,
    pub sponsor_commitment: String,
    pub token_commitment: String,
    pub amount: u128,
    pub status: RebateStatus,
    pub queued_at_height: u64,
    pub paid_at_height: Option<u64>,
    pub metadata: Value,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "account_id": self.account_id,
            "reservation_id": self.reservation_id,
            "receipt_id": self.receipt_id,
            "sponsor_commitment": self.sponsor_commitment,
            "token_commitment": self.token_commitment,
            "amount": self.amount.to_string(),
            "status": self.status.as_str(),
            "queued_at_height": self.queued_at_height,
            "paid_at_height": self.paid_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn commitment(&self) -> String {
        rebate_commitment(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub account_id: String,
    pub epoch_id: Option<String>,
    pub proof_id: Option<String>,
    pub bundle_id: Option<String>,
    pub reservation_id: Option<String>,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub challenger_commitment: String,
    pub penalty_amount: u128,
    pub submitted_at_height: u64,
    pub accepted: bool,
    pub metadata: Value,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "account_id": self.account_id,
            "epoch_id": self.epoch_id,
            "proof_id": self.proof_id,
            "bundle_id": self.bundle_id,
            "reservation_id": self.reservation_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "challenger_commitment": self.challenger_commitment,
            "penalty_amount": self.penalty_amount.to_string(),
            "submitted_at_height": self.submitted_at_height,
            "accepted": self.accepted,
            "metadata": self.metadata,
        })
    }

    pub fn commitment(&self) -> String {
        slashing_evidence_commitment(&self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub accounts: BTreeMap<String, PrivateSmartAccount>,
    pub key_epochs: BTreeMap<String, KeyEpoch>,
    pub session_proofs: BTreeMap<String, StealthSessionProof>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub auth_bundles: BTreeMap<String, FastAuthorizationBundle>,
    pub sponsor_reservations: BTreeMap<String, FeeSponsorReservation>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub account_epochs: BTreeMap<String, BTreeSet<String>>,
    pub account_proofs: BTreeMap<String, BTreeSet<String>>,
    pub epoch_proofs: BTreeMap<String, BTreeSet<String>>,
    pub proof_bundles: BTreeMap<String, BTreeSet<String>>,
    pub account_bundles: BTreeMap<String, BTreeSet<String>>,
    pub reservation_index: BTreeMap<String, BTreeSet<String>>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            height: DEVNET_HEIGHT,
            accounts: BTreeMap::new(),
            key_epochs: BTreeMap::new(),
            session_proofs: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            auth_bundles: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            account_epochs: BTreeMap::new(),
            account_proofs: BTreeMap::new(),
            epoch_proofs: BTreeMap::new(),
            proof_bundles: BTreeMap::new(),
            account_bundles: BTreeMap::new(),
            reservation_index: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        }
    }

    pub fn with_config(config: Config, height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            ..Self::devnet()
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": {
                "chain_id": self.config.chain_id,
                "protocol_version": self.config.protocol_version,
                "schema_version": self.config.schema_version,
                "devnet_height": self.config.devnet_height,
                "hash_suite": self.config.hash_suite,
                "pq_kem_suite": self.config.pq_kem_suite,
                "pq_signature_suite": self.config.pq_signature_suite,
                "stealth_session_proof_scheme": self.config.stealth_session_proof_scheme,
                "nullifier_fence_scheme": self.config.nullifier_fence_scheme,
                "fast_auth_bundle_scheme": self.config.fast_auth_bundle_scheme,
                "fee_sponsor_reservation_scheme": self.config.fee_sponsor_reservation_scheme,
                "settlement_receipt_scheme": self.config.settlement_receipt_scheme,
                "rebate_scheme": self.config.rebate_scheme,
                "slashing_evidence_scheme": self.config.slashing_evidence_scheme,
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "batch_privacy_set_size": self.config.batch_privacy_set_size,
                "epoch_ttl_blocks": self.config.epoch_ttl_blocks,
                "session_ttl_blocks": self.config.session_ttl_blocks,
                "ratchet_ttl_blocks": self.config.ratchet_ttl_blocks,
                "sponsor_ttl_blocks": self.config.sponsor_ttl_blocks,
                "settlement_ttl_blocks": self.config.settlement_ttl_blocks,
                "max_auth_fee_bps": self.config.max_auth_fee_bps,
                "target_rebate_bps": self.config.target_rebate_bps,
                "sponsor_coverage_bps": self.config.sponsor_coverage_bps,
                "fast_auth_batch_target": self.config.fast_auth_batch_target,
                "fast_auth_batch_limit": self.config.fast_auth_batch_limit,
            },
            "height": self.height,
            "roots": self.roots_record(),
            "counts": {
                "accounts": self.accounts.len(),
                "key_epochs": self.key_epochs.len(),
                "session_proofs": self.session_proofs.len(),
                "nullifier_fences": self.nullifier_fences.len(),
                "auth_bundles": self.auth_bundles.len(),
                "sponsor_reservations": self.sponsor_reservations.len(),
                "settlement_receipts": self.settlement_receipts.len(),
                "rebates": self.rebates.len(),
                "slashing_evidence": self.slashing_evidence.len(),
            }
        })
    }

    pub fn roots_record(&self) -> Value {
        json!({
            "accounts_root": records_root("accounts", self.accounts.values().map(PrivateSmartAccount::public_record).collect()),
            "key_epochs_root": records_root("key_epochs", self.key_epochs.values().map(KeyEpoch::public_record).collect()),
            "session_proofs_root": records_root("session_proofs", self.session_proofs.values().map(StealthSessionProof::public_record).collect()),
            "nullifier_fences_root": records_root("nullifier_fences", self.nullifier_fences.values().map(NullifierFence::public_record).collect()),
            "auth_bundles_root": records_root("auth_bundles", self.auth_bundles.values().map(FastAuthorizationBundle::public_record).collect()),
            "sponsor_reservations_root": records_root("sponsor_reservations", self.sponsor_reservations.values().map(FeeSponsorReservation::public_record).collect()),
            "settlement_receipts_root": records_root("settlement_receipts", self.settlement_receipts.values().map(SettlementReceipt::public_record).collect()),
            "rebates_root": records_root("rebates", self.rebates.values().map(FeeRebate::public_record).collect()),
            "slashing_evidence_root": records_root("slashing_evidence", self.slashing_evidence.values().map(SlashingEvidence::public_record).collect()),
            "consumed_nullifiers_root": merkle_root(
                "private-session-ratchet:consumed-nullifiers",
                &self.consumed_nullifiers.iter().map(|id| json!(id)).collect::<Vec<_>>()
            ),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "private-session-ratchet:state-root",
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(&self.config.protocol_version),
                HashPart::U64(self.config.schema_version),
                HashPart::U64(self.height),
                HashPart::Json(&self.roots_record()),
            ],
            32,
        )
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn register_account(
        &mut self,
        owner_commitment: impl Into<String>,
        account_class: AccountClass,
        policy_root: impl Into<String>,
        spending_scope_root: impl Into<String>,
        token_scope_root: impl Into<String>,
        privacy_set_size: u64,
        metadata: Value,
    ) -> Result<String> {
        ensure_capacity("accounts", self.accounts.len(), self.config.max_accounts)?;
        require_privacy_set(&self.config, privacy_set_size)?;
        let owner_commitment = owner_commitment.into();
        let policy_root = policy_root.into();
        let spending_scope_root = spending_scope_root.into();
        let token_scope_root = token_scope_root.into();
        require_nonempty("owner_commitment", &owner_commitment)?;
        require_nonempty("policy_root", &policy_root)?;
        require_nonempty("spending_scope_root", &spending_scope_root)?;
        require_nonempty("token_scope_root", &token_scope_root)?;
        let account_id = derive_account_id(
            &self.config.chain_id,
            &owner_commitment,
            account_class,
            &policy_root,
            self.height,
        );
        if self.accounts.contains_key(&account_id) {
            return Err(format!("account already exists: {account_id}"));
        }
        let account = PrivateSmartAccount {
            account_id: account_id.clone(),
            owner_commitment,
            account_class,
            status: AccountStatus::Active,
            policy_root,
            spending_scope_root,
            token_scope_root,
            active_epoch_id: None,
            epoch_counter: 0,
            session_counter: 0,
            sponsor_allowance: 0,
            privacy_set_size,
            created_at_height: self.height,
            updated_at_height: self.height,
            metadata,
        };
        self.accounts.insert(account_id.clone(), account);
        Ok(account_id)
    }

    pub fn open_key_epoch(
        &mut self,
        account_id: &str,
        kem_algorithm: KemAlgorithm,
        signature_algorithm: SignatureAlgorithm,
        session_key_commitment: impl Into<String>,
        ratchet_public_root: impl Into<String>,
        encrypted_state_root: impl Into<String>,
        stealth_address_root: impl Into<String>,
        metadata: Value,
    ) -> Result<String> {
        ensure_capacity(
            "key_epochs",
            self.key_epochs.len(),
            self.config.max_key_epochs,
        )?;
        require_pq_strength(&self.config, kem_algorithm, signature_algorithm)?;
        let session_key_commitment = session_key_commitment.into();
        let ratchet_public_root = ratchet_public_root.into();
        let encrypted_state_root = encrypted_state_root.into();
        let stealth_address_root = stealth_address_root.into();
        require_nonempty("session_key_commitment", &session_key_commitment)?;
        require_nonempty("ratchet_public_root", &ratchet_public_root)?;
        require_nonempty("encrypted_state_root", &encrypted_state_root)?;
        require_nonempty("stealth_address_root", &stealth_address_root)?;
        let account = self.account_mut(account_id)?;
        if !account.status.accepts_sessions() {
            return Err(format!("account does not accept epochs: {account_id}"));
        }
        let parent_epoch_id = account.active_epoch_id.clone();
        let epoch_index = account.epoch_counter + 1;
        let proof_namespace =
            derive_proof_namespace(&self.config.chain_id, account_id, epoch_index);
        let nullifier_domain =
            derive_nullifier_domain(&self.config.chain_id, account_id, epoch_index);
        let epoch_id = derive_epoch_id(
            &self.config.chain_id,
            account_id,
            epoch_index,
            &session_key_commitment,
            &ratchet_public_root,
        );
        if self.key_epochs.contains_key(&epoch_id) {
            return Err(format!("epoch already exists: {epoch_id}"));
        }
        let epoch = KeyEpoch {
            epoch_id: epoch_id.clone(),
            account_id: account_id.to_string(),
            parent_epoch_id,
            epoch_index,
            status: EpochStatus::Proposed,
            kem_algorithm,
            signature_algorithm,
            falcon_ready: matches!(
                signature_algorithm,
                SignatureAlgorithm::Falcon512Ready | SignatureAlgorithm::Falcon1024Ready
            ),
            pq_security_bits: kem_algorithm
                .pq_security_bits()
                .min(signature_algorithm.pq_security_bits()),
            session_key_commitment,
            ratchet_public_root,
            encrypted_state_root,
            stealth_address_root,
            proof_namespace,
            nullifier_domain,
            opens_at_height: self.height,
            expires_at_height: self.height + self.config.epoch_ttl_blocks,
            activated_at_height: None,
            superseded_by: None,
            metadata,
        };
        account.epoch_counter = epoch_index;
        account.status = AccountStatus::Ratcheting;
        account.updated_at_height = self.height;
        self.account_epochs
            .entry(account_id.to_string())
            .or_default()
            .insert(epoch_id.clone());
        self.key_epochs.insert(epoch_id.clone(), epoch);
        Ok(epoch_id)
    }

    pub fn activate_epoch(&mut self, epoch_id: &str) -> Result<()> {
        let account_id = self.epoch(epoch_id)?.account_id.clone();
        let prior_epoch_id = self.account(&account_id)?.active_epoch_id.clone();
        if let Some(prior_epoch_id) = prior_epoch_id {
            if prior_epoch_id != epoch_id {
                if let Some(prior) = self.key_epochs.get_mut(&prior_epoch_id) {
                    prior.status = EpochStatus::Superseded;
                    prior.superseded_by = Some(epoch_id.to_string());
                }
            }
        }
        let epoch = self.epoch_mut(epoch_id)?;
        if !epoch.status.live() {
            return Err(format!("epoch cannot be activated from {:?}", epoch.status));
        }
        if self.height > epoch.expires_at_height {
            epoch.status = EpochStatus::Expired;
            return Err(format!("epoch expired: {epoch_id}"));
        }
        epoch.status = EpochStatus::Active;
        epoch.activated_at_height = Some(self.height);
        let account = self.account_mut(&account_id)?;
        account.active_epoch_id = Some(epoch_id.to_string());
        account.status = AccountStatus::Active;
        account.updated_at_height = self.height;
        Ok(())
    }

    pub fn reserve_epoch_sponsor(
        &mut self,
        account_id: &str,
        epoch_id: &str,
        sponsor_commitment: impl Into<String>,
        token_commitment: impl Into<String>,
        reserved_amount: u128,
        metadata: Value,
    ) -> Result<String> {
        self.ensure_account_epoch(account_id, epoch_id)?;
        let sponsor_commitment = sponsor_commitment.into();
        let token_commitment = token_commitment.into();
        let reservation_id = self.insert_sponsor_reservation(
            account_id,
            epoch_id,
            None,
            None,
            sponsor_commitment,
            token_commitment,
            reserved_amount,
            metadata,
        )?;
        if let Some(epoch) = self.key_epochs.get_mut(epoch_id) {
            if epoch.status == EpochStatus::Proposed {
                epoch.status = EpochStatus::SponsorReserved;
            }
        }
        Ok(reservation_id)
    }

    pub fn submit_stealth_session_proof(
        &mut self,
        account_id: &str,
        epoch_id: &str,
        session_tag: impl Into<String>,
        proof_commitment: impl Into<String>,
        stealth_address_commitment: impl Into<String>,
        view_tag_commitment: impl Into<String>,
        allowed_contract_root: impl Into<String>,
        allowed_method_root: impl Into<String>,
        asset_scope_root: impl Into<String>,
        max_fee: u128,
        privacy_set_size: u64,
        nullifier: impl Into<String>,
        metadata: Value,
    ) -> Result<String> {
        ensure_capacity(
            "session_proofs",
            self.session_proofs.len(),
            self.config.max_session_proofs,
        )?;
        self.ensure_account_epoch(account_id, epoch_id)?;
        require_privacy_set(&self.config, privacy_set_size)?;
        let epoch = self.epoch(epoch_id)?;
        if !epoch.status.accepts_proofs() {
            return Err(format!("epoch does not accept session proofs: {epoch_id}"));
        }
        if self.height > epoch.expires_at_height {
            return Err(format!("epoch expired: {epoch_id}"));
        }
        let session_tag = session_tag.into();
        let proof_commitment = proof_commitment.into();
        let stealth_address_commitment = stealth_address_commitment.into();
        let view_tag_commitment = view_tag_commitment.into();
        let allowed_contract_root = allowed_contract_root.into();
        let allowed_method_root = allowed_method_root.into();
        let asset_scope_root = asset_scope_root.into();
        let nullifier = nullifier.into();
        require_nonempty("session_tag", &session_tag)?;
        require_nonempty("proof_commitment", &proof_commitment)?;
        require_nonempty("stealth_address_commitment", &stealth_address_commitment)?;
        require_nonempty("view_tag_commitment", &view_tag_commitment)?;
        require_nonempty("allowed_contract_root", &allowed_contract_root)?;
        require_nonempty("allowed_method_root", &allowed_method_root)?;
        require_nonempty("asset_scope_root", &asset_scope_root)?;
        self.ensure_nullifier_available(&nullifier)?;
        let proof_id = derive_session_proof_id(
            &self.config.chain_id,
            account_id,
            epoch_id,
            &session_tag,
            &proof_commitment,
        );
        if self.session_proofs.contains_key(&proof_id) {
            return Err(format!("session proof already exists: {proof_id}"));
        }
        let proof = StealthSessionProof {
            proof_id: proof_id.clone(),
            account_id: account_id.to_string(),
            epoch_id: epoch_id.to_string(),
            session_tag,
            proof_commitment,
            stealth_address_commitment,
            view_tag_commitment,
            allowed_contract_root,
            allowed_method_root,
            asset_scope_root,
            max_fee,
            privacy_set_size,
            nullifier: nullifier.clone(),
            status: SessionProofStatus::Submitted,
            submitted_at_height: self.height,
            expires_at_height: self.height + self.config.session_ttl_blocks,
            sponsor_reservation_id: None,
            auth_bundle_ids: BTreeSet::new(),
            metadata,
        };
        self.session_proofs.insert(proof_id.clone(), proof);
        self.account_proofs
            .entry(account_id.to_string())
            .or_default()
            .insert(proof_id.clone());
        self.epoch_proofs
            .entry(epoch_id.to_string())
            .or_default()
            .insert(proof_id.clone());
        self.insert_nullifier_fence(
            account_id,
            epoch_id,
            &nullifier,
            &proof_id,
            "session_proof",
            self.height + self.config.session_ttl_blocks,
        )?;
        if let Some(proof) = self.session_proofs.get_mut(&proof_id) {
            proof.status = SessionProofStatus::ReplayFenced;
        }
        if let Some(epoch) = self.key_epochs.get_mut(epoch_id) {
            if epoch.status == EpochStatus::SponsorReserved {
                epoch.status = EpochStatus::ProofBound;
            }
        }
        let account = self.account_mut(account_id)?;
        account.session_counter += 1;
        account.updated_at_height = self.height;
        Ok(proof_id)
    }

    pub fn reserve_session_sponsor(
        &mut self,
        proof_id: &str,
        sponsor_commitment: impl Into<String>,
        token_commitment: impl Into<String>,
        reserved_amount: u128,
        metadata: Value,
    ) -> Result<String> {
        let proof = self.session_proof(proof_id)?.clone();
        if !proof.status.authorizable() {
            return Err(format!("proof is not sponsorable: {proof_id}"));
        }
        let reservation_id = self.insert_sponsor_reservation(
            &proof.account_id,
            &proof.epoch_id,
            Some(proof_id.to_string()),
            None,
            sponsor_commitment.into(),
            token_commitment.into(),
            reserved_amount,
            metadata,
        )?;
        if let Some(proof) = self.session_proofs.get_mut(proof_id) {
            proof.sponsor_reservation_id = Some(reservation_id.clone());
            proof.status = SessionProofStatus::SponsorMatched;
        }
        Ok(reservation_id)
    }

    pub fn prepare_fast_authorization_bundle(
        &mut self,
        proof_id: &str,
        bundle_kind: AuthBundleKind,
        target_contract: impl Into<String>,
        method_selector: impl Into<String>,
        call_commitment: impl Into<String>,
        token_commitment: impl Into<String>,
        auth_root: impl Into<String>,
        witness_root: impl Into<String>,
        nullifier: impl Into<String>,
        max_fee: u128,
        gas_units: u64,
        priority_lane: u16,
        metadata: Value,
    ) -> Result<String> {
        ensure_capacity(
            "auth_bundles",
            self.auth_bundles.len(),
            self.config.max_auth_bundles,
        )?;
        let proof = self.session_proof(proof_id)?.clone();
        if !proof.status.authorizable() {
            return Err(format!("session proof is not authorizable: {proof_id}"));
        }
        if self.height > proof.expires_at_height {
            return Err(format!("session proof expired: {proof_id}"));
        }
        if max_fee > proof.max_fee {
            return Err("bundle max_fee exceeds session proof max_fee".to_string());
        }
        let target_contract = target_contract.into();
        let method_selector = method_selector.into();
        let call_commitment = call_commitment.into();
        let token_commitment = token_commitment.into();
        let auth_root = auth_root.into();
        let witness_root = witness_root.into();
        let nullifier = nullifier.into();
        require_nonempty("target_contract", &target_contract)?;
        require_nonempty("method_selector", &method_selector)?;
        require_nonempty("call_commitment", &call_commitment)?;
        require_nonempty("token_commitment", &token_commitment)?;
        require_nonempty("auth_root", &auth_root)?;
        require_nonempty("witness_root", &witness_root)?;
        self.ensure_nullifier_available(&nullifier)?;
        let bundle_id = derive_auth_bundle_id(
            &self.config.chain_id,
            proof_id,
            bundle_kind,
            &target_contract,
            &method_selector,
            &call_commitment,
        );
        if self.auth_bundles.contains_key(&bundle_id) {
            return Err(format!("auth bundle already exists: {bundle_id}"));
        }
        let bundle = FastAuthorizationBundle {
            bundle_id: bundle_id.clone(),
            proof_id: proof_id.to_string(),
            account_id: proof.account_id.clone(),
            epoch_id: proof.epoch_id.clone(),
            bundle_kind,
            status: AuthBundleStatus::Prepared,
            target_contract,
            method_selector,
            call_commitment,
            token_commitment,
            auth_root,
            witness_root,
            nullifier: nullifier.clone(),
            sponsor_reservation_id: None,
            max_fee,
            reserved_fee: 0,
            gas_units,
            priority_lane,
            submitted_at_height: self.height,
            expires_at_height: self.height + self.config.ratchet_ttl_blocks,
            settled_receipt_id: None,
            metadata,
        };
        self.auth_bundles.insert(bundle_id.clone(), bundle);
        self.proof_bundles
            .entry(proof_id.to_string())
            .or_default()
            .insert(bundle_id.clone());
        self.account_bundles
            .entry(proof.account_id.clone())
            .or_default()
            .insert(bundle_id.clone());
        if let Some(proof) = self.session_proofs.get_mut(proof_id) {
            proof.auth_bundle_ids.insert(bundle_id.clone());
        }
        self.insert_nullifier_fence(
            &proof.account_id,
            &proof.epoch_id,
            &nullifier,
            &bundle_id,
            "auth_bundle",
            self.height + self.config.ratchet_ttl_blocks,
        )?;
        if let Some(bundle) = self.auth_bundles.get_mut(&bundle_id) {
            bundle.status = AuthBundleStatus::ReplayFenced;
        }
        Ok(bundle_id)
    }

    pub fn reserve_bundle_sponsor(
        &mut self,
        bundle_id: &str,
        sponsor_commitment: impl Into<String>,
        token_commitment: impl Into<String>,
        reserved_amount: u128,
        metadata: Value,
    ) -> Result<String> {
        let bundle = self.auth_bundle(bundle_id)?.clone();
        if !matches!(
            bundle.status,
            AuthBundleStatus::ReplayFenced | AuthBundleStatus::Prepared
        ) {
            return Err(format!("bundle is not sponsorable: {bundle_id}"));
        }
        if reserved_amount > bundle.max_fee {
            return Err("reserved_amount exceeds bundle max_fee".to_string());
        }
        let reservation_id = self.insert_sponsor_reservation(
            &bundle.account_id,
            &bundle.epoch_id,
            Some(bundle.proof_id.clone()),
            Some(bundle_id.to_string()),
            sponsor_commitment.into(),
            token_commitment.into(),
            reserved_amount,
            metadata,
        )?;
        if let Some(bundle) = self.auth_bundles.get_mut(bundle_id) {
            bundle.sponsor_reservation_id = Some(reservation_id.clone());
            bundle.reserved_fee = reserved_amount;
            bundle.status = AuthBundleStatus::SponsorReserved;
        }
        Ok(reservation_id)
    }

    pub fn authorize_bundle(&mut self, bundle_id: &str) -> Result<()> {
        let (proof_id, proof_status, expires_at_height) = {
            let bundle = self.auth_bundle(bundle_id)?;
            let proof = self.session_proof(&bundle.proof_id)?;
            (
                bundle.proof_id.clone(),
                proof.status,
                bundle.expires_at_height,
            )
        };
        if !proof_status.authorizable() {
            return Err(format!("proof is not authorizable for bundle: {proof_id}"));
        }
        if self.height > expires_at_height {
            let bundle = self.auth_bundle_mut(bundle_id)?;
            bundle.status = AuthBundleStatus::Expired;
            return Err(format!("bundle expired: {bundle_id}"));
        }
        let bundle = self.auth_bundle_mut(bundle_id)?;
        if !matches!(
            bundle.status,
            AuthBundleStatus::ReplayFenced | AuthBundleStatus::SponsorReserved
        ) {
            return Err(format!(
                "bundle cannot be authorized from {:?}",
                bundle.status
            ));
        }
        bundle.status = AuthBundleStatus::Authorized;
        let proof = self.session_proof_mut(&proof_id)?;
        proof.status = SessionProofStatus::Authorized;
        Ok(())
    }

    pub fn settle_bundle(
        &mut self,
        bundle_id: &str,
        receipt_kind: ReceiptKind,
        execution_root: impl Into<String>,
        state_diff_root: impl Into<String>,
        fee_paid: u128,
        metadata: Value,
    ) -> Result<String> {
        ensure_capacity(
            "settlement_receipts",
            self.settlement_receipts.len(),
            self.config.max_settlement_receipts,
        )?;
        let execution_root = execution_root.into();
        let state_diff_root = state_diff_root.into();
        require_nonempty("execution_root", &execution_root)?;
        require_nonempty("state_diff_root", &state_diff_root)?;
        let bundle = self.auth_bundle(bundle_id)?.clone();
        if !bundle.status.can_settle() {
            return Err(format!("bundle cannot settle from {:?}", bundle.status));
        }
        if fee_paid > bundle.max_fee {
            return Err("fee_paid exceeds bundle max_fee".to_string());
        }
        let proof_id = bundle.proof_id.clone();
        let reservation_id = bundle.sponsor_reservation_id.clone();
        let receipt_id = derive_receipt_id(
            &self.config.chain_id,
            bundle_id,
            &proof_id,
            &execution_root,
            &state_diff_root,
            self.height,
        );
        if self.settlement_receipts.contains_key(&receipt_id) {
            return Err(format!("settlement receipt already exists: {receipt_id}"));
        }
        let mut rebate_id = None;
        if let Some(reservation_id) = &reservation_id {
            rebate_id = self.consume_reservation_and_queue_rebate(reservation_id, fee_paid)?;
        }
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            bundle_id: bundle_id.to_string(),
            proof_id: proof_id.clone(),
            account_id: bundle.account_id.clone(),
            epoch_id: bundle.epoch_id.clone(),
            receipt_kind,
            execution_root,
            state_diff_root,
            fee_paid,
            sponsor_reservation_id: reservation_id,
            rebate_id,
            settled_at_height: self.height,
            metadata,
        };
        self.settlement_receipts.insert(receipt_id.clone(), receipt);
        if let Some(bundle) = self.auth_bundles.get_mut(bundle_id) {
            bundle.status = match receipt_kind {
                ReceiptKind::BundleReverted => AuthBundleStatus::Reverted,
                _ => AuthBundleStatus::Settled,
            };
            bundle.settled_receipt_id = Some(receipt_id.clone());
        }
        if let Some(proof) = self.session_proofs.get_mut(&proof_id) {
            proof.status = SessionProofStatus::Settled;
        }
        self.consumed_nullifiers
            .insert(self.auth_bundle(bundle_id)?.nullifier.clone());
        Ok(receipt_id)
    }

    pub fn pay_rebate(&mut self, rebate_id: &str) -> Result<()> {
        let rebate = self
            .rebates
            .get_mut(rebate_id)
            .ok_or_else(|| format!("unknown rebate: {rebate_id}"))?;
        if rebate.status != RebateStatus::Queued {
            return Err(format!("rebate is not queued: {rebate_id}"));
        }
        rebate.status = RebateStatus::Paid;
        rebate.paid_at_height = Some(self.height);
        if let Some(reservation) = self.sponsor_reservations.get_mut(&rebate.reservation_id) {
            reservation.status = SponsorReservationStatus::Refunded;
        }
        Ok(())
    }

    pub fn revoke_epoch(&mut self, epoch_id: &str, metadata: Value) -> Result<String> {
        let epoch = self.epoch(epoch_id)?.clone();
        let receipt_id = derive_receipt_id(
            &self.config.chain_id,
            "epoch-revocation",
            epoch_id,
            &epoch.ratchet_public_root,
            &epoch.encrypted_state_root,
            self.height,
        );
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            bundle_id: "epoch-revocation".to_string(),
            proof_id: "epoch-revocation".to_string(),
            account_id: epoch.account_id.clone(),
            epoch_id: epoch_id.to_string(),
            receipt_kind: ReceiptKind::EpochRevoked,
            execution_root: epoch.ratchet_public_root,
            state_diff_root: epoch.encrypted_state_root,
            fee_paid: 0,
            sponsor_reservation_id: None,
            rebate_id: None,
            settled_at_height: self.height,
            metadata,
        };
        self.settlement_receipts.insert(receipt_id.clone(), receipt);
        if let Some(epoch) = self.key_epochs.get_mut(epoch_id) {
            epoch.status = EpochStatus::Revoked;
        }
        let account = self.account_mut(&epoch.account_id)?;
        if account.active_epoch_id.as_deref() == Some(epoch_id) {
            account.active_epoch_id = None;
            account.status = AccountStatus::Frozen;
        }
        Ok(receipt_id)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        account_id: &str,
        epoch_id: Option<String>,
        proof_id: Option<String>,
        bundle_id: Option<String>,
        reservation_id: Option<String>,
        reason: SlashingReason,
        evidence_root: impl Into<String>,
        challenger_commitment: impl Into<String>,
        penalty_amount: u128,
        metadata: Value,
    ) -> Result<String> {
        ensure_capacity(
            "slashing_evidence",
            self.slashing_evidence.len(),
            self.config.max_slashing_evidence,
        )?;
        self.account(account_id)?;
        let evidence_root = evidence_root.into();
        let challenger_commitment = challenger_commitment.into();
        require_nonempty("evidence_root", &evidence_root)?;
        require_nonempty("challenger_commitment", &challenger_commitment)?;
        let evidence_id = derive_slashing_evidence_id(
            &self.config.chain_id,
            account_id,
            reason,
            &evidence_root,
            self.height,
        );
        if self.slashing_evidence.contains_key(&evidence_id) {
            return Err(format!("slashing evidence already exists: {evidence_id}"));
        }
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            account_id: account_id.to_string(),
            epoch_id,
            proof_id,
            bundle_id,
            reservation_id,
            reason,
            evidence_root,
            challenger_commitment,
            penalty_amount,
            submitted_at_height: self.height,
            accepted: false,
            metadata,
        };
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn accept_slashing_evidence(&mut self, evidence_id: &str) -> Result<String> {
        let evidence = self
            .slashing_evidence
            .get(evidence_id)
            .ok_or_else(|| format!("unknown slashing evidence: {evidence_id}"))?
            .clone();
        if let Some(epoch_id) = &evidence.epoch_id {
            if let Some(epoch) = self.key_epochs.get_mut(epoch_id) {
                epoch.status = EpochStatus::Slashed;
            }
        }
        if let Some(proof_id) = &evidence.proof_id {
            if let Some(proof) = self.session_proofs.get_mut(proof_id) {
                proof.status = SessionProofStatus::Slashed;
            }
        }
        if let Some(bundle_id) = &evidence.bundle_id {
            if let Some(bundle) = self.auth_bundles.get_mut(bundle_id) {
                bundle.status = AuthBundleStatus::Slashed;
            }
        }
        if let Some(reservation_id) = &evidence.reservation_id {
            if let Some(reservation) = self.sponsor_reservations.get_mut(reservation_id) {
                reservation.status = SponsorReservationStatus::Slashed;
            }
        }
        if let Some(account) = self.accounts.get_mut(&evidence.account_id) {
            account.status = AccountStatus::Slashed;
            account.updated_at_height = self.height;
        }
        if let Some(evidence) = self.slashing_evidence.get_mut(evidence_id) {
            evidence.accepted = true;
        }
        let receipt_id = derive_receipt_id(
            &self.config.chain_id,
            "slash",
            evidence_id,
            &evidence.evidence_root,
            &evidence.challenger_commitment,
            self.height,
        );
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            bundle_id: evidence.bundle_id.unwrap_or_else(|| "slash".to_string()),
            proof_id: evidence.proof_id.unwrap_or_else(|| "slash".to_string()),
            account_id: evidence.account_id,
            epoch_id: evidence.epoch_id.unwrap_or_else(|| "slash".to_string()),
            receipt_kind: ReceiptKind::SlashApplied,
            execution_root: evidence.evidence_root,
            state_diff_root: evidence_id.to_string(),
            fee_paid: evidence.penalty_amount,
            sponsor_reservation_id: evidence.reservation_id,
            rebate_id: None,
            settled_at_height: self.height,
            metadata: json!({"reason": evidence.reason.as_str()}),
        };
        self.settlement_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn expire_height(&mut self, height: u64) -> usize {
        self.height = height;
        let mut expired = 0;
        for epoch in self.key_epochs.values_mut() {
            if epoch.status.live() && height > epoch.expires_at_height {
                epoch.status = EpochStatus::Expired;
                expired += 1;
            }
        }
        for proof in self.session_proofs.values_mut() {
            if proof.status.authorizable() && height > proof.expires_at_height {
                proof.status = SessionProofStatus::Expired;
                expired += 1;
            }
        }
        for bundle in self.auth_bundles.values_mut() {
            if !matches!(
                bundle.status,
                AuthBundleStatus::Settled
                    | AuthBundleStatus::Reverted
                    | AuthBundleStatus::Cancelled
                    | AuthBundleStatus::Slashed
            ) && height > bundle.expires_at_height
            {
                bundle.status = AuthBundleStatus::Expired;
                expired += 1;
            }
        }
        for reservation in self.sponsor_reservations.values_mut() {
            if reservation.status.spendable() && height > reservation.expires_at_height {
                reservation.status = SponsorReservationStatus::Expired;
                expired += 1;
            }
        }
        for rebate in self.rebates.values_mut() {
            if rebate.status == RebateStatus::Queued
                && height > rebate.queued_at_height + self.config.settlement_ttl_blocks
            {
                rebate.status = RebateStatus::Expired;
                expired += 1;
            }
        }
        expired
    }

    fn account(&self, account_id: &str) -> Result<&PrivateSmartAccount> {
        self.accounts
            .get(account_id)
            .ok_or_else(|| format!("unknown account: {account_id}"))
    }

    fn account_mut(&mut self, account_id: &str) -> Result<&mut PrivateSmartAccount> {
        self.accounts
            .get_mut(account_id)
            .ok_or_else(|| format!("unknown account: {account_id}"))
    }

    fn epoch(&self, epoch_id: &str) -> Result<&KeyEpoch> {
        self.key_epochs
            .get(epoch_id)
            .ok_or_else(|| format!("unknown key epoch: {epoch_id}"))
    }

    fn epoch_mut(&mut self, epoch_id: &str) -> Result<&mut KeyEpoch> {
        self.key_epochs
            .get_mut(epoch_id)
            .ok_or_else(|| format!("unknown key epoch: {epoch_id}"))
    }

    fn session_proof(&self, proof_id: &str) -> Result<&StealthSessionProof> {
        self.session_proofs
            .get(proof_id)
            .ok_or_else(|| format!("unknown session proof: {proof_id}"))
    }

    fn session_proof_mut(&mut self, proof_id: &str) -> Result<&mut StealthSessionProof> {
        self.session_proofs
            .get_mut(proof_id)
            .ok_or_else(|| format!("unknown session proof: {proof_id}"))
    }

    fn auth_bundle(&self, bundle_id: &str) -> Result<&FastAuthorizationBundle> {
        self.auth_bundles
            .get(bundle_id)
            .ok_or_else(|| format!("unknown auth bundle: {bundle_id}"))
    }

    fn auth_bundle_mut(&mut self, bundle_id: &str) -> Result<&mut FastAuthorizationBundle> {
        self.auth_bundles
            .get_mut(bundle_id)
            .ok_or_else(|| format!("unknown auth bundle: {bundle_id}"))
    }

    fn ensure_account_epoch(&self, account_id: &str, epoch_id: &str) -> Result<()> {
        self.account(account_id)?;
        let epoch = self.epoch(epoch_id)?;
        if epoch.account_id != account_id {
            return Err(format!(
                "epoch {epoch_id} belongs to account {}, not {account_id}",
                epoch.account_id
            ));
        }
        Ok(())
    }

    fn ensure_nullifier_available(&self, nullifier: &str) -> Result<()> {
        require_nonempty("nullifier", nullifier)?;
        if self.consumed_nullifiers.contains(nullifier) {
            return Err(format!("nullifier already consumed: {nullifier}"));
        }
        if self
            .nullifier_fences
            .values()
            .any(|fence| fence.nullifier == nullifier && !fence.consumed)
        {
            return Err(format!("nullifier already fenced: {nullifier}"));
        }
        Ok(())
    }

    fn insert_nullifier_fence(
        &mut self,
        account_id: &str,
        epoch_id: &str,
        nullifier: &str,
        source_id: &str,
        source_kind: &str,
        expires_at_height: u64,
    ) -> Result<String> {
        ensure_capacity(
            "nullifier_fences",
            self.nullifier_fences.len(),
            self.config.max_nullifier_fences,
        )?;
        let fence_id = derive_nullifier_fence_id(
            &self.config.chain_id,
            account_id,
            epoch_id,
            nullifier,
            source_id,
        );
        if self.nullifier_fences.contains_key(&fence_id) {
            return Err(format!("nullifier fence already exists: {fence_id}"));
        }
        let fence = NullifierFence {
            fence_id: fence_id.clone(),
            account_id: account_id.to_string(),
            epoch_id: epoch_id.to_string(),
            nullifier: nullifier.to_string(),
            source_id: source_id.to_string(),
            source_kind: source_kind.to_string(),
            first_seen_height: self.height,
            expires_at_height,
            consumed: false,
        };
        self.nullifier_fences.insert(fence_id.clone(), fence);
        Ok(fence_id)
    }

    fn insert_sponsor_reservation(
        &mut self,
        account_id: &str,
        epoch_id: &str,
        proof_id: Option<String>,
        bundle_id: Option<String>,
        sponsor_commitment: String,
        token_commitment: String,
        reserved_amount: u128,
        metadata: Value,
    ) -> Result<String> {
        ensure_capacity(
            "sponsor_reservations",
            self.sponsor_reservations.len(),
            self.config.max_sponsor_reservations,
        )?;
        require_nonempty("sponsor_commitment", &sponsor_commitment)?;
        require_nonempty("token_commitment", &token_commitment)?;
        if reserved_amount == 0 {
            return Err("reserved_amount must be nonzero".to_string());
        }
        let reservation_id = derive_sponsor_reservation_id(
            &self.config.chain_id,
            account_id,
            epoch_id,
            proof_id.as_deref(),
            bundle_id.as_deref(),
            &sponsor_commitment,
            self.height,
        );
        if self.sponsor_reservations.contains_key(&reservation_id) {
            return Err(format!(
                "sponsor reservation already exists: {reservation_id}"
            ));
        }
        let reservation = FeeSponsorReservation {
            reservation_id: reservation_id.clone(),
            account_id: account_id.to_string(),
            epoch_id: epoch_id.to_string(),
            proof_id,
            bundle_id,
            sponsor_commitment,
            token_commitment,
            reserved_amount,
            consumed_amount: 0,
            rebate_amount: 0,
            coverage_bps: self.config.sponsor_coverage_bps,
            status: SponsorReservationStatus::Reserved,
            reserved_at_height: self.height,
            expires_at_height: self.height + self.config.sponsor_ttl_blocks,
            metadata,
        };
        self.sponsor_reservations
            .insert(reservation_id.clone(), reservation);
        self.reservation_index
            .entry(account_id.to_string())
            .or_default()
            .insert(reservation_id.clone());
        Ok(reservation_id)
    }

    fn consume_reservation_and_queue_rebate(
        &mut self,
        reservation_id: &str,
        fee_paid: u128,
    ) -> Result<Option<String>> {
        let reservation = self
            .sponsor_reservations
            .get_mut(reservation_id)
            .ok_or_else(|| format!("unknown sponsor reservation: {reservation_id}"))?;
        if !reservation.status.spendable() {
            return Err(format!("reservation is not spendable: {reservation_id}"));
        }
        if fee_paid > reservation.reserved_amount {
            return Err("fee_paid exceeds sponsor reservation".to_string());
        }
        reservation.consumed_amount = fee_paid;
        reservation.rebate_amount = reservation.reserved_amount.saturating_sub(fee_paid);
        reservation.status = if reservation.rebate_amount > 0 {
            SponsorReservationStatus::RebateQueued
        } else {
            SponsorReservationStatus::Consumed
        };
        if reservation.rebate_amount == 0 {
            return Ok(None);
        }
        ensure_capacity("rebates", self.rebates.len(), self.config.max_rebates)?;
        let rebate_id = derive_rebate_id(
            &self.config.chain_id,
            reservation_id,
            &reservation.sponsor_commitment,
            reservation.rebate_amount,
            self.height,
        );
        let rebate = FeeRebate {
            rebate_id: rebate_id.clone(),
            account_id: reservation.account_id.clone(),
            reservation_id: reservation_id.to_string(),
            receipt_id: "pending-receipt-link".to_string(),
            sponsor_commitment: reservation.sponsor_commitment.clone(),
            token_commitment: reservation.token_commitment.clone(),
            amount: reservation.rebate_amount,
            status: RebateStatus::Queued,
            queued_at_height: self.height,
            paid_at_height: None,
            metadata: json!({"source": "sponsor_reservation_change"}),
        };
        self.rebates.insert(rebate_id.clone(), rebate);
        Ok(Some(rebate_id))
    }
}

pub fn derive_account_id(
    chain_id: &str,
    owner_commitment: &str,
    account_class: AccountClass,
    policy_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-session-ratchet:account-id",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(account_class.as_str()),
            HashPart::Str(policy_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn derive_epoch_id(
    chain_id: &str,
    account_id: &str,
    epoch_index: u64,
    session_key_commitment: &str,
    ratchet_public_root: &str,
) -> String {
    domain_hash(
        "private-session-ratchet:epoch-id",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(account_id),
            HashPart::U64(epoch_index),
            HashPart::Str(session_key_commitment),
            HashPart::Str(ratchet_public_root),
        ],
        32,
    )
}

pub fn derive_proof_namespace(chain_id: &str, account_id: &str, epoch_index: u64) -> String {
    domain_hash(
        "private-session-ratchet:proof-namespace",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(account_id),
            HashPart::U64(epoch_index),
        ],
        32,
    )
}

pub fn derive_nullifier_domain(chain_id: &str, account_id: &str, epoch_index: u64) -> String {
    domain_hash(
        "private-session-ratchet:nullifier-domain",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(account_id),
            HashPart::U64(epoch_index),
        ],
        32,
    )
}

pub fn derive_session_proof_id(
    chain_id: &str,
    account_id: &str,
    epoch_id: &str,
    session_tag: &str,
    proof_commitment: &str,
) -> String {
    domain_hash(
        "private-session-ratchet:session-proof-id",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(account_id),
            HashPart::Str(epoch_id),
            HashPart::Str(session_tag),
            HashPart::Str(proof_commitment),
        ],
        32,
    )
}

pub fn derive_nullifier_fence_id(
    chain_id: &str,
    account_id: &str,
    epoch_id: &str,
    nullifier: &str,
    source_id: &str,
) -> String {
    domain_hash(
        "private-session-ratchet:nullifier-fence-id",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(account_id),
            HashPart::Str(epoch_id),
            HashPart::Str(nullifier),
            HashPart::Str(source_id),
        ],
        32,
    )
}

pub fn derive_auth_bundle_id(
    chain_id: &str,
    proof_id: &str,
    bundle_kind: AuthBundleKind,
    target_contract: &str,
    method_selector: &str,
    call_commitment: &str,
) -> String {
    domain_hash(
        "private-session-ratchet:auth-bundle-id",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(proof_id),
            HashPart::Str(bundle_kind.as_str()),
            HashPart::Str(target_contract),
            HashPart::Str(method_selector),
            HashPart::Str(call_commitment),
        ],
        32,
    )
}

pub fn derive_sponsor_reservation_id(
    chain_id: &str,
    account_id: &str,
    epoch_id: &str,
    proof_id: Option<&str>,
    bundle_id: Option<&str>,
    sponsor_commitment: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-session-ratchet:sponsor-reservation-id",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(account_id),
            HashPart::Str(epoch_id),
            HashPart::Str(proof_id.unwrap_or("")),
            HashPart::Str(bundle_id.unwrap_or("")),
            HashPart::Str(sponsor_commitment),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn derive_receipt_id(
    chain_id: &str,
    bundle_id: &str,
    proof_id: &str,
    execution_root: &str,
    state_diff_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-session-ratchet:receipt-id",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(bundle_id),
            HashPart::Str(proof_id),
            HashPart::Str(execution_root),
            HashPart::Str(state_diff_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn derive_rebate_id(
    chain_id: &str,
    reservation_id: &str,
    sponsor_commitment: &str,
    amount: u128,
    height: u64,
) -> String {
    domain_hash(
        "private-session-ratchet:rebate-id",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(reservation_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Int(amount as i128),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn derive_slashing_evidence_id(
    chain_id: &str,
    account_id: &str,
    reason: SlashingReason,
    evidence_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "private-session-ratchet:slashing-evidence-id",
        &[
            HashPart::Str(chain_id),
            HashPart::Str(account_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn account_commitment(record: &Value) -> String {
    domain_hash(
        "private-session-ratchet:account-commitment",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn epoch_commitment(record: &Value) -> String {
    domain_hash(
        "private-session-ratchet:epoch-commitment",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn session_proof_commitment(record: &Value) -> String {
    domain_hash(
        "private-session-ratchet:session-proof-commitment",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn nullifier_fence_commitment(record: &Value) -> String {
    domain_hash(
        "private-session-ratchet:nullifier-fence-commitment",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn auth_bundle_commitment(record: &Value) -> String {
    domain_hash(
        "private-session-ratchet:auth-bundle-commitment",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn sponsor_reservation_commitment(record: &Value) -> String {
    domain_hash(
        "private-session-ratchet:sponsor-reservation-commitment",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn settlement_receipt_commitment(record: &Value) -> String {
    domain_hash(
        "private-session-ratchet:settlement-receipt-commitment",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn rebate_commitment(record: &Value) -> String {
    domain_hash(
        "private-session-ratchet:rebate-commitment",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn slashing_evidence_commitment(record: &Value) -> String {
    domain_hash(
        "private-session-ratchet:slashing-evidence-commitment",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn records_root(label: &str, records: Vec<Value>) -> String {
    merkle_root(&format!("private-session-ratchet:{label}"), &records)
}

pub fn require_nonempty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{name} must be nonempty"))
    } else {
        Ok(())
    }
}

pub fn require_bps(name: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{name} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}

pub fn require_privacy_set(config: &Config, privacy_set_size: u64) -> Result<()> {
    if privacy_set_size < config.min_privacy_set_size {
        Err(format!(
            "privacy_set_size {privacy_set_size} below minimum {}",
            config.min_privacy_set_size
        ))
    } else {
        Ok(())
    }
}

pub fn require_pq_strength(
    config: &Config,
    kem_algorithm: KemAlgorithm,
    signature_algorithm: SignatureAlgorithm,
) -> Result<()> {
    let security_bits = kem_algorithm
        .pq_security_bits()
        .min(signature_algorithm.pq_security_bits());
    if security_bits < config.min_pq_security_bits {
        Err(format!(
            "pq security bits {security_bits} below minimum {}",
            config.min_pq_security_bits
        ))
    } else {
        Ok(())
    }
}

pub fn ensure_capacity(name: &str, current: usize, max: usize) -> Result<()> {
    if current >= max {
        Err(format!("{name} capacity exceeded: {current}/{max}"))
    } else {
        Ok(())
    }
}

pub fn deterministic_scope_root(label: &str, commitments: &[String]) -> String {
    let leaves = commitments
        .iter()
        .map(|commitment| json!({ "label": label, "commitment": commitment }))
        .collect::<Vec<_>>();
    merkle_root(&format!("private-session-ratchet:scope:{label}"), &leaves)
}

pub fn deterministic_empty_root(label: &str) -> String {
    merkle_root(&format!("private-session-ratchet:empty:{label}"), &[])
}
