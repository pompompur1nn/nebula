use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivatePqMultisigSpendAuthorityResult<T> = Result<T, String>;
pub type SpendIntentId = String;
pub type CommitteeId = String;
pub type SignerId = String;
pub type AuthorizationId = String;
pub type Nullifier = String;
pub type PolicyId = String;
pub type SponsorshipId = String;
pub type ChallengeId = String;
pub type ReceiptId = String;
pub type EventId = String;

pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_PROTOCOL_VERSION: &str =
    "nebula-private-pq-multisig-spend-authority-v1";
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_ML_DSA_SUITE: &str =
    "ml-dsa-87-private-spend-authority-commitment-v1";
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_SLH_DSA_SUITE: &str =
    "slh-dsa-shake-256f-private-spend-authority-commitment-v1";
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_NULLIFIER_SUITE: &str =
    "shielded-nullifier-set-membership-v1";
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_RECEIPT_SUITE: &str = "zk-private-spend-receipt-v1";
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEVNET_HEIGHT: u64 = 4_096;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEFAULT_INTENT_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEFAULT_AUTHORIZATION_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEFAULT_MAX_FEE_BPS: u64 = 50;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEFAULT_SPONSOR_RESERVE_UNITS: u128 = 25_000_000_000;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_BPS: u64 = 10_000;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_SIGNERS: usize = 4_096;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_COMMITTEES: usize = 512;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_INTENTS: usize = 524_288;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_AUTHORIZATIONS: usize = 1_048_576;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_NULLIFIERS: usize = 1_048_576;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_POLICIES: usize = 65_536;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_SPONSORSHIPS: usize = 262_144;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_CHALLENGES: usize = 262_144;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_RECEIPTS: usize = 1_048_576;
pub const PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_EVENTS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSignatureScheme {
    MlDsa87,
    SlhDsaShake256f,
    HybridMlDsaSlhDsa,
}

impl PqSignatureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
            Self::HybridMlDsaSlhDsa => "hybrid_ml_dsa_slh_dsa",
        }
    }

    pub fn security_bits(self) -> u16 {
        match self {
            Self::MlDsa87 => 256,
            Self::SlhDsaShake256f => 256,
            Self::HybridMlDsaSlhDsa => 256,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Active,
    Rotating,
    Paused,
    Retired,
    Slashed,
}

impl CommitteeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Paused => "paused",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendIntentKind {
    MoneroExit,
    PrivateTransfer,
    ContractSpend,
    FeeSweep,
    RecoverySpend,
    TreasurySpend,
    EmergencyFreeze,
}

impl SpendIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroExit => "monero_exit",
            Self::PrivateTransfer => "private_transfer",
            Self::ContractSpend => "contract_spend",
            Self::FeeSweep => "fee_sweep",
            Self::RecoverySpend => "recovery_spend",
            Self::TreasurySpend => "treasury_spend",
            Self::EmergencyFreeze => "emergency_freeze",
        }
    }

    pub fn default_policy_tag(self) -> &'static str {
        match self {
            Self::MoneroExit => "monero-exit",
            Self::PrivateTransfer => "private-transfer",
            Self::ContractSpend => "contract-spend",
            Self::FeeSweep => "fee-sweep",
            Self::RecoverySpend => "recovery",
            Self::TreasurySpend => "treasury",
            Self::EmergencyFreeze => "emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendIntentStatus {
    Draft,
    Committed,
    AuthorizationOpen,
    Authorized,
    Submitted,
    Executed,
    Cancelled,
    Expired,
    Challenged,
    Rejected,
}

impl SpendIntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Committed => "committed",
            Self::AuthorizationOpen => "authorization_open",
            Self::Authorized => "authorized",
            Self::Submitted => "submitted",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::AuthorizationOpen | Self::Authorized | Self::Submitted
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationStatus {
    Pending,
    Counted,
    Superseded,
    Revoked,
    Expired,
    Slashed,
}

impl AuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Counted => "counted",
            Self::Superseded => "superseded",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn counts(self) -> bool {
        matches!(self, Self::Pending | Self::Counted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierStatus {
    Reserved,
    Spent,
    Released,
    Challenged,
    Burned,
}

impl NullifierStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Spent => "spent",
            Self::Released => "released",
            Self::Challenged => "challenged",
            Self::Burned => "burned",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelockMode {
    None,
    Relative,
    Absolute,
    EpochBoundary,
    ChallengeWindow,
}

impl TimelockMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Relative => "relative",
            Self::Absolute => "absolute",
            Self::EpochBoundary => "epoch_boundary",
            Self::ChallengeWindow => "challenge_window",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Offered,
    Locked,
    Used,
    Refunded,
    Expired,
    Slashed,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Locked => "locked",
            Self::Used => "used",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn available(self) -> bool {
        matches!(self, Self::Offered | Self::Locked)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Answered,
    Upheld,
    Dismissed,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Answered => "answered",
            Self::Upheld => "upheld",
            Self::Dismissed => "dismissed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Finalized,
    Reverted,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Finalized => "finalized",
            Self::Reverted => "reverted",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub protocol_id: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub ml_dsa_suite: String,
    pub slh_dsa_suite: String,
    pub nullifier_suite: String,
    pub receipt_suite: String,
    pub epoch_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub authorization_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub sponsor_reserve_units: u128,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_id: PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_SCHEMA_VERSION,
            hash_suite: PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_HASH_SUITE.to_string(),
            ml_dsa_suite: PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_ML_DSA_SUITE.to_string(),
            slh_dsa_suite: PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_SLH_DSA_SUITE.to_string(),
            nullifier_suite: PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_NULLIFIER_SUITE.to_string(),
            receipt_suite: PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_RECEIPT_SUITE.to_string(),
            epoch_blocks: PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEFAULT_EPOCH_BLOCKS,
            intent_ttl_blocks: PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEFAULT_INTENT_TTL_BLOCKS,
            authorization_ttl_blocks:
                PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEFAULT_AUTHORIZATION_TTL_BLOCKS,
            challenge_window_blocks:
                PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_privacy_set_size: PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_fee_bps: PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEFAULT_MAX_FEE_BPS,
            sponsor_reserve_units:
                PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEFAULT_SPONSOR_RESERVE_UNITS,
        }
    }

    pub fn validate(&self) -> PrivatePqMultisigSpendAuthorityResult<()> {
        if self.protocol_id != PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_PROTOCOL_VERSION {
            return Err("private pq multisig spend authority protocol id mismatch".to_string());
        }
        if self.schema_version == 0 {
            return Err("schema version must be nonzero".to_string());
        }
        if self.epoch_blocks == 0 {
            return Err("epoch blocks must be nonzero".to_string());
        }
        if self.intent_ttl_blocks == 0 {
            return Err("intent ttl blocks must be nonzero".to_string());
        }
        if self.authorization_ttl_blocks == 0 {
            return Err("authorization ttl blocks must be nonzero".to_string());
        }
        if self.challenge_window_blocks == 0 {
            return Err("challenge window blocks must be nonzero".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("minimum privacy set size must be nonzero".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("minimum pq security bits must be at least 128".to_string());
        }
        if self.max_fee_bps > PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_BPS {
            return Err("max fee bps exceeds denominator".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_id": self.protocol_id,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "ml_dsa_suite": self.ml_dsa_suite,
            "slh_dsa_suite": self.slh_dsa_suite,
            "nullifier_suite": self.nullifier_suite,
            "receipt_suite": self.receipt_suite,
            "epoch_blocks": self.epoch_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "authorization_ttl_blocks": self.authorization_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "sponsor_reserve_units": self.sponsor_reserve_units.to_string(),
        })
    }

    pub fn root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqSigner {
    pub signer_id: SignerId,
    pub label: String,
    pub scheme: PqSignatureScheme,
    pub ml_dsa_public_commitment: String,
    pub slh_dsa_public_commitment: String,
    pub privacy_group_commitment: String,
    pub weight: u64,
    pub active_from_height: u64,
    pub active_until_height: Option<u64>,
    pub revoked: bool,
}

impl PqSigner {
    pub fn new(
        label: &str,
        scheme: PqSignatureScheme,
        privacy_group_commitment: &str,
        weight: u64,
        active_from_height: u64,
    ) -> Self {
        let ml_dsa_public_commitment = labeled_commitment("ML-DSA-PUBLIC", label);
        let slh_dsa_public_commitment = labeled_commitment("SLH-DSA-PUBLIC", label);
        let signer_id = signer_id(
            label,
            scheme,
            &ml_dsa_public_commitment,
            &slh_dsa_public_commitment,
            privacy_group_commitment,
        );
        Self {
            signer_id,
            label: label.to_string(),
            scheme,
            ml_dsa_public_commitment,
            slh_dsa_public_commitment,
            privacy_group_commitment: privacy_group_commitment.to_string(),
            weight,
            active_from_height,
            active_until_height: None,
            revoked: false,
        }
    }

    pub fn usable_at(&self, height: u64, min_security_bits: u16) -> bool {
        if self.revoked || self.weight == 0 || self.scheme.security_bits() < min_security_bits {
            return false;
        }
        if height < self.active_from_height {
            return false;
        }
        match self.active_until_height {
            Some(until) => height <= until,
            None => true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signer_id": self.signer_id,
            "label": self.label,
            "scheme": self.scheme.as_str(),
            "ml_dsa_public_commitment": self.ml_dsa_public_commitment,
            "slh_dsa_public_commitment": self.slh_dsa_public_commitment,
            "privacy_group_commitment": self.privacy_group_commitment,
            "weight": self.weight,
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
            "revoked": self.revoked,
        })
    }

    pub fn root(&self) -> String {
        record_root("SIGNER", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignerCommittee {
    pub committee_id: CommitteeId,
    pub label: String,
    pub epoch: u64,
    pub status: CommitteeStatus,
    pub threshold_weight: u64,
    pub signer_ids: BTreeSet<SignerId>,
    pub policy_ids: BTreeSet<PolicyId>,
    pub aggregate_public_key_commitment: String,
    pub rotation_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl SignerCommittee {
    pub fn new(
        label: &str,
        epoch: u64,
        threshold_weight: u64,
        signer_ids: BTreeSet<SignerId>,
        policy_ids: BTreeSet<PolicyId>,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let signer_root = merkle_root(
            "PRIVATE-PQ-MULTISIG-COMMITTEE-SIGNER",
            &string_values(&signer_ids),
        );
        let policy_root = merkle_root(
            "PRIVATE-PQ-MULTISIG-COMMITTEE-POLICY",
            &string_values(&policy_ids),
        );
        let aggregate_public_key_commitment = record_root(
            "COMMITTEE-AGGREGATE-PUBLIC-KEY",
            &json!({
                "label": label,
                "epoch": epoch,
                "signer_root": signer_root,
                "policy_root": policy_root,
            }),
        );
        let rotation_root = record_root(
            "COMMITTEE-ROTATION",
            &json!({
                "label": label,
                "epoch": epoch,
                "opened_at_height": opened_at_height,
                "expires_at_height": expires_at_height,
            }),
        );
        let committee_id = committee_id(label, epoch, &aggregate_public_key_commitment);
        Self {
            committee_id,
            label: label.to_string(),
            epoch,
            status: CommitteeStatus::Active,
            threshold_weight,
            signer_ids,
            policy_ids,
            aggregate_public_key_commitment,
            rotation_root,
            opened_at_height,
            expires_at_height,
        }
    }

    pub fn signer_root(&self) -> String {
        merkle_root(
            "PRIVATE-PQ-MULTISIG-COMMITTEE-SIGNER",
            &string_values(&self.signer_ids),
        )
    }

    pub fn policy_root(&self) -> String {
        merkle_root(
            "PRIVATE-PQ-MULTISIG-COMMITTEE-POLICY",
            &string_values(&self.policy_ids),
        )
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.accepts_intents()
            && self.opened_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "label": self.label,
            "epoch": self.epoch,
            "status": self.status.as_str(),
            "threshold_weight": self.threshold_weight,
            "signer_ids": self.signer_ids.iter().cloned().collect::<Vec<_>>(),
            "policy_ids": self.policy_ids.iter().cloned().collect::<Vec<_>>(),
            "signer_root": self.signer_root(),
            "policy_root": self.policy_root(),
            "aggregate_public_key_commitment": self.aggregate_public_key_commitment,
            "rotation_root": self.rotation_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("COMMITTEE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpendingPolicy {
    pub policy_id: PolicyId,
    pub tag: String,
    pub mode: TimelockMode,
    pub min_unlock_height: u64,
    pub relative_delay_blocks: u64,
    pub max_amount_units: u128,
    pub max_fee_bps: u64,
    pub allowed_asset_ids: BTreeSet<String>,
    pub required_privacy_set_size: u64,
    pub require_fee_sponsor: bool,
    pub challenge_window_blocks: u64,
}

impl SpendingPolicy {
    pub fn new(
        tag: &str,
        mode: TimelockMode,
        min_unlock_height: u64,
        relative_delay_blocks: u64,
        max_amount_units: u128,
        max_fee_bps: u64,
        allowed_asset_ids: BTreeSet<String>,
        required_privacy_set_size: u64,
        require_fee_sponsor: bool,
        challenge_window_blocks: u64,
    ) -> Self {
        let policy_id = policy_id(tag, mode, min_unlock_height, max_amount_units);
        Self {
            policy_id,
            tag: tag.to_string(),
            mode,
            min_unlock_height,
            relative_delay_blocks,
            max_amount_units,
            max_fee_bps,
            allowed_asset_ids,
            required_privacy_set_size,
            require_fee_sponsor,
            challenge_window_blocks,
        }
    }

    pub fn accepts(&self, intent: &SpendIntent, current_height: u64) -> bool {
        if intent.amount_units > self.max_amount_units || intent.max_fee_bps > self.max_fee_bps {
            return false;
        }
        if !self.allowed_asset_ids.is_empty() && !self.allowed_asset_ids.contains(&intent.asset_id)
        {
            return false;
        }
        if intent.privacy_set_size < self.required_privacy_set_size {
            return false;
        }
        match self.mode {
            TimelockMode::None => true,
            TimelockMode::Absolute => current_height >= self.min_unlock_height,
            TimelockMode::Relative => {
                current_height
                    >= intent
                        .created_at_height
                        .saturating_add(self.relative_delay_blocks)
            }
            TimelockMode::EpochBoundary => {
                current_height >= self.min_unlock_height
                    && current_height >= intent.valid_after_height
            }
            TimelockMode::ChallengeWindow => current_height >= intent.challenge_deadline_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "tag": self.tag,
            "mode": self.mode.as_str(),
            "min_unlock_height": self.min_unlock_height,
            "relative_delay_blocks": self.relative_delay_blocks,
            "max_amount_units": self.max_amount_units.to_string(),
            "max_fee_bps": self.max_fee_bps,
            "allowed_asset_ids": self.allowed_asset_ids.iter().cloned().collect::<Vec<_>>(),
            "required_privacy_set_size": self.required_privacy_set_size,
            "require_fee_sponsor": self.require_fee_sponsor,
            "challenge_window_blocks": self.challenge_window_blocks,
        })
    }

    pub fn root(&self) -> String {
        record_root("POLICY", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpendIntent {
    pub intent_id: SpendIntentId,
    pub kind: SpendIntentKind,
    pub status: SpendIntentStatus,
    pub account_commitment: String,
    pub asset_id: String,
    pub amount_units: u128,
    pub recipient_commitment: String,
    pub encrypted_payload_hash: String,
    pub spend_note_commitment: String,
    pub policy_id: PolicyId,
    pub committee_id: CommitteeId,
    pub privacy_set_size: u64,
    pub nullifier_commitment: Nullifier,
    pub max_fee_bps: u64,
    pub sponsor_id: Option<SponsorshipId>,
    pub created_at_height: u64,
    pub valid_after_height: u64,
    pub expires_at_height: u64,
    pub challenge_deadline_height: u64,
}

impl SpendIntent {
    pub fn new(
        kind: SpendIntentKind,
        account_commitment: &str,
        asset_id: &str,
        amount_units: u128,
        recipient_commitment: &str,
        policy_id: &str,
        committee_id: &str,
        privacy_set_size: u64,
        max_fee_bps: u64,
        created_at_height: u64,
        config: &Config,
    ) -> Self {
        let encrypted_payload_hash =
            labeled_commitment("ENCRYPTED-SPEND-PAYLOAD", account_commitment);
        let spend_note_commitment = labeled_commitment("SPEND-NOTE", recipient_commitment);
        let nullifier_commitment = nullifier_for(
            account_commitment,
            &spend_note_commitment,
            created_at_height,
        );
        let valid_after_height = created_at_height;
        let expires_at_height = created_at_height.saturating_add(config.intent_ttl_blocks);
        let challenge_deadline_height =
            created_at_height.saturating_add(config.challenge_window_blocks);
        let intent_id = spend_intent_id(
            kind,
            account_commitment,
            asset_id,
            amount_units,
            &nullifier_commitment,
            created_at_height,
        );
        Self {
            intent_id,
            kind,
            status: SpendIntentStatus::Committed,
            account_commitment: account_commitment.to_string(),
            asset_id: asset_id.to_string(),
            amount_units,
            recipient_commitment: recipient_commitment.to_string(),
            encrypted_payload_hash,
            spend_note_commitment,
            policy_id: policy_id.to_string(),
            committee_id: committee_id.to_string(),
            privacy_set_size,
            nullifier_commitment,
            max_fee_bps,
            sponsor_id: None,
            created_at_height,
            valid_after_height,
            expires_at_height,
            challenge_deadline_height,
        }
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "account_commitment": self.account_commitment,
            "asset_id": self.asset_id,
            "amount_units": self.amount_units.to_string(),
            "recipient_commitment": self.recipient_commitment,
            "encrypted_payload_hash": self.encrypted_payload_hash,
            "spend_note_commitment": self.spend_note_commitment,
            "policy_id": self.policy_id,
            "committee_id": self.committee_id,
            "privacy_set_size": self.privacy_set_size,
            "nullifier_commitment": self.nullifier_commitment,
            "max_fee_bps": self.max_fee_bps,
            "sponsor_id": self.sponsor_id,
            "created_at_height": self.created_at_height,
            "valid_after_height": self.valid_after_height,
            "expires_at_height": self.expires_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("SPEND-INTENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationCommitment {
    pub authorization_id: AuthorizationId,
    pub intent_id: SpendIntentId,
    pub committee_id: CommitteeId,
    pub signer_id: SignerId,
    pub scheme: PqSignatureScheme,
    pub ml_dsa_authorization_commitment: String,
    pub slh_dsa_authorization_commitment: String,
    pub signature_transcript_hash: String,
    pub signer_privacy_nullifier: String,
    pub weight: u64,
    pub status: AuthorizationStatus,
    pub authorized_at_height: u64,
    pub expires_at_height: u64,
}

impl AuthorizationCommitment {
    pub fn new(
        intent: &SpendIntent,
        signer: &PqSigner,
        committee_id: &str,
        weight: u64,
        height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let signature_transcript_hash = record_root(
            "AUTHORIZATION-TRANSCRIPT",
            &json!({
                "intent_id": intent.intent_id,
                "signer_id": signer.signer_id,
                "committee_id": committee_id,
                "height": height,
            }),
        );
        let ml_dsa_authorization_commitment = authorization_commitment(
            "ML-DSA-AUTHORIZATION",
            &intent.intent_id,
            &signer.signer_id,
            &signature_transcript_hash,
        );
        let slh_dsa_authorization_commitment = authorization_commitment(
            "SLH-DSA-AUTHORIZATION",
            &intent.intent_id,
            &signer.signer_id,
            &signature_transcript_hash,
        );
        let signer_privacy_nullifier = authorization_commitment(
            "SIGNER-PRIVACY-NULLIFIER",
            &intent.intent_id,
            &signer.privacy_group_commitment,
            &signature_transcript_hash,
        );
        let authorization_id = authorization_id(
            &intent.intent_id,
            committee_id,
            &signer.signer_id,
            &signature_transcript_hash,
        );
        Self {
            authorization_id,
            intent_id: intent.intent_id.clone(),
            committee_id: committee_id.to_string(),
            signer_id: signer.signer_id.clone(),
            scheme: signer.scheme,
            ml_dsa_authorization_commitment,
            slh_dsa_authorization_commitment,
            signature_transcript_hash,
            signer_privacy_nullifier,
            weight,
            status: AuthorizationStatus::Counted,
            authorized_at_height: height,
            expires_at_height: height.saturating_add(ttl_blocks),
        }
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.counts() && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "intent_id": self.intent_id,
            "committee_id": self.committee_id,
            "signer_id": self.signer_id,
            "scheme": self.scheme.as_str(),
            "ml_dsa_authorization_commitment": self.ml_dsa_authorization_commitment,
            "slh_dsa_authorization_commitment": self.slh_dsa_authorization_commitment,
            "signature_transcript_hash": self.signature_transcript_hash,
            "signer_privacy_nullifier": self.signer_privacy_nullifier,
            "weight": self.weight,
            "status": self.status.as_str(),
            "authorized_at_height": self.authorized_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("AUTHORIZATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyNullifierRecord {
    pub nullifier: Nullifier,
    pub intent_id: SpendIntentId,
    pub account_set_root: String,
    pub note_commitment: String,
    pub status: NullifierStatus,
    pub reserved_at_height: u64,
    pub spent_at_height: Option<u64>,
}

impl PrivacyNullifierRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier": self.nullifier,
            "intent_id": self.intent_id,
            "account_set_root": self.account_set_root,
            "note_commitment": self.note_commitment,
            "status": self.status.as_str(),
            "reserved_at_height": self.reserved_at_height,
            "spent_at_height": self.spent_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("NULLIFIER", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeSponsorship {
    pub sponsorship_id: SponsorshipId,
    pub intent_id: SpendIntentId,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_units: u128,
    pub reserve_units: u128,
    pub status: SponsorshipStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeSponsorship {
    pub fn new(
        intent_id: &str,
        sponsor_commitment: &str,
        fee_asset_id: &str,
        max_fee_units: u128,
        reserve_units: u128,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let sponsorship_id = sponsorship_id(
            intent_id,
            sponsor_commitment,
            fee_asset_id,
            max_fee_units,
            opened_at_height,
        );
        Self {
            sponsorship_id,
            intent_id: intent_id.to_string(),
            sponsor_commitment: sponsor_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_units,
            reserve_units,
            status: SponsorshipStatus::Locked,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
        }
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.available() && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "intent_id": self.intent_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units.to_string(),
            "reserve_units": self.reserve_units.to_string(),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("FEE-SPONSORSHIP", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChallengeWindow {
    pub challenge_id: ChallengeId,
    pub intent_id: SpendIntentId,
    pub challenger_commitment: String,
    pub challenge_kind: String,
    pub evidence_root: String,
    pub status: ChallengeStatus,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub bond_units: u128,
}

impl ChallengeWindow {
    pub fn new(
        intent_id: &str,
        challenger_commitment: &str,
        challenge_kind: &str,
        evidence_root: &str,
        opened_at_height: u64,
        window_blocks: u64,
        bond_units: u128,
    ) -> Self {
        let deadline_height = opened_at_height.saturating_add(window_blocks);
        let challenge_id = challenge_id(
            intent_id,
            challenger_commitment,
            challenge_kind,
            evidence_root,
            opened_at_height,
        );
        Self {
            challenge_id,
            intent_id: intent_id.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            challenge_kind: challenge_kind.to_string(),
            evidence_root: evidence_root.to_string(),
            status: ChallengeStatus::Open,
            opened_at_height,
            deadline_height,
            bond_units,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "intent_id": self.intent_id,
            "challenger_commitment": self.challenger_commitment,
            "challenge_kind": self.challenge_kind,
            "evidence_root": self.evidence_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "bond_units": self.bond_units.to_string(),
        })
    }

    pub fn root(&self) -> String {
        record_root("CHALLENGE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpendReceipt {
    pub receipt_id: ReceiptId,
    pub intent_id: SpendIntentId,
    pub committee_id: CommitteeId,
    pub authorization_root: String,
    pub nullifier: Nullifier,
    pub settlement_tx_commitment: String,
    pub fee_paid_units: u128,
    pub sponsor_id: Option<SponsorshipId>,
    pub status: ReceiptStatus,
    pub executed_at_height: u64,
    pub challenge_deadline_height: u64,
}

impl SpendReceipt {
    pub fn new(
        intent: &SpendIntent,
        authorization_root: &str,
        settlement_tx_commitment: &str,
        fee_paid_units: u128,
        executed_at_height: u64,
    ) -> Self {
        let challenge_deadline_height = executed_at_height
            .saturating_add(PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEFAULT_CHALLENGE_WINDOW_BLOCKS);
        let receipt_id = receipt_id(
            &intent.intent_id,
            &intent.nullifier_commitment,
            settlement_tx_commitment,
            executed_at_height,
        );
        Self {
            receipt_id,
            intent_id: intent.intent_id.clone(),
            committee_id: intent.committee_id.clone(),
            authorization_root: authorization_root.to_string(),
            nullifier: intent.nullifier_commitment.clone(),
            settlement_tx_commitment: settlement_tx_commitment.to_string(),
            fee_paid_units,
            sponsor_id: intent.sponsor_id.clone(),
            status: ReceiptStatus::Finalized,
            executed_at_height,
            challenge_deadline_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "intent_id": self.intent_id,
            "committee_id": self.committee_id,
            "authorization_root": self.authorization_root,
            "nullifier": self.nullifier,
            "settlement_tx_commitment": self.settlement_tx_commitment,
            "fee_paid_units": self.fee_paid_units.to_string(),
            "sponsor_id": self.sponsor_id,
            "status": self.status.as_str(),
            "executed_at_height": self.executed_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub event_id: EventId,
    pub subject_kind: String,
    pub subject_id: String,
    pub event_kind: String,
    pub record_root: String,
    pub height: u64,
}

impl AuditEvent {
    pub fn new(
        subject_kind: &str,
        subject_id: &str,
        event_kind: &str,
        record_root: &str,
        height: u64,
    ) -> Self {
        let event_id = event_id(subject_kind, subject_id, event_kind, record_root, height);
        Self {
            event_id,
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            event_kind: event_kind.to_string(),
            record_root: record_root.to_string(),
            height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "event_kind": self.event_kind,
            "record_root": self.record_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roots {
    pub config_root: String,
    pub signer_root: String,
    pub committee_root: String,
    pub policy_root: String,
    pub intent_root: String,
    pub authorization_root: String,
    pub nullifier_root: String,
    pub sponsorship_root: String,
    pub challenge_root: String,
    pub receipt_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "signer_root": self.signer_root,
            "committee_root": self.committee_root,
            "policy_root": self.policy_root,
            "intent_root": self.intent_root,
            "authorization_root": self.authorization_root,
            "nullifier_root": self.nullifier_root,
            "sponsorship_root": self.sponsorship_root,
            "challenge_root": self.challenge_root,
            "receipt_root": self.receipt_root,
            "event_root": self.event_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(map) = record.as_object_mut() {
            map.insert(
                "state_root".to_string(),
                Value::String(self.state_root.clone()),
            );
        }
        record
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    pub signer_count: usize,
    pub committee_count: usize,
    pub policy_count: usize,
    pub intent_count: usize,
    pub active_intent_count: usize,
    pub authorization_count: usize,
    pub counted_authorization_count: usize,
    pub nullifier_count: usize,
    pub spent_nullifier_count: usize,
    pub sponsorship_count: usize,
    pub active_sponsorship_count: usize,
    pub open_challenge_count: usize,
    pub receipt_count: usize,
    pub event_count: usize,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "signer_count": self.signer_count,
            "committee_count": self.committee_count,
            "policy_count": self.policy_count,
            "intent_count": self.intent_count,
            "active_intent_count": self.active_intent_count,
            "authorization_count": self.authorization_count,
            "counted_authorization_count": self.counted_authorization_count,
            "nullifier_count": self.nullifier_count,
            "spent_nullifier_count": self.spent_nullifier_count,
            "sponsorship_count": self.sponsorship_count,
            "active_sponsorship_count": self.active_sponsorship_count,
            "open_challenge_count": self.open_challenge_count,
            "receipt_count": self.receipt_count,
            "event_count": self.event_count,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub chain_id: String,
    pub height: u64,
    pub config: Config,
    pub signers: BTreeMap<SignerId, PqSigner>,
    pub committees: BTreeMap<CommitteeId, SignerCommittee>,
    pub policies: BTreeMap<PolicyId, SpendingPolicy>,
    pub intents: BTreeMap<SpendIntentId, SpendIntent>,
    pub authorizations: BTreeMap<AuthorizationId, AuthorizationCommitment>,
    pub nullifiers: BTreeMap<Nullifier, PrivacyNullifierRecord>,
    pub sponsorships: BTreeMap<SponsorshipId, FeeSponsorship>,
    pub challenges: BTreeMap<ChallengeId, ChallengeWindow>,
    pub receipts: BTreeMap<ReceiptId, SpendReceipt>,
    pub events: BTreeMap<EventId, AuditEvent>,
}

impl State {
    pub fn devnet() -> PrivatePqMultisigSpendAuthorityResult<State> {
        let config = Config::devnet();
        let mut state = State {
            chain_id: CHAIN_ID.to_string(),
            height: PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_DEVNET_HEIGHT,
            config,
            signers: BTreeMap::new(),
            committees: BTreeMap::new(),
            policies: BTreeMap::new(),
            intents: BTreeMap::new(),
            authorizations: BTreeMap::new(),
            nullifiers: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            challenges: BTreeMap::new(),
            receipts: BTreeMap::new(),
            events: BTreeMap::new(),
        };

        let assets = btree_set(&["dxmr-devnet", "piconero-devnet", "dusd-devnet"]);
        let monero_policy = SpendingPolicy::new(
            SpendIntentKind::MoneroExit.default_policy_tag(),
            TimelockMode::None,
            state.height,
            0,
            50_000_000_000_000,
            20,
            assets.clone(),
            state.config.min_privacy_set_size,
            true,
            state.config.challenge_window_blocks,
        );
        let treasury_policy = SpendingPolicy::new(
            SpendIntentKind::TreasurySpend.default_policy_tag(),
            TimelockMode::Relative,
            state.height,
            32,
            250_000_000_000_000,
            10,
            assets.clone(),
            state.config.min_privacy_set_size.saturating_mul(2),
            true,
            state.config.challenge_window_blocks,
        );
        let recovery_policy = SpendingPolicy::new(
            SpendIntentKind::RecoverySpend.default_policy_tag(),
            TimelockMode::Absolute,
            state.height.saturating_sub(1),
            0,
            25_000_000_000_000,
            30,
            assets,
            state.config.min_privacy_set_size,
            false,
            state.config.challenge_window_blocks,
        );
        state.insert_policy(monero_policy)?;
        state.insert_policy(treasury_policy)?;
        state.insert_policy(recovery_policy)?;

        let signer_a = PqSigner::new(
            "devnet-spend-authority-a",
            PqSignatureScheme::HybridMlDsaSlhDsa,
            "devnet-privacy-group-alpha",
            40,
            state.height.saturating_sub(64),
        );
        let signer_b = PqSigner::new(
            "devnet-spend-authority-b",
            PqSignatureScheme::MlDsa87,
            "devnet-privacy-group-alpha",
            35,
            state.height.saturating_sub(64),
        );
        let signer_c = PqSigner::new(
            "devnet-spend-authority-c",
            PqSignatureScheme::SlhDsaShake256f,
            "devnet-privacy-group-beta",
            30,
            state.height.saturating_sub(64),
        );
        let signer_d = PqSigner::new(
            "devnet-spend-authority-d",
            PqSignatureScheme::HybridMlDsaSlhDsa,
            "devnet-privacy-group-beta",
            25,
            state.height.saturating_sub(64),
        );
        let signer_ids = vec![
            signer_a.signer_id.clone(),
            signer_b.signer_id.clone(),
            signer_c.signer_id.clone(),
            signer_d.signer_id.clone(),
        ];
        state.insert_signer(signer_a)?;
        state.insert_signer(signer_b)?;
        state.insert_signer(signer_c)?;
        state.insert_signer(signer_d)?;

        let policy_ids = state.policies.keys().cloned().collect::<BTreeSet<_>>();
        let committee = SignerCommittee::new(
            "devnet-private-spend-authority",
            state.height / state.config.epoch_blocks,
            75,
            signer_ids.iter().cloned().collect::<BTreeSet<_>>(),
            policy_ids,
            state.height.saturating_sub(32),
            state.height.saturating_add(state.config.epoch_blocks),
        );
        let committee_id = committee.committee_id.clone();
        state.insert_committee(committee)?;

        let policy_id = state
            .policies
            .values()
            .find(|policy| policy.tag == "monero-exit")
            .map(|policy| policy.policy_id.clone())
            .ok_or_else(|| "devnet monero policy missing".to_string())?;
        let mut intent = SpendIntent::new(
            SpendIntentKind::MoneroExit,
            "devnet-account-commitment-alpha",
            "dxmr-devnet",
            12_500_000_000,
            "devnet-recipient-stealth-commitment-alpha",
            &policy_id,
            &committee_id,
            256,
            8,
            state.height.saturating_sub(8),
            &state.config,
        );
        let sponsor = FeeSponsorship::new(
            &intent.intent_id,
            "devnet-fee-sponsor-alpha",
            "piconero-devnet",
            50_000_000,
            state.config.sponsor_reserve_units,
            state.height.saturating_sub(7),
            state.config.intent_ttl_blocks,
        );
        intent.sponsor_id = Some(sponsor.sponsorship_id.clone());
        state.insert_intent(intent.clone())?;
        state.insert_sponsorship(sponsor)?;

        for signer_id in signer_ids.iter().take(3) {
            let signer = state
                .signers
                .get(signer_id)
                .cloned()
                .ok_or_else(|| format!("devnet signer {signer_id} missing"))?;
            let authorization = AuthorizationCommitment::new(
                &intent,
                &signer,
                &committee_id,
                signer.weight,
                state.height.saturating_sub(4),
                state.config.authorization_ttl_blocks,
            );
            state.insert_authorization(authorization)?;
        }
        let authorization_root = state.intent_authorization_root(&intent.intent_id);
        let mut receipt = SpendReceipt::new(
            &intent,
            &authorization_root,
            &labeled_commitment("DEVNET-SETTLEMENT-TX", &intent.intent_id),
            12_000_000,
            state.height,
        );
        receipt.challenge_deadline_height = state
            .height
            .saturating_add(state.config.challenge_window_blocks);
        state.insert_receipt(receipt)?;

        let challenge = ChallengeWindow::new(
            &intent.intent_id,
            "devnet-watchtower-privacy-sentinel",
            "receipt-finality-window",
            &labeled_commitment("DEVNET-CHALLENGE-EVIDENCE", &intent.intent_id),
            state.height,
            state.config.challenge_window_blocks,
            2_000_000_000,
        );
        state.insert_challenge(challenge)?;

        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> PrivatePqMultisigSpendAuthorityResult<()> {
        if self.chain_id != CHAIN_ID {
            return Err("chain id mismatch".to_string());
        }
        self.config.validate()?;
        if self.signers.len() > PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_SIGNERS {
            return Err("too many signers".to_string());
        }
        if self.committees.len() > PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_COMMITTEES {
            return Err("too many committees".to_string());
        }
        if self.policies.len() > PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_POLICIES {
            return Err("too many policies".to_string());
        }
        if self.intents.len() > PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_INTENTS {
            return Err("too many intents".to_string());
        }
        if self.authorizations.len() > PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_AUTHORIZATIONS {
            return Err("too many authorizations".to_string());
        }
        if self.nullifiers.len() > PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_NULLIFIERS {
            return Err("too many nullifiers".to_string());
        }
        if self.sponsorships.len() > PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_SPONSORSHIPS {
            return Err("too many sponsorships".to_string());
        }
        if self.challenges.len() > PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_CHALLENGES {
            return Err("too many challenges".to_string());
        }
        if self.receipts.len() > PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_RECEIPTS {
            return Err("too many receipts".to_string());
        }
        if self.events.len() > PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_MAX_EVENTS {
            return Err("too many events".to_string());
        }

        for (signer_id, signer) in &self.signers {
            if signer_id != &signer.signer_id {
                return Err(format!("signer key mismatch for {signer_id}"));
            }
            if signer.weight == 0 {
                return Err(format!("signer {signer_id} has zero weight"));
            }
        }
        for (policy_id, policy) in &self.policies {
            if policy_id != &policy.policy_id {
                return Err(format!("policy key mismatch for {policy_id}"));
            }
            if policy.max_fee_bps > self.config.max_fee_bps {
                return Err(format!("policy {policy_id} fee exceeds config max"));
            }
            if policy.required_privacy_set_size < self.config.min_privacy_set_size {
                return Err(format!("policy {policy_id} privacy set too small"));
            }
        }
        for (committee_id, committee) in &self.committees {
            if committee_id != &committee.committee_id {
                return Err(format!("committee key mismatch for {committee_id}"));
            }
            if committee.threshold_weight == 0 {
                return Err(format!("committee {committee_id} has zero threshold"));
            }
            if committee.opened_at_height > committee.expires_at_height {
                return Err(format!(
                    "committee {committee_id} has invalid height window"
                ));
            }
            let mut total_weight = 0_u64;
            for signer_id in &committee.signer_ids {
                let signer = self.signers.get(signer_id).ok_or_else(|| {
                    format!("committee {committee_id} references missing signer {signer_id}")
                })?;
                total_weight = total_weight.saturating_add(signer.weight);
            }
            if total_weight < committee.threshold_weight {
                return Err(format!(
                    "committee {committee_id} threshold exceeds signer weight"
                ));
            }
            for policy_id in &committee.policy_ids {
                if !self.policies.contains_key(policy_id) {
                    return Err(format!(
                        "committee {committee_id} references missing policy {policy_id}"
                    ));
                }
            }
        }
        let mut seen_intent_nullifiers = BTreeSet::new();
        for (intent_id, intent) in &self.intents {
            if intent_id != &intent.intent_id {
                return Err(format!("intent key mismatch for {intent_id}"));
            }
            if !self.committees.contains_key(&intent.committee_id) {
                return Err(format!("intent {intent_id} references missing committee"));
            }
            let policy = self
                .policies
                .get(&intent.policy_id)
                .ok_or_else(|| format!("intent {intent_id} references missing policy"))?;
            if intent.max_fee_bps > self.config.max_fee_bps {
                return Err(format!("intent {intent_id} max fee exceeds config"));
            }
            if intent.privacy_set_size < self.config.min_privacy_set_size {
                return Err(format!(
                    "intent {intent_id} privacy set below config minimum"
                ));
            }
            if !policy.accepts(intent, self.height) && intent.status.active() {
                return Err(format!("active intent {intent_id} does not satisfy policy"));
            }
            if !seen_intent_nullifiers.insert(intent.nullifier_commitment.clone()) {
                return Err(format!(
                    "duplicate intent nullifier {}",
                    intent.nullifier_commitment
                ));
            }
            if !self.nullifiers.contains_key(&intent.nullifier_commitment) {
                return Err(format!("intent {intent_id} has no nullifier reservation"));
            }
            if policy.require_fee_sponsor && intent.sponsor_id.is_none() {
                return Err(format!("intent {intent_id} requires fee sponsor"));
            }
            if let Some(sponsor_id) = &intent.sponsor_id {
                let sponsorship = self
                    .sponsorships
                    .get(sponsor_id)
                    .ok_or_else(|| format!("intent {intent_id} references missing sponsorship"))?;
                if sponsorship.intent_id != *intent_id {
                    return Err(format!("intent {intent_id} sponsorship points elsewhere"));
                }
            }
        }
        for (authorization_id, authorization) in &self.authorizations {
            if authorization_id != &authorization.authorization_id {
                return Err(format!("authorization key mismatch for {authorization_id}"));
            }
            let intent = self.intents.get(&authorization.intent_id).ok_or_else(|| {
                format!("authorization {authorization_id} references missing intent")
            })?;
            let committee = self
                .committees
                .get(&authorization.committee_id)
                .ok_or_else(|| {
                    format!("authorization {authorization_id} references missing committee")
                })?;
            let signer = self.signers.get(&authorization.signer_id).ok_or_else(|| {
                format!("authorization {authorization_id} references missing signer")
            })?;
            if authorization.committee_id != intent.committee_id {
                return Err(format!(
                    "authorization {authorization_id} committee does not match intent"
                ));
            }
            if !committee.signer_ids.contains(&authorization.signer_id) {
                return Err(format!(
                    "authorization {authorization_id} signer not in committee"
                ));
            }
            if authorization.scheme != signer.scheme {
                return Err(format!(
                    "authorization {authorization_id} signer scheme mismatch"
                ));
            }
        }
        for (nullifier, record) in &self.nullifiers {
            if nullifier != &record.nullifier {
                return Err(format!("nullifier key mismatch for {nullifier}"));
            }
            if !self.intents.contains_key(&record.intent_id) {
                return Err(format!("nullifier {nullifier} references missing intent"));
            }
        }
        for (sponsorship_id, sponsorship) in &self.sponsorships {
            if sponsorship_id != &sponsorship.sponsorship_id {
                return Err(format!("sponsorship key mismatch for {sponsorship_id}"));
            }
            if sponsorship.reserve_units < self.config.sponsor_reserve_units {
                return Err(format!(
                    "sponsorship {sponsorship_id} reserve below minimum"
                ));
            }
            if !self.intents.contains_key(&sponsorship.intent_id) {
                return Err(format!(
                    "sponsorship {sponsorship_id} references missing intent"
                ));
            }
        }
        for (challenge_id, challenge) in &self.challenges {
            if challenge_id != &challenge.challenge_id {
                return Err(format!("challenge key mismatch for {challenge_id}"));
            }
            if !self.intents.contains_key(&challenge.intent_id) {
                return Err(format!(
                    "challenge {challenge_id} references missing intent"
                ));
            }
            if challenge.deadline_height < challenge.opened_at_height {
                return Err(format!("challenge {challenge_id} has invalid deadline"));
            }
        }
        for (receipt_id, receipt) in &self.receipts {
            if receipt_id != &receipt.receipt_id {
                return Err(format!("receipt key mismatch for {receipt_id}"));
            }
            if !self.intents.contains_key(&receipt.intent_id) {
                return Err(format!("receipt {receipt_id} references missing intent"));
            }
            if !self.nullifiers.contains_key(&receipt.nullifier) {
                return Err(format!("receipt {receipt_id} references missing nullifier"));
            }
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> PrivatePqMultisigSpendAuthorityResult<()> {
        self.height = height;
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> PrivatePqMultisigSpendAuthorityResult<()> {
        if height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = height;
        self.expire_records();
        self.validate()
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.root();
        let signer_root = merkle_root(
            "PRIVATE-PQ-MULTISIG-SIGNER",
            &map_records(&self.signers, |v| v.public_record()),
        );
        let committee_root = merkle_root(
            "PRIVATE-PQ-MULTISIG-COMMITTEE",
            &map_records(&self.committees, |v| v.public_record()),
        );
        let policy_root = merkle_root(
            "PRIVATE-PQ-MULTISIG-POLICY",
            &map_records(&self.policies, |v| v.public_record()),
        );
        let intent_root = merkle_root(
            "PRIVATE-PQ-MULTISIG-INTENT",
            &map_records(&self.intents, |v| v.public_record()),
        );
        let authorization_root = merkle_root(
            "PRIVATE-PQ-MULTISIG-AUTHORIZATION",
            &map_records(&self.authorizations, |v| v.public_record()),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-PQ-MULTISIG-NULLIFIER",
            &map_records(&self.nullifiers, |v| v.public_record()),
        );
        let sponsorship_root = merkle_root(
            "PRIVATE-PQ-MULTISIG-SPONSORSHIP",
            &map_records(&self.sponsorships, |v| v.public_record()),
        );
        let challenge_root = merkle_root(
            "PRIVATE-PQ-MULTISIG-CHALLENGE",
            &map_records(&self.challenges, |v| v.public_record()),
        );
        let receipt_root = merkle_root(
            "PRIVATE-PQ-MULTISIG-RECEIPT",
            &map_records(&self.receipts, |v| v.public_record()),
        );
        let event_root = merkle_root(
            "PRIVATE-PQ-MULTISIG-EVENT",
            &map_records(&self.events, |v| v.public_record()),
        );
        let record = json!({
            "config_root": config_root,
            "signer_root": signer_root,
            "committee_root": committee_root,
            "policy_root": policy_root,
            "intent_root": intent_root,
            "authorization_root": authorization_root,
            "nullifier_root": nullifier_root,
            "sponsorship_root": sponsorship_root,
            "challenge_root": challenge_root,
            "receipt_root": receipt_root,
            "event_root": event_root,
            "height": self.height,
        });
        let state_root = root_from_record(&record);
        Roots {
            config_root,
            signer_root,
            committee_root,
            policy_root,
            intent_root,
            authorization_root,
            nullifier_root,
            sponsorship_root,
            challenge_root,
            receipt_root,
            event_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            signer_count: self.signers.len(),
            committee_count: self.committees.len(),
            policy_count: self.policies.len(),
            intent_count: self.intents.len(),
            active_intent_count: self
                .intents
                .values()
                .filter(|intent| intent.status.active())
                .count(),
            authorization_count: self.authorizations.len(),
            counted_authorization_count: self
                .authorizations
                .values()
                .filter(|auth| auth.status.counts())
                .count(),
            nullifier_count: self.nullifiers.len(),
            spent_nullifier_count: self
                .nullifiers
                .values()
                .filter(|record| record.status == NullifierStatus::Spent)
                .count(),
            sponsorship_count: self.sponsorships.len(),
            active_sponsorship_count: self
                .sponsorships
                .values()
                .filter(|sponsor| sponsor.active_at(self.height))
                .count(),
            open_challenge_count: self
                .challenges
                .values()
                .filter(|challenge| challenge.status == ChallengeStatus::Open)
                .count(),
            receipt_count: self.receipts.len(),
            event_count: self.events.len(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "chain_id": self.chain_id,
            "protocol_id": self.config.protocol_id,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn insert_signer(&mut self, signer: PqSigner) -> PrivatePqMultisigSpendAuthorityResult<()> {
        if self.signers.contains_key(&signer.signer_id) {
            return Err(format!("signer {} already exists", signer.signer_id));
        }
        let root = signer.root();
        let id = signer.signer_id.clone();
        self.signers.insert(id.clone(), signer);
        self.record_event("signer", &id, "inserted", &root);
        Ok(())
    }

    pub fn insert_committee(
        &mut self,
        committee: SignerCommittee,
    ) -> PrivatePqMultisigSpendAuthorityResult<()> {
        if self.committees.contains_key(&committee.committee_id) {
            return Err(format!(
                "committee {} already exists",
                committee.committee_id
            ));
        }
        for signer_id in &committee.signer_ids {
            if !self.signers.contains_key(signer_id) {
                return Err(format!("committee references missing signer {signer_id}"));
            }
        }
        let root = committee.root();
        let id = committee.committee_id.clone();
        self.committees.insert(id.clone(), committee);
        self.record_event("committee", &id, "inserted", &root);
        Ok(())
    }

    pub fn insert_policy(
        &mut self,
        policy: SpendingPolicy,
    ) -> PrivatePqMultisigSpendAuthorityResult<()> {
        if self.policies.contains_key(&policy.policy_id) {
            return Err(format!("policy {} already exists", policy.policy_id));
        }
        if policy.max_fee_bps > self.config.max_fee_bps {
            return Err("policy fee exceeds config maximum".to_string());
        }
        let root = policy.root();
        let id = policy.policy_id.clone();
        self.policies.insert(id.clone(), policy);
        self.record_event("policy", &id, "inserted", &root);
        Ok(())
    }

    pub fn insert_intent(
        &mut self,
        intent: SpendIntent,
    ) -> PrivatePqMultisigSpendAuthorityResult<()> {
        if self.intents.contains_key(&intent.intent_id) {
            return Err(format!("intent {} already exists", intent.intent_id));
        }
        if self.nullifiers.contains_key(&intent.nullifier_commitment) {
            return Err(format!(
                "nullifier {} already reserved",
                intent.nullifier_commitment
            ));
        }
        let committee = self
            .committees
            .get(&intent.committee_id)
            .ok_or_else(|| "intent committee missing".to_string())?;
        if !committee.active_at(self.height) {
            return Err("intent committee not active".to_string());
        }
        let policy = self
            .policies
            .get(&intent.policy_id)
            .ok_or_else(|| "intent policy missing".to_string())?;
        if !committee.policy_ids.contains(&intent.policy_id) {
            return Err("intent policy not admitted by committee".to_string());
        }
        if !policy.accepts(&intent, self.height) {
            return Err("intent does not satisfy policy at current height".to_string());
        }
        let nullifier_record = PrivacyNullifierRecord {
            nullifier: intent.nullifier_commitment.clone(),
            intent_id: intent.intent_id.clone(),
            account_set_root: record_root(
                "ACCOUNT-SET",
                &json!({
                    "account_commitment": intent.account_commitment,
                    "privacy_set_size": intent.privacy_set_size,
                }),
            ),
            note_commitment: intent.spend_note_commitment.clone(),
            status: NullifierStatus::Reserved,
            reserved_at_height: self.height,
            spent_at_height: None,
        };
        let root = intent.root();
        let id = intent.intent_id.clone();
        self.nullifiers
            .insert(nullifier_record.nullifier.clone(), nullifier_record);
        self.intents.insert(id.clone(), intent);
        self.record_event("intent", &id, "inserted", &root);
        Ok(())
    }

    pub fn insert_authorization(
        &mut self,
        authorization: AuthorizationCommitment,
    ) -> PrivatePqMultisigSpendAuthorityResult<()> {
        if self
            .authorizations
            .contains_key(&authorization.authorization_id)
        {
            return Err(format!(
                "authorization {} already exists",
                authorization.authorization_id
            ));
        }
        let intent = self
            .intents
            .get(&authorization.intent_id)
            .ok_or_else(|| "authorization intent missing".to_string())?;
        let intent_id = intent.intent_id.clone();
        let committee = self
            .committees
            .get(&authorization.committee_id)
            .ok_or_else(|| "authorization committee missing".to_string())?;
        if intent.committee_id != authorization.committee_id {
            return Err("authorization committee does not match intent".to_string());
        }
        if !committee.signer_ids.contains(&authorization.signer_id) {
            return Err("authorization signer not in committee".to_string());
        }
        let signer = self
            .signers
            .get(&authorization.signer_id)
            .ok_or_else(|| "authorization signer missing".to_string())?;
        if !signer.usable_at(self.height, self.config.min_pq_security_bits) {
            return Err("authorization signer not usable".to_string());
        }
        let root = authorization.root();
        let id = authorization.authorization_id.clone();
        self.authorizations.insert(id.clone(), authorization);
        self.refresh_intent_authorization_status(&intent_id);
        self.record_event("authorization", &id, "inserted", &root);
        Ok(())
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: FeeSponsorship,
    ) -> PrivatePqMultisigSpendAuthorityResult<()> {
        if self.sponsorships.contains_key(&sponsorship.sponsorship_id) {
            return Err(format!(
                "sponsorship {} already exists",
                sponsorship.sponsorship_id
            ));
        }
        if sponsorship.reserve_units < self.config.sponsor_reserve_units {
            return Err("sponsorship reserve below configured minimum".to_string());
        }
        if !self.intents.contains_key(&sponsorship.intent_id) {
            return Err("sponsorship intent missing".to_string());
        }
        let root = sponsorship.root();
        let id = sponsorship.sponsorship_id.clone();
        self.sponsorships.insert(id.clone(), sponsorship);
        self.record_event("sponsorship", &id, "inserted", &root);
        Ok(())
    }

    pub fn insert_challenge(
        &mut self,
        challenge: ChallengeWindow,
    ) -> PrivatePqMultisigSpendAuthorityResult<()> {
        if self.challenges.contains_key(&challenge.challenge_id) {
            return Err(format!(
                "challenge {} already exists",
                challenge.challenge_id
            ));
        }
        if !self.intents.contains_key(&challenge.intent_id) {
            return Err("challenge intent missing".to_string());
        }
        let root = challenge.root();
        let id = challenge.challenge_id.clone();
        if let Some(intent) = self.intents.get_mut(&challenge.intent_id) {
            intent.status = SpendIntentStatus::Challenged;
        }
        self.challenges.insert(id.clone(), challenge);
        self.record_event("challenge", &id, "inserted", &root);
        Ok(())
    }

    pub fn insert_receipt(
        &mut self,
        receipt: SpendReceipt,
    ) -> PrivatePqMultisigSpendAuthorityResult<()> {
        if self.receipts.contains_key(&receipt.receipt_id) {
            return Err(format!("receipt {} already exists", receipt.receipt_id));
        }
        let intent = self
            .intents
            .get_mut(&receipt.intent_id)
            .ok_or_else(|| "receipt intent missing".to_string())?;
        if intent.nullifier_commitment != receipt.nullifier {
            return Err("receipt nullifier does not match intent".to_string());
        }
        intent.status = SpendIntentStatus::Executed;
        if let Some(nullifier) = self.nullifiers.get_mut(&receipt.nullifier) {
            nullifier.status = NullifierStatus::Spent;
            nullifier.spent_at_height = Some(receipt.executed_at_height);
        }
        if let Some(sponsor_id) = &receipt.sponsor_id {
            if let Some(sponsor) = self.sponsorships.get_mut(sponsor_id) {
                sponsor.status = SponsorshipStatus::Used;
            }
        }
        let root = receipt.root();
        let id = receipt.receipt_id.clone();
        self.receipts.insert(id.clone(), receipt);
        self.record_event("receipt", &id, "inserted", &root);
        Ok(())
    }

    pub fn authorization_weight_for_intent(&self, intent_id: &str) -> u64 {
        let mut seen_signers = BTreeSet::new();
        let mut weight = 0_u64;
        for authorization in self.authorizations.values() {
            if authorization.intent_id == intent_id
                && authorization.active_at(self.height)
                && seen_signers.insert(authorization.signer_id.clone())
            {
                weight = weight.saturating_add(authorization.weight);
            }
        }
        weight
    }

    pub fn intent_authorization_root(&self, intent_id: &str) -> String {
        let records = self
            .authorizations
            .values()
            .filter(|authorization| authorization.intent_id == intent_id)
            .map(|authorization| authorization.public_record())
            .collect::<Vec<_>>();
        merkle_root("PRIVATE-PQ-MULTISIG-INTENT-AUTHORIZATION", &records)
    }

    fn refresh_intent_authorization_status(&mut self, intent_id: &str) {
        let Some(intent) = self.intents.get(intent_id).cloned() else {
            return;
        };
        let Some(committee) = self.committees.get(&intent.committee_id) else {
            return;
        };
        let weight = self.authorization_weight_for_intent(intent_id);
        if let Some(intent_mut) = self.intents.get_mut(intent_id) {
            if weight >= committee.threshold_weight {
                intent_mut.status = SpendIntentStatus::Authorized;
            } else if intent_mut.status == SpendIntentStatus::Committed {
                intent_mut.status = SpendIntentStatus::AuthorizationOpen;
            }
        }
    }

    fn expire_records(&mut self) {
        for intent in self.intents.values_mut() {
            if intent.status.active() && intent.expired_at(self.height) {
                intent.status = SpendIntentStatus::Expired;
            }
        }
        for authorization in self.authorizations.values_mut() {
            if authorization.status.counts() && self.height > authorization.expires_at_height {
                authorization.status = AuthorizationStatus::Expired;
            }
        }
        for sponsorship in self.sponsorships.values_mut() {
            if sponsorship.status.available() && self.height > sponsorship.expires_at_height {
                sponsorship.status = SponsorshipStatus::Expired;
            }
        }
        for challenge in self.challenges.values_mut() {
            if challenge.status == ChallengeStatus::Open && self.height > challenge.deadline_height
            {
                challenge.status = ChallengeStatus::Expired;
            }
        }
    }

    fn record_event(&mut self, subject_kind: &str, subject_id: &str, event_kind: &str, root: &str) {
        let event = AuditEvent::new(subject_kind, subject_id, event_kind, root, self.height);
        self.events.insert(event.event_id.clone(), event);
    }
}

pub fn root_from_record(record: &Value) -> String {
    record_root("STATE", record)
}

pub fn devnet() -> PrivatePqMultisigSpendAuthorityResult<State> {
    State::devnet()
}

fn record_root(record_kind: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-PQ-MULTISIG-SPEND-AUTHORITY-{record_kind}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn labeled_commitment(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("PRIVATE-PQ-MULTISIG-SPEND-AUTHORITY-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_PQ_MULTISIG_SPEND_AUTHORITY_PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn signer_id(
    label: &str,
    scheme: PqSignatureScheme,
    ml_dsa_public_commitment: &str,
    slh_dsa_public_commitment: &str,
    privacy_group_commitment: &str,
) -> String {
    domain_hash(
        "PRIVATE-PQ-MULTISIG-SPEND-AUTHORITY-SIGNER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(scheme.as_str()),
            HashPart::Str(ml_dsa_public_commitment),
            HashPart::Str(slh_dsa_public_commitment),
            HashPart::Str(privacy_group_commitment),
        ],
        32,
    )
}

fn committee_id(label: &str, epoch: u64, aggregate_public_key_commitment: &str) -> String {
    domain_hash(
        "PRIVATE-PQ-MULTISIG-SPEND-AUTHORITY-COMMITTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(epoch as i128),
            HashPart::Str(aggregate_public_key_commitment),
        ],
        32,
    )
}

fn policy_id(
    tag: &str,
    mode: TimelockMode,
    min_unlock_height: u64,
    max_amount_units: u128,
) -> String {
    domain_hash(
        "PRIVATE-PQ-MULTISIG-SPEND-AUTHORITY-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(tag),
            HashPart::Str(mode.as_str()),
            HashPart::Int(min_unlock_height as i128),
            HashPart::Str(&max_amount_units.to_string()),
        ],
        32,
    )
}

fn spend_intent_id(
    kind: SpendIntentKind,
    account_commitment: &str,
    asset_id: &str,
    amount_units: u128,
    nullifier: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-PQ-MULTISIG-SPEND-AUTHORITY-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(account_commitment),
            HashPart::Str(asset_id),
            HashPart::Str(&amount_units.to_string()),
            HashPart::Str(nullifier),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

fn nullifier_for(account_commitment: &str, note_commitment: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-PQ-MULTISIG-SPEND-AUTHORITY-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(note_commitment),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

fn authorization_commitment(
    domain: &str,
    intent_id: &str,
    signer_id: &str,
    transcript_hash: &str,
) -> String {
    domain_hash(
        &format!("PRIVATE-PQ-MULTISIG-SPEND-AUTHORITY-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(signer_id),
            HashPart::Str(transcript_hash),
        ],
        32,
    )
}

fn authorization_id(
    intent_id: &str,
    committee_id: &str,
    signer_id: &str,
    transcript_hash: &str,
) -> String {
    domain_hash(
        "PRIVATE-PQ-MULTISIG-SPEND-AUTHORITY-AUTHORIZATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(committee_id),
            HashPart::Str(signer_id),
            HashPart::Str(transcript_hash),
        ],
        32,
    )
}

fn sponsorship_id(
    intent_id: &str,
    sponsor_commitment: &str,
    fee_asset_id: &str,
    max_fee_units: u128,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-PQ-MULTISIG-SPEND-AUTHORITY-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Str(&max_fee_units.to_string()),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

fn challenge_id(
    intent_id: &str,
    challenger_commitment: &str,
    challenge_kind: &str,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-PQ-MULTISIG-SPEND-AUTHORITY-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(challenge_kind),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

fn receipt_id(
    intent_id: &str,
    nullifier: &str,
    settlement_tx_commitment: &str,
    executed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-PQ-MULTISIG-SPEND-AUTHORITY-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(nullifier),
            HashPart::Str(settlement_tx_commitment),
            HashPart::Int(executed_at_height as i128),
        ],
        32,
    )
}

fn event_id(
    subject_kind: &str,
    subject_id: &str,
    event_kind: &str,
    record_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-PQ-MULTISIG-SPEND-AUTHORITY-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(event_kind),
            HashPart::Str(record_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

fn string_values(values: &BTreeSet<String>) -> Vec<Value> {
    values.iter().cloned().map(Value::String).collect()
}

fn btree_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn map_records<T, F>(values: &BTreeMap<String, T>, mut f: F) -> Vec<Value>
where
    F: FnMut(&T) -> Value,
{
    values.values().map(|value| f(value)).collect()
}
