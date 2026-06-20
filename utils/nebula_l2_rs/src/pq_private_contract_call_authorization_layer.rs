use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash as stable_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqPrivateContractCallAuthorizationLayerResult<T> = Result<T, String>;

pub const PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_PROTOCOL_VERSION: &str =
    "nebula-pq-private-contract-call-authorization-layer-v1";
pub const PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_SCHEMA_VERSION: &str =
    "pq-private-contract-call-authorization-layer-state-v1";
pub const PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_DEVNET_LABEL: &str =
    "devnet-pq-private-contract-call-authorization-layer";
pub const PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_PQ_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s+capability-nullifier-v1";
pub const PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_SESSION_SUITE: &str =
    "ML-KEM-768+private-contract-session-key-v1";
pub const PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_SPONSOR_SUITE: &str =
    "zk-sponsor-proof-hook-v1";
pub const PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_DEFAULT_SESSION_TTL_BLOCKS: u64 = 96;
pub const PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_DEFAULT_QUEUE_TTL_BLOCKS: u64 = 18;
pub const PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_DEFAULT_REVOCATION_WINDOW_BLOCKS: u64 = 720;
pub const PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_DEFAULT_MAX_CALL_WEIGHT: u64 = 1_200_000;
pub const PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_DEFAULT_MAX_BATCH_WEIGHT: u64 = 8_000_000;
pub const PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_DEFAULT_MAX_BATCH_ITEMS: u64 = 512;
pub const PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_DEFAULT_MIN_PRIVACY_SET: u64 = 96;
pub const PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallCapabilityKind {
    ReadOnlySimulation,
    PrivateStateRead,
    PrivateStateWrite,
    TokenSpend,
    VaultSpend,
    DelegateCall,
    CrossContractMessage,
    EmergencyPause,
}

impl CallCapabilityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnlySimulation => "read_only_simulation",
            Self::PrivateStateRead => "private_state_read",
            Self::PrivateStateWrite => "private_state_write",
            Self::TokenSpend => "token_spend",
            Self::VaultSpend => "vault_spend",
            Self::DelegateCall => "delegate_call",
            Self::CrossContractMessage => "cross_contract_message",
            Self::EmergencyPause => "emergency_pause",
        }
    }

    pub fn permits_value_movement(self) -> bool {
        matches!(self, Self::TokenSpend | Self::VaultSpend)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityNoteStatus {
    Draft,
    Active,
    Consumed,
    Revoked,
    Expired,
    Quarantined,
}

impl CapabilityNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Consumed => "consumed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Draft | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKeyStatus {
    Proposed,
    Active,
    Rotating,
    Suspended,
    Revoked,
    Expired,
}

impl SessionKeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn authorizes_calls(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendBoundKind {
    ViewOnly,
    PerCall,
    PerSession,
    PerEpoch,
    ContractScoped,
    AssetScoped,
}

impl SpendBoundKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewOnly => "view_only",
            Self::PerCall => "per_call",
            Self::PerSession => "per_session",
            Self::PerEpoch => "per_epoch",
            Self::ContractScoped => "contract_scoped",
            Self::AssetScoped => "asset_scoped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Open,
    Reserved,
    Spent,
    Revoked,
    Disputed,
    Expired,
}

impl FenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Spent => "spent",
            Self::Revoked => "revoked",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn blocks_replay(self) -> bool {
        matches!(self, Self::Reserved | Self::Spent | Self::Revoked)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStatus {
    Funding,
    Active,
    Exhausted,
    Frozen,
    Revoked,
    Expired,
}

impl BudgetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Funding => "funding",
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Frozen => "frozen",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Funding | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorHookStatus {
    Offered,
    Bound,
    Proved,
    Settled,
    Challenged,
    Slashed,
    Revoked,
}

impl SponsorHookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Bound => "bound",
            Self::Proved => "proved",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueStatus {
    Open,
    Sealed,
    Sequenced,
    Proved,
    Settled,
    Expired,
    Cancelled,
}

impl QueueStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Sequenced => "sequenced",
            Self::Proved => "proved",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn accepts_items(self) -> bool {
        matches!(self, Self::Open | Self::Sealed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    UserRequest,
    SessionRotation,
    BudgetLimit,
    ReplayFenceHit,
    SponsorChallenge,
    ContractEmergency,
    GovernanceDirective,
}

impl RevocationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserRequest => "user_request",
            Self::SessionRotation => "session_rotation",
            Self::BudgetLimit => "budget_limit",
            Self::ReplayFenceHit => "replay_fence_hit",
            Self::SponsorChallenge => "sponsor_challenge",
            Self::ContractEmergency => "contract_emergency",
            Self::GovernanceDirective => "governance_directive",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub session_ttl_blocks: u64,
    pub queue_ttl_blocks: u64,
    pub revocation_window_blocks: u64,
    pub max_call_weight: u64,
    pub max_batch_weight: u64,
    pub max_batch_items: u64,
    pub min_privacy_set: u64,
    pub max_sponsor_rebate_bps: u64,
    pub pq_suite: String,
    pub session_suite: String,
    pub sponsor_suite: String,
    pub hash_suite: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            session_ttl_blocks:
                PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_DEFAULT_SESSION_TTL_BLOCKS,
            queue_ttl_blocks: PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_DEFAULT_QUEUE_TTL_BLOCKS,
            revocation_window_blocks:
                PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_DEFAULT_REVOCATION_WINDOW_BLOCKS,
            max_call_weight: PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_DEFAULT_MAX_CALL_WEIGHT,
            max_batch_weight: PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_DEFAULT_MAX_BATCH_WEIGHT,
            max_batch_items: PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_DEFAULT_MAX_BATCH_ITEMS,
            min_privacy_set: PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_DEFAULT_MIN_PRIVACY_SET,
            max_sponsor_rebate_bps: 8_500,
            pq_suite: PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_PQ_SUITE.to_string(),
            session_suite: PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_SESSION_SUITE.to_string(),
            sponsor_suite: PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_SPONSOR_SUITE.to_string(),
            hash_suite: PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_HASH_SUITE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "session_ttl_blocks": self.session_ttl_blocks,
            "queue_ttl_blocks": self.queue_ttl_blocks,
            "revocation_window_blocks": self.revocation_window_blocks,
            "max_call_weight": self.max_call_weight,
            "max_batch_weight": self.max_batch_weight,
            "max_batch_items": self.max_batch_items,
            "min_privacy_set": self.min_privacy_set,
            "max_sponsor_rebate_bps": self.max_sponsor_rebate_bps,
            "pq_suite": self.pq_suite,
            "session_suite": self.session_suite,
            "sponsor_suite": self.sponsor_suite,
            "hash_suite": self.hash_suite,
        })
    }

    pub fn validate(&self) -> PqPrivateContractCallAuthorizationLayerResult<()> {
        if self.session_ttl_blocks == 0
            || self.queue_ttl_blocks == 0
            || self.revocation_window_blocks == 0
            || self.max_call_weight == 0
            || self.max_batch_weight == 0
            || self.max_batch_items == 0
            || self.min_privacy_set == 0
        {
            return Err("authorization layer config limits must be positive".to_string());
        }
        if self.max_call_weight > self.max_batch_weight {
            return Err("authorization layer call weight exceeds batch weight".to_string());
        }
        if self.max_sponsor_rebate_bps > PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_MAX_BPS {
            return Err("authorization layer sponsor rebate exceeds max bps".to_string());
        }
        if self.pq_suite.is_empty()
            || self.session_suite.is_empty()
            || self.sponsor_suite.is_empty()
            || self.hash_suite.is_empty()
        {
            return Err("authorization layer suite labels must be populated".to_string());
        }
        Ok(())
    }

    pub fn root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallCapabilityNote {
    pub note_id: String,
    pub owner_commitment: String,
    pub contract_id: String,
    pub function_selector_root: String,
    pub capability: CallCapabilityKind,
    pub status: CapabilityNoteStatus,
    pub allowance_budget_id: String,
    pub session_key_id: String,
    pub nullifier_root: String,
    pub view_tag_root: String,
    pub sponsor_hook_id: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub call_weight_limit: u64,
    pub privacy_set_size: u64,
}

impl CallCapabilityNote {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "owner_commitment": self.owner_commitment,
            "contract_id": self.contract_id,
            "function_selector_root": self.function_selector_root,
            "capability": self.capability.as_str(),
            "status": self.status.as_str(),
            "allowance_budget_id": self.allowance_budget_id,
            "session_key_id": self.session_key_id,
            "nullifier_root": self.nullifier_root,
            "view_tag_root": self.view_tag_root,
            "sponsor_hook_id": self.sponsor_hook_id,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "call_weight_limit": self.call_weight_limit,
            "privacy_set_size": self.privacy_set_size,
        })
    }

    pub fn root(&self) -> String {
        record_root("CAPABILITY-NOTE", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> PqPrivateContractCallAuthorizationLayerResult<()> {
        require_id("capability note id", &self.note_id)?;
        require_id("capability owner", &self.owner_commitment)?;
        require_id("capability contract", &self.contract_id)?;
        require_hash(
            "capability function selector root",
            &self.function_selector_root,
        )?;
        require_hash("capability nullifier root", &self.nullifier_root)?;
        require_hash("capability view tag root", &self.view_tag_root)?;
        require_id("capability budget", &self.allowance_budget_id)?;
        require_id("capability session key", &self.session_key_id)?;
        if self.sponsor_hook_id.is_empty() {
            return Err("capability sponsor hook id must be populated".to_string());
        }
        if self.opened_at_height >= self.expires_at_height {
            return Err("capability note expiry must be after opening height".to_string());
        }
        if self.call_weight_limit == 0 || self.call_weight_limit > config.max_call_weight {
            return Err("capability note call weight limit is outside config bounds".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set {
            return Err("capability note privacy set is below minimum".to_string());
        }
        if self.capability.permits_value_movement() && self.allowance_budget_id == "view-only" {
            return Err("value-moving capability requires private allowance budget".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKey {
    pub session_key_id: String,
    pub account_commitment: String,
    pub pq_public_key_commitment: String,
    pub kem_ciphertext_root: String,
    pub transcript_root: String,
    pub status: SessionKeyStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub rotation_nonce: u64,
    pub allowed_contract_root: String,
    pub allowed_capability_root: String,
}

impl SessionKey {
    pub fn public_record(&self) -> Value {
        json!({
            "session_key_id": self.session_key_id,
            "account_commitment": self.account_commitment,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "kem_ciphertext_root": self.kem_ciphertext_root,
            "transcript_root": self.transcript_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "rotation_nonce": self.rotation_nonce,
            "allowed_contract_root": self.allowed_contract_root,
            "allowed_capability_root": self.allowed_capability_root,
        })
    }

    pub fn root(&self) -> String {
        record_root("SESSION-KEY", &self.public_record())
    }

    pub fn validate(&self) -> PqPrivateContractCallAuthorizationLayerResult<()> {
        require_id("session key id", &self.session_key_id)?;
        require_id("session account", &self.account_commitment)?;
        require_hash(
            "session pq public key commitment",
            &self.pq_public_key_commitment,
        )?;
        require_hash("session kem ciphertext root", &self.kem_ciphertext_root)?;
        require_hash("session transcript root", &self.transcript_root)?;
        require_hash("session allowed contract root", &self.allowed_contract_root)?;
        require_hash(
            "session allowed capability root",
            &self.allowed_capability_root,
        )?;
        if self.opened_at_height >= self.expires_at_height {
            return Err("session key expiry must be after opening height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewOnlySpendBound {
    pub bound_id: String,
    pub note_id: String,
    pub account_commitment: String,
    pub contract_id: String,
    pub asset_commitment: String,
    pub bound_kind: SpendBoundKind,
    pub max_amount_commitment: String,
    pub consumed_amount_commitment: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub disclosure_root: String,
}

impl ViewOnlySpendBound {
    pub fn public_record(&self) -> Value {
        json!({
            "bound_id": self.bound_id,
            "note_id": self.note_id,
            "account_commitment": self.account_commitment,
            "contract_id": self.contract_id,
            "asset_commitment": self.asset_commitment,
            "bound_kind": self.bound_kind.as_str(),
            "max_amount_commitment": self.max_amount_commitment,
            "consumed_amount_commitment": self.consumed_amount_commitment,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "disclosure_root": self.disclosure_root,
        })
    }

    pub fn root(&self) -> String {
        record_root("VIEW-SPEND-BOUND", &self.public_record())
    }

    pub fn validate(&self) -> PqPrivateContractCallAuthorizationLayerResult<()> {
        require_id("spend bound id", &self.bound_id)?;
        require_id("spend bound note", &self.note_id)?;
        require_id("spend bound account", &self.account_commitment)?;
        require_id("spend bound contract", &self.contract_id)?;
        require_hash("spend bound asset commitment", &self.asset_commitment)?;
        require_hash(
            "spend bound max amount commitment",
            &self.max_amount_commitment,
        )?;
        require_hash(
            "spend bound consumed amount commitment",
            &self.consumed_amount_commitment,
        )?;
        require_hash("spend bound disclosure root", &self.disclosure_root)?;
        if self.window_start_height >= self.window_end_height {
            return Err("spend bound window must be increasing".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayNullifierFence {
    pub fence_id: String,
    pub nullifier_commitment: String,
    pub session_key_id: String,
    pub note_id: String,
    pub call_digest_root: String,
    pub status: FenceStatus,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub settlement_receipt_root: String,
}

impl ReplayNullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "nullifier_commitment": self.nullifier_commitment,
            "session_key_id": self.session_key_id,
            "note_id": self.note_id,
            "call_digest_root": self.call_digest_root,
            "status": self.status.as_str(),
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "settlement_receipt_root": self.settlement_receipt_root,
        })
    }

    pub fn root(&self) -> String {
        record_root("REPLAY-NULLIFIER-FENCE", &self.public_record())
    }

    pub fn validate(&self) -> PqPrivateContractCallAuthorizationLayerResult<()> {
        require_id("replay fence id", &self.fence_id)?;
        require_hash("replay fence nullifier", &self.nullifier_commitment)?;
        require_id("replay fence session", &self.session_key_id)?;
        require_id("replay fence note", &self.note_id)?;
        require_hash("replay fence call digest root", &self.call_digest_root)?;
        require_hash(
            "replay fence settlement receipt root",
            &self.settlement_receipt_root,
        )?;
        if self.reserved_at_height >= self.expires_at_height {
            return Err("replay fence expiry must be after reservation height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateAllowanceBudget {
    pub budget_id: String,
    pub owner_commitment: String,
    pub contract_scope_root: String,
    pub asset_scope_root: String,
    pub budget_commitment: String,
    pub spent_commitment: String,
    pub reserved_commitment: String,
    pub status: BudgetStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub epoch: u64,
}

impl PrivateAllowanceBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "owner_commitment": self.owner_commitment,
            "contract_scope_root": self.contract_scope_root,
            "asset_scope_root": self.asset_scope_root,
            "budget_commitment": self.budget_commitment,
            "spent_commitment": self.spent_commitment,
            "reserved_commitment": self.reserved_commitment,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "epoch": self.epoch,
        })
    }

    pub fn root(&self) -> String {
        record_root("PRIVATE-ALLOWANCE-BUDGET", &self.public_record())
    }

    pub fn validate(&self) -> PqPrivateContractCallAuthorizationLayerResult<()> {
        require_id("allowance budget id", &self.budget_id)?;
        require_id("allowance owner", &self.owner_commitment)?;
        require_hash("allowance contract scope root", &self.contract_scope_root)?;
        require_hash("allowance asset scope root", &self.asset_scope_root)?;
        require_hash("allowance budget commitment", &self.budget_commitment)?;
        require_hash("allowance spent commitment", &self.spent_commitment)?;
        require_hash("allowance reserved commitment", &self.reserved_commitment)?;
        if self.opened_at_height >= self.expires_at_height {
            return Err("allowance budget expiry must be after opening height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorProofHook {
    pub hook_id: String,
    pub sponsor_commitment: String,
    pub account_commitment: String,
    pub contract_scope_root: String,
    pub fee_asset_commitment: String,
    pub proof_program_root: String,
    pub witness_policy_root: String,
    pub rebate_bps: u64,
    pub status: SponsorHookStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorProofHook {
    pub fn public_record(&self) -> Value {
        json!({
            "hook_id": self.hook_id,
            "sponsor_commitment": self.sponsor_commitment,
            "account_commitment": self.account_commitment,
            "contract_scope_root": self.contract_scope_root,
            "fee_asset_commitment": self.fee_asset_commitment,
            "proof_program_root": self.proof_program_root,
            "witness_policy_root": self.witness_policy_root,
            "rebate_bps": self.rebate_bps,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        record_root("SPONSOR-PROOF-HOOK", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> PqPrivateContractCallAuthorizationLayerResult<()> {
        require_id("sponsor hook id", &self.hook_id)?;
        require_id("sponsor hook sponsor", &self.sponsor_commitment)?;
        require_id("sponsor hook account", &self.account_commitment)?;
        require_hash(
            "sponsor hook contract scope root",
            &self.contract_scope_root,
        )?;
        require_hash(
            "sponsor hook fee asset commitment",
            &self.fee_asset_commitment,
        )?;
        require_hash("sponsor hook proof program root", &self.proof_program_root)?;
        require_hash(
            "sponsor hook witness policy root",
            &self.witness_policy_root,
        )?;
        if self.rebate_bps > config.max_sponsor_rebate_bps {
            return Err("sponsor hook rebate exceeds config".to_string());
        }
        if self.opened_at_height >= self.expires_at_height {
            return Err("sponsor hook expiry must be after opening height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchAuthorizationQueue {
    pub queue_id: String,
    pub contract_id: String,
    pub queue_root: String,
    pub status: QueueStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub max_items: u64,
    pub max_weight: u64,
    pub current_items: u64,
    pub current_weight: u64,
    pub sponsor_pool_root: String,
    pub sequencer_commitment: String,
}

impl BatchAuthorizationQueue {
    pub fn public_record(&self) -> Value {
        json!({
            "queue_id": self.queue_id,
            "contract_id": self.contract_id,
            "queue_root": self.queue_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "max_items": self.max_items,
            "max_weight": self.max_weight,
            "current_items": self.current_items,
            "current_weight": self.current_weight,
            "sponsor_pool_root": self.sponsor_pool_root,
            "sequencer_commitment": self.sequencer_commitment,
        })
    }

    pub fn root(&self) -> String {
        record_root("BATCH-AUTHORIZATION-QUEUE", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> PqPrivateContractCallAuthorizationLayerResult<()> {
        require_id("authorization queue id", &self.queue_id)?;
        require_id("authorization queue contract", &self.contract_id)?;
        require_hash("authorization queue root", &self.queue_root)?;
        require_hash(
            "authorization queue sponsor pool root",
            &self.sponsor_pool_root,
        )?;
        require_id("authorization queue sequencer", &self.sequencer_commitment)?;
        if self.opened_at_height >= self.expires_at_height {
            return Err("authorization queue expiry must be after opening height".to_string());
        }
        if self.max_items == 0 || self.max_items > config.max_batch_items {
            return Err("authorization queue item limit is outside config bounds".to_string());
        }
        if self.max_weight == 0 || self.max_weight > config.max_batch_weight {
            return Err("authorization queue weight limit is outside config bounds".to_string());
        }
        if self.current_items > self.max_items || self.current_weight > self.max_weight {
            return Err("authorization queue usage exceeds limits".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationReceipt {
    pub receipt_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub reason: RevocationReason,
    pub revoked_by_commitment: String,
    pub revoked_at_height: u64,
    pub effective_at_height: u64,
    pub replacement_root: String,
    pub audit_trail_root: String,
}

impl RevocationReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "reason": self.reason.as_str(),
            "revoked_by_commitment": self.revoked_by_commitment,
            "revoked_at_height": self.revoked_at_height,
            "effective_at_height": self.effective_at_height,
            "replacement_root": self.replacement_root,
            "audit_trail_root": self.audit_trail_root,
        })
    }

    pub fn root(&self) -> String {
        record_root("REVOCATION-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> PqPrivateContractCallAuthorizationLayerResult<()> {
        require_id("revocation receipt id", &self.receipt_id)?;
        require_id("revocation subject id", &self.subject_id)?;
        require_hash("revocation subject root", &self.subject_root)?;
        require_id("revocation authority", &self.revoked_by_commitment)?;
        require_hash("revocation replacement root", &self.replacement_root)?;
        require_hash("revocation audit trail root", &self.audit_trail_root)?;
        if self.revoked_at_height > self.effective_at_height {
            return Err("revocation effective height must not precede revoked height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationPolicy {
    pub policy_id: String,
    pub contract_id: String,
    pub required_capability_root: String,
    pub session_policy_root: String,
    pub spend_bound_policy_root: String,
    pub replay_policy_root: String,
    pub sponsor_policy_root: String,
    pub min_privacy_set: u64,
    pub max_call_weight: u64,
    pub enabled: bool,
}

impl AuthorizationPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "contract_id": self.contract_id,
            "required_capability_root": self.required_capability_root,
            "session_policy_root": self.session_policy_root,
            "spend_bound_policy_root": self.spend_bound_policy_root,
            "replay_policy_root": self.replay_policy_root,
            "sponsor_policy_root": self.sponsor_policy_root,
            "min_privacy_set": self.min_privacy_set,
            "max_call_weight": self.max_call_weight,
            "enabled": self.enabled,
        })
    }

    pub fn root(&self) -> String {
        record_root("AUTHORIZATION-POLICY", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> PqPrivateContractCallAuthorizationLayerResult<()> {
        require_id("authorization policy id", &self.policy_id)?;
        require_id("authorization policy contract", &self.contract_id)?;
        require_hash(
            "authorization policy required capability root",
            &self.required_capability_root,
        )?;
        require_hash(
            "authorization policy session root",
            &self.session_policy_root,
        )?;
        require_hash(
            "authorization policy spend bound root",
            &self.spend_bound_policy_root,
        )?;
        require_hash("authorization policy replay root", &self.replay_policy_root)?;
        require_hash(
            "authorization policy sponsor root",
            &self.sponsor_policy_root,
        )?;
        if self.min_privacy_set < config.min_privacy_set {
            return Err("authorization policy privacy set below config".to_string());
        }
        if self.max_call_weight == 0 || self.max_call_weight > config.max_call_weight {
            return Err("authorization policy call weight outside config".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub capability_note_root: String,
    pub session_key_root: String,
    pub view_spend_bound_root: String,
    pub replay_fence_root: String,
    pub allowance_budget_root: String,
    pub sponsor_hook_root: String,
    pub queue_root: String,
    pub revocation_receipt_root: String,
    pub policy_root: String,
    pub active_account_root: String,
    pub nullifier_fence_index_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "capability_note_root": self.capability_note_root,
            "session_key_root": self.session_key_root,
            "view_spend_bound_root": self.view_spend_bound_root,
            "replay_fence_root": self.replay_fence_root,
            "allowance_budget_root": self.allowance_budget_root,
            "sponsor_hook_root": self.sponsor_hook_root,
            "queue_root": self.queue_root,
            "revocation_receipt_root": self.revocation_receipt_root,
            "policy_root": self.policy_root,
            "active_account_root": self.active_account_root,
            "nullifier_fence_index_root": self.nullifier_fence_index_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub capability_notes: u64,
    pub live_capability_notes: u64,
    pub session_keys: u64,
    pub authorizing_session_keys: u64,
    pub view_spend_bounds: u64,
    pub replay_fences: u64,
    pub blocking_replay_fences: u64,
    pub allowance_budgets: u64,
    pub spendable_allowance_budgets: u64,
    pub sponsor_hooks: u64,
    pub authorization_queues: u64,
    pub accepting_queues: u64,
    pub revocation_receipts: u64,
    pub policies: u64,
    pub enabled_policies: u64,
    pub monotonic_event_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "capability_notes": self.capability_notes,
            "live_capability_notes": self.live_capability_notes,
            "session_keys": self.session_keys,
            "authorizing_session_keys": self.authorizing_session_keys,
            "view_spend_bounds": self.view_spend_bounds,
            "replay_fences": self.replay_fences,
            "blocking_replay_fences": self.blocking_replay_fences,
            "allowance_budgets": self.allowance_budgets,
            "spendable_allowance_budgets": self.spendable_allowance_budgets,
            "sponsor_hooks": self.sponsor_hooks,
            "authorization_queues": self.authorization_queues,
            "accepting_queues": self.accepting_queues,
            "revocation_receipts": self.revocation_receipts,
            "policies": self.policies,
            "enabled_policies": self.enabled_policies,
            "monotonic_event_counter": self.monotonic_event_counter,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub capability_notes: Vec<CallCapabilityNote>,
    pub session_keys: Vec<SessionKey>,
    pub view_spend_bounds: Vec<ViewOnlySpendBound>,
    pub replay_fences: Vec<ReplayNullifierFence>,
    pub allowance_budgets: Vec<PrivateAllowanceBudget>,
    pub sponsor_hooks: Vec<SponsorProofHook>,
    pub authorization_queues: Vec<BatchAuthorizationQueue>,
    pub revocation_receipts: Vec<RevocationReceipt>,
    pub policies: Vec<AuthorizationPolicy>,
    pub monotonic_event_counter: u64,
}

impl State {
    pub fn devnet() -> PqPrivateContractCallAuthorizationLayerResult<State> {
        let height = 1_992;
        let config = Config::devnet();
        let owner_alpha = commitment("ACCOUNT", "devnet-private-caller-alpha");
        let owner_beta = commitment("ACCOUNT", "devnet-private-caller-beta");
        let contract_swap = id("CONTRACT", "private-swap-router");
        let contract_vault = id("CONTRACT", "private-vault-spend-gate");

        let session_alpha = SessionKey {
            session_key_id: id("SESSION-KEY", "alpha-session-0"),
            account_commitment: owner_alpha.clone(),
            pq_public_key_commitment: commitment("PQ-KEY", "alpha-ml-dsa-65"),
            kem_ciphertext_root: commitment("KEM-CIPHERTEXT", "alpha-session-ciphertext"),
            transcript_root: commitment("SESSION-TRANSCRIPT", "alpha-contract-call-session"),
            status: SessionKeyStatus::Active,
            opened_at_height: height - 24,
            expires_at_height: height + config.session_ttl_blocks,
            rotation_nonce: 7,
            allowed_contract_root: list_root("SESSION-CONTRACTS", &[contract_swap.clone()]),
            allowed_capability_root: list_root(
                "SESSION-CAPABILITIES",
                &[
                    CallCapabilityKind::PrivateStateRead.as_str().to_string(),
                    CallCapabilityKind::PrivateStateWrite.as_str().to_string(),
                    CallCapabilityKind::TokenSpend.as_str().to_string(),
                ],
            ),
        };
        let session_beta = SessionKey {
            session_key_id: id("SESSION-KEY", "beta-session-0"),
            account_commitment: owner_beta.clone(),
            pq_public_key_commitment: commitment("PQ-KEY", "beta-hybrid"),
            kem_ciphertext_root: commitment("KEM-CIPHERTEXT", "beta-session-ciphertext"),
            transcript_root: commitment("SESSION-TRANSCRIPT", "beta-view-only-session"),
            status: SessionKeyStatus::Rotating,
            opened_at_height: height - 32,
            expires_at_height: height + config.session_ttl_blocks / 2,
            rotation_nonce: 3,
            allowed_contract_root: list_root("SESSION-CONTRACTS", &[contract_vault.clone()]),
            allowed_capability_root: list_root(
                "SESSION-CAPABILITIES",
                &[
                    CallCapabilityKind::ReadOnlySimulation.as_str().to_string(),
                    CallCapabilityKind::PrivateStateRead.as_str().to_string(),
                ],
            ),
        };

        let budget_alpha = PrivateAllowanceBudget {
            budget_id: id("ALLOWANCE-BUDGET", "alpha-swap-budget-epoch-12"),
            owner_commitment: owner_alpha.clone(),
            contract_scope_root: list_root("BUDGET-CONTRACTS", &[contract_swap.clone()]),
            asset_scope_root: list_root(
                "BUDGET-ASSETS",
                &[
                    commitment("ASSET", "shielded-dusd"),
                    commitment("ASSET", "shielded-xmr"),
                ],
            ),
            budget_commitment: commitment("BUDGET", "alpha-epoch-12-budget"),
            spent_commitment: commitment("BUDGET-SPENT", "alpha-epoch-12-spent"),
            reserved_commitment: commitment("BUDGET-RESERVED", "alpha-epoch-12-reserved"),
            status: BudgetStatus::Active,
            opened_at_height: height - 120,
            expires_at_height: height + 600,
            epoch: 12,
        };
        let budget_beta = PrivateAllowanceBudget {
            budget_id: id("ALLOWANCE-BUDGET", "beta-view-only-budget"),
            owner_commitment: owner_beta.clone(),
            contract_scope_root: list_root("BUDGET-CONTRACTS", &[contract_vault.clone()]),
            asset_scope_root: list_root("BUDGET-ASSETS", &[commitment("ASSET", "vault-share")]),
            budget_commitment: commitment("BUDGET", "beta-view-bound-budget"),
            spent_commitment: commitment("BUDGET-SPENT", "beta-view-bound-spent"),
            reserved_commitment: commitment("BUDGET-RESERVED", "beta-view-bound-reserved"),
            status: BudgetStatus::Funding,
            opened_at_height: height - 64,
            expires_at_height: height + 480,
            epoch: 12,
        };

        let hook_alpha = SponsorProofHook {
            hook_id: id("SPONSOR-HOOK", "alpha-low-fee-sponsor"),
            sponsor_commitment: commitment("SPONSOR", "devnet-contract-call-sponsor"),
            account_commitment: owner_alpha.clone(),
            contract_scope_root: list_root("SPONSOR-CONTRACTS", &[contract_swap.clone()]),
            fee_asset_commitment: commitment("ASSET", "nebula-fee-credit"),
            proof_program_root: commitment("SPONSOR-PROGRAM", "swap-router-proof-hook"),
            witness_policy_root: commitment("SPONSOR-WITNESS-POLICY", "no-call-data-disclosure"),
            rebate_bps: 7_500,
            status: SponsorHookStatus::Bound,
            opened_at_height: height - 48,
            expires_at_height: height + 384,
        };
        let hook_beta = SponsorProofHook {
            hook_id: id("SPONSOR-HOOK", "beta-view-only-sponsor"),
            sponsor_commitment: commitment("SPONSOR", "devnet-view-sponsor"),
            account_commitment: owner_beta.clone(),
            contract_scope_root: list_root("SPONSOR-CONTRACTS", &[contract_vault.clone()]),
            fee_asset_commitment: commitment("ASSET", "nebula-fee-credit"),
            proof_program_root: commitment("SPONSOR-PROGRAM", "view-only-proof-hook"),
            witness_policy_root: commitment("SPONSOR-WITNESS-POLICY", "view-bounds-only"),
            rebate_bps: 2_500,
            status: SponsorHookStatus::Offered,
            opened_at_height: height - 16,
            expires_at_height: height + 128,
        };

        let note_alpha = CallCapabilityNote {
            note_id: id("CAPABILITY-NOTE", "alpha-swap-call-note"),
            owner_commitment: owner_alpha.clone(),
            contract_id: contract_swap.clone(),
            function_selector_root: commitment("FUNCTION-SELECTOR", "swap_exact_private_input"),
            capability: CallCapabilityKind::TokenSpend,
            status: CapabilityNoteStatus::Active,
            allowance_budget_id: budget_alpha.budget_id.clone(),
            session_key_id: session_alpha.session_key_id.clone(),
            nullifier_root: commitment("NULLIFIER-SET", "alpha-swap-nullifiers"),
            view_tag_root: commitment("VIEW-TAG", "alpha-swap-view-tags"),
            sponsor_hook_id: hook_alpha.hook_id.clone(),
            opened_at_height: height - 12,
            expires_at_height: height + 72,
            call_weight_limit: 980_000,
            privacy_set_size: 256,
        };
        let note_beta = CallCapabilityNote {
            note_id: id("CAPABILITY-NOTE", "beta-vault-read-note"),
            owner_commitment: owner_beta.clone(),
            contract_id: contract_vault.clone(),
            function_selector_root: commitment("FUNCTION-SELECTOR", "preview_private_withdrawal"),
            capability: CallCapabilityKind::ReadOnlySimulation,
            status: CapabilityNoteStatus::Draft,
            allowance_budget_id: budget_beta.budget_id.clone(),
            session_key_id: session_beta.session_key_id.clone(),
            nullifier_root: commitment("NULLIFIER-SET", "beta-view-nullifiers"),
            view_tag_root: commitment("VIEW-TAG", "beta-vault-view-tags"),
            sponsor_hook_id: hook_beta.hook_id.clone(),
            opened_at_height: height - 8,
            expires_at_height: height + 56,
            call_weight_limit: 220_000,
            privacy_set_size: 128,
        };

        let bound_alpha = ViewOnlySpendBound {
            bound_id: id("SPEND-BOUND", "alpha-per-call-dusd"),
            note_id: note_alpha.note_id.clone(),
            account_commitment: owner_alpha.clone(),
            contract_id: contract_swap.clone(),
            asset_commitment: commitment("ASSET", "shielded-dusd"),
            bound_kind: SpendBoundKind::PerCall,
            max_amount_commitment: commitment("BOUND-MAX", "alpha-per-call-max"),
            consumed_amount_commitment: commitment("BOUND-CONSUMED", "alpha-per-call-consumed"),
            window_start_height: height - 12,
            window_end_height: height + 72,
            disclosure_root: commitment("BOUND-DISCLOSURE", "selector-and-asset-only"),
        };
        let bound_beta = ViewOnlySpendBound {
            bound_id: id("SPEND-BOUND", "beta-view-only-vault"),
            note_id: note_beta.note_id.clone(),
            account_commitment: owner_beta.clone(),
            contract_id: contract_vault.clone(),
            asset_commitment: commitment("ASSET", "vault-share"),
            bound_kind: SpendBoundKind::ViewOnly,
            max_amount_commitment: commitment("BOUND-MAX", "beta-view-only-max"),
            consumed_amount_commitment: commitment("BOUND-CONSUMED", "beta-view-only-consumed"),
            window_start_height: height - 8,
            window_end_height: height + 56,
            disclosure_root: commitment("BOUND-DISCLOSURE", "view-only-envelope"),
        };

        let fence_alpha = ReplayNullifierFence {
            fence_id: id("REPLAY-FENCE", "alpha-swap-call-0"),
            nullifier_commitment: commitment("NULLIFIER", "alpha-swap-nullifier-0"),
            session_key_id: session_alpha.session_key_id.clone(),
            note_id: note_alpha.note_id.clone(),
            call_digest_root: commitment("CALL-DIGEST", "alpha-swap-call-digest-0"),
            status: FenceStatus::Reserved,
            reserved_at_height: height - 2,
            expires_at_height: height + config.queue_ttl_blocks,
            settlement_receipt_root: commitment("SETTLEMENT-RECEIPT", "pending-alpha-swap"),
        };
        let fence_beta = ReplayNullifierFence {
            fence_id: id("REPLAY-FENCE", "beta-view-call-0"),
            nullifier_commitment: commitment("NULLIFIER", "beta-view-nullifier-0"),
            session_key_id: session_beta.session_key_id.clone(),
            note_id: note_beta.note_id.clone(),
            call_digest_root: commitment("CALL-DIGEST", "beta-view-call-digest-0"),
            status: FenceStatus::Open,
            reserved_at_height: height - 1,
            expires_at_height: height + config.queue_ttl_blocks,
            settlement_receipt_root: commitment("SETTLEMENT-RECEIPT", "pending-beta-view"),
        };

        let queue_swap = BatchAuthorizationQueue {
            queue_id: id("AUTH-QUEUE", "private-swap-router-fast-lane"),
            contract_id: contract_swap.clone(),
            queue_root: list_root(
                "QUEUE-ITEMS",
                &[note_alpha.root(), fence_alpha.root(), hook_alpha.root()],
            ),
            status: QueueStatus::Open,
            opened_at_height: height - 3,
            expires_at_height: height + config.queue_ttl_blocks,
            max_items: 128,
            max_weight: 4_000_000,
            current_items: 3,
            current_weight: 1_140_000,
            sponsor_pool_root: list_root("QUEUE-SPONSORS", &[hook_alpha.hook_id.clone()]),
            sequencer_commitment: commitment("SEQUENCER", "devnet-private-sequencer-alpha"),
        };
        let queue_vault = BatchAuthorizationQueue {
            queue_id: id("AUTH-QUEUE", "private-vault-view-lane"),
            contract_id: contract_vault.clone(),
            queue_root: list_root(
                "QUEUE-ITEMS",
                &[note_beta.root(), fence_beta.root(), hook_beta.root()],
            ),
            status: QueueStatus::Sealed,
            opened_at_height: height - 2,
            expires_at_height: height + config.queue_ttl_blocks,
            max_items: 64,
            max_weight: 2_000_000,
            current_items: 2,
            current_weight: 340_000,
            sponsor_pool_root: list_root("QUEUE-SPONSORS", &[hook_beta.hook_id.clone()]),
            sequencer_commitment: commitment("SEQUENCER", "devnet-private-sequencer-beta"),
        };

        let policy_swap = AuthorizationPolicy {
            policy_id: id("AUTH-POLICY", "private-swap-router-policy"),
            contract_id: contract_swap.clone(),
            required_capability_root: list_root(
                "REQUIRED-CAPABILITIES",
                &[
                    CallCapabilityKind::PrivateStateRead.as_str().to_string(),
                    CallCapabilityKind::PrivateStateWrite.as_str().to_string(),
                    CallCapabilityKind::TokenSpend.as_str().to_string(),
                ],
            ),
            session_policy_root: commitment("SESSION-POLICY", "short-lived-pq-session"),
            spend_bound_policy_root: commitment("SPEND-POLICY", "asset-and-call-bound"),
            replay_policy_root: commitment("REPLAY-POLICY", "single-nullifier-per-call"),
            sponsor_policy_root: commitment("SPONSOR-POLICY", "optional-proof-hook"),
            min_privacy_set: 128,
            max_call_weight: 1_000_000,
            enabled: true,
        };
        let policy_vault = AuthorizationPolicy {
            policy_id: id("AUTH-POLICY", "private-vault-view-policy"),
            contract_id: contract_vault.clone(),
            required_capability_root: list_root(
                "REQUIRED-CAPABILITIES",
                &[
                    CallCapabilityKind::ReadOnlySimulation.as_str().to_string(),
                    CallCapabilityKind::PrivateStateRead.as_str().to_string(),
                ],
            ),
            session_policy_root: commitment("SESSION-POLICY", "view-session-rotation"),
            spend_bound_policy_root: commitment("SPEND-POLICY", "view-only-bound"),
            replay_policy_root: commitment("REPLAY-POLICY", "view-nullifier-reservation"),
            sponsor_policy_root: commitment("SPONSOR-POLICY", "view-proof-hook"),
            min_privacy_set: 96,
            max_call_weight: 300_000,
            enabled: true,
        };

        let receipt = RevocationReceipt {
            receipt_id: id("REVOCATION", "rotated-stale-alpha-session"),
            subject_id: id("SESSION-KEY", "alpha-session-stale"),
            subject_root: commitment("STALE-SESSION", "alpha-session-stale-root"),
            reason: RevocationReason::SessionRotation,
            revoked_by_commitment: owner_alpha,
            revoked_at_height: height - 44,
            effective_at_height: height - 44,
            replacement_root: session_alpha.root(),
            audit_trail_root: commitment("REVOCATION-AUDIT", "alpha-session-rotation-audit"),
        };

        let state = State {
            height,
            config,
            capability_notes: vec![note_alpha, note_beta],
            session_keys: vec![session_alpha, session_beta],
            view_spend_bounds: vec![bound_alpha, bound_beta],
            replay_fences: vec![fence_alpha, fence_beta],
            allowance_budgets: vec![budget_alpha, budget_beta],
            sponsor_hooks: vec![hook_alpha, hook_beta],
            authorization_queues: vec![queue_swap, queue_vault],
            revocation_receipts: vec![receipt],
            policies: vec![policy_swap, policy_vault],
            monotonic_event_counter: 31,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> PqPrivateContractCallAuthorizationLayerResult<()> {
        self.config.validate()?;
        validate_unique(
            "capability note",
            self.capability_notes
                .iter()
                .map(|item| item.note_id.as_str()),
        )?;
        validate_unique(
            "session key",
            self.session_keys
                .iter()
                .map(|item| item.session_key_id.as_str()),
        )?;
        validate_unique(
            "spend bound",
            self.view_spend_bounds
                .iter()
                .map(|item| item.bound_id.as_str()),
        )?;
        validate_unique(
            "replay fence",
            self.replay_fences.iter().map(|item| item.fence_id.as_str()),
        )?;
        validate_unique(
            "allowance budget",
            self.allowance_budgets
                .iter()
                .map(|item| item.budget_id.as_str()),
        )?;
        validate_unique(
            "sponsor hook",
            self.sponsor_hooks.iter().map(|item| item.hook_id.as_str()),
        )?;
        validate_unique(
            "authorization queue",
            self.authorization_queues
                .iter()
                .map(|item| item.queue_id.as_str()),
        )?;
        validate_unique(
            "revocation receipt",
            self.revocation_receipts
                .iter()
                .map(|item| item.receipt_id.as_str()),
        )?;
        validate_unique(
            "policy",
            self.policies.iter().map(|item| item.policy_id.as_str()),
        )?;

        let sessions = self
            .session_keys
            .iter()
            .map(|item| (item.session_key_id.as_str(), item))
            .collect::<BTreeMap<_, _>>();
        let budgets = self
            .allowance_budgets
            .iter()
            .map(|item| (item.budget_id.as_str(), item))
            .collect::<BTreeMap<_, _>>();
        let hooks = self
            .sponsor_hooks
            .iter()
            .map(|item| (item.hook_id.as_str(), item))
            .collect::<BTreeMap<_, _>>();
        let notes = self
            .capability_notes
            .iter()
            .map(|item| (item.note_id.as_str(), item))
            .collect::<BTreeMap<_, _>>();

        for session in &self.session_keys {
            session.validate()?;
        }
        for budget in &self.allowance_budgets {
            budget.validate()?;
        }
        for hook in &self.sponsor_hooks {
            hook.validate(&self.config)?;
        }
        for note in &self.capability_notes {
            note.validate(&self.config)?;
            if !sessions.contains_key(note.session_key_id.as_str()) {
                return Err(format!(
                    "capability note {} references missing session",
                    note.note_id
                ));
            }
            if !budgets.contains_key(note.allowance_budget_id.as_str()) {
                return Err(format!(
                    "capability note {} references missing allowance budget",
                    note.note_id
                ));
            }
            if note.sponsor_hook_id != "none" && !hooks.contains_key(note.sponsor_hook_id.as_str())
            {
                return Err(format!(
                    "capability note {} references missing sponsor hook",
                    note.note_id
                ));
            }
        }
        for bound in &self.view_spend_bounds {
            bound.validate()?;
            if !notes.contains_key(bound.note_id.as_str()) {
                return Err(format!(
                    "spend bound {} references missing capability note",
                    bound.bound_id
                ));
            }
        }
        for fence in &self.replay_fences {
            fence.validate()?;
            if !notes.contains_key(fence.note_id.as_str()) {
                return Err(format!(
                    "replay fence {} references missing capability note",
                    fence.fence_id
                ));
            }
            if !sessions.contains_key(fence.session_key_id.as_str()) {
                return Err(format!(
                    "replay fence {} references missing session",
                    fence.fence_id
                ));
            }
        }
        for queue in &self.authorization_queues {
            queue.validate(&self.config)?;
        }
        for receipt in &self.revocation_receipts {
            receipt.validate()?;
        }
        for policy in &self.policies {
            policy.validate(&self.config)?;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn update_height(
        &mut self,
        height: u64,
    ) -> PqPrivateContractCallAuthorizationLayerResult<()> {
        if height < self.height {
            return Err("authorization layer height cannot decrease".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn counters(&self) -> Counters {
        Counters {
            capability_notes: self.capability_notes.len() as u64,
            live_capability_notes: self
                .capability_notes
                .iter()
                .filter(|item| item.status.is_live())
                .count() as u64,
            session_keys: self.session_keys.len() as u64,
            authorizing_session_keys: self
                .session_keys
                .iter()
                .filter(|item| item.status.authorizes_calls())
                .count() as u64,
            view_spend_bounds: self.view_spend_bounds.len() as u64,
            replay_fences: self.replay_fences.len() as u64,
            blocking_replay_fences: self
                .replay_fences
                .iter()
                .filter(|item| item.status.blocks_replay())
                .count() as u64,
            allowance_budgets: self.allowance_budgets.len() as u64,
            spendable_allowance_budgets: self
                .allowance_budgets
                .iter()
                .filter(|item| item.status.spendable())
                .count() as u64,
            sponsor_hooks: self.sponsor_hooks.len() as u64,
            authorization_queues: self.authorization_queues.len() as u64,
            accepting_queues: self
                .authorization_queues
                .iter()
                .filter(|item| item.status.accepts_items())
                .count() as u64,
            revocation_receipts: self.revocation_receipts.len() as u64,
            policies: self.policies.len() as u64,
            enabled_policies: self.policies.iter().filter(|item| item.enabled).count() as u64,
            monotonic_event_counter: self.monotonic_event_counter,
        }
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.root();
        let capability_note_root = records_root(
            "CAPABILITY-NOTES",
            self.capability_notes
                .iter()
                .map(CallCapabilityNote::public_record)
                .collect(),
        );
        let session_key_root = records_root(
            "SESSION-KEYS",
            self.session_keys
                .iter()
                .map(SessionKey::public_record)
                .collect(),
        );
        let view_spend_bound_root = records_root(
            "VIEW-SPEND-BOUNDS",
            self.view_spend_bounds
                .iter()
                .map(ViewOnlySpendBound::public_record)
                .collect(),
        );
        let replay_fence_root = records_root(
            "REPLAY-FENCES",
            self.replay_fences
                .iter()
                .map(ReplayNullifierFence::public_record)
                .collect(),
        );
        let allowance_budget_root = records_root(
            "ALLOWANCE-BUDGETS",
            self.allowance_budgets
                .iter()
                .map(PrivateAllowanceBudget::public_record)
                .collect(),
        );
        let sponsor_hook_root = records_root(
            "SPONSOR-HOOKS",
            self.sponsor_hooks
                .iter()
                .map(SponsorProofHook::public_record)
                .collect(),
        );
        let queue_root = records_root(
            "AUTHORIZATION-QUEUES",
            self.authorization_queues
                .iter()
                .map(BatchAuthorizationQueue::public_record)
                .collect(),
        );
        let revocation_receipt_root = records_root(
            "REVOCATION-RECEIPTS",
            self.revocation_receipts
                .iter()
                .map(RevocationReceipt::public_record)
                .collect(),
        );
        let policy_root = records_root(
            "AUTHORIZATION-POLICIES",
            self.policies
                .iter()
                .map(AuthorizationPolicy::public_record)
                .collect(),
        );
        let active_account_root = records_root(
            "ACTIVE-AUTHORIZATION-ACCOUNTS",
            self.capability_notes
                .iter()
                .filter(|item| item.status.is_live())
                .map(|item| json!(item.owner_commitment))
                .collect(),
        );
        let nullifier_fence_index_root = records_root(
            "NULLIFIER-FENCE-INDEX",
            self.replay_fences
                .iter()
                .map(|item| {
                    json!({
                        "nullifier_commitment": item.nullifier_commitment,
                        "fence_id": item.fence_id,
                        "status": item.status.as_str(),
                    })
                })
                .collect(),
        );
        let counters = self.counters().public_record();
        let root_payload = json!({
            "height": self.height,
            "protocol_version": PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config_root": config_root,
            "capability_note_root": capability_note_root,
            "session_key_root": session_key_root,
            "view_spend_bound_root": view_spend_bound_root,
            "replay_fence_root": replay_fence_root,
            "allowance_budget_root": allowance_budget_root,
            "sponsor_hook_root": sponsor_hook_root,
            "queue_root": queue_root,
            "revocation_receipt_root": revocation_receipt_root,
            "policy_root": policy_root,
            "active_account_root": active_account_root,
            "nullifier_fence_index_root": nullifier_fence_index_root,
            "counters": counters,
        });
        let state_root = root_from_record(&root_payload);
        Roots {
            config_root,
            capability_note_root,
            session_key_root,
            view_spend_bound_root,
            replay_fence_root,
            allowance_budget_root,
            sponsor_hook_root,
            queue_root,
            revocation_receipt_root,
            policy_root,
            active_account_root,
            nullifier_fence_index_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_PROTOCOL_VERSION,
            "schema_version": PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_SCHEMA_VERSION,
            "devnet_label": PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_DEVNET_LABEL,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "capability_notes": self.capability_notes.iter().map(CallCapabilityNote::public_record).collect::<Vec<_>>(),
            "session_keys": self.session_keys.iter().map(SessionKey::public_record).collect::<Vec<_>>(),
            "view_spend_bounds": self.view_spend_bounds.iter().map(ViewOnlySpendBound::public_record).collect::<Vec<_>>(),
            "replay_fences": self.replay_fences.iter().map(ReplayNullifierFence::public_record).collect::<Vec<_>>(),
            "allowance_budgets": self.allowance_budgets.iter().map(PrivateAllowanceBudget::public_record).collect::<Vec<_>>(),
            "sponsor_hooks": self.sponsor_hooks.iter().map(SponsorProofHook::public_record).collect::<Vec<_>>(),
            "authorization_queues": self.authorization_queues.iter().map(BatchAuthorizationQueue::public_record).collect::<Vec<_>>(),
            "revocation_receipts": self.revocation_receipts.iter().map(RevocationReceipt::public_record).collect::<Vec<_>>(),
            "policies": self.policies.iter().map(AuthorizationPolicy::public_record).collect::<Vec<_>>(),
            "counters": counters.public_record(),
            "roots": roots.public_record(),
        })
    }
}

pub fn root_from_record(record: &Value) -> String {
    record_root("STATE-RECORD", record)
}

pub fn devnet() -> PqPrivateContractCallAuthorizationLayerResult<State> {
    State::devnet()
}

fn record_root(domain: &str, record: &Value) -> String {
    stable_hash(
        &format!("PQ-PRIVATE-CONTRACT-CALL-AUTHORIZATION-LAYER-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn records_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!("PQ-PRIVATE-CONTRACT-CALL-AUTHORIZATION-LAYER-{domain}"),
        &records,
    )
}

fn list_root(domain: &str, values: &[String]) -> String {
    let records = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    records_root(domain, records)
}

fn id(domain: &str, label: &str) -> String {
    stable_hash(
        &format!("PQ-PRIVATE-CONTRACT-CALL-AUTHORIZATION-LAYER-{domain}-ID"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn commitment(domain: &str, label: &str) -> String {
    stable_hash(
        &format!("PQ-PRIVATE-CONTRACT-CALL-AUTHORIZATION-LAYER-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PQ_PRIVATE_CONTRACT_CALL_AUTHORIZATION_LAYER_PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn require_id(label: &str, value: &str) -> PqPrivateContractCallAuthorizationLayerResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must be populated"));
    }
    Ok(())
}

fn require_hash(label: &str, value: &str) -> PqPrivateContractCallAuthorizationLayerResult<()> {
    if value.len() < 32 || value.trim().is_empty() {
        return Err(format!("{label} must be a populated commitment root"));
    }
    Ok(())
}

fn validate_unique<'a, I>(
    label: &str,
    values: I,
) -> PqPrivateContractCallAuthorizationLayerResult<()>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(format!("duplicate {label} id {value}"));
        }
    }
    Ok(())
}
