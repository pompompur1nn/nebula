use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqAccountSessionPaymasterResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-account-session-paymaster-v1";
pub const PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_SESSION_SCHEME: &str =
    "ml-dsa-87-session-key-commitment+zk-wallet-policy-v1";
pub const PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_PAYMASTER_SCHEME: &str =
    "private-low-fee-paymaster-credit-root-v1";
pub const PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_REPLAY_FENCE_SCHEME: &str =
    "private-session-nullifier-replay-fence-root-v1";
pub const PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_BATCH_SCHEME: &str =
    "pq-session-batched-authorization-root-v1";
pub const PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEVNET_HEIGHT: u64 = 144_000;
pub const PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEFAULT_MAX_OPEN_SESSIONS: usize = 262_144;
pub const PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEFAULT_MAX_BATCH_SESSIONS: usize = 2_048;
pub const PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEFAULT_SESSION_TTL_BLOCKS: u64 = 72;
pub const PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 1_024;
pub const PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 8_192;
pub const PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEFAULT_MAX_FEE_BPS: u64 = 30;
pub const PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEFAULT_SPONSOR_COVERAGE_BPS: u64 = 8_500;
pub const PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    ContractCall,
    TokenTransfer,
    DefiIntent,
    MoneroExit,
    ProofPublication,
    WalletRecovery,
    CrossDomainMessage,
}

impl SessionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractCall => "contract_call",
            Self::TokenTransfer => "token_transfer",
            Self::DefiIntent => "defi_intent",
            Self::MoneroExit => "monero_exit",
            Self::ProofPublication => "proof_publication",
            Self::WalletRecovery => "wallet_recovery",
            Self::CrossDomainMessage => "cross_domain_message",
        }
    }

    pub fn default_scope(self) -> DelegationScope {
        match self {
            Self::ContractCall => DelegationScope::ContractScoped,
            Self::TokenTransfer => DelegationScope::AssetScoped,
            Self::DefiIntent => DelegationScope::VenueScoped,
            Self::MoneroExit => DelegationScope::ExitScoped,
            Self::ProofPublication => DelegationScope::ProofScoped,
            Self::WalletRecovery => DelegationScope::RecoveryScoped,
            Self::CrossDomainMessage => DelegationScope::MessageScoped,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationScope {
    ContractScoped,
    AssetScoped,
    VenueScoped,
    ExitScoped,
    ProofScoped,
    RecoveryScoped,
    MessageScoped,
    MultiLaneScoped,
}

impl DelegationScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractScoped => "contract_scoped",
            Self::AssetScoped => "asset_scoped",
            Self::VenueScoped => "venue_scoped",
            Self::ExitScoped => "exit_scoped",
            Self::ProofScoped => "proof_scoped",
            Self::RecoveryScoped => "recovery_scoped",
            Self::MessageScoped => "message_scoped",
            Self::MultiLaneScoped => "multi_lane_scoped",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Open,
    Sponsored,
    Batched,
    Settled,
    Revoked,
    Expired,
    Rejected,
}

impl SessionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sponsored => "sponsored",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Sponsored)
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Revoked | Self::Expired | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Offered,
    Reserved,
    Spent,
    Refunded,
    Expired,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Spent => "spent",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    SettlementReady,
    Settled,
    Expired,
    Rejected,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub max_open_sessions: usize,
    pub max_batch_sessions: usize,
    pub session_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub default_sponsor_coverage_bps: u64,
    pub require_fee_sponsor: bool,
    pub require_replay_fence: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            max_open_sessions: PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEFAULT_MAX_OPEN_SESSIONS,
            max_batch_sessions: PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEFAULT_MAX_BATCH_SESSIONS,
            session_ttl_blocks: PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEFAULT_SESSION_TTL_BLOCKS,
            sponsor_ttl_blocks: PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEFAULT_SPONSOR_TTL_BLOCKS,
            min_privacy_set_size:
                PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size:
                PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_fee_bps: PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEFAULT_MAX_FEE_BPS,
            default_sponsor_coverage_bps:
                PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEFAULT_SPONSOR_COVERAGE_BPS,
            require_fee_sponsor: true,
            require_replay_fence: true,
        }
    }

    pub fn validate(&self) -> PrivateL2PqAccountSessionPaymasterResult<()> {
        if self.max_open_sessions == 0 {
            return Err("pq session paymaster max_open_sessions must be non-zero".to_string());
        }
        if self.max_batch_sessions == 0 || self.max_batch_sessions > self.max_open_sessions {
            return Err("pq session paymaster max_batch_sessions invalid".to_string());
        }
        if self.session_ttl_blocks == 0 || self.sponsor_ttl_blocks == 0 {
            return Err("pq session paymaster ttl values must be non-zero".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("pq session paymaster privacy set config invalid".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("pq session paymaster pq security floor too low".to_string());
        }
        if self.max_fee_bps > PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_MAX_BPS
            || self.default_sponsor_coverage_bps > PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_MAX_BPS
        {
            return Err("pq session paymaster bps config exceeds max".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "max_open_sessions": self.max_open_sessions,
            "max_batch_sessions": self.max_batch_sessions,
            "session_ttl_blocks": self.session_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "default_sponsor_coverage_bps": self.default_sponsor_coverage_bps,
            "require_fee_sponsor": self.require_fee_sponsor,
            "require_replay_fence": self.require_replay_fence,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_session_sequence: u64,
    pub next_sponsor_sequence: u64,
    pub next_batch_sequence: u64,
    pub sessions_opened: u64,
    pub sessions_sponsored: u64,
    pub sessions_batched: u64,
    pub sessions_settled: u64,
    pub sessions_revoked: u64,
    pub sessions_expired: u64,
    pub sessions_rejected: u64,
    pub sponsor_credits_reserved: u64,
    pub sponsor_credits_spent: u64,
    pub sponsor_credits_refunded: u64,
    pub batches_built: u64,
    pub batches_settled: u64,
    pub receipts_published: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "next_session_sequence": self.next_session_sequence,
            "next_sponsor_sequence": self.next_sponsor_sequence,
            "next_batch_sequence": self.next_batch_sequence,
            "sessions_opened": self.sessions_opened,
            "sessions_sponsored": self.sessions_sponsored,
            "sessions_batched": self.sessions_batched,
            "sessions_settled": self.sessions_settled,
            "sessions_revoked": self.sessions_revoked,
            "sessions_expired": self.sessions_expired,
            "sessions_rejected": self.sessions_rejected,
            "sponsor_credits_reserved": self.sponsor_credits_reserved,
            "sponsor_credits_spent": self.sponsor_credits_spent,
            "sponsor_credits_refunded": self.sponsor_credits_refunded,
            "batches_built": self.batches_built,
            "batches_settled": self.batches_settled,
            "receipts_published": self.receipts_published,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenSessionRequest {
    pub session_kind: SessionKind,
    pub delegation_scope: Option<DelegationScope>,
    pub wallet_commitment: String,
    pub account_policy_root: String,
    pub session_key_commitment: String,
    pub spend_limit_root: String,
    pub scope_root: String,
    pub call_policy_root: String,
    pub lane_binding_root: String,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub pq_authorization_root: String,
    pub pq_signature_root: String,
    pub privacy_proof_root: String,
    pub low_fee_sponsor_root: Option<String>,
    pub max_fee_bps: u64,
    pub sponsor_budget_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub request_nonce: String,
}

impl OpenSessionRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqAccountSessionPaymasterResult<()> {
        validate_root("wallet_commitment", &self.wallet_commitment)?;
        validate_root("account_policy_root", &self.account_policy_root)?;
        validate_root("session_key_commitment", &self.session_key_commitment)?;
        validate_root("spend_limit_root", &self.spend_limit_root)?;
        validate_root("scope_root", &self.scope_root)?;
        validate_root("call_policy_root", &self.call_policy_root)?;
        validate_root("lane_binding_root", &self.lane_binding_root)?;
        validate_root("nullifier_root", &self.nullifier_root)?;
        validate_root("replay_fence_root", &self.replay_fence_root)?;
        validate_root("pq_authorization_root", &self.pq_authorization_root)?;
        validate_root("pq_signature_root", &self.pq_signature_root)?;
        validate_root("privacy_proof_root", &self.privacy_proof_root)?;
        validate_secret("request_nonce", &self.request_nonce)?;
        if config.require_fee_sponsor {
            match &self.low_fee_sponsor_root {
                Some(root) => validate_root("low_fee_sponsor_root", root)?,
                None => return Err("pq session paymaster requires fee sponsor root".to_string()),
            }
        }
        if self.max_fee_bps > config.max_fee_bps {
            return Err("pq session paymaster max fee exceeds config cap".to_string());
        }
        if self.sponsor_budget_micro_units == 0 && config.require_fee_sponsor {
            return Err("pq session paymaster sponsor budget must be non-zero".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("pq session paymaster privacy set below floor".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("pq session paymaster pq security bits below floor".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("pq session paymaster expiry must follow open height".to_string());
        }
        if self.expires_at_height
            > self
                .opened_at_height
                .saturating_add(config.session_ttl_blocks)
        {
            return Err("pq session paymaster session ttl exceeds config".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorSessionRequest {
    pub session_id: String,
    pub sponsor_id: String,
    pub sponsor_policy_root: String,
    pub fee_credit_root: String,
    pub rebate_commitment_root: String,
    pub sponsor_pq_authorization_root: String,
    pub coverage_bps: u64,
    pub max_fee_bps: u64,
    pub credit_micro_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorSessionRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqAccountSessionPaymasterResult<()> {
        validate_root("session_id", &self.session_id)?;
        validate_secret("sponsor_id", &self.sponsor_id)?;
        validate_root("sponsor_policy_root", &self.sponsor_policy_root)?;
        validate_root("fee_credit_root", &self.fee_credit_root)?;
        validate_root("rebate_commitment_root", &self.rebate_commitment_root)?;
        validate_root(
            "sponsor_pq_authorization_root",
            &self.sponsor_pq_authorization_root,
        )?;
        if self.coverage_bps == 0
            || self.coverage_bps > PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_MAX_BPS
        {
            return Err("pq session sponsor coverage bps invalid".to_string());
        }
        if self.max_fee_bps > config.max_fee_bps {
            return Err("pq session sponsor max fee exceeds config cap".to_string());
        }
        if self.credit_micro_units == 0 {
            return Err("pq session sponsor credit must be non-zero".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("pq session sponsor expiry must follow open height".to_string());
        }
        if self.expires_at_height
            > self
                .opened_at_height
                .saturating_add(config.sponsor_ttl_blocks)
        {
            return Err("pq session sponsor ttl exceeds config".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildAuthorizationBatchRequest {
    pub session_ids: Vec<String>,
    pub builder_commitment: String,
    pub batch_witness_root: String,
    pub batch_proof_root: String,
    pub aggregate_pq_authorization_root: String,
    pub aggregate_privacy_proof_root: String,
    pub aggregate_fee_sponsor_root: String,
    pub call_graph_root: String,
    pub fee_credit_root: String,
    pub low_fee_rebate_root: String,
    pub sealed_at_height: u64,
}

impl BuildAuthorizationBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2PqAccountSessionPaymasterResult<()> {
        if self.session_ids.is_empty() {
            return Err("pq session batch requires sessions".to_string());
        }
        if self.session_ids.len() > config.max_batch_sessions {
            return Err("pq session batch exceeds max sessions".to_string());
        }
        let unique = self.session_ids.iter().collect::<BTreeSet<_>>();
        if unique.len() != self.session_ids.len() {
            return Err("pq session batch cannot contain duplicate sessions".to_string());
        }
        validate_root("builder_commitment", &self.builder_commitment)?;
        validate_root("batch_witness_root", &self.batch_witness_root)?;
        validate_root("batch_proof_root", &self.batch_proof_root)?;
        validate_root(
            "aggregate_pq_authorization_root",
            &self.aggregate_pq_authorization_root,
        )?;
        validate_root(
            "aggregate_privacy_proof_root",
            &self.aggregate_privacy_proof_root,
        )?;
        validate_root(
            "aggregate_fee_sponsor_root",
            &self.aggregate_fee_sponsor_root,
        )?;
        validate_root("call_graph_root", &self.call_graph_root)?;
        validate_root("fee_credit_root", &self.fee_credit_root)?;
        validate_root("low_fee_rebate_root", &self.low_fee_rebate_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleAuthorizationBatchRequest {
    pub batch_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub settlement_witness_root: String,
    pub spent_nullifier_root: String,
    pub replay_fence_consumption_root: String,
    pub fee_spend_root: String,
    pub sponsor_rebate_root: String,
    pub state_transition_root: String,
    pub runtime_state_root_after: String,
    pub settled_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl SettleAuthorizationBatchRequest {
    pub fn validate(&self) -> PrivateL2PqAccountSessionPaymasterResult<()> {
        validate_root("batch_id", &self.batch_id)?;
        validate_root("settlement_tx_root", &self.settlement_tx_root)?;
        validate_root("settlement_proof_root", &self.settlement_proof_root)?;
        validate_root("settlement_witness_root", &self.settlement_witness_root)?;
        validate_root("spent_nullifier_root", &self.spent_nullifier_root)?;
        validate_root(
            "replay_fence_consumption_root",
            &self.replay_fence_consumption_root,
        )?;
        validate_root("fee_spend_root", &self.fee_spend_root)?;
        validate_root("sponsor_rebate_root", &self.sponsor_rebate_root)?;
        validate_root("state_transition_root", &self.state_transition_root)?;
        validate_root("runtime_state_root_after", &self.runtime_state_root_after)?;
        if let Some(finalized_at_height) = self.finalized_at_height {
            if finalized_at_height < self.settled_at_height {
                return Err("pq session finality cannot precede settlement".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateAccountSession {
    pub session_id: String,
    pub sequence: u64,
    pub status: SessionStatus,
    pub session_kind: SessionKind,
    pub delegation_scope: DelegationScope,
    pub wallet_commitment: String,
    pub account_policy_root: String,
    pub session_key_commitment: String,
    pub spend_limit_root: String,
    pub scope_root: String,
    pub call_policy_root: String,
    pub lane_binding_root: String,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub pq_authorization_root: String,
    pub pq_signature_root: String,
    pub privacy_proof_root: String,
    pub low_fee_sponsor_root: String,
    pub max_fee_bps: u64,
    pub sponsor_budget_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub updated_at_height: u64,
    pub request_nonce_root: String,
    pub sponsor_receipt_id: Option<String>,
    pub batch_id: Option<String>,
    pub settlement_receipt_id: Option<String>,
}

impl PrivateAccountSession {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_account_session",
            "session_id": self.session_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "session_kind": self.session_kind.as_str(),
            "delegation_scope": self.delegation_scope.as_str(),
            "wallet_commitment": self.wallet_commitment,
            "account_policy_root": self.account_policy_root,
            "session_key_commitment": self.session_key_commitment,
            "spend_limit_root": self.spend_limit_root,
            "scope_root": self.scope_root,
            "call_policy_root": self.call_policy_root,
            "lane_binding_root": self.lane_binding_root,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "pq_authorization_root": self.pq_authorization_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_proof_root": self.privacy_proof_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "max_fee_bps": self.max_fee_bps,
            "sponsor_budget_micro_units": self.sponsor_budget_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "updated_at_height": self.updated_at_height,
            "request_nonce_root": self.request_nonce_root,
            "sponsor_receipt_id": self.sponsor_receipt_id,
            "batch_id": self.batch_id,
            "settlement_receipt_id": self.settlement_receipt_id,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-SESSION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorReceipt {
    pub sponsor_receipt_id: String,
    pub sequence: u64,
    pub session_id: String,
    pub sponsor_id: String,
    pub status: SponsorStatus,
    pub sponsor_policy_root: String,
    pub fee_credit_root: String,
    pub rebate_commitment_root: String,
    pub sponsor_pq_authorization_root: String,
    pub coverage_bps: u64,
    pub max_fee_bps: u64,
    pub credit_micro_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub spent_at_height: Option<u64>,
}

impl SponsorReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_account_session_sponsor_receipt",
            "sponsor_receipt_id": self.sponsor_receipt_id,
            "sequence": self.sequence,
            "session_id": self.session_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status.as_str(),
            "sponsor_policy_root": self.sponsor_policy_root,
            "fee_credit_root": self.fee_credit_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "sponsor_pq_authorization_root": self.sponsor_pq_authorization_root,
            "coverage_bps": self.coverage_bps,
            "max_fee_bps": self.max_fee_bps,
            "credit_micro_units": self.credit_micro_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "spent_at_height": self.spent_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-SPONSOR-RECEIPT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationBatch {
    pub batch_id: String,
    pub sequence: u64,
    pub status: BatchStatus,
    pub session_ids: Vec<String>,
    pub session_root: String,
    pub sponsor_receipt_root: String,
    pub builder_commitment: String,
    pub batch_witness_root: String,
    pub batch_proof_root: String,
    pub aggregate_pq_authorization_root: String,
    pub aggregate_privacy_proof_root: String,
    pub aggregate_fee_sponsor_root: String,
    pub call_graph_root: String,
    pub fee_credit_root: String,
    pub low_fee_rebate_root: String,
    pub total_sponsor_budget_micro_units: u64,
    pub max_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub sealed_at_height: u64,
    pub settlement_deadline_height: u64,
}

impl AuthorizationBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_account_session_authorization_batch",
            "batch_id": self.batch_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "session_ids": self.session_ids,
            "session_root": self.session_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "builder_commitment": self.builder_commitment,
            "batch_witness_root": self.batch_witness_root,
            "batch_proof_root": self.batch_proof_root,
            "aggregate_pq_authorization_root": self.aggregate_pq_authorization_root,
            "aggregate_privacy_proof_root": self.aggregate_privacy_proof_root,
            "aggregate_fee_sponsor_root": self.aggregate_fee_sponsor_root,
            "call_graph_root": self.call_graph_root,
            "fee_credit_root": self.fee_credit_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "total_sponsor_budget_micro_units": self.total_sponsor_budget_micro_units,
            "max_fee_bps": self.max_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "sealed_at_height": self.sealed_at_height,
            "settlement_deadline_height": self.settlement_deadline_height,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-AUTHORIZATION-BATCH",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub status: BatchStatus,
    pub batch_root: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub settlement_witness_root: String,
    pub spent_nullifier_root: String,
    pub replay_fence_consumption_root: String,
    pub fee_spend_root: String,
    pub sponsor_rebate_root: String,
    pub state_transition_root: String,
    pub runtime_state_root_before: String,
    pub runtime_state_root_after: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub settled_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_account_session_settlement_receipt",
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "batch_root": self.batch_root,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "settlement_witness_root": self.settlement_witness_root,
            "spent_nullifier_root": self.spent_nullifier_root,
            "replay_fence_consumption_root": self.replay_fence_consumption_root,
            "fee_spend_root": self.fee_spend_root,
            "sponsor_rebate_root": self.sponsor_rebate_root,
            "state_transition_root": self.state_transition_root,
            "runtime_state_root_before": self.runtime_state_root_before,
            "runtime_state_root_after": self.runtime_state_root_after,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "settled_at_height": self.settled_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-SETTLEMENT-RECEIPT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub session_root: String,
    pub open_session_root: String,
    pub sponsor_receipt_root: String,
    pub batch_root: String,
    pub settlement_receipt_root: String,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub pq_authorization_root: String,
    pub fee_sponsor_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "session_root": self.session_root,
            "open_session_root": self.open_session_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "batch_root": self.batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "pq_authorization_root": self.pq_authorization_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub runtime_root: String,
    pub sessions: BTreeMap<String, PrivateAccountSession>,
    pub sponsor_receipts: BTreeMap<String, SponsorReceipt>,
    pub batches: BTreeMap<String, AuthorizationBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub nullifier_index: BTreeSet<String>,
    pub replay_fence_index: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let runtime_root = root_from_record(
            "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-DEVNET-RUNTIME",
            &json!({
                "chain_id": CHAIN_ID,
                "protocol_version": PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_PROTOCOL_VERSION,
                "profile": "devnet",
            }),
        );
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            current_height: PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_DEVNET_HEIGHT,
            runtime_root,
            sessions: BTreeMap::new(),
            sponsor_receipts: BTreeMap::new(),
            batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            nullifier_index: BTreeSet::new(),
            replay_fence_index: BTreeSet::new(),
        }
    }

    pub fn open_session(
        &mut self,
        request: OpenSessionRequest,
    ) -> PrivateL2PqAccountSessionPaymasterResult<PrivateAccountSession> {
        self.config.validate()?;
        self.expire_stale(request.opened_at_height);
        request.validate(&self.config)?;
        if self
            .sessions
            .values()
            .filter(|session| !session.status.terminal())
            .count()
            >= self.config.max_open_sessions
        {
            self.counters.sessions_rejected = self.counters.sessions_rejected.saturating_add(1);
            return Err("pq session paymaster open-session capacity reached".to_string());
        }
        if self.nullifier_index.contains(&request.nullifier_root) {
            self.counters.sessions_rejected = self.counters.sessions_rejected.saturating_add(1);
            return Err("pq session paymaster nullifier already used".to_string());
        }
        if self.replay_fence_index.contains(&request.replay_fence_root) {
            self.counters.sessions_rejected = self.counters.sessions_rejected.saturating_add(1);
            return Err("pq session paymaster replay fence already used".to_string());
        }
        let sequence = self.counters.next_session_sequence.saturating_add(1);
        let delegation_scope = request
            .delegation_scope
            .unwrap_or_else(|| request.session_kind.default_scope());
        let session_id = session_id(
            sequence,
            &request.wallet_commitment,
            &request.session_key_commitment,
            &request.nullifier_root,
            request.opened_at_height,
            &request.request_nonce,
        );
        let low_fee_sponsor_root = request
            .low_fee_sponsor_root
            .unwrap_or_else(empty_fee_sponsor_root);
        let session = PrivateAccountSession {
            session_id: session_id.clone(),
            sequence,
            status: SessionStatus::Open,
            session_kind: request.session_kind,
            delegation_scope,
            wallet_commitment: request.wallet_commitment,
            account_policy_root: request.account_policy_root,
            session_key_commitment: request.session_key_commitment,
            spend_limit_root: request.spend_limit_root,
            scope_root: request.scope_root,
            call_policy_root: request.call_policy_root,
            lane_binding_root: request.lane_binding_root,
            nullifier_root: request.nullifier_root,
            replay_fence_root: request.replay_fence_root,
            pq_authorization_root: request.pq_authorization_root,
            pq_signature_root: request.pq_signature_root,
            privacy_proof_root: request.privacy_proof_root,
            low_fee_sponsor_root,
            max_fee_bps: request.max_fee_bps,
            sponsor_budget_micro_units: request.sponsor_budget_micro_units,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            opened_at_height: request.opened_at_height,
            expires_at_height: request.expires_at_height,
            updated_at_height: request.opened_at_height,
            request_nonce_root: secret_root(
                "PRIVATE-L2-PQ-ACCOUNT-SESSION-NONCE",
                &request.request_nonce,
            ),
            sponsor_receipt_id: None,
            batch_id: None,
            settlement_receipt_id: None,
        };
        self.nullifier_index.insert(session.nullifier_root.clone());
        self.replay_fence_index
            .insert(session.replay_fence_root.clone());
        self.sessions.insert(session_id, session.clone());
        self.counters.next_session_sequence = sequence;
        self.counters.sessions_opened = self.counters.sessions_opened.saturating_add(1);
        self.current_height = self.current_height.max(session.opened_at_height);
        Ok(session)
    }

    pub fn sponsor_session(
        &mut self,
        request: SponsorSessionRequest,
    ) -> PrivateL2PqAccountSessionPaymasterResult<SponsorReceipt> {
        self.config.validate()?;
        self.expire_stale(request.opened_at_height);
        request.validate(&self.config)?;
        let mut session = self
            .sessions
            .get(&request.session_id)
            .cloned()
            .ok_or_else(|| format!("unknown pq account session {}", request.session_id))?;
        if !session.status.live() {
            return Err("pq account session is not sponsorable".to_string());
        }
        if request.opened_at_height > session.expires_at_height {
            session.status = SessionStatus::Expired;
            session.updated_at_height = request.opened_at_height;
            self.sessions.insert(session.session_id.clone(), session);
            self.counters.sessions_expired = self.counters.sessions_expired.saturating_add(1);
            return Err("pq account session expired before sponsorship".to_string());
        }
        if request.max_fee_bps > session.max_fee_bps {
            return Err("pq account session sponsor fee exceeds session cap".to_string());
        }
        let sequence = self.counters.next_sponsor_sequence.saturating_add(1);
        let sponsor_receipt_id = sponsor_receipt_id(
            sequence,
            &request.session_id,
            &request.sponsor_id,
            &request.fee_credit_root,
            request.opened_at_height,
        );
        let receipt = SponsorReceipt {
            sponsor_receipt_id: sponsor_receipt_id.clone(),
            sequence,
            session_id: request.session_id,
            sponsor_id: request.sponsor_id,
            status: SponsorStatus::Reserved,
            sponsor_policy_root: request.sponsor_policy_root,
            fee_credit_root: request.fee_credit_root,
            rebate_commitment_root: request.rebate_commitment_root,
            sponsor_pq_authorization_root: request.sponsor_pq_authorization_root,
            coverage_bps: request.coverage_bps,
            max_fee_bps: request.max_fee_bps,
            credit_micro_units: request.credit_micro_units,
            opened_at_height: request.opened_at_height,
            expires_at_height: request.expires_at_height,
            spent_at_height: None,
        };
        session.status = SessionStatus::Sponsored;
        session.updated_at_height = receipt.opened_at_height;
        session.sponsor_receipt_id = Some(sponsor_receipt_id.clone());
        session.low_fee_sponsor_root = receipt.fee_credit_root.clone();
        self.sessions.insert(session.session_id.clone(), session);
        self.sponsor_receipts
            .insert(sponsor_receipt_id, receipt.clone());
        self.counters.next_sponsor_sequence = sequence;
        self.counters.sessions_sponsored = self.counters.sessions_sponsored.saturating_add(1);
        self.counters.sponsor_credits_reserved = self
            .counters
            .sponsor_credits_reserved
            .saturating_add(receipt.credit_micro_units);
        self.current_height = self.current_height.max(receipt.opened_at_height);
        Ok(receipt)
    }

    pub fn build_authorization_batch(
        &mut self,
        request: BuildAuthorizationBatchRequest,
    ) -> PrivateL2PqAccountSessionPaymasterResult<AuthorizationBatch> {
        self.config.validate()?;
        self.expire_stale(request.sealed_at_height);
        request.validate(&self.config)?;
        let mut sessions = Vec::with_capacity(request.session_ids.len());
        for session_id in &request.session_ids {
            let session = self
                .sessions
                .get(session_id)
                .cloned()
                .ok_or_else(|| format!("unknown pq account session {session_id}"))?;
            if !session.status.live() {
                return Err(format!("pq account session {session_id} is not batchable"));
            }
            if request.sealed_at_height > session.expires_at_height {
                return Err(format!(
                    "pq account session {session_id} expired before batch"
                ));
            }
            if self.config.require_fee_sponsor && session.sponsor_receipt_id.is_none() {
                return Err(format!(
                    "pq account session {session_id} requires sponsor receipt"
                ));
            }
            sessions.push(session);
        }
        let session_root = merkle_root(
            "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-BATCH-SESSIONS",
            &sessions
                .iter()
                .map(PrivateAccountSession::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsor_records = sessions
            .iter()
            .filter_map(|session| session.sponsor_receipt_id.as_ref())
            .filter_map(|receipt_id| self.sponsor_receipts.get(receipt_id))
            .map(SponsorReceipt::public_record)
            .collect::<Vec<_>>();
        let sponsor_receipt_root = merkle_root(
            "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-BATCH-SPONSORS",
            &sponsor_records,
        );
        let total_sponsor_budget_micro_units = sessions
            .iter()
            .map(|session| session.sponsor_budget_micro_units)
            .sum::<u64>();
        let max_fee_bps = sessions
            .iter()
            .map(|session| session.max_fee_bps)
            .max()
            .unwrap_or_default();
        let min_privacy_set_size = sessions
            .iter()
            .map(|session| session.privacy_set_size)
            .min()
            .unwrap_or_default();
        let sequence = self.counters.next_batch_sequence.saturating_add(1);
        let batch_id = authorization_batch_id(
            sequence,
            &session_root,
            &request.aggregate_pq_authorization_root,
            request.sealed_at_height,
        );
        let batch = AuthorizationBatch {
            batch_id: batch_id.clone(),
            sequence,
            status: BatchStatus::SettlementReady,
            session_ids: request.session_ids.clone(),
            session_root,
            sponsor_receipt_root,
            builder_commitment: request.builder_commitment,
            batch_witness_root: request.batch_witness_root,
            batch_proof_root: request.batch_proof_root,
            aggregate_pq_authorization_root: request.aggregate_pq_authorization_root,
            aggregate_privacy_proof_root: request.aggregate_privacy_proof_root,
            aggregate_fee_sponsor_root: request.aggregate_fee_sponsor_root,
            call_graph_root: request.call_graph_root,
            fee_credit_root: request.fee_credit_root,
            low_fee_rebate_root: request.low_fee_rebate_root,
            total_sponsor_budget_micro_units,
            max_fee_bps,
            min_privacy_set_size,
            sealed_at_height: request.sealed_at_height,
            settlement_deadline_height: request
                .sealed_at_height
                .saturating_add(self.config.session_ttl_blocks),
        };
        for session_id in &batch.session_ids {
            if let Some(session) = self.sessions.get_mut(session_id) {
                session.status = SessionStatus::Batched;
                session.batch_id = Some(batch_id.clone());
                session.updated_at_height = batch.sealed_at_height;
            }
        }
        self.batches.insert(batch_id, batch.clone());
        self.counters.next_batch_sequence = sequence;
        self.counters.batches_built = self.counters.batches_built.saturating_add(1);
        self.counters.sessions_batched = self
            .counters
            .sessions_batched
            .saturating_add(batch.session_ids.len() as u64);
        self.current_height = self.current_height.max(batch.sealed_at_height);
        Ok(batch)
    }

    pub fn settle_authorization_batch(
        &mut self,
        request: SettleAuthorizationBatchRequest,
    ) -> PrivateL2PqAccountSessionPaymasterResult<SettlementReceipt> {
        self.config.validate()?;
        request.validate()?;
        self.expire_stale(request.settled_at_height);
        let state_root_before = self.state_root();
        let runtime_state_root_before = self.runtime_root.clone();
        let batch = self
            .batches
            .get(&request.batch_id)
            .cloned()
            .ok_or_else(|| format!("unknown pq account session batch {}", request.batch_id))?;
        if !batch.status.can_settle() {
            return Err("pq account session batch is not settlement ready".to_string());
        }
        if request.settled_at_height > batch.settlement_deadline_height {
            return Err("pq account session batch settlement deadline elapsed".to_string());
        }
        for session_id in &batch.session_ids {
            if let Some(session) = self.sessions.get_mut(session_id) {
                session.status = SessionStatus::Settled;
                session.updated_at_height = request.settled_at_height;
            }
        }
        for receipt in self.sponsor_receipts.values_mut() {
            if batch.session_ids.contains(&receipt.session_id) {
                receipt.status = SponsorStatus::Spent;
                receipt.spent_at_height = Some(request.settled_at_height);
                self.counters.sponsor_credits_spent = self
                    .counters
                    .sponsor_credits_spent
                    .saturating_add(receipt.credit_micro_units);
            }
        }
        if let Some(stored_batch) = self.batches.get_mut(&request.batch_id) {
            stored_batch.status = BatchStatus::Settled;
        }
        self.runtime_root = request.runtime_state_root_after.clone();
        self.current_height = self.current_height.max(request.settled_at_height);
        let state_root_after = self.state_root();
        let receipt_id = settlement_receipt_id(
            &request.batch_id,
            &request.settlement_tx_root,
            &request.settlement_proof_root,
            request.settled_at_height,
        );
        for session_id in &batch.session_ids {
            if let Some(session) = self.sessions.get_mut(session_id) {
                session.settlement_receipt_id = Some(receipt_id.clone());
            }
        }
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            batch_id: request.batch_id,
            status: BatchStatus::Settled,
            batch_root: batch.state_root(),
            settlement_tx_root: request.settlement_tx_root,
            settlement_proof_root: request.settlement_proof_root,
            settlement_witness_root: request.settlement_witness_root,
            spent_nullifier_root: request.spent_nullifier_root,
            replay_fence_consumption_root: request.replay_fence_consumption_root,
            fee_spend_root: request.fee_spend_root,
            sponsor_rebate_root: request.sponsor_rebate_root,
            state_transition_root: request.state_transition_root,
            runtime_state_root_before,
            runtime_state_root_after: request.runtime_state_root_after,
            state_root_before,
            state_root_after,
            settled_at_height: request.settled_at_height,
            finalized_at_height: request.finalized_at_height,
        };
        self.settlement_receipts.insert(receipt_id, receipt.clone());
        self.counters.batches_settled = self.counters.batches_settled.saturating_add(1);
        self.counters.sessions_settled = self
            .counters
            .sessions_settled
            .saturating_add(batch.session_ids.len() as u64);
        self.counters.receipts_published = self.counters.receipts_published.saturating_add(1);
        Ok(receipt)
    }

    pub fn revoke_session(
        &mut self,
        session_id: &str,
        revoked_at_height: u64,
        revocation_root: &str,
    ) -> PrivateL2PqAccountSessionPaymasterResult<String> {
        validate_root("session_id", session_id)?;
        validate_root("revocation_root", revocation_root)?;
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| format!("unknown pq account session {session_id}"))?;
        if !session.status.live() {
            return Err("pq account session cannot be revoked from current status".to_string());
        }
        session.status = SessionStatus::Revoked;
        session.updated_at_height = revoked_at_height;
        self.counters.sessions_revoked = self.counters.sessions_revoked.saturating_add(1);
        self.current_height = self.current_height.max(revoked_at_height);
        Ok(root_from_record(
            "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-REVOCATION",
            &json!({
                "session_id": session_id,
                "revoked_at_height": revoked_at_height,
                "revocation_root": revocation_root,
            }),
        ))
    }

    pub fn roots(&self) -> Roots {
        let session_records = self
            .sessions
            .values()
            .map(PrivateAccountSession::public_record)
            .collect::<Vec<_>>();
        let open_session_records = self
            .sessions
            .values()
            .filter(|session| session.status.live())
            .map(PrivateAccountSession::public_record)
            .collect::<Vec<_>>();
        let sponsor_records = self
            .sponsor_receipts
            .values()
            .map(SponsorReceipt::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(AuthorizationBatch::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .settlement_receipts
            .values()
            .map(SettlementReceipt::public_record)
            .collect::<Vec<_>>();
        let pq_records = self
            .sessions
            .values()
            .map(|session| json!(session.pq_authorization_root))
            .chain(
                self.sponsor_receipts
                    .values()
                    .map(|receipt| json!(receipt.sponsor_pq_authorization_root.clone())),
            )
            .collect::<Vec<_>>();
        let fee_records = self
            .sessions
            .values()
            .map(|session| json!(session.low_fee_sponsor_root))
            .chain(
                self.sponsor_receipts
                    .values()
                    .map(|receipt| json!(receipt.fee_credit_root.clone())),
            )
            .collect::<Vec<_>>();
        let session_root = merkle_root(
            "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-SESSIONS",
            &session_records,
        );
        let open_session_root = merkle_root(
            "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-OPEN-SESSIONS",
            &open_session_records,
        );
        let sponsor_receipt_root = merkle_root(
            "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-SPONSORS",
            &sponsor_records,
        );
        let batch_root = merkle_root(
            "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-BATCHES",
            &batch_records,
        );
        let settlement_receipt_root = merkle_root(
            "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-SETTLEMENT-RECEIPTS",
            &receipt_records,
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-NULLIFIERS",
            &self
                .nullifier_index
                .iter()
                .map(|root| json!(root))
                .collect::<Vec<_>>(),
        );
        let replay_fence_root = merkle_root(
            "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-REPLAY-FENCES",
            &self
                .replay_fence_index
                .iter()
                .map(|root| json!(root))
                .collect::<Vec<_>>(),
        );
        let pq_authorization_root = merkle_root(
            "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-PQ-AUTH",
            &pq_records,
        );
        let fee_sponsor_root = merkle_root(
            "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-FEE-SPONSORS",
            &fee_records,
        );
        let state_root = root_from_record(
            "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-ROOTS",
            &json!({
                "session_root": session_root,
                "open_session_root": open_session_root,
                "sponsor_receipt_root": sponsor_receipt_root,
                "batch_root": batch_root,
                "settlement_receipt_root": settlement_receipt_root,
                "nullifier_root": nullifier_root,
                "replay_fence_root": replay_fence_root,
                "pq_authorization_root": pq_authorization_root,
                "fee_sponsor_root": fee_sponsor_root,
                "height": self.current_height,
            }),
        );
        Roots {
            session_root,
            open_session_root,
            sponsor_receipt_root,
            batch_root,
            settlement_receipt_root,
            nullifier_root,
            replay_fence_root,
            pq_authorization_root,
            fee_sponsor_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_pq_account_session_paymaster_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_SCHEMA_VERSION,
            "privacy_boundary": "roots_only_no_plaintext_accounts_no_plaintext_calldata_no_view_keys",
            "current_height": self.current_height,
            "runtime_root": self.runtime_root,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "session_count": self.sessions.len(),
            "sponsor_receipt_count": self.sponsor_receipts.len(),
            "batch_count": self.batches.len(),
            "settlement_receipt_count": self.settlement_receipts.len(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn expire_stale(&mut self, current_height: u64) {
        for session in self.sessions.values_mut() {
            if session.status.live() && current_height > session.expires_at_height {
                session.status = SessionStatus::Expired;
                session.updated_at_height = current_height;
                self.counters.sessions_expired = self.counters.sessions_expired.saturating_add(1);
            }
        }
        for receipt in self.sponsor_receipts.values_mut() {
            if matches!(
                receipt.status,
                SponsorStatus::Offered | SponsorStatus::Reserved
            ) && current_height > receipt.expires_at_height
            {
                receipt.status = SponsorStatus::Expired;
            }
        }
        for batch in self.batches.values_mut() {
            if matches!(
                batch.status,
                BatchStatus::Open | BatchStatus::SettlementReady
            ) && current_height > batch.settlement_deadline_height
            {
                batch.status = BatchStatus::Expired;
            }
        }
        self.current_height = self.current_height.max(current_height);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn session_id(
    sequence: u64,
    wallet_commitment: &str,
    session_key_commitment: &str,
    nullifier_root: &str,
    opened_at_height: u64,
    nonce: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-SESSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(wallet_commitment),
            HashPart::Str(session_key_commitment),
            HashPart::Str(nullifier_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn sponsor_receipt_id(
    sequence: u64,
    session_id: &str,
    sponsor_id: &str,
    fee_credit_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-SPONSOR-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(session_id),
            HashPart::Str(sponsor_id),
            HashPart::Str(fee_credit_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn authorization_batch_id(
    sequence: u64,
    session_root: &str,
    aggregate_pq_authorization_root: &str,
    sealed_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(session_root),
            HashPart::Str(aggregate_pq_authorization_root),
            HashPart::Int(sealed_at_height as i128),
        ],
        32,
    )
}

pub fn settlement_receipt_id(
    batch_id: &str,
    settlement_tx_root: &str,
    settlement_proof_root: &str,
    settled_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(settlement_tx_root),
            HashPart::Str(settlement_proof_root),
            HashPart::Int(settled_at_height as i128),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn secret_root(domain: &str, secret: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_ACCOUNT_SESSION_PAYMASTER_PROTOCOL_VERSION),
            HashPart::Str(secret),
        ],
        32,
    )
}

pub fn empty_fee_sponsor_root() -> String {
    merkle_root(
        "PRIVATE-L2-PQ-ACCOUNT-SESSION-PAYMASTER-EMPTY-FEE-SPONSOR",
        &[],
    )
}

fn validate_root(name: &str, root: &str) -> PrivateL2PqAccountSessionPaymasterResult<()> {
    if root.trim().is_empty() {
        return Err(format!("{name} is required"));
    }
    Ok(())
}

fn validate_secret(name: &str, secret: &str) -> PrivateL2PqAccountSessionPaymasterResult<()> {
    if secret.trim().is_empty() {
        return Err(format!("{name} is required"));
    }
    Ok(())
}
