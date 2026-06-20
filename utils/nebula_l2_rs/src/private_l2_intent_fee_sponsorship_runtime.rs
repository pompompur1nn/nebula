use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2IntentFeeSponsorshipRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-intent-fee-sponsorship-runtime-v1";
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-intent-sponsor-v1";
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_VOUCHER_SUITE: &str =
    "privacy-preserving-sponsor-voucher-nullifier-v1";
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_RECEIPT_SUITE: &str =
    "fast-private-l2-execution-receipt-v1";
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEVNET_HEIGHT: u64 = 236_000;
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MAX_SPONSOR_VAULTS: usize = 131_072;
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MAX_OPEN_INTENTS: usize = 1_048_576;
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MAX_QUOTES: usize = 1_048_576;
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize = 1_048_576;
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 1_048_576;
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 65_536;
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MIN_SPONSOR_COVER_BPS: u64 = 7_500;
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MAX_SPONSOR_COVER_BPS: u64 = 10_000;
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 10;
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 8;
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MIN_SLASH_BPS: u64 = 250;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsoredIntentLane {
    PrivateContractCall,
    DefiSwap,
    DefiLending,
    DefiPerps,
    ConfidentialStablecoin,
    ConfidentialToken,
    BatchSettlement,
    EmergencyEscape,
}

impl SponsoredIntentLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractCall => "private_contract_call",
            Self::DefiSwap => "defi_swap",
            Self::DefiLending => "defi_lending",
            Self::DefiPerps => "defi_perps",
            Self::ConfidentialStablecoin => "confidential_stablecoin",
            Self::ConfidentialToken => "confidential_token",
            Self::BatchSettlement => "batch_settlement",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::DefiPerps => 9_250,
            Self::DefiSwap => 9_000,
            Self::PrivateContractCall => 8_800,
            Self::DefiLending => 8_650,
            Self::ConfidentialStablecoin => 8_400,
            Self::ConfidentialToken => 8_000,
            Self::BatchSettlement => 7_400,
        }
    }

    pub fn defi(self) -> bool {
        matches!(
            self,
            Self::DefiSwap | Self::DefiLending | Self::DefiPerps | Self::ConfidentialStablecoin
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorVaultStatus {
    Active,
    Paused,
    Draining,
    Slashed,
    Closed,
}

impl SponsorVaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Slashed => "slashed",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_quotes(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Open,
    Quoted,
    Reserved,
    Executing,
    Settled,
    Rebated,
    Expired,
    Rejected,
    Slashed,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Quoted => "quoted",
            Self::Reserved => "reserved",
            Self::Executing => "executing",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }

    pub fn quotable(self) -> bool {
        matches!(self, Self::Open | Self::Quoted)
    }

    pub fn reservable(self) -> bool {
        matches!(self, Self::Quoted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Posted,
    Selected,
    Reserved,
    Filled,
    Expired,
    Slashed,
    Rejected,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Selected => "selected",
            Self::Reserved => "reserved",
            Self::Filled => "filled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
            Self::Rejected => "rejected",
        }
    }

    pub fn can_reserve(self) -> bool {
        matches!(self, Self::Posted | Self::Selected)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Executing,
    Settled,
    Rebated,
    Expired,
    Slashed,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Executing => "executing",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::Reserved | Self::Executing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    FastAccepted,
    SettlementPosted,
    Finalized,
    Rebated,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FastAccepted => "fast_accepted",
            Self::SettlementPosted => "settlement_posted",
            Self::Finalized => "finalized",
            Self::Rebated => "rebated",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorSlashReason {
    UnderfundedQuote,
    ExpiredExecution,
    ReceiptMismatch,
    PrivacyLeak,
    ReplayAttempt,
    InvalidPqAuthorization,
}

impl SponsorSlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnderfundedQuote => "underfunded_quote",
            Self::ExpiredExecution => "expired_execution",
            Self::ReceiptMismatch => "receipt_mismatch",
            Self::PrivacyLeak => "privacy_leak",
            Self::ReplayAttempt => "replay_attempt",
            Self::InvalidPqAuthorization => "invalid_pq_authorization",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub voucher_suite: String,
    pub receipt_suite: String,
    pub max_sponsor_vaults: usize,
    pub max_open_intents: usize,
    pub max_quotes: usize,
    pub max_reservations: usize,
    pub max_receipts: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub min_sponsor_cover_bps: u64,
    pub max_sponsor_cover_bps: u64,
    pub quote_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub min_slash_bps: u64,
    pub require_pq_authorization: bool,
    pub require_voucher_nullifier: bool,
    pub require_fast_receipt_root: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_PQ_AUTH_SUITE.to_string(),
            voucher_suite: PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_VOUCHER_SUITE.to_string(),
            receipt_suite: PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_RECEIPT_SUITE.to_string(),
            max_sponsor_vaults:
                PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MAX_SPONSOR_VAULTS,
            max_open_intents: PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MAX_OPEN_INTENTS,
            max_quotes: PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MAX_QUOTES,
            max_reservations: PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_receipts: PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MAX_RECEIPTS,
            min_privacy_set_size:
                PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            min_sponsor_cover_bps:
                PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MIN_SPONSOR_COVER_BPS,
            max_sponsor_cover_bps:
                PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MAX_SPONSOR_COVER_BPS,
            quote_ttl_blocks: PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            receipt_ttl_blocks:
                PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS,
            min_slash_bps: PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEFAULT_MIN_SLASH_BPS,
            require_pq_authorization: true,
            require_voucher_nullifier: true,
            require_fast_receipt_root: true,
        }
    }

    pub fn validate(&self) -> PrivateL2IntentFeeSponsorshipRuntimeResult<()> {
        if self.protocol_version != PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_PROTOCOL_VERSION {
            return Err("intent fee sponsorship protocol version mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("intent fee sponsorship chain id mismatch".to_string());
        }
        if self.max_sponsor_vaults == 0
            || self.max_open_intents == 0
            || self.max_quotes == 0
            || self.max_reservations == 0
            || self.max_receipts == 0
        {
            return Err("intent fee sponsorship capacities must be positive".to_string());
        }
        if self.min_privacy_set_size == 0 || self.batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err("intent fee sponsorship privacy set policy is invalid".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("intent fee sponsorship PQ security floor is too low".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_MAX_BPS
            || self.min_sponsor_cover_bps > PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_MAX_BPS
            || self.max_sponsor_cover_bps > PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_MAX_BPS
            || self.min_sponsor_cover_bps > self.max_sponsor_cover_bps
        {
            return Err("intent fee sponsorship fee policy is invalid".to_string());
        }
        if self.quote_ttl_blocks == 0
            || self.reservation_ttl_blocks == 0
            || self.receipt_ttl_blocks == 0
        {
            return Err("intent fee sponsorship TTLs must be positive".to_string());
        }
        if self.min_slash_bps == 0
            || self.min_slash_bps > PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_MAX_BPS
        {
            return Err("intent fee sponsorship slash policy is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "voucher_suite": self.voucher_suite,
            "receipt_suite": self.receipt_suite,
            "max_sponsor_vaults": self.max_sponsor_vaults,
            "max_open_intents": self.max_open_intents,
            "max_quotes": self.max_quotes,
            "max_reservations": self.max_reservations,
            "max_receipts": self.max_receipts,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_sponsor_cover_bps": self.min_sponsor_cover_bps,
            "max_sponsor_cover_bps": self.max_sponsor_cover_bps,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "min_slash_bps": self.min_slash_bps,
            "require_pq_authorization": self.require_pq_authorization,
            "require_voucher_nullifier": self.require_voucher_nullifier,
            "require_fast_receipt_root": self.require_fast_receipt_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub sponsor_vault_counter: u64,
    pub sponsored_intent_counter: u64,
    pub fee_quote_counter: u64,
    pub budget_reservation_counter: u64,
    pub execution_receipt_counter: u64,
    pub rebate_receipt_counter: u64,
    pub slashing_receipt_counter: u64,
    pub consumed_nullifier_counter: u64,
    pub privacy_rejection_counter: u64,
    pub pq_rejection_counter: u64,
    pub fee_rejection_counter: u64,
    pub replay_rejection_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_vault_counter": self.sponsor_vault_counter,
            "sponsored_intent_counter": self.sponsored_intent_counter,
            "fee_quote_counter": self.fee_quote_counter,
            "budget_reservation_counter": self.budget_reservation_counter,
            "execution_receipt_counter": self.execution_receipt_counter,
            "rebate_receipt_counter": self.rebate_receipt_counter,
            "slashing_receipt_counter": self.slashing_receipt_counter,
            "consumed_nullifier_counter": self.consumed_nullifier_counter,
            "privacy_rejection_counter": self.privacy_rejection_counter,
            "pq_rejection_counter": self.pq_rejection_counter,
            "fee_rejection_counter": self.fee_rejection_counter,
            "replay_rejection_counter": self.replay_rejection_counter,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterSponsorVaultRequest {
    pub sponsor_commitment: String,
    pub vault_asset_id: String,
    pub budget_commitment_root: String,
    pub voucher_policy_root: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub initial_budget: u64,
    pub max_sponsor_cover_bps: u64,
    pub min_intent_priority: u64,
    pub registered_at_height: u64,
    pub sponsor_nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenFeeSponsorshipIntentRequest {
    pub lane: SponsoredIntentLane,
    pub caller_commitment: String,
    pub contract_commitment: String,
    pub intent_payload_root: String,
    pub private_call_witness_root: String,
    pub voucher_commitment_root: String,
    pub pq_authorization_root: String,
    pub replay_nullifier: String,
    pub max_user_fee_bps: u64,
    pub requested_sponsor_cover_bps: u64,
    pub priority_score: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuoteSponsoredFeeRequest {
    pub sponsor_vault_id: String,
    pub intent_id: String,
    pub quote_terms_root: String,
    pub voucher_blinding_root: String,
    pub max_sponsored_fee: u64,
    pub user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub execution_deadline_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub quote_nonce: String,
    pub quoted_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveSponsorBudgetRequest {
    pub intent_id: String,
    pub fee_quote_id: String,
    pub sponsor_vault_id: String,
    pub reservation_commitment_root: String,
    pub voucher_nullifier: String,
    pub max_sponsored_fee: u64,
    pub reserved_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleSponsoredIntentReceiptRequest {
    pub intent_id: String,
    pub fee_quote_id: String,
    pub budget_reservation_id: String,
    pub sponsor_vault_id: String,
    pub execution_receipt_root: String,
    pub state_transition_root: String,
    pub gas_measurement_root: String,
    pub settlement_tx_root: String,
    pub actual_sponsored_fee: u64,
    pub fast_finality_millis: u64,
    pub receipt_nullifier: String,
    pub settled_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateSponsorSurplusRequest {
    pub intent_id: String,
    pub execution_receipt_id: String,
    pub budget_reservation_id: String,
    pub sponsor_vault_id: String,
    pub rebate_commitment_root: String,
    pub surplus_amount: u64,
    pub rebate_nullifier: String,
    pub rebated_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashBadSponsorQuoteRequest {
    pub fee_quote_id: String,
    pub sponsor_vault_id: String,
    pub intent_id: String,
    pub reason: SponsorSlashReason,
    pub evidence_root: String,
    pub challenger_commitment: String,
    pub slash_amount: u64,
    pub evidence_nullifier: String,
    pub slashed_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorVaultRecord {
    pub sponsor_vault_id: String,
    pub sponsor_commitment: String,
    pub vault_asset_id: String,
    pub budget_commitment_root: String,
    pub voucher_policy_root: String,
    pub pq_authorization_root: String,
    pub status: SponsorVaultStatus,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub initial_budget: u64,
    pub available_budget: u64,
    pub reserved_budget: u64,
    pub spent_budget: u64,
    pub rebated_surplus: u64,
    pub slashed_budget: u64,
    pub max_sponsor_cover_bps: u64,
    pub min_intent_priority: u64,
    pub registered_at_height: u64,
    pub sponsor_nonce: String,
}

impl SponsorVaultRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_vault_id": self.sponsor_vault_id,
            "sponsor_commitment": self.sponsor_commitment,
            "vault_asset_id": self.vault_asset_id,
            "budget_commitment_root": self.budget_commitment_root,
            "voucher_policy_root": self.voucher_policy_root,
            "pq_authorization_root": self.pq_authorization_root,
            "status": self.status.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "initial_budget": self.initial_budget,
            "available_budget": self.available_budget,
            "reserved_budget": self.reserved_budget,
            "spent_budget": self.spent_budget,
            "rebated_surplus": self.rebated_surplus,
            "slashed_budget": self.slashed_budget,
            "max_sponsor_cover_bps": self.max_sponsor_cover_bps,
            "min_intent_priority": self.min_intent_priority,
            "registered_at_height": self.registered_at_height,
            "sponsor_nonce": self.sponsor_nonce,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsoredIntentRecord {
    pub intent_id: String,
    pub lane: SponsoredIntentLane,
    pub caller_commitment: String,
    pub contract_commitment: String,
    pub intent_payload_root: String,
    pub private_call_witness_root: String,
    pub voucher_commitment_root: String,
    pub pq_authorization_root: String,
    pub replay_nullifier_root: String,
    pub status: IntentStatus,
    pub max_user_fee_bps: u64,
    pub requested_sponsor_cover_bps: u64,
    pub priority_score: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub selected_quote_id: Option<String>,
    pub budget_reservation_id: Option<String>,
    pub execution_receipt_id: Option<String>,
}

impl SponsoredIntentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "lane": self.lane.as_str(),
            "caller_commitment": self.caller_commitment,
            "contract_commitment": self.contract_commitment,
            "intent_payload_root": self.intent_payload_root,
            "private_call_witness_root": self.private_call_witness_root,
            "voucher_commitment_root": self.voucher_commitment_root,
            "pq_authorization_root": self.pq_authorization_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "status": self.status.as_str(),
            "max_user_fee_bps": self.max_user_fee_bps,
            "requested_sponsor_cover_bps": self.requested_sponsor_cover_bps,
            "priority_score": self.priority_score,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "selected_quote_id": self.selected_quote_id,
            "budget_reservation_id": self.budget_reservation_id,
            "execution_receipt_id": self.execution_receipt_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsoredFeeQuoteRecord {
    pub fee_quote_id: String,
    pub sponsor_vault_id: String,
    pub intent_id: String,
    pub quote_terms_root: String,
    pub voucher_blinding_root: String,
    pub status: QuoteStatus,
    pub max_sponsored_fee: u64,
    pub user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub execution_deadline_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub quote_nonce: String,
    pub quoted_at_height: u64,
    pub expires_at_height: u64,
    pub budget_reservation_id: Option<String>,
}

impl SponsoredFeeQuoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_quote_id": self.fee_quote_id,
            "sponsor_vault_id": self.sponsor_vault_id,
            "intent_id": self.intent_id,
            "quote_terms_root": self.quote_terms_root,
            "voucher_blinding_root": self.voucher_blinding_root,
            "status": self.status.as_str(),
            "max_sponsored_fee": self.max_sponsored_fee,
            "user_fee_bps": self.user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "execution_deadline_height": self.execution_deadline_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "quote_nonce": self.quote_nonce,
            "quoted_at_height": self.quoted_at_height,
            "expires_at_height": self.expires_at_height,
            "budget_reservation_id": self.budget_reservation_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorBudgetReservationRecord {
    pub budget_reservation_id: String,
    pub intent_id: String,
    pub fee_quote_id: String,
    pub sponsor_vault_id: String,
    pub reservation_commitment_root: String,
    pub voucher_nullifier_root: String,
    pub status: ReservationStatus,
    pub reserved_budget: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
    pub execution_receipt_id: Option<String>,
}

impl SponsorBudgetReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_reservation_id": self.budget_reservation_id,
            "intent_id": self.intent_id,
            "fee_quote_id": self.fee_quote_id,
            "sponsor_vault_id": self.sponsor_vault_id,
            "reservation_commitment_root": self.reservation_commitment_root,
            "voucher_nullifier_root": self.voucher_nullifier_root,
            "status": self.status.as_str(),
            "reserved_budget": self.reserved_budget,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
            "execution_receipt_id": self.execution_receipt_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsoredIntentExecutionReceipt {
    pub execution_receipt_id: String,
    pub intent_id: String,
    pub fee_quote_id: String,
    pub budget_reservation_id: String,
    pub sponsor_vault_id: String,
    pub execution_receipt_root: String,
    pub state_transition_root: String,
    pub gas_measurement_root: String,
    pub settlement_tx_root: String,
    pub receipt_nullifier_root: String,
    pub status: ReceiptStatus,
    pub reserved_budget: u64,
    pub actual_sponsored_fee: u64,
    pub sponsor_surplus: u64,
    pub fast_finality_millis: u64,
    pub settled_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsoredIntentExecutionReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "execution_receipt_id": self.execution_receipt_id,
            "intent_id": self.intent_id,
            "fee_quote_id": self.fee_quote_id,
            "budget_reservation_id": self.budget_reservation_id,
            "sponsor_vault_id": self.sponsor_vault_id,
            "execution_receipt_root": self.execution_receipt_root,
            "state_transition_root": self.state_transition_root,
            "gas_measurement_root": self.gas_measurement_root,
            "settlement_tx_root": self.settlement_tx_root,
            "receipt_nullifier_root": self.receipt_nullifier_root,
            "status": self.status.as_str(),
            "reserved_budget": self.reserved_budget,
            "actual_sponsored_fee": self.actual_sponsored_fee,
            "sponsor_surplus": self.sponsor_surplus,
            "fast_finality_millis": self.fast_finality_millis,
            "settled_at_height": self.settled_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorSurplusRebateRecord {
    pub rebate_receipt_id: String,
    pub intent_id: String,
    pub execution_receipt_id: String,
    pub budget_reservation_id: String,
    pub sponsor_vault_id: String,
    pub rebate_commitment_root: String,
    pub surplus_amount: u64,
    pub rebate_nullifier_root: String,
    pub rebated_at_height: u64,
}

impl SponsorSurplusRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_receipt_id": self.rebate_receipt_id,
            "intent_id": self.intent_id,
            "execution_receipt_id": self.execution_receipt_id,
            "budget_reservation_id": self.budget_reservation_id,
            "sponsor_vault_id": self.sponsor_vault_id,
            "rebate_commitment_root": self.rebate_commitment_root,
            "surplus_amount": self.surplus_amount,
            "rebate_nullifier_root": self.rebate_nullifier_root,
            "rebated_at_height": self.rebated_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorQuoteSlashingRecord {
    pub slashing_receipt_id: String,
    pub fee_quote_id: String,
    pub sponsor_vault_id: String,
    pub intent_id: String,
    pub reason: SponsorSlashReason,
    pub evidence_root: String,
    pub challenger_commitment: String,
    pub slash_amount: u64,
    pub evidence_nullifier_root: String,
    pub slashed_at_height: u64,
}

impl SponsorQuoteSlashingRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "slashing_receipt_id": self.slashing_receipt_id,
            "fee_quote_id": self.fee_quote_id,
            "sponsor_vault_id": self.sponsor_vault_id,
            "intent_id": self.intent_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "challenger_commitment": self.challenger_commitment,
            "slash_amount": self.slash_amount,
            "evidence_nullifier_root": self.evidence_nullifier_root,
            "slashed_at_height": self.slashed_at_height,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub sponsor_vault_root: String,
    pub sponsored_intent_root: String,
    pub fee_quote_root: String,
    pub budget_reservation_root: String,
    pub execution_receipt_root: String,
    pub rebate_receipt_root: String,
    pub slashing_receipt_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_vault_root": self.sponsor_vault_root,
            "sponsored_intent_root": self.sponsored_intent_root,
            "fee_quote_root": self.fee_quote_root,
            "budget_reservation_root": self.budget_reservation_root,
            "execution_receipt_root": self.execution_receipt_root,
            "rebate_receipt_root": self.rebate_receipt_root,
            "slashing_receipt_root": self.slashing_receipt_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub counters: Counters,
    pub sponsor_vaults: BTreeMap<String, SponsorVaultRecord>,
    pub sponsored_intents: BTreeMap<String, SponsoredIntentRecord>,
    pub fee_quotes: BTreeMap<String, SponsoredFeeQuoteRecord>,
    pub budget_reservations: BTreeMap<String, SponsorBudgetReservationRecord>,
    pub execution_receipts: BTreeMap<String, SponsoredIntentExecutionReceipt>,
    pub rebate_receipts: BTreeMap<String, SponsorSurplusRebateRecord>,
    pub slashing_receipts: BTreeMap<String, SponsorQuoteSlashingRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2IntentFeeSponsorshipRuntimeResult<Self> {
        let config = Config::devnet();
        config.validate()?;
        let mut state = Self {
            config,
            current_height: PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_DEVNET_HEIGHT,
            counters: Counters::default(),
            sponsor_vaults: BTreeMap::new(),
            sponsored_intents: BTreeMap::new(),
            fee_quotes: BTreeMap::new(),
            budget_reservations: BTreeMap::new(),
            execution_receipts: BTreeMap::new(),
            rebate_receipts: BTreeMap::new(),
            slashing_receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        };

        let sponsor = state.register_sponsor_vault(RegisterSponsorVaultRequest {
            sponsor_commitment: payload_root(
                "DEVNET-SPONSOR",
                &json!({"sponsor": "defi-gas-coop"}),
            ),
            vault_asset_id: "devnet-private-l2-fee-credit".to_string(),
            budget_commitment_root: payload_root(
                "DEVNET-BUDGET",
                &json!({"budget": 50_000_000u64}),
            ),
            voucher_policy_root: payload_root(
                "DEVNET-VOUCHER-POLICY",
                &json!({"lanes": ["private_contract_call", "defi_swap", "defi_lending"]}),
            ),
            pq_authorization_root: payload_root(
                "DEVNET-SPONSOR-PQ-AUTH",
                &json!({"scheme": PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_PQ_AUTH_SUITE}),
            ),
            privacy_set_size: state.config.batch_privacy_set_size,
            pq_security_bits: state.config.min_pq_security_bits,
            initial_budget: 50_000_000,
            max_sponsor_cover_bps: 9_500,
            min_intent_priority: 8_000,
            registered_at_height: state.current_height,
            sponsor_nonce: "devnet-sponsor-vault-0".to_string(),
        })?;

        let intent = state.open_fee_sponsorship_intent(OpenFeeSponsorshipIntentRequest {
            lane: SponsoredIntentLane::DefiSwap,
            caller_commitment: payload_root("DEVNET-CALLER", &json!({"account": "alice"})),
            contract_commitment: payload_root("DEVNET-CONTRACT", &json!({"amm": "stable-swap"})),
            intent_payload_root: payload_root(
                "DEVNET-INTENT-PAYLOAD",
                &json!({"swap": "xmr-usd-private", "max_slippage_bps": 20}),
            ),
            private_call_witness_root: payload_root(
                "DEVNET-WITNESS",
                &json!({"witness": "hidden"}),
            ),
            voucher_commitment_root: payload_root("DEVNET-VOUCHER", &json!({"voucher": "sponsor"})),
            pq_authorization_root: payload_root("DEVNET-INTENT-PQ-AUTH", &json!({"auth": "pq"})),
            replay_nullifier: "devnet-intent-nullifier-0".to_string(),
            max_user_fee_bps: 8,
            requested_sponsor_cover_bps: 9_000,
            priority_score: SponsoredIntentLane::DefiSwap.default_priority(),
            privacy_set_size: state.config.batch_privacy_set_size,
            pq_security_bits: state.config.min_pq_security_bits,
            opened_at_height: state.current_height,
            expires_at_height: state.current_height + 20,
        })?;

        let quote = state.quote_sponsored_fee(QuoteSponsoredFeeRequest {
            sponsor_vault_id: sponsor.sponsor_vault_id.clone(),
            intent_id: intent.intent_id.clone(),
            quote_terms_root: payload_root("DEVNET-QUOTE-TERMS", &json!({"max_fee": 12_000u64})),
            voucher_blinding_root: payload_root("DEVNET-VOUCHER-BLINDING", &json!({"blind": 0})),
            max_sponsored_fee: 12_000,
            user_fee_bps: 8,
            sponsor_cover_bps: 9_000,
            execution_deadline_height: state.current_height + 6,
            privacy_set_size: state.config.batch_privacy_set_size,
            pq_security_bits: state.config.min_pq_security_bits,
            quote_nonce: "devnet-quote-0".to_string(),
            quoted_at_height: state.current_height,
        })?;

        let reservation = state.reserve_sponsor_budget(ReserveSponsorBudgetRequest {
            intent_id: intent.intent_id.clone(),
            fee_quote_id: quote.fee_quote_id.clone(),
            sponsor_vault_id: sponsor.sponsor_vault_id.clone(),
            reservation_commitment_root: payload_root(
                "DEVNET-RESERVATION",
                &json!({"intent": intent.intent_id, "quote": quote.fee_quote_id}),
            ),
            voucher_nullifier: "devnet-voucher-nullifier-0".to_string(),
            max_sponsored_fee: 12_000,
            reserved_at_height: state.current_height + 1,
        })?;

        let receipt =
            state.settle_sponsored_intent_receipt(SettleSponsoredIntentReceiptRequest {
                intent_id: reservation.intent_id.clone(),
                fee_quote_id: reservation.fee_quote_id.clone(),
                budget_reservation_id: reservation.budget_reservation_id.clone(),
                sponsor_vault_id: sponsor.sponsor_vault_id.clone(),
                execution_receipt_root: payload_root("DEVNET-FAST-RECEIPT", &json!({"ok": true})),
                state_transition_root: payload_root(
                    "DEVNET-STATE-TRANSITION",
                    &json!({"delta": "root"}),
                ),
                gas_measurement_root: payload_root("DEVNET-GAS", &json!({"gas": 9_800u64})),
                settlement_tx_root: payload_root("DEVNET-SETTLEMENT-TX", &json!({"tx": "private"})),
                actual_sponsored_fee: 9_800,
                fast_finality_millis: 420,
                receipt_nullifier: "devnet-receipt-nullifier-0".to_string(),
                settled_at_height: state.current_height + 2,
            })?;

        state.rebate_sponsor_surplus(RebateSponsorSurplusRequest {
            intent_id: receipt.intent_id.clone(),
            execution_receipt_id: receipt.execution_receipt_id.clone(),
            budget_reservation_id: receipt.budget_reservation_id.clone(),
            sponsor_vault_id: receipt.sponsor_vault_id.clone(),
            rebate_commitment_root: payload_root(
                "DEVNET-REBATE",
                &json!({"surplus": receipt.sponsor_surplus}),
            ),
            surplus_amount: receipt.sponsor_surplus,
            rebate_nullifier: "devnet-rebate-nullifier-0".to_string(),
            rebated_at_height: state.current_height + 3,
        })?;

        Ok(state)
    }

    pub fn register_sponsor_vault(
        &mut self,
        request: RegisterSponsorVaultRequest,
    ) -> PrivateL2IntentFeeSponsorshipRuntimeResult<SponsorVaultRecord> {
        self.config.validate()?;
        if self.sponsor_vaults.len() >= self.config.max_sponsor_vaults {
            return Err("intent fee sponsorship sponsor vault capacity reached".to_string());
        }
        required("sponsor_commitment", &request.sponsor_commitment)?;
        required("vault_asset_id", &request.vault_asset_id)?;
        required("budget_commitment_root", &request.budget_commitment_root)?;
        required("voucher_policy_root", &request.voucher_policy_root)?;
        required("pq_authorization_root", &request.pq_authorization_root)?;
        required("sponsor_nonce", &request.sponsor_nonce)?;
        validate_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        if request.initial_budget == 0 {
            return Err("intent fee sponsorship sponsor budget must be positive".to_string());
        }
        if request.max_sponsor_cover_bps < self.config.min_sponsor_cover_bps
            || request.max_sponsor_cover_bps > self.config.max_sponsor_cover_bps
        {
            return Err("intent fee sponsorship sponsor cover policy is invalid".to_string());
        }

        let counter = self.counters.sponsor_vault_counter.saturating_add(1);
        let sponsor_vault_id = sponsor_vault_id(&request, counter);
        if self.sponsor_vaults.contains_key(&sponsor_vault_id) {
            return Err("intent fee sponsorship sponsor vault id collision".to_string());
        }
        let record = SponsorVaultRecord {
            sponsor_vault_id: sponsor_vault_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            vault_asset_id: request.vault_asset_id,
            budget_commitment_root: request.budget_commitment_root,
            voucher_policy_root: request.voucher_policy_root,
            pq_authorization_root: request.pq_authorization_root,
            status: SponsorVaultStatus::Active,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            initial_budget: request.initial_budget,
            available_budget: request.initial_budget,
            reserved_budget: 0,
            spent_budget: 0,
            rebated_surplus: 0,
            slashed_budget: 0,
            max_sponsor_cover_bps: request.max_sponsor_cover_bps,
            min_intent_priority: request.min_intent_priority,
            registered_at_height: request.registered_at_height,
            sponsor_nonce: request.sponsor_nonce,
        };
        self.counters.sponsor_vault_counter = counter;
        self.sponsor_vaults.insert(sponsor_vault_id, record.clone());
        Ok(record)
    }

    pub fn open_fee_sponsorship_intent(
        &mut self,
        request: OpenFeeSponsorshipIntentRequest,
    ) -> PrivateL2IntentFeeSponsorshipRuntimeResult<SponsoredIntentRecord> {
        if self.sponsored_intents.len() >= self.config.max_open_intents {
            return Err("intent fee sponsorship intent capacity reached".to_string());
        }
        required("caller_commitment", &request.caller_commitment)?;
        required("contract_commitment", &request.contract_commitment)?;
        required("intent_payload_root", &request.intent_payload_root)?;
        required(
            "private_call_witness_root",
            &request.private_call_witness_root,
        )?;
        required("voucher_commitment_root", &request.voucher_commitment_root)?;
        required("pq_authorization_root", &request.pq_authorization_root)?;
        required("replay_nullifier", &request.replay_nullifier)?;
        if request.opened_at_height > request.expires_at_height {
            return Err("intent fee sponsorship intent expiry precedes opening".to_string());
        }
        validate_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        if request.max_user_fee_bps > self.config.max_user_fee_bps {
            return Err("intent fee sponsorship user fee exceeds low-fee cap".to_string());
        }
        if request.requested_sponsor_cover_bps < self.config.min_sponsor_cover_bps
            || request.requested_sponsor_cover_bps > self.config.max_sponsor_cover_bps
        {
            return Err("intent fee sponsorship requested cover is outside policy".to_string());
        }
        if request.priority_score < request.lane.default_priority().saturating_sub(2_000) {
            return Err("intent fee sponsorship priority is too low for lane".to_string());
        }
        let replay_nullifier_root =
            self.consume_nullifier("INTENT-REPLAY-NULLIFIER", &request.replay_nullifier)?;
        let counter = self.counters.sponsored_intent_counter.saturating_add(1);
        let intent_id = sponsored_intent_id(&request, counter);
        let record = SponsoredIntentRecord {
            intent_id: intent_id.clone(),
            lane: request.lane,
            caller_commitment: request.caller_commitment,
            contract_commitment: request.contract_commitment,
            intent_payload_root: request.intent_payload_root,
            private_call_witness_root: request.private_call_witness_root,
            voucher_commitment_root: request.voucher_commitment_root,
            pq_authorization_root: request.pq_authorization_root,
            replay_nullifier_root,
            status: IntentStatus::Open,
            max_user_fee_bps: request.max_user_fee_bps,
            requested_sponsor_cover_bps: request.requested_sponsor_cover_bps,
            priority_score: request.priority_score,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            opened_at_height: request.opened_at_height,
            expires_at_height: request.expires_at_height,
            selected_quote_id: None,
            budget_reservation_id: None,
            execution_receipt_id: None,
        };
        self.counters.sponsored_intent_counter = counter;
        self.sponsored_intents.insert(intent_id, record.clone());
        Ok(record)
    }

    pub fn quote_sponsored_fee(
        &mut self,
        request: QuoteSponsoredFeeRequest,
    ) -> PrivateL2IntentFeeSponsorshipRuntimeResult<SponsoredFeeQuoteRecord> {
        if self.fee_quotes.len() >= self.config.max_quotes {
            return Err("intent fee sponsorship quote capacity reached".to_string());
        }
        required("sponsor_vault_id", &request.sponsor_vault_id)?;
        required("intent_id", &request.intent_id)?;
        required("quote_terms_root", &request.quote_terms_root)?;
        required("voucher_blinding_root", &request.voucher_blinding_root)?;
        required("quote_nonce", &request.quote_nonce)?;
        validate_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        if request.max_sponsored_fee == 0 {
            return Err("intent fee sponsorship quote fee must be positive".to_string());
        }
        if request.user_fee_bps > self.config.max_user_fee_bps {
            return Err("intent fee sponsorship quote exceeds user fee cap".to_string());
        }
        if request.sponsor_cover_bps < self.config.min_sponsor_cover_bps
            || request.sponsor_cover_bps > self.config.max_sponsor_cover_bps
        {
            return Err("intent fee sponsorship quote sponsor cover is invalid".to_string());
        }

        let vault = self
            .sponsor_vaults
            .get(&request.sponsor_vault_id)
            .ok_or_else(|| "intent fee sponsorship sponsor vault not found".to_string())?;
        if !vault.status.accepts_quotes() {
            return Err("intent fee sponsorship sponsor vault does not accept quotes".to_string());
        }
        if vault.available_budget < request.max_sponsored_fee {
            return Err("intent fee sponsorship sponsor budget is insufficient".to_string());
        }
        if vault.max_sponsor_cover_bps < request.sponsor_cover_bps {
            return Err("intent fee sponsorship quote exceeds vault cover cap".to_string());
        }

        let intent = self
            .sponsored_intents
            .get(&request.intent_id)
            .ok_or_else(|| "intent fee sponsorship intent not found".to_string())?;
        if !intent.status.quotable() {
            return Err("intent fee sponsorship intent cannot be quoted".to_string());
        }
        if request.quoted_at_height > intent.expires_at_height {
            return Err("intent fee sponsorship intent expired before quote".to_string());
        }
        if intent.priority_score < vault.min_intent_priority {
            return Err("intent fee sponsorship intent priority below sponsor policy".to_string());
        }
        if request.user_fee_bps > intent.max_user_fee_bps
            || request.sponsor_cover_bps < intent.requested_sponsor_cover_bps
        {
            return Err(
                "intent fee sponsorship quote does not satisfy intent fee terms".to_string(),
            );
        }

        let counter = self.counters.fee_quote_counter.saturating_add(1);
        let fee_quote_id = sponsored_fee_quote_id(&request, counter);
        let record = SponsoredFeeQuoteRecord {
            fee_quote_id: fee_quote_id.clone(),
            sponsor_vault_id: request.sponsor_vault_id,
            intent_id: request.intent_id.clone(),
            quote_terms_root: request.quote_terms_root,
            voucher_blinding_root: request.voucher_blinding_root,
            status: QuoteStatus::Posted,
            max_sponsored_fee: request.max_sponsored_fee,
            user_fee_bps: request.user_fee_bps,
            sponsor_cover_bps: request.sponsor_cover_bps,
            execution_deadline_height: request.execution_deadline_height,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            quote_nonce: request.quote_nonce,
            quoted_at_height: request.quoted_at_height,
            expires_at_height: request.quoted_at_height + self.config.quote_ttl_blocks,
            budget_reservation_id: None,
        };
        self.counters.fee_quote_counter = counter;
        self.fee_quotes.insert(fee_quote_id.clone(), record.clone());
        if let Some(intent) = self.sponsored_intents.get_mut(&request.intent_id) {
            intent.status = IntentStatus::Quoted;
            intent.selected_quote_id = Some(fee_quote_id);
        }
        Ok(record)
    }

    pub fn reserve_sponsor_budget(
        &mut self,
        request: ReserveSponsorBudgetRequest,
    ) -> PrivateL2IntentFeeSponsorshipRuntimeResult<SponsorBudgetReservationRecord> {
        if self.budget_reservations.len() >= self.config.max_reservations {
            return Err("intent fee sponsorship reservation capacity reached".to_string());
        }
        required("intent_id", &request.intent_id)?;
        required("fee_quote_id", &request.fee_quote_id)?;
        required("sponsor_vault_id", &request.sponsor_vault_id)?;
        required(
            "reservation_commitment_root",
            &request.reservation_commitment_root,
        )?;
        required("voucher_nullifier", &request.voucher_nullifier)?;

        let quote = self
            .fee_quotes
            .get(&request.fee_quote_id)
            .ok_or_else(|| "intent fee sponsorship quote not found".to_string())?;
        if quote.intent_id != request.intent_id
            || quote.sponsor_vault_id != request.sponsor_vault_id
        {
            return Err(
                "intent fee sponsorship reservation references inconsistent quote".to_string(),
            );
        }
        if !quote.status.can_reserve() {
            return Err("intent fee sponsorship quote cannot be reserved".to_string());
        }
        if request.reserved_at_height > quote.expires_at_height {
            return Err("intent fee sponsorship quote expired before reservation".to_string());
        }
        if request.max_sponsored_fee != quote.max_sponsored_fee {
            return Err("intent fee sponsorship reservation fee does not match quote".to_string());
        }

        let intent = self
            .sponsored_intents
            .get(&request.intent_id)
            .ok_or_else(|| "intent fee sponsorship intent not found".to_string())?;
        if !intent.status.reservable() {
            return Err("intent fee sponsorship intent cannot reserve budget".to_string());
        }

        {
            let vault = self
                .sponsor_vaults
                .get_mut(&request.sponsor_vault_id)
                .ok_or_else(|| "intent fee sponsorship sponsor vault not found".to_string())?;
            if vault.available_budget < request.max_sponsored_fee {
                return Err("intent fee sponsorship sponsor budget is insufficient".to_string());
            }
            vault.available_budget = vault
                .available_budget
                .saturating_sub(request.max_sponsored_fee);
            vault.reserved_budget = vault
                .reserved_budget
                .saturating_add(request.max_sponsored_fee);
        }

        let voucher_nullifier_root =
            self.consume_nullifier("SPONSOR-VOUCHER-NULLIFIER", &request.voucher_nullifier)?;
        let counter = self.counters.budget_reservation_counter.saturating_add(1);
        let budget_reservation_id = sponsor_budget_reservation_id(&request, counter);
        let record = SponsorBudgetReservationRecord {
            budget_reservation_id: budget_reservation_id.clone(),
            intent_id: request.intent_id.clone(),
            fee_quote_id: request.fee_quote_id.clone(),
            sponsor_vault_id: request.sponsor_vault_id,
            reservation_commitment_root: request.reservation_commitment_root,
            voucher_nullifier_root,
            status: ReservationStatus::Reserved,
            reserved_budget: request.max_sponsored_fee,
            reserved_at_height: request.reserved_at_height,
            expires_at_height: request.reserved_at_height + self.config.reservation_ttl_blocks,
            execution_receipt_id: None,
        };
        self.counters.budget_reservation_counter = counter;
        self.budget_reservations
            .insert(budget_reservation_id.clone(), record.clone());
        if let Some(quote) = self.fee_quotes.get_mut(&request.fee_quote_id) {
            quote.status = QuoteStatus::Reserved;
            quote.budget_reservation_id = Some(budget_reservation_id.clone());
        }
        if let Some(intent) = self.sponsored_intents.get_mut(&request.intent_id) {
            intent.status = IntentStatus::Reserved;
            intent.budget_reservation_id = Some(budget_reservation_id);
        }
        Ok(record)
    }

    pub fn settle_sponsored_intent_receipt(
        &mut self,
        request: SettleSponsoredIntentReceiptRequest,
    ) -> PrivateL2IntentFeeSponsorshipRuntimeResult<SponsoredIntentExecutionReceipt> {
        if self.execution_receipts.len() >= self.config.max_receipts {
            return Err("intent fee sponsorship execution receipt capacity reached".to_string());
        }
        required("execution_receipt_root", &request.execution_receipt_root)?;
        required("state_transition_root", &request.state_transition_root)?;
        required("gas_measurement_root", &request.gas_measurement_root)?;
        required("settlement_tx_root", &request.settlement_tx_root)?;
        required("receipt_nullifier", &request.receipt_nullifier)?;

        let reservation = self
            .budget_reservations
            .get(&request.budget_reservation_id)
            .ok_or_else(|| "intent fee sponsorship budget reservation not found".to_string())?;
        if reservation.intent_id != request.intent_id
            || reservation.fee_quote_id != request.fee_quote_id
            || reservation.sponsor_vault_id != request.sponsor_vault_id
        {
            return Err(
                "intent fee sponsorship receipt references inconsistent reservation".to_string(),
            );
        }
        if !reservation.status.can_settle() {
            return Err("intent fee sponsorship reservation cannot settle".to_string());
        }
        if request.settled_at_height > reservation.expires_at_height {
            return Err("intent fee sponsorship reservation expired before settlement".to_string());
        }
        if request.actual_sponsored_fee > reservation.reserved_budget {
            return Err("intent fee sponsorship actual fee exceeds reserved budget".to_string());
        }
        let reserved_budget = reservation.reserved_budget;
        let sponsor_surplus = reserved_budget.saturating_sub(request.actual_sponsored_fee);
        let receipt_nullifier_root = self.consume_nullifier(
            "FAST-EXECUTION-RECEIPT-NULLIFIER",
            &request.receipt_nullifier,
        )?;

        {
            let vault = self
                .sponsor_vaults
                .get_mut(&request.sponsor_vault_id)
                .ok_or_else(|| "intent fee sponsorship sponsor vault not found".to_string())?;
            vault.reserved_budget = vault.reserved_budget.saturating_sub(reserved_budget);
            vault.spent_budget = vault
                .spent_budget
                .saturating_add(request.actual_sponsored_fee);
            vault.available_budget = vault.available_budget.saturating_add(sponsor_surplus);
        }

        let counter = self.counters.execution_receipt_counter.saturating_add(1);
        let execution_receipt_id = sponsored_execution_receipt_id(&request, counter);
        let record = SponsoredIntentExecutionReceipt {
            execution_receipt_id: execution_receipt_id.clone(),
            intent_id: request.intent_id.clone(),
            fee_quote_id: request.fee_quote_id.clone(),
            budget_reservation_id: request.budget_reservation_id.clone(),
            sponsor_vault_id: request.sponsor_vault_id,
            execution_receipt_root: request.execution_receipt_root,
            state_transition_root: request.state_transition_root,
            gas_measurement_root: request.gas_measurement_root,
            settlement_tx_root: request.settlement_tx_root,
            receipt_nullifier_root,
            status: ReceiptStatus::FastAccepted,
            reserved_budget,
            actual_sponsored_fee: request.actual_sponsored_fee,
            sponsor_surplus,
            fast_finality_millis: request.fast_finality_millis,
            settled_at_height: request.settled_at_height,
            expires_at_height: request.settled_at_height + self.config.receipt_ttl_blocks,
        };
        self.counters.execution_receipt_counter = counter;
        self.execution_receipts
            .insert(execution_receipt_id.clone(), record.clone());
        if let Some(reservation) = self
            .budget_reservations
            .get_mut(&request.budget_reservation_id)
        {
            reservation.status = ReservationStatus::Settled;
            reservation.execution_receipt_id = Some(execution_receipt_id.clone());
        }
        if let Some(quote) = self.fee_quotes.get_mut(&request.fee_quote_id) {
            quote.status = QuoteStatus::Filled;
        }
        if let Some(intent) = self.sponsored_intents.get_mut(&request.intent_id) {
            intent.status = IntentStatus::Settled;
            intent.execution_receipt_id = Some(execution_receipt_id);
        }
        Ok(record)
    }

    pub fn rebate_sponsor_surplus(
        &mut self,
        request: RebateSponsorSurplusRequest,
    ) -> PrivateL2IntentFeeSponsorshipRuntimeResult<SponsorSurplusRebateRecord> {
        required("rebate_commitment_root", &request.rebate_commitment_root)?;
        required("rebate_nullifier", &request.rebate_nullifier)?;
        let receipt = self
            .execution_receipts
            .get(&request.execution_receipt_id)
            .ok_or_else(|| "intent fee sponsorship execution receipt not found".to_string())?;
        if receipt.intent_id != request.intent_id
            || receipt.budget_reservation_id != request.budget_reservation_id
            || receipt.sponsor_vault_id != request.sponsor_vault_id
        {
            return Err(
                "intent fee sponsorship rebate references inconsistent receipt".to_string(),
            );
        }
        if request.surplus_amount != receipt.sponsor_surplus {
            return Err("intent fee sponsorship rebate does not match sponsor surplus".to_string());
        }
        let rebate_nullifier_root = self.consume_nullifier(
            "SPONSOR-SURPLUS-REBATE-NULLIFIER",
            &request.rebate_nullifier,
        )?;
        let counter = self.counters.rebate_receipt_counter.saturating_add(1);
        let rebate_receipt_id = sponsor_surplus_rebate_id(&request, counter);
        let record = SponsorSurplusRebateRecord {
            rebate_receipt_id: rebate_receipt_id.clone(),
            intent_id: request.intent_id.clone(),
            execution_receipt_id: request.execution_receipt_id.clone(),
            budget_reservation_id: request.budget_reservation_id.clone(),
            sponsor_vault_id: request.sponsor_vault_id.clone(),
            rebate_commitment_root: request.rebate_commitment_root,
            surplus_amount: request.surplus_amount,
            rebate_nullifier_root,
            rebated_at_height: request.rebated_at_height,
        };
        self.counters.rebate_receipt_counter = counter;
        self.rebate_receipts
            .insert(rebate_receipt_id.clone(), record.clone());
        if let Some(vault) = self.sponsor_vaults.get_mut(&request.sponsor_vault_id) {
            vault.rebated_surplus = vault.rebated_surplus.saturating_add(request.surplus_amount);
        }
        if let Some(reservation) = self
            .budget_reservations
            .get_mut(&request.budget_reservation_id)
        {
            reservation.status = ReservationStatus::Rebated;
        }
        if let Some(receipt) = self
            .execution_receipts
            .get_mut(&request.execution_receipt_id)
        {
            receipt.status = ReceiptStatus::Rebated;
        }
        if let Some(intent) = self.sponsored_intents.get_mut(&request.intent_id) {
            intent.status = IntentStatus::Rebated;
        }
        Ok(record)
    }

    pub fn slash_bad_sponsor_quote(
        &mut self,
        request: SlashBadSponsorQuoteRequest,
    ) -> PrivateL2IntentFeeSponsorshipRuntimeResult<SponsorQuoteSlashingRecord> {
        required("fee_quote_id", &request.fee_quote_id)?;
        required("sponsor_vault_id", &request.sponsor_vault_id)?;
        required("intent_id", &request.intent_id)?;
        required("evidence_root", &request.evidence_root)?;
        required("challenger_commitment", &request.challenger_commitment)?;
        required("evidence_nullifier", &request.evidence_nullifier)?;
        if request.slash_amount == 0 {
            return Err("intent fee sponsorship slash amount must be positive".to_string());
        }
        let quote = self
            .fee_quotes
            .get(&request.fee_quote_id)
            .ok_or_else(|| "intent fee sponsorship quote not found".to_string())?;
        if quote.intent_id != request.intent_id
            || quote.sponsor_vault_id != request.sponsor_vault_id
        {
            return Err("intent fee sponsorship slash references inconsistent quote".to_string());
        }
        let minimum_slash = quote
            .max_sponsored_fee
            .saturating_mul(self.config.min_slash_bps)
            / PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_MAX_BPS;
        if request.slash_amount < minimum_slash.max(1) {
            return Err("intent fee sponsorship slash below minimum".to_string());
        }
        let evidence_nullifier_root = self.consume_nullifier(
            "SPONSOR-SLASH-EVIDENCE-NULLIFIER",
            &request.evidence_nullifier,
        )?;
        {
            let vault = self
                .sponsor_vaults
                .get_mut(&request.sponsor_vault_id)
                .ok_or_else(|| "intent fee sponsorship sponsor vault not found".to_string())?;
            let from_available = request.slash_amount.min(vault.available_budget);
            vault.available_budget = vault.available_budget.saturating_sub(from_available);
            let remaining = request.slash_amount.saturating_sub(from_available);
            vault.reserved_budget = vault.reserved_budget.saturating_sub(remaining);
            vault.slashed_budget = vault.slashed_budget.saturating_add(request.slash_amount);
            vault.status = SponsorVaultStatus::Slashed;
        }

        let counter = self.counters.slashing_receipt_counter.saturating_add(1);
        let slashing_receipt_id = sponsor_quote_slashing_id(&request, counter);
        let record = SponsorQuoteSlashingRecord {
            slashing_receipt_id: slashing_receipt_id.clone(),
            fee_quote_id: request.fee_quote_id.clone(),
            sponsor_vault_id: request.sponsor_vault_id.clone(),
            intent_id: request.intent_id.clone(),
            reason: request.reason,
            evidence_root: request.evidence_root,
            challenger_commitment: request.challenger_commitment,
            slash_amount: request.slash_amount,
            evidence_nullifier_root,
            slashed_at_height: request.slashed_at_height,
        };
        self.counters.slashing_receipt_counter = counter;
        self.slashing_receipts
            .insert(slashing_receipt_id, record.clone());
        if let Some(quote) = self.fee_quotes.get_mut(&request.fee_quote_id) {
            quote.status = QuoteStatus::Slashed;
        }
        if let Some(intent) = self.sponsored_intents.get_mut(&request.intent_id) {
            intent.status = IntentStatus::Slashed;
        }
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let sponsor_vault_root = merkle_root(
            "PRIVATE-L2-INTENT-FEE-SPONSORSHIP-SPONSOR-VAULTS",
            &self
                .sponsor_vaults
                .values()
                .map(SponsorVaultRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsored_intent_root = merkle_root(
            "PRIVATE-L2-INTENT-FEE-SPONSORSHIP-INTENTS",
            &self
                .sponsored_intents
                .values()
                .map(SponsoredIntentRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let fee_quote_root = merkle_root(
            "PRIVATE-L2-INTENT-FEE-SPONSORSHIP-FEE-QUOTES",
            &self
                .fee_quotes
                .values()
                .map(SponsoredFeeQuoteRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let budget_reservation_root = merkle_root(
            "PRIVATE-L2-INTENT-FEE-SPONSORSHIP-BUDGET-RESERVATIONS",
            &self
                .budget_reservations
                .values()
                .map(SponsorBudgetReservationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let execution_receipt_root = merkle_root(
            "PRIVATE-L2-INTENT-FEE-SPONSORSHIP-EXECUTION-RECEIPTS",
            &self
                .execution_receipts
                .values()
                .map(SponsoredIntentExecutionReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let rebate_receipt_root = merkle_root(
            "PRIVATE-L2-INTENT-FEE-SPONSORSHIP-REBATE-RECEIPTS",
            &self
                .rebate_receipts
                .values()
                .map(SponsorSurplusRebateRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let slashing_receipt_root = merkle_root(
            "PRIVATE-L2-INTENT-FEE-SPONSORSHIP-SLASHING-RECEIPTS",
            &self
                .slashing_receipts
                .values()
                .map(SponsorQuoteSlashingRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-INTENT-FEE-SPONSORSHIP-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_root = root_from_record(
            "PRIVATE-L2-INTENT-FEE-SPONSORSHIP-STATE",
            &json!({
                "protocol_version": self.config.protocol_version,
                "chain_id": self.config.chain_id,
                "current_height": self.current_height,
                "sponsor_vault_root": sponsor_vault_root,
                "sponsored_intent_root": sponsored_intent_root,
                "fee_quote_root": fee_quote_root,
                "budget_reservation_root": budget_reservation_root,
                "execution_receipt_root": execution_receipt_root,
                "rebate_receipt_root": rebate_receipt_root,
                "slashing_receipt_root": slashing_receipt_root,
                "nullifier_root": nullifier_root,
                "counters": self.counters.public_record(),
            }),
        );
        Roots {
            sponsor_vault_root,
            sponsored_intent_root,
            fee_quote_root,
            budget_reservation_root,
            execution_receipt_root,
            rebate_receipt_root,
            slashing_receipt_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "hash_suite": self.config.hash_suite,
            "pq_auth_suite": self.config.pq_auth_suite,
            "voucher_suite": self.config.voucher_suite,
            "receipt_suite": self.config.receipt_suite,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "sponsor_vault_ids": self.sponsor_vaults.keys().cloned().collect::<Vec<_>>(),
            "sponsored_intent_ids": self.sponsored_intents.keys().cloned().collect::<Vec<_>>(),
            "fee_quote_ids": self.fee_quotes.keys().cloned().collect::<Vec<_>>(),
            "budget_reservation_ids": self.budget_reservations.keys().cloned().collect::<Vec<_>>(),
            "execution_receipt_ids": self.execution_receipts.keys().cloned().collect::<Vec<_>>(),
            "rebate_receipt_ids": self.rebate_receipts.keys().cloned().collect::<Vec<_>>(),
            "slashing_receipt_ids": self.slashing_receipts.keys().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn consume_nullifier(
        &mut self,
        label: &str,
        nullifier: &str,
    ) -> PrivateL2IntentFeeSponsorshipRuntimeResult<String> {
        required("nullifier", nullifier)?;
        let nullifier_root = root_from_record(
            &format!("PRIVATE-L2-INTENT-FEE-SPONSORSHIP-{label}"),
            &json!({ "nullifier": nullifier }),
        );
        if !self.consumed_nullifiers.insert(nullifier_root.clone()) {
            self.counters.replay_rejection_counter =
                self.counters.replay_rejection_counter.saturating_add(1);
            return Err("intent fee sponsorship nullifier replay detected".to_string());
        }
        self.counters.consumed_nullifier_counter =
            self.counters.consumed_nullifier_counter.saturating_add(1);
        Ok(nullifier_root)
    }
}

pub fn sponsor_vault_id(request: &RegisterSponsorVaultRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-INTENT-FEE-SPONSORSHIP-SPONSOR-VAULT-ID",
        &json!({
            "counter": counter,
            "sponsor_commitment": request.sponsor_commitment,
            "vault_asset_id": request.vault_asset_id,
            "budget_commitment_root": request.budget_commitment_root,
            "voucher_policy_root": request.voucher_policy_root,
            "sponsor_nonce": request.sponsor_nonce,
            "registered_at_height": request.registered_at_height,
        }),
    )
}

pub fn sponsored_intent_id(request: &OpenFeeSponsorshipIntentRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-INTENT-FEE-SPONSORSHIP-INTENT-ID",
        &json!({
            "counter": counter,
            "lane": request.lane.as_str(),
            "caller_commitment": request.caller_commitment,
            "contract_commitment": request.contract_commitment,
            "intent_payload_root": request.intent_payload_root,
            "voucher_commitment_root": request.voucher_commitment_root,
            "replay_nullifier": request.replay_nullifier,
            "opened_at_height": request.opened_at_height,
        }),
    )
}

pub fn sponsored_fee_quote_id(request: &QuoteSponsoredFeeRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-INTENT-FEE-SPONSORSHIP-FEE-QUOTE-ID",
        &json!({
            "counter": counter,
            "sponsor_vault_id": request.sponsor_vault_id,
            "intent_id": request.intent_id,
            "quote_terms_root": request.quote_terms_root,
            "voucher_blinding_root": request.voucher_blinding_root,
            "max_sponsored_fee": request.max_sponsored_fee,
            "quote_nonce": request.quote_nonce,
            "quoted_at_height": request.quoted_at_height,
        }),
    )
}

pub fn sponsor_budget_reservation_id(
    request: &ReserveSponsorBudgetRequest,
    counter: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-INTENT-FEE-SPONSORSHIP-BUDGET-RESERVATION-ID",
        &json!({
            "counter": counter,
            "intent_id": request.intent_id,
            "fee_quote_id": request.fee_quote_id,
            "sponsor_vault_id": request.sponsor_vault_id,
            "reservation_commitment_root": request.reservation_commitment_root,
            "voucher_nullifier": request.voucher_nullifier,
            "reserved_at_height": request.reserved_at_height,
        }),
    )
}

pub fn sponsored_execution_receipt_id(
    request: &SettleSponsoredIntentReceiptRequest,
    counter: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-INTENT-FEE-SPONSORSHIP-EXECUTION-RECEIPT-ID",
        &json!({
            "counter": counter,
            "intent_id": request.intent_id,
            "fee_quote_id": request.fee_quote_id,
            "budget_reservation_id": request.budget_reservation_id,
            "sponsor_vault_id": request.sponsor_vault_id,
            "execution_receipt_root": request.execution_receipt_root,
            "state_transition_root": request.state_transition_root,
            "receipt_nullifier": request.receipt_nullifier,
            "settled_at_height": request.settled_at_height,
        }),
    )
}

pub fn sponsor_surplus_rebate_id(request: &RebateSponsorSurplusRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-INTENT-FEE-SPONSORSHIP-SPONSOR-SURPLUS-REBATE-ID",
        &json!({
            "counter": counter,
            "intent_id": request.intent_id,
            "execution_receipt_id": request.execution_receipt_id,
            "budget_reservation_id": request.budget_reservation_id,
            "sponsor_vault_id": request.sponsor_vault_id,
            "rebate_commitment_root": request.rebate_commitment_root,
            "rebate_nullifier": request.rebate_nullifier,
            "rebated_at_height": request.rebated_at_height,
        }),
    )
}

pub fn sponsor_quote_slashing_id(request: &SlashBadSponsorQuoteRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-INTENT-FEE-SPONSORSHIP-SPONSOR-QUOTE-SLASHING-ID",
        &json!({
            "counter": counter,
            "fee_quote_id": request.fee_quote_id,
            "sponsor_vault_id": request.sponsor_vault_id,
            "intent_id": request.intent_id,
            "reason": request.reason.as_str(),
            "evidence_root": request.evidence_root,
            "challenger_commitment": request.challenger_commitment,
            "evidence_nullifier": request.evidence_nullifier,
            "slashed_at_height": request.slashed_at_height,
        }),
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_INTENT_FEE_SPONSORSHIP_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(
        &format!("PRIVATE-L2-INTENT-FEE-SPONSORSHIP-PAYLOAD-{domain}"),
        payload,
    )
}

pub fn state_root_from_public_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-INTENT-FEE-SPONSORSHIP-STATE-FROM-RECORD",
        record,
    )
}

pub fn devnet() -> PrivateL2IntentFeeSponsorshipRuntimeResult<State> {
    State::devnet()
}

fn required(field: &str, value: &str) -> PrivateL2IntentFeeSponsorshipRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("intent fee sponsorship field {field} is required"));
    }
    Ok(())
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2IntentFeeSponsorshipRuntimeResult<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("intent fee sponsorship privacy set below minimum".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err("intent fee sponsorship PQ security bits below minimum".to_string());
    }
    Ok(())
}
