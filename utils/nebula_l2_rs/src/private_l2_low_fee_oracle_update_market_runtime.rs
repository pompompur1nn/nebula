use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeeOracleUpdateMarketRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-oracle-update-market-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_INTENT_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024+private-oracle-update-intent-v1";
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_SOLVER_QUOTE_SCHEME: &str =
    "commit-reveal-low-fee-oracle-solver-quote-v1";
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_PQ_COMMITTEE_SCHEME: &str =
    "ml-dsa-87+slh-dsa-pq-oracle-committee-attestation-v1";
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_SPONSOR_RESERVATION_SCHEME: &str =
    "roots-only-low-fee-oracle-update-sponsor-reservation-v1";
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_BATCH_SCHEME: &str =
    "private-low-fee-oracle-update-batch-v1";
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_RECEIPT_REBATE_SCHEME: &str =
    "roots-only-oracle-update-receipt-rebate-v1";
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEVNET_HEIGHT: u64 = 443_200;
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS: u64 = 32;
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 16;
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MAX_INTENTS: usize = 1_048_576;
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MAX_QUOTES: usize = 1_048_576;
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MAX_BATCH_INTENTS: usize = 512;
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize = 4_096;
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 1_024;
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MIN_COMMITTEE_WEIGHT: u64 = 5;
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 18;
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_MICRO_UNITS: u64 =
    20_000;
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_SPONSOR_BUDGET_MICRO_UNITS: u64 =
    500_000_000;
pub const PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleUpdateKind {
    PriceSpot,
    PriceTwap,
    FundingRate,
    ReserveProof,
    Volatility,
    FeeIndex,
    SequencerHealth,
    DataAvailabilityFee,
    RiskParameter,
    EmergencyFlag,
}

impl OracleUpdateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PriceSpot => "price_spot",
            Self::PriceTwap => "price_twap",
            Self::FundingRate => "funding_rate",
            Self::ReserveProof => "reserve_proof",
            Self::Volatility => "volatility",
            Self::FeeIndex => "fee_index",
            Self::SequencerHealth => "sequencer_health",
            Self::DataAvailabilityFee => "data_availability_fee",
            Self::RiskParameter => "risk_parameter",
            Self::EmergencyFlag => "emergency_flag",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    Quoted,
    Sponsored,
    Batched,
    Settled,
    Rejected,
    Expired,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Quoted => "quoted",
            Self::Sponsored => "sponsored",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Submitted | Self::Quoted | Self::Sponsored)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverQuoteStatus {
    Posted,
    Selected,
    Settled,
    Rejected,
    Expired,
}

impl SolverQuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Selected => "selected",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Posted,
    QuorumMet,
    Used,
    Rejected,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::QuorumMet => "quorum_met",
            Self::Used => "used",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
}

impl SponsorReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateBatchStatus {
    Open,
    Attested,
    Sponsored,
    Settled,
    Rejected,
    Expired,
}

impl UpdateBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Attested => "attested",
            Self::Sponsored => "sponsored",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn settlement_ready(self) -> bool {
        matches!(self, Self::Open | Self::Attested | Self::Sponsored)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Rebated,
    Finalized,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Rebated => "rebated",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub intent_encryption_scheme: String,
    pub solver_quote_scheme: String,
    pub pq_committee_scheme: String,
    pub sponsor_reservation_scheme: String,
    pub batch_scheme: String,
    pub receipt_rebate_scheme: String,
    pub intent_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub max_intents: usize,
    pub max_quotes: usize,
    pub max_batch_intents: usize,
    pub max_reservations: usize,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_committee_weight: u64,
    pub quorum_bps: u64,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub max_sponsor_fee_micro_units: u64,
    pub sponsor_budget_micro_units: u64,
    pub require_pq_attestation: bool,
    pub require_fee_sponsor: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_HASH_SUITE.to_string(),
            intent_encryption_scheme:
                PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_INTENT_ENCRYPTION_SCHEME.to_string(),
            solver_quote_scheme:
                PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_SOLVER_QUOTE_SCHEME.to_string(),
            pq_committee_scheme:
                PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_PQ_COMMITTEE_SCHEME.to_string(),
            sponsor_reservation_scheme:
                PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_SPONSOR_RESERVATION_SCHEME
                    .to_string(),
            batch_scheme: PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_BATCH_SCHEME.to_string(),
            receipt_rebate_scheme:
                PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_RECEIPT_REBATE_SCHEME.to_string(),
            intent_ttl_blocks:
                PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS,
            quote_ttl_blocks:
                PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            receipt_ttl_blocks:
                PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS,
            max_intents: PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MAX_INTENTS,
            max_quotes: PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MAX_QUOTES,
            max_batch_intents:
                PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MAX_BATCH_INTENTS,
            max_reservations:
                PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            min_privacy_set_size:
                PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_committee_weight:
                PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MIN_COMMITTEE_WEIGHT,
            quorum_bps: PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_QUORUM_BPS,
            max_user_fee_bps:
                PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_solver_fee_bps:
                PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MAX_SOLVER_FEE_BPS,
            max_sponsor_fee_micro_units:
                PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_MICRO_UNITS,
            sponsor_budget_micro_units:
                PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEFAULT_SPONSOR_BUDGET_MICRO_UNITS,
            require_pq_attestation: true,
            require_fee_sponsor: true,
        }
    }

    pub fn validate(&self) -> PrivateL2LowFeeOracleUpdateMarketRuntimeResult<()> {
        ensure_eq(&self.chain_id, CHAIN_ID, "oracle update market chain id")?;
        ensure_eq(
            &self.protocol_version,
            PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_PROTOCOL_VERSION,
            "oracle update market protocol version",
        )?;
        if self.schema_version != PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_SCHEMA_VERSION {
            return Err("oracle update market schema version mismatch".to_string());
        }
        if self.intent_ttl_blocks == 0
            || self.quote_ttl_blocks == 0
            || self.batch_ttl_blocks == 0
            || self.receipt_ttl_blocks == 0
            || self.max_intents == 0
            || self.max_quotes == 0
            || self.max_batch_intents == 0
            || self.max_reservations == 0
        {
            return Err("oracle update market windows and capacities must be positive".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.min_pq_security_bits < 192
            || self.min_committee_weight == 0
        {
            return Err(
                "oracle update market privacy, PQ, or quorum floors are invalid".to_string(),
            );
        }
        if self.quorum_bps > PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_MAX_BPS
            || self.max_user_fee_bps > PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_MAX_BPS
            || self.max_solver_fee_bps > PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_MAX_BPS
        {
            return Err("oracle update market bps configuration is invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_oracle_update_market_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "intent_encryption_scheme": self.intent_encryption_scheme,
            "solver_quote_scheme": self.solver_quote_scheme,
            "pq_committee_scheme": self.pq_committee_scheme,
            "sponsor_reservation_scheme": self.sponsor_reservation_scheme,
            "batch_scheme": self.batch_scheme,
            "receipt_rebate_scheme": self.receipt_rebate_scheme,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "max_intents": self.max_intents,
            "max_quotes": self.max_quotes,
            "max_batch_intents": self.max_batch_intents,
            "max_reservations": self.max_reservations,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_committee_weight": self.min_committee_weight,
            "quorum_bps": self.quorum_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "max_sponsor_fee_micro_units": self.max_sponsor_fee_micro_units,
            "sponsor_budget_micro_units": self.sponsor_budget_micro_units,
            "require_pq_attestation": self.require_pq_attestation,
            "require_fee_sponsor": self.require_fee_sponsor,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub next_intent_nonce: u64,
    pub next_quote_nonce: u64,
    pub next_attestation_nonce: u64,
    pub next_reservation_nonce: u64,
    pub next_batch_nonce: u64,
    pub next_receipt_nonce: u64,
    pub intents_submitted: u64,
    pub solver_quotes_posted: u64,
    pub attestations_posted: u64,
    pub sponsor_reservations_recorded: u64,
    pub update_batches_opened: u64,
    pub receipts_published: u64,
    pub rebates_paid_micro_units: u64,
    pub sponsored_fee_micro_units: u64,
    pub settled_intents: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_oracle_update_market_counters",
            "next_intent_nonce": self.next_intent_nonce,
            "next_quote_nonce": self.next_quote_nonce,
            "next_attestation_nonce": self.next_attestation_nonce,
            "next_reservation_nonce": self.next_reservation_nonce,
            "next_batch_nonce": self.next_batch_nonce,
            "next_receipt_nonce": self.next_receipt_nonce,
            "intents_submitted": self.intents_submitted,
            "solver_quotes_posted": self.solver_quotes_posted,
            "attestations_posted": self.attestations_posted,
            "sponsor_reservations_recorded": self.sponsor_reservations_recorded,
            "update_batches_opened": self.update_batches_opened,
            "receipts_published": self.receipts_published,
            "rebates_paid_micro_units": self.rebates_paid_micro_units,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
            "settled_intents": self.settled_intents,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitEncryptedOracleUpdateIntentRequest {
    pub update_kind: OracleUpdateKind,
    pub feed_id: String,
    pub requester_commitment: String,
    pub encrypted_intent_root: String,
    pub encrypted_witness_root: String,
    pub update_commitment_root: String,
    pub nullifier_root: String,
    pub refund_commitment_root: String,
    pub max_user_fee_bps: u64,
    pub max_sponsor_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitEncryptedOracleUpdateIntentRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeOracleUpdateMarketRuntimeResult<()> {
        require_non_empty("feed id", &self.feed_id)?;
        require_root("requester commitment", &self.requester_commitment)?;
        require_root("encrypted intent root", &self.encrypted_intent_root)?;
        require_root("encrypted witness root", &self.encrypted_witness_root)?;
        require_root("update commitment root", &self.update_commitment_root)?;
        require_root("nullifier root", &self.nullifier_root)?;
        require_root("refund commitment root", &self.refund_commitment_root)?;
        require_root("PQ authorization root", &self.pq_authorization_root)?;
        if self.max_user_fee_bps > config.max_user_fee_bps {
            return Err("oracle update intent fee cap exceeds low-fee policy".to_string());
        }
        if self.max_sponsor_fee_micro_units > config.max_sponsor_fee_micro_units {
            return Err("oracle update intent sponsor fee exceeds policy".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("oracle update intent privacy set is below minimum".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("oracle update intent PQ security bits below minimum".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height
            || self.expires_at_height
                > self
                    .submitted_at_height
                    .saturating_add(config.intent_ttl_blocks)
        {
            return Err("oracle update intent expiry is outside ttl".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "submit_encrypted_oracle_update_intent_request",
            "update_kind": self.update_kind.as_str(),
            "feed_id": self.feed_id,
            "requester_commitment": self.requester_commitment,
            "encrypted_intent_root": self.encrypted_intent_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "update_commitment_root": self.update_commitment_root,
            "nullifier_root": self.nullifier_root,
            "refund_commitment_root": self.refund_commitment_root,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_sponsor_fee_micro_units": self.max_sponsor_fee_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "pq_authorization_root": self.pq_authorization_root,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostSolverQuoteRequest {
    pub solver_commitment: String,
    pub intent_ids: Vec<String>,
    pub route_commitment_root: String,
    pub execution_plan_root: String,
    pub quote_commitment_root: String,
    pub expected_rebate_micro_units: u64,
    pub solver_fee_bps: u64,
    pub sponsored_fee_micro_units: u64,
    pub valid_at_height: u64,
    pub expires_at_height: u64,
}

impl PostSolverQuoteRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeOracleUpdateMarketRuntimeResult<()> {
        require_root("solver commitment", &self.solver_commitment)?;
        ensure_unique(&self.intent_ids, "intent id")?;
        require_root("route commitment root", &self.route_commitment_root)?;
        require_root("execution plan root", &self.execution_plan_root)?;
        require_root("quote commitment root", &self.quote_commitment_root)?;
        if self.intent_ids.is_empty() || self.intent_ids.len() > config.max_batch_intents {
            return Err("solver quote intent coverage is outside capacity".to_string());
        }
        if self.solver_fee_bps > config.max_solver_fee_bps {
            return Err("solver quote fee exceeds low-fee policy".to_string());
        }
        if self.sponsored_fee_micro_units > config.max_sponsor_fee_micro_units {
            return Err("solver quote sponsor fee exceeds policy".to_string());
        }
        if self.expires_at_height <= self.valid_at_height
            || self.expires_at_height > self.valid_at_height.saturating_add(config.quote_ttl_blocks)
        {
            return Err("solver quote expiry is outside ttl".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "post_solver_quote_request",
            "solver_commitment": self.solver_commitment,
            "intent_ids": self.intent_ids,
            "route_commitment_root": self.route_commitment_root,
            "execution_plan_root": self.execution_plan_root,
            "quote_commitment_root": self.quote_commitment_root,
            "expected_rebate_micro_units": self.expected_rebate_micro_units,
            "solver_fee_bps": self.solver_fee_bps,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
            "valid_at_height": self.valid_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostPqOracleCommitteeAttestationRequest {
    pub batch_id: String,
    pub committee_id: String,
    pub committee_member_root: String,
    pub attestation_payload_root: String,
    pub pq_signature_root: String,
    pub backup_signature_root: String,
    pub signed_intent_root: String,
    pub signer_weight: u64,
    pub total_weight: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl PostPqOracleCommitteeAttestationRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeOracleUpdateMarketRuntimeResult<()> {
        require_non_empty("batch id", &self.batch_id)?;
        require_non_empty("committee id", &self.committee_id)?;
        require_root("committee member root", &self.committee_member_root)?;
        require_root("attestation payload root", &self.attestation_payload_root)?;
        require_root("PQ signature root", &self.pq_signature_root)?;
        require_root("backup signature root", &self.backup_signature_root)?;
        require_root("signed intent root", &self.signed_intent_root)?;
        if self.signer_weight < config.min_committee_weight
            || self.signer_weight > self.total_weight
        {
            return Err("PQ oracle committee signer weight is invalid".to_string());
        }
        if quorum_bps(self.signer_weight, self.total_weight) < config.quorum_bps {
            return Err("PQ oracle committee quorum is below threshold".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("PQ oracle committee attestation security bits below minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "post_pq_oracle_committee_attestation_request",
            "batch_id": self.batch_id,
            "committee_id": self.committee_id,
            "committee_member_root": self.committee_member_root,
            "attestation_payload_root": self.attestation_payload_root,
            "pq_signature_root": self.pq_signature_root,
            "backup_signature_root": self.backup_signature_root,
            "signed_intent_root": self.signed_intent_root,
            "signer_weight": self.signer_weight,
            "total_weight": self.total_weight,
            "quorum_bps": quorum_bps(self.signer_weight, self.total_weight),
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveFeeSponsorRequest {
    pub sponsor_commitment: String,
    pub intent_ids: Vec<String>,
    pub quote_id: Option<String>,
    pub rebate_commitment_root: String,
    pub reservation_authorization_root: String,
    pub reserved_fee_micro_units: u64,
    pub reserved_rebate_micro_units: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveFeeSponsorRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeOracleUpdateMarketRuntimeResult<()> {
        require_root("sponsor commitment", &self.sponsor_commitment)?;
        ensure_unique(&self.intent_ids, "intent id")?;
        require_root("rebate commitment root", &self.rebate_commitment_root)?;
        require_root(
            "reservation authorization root",
            &self.reservation_authorization_root,
        )?;
        if let Some(quote_id) = &self.quote_id {
            require_non_empty("quote id", quote_id)?;
        }
        if self.intent_ids.is_empty() || self.intent_ids.len() > config.max_batch_intents {
            return Err("fee sponsor reservation intent coverage is outside capacity".to_string());
        }
        if self.reserved_fee_micro_units > config.sponsor_budget_micro_units
            || self.reserved_rebate_micro_units > config.sponsor_budget_micro_units
        {
            return Err("fee sponsor reservation exceeds budget".to_string());
        }
        if self.expires_at_height <= self.reserved_at_height
            || self.expires_at_height
                > self
                    .reserved_at_height
                    .saturating_add(config.receipt_ttl_blocks)
        {
            return Err("fee sponsor reservation expiry is outside ttl".to_string());
        }
        Ok(())
    }

    pub fn total_reserved_micro_units(&self) -> u64 {
        self.reserved_fee_micro_units
            .saturating_add(self.reserved_rebate_micro_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_fee_sponsor_request",
            "sponsor_commitment": self.sponsor_commitment,
            "intent_ids": self.intent_ids,
            "quote_id": self.quote_id,
            "rebate_commitment_root": self.rebate_commitment_root,
            "reservation_authorization_root": self.reservation_authorization_root,
            "reserved_fee_micro_units": self.reserved_fee_micro_units,
            "reserved_rebate_micro_units": self.reserved_rebate_micro_units,
            "total_reserved_micro_units": self.total_reserved_micro_units(),
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenLowFeeUpdateBatchRequest {
    pub intent_ids: Vec<String>,
    pub selected_quote_id: Option<String>,
    pub reservation_ids: Vec<String>,
    pub feed_root: String,
    pub encrypted_update_root: String,
    pub batch_witness_root: String,
    pub update_result_commitment_root: String,
    pub low_fee_policy_root: String,
    pub state_root_before: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl OpenLowFeeUpdateBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeOracleUpdateMarketRuntimeResult<()> {
        ensure_unique(&self.intent_ids, "intent id")?;
        ensure_unique(&self.reservation_ids, "reservation id")?;
        require_root("feed root", &self.feed_root)?;
        require_root("encrypted update root", &self.encrypted_update_root)?;
        require_root("batch witness root", &self.batch_witness_root)?;
        require_root(
            "update result commitment root",
            &self.update_result_commitment_root,
        )?;
        require_root("low-fee policy root", &self.low_fee_policy_root)?;
        require_root("state root before", &self.state_root_before)?;
        if let Some(quote_id) = &self.selected_quote_id {
            require_non_empty("selected quote id", quote_id)?;
        }
        if self.intent_ids.is_empty() || self.intent_ids.len() > config.max_batch_intents {
            return Err("low-fee update batch intent count is outside capacity".to_string());
        }
        if config.require_fee_sponsor && self.reservation_ids.is_empty() {
            return Err("low-fee update batch requires fee sponsor reservations".to_string());
        }
        if self.expires_at_height <= self.opened_at_height
            || self.expires_at_height
                > self
                    .opened_at_height
                    .saturating_add(config.batch_ttl_blocks)
        {
            return Err("low-fee update batch expiry is outside ttl".to_string());
        }
        Ok(())
    }

    pub fn intent_root(&self) -> String {
        id_list_root("BATCH-INTENT-ID", &self.intent_ids)
    }

    pub fn reservation_root(&self) -> String {
        id_list_root("BATCH-RESERVATION-ID", &self.reservation_ids)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "open_low_fee_update_batch_request",
            "intent_ids": self.intent_ids,
            "selected_quote_id": self.selected_quote_id,
            "reservation_ids": self.reservation_ids,
            "intent_root": self.intent_root(),
            "reservation_root": self.reservation_root(),
            "feed_root": self.feed_root,
            "encrypted_update_root": self.encrypted_update_root,
            "batch_witness_root": self.batch_witness_root,
            "update_result_commitment_root": self.update_result_commitment_root,
            "low_fee_policy_root": self.low_fee_policy_root,
            "state_root_before": self.state_root_before,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishOracleUpdateReceiptRequest {
    pub batch_id: String,
    pub selected_quote_id: Option<String>,
    pub attestation_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub settlement_tx_root: String,
    pub receipt_payload_root: String,
    pub rebate_distribution_root: String,
    pub state_root_before: String,
    pub runtime_state_root_after: String,
    pub settled_fee_micro_units: u64,
    pub rebate_paid_micro_units: u64,
    pub settled_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl PublishOracleUpdateReceiptRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2LowFeeOracleUpdateMarketRuntimeResult<()> {
        require_non_empty("batch id", &self.batch_id)?;
        ensure_unique(&self.attestation_ids, "attestation id")?;
        ensure_unique(&self.reservation_ids, "reservation id")?;
        require_root("settlement tx root", &self.settlement_tx_root)?;
        require_root("receipt payload root", &self.receipt_payload_root)?;
        require_root("rebate distribution root", &self.rebate_distribution_root)?;
        require_root("state root before", &self.state_root_before)?;
        require_root("runtime state root after", &self.runtime_state_root_after)?;
        if let Some(quote_id) = &self.selected_quote_id {
            require_non_empty("selected quote id", quote_id)?;
        }
        if config.require_pq_attestation && self.attestation_ids.is_empty() {
            return Err("oracle update receipt requires PQ attestation".to_string());
        }
        if config.require_fee_sponsor && self.reservation_ids.is_empty() {
            return Err("oracle update receipt requires sponsor reservations".to_string());
        }
        if self.settled_fee_micro_units > config.sponsor_budget_micro_units
            || self.rebate_paid_micro_units > config.sponsor_budget_micro_units
        {
            return Err("oracle update receipt fee or rebate exceeds budget".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "publish_oracle_update_receipt_request",
            "batch_id": self.batch_id,
            "selected_quote_id": self.selected_quote_id,
            "attestation_ids": self.attestation_ids,
            "reservation_ids": self.reservation_ids,
            "settlement_tx_root": self.settlement_tx_root,
            "receipt_payload_root": self.receipt_payload_root,
            "rebate_distribution_root": self.rebate_distribution_root,
            "state_root_before": self.state_root_before,
            "runtime_state_root_after": self.runtime_state_root_after,
            "settled_fee_micro_units": self.settled_fee_micro_units,
            "rebate_paid_micro_units": self.rebate_paid_micro_units,
            "settled_at_height": self.settled_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedOracleUpdateIntentRecord {
    pub intent_id: String,
    pub status: IntentStatus,
    pub selected_quote_id: Option<String>,
    pub reservation_ids: BTreeSet<String>,
    pub batch_id: Option<String>,
    pub receipt_id: Option<String>,
    pub request: SubmitEncryptedOracleUpdateIntentRequest,
}

impl EncryptedOracleUpdateIntentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_oracle_update_intent_record",
            "intent_id": self.intent_id,
            "status": self.status.as_str(),
            "selected_quote_id": self.selected_quote_id,
            "reservation_ids": self.reservation_ids,
            "batch_id": self.batch_id,
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverQuoteRecord {
    pub quote_id: String,
    pub score: u128,
    pub status: SolverQuoteStatus,
    pub batch_id: Option<String>,
    pub receipt_id: Option<String>,
    pub request: PostSolverQuoteRequest,
}

impl SolverQuoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "solver_quote_record",
            "quote_id": self.quote_id,
            "score": self.score,
            "status": self.status.as_str(),
            "batch_id": self.batch_id,
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqOracleCommitteeAttestationRecord {
    pub attestation_id: String,
    pub status: AttestationStatus,
    pub request: PostPqOracleCommitteeAttestationRequest,
}

impl PqOracleCommitteeAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_oracle_committee_attestation_record",
            "attestation_id": self.attestation_id,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorReservationRecord {
    pub reservation_id: String,
    pub status: SponsorReservationStatus,
    pub batch_id: Option<String>,
    pub receipt_id: Option<String>,
    pub request: ReserveFeeSponsorRequest,
}

impl FeeSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_sponsor_reservation_record",
            "reservation_id": self.reservation_id,
            "status": self.status.as_str(),
            "batch_id": self.batch_id,
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeUpdateBatchRecord {
    pub batch_id: String,
    pub status: UpdateBatchStatus,
    pub attestation_ids: BTreeSet<String>,
    pub receipt_id: Option<String>,
    pub request: OpenLowFeeUpdateBatchRequest,
}

impl LowFeeUpdateBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_update_batch_record",
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "attestation_ids": self.attestation_ids,
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleUpdateReceiptRecord {
    pub receipt_id: String,
    pub status: ReceiptStatus,
    pub request: PublishOracleUpdateReceiptRequest,
}

impl OracleUpdateReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_update_receipt_record",
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
            "request": self.request.public_record(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub intent_root: String,
    pub solver_quote_root: String,
    pub attestation_root: String,
    pub sponsor_reservation_root: String,
    pub update_batch_root: String,
    pub receipt_root: String,
    pub consumed_nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "intent_root": self.intent_root,
            "solver_quote_root": self.solver_quote_root,
            "attestation_root": self.attestation_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "update_batch_root": self.update_batch_root,
            "receipt_root": self.receipt_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub runtime_root: String,
    pub sponsor_budget_remaining_micro_units: u64,
    pub intents: BTreeMap<String, EncryptedOracleUpdateIntentRecord>,
    pub solver_quotes: BTreeMap<String, SolverQuoteRecord>,
    pub attestations: BTreeMap<String, PqOracleCommitteeAttestationRecord>,
    pub sponsor_reservations: BTreeMap<String, FeeSponsorReservationRecord>,
    pub update_batches: BTreeMap<String, LowFeeUpdateBatchRecord>,
    pub receipts: BTreeMap<String, OracleUpdateReceiptRecord>,
    pub consumed_nullifier_roots: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn devnet() -> Self {
        Self::new(
            Config::devnet(),
            PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_DEVNET_HEIGHT,
        )
    }

    pub fn new(config: Config, current_height: u64) -> Self {
        let sponsor_budget_remaining_micro_units = config.sponsor_budget_micro_units;
        Self {
            config,
            counters: Counters::default(),
            current_height,
            runtime_root: commitment_id(
                "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-RUNTIME",
                "genesis",
            ),
            sponsor_budget_remaining_micro_units,
            intents: BTreeMap::new(),
            solver_quotes: BTreeMap::new(),
            attestations: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            update_batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            consumed_nullifier_roots: BTreeSet::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn submit_encrypted_oracle_update_intent(
        &mut self,
        request: SubmitEncryptedOracleUpdateIntentRequest,
    ) -> PrivateL2LowFeeOracleUpdateMarketRuntimeResult<EncryptedOracleUpdateIntentRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.intents.len() >= self.config.max_intents {
            return Err("oracle update intent capacity reached".to_string());
        }
        if self
            .consumed_nullifier_roots
            .contains(&request.nullifier_root)
        {
            return Err("oracle update intent nullifier root already consumed".to_string());
        }
        let intent_id =
            encrypted_oracle_update_intent_id(&request, self.counters.next_intent_nonce);
        let record = EncryptedOracleUpdateIntentRecord {
            intent_id: intent_id.clone(),
            status: IntentStatus::Submitted,
            selected_quote_id: None,
            reservation_ids: BTreeSet::new(),
            batch_id: None,
            receipt_id: None,
            request,
        };
        self.current_height = self.current_height.max(record.request.submitted_at_height);
        self.counters.next_intent_nonce = self.counters.next_intent_nonce.saturating_add(1);
        self.counters.intents_submitted = self.counters.intents_submitted.saturating_add(1);
        self.publish_public_record(
            "encrypted_oracle_update_intent",
            &intent_id,
            record.public_record(),
        );
        self.intents.insert(intent_id, record.clone());
        Ok(record)
    }

    pub fn post_solver_quote(
        &mut self,
        request: PostSolverQuoteRequest,
    ) -> PrivateL2LowFeeOracleUpdateMarketRuntimeResult<SolverQuoteRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.solver_quotes.len() >= self.config.max_quotes {
            return Err("solver quote capacity reached".to_string());
        }
        for intent_id in &request.intent_ids {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| "solver quote references unknown intent".to_string())?;
            if !intent.status.batchable() {
                return Err("solver quote references non-batchable intent".to_string());
            }
        }
        let score = solver_quote_score(&request);
        let quote_id = solver_quote_id(&request, score, self.counters.next_quote_nonce);
        let record = SolverQuoteRecord {
            quote_id: quote_id.clone(),
            score,
            status: SolverQuoteStatus::Posted,
            batch_id: None,
            receipt_id: None,
            request,
        };
        for intent_id in &record.request.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Quoted;
                intent.selected_quote_id = Some(quote_id.clone());
            }
        }
        self.current_height = self.current_height.max(record.request.valid_at_height);
        self.counters.next_quote_nonce = self.counters.next_quote_nonce.saturating_add(1);
        self.counters.solver_quotes_posted = self.counters.solver_quotes_posted.saturating_add(1);
        self.refresh_intent_records(&record.request.intent_ids);
        self.publish_public_record("solver_quote", &quote_id, record.public_record());
        self.solver_quotes.insert(quote_id, record.clone());
        Ok(record)
    }

    pub fn reserve_fee_sponsor(
        &mut self,
        request: ReserveFeeSponsorRequest,
    ) -> PrivateL2LowFeeOracleUpdateMarketRuntimeResult<FeeSponsorReservationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.sponsor_reservations.len() >= self.config.max_reservations {
            return Err("fee sponsor reservation capacity reached".to_string());
        }
        if request.total_reserved_micro_units() > self.sponsor_budget_remaining_micro_units {
            return Err("fee sponsor budget is exhausted".to_string());
        }
        for intent_id in &request.intent_ids {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| "fee sponsor reservation references unknown intent".to_string())?;
            if !intent.status.batchable() {
                return Err("fee sponsor reservation references non-batchable intent".to_string());
            }
        }
        if let Some(quote_id) = &request.quote_id {
            let quote = self
                .solver_quotes
                .get(quote_id)
                .ok_or_else(|| "fee sponsor reservation references unknown quote".to_string())?;
            if !covers_all_ids(&quote.request.intent_ids, &request.intent_ids) {
                return Err("fee sponsor reservation quote does not cover intents".to_string());
            }
        }
        let reservation_id = fee_sponsor_reservation_id(
            &request,
            self.counters.next_reservation_nonce,
            self.sponsor_budget_remaining_micro_units,
        );
        self.sponsor_budget_remaining_micro_units = self
            .sponsor_budget_remaining_micro_units
            .saturating_sub(request.total_reserved_micro_units());
        let record = FeeSponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            status: SponsorReservationStatus::Reserved,
            batch_id: None,
            receipt_id: None,
            request,
        };
        for intent_id in &record.request.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Sponsored;
                intent.reservation_ids.insert(reservation_id.clone());
            }
        }
        self.current_height = self.current_height.max(record.request.reserved_at_height);
        self.counters.next_reservation_nonce =
            self.counters.next_reservation_nonce.saturating_add(1);
        self.counters.sponsor_reservations_recorded = self
            .counters
            .sponsor_reservations_recorded
            .saturating_add(1);
        self.counters.sponsored_fee_micro_units = self
            .counters
            .sponsored_fee_micro_units
            .saturating_add(record.request.reserved_fee_micro_units);
        self.refresh_intent_records(&record.request.intent_ids);
        self.publish_public_record(
            "fee_sponsor_reservation",
            &reservation_id,
            record.public_record(),
        );
        self.sponsor_reservations
            .insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn open_low_fee_update_batch(
        &mut self,
        request: OpenLowFeeUpdateBatchRequest,
    ) -> PrivateL2LowFeeOracleUpdateMarketRuntimeResult<LowFeeUpdateBatchRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        for intent_id in &request.intent_ids {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| "low-fee update batch references unknown intent".to_string())?;
            if !intent.status.batchable() {
                return Err("low-fee update batch references non-batchable intent".to_string());
            }
        }
        if let Some(quote_id) = &request.selected_quote_id {
            let quote = self
                .solver_quotes
                .get(quote_id)
                .ok_or_else(|| "low-fee update batch references unknown quote".to_string())?;
            if !covers_all_ids(&quote.request.intent_ids, &request.intent_ids) {
                return Err("low-fee update batch quote does not cover intents".to_string());
            }
        }
        if !covers_all_reservations(
            &self.sponsor_reservations,
            &request.reservation_ids,
            &request.intent_ids,
        ) {
            return Err(
                "low-fee update batch sponsor reservations do not cover intents".to_string(),
            );
        }
        let batch_id = low_fee_update_batch_id(&request, self.counters.next_batch_nonce);
        let record = LowFeeUpdateBatchRecord {
            batch_id: batch_id.clone(),
            status: UpdateBatchStatus::Open,
            attestation_ids: BTreeSet::new(),
            receipt_id: None,
            request,
        };
        for intent_id in &record.request.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Batched;
                intent.batch_id = Some(batch_id.clone());
            }
        }
        if let Some(quote_id) = &record.request.selected_quote_id {
            if let Some(quote) = self.solver_quotes.get_mut(quote_id) {
                quote.status = SolverQuoteStatus::Selected;
                quote.batch_id = Some(batch_id.clone());
            }
        }
        for reservation_id in &record.request.reservation_ids {
            if let Some(reservation) = self.sponsor_reservations.get_mut(reservation_id) {
                reservation.batch_id = Some(batch_id.clone());
            }
        }
        self.current_height = self.current_height.max(record.request.opened_at_height);
        self.counters.next_batch_nonce = self.counters.next_batch_nonce.saturating_add(1);
        self.counters.update_batches_opened = self.counters.update_batches_opened.saturating_add(1);
        self.refresh_intent_records(&record.request.intent_ids);
        if let Some(quote_id) = &record.request.selected_quote_id {
            self.refresh_quote_records(&[quote_id.clone()]);
        }
        self.refresh_reservation_records(&record.request.reservation_ids);
        self.publish_public_record("low_fee_update_batch", &batch_id, record.public_record());
        self.update_batches.insert(batch_id, record.clone());
        Ok(record)
    }

    pub fn post_pq_oracle_committee_attestation(
        &mut self,
        request: PostPqOracleCommitteeAttestationRequest,
    ) -> PrivateL2LowFeeOracleUpdateMarketRuntimeResult<PqOracleCommitteeAttestationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let batch = self
            .update_batches
            .get(&request.batch_id)
            .cloned()
            .ok_or_else(|| {
                "PQ oracle committee attestation references unknown batch".to_string()
            })?;
        if !batch.status.settlement_ready() {
            return Err(
                "PQ oracle committee attestation references non-settlement-ready batch".to_string(),
            );
        }
        let attestation_id =
            pq_oracle_committee_attestation_id(&request, self.counters.next_attestation_nonce);
        let record = PqOracleCommitteeAttestationRecord {
            attestation_id: attestation_id.clone(),
            status: AttestationStatus::QuorumMet,
            request,
        };
        if let Some(batch) = self.update_batches.get_mut(&record.request.batch_id) {
            batch.status = UpdateBatchStatus::Attested;
            batch.attestation_ids.insert(attestation_id.clone());
        }
        self.current_height = self.current_height.max(record.request.attested_at_height);
        self.counters.next_attestation_nonce =
            self.counters.next_attestation_nonce.saturating_add(1);
        self.counters.attestations_posted = self.counters.attestations_posted.saturating_add(1);
        self.refresh_batch_records(&[record.request.batch_id.clone()]);
        self.publish_public_record(
            "pq_oracle_committee_attestation",
            &attestation_id,
            record.public_record(),
        );
        self.attestations.insert(attestation_id, record.clone());
        Ok(record)
    }

    pub fn publish_oracle_update_receipt(
        &mut self,
        request: PublishOracleUpdateReceiptRequest,
    ) -> PrivateL2LowFeeOracleUpdateMarketRuntimeResult<OracleUpdateReceiptRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let batch = self
            .update_batches
            .get(&request.batch_id)
            .cloned()
            .ok_or_else(|| "oracle update receipt references unknown batch".to_string())?;
        if !batch.status.settlement_ready() {
            return Err("oracle update receipt references non-settlement-ready batch".to_string());
        }
        if request.settled_at_height
            > batch
                .request
                .expires_at_height
                .saturating_add(self.config.receipt_ttl_blocks)
        {
            return Err("oracle update receipt deadline elapsed".to_string());
        }
        if !covers_all_ids(&batch.request.reservation_ids, &request.reservation_ids) {
            return Err("oracle update receipt reservations are not attached to batch".to_string());
        }
        if self.config.require_pq_attestation
            && !covers_all_attestations(
                &self.attestations,
                &request.attestation_ids,
                &request.batch_id,
            )
        {
            return Err("oracle update receipt attestations do not cover batch".to_string());
        }
        let receipt_id = oracle_update_receipt_id(&request, self.counters.next_receipt_nonce);
        if let Some(batch) = self.update_batches.get_mut(&request.batch_id) {
            batch.status = UpdateBatchStatus::Settled;
            batch.receipt_id = Some(receipt_id.clone());
        }
        for intent_id in &batch.request.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Settled;
                intent.receipt_id = Some(receipt_id.clone());
            }
        }
        if let Some(quote_id) = &request.selected_quote_id {
            if let Some(quote) = self.solver_quotes.get_mut(quote_id) {
                quote.status = SolverQuoteStatus::Settled;
                quote.receipt_id = Some(receipt_id.clone());
            }
        }
        for attestation_id in &request.attestation_ids {
            if let Some(attestation) = self.attestations.get_mut(attestation_id) {
                attestation.status = AttestationStatus::Used;
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.sponsor_reservations.get_mut(reservation_id) {
                reservation.status = SponsorReservationStatus::Consumed;
                reservation.receipt_id = Some(receipt_id.clone());
            }
        }
        for intent_id in &batch.request.intent_ids {
            if let Some(intent) = self.intents.get(intent_id) {
                self.consumed_nullifier_roots
                    .insert(intent.request.nullifier_root.clone());
            }
        }
        self.runtime_root = request.runtime_state_root_after.clone();
        self.current_height = self.current_height.max(request.settled_at_height);
        self.counters.next_receipt_nonce = self.counters.next_receipt_nonce.saturating_add(1);
        self.counters.receipts_published = self.counters.receipts_published.saturating_add(1);
        self.counters.rebates_paid_micro_units = self
            .counters
            .rebates_paid_micro_units
            .saturating_add(request.rebate_paid_micro_units);
        self.counters.settled_intents = self
            .counters
            .settled_intents
            .saturating_add(batch.request.intent_ids.len() as u64);
        let status = if request.finalized_at_height.is_some() {
            ReceiptStatus::Finalized
        } else if request.rebate_paid_micro_units > 0 {
            ReceiptStatus::Rebated
        } else {
            ReceiptStatus::Published
        };
        let record = OracleUpdateReceiptRecord {
            receipt_id: receipt_id.clone(),
            status,
            request,
        };
        self.refresh_intent_records(&batch.request.intent_ids);
        self.refresh_batch_records(&[record.request.batch_id.clone()]);
        if let Some(quote_id) = &record.request.selected_quote_id {
            self.refresh_quote_records(&[quote_id.clone()]);
        }
        self.refresh_attestation_records(&record.request.attestation_ids);
        self.refresh_reservation_records(&record.request.reservation_ids);
        self.publish_public_record("oracle_update_receipt", &receipt_id, record.public_record());
        self.receipts.insert(receipt_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: private_l2_low_fee_oracle_update_market_payload_root(
                "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-CONFIG",
                &self.config.public_record(),
            ),
            counter_root: private_l2_low_fee_oracle_update_market_payload_root(
                "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-COUNTERS",
                &self.counters.public_record(),
            ),
            intent_root: private_l2_low_fee_oracle_update_market_merkle_root(
                "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-INTENT",
                self.intents
                    .values()
                    .map(EncryptedOracleUpdateIntentRecord::public_record)
                    .collect(),
            ),
            solver_quote_root: private_l2_low_fee_oracle_update_market_merkle_root(
                "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-SOLVER-QUOTE",
                self.solver_quotes
                    .values()
                    .map(SolverQuoteRecord::public_record)
                    .collect(),
            ),
            attestation_root: private_l2_low_fee_oracle_update_market_merkle_root(
                "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-ATTESTATION",
                self.attestations
                    .values()
                    .map(PqOracleCommitteeAttestationRecord::public_record)
                    .collect(),
            ),
            sponsor_reservation_root: private_l2_low_fee_oracle_update_market_merkle_root(
                "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-SPONSOR-RESERVATION",
                self.sponsor_reservations
                    .values()
                    .map(FeeSponsorReservationRecord::public_record)
                    .collect(),
            ),
            update_batch_root: private_l2_low_fee_oracle_update_market_merkle_root(
                "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-UPDATE-BATCH",
                self.update_batches
                    .values()
                    .map(LowFeeUpdateBatchRecord::public_record)
                    .collect(),
            ),
            receipt_root: private_l2_low_fee_oracle_update_market_merkle_root(
                "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-RECEIPT",
                self.receipts
                    .values()
                    .map(OracleUpdateReceiptRecord::public_record)
                    .collect(),
            ),
            consumed_nullifier_root: private_l2_low_fee_oracle_update_market_merkle_root(
                "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-CONSUMED-NULLIFIER",
                self.consumed_nullifier_roots
                    .iter()
                    .map(|root| json!({ "nullifier_root": root }))
                    .collect(),
            ),
            public_record_root: private_l2_low_fee_oracle_update_market_merkle_root(
                "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-PUBLIC-RECORD",
                self.public_records.values().cloned().collect(),
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_low_fee_oracle_update_market_runtime",
            "protocol_version": PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "hash_suite": PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_HASH_SUITE,
            "intent_encryption_scheme": PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_INTENT_ENCRYPTION_SCHEME,
            "solver_quote_scheme": PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_SOLVER_QUOTE_SCHEME,
            "pq_committee_scheme": PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_PQ_COMMITTEE_SCHEME,
            "sponsor_reservation_scheme": PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_SPONSOR_RESERVATION_SCHEME,
            "batch_scheme": PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_BATCH_SCHEME,
            "receipt_rebate_scheme": PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_RECEIPT_REBATE_SCHEME,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "runtime_root": self.runtime_root,
            "sponsor_budget_remaining_micro_units": self.sponsor_budget_remaining_micro_units,
            "roots": self.roots().public_record(),
            "privacy_boundary": "public records expose roots, commitments, statuses, counters, and deterministic ids only",
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        json!({
            "state_root": private_l2_low_fee_oracle_update_market_state_root_from_record(&record),
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        private_l2_low_fee_oracle_update_market_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    fn publish_public_record(&mut self, record_kind: &str, subject_id: &str, payload: Value) {
        let record_id = public_record_id(record_kind, subject_id, &payload);
        self.public_records.insert(
            record_id,
            roots_only_payload(record_kind, subject_id, &payload),
        );
    }

    fn refresh_intent_records(&mut self, intent_ids: &[String]) {
        let updates = intent_ids
            .iter()
            .filter_map(|intent_id| {
                self.intents
                    .get(intent_id)
                    .map(|intent| (intent.intent_id.clone(), intent.public_record()))
            })
            .collect::<Vec<_>>();
        for (intent_id, record) in updates {
            self.publish_public_record("encrypted_oracle_update_intent", &intent_id, record);
        }
    }

    fn refresh_quote_records(&mut self, quote_ids: &[String]) {
        let updates = quote_ids
            .iter()
            .filter_map(|quote_id| {
                self.solver_quotes
                    .get(quote_id)
                    .map(|quote| (quote.quote_id.clone(), quote.public_record()))
            })
            .collect::<Vec<_>>();
        for (quote_id, record) in updates {
            self.publish_public_record("solver_quote", &quote_id, record);
        }
    }

    fn refresh_attestation_records(&mut self, attestation_ids: &[String]) {
        let updates = attestation_ids
            .iter()
            .filter_map(|attestation_id| {
                self.attestations.get(attestation_id).map(|attestation| {
                    (
                        attestation.attestation_id.clone(),
                        attestation.public_record(),
                    )
                })
            })
            .collect::<Vec<_>>();
        for (attestation_id, record) in updates {
            self.publish_public_record("pq_oracle_committee_attestation", &attestation_id, record);
        }
    }

    fn refresh_reservation_records(&mut self, reservation_ids: &[String]) {
        let updates = reservation_ids
            .iter()
            .filter_map(|reservation_id| {
                self.sponsor_reservations
                    .get(reservation_id)
                    .map(|reservation| {
                        (
                            reservation.reservation_id.clone(),
                            reservation.public_record(),
                        )
                    })
            })
            .collect::<Vec<_>>();
        for (reservation_id, record) in updates {
            self.publish_public_record("fee_sponsor_reservation", &reservation_id, record);
        }
    }

    fn refresh_batch_records(&mut self, batch_ids: &[String]) {
        let updates = batch_ids
            .iter()
            .filter_map(|batch_id| {
                self.update_batches
                    .get(batch_id)
                    .map(|batch| (batch.batch_id.clone(), batch.public_record()))
            })
            .collect::<Vec<_>>();
        for (batch_id, record) in updates {
            self.publish_public_record("low_fee_update_batch", &batch_id, record);
        }
    }
}

pub fn private_l2_low_fee_oracle_update_market_payload_root(
    domain: &str,
    payload: &Value,
) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn private_l2_low_fee_oracle_update_market_state_root_from_record(record: &Value) -> String {
    private_l2_low_fee_oracle_update_market_payload_root(
        "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-STATE",
        record,
    )
}

pub fn private_l2_low_fee_oracle_update_market_state_root(state: &State) -> String {
    state.state_root()
}

pub fn private_l2_low_fee_oracle_update_market_merkle_root(
    domain: &str,
    leaves: Vec<Value>,
) -> String {
    merkle_root(domain, &leaves)
}

pub fn encrypted_oracle_update_intent_id(
    request: &SubmitEncryptedOracleUpdateIntentRequest,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(request.update_kind.as_str()),
            HashPart::Str(&request.feed_id),
            HashPart::Str(&request.requester_commitment),
            HashPart::Str(&request.encrypted_intent_root),
            HashPart::Str(&request.update_commitment_root),
            HashPart::Str(&request.nullifier_root),
        ],
        32,
    )
}

pub fn solver_quote_id(request: &PostSolverQuoteRequest, score: u128, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-SOLVER-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.solver_commitment),
            HashPart::Str(&id_list_root("SOLVER-QUOTE-INTENT-ID", &request.intent_ids)),
            HashPart::Str(&request.route_commitment_root),
            HashPart::Str(&request.execution_plan_root),
            HashPart::Int(score as i128),
        ],
        32,
    )
}

pub fn pq_oracle_committee_attestation_id(
    request: &PostPqOracleCommitteeAttestationRequest,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-PQ-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.committee_id),
            HashPart::Str(&request.attestation_payload_root),
            HashPart::Str(&request.pq_signature_root),
            HashPart::Int(request.signer_weight as i128),
            HashPart::Int(request.total_weight as i128),
        ],
        32,
    )
}

pub fn fee_sponsor_reservation_id(
    request: &ReserveFeeSponsorRequest,
    nonce: u64,
    remaining_budget_micro_units: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&id_list_root(
                "SPONSOR-RESERVATION-INTENT-ID",
                &request.intent_ids,
            )),
            HashPart::Str(&request.rebate_commitment_root),
            HashPart::Int(request.total_reserved_micro_units() as i128),
            HashPart::Int(remaining_budget_micro_units as i128),
        ],
        32,
    )
}

pub fn low_fee_update_batch_id(request: &OpenLowFeeUpdateBatchRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.intent_root()),
            HashPart::Str(&request.reservation_root()),
            HashPart::Str(&request.encrypted_update_root),
            HashPart::Str(&request.update_result_commitment_root),
            HashPart::Str(&request.state_root_before),
        ],
        32,
    )
}

pub fn oracle_update_receipt_id(request: &PublishOracleUpdateReceiptRequest, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(nonce as i128),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&id_list_root(
                "RECEIPT-ATTESTATION-ID",
                &request.attestation_ids,
            )),
            HashPart::Str(&id_list_root(
                "RECEIPT-RESERVATION-ID",
                &request.reservation_ids,
            )),
            HashPart::Str(&request.settlement_tx_root),
            HashPart::Str(&request.receipt_payload_root),
            HashPart::Str(&request.runtime_state_root_after),
            HashPart::Int(request.settled_at_height as i128),
        ],
        32,
    )
}

fn solver_quote_score(request: &PostSolverQuoteRequest) -> u128 {
    let rebate_bonus = request.expected_rebate_micro_units as u128;
    let coverage_bonus = request.intent_ids.len() as u128 * 10_000_000;
    let sponsor_bonus = request.sponsored_fee_micro_units as u128;
    let fee_penalty = request.solver_fee_bps as u128 * 1_000_000;
    rebate_bonus
        .saturating_add(coverage_bonus)
        .saturating_add(sponsor_bonus)
        .saturating_sub(fee_penalty)
}

fn id_list_root(label: &str, ids: &[String]) -> String {
    private_l2_low_fee_oracle_update_market_merkle_root(
        &format!("PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-{label}"),
        ids.iter().map(|id| json!(id)).collect(),
    )
}

fn covers_all_ids(covering_ids: &[String], requested_ids: &[String]) -> bool {
    let covering = covering_ids.iter().collect::<BTreeSet<_>>();
    requested_ids.iter().all(|id| covering.contains(id))
}

fn covers_all_reservations(
    reservations: &BTreeMap<String, FeeSponsorReservationRecord>,
    reservation_ids: &[String],
    intent_ids: &[String],
) -> bool {
    let covered_intents = reservation_ids
        .iter()
        .filter_map(|reservation_id| reservations.get(reservation_id))
        .filter(|reservation| reservation.status == SponsorReservationStatus::Reserved)
        .flat_map(|reservation| reservation.request.intent_ids.iter())
        .collect::<BTreeSet<_>>();
    intent_ids
        .iter()
        .all(|intent_id| covered_intents.contains(intent_id))
}

fn covers_all_attestations(
    attestations: &BTreeMap<String, PqOracleCommitteeAttestationRecord>,
    attestation_ids: &[String],
    batch_id: &str,
) -> bool {
    attestation_ids.iter().all(|attestation_id| {
        attestations
            .get(attestation_id)
            .map(|attestation| {
                attestation.status == AttestationStatus::QuorumMet
                    && attestation.request.batch_id == batch_id
            })
            .unwrap_or(false)
    })
}

fn public_record_id(record_kind: &str, subject_id: &str, payload: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn roots_only_payload(record_kind: &str, subject_id: &str, payload: &Value) -> Value {
    json!({
        "kind": "private_l2_low_fee_oracle_update_market_roots_only_payload",
        "chain_id": CHAIN_ID,
        "record_kind": record_kind,
        "subject_id": subject_id,
        "payload_root": private_l2_low_fee_oracle_update_market_payload_root(
            "PRIVATE-L2-LOW-FEE-ORACLE-UPDATE-MARKET-ROOTS-ONLY-PAYLOAD",
            payload,
        ),
    })
}

fn commitment_id(domain: &str, label: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn quorum_bps(weight: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    weight.saturating_mul(PRIVATE_L2_LOW_FEE_ORACLE_UPDATE_MARKET_RUNTIME_MAX_BPS) / total
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2LowFeeOracleUpdateMarketRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_root(label: &str, value: &str) -> PrivateL2LowFeeOracleUpdateMarketRuntimeResult<()> {
    require_non_empty(label, value)?;
    if value.len() < 32 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} must be a hex commitment/root of at least 32 chars"
        ));
    }
    Ok(())
}

fn ensure_unique(
    values: &[String],
    label: &str,
) -> PrivateL2LowFeeOracleUpdateMarketRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(label, value)?;
        if !seen.insert(value) {
            return Err(format!("duplicate {label}: {value}"));
        }
    }
    Ok(())
}

fn ensure_eq(
    actual: &str,
    expected: &str,
    label: &str,
) -> PrivateL2LowFeeOracleUpdateMarketRuntimeResult<()> {
    if actual != expected {
        return Err(format!(
            "{label} mismatch: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}
