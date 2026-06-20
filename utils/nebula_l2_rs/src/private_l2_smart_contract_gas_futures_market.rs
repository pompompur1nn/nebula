use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2SmartContractGasFuturesMarketResult<T> = Result<T, String>;

pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_PROTOCOL_VERSION: &str =
    "nebula-private-l2-smart-contract-gas-futures-market-v1";
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s";
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_LOCK_SCHEME: &str =
    "zk-private-contract-fee-lock-v1";
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_ORDER_SCHEME: &str =
    "sealed-private-contract-gas-future-order-v1";
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_MATCH_PROOF_SCHEME: &str =
    "zk-matched-contract-gas-hedge-batch-v1";
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_SPONSOR_SETTLEMENT_SCHEME: &str =
    "low-fee-private-contract-gas-sponsor-settlement-v1";
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_RECEIPT_SCHEME: &str =
    "contract-call-batch-bound-gas-hedge-receipt-v1";
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEVNET_HEIGHT: u64 = 188_000;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_FEE_ASSET_ID: &str = "asset:wxmr";
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_EPOCH_BLOCKS: u64 = 48;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_ORDER_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_LOCK_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_SETTLEMENT_DELAY_BLOCKS: u64 = 2;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 48;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_MAX_ORDERS_PER_BATCH: usize = 512;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_MAX_CALL_BATCH_BINDINGS: usize =
    1024;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_MIN_PRIVACY_SET: u64 = 4_096;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_MAX_USER_FEE_MICRO_UNITS: u64 =
    1_800;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_TARGET_SPONSOR_DISCOUNT_BPS: u64 =
    7_500;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_MIN_SPONSOR_COVERAGE_BPS: u64 =
    11_000;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractGasLane {
    ConfidentialCall,
    PrivateDefiHook,
    TokenMintBurn,
    OracleCallback,
    RecursiveProof,
    WalletSession,
    EmergencyEscape,
}

impl ContractGasLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialCall => "confidential_call",
            Self::PrivateDefiHook => "private_defi_hook",
            Self::TokenMintBurn => "token_mint_burn",
            Self::OracleCallback => "oracle_callback",
            Self::RecursiveProof => "recursive_proof",
            Self::WalletSession => "wallet_session",
            Self::EmergencyEscape => "emergency_escape",
        }
    }

    pub fn default_fee_cap_micro_units(self) -> u64 {
        match self {
            Self::EmergencyEscape => 2_500,
            Self::RecursiveProof => 2_100,
            Self::PrivateDefiHook => 1_700,
            Self::ConfidentialCall => 1_500,
            Self::OracleCallback => 1_250,
            Self::TokenMintBurn => 1_100,
            Self::WalletSession => 900,
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::ConfidentialCall => 8_800,
            Self::PrivateDefiHook => 8_200,
            Self::OracleCallback => 7_400,
            Self::TokenMintBurn => 6_800,
            Self::RecursiveProof => 6_200,
            Self::WalletSession => 5_500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuturesSide {
    FeePayerLong,
    SponsorShort,
    MakerNeutral,
}

impl FuturesSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeePayerLong => "fee_payer_long",
            Self::SponsorShort => "sponsor_short",
            Self::MakerNeutral => "maker_neutral",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeLockStatus {
    Open,
    Matched,
    Settled,
    Expired,
    Cancelled,
    Challenged,
}

impl FeeLockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Matched => "matched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Challenged => "challenged",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Matched | Self::Challenged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuturesOrderStatus {
    Posted,
    Matched,
    Settled,
    Expired,
    Cancelled,
    Slashed,
}

impl FuturesOrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Matched => "matched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }

    pub fn matchable(self) -> bool {
        matches!(self, Self::Posted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgeBatchStatus {
    Open,
    Matched,
    SponsorReserved,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl HedgeBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Matched => "matched",
            Self::SponsorReserved => "sponsor_reserved",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady | Self::SponsorReserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorSettlementStatus {
    Reserved,
    Accepted,
    Finalized,
    Rejected,
    Slashed,
}

impl SponsorSettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Accepted => "accepted",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Draft,
    Published,
    BoundToContractBatch,
    Finalized,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::BoundToContractBatch => "bound_to_contract_batch",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub lock_scheme: String,
    pub order_scheme: String,
    pub match_proof_scheme: String,
    pub sponsor_settlement_scheme: String,
    pub receipt_scheme: String,
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub order_ttl_blocks: u64,
    pub lock_ttl_blocks: u64,
    pub settlement_delay_blocks: u64,
    pub challenge_window_blocks: u64,
    pub max_orders_per_batch: usize,
    pub max_call_batch_bindings: usize,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_micro_units: u64,
    pub target_sponsor_discount_bps: u64,
    pub min_sponsor_coverage_bps: u64,
    pub privacy_policy_root: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_SCHEMA_VERSION,
            hash_suite: PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_PQ_AUTH_SUITE.to_string(),
            lock_scheme: PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_LOCK_SCHEME.to_string(),
            order_scheme: PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_ORDER_SCHEME.to_string(),
            match_proof_scheme: PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_MATCH_PROOF_SCHEME
                .to_string(),
            sponsor_settlement_scheme:
                PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_SPONSOR_SETTLEMENT_SCHEME.to_string(),
            receipt_scheme: PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_RECEIPT_SCHEME.to_string(),
            fee_asset_id: PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_FEE_ASSET_ID
                .to_string(),
            epoch_blocks: PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_EPOCH_BLOCKS,
            order_ttl_blocks: PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_ORDER_TTL_BLOCKS,
            lock_ttl_blocks: PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_LOCK_TTL_BLOCKS,
            settlement_delay_blocks:
                PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_SETTLEMENT_DELAY_BLOCKS,
            challenge_window_blocks:
                PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            max_orders_per_batch:
                PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_MAX_ORDERS_PER_BATCH,
            max_call_batch_bindings:
                PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_MAX_CALL_BATCH_BINDINGS,
            min_privacy_set: PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_micro_units:
                PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_MAX_USER_FEE_MICRO_UNITS,
            target_sponsor_discount_bps:
                PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_TARGET_SPONSOR_DISCOUNT_BPS,
            min_sponsor_coverage_bps:
                PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEFAULT_MIN_SPONSOR_COVERAGE_BPS,
            privacy_policy_root: string_root(
                "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-PRIVACY-POLICY",
                "sealed-orders-roots-only-batch-receipts-contract-call-binding",
            ),
        }
    }

    pub fn validate(&self) -> PrivateL2SmartContractGasFuturesMarketResult<String> {
        ensure_non_empty(&self.protocol_version, "protocol version")?;
        ensure_non_empty(&self.hash_suite, "hash suite")?;
        ensure_non_empty(&self.pq_auth_suite, "pq auth suite")?;
        ensure_non_empty(&self.lock_scheme, "lock scheme")?;
        ensure_non_empty(&self.order_scheme, "order scheme")?;
        ensure_non_empty(&self.match_proof_scheme, "match proof scheme")?;
        ensure_non_empty(&self.sponsor_settlement_scheme, "sponsor settlement scheme")?;
        ensure_non_empty(&self.receipt_scheme, "receipt scheme")?;
        ensure_non_empty(&self.fee_asset_id, "fee asset id")?;
        ensure_non_empty(&self.privacy_policy_root, "privacy policy root")?;
        if self.schema_version == 0
            || self.epoch_blocks == 0
            || self.order_ttl_blocks == 0
            || self.lock_ttl_blocks == 0
            || self.challenge_window_blocks == 0
        {
            return Err("smart contract gas futures timing values must be positive".to_string());
        }
        if self.max_orders_per_batch == 0 || self.max_call_batch_bindings == 0 {
            return Err("smart contract gas futures capacities must be positive".to_string());
        }
        if self.min_privacy_set == 0 || self.min_pq_security_bits < 128 {
            return Err("smart contract gas futures privacy and pq floors are too low".to_string());
        }
        if self.max_user_fee_micro_units == 0 {
            return Err("smart contract gas futures fee cap must be positive".to_string());
        }
        if self.target_sponsor_discount_bps > PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_MAX_BPS {
            return Err("smart contract gas futures sponsor discount exceeds bps cap".to_string());
        }
        if self.min_sponsor_coverage_bps < PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_MAX_BPS {
            return Err(
                "smart contract gas futures sponsor coverage must be overcollateralized"
                    .to_string(),
            );
        }
        Ok(self.root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "lock_scheme": self.lock_scheme,
            "order_scheme": self.order_scheme,
            "match_proof_scheme": self.match_proof_scheme,
            "sponsor_settlement_scheme": self.sponsor_settlement_scheme,
            "receipt_scheme": self.receipt_scheme,
            "fee_asset_id": self.fee_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "order_ttl_blocks": self.order_ttl_blocks,
            "lock_ttl_blocks": self.lock_ttl_blocks,
            "settlement_delay_blocks": self.settlement_delay_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "max_orders_per_batch": self.max_orders_per_batch,
            "max_call_batch_bindings": self.max_call_batch_bindings,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_micro_units": self.max_user_fee_micro_units,
            "target_sponsor_discount_bps": self.target_sponsor_discount_bps,
            "min_sponsor_coverage_bps": self.min_sponsor_coverage_bps,
            "privacy_policy_root": self.privacy_policy_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub fee_locks_opened: u64,
    pub futures_orders_posted: u64,
    pub hedge_batches_matched: u64,
    pub sponsor_settlements_opened: u64,
    pub receipts_published: u64,
    pub contract_batch_bindings: u64,
    pub active_locks: u64,
    pub active_orders: u64,
    pub active_batches: u64,
    pub total_locked_gas_units: u64,
    pub total_sponsored_fee_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_locks_opened": self.fee_locks_opened,
            "futures_orders_posted": self.futures_orders_posted,
            "hedge_batches_matched": self.hedge_batches_matched,
            "sponsor_settlements_opened": self.sponsor_settlements_opened,
            "receipts_published": self.receipts_published,
            "contract_batch_bindings": self.contract_batch_bindings,
            "active_locks": self.active_locks,
            "active_orders": self.active_orders,
            "active_batches": self.active_batches,
            "total_locked_gas_units": self.total_locked_gas_units,
            "total_sponsored_fee_units": self.total_sponsored_fee_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAuthorization {
    pub authorizer_commitment: String,
    pub pq_public_key_root: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqAuthorization {
    pub fn validate(
        &self,
        config: &Config,
        current_height: u64,
    ) -> PrivateL2SmartContractGasFuturesMarketResult<()> {
        ensure_non_empty(&self.authorizer_commitment, "authorizer commitment")?;
        ensure_non_empty(&self.pq_public_key_root, "pq public key root")?;
        ensure_non_empty(&self.signature_root, "signature root")?;
        ensure_non_empty(&self.transcript_root, "transcript root")?;
        if self.security_bits < config.min_pq_security_bits {
            return Err("pq authorization security bits below configured floor".to_string());
        }
        if self.expires_at_height <= self.issued_at_height
            || self.expires_at_height < current_height
        {
            return Err("pq authorization is expired or malformed".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "authorizer_commitment": self.authorizer_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "security_bits": self.security_bits,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-PQ-AUTHORIZATION",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeeLock {
    pub lock_id: String,
    pub owner_commitment: String,
    pub contract_id: String,
    pub contract_call_batch_root: Option<String>,
    pub lane: ContractGasLane,
    pub fee_asset_id: String,
    pub max_fee_micro_units: u64,
    pub locked_gas_units: u64,
    pub fee_cap_root: String,
    pub nullifier_root: String,
    pub encrypted_terms_root: String,
    pub pq_authorization_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: FeeLockStatus,
}

impl PrivateFeeLock {
    pub fn public_record(&self) -> Value {
        json!({
            "lock_id": self.lock_id,
            "owner_commitment": self.owner_commitment,
            "contract_id": self.contract_id,
            "contract_call_batch_root": self.contract_call_batch_root,
            "lane": self.lane.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "locked_gas_units": self.locked_gas_units,
            "fee_cap_root": self.fee_cap_root,
            "nullifier_root": self.nullifier_root,
            "encrypted_terms_root": self.encrypted_terms_root,
            "pq_authorization_root": self.pq_authorization_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-FEE-LOCK",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuturesOrder {
    pub order_id: String,
    pub trader_commitment: String,
    pub side: FuturesSide,
    pub lane: ContractGasLane,
    pub fee_asset_id: String,
    pub notional_gas_units: u64,
    pub limit_fee_micro_units: u64,
    pub margin_root: String,
    pub sealed_order_root: String,
    pub pq_authorization_root: String,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
    pub status: FuturesOrderStatus,
}

impl FuturesOrder {
    pub fn public_record(&self) -> Value {
        json!({
            "order_id": self.order_id,
            "trader_commitment": self.trader_commitment,
            "side": self.side.as_str(),
            "lane": self.lane.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "notional_gas_units": self.notional_gas_units,
            "limit_fee_micro_units": self.limit_fee_micro_units,
            "margin_root": self.margin_root,
            "sealed_order_root": self.sealed_order_root,
            "pq_authorization_root": self.pq_authorization_root,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-ORDER",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchedHedgeBatch {
    pub batch_id: String,
    pub lane: ContractGasLane,
    pub fee_lock_ids: Vec<String>,
    pub order_ids: Vec<String>,
    pub fee_lock_root: String,
    pub order_root: String,
    pub matched_notional_gas_units: u64,
    pub clearing_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub match_proof_root: String,
    pub aggregate_pq_authorization_root: String,
    pub matched_at_height: u64,
    pub settlement_ready_at_height: u64,
    pub status: HedgeBatchStatus,
}

impl MatchedHedgeBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane": self.lane.as_str(),
            "fee_lock_ids": self.fee_lock_ids,
            "order_ids": self.order_ids,
            "fee_lock_root": self.fee_lock_root,
            "order_root": self.order_root,
            "matched_notional_gas_units": self.matched_notional_gas_units,
            "clearing_fee_micro_units": self.clearing_fee_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "match_proof_root": self.match_proof_root,
            "aggregate_pq_authorization_root": self.aggregate_pq_authorization_root,
            "matched_at_height": self.matched_at_height,
            "settlement_ready_at_height": self.settlement_ready_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-MATCHED-HEDGE-BATCH",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorSettlement {
    pub settlement_id: String,
    pub batch_id: String,
    pub sponsor_commitment: String,
    pub sponsor_vault_root: String,
    pub reserve_proof_root: String,
    pub payout_root: String,
    pub sponsored_fee_units: u64,
    pub discount_bps: u64,
    pub coverage_bps: u64,
    pub pq_authorization_root: String,
    pub opened_at_height: u64,
    pub finalized_at_height: Option<u64>,
    pub status: SponsorSettlementStatus,
}

impl SponsorSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "batch_id": self.batch_id,
            "sponsor_commitment": self.sponsor_commitment,
            "sponsor_vault_root": self.sponsor_vault_root,
            "reserve_proof_root": self.reserve_proof_root,
            "payout_root": self.payout_root,
            "sponsored_fee_units": self.sponsored_fee_units,
            "discount_bps": self.discount_bps,
            "coverage_bps": self.coverage_bps,
            "pq_authorization_root": self.pq_authorization_root,
            "opened_at_height": self.opened_at_height,
            "finalized_at_height": self.finalized_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-SPONSOR-SETTLEMENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HedgeReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub settlement_id: String,
    pub contract_call_batch_root: Option<String>,
    pub contract_receipt_root: Option<String>,
    pub fee_lock_root: String,
    pub order_root: String,
    pub sponsor_settlement_root: String,
    pub realized_fee_micro_units: u64,
    pub saved_fee_micro_units: u64,
    pub receipt_proof_root: String,
    pub published_at_height: u64,
    pub finalized_at_height: Option<u64>,
    pub status: ReceiptStatus,
}

impl HedgeReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "settlement_id": self.settlement_id,
            "contract_call_batch_root": self.contract_call_batch_root,
            "contract_receipt_root": self.contract_receipt_root,
            "fee_lock_root": self.fee_lock_root,
            "order_root": self.order_root,
            "sponsor_settlement_root": self.sponsor_settlement_root,
            "realized_fee_micro_units": self.realized_fee_micro_units,
            "saved_fee_micro_units": self.saved_fee_micro_units,
            "receipt_proof_root": self.receipt_proof_root,
            "published_at_height": self.published_at_height,
            "finalized_at_height": self.finalized_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-HEDGE-RECEIPT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub fee_lock_root: String,
    pub open_fee_lock_root: String,
    pub futures_order_root: String,
    pub matched_batch_root: String,
    pub sponsor_settlement_root: String,
    pub receipt_root: String,
    pub contract_call_binding_root: String,
    pub pq_authorization_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "fee_lock_root": self.fee_lock_root,
            "open_fee_lock_root": self.open_fee_lock_root,
            "futures_order_root": self.futures_order_root,
            "matched_batch_root": self.matched_batch_root,
            "sponsor_settlement_root": self.sponsor_settlement_root,
            "receipt_root": self.receipt_root,
            "contract_call_binding_root": self.contract_call_binding_root,
            "pq_authorization_root": self.pq_authorization_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub fee_locks: BTreeMap<String, PrivateFeeLock>,
    pub futures_orders: BTreeMap<String, FuturesOrder>,
    pub matched_batches: BTreeMap<String, MatchedHedgeBatch>,
    pub sponsor_settlements: BTreeMap<String, SponsorSettlement>,
    pub receipts: BTreeMap<String, HedgeReceipt>,
    pub pq_authorizations: BTreeMap<String, PqAuthorization>,
    pub spent_nullifier_roots: BTreeSet<String>,
    pub contract_call_batch_roots: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            current_height: PRIVATE_L2_SMART_CONTRACT_GAS_FUTURES_MARKET_DEVNET_HEIGHT,
            fee_locks: BTreeMap::new(),
            futures_orders: BTreeMap::new(),
            matched_batches: BTreeMap::new(),
            sponsor_settlements: BTreeMap::new(),
            receipts: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            spent_nullifier_roots: BTreeSet::new(),
            contract_call_batch_roots: BTreeSet::new(),
        }
    }

    pub fn register_pq_authorization(
        &mut self,
        authorization: PqAuthorization,
    ) -> PrivateL2SmartContractGasFuturesMarketResult<String> {
        self.config.validate()?;
        authorization.validate(&self.config, self.current_height)?;
        let root = authorization.root();
        self.pq_authorizations.insert(root.clone(), authorization);
        Ok(root)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_fee_lock(
        &mut self,
        owner_commitment: impl Into<String>,
        contract_id: impl Into<String>,
        contract_call_batch_root: Option<String>,
        lane: ContractGasLane,
        max_fee_micro_units: u64,
        locked_gas_units: u64,
        fee_cap_root: impl Into<String>,
        nullifier_root: impl Into<String>,
        encrypted_terms_root: impl Into<String>,
        pq_authorization_root: impl Into<String>,
    ) -> PrivateL2SmartContractGasFuturesMarketResult<PrivateFeeLock> {
        self.config.validate()?;
        if max_fee_micro_units == 0 || max_fee_micro_units > self.config.max_user_fee_micro_units {
            return Err("private fee lock exceeds configured low-fee cap".to_string());
        }
        if max_fee_micro_units > lane.default_fee_cap_micro_units() || locked_gas_units == 0 {
            return Err("private fee lock lane cap or gas amount is invalid".to_string());
        }

        let owner_commitment = owner_commitment.into();
        let contract_id = contract_id.into();
        let fee_cap_root = fee_cap_root.into();
        let nullifier_root = nullifier_root.into();
        let encrypted_terms_root = encrypted_terms_root.into();
        let pq_authorization_root = pq_authorization_root.into();
        ensure_non_empty(&owner_commitment, "owner commitment")?;
        ensure_non_empty(&contract_id, "contract id")?;
        ensure_non_empty(&fee_cap_root, "fee cap root")?;
        ensure_non_empty(&nullifier_root, "nullifier root")?;
        ensure_non_empty(&encrypted_terms_root, "encrypted terms root")?;
        self.ensure_pq_authorization(&pq_authorization_root)?;
        if self.spent_nullifier_roots.contains(&nullifier_root)
            || self
                .fee_locks
                .values()
                .any(|lock| lock.nullifier_root == nullifier_root && lock.status.live())
        {
            return Err("private fee lock nullifier is already pending or spent".to_string());
        }
        if let Some(root) = &contract_call_batch_root {
            ensure_non_empty(root, "contract call batch root")?;
            self.contract_call_batch_roots.insert(root.clone());
        }

        let nonce = self.counters.fee_locks_opened;
        let lock_id = fee_lock_id(
            &owner_commitment,
            &contract_id,
            lane,
            &nullifier_root,
            self.current_height,
            nonce,
        );
        let lock = PrivateFeeLock {
            lock_id: lock_id.clone(),
            owner_commitment,
            contract_id,
            contract_call_batch_root,
            lane,
            fee_asset_id: self.config.fee_asset_id.clone(),
            max_fee_micro_units,
            locked_gas_units,
            fee_cap_root,
            nullifier_root,
            encrypted_terms_root,
            pq_authorization_root,
            opened_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.lock_ttl_blocks,
            status: FeeLockStatus::Open,
        };
        self.counters.fee_locks_opened += 1;
        self.counters.active_locks += 1;
        self.counters.total_locked_gas_units = self
            .counters
            .total_locked_gas_units
            .saturating_add(locked_gas_units);
        self.fee_locks.insert(lock_id, lock.clone());
        Ok(lock)
    }

    pub fn post_futures_order(
        &mut self,
        request: PostFuturesOrderRequest,
    ) -> PrivateL2SmartContractGasFuturesMarketResult<FuturesOrder> {
        self.config.validate()?;
        request.validate(&self.config)?;
        self.ensure_pq_authorization(&request.pq_authorization_root)?;
        let nonce = self.counters.futures_orders_posted;
        let order_id = futures_order_id(
            &request.trader_commitment,
            request.side,
            request.lane,
            &request.sealed_order_root,
            self.current_height,
            nonce,
        );
        let order = FuturesOrder {
            order_id: order_id.clone(),
            trader_commitment: request.trader_commitment,
            side: request.side,
            lane: request.lane,
            fee_asset_id: self.config.fee_asset_id.clone(),
            notional_gas_units: request.notional_gas_units,
            limit_fee_micro_units: request.limit_fee_micro_units,
            margin_root: request.margin_root,
            sealed_order_root: request.sealed_order_root,
            pq_authorization_root: request.pq_authorization_root,
            posted_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.order_ttl_blocks,
            status: FuturesOrderStatus::Posted,
        };
        self.counters.futures_orders_posted += 1;
        self.counters.active_orders += 1;
        self.futures_orders.insert(order_id, order.clone());
        Ok(order)
    }

    pub fn match_hedge_batch(
        &mut self,
        lane: ContractGasLane,
        fee_lock_ids: Vec<String>,
        order_ids: Vec<String>,
        clearing_fee_micro_units: u64,
        privacy_set_size: u64,
        match_proof_root: impl Into<String>,
        aggregate_pq_authorization_root: impl Into<String>,
    ) -> PrivateL2SmartContractGasFuturesMarketResult<MatchedHedgeBatch> {
        self.config.validate()?;
        if fee_lock_ids.is_empty() || order_ids.is_empty() {
            return Err("matched hedge batch requires fee locks and futures orders".to_string());
        }
        if order_ids.len() > self.config.max_orders_per_batch {
            return Err("matched hedge batch exceeds order capacity".to_string());
        }
        if privacy_set_size < self.config.min_privacy_set {
            return Err("matched hedge batch privacy set below configured floor".to_string());
        }
        if clearing_fee_micro_units == 0
            || clearing_fee_micro_units > lane.default_fee_cap_micro_units()
        {
            return Err("matched hedge batch clearing fee is outside lane cap".to_string());
        }
        let match_proof_root = match_proof_root.into();
        let aggregate_pq_authorization_root = aggregate_pq_authorization_root.into();
        ensure_non_empty(&match_proof_root, "match proof root")?;
        ensure_non_empty(
            &aggregate_pq_authorization_root,
            "aggregate pq authorization root",
        )?;

        let mut matched_notional_gas_units = 0u64;
        for lock_id in &fee_lock_ids {
            let lock = self
                .fee_locks
                .get_mut(lock_id)
                .ok_or_else(|| format!("unknown fee lock: {lock_id}"))?;
            if lock.lane != lane || lock.status != FeeLockStatus::Open {
                return Err("fee lock is not open on requested lane".to_string());
            }
            lock.status = FeeLockStatus::Matched;
            matched_notional_gas_units =
                matched_notional_gas_units.saturating_add(lock.locked_gas_units);
        }
        for order_id in &order_ids {
            let order = self
                .futures_orders
                .get_mut(order_id)
                .ok_or_else(|| format!("unknown futures order: {order_id}"))?;
            if order.lane != lane || !order.status.matchable() {
                return Err("futures order is not matchable on requested lane".to_string());
            }
            order.status = FuturesOrderStatus::Matched;
        }

        let fee_lock_root = id_merkle_root(
            "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-LOCK-IDS",
            &fee_lock_ids,
        );
        let order_root = id_merkle_root(
            "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-ORDER-IDS",
            &order_ids,
        );
        let nonce = self.counters.hedge_batches_matched;
        let batch_id = hedge_batch_id(
            lane,
            &fee_lock_root,
            &order_root,
            &match_proof_root,
            self.current_height,
            nonce,
        );
        let batch = MatchedHedgeBatch {
            batch_id: batch_id.clone(),
            lane,
            fee_lock_ids,
            order_ids,
            fee_lock_root,
            order_root,
            matched_notional_gas_units,
            clearing_fee_micro_units,
            privacy_set_size,
            match_proof_root,
            aggregate_pq_authorization_root,
            matched_at_height: self.current_height,
            settlement_ready_at_height: self.current_height + self.config.settlement_delay_blocks,
            status: HedgeBatchStatus::Matched,
        };
        self.counters.hedge_batches_matched += 1;
        self.counters.active_batches += 1;
        self.matched_batches.insert(batch_id, batch.clone());
        Ok(batch)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn reserve_sponsor_settlement(
        &mut self,
        batch_id: impl Into<String>,
        sponsor_commitment: impl Into<String>,
        sponsor_vault_root: impl Into<String>,
        reserve_proof_root: impl Into<String>,
        payout_root: impl Into<String>,
        sponsored_fee_units: u64,
        discount_bps: u64,
        coverage_bps: u64,
        pq_authorization_root: impl Into<String>,
    ) -> PrivateL2SmartContractGasFuturesMarketResult<SponsorSettlement> {
        self.config.validate()?;
        let batch_id = batch_id.into();
        let sponsor_commitment = sponsor_commitment.into();
        let sponsor_vault_root = sponsor_vault_root.into();
        let reserve_proof_root = reserve_proof_root.into();
        let payout_root = payout_root.into();
        let pq_authorization_root = pq_authorization_root.into();
        ensure_non_empty(&batch_id, "batch id")?;
        ensure_non_empty(&sponsor_commitment, "sponsor commitment")?;
        ensure_non_empty(&sponsor_vault_root, "sponsor vault root")?;
        ensure_non_empty(&reserve_proof_root, "reserve proof root")?;
        ensure_non_empty(&payout_root, "payout root")?;
        self.ensure_pq_authorization(&pq_authorization_root)?;
        if sponsored_fee_units == 0 {
            return Err("sponsored fee units must be positive".to_string());
        }
        if discount_bps > self.config.target_sponsor_discount_bps {
            return Err("sponsor settlement discount exceeds low-fee target".to_string());
        }
        if coverage_bps < self.config.min_sponsor_coverage_bps {
            return Err("sponsor settlement coverage below configured floor".to_string());
        }
        let batch = self
            .matched_batches
            .get_mut(&batch_id)
            .ok_or_else(|| format!("unknown matched hedge batch: {batch_id}"))?;
        if !matches!(batch.status, HedgeBatchStatus::Matched) {
            return Err("matched hedge batch is not ready for sponsor reservation".to_string());
        }
        batch.status = HedgeBatchStatus::SponsorReserved;

        let nonce = self.counters.sponsor_settlements_opened;
        let settlement_id = sponsor_settlement_id(
            &batch_id,
            &sponsor_commitment,
            &sponsor_vault_root,
            self.current_height,
            nonce,
        );
        let settlement = SponsorSettlement {
            settlement_id: settlement_id.clone(),
            batch_id,
            sponsor_commitment,
            sponsor_vault_root,
            reserve_proof_root,
            payout_root,
            sponsored_fee_units,
            discount_bps,
            coverage_bps,
            pq_authorization_root,
            opened_at_height: self.current_height,
            finalized_at_height: None,
            status: SponsorSettlementStatus::Reserved,
        };
        self.counters.sponsor_settlements_opened += 1;
        self.counters.total_sponsored_fee_units = self
            .counters
            .total_sponsored_fee_units
            .saturating_add(sponsored_fee_units);
        self.sponsor_settlements
            .insert(settlement_id, settlement.clone());
        Ok(settlement)
    }

    pub fn publish_receipt(
        &mut self,
        batch_id: impl Into<String>,
        settlement_id: impl Into<String>,
        realized_fee_micro_units: u64,
        saved_fee_micro_units: u64,
        receipt_proof_root: impl Into<String>,
    ) -> PrivateL2SmartContractGasFuturesMarketResult<HedgeReceipt> {
        self.config.validate()?;
        let batch_id = batch_id.into();
        let settlement_id = settlement_id.into();
        let receipt_proof_root = receipt_proof_root.into();
        ensure_non_empty(&batch_id, "batch id")?;
        ensure_non_empty(&settlement_id, "settlement id")?;
        ensure_non_empty(&receipt_proof_root, "receipt proof root")?;
        if realized_fee_micro_units == 0 {
            return Err("receipt realized fee must be positive".to_string());
        }
        let batch = self
            .matched_batches
            .get_mut(&batch_id)
            .ok_or_else(|| format!("unknown matched hedge batch: {batch_id}"))?;
        if !batch.status.can_settle() {
            return Err("matched hedge batch cannot settle".to_string());
        }
        let settlement = self
            .sponsor_settlements
            .get_mut(&settlement_id)
            .ok_or_else(|| format!("unknown sponsor settlement: {settlement_id}"))?;
        if settlement.batch_id != batch_id {
            return Err("sponsor settlement is not bound to matched hedge batch".to_string());
        }
        settlement.status = SponsorSettlementStatus::Finalized;
        settlement.finalized_at_height = Some(self.current_height);
        batch.status = HedgeBatchStatus::Settled;

        for lock_id in &batch.fee_lock_ids {
            if let Some(lock) = self.fee_locks.get_mut(lock_id) {
                lock.status = FeeLockStatus::Settled;
                self.spent_nullifier_roots
                    .insert(lock.nullifier_root.clone());
            }
        }
        for order_id in &batch.order_ids {
            if let Some(order) = self.futures_orders.get_mut(order_id) {
                order.status = FuturesOrderStatus::Settled;
            }
        }

        let contract_call_batch_root = batch
            .fee_lock_ids
            .iter()
            .filter_map(|id| self.fee_locks.get(id))
            .find_map(|lock| lock.contract_call_batch_root.clone());
        let receipt_id = hedge_receipt_id(
            &batch_id,
            &settlement_id,
            &receipt_proof_root,
            self.current_height,
            self.counters.receipts_published,
        );
        let receipt = HedgeReceipt {
            receipt_id: receipt_id.clone(),
            batch_id,
            settlement_id,
            contract_call_batch_root,
            contract_receipt_root: None,
            fee_lock_root: batch.fee_lock_root.clone(),
            order_root: batch.order_root.clone(),
            sponsor_settlement_root: settlement.root(),
            realized_fee_micro_units,
            saved_fee_micro_units,
            receipt_proof_root,
            published_at_height: self.current_height,
            finalized_at_height: None,
            status: ReceiptStatus::Published,
        };
        self.counters.receipts_published += 1;
        self.counters.active_locks = self
            .counters
            .active_locks
            .saturating_sub(batch.fee_lock_ids.len() as u64);
        self.counters.active_orders = self
            .counters
            .active_orders
            .saturating_sub(batch.order_ids.len() as u64);
        self.counters.active_batches = self.counters.active_batches.saturating_sub(1);
        self.receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn bind_receipt_to_contract_call_batch(
        &mut self,
        receipt_id: impl Into<String>,
        contract_call_batch_root: impl Into<String>,
        contract_receipt_root: impl Into<String>,
    ) -> PrivateL2SmartContractGasFuturesMarketResult<String> {
        let receipt_id = receipt_id.into();
        let contract_call_batch_root = contract_call_batch_root.into();
        let contract_receipt_root = contract_receipt_root.into();
        ensure_non_empty(&receipt_id, "receipt id")?;
        ensure_non_empty(&contract_call_batch_root, "contract call batch root")?;
        ensure_non_empty(&contract_receipt_root, "contract receipt root")?;
        if self.contract_call_batch_roots.len() >= self.config.max_call_batch_bindings {
            return Err("contract call batch binding capacity reached".to_string());
        }
        let receipt = self
            .receipts
            .get_mut(&receipt_id)
            .ok_or_else(|| format!("unknown hedge receipt: {receipt_id}"))?;
        receipt.contract_call_batch_root = Some(contract_call_batch_root.clone());
        receipt.contract_receipt_root = Some(contract_receipt_root);
        receipt.status = ReceiptStatus::BoundToContractBatch;
        self.contract_call_batch_roots
            .insert(contract_call_batch_root);
        self.counters.contract_batch_bindings += 1;
        Ok(receipt.root())
    }

    pub fn roots(&self) -> Roots {
        let fee_lock_roots: Vec<String> =
            self.fee_locks.values().map(PrivateFeeLock::root).collect();
        let open_fee_lock_roots: Vec<String> = self
            .fee_locks
            .values()
            .filter(|lock| lock.status.live())
            .map(PrivateFeeLock::root)
            .collect();
        let order_roots: Vec<String> = self
            .futures_orders
            .values()
            .map(FuturesOrder::root)
            .collect();
        let batch_roots: Vec<String> = self
            .matched_batches
            .values()
            .map(MatchedHedgeBatch::root)
            .collect();
        let settlement_roots: Vec<String> = self
            .sponsor_settlements
            .values()
            .map(SponsorSettlement::root)
            .collect();
        let receipt_roots: Vec<String> = self.receipts.values().map(HedgeReceipt::root).collect();
        let contract_call_batch_roots: Vec<String> =
            self.contract_call_batch_roots.iter().cloned().collect();
        let pq_authorization_roots: Vec<String> = self.pq_authorizations.keys().cloned().collect();

        Roots {
            config_root: self.config.root(),
            fee_lock_root: id_merkle_root(
                "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-FEE-LOCKS",
                &fee_lock_roots,
            ),
            open_fee_lock_root: id_merkle_root(
                "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-OPEN-FEE-LOCKS",
                &open_fee_lock_roots,
            ),
            futures_order_root: id_merkle_root(
                "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-ORDERS",
                &order_roots,
            ),
            matched_batch_root: id_merkle_root(
                "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-MATCHED-BATCHES",
                &batch_roots,
            ),
            sponsor_settlement_root: id_merkle_root(
                "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-SPONSOR-SETTLEMENTS",
                &settlement_roots,
            ),
            receipt_root: id_merkle_root(
                "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-RECEIPTS",
                &receipt_roots,
            ),
            contract_call_binding_root: id_merkle_root(
                "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-CONTRACT-CALL-BINDINGS",
                &contract_call_batch_roots,
            ),
            pq_authorization_root: id_merkle_root(
                "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-PQ-AUTHORIZATIONS",
                &pq_authorization_roots,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        domain_hash(
            "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Json(&roots.public_record()),
                HashPart::Int(self.current_height as i128),
            ],
            32,
        )
    }

    fn ensure_pq_authorization(
        &self,
        pq_authorization_root: &str,
    ) -> PrivateL2SmartContractGasFuturesMarketResult<()> {
        ensure_non_empty(pq_authorization_root, "pq authorization root")?;
        if !self.pq_authorizations.contains_key(pq_authorization_root) {
            return Err("unknown pq authorization root".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostFuturesOrderRequest {
    pub trader_commitment: String,
    pub side: FuturesSide,
    pub lane: ContractGasLane,
    pub notional_gas_units: u64,
    pub limit_fee_micro_units: u64,
    pub margin_root: String,
    pub sealed_order_root: String,
    pub pq_authorization_root: String,
}

impl PostFuturesOrderRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2SmartContractGasFuturesMarketResult<()> {
        ensure_non_empty(&self.trader_commitment, "trader commitment")?;
        ensure_non_empty(&self.margin_root, "margin root")?;
        ensure_non_empty(&self.sealed_order_root, "sealed order root")?;
        ensure_non_empty(&self.pq_authorization_root, "pq authorization root")?;
        if self.notional_gas_units == 0 {
            return Err("futures order notional gas units must be positive".to_string());
        }
        if self.limit_fee_micro_units == 0
            || self.limit_fee_micro_units > config.max_user_fee_micro_units
            || self.limit_fee_micro_units > self.lane.default_fee_cap_micro_units()
        {
            return Err(
                "futures order fee limit is outside configured low-fee lane cap".to_string(),
            );
        }
        Ok(())
    }
}

pub fn string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn fee_lock_id(
    owner_commitment: &str,
    contract_id: &str,
    lane: ContractGasLane,
    nullifier_root: &str,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-FEE-LOCK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(contract_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(nullifier_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn futures_order_id(
    trader_commitment: &str,
    side: FuturesSide,
    lane: ContractGasLane,
    sealed_order_root: &str,
    posted_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-ORDER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(trader_commitment),
            HashPart::Str(side.as_str()),
            HashPart::Str(lane.as_str()),
            HashPart::Str(sealed_order_root),
            HashPart::Int(posted_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn hedge_batch_id(
    lane: ContractGasLane,
    fee_lock_root: &str,
    order_root: &str,
    match_proof_root: &str,
    matched_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-HEDGE-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(fee_lock_root),
            HashPart::Str(order_root),
            HashPart::Str(match_proof_root),
            HashPart::Int(matched_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn sponsor_settlement_id(
    batch_id: &str,
    sponsor_commitment: &str,
    sponsor_vault_root: &str,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-SPONSOR-SETTLEMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(sponsor_vault_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn hedge_receipt_id(
    batch_id: &str,
    settlement_id: &str,
    receipt_proof_root: &str,
    published_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-SMART-CONTRACT-GAS-FUTURES-HEDGE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id),
            HashPart::Str(settlement_id),
            HashPart::Str(receipt_proof_root),
            HashPart::Int(published_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

fn id_merkle_root(domain: &str, ids: &[String]) -> String {
    let leaves: Vec<Value> = ids.iter().map(|id| json!({ "id": id })).collect();
    merkle_root(domain, &leaves)
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateL2SmartContractGasFuturesMarketResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}
