use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2SmartContractGasEscrowRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-smart-contract-gas-escrow-runtime-v1";
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-contract-gas-escrow-v1";
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_ESCROW_SCHEME: &str =
    "private-l2-contract-gas-escrow-root-v1";
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_SPONSOR_SCHEME: &str =
    "roots-only-contract-gas-sponsor-credit-v1";
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_BATCH_SCHEME: &str =
    "private-l2-contract-gas-escrow-batch-root-v1";
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEVNET_HEIGHT: u64 = 336_000;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_MAX_ESCROWS: usize = 1_048_576;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_MAX_QUOTES: usize = 1_048_576;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize = 1_048_576;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_MAX_BATCHES: usize = 262_144;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize = 16_384;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 8_192;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 65_536;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 16;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_MAX_SPONSOR_COVER_BPS: u64 = 10_000;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_ESCROW_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 8;
pub const PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractGasLane {
    PrivateCall,
    DefiBatch,
    TokenTransfer,
    OracleUpdate,
    BridgeSettlement,
    GovernanceExecution,
    EmergencyRecovery,
}

impl ContractGasLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateCall => "private_call",
            Self::DefiBatch => "defi_batch",
            Self::TokenTransfer => "token_transfer",
            Self::OracleUpdate => "oracle_update",
            Self::BridgeSettlement => "bridge_settlement",
            Self::GovernanceExecution => "governance_execution",
            Self::EmergencyRecovery => "emergency_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowStatus {
    Open,
    Quoted,
    Reserved,
    Batched,
    Settled,
    Refunded,
    Expired,
    Rejected,
}

impl EscrowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Quoted => "quoted",
            Self::Reserved => "reserved",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Open | Self::Quoted | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Posted,
    Accepted,
    Replaced,
    Expired,
    Slashed,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Accepted => "accepted",
            Self::Replaced => "replaced",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
    Slashed,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Built,
    Sealed,
    Settled,
    Rejected,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::Sealed => "sealed",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Reorged,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub fee_asset_id: String,
    pub max_escrows: usize,
    pub max_quotes: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_batch_items: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_sponsor_cover_bps: u64,
    pub escrow_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_FEE_ASSET_ID
                .to_string(),
            max_escrows: PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_MAX_ESCROWS,
            max_quotes: PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_MAX_QUOTES,
            max_reservations: PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_MAX_BATCHES,
            max_batch_items: PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            min_privacy_set_size:
                PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_sponsor_cover_bps:
                PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_MAX_SPONSOR_COVER_BPS,
            escrow_ttl_blocks:
                PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_ESCROW_TTL_BLOCKS,
            quote_ttl_blocks: PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_smart_contract_gas_escrow_config",
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "max_escrows": self.max_escrows,
            "max_quotes": self.max_quotes,
            "max_reservations": self.max_reservations,
            "max_batches": self.max_batches,
            "max_batch_items": self.max_batch_items,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_sponsor_cover_bps": self.max_sponsor_cover_bps,
            "escrow_ttl_blocks": self.escrow_ttl_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-SMART-CONTRACT-GAS-ESCROW-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub escrows_opened: u64,
    pub quotes_posted: u64,
    pub reservations_opened: u64,
    pub batches_built: u64,
    pub receipts_published: u64,
    pub escrows_settled: u64,
    pub refunds_published: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_smart_contract_gas_escrow_counters",
            "escrows_opened": self.escrows_opened,
            "quotes_posted": self.quotes_posted,
            "reservations_opened": self.reservations_opened,
            "batches_built": self.batches_built,
            "receipts_published": self.receipts_published,
            "escrows_settled": self.escrows_settled,
            "refunds_published": self.refunds_published,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenGasEscrowRequest {
    pub lane: ContractGasLane,
    pub contract_call_commitment: String,
    pub caller_commitment: String,
    pub contract_id_root: String,
    pub calldata_commitment_root: String,
    pub max_gas_commitment_root: String,
    pub fee_asset_id: String,
    pub fee_note_root: String,
    pub refund_note_root: String,
    pub sponsor_hint_root: Option<String>,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl OpenGasEscrowRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "contract_call_commitment": self.contract_call_commitment,
            "caller_commitment": self.caller_commitment,
            "contract_id_root": self.contract_id_root,
            "calldata_commitment_root": self.calldata_commitment_root,
            "max_gas_commitment_root": self.max_gas_commitment_root,
            "fee_asset_id": self.fee_asset_id,
            "fee_note_root": self.fee_note_root,
            "refund_note_root": self.refund_note_root,
            "sponsor_hint_root": self.sponsor_hint_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuoteGasExecutionRequest {
    pub escrow_id: String,
    pub executor_commitment: String,
    pub execution_profile_root: String,
    pub quoted_gas_root: String,
    pub quoted_fee_bps: u64,
    pub latency_target_ms: u64,
    pub preconfirmation_root: String,
    pub pq_quote_root: String,
    pub quoted_at_height: u64,
    pub expires_at_height: u64,
}

impl QuoteGasExecutionRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "escrow_id": self.escrow_id,
            "executor_commitment": self.executor_commitment,
            "execution_profile_root": self.execution_profile_root,
            "quoted_gas_root": self.quoted_gas_root,
            "quoted_fee_bps": self.quoted_fee_bps,
            "latency_target_ms": self.latency_target_ms,
            "preconfirmation_root": self.preconfirmation_root,
            "pq_quote_root": self.pq_quote_root,
            "quoted_at_height": self.quoted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReserveSponsorCreditRequest {
    pub escrow_id: String,
    pub quote_id: String,
    pub sponsor_commitment: String,
    pub sponsor_budget_root: String,
    pub reserved_cover_bps: u64,
    pub rebate_note_root: String,
    pub pq_reservation_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveSponsorCreditRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "escrow_id": self.escrow_id,
            "quote_id": self.quote_id,
            "sponsor_commitment": self.sponsor_commitment,
            "sponsor_budget_root": self.sponsor_budget_root,
            "reserved_cover_bps": self.reserved_cover_bps,
            "rebate_note_root": self.rebate_note_root,
            "pq_reservation_root": self.pq_reservation_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildGasEscrowBatchRequest {
    pub operator_commitment: String,
    pub lane: ContractGasLane,
    pub escrow_ids: Vec<String>,
    pub quote_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub aggregate_call_root: String,
    pub aggregate_gas_root: String,
    pub aggregate_fee_note_root: String,
    pub aggregate_refund_note_root: String,
    pub aggregate_sponsor_root: String,
    pub recursive_proof_root: String,
    pub pq_batch_authorization_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub built_at_height: u64,
    pub expires_at_height: u64,
}

impl BuildGasEscrowBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "operator_commitment": self.operator_commitment,
            "lane": self.lane.as_str(),
            "escrow_ids": self.escrow_ids,
            "quote_ids": self.quote_ids,
            "reservation_ids": self.reservation_ids,
            "aggregate_call_root": self.aggregate_call_root,
            "aggregate_gas_root": self.aggregate_gas_root,
            "aggregate_fee_note_root": self.aggregate_fee_note_root,
            "aggregate_refund_note_root": self.aggregate_refund_note_root,
            "aggregate_sponsor_root": self.aggregate_sponsor_root,
            "recursive_proof_root": self.recursive_proof_root,
            "pq_batch_authorization_root": self.pq_batch_authorization_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "built_at_height": self.built_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettleGasEscrowBatchRequest {
    pub batch_id: String,
    pub execution_receipt_root: String,
    pub settlement_tx_root: String,
    pub gas_used_root: String,
    pub fee_paid_root: String,
    pub refund_root: String,
    pub sponsor_credit_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub pq_settlement_root: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl SettleGasEscrowBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "execution_receipt_root": self.execution_receipt_root,
            "settlement_tx_root": self.settlement_tx_root,
            "gas_used_root": self.gas_used_root,
            "fee_paid_root": self.fee_paid_root,
            "refund_root": self.refund_root,
            "sponsor_credit_root": self.sponsor_credit_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "pq_settlement_root": self.pq_settlement_root,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublishGasRefundRequest {
    pub escrow_id: String,
    pub receipt_id: String,
    pub refund_note_root: String,
    pub refund_proof_root: String,
    pub pq_refund_authorization_root: String,
    pub published_at_height: u64,
}

impl PublishGasRefundRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "escrow_id": self.escrow_id,
            "receipt_id": self.receipt_id,
            "refund_note_root": self.refund_note_root,
            "refund_proof_root": self.refund_proof_root,
            "pq_refund_authorization_root": self.pq_refund_authorization_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GasEscrowRecord {
    pub escrow_id: String,
    pub request: OpenGasEscrowRequest,
    pub status: EscrowStatus,
    pub quote_id: Option<String>,
    pub reservation_id: Option<String>,
    pub batch_id: Option<String>,
}

impl GasEscrowRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_smart_contract_gas_escrow",
            "escrow_id": self.escrow_id,
            "lane": self.request.lane.as_str(),
            "contract_call_commitment": self.request.contract_call_commitment,
            "caller_commitment": self.request.caller_commitment,
            "contract_id_root": self.request.contract_id_root,
            "calldata_commitment_root": self.request.calldata_commitment_root,
            "max_gas_commitment_root": self.request.max_gas_commitment_root,
            "fee_asset_id": self.request.fee_asset_id,
            "fee_note_root": self.request.fee_note_root,
            "refund_note_root": self.request.refund_note_root,
            "sponsor_hint_root": self.request.sponsor_hint_root,
            "pq_authorization_root": self.request.pq_authorization_root,
            "privacy_set_size": self.request.privacy_set_size,
            "pq_security_bits": self.request.pq_security_bits,
            "max_fee_bps": self.request.max_fee_bps,
            "status": self.status.as_str(),
            "quote_id": self.quote_id,
            "reservation_id": self.reservation_id,
            "batch_id": self.batch_id,
            "opened_at_height": self.request.opened_at_height,
            "expires_at_height": self.request.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GasQuoteRecord {
    pub quote_id: String,
    pub request: QuoteGasExecutionRequest,
    pub status: QuoteStatus,
}

impl GasQuoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_smart_contract_gas_quote",
            "quote_id": self.quote_id,
            "escrow_id": self.request.escrow_id,
            "executor_commitment": self.request.executor_commitment,
            "execution_profile_root": self.request.execution_profile_root,
            "quoted_gas_root": self.request.quoted_gas_root,
            "quoted_fee_bps": self.request.quoted_fee_bps,
            "latency_target_ms": self.request.latency_target_ms,
            "preconfirmation_root": self.request.preconfirmation_root,
            "pq_quote_root": self.request.pq_quote_root,
            "status": self.status.as_str(),
            "quoted_at_height": self.request.quoted_at_height,
            "expires_at_height": self.request.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorReservationRecord {
    pub reservation_id: String,
    pub request: ReserveSponsorCreditRequest,
    pub status: ReservationStatus,
}

impl SponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_smart_contract_gas_sponsor_reservation",
            "reservation_id": self.reservation_id,
            "escrow_id": self.request.escrow_id,
            "quote_id": self.request.quote_id,
            "sponsor_commitment": self.request.sponsor_commitment,
            "sponsor_budget_root": self.request.sponsor_budget_root,
            "reserved_cover_bps": self.request.reserved_cover_bps,
            "rebate_note_root": self.request.rebate_note_root,
            "pq_reservation_root": self.request.pq_reservation_root,
            "status": self.status.as_str(),
            "reserved_at_height": self.request.reserved_at_height,
            "expires_at_height": self.request.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GasEscrowBatchRecord {
    pub batch_id: String,
    pub request: BuildGasEscrowBatchRequest,
    pub status: BatchStatus,
    pub settlement_receipt_id: Option<String>,
}

impl GasEscrowBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_smart_contract_gas_escrow_batch",
            "batch_id": self.batch_id,
            "operator_commitment": self.request.operator_commitment,
            "lane": self.request.lane.as_str(),
            "escrow_ids": self.request.escrow_ids,
            "quote_ids": self.request.quote_ids,
            "reservation_ids": self.request.reservation_ids,
            "aggregate_call_root": self.request.aggregate_call_root,
            "aggregate_gas_root": self.request.aggregate_gas_root,
            "aggregate_fee_note_root": self.request.aggregate_fee_note_root,
            "aggregate_refund_note_root": self.request.aggregate_refund_note_root,
            "aggregate_sponsor_root": self.request.aggregate_sponsor_root,
            "recursive_proof_root": self.request.recursive_proof_root,
            "pq_batch_authorization_root": self.request.pq_batch_authorization_root,
            "max_fee_bps": self.request.max_fee_bps,
            "privacy_set_size": self.request.privacy_set_size,
            "status": self.status.as_str(),
            "settlement_receipt_id": self.settlement_receipt_id,
            "built_at_height": self.request.built_at_height,
            "expires_at_height": self.request.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GasEscrowSettlementReceipt {
    pub receipt_id: String,
    pub request: SettleGasEscrowBatchRequest,
    pub status: ReceiptStatus,
    pub settled_escrow_ids: Vec<String>,
}

impl GasEscrowSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_smart_contract_gas_escrow_settlement_receipt",
            "receipt_id": self.receipt_id,
            "batch_id": self.request.batch_id,
            "execution_receipt_root": self.request.execution_receipt_root,
            "settlement_tx_root": self.request.settlement_tx_root,
            "gas_used_root": self.request.gas_used_root,
            "fee_paid_root": self.request.fee_paid_root,
            "refund_root": self.request.refund_root,
            "sponsor_credit_root": self.request.sponsor_credit_root,
            "state_root_before": self.request.state_root_before,
            "state_root_after": self.request.state_root_after,
            "pq_settlement_root": self.request.pq_settlement_root,
            "settled_fee_bps": self.request.settled_fee_bps,
            "settled_escrow_ids": self.settled_escrow_ids,
            "status": self.status.as_str(),
            "settled_at_height": self.request.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GasRefundRecord {
    pub refund_id: String,
    pub request: PublishGasRefundRequest,
}

impl GasRefundRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_smart_contract_gas_refund",
            "refund_id": self.refund_id,
            "escrow_id": self.request.escrow_id,
            "receipt_id": self.request.receipt_id,
            "refund_note_root": self.request.refund_note_root,
            "refund_proof_root": self.request.refund_proof_root,
            "pq_refund_authorization_root": self.request.pq_refund_authorization_root,
            "published_at_height": self.request.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub escrow_root: String,
    pub quote_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub refund_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "escrow_root": self.escrow_root,
            "quote_root": self.quote_root,
            "reservation_root": self.reservation_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "refund_root": self.refund_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub escrows: BTreeMap<String, GasEscrowRecord>,
    pub quotes: BTreeMap<String, GasQuoteRecord>,
    pub reservations: BTreeMap<String, SponsorReservationRecord>,
    pub batches: BTreeMap<String, GasEscrowBatchRecord>,
    pub receipts: BTreeMap<String, GasEscrowSettlementReceipt>,
    pub refunds: BTreeMap<String, GasRefundRecord>,
    pub seen_call_commitments: BTreeSet<String>,
    pub public_records: Vec<Value>,
}

impl State {
    pub fn devnet() -> PrivateL2SmartContractGasEscrowRuntimeResult<Self> {
        Self::with_config(Config::devnet())
    }

    pub fn with_config(config: Config) -> PrivateL2SmartContractGasEscrowRuntimeResult<Self> {
        if config.min_privacy_set_size == 0 {
            return Err("min privacy set must be non-zero".to_string());
        }
        if config.batch_privacy_set_size < config.min_privacy_set_size {
            return Err("batch privacy set must cover min privacy set".to_string());
        }
        if config.min_pq_security_bits < 192 {
            return Err("minimum pq security bits must be at least 192".to_string());
        }
        if config.max_user_fee_bps > PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_MAX_BPS {
            return Err("max user fee exceeds bps denominator".to_string());
        }
        if config.max_sponsor_cover_bps > PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_MAX_BPS {
            return Err("max sponsor cover exceeds bps denominator".to_string());
        }
        Ok(Self {
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_DEVNET_HEIGHT,
            escrows: BTreeMap::new(),
            quotes: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            refunds: BTreeMap::new(),
            seen_call_commitments: BTreeSet::new(),
            public_records: Vec::new(),
        })
    }

    pub fn open_gas_escrow(
        &mut self,
        request: OpenGasEscrowRequest,
    ) -> PrivateL2SmartContractGasEscrowRuntimeResult<GasEscrowRecord> {
        if self.escrows.len() >= self.config.max_escrows {
            return Err("gas escrow queue is full".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("gas escrow max fee exceeds runtime fee cap".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("gas escrow privacy set below runtime minimum".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("gas escrow pq security bits below runtime minimum".to_string());
        }
        if request.expires_at_height <= request.opened_at_height {
            return Err("gas escrow expiry must be after open height".to_string());
        }
        if self
            .seen_call_commitments
            .contains(&request.contract_call_commitment)
        {
            return Err("contract call commitment already escrowed".to_string());
        }
        self.counters.escrows_opened = self.counters.escrows_opened.saturating_add(1);
        let escrow_id = gas_escrow_id(&request, self.counters.escrows_opened);
        self.seen_call_commitments
            .insert(request.contract_call_commitment.clone());
        let record = GasEscrowRecord {
            escrow_id,
            request,
            status: EscrowStatus::Open,
            quote_id: None,
            reservation_id: None,
            batch_id: None,
        };
        self.public_records.push(record.public_record());
        self.escrows
            .insert(record.escrow_id.clone(), record.clone());
        Ok(record)
    }

    pub fn quote_gas_execution(
        &mut self,
        request: QuoteGasExecutionRequest,
    ) -> PrivateL2SmartContractGasEscrowRuntimeResult<GasQuoteRecord> {
        if self.quotes.len() >= self.config.max_quotes {
            return Err("gas quote store is full".to_string());
        }
        let escrow = self
            .escrows
            .get_mut(&request.escrow_id)
            .ok_or_else(|| "gas escrow missing for quote".to_string())?;
        if !escrow.status.batchable() {
            return Err("gas escrow is not quoteable".to_string());
        }
        if request.quoted_fee_bps > escrow.request.max_fee_bps {
            return Err("gas quote exceeds escrow fee cap".to_string());
        }
        if request.expires_at_height <= request.quoted_at_height {
            return Err("gas quote expiry must be after quote height".to_string());
        }
        self.counters.quotes_posted = self.counters.quotes_posted.saturating_add(1);
        let quote_id = gas_quote_id(&request, self.counters.quotes_posted);
        escrow.quote_id = Some(quote_id.clone());
        escrow.status = EscrowStatus::Quoted;
        let record = GasQuoteRecord {
            quote_id,
            request,
            status: QuoteStatus::Posted,
        };
        self.public_records.push(record.public_record());
        self.quotes.insert(record.quote_id.clone(), record.clone());
        Ok(record)
    }

    pub fn reserve_sponsor_credit(
        &mut self,
        request: ReserveSponsorCreditRequest,
    ) -> PrivateL2SmartContractGasEscrowRuntimeResult<SponsorReservationRecord> {
        if self.reservations.len() >= self.config.max_reservations {
            return Err("sponsor reservation store is full".to_string());
        }
        let escrow = self
            .escrows
            .get_mut(&request.escrow_id)
            .ok_or_else(|| "gas escrow missing for sponsor reservation".to_string())?;
        if escrow.quote_id.as_deref() != Some(request.quote_id.as_str()) {
            return Err("sponsor reservation quote does not match escrow quote".to_string());
        }
        if request.reserved_cover_bps > self.config.max_sponsor_cover_bps {
            return Err("reserved sponsor cover exceeds runtime cap".to_string());
        }
        if request.expires_at_height <= request.reserved_at_height {
            return Err("sponsor reservation expiry must be after reserve height".to_string());
        }
        self.counters.reservations_opened = self.counters.reservations_opened.saturating_add(1);
        let reservation_id = sponsor_reservation_id(&request, self.counters.reservations_opened);
        escrow.reservation_id = Some(reservation_id.clone());
        escrow.status = EscrowStatus::Reserved;
        if let Some(quote) = self.quotes.get_mut(&request.quote_id) {
            quote.status = QuoteStatus::Accepted;
        }
        let record = SponsorReservationRecord {
            reservation_id,
            request,
            status: ReservationStatus::Reserved,
        };
        self.public_records.push(record.public_record());
        self.reservations
            .insert(record.reservation_id.clone(), record.clone());
        Ok(record)
    }

    pub fn build_gas_batch(
        &mut self,
        request: BuildGasEscrowBatchRequest,
    ) -> PrivateL2SmartContractGasEscrowRuntimeResult<GasEscrowBatchRecord> {
        if self.batches.len() >= self.config.max_batches {
            return Err("gas escrow batch store is full".to_string());
        }
        if request.escrow_ids.is_empty() {
            return Err("gas escrow batch must contain escrows".to_string());
        }
        if request.escrow_ids.len() > self.config.max_batch_items {
            return Err("gas escrow batch exceeds max batch items".to_string());
        }
        if request.quote_ids.len() > request.escrow_ids.len()
            || request.reservation_ids.len() > request.escrow_ids.len()
        {
            return Err("gas escrow batch has more quotes/reservations than escrows".to_string());
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("gas escrow batch fee exceeds runtime fee cap".to_string());
        }
        if request.privacy_set_size < self.config.batch_privacy_set_size {
            return Err("gas escrow batch privacy set below runtime batch target".to_string());
        }
        let mut unique_escrows = BTreeSet::new();
        for escrow_id in &request.escrow_ids {
            if !unique_escrows.insert(escrow_id.clone()) {
                return Err("gas escrow batch contains duplicate escrow id".to_string());
            }
            let escrow = self
                .escrows
                .get(escrow_id)
                .ok_or_else(|| format!("gas escrow missing from runtime: {escrow_id}"))?;
            if !escrow.status.batchable() {
                return Err(format!("gas escrow is not batchable: {escrow_id}"));
            }
        }
        for quote_id in &request.quote_ids {
            if !self.quotes.contains_key(quote_id) {
                return Err(format!("gas quote missing from runtime: {quote_id}"));
            }
        }
        for reservation_id in &request.reservation_ids {
            if !self.reservations.contains_key(reservation_id) {
                return Err(format!(
                    "gas sponsor reservation missing from runtime: {reservation_id}"
                ));
            }
        }
        self.counters.batches_built = self.counters.batches_built.saturating_add(1);
        let batch_id = gas_batch_id(&request, self.counters.batches_built);
        for escrow_id in &request.escrow_ids {
            if let Some(escrow) = self.escrows.get_mut(escrow_id) {
                escrow.status = EscrowStatus::Batched;
                escrow.batch_id = Some(batch_id.clone());
            }
        }
        let record = GasEscrowBatchRecord {
            batch_id,
            request,
            status: BatchStatus::Built,
            settlement_receipt_id: None,
        };
        self.public_records.push(record.public_record());
        self.batches.insert(record.batch_id.clone(), record.clone());
        Ok(record)
    }

    pub fn settle_gas_batch(
        &mut self,
        request: SettleGasEscrowBatchRequest,
    ) -> PrivateL2SmartContractGasEscrowRuntimeResult<GasEscrowSettlementReceipt> {
        if self.receipts.len() >= self.config.max_batches {
            return Err("gas settlement receipt store is full".to_string());
        }
        if request.settled_fee_bps > self.config.max_user_fee_bps {
            return Err("settled gas fee exceeds runtime cap".to_string());
        }
        let batch = self
            .batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "gas escrow batch missing for settlement".to_string())?;
        if !matches!(batch.status, BatchStatus::Built | BatchStatus::Sealed) {
            return Err("gas escrow batch cannot be settled from current status".to_string());
        }
        self.counters.receipts_published = self.counters.receipts_published.saturating_add(1);
        let receipt_id = gas_settlement_receipt_id(&request, self.counters.receipts_published);
        let settled_escrow_ids = batch.request.escrow_ids.clone();
        batch.status = BatchStatus::Settled;
        batch.settlement_receipt_id = Some(receipt_id.clone());
        for escrow_id in &settled_escrow_ids {
            if let Some(escrow) = self.escrows.get_mut(escrow_id) {
                escrow.status = EscrowStatus::Settled;
                self.counters.escrows_settled = self.counters.escrows_settled.saturating_add(1);
            }
        }
        for reservation in self.reservations.values_mut() {
            if settled_escrow_ids.contains(&reservation.request.escrow_id) {
                reservation.status = ReservationStatus::Consumed;
            }
        }
        let receipt = GasEscrowSettlementReceipt {
            receipt_id,
            request,
            status: ReceiptStatus::Published,
            settled_escrow_ids,
        };
        self.public_records.push(receipt.public_record());
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn publish_refund(
        &mut self,
        request: PublishGasRefundRequest,
    ) -> PrivateL2SmartContractGasEscrowRuntimeResult<GasRefundRecord> {
        let escrow = self
            .escrows
            .get_mut(&request.escrow_id)
            .ok_or_else(|| "gas escrow missing for refund".to_string())?;
        if !self.receipts.contains_key(&request.receipt_id) {
            return Err("gas settlement receipt missing for refund".to_string());
        }
        if !matches!(
            escrow.status,
            EscrowStatus::Settled | EscrowStatus::Refunded
        ) {
            return Err("gas refund requires a settled escrow".to_string());
        }
        self.counters.refunds_published = self.counters.refunds_published.saturating_add(1);
        let refund_id = gas_refund_id(&request, self.counters.refunds_published);
        escrow.status = EscrowStatus::Refunded;
        let record = GasRefundRecord { refund_id, request };
        self.public_records.push(record.public_record());
        self.refunds
            .insert(record.refund_id.clone(), record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let escrow_records = self
            .escrows
            .values()
            .map(GasEscrowRecord::public_record)
            .collect::<Vec<_>>();
        let quote_records = self
            .quotes
            .values()
            .map(GasQuoteRecord::public_record)
            .collect::<Vec<_>>();
        let reservation_records = self
            .reservations
            .values()
            .map(SponsorReservationRecord::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(GasEscrowBatchRecord::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(GasEscrowSettlementReceipt::public_record)
            .collect::<Vec<_>>();
        let refund_records = self
            .refunds
            .values()
            .map(GasRefundRecord::public_record)
            .collect::<Vec<_>>();
        Roots {
            escrow_root: merkle_root("PRIVATE-L2-SMART-CONTRACT-GAS-ESCROW", &escrow_records),
            quote_root: merkle_root("PRIVATE-L2-SMART-CONTRACT-GAS-QUOTE", &quote_records),
            reservation_root: merkle_root(
                "PRIVATE-L2-SMART-CONTRACT-GAS-SPONSOR",
                &reservation_records,
            ),
            batch_root: merkle_root("PRIVATE-L2-SMART-CONTRACT-GAS-BATCH", &batch_records),
            receipt_root: merkle_root("PRIVATE-L2-SMART-CONTRACT-GAS-RECEIPT", &receipt_records),
            refund_root: merkle_root("PRIVATE-L2-SMART-CONTRACT-GAS-REFUND", &refund_records),
            public_record_root: merkle_root(
                "PRIVATE-L2-SMART-CONTRACT-GAS-PUBLIC-RECORD",
                &self.public_records,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_smart_contract_gas_escrow_runtime",
            "protocol_version": PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_HASH_SUITE,
            "pq_auth_suite": PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_PQ_AUTH_SUITE,
            "escrow_scheme": PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_ESCROW_SCHEME,
            "sponsor_scheme": PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_SPONSOR_SCHEME,
            "batch_scheme": PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_BATCH_SCHEME,
            "config": self.config.public_record(),
            "config_root": self.config.state_root(),
            "counters": self.counters.public_record(),
            "current_height": self.current_height,
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        let state_root = root_from_record("PRIVATE-L2-SMART-CONTRACT-GAS-ESCROW-STATE", &record);
        json!({
            "state_root": state_root,
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-SMART-CONTRACT-GAS-ESCROW-STATE",
            &self.public_record_without_state_root(),
        )
    }
}

pub fn gas_escrow_id(request: &OpenGasEscrowRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-SMART-CONTRACT-GAS-ESCROW-ID",
        &[
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.contract_call_commitment),
            HashPart::Str(&request.caller_commitment),
            HashPart::Str(&request.contract_id_root),
            HashPart::Str(&request.fee_note_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn gas_quote_id(request: &QuoteGasExecutionRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-SMART-CONTRACT-GAS-QUOTE-ID",
        &[
            HashPart::Str(&request.escrow_id),
            HashPart::Str(&request.executor_commitment),
            HashPart::Str(&request.quoted_gas_root),
            HashPart::Str(&request.pq_quote_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(request: &ReserveSponsorCreditRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-SMART-CONTRACT-GAS-SPONSOR-ID",
        &[
            HashPart::Str(&request.escrow_id),
            HashPart::Str(&request.quote_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.sponsor_budget_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn gas_batch_id(request: &BuildGasEscrowBatchRequest, counter: u64) -> String {
    let request_record = request.public_record();
    domain_hash(
        "PRIVATE-L2-SMART-CONTRACT-GAS-BATCH-ID",
        &[
            HashPart::Json(&request_record),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn gas_settlement_receipt_id(request: &SettleGasEscrowBatchRequest, counter: u64) -> String {
    let request_record = request.public_record();
    domain_hash(
        "PRIVATE-L2-SMART-CONTRACT-GAS-RECEIPT-ID",
        &[
            HashPart::Json(&request_record),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn gas_refund_id(request: &PublishGasRefundRequest, counter: u64) -> String {
    let request_record = request.public_record();
    domain_hash(
        "PRIVATE-L2-SMART-CONTRACT-GAS-REFUND-ID",
        &[
            HashPart::Json(&request_record),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_SMART_CONTRACT_GAS_ESCROW_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}
