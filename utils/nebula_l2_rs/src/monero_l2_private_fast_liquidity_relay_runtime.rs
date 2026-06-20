use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PrivateFastLiquidityRelayRuntimeResult<T> = Result<T, String>;

pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-private-fast-liquidity-relay-runtime-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEVNET_HEIGHT: u64 = 312_000;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEVNET_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_QUOTE_SCHEME: &str =
    "ml-kem-1024+ml-dsa-87-private-fast-liquidity-quote-root-v1";
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_OPERATOR_ATTESTATION_SCHEME: &str =
    "ml-dsa-87-relay-operator-liquidity-attestation-root-v1";
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_BRIDGE_COMMITMENT_SCHEME: &str =
    "roots-only-monero-deposit-exit-relay-commitment-v1";
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_LOW_FEE_RECEIPT_SCHEME: &str =
    "low-fee-private-relay-reservation-rebate-receipt-root-v1";
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_BATCH_SCHEME: &str =
    "private-fast-liquidity-relay-batch-root-v1";
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_SETTLEMENT_SCHEME: &str =
    "monero-l2-private-fast-liquidity-settlement-receipt-root-v1";
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_NULLIFIER_SCHEME: &str =
    "monero-l2-private-fast-liquidity-relay-nullifier-root-v1";
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 18;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_COMMITMENT_TTL_BLOCKS: u64 = 36;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 72;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 8_192;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 22;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 5;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_REBATE_BPS: u64 = 12;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_MIN_OPERATOR_STAKE_BPS: u64 =
    11_000;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_MAX_QUOTES: usize = 262_144;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_MAX_ATTESTATIONS: usize = 262_144;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_MAX_COMMITMENTS: usize = 262_144;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_MAX_FEE_RECEIPTS: usize = 262_144;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_MAX_BATCHES: usize = 131_072;
pub const MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_MAX_SETTLEMENTS: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayDirection {
    Deposit,
    Exit,
    Bidirectional,
}

impl RelayDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Exit => "exit",
            Self::Bidirectional => "bidirectional",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayPriority {
    LowFee,
    Standard,
    Fast,
    Defi,
    Emergency,
}

impl RelayPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::Defi => "defi",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFee => config.low_fee_bps,
            Self::Standard => config.max_user_fee_bps.saturating_mul(2) / 3,
            Self::Fast | Self::Emergency => config.max_user_fee_bps,
            Self::Defi => config.max_user_fee_bps.saturating_mul(3) / 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Open,
    Attested,
    Committed,
    Batched,
    Settled,
    Expired,
    Cancelled,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Attested => "attested",
            Self::Committed => "committed",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Attested | Self::Committed | Self::Batched
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Pending,
    Proven,
    Batched,
    Settled,
    Expired,
    Rejected,
}

impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Proven => "proven",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Published,
    Finalized,
    Reconciled,
    Failed,
    Disputed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Reconciled => "reconciled",
            Self::Failed => "failed",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub quote_scheme: String,
    pub operator_attestation_scheme: String,
    pub bridge_commitment_scheme: String,
    pub low_fee_receipt_scheme: String,
    pub batch_scheme: String,
    pub settlement_scheme: String,
    pub nullifier_scheme: String,
    pub genesis_height: u64,
    pub quote_ttl_blocks: u64,
    pub commitment_ttl_blocks: u64,
    pub batch_window_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub low_fee_bps: u64,
    pub rebate_bps: u64,
    pub min_operator_stake_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_SCHEMA_VERSION,
            monero_network: MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEVNET_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEVNET_L2_NETWORK
                .to_string(),
            asset_id: MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEVNET_FEE_ASSET_ID
                .to_string(),
            hash_suite: MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_HASH_SUITE.to_string(),
            quote_scheme: MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_QUOTE_SCHEME.to_string(),
            operator_attestation_scheme:
                MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_OPERATOR_ATTESTATION_SCHEME
                    .to_string(),
            bridge_commitment_scheme:
                MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_BRIDGE_COMMITMENT_SCHEME.to_string(),
            low_fee_receipt_scheme:
                MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_LOW_FEE_RECEIPT_SCHEME.to_string(),
            batch_scheme: MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_BATCH_SCHEME.to_string(),
            settlement_scheme: MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_SETTLEMENT_SCHEME
                .to_string(),
            nullifier_scheme: MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_NULLIFIER_SCHEME
                .to_string(),
            genesis_height: MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEVNET_HEIGHT,
            quote_ttl_blocks:
                MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
            commitment_ttl_blocks:
                MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_COMMITMENT_TTL_BLOCKS,
            batch_window_blocks:
                MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_BATCH_WINDOW_BLOCKS,
            settlement_ttl_blocks:
                MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            min_privacy_set_size:
                MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits:
                MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_user_fee_bps:
                MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            low_fee_bps: MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_LOW_FEE_BPS,
            rebate_bps: MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_REBATE_BPS,
            min_operator_stake_bps:
                MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_DEFAULT_MIN_OPERATOR_STAKE_BPS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub quotes: usize,
    pub operator_attestations: usize,
    pub bridge_commitments: usize,
    pub low_fee_receipts: usize,
    pub relay_batches: usize,
    pub settlement_receipts: usize,
    pub public_records: usize,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub quote_root: String,
    pub operator_attestation_root: String,
    pub bridge_commitment_root: String,
    pub low_fee_receipt_root: String,
    pub relay_batch_root: String,
    pub settlement_receipt_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityQuoteRequest {
    pub quote_id: String,
    pub operator_id: String,
    pub direction: RelayDirection,
    pub priority: RelayPriority,
    pub amount_piconero: u64,
    pub min_receive_piconero: u64,
    pub route_commitment: String,
    pub private_recipient_commitment: String,
    pub defi_call_commitment: Option<String>,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub requested_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityQuote {
    pub quote_id: String,
    pub operator_id: String,
    pub direction: RelayDirection,
    pub priority: RelayPriority,
    pub amount_piconero: u64,
    pub fee_bps: u64,
    pub fee_piconero: u64,
    pub rebate_bps: u64,
    pub rebate_piconero: u64,
    pub min_receive_piconero: u64,
    pub route_commitment: String,
    pub private_recipient_commitment: String,
    pub defi_call_commitment: Option<String>,
    pub quote_root: String,
    pub expires_at_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: QuoteStatus,
}

impl LiquidityQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "operator_id": self.operator_id,
            "direction": self.direction.as_str(),
            "priority": self.priority.as_str(),
            "amount_piconero": self.amount_piconero,
            "fee_bps": self.fee_bps,
            "fee_piconero": self.fee_piconero,
            "rebate_bps": self.rebate_bps,
            "rebate_piconero": self.rebate_piconero,
            "min_receive_piconero": self.min_receive_piconero,
            "route_commitment": self.route_commitment,
            "private_recipient_commitment": self.private_recipient_commitment,
            "defi_call_commitment": self.defi_call_commitment,
            "quote_root": self.quote_root,
            "expires_at_height": self.expires_at_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorAttestationRequest {
    pub attestation_id: String,
    pub quote_id: String,
    pub operator_id: String,
    pub liquidity_root: String,
    pub pq_pubkey_root: String,
    pub reserve_proof_root: String,
    pub stake_bps: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorAttestation {
    pub attestation_id: String,
    pub quote_id: String,
    pub operator_id: String,
    pub liquidity_root: String,
    pub pq_pubkey_root: String,
    pub reserve_proof_root: String,
    pub stake_bps: u64,
    pub pq_security_bits: u16,
    pub attestation_root: String,
    pub attested_at_height: u64,
}

impl OperatorAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeCommitmentRequest {
    pub commitment_id: String,
    pub quote_id: String,
    pub direction: RelayDirection,
    pub monero_tx_commitment: String,
    pub l2_note_commitment: String,
    pub nullifier: String,
    pub view_tag_root: String,
    pub amount_commitment: String,
    pub proof_root: String,
    pub committed_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeCommitment {
    pub commitment_id: String,
    pub quote_id: String,
    pub direction: RelayDirection,
    pub monero_tx_commitment: String,
    pub l2_note_commitment: String,
    pub nullifier: String,
    pub view_tag_root: String,
    pub amount_commitment: String,
    pub proof_root: String,
    pub commitment_root: String,
    pub expires_at_height: u64,
    pub status: CommitmentStatus,
}

impl BridgeCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "quote_id": self.quote_id,
            "direction": self.direction.as_str(),
            "monero_tx_commitment": self.monero_tx_commitment,
            "l2_note_commitment": self.l2_note_commitment,
            "nullifier": self.nullifier,
            "view_tag_root": self.view_tag_root,
            "amount_commitment": self.amount_commitment,
            "proof_root": self.proof_root,
            "commitment_root": self.commitment_root,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeReceiptRequest {
    pub receipt_id: String,
    pub quote_id: String,
    pub reservation_commitment: String,
    pub sponsor_commitment: String,
    pub user_fee_paid_piconero: u64,
    pub rebate_destination_commitment: String,
    pub issued_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeReceipt {
    pub receipt_id: String,
    pub quote_id: String,
    pub reservation_commitment: String,
    pub sponsor_commitment: String,
    pub user_fee_paid_piconero: u64,
    pub rebate_piconero: u64,
    pub rebate_destination_commitment: String,
    pub receipt_root: String,
    pub issued_at_height: u64,
}

impl LowFeeReceipt {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayBatchRequest {
    pub batch_id: String,
    pub operator_id: String,
    pub quote_ids: Vec<String>,
    pub commitment_ids: Vec<String>,
    pub fee_receipt_ids: Vec<String>,
    pub private_orderflow_root: String,
    pub defi_intent_root: String,
    pub sealed_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayBatch {
    pub batch_id: String,
    pub operator_id: String,
    pub quote_ids: Vec<String>,
    pub commitment_ids: Vec<String>,
    pub fee_receipt_ids: Vec<String>,
    pub private_orderflow_root: String,
    pub defi_intent_root: String,
    pub batch_root: String,
    pub sealed_at_height: u64,
    pub settlement_due_height: u64,
    pub status: BatchStatus,
}

impl RelayBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "operator_id": self.operator_id,
            "quote_ids": self.quote_ids,
            "commitment_ids": self.commitment_ids,
            "fee_receipt_ids": self.fee_receipt_ids,
            "private_orderflow_root": self.private_orderflow_root,
            "defi_intent_root": self.defi_intent_root,
            "batch_root": self.batch_root,
            "sealed_at_height": self.sealed_at_height,
            "settlement_due_height": self.settlement_due_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceiptRequest {
    pub settlement_id: String,
    pub batch_id: String,
    pub monero_anchor_root: String,
    pub l2_state_transition_root: String,
    pub token_delta_root: String,
    pub smart_contract_receipt_root: String,
    pub pq_signature_root: String,
    pub settled_at_height: u64,
    pub status: SettlementStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub settlement_id: String,
    pub batch_id: String,
    pub monero_anchor_root: String,
    pub l2_state_transition_root: String,
    pub token_delta_root: String,
    pub smart_contract_receipt_root: String,
    pub pq_signature_root: String,
    pub settlement_root: String,
    pub settled_at_height: u64,
    pub status: SettlementStatus,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "batch_id": self.batch_id,
            "monero_anchor_root": self.monero_anchor_root,
            "l2_state_transition_root": self.l2_state_transition_root,
            "token_delta_root": self.token_delta_root,
            "smart_contract_receipt_root": self.smart_contract_receipt_root,
            "pq_signature_root": self.pq_signature_root,
            "settlement_root": self.settlement_root,
            "settled_at_height": self.settled_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub quotes: BTreeMap<String, LiquidityQuote>,
    pub operator_attestations: BTreeMap<String, OperatorAttestation>,
    pub bridge_commitments: BTreeMap<String, BridgeCommitment>,
    pub low_fee_receipts: BTreeMap<String, LowFeeReceipt>,
    pub relay_batches: BTreeMap<String, RelayBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn devnet() -> MoneroL2PrivateFastLiquidityRelayRuntimeResult<Self> {
        let mut state = Self {
            config: Config::devnet(),
            quotes: BTreeMap::new(),
            operator_attestations: BTreeMap::new(),
            bridge_commitments: BTreeMap::new(),
            low_fee_receipts: BTreeMap::new(),
            relay_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };

        let quote = state.quote_private_fast_liquidity(LiquidityQuoteRequest {
            quote_id: "devnet-fast-xmr-entry-quote-0001".to_string(),
            operator_id: "devnet-pq-relay-operator-01".to_string(),
            direction: RelayDirection::Bidirectional,
            priority: RelayPriority::LowFee,
            amount_piconero: 25_000_000_000_000,
            min_receive_piconero: 24_999_000_000_000,
            route_commitment: root_from_parts(
                "DEVNET-ROUTE",
                &[HashPart::Str("private-fast-bridge-route")],
            ),
            private_recipient_commitment: root_from_parts(
                "DEVNET-RECIPIENT",
                &[HashPart::Str("stealth-recipient-root")],
            ),
            defi_call_commitment: Some(root_from_parts(
                "DEVNET-DEFI-CALL",
                &[HashPart::Str("private-token-swap-intent")],
            )),
            privacy_set_size: 16_384,
            pq_security_bits: 256,
            requested_at_height: state.config.genesis_height,
        })?;

        state.attest_pq_relay_operator(OperatorAttestationRequest {
            attestation_id: "devnet-pq-relay-attestation-0001".to_string(),
            quote_id: quote.quote_id.clone(),
            operator_id: quote.operator_id.clone(),
            liquidity_root: root_from_parts("DEVNET-LIQUIDITY", &[HashPart::Str("reserve")]),
            pq_pubkey_root: root_from_parts("DEVNET-PQ-PUBKEY", &[HashPart::Str("ml-dsa-87")]),
            reserve_proof_root: root_from_parts(
                "DEVNET-RESERVE-PROOF",
                &[HashPart::Str("overcollateralized-xmr")],
            ),
            stake_bps: 12_500,
            pq_security_bits: 256,
            attested_at_height: state.config.genesis_height + 1,
        })?;

        let commitment = state.commit_monero_deposit_exit_relay(BridgeCommitmentRequest {
            commitment_id: "devnet-monero-relay-commitment-0001".to_string(),
            quote_id: quote.quote_id.clone(),
            direction: RelayDirection::Deposit,
            monero_tx_commitment: root_from_parts(
                "DEVNET-MONERO-TX",
                &[HashPart::Str("tx-private-root")],
            ),
            l2_note_commitment: root_from_parts("DEVNET-L2-NOTE", &[HashPart::Str("note-root")]),
            nullifier: root_from_parts("DEVNET-NULLIFIER", &[HashPart::Str("nullifier-0001")]),
            view_tag_root: root_from_parts("DEVNET-VIEW-TAG", &[HashPart::Str("view-tags")]),
            amount_commitment: root_from_parts(
                "DEVNET-AMOUNT",
                &[HashPart::Int(25_000_000_000_000)],
            ),
            proof_root: root_from_parts("DEVNET-BRIDGE-PROOF", &[HashPart::Str("proof-root")]),
            committed_at_height: state.config.genesis_height + 2,
        })?;

        let fee_receipt = state.issue_low_fee_reservation_rebate(LowFeeReceiptRequest {
            receipt_id: "devnet-low-fee-rebate-0001".to_string(),
            quote_id: quote.quote_id.clone(),
            reservation_commitment: commitment.commitment_root.clone(),
            sponsor_commitment: root_from_parts(
                "DEVNET-SPONSOR",
                &[HashPart::Str("fee-sponsor-root")],
            ),
            user_fee_paid_piconero: quote.fee_piconero,
            rebate_destination_commitment: root_from_parts(
                "DEVNET-REBATE-DESTINATION",
                &[HashPart::Str("rebate-note-root")],
            ),
            issued_at_height: state.config.genesis_height + 3,
        })?;

        let batch = state.seal_relay_batch(RelayBatchRequest {
            batch_id: "devnet-private-fast-relay-batch-0001".to_string(),
            operator_id: quote.operator_id.clone(),
            quote_ids: vec![quote.quote_id.clone()],
            commitment_ids: vec![commitment.commitment_id.clone()],
            fee_receipt_ids: vec![fee_receipt.receipt_id.clone()],
            private_orderflow_root: root_from_parts(
                "DEVNET-ORDERFLOW",
                &[HashPart::Str("sealed-orderflow")],
            ),
            defi_intent_root: root_from_parts("DEVNET-DEFI-INTENT", &[HashPart::Str("intent")]),
            sealed_at_height: state.config.genesis_height + 4,
        })?;

        state.record_settlement_receipt(SettlementReceiptRequest {
            settlement_id: "devnet-fast-liquidity-settlement-0001".to_string(),
            batch_id: batch.batch_id,
            monero_anchor_root: root_from_parts(
                "DEVNET-MONERO-ANCHOR",
                &[HashPart::Str("anchor-root")],
            ),
            l2_state_transition_root: state.state_root(),
            token_delta_root: root_from_parts("DEVNET-TOKEN-DELTAS", &[HashPart::Str("deltas")]),
            smart_contract_receipt_root: root_from_parts(
                "DEVNET-SMART-CONTRACT-RECEIPTS",
                &[HashPart::Str("receipts")],
            ),
            pq_signature_root: root_from_parts("DEVNET-PQ-SIGNATURE", &[HashPart::Str("sig")]),
            settled_at_height: state.config.genesis_height + 5,
            status: SettlementStatus::Finalized,
        })?;

        Ok(state)
    }

    pub fn quote_private_fast_liquidity(
        &mut self,
        request: LiquidityQuoteRequest,
    ) -> MoneroL2PrivateFastLiquidityRelayRuntimeResult<LiquidityQuote> {
        ensure_capacity(
            self.quotes.len(),
            MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_MAX_QUOTES,
            "quotes",
        )?;
        ensure_new_key(&self.quotes, &request.quote_id, "quote")?;
        ensure_non_empty("operator id", &request.operator_id)?;
        ensure_non_empty("route commitment", &request.route_commitment)?;
        ensure_non_empty(
            "private recipient commitment",
            &request.private_recipient_commitment,
        )?;
        ensure_minimum_privacy(&self.config, request.privacy_set_size)?;
        ensure_pq_security(&self.config, request.pq_security_bits)?;
        ensure_positive("amount", request.amount_piconero)?;

        let fee_bps = request.priority.fee_bps(&self.config);
        let fee_piconero = request.amount_piconero.saturating_mul(fee_bps)
            / MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_MAX_BPS;
        let rebate_bps = if request.priority == RelayPriority::LowFee {
            self.config.rebate_bps
        } else {
            0
        };
        let rebate_piconero = request.amount_piconero.saturating_mul(rebate_bps)
            / MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_MAX_BPS;
        let quote_root = root_from_record(
            "MONERO-L2-PRIVATE-FAST-LIQUIDITY-QUOTE",
            &json!({
                "quote_id": &request.quote_id,
                "operator_id": &request.operator_id,
                "direction": request.direction.as_str(),
                "priority": request.priority.as_str(),
                "amount_piconero": request.amount_piconero,
                "fee_bps": fee_bps,
                "rebate_bps": rebate_bps,
                "route_commitment": &request.route_commitment,
                "private_recipient_commitment": &request.private_recipient_commitment,
                "defi_call_commitment": &request.defi_call_commitment,
                "requested_at_height": request.requested_at_height,
            }),
        );
        let quote = LiquidityQuote {
            quote_id: request.quote_id,
            operator_id: request.operator_id,
            direction: request.direction,
            priority: request.priority,
            amount_piconero: request.amount_piconero,
            fee_bps,
            fee_piconero,
            rebate_bps,
            rebate_piconero,
            min_receive_piconero: request.min_receive_piconero,
            route_commitment: request.route_commitment,
            private_recipient_commitment: request.private_recipient_commitment,
            defi_call_commitment: request.defi_call_commitment,
            quote_root,
            expires_at_height: request
                .requested_at_height
                .saturating_add(self.config.quote_ttl_blocks),
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            status: QuoteStatus::Open,
        };
        self.public_records
            .insert(format!("quote:{}", quote.quote_id), quote.public_record());
        self.quotes.insert(quote.quote_id.clone(), quote.clone());
        Ok(quote)
    }

    pub fn attest_pq_relay_operator(
        &mut self,
        request: OperatorAttestationRequest,
    ) -> MoneroL2PrivateFastLiquidityRelayRuntimeResult<OperatorAttestation> {
        ensure_capacity(
            self.operator_attestations.len(),
            MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_MAX_ATTESTATIONS,
            "operator attestations",
        )?;
        ensure_new_key(
            &self.operator_attestations,
            &request.attestation_id,
            "operator attestation",
        )?;
        ensure_non_empty("liquidity root", &request.liquidity_root)?;
        ensure_non_empty("pq pubkey root", &request.pq_pubkey_root)?;
        ensure_non_empty("reserve proof root", &request.reserve_proof_root)?;
        ensure_pq_security(&self.config, request.pq_security_bits)?;
        if request.stake_bps < self.config.min_operator_stake_bps {
            return Err(format!(
                "operator stake {} bps below minimum {} bps",
                request.stake_bps, self.config.min_operator_stake_bps
            ));
        }
        let quote = self
            .quotes
            .get_mut(&request.quote_id)
            .ok_or_else(|| format!("unknown quote {}", request.quote_id))?;
        if quote.operator_id != request.operator_id {
            return Err("operator attestation does not match quote operator".to_string());
        }
        if !quote.status.live() {
            return Err("quote is not live".to_string());
        }
        quote.status = QuoteStatus::Attested;
        let attestation_root = root_from_record(
            "MONERO-L2-PRIVATE-FAST-LIQUIDITY-OPERATOR-ATTESTATION",
            &json!(&request),
        );
        let attestation = OperatorAttestation {
            attestation_id: request.attestation_id,
            quote_id: request.quote_id,
            operator_id: request.operator_id,
            liquidity_root: request.liquidity_root,
            pq_pubkey_root: request.pq_pubkey_root,
            reserve_proof_root: request.reserve_proof_root,
            stake_bps: request.stake_bps,
            pq_security_bits: request.pq_security_bits,
            attestation_root,
            attested_at_height: request.attested_at_height,
        };
        self.public_records.insert(
            format!("attestation:{}", attestation.attestation_id),
            attestation.public_record(),
        );
        self.public_records
            .insert(format!("quote:{}", quote.quote_id), quote.public_record());
        self.operator_attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        Ok(attestation)
    }

    pub fn commit_monero_deposit_exit_relay(
        &mut self,
        request: BridgeCommitmentRequest,
    ) -> MoneroL2PrivateFastLiquidityRelayRuntimeResult<BridgeCommitment> {
        ensure_capacity(
            self.bridge_commitments.len(),
            MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_MAX_COMMITMENTS,
            "bridge commitments",
        )?;
        ensure_new_key(
            &self.bridge_commitments,
            &request.commitment_id,
            "bridge commitment",
        )?;
        ensure_non_empty("monero tx commitment", &request.monero_tx_commitment)?;
        ensure_non_empty("l2 note commitment", &request.l2_note_commitment)?;
        ensure_non_empty("nullifier", &request.nullifier)?;
        ensure_non_empty("proof root", &request.proof_root)?;
        if self.nullifiers.contains(&request.nullifier) {
            return Err(format!("duplicate nullifier {}", request.nullifier));
        }
        let quote = self
            .quotes
            .get_mut(&request.quote_id)
            .ok_or_else(|| format!("unknown quote {}", request.quote_id))?;
        if !quote.status.live() {
            return Err("quote is not live".to_string());
        }
        quote.status = QuoteStatus::Committed;
        let commitment_root = root_from_record(
            "MONERO-L2-PRIVATE-FAST-LIQUIDITY-BRIDGE-COMMITMENT",
            &json!(&request),
        );
        let commitment = BridgeCommitment {
            commitment_id: request.commitment_id,
            quote_id: request.quote_id,
            direction: request.direction,
            monero_tx_commitment: request.monero_tx_commitment,
            l2_note_commitment: request.l2_note_commitment,
            nullifier: request.nullifier,
            view_tag_root: request.view_tag_root,
            amount_commitment: request.amount_commitment,
            proof_root: request.proof_root,
            commitment_root,
            expires_at_height: request
                .committed_at_height
                .saturating_add(self.config.commitment_ttl_blocks),
            status: CommitmentStatus::Pending,
        };
        self.nullifiers.insert(commitment.nullifier.clone());
        self.public_records.insert(
            format!("commitment:{}", commitment.commitment_id),
            commitment.public_record(),
        );
        self.public_records
            .insert(format!("quote:{}", quote.quote_id), quote.public_record());
        self.bridge_commitments
            .insert(commitment.commitment_id.clone(), commitment.clone());
        Ok(commitment)
    }

    pub fn issue_low_fee_reservation_rebate(
        &mut self,
        request: LowFeeReceiptRequest,
    ) -> MoneroL2PrivateFastLiquidityRelayRuntimeResult<LowFeeReceipt> {
        ensure_capacity(
            self.low_fee_receipts.len(),
            MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_MAX_FEE_RECEIPTS,
            "low fee receipts",
        )?;
        ensure_new_key(
            &self.low_fee_receipts,
            &request.receipt_id,
            "low fee receipt",
        )?;
        ensure_non_empty("reservation commitment", &request.reservation_commitment)?;
        ensure_non_empty("sponsor commitment", &request.sponsor_commitment)?;
        ensure_non_empty(
            "rebate destination commitment",
            &request.rebate_destination_commitment,
        )?;
        let quote = self
            .quotes
            .get(&request.quote_id)
            .ok_or_else(|| format!("unknown quote {}", request.quote_id))?;
        let rebate_piconero = quote.rebate_piconero.min(request.user_fee_paid_piconero);
        let receipt_root = root_from_record(
            "MONERO-L2-PRIVATE-FAST-LIQUIDITY-LOW-FEE-RECEIPT",
            &json!({
                "receipt_id": &request.receipt_id,
                "quote_id": &request.quote_id,
                "reservation_commitment": &request.reservation_commitment,
                "sponsor_commitment": &request.sponsor_commitment,
                "user_fee_paid_piconero": request.user_fee_paid_piconero,
                "rebate_piconero": rebate_piconero,
                "rebate_destination_commitment": &request.rebate_destination_commitment,
                "issued_at_height": request.issued_at_height,
            }),
        );
        let receipt = LowFeeReceipt {
            receipt_id: request.receipt_id,
            quote_id: request.quote_id,
            reservation_commitment: request.reservation_commitment,
            sponsor_commitment: request.sponsor_commitment,
            user_fee_paid_piconero: request.user_fee_paid_piconero,
            rebate_piconero,
            rebate_destination_commitment: request.rebate_destination_commitment,
            receipt_root,
            issued_at_height: request.issued_at_height,
        };
        self.public_records.insert(
            format!("fee_receipt:{}", receipt.receipt_id),
            receipt.public_record(),
        );
        self.low_fee_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn seal_relay_batch(
        &mut self,
        request: RelayBatchRequest,
    ) -> MoneroL2PrivateFastLiquidityRelayRuntimeResult<RelayBatch> {
        ensure_capacity(
            self.relay_batches.len(),
            MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_MAX_BATCHES,
            "relay batches",
        )?;
        ensure_new_key(&self.relay_batches, &request.batch_id, "relay batch")?;
        ensure_non_empty("private orderflow root", &request.private_orderflow_root)?;
        ensure_non_empty("defi intent root", &request.defi_intent_root)?;
        if request.quote_ids.is_empty() || request.commitment_ids.is_empty() {
            return Err("relay batch requires at least one quote and commitment".to_string());
        }
        for quote_id in &request.quote_ids {
            let quote = self
                .quotes
                .get_mut(quote_id)
                .ok_or_else(|| format!("unknown quote {quote_id}"))?;
            quote.status = QuoteStatus::Batched;
            self.public_records
                .insert(format!("quote:{quote_id}"), quote.public_record());
        }
        for commitment_id in &request.commitment_ids {
            let commitment = self
                .bridge_commitments
                .get_mut(commitment_id)
                .ok_or_else(|| format!("unknown commitment {commitment_id}"))?;
            commitment.status = CommitmentStatus::Batched;
            self.public_records.insert(
                format!("commitment:{commitment_id}"),
                commitment.public_record(),
            );
        }
        for receipt_id in &request.fee_receipt_ids {
            if !self.low_fee_receipts.contains_key(receipt_id) {
                return Err(format!("unknown low fee receipt {receipt_id}"));
            }
        }
        let batch_root = root_from_record(
            "MONERO-L2-PRIVATE-FAST-LIQUIDITY-RELAY-BATCH",
            &json!(&request),
        );
        let batch = RelayBatch {
            batch_id: request.batch_id,
            operator_id: request.operator_id,
            quote_ids: request.quote_ids,
            commitment_ids: request.commitment_ids,
            fee_receipt_ids: request.fee_receipt_ids,
            private_orderflow_root: request.private_orderflow_root,
            defi_intent_root: request.defi_intent_root,
            batch_root,
            sealed_at_height: request.sealed_at_height,
            settlement_due_height: request
                .sealed_at_height
                .saturating_add(self.config.settlement_ttl_blocks),
            status: BatchStatus::SettlementReady,
        };
        self.public_records
            .insert(format!("batch:{}", batch.batch_id), batch.public_record());
        self.relay_batches
            .insert(batch.batch_id.clone(), batch.clone());
        Ok(batch)
    }

    pub fn record_settlement_receipt(
        &mut self,
        request: SettlementReceiptRequest,
    ) -> MoneroL2PrivateFastLiquidityRelayRuntimeResult<SettlementReceipt> {
        ensure_capacity(
            self.settlement_receipts.len(),
            MONERO_L2_PRIVATE_FAST_LIQUIDITY_RELAY_RUNTIME_MAX_SETTLEMENTS,
            "settlement receipts",
        )?;
        ensure_new_key(
            &self.settlement_receipts,
            &request.settlement_id,
            "settlement receipt",
        )?;
        ensure_non_empty("monero anchor root", &request.monero_anchor_root)?;
        ensure_non_empty(
            "l2 state transition root",
            &request.l2_state_transition_root,
        )?;
        ensure_non_empty("pq signature root", &request.pq_signature_root)?;
        let batch = self
            .relay_batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| format!("unknown batch {}", request.batch_id))?;
        batch.status = if request.status == SettlementStatus::Disputed {
            BatchStatus::Disputed
        } else {
            BatchStatus::Settled
        };
        let quote_ids = batch.quote_ids.clone();
        let commitment_ids = batch.commitment_ids.clone();
        self.public_records
            .insert(format!("batch:{}", batch.batch_id), batch.public_record());
        for quote_id in quote_ids {
            if let Some(quote) = self.quotes.get_mut(&quote_id) {
                quote.status = QuoteStatus::Settled;
                self.public_records
                    .insert(format!("quote:{quote_id}"), quote.public_record());
            }
        }
        for commitment_id in commitment_ids {
            if let Some(commitment) = self.bridge_commitments.get_mut(&commitment_id) {
                commitment.status = CommitmentStatus::Settled;
                self.public_records.insert(
                    format!("commitment:{commitment_id}"),
                    commitment.public_record(),
                );
            }
        }
        let settlement_root = root_from_record(
            "MONERO-L2-PRIVATE-FAST-LIQUIDITY-SETTLEMENT-RECEIPT",
            &json!(&request),
        );
        let receipt = SettlementReceipt {
            settlement_id: request.settlement_id,
            batch_id: request.batch_id,
            monero_anchor_root: request.monero_anchor_root,
            l2_state_transition_root: request.l2_state_transition_root,
            token_delta_root: request.token_delta_root,
            smart_contract_receipt_root: request.smart_contract_receipt_root,
            pq_signature_root: request.pq_signature_root,
            settlement_root,
            settled_at_height: request.settled_at_height,
            status: request.status,
        };
        self.public_records.insert(
            format!("settlement:{}", receipt.settlement_id),
            receipt.public_record(),
        );
        self.settlement_receipts
            .insert(receipt.settlement_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn counters(&self) -> Counters {
        Counters {
            quotes: self.quotes.len(),
            operator_attestations: self.operator_attestations.len(),
            bridge_commitments: self.bridge_commitments.len(),
            low_fee_receipts: self.low_fee_receipts.len(),
            relay_batches: self.relay_batches.len(),
            settlement_receipts: self.settlement_receipts.len(),
            public_records: self.public_records.len(),
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            quote_root: public_record_root(
                "MONERO-L2-PRIVATE-FAST-LIQUIDITY-QUOTES",
                &self
                    .quotes
                    .values()
                    .map(LiquidityQuote::public_record)
                    .collect::<Vec<_>>(),
            ),
            operator_attestation_root: public_record_root(
                "MONERO-L2-PRIVATE-FAST-LIQUIDITY-OPERATOR-ATTESTATIONS",
                &self
                    .operator_attestations
                    .values()
                    .map(OperatorAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            bridge_commitment_root: public_record_root(
                "MONERO-L2-PRIVATE-FAST-LIQUIDITY-BRIDGE-COMMITMENTS",
                &self
                    .bridge_commitments
                    .values()
                    .map(BridgeCommitment::public_record)
                    .collect::<Vec<_>>(),
            ),
            low_fee_receipt_root: public_record_root(
                "MONERO-L2-PRIVATE-FAST-LIQUIDITY-LOW-FEE-RECEIPTS",
                &self
                    .low_fee_receipts
                    .values()
                    .map(LowFeeReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            relay_batch_root: public_record_root(
                "MONERO-L2-PRIVATE-FAST-LIQUIDITY-RELAY-BATCHES",
                &self
                    .relay_batches
                    .values()
                    .map(RelayBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            settlement_receipt_root: public_record_root(
                "MONERO-L2-PRIVATE-FAST-LIQUIDITY-SETTLEMENT-RECEIPTS",
                &self
                    .settlement_receipts
                    .values()
                    .map(SettlementReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            nullifier_root: public_record_root(
                "MONERO-L2-PRIVATE-FAST-LIQUIDITY-NULLIFIERS",
                &self
                    .nullifiers
                    .iter()
                    .map(|value| json!(value))
                    .collect::<Vec<_>>(),
            ),
            public_record_root: public_record_root(
                "MONERO-L2-PRIVATE-FAST-LIQUIDITY-PUBLIC-RECORDS",
                &self.public_records.values().cloned().collect::<Vec<_>>(),
            ),
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "MONERO-L2-PRIVATE-FAST-LIQUIDITY-RELAY-STATE",
            &self.public_record_without_root(),
        )
    }
}

pub fn devnet() -> MoneroL2PrivateFastLiquidityRelayRuntimeResult<State> {
    State::devnet()
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let mut sorted = records.to_vec();
    sorted.sort_by_key(crate::hash::canonical_json_string);
    merkle_root(domain, &sorted)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("MONERO-L2-PRIVATE-FAST-LIQUIDITY-RELAY-STATE", record)
}

fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn ensure_non_empty(
    label: &str,
    value: &str,
) -> MoneroL2PrivateFastLiquidityRelayRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(label: &str, value: u64) -> MoneroL2PrivateFastLiquidityRelayRuntimeResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(
    len: usize,
    max: usize,
    label: &str,
) -> MoneroL2PrivateFastLiquidityRelayRuntimeResult<()> {
    if len >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn ensure_new_key<T>(
    values: &BTreeMap<String, T>,
    key: &str,
    label: &str,
) -> MoneroL2PrivateFastLiquidityRelayRuntimeResult<()> {
    ensure_non_empty(label, key)?;
    if values.contains_key(key) {
        Err(format!("{label} {key} already exists"))
    } else {
        Ok(())
    }
}

fn ensure_minimum_privacy(
    config: &Config,
    privacy_set_size: u64,
) -> MoneroL2PrivateFastLiquidityRelayRuntimeResult<()> {
    if privacy_set_size < config.min_privacy_set_size {
        Err(format!(
            "privacy set {} below minimum {}",
            privacy_set_size, config.min_privacy_set_size
        ))
    } else {
        Ok(())
    }
}

fn ensure_pq_security(
    config: &Config,
    pq_security_bits: u16,
) -> MoneroL2PrivateFastLiquidityRelayRuntimeResult<()> {
    if pq_security_bits < config.min_pq_security_bits {
        Err(format!(
            "pq security {} below minimum {}",
            pq_security_bits, config.min_pq_security_bits
        ))
    } else {
        Ok(())
    }
}
