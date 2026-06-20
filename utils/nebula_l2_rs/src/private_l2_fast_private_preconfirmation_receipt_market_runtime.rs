use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-private-preconfirmation-receipt-market-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_620_000;
pub const DEVNET_EPOCH: u64 = 2_240;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ml-dsa-87+slh-dsa-shake-256s-preconfirmation-market-auth-v1";
pub const SEALED_TICKET_SUITE: &str = "ml-kem-1024+xwing-sealed-preconfirmation-ticket-v1";
pub const RECEIPT_PROOF_SUITE: &str = "zk-private-preconfirmation-receipt-proof-v1";
pub const PRIVACY_FENCE_SUITE: &str = "private-preconfirmation-nullifier-fence-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-preconfirmation-receipt-rebate-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MIN_PRIVACY_SET: u64 = 32_768;
pub const DEFAULT_TARGET_PRIVACY_SET: u64 = 262_144;
pub const DEFAULT_MAX_TICKETS_PER_BATCH: usize = 4_096;
pub const DEFAULT_MAX_ACTIVE_SLOTS: usize = 8_192;
pub const DEFAULT_MAX_ACTIVE_BIDS: usize = 131_072;
pub const DEFAULT_TICKET_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_FINALITY_DELAY_BLOCKS: u64 = 8;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_FEE_BPS: u64 = 5;
pub const DEFAULT_REBATE_BPS: u64 = 9;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_SEQUENCER_BOND_MICRO_UNITS: u64 = 2_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconfirmationLane {
    ContractCall,
    TokenTransfer,
    DefiIntent,
    BridgeExit,
    OracleUpdate,
    PaymasterRefund,
    StateChannelClose,
    Emergency,
}

impl PreconfirmationLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractCall => "contract_call",
            Self::TokenTransfer => "token_transfer",
            Self::DefiIntent => "defi_intent",
            Self::BridgeExit => "bridge_exit",
            Self::OracleUpdate => "oracle_update",
            Self::PaymasterRefund => "paymaster_refund",
            Self::StateChannelClose => "state_channel_close",
            Self::Emergency => "emergency",
        }
    }

    pub fn target_fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::PaymasterRefund => config.target_fee_bps.saturating_sub(2),
            Self::ContractCall | Self::TokenTransfer => config.target_fee_bps,
            Self::DefiIntent | Self::StateChannelClose => config.target_fee_bps + 1,
            Self::BridgeExit | Self::OracleUpdate => config.target_fee_bps + 2,
            Self::Emergency => config.max_user_fee_bps,
        }
        .min(config.max_user_fee_bps)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotStatus {
    Open,
    Filled,
    Draining,
    Suspended,
    Slashed,
    Retired,
}

impl SlotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Filled => "filled",
            Self::Draining => "draining",
            Self::Suspended => "suspended",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_tickets(self) -> bool {
        matches!(self, Self::Open | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Sealed,
    BidQuoted,
    Matched,
    Batched,
    Proved,
    Settled,
    Rejected,
    Expired,
}

impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::BidQuoted => "bid_quoted",
            Self::Matched => "matched",
            Self::Batched => "batched",
            Self::Proved => "proved",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn marketable(self) -> bool {
        matches!(self, Self::Sealed | Self::BidQuoted | Self::Matched)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidSide {
    Maker,
    Taker,
    Sponsor,
}

impl BidSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Maker => "maker",
            Self::Taker => "taker",
            Self::Sponsor => "sponsor",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Open,
    Matched,
    Settled,
    Cancelled,
    Expired,
    Slashed,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Matched => "matched",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Matched,
    Batched,
    Settled,
    Disputed,
    Expired,
}

impl OrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    ProofPublished,
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
            Self::ProofPublished => "proof_published",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Accepted,
    Finalized,
    Reverted,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Accepted => "accepted",
            Self::Finalized => "finalized",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Claimed,
    Expired,
    Slashed,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    BadPreconfirmation,
    MissingReceipt,
    InvalidOrdering,
    PrivacyFenceLeak,
    DoubleSell,
    LateSettlement,
}

impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadPreconfirmation => "bad_preconfirmation",
            Self::MissingReceipt => "missing_receipt",
            Self::InvalidOrdering => "invalid_ordering",
            Self::PrivacyFenceLeak => "privacy_fence_leak",
            Self::DoubleSell => "double_sell",
            Self::LateSettlement => "late_settlement",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub max_tickets_per_batch: usize,
    pub max_active_slots: usize,
    pub max_active_bids: usize,
    pub ticket_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub finality_delay_blocks: u64,
    pub max_user_fee_bps: u64,
    pub target_fee_bps: u64,
    pub rebate_bps: u64,
    pub min_pq_security_bits: u16,
    pub sequencer_bond_micro_units: u64,
    pub require_privacy_fence: bool,
    pub require_pq_receipts: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET,
            max_tickets_per_batch: DEFAULT_MAX_TICKETS_PER_BATCH,
            max_active_slots: DEFAULT_MAX_ACTIVE_SLOTS,
            max_active_bids: DEFAULT_MAX_ACTIVE_BIDS,
            ticket_ttl_blocks: DEFAULT_TICKET_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            finality_delay_blocks: DEFAULT_FINALITY_DELAY_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_fee_bps: DEFAULT_TARGET_FEE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            sequencer_bond_micro_units: DEFAULT_SEQUENCER_BOND_MICRO_UNITS,
            require_privacy_fence: true,
            require_pq_receipts: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_nonempty("protocol_version", &self.protocol_version)?;
        require_nonempty("chain_id", &self.chain_id)?;
        require_nonempty("fee_asset_id", &self.fee_asset_id)?;
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target privacy set is below minimum".to_string());
        }
        if self.max_tickets_per_batch == 0 || self.max_active_slots == 0 {
            return Err("market capacity limits must be positive".to_string());
        }
        if self.ticket_ttl_blocks == 0
            || self.bid_ttl_blocks == 0
            || self.settlement_ttl_blocks == 0
        {
            return Err("ttl values must be positive".to_string());
        }
        if self.target_fee_bps > self.max_user_fee_bps || self.max_user_fee_bps > MAX_BPS {
            return Err("fee bps configuration is invalid".to_string());
        }
        if self.rebate_bps > self.max_user_fee_bps {
            return Err("rebate cannot exceed max user fee".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("pq security below runtime minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "max_tickets_per_batch": self.max_tickets_per_batch,
            "max_active_slots": self.max_active_slots,
            "max_active_bids": self.max_active_bids,
            "ticket_ttl_blocks": self.ticket_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "finality_delay_blocks": self.finality_delay_blocks,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_fee_bps": self.target_fee_bps,
            "rebate_bps": self.rebate_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "sequencer_bond_micro_units": self.sequencer_bond_micro_units,
            "require_privacy_fence": self.require_privacy_fence,
            "require_pq_receipts": self.require_pq_receipts,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub slot_sequence: u64,
    pub fence_sequence: u64,
    pub ticket_sequence: u64,
    pub bid_sequence: u64,
    pub order_sequence: u64,
    pub batch_sequence: u64,
    pub proof_sequence: u64,
    pub receipt_sequence: u64,
    pub rebate_sequence: u64,
    pub slashing_sequence: u64,
    pub checkpoint_sequence: u64,
    pub event_sequence: u64,
}

impl Counters {
    fn next_slot(&mut self) -> u64 {
        self.slot_sequence += 1;
        self.slot_sequence
    }

    fn next_fence(&mut self) -> u64 {
        self.fence_sequence += 1;
        self.fence_sequence
    }

    fn next_ticket(&mut self) -> u64 {
        self.ticket_sequence += 1;
        self.ticket_sequence
    }

    fn next_bid(&mut self) -> u64 {
        self.bid_sequence += 1;
        self.bid_sequence
    }

    fn next_order(&mut self) -> u64 {
        self.order_sequence += 1;
        self.order_sequence
    }

    fn next_batch(&mut self) -> u64 {
        self.batch_sequence += 1;
        self.batch_sequence
    }

    fn next_proof(&mut self) -> u64 {
        self.proof_sequence += 1;
        self.proof_sequence
    }

    fn next_receipt(&mut self) -> u64 {
        self.receipt_sequence += 1;
        self.receipt_sequence
    }

    fn next_rebate(&mut self) -> u64 {
        self.rebate_sequence += 1;
        self.rebate_sequence
    }

    fn next_slashing(&mut self) -> u64 {
        self.slashing_sequence += 1;
        self.slashing_sequence
    }

    fn next_checkpoint(&mut self) -> u64 {
        self.checkpoint_sequence += 1;
        self.checkpoint_sequence
    }

    fn next_event(&mut self) -> u64 {
        self.event_sequence += 1;
        self.event_sequence
    }

    pub fn public_record(&self) -> Value {
        json!({
            "slot_sequence": self.slot_sequence,
            "fence_sequence": self.fence_sequence,
            "ticket_sequence": self.ticket_sequence,
            "bid_sequence": self.bid_sequence,
            "order_sequence": self.order_sequence,
            "batch_sequence": self.batch_sequence,
            "proof_sequence": self.proof_sequence,
            "receipt_sequence": self.receipt_sequence,
            "rebate_sequence": self.rebate_sequence,
            "slashing_sequence": self.slashing_sequence,
            "checkpoint_sequence": self.checkpoint_sequence,
            "event_sequence": self.event_sequence,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub slot_root: String,
    pub privacy_fence_root: String,
    pub ticket_root: String,
    pub bid_root: String,
    pub order_root: String,
    pub batch_root: String,
    pub proof_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub slashing_root: String,
    pub checkpoint_root: String,
    pub event_root: String,
    pub config_root: String,
    pub counter_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "slot_root": self.slot_root,
            "privacy_fence_root": self.privacy_fence_root,
            "ticket_root": self.ticket_root,
            "bid_root": self.bid_root,
            "order_root": self.order_root,
            "batch_root": self.batch_root,
            "proof_root": self.proof_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "slashing_root": self.slashing_root,
            "checkpoint_root": self.checkpoint_root,
            "event_root": self.event_root,
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SequencerSlot {
    pub slot_id: String,
    pub lane: PreconfirmationLane,
    pub sequencer_commitment: String,
    pub pq_auth_key_root: String,
    pub capacity: u64,
    pub remaining_capacity: u64,
    pub bond_micro_units: u64,
    pub status: SlotStatus,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub created_at_height: u64,
}

impl SequencerSlot {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_preconfirmation_sequencer_slot",
            "slot_id": self.slot_id,
            "lane": self.lane.as_str(),
            "sequencer_commitment": self.sequencer_commitment,
            "pq_auth_key_root": self.pq_auth_key_root,
            "capacity": self.capacity,
            "remaining_capacity": self.remaining_capacity,
            "bond_micro_units": self.bond_micro_units,
            "status": self.status.as_str(),
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub lane: PreconfirmationLane,
    pub epoch: u64,
    pub privacy_set_size: u64,
    pub nullifier_root: String,
    pub encrypted_membership_root: String,
    pub pq_policy_root: String,
    pub expires_at_height: u64,
    pub created_at_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_preconfirmation_privacy_fence",
            "fence_id": self.fence_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "privacy_set_size": self.privacy_set_size,
            "nullifier_root": self.nullifier_root,
            "encrypted_membership_root": self.encrypted_membership_root,
            "pq_policy_root": self.pq_policy_root,
            "expires_at_height": self.expires_at_height,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreconfirmationTicket {
    pub ticket_id: String,
    pub lane: PreconfirmationLane,
    pub slot_id: String,
    pub privacy_fence_id: String,
    pub owner_commitment: String,
    pub sealed_call_root: String,
    pub state_read_root: String,
    pub state_write_commitment_root: String,
    pub nullifier_commitment: String,
    pub max_fee_micro_units: u64,
    pub status: TicketStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl PreconfirmationTicket {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_preconfirmation_ticket",
            "ticket_id": self.ticket_id,
            "lane": self.lane.as_str(),
            "slot_id": self.slot_id,
            "privacy_fence_id": self.privacy_fence_id,
            "owner_commitment": self.owner_commitment,
            "sealed_call_root": self.sealed_call_root,
            "state_read_root": self.state_read_root,
            "state_write_commitment_root": self.state_write_commitment_root,
            "nullifier_commitment": self.nullifier_commitment,
            "max_fee_micro_units": self.max_fee_micro_units,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptBid {
    pub bid_id: String,
    pub ticket_id: String,
    pub bidder_commitment: String,
    pub side: BidSide,
    pub lane: PreconfirmationLane,
    pub fee_bps: u64,
    pub bid_micro_units: u64,
    pub rebate_bps: u64,
    pub status: BidStatus,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl ReceiptBid {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_preconfirmation_receipt_bid",
            "bid_id": self.bid_id,
            "ticket_id": self.ticket_id,
            "bidder_commitment": self.bidder_commitment,
            "side": self.side.as_str(),
            "lane": self.lane.as_str(),
            "fee_bps": self.fee_bps,
            "bid_micro_units": self.bid_micro_units,
            "rebate_bps": self.rebate_bps,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptOrder {
    pub order_id: String,
    pub ticket_id: String,
    pub bid_id: String,
    pub slot_id: String,
    pub clearing_price_micro_units: u64,
    pub fee_bps: u64,
    pub status: OrderStatus,
    pub matched_at_height: u64,
}

impl ReceiptOrder {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_preconfirmation_receipt_order",
            "order_id": self.order_id,
            "ticket_id": self.ticket_id,
            "bid_id": self.bid_id,
            "slot_id": self.slot_id,
            "clearing_price_micro_units": self.clearing_price_micro_units,
            "fee_bps": self.fee_bps,
            "status": self.status.as_str(),
            "matched_at_height": self.matched_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub lane: PreconfirmationLane,
    pub order_ids: Vec<String>,
    pub order_root: String,
    pub ticket_root: String,
    pub aggregate_nullifier_root: String,
    pub fee_root: String,
    pub status: BatchStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl SettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_preconfirmation_settlement_batch",
            "batch_id": self.batch_id,
            "lane": self.lane.as_str(),
            "order_ids": self.order_ids,
            "order_root": self.order_root,
            "ticket_root": self.ticket_root,
            "aggregate_nullifier_root": self.aggregate_nullifier_root,
            "fee_root": self.fee_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptProof {
    pub proof_id: String,
    pub batch_id: String,
    pub proof_root: String,
    pub verifier_key_root: String,
    pub public_input_root: String,
    pub pq_signature_root: String,
    pub published_at_height: u64,
}

impl ReceiptProof {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_preconfirmation_receipt_proof",
            "proof_id": self.proof_id,
            "batch_id": self.batch_id,
            "proof_root": self.proof_root,
            "verifier_key_root": self.verifier_key_root,
            "public_input_root": self.public_input_root,
            "pq_signature_root": self.pq_signature_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub proof_id: String,
    pub state_delta_root: String,
    pub fee_settlement_root: String,
    pub status: ReceiptStatus,
    pub published_at_height: u64,
    pub finalizes_at_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_preconfirmation_settlement_receipt",
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "proof_id": self.proof_id,
            "state_delta_root": self.state_delta_root,
            "fee_settlement_root": self.fee_settlement_root,
            "status": self.status.as_str(),
            "published_at_height": self.published_at_height,
            "finalizes_at_height": self.finalizes_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub status: RebateStatus,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_preconfirmation_fee_rebate",
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "asset_id": self.asset_id,
            "amount_micro_units": self.amount_micro_units,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub slot_id: String,
    pub reason: SlashReason,
    pub evidence_root: String,
    pub penalty_micro_units: u64,
    pub resolved: bool,
    pub created_at_height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_preconfirmation_slashing_evidence",
            "evidence_id": self.evidence_id,
            "slot_id": self.slot_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "penalty_micro_units": self.penalty_micro_units,
            "resolved": self.resolved,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MarketCheckpoint {
    pub checkpoint_id: String,
    pub height: u64,
    pub epoch: u64,
    pub roots: Roots,
    pub active_ticket_count: usize,
    pub active_bid_count: usize,
    pub created_at_height: u64,
}

impl MarketCheckpoint {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fast_private_preconfirmation_market_checkpoint",
            "checkpoint_id": self.checkpoint_id,
            "height": self.height,
            "epoch": self.epoch,
            "roots": self.roots.public_record(),
            "active_ticket_count": self.active_ticket_count,
            "active_bid_count": self.active_bid_count,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub slots: BTreeMap<String, SequencerSlot>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub tickets: BTreeMap<String, PreconfirmationTicket>,
    pub bids: BTreeMap<String, ReceiptBid>,
    pub orders: BTreeMap<String, ReceiptOrder>,
    pub batches: BTreeMap<String, SettlementBatch>,
    pub proofs: BTreeMap<String, ReceiptProof>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub checkpoints: BTreeMap<String, MarketCheckpoint>,
    pub events: Vec<Value>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            height,
            epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            slots: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            tickets: BTreeMap::new(),
            bids: BTreeMap::new(),
            orders: BTreeMap::new(),
            batches: BTreeMap::new(),
            proofs: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            events: Vec::new(),
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH)?;
        let contract_fence = state.open_privacy_fence(
            PreconfirmationLane::ContractCall,
            state.epoch,
            state.config.target_privacy_set_size,
            &json!({"nullifiers": ["devnet-contract-preconf-nullifier-root"]}),
            &json!({"members": "encrypted contract call preconfirmation set"}),
        )?;
        let defi_fence = state.open_privacy_fence(
            PreconfirmationLane::DefiIntent,
            state.epoch,
            state.config.target_privacy_set_size * 2,
            &json!({"nullifiers": ["devnet-defi-preconf-nullifier-root"]}),
            &json!({"members": "encrypted defi preconfirmation set"}),
        )?;
        let slot_a = state.register_slot(
            PreconfirmationLane::ContractCall,
            "devnet:sequencer:fast-preconf-a",
            &json!({"suite": PQ_AUTH_SUITE, "key": "devnet-a"}),
            1_024,
            state.height,
            state.height + 32,
        )?;
        let slot_b = state.register_slot(
            PreconfirmationLane::DefiIntent,
            "devnet:sequencer:fast-preconf-b",
            &json!({"suite": PQ_AUTH_SUITE, "key": "devnet-b"}),
            2_048,
            state.height,
            state.height + 32,
        )?;
        let ticket_a = state.submit_ticket(SubmitTicketRequest {
            lane: PreconfirmationLane::ContractCall,
            slot_id: slot_a.slot_id.clone(),
            privacy_fence_id: contract_fence.fence_id.clone(),
            owner_commitment: "devnet:owner:preconf:contract:1".to_string(),
            sealed_call: json!({"call": "private_swap", "suite": SEALED_TICKET_SUITE}),
            state_read: json!({"read_set": ["pool:xmr-usdc"]}),
            state_write_commitment: json!({"write_commitment": "contract-write-1"}),
            max_fee_micro_units: 220,
        })?;
        let ticket_b = state.submit_ticket(SubmitTicketRequest {
            lane: PreconfirmationLane::DefiIntent,
            slot_id: slot_b.slot_id.clone(),
            privacy_fence_id: defi_fence.fence_id.clone(),
            owner_commitment: "devnet:owner:preconf:defi:2".to_string(),
            sealed_call: json!({"call": "clear_margin", "suite": SEALED_TICKET_SUITE}),
            state_read: json!({"read_set": ["vault:xmr", "perp:xmr-usd"]}),
            state_write_commitment: json!({"write_commitment": "defi-write-2"}),
            max_fee_micro_units: 320,
        })?;
        let bid_a = state.post_bid(
            &ticket_a.ticket_id,
            "devnet:bidder:maker:1",
            BidSide::Maker,
            180,
        )?;
        let bid_b = state.post_bid(
            &ticket_b.ticket_id,
            "devnet:bidder:sponsor:2",
            BidSide::Sponsor,
            240,
        )?;
        let order_a = state.match_order(&ticket_a.ticket_id, &bid_a.bid_id)?;
        let order_b = state.match_order(&ticket_b.ticket_id, &bid_b.bid_id)?;
        let batch_a = state
            .build_settlement_batch(PreconfirmationLane::ContractCall, vec![order_a.order_id])?;
        let proof_a = state.publish_proof(
            &batch_a.batch_id,
            &json!({"proof": "devnet-contract-preconfirmation-proof"}),
        )?;
        state.settle_batch(
            &batch_a.batch_id,
            &proof_a.proof_id,
            &json!({"state_delta": "contract-preconf-delta"}),
        )?;
        let batch_b = state
            .build_settlement_batch(PreconfirmationLane::DefiIntent, vec![order_b.order_id])?;
        let proof_b = state.publish_proof(
            &batch_b.batch_id,
            &json!({"proof": "devnet-defi-preconfirmation-proof"}),
        )?;
        state.settle_batch(
            &batch_b.batch_id,
            &proof_b.proof_id,
            &json!({"state_delta": "defi-preconf-delta"}),
        )?;
        state.record_checkpoint()?;
        Ok(state)
    }

    pub fn register_slot(
        &mut self,
        lane: PreconfirmationLane,
        sequencer_commitment: &str,
        pq_auth_key: &Value,
        capacity: u64,
        opens_at_height: u64,
        closes_at_height: u64,
    ) -> Result<SequencerSlot> {
        if self.slots.len() >= self.config.max_active_slots {
            return Err("active slot limit exceeded".to_string());
        }
        require_nonempty("sequencer_commitment", sequencer_commitment)?;
        if capacity == 0 {
            return Err("slot capacity must be positive".to_string());
        }
        if closes_at_height <= opens_at_height {
            return Err("slot closes before it opens".to_string());
        }
        let sequence = self.counters.next_slot();
        let slot = SequencerSlot {
            slot_id: slot_id(lane, sequencer_commitment, self.epoch, sequence),
            lane,
            sequencer_commitment: sequencer_commitment.to_string(),
            pq_auth_key_root: payload_root("SLOT-PQ-AUTH-KEY", pq_auth_key),
            capacity,
            remaining_capacity: capacity,
            bond_micro_units: self.config.sequencer_bond_micro_units,
            status: SlotStatus::Open,
            opens_at_height,
            closes_at_height,
            created_at_height: self.height,
        };
        self.slots.insert(slot.slot_id.clone(), slot.clone());
        self.emit_event("slot_registered", &slot.public_record());
        self.recompute_roots();
        Ok(slot)
    }

    pub fn open_privacy_fence(
        &mut self,
        lane: PreconfirmationLane,
        epoch: u64,
        privacy_set_size: u64,
        nullifier_payload: &Value,
        membership_payload: &Value,
    ) -> Result<PrivacyFence> {
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below minimum".to_string());
        }
        let sequence = self.counters.next_fence();
        let fence = PrivacyFence {
            fence_id: privacy_fence_id(lane, epoch, sequence),
            lane,
            epoch,
            privacy_set_size,
            nullifier_root: payload_root("PRIVACY-FENCE-NULLIFIER", nullifier_payload),
            encrypted_membership_root: payload_root("PRIVACY-FENCE-MEMBERSHIP", membership_payload),
            pq_policy_root: payload_root(
                "PRIVACY-FENCE-PQ-POLICY",
                &json!({"suite": PRIVACY_FENCE_SUITE, "lane": lane.as_str(), "epoch": epoch}),
            ),
            expires_at_height: self.height + self.config.settlement_ttl_blocks * 4,
            created_at_height: self.height,
        };
        self.privacy_fences
            .insert(fence.fence_id.clone(), fence.clone());
        self.emit_event("privacy_fence_opened", &fence.public_record());
        self.recompute_roots();
        Ok(fence)
    }

    pub fn submit_ticket(&mut self, request: SubmitTicketRequest) -> Result<PreconfirmationTicket> {
        require_nonempty("owner_commitment", &request.owner_commitment)?;
        let slot = self
            .slots
            .get_mut(&request.slot_id)
            .ok_or_else(|| "slot not found".to_string())?;
        if slot.lane != request.lane {
            return Err("slot lane mismatch".to_string());
        }
        if !slot.status.accepts_tickets() {
            return Err("slot cannot accept tickets".to_string());
        }
        if slot.remaining_capacity == 0 {
            return Err("slot capacity exhausted".to_string());
        }
        if self.height < slot.opens_at_height || self.height > slot.closes_at_height {
            return Err("slot is outside admission window".to_string());
        }
        let fence = self
            .privacy_fences
            .get(&request.privacy_fence_id)
            .ok_or_else(|| "privacy fence not found".to_string())?;
        if fence.lane != request.lane {
            return Err("privacy fence lane mismatch".to_string());
        }
        if fence.expires_at_height <= self.height {
            return Err("privacy fence expired".to_string());
        }
        if request.max_fee_micro_units == 0 {
            return Err("ticket max fee must be positive".to_string());
        }
        let sealed_call_root = payload_root("TICKET-SEALED-CALL", &request.sealed_call);
        let state_write_commitment_root =
            payload_root("TICKET-STATE-WRITE", &request.state_write_commitment);
        let sequence = self.counters.next_ticket();
        let ticket = PreconfirmationTicket {
            ticket_id: ticket_id(
                request.lane,
                &request.owner_commitment,
                &sealed_call_root,
                sequence,
            ),
            lane: request.lane,
            slot_id: request.slot_id,
            privacy_fence_id: request.privacy_fence_id,
            owner_commitment: request.owner_commitment,
            sealed_call_root,
            state_read_root: payload_root("TICKET-STATE-READ", &request.state_read),
            state_write_commitment_root,
            nullifier_commitment: nullifier_commitment(
                request.lane,
                &request.sealed_call,
                &request.state_write_commitment,
                sequence,
            ),
            max_fee_micro_units: request.max_fee_micro_units,
            status: TicketStatus::Sealed,
            submitted_at_height: self.height,
            expires_at_height: self.height + self.config.ticket_ttl_blocks,
        };
        slot.remaining_capacity = slot.remaining_capacity.saturating_sub(1);
        self.tickets
            .insert(ticket.ticket_id.clone(), ticket.clone());
        self.emit_event("ticket_submitted", &ticket.public_record());
        self.recompute_roots();
        Ok(ticket)
    }

    pub fn post_bid(
        &mut self,
        ticket_id: &str,
        bidder_commitment: &str,
        side: BidSide,
        bid_micro_units: u64,
    ) -> Result<ReceiptBid> {
        if self.bids.len() >= self.config.max_active_bids {
            return Err("active bid limit exceeded".to_string());
        }
        require_nonempty("bidder_commitment", bidder_commitment)?;
        let ticket = self
            .tickets
            .get(ticket_id)
            .ok_or_else(|| "ticket not found".to_string())?
            .clone();
        if !ticket.status.marketable() {
            return Err("ticket is not marketable".to_string());
        }
        if ticket.expires_at_height <= self.height {
            return Err("ticket expired".to_string());
        }
        if bid_micro_units == 0 || bid_micro_units > ticket.max_fee_micro_units {
            return Err("bid is outside ticket fee budget".to_string());
        }
        let sequence = self.counters.next_bid();
        let bid = ReceiptBid {
            bid_id: bid_id(ticket_id, bidder_commitment, side, sequence),
            ticket_id: ticket_id.to_string(),
            bidder_commitment: bidder_commitment.to_string(),
            side,
            lane: ticket.lane,
            fee_bps: ticket.lane.target_fee_bps(&self.config),
            bid_micro_units,
            rebate_bps: self.config.rebate_bps,
            status: BidStatus::Open,
            created_at_height: self.height,
            expires_at_height: self.height + self.config.bid_ttl_blocks,
        };
        self.bids.insert(bid.bid_id.clone(), bid.clone());
        if let Some(ticket) = self.tickets.get_mut(ticket_id) {
            ticket.status = TicketStatus::BidQuoted;
        }
        self.emit_event("bid_posted", &bid.public_record());
        self.recompute_roots();
        Ok(bid)
    }

    pub fn match_order(&mut self, ticket_id: &str, bid_id_value: &str) -> Result<ReceiptOrder> {
        let ticket = self
            .tickets
            .get(ticket_id)
            .ok_or_else(|| "ticket not found".to_string())?
            .clone();
        let bid = self
            .bids
            .get(bid_id_value)
            .ok_or_else(|| "bid not found".to_string())?
            .clone();
        if bid.ticket_id != ticket_id {
            return Err("bid does not belong to ticket".to_string());
        }
        if bid.status != BidStatus::Open {
            return Err("bid is not open".to_string());
        }
        if bid.expires_at_height <= self.height {
            return Err("bid expired".to_string());
        }
        if !ticket.status.marketable() {
            return Err("ticket cannot be matched".to_string());
        }
        let sequence = self.counters.next_order();
        let order = ReceiptOrder {
            order_id: order_id(ticket_id, bid_id_value, sequence),
            ticket_id: ticket_id.to_string(),
            bid_id: bid_id_value.to_string(),
            slot_id: ticket.slot_id.clone(),
            clearing_price_micro_units: bid.bid_micro_units,
            fee_bps: bid.fee_bps,
            status: OrderStatus::Matched,
            matched_at_height: self.height,
        };
        self.orders.insert(order.order_id.clone(), order.clone());
        if let Some(ticket) = self.tickets.get_mut(ticket_id) {
            ticket.status = TicketStatus::Matched;
        }
        if let Some(bid) = self.bids.get_mut(bid_id_value) {
            bid.status = BidStatus::Matched;
        }
        self.emit_event("order_matched", &order.public_record());
        self.recompute_roots();
        Ok(order)
    }

    pub fn build_settlement_batch(
        &mut self,
        lane: PreconfirmationLane,
        order_ids: Vec<String>,
    ) -> Result<SettlementBatch> {
        ensure_nonempty_unique("order_ids", &order_ids)?;
        if order_ids.len() > self.config.max_tickets_per_batch {
            return Err("batch ticket limit exceeded".to_string());
        }
        let mut tickets = Vec::new();
        let mut fee_items = Vec::new();
        let mut nullifiers = Vec::new();
        for order_id_value in &order_ids {
            let order = self
                .orders
                .get(order_id_value)
                .ok_or_else(|| "order not found".to_string())?;
            if order.status != OrderStatus::Matched {
                return Err("order is not matchable into batch".to_string());
            }
            let ticket = self
                .tickets
                .get(&order.ticket_id)
                .ok_or_else(|| "ticket not found".to_string())?;
            if ticket.lane != lane {
                return Err("order lane mismatch".to_string());
            }
            tickets.push(ticket.public_record());
            fee_items.push(json!({
                "order_id": order.order_id,
                "price": order.clearing_price_micro_units,
                "fee_bps": order.fee_bps,
            }));
            nullifiers.push(json!(ticket.nullifier_commitment));
        }
        let sequence = self.counters.next_batch();
        let batch = SettlementBatch {
            batch_id: batch_id(lane, self.epoch, sequence),
            lane,
            order_ids: order_ids.clone(),
            order_root: records_root(
                "BATCH-ORDERS",
                order_ids
                    .iter()
                    .filter_map(|id| self.orders.get(id))
                    .map(ReceiptOrder::public_record)
                    .collect(),
            ),
            ticket_root: records_root("BATCH-TICKETS", tickets),
            aggregate_nullifier_root: records_root("BATCH-NULLIFIERS", nullifiers),
            fee_root: records_root("BATCH-FEES", fee_items),
            status: BatchStatus::Sealed,
            opened_at_height: self.height,
            expires_at_height: self.height + self.config.settlement_ttl_blocks,
        };
        for order_id_value in &order_ids {
            if let Some(order) = self.orders.get_mut(order_id_value) {
                order.status = OrderStatus::Batched;
            }
            let ticket_id_value = self
                .orders
                .get(order_id_value)
                .map(|order| order.ticket_id.clone())
                .unwrap_or_default();
            if let Some(ticket) = self.tickets.get_mut(&ticket_id_value) {
                ticket.status = TicketStatus::Batched;
            }
        }
        self.batches.insert(batch.batch_id.clone(), batch.clone());
        self.emit_event("batch_built", &batch.public_record());
        self.recompute_roots();
        Ok(batch)
    }

    pub fn publish_proof(
        &mut self,
        batch_id_value: &str,
        proof_payload: &Value,
    ) -> Result<ReceiptProof> {
        let batch = self
            .batches
            .get_mut(batch_id_value)
            .ok_or_else(|| "batch not found".to_string())?;
        if batch.status != BatchStatus::Sealed {
            return Err("batch is not sealed".to_string());
        }
        batch.status = BatchStatus::ProofPublished;
        let sequence = self.counters.next_proof();
        let public_input = json!({
            "batch_id": batch.batch_id,
            "order_root": batch.order_root,
            "ticket_root": batch.ticket_root,
            "aggregate_nullifier_root": batch.aggregate_nullifier_root,
            "fee_root": batch.fee_root,
        });
        let proof = ReceiptProof {
            proof_id: proof_id(batch_id_value, sequence),
            batch_id: batch_id_value.to_string(),
            proof_root: payload_root("RECEIPT-PROOF", proof_payload),
            verifier_key_root: payload_root(
                "RECEIPT-PROOF-VERIFIER-KEY",
                &json!({"suite": RECEIPT_PROOF_SUITE, "pq_security_bits": self.config.min_pq_security_bits}),
            ),
            public_input_root: payload_root("RECEIPT-PROOF-PUBLIC-INPUT", &public_input),
            pq_signature_root: payload_root(
                "RECEIPT-PROOF-PQ-SIGNATURE",
                &json!({"suite": PQ_AUTH_SUITE, "batch_id": batch_id_value}),
            ),
            published_at_height: self.height,
        };
        self.proofs.insert(proof.proof_id.clone(), proof.clone());
        self.emit_event("proof_published", &proof.public_record());
        self.recompute_roots();
        Ok(proof)
    }

    pub fn settle_batch(
        &mut self,
        batch_id_value: &str,
        proof_id_value: &str,
        state_delta: &Value,
    ) -> Result<SettlementReceipt> {
        let proof = self
            .proofs
            .get(proof_id_value)
            .ok_or_else(|| "proof not found".to_string())?;
        if proof.batch_id != batch_id_value {
            return Err("proof batch mismatch".to_string());
        }
        let batch = self
            .batches
            .get_mut(batch_id_value)
            .ok_or_else(|| "batch not found".to_string())?;
        if batch.status != BatchStatus::ProofPublished {
            return Err("batch is not proof-published".to_string());
        }
        batch.status = BatchStatus::Settled;
        let order_ids = batch.order_ids.clone();
        let sequence = self.counters.next_receipt();
        let receipt = SettlementReceipt {
            receipt_id: receipt_id(batch_id_value, proof_id_value, sequence),
            batch_id: batch_id_value.to_string(),
            proof_id: proof_id_value.to_string(),
            state_delta_root: payload_root("SETTLEMENT-STATE-DELTA", state_delta),
            fee_settlement_root: batch.fee_root.clone(),
            status: ReceiptStatus::Published,
            published_at_height: self.height,
            finalizes_at_height: self.height + self.config.finality_delay_blocks,
        };
        self.receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        let mut rebate_tickets = Vec::new();
        for order_id_value in &order_ids {
            if let Some(order) = self.orders.get_mut(order_id_value) {
                order.status = OrderStatus::Settled;
                if let Some(ticket) = self.tickets.get_mut(&order.ticket_id) {
                    ticket.status = TicketStatus::Settled;
                    rebate_tickets.push(ticket.clone());
                }
                if let Some(bid) = self.bids.get_mut(&order.bid_id) {
                    bid.status = BidStatus::Settled;
                }
            }
        }
        for ticket in &rebate_tickets {
            self.issue_rebate_for_ticket(&receipt, ticket)?;
        }
        self.emit_event("batch_settled", &receipt.public_record());
        self.recompute_roots();
        Ok(receipt)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        slot_id_value: &str,
        reason: SlashReason,
        evidence_payload: &Value,
        penalty_micro_units: u64,
    ) -> Result<SlashingEvidence> {
        let slot = self
            .slots
            .get_mut(slot_id_value)
            .ok_or_else(|| "slot not found".to_string())?;
        let evidence_root = payload_root("SLASHING-EVIDENCE", evidence_payload);
        let sequence = self.counters.next_slashing();
        let evidence = SlashingEvidence {
            evidence_id: slashing_evidence_id(slot_id_value, reason, &evidence_root, sequence),
            slot_id: slot_id_value.to_string(),
            reason,
            evidence_root,
            penalty_micro_units,
            resolved: false,
            created_at_height: self.height,
        };
        slot.status = SlotStatus::Slashed;
        slot.bond_micro_units = slot.bond_micro_units.saturating_sub(penalty_micro_units);
        self.slashing_evidence
            .insert(evidence.evidence_id.clone(), evidence.clone());
        self.emit_event("slashing_evidence_submitted", &evidence.public_record());
        self.recompute_roots();
        Ok(evidence)
    }

    pub fn claim_rebate(&mut self, rebate_id_value: &str) -> Result<()> {
        let rebate = self
            .rebates
            .get_mut(rebate_id_value)
            .ok_or_else(|| "rebate not found".to_string())?;
        if rebate.status != RebateStatus::Accrued {
            return Err("rebate is not claimable".to_string());
        }
        if rebate.expires_at_height <= self.height {
            rebate.status = RebateStatus::Expired;
            self.recompute_roots();
            return Err("rebate expired".to_string());
        }
        rebate.status = RebateStatus::Claimed;
        self.emit_event("rebate_claimed", &json!({"rebate_id": rebate_id_value}));
        self.recompute_roots();
        Ok(())
    }

    pub fn advance_height(&mut self, new_height: u64) -> Result<()> {
        if new_height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = new_height;
        self.expire_old_records();
        self.recompute_roots();
        Ok(())
    }

    pub fn record_checkpoint(&mut self) -> Result<MarketCheckpoint> {
        self.recompute_roots();
        let sequence = self.counters.next_checkpoint();
        let checkpoint = MarketCheckpoint {
            checkpoint_id: checkpoint_id(self.height, self.epoch, sequence),
            height: self.height,
            epoch: self.epoch,
            roots: self.roots.clone(),
            active_ticket_count: self
                .tickets
                .values()
                .filter(|ticket| ticket.status.marketable())
                .count(),
            active_bid_count: self
                .bids
                .values()
                .filter(|bid| bid.status == BidStatus::Open)
                .count(),
            created_at_height: self.height,
        };
        self.checkpoints
            .insert(checkpoint.checkpoint_id.clone(), checkpoint.clone());
        self.emit_event("checkpoint_recorded", &checkpoint.public_record());
        self.recompute_roots();
        Ok(checkpoint)
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn roots(&self) -> &Roots {
        &self.roots
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_fast_private_preconfirmation_receipt_market_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "sealed_ticket_suite": SEALED_TICKET_SUITE,
            "receipt_proof_suite": RECEIPT_PROOF_SUITE,
            "privacy_fence_suite": PRIVACY_FENCE_SUITE,
            "low_fee_rebate_suite": LOW_FEE_REBATE_SUITE,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots_without_self_reference(&self.roots),
            "slots": self.slots.values().map(SequencerSlot::public_record).collect::<Vec<_>>(),
            "privacy_fences": self.privacy_fences.values().map(PrivacyFence::public_record).collect::<Vec<_>>(),
            "tickets": self.tickets.values().map(PreconfirmationTicket::public_record).collect::<Vec<_>>(),
            "bids": self.bids.values().map(ReceiptBid::public_record).collect::<Vec<_>>(),
            "orders": self.orders.values().map(ReceiptOrder::public_record).collect::<Vec<_>>(),
            "batches": self.batches.values().map(SettlementBatch::public_record).collect::<Vec<_>>(),
            "proofs": self.proofs.values().map(ReceiptProof::public_record).collect::<Vec<_>>(),
            "receipts": self.receipts.values().map(SettlementReceipt::public_record).collect::<Vec<_>>(),
            "rebates": self.rebates.values().map(FeeRebate::public_record).collect::<Vec<_>>(),
            "slashing_evidence": self.slashing_evidence.values().map(SlashingEvidence::public_record).collect::<Vec<_>>(),
            "checkpoints": self.checkpoints.values().map(MarketCheckpoint::public_record).collect::<Vec<_>>(),
            "events": self.events.clone(),
        })
    }

    fn issue_rebate_for_ticket(
        &mut self,
        receipt: &SettlementReceipt,
        ticket: &PreconfirmationTicket,
    ) -> Result<()> {
        let amount = ticket
            .max_fee_micro_units
            .saturating_mul(self.config.rebate_bps)
            / MAX_BPS;
        let sequence = self.counters.next_rebate();
        let rebate = FeeRebate {
            rebate_id: rebate_id(&receipt.receipt_id, &ticket.owner_commitment, sequence),
            receipt_id: receipt.receipt_id.clone(),
            beneficiary_commitment: ticket.owner_commitment.clone(),
            asset_id: self.config.fee_asset_id.clone(),
            amount_micro_units: amount,
            status: RebateStatus::Accrued,
            created_at_height: self.height,
            expires_at_height: self.height + self.config.settlement_ttl_blocks * 4,
        };
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        Ok(())
    }

    fn expire_old_records(&mut self) {
        for ticket in self.tickets.values_mut() {
            if ticket.status.marketable() && ticket.expires_at_height <= self.height {
                ticket.status = TicketStatus::Expired;
            }
        }
        for bid in self.bids.values_mut() {
            if bid.status == BidStatus::Open && bid.expires_at_height <= self.height {
                bid.status = BidStatus::Expired;
            }
        }
        for batch in self.batches.values_mut() {
            if matches!(batch.status, BatchStatus::Open | BatchStatus::Sealed)
                && batch.expires_at_height <= self.height
            {
                batch.status = BatchStatus::Expired;
            }
        }
        for rebate in self.rebates.values_mut() {
            if rebate.status == RebateStatus::Accrued && rebate.expires_at_height <= self.height {
                rebate.status = RebateStatus::Expired;
            }
        }
    }

    fn emit_event(&mut self, event_kind: &str, payload: &Value) {
        let sequence = self.counters.next_event();
        self.events.push(json!({
            "event_id": event_id(event_kind, self.height, sequence),
            "kind": event_kind,
            "height": self.height,
            "sequence": sequence,
            "payload_root": payload_root("EVENT-PAYLOAD", payload),
        }));
    }

    fn recompute_roots(&mut self) {
        self.roots.slot_root = records_root(
            "PRECONFIRMATION-SLOTS",
            self.slots
                .values()
                .map(SequencerSlot::public_record)
                .collect(),
        );
        self.roots.privacy_fence_root = records_root(
            "PRECONFIRMATION-PRIVACY-FENCES",
            self.privacy_fences
                .values()
                .map(PrivacyFence::public_record)
                .collect(),
        );
        self.roots.ticket_root = records_root(
            "PRECONFIRMATION-TICKETS",
            self.tickets
                .values()
                .map(PreconfirmationTicket::public_record)
                .collect(),
        );
        self.roots.bid_root = records_root(
            "PRECONFIRMATION-BIDS",
            self.bids.values().map(ReceiptBid::public_record).collect(),
        );
        self.roots.order_root = records_root(
            "PRECONFIRMATION-ORDERS",
            self.orders
                .values()
                .map(ReceiptOrder::public_record)
                .collect(),
        );
        self.roots.batch_root = records_root(
            "PRECONFIRMATION-BATCHES",
            self.batches
                .values()
                .map(SettlementBatch::public_record)
                .collect(),
        );
        self.roots.proof_root = records_root(
            "PRECONFIRMATION-PROOFS",
            self.proofs
                .values()
                .map(ReceiptProof::public_record)
                .collect(),
        );
        self.roots.receipt_root = records_root(
            "PRECONFIRMATION-RECEIPTS",
            self.receipts
                .values()
                .map(SettlementReceipt::public_record)
                .collect(),
        );
        self.roots.rebate_root = records_root(
            "PRECONFIRMATION-REBATES",
            self.rebates
                .values()
                .map(FeeRebate::public_record)
                .collect(),
        );
        self.roots.slashing_root = records_root(
            "PRECONFIRMATION-SLASHING",
            self.slashing_evidence
                .values()
                .map(SlashingEvidence::public_record)
                .collect(),
        );
        self.roots.checkpoint_root = records_root(
            "PRECONFIRMATION-CHECKPOINTS",
            self.checkpoints
                .values()
                .map(MarketCheckpoint::public_record)
                .collect(),
        );
        self.roots.event_root = records_root("PRECONFIRMATION-EVENTS", self.events.clone());
        self.roots.config_root =
            payload_root("PRECONFIRMATION-CONFIG", &self.config.public_record());
        self.roots.counter_root =
            payload_root("PRECONFIRMATION-COUNTERS", &self.counters.public_record());
        self.roots.state_root = self.state_root();
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitTicketRequest {
    pub lane: PreconfirmationLane,
    pub slot_id: String,
    pub privacy_fence_id: String,
    pub owner_commitment: String,
    pub sealed_call: Value,
    pub state_read: Value,
    pub state_write_commitment: Value,
    pub max_fee_micro_units: u64,
}

pub fn private_l2_fast_private_preconfirmation_receipt_market_runtime_public_record() -> Value {
    State::devnet()
        .expect("devnet fast private preconfirmation receipt market")
        .public_record()
}

pub fn private_l2_fast_private_preconfirmation_receipt_market_runtime_state_root() -> String {
    State::devnet()
        .expect("devnet fast private preconfirmation receipt market")
        .state_root()
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

pub fn slot_id(
    lane: PreconfirmationLane,
    sequencer_commitment: &str,
    epoch: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-PRECONFIRMATION-RECEIPT-MARKET:SLOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(sequencer_commitment),
            HashPart::U64(epoch),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn privacy_fence_id(lane: PreconfirmationLane, epoch: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-PRECONFIRMATION-RECEIPT-MARKET:PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::U64(epoch),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn ticket_id(
    lane: PreconfirmationLane,
    owner_commitment: &str,
    sealed_call_root: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-PRECONFIRMATION-RECEIPT-MARKET:TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(owner_commitment),
            HashPart::Str(sealed_call_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn bid_id(
    ticket_id_value: &str,
    bidder_commitment: &str,
    side: BidSide,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-PRECONFIRMATION-RECEIPT-MARKET:BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ticket_id_value),
            HashPart::Str(bidder_commitment),
            HashPart::Str(side.as_str()),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn order_id(ticket_id_value: &str, bid_id_value: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-PRECONFIRMATION-RECEIPT-MARKET:ORDER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(ticket_id_value),
            HashPart::Str(bid_id_value),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn batch_id(lane: PreconfirmationLane, epoch: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-PRECONFIRMATION-RECEIPT-MARKET:BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::U64(epoch),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn proof_id(batch_id_value: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-PRECONFIRMATION-RECEIPT-MARKET:PROOF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id_value),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn receipt_id(batch_id_value: &str, proof_id_value: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-PRECONFIRMATION-RECEIPT-MARKET:RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(batch_id_value),
            HashPart::Str(proof_id_value),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn rebate_id(receipt_id_value: &str, beneficiary_commitment: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-PRECONFIRMATION-RECEIPT-MARKET:REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id_value),
            HashPart::Str(beneficiary_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn slashing_evidence_id(
    slot_id_value: &str,
    reason: SlashReason,
    evidence_root: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-PRECONFIRMATION-RECEIPT-MARKET:SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(slot_id_value),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn checkpoint_id(height: u64, epoch: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-PRECONFIRMATION-RECEIPT-MARKET:CHECKPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(height),
            HashPart::U64(epoch),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn event_id(event_kind: &str, height: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-PRECONFIRMATION-RECEIPT-MARKET:EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn nullifier_commitment(
    lane: PreconfirmationLane,
    sealed_call: &Value,
    state_write_commitment: &Value,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PRIVATE-PRECONFIRMATION-RECEIPT-MARKET:NULLIFIER-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Json(sealed_call),
            HashPart::Json(state_write_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FAST-PRIVATE-PRECONFIRMATION-RECEIPT-MARKET:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FAST-PRIVATE-PRECONFIRMATION-RECEIPT-MARKET:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("STATE-ROOT", record)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("PRIVATE-L2-FAST-PRIVATE-PRECONFIRMATION-RECEIPT-MARKET:{domain}"),
        records,
    )
}

fn records_root(domain: &str, records: Vec<Value>) -> String {
    public_record_root(domain, &records)
}

fn roots_without_self_reference(roots: &Roots) -> Value {
    json!({
        "slot_root": roots.slot_root,
        "privacy_fence_root": roots.privacy_fence_root,
        "ticket_root": roots.ticket_root,
        "bid_root": roots.bid_root,
        "order_root": roots.order_root,
        "batch_root": roots.batch_root,
        "proof_root": roots.proof_root,
        "receipt_root": roots.receipt_root,
        "rebate_root": roots.rebate_root,
        "slashing_root": roots.slashing_root,
        "checkpoint_root": roots.checkpoint_root,
        "event_root": roots.event_root,
        "config_root": roots.config_root,
        "counter_root": roots.counter_root,
    })
}

fn require_nonempty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_nonempty_unique(label: &str, values: &[String]) -> Result<()> {
    if values.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() {
            return Err(format!("{label} cannot contain empty values"));
        }
        if !seen.insert(value) {
            return Err(format!("{label} contains duplicates"));
        }
    }
    Ok(())
}
