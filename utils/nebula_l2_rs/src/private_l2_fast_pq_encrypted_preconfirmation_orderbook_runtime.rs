use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqEncryptedPreconfirmationOrderbookRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-encrypted-preconfirmation-orderbook-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SIGNATURE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PQ_KEM_SUITE: &str = "ML-KEM-1024-threshold-envelope";
pub const ENCRYPTED_ORDER_SUITE: &str = "threshold-pq-sealed-order-commitment-v1";
pub const PRECONFIRMATION_SUITE: &str = "fast-pq-sequencer-ticket-v1";
pub const PRIVATE_AUCTION_SUITE: &str = "batch-uniform-clearing-private-orderbook-v1";
pub const CONTRACT_BUNDLE_SUITE: &str = "confidential-contract-call-bundle-intent-v1";
pub const NULLIFIER_SUITE: &str = "zk-nullifier-private-cancel-accounting-v1";
pub const DEVNET_L2_HEIGHT: u64 = 1_880_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_260_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 1_024;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 8_192;
pub const DEFAULT_TARGET_PRECONF_MS: u64 = 250;
pub const DEFAULT_MAX_PRECONF_MS: u64 = 900;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 6;
pub const DEFAULT_TICKET_TTL_BLOCKS: u64 = 10;
pub const DEFAULT_BUNDLE_TTL_BLOCKS: u64 = 12;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 32;
pub const DEFAULT_BASE_FEE_MICRO_UNITS: u64 = 300;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 25;
pub const DEFAULT_SLASH_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_SOLVER_BOND_MICRO_UNITS: u64 = 5_000_000;
pub const DEFAULT_SEQUENCER_BOND_MICRO_UNITS: u64 = 50_000_000;
pub const DEFAULT_REBATE_POOL_MICRO_UNITS: u64 = 250_000_000;
pub const DEFAULT_MAX_ORDER_COMMITMENTS: usize = 1_048_576;
pub const DEFAULT_MAX_APPROVALS: usize = 262_144;
pub const DEFAULT_MAX_TICKETS: usize = 524_288;
pub const DEFAULT_MAX_AUCTIONS: usize = 131_072;
pub const DEFAULT_MAX_SOLVER_BIDS: usize = 1_048_576;
pub const DEFAULT_MAX_BUNDLE_INTENTS: usize = 524_288;
pub const DEFAULT_MAX_REBATES: usize = 524_288;
pub const DEFAULT_MAX_NULLIFIERS: usize = 2_097_152;
pub const DEFAULT_MAX_RECEIPTS: usize = 524_288;
pub const DEFAULT_MAX_SLA_SNAPSHOTS: usize = 131_072;
pub const DEFAULT_MAX_SLASHING_EVIDENCE: usize = 131_072;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderSide {
    Buy,
    Sell,
    Mint,
    Burn,
    Lend,
    Borrow,
    ContractCall,
}

impl OrderSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Buy => "buy",
            Self::Sell => "sell",
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::Lend => "lend",
            Self::Borrow => "borrow",
            Self::ContractCall => "contract_call",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::ContractCall => 160,
            Self::Borrow => 130,
            Self::Lend => 120,
            Self::Buy => 112,
            Self::Sell => 112,
            Self::Mint => 96,
            Self::Burn => 96,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetClass {
    Monero,
    ConfidentialToken,
    StableAsset,
    LiquidityShare,
    PerpetualPosition,
    LendingNote,
    ContractState,
}

impl AssetClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Monero => "monero",
            Self::ConfidentialToken => "confidential_token",
            Self::StableAsset => "stable_asset",
            Self::LiquidityShare => "liquidity_share",
            Self::PerpetualPosition => "perpetual_position",
            Self::LendingNote => "lending_note",
            Self::ContractState => "contract_state",
        }
    }

    pub fn privacy_floor(self) -> u64 {
        match self {
            Self::Monero => 16_384,
            Self::ContractState => 8_192,
            Self::ConfidentialToken => 4_096,
            Self::StableAsset => 2_048,
            Self::PerpetualPosition => 2_048,
            Self::LendingNote => 2_048,
            Self::LiquidityShare => 1_024,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Submitted,
    Approved,
    Ticketed,
    Batched,
    Matched,
    Settled,
    Cancelled,
    Expired,
    Slashed,
}

impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Approved => "approved",
            Self::Ticketed => "ticketed",
            Self::Batched => "batched",
            Self::Matched => "matched",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Superseded,
    Slashed,
}

impl ApprovalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Issued,
    Bound,
    Included,
    Settled,
    Expired,
    Cancelled,
    Slashed,
}

impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Bound => "bound",
            Self::Included => "included",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Open,
    Sealed,
    Solving,
    Clearing,
    Settled,
    Cancelled,
    Expired,
    Challenged,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Solving => "solving",
            Self::Clearing => "clearing",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Posted,
    Shortlisted,
    Selected,
    Rejected,
    Settled,
    Expired,
    Slashed,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Shortlisted => "shortlisted",
            Self::Selected => "selected",
            Self::Rejected => "rejected",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    Submitted,
    Approved,
    Ticketed,
    Executing,
    Settled,
    Cancelled,
    Expired,
    Reverted,
}

impl BundleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Approved => "approved",
            Self::Ticketed => "ticketed",
            Self::Executing => "executing",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Reserved,
    Earned,
    Paid,
    ClawedBack,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Earned => "earned",
            Self::Paid => "paid",
            Self::ClawedBack => "clawed_back",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NullifierKind {
    OrderCancel,
    BundleCancel,
    TicketSpend,
    RebateClaim,
    SolverBidSpend,
    SettlementSpend,
    SlashingClaim,
}

impl NullifierKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OrderCancel => "order_cancel",
            Self::BundleCancel => "bundle_cancel",
            Self::TicketSpend => "ticket_spend",
            Self::RebateClaim => "rebate_claim",
            Self::SolverBidSpend => "solver_bid_spend",
            Self::SettlementSpend => "settlement_spend",
            Self::SlashingClaim => "slashing_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Applied,
    Finalized,
    Reverted,
    Challenged,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::Finalized => "finalized",
            Self::Reverted => "reverted",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaStatus {
    Healthy,
    Degraded,
    Breached,
    Recovering,
}

impl SlaStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Breached => "breached",
            Self::Recovering => "recovering",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    InvalidPqApproval,
    MissedPreconfirmationSla,
    EquivocatedTicket,
    OrderRevealLeak,
    InvalidClearingProof,
    Censorship,
    SolverDefault,
    RebateFraud,
    NullifierReplay,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqApproval => "invalid_pq_approval",
            Self::MissedPreconfirmationSla => "missed_preconfirmation_sla",
            Self::EquivocatedTicket => "equivocated_ticket",
            Self::OrderRevealLeak => "order_reveal_leak",
            Self::InvalidClearingProof => "invalid_clearing_proof",
            Self::Censorship => "censorship",
            Self::SolverDefault => "solver_default",
            Self::RebateFraud => "rebate_fraud",
            Self::NullifierReplay => "nullifier_replay",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub target_preconfirmation_ms: u64,
    pub max_preconfirmation_ms: u64,
    pub auction_ttl_blocks: u64,
    pub ticket_ttl_blocks: u64,
    pub bundle_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub base_fee_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub slash_window_blocks: u64,
    pub solver_bond_micro_units: u64,
    pub sequencer_bond_micro_units: u64,
    pub rebate_pool_micro_units: u64,
    pub max_order_commitments: usize,
    pub max_approvals: usize,
    pub max_tickets: usize,
    pub max_auctions: usize,
    pub max_solver_bids: usize,
    pub max_bundle_intents: usize,
    pub max_rebates: usize,
    pub max_nullifiers: usize,
    pub max_receipts: usize,
    pub max_sla_snapshots: usize,
    pub max_slashing_evidence: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            target_preconfirmation_ms: DEFAULT_TARGET_PRECONF_MS,
            max_preconfirmation_ms: DEFAULT_MAX_PRECONF_MS,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            ticket_ttl_blocks: DEFAULT_TICKET_TTL_BLOCKS,
            bundle_ttl_blocks: DEFAULT_BUNDLE_TTL_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            base_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            slash_window_blocks: DEFAULT_SLASH_WINDOW_BLOCKS,
            solver_bond_micro_units: DEFAULT_SOLVER_BOND_MICRO_UNITS,
            sequencer_bond_micro_units: DEFAULT_SEQUENCER_BOND_MICRO_UNITS,
            rebate_pool_micro_units: DEFAULT_REBATE_POOL_MICRO_UNITS,
            max_order_commitments: DEFAULT_MAX_ORDER_COMMITMENTS,
            max_approvals: DEFAULT_MAX_APPROVALS,
            max_tickets: DEFAULT_MAX_TICKETS,
            max_auctions: DEFAULT_MAX_AUCTIONS,
            max_solver_bids: DEFAULT_MAX_SOLVER_BIDS,
            max_bundle_intents: DEFAULT_MAX_BUNDLE_INTENTS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_sla_snapshots: DEFAULT_MAX_SLA_SNAPSHOTS,
            max_slashing_evidence: DEFAULT_MAX_SLASHING_EVIDENCE,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "hash_suite": HASH_SUITE,
            "pq_signature_suite": PQ_SIGNATURE_SUITE,
            "pq_kem_suite": PQ_KEM_SUITE,
            "encrypted_order_suite": ENCRYPTED_ORDER_SUITE,
            "preconfirmation_suite": PRECONFIRMATION_SUITE,
            "private_auction_suite": PRIVATE_AUCTION_SUITE,
            "contract_bundle_suite": CONTRACT_BUNDLE_SUITE,
            "nullifier_suite": NULLIFIER_SUITE,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "target_preconfirmation_ms": self.target_preconfirmation_ms,
            "max_preconfirmation_ms": self.max_preconfirmation_ms,
            "auction_ttl_blocks": self.auction_ttl_blocks,
            "ticket_ttl_blocks": self.ticket_ttl_blocks,
            "bundle_ttl_blocks": self.bundle_ttl_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "base_fee_micro_units": self.base_fee_micro_units,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "slash_window_blocks": self.slash_window_blocks,
            "solver_bond_micro_units": self.solver_bond_micro_units,
            "sequencer_bond_micro_units": self.sequencer_bond_micro_units,
            "rebate_pool_micro_units": self.rebate_pool_micro_units,
            "max_order_commitments": self.max_order_commitments,
            "max_approvals": self.max_approvals,
            "max_tickets": self.max_tickets,
            "max_auctions": self.max_auctions,
            "max_solver_bids": self.max_solver_bids,
            "max_bundle_intents": self.max_bundle_intents,
            "max_rebates": self.max_rebates,
            "max_nullifiers": self.max_nullifiers,
            "max_receipts": self.max_receipts,
            "max_sla_snapshots": self.max_sla_snapshots,
            "max_slashing_evidence": self.max_slashing_evidence,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub order_commitments: usize,
    pub pq_approvals: usize,
    pub preconfirmation_tickets: usize,
    pub batch_auctions: usize,
    pub solver_bids: usize,
    pub bundle_intents: usize,
    pub fee_rebates: usize,
    pub cancellation_nullifiers: usize,
    pub settlement_receipts: usize,
    pub sla_snapshots: usize,
    pub slashing_evidence: usize,
    pub accepted_orders: u64,
    pub cancelled_orders: u64,
    pub settled_orders: u64,
    pub rejected_orders: u64,
    pub total_fee_micro_units: u128,
    pub total_rebate_micro_units: u128,
    pub total_slash_micro_units: u128,
    pub average_preconfirmation_ms: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "order_commitments": self.order_commitments,
            "pq_approvals": self.pq_approvals,
            "preconfirmation_tickets": self.preconfirmation_tickets,
            "batch_auctions": self.batch_auctions,
            "solver_bids": self.solver_bids,
            "bundle_intents": self.bundle_intents,
            "fee_rebates": self.fee_rebates,
            "cancellation_nullifiers": self.cancellation_nullifiers,
            "settlement_receipts": self.settlement_receipts,
            "sla_snapshots": self.sla_snapshots,
            "slashing_evidence": self.slashing_evidence,
            "accepted_orders": self.accepted_orders,
            "cancelled_orders": self.cancelled_orders,
            "settled_orders": self.settled_orders,
            "rejected_orders": self.rejected_orders,
            "total_fee_micro_units": self.total_fee_micro_units.to_string(),
            "total_rebate_micro_units": self.total_rebate_micro_units.to_string(),
            "total_slash_micro_units": self.total_slash_micro_units.to_string(),
            "average_preconfirmation_ms": self.average_preconfirmation_ms,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub order_commitment_root: String,
    pub pq_approval_root: String,
    pub preconfirmation_ticket_root: String,
    pub batch_auction_root: String,
    pub solver_bid_root: String,
    pub bundle_intent_root: String,
    pub fee_rebate_root: String,
    pub cancellation_nullifier_root: String,
    pub settlement_receipt_root: String,
    pub sla_snapshot_root: String,
    pub slashing_evidence_root: String,
    pub counters_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "order_commitment_root": self.order_commitment_root,
            "pq_approval_root": self.pq_approval_root,
            "preconfirmation_ticket_root": self.preconfirmation_ticket_root,
            "batch_auction_root": self.batch_auction_root,
            "solver_bid_root": self.solver_bid_root,
            "bundle_intent_root": self.bundle_intent_root,
            "fee_rebate_root": self.fee_rebate_root,
            "cancellation_nullifier_root": self.cancellation_nullifier_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "sla_snapshot_root": self.sla_snapshot_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedOrderCommitmentRequest {
    pub owner_commitment: String,
    pub market_id: String,
    pub pair_id: String,
    pub side: OrderSide,
    pub asset_class: AssetClass,
    pub encrypted_order_payload_root: String,
    pub order_commitment: String,
    pub reveal_key_commitment: String,
    pub nullifier_commitment: String,
    pub account_nonce_commitment: String,
    pub max_fee_micro_units: u64,
    pub fee_cap_bps: u64,
    pub notional_commitment: String,
    pub limit_price_commitment: String,
    pub privacy_set_size: u64,
    pub pq_ciphertext_root: String,
    pub pq_public_key_root: String,
    pub proof_root: String,
    pub submitted_height: u64,
    pub expires_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedOrderCommitment {
    pub order_id: String,
    pub owner_commitment: String,
    pub market_id: String,
    pub pair_id: String,
    pub side: OrderSide,
    pub asset_class: AssetClass,
    pub encrypted_order_payload_root: String,
    pub order_commitment: String,
    pub reveal_key_commitment: String,
    pub nullifier_commitment: String,
    pub account_nonce_commitment: String,
    pub max_fee_micro_units: u64,
    pub fee_cap_bps: u64,
    pub notional_commitment: String,
    pub limit_price_commitment: String,
    pub privacy_set_size: u64,
    pub pq_ciphertext_root: String,
    pub pq_public_key_root: String,
    pub proof_root: String,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub status: CommitmentStatus,
    pub priority_score: u64,
}

impl EncryptedOrderCommitment {
    pub fn from_request(config: &Config, request: EncryptedOrderCommitmentRequest) -> Result<Self> {
        ensure_non_empty("owner_commitment", &request.owner_commitment)?;
        ensure_non_empty("market_id", &request.market_id)?;
        ensure_non_empty("pair_id", &request.pair_id)?;
        ensure_non_empty(
            "encrypted_order_payload_root",
            &request.encrypted_order_payload_root,
        )?;
        ensure_non_empty("order_commitment", &request.order_commitment)?;
        ensure_non_empty("reveal_key_commitment", &request.reveal_key_commitment)?;
        ensure_non_empty("nullifier_commitment", &request.nullifier_commitment)?;
        ensure_non_empty(
            "account_nonce_commitment",
            &request.account_nonce_commitment,
        )?;
        ensure_non_empty("notional_commitment", &request.notional_commitment)?;
        ensure_non_empty("limit_price_commitment", &request.limit_price_commitment)?;
        ensure_non_empty("pq_ciphertext_root", &request.pq_ciphertext_root)?;
        ensure_non_empty("pq_public_key_root", &request.pq_public_key_root)?;
        ensure_non_empty("proof_root", &request.proof_root)?;
        ensure_bps("fee_cap_bps", request.fee_cap_bps)?;
        if request.fee_cap_bps > config.max_user_fee_bps {
            return Err(format!(
                "fee_cap_bps {} exceeds configured maximum {}",
                request.fee_cap_bps, config.max_user_fee_bps
            ));
        }
        if request.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "privacy_set_size {} below configured floor {}",
                request.privacy_set_size, config.min_privacy_set_size
            ));
        }
        if request.privacy_set_size < request.asset_class.privacy_floor() {
            return Err(format!(
                "privacy_set_size {} below asset privacy floor {}",
                request.privacy_set_size,
                request.asset_class.privacy_floor()
            ));
        }
        if request.expires_height <= request.submitted_height {
            return Err("order expires_height must be greater than submitted_height".to_string());
        }
        let order_id = order_commitment_id(&request);
        let priority_score = order_priority_score(
            request.side,
            request.asset_class,
            request.privacy_set_size,
            request.max_fee_micro_units,
            request.fee_cap_bps,
        );
        Ok(Self {
            order_id,
            owner_commitment: request.owner_commitment,
            market_id: request.market_id,
            pair_id: request.pair_id,
            side: request.side,
            asset_class: request.asset_class,
            encrypted_order_payload_root: request.encrypted_order_payload_root,
            order_commitment: request.order_commitment,
            reveal_key_commitment: request.reveal_key_commitment,
            nullifier_commitment: request.nullifier_commitment,
            account_nonce_commitment: request.account_nonce_commitment,
            max_fee_micro_units: request.max_fee_micro_units,
            fee_cap_bps: request.fee_cap_bps,
            notional_commitment: request.notional_commitment,
            limit_price_commitment: request.limit_price_commitment,
            privacy_set_size: request.privacy_set_size,
            pq_ciphertext_root: request.pq_ciphertext_root,
            pq_public_key_root: request.pq_public_key_root,
            proof_root: request.proof_root,
            submitted_height: request.submitted_height,
            expires_height: request.expires_height,
            status: CommitmentStatus::Submitted,
            priority_score,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "order_id": self.order_id,
            "owner_commitment": self.owner_commitment,
            "market_id": self.market_id,
            "pair_id": self.pair_id,
            "side": self.side.as_str(),
            "asset_class": self.asset_class.as_str(),
            "encrypted_order_payload_root": self.encrypted_order_payload_root,
            "order_commitment": self.order_commitment,
            "reveal_key_commitment": self.reveal_key_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "account_nonce_commitment": self.account_nonce_commitment,
            "max_fee_micro_units": self.max_fee_micro_units,
            "fee_cap_bps": self.fee_cap_bps,
            "notional_commitment": self.notional_commitment,
            "limit_price_commitment": self.limit_price_commitment,
            "privacy_set_size": self.privacy_set_size,
            "pq_ciphertext_root": self.pq_ciphertext_root,
            "pq_public_key_root": self.pq_public_key_root,
            "proof_root": self.proof_root,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
            "priority_score": self.priority_score,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("ORDER-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqSequencerApprovalRequest {
    pub order_id: String,
    pub sequencer_id: String,
    pub committee_id: String,
    pub approval_round: u64,
    pub approved_payload_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub latency_budget_ms: u64,
    pub approved_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqSequencerApproval {
    pub approval_id: String,
    pub order_id: String,
    pub sequencer_id: String,
    pub committee_id: String,
    pub approval_round: u64,
    pub approved_payload_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub security_bits: u16,
    pub latency_budget_ms: u64,
    pub approved_height: u64,
    pub status: ApprovalStatus,
}

impl PqSequencerApproval {
    pub fn from_request(config: &Config, request: PqSequencerApprovalRequest) -> Result<Self> {
        ensure_non_empty("order_id", &request.order_id)?;
        ensure_non_empty("sequencer_id", &request.sequencer_id)?;
        ensure_non_empty("committee_id", &request.committee_id)?;
        ensure_non_empty("approved_payload_root", &request.approved_payload_root)?;
        ensure_non_empty("pq_signature_root", &request.pq_signature_root)?;
        ensure_non_empty("transcript_root", &request.transcript_root)?;
        if request.security_bits < config.min_pq_security_bits {
            return Err(format!(
                "security_bits {} below configured floor {}",
                request.security_bits, config.min_pq_security_bits
            ));
        }
        if request.latency_budget_ms > config.max_preconfirmation_ms {
            return Err(format!(
                "latency_budget_ms {} exceeds max_preconfirmation_ms {}",
                request.latency_budget_ms, config.max_preconfirmation_ms
            ));
        }
        let approval_id = pq_approval_id(&request);
        Ok(Self {
            approval_id,
            order_id: request.order_id,
            sequencer_id: request.sequencer_id,
            committee_id: request.committee_id,
            approval_round: request.approval_round,
            approved_payload_root: request.approved_payload_root,
            pq_signature_root: request.pq_signature_root,
            transcript_root: request.transcript_root,
            security_bits: request.security_bits,
            latency_budget_ms: request.latency_budget_ms,
            approved_height: request.approved_height,
            status: ApprovalStatus::Approved,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "approval_id": self.approval_id,
            "order_id": self.order_id,
            "sequencer_id": self.sequencer_id,
            "committee_id": self.committee_id,
            "approval_round": self.approval_round,
            "approved_payload_root": self.approved_payload_root,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "security_bits": self.security_bits,
            "latency_budget_ms": self.latency_budget_ms,
            "approved_height": self.approved_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("PQ-APPROVAL", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FastPreconfirmationTicketRequest {
    pub order_id: String,
    pub approval_id: String,
    pub ticket_owner_commitment: String,
    pub inclusion_lane: String,
    pub preconfirmed_state_root: String,
    pub fee_lock_commitment: String,
    pub rebate_hint_commitment: String,
    pub ticket_nullifier_commitment: String,
    pub issued_height: u64,
    pub expires_height: u64,
    pub promised_latency_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FastPreconfirmationTicket {
    pub ticket_id: String,
    pub order_id: String,
    pub approval_id: String,
    pub ticket_owner_commitment: String,
    pub inclusion_lane: String,
    pub preconfirmed_state_root: String,
    pub fee_lock_commitment: String,
    pub rebate_hint_commitment: String,
    pub ticket_nullifier_commitment: String,
    pub issued_height: u64,
    pub expires_height: u64,
    pub promised_latency_ms: u64,
    pub status: TicketStatus,
}

impl FastPreconfirmationTicket {
    pub fn from_request(
        config: &Config,
        request: FastPreconfirmationTicketRequest,
    ) -> Result<Self> {
        ensure_non_empty("order_id", &request.order_id)?;
        ensure_non_empty("approval_id", &request.approval_id)?;
        ensure_non_empty("ticket_owner_commitment", &request.ticket_owner_commitment)?;
        ensure_non_empty("inclusion_lane", &request.inclusion_lane)?;
        ensure_non_empty("preconfirmed_state_root", &request.preconfirmed_state_root)?;
        ensure_non_empty("fee_lock_commitment", &request.fee_lock_commitment)?;
        ensure_non_empty("rebate_hint_commitment", &request.rebate_hint_commitment)?;
        ensure_non_empty(
            "ticket_nullifier_commitment",
            &request.ticket_nullifier_commitment,
        )?;
        if request.expires_height <= request.issued_height {
            return Err("ticket expires_height must be greater than issued_height".to_string());
        }
        if request.expires_height - request.issued_height > config.ticket_ttl_blocks {
            return Err("ticket ttl exceeds configured ticket_ttl_blocks".to_string());
        }
        if request.promised_latency_ms > config.max_preconfirmation_ms {
            return Err("promised_latency_ms exceeds max_preconfirmation_ms".to_string());
        }
        let ticket_id = preconfirmation_ticket_id(&request);
        Ok(Self {
            ticket_id,
            order_id: request.order_id,
            approval_id: request.approval_id,
            ticket_owner_commitment: request.ticket_owner_commitment,
            inclusion_lane: request.inclusion_lane,
            preconfirmed_state_root: request.preconfirmed_state_root,
            fee_lock_commitment: request.fee_lock_commitment,
            rebate_hint_commitment: request.rebate_hint_commitment,
            ticket_nullifier_commitment: request.ticket_nullifier_commitment,
            issued_height: request.issued_height,
            expires_height: request.expires_height,
            promised_latency_ms: request.promised_latency_ms,
            status: TicketStatus::Issued,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "order_id": self.order_id,
            "approval_id": self.approval_id,
            "ticket_owner_commitment": self.ticket_owner_commitment,
            "inclusion_lane": self.inclusion_lane,
            "preconfirmed_state_root": self.preconfirmed_state_root,
            "fee_lock_commitment": self.fee_lock_commitment,
            "rebate_hint_commitment": self.rebate_hint_commitment,
            "ticket_nullifier_commitment": self.ticket_nullifier_commitment,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
            "promised_latency_ms": self.promised_latency_ms,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("PRECONFIRMATION-TICKET", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateBatchAuctionRequest {
    pub market_id: String,
    pub pair_id: String,
    pub opening_state_root: String,
    pub encrypted_order_root: String,
    pub privacy_pool_root: String,
    pub eligibility_root: String,
    pub uniform_clearing_commitment: String,
    pub opened_height: u64,
    pub seal_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateBatchAuction {
    pub auction_id: String,
    pub market_id: String,
    pub pair_id: String,
    pub opening_state_root: String,
    pub encrypted_order_root: String,
    pub privacy_pool_root: String,
    pub eligibility_root: String,
    pub uniform_clearing_commitment: String,
    pub opened_height: u64,
    pub seal_height: u64,
    pub status: AuctionStatus,
    pub order_ids: Vec<String>,
    pub selected_bid_id: Option<String>,
}

impl PrivateBatchAuction {
    pub fn from_request(config: &Config, request: PrivateBatchAuctionRequest) -> Result<Self> {
        ensure_non_empty("market_id", &request.market_id)?;
        ensure_non_empty("pair_id", &request.pair_id)?;
        ensure_non_empty("opening_state_root", &request.opening_state_root)?;
        ensure_non_empty("encrypted_order_root", &request.encrypted_order_root)?;
        ensure_non_empty("privacy_pool_root", &request.privacy_pool_root)?;
        ensure_non_empty("eligibility_root", &request.eligibility_root)?;
        ensure_non_empty(
            "uniform_clearing_commitment",
            &request.uniform_clearing_commitment,
        )?;
        if request.seal_height <= request.opened_height {
            return Err("auction seal_height must be greater than opened_height".to_string());
        }
        if request.seal_height - request.opened_height > config.auction_ttl_blocks {
            return Err("auction ttl exceeds configured auction_ttl_blocks".to_string());
        }
        let auction_id = batch_auction_id(&request);
        Ok(Self {
            auction_id,
            market_id: request.market_id,
            pair_id: request.pair_id,
            opening_state_root: request.opening_state_root,
            encrypted_order_root: request.encrypted_order_root,
            privacy_pool_root: request.privacy_pool_root,
            eligibility_root: request.eligibility_root,
            uniform_clearing_commitment: request.uniform_clearing_commitment,
            opened_height: request.opened_height,
            seal_height: request.seal_height,
            status: AuctionStatus::Open,
            order_ids: Vec::new(),
            selected_bid_id: None,
        })
    }

    pub fn order_root(&self) -> String {
        string_merkle_root("AUCTION-ORDER-IDS", &self.order_ids)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "market_id": self.market_id,
            "pair_id": self.pair_id,
            "opening_state_root": self.opening_state_root,
            "encrypted_order_root": self.encrypted_order_root,
            "privacy_pool_root": self.privacy_pool_root,
            "eligibility_root": self.eligibility_root,
            "uniform_clearing_commitment": self.uniform_clearing_commitment,
            "opened_height": self.opened_height,
            "seal_height": self.seal_height,
            "status": self.status.as_str(),
            "order_root": self.order_root(),
            "order_count": self.order_ids.len(),
            "selected_bid_id": self.selected_bid_id,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("PRIVATE-BATCH-AUCTION", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SolverBidRequest {
    pub auction_id: String,
    pub solver_id: String,
    pub bid_commitment: String,
    pub clearing_proof_root: String,
    pub proposed_settlement_root: String,
    pub surplus_commitment: String,
    pub rebate_commitment: String,
    pub solver_bond_commitment: String,
    pub fee_micro_units: u64,
    pub latency_ms: u64,
    pub submitted_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SolverBid {
    pub bid_id: String,
    pub auction_id: String,
    pub solver_id: String,
    pub bid_commitment: String,
    pub clearing_proof_root: String,
    pub proposed_settlement_root: String,
    pub surplus_commitment: String,
    pub rebate_commitment: String,
    pub solver_bond_commitment: String,
    pub fee_micro_units: u64,
    pub latency_ms: u64,
    pub submitted_height: u64,
    pub score: u64,
    pub status: BidStatus,
}

impl SolverBid {
    pub fn from_request(config: &Config, request: SolverBidRequest) -> Result<Self> {
        ensure_non_empty("auction_id", &request.auction_id)?;
        ensure_non_empty("solver_id", &request.solver_id)?;
        ensure_non_empty("bid_commitment", &request.bid_commitment)?;
        ensure_non_empty("clearing_proof_root", &request.clearing_proof_root)?;
        ensure_non_empty(
            "proposed_settlement_root",
            &request.proposed_settlement_root,
        )?;
        ensure_non_empty("surplus_commitment", &request.surplus_commitment)?;
        ensure_non_empty("rebate_commitment", &request.rebate_commitment)?;
        ensure_non_empty("solver_bond_commitment", &request.solver_bond_commitment)?;
        if request.latency_ms > config.max_preconfirmation_ms {
            return Err("solver bid latency_ms exceeds max_preconfirmation_ms".to_string());
        }
        let bid_id = solver_bid_id(&request);
        let score = solver_bid_score(request.fee_micro_units, request.latency_ms);
        Ok(Self {
            bid_id,
            auction_id: request.auction_id,
            solver_id: request.solver_id,
            bid_commitment: request.bid_commitment,
            clearing_proof_root: request.clearing_proof_root,
            proposed_settlement_root: request.proposed_settlement_root,
            surplus_commitment: request.surplus_commitment,
            rebate_commitment: request.rebate_commitment,
            solver_bond_commitment: request.solver_bond_commitment,
            fee_micro_units: request.fee_micro_units,
            latency_ms: request.latency_ms,
            submitted_height: request.submitted_height,
            score,
            status: BidStatus::Posted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "solver_id": self.solver_id,
            "bid_commitment": self.bid_commitment,
            "clearing_proof_root": self.clearing_proof_root,
            "proposed_settlement_root": self.proposed_settlement_root,
            "surplus_commitment": self.surplus_commitment,
            "rebate_commitment": self.rebate_commitment,
            "solver_bond_commitment": self.solver_bond_commitment,
            "fee_micro_units": self.fee_micro_units,
            "latency_ms": self.latency_ms,
            "submitted_height": self.submitted_height,
            "score": self.score,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("SOLVER-BID", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractCallBundleIntentRequest {
    pub owner_commitment: String,
    pub contract_namespace: String,
    pub call_graph_root: String,
    pub encrypted_calldata_root: String,
    pub access_list_commitment: String,
    pub state_diff_commitment: String,
    pub max_gas_commitment: String,
    pub fee_cap_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub submitted_height: u64,
    pub expires_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractCallBundleIntent {
    pub bundle_id: String,
    pub owner_commitment: String,
    pub contract_namespace: String,
    pub call_graph_root: String,
    pub encrypted_calldata_root: String,
    pub access_list_commitment: String,
    pub state_diff_commitment: String,
    pub max_gas_commitment: String,
    pub fee_cap_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub status: BundleStatus,
}

impl ContractCallBundleIntent {
    pub fn from_request(config: &Config, request: ContractCallBundleIntentRequest) -> Result<Self> {
        ensure_non_empty("owner_commitment", &request.owner_commitment)?;
        ensure_non_empty("contract_namespace", &request.contract_namespace)?;
        ensure_non_empty("call_graph_root", &request.call_graph_root)?;
        ensure_non_empty("encrypted_calldata_root", &request.encrypted_calldata_root)?;
        ensure_non_empty("access_list_commitment", &request.access_list_commitment)?;
        ensure_non_empty("state_diff_commitment", &request.state_diff_commitment)?;
        ensure_non_empty("max_gas_commitment", &request.max_gas_commitment)?;
        ensure_non_empty("pq_authorization_root", &request.pq_authorization_root)?;
        if request.privacy_set_size < config.min_privacy_set_size {
            return Err("bundle privacy_set_size below configured floor".to_string());
        }
        if request.expires_height <= request.submitted_height {
            return Err("bundle expires_height must be greater than submitted_height".to_string());
        }
        if request.expires_height - request.submitted_height > config.bundle_ttl_blocks {
            return Err("bundle ttl exceeds configured bundle_ttl_blocks".to_string());
        }
        let bundle_id = contract_bundle_id(&request);
        Ok(Self {
            bundle_id,
            owner_commitment: request.owner_commitment,
            contract_namespace: request.contract_namespace,
            call_graph_root: request.call_graph_root,
            encrypted_calldata_root: request.encrypted_calldata_root,
            access_list_commitment: request.access_list_commitment,
            state_diff_commitment: request.state_diff_commitment,
            max_gas_commitment: request.max_gas_commitment,
            fee_cap_micro_units: request.fee_cap_micro_units,
            privacy_set_size: request.privacy_set_size,
            pq_authorization_root: request.pq_authorization_root,
            submitted_height: request.submitted_height,
            expires_height: request.expires_height,
            status: BundleStatus::Submitted,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id,
            "owner_commitment": self.owner_commitment,
            "contract_namespace": self.contract_namespace,
            "call_graph_root": self.call_graph_root,
            "encrypted_calldata_root": self.encrypted_calldata_root,
            "access_list_commitment": self.access_list_commitment,
            "state_diff_commitment": self.state_diff_commitment,
            "max_gas_commitment": self.max_gas_commitment,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "pq_authorization_root": self.pq_authorization_root,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONTRACT-BUNDLE-INTENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LowFeeRebateRequest {
    pub subject_id: String,
    pub beneficiary_commitment: String,
    pub fee_paid_micro_units: u64,
    pub target_fee_micro_units: u64,
    pub rebate_nullifier: String,
    pub eligibility_proof_root: String,
    pub issued_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub subject_id: String,
    pub beneficiary_commitment: String,
    pub fee_paid_micro_units: u64,
    pub target_fee_micro_units: u64,
    pub rebate_micro_units: u64,
    pub rebate_nullifier: String,
    pub eligibility_proof_root: String,
    pub issued_height: u64,
    pub status: RebateStatus,
}

impl LowFeeRebate {
    pub fn from_request(config: &Config, request: LowFeeRebateRequest) -> Result<Self> {
        ensure_non_empty("subject_id", &request.subject_id)?;
        ensure_non_empty("beneficiary_commitment", &request.beneficiary_commitment)?;
        ensure_non_empty("rebate_nullifier", &request.rebate_nullifier)?;
        ensure_non_empty("eligibility_proof_root", &request.eligibility_proof_root)?;
        let cap = request
            .fee_paid_micro_units
            .saturating_mul(config.max_rebate_bps)
            / MAX_BPS;
        let delta = request
            .fee_paid_micro_units
            .saturating_sub(request.target_fee_micro_units);
        let rebate_micro_units = delta.min(cap);
        let rebate_id = low_fee_rebate_id(&request, rebate_micro_units);
        Ok(Self {
            rebate_id,
            subject_id: request.subject_id,
            beneficiary_commitment: request.beneficiary_commitment,
            fee_paid_micro_units: request.fee_paid_micro_units,
            target_fee_micro_units: request.target_fee_micro_units,
            rebate_micro_units,
            rebate_nullifier: request.rebate_nullifier,
            eligibility_proof_root: request.eligibility_proof_root,
            issued_height: request.issued_height,
            status: RebateStatus::Reserved,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "subject_id": self.subject_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "target_fee_micro_units": self.target_fee_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "rebate_nullifier": self.rebate_nullifier,
            "eligibility_proof_root": self.eligibility_proof_root,
            "issued_height": self.issued_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("LOW-FEE-REBATE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateCancellationNullifierRequest {
    pub subject_id: String,
    pub kind: NullifierKind,
    pub nullifier: String,
    pub owner_commitment: String,
    pub proof_root: String,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateCancellationNullifier {
    pub nullifier_id: String,
    pub subject_id: String,
    pub kind: NullifierKind,
    pub nullifier: String,
    pub owner_commitment: String,
    pub proof_root: String,
    pub height: u64,
}

impl PrivateCancellationNullifier {
    pub fn from_request(request: PrivateCancellationNullifierRequest) -> Result<Self> {
        ensure_non_empty("subject_id", &request.subject_id)?;
        ensure_non_empty("nullifier", &request.nullifier)?;
        ensure_non_empty("owner_commitment", &request.owner_commitment)?;
        ensure_non_empty("proof_root", &request.proof_root)?;
        let nullifier_id = cancellation_nullifier_id(&request);
        Ok(Self {
            nullifier_id,
            subject_id: request.subject_id,
            kind: request.kind,
            nullifier: request.nullifier,
            owner_commitment: request.owner_commitment,
            proof_root: request.proof_root,
            height: request.height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "subject_id": self.subject_id,
            "kind": self.kind.as_str(),
            "nullifier": self.nullifier,
            "owner_commitment": self.owner_commitment,
            "proof_root": self.proof_root,
            "height": self.height,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CANCELLATION-NULLIFIER", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementReceiptRequest {
    pub subject_id: String,
    pub auction_id: Option<String>,
    pub ticket_id: Option<String>,
    pub bundle_id: Option<String>,
    pub solver_id: String,
    pub settlement_state_root: String,
    pub clearing_price_commitment: String,
    pub fee_charged_micro_units: u64,
    pub rebate_micro_units: u64,
    pub inclusion_proof_root: String,
    pub settled_height: u64,
    pub latency_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub subject_id: String,
    pub auction_id: Option<String>,
    pub ticket_id: Option<String>,
    pub bundle_id: Option<String>,
    pub solver_id: String,
    pub settlement_state_root: String,
    pub clearing_price_commitment: String,
    pub fee_charged_micro_units: u64,
    pub rebate_micro_units: u64,
    pub inclusion_proof_root: String,
    pub settled_height: u64,
    pub latency_ms: u64,
    pub status: ReceiptStatus,
}

impl SettlementReceipt {
    pub fn from_request(config: &Config, request: SettlementReceiptRequest) -> Result<Self> {
        ensure_non_empty("subject_id", &request.subject_id)?;
        ensure_non_empty("solver_id", &request.solver_id)?;
        ensure_non_empty("settlement_state_root", &request.settlement_state_root)?;
        ensure_non_empty(
            "clearing_price_commitment",
            &request.clearing_price_commitment,
        )?;
        ensure_non_empty("inclusion_proof_root", &request.inclusion_proof_root)?;
        if request.latency_ms > config.max_preconfirmation_ms.saturating_mul(4) {
            return Err("settlement receipt latency_ms is outside acceptable range".to_string());
        }
        let receipt_id = settlement_receipt_id(&request);
        Ok(Self {
            receipt_id,
            subject_id: request.subject_id,
            auction_id: request.auction_id,
            ticket_id: request.ticket_id,
            bundle_id: request.bundle_id,
            solver_id: request.solver_id,
            settlement_state_root: request.settlement_state_root,
            clearing_price_commitment: request.clearing_price_commitment,
            fee_charged_micro_units: request.fee_charged_micro_units,
            rebate_micro_units: request.rebate_micro_units,
            inclusion_proof_root: request.inclusion_proof_root,
            settled_height: request.settled_height,
            latency_ms: request.latency_ms,
            status: ReceiptStatus::Applied,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "subject_id": self.subject_id,
            "auction_id": self.auction_id,
            "ticket_id": self.ticket_id,
            "bundle_id": self.bundle_id,
            "solver_id": self.solver_id,
            "settlement_state_root": self.settlement_state_root,
            "clearing_price_commitment": self.clearing_price_commitment,
            "fee_charged_micro_units": self.fee_charged_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "inclusion_proof_root": self.inclusion_proof_root,
            "settled_height": self.settled_height,
            "latency_ms": self.latency_ms,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("SETTLEMENT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LatencySlaSnapshotRequest {
    pub sequencer_id: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub sample_count: u64,
    pub p50_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub p99_latency_ms: u64,
    pub missed_tickets: u64,
    pub observed_ticket_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LatencySlaSnapshot {
    pub snapshot_id: String,
    pub sequencer_id: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub sample_count: u64,
    pub p50_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub p99_latency_ms: u64,
    pub missed_tickets: u64,
    pub observed_ticket_root: String,
    pub status: SlaStatus,
}

impl LatencySlaSnapshot {
    pub fn from_request(config: &Config, request: LatencySlaSnapshotRequest) -> Result<Self> {
        ensure_non_empty("sequencer_id", &request.sequencer_id)?;
        ensure_non_empty("observed_ticket_root", &request.observed_ticket_root)?;
        if request.window_end_height <= request.window_start_height {
            return Err("sla window_end_height must be greater than start".to_string());
        }
        let status = if request.p99_latency_ms > config.max_preconfirmation_ms {
            SlaStatus::Breached
        } else if request.p95_latency_ms > config.target_preconfirmation_ms {
            SlaStatus::Degraded
        } else {
            SlaStatus::Healthy
        };
        let snapshot_id = sla_snapshot_id(&request);
        Ok(Self {
            snapshot_id,
            sequencer_id: request.sequencer_id,
            window_start_height: request.window_start_height,
            window_end_height: request.window_end_height,
            sample_count: request.sample_count,
            p50_latency_ms: request.p50_latency_ms,
            p95_latency_ms: request.p95_latency_ms,
            p99_latency_ms: request.p99_latency_ms,
            missed_tickets: request.missed_tickets,
            observed_ticket_root: request.observed_ticket_root,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "sequencer_id": self.sequencer_id,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "sample_count": self.sample_count,
            "p50_latency_ms": self.p50_latency_ms,
            "p95_latency_ms": self.p95_latency_ms,
            "p99_latency_ms": self.p99_latency_ms,
            "missed_tickets": self.missed_tickets,
            "observed_ticket_root": self.observed_ticket_root,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("LATENCY-SLA-SNAPSHOT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingEvidenceRequest {
    pub offender_id: String,
    pub reason: SlashingReason,
    pub subject_id: String,
    pub evidence_root: String,
    pub witness_root: String,
    pub conflicting_commitment_root: String,
    pub reporter_commitment: String,
    pub slash_amount_micro_units: u64,
    pub height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub offender_id: String,
    pub reason: SlashingReason,
    pub subject_id: String,
    pub evidence_root: String,
    pub witness_root: String,
    pub conflicting_commitment_root: String,
    pub reporter_commitment: String,
    pub slash_amount_micro_units: u64,
    pub height: u64,
    pub executed: bool,
}

impl SlashingEvidence {
    pub fn from_request(config: &Config, request: SlashingEvidenceRequest) -> Result<Self> {
        ensure_non_empty("offender_id", &request.offender_id)?;
        ensure_non_empty("subject_id", &request.subject_id)?;
        ensure_non_empty("evidence_root", &request.evidence_root)?;
        ensure_non_empty("witness_root", &request.witness_root)?;
        ensure_non_empty(
            "conflicting_commitment_root",
            &request.conflicting_commitment_root,
        )?;
        ensure_non_empty("reporter_commitment", &request.reporter_commitment)?;
        if request.slash_amount_micro_units > config.sequencer_bond_micro_units {
            return Err("slash_amount_micro_units exceeds sequencer bond".to_string());
        }
        let evidence_id = slashing_evidence_id(&request);
        Ok(Self {
            evidence_id,
            offender_id: request.offender_id,
            reason: request.reason,
            subject_id: request.subject_id,
            evidence_root: request.evidence_root,
            witness_root: request.witness_root,
            conflicting_commitment_root: request.conflicting_commitment_root,
            reporter_commitment: request.reporter_commitment,
            slash_amount_micro_units: request.slash_amount_micro_units,
            height: request.height,
            executed: false,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "offender_id": self.offender_id,
            "reason": self.reason.as_str(),
            "subject_id": self.subject_id,
            "evidence_root": self.evidence_root,
            "witness_root": self.witness_root,
            "conflicting_commitment_root": self.conflicting_commitment_root,
            "reporter_commitment": self.reporter_commitment,
            "slash_amount_micro_units": self.slash_amount_micro_units,
            "height": self.height,
            "executed": self.executed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("SLASHING-EVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub order_commitments: BTreeMap<String, EncryptedOrderCommitment>,
    pub pq_approvals: BTreeMap<String, PqSequencerApproval>,
    pub preconfirmation_tickets: BTreeMap<String, FastPreconfirmationTicket>,
    pub batch_auctions: BTreeMap<String, PrivateBatchAuction>,
    pub solver_bids: BTreeMap<String, SolverBid>,
    pub bundle_intents: BTreeMap<String, ContractCallBundleIntent>,
    pub fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub cancellation_nullifiers: BTreeMap<String, PrivateCancellationNullifier>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub sla_snapshots: BTreeMap<String, LatencySlaSnapshot>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            order_commitments: BTreeMap::new(),
            pq_approvals: BTreeMap::new(),
            preconfirmation_tickets: BTreeMap::new(),
            batch_auctions: BTreeMap::new(),
            solver_bids: BTreeMap::new(),
            bundle_intents: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            cancellation_nullifiers: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            sla_snapshots: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        }
    }

    pub fn with_config(config: Config) -> Self {
        Self {
            config,
            ..Self::devnet()
        }
    }

    pub fn submit_encrypted_order(
        &mut self,
        request: EncryptedOrderCommitmentRequest,
    ) -> Result<EncryptedOrderCommitment> {
        ensure_capacity(
            "order_commitments",
            self.order_commitments.len(),
            self.config.max_order_commitments,
        )?;
        let order = EncryptedOrderCommitment::from_request(&self.config, request)?;
        ensure_absent("order_commitment", &self.order_commitments, &order.order_id)?;
        self.order_commitments
            .insert(order.order_id.clone(), order.clone());
        Ok(order)
    }

    pub fn approve_order_pq(
        &mut self,
        request: PqSequencerApprovalRequest,
    ) -> Result<PqSequencerApproval> {
        ensure_capacity(
            "pq_approvals",
            self.pq_approvals.len(),
            self.config.max_approvals,
        )?;
        let approval = PqSequencerApproval::from_request(&self.config, request)?;
        let order = self
            .order_commitments
            .get_mut(&approval.order_id)
            .ok_or_else(|| format!("unknown order_id {}", approval.order_id))?;
        ensure_absent("pq_approval", &self.pq_approvals, &approval.approval_id)?;
        order.status = CommitmentStatus::Approved;
        self.pq_approvals
            .insert(approval.approval_id.clone(), approval.clone());
        Ok(approval)
    }

    pub fn issue_preconfirmation_ticket(
        &mut self,
        request: FastPreconfirmationTicketRequest,
    ) -> Result<FastPreconfirmationTicket> {
        ensure_capacity(
            "preconfirmation_tickets",
            self.preconfirmation_tickets.len(),
            self.config.max_tickets,
        )?;
        let ticket = FastPreconfirmationTicket::from_request(&self.config, request)?;
        let approval = self
            .pq_approvals
            .get(&ticket.approval_id)
            .ok_or_else(|| format!("unknown approval_id {}", ticket.approval_id))?;
        if approval.order_id != ticket.order_id {
            return Err("ticket order_id does not match approval order_id".to_string());
        }
        let order = self
            .order_commitments
            .get_mut(&ticket.order_id)
            .ok_or_else(|| format!("unknown order_id {}", ticket.order_id))?;
        ensure_absent(
            "preconfirmation_ticket",
            &self.preconfirmation_tickets,
            &ticket.ticket_id,
        )?;
        order.status = CommitmentStatus::Ticketed;
        self.preconfirmation_tickets
            .insert(ticket.ticket_id.clone(), ticket.clone());
        Ok(ticket)
    }

    pub fn open_private_batch_auction(
        &mut self,
        request: PrivateBatchAuctionRequest,
    ) -> Result<PrivateBatchAuction> {
        ensure_capacity(
            "batch_auctions",
            self.batch_auctions.len(),
            self.config.max_auctions,
        )?;
        let auction = PrivateBatchAuction::from_request(&self.config, request)?;
        ensure_absent("batch_auction", &self.batch_auctions, &auction.auction_id)?;
        self.batch_auctions
            .insert(auction.auction_id.clone(), auction.clone());
        Ok(auction)
    }

    pub fn attach_order_to_auction(&mut self, auction_id: &str, order_id: &str) -> Result<()> {
        let order = self
            .order_commitments
            .get_mut(order_id)
            .ok_or_else(|| format!("unknown order_id {order_id}"))?;
        if !matches!(
            order.status,
            CommitmentStatus::Submitted | CommitmentStatus::Approved | CommitmentStatus::Ticketed
        ) {
            return Err(format!(
                "order {order_id} is not attachable in status {}",
                order.status.as_str()
            ));
        }
        let auction = self
            .batch_auctions
            .get_mut(auction_id)
            .ok_or_else(|| format!("unknown auction_id {auction_id}"))?;
        if !matches!(auction.status, AuctionStatus::Open | AuctionStatus::Solving) {
            return Err(format!(
                "auction {auction_id} is not accepting orders in status {}",
                auction.status.as_str()
            ));
        }
        if auction
            .order_ids
            .iter()
            .any(|candidate| candidate == order_id)
        {
            return Err(format!("order {order_id} already attached to auction"));
        }
        auction.order_ids.push(order_id.to_string());
        order.status = CommitmentStatus::Batched;
        Ok(())
    }

    pub fn post_solver_bid(&mut self, request: SolverBidRequest) -> Result<SolverBid> {
        ensure_capacity(
            "solver_bids",
            self.solver_bids.len(),
            self.config.max_solver_bids,
        )?;
        let bid = SolverBid::from_request(&self.config, request)?;
        let auction = self
            .batch_auctions
            .get_mut(&bid.auction_id)
            .ok_or_else(|| format!("unknown auction_id {}", bid.auction_id))?;
        if !matches!(
            auction.status,
            AuctionStatus::Open | AuctionStatus::Sealed | AuctionStatus::Solving
        ) {
            return Err("auction is not accepting solver bids".to_string());
        }
        ensure_absent("solver_bid", &self.solver_bids, &bid.bid_id)?;
        auction.status = AuctionStatus::Solving;
        self.solver_bids.insert(bid.bid_id.clone(), bid.clone());
        Ok(bid)
    }

    pub fn select_solver_bid(&mut self, auction_id: &str, bid_id: &str) -> Result<()> {
        let auction = self
            .batch_auctions
            .get_mut(auction_id)
            .ok_or_else(|| format!("unknown auction_id {auction_id}"))?;
        let bid = self
            .solver_bids
            .get_mut(bid_id)
            .ok_or_else(|| format!("unknown bid_id {bid_id}"))?;
        if bid.auction_id != auction_id {
            return Err("bid auction_id does not match selected auction_id".to_string());
        }
        bid.status = BidStatus::Selected;
        auction.status = AuctionStatus::Clearing;
        auction.selected_bid_id = Some(bid_id.to_string());
        Ok(())
    }

    pub fn submit_contract_bundle_intent(
        &mut self,
        request: ContractCallBundleIntentRequest,
    ) -> Result<ContractCallBundleIntent> {
        ensure_capacity(
            "bundle_intents",
            self.bundle_intents.len(),
            self.config.max_bundle_intents,
        )?;
        let bundle = ContractCallBundleIntent::from_request(&self.config, request)?;
        ensure_absent("bundle_intent", &self.bundle_intents, &bundle.bundle_id)?;
        self.bundle_intents
            .insert(bundle.bundle_id.clone(), bundle.clone());
        Ok(bundle)
    }

    pub fn approve_bundle(&mut self, bundle_id: &str) -> Result<()> {
        let bundle = self
            .bundle_intents
            .get_mut(bundle_id)
            .ok_or_else(|| format!("unknown bundle_id {bundle_id}"))?;
        if !matches!(bundle.status, BundleStatus::Submitted) {
            return Err("bundle is not in submitted status".to_string());
        }
        bundle.status = BundleStatus::Approved;
        Ok(())
    }

    pub fn reserve_low_fee_rebate(&mut self, request: LowFeeRebateRequest) -> Result<LowFeeRebate> {
        ensure_capacity(
            "fee_rebates",
            self.fee_rebates.len(),
            self.config.max_rebates,
        )?;
        if self.spent_nullifiers.contains(&request.rebate_nullifier) {
            return Err("rebate nullifier already spent".to_string());
        }
        let rebate = LowFeeRebate::from_request(&self.config, request)?;
        ensure_absent("fee_rebate", &self.fee_rebates, &rebate.rebate_id)?;
        self.fee_rebates
            .insert(rebate.rebate_id.clone(), rebate.clone());
        Ok(rebate)
    }

    pub fn mark_rebate_paid(&mut self, rebate_id: &str) -> Result<()> {
        let rebate = self
            .fee_rebates
            .get_mut(rebate_id)
            .ok_or_else(|| format!("unknown rebate_id {rebate_id}"))?;
        if self.spent_nullifiers.contains(&rebate.rebate_nullifier) {
            return Err("rebate nullifier already spent".to_string());
        }
        rebate.status = RebateStatus::Paid;
        self.spent_nullifiers
            .insert(rebate.rebate_nullifier.clone());
        Ok(())
    }

    pub fn spend_private_nullifier(
        &mut self,
        request: PrivateCancellationNullifierRequest,
    ) -> Result<PrivateCancellationNullifier> {
        ensure_capacity(
            "cancellation_nullifiers",
            self.cancellation_nullifiers.len(),
            self.config.max_nullifiers,
        )?;
        if self.spent_nullifiers.contains(&request.nullifier) {
            return Err("private nullifier already spent".to_string());
        }
        let nullifier = PrivateCancellationNullifier::from_request(request)?;
        ensure_absent(
            "cancellation_nullifier",
            &self.cancellation_nullifiers,
            &nullifier.nullifier_id,
        )?;
        self.spent_nullifiers.insert(nullifier.nullifier.clone());
        self.apply_nullifier_status(&nullifier.subject_id, nullifier.kind)?;
        self.cancellation_nullifiers
            .insert(nullifier.nullifier_id.clone(), nullifier.clone());
        Ok(nullifier)
    }

    pub fn record_settlement_receipt(
        &mut self,
        request: SettlementReceiptRequest,
    ) -> Result<SettlementReceipt> {
        ensure_capacity(
            "settlement_receipts",
            self.settlement_receipts.len(),
            self.config.max_receipts,
        )?;
        let receipt = SettlementReceipt::from_request(&self.config, request)?;
        ensure_absent(
            "settlement_receipt",
            &self.settlement_receipts,
            &receipt.receipt_id,
        )?;
        self.apply_settlement_status(&receipt);
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn record_latency_sla_snapshot(
        &mut self,
        request: LatencySlaSnapshotRequest,
    ) -> Result<LatencySlaSnapshot> {
        ensure_capacity(
            "sla_snapshots",
            self.sla_snapshots.len(),
            self.config.max_sla_snapshots,
        )?;
        let snapshot = LatencySlaSnapshot::from_request(&self.config, request)?;
        ensure_absent("sla_snapshot", &self.sla_snapshots, &snapshot.snapshot_id)?;
        self.sla_snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot.clone());
        Ok(snapshot)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        request: SlashingEvidenceRequest,
    ) -> Result<SlashingEvidence> {
        ensure_capacity(
            "slashing_evidence",
            self.slashing_evidence.len(),
            self.config.max_slashing_evidence,
        )?;
        let evidence = SlashingEvidence::from_request(&self.config, request)?;
        ensure_absent(
            "slashing_evidence",
            &self.slashing_evidence,
            &evidence.evidence_id,
        )?;
        self.apply_slashing_hint(&evidence);
        self.slashing_evidence
            .insert(evidence.evidence_id.clone(), evidence.clone());
        Ok(evidence)
    }

    pub fn expire_at_height(&mut self, height: u64) {
        for order in self.order_commitments.values_mut() {
            if order.expires_height <= height
                && matches!(
                    order.status,
                    CommitmentStatus::Submitted
                        | CommitmentStatus::Approved
                        | CommitmentStatus::Ticketed
                        | CommitmentStatus::Batched
                )
            {
                order.status = CommitmentStatus::Expired;
            }
        }
        for ticket in self.preconfirmation_tickets.values_mut() {
            if ticket.expires_height <= height
                && matches!(ticket.status, TicketStatus::Issued | TicketStatus::Bound)
            {
                ticket.status = TicketStatus::Expired;
            }
        }
        for auction in self.batch_auctions.values_mut() {
            if auction.seal_height <= height
                && matches!(auction.status, AuctionStatus::Open | AuctionStatus::Sealed)
            {
                auction.status = AuctionStatus::Expired;
            }
        }
        for bundle in self.bundle_intents.values_mut() {
            if bundle.expires_height <= height
                && matches!(
                    bundle.status,
                    BundleStatus::Submitted | BundleStatus::Approved
                )
            {
                bundle.status = BundleStatus::Expired;
            }
        }
    }

    pub fn best_solver_bid_for_auction(&self, auction_id: &str) -> Option<&SolverBid> {
        self.solver_bids
            .values()
            .filter(|bid| bid.auction_id == auction_id && matches!(bid.status, BidStatus::Posted))
            .max_by_key(|bid| bid.score)
    }

    pub fn counters(&self) -> Counters {
        let receipts = self.settlement_receipts.values().collect::<Vec<_>>();
        let settled_orders = self
            .order_commitments
            .values()
            .filter(|order| matches!(order.status, CommitmentStatus::Settled))
            .count() as u64;
        let cancelled_orders = self
            .order_commitments
            .values()
            .filter(|order| matches!(order.status, CommitmentStatus::Cancelled))
            .count() as u64;
        let rejected_orders = self
            .order_commitments
            .values()
            .filter(|order| {
                matches!(
                    order.status,
                    CommitmentStatus::Expired | CommitmentStatus::Slashed
                )
            })
            .count() as u64;
        let total_fee_micro_units = receipts
            .iter()
            .map(|receipt| receipt.fee_charged_micro_units as u128)
            .sum();
        let total_rebate_micro_units = self
            .fee_rebates
            .values()
            .map(|rebate| rebate.rebate_micro_units as u128)
            .sum();
        let total_slash_micro_units = self
            .slashing_evidence
            .values()
            .map(|evidence| evidence.slash_amount_micro_units as u128)
            .sum();
        let average_preconfirmation_ms = if receipts.is_empty() {
            0
        } else {
            receipts
                .iter()
                .map(|receipt| receipt.latency_ms)
                .sum::<u64>()
                / receipts.len() as u64
        };
        Counters {
            order_commitments: self.order_commitments.len(),
            pq_approvals: self.pq_approvals.len(),
            preconfirmation_tickets: self.preconfirmation_tickets.len(),
            batch_auctions: self.batch_auctions.len(),
            solver_bids: self.solver_bids.len(),
            bundle_intents: self.bundle_intents.len(),
            fee_rebates: self.fee_rebates.len(),
            cancellation_nullifiers: self.cancellation_nullifiers.len(),
            settlement_receipts: self.settlement_receipts.len(),
            sla_snapshots: self.sla_snapshots.len(),
            slashing_evidence: self.slashing_evidence.len(),
            accepted_orders: self.order_commitments.len() as u64,
            cancelled_orders,
            settled_orders,
            rejected_orders,
            total_fee_micro_units,
            total_rebate_micro_units,
            total_slash_micro_units,
            average_preconfirmation_ms,
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.state_root(),
            order_commitment_root: map_root("ORDER-COMMITMENTS", &self.order_commitments),
            pq_approval_root: map_root("PQ-APPROVALS", &self.pq_approvals),
            preconfirmation_ticket_root: map_root(
                "PRECONFIRMATION-TICKETS",
                &self.preconfirmation_tickets,
            ),
            batch_auction_root: map_root("BATCH-AUCTIONS", &self.batch_auctions),
            solver_bid_root: map_root("SOLVER-BIDS", &self.solver_bids),
            bundle_intent_root: map_root("BUNDLE-INTENTS", &self.bundle_intents),
            fee_rebate_root: map_root("FEE-REBATES", &self.fee_rebates),
            cancellation_nullifier_root: map_root(
                "CANCELLATION-NULLIFIERS",
                &self.cancellation_nullifiers,
            ),
            settlement_receipt_root: map_root("SETTLEMENT-RECEIPTS", &self.settlement_receipts),
            sla_snapshot_root: map_root("SLA-SNAPSHOTS", &self.sla_snapshots),
            slashing_evidence_root: map_root("SLASHING-EVIDENCE", &self.slashing_evidence),
            counters_root: self.counters().state_root(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.config.chain_id,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
            "counters": counters.public_record(),
            "counters_root": counters.state_root(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(object) = &mut record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        record_root("STATE", &self.public_record_without_state_root())
    }

    fn apply_nullifier_status(&mut self, subject_id: &str, kind: NullifierKind) -> Result<()> {
        match kind {
            NullifierKind::OrderCancel => {
                let order = self
                    .order_commitments
                    .get_mut(subject_id)
                    .ok_or_else(|| format!("unknown order subject_id {subject_id}"))?;
                order.status = CommitmentStatus::Cancelled;
            }
            NullifierKind::BundleCancel => {
                let bundle = self
                    .bundle_intents
                    .get_mut(subject_id)
                    .ok_or_else(|| format!("unknown bundle subject_id {subject_id}"))?;
                bundle.status = BundleStatus::Cancelled;
            }
            NullifierKind::TicketSpend => {
                let ticket = self
                    .preconfirmation_tickets
                    .get_mut(subject_id)
                    .ok_or_else(|| format!("unknown ticket subject_id {subject_id}"))?;
                ticket.status = TicketStatus::Included;
            }
            NullifierKind::RebateClaim => {
                let rebate = self
                    .fee_rebates
                    .get_mut(subject_id)
                    .ok_or_else(|| format!("unknown rebate subject_id {subject_id}"))?;
                rebate.status = RebateStatus::Paid;
            }
            NullifierKind::SolverBidSpend => {
                let bid = self
                    .solver_bids
                    .get_mut(subject_id)
                    .ok_or_else(|| format!("unknown solver bid subject_id {subject_id}"))?;
                bid.status = BidStatus::Settled;
            }
            NullifierKind::SettlementSpend => {
                let receipt = self
                    .settlement_receipts
                    .get_mut(subject_id)
                    .ok_or_else(|| format!("unknown settlement subject_id {subject_id}"))?;
                receipt.status = ReceiptStatus::Finalized;
            }
            NullifierKind::SlashingClaim => {
                let evidence = self
                    .slashing_evidence
                    .get_mut(subject_id)
                    .ok_or_else(|| format!("unknown evidence subject_id {subject_id}"))?;
                evidence.executed = true;
            }
        }
        Ok(())
    }

    fn apply_settlement_status(&mut self, receipt: &SettlementReceipt) {
        if let Some(order) = self.order_commitments.get_mut(&receipt.subject_id) {
            order.status = CommitmentStatus::Settled;
        }
        if let Some(ticket_id) = &receipt.ticket_id {
            if let Some(ticket) = self.preconfirmation_tickets.get_mut(ticket_id) {
                ticket.status = TicketStatus::Settled;
            }
        }
        if let Some(auction_id) = &receipt.auction_id {
            if let Some(auction) = self.batch_auctions.get_mut(auction_id) {
                auction.status = AuctionStatus::Settled;
            }
        }
        if let Some(bundle_id) = &receipt.bundle_id {
            if let Some(bundle) = self.bundle_intents.get_mut(bundle_id) {
                bundle.status = BundleStatus::Settled;
            }
        }
    }

    fn apply_slashing_hint(&mut self, evidence: &SlashingEvidence) {
        if let Some(order) = self.order_commitments.get_mut(&evidence.subject_id) {
            order.status = CommitmentStatus::Slashed;
        }
        if let Some(ticket) = self.preconfirmation_tickets.get_mut(&evidence.subject_id) {
            ticket.status = TicketStatus::Slashed;
        }
        if let Some(bid) = self.solver_bids.get_mut(&evidence.subject_id) {
            bid.status = BidStatus::Slashed;
        }
        if let Some(auction) = self.batch_auctions.get_mut(&evidence.subject_id) {
            auction.status = AuctionStatus::Challenged;
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for EncryptedOrderCommitment {
    fn public_record(&self) -> Value {
        EncryptedOrderCommitment::public_record(self)
    }
}

impl PublicRecord for PqSequencerApproval {
    fn public_record(&self) -> Value {
        PqSequencerApproval::public_record(self)
    }
}

impl PublicRecord for FastPreconfirmationTicket {
    fn public_record(&self) -> Value {
        FastPreconfirmationTicket::public_record(self)
    }
}

impl PublicRecord for PrivateBatchAuction {
    fn public_record(&self) -> Value {
        PrivateBatchAuction::public_record(self)
    }
}

impl PublicRecord for SolverBid {
    fn public_record(&self) -> Value {
        SolverBid::public_record(self)
    }
}

impl PublicRecord for ContractCallBundleIntent {
    fn public_record(&self) -> Value {
        ContractCallBundleIntent::public_record(self)
    }
}

impl PublicRecord for LowFeeRebate {
    fn public_record(&self) -> Value {
        LowFeeRebate::public_record(self)
    }
}

impl PublicRecord for PrivateCancellationNullifier {
    fn public_record(&self) -> Value {
        PrivateCancellationNullifier::public_record(self)
    }
}

impl PublicRecord for SettlementReceipt {
    fn public_record(&self) -> Value {
        SettlementReceipt::public_record(self)
    }
}

impl PublicRecord for LatencySlaSnapshot {
    fn public_record(&self) -> Value {
        LatencySlaSnapshot::public_record(self)
    }
}

impl PublicRecord for SlashingEvidence {
    fn public_record(&self) -> Value {
        SlashingEvidence::public_record(self)
    }
}

pub fn order_commitment_id(request: &EncryptedOrderCommitmentRequest) -> String {
    domain_hash(
        "FAST-PQ-ORDER-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.market_id),
            HashPart::Str(&request.pair_id),
            HashPart::Str(request.side.as_str()),
            HashPart::Str(request.asset_class.as_str()),
            HashPart::Str(&request.order_commitment),
            HashPart::Str(&request.nullifier_commitment),
            HashPart::U64(request.submitted_height),
        ],
        32,
    )
}

pub fn pq_approval_id(request: &PqSequencerApprovalRequest) -> String {
    domain_hash(
        "FAST-PQ-SEQUENCER-APPROVAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.order_id),
            HashPart::Str(&request.sequencer_id),
            HashPart::Str(&request.committee_id),
            HashPart::U64(request.approval_round),
            HashPart::Str(&request.approved_payload_root),
            HashPart::Str(&request.pq_signature_root),
        ],
        32,
    )
}

pub fn preconfirmation_ticket_id(request: &FastPreconfirmationTicketRequest) -> String {
    domain_hash(
        "FAST-PQ-PRECONFIRMATION-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.order_id),
            HashPart::Str(&request.approval_id),
            HashPart::Str(&request.ticket_owner_commitment),
            HashPart::Str(&request.preconfirmed_state_root),
            HashPart::Str(&request.ticket_nullifier_commitment),
            HashPart::U64(request.issued_height),
        ],
        32,
    )
}

pub fn batch_auction_id(request: &PrivateBatchAuctionRequest) -> String {
    domain_hash(
        "FAST-PQ-PRIVATE-BATCH-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.market_id),
            HashPart::Str(&request.pair_id),
            HashPart::Str(&request.opening_state_root),
            HashPart::Str(&request.encrypted_order_root),
            HashPart::U64(request.opened_height),
            HashPart::U64(request.seal_height),
        ],
        32,
    )
}

pub fn solver_bid_id(request: &SolverBidRequest) -> String {
    domain_hash(
        "FAST-PQ-SOLVER-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.auction_id),
            HashPart::Str(&request.solver_id),
            HashPart::Str(&request.bid_commitment),
            HashPart::Str(&request.proposed_settlement_root),
            HashPart::U64(request.fee_micro_units),
            HashPart::U64(request.submitted_height),
        ],
        32,
    )
}

pub fn contract_bundle_id(request: &ContractCallBundleIntentRequest) -> String {
    domain_hash(
        "FAST-PQ-CONTRACT-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.contract_namespace),
            HashPart::Str(&request.call_graph_root),
            HashPart::Str(&request.encrypted_calldata_root),
            HashPart::Str(&request.pq_authorization_root),
            HashPart::U64(request.submitted_height),
        ],
        32,
    )
}

pub fn low_fee_rebate_id(request: &LowFeeRebateRequest, rebate_micro_units: u64) -> String {
    domain_hash(
        "FAST-PQ-LOW-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.beneficiary_commitment),
            HashPart::Str(&request.rebate_nullifier),
            HashPart::U64(request.fee_paid_micro_units),
            HashPart::U64(rebate_micro_units),
            HashPart::U64(request.issued_height),
        ],
        32,
    )
}

pub fn cancellation_nullifier_id(request: &PrivateCancellationNullifierRequest) -> String {
    domain_hash(
        "FAST-PQ-CANCELLATION-NULLIFIER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(&request.nullifier),
            HashPart::Str(&request.owner_commitment),
            HashPart::U64(request.height),
        ],
        32,
    )
}

pub fn settlement_receipt_id(request: &SettlementReceiptRequest) -> String {
    domain_hash(
        "FAST-PQ-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.auction_id.as_deref().unwrap_or("")),
            HashPart::Str(request.ticket_id.as_deref().unwrap_or("")),
            HashPart::Str(request.bundle_id.as_deref().unwrap_or("")),
            HashPart::Str(&request.solver_id),
            HashPart::Str(&request.settlement_state_root),
            HashPart::U64(request.settled_height),
        ],
        32,
    )
}

pub fn sla_snapshot_id(request: &LatencySlaSnapshotRequest) -> String {
    domain_hash(
        "FAST-PQ-LATENCY-SLA-SNAPSHOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.sequencer_id),
            HashPart::U64(request.window_start_height),
            HashPart::U64(request.window_end_height),
            HashPart::Str(&request.observed_ticket_root),
        ],
        32,
    )
}

pub fn slashing_evidence_id(request: &SlashingEvidenceRequest) -> String {
    domain_hash(
        "FAST-PQ-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.offender_id),
            HashPart::Str(request.reason.as_str()),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.evidence_root),
            HashPart::Str(&request.witness_root),
            HashPart::U64(request.height),
        ],
        32,
    )
}

pub fn order_priority_score(
    side: OrderSide,
    asset_class: AssetClass,
    privacy_set_size: u64,
    max_fee_micro_units: u64,
    fee_cap_bps: u64,
) -> u64 {
    let privacy_score = privacy_set_size.min(65_536) / 64;
    let fee_score = max_fee_micro_units.min(1_000_000) / 1_000;
    let low_fee_bonus = MAX_BPS.saturating_sub(fee_cap_bps.min(MAX_BPS)) / 100;
    side.priority_weight()
        .saturating_mul(10)
        .saturating_add(asset_class.privacy_floor() / 128)
        .saturating_add(privacy_score)
        .saturating_add(fee_score)
        .saturating_add(low_fee_bonus)
}

pub fn solver_bid_score(fee_micro_units: u64, latency_ms: u64) -> u64 {
    let fee_penalty = fee_micro_units.min(10_000_000) / 1_000;
    let latency_penalty = latency_ms.min(10_000);
    20_000_u64.saturating_sub(fee_penalty.saturating_add(latency_penalty))
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("FAST-PQ-ORDERBOOK-{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}

pub fn string_merkle_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(&format!("FAST-PQ-ORDERBOOK-{domain}"), &leaves)
}

pub fn map_root<T: PublicRecord>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(id, value)| {
            json!({
                "id": id,
                "record": value.public_record(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(&format!("FAST-PQ-ORDERBOOK-{domain}"), &leaves)
}

fn ensure_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} must be <= {MAX_BPS}"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(label: &str, len: usize, max: usize) -> Result<()> {
    if len >= max {
        Err(format!("{label} capacity {max} exhausted"))
    } else {
        Ok(())
    }
}

fn ensure_absent<T>(label: &str, map: &BTreeMap<String, T>, id: &str) -> Result<()> {
    if map.contains_key(id) {
        Err(format!("{label} id {id} already exists"))
    } else {
        Ok(())
    }
}

pub fn deterministic_devnet_order_request(
    label: &str,
    height: u64,
) -> EncryptedOrderCommitmentRequest {
    let seed = domain_hash(
        "FAST-PQ-ORDERBOOK-DEVNET-ORDER-SEED",
        &[HashPart::Str(label), HashPart::U64(height)],
        32,
    );
    EncryptedOrderCommitmentRequest {
        owner_commitment: domain_hash("FAST-PQ-OWNER", &[HashPart::Str(&seed)], 32),
        market_id: "xmr-usd-confidential".to_string(),
        pair_id: "xmr:zusd".to_string(),
        side: OrderSide::Buy,
        asset_class: AssetClass::Monero,
        encrypted_order_payload_root: domain_hash(
            "FAST-PQ-ENCRYPTED-PAYLOAD",
            &[HashPart::Str(&seed)],
            32,
        ),
        order_commitment: domain_hash("FAST-PQ-ORDER-COMMITMENT", &[HashPart::Str(&seed)], 32),
        reveal_key_commitment: domain_hash("FAST-PQ-REVEAL-KEY", &[HashPart::Str(&seed)], 32),
        nullifier_commitment: domain_hash(
            "FAST-PQ-NULLIFIER-COMMITMENT",
            &[HashPart::Str(&seed)],
            32,
        ),
        account_nonce_commitment: domain_hash("FAST-PQ-ACCOUNT-NONCE", &[HashPart::Str(&seed)], 32),
        max_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS,
        fee_cap_bps: DEFAULT_MAX_USER_FEE_BPS,
        notional_commitment: domain_hash("FAST-PQ-NOTIONAL", &[HashPart::Str(&seed)], 32),
        limit_price_commitment: domain_hash("FAST-PQ-LIMIT-PRICE", &[HashPart::Str(&seed)], 32),
        privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
        pq_ciphertext_root: domain_hash("FAST-PQ-CIPHERTEXT", &[HashPart::Str(&seed)], 32),
        pq_public_key_root: domain_hash("FAST-PQ-PUBLIC-KEY", &[HashPart::Str(&seed)], 32),
        proof_root: domain_hash("FAST-PQ-ORDER-PROOF", &[HashPart::Str(&seed)], 32),
        submitted_height: height,
        expires_height: height + DEFAULT_AUCTION_TTL_BLOCKS,
    }
}

pub fn deterministic_devnet_state() -> State {
    let mut state = State::devnet();
    let order = state
        .submit_encrypted_order(deterministic_devnet_order_request(
            "genesis-order",
            DEVNET_L2_HEIGHT,
        ))
        .expect("deterministic devnet order");
    let approval_request = PqSequencerApprovalRequest {
        order_id: order.order_id.clone(),
        sequencer_id: "devnet-pq-sequencer-0".to_string(),
        committee_id: "devnet-fast-committee".to_string(),
        approval_round: 0,
        approved_payload_root: order.state_root(),
        pq_signature_root: domain_hash("FAST-PQ-DEVNET-SIG", &[HashPart::Str(&order.order_id)], 32),
        transcript_root: domain_hash(
            "FAST-PQ-DEVNET-TRANSCRIPT",
            &[HashPart::Str(&order.order_id)],
            32,
        ),
        security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        latency_budget_ms: DEFAULT_TARGET_PRECONF_MS,
        approved_height: DEVNET_L2_HEIGHT,
    };
    let approval = state
        .approve_order_pq(approval_request)
        .expect("devnet approval");
    let ticket_request = FastPreconfirmationTicketRequest {
        order_id: order.order_id.clone(),
        approval_id: approval.approval_id.clone(),
        ticket_owner_commitment: order.owner_commitment.clone(),
        inclusion_lane: "fast-private-defi".to_string(),
        preconfirmed_state_root: state.state_root(),
        fee_lock_commitment: domain_hash(
            "FAST-PQ-DEVNET-FEE-LOCK",
            &[HashPart::Str(&order.order_id)],
            32,
        ),
        rebate_hint_commitment: domain_hash(
            "FAST-PQ-DEVNET-REBATE-HINT",
            &[HashPart::Str(&order.order_id)],
            32,
        ),
        ticket_nullifier_commitment: domain_hash(
            "FAST-PQ-DEVNET-TICKET-NULLIFIER",
            &[HashPart::Str(&order.order_id)],
            32,
        ),
        issued_height: DEVNET_L2_HEIGHT,
        expires_height: DEVNET_L2_HEIGHT + DEFAULT_TICKET_TTL_BLOCKS,
        promised_latency_ms: DEFAULT_TARGET_PRECONF_MS,
    };
    let _ticket = state
        .issue_preconfirmation_ticket(ticket_request)
        .expect("devnet ticket");
    state
}
