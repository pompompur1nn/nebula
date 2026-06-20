use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_FAST_WITHDRAWAL_NETTING_AUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-fast-withdrawal-netting-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_FAST_WITHDRAWAL_NETTING_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_AUCTION_ID: &str = "monero-l2-pq-private-fast-withdrawal-netting-auction-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_128_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_PROOF_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-private-fast-withdrawal-v1";
pub const SEALED_INTENT_SCHEME: &str = "monero-l2-sealed-withdrawal-intent-root-v1";
pub const LIQUIDITY_BID_SCHEME: &str = "pq-private-fast-withdrawal-liquidity-bid-root-v1";
pub const NETTING_ROUND_SCHEME: &str = "confidential-withdrawal-netting-round-root-v1";
pub const SETTLEMENT_RECEIPT_SCHEME: &str = "fast-monero-exit-settlement-receipt-root-v1";
pub const LOW_FEE_REBATE_SCHEME: &str = "fast-withdrawal-low-fee-rebate-root-v1";
pub const PRIVACY_ACCOUNTING_SCHEME: &str = "withdrawal-privacy-set-accounting-root-v1";
pub const SLASHING_SCHEME: &str = "stale-liquidity-invalid-proof-slashing-root-v1";
pub const REPLAY_DOMAIN: &str = "monero-l2-pq-private-fast-withdrawal-netting-auction-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_PROOF_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_ROUND_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_LP_STAKE_PICONERO: u64 = 2_000_000_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_FAST_LANE_FEE_BPS: u64 = 14;
pub const DEFAULT_DEFI_LANE_FEE_BPS: u64 = 9;
pub const DEFAULT_LOW_FEE_LANE_BPS: u64 = 4;
pub const DEFAULT_REBATE_BPS: u64 = 5;
pub const DEFAULT_SLASH_INVALID_PROOF_BPS: u64 = 2_500;
pub const DEFAULT_SLASH_STALE_LIQUIDITY_BPS: u64 = 850;
pub const DEFAULT_MAX_ROUND_ITEMS: usize = 512;
pub const DEFAULT_MIN_NETTING_FILL_BPS: u64 = 2_000;
pub const MAX_INTENTS: usize = 2_097_152;
pub const MAX_PROOFS: usize = 4_194_304;
pub const MAX_BIDS: usize = 2_097_152;
pub const MAX_ROUNDS: usize = 524_288;
pub const MAX_RECEIPTS: usize = 4_194_304;
pub const MAX_REBATES: usize = 2_097_152;
pub const MAX_PRIVACY_ACCOUNTS: usize = 2_097_152;
pub const MAX_SLASHINGS: usize = 1_048_576;
pub const MAX_PUBLIC_RECORDS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalLane {
    LowFee,
    Standard,
    Fast,
    DefiLiquidity,
    AtomicSwap,
    Emergency,
}

impl WithdrawalLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::DefiLiquidity => "defi_liquidity",
            Self::AtomicSwap => "atomic_swap",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFee => config.low_fee_lane_bps,
            Self::Standard => config.max_user_fee_bps.saturating_mul(2) / 3,
            Self::Fast | Self::Emergency => config.fast_lane_fee_bps,
            Self::DefiLiquidity | Self::AtomicSwap => config.defi_lane_fee_bps,
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::Fast => 940,
            Self::DefiLiquidity => 900,
            Self::AtomicSwap => 860,
            Self::Standard => 760,
            Self::LowFee => 680,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    WalletExit,
    DefiPositionExit,
    TokenUnwrap,
    AtomicSwapPayout,
    MarketMakerRebalance,
    EmergencyExit,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletExit => "wallet_exit",
            Self::DefiPositionExit => "defi_position_exit",
            Self::TokenUnwrap => "token_unwrap",
            Self::AtomicSwapPayout => "atomic_swap_payout",
            Self::MarketMakerRebalance => "market_maker_rebalance",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn requires_defi_lane(self) -> bool {
        matches!(
            self,
            Self::DefiPositionExit | Self::TokenUnwrap | Self::MarketMakerRebalance
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Sealed,
    ProofAttached,
    Bidding,
    BidAccepted,
    Netted,
    ReceiptPublished,
    Settled,
    Expired,
    Rejected,
    Slashed,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::ProofAttached => "proof_attached",
            Self::Bidding => "bidding",
            Self::BidAccepted => "bid_accepted",
            Self::Netted => "netted",
            Self::ReceiptPublished => "receipt_published",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed
                | Self::ProofAttached
                | Self::Bidding
                | Self::BidAccepted
                | Self::Netted
                | Self::ReceiptPublished
        )
    }

    pub fn nettable(self) -> bool {
        matches!(
            self,
            Self::BidAccepted | Self::ProofAttached | Self::Bidding
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Submitted,
    Accepted,
    Invalid,
    Expired,
    Slashed,
}

impl ProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Invalid => "invalid",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Posted,
    Accepted,
    Superseded,
    Netted,
    Settled,
    Stale,
    Slashed,
    Rejected,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Stale => "stale",
            Self::Slashed => "slashed",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Posted | Self::Accepted | Self::Netted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundStatus {
    Open,
    Sealed,
    Cleared,
    ReceiptPublished,
    Settled,
    Expired,
    Challenged,
}

impl RoundStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Cleared => "cleared",
            Self::ReceiptPublished => "receipt_published",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    InvalidPqProof,
    ReplayedNullifier,
    StaleLiquidity,
    UnderfundedBid,
    ReceiptMismatch,
    PrivacySetShortfall,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqProof => "invalid_pq_proof",
            Self::ReplayedNullifier => "replayed_nullifier",
            Self::StaleLiquidity => "stale_liquidity",
            Self::UnderfundedBid => "underfunded_bid",
            Self::ReceiptMismatch => "receipt_mismatch",
            Self::PrivacySetShortfall => "privacy_set_shortfall",
        }
    }

    pub fn penalty_bps(self, config: &Config) -> u64 {
        match self {
            Self::InvalidPqProof | Self::ReplayedNullifier | Self::ReceiptMismatch => {
                config.slash_invalid_proof_bps
            }
            Self::StaleLiquidity | Self::UnderfundedBid | Self::PrivacySetShortfall => {
                config.slash_stale_liquidity_bps
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub auction_id: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_auth_proof_suite: String,
    pub sealed_intent_scheme: String,
    pub liquidity_bid_scheme: String,
    pub netting_round_scheme: String,
    pub settlement_receipt_scheme: String,
    pub low_fee_rebate_scheme: String,
    pub privacy_accounting_scheme: String,
    pub slashing_scheme: String,
    pub replay_domain: String,
    pub genesis_height: u64,
    pub intent_ttl_blocks: u64,
    pub proof_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub round_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_lp_stake_piconero: u64,
    pub max_user_fee_bps: u64,
    pub fast_lane_fee_bps: u64,
    pub defi_lane_fee_bps: u64,
    pub low_fee_lane_bps: u64,
    pub rebate_bps: u64,
    pub slash_invalid_proof_bps: u64,
    pub slash_stale_liquidity_bps: u64,
    pub max_round_items: usize,
    pub min_netting_fill_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            auction_id: DEVNET_AUCTION_ID.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_proof_suite: PQ_AUTH_PROOF_SUITE.to_string(),
            sealed_intent_scheme: SEALED_INTENT_SCHEME.to_string(),
            liquidity_bid_scheme: LIQUIDITY_BID_SCHEME.to_string(),
            netting_round_scheme: NETTING_ROUND_SCHEME.to_string(),
            settlement_receipt_scheme: SETTLEMENT_RECEIPT_SCHEME.to_string(),
            low_fee_rebate_scheme: LOW_FEE_REBATE_SCHEME.to_string(),
            privacy_accounting_scheme: PRIVACY_ACCOUNTING_SCHEME.to_string(),
            slashing_scheme: SLASHING_SCHEME.to_string(),
            replay_domain: REPLAY_DOMAIN.to_string(),
            genesis_height: DEVNET_HEIGHT,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            proof_ttl_blocks: DEFAULT_PROOF_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            round_ttl_blocks: DEFAULT_ROUND_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_lp_stake_piconero: DEFAULT_MIN_LP_STAKE_PICONERO,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            fast_lane_fee_bps: DEFAULT_FAST_LANE_FEE_BPS,
            defi_lane_fee_bps: DEFAULT_DEFI_LANE_FEE_BPS,
            low_fee_lane_bps: DEFAULT_LOW_FEE_LANE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            slash_invalid_proof_bps: DEFAULT_SLASH_INVALID_PROOF_BPS,
            slash_stale_liquidity_bps: DEFAULT_SLASH_STALE_LIQUIDITY_BPS,
            max_round_items: DEFAULT_MAX_ROUND_ITEMS,
            min_netting_fill_bps: DEFAULT_MIN_NETTING_FILL_BPS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_sequence: u64,
    pub intents_sealed: u64,
    pub proofs_attached: u64,
    pub bids_posted: u64,
    pub bids_accepted: u64,
    pub rounds_opened: u64,
    pub rounds_cleared: u64,
    pub receipts_published: u64,
    pub rebates_issued: u64,
    pub privacy_accounts_recorded: u64,
    pub slashing_events: u64,
    pub expired_items: u64,
    pub public_records: usize,
    pub total_requested_piconero: u128,
    pub total_fast_filled_piconero: u128,
    pub total_net_settled_piconero: u128,
    pub total_rebated_piconero: u128,
    pub total_slashed_piconero: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub intent_root: String,
    pub proof_root: String,
    pub bid_root: String,
    pub round_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub privacy_account_root: String,
    pub slashing_root: String,
    pub consumed_nullifier_root: String,
    pub lp_index_root: String,
    pub intent_owner_index_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedWithdrawalIntent {
    pub intent_id: String,
    pub sequence: u64,
    pub kind: IntentKind,
    pub lane: WithdrawalLane,
    pub owner_commitment: String,
    pub sealed_payload_root: String,
    pub pq_ciphertext_root: String,
    pub monero_stealth_address_commitment: String,
    pub amount_commitment: String,
    pub amount_piconero_hint: u128,
    pub withdrawal_nullifier: String,
    pub defi_context_root: Option<String>,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub submitted_l2_height: u64,
    pub expires_l2_height: u64,
    pub status: IntentStatus,
    pub proof_id: Option<String>,
    pub accepted_bid_id: Option<String>,
    pub round_id: Option<String>,
    pub receipt_id: Option<String>,
    pub metadata_root: String,
}

impl SealedWithdrawalIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "sequence": self.sequence,
            "kind": self.kind.as_str(),
            "lane": self.lane.as_str(),
            "owner_commitment": self.owner_commitment,
            "sealed_payload_root": self.sealed_payload_root,
            "pq_ciphertext_root": self.pq_ciphertext_root,
            "monero_stealth_address_commitment": self.monero_stealth_address_commitment,
            "amount_commitment": self.amount_commitment,
            "amount_piconero_hint": self.amount_piconero_hint,
            "withdrawal_nullifier": self.withdrawal_nullifier,
            "defi_context_root": self.defi_context_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "submitted_l2_height": self.submitted_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "status": self.status.as_str(),
            "proof_id": self.proof_id,
            "accepted_bid_id": self.accepted_bid_id,
            "round_id": self.round_id,
            "receipt_id": self.receipt_id,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAuthorizationProof {
    pub proof_id: String,
    pub intent_id: String,
    pub prover_commitment: String,
    pub authorization_root: String,
    pub proof_root: String,
    pub nullifier_root: String,
    pub transcript_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub attached_l2_height: u64,
    pub expires_l2_height: u64,
    pub status: ProofStatus,
}

impl PqAuthorizationProof {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "intent_id": self.intent_id,
            "prover_commitment": self.prover_commitment,
            "authorization_root": self.authorization_root,
            "proof_root": self.proof_root,
            "nullifier_root": self.nullifier_root,
            "transcript_root": self.transcript_root,
            "pq_public_key_root": self.pq_public_key_root,
            "pq_signature_root": self.pq_signature_root,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "attached_l2_height": self.attached_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityProviderBid {
    pub bid_id: String,
    pub intent_id: String,
    pub lp_id: String,
    pub lp_stake_piconero: u64,
    pub bid_commitment_root: String,
    pub reserve_proof_root: String,
    pub settlement_route_root: String,
    pub advance_amount_piconero: u128,
    pub fee_bps: u64,
    pub max_settlement_l2_height: u64,
    pub posted_l2_height: u64,
    pub expires_l2_height: u64,
    pub status: BidStatus,
}

impl LiquidityProviderBid {
    pub fn fee_piconero(&self) -> u128 {
        bps_amount(self.advance_amount_piconero, self.fee_bps)
    }

    pub fn net_advance_piconero(&self) -> u128 {
        self.advance_amount_piconero
            .saturating_sub(self.fee_piconero())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "intent_id": self.intent_id,
            "lp_id": self.lp_id,
            "lp_stake_piconero": self.lp_stake_piconero,
            "bid_commitment_root": self.bid_commitment_root,
            "reserve_proof_root": self.reserve_proof_root,
            "settlement_route_root": self.settlement_route_root,
            "advance_amount_piconero": self.advance_amount_piconero,
            "fee_bps": self.fee_bps,
            "fee_piconero": self.fee_piconero(),
            "net_advance_piconero": self.net_advance_piconero(),
            "max_settlement_l2_height": self.max_settlement_l2_height,
            "posted_l2_height": self.posted_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NettingRound {
    pub round_id: String,
    pub sequence: u64,
    pub coordinator_id: String,
    pub lane: WithdrawalLane,
    pub intent_ids: BTreeSet<String>,
    pub bid_ids: BTreeSet<String>,
    pub netted_commitment_root: String,
    pub clearing_price_bps: u64,
    pub gross_withdrawal_piconero: u128,
    pub net_lp_advance_piconero: u128,
    pub net_settlement_piconero: u128,
    pub privacy_set_size: u64,
    pub opened_l2_height: u64,
    pub expires_l2_height: u64,
    pub status: RoundStatus,
    pub receipt_id: Option<String>,
}

impl NettingRound {
    pub fn fill_bps(&self) -> u64 {
        if self.gross_withdrawal_piconero == 0 {
            0
        } else {
            ((self.net_lp_advance_piconero.saturating_mul(MAX_BPS as u128))
                / self.gross_withdrawal_piconero) as u64
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "round_id": self.round_id,
            "sequence": self.sequence,
            "coordinator_id": self.coordinator_id,
            "lane": self.lane.as_str(),
            "intent_ids": self.intent_ids,
            "bid_ids": self.bid_ids,
            "netted_commitment_root": self.netted_commitment_root,
            "clearing_price_bps": self.clearing_price_bps,
            "gross_withdrawal_piconero": self.gross_withdrawal_piconero,
            "net_lp_advance_piconero": self.net_lp_advance_piconero,
            "net_settlement_piconero": self.net_settlement_piconero,
            "fill_bps": self.fill_bps(),
            "privacy_set_size": self.privacy_set_size,
            "opened_l2_height": self.opened_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "status": self.status.as_str(),
            "receipt_id": self.receipt_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FastSettlementReceipt {
    pub receipt_id: String,
    pub round_id: String,
    pub monero_tx_root: String,
    pub l2_settlement_root: String,
    pub lp_fill_root: String,
    pub intent_fill_root: String,
    pub total_paid_piconero: u128,
    pub total_fee_piconero: u128,
    pub total_rebate_piconero: u128,
    pub published_l2_height: u64,
    pub expires_l2_height: u64,
    pub settlement_finality_height: u64,
}

impl FastSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub intent_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub fee_paid_piconero: u128,
    pub rebate_piconero: u128,
    pub rebate_bps: u64,
    pub issued_l2_height: u64,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacySetAccount {
    pub account_id: String,
    pub subject_id: String,
    pub lane: WithdrawalLane,
    pub window_start_l2_height: u64,
    pub window_end_l2_height: u64,
    pub participant_count: u64,
    pub decoy_count: u64,
    pub liquidity_provider_count: u64,
    pub privacy_set_size: u64,
    pub commitment_root: String,
}

impl PrivacySetAccount {
    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "subject_id": self.subject_id,
            "lane": self.lane.as_str(),
            "window_start_l2_height": self.window_start_l2_height,
            "window_end_l2_height": self.window_end_l2_height,
            "participant_count": self.participant_count,
            "decoy_count": self.decoy_count,
            "liquidity_provider_count": self.liquidity_provider_count,
            "privacy_set_size": self.privacy_set_size,
            "commitment_root": self.commitment_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvent {
    pub slashing_id: String,
    pub offender_id: String,
    pub intent_id: Option<String>,
    pub proof_id: Option<String>,
    pub bid_id: Option<String>,
    pub round_id: Option<String>,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub base_bond_piconero: u128,
    pub penalty_bps: u64,
    pub slashed_piconero: u128,
    pub created_l2_height: u64,
}

impl SlashingEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "slashing_id": self.slashing_id,
            "offender_id": self.offender_id,
            "intent_id": self.intent_id,
            "proof_id": self.proof_id,
            "bid_id": self.bid_id,
            "round_id": self.round_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "base_bond_piconero": self.base_bond_piconero,
            "penalty_bps": self.penalty_bps,
            "slashed_piconero": self.slashed_piconero,
            "created_l2_height": self.created_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealWithdrawalIntentRequest {
    pub kind: IntentKind,
    pub lane: WithdrawalLane,
    pub owner_commitment: String,
    pub sealed_payload_root: String,
    pub pq_ciphertext_root: String,
    pub monero_stealth_address_commitment: String,
    pub amount_commitment: String,
    pub amount_piconero_hint: u128,
    pub withdrawal_nullifier: String,
    pub defi_context_root: Option<String>,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub metadata_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttachPqAuthorizationProofRequest {
    pub intent_id: String,
    pub prover_commitment: String,
    pub authorization_root: String,
    pub proof_root: String,
    pub nullifier_root: String,
    pub transcript_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PostLiquidityProviderBidRequest {
    pub intent_id: String,
    pub lp_id: String,
    pub lp_stake_piconero: u64,
    pub bid_commitment_root: String,
    pub reserve_proof_root: String,
    pub settlement_route_root: String,
    pub advance_amount_piconero: u128,
    pub fee_bps: u64,
    pub max_settlement_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AcceptLiquidityProviderBidRequest {
    pub intent_id: String,
    pub bid_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenNettingRoundRequest {
    pub coordinator_id: String,
    pub lane: WithdrawalLane,
    pub intent_ids: BTreeSet<String>,
    pub netted_commitment_root: String,
    pub clearing_price_bps: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishFastSettlementReceiptRequest {
    pub round_id: String,
    pub monero_tx_root: String,
    pub l2_settlement_root: String,
    pub lp_fill_root: String,
    pub intent_fill_root: String,
    pub total_paid_piconero: u128,
    pub total_fee_piconero: u128,
    pub settlement_finality_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordPrivacySetAccountRequest {
    pub subject_id: String,
    pub lane: WithdrawalLane,
    pub window_start_l2_height: u64,
    pub window_end_l2_height: u64,
    pub participant_count: u64,
    pub decoy_count: u64,
    pub liquidity_provider_count: u64,
    pub privacy_set_size: u64,
    pub commitment_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashInvalidProofRequest {
    pub offender_id: String,
    pub intent_id: String,
    pub proof_id: String,
    pub evidence_root: String,
    pub base_bond_piconero: u128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashStaleLiquidityRequest {
    pub offender_id: String,
    pub bid_id: String,
    pub evidence_root: String,
    pub base_bond_piconero: u128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_l2_height: u64,
    pub counters: Counters,
    pub intents: BTreeMap<String, SealedWithdrawalIntent>,
    pub proofs: BTreeMap<String, PqAuthorizationProof>,
    pub bids: BTreeMap<String, LiquidityProviderBid>,
    pub rounds: BTreeMap<String, NettingRound>,
    pub receipts: BTreeMap<String, FastSettlementReceipt>,
    pub rebates: BTreeMap<String, LowFeeRebate>,
    pub privacy_accounts: BTreeMap<String, PrivacySetAccount>,
    pub slashings: BTreeMap<String, SlashingEvent>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub lp_index: BTreeMap<String, BTreeSet<String>>,
    pub intent_owner_index: BTreeMap<String, BTreeSet<String>>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            current_l2_height: config.genesis_height,
            config,
            counters: Counters::default(),
            intents: BTreeMap::new(),
            proofs: BTreeMap::new(),
            bids: BTreeMap::new(),
            rounds: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_accounts: BTreeMap::new(),
            slashings: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            lp_index: BTreeMap::new(),
            intent_owner_index: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        state
            .seal_withdrawal_intent(SealWithdrawalIntentRequest {
                kind: IntentKind::DefiPositionExit,
                lane: WithdrawalLane::DefiLiquidity,
                owner_commitment: "devnet-owner-commitment-0".to_string(),
                sealed_payload_root: root_from_parts(
                    "DEVNET-SEALED-WITHDRAWAL-PAYLOAD",
                    &[HashPart::Str("payload-0")],
                ),
                pq_ciphertext_root: root_from_parts(
                    "DEVNET-PQ-CIPHERTEXT",
                    &[HashPart::Str("ml-kem-0")],
                ),
                monero_stealth_address_commitment: "devnet-stealth-address-commitment-0"
                    .to_string(),
                amount_commitment: "devnet-confidential-amount-commitment-0".to_string(),
                amount_piconero_hint: 4_200_000_000_000,
                withdrawal_nullifier: "devnet-fast-withdrawal-nullifier-0".to_string(),
                defi_context_root: Some(root_from_parts(
                    "DEVNET-DEFI-CONTEXT",
                    &[HashPart::Str("pool-exit")],
                )),
                max_fee_bps: DEFAULT_DEFI_LANE_FEE_BPS,
                privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
                metadata_root: root_from_parts(
                    "DEVNET-WITHDRAWAL-METADATA",
                    &[HashPart::Str("fast-defi")],
                ),
            })
            .expect("devnet intent");
        let intent_id = state
            .intents
            .keys()
            .next()
            .expect("devnet intent exists")
            .clone();
        state
            .attach_pq_authorization_proof(AttachPqAuthorizationProofRequest {
                intent_id: intent_id.clone(),
                prover_commitment: "devnet-prover-commitment-0".to_string(),
                authorization_root: root_from_parts(
                    "DEVNET-AUTHORIZATION",
                    &[HashPart::Str("authorization")],
                ),
                proof_root: root_from_parts("DEVNET-PROOF", &[HashPart::Str("proof")]),
                nullifier_root: root_from_parts("DEVNET-NULLIFIER", &[HashPart::Str("nullifier")]),
                transcript_root: root_from_parts(
                    "DEVNET-TRANSCRIPT",
                    &[HashPart::Str("transcript")],
                ),
                pq_public_key_root: root_from_parts("DEVNET-PQ-PK", &[HashPart::Str("pk")]),
                pq_signature_root: root_from_parts("DEVNET-PQ-SIG", &[HashPart::Str("sig")]),
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            })
            .expect("devnet proof");
        let bid = state
            .post_liquidity_provider_bid(PostLiquidityProviderBidRequest {
                intent_id: intent_id.clone(),
                lp_id: "devnet-lp-0".to_string(),
                lp_stake_piconero: DEFAULT_MIN_LP_STAKE_PICONERO,
                bid_commitment_root: root_from_parts("DEVNET-BID", &[HashPart::Str("bid")]),
                reserve_proof_root: root_from_parts("DEVNET-RESERVE", &[HashPart::Str("reserve")]),
                settlement_route_root: root_from_parts("DEVNET-ROUTE", &[HashPart::Str("route")]),
                advance_amount_piconero: 4_200_000_000_000,
                fee_bps: DEFAULT_DEFI_LANE_FEE_BPS,
                max_settlement_l2_height: DEVNET_HEIGHT + 8,
            })
            .expect("devnet bid");
        state
            .accept_liquidity_provider_bid(AcceptLiquidityProviderBidRequest {
                intent_id: intent_id.clone(),
                bid_id: bid.bid_id.clone(),
            })
            .expect("devnet accept bid");
        let round = state
            .open_netting_round(OpenNettingRoundRequest {
                coordinator_id: "devnet-netting-coordinator-0".to_string(),
                lane: WithdrawalLane::DefiLiquidity,
                intent_ids: BTreeSet::from([intent_id.clone()]),
                netted_commitment_root: root_from_parts(
                    "DEVNET-NETTED",
                    &[HashPart::Str("netted")],
                ),
                clearing_price_bps: DEFAULT_DEFI_LANE_FEE_BPS,
                privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            })
            .expect("devnet round");
        state
            .publish_fast_settlement_receipt(PublishFastSettlementReceiptRequest {
                round_id: round.round_id,
                monero_tx_root: root_from_parts("DEVNET-MONERO-TX", &[HashPart::Str("tx")]),
                l2_settlement_root: root_from_parts(
                    "DEVNET-L2-SETTLEMENT",
                    &[HashPart::Str("settlement")],
                ),
                lp_fill_root: root_from_parts("DEVNET-LP-FILL", &[HashPart::Str("lp-fill")]),
                intent_fill_root: root_from_parts(
                    "DEVNET-INTENT-FILL",
                    &[HashPart::Str("intent-fill")],
                ),
                total_paid_piconero: 4_196_220_000_000,
                total_fee_piconero: 3_780_000_000,
                settlement_finality_height: DEVNET_HEIGHT + 20,
            })
            .expect("devnet receipt");
        state
    }

    pub fn advance_height(&mut self, height: u64) -> Result<()> {
        if height < self.current_l2_height {
            return Err("cannot move l2 height backwards".to_string());
        }
        self.current_l2_height = height;
        Ok(())
    }

    pub fn seal_withdrawal_intent(
        &mut self,
        request: SealWithdrawalIntentRequest,
    ) -> Result<SealedWithdrawalIntent> {
        self.ensure_capacity("intents", self.intents.len(), MAX_INTENTS)?;
        if request.owner_commitment.is_empty()
            || request.sealed_payload_root.is_empty()
            || request.pq_ciphertext_root.is_empty()
            || request.withdrawal_nullifier.is_empty()
        {
            return Err(
                "sealed intent requires owner, payload, pq ciphertext, and nullifier".to_string(),
            );
        }
        if self
            .consumed_nullifiers
            .contains(&request.withdrawal_nullifier)
        {
            return Err("withdrawal nullifier already consumed".to_string());
        }
        if request.kind.requires_defi_lane()
            && !matches!(
                request.lane,
                WithdrawalLane::DefiLiquidity
                    | WithdrawalLane::AtomicSwap
                    | WithdrawalLane::Emergency
            )
        {
            return Err("defi withdrawal kind requires defi, swap, or emergency lane".to_string());
        }
        if request.max_fee_bps > request.lane.fee_bps(&self.config)
            || request.max_fee_bps > self.config.max_user_fee_bps
        {
            return Err("intent fee cap exceeds lane or configured maximum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("intent privacy set below configured floor".to_string());
        }
        let sequence = self.next_sequence();
        let intent_id = intent_id(sequence, &request);
        if self.intents.contains_key(&intent_id) {
            return Err("intent already exists".to_string());
        }
        let intent = SealedWithdrawalIntent {
            intent_id: intent_id.clone(),
            sequence,
            kind: request.kind,
            lane: request.lane,
            owner_commitment: request.owner_commitment,
            sealed_payload_root: request.sealed_payload_root,
            pq_ciphertext_root: request.pq_ciphertext_root,
            monero_stealth_address_commitment: request.monero_stealth_address_commitment,
            amount_commitment: request.amount_commitment,
            amount_piconero_hint: request.amount_piconero_hint,
            withdrawal_nullifier: request.withdrawal_nullifier.clone(),
            defi_context_root: request.defi_context_root,
            max_fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            submitted_l2_height: self.current_l2_height,
            expires_l2_height: self.current_l2_height + self.config.intent_ttl_blocks,
            status: IntentStatus::Sealed,
            proof_id: None,
            accepted_bid_id: None,
            round_id: None,
            receipt_id: None,
            metadata_root: request.metadata_root,
        };
        self.consumed_nullifiers
            .insert(request.withdrawal_nullifier);
        self.intent_owner_index
            .entry(intent.owner_commitment.clone())
            .or_default()
            .insert(intent_id.clone());
        self.counters.intents_sealed += 1;
        self.counters.total_requested_piconero = self
            .counters
            .total_requested_piconero
            .saturating_add(intent.amount_piconero_hint);
        self.intents.insert(intent_id.clone(), intent.clone());
        self.record_public(format!("intent:{intent_id}"), intent.public_record())?;
        Ok(intent)
    }

    pub fn attach_pq_authorization_proof(
        &mut self,
        request: AttachPqAuthorizationProofRequest,
    ) -> Result<PqAuthorizationProof> {
        self.ensure_capacity("proofs", self.proofs.len(), MAX_PROOFS)?;
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq proof security below configured floor".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("pq proof privacy set below configured floor".to_string());
        }
        let intent = self
            .intents
            .get_mut(&request.intent_id)
            .ok_or_else(|| "intent not found for pq proof".to_string())?;
        if !intent.status.live() || self.current_l2_height > intent.expires_l2_height {
            return Err("intent is not live for pq proof attachment".to_string());
        }
        if intent.proof_id.is_some() {
            return Err("intent already has pq proof".to_string());
        }
        if request.prover_commitment.is_empty()
            || request.authorization_root.is_empty()
            || request.proof_root.is_empty()
            || request.transcript_root.is_empty()
        {
            return Err("pq proof request has empty roots".to_string());
        }
        let proof_id = pq_proof_id(
            &request.intent_id,
            &request.proof_root,
            self.current_l2_height,
        );
        if self.proofs.contains_key(&proof_id) {
            return Err("pq proof already exists".to_string());
        }
        let proof = PqAuthorizationProof {
            proof_id: proof_id.clone(),
            intent_id: request.intent_id.clone(),
            prover_commitment: request.prover_commitment,
            authorization_root: request.authorization_root,
            proof_root: request.proof_root,
            nullifier_root: request.nullifier_root,
            transcript_root: request.transcript_root,
            pq_public_key_root: request.pq_public_key_root,
            pq_signature_root: request.pq_signature_root,
            pq_security_bits: request.pq_security_bits,
            privacy_set_size: request.privacy_set_size,
            attached_l2_height: self.current_l2_height,
            expires_l2_height: self.current_l2_height + self.config.proof_ttl_blocks,
            status: ProofStatus::Accepted,
        };
        intent.proof_id = Some(proof_id.clone());
        intent.status = IntentStatus::ProofAttached;
        self.counters.proofs_attached += 1;
        self.proofs.insert(proof_id.clone(), proof.clone());
        self.record_public(format!("proof:{proof_id}"), proof.public_record())?;
        Ok(proof)
    }

    pub fn post_liquidity_provider_bid(
        &mut self,
        request: PostLiquidityProviderBidRequest,
    ) -> Result<LiquidityProviderBid> {
        self.ensure_capacity("bids", self.bids.len(), MAX_BIDS)?;
        if request.lp_id.is_empty()
            || request.bid_commitment_root.is_empty()
            || request.reserve_proof_root.is_empty()
            || request.settlement_route_root.is_empty()
        {
            return Err("liquidity bid requires lp and roots".to_string());
        }
        if request.lp_stake_piconero < self.config.min_lp_stake_piconero {
            return Err("liquidity provider stake below minimum".to_string());
        }
        let intent = self
            .intents
            .get_mut(&request.intent_id)
            .ok_or_else(|| "intent not found for liquidity bid".to_string())?;
        if !matches!(
            intent.status,
            IntentStatus::ProofAttached | IntentStatus::Bidding
        ) {
            return Err("intent must have pq proof before liquidity bidding".to_string());
        }
        if self.current_l2_height > intent.expires_l2_height {
            return Err("intent expired before liquidity bid".to_string());
        }
        if request.advance_amount_piconero == 0
            || request.advance_amount_piconero > intent.amount_piconero_hint
        {
            return Err("liquidity bid advance amount invalid".to_string());
        }
        if request.fee_bps > intent.max_fee_bps || request.fee_bps > MAX_BPS {
            return Err("liquidity bid fee exceeds intent cap".to_string());
        }
        if request.max_settlement_l2_height <= self.current_l2_height {
            return Err("liquidity bid settlement height is stale".to_string());
        }
        let bid_id = liquidity_bid_id(
            &request.intent_id,
            &request.lp_id,
            &request.bid_commitment_root,
            self.current_l2_height,
        );
        if self.bids.contains_key(&bid_id) {
            return Err("liquidity bid already exists".to_string());
        }
        let bid = LiquidityProviderBid {
            bid_id: bid_id.clone(),
            intent_id: request.intent_id.clone(),
            lp_id: request.lp_id,
            lp_stake_piconero: request.lp_stake_piconero,
            bid_commitment_root: request.bid_commitment_root,
            reserve_proof_root: request.reserve_proof_root,
            settlement_route_root: request.settlement_route_root,
            advance_amount_piconero: request.advance_amount_piconero,
            fee_bps: request.fee_bps,
            max_settlement_l2_height: request.max_settlement_l2_height,
            posted_l2_height: self.current_l2_height,
            expires_l2_height: self.current_l2_height + self.config.bid_ttl_blocks,
            status: BidStatus::Posted,
        };
        intent.status = IntentStatus::Bidding;
        self.lp_index
            .entry(bid.lp_id.clone())
            .or_default()
            .insert(bid_id.clone());
        self.counters.bids_posted += 1;
        self.bids.insert(bid_id.clone(), bid.clone());
        self.record_public(format!("bid:{bid_id}"), bid.public_record())?;
        Ok(bid)
    }

    pub fn accept_liquidity_provider_bid(
        &mut self,
        request: AcceptLiquidityProviderBidRequest,
    ) -> Result<LiquidityProviderBid> {
        let intent = self
            .intents
            .get_mut(&request.intent_id)
            .ok_or_else(|| "intent not found for bid acceptance".to_string())?;
        if !matches!(
            intent.status,
            IntentStatus::ProofAttached | IntentStatus::Bidding
        ) {
            return Err("intent cannot accept bid in current status".to_string());
        }
        let accepted_fee_bps = {
            let bid = self
                .bids
                .get_mut(&request.bid_id)
                .ok_or_else(|| "liquidity bid not found".to_string())?;
            if bid.intent_id != request.intent_id {
                return Err("liquidity bid does not match intent".to_string());
            }
            if bid.status != BidStatus::Posted {
                return Err("liquidity bid is not postable".to_string());
            }
            if self.current_l2_height > bid.expires_l2_height
                || self.current_l2_height > bid.max_settlement_l2_height
            {
                return Err("liquidity bid is stale".to_string());
            }
            bid.status = BidStatus::Accepted;
            bid.fee_bps
        };
        for (bid_id, bid) in self.bids.iter_mut() {
            if bid.intent_id == request.intent_id
                && *bid_id != request.bid_id
                && bid.status == BidStatus::Posted
            {
                bid.status = BidStatus::Superseded;
            }
        }
        intent.accepted_bid_id = Some(request.bid_id.clone());
        intent.max_fee_bps = accepted_fee_bps.min(intent.max_fee_bps);
        intent.status = IntentStatus::BidAccepted;
        self.counters.bids_accepted += 1;
        let bid = self
            .bids
            .get(&request.bid_id)
            .expect("accepted bid exists")
            .clone();
        self.record_public(format!("bid:{}", request.bid_id), bid.public_record())?;
        Ok(bid)
    }

    pub fn open_netting_round(&mut self, request: OpenNettingRoundRequest) -> Result<NettingRound> {
        self.ensure_capacity("rounds", self.rounds.len(), MAX_ROUNDS)?;
        if request.coordinator_id.is_empty() || request.intent_ids.is_empty() {
            return Err("netting round requires coordinator and intents".to_string());
        }
        if request.intent_ids.len() > self.config.max_round_items {
            return Err("netting round exceeds max item count".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("netting round privacy set below configured floor".to_string());
        }
        if request.clearing_price_bps > request.lane.fee_bps(&self.config) {
            return Err("netting round clearing price exceeds lane cap".to_string());
        }
        let mut bid_ids = BTreeSet::new();
        let mut gross = 0u128;
        let mut advance = 0u128;
        for intent_id in &request.intent_ids {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| format!("intent {intent_id} not found for netting"))?;
            if intent.lane != request.lane {
                return Err("netting round contains wrong lane intent".to_string());
            }
            if !intent.status.nettable() {
                return Err("netting round contains non-nettable intent".to_string());
            }
            if self.current_l2_height > intent.expires_l2_height {
                return Err("netting round contains expired intent".to_string());
            }
            gross = gross.saturating_add(intent.amount_piconero_hint);
            if let Some(bid_id) = &intent.accepted_bid_id {
                let bid = self
                    .bids
                    .get(bid_id)
                    .ok_or_else(|| "accepted bid missing".to_string())?;
                if bid.status != BidStatus::Accepted {
                    return Err("accepted bid is not active".to_string());
                }
                if self.current_l2_height > bid.expires_l2_height {
                    return Err("accepted bid is stale for netting".to_string());
                }
                advance = advance.saturating_add(bid.advance_amount_piconero);
                bid_ids.insert(bid_id.clone());
            }
        }
        let fill_bps = if gross == 0 {
            0
        } else {
            ((advance.saturating_mul(MAX_BPS as u128)) / gross) as u64
        };
        if fill_bps < self.config.min_netting_fill_bps {
            return Err("netting round fill below configured minimum".to_string());
        }
        let sequence = self.next_sequence();
        let round_id = netting_round_id(
            sequence,
            &request.coordinator_id,
            request.lane,
            &request.netted_commitment_root,
        );
        let net_settlement = gross.saturating_sub(advance);
        let round = NettingRound {
            round_id: round_id.clone(),
            sequence,
            coordinator_id: request.coordinator_id,
            lane: request.lane,
            intent_ids: request.intent_ids.clone(),
            bid_ids: bid_ids.clone(),
            netted_commitment_root: request.netted_commitment_root,
            clearing_price_bps: request.clearing_price_bps,
            gross_withdrawal_piconero: gross,
            net_lp_advance_piconero: advance,
            net_settlement_piconero: net_settlement,
            privacy_set_size: request.privacy_set_size,
            opened_l2_height: self.current_l2_height,
            expires_l2_height: self.current_l2_height + self.config.round_ttl_blocks,
            status: RoundStatus::Cleared,
            receipt_id: None,
        };
        for intent_id in &request.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = IntentStatus::Netted;
                intent.round_id = Some(round_id.clone());
            }
        }
        for bid_id in bid_ids {
            if let Some(bid) = self.bids.get_mut(&bid_id) {
                bid.status = BidStatus::Netted;
            }
        }
        self.counters.rounds_opened += 1;
        self.counters.rounds_cleared += 1;
        self.rounds.insert(round_id.clone(), round.clone());
        self.record_public(format!("round:{round_id}"), round.public_record())?;
        Ok(round)
    }

    pub fn publish_fast_settlement_receipt(
        &mut self,
        request: PublishFastSettlementReceiptRequest,
    ) -> Result<FastSettlementReceipt> {
        self.ensure_capacity("receipts", self.receipts.len(), MAX_RECEIPTS)?;
        let (round_id, intent_ids, bid_ids, round_net_settlement, round_gross) = {
            let round = self
                .rounds
                .get(&request.round_id)
                .ok_or_else(|| "netting round not found for receipt".to_string())?;
            if round.status != RoundStatus::Cleared {
                return Err("netting round is not cleared for receipt".to_string());
            }
            if self.current_l2_height > round.expires_l2_height {
                return Err("netting round expired before receipt".to_string());
            }
            (
                round.round_id.clone(),
                round.intent_ids.clone(),
                round.bid_ids.clone(),
                round.net_settlement_piconero,
                round.gross_withdrawal_piconero,
            )
        };
        if request
            .total_paid_piconero
            .saturating_add(request.total_fee_piconero)
            > round_gross
        {
            return Err("receipt paid plus fees exceeds gross withdrawal".to_string());
        }
        let total_rebate = bps_amount(request.total_fee_piconero, self.config.rebate_bps);
        let receipt_id = receipt_id(
            &round_id,
            &request.monero_tx_root,
            &request.l2_settlement_root,
            self.current_l2_height,
        );
        if self.receipts.contains_key(&receipt_id) {
            return Err("settlement receipt already exists".to_string());
        }
        let receipt = FastSettlementReceipt {
            receipt_id: receipt_id.clone(),
            round_id: round_id.clone(),
            monero_tx_root: request.monero_tx_root,
            l2_settlement_root: request.l2_settlement_root,
            lp_fill_root: request.lp_fill_root,
            intent_fill_root: request.intent_fill_root,
            total_paid_piconero: request.total_paid_piconero,
            total_fee_piconero: request.total_fee_piconero,
            total_rebate_piconero: total_rebate,
            published_l2_height: self.current_l2_height,
            expires_l2_height: self.current_l2_height + self.config.receipt_ttl_blocks,
            settlement_finality_height: request.settlement_finality_height,
        };
        if let Some(round) = self.rounds.get_mut(&round_id) {
            round.status = RoundStatus::ReceiptPublished;
            round.receipt_id = Some(receipt_id.clone());
        }
        for intent_id in intent_ids {
            let mut issue_low_fee_rebate = false;
            if let Some(intent) = self.intents.get_mut(&intent_id) {
                intent.status = IntentStatus::ReceiptPublished;
                intent.receipt_id = Some(receipt_id.clone());
                issue_low_fee_rebate = intent.lane == WithdrawalLane::LowFee && total_rebate > 0;
            }
            if issue_low_fee_rebate {
                let rebate = self.issue_rebate(&intent_id, &receipt_id, total_rebate)?;
                self.record_public(
                    format!("rebate:{}", rebate.rebate_id),
                    rebate.public_record(),
                )?;
            }
        }
        for bid_id in bid_ids {
            if let Some(bid) = self.bids.get_mut(&bid_id) {
                bid.status = BidStatus::Settled;
            }
        }
        self.counters.receipts_published += 1;
        self.counters.total_fast_filled_piconero = self
            .counters
            .total_fast_filled_piconero
            .saturating_add(request.total_paid_piconero);
        self.counters.total_net_settled_piconero = self
            .counters
            .total_net_settled_piconero
            .saturating_add(round_net_settlement);
        self.receipts.insert(receipt_id.clone(), receipt.clone());
        self.record_public(format!("receipt:{receipt_id}"), receipt.public_record())?;
        Ok(receipt)
    }

    pub fn record_privacy_set_account(
        &mut self,
        request: RecordPrivacySetAccountRequest,
    ) -> Result<PrivacySetAccount> {
        self.ensure_capacity(
            "privacy_accounts",
            self.privacy_accounts.len(),
            MAX_PRIVACY_ACCOUNTS,
        )?;
        if request.subject_id.is_empty() || request.commitment_root.is_empty() {
            return Err("privacy account requires subject and commitment root".to_string());
        }
        if request.window_end_l2_height < request.window_start_l2_height {
            return Err("privacy account window is invalid".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy account set below configured floor".to_string());
        }
        let account_id = privacy_account_id(
            &request.subject_id,
            request.lane,
            request.window_start_l2_height,
            request.window_end_l2_height,
            &request.commitment_root,
        );
        if self.privacy_accounts.contains_key(&account_id) {
            return Err("privacy account already exists".to_string());
        }
        let account = PrivacySetAccount {
            account_id: account_id.clone(),
            subject_id: request.subject_id,
            lane: request.lane,
            window_start_l2_height: request.window_start_l2_height,
            window_end_l2_height: request.window_end_l2_height,
            participant_count: request.participant_count,
            decoy_count: request.decoy_count,
            liquidity_provider_count: request.liquidity_provider_count,
            privacy_set_size: request.privacy_set_size,
            commitment_root: request.commitment_root,
        };
        self.counters.privacy_accounts_recorded += 1;
        self.privacy_accounts
            .insert(account_id.clone(), account.clone());
        self.record_public(
            format!("privacy_account:{account_id}"),
            account.public_record(),
        )?;
        Ok(account)
    }

    pub fn slash_invalid_proof(
        &mut self,
        request: SlashInvalidProofRequest,
    ) -> Result<SlashingEvent> {
        self.ensure_capacity("slashings", self.slashings.len(), MAX_SLASHINGS)?;
        if !self.intents.contains_key(&request.intent_id) {
            return Err("intent not found for invalid proof slashing".to_string());
        }
        let proof = self
            .proofs
            .get_mut(&request.proof_id)
            .ok_or_else(|| "proof not found for slashing".to_string())?;
        if proof.intent_id != request.intent_id {
            return Err("proof does not match intent for slashing".to_string());
        }
        proof.status = ProofStatus::Slashed;
        if let Some(intent) = self.intents.get_mut(&request.intent_id) {
            intent.status = IntentStatus::Slashed;
        }
        self.create_slashing(
            SlashingReason::InvalidPqProof,
            request.offender_id,
            Some(request.intent_id),
            Some(request.proof_id),
            None,
            None,
            request.evidence_root,
            request.base_bond_piconero,
        )
    }

    pub fn slash_stale_liquidity(
        &mut self,
        request: SlashStaleLiquidityRequest,
    ) -> Result<SlashingEvent> {
        self.ensure_capacity("slashings", self.slashings.len(), MAX_SLASHINGS)?;
        let (intent_id, bid_id) = {
            let bid = self
                .bids
                .get_mut(&request.bid_id)
                .ok_or_else(|| "bid not found for stale liquidity slashing".to_string())?;
            bid.status = BidStatus::Slashed;
            (bid.intent_id.clone(), bid.bid_id.clone())
        };
        if let Some(intent) = self.intents.get_mut(&intent_id) {
            intent.status = IntentStatus::Slashed;
        }
        self.create_slashing(
            SlashingReason::StaleLiquidity,
            request.offender_id,
            Some(intent_id),
            None,
            Some(bid_id),
            None,
            request.evidence_root,
            request.base_bond_piconero,
        )
    }

    pub fn expire_stale_items(&mut self) -> usize {
        let mut expired = 0usize;
        for intent in self.intents.values_mut() {
            if intent.status.live() && self.current_l2_height > intent.expires_l2_height {
                intent.status = IntentStatus::Expired;
                expired += 1;
            }
        }
        for proof in self.proofs.values_mut() {
            if proof.status.usable() && self.current_l2_height > proof.expires_l2_height {
                proof.status = ProofStatus::Expired;
                expired += 1;
            }
        }
        for bid in self.bids.values_mut() {
            if bid.status.live()
                && (self.current_l2_height > bid.expires_l2_height
                    || self.current_l2_height > bid.max_settlement_l2_height)
            {
                bid.status = BidStatus::Stale;
                expired += 1;
            }
        }
        for round in self.rounds.values_mut() {
            if matches!(round.status, RoundStatus::Open | RoundStatus::Cleared)
                && self.current_l2_height > round.expires_l2_height
            {
                round.status = RoundStatus::Expired;
                expired += 1;
            }
        }
        self.counters.expired_items = self.counters.expired_items.saturating_add(expired as u64);
        expired
    }

    pub fn mark_receipt_settled(&mut self, receipt_id: &str) -> Result<()> {
        let receipt = self
            .receipts
            .get(receipt_id)
            .ok_or_else(|| "receipt not found for settlement".to_string())?
            .clone();
        if self.current_l2_height < receipt.settlement_finality_height {
            return Err("receipt has not reached settlement finality".to_string());
        }
        let round = self
            .rounds
            .get_mut(&receipt.round_id)
            .ok_or_else(|| "receipt round missing".to_string())?;
        round.status = RoundStatus::Settled;
        for intent_id in round.intent_ids.clone() {
            if let Some(intent) = self.intents.get_mut(&intent_id) {
                intent.status = IntentStatus::Settled;
            }
        }
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        Roots {
            intent_root: map_root("monero-l2-fast-withdrawal:intents", &self.intents),
            proof_root: map_root("monero-l2-fast-withdrawal:proofs", &self.proofs),
            bid_root: map_root("monero-l2-fast-withdrawal:bids", &self.bids),
            round_root: map_root("monero-l2-fast-withdrawal:rounds", &self.rounds),
            receipt_root: map_root("monero-l2-fast-withdrawal:receipts", &self.receipts),
            rebate_root: map_root("monero-l2-fast-withdrawal:rebates", &self.rebates),
            privacy_account_root: map_root(
                "monero-l2-fast-withdrawal:privacy-accounts",
                &self.privacy_accounts,
            ),
            slashing_root: map_root("monero-l2-fast-withdrawal:slashings", &self.slashings),
            consumed_nullifier_root: set_root(
                "monero-l2-fast-withdrawal:consumed-nullifiers",
                &self.consumed_nullifiers,
            ),
            lp_index_root: nested_set_root("monero-l2-fast-withdrawal:lp-index", &self.lp_index),
            intent_owner_index_root: nested_set_root(
                "monero-l2-fast-withdrawal:owner-index",
                &self.intent_owner_index,
            ),
            public_record_root: map_root(
                "monero-l2-fast-withdrawal:public-records",
                &self.public_records,
            ),
        }
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "auction_id": self.config.auction_id,
            "asset_id": self.config.asset_id,
            "fee_asset_id": self.config.fee_asset_id,
            "hash_suite": self.config.hash_suite,
            "pq_auth_proof_suite": self.config.pq_auth_proof_suite,
            "config": self.config.public_record(),
            "current_l2_height": self.current_l2_height,
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "intent_count": self.intents.len(),
            "proof_count": self.proofs.len(),
            "bid_count": self.bids.len(),
            "round_count": self.rounds.len(),
            "receipt_count": self.receipts.len(),
            "rebate_count": self.rebates.len(),
            "privacy_account_count": self.privacy_accounts.len(),
            "slashing_count": self.slashings.len(),
            "live_intent_count": self.live_intent_count(),
            "pending_bid_count": self.pending_bid_count(),
        })
    }

    pub fn live_intent_count(&self) -> usize {
        self.intents
            .values()
            .filter(|intent| intent.status.live())
            .count()
    }

    pub fn pending_bid_count(&self) -> usize {
        self.bids
            .values()
            .filter(|bid| matches!(bid.status, BidStatus::Posted | BidStatus::Accepted))
            .count()
    }

    fn next_sequence(&mut self) -> u64 {
        let sequence = self.counters.next_sequence;
        self.counters.next_sequence += 1;
        sequence
    }

    fn ensure_capacity(&self, label: &str, current: usize, max: usize) -> Result<()> {
        if current >= max {
            Err(format!("{label} capacity exceeded"))
        } else {
            Ok(())
        }
    }

    fn record_public(&mut self, key: String, record: Value) -> Result<()> {
        self.ensure_capacity(
            "public_records",
            self.public_records.len(),
            MAX_PUBLIC_RECORDS,
        )?;
        self.public_records.insert(key, record);
        self.counters.public_records = self.public_records.len();
        Ok(())
    }

    fn issue_rebate(
        &mut self,
        intent_id: &str,
        receipt_id: &str,
        shared_rebate_pool: u128,
    ) -> Result<LowFeeRebate> {
        self.ensure_capacity("rebates", self.rebates.len(), MAX_REBATES)?;
        let intent = self
            .intents
            .get(intent_id)
            .ok_or_else(|| "intent not found for rebate".to_string())?;
        let rebate_piconero = shared_rebate_pool.min(bps_amount(
            intent.amount_piconero_hint,
            self.config.rebate_bps,
        ));
        let rebate_id = rebate_id(intent_id, receipt_id, rebate_piconero);
        let rebate = LowFeeRebate {
            rebate_id: rebate_id.clone(),
            intent_id: intent_id.to_string(),
            receipt_id: receipt_id.to_string(),
            beneficiary_commitment: intent.owner_commitment.clone(),
            fee_paid_piconero: bps_amount(intent.amount_piconero_hint, intent.max_fee_bps),
            rebate_piconero,
            rebate_bps: self.config.rebate_bps,
            issued_l2_height: self.current_l2_height,
        };
        self.counters.rebates_issued += 1;
        self.counters.total_rebated_piconero = self
            .counters
            .total_rebated_piconero
            .saturating_add(rebate_piconero);
        self.rebates.insert(rebate_id, rebate.clone());
        Ok(rebate)
    }

    #[allow(clippy::too_many_arguments)]
    fn create_slashing(
        &mut self,
        reason: SlashingReason,
        offender_id: String,
        intent_id: Option<String>,
        proof_id: Option<String>,
        bid_id: Option<String>,
        round_id: Option<String>,
        evidence_root: String,
        base_bond_piconero: u128,
    ) -> Result<SlashingEvent> {
        if offender_id.is_empty() || evidence_root.is_empty() {
            return Err("slashing requires offender and evidence".to_string());
        }
        let penalty_bps = reason.penalty_bps(&self.config);
        let slashed_piconero = bps_amount(base_bond_piconero, penalty_bps);
        let slashing_id = slashing_id(
            &offender_id,
            reason,
            &evidence_root,
            self.current_l2_height,
            self.slashings.len() as u64,
        );
        let event = SlashingEvent {
            slashing_id: slashing_id.clone(),
            offender_id,
            intent_id,
            proof_id,
            bid_id,
            round_id,
            reason,
            evidence_root,
            base_bond_piconero,
            penalty_bps,
            slashed_piconero,
            created_l2_height: self.current_l2_height,
        };
        self.counters.slashing_events += 1;
        self.counters.total_slashed_piconero = self
            .counters
            .total_slashed_piconero
            .saturating_add(slashed_piconero);
        self.slashings.insert(slashing_id.clone(), event.clone());
        self.record_public(format!("slashing:{slashing_id}"), event.public_record())?;
        Ok(event)
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn monero_l2_pq_private_fast_withdrawal_netting_auction_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}

pub fn monero_l2_pq_private_fast_withdrawal_netting_auction_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}

pub fn intent_id(sequence: u64, request: &SealWithdrawalIntentRequest) -> String {
    domain_hash(
        "monero-l2-pq-private-fast-withdrawal-netting-auction:intent-id",
        &[
            HashPart::U64(sequence),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.withdrawal_nullifier),
            HashPart::U64(request.max_fee_bps),
        ],
        16,
    )
}

pub fn pq_proof_id(intent_id: &str, proof_root: &str, attached_l2_height: u64) -> String {
    domain_hash(
        "monero-l2-pq-private-fast-withdrawal-netting-auction:pq-proof-id",
        &[
            HashPart::Str(intent_id),
            HashPart::Str(proof_root),
            HashPart::U64(attached_l2_height),
        ],
        16,
    )
}

pub fn liquidity_bid_id(
    intent_id: &str,
    lp_id: &str,
    bid_commitment_root: &str,
    posted_l2_height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-fast-withdrawal-netting-auction:liquidity-bid-id",
        &[
            HashPart::Str(intent_id),
            HashPart::Str(lp_id),
            HashPart::Str(bid_commitment_root),
            HashPart::U64(posted_l2_height),
        ],
        16,
    )
}

pub fn netting_round_id(
    sequence: u64,
    coordinator_id: &str,
    lane: WithdrawalLane,
    netted_commitment_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-private-fast-withdrawal-netting-auction:netting-round-id",
        &[
            HashPart::U64(sequence),
            HashPart::Str(coordinator_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(netted_commitment_root),
        ],
        16,
    )
}

pub fn receipt_id(
    round_id: &str,
    monero_tx_root: &str,
    l2_settlement_root: &str,
    published_l2_height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-fast-withdrawal-netting-auction:receipt-id",
        &[
            HashPart::Str(round_id),
            HashPart::Str(monero_tx_root),
            HashPart::Str(l2_settlement_root),
            HashPart::U64(published_l2_height),
        ],
        16,
    )
}

pub fn rebate_id(intent_id: &str, receipt_id: &str, rebate_piconero: u128) -> String {
    domain_hash(
        "monero-l2-pq-private-fast-withdrawal-netting-auction:rebate-id",
        &[
            HashPart::Str(intent_id),
            HashPart::Str(receipt_id),
            HashPart::Str(&rebate_piconero.to_string()),
        ],
        16,
    )
}

pub fn privacy_account_id(
    subject_id: &str,
    lane: WithdrawalLane,
    start_height: u64,
    end_height: u64,
    commitment_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-private-fast-withdrawal-netting-auction:privacy-account-id",
        &[
            HashPart::Str(subject_id),
            HashPart::Str(lane.as_str()),
            HashPart::U64(start_height),
            HashPart::U64(end_height),
            HashPart::Str(commitment_root),
        ],
        16,
    )
}

pub fn slashing_id(
    offender_id: &str,
    reason: SlashingReason,
    evidence_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-fast-withdrawal-netting-auction:slashing-id",
        &[
            HashPart::Str(offender_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(evidence_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        16,
    )
}

pub fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "monero-l2-pq-private-fast-withdrawal-netting-auction:state-root",
        record,
    )
}

pub fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": serde_json::to_value(value).expect("serializable map value"),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn nested_set_root(domain: &str, map: &BTreeMap<String, BTreeSet<String>>) -> String {
    let leaves = map
        .iter()
        .map(|(key, set)| {
            json!({
                "key": key,
                "set_root": set_root(&format!("{domain}:{key}"), set),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn bps_amount(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
}
