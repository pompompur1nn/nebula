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
    "nebula-private-l2-pq-confidential-cross-margin-lending-intent-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_PQ_ENCRYPTION_SUITE: &str =
    "ML-KEM-1024+hybrid-view-key-encrypted-lending-intent-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_PQ_SIGNATURE_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-dual-attestation-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_CONFIDENTIAL_NOTE_SUITE:
    &str = "pedersen-note+range-proof+pq-binding-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_RISK_ATTESTATION_SUITE:
    &str = "zk-risk-vector+oracle-committee-pq-attestation-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_LIQUIDATION_AUCTION_SUITE: &str = "sealed-bid-private-liquidation-auction-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_SOLVER_RECEIPT_SUITE:
    &str = "roots-only-fast-lane-solver-receipt-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_FEE_REBATE_SUITE: &str =
    "low-fee-confidential-rebate-claim-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_PRIVACY_FENCE_SUITE: &str =
    "nullifier-set+view-tag-fence+mev-delay-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_SLASHING_EVIDENCE_SUITE:
    &str = "pq-signed-fraud-evidence+bond-slash-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MONERO_NETWORK:
    &str = "monero-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_L2_NETWORK: &str =
    "nebula-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_FAST_LANE: &str =
    "devnet-pq-cross-margin-lending-fast-lane";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_LOW_FEE_LANE:
    &str = "devnet-pq-cross-margin-lending-low-fee";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT: u64 =
    1_984_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_MONERO_HEIGHT: u64 =
    3_684_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_RISK_TTL_BLOCKS:
    u64 = 12;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_AUCTION_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_REBATE_EPOCH_BLOCKS: u64 = 1_440;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 65_536;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 22;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MIN_INITIAL_MARGIN_BPS: u64 = 14_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MIN_MAINTENANCE_MARGIN_BPS: u64 = 11_500;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_LIQUIDATION_BONUS_BPS: u64 = 650;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_BORROW_RATE_BPS: u64 = 3_200;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_REBATE_BUDGET_MICRO_UNITS: u64 = 400_000_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_SLASHING_ESCROW_MICRO_UNITS: u64 = 120_000_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_INTENTS:
    usize = 524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_COLLATERAL_NOTES: usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_BORROW_NOTES: usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_MARGIN_ACCOUNTS: usize = 262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS: usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_LIQUIDATION_AUCTIONS: usize = 262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_SOLVER_RECEIPTS: usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_FEE_REBATES:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_PRIVACY_FENCES: usize = 2_097_152;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_SLASHING_EVIDENCE: usize = 262_144;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentKind {
    Supply,
    Withdraw,
    Borrow,
    Repay,
    RollDebt,
    RebalanceCollateral,
    CrossMarginTransfer,
    LiquidationBackstop,
}
impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Supply => "supply",
            Self::Withdraw => "withdraw",
            Self::Borrow => "borrow",
            Self::Repay => "repay",
            Self::RollDebt => "roll_debt",
            Self::RebalanceCollateral => "rebalance_collateral",
            Self::CrossMarginTransfer => "cross_margin_transfer",
            Self::LiquidationBackstop => "liquidation_backstop",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Encrypted,
    Admitted,
    RiskChecked,
    SolverReserved,
    Settled,
    Rejected,
    Expired,
    Slashed,
}
impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Admitted => "admitted",
            Self::RiskChecked => "risk_checked",
            Self::SolverReserved => "solver_reserved",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Encrypted | Self::Admitted | Self::RiskChecked | Self::SolverReserved
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    Pending,
    Active,
    Locked,
    Spent,
    Released,
    Liquidated,
}
impl NoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Locked => "locked",
            Self::Spent => "spent",
            Self::Released => "released",
            Self::Liquidated => "liquidated",
        }
    }
    pub fn live(self) -> bool {
        matches!(self, Self::Pending | Self::Active | Self::Locked)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    Open,
    ReduceOnly,
    MarginCall,
    Liquidatable,
    Frozen,
    Closed,
}
impl AccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::ReduceOnly => "reduce_only",
            Self::MarginCall => "margin_call",
            Self::Liquidatable => "liquidatable",
            Self::Frozen => "frozen",
            Self::Closed => "closed",
        }
    }
    pub fn accepts_new_borrow(self) -> bool {
        matches!(self, Self::Open)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskVerdict {
    Healthy,
    Watch,
    ReduceOnly,
    MarginCall,
    Liquidatable,
    Reject,
}
impl RiskVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::ReduceOnly => "reduce_only",
            Self::MarginCall => "margin_call",
            Self::Liquidatable => "liquidatable",
            Self::Reject => "reject",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Sealed,
    Bidding,
    Clearing,
    Awarded,
    Settled,
    Cancelled,
    Slashed,
}
impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Bidding => "bidding",
            Self::Clearing => "clearing",
            Self::Awarded => "awarded",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Reserved,
    Included,
    Proved,
    Rebated,
    Challenged,
    Slashed,
}
impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Included => "included",
            Self::Proved => "proved",
            Self::Rebated => "rebated",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    InvalidRiskProof,
    DoubleSpendNullifier,
    SolverCensorship,
    BadLiquidationPrice,
    FeeOvercharge,
    AuctionRevealFailure,
    PrivacyFenceBypass,
}
impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRiskProof => "invalid_risk_proof",
            Self::DoubleSpendNullifier => "double_spend_nullifier",
            Self::SolverCensorship => "solver_censorship",
            Self::BadLiquidationPrice => "bad_liquidation_price",
            Self::FeeOvercharge => "fee_overcharge",
            Self::AuctionRevealFailure => "auction_reveal_failure",
            Self::PrivacyFenceBypass => "privacy_fence_bypass",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub fast_lane_id: String,
    pub low_fee_lane_id: String,
    pub pq_encryption_suite: String,
    pub pq_signature_suite: String,
    pub confidential_note_suite: String,
    pub risk_attestation_suite: String,
    pub liquidation_auction_suite: String,
    pub solver_receipt_suite: String,
    pub fee_rebate_suite: String,
    pub privacy_fence_suite: String,
    pub slashing_evidence_suite: String,
    pub intent_ttl_blocks: u64,
    pub risk_ttl_blocks: u64,
    pub auction_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub rebate_epoch_blocks: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub min_initial_margin_bps: u64,
    pub min_maintenance_margin_bps: u64,
    pub liquidation_bonus_bps: u64,
    pub max_borrow_rate_bps: u64,
    pub rebate_budget_micro_units: u64,
    pub slashing_escrow_micro_units: u64,
    pub max_intents: usize,
    pub max_collateral_notes: usize,
    pub max_borrow_notes: usize,
    pub max_margin_accounts: usize,
    pub max_risk_attestations: usize,
    pub max_liquidation_auctions: usize,
    pub max_solver_receipts: usize,
    pub max_fee_rebates: usize,
    pub max_privacy_fences: usize,
    pub max_slashing_evidence: usize,
}
impl Config {
    pub fn devnet() -> Self {
        Self { protocol_version: PROTOCOL_VERSION.to_string(), schema_version: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_SCHEMA_VERSION, chain_id: CHAIN_ID.to_string(), monero_network: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MONERO_NETWORK.to_string(), l2_network: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_L2_NETWORK.to_string(), fast_lane_id: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_FAST_LANE.to_string(), low_fee_lane_id: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_LOW_FEE_LANE.to_string(), pq_encryption_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_PQ_ENCRYPTION_SUITE.to_string(), pq_signature_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_PQ_SIGNATURE_SUITE.to_string(), confidential_note_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_CONFIDENTIAL_NOTE_SUITE.to_string(), risk_attestation_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_RISK_ATTESTATION_SUITE.to_string(), liquidation_auction_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_LIQUIDATION_AUCTION_SUITE.to_string(), solver_receipt_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_SOLVER_RECEIPT_SUITE.to_string(), fee_rebate_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_FEE_REBATE_SUITE.to_string(), privacy_fence_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_PRIVACY_FENCE_SUITE.to_string(), slashing_evidence_suite: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_SLASHING_EVIDENCE_SUITE.to_string(), intent_ttl_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS, risk_ttl_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_RISK_TTL_BLOCKS, auction_ttl_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_AUCTION_TTL_BLOCKS, settlement_ttl_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS, rebate_epoch_blocks: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_REBATE_EPOCH_BLOCKS, min_privacy_set_size: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE, batch_privacy_set_size: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE, min_pq_security_bits: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS, max_user_fee_bps: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_USER_FEE_BPS, max_solver_fee_bps: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_SOLVER_FEE_BPS, min_initial_margin_bps: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MIN_INITIAL_MARGIN_BPS, min_maintenance_margin_bps: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MIN_MAINTENANCE_MARGIN_BPS, liquidation_bonus_bps: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_LIQUIDATION_BONUS_BPS, max_borrow_rate_bps: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_BORROW_RATE_BPS, rebate_budget_micro_units: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_REBATE_BUDGET_MICRO_UNITS, slashing_escrow_micro_units: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_SLASHING_ESCROW_MICRO_UNITS, max_intents: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_INTENTS, max_collateral_notes: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_COLLATERAL_NOTES, max_borrow_notes: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_BORROW_NOTES, max_margin_accounts: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_MARGIN_ACCOUNTS, max_risk_attestations: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS, max_liquidation_auctions: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_LIQUIDATION_AUCTIONS, max_solver_receipts: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_SOLVER_RECEIPTS, max_fee_rebates: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_FEE_REBATES, max_privacy_fences: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_PRIVACY_FENCES, max_slashing_evidence: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_MAX_SLASHING_EVIDENCE }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("max_solver_fee_bps", self.max_solver_fee_bps)?;
        ensure_bps("liquidation_bonus_bps", self.liquidation_bonus_bps)?;
        if self.min_initial_margin_bps < self.min_maintenance_margin_bps {
            return Err("initial margin must be at least maintenance margin".to_string());
        }
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch privacy set must cover the minimum privacy set".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("post-quantum security bits below policy floor".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub encrypted_lending_intents: u64,
    pub collateral_notes: u64,
    pub borrow_notes: u64,
    pub margin_accounts: u64,
    pub risk_attestations: u64,
    pub liquidation_auctions: u64,
    pub solver_receipts: u64,
    pub fee_rebates: u64,
    pub privacy_nullifier_fences: u64,
    pub slashing_evidence: u64,
    pub active_intents: u64,
    pub active_margin_accounts: u64,
    pub live_collateral_notes: u64,
    pub live_borrow_notes: u64,
    pub liquidatable_accounts: u64,
    pub total_rebate_micro_units: u64,
    pub total_slashed_micro_units: u64,
}
impl Counters {
    pub fn empty() -> Self {
        Self {
            encrypted_lending_intents: 0,
            collateral_notes: 0,
            borrow_notes: 0,
            margin_accounts: 0,
            risk_attestations: 0,
            liquidation_auctions: 0,
            solver_receipts: 0,
            fee_rebates: 0,
            privacy_nullifier_fences: 0,
            slashing_evidence: 0,
            active_intents: 0,
            active_margin_accounts: 0,
            live_collateral_notes: 0,
            live_borrow_notes: 0,
            liquidatable_accounts: 0,
            total_rebate_micro_units: 0,
            total_slashed_micro_units: 0,
        }
    }
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedLendingIntent {
    pub intent_id: String,
    pub account_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub intent_kind: IntentKind,
    pub status: IntentStatus,
    pub encrypted_payload_root: String,
    pub nullifier_root: String,
    pub witness_root: String,
    pub proof_root: String,
    pub view_tag: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub lane_id: String,
    pub metadata_root: String,
}
impl EncryptedLendingIntent {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_id(&self) -> &str {
        &self.intent_id
    }
    pub fn deterministic_id(seed: &str, account_id: &str, market_id: &str, nonce: u64) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-INTENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(seed),
                HashPart::Str(account_id),
                HashPart::Str(market_id),
                HashPart::U64(nonce),
            ],
            32,
        )
    }
    pub fn commitment_root(&self) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-INTENT-COMMITMENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("intent_id", &self.intent_id)?;
        ensure_non_empty("account_id", &self.account_id)?;
        ensure_non_empty("market_id", &self.market_id)?;
        ensure_non_empty("asset_id", &self.asset_id)?;
        ensure_non_empty("encrypted_payload_root", &self.encrypted_payload_root)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("witness_root", &self.witness_root)?;
        ensure_non_empty("proof_root", &self.proof_root)?;
        ensure_non_empty("pq_public_key_root", &self.pq_public_key_root)?;
        ensure_non_empty("pq_signature_root", &self.pq_signature_root)?;
        ensure_non_empty("lane_id", &self.lane_id)?;
        ensure_bps("fee_bps", self.fee_bps)?;
        if self.fee_bps > config.max_user_fee_bps.max(config.max_solver_fee_bps) {
            return Err(format!(
                "encrypted_lending_intent fee exceeds configured ceiling"
            ));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "encrypted_lending_intent privacy set below configured floor"
            ));
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!(
                "encrypted_lending_intent expiry must be after opening height"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CollateralNote {
    pub note_id: String,
    pub account_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub status: NoteStatus,
    pub commitment: String,
    pub nullifier_root: String,
    pub witness_root: String,
    pub proof_root: String,
    pub view_tag: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub lane_id: String,
    pub metadata_root: String,
}
impl CollateralNote {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_id(&self) -> &str {
        &self.note_id
    }
    pub fn deterministic_id(seed: &str, account_id: &str, market_id: &str, nonce: u64) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-COLLATERAL-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(seed),
                HashPart::Str(account_id),
                HashPart::Str(market_id),
                HashPart::U64(nonce),
            ],
            32,
        )
    }
    pub fn commitment_root(&self) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-COLLATERAL-COMMITMENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("note_id", &self.note_id)?;
        ensure_non_empty("account_id", &self.account_id)?;
        ensure_non_empty("market_id", &self.market_id)?;
        ensure_non_empty("asset_id", &self.asset_id)?;
        ensure_non_empty("commitment", &self.commitment)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("witness_root", &self.witness_root)?;
        ensure_non_empty("proof_root", &self.proof_root)?;
        ensure_non_empty("pq_public_key_root", &self.pq_public_key_root)?;
        ensure_non_empty("pq_signature_root", &self.pq_signature_root)?;
        ensure_non_empty("lane_id", &self.lane_id)?;
        ensure_bps("fee_bps", self.fee_bps)?;
        if self.fee_bps > config.max_user_fee_bps.max(config.max_solver_fee_bps) {
            return Err(format!("collateral_note fee exceeds configured ceiling"));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "collateral_note privacy set below configured floor"
            ));
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!(
                "collateral_note expiry must be after opening height"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BorrowNote {
    pub note_id: String,
    pub account_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub status: NoteStatus,
    pub debt_commitment: String,
    pub nullifier_root: String,
    pub witness_root: String,
    pub proof_root: String,
    pub view_tag: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub lane_id: String,
    pub metadata_root: String,
}
impl BorrowNote {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_id(&self) -> &str {
        &self.note_id
    }
    pub fn deterministic_id(seed: &str, account_id: &str, market_id: &str, nonce: u64) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-BORROW-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(seed),
                HashPart::Str(account_id),
                HashPart::Str(market_id),
                HashPart::U64(nonce),
            ],
            32,
        )
    }
    pub fn commitment_root(&self) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-BORROW-COMMITMENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("note_id", &self.note_id)?;
        ensure_non_empty("account_id", &self.account_id)?;
        ensure_non_empty("market_id", &self.market_id)?;
        ensure_non_empty("asset_id", &self.asset_id)?;
        ensure_non_empty("debt_commitment", &self.debt_commitment)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("witness_root", &self.witness_root)?;
        ensure_non_empty("proof_root", &self.proof_root)?;
        ensure_non_empty("pq_public_key_root", &self.pq_public_key_root)?;
        ensure_non_empty("pq_signature_root", &self.pq_signature_root)?;
        ensure_non_empty("lane_id", &self.lane_id)?;
        ensure_bps("fee_bps", self.fee_bps)?;
        if self.fee_bps > config.max_user_fee_bps.max(config.max_solver_fee_bps) {
            return Err(format!("borrow_note fee exceeds configured ceiling"));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("borrow_note privacy set below configured floor"));
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!("borrow_note expiry must be after opening height"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MarginAccount {
    pub account_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub status: AccountStatus,
    pub account_commitment: String,
    pub nullifier_root: String,
    pub witness_root: String,
    pub proof_root: String,
    pub view_tag: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub lane_id: String,
    pub metadata_root: String,
}
impl MarginAccount {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_id(&self) -> &str {
        &self.account_id
    }
    pub fn deterministic_id(seed: &str, account_id: &str, market_id: &str, nonce: u64) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-ACCOUNT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(seed),
                HashPart::Str(account_id),
                HashPart::Str(market_id),
                HashPart::U64(nonce),
            ],
            32,
        )
    }
    pub fn commitment_root(&self) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-ACCOUNT-COMMITMENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("account_id", &self.account_id)?;
        ensure_non_empty("account_id", &self.account_id)?;
        ensure_non_empty("market_id", &self.market_id)?;
        ensure_non_empty("asset_id", &self.asset_id)?;
        ensure_non_empty("account_commitment", &self.account_commitment)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("witness_root", &self.witness_root)?;
        ensure_non_empty("proof_root", &self.proof_root)?;
        ensure_non_empty("pq_public_key_root", &self.pq_public_key_root)?;
        ensure_non_empty("pq_signature_root", &self.pq_signature_root)?;
        ensure_non_empty("lane_id", &self.lane_id)?;
        ensure_bps("fee_bps", self.fee_bps)?;
        if self.fee_bps > config.max_user_fee_bps.max(config.max_solver_fee_bps) {
            return Err(format!("margin_account fee exceeds configured ceiling"));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("margin_account privacy set below configured floor"));
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!(
                "margin_account expiry must be after opening height"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskAttestation {
    pub attestation_id: String,
    pub account_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub verdict: RiskVerdict,
    pub risk_vector_root: String,
    pub nullifier_root: String,
    pub witness_root: String,
    pub proof_root: String,
    pub view_tag: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub lane_id: String,
    pub metadata_root: String,
}
impl RiskAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_id(&self) -> &str {
        &self.attestation_id
    }
    pub fn deterministic_id(seed: &str, account_id: &str, market_id: &str, nonce: u64) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-RISK-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(seed),
                HashPart::Str(account_id),
                HashPart::Str(market_id),
                HashPart::U64(nonce),
            ],
            32,
        )
    }
    pub fn commitment_root(&self) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-RISK-COMMITMENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("attestation_id", &self.attestation_id)?;
        ensure_non_empty("account_id", &self.account_id)?;
        ensure_non_empty("market_id", &self.market_id)?;
        ensure_non_empty("asset_id", &self.asset_id)?;
        ensure_non_empty("risk_vector_root", &self.risk_vector_root)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("witness_root", &self.witness_root)?;
        ensure_non_empty("proof_root", &self.proof_root)?;
        ensure_non_empty("pq_public_key_root", &self.pq_public_key_root)?;
        ensure_non_empty("pq_signature_root", &self.pq_signature_root)?;
        ensure_non_empty("lane_id", &self.lane_id)?;
        ensure_bps("fee_bps", self.fee_bps)?;
        if self.fee_bps > config.max_user_fee_bps.max(config.max_solver_fee_bps) {
            return Err(format!("risk_attestation fee exceeds configured ceiling"));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "risk_attestation privacy set below configured floor"
            ));
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!(
                "risk_attestation expiry must be after opening height"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidationAuction {
    pub auction_id: String,
    pub account_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub status: AuctionStatus,
    pub sealed_bid_root: String,
    pub nullifier_root: String,
    pub witness_root: String,
    pub proof_root: String,
    pub view_tag: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub lane_id: String,
    pub metadata_root: String,
}
impl LiquidationAuction {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_id(&self) -> &str {
        &self.auction_id
    }
    pub fn deterministic_id(seed: &str, account_id: &str, market_id: &str, nonce: u64) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-AUCTION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(seed),
                HashPart::Str(account_id),
                HashPart::Str(market_id),
                HashPart::U64(nonce),
            ],
            32,
        )
    }
    pub fn commitment_root(&self) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-AUCTION-COMMITMENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("auction_id", &self.auction_id)?;
        ensure_non_empty("account_id", &self.account_id)?;
        ensure_non_empty("market_id", &self.market_id)?;
        ensure_non_empty("asset_id", &self.asset_id)?;
        ensure_non_empty("sealed_bid_root", &self.sealed_bid_root)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("witness_root", &self.witness_root)?;
        ensure_non_empty("proof_root", &self.proof_root)?;
        ensure_non_empty("pq_public_key_root", &self.pq_public_key_root)?;
        ensure_non_empty("pq_signature_root", &self.pq_signature_root)?;
        ensure_non_empty("lane_id", &self.lane_id)?;
        ensure_bps("fee_bps", self.fee_bps)?;
        if self.fee_bps > config.max_user_fee_bps.max(config.max_solver_fee_bps) {
            return Err(format!(
                "liquidation_auction fee exceeds configured ceiling"
            ));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "liquidation_auction privacy set below configured floor"
            ));
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!(
                "liquidation_auction expiry must be after opening height"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SolverReceipt {
    pub receipt_id: String,
    pub account_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub status: ReceiptStatus,
    pub execution_root: String,
    pub nullifier_root: String,
    pub witness_root: String,
    pub proof_root: String,
    pub view_tag: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub lane_id: String,
    pub metadata_root: String,
}
impl SolverReceipt {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_id(&self) -> &str {
        &self.receipt_id
    }
    pub fn deterministic_id(seed: &str, account_id: &str, market_id: &str, nonce: u64) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-RECEIPT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(seed),
                HashPart::Str(account_id),
                HashPart::Str(market_id),
                HashPart::U64(nonce),
            ],
            32,
        )
    }
    pub fn commitment_root(&self) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-RECEIPT-COMMITMENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("receipt_id", &self.receipt_id)?;
        ensure_non_empty("account_id", &self.account_id)?;
        ensure_non_empty("market_id", &self.market_id)?;
        ensure_non_empty("asset_id", &self.asset_id)?;
        ensure_non_empty("execution_root", &self.execution_root)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("witness_root", &self.witness_root)?;
        ensure_non_empty("proof_root", &self.proof_root)?;
        ensure_non_empty("pq_public_key_root", &self.pq_public_key_root)?;
        ensure_non_empty("pq_signature_root", &self.pq_signature_root)?;
        ensure_non_empty("lane_id", &self.lane_id)?;
        ensure_bps("fee_bps", self.fee_bps)?;
        if self.fee_bps > config.max_user_fee_bps.max(config.max_solver_fee_bps) {
            return Err(format!("solver_receipt fee exceeds configured ceiling"));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("solver_receipt privacy set below configured floor"));
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!(
                "solver_receipt expiry must be after opening height"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub account_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub rebate_commitment: String,
    pub nullifier_root: String,
    pub witness_root: String,
    pub proof_root: String,
    pub view_tag: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub lane_id: String,
    pub metadata_root: String,
}
impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_id(&self) -> &str {
        &self.rebate_id
    }
    pub fn deterministic_id(seed: &str, account_id: &str, market_id: &str, nonce: u64) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-REBATE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(seed),
                HashPart::Str(account_id),
                HashPart::Str(market_id),
                HashPart::U64(nonce),
            ],
            32,
        )
    }
    pub fn commitment_root(&self) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-REBATE-COMMITMENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("rebate_id", &self.rebate_id)?;
        ensure_non_empty("account_id", &self.account_id)?;
        ensure_non_empty("market_id", &self.market_id)?;
        ensure_non_empty("asset_id", &self.asset_id)?;
        ensure_non_empty("rebate_commitment", &self.rebate_commitment)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("witness_root", &self.witness_root)?;
        ensure_non_empty("proof_root", &self.proof_root)?;
        ensure_non_empty("pq_public_key_root", &self.pq_public_key_root)?;
        ensure_non_empty("pq_signature_root", &self.pq_signature_root)?;
        ensure_non_empty("lane_id", &self.lane_id)?;
        ensure_bps("fee_bps", self.fee_bps)?;
        if self.fee_bps > config.max_user_fee_bps.max(config.max_solver_fee_bps) {
            return Err(format!("fee_rebate fee exceeds configured ceiling"));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("fee_rebate privacy set below configured floor"));
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!("fee_rebate expiry must be after opening height"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyNullifierFence {
    pub fence_id: String,
    pub account_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub nullifier_root: String,
    pub witness_root: String,
    pub proof_root: String,
    pub view_tag: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub lane_id: String,
    pub metadata_root: String,
}
impl PrivacyNullifierFence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_id(&self) -> &str {
        &self.fence_id
    }
    pub fn deterministic_id(seed: &str, account_id: &str, market_id: &str, nonce: u64) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-FENCE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(seed),
                HashPart::Str(account_id),
                HashPart::Str(market_id),
                HashPart::U64(nonce),
            ],
            32,
        )
    }
    pub fn commitment_root(&self) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-FENCE-COMMITMENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("fence_id", &self.fence_id)?;
        ensure_non_empty("account_id", &self.account_id)?;
        ensure_non_empty("market_id", &self.market_id)?;
        ensure_non_empty("asset_id", &self.asset_id)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("witness_root", &self.witness_root)?;
        ensure_non_empty("proof_root", &self.proof_root)?;
        ensure_non_empty("pq_public_key_root", &self.pq_public_key_root)?;
        ensure_non_empty("pq_signature_root", &self.pq_signature_root)?;
        ensure_non_empty("lane_id", &self.lane_id)?;
        ensure_bps("fee_bps", self.fee_bps)?;
        if self.fee_bps > config.max_user_fee_bps.max(config.max_solver_fee_bps) {
            return Err(format!(
                "privacy_nullifier_fence fee exceeds configured ceiling"
            ));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "privacy_nullifier_fence privacy set below configured floor"
            ));
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!(
                "privacy_nullifier_fence expiry must be after opening height"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub account_id: String,
    pub market_id: String,
    pub asset_id: String,
    pub reason: SlashReason,
    pub evidence_root: String,
    pub nullifier_root: String,
    pub witness_root: String,
    pub proof_root: String,
    pub view_tag: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub lane_id: String,
    pub metadata_root: String,
}
impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn record_id(&self) -> &str {
        &self.evidence_id
    }
    pub fn deterministic_id(seed: &str, account_id: &str, market_id: &str, nonce: u64) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-SLASH-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(seed),
                HashPart::Str(account_id),
                HashPart::Str(market_id),
                HashPart::U64(nonce),
            ],
            32,
        )
    }
    pub fn commitment_root(&self) -> String {
        domain_hash(
            "PQ-CROSS-MARGIN-LENDING-SLASH-COMMITMENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("evidence_id", &self.evidence_id)?;
        ensure_non_empty("account_id", &self.account_id)?;
        ensure_non_empty("market_id", &self.market_id)?;
        ensure_non_empty("asset_id", &self.asset_id)?;
        ensure_non_empty("evidence_root", &self.evidence_root)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("witness_root", &self.witness_root)?;
        ensure_non_empty("proof_root", &self.proof_root)?;
        ensure_non_empty("pq_public_key_root", &self.pq_public_key_root)?;
        ensure_non_empty("pq_signature_root", &self.pq_signature_root)?;
        ensure_non_empty("lane_id", &self.lane_id)?;
        ensure_bps("fee_bps", self.fee_bps)?;
        if self.fee_bps > config.max_user_fee_bps.max(config.max_solver_fee_bps) {
            return Err(format!("slashing_evidence fee exceeds configured ceiling"));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "slashing_evidence privacy set below configured floor"
            ));
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!(
                "slashing_evidence expiry must be after opening height"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub encrypted_lending_intent_root: String,
    pub collateral_note_root: String,
    pub borrow_note_root: String,
    pub margin_account_root: String,
    pub risk_attestation_root: String,
    pub liquidation_auction_root: String,
    pub solver_receipt_root: String,
    pub fee_rebate_root: String,
    pub privacy_nullifier_fence_root: String,
    pub slashing_evidence_root: String,
    pub spent_nullifier_root: String,
    pub domain_catalog_root: String,
    pub config_root: String,
    pub counters_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub encrypted_lending_intents: BTreeMap<String, EncryptedLendingIntent>,
    pub collateral_notes: BTreeMap<String, CollateralNote>,
    pub borrow_notes: BTreeMap<String, BorrowNote>,
    pub margin_accounts: BTreeMap<String, MarginAccount>,
    pub risk_attestations: BTreeMap<String, RiskAttestation>,
    pub liquidation_auctions: BTreeMap<String, LiquidationAuction>,
    pub solver_receipts: BTreeMap<String, SolverReceipt>,
    pub fee_rebates: BTreeMap<String, FeeRebate>,
    pub privacy_nullifier_fences: BTreeMap<String, PrivacyNullifierFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub spent_nullifiers: BTreeSet<String>,
}
impl State {
    pub fn empty(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::empty(),
            roots: empty_roots(),
            encrypted_lending_intents: BTreeMap::new(),
            collateral_notes: BTreeMap::new(),
            borrow_notes: BTreeMap::new(),
            margin_accounts: BTreeMap::new(),
            risk_attestations: BTreeMap::new(),
            liquidation_auctions: BTreeMap::new(),
            solver_receipts: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            privacy_nullifier_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        };
        state.refresh_counters_and_roots();
        Ok(state)
    }
    pub fn devnet() -> Self {
        let mut state = Self::empty(Config::devnet()).expect("valid devnet config");
        for intent in devnet_encrypted_lending_intents() {
            state
                .insert_encrypted_lending_intent(intent)
                .expect("valid devnet intent");
        }
        for note in devnet_collateral_notes() {
            state
                .insert_collateral_note(note)
                .expect("valid devnet collateral note");
        }
        for note in devnet_borrow_notes() {
            state
                .insert_borrow_note(note)
                .expect("valid devnet borrow note");
        }
        for account in devnet_margin_accounts() {
            state
                .insert_margin_account(account)
                .expect("valid devnet margin account");
        }
        for attestation in devnet_risk_attestations() {
            state
                .insert_risk_attestation(attestation)
                .expect("valid devnet risk attestation");
        }
        for auction in devnet_liquidation_auctions() {
            state
                .insert_liquidation_auction(auction)
                .expect("valid devnet liquidation auction");
        }
        for receipt in devnet_solver_receipts() {
            state
                .insert_solver_receipt(receipt)
                .expect("valid devnet solver receipt");
        }
        for rebate in devnet_fee_rebates() {
            state
                .insert_fee_rebate(rebate)
                .expect("valid devnet fee rebate");
        }
        for fence in devnet_privacy_nullifier_fences() {
            state
                .insert_privacy_nullifier_fence(fence)
                .expect("valid devnet privacy fence");
        }
        for evidence in devnet_slashing_evidence() {
            state
                .insert_slashing_evidence(evidence)
                .expect("valid devnet slashing evidence");
        }
        state
            .mark_nullifier_spent("devnet-nullifier-wallet-a-0001")
            .expect("valid devnet nullifier");
        state
            .mark_nullifier_spent("devnet-nullifier-wallet-b-0001")
            .expect("valid devnet nullifier");
        state.refresh_counters_and_roots();
        state
    }
    pub fn public_record_without_root(&self) -> Value {
        json!({ "protocol_version": self.config.protocol_version, "schema_version": self.config.schema_version, "chain_id": self.config.chain_id, "config": self.config.public_record(), "counters": self.counters.public_record(), "roots": self.roots.public_record() })
    }
    pub fn public_record(&self) -> Value {
        json!({ "state_root": self.state_root(), "record": self.public_record_without_root() })
    }
    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_root())
    }
    pub fn refresh_counters_and_roots(&mut self) {
        self.counters = self.derive_counters();
        self.roots = self.derive_roots();
    }
    pub fn mark_nullifier_spent(&mut self, nullifier: &str) -> Result<()> {
        ensure_non_empty("nullifier", nullifier)?;
        if !self.spent_nullifiers.insert(nullifier.to_string()) {
            return Err("nullifier already spent".to_string());
        }
        self.refresh_counters_and_roots();
        Ok(())
    }
    pub fn has_spent_nullifier(&self, nullifier: &str) -> bool {
        self.spent_nullifiers.contains(nullifier)
    }
    pub fn insert_encrypted_lending_intent(
        &mut self,
        record: EncryptedLendingIntent,
    ) -> Result<()> {
        record.validate(&self.config)?;
        if self.encrypted_lending_intents.len() >= self.config.max_intents {
            return Err("encrypted_lending_intent capacity exceeded".to_string());
        }
        if self
            .encrypted_lending_intents
            .contains_key(record.record_id())
        {
            return Err(format!(
                "duplicate encrypted_lending_intent: {}",
                record.record_id()
            ));
        }
        self.encrypted_lending_intents
            .insert(record.record_id().to_string(), record);
        self.refresh_counters_and_roots();
        Ok(())
    }
    pub fn insert_collateral_note(&mut self, record: CollateralNote) -> Result<()> {
        record.validate(&self.config)?;
        if self.collateral_notes.len() >= self.config.max_collateral_notes {
            return Err("collateral_note capacity exceeded".to_string());
        }
        if self.collateral_notes.contains_key(record.record_id()) {
            return Err(format!("duplicate collateral_note: {}", record.record_id()));
        }
        self.collateral_notes
            .insert(record.record_id().to_string(), record);
        self.refresh_counters_and_roots();
        Ok(())
    }
    pub fn insert_borrow_note(&mut self, record: BorrowNote) -> Result<()> {
        record.validate(&self.config)?;
        if self.borrow_notes.len() >= self.config.max_borrow_notes {
            return Err("borrow_note capacity exceeded".to_string());
        }
        if self.borrow_notes.contains_key(record.record_id()) {
            return Err(format!("duplicate borrow_note: {}", record.record_id()));
        }
        self.borrow_notes
            .insert(record.record_id().to_string(), record);
        self.refresh_counters_and_roots();
        Ok(())
    }
    pub fn insert_margin_account(&mut self, record: MarginAccount) -> Result<()> {
        record.validate(&self.config)?;
        if self.margin_accounts.len() >= self.config.max_margin_accounts {
            return Err("margin_account capacity exceeded".to_string());
        }
        if self.margin_accounts.contains_key(record.record_id()) {
            return Err(format!("duplicate margin_account: {}", record.record_id()));
        }
        self.margin_accounts
            .insert(record.record_id().to_string(), record);
        self.refresh_counters_and_roots();
        Ok(())
    }
    pub fn insert_risk_attestation(&mut self, record: RiskAttestation) -> Result<()> {
        record.validate(&self.config)?;
        if self.risk_attestations.len() >= self.config.max_risk_attestations {
            return Err("risk_attestation capacity exceeded".to_string());
        }
        if self.risk_attestations.contains_key(record.record_id()) {
            return Err(format!(
                "duplicate risk_attestation: {}",
                record.record_id()
            ));
        }
        self.risk_attestations
            .insert(record.record_id().to_string(), record);
        self.refresh_counters_and_roots();
        Ok(())
    }
    pub fn insert_liquidation_auction(&mut self, record: LiquidationAuction) -> Result<()> {
        record.validate(&self.config)?;
        if self.liquidation_auctions.len() >= self.config.max_liquidation_auctions {
            return Err("liquidation_auction capacity exceeded".to_string());
        }
        if self.liquidation_auctions.contains_key(record.record_id()) {
            return Err(format!(
                "duplicate liquidation_auction: {}",
                record.record_id()
            ));
        }
        self.liquidation_auctions
            .insert(record.record_id().to_string(), record);
        self.refresh_counters_and_roots();
        Ok(())
    }
    pub fn insert_solver_receipt(&mut self, record: SolverReceipt) -> Result<()> {
        record.validate(&self.config)?;
        if self.solver_receipts.len() >= self.config.max_solver_receipts {
            return Err("solver_receipt capacity exceeded".to_string());
        }
        if self.solver_receipts.contains_key(record.record_id()) {
            return Err(format!("duplicate solver_receipt: {}", record.record_id()));
        }
        self.solver_receipts
            .insert(record.record_id().to_string(), record);
        self.refresh_counters_and_roots();
        Ok(())
    }
    pub fn insert_fee_rebate(&mut self, record: FeeRebate) -> Result<()> {
        record.validate(&self.config)?;
        if self.fee_rebates.len() >= self.config.max_fee_rebates {
            return Err("fee_rebate capacity exceeded".to_string());
        }
        if self.fee_rebates.contains_key(record.record_id()) {
            return Err(format!("duplicate fee_rebate: {}", record.record_id()));
        }
        self.fee_rebates
            .insert(record.record_id().to_string(), record);
        self.refresh_counters_and_roots();
        Ok(())
    }
    pub fn insert_privacy_nullifier_fence(&mut self, record: PrivacyNullifierFence) -> Result<()> {
        record.validate(&self.config)?;
        if self.privacy_nullifier_fences.len() >= self.config.max_privacy_fences {
            return Err("privacy_nullifier_fence capacity exceeded".to_string());
        }
        if self
            .privacy_nullifier_fences
            .contains_key(record.record_id())
        {
            return Err(format!(
                "duplicate privacy_nullifier_fence: {}",
                record.record_id()
            ));
        }
        self.privacy_nullifier_fences
            .insert(record.record_id().to_string(), record);
        self.refresh_counters_and_roots();
        Ok(())
    }
    pub fn insert_slashing_evidence(&mut self, record: SlashingEvidence) -> Result<()> {
        record.validate(&self.config)?;
        if self.slashing_evidence.len() >= self.config.max_slashing_evidence {
            return Err("slashing_evidence capacity exceeded".to_string());
        }
        if self.slashing_evidence.contains_key(record.record_id()) {
            return Err(format!(
                "duplicate slashing_evidence: {}",
                record.record_id()
            ));
        }
        self.slashing_evidence
            .insert(record.record_id().to_string(), record);
        self.refresh_counters_and_roots();
        Ok(())
    }
    fn derive_counters(&self) -> Counters {
        Counters {
            encrypted_lending_intents: self.encrypted_lending_intents.len() as u64,
            collateral_notes: self.collateral_notes.len() as u64,
            borrow_notes: self.borrow_notes.len() as u64,
            margin_accounts: self.margin_accounts.len() as u64,
            risk_attestations: self.risk_attestations.len() as u64,
            liquidation_auctions: self.liquidation_auctions.len() as u64,
            solver_receipts: self.solver_receipts.len() as u64,
            fee_rebates: self.fee_rebates.len() as u64,
            privacy_nullifier_fences: self.privacy_nullifier_fences.len() as u64,
            slashing_evidence: self.slashing_evidence.len() as u64,
            active_intents: self
                .encrypted_lending_intents
                .values()
                .filter(|record| record.status.live())
                .count() as u64,
            active_margin_accounts: self
                .margin_accounts
                .values()
                .filter(|record| {
                    matches!(
                        record.status,
                        AccountStatus::Open | AccountStatus::ReduceOnly | AccountStatus::MarginCall
                    )
                })
                .count() as u64,
            live_collateral_notes: self
                .collateral_notes
                .values()
                .filter(|record| record.status.live())
                .count() as u64,
            live_borrow_notes: self
                .borrow_notes
                .values()
                .filter(|record| record.status.live())
                .count() as u64,
            liquidatable_accounts: self
                .margin_accounts
                .values()
                .filter(|record| record.status == AccountStatus::Liquidatable)
                .count() as u64,
            total_rebate_micro_units: self.fee_rebates.values().map(|record| record.fee_bps).sum(),
            total_slashed_micro_units: self
                .slashing_evidence
                .values()
                .map(|record| record.fee_bps)
                .sum(),
        }
    }
    fn derive_roots(&self) -> Roots {
        Roots {
            encrypted_lending_intent_root: map_root(
                "PQ-CROSS-MARGIN-LENDING-INTENT",
                &self.encrypted_lending_intents,
            ),
            collateral_note_root: map_root(
                "PQ-CROSS-MARGIN-LENDING-COLLATERAL-NOTE",
                &self.collateral_notes,
            ),
            borrow_note_root: map_root("PQ-CROSS-MARGIN-LENDING-BORROW-NOTE", &self.borrow_notes),
            margin_account_root: map_root(
                "PQ-CROSS-MARGIN-LENDING-MARGIN-ACCOUNT",
                &self.margin_accounts,
            ),
            risk_attestation_root: map_root(
                "PQ-CROSS-MARGIN-LENDING-RISK-ATTESTATION",
                &self.risk_attestations,
            ),
            liquidation_auction_root: map_root(
                "PQ-CROSS-MARGIN-LENDING-LIQUIDATION-AUCTION",
                &self.liquidation_auctions,
            ),
            solver_receipt_root: map_root(
                "PQ-CROSS-MARGIN-LENDING-SOLVER-RECEIPT",
                &self.solver_receipts,
            ),
            fee_rebate_root: map_root("PQ-CROSS-MARGIN-LENDING-FEE-REBATE", &self.fee_rebates),
            privacy_nullifier_fence_root: map_root(
                "PQ-CROSS-MARGIN-LENDING-PRIVACY-FENCE",
                &self.privacy_nullifier_fences,
            ),
            slashing_evidence_root: map_root(
                "PQ-CROSS-MARGIN-LENDING-SLASHING-EVIDENCE",
                &self.slashing_evidence,
            ),
            spent_nullifier_root: set_root(
                "PQ-CROSS-MARGIN-LENDING-SPENT-NULLIFIER",
                &self.spent_nullifiers,
            ),
            domain_catalog_root: merkle_root(
                "PQ-CROSS-MARGIN-LENDING-DOMAIN-CATALOG",
                &domain_catalog_records(),
            ),
            config_root: domain_hash(
                "PQ-CROSS-MARGIN-LENDING-CONFIG",
                &[HashPart::Json(&self.config.public_record())],
                32,
            ),
            counters_root: domain_hash(
                "PQ-CROSS-MARGIN-LENDING-COUNTERS",
                &[HashPart::Json(&self.counters.public_record())],
                32,
            ),
        }
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}
impl PublicRecord for EncryptedLendingIntent {
    fn public_record(&self) -> Value {
        EncryptedLendingIntent::public_record(self)
    }
}
impl PublicRecord for CollateralNote {
    fn public_record(&self) -> Value {
        CollateralNote::public_record(self)
    }
}
impl PublicRecord for BorrowNote {
    fn public_record(&self) -> Value {
        BorrowNote::public_record(self)
    }
}
impl PublicRecord for MarginAccount {
    fn public_record(&self) -> Value {
        MarginAccount::public_record(self)
    }
}
impl PublicRecord for RiskAttestation {
    fn public_record(&self) -> Value {
        RiskAttestation::public_record(self)
    }
}
impl PublicRecord for LiquidationAuction {
    fn public_record(&self) -> Value {
        LiquidationAuction::public_record(self)
    }
}
impl PublicRecord for SolverReceipt {
    fn public_record(&self) -> Value {
        SolverReceipt::public_record(self)
    }
}
impl PublicRecord for FeeRebate {
    fn public_record(&self) -> Value {
        FeeRebate::public_record(self)
    }
}
impl PublicRecord for PrivacyNullifierFence {
    fn public_record(&self) -> Value {
        PrivacyNullifierFence::public_record(self)
    }
}
impl PublicRecord for SlashingEvidence {
    fn public_record(&self) -> Value {
        SlashingEvidence::public_record(self)
    }
}

fn empty_roots() -> Roots {
    Roots {
        encrypted_lending_intent_root: merkle_root("PQ-CROSS-MARGIN-LENDING-INTENT", &[]),
        collateral_note_root: merkle_root("PQ-CROSS-MARGIN-LENDING-COLLATERAL-NOTE", &[]),
        borrow_note_root: merkle_root("PQ-CROSS-MARGIN-LENDING-BORROW-NOTE", &[]),
        margin_account_root: merkle_root("PQ-CROSS-MARGIN-LENDING-MARGIN-ACCOUNT", &[]),
        risk_attestation_root: merkle_root("PQ-CROSS-MARGIN-LENDING-RISK-ATTESTATION", &[]),
        liquidation_auction_root: merkle_root("PQ-CROSS-MARGIN-LENDING-LIQUIDATION-AUCTION", &[]),
        solver_receipt_root: merkle_root("PQ-CROSS-MARGIN-LENDING-SOLVER-RECEIPT", &[]),
        fee_rebate_root: merkle_root("PQ-CROSS-MARGIN-LENDING-FEE-REBATE", &[]),
        privacy_nullifier_fence_root: merkle_root("PQ-CROSS-MARGIN-LENDING-PRIVACY-FENCE", &[]),
        slashing_evidence_root: merkle_root("PQ-CROSS-MARGIN-LENDING-SLASHING-EVIDENCE", &[]),
        spent_nullifier_root: merkle_root("PQ-CROSS-MARGIN-LENDING-SPENT-NULLIFIER", &[]),
        domain_catalog_root: merkle_root(
            "PQ-CROSS-MARGIN-LENDING-DOMAIN-CATALOG",
            &domain_catalog_records(),
        ),
        config_root: merkle_root("PQ-CROSS-MARGIN-LENDING-CONFIG", &[]),
        counters_root: merkle_root("PQ-CROSS-MARGIN-LENDING-COUNTERS", &[]),
    }
}
fn ensure_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}
fn ensure_bps(label: &str, value: u64) -> Result<()> {
    if value > PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_MAX_BPS {
        return Err(format!("{label} exceeds bps denominator"));
    }
    Ok(())
}
fn map_root<T: PublicRecord>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(id, record)| json!({"id": id, "record": record.public_record()}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
fn set_root(domain: &str, records: &BTreeSet<String>) -> String {
    let leaves = records.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "PQ-CROSS-MARGIN-LENDING-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}
pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}
pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}
pub fn deterministic_market_id(
    collateral_asset_id: &str,
    borrow_asset_id: &str,
    risk_model_root: &str,
) -> String {
    domain_hash(
        "PQ-CROSS-MARGIN-LENDING-MARKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(collateral_asset_id),
            HashPart::Str(borrow_asset_id),
            HashPart::Str(risk_model_root),
        ],
        32,
    )
}
pub fn deterministic_account_id(
    owner_view_root: &str,
    margin_group_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PQ-CROSS-MARGIN-LENDING-ACCOUNT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_view_root),
            HashPart::Str(margin_group_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}
pub fn deterministic_nullifier_fence_id(
    nullifier_root: &str,
    lane_id: &str,
    height: u64,
) -> String {
    domain_hash(
        "PQ-CROSS-MARGIN-LENDING-NULLIFIER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(nullifier_root),
            HashPart::Str(lane_id),
            HashPart::U64(height),
        ],
        32,
    )
}
fn sample_hash(domain: &str, label: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(label)], 32)
}
fn sample_record_base(
    label: &str,
    index: u64,
) -> (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
) {
    (
        deterministic_account_id(
            &format!("devnet-owner-{label}"),
            "devnet-margin-group-cross",
            index,
        ),
        deterministic_market_id("asset:wxmr", "asset:private-dusd", "devnet-risk-model-root"),
        "asset:wxmr".to_string(),
        sample_hash("PQ-CROSS-MARGIN-LENDING-SAMPLE-COMMITMENT", label),
        sample_hash("PQ-CROSS-MARGIN-LENDING-SAMPLE-NULLIFIER", label),
        sample_hash("PQ-CROSS-MARGIN-LENDING-SAMPLE-WITNESS", label),
        sample_hash("PQ-CROSS-MARGIN-LENDING-SAMPLE-PROOF", label),
        sample_hash("PQ-CROSS-MARGIN-LENDING-SAMPLE-PQ-PUBLIC-KEY", label),
        sample_hash("PQ-CROSS-MARGIN-LENDING-SAMPLE-PQ-SIGNATURE", label),
    )
}

fn devnet_encrypted_lending_intents() -> Vec<EncryptedLendingIntent> {
    (0..3).map(|index| { let label = format!("encrypted_lending_intent-{index}"); let (account_id, market_id, asset_id, commitment, nullifier, witness, proof, pq_key, pq_sig) = sample_record_base(&label, index); EncryptedLendingIntent { intent_id: EncryptedLendingIntent::deterministic_id("devnet", &account_id, &market_id, index), account_id, market_id, asset_id, intent_kind: IntentKind::Borrow, status: IntentStatus::Admitted, encrypted_payload_root: commitment, nullifier_root: nullifier, witness_root: witness, proof_root: proof, view_tag: format!("view-tag-{label}"), pq_public_key_root: pq_key, pq_signature_root: pq_sig, privacy_set_size: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE, fee_bps: 8 + index, opened_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + index, expires_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + 64 + index, lane_id: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_LOW_FEE_LANE.to_string(), metadata_root: sample_hash("PQ-CROSS-MARGIN-LENDING-SAMPLE-METADATA", &label) } }).collect()
}
fn devnet_collateral_notes() -> Vec<CollateralNote> {
    (0..3).map(|index| { let label = format!("collateral_note-{index}"); let (account_id, market_id, asset_id, commitment, nullifier, witness, proof, pq_key, pq_sig) = sample_record_base(&label, index); CollateralNote { note_id: CollateralNote::deterministic_id("devnet", &account_id, &market_id, index), account_id, market_id, asset_id, status: NoteStatus::Active, commitment: commitment, nullifier_root: nullifier, witness_root: witness, proof_root: proof, view_tag: format!("view-tag-{label}"), pq_public_key_root: pq_key, pq_signature_root: pq_sig, privacy_set_size: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE, fee_bps: 8 + index, opened_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + index, expires_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + 64 + index, lane_id: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_LOW_FEE_LANE.to_string(), metadata_root: sample_hash("PQ-CROSS-MARGIN-LENDING-SAMPLE-METADATA", &label) } }).collect()
}
fn devnet_borrow_notes() -> Vec<BorrowNote> {
    (0..3).map(|index| { let label = format!("borrow_note-{index}"); let (account_id, market_id, asset_id, commitment, nullifier, witness, proof, pq_key, pq_sig) = sample_record_base(&label, index); BorrowNote { note_id: BorrowNote::deterministic_id("devnet", &account_id, &market_id, index), account_id, market_id, asset_id, status: NoteStatus::Active, debt_commitment: commitment, nullifier_root: nullifier, witness_root: witness, proof_root: proof, view_tag: format!("view-tag-{label}"), pq_public_key_root: pq_key, pq_signature_root: pq_sig, privacy_set_size: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE, fee_bps: 8 + index, opened_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + index, expires_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + 64 + index, lane_id: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_LOW_FEE_LANE.to_string(), metadata_root: sample_hash("PQ-CROSS-MARGIN-LENDING-SAMPLE-METADATA", &label) } }).collect()
}
fn devnet_margin_accounts() -> Vec<MarginAccount> {
    (0..3).map(|index| { let label = format!("margin_account-{index}"); let (account_id, market_id, asset_id, commitment, nullifier, witness, proof, pq_key, pq_sig) = sample_record_base(&label, index); MarginAccount { account_id, market_id, asset_id, status: if index == 2 { AccountStatus::MarginCall } else { AccountStatus::Open }, account_commitment: commitment, nullifier_root: nullifier, witness_root: witness, proof_root: proof, view_tag: format!("view-tag-{label}"), pq_public_key_root: pq_key, pq_signature_root: pq_sig, privacy_set_size: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE, fee_bps: 8 + index, opened_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + index, expires_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + 64 + index, lane_id: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_LOW_FEE_LANE.to_string(), metadata_root: sample_hash("PQ-CROSS-MARGIN-LENDING-SAMPLE-METADATA", &label) } }).collect()
}
fn devnet_risk_attestations() -> Vec<RiskAttestation> {
    (0..3).map(|index| { let label = format!("risk_attestation-{index}"); let (account_id, market_id, asset_id, commitment, nullifier, witness, proof, pq_key, pq_sig) = sample_record_base(&label, index); RiskAttestation { attestation_id: RiskAttestation::deterministic_id("devnet", &account_id, &market_id, index), account_id, market_id, asset_id, verdict: if index == 2 { RiskVerdict::MarginCall } else { RiskVerdict::Healthy }, risk_vector_root: commitment, nullifier_root: nullifier, witness_root: witness, proof_root: proof, view_tag: format!("view-tag-{label}"), pq_public_key_root: pq_key, pq_signature_root: pq_sig, privacy_set_size: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE, fee_bps: 8 + index, opened_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + index, expires_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + 64 + index, lane_id: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_LOW_FEE_LANE.to_string(), metadata_root: sample_hash("PQ-CROSS-MARGIN-LENDING-SAMPLE-METADATA", &label) } }).collect()
}
fn devnet_liquidation_auctions() -> Vec<LiquidationAuction> {
    (0..3).map(|index| { let label = format!("liquidation_auction-{index}"); let (account_id, market_id, asset_id, commitment, nullifier, witness, proof, pq_key, pq_sig) = sample_record_base(&label, index); LiquidationAuction { auction_id: LiquidationAuction::deterministic_id("devnet", &account_id, &market_id, index), account_id, market_id, asset_id, status: AuctionStatus::Bidding, sealed_bid_root: commitment, nullifier_root: nullifier, witness_root: witness, proof_root: proof, view_tag: format!("view-tag-{label}"), pq_public_key_root: pq_key, pq_signature_root: pq_sig, privacy_set_size: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE, fee_bps: 8 + index, opened_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + index, expires_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + 64 + index, lane_id: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_LOW_FEE_LANE.to_string(), metadata_root: sample_hash("PQ-CROSS-MARGIN-LENDING-SAMPLE-METADATA", &label) } }).collect()
}
fn devnet_solver_receipts() -> Vec<SolverReceipt> {
    (0..3).map(|index| { let label = format!("solver_receipt-{index}"); let (account_id, market_id, asset_id, commitment, nullifier, witness, proof, pq_key, pq_sig) = sample_record_base(&label, index); SolverReceipt { receipt_id: SolverReceipt::deterministic_id("devnet", &account_id, &market_id, index), account_id, market_id, asset_id, status: ReceiptStatus::Proved, execution_root: commitment, nullifier_root: nullifier, witness_root: witness, proof_root: proof, view_tag: format!("view-tag-{label}"), pq_public_key_root: pq_key, pq_signature_root: pq_sig, privacy_set_size: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE, fee_bps: 8 + index, opened_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + index, expires_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + 64 + index, lane_id: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_LOW_FEE_LANE.to_string(), metadata_root: sample_hash("PQ-CROSS-MARGIN-LENDING-SAMPLE-METADATA", &label) } }).collect()
}
fn devnet_fee_rebates() -> Vec<FeeRebate> {
    (0..3).map(|index| { let label = format!("fee_rebate-{index}"); let (account_id, market_id, asset_id, commitment, nullifier, witness, proof, pq_key, pq_sig) = sample_record_base(&label, index); FeeRebate { rebate_id: FeeRebate::deterministic_id("devnet", &account_id, &market_id, index), account_id, market_id, asset_id, rebate_commitment: commitment, nullifier_root: nullifier, witness_root: witness, proof_root: proof, view_tag: format!("view-tag-{label}"), pq_public_key_root: pq_key, pq_signature_root: pq_sig, privacy_set_size: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE, fee_bps: 8 + index, opened_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + index, expires_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + 64 + index, lane_id: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_LOW_FEE_LANE.to_string(), metadata_root: sample_hash("PQ-CROSS-MARGIN-LENDING-SAMPLE-METADATA", &label) } }).collect()
}
fn devnet_privacy_nullifier_fences() -> Vec<PrivacyNullifierFence> {
    (0..3).map(|index| { let label = format!("privacy_nullifier_fence-{index}"); let (account_id, market_id, asset_id, commitment, _nullifier, witness, proof, pq_key, pq_sig) = sample_record_base(&label, index); PrivacyNullifierFence { fence_id: PrivacyNullifierFence::deterministic_id("devnet", &account_id, &market_id, index), account_id, market_id, asset_id, nullifier_root: commitment, witness_root: witness, proof_root: proof, view_tag: format!("view-tag-{label}"), pq_public_key_root: pq_key, pq_signature_root: pq_sig, privacy_set_size: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE, fee_bps: 8 + index, opened_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + index, expires_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + 64 + index, lane_id: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_LOW_FEE_LANE.to_string(), metadata_root: sample_hash("PQ-CROSS-MARGIN-LENDING-SAMPLE-METADATA", &label) } }).collect()
}
fn devnet_slashing_evidence() -> Vec<SlashingEvidence> {
    (0..3).map(|index| { let label = format!("slashing_evidence-{index}"); let (account_id, market_id, asset_id, commitment, nullifier, witness, proof, pq_key, pq_sig) = sample_record_base(&label, index); SlashingEvidence { evidence_id: SlashingEvidence::deterministic_id("devnet", &account_id, &market_id, index), account_id, market_id, asset_id, reason: SlashReason::FeeOvercharge, evidence_root: commitment, nullifier_root: nullifier, witness_root: witness, proof_root: proof, view_tag: format!("view-tag-{label}"), pq_public_key_root: pq_key, pq_signature_root: pq_sig, privacy_set_size: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE, fee_bps: 8 + index, opened_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + index, expires_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEVNET_L2_HEIGHT + 64 + index, lane_id: PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_DEFAULT_LOW_FEE_LANE.to_string(), metadata_root: sample_hash("PQ-CROSS-MARGIN-LENDING-SAMPLE-METADATA", &label) } }).collect()
}
pub fn domain_catalog_records() -> Vec<Value> {
    vec![
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-INTENT", "purpose": "canonical intent root", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-COLLATERAL-NOTE", "purpose": "canonical collateral-note root", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-BORROW-NOTE", "purpose": "canonical borrow-note root", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-MARGIN-ACCOUNT", "purpose": "canonical margin-account root", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RISK-ATTESTATION", "purpose": "canonical risk-attestation root", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-LIQUIDATION-AUCTION", "purpose": "canonical liquidation-auction root", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-SOLVER-RECEIPT", "purpose": "canonical solver-receipt root", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-FEE-REBATE", "purpose": "canonical fee-rebate root", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-PRIVACY-FENCE", "purpose": "canonical privacy-fence root", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-SLASHING-EVIDENCE", "purpose": "canonical slashing-evidence root", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-STATE", "purpose": "canonical state root", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-CONFIG", "purpose": "canonical config root", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-COUNTERS", "purpose": "canonical counters root", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-SPENT-NULLIFIER", "purpose": "canonical spent-nullifier root", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0001", "purpose": "reserved deterministic extension domain 0001", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0002", "purpose": "reserved deterministic extension domain 0002", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0003", "purpose": "reserved deterministic extension domain 0003", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0004", "purpose": "reserved deterministic extension domain 0004", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0005", "purpose": "reserved deterministic extension domain 0005", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0006", "purpose": "reserved deterministic extension domain 0006", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0007", "purpose": "reserved deterministic extension domain 0007", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0008", "purpose": "reserved deterministic extension domain 0008", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0009", "purpose": "reserved deterministic extension domain 0009", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0010", "purpose": "reserved deterministic extension domain 0010", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0011", "purpose": "reserved deterministic extension domain 0011", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0012", "purpose": "reserved deterministic extension domain 0012", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0013", "purpose": "reserved deterministic extension domain 0013", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0014", "purpose": "reserved deterministic extension domain 0014", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0015", "purpose": "reserved deterministic extension domain 0015", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0016", "purpose": "reserved deterministic extension domain 0016", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0017", "purpose": "reserved deterministic extension domain 0017", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0018", "purpose": "reserved deterministic extension domain 0018", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0019", "purpose": "reserved deterministic extension domain 0019", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0020", "purpose": "reserved deterministic extension domain 0020", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0021", "purpose": "reserved deterministic extension domain 0021", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0022", "purpose": "reserved deterministic extension domain 0022", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0023", "purpose": "reserved deterministic extension domain 0023", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0024", "purpose": "reserved deterministic extension domain 0024", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0025", "purpose": "reserved deterministic extension domain 0025", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0026", "purpose": "reserved deterministic extension domain 0026", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0027", "purpose": "reserved deterministic extension domain 0027", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0028", "purpose": "reserved deterministic extension domain 0028", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0029", "purpose": "reserved deterministic extension domain 0029", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0030", "purpose": "reserved deterministic extension domain 0030", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0031", "purpose": "reserved deterministic extension domain 0031", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0032", "purpose": "reserved deterministic extension domain 0032", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0033", "purpose": "reserved deterministic extension domain 0033", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0034", "purpose": "reserved deterministic extension domain 0034", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0035", "purpose": "reserved deterministic extension domain 0035", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0036", "purpose": "reserved deterministic extension domain 0036", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0037", "purpose": "reserved deterministic extension domain 0037", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0038", "purpose": "reserved deterministic extension domain 0038", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0039", "purpose": "reserved deterministic extension domain 0039", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0040", "purpose": "reserved deterministic extension domain 0040", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0041", "purpose": "reserved deterministic extension domain 0041", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0042", "purpose": "reserved deterministic extension domain 0042", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0043", "purpose": "reserved deterministic extension domain 0043", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0044", "purpose": "reserved deterministic extension domain 0044", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0045", "purpose": "reserved deterministic extension domain 0045", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0046", "purpose": "reserved deterministic extension domain 0046", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0047", "purpose": "reserved deterministic extension domain 0047", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0048", "purpose": "reserved deterministic extension domain 0048", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0049", "purpose": "reserved deterministic extension domain 0049", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0050", "purpose": "reserved deterministic extension domain 0050", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0051", "purpose": "reserved deterministic extension domain 0051", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0052", "purpose": "reserved deterministic extension domain 0052", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0053", "purpose": "reserved deterministic extension domain 0053", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0054", "purpose": "reserved deterministic extension domain 0054", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0055", "purpose": "reserved deterministic extension domain 0055", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0056", "purpose": "reserved deterministic extension domain 0056", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0057", "purpose": "reserved deterministic extension domain 0057", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0058", "purpose": "reserved deterministic extension domain 0058", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0059", "purpose": "reserved deterministic extension domain 0059", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0060", "purpose": "reserved deterministic extension domain 0060", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0061", "purpose": "reserved deterministic extension domain 0061", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0062", "purpose": "reserved deterministic extension domain 0062", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0063", "purpose": "reserved deterministic extension domain 0063", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0064", "purpose": "reserved deterministic extension domain 0064", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0065", "purpose": "reserved deterministic extension domain 0065", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0066", "purpose": "reserved deterministic extension domain 0066", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0067", "purpose": "reserved deterministic extension domain 0067", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0068", "purpose": "reserved deterministic extension domain 0068", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0069", "purpose": "reserved deterministic extension domain 0069", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0070", "purpose": "reserved deterministic extension domain 0070", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0071", "purpose": "reserved deterministic extension domain 0071", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0072", "purpose": "reserved deterministic extension domain 0072", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0073", "purpose": "reserved deterministic extension domain 0073", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0074", "purpose": "reserved deterministic extension domain 0074", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0075", "purpose": "reserved deterministic extension domain 0075", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0076", "purpose": "reserved deterministic extension domain 0076", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0077", "purpose": "reserved deterministic extension domain 0077", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0078", "purpose": "reserved deterministic extension domain 0078", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0079", "purpose": "reserved deterministic extension domain 0079", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0080", "purpose": "reserved deterministic extension domain 0080", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0081", "purpose": "reserved deterministic extension domain 0081", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0082", "purpose": "reserved deterministic extension domain 0082", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0083", "purpose": "reserved deterministic extension domain 0083", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0084", "purpose": "reserved deterministic extension domain 0084", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0085", "purpose": "reserved deterministic extension domain 0085", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0086", "purpose": "reserved deterministic extension domain 0086", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0087", "purpose": "reserved deterministic extension domain 0087", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0088", "purpose": "reserved deterministic extension domain 0088", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0089", "purpose": "reserved deterministic extension domain 0089", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0090", "purpose": "reserved deterministic extension domain 0090", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0091", "purpose": "reserved deterministic extension domain 0091", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0092", "purpose": "reserved deterministic extension domain 0092", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0093", "purpose": "reserved deterministic extension domain 0093", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0094", "purpose": "reserved deterministic extension domain 0094", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0095", "purpose": "reserved deterministic extension domain 0095", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0096", "purpose": "reserved deterministic extension domain 0096", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0097", "purpose": "reserved deterministic extension domain 0097", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0098", "purpose": "reserved deterministic extension domain 0098", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0099", "purpose": "reserved deterministic extension domain 0099", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0100", "purpose": "reserved deterministic extension domain 0100", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0101", "purpose": "reserved deterministic extension domain 0101", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0102", "purpose": "reserved deterministic extension domain 0102", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0103", "purpose": "reserved deterministic extension domain 0103", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0104", "purpose": "reserved deterministic extension domain 0104", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0105", "purpose": "reserved deterministic extension domain 0105", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0106", "purpose": "reserved deterministic extension domain 0106", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0107", "purpose": "reserved deterministic extension domain 0107", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0108", "purpose": "reserved deterministic extension domain 0108", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0109", "purpose": "reserved deterministic extension domain 0109", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0110", "purpose": "reserved deterministic extension domain 0110", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0111", "purpose": "reserved deterministic extension domain 0111", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0112", "purpose": "reserved deterministic extension domain 0112", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0113", "purpose": "reserved deterministic extension domain 0113", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0114", "purpose": "reserved deterministic extension domain 0114", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0115", "purpose": "reserved deterministic extension domain 0115", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0116", "purpose": "reserved deterministic extension domain 0116", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0117", "purpose": "reserved deterministic extension domain 0117", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0118", "purpose": "reserved deterministic extension domain 0118", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0119", "purpose": "reserved deterministic extension domain 0119", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0120", "purpose": "reserved deterministic extension domain 0120", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0121", "purpose": "reserved deterministic extension domain 0121", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0122", "purpose": "reserved deterministic extension domain 0122", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0123", "purpose": "reserved deterministic extension domain 0123", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0124", "purpose": "reserved deterministic extension domain 0124", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0125", "purpose": "reserved deterministic extension domain 0125", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0126", "purpose": "reserved deterministic extension domain 0126", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0127", "purpose": "reserved deterministic extension domain 0127", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0128", "purpose": "reserved deterministic extension domain 0128", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0129", "purpose": "reserved deterministic extension domain 0129", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0130", "purpose": "reserved deterministic extension domain 0130", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0131", "purpose": "reserved deterministic extension domain 0131", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0132", "purpose": "reserved deterministic extension domain 0132", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0133", "purpose": "reserved deterministic extension domain 0133", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0134", "purpose": "reserved deterministic extension domain 0134", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0135", "purpose": "reserved deterministic extension domain 0135", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0136", "purpose": "reserved deterministic extension domain 0136", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0137", "purpose": "reserved deterministic extension domain 0137", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0138", "purpose": "reserved deterministic extension domain 0138", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0139", "purpose": "reserved deterministic extension domain 0139", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0140", "purpose": "reserved deterministic extension domain 0140", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0141", "purpose": "reserved deterministic extension domain 0141", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0142", "purpose": "reserved deterministic extension domain 0142", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0143", "purpose": "reserved deterministic extension domain 0143", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0144", "purpose": "reserved deterministic extension domain 0144", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0145", "purpose": "reserved deterministic extension domain 0145", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0146", "purpose": "reserved deterministic extension domain 0146", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0147", "purpose": "reserved deterministic extension domain 0147", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0148", "purpose": "reserved deterministic extension domain 0148", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0149", "purpose": "reserved deterministic extension domain 0149", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0150", "purpose": "reserved deterministic extension domain 0150", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0151", "purpose": "reserved deterministic extension domain 0151", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0152", "purpose": "reserved deterministic extension domain 0152", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0153", "purpose": "reserved deterministic extension domain 0153", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0154", "purpose": "reserved deterministic extension domain 0154", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0155", "purpose": "reserved deterministic extension domain 0155", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0156", "purpose": "reserved deterministic extension domain 0156", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0157", "purpose": "reserved deterministic extension domain 0157", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0158", "purpose": "reserved deterministic extension domain 0158", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0159", "purpose": "reserved deterministic extension domain 0159", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0160", "purpose": "reserved deterministic extension domain 0160", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0161", "purpose": "reserved deterministic extension domain 0161", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0162", "purpose": "reserved deterministic extension domain 0162", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0163", "purpose": "reserved deterministic extension domain 0163", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0164", "purpose": "reserved deterministic extension domain 0164", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0165", "purpose": "reserved deterministic extension domain 0165", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0166", "purpose": "reserved deterministic extension domain 0166", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0167", "purpose": "reserved deterministic extension domain 0167", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0168", "purpose": "reserved deterministic extension domain 0168", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0169", "purpose": "reserved deterministic extension domain 0169", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0170", "purpose": "reserved deterministic extension domain 0170", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0171", "purpose": "reserved deterministic extension domain 0171", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0172", "purpose": "reserved deterministic extension domain 0172", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0173", "purpose": "reserved deterministic extension domain 0173", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0174", "purpose": "reserved deterministic extension domain 0174", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0175", "purpose": "reserved deterministic extension domain 0175", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0176", "purpose": "reserved deterministic extension domain 0176", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0177", "purpose": "reserved deterministic extension domain 0177", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0178", "purpose": "reserved deterministic extension domain 0178", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0179", "purpose": "reserved deterministic extension domain 0179", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0180", "purpose": "reserved deterministic extension domain 0180", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0181", "purpose": "reserved deterministic extension domain 0181", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0182", "purpose": "reserved deterministic extension domain 0182", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0183", "purpose": "reserved deterministic extension domain 0183", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0184", "purpose": "reserved deterministic extension domain 0184", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0185", "purpose": "reserved deterministic extension domain 0185", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0186", "purpose": "reserved deterministic extension domain 0186", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0187", "purpose": "reserved deterministic extension domain 0187", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0188", "purpose": "reserved deterministic extension domain 0188", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0189", "purpose": "reserved deterministic extension domain 0189", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0190", "purpose": "reserved deterministic extension domain 0190", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0191", "purpose": "reserved deterministic extension domain 0191", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0192", "purpose": "reserved deterministic extension domain 0192", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0193", "purpose": "reserved deterministic extension domain 0193", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0194", "purpose": "reserved deterministic extension domain 0194", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0195", "purpose": "reserved deterministic extension domain 0195", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0196", "purpose": "reserved deterministic extension domain 0196", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0197", "purpose": "reserved deterministic extension domain 0197", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0198", "purpose": "reserved deterministic extension domain 0198", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0199", "purpose": "reserved deterministic extension domain 0199", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0200", "purpose": "reserved deterministic extension domain 0200", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0201", "purpose": "reserved deterministic extension domain 0201", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0202", "purpose": "reserved deterministic extension domain 0202", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0203", "purpose": "reserved deterministic extension domain 0203", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0204", "purpose": "reserved deterministic extension domain 0204", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0205", "purpose": "reserved deterministic extension domain 0205", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0206", "purpose": "reserved deterministic extension domain 0206", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0207", "purpose": "reserved deterministic extension domain 0207", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0208", "purpose": "reserved deterministic extension domain 0208", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0209", "purpose": "reserved deterministic extension domain 0209", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0210", "purpose": "reserved deterministic extension domain 0210", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0211", "purpose": "reserved deterministic extension domain 0211", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0212", "purpose": "reserved deterministic extension domain 0212", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0213", "purpose": "reserved deterministic extension domain 0213", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0214", "purpose": "reserved deterministic extension domain 0214", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0215", "purpose": "reserved deterministic extension domain 0215", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0216", "purpose": "reserved deterministic extension domain 0216", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0217", "purpose": "reserved deterministic extension domain 0217", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0218", "purpose": "reserved deterministic extension domain 0218", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0219", "purpose": "reserved deterministic extension domain 0219", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0220", "purpose": "reserved deterministic extension domain 0220", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0221", "purpose": "reserved deterministic extension domain 0221", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0222", "purpose": "reserved deterministic extension domain 0222", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0223", "purpose": "reserved deterministic extension domain 0223", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0224", "purpose": "reserved deterministic extension domain 0224", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0225", "purpose": "reserved deterministic extension domain 0225", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0226", "purpose": "reserved deterministic extension domain 0226", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0227", "purpose": "reserved deterministic extension domain 0227", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0228", "purpose": "reserved deterministic extension domain 0228", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0229", "purpose": "reserved deterministic extension domain 0229", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0230", "purpose": "reserved deterministic extension domain 0230", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0231", "purpose": "reserved deterministic extension domain 0231", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0232", "purpose": "reserved deterministic extension domain 0232", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0233", "purpose": "reserved deterministic extension domain 0233", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0234", "purpose": "reserved deterministic extension domain 0234", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0235", "purpose": "reserved deterministic extension domain 0235", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0236", "purpose": "reserved deterministic extension domain 0236", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0237", "purpose": "reserved deterministic extension domain 0237", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0238", "purpose": "reserved deterministic extension domain 0238", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0239", "purpose": "reserved deterministic extension domain 0239", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0240", "purpose": "reserved deterministic extension domain 0240", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0241", "purpose": "reserved deterministic extension domain 0241", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0242", "purpose": "reserved deterministic extension domain 0242", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0243", "purpose": "reserved deterministic extension domain 0243", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0244", "purpose": "reserved deterministic extension domain 0244", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0245", "purpose": "reserved deterministic extension domain 0245", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0246", "purpose": "reserved deterministic extension domain 0246", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0247", "purpose": "reserved deterministic extension domain 0247", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0248", "purpose": "reserved deterministic extension domain 0248", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0249", "purpose": "reserved deterministic extension domain 0249", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0250", "purpose": "reserved deterministic extension domain 0250", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0251", "purpose": "reserved deterministic extension domain 0251", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0252", "purpose": "reserved deterministic extension domain 0252", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0253", "purpose": "reserved deterministic extension domain 0253", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0254", "purpose": "reserved deterministic extension domain 0254", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0255", "purpose": "reserved deterministic extension domain 0255", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0256", "purpose": "reserved deterministic extension domain 0256", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0257", "purpose": "reserved deterministic extension domain 0257", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0258", "purpose": "reserved deterministic extension domain 0258", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0259", "purpose": "reserved deterministic extension domain 0259", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0260", "purpose": "reserved deterministic extension domain 0260", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0261", "purpose": "reserved deterministic extension domain 0261", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0262", "purpose": "reserved deterministic extension domain 0262", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0263", "purpose": "reserved deterministic extension domain 0263", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0264", "purpose": "reserved deterministic extension domain 0264", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0265", "purpose": "reserved deterministic extension domain 0265", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0266", "purpose": "reserved deterministic extension domain 0266", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0267", "purpose": "reserved deterministic extension domain 0267", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0268", "purpose": "reserved deterministic extension domain 0268", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0269", "purpose": "reserved deterministic extension domain 0269", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0270", "purpose": "reserved deterministic extension domain 0270", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0271", "purpose": "reserved deterministic extension domain 0271", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0272", "purpose": "reserved deterministic extension domain 0272", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0273", "purpose": "reserved deterministic extension domain 0273", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0274", "purpose": "reserved deterministic extension domain 0274", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0275", "purpose": "reserved deterministic extension domain 0275", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0276", "purpose": "reserved deterministic extension domain 0276", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0277", "purpose": "reserved deterministic extension domain 0277", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0278", "purpose": "reserved deterministic extension domain 0278", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0279", "purpose": "reserved deterministic extension domain 0279", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0280", "purpose": "reserved deterministic extension domain 0280", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0281", "purpose": "reserved deterministic extension domain 0281", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0282", "purpose": "reserved deterministic extension domain 0282", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0283", "purpose": "reserved deterministic extension domain 0283", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0284", "purpose": "reserved deterministic extension domain 0284", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0285", "purpose": "reserved deterministic extension domain 0285", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0286", "purpose": "reserved deterministic extension domain 0286", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0287", "purpose": "reserved deterministic extension domain 0287", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0288", "purpose": "reserved deterministic extension domain 0288", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0289", "purpose": "reserved deterministic extension domain 0289", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0290", "purpose": "reserved deterministic extension domain 0290", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0291", "purpose": "reserved deterministic extension domain 0291", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0292", "purpose": "reserved deterministic extension domain 0292", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0293", "purpose": "reserved deterministic extension domain 0293", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0294", "purpose": "reserved deterministic extension domain 0294", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0295", "purpose": "reserved deterministic extension domain 0295", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0296", "purpose": "reserved deterministic extension domain 0296", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0297", "purpose": "reserved deterministic extension domain 0297", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0298", "purpose": "reserved deterministic extension domain 0298", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0299", "purpose": "reserved deterministic extension domain 0299", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0300", "purpose": "reserved deterministic extension domain 0300", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0301", "purpose": "reserved deterministic extension domain 0301", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0302", "purpose": "reserved deterministic extension domain 0302", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0303", "purpose": "reserved deterministic extension domain 0303", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0304", "purpose": "reserved deterministic extension domain 0304", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0305", "purpose": "reserved deterministic extension domain 0305", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0306", "purpose": "reserved deterministic extension domain 0306", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0307", "purpose": "reserved deterministic extension domain 0307", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0308", "purpose": "reserved deterministic extension domain 0308", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0309", "purpose": "reserved deterministic extension domain 0309", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0310", "purpose": "reserved deterministic extension domain 0310", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0311", "purpose": "reserved deterministic extension domain 0311", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0312", "purpose": "reserved deterministic extension domain 0312", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0313", "purpose": "reserved deterministic extension domain 0313", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0314", "purpose": "reserved deterministic extension domain 0314", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0315", "purpose": "reserved deterministic extension domain 0315", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0316", "purpose": "reserved deterministic extension domain 0316", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0317", "purpose": "reserved deterministic extension domain 0317", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0318", "purpose": "reserved deterministic extension domain 0318", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0319", "purpose": "reserved deterministic extension domain 0319", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0320", "purpose": "reserved deterministic extension domain 0320", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0321", "purpose": "reserved deterministic extension domain 0321", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0322", "purpose": "reserved deterministic extension domain 0322", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0323", "purpose": "reserved deterministic extension domain 0323", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0324", "purpose": "reserved deterministic extension domain 0324", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0325", "purpose": "reserved deterministic extension domain 0325", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0326", "purpose": "reserved deterministic extension domain 0326", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0327", "purpose": "reserved deterministic extension domain 0327", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0328", "purpose": "reserved deterministic extension domain 0328", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0329", "purpose": "reserved deterministic extension domain 0329", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0330", "purpose": "reserved deterministic extension domain 0330", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0331", "purpose": "reserved deterministic extension domain 0331", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0332", "purpose": "reserved deterministic extension domain 0332", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0333", "purpose": "reserved deterministic extension domain 0333", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0334", "purpose": "reserved deterministic extension domain 0334", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0335", "purpose": "reserved deterministic extension domain 0335", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0336", "purpose": "reserved deterministic extension domain 0336", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0337", "purpose": "reserved deterministic extension domain 0337", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0338", "purpose": "reserved deterministic extension domain 0338", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0339", "purpose": "reserved deterministic extension domain 0339", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0340", "purpose": "reserved deterministic extension domain 0340", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0341", "purpose": "reserved deterministic extension domain 0341", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0342", "purpose": "reserved deterministic extension domain 0342", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0343", "purpose": "reserved deterministic extension domain 0343", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0344", "purpose": "reserved deterministic extension domain 0344", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0345", "purpose": "reserved deterministic extension domain 0345", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0346", "purpose": "reserved deterministic extension domain 0346", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0347", "purpose": "reserved deterministic extension domain 0347", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0348", "purpose": "reserved deterministic extension domain 0348", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0349", "purpose": "reserved deterministic extension domain 0349", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0350", "purpose": "reserved deterministic extension domain 0350", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0351", "purpose": "reserved deterministic extension domain 0351", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0352", "purpose": "reserved deterministic extension domain 0352", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0353", "purpose": "reserved deterministic extension domain 0353", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0354", "purpose": "reserved deterministic extension domain 0354", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0355", "purpose": "reserved deterministic extension domain 0355", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0356", "purpose": "reserved deterministic extension domain 0356", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0357", "purpose": "reserved deterministic extension domain 0357", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0358", "purpose": "reserved deterministic extension domain 0358", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0359", "purpose": "reserved deterministic extension domain 0359", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0360", "purpose": "reserved deterministic extension domain 0360", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0361", "purpose": "reserved deterministic extension domain 0361", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0362", "purpose": "reserved deterministic extension domain 0362", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0363", "purpose": "reserved deterministic extension domain 0363", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0364", "purpose": "reserved deterministic extension domain 0364", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0365", "purpose": "reserved deterministic extension domain 0365", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0366", "purpose": "reserved deterministic extension domain 0366", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0367", "purpose": "reserved deterministic extension domain 0367", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0368", "purpose": "reserved deterministic extension domain 0368", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0369", "purpose": "reserved deterministic extension domain 0369", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0370", "purpose": "reserved deterministic extension domain 0370", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0371", "purpose": "reserved deterministic extension domain 0371", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0372", "purpose": "reserved deterministic extension domain 0372", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0373", "purpose": "reserved deterministic extension domain 0373", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0374", "purpose": "reserved deterministic extension domain 0374", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0375", "purpose": "reserved deterministic extension domain 0375", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0376", "purpose": "reserved deterministic extension domain 0376", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0377", "purpose": "reserved deterministic extension domain 0377", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0378", "purpose": "reserved deterministic extension domain 0378", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0379", "purpose": "reserved deterministic extension domain 0379", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0380", "purpose": "reserved deterministic extension domain 0380", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0381", "purpose": "reserved deterministic extension domain 0381", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0382", "purpose": "reserved deterministic extension domain 0382", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0383", "purpose": "reserved deterministic extension domain 0383", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0384", "purpose": "reserved deterministic extension domain 0384", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0385", "purpose": "reserved deterministic extension domain 0385", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0386", "purpose": "reserved deterministic extension domain 0386", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0387", "purpose": "reserved deterministic extension domain 0387", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0388", "purpose": "reserved deterministic extension domain 0388", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0389", "purpose": "reserved deterministic extension domain 0389", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0390", "purpose": "reserved deterministic extension domain 0390", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0391", "purpose": "reserved deterministic extension domain 0391", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0392", "purpose": "reserved deterministic extension domain 0392", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0393", "purpose": "reserved deterministic extension domain 0393", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0394", "purpose": "reserved deterministic extension domain 0394", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0395", "purpose": "reserved deterministic extension domain 0395", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0396", "purpose": "reserved deterministic extension domain 0396", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0397", "purpose": "reserved deterministic extension domain 0397", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0398", "purpose": "reserved deterministic extension domain 0398", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0399", "purpose": "reserved deterministic extension domain 0399", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0400", "purpose": "reserved deterministic extension domain 0400", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0401", "purpose": "reserved deterministic extension domain 0401", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0402", "purpose": "reserved deterministic extension domain 0402", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0403", "purpose": "reserved deterministic extension domain 0403", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0404", "purpose": "reserved deterministic extension domain 0404", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0405", "purpose": "reserved deterministic extension domain 0405", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0406", "purpose": "reserved deterministic extension domain 0406", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0407", "purpose": "reserved deterministic extension domain 0407", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0408", "purpose": "reserved deterministic extension domain 0408", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0409", "purpose": "reserved deterministic extension domain 0409", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0410", "purpose": "reserved deterministic extension domain 0410", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0411", "purpose": "reserved deterministic extension domain 0411", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0412", "purpose": "reserved deterministic extension domain 0412", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0413", "purpose": "reserved deterministic extension domain 0413", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0414", "purpose": "reserved deterministic extension domain 0414", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0415", "purpose": "reserved deterministic extension domain 0415", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0416", "purpose": "reserved deterministic extension domain 0416", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0417", "purpose": "reserved deterministic extension domain 0417", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0418", "purpose": "reserved deterministic extension domain 0418", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0419", "purpose": "reserved deterministic extension domain 0419", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0420", "purpose": "reserved deterministic extension domain 0420", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0421", "purpose": "reserved deterministic extension domain 0421", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0422", "purpose": "reserved deterministic extension domain 0422", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0423", "purpose": "reserved deterministic extension domain 0423", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0424", "purpose": "reserved deterministic extension domain 0424", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0425", "purpose": "reserved deterministic extension domain 0425", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0426", "purpose": "reserved deterministic extension domain 0426", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0427", "purpose": "reserved deterministic extension domain 0427", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0428", "purpose": "reserved deterministic extension domain 0428", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0429", "purpose": "reserved deterministic extension domain 0429", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0430", "purpose": "reserved deterministic extension domain 0430", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0431", "purpose": "reserved deterministic extension domain 0431", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0432", "purpose": "reserved deterministic extension domain 0432", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0433", "purpose": "reserved deterministic extension domain 0433", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0434", "purpose": "reserved deterministic extension domain 0434", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0435", "purpose": "reserved deterministic extension domain 0435", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0436", "purpose": "reserved deterministic extension domain 0436", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0437", "purpose": "reserved deterministic extension domain 0437", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0438", "purpose": "reserved deterministic extension domain 0438", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0439", "purpose": "reserved deterministic extension domain 0439", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0440", "purpose": "reserved deterministic extension domain 0440", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0441", "purpose": "reserved deterministic extension domain 0441", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0442", "purpose": "reserved deterministic extension domain 0442", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0443", "purpose": "reserved deterministic extension domain 0443", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0444", "purpose": "reserved deterministic extension domain 0444", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0445", "purpose": "reserved deterministic extension domain 0445", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0446", "purpose": "reserved deterministic extension domain 0446", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0447", "purpose": "reserved deterministic extension domain 0447", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0448", "purpose": "reserved deterministic extension domain 0448", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0449", "purpose": "reserved deterministic extension domain 0449", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0450", "purpose": "reserved deterministic extension domain 0450", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0451", "purpose": "reserved deterministic extension domain 0451", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0452", "purpose": "reserved deterministic extension domain 0452", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0453", "purpose": "reserved deterministic extension domain 0453", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0454", "purpose": "reserved deterministic extension domain 0454", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0455", "purpose": "reserved deterministic extension domain 0455", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0456", "purpose": "reserved deterministic extension domain 0456", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0457", "purpose": "reserved deterministic extension domain 0457", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0458", "purpose": "reserved deterministic extension domain 0458", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0459", "purpose": "reserved deterministic extension domain 0459", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0460", "purpose": "reserved deterministic extension domain 0460", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0461", "purpose": "reserved deterministic extension domain 0461", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0462", "purpose": "reserved deterministic extension domain 0462", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0463", "purpose": "reserved deterministic extension domain 0463", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0464", "purpose": "reserved deterministic extension domain 0464", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0465", "purpose": "reserved deterministic extension domain 0465", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0466", "purpose": "reserved deterministic extension domain 0466", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0467", "purpose": "reserved deterministic extension domain 0467", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0468", "purpose": "reserved deterministic extension domain 0468", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0469", "purpose": "reserved deterministic extension domain 0469", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0470", "purpose": "reserved deterministic extension domain 0470", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0471", "purpose": "reserved deterministic extension domain 0471", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0472", "purpose": "reserved deterministic extension domain 0472", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0473", "purpose": "reserved deterministic extension domain 0473", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0474", "purpose": "reserved deterministic extension domain 0474", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0475", "purpose": "reserved deterministic extension domain 0475", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0476", "purpose": "reserved deterministic extension domain 0476", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0477", "purpose": "reserved deterministic extension domain 0477", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0478", "purpose": "reserved deterministic extension domain 0478", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0479", "purpose": "reserved deterministic extension domain 0479", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0480", "purpose": "reserved deterministic extension domain 0480", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0481", "purpose": "reserved deterministic extension domain 0481", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0482", "purpose": "reserved deterministic extension domain 0482", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0483", "purpose": "reserved deterministic extension domain 0483", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0484", "purpose": "reserved deterministic extension domain 0484", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0485", "purpose": "reserved deterministic extension domain 0485", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0486", "purpose": "reserved deterministic extension domain 0486", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0487", "purpose": "reserved deterministic extension domain 0487", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0488", "purpose": "reserved deterministic extension domain 0488", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0489", "purpose": "reserved deterministic extension domain 0489", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0490", "purpose": "reserved deterministic extension domain 0490", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0491", "purpose": "reserved deterministic extension domain 0491", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0492", "purpose": "reserved deterministic extension domain 0492", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0493", "purpose": "reserved deterministic extension domain 0493", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0494", "purpose": "reserved deterministic extension domain 0494", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0495", "purpose": "reserved deterministic extension domain 0495", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0496", "purpose": "reserved deterministic extension domain 0496", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0497", "purpose": "reserved deterministic extension domain 0497", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0498", "purpose": "reserved deterministic extension domain 0498", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0499", "purpose": "reserved deterministic extension domain 0499", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0500", "purpose": "reserved deterministic extension domain 0500", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0501", "purpose": "reserved deterministic extension domain 0501", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0502", "purpose": "reserved deterministic extension domain 0502", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0503", "purpose": "reserved deterministic extension domain 0503", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0504", "purpose": "reserved deterministic extension domain 0504", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0505", "purpose": "reserved deterministic extension domain 0505", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0506", "purpose": "reserved deterministic extension domain 0506", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0507", "purpose": "reserved deterministic extension domain 0507", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0508", "purpose": "reserved deterministic extension domain 0508", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0509", "purpose": "reserved deterministic extension domain 0509", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0510", "purpose": "reserved deterministic extension domain 0510", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0511", "purpose": "reserved deterministic extension domain 0511", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0512", "purpose": "reserved deterministic extension domain 0512", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0513", "purpose": "reserved deterministic extension domain 0513", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0514", "purpose": "reserved deterministic extension domain 0514", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0515", "purpose": "reserved deterministic extension domain 0515", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0516", "purpose": "reserved deterministic extension domain 0516", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0517", "purpose": "reserved deterministic extension domain 0517", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0518", "purpose": "reserved deterministic extension domain 0518", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0519", "purpose": "reserved deterministic extension domain 0519", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0520", "purpose": "reserved deterministic extension domain 0520", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0521", "purpose": "reserved deterministic extension domain 0521", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0522", "purpose": "reserved deterministic extension domain 0522", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0523", "purpose": "reserved deterministic extension domain 0523", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0524", "purpose": "reserved deterministic extension domain 0524", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0525", "purpose": "reserved deterministic extension domain 0525", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0526", "purpose": "reserved deterministic extension domain 0526", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0527", "purpose": "reserved deterministic extension domain 0527", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0528", "purpose": "reserved deterministic extension domain 0528", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0529", "purpose": "reserved deterministic extension domain 0529", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0530", "purpose": "reserved deterministic extension domain 0530", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0531", "purpose": "reserved deterministic extension domain 0531", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0532", "purpose": "reserved deterministic extension domain 0532", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0533", "purpose": "reserved deterministic extension domain 0533", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0534", "purpose": "reserved deterministic extension domain 0534", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0535", "purpose": "reserved deterministic extension domain 0535", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0536", "purpose": "reserved deterministic extension domain 0536", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0537", "purpose": "reserved deterministic extension domain 0537", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0538", "purpose": "reserved deterministic extension domain 0538", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0539", "purpose": "reserved deterministic extension domain 0539", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0540", "purpose": "reserved deterministic extension domain 0540", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0541", "purpose": "reserved deterministic extension domain 0541", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0542", "purpose": "reserved deterministic extension domain 0542", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0543", "purpose": "reserved deterministic extension domain 0543", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0544", "purpose": "reserved deterministic extension domain 0544", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0545", "purpose": "reserved deterministic extension domain 0545", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0546", "purpose": "reserved deterministic extension domain 0546", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0547", "purpose": "reserved deterministic extension domain 0547", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0548", "purpose": "reserved deterministic extension domain 0548", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0549", "purpose": "reserved deterministic extension domain 0549", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0550", "purpose": "reserved deterministic extension domain 0550", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0551", "purpose": "reserved deterministic extension domain 0551", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0552", "purpose": "reserved deterministic extension domain 0552", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0553", "purpose": "reserved deterministic extension domain 0553", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0554", "purpose": "reserved deterministic extension domain 0554", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0555", "purpose": "reserved deterministic extension domain 0555", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0556", "purpose": "reserved deterministic extension domain 0556", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0557", "purpose": "reserved deterministic extension domain 0557", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0558", "purpose": "reserved deterministic extension domain 0558", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0559", "purpose": "reserved deterministic extension domain 0559", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0560", "purpose": "reserved deterministic extension domain 0560", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0561", "purpose": "reserved deterministic extension domain 0561", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0562", "purpose": "reserved deterministic extension domain 0562", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0563", "purpose": "reserved deterministic extension domain 0563", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0564", "purpose": "reserved deterministic extension domain 0564", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0565", "purpose": "reserved deterministic extension domain 0565", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0566", "purpose": "reserved deterministic extension domain 0566", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0567", "purpose": "reserved deterministic extension domain 0567", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0568", "purpose": "reserved deterministic extension domain 0568", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0569", "purpose": "reserved deterministic extension domain 0569", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0570", "purpose": "reserved deterministic extension domain 0570", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0571", "purpose": "reserved deterministic extension domain 0571", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0572", "purpose": "reserved deterministic extension domain 0572", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0573", "purpose": "reserved deterministic extension domain 0573", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0574", "purpose": "reserved deterministic extension domain 0574", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0575", "purpose": "reserved deterministic extension domain 0575", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0576", "purpose": "reserved deterministic extension domain 0576", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0577", "purpose": "reserved deterministic extension domain 0577", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0578", "purpose": "reserved deterministic extension domain 0578", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0579", "purpose": "reserved deterministic extension domain 0579", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0580", "purpose": "reserved deterministic extension domain 0580", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0581", "purpose": "reserved deterministic extension domain 0581", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0582", "purpose": "reserved deterministic extension domain 0582", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0583", "purpose": "reserved deterministic extension domain 0583", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0584", "purpose": "reserved deterministic extension domain 0584", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0585", "purpose": "reserved deterministic extension domain 0585", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0586", "purpose": "reserved deterministic extension domain 0586", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0587", "purpose": "reserved deterministic extension domain 0587", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0588", "purpose": "reserved deterministic extension domain 0588", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0589", "purpose": "reserved deterministic extension domain 0589", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0590", "purpose": "reserved deterministic extension domain 0590", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0591", "purpose": "reserved deterministic extension domain 0591", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0592", "purpose": "reserved deterministic extension domain 0592", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0593", "purpose": "reserved deterministic extension domain 0593", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0594", "purpose": "reserved deterministic extension domain 0594", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0595", "purpose": "reserved deterministic extension domain 0595", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0596", "purpose": "reserved deterministic extension domain 0596", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0597", "purpose": "reserved deterministic extension domain 0597", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0598", "purpose": "reserved deterministic extension domain 0598", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0599", "purpose": "reserved deterministic extension domain 0599", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0600", "purpose": "reserved deterministic extension domain 0600", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0601", "purpose": "reserved deterministic extension domain 0601", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0602", "purpose": "reserved deterministic extension domain 0602", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0603", "purpose": "reserved deterministic extension domain 0603", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0604", "purpose": "reserved deterministic extension domain 0604", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0605", "purpose": "reserved deterministic extension domain 0605", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0606", "purpose": "reserved deterministic extension domain 0606", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0607", "purpose": "reserved deterministic extension domain 0607", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0608", "purpose": "reserved deterministic extension domain 0608", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0609", "purpose": "reserved deterministic extension domain 0609", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0610", "purpose": "reserved deterministic extension domain 0610", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0611", "purpose": "reserved deterministic extension domain 0611", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0612", "purpose": "reserved deterministic extension domain 0612", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0613", "purpose": "reserved deterministic extension domain 0613", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0614", "purpose": "reserved deterministic extension domain 0614", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0615", "purpose": "reserved deterministic extension domain 0615", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0616", "purpose": "reserved deterministic extension domain 0616", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0617", "purpose": "reserved deterministic extension domain 0617", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0618", "purpose": "reserved deterministic extension domain 0618", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0619", "purpose": "reserved deterministic extension domain 0619", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0620", "purpose": "reserved deterministic extension domain 0620", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0621", "purpose": "reserved deterministic extension domain 0621", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0622", "purpose": "reserved deterministic extension domain 0622", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0623", "purpose": "reserved deterministic extension domain 0623", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0624", "purpose": "reserved deterministic extension domain 0624", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0625", "purpose": "reserved deterministic extension domain 0625", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0626", "purpose": "reserved deterministic extension domain 0626", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0627", "purpose": "reserved deterministic extension domain 0627", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0628", "purpose": "reserved deterministic extension domain 0628", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0629", "purpose": "reserved deterministic extension domain 0629", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0630", "purpose": "reserved deterministic extension domain 0630", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0631", "purpose": "reserved deterministic extension domain 0631", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0632", "purpose": "reserved deterministic extension domain 0632", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0633", "purpose": "reserved deterministic extension domain 0633", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0634", "purpose": "reserved deterministic extension domain 0634", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0635", "purpose": "reserved deterministic extension domain 0635", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0636", "purpose": "reserved deterministic extension domain 0636", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0637", "purpose": "reserved deterministic extension domain 0637", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0638", "purpose": "reserved deterministic extension domain 0638", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0639", "purpose": "reserved deterministic extension domain 0639", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0640", "purpose": "reserved deterministic extension domain 0640", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0641", "purpose": "reserved deterministic extension domain 0641", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0642", "purpose": "reserved deterministic extension domain 0642", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0643", "purpose": "reserved deterministic extension domain 0643", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0644", "purpose": "reserved deterministic extension domain 0644", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0645", "purpose": "reserved deterministic extension domain 0645", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0646", "purpose": "reserved deterministic extension domain 0646", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0647", "purpose": "reserved deterministic extension domain 0647", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0648", "purpose": "reserved deterministic extension domain 0648", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0649", "purpose": "reserved deterministic extension domain 0649", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0650", "purpose": "reserved deterministic extension domain 0650", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0651", "purpose": "reserved deterministic extension domain 0651", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0652", "purpose": "reserved deterministic extension domain 0652", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0653", "purpose": "reserved deterministic extension domain 0653", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0654", "purpose": "reserved deterministic extension domain 0654", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0655", "purpose": "reserved deterministic extension domain 0655", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0656", "purpose": "reserved deterministic extension domain 0656", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0657", "purpose": "reserved deterministic extension domain 0657", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0658", "purpose": "reserved deterministic extension domain 0658", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0659", "purpose": "reserved deterministic extension domain 0659", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0660", "purpose": "reserved deterministic extension domain 0660", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0661", "purpose": "reserved deterministic extension domain 0661", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0662", "purpose": "reserved deterministic extension domain 0662", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0663", "purpose": "reserved deterministic extension domain 0663", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0664", "purpose": "reserved deterministic extension domain 0664", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0665", "purpose": "reserved deterministic extension domain 0665", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0666", "purpose": "reserved deterministic extension domain 0666", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0667", "purpose": "reserved deterministic extension domain 0667", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0668", "purpose": "reserved deterministic extension domain 0668", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0669", "purpose": "reserved deterministic extension domain 0669", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0670", "purpose": "reserved deterministic extension domain 0670", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0671", "purpose": "reserved deterministic extension domain 0671", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0672", "purpose": "reserved deterministic extension domain 0672", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0673", "purpose": "reserved deterministic extension domain 0673", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0674", "purpose": "reserved deterministic extension domain 0674", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0675", "purpose": "reserved deterministic extension domain 0675", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0676", "purpose": "reserved deterministic extension domain 0676", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0677", "purpose": "reserved deterministic extension domain 0677", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0678", "purpose": "reserved deterministic extension domain 0678", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0679", "purpose": "reserved deterministic extension domain 0679", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0680", "purpose": "reserved deterministic extension domain 0680", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0681", "purpose": "reserved deterministic extension domain 0681", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0682", "purpose": "reserved deterministic extension domain 0682", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0683", "purpose": "reserved deterministic extension domain 0683", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0684", "purpose": "reserved deterministic extension domain 0684", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0685", "purpose": "reserved deterministic extension domain 0685", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0686", "purpose": "reserved deterministic extension domain 0686", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0687", "purpose": "reserved deterministic extension domain 0687", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0688", "purpose": "reserved deterministic extension domain 0688", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0689", "purpose": "reserved deterministic extension domain 0689", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0690", "purpose": "reserved deterministic extension domain 0690", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0691", "purpose": "reserved deterministic extension domain 0691", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0692", "purpose": "reserved deterministic extension domain 0692", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0693", "purpose": "reserved deterministic extension domain 0693", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0694", "purpose": "reserved deterministic extension domain 0694", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0695", "purpose": "reserved deterministic extension domain 0695", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0696", "purpose": "reserved deterministic extension domain 0696", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0697", "purpose": "reserved deterministic extension domain 0697", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0698", "purpose": "reserved deterministic extension domain 0698", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0699", "purpose": "reserved deterministic extension domain 0699", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0700", "purpose": "reserved deterministic extension domain 0700", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0701", "purpose": "reserved deterministic extension domain 0701", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0702", "purpose": "reserved deterministic extension domain 0702", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0703", "purpose": "reserved deterministic extension domain 0703", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0704", "purpose": "reserved deterministic extension domain 0704", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0705", "purpose": "reserved deterministic extension domain 0705", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0706", "purpose": "reserved deterministic extension domain 0706", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0707", "purpose": "reserved deterministic extension domain 0707", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0708", "purpose": "reserved deterministic extension domain 0708", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0709", "purpose": "reserved deterministic extension domain 0709", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0710", "purpose": "reserved deterministic extension domain 0710", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0711", "purpose": "reserved deterministic extension domain 0711", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0712", "purpose": "reserved deterministic extension domain 0712", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0713", "purpose": "reserved deterministic extension domain 0713", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0714", "purpose": "reserved deterministic extension domain 0714", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0715", "purpose": "reserved deterministic extension domain 0715", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0716", "purpose": "reserved deterministic extension domain 0716", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0717", "purpose": "reserved deterministic extension domain 0717", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0718", "purpose": "reserved deterministic extension domain 0718", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0719", "purpose": "reserved deterministic extension domain 0719", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0720", "purpose": "reserved deterministic extension domain 0720", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0721", "purpose": "reserved deterministic extension domain 0721", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0722", "purpose": "reserved deterministic extension domain 0722", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0723", "purpose": "reserved deterministic extension domain 0723", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0724", "purpose": "reserved deterministic extension domain 0724", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0725", "purpose": "reserved deterministic extension domain 0725", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0726", "purpose": "reserved deterministic extension domain 0726", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0727", "purpose": "reserved deterministic extension domain 0727", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0728", "purpose": "reserved deterministic extension domain 0728", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0729", "purpose": "reserved deterministic extension domain 0729", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0730", "purpose": "reserved deterministic extension domain 0730", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0731", "purpose": "reserved deterministic extension domain 0731", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0732", "purpose": "reserved deterministic extension domain 0732", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0733", "purpose": "reserved deterministic extension domain 0733", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0734", "purpose": "reserved deterministic extension domain 0734", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0735", "purpose": "reserved deterministic extension domain 0735", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0736", "purpose": "reserved deterministic extension domain 0736", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0737", "purpose": "reserved deterministic extension domain 0737", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0738", "purpose": "reserved deterministic extension domain 0738", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0739", "purpose": "reserved deterministic extension domain 0739", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0740", "purpose": "reserved deterministic extension domain 0740", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0741", "purpose": "reserved deterministic extension domain 0741", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0742", "purpose": "reserved deterministic extension domain 0742", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0743", "purpose": "reserved deterministic extension domain 0743", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0744", "purpose": "reserved deterministic extension domain 0744", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0745", "purpose": "reserved deterministic extension domain 0745", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0746", "purpose": "reserved deterministic extension domain 0746", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0747", "purpose": "reserved deterministic extension domain 0747", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0748", "purpose": "reserved deterministic extension domain 0748", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0749", "purpose": "reserved deterministic extension domain 0749", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0750", "purpose": "reserved deterministic extension domain 0750", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0751", "purpose": "reserved deterministic extension domain 0751", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0752", "purpose": "reserved deterministic extension domain 0752", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0753", "purpose": "reserved deterministic extension domain 0753", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0754", "purpose": "reserved deterministic extension domain 0754", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0755", "purpose": "reserved deterministic extension domain 0755", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0756", "purpose": "reserved deterministic extension domain 0756", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0757", "purpose": "reserved deterministic extension domain 0757", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0758", "purpose": "reserved deterministic extension domain 0758", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0759", "purpose": "reserved deterministic extension domain 0759", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0760", "purpose": "reserved deterministic extension domain 0760", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0761", "purpose": "reserved deterministic extension domain 0761", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0762", "purpose": "reserved deterministic extension domain 0762", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0763", "purpose": "reserved deterministic extension domain 0763", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0764", "purpose": "reserved deterministic extension domain 0764", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0765", "purpose": "reserved deterministic extension domain 0765", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0766", "purpose": "reserved deterministic extension domain 0766", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0767", "purpose": "reserved deterministic extension domain 0767", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0768", "purpose": "reserved deterministic extension domain 0768", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0769", "purpose": "reserved deterministic extension domain 0769", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0770", "purpose": "reserved deterministic extension domain 0770", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0771", "purpose": "reserved deterministic extension domain 0771", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0772", "purpose": "reserved deterministic extension domain 0772", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0773", "purpose": "reserved deterministic extension domain 0773", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0774", "purpose": "reserved deterministic extension domain 0774", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0775", "purpose": "reserved deterministic extension domain 0775", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0776", "purpose": "reserved deterministic extension domain 0776", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0777", "purpose": "reserved deterministic extension domain 0777", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0778", "purpose": "reserved deterministic extension domain 0778", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0779", "purpose": "reserved deterministic extension domain 0779", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0780", "purpose": "reserved deterministic extension domain 0780", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0781", "purpose": "reserved deterministic extension domain 0781", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0782", "purpose": "reserved deterministic extension domain 0782", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0783", "purpose": "reserved deterministic extension domain 0783", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0784", "purpose": "reserved deterministic extension domain 0784", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0785", "purpose": "reserved deterministic extension domain 0785", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0786", "purpose": "reserved deterministic extension domain 0786", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0787", "purpose": "reserved deterministic extension domain 0787", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0788", "purpose": "reserved deterministic extension domain 0788", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0789", "purpose": "reserved deterministic extension domain 0789", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0790", "purpose": "reserved deterministic extension domain 0790", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0791", "purpose": "reserved deterministic extension domain 0791", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0792", "purpose": "reserved deterministic extension domain 0792", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0793", "purpose": "reserved deterministic extension domain 0793", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0794", "purpose": "reserved deterministic extension domain 0794", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0795", "purpose": "reserved deterministic extension domain 0795", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0796", "purpose": "reserved deterministic extension domain 0796", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0797", "purpose": "reserved deterministic extension domain 0797", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0798", "purpose": "reserved deterministic extension domain 0798", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0799", "purpose": "reserved deterministic extension domain 0799", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0800", "purpose": "reserved deterministic extension domain 0800", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0801", "purpose": "reserved deterministic extension domain 0801", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0802", "purpose": "reserved deterministic extension domain 0802", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0803", "purpose": "reserved deterministic extension domain 0803", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0804", "purpose": "reserved deterministic extension domain 0804", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0805", "purpose": "reserved deterministic extension domain 0805", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0806", "purpose": "reserved deterministic extension domain 0806", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0807", "purpose": "reserved deterministic extension domain 0807", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0808", "purpose": "reserved deterministic extension domain 0808", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0809", "purpose": "reserved deterministic extension domain 0809", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0810", "purpose": "reserved deterministic extension domain 0810", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0811", "purpose": "reserved deterministic extension domain 0811", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0812", "purpose": "reserved deterministic extension domain 0812", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0813", "purpose": "reserved deterministic extension domain 0813", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0814", "purpose": "reserved deterministic extension domain 0814", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0815", "purpose": "reserved deterministic extension domain 0815", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0816", "purpose": "reserved deterministic extension domain 0816", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0817", "purpose": "reserved deterministic extension domain 0817", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0818", "purpose": "reserved deterministic extension domain 0818", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0819", "purpose": "reserved deterministic extension domain 0819", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0820", "purpose": "reserved deterministic extension domain 0820", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0821", "purpose": "reserved deterministic extension domain 0821", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0822", "purpose": "reserved deterministic extension domain 0822", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0823", "purpose": "reserved deterministic extension domain 0823", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0824", "purpose": "reserved deterministic extension domain 0824", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0825", "purpose": "reserved deterministic extension domain 0825", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0826", "purpose": "reserved deterministic extension domain 0826", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0827", "purpose": "reserved deterministic extension domain 0827", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0828", "purpose": "reserved deterministic extension domain 0828", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0829", "purpose": "reserved deterministic extension domain 0829", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0830", "purpose": "reserved deterministic extension domain 0830", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0831", "purpose": "reserved deterministic extension domain 0831", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0832", "purpose": "reserved deterministic extension domain 0832", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0833", "purpose": "reserved deterministic extension domain 0833", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0834", "purpose": "reserved deterministic extension domain 0834", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0835", "purpose": "reserved deterministic extension domain 0835", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0836", "purpose": "reserved deterministic extension domain 0836", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0837", "purpose": "reserved deterministic extension domain 0837", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0838", "purpose": "reserved deterministic extension domain 0838", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0839", "purpose": "reserved deterministic extension domain 0839", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0840", "purpose": "reserved deterministic extension domain 0840", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0841", "purpose": "reserved deterministic extension domain 0841", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0842", "purpose": "reserved deterministic extension domain 0842", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0843", "purpose": "reserved deterministic extension domain 0843", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0844", "purpose": "reserved deterministic extension domain 0844", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0845", "purpose": "reserved deterministic extension domain 0845", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0846", "purpose": "reserved deterministic extension domain 0846", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0847", "purpose": "reserved deterministic extension domain 0847", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0848", "purpose": "reserved deterministic extension domain 0848", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0849", "purpose": "reserved deterministic extension domain 0849", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0850", "purpose": "reserved deterministic extension domain 0850", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0851", "purpose": "reserved deterministic extension domain 0851", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0852", "purpose": "reserved deterministic extension domain 0852", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0853", "purpose": "reserved deterministic extension domain 0853", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0854", "purpose": "reserved deterministic extension domain 0854", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0855", "purpose": "reserved deterministic extension domain 0855", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0856", "purpose": "reserved deterministic extension domain 0856", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0857", "purpose": "reserved deterministic extension domain 0857", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0858", "purpose": "reserved deterministic extension domain 0858", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0859", "purpose": "reserved deterministic extension domain 0859", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0860", "purpose": "reserved deterministic extension domain 0860", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0861", "purpose": "reserved deterministic extension domain 0861", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0862", "purpose": "reserved deterministic extension domain 0862", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0863", "purpose": "reserved deterministic extension domain 0863", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0864", "purpose": "reserved deterministic extension domain 0864", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0865", "purpose": "reserved deterministic extension domain 0865", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0866", "purpose": "reserved deterministic extension domain 0866", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0867", "purpose": "reserved deterministic extension domain 0867", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0868", "purpose": "reserved deterministic extension domain 0868", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0869", "purpose": "reserved deterministic extension domain 0869", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0870", "purpose": "reserved deterministic extension domain 0870", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0871", "purpose": "reserved deterministic extension domain 0871", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0872", "purpose": "reserved deterministic extension domain 0872", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0873", "purpose": "reserved deterministic extension domain 0873", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0874", "purpose": "reserved deterministic extension domain 0874", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0875", "purpose": "reserved deterministic extension domain 0875", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0876", "purpose": "reserved deterministic extension domain 0876", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0877", "purpose": "reserved deterministic extension domain 0877", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0878", "purpose": "reserved deterministic extension domain 0878", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0879", "purpose": "reserved deterministic extension domain 0879", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0880", "purpose": "reserved deterministic extension domain 0880", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0881", "purpose": "reserved deterministic extension domain 0881", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0882", "purpose": "reserved deterministic extension domain 0882", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0883", "purpose": "reserved deterministic extension domain 0883", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0884", "purpose": "reserved deterministic extension domain 0884", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0885", "purpose": "reserved deterministic extension domain 0885", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0886", "purpose": "reserved deterministic extension domain 0886", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0887", "purpose": "reserved deterministic extension domain 0887", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0888", "purpose": "reserved deterministic extension domain 0888", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0889", "purpose": "reserved deterministic extension domain 0889", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0890", "purpose": "reserved deterministic extension domain 0890", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0891", "purpose": "reserved deterministic extension domain 0891", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0892", "purpose": "reserved deterministic extension domain 0892", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0893", "purpose": "reserved deterministic extension domain 0893", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0894", "purpose": "reserved deterministic extension domain 0894", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0895", "purpose": "reserved deterministic extension domain 0895", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0896", "purpose": "reserved deterministic extension domain 0896", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0897", "purpose": "reserved deterministic extension domain 0897", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0898", "purpose": "reserved deterministic extension domain 0898", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0899", "purpose": "reserved deterministic extension domain 0899", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0900", "purpose": "reserved deterministic extension domain 0900", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
        json!({"domain": "PQ-CROSS-MARGIN-LENDING-RESERVED-DOMAIN-0901", "purpose": "reserved deterministic extension domain 0901", "suite": PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_LENDING_INTENT_RUNTIME_HASH_SUITE}),
    ]
}
