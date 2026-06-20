use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateSmartContractRollupOrderbookResult<T> = Result<T, String>;

pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_PROTOCOL_VERSION: &str =
    "nebula-private-smart-contract-rollup-orderbook-v1";
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_SECURITY_MODEL: &str =
    "devnet-production-shaped-records-not-real-cryptography";
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_SEALED_ORDER_SCHEME: &str =
    "ml-kem-1024-threshold-sealed-order-v1";
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_CONFIDENTIAL_PAIR_SCHEME: &str =
    "confidential-token-pair-commitment-v1";
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_AUCTION_SCHEME: &str =
    "frequent-batch-auction-private-contract-v1";
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_SOLVER_COMMITMENT_SCHEME: &str =
    "solver-commit-reveal-pq-attested-v1";
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_ZK_RECEIPT_SCHEME: &str =
    "zk-contract-execution-receipt-rollup-v1";
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_REBATE_SCHEME: &str =
    "low-fee-maker-rebate-note-v1";
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_CANCELLATION_NULLIFIER_SCHEME: &str =
    "sealed-order-cancellation-nullifier-v1";
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_CHALLENGE_SCHEME: &str =
    "fraud-validity-liveness-challenge-v1";
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEVNET_HEIGHT: u64 = 1_280;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEVNET_BASE_ASSET_ID: &str = "dxmr";
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEVNET_QUOTE_ASSET_ID: &str = "dusd";
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_EPOCH_BLOCKS: u64 = 8;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_COMMIT_TTL_BLOCKS: u64 = 16;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_REVEAL_TTL_BLOCKS: u64 = 4;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 32;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_CHALLENGE_TTL_BLOCKS: u64 = 240;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_MAX_BATCH_ORDERS: usize = 512;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_MAX_CALLS_PER_RECEIPT: usize = 64;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_MAX_PAIR_FEE_BPS: u64 = 35;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_LOW_FEE_LANE_BPS: u64 = 7;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_MAKER_REBATE_BPS: u64 = 2_500;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_SOLVER_BOND_UNITS: u64 = 50_000_000_000;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_SLASH_BPS: u64 = 2_000;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_BPS: u64 = 10_000;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_PAIRS: usize = 16_384;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_ORDERBOOKS: usize = 16_384;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_ORDERS: usize = 524_288;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_AUCTIONS: usize = 131_072;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_SOLVER_COMMITMENTS: usize = 262_144;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_RECEIPTS: usize = 262_144;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_REBATES: usize = 262_144;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_CANCELLATIONS: usize = 262_144;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_CHALLENGES: usize = 131_072;
pub const PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_EVENTS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractLaneKind {
    LowFee,
    PrivateDex,
    TokenMint,
    TokenBurn,
    Lending,
    Derivatives,
    Governance,
    OracleUpdate,
    MoneroExit,
    EmergencyUnwind,
}

impl ContractLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::PrivateDex => "private_dex",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::Lending => "lending",
            Self::Derivatives => "derivatives",
            Self::Governance => "governance",
            Self::OracleUpdate => "oracle_update",
            Self::MoneroExit => "monero_exit",
            Self::EmergencyUnwind => "emergency_unwind",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::EmergencyUnwind => 0,
            Self::MoneroExit => 1,
            Self::OracleUpdate => 2,
            Self::Derivatives => 3,
            Self::Lending => 4,
            Self::PrivateDex => 5,
            Self::TokenMint | Self::TokenBurn => 6,
            Self::Governance => 7,
            Self::LowFee => 8,
        }
    }

    pub fn maker_rebate_weight_bps(self) -> u64 {
        match self {
            Self::LowFee => 10_000,
            Self::PrivateDex => 8_500,
            Self::TokenMint | Self::TokenBurn => 7_250,
            Self::Lending => 6_500,
            Self::Derivatives => 5_500,
            Self::Governance | Self::OracleUpdate => 4_000,
            Self::MoneroExit => 8_000,
            Self::EmergencyUnwind => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderSide {
    Buy,
    Sell,
    Mint,
    Burn,
    Call,
}

impl OrderSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Buy => "buy",
            Self::Sell => "sell",
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::Call => "call",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedOrderStatus {
    Sealed,
    Queued,
    Matched,
    Executed,
    Rebated,
    Cancelled,
    Expired,
    Challenged,
}

impl SealedOrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Queued => "queued",
            Self::Matched => "matched",
            Self::Executed => "executed",
            Self::Rebated => "rebated",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Sealed | Self::Queued | Self::Matched)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Collecting,
    CommitOpen,
    RevealOpen,
    Solving,
    Settling,
    Settled,
    Disputed,
    Cancelled,
    Expired,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::CommitOpen => "commit_open",
            Self::RevealOpen => "reveal_open",
            Self::Solving => "solving",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Collecting | Self::CommitOpen)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolverCommitmentStatus {
    Committed,
    Revealed,
    Selected,
    Executed,
    Slashed,
    Expired,
}

impl SolverCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Selected => "selected",
            Self::Executed => "executed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Submitted,
    Verified,
    Finalized,
    Rejected,
    Challenged,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Finalized => "finalized",
            Self::Rejected => "rejected",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    InvalidSolverReveal,
    InvalidExecutionReceipt,
    MissingDataAvailability,
    RebateWithholding,
    CancellationDoubleSpend,
    PairPolicyViolation,
    SequencerCensorship,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidSolverReveal => "invalid_solver_reveal",
            Self::InvalidExecutionReceipt => "invalid_execution_receipt",
            Self::MissingDataAvailability => "missing_data_availability",
            Self::RebateWithholding => "rebate_withholding",
            Self::CancellationDoubleSpend => "cancellation_double_spend",
            Self::PairPolicyViolation => "pair_policy_violation",
            Self::SequencerCensorship => "sequencer_censorship",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Responded,
    Sustained,
    Dismissed,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Responded => "responded",
            Self::Sustained => "sustained",
            Self::Dismissed => "dismissed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub sealed_order_scheme: String,
    pub confidential_pair_scheme: String,
    pub auction_scheme: String,
    pub solver_commitment_scheme: String,
    pub zk_receipt_scheme: String,
    pub rebate_scheme: String,
    pub cancellation_nullifier_scheme: String,
    pub challenge_scheme: String,
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub commit_ttl_blocks: u64,
    pub reveal_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub challenge_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_batch_orders: usize,
    pub max_calls_per_receipt: usize,
    pub max_pair_fee_bps: u64,
    pub low_fee_lane_bps: u64,
    pub maker_rebate_bps: u64,
    pub solver_bond_units: u64,
    pub slash_bps: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_SCHEMA_VERSION,
            hash_suite: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_HASH_SUITE.to_string(),
            sealed_order_scheme: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_SEALED_ORDER_SCHEME
                .to_string(),
            confidential_pair_scheme:
                PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_CONFIDENTIAL_PAIR_SCHEME.to_string(),
            auction_scheme: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_AUCTION_SCHEME.to_string(),
            solver_commitment_scheme:
                PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_SOLVER_COMMITMENT_SCHEME.to_string(),
            zk_receipt_scheme: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_ZK_RECEIPT_SCHEME
                .to_string(),
            rebate_scheme: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_REBATE_SCHEME.to_string(),
            cancellation_nullifier_scheme:
                PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_CANCELLATION_NULLIFIER_SCHEME.to_string(),
            challenge_scheme: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_CHALLENGE_SCHEME.to_string(),
            fee_asset_id: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEVNET_FEE_ASSET_ID.to_string(),
            epoch_blocks: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_EPOCH_BLOCKS,
            commit_ttl_blocks: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_COMMIT_TTL_BLOCKS,
            reveal_ttl_blocks: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_REVEAL_TTL_BLOCKS,
            settlement_ttl_blocks:
                PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            challenge_ttl_blocks:
                PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_CHALLENGE_TTL_BLOCKS,
            min_privacy_set_size:
                PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_batch_orders: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_MAX_BATCH_ORDERS,
            max_calls_per_receipt:
                PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_MAX_CALLS_PER_RECEIPT,
            max_pair_fee_bps: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_MAX_PAIR_FEE_BPS,
            low_fee_lane_bps: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_LOW_FEE_LANE_BPS,
            maker_rebate_bps: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_MAKER_REBATE_BPS,
            solver_bond_units: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_SOLVER_BOND_UNITS,
            slash_bps: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_SLASH_BPS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> PrivateSmartContractRollupOrderbookResult<()> {
        if self.chain_id != CHAIN_ID {
            return Err("config chain_id does not match crate CHAIN_ID".to_string());
        }
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("sealed_order_scheme", &self.sealed_order_scheme)?;
        require_non_empty("confidential_pair_scheme", &self.confidential_pair_scheme)?;
        require_non_empty("auction_scheme", &self.auction_scheme)?;
        require_non_empty("solver_commitment_scheme", &self.solver_commitment_scheme)?;
        require_non_empty("zk_receipt_scheme", &self.zk_receipt_scheme)?;
        require_non_empty("rebate_scheme", &self.rebate_scheme)?;
        require_non_empty(
            "cancellation_nullifier_scheme",
            &self.cancellation_nullifier_scheme,
        )?;
        require_non_empty("challenge_scheme", &self.challenge_scheme)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_zero("epoch_blocks", self.epoch_blocks)?;
        require_non_zero("commit_ttl_blocks", self.commit_ttl_blocks)?;
        require_non_zero("reveal_ttl_blocks", self.reveal_ttl_blocks)?;
        require_non_zero("settlement_ttl_blocks", self.settlement_ttl_blocks)?;
        require_non_zero("challenge_ttl_blocks", self.challenge_ttl_blocks)?;
        require_non_zero("min_privacy_set_size", self.min_privacy_set_size)?;
        if self.min_pq_security_bits < 128 {
            return Err("min_pq_security_bits must be at least 128".to_string());
        }
        if self.max_batch_orders == 0 {
            return Err("max_batch_orders must be non-zero".to_string());
        }
        if self.max_calls_per_receipt == 0 {
            return Err("max_calls_per_receipt must be non-zero".to_string());
        }
        if self.max_pair_fee_bps > PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_BPS {
            return Err("max_pair_fee_bps exceeds basis point denominator".to_string());
        }
        if self.low_fee_lane_bps > self.max_pair_fee_bps {
            return Err("low_fee_lane_bps exceeds max_pair_fee_bps".to_string());
        }
        if self.maker_rebate_bps > PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_BPS {
            return Err("maker_rebate_bps exceeds basis point denominator".to_string());
        }
        if self.slash_bps > PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_BPS {
            return Err("slash_bps exceeds basis point denominator".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "sealed_order_scheme": self.sealed_order_scheme,
            "confidential_pair_scheme": self.confidential_pair_scheme,
            "auction_scheme": self.auction_scheme,
            "solver_commitment_scheme": self.solver_commitment_scheme,
            "zk_receipt_scheme": self.zk_receipt_scheme,
            "rebate_scheme": self.rebate_scheme,
            "cancellation_nullifier_scheme": self.cancellation_nullifier_scheme,
            "challenge_scheme": self.challenge_scheme,
            "fee_asset_id": self.fee_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "commit_ttl_blocks": self.commit_ttl_blocks,
            "reveal_ttl_blocks": self.reveal_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "challenge_ttl_blocks": self.challenge_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_batch_orders": self.max_batch_orders,
            "max_calls_per_receipt": self.max_calls_per_receipt,
            "max_pair_fee_bps": self.max_pair_fee_bps,
            "low_fee_lane_bps": self.low_fee_lane_bps,
            "maker_rebate_bps": self.maker_rebate_bps,
            "solver_bond_units": self.solver_bond_units,
            "slash_bps": self.slash_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialTokenPair {
    pub pair_id: String,
    pub base_asset_commitment: String,
    pub quote_asset_commitment: String,
    pub pair_policy_root: String,
    pub oracle_root: String,
    pub fee_bps: u64,
    pub min_lot_size_units: u64,
    pub tick_size_units: u64,
    pub privacy_set_size: u64,
    pub lane: ContractLaneKind,
    pub enabled: bool,
}

impl ConfidentialTokenPair {
    pub fn new(
        base_asset_commitment: &str,
        quote_asset_commitment: &str,
        pair_policy_root: &str,
        oracle_root: &str,
        lane: ContractLaneKind,
        fee_bps: u64,
    ) -> Self {
        let pair_id = domain_hash(
            "PRIVATE-SC-ROLLUP-ORDERBOOK-PAIR-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(base_asset_commitment),
                HashPart::Str(quote_asset_commitment),
                HashPart::Str(pair_policy_root),
                HashPart::Str(oracle_root),
                HashPart::Str(lane.as_str()),
            ],
            32,
        );
        Self {
            pair_id,
            base_asset_commitment: base_asset_commitment.to_string(),
            quote_asset_commitment: quote_asset_commitment.to_string(),
            pair_policy_root: pair_policy_root.to_string(),
            oracle_root: oracle_root.to_string(),
            fee_bps,
            min_lot_size_units: 1,
            tick_size_units: 1,
            privacy_set_size: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEFAULT_MIN_PRIVACY_SET_SIZE,
            lane,
            enabled: true,
        }
    }

    pub fn validate(&self, config: &Config) -> PrivateSmartContractRollupOrderbookResult<()> {
        require_hash_like("pair_id", &self.pair_id)?;
        require_hash_like("base_asset_commitment", &self.base_asset_commitment)?;
        require_hash_like("quote_asset_commitment", &self.quote_asset_commitment)?;
        require_hash_like("pair_policy_root", &self.pair_policy_root)?;
        require_hash_like("oracle_root", &self.oracle_root)?;
        if self.base_asset_commitment == self.quote_asset_commitment {
            return Err(format!(
                "pair {} has identical asset commitments",
                self.pair_id
            ));
        }
        if self.fee_bps > config.max_pair_fee_bps {
            return Err(format!("pair {} fee exceeds configured cap", self.pair_id));
        }
        require_non_zero("min_lot_size_units", self.min_lot_size_units)?;
        require_non_zero("tick_size_units", self.tick_size_units)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!("pair {} privacy set too small", self.pair_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pair_id": self.pair_id,
            "base_asset_commitment": self.base_asset_commitment,
            "quote_asset_commitment": self.quote_asset_commitment,
            "pair_policy_root": self.pair_policy_root,
            "oracle_root": self.oracle_root,
            "fee_bps": self.fee_bps,
            "min_lot_size_units": self.min_lot_size_units,
            "tick_size_units": self.tick_size_units,
            "privacy_set_size": self.privacy_set_size,
            "lane": self.lane.as_str(),
            "enabled": self.enabled,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollupOrderbook {
    pub orderbook_id: String,
    pub pair_id: String,
    pub contract_root: String,
    pub state_commitment_root: String,
    pub maker_rebate_pool_root: String,
    pub fee_lane_bps: u64,
    pub opened_at_height: u64,
    pub last_cleared_height: u64,
    pub active: bool,
}

impl RollupOrderbook {
    pub fn new(
        pair_id: &str,
        contract_root: &str,
        state_commitment_root: &str,
        maker_rebate_pool_root: &str,
        opened_at_height: u64,
        fee_lane_bps: u64,
    ) -> Self {
        let orderbook_id = domain_hash(
            "PRIVATE-SC-ROLLUP-ORDERBOOK-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(pair_id),
                HashPart::Str(contract_root),
                HashPart::Str(state_commitment_root),
                HashPart::Str(maker_rebate_pool_root),
                HashPart::Int(opened_at_height as i128),
            ],
            32,
        );
        Self {
            orderbook_id,
            pair_id: pair_id.to_string(),
            contract_root: contract_root.to_string(),
            state_commitment_root: state_commitment_root.to_string(),
            maker_rebate_pool_root: maker_rebate_pool_root.to_string(),
            fee_lane_bps,
            opened_at_height,
            last_cleared_height: opened_at_height,
            active: true,
        }
    }

    pub fn validate(&self, config: &Config) -> PrivateSmartContractRollupOrderbookResult<()> {
        require_hash_like("orderbook_id", &self.orderbook_id)?;
        require_hash_like("pair_id", &self.pair_id)?;
        require_hash_like("contract_root", &self.contract_root)?;
        require_hash_like("state_commitment_root", &self.state_commitment_root)?;
        require_hash_like("maker_rebate_pool_root", &self.maker_rebate_pool_root)?;
        if self.fee_lane_bps > config.max_pair_fee_bps {
            return Err(format!(
                "orderbook {} fee lane exceeds configured cap",
                self.orderbook_id
            ));
        }
        if self.last_cleared_height < self.opened_at_height {
            return Err(format!(
                "orderbook {} last_cleared_height precedes open",
                self.orderbook_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "orderbook_id": self.orderbook_id,
            "pair_id": self.pair_id,
            "contract_root": self.contract_root,
            "state_commitment_root": self.state_commitment_root,
            "maker_rebate_pool_root": self.maker_rebate_pool_root,
            "fee_lane_bps": self.fee_lane_bps,
            "opened_at_height": self.opened_at_height,
            "last_cleared_height": self.last_cleared_height,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedOrder {
    pub order_id: String,
    pub orderbook_id: String,
    pub pair_id: String,
    pub owner_commitment: String,
    pub side: OrderSide,
    pub sealed_payload_root: String,
    pub price_commitment: String,
    pub quantity_commitment: String,
    pub contract_call_root: String,
    pub witness_commitment_root: String,
    pub max_fee_commitment: String,
    pub salt_commitment: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: SealedOrderStatus,
    pub maker: bool,
}

impl SealedOrder {
    pub fn new(
        orderbook_id: &str,
        pair_id: &str,
        owner_commitment: &str,
        side: OrderSide,
        sealed_payload_root: &str,
        price_commitment: &str,
        quantity_commitment: &str,
        contract_call_root: &str,
        witness_commitment_root: &str,
        max_fee_commitment: &str,
        salt_commitment: &str,
        submitted_at_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let order_id = domain_hash(
            "PRIVATE-SC-ROLLUP-ORDERBOOK-SEALED-ORDER-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(orderbook_id),
                HashPart::Str(pair_id),
                HashPart::Str(owner_commitment),
                HashPart::Str(side.as_str()),
                HashPart::Str(sealed_payload_root),
                HashPart::Str(price_commitment),
                HashPart::Str(quantity_commitment),
                HashPart::Str(contract_call_root),
                HashPart::Str(witness_commitment_root),
                HashPart::Str(max_fee_commitment),
                HashPart::Str(salt_commitment),
                HashPart::Int(submitted_at_height as i128),
                HashPart::Int(expires_at_height as i128),
            ],
            32,
        );
        Self {
            order_id,
            orderbook_id: orderbook_id.to_string(),
            pair_id: pair_id.to_string(),
            owner_commitment: owner_commitment.to_string(),
            side,
            sealed_payload_root: sealed_payload_root.to_string(),
            price_commitment: price_commitment.to_string(),
            quantity_commitment: quantity_commitment.to_string(),
            contract_call_root: contract_call_root.to_string(),
            witness_commitment_root: witness_commitment_root.to_string(),
            max_fee_commitment: max_fee_commitment.to_string(),
            salt_commitment: salt_commitment.to_string(),
            submitted_at_height,
            expires_at_height,
            status: SealedOrderStatus::Sealed,
            maker: true,
        }
    }

    pub fn validate(&self) -> PrivateSmartContractRollupOrderbookResult<()> {
        require_hash_like("order_id", &self.order_id)?;
        require_hash_like("orderbook_id", &self.orderbook_id)?;
        require_hash_like("pair_id", &self.pair_id)?;
        require_hash_like("owner_commitment", &self.owner_commitment)?;
        require_hash_like("sealed_payload_root", &self.sealed_payload_root)?;
        require_hash_like("price_commitment", &self.price_commitment)?;
        require_hash_like("quantity_commitment", &self.quantity_commitment)?;
        require_hash_like("contract_call_root", &self.contract_call_root)?;
        require_hash_like("witness_commitment_root", &self.witness_commitment_root)?;
        require_hash_like("max_fee_commitment", &self.max_fee_commitment)?;
        require_hash_like("salt_commitment", &self.salt_commitment)?;
        if self.expires_at_height <= self.submitted_at_height {
            return Err(format!(
                "order {} expires before it can be included",
                self.order_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "order_id": self.order_id,
            "orderbook_id": self.orderbook_id,
            "pair_id": self.pair_id,
            "owner_commitment": self.owner_commitment,
            "side": self.side.as_str(),
            "sealed_payload_root": self.sealed_payload_root,
            "price_commitment": self.price_commitment,
            "quantity_commitment": self.quantity_commitment,
            "contract_call_root": self.contract_call_root,
            "witness_commitment_root": self.witness_commitment_root,
            "max_fee_commitment": self.max_fee_commitment,
            "salt_commitment": self.salt_commitment,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "maker": self.maker,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchAuction {
    pub auction_id: String,
    pub orderbook_id: String,
    pub pair_id: String,
    pub lane: ContractLaneKind,
    pub order_root: String,
    pub opening_state_root: String,
    pub data_availability_root: String,
    pub min_privacy_set_size: u64,
    pub opened_at_height: u64,
    pub commit_deadline_height: u64,
    pub reveal_deadline_height: u64,
    pub settlement_deadline_height: u64,
    pub status: AuctionStatus,
}

impl BatchAuction {
    pub fn new(
        orderbook_id: &str,
        pair_id: &str,
        lane: ContractLaneKind,
        order_root: &str,
        opening_state_root: &str,
        data_availability_root: &str,
        opened_at_height: u64,
        config: &Config,
    ) -> Self {
        let commit_deadline_height = opened_at_height.saturating_add(config.commit_ttl_blocks);
        let reveal_deadline_height =
            commit_deadline_height.saturating_add(config.reveal_ttl_blocks);
        let settlement_deadline_height =
            reveal_deadline_height.saturating_add(config.settlement_ttl_blocks);
        let auction_id = domain_hash(
            "PRIVATE-SC-ROLLUP-ORDERBOOK-AUCTION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(orderbook_id),
                HashPart::Str(pair_id),
                HashPart::Str(lane.as_str()),
                HashPart::Str(order_root),
                HashPart::Str(opening_state_root),
                HashPart::Str(data_availability_root),
                HashPart::Int(opened_at_height as i128),
            ],
            32,
        );
        Self {
            auction_id,
            orderbook_id: orderbook_id.to_string(),
            pair_id: pair_id.to_string(),
            lane,
            order_root: order_root.to_string(),
            opening_state_root: opening_state_root.to_string(),
            data_availability_root: data_availability_root.to_string(),
            min_privacy_set_size: config.min_privacy_set_size,
            opened_at_height,
            commit_deadline_height,
            reveal_deadline_height,
            settlement_deadline_height,
            status: AuctionStatus::CommitOpen,
        }
    }

    pub fn validate(&self) -> PrivateSmartContractRollupOrderbookResult<()> {
        require_hash_like("auction_id", &self.auction_id)?;
        require_hash_like("orderbook_id", &self.orderbook_id)?;
        require_hash_like("pair_id", &self.pair_id)?;
        require_hash_like("order_root", &self.order_root)?;
        require_hash_like("opening_state_root", &self.opening_state_root)?;
        require_hash_like("data_availability_root", &self.data_availability_root)?;
        require_non_zero("min_privacy_set_size", self.min_privacy_set_size)?;
        if self.commit_deadline_height <= self.opened_at_height {
            return Err(format!(
                "auction {} has invalid commit deadline",
                self.auction_id
            ));
        }
        if self.reveal_deadline_height <= self.commit_deadline_height {
            return Err(format!(
                "auction {} has invalid reveal deadline",
                self.auction_id
            ));
        }
        if self.settlement_deadline_height <= self.reveal_deadline_height {
            return Err(format!(
                "auction {} has invalid settlement deadline",
                self.auction_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "orderbook_id": self.orderbook_id,
            "pair_id": self.pair_id,
            "lane": self.lane.as_str(),
            "order_root": self.order_root,
            "opening_state_root": self.opening_state_root,
            "data_availability_root": self.data_availability_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "commit_deadline_height": self.commit_deadline_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverCommitment {
    pub commitment_id: String,
    pub auction_id: String,
    pub solver_commitment: String,
    pub solution_commitment_root: String,
    pub execution_plan_root: String,
    pub surplus_commitment_root: String,
    pub bond_commitment_root: String,
    pub pq_attestation_root: String,
    pub committed_at_height: u64,
    pub reveal_deadline_height: u64,
    pub status: SolverCommitmentStatus,
}

impl SolverCommitment {
    pub fn new(
        auction_id: &str,
        solver_commitment: &str,
        solution_commitment_root: &str,
        execution_plan_root: &str,
        surplus_commitment_root: &str,
        bond_commitment_root: &str,
        pq_attestation_root: &str,
        committed_at_height: u64,
        reveal_deadline_height: u64,
    ) -> Self {
        let commitment_id = domain_hash(
            "PRIVATE-SC-ROLLUP-ORDERBOOK-SOLVER-COMMITMENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(auction_id),
                HashPart::Str(solver_commitment),
                HashPart::Str(solution_commitment_root),
                HashPart::Str(execution_plan_root),
                HashPart::Str(surplus_commitment_root),
                HashPart::Str(bond_commitment_root),
                HashPart::Str(pq_attestation_root),
                HashPart::Int(committed_at_height as i128),
            ],
            32,
        );
        Self {
            commitment_id,
            auction_id: auction_id.to_string(),
            solver_commitment: solver_commitment.to_string(),
            solution_commitment_root: solution_commitment_root.to_string(),
            execution_plan_root: execution_plan_root.to_string(),
            surplus_commitment_root: surplus_commitment_root.to_string(),
            bond_commitment_root: bond_commitment_root.to_string(),
            pq_attestation_root: pq_attestation_root.to_string(),
            committed_at_height,
            reveal_deadline_height,
            status: SolverCommitmentStatus::Committed,
        }
    }

    pub fn validate(&self) -> PrivateSmartContractRollupOrderbookResult<()> {
        require_hash_like("commitment_id", &self.commitment_id)?;
        require_hash_like("auction_id", &self.auction_id)?;
        require_hash_like("solver_commitment", &self.solver_commitment)?;
        require_hash_like("solution_commitment_root", &self.solution_commitment_root)?;
        require_hash_like("execution_plan_root", &self.execution_plan_root)?;
        require_hash_like("surplus_commitment_root", &self.surplus_commitment_root)?;
        require_hash_like("bond_commitment_root", &self.bond_commitment_root)?;
        require_hash_like("pq_attestation_root", &self.pq_attestation_root)?;
        if self.reveal_deadline_height <= self.committed_at_height {
            return Err(format!(
                "solver commitment {} has invalid reveal deadline",
                self.commitment_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "auction_id": self.auction_id,
            "solver_commitment": self.solver_commitment,
            "solution_commitment_root": self.solution_commitment_root,
            "execution_plan_root": self.execution_plan_root,
            "surplus_commitment_root": self.surplus_commitment_root,
            "bond_commitment_root": self.bond_commitment_root,
            "pq_attestation_root": self.pq_attestation_root,
            "committed_at_height": self.committed_at_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkExecutionReceipt {
    pub receipt_id: String,
    pub auction_id: String,
    pub commitment_id: String,
    pub executor_commitment: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub filled_order_root: String,
    pub transfer_root: String,
    pub contract_call_receipt_root: String,
    pub proof_root: String,
    pub fee_root: String,
    pub submitted_at_height: u64,
    pub finalized_at_height: u64,
    pub call_count: usize,
    pub status: ReceiptStatus,
}

impl ZkExecutionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        auction_id: &str,
        commitment_id: &str,
        executor_commitment: &str,
        pre_state_root: &str,
        post_state_root: &str,
        filled_order_root: &str,
        transfer_root: &str,
        contract_call_receipt_root: &str,
        proof_root: &str,
        fee_root: &str,
        submitted_at_height: u64,
        finalized_at_height: u64,
        call_count: usize,
    ) -> Self {
        let receipt_id = domain_hash(
            "PRIVATE-SC-ROLLUP-ORDERBOOK-ZK-RECEIPT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(auction_id),
                HashPart::Str(commitment_id),
                HashPart::Str(executor_commitment),
                HashPart::Str(pre_state_root),
                HashPart::Str(post_state_root),
                HashPart::Str(filled_order_root),
                HashPart::Str(transfer_root),
                HashPart::Str(contract_call_receipt_root),
                HashPart::Str(proof_root),
                HashPart::Str(fee_root),
                HashPart::Int(submitted_at_height as i128),
            ],
            32,
        );
        Self {
            receipt_id,
            auction_id: auction_id.to_string(),
            commitment_id: commitment_id.to_string(),
            executor_commitment: executor_commitment.to_string(),
            pre_state_root: pre_state_root.to_string(),
            post_state_root: post_state_root.to_string(),
            filled_order_root: filled_order_root.to_string(),
            transfer_root: transfer_root.to_string(),
            contract_call_receipt_root: contract_call_receipt_root.to_string(),
            proof_root: proof_root.to_string(),
            fee_root: fee_root.to_string(),
            submitted_at_height,
            finalized_at_height,
            call_count,
            status: ReceiptStatus::Submitted,
        }
    }

    pub fn validate(&self, config: &Config) -> PrivateSmartContractRollupOrderbookResult<()> {
        require_hash_like("receipt_id", &self.receipt_id)?;
        require_hash_like("auction_id", &self.auction_id)?;
        require_hash_like("commitment_id", &self.commitment_id)?;
        require_hash_like("executor_commitment", &self.executor_commitment)?;
        require_hash_like("pre_state_root", &self.pre_state_root)?;
        require_hash_like("post_state_root", &self.post_state_root)?;
        require_hash_like("filled_order_root", &self.filled_order_root)?;
        require_hash_like("transfer_root", &self.transfer_root)?;
        require_hash_like(
            "contract_call_receipt_root",
            &self.contract_call_receipt_root,
        )?;
        require_hash_like("proof_root", &self.proof_root)?;
        require_hash_like("fee_root", &self.fee_root)?;
        if self.call_count == 0 {
            return Err(format!("receipt {} has no contract calls", self.receipt_id));
        }
        if self.call_count > config.max_calls_per_receipt {
            return Err(format!("receipt {} exceeds call limit", self.receipt_id));
        }
        if self.finalized_at_height < self.submitted_at_height {
            return Err(format!(
                "receipt {} finalizes before submission",
                self.receipt_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "auction_id": self.auction_id,
            "commitment_id": self.commitment_id,
            "executor_commitment": self.executor_commitment,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "filled_order_root": self.filled_order_root,
            "transfer_root": self.transfer_root,
            "contract_call_receipt_root": self.contract_call_receipt_root,
            "proof_root": self.proof_root,
            "fee_root": self.fee_root,
            "submitted_at_height": self.submitted_at_height,
            "finalized_at_height": self.finalized_at_height,
            "call_count": self.call_count,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MakerRebate {
    pub rebate_id: String,
    pub order_id: String,
    pub receipt_id: String,
    pub maker_commitment: String,
    pub rebate_note_commitment: String,
    pub fee_asset_id: String,
    pub fee_paid_commitment: String,
    pub rebate_bps: u64,
    pub rebate_amount_commitment: String,
    pub nullifier_root: String,
    pub issued_at_height: u64,
    pub claimed: bool,
}

impl MakerRebate {
    pub fn new(
        order_id: &str,
        receipt_id: &str,
        maker_commitment: &str,
        rebate_note_commitment: &str,
        fee_asset_id: &str,
        fee_paid_commitment: &str,
        rebate_bps: u64,
        rebate_amount_commitment: &str,
        nullifier_root: &str,
        issued_at_height: u64,
    ) -> Self {
        let rebate_id = domain_hash(
            "PRIVATE-SC-ROLLUP-ORDERBOOK-MAKER-REBATE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(order_id),
                HashPart::Str(receipt_id),
                HashPart::Str(maker_commitment),
                HashPart::Str(rebate_note_commitment),
                HashPart::Str(fee_asset_id),
                HashPart::Str(fee_paid_commitment),
                HashPart::Int(rebate_bps as i128),
                HashPart::Str(rebate_amount_commitment),
                HashPart::Str(nullifier_root),
                HashPart::Int(issued_at_height as i128),
            ],
            32,
        );
        Self {
            rebate_id,
            order_id: order_id.to_string(),
            receipt_id: receipt_id.to_string(),
            maker_commitment: maker_commitment.to_string(),
            rebate_note_commitment: rebate_note_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            fee_paid_commitment: fee_paid_commitment.to_string(),
            rebate_bps,
            rebate_amount_commitment: rebate_amount_commitment.to_string(),
            nullifier_root: nullifier_root.to_string(),
            issued_at_height,
            claimed: false,
        }
    }

    pub fn validate(&self, config: &Config) -> PrivateSmartContractRollupOrderbookResult<()> {
        require_hash_like("rebate_id", &self.rebate_id)?;
        require_hash_like("order_id", &self.order_id)?;
        require_hash_like("receipt_id", &self.receipt_id)?;
        require_hash_like("maker_commitment", &self.maker_commitment)?;
        require_hash_like("rebate_note_commitment", &self.rebate_note_commitment)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_hash_like("fee_paid_commitment", &self.fee_paid_commitment)?;
        require_hash_like("rebate_amount_commitment", &self.rebate_amount_commitment)?;
        require_hash_like("nullifier_root", &self.nullifier_root)?;
        if self.rebate_bps > config.maker_rebate_bps {
            return Err(format!(
                "rebate {} exceeds configured maker rebate",
                self.rebate_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "order_id": self.order_id,
            "receipt_id": self.receipt_id,
            "maker_commitment": self.maker_commitment,
            "rebate_note_commitment": self.rebate_note_commitment,
            "fee_asset_id": self.fee_asset_id,
            "fee_paid_commitment": self.fee_paid_commitment,
            "rebate_bps": self.rebate_bps,
            "rebate_amount_commitment": self.rebate_amount_commitment,
            "nullifier_root": self.nullifier_root,
            "issued_at_height": self.issued_at_height,
            "claimed": self.claimed,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationNullifier {
    pub cancellation_id: String,
    pub order_id: String,
    pub owner_commitment: String,
    pub nullifier: String,
    pub witness_root: String,
    pub pq_signature_root: String,
    pub cancelled_at_height: u64,
    pub effective_at_height: u64,
}

impl CancellationNullifier {
    pub fn new(
        order_id: &str,
        owner_commitment: &str,
        nullifier: &str,
        witness_root: &str,
        pq_signature_root: &str,
        cancelled_at_height: u64,
        effective_at_height: u64,
    ) -> Self {
        let cancellation_id = domain_hash(
            "PRIVATE-SC-ROLLUP-ORDERBOOK-CANCELLATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(order_id),
                HashPart::Str(owner_commitment),
                HashPart::Str(nullifier),
                HashPart::Str(witness_root),
                HashPart::Str(pq_signature_root),
                HashPart::Int(cancelled_at_height as i128),
                HashPart::Int(effective_at_height as i128),
            ],
            32,
        );
        Self {
            cancellation_id,
            order_id: order_id.to_string(),
            owner_commitment: owner_commitment.to_string(),
            nullifier: nullifier.to_string(),
            witness_root: witness_root.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            cancelled_at_height,
            effective_at_height,
        }
    }

    pub fn validate(&self) -> PrivateSmartContractRollupOrderbookResult<()> {
        require_hash_like("cancellation_id", &self.cancellation_id)?;
        require_hash_like("order_id", &self.order_id)?;
        require_hash_like("owner_commitment", &self.owner_commitment)?;
        require_hash_like("nullifier", &self.nullifier)?;
        require_hash_like("witness_root", &self.witness_root)?;
        require_hash_like("pq_signature_root", &self.pq_signature_root)?;
        if self.effective_at_height < self.cancelled_at_height {
            return Err(format!(
                "cancellation {} effective height precedes cancellation",
                self.cancellation_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cancellation_id": self.cancellation_id,
            "order_id": self.order_id,
            "owner_commitment": self.owner_commitment,
            "nullifier": self.nullifier,
            "witness_root": self.witness_root,
            "pq_signature_root": self.pq_signature_root,
            "cancelled_at_height": self.cancelled_at_height,
            "effective_at_height": self.effective_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRecord {
    pub challenge_id: String,
    pub challenge_kind: ChallengeKind,
    pub challenger_commitment: String,
    pub subject_id: String,
    pub subject_root: String,
    pub evidence_root: String,
    pub bond_commitment_root: String,
    pub opened_at_height: u64,
    pub response_deadline_height: u64,
    pub resolved_at_height: u64,
    pub status: ChallengeStatus,
}

impl ChallengeRecord {
    pub fn new(
        challenge_kind: ChallengeKind,
        challenger_commitment: &str,
        subject_id: &str,
        subject_root: &str,
        evidence_root: &str,
        bond_commitment_root: &str,
        opened_at_height: u64,
        response_deadline_height: u64,
    ) -> Self {
        let challenge_id = domain_hash(
            "PRIVATE-SC-ROLLUP-ORDERBOOK-CHALLENGE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(challenge_kind.as_str()),
                HashPart::Str(challenger_commitment),
                HashPart::Str(subject_id),
                HashPart::Str(subject_root),
                HashPart::Str(evidence_root),
                HashPart::Str(bond_commitment_root),
                HashPart::Int(opened_at_height as i128),
                HashPart::Int(response_deadline_height as i128),
            ],
            32,
        );
        Self {
            challenge_id,
            challenge_kind,
            challenger_commitment: challenger_commitment.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            evidence_root: evidence_root.to_string(),
            bond_commitment_root: bond_commitment_root.to_string(),
            opened_at_height,
            response_deadline_height,
            resolved_at_height: 0,
            status: ChallengeStatus::Open,
        }
    }

    pub fn validate(&self) -> PrivateSmartContractRollupOrderbookResult<()> {
        require_hash_like("challenge_id", &self.challenge_id)?;
        require_hash_like("challenger_commitment", &self.challenger_commitment)?;
        require_hash_like("subject_id", &self.subject_id)?;
        require_hash_like("subject_root", &self.subject_root)?;
        require_hash_like("evidence_root", &self.evidence_root)?;
        require_hash_like("bond_commitment_root", &self.bond_commitment_root)?;
        if self.response_deadline_height <= self.opened_at_height {
            return Err(format!(
                "challenge {} has invalid response deadline",
                self.challenge_id
            ));
        }
        if self.resolved_at_height != 0 && self.resolved_at_height < self.opened_at_height {
            return Err(format!(
                "challenge {} resolves before it opens",
                self.challenge_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "challenge_kind": self.challenge_kind.as_str(),
            "challenger_commitment": self.challenger_commitment,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "evidence_root": self.evidence_root,
            "bond_commitment_root": self.bond_commitment_root,
            "opened_at_height": self.opened_at_height,
            "response_deadline_height": self.response_deadline_height,
            "resolved_at_height": self.resolved_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub pair_root: String,
    pub orderbook_root: String,
    pub sealed_order_root: String,
    pub auction_root: String,
    pub solver_commitment_root: String,
    pub execution_receipt_root: String,
    pub maker_rebate_root: String,
    pub cancellation_nullifier_root: String,
    pub challenge_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "pair_root": self.pair_root,
            "orderbook_root": self.orderbook_root,
            "sealed_order_root": self.sealed_order_root,
            "auction_root": self.auction_root,
            "solver_commitment_root": self.solver_commitment_root,
            "execution_receipt_root": self.execution_receipt_root,
            "maker_rebate_root": self.maker_rebate_root,
            "cancellation_nullifier_root": self.cancellation_nullifier_root,
            "challenge_root": self.challenge_root,
            "event_root": self.event_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub confidential_pairs: usize,
    pub orderbooks: usize,
    pub sealed_orders: usize,
    pub live_orders: usize,
    pub batch_auctions: usize,
    pub solver_commitments: usize,
    pub zk_execution_receipts: usize,
    pub maker_rebates: usize,
    pub cancellation_nullifiers: usize,
    pub challenge_records: usize,
    pub open_challenges: usize,
    pub events: usize,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "confidential_pairs": self.confidential_pairs,
            "orderbooks": self.orderbooks,
            "sealed_orders": self.sealed_orders,
            "live_orders": self.live_orders,
            "batch_auctions": self.batch_auctions,
            "solver_commitments": self.solver_commitments,
            "zk_execution_receipts": self.zk_execution_receipts,
            "maker_rebates": self.maker_rebates,
            "cancellation_nullifiers": self.cancellation_nullifiers,
            "challenge_records": self.challenge_records,
            "open_challenges": self.open_challenges,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub pairs: BTreeMap<String, ConfidentialTokenPair>,
    pub orderbooks: BTreeMap<String, RollupOrderbook>,
    pub sealed_orders: BTreeMap<String, SealedOrder>,
    pub auctions: BTreeMap<String, BatchAuction>,
    pub solver_commitments: BTreeMap<String, SolverCommitment>,
    pub execution_receipts: BTreeMap<String, ZkExecutionReceipt>,
    pub maker_rebates: BTreeMap<String, MakerRebate>,
    pub cancellation_nullifiers: BTreeMap<String, CancellationNullifier>,
    pub challenge_records: BTreeMap<String, ChallengeRecord>,
    pub events: Vec<Value>,
}

impl State {
    pub fn devnet() -> PrivateSmartContractRollupOrderbookResult<Self> {
        let config = Config::default();
        config.validate()?;
        let base_commitment = sample_hash("asset-dxmr");
        let quote_commitment = sample_hash("asset-dusd");
        let pair_policy_root = sample_hash("pair-policy-private-dex");
        let oracle_root = sample_hash("oracle-pair-dxmr-dusd");
        let pair = ConfidentialTokenPair::new(
            &base_commitment,
            &quote_commitment,
            &pair_policy_root,
            &oracle_root,
            ContractLaneKind::PrivateDex,
            config.low_fee_lane_bps,
        );
        let orderbook = RollupOrderbook::new(
            &pair.pair_id,
            &sample_hash("contract-private-dex-vm"),
            &sample_hash("opening-state"),
            &sample_hash("maker-rebate-pool"),
            PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEVNET_HEIGHT,
            config.low_fee_lane_bps,
        );
        let order = SealedOrder::new(
            &orderbook.orderbook_id,
            &pair.pair_id,
            &sample_hash("owner-maker-0"),
            OrderSide::Sell,
            &sample_hash("sealed-payload-0"),
            &sample_hash("price-commitment-0"),
            &sample_hash("quantity-commitment-0"),
            &sample_hash("contract-call-0"),
            &sample_hash("witness-0"),
            &sample_hash("max-fee-0"),
            &sample_hash("salt-0"),
            PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEVNET_HEIGHT,
            PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEVNET_HEIGHT
                .saturating_add(config.commit_ttl_blocks)
                .saturating_add(config.reveal_ttl_blocks),
        );
        let order_root = merkle_root(
            "PRIVATE-SC-ROLLUP-ORDERBOOK-DEVNET-ORDER-ROOT",
            &[order.public_record()],
        );
        let auction = BatchAuction::new(
            &orderbook.orderbook_id,
            &pair.pair_id,
            ContractLaneKind::PrivateDex,
            &order_root,
            &orderbook.state_commitment_root,
            &sample_hash("auction-da-root"),
            PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEVNET_HEIGHT,
            &config,
        );
        let solver = SolverCommitment::new(
            &auction.auction_id,
            &sample_hash("solver-commitment-0"),
            &sample_hash("solution-commitment-0"),
            &sample_hash("execution-plan-0"),
            &sample_hash("surplus-commitment-0"),
            &sample_hash("solver-bond-0"),
            &sample_hash("pq-attestation-0"),
            PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEVNET_HEIGHT.saturating_add(1),
            auction.reveal_deadline_height,
        );
        let receipt = ZkExecutionReceipt::new(
            &auction.auction_id,
            &solver.commitment_id,
            &sample_hash("executor-0"),
            &auction.opening_state_root,
            &sample_hash("post-state-0"),
            &sample_hash("filled-orders-0"),
            &sample_hash("transfers-0"),
            &sample_hash("contract-call-receipts-0"),
            &sample_hash("zk-proof-0"),
            &sample_hash("fee-root-0"),
            auction.reveal_deadline_height.saturating_add(1),
            auction.reveal_deadline_height.saturating_add(3),
            2,
        );
        let rebate = MakerRebate::new(
            &order.order_id,
            &receipt.receipt_id,
            &order.owner_commitment,
            &sample_hash("rebate-note-0"),
            &config.fee_asset_id,
            &sample_hash("fee-paid-0"),
            config.maker_rebate_bps / 2,
            &sample_hash("rebate-amount-0"),
            &sample_hash("rebate-nullifier-root-0"),
            receipt.finalized_at_height,
        );
        let cancellation = CancellationNullifier::new(
            &sample_hash("expired-order-reference"),
            &sample_hash("owner-maker-1"),
            &sample_hash("cancel-nullifier-0"),
            &sample_hash("cancel-witness-0"),
            &sample_hash("cancel-pq-signature-0"),
            PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEVNET_HEIGHT.saturating_add(2),
            PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEVNET_HEIGHT.saturating_add(2),
        );
        let challenge = ChallengeRecord::new(
            ChallengeKind::InvalidExecutionReceipt,
            &sample_hash("challenger-0"),
            &receipt.receipt_id,
            &root_from_record(&receipt.public_record()),
            &sample_hash("challenge-evidence-0"),
            &sample_hash("challenge-bond-0"),
            receipt.finalized_at_height.saturating_add(1),
            receipt
                .finalized_at_height
                .saturating_add(1)
                .saturating_add(config.challenge_ttl_blocks),
        );
        let mut state = Self {
            config,
            height: PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_DEVNET_HEIGHT,
            pairs: BTreeMap::new(),
            orderbooks: BTreeMap::new(),
            sealed_orders: BTreeMap::new(),
            auctions: BTreeMap::new(),
            solver_commitments: BTreeMap::new(),
            execution_receipts: BTreeMap::new(),
            maker_rebates: BTreeMap::new(),
            cancellation_nullifiers: BTreeMap::new(),
            challenge_records: BTreeMap::new(),
            events: Vec::new(),
        };
        state.pairs.insert(pair.pair_id.clone(), pair);
        state
            .orderbooks
            .insert(orderbook.orderbook_id.clone(), orderbook);
        state.sealed_orders.insert(order.order_id.clone(), order);
        state.auctions.insert(auction.auction_id.clone(), auction);
        state
            .solver_commitments
            .insert(solver.commitment_id.clone(), solver);
        state
            .execution_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        state.maker_rebates.insert(rebate.rebate_id.clone(), rebate);
        state
            .cancellation_nullifiers
            .insert(cancellation.cancellation_id.clone(), cancellation);
        state
            .challenge_records
            .insert(challenge.challenge_id.clone(), challenge);
        state.events.push(json!({
            "event": "devnet_private_smart_contract_rollup_orderbook_initialized",
            "chain_id": CHAIN_ID,
            "height": state.height,
            "protocol_version": PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_PROTOCOL_VERSION,
        }));
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> PrivateSmartContractRollupOrderbookResult<()> {
        self.config.validate()?;
        if self.height == 0 {
            return Err("state height must be non-zero".to_string());
        }
        enforce_limit(
            "pairs",
            self.pairs.len(),
            PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_PAIRS,
        )?;
        enforce_limit(
            "orderbooks",
            self.orderbooks.len(),
            PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_ORDERBOOKS,
        )?;
        enforce_limit(
            "sealed_orders",
            self.sealed_orders.len(),
            PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_ORDERS,
        )?;
        enforce_limit(
            "auctions",
            self.auctions.len(),
            PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_AUCTIONS,
        )?;
        enforce_limit(
            "solver_commitments",
            self.solver_commitments.len(),
            PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_SOLVER_COMMITMENTS,
        )?;
        enforce_limit(
            "execution_receipts",
            self.execution_receipts.len(),
            PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_RECEIPTS,
        )?;
        enforce_limit(
            "maker_rebates",
            self.maker_rebates.len(),
            PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_REBATES,
        )?;
        enforce_limit(
            "cancellation_nullifiers",
            self.cancellation_nullifiers.len(),
            PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_CANCELLATIONS,
        )?;
        enforce_limit(
            "challenge_records",
            self.challenge_records.len(),
            PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_CHALLENGES,
        )?;
        enforce_limit(
            "events",
            self.events.len(),
            PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_MAX_EVENTS,
        )?;
        let mut seen_pair_assets = BTreeSet::new();
        for (pair_id, pair) in &self.pairs {
            if pair_id != &pair.pair_id {
                return Err(format!("pair map key mismatch for {}", pair.pair_id));
            }
            pair.validate(&self.config)?;
            let pair_key = format!(
                "{}:{}",
                pair.base_asset_commitment, pair.quote_asset_commitment
            );
            if !seen_pair_assets.insert(pair_key) {
                return Err(format!("duplicate confidential pair {}", pair.pair_id));
            }
        }
        for (orderbook_id, orderbook) in &self.orderbooks {
            if orderbook_id != &orderbook.orderbook_id {
                return Err(format!(
                    "orderbook map key mismatch for {}",
                    orderbook.orderbook_id
                ));
            }
            orderbook.validate(&self.config)?;
            if !self.pairs.contains_key(&orderbook.pair_id) {
                return Err(format!(
                    "orderbook {} references unknown pair {}",
                    orderbook.orderbook_id, orderbook.pair_id
                ));
            }
        }
        for (order_id, order) in &self.sealed_orders {
            if order_id != &order.order_id {
                return Err(format!("order map key mismatch for {}", order.order_id));
            }
            order.validate()?;
            if !self.pairs.contains_key(&order.pair_id) {
                return Err(format!("order {} references unknown pair", order.order_id));
            }
            if !self.orderbooks.contains_key(&order.orderbook_id) {
                return Err(format!(
                    "order {} references unknown orderbook",
                    order.order_id
                ));
            }
            if order.submitted_at_height > self.height.saturating_add(self.config.epoch_blocks) {
                return Err(format!("order {} is too far in the future", order.order_id));
            }
        }
        for (auction_id, auction) in &self.auctions {
            if auction_id != &auction.auction_id {
                return Err(format!(
                    "auction map key mismatch for {}",
                    auction.auction_id
                ));
            }
            auction.validate()?;
            if !self.pairs.contains_key(&auction.pair_id) {
                return Err(format!(
                    "auction {} references unknown pair",
                    auction.auction_id
                ));
            }
            if !self.orderbooks.contains_key(&auction.orderbook_id) {
                return Err(format!(
                    "auction {} references unknown orderbook",
                    auction.auction_id
                ));
            }
            if auction.min_privacy_set_size < self.config.min_privacy_set_size {
                return Err(format!(
                    "auction {} privacy set too small",
                    auction.auction_id
                ));
            }
        }
        for (commitment_id, commitment) in &self.solver_commitments {
            if commitment_id != &commitment.commitment_id {
                return Err(format!(
                    "solver commitment map key mismatch for {}",
                    commitment.commitment_id
                ));
            }
            commitment.validate()?;
            if !self.auctions.contains_key(&commitment.auction_id) {
                return Err(format!(
                    "solver commitment {} references unknown auction",
                    commitment.commitment_id
                ));
            }
        }
        for (receipt_id, receipt) in &self.execution_receipts {
            if receipt_id != &receipt.receipt_id {
                return Err(format!(
                    "receipt map key mismatch for {}",
                    receipt.receipt_id
                ));
            }
            receipt.validate(&self.config)?;
            if !self.auctions.contains_key(&receipt.auction_id) {
                return Err(format!(
                    "receipt {} references unknown auction",
                    receipt.receipt_id
                ));
            }
            if !self.solver_commitments.contains_key(&receipt.commitment_id) {
                return Err(format!(
                    "receipt {} references unknown solver commitment",
                    receipt.receipt_id
                ));
            }
        }
        for (rebate_id, rebate) in &self.maker_rebates {
            if rebate_id != &rebate.rebate_id {
                return Err(format!("rebate map key mismatch for {}", rebate.rebate_id));
            }
            rebate.validate(&self.config)?;
            if !self.sealed_orders.contains_key(&rebate.order_id) {
                return Err(format!(
                    "rebate {} references unknown order",
                    rebate.rebate_id
                ));
            }
            if !self.execution_receipts.contains_key(&rebate.receipt_id) {
                return Err(format!(
                    "rebate {} references unknown execution receipt",
                    rebate.rebate_id
                ));
            }
        }
        let mut seen_nullifiers = BTreeSet::new();
        for (cancellation_id, cancellation) in &self.cancellation_nullifiers {
            if cancellation_id != &cancellation.cancellation_id {
                return Err(format!(
                    "cancellation map key mismatch for {}",
                    cancellation.cancellation_id
                ));
            }
            cancellation.validate()?;
            if !seen_nullifiers.insert(cancellation.nullifier.clone()) {
                return Err(format!(
                    "duplicate cancellation nullifier {}",
                    cancellation.nullifier
                ));
            }
        }
        for (challenge_id, challenge) in &self.challenge_records {
            if challenge_id != &challenge.challenge_id {
                return Err(format!(
                    "challenge map key mismatch for {}",
                    challenge.challenge_id
                ));
            }
            challenge.validate()?;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> PrivateSmartContractRollupOrderbookResult<()> {
        require_non_zero("height", height)?;
        self.height = height;
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> PrivateSmartContractRollupOrderbookResult<()> {
        if height < self.height {
            return Err("update_height cannot move backwards".to_string());
        }
        self.set_height(height)
    }

    pub fn roots(&self) -> Roots {
        let config_record = self.config.public_record();
        let pair_records = map_records(&self.pairs, ConfidentialTokenPair::public_record);
        let orderbook_records = map_records(&self.orderbooks, RollupOrderbook::public_record);
        let order_records = map_records(&self.sealed_orders, SealedOrder::public_record);
        let auction_records = map_records(&self.auctions, BatchAuction::public_record);
        let solver_records = map_records(&self.solver_commitments, SolverCommitment::public_record);
        let receipt_records =
            map_records(&self.execution_receipts, ZkExecutionReceipt::public_record);
        let rebate_records = map_records(&self.maker_rebates, MakerRebate::public_record);
        let cancellation_records = map_records(
            &self.cancellation_nullifiers,
            CancellationNullifier::public_record,
        );
        let challenge_records =
            map_records(&self.challenge_records, ChallengeRecord::public_record);
        let config_root = root_from_record(&config_record);
        let pair_root = merkle_root("PRIVATE-SC-ROLLUP-ORDERBOOK-PAIRS", &pair_records);
        let orderbook_root =
            merkle_root("PRIVATE-SC-ROLLUP-ORDERBOOK-ORDERBOOKS", &orderbook_records);
        let sealed_order_root =
            merkle_root("PRIVATE-SC-ROLLUP-ORDERBOOK-SEALED-ORDERS", &order_records);
        let auction_root = merkle_root("PRIVATE-SC-ROLLUP-ORDERBOOK-AUCTIONS", &auction_records);
        let solver_commitment_root = merkle_root(
            "PRIVATE-SC-ROLLUP-ORDERBOOK-SOLVER-COMMITMENTS",
            &solver_records,
        );
        let execution_receipt_root = merkle_root(
            "PRIVATE-SC-ROLLUP-ORDERBOOK-EXECUTION-RECEIPTS",
            &receipt_records,
        );
        let maker_rebate_root =
            merkle_root("PRIVATE-SC-ROLLUP-ORDERBOOK-MAKER-REBATES", &rebate_records);
        let cancellation_nullifier_root = merkle_root(
            "PRIVATE-SC-ROLLUP-ORDERBOOK-CANCELLATION-NULLIFIERS",
            &cancellation_records,
        );
        let challenge_root =
            merkle_root("PRIVATE-SC-ROLLUP-ORDERBOOK-CHALLENGES", &challenge_records);
        let event_root = merkle_root("PRIVATE-SC-ROLLUP-ORDERBOOK-EVENTS", &self.events);
        let state_payload = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_PROTOCOL_VERSION,
            "height": self.height,
            "config_root": config_root,
            "pair_root": pair_root,
            "orderbook_root": orderbook_root,
            "sealed_order_root": sealed_order_root,
            "auction_root": auction_root,
            "solver_commitment_root": solver_commitment_root,
            "execution_receipt_root": execution_receipt_root,
            "maker_rebate_root": maker_rebate_root,
            "cancellation_nullifier_root": cancellation_nullifier_root,
            "challenge_root": challenge_root,
            "event_root": event_root,
        });
        let state_root = root_from_record(&state_payload);
        Roots {
            config_root,
            pair_root,
            orderbook_root,
            sealed_order_root,
            auction_root,
            solver_commitment_root,
            execution_receipt_root,
            maker_rebate_root,
            cancellation_nullifier_root,
            challenge_root,
            event_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            confidential_pairs: self.pairs.len(),
            orderbooks: self.orderbooks.len(),
            sealed_orders: self.sealed_orders.len(),
            live_orders: self
                .sealed_orders
                .values()
                .filter(|order| order.status.live())
                .count(),
            batch_auctions: self.auctions.len(),
            solver_commitments: self.solver_commitments.len(),
            zk_execution_receipts: self.execution_receipts.len(),
            maker_rebates: self.maker_rebates.len(),
            cancellation_nullifiers: self.cancellation_nullifiers.len(),
            challenge_records: self.challenge_records.len(),
            open_challenges: self
                .challenge_records
                .values()
                .filter(|challenge| challenge.status == ChallengeStatus::Open)
                .count(),
            events: self.events.len(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_PROTOCOL_VERSION,
            "security_model": PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_SECURITY_MODEL,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-SC-ROLLUP-ORDERBOOK-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> PrivateSmartContractRollupOrderbookResult<State> {
    State::devnet()
}

fn map_records<T, F>(items: &BTreeMap<String, T>, record_fn: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    items.values().map(record_fn).collect()
}

fn sample_hash(label: &str) -> String {
    domain_hash(
        "PRIVATE-SC-ROLLUP-ORDERBOOK-DEVNET-SAMPLE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_SMART_CONTRACT_ROLLUP_ORDERBOOK_PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn require_non_empty(name: &str, value: &str) -> PrivateSmartContractRollupOrderbookResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(())
}

fn require_non_zero(name: &str, value: u64) -> PrivateSmartContractRollupOrderbookResult<()> {
    if value == 0 {
        return Err(format!("{name} must be non-zero"));
    }
    Ok(())
}

fn require_hash_like(name: &str, value: &str) -> PrivateSmartContractRollupOrderbookResult<()> {
    require_non_empty(name, value)?;
    if value.len() < 16 {
        return Err(format!("{name} must be at least 16 hex characters"));
    }
    if !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!("{name} must be hex encoded"));
    }
    Ok(())
}

fn enforce_limit(
    name: &str,
    observed: usize,
    limit: usize,
) -> PrivateSmartContractRollupOrderbookResult<()> {
    if observed > limit {
        return Err(format!("{name} exceeds limit {limit}"));
    }
    Ok(())
}
