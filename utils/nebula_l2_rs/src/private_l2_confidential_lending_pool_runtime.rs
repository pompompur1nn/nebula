use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialLendingPoolRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-lending-pool-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_PQ_AUTH_SCHEME: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-lending-v1";
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_MARKET_SCHEME: &str =
    "monero-private-l2-confidential-lending-market-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_COLLATERAL_SCHEME: &str =
    "monero-private-l2-confidential-collateral-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEBT_SCHEME: &str =
    "monero-private-l2-confidential-debt-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_RISK_ATTESTATION_SCHEME: &str =
    "monero-private-l2-confidential-risk-attestation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_LIQUIDATION_SCHEME: &str =
    "monero-private-l2-batched-liquidation-settlement-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_RECEIPT_SCHEME: &str =
    "roots-only-confidential-lending-settlement-receipt-v1";
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEVNET_HEIGHT: u64 = 188_000;
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "devnet-private-l2-lending-low-fee";
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_MAX_MARKETS: usize = 65_536;
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_MAX_OPEN_POSITIONS: usize = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_MAX_BATCH_LIQUIDATIONS: usize =
    4_096;
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 2_048;
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 16_384;
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 24;
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_MAX_INTEREST_RATE_BPS: u64 = 3_500;
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_MIN_COLLATERAL_FACTOR_BPS: u64 =
    12_500;
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_LIQUIDATION_THRESHOLD_BPS: u64 =
    11_250;
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_LIQUIDATION_BONUS_BPS: u64 = 650;
pub const PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 18;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketKind {
    MoneroCollateral,
    StableDebt,
    CrossMargin,
    Isolated,
    OracleBound,
}

impl MarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroCollateral => "monero_collateral",
            Self::StableDebt => "stable_debt",
            Self::CrossMargin => "cross_margin",
            Self::Isolated => "isolated",
            Self::OracleBound => "oracle_bound",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Open,
    Paused,
    LiquidationOnly,
    Settling,
    Closed,
}

impl MarketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Paused => "paused",
            Self::LiquidationOnly => "liquidation_only",
            Self::Settling => "settling",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_position_flow(self) -> bool {
        matches!(self, Self::Open)
    }

    pub fn accepts_liquidations(self) -> bool {
        matches!(self, Self::Open | Self::LiquidationOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    Pending,
    RiskAttested,
    Borrowed,
    LiquidationPending,
    Settled,
    Repaid,
    Rejected,
}

impl PositionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::RiskAttested => "risk_attested",
            Self::Borrowed => "borrowed",
            Self::LiquidationPending => "liquidation_pending",
            Self::Settled => "settled",
            Self::Repaid => "repaid",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::RiskAttested | Self::Borrowed | Self::LiquidationPending
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskVerdict {
    Healthy,
    Watch,
    ReduceOnly,
    Liquidatable,
    Rejected,
}

impl RiskVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::ReduceOnly => "reduce_only",
            Self::Liquidatable => "liquidatable",
            Self::Rejected => "rejected",
        }
    }

    pub fn allows_borrow(self) -> bool {
        matches!(self, Self::Healthy | Self::Watch)
    }

    pub fn allows_liquidation(self) -> bool {
        matches!(self, Self::Liquidatable | Self::ReduceOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationBatchStatus {
    Open,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl LiquidationBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReceiptKind {
    MarketOpened,
    CollateralDeposited,
    DebtBorrowed,
    RiskAttested,
    LiquidationSettled,
}

impl SettlementReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MarketOpened => "market_opened",
            Self::CollateralDeposited => "collateral_deposited",
            Self::DebtBorrowed => "debt_borrowed",
            Self::RiskAttested => "risk_attested",
            Self::LiquidationSettled => "liquidation_settled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub low_fee_lane: String,
    pub hash_suite: String,
    pub pq_authorization_scheme: String,
    pub market_scheme: String,
    pub collateral_scheme: String,
    pub debt_scheme: String,
    pub risk_attestation_scheme: String,
    pub liquidation_scheme: String,
    pub receipt_scheme: String,
    pub max_markets: usize,
    pub max_open_positions: usize,
    pub max_batch_liquidations: usize,
    pub min_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_interest_rate_bps: u64,
    pub min_collateral_factor_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub liquidation_bonus_bps: u64,
    pub settlement_ttl_blocks: u64,
    pub require_low_fee_sponsor: bool,
    pub require_oracle_bound: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_MONERO_NETWORK
                .to_string(),
            low_fee_lane: PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_LOW_FEE_LANE
                .to_string(),
            hash_suite: PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_HASH_SUITE.to_string(),
            pq_authorization_scheme: PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_PQ_AUTH_SCHEME
                .to_string(),
            market_scheme: PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_MARKET_SCHEME.to_string(),
            collateral_scheme: PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_COLLATERAL_SCHEME
                .to_string(),
            debt_scheme: PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEBT_SCHEME.to_string(),
            risk_attestation_scheme:
                PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_RISK_ATTESTATION_SCHEME.to_string(),
            liquidation_scheme: PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_LIQUIDATION_SCHEME
                .to_string(),
            receipt_scheme: PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_RECEIPT_SCHEME.to_string(),
            max_markets: PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_MAX_MARKETS,
            max_open_positions:
                PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_MAX_OPEN_POSITIONS,
            max_batch_liquidations:
                PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_MAX_BATCH_LIQUIDATIONS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_interest_rate_bps:
                PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_MAX_INTEREST_RATE_BPS,
            min_collateral_factor_bps:
                PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_MIN_COLLATERAL_FACTOR_BPS,
            liquidation_threshold_bps:
                PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_LIQUIDATION_THRESHOLD_BPS,
            liquidation_bonus_bps:
                PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_LIQUIDATION_BONUS_BPS,
            settlement_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            require_low_fee_sponsor: true,
            require_oracle_bound: true,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialLendingPoolRuntimeResult<()> {
        require_non_empty("protocol version", &self.protocol_version)?;
        require_non_empty("chain id", &self.chain_id)?;
        require_non_empty("monero network", &self.monero_network)?;
        require_non_empty("low fee lane", &self.low_fee_lane)?;
        require_non_empty("hash suite", &self.hash_suite)?;
        require_non_empty("PQ authorization scheme", &self.pq_authorization_scheme)?;
        require_non_empty("market scheme", &self.market_scheme)?;
        require_non_empty("collateral scheme", &self.collateral_scheme)?;
        require_non_empty("debt scheme", &self.debt_scheme)?;
        require_non_empty("risk attestation scheme", &self.risk_attestation_scheme)?;
        require_non_empty("liquidation scheme", &self.liquidation_scheme)?;
        require_non_empty("receipt scheme", &self.receipt_scheme)?;
        if self.max_markets == 0
            || self.max_open_positions == 0
            || self.max_batch_liquidations == 0
            || self.settlement_ttl_blocks == 0
        {
            return Err("confidential lending runtime capacities must be positive".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.min_batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err("batch privacy set must cover individual privacy set".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("PQ authorization security floor is too low".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_MAX_BPS
            || self.max_interest_rate_bps > PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_MAX_BPS
            || self.liquidation_bonus_bps > PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_MAX_BPS
        {
            return Err("confidential lending bps values exceed range".to_string());
        }
        if self.min_collateral_factor_bps <= PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_MAX_BPS {
            return Err("collateral factor must exceed full debt coverage".to_string());
        }
        if self.liquidation_threshold_bps <= PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_MAX_BPS
            || self.liquidation_threshold_bps > self.min_collateral_factor_bps
        {
            return Err(
                "liquidation threshold must be over 100% and below collateral factor".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "low_fee_lane": self.low_fee_lane,
            "hash_suite": self.hash_suite,
            "pq_authorization_scheme": self.pq_authorization_scheme,
            "market_scheme": self.market_scheme,
            "collateral_scheme": self.collateral_scheme,
            "debt_scheme": self.debt_scheme,
            "risk_attestation_scheme": self.risk_attestation_scheme,
            "liquidation_scheme": self.liquidation_scheme,
            "receipt_scheme": self.receipt_scheme,
            "max_markets": self.max_markets,
            "max_open_positions": self.max_open_positions,
            "max_batch_liquidations": self.max_batch_liquidations,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_batch_privacy_set_size": self.min_batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_interest_rate_bps": self.max_interest_rate_bps,
            "min_collateral_factor_bps": self.min_collateral_factor_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "liquidation_bonus_bps": self.liquidation_bonus_bps,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "require_low_fee_sponsor": self.require_low_fee_sponsor,
            "require_oracle_bound": self.require_oracle_bound,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub market_counter: u64,
    pub collateral_deposit_counter: u64,
    pub debt_position_counter: u64,
    pub risk_attestation_counter: u64,
    pub liquidation_batch_counter: u64,
    pub settlement_receipt_counter: u64,
    pub consumed_nullifier_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "market_counter": self.market_counter,
            "collateral_deposit_counter": self.collateral_deposit_counter,
            "debt_position_counter": self.debt_position_counter,
            "risk_attestation_counter": self.risk_attestation_counter,
            "liquidation_batch_counter": self.liquidation_batch_counter,
            "settlement_receipt_counter": self.settlement_receipt_counter,
            "consumed_nullifier_counter": self.consumed_nullifier_counter,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenMarketRequest {
    pub market_kind: MarketKind,
    pub market_owner_commitment: String,
    pub collateral_asset_root: String,
    pub debt_asset_root: String,
    pub reserve_note_root: String,
    pub interest_model_root: String,
    pub oracle_root: String,
    pub risk_policy_root: String,
    pub pq_authority_root: String,
    pub privacy_policy_root: String,
    pub low_fee_sponsor_root: String,
    pub market_nullifier: String,
    pub collateral_factor_bps: u64,
    pub max_interest_rate_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
}

impl OpenMarketRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialLendingPoolRuntimeResult<()> {
        require_non_empty("market owner commitment", &self.market_owner_commitment)?;
        require_non_empty("collateral asset root", &self.collateral_asset_root)?;
        require_non_empty("debt asset root", &self.debt_asset_root)?;
        require_non_empty("reserve note root", &self.reserve_note_root)?;
        require_non_empty("interest model root", &self.interest_model_root)?;
        require_non_empty("risk policy root", &self.risk_policy_root)?;
        require_non_empty("PQ authority root", &self.pq_authority_root)?;
        require_non_empty("privacy policy root", &self.privacy_policy_root)?;
        require_non_empty("market nullifier", &self.market_nullifier)?;
        if self.collateral_asset_root == self.debt_asset_root {
            return Err("collateral and debt assets must differ".to_string());
        }
        if config.require_oracle_bound {
            require_non_empty("oracle root", &self.oracle_root)?;
        }
        if config.require_low_fee_sponsor {
            require_non_empty("low fee sponsor root", &self.low_fee_sponsor_root)?;
        }
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.collateral_factor_bps < config.min_collateral_factor_bps {
            return Err("market collateral factor below configured minimum".to_string());
        }
        if self.max_interest_rate_bps > config.max_interest_rate_bps {
            return Err("market interest rate exceeds configured maximum".to_string());
        }
        if self.liquidation_threshold_bps > self.collateral_factor_bps
            || self.liquidation_threshold_bps < config.liquidation_threshold_bps
        {
            return Err("market liquidation threshold is outside policy".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_kind": self.market_kind.as_str(),
            "market_owner_commitment": self.market_owner_commitment,
            "collateral_asset_root": self.collateral_asset_root,
            "debt_asset_root": self.debt_asset_root,
            "reserve_note_root": self.reserve_note_root,
            "interest_model_root": self.interest_model_root,
            "oracle_root": self.oracle_root,
            "risk_policy_root": self.risk_policy_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_policy_root": self.privacy_policy_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "market_nullifier": self.market_nullifier,
            "collateral_factor_bps": self.collateral_factor_bps,
            "max_interest_rate_bps": self.max_interest_rate_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositPrivateCollateralRequest {
    pub market_id: String,
    pub borrower_commitment: String,
    pub collateral_note_root: String,
    pub amount_commitment_root: String,
    pub monero_lock_root: String,
    pub range_proof_root: String,
    pub privacy_proof_root: String,
    pub pq_authorization_root: String,
    pub low_fee_sponsor_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub deposited_at_height: u64,
    pub expires_at_height: u64,
}

impl DepositPrivateCollateralRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialLendingPoolRuntimeResult<()> {
        require_non_empty("market id", &self.market_id)?;
        require_non_empty("borrower commitment", &self.borrower_commitment)?;
        require_non_empty("collateral note root", &self.collateral_note_root)?;
        require_non_empty("amount commitment root", &self.amount_commitment_root)?;
        require_non_empty("monero lock root", &self.monero_lock_root)?;
        require_non_empty("range proof root", &self.range_proof_root)?;
        require_non_empty("privacy proof root", &self.privacy_proof_root)?;
        require_non_empty("PQ authorization root", &self.pq_authorization_root)?;
        require_non_empty("nullifier", &self.nullifier)?;
        if config.require_low_fee_sponsor {
            require_non_empty("low fee sponsor root", &self.low_fee_sponsor_root)?;
        }
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("collateral deposit fee exceeds low-fee cap".to_string());
        }
        if self.expires_at_height <= self.deposited_at_height {
            return Err("collateral deposit expiry must follow deposit height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "borrower_commitment": self.borrower_commitment,
            "collateral_note_root": self.collateral_note_root,
            "amount_commitment_root": self.amount_commitment_root,
            "monero_lock_root": self.monero_lock_root,
            "range_proof_root": self.range_proof_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "nullifier": self.nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "deposited_at_height": self.deposited_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BorrowConfidentialDebtRequest {
    pub market_id: String,
    pub collateral_deposit_id: String,
    pub borrower_commitment: String,
    pub debt_note_root: String,
    pub debt_amount_commitment_root: String,
    pub collateral_position_root: String,
    pub health_factor_commitment_root: String,
    pub oracle_bound_root: String,
    pub privacy_proof_root: String,
    pub pq_authorization_root: String,
    pub low_fee_sponsor_root: String,
    pub nullifier: String,
    pub collateral_factor_bps: u64,
    pub max_interest_rate_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub borrowed_at_height: u64,
    pub expires_at_height: u64,
}

impl BorrowConfidentialDebtRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialLendingPoolRuntimeResult<()> {
        require_non_empty("market id", &self.market_id)?;
        require_non_empty("collateral deposit id", &self.collateral_deposit_id)?;
        require_non_empty("borrower commitment", &self.borrower_commitment)?;
        require_non_empty("debt note root", &self.debt_note_root)?;
        require_non_empty(
            "debt amount commitment root",
            &self.debt_amount_commitment_root,
        )?;
        require_non_empty("collateral position root", &self.collateral_position_root)?;
        require_non_empty(
            "health factor commitment root",
            &self.health_factor_commitment_root,
        )?;
        require_non_empty("privacy proof root", &self.privacy_proof_root)?;
        require_non_empty("PQ authorization root", &self.pq_authorization_root)?;
        require_non_empty("nullifier", &self.nullifier)?;
        if config.require_oracle_bound {
            require_non_empty("oracle bound root", &self.oracle_bound_root)?;
        }
        if config.require_low_fee_sponsor {
            require_non_empty("low fee sponsor root", &self.low_fee_sponsor_root)?;
        }
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.collateral_factor_bps < config.min_collateral_factor_bps {
            return Err("borrow collateral factor below configured minimum".to_string());
        }
        if self.max_interest_rate_bps > config.max_interest_rate_bps
            || self.max_fee_bps > config.max_user_fee_bps
        {
            return Err("borrow rate or fee exceeds policy".to_string());
        }
        if self.expires_at_height <= self.borrowed_at_height {
            return Err("borrow expiry must follow borrow height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "collateral_deposit_id": self.collateral_deposit_id,
            "borrower_commitment": self.borrower_commitment,
            "debt_note_root": self.debt_note_root,
            "debt_amount_commitment_root": self.debt_amount_commitment_root,
            "collateral_position_root": self.collateral_position_root,
            "health_factor_commitment_root": self.health_factor_commitment_root,
            "oracle_bound_root": self.oracle_bound_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "nullifier": self.nullifier,
            "collateral_factor_bps": self.collateral_factor_bps,
            "max_interest_rate_bps": self.max_interest_rate_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "borrowed_at_height": self.borrowed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAttestationRequest {
    pub debt_position_id: String,
    pub attestor_commitment: String,
    pub verdict: RiskVerdict,
    pub risk_score_bps: u64,
    pub health_factor_bps: u64,
    pub exposure_commitment_root: String,
    pub oracle_root: String,
    pub proof_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub attestation_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl RiskAttestationRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialLendingPoolRuntimeResult<()> {
        require_non_empty("debt position id", &self.debt_position_id)?;
        require_non_empty("attestor commitment", &self.attestor_commitment)?;
        require_non_empty("exposure commitment root", &self.exposure_commitment_root)?;
        require_non_empty("oracle root", &self.oracle_root)?;
        require_non_empty("proof root", &self.proof_root)?;
        require_non_empty("PQ authorization root", &self.pq_authorization_root)?;
        require_non_empty("privacy proof root", &self.privacy_proof_root)?;
        require_non_empty("attestation nullifier", &self.attestation_nullifier)?;
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.risk_score_bps > PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_MAX_BPS {
            return Err("risk score exceeds bps range".to_string());
        }
        if self.verdict.allows_borrow() && self.health_factor_bps < config.min_collateral_factor_bps
        {
            return Err("borrow-allowing attestation has insufficient health".to_string());
        }
        if self.verdict.allows_liquidation()
            && self.health_factor_bps > config.liquidation_threshold_bps
        {
            return Err("liquidation verdict requires health below threshold".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "debt_position_id": self.debt_position_id,
            "attestor_commitment": self.attestor_commitment,
            "verdict": self.verdict.as_str(),
            "risk_score_bps": self.risk_score_bps,
            "health_factor_bps": self.health_factor_bps,
            "exposure_commitment_root": self.exposure_commitment_root,
            "oracle_root": self.oracle_root,
            "proof_root": self.proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "attestation_nullifier": self.attestation_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildBatchedPrivateLiquidationRequest {
    pub market_id: String,
    pub debt_position_ids: Vec<String>,
    pub liquidator_commitment: String,
    pub seized_collateral_root: String,
    pub repaid_debt_root: String,
    pub auction_clearing_root: String,
    pub liquidation_proof_root: String,
    pub recursive_batch_proof_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_batch_authorization_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub built_at_height: u64,
}

impl BuildBatchedPrivateLiquidationRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialLendingPoolRuntimeResult<()> {
        require_non_empty("market id", &self.market_id)?;
        require_non_empty("liquidator commitment", &self.liquidator_commitment)?;
        require_non_empty("seized collateral root", &self.seized_collateral_root)?;
        require_non_empty("repaid debt root", &self.repaid_debt_root)?;
        require_non_empty("auction clearing root", &self.auction_clearing_root)?;
        require_non_empty("liquidation proof root", &self.liquidation_proof_root)?;
        require_non_empty(
            "recursive batch proof root",
            &self.recursive_batch_proof_root,
        )?;
        require_non_empty(
            "PQ batch authorization root",
            &self.pq_batch_authorization_root,
        )?;
        if config.require_low_fee_sponsor {
            require_non_empty("low fee sponsor root", &self.low_fee_sponsor_root)?;
        }
        if self.debt_position_ids.is_empty()
            || self.debt_position_ids.len() > config.max_batch_liquidations
        {
            return Err("liquidation batch size is outside policy".to_string());
        }
        if self.privacy_set_size < config.min_batch_privacy_set_size {
            return Err("liquidation batch privacy set below configured minimum".to_string());
        }
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("liquidation batch fee exceeds low-fee cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "debt_position_ids": self.debt_position_ids,
            "liquidator_commitment": self.liquidator_commitment,
            "seized_collateral_root": self.seized_collateral_root,
            "repaid_debt_root": self.repaid_debt_root,
            "auction_clearing_root": self.auction_clearing_root,
            "liquidation_proof_root": self.liquidation_proof_root,
            "recursive_batch_proof_root": self.recursive_batch_proof_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_batch_authorization_root": self.pq_batch_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "built_at_height": self.built_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceiptRequest {
    pub receipt_kind: SettlementReceiptKind,
    pub subject_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub account_delta_root: String,
    pub nullifier_root: String,
    pub output_note_root: String,
    pub low_fee_sponsor_receipt_root: String,
    pub pq_settlement_root: String,
    pub state_root_after: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl SettlementReceiptRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialLendingPoolRuntimeResult<()> {
        require_non_empty("subject id", &self.subject_id)?;
        require_non_empty("settlement tx root", &self.settlement_tx_root)?;
        require_non_empty("settlement proof root", &self.settlement_proof_root)?;
        require_non_empty("account delta root", &self.account_delta_root)?;
        require_non_empty("nullifier root", &self.nullifier_root)?;
        require_non_empty("output note root", &self.output_note_root)?;
        require_non_empty("PQ settlement root", &self.pq_settlement_root)?;
        require_non_empty("state root after", &self.state_root_after)?;
        if config.require_low_fee_sponsor {
            require_non_empty(
                "low fee sponsor receipt root",
                &self.low_fee_sponsor_receipt_root,
            )?;
        }
        if self.settled_fee_bps > config.max_user_fee_bps {
            return Err("settlement fee exceeds low-fee cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_kind": self.receipt_kind.as_str(),
            "subject_id": self.subject_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "account_delta_root": self.account_delta_root,
            "nullifier_root": self.nullifier_root,
            "output_note_root": self.output_note_root,
            "low_fee_sponsor_receipt_root": self.low_fee_sponsor_receipt_root,
            "pq_settlement_root": self.pq_settlement_root,
            "state_root_after": self.state_root_after,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialLendingMarket {
    pub market_id: String,
    pub market_kind: MarketKind,
    pub status: MarketStatus,
    pub market_owner_commitment: String,
    pub collateral_asset_root: String,
    pub debt_asset_root: String,
    pub reserve_note_root: String,
    pub interest_model_root: String,
    pub oracle_root: String,
    pub risk_policy_root: String,
    pub pq_authority_root: String,
    pub privacy_policy_root: String,
    pub low_fee_sponsor_root: String,
    pub collateral_factor_bps: u64,
    pub max_interest_rate_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub latest_market_state_root: String,
    pub opened_at_height: u64,
    pub collateral_deposit_ids: Vec<String>,
    pub debt_position_ids: Vec<String>,
    pub liquidation_batch_ids: Vec<String>,
}

impl ConfidentialLendingMarket {
    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "market_kind": self.market_kind.as_str(),
            "status": self.status.as_str(),
            "market_owner_commitment": self.market_owner_commitment,
            "collateral_asset_root": self.collateral_asset_root,
            "debt_asset_root": self.debt_asset_root,
            "reserve_note_root": self.reserve_note_root,
            "interest_model_root": self.interest_model_root,
            "oracle_root": self.oracle_root,
            "risk_policy_root": self.risk_policy_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_policy_root": self.privacy_policy_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "collateral_factor_bps": self.collateral_factor_bps,
            "max_interest_rate_bps": self.max_interest_rate_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "latest_market_state_root": self.latest_market_state_root,
            "opened_at_height": self.opened_at_height,
            "collateral_deposit_ids": self.collateral_deposit_ids,
            "debt_position_ids": self.debt_position_ids,
            "liquidation_batch_ids": self.liquidation_batch_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCollateralDeposit {
    pub deposit_id: String,
    pub market_id: String,
    pub borrower_commitment: String,
    pub collateral_note_root: String,
    pub amount_commitment_root: String,
    pub monero_lock_root: String,
    pub range_proof_root: String,
    pub privacy_proof_root: String,
    pub pq_authorization_root: String,
    pub low_fee_sponsor_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub status: PositionStatus,
    pub deposited_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateCollateralDeposit {
    pub fn public_record(&self) -> Value {
        json!({
            "deposit_id": self.deposit_id,
            "market_id": self.market_id,
            "borrower_commitment": self.borrower_commitment,
            "collateral_note_root": self.collateral_note_root,
            "amount_commitment_root": self.amount_commitment_root,
            "monero_lock_root": self.monero_lock_root,
            "range_proof_root": self.range_proof_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "nullifier": self.nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "deposited_at_height": self.deposited_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialDebtPosition {
    pub debt_position_id: String,
    pub market_id: String,
    pub collateral_deposit_id: String,
    pub borrower_commitment: String,
    pub debt_note_root: String,
    pub debt_amount_commitment_root: String,
    pub collateral_position_root: String,
    pub health_factor_commitment_root: String,
    pub oracle_bound_root: String,
    pub privacy_proof_root: String,
    pub pq_authorization_root: String,
    pub low_fee_sponsor_root: String,
    pub nullifier: String,
    pub collateral_factor_bps: u64,
    pub max_interest_rate_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub status: PositionStatus,
    pub borrowed_at_height: u64,
    pub expires_at_height: u64,
}

impl ConfidentialDebtPosition {
    pub fn public_record(&self) -> Value {
        json!({
            "debt_position_id": self.debt_position_id,
            "market_id": self.market_id,
            "collateral_deposit_id": self.collateral_deposit_id,
            "borrower_commitment": self.borrower_commitment,
            "debt_note_root": self.debt_note_root,
            "debt_amount_commitment_root": self.debt_amount_commitment_root,
            "collateral_position_root": self.collateral_position_root,
            "health_factor_commitment_root": self.health_factor_commitment_root,
            "oracle_bound_root": self.oracle_bound_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "nullifier": self.nullifier,
            "collateral_factor_bps": self.collateral_factor_bps,
            "max_interest_rate_bps": self.max_interest_rate_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "borrowed_at_height": self.borrowed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAttestationRecord {
    pub attestation_id: String,
    pub debt_position_id: String,
    pub attestor_commitment: String,
    pub verdict: RiskVerdict,
    pub risk_score_bps: u64,
    pub health_factor_bps: u64,
    pub exposure_commitment_root: String,
    pub oracle_root: String,
    pub proof_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub attestation_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl RiskAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "debt_position_id": self.debt_position_id,
            "attestor_commitment": self.attestor_commitment,
            "verdict": self.verdict.as_str(),
            "risk_score_bps": self.risk_score_bps,
            "health_factor_bps": self.health_factor_bps,
            "exposure_commitment_root": self.exposure_commitment_root,
            "oracle_root": self.oracle_root,
            "proof_root": self.proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "attestation_nullifier": self.attestation_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchedPrivateLiquidation {
    pub liquidation_batch_id: String,
    pub market_id: String,
    pub debt_position_ids: Vec<String>,
    pub liquidator_commitment: String,
    pub seized_collateral_root: String,
    pub repaid_debt_root: String,
    pub auction_clearing_root: String,
    pub liquidation_proof_root: String,
    pub recursive_batch_proof_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_batch_authorization_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub status: LiquidationBatchStatus,
    pub built_at_height: u64,
    pub settlement_deadline_height: u64,
}

impl BatchedPrivateLiquidation {
    pub fn public_record(&self) -> Value {
        json!({
            "liquidation_batch_id": self.liquidation_batch_id,
            "market_id": self.market_id,
            "debt_position_ids": self.debt_position_ids,
            "liquidator_commitment": self.liquidator_commitment,
            "seized_collateral_root": self.seized_collateral_root,
            "repaid_debt_root": self.repaid_debt_root,
            "auction_clearing_root": self.auction_clearing_root,
            "liquidation_proof_root": self.liquidation_proof_root,
            "recursive_batch_proof_root": self.recursive_batch_proof_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_batch_authorization_root": self.pq_batch_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "built_at_height": self.built_at_height,
            "settlement_deadline_height": self.settlement_deadline_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub receipt_kind: SettlementReceiptKind,
    pub subject_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub account_delta_root: String,
    pub nullifier_root: String,
    pub output_note_root: String,
    pub low_fee_sponsor_receipt_root: String,
    pub pq_settlement_root: String,
    pub state_root_after: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "subject_id": self.subject_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "account_delta_root": self.account_delta_root,
            "nullifier_root": self.nullifier_root,
            "output_note_root": self.output_note_root,
            "low_fee_sponsor_receipt_root": self.low_fee_sponsor_receipt_root,
            "pq_settlement_root": self.pq_settlement_root,
            "state_root_after": self.state_root_after,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub market_root: String,
    pub collateral_deposit_root: String,
    pub debt_position_root: String,
    pub risk_attestation_root: String,
    pub liquidation_batch_root: String,
    pub settlement_receipt_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "market_root": self.market_root,
            "collateral_deposit_root": self.collateral_deposit_root,
            "debt_position_root": self.debt_position_root,
            "risk_attestation_root": self.risk_attestation_root,
            "liquidation_batch_root": self.liquidation_batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub markets: BTreeMap<String, ConfidentialLendingMarket>,
    pub collateral_deposits: BTreeMap<String, PrivateCollateralDeposit>,
    pub debt_positions: BTreeMap<String, ConfidentialDebtPosition>,
    pub risk_attestations: BTreeMap<String, RiskAttestationRecord>,
    pub liquidation_batches: BTreeMap<String, BatchedPrivateLiquidation>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            current_height: PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_DEVNET_HEIGHT,
            markets: BTreeMap::new(),
            collateral_deposits: BTreeMap::new(),
            debt_positions: BTreeMap::new(),
            risk_attestations: BTreeMap::new(),
            liquidation_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        }
    }

    pub fn open_market(
        &mut self,
        request: OpenMarketRequest,
    ) -> PrivateL2ConfidentialLendingPoolRuntimeResult<ConfidentialLendingMarket> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.markets.len() >= self.config.max_markets {
            return Err("confidential lending market capacity exhausted".to_string());
        }
        self.consume_nullifier(&request.market_nullifier)?;
        self.counters.market_counter = self.counters.market_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.opened_at_height);
        let market_id = market_id(&request, self.counters.market_counter);
        let latest_market_state_root = payload_root(
            "PRIVATE-L2-CONFIDENTIAL-LENDING-MARKET-INITIAL",
            &request.public_record(),
        );
        let market = ConfidentialLendingMarket {
            market_id: market_id.clone(),
            market_kind: request.market_kind,
            status: MarketStatus::Open,
            market_owner_commitment: request.market_owner_commitment,
            collateral_asset_root: request.collateral_asset_root,
            debt_asset_root: request.debt_asset_root,
            reserve_note_root: request.reserve_note_root,
            interest_model_root: request.interest_model_root,
            oracle_root: request.oracle_root,
            risk_policy_root: request.risk_policy_root,
            pq_authority_root: request.pq_authority_root,
            privacy_policy_root: request.privacy_policy_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            collateral_factor_bps: request.collateral_factor_bps,
            max_interest_rate_bps: request.max_interest_rate_bps,
            liquidation_threshold_bps: request.liquidation_threshold_bps,
            latest_market_state_root,
            opened_at_height: request.opened_at_height,
            collateral_deposit_ids: Vec::new(),
            debt_position_ids: Vec::new(),
            liquidation_batch_ids: Vec::new(),
        };
        self.markets.insert(market_id, market.clone());
        Ok(market)
    }

    pub fn deposit_private_collateral(
        &mut self,
        request: DepositPrivateCollateralRequest,
    ) -> PrivateL2ConfidentialLendingPoolRuntimeResult<PrivateCollateralDeposit> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.collateral_deposits.len() >= self.config.max_open_positions {
            return Err("confidential lending collateral capacity exhausted".to_string());
        }
        let market = self
            .markets
            .get(&request.market_id)
            .ok_or_else(|| "collateral deposit references unknown market".to_string())?;
        if !market.status.accepts_position_flow() {
            return Err("market is not accepting collateral deposits".to_string());
        }
        self.consume_nullifier(&request.nullifier)?;
        self.counters.collateral_deposit_counter =
            self.counters.collateral_deposit_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.deposited_at_height);
        let deposit_id = collateral_deposit_id(&request, self.counters.collateral_deposit_counter);
        let deposit = PrivateCollateralDeposit {
            deposit_id: deposit_id.clone(),
            market_id: request.market_id.clone(),
            borrower_commitment: request.borrower_commitment,
            collateral_note_root: request.collateral_note_root,
            amount_commitment_root: request.amount_commitment_root,
            monero_lock_root: request.monero_lock_root,
            range_proof_root: request.range_proof_root,
            privacy_proof_root: request.privacy_proof_root,
            pq_authorization_root: request.pq_authorization_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            nullifier: request.nullifier,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            status: PositionStatus::Pending,
            deposited_at_height: request.deposited_at_height,
            expires_at_height: request.expires_at_height,
        };
        if let Some(market) = self.markets.get_mut(&request.market_id) {
            market.collateral_deposit_ids.push(deposit_id.clone());
        }
        self.collateral_deposits.insert(deposit_id, deposit.clone());
        Ok(deposit)
    }

    pub fn borrow_confidential_debt(
        &mut self,
        request: BorrowConfidentialDebtRequest,
    ) -> PrivateL2ConfidentialLendingPoolRuntimeResult<ConfidentialDebtPosition> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.debt_positions.len() >= self.config.max_open_positions {
            return Err("confidential lending debt capacity exhausted".to_string());
        }
        let market = self
            .markets
            .get(&request.market_id)
            .ok_or_else(|| "borrow references unknown market".to_string())?;
        if !market.status.accepts_position_flow() {
            return Err("market is not accepting borrows".to_string());
        }
        if request.max_interest_rate_bps > market.max_interest_rate_bps
            || request.collateral_factor_bps < market.collateral_factor_bps
        {
            return Err("borrow terms are outside market policy".to_string());
        }
        let deposit = self
            .collateral_deposits
            .get(&request.collateral_deposit_id)
            .ok_or_else(|| "borrow references unknown collateral deposit".to_string())?;
        if deposit.market_id != request.market_id {
            return Err("collateral deposit belongs to another market".to_string());
        }
        if !deposit.status.live() {
            return Err("collateral deposit is not live".to_string());
        }
        if deposit.expires_at_height <= request.borrowed_at_height {
            return Err("collateral deposit expired before borrow".to_string());
        }
        self.consume_nullifier(&request.nullifier)?;
        self.counters.debt_position_counter = self.counters.debt_position_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.borrowed_at_height);
        let debt_position_id = debt_position_id(&request, self.counters.debt_position_counter);
        if let Some(deposit) = self
            .collateral_deposits
            .get_mut(&request.collateral_deposit_id)
        {
            deposit.status = PositionStatus::Borrowed;
        }
        let position = ConfidentialDebtPosition {
            debt_position_id: debt_position_id.clone(),
            market_id: request.market_id.clone(),
            collateral_deposit_id: request.collateral_deposit_id,
            borrower_commitment: request.borrower_commitment,
            debt_note_root: request.debt_note_root,
            debt_amount_commitment_root: request.debt_amount_commitment_root,
            collateral_position_root: request.collateral_position_root,
            health_factor_commitment_root: request.health_factor_commitment_root,
            oracle_bound_root: request.oracle_bound_root,
            privacy_proof_root: request.privacy_proof_root,
            pq_authorization_root: request.pq_authorization_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            nullifier: request.nullifier,
            collateral_factor_bps: request.collateral_factor_bps,
            max_interest_rate_bps: request.max_interest_rate_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            status: PositionStatus::Borrowed,
            borrowed_at_height: request.borrowed_at_height,
            expires_at_height: request.expires_at_height,
        };
        if let Some(market) = self.markets.get_mut(&request.market_id) {
            market.debt_position_ids.push(debt_position_id.clone());
        }
        self.debt_positions
            .insert(debt_position_id, position.clone());
        Ok(position)
    }

    pub fn attest_risk(
        &mut self,
        request: RiskAttestationRequest,
    ) -> PrivateL2ConfidentialLendingPoolRuntimeResult<RiskAttestationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let position = self
            .debt_positions
            .get(&request.debt_position_id)
            .ok_or_else(|| "risk attestation references unknown debt position".to_string())?;
        if !position.status.live() {
            return Err("risk attestation cannot target a closed position".to_string());
        }
        if position.expires_at_height <= request.attested_at_height {
            return Err("risk attestation cannot target expired debt".to_string());
        }
        self.consume_nullifier(&request.attestation_nullifier)?;
        self.counters.risk_attestation_counter =
            self.counters.risk_attestation_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.attested_at_height);
        let attestation_id = risk_attestation_id(&request, self.counters.risk_attestation_counter);
        if let Some(position) = self.debt_positions.get_mut(&request.debt_position_id) {
            position.status = if request.verdict.allows_liquidation() {
                PositionStatus::LiquidationPending
            } else if request.verdict.allows_borrow() {
                PositionStatus::RiskAttested
            } else {
                PositionStatus::Rejected
            };
        }
        let record = RiskAttestationRecord {
            attestation_id: attestation_id.clone(),
            debt_position_id: request.debt_position_id,
            attestor_commitment: request.attestor_commitment,
            verdict: request.verdict,
            risk_score_bps: request.risk_score_bps,
            health_factor_bps: request.health_factor_bps,
            exposure_commitment_root: request.exposure_commitment_root,
            oracle_root: request.oracle_root,
            proof_root: request.proof_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            attestation_nullifier: request.attestation_nullifier,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            attested_at_height: request.attested_at_height,
        };
        self.risk_attestations
            .insert(attestation_id, record.clone());
        Ok(record)
    }

    pub fn build_batched_private_liquidation(
        &mut self,
        request: BuildBatchedPrivateLiquidationRequest,
    ) -> PrivateL2ConfidentialLendingPoolRuntimeResult<BatchedPrivateLiquidation> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let market = self
            .markets
            .get(&request.market_id)
            .ok_or_else(|| "liquidation references unknown market".to_string())?;
        if !market.status.accepts_liquidations() {
            return Err("market is not accepting liquidations".to_string());
        }
        let mut seen = BTreeSet::new();
        for position_id in &request.debt_position_ids {
            if !seen.insert(position_id.clone()) {
                return Err("duplicate debt position in liquidation batch".to_string());
            }
            let position = self
                .debt_positions
                .get(position_id)
                .ok_or_else(|| format!("unknown debt position {position_id}"))?;
            if position.market_id != request.market_id {
                return Err("liquidation position belongs to another market".to_string());
            }
            if position.status != PositionStatus::LiquidationPending {
                return Err("liquidation requires a liquidation-pending position".to_string());
            }
        }
        self.counters.liquidation_batch_counter =
            self.counters.liquidation_batch_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.built_at_height);
        let liquidation_batch_id =
            liquidation_batch_id(&request, self.counters.liquidation_batch_counter);
        for position_id in &request.debt_position_ids {
            if let Some(position) = self.debt_positions.get_mut(position_id) {
                position.status = PositionStatus::LiquidationPending;
            }
        }
        let batch = BatchedPrivateLiquidation {
            liquidation_batch_id: liquidation_batch_id.clone(),
            market_id: request.market_id.clone(),
            debt_position_ids: request.debt_position_ids,
            liquidator_commitment: request.liquidator_commitment,
            seized_collateral_root: request.seized_collateral_root,
            repaid_debt_root: request.repaid_debt_root,
            auction_clearing_root: request.auction_clearing_root,
            liquidation_proof_root: request.liquidation_proof_root,
            recursive_batch_proof_root: request.recursive_batch_proof_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            pq_batch_authorization_root: request.pq_batch_authorization_root,
            privacy_set_size: request.privacy_set_size,
            max_fee_bps: request.max_fee_bps,
            status: LiquidationBatchStatus::SettlementReady,
            built_at_height: request.built_at_height,
            settlement_deadline_height: request
                .built_at_height
                .saturating_add(self.config.settlement_ttl_blocks),
        };
        if let Some(market) = self.markets.get_mut(&request.market_id) {
            market
                .liquidation_batch_ids
                .push(liquidation_batch_id.clone());
        }
        self.liquidation_batches
            .insert(liquidation_batch_id, batch.clone());
        Ok(batch)
    }

    pub fn publish_settlement_receipt(
        &mut self,
        request: SettlementReceiptRequest,
    ) -> PrivateL2ConfidentialLendingPoolRuntimeResult<SettlementReceipt> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if request.receipt_kind == SettlementReceiptKind::LiquidationSettled {
            let batch = self
                .liquidation_batches
                .get(&request.subject_id)
                .ok_or_else(|| "receipt references unknown liquidation batch".to_string())?
                .clone();
            if !batch.status.can_settle() {
                return Err("liquidation batch is not settlement-ready".to_string());
            }
            if request.settled_at_height > batch.settlement_deadline_height {
                return Err("liquidation settlement deadline elapsed".to_string());
            }
            for position_id in &batch.debt_position_ids {
                if let Some(position) = self.debt_positions.get_mut(position_id) {
                    position.status = PositionStatus::Settled;
                }
            }
            if let Some(stored_batch) = self.liquidation_batches.get_mut(&request.subject_id) {
                stored_batch.status = LiquidationBatchStatus::Settled;
            }
            if let Some(market) = self.markets.get_mut(&batch.market_id) {
                market.latest_market_state_root = request.state_root_after.clone();
            }
        }
        self.counters.settlement_receipt_counter =
            self.counters.settlement_receipt_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.settled_at_height);
        let receipt_id = settlement_receipt_id(&request, self.counters.settlement_receipt_counter);
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            receipt_kind: request.receipt_kind,
            subject_id: request.subject_id,
            settlement_tx_root: request.settlement_tx_root,
            settlement_proof_root: request.settlement_proof_root,
            account_delta_root: request.account_delta_root,
            nullifier_root: request.nullifier_root,
            output_note_root: request.output_note_root,
            low_fee_sponsor_receipt_root: request.low_fee_sponsor_receipt_root,
            pq_settlement_root: request.pq_settlement_root,
            state_root_after: request.state_root_after,
            settled_fee_bps: request.settled_fee_bps,
            settled_at_height: request.settled_at_height,
        };
        self.settlement_receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn roots(&self) -> Roots {
        let market_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-LENDING-MARKETS",
            &self
                .markets
                .values()
                .map(ConfidentialLendingMarket::public_record)
                .collect::<Vec<_>>(),
        );
        let collateral_deposit_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-LENDING-COLLATERAL-DEPOSITS",
            &self
                .collateral_deposits
                .values()
                .map(PrivateCollateralDeposit::public_record)
                .collect::<Vec<_>>(),
        );
        let debt_position_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-LENDING-DEBT-POSITIONS",
            &self
                .debt_positions
                .values()
                .map(ConfidentialDebtPosition::public_record)
                .collect::<Vec<_>>(),
        );
        let risk_attestation_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-LENDING-RISK-ATTESTATIONS",
            &self
                .risk_attestations
                .values()
                .map(RiskAttestationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let liquidation_batch_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-LENDING-LIQUIDATION-BATCHES",
            &self
                .liquidation_batches
                .values()
                .map(BatchedPrivateLiquidation::public_record)
                .collect::<Vec<_>>(),
        );
        let settlement_receipt_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-LENDING-SETTLEMENT-RECEIPTS",
            &self
                .settlement_receipts
                .values()
                .map(SettlementReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-LENDING-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-LENDING-STATE",
            &json!({
                "chain_id": self.config.chain_id,
                "protocol_version": self.config.protocol_version,
                "current_height": self.current_height,
                "market_root": market_root,
                "collateral_deposit_root": collateral_deposit_root,
                "debt_position_root": debt_position_root,
                "risk_attestation_root": risk_attestation_root,
                "liquidation_batch_root": liquidation_batch_root,
                "settlement_receipt_root": settlement_receipt_root,
                "nullifier_root": nullifier_root,
                "counters": self.counters.public_record(),
            }),
        );
        Roots {
            market_root,
            collateral_deposit_root,
            debt_position_root,
            risk_attestation_root,
            liquidation_batch_root,
            settlement_receipt_root,
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
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "market_ids": self.markets.keys().cloned().collect::<Vec<_>>(),
            "collateral_deposit_ids": self.collateral_deposits.keys().cloned().collect::<Vec<_>>(),
            "debt_position_ids": self.debt_positions.keys().cloned().collect::<Vec<_>>(),
            "risk_attestation_ids": self.risk_attestations.keys().cloned().collect::<Vec<_>>(),
            "liquidation_batch_ids": self.liquidation_batches.keys().cloned().collect::<Vec<_>>(),
            "settlement_receipt_ids": self.settlement_receipts.keys().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn consume_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2ConfidentialLendingPoolRuntimeResult<()> {
        let nullifier_hash = payload_id(
            "PRIVATE-L2-CONFIDENTIAL-LENDING-NULLIFIER-ID",
            &[HashPart::Str(nullifier)],
        );
        if !self.consumed_nullifiers.insert(nullifier_hash) {
            return Err("confidential lending nullifier replay detected".to_string());
        }
        self.counters.consumed_nullifier_counter =
            self.counters.consumed_nullifier_counter.saturating_add(1);
        Ok(())
    }
}

pub fn market_id(request: &OpenMarketRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-LENDING-MARKET-ID",
        &json!({
            "counter": counter,
            "market_kind": request.market_kind.as_str(),
            "market_owner_commitment": request.market_owner_commitment,
            "collateral_asset_root": request.collateral_asset_root,
            "debt_asset_root": request.debt_asset_root,
            "reserve_note_root": request.reserve_note_root,
            "opened_at_height": request.opened_at_height,
        }),
    )
}

pub fn collateral_deposit_id(request: &DepositPrivateCollateralRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-LENDING-COLLATERAL-DEPOSIT-ID",
        &json!({
            "counter": counter,
            "market_id": request.market_id,
            "borrower_commitment": request.borrower_commitment,
            "collateral_note_root": request.collateral_note_root,
            "monero_lock_root": request.monero_lock_root,
            "nullifier": request.nullifier,
            "deposited_at_height": request.deposited_at_height,
        }),
    )
}

pub fn debt_position_id(request: &BorrowConfidentialDebtRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-LENDING-DEBT-POSITION-ID",
        &json!({
            "counter": counter,
            "market_id": request.market_id,
            "collateral_deposit_id": request.collateral_deposit_id,
            "borrower_commitment": request.borrower_commitment,
            "debt_note_root": request.debt_note_root,
            "collateral_position_root": request.collateral_position_root,
            "nullifier": request.nullifier,
            "borrowed_at_height": request.borrowed_at_height,
        }),
    )
}

pub fn risk_attestation_id(request: &RiskAttestationRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-LENDING-RISK-ATTESTATION-ID",
        &json!({
            "counter": counter,
            "debt_position_id": request.debt_position_id,
            "attestor_commitment": request.attestor_commitment,
            "verdict": request.verdict.as_str(),
            "risk_score_bps": request.risk_score_bps,
            "health_factor_bps": request.health_factor_bps,
            "proof_root": request.proof_root,
            "attestation_nullifier": request.attestation_nullifier,
            "attested_at_height": request.attested_at_height,
        }),
    )
}

pub fn liquidation_batch_id(
    request: &BuildBatchedPrivateLiquidationRequest,
    counter: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-LENDING-LIQUIDATION-BATCH-ID",
        &json!({
            "counter": counter,
            "market_id": request.market_id,
            "debt_position_ids": request.debt_position_ids,
            "seized_collateral_root": request.seized_collateral_root,
            "repaid_debt_root": request.repaid_debt_root,
            "recursive_batch_proof_root": request.recursive_batch_proof_root,
            "built_at_height": request.built_at_height,
        }),
    )
}

pub fn settlement_receipt_id(request: &SettlementReceiptRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-LENDING-SETTLEMENT-RECEIPT-ID",
        &json!({
            "counter": counter,
            "receipt_kind": request.receipt_kind.as_str(),
            "subject_id": request.subject_id,
            "settlement_tx_root": request.settlement_tx_root,
            "settlement_proof_root": request.settlement_proof_root,
            "state_root_after": request.state_root_after,
            "settled_at_height": request.settled_at_height,
        }),
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn payload_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!(
            "{}:{}:{}",
            PRIVATE_L2_CONFIDENTIAL_LENDING_POOL_RUNTIME_PROTOCOL_VERSION, CHAIN_ID, domain
        ),
        parts,
        32,
    )
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2ConfidentialLendingPoolRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2ConfidentialLendingPoolRuntimeResult<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("privacy set is below configured anonymity threshold".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err("PQ authorization security bits below configured minimum".to_string());
    }
    Ok(())
}
