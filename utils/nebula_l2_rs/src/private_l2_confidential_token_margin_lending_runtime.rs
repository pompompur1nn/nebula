use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialTokenMarginLendingRuntimeResult<T> = std::result::Result<T, String>;
pub type Result<T> = PrivateL2ConfidentialTokenMarginLendingRuntimeResult<T>;

pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-token-margin-lending-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_PQ_AUTH_SCHEME: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-token-margin-lending-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_MARKET_SCHEME: &str =
    "monero-private-l2-confidential-token-margin-market-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_COLLATERAL_SCHEME: &str =
    "monero-private-l2-confidential-token-collateral-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEBT_SCHEME: &str =
    "monero-private-l2-confidential-token-debt-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_BORROW_INTENT_SCHEME: &str =
    "monero-private-l2-encrypted-token-borrow-intent-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_HEALTH_SCHEME: &str =
    "monero-private-l2-margin-health-attestation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_LIQUIDATION_SCHEME: &str =
    "monero-private-l2-confidential-token-liquidation-queue-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_RECEIPT_SCHEME: &str =
    "roots-only-confidential-token-margin-lending-settlement-receipt-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEVNET_HEIGHT: u64 = 266_000;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_L2_NETWORK: &str =
    "nebula-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "devnet-private-l2-token-margin-lending-low-fee";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID: &str =
    "asset:wxmr";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_DEBT_ASSET_ID: &str =
    "asset:private-dusd";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MAX_MARKETS: usize = 65_536;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MAX_NOTES: usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MAX_BORROW_INTENTS: usize =
    524_288;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MAX_LIQUIDATION_QUEUE:
    usize = 131_072;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    4_096;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    32_768;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    256;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 22;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MAX_BORROW_RATE_BPS: u64 =
    3_600;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_INITIAL_MARGIN_BPS: u64 =
    15_000;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MAINTENANCE_MARGIN_BPS: u64 =
    12_500;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_LIQUIDATION_BONUS_BPS: u64 =
    650;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 =
    16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginMarketKind {
    CrossToken,
    IsolatedToken,
    MoneroCollateral,
    StableDebt,
    OracleBound,
}

impl MarginMarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CrossToken => "cross_token",
            Self::IsolatedToken => "isolated_token",
            Self::MoneroCollateral => "monero_collateral",
            Self::StableDebt => "stable_debt",
            Self::OracleBound => "oracle_bound",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Open,
    Paused,
    BorrowOnly,
    RepayOnly,
    LiquidationOnly,
    Closed,
}

impl MarketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Paused => "paused",
            Self::BorrowOnly => "borrow_only",
            Self::RepayOnly => "repay_only",
            Self::LiquidationOnly => "liquidation_only",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_borrows(self) -> bool {
        matches!(self, Self::Open | Self::BorrowOnly)
    }

    pub fn accepts_repayments(self) -> bool {
        matches!(self, Self::Open | Self::RepayOnly | Self::LiquidationOnly)
    }

    pub fn accepts_liquidations(self) -> bool {
        matches!(self, Self::Open | Self::RepayOnly | Self::LiquidationOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BorrowIntentKind {
    OpenBorrow,
    IncreaseBorrow,
    Repay,
    RollDebt,
    CollateralSwap,
}

impl BorrowIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenBorrow => "open_borrow",
            Self::IncreaseBorrow => "increase_borrow",
            Self::Repay => "repay",
            Self::RollDebt => "roll_debt",
            Self::CollateralSwap => "collateral_swap",
        }
    }

    pub fn increases_debt(self) -> bool {
        matches!(
            self,
            Self::OpenBorrow | Self::IncreaseBorrow | Self::RollDebt
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Queued,
    HealthAttested,
    Sponsored,
    Settled,
    Rejected,
    Expired,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::HealthAttested => "health_attested",
            Self::Sponsored => "sponsored",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthVerdict {
    Healthy,
    Watch,
    MarginCall,
    ReduceOnly,
    Liquidatable,
    Rejected,
}

impl HealthVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::MarginCall => "margin_call",
            Self::ReduceOnly => "reduce_only",
            Self::Liquidatable => "liquidatable",
            Self::Rejected => "rejected",
        }
    }

    pub fn allows_borrow(self) -> bool {
        matches!(self, Self::Healthy | Self::Watch)
    }

    pub fn allows_liquidation(self) -> bool {
        matches!(
            self,
            Self::MarginCall | Self::ReduceOnly | Self::Liquidatable
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationStatus {
    Queued,
    Reserved,
    Settled,
    Disputed,
    Expired,
}

impl LiquidationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Reserved => "reserved",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    MarketOpened,
    CollateralDeposited,
    DebtMinted,
    BorrowIntentSettled,
    HealthAttested,
    LiquidationQueued,
    LiquidationSettled,
    SponsorReserved,
    RebateCredited,
    RiskEpochRolled,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MarketOpened => "market_opened",
            Self::CollateralDeposited => "collateral_deposited",
            Self::DebtMinted => "debt_minted",
            Self::BorrowIntentSettled => "borrow_intent_settled",
            Self::HealthAttested => "health_attested",
            Self::LiquidationQueued => "liquidation_queued",
            Self::LiquidationSettled => "liquidation_settled",
            Self::SponsorReserved => "sponsor_reserved",
            Self::RebateCredited => "rebate_credited",
            Self::RiskEpochRolled => "risk_epoch_rolled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_auth_scheme: String,
    pub market_scheme: String,
    pub collateral_scheme: String,
    pub debt_scheme: String,
    pub borrow_intent_scheme: String,
    pub health_scheme: String,
    pub liquidation_scheme: String,
    pub receipt_scheme: String,
    pub monero_network: String,
    pub l2_network: String,
    pub low_fee_lane_id: String,
    pub default_collateral_asset_id: String,
    pub default_debt_asset_id: String,
    pub max_markets: usize,
    pub max_notes: usize,
    pub max_borrow_intents: usize,
    pub max_liquidation_queue: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_borrow_rate_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_bonus_bps: u64,
    pub settlement_ttl_blocks: u64,
    pub devnet_height: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_SCHEMA_VERSION,
            hash_suite: PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_PQ_AUTH_SCHEME
                .to_string(),
            market_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_MARKET_SCHEME
                .to_string(),
            collateral_scheme:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_COLLATERAL_SCHEME.to_string(),
            debt_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEBT_SCHEME
                .to_string(),
            borrow_intent_scheme:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_BORROW_INTENT_SCHEME
                    .to_string(),
            health_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_HEALTH_SCHEME
                .to_string(),
            liquidation_scheme:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_LIQUIDATION_SCHEME.to_string(),
            receipt_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_RECEIPT_SCHEME
                .to_string(),
            monero_network:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MONERO_NETWORK
                    .to_string(),
            l2_network: PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_L2_NETWORK
                .to_string(),
            low_fee_lane_id:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_LOW_FEE_LANE
                    .to_string(),
            default_collateral_asset_id:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID
                    .to_string(),
            default_debt_asset_id:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_DEBT_ASSET_ID
                    .to_string(),
            max_markets: PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MAX_MARKETS,
            max_notes: PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MAX_NOTES,
            max_borrow_intents:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MAX_BORROW_INTENTS,
            max_liquidation_queue:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MAX_LIQUIDATION_QUEUE,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_borrow_rate_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MAX_BORROW_RATE_BPS,
            initial_margin_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_MAINTENANCE_MARGIN_BPS,
            liquidation_bonus_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_LIQUIDATION_BONUS_BPS,
            settlement_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            devnet_height: PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_DEVNET_HEIGHT,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub market_counter: u64,
    pub collateral_note_counter: u64,
    pub debt_note_counter: u64,
    pub borrow_intent_counter: u64,
    pub health_attestation_counter: u64,
    pub liquidation_queue_counter: u64,
    pub sponsor_reservation_counter: u64,
    pub settlement_receipt_counter: u64,
    pub rebate_counter: u64,
    pub risk_epoch_counter: u64,
    pub consumed_nullifier_counter: u64,
    pub event_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub market_root: String,
    pub collateral_note_root: String,
    pub debt_note_root: String,
    pub borrow_intent_root: String,
    pub health_attestation_root: String,
    pub liquidation_queue_root: String,
    pub sponsor_reservation_root: String,
    pub settlement_receipt_root: String,
    pub rebate_root: String,
    pub risk_epoch_root: String,
    pub privacy_fence_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMarginMarket {
    pub market_id: String,
    pub market_kind: MarginMarketKind,
    pub status: MarketStatus,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub market_operator_commitment: String,
    pub oracle_price_root: String,
    pub interest_model_root: String,
    pub collateral_factor_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_bonus_bps: u64,
    pub max_borrow_rate_bps: u64,
    pub open_interest_commitment: String,
    pub liquidity_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
}

impl PrivateMarginMarket {
    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "market_kind": self.market_kind.as_str(),
            "status": self.status.as_str(),
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "market_operator_commitment": self.market_operator_commitment,
            "oracle_price_root": self.oracle_price_root,
            "interest_model_root": self.interest_model_root,
            "collateral_factor_bps": self.collateral_factor_bps,
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "liquidation_bonus_bps": self.liquidation_bonus_bps,
            "max_borrow_rate_bps": self.max_borrow_rate_bps,
            "open_interest_commitment": self.open_interest_commitment,
            "liquidity_commitment": self.liquidity_commitment,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralNote {
    pub note_id: String,
    pub market_id: String,
    pub owner_commitment: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub note_commitment_root: String,
    pub range_proof_root: String,
    pub custody_proof_root: String,
    pub unlock_condition_root: String,
    pub nullifier_hash: String,
    pub status: NoteStatus,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub deposited_at_height: u64,
}

impl CollateralNote {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "market_id": self.market_id,
            "owner_commitment": self.owner_commitment,
            "asset_id": self.asset_id,
            "amount_commitment": self.amount_commitment,
            "note_commitment_root": self.note_commitment_root,
            "range_proof_root": self.range_proof_root,
            "custody_proof_root": self.custody_proof_root,
            "unlock_condition_root": self.unlock_condition_root,
            "nullifier_hash": self.nullifier_hash,
            "status": self.status.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "deposited_at_height": self.deposited_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebtNote {
    pub note_id: String,
    pub market_id: String,
    pub borrower_commitment: String,
    pub debt_asset_id: String,
    pub principal_commitment: String,
    pub debt_note_root: String,
    pub rate_commitment_root: String,
    pub maturity_root: String,
    pub borrow_intent_id: String,
    pub nullifier_hash: String,
    pub status: NoteStatus,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub minted_at_height: u64,
}

impl DebtNote {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "market_id": self.market_id,
            "borrower_commitment": self.borrower_commitment,
            "debt_asset_id": self.debt_asset_id,
            "principal_commitment": self.principal_commitment,
            "debt_note_root": self.debt_note_root,
            "rate_commitment_root": self.rate_commitment_root,
            "maturity_root": self.maturity_root,
            "borrow_intent_id": self.borrow_intent_id,
            "nullifier_hash": self.nullifier_hash,
            "status": self.status.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "minted_at_height": self.minted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBorrowIntent {
    pub intent_id: String,
    pub market_id: String,
    pub intent_kind: BorrowIntentKind,
    pub status: IntentStatus,
    pub borrower_commitment: String,
    pub collateral_note_ids: Vec<String>,
    pub debt_note_root: String,
    pub encrypted_payload_root: String,
    pub ciphertext_hash: String,
    pub route_commitment_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub intent_nullifier_hash: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedBorrowIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "market_id": self.market_id,
            "intent_kind": self.intent_kind.as_str(),
            "status": self.status.as_str(),
            "borrower_commitment": self.borrower_commitment,
            "collateral_note_ids": self.collateral_note_ids,
            "debt_note_root": self.debt_note_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "ciphertext_hash": self.ciphertext_hash,
            "route_commitment_root": self.route_commitment_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "intent_nullifier_hash": self.intent_nullifier_hash,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarginHealthAttestation {
    pub attestation_id: String,
    pub market_id: String,
    pub intent_id: String,
    pub attestor_commitment: String,
    pub verdict: HealthVerdict,
    pub health_factor_bps: u64,
    pub collateral_value_commitment: String,
    pub debt_value_commitment: String,
    pub oracle_price_root: String,
    pub risk_model_root: String,
    pub recursive_proof_root: String,
    pub attestation_nullifier_hash: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl MarginHealthAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "market_id": self.market_id,
            "intent_id": self.intent_id,
            "attestor_commitment": self.attestor_commitment,
            "verdict": self.verdict.as_str(),
            "health_factor_bps": self.health_factor_bps,
            "collateral_value_commitment": self.collateral_value_commitment,
            "debt_value_commitment": self.debt_value_commitment,
            "oracle_price_root": self.oracle_price_root,
            "risk_model_root": self.risk_model_root,
            "recursive_proof_root": self.recursive_proof_root,
            "attestation_nullifier_hash": self.attestation_nullifier_hash,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationQueueItem {
    pub liquidation_id: String,
    pub market_id: String,
    pub intent_id: String,
    pub health_attestation_id: String,
    pub status: LiquidationStatus,
    pub liquidator_commitment: String,
    pub seized_collateral_root: String,
    pub repaid_debt_root: String,
    pub penalty_commitment: String,
    pub queue_priority: u64,
    pub liquidation_nullifier_hash: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub queued_at_height: u64,
}

impl LiquidationQueueItem {
    pub fn public_record(&self) -> Value {
        json!({
            "liquidation_id": self.liquidation_id,
            "market_id": self.market_id,
            "intent_id": self.intent_id,
            "health_attestation_id": self.health_attestation_id,
            "status": self.status.as_str(),
            "liquidator_commitment": self.liquidator_commitment,
            "seized_collateral_root": self.seized_collateral_root,
            "repaid_debt_root": self.repaid_debt_root,
            "penalty_commitment": self.penalty_commitment,
            "queue_priority": self.queue_priority,
            "liquidation_nullifier_hash": self.liquidation_nullifier_hash,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "queued_at_height": self.queued_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub target_id: String,
    pub fee_asset_id: String,
    pub fee_budget_commitment: String,
    pub rebate_policy_root: String,
    pub reservation_nullifier_hash: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorReservation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub receipt_kind: ReceiptKind,
    pub subject_id: String,
    pub market_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub fee_receipt_root: String,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "subject_id": self.subject_id,
            "market_id": self.market_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "fee_receipt_root": self.fee_receipt_root,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateCredit {
    pub rebate_id: String,
    pub recipient_commitment: String,
    pub market_id: String,
    pub source_receipt_id: String,
    pub rebate_asset_id: String,
    pub rebate_commitment: String,
    pub fee_savings_bps: u64,
    pub rebate_nullifier_hash: String,
    pub credited_at_height: u64,
}

impl RebateCredit {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskEpoch {
    pub epoch_id: String,
    pub epoch_index: u64,
    pub oracle_set_root: String,
    pub interest_model_root: String,
    pub liquidation_model_root: String,
    pub market_ids: Vec<String>,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub closed_at_height: Option<u64>,
}

impl RiskEpoch {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub record_root: String,
    pub emitted_at_height: u64,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub markets: BTreeMap<String, PrivateMarginMarket>,
    pub collateral_notes: BTreeMap<String, CollateralNote>,
    pub debt_notes: BTreeMap<String, DebtNote>,
    pub borrow_intents: BTreeMap<String, EncryptedBorrowIntent>,
    pub health_attestations: BTreeMap<String, MarginHealthAttestation>,
    pub liquidation_queue: BTreeMap<String, LiquidationQueueItem>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, RebateCredit>,
    pub risk_epochs: BTreeMap<String, RiskEpoch>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub events: BTreeMap<String, RuntimeEvent>,
    pub counters: Counters,
}

pub type Runtime = State;

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            markets: BTreeMap::new(),
            collateral_notes: BTreeMap::new(),
            debt_notes: BTreeMap::new(),
            borrow_intents: BTreeMap::new(),
            health_attestations: BTreeMap::new(),
            liquidation_queue: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            risk_epochs: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            events: BTreeMap::new(),
            counters: Counters::default(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        let height = state.config.devnet_height;
        let market_id = private_margin_market_id("devnet-wxmr-dusd", 1);
        let market = PrivateMarginMarket {
            market_id: market_id.clone(),
            market_kind: MarginMarketKind::MoneroCollateral,
            status: MarketStatus::Open,
            collateral_asset_id: state.config.default_collateral_asset_id.clone(),
            debt_asset_id: state.config.default_debt_asset_id.clone(),
            market_operator_commitment: sample_commitment("operator", "margin-lending"),
            oracle_price_root: sample_root("oracle", "wxmr-dusd-devnet"),
            interest_model_root: sample_root("interest-model", "kinked-borrow-rate"),
            collateral_factor_bps: 7_000,
            initial_margin_bps: state.config.initial_margin_bps,
            maintenance_margin_bps: state.config.maintenance_margin_bps,
            liquidation_bonus_bps: state.config.liquidation_bonus_bps,
            max_borrow_rate_bps: 1_850,
            open_interest_commitment: sample_commitment("open-interest", "devnet-market"),
            liquidity_commitment: sample_commitment("liquidity", "devnet-market"),
            privacy_set_size: state.config.batch_privacy_set_size,
            pq_security_bits: state.config.min_pq_security_bits,
            opened_at_height: height,
        };
        state.counters.market_counter = 1;
        state.markets.insert(market_id.clone(), market);

        let collateral_id = collateral_note_id("devnet-collateral", 1);
        let collateral_nullifier = state.nullifier_hash("devnet-collateral-nullifier");
        state
            .consumed_nullifiers
            .insert(collateral_nullifier.clone());
        state.counters.consumed_nullifier_counter = 1;
        state.counters.collateral_note_counter = 1;
        state.collateral_notes.insert(
            collateral_id.clone(),
            CollateralNote {
                note_id: collateral_id.clone(),
                market_id: market_id.clone(),
                owner_commitment: sample_commitment("owner", "alice"),
                asset_id: state.config.default_collateral_asset_id.clone(),
                amount_commitment: sample_commitment("amount", "42-wxmr"),
                note_commitment_root: sample_root("collateral-note", "alice-wxmr"),
                range_proof_root: sample_root("range-proof", "alice-wxmr"),
                custody_proof_root: sample_root("custody-proof", "monero-lock"),
                unlock_condition_root: sample_root("unlock", "health-or-repay"),
                nullifier_hash: collateral_nullifier,
                status: NoteStatus::Locked,
                privacy_set_size: state.config.batch_privacy_set_size,
                pq_security_bits: state.config.min_pq_security_bits,
                deposited_at_height: height + 1,
            },
        );

        let intent_id = borrow_intent_id("devnet-borrow", 1);
        let intent_nullifier = state.nullifier_hash("devnet-borrow-nullifier");
        state.consumed_nullifiers.insert(intent_nullifier.clone());
        state.counters.consumed_nullifier_counter += 1;
        state.counters.borrow_intent_counter = 1;
        state.borrow_intents.insert(
            intent_id.clone(),
            EncryptedBorrowIntent {
                intent_id: intent_id.clone(),
                market_id: market_id.clone(),
                intent_kind: BorrowIntentKind::OpenBorrow,
                status: IntentStatus::HealthAttested,
                borrower_commitment: sample_commitment("borrower", "alice"),
                collateral_note_ids: vec![collateral_id.clone()],
                debt_note_root: sample_root("debt-note", "alice-dusd"),
                encrypted_payload_root: sample_root("encrypted-borrow-payload", "alice"),
                ciphertext_hash: sample_root("ciphertext", "borrow-intent"),
                route_commitment_root: sample_root("route", "private-lending"),
                max_fee_bps: 9,
                privacy_set_size: state.config.batch_privacy_set_size,
                pq_security_bits: state.config.min_pq_security_bits,
                intent_nullifier_hash: intent_nullifier,
                submitted_at_height: height + 2,
                expires_at_height: height + 2 + state.config.settlement_ttl_blocks,
            },
        );

        let debt_id = debt_note_id("devnet-debt", 1);
        let debt_nullifier = state.nullifier_hash("devnet-debt-nullifier");
        state.consumed_nullifiers.insert(debt_nullifier.clone());
        state.counters.consumed_nullifier_counter += 1;
        state.counters.debt_note_counter = 1;
        state.debt_notes.insert(
            debt_id.clone(),
            DebtNote {
                note_id: debt_id,
                market_id: market_id.clone(),
                borrower_commitment: sample_commitment("borrower", "alice"),
                debt_asset_id: state.config.default_debt_asset_id.clone(),
                principal_commitment: sample_commitment("principal", "12000-dusd"),
                debt_note_root: sample_root("debt-note", "alice-dusd"),
                rate_commitment_root: sample_root("rate", "devnet-fixed-window"),
                maturity_root: sample_root("maturity", "rolling"),
                borrow_intent_id: intent_id.clone(),
                nullifier_hash: debt_nullifier,
                status: NoteStatus::Active,
                privacy_set_size: state.config.batch_privacy_set_size,
                pq_security_bits: state.config.min_pq_security_bits,
                minted_at_height: height + 3,
            },
        );

        let attestation_id = health_attestation_id("devnet-health", 1);
        let health_nullifier = state.nullifier_hash("devnet-health-nullifier");
        state.consumed_nullifiers.insert(health_nullifier.clone());
        state.counters.consumed_nullifier_counter += 1;
        state.counters.health_attestation_counter = 1;
        state.health_attestations.insert(
            attestation_id.clone(),
            MarginHealthAttestation {
                attestation_id: attestation_id.clone(),
                market_id: market_id.clone(),
                intent_id: intent_id.clone(),
                attestor_commitment: sample_commitment("risk-attestor", "devnet-committee"),
                verdict: HealthVerdict::Healthy,
                health_factor_bps: 18_750,
                collateral_value_commitment: sample_commitment("collateral-value", "devnet"),
                debt_value_commitment: sample_commitment("debt-value", "devnet"),
                oracle_price_root: sample_root("oracle", "wxmr-dusd-devnet"),
                risk_model_root: sample_root("risk-model", "margin-v1"),
                recursive_proof_root: sample_root("recursive-proof", "health"),
                attestation_nullifier_hash: health_nullifier,
                privacy_set_size: state.config.batch_privacy_set_size,
                pq_security_bits: state.config.min_pq_security_bits,
                attested_at_height: height + 4,
            },
        );

        let sponsor_id = sponsor_reservation_id("devnet-sponsor", 1);
        let sponsor_nullifier = state.nullifier_hash("devnet-sponsor-nullifier");
        state.consumed_nullifiers.insert(sponsor_nullifier.clone());
        state.counters.consumed_nullifier_counter += 1;
        state.counters.sponsor_reservation_counter = 1;
        state.sponsor_reservations.insert(
            sponsor_id,
            SponsorReservation {
                reservation_id: sponsor_reservation_id("devnet-sponsor", 1),
                sponsor_commitment: sample_commitment("sponsor", "relay"),
                target_id: intent_id.clone(),
                fee_asset_id: state.config.default_debt_asset_id.clone(),
                fee_budget_commitment: sample_commitment("fee-budget", "intent"),
                rebate_policy_root: sample_root("rebate-policy", "low-fee"),
                reservation_nullifier_hash: sponsor_nullifier,
                reserved_at_height: height + 4,
                expires_at_height: height + 4 + state.config.settlement_ttl_blocks,
            },
        );

        let epoch_id = risk_epoch_id(1, 1);
        state.counters.risk_epoch_counter = 1;
        state.risk_epochs.insert(
            epoch_id.clone(),
            RiskEpoch {
                epoch_id,
                epoch_index: 1,
                oracle_set_root: sample_root("oracle-set", "devnet"),
                interest_model_root: sample_root("interest-model", "kinked-borrow-rate"),
                liquidation_model_root: sample_root("liquidation-model", "margin-v1"),
                market_ids: vec![market_id.clone()],
                privacy_set_size: state.config.batch_privacy_set_size,
                pq_security_bits: state.config.min_pq_security_bits,
                opened_at_height: height,
                closed_at_height: None,
            },
        );

        let receipt_id = settlement_receipt_id("devnet-receipt", 1);
        let before = payload_root("DEVNET-STATE-BEFORE", &json!({"height": height}));
        let after = state.state_root();
        state.counters.settlement_receipt_counter = 1;
        state.settlement_receipts.insert(
            receipt_id.clone(),
            SettlementReceipt {
                receipt_id: receipt_id.clone(),
                receipt_kind: ReceiptKind::BorrowIntentSettled,
                subject_id: intent_id.clone(),
                market_id: market_id.clone(),
                settlement_tx_root: sample_root("settlement-tx", "borrow"),
                settlement_proof_root: sample_root("settlement-proof", "borrow"),
                state_root_before: before,
                state_root_after: after,
                fee_receipt_root: sample_root("fee-receipt", "sponsored"),
                settled_at_height: height + 5,
            },
        );

        let rebate_id = rebate_id("devnet-rebate", 1);
        let rebate_nullifier = state.nullifier_hash("devnet-rebate-nullifier");
        state.consumed_nullifiers.insert(rebate_nullifier.clone());
        state.counters.consumed_nullifier_counter += 1;
        state.counters.rebate_counter = 1;
        state.rebates.insert(
            rebate_id.clone(),
            RebateCredit {
                rebate_id,
                recipient_commitment: sample_commitment("borrower", "alice"),
                market_id: market_id.clone(),
                source_receipt_id: receipt_id.clone(),
                rebate_asset_id: state.config.default_debt_asset_id.clone(),
                rebate_commitment: sample_commitment("rebate", "low-fee"),
                fee_savings_bps: 7,
                rebate_nullifier_hash: rebate_nullifier,
                credited_at_height: height + 5,
            },
        );

        state.emit_event(
            "devnet_margin_market_ready",
            &market_id,
            sample_root("event", "market-ready"),
            height + 5,
        );
        state
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: root_from_record(
                "PRIVATE-L2-TOKEN-MARGIN-LENDING-CONFIG",
                &self.config.public_record(),
            ),
            market_root: map_root("PRIVATE-L2-TOKEN-MARGIN-LENDING-MARKETS", &self.markets),
            collateral_note_root: map_root(
                "PRIVATE-L2-TOKEN-MARGIN-LENDING-COLLATERAL-NOTES",
                &self.collateral_notes,
            ),
            debt_note_root: map_root(
                "PRIVATE-L2-TOKEN-MARGIN-LENDING-DEBT-NOTES",
                &self.debt_notes,
            ),
            borrow_intent_root: map_root(
                "PRIVATE-L2-TOKEN-MARGIN-LENDING-BORROW-INTENTS",
                &self.borrow_intents,
            ),
            health_attestation_root: map_root(
                "PRIVATE-L2-TOKEN-MARGIN-LENDING-HEALTH-ATTESTATIONS",
                &self.health_attestations,
            ),
            liquidation_queue_root: map_root(
                "PRIVATE-L2-TOKEN-MARGIN-LENDING-LIQUIDATION-QUEUE",
                &self.liquidation_queue,
            ),
            sponsor_reservation_root: map_root(
                "PRIVATE-L2-TOKEN-MARGIN-LENDING-SPONSOR-RESERVATIONS",
                &self.sponsor_reservations,
            ),
            settlement_receipt_root: map_root(
                "PRIVATE-L2-TOKEN-MARGIN-LENDING-SETTLEMENT-RECEIPTS",
                &self.settlement_receipts,
            ),
            rebate_root: map_root("PRIVATE-L2-TOKEN-MARGIN-LENDING-REBATES", &self.rebates),
            risk_epoch_root: map_root(
                "PRIVATE-L2-TOKEN-MARGIN-LENDING-RISK-EPOCHS",
                &self.risk_epochs,
            ),
            privacy_fence_root: set_root(
                "PRIVATE-L2-TOKEN-MARGIN-LENDING-PRIVACY-FENCES",
                &self.consumed_nullifiers,
            ),
            event_root: map_root("PRIVATE-L2-TOKEN-MARGIN-LENDING-EVENTS", &self.events),
            state_root: String::new(),
        };
        roots.state_root = root_from_record(
            "PRIVATE-L2-TOKEN-MARGIN-LENDING-STATE",
            &json!({
                "config_root": roots.config_root,
                "market_root": roots.market_root,
                "collateral_note_root": roots.collateral_note_root,
                "debt_note_root": roots.debt_note_root,
                "borrow_intent_root": roots.borrow_intent_root,
                "health_attestation_root": roots.health_attestation_root,
                "liquidation_queue_root": roots.liquidation_queue_root,
                "sponsor_reservation_root": roots.sponsor_reservation_root,
                "settlement_receipt_root": roots.settlement_receipt_root,
                "rebate_root": roots.rebate_root,
                "risk_epoch_root": roots.risk_epoch_root,
                "privacy_fence_root": roots.privacy_fence_root,
                "event_root": roots.event_root,
                "counters": self.counters.public_record(),
            }),
        );
        roots
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol": PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters.public_record(),
            "market_ids": self.markets.keys().cloned().collect::<Vec<_>>(),
            "collateral_note_ids": self.collateral_notes.keys().cloned().collect::<Vec<_>>(),
            "debt_note_ids": self.debt_notes.keys().cloned().collect::<Vec<_>>(),
            "borrow_intent_ids": self.borrow_intents.keys().cloned().collect::<Vec<_>>(),
            "health_attestation_ids": self.health_attestations.keys().cloned().collect::<Vec<_>>(),
            "liquidation_ids": self.liquidation_queue.keys().cloned().collect::<Vec<_>>(),
            "sponsor_reservation_ids": self.sponsor_reservations.keys().cloned().collect::<Vec<_>>(),
            "settlement_receipt_ids": self.settlement_receipts.keys().cloned().collect::<Vec<_>>(),
            "rebate_ids": self.rebates.keys().cloned().collect::<Vec<_>>(),
            "risk_epoch_ids": self.risk_epochs.keys().cloned().collect::<Vec<_>>(),
            "event_ids": self.events.keys().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn register_market(&mut self, mut market: PrivateMarginMarket) -> Result<String> {
        if self.markets.len() >= self.config.max_markets {
            return Err("confidential token margin lending market capacity exceeded".to_string());
        }
        required("collateral_asset_id", &market.collateral_asset_id)?;
        required("debt_asset_id", &market.debt_asset_id)?;
        validate_privacy_and_pq(
            market.privacy_set_size,
            market.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        self.counters.market_counter = self.counters.market_counter.saturating_add(1);
        if market.market_id.trim().is_empty() {
            market.market_id = private_margin_market_id(
                &format!(
                    "{}:{}:{}",
                    market.collateral_asset_id, market.debt_asset_id, market.opened_at_height
                ),
                self.counters.market_counter,
            );
        }
        let id = market.market_id.clone();
        self.markets.insert(id.clone(), market);
        Ok(id)
    }

    pub fn add_collateral_note(
        &mut self,
        mut note: CollateralNote,
        nullifier: &str,
    ) -> Result<String> {
        if self.collateral_notes.len() + self.debt_notes.len() >= self.config.max_notes {
            return Err("confidential token margin lending note capacity exceeded".to_string());
        }
        self.require_market(&note.market_id)?;
        self.consume_nullifier(nullifier)?;
        validate_privacy_and_pq(
            note.privacy_set_size,
            note.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        self.counters.collateral_note_counter =
            self.counters.collateral_note_counter.saturating_add(1);
        if note.note_id.trim().is_empty() {
            note.note_id = collateral_note_id(
                &note.note_commitment_root,
                self.counters.collateral_note_counter,
            );
        }
        note.nullifier_hash = self.nullifier_hash(nullifier);
        let id = note.note_id.clone();
        self.collateral_notes.insert(id.clone(), note);
        Ok(id)
    }

    pub fn submit_borrow_intent(
        &mut self,
        mut intent: EncryptedBorrowIntent,
        nullifier: &str,
    ) -> Result<String> {
        if self.borrow_intents.len() >= self.config.max_borrow_intents {
            return Err(
                "confidential token margin lending borrow intent capacity exceeded".to_string(),
            );
        }
        let market = self.require_market(&intent.market_id)?;
        if !market.status.accepts_borrows() && intent.intent_kind.increases_debt() {
            return Err(
                "confidential token margin lending market does not accept borrows".to_string(),
            );
        }
        if intent.max_fee_bps > self.config.max_user_fee_bps {
            return Err(
                "confidential token margin lending fee exceeds configured maximum".to_string(),
            );
        }
        self.consume_nullifier(nullifier)?;
        validate_privacy_and_pq(
            intent.privacy_set_size,
            intent.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        self.counters.borrow_intent_counter = self.counters.borrow_intent_counter.saturating_add(1);
        if intent.intent_id.trim().is_empty() {
            intent.intent_id = borrow_intent_id(
                &intent.encrypted_payload_root,
                self.counters.borrow_intent_counter,
            );
        }
        intent.intent_nullifier_hash = self.nullifier_hash(nullifier);
        let id = intent.intent_id.clone();
        self.borrow_intents.insert(id.clone(), intent);
        Ok(id)
    }

    pub fn attest_health(
        &mut self,
        mut attestation: MarginHealthAttestation,
        nullifier: &str,
    ) -> Result<String> {
        self.require_market(&attestation.market_id)?;
        if !self.borrow_intents.contains_key(&attestation.intent_id) {
            return Err("confidential token margin lending borrow intent missing".to_string());
        }
        self.consume_nullifier(nullifier)?;
        validate_privacy_and_pq(
            attestation.privacy_set_size,
            attestation.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        self.counters.health_attestation_counter =
            self.counters.health_attestation_counter.saturating_add(1);
        if attestation.attestation_id.trim().is_empty() {
            attestation.attestation_id = health_attestation_id(
                &attestation.intent_id,
                self.counters.health_attestation_counter,
            );
        }
        attestation.attestation_nullifier_hash = self.nullifier_hash(nullifier);
        if let Some(intent) = self.borrow_intents.get_mut(&attestation.intent_id) {
            if attestation.verdict.allows_borrow() {
                intent.status = IntentStatus::HealthAttested;
            } else if attestation.verdict == HealthVerdict::Rejected {
                intent.status = IntentStatus::Rejected;
            }
        }
        let id = attestation.attestation_id.clone();
        self.health_attestations.insert(id.clone(), attestation);
        Ok(id)
    }

    pub fn queue_liquidation(
        &mut self,
        mut item: LiquidationQueueItem,
        nullifier: &str,
    ) -> Result<String> {
        if self.liquidation_queue.len() >= self.config.max_liquidation_queue {
            return Err(
                "confidential token margin lending liquidation queue capacity exceeded".to_string(),
            );
        }
        let market = self.require_market(&item.market_id)?;
        if !market.status.accepts_liquidations() {
            return Err(
                "confidential token margin lending market does not accept liquidations".to_string(),
            );
        }
        let attestation = self
            .health_attestations
            .get(&item.health_attestation_id)
            .ok_or_else(|| {
                "confidential token margin lending health attestation missing".to_string()
            })?;
        if !attestation.verdict.allows_liquidation() {
            return Err(
                "confidential token margin lending attestation is not liquidatable".to_string(),
            );
        }
        self.consume_nullifier(nullifier)?;
        validate_privacy_and_pq(
            item.privacy_set_size,
            item.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        self.counters.liquidation_queue_counter =
            self.counters.liquidation_queue_counter.saturating_add(1);
        if item.liquidation_id.trim().is_empty() {
            item.liquidation_id =
                liquidation_id(&item.intent_id, self.counters.liquidation_queue_counter);
        }
        item.liquidation_nullifier_hash = self.nullifier_hash(nullifier);
        let id = item.liquidation_id.clone();
        self.liquidation_queue.insert(id.clone(), item);
        Ok(id)
    }

    pub fn reserve_sponsor(
        &mut self,
        mut reservation: SponsorReservation,
        nullifier: &str,
    ) -> Result<String> {
        self.consume_nullifier(nullifier)?;
        self.counters.sponsor_reservation_counter =
            self.counters.sponsor_reservation_counter.saturating_add(1);
        if reservation.reservation_id.trim().is_empty() {
            reservation.reservation_id = sponsor_reservation_id(
                &reservation.target_id,
                self.counters.sponsor_reservation_counter,
            );
        }
        reservation.reservation_nullifier_hash = self.nullifier_hash(nullifier);
        let id = reservation.reservation_id.clone();
        self.sponsor_reservations.insert(id.clone(), reservation);
        Ok(id)
    }

    pub fn record_settlement_receipt(&mut self, mut receipt: SettlementReceipt) -> Result<String> {
        required("subject_id", &receipt.subject_id)?;
        required("settlement_proof_root", &receipt.settlement_proof_root)?;
        self.counters.settlement_receipt_counter =
            self.counters.settlement_receipt_counter.saturating_add(1);
        if receipt.receipt_id.trim().is_empty() {
            receipt.receipt_id = settlement_receipt_id(
                &receipt.subject_id,
                self.counters.settlement_receipt_counter,
            );
        }
        if receipt.state_root_after.trim().is_empty() {
            receipt.state_root_after = self.state_root();
        }
        let id = receipt.receipt_id.clone();
        self.settlement_receipts.insert(id.clone(), receipt);
        Ok(id)
    }

    pub fn credit_rebate(&mut self, mut rebate: RebateCredit, nullifier: &str) -> Result<String> {
        self.require_market(&rebate.market_id)?;
        self.consume_nullifier(nullifier)?;
        self.counters.rebate_counter = self.counters.rebate_counter.saturating_add(1);
        if rebate.rebate_id.trim().is_empty() {
            rebate.rebate_id = rebate_id(&rebate.source_receipt_id, self.counters.rebate_counter);
        }
        rebate.rebate_nullifier_hash = self.nullifier_hash(nullifier);
        let id = rebate.rebate_id.clone();
        self.rebates.insert(id.clone(), rebate);
        Ok(id)
    }

    pub fn roll_risk_epoch(&mut self, mut epoch: RiskEpoch) -> Result<String> {
        validate_privacy_and_pq(
            epoch.privacy_set_size,
            epoch.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        self.counters.risk_epoch_counter = self.counters.risk_epoch_counter.saturating_add(1);
        if epoch.epoch_id.trim().is_empty() {
            epoch.epoch_id = risk_epoch_id(epoch.epoch_index, self.counters.risk_epoch_counter);
        }
        let id = epoch.epoch_id.clone();
        self.risk_epochs.insert(id.clone(), epoch);
        Ok(id)
    }

    pub fn emit_event(
        &mut self,
        event_kind: &str,
        subject_id: &str,
        record_root: String,
        emitted_at_height: u64,
    ) -> String {
        self.counters.event_counter = self.counters.event_counter.saturating_add(1);
        let event_id = runtime_event_id(event_kind, subject_id, self.counters.event_counter);
        self.events.insert(
            event_id.clone(),
            RuntimeEvent {
                event_id: event_id.clone(),
                event_kind: event_kind.to_string(),
                subject_id: subject_id.to_string(),
                record_root,
                emitted_at_height,
            },
        );
        event_id
    }

    fn require_market(&self, market_id: &str) -> Result<&PrivateMarginMarket> {
        self.markets
            .get(market_id)
            .ok_or_else(|| "confidential token margin lending market does not exist".to_string())
    }

    fn consume_nullifier(&mut self, nullifier: &str) -> Result<()> {
        required("nullifier", nullifier)?;
        let nullifier_hash = self.nullifier_hash(nullifier);
        if !self.consumed_nullifiers.insert(nullifier_hash) {
            return Err("confidential token margin lending nullifier replay detected".to_string());
        }
        self.counters.consumed_nullifier_counter =
            self.counters.consumed_nullifier_counter.saturating_add(1);
        Ok(())
    }

    fn nullifier_hash(&self, nullifier: &str) -> String {
        payload_root(
            "PRIVATE-L2-TOKEN-MARGIN-LENDING-NULLIFIER",
            &json!({ "nullifier": nullifier }),
        )
    }
}

pub fn private_margin_market_id(seed: &str, counter: u64) -> String {
    deterministic_id("PRIVATE-L2-TOKEN-MARGIN-LENDING-MARKET-ID", seed, counter)
}

pub fn collateral_note_id(seed: &str, counter: u64) -> String {
    deterministic_id(
        "PRIVATE-L2-TOKEN-MARGIN-LENDING-COLLATERAL-NOTE-ID",
        seed,
        counter,
    )
}

pub fn debt_note_id(seed: &str, counter: u64) -> String {
    deterministic_id(
        "PRIVATE-L2-TOKEN-MARGIN-LENDING-DEBT-NOTE-ID",
        seed,
        counter,
    )
}

pub fn borrow_intent_id(seed: &str, counter: u64) -> String {
    deterministic_id(
        "PRIVATE-L2-TOKEN-MARGIN-LENDING-BORROW-INTENT-ID",
        seed,
        counter,
    )
}

pub fn health_attestation_id(seed: &str, counter: u64) -> String {
    deterministic_id(
        "PRIVATE-L2-TOKEN-MARGIN-LENDING-HEALTH-ATTESTATION-ID",
        seed,
        counter,
    )
}

pub fn liquidation_id(seed: &str, counter: u64) -> String {
    deterministic_id(
        "PRIVATE-L2-TOKEN-MARGIN-LENDING-LIQUIDATION-ID",
        seed,
        counter,
    )
}

pub fn sponsor_reservation_id(seed: &str, counter: u64) -> String {
    deterministic_id(
        "PRIVATE-L2-TOKEN-MARGIN-LENDING-SPONSOR-RESERVATION-ID",
        seed,
        counter,
    )
}

pub fn settlement_receipt_id(seed: &str, counter: u64) -> String {
    deterministic_id(
        "PRIVATE-L2-TOKEN-MARGIN-LENDING-SETTLEMENT-RECEIPT-ID",
        seed,
        counter,
    )
}

pub fn rebate_id(seed: &str, counter: u64) -> String {
    deterministic_id("PRIVATE-L2-TOKEN-MARGIN-LENDING-REBATE-ID", seed, counter)
}

pub fn risk_epoch_id(epoch_index: u64, counter: u64) -> String {
    deterministic_id(
        "PRIVATE-L2-TOKEN-MARGIN-LENDING-RISK-EPOCH-ID",
        &epoch_index.to_string(),
        counter,
    )
}

pub fn runtime_event_id(event_kind: &str, subject_id: &str, counter: u64) -> String {
    deterministic_id(
        "PRIVATE-L2-TOKEN-MARGIN-LENDING-EVENT-ID",
        &format!("{event_kind}:{subject_id}"),
        counter,
    )
}

pub fn deterministic_id(domain: &str, seed: &str, counter: u64) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(seed),
            HashPart::U64(counter),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_TOKEN_MARGIN_LENDING_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    root_from_record("PRIVATE-L2-TOKEN-MARGIN-LENDING-PUBLIC-RECORD", record)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-TOKEN-MARGIN-LENDING-STATE-FROM-RECORD", record)
}

fn map_root<T: PublicRecord>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(id, record)| json!({"id": id, "record_root": root_from_record(domain, &record.public_record())}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({"value_root": root_from_record(domain, &json!({"value": value}))}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn sample_root(domain: &str, seed: &str) -> String {
    payload_root(domain, &json!({ "devnet_seed": seed }))
}

fn sample_commitment(domain: &str, seed: &str) -> String {
    payload_root(domain, &json!({ "commitment_seed": seed }))
}

fn required(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!(
            "confidential token margin lending field {field} is required"
        ));
    }
    Ok(())
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> Result<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("confidential token margin lending privacy set below minimum".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err("confidential token margin lending PQ security bits below minimum".to_string());
    }
    Ok(())
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for PrivateMarginMarket {
    fn public_record(&self) -> Value {
        PrivateMarginMarket::public_record(self)
    }
}

impl PublicRecord for CollateralNote {
    fn public_record(&self) -> Value {
        CollateralNote::public_record(self)
    }
}

impl PublicRecord for DebtNote {
    fn public_record(&self) -> Value {
        DebtNote::public_record(self)
    }
}

impl PublicRecord for EncryptedBorrowIntent {
    fn public_record(&self) -> Value {
        EncryptedBorrowIntent::public_record(self)
    }
}

impl PublicRecord for MarginHealthAttestation {
    fn public_record(&self) -> Value {
        MarginHealthAttestation::public_record(self)
    }
}

impl PublicRecord for LiquidationQueueItem {
    fn public_record(&self) -> Value {
        LiquidationQueueItem::public_record(self)
    }
}

impl PublicRecord for SponsorReservation {
    fn public_record(&self) -> Value {
        SponsorReservation::public_record(self)
    }
}

impl PublicRecord for SettlementReceipt {
    fn public_record(&self) -> Value {
        SettlementReceipt::public_record(self)
    }
}

impl PublicRecord for RebateCredit {
    fn public_record(&self) -> Value {
        RebateCredit::public_record(self)
    }
}

impl PublicRecord for RiskEpoch {
    fn public_record(&self) -> Value {
        RiskEpoch::public_record(self)
    }
}

impl PublicRecord for RuntimeEvent {
    fn public_record(&self) -> Value {
        RuntimeEvent::public_record(self)
    }
}
