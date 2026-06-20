use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialOptionsVaultRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-options-vault-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_PQ_AUTH_SCHEME: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-options-vault-v1";
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_VAULT_SCHEME: &str =
    "monero-private-l2-confidential-options-vault-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_OPTION_SCHEME: &str =
    "monero-private-l2-confidential-option-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_PURCHASE_SCHEME: &str =
    "monero-private-l2-confidential-option-purchase-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_RISK_SCHEME: &str =
    "monero-private-l2-confidential-vault-risk-attestation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_BATCH_SCHEME: &str =
    "monero-private-l2-low-fee-confidential-options-batch-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_EXERCISE_SCHEME: &str =
    "monero-private-l2-confidential-option-exercise-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_RECEIPT_SCHEME: &str =
    "roots-only-confidential-options-vault-settlement-receipt-v1";
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEVNET_HEIGHT: u64 = 244_000;
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "devnet-private-l2-options-vault-low-fee";
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID: &str =
    "asset:wxmr";
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_QUOTE_ASSET_ID: &str =
    "asset:private-dusd";
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MAX_VAULTS: usize = 65_536;
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MAX_OPEN_OPTIONS: usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MAX_PURCHASES: usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize = 8_192;
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    32_768;
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MAX_VAULT_FEE_BPS: u64 = 80;
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MAX_PREMIUM_BPS: u64 = 5_000;
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MIN_COLLATERALIZATION_BPS: u64 =
    12_500;
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_LIQUIDATION_GUARD_BPS: u64 = 11_000;
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 10;
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_FAST_SETTLEMENT_BLOCKS: u64 = 2;
pub const PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionsVaultKind {
    CoveredCall,
    CashSecuredPut,
    Straddle,
    Strangle,
    VolatilityVault,
    PortfolioHedge,
}

impl OptionsVaultKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CoveredCall => "covered_call",
            Self::CashSecuredPut => "cash_secured_put",
            Self::Straddle => "straddle",
            Self::Strangle => "strangle",
            Self::VolatilityVault => "volatility_vault",
            Self::PortfolioHedge => "portfolio_hedge",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Open,
    RiskReview,
    WriteOnly,
    ExerciseOnly,
    Paused,
    Settling,
    Closed,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::RiskReview => "risk_review",
            Self::WriteOnly => "write_only",
            Self::ExerciseOnly => "exercise_only",
            Self::Paused => "paused",
            Self::Settling => "settling",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_writes(self) -> bool {
        matches!(self, Self::Open | Self::WriteOnly)
    }

    pub fn accepts_purchases(self) -> bool {
        matches!(self, Self::Open)
    }

    pub fn accepts_exercise(self) -> bool {
        matches!(self, Self::Open | Self::ExerciseOnly | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionKind {
    Call,
    Put,
    BinaryCall,
    BinaryPut,
    BarrierCall,
    BarrierPut,
}

impl OptionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Put => "put",
            Self::BinaryCall => "binary_call",
            Self::BinaryPut => "binary_put",
            Self::BarrierCall => "barrier_call",
            Self::BarrierPut => "barrier_put",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionStyle {
    European,
    American,
    Bermudan,
}

impl OptionStyle {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::European => "european",
            Self::American => "american",
            Self::Bermudan => "bermudan",
        }
    }

    pub fn can_exercise_before_expiry(self) -> bool {
        matches!(self, Self::American | Self::Bermudan)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionSide {
    Writer,
    Buyer,
}

impl OptionSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Writer => "writer",
            Self::Buyer => "buyer",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionStatus {
    Written,
    RiskAttested,
    Listed,
    Purchased,
    Batched,
    Settled,
    Exercised,
    Expired,
    Rejected,
}

impl OptionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Written => "written",
            Self::RiskAttested => "risk_attested",
            Self::Listed => "listed",
            Self::Purchased => "purchased",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Exercised => "exercised",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn buyable(self) -> bool {
        matches!(self, Self::Written | Self::RiskAttested | Self::Listed)
    }

    pub fn batchable(self) -> bool {
        matches!(
            self,
            Self::Written | Self::RiskAttested | Self::Listed | Self::Purchased
        )
    }

    pub fn exercisable(self) -> bool {
        matches!(self, Self::Purchased | Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurchaseStatus {
    Pending,
    Batched,
    Settled,
    Exercised,
    Expired,
    Rejected,
}

impl PurchaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Exercised => "exercised",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Pending)
    }

    pub fn exercisable(self) -> bool {
        matches!(self, Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultRiskVerdict {
    Healthy,
    Watch,
    RaiseCollateral,
    WriteOnly,
    ExerciseOnly,
    Halt,
    Rejected,
}

impl VaultRiskVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::RaiseCollateral => "raise_collateral",
            Self::WriteOnly => "write_only",
            Self::ExerciseOnly => "exercise_only",
            Self::Halt => "halt",
            Self::Rejected => "rejected",
        }
    }

    pub fn allows_batching(self) -> bool {
        matches!(self, Self::Healthy | Self::Watch | Self::RaiseCollateral)
    }

    pub fn vault_status(self) -> VaultStatus {
        match self {
            Self::Healthy => VaultStatus::Open,
            Self::Watch | Self::RaiseCollateral => VaultStatus::RiskReview,
            Self::WriteOnly => VaultStatus::WriteOnly,
            Self::ExerciseOnly => VaultStatus::ExerciseOnly,
            Self::Halt | Self::Rejected => VaultStatus::Paused,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionsBatchStatus {
    Open,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
    Rejected,
}

impl OptionsBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReceiptKind {
    VaultOpened,
    OptionWritten,
    OptionPurchased,
    RiskAttested,
    BatchSettled,
    OptionExercised,
}

impl SettlementReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VaultOpened => "vault_opened",
            Self::OptionWritten => "option_written",
            Self::OptionPurchased => "option_purchased",
            Self::RiskAttested => "risk_attested",
            Self::BatchSettled => "batch_settled",
            Self::OptionExercised => "option_exercised",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub low_fee_lane: String,
    pub collateral_asset_id: String,
    pub quote_asset_id: String,
    pub hash_suite: String,
    pub pq_authorization_scheme: String,
    pub vault_scheme: String,
    pub option_scheme: String,
    pub purchase_scheme: String,
    pub risk_scheme: String,
    pub batch_scheme: String,
    pub exercise_scheme: String,
    pub receipt_scheme: String,
    pub max_vaults: usize,
    pub max_open_options: usize,
    pub max_purchases: usize,
    pub max_risk_attestations: usize,
    pub max_batch_items: usize,
    pub min_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_vault_fee_bps: u64,
    pub max_premium_bps: u64,
    pub min_collateralization_bps: u64,
    pub liquidation_guard_bps: u64,
    pub settlement_ttl_blocks: u64,
    pub fast_settlement_blocks: u64,
    pub require_low_fee_sponsor: bool,
    pub require_oracle_bound: bool,
    pub require_roots_only_public_records: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MONERO_NETWORK
                .to_string(),
            l2_network: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_L2_NETWORK
                .to_string(),
            low_fee_lane: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_LOW_FEE_LANE
                .to_string(),
            collateral_asset_id:
                PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID
                    .to_string(),
            quote_asset_id: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_QUOTE_ASSET_ID
                .to_string(),
            hash_suite: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_HASH_SUITE.to_string(),
            pq_authorization_scheme: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_PQ_AUTH_SCHEME
                .to_string(),
            vault_scheme: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_VAULT_SCHEME.to_string(),
            option_scheme: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_OPTION_SCHEME.to_string(),
            purchase_scheme: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_PURCHASE_SCHEME
                .to_string(),
            risk_scheme: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_RISK_SCHEME.to_string(),
            batch_scheme: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_BATCH_SCHEME.to_string(),
            exercise_scheme: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_EXERCISE_SCHEME
                .to_string(),
            receipt_scheme: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_RECEIPT_SCHEME
                .to_string(),
            max_vaults: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MAX_VAULTS,
            max_open_options:
                PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MAX_OPEN_OPTIONS,
            max_purchases: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MAX_PURCHASES,
            max_risk_attestations:
                PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS,
            max_batch_items: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_vault_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MAX_VAULT_FEE_BPS,
            max_premium_bps: PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MAX_PREMIUM_BPS,
            min_collateralization_bps:
                PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_MIN_COLLATERALIZATION_BPS,
            liquidation_guard_bps:
                PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_LIQUIDATION_GUARD_BPS,
            settlement_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            fast_settlement_blocks:
                PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_DEFAULT_FAST_SETTLEMENT_BLOCKS,
            require_low_fee_sponsor: true,
            require_oracle_bound: true,
            require_roots_only_public_records: true,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<()> {
        require_non_empty("protocol version", &self.protocol_version)?;
        require_non_empty("chain id", &self.chain_id)?;
        require_non_empty("monero network", &self.monero_network)?;
        require_non_empty("L2 network", &self.l2_network)?;
        require_non_empty("low fee lane", &self.low_fee_lane)?;
        require_non_empty("collateral asset id", &self.collateral_asset_id)?;
        require_non_empty("quote asset id", &self.quote_asset_id)?;
        require_non_empty("hash suite", &self.hash_suite)?;
        require_non_empty("PQ authorization scheme", &self.pq_authorization_scheme)?;
        require_non_empty("vault scheme", &self.vault_scheme)?;
        require_non_empty("option scheme", &self.option_scheme)?;
        require_non_empty("purchase scheme", &self.purchase_scheme)?;
        require_non_empty("risk scheme", &self.risk_scheme)?;
        require_non_empty("batch scheme", &self.batch_scheme)?;
        require_non_empty("exercise scheme", &self.exercise_scheme)?;
        require_non_empty("receipt scheme", &self.receipt_scheme)?;
        if self.max_vaults == 0
            || self.max_open_options == 0
            || self.max_purchases == 0
            || self.max_risk_attestations == 0
            || self.max_batch_items == 0
        {
            return Err("options vault runtime capacities must be positive".to_string());
        }
        if self.max_batch_items > self.max_open_options || self.max_batch_items > self.max_purchases
        {
            return Err("options batch size exceeds note capacity".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.min_batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err("batch privacy set must cover individual privacy set".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("PQ authorization security floor is too low".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_MAX_BPS
            || self.max_vault_fee_bps > PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_MAX_BPS
            || self.max_premium_bps > PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_MAX_BPS
        {
            return Err("options bps policy exceeds range".to_string());
        }
        if self.min_collateralization_bps <= PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_MAX_BPS {
            return Err("vault collateralization must exceed full option exposure".to_string());
        }
        if self.liquidation_guard_bps <= PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_MAX_BPS
            || self.liquidation_guard_bps > self.min_collateralization_bps
        {
            return Err(
                "liquidation guard must be over 100% and below collateralization".to_string(),
            );
        }
        if self.settlement_ttl_blocks == 0 || self.fast_settlement_blocks == 0 {
            return Err("settlement windows must be positive".to_string());
        }
        if self.fast_settlement_blocks > self.settlement_ttl_blocks {
            return Err("fast settlement window cannot exceed settlement TTL".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "low_fee_lane": self.low_fee_lane,
            "collateral_asset_id": self.collateral_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "hash_suite": self.hash_suite,
            "pq_authorization_scheme": self.pq_authorization_scheme,
            "vault_scheme": self.vault_scheme,
            "option_scheme": self.option_scheme,
            "purchase_scheme": self.purchase_scheme,
            "risk_scheme": self.risk_scheme,
            "batch_scheme": self.batch_scheme,
            "exercise_scheme": self.exercise_scheme,
            "receipt_scheme": self.receipt_scheme,
            "max_vaults": self.max_vaults,
            "max_open_options": self.max_open_options,
            "max_purchases": self.max_purchases,
            "max_risk_attestations": self.max_risk_attestations,
            "max_batch_items": self.max_batch_items,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_batch_privacy_set_size": self.min_batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_vault_fee_bps": self.max_vault_fee_bps,
            "max_premium_bps": self.max_premium_bps,
            "min_collateralization_bps": self.min_collateralization_bps,
            "liquidation_guard_bps": self.liquidation_guard_bps,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "fast_settlement_blocks": self.fast_settlement_blocks,
            "require_low_fee_sponsor": self.require_low_fee_sponsor,
            "require_oracle_bound": self.require_oracle_bound,
            "require_roots_only_public_records": self.require_roots_only_public_records,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub vault_counter: u64,
    pub option_counter: u64,
    pub purchase_counter: u64,
    pub risk_attestation_counter: u64,
    pub batch_counter: u64,
    pub settlement_receipt_counter: u64,
    pub exercise_counter: u64,
    pub consumed_nullifier_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_counter": self.vault_counter,
            "option_counter": self.option_counter,
            "purchase_counter": self.purchase_counter,
            "risk_attestation_counter": self.risk_attestation_counter,
            "batch_counter": self.batch_counter,
            "settlement_receipt_counter": self.settlement_receipt_counter,
            "exercise_counter": self.exercise_counter,
            "consumed_nullifier_counter": self.consumed_nullifier_counter,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenOptionsVaultRequest {
    pub vault_kind: OptionsVaultKind,
    pub vault_owner_commitment: String,
    pub collateral_asset_root: String,
    pub quote_asset_root: String,
    pub reserve_note_root: String,
    pub strategy_root: String,
    pub oracle_root: String,
    pub risk_policy_root: String,
    pub pq_authority_root: String,
    pub privacy_policy_root: String,
    pub low_fee_sponsor_root: String,
    pub vault_nullifier: String,
    pub collateralization_bps: u64,
    pub max_premium_bps: u64,
    pub vault_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
}

impl OpenOptionsVaultRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<()> {
        require_non_empty("vault owner commitment", &self.vault_owner_commitment)?;
        require_non_empty("collateral asset root", &self.collateral_asset_root)?;
        require_non_empty("quote asset root", &self.quote_asset_root)?;
        require_non_empty("reserve note root", &self.reserve_note_root)?;
        require_non_empty("strategy root", &self.strategy_root)?;
        require_non_empty("risk policy root", &self.risk_policy_root)?;
        require_non_empty("PQ authority root", &self.pq_authority_root)?;
        require_non_empty("privacy policy root", &self.privacy_policy_root)?;
        require_non_empty("vault nullifier", &self.vault_nullifier)?;
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
        if self.collateralization_bps < config.min_collateralization_bps {
            return Err("vault collateralization below configured floor".to_string());
        }
        if self.max_premium_bps > config.max_premium_bps
            || self.vault_fee_bps > config.max_vault_fee_bps
        {
            return Err("vault premium or fee exceeds policy".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_kind": self.vault_kind.as_str(),
            "vault_owner_commitment": self.vault_owner_commitment,
            "collateral_asset_root": self.collateral_asset_root,
            "quote_asset_root": self.quote_asset_root,
            "reserve_note_root": self.reserve_note_root,
            "strategy_root": self.strategy_root,
            "oracle_root": self.oracle_root,
            "risk_policy_root": self.risk_policy_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_policy_root": self.privacy_policy_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "vault_nullifier": self.vault_nullifier,
            "collateralization_bps": self.collateralization_bps,
            "max_premium_bps": self.max_premium_bps,
            "vault_fee_bps": self.vault_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritePrivateOptionRequest {
    pub vault_id: String,
    pub writer_commitment: String,
    pub option_kind: OptionKind,
    pub option_style: OptionStyle,
    pub series_root: String,
    pub strike_commitment_root: String,
    pub notional_commitment_root: String,
    pub premium_commitment_root: String,
    pub collateral_note_root: String,
    pub expiry_commitment_root: String,
    pub oracle_bound_root: String,
    pub range_proof_root: String,
    pub privacy_proof_root: String,
    pub pq_authorization_root: String,
    pub low_fee_sponsor_root: String,
    pub option_nullifier: String,
    pub collateralization_bps: u64,
    pub premium_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub written_at_height: u64,
    pub expires_at_height: u64,
}

impl WritePrivateOptionRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<()> {
        require_non_empty("vault id", &self.vault_id)?;
        require_non_empty("writer commitment", &self.writer_commitment)?;
        require_non_empty("series root", &self.series_root)?;
        require_non_empty("strike commitment root", &self.strike_commitment_root)?;
        require_non_empty("notional commitment root", &self.notional_commitment_root)?;
        require_non_empty("premium commitment root", &self.premium_commitment_root)?;
        require_non_empty("collateral note root", &self.collateral_note_root)?;
        require_non_empty("expiry commitment root", &self.expiry_commitment_root)?;
        require_non_empty("range proof root", &self.range_proof_root)?;
        require_non_empty("privacy proof root", &self.privacy_proof_root)?;
        require_non_empty("PQ authorization root", &self.pq_authorization_root)?;
        require_non_empty("option nullifier", &self.option_nullifier)?;
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
        if self.collateralization_bps < config.min_collateralization_bps {
            return Err("option collateralization below configured floor".to_string());
        }
        if self.premium_bps > config.max_premium_bps || self.max_fee_bps > config.max_user_fee_bps {
            return Err("option premium or fee exceeds policy".to_string());
        }
        require_height_window(
            "private option",
            self.written_at_height,
            self.expires_at_height,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "writer_commitment": self.writer_commitment,
            "option_kind": self.option_kind.as_str(),
            "option_style": self.option_style.as_str(),
            "series_root": self.series_root,
            "strike_commitment_root": self.strike_commitment_root,
            "notional_commitment_root": self.notional_commitment_root,
            "premium_commitment_root": self.premium_commitment_root,
            "collateral_note_root": self.collateral_note_root,
            "expiry_commitment_root": self.expiry_commitment_root,
            "oracle_bound_root": self.oracle_bound_root,
            "range_proof_root": self.range_proof_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "option_nullifier": self.option_nullifier,
            "collateralization_bps": self.collateralization_bps,
            "premium_bps": self.premium_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "written_at_height": self.written_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuyPrivateOptionRequest {
    pub vault_id: String,
    pub option_id: String,
    pub buyer_commitment: String,
    pub premium_payment_root: String,
    pub buyer_note_root: String,
    pub delivery_address_root: String,
    pub slippage_guard_root: String,
    pub oracle_bound_root: String,
    pub privacy_proof_root: String,
    pub pq_authorization_root: String,
    pub low_fee_sponsor_root: String,
    pub purchase_nullifier: String,
    pub premium_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub purchased_at_height: u64,
    pub expires_at_height: u64,
}

impl BuyPrivateOptionRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<()> {
        require_non_empty("vault id", &self.vault_id)?;
        require_non_empty("option id", &self.option_id)?;
        require_non_empty("buyer commitment", &self.buyer_commitment)?;
        require_non_empty("premium payment root", &self.premium_payment_root)?;
        require_non_empty("buyer note root", &self.buyer_note_root)?;
        require_non_empty("delivery address root", &self.delivery_address_root)?;
        require_non_empty("slippage guard root", &self.slippage_guard_root)?;
        require_non_empty("privacy proof root", &self.privacy_proof_root)?;
        require_non_empty("PQ authorization root", &self.pq_authorization_root)?;
        require_non_empty("purchase nullifier", &self.purchase_nullifier)?;
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
        if self.premium_bps > config.max_premium_bps || self.max_fee_bps > config.max_user_fee_bps {
            return Err("option purchase premium or fee exceeds policy".to_string());
        }
        require_height_window(
            "private option purchase",
            self.purchased_at_height,
            self.expires_at_height,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "option_id": self.option_id,
            "buyer_commitment": self.buyer_commitment,
            "premium_payment_root": self.premium_payment_root,
            "buyer_note_root": self.buyer_note_root,
            "delivery_address_root": self.delivery_address_root,
            "slippage_guard_root": self.slippage_guard_root,
            "oracle_bound_root": self.oracle_bound_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "purchase_nullifier": self.purchase_nullifier,
            "premium_bps": self.premium_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "purchased_at_height": self.purchased_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestVaultRiskRequest {
    pub vault_id: String,
    pub attestor_commitment: String,
    pub verdict: VaultRiskVerdict,
    pub risk_score_bps: u64,
    pub collateralization_bps: u64,
    pub exposure_commitment_root: String,
    pub implied_volatility_root: String,
    pub oracle_root: String,
    pub scenario_set_root: String,
    pub proof_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub attestation_nullifier: String,
    pub vault_state_root_before: String,
    pub vault_state_root_after: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl AttestVaultRiskRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<()> {
        require_non_empty("vault id", &self.vault_id)?;
        require_non_empty("attestor commitment", &self.attestor_commitment)?;
        require_non_empty("exposure commitment root", &self.exposure_commitment_root)?;
        require_non_empty("implied volatility root", &self.implied_volatility_root)?;
        require_non_empty("oracle root", &self.oracle_root)?;
        require_non_empty("scenario set root", &self.scenario_set_root)?;
        require_non_empty("proof root", &self.proof_root)?;
        require_non_empty("PQ authorization root", &self.pq_authorization_root)?;
        require_non_empty("privacy proof root", &self.privacy_proof_root)?;
        require_non_empty("attestation nullifier", &self.attestation_nullifier)?;
        require_non_empty("vault state root before", &self.vault_state_root_before)?;
        require_non_empty("vault state root after", &self.vault_state_root_after)?;
        require_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.risk_score_bps > PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_MAX_BPS {
            return Err("vault risk score exceeds bps range".to_string());
        }
        if self.verdict.allows_batching()
            && self.collateralization_bps < config.liquidation_guard_bps
        {
            return Err("batch-allowing risk verdict has insufficient collateral".to_string());
        }
        if matches!(self.verdict, VaultRiskVerdict::Healthy)
            && self.collateralization_bps < config.min_collateralization_bps
        {
            return Err("healthy verdict requires configured collateralization floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "attestor_commitment": self.attestor_commitment,
            "verdict": self.verdict.as_str(),
            "risk_score_bps": self.risk_score_bps,
            "collateralization_bps": self.collateralization_bps,
            "exposure_commitment_root": self.exposure_commitment_root,
            "implied_volatility_root": self.implied_volatility_root,
            "oracle_root": self.oracle_root,
            "scenario_set_root": self.scenario_set_root,
            "proof_root": self.proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "attestation_nullifier": self.attestation_nullifier,
            "vault_state_root_before": self.vault_state_root_before,
            "vault_state_root_after": self.vault_state_root_after,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildOptionsBatchRequest {
    pub vault_id: String,
    pub option_ids: Vec<String>,
    pub purchase_ids: Vec<String>,
    pub batcher_commitment: String,
    pub matching_root: String,
    pub settlement_call_root: String,
    pub premium_netting_root: String,
    pub collateral_delta_root: String,
    pub recursive_batch_proof_root: String,
    pub da_commitment_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_batch_authorization_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub built_at_height: u64,
    pub expires_at_height: u64,
}

impl BuildOptionsBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<()> {
        require_non_empty("vault id", &self.vault_id)?;
        require_non_empty("batcher commitment", &self.batcher_commitment)?;
        require_non_empty("matching root", &self.matching_root)?;
        require_non_empty("settlement call root", &self.settlement_call_root)?;
        require_non_empty("premium netting root", &self.premium_netting_root)?;
        require_non_empty("collateral delta root", &self.collateral_delta_root)?;
        require_non_empty(
            "recursive batch proof root",
            &self.recursive_batch_proof_root,
        )?;
        require_non_empty("DA commitment root", &self.da_commitment_root)?;
        require_non_empty(
            "PQ batch authorization root",
            &self.pq_batch_authorization_root,
        )?;
        if config.require_low_fee_sponsor {
            require_non_empty("low fee sponsor root", &self.low_fee_sponsor_root)?;
        }
        let item_count = self
            .option_ids
            .len()
            .saturating_add(self.purchase_ids.len());
        if item_count == 0 || item_count > config.max_batch_items {
            return Err("options batch size is outside policy".to_string());
        }
        if self.privacy_set_size < config.min_batch_privacy_set_size {
            return Err("options batch privacy set below configured minimum".to_string());
        }
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("options batch fee exceeds low-fee cap".to_string());
        }
        require_height_window(
            "options batch",
            self.built_at_height,
            self.expires_at_height,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "option_ids": self.option_ids,
            "purchase_ids": self.purchase_ids,
            "batcher_commitment": self.batcher_commitment,
            "matching_root": self.matching_root,
            "settlement_call_root": self.settlement_call_root,
            "premium_netting_root": self.premium_netting_root,
            "collateral_delta_root": self.collateral_delta_root,
            "recursive_batch_proof_root": self.recursive_batch_proof_root,
            "da_commitment_root": self.da_commitment_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_batch_authorization_root": self.pq_batch_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "built_at_height": self.built_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleOptionsBatchRequest {
    pub batch_id: String,
    pub settlement_publisher_commitment: String,
    pub settlement_proof_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub receipt_root: String,
    pub low_fee_sponsor_receipt_root: String,
    pub pq_settlement_authorization_root: String,
    pub settled_at_height: u64,
}

impl SettleOptionsBatchRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<()> {
        require_non_empty("batch id", &self.batch_id)?;
        require_non_empty(
            "settlement publisher commitment",
            &self.settlement_publisher_commitment,
        )?;
        require_non_empty("settlement proof root", &self.settlement_proof_root)?;
        require_non_empty("state root before", &self.state_root_before)?;
        require_non_empty("state root after", &self.state_root_after)?;
        require_non_empty("receipt root", &self.receipt_root)?;
        require_non_empty(
            "PQ settlement authorization root",
            &self.pq_settlement_authorization_root,
        )?;
        if config.require_low_fee_sponsor {
            require_non_empty(
                "low fee sponsor receipt root",
                &self.low_fee_sponsor_receipt_root,
            )?;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "settlement_publisher_commitment": self.settlement_publisher_commitment,
            "settlement_proof_root": self.settlement_proof_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "receipt_root": self.receipt_root,
            "low_fee_sponsor_receipt_root": self.low_fee_sponsor_receipt_root,
            "pq_settlement_authorization_root": self.pq_settlement_authorization_root,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExerciseOptionRequest {
    pub vault_id: String,
    pub option_id: String,
    pub purchase_id: String,
    pub exerciser_commitment: String,
    pub exercise_note_root: String,
    pub settlement_price_root: String,
    pub payoff_commitment_root: String,
    pub collateral_release_root: String,
    pub delivery_root: String,
    pub oracle_bound_root: String,
    pub privacy_proof_root: String,
    pub pq_authorization_root: String,
    pub low_fee_sponsor_root: String,
    pub exercise_nullifier: String,
    pub exercise_window_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub exercised_at_height: u64,
}

impl ExerciseOptionRequest {
    pub fn validate(&self, config: &Config) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<()> {
        require_non_empty("vault id", &self.vault_id)?;
        require_non_empty("option id", &self.option_id)?;
        require_non_empty("purchase id", &self.purchase_id)?;
        require_non_empty("exerciser commitment", &self.exerciser_commitment)?;
        require_non_empty("exercise note root", &self.exercise_note_root)?;
        require_non_empty("settlement price root", &self.settlement_price_root)?;
        require_non_empty("payoff commitment root", &self.payoff_commitment_root)?;
        require_non_empty("collateral release root", &self.collateral_release_root)?;
        require_non_empty("delivery root", &self.delivery_root)?;
        require_non_empty("privacy proof root", &self.privacy_proof_root)?;
        require_non_empty("PQ authorization root", &self.pq_authorization_root)?;
        require_non_empty("exercise nullifier", &self.exercise_nullifier)?;
        require_non_empty("exercise window root", &self.exercise_window_root)?;
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
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("option exercise fee exceeds low-fee cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "option_id": self.option_id,
            "purchase_id": self.purchase_id,
            "exerciser_commitment": self.exerciser_commitment,
            "exercise_note_root": self.exercise_note_root,
            "settlement_price_root": self.settlement_price_root,
            "payoff_commitment_root": self.payoff_commitment_root,
            "collateral_release_root": self.collateral_release_root,
            "delivery_root": self.delivery_root,
            "oracle_bound_root": self.oracle_bound_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "exercise_nullifier": self.exercise_nullifier,
            "exercise_window_root": self.exercise_window_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "exercised_at_height": self.exercised_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionsVaultRecord {
    pub vault_id: String,
    pub vault_kind: OptionsVaultKind,
    pub status: VaultStatus,
    pub vault_owner_commitment: String,
    pub collateral_asset_root: String,
    pub quote_asset_root: String,
    pub reserve_note_root: String,
    pub strategy_root: String,
    pub oracle_root: String,
    pub risk_policy_root: String,
    pub pq_authority_root: String,
    pub privacy_policy_root: String,
    pub low_fee_sponsor_root: String,
    pub latest_vault_state_root: String,
    pub latest_risk_attestation_id: Option<String>,
    pub collateralization_bps: u64,
    pub max_premium_bps: u64,
    pub vault_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
}

impl OptionsVaultRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "vault_kind": self.vault_kind.as_str(),
            "status": self.status.as_str(),
            "vault_owner_commitment": self.vault_owner_commitment,
            "collateral_asset_root": self.collateral_asset_root,
            "quote_asset_root": self.quote_asset_root,
            "reserve_note_root": self.reserve_note_root,
            "strategy_root": self.strategy_root,
            "oracle_root": self.oracle_root,
            "risk_policy_root": self.risk_policy_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_policy_root": self.privacy_policy_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "latest_vault_state_root": self.latest_vault_state_root,
            "latest_risk_attestation_id": self.latest_risk_attestation_id,
            "collateralization_bps": self.collateralization_bps,
            "max_premium_bps": self.max_premium_bps,
            "vault_fee_bps": self.vault_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOptionRecord {
    pub option_id: String,
    pub vault_id: String,
    pub writer_commitment: String,
    pub option_kind: OptionKind,
    pub option_style: OptionStyle,
    pub status: OptionStatus,
    pub series_root: String,
    pub strike_commitment_root: String,
    pub notional_commitment_root: String,
    pub premium_commitment_root: String,
    pub collateral_note_root: String,
    pub expiry_commitment_root: String,
    pub oracle_bound_root: String,
    pub range_proof_root: String,
    pub privacy_proof_root: String,
    pub pq_authorization_root: String,
    pub low_fee_sponsor_root: String,
    pub latest_purchase_id: Option<String>,
    pub latest_batch_id: Option<String>,
    pub latest_exercise_id: Option<String>,
    pub collateralization_bps: u64,
    pub premium_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub written_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivateOptionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "option_id": self.option_id,
            "vault_id": self.vault_id,
            "writer_commitment": self.writer_commitment,
            "option_kind": self.option_kind.as_str(),
            "option_style": self.option_style.as_str(),
            "status": self.status.as_str(),
            "series_root": self.series_root,
            "strike_commitment_root": self.strike_commitment_root,
            "notional_commitment_root": self.notional_commitment_root,
            "premium_commitment_root": self.premium_commitment_root,
            "collateral_note_root": self.collateral_note_root,
            "expiry_commitment_root": self.expiry_commitment_root,
            "oracle_bound_root": self.oracle_bound_root,
            "range_proof_root": self.range_proof_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "latest_purchase_id": self.latest_purchase_id,
            "latest_batch_id": self.latest_batch_id,
            "latest_exercise_id": self.latest_exercise_id,
            "collateralization_bps": self.collateralization_bps,
            "premium_bps": self.premium_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "written_at_height": self.written_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionPurchaseRecord {
    pub purchase_id: String,
    pub vault_id: String,
    pub option_id: String,
    pub buyer_commitment: String,
    pub status: PurchaseStatus,
    pub premium_payment_root: String,
    pub buyer_note_root: String,
    pub delivery_address_root: String,
    pub slippage_guard_root: String,
    pub oracle_bound_root: String,
    pub privacy_proof_root: String,
    pub pq_authorization_root: String,
    pub low_fee_sponsor_root: String,
    pub latest_batch_id: Option<String>,
    pub latest_exercise_id: Option<String>,
    pub premium_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub purchased_at_height: u64,
    pub expires_at_height: u64,
}

impl OptionPurchaseRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "purchase_id": self.purchase_id,
            "vault_id": self.vault_id,
            "option_id": self.option_id,
            "buyer_commitment": self.buyer_commitment,
            "status": self.status.as_str(),
            "premium_payment_root": self.premium_payment_root,
            "buyer_note_root": self.buyer_note_root,
            "delivery_address_root": self.delivery_address_root,
            "slippage_guard_root": self.slippage_guard_root,
            "oracle_bound_root": self.oracle_bound_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "latest_batch_id": self.latest_batch_id,
            "latest_exercise_id": self.latest_exercise_id,
            "premium_bps": self.premium_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "purchased_at_height": self.purchased_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRiskAttestationRecord {
    pub attestation_id: String,
    pub vault_id: String,
    pub attestor_commitment: String,
    pub verdict: VaultRiskVerdict,
    pub risk_score_bps: u64,
    pub collateralization_bps: u64,
    pub exposure_commitment_root: String,
    pub implied_volatility_root: String,
    pub oracle_root: String,
    pub scenario_set_root: String,
    pub proof_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub vault_state_root_before: String,
    pub vault_state_root_after: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl VaultRiskAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "vault_id": self.vault_id,
            "attestor_commitment": self.attestor_commitment,
            "verdict": self.verdict.as_str(),
            "risk_score_bps": self.risk_score_bps,
            "collateralization_bps": self.collateralization_bps,
            "exposure_commitment_root": self.exposure_commitment_root,
            "implied_volatility_root": self.implied_volatility_root,
            "oracle_root": self.oracle_root,
            "scenario_set_root": self.scenario_set_root,
            "proof_root": self.proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "vault_state_root_before": self.vault_state_root_before,
            "vault_state_root_after": self.vault_state_root_after,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionsBatchRecord {
    pub batch_id: String,
    pub vault_id: String,
    pub option_ids: Vec<String>,
    pub purchase_ids: Vec<String>,
    pub status: OptionsBatchStatus,
    pub batcher_commitment: String,
    pub matching_root: String,
    pub settlement_call_root: String,
    pub premium_netting_root: String,
    pub collateral_delta_root: String,
    pub recursive_batch_proof_root: String,
    pub da_commitment_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_batch_authorization_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub built_at_height: u64,
    pub expires_at_height: u64,
    pub settled_at_height: Option<u64>,
}

impl OptionsBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "vault_id": self.vault_id,
            "option_ids": self.option_ids,
            "purchase_ids": self.purchase_ids,
            "status": self.status.as_str(),
            "batcher_commitment": self.batcher_commitment,
            "matching_root": self.matching_root,
            "settlement_call_root": self.settlement_call_root,
            "premium_netting_root": self.premium_netting_root,
            "collateral_delta_root": self.collateral_delta_root,
            "recursive_batch_proof_root": self.recursive_batch_proof_root,
            "da_commitment_root": self.da_commitment_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_batch_authorization_root": self.pq_batch_authorization_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "built_at_height": self.built_at_height,
            "expires_at_height": self.expires_at_height,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionsSettlementReceipt {
    pub receipt_id: String,
    pub kind: SettlementReceiptKind,
    pub subject_id: String,
    pub subject_root: String,
    pub batch_id: Option<String>,
    pub state_root_before: String,
    pub state_root_after: String,
    pub low_fee_sponsor_receipt_root: String,
    pub pq_authorization_root: String,
    pub published_at_height: u64,
}

impl OptionsSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "batch_id": self.batch_id,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "low_fee_sponsor_receipt_root": self.low_fee_sponsor_receipt_root,
            "pq_authorization_root": self.pq_authorization_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionExerciseRecord {
    pub exercise_id: String,
    pub vault_id: String,
    pub option_id: String,
    pub purchase_id: String,
    pub exerciser_commitment: String,
    pub exercise_note_root: String,
    pub settlement_price_root: String,
    pub payoff_commitment_root: String,
    pub collateral_release_root: String,
    pub delivery_root: String,
    pub oracle_bound_root: String,
    pub privacy_proof_root: String,
    pub pq_authorization_root: String,
    pub low_fee_sponsor_root: String,
    pub exercise_window_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub exercised_at_height: u64,
}

impl OptionExerciseRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "exercise_id": self.exercise_id,
            "vault_id": self.vault_id,
            "option_id": self.option_id,
            "purchase_id": self.purchase_id,
            "exerciser_commitment": self.exerciser_commitment,
            "exercise_note_root": self.exercise_note_root,
            "settlement_price_root": self.settlement_price_root,
            "payoff_commitment_root": self.payoff_commitment_root,
            "collateral_release_root": self.collateral_release_root,
            "delivery_root": self.delivery_root,
            "oracle_bound_root": self.oracle_bound_root,
            "privacy_proof_root": self.privacy_proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "exercise_window_root": self.exercise_window_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "exercised_at_height": self.exercised_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub vault_root: String,
    pub option_root: String,
    pub purchase_root: String,
    pub risk_attestation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub exercise_root: String,
    pub consumed_nullifier_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_root": self.vault_root,
            "option_root": self.option_root,
            "purchase_root": self.purchase_root,
            "risk_attestation_root": self.risk_attestation_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "exercise_root": self.exercise_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "event_root": self.event_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub vaults: BTreeMap<String, OptionsVaultRecord>,
    pub options: BTreeMap<String, PrivateOptionRecord>,
    pub purchases: BTreeMap<String, OptionPurchaseRecord>,
    pub risk_attestations: BTreeMap<String, VaultRiskAttestationRecord>,
    pub batches: BTreeMap<String, OptionsBatchRecord>,
    pub receipts: BTreeMap<String, OptionsSettlementReceipt>,
    pub exercises: BTreeMap<String, OptionExerciseRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub events: Vec<Value>,
}

impl State {
    pub fn devnet() -> Self {
        Self::with_config(Config::devnet()).expect("devnet options vault config")
    }

    pub fn with_config(config: Config) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            vaults: BTreeMap::new(),
            options: BTreeMap::new(),
            purchases: BTreeMap::new(),
            risk_attestations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            exercises: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            events: Vec::new(),
        })
    }

    pub fn open_options_vault(
        &mut self,
        request: OpenOptionsVaultRequest,
    ) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<OptionsVaultRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        self.ensure_new_nullifier(&request.vault_nullifier)?;
        if self.vaults.len() >= self.config.max_vaults {
            return Err("options vault capacity exceeded".to_string());
        }

        let sequence = self.counters.vault_counter.saturating_add(1);
        let latest_vault_state_root = payload_root(
            "PRIVATE-L2-CONFIDENTIAL-OPTIONS-VAULT-OPEN-STATE",
            &request.public_record(),
        );
        let vault_id = options_vault_id(
            sequence,
            request.vault_kind,
            &request.vault_owner_commitment,
            &request.reserve_note_root,
            &request.strategy_root,
            &request.vault_nullifier,
            request.opened_at_height,
        );
        if self.vaults.contains_key(&vault_id) {
            return Err("options vault id collision".to_string());
        }

        let record = OptionsVaultRecord {
            vault_id: vault_id.clone(),
            vault_kind: request.vault_kind,
            status: VaultStatus::Open,
            vault_owner_commitment: request.vault_owner_commitment,
            collateral_asset_root: request.collateral_asset_root,
            quote_asset_root: request.quote_asset_root,
            reserve_note_root: request.reserve_note_root,
            strategy_root: request.strategy_root,
            oracle_root: request.oracle_root,
            risk_policy_root: request.risk_policy_root,
            pq_authority_root: request.pq_authority_root,
            privacy_policy_root: request.privacy_policy_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            latest_vault_state_root,
            latest_risk_attestation_id: None,
            collateralization_bps: request.collateralization_bps,
            max_premium_bps: request.max_premium_bps,
            vault_fee_bps: request.vault_fee_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            opened_at_height: request.opened_at_height,
        };

        self.vaults.insert(vault_id.clone(), record.clone());
        self.consume_nullifier(request.vault_nullifier);
        self.counters.vault_counter = sequence;
        self.push_event(
            SettlementReceiptKind::VaultOpened,
            &vault_id,
            &record.public_record(),
            request.opened_at_height,
        );
        Ok(record)
    }

    pub fn write_private_option(
        &mut self,
        request: WritePrivateOptionRequest,
    ) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<PrivateOptionRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        self.ensure_new_nullifier(&request.option_nullifier)?;
        if self.options.len() >= self.config.max_open_options {
            return Err("private option capacity exceeded".to_string());
        }
        let vault = self
            .vaults
            .get(&request.vault_id)
            .ok_or_else(|| "unknown options vault".to_string())?;
        if !vault.status.accepts_writes() {
            return Err("options vault does not accept writes".to_string());
        }
        if request.collateralization_bps < vault.collateralization_bps {
            return Err("private option collateralization below vault floor".to_string());
        }
        if request.premium_bps > vault.max_premium_bps {
            return Err("private option premium exceeds vault policy".to_string());
        }

        let sequence = self.counters.option_counter.saturating_add(1);
        let option_id = private_option_id(
            sequence,
            &request.vault_id,
            &request.writer_commitment,
            request.option_kind,
            request.option_style,
            &request.series_root,
            &request.option_nullifier,
            request.written_at_height,
        );
        if self.options.contains_key(&option_id) {
            return Err("private option id collision".to_string());
        }

        let record = PrivateOptionRecord {
            option_id: option_id.clone(),
            vault_id: request.vault_id.clone(),
            writer_commitment: request.writer_commitment,
            option_kind: request.option_kind,
            option_style: request.option_style,
            status: OptionStatus::Written,
            series_root: request.series_root,
            strike_commitment_root: request.strike_commitment_root,
            notional_commitment_root: request.notional_commitment_root,
            premium_commitment_root: request.premium_commitment_root,
            collateral_note_root: request.collateral_note_root,
            expiry_commitment_root: request.expiry_commitment_root,
            oracle_bound_root: request.oracle_bound_root,
            range_proof_root: request.range_proof_root,
            privacy_proof_root: request.privacy_proof_root,
            pq_authorization_root: request.pq_authorization_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            latest_purchase_id: None,
            latest_batch_id: None,
            latest_exercise_id: None,
            collateralization_bps: request.collateralization_bps,
            premium_bps: request.premium_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            written_at_height: request.written_at_height,
            expires_at_height: request.expires_at_height,
        };

        self.options.insert(option_id.clone(), record.clone());
        self.consume_nullifier(request.option_nullifier);
        self.counters.option_counter = sequence;
        self.push_event(
            SettlementReceiptKind::OptionWritten,
            &option_id,
            &record.public_record(),
            request.written_at_height,
        );
        Ok(record)
    }

    pub fn buy_private_option(
        &mut self,
        request: BuyPrivateOptionRequest,
    ) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<OptionPurchaseRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        self.ensure_new_nullifier(&request.purchase_nullifier)?;
        if self.purchases.len() >= self.config.max_purchases {
            return Err("private option purchase capacity exceeded".to_string());
        }
        let vault = self
            .vaults
            .get(&request.vault_id)
            .ok_or_else(|| "unknown options vault".to_string())?;
        if !vault.status.accepts_purchases() {
            return Err("options vault does not accept purchases".to_string());
        }
        let option = self
            .options
            .get(&request.option_id)
            .ok_or_else(|| "unknown private option".to_string())?;
        if option.vault_id != request.vault_id {
            return Err("private option is not in requested vault".to_string());
        }
        if !option.status.buyable() {
            return Err("private option is not buyable".to_string());
        }
        if request.purchased_at_height >= option.expires_at_height {
            return Err("private option purchase occurs at or after expiry".to_string());
        }
        if request.premium_bps > option.premium_bps {
            return Err("private option purchase premium exceeds writer commitment".to_string());
        }

        let sequence = self.counters.purchase_counter.saturating_add(1);
        let purchase_id = option_purchase_id(
            sequence,
            &request.vault_id,
            &request.option_id,
            &request.buyer_commitment,
            &request.premium_payment_root,
            &request.purchase_nullifier,
            request.purchased_at_height,
        );
        if self.purchases.contains_key(&purchase_id) {
            return Err("private option purchase id collision".to_string());
        }

        let record = OptionPurchaseRecord {
            purchase_id: purchase_id.clone(),
            vault_id: request.vault_id,
            option_id: request.option_id.clone(),
            buyer_commitment: request.buyer_commitment,
            status: PurchaseStatus::Pending,
            premium_payment_root: request.premium_payment_root,
            buyer_note_root: request.buyer_note_root,
            delivery_address_root: request.delivery_address_root,
            slippage_guard_root: request.slippage_guard_root,
            oracle_bound_root: request.oracle_bound_root,
            privacy_proof_root: request.privacy_proof_root,
            pq_authorization_root: request.pq_authorization_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            latest_batch_id: None,
            latest_exercise_id: None,
            premium_bps: request.premium_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            purchased_at_height: request.purchased_at_height,
            expires_at_height: request.expires_at_height,
        };

        if let Some(option) = self.options.get_mut(&request.option_id) {
            option.status = OptionStatus::Purchased;
            option.latest_purchase_id = Some(purchase_id.clone());
        }
        self.purchases.insert(purchase_id.clone(), record.clone());
        self.consume_nullifier(request.purchase_nullifier);
        self.counters.purchase_counter = sequence;
        self.push_event(
            SettlementReceiptKind::OptionPurchased,
            &purchase_id,
            &record.public_record(),
            request.purchased_at_height,
        );
        Ok(record)
    }

    pub fn attest_vault_risk(
        &mut self,
        request: AttestVaultRiskRequest,
    ) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<VaultRiskAttestationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        self.ensure_new_nullifier(&request.attestation_nullifier)?;
        if self.risk_attestations.len() >= self.config.max_risk_attestations {
            return Err("vault risk attestation capacity exceeded".to_string());
        }
        if !self.vaults.contains_key(&request.vault_id) {
            return Err("unknown options vault".to_string());
        }

        let sequence = self.counters.risk_attestation_counter.saturating_add(1);
        let attestation_id = vault_risk_attestation_id(
            sequence,
            &request.vault_id,
            request.verdict,
            &request.attestor_commitment,
            &request.vault_state_root_after,
            &request.attestation_nullifier,
            request.attested_at_height,
        );
        if self.risk_attestations.contains_key(&attestation_id) {
            return Err("vault risk attestation id collision".to_string());
        }

        let record = VaultRiskAttestationRecord {
            attestation_id: attestation_id.clone(),
            vault_id: request.vault_id.clone(),
            attestor_commitment: request.attestor_commitment,
            verdict: request.verdict,
            risk_score_bps: request.risk_score_bps,
            collateralization_bps: request.collateralization_bps,
            exposure_commitment_root: request.exposure_commitment_root,
            implied_volatility_root: request.implied_volatility_root,
            oracle_root: request.oracle_root,
            scenario_set_root: request.scenario_set_root,
            proof_root: request.proof_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            vault_state_root_before: request.vault_state_root_before,
            vault_state_root_after: request.vault_state_root_after.clone(),
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            attested_at_height: request.attested_at_height,
        };

        if let Some(vault) = self.vaults.get_mut(&request.vault_id) {
            vault.latest_vault_state_root = request.vault_state_root_after;
            vault.latest_risk_attestation_id = Some(attestation_id.clone());
            vault.status = request.verdict.vault_status();
            vault.collateralization_bps = request.collateralization_bps;
        }
        self.risk_attestations
            .insert(attestation_id.clone(), record.clone());
        self.consume_nullifier(request.attestation_nullifier);
        self.counters.risk_attestation_counter = sequence;
        self.push_event(
            SettlementReceiptKind::RiskAttested,
            &attestation_id,
            &record.public_record(),
            request.attested_at_height,
        );
        Ok(record)
    }

    pub fn build_options_batch(
        &mut self,
        request: BuildOptionsBatchRequest,
    ) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<OptionsBatchRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let vault = self
            .vaults
            .get(&request.vault_id)
            .ok_or_else(|| "unknown options vault".to_string())?;
        if matches!(vault.status, VaultStatus::Paused | VaultStatus::Closed) {
            return Err("options vault does not accept batching".to_string());
        }
        for option_id in &request.option_ids {
            let option = self
                .options
                .get(option_id)
                .ok_or_else(|| format!("unknown private option {option_id}"))?;
            if option.vault_id != request.vault_id {
                return Err("option batch crosses vault boundaries".to_string());
            }
            if !option.status.batchable() {
                return Err("private option is not batchable".to_string());
            }
            if request.built_at_height >= option.expires_at_height {
                return Err("private option expired before batch build".to_string());
            }
        }
        for purchase_id in &request.purchase_ids {
            let purchase = self
                .purchases
                .get(purchase_id)
                .ok_or_else(|| format!("unknown private option purchase {purchase_id}"))?;
            if purchase.vault_id != request.vault_id {
                return Err("purchase batch crosses vault boundaries".to_string());
            }
            if !purchase.status.batchable() {
                return Err("private option purchase is not batchable".to_string());
            }
            if request.built_at_height >= purchase.expires_at_height {
                return Err("private option purchase expired before batch build".to_string());
            }
        }

        let sequence = self.counters.batch_counter.saturating_add(1);
        let batch_id = options_batch_id(
            sequence,
            &request.vault_id,
            &request.option_ids,
            &request.purchase_ids,
            &request.matching_root,
            &request.recursive_batch_proof_root,
            request.built_at_height,
        );
        if self.batches.contains_key(&batch_id) {
            return Err("options batch id collision".to_string());
        }

        let record = OptionsBatchRecord {
            batch_id: batch_id.clone(),
            vault_id: request.vault_id,
            option_ids: request.option_ids,
            purchase_ids: request.purchase_ids,
            status: OptionsBatchStatus::SettlementReady,
            batcher_commitment: request.batcher_commitment,
            matching_root: request.matching_root,
            settlement_call_root: request.settlement_call_root,
            premium_netting_root: request.premium_netting_root,
            collateral_delta_root: request.collateral_delta_root,
            recursive_batch_proof_root: request.recursive_batch_proof_root,
            da_commitment_root: request.da_commitment_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            pq_batch_authorization_root: request.pq_batch_authorization_root,
            privacy_set_size: request.privacy_set_size,
            max_fee_bps: request.max_fee_bps,
            built_at_height: request.built_at_height,
            expires_at_height: request.expires_at_height,
            settled_at_height: None,
        };

        for option_id in &record.option_ids {
            if let Some(option) = self.options.get_mut(option_id) {
                option.status = OptionStatus::Batched;
                option.latest_batch_id = Some(batch_id.clone());
            }
        }
        for purchase_id in &record.purchase_ids {
            if let Some(purchase) = self.purchases.get_mut(purchase_id) {
                purchase.status = PurchaseStatus::Batched;
                purchase.latest_batch_id = Some(batch_id.clone());
            }
        }
        self.batches.insert(batch_id, record.clone());
        self.counters.batch_counter = sequence;
        Ok(record)
    }

    pub fn settle_options_batch(
        &mut self,
        request: SettleOptionsBatchRequest,
    ) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<OptionsSettlementReceipt> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let state_root_before = self.state_root();
        if state_root_before != request.state_root_before {
            return Err("options batch settlement state_root_before mismatch".to_string());
        }
        let batch = self
            .batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "unknown options batch".to_string())?;
        if !batch.status.can_settle() {
            return Err("options batch cannot settle".to_string());
        }
        if request.settled_at_height > batch.expires_at_height {
            batch.status = OptionsBatchStatus::Expired;
            return Err("options batch settlement expired".to_string());
        }
        if request
            .settled_at_height
            .saturating_sub(batch.built_at_height)
            > self.config.settlement_ttl_blocks
        {
            batch.status = OptionsBatchStatus::Expired;
            return Err("options batch settlement exceeded TTL".to_string());
        }

        batch.status = OptionsBatchStatus::Settled;
        batch.settled_at_height = Some(request.settled_at_height);
        let option_ids = batch.option_ids.clone();
        let purchase_ids = batch.purchase_ids.clone();
        for option_id in option_ids {
            if let Some(option) = self.options.get_mut(&option_id) {
                option.status = OptionStatus::Settled;
            }
        }
        for purchase_id in purchase_ids {
            if let Some(purchase) = self.purchases.get_mut(&purchase_id) {
                purchase.status = PurchaseStatus::Settled;
            }
        }

        let sequence = self.counters.settlement_receipt_counter.saturating_add(1);
        let subject_root = payload_root(
            "PRIVATE-L2-CONFIDENTIAL-OPTIONS-BATCH-SETTLEMENT",
            &request.public_record(),
        );
        let receipt_id = settlement_receipt_id(
            sequence,
            SettlementReceiptKind::BatchSettled,
            &request.batch_id,
            &subject_root,
            request.settled_at_height,
        );
        let receipt = OptionsSettlementReceipt {
            receipt_id: receipt_id.clone(),
            kind: SettlementReceiptKind::BatchSettled,
            subject_id: request.batch_id.clone(),
            subject_root,
            batch_id: Some(request.batch_id.clone()),
            state_root_before,
            state_root_after: request.state_root_after,
            low_fee_sponsor_receipt_root: request.low_fee_sponsor_receipt_root,
            pq_authorization_root: request.pq_settlement_authorization_root,
            published_at_height: request.settled_at_height,
        };

        self.receipts.insert(receipt_id.clone(), receipt.clone());
        self.counters.settlement_receipt_counter = sequence;
        self.push_event(
            SettlementReceiptKind::BatchSettled,
            &request.batch_id,
            &receipt.public_record(),
            request.settled_at_height,
        );
        Ok(receipt)
    }

    pub fn exercise_option(
        &mut self,
        request: ExerciseOptionRequest,
    ) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<OptionExerciseRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        self.ensure_new_nullifier(&request.exercise_nullifier)?;
        let vault = self
            .vaults
            .get(&request.vault_id)
            .ok_or_else(|| "unknown options vault".to_string())?;
        if !vault.status.accepts_exercise() {
            return Err("options vault does not accept exercise".to_string());
        }
        let option = self
            .options
            .get(&request.option_id)
            .ok_or_else(|| "unknown private option".to_string())?;
        if option.vault_id != request.vault_id {
            return Err("exercise option is not in requested vault".to_string());
        }
        if !option.status.exercisable() {
            return Err("private option is not exercisable".to_string());
        }
        if request.exercised_at_height > option.expires_at_height
            && !option.option_style.can_exercise_before_expiry()
        {
            return Err(
                "european private option exercise is outside expiry commitment".to_string(),
            );
        }
        let purchase = self
            .purchases
            .get(&request.purchase_id)
            .ok_or_else(|| "unknown private option purchase".to_string())?;
        if purchase.option_id != request.option_id || purchase.vault_id != request.vault_id {
            return Err("exercise purchase does not match option and vault".to_string());
        }
        if !purchase.status.exercisable() {
            return Err("private option purchase is not exercisable".to_string());
        }

        let sequence = self.counters.exercise_counter.saturating_add(1);
        let exercise_id = option_exercise_id(
            sequence,
            &request.vault_id,
            &request.option_id,
            &request.purchase_id,
            &request.exerciser_commitment,
            &request.exercise_note_root,
            &request.exercise_nullifier,
            request.exercised_at_height,
        );
        if self.exercises.contains_key(&exercise_id) {
            return Err("private option exercise id collision".to_string());
        }

        let record = OptionExerciseRecord {
            exercise_id: exercise_id.clone(),
            vault_id: request.vault_id,
            option_id: request.option_id.clone(),
            purchase_id: request.purchase_id.clone(),
            exerciser_commitment: request.exerciser_commitment,
            exercise_note_root: request.exercise_note_root,
            settlement_price_root: request.settlement_price_root,
            payoff_commitment_root: request.payoff_commitment_root,
            collateral_release_root: request.collateral_release_root,
            delivery_root: request.delivery_root,
            oracle_bound_root: request.oracle_bound_root,
            privacy_proof_root: request.privacy_proof_root,
            pq_authorization_root: request.pq_authorization_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            exercise_window_root: request.exercise_window_root,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            exercised_at_height: request.exercised_at_height,
        };

        if let Some(option) = self.options.get_mut(&request.option_id) {
            option.status = OptionStatus::Exercised;
            option.latest_exercise_id = Some(exercise_id.clone());
        }
        if let Some(purchase) = self.purchases.get_mut(&request.purchase_id) {
            purchase.status = PurchaseStatus::Exercised;
            purchase.latest_exercise_id = Some(exercise_id.clone());
        }
        self.exercises.insert(exercise_id.clone(), record.clone());
        self.consume_nullifier(request.exercise_nullifier);
        self.counters.exercise_counter = sequence;
        self.push_event(
            SettlementReceiptKind::OptionExercised,
            &exercise_id,
            &record.public_record(),
            request.exercised_at_height,
        );
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let vault_root = records_root(
            "PRIVATE-L2-CONFIDENTIAL-OPTIONS-VAULTS",
            self.vaults
                .values()
                .map(OptionsVaultRecord::public_record)
                .collect(),
        );
        let option_root = records_root(
            "PRIVATE-L2-CONFIDENTIAL-OPTIONS-NOTES",
            self.options
                .values()
                .map(PrivateOptionRecord::public_record)
                .collect(),
        );
        let purchase_root = records_root(
            "PRIVATE-L2-CONFIDENTIAL-OPTIONS-PURCHASES",
            self.purchases
                .values()
                .map(OptionPurchaseRecord::public_record)
                .collect(),
        );
        let risk_attestation_root = records_root(
            "PRIVATE-L2-CONFIDENTIAL-OPTIONS-RISK-ATTESTATIONS",
            self.risk_attestations
                .values()
                .map(VaultRiskAttestationRecord::public_record)
                .collect(),
        );
        let batch_root = records_root(
            "PRIVATE-L2-CONFIDENTIAL-OPTIONS-BATCHES",
            self.batches
                .values()
                .map(OptionsBatchRecord::public_record)
                .collect(),
        );
        let receipt_root = records_root(
            "PRIVATE-L2-CONFIDENTIAL-OPTIONS-RECEIPTS",
            self.receipts
                .values()
                .map(OptionsSettlementReceipt::public_record)
                .collect(),
        );
        let exercise_root = records_root(
            "PRIVATE-L2-CONFIDENTIAL-OPTIONS-EXERCISES",
            self.exercises
                .values()
                .map(OptionExerciseRecord::public_record)
                .collect(),
        );
        let consumed_nullifier_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-OPTIONS-CONSUMED-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let event_root = merkle_root("PRIVATE-L2-CONFIDENTIAL-OPTIONS-EVENTS", &self.events);
        let state_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-OPTIONS-VAULT-STATE",
            &json!({
                "protocol_version": self.config.protocol_version,
                "chain_id": self.config.chain_id,
                "counters": self.counters.public_record(),
                "vault_root": vault_root,
                "option_root": option_root,
                "purchase_root": purchase_root,
                "risk_attestation_root": risk_attestation_root,
                "batch_root": batch_root,
                "receipt_root": receipt_root,
                "exercise_root": exercise_root,
                "consumed_nullifier_root": consumed_nullifier_root,
                "event_root": event_root,
            }),
        );

        Roots {
            vault_root,
            option_root,
            purchase_root,
            risk_attestation_root,
            batch_root,
            receipt_root,
            exercise_root,
            consumed_nullifier_root,
            event_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "vault_count": self.vaults.len(),
            "option_count": self.options.len(),
            "purchase_count": self.purchases.len(),
            "risk_attestation_count": self.risk_attestations.len(),
            "batch_count": self.batches.len(),
            "receipt_count": self.receipts.len(),
            "exercise_count": self.exercises.len(),
            "consumed_nullifier_count": self.consumed_nullifiers.len(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn ensure_new_nullifier(
        &self,
        nullifier: &str,
    ) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<()> {
        require_non_empty("nullifier", nullifier)?;
        if self.consumed_nullifiers.contains(nullifier) {
            return Err("confidential options nullifier already consumed".to_string());
        }
        Ok(())
    }

    fn consume_nullifier(&mut self, nullifier: String) {
        if self.consumed_nullifiers.insert(nullifier) {
            self.counters.consumed_nullifier_counter =
                self.counters.consumed_nullifier_counter.saturating_add(1);
        }
    }

    fn push_event(
        &mut self,
        kind: SettlementReceiptKind,
        subject_id: &str,
        payload: &Value,
        height: u64,
    ) {
        let event_id = domain_hash(
            "PRIVATE-L2-CONFIDENTIAL-OPTIONS-EVENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.config.protocol_version),
                HashPart::Str(kind.as_str()),
                HashPart::Str(subject_id),
                HashPart::Int(height as i128),
                HashPart::Json(payload),
            ],
            32,
        );
        self.events.push(json!({
            "event_id": event_id,
            "kind": kind.as_str(),
            "subject_id": subject_id,
            "payload_root": payload_root("PRIVATE-L2-CONFIDENTIAL-OPTIONS-EVENT-PAYLOAD", payload),
            "height": height,
        }));
    }
}

pub fn options_vault_id(
    sequence: u64,
    vault_kind: OptionsVaultKind,
    vault_owner_commitment: &str,
    reserve_note_root: &str,
    strategy_root: &str,
    vault_nullifier: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-OPTIONS-VAULT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(vault_kind.as_str()),
            HashPart::Str(vault_owner_commitment),
            HashPart::Str(reserve_note_root),
            HashPart::Str(strategy_root),
            HashPart::Str(vault_nullifier),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn private_option_id(
    sequence: u64,
    vault_id: &str,
    writer_commitment: &str,
    option_kind: OptionKind,
    option_style: OptionStyle,
    series_root: &str,
    option_nullifier: &str,
    written_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-OPTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(vault_id),
            HashPart::Str(writer_commitment),
            HashPart::Str(option_kind.as_str()),
            HashPart::Str(option_style.as_str()),
            HashPart::Str(series_root),
            HashPart::Str(option_nullifier),
            HashPart::Int(written_at_height as i128),
        ],
        32,
    )
}

pub fn option_purchase_id(
    sequence: u64,
    vault_id: &str,
    option_id: &str,
    buyer_commitment: &str,
    premium_payment_root: &str,
    purchase_nullifier: &str,
    purchased_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-OPTION-PURCHASE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(vault_id),
            HashPart::Str(option_id),
            HashPart::Str(buyer_commitment),
            HashPart::Str(premium_payment_root),
            HashPart::Str(purchase_nullifier),
            HashPart::Int(purchased_at_height as i128),
        ],
        32,
    )
}

pub fn vault_risk_attestation_id(
    sequence: u64,
    vault_id: &str,
    verdict: VaultRiskVerdict,
    attestor_commitment: &str,
    vault_state_root_after: &str,
    attestation_nullifier: &str,
    attested_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-OPTIONS-RISK-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(vault_id),
            HashPart::Str(verdict.as_str()),
            HashPart::Str(attestor_commitment),
            HashPart::Str(vault_state_root_after),
            HashPart::Str(attestation_nullifier),
            HashPart::Int(attested_at_height as i128),
        ],
        32,
    )
}

pub fn options_batch_id(
    sequence: u64,
    vault_id: &str,
    option_ids: &[String],
    purchase_ids: &[String],
    matching_root: &str,
    recursive_batch_proof_root: &str,
    built_at_height: u64,
) -> String {
    let option_root = string_slice_root(
        "PRIVATE-L2-CONFIDENTIAL-OPTIONS-BATCH-OPTION-IDS",
        option_ids,
    );
    let purchase_root = string_slice_root(
        "PRIVATE-L2-CONFIDENTIAL-OPTIONS-BATCH-PURCHASE-IDS",
        purchase_ids,
    );
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-OPTIONS-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(vault_id),
            HashPart::Str(&option_root),
            HashPart::Str(&purchase_root),
            HashPart::Str(matching_root),
            HashPart::Str(recursive_batch_proof_root),
            HashPart::Int(built_at_height as i128),
        ],
        32,
    )
}

pub fn settlement_receipt_id(
    sequence: u64,
    kind: SettlementReceiptKind,
    subject_id: &str,
    subject_root: &str,
    published_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-OPTIONS-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Int(published_at_height as i128),
        ],
        32,
    )
}

pub fn option_exercise_id(
    sequence: u64,
    vault_id: &str,
    option_id: &str,
    purchase_id: &str,
    exerciser_commitment: &str,
    exercise_note_root: &str,
    exercise_nullifier: &str,
    exercised_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-OPTION-EXERCISE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(vault_id),
            HashPart::Str(option_id),
            HashPart::Str(purchase_id),
            HashPart::Str(exerciser_commitment),
            HashPart::Str(exercise_note_root),
            HashPart::Str(exercise_nullifier),
            HashPart::Int(exercised_at_height as i128),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_OPTIONS_VAULT_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn records_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn string_slice_root(domain: &str, values: &[String]) -> String {
    merkle_root(
        domain,
        &values.iter().map(|value| json!(value)).collect::<Vec<_>>(),
    )
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("confidential options {label} is required"));
    }
    Ok(())
}

fn require_height_window(
    label: &str,
    opened_at_height: u64,
    expires_at_height: u64,
) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<()> {
    if expires_at_height <= opened_at_height {
        return Err(format!("{label} expiry must follow opening height"));
    }
    Ok(())
}

fn require_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2ConfidentialOptionsVaultRuntimeResult<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("roots-only privacy set is below configured minimum".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err(
            "post-quantum authorization security bits below configured minimum".to_string(),
        );
    }
    Ok(())
}
