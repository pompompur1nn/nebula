use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ConfidentialOptionsResult<T> = Result<T, String>;

pub const CONFIDENTIAL_OPTIONS_PROTOCOL_VERSION: &str = "nebula-confidential-options-v1";
pub const CONFIDENTIAL_OPTIONS_COMMITMENT_SCHEME: &str =
    "devnet-shake256-sealed-options-commitment-v1";
pub const CONFIDENTIAL_OPTIONS_ORDER_ENCRYPTION_SCHEME: &str =
    "devnet-xwing-sealed-option-order-v1";
pub const CONFIDENTIAL_OPTIONS_RANGE_PROOF_SCHEME: &str = "devnet-mock-pq-range-proof-v1";
pub const CONFIDENTIAL_OPTIONS_EXERCISE_PROOF_SCHEME: &str =
    "devnet-private-exercise-receipt-proof-v1";
pub const CONFIDENTIAL_OPTIONS_ORACLE_GUARD_SCHEME: &str = "threshold-oracle-guard-root-v1";
pub const CONFIDENTIAL_OPTIONS_SETTLEMENT_SCHEME: &str =
    "zk-confidential-option-settlement-root-v1";
pub const CONFIDENTIAL_OPTIONS_PQ_QUOTE_SCHEME: &str = "ml-dsa-87-market-maker-quote-v1";
pub const CONFIDENTIAL_OPTIONS_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const CONFIDENTIAL_OPTIONS_MAX_BPS: u64 = 10_000;
pub const CONFIDENTIAL_OPTIONS_MAX_MARGIN_BPS: u64 = 100_000;
pub const CONFIDENTIAL_OPTIONS_DEVNET_HEIGHT: u64 = 128;
pub const CONFIDENTIAL_OPTIONS_DEVNET_WXMR_ASSET_ID: &str = "wxmr-devnet";
pub const CONFIDENTIAL_OPTIONS_DEVNET_PRIVATE_STABLE_ASSET_ID: &str = "usdd-devnet";
pub const CONFIDENTIAL_OPTIONS_DEVNET_ORACLE_FEED_ID: &str = "feed-wxmr-usdd-devnet";
pub const CONFIDENTIAL_OPTIONS_DEFAULT_ORDER_TTL_BLOCKS: u64 = 48;
pub const CONFIDENTIAL_OPTIONS_DEFAULT_EXERCISE_TTL_BLOCKS: u64 = 72;
pub const CONFIDENTIAL_OPTIONS_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 18;
pub const CONFIDENTIAL_OPTIONS_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS: u64 = 12;
pub const CONFIDENTIAL_OPTIONS_DEFAULT_ORACLE_DEVIATION_BPS: u64 = 650;
pub const CONFIDENTIAL_OPTIONS_DEFAULT_LOW_FEE_LANE: &str = "small-private-options-hedge";
pub const CONFIDENTIAL_OPTIONS_DEFAULT_MIN_NOTIONAL_UNITS: u64 = 1_000_000;
pub const CONFIDENTIAL_OPTIONS_DEFAULT_MAX_NOTIONAL_UNITS: u64 = 500_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionContractKind {
    Call,
    Put,
    CoveredCall,
    ProtectivePut,
    Collar,
    PrincipalProtectedNote,
}

impl OptionContractKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Put => "put",
            Self::CoveredCall => "covered_call",
            Self::ProtectivePut => "protective_put",
            Self::Collar => "collar",
            Self::PrincipalProtectedNote => "principal_protected_note",
        }
    }

    pub fn is_structured_product(&self) -> bool {
        matches!(self, Self::Collar | Self::PrincipalProtectedNote)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionExerciseStyle {
    European,
    American,
    Bermudan,
    BarrierGuarded,
}

impl OptionExerciseStyle {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::European => "european",
            Self::American => "american",
            Self::Bermudan => "bermudan",
            Self::BarrierGuarded => "barrier_guarded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionSeriesStatus {
    Draft,
    Active,
    ReduceOnly,
    ExerciseOnly,
    Settling,
    Settled,
    Paused,
    Retired,
}

impl OptionSeriesStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::ReduceOnly => "reduce_only",
            Self::ExerciseOnly => "exercise_only",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_orders(&self) -> bool {
        matches!(self, Self::Active | Self::ReduceOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionOrderSide {
    Buy,
    Sell,
}

impl OptionOrderSide {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Buy => "buy",
            Self::Sell => "sell",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionPositionEffect {
    Open,
    Close,
    Roll,
    Hedge,
}

impl OptionPositionEffect {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Close => "close",
            Self::Roll => "roll",
            Self::Hedge => "hedge",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedOrderStatus {
    Committed,
    Eligible,
    Matched,
    PartiallyFilled,
    Filled,
    Exercised,
    Cancelled,
    Expired,
}

impl SealedOrderStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Eligible => "eligible",
            Self::Matched => "matched",
            Self::PartiallyFilled => "partially_filled",
            Self::Filled => "filled",
            Self::Exercised => "exercised",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Eligible | Self::Matched | Self::PartiallyFilled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginVaultStatus {
    Active,
    Frozen,
    MarginCall,
    Liquidating,
    Settling,
    Closed,
}

impl MarginVaultStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::MarginCall => "margin_call",
            Self::Liquidating => "liquidating",
            Self::Settling => "settling",
            Self::Closed => "closed",
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(
            self,
            Self::Active | Self::Frozen | Self::MarginCall | Self::Liquidating
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExerciseReceiptStatus {
    Submitted,
    Proven,
    Challenged,
    Settled,
    Rejected,
    Expired,
}

impl ExerciseReceiptStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Proven => "proven",
            Self::Challenged => "challenged",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleGuardAction {
    Allow,
    Watch,
    FreezeOrders,
    ExerciseOnly,
    PauseSettlement,
    FreezeSeries,
}

impl OracleGuardAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Watch => "watch",
            Self::FreezeOrders => "freeze_orders",
            Self::ExerciseOnly => "exercise_only",
            Self::PauseSettlement => "pause_settlement",
            Self::FreezeSeries => "freeze_series",
        }
    }

    pub fn allows_orders(&self) -> bool {
        matches!(self, Self::Allow | Self::Watch)
    }

    pub fn allows_settlement(&self) -> bool {
        matches!(self, Self::Allow | Self::Watch | Self::ExerciseOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleGuardStatus {
    Preview,
    Active,
    ChallengeOpen,
    Expired,
    Revoked,
}

impl OracleGuardStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Preview => "preview",
            Self::Active => "active",
            Self::ChallengeOpen => "challenge_open",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionRiskSeverity {
    Healthy,
    Watch,
    Elevated,
    Critical,
}

impl OptionRiskSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
        }
    }

    pub fn score_bps(&self) -> u64 {
        match self {
            Self::Healthy => 0,
            Self::Watch => 2_500,
            Self::Elevated => 6_500,
            Self::Critical => 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionLiquidationStatus {
    Queued,
    ChallengeOpen,
    Executable,
    Executed,
    Cancelled,
    Expired,
}

impl OptionLiquidationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::ChallengeOpen => "challenge_open",
            Self::Executable => "executable",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(self, Self::Queued | Self::ChallengeOpen | Self::Executable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionSettlementStatus {
    Preview,
    PendingProof,
    ChallengeOpen,
    Executable,
    Settled,
    Cancelled,
}

impl OptionSettlementStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Preview => "preview",
            Self::PendingProof => "pending_proof",
            Self::ChallengeOpen => "challenge_open",
            Self::Executable => "executable",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_pending(&self) -> bool {
        matches!(
            self,
            Self::Preview | Self::PendingProof | Self::ChallengeOpen | Self::Executable
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgingSponsorshipStatus {
    Reserved,
    Active,
    Applied,
    Reclaimed,
    Expired,
    Revoked,
}

impl HedgingSponsorshipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Active => "active",
            Self::Applied => "applied",
            Self::Reclaimed => "reclaimed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqQuoteKind {
    TwoWay,
    BidOnly,
    AskOnly,
    HedgeOnly,
    LiquidationBackstop,
}

impl PqQuoteKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TwoWay => "two_way",
            Self::BidOnly => "bid_only",
            Self::AskOnly => "ask_only",
            Self::HedgeOnly => "hedge_only",
            Self::LiquidationBackstop => "liquidation_backstop",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqQuoteStatus {
    Indicative,
    Firm,
    Matched,
    Expired,
    Revoked,
}

impl PqQuoteStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Indicative => "indicative",
            Self::Firm => "firm",
            Self::Matched => "matched",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialOptionsConfig {
    pub protocol_version: String,
    pub underlying_asset_id: String,
    pub collateral_asset_id: String,
    pub premium_asset_id: String,
    pub commitment_scheme: String,
    pub order_encryption_scheme: String,
    pub range_proof_scheme: String,
    pub exercise_proof_scheme: String,
    pub oracle_guard_scheme: String,
    pub settlement_scheme: String,
    pub pq_quote_scheme: String,
    pub price_scale: u64,
    pub default_order_ttl_blocks: u64,
    pub default_exercise_ttl_blocks: u64,
    pub default_challenge_window_blocks: u64,
    pub max_oracle_staleness_blocks: u64,
    pub max_oracle_deviation_bps: u64,
    pub min_notional_units: u64,
    pub max_notional_units: u64,
    pub maker_fee_bps: u64,
    pub taker_fee_bps: u64,
    pub default_low_fee_lane: String,
    pub metadata_root: String,
}

impl Default for ConfidentialOptionsConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

impl ConfidentialOptionsConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: CONFIDENTIAL_OPTIONS_PROTOCOL_VERSION.to_string(),
            underlying_asset_id: CONFIDENTIAL_OPTIONS_DEVNET_WXMR_ASSET_ID.to_string(),
            collateral_asset_id: CONFIDENTIAL_OPTIONS_DEVNET_PRIVATE_STABLE_ASSET_ID.to_string(),
            premium_asset_id: CONFIDENTIAL_OPTIONS_DEVNET_PRIVATE_STABLE_ASSET_ID.to_string(),
            commitment_scheme: CONFIDENTIAL_OPTIONS_COMMITMENT_SCHEME.to_string(),
            order_encryption_scheme: CONFIDENTIAL_OPTIONS_ORDER_ENCRYPTION_SCHEME.to_string(),
            range_proof_scheme: CONFIDENTIAL_OPTIONS_RANGE_PROOF_SCHEME.to_string(),
            exercise_proof_scheme: CONFIDENTIAL_OPTIONS_EXERCISE_PROOF_SCHEME.to_string(),
            oracle_guard_scheme: CONFIDENTIAL_OPTIONS_ORACLE_GUARD_SCHEME.to_string(),
            settlement_scheme: CONFIDENTIAL_OPTIONS_SETTLEMENT_SCHEME.to_string(),
            pq_quote_scheme: CONFIDENTIAL_OPTIONS_PQ_QUOTE_SCHEME.to_string(),
            price_scale: CONFIDENTIAL_OPTIONS_PRICE_SCALE,
            default_order_ttl_blocks: CONFIDENTIAL_OPTIONS_DEFAULT_ORDER_TTL_BLOCKS,
            default_exercise_ttl_blocks: CONFIDENTIAL_OPTIONS_DEFAULT_EXERCISE_TTL_BLOCKS,
            default_challenge_window_blocks: CONFIDENTIAL_OPTIONS_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            max_oracle_staleness_blocks: CONFIDENTIAL_OPTIONS_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS,
            max_oracle_deviation_bps: CONFIDENTIAL_OPTIONS_DEFAULT_ORACLE_DEVIATION_BPS,
            min_notional_units: CONFIDENTIAL_OPTIONS_DEFAULT_MIN_NOTIONAL_UNITS,
            max_notional_units: CONFIDENTIAL_OPTIONS_DEFAULT_MAX_NOTIONAL_UNITS,
            maker_fee_bps: 2,
            taker_fee_bps: 8,
            default_low_fee_lane: CONFIDENTIAL_OPTIONS_DEFAULT_LOW_FEE_LANE.to_string(),
            metadata_root: confidential_options_payload_root(
                "CONFIDENTIAL-OPTIONS-CONFIG-METADATA",
                &json!({
                    "mode": "devnet",
                    "theme": "privacy_preserving_options_on_wxmr",
                    "collateral": "private_stablecoin"
                }),
            ),
        }
    }

    pub fn validate(&self) -> ConfidentialOptionsResult<()> {
        ensure_non_empty(&self.protocol_version, "config protocol_version")?;
        ensure_non_empty(&self.underlying_asset_id, "config underlying_asset_id")?;
        ensure_non_empty(&self.collateral_asset_id, "config collateral_asset_id")?;
        ensure_non_empty(&self.premium_asset_id, "config premium_asset_id")?;
        ensure_non_empty(&self.commitment_scheme, "config commitment_scheme")?;
        ensure_non_empty(
            &self.order_encryption_scheme,
            "config order_encryption_scheme",
        )?;
        ensure_non_empty(&self.range_proof_scheme, "config range_proof_scheme")?;
        ensure_non_empty(&self.exercise_proof_scheme, "config exercise_proof_scheme")?;
        ensure_non_empty(&self.oracle_guard_scheme, "config oracle_guard_scheme")?;
        ensure_non_empty(&self.settlement_scheme, "config settlement_scheme")?;
        ensure_non_empty(&self.pq_quote_scheme, "config pq_quote_scheme")?;
        ensure_non_empty(&self.default_low_fee_lane, "config default_low_fee_lane")?;
        ensure_non_empty(&self.metadata_root, "config metadata_root")?;
        ensure_bps(
            self.max_oracle_deviation_bps,
            "config max_oracle_deviation_bps",
        )?;
        ensure_bps(self.maker_fee_bps, "config maker_fee_bps")?;
        ensure_bps(self.taker_fee_bps, "config taker_fee_bps")?;
        if self.price_scale == 0 {
            return Err("config price_scale must be positive".to_string());
        }
        if self.default_order_ttl_blocks == 0
            || self.default_exercise_ttl_blocks == 0
            || self.default_challenge_window_blocks == 0
            || self.max_oracle_staleness_blocks == 0
        {
            return Err("config ttl and staleness settings must be positive".to_string());
        }
        if self.default_order_ttl_blocks <= self.default_challenge_window_blocks {
            return Err("config order ttl must exceed challenge window".to_string());
        }
        if self.min_notional_units == 0 || self.min_notional_units > self.max_notional_units {
            return Err("config notional bounds are invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_options_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "underlying_asset_id": self.underlying_asset_id,
            "collateral_asset_id": self.collateral_asset_id,
            "premium_asset_id": self.premium_asset_id,
            "commitment_scheme": self.commitment_scheme,
            "order_encryption_scheme": self.order_encryption_scheme,
            "range_proof_scheme": self.range_proof_scheme,
            "exercise_proof_scheme": self.exercise_proof_scheme,
            "oracle_guard_scheme": self.oracle_guard_scheme,
            "settlement_scheme": self.settlement_scheme,
            "pq_quote_scheme": self.pq_quote_scheme,
            "price_scale": self.price_scale,
            "default_order_ttl_blocks": self.default_order_ttl_blocks,
            "default_exercise_ttl_blocks": self.default_exercise_ttl_blocks,
            "default_challenge_window_blocks": self.default_challenge_window_blocks,
            "max_oracle_staleness_blocks": self.max_oracle_staleness_blocks,
            "max_oracle_deviation_bps": self.max_oracle_deviation_bps,
            "min_notional_units": self.min_notional_units,
            "max_notional_units": self.max_notional_units,
            "maker_fee_bps": self.maker_fee_bps,
            "taker_fee_bps": self.taker_fee_bps,
            "default_low_fee_lane": self.default_low_fee_lane,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn config_root(&self) -> String {
        confidential_options_payload_root("CONFIDENTIAL-OPTIONS-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialOptionSeries {
    pub series_id: String,
    pub display_name: String,
    pub underlying_asset_id: String,
    pub collateral_asset_id: String,
    pub premium_asset_id: String,
    pub settlement_asset_id: String,
    pub oracle_feed_id: String,
    pub kind: OptionContractKind,
    pub exercise_style: OptionExerciseStyle,
    pub strike_price_commitment: String,
    pub strike_bucket: String,
    pub contract_size_commitment: String,
    pub notional_floor_units: u64,
    pub notional_cap_units: u64,
    pub open_interest_call_units: u64,
    pub open_interest_put_units: u64,
    pub listed_at_height: u64,
    pub exercise_start_height: u64,
    pub expiration_height: u64,
    pub settlement_height: u64,
    pub maker_fee_bps: u64,
    pub taker_fee_bps: u64,
    pub min_margin_bps: u64,
    pub oracle_guard_root: String,
    pub sealed_order_root: String,
    pub exercise_receipt_root: String,
    pub settlement_root: String,
    pub liquidation_root: String,
    pub pq_quote_root: String,
    pub low_fee_sponsorship_root: String,
    pub metadata_root: String,
    pub status: OptionSeriesStatus,
}

impl ConfidentialOptionSeries {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        display_name: &str,
        underlying_asset_id: &str,
        collateral_asset_id: &str,
        premium_asset_id: &str,
        settlement_asset_id: &str,
        oracle_feed_id: &str,
        kind: OptionContractKind,
        exercise_style: OptionExerciseStyle,
        strike_price_commitment: &str,
        strike_bucket: &str,
        contract_size_commitment: &str,
        notional_floor_units: u64,
        notional_cap_units: u64,
        listed_at_height: u64,
        exercise_start_height: u64,
        expiration_height: u64,
        settlement_height: u64,
        min_margin_bps: u64,
        metadata: &Value,
    ) -> ConfidentialOptionsResult<Self> {
        let metadata_root =
            confidential_options_payload_root("CONFIDENTIAL-OPTIONS-SERIES-METADATA", metadata);
        let series_id = confidential_options_series_id(
            underlying_asset_id,
            collateral_asset_id,
            oracle_feed_id,
            strike_price_commitment,
            expiration_height,
            &metadata_root,
        );
        let series = Self {
            series_id,
            display_name: display_name.to_string(),
            underlying_asset_id: underlying_asset_id.to_string(),
            collateral_asset_id: collateral_asset_id.to_string(),
            premium_asset_id: premium_asset_id.to_string(),
            settlement_asset_id: settlement_asset_id.to_string(),
            oracle_feed_id: oracle_feed_id.to_string(),
            kind,
            exercise_style,
            strike_price_commitment: strike_price_commitment.to_string(),
            strike_bucket: strike_bucket.to_string(),
            contract_size_commitment: contract_size_commitment.to_string(),
            notional_floor_units,
            notional_cap_units,
            open_interest_call_units: 0,
            open_interest_put_units: 0,
            listed_at_height,
            exercise_start_height,
            expiration_height,
            settlement_height,
            maker_fee_bps: 2,
            taker_fee_bps: 8,
            min_margin_bps,
            oracle_guard_root: merkle_root("CONFIDENTIAL-OPTIONS-ORACLE-GUARD", &[]),
            sealed_order_root: merkle_root("CONFIDENTIAL-OPTIONS-SEALED-ORDER", &[]),
            exercise_receipt_root: merkle_root("CONFIDENTIAL-OPTIONS-EXERCISE-RECEIPT", &[]),
            settlement_root: merkle_root("CONFIDENTIAL-OPTIONS-SETTLEMENT-BATCH", &[]),
            liquidation_root: merkle_root("CONFIDENTIAL-OPTIONS-LIQUIDATION", &[]),
            pq_quote_root: merkle_root("CONFIDENTIAL-OPTIONS-PQ-QUOTE", &[]),
            low_fee_sponsorship_root: merkle_root(
                "CONFIDENTIAL-OPTIONS-LOW-FEE-HEDGING-SPONSORSHIP",
                &[],
            ),
            metadata_root,
            status: OptionSeriesStatus::Active,
        };
        series.validate()?;
        Ok(series)
    }

    pub fn wxmr_private_stable_call_devnet(
        listed_at_height: u64,
        exercise_start_height: u64,
        expiration_height: u64,
        settlement_height: u64,
    ) -> ConfidentialOptionsResult<Self> {
        let strike_commitment = confidential_options_price_commitment(
            "devnet-wxmr-call-strike",
            180 * CONFIDENTIAL_OPTIONS_PRICE_SCALE,
            "devnet-call-strike-blinding",
        );
        Self::new(
            "wXMR private stable covered call",
            CONFIDENTIAL_OPTIONS_DEVNET_WXMR_ASSET_ID,
            CONFIDENTIAL_OPTIONS_DEVNET_PRIVATE_STABLE_ASSET_ID,
            CONFIDENTIAL_OPTIONS_DEVNET_PRIVATE_STABLE_ASSET_ID,
            CONFIDENTIAL_OPTIONS_DEVNET_PRIVATE_STABLE_ASSET_ID,
            CONFIDENTIAL_OPTIONS_DEVNET_ORACLE_FEED_ID,
            OptionContractKind::CoveredCall,
            OptionExerciseStyle::European,
            &strike_commitment,
            "wxmr_175_200_usdd",
            &confidential_options_amount_commitment(
                "devnet-call-contract-size",
                1_000_000_000,
                "devnet-contract-size-blinding",
            ),
            CONFIDENTIAL_OPTIONS_DEFAULT_MIN_NOTIONAL_UNITS,
            CONFIDENTIAL_OPTIONS_DEFAULT_MAX_NOTIONAL_UNITS,
            listed_at_height,
            exercise_start_height,
            expiration_height,
            settlement_height,
            12_500,
            &json!({
                "payoff": "covered_call",
                "underlying": "wrapped_xmr",
                "collateral": "private_stablecoin",
                "privacy": "sealed_orders_and_private_exercise_receipts"
            }),
        )
    }

    pub fn principal_protected_note_devnet(
        listed_at_height: u64,
        exercise_start_height: u64,
        expiration_height: u64,
        settlement_height: u64,
    ) -> ConfidentialOptionsResult<Self> {
        let strike_commitment = confidential_options_price_commitment(
            "devnet-ppn-downside-floor",
            150 * CONFIDENTIAL_OPTIONS_PRICE_SCALE,
            "devnet-ppn-floor-blinding",
        );
        Self::new(
            "wXMR private principal protected note",
            CONFIDENTIAL_OPTIONS_DEVNET_WXMR_ASSET_ID,
            CONFIDENTIAL_OPTIONS_DEVNET_PRIVATE_STABLE_ASSET_ID,
            CONFIDENTIAL_OPTIONS_DEVNET_PRIVATE_STABLE_ASSET_ID,
            CONFIDENTIAL_OPTIONS_DEVNET_PRIVATE_STABLE_ASSET_ID,
            CONFIDENTIAL_OPTIONS_DEVNET_ORACLE_FEED_ID,
            OptionContractKind::PrincipalProtectedNote,
            OptionExerciseStyle::BarrierGuarded,
            &strike_commitment,
            "wxmr_150_floor_with_upside",
            &confidential_options_amount_commitment(
                "devnet-ppn-notional",
                5_000_000_000,
                "devnet-ppn-notional-blinding",
            ),
            5_000_000,
            1_000_000_000_000,
            listed_at_height,
            exercise_start_height,
            expiration_height,
            settlement_height,
            10_000,
            &json!({
                "payoff": "principal_protected_note",
                "floor": "private_stablecoin_principal",
                "upside": "sealed_wxmr_option_component"
            }),
        )
    }

    pub fn accepts_orders_at(&self, height: u64) -> bool {
        self.status.accepts_orders()
            && height >= self.listed_at_height
            && height < self.expiration_height
    }

    pub fn exercise_window_contains(&self, height: u64) -> bool {
        height >= self.exercise_start_height && height <= self.expiration_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_option_series",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_OPTIONS_PROTOCOL_VERSION,
            "series_id": self.series_id,
            "display_name": self.display_name,
            "underlying_asset_id": self.underlying_asset_id,
            "collateral_asset_id": self.collateral_asset_id,
            "premium_asset_id": self.premium_asset_id,
            "settlement_asset_id": self.settlement_asset_id,
            "oracle_feed_id": self.oracle_feed_id,
            "option_kind": self.kind.as_str(),
            "exercise_style": self.exercise_style.as_str(),
            "strike_price_commitment": self.strike_price_commitment,
            "strike_bucket": self.strike_bucket,
            "contract_size_commitment": self.contract_size_commitment,
            "notional_floor_units": self.notional_floor_units,
            "notional_cap_units": self.notional_cap_units,
            "open_interest_call_units": self.open_interest_call_units,
            "open_interest_put_units": self.open_interest_put_units,
            "listed_at_height": self.listed_at_height,
            "exercise_start_height": self.exercise_start_height,
            "expiration_height": self.expiration_height,
            "settlement_height": self.settlement_height,
            "maker_fee_bps": self.maker_fee_bps,
            "taker_fee_bps": self.taker_fee_bps,
            "min_margin_bps": self.min_margin_bps,
            "oracle_guard_root": self.oracle_guard_root,
            "sealed_order_root": self.sealed_order_root,
            "exercise_receipt_root": self.exercise_receipt_root,
            "settlement_root": self.settlement_root,
            "liquidation_root": self.liquidation_root,
            "pq_quote_root": self.pq_quote_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "metadata_root": self.metadata_root,
            "status": self.status.as_str(),
            "is_structured_product": self.kind.is_structured_product(),
        })
    }

    pub fn validate(&self) -> ConfidentialOptionsResult<()> {
        ensure_non_empty(&self.series_id, "series series_id")?;
        ensure_non_empty(&self.display_name, "series display_name")?;
        ensure_non_empty(&self.underlying_asset_id, "series underlying_asset_id")?;
        ensure_non_empty(&self.collateral_asset_id, "series collateral_asset_id")?;
        ensure_non_empty(&self.premium_asset_id, "series premium_asset_id")?;
        ensure_non_empty(&self.settlement_asset_id, "series settlement_asset_id")?;
        ensure_non_empty(&self.oracle_feed_id, "series oracle_feed_id")?;
        ensure_non_empty(
            &self.strike_price_commitment,
            "series strike_price_commitment",
        )?;
        ensure_non_empty(&self.strike_bucket, "series strike_bucket")?;
        ensure_non_empty(
            &self.contract_size_commitment,
            "series contract_size_commitment",
        )?;
        ensure_non_empty(&self.metadata_root, "series metadata_root")?;
        ensure_bps(self.maker_fee_bps, "series maker_fee_bps")?;
        ensure_bps(self.taker_fee_bps, "series taker_fee_bps")?;
        ensure_margin_bps(self.min_margin_bps, "series min_margin_bps")?;
        if self.notional_floor_units == 0 || self.notional_floor_units > self.notional_cap_units {
            return Err("series notional bounds are invalid".to_string());
        }
        if self.listed_at_height > self.exercise_start_height {
            return Err("series listing must not start after exercise window".to_string());
        }
        if self.exercise_start_height > self.expiration_height {
            return Err("series exercise start exceeds expiration".to_string());
        }
        if self.expiration_height > self.settlement_height {
            return Err("series expiration exceeds settlement height".to_string());
        }
        let expected_id = confidential_options_series_id(
            &self.underlying_asset_id,
            &self.collateral_asset_id,
            &self.oracle_feed_id,
            &self.strike_price_commitment,
            self.expiration_height,
            &self.metadata_root,
        );
        if self.series_id != expected_id {
            return Err("series id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionMarginVault {
    pub vault_id: String,
    pub owner_commitment: String,
    pub collateral_asset_id: String,
    pub balance_commitment: String,
    pub balance_floor_units: u64,
    pub locked_margin_commitment: String,
    pub locked_margin_upper_bound_units: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
    pub nonce: u64,
    pub status: MarginVaultStatus,
    pub metadata_root: String,
}

impl OptionMarginVault {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_label: &str,
        collateral_asset_id: &str,
        balance_floor_units: u64,
        locked_margin_upper_bound_units: u64,
        maintenance_margin_bps: u64,
        liquidation_threshold_bps: u64,
        opened_at_height: u64,
        nonce: u64,
        metadata: &Value,
    ) -> ConfidentialOptionsResult<Self> {
        let owner_commitment = confidential_options_account_commitment(owner_label);
        let vault_id = confidential_options_margin_vault_id(
            &owner_commitment,
            collateral_asset_id,
            opened_at_height,
            nonce,
        );
        let vault = Self {
            vault_id,
            owner_commitment,
            collateral_asset_id: collateral_asset_id.to_string(),
            balance_commitment: confidential_options_amount_commitment(
                "option-vault-balance",
                balance_floor_units,
                &confidential_options_blinding(owner_label, nonce, "vault-balance"),
            ),
            balance_floor_units,
            locked_margin_commitment: confidential_options_amount_commitment(
                "option-vault-locked-margin",
                locked_margin_upper_bound_units,
                &confidential_options_blinding(owner_label, nonce, "vault-locked-margin"),
            ),
            locked_margin_upper_bound_units,
            maintenance_margin_bps,
            liquidation_threshold_bps,
            opened_at_height,
            updated_at_height: opened_at_height,
            nonce,
            status: MarginVaultStatus::Active,
            metadata_root: confidential_options_payload_root(
                "CONFIDENTIAL-OPTIONS-MARGIN-VAULT-METADATA",
                metadata,
            ),
        };
        vault.validate()?;
        Ok(vault)
    }

    pub fn available_floor_units(&self) -> u64 {
        self.balance_floor_units
            .saturating_sub(self.locked_margin_upper_bound_units)
    }

    pub fn margin_utilization_bps(&self) -> u64 {
        ratio_bps(
            self.locked_margin_upper_bound_units,
            self.balance_floor_units.max(1),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_option_margin_vault",
            "chain_id": CHAIN_ID,
            "vault_id": self.vault_id,
            "owner_commitment": self.owner_commitment,
            "collateral_asset_id": self.collateral_asset_id,
            "balance_commitment": self.balance_commitment,
            "balance_floor_units": self.balance_floor_units,
            "locked_margin_commitment": self.locked_margin_commitment,
            "locked_margin_upper_bound_units": self.locked_margin_upper_bound_units,
            "available_floor_units": self.available_floor_units(),
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "margin_utilization_bps": self.margin_utilization_bps(),
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn validate(&self) -> ConfidentialOptionsResult<()> {
        ensure_non_empty(&self.vault_id, "margin vault vault_id")?;
        ensure_non_empty(&self.owner_commitment, "margin vault owner_commitment")?;
        ensure_non_empty(
            &self.collateral_asset_id,
            "margin vault collateral_asset_id",
        )?;
        ensure_non_empty(&self.balance_commitment, "margin vault balance_commitment")?;
        ensure_non_empty(
            &self.locked_margin_commitment,
            "margin vault locked_margin_commitment",
        )?;
        ensure_non_empty(&self.metadata_root, "margin vault metadata_root")?;
        ensure_margin_bps(
            self.maintenance_margin_bps,
            "margin vault maintenance_margin_bps",
        )?;
        ensure_margin_bps(
            self.liquidation_threshold_bps,
            "margin vault liquidation_threshold_bps",
        )?;
        if self.maintenance_margin_bps > self.liquidation_threshold_bps {
            return Err(
                "margin vault maintenance margin exceeds liquidation threshold".to_string(),
            );
        }
        if self.updated_at_height < self.opened_at_height {
            return Err("margin vault updated height precedes opened height".to_string());
        }
        let expected_id = confidential_options_margin_vault_id(
            &self.owner_commitment,
            &self.collateral_asset_id,
            self.opened_at_height,
            self.nonce,
        );
        if self.vault_id != expected_id {
            return Err("margin vault id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedOptionOrder {
    pub order_id: String,
    pub series_id: String,
    pub margin_vault_id: String,
    pub owner_commitment: String,
    pub side: OptionOrderSide,
    pub position_effect: OptionPositionEffect,
    pub size_commitment: String,
    pub premium_limit_commitment: String,
    pub collateral_commitment: String,
    pub fee_commitment: String,
    pub max_fee_units: u64,
    pub quote_id: String,
    pub sponsorship_id: String,
    pub encrypted_order_root: String,
    pub compliance_proof_root: String,
    pub range_proof_root: String,
    pub pq_authorization_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: SealedOrderStatus,
}

impl SealedOptionOrder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        series_id: &str,
        margin_vault_id: &str,
        owner_label: &str,
        side: OptionOrderSide,
        position_effect: OptionPositionEffect,
        size_units: u64,
        premium_limit_units: u64,
        collateral_units: u64,
        max_fee_units: u64,
        quote_id: &str,
        sponsorship_id: &str,
        encrypted_order: &Value,
        submitted_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> ConfidentialOptionsResult<Self> {
        let owner_commitment = confidential_options_account_commitment(owner_label);
        let size_commitment = confidential_options_amount_commitment(
            "option-order-size",
            size_units,
            &confidential_options_blinding(owner_label, nonce, "order-size"),
        );
        let premium_limit_commitment = confidential_options_amount_commitment(
            "option-order-premium-limit",
            premium_limit_units,
            &confidential_options_blinding(owner_label, nonce, "order-premium"),
        );
        let collateral_commitment = confidential_options_amount_commitment(
            "option-order-collateral",
            collateral_units,
            &confidential_options_blinding(owner_label, nonce, "order-collateral"),
        );
        let fee_commitment = confidential_options_amount_commitment(
            "option-order-fee",
            max_fee_units,
            &confidential_options_blinding(owner_label, nonce, "order-fee"),
        );
        let range_proof_root = confidential_options_proof_root(
            CONFIDENTIAL_OPTIONS_RANGE_PROOF_SCHEME,
            &size_commitment,
            &collateral_commitment,
        );
        let order_id = confidential_options_sealed_order_id(
            series_id,
            &owner_commitment,
            side,
            &size_commitment,
            &premium_limit_commitment,
            submitted_at_height,
            nonce,
        );
        let order = Self {
            order_id,
            series_id: series_id.to_string(),
            margin_vault_id: margin_vault_id.to_string(),
            owner_commitment,
            side,
            position_effect,
            size_commitment,
            premium_limit_commitment,
            collateral_commitment,
            fee_commitment,
            max_fee_units,
            quote_id: quote_id.to_string(),
            sponsorship_id: sponsorship_id.to_string(),
            encrypted_order_root: confidential_options_payload_root(
                "CONFIDENTIAL-OPTIONS-SEALED-ORDER-CIPHERTEXT",
                encrypted_order,
            ),
            compliance_proof_root: confidential_options_proof_root(
                "compliance",
                &confidential_options_string_root(
                    "CONFIDENTIAL-OPTIONS-COMPLIANCE-PUBLIC",
                    series_id,
                ),
                &confidential_options_string_root(
                    "CONFIDENTIAL-OPTIONS-COMPLIANCE-PRIVATE",
                    owner_label,
                ),
            ),
            range_proof_root,
            pq_authorization_root: confidential_options_string_root(
                "CONFIDENTIAL-OPTIONS-PQ-ORDER-AUTHORIZATION",
                owner_label,
            ),
            submitted_at_height,
            expires_at_height,
            nonce,
            status: SealedOrderStatus::Committed,
        };
        order.validate()?;
        Ok(order)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.is_live()
            && height >= self.submitted_at_height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_option_order",
            "chain_id": CHAIN_ID,
            "order_id": self.order_id,
            "series_id": self.series_id,
            "margin_vault_id": self.margin_vault_id,
            "owner_commitment": self.owner_commitment,
            "side": self.side.as_str(),
            "position_effect": self.position_effect.as_str(),
            "size_commitment": self.size_commitment,
            "premium_limit_commitment": self.premium_limit_commitment,
            "collateral_commitment": self.collateral_commitment,
            "fee_commitment": self.fee_commitment,
            "max_fee_units": self.max_fee_units,
            "quote_id": self.quote_id,
            "sponsorship_id": self.sponsorship_id,
            "encrypted_order_root": self.encrypted_order_root,
            "compliance_proof_root": self.compliance_proof_root,
            "range_proof_root": self.range_proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialOptionsResult<()> {
        ensure_non_empty(&self.order_id, "sealed order order_id")?;
        ensure_non_empty(&self.series_id, "sealed order series_id")?;
        ensure_non_empty(&self.margin_vault_id, "sealed order margin_vault_id")?;
        ensure_non_empty(&self.owner_commitment, "sealed order owner_commitment")?;
        ensure_non_empty(&self.size_commitment, "sealed order size_commitment")?;
        ensure_non_empty(
            &self.premium_limit_commitment,
            "sealed order premium_limit_commitment",
        )?;
        ensure_non_empty(
            &self.collateral_commitment,
            "sealed order collateral_commitment",
        )?;
        ensure_non_empty(&self.fee_commitment, "sealed order fee_commitment")?;
        ensure_non_empty(
            &self.encrypted_order_root,
            "sealed order encrypted_order_root",
        )?;
        ensure_non_empty(
            &self.compliance_proof_root,
            "sealed order compliance_proof_root",
        )?;
        ensure_non_empty(&self.range_proof_root, "sealed order range_proof_root")?;
        ensure_non_empty(
            &self.pq_authorization_root,
            "sealed order pq_authorization_root",
        )?;
        if self.expires_at_height <= self.submitted_at_height {
            return Err("sealed order expiration must be after submission".to_string());
        }
        let expected_id = confidential_options_sealed_order_id(
            &self.series_id,
            &self.owner_commitment,
            self.side,
            &self.size_commitment,
            &self.premium_limit_commitment,
            self.submitted_at_height,
            self.nonce,
        );
        if self.order_id != expected_id {
            return Err("sealed order id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateExerciseReceipt {
    pub receipt_id: String,
    pub series_id: String,
    pub order_id: String,
    pub margin_vault_id: String,
    pub holder_commitment: String,
    pub exercise_nullifier_hash: String,
    pub exercise_quantity_commitment: String,
    pub settlement_price_commitment: String,
    pub payout_commitment: String,
    pub collateral_release_commitment: String,
    pub oracle_guard_id: String,
    pub exercise_proof_root: String,
    pub privacy_budget_root: String,
    pub exercised_at_height: u64,
    pub settlement_due_height: u64,
    pub status: ExerciseReceiptStatus,
}

impl PrivateExerciseReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        series_id: &str,
        order_id: &str,
        margin_vault_id: &str,
        holder_label: &str,
        nullifier_label: &str,
        exercise_quantity_units: u64,
        settlement_price_units: u64,
        payout_units: u64,
        collateral_release_units: u64,
        oracle_guard_id: &str,
        exercised_at_height: u64,
        settlement_due_height: u64,
        metadata: &Value,
    ) -> ConfidentialOptionsResult<Self> {
        let holder_commitment = confidential_options_account_commitment(holder_label);
        let exercise_nullifier_hash =
            confidential_options_nullifier_hash(nullifier_label, series_id, order_id);
        let exercise_quantity_commitment = confidential_options_amount_commitment(
            "option-exercise-quantity",
            exercise_quantity_units,
            &confidential_options_blinding(holder_label, exercised_at_height, "exercise-quantity"),
        );
        let settlement_price_commitment = confidential_options_price_commitment(
            "option-exercise-settlement-price",
            settlement_price_units,
            &confidential_options_blinding(holder_label, exercised_at_height, "settlement-price"),
        );
        let payout_commitment = confidential_options_amount_commitment(
            "option-exercise-payout",
            payout_units,
            &confidential_options_blinding(holder_label, exercised_at_height, "exercise-payout"),
        );
        let collateral_release_commitment = confidential_options_amount_commitment(
            "option-exercise-collateral-release",
            collateral_release_units,
            &confidential_options_blinding(holder_label, exercised_at_height, "collateral-release"),
        );
        let exercise_proof_root = confidential_options_proof_root(
            CONFIDENTIAL_OPTIONS_EXERCISE_PROOF_SCHEME,
            &confidential_options_payload_root(
                "CONFIDENTIAL-OPTIONS-EXERCISE-PUBLIC-INPUT",
                metadata,
            ),
            &exercise_quantity_commitment,
        );
        let receipt_id = confidential_options_exercise_receipt_id(
            series_id,
            order_id,
            &holder_commitment,
            &exercise_nullifier_hash,
            exercised_at_height,
        );
        let receipt = Self {
            receipt_id,
            series_id: series_id.to_string(),
            order_id: order_id.to_string(),
            margin_vault_id: margin_vault_id.to_string(),
            holder_commitment,
            exercise_nullifier_hash,
            exercise_quantity_commitment,
            settlement_price_commitment,
            payout_commitment,
            collateral_release_commitment,
            oracle_guard_id: oracle_guard_id.to_string(),
            exercise_proof_root,
            privacy_budget_root: confidential_options_payload_root(
                "CONFIDENTIAL-OPTIONS-EXERCISE-PRIVACY-BUDGET",
                metadata,
            ),
            exercised_at_height,
            settlement_due_height,
            status: ExerciseReceiptStatus::Proven,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_option_exercise_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "series_id": self.series_id,
            "order_id": self.order_id,
            "margin_vault_id": self.margin_vault_id,
            "holder_commitment": self.holder_commitment,
            "exercise_nullifier_hash": self.exercise_nullifier_hash,
            "exercise_quantity_commitment": self.exercise_quantity_commitment,
            "settlement_price_commitment": self.settlement_price_commitment,
            "payout_commitment": self.payout_commitment,
            "collateral_release_commitment": self.collateral_release_commitment,
            "oracle_guard_id": self.oracle_guard_id,
            "exercise_proof_root": self.exercise_proof_root,
            "privacy_budget_root": self.privacy_budget_root,
            "exercised_at_height": self.exercised_at_height,
            "settlement_due_height": self.settlement_due_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialOptionsResult<()> {
        ensure_non_empty(&self.receipt_id, "exercise receipt receipt_id")?;
        ensure_non_empty(&self.series_id, "exercise receipt series_id")?;
        ensure_non_empty(&self.order_id, "exercise receipt order_id")?;
        ensure_non_empty(&self.margin_vault_id, "exercise receipt margin_vault_id")?;
        ensure_non_empty(
            &self.holder_commitment,
            "exercise receipt holder_commitment",
        )?;
        ensure_non_empty(
            &self.exercise_nullifier_hash,
            "exercise receipt exercise_nullifier_hash",
        )?;
        ensure_non_empty(
            &self.exercise_quantity_commitment,
            "exercise receipt exercise_quantity_commitment",
        )?;
        ensure_non_empty(
            &self.settlement_price_commitment,
            "exercise receipt settlement_price_commitment",
        )?;
        ensure_non_empty(
            &self.payout_commitment,
            "exercise receipt payout_commitment",
        )?;
        ensure_non_empty(
            &self.collateral_release_commitment,
            "exercise receipt collateral_release_commitment",
        )?;
        ensure_non_empty(&self.oracle_guard_id, "exercise receipt oracle_guard_id")?;
        ensure_non_empty(
            &self.exercise_proof_root,
            "exercise receipt exercise_proof_root",
        )?;
        ensure_non_empty(
            &self.privacy_budget_root,
            "exercise receipt privacy_budget_root",
        )?;
        if self.settlement_due_height < self.exercised_at_height {
            return Err("exercise receipt settlement due height precedes exercise".to_string());
        }
        let expected_id = confidential_options_exercise_receipt_id(
            &self.series_id,
            &self.order_id,
            &self.holder_commitment,
            &self.exercise_nullifier_hash,
            self.exercised_at_height,
        );
        if self.receipt_id != expected_id {
            return Err("exercise receipt id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionOracleGuardRoot {
    pub guard_id: String,
    pub series_id: String,
    pub oracle_feed_id: String,
    pub median_price_commitment: String,
    pub source_set_root: String,
    pub max_deviation_bps: u64,
    pub observed_deviation_bps: u64,
    pub max_staleness_blocks: u64,
    pub median_update_height: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub committee_id: String,
    pub quorum: u64,
    pub pq_signature_root: String,
    pub action: OracleGuardAction,
    pub status: OracleGuardStatus,
    pub severity: OptionRiskSeverity,
    pub metadata_root: String,
}

impl OptionOracleGuardRoot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        series_id: &str,
        oracle_feed_id: &str,
        median_price_units: u64,
        max_deviation_bps: u64,
        observed_deviation_bps: u64,
        max_staleness_blocks: u64,
        median_update_height: u64,
        valid_from_height: u64,
        valid_until_height: u64,
        committee_id: &str,
        quorum: u64,
        source_records: &[Value],
        action: OracleGuardAction,
        severity: OptionRiskSeverity,
        metadata: &Value,
    ) -> ConfidentialOptionsResult<Self> {
        let source_set_root = merkle_root("CONFIDENTIAL-OPTIONS-ORACLE-SOURCE", source_records);
        let median_price_commitment = confidential_options_price_commitment(
            "option-oracle-median-price",
            median_price_units,
            &confidential_options_blinding(series_id, median_update_height, "oracle-median"),
        );
        let guard_id = confidential_options_oracle_guard_id(
            series_id,
            oracle_feed_id,
            &source_set_root,
            median_update_height,
        );
        let guard = Self {
            guard_id,
            series_id: series_id.to_string(),
            oracle_feed_id: oracle_feed_id.to_string(),
            median_price_commitment,
            source_set_root,
            max_deviation_bps,
            observed_deviation_bps,
            max_staleness_blocks,
            median_update_height,
            valid_from_height,
            valid_until_height,
            committee_id: committee_id.to_string(),
            quorum,
            pq_signature_root: confidential_options_payload_root(
                "CONFIDENTIAL-OPTIONS-ORACLE-GUARD-PQ-SIGNATURE",
                metadata,
            ),
            action,
            status: OracleGuardStatus::Active,
            severity,
            metadata_root: confidential_options_payload_root(
                "CONFIDENTIAL-OPTIONS-ORACLE-GUARD-METADATA",
                metadata,
            ),
        };
        guard.validate()?;
        Ok(guard)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == OracleGuardStatus::Active
            && height >= self.valid_from_height
            && height <= self.valid_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_options_oracle_guard_root",
            "chain_id": CHAIN_ID,
            "guard_id": self.guard_id,
            "series_id": self.series_id,
            "oracle_feed_id": self.oracle_feed_id,
            "median_price_commitment": self.median_price_commitment,
            "source_set_root": self.source_set_root,
            "max_deviation_bps": self.max_deviation_bps,
            "observed_deviation_bps": self.observed_deviation_bps,
            "max_staleness_blocks": self.max_staleness_blocks,
            "median_update_height": self.median_update_height,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "committee_id": self.committee_id,
            "quorum": self.quorum,
            "pq_signature_root": self.pq_signature_root,
            "action": self.action.as_str(),
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "risk_score_bps": self.severity.score_bps().max(self.observed_deviation_bps),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn validate(&self) -> ConfidentialOptionsResult<()> {
        ensure_non_empty(&self.guard_id, "oracle guard guard_id")?;
        ensure_non_empty(&self.series_id, "oracle guard series_id")?;
        ensure_non_empty(&self.oracle_feed_id, "oracle guard oracle_feed_id")?;
        ensure_non_empty(
            &self.median_price_commitment,
            "oracle guard median_price_commitment",
        )?;
        ensure_non_empty(&self.source_set_root, "oracle guard source_set_root")?;
        ensure_non_empty(&self.committee_id, "oracle guard committee_id")?;
        ensure_non_empty(&self.pq_signature_root, "oracle guard pq_signature_root")?;
        ensure_non_empty(&self.metadata_root, "oracle guard metadata_root")?;
        ensure_bps(self.max_deviation_bps, "oracle guard max_deviation_bps")?;
        ensure_bps(
            self.observed_deviation_bps,
            "oracle guard observed_deviation_bps",
        )?;
        if self.max_staleness_blocks == 0 {
            return Err("oracle guard max staleness must be positive".to_string());
        }
        if self.quorum == 0 {
            return Err("oracle guard quorum must be positive".to_string());
        }
        if self.valid_until_height < self.valid_from_height {
            return Err("oracle guard validity window is inverted".to_string());
        }
        if self.median_update_height > self.valid_until_height {
            return Err("oracle guard median update is after validity window".to_string());
        }
        let expected_id = confidential_options_oracle_guard_id(
            &self.series_id,
            &self.oracle_feed_id,
            &self.source_set_root,
            self.median_update_height,
        );
        if self.guard_id != expected_id {
            return Err("oracle guard id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateOptionLiquidation {
    pub liquidation_id: String,
    pub series_id: String,
    pub margin_vault_id: String,
    pub order_id: String,
    pub keeper_commitment: String,
    pub health_factor_floor_bps: u64,
    pub required_margin_commitment: String,
    pub posted_margin_commitment: String,
    pub shortfall_commitment: String,
    pub collateral_seizure_commitment: String,
    pub oracle_guard_id: String,
    pub evidence_root: String,
    pub submitted_at_height: u64,
    pub challenge_until_height: u64,
    pub nonce: u64,
    pub status: OptionLiquidationStatus,
}

impl PrivateOptionLiquidation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        series_id: &str,
        margin_vault_id: &str,
        order_id: &str,
        keeper_label: &str,
        health_factor_floor_bps: u64,
        required_margin_units: u64,
        posted_margin_units: u64,
        shortfall_units: u64,
        collateral_seizure_units: u64,
        oracle_guard_id: &str,
        evidence: &Value,
        submitted_at_height: u64,
        challenge_window_blocks: u64,
        nonce: u64,
    ) -> ConfidentialOptionsResult<Self> {
        let keeper_commitment = confidential_options_account_commitment(keeper_label);
        let liquidation_id = confidential_options_liquidation_id(
            margin_vault_id,
            series_id,
            &keeper_commitment,
            submitted_at_height,
            nonce,
        );
        let liquidation = Self {
            liquidation_id,
            series_id: series_id.to_string(),
            margin_vault_id: margin_vault_id.to_string(),
            order_id: order_id.to_string(),
            keeper_commitment,
            health_factor_floor_bps,
            required_margin_commitment: confidential_options_amount_commitment(
                "option-liquidation-required-margin",
                required_margin_units,
                &confidential_options_blinding(keeper_label, nonce, "required-margin"),
            ),
            posted_margin_commitment: confidential_options_amount_commitment(
                "option-liquidation-posted-margin",
                posted_margin_units,
                &confidential_options_blinding(keeper_label, nonce, "posted-margin"),
            ),
            shortfall_commitment: confidential_options_amount_commitment(
                "option-liquidation-shortfall",
                shortfall_units,
                &confidential_options_blinding(keeper_label, nonce, "shortfall"),
            ),
            collateral_seizure_commitment: confidential_options_amount_commitment(
                "option-liquidation-collateral-seizure",
                collateral_seizure_units,
                &confidential_options_blinding(keeper_label, nonce, "seizure"),
            ),
            oracle_guard_id: oracle_guard_id.to_string(),
            evidence_root: confidential_options_payload_root(
                "CONFIDENTIAL-OPTIONS-LIQUIDATION-EVIDENCE",
                evidence,
            ),
            submitted_at_height,
            challenge_until_height: submitted_at_height.saturating_add(challenge_window_blocks),
            nonce,
            status: OptionLiquidationStatus::ChallengeOpen,
        };
        liquidation.validate()?;
        Ok(liquidation)
    }

    pub fn is_open_at(&self, height: u64) -> bool {
        self.status.is_open() && height <= self.challenge_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_option_liquidation",
            "chain_id": CHAIN_ID,
            "liquidation_id": self.liquidation_id,
            "series_id": self.series_id,
            "margin_vault_id": self.margin_vault_id,
            "order_id": self.order_id,
            "keeper_commitment": self.keeper_commitment,
            "health_factor_floor_bps": self.health_factor_floor_bps,
            "required_margin_commitment": self.required_margin_commitment,
            "posted_margin_commitment": self.posted_margin_commitment,
            "shortfall_commitment": self.shortfall_commitment,
            "collateral_seizure_commitment": self.collateral_seizure_commitment,
            "oracle_guard_id": self.oracle_guard_id,
            "evidence_root": self.evidence_root,
            "submitted_at_height": self.submitted_at_height,
            "challenge_until_height": self.challenge_until_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialOptionsResult<()> {
        ensure_non_empty(&self.liquidation_id, "liquidation liquidation_id")?;
        ensure_non_empty(&self.series_id, "liquidation series_id")?;
        ensure_non_empty(&self.margin_vault_id, "liquidation margin_vault_id")?;
        ensure_non_empty(&self.order_id, "liquidation order_id")?;
        ensure_non_empty(&self.keeper_commitment, "liquidation keeper_commitment")?;
        ensure_non_empty(
            &self.required_margin_commitment,
            "liquidation required_margin_commitment",
        )?;
        ensure_non_empty(
            &self.posted_margin_commitment,
            "liquidation posted_margin_commitment",
        )?;
        ensure_non_empty(
            &self.shortfall_commitment,
            "liquidation shortfall_commitment",
        )?;
        ensure_non_empty(
            &self.collateral_seizure_commitment,
            "liquidation collateral_seizure_commitment",
        )?;
        ensure_non_empty(&self.oracle_guard_id, "liquidation oracle_guard_id")?;
        ensure_non_empty(&self.evidence_root, "liquidation evidence_root")?;
        ensure_margin_bps(
            self.health_factor_floor_bps,
            "liquidation health_factor_floor_bps",
        )?;
        if self.challenge_until_height < self.submitted_at_height {
            return Err("liquidation challenge window is inverted".to_string());
        }
        let expected_id = confidential_options_liquidation_id(
            &self.margin_vault_id,
            &self.series_id,
            &self.keeper_commitment,
            self.submitted_at_height,
            self.nonce,
        );
        if self.liquidation_id != expected_id {
            return Err("liquidation id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionSettlementBatch {
    pub batch_id: String,
    pub series_id: String,
    pub oracle_guard_id: String,
    pub settlement_height: u64,
    pub sealed_order_root: String,
    pub exercise_receipt_root: String,
    pub liquidation_root: String,
    pub margin_delta_root: String,
    pub payout_root: String,
    pub fee_root: String,
    pub low_fee_rebate_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub circuit_proof_root: String,
    pub emitted_at_height: u64,
    pub nonce: u64,
    pub status: OptionSettlementStatus,
}

impl OptionSettlementBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        series_id: &str,
        oracle_guard_id: &str,
        settlement_height: u64,
        sealed_orders: &[SealedOptionOrder],
        exercise_receipts: &[PrivateExerciseReceipt],
        liquidations: &[PrivateOptionLiquidation],
        margin_deltas: &[Value],
        payout_records: &[Value],
        fee_records: &[Value],
        low_fee_rebates: &[Value],
        pre_state_root: &str,
        post_state_root: &str,
        emitted_at_height: u64,
        nonce: u64,
    ) -> ConfidentialOptionsResult<Self> {
        let sealed_order_root = confidential_options_sealed_order_root(sealed_orders);
        let exercise_receipt_root = confidential_options_exercise_receipt_root(exercise_receipts);
        let liquidation_root = confidential_options_liquidation_root(liquidations);
        let margin_delta_root = merkle_root("CONFIDENTIAL-OPTIONS-MARGIN-DELTA", margin_deltas);
        let payout_root = merkle_root("CONFIDENTIAL-OPTIONS-PAYOUT", payout_records);
        let fee_root = merkle_root("CONFIDENTIAL-OPTIONS-FEE", fee_records);
        let low_fee_rebate_root =
            merkle_root("CONFIDENTIAL-OPTIONS-LOW-FEE-REBATE", low_fee_rebates);
        let batch_id = confidential_options_settlement_batch_id(
            series_id,
            settlement_height,
            &sealed_order_root,
            &exercise_receipt_root,
            nonce,
        );
        let batch = Self {
            batch_id,
            series_id: series_id.to_string(),
            oracle_guard_id: oracle_guard_id.to_string(),
            settlement_height,
            sealed_order_root,
            exercise_receipt_root,
            liquidation_root,
            margin_delta_root,
            payout_root,
            fee_root,
            low_fee_rebate_root,
            pre_state_root: pre_state_root.to_string(),
            post_state_root: post_state_root.to_string(),
            circuit_proof_root: confidential_options_proof_root(
                CONFIDENTIAL_OPTIONS_SETTLEMENT_SCHEME,
                pre_state_root,
                post_state_root,
            ),
            emitted_at_height,
            nonce,
            status: OptionSettlementStatus::PendingProof,
        };
        batch.validate()?;
        Ok(batch)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_options_settlement_batch",
            "chain_id": CHAIN_ID,
            "batch_id": self.batch_id,
            "series_id": self.series_id,
            "oracle_guard_id": self.oracle_guard_id,
            "settlement_height": self.settlement_height,
            "sealed_order_root": self.sealed_order_root,
            "exercise_receipt_root": self.exercise_receipt_root,
            "liquidation_root": self.liquidation_root,
            "margin_delta_root": self.margin_delta_root,
            "payout_root": self.payout_root,
            "fee_root": self.fee_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "circuit_proof_root": self.circuit_proof_root,
            "emitted_at_height": self.emitted_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialOptionsResult<()> {
        ensure_non_empty(&self.batch_id, "settlement batch batch_id")?;
        ensure_non_empty(&self.series_id, "settlement batch series_id")?;
        ensure_non_empty(&self.oracle_guard_id, "settlement batch oracle_guard_id")?;
        ensure_non_empty(
            &self.sealed_order_root,
            "settlement batch sealed_order_root",
        )?;
        ensure_non_empty(
            &self.exercise_receipt_root,
            "settlement batch exercise_receipt_root",
        )?;
        ensure_non_empty(&self.liquidation_root, "settlement batch liquidation_root")?;
        ensure_non_empty(
            &self.margin_delta_root,
            "settlement batch margin_delta_root",
        )?;
        ensure_non_empty(&self.payout_root, "settlement batch payout_root")?;
        ensure_non_empty(&self.fee_root, "settlement batch fee_root")?;
        ensure_non_empty(
            &self.low_fee_rebate_root,
            "settlement batch low_fee_rebate_root",
        )?;
        ensure_non_empty(&self.pre_state_root, "settlement batch pre_state_root")?;
        ensure_non_empty(&self.post_state_root, "settlement batch post_state_root")?;
        ensure_non_empty(
            &self.circuit_proof_root,
            "settlement batch circuit_proof_root",
        )?;
        if self.emitted_at_height < self.settlement_height {
            return Err("settlement batch emitted height precedes settlement height".to_string());
        }
        let expected_id = confidential_options_settlement_batch_id(
            &self.series_id,
            self.settlement_height,
            &self.sealed_order_root,
            &self.exercise_receipt_root,
            self.nonce,
        );
        if self.batch_id != expected_id {
            return Err("settlement batch id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeHedgingSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub series_id: String,
    pub lane_id: String,
    pub fee_asset_id: String,
    pub hedging_strategy_root: String,
    pub sponsored_notional_cap_units: u64,
    pub reserved_fee_units: u64,
    pub spent_fee_units: u64,
    pub max_fee_per_order_units: u64,
    pub rebate_bps: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: HedgingSponsorshipStatus,
}

impl LowFeeHedgingSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_label: &str,
        beneficiary_label: &str,
        series_id: &str,
        lane_id: &str,
        fee_asset_id: &str,
        sponsored_notional_cap_units: u64,
        reserved_fee_units: u64,
        max_fee_per_order_units: u64,
        rebate_bps: u64,
        strategy: &Value,
        created_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> ConfidentialOptionsResult<Self> {
        let sponsor_commitment = confidential_options_account_commitment(sponsor_label);
        let beneficiary_commitment = confidential_options_account_commitment(beneficiary_label);
        let sponsorship_id = confidential_options_sponsorship_id(
            &sponsor_commitment,
            &beneficiary_commitment,
            series_id,
            lane_id,
            nonce,
        );
        let sponsorship = Self {
            sponsorship_id,
            sponsor_commitment,
            beneficiary_commitment,
            series_id: series_id.to_string(),
            lane_id: lane_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            hedging_strategy_root: confidential_options_payload_root(
                "CONFIDENTIAL-OPTIONS-HEDGING-SPONSORSHIP-STRATEGY",
                strategy,
            ),
            sponsored_notional_cap_units,
            reserved_fee_units,
            spent_fee_units: 0,
            max_fee_per_order_units,
            rebate_bps,
            created_at_height,
            expires_at_height,
            nonce,
            status: HedgingSponsorshipStatus::Active,
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn available_fee_units(&self) -> u64 {
        self.reserved_fee_units.saturating_sub(self.spent_fee_units)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        matches!(
            self.status,
            HedgingSponsorshipStatus::Reserved | HedgingSponsorshipStatus::Active
        ) && height >= self.created_at_height
            && height <= self.expires_at_height
            && self.available_fee_units() > 0
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_options_hedging_sponsorship",
            "chain_id": CHAIN_ID,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "series_id": self.series_id,
            "lane_id": self.lane_id,
            "fee_asset_id": self.fee_asset_id,
            "hedging_strategy_root": self.hedging_strategy_root,
            "sponsored_notional_cap_units": self.sponsored_notional_cap_units,
            "reserved_fee_units": self.reserved_fee_units,
            "spent_fee_units": self.spent_fee_units,
            "available_fee_units": self.available_fee_units(),
            "max_fee_per_order_units": self.max_fee_per_order_units,
            "rebate_bps": self.rebate_bps,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialOptionsResult<()> {
        ensure_non_empty(&self.sponsorship_id, "sponsorship sponsorship_id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsorship sponsor_commitment")?;
        ensure_non_empty(
            &self.beneficiary_commitment,
            "sponsorship beneficiary_commitment",
        )?;
        ensure_non_empty(&self.series_id, "sponsorship series_id")?;
        ensure_non_empty(&self.lane_id, "sponsorship lane_id")?;
        ensure_non_empty(&self.fee_asset_id, "sponsorship fee_asset_id")?;
        ensure_non_empty(
            &self.hedging_strategy_root,
            "sponsorship hedging_strategy_root",
        )?;
        ensure_bps(self.rebate_bps, "sponsorship rebate_bps")?;
        if self.sponsored_notional_cap_units == 0 {
            return Err("sponsorship notional cap must be positive".to_string());
        }
        if self.max_fee_per_order_units == 0 {
            return Err("sponsorship max fee per order must be positive".to_string());
        }
        if self.spent_fee_units > self.reserved_fee_units {
            return Err("sponsorship spent fee exceeds reserved fee".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("sponsorship expiration must be after creation".to_string());
        }
        let expected_id = confidential_options_sponsorship_id(
            &self.sponsor_commitment,
            &self.beneficiary_commitment,
            &self.series_id,
            &self.lane_id,
            self.nonce,
        );
        if self.sponsorship_id != expected_id {
            return Err("sponsorship id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqMarketMakerQuote {
    pub quote_id: String,
    pub series_id: String,
    pub market_maker_commitment: String,
    pub quote_kind: PqQuoteKind,
    pub bid_premium_commitment: String,
    pub ask_premium_commitment: String,
    pub max_contracts_commitment: String,
    pub delta_hedge_commitment: String,
    pub collateral_vault_id: String,
    pub oracle_guard_id: String,
    pub fee_bps: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub quote_policy_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub signature_scheme: String,
    pub nonce: u64,
    pub status: PqQuoteStatus,
}

impl PqMarketMakerQuote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        series_id: &str,
        market_maker_label: &str,
        quote_kind: PqQuoteKind,
        bid_premium_units: u64,
        ask_premium_units: u64,
        max_contracts_units: u64,
        delta_hedge_units: u64,
        collateral_vault_id: &str,
        oracle_guard_id: &str,
        fee_bps: u64,
        valid_from_height: u64,
        valid_until_height: u64,
        policy: &Value,
        pq_public_key: &Value,
        pq_signature: &Value,
        nonce: u64,
    ) -> ConfidentialOptionsResult<Self> {
        let market_maker_commitment = confidential_options_account_commitment(market_maker_label);
        let bid_premium_commitment = confidential_options_amount_commitment(
            "option-mm-bid-premium",
            bid_premium_units,
            &confidential_options_blinding(market_maker_label, nonce, "mm-bid"),
        );
        let ask_premium_commitment = confidential_options_amount_commitment(
            "option-mm-ask-premium",
            ask_premium_units,
            &confidential_options_blinding(market_maker_label, nonce, "mm-ask"),
        );
        let quote_id = confidential_options_pq_quote_id(
            &market_maker_commitment,
            series_id,
            &bid_premium_commitment,
            &ask_premium_commitment,
            valid_from_height,
            nonce,
        );
        let quote = Self {
            quote_id,
            series_id: series_id.to_string(),
            market_maker_commitment,
            quote_kind,
            bid_premium_commitment,
            ask_premium_commitment,
            max_contracts_commitment: confidential_options_amount_commitment(
                "option-mm-max-contracts",
                max_contracts_units,
                &confidential_options_blinding(market_maker_label, nonce, "mm-max-contracts"),
            ),
            delta_hedge_commitment: confidential_options_amount_commitment(
                "option-mm-delta-hedge",
                delta_hedge_units,
                &confidential_options_blinding(market_maker_label, nonce, "mm-delta"),
            ),
            collateral_vault_id: collateral_vault_id.to_string(),
            oracle_guard_id: oracle_guard_id.to_string(),
            fee_bps,
            valid_from_height,
            valid_until_height,
            quote_policy_root: confidential_options_payload_root(
                "CONFIDENTIAL-OPTIONS-PQ-QUOTE-POLICY",
                policy,
            ),
            pq_public_key_root: confidential_options_payload_root(
                "CONFIDENTIAL-OPTIONS-PQ-QUOTE-PUBLIC-KEY",
                pq_public_key,
            ),
            pq_signature_root: confidential_options_payload_root(
                "CONFIDENTIAL-OPTIONS-PQ-QUOTE-SIGNATURE",
                pq_signature,
            ),
            signature_scheme: CONFIDENTIAL_OPTIONS_PQ_QUOTE_SCHEME.to_string(),
            nonce,
            status: PqQuoteStatus::Firm,
        };
        quote.validate()?;
        Ok(quote)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        matches!(self.status, PqQuoteStatus::Indicative | PqQuoteStatus::Firm)
            && height >= self.valid_from_height
            && height <= self.valid_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_signed_market_maker_quote",
            "chain_id": CHAIN_ID,
            "quote_id": self.quote_id,
            "series_id": self.series_id,
            "market_maker_commitment": self.market_maker_commitment,
            "quote_kind": self.quote_kind.as_str(),
            "bid_premium_commitment": self.bid_premium_commitment,
            "ask_premium_commitment": self.ask_premium_commitment,
            "max_contracts_commitment": self.max_contracts_commitment,
            "delta_hedge_commitment": self.delta_hedge_commitment,
            "collateral_vault_id": self.collateral_vault_id,
            "oracle_guard_id": self.oracle_guard_id,
            "fee_bps": self.fee_bps,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "quote_policy_root": self.quote_policy_root,
            "pq_public_key_root": self.pq_public_key_root,
            "pq_signature_root": self.pq_signature_root,
            "signature_scheme": self.signature_scheme,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialOptionsResult<()> {
        ensure_non_empty(&self.quote_id, "pq quote quote_id")?;
        ensure_non_empty(&self.series_id, "pq quote series_id")?;
        ensure_non_empty(
            &self.market_maker_commitment,
            "pq quote market_maker_commitment",
        )?;
        ensure_non_empty(
            &self.bid_premium_commitment,
            "pq quote bid_premium_commitment",
        )?;
        ensure_non_empty(
            &self.ask_premium_commitment,
            "pq quote ask_premium_commitment",
        )?;
        ensure_non_empty(
            &self.max_contracts_commitment,
            "pq quote max_contracts_commitment",
        )?;
        ensure_non_empty(
            &self.delta_hedge_commitment,
            "pq quote delta_hedge_commitment",
        )?;
        ensure_non_empty(&self.collateral_vault_id, "pq quote collateral_vault_id")?;
        ensure_non_empty(&self.oracle_guard_id, "pq quote oracle_guard_id")?;
        ensure_non_empty(&self.quote_policy_root, "pq quote quote_policy_root")?;
        ensure_non_empty(&self.pq_public_key_root, "pq quote pq_public_key_root")?;
        ensure_non_empty(&self.pq_signature_root, "pq quote pq_signature_root")?;
        ensure_non_empty(&self.signature_scheme, "pq quote signature_scheme")?;
        ensure_bps(self.fee_bps, "pq quote fee_bps")?;
        if self.valid_until_height <= self.valid_from_height {
            return Err("pq quote validity window is invalid".to_string());
        }
        let expected_id = confidential_options_pq_quote_id(
            &self.market_maker_commitment,
            &self.series_id,
            &self.bid_premium_commitment,
            &self.ask_premium_commitment,
            self.valid_from_height,
            self.nonce,
        );
        if self.quote_id != expected_id {
            return Err("pq quote id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialOptionsPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl ConfidentialOptionsPublicRecord {
    pub fn new(
        record_kind: &str,
        subject_id: &str,
        payload: &Value,
        emitted_at_height: u64,
        sequence: u64,
    ) -> ConfidentialOptionsResult<Self> {
        let payload_root =
            confidential_options_payload_root("CONFIDENTIAL-OPTIONS-PUBLIC-PAYLOAD", payload);
        let record_id = confidential_options_public_record_id(
            record_kind,
            subject_id,
            &payload_root,
            emitted_at_height,
            sequence,
        );
        let record = Self {
            record_id,
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            emitted_at_height,
            sequence,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_options_public_record",
            "chain_id": CHAIN_ID,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn validate(&self) -> ConfidentialOptionsResult<()> {
        ensure_non_empty(&self.record_id, "public record record_id")?;
        ensure_non_empty(&self.record_kind, "public record record_kind")?;
        ensure_non_empty(&self.subject_id, "public record subject_id")?;
        ensure_non_empty(&self.payload_root, "public record payload_root")?;
        let expected_id = confidential_options_public_record_id(
            &self.record_kind,
            &self.subject_id,
            &self.payload_root,
            self.emitted_at_height,
            self.sequence,
        );
        if self.record_id != expected_id {
            return Err("public record id does not match deterministic fields".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialOptionsCounters {
    pub series_count: u64,
    pub active_series_count: u64,
    pub margin_vault_count: u64,
    pub open_margin_vault_count: u64,
    pub sealed_order_count: u64,
    pub live_sealed_order_count: u64,
    pub exercise_receipt_count: u64,
    pub proven_exercise_receipt_count: u64,
    pub oracle_guard_count: u64,
    pub active_oracle_guard_count: u64,
    pub liquidation_count: u64,
    pub open_liquidation_count: u64,
    pub settlement_batch_count: u64,
    pub pending_settlement_batch_count: u64,
    pub low_fee_sponsorship_count: u64,
    pub active_low_fee_sponsorship_count: u64,
    pub pq_quote_count: u64,
    pub live_pq_quote_count: u64,
    pub public_record_count: u64,
    pub total_margin_floor_units: u64,
    pub total_available_margin_floor_units: u64,
    pub total_sponsored_fee_budget_units: u64,
    pub aggregate_risk_score_bps: u64,
}

impl ConfidentialOptionsCounters {
    pub fn risk_status(&self) -> &'static str {
        confidential_options_risk_status(self.aggregate_risk_score_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_options_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_OPTIONS_PROTOCOL_VERSION,
            "series_count": self.series_count,
            "active_series_count": self.active_series_count,
            "margin_vault_count": self.margin_vault_count,
            "open_margin_vault_count": self.open_margin_vault_count,
            "sealed_order_count": self.sealed_order_count,
            "live_sealed_order_count": self.live_sealed_order_count,
            "exercise_receipt_count": self.exercise_receipt_count,
            "proven_exercise_receipt_count": self.proven_exercise_receipt_count,
            "oracle_guard_count": self.oracle_guard_count,
            "active_oracle_guard_count": self.active_oracle_guard_count,
            "liquidation_count": self.liquidation_count,
            "open_liquidation_count": self.open_liquidation_count,
            "settlement_batch_count": self.settlement_batch_count,
            "pending_settlement_batch_count": self.pending_settlement_batch_count,
            "low_fee_sponsorship_count": self.low_fee_sponsorship_count,
            "active_low_fee_sponsorship_count": self.active_low_fee_sponsorship_count,
            "pq_quote_count": self.pq_quote_count,
            "live_pq_quote_count": self.live_pq_quote_count,
            "public_record_count": self.public_record_count,
            "total_margin_floor_units": self.total_margin_floor_units,
            "total_available_margin_floor_units": self.total_available_margin_floor_units,
            "total_sponsored_fee_budget_units": self.total_sponsored_fee_budget_units,
            "aggregate_risk_score_bps": self.aggregate_risk_score_bps,
            "risk_status": self.risk_status(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialOptionsRoots {
    pub config_root: String,
    pub series_root: String,
    pub margin_vault_root: String,
    pub sealed_order_root: String,
    pub exercise_receipt_root: String,
    pub oracle_guard_root: String,
    pub liquidation_root: String,
    pub settlement_batch_root: String,
    pub low_fee_sponsorship_root: String,
    pub pq_quote_root: String,
    pub public_record_root: String,
}

impl ConfidentialOptionsRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_options_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_OPTIONS_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "series_root": self.series_root,
            "margin_vault_root": self.margin_vault_root,
            "sealed_order_root": self.sealed_order_root,
            "exercise_receipt_root": self.exercise_receipt_root,
            "oracle_guard_root": self.oracle_guard_root,
            "liquidation_root": self.liquidation_root,
            "settlement_batch_root": self.settlement_batch_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "pq_quote_root": self.pq_quote_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        confidential_options_state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialOptionsState {
    pub height: u64,
    pub nonce: u64,
    pub config: ConfidentialOptionsConfig,
    pub series: BTreeMap<String, ConfidentialOptionSeries>,
    pub margin_vaults: BTreeMap<String, OptionMarginVault>,
    pub sealed_orders: BTreeMap<String, SealedOptionOrder>,
    pub exercise_receipts: BTreeMap<String, PrivateExerciseReceipt>,
    pub oracle_guards: BTreeMap<String, OptionOracleGuardRoot>,
    pub liquidations: BTreeMap<String, PrivateOptionLiquidation>,
    pub settlement_batches: BTreeMap<String, OptionSettlementBatch>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeHedgingSponsorship>,
    pub pq_quotes: BTreeMap<String, PqMarketMakerQuote>,
    pub public_records: BTreeMap<String, ConfidentialOptionsPublicRecord>,
}

impl Default for ConfidentialOptionsState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfidentialOptionsState {
    pub fn new() -> Self {
        Self {
            height: 0,
            nonce: 0,
            config: ConfidentialOptionsConfig::default(),
            series: BTreeMap::new(),
            margin_vaults: BTreeMap::new(),
            sealed_orders: BTreeMap::new(),
            exercise_receipts: BTreeMap::new(),
            oracle_guards: BTreeMap::new(),
            liquidations: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            pq_quotes: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn with_config(config: ConfidentialOptionsConfig) -> ConfidentialOptionsResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            ..Self::new()
        })
    }

    pub fn devnet() -> ConfidentialOptionsResult<Self> {
        let mut state = Self::with_config(ConfidentialOptionsConfig::devnet())?;
        state.set_height(CONFIDENTIAL_OPTIONS_DEVNET_HEIGHT);

        let mut call_series = ConfidentialOptionSeries::wxmr_private_stable_call_devnet(
            state.height.saturating_sub(96),
            state.height.saturating_sub(8),
            state.height.saturating_add(96),
            state.height.saturating_add(104),
        )?;
        call_series.open_interest_call_units = 12_000_000_000;
        let call_series_id = call_series.series_id.clone();
        state.insert_series(call_series)?;

        let structured_series = ConfidentialOptionSeries::principal_protected_note_devnet(
            state.height.saturating_sub(80),
            state.height.saturating_add(24),
            state.height.saturating_add(240),
            state.height.saturating_add(248),
        )?;
        let structured_series_id = structured_series.series_id.clone();
        state.insert_series(structured_series)?;

        let collateral_asset_id = state.config.collateral_asset_id.clone();
        let premium_asset_id = state.config.premium_asset_id.clone();
        let default_low_fee_lane = state.config.default_low_fee_lane.clone();
        let default_order_ttl_blocks = state.config.default_order_ttl_blocks;
        let default_exercise_ttl_blocks = state.config.default_exercise_ttl_blocks;
        let default_challenge_window_blocks = state.config.default_challenge_window_blocks;
        let max_oracle_deviation_bps = state.config.max_oracle_deviation_bps;
        let max_oracle_staleness_blocks = state.config.max_oracle_staleness_blocks;

        let maker_vault = OptionMarginVault::new(
            "devnet-market-maker-options",
            &collateral_asset_id,
            900_000_000_000,
            275_000_000_000,
            8_000,
            10_500,
            state.height.saturating_sub(72),
            state.next_nonce(),
            &json!({
                "role": "market_maker_margin",
                "asset": "private_stablecoin",
                "visibility": "floor_and_commitments"
            }),
        )?;
        let maker_vault_id = maker_vault.vault_id.clone();
        state.insert_margin_vault(maker_vault)?;

        let trader_vault = OptionMarginVault::new(
            "devnet-alice-options",
            &collateral_asset_id,
            120_000_000_000,
            15_000_000_000,
            6_500,
            8_500,
            state.height.saturating_sub(48),
            state.next_nonce(),
            &json!({"role": "private_hedger", "asset": "private_stablecoin"}),
        )?;
        let trader_vault_id = trader_vault.vault_id.clone();
        state.insert_margin_vault(trader_vault)?;

        let oracle_guard = OptionOracleGuardRoot::new(
            &call_series_id,
            CONFIDENTIAL_OPTIONS_DEVNET_ORACLE_FEED_ID,
            178 * CONFIDENTIAL_OPTIONS_PRICE_SCALE,
            max_oracle_deviation_bps,
            210,
            max_oracle_staleness_blocks,
            state.height.saturating_sub(1),
            state.height.saturating_sub(1),
            state.height.saturating_add(12),
            "devnet-options-oracle-committee",
            3,
            &[
                json!({"source": "devnet-median-1", "height": state.height - 2}),
                json!({"source": "devnet-median-2", "height": state.height - 1}),
                json!({"source": "devnet-median-3", "height": state.height - 1}),
            ],
            OracleGuardAction::Watch,
            OptionRiskSeverity::Watch,
            &json!({
                "threshold": "3-of-5",
                "pq_signature_scheme": CONFIDENTIAL_OPTIONS_PQ_QUOTE_SCHEME
            }),
        )?;
        let oracle_guard_id = oracle_guard.guard_id.clone();
        state.insert_oracle_guard(oracle_guard)?;

        let structured_guard = OptionOracleGuardRoot::new(
            &structured_series_id,
            CONFIDENTIAL_OPTIONS_DEVNET_ORACLE_FEED_ID,
            176 * CONFIDENTIAL_OPTIONS_PRICE_SCALE,
            max_oracle_deviation_bps,
            320,
            max_oracle_staleness_blocks,
            state.height.saturating_sub(1),
            state.height,
            state.height.saturating_add(12),
            "devnet-options-oracle-committee",
            3,
            &[json!({"source": "devnet-structured-note-median", "height": state.height - 1})],
            OracleGuardAction::Allow,
            OptionRiskSeverity::Healthy,
            &json!({"product": "principal_protected_note", "barrier_monitor": true}),
        )?;
        state.insert_oracle_guard(structured_guard)?;

        let pq_quote = PqMarketMakerQuote::new(
            &call_series_id,
            "devnet-market-maker-options",
            PqQuoteKind::TwoWay,
            2_850_000,
            3_150_000,
            25_000_000_000,
            8_500_000_000,
            &maker_vault_id,
            &oracle_guard_id,
            3,
            state.height.saturating_sub(1),
            state.height.saturating_add(18),
            &json!({
                "quote": "firm_two_way",
                "hedge": "low_fee_delta_rebalance",
                "max_slippage_bps": 85
            }),
            &json!({"scheme": CONFIDENTIAL_OPTIONS_PQ_QUOTE_SCHEME, "member": "mm-key-1"}),
            &json!({"aggregate_signature_root": "devnet-mm-quote-pq-sig-root"}),
            state.next_nonce(),
        )?;
        let pq_quote_id = pq_quote.quote_id.clone();
        state.insert_pq_quote(pq_quote)?;

        let sponsorship = LowFeeHedgingSponsorship::new(
            "devnet-foundation-paymaster",
            "devnet-alice-options",
            &call_series_id,
            &default_low_fee_lane,
            &premium_asset_id,
            25_000_000_000,
            350_000,
            7_500,
            8_500,
            &json!({
                "target": "small_private_option_hedges",
                "strategy": "delta_hedge_rebalances_and_exercise_receipts"
            }),
            state.height.saturating_sub(6),
            state.height.saturating_add(180),
            state.next_nonce(),
        )?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        state.insert_low_fee_sponsorship(sponsorship)?;

        let order = SealedOptionOrder::new(
            &call_series_id,
            &trader_vault_id,
            "devnet-alice-options",
            OptionOrderSide::Buy,
            OptionPositionEffect::Hedge,
            12_000_000_000,
            3_200_000,
            15_000_000_000,
            7_500,
            &pq_quote_id,
            &sponsorship_id,
            &json!({
                "ciphertext": "devnet-alice-covered-call-order",
                "routing": "threshold_encrypted_batch",
                "intent": "hedge_wxmr_exposure"
            }),
            state.height.saturating_sub(4),
            state.height.saturating_add(default_order_ttl_blocks),
            state.next_nonce(),
        )?;
        let order_id = order.order_id.clone();
        state.insert_sealed_order(order)?;

        let exercise_receipt = PrivateExerciseReceipt::new(
            &call_series_id,
            &order_id,
            &trader_vault_id,
            "devnet-alice-options",
            "alice-option-exercise-nullifier-0",
            4_000_000_000,
            181 * CONFIDENTIAL_OPTIONS_PRICE_SCALE,
            4_000_000,
            2_000_000,
            &oracle_guard_id,
            state.height,
            state.height.saturating_add(default_exercise_ttl_blocks),
            &json!({
                "exercise": "private_receipt",
                "proof": CONFIDENTIAL_OPTIONS_EXERCISE_PROOF_SCHEME,
                "reveals": "nullifier_and_commitment_roots_only"
            }),
        )?;
        let receipt_id = exercise_receipt.receipt_id.clone();
        state.insert_exercise_receipt(exercise_receipt)?;

        let liquidation = PrivateOptionLiquidation::new(
            &call_series_id,
            &maker_vault_id,
            &order_id,
            "devnet-options-keeper",
            7_900,
            45_000_000_000,
            38_000_000_000,
            7_000_000_000,
            8_000_000_000,
            &oracle_guard_id,
            &json!({
                "reason": "margin_floor_watch",
                "series_id": call_series_id.clone(),
                "vault_id": maker_vault_id.clone()
            }),
            state.height.saturating_sub(2),
            default_challenge_window_blocks,
            state.next_nonce(),
        )?;
        state.insert_liquidation(liquidation)?;

        let pre_state_root = confidential_options_string_root(
            "CONFIDENTIAL-OPTIONS-DEVNET-PRE-STATE",
            "pre-settlement-root",
        );
        let post_state_root = confidential_options_string_root(
            "CONFIDENTIAL-OPTIONS-DEVNET-POST-STATE",
            "post-settlement-root",
        );
        let order_values = state.sealed_orders.values().cloned().collect::<Vec<_>>();
        let receipt_values = state
            .exercise_receipts
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let liquidation_values = state.liquidations.values().cloned().collect::<Vec<_>>();
        let settlement = OptionSettlementBatch::new(
            &call_series_id,
            &oracle_guard_id,
            state.height,
            &order_values,
            &receipt_values,
            &liquidation_values,
            &[json!({"vault_id": trader_vault_id, "delta": "private_margin_release"})],
            &[json!({"receipt_id": receipt_id, "payout": "private_stablecoin_commitment"})],
            &[json!({"sponsorship_id": sponsorship_id, "fee": "sponsored"})],
            &[json!({"lane": default_low_fee_lane, "rebate": "bounded"})],
            &pre_state_root,
            &post_state_root,
            state.height.saturating_add(1),
            state.next_nonce(),
        )?;
        state.insert_settlement_batch(settlement)?;

        let public_record = ConfidentialOptionsPublicRecord::new(
            "devnet_state_root",
            &call_series_id,
            &json!({
                "height": state.height,
                "series_id": call_series_id,
                "state_root": state.state_root(),
                "privacy": "roots_and_commitments_only"
            }),
            state.height,
            state.next_nonce(),
        )?;
        state.insert_public_record(public_record)?;

        state.refresh_series_roots();
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn next_nonce(&mut self) -> u64 {
        self.nonce = self.nonce.saturating_add(1);
        self.nonce
    }

    pub fn insert_series(
        &mut self,
        series: ConfidentialOptionSeries,
    ) -> ConfidentialOptionsResult<ConfidentialOptionSeries> {
        series.validate()?;
        self.series.insert(series.series_id.clone(), series.clone());
        Ok(series)
    }

    pub fn insert_margin_vault(
        &mut self,
        vault: OptionMarginVault,
    ) -> ConfidentialOptionsResult<OptionMarginVault> {
        vault.validate()?;
        self.margin_vaults
            .insert(vault.vault_id.clone(), vault.clone());
        Ok(vault)
    }

    pub fn insert_sealed_order(
        &mut self,
        order: SealedOptionOrder,
    ) -> ConfidentialOptionsResult<SealedOptionOrder> {
        order.validate()?;
        ensure_state_series(&self.series, &order.series_id, "sealed order")?;
        ensure_state_vault(&self.margin_vaults, &order.margin_vault_id, "sealed order")?;
        if !order.quote_id.is_empty() && !self.pq_quotes.contains_key(&order.quote_id) {
            return Err("sealed order references missing pq quote".to_string());
        }
        if !order.sponsorship_id.is_empty()
            && !self
                .low_fee_sponsorships
                .contains_key(&order.sponsorship_id)
        {
            return Err("sealed order references missing low fee sponsorship".to_string());
        }
        self.sealed_orders
            .insert(order.order_id.clone(), order.clone());
        Ok(order)
    }

    pub fn insert_exercise_receipt(
        &mut self,
        receipt: PrivateExerciseReceipt,
    ) -> ConfidentialOptionsResult<PrivateExerciseReceipt> {
        receipt.validate()?;
        ensure_state_series(&self.series, &receipt.series_id, "exercise receipt")?;
        ensure_state_vault(
            &self.margin_vaults,
            &receipt.margin_vault_id,
            "exercise receipt",
        )?;
        if !self.sealed_orders.contains_key(&receipt.order_id) {
            return Err("exercise receipt references missing sealed order".to_string());
        }
        if !self.oracle_guards.contains_key(&receipt.oracle_guard_id) {
            return Err("exercise receipt references missing oracle guard".to_string());
        }
        self.exercise_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    pub fn insert_oracle_guard(
        &mut self,
        guard: OptionOracleGuardRoot,
    ) -> ConfidentialOptionsResult<OptionOracleGuardRoot> {
        guard.validate()?;
        ensure_state_series(&self.series, &guard.series_id, "oracle guard")?;
        self.oracle_guards
            .insert(guard.guard_id.clone(), guard.clone());
        Ok(guard)
    }

    pub fn insert_liquidation(
        &mut self,
        liquidation: PrivateOptionLiquidation,
    ) -> ConfidentialOptionsResult<PrivateOptionLiquidation> {
        liquidation.validate()?;
        ensure_state_series(&self.series, &liquidation.series_id, "liquidation")?;
        ensure_state_vault(
            &self.margin_vaults,
            &liquidation.margin_vault_id,
            "liquidation",
        )?;
        if !self.sealed_orders.contains_key(&liquidation.order_id) {
            return Err("liquidation references missing sealed order".to_string());
        }
        if !self
            .oracle_guards
            .contains_key(&liquidation.oracle_guard_id)
        {
            return Err("liquidation references missing oracle guard".to_string());
        }
        self.liquidations
            .insert(liquidation.liquidation_id.clone(), liquidation.clone());
        Ok(liquidation)
    }

    pub fn insert_settlement_batch(
        &mut self,
        batch: OptionSettlementBatch,
    ) -> ConfidentialOptionsResult<OptionSettlementBatch> {
        batch.validate()?;
        ensure_state_series(&self.series, &batch.series_id, "settlement batch")?;
        if !self.oracle_guards.contains_key(&batch.oracle_guard_id) {
            return Err("settlement batch references missing oracle guard".to_string());
        }
        self.settlement_batches
            .insert(batch.batch_id.clone(), batch.clone());
        Ok(batch)
    }

    pub fn insert_low_fee_sponsorship(
        &mut self,
        sponsorship: LowFeeHedgingSponsorship,
    ) -> ConfidentialOptionsResult<LowFeeHedgingSponsorship> {
        sponsorship.validate()?;
        ensure_state_series(&self.series, &sponsorship.series_id, "sponsorship")?;
        self.low_fee_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship.clone());
        Ok(sponsorship)
    }

    pub fn insert_pq_quote(
        &mut self,
        quote: PqMarketMakerQuote,
    ) -> ConfidentialOptionsResult<PqMarketMakerQuote> {
        quote.validate()?;
        ensure_state_series(&self.series, &quote.series_id, "pq quote")?;
        ensure_state_vault(&self.margin_vaults, &quote.collateral_vault_id, "pq quote")?;
        if !self.oracle_guards.contains_key(&quote.oracle_guard_id) {
            return Err("pq quote references missing oracle guard".to_string());
        }
        self.pq_quotes.insert(quote.quote_id.clone(), quote.clone());
        Ok(quote)
    }

    pub fn insert_public_record(
        &mut self,
        record: ConfidentialOptionsPublicRecord,
    ) -> ConfidentialOptionsResult<ConfidentialOptionsPublicRecord> {
        record.validate()?;
        self.public_records
            .insert(record.record_id.clone(), record.clone());
        Ok(record)
    }

    pub fn refresh_series_roots(&mut self) {
        let series_ids = self.series.keys().cloned().collect::<Vec<_>>();
        for series_id in series_ids {
            let oracle_guard_root = confidential_options_oracle_guard_root(
                &self
                    .oracle_guards
                    .values()
                    .filter(|guard| guard.series_id == series_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let sealed_order_root = confidential_options_sealed_order_root(
                &self
                    .sealed_orders
                    .values()
                    .filter(|order| order.series_id == series_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let exercise_receipt_root = confidential_options_exercise_receipt_root(
                &self
                    .exercise_receipts
                    .values()
                    .filter(|receipt| receipt.series_id == series_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let settlement_root = confidential_options_settlement_batch_root(
                &self
                    .settlement_batches
                    .values()
                    .filter(|batch| batch.series_id == series_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let liquidation_root = confidential_options_liquidation_root(
                &self
                    .liquidations
                    .values()
                    .filter(|liquidation| liquidation.series_id == series_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let pq_quote_root = confidential_options_pq_quote_root(
                &self
                    .pq_quotes
                    .values()
                    .filter(|quote| quote.series_id == series_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            let low_fee_sponsorship_root = confidential_options_low_fee_sponsorship_root(
                &self
                    .low_fee_sponsorships
                    .values()
                    .filter(|sponsorship| sponsorship.series_id == series_id)
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            if let Some(series) = self.series.get_mut(&series_id) {
                series.oracle_guard_root = oracle_guard_root;
                series.sealed_order_root = sealed_order_root;
                series.exercise_receipt_root = exercise_receipt_root;
                series.settlement_root = settlement_root;
                series.liquidation_root = liquidation_root;
                series.pq_quote_root = pq_quote_root;
                series.low_fee_sponsorship_root = low_fee_sponsorship_root;
            }
        }
    }

    pub fn config_root(&self) -> String {
        self.config.config_root()
    }

    pub fn series_root(&self) -> String {
        confidential_options_series_root(&self.series.values().cloned().collect::<Vec<_>>())
    }

    pub fn margin_vault_root(&self) -> String {
        confidential_options_margin_vault_root(
            &self.margin_vaults.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn sealed_order_root(&self) -> String {
        confidential_options_sealed_order_root(
            &self.sealed_orders.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn exercise_receipt_root(&self) -> String {
        confidential_options_exercise_receipt_root(
            &self.exercise_receipts.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn oracle_guard_root(&self) -> String {
        confidential_options_oracle_guard_root(
            &self.oracle_guards.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn liquidation_root(&self) -> String {
        confidential_options_liquidation_root(
            &self.liquidations.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn settlement_batch_root(&self) -> String {
        confidential_options_settlement_batch_root(
            &self
                .settlement_batches
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_sponsorship_root(&self) -> String {
        confidential_options_low_fee_sponsorship_root(
            &self
                .low_fee_sponsorships
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn pq_quote_root(&self) -> String {
        confidential_options_pq_quote_root(&self.pq_quotes.values().cloned().collect::<Vec<_>>())
    }

    pub fn public_record_root(&self) -> String {
        confidential_options_public_record_root(
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn roots(&self) -> ConfidentialOptionsRoots {
        ConfidentialOptionsRoots {
            config_root: self.config_root(),
            series_root: self.series_root(),
            margin_vault_root: self.margin_vault_root(),
            sealed_order_root: self.sealed_order_root(),
            exercise_receipt_root: self.exercise_receipt_root(),
            oracle_guard_root: self.oracle_guard_root(),
            liquidation_root: self.liquidation_root(),
            settlement_batch_root: self.settlement_batch_root(),
            low_fee_sponsorship_root: self.low_fee_sponsorship_root(),
            pq_quote_root: self.pq_quote_root(),
            public_record_root: self.public_record_root(),
        }
    }

    pub fn state_roots(&self) -> ConfidentialOptionsRoots {
        self.roots()
    }

    pub fn counters(&self) -> ConfidentialOptionsCounters {
        ConfidentialOptionsCounters {
            series_count: self.series.len() as u64,
            active_series_count: self
                .series
                .values()
                .filter(|series| series.accepts_orders_at(self.height))
                .count() as u64,
            margin_vault_count: self.margin_vaults.len() as u64,
            open_margin_vault_count: self
                .margin_vaults
                .values()
                .filter(|vault| vault.status.is_open())
                .count() as u64,
            sealed_order_count: self.sealed_orders.len() as u64,
            live_sealed_order_count: self
                .sealed_orders
                .values()
                .filter(|order| order.is_live_at(self.height))
                .count() as u64,
            exercise_receipt_count: self.exercise_receipts.len() as u64,
            proven_exercise_receipt_count: self
                .exercise_receipts
                .values()
                .filter(|receipt| {
                    matches!(
                        receipt.status,
                        ExerciseReceiptStatus::Proven | ExerciseReceiptStatus::Settled
                    )
                })
                .count() as u64,
            oracle_guard_count: self.oracle_guards.len() as u64,
            active_oracle_guard_count: self
                .oracle_guards
                .values()
                .filter(|guard| guard.is_active_at(self.height))
                .count() as u64,
            liquidation_count: self.liquidations.len() as u64,
            open_liquidation_count: self
                .liquidations
                .values()
                .filter(|liquidation| liquidation.is_open_at(self.height))
                .count() as u64,
            settlement_batch_count: self.settlement_batches.len() as u64,
            pending_settlement_batch_count: self
                .settlement_batches
                .values()
                .filter(|batch| batch.status.is_pending())
                .count() as u64,
            low_fee_sponsorship_count: self.low_fee_sponsorships.len() as u64,
            active_low_fee_sponsorship_count: self.active_low_fee_sponsorship_count(),
            pq_quote_count: self.pq_quotes.len() as u64,
            live_pq_quote_count: self
                .pq_quotes
                .values()
                .filter(|quote| quote.is_live_at(self.height))
                .count() as u64,
            public_record_count: self.public_records.len() as u64,
            total_margin_floor_units: self.total_margin_floor_units(),
            total_available_margin_floor_units: self.total_available_margin_floor_units(),
            total_sponsored_fee_budget_units: self.total_sponsored_fee_budget_units(),
            aggregate_risk_score_bps: self.aggregate_risk_score_bps(),
        }
    }

    pub fn series_ids(&self) -> Vec<String> {
        self.series.keys().cloned().collect()
    }

    pub fn active_series_ids(&self) -> Vec<String> {
        self.series
            .values()
            .filter(|series| series.accepts_orders_at(self.height))
            .map(|series| series.series_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn guarded_series_ids(&self) -> Vec<String> {
        self.oracle_guards
            .values()
            .filter(|guard| guard.is_active_at(self.height))
            .map(|guard| guard.series_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn active_low_fee_sponsorship_count(&self) -> u64 {
        self.low_fee_sponsorships
            .values()
            .filter(|sponsorship| sponsorship.is_active_at(self.height))
            .count() as u64
    }

    pub fn total_margin_floor_units(&self) -> u64 {
        self.margin_vaults.values().fold(0_u64, |total, vault| {
            total.saturating_add(vault.balance_floor_units)
        })
    }

    pub fn total_available_margin_floor_units(&self) -> u64 {
        self.margin_vaults.values().fold(0_u64, |total, vault| {
            total.saturating_add(vault.available_floor_units())
        })
    }

    pub fn total_sponsored_fee_budget_units(&self) -> u64 {
        self.low_fee_sponsorships
            .values()
            .fold(0_u64, |total, sponsorship| {
                total.saturating_add(sponsorship.available_fee_units())
            })
    }

    pub fn aggregate_risk_score_bps(&self) -> u64 {
        self.oracle_guards
            .values()
            .map(|guard| guard.severity.score_bps().max(guard.observed_deviation_bps))
            .chain(
                self.liquidations
                    .values()
                    .filter(|liquidation| liquidation.status.is_open())
                    .map(|liquidation| {
                        if liquidation.health_factor_floor_bps < 8_000 {
                            9_000
                        } else {
                            6_500
                        }
                    }),
            )
            .max()
            .unwrap_or(0)
    }

    pub fn state_root(&self) -> String {
        confidential_options_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(fields) = &mut record {
            fields.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> ConfidentialOptionsResult<String> {
        self.config.validate()?;
        for (id, series) in &self.series {
            if id != &series.series_id {
                return Err("state series key does not match series id".to_string());
            }
            series.validate()?;
        }
        for (id, vault) in &self.margin_vaults {
            if id != &vault.vault_id {
                return Err("state vault key does not match vault id".to_string());
            }
            vault.validate()?;
        }
        for (id, guard) in &self.oracle_guards {
            if id != &guard.guard_id {
                return Err("state oracle guard key does not match guard id".to_string());
            }
            guard.validate()?;
            ensure_state_series(&self.series, &guard.series_id, "oracle guard")?;
        }
        for (id, quote) in &self.pq_quotes {
            if id != &quote.quote_id {
                return Err("state pq quote key does not match quote id".to_string());
            }
            quote.validate()?;
            ensure_state_series(&self.series, &quote.series_id, "pq quote")?;
            ensure_state_vault(&self.margin_vaults, &quote.collateral_vault_id, "pq quote")?;
            if !self.oracle_guards.contains_key(&quote.oracle_guard_id) {
                return Err("pq quote references missing oracle guard".to_string());
            }
        }
        for (id, sponsorship) in &self.low_fee_sponsorships {
            if id != &sponsorship.sponsorship_id {
                return Err("state sponsorship key does not match sponsorship id".to_string());
            }
            sponsorship.validate()?;
            ensure_state_series(&self.series, &sponsorship.series_id, "sponsorship")?;
        }
        for (id, order) in &self.sealed_orders {
            if id != &order.order_id {
                return Err("state order key does not match order id".to_string());
            }
            order.validate()?;
            ensure_state_series(&self.series, &order.series_id, "sealed order")?;
            ensure_state_vault(&self.margin_vaults, &order.margin_vault_id, "sealed order")?;
            if !order.quote_id.is_empty() && !self.pq_quotes.contains_key(&order.quote_id) {
                return Err("sealed order references missing pq quote".to_string());
            }
            if !order.sponsorship_id.is_empty()
                && !self
                    .low_fee_sponsorships
                    .contains_key(&order.sponsorship_id)
            {
                return Err("sealed order references missing low fee sponsorship".to_string());
            }
        }
        for (id, receipt) in &self.exercise_receipts {
            if id != &receipt.receipt_id {
                return Err("state receipt key does not match receipt id".to_string());
            }
            receipt.validate()?;
            ensure_state_series(&self.series, &receipt.series_id, "exercise receipt")?;
            ensure_state_vault(
                &self.margin_vaults,
                &receipt.margin_vault_id,
                "exercise receipt",
            )?;
            if !self.sealed_orders.contains_key(&receipt.order_id) {
                return Err("exercise receipt references missing sealed order".to_string());
            }
            if !self.oracle_guards.contains_key(&receipt.oracle_guard_id) {
                return Err("exercise receipt references missing oracle guard".to_string());
            }
        }
        for (id, liquidation) in &self.liquidations {
            if id != &liquidation.liquidation_id {
                return Err("state liquidation key does not match liquidation id".to_string());
            }
            liquidation.validate()?;
            ensure_state_series(&self.series, &liquidation.series_id, "liquidation")?;
            ensure_state_vault(
                &self.margin_vaults,
                &liquidation.margin_vault_id,
                "liquidation",
            )?;
            if !self.sealed_orders.contains_key(&liquidation.order_id) {
                return Err("liquidation references missing sealed order".to_string());
            }
            if !self
                .oracle_guards
                .contains_key(&liquidation.oracle_guard_id)
            {
                return Err("liquidation references missing oracle guard".to_string());
            }
        }
        for (id, batch) in &self.settlement_batches {
            if id != &batch.batch_id {
                return Err("state settlement key does not match batch id".to_string());
            }
            batch.validate()?;
            ensure_state_series(&self.series, &batch.series_id, "settlement batch")?;
            if !self.oracle_guards.contains_key(&batch.oracle_guard_id) {
                return Err("settlement batch references missing oracle guard".to_string());
            }
        }
        for (id, record) in &self.public_records {
            if id != &record.record_id {
                return Err("state public record key does not match record id".to_string());
            }
            record.validate()?;
        }
        Ok(self.state_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "confidential_options_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_OPTIONS_PROTOCOL_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "series_ids": self.series_ids(),
            "active_series_ids": self.active_series_ids(),
            "guarded_series_ids": self.guarded_series_ids(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
        })
    }
}

pub fn confidential_options_state_root(state: &ConfidentialOptionsState) -> String {
    state.state_root()
}

pub fn confidential_options_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "CONFIDENTIAL-OPTIONS-STATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn confidential_options_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn confidential_options_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn confidential_options_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn confidential_options_account_commitment(label: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-OPTIONS-ACCOUNT-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn confidential_options_blinding(
    subject: impl ToString,
    nonce: impl ToString,
    purpose: &str,
) -> String {
    let subject = subject.to_string();
    let nonce = nonce.to_string();
    domain_hash(
        "CONFIDENTIAL-OPTIONS-BLINDING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&subject),
            HashPart::Str(&nonce),
            HashPart::Str(purpose),
        ],
        32,
    )
}

pub fn confidential_options_amount_commitment(label: &str, units: u64, blinding: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-OPTIONS-AMOUNT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(units as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn confidential_options_price_commitment(
    label: &str,
    price_units: u64,
    blinding: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-OPTIONS-PRICE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(price_units as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn confidential_options_nullifier_hash(
    nullifier_label: &str,
    series_id: &str,
    order_id: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-OPTIONS-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(nullifier_label),
            HashPart::Str(series_id),
            HashPart::Str(order_id),
        ],
        32,
    )
}

pub fn confidential_options_proof_root(
    proof_system: &str,
    public_input_root: &str,
    private_witness_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-OPTIONS-PROOF-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proof_system),
            HashPart::Str(public_input_root),
            HashPart::Str(private_witness_root),
        ],
        32,
    )
}

pub fn confidential_options_series_root(series: &[ConfidentialOptionSeries]) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-OPTIONS-SERIES",
        series
            .iter()
            .map(ConfidentialOptionSeries::public_record)
            .collect(),
        "series_id",
    )
}

pub fn confidential_options_margin_vault_root(vaults: &[OptionMarginVault]) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-OPTIONS-MARGIN-VAULT",
        vaults
            .iter()
            .map(OptionMarginVault::public_record)
            .collect(),
        "vault_id",
    )
}

pub fn confidential_options_sealed_order_root(orders: &[SealedOptionOrder]) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-OPTIONS-SEALED-ORDER",
        orders
            .iter()
            .map(SealedOptionOrder::public_record)
            .collect(),
        "order_id",
    )
}

pub fn confidential_options_exercise_receipt_root(receipts: &[PrivateExerciseReceipt]) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-OPTIONS-EXERCISE-RECEIPT",
        receipts
            .iter()
            .map(PrivateExerciseReceipt::public_record)
            .collect(),
        "receipt_id",
    )
}

pub fn confidential_options_oracle_guard_root(guards: &[OptionOracleGuardRoot]) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-OPTIONS-ORACLE-GUARD",
        guards
            .iter()
            .map(OptionOracleGuardRoot::public_record)
            .collect(),
        "guard_id",
    )
}

pub fn confidential_options_liquidation_root(liquidations: &[PrivateOptionLiquidation]) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-OPTIONS-LIQUIDATION",
        liquidations
            .iter()
            .map(PrivateOptionLiquidation::public_record)
            .collect(),
        "liquidation_id",
    )
}

pub fn confidential_options_settlement_batch_root(batches: &[OptionSettlementBatch]) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-OPTIONS-SETTLEMENT-BATCH",
        batches
            .iter()
            .map(OptionSettlementBatch::public_record)
            .collect(),
        "batch_id",
    )
}

pub fn confidential_options_low_fee_sponsorship_root(
    sponsorships: &[LowFeeHedgingSponsorship],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-OPTIONS-LOW-FEE-HEDGING-SPONSORSHIP",
        sponsorships
            .iter()
            .map(LowFeeHedgingSponsorship::public_record)
            .collect(),
        "sponsorship_id",
    )
}

pub fn confidential_options_pq_quote_root(quotes: &[PqMarketMakerQuote]) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-OPTIONS-PQ-QUOTE",
        quotes
            .iter()
            .map(PqMarketMakerQuote::public_record)
            .collect(),
        "quote_id",
    )
}

pub fn confidential_options_public_record_root(
    records: &[ConfidentialOptionsPublicRecord],
) -> String {
    sorted_merkle_root(
        "CONFIDENTIAL-OPTIONS-PUBLIC-RECORD",
        records
            .iter()
            .map(ConfidentialOptionsPublicRecord::public_record)
            .collect(),
        "record_id",
    )
}

#[allow(clippy::too_many_arguments)]
pub fn confidential_options_series_id(
    underlying_asset_id: &str,
    collateral_asset_id: &str,
    oracle_feed_id: &str,
    strike_price_commitment: &str,
    expiration_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-OPTIONS-SERIES-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(underlying_asset_id),
            HashPart::Str(collateral_asset_id),
            HashPart::Str(oracle_feed_id),
            HashPart::Str(strike_price_commitment),
            HashPart::Int(expiration_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn confidential_options_margin_vault_id(
    owner_commitment: &str,
    collateral_asset_id: &str,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-OPTIONS-MARGIN-VAULT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(collateral_asset_id),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_options_sealed_order_id(
    series_id: &str,
    owner_commitment: &str,
    side: OptionOrderSide,
    size_commitment: &str,
    premium_limit_commitment: &str,
    submitted_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-OPTIONS-SEALED-ORDER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(series_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(side.as_str()),
            HashPart::Str(size_commitment),
            HashPart::Str(premium_limit_commitment),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_options_exercise_receipt_id(
    series_id: &str,
    order_id: &str,
    holder_commitment: &str,
    exercise_nullifier_hash: &str,
    exercised_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-OPTIONS-EXERCISE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(series_id),
            HashPart::Str(order_id),
            HashPart::Str(holder_commitment),
            HashPart::Str(exercise_nullifier_hash),
            HashPart::Int(exercised_at_height as i128),
        ],
        32,
    )
}

pub fn confidential_options_oracle_guard_id(
    series_id: &str,
    oracle_feed_id: &str,
    source_set_root: &str,
    median_update_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-OPTIONS-ORACLE-GUARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(series_id),
            HashPart::Str(oracle_feed_id),
            HashPart::Str(source_set_root),
            HashPart::Int(median_update_height as i128),
        ],
        32,
    )
}

pub fn confidential_options_liquidation_id(
    margin_vault_id: &str,
    series_id: &str,
    keeper_commitment: &str,
    submitted_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-OPTIONS-LIQUIDATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(margin_vault_id),
            HashPart::Str(series_id),
            HashPart::Str(keeper_commitment),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_options_settlement_batch_id(
    series_id: &str,
    settlement_height: u64,
    sealed_order_root: &str,
    exercise_receipt_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-OPTIONS-SETTLEMENT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(series_id),
            HashPart::Int(settlement_height as i128),
            HashPart::Str(sealed_order_root),
            HashPart::Str(exercise_receipt_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_options_sponsorship_id(
    sponsor_commitment: &str,
    beneficiary_commitment: &str,
    series_id: &str,
    lane_id: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-OPTIONS-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(series_id),
            HashPart::Str(lane_id),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_options_pq_quote_id(
    market_maker_commitment: &str,
    series_id: &str,
    bid_premium_commitment: &str,
    ask_premium_commitment: &str,
    valid_from_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-OPTIONS-PQ-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_maker_commitment),
            HashPart::Str(series_id),
            HashPart::Str(bid_premium_commitment),
            HashPart::Str(ask_premium_commitment),
            HashPart::Int(valid_from_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_options_public_record_id(
    record_kind: &str,
    subject_id: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-OPTIONS-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn confidential_options_bps_mul_floor(units: u64, bps: u64) -> u64 {
    mul_div_floor(units, bps, CONFIDENTIAL_OPTIONS_MAX_BPS)
}

pub fn confidential_options_bps_mul_ceil(units: u64, bps: u64) -> u64 {
    mul_div_ceil(units, bps, CONFIDENTIAL_OPTIONS_MAX_BPS)
}

pub fn confidential_options_risk_status(score_bps: u64) -> &'static str {
    if score_bps >= 9_000 {
        "critical"
    } else if score_bps >= 6_000 {
        "elevated"
    } else if score_bps >= 2_500 {
        "watch"
    } else {
        "healthy"
    }
}

fn sorted_merkle_root(domain: &str, mut leaves: Vec<Value>, sort_key: &str) -> String {
    leaves.sort_by_key(|record| {
        record
            .get(sort_key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    });
    merkle_root(domain, &leaves)
}

fn ensure_non_empty(value: &str, label: &str) -> ConfidentialOptionsResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> ConfidentialOptionsResult<()> {
    if value > CONFIDENTIAL_OPTIONS_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_margin_bps(value: u64, label: &str) -> ConfidentialOptionsResult<()> {
    if value > CONFIDENTIAL_OPTIONS_MAX_MARGIN_BPS {
        Err(format!("{label} exceeds max margin bps"))
    } else {
        Ok(())
    }
}

fn ensure_state_series(
    series: &BTreeMap<String, ConfidentialOptionSeries>,
    series_id: &str,
    label: &str,
) -> ConfidentialOptionsResult<()> {
    if series.contains_key(series_id) {
        Ok(())
    } else {
        Err(format!("{label} references unknown option series"))
    }
}

fn ensure_state_vault(
    vaults: &BTreeMap<String, OptionMarginVault>,
    vault_id: &str,
    label: &str,
) -> ConfidentialOptionsResult<()> {
    if vaults.contains_key(vault_id) {
        Ok(())
    } else {
        Err(format!("{label} references unknown margin vault"))
    }
}

fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    let value = (numerator as u128).saturating_mul(CONFIDENTIAL_OPTIONS_MAX_BPS as u128)
        / denominator as u128;
    value.min(u64::MAX as u128) as u64
}

fn mul_div_floor(value: u64, multiplier: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    let result = (value as u128).saturating_mul(multiplier as u128) / denominator as u128;
    result.min(u64::MAX as u128) as u64
}

fn mul_div_ceil(value: u64, multiplier: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    let numerator = (value as u128).saturating_mul(multiplier as u128);
    let denominator = denominator as u128;
    let result = numerator.saturating_add(denominator.saturating_sub(1)) / denominator;
    result.min(u64::MAX as u128) as u64
}
