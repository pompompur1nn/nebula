use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialPerpetualsMarginRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-perpetuals-margin-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_PQ_AUTH_SCHEME: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-perpetuals-margin-v1";
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_MARKET_SCHEME: &str =
    "monero-private-l2-confidential-perpetual-market-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_VAULT_SCHEME: &str =
    "monero-private-l2-confidential-margin-vault-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_POSITION_NOTE_SCHEME: &str =
    "monero-private-l2-confidential-shielded-position-note-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_FUNDING_SCHEME: &str =
    "monero-private-l2-low-fee-funding-settlement-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_RISK_SCHEME: &str =
    "monero-private-l2-liquidation-risk-attestation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_BATCH_SCHEME: &str =
    "monero-private-l2-confidential-perpetuals-batch-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_RECEIPT_SCHEME: &str =
    "roots-only-confidential-perpetuals-margin-settlement-receipt-v1";
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEVNET_HEIGHT: u64 = 236_000;
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_L2_NETWORK: &str =
    "nebula-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "devnet-private-l2-perpetuals-margin-low-fee";
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID: &str =
    "asset:wxmr";
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_QUOTE_ASSET_ID: &str =
    "asset:private-dusd";
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MAX_MARKETS: usize = 65_536;
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MAX_VAULTS: usize = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MAX_POSITION_NOTES: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MAX_BATCH_NOTES: usize = 8_192;
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MAX_FUNDING_SETTLEMENTS: usize =
    262_144;
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    4_096;
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    32_768;
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MAX_FUNDING_RATE_BPS: u64 =
    1_000;
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_INITIAL_MARGIN_BPS: u64 = 1_600;
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MAINTENANCE_MARGIN_BPS: u64 =
    800;
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_LIQUIDATION_PENALTY_BPS: u64 =
    450;
pub const PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerpetualMarketKind {
    Linear,
    Inverse,
    Quanto,
    SyntheticIndex,
    FundingOnly,
}

impl PerpetualMarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linear => "linear",
            Self::Inverse => "inverse",
            Self::Quanto => "quanto",
            Self::SyntheticIndex => "synthetic_index",
            Self::FundingOnly => "funding_only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginVaultMode {
    Isolated,
    Cross,
    Portfolio,
}

impl MarginVaultMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Isolated => "isolated",
            Self::Cross => "cross",
            Self::Portfolio => "portfolio",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    Long,
    Short,
}

impl PositionSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Long => "long",
            Self::Short => "short",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionIntentKind {
    Open,
    Increase,
    Reduce,
    Close,
    CollateralRebalance,
}

impl PositionIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Increase => "increase",
            Self::Reduce => "reduce",
            Self::Close => "close",
            Self::CollateralRebalance => "collateral_rebalance",
        }
    }

    pub fn reduce_only_safe(self) -> bool {
        matches!(self, Self::Reduce | Self::Close | Self::CollateralRebalance)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Open,
    Paused,
    FundingOnly,
    LiquidationOnly,
    Closed,
}

impl MarketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Paused => "paused",
            Self::FundingOnly => "funding_only",
            Self::LiquidationOnly => "liquidation_only",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_positions(self) -> bool {
        matches!(self, Self::Open)
    }

    pub fn accepts_funding(self) -> bool {
        matches!(self, Self::Open | Self::FundingOnly)
    }

    pub fn accepts_liquidations(self) -> bool {
        matches!(self, Self::Open | Self::FundingOnly | Self::LiquidationOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Open,
    ReduceOnly,
    LiquidationOnly,
    Suspended,
    Closed,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::ReduceOnly => "reduce_only",
            Self::LiquidationOnly => "liquidation_only",
            Self::Suspended => "suspended",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_intent(self, intent_kind: PositionIntentKind) -> bool {
        matches!(self, Self::Open)
            || (matches!(self, Self::ReduceOnly) && intent_kind.reduce_only_safe())
    }

    pub fn accepts_liquidation(self) -> bool {
        matches!(self, Self::Open | Self::ReduceOnly | Self::LiquidationOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    Pending,
    RiskAttested,
    Batched,
    Settled,
    Rejected,
    Expired,
}

impl NoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::RiskAttested => "risk_attested",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Pending | Self::RiskAttested)
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

    pub fn allows_batching(self) -> bool {
        matches!(self, Self::Healthy | Self::Watch | Self::ReduceOnly)
    }

    pub fn allows_liquidation(self) -> bool {
        matches!(self, Self::Liquidatable | Self::ReduceOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
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
pub enum FundingSettlementStatus {
    Pending,
    SettlementReady,
    Settled,
    Disputed,
}

impl FundingSettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReceiptKind {
    PositionBatchSettled,
    FundingSettled,
    LiquidationSettled,
}

impl SettlementReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PositionBatchSettled => "position_batch_settled",
            Self::FundingSettled => "funding_settled",
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
    pub l2_network: String,
    pub low_fee_lane: String,
    pub collateral_asset_id: String,
    pub quote_asset_id: String,
    pub hash_suite: String,
    pub pq_authorization_scheme: String,
    pub market_scheme: String,
    pub vault_scheme: String,
    pub position_note_scheme: String,
    pub funding_scheme: String,
    pub risk_scheme: String,
    pub batch_scheme: String,
    pub receipt_scheme: String,
    pub max_markets: usize,
    pub max_vaults: usize,
    pub max_position_notes: usize,
    pub max_risk_attestations: usize,
    pub max_batch_notes: usize,
    pub max_funding_settlements: usize,
    pub min_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_funding_rate_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_penalty_bps: u64,
    pub settlement_ttl_blocks: u64,
    pub require_low_fee_sponsor: bool,
    pub require_oracle_bound: bool,
    pub require_roots_only_public_state: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network:
                PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MONERO_NETWORK.to_string(),
            l2_network: PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_L2_NETWORK
                .to_string(),
            low_fee_lane: PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_LOW_FEE_LANE
                .to_string(),
            collateral_asset_id:
                PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID
                    .to_string(),
            quote_asset_id:
                PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_QUOTE_ASSET_ID.to_string(),
            hash_suite: PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_HASH_SUITE.to_string(),
            pq_authorization_scheme:
                PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_PQ_AUTH_SCHEME.to_string(),
            market_scheme: PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_MARKET_SCHEME
                .to_string(),
            vault_scheme: PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_VAULT_SCHEME
                .to_string(),
            position_note_scheme:
                PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_POSITION_NOTE_SCHEME.to_string(),
            funding_scheme: PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_FUNDING_SCHEME
                .to_string(),
            risk_scheme: PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_RISK_SCHEME.to_string(),
            batch_scheme: PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_BATCH_SCHEME
                .to_string(),
            receipt_scheme: PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_RECEIPT_SCHEME
                .to_string(),
            max_markets: PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MAX_MARKETS,
            max_vaults: PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MAX_VAULTS,
            max_position_notes:
                PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MAX_POSITION_NOTES,
            max_risk_attestations:
                PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS,
            max_batch_notes:
                PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MAX_BATCH_NOTES,
            max_funding_settlements:
                PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MAX_FUNDING_SETTLEMENTS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_funding_rate_bps:
                PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MAX_FUNDING_RATE_BPS,
            initial_margin_bps:
                PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps:
                PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_MAINTENANCE_MARGIN_BPS,
            liquidation_penalty_bps:
                PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_LIQUIDATION_PENALTY_BPS,
            settlement_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            require_low_fee_sponsor: true,
            require_oracle_bound: true,
            require_roots_only_public_state: true,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialPerpetualsMarginRuntimeResult<()> {
        required("chain_id", &self.chain_id)?;
        required("monero_network", &self.monero_network)?;
        required("l2_network", &self.l2_network)?;
        required("low_fee_lane", &self.low_fee_lane)?;
        required("collateral_asset_id", &self.collateral_asset_id)?;
        required("quote_asset_id", &self.quote_asset_id)?;
        if self.max_markets == 0
            || self.max_vaults == 0
            || self.max_position_notes == 0
            || self.max_risk_attestations == 0
            || self.max_batch_notes == 0
            || self.max_funding_settlements == 0
            || self.settlement_ttl_blocks == 0
        {
            return Err("confidential perpetuals capacities must be positive".to_string());
        }
        if self.max_batch_notes > self.max_position_notes {
            return Err("confidential perpetuals batch size exceeds note capacity".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.min_batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err("confidential perpetuals privacy policy is invalid".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("confidential perpetuals PQ security floor is too low".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_MAX_BPS
            || self.max_funding_rate_bps > PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_MAX_BPS
            || self.initial_margin_bps > PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_MAX_BPS
        {
            return Err("confidential perpetuals bps values exceed range".to_string());
        }
        if self.maintenance_margin_bps == 0
            || self.initial_margin_bps < self.maintenance_margin_bps
            || self.liquidation_penalty_bps > self.maintenance_margin_bps
        {
            return Err("confidential perpetuals margin policy is invalid".to_string());
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
            "market_scheme": self.market_scheme,
            "vault_scheme": self.vault_scheme,
            "position_note_scheme": self.position_note_scheme,
            "funding_scheme": self.funding_scheme,
            "risk_scheme": self.risk_scheme,
            "batch_scheme": self.batch_scheme,
            "receipt_scheme": self.receipt_scheme,
            "max_markets": self.max_markets,
            "max_vaults": self.max_vaults,
            "max_position_notes": self.max_position_notes,
            "max_risk_attestations": self.max_risk_attestations,
            "max_batch_notes": self.max_batch_notes,
            "max_funding_settlements": self.max_funding_settlements,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_batch_privacy_set_size": self.min_batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_funding_rate_bps": self.max_funding_rate_bps,
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "liquidation_penalty_bps": self.liquidation_penalty_bps,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "require_low_fee_sponsor": self.require_low_fee_sponsor,
            "require_oracle_bound": self.require_oracle_bound,
            "require_roots_only_public_state": self.require_roots_only_public_state,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub market_counter: u64,
    pub margin_vault_counter: u64,
    pub position_note_counter: u64,
    pub risk_attestation_counter: u64,
    pub funding_settlement_counter: u64,
    pub settlement_batch_counter: u64,
    pub settlement_receipt_counter: u64,
    pub consumed_nullifier_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "market_counter": self.market_counter,
            "margin_vault_counter": self.margin_vault_counter,
            "position_note_counter": self.position_note_counter,
            "risk_attestation_counter": self.risk_attestation_counter,
            "funding_settlement_counter": self.funding_settlement_counter,
            "settlement_batch_counter": self.settlement_batch_counter,
            "settlement_receipt_counter": self.settlement_receipt_counter,
            "consumed_nullifier_counter": self.consumed_nullifier_counter,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub market_root: String,
    pub margin_vault_root: String,
    pub position_note_root: String,
    pub risk_attestation_root: String,
    pub funding_settlement_root: String,
    pub settlement_batch_root: String,
    pub settlement_receipt_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "market_root": self.market_root,
            "margin_vault_root": self.margin_vault_root,
            "position_note_root": self.position_note_root,
            "risk_attestation_root": self.risk_attestation_root,
            "funding_settlement_root": self.funding_settlement_root,
            "settlement_batch_root": self.settlement_batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenPerpetualMarketRequest {
    pub market_kind: PerpetualMarketKind,
    pub market_owner_commitment: String,
    pub base_asset_root: String,
    pub quote_asset_root: String,
    pub collateral_asset_root: String,
    pub oracle_root: String,
    pub funding_curve_root: String,
    pub risk_policy_root: String,
    pub matching_policy_root: String,
    pub pq_authority_root: String,
    pub privacy_policy_root: String,
    pub low_fee_sponsor_root: String,
    pub market_nullifier: String,
    pub max_funding_rate_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
}

impl OpenPerpetualMarketRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialPerpetualsMarginRuntimeResult<()> {
        required("market_owner_commitment", &self.market_owner_commitment)?;
        required("base_asset_root", &self.base_asset_root)?;
        required("quote_asset_root", &self.quote_asset_root)?;
        required("collateral_asset_root", &self.collateral_asset_root)?;
        required("funding_curve_root", &self.funding_curve_root)?;
        required("risk_policy_root", &self.risk_policy_root)?;
        required("matching_policy_root", &self.matching_policy_root)?;
        required("pq_authority_root", &self.pq_authority_root)?;
        required("privacy_policy_root", &self.privacy_policy_root)?;
        required("market_nullifier", &self.market_nullifier)?;
        if config.require_oracle_bound {
            required("oracle_root", &self.oracle_root)?;
        }
        if config.require_low_fee_sponsor {
            required("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.max_funding_rate_bps > config.max_funding_rate_bps {
            return Err("perpetual market funding cap exceeds config".to_string());
        }
        if self.maintenance_margin_bps == 0
            || self.initial_margin_bps < self.maintenance_margin_bps
            || self.initial_margin_bps < config.initial_margin_bps
            || self.maintenance_margin_bps < config.maintenance_margin_bps
        {
            return Err("perpetual market margin policy below config".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_kind": self.market_kind.as_str(),
            "market_owner_commitment": self.market_owner_commitment,
            "base_asset_root": self.base_asset_root,
            "quote_asset_root": self.quote_asset_root,
            "collateral_asset_root": self.collateral_asset_root,
            "oracle_root": self.oracle_root,
            "funding_curve_root": self.funding_curve_root,
            "risk_policy_root": self.risk_policy_root,
            "matching_policy_root": self.matching_policy_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_policy_root": self.privacy_policy_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "market_nullifier": self.market_nullifier,
            "max_funding_rate_bps": self.max_funding_rate_bps,
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenMarginVaultRequest {
    pub market_id: String,
    pub vault_mode: MarginVaultMode,
    pub owner_commitment: String,
    pub collateral_note_root: String,
    pub collateral_lock_root: String,
    pub account_state_root: String,
    pub leverage_policy_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub low_fee_sponsor_root: String,
    pub vault_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
}

impl OpenMarginVaultRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialPerpetualsMarginRuntimeResult<()> {
        required("market_id", &self.market_id)?;
        required("owner_commitment", &self.owner_commitment)?;
        required("collateral_note_root", &self.collateral_note_root)?;
        required("collateral_lock_root", &self.collateral_lock_root)?;
        required("account_state_root", &self.account_state_root)?;
        required("leverage_policy_root", &self.leverage_policy_root)?;
        required("pq_authorization_root", &self.pq_authorization_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("vault_nullifier", &self.vault_nullifier)?;
        if config.require_low_fee_sponsor {
            required("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("margin vault fee exceeds low-fee policy".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "vault_mode": self.vault_mode.as_str(),
            "owner_commitment": self.owner_commitment,
            "collateral_note_root": self.collateral_note_root,
            "collateral_lock_root": self.collateral_lock_root,
            "account_state_root": self.account_state_root,
            "leverage_policy_root": self.leverage_policy_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "vault_nullifier": self.vault_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitShieldedPositionNoteRequest {
    pub market_id: String,
    pub margin_vault_id: String,
    pub side: PositionSide,
    pub intent_kind: PositionIntentKind,
    pub trader_commitment: String,
    pub position_note_root: String,
    pub notional_commitment_root: String,
    pub collateral_delta_root: String,
    pub limit_price_root: String,
    pub funding_index_root: String,
    pub mev_protection_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub low_fee_sponsor_root: String,
    pub note_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl SubmitShieldedPositionNoteRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialPerpetualsMarginRuntimeResult<()> {
        required("market_id", &self.market_id)?;
        required("margin_vault_id", &self.margin_vault_id)?;
        required("trader_commitment", &self.trader_commitment)?;
        required("position_note_root", &self.position_note_root)?;
        required("notional_commitment_root", &self.notional_commitment_root)?;
        required("collateral_delta_root", &self.collateral_delta_root)?;
        required("limit_price_root", &self.limit_price_root)?;
        required("funding_index_root", &self.funding_index_root)?;
        required("mev_protection_root", &self.mev_protection_root)?;
        required("pq_authorization_root", &self.pq_authorization_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("note_nullifier", &self.note_nullifier)?;
        if config.require_low_fee_sponsor {
            required("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("shielded position note fee exceeds low-fee policy".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("shielded position note expiry must follow submission".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "margin_vault_id": self.margin_vault_id,
            "side": self.side.as_str(),
            "intent_kind": self.intent_kind.as_str(),
            "trader_commitment": self.trader_commitment,
            "position_note_root": self.position_note_root,
            "notional_commitment_root": self.notional_commitment_root,
            "collateral_delta_root": self.collateral_delta_root,
            "limit_price_root": self.limit_price_root,
            "funding_index_root": self.funding_index_root,
            "mev_protection_root": self.mev_protection_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "note_nullifier": self.note_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestLiquidationRiskRequest {
    pub market_id: String,
    pub margin_vault_id: String,
    pub position_note_id: String,
    pub attestor_commitment: String,
    pub verdict: RiskVerdict,
    pub margin_health_bps: u64,
    pub liquidation_price_root: String,
    pub exposure_root: String,
    pub oracle_snapshot_root: String,
    pub risk_model_root: String,
    pub proof_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub attestation_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl AttestLiquidationRiskRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialPerpetualsMarginRuntimeResult<()> {
        required("market_id", &self.market_id)?;
        required("margin_vault_id", &self.margin_vault_id)?;
        required("position_note_id", &self.position_note_id)?;
        required("attestor_commitment", &self.attestor_commitment)?;
        required("liquidation_price_root", &self.liquidation_price_root)?;
        required("exposure_root", &self.exposure_root)?;
        required("risk_model_root", &self.risk_model_root)?;
        required("proof_root", &self.proof_root)?;
        required("pq_authorization_root", &self.pq_authorization_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("attestation_nullifier", &self.attestation_nullifier)?;
        if config.require_oracle_bound {
            required("oracle_snapshot_root", &self.oracle_snapshot_root)?;
        }
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "margin_vault_id": self.margin_vault_id,
            "position_note_id": self.position_note_id,
            "attestor_commitment": self.attestor_commitment,
            "verdict": self.verdict.as_str(),
            "margin_health_bps": self.margin_health_bps,
            "liquidation_price_root": self.liquidation_price_root,
            "exposure_root": self.exposure_root,
            "oracle_snapshot_root": self.oracle_snapshot_root,
            "risk_model_root": self.risk_model_root,
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
pub struct SettleLowFeeFundingRequest {
    pub market_id: String,
    pub funding_epoch: u64,
    pub funding_rate_bps: u64,
    pub payer_note_root: String,
    pub receiver_note_root: String,
    pub net_funding_delta_root: String,
    pub oracle_snapshot_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub settlement_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub settled_at_height: u64,
}

impl SettleLowFeeFundingRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialPerpetualsMarginRuntimeResult<()> {
        required("market_id", &self.market_id)?;
        required("payer_note_root", &self.payer_note_root)?;
        required("receiver_note_root", &self.receiver_note_root)?;
        required("net_funding_delta_root", &self.net_funding_delta_root)?;
        required("pq_authorization_root", &self.pq_authorization_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("settlement_nullifier", &self.settlement_nullifier)?;
        if config.require_oracle_bound {
            required("oracle_snapshot_root", &self.oracle_snapshot_root)?;
        }
        if config.require_low_fee_sponsor {
            required("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.funding_rate_bps > config.max_funding_rate_bps {
            return Err("funding settlement rate exceeds cap".to_string());
        }
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("funding settlement fee exceeds low-fee policy".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "funding_epoch": self.funding_epoch,
            "funding_rate_bps": self.funding_rate_bps,
            "payer_note_root": self.payer_note_root,
            "receiver_note_root": self.receiver_note_root,
            "net_funding_delta_root": self.net_funding_delta_root,
            "oracle_snapshot_root": self.oracle_snapshot_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "settlement_nullifier": self.settlement_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildSettlementBatchRequest {
    pub market_id: String,
    pub position_note_ids: Vec<String>,
    pub builder_commitment: String,
    pub matching_engine_root: String,
    pub netting_root: String,
    pub account_delta_root: String,
    pub funding_delta_root: String,
    pub oracle_snapshot_root: String,
    pub recursive_batch_proof_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_batch_authorization_root: String,
    pub privacy_proof_root: String,
    pub batch_nullifier: String,
    pub min_batch_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub built_at_height: u64,
}

impl BuildSettlementBatchRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialPerpetualsMarginRuntimeResult<()> {
        required("market_id", &self.market_id)?;
        required("builder_commitment", &self.builder_commitment)?;
        required("matching_engine_root", &self.matching_engine_root)?;
        required("netting_root", &self.netting_root)?;
        required("account_delta_root", &self.account_delta_root)?;
        required("funding_delta_root", &self.funding_delta_root)?;
        required(
            "recursive_batch_proof_root",
            &self.recursive_batch_proof_root,
        )?;
        required(
            "pq_batch_authorization_root",
            &self.pq_batch_authorization_root,
        )?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("batch_nullifier", &self.batch_nullifier)?;
        if self.position_note_ids.is_empty()
            || self.position_note_ids.len() > config.max_batch_notes
        {
            return Err("settlement batch note count is outside policy".to_string());
        }
        if config.require_oracle_bound {
            required("oracle_snapshot_root", &self.oracle_snapshot_root)?;
        }
        if config.require_low_fee_sponsor {
            required("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        validate_privacy_and_pq(
            self.min_batch_privacy_set_size,
            self.pq_security_bits,
            config.min_batch_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("settlement batch fee exceeds low-fee policy".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishBatchSettlementReceiptRequest {
    pub receipt_kind: SettlementReceiptKind,
    pub subject_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub included_note_root: String,
    pub rejected_note_root: String,
    pub account_delta_root: String,
    pub output_note_root: String,
    pub funding_payment_root: String,
    pub fee_receipt_root: String,
    pub low_fee_sponsor_receipt_root: String,
    pub pq_settlement_root: String,
    pub state_root_after: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl PublishBatchSettlementReceiptRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialPerpetualsMarginRuntimeResult<()> {
        required("subject_id", &self.subject_id)?;
        required("settlement_tx_root", &self.settlement_tx_root)?;
        required("settlement_proof_root", &self.settlement_proof_root)?;
        required("included_note_root", &self.included_note_root)?;
        required("account_delta_root", &self.account_delta_root)?;
        required("output_note_root", &self.output_note_root)?;
        required("funding_payment_root", &self.funding_payment_root)?;
        required("fee_receipt_root", &self.fee_receipt_root)?;
        required("pq_settlement_root", &self.pq_settlement_root)?;
        required("state_root_after", &self.state_root_after)?;
        if config.require_low_fee_sponsor {
            required(
                "low_fee_sponsor_receipt_root",
                &self.low_fee_sponsor_receipt_root,
            )?;
        }
        if self.settled_fee_bps > config.max_user_fee_bps {
            return Err("settlement receipt fee exceeds low-fee policy".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerpetualMarket {
    pub market_id: String,
    pub market_kind: PerpetualMarketKind,
    pub market_owner_commitment: String,
    pub base_asset_root: String,
    pub quote_asset_root: String,
    pub collateral_asset_root: String,
    pub oracle_root: String,
    pub funding_curve_root: String,
    pub risk_policy_root: String,
    pub matching_policy_root: String,
    pub pq_authority_root: String,
    pub privacy_policy_root: String,
    pub low_fee_sponsor_root: String,
    pub max_funding_rate_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: MarketStatus,
    pub latest_market_state_root: String,
    pub margin_vault_ids: Vec<String>,
    pub settlement_batch_ids: Vec<String>,
    pub funding_settlement_ids: Vec<String>,
    pub opened_at_height: u64,
}

impl PerpetualMarket {
    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "market_kind": self.market_kind.as_str(),
            "market_owner_commitment": self.market_owner_commitment,
            "base_asset_root": self.base_asset_root,
            "quote_asset_root": self.quote_asset_root,
            "collateral_asset_root": self.collateral_asset_root,
            "oracle_root": self.oracle_root,
            "funding_curve_root": self.funding_curve_root,
            "risk_policy_root": self.risk_policy_root,
            "matching_policy_root": self.matching_policy_root,
            "pq_authority_root": self.pq_authority_root,
            "privacy_policy_root": self.privacy_policy_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "max_funding_rate_bps": self.max_funding_rate_bps,
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "latest_market_state_root": self.latest_market_state_root,
            "margin_vault_ids": self.margin_vault_ids,
            "settlement_batch_ids": self.settlement_batch_ids,
            "funding_settlement_ids": self.funding_settlement_ids,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarginVault {
    pub margin_vault_id: String,
    pub market_id: String,
    pub vault_mode: MarginVaultMode,
    pub owner_commitment: String,
    pub collateral_note_root: String,
    pub collateral_lock_root: String,
    pub latest_account_state_root: String,
    pub leverage_policy_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub low_fee_sponsor_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub status: VaultStatus,
    pub position_note_ids: Vec<String>,
    pub risk_attestation_ids: Vec<String>,
    pub opened_at_height: u64,
}

impl MarginVault {
    pub fn public_record(&self) -> Value {
        json!({
            "margin_vault_id": self.margin_vault_id,
            "market_id": self.market_id,
            "vault_mode": self.vault_mode.as_str(),
            "owner_commitment": self.owner_commitment,
            "collateral_note_root": self.collateral_note_root,
            "collateral_lock_root": self.collateral_lock_root,
            "latest_account_state_root": self.latest_account_state_root,
            "leverage_policy_root": self.leverage_policy_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "position_note_ids": self.position_note_ids,
            "risk_attestation_ids": self.risk_attestation_ids,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedPositionNote {
    pub position_note_id: String,
    pub market_id: String,
    pub margin_vault_id: String,
    pub side: PositionSide,
    pub intent_kind: PositionIntentKind,
    pub trader_commitment: String,
    pub position_note_root: String,
    pub notional_commitment_root: String,
    pub collateral_delta_root: String,
    pub limit_price_root: String,
    pub funding_index_root: String,
    pub mev_protection_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub low_fee_sponsor_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub status: NoteStatus,
    pub latest_risk_attestation_id: Option<String>,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl ShieldedPositionNote {
    pub fn public_record(&self) -> Value {
        json!({
            "position_note_id": self.position_note_id,
            "market_id": self.market_id,
            "margin_vault_id": self.margin_vault_id,
            "side": self.side.as_str(),
            "intent_kind": self.intent_kind.as_str(),
            "trader_commitment": self.trader_commitment,
            "position_note_root": self.position_note_root,
            "notional_commitment_root": self.notional_commitment_root,
            "collateral_delta_root": self.collateral_delta_root,
            "limit_price_root": self.limit_price_root,
            "funding_index_root": self.funding_index_root,
            "mev_protection_root": self.mev_protection_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "latest_risk_attestation_id": self.latest_risk_attestation_id,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationRiskAttestation {
    pub risk_attestation_id: String,
    pub market_id: String,
    pub margin_vault_id: String,
    pub position_note_id: String,
    pub attestor_commitment: String,
    pub verdict: RiskVerdict,
    pub margin_health_bps: u64,
    pub liquidation_price_root: String,
    pub exposure_root: String,
    pub oracle_snapshot_root: String,
    pub risk_model_root: String,
    pub proof_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl LiquidationRiskAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "risk_attestation_id": self.risk_attestation_id,
            "market_id": self.market_id,
            "margin_vault_id": self.margin_vault_id,
            "position_note_id": self.position_note_id,
            "attestor_commitment": self.attestor_commitment,
            "verdict": self.verdict.as_str(),
            "margin_health_bps": self.margin_health_bps,
            "liquidation_price_root": self.liquidation_price_root,
            "exposure_root": self.exposure_root,
            "oracle_snapshot_root": self.oracle_snapshot_root,
            "risk_model_root": self.risk_model_root,
            "proof_root": self.proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeFundingSettlement {
    pub funding_settlement_id: String,
    pub market_id: String,
    pub funding_epoch: u64,
    pub funding_rate_bps: u64,
    pub payer_note_root: String,
    pub receiver_note_root: String,
    pub net_funding_delta_root: String,
    pub oracle_snapshot_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub status: FundingSettlementStatus,
    pub settled_at_height: u64,
}

impl LowFeeFundingSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "funding_settlement_id": self.funding_settlement_id,
            "market_id": self.market_id,
            "funding_epoch": self.funding_epoch,
            "funding_rate_bps": self.funding_rate_bps,
            "payer_note_root": self.payer_note_root,
            "receiver_note_root": self.receiver_note_root,
            "net_funding_delta_root": self.net_funding_delta_root,
            "oracle_snapshot_root": self.oracle_snapshot_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementBatch {
    pub settlement_batch_id: String,
    pub market_id: String,
    pub position_note_ids: Vec<String>,
    pub builder_commitment: String,
    pub matching_engine_root: String,
    pub netting_root: String,
    pub account_delta_root: String,
    pub funding_delta_root: String,
    pub oracle_snapshot_root: String,
    pub recursive_batch_proof_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_batch_authorization_root: String,
    pub privacy_proof_root: String,
    pub min_batch_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub status: BatchStatus,
    pub built_at_height: u64,
    pub settlement_deadline_height: u64,
}

impl SettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_batch_id": self.settlement_batch_id,
            "market_id": self.market_id,
            "position_note_ids": self.position_note_ids,
            "builder_commitment": self.builder_commitment,
            "matching_engine_root": self.matching_engine_root,
            "netting_root": self.netting_root,
            "account_delta_root": self.account_delta_root,
            "funding_delta_root": self.funding_delta_root,
            "oracle_snapshot_root": self.oracle_snapshot_root,
            "recursive_batch_proof_root": self.recursive_batch_proof_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_batch_authorization_root": self.pq_batch_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "min_batch_privacy_set_size": self.min_batch_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "built_at_height": self.built_at_height,
            "settlement_deadline_height": self.settlement_deadline_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchSettlementReceipt {
    pub settlement_receipt_id: String,
    pub receipt_kind: SettlementReceiptKind,
    pub subject_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub included_note_root: String,
    pub rejected_note_root: String,
    pub account_delta_root: String,
    pub output_note_root: String,
    pub funding_payment_root: String,
    pub fee_receipt_root: String,
    pub low_fee_sponsor_receipt_root: String,
    pub pq_settlement_root: String,
    pub state_root_after: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl BatchSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_receipt_id": self.settlement_receipt_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "subject_id": self.subject_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "included_note_root": self.included_note_root,
            "rejected_note_root": self.rejected_note_root,
            "account_delta_root": self.account_delta_root,
            "output_note_root": self.output_note_root,
            "funding_payment_root": self.funding_payment_root,
            "fee_receipt_root": self.fee_receipt_root,
            "low_fee_sponsor_receipt_root": self.low_fee_sponsor_receipt_root,
            "pq_settlement_root": self.pq_settlement_root,
            "state_root_after": self.state_root_after,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateL2ConfidentialPerpetualsMarginRuntime {
    pub chain_id: String,
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub markets: BTreeMap<String, PerpetualMarket>,
    pub margin_vaults: BTreeMap<String, MarginVault>,
    pub position_notes: BTreeMap<String, ShieldedPositionNote>,
    pub risk_attestations: BTreeMap<String, LiquidationRiskAttestation>,
    pub funding_settlements: BTreeMap<String, LowFeeFundingSettlement>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub settlement_receipts: BTreeMap<String, BatchSettlementReceipt>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl Default for PrivateL2ConfidentialPerpetualsMarginRuntime {
    fn default() -> Self {
        Self::devnet()
    }
}

impl PrivateL2ConfidentialPerpetualsMarginRuntime {
    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> Self {
        Self {
            chain_id: config.chain_id.clone(),
            config,
            counters: Counters::default(),
            current_height: PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_DEVNET_HEIGHT,
            markets: BTreeMap::new(),
            margin_vaults: BTreeMap::new(),
            position_notes: BTreeMap::new(),
            risk_attestations: BTreeMap::new(),
            funding_settlements: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        }
    }

    pub fn open_perpetual_market(
        &mut self,
        request: OpenPerpetualMarketRequest,
    ) -> PrivateL2ConfidentialPerpetualsMarginRuntimeResult<PerpetualMarket> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.markets.len() >= self.config.max_markets {
            return Err("confidential perpetuals market capacity exhausted".to_string());
        }
        self.consume_nullifier(&request.market_nullifier)?;
        self.counters.market_counter = self.counters.market_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.opened_at_height);
        let market_id = perpetual_market_id(&request, self.counters.market_counter);
        let market = PerpetualMarket {
            market_id: market_id.clone(),
            market_kind: request.market_kind,
            market_owner_commitment: request.market_owner_commitment,
            base_asset_root: request.base_asset_root,
            quote_asset_root: request.quote_asset_root,
            collateral_asset_root: request.collateral_asset_root,
            oracle_root: request.oracle_root,
            funding_curve_root: request.funding_curve_root.clone(),
            risk_policy_root: request.risk_policy_root,
            matching_policy_root: request.matching_policy_root,
            pq_authority_root: request.pq_authority_root,
            privacy_policy_root: request.privacy_policy_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            max_funding_rate_bps: request.max_funding_rate_bps,
            initial_margin_bps: request.initial_margin_bps,
            maintenance_margin_bps: request.maintenance_margin_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            status: MarketStatus::Open,
            latest_market_state_root: request.funding_curve_root,
            margin_vault_ids: Vec::new(),
            settlement_batch_ids: Vec::new(),
            funding_settlement_ids: Vec::new(),
            opened_at_height: request.opened_at_height,
        };
        self.markets.insert(market_id, market.clone());
        Ok(market)
    }

    pub fn open_margin_vault(
        &mut self,
        request: OpenMarginVaultRequest,
    ) -> PrivateL2ConfidentialPerpetualsMarginRuntimeResult<MarginVault> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.margin_vaults.len() >= self.config.max_vaults {
            return Err("confidential perpetuals margin vault capacity exhausted".to_string());
        }
        let market = self
            .markets
            .get(&request.market_id)
            .ok_or_else(|| "margin vault references unknown market".to_string())?;
        if !market.status.accepts_positions() {
            return Err("perpetual market is not accepting vaults".to_string());
        }
        self.consume_nullifier(&request.vault_nullifier)?;
        self.counters.margin_vault_counter = self.counters.margin_vault_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.opened_at_height);
        let margin_vault_id = margin_vault_id(&request, self.counters.margin_vault_counter);
        let vault = MarginVault {
            margin_vault_id: margin_vault_id.clone(),
            market_id: request.market_id.clone(),
            vault_mode: request.vault_mode,
            owner_commitment: request.owner_commitment,
            collateral_note_root: request.collateral_note_root,
            collateral_lock_root: request.collateral_lock_root,
            latest_account_state_root: request.account_state_root,
            leverage_policy_root: request.leverage_policy_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            status: VaultStatus::Open,
            position_note_ids: Vec::new(),
            risk_attestation_ids: Vec::new(),
            opened_at_height: request.opened_at_height,
        };
        if let Some(market) = self.markets.get_mut(&request.market_id) {
            market.margin_vault_ids.push(margin_vault_id.clone());
        }
        self.margin_vaults.insert(margin_vault_id, vault.clone());
        Ok(vault)
    }

    pub fn submit_shielded_position_note(
        &mut self,
        request: SubmitShieldedPositionNoteRequest,
    ) -> PrivateL2ConfidentialPerpetualsMarginRuntimeResult<ShieldedPositionNote> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.position_notes.len() >= self.config.max_position_notes {
            return Err("confidential perpetuals position note capacity exhausted".to_string());
        }
        let market = self
            .markets
            .get(&request.market_id)
            .ok_or_else(|| "position note references unknown market".to_string())?;
        if !market.status.accepts_positions() {
            return Err("perpetual market is not accepting position notes".to_string());
        }
        let vault = self
            .margin_vaults
            .get(&request.margin_vault_id)
            .ok_or_else(|| "position note references unknown margin vault".to_string())?;
        if vault.market_id != request.market_id {
            return Err("position note vault/market mismatch".to_string());
        }
        if !vault.status.accepts_intent(request.intent_kind) {
            return Err("margin vault does not accept this position intent".to_string());
        }
        self.consume_nullifier(&request.note_nullifier)?;
        self.counters.position_note_counter = self.counters.position_note_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.submitted_at_height);
        let position_note_id = position_note_id(&request, self.counters.position_note_counter);
        let note = ShieldedPositionNote {
            position_note_id: position_note_id.clone(),
            market_id: request.market_id.clone(),
            margin_vault_id: request.margin_vault_id.clone(),
            side: request.side,
            intent_kind: request.intent_kind,
            trader_commitment: request.trader_commitment,
            position_note_root: request.position_note_root,
            notional_commitment_root: request.notional_commitment_root,
            collateral_delta_root: request.collateral_delta_root,
            limit_price_root: request.limit_price_root,
            funding_index_root: request.funding_index_root,
            mev_protection_root: request.mev_protection_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            status: NoteStatus::Pending,
            latest_risk_attestation_id: None,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request.expires_at_height,
        };
        if let Some(vault) = self.margin_vaults.get_mut(&request.margin_vault_id) {
            vault.position_note_ids.push(position_note_id.clone());
        }
        self.position_notes.insert(position_note_id, note.clone());
        Ok(note)
    }

    pub fn attest_liquidation_risk(
        &mut self,
        request: AttestLiquidationRiskRequest,
    ) -> PrivateL2ConfidentialPerpetualsMarginRuntimeResult<LiquidationRiskAttestation> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.risk_attestations.len() >= self.config.max_risk_attestations {
            return Err("confidential perpetuals risk attestation capacity exhausted".to_string());
        }
        let note = self
            .position_notes
            .get(&request.position_note_id)
            .ok_or_else(|| "risk attestation references unknown position note".to_string())?;
        if note.market_id != request.market_id || note.margin_vault_id != request.margin_vault_id {
            return Err("risk attestation note/vault/market mismatch".to_string());
        }
        self.consume_nullifier(&request.attestation_nullifier)?;
        self.counters.risk_attestation_counter =
            self.counters.risk_attestation_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.attested_at_height);
        let risk_attestation_id =
            risk_attestation_id(&request, self.counters.risk_attestation_counter);
        if let Some(note) = self.position_notes.get_mut(&request.position_note_id) {
            note.latest_risk_attestation_id = Some(risk_attestation_id.clone());
            note.status = if request.verdict.allows_batching() {
                NoteStatus::RiskAttested
            } else {
                NoteStatus::Rejected
            };
        }
        if let Some(vault) = self.margin_vaults.get_mut(&request.margin_vault_id) {
            vault.risk_attestation_ids.push(risk_attestation_id.clone());
            if request.verdict == RiskVerdict::ReduceOnly {
                vault.status = VaultStatus::ReduceOnly;
            }
            if request.verdict == RiskVerdict::Liquidatable {
                vault.status = VaultStatus::LiquidationOnly;
            }
        }
        let attestation = LiquidationRiskAttestation {
            risk_attestation_id: risk_attestation_id.clone(),
            market_id: request.market_id,
            margin_vault_id: request.margin_vault_id,
            position_note_id: request.position_note_id,
            attestor_commitment: request.attestor_commitment,
            verdict: request.verdict,
            margin_health_bps: request.margin_health_bps,
            liquidation_price_root: request.liquidation_price_root,
            exposure_root: request.exposure_root,
            oracle_snapshot_root: request.oracle_snapshot_root,
            risk_model_root: request.risk_model_root,
            proof_root: request.proof_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            attested_at_height: request.attested_at_height,
        };
        self.risk_attestations
            .insert(risk_attestation_id, attestation.clone());
        Ok(attestation)
    }

    pub fn settle_low_fee_funding(
        &mut self,
        request: SettleLowFeeFundingRequest,
    ) -> PrivateL2ConfidentialPerpetualsMarginRuntimeResult<LowFeeFundingSettlement> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.funding_settlements.len() >= self.config.max_funding_settlements {
            return Err("confidential perpetuals funding capacity exhausted".to_string());
        }
        let market = self
            .markets
            .get(&request.market_id)
            .ok_or_else(|| "funding settlement references unknown market".to_string())?;
        if !market.status.accepts_funding() {
            return Err("perpetual market is not accepting funding settlements".to_string());
        }
        self.consume_nullifier(&request.settlement_nullifier)?;
        self.counters.funding_settlement_counter =
            self.counters.funding_settlement_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.settled_at_height);
        let funding_settlement_id =
            funding_settlement_id(&request, self.counters.funding_settlement_counter);
        let settlement = LowFeeFundingSettlement {
            funding_settlement_id: funding_settlement_id.clone(),
            market_id: request.market_id.clone(),
            funding_epoch: request.funding_epoch,
            funding_rate_bps: request.funding_rate_bps,
            payer_note_root: request.payer_note_root,
            receiver_note_root: request.receiver_note_root,
            net_funding_delta_root: request.net_funding_delta_root,
            oracle_snapshot_root: request.oracle_snapshot_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            status: FundingSettlementStatus::SettlementReady,
            settled_at_height: request.settled_at_height,
        };
        if let Some(market) = self.markets.get_mut(&request.market_id) {
            market
                .funding_settlement_ids
                .push(funding_settlement_id.clone());
            market.latest_market_state_root = settlement.net_funding_delta_root.clone();
        }
        self.funding_settlements
            .insert(funding_settlement_id, settlement.clone());
        Ok(settlement)
    }

    pub fn build_settlement_batch(
        &mut self,
        request: BuildSettlementBatchRequest,
    ) -> PrivateL2ConfidentialPerpetualsMarginRuntimeResult<SettlementBatch> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let market = self
            .markets
            .get(&request.market_id)
            .ok_or_else(|| "settlement batch references unknown market".to_string())?;
        if !market.status.accepts_positions() {
            return Err("perpetual market is not accepting settlement batches".to_string());
        }
        let mut seen = BTreeSet::new();
        for note_id in &request.position_note_ids {
            if !seen.insert(note_id.clone()) {
                return Err("duplicate position note in settlement batch".to_string());
            }
            let note = self
                .position_notes
                .get(note_id)
                .ok_or_else(|| format!("position note {note_id} not found"))?;
            if note.market_id != request.market_id {
                return Err("position note belongs to another market".to_string());
            }
            if !note.status.batchable() {
                return Err("position note is not batchable".to_string());
            }
            if note.expires_at_height <= request.built_at_height {
                return Err("position note expired before settlement batch".to_string());
            }
            if let Some(risk_id) = &note.latest_risk_attestation_id {
                let risk = self
                    .risk_attestations
                    .get(risk_id)
                    .ok_or_else(|| "position note risk attestation missing".to_string())?;
                if !risk.verdict.allows_batching() {
                    return Err("risk verdict does not allow settlement batching".to_string());
                }
            }
        }
        self.consume_nullifier(&request.batch_nullifier)?;
        self.counters.settlement_batch_counter =
            self.counters.settlement_batch_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.built_at_height);
        let settlement_batch_id =
            settlement_batch_id(&request, self.counters.settlement_batch_counter);
        for note_id in &request.position_note_ids {
            if let Some(note) = self.position_notes.get_mut(note_id) {
                note.status = NoteStatus::Batched;
            }
        }
        let batch = SettlementBatch {
            settlement_batch_id: settlement_batch_id.clone(),
            market_id: request.market_id.clone(),
            position_note_ids: request.position_note_ids,
            builder_commitment: request.builder_commitment,
            matching_engine_root: request.matching_engine_root,
            netting_root: request.netting_root,
            account_delta_root: request.account_delta_root,
            funding_delta_root: request.funding_delta_root,
            oracle_snapshot_root: request.oracle_snapshot_root,
            recursive_batch_proof_root: request.recursive_batch_proof_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            pq_batch_authorization_root: request.pq_batch_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            min_batch_privacy_set_size: request.min_batch_privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            status: BatchStatus::SettlementReady,
            built_at_height: request.built_at_height,
            settlement_deadline_height: request
                .built_at_height
                .saturating_add(self.config.settlement_ttl_blocks),
        };
        if let Some(market) = self.markets.get_mut(&request.market_id) {
            market
                .settlement_batch_ids
                .push(settlement_batch_id.clone());
        }
        self.settlement_batches
            .insert(settlement_batch_id, batch.clone());
        Ok(batch)
    }

    pub fn publish_batch_settlement_receipt(
        &mut self,
        request: PublishBatchSettlementReceiptRequest,
    ) -> PrivateL2ConfidentialPerpetualsMarginRuntimeResult<BatchSettlementReceipt> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if request.receipt_kind == SettlementReceiptKind::PositionBatchSettled {
            let batch = self
                .settlement_batches
                .get(&request.subject_id)
                .ok_or_else(|| "settlement receipt references unknown batch".to_string())?
                .clone();
            if !batch.status.can_settle() {
                return Err("settlement batch cannot settle from current status".to_string());
            }
            if request.settled_at_height > batch.settlement_deadline_height {
                return Err("settlement batch deadline elapsed".to_string());
            }
            for note_id in &batch.position_note_ids {
                if let Some(note) = self.position_notes.get_mut(note_id) {
                    note.status = NoteStatus::Settled;
                }
            }
            if let Some(stored_batch) = self.settlement_batches.get_mut(&request.subject_id) {
                stored_batch.status = BatchStatus::Settled;
            }
            if let Some(market) = self.markets.get_mut(&batch.market_id) {
                market.latest_market_state_root = request.state_root_after.clone();
            }
        }
        self.counters.settlement_receipt_counter =
            self.counters.settlement_receipt_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.settled_at_height);
        let settlement_receipt_id =
            settlement_receipt_id(&request, self.counters.settlement_receipt_counter);
        let receipt = BatchSettlementReceipt {
            settlement_receipt_id: settlement_receipt_id.clone(),
            receipt_kind: request.receipt_kind,
            subject_id: request.subject_id,
            settlement_tx_root: request.settlement_tx_root,
            settlement_proof_root: request.settlement_proof_root,
            included_note_root: request.included_note_root,
            rejected_note_root: request.rejected_note_root,
            account_delta_root: request.account_delta_root,
            output_note_root: request.output_note_root,
            funding_payment_root: request.funding_payment_root,
            fee_receipt_root: request.fee_receipt_root,
            low_fee_sponsor_receipt_root: request.low_fee_sponsor_receipt_root,
            pq_settlement_root: request.pq_settlement_root,
            state_root_after: request.state_root_after,
            settled_fee_bps: request.settled_fee_bps,
            settled_at_height: request.settled_at_height,
        };
        self.settlement_receipts
            .insert(settlement_receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn roots(&self) -> Roots {
        let market_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-PERPETUALS-MARKETS",
            &self
                .markets
                .values()
                .map(PerpetualMarket::public_record)
                .collect::<Vec<_>>(),
        );
        let margin_vault_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-PERPETUALS-MARGIN-VAULTS",
            &self
                .margin_vaults
                .values()
                .map(MarginVault::public_record)
                .collect::<Vec<_>>(),
        );
        let position_note_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-PERPETUALS-POSITION-NOTES",
            &self
                .position_notes
                .values()
                .map(ShieldedPositionNote::public_record)
                .collect::<Vec<_>>(),
        );
        let risk_attestation_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-PERPETUALS-RISK-ATTESTATIONS",
            &self
                .risk_attestations
                .values()
                .map(LiquidationRiskAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        let funding_settlement_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-PERPETUALS-FUNDING-SETTLEMENTS",
            &self
                .funding_settlements
                .values()
                .map(LowFeeFundingSettlement::public_record)
                .collect::<Vec<_>>(),
        );
        let settlement_batch_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-PERPETUALS-SETTLEMENT-BATCHES",
            &self
                .settlement_batches
                .values()
                .map(SettlementBatch::public_record)
                .collect::<Vec<_>>(),
        );
        let settlement_receipt_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-PERPETUALS-SETTLEMENT-RECEIPTS",
            &self
                .settlement_receipts
                .values()
                .map(BatchSettlementReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-PERPETUALS-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-PERPETUALS-MARGIN-STATE",
            &json!({
                "chain_id": self.config.chain_id,
                "protocol_version": self.config.protocol_version,
                "current_height": self.current_height,
                "market_root": market_root,
                "margin_vault_root": margin_vault_root,
                "position_note_root": position_note_root,
                "risk_attestation_root": risk_attestation_root,
                "funding_settlement_root": funding_settlement_root,
                "settlement_batch_root": settlement_batch_root,
                "settlement_receipt_root": settlement_receipt_root,
                "nullifier_root": nullifier_root,
                "counters": self.counters.public_record(),
            }),
        );
        Roots {
            market_root,
            margin_vault_root,
            position_note_root,
            risk_attestation_root,
            funding_settlement_root,
            settlement_batch_root,
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
            "margin_vault_ids": self.margin_vaults.keys().cloned().collect::<Vec<_>>(),
            "position_note_ids": self.position_notes.keys().cloned().collect::<Vec<_>>(),
            "risk_attestation_ids": self.risk_attestations.keys().cloned().collect::<Vec<_>>(),
            "funding_settlement_ids": self.funding_settlements.keys().cloned().collect::<Vec<_>>(),
            "settlement_batch_ids": self.settlement_batches.keys().cloned().collect::<Vec<_>>(),
            "settlement_receipt_ids": self.settlement_receipts.keys().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn consume_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2ConfidentialPerpetualsMarginRuntimeResult<()> {
        let nullifier_hash = payload_id(
            "PRIVATE-L2-CONFIDENTIAL-PERPETUALS-NULLIFIER-ID",
            &[HashPart::Str(nullifier)],
        );
        if !self.consumed_nullifiers.insert(nullifier_hash) {
            return Err("confidential perpetuals nullifier replay detected".to_string());
        }
        self.counters.consumed_nullifier_counter =
            self.counters.consumed_nullifier_counter.saturating_add(1);
        Ok(())
    }
}

pub fn perpetual_market_id(request: &OpenPerpetualMarketRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-PERPETUALS-MARKET-ID",
        &json!({
            "counter": counter,
            "market_kind": request.market_kind.as_str(),
            "market_owner_commitment": request.market_owner_commitment,
            "base_asset_root": request.base_asset_root,
            "quote_asset_root": request.quote_asset_root,
            "market_nullifier": request.market_nullifier,
            "opened_at_height": request.opened_at_height,
        }),
    )
}

pub fn margin_vault_id(request: &OpenMarginVaultRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-PERPETUALS-MARGIN-VAULT-ID",
        &json!({
            "counter": counter,
            "market_id": request.market_id,
            "vault_mode": request.vault_mode.as_str(),
            "owner_commitment": request.owner_commitment,
            "collateral_note_root": request.collateral_note_root,
            "vault_nullifier": request.vault_nullifier,
            "opened_at_height": request.opened_at_height,
        }),
    )
}

pub fn position_note_id(request: &SubmitShieldedPositionNoteRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-PERPETUALS-POSITION-NOTE-ID",
        &json!({
            "counter": counter,
            "market_id": request.market_id,
            "margin_vault_id": request.margin_vault_id,
            "side": request.side.as_str(),
            "intent_kind": request.intent_kind.as_str(),
            "position_note_root": request.position_note_root,
            "notional_commitment_root": request.notional_commitment_root,
            "note_nullifier": request.note_nullifier,
            "submitted_at_height": request.submitted_at_height,
        }),
    )
}

pub fn risk_attestation_id(request: &AttestLiquidationRiskRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-PERPETUALS-RISK-ATTESTATION-ID",
        &json!({
            "counter": counter,
            "market_id": request.market_id,
            "margin_vault_id": request.margin_vault_id,
            "position_note_id": request.position_note_id,
            "attestor_commitment": request.attestor_commitment,
            "verdict": request.verdict.as_str(),
            "proof_root": request.proof_root,
            "attestation_nullifier": request.attestation_nullifier,
            "attested_at_height": request.attested_at_height,
        }),
    )
}

pub fn funding_settlement_id(request: &SettleLowFeeFundingRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-PERPETUALS-FUNDING-SETTLEMENT-ID",
        &json!({
            "counter": counter,
            "market_id": request.market_id,
            "funding_epoch": request.funding_epoch,
            "funding_rate_bps": request.funding_rate_bps,
            "net_funding_delta_root": request.net_funding_delta_root,
            "settlement_nullifier": request.settlement_nullifier,
            "settled_at_height": request.settled_at_height,
        }),
    )
}

pub fn settlement_batch_id(request: &BuildSettlementBatchRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-PERPETUALS-SETTLEMENT-BATCH-ID",
        &json!({
            "counter": counter,
            "market_id": request.market_id,
            "position_note_ids": request.position_note_ids,
            "matching_engine_root": request.matching_engine_root,
            "netting_root": request.netting_root,
            "recursive_batch_proof_root": request.recursive_batch_proof_root,
            "batch_nullifier": request.batch_nullifier,
            "built_at_height": request.built_at_height,
        }),
    )
}

pub fn settlement_receipt_id(
    request: &PublishBatchSettlementReceiptRequest,
    counter: u64,
) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-PERPETUALS-SETTLEMENT-RECEIPT-ID",
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
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_PROTOCOL_VERSION),
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
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_PROTOCOL_VERSION),
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
            PRIVATE_L2_CONFIDENTIAL_PERPETUALS_MARGIN_RUNTIME_PROTOCOL_VERSION, CHAIN_ID, domain
        ),
        parts,
        32,
    )
}

fn required(field: &str, value: &str) -> PrivateL2ConfidentialPerpetualsMarginRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("confidential perpetuals field {field} is required"));
    }
    Ok(())
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2ConfidentialPerpetualsMarginRuntimeResult<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("confidential perpetuals privacy set below minimum".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err("confidential perpetuals PQ security bits below minimum".to_string());
    }
    Ok(())
}
