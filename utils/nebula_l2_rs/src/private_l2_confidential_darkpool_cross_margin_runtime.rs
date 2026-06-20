use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialDarkpoolCrossMarginRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-darkpool-cross-margin-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SCHEME: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-darkpool-v1";
pub const VIEWING_KEY_SCHEME: &str = "monero-view-tag-selective-disclosure-v1";
pub const ORDER_ENCRYPTION_SCHEME: &str = "hybrid-pq-threshold-sealed-orderflow-v1";
pub const DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_LOW_FEE_LANE: &str = "devnet-private-darkpool-low-fee";
pub const DEFAULT_BASE_ASSET_ID: &str = "asset:wxmr";
pub const DEFAULT_QUOTE_ASSET_ID: &str = "asset:private-dusd";
pub const DEFAULT_BATCH_LIMIT: usize = 8192;
pub const DEFAULT_MIN_PRIVACY_SET: u64 = 32768;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_REBATE_BPS: u64 = 6;
pub const DEFAULT_INITIAL_MARGIN_BPS: u64 = 1400;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 650;
pub const DEFAULT_LIQUIDATION_PENALTY_BPS: u64 = 350;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    Open,
    ReduceOnly,
    LiquidationOnly,
    Frozen,
    Closed,
}

impl AccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::ReduceOnly => "reduce_only",
            Self::LiquidationOnly => "liquidation_only",
            Self::Frozen => "frozen",
            Self::Closed => "closed",
        }
    }

    pub fn can_place_orders(self) -> bool {
        matches!(self, Self::Open | Self::ReduceOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginMode {
    Cross,
    Portfolio,
    DeltaNeutral,
}

impl MarginMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cross => "cross",
            Self::Portfolio => "portfolio",
            Self::DeltaNeutral => "delta_neutral",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderSide {
    Buy,
    Sell,
}

impl OrderSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Buy => "buy",
            Self::Sell => "sell",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderKind {
    Limit,
    Pegged,
    FillOrKill,
    PostOnly,
    ReduceOnly,
    Rebalance,
}

impl OrderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Limit => "limit",
            Self::Pegged => "pegged",
            Self::FillOrKill => "fill_or_kill",
            Self::PostOnly => "post_only",
            Self::ReduceOnly => "reduce_only",
            Self::Rebalance => "rebalance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Sealed,
    RiskAttested,
    Queued,
    Matched,
    Settled,
    Cancelled,
    Rejected,
    Expired,
}

impl OrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::RiskAttested => "risk_attested",
            Self::Queued => "queued",
            Self::Matched => "matched",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn matchable(self) -> bool {
        matches!(self, Self::Sealed | Self::RiskAttested | Self::Queued)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskVerdict {
    Healthy,
    Watch,
    Deleveraging,
    LiquidationOnly,
    Reject,
}

impl RiskVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::Deleveraging => "deleveraging",
            Self::LiquidationOnly => "liquidation_only",
            Self::Reject => "reject",
        }
    }

    pub fn allows_match(self) -> bool {
        matches!(self, Self::Healthy | Self::Watch | Self::Deleveraging)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Collecting,
    Solved,
    Proved,
    Settled,
    Disputed,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Solved => "solved",
            Self::Proved => "proved",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Reserved,
    Consumed,
    Rebated,
    Expired,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub low_fee_lane_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub max_batch_orders: usize,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub default_rebate_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_penalty_bps: u64,
    pub settlement_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub hash_suite: String,
    pub pq_auth_scheme: String,
    pub order_encryption_scheme: String,
    pub viewing_key_scheme: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            low_fee_lane_id: DEFAULT_LOW_FEE_LANE.to_string(),
            base_asset_id: DEFAULT_BASE_ASSET_ID.to_string(),
            quote_asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
            max_batch_orders: DEFAULT_BATCH_LIMIT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            default_rebate_bps: DEFAULT_REBATE_BPS,
            initial_margin_bps: DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            liquidation_penalty_bps: DEFAULT_LIQUIDATION_PENALTY_BPS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_scheme: PQ_AUTH_SCHEME.to_string(),
            order_encryption_scheme: ORDER_ENCRYPTION_SCHEME.to_string(),
            viewing_key_scheme: VIEWING_KEY_SCHEME.to_string(),
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "low_fee_lane_id": self.low_fee_lane_id,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "max_batch_orders": self.max_batch_orders,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "default_rebate_bps": self.default_rebate_bps,
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "liquidation_penalty_bps": self.liquidation_penalty_bps,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "hash_suite": self.hash_suite,
            "pq_auth_scheme": self.pq_auth_scheme,
            "order_encryption_scheme": self.order_encryption_scheme,
            "viewing_key_scheme": self.viewing_key_scheme,
        })
    }

    pub fn validate(&self) -> PrivateL2ConfidentialDarkpoolCrossMarginRuntimeResult<()> {
        require(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        require(self.max_batch_orders > 0, "batch limit must be positive")?;
        require(self.min_privacy_set_size >= 1024, "privacy set too small")?;
        require(self.max_user_fee_bps <= MAX_BPS, "max fee bps invalid")?;
        require(
            self.default_rebate_bps <= self.max_user_fee_bps,
            "rebate exceeds max fee",
        )?;
        require(
            self.initial_margin_bps > self.maintenance_margin_bps,
            "margin ladder invalid",
        )?;
        require(
            self.liquidation_penalty_bps <= MAX_BPS,
            "liquidation penalty invalid",
        )?;
        require(self.min_pq_security_bits >= 192, "pq security below policy")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    pub accounts: u64,
    pub vaults: u64,
    pub orders: u64,
    pub nullifiers: u64,
    pub risk_attestations: u64,
    pub sponsor_reservations: u64,
    pub matching_batches: u64,
    pub settlement_receipts: u64,
    pub rebates: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "accounts": self.accounts,
            "vaults": self.vaults,
            "orders": self.orders,
            "nullifiers": self.nullifiers,
            "risk_attestations": self.risk_attestations,
            "sponsor_reservations": self.sponsor_reservations,
            "matching_batches": self.matching_batches,
            "settlement_receipts": self.settlement_receipts,
            "rebates": self.rebates,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfidentialAccount {
    pub account_id: String,
    pub owner_commitment: String,
    pub view_tag_root: String,
    pub pq_public_key_root: String,
    pub margin_mode: MarginMode,
    pub status: AccountStatus,
    pub collateral_commitment_root: String,
    pub position_commitment_root: String,
    pub debt_commitment_root: String,
    pub health_commitment_root: String,
    pub max_leverage_bps: u64,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl ConfidentialAccount {
    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "owner_commitment": self.owner_commitment,
            "view_tag_root": self.view_tag_root,
            "pq_public_key_root": self.pq_public_key_root,
            "margin_mode": self.margin_mode.as_str(),
            "status": self.status.as_str(),
            "collateral_commitment_root": self.collateral_commitment_root,
            "position_commitment_root": self.position_commitment_root,
            "debt_commitment_root": self.debt_commitment_root,
            "health_commitment_root": self.health_commitment_root,
            "max_leverage_bps": self.max_leverage_bps,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialDarkpoolCrossMarginRuntimeResult<()> {
        require(!self.account_id.is_empty(), "account id missing")?;
        require(
            self.status.can_place_orders() || self.status != AccountStatus::Closed,
            "closed account active",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "account privacy set too small",
        )?;
        require(self.max_leverage_bps >= MAX_BPS, "leverage below 1x")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrossMarginVault {
    pub vault_id: String,
    pub account_id: String,
    pub vault_label: String,
    pub collateral_asset_ids: Vec<String>,
    pub collateral_note_root: String,
    pub liability_note_root: String,
    pub unrealized_pnl_root: String,
    pub margin_requirement_root: String,
    pub insurance_bucket_root: String,
    pub available_credit_root: String,
    pub withdrawal_nullifier_root: String,
    pub created_at_height: u64,
    pub last_rebalanced_height: u64,
}

impl CrossMarginVault {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "account_id": self.account_id,
            "vault_label": self.vault_label,
            "collateral_asset_ids": self.collateral_asset_ids,
            "collateral_note_root": self.collateral_note_root,
            "liability_note_root": self.liability_note_root,
            "unrealized_pnl_root": self.unrealized_pnl_root,
            "margin_requirement_root": self.margin_requirement_root,
            "insurance_bucket_root": self.insurance_bucket_root,
            "available_credit_root": self.available_credit_root,
            "withdrawal_nullifier_root": self.withdrawal_nullifier_root,
            "created_at_height": self.created_at_height,
            "last_rebalanced_height": self.last_rebalanced_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedDarkpoolOrder {
    pub order_id: String,
    pub account_id: String,
    pub vault_id: String,
    pub market_id: String,
    pub side: OrderSide,
    pub kind: OrderKind,
    pub status: OrderStatus,
    pub order_commitment: String,
    pub nullifier: String,
    pub amount_commitment_root: String,
    pub price_commitment_root: String,
    pub time_in_force_root: String,
    pub encrypted_payload_root: String,
    pub threshold_key_root: String,
    pub pq_auth_root: String,
    pub risk_hint_root: String,
    pub fee_commitment_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedDarkpoolOrder {
    pub fn public_record(&self) -> Value {
        json!({
            "order_id": self.order_id,
            "account_id": self.account_id,
            "vault_id": self.vault_id,
            "market_id": self.market_id,
            "side": self.side.as_str(),
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "order_commitment": self.order_commitment,
            "nullifier": self.nullifier,
            "amount_commitment_root": self.amount_commitment_root,
            "price_commitment_root": self.price_commitment_root,
            "time_in_force_root": self.time_in_force_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "threshold_key_root": self.threshold_key_root,
            "pq_auth_root": self.pq_auth_root,
            "risk_hint_root": self.risk_hint_root,
            "fee_commitment_root": self.fee_commitment_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialDarkpoolCrossMarginRuntimeResult<()> {
        require(
            self.status.matchable() || self.status == OrderStatus::Settled,
            "invalid order status",
        )?;
        require(
            self.max_fee_bps <= config.max_user_fee_bps,
            "order fee exceeds policy",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "order privacy set too small",
        )?;
        require(
            self.expires_at_height > self.submitted_at_height,
            "order ttl invalid",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrderCommitment {
    pub commitment_id: String,
    pub order_id: String,
    pub commitment_root: String,
    pub payload_root: String,
    pub blinding_root: String,
    pub market_root: String,
    pub created_at_height: u64,
}

impl OrderCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "order_id": self.order_id,
            "commitment_root": self.commitment_root,
            "payload_root": self.payload_root,
            "blinding_root": self.blinding_root,
            "market_root": self.market_root,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrderNullifier {
    pub nullifier_id: String,
    pub order_id: String,
    pub account_id: String,
    pub nullifier_root: String,
    pub replay_domain: String,
    pub spent: bool,
    pub spent_at_height: Option<u64>,
}

impl OrderNullifier {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "order_id": self.order_id,
            "account_id": self.account_id,
            "nullifier_root": self.nullifier_root,
            "replay_domain": self.replay_domain,
            "spent": self.spent,
            "spent_at_height": self.spent_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RiskAttestation {
    pub attestation_id: String,
    pub account_id: String,
    pub vault_id: String,
    pub order_id: Option<String>,
    pub attester_commitment: String,
    pub verdict: RiskVerdict,
    pub margin_mode: MarginMode,
    pub collateral_root: String,
    pub exposure_root: String,
    pub stress_vector_root: String,
    pub oracle_snapshot_root: String,
    pub health_factor_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl RiskAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "account_id": self.account_id,
            "vault_id": self.vault_id,
            "order_id": self.order_id,
            "attester_commitment": self.attester_commitment,
            "verdict": self.verdict.as_str(),
            "margin_mode": self.margin_mode.as_str(),
            "collateral_root": self.collateral_root,
            "exposure_root": self.exposure_root,
            "stress_vector_root": self.stress_vector_root,
            "oracle_snapshot_root": self.oracle_snapshot_root,
            "health_factor_root": self.health_factor_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_set_size": self.privacy_set_size,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LowFeeSponsorReservation {
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub account_id: Option<String>,
    pub batch_id: Option<String>,
    pub fee_asset_id: String,
    pub reserved_fee_root: String,
    pub rebate_commitment_root: String,
    pub max_fee_bps: u64,
    pub status: SponsorStatus,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeSponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "sponsor_commitment": self.sponsor_commitment,
            "account_id": self.account_id,
            "batch_id": self.batch_id,
            "fee_asset_id": self.fee_asset_id,
            "reserved_fee_root": self.reserved_fee_root,
            "rebate_commitment_root": self.rebate_commitment_root,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchFill {
    pub fill_id: String,
    pub maker_order_id: String,
    pub taker_order_id: String,
    pub market_id: String,
    pub fill_commitment_root: String,
    pub price_commitment_root: String,
    pub quantity_commitment_root: String,
    pub fee_commitment_root: String,
    pub maker_rebate_root: String,
    pub taker_rebate_root: String,
}

impl MatchFill {
    pub fn public_record(&self) -> Value {
        json!({
            "fill_id": self.fill_id,
            "maker_order_id": self.maker_order_id,
            "taker_order_id": self.taker_order_id,
            "market_id": self.market_id,
            "fill_commitment_root": self.fill_commitment_root,
            "price_commitment_root": self.price_commitment_root,
            "quantity_commitment_root": self.quantity_commitment_root,
            "fee_commitment_root": self.fee_commitment_root,
            "maker_rebate_root": self.maker_rebate_root,
            "taker_rebate_root": self.taker_rebate_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MatchingBatch {
    pub batch_id: String,
    pub solver_commitment: String,
    pub status: BatchStatus,
    pub order_ids: Vec<String>,
    pub fill_ids: Vec<String>,
    pub order_root: String,
    pub fill_root: String,
    pub nullifier_root: String,
    pub risk_attestation_root: String,
    pub sponsor_reservation_root: String,
    pub solver_proof_root: String,
    pub settlement_intent_root: String,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
}

impl MatchingBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "solver_commitment": self.solver_commitment,
            "status": self.status.as_str(),
            "order_ids": self.order_ids,
            "fill_ids": self.fill_ids,
            "order_root": self.order_root,
            "fill_root": self.fill_root,
            "nullifier_root": self.nullifier_root,
            "risk_attestation_root": self.risk_attestation_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "solver_proof_root": self.solver_proof_root,
            "settlement_intent_root": self.settlement_intent_root,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub account_id: String,
    pub vault_id: String,
    pub fill_root: String,
    pub debit_note_root: String,
    pub credit_note_root: String,
    pub fee_paid_root: String,
    pub rebate_root: String,
    pub post_margin_root: String,
    pub settlement_proof_root: String,
    pub settled_at_height: u64,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "account_id": self.account_id,
            "vault_id": self.vault_id,
            "fill_root": self.fill_root,
            "debit_note_root": self.debit_note_root,
            "credit_note_root": self.credit_note_root,
            "fee_paid_root": self.fee_paid_root,
            "rebate_root": self.rebate_root,
            "post_margin_root": self.post_margin_root,
            "settlement_proof_root": self.settlement_proof_root,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub account_id: String,
    pub sponsor_reservation_id: Option<String>,
    pub rebate_asset_id: String,
    pub rebate_note_root: String,
    pub rebate_bps: u64,
    pub issued_at_height: u64,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "account_id": self.account_id,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "rebate_asset_id": self.rebate_asset_id,
            "rebate_note_root": self.rebate_note_root,
            "rebate_bps": self.rebate_bps,
            "issued_at_height": self.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub event_id: String,
    pub event_kind: String,
    pub actor_commitment: String,
    pub account_id: Option<String>,
    pub order_id: Option<String>,
    pub batch_id: Option<String>,
    pub event_root: String,
    pub issued_at_height: u64,
}

impl AuditEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "actor_commitment": self.actor_commitment,
            "account_id": self.account_id,
            "order_id": self.order_id,
            "batch_id": self.batch_id,
            "event_root": self.event_root,
            "issued_at_height": self.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DarkpoolMarketConfig {
    pub market_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub price_tick_root: String,
    pub quantity_tick_root: String,
    pub oracle_band_root: String,
    pub maker_fee_bps: u64,
    pub taker_fee_bps: u64,
    pub rebate_bps: u64,
    pub min_privacy_set_size: u64,
    pub batch_interval_blocks: u64,
    pub active: bool,
}

impl DarkpoolMarketConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "price_tick_root": self.price_tick_root,
            "quantity_tick_root": self.quantity_tick_root,
            "oracle_band_root": self.oracle_band_root,
            "maker_fee_bps": self.maker_fee_bps,
            "taker_fee_bps": self.taker_fee_bps,
            "rebate_bps": self.rebate_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_interval_blocks": self.batch_interval_blocks,
            "active": self.active,
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialDarkpoolCrossMarginRuntimeResult<()> {
        require(!self.market_id.is_empty(), "market id missing")?;
        require(
            self.maker_fee_bps <= config.max_user_fee_bps,
            "maker fee exceeds policy",
        )?;
        require(
            self.taker_fee_bps <= config.max_user_fee_bps,
            "taker fee exceeds policy",
        )?;
        require(
            self.rebate_bps <= self.taker_fee_bps,
            "rebate exceeds taker fee",
        )?;
        require(
            self.min_privacy_set_size >= config.min_privacy_set_size,
            "market privacy set too small",
        )?;
        require(self.batch_interval_blocks > 0, "batch interval missing")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyPoolSnapshot {
    pub snapshot_id: String,
    pub anonymity_set_root: String,
    pub decoy_output_root: String,
    pub view_tag_bucket_root: String,
    pub order_commitment_root: String,
    pub account_commitment_root: String,
    pub nullifier_accumulator_root: String,
    pub minimum_set_size: u64,
    pub observed_set_size: u64,
    pub sampled_at_height: u64,
}

impl PrivacyPoolSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "anonymity_set_root": self.anonymity_set_root,
            "decoy_output_root": self.decoy_output_root,
            "view_tag_bucket_root": self.view_tag_bucket_root,
            "order_commitment_root": self.order_commitment_root,
            "account_commitment_root": self.account_commitment_root,
            "nullifier_accumulator_root": self.nullifier_accumulator_root,
            "minimum_set_size": self.minimum_set_size,
            "observed_set_size": self.observed_set_size,
            "sampled_at_height": self.sampled_at_height,
        })
    }

    pub fn validate(&self) -> PrivateL2ConfidentialDarkpoolCrossMarginRuntimeResult<()> {
        require(
            self.observed_set_size >= self.minimum_set_size,
            "privacy pool underfilled",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OraclePriceBand {
    pub band_id: String,
    pub market_id: String,
    pub oracle_committee_root: String,
    pub lower_price_commitment_root: String,
    pub upper_price_commitment_root: String,
    pub twap_commitment_root: String,
    pub volatility_commitment_root: String,
    pub signature_root: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl OraclePriceBand {
    pub fn public_record(&self) -> Value {
        json!({
            "band_id": self.band_id,
            "market_id": self.market_id,
            "oracle_committee_root": self.oracle_committee_root,
            "lower_price_commitment_root": self.lower_price_commitment_root,
            "upper_price_commitment_root": self.upper_price_commitment_root,
            "twap_commitment_root": self.twap_commitment_root,
            "volatility_commitment_root": self.volatility_commitment_root,
            "signature_root": self.signature_root,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiquidityBand {
    pub band_id: String,
    pub market_id: String,
    pub side: OrderSide,
    pub liquidity_commitment_root: String,
    pub price_band_root: String,
    pub depth_bucket_root: String,
    pub maker_count_root: String,
    pub inventory_skew_root: String,
    pub sampled_at_height: u64,
}

impl LiquidityBand {
    pub fn public_record(&self) -> Value {
        json!({
            "band_id": self.band_id,
            "market_id": self.market_id,
            "side": self.side.as_str(),
            "liquidity_commitment_root": self.liquidity_commitment_root,
            "price_band_root": self.price_band_root,
            "depth_bucket_root": self.depth_bucket_root,
            "maker_count_root": self.maker_count_root,
            "inventory_skew_root": self.inventory_skew_root,
            "sampled_at_height": self.sampled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MarginBucket {
    pub bucket_id: String,
    pub account_id: String,
    pub vault_id: String,
    pub collateral_bucket_root: String,
    pub exposure_bucket_root: String,
    pub pending_order_bucket_root: String,
    pub maintenance_requirement_root: String,
    pub initial_requirement_root: String,
    pub liquidation_threshold_root: String,
    pub sampled_at_height: u64,
}

impl MarginBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "account_id": self.account_id,
            "vault_id": self.vault_id,
            "collateral_bucket_root": self.collateral_bucket_root,
            "exposure_bucket_root": self.exposure_bucket_root,
            "pending_order_bucket_root": self.pending_order_bucket_root,
            "maintenance_requirement_root": self.maintenance_requirement_root,
            "initial_requirement_root": self.initial_requirement_root,
            "liquidation_threshold_root": self.liquidation_threshold_root,
            "sampled_at_height": self.sampled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementNettingLane {
    pub lane_id: String,
    pub batch_id: String,
    pub debit_root: String,
    pub credit_root: String,
    pub fee_root: String,
    pub rebate_root: String,
    pub bridge_exit_root: String,
    pub compressed_proof_root: String,
    pub netted_account_count: u64,
    pub settled_at_height: u64,
}

impl SettlementNettingLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "batch_id": self.batch_id,
            "debit_root": self.debit_root,
            "credit_root": self.credit_root,
            "fee_root": self.fee_root,
            "rebate_root": self.rebate_root,
            "bridge_exit_root": self.bridge_exit_root,
            "compressed_proof_root": self.compressed_proof_root,
            "netted_account_count": self.netted_account_count,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WithdrawalQueueItem {
    pub queue_item_id: String,
    pub account_id: String,
    pub vault_id: String,
    pub destination_subaddress_root: String,
    pub amount_commitment_root: String,
    pub fee_commitment_root: String,
    pub withdrawal_nullifier: String,
    pub exit_proof_root: String,
    pub requested_at_height: u64,
    pub executable_after_height: u64,
}

impl WithdrawalQueueItem {
    pub fn public_record(&self) -> Value {
        json!({
            "queue_item_id": self.queue_item_id,
            "account_id": self.account_id,
            "vault_id": self.vault_id,
            "destination_subaddress_root": self.destination_subaddress_root,
            "amount_commitment_root": self.amount_commitment_root,
            "fee_commitment_root": self.fee_commitment_root,
            "withdrawal_nullifier": self.withdrawal_nullifier,
            "exit_proof_root": self.exit_proof_root,
            "requested_at_height": self.requested_at_height,
            "executable_after_height": self.executable_after_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SponsorAuctionQuote {
    pub quote_id: String,
    pub sponsor_commitment: String,
    pub lane_id: String,
    pub fee_asset_id: String,
    pub capacity_commitment_root: String,
    pub bid_fee_bps: u64,
    pub rebate_bps: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl SponsorAuctionQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane_id": self.lane_id,
            "fee_asset_id": self.fee_asset_id,
            "capacity_commitment_root": self.capacity_commitment_root,
            "bid_fee_bps": self.bid_fee_bps,
            "rebate_bps": self.rebate_bps,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchDispute {
    pub dispute_id: String,
    pub batch_id: String,
    pub challenger_commitment: String,
    pub challenged_root: String,
    pub evidence_root: String,
    pub bond_commitment_root: String,
    pub response_window_end_height: u64,
    pub opened_at_height: u64,
    pub resolved: bool,
}

impl BatchDispute {
    pub fn public_record(&self) -> Value {
        json!({
            "dispute_id": self.dispute_id,
            "batch_id": self.batch_id,
            "challenger_commitment": self.challenger_commitment,
            "challenged_root": self.challenged_root,
            "evidence_root": self.evidence_root,
            "bond_commitment_root": self.bond_commitment_root,
            "response_window_end_height": self.response_window_end_height,
            "opened_at_height": self.opened_at_height,
            "resolved": self.resolved,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmergencyCircuitBreaker {
    pub breaker_id: String,
    pub guardian_committee_root: String,
    pub affected_market_root: String,
    pub affected_batch_root: String,
    pub reason_root: String,
    pub pause_orders: bool,
    pub pause_settlement: bool,
    pub allow_withdrawals: bool,
    pub pq_signature_root: String,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
}

impl EmergencyCircuitBreaker {
    pub fn public_record(&self) -> Value {
        json!({
            "breaker_id": self.breaker_id,
            "guardian_committee_root": self.guardian_committee_root,
            "affected_market_root": self.affected_market_root,
            "affected_batch_root": self.affected_batch_root,
            "reason_root": self.reason_root,
            "pause_orders": self.pause_orders,
            "pause_settlement": self.pause_settlement,
            "allow_withdrawals": self.allow_withdrawals,
            "pq_signature_root": self.pq_signature_root,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeTelemetry {
    pub telemetry_id: String,
    pub sample_window_root: String,
    pub orders_per_second_bucket: String,
    pub proof_latency_bucket: String,
    pub matching_latency_bucket: String,
    pub settlement_latency_bucket: String,
    pub median_fee_bps: u64,
    pub sponsor_fill_rate_bps: u64,
    pub privacy_set_size: u64,
    pub sampled_at_height: u64,
}

impl RuntimeTelemetry {
    pub fn public_record(&self) -> Value {
        json!({
            "telemetry_id": self.telemetry_id,
            "sample_window_root": self.sample_window_root,
            "orders_per_second_bucket": self.orders_per_second_bucket,
            "proof_latency_bucket": self.proof_latency_bucket,
            "matching_latency_bucket": self.matching_latency_bucket,
            "settlement_latency_bucket": self.settlement_latency_bucket,
            "median_fee_bps": self.median_fee_bps,
            "sponsor_fill_rate_bps": self.sponsor_fill_rate_bps,
            "privacy_set_size": self.privacy_set_size,
            "sampled_at_height": self.sampled_at_height,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub account_root: String,
    pub vault_root: String,
    pub order_root: String,
    pub commitment_root: String,
    pub nullifier_root: String,
    pub risk_attestation_root: String,
    pub sponsor_reservation_root: String,
    pub fill_root: String,
    pub matching_batch_root: String,
    pub settlement_receipt_root: String,
    pub rebate_root: String,
    pub event_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "account_root": self.account_root,
            "vault_root": self.vault_root,
            "order_root": self.order_root,
            "commitment_root": self.commitment_root,
            "nullifier_root": self.nullifier_root,
            "risk_attestation_root": self.risk_attestation_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "fill_root": self.fill_root,
            "matching_batch_root": self.matching_batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "rebate_root": self.rebate_root,
            "event_root": self.event_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub accounts: BTreeMap<String, ConfidentialAccount>,
    pub vaults: BTreeMap<String, CrossMarginVault>,
    pub orders: BTreeMap<String, EncryptedDarkpoolOrder>,
    pub commitments: BTreeMap<String, OrderCommitment>,
    pub nullifiers: BTreeMap<String, OrderNullifier>,
    pub risk_attestations: BTreeMap<String, RiskAttestation>,
    pub sponsor_reservations: BTreeMap<String, LowFeeSponsorReservation>,
    pub fills: BTreeMap<String, MatchFill>,
    pub matching_batches: BTreeMap<String, MatchingBatch>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub events: Vec<AuditEvent>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            accounts: BTreeMap::new(),
            vaults: BTreeMap::new(),
            orders: BTreeMap::new(),
            commitments: BTreeMap::new(),
            nullifiers: BTreeMap::new(),
            risk_attestations: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            fills: BTreeMap::new(),
            matching_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            events: Vec::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        let height = 232_000;

        let alice_owner = deterministic_commitment("owner", "alice");
        let bob_owner = deterministic_commitment("owner", "bob");
        let alice_account_id = account_id(&alice_owner, 0);
        let bob_account_id = account_id(&bob_owner, 1);
        let alice_vault_id = vault_id(&alice_account_id, "cross-margin-primary", 0);
        let bob_vault_id = vault_id(&bob_account_id, "cross-margin-primary", 1);

        let alice = ConfidentialAccount {
            account_id: alice_account_id.clone(),
            owner_commitment: alice_owner.clone(),
            view_tag_root: payload_root(&json!(["view-tag", "alice", "epoch-0"])),
            pq_public_key_root: payload_root(&json!(["ml-kem-1024", "ml-dsa-87", "alice"])),
            margin_mode: MarginMode::Cross,
            status: AccountStatus::Open,
            collateral_commitment_root: payload_root(&json!({"wxmr": "alice-collateral-note"})),
            position_commitment_root: payload_root(&json!({"xmr_usd": "flat"})),
            debt_commitment_root: payload_root(&json!({"dusd": "zero"})),
            health_commitment_root: payload_root(&json!({"hf_bucket": "gt-3"})),
            max_leverage_bps: 30_000,
            privacy_set_size: 65_536,
            created_at_height: height,
            updated_at_height: height,
        };
        let bob = ConfidentialAccount {
            account_id: bob_account_id.clone(),
            owner_commitment: bob_owner.clone(),
            view_tag_root: payload_root(&json!(["view-tag", "bob", "epoch-0"])),
            pq_public_key_root: payload_root(&json!(["ml-kem-1024", "ml-dsa-87", "bob"])),
            margin_mode: MarginMode::Portfolio,
            status: AccountStatus::Open,
            collateral_commitment_root: payload_root(&json!({"wxmr": "bob-collateral-note"})),
            position_commitment_root: payload_root(&json!({"xmr_usd": "flat"})),
            debt_commitment_root: payload_root(&json!({"dusd": "zero"})),
            health_commitment_root: payload_root(&json!({"hf_bucket": "gt-4"})),
            max_leverage_bps: 25_000,
            privacy_set_size: 65_536,
            created_at_height: height,
            updated_at_height: height,
        };
        state.accounts.insert(alice_account_id.clone(), alice);
        state.accounts.insert(bob_account_id.clone(), bob);

        state.vaults.insert(
            alice_vault_id.clone(),
            CrossMarginVault {
                vault_id: alice_vault_id.clone(),
                account_id: alice_account_id.clone(),
                vault_label: "cross-margin-primary".to_string(),
                collateral_asset_ids: vec![
                    DEFAULT_BASE_ASSET_ID.to_string(),
                    DEFAULT_QUOTE_ASSET_ID.to_string(),
                ],
                collateral_note_root: payload_root(&json!(["alice-wxmr-note", "alice-dusd-note"])),
                liability_note_root: payload_root(&json!(["alice-liability-bucket-0"])),
                unrealized_pnl_root: payload_root(&json!({"bucket": "near_zero"})),
                margin_requirement_root: payload_root(
                    &json!({"initial_bps": DEFAULT_INITIAL_MARGIN_BPS}),
                ),
                insurance_bucket_root: payload_root(&json!({"bucket": "standard"})),
                available_credit_root: payload_root(&json!({"credit_bucket": "large"})),
                withdrawal_nullifier_root: payload_root(&json!({"withdrawals": []})),
                created_at_height: height,
                last_rebalanced_height: height + 1,
            },
        );
        state.vaults.insert(
            bob_vault_id.clone(),
            CrossMarginVault {
                vault_id: bob_vault_id.clone(),
                account_id: bob_account_id.clone(),
                vault_label: "cross-margin-primary".to_string(),
                collateral_asset_ids: vec![
                    DEFAULT_BASE_ASSET_ID.to_string(),
                    DEFAULT_QUOTE_ASSET_ID.to_string(),
                ],
                collateral_note_root: payload_root(&json!(["bob-wxmr-note", "bob-dusd-note"])),
                liability_note_root: payload_root(&json!(["bob-liability-bucket-0"])),
                unrealized_pnl_root: payload_root(&json!({"bucket": "near_zero"})),
                margin_requirement_root: payload_root(
                    &json!({"initial_bps": DEFAULT_INITIAL_MARGIN_BPS}),
                ),
                insurance_bucket_root: payload_root(&json!({"bucket": "standard"})),
                available_credit_root: payload_root(&json!({"credit_bucket": "large"})),
                withdrawal_nullifier_root: payload_root(&json!({"withdrawals": []})),
                created_at_height: height,
                last_rebalanced_height: height + 1,
            },
        );

        let alice_order_id = order_id(&alice_account_id, "xmr-usd", OrderSide::Buy, 0);
        let bob_order_id = order_id(&bob_account_id, "xmr-usd", OrderSide::Sell, 1);
        let alice_nullifier = nullifier_id(&alice_order_id, &alice_account_id);
        let bob_nullifier = nullifier_id(&bob_order_id, &bob_account_id);

        state.orders.insert(
            alice_order_id.clone(),
            sample_order(
                &alice_order_id,
                &alice_account_id,
                &alice_vault_id,
                "xmr-usd",
                OrderSide::Buy,
                alice_nullifier.clone(),
                height + 2,
            ),
        );
        state.orders.insert(
            bob_order_id.clone(),
            sample_order(
                &bob_order_id,
                &bob_account_id,
                &bob_vault_id,
                "xmr-usd",
                OrderSide::Sell,
                bob_nullifier.clone(),
                height + 2,
            ),
        );

        for (sequence, order_id_value, account_id_value, nullifier_value) in [
            (
                0_u64,
                alice_order_id.as_str(),
                alice_account_id.as_str(),
                alice_nullifier.as_str(),
            ),
            (
                1_u64,
                bob_order_id.as_str(),
                bob_account_id.as_str(),
                bob_nullifier.as_str(),
            ),
        ] {
            let commitment_id_value = commitment_id(order_id_value, sequence);
            state.commitments.insert(
                commitment_id_value.clone(),
                OrderCommitment {
                    commitment_id: commitment_id_value,
                    order_id: order_id_value.to_string(),
                    commitment_root: payload_root(&json!(["order-commitment", order_id_value])),
                    payload_root: payload_root(&json!(["sealed-payload", order_id_value])),
                    blinding_root: payload_root(&json!(["blinding", sequence])),
                    market_root: payload_root(&json!({"market": "xmr-usd"})),
                    created_at_height: height + 2,
                },
            );
            state.nullifiers.insert(
                nullifier_value.to_string(),
                OrderNullifier {
                    nullifier_id: nullifier_value.to_string(),
                    order_id: order_id_value.to_string(),
                    account_id: account_id_value.to_string(),
                    nullifier_root: payload_root(&json!(["nullifier", nullifier_value])),
                    replay_domain: replay_domain("devnet-darkpool", height + 2),
                    spent: false,
                    spent_at_height: None,
                },
            );
        }

        let alice_risk =
            risk_attestation_id(&alice_account_id, &alice_vault_id, Some(&alice_order_id), 0);
        let bob_risk = risk_attestation_id(&bob_account_id, &bob_vault_id, Some(&bob_order_id), 1);
        state.risk_attestations.insert(
            alice_risk.clone(),
            sample_risk(
                &alice_risk,
                &alice_account_id,
                &alice_vault_id,
                Some(alice_order_id.clone()),
                RiskVerdict::Healthy,
                height + 3,
            ),
        );
        state.risk_attestations.insert(
            bob_risk.clone(),
            sample_risk(
                &bob_risk,
                &bob_account_id,
                &bob_vault_id,
                Some(bob_order_id.clone()),
                RiskVerdict::Healthy,
                height + 3,
            ),
        );

        let batch_id_value = matching_batch_id("solver-devnet-0", height + 4, 0);
        let sponsor_id_value = sponsor_reservation_id("sponsor-devnet-0", Some(&batch_id_value), 0);
        state.sponsor_reservations.insert(
            sponsor_id_value.clone(),
            LowFeeSponsorReservation {
                reservation_id: sponsor_id_value.clone(),
                sponsor_commitment: deterministic_commitment("sponsor", "devnet-0"),
                account_id: None,
                batch_id: Some(batch_id_value.clone()),
                fee_asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
                reserved_fee_root: payload_root(&json!({"fee_bucket": "low"})),
                rebate_commitment_root: payload_root(&json!({"rebate": "maker-taker"})),
                max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
                status: SponsorStatus::Reserved,
                reserved_at_height: height + 3,
                expires_at_height: height + 32,
            },
        );

        let fill_id_value = fill_id(&batch_id_value, &alice_order_id, &bob_order_id, 0);
        state.fills.insert(
            fill_id_value.clone(),
            MatchFill {
                fill_id: fill_id_value.clone(),
                maker_order_id: bob_order_id.clone(),
                taker_order_id: alice_order_id.clone(),
                market_id: "xmr-usd".to_string(),
                fill_commitment_root: payload_root(&json!(["fill", "xmr-usd", "mid-bucket"])),
                price_commitment_root: payload_root(&json!({"price_bucket": "devnet-mid"})),
                quantity_commitment_root: payload_root(&json!({"quantity_bucket": "medium"})),
                fee_commitment_root: payload_root(&json!({"fee_bps": DEFAULT_MAX_USER_FEE_BPS})),
                maker_rebate_root: payload_root(&json!({"rebate_bps": DEFAULT_REBATE_BPS})),
                taker_rebate_root: payload_root(&json!({"rebate_bps": 2})),
            },
        );

        state.matching_batches.insert(
            batch_id_value.clone(),
            MatchingBatch {
                batch_id: batch_id_value.clone(),
                solver_commitment: deterministic_commitment("solver", "devnet-0"),
                status: BatchStatus::Proved,
                order_ids: vec![alice_order_id.clone(), bob_order_id.clone()],
                fill_ids: vec![fill_id_value.clone()],
                order_root: id_list_root(
                    "DARKPOOL-BATCH-ORDER-ID",
                    &[alice_order_id.clone(), bob_order_id.clone()],
                ),
                fill_root: id_list_root(
                    "DARKPOOL-BATCH-FILL-ID",
                    std::slice::from_ref(&fill_id_value),
                ),
                nullifier_root: id_list_root(
                    "DARKPOOL-BATCH-NULLIFIER",
                    &[alice_nullifier.clone(), bob_nullifier.clone()],
                ),
                risk_attestation_root: id_list_root(
                    "DARKPOOL-BATCH-RISK-ID",
                    &[alice_risk.clone(), bob_risk.clone()],
                ),
                sponsor_reservation_root: id_list_root(
                    "DARKPOOL-BATCH-SPONSOR-ID",
                    std::slice::from_ref(&sponsor_id_value),
                ),
                solver_proof_root: payload_root(&json!([
                    "recursive-proof",
                    "devnet-darkpool",
                    "batch-0"
                ])),
                settlement_intent_root: payload_root(&json!(["settle", "netted", "low-fee"])),
                privacy_set_size: 131_072,
                opened_at_height: height + 4,
                sealed_at_height: height + 5,
            },
        );

        let receipt_a = settlement_receipt_id(&batch_id_value, &alice_account_id, 0);
        let receipt_b = settlement_receipt_id(&batch_id_value, &bob_account_id, 1);
        state.settlement_receipts.insert(
            receipt_a.clone(),
            sample_receipt(
                &receipt_a,
                &batch_id_value,
                &alice_account_id,
                &alice_vault_id,
                &fill_id_value,
                height + 6,
            ),
        );
        state.settlement_receipts.insert(
            receipt_b.clone(),
            sample_receipt(
                &receipt_b,
                &batch_id_value,
                &bob_account_id,
                &bob_vault_id,
                &fill_id_value,
                height + 6,
            ),
        );

        let rebate_a = rebate_id(&receipt_a, &alice_account_id, 0);
        let rebate_b = rebate_id(&receipt_b, &bob_account_id, 1);
        state.rebates.insert(
            rebate_a.clone(),
            FeeRebate {
                rebate_id: rebate_a,
                receipt_id: receipt_a,
                account_id: alice_account_id.clone(),
                sponsor_reservation_id: Some(sponsor_id_value.clone()),
                rebate_asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
                rebate_note_root: payload_root(&json!({"rebate": "alice"})),
                rebate_bps: 2,
                issued_at_height: height + 6,
            },
        );
        state.rebates.insert(
            rebate_b.clone(),
            FeeRebate {
                rebate_id: rebate_b,
                receipt_id: receipt_b,
                account_id: bob_account_id.clone(),
                sponsor_reservation_id: Some(sponsor_id_value.clone()),
                rebate_asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
                rebate_note_root: payload_root(&json!({"rebate": "bob"})),
                rebate_bps: DEFAULT_REBATE_BPS,
                issued_at_height: height + 6,
            },
        );

        for (sequence, kind, actor, account, order, batch) in [
            (
                0_u64,
                "account_opened",
                alice_owner.as_str(),
                Some(alice_account_id.as_str()),
                None,
                None,
            ),
            (
                1_u64,
                "account_opened",
                bob_owner.as_str(),
                Some(bob_account_id.as_str()),
                None,
                None,
            ),
            (
                2_u64,
                "order_sealed",
                alice_owner.as_str(),
                Some(alice_account_id.as_str()),
                Some(alice_order_id.as_str()),
                None,
            ),
            (
                3_u64,
                "order_sealed",
                bob_owner.as_str(),
                Some(bob_account_id.as_str()),
                Some(bob_order_id.as_str()),
                None,
            ),
            (
                4_u64,
                "batch_proved",
                "solver-devnet-0",
                None,
                None,
                Some(batch_id_value.as_str()),
            ),
        ] {
            let event_id_value = event_id(kind, actor, sequence);
            state.events.push(AuditEvent {
                event_id: event_id_value,
                event_kind: kind.to_string(),
                actor_commitment: deterministic_commitment("actor", actor),
                account_id: account.map(str::to_string),
                order_id: order.map(str::to_string),
                batch_id: batch.map(str::to_string),
                event_root: payload_root(&json!([kind, actor, sequence])),
                issued_at_height: height + sequence,
            });
        }

        state.refresh_counters();
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots_without_recursive_roots().public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn refresh_counters(&mut self) {
        self.counters = Counters {
            accounts: self.accounts.len() as u64,
            vaults: self.vaults.len() as u64,
            orders: self.orders.len() as u64,
            nullifiers: self.nullifiers.len() as u64,
            risk_attestations: self.risk_attestations.len() as u64,
            sponsor_reservations: self.sponsor_reservations.len() as u64,
            matching_batches: self.matching_batches.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            rebates: self.rebates.len() as u64,
            events: self.events.len() as u64,
        };
    }

    pub fn refresh_roots(&mut self) {
        let mut roots = Roots {
            config_root: payload_root(&self.config.public_record()),
            counters_root: payload_root(&self.counters.public_record()),
            account_root: merkle_records(
                "DARKPOOL-ACCOUNT",
                self.accounts
                    .values()
                    .map(ConfidentialAccount::public_record)
                    .collect(),
            ),
            vault_root: merkle_records(
                "DARKPOOL-CROSS-MARGIN-VAULT",
                self.vaults
                    .values()
                    .map(CrossMarginVault::public_record)
                    .collect(),
            ),
            order_root: merkle_records(
                "DARKPOOL-ENCRYPTED-ORDER",
                self.orders
                    .values()
                    .map(EncryptedDarkpoolOrder::public_record)
                    .collect(),
            ),
            commitment_root: merkle_records(
                "DARKPOOL-ORDER-COMMITMENT",
                self.commitments
                    .values()
                    .map(OrderCommitment::public_record)
                    .collect(),
            ),
            nullifier_root: merkle_records(
                "DARKPOOL-ORDER-NULLIFIER",
                self.nullifiers
                    .values()
                    .map(OrderNullifier::public_record)
                    .collect(),
            ),
            risk_attestation_root: merkle_records(
                "DARKPOOL-RISK-ATTESTATION",
                self.risk_attestations
                    .values()
                    .map(RiskAttestation::public_record)
                    .collect(),
            ),
            sponsor_reservation_root: merkle_records(
                "DARKPOOL-SPONSOR-RESERVATION",
                self.sponsor_reservations
                    .values()
                    .map(LowFeeSponsorReservation::public_record)
                    .collect(),
            ),
            fill_root: merkle_records(
                "DARKPOOL-MATCH-FILL",
                self.fills.values().map(MatchFill::public_record).collect(),
            ),
            matching_batch_root: merkle_records(
                "DARKPOOL-MATCHING-BATCH",
                self.matching_batches
                    .values()
                    .map(MatchingBatch::public_record)
                    .collect(),
            ),
            settlement_receipt_root: merkle_records(
                "DARKPOOL-SETTLEMENT-RECEIPT",
                self.settlement_receipts
                    .values()
                    .map(SettlementReceipt::public_record)
                    .collect(),
            ),
            rebate_root: merkle_records(
                "DARKPOOL-FEE-REBATE",
                self.rebates
                    .values()
                    .map(FeeRebate::public_record)
                    .collect(),
            ),
            event_root: merkle_records(
                "DARKPOOL-AUDIT-EVENT",
                self.events.iter().map(AuditEvent::public_record).collect(),
            ),
            public_record_root: String::new(),
            state_root: String::new(),
        };
        roots.public_record_root = public_record_root(&roots.public_record());
        roots.state_root = state_root_from_record(&json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "roots": roots.public_record(),
        }));
        self.roots = roots;
    }

    pub fn validate(&self) -> PrivateL2ConfidentialDarkpoolCrossMarginRuntimeResult<()> {
        self.config.validate()?;
        let mut seen_nullifiers = BTreeSet::new();
        for account in self.accounts.values() {
            account.validate(&self.config)?;
        }
        for order in self.orders.values() {
            order.validate(&self.config)?;
            require(
                self.accounts.contains_key(&order.account_id),
                "order references missing account",
            )?;
            require(
                self.vaults.contains_key(&order.vault_id),
                "order references missing vault",
            )?;
            require(
                seen_nullifiers.insert(order.nullifier.clone()),
                "duplicate order nullifier",
            )?;
        }
        for attestation in self.risk_attestations.values() {
            require(
                attestation.privacy_set_size >= self.config.min_privacy_set_size,
                "risk privacy set too small",
            )?;
            require(
                attestation.expires_at_height > attestation.issued_at_height,
                "risk ttl invalid",
            )?;
            require(
                attestation.verdict.allows_match() || attestation.order_id.is_none(),
                "rejecting risk attached to matchable order",
            )?;
        }
        for reservation in self.sponsor_reservations.values() {
            require(
                reservation.max_fee_bps <= self.config.max_user_fee_bps,
                "reservation fee exceeds policy",
            )?;
            require(
                reservation.expires_at_height > reservation.reserved_at_height,
                "reservation ttl invalid",
            )?;
        }
        for batch in self.matching_batches.values() {
            require(
                batch.order_ids.len() <= self.config.max_batch_orders,
                "batch too large",
            )?;
            require(
                batch.privacy_set_size >= self.config.min_privacy_set_size,
                "batch privacy set too small",
            )?;
        }
        Ok(())
    }

    fn roots_without_recursive_roots(&self) -> Roots {
        let mut roots = self.roots.clone();
        roots.public_record_root.clear();
        roots.state_root.clear();
        roots
    }
}

pub fn payload_root(payload: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-CROSS-MARGIN-PAYLOAD",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-CROSS-MARGIN-PUBLIC-RECORD",
        record,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-CROSS-MARGIN-STATE",
        record,
    )
}

pub fn deterministic_commitment(kind: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn account_id(owner_commitment: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-ACCOUNT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(owner_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn vault_id(account_id: &str, label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-VAULT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(account_id),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn order_id(account_id: &str, market_id: &str, side: OrderSide, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-ORDER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(account_id),
            HashPart::Str(market_id),
            HashPart::Str(side.as_str()),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn commitment_id(order_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-ORDER-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(order_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn nullifier_id(order_id: &str, account_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-ORDER-NULLIFIER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(order_id),
            HashPart::Str(account_id),
        ],
        32,
    )
}

pub fn risk_attestation_id(
    account_id: &str,
    vault_id: &str,
    order_id: Option<&str>,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-RISK-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(account_id),
            HashPart::Str(vault_id),
            HashPart::Str(order_id.unwrap_or("")),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(
    sponsor_commitment: &str,
    batch_id: Option<&str>,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(batch_id.unwrap_or("")),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn matching_batch_id(solver_commitment: &str, opened_at_height: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-MATCHING-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(solver_commitment),
            HashPart::U64(opened_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn fill_id(
    batch_id: &str,
    maker_order_id: &str,
    taker_order_id: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-FILL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(maker_order_id),
            HashPart::Str(taker_order_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn settlement_receipt_id(batch_id: &str, account_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(account_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn rebate_id(receipt_id: &str, account_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(receipt_id),
            HashPart::Str(account_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn event_id(kind: &str, actor_commitment: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(actor_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn market_config_id(base_asset_id: &str, quote_asset_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-MARKET-CONFIG-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(base_asset_id),
            HashPart::Str(quote_asset_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn privacy_snapshot_id(anonymity_set_root: &str, sampled_at_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-PRIVACY-SNAPSHOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(anonymity_set_root),
            HashPart::U64(sampled_at_height),
        ],
        32,
    )
}

pub fn oracle_price_band_id(market_id: &str, oracle_committee_root: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-ORACLE-PRICE-BAND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(market_id),
            HashPart::Str(oracle_committee_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn liquidity_band_id(market_id: &str, side: OrderSide, sampled_at_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-LIQUIDITY-BAND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(market_id),
            HashPart::Str(side.as_str()),
            HashPart::U64(sampled_at_height),
        ],
        32,
    )
}

pub fn margin_bucket_id(account_id: &str, vault_id: &str, sampled_at_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-MARGIN-BUCKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(account_id),
            HashPart::Str(vault_id),
            HashPart::U64(sampled_at_height),
        ],
        32,
    )
}

pub fn settlement_netting_lane_id(batch_id: &str, lane_label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-SETTLEMENT-NETTING-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(lane_label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn withdrawal_queue_item_id(account_id: &str, vault_id: &str, nullifier: &str) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-WITHDRAWAL-QUEUE-ITEM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(account_id),
            HashPart::Str(vault_id),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

pub fn sponsor_auction_quote_id(sponsor_commitment: &str, lane_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-SPONSOR-AUCTION-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn batch_dispute_id(batch_id: &str, challenger_commitment: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-BATCH-DISPUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(batch_id),
            HashPart::Str(challenger_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn emergency_breaker_id(guardian_committee_root: &str, height: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-EMERGENCY-BREAKER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(guardian_committee_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn telemetry_id(sample_window_root: &str, sampled_at_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-TELEMETRY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(sample_window_root),
            HashPart::U64(sampled_at_height),
        ],
        32,
    )
}

pub fn replay_domain(label: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-DARKPOOL-REPLAY-DOMAIN",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(height),
        ],
        32,
    )
}

fn sample_order(
    order_id_value: &str,
    account_id_value: &str,
    vault_id_value: &str,
    market_id: &str,
    side: OrderSide,
    nullifier_value: String,
    height: u64,
) -> EncryptedDarkpoolOrder {
    EncryptedDarkpoolOrder {
        order_id: order_id_value.to_string(),
        account_id: account_id_value.to_string(),
        vault_id: vault_id_value.to_string(),
        market_id: market_id.to_string(),
        side,
        kind: OrderKind::Limit,
        status: OrderStatus::RiskAttested,
        order_commitment: payload_root(&json!(["order", order_id_value, side.as_str()])),
        nullifier: nullifier_value,
        amount_commitment_root: payload_root(&json!({"amount_bucket": "medium"})),
        price_commitment_root: payload_root(&json!({"price_bucket": "mid"})),
        time_in_force_root: payload_root(&json!({"ttl": DEFAULT_SETTLEMENT_TTL_BLOCKS})),
        encrypted_payload_root: payload_root(
            &json!({"ciphertext": order_id_value, "scheme": ORDER_ENCRYPTION_SCHEME}),
        ),
        threshold_key_root: payload_root(&json!({"committee": "devnet-threshold"})),
        pq_auth_root: payload_root(&json!({"scheme": PQ_AUTH_SCHEME, "subject": order_id_value})),
        risk_hint_root: payload_root(&json!({"risk": "healthy"})),
        fee_commitment_root: payload_root(&json!({"max_fee_bps": DEFAULT_MAX_USER_FEE_BPS})),
        max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
        privacy_set_size: 65_536,
        submitted_at_height: height,
        expires_at_height: height + DEFAULT_SETTLEMENT_TTL_BLOCKS,
    }
}

fn sample_risk(
    attestation_id_value: &str,
    account_id_value: &str,
    vault_id_value: &str,
    order_id_value: Option<String>,
    verdict: RiskVerdict,
    height: u64,
) -> RiskAttestation {
    RiskAttestation {
        attestation_id: attestation_id_value.to_string(),
        account_id: account_id_value.to_string(),
        vault_id: vault_id_value.to_string(),
        order_id: order_id_value,
        attester_commitment: deterministic_commitment("risk-attester", "devnet-committee-0"),
        verdict,
        margin_mode: MarginMode::Cross,
        collateral_root: payload_root(&json!({"collateral_bucket": "sufficient"})),
        exposure_root: payload_root(&json!({"exposure_bucket": "balanced"})),
        stress_vector_root: payload_root(&json!({"stress": ["xmr-down-20", "dusd-depeg-2"]})),
        oracle_snapshot_root: payload_root(&json!({"oracle": "devnet-private-twap"})),
        health_factor_root: payload_root(&json!({"hf": "gt-2"})),
        pq_signature_root: payload_root(&json!({"signature": "aggregate-pq-devnet"})),
        privacy_set_size: 65_536,
        issued_at_height: height,
        expires_at_height: height + DEFAULT_SETTLEMENT_TTL_BLOCKS,
    }
}

fn sample_receipt(
    receipt_id_value: &str,
    batch_id_value: &str,
    account_id_value: &str,
    vault_id_value: &str,
    fill_id_value: &str,
    height: u64,
) -> SettlementReceipt {
    SettlementReceipt {
        receipt_id: receipt_id_value.to_string(),
        batch_id: batch_id_value.to_string(),
        account_id: account_id_value.to_string(),
        vault_id: vault_id_value.to_string(),
        fill_root: payload_root(&json!([fill_id_value])),
        debit_note_root: payload_root(&json!({"debit": "confidential"})),
        credit_note_root: payload_root(&json!({"credit": "confidential"})),
        fee_paid_root: payload_root(&json!({"fee": "sponsored-low"})),
        rebate_root: payload_root(&json!({"rebate": "pending"})),
        post_margin_root: payload_root(&json!({"post_margin": "healthy"})),
        settlement_proof_root: payload_root(&json!({"recursive_proof": batch_id_value})),
        settled_at_height: height,
    }
}

fn merkle_records(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn id_list_root(domain: &str, ids: &[String]) -> String {
    let records = ids.iter().map(|id| json!({"id": id})).collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn require(
    condition: bool,
    message: &str,
) -> PrivateL2ConfidentialDarkpoolCrossMarginRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
