use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-perps-funding-rate-clearing-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_PQ_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-perps-clearing-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEVNET_HEIGHT: u64 =
    940_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_MAX_FUNDING_RATE_BPS: i64 =
    375;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_MARKETS:
    usize = 65_536;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_ACCOUNTS:
    usize = 2_097_152;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_POSITIONS:
    usize = 8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_OBSERVATIONS:
    usize = 4_194_304;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_ATTESTATIONS:
    usize = 2_097_152;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_BATCHES:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_RECEIPTS:
    usize = 4_194_304;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_GUARDS: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_REBATES:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_QUARANTINES:
    usize = 524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MIN_PRIVACY_SET:
    u64 = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_BATCH_PRIVACY_SET:
    u64 = 1_024;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MIN_PQ_BITS: u16 =
    256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_STALENESS:
    u64 = 40;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_REDACTION_BUDGET:
    u64 = 12;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_LOW_FEE_REBATE_BPS:
    u64 = 18;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PerpsMarketKind {
    XmrUsd,
    BtcUsd,
    EthUsd,
    XmrBtc,
    PrivateBasket,
    PrivateRate,
    PrivateVolatility,
    PrivateCommodity,
}

impl PerpsMarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::XmrUsd => "xmr_usd",
            Self::BtcUsd => "btc_usd",
            Self::EthUsd => "eth_usd",
            Self::XmrBtc => "xmr_btc",
            Self::PrivateBasket => "private_basket",
            Self::PrivateRate => "private_rate",
            Self::PrivateVolatility => "private_volatility",
            Self::PrivateCommodity => "private_commodity",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Proposed,
    Active,
    FundingPaused,
    ReduceOnly,
    Quarantined,
    Settled,
}

impl MarketStatus {
    pub fn accepts_funding(self) -> bool {
        matches!(self, Self::Active | Self::ReduceOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    Long,
    Short,
    Flat,
}

impl PositionSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Long => "long",
            Self::Short => "short",
            Self::Flat => "flat",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    Open,
    FundingQueued,
    FundingSettled,
    ReduceOnly,
    LiquidationGuarded,
    Closed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Sealed,
    Attested,
    UsedInClearing,
    Stale,
    Quarantined,
    Disputed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingVerdict {
    Accept,
    ClampFunding,
    GuardBand,
    QuarantineOracle,
    PauseMarket,
}

impl ClearingVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::ClampFunding => "clamp_funding",
            Self::GuardBand => "guard_band",
            Self::QuarantineOracle => "quarantine_oracle",
            Self::PauseMarket => "pause_market",
        }
    }

    pub fn allows_settlement(self) -> bool {
        matches!(self, Self::Accept | Self::ClampFunding | Self::GuardBand)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingBatchStatus {
    Proposed,
    Attested,
    Settling,
    Settled,
    Quarantined,
    Disputed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    MarketRegistered,
    AccountCommitted,
    PositionCommitted,
    FundingObservationSealed,
    ClearingAttested,
    FundingBatchBuilt,
    FundingSettled,
    LiquidationGuardPublished,
    LowFeeRebatePublished,
    OracleQuarantined,
}

impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MarketRegistered => "market_registered",
            Self::AccountCommitted => "account_committed",
            Self::PositionCommitted => "position_committed",
            Self::FundingObservationSealed => "funding_observation_sealed",
            Self::ClearingAttested => "clearing_attested",
            Self::FundingBatchBuilt => "funding_batch_built",
            Self::FundingSettled => "funding_settled",
            Self::LiquidationGuardPublished => "liquidation_guard_published",
            Self::LowFeeRebatePublished => "low_fee_rebate_published",
            Self::OracleQuarantined => "oracle_quarantined",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_suite: String,
    pub max_markets: usize,
    pub max_accounts: usize,
    pub max_positions: usize,
    pub max_observations: usize,
    pub max_attestations: usize,
    pub max_clearing_batches: usize,
    pub max_settlement_receipts: usize,
    pub max_liquidation_guards: usize,
    pub max_low_fee_rebates: usize,
    pub max_oracle_quarantines: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_oracle_staleness_blocks: u64,
    pub max_funding_rate_bps: i64,
    pub low_fee_rebate_bps: u64,
    pub default_redaction_budget: u64,
    pub devnet_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            schema_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_HASH_SUITE
                    .to_string(),
            pq_suite: PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_PQ_SUITE
                .to_string(),
            max_markets:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_MARKETS,
            max_accounts:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_ACCOUNTS,
            max_positions:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_POSITIONS,
            max_observations:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_OBSERVATIONS,
            max_attestations:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_clearing_batches:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_BATCHES,
            max_settlement_receipts:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_liquidation_guards:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_GUARDS,
            max_low_fee_rebates:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_REBATES,
            max_oracle_quarantines:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_QUARANTINES,
            min_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MIN_PQ_BITS,
            max_oracle_staleness_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_MAX_STALENESS,
            max_funding_rate_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_MAX_FUNDING_RATE_BPS,
            low_fee_rebate_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_LOW_FEE_REBATE_BPS,
            default_redaction_budget:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEFAULT_REDACTION_BUDGET,
            devnet_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_DEVNET_HEIGHT,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "max_markets": self.max_markets,
            "max_accounts": self.max_accounts,
            "max_positions": self.max_positions,
            "max_observations": self.max_observations,
            "max_attestations": self.max_attestations,
            "max_clearing_batches": self.max_clearing_batches,
            "max_settlement_receipts": self.max_settlement_receipts,
            "max_liquidation_guards": self.max_liquidation_guards,
            "max_low_fee_rebates": self.max_low_fee_rebates,
            "max_oracle_quarantines": self.max_oracle_quarantines,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_oracle_staleness_blocks": self.max_oracle_staleness_blocks,
            "max_funding_rate_bps": self.max_funding_rate_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "default_redaction_budget": self.default_redaction_budget,
            "devnet_height": self.devnet_height,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub market_counter: u64,
    pub account_counter: u64,
    pub position_counter: u64,
    pub observation_counter: u64,
    pub attestation_counter: u64,
    pub clearing_batch_counter: u64,
    pub settlement_receipt_counter: u64,
    pub liquidation_guard_counter: u64,
    pub low_fee_rebate_counter: u64,
    pub oracle_quarantine_counter: u64,
    pub consumed_nullifier_counter: u64,
    pub event_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "market_counter": self.market_counter,
            "account_counter": self.account_counter,
            "position_counter": self.position_counter,
            "observation_counter": self.observation_counter,
            "attestation_counter": self.attestation_counter,
            "clearing_batch_counter": self.clearing_batch_counter,
            "settlement_receipt_counter": self.settlement_receipt_counter,
            "liquidation_guard_counter": self.liquidation_guard_counter,
            "low_fee_rebate_counter": self.low_fee_rebate_counter,
            "oracle_quarantine_counter": self.oracle_quarantine_counter,
            "consumed_nullifier_counter": self.consumed_nullifier_counter,
            "event_counter": self.event_counter,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub market_root: String,
    pub account_root: String,
    pub position_root: String,
    pub funding_observation_root: String,
    pub clearing_attestation_root: String,
    pub clearing_batch_root: String,
    pub settlement_receipt_root: String,
    pub liquidation_guard_root: String,
    pub low_fee_rebate_root: String,
    pub oracle_quarantine_root: String,
    pub consumed_nullifier_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "market_root": self.market_root,
            "account_root": self.account_root,
            "position_root": self.position_root,
            "funding_observation_root": self.funding_observation_root,
            "clearing_attestation_root": self.clearing_attestation_root,
            "clearing_batch_root": self.clearing_batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "liquidation_guard_root": self.liquidation_guard_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "oracle_quarantine_root": self.oracle_quarantine_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "event_root": self.event_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterPerpsMarketRequest {
    pub market_kind: PerpsMarketKind,
    pub quote_asset: String,
    pub base_asset_commitment: String,
    pub market_operator_commitment: String,
    pub funding_curve_root: String,
    pub margin_rules_root: String,
    pub oracle_set_root: String,
    pub max_leverage_bps: u64,
    pub maintenance_margin_bps: u64,
    pub maker_fee_bps: u64,
    pub taker_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub market_nonce: String,
    pub opened_at_height: u64,
}

impl RegisterPerpsMarketRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("perps market request serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PerpsMarketRecord {
    pub market_id: String,
    pub request: RegisterPerpsMarketRequest,
    pub status: MarketStatus,
    pub cumulative_funding_bps: i64,
    pub last_funding_height: u64,
    pub redaction_budget_remaining: u64,
}

impl PerpsMarketRecord {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("perps market record serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitCrossMarginAccountRequest {
    pub owner_commitment: String,
    pub account_note_root: String,
    pub collateral_commitment_root: String,
    pub cross_margin_policy_root: String,
    pub viewing_key_commitment: String,
    pub account_nullifier: String,
    pub redaction_budget: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub account_nonce: String,
    pub committed_at_height: u64,
}

impl CommitCrossMarginAccountRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("cross-margin account request serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrossMarginAccountRecord {
    pub account_id: String,
    pub request: CommitCrossMarginAccountRequest,
    pub active_position_count: u64,
    pub cumulative_rebate_bps: u64,
    pub redaction_budget_remaining: u64,
}

impl CrossMarginAccountRecord {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("cross-margin account record serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitPerpsPositionRequest {
    pub market_id: String,
    pub account_id: String,
    pub side: PositionSide,
    pub position_commitment: String,
    pub size_commitment: String,
    pub entry_price_commitment: String,
    pub margin_commitment_root: String,
    pub leverage_bps: u64,
    pub position_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub position_nonce: String,
    pub committed_at_height: u64,
}

impl CommitPerpsPositionRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("perps position request serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PerpsPositionRecord {
    pub position_id: String,
    pub request: CommitPerpsPositionRequest,
    pub status: PositionStatus,
    pub funding_cursor_height: u64,
    pub last_settlement_receipt_id: Option<String>,
}

impl PerpsPositionRecord {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("perps position record serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealFundingObservationRequest {
    pub market_id: String,
    pub oracle_committee_root: String,
    pub sealed_mark_price_root: String,
    pub sealed_index_price_root: String,
    pub premium_sample_root: String,
    pub funding_rate_bps: i64,
    pub observation_window_start: u64,
    pub observation_window_end: u64,
    pub observed_at_height: u64,
    pub oracle_epoch: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub observation_nullifier: String,
    pub observation_nonce: String,
}

impl SealFundingObservationRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("funding observation request serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FundingObservationRecord {
    pub observation_id: String,
    pub request: SealFundingObservationRequest,
    pub status: ObservationStatus,
    pub age_at_last_check: u64,
}

impl FundingObservationRecord {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("funding observation record serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttestPqClearingRequest {
    pub market_id: String,
    pub observation_id: String,
    pub clearing_committee_root: String,
    pub pq_signature_root: String,
    pub recursive_proof_root: String,
    pub verdict: ClearingVerdict,
    pub clamped_funding_rate_bps: i64,
    pub guard_band_bps: u64,
    pub oracle_latency_blocks: u64,
    pub stale_after_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attestation_nullifier: String,
    pub attestation_nonce: String,
    pub attested_at_height: u64,
}

impl AttestPqClearingRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("PQ clearing request serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqClearingAttestationRecord {
    pub attestation_id: String,
    pub request: AttestPqClearingRequest,
    pub accepted_for_settlement: bool,
}

impl PqClearingAttestationRecord {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("PQ clearing attestation record serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildFundingClearingBatchRequest {
    pub market_id: String,
    pub observation_id: String,
    pub attestation_id: String,
    pub position_ids: Vec<String>,
    pub account_ids: Vec<String>,
    pub funding_delta_root: String,
    pub cross_margin_delta_root: String,
    pub fee_commitment_root: String,
    pub rebate_eligibility_root: String,
    pub batch_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub batch_nonce: String,
    pub built_at_height: u64,
}

impl BuildFundingClearingBatchRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("funding clearing batch request serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FundingClearingBatchRecord {
    pub batch_id: String,
    pub request: BuildFundingClearingBatchRequest,
    pub status: ClearingBatchStatus,
    pub settled_receipt_count: u64,
}

impl FundingClearingBatchRecord {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("funding clearing batch record serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishFundingSettlementReceiptRequest {
    pub batch_id: String,
    pub market_id: String,
    pub account_id: String,
    pub position_id: String,
    pub settlement_note_root: String,
    pub funding_payment_commitment: String,
    pub post_margin_commitment_root: String,
    pub receipt_nullifier: String,
    pub receipt_kind: ReceiptKind,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub receipt_nonce: String,
    pub settled_at_height: u64,
}

impl PublishFundingSettlementReceiptRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("funding settlement receipt request serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FundingSettlementReceiptRecord {
    pub receipt_id: String,
    pub request: PublishFundingSettlementReceiptRequest,
    pub public_payload_root: String,
}

impl FundingSettlementReceiptRecord {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("funding settlement receipt record serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishLiquidationGuardBandRequest {
    pub market_id: String,
    pub account_id: String,
    pub position_id: String,
    pub attestation_id: String,
    pub guard_band_bps: u64,
    pub guarded_margin_root: String,
    pub liquidation_price_commitment: String,
    pub grace_window_start: u64,
    pub grace_window_end: u64,
    pub guard_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub guard_nonce: String,
    pub published_at_height: u64,
}

impl PublishLiquidationGuardBandRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("liquidation guard request serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidationGuardBandRecord {
    pub guard_id: String,
    pub request: PublishLiquidationGuardBandRequest,
    pub active: bool,
}

impl LiquidationGuardBandRecord {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("liquidation guard record serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishLowFeeRebateRequest {
    pub account_id: String,
    pub batch_id: String,
    pub sponsor_commitment: String,
    pub rebate_commitment_root: String,
    pub fee_payment_root: String,
    pub rebate_bps: u64,
    pub rebate_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub rebate_nonce: String,
    pub published_at_height: u64,
}

impl PublishLowFeeRebateRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("low-fee rebate request serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebateRecord {
    pub rebate_id: String,
    pub request: PublishLowFeeRebateRequest,
    pub credited: bool,
}

impl LowFeeRebateRecord {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("low-fee rebate record serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineStaleOracleRequest {
    pub market_id: String,
    pub observation_id: String,
    pub attestation_id: Option<String>,
    pub oracle_committee_root: String,
    pub stale_reason_root: String,
    pub last_valid_height: u64,
    pub quarantined_at_height: u64,
    pub quarantine_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub quarantine_nonce: String,
}

impl QuarantineStaleOracleRequest {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("stale oracle quarantine request serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StaleOracleQuarantineRecord {
    pub quarantine_id: String,
    pub request: QuarantineStaleOracleRequest,
    pub market_status_after: MarketStatus,
}

impl StaleOracleQuarantineRecord {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("stale oracle quarantine record serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DevnetFixtureRecord {
    pub fixture_id: String,
    pub label: String,
    pub market_ids: Vec<String>,
    pub account_ids: Vec<String>,
    pub position_ids: Vec<String>,
    pub root_summary: String,
}

impl DevnetFixtureRecord {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("devnet fixture record serialization")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub markets: BTreeMap<String, PerpsMarketRecord>,
    pub accounts: BTreeMap<String, CrossMarginAccountRecord>,
    pub positions: BTreeMap<String, PerpsPositionRecord>,
    pub funding_observations: BTreeMap<String, FundingObservationRecord>,
    pub clearing_attestations: BTreeMap<String, PqClearingAttestationRecord>,
    pub clearing_batches: BTreeMap<String, FundingClearingBatchRecord>,
    pub settlement_receipts: BTreeMap<String, FundingSettlementReceiptRecord>,
    pub liquidation_guards: BTreeMap<String, LiquidationGuardBandRecord>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebateRecord>,
    pub oracle_quarantines: BTreeMap<String, StaleOracleQuarantineRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub events: Vec<Value>,
    pub devnet_fixtures: BTreeMap<String, DevnetFixtureRecord>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            markets: BTreeMap::new(),
            accounts: BTreeMap::new(),
            positions: BTreeMap::new(),
            funding_observations: BTreeMap::new(),
            clearing_attestations: BTreeMap::new(),
            clearing_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            liquidation_guards: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            oracle_quarantines: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            events: Vec::new(),
            devnet_fixtures: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let market = state
            .register_market(RegisterPerpsMarketRequest {
                market_kind: PerpsMarketKind::XmrUsd,
                quote_asset: "pUSD".to_string(),
                base_asset_commitment: demo_root("base-xmr"),
                market_operator_commitment: demo_root("operator-xmr-perps"),
                funding_curve_root: demo_root("funding-curve-xmr-usd"),
                margin_rules_root: demo_root("margin-rules-xmr-usd"),
                oracle_set_root: demo_root("oracle-set-xmr-usd"),
                max_leverage_bps: 500_000,
                maintenance_margin_bps: 625,
                maker_fee_bps: 2,
                taker_fee_bps: 5,
                privacy_set_size: 2_048,
                pq_security_bits: 256,
                market_nonce: "demo-market-xmr-usd".to_string(),
                opened_at_height: state.config.devnet_height,
            })
            .expect("demo market");
        let account = state
            .commit_account(CommitCrossMarginAccountRequest {
                owner_commitment: demo_root("owner-alice"),
                account_note_root: demo_root("account-note-alice"),
                collateral_commitment_root: demo_root("collateral-alice"),
                cross_margin_policy_root: demo_root("cross-margin-policy-alice"),
                viewing_key_commitment: demo_root("viewing-key-alice"),
                account_nullifier: demo_root("account-nullifier-alice"),
                redaction_budget: 10,
                privacy_set_size: 2_048,
                pq_security_bits: 256,
                account_nonce: "demo-account-alice".to_string(),
                committed_at_height: state.config.devnet_height + 1,
            })
            .expect("demo account");
        let position = state
            .commit_position(CommitPerpsPositionRequest {
                market_id: market.market_id.clone(),
                account_id: account.account_id.clone(),
                side: PositionSide::Long,
                position_commitment: demo_root("position-alice-long-xmr"),
                size_commitment: demo_root("position-size-alice"),
                entry_price_commitment: demo_root("entry-price-alice"),
                margin_commitment_root: demo_root("margin-position-alice"),
                leverage_bps: 150_000,
                position_nullifier: demo_root("position-nullifier-alice"),
                privacy_set_size: 2_048,
                pq_security_bits: 256,
                position_nonce: "demo-position-alice".to_string(),
                committed_at_height: state.config.devnet_height + 2,
            })
            .expect("demo position");
        let observation = state
            .seal_funding_observation(SealFundingObservationRequest {
                market_id: market.market_id.clone(),
                oracle_committee_root: demo_root("oracle-committee-epoch-1"),
                sealed_mark_price_root: demo_root("sealed-mark-xmr-usd-1"),
                sealed_index_price_root: demo_root("sealed-index-xmr-usd-1"),
                premium_sample_root: demo_root("premium-sample-xmr-usd-1"),
                funding_rate_bps: 7,
                observation_window_start: state.config.devnet_height,
                observation_window_end: state.config.devnet_height + 20,
                observed_at_height: state.config.devnet_height + 21,
                oracle_epoch: 1,
                privacy_set_size: 2_048,
                pq_security_bits: 256,
                observation_nullifier: demo_root("observation-nullifier-1"),
                observation_nonce: "demo-observation-1".to_string(),
            })
            .expect("demo observation");
        let attestation = state
            .attest_pq_clearing(AttestPqClearingRequest {
                market_id: market.market_id.clone(),
                observation_id: observation.observation_id.clone(),
                clearing_committee_root: demo_root("clearing-committee-1"),
                pq_signature_root: demo_root("pq-signatures-1"),
                recursive_proof_root: demo_root("recursive-proof-1"),
                verdict: ClearingVerdict::Accept,
                clamped_funding_rate_bps: 7,
                guard_band_bps: 35,
                oracle_latency_blocks: 1,
                stale_after_height: state.config.devnet_height + 61,
                privacy_set_size: 2_048,
                pq_security_bits: 256,
                attestation_nullifier: demo_root("attestation-nullifier-1"),
                attestation_nonce: "demo-attestation-1".to_string(),
                attested_at_height: state.config.devnet_height + 22,
            })
            .expect("demo attestation");
        let batch = state
            .build_funding_clearing_batch(BuildFundingClearingBatchRequest {
                market_id: market.market_id.clone(),
                observation_id: observation.observation_id.clone(),
                attestation_id: attestation.attestation_id.clone(),
                position_ids: vec![position.position_id.clone()],
                account_ids: vec![account.account_id.clone()],
                funding_delta_root: demo_root("funding-delta-batch-1"),
                cross_margin_delta_root: demo_root("cross-margin-delta-batch-1"),
                fee_commitment_root: demo_root("fee-commitment-batch-1"),
                rebate_eligibility_root: demo_root("rebate-eligibility-batch-1"),
                batch_nullifier: demo_root("batch-nullifier-1"),
                privacy_set_size: 2_048,
                pq_security_bits: 256,
                batch_nonce: "demo-batch-1".to_string(),
                built_at_height: state.config.devnet_height + 23,
            })
            .expect("demo batch");
        state
            .publish_settlement_receipt(PublishFundingSettlementReceiptRequest {
                batch_id: batch.batch_id.clone(),
                market_id: market.market_id.clone(),
                account_id: account.account_id.clone(),
                position_id: position.position_id.clone(),
                settlement_note_root: demo_root("settlement-note-1"),
                funding_payment_commitment: demo_root("funding-payment-1"),
                post_margin_commitment_root: demo_root("post-margin-1"),
                receipt_nullifier: demo_root("receipt-nullifier-1"),
                receipt_kind: ReceiptKind::FundingSettled,
                privacy_set_size: 2_048,
                pq_security_bits: 256,
                receipt_nonce: "demo-receipt-1".to_string(),
                settled_at_height: state.config.devnet_height + 24,
            })
            .expect("demo settlement receipt");
        state
            .publish_liquidation_guard(PublishLiquidationGuardBandRequest {
                market_id: market.market_id.clone(),
                account_id: account.account_id.clone(),
                position_id: position.position_id.clone(),
                attestation_id: attestation.attestation_id.clone(),
                guard_band_bps: 35,
                guarded_margin_root: demo_root("guarded-margin-1"),
                liquidation_price_commitment: demo_root("liquidation-price-1"),
                grace_window_start: state.config.devnet_height + 24,
                grace_window_end: state.config.devnet_height + 54,
                guard_nullifier: demo_root("guard-nullifier-1"),
                privacy_set_size: 2_048,
                pq_security_bits: 256,
                guard_nonce: "demo-guard-1".to_string(),
                published_at_height: state.config.devnet_height + 24,
            })
            .expect("demo guard");
        state
            .publish_low_fee_rebate(PublishLowFeeRebateRequest {
                account_id: account.account_id.clone(),
                batch_id: batch.batch_id.clone(),
                sponsor_commitment: demo_root("rebate-sponsor-1"),
                rebate_commitment_root: demo_root("rebate-commitment-1"),
                fee_payment_root: demo_root("fee-payment-1"),
                rebate_bps: state.config.low_fee_rebate_bps,
                rebate_nullifier: demo_root("rebate-nullifier-1"),
                privacy_set_size: 2_048,
                pq_security_bits: 256,
                rebate_nonce: "demo-rebate-1".to_string(),
                published_at_height: state.config.devnet_height + 25,
            })
            .expect("demo rebate");
        let fixture = DevnetFixtureRecord {
            fixture_id: demo_root("fixture-confidential-perps"),
            label: "confidential-perps-funding-rate-clearing-demo".to_string(),
            market_ids: vec![market.market_id],
            account_ids: vec![account.account_id],
            position_ids: vec![position.position_id],
            root_summary: state.state_root(),
        };
        state
            .devnet_fixtures
            .insert(fixture.fixture_id.clone(), fixture);
        state
    }

    pub fn register_market(
        &mut self,
        request: RegisterPerpsMarketRequest,
    ) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<PerpsMarketRecord> {
        require_capacity("markets", self.markets.len(), self.config.max_markets)?;
        require_non_empty("quote_asset", &request.quote_asset)?;
        require_root("base_asset_commitment", &request.base_asset_commitment)?;
        require_root(
            "market_operator_commitment",
            &request.market_operator_commitment,
        )?;
        require_root("funding_curve_root", &request.funding_curve_root)?;
        require_root("margin_rules_root", &request.margin_rules_root)?;
        require_root("oracle_set_root", &request.oracle_set_root)?;
        require_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        require_bps("maintenance_margin_bps", request.maintenance_margin_bps)?;
        require_bps("maker_fee_bps", request.maker_fee_bps)?;
        require_bps("taker_fee_bps", request.taker_fee_bps)?;
        require_positive_u64("max_leverage_bps", request.max_leverage_bps)?;
        let sequence = self.counters.market_counter.saturating_add(1);
        let market_id = perps_market_id(&request, sequence);
        let record = PerpsMarketRecord {
            market_id: market_id.clone(),
            request,
            status: MarketStatus::Active,
            cumulative_funding_bps: 0,
            last_funding_height: 0,
            redaction_budget_remaining: self.config.default_redaction_budget,
        };
        self.counters.market_counter = sequence;
        self.markets.insert(market_id.clone(), record.clone());
        self.push_event(
            ReceiptKind::MarketRegistered,
            &market_id,
            &record.public_record(),
            record.request.opened_at_height,
        );
        Ok(record)
    }

    pub fn commit_account(
        &mut self,
        request: CommitCrossMarginAccountRequest,
    ) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<CrossMarginAccountRecord>
    {
        require_capacity("accounts", self.accounts.len(), self.config.max_accounts)?;
        self.ensure_new_nullifier(&request.account_nullifier)?;
        require_root("owner_commitment", &request.owner_commitment)?;
        require_root("account_note_root", &request.account_note_root)?;
        require_root(
            "collateral_commitment_root",
            &request.collateral_commitment_root,
        )?;
        require_root(
            "cross_margin_policy_root",
            &request.cross_margin_policy_root,
        )?;
        require_root("viewing_key_commitment", &request.viewing_key_commitment)?;
        require_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let sequence = self.counters.account_counter.saturating_add(1);
        let account_id = cross_margin_account_id(&request, sequence);
        self.consume_nullifier(request.account_nullifier.clone());
        let record = CrossMarginAccountRecord {
            account_id: account_id.clone(),
            redaction_budget_remaining: request.redaction_budget,
            request,
            active_position_count: 0,
            cumulative_rebate_bps: 0,
        };
        self.counters.account_counter = sequence;
        self.accounts.insert(account_id.clone(), record.clone());
        self.push_event(
            ReceiptKind::AccountCommitted,
            &account_id,
            &record.public_record(),
            record.request.committed_at_height,
        );
        Ok(record)
    }

    pub fn commit_position(
        &mut self,
        request: CommitPerpsPositionRequest,
    ) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<PerpsPositionRecord> {
        require_capacity("positions", self.positions.len(), self.config.max_positions)?;
        let market = self.require_market(&request.market_id)?;
        if !market.status.accepts_funding() {
            return Err(format!(
                "perps market {} does not accept funding",
                request.market_id
            ));
        }
        self.require_account(&request.account_id)?;
        self.ensure_new_nullifier(&request.position_nullifier)?;
        require_root("position_commitment", &request.position_commitment)?;
        require_root("size_commitment", &request.size_commitment)?;
        require_root("entry_price_commitment", &request.entry_price_commitment)?;
        require_root("margin_commitment_root", &request.margin_commitment_root)?;
        require_positive_u64("leverage_bps", request.leverage_bps)?;
        require_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let sequence = self.counters.position_counter.saturating_add(1);
        let position_id = perps_position_id(&request, sequence);
        self.consume_nullifier(request.position_nullifier.clone());
        let record = PerpsPositionRecord {
            position_id: position_id.clone(),
            funding_cursor_height: request.committed_at_height,
            request,
            status: PositionStatus::Open,
            last_settlement_receipt_id: None,
        };
        if let Some(account) = self.accounts.get_mut(&record.request.account_id) {
            account.active_position_count = account.active_position_count.saturating_add(1);
        }
        self.counters.position_counter = sequence;
        self.positions.insert(position_id.clone(), record.clone());
        self.push_event(
            ReceiptKind::PositionCommitted,
            &position_id,
            &record.public_record(),
            record.request.committed_at_height,
        );
        Ok(record)
    }

    pub fn seal_funding_observation(
        &mut self,
        request: SealFundingObservationRequest,
    ) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<FundingObservationRecord>
    {
        require_capacity(
            "funding_observations",
            self.funding_observations.len(),
            self.config.max_observations,
        )?;
        self.require_market(&request.market_id)?;
        self.ensure_new_nullifier(&request.observation_nullifier)?;
        require_window(
            "funding observation",
            request.observation_window_start,
            request.observation_window_end,
        )?;
        require_funding_rate(request.funding_rate_bps, self.config.max_funding_rate_bps)?;
        require_root("oracle_committee_root", &request.oracle_committee_root)?;
        require_root("sealed_mark_price_root", &request.sealed_mark_price_root)?;
        require_root("sealed_index_price_root", &request.sealed_index_price_root)?;
        require_root("premium_sample_root", &request.premium_sample_root)?;
        require_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let sequence = self.counters.observation_counter.saturating_add(1);
        let observation_id = funding_observation_id(&request, sequence);
        self.consume_nullifier(request.observation_nullifier.clone());
        let record = FundingObservationRecord {
            observation_id: observation_id.clone(),
            request,
            status: ObservationStatus::Sealed,
            age_at_last_check: 0,
        };
        self.counters.observation_counter = sequence;
        self.funding_observations
            .insert(observation_id.clone(), record.clone());
        self.push_event(
            ReceiptKind::FundingObservationSealed,
            &observation_id,
            &record.public_record(),
            record.request.observed_at_height,
        );
        Ok(record)
    }

    pub fn attest_pq_clearing(
        &mut self,
        request: AttestPqClearingRequest,
    ) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<PqClearingAttestationRecord>
    {
        require_capacity(
            "clearing_attestations",
            self.clearing_attestations.len(),
            self.config.max_attestations,
        )?;
        self.require_market(&request.market_id)?;
        let observation = self.require_observation(&request.observation_id)?;
        if observation.request.market_id != request.market_id {
            return Err("clearing attestation market does not match observation".to_string());
        }
        self.ensure_new_nullifier(&request.attestation_nullifier)?;
        require_root("clearing_committee_root", &request.clearing_committee_root)?;
        require_root("pq_signature_root", &request.pq_signature_root)?;
        require_root("recursive_proof_root", &request.recursive_proof_root)?;
        require_funding_rate(
            request.clamped_funding_rate_bps,
            self.config.max_funding_rate_bps,
        )?;
        require_bps("guard_band_bps", request.guard_band_bps)?;
        require_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let sequence = self.counters.attestation_counter.saturating_add(1);
        let attestation_id = pq_clearing_attestation_id(&request, sequence);
        self.consume_nullifier(request.attestation_nullifier.clone());
        let record = PqClearingAttestationRecord {
            attestation_id: attestation_id.clone(),
            accepted_for_settlement: request.verdict.allows_settlement(),
            request,
        };
        if let Some(observation) = self
            .funding_observations
            .get_mut(&record.request.observation_id)
        {
            observation.status = if record.accepted_for_settlement {
                ObservationStatus::Attested
            } else {
                ObservationStatus::Quarantined
            };
            observation.age_at_last_check = record
                .request
                .attested_at_height
                .saturating_sub(observation.request.observed_at_height);
        }
        if matches!(
            record.request.verdict,
            ClearingVerdict::QuarantineOracle | ClearingVerdict::PauseMarket
        ) {
            if let Some(market) = self.markets.get_mut(&record.request.market_id) {
                market.status = MarketStatus::Quarantined;
            }
        }
        self.counters.attestation_counter = sequence;
        self.clearing_attestations
            .insert(attestation_id.clone(), record.clone());
        self.push_event(
            ReceiptKind::ClearingAttested,
            &attestation_id,
            &record.public_record(),
            record.request.attested_at_height,
        );
        Ok(record)
    }

    pub fn build_funding_clearing_batch(
        &mut self,
        request: BuildFundingClearingBatchRequest,
    ) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<FundingClearingBatchRecord>
    {
        require_capacity(
            "clearing_batches",
            self.clearing_batches.len(),
            self.config.max_clearing_batches,
        )?;
        self.require_market(&request.market_id)?;
        self.require_observation(&request.observation_id)?;
        let attestation = self.require_attestation(&request.attestation_id)?;
        if !attestation.accepted_for_settlement {
            return Err("clearing attestation is not accepted for settlement".to_string());
        }
        for position_id in &request.position_ids {
            self.require_position(position_id)?;
        }
        for account_id in &request.account_ids {
            self.require_account(account_id)?;
        }
        self.ensure_new_nullifier(&request.batch_nullifier)?;
        require_root("funding_delta_root", &request.funding_delta_root)?;
        require_root("cross_margin_delta_root", &request.cross_margin_delta_root)?;
        require_root("fee_commitment_root", &request.fee_commitment_root)?;
        require_root("rebate_eligibility_root", &request.rebate_eligibility_root)?;
        require_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.batch_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let sequence = self.counters.clearing_batch_counter.saturating_add(1);
        let batch_id = funding_clearing_batch_id(&request, sequence);
        self.consume_nullifier(request.batch_nullifier.clone());
        let record = FundingClearingBatchRecord {
            batch_id: batch_id.clone(),
            request,
            status: ClearingBatchStatus::Attested,
            settled_receipt_count: 0,
        };
        for position_id in &record.request.position_ids {
            if let Some(position) = self.positions.get_mut(position_id) {
                position.status = PositionStatus::FundingQueued;
            }
        }
        if let Some(observation) = self
            .funding_observations
            .get_mut(&record.request.observation_id)
        {
            observation.status = ObservationStatus::UsedInClearing;
        }
        self.counters.clearing_batch_counter = sequence;
        self.clearing_batches
            .insert(batch_id.clone(), record.clone());
        self.push_event(
            ReceiptKind::FundingBatchBuilt,
            &batch_id,
            &record.public_record(),
            record.request.built_at_height,
        );
        Ok(record)
    }

    pub fn publish_settlement_receipt(
        &mut self,
        request: PublishFundingSettlementReceiptRequest,
    ) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<FundingSettlementReceiptRecord>
    {
        require_capacity(
            "settlement_receipts",
            self.settlement_receipts.len(),
            self.config.max_settlement_receipts,
        )?;
        self.require_market(&request.market_id)?;
        self.require_account(&request.account_id)?;
        self.require_position(&request.position_id)?;
        self.require_batch(&request.batch_id)?;
        self.ensure_new_nullifier(&request.receipt_nullifier)?;
        require_root("settlement_note_root", &request.settlement_note_root)?;
        require_root(
            "funding_payment_commitment",
            &request.funding_payment_commitment,
        )?;
        require_root(
            "post_margin_commitment_root",
            &request.post_margin_commitment_root,
        )?;
        require_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let sequence = self.counters.settlement_receipt_counter.saturating_add(1);
        let receipt_id = funding_settlement_receipt_id(&request, sequence);
        self.consume_nullifier(request.receipt_nullifier.clone());
        let public_payload_root = payload_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-RECEIPT-PAYLOAD",
            &request.public_record(),
        );
        let record = FundingSettlementReceiptRecord {
            receipt_id: receipt_id.clone(),
            request,
            public_payload_root,
        };
        if let Some(position) = self.positions.get_mut(&record.request.position_id) {
            position.status = PositionStatus::FundingSettled;
            position.funding_cursor_height = record.request.settled_at_height;
            position.last_settlement_receipt_id = Some(receipt_id.clone());
        }
        if let Some(batch) = self.clearing_batches.get_mut(&record.request.batch_id) {
            batch.status = ClearingBatchStatus::Settling;
            batch.settled_receipt_count = batch.settled_receipt_count.saturating_add(1);
        }
        if let Some(market) = self.markets.get_mut(&record.request.market_id) {
            market.last_funding_height = record.request.settled_at_height;
        }
        self.counters.settlement_receipt_counter = sequence;
        self.settlement_receipts
            .insert(receipt_id.clone(), record.clone());
        self.push_event(
            ReceiptKind::FundingSettled,
            &receipt_id,
            &record.public_record(),
            record.request.settled_at_height,
        );
        Ok(record)
    }

    pub fn publish_liquidation_guard(
        &mut self,
        request: PublishLiquidationGuardBandRequest,
    ) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<LiquidationGuardBandRecord>
    {
        require_capacity(
            "liquidation_guards",
            self.liquidation_guards.len(),
            self.config.max_liquidation_guards,
        )?;
        self.require_market(&request.market_id)?;
        self.require_account(&request.account_id)?;
        self.require_position(&request.position_id)?;
        self.require_attestation(&request.attestation_id)?;
        self.ensure_new_nullifier(&request.guard_nullifier)?;
        require_window(
            "liquidation guard",
            request.grace_window_start,
            request.grace_window_end,
        )?;
        require_bps("guard_band_bps", request.guard_band_bps)?;
        require_root("guarded_margin_root", &request.guarded_margin_root)?;
        require_root(
            "liquidation_price_commitment",
            &request.liquidation_price_commitment,
        )?;
        require_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let sequence = self.counters.liquidation_guard_counter.saturating_add(1);
        let guard_id = liquidation_guard_id(&request, sequence);
        self.consume_nullifier(request.guard_nullifier.clone());
        let record = LiquidationGuardBandRecord {
            guard_id: guard_id.clone(),
            request,
            active: true,
        };
        if let Some(position) = self.positions.get_mut(&record.request.position_id) {
            position.status = PositionStatus::LiquidationGuarded;
        }
        self.counters.liquidation_guard_counter = sequence;
        self.liquidation_guards
            .insert(guard_id.clone(), record.clone());
        self.push_event(
            ReceiptKind::LiquidationGuardPublished,
            &guard_id,
            &record.public_record(),
            record.request.published_at_height,
        );
        Ok(record)
    }

    pub fn publish_low_fee_rebate(
        &mut self,
        request: PublishLowFeeRebateRequest,
    ) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<LowFeeRebateRecord> {
        require_capacity(
            "low_fee_rebates",
            self.low_fee_rebates.len(),
            self.config.max_low_fee_rebates,
        )?;
        self.require_account(&request.account_id)?;
        self.require_batch(&request.batch_id)?;
        self.ensure_new_nullifier(&request.rebate_nullifier)?;
        require_bps("rebate_bps", request.rebate_bps)?;
        require_root("sponsor_commitment", &request.sponsor_commitment)?;
        require_root("rebate_commitment_root", &request.rebate_commitment_root)?;
        require_root("fee_payment_root", &request.fee_payment_root)?;
        require_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        let sequence = self.counters.low_fee_rebate_counter.saturating_add(1);
        let rebate_id = low_fee_rebate_id(&request, sequence);
        self.consume_nullifier(request.rebate_nullifier.clone());
        let record = LowFeeRebateRecord {
            rebate_id: rebate_id.clone(),
            request,
            credited: true,
        };
        if let Some(account) = self.accounts.get_mut(&record.request.account_id) {
            account.cumulative_rebate_bps = account
                .cumulative_rebate_bps
                .saturating_add(record.request.rebate_bps);
        }
        self.counters.low_fee_rebate_counter = sequence;
        self.low_fee_rebates
            .insert(rebate_id.clone(), record.clone());
        self.push_event(
            ReceiptKind::LowFeeRebatePublished,
            &rebate_id,
            &record.public_record(),
            record.request.published_at_height,
        );
        Ok(record)
    }

    pub fn quarantine_stale_oracle(
        &mut self,
        request: QuarantineStaleOracleRequest,
    ) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<StaleOracleQuarantineRecord>
    {
        require_capacity(
            "oracle_quarantines",
            self.oracle_quarantines.len(),
            self.config.max_oracle_quarantines,
        )?;
        self.require_market(&request.market_id)?;
        self.require_observation(&request.observation_id)?;
        if let Some(attestation_id) = &request.attestation_id {
            self.require_attestation(attestation_id)?;
        }
        self.ensure_new_nullifier(&request.quarantine_nullifier)?;
        require_root("oracle_committee_root", &request.oracle_committee_root)?;
        require_root("stale_reason_root", &request.stale_reason_root)?;
        require_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        if request
            .quarantined_at_height
            .saturating_sub(request.last_valid_height)
            < self.config.max_oracle_staleness_blocks
        {
            return Err(
                "oracle quarantine is earlier than configured staleness window".to_string(),
            );
        }
        let sequence = self.counters.oracle_quarantine_counter.saturating_add(1);
        let quarantine_id = stale_oracle_quarantine_id(&request, sequence);
        self.consume_nullifier(request.quarantine_nullifier.clone());
        let record = StaleOracleQuarantineRecord {
            quarantine_id: quarantine_id.clone(),
            request,
            market_status_after: MarketStatus::Quarantined,
        };
        if let Some(market) = self.markets.get_mut(&record.request.market_id) {
            market.status = MarketStatus::Quarantined;
        }
        if let Some(observation) = self
            .funding_observations
            .get_mut(&record.request.observation_id)
        {
            observation.status = ObservationStatus::Quarantined;
            observation.age_at_last_check = record
                .request
                .quarantined_at_height
                .saturating_sub(observation.request.observed_at_height);
        }
        self.counters.oracle_quarantine_counter = sequence;
        self.oracle_quarantines
            .insert(quarantine_id.clone(), record.clone());
        self.push_event(
            ReceiptKind::OracleQuarantined,
            &quarantine_id,
            &record.public_record(),
            record.request.quarantined_at_height,
        );
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let market_root = records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-MARKETS",
            self.markets
                .values()
                .map(PerpsMarketRecord::public_record)
                .collect(),
        );
        let account_root = records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-ACCOUNTS",
            self.accounts
                .values()
                .map(CrossMarginAccountRecord::public_record)
                .collect(),
        );
        let position_root = records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-POSITIONS",
            self.positions
                .values()
                .map(PerpsPositionRecord::public_record)
                .collect(),
        );
        let funding_observation_root = records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-FUNDING-OBSERVATIONS",
            self.funding_observations
                .values()
                .map(FundingObservationRecord::public_record)
                .collect(),
        );
        let clearing_attestation_root = records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-CLEARING-ATTESTATIONS",
            self.clearing_attestations
                .values()
                .map(PqClearingAttestationRecord::public_record)
                .collect(),
        );
        let clearing_batch_root = records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-CLEARING-BATCHES",
            self.clearing_batches
                .values()
                .map(FundingClearingBatchRecord::public_record)
                .collect(),
        );
        let settlement_receipt_root = records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-SETTLEMENT-RECEIPTS",
            self.settlement_receipts
                .values()
                .map(FundingSettlementReceiptRecord::public_record)
                .collect(),
        );
        let liquidation_guard_root = records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-LIQUIDATION-GUARDS",
            self.liquidation_guards
                .values()
                .map(LiquidationGuardBandRecord::public_record)
                .collect(),
        );
        let low_fee_rebate_root = records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-LOW-FEE-REBATES",
            self.low_fee_rebates
                .values()
                .map(LowFeeRebateRecord::public_record)
                .collect(),
        );
        let oracle_quarantine_root = records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-ORACLE-QUARANTINES",
            self.oracle_quarantines
                .values()
                .map(StaleOracleQuarantineRecord::public_record)
                .collect(),
        );
        let consumed_nullifier_root = records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-CONSUMED-NULLIFIERS",
            self.consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect(),
        );
        let event_root = records_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-EVENTS",
            self.events.clone(),
        );
        let state_record = json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "counters": self.counters.public_record(),
            "market_root": market_root,
            "account_root": account_root,
            "position_root": position_root,
            "funding_observation_root": funding_observation_root,
            "clearing_attestation_root": clearing_attestation_root,
            "clearing_batch_root": clearing_batch_root,
            "settlement_receipt_root": settlement_receipt_root,
            "liquidation_guard_root": liquidation_guard_root,
            "low_fee_rebate_root": low_fee_rebate_root,
            "oracle_quarantine_root": oracle_quarantine_root,
            "consumed_nullifier_root": consumed_nullifier_root,
            "event_root": event_root,
        });
        let state_root = state_root_from_record(&state_record);
        Roots {
            market_root,
            account_root,
            position_root,
            funding_observation_root,
            clearing_attestation_root,
            clearing_batch_root,
            settlement_receipt_root,
            liquidation_guard_root,
            low_fee_rebate_root,
            oracle_quarantine_root,
            consumed_nullifier_root,
            event_root,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "hash_suite": self.config.hash_suite,
            "pq_suite": self.config.pq_suite,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "market_count": self.markets.len(),
            "account_count": self.accounts.len(),
            "position_count": self.positions.len(),
            "funding_observation_count": self.funding_observations.len(),
            "clearing_attestation_count": self.clearing_attestations.len(),
            "clearing_batch_count": self.clearing_batches.len(),
            "settlement_receipt_count": self.settlement_receipts.len(),
            "liquidation_guard_count": self.liquidation_guards.len(),
            "low_fee_rebate_count": self.low_fee_rebates.len(),
            "oracle_quarantine_count": self.oracle_quarantines.len(),
            "consumed_nullifier_count": self.consumed_nullifiers.len(),
            "devnet_fixture_count": self.devnet_fixtures.len(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn require_market(
        &self,
        market_id: &str,
    ) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<&PerpsMarketRecord> {
        self.markets
            .get(market_id)
            .ok_or_else(|| format!("unknown confidential perps market {market_id}"))
    }

    fn require_account(
        &self,
        account_id: &str,
    ) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<&CrossMarginAccountRecord>
    {
        self.accounts
            .get(account_id)
            .ok_or_else(|| format!("unknown cross-margin account {account_id}"))
    }

    fn require_position(
        &self,
        position_id: &str,
    ) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<&PerpsPositionRecord> {
        self.positions
            .get(position_id)
            .ok_or_else(|| format!("unknown confidential perps position {position_id}"))
    }

    fn require_observation(
        &self,
        observation_id: &str,
    ) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<&FundingObservationRecord>
    {
        self.funding_observations
            .get(observation_id)
            .ok_or_else(|| format!("unknown sealed funding observation {observation_id}"))
    }

    fn require_attestation(
        &self,
        attestation_id: &str,
    ) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<&PqClearingAttestationRecord>
    {
        self.clearing_attestations
            .get(attestation_id)
            .ok_or_else(|| format!("unknown PQ clearing attestation {attestation_id}"))
    }

    fn require_batch(
        &self,
        batch_id: &str,
    ) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<&FundingClearingBatchRecord>
    {
        self.clearing_batches
            .get(batch_id)
            .ok_or_else(|| format!("unknown funding clearing batch {batch_id}"))
    }

    fn ensure_new_nullifier(
        &self,
        nullifier: &str,
    ) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<()> {
        require_root("nullifier", nullifier)?;
        if self.consumed_nullifiers.contains(nullifier) {
            return Err("confidential perps nullifier already consumed".to_string());
        }
        Ok(())
    }

    fn consume_nullifier(&mut self, nullifier: String) {
        if self.consumed_nullifiers.insert(nullifier) {
            self.counters.consumed_nullifier_counter =
                self.counters.consumed_nullifier_counter.saturating_add(1);
        }
    }

    fn push_event(&mut self, kind: ReceiptKind, subject_id: &str, payload: &Value, height: u64) {
        let event_id = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-EVENT-ID",
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
        self.counters.event_counter = self.counters.event_counter.saturating_add(1);
        self.events.push(json!({
            "event_id": event_id,
            "sequence": self.counters.event_counter,
            "kind": kind.as_str(),
            "subject_id": subject_id,
            "payload_root": payload_root("PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-EVENT-PAYLOAD", payload),
            "height": height,
        }));
    }
}

pub type Runtime = State;

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn perps_market_id(request: &RegisterPerpsMarketRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-MARKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(request.market_kind.as_str()),
            HashPart::Str(&request.quote_asset),
            HashPart::Str(&request.base_asset_commitment),
            HashPart::Str(&request.market_operator_commitment),
            HashPart::Str(&request.market_nonce),
            HashPart::Int(request.opened_at_height as i128),
        ],
        32,
    )
}

pub fn cross_margin_account_id(request: &CommitCrossMarginAccountRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-ACCOUNT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.account_note_root),
            HashPart::Str(&request.collateral_commitment_root),
            HashPart::Str(&request.account_nullifier),
            HashPart::Str(&request.account_nonce),
        ],
        32,
    )
}

pub fn perps_position_id(request: &CommitPerpsPositionRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-POSITION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.market_id),
            HashPart::Str(&request.account_id),
            HashPart::Str(request.side.as_str()),
            HashPart::Str(&request.position_commitment),
            HashPart::Str(&request.position_nullifier),
            HashPart::Str(&request.position_nonce),
        ],
        32,
    )
}

pub fn funding_observation_id(request: &SealFundingObservationRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-FUNDING-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.market_id),
            HashPart::Str(&request.oracle_committee_root),
            HashPart::Str(&request.sealed_mark_price_root),
            HashPart::Str(&request.sealed_index_price_root),
            HashPart::Int(request.oracle_epoch as i128),
            HashPart::Str(&request.observation_nullifier),
            HashPart::Str(&request.observation_nonce),
        ],
        32,
    )
}

pub fn pq_clearing_attestation_id(request: &AttestPqClearingRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-CLEARING-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.market_id),
            HashPart::Str(&request.observation_id),
            HashPart::Str(&request.clearing_committee_root),
            HashPart::Str(&request.pq_signature_root),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Str(&request.attestation_nullifier),
            HashPart::Str(&request.attestation_nonce),
        ],
        32,
    )
}

pub fn funding_clearing_batch_id(
    request: &BuildFundingClearingBatchRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-CLEARING-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.market_id),
            HashPart::Str(&request.observation_id),
            HashPart::Str(&request.attestation_id),
            HashPart::Str(&string_list_root("POSITIONS", &request.position_ids)),
            HashPart::Str(&string_list_root("ACCOUNTS", &request.account_ids)),
            HashPart::Str(&request.funding_delta_root),
            HashPart::Str(&request.batch_nullifier),
            HashPart::Str(&request.batch_nonce),
        ],
        32,
    )
}

pub fn funding_settlement_receipt_id(
    request: &PublishFundingSettlementReceiptRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.market_id),
            HashPart::Str(&request.account_id),
            HashPart::Str(&request.position_id),
            HashPart::Str(&request.settlement_note_root),
            HashPart::Str(&request.receipt_nullifier),
            HashPart::Str(&request.receipt_nonce),
        ],
        32,
    )
}

pub fn liquidation_guard_id(request: &PublishLiquidationGuardBandRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-LIQUIDATION-GUARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.market_id),
            HashPart::Str(&request.account_id),
            HashPart::Str(&request.position_id),
            HashPart::Str(&request.attestation_id),
            HashPart::Str(&request.guarded_margin_root),
            HashPart::Str(&request.guard_nullifier),
            HashPart::Str(&request.guard_nonce),
        ],
        32,
    )
}

pub fn low_fee_rebate_id(request: &PublishLowFeeRebateRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-LOW-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.account_id),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.rebate_commitment_root),
            HashPart::Str(&request.rebate_nullifier),
            HashPart::Str(&request.rebate_nonce),
        ],
        32,
    )
}

pub fn stale_oracle_quarantine_id(request: &QuarantineStaleOracleRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-STALE-ORACLE-QUARANTINE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Int(sequence as i128),
            HashPart::Str(&request.market_id),
            HashPart::Str(&request.observation_id),
            HashPart::Str(&request.oracle_committee_root),
            HashPart::Str(&request.stale_reason_root),
            HashPart::Str(&request.quarantine_nullifier),
            HashPart::Str(&request.quarantine_nonce),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-STATE", record)
}

fn records_root(domain: &str, records: Vec<Value>) -> String {
    public_record_root(domain, &records)
}

fn string_list_root(label: &str, values: &[String]) -> String {
    public_record_root(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-{label}-LIST"),
        &values.iter().map(|value| json!(value)).collect::<Vec<_>>(),
    )
}

fn demo_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-PERPS-DEMO-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(label),
        ],
        32,
    )
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("confidential perps {label} is required"));
    }
    Ok(())
}

fn require_root(
    label: &str,
    value: &str,
) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<()> {
    require_non_empty(label, value)?;
    if value.len() < 16 {
        return Err(format!("confidential perps {label} must look like a root"));
    }
    Ok(())
}

fn require_positive_u64(
    label: &str,
    value: u64,
) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<()> {
    if value == 0 {
        return Err(format!("confidential perps {label} must be positive"));
    }
    Ok(())
}

fn require_bps(
    label: &str,
    value: u64,
) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<()> {
    if value > PRIVATE_L2_PQ_CONFIDENTIAL_PERPS_FUNDING_RATE_CLEARING_RUNTIME_MAX_BPS {
        return Err(format!("confidential perps {label} exceeds max bps"));
    }
    Ok(())
}

fn require_funding_rate(
    value: i64,
    max_abs_bps: i64,
) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<()> {
    if value.abs() > max_abs_bps {
        return Err("confidential perps funding rate exceeds clamp".to_string());
    }
    Ok(())
}

fn require_window(
    label: &str,
    start: u64,
    end: u64,
) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<()> {
    if end <= start {
        return Err(format!("confidential perps {label} window is invalid"));
    }
    Ok(())
}

fn require_capacity(
    label: &str,
    current: usize,
    max: usize,
) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<()> {
    if current >= max {
        return Err(format!("confidential perps {label} capacity exceeded"));
    }
    Ok(())
}

fn require_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2PqConfidentialPerpsFundingRateClearingRuntimeResult<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("confidential perps privacy set is below minimum".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err("confidential perps PQ security bits are below minimum".to_string());
    }
    Ok(())
}
