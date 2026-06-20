use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedExitFeeRebateOptionsAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_EXIT_FEE_REBATE_OPTIONS_AMM_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-exit-fee-rebate-options-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_EXIT_FEE_REBATE_OPTIONS_AMM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SETTLEMENT_COUPON_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-exit-fee-rebate-options-coupon-v1";
pub const CONFIDENTIAL_OPTION_SERIES_SUITE: &str =
    "confidential-tokenized-exit-fee-rebate-options-series-root-v1";
pub const EXIT_FEE_POOL_SUITE: &str = "confidential-tokenized-exit-fee-rebate-options-pool-root-v1";
pub const COLLATERAL_ACCOUNT_SUITE: &str =
    "confidential-tokenized-exit-fee-rebate-options-collateral-account-root-v1";
pub const SETTLEMENT_COUPON_ROOT_SUITE: &str =
    "pq-signed-exit-fee-rebate-options-settlement-coupon-root-v1";
pub const LOW_FEE_NETTING_SUITE: &str = "low-fee-exit-fee-rebate-options-netting-window-root-v1";
pub const EXIT_INTENT_SUITE: &str =
    "sealed-tokenized-exit-fee-rebate-options-intent-nullifier-root-v1";
pub const COLLATERAL_ROOT_SUITE: &str =
    "privacy-preserving-exit-fee-rebate-options-collateral-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "privacy-preserving-roots-only-exit-fee-rebate-options-amm-record-v1";
pub const DEVNET_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-confidential-tokenized-exit-fee-rebate-options-amm-devnet";
pub const DEVNET_AMM_ID: &str =
    "private-l2-pq-confidential-tokenized-exit-fee-rebate-options-amm-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_028_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 4_640_000;
pub const DEVNET_UNDERLYING_ASSET_ID: &str = "pxmr-private-devnet";
pub const DEVNET_QUOTE_ASSET_ID: &str = "dusd-private-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "nebula-exit-fee-credit-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_EXIT_FEE_BPS: u64 = 16;
pub const DEFAULT_TARGET_NET_EXIT_FEE_BPS: u64 = 5;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 2;
pub const DEFAULT_LP_FEE_BPS: u64 = 4;
pub const DEFAULT_REBATE_SHARE_BPS: u64 = 7_250;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ORACLE_QUORUM: u16 = 5;
pub const DEFAULT_COUPON_QUORUM: u16 = 4;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 18;
pub const DEFAULT_NETTING_WINDOW_BLOCKS: u64 = 10;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_MIN_COLLATERAL_COVERAGE_BPS: u64 = 10_850;
pub const DEFAULT_MAX_EXIT_FEE_BPS: u64 = 24;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 1_800;
pub const DEFAULT_MAX_POOL_DELTA_ABS_BPS: i64 = 6_000;
pub const DEFAULT_MAX_POOL_GAMMA_BPS: u64 = 1_100;
pub const DEFAULT_MAX_NETTING_ITEMS: usize = 4_096;
pub const DEFAULT_MAX_SERIES: usize = 8_192;
pub const DEFAULT_MAX_POOLS: usize = 1_024;
pub const DEFAULT_MAX_COUPONS: usize = 1_048_576;
pub const DEFAULT_MAX_EXIT_INTENTS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeriesStatus {
    Draft,
    Open,
    Paused,
    Expiring,
    Settling,
    Settled,
    Retired,
}

impl SeriesStatus {
    pub fn accepts_exits(self) -> bool {
        matches!(self, Self::Open | Self::Expiring)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Warmup,
    Active,
    Degraded,
    Paused,
    Draining,
    Settled,
    Retired,
}

impl PoolStatus {
    pub fn accepts_exit_intents(self) -> bool {
        matches!(self, Self::Active | Self::Degraded | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitIntentStatus {
    Sealed,
    PrivacyChecked,
    CouponQuoted,
    CouponSigned,
    Netted,
    Exited,
    Rebated,
    Expired,
    Rejected,
}

impl ExitIntentStatus {
    pub fn is_nettable(self) -> bool {
        matches!(
            self,
            Self::CouponSigned | Self::CouponQuoted | Self::PrivacyChecked
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Draft,
    PqSigned,
    Admitted,
    Netted,
    Settled,
    Redeemed,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingStatus {
    Open,
    Collecting,
    Frozen,
    Settled,
    PartiallySettled,
    Quarantined,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_settlement_coupon_suite: String,
    pub amm_id: String,
    pub replay_domain: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub underlying_asset_id: String,
    pub quote_asset_id: String,
    pub rebate_asset_id: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub oracle_quorum: u16,
    pub coupon_quorum: u16,
    pub settlement_window_blocks: u64,
    pub netting_window_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub exit_fee_bps: u64,
    pub target_net_exit_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub lp_fee_bps: u64,
    pub rebate_share_bps: u64,
    pub max_exit_fee_bps: u64,
    pub max_rebate_bps: u64,
    pub min_collateral_coverage_bps: u64,
    pub max_pool_delta_abs_bps: i64,
    pub max_pool_gamma_bps: u64,
    pub max_netting_items: usize,
    pub max_series: usize,
    pub max_pools: usize,
    pub max_coupons: usize,
    pub max_exit_intents: usize,
    pub require_confidential_series: bool,
    pub require_pq_signed_coupons: bool,
    pub allow_low_fee_netting: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_settlement_coupon_suite: PQ_SETTLEMENT_COUPON_SUITE.to_string(),
            amm_id: DEVNET_AMM_ID.to_string(),
            replay_domain: DEVNET_REPLAY_DOMAIN.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            underlying_asset_id: DEVNET_UNDERLYING_ASSET_ID.to_string(),
            quote_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            coupon_quorum: DEFAULT_COUPON_QUORUM,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            netting_window_blocks: DEFAULT_NETTING_WINDOW_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            exit_fee_bps: DEFAULT_EXIT_FEE_BPS,
            target_net_exit_fee_bps: DEFAULT_TARGET_NET_EXIT_FEE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            lp_fee_bps: DEFAULT_LP_FEE_BPS,
            rebate_share_bps: DEFAULT_REBATE_SHARE_BPS,
            max_exit_fee_bps: DEFAULT_MAX_EXIT_FEE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            min_collateral_coverage_bps: DEFAULT_MIN_COLLATERAL_COVERAGE_BPS,
            max_pool_delta_abs_bps: DEFAULT_MAX_POOL_DELTA_ABS_BPS,
            max_pool_gamma_bps: DEFAULT_MAX_POOL_GAMMA_BPS,
            max_netting_items: DEFAULT_MAX_NETTING_ITEMS,
            max_series: DEFAULT_MAX_SERIES,
            max_pools: DEFAULT_MAX_POOLS,
            max_coupons: DEFAULT_MAX_COUPONS,
            max_exit_intents: DEFAULT_MAX_EXIT_INTENTS,
            require_confidential_series: true,
            require_pq_signed_coupons: true,
            allow_low_fee_netting: true,
        }
    }

    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("CONFIG", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_pool_index: u64,
    pub next_series_index: u64,
    pub next_collateral_index: u64,
    pub next_intent_index: u64,
    pub next_coupon_index: u64,
    pub next_netting_index: u64,
    pub next_public_record_index: u64,
    pub pools: u64,
    pub open_series: u64,
    pub collateral_accounts: u64,
    pub exit_intents: u64,
    pub pq_signed_coupons: u64,
    pub netting_windows: u64,
    pub coupons_netted: u64,
    pub rebates_reserved_micro_units: u128,
    pub rebates_redeemed_micro_units: u128,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            next_pool_index: 1,
            next_series_index: 1,
            next_collateral_index: 1,
            next_intent_index: 1,
            next_coupon_index: 1,
            next_netting_index: 1,
            next_public_record_index: 1,
            pools: 0,
            open_series: 0,
            collateral_accounts: 0,
            exit_intents: 0,
            pq_signed_coupons: 0,
            netting_windows: 0,
            coupons_netted: 0,
            rebates_reserved_micro_units: 0,
            rebates_redeemed_micro_units: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("COUNTERS", &self.public_record())
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub pools_root: String,
    pub option_series_root: String,
    pub collateral_accounts_root: String,
    pub collateral_commitments_root: String,
    pub exit_intents_root: String,
    pub settlement_coupons_root: String,
    pub low_fee_netting_root: String,
    pub nullifier_root: String,
    pub public_records_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitFeeRebatePool {
    pub pool_id: String,
    pub operator_commitment: String,
    pub underlying_asset_id: String,
    pub quote_asset_id: String,
    pub rebate_asset_id: String,
    pub fee_asset_id: String,
    pub sealed_reserve_commitment: String,
    pub inventory_root: String,
    pub exit_fee_curve_root: String,
    pub rebate_budget_root: String,
    pub delta_bps: i64,
    pub gamma_bps: u64,
    pub utilization_bps: u64,
    pub exit_fee_bps: u64,
    pub target_net_exit_fee_bps: u64,
    pub status: PoolStatus,
}

impl ExitFeeRebatePool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "underlying_asset_id": self.underlying_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "inventory_root": self.inventory_root,
            "exit_fee_curve_root": self.exit_fee_curve_root,
            "rebate_budget_root": self.rebate_budget_root,
            "delta_bps": self.delta_bps,
            "gamma_bps": self.gamma_bps,
            "utilization_bps": self.utilization_bps,
            "exit_fee_bps": self.exit_fee_bps,
            "target_net_exit_fee_bps": self.target_net_exit_fee_bps,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialOptionSeries {
    pub series_id: String,
    pub pool_id: String,
    pub option_kind: OptionKind,
    pub option_style: OptionStyle,
    pub underlying_asset_id: String,
    pub quote_asset_id: String,
    pub strike_price_micro_units: u64,
    pub expiry_l2_height: u64,
    pub barrier_price_micro_units: Option<u64>,
    pub confidential_terms_root: String,
    pub option_token_supply_commitment: String,
    pub writer_inventory_commitment: String,
    pub exit_fee_rebate_schedule_root: String,
    pub premium_curve_root: String,
    pub status: SeriesStatus,
}

impl ConfidentialOptionSeries {
    pub fn public_record(&self) -> Value {
        json!({
            "series_id": self.series_id,
            "pool_id": self.pool_id,
            "option_kind": self.option_kind,
            "option_style": self.option_style,
            "underlying_asset_id": self.underlying_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "strike_price_micro_units": self.strike_price_micro_units,
            "expiry_l2_height": self.expiry_l2_height,
            "barrier_price_micro_units": self.barrier_price_micro_units,
            "confidential_terms_root": self.confidential_terms_root,
            "option_token_supply_commitment": self.option_token_supply_commitment,
            "writer_inventory_commitment": self.writer_inventory_commitment,
            "exit_fee_rebate_schedule_root": self.exit_fee_rebate_schedule_root,
            "premium_curve_root": self.premium_curve_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CollateralAccount {
    pub account_id: String,
    pub pool_id: String,
    pub controller_commitment: String,
    pub collateral_asset_id: String,
    pub collateral_commitment: String,
    pub liability_commitment: String,
    pub withdrawal_nullifier_root: String,
    pub collateral_coverage_bps: u64,
    pub locked_rebate_budget_micro_units: u128,
    pub active: bool,
}

impl CollateralAccount {
    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "pool_id": self.pool_id,
            "collateral_asset_id": self.collateral_asset_id,
            "collateral_commitment": self.collateral_commitment,
            "liability_commitment": self.liability_commitment,
            "withdrawal_nullifier_root": self.withdrawal_nullifier_root,
            "collateral_coverage_bps": self.collateral_coverage_bps,
            "locked_rebate_budget_micro_units": self.locked_rebate_budget_micro_units,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedExitIntent {
    pub intent_id: String,
    pub series_id: String,
    pub owner_commitment: String,
    pub option_note_commitment: String,
    pub exit_nullifier: String,
    pub encrypted_exit_payload_root: String,
    pub requested_exit_contracts_commitment: String,
    pub max_exit_fee_bps: u64,
    pub sealed_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub status: ExitIntentStatus,
}

impl SealedExitIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "series_id": self.series_id,
            "option_note_commitment": self.option_note_commitment,
            "exit_nullifier": self.exit_nullifier,
            "encrypted_exit_payload_root": self.encrypted_exit_payload_root,
            "requested_exit_contracts_commitment": self.requested_exit_contracts_commitment,
            "max_exit_fee_bps": self.max_exit_fee_bps,
            "sealed_at_l2_height": self.sealed_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSettlementCoupon {
    pub coupon_id: String,
    pub intent_id: String,
    pub series_id: String,
    pub pool_id: String,
    pub signer_committee_root: String,
    pub encrypted_coupon_payload_root: String,
    pub exit_fee_bps: u64,
    pub target_net_fee_bps: u64,
    pub rebate_bps: u64,
    pub gross_exit_fee_micro_units: u128,
    pub reserved_rebate_micro_units: u128,
    pub collateral_account_id: String,
    pub collateral_root: String,
    pub coupon_round: u64,
    pub pq_signature_root: String,
    pub signed_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub status: CouponStatus,
}

impl PqSettlementCoupon {
    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "intent_id": self.intent_id,
            "series_id": self.series_id,
            "pool_id": self.pool_id,
            "encrypted_coupon_payload_root": self.encrypted_coupon_payload_root,
            "exit_fee_bps": self.exit_fee_bps,
            "target_net_fee_bps": self.target_net_fee_bps,
            "rebate_bps": self.rebate_bps,
            "gross_exit_fee_micro_units": self.gross_exit_fee_micro_units,
            "reserved_rebate_micro_units": self.reserved_rebate_micro_units,
            "collateral_account_id": self.collateral_account_id,
            "collateral_root": self.collateral_root,
            "coupon_round": self.coupon_round,
            "pq_signature_root": self.pq_signature_root,
            "signed_at_l2_height": self.signed_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeNettingWindow {
    pub window_id: String,
    pub pool_id: String,
    pub series_ids: Vec<String>,
    pub coupon_ids: Vec<String>,
    pub start_l2_height: u64,
    pub end_l2_height: u64,
    pub gross_exit_fee_micro_units: u128,
    pub net_exit_fee_micro_units: u128,
    pub rebate_redeemed_micro_units: u128,
    pub settlement_root: String,
    pub netting_proof_root: String,
    pub collateral_root_after: String,
    pub status: NettingStatus,
}

impl LowFeeNettingWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "pool_id": self.pool_id,
            "series_ids": self.series_ids,
            "coupon_ids": self.coupon_ids,
            "start_l2_height": self.start_l2_height,
            "end_l2_height": self.end_l2_height,
            "gross_exit_fee_micro_units": self.gross_exit_fee_micro_units,
            "net_exit_fee_micro_units": self.net_exit_fee_micro_units,
            "rebate_redeemed_micro_units": self.rebate_redeemed_micro_units,
            "settlement_root": self.settlement_root,
            "netting_proof_root": self.netting_proof_root,
            "collateral_root_after": self.collateral_root_after,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub redacted_payload: Value,
    pub emitted_at_l2_height: u64,
}

impl DeterministicPublicRecord {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterPoolInput {
    pub pool_id: String,
    pub operator_commitment: String,
    pub sealed_reserve_commitment: String,
    pub inventory_root: String,
    pub exit_fee_curve_root: String,
    pub rebate_budget_root: String,
    pub delta_bps: i64,
    pub gamma_bps: u64,
    pub utilization_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenSeriesInput {
    pub pool_id: String,
    pub option_kind: OptionKind,
    pub option_style: OptionStyle,
    pub strike_price_micro_units: u64,
    pub expiry_l2_height: u64,
    pub barrier_price_micro_units: Option<u64>,
    pub confidential_terms_root: String,
    pub option_token_supply_commitment: String,
    pub writer_inventory_commitment: String,
    pub exit_fee_rebate_schedule_root: String,
    pub premium_curve_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealExitIntentInput {
    pub series_id: String,
    pub owner_commitment: String,
    pub option_note_commitment: String,
    pub exit_nullifier: String,
    pub encrypted_exit_payload_root: String,
    pub requested_exit_contracts_commitment: String,
    pub max_exit_fee_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignCouponInput {
    pub intent_id: String,
    pub signer_committee_root: String,
    pub encrypted_coupon_payload_root: String,
    pub gross_exit_fee_micro_units: u128,
    pub collateral_account_id: String,
    pub collateral_root: String,
    pub coupon_round: u64,
    pub pq_signature_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetCouponsInput {
    pub pool_id: String,
    pub coupon_ids: Vec<String>,
    pub settlement_root: String,
    pub netting_proof_root: String,
    pub collateral_root_after: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub pools: BTreeMap<String, ExitFeeRebatePool>,
    pub option_series: BTreeMap<String, ConfidentialOptionSeries>,
    pub collateral_accounts: BTreeMap<String, CollateralAccount>,
    pub exit_intents: BTreeMap<String, SealedExitIntent>,
    pub settlement_coupons: BTreeMap<String, PqSettlementCoupon>,
    pub netting_windows: BTreeMap<String, LowFeeNettingWindow>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, DeterministicPublicRecord>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::new(),
            roots: Roots::default(),
            pools: BTreeMap::new(),
            option_series: BTreeMap::new(),
            collateral_accounts: BTreeMap::new(),
            exit_intents: BTreeMap::new(),
            settlement_coupons: BTreeMap::new(),
            netting_windows: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        state.install_devnet_fixtures();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "amm_id": self.config.amm_id,
            "replay_domain": self.config.replay_domain,
            "l2_height": self.config.l2_height,
            "monero_height": self.config.monero_height,
            "hash_suite": HASH_SUITE,
            "pq_settlement_coupon_suite": PQ_SETTLEMENT_COUPON_SUITE,
            "privacy_policy": "roots_only_no_owner_commitments_no_coupon_plaintext",
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "operator_safe_public_records": self
                .public_records
                .values()
                .map(DeterministicPublicRecord::public_record)
                .collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn register_pool(
        &mut self,
        input: RegisterPoolInput,
    ) -> PrivateL2PqConfidentialTokenizedExitFeeRebateOptionsAmmRuntimeResult<String> {
        require(
            self.pools.len() < self.config.max_pools,
            "pool limit reached",
        )?;
        require_root("operator_commitment", &input.operator_commitment)?;
        require_root(
            "sealed_reserve_commitment",
            &input.sealed_reserve_commitment,
        )?;
        require_root("inventory_root", &input.inventory_root)?;
        require_root("exit_fee_curve_root", &input.exit_fee_curve_root)?;
        require_root("rebate_budget_root", &input.rebate_budget_root)?;
        require(
            input.delta_bps.abs() <= self.config.max_pool_delta_abs_bps,
            "pool delta exceeds configured bound",
        )?;
        require(
            input.gamma_bps <= self.config.max_pool_gamma_bps,
            "pool gamma exceeds configured bound",
        )?;
        require(
            input.utilization_bps <= MAX_BPS,
            "utilization exceeds MAX_BPS",
        )?;
        let pool_id = if input.pool_id.trim().is_empty() {
            deterministic_id(
                "exit-fee-rebate-pool",
                &[
                    HashPart::Str(&input.operator_commitment),
                    HashPart::Str(&input.inventory_root),
                    HashPart::U64(self.counters.next_pool_index),
                ],
            )
        } else {
            input.pool_id
        };
        require(!self.pools.contains_key(&pool_id), "duplicate pool")?;
        let pool = ExitFeeRebatePool {
            pool_id: pool_id.clone(),
            operator_commitment: input.operator_commitment,
            underlying_asset_id: self.config.underlying_asset_id.clone(),
            quote_asset_id: self.config.quote_asset_id.clone(),
            rebate_asset_id: self.config.rebate_asset_id.clone(),
            fee_asset_id: self.config.fee_asset_id.clone(),
            sealed_reserve_commitment: input.sealed_reserve_commitment,
            inventory_root: input.inventory_root,
            exit_fee_curve_root: input.exit_fee_curve_root,
            rebate_budget_root: input.rebate_budget_root,
            delta_bps: input.delta_bps,
            gamma_bps: input.gamma_bps,
            utilization_bps: input.utilization_bps,
            exit_fee_bps: self.config.exit_fee_bps,
            target_net_exit_fee_bps: self.config.target_net_exit_fee_bps,
            status: PoolStatus::Active,
        };
        self.pools.insert(pool_id.clone(), pool.clone());
        self.counters.pools = self.counters.pools.saturating_add(1);
        self.counters.next_pool_index = self.counters.next_pool_index.saturating_add(1);
        self.emit_public_record("exit_fee_rebate_pool", &pool_id, pool.public_record());
        self.refresh_roots();
        Ok(pool_id)
    }

    pub fn open_confidential_series(
        &mut self,
        input: OpenSeriesInput,
    ) -> PrivateL2PqConfidentialTokenizedExitFeeRebateOptionsAmmRuntimeResult<String> {
        require(
            self.option_series.len() < self.config.max_series,
            "series limit reached",
        )?;
        let pool = self
            .pools
            .get(&input.pool_id)
            .ok_or_else(|| "unknown pool".to_string())?;
        require(
            pool.status.accepts_exit_intents(),
            "pool is not accepting exits",
        )?;
        require(
            input.expiry_l2_height > self.config.l2_height,
            "series already expired",
        )?;
        require_root("confidential_terms_root", &input.confidential_terms_root)?;
        require_root(
            "option_token_supply_commitment",
            &input.option_token_supply_commitment,
        )?;
        require_root(
            "writer_inventory_commitment",
            &input.writer_inventory_commitment,
        )?;
        require_root(
            "exit_fee_rebate_schedule_root",
            &input.exit_fee_rebate_schedule_root,
        )?;
        require_root("premium_curve_root", &input.premium_curve_root)?;
        let series_id = deterministic_id(
            "exit-fee-rebate-option-series",
            &[
                HashPart::Str(&input.pool_id),
                HashPart::Str(input.option_kind.as_str()),
                HashPart::Str(input.option_style.as_str()),
                HashPart::U64(input.strike_price_micro_units),
                HashPart::U64(input.expiry_l2_height),
                HashPart::U64(self.counters.next_series_index),
            ],
        );
        let series = ConfidentialOptionSeries {
            series_id: series_id.clone(),
            pool_id: input.pool_id,
            option_kind: input.option_kind,
            option_style: input.option_style,
            underlying_asset_id: self.config.underlying_asset_id.clone(),
            quote_asset_id: self.config.quote_asset_id.clone(),
            strike_price_micro_units: input.strike_price_micro_units,
            expiry_l2_height: input.expiry_l2_height,
            barrier_price_micro_units: input.barrier_price_micro_units,
            confidential_terms_root: input.confidential_terms_root,
            option_token_supply_commitment: input.option_token_supply_commitment,
            writer_inventory_commitment: input.writer_inventory_commitment,
            exit_fee_rebate_schedule_root: input.exit_fee_rebate_schedule_root,
            premium_curve_root: input.premium_curve_root,
            status: SeriesStatus::Open,
        };
        self.option_series.insert(series_id.clone(), series.clone());
        self.counters.open_series = self.counters.open_series.saturating_add(1);
        self.counters.next_series_index = self.counters.next_series_index.saturating_add(1);
        self.emit_public_record(
            "confidential_option_series",
            &series_id,
            series.public_record(),
        );
        self.refresh_roots();
        Ok(series_id)
    }

    pub fn upsert_collateral_account(
        &mut self,
        mut account: CollateralAccount,
    ) -> PrivateL2PqConfidentialTokenizedExitFeeRebateOptionsAmmRuntimeResult<String> {
        require(self.pools.contains_key(&account.pool_id), "unknown pool")?;
        require_root("controller_commitment", &account.controller_commitment)?;
        require_root("collateral_commitment", &account.collateral_commitment)?;
        require_root("liability_commitment", &account.liability_commitment)?;
        require_root(
            "withdrawal_nullifier_root",
            &account.withdrawal_nullifier_root,
        )?;
        require(
            account.collateral_coverage_bps >= self.config.min_collateral_coverage_bps,
            "collateral coverage below minimum",
        )?;
        if account.account_id.trim().is_empty() {
            account.account_id = deterministic_id(
                "exit-fee-rebate-collateral-account",
                &[
                    HashPart::Str(&account.pool_id),
                    HashPart::Str(&account.controller_commitment),
                    HashPart::U64(self.counters.next_collateral_index),
                ],
            );
        }
        let account_id = account.account_id.clone();
        let is_new = !self.collateral_accounts.contains_key(&account_id);
        self.collateral_accounts
            .insert(account_id.clone(), account.clone());
        if is_new {
            self.counters.collateral_accounts = self.counters.collateral_accounts.saturating_add(1);
            self.counters.next_collateral_index =
                self.counters.next_collateral_index.saturating_add(1);
        }
        self.emit_public_record("collateral_account", &account_id, account.public_record());
        self.refresh_roots();
        Ok(account_id)
    }

    pub fn seal_exit_intent(
        &mut self,
        input: SealExitIntentInput,
    ) -> PrivateL2PqConfidentialTokenizedExitFeeRebateOptionsAmmRuntimeResult<String> {
        require(
            self.exit_intents.len() < self.config.max_exit_intents,
            "exit intent limit reached",
        )?;
        let series = self
            .option_series
            .get(&input.series_id)
            .ok_or_else(|| "unknown option series".to_string())?;
        require(
            series.status.accepts_exits(),
            "series is not accepting exits",
        )?;
        require_root("owner_commitment", &input.owner_commitment)?;
        require_root("option_note_commitment", &input.option_note_commitment)?;
        require_root("exit_nullifier", &input.exit_nullifier)?;
        require(
            !self.consumed_nullifiers.contains(&input.exit_nullifier),
            "duplicate exit nullifier",
        )?;
        require_root(
            "encrypted_exit_payload_root",
            &input.encrypted_exit_payload_root,
        )?;
        require_root(
            "requested_exit_contracts_commitment",
            &input.requested_exit_contracts_commitment,
        )?;
        require(
            input.max_exit_fee_bps <= self.config.max_exit_fee_bps,
            "exit fee exceeds configured maximum",
        )?;
        let intent_id = deterministic_id(
            "sealed-exit-intent",
            &[
                HashPart::Str(&input.series_id),
                HashPart::Str(&input.exit_nullifier),
                HashPart::U64(self.counters.next_intent_index),
            ],
        );
        let intent = SealedExitIntent {
            intent_id: intent_id.clone(),
            series_id: input.series_id,
            owner_commitment: input.owner_commitment,
            option_note_commitment: input.option_note_commitment,
            exit_nullifier: input.exit_nullifier,
            encrypted_exit_payload_root: input.encrypted_exit_payload_root,
            requested_exit_contracts_commitment: input.requested_exit_contracts_commitment,
            max_exit_fee_bps: input.max_exit_fee_bps,
            sealed_at_l2_height: self.config.l2_height,
            expires_at_l2_height: self.config.l2_height + self.config.settlement_window_blocks,
            status: ExitIntentStatus::Sealed,
        };
        self.consumed_nullifiers
            .insert(intent.exit_nullifier.clone());
        self.exit_intents.insert(intent_id.clone(), intent.clone());
        self.counters.exit_intents = self.counters.exit_intents.saturating_add(1);
        self.counters.next_intent_index = self.counters.next_intent_index.saturating_add(1);
        self.emit_public_record("sealed_exit_intent", &intent_id, intent.public_record());
        self.refresh_roots();
        Ok(intent_id)
    }

    pub fn sign_settlement_coupon(
        &mut self,
        input: SignCouponInput,
    ) -> PrivateL2PqConfidentialTokenizedExitFeeRebateOptionsAmmRuntimeResult<String> {
        require(
            self.settlement_coupons.len() < self.config.max_coupons,
            "settlement coupon limit reached",
        )?;
        let intent = self
            .exit_intents
            .get(&input.intent_id)
            .ok_or_else(|| "unknown exit intent".to_string())?;
        require(intent.status.is_nettable(), "intent is not nettable")?;
        let series = self
            .option_series
            .get(&intent.series_id)
            .ok_or_else(|| "unknown option series".to_string())?;
        let account = self
            .collateral_accounts
            .get(&input.collateral_account_id)
            .ok_or_else(|| "unknown collateral account".to_string())?;
        require(account.active, "collateral account inactive")?;
        require(
            account.pool_id == series.pool_id,
            "collateral account pool mismatch",
        )?;
        require_root("signer_committee_root", &input.signer_committee_root)?;
        require_root(
            "encrypted_coupon_payload_root",
            &input.encrypted_coupon_payload_root,
        )?;
        require_root("collateral_root", &input.collateral_root)?;
        require_root("pq_signature_root", &input.pq_signature_root)?;
        let rebate_bps = rebate_bps_for_fee(
            self.config.exit_fee_bps,
            self.config.target_net_exit_fee_bps,
            self.config.rebate_share_bps,
            self.config.max_rebate_bps,
        );
        let reserved_rebate_micro_units = bps_amount(input.gross_exit_fee_micro_units, rebate_bps)
            .min(bps_amount(
                input.gross_exit_fee_micro_units,
                self.config.max_rebate_bps,
            ));
        let coupon_id = deterministic_id(
            "pq-settlement-coupon",
            &[
                HashPart::Str(&input.intent_id),
                HashPart::Str(&input.pq_signature_root),
                HashPart::U64(input.coupon_round),
                HashPart::U64(self.counters.next_coupon_index),
            ],
        );
        let coupon = PqSettlementCoupon {
            coupon_id: coupon_id.clone(),
            intent_id: input.intent_id,
            series_id: series.series_id.clone(),
            pool_id: series.pool_id.clone(),
            signer_committee_root: input.signer_committee_root,
            encrypted_coupon_payload_root: input.encrypted_coupon_payload_root,
            exit_fee_bps: self.config.exit_fee_bps,
            target_net_fee_bps: self.config.target_net_exit_fee_bps,
            rebate_bps,
            gross_exit_fee_micro_units: input.gross_exit_fee_micro_units,
            reserved_rebate_micro_units,
            collateral_account_id: input.collateral_account_id,
            collateral_root: input.collateral_root,
            coupon_round: input.coupon_round,
            pq_signature_root: input.pq_signature_root,
            signed_at_l2_height: self.config.l2_height,
            expires_at_l2_height: self.config.l2_height + self.config.coupon_ttl_blocks,
            status: CouponStatus::PqSigned,
        };
        self.settlement_coupons
            .insert(coupon_id.clone(), coupon.clone());
        self.counters.pq_signed_coupons = self.counters.pq_signed_coupons.saturating_add(1);
        self.counters.rebates_reserved_micro_units = self
            .counters
            .rebates_reserved_micro_units
            .saturating_add(reserved_rebate_micro_units);
        self.counters.next_coupon_index = self.counters.next_coupon_index.saturating_add(1);
        self.emit_public_record("pq_settlement_coupon", &coupon_id, coupon.public_record());
        self.refresh_roots();
        Ok(coupon_id)
    }

    pub fn net_low_fee_coupons(
        &mut self,
        input: NetCouponsInput,
    ) -> PrivateL2PqConfidentialTokenizedExitFeeRebateOptionsAmmRuntimeResult<String> {
        require(
            self.config.allow_low_fee_netting,
            "low-fee netting disabled",
        )?;
        require(self.pools.contains_key(&input.pool_id), "unknown pool")?;
        require(!input.coupon_ids.is_empty(), "netting requires coupons")?;
        require(
            input.coupon_ids.len() <= self.config.max_netting_items,
            "netting window too large",
        )?;
        require(
            unique_strings(&input.coupon_ids),
            "coupon ids must be unique",
        )?;
        require_root("settlement_root", &input.settlement_root)?;
        require_root("netting_proof_root", &input.netting_proof_root)?;
        require_root("collateral_root_after", &input.collateral_root_after)?;
        let mut series_ids = BTreeSet::new();
        let mut gross_exit_fee_micro_units = 0u128;
        let mut rebate_redeemed_micro_units = 0u128;
        for coupon_id in &input.coupon_ids {
            let coupon = self
                .settlement_coupons
                .get(coupon_id)
                .ok_or_else(|| "unknown settlement coupon".to_string())?;
            require(coupon.pool_id == input.pool_id, "coupon pool mismatch")?;
            require(
                matches!(
                    coupon.status,
                    CouponStatus::PqSigned | CouponStatus::Admitted
                ),
                "coupon is not eligible for netting",
            )?;
            require(
                coupon.expires_at_l2_height >= self.config.l2_height,
                "coupon expired",
            )?;
            series_ids.insert(coupon.series_id.clone());
            gross_exit_fee_micro_units =
                gross_exit_fee_micro_units.saturating_add(coupon.gross_exit_fee_micro_units);
            rebate_redeemed_micro_units =
                rebate_redeemed_micro_units.saturating_add(coupon.reserved_rebate_micro_units);
        }
        let net_exit_fee_micro_units =
            gross_exit_fee_micro_units.saturating_sub(rebate_redeemed_micro_units);
        let window_id = deterministic_id(
            "low-fee-exit-fee-netting-window",
            &[
                HashPart::Str(&input.pool_id),
                HashPart::Str(&input.settlement_root),
                HashPart::U64(self.counters.next_netting_index),
            ],
        );
        let window = LowFeeNettingWindow {
            window_id: window_id.clone(),
            pool_id: input.pool_id,
            series_ids: series_ids.into_iter().collect(),
            coupon_ids: input.coupon_ids.clone(),
            start_l2_height: self.config.l2_height,
            end_l2_height: self.config.l2_height + self.config.netting_window_blocks,
            gross_exit_fee_micro_units,
            net_exit_fee_micro_units,
            rebate_redeemed_micro_units,
            settlement_root: input.settlement_root,
            netting_proof_root: input.netting_proof_root,
            collateral_root_after: input.collateral_root_after,
            status: NettingStatus::Settled,
        };
        for coupon_id in input.coupon_ids {
            if let Some(coupon) = self.settlement_coupons.get_mut(&coupon_id) {
                coupon.status = CouponStatus::Netted;
            }
        }
        self.netting_windows
            .insert(window_id.clone(), window.clone());
        self.counters.netting_windows = self.counters.netting_windows.saturating_add(1);
        self.counters.coupons_netted = self
            .counters
            .coupons_netted
            .saturating_add(window.coupon_ids.len() as u64);
        self.counters.rebates_redeemed_micro_units = self
            .counters
            .rebates_redeemed_micro_units
            .saturating_add(rebate_redeemed_micro_units);
        self.counters.next_netting_index = self.counters.next_netting_index.saturating_add(1);
        self.emit_public_record("low_fee_netting_window", &window_id, window.public_record());
        self.refresh_roots();
        Ok(window_id)
    }

    fn emit_public_record(&mut self, record_kind: &str, subject_id: &str, redacted_payload: Value) {
        let payload_root = payload_root("PUBLIC_RECORD_REDACTED_PAYLOAD", &redacted_payload);
        let record_id = deterministic_id(
            "exit-fee-rebate-public-record",
            &[
                HashPart::Str(record_kind),
                HashPart::Str(subject_id),
                HashPart::Str(&payload_root),
                HashPart::U64(self.counters.next_public_record_index),
            ],
        );
        self.public_records.insert(
            record_id.clone(),
            DeterministicPublicRecord {
                record_id,
                record_kind: record_kind.to_string(),
                subject_id: subject_id.to_string(),
                payload_root,
                redacted_payload,
                emitted_at_l2_height: self.config.l2_height,
            },
        );
        self.counters.next_public_record_index =
            self.counters.next_public_record_index.saturating_add(1);
    }

    fn refresh_roots(&mut self) {
        self.roots.config_root = self.config.root();
        self.roots.counters_root = self.counters.root();
        self.roots.pools_root = merkle_root(
            EXIT_FEE_POOL_SUITE,
            &self
                .pools
                .values()
                .map(ExitFeeRebatePool::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.option_series_root = merkle_root(
            CONFIDENTIAL_OPTION_SERIES_SUITE,
            &self
                .option_series
                .values()
                .map(ConfidentialOptionSeries::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.collateral_accounts_root = merkle_root(
            COLLATERAL_ACCOUNT_SUITE,
            &self
                .collateral_accounts
                .values()
                .map(CollateralAccount::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.collateral_commitments_root = merkle_root(
            COLLATERAL_ROOT_SUITE,
            &self
                .collateral_accounts
                .values()
                .map(|account| {
                    json!({
                        "account_id": account.account_id,
                        "pool_id": account.pool_id,
                        "collateral_commitment": account.collateral_commitment,
                        "liability_commitment": account.liability_commitment,
                        "coverage_bps": account.collateral_coverage_bps,
                    })
                })
                .collect::<Vec<_>>(),
        );
        self.roots.exit_intents_root = merkle_root(
            EXIT_INTENT_SUITE,
            &self
                .exit_intents
                .values()
                .map(SealedExitIntent::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.settlement_coupons_root = merkle_root(
            SETTLEMENT_COUPON_ROOT_SUITE,
            &self
                .settlement_coupons
                .values()
                .map(PqSettlementCoupon::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.low_fee_netting_root = merkle_root(
            LOW_FEE_NETTING_SUITE,
            &self
                .netting_windows
                .values()
                .map(LowFeeNettingWindow::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.nullifier_root = merkle_root(
            "exit-fee-rebate-options-consumed-nullifier-root-v1",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!({ "exit_nullifier": nullifier }))
                .collect::<Vec<_>>(),
        );
        self.roots.public_records_root = merkle_root(
            PUBLIC_RECORD_SUITE,
            &self
                .public_records
                .values()
                .map(DeterministicPublicRecord::public_record)
                .collect::<Vec<_>>(),
        );
        self.roots.state_root = domain_hash(
            "private-l2-pq-confidential-tokenized-exit-fee-rebate-options-amm-state-root-v1",
            &[
                HashPart::Str(&self.config.protocol_version),
                HashPart::U64(self.config.schema_version),
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(&self.config.amm_id),
                HashPart::U64(self.config.l2_height),
                HashPart::U64(self.config.monero_height),
                HashPart::Str(&self.roots.config_root),
                HashPart::Str(&self.roots.counters_root),
                HashPart::Str(&self.roots.pools_root),
                HashPart::Str(&self.roots.option_series_root),
                HashPart::Str(&self.roots.collateral_accounts_root),
                HashPart::Str(&self.roots.collateral_commitments_root),
                HashPart::Str(&self.roots.exit_intents_root),
                HashPart::Str(&self.roots.settlement_coupons_root),
                HashPart::Str(&self.roots.low_fee_netting_root),
                HashPart::Str(&self.roots.nullifier_root),
                HashPart::Str(&self.roots.public_records_root),
            ],
            32,
        );
    }

    fn install_devnet_fixtures(&mut self) {
        let pool_id = self
            .register_pool(RegisterPoolInput {
                pool_id: "exit-fee-rebate-options-pxmr-dusd-devnet".to_string(),
                operator_commitment: hex_root("devnet-pool-operator", 1),
                sealed_reserve_commitment: hex_root("devnet-pool-reserve", 1),
                inventory_root: hex_root("devnet-pool-inventory", 1),
                exit_fee_curve_root: hex_root("devnet-exit-fee-curve", 1),
                rebate_budget_root: hex_root("devnet-rebate-budget", 1),
                delta_bps: 2_850,
                gamma_bps: 390,
                utilization_bps: 6_900,
            })
            .expect("devnet pool");
        let series_id = self
            .open_confidential_series(OpenSeriesInput {
                pool_id: pool_id.clone(),
                option_kind: OptionKind::Put,
                option_style: OptionStyle::European,
                strike_price_micro_units: 162_000_000,
                expiry_l2_height: DEVNET_L2_HEIGHT + 21_600,
                barrier_price_micro_units: None,
                confidential_terms_root: hex_root("devnet-series-terms", 1),
                option_token_supply_commitment: hex_root("devnet-series-supply", 1),
                writer_inventory_commitment: hex_root("devnet-writer-inventory", 1),
                exit_fee_rebate_schedule_root: hex_root("devnet-rebate-schedule", 1),
                premium_curve_root: hex_root("devnet-premium-curve", 1),
            })
            .expect("devnet series");
        let collateral_account_id = self
            .upsert_collateral_account(CollateralAccount {
                account_id: String::new(),
                pool_id: pool_id.clone(),
                controller_commitment: hex_root("devnet-collateral-controller", 1),
                collateral_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
                collateral_commitment: hex_root("devnet-collateral", 1),
                liability_commitment: hex_root("devnet-collateral-liability", 1),
                withdrawal_nullifier_root: hex_root("devnet-withdrawal-nullifiers", 1),
                collateral_coverage_bps: 11_400,
                locked_rebate_budget_micro_units: 900_000_000,
                active: true,
            })
            .expect("devnet collateral account");
        let intent_id = self
            .seal_exit_intent(SealExitIntentInput {
                series_id,
                owner_commitment: hex_root("devnet-exit-owner", 1),
                option_note_commitment: hex_root("devnet-option-note", 1),
                exit_nullifier: hex_root("devnet-exit-nullifier", 1),
                encrypted_exit_payload_root: hex_root("devnet-exit-payload", 1),
                requested_exit_contracts_commitment: hex_root("devnet-exit-contracts", 1),
                max_exit_fee_bps: 18,
            })
            .expect("devnet exit intent");
        let coupon_id = self
            .sign_settlement_coupon(SignCouponInput {
                intent_id,
                signer_committee_root: hex_root("devnet-coupon-committee", 1),
                encrypted_coupon_payload_root: hex_root("devnet-coupon-payload", 1),
                gross_exit_fee_micro_units: 1_640_000,
                collateral_account_id,
                collateral_root: hex_root("devnet-collateral-root-before", 1),
                coupon_round: 77,
                pq_signature_root: hex_root("devnet-coupon-pq-signature", 1),
            })
            .expect("devnet settlement coupon");
        self.net_low_fee_coupons(NetCouponsInput {
            pool_id,
            coupon_ids: vec![coupon_id],
            settlement_root: hex_root("devnet-low-fee-settlement", 1),
            netting_proof_root: hex_root("devnet-low-fee-netting-proof", 1),
            collateral_root_after: hex_root("devnet-collateral-root-after", 1),
        })
        .expect("devnet low-fee netting");
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    format!("{domain}:{}", domain_hash(domain, parts, 16))
}

fn payload_root(label: &str, value: &Value) -> String {
    domain_hash(
        "private-l2-pq-confidential-tokenized-exit-fee-rebate-options-amm-payload-root-v1",
        &[HashPart::Str(label), HashPart::Json(value)],
        32,
    )
}

fn stable_record<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("runtime record serialization")
}

fn unique_strings(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn bps_amount(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn rebate_bps_for_fee(
    exit_fee_bps: u64,
    target_net_exit_fee_bps: u64,
    rebate_share_bps: u64,
    max_rebate_bps: u64,
) -> u64 {
    let computed = exit_fee_bps
        .saturating_sub(target_net_exit_fee_bps)
        .saturating_mul(rebate_share_bps)
        / MAX_BPS;
    computed.min(max_rebate_bps)
}

fn require(condition: bool, message: &str) -> Result<()> {
    if !condition {
        return Err(message.to_string());
    }
    Ok(())
}

fn require_root(label: &str, value: &str) -> Result<()> {
    if value.len() < 32 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} must be a hex commitment/root of at least 32 chars"
        ));
    }
    Ok(())
}

fn hex_root(label: &str, index: u64) -> String {
    domain_hash(
        "private-l2-pq-confidential-tokenized-exit-fee-rebate-options-amm-devnet-root-v1",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}
