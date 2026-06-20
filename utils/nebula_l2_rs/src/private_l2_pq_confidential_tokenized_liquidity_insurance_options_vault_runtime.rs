use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedLiquidityInsuranceOptionsVaultRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_LIQUIDITY_INSURANCE_OPTIONS_VAULT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-liquidity-insurance-options-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_LIQUIDITY_INSURANCE_OPTIONS_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_CLAIM_COUPON_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-liquidity-insurance-claim-coupon-v1";
pub const CONFIDENTIAL_SERIES_SUITE: &str =
    "confidential-tokenized-liquidity-insurance-options-series-root-v1";
pub const INSURANCE_VAULT_SUITE: &str =
    "confidential-tokenized-liquidity-insurance-options-vault-root-v1";
pub const COLLATERAL_ROOT_SUITE: &str = "privacy-preserving-liquidity-insurance-collateral-root-v1";
pub const PREMIUM_ROOT_SUITE: &str = "privacy-preserving-liquidity-insurance-premium-root-v1";
pub const CLAIM_COUPON_ROOT_SUITE: &str = "pq-signed-liquidity-insurance-claim-coupon-root-v1";
pub const LOW_FEE_NETTING_SUITE: &str = "low-fee-liquidity-insurance-claim-netting-window-root-v1";
pub const CLAIM_INTENT_SUITE: &str =
    "sealed-tokenized-liquidity-insurance-claim-intent-nullifier-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "privacy-preserving-roots-only-liquidity-insurance-options-vault-record-v1";
pub const STATE_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-liquidity-insurance-options-vault-state-root-v1";
pub const PAYLOAD_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-liquidity-insurance-options-vault-payload-root-v1";
pub const DEVNET_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-confidential-tokenized-liquidity-insurance-options-vault-devnet";
pub const DEVNET_VAULT_ID: &str =
    "private-l2-pq-confidential-tokenized-liquidity-insurance-options-vault-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_044_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 4_656_000;
pub const DEVNET_UNDERLYING_ASSET_ID: &str = "pxmr-private-devnet";
pub const DEVNET_COLLATERAL_ASSET_ID: &str = "dusd-private-devnet";
pub const DEVNET_PREMIUM_ASSET_ID: &str = "nebula-premium-credit-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 2;
pub const DEFAULT_LP_FEE_BPS: u64 = 3;
pub const DEFAULT_INSURANCE_FEE_BPS: u64 = 9;
pub const DEFAULT_TARGET_NET_CLAIM_FEE_BPS: u64 = 4;
pub const DEFAULT_PREMIUM_REBATE_SHARE_BPS: u64 = 6_500;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ORACLE_QUORUM: u16 = 5;
pub const DEFAULT_COUPON_QUORUM: u16 = 4;
pub const DEFAULT_CLAIM_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 18;
pub const DEFAULT_NETTING_WINDOW_BLOCKS: u64 = 10;
pub const DEFAULT_MIN_COLLATERAL_COVERAGE_BPS: u64 = 11_250;
pub const DEFAULT_MIN_PREMIUM_COVERAGE_BPS: u64 = 1_050;
pub const DEFAULT_MAX_PAYOUT_BPS: u64 = 8_500;
pub const DEFAULT_MAX_VAULT_DELTA_ABS_BPS: i64 = 5_500;
pub const DEFAULT_MAX_VAULT_GAMMA_BPS: u64 = 1_250;
pub const DEFAULT_MAX_NETTING_ITEMS: usize = 4_096;
pub const DEFAULT_MAX_SERIES: usize = 8_192;
pub const DEFAULT_MAX_VAULTS: usize = 1_024;
pub const DEFAULT_MAX_COUPONS: usize = 1_048_576;
pub const DEFAULT_MAX_CLAIM_INTENTS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InsuranceOptionKind {
    LiquidityPut,
    LiquidityCall,
    GapPut,
    GapCall,
    DrawdownBinary,
    UtilizationBarrier,
}

impl InsuranceOptionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LiquidityPut => "liquidity_put",
            Self::LiquidityCall => "liquidity_call",
            Self::GapPut => "gap_put",
            Self::GapCall => "gap_call",
            Self::DrawdownBinary => "drawdown_binary",
            Self::UtilizationBarrier => "utilization_barrier",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExerciseStyle {
    European,
    American,
    Bermudan,
}

impl ExerciseStyle {
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
pub enum VaultStatus {
    Warmup,
    Active,
    Degraded,
    Paused,
    Draining,
    Settled,
    Retired,
}

impl VaultStatus {
    pub fn accepts_premiums(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }

    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Active | Self::Degraded | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeriesStatus {
    Draft,
    Open,
    Paused,
    Expiring,
    Claiming,
    Settling,
    Settled,
    Retired,
}

impl SeriesStatus {
    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Open | Self::Expiring | Self::Claiming)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimIntentStatus {
    Sealed,
    PrivacyChecked,
    CouponQuoted,
    CouponSigned,
    Netted,
    Paid,
    Expired,
    Rejected,
}

impl ClaimIntentStatus {
    pub fn is_nettable(self) -> bool {
        matches!(
            self,
            Self::PrivacyChecked | Self::CouponQuoted | Self::CouponSigned
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
    pub pq_claim_coupon_suite: String,
    pub vault_runtime_id: String,
    pub replay_domain: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub underlying_asset_id: String,
    pub collateral_asset_id: String,
    pub premium_asset_id: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub oracle_quorum: u16,
    pub coupon_quorum: u16,
    pub claim_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub netting_window_blocks: u64,
    pub insurance_fee_bps: u64,
    pub target_net_claim_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub lp_fee_bps: u64,
    pub premium_rebate_share_bps: u64,
    pub min_collateral_coverage_bps: u64,
    pub min_premium_coverage_bps: u64,
    pub max_payout_bps: u64,
    pub max_vault_delta_abs_bps: i64,
    pub max_vault_gamma_bps: u64,
    pub max_netting_items: usize,
    pub max_series: usize,
    pub max_vaults: usize,
    pub max_coupons: usize,
    pub max_claim_intents: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_claim_coupon_suite: PQ_CLAIM_COUPON_SUITE.to_string(),
            vault_runtime_id: DEVNET_VAULT_ID.to_string(),
            replay_domain: DEVNET_REPLAY_DOMAIN.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            underlying_asset_id: DEVNET_UNDERLYING_ASSET_ID.to_string(),
            collateral_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
            premium_asset_id: DEVNET_PREMIUM_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            coupon_quorum: DEFAULT_COUPON_QUORUM,
            claim_ttl_blocks: DEFAULT_CLAIM_TTL_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            netting_window_blocks: DEFAULT_NETTING_WINDOW_BLOCKS,
            insurance_fee_bps: DEFAULT_INSURANCE_FEE_BPS,
            target_net_claim_fee_bps: DEFAULT_TARGET_NET_CLAIM_FEE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            lp_fee_bps: DEFAULT_LP_FEE_BPS,
            premium_rebate_share_bps: DEFAULT_PREMIUM_REBATE_SHARE_BPS,
            min_collateral_coverage_bps: DEFAULT_MIN_COLLATERAL_COVERAGE_BPS,
            min_premium_coverage_bps: DEFAULT_MIN_PREMIUM_COVERAGE_BPS,
            max_payout_bps: DEFAULT_MAX_PAYOUT_BPS,
            max_vault_delta_abs_bps: DEFAULT_MAX_VAULT_DELTA_ABS_BPS,
            max_vault_gamma_bps: DEFAULT_MAX_VAULT_GAMMA_BPS,
            max_netting_items: DEFAULT_MAX_NETTING_ITEMS,
            max_series: DEFAULT_MAX_SERIES,
            max_vaults: DEFAULT_MAX_VAULTS,
            max_coupons: DEFAULT_MAX_COUPONS,
            max_claim_intents: DEFAULT_MAX_CLAIM_INTENTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_claim_coupon_suite": self.pq_claim_coupon_suite,
            "vault_runtime_id": self.vault_runtime_id,
            "replay_domain": self.replay_domain,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "underlying_asset_id": self.underlying_asset_id,
            "collateral_asset_id": self.collateral_asset_id,
            "premium_asset_id": self.premium_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "oracle_quorum": self.oracle_quorum,
            "coupon_quorum": self.coupon_quorum,
            "claim_ttl_blocks": self.claim_ttl_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "netting_window_blocks": self.netting_window_blocks,
            "insurance_fee_bps": self.insurance_fee_bps,
            "target_net_claim_fee_bps": self.target_net_claim_fee_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "lp_fee_bps": self.lp_fee_bps,
            "premium_rebate_share_bps": self.premium_rebate_share_bps,
            "min_collateral_coverage_bps": self.min_collateral_coverage_bps,
            "min_premium_coverage_bps": self.min_premium_coverage_bps,
            "max_payout_bps": self.max_payout_bps,
            "max_vault_delta_abs_bps": self.max_vault_delta_abs_bps,
            "max_vault_gamma_bps": self.max_vault_gamma_bps,
            "max_netting_items": self.max_netting_items,
            "max_series": self.max_series,
            "max_vaults": self.max_vaults,
            "max_coupons": self.max_coupons,
            "max_claim_intents": self.max_claim_intents,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("config", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        require(!self.chain_id.is_empty(), "chain id is empty")?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "unexpected protocol version",
        )?;
        require(
            self.schema_version == SCHEMA_VERSION,
            "unexpected schema version",
        )?;
        require(self.oracle_quorum > 0, "oracle quorum is zero")?;
        require(self.coupon_quorum > 0, "coupon quorum is zero")?;
        require(
            self.min_privacy_set_size <= self.target_privacy_set_size,
            "minimum privacy set exceeds target privacy set",
        )?;
        require_bps("insurance fee bps", self.insurance_fee_bps)?;
        require_bps("target net claim fee bps", self.target_net_claim_fee_bps)?;
        require_bps("protocol fee bps", self.protocol_fee_bps)?;
        require_bps("lp fee bps", self.lp_fee_bps)?;
        require_bps("premium rebate share bps", self.premium_rebate_share_bps)?;
        require_bps(
            "minimum premium coverage bps",
            self.min_premium_coverage_bps,
        )?;
        require_bps("maximum payout bps", self.max_payout_bps)?;
        require_bps("maximum vault gamma bps", self.max_vault_gamma_bps)?;
        require(self.max_vault_delta_abs_bps >= 0, "negative max delta")?;
        require(self.max_netting_items > 0, "max netting items is zero")?;
        require(self.max_series > 0, "max series is zero")?;
        require(self.max_vaults > 0, "max vaults is zero")?;
        require(self.max_coupons > 0, "max coupons is zero")?;
        require(self.max_claim_intents > 0, "max claim intents is zero")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub sequence: u64,
    pub vaults: u64,
    pub option_series: u64,
    pub collateral_accounts: u64,
    pub premium_accounts: u64,
    pub claim_intents: u64,
    pub claim_coupons: u64,
    pub netting_windows: u64,
    pub consumed_nullifiers: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "sequence": self.sequence,
            "vaults": self.vaults,
            "option_series": self.option_series,
            "collateral_accounts": self.collateral_accounts,
            "premium_accounts": self.premium_accounts,
            "claim_intents": self.claim_intents,
            "claim_coupons": self.claim_coupons,
            "netting_windows": self.netting_windows,
            "consumed_nullifiers": self.consumed_nullifiers,
            "public_records": self.public_records,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub vaults_root: String,
    pub option_series_root: String,
    pub collateral_accounts_root: String,
    pub collateral_commitments_root: String,
    pub premium_accounts_root: String,
    pub premium_commitments_root: String,
    pub claim_intents_root: String,
    pub claim_coupons_root: String,
    pub low_fee_netting_root: String,
    pub nullifier_root: String,
    pub public_records_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let empty = merkle_root("empty-liquidity-insurance-options-vault-root-v1", &[]);
        Self {
            config_root: config.state_root(),
            counters_root: counters.state_root(),
            vaults_root: empty.clone(),
            option_series_root: empty.clone(),
            collateral_accounts_root: empty.clone(),
            collateral_commitments_root: empty.clone(),
            premium_accounts_root: empty.clone(),
            premium_commitments_root: empty.clone(),
            claim_intents_root: empty.clone(),
            claim_coupons_root: empty.clone(),
            low_fee_netting_root: empty.clone(),
            nullifier_root: empty.clone(),
            public_records_root: empty,
            state_root: String::new(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "vaults_root": self.vaults_root,
            "option_series_root": self.option_series_root,
            "collateral_accounts_root": self.collateral_accounts_root,
            "collateral_commitments_root": self.collateral_commitments_root,
            "premium_accounts_root": self.premium_accounts_root,
            "premium_commitments_root": self.premium_commitments_root,
            "claim_intents_root": self.claim_intents_root,
            "claim_coupons_root": self.claim_coupons_root,
            "low_fee_netting_root": self.low_fee_netting_root,
            "nullifier_root": self.nullifier_root,
            "public_records_root": self.public_records_root,
            "state_root": self.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InsuranceVault {
    pub vault_id: String,
    pub status: VaultStatus,
    pub operator_commitment: String,
    pub insured_liquidity_commitment: String,
    pub reserved_collateral_commitment: String,
    pub premium_reserve_commitment: String,
    pub collateral_root: String,
    pub premium_root: String,
    pub liability_root: String,
    pub inventory_root: String,
    pub risk_curve_root: String,
    pub delta_bps: i64,
    pub gamma_bps: u64,
    pub utilization_bps: u64,
    pub collateral_coverage_bps: u64,
    pub premium_coverage_bps: u64,
}

impl InsuranceVault {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "status": self.status,
            "operator_commitment": self.operator_commitment,
            "insured_liquidity_commitment": self.insured_liquidity_commitment,
            "reserved_collateral_commitment": self.reserved_collateral_commitment,
            "premium_reserve_commitment": self.premium_reserve_commitment,
            "collateral_root": self.collateral_root,
            "premium_root": self.premium_root,
            "liability_root": self.liability_root,
            "inventory_root": self.inventory_root,
            "risk_curve_root": self.risk_curve_root,
            "delta_bps": self.delta_bps,
            "gamma_bps": self.gamma_bps,
            "utilization_bps": self.utilization_bps,
            "collateral_coverage_bps": self.collateral_coverage_bps,
            "premium_coverage_bps": self.premium_coverage_bps,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("insurance_vault", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialOptionSeries {
    pub series_id: String,
    pub vault_id: String,
    pub status: SeriesStatus,
    pub option_kind: InsuranceOptionKind,
    pub exercise_style: ExerciseStyle,
    pub strike_liquidity_bps: u64,
    pub expiry_l2_height: u64,
    pub barrier_liquidity_bps: Option<u64>,
    pub confidential_terms_root: String,
    pub option_token_supply_commitment: String,
    pub writer_inventory_commitment: String,
    pub premium_curve_root: String,
    pub payout_schedule_root: String,
    pub oracle_committee_root: String,
    pub max_payout_bps: u64,
}

impl ConfidentialOptionSeries {
    pub fn public_record(&self) -> Value {
        json!({
            "series_id": self.series_id,
            "vault_id": self.vault_id,
            "status": self.status,
            "option_kind": self.option_kind,
            "exercise_style": self.exercise_style,
            "strike_liquidity_bps": self.strike_liquidity_bps,
            "expiry_l2_height": self.expiry_l2_height,
            "barrier_liquidity_bps": self.barrier_liquidity_bps,
            "confidential_terms_root": self.confidential_terms_root,
            "option_token_supply_commitment": self.option_token_supply_commitment,
            "writer_inventory_commitment": self.writer_inventory_commitment,
            "premium_curve_root": self.premium_curve_root,
            "payout_schedule_root": self.payout_schedule_root,
            "oracle_committee_root": self.oracle_committee_root,
            "max_payout_bps": self.max_payout_bps,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("confidential_option_series", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CollateralAccount {
    pub account_id: String,
    pub vault_id: String,
    pub controller_commitment: String,
    pub collateral_asset_id: String,
    pub collateral_commitment: String,
    pub liability_commitment: String,
    pub locked_payout_commitment: String,
    pub withdrawal_nullifier_root: String,
    pub collateral_coverage_bps: u64,
    pub active: bool,
}

impl CollateralAccount {
    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "vault_id": self.vault_id,
            "controller_commitment": self.controller_commitment,
            "collateral_asset_id": self.collateral_asset_id,
            "collateral_commitment": self.collateral_commitment,
            "liability_commitment": self.liability_commitment,
            "locked_payout_commitment": self.locked_payout_commitment,
            "withdrawal_nullifier_root": self.withdrawal_nullifier_root,
            "collateral_coverage_bps": self.collateral_coverage_bps,
            "active": self.active,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("collateral_account", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PremiumAccount {
    pub account_id: String,
    pub vault_id: String,
    pub payer_commitment: String,
    pub premium_asset_id: String,
    pub premium_commitment: String,
    pub accrued_fee_commitment: String,
    pub refund_commitment: String,
    pub premium_nullifier_root: String,
    pub premium_coverage_bps: u64,
    pub active: bool,
}

impl PremiumAccount {
    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "vault_id": self.vault_id,
            "payer_commitment": self.payer_commitment,
            "premium_asset_id": self.premium_asset_id,
            "premium_commitment": self.premium_commitment,
            "accrued_fee_commitment": self.accrued_fee_commitment,
            "refund_commitment": self.refund_commitment,
            "premium_nullifier_root": self.premium_nullifier_root,
            "premium_coverage_bps": self.premium_coverage_bps,
            "active": self.active,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("premium_account", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedClaimIntent {
    pub intent_id: String,
    pub series_id: String,
    pub vault_id: String,
    pub status: ClaimIntentStatus,
    pub claimant_commitment: String,
    pub option_note_commitment: String,
    pub claim_nullifier: String,
    pub encrypted_claim_payload_root: String,
    pub observed_liquidity_root: String,
    pub requested_payout_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_claim_fee_bps: u64,
    pub created_l2_height: u64,
    pub expires_l2_height: u64,
}

impl SealedClaimIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "series_id": self.series_id,
            "vault_id": self.vault_id,
            "status": self.status,
            "claimant_commitment": self.claimant_commitment,
            "option_note_commitment": self.option_note_commitment,
            "claim_nullifier": self.claim_nullifier,
            "encrypted_claim_payload_root": self.encrypted_claim_payload_root,
            "observed_liquidity_root": self.observed_liquidity_root,
            "requested_payout_commitment": self.requested_payout_commitment,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_claim_fee_bps": self.max_claim_fee_bps,
            "created_l2_height": self.created_l2_height,
            "expires_l2_height": self.expires_l2_height,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("sealed_claim_intent", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqClaimCoupon {
    pub coupon_id: String,
    pub intent_id: String,
    pub series_id: String,
    pub vault_id: String,
    pub status: CouponStatus,
    pub signer_committee_root: String,
    pub encrypted_coupon_payload_root: String,
    pub payout_commitment: String,
    pub gross_claim_fee_micro_units: u128,
    pub net_claim_fee_micro_units: u128,
    pub premium_rebate_micro_units: u128,
    pub collateral_account_id: String,
    pub premium_account_id: String,
    pub collateral_root_before: String,
    pub premium_root_before: String,
    pub coupon_round: u64,
    pub pq_signature_root: String,
    pub expires_l2_height: u64,
}

impl PqClaimCoupon {
    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "intent_id": self.intent_id,
            "series_id": self.series_id,
            "vault_id": self.vault_id,
            "status": self.status,
            "signer_committee_root": self.signer_committee_root,
            "encrypted_coupon_payload_root": self.encrypted_coupon_payload_root,
            "payout_commitment": self.payout_commitment,
            "gross_claim_fee_micro_units": self.gross_claim_fee_micro_units,
            "net_claim_fee_micro_units": self.net_claim_fee_micro_units,
            "premium_rebate_micro_units": self.premium_rebate_micro_units,
            "collateral_account_id": self.collateral_account_id,
            "premium_account_id": self.premium_account_id,
            "collateral_root_before": self.collateral_root_before,
            "premium_root_before": self.premium_root_before,
            "coupon_round": self.coupon_round,
            "pq_signature_root": self.pq_signature_root,
            "expires_l2_height": self.expires_l2_height,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("pq_claim_coupon", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeClaimNettingWindow {
    pub window_id: String,
    pub vault_id: String,
    pub status: NettingStatus,
    pub coupon_ids: Vec<String>,
    pub gross_claim_fee_micro_units: u128,
    pub net_claim_fee_micro_units: u128,
    pub premium_rebate_micro_units: u128,
    pub settlement_root: String,
    pub netting_proof_root: String,
    pub collateral_root_after: String,
    pub premium_root_after: String,
    pub opened_l2_height: u64,
    pub closed_l2_height: u64,
}

impl LowFeeClaimNettingWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "vault_id": self.vault_id,
            "status": self.status,
            "coupon_ids": self.coupon_ids,
            "gross_claim_fee_micro_units": self.gross_claim_fee_micro_units,
            "net_claim_fee_micro_units": self.net_claim_fee_micro_units,
            "premium_rebate_micro_units": self.premium_rebate_micro_units,
            "settlement_root": self.settlement_root,
            "netting_proof_root": self.netting_proof_root,
            "collateral_root_after": self.collateral_root_after,
            "premium_root_after": self.premium_root_after,
            "opened_l2_height": self.opened_l2_height,
            "closed_l2_height": self.closed_l2_height,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("low_fee_claim_netting_window", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub record_root: String,
    pub state_root_after: String,
    pub sequence: u64,
}

impl DeterministicPublicRecord {
    pub fn new(record_kind: &str, sequence: u64, record: &Value, state_root_after: &str) -> Self {
        let record_root = payload_root(record_kind, record);
        let record_id = deterministic_id(
            "LIQUIDITY-INSURANCE-PUBLIC-RECORD",
            &[
                HashPart::Str(record_kind),
                HashPart::U64(sequence),
                HashPart::Str(&record_root),
                HashPart::Str(state_root_after),
            ],
        );
        Self {
            record_id,
            record_kind: record_kind.to_string(),
            record_root,
            state_root_after: state_root_after.to_string(),
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "record_root": self.record_root,
            "state_root_after": self.state_root_after,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterVaultInput {
    pub vault_id: String,
    pub operator_commitment: String,
    pub insured_liquidity_commitment: String,
    pub reserved_collateral_commitment: String,
    pub premium_reserve_commitment: String,
    pub collateral_root: String,
    pub premium_root: String,
    pub liability_root: String,
    pub inventory_root: String,
    pub risk_curve_root: String,
    pub delta_bps: i64,
    pub gamma_bps: u64,
    pub utilization_bps: u64,
    pub collateral_coverage_bps: u64,
    pub premium_coverage_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenSeriesInput {
    pub vault_id: String,
    pub option_kind: InsuranceOptionKind,
    pub exercise_style: ExerciseStyle,
    pub strike_liquidity_bps: u64,
    pub expiry_l2_height: u64,
    pub barrier_liquidity_bps: Option<u64>,
    pub confidential_terms_root: String,
    pub option_token_supply_commitment: String,
    pub writer_inventory_commitment: String,
    pub premium_curve_root: String,
    pub payout_schedule_root: String,
    pub oracle_committee_root: String,
    pub max_payout_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealClaimIntentInput {
    pub series_id: String,
    pub claimant_commitment: String,
    pub option_note_commitment: String,
    pub claim_nullifier: String,
    pub encrypted_claim_payload_root: String,
    pub observed_liquidity_root: String,
    pub requested_payout_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_claim_fee_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignClaimCouponInput {
    pub intent_id: String,
    pub signer_committee_root: String,
    pub encrypted_coupon_payload_root: String,
    pub payout_commitment: String,
    pub gross_claim_fee_micro_units: u128,
    pub collateral_account_id: String,
    pub premium_account_id: String,
    pub collateral_root_before: String,
    pub premium_root_before: String,
    pub coupon_round: u64,
    pub pq_signature_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetClaimCouponsInput {
    pub vault_id: String,
    pub coupon_ids: Vec<String>,
    pub settlement_root: String,
    pub netting_proof_root: String,
    pub collateral_root_after: String,
    pub premium_root_after: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub roots: Roots,
    pub counters: Counters,
    pub vaults: BTreeMap<String, InsuranceVault>,
    pub option_series: BTreeMap<String, ConfidentialOptionSeries>,
    pub collateral_accounts: BTreeMap<String, CollateralAccount>,
    pub premium_accounts: BTreeMap<String, PremiumAccount>,
    pub claim_intents: BTreeMap<String, SealedClaimIntent>,
    pub claim_coupons: BTreeMap<String, PqClaimCoupon>,
    pub netting_windows: BTreeMap<String, LowFeeClaimNettingWindow>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, DeterministicPublicRecord>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        let mut state = Self {
            config,
            roots,
            counters,
            vaults: BTreeMap::new(),
            option_series: BTreeMap::new(),
            collateral_accounts: BTreeMap::new(),
            premium_accounts: BTreeMap::new(),
            claim_intents: BTreeMap::new(),
            claim_coupons: BTreeMap::new(),
            netting_windows: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("valid devnet config");
        state.install_devnet_fixtures();
        state.refresh_roots();
        state
    }

    pub fn register_vault(&mut self, input: RegisterVaultInput) -> Result<String> {
        require(
            self.vaults.len() < self.config.max_vaults,
            "vault limit reached",
        )?;
        require(!input.vault_id.trim().is_empty(), "vault id is empty")?;
        require(
            !self.vaults.contains_key(&input.vault_id),
            "vault already exists",
        )?;
        require_root("operator commitment", &input.operator_commitment)?;
        require_root(
            "insured liquidity commitment",
            &input.insured_liquidity_commitment,
        )?;
        require_root(
            "reserved collateral commitment",
            &input.reserved_collateral_commitment,
        )?;
        require_root(
            "premium reserve commitment",
            &input.premium_reserve_commitment,
        )?;
        require_root("collateral root", &input.collateral_root)?;
        require_root("premium root", &input.premium_root)?;
        require_root("liability root", &input.liability_root)?;
        require_root("inventory root", &input.inventory_root)?;
        require_root("risk curve root", &input.risk_curve_root)?;
        require_bps("gamma bps", input.gamma_bps)?;
        require_bps("utilization bps", input.utilization_bps)?;
        require(
            input.delta_bps.abs() <= self.config.max_vault_delta_abs_bps,
            "vault delta exceeds configured bound",
        )?;
        require(
            input.gamma_bps <= self.config.max_vault_gamma_bps,
            "vault gamma exceeds configured bound",
        )?;
        require(
            input.collateral_coverage_bps >= self.config.min_collateral_coverage_bps,
            "collateral coverage below configured minimum",
        )?;
        require(
            input.premium_coverage_bps >= self.config.min_premium_coverage_bps,
            "premium coverage below configured minimum",
        )?;

        let vault = InsuranceVault {
            vault_id: input.vault_id.clone(),
            status: VaultStatus::Active,
            operator_commitment: input.operator_commitment,
            insured_liquidity_commitment: input.insured_liquidity_commitment,
            reserved_collateral_commitment: input.reserved_collateral_commitment,
            premium_reserve_commitment: input.premium_reserve_commitment,
            collateral_root: input.collateral_root,
            premium_root: input.premium_root,
            liability_root: input.liability_root,
            inventory_root: input.inventory_root,
            risk_curve_root: input.risk_curve_root,
            delta_bps: input.delta_bps,
            gamma_bps: input.gamma_bps,
            utilization_bps: input.utilization_bps,
            collateral_coverage_bps: input.collateral_coverage_bps,
            premium_coverage_bps: input.premium_coverage_bps,
        };
        let vault_id = vault.vault_id.clone();
        self.vaults.insert(vault_id.clone(), vault.clone());
        self.counters.vaults = self.vaults.len() as u64;
        self.record_public("vault_registered", &vault.public_record())?;
        Ok(vault_id)
    }

    pub fn open_confidential_series(&mut self, input: OpenSeriesInput) -> Result<String> {
        require(
            self.option_series.len() < self.config.max_series,
            "option series limit reached",
        )?;
        let vault = self
            .vaults
            .get(&input.vault_id)
            .ok_or_else(|| "unknown vault".to_string())?;
        require(
            vault.status.accepts_premiums(),
            "vault does not accept premiums",
        )?;
        require_bps("strike liquidity bps", input.strike_liquidity_bps)?;
        if let Some(barrier) = input.barrier_liquidity_bps {
            require_bps("barrier liquidity bps", barrier)?;
        }
        require(
            input.expiry_l2_height > self.config.l2_height,
            "series expiry must be in the future",
        )?;
        require_root("confidential terms root", &input.confidential_terms_root)?;
        require_root(
            "option token supply commitment",
            &input.option_token_supply_commitment,
        )?;
        require_root(
            "writer inventory commitment",
            &input.writer_inventory_commitment,
        )?;
        require_root("premium curve root", &input.premium_curve_root)?;
        require_root("payout schedule root", &input.payout_schedule_root)?;
        require_root("oracle committee root", &input.oracle_committee_root)?;
        require_bps("max payout bps", input.max_payout_bps)?;
        require(
            input.max_payout_bps <= self.config.max_payout_bps,
            "series payout exceeds configured maximum",
        )?;

        let sequence = self.next_sequence();
        let series_id = deterministic_id(
            "LIQUIDITY-INSURANCE-SERIES",
            &[
                HashPart::Str(&input.vault_id),
                HashPart::Str(input.option_kind.as_str()),
                HashPart::Str(input.exercise_style.as_str()),
                HashPart::U64(input.strike_liquidity_bps),
                HashPart::U64(input.expiry_l2_height),
                HashPart::Str(&input.confidential_terms_root),
                HashPart::U64(sequence),
            ],
        );
        let series = ConfidentialOptionSeries {
            series_id: series_id.clone(),
            vault_id: input.vault_id,
            status: SeriesStatus::Open,
            option_kind: input.option_kind,
            exercise_style: input.exercise_style,
            strike_liquidity_bps: input.strike_liquidity_bps,
            expiry_l2_height: input.expiry_l2_height,
            barrier_liquidity_bps: input.barrier_liquidity_bps,
            confidential_terms_root: input.confidential_terms_root,
            option_token_supply_commitment: input.option_token_supply_commitment,
            writer_inventory_commitment: input.writer_inventory_commitment,
            premium_curve_root: input.premium_curve_root,
            payout_schedule_root: input.payout_schedule_root,
            oracle_committee_root: input.oracle_committee_root,
            max_payout_bps: input.max_payout_bps,
        };
        self.option_series.insert(series_id.clone(), series.clone());
        self.counters.option_series = self.option_series.len() as u64;
        self.record_public("confidential_series_opened", &series.public_record())?;
        Ok(series_id)
    }

    pub fn upsert_collateral_account(&mut self, mut account: CollateralAccount) -> Result<String> {
        require(
            self.collateral_accounts.len() < self.config.max_vaults * 16
                || self.collateral_accounts.contains_key(&account.account_id),
            "collateral account limit reached",
        )?;
        require(self.vaults.contains_key(&account.vault_id), "unknown vault")?;
        require_root("controller commitment", &account.controller_commitment)?;
        require_root("collateral commitment", &account.collateral_commitment)?;
        require_root("liability commitment", &account.liability_commitment)?;
        require_root(
            "locked payout commitment",
            &account.locked_payout_commitment,
        )?;
        require_root(
            "withdrawal nullifier root",
            &account.withdrawal_nullifier_root,
        )?;
        require(
            account.collateral_coverage_bps >= self.config.min_collateral_coverage_bps,
            "collateral account coverage below configured minimum",
        )?;
        if account.account_id.is_empty() {
            account.account_id = deterministic_id(
                "LIQUIDITY-INSURANCE-COLLATERAL-ACCOUNT",
                &[
                    HashPart::Str(&account.vault_id),
                    HashPart::Str(&account.controller_commitment),
                    HashPart::Str(&account.collateral_commitment),
                ],
            );
        }
        let account_id = account.account_id.clone();
        self.collateral_accounts
            .insert(account_id.clone(), account.clone());
        self.counters.collateral_accounts = self.collateral_accounts.len() as u64;
        self.record_public("collateral_account_upserted", &account.public_record())?;
        Ok(account_id)
    }

    pub fn upsert_premium_account(&mut self, mut account: PremiumAccount) -> Result<String> {
        require(
            self.premium_accounts.len() < self.config.max_vaults * 16
                || self.premium_accounts.contains_key(&account.account_id),
            "premium account limit reached",
        )?;
        require(self.vaults.contains_key(&account.vault_id), "unknown vault")?;
        require_root("payer commitment", &account.payer_commitment)?;
        require_root("premium commitment", &account.premium_commitment)?;
        require_root("accrued fee commitment", &account.accrued_fee_commitment)?;
        require_root("refund commitment", &account.refund_commitment)?;
        require_root("premium nullifier root", &account.premium_nullifier_root)?;
        require(
            account.premium_coverage_bps >= self.config.min_premium_coverage_bps,
            "premium account coverage below configured minimum",
        )?;
        if account.account_id.is_empty() {
            account.account_id = deterministic_id(
                "LIQUIDITY-INSURANCE-PREMIUM-ACCOUNT",
                &[
                    HashPart::Str(&account.vault_id),
                    HashPart::Str(&account.payer_commitment),
                    HashPart::Str(&account.premium_commitment),
                ],
            );
        }
        let account_id = account.account_id.clone();
        self.premium_accounts
            .insert(account_id.clone(), account.clone());
        self.counters.premium_accounts = self.premium_accounts.len() as u64;
        self.record_public("premium_account_upserted", &account.public_record())?;
        Ok(account_id)
    }

    pub fn seal_claim_intent(&mut self, input: SealClaimIntentInput) -> Result<String> {
        require(
            self.claim_intents.len() < self.config.max_claim_intents,
            "claim intent limit reached",
        )?;
        let series = self
            .option_series
            .get(&input.series_id)
            .ok_or_else(|| "unknown option series".to_string())?;
        require(
            series.status.accepts_claims(),
            "series does not accept claims",
        )?;
        let vault_id = series.vault_id.clone();
        let vault = self
            .vaults
            .get(&vault_id)
            .ok_or_else(|| "unknown vault".to_string())?;
        require(
            vault.status.accepts_claims(),
            "vault does not accept claims",
        )?;
        require_root("claimant commitment", &input.claimant_commitment)?;
        require_root("option note commitment", &input.option_note_commitment)?;
        require_root("claim nullifier", &input.claim_nullifier)?;
        require_root(
            "encrypted claim payload root",
            &input.encrypted_claim_payload_root,
        )?;
        require_root("observed liquidity root", &input.observed_liquidity_root)?;
        require_root(
            "requested payout commitment",
            &input.requested_payout_commitment,
        )?;
        require_bps("max claim fee bps", input.max_claim_fee_bps)?;
        require(
            input.max_claim_fee_bps >= self.config.target_net_claim_fee_bps,
            "max claim fee below target net claim fee",
        )?;
        require_privacy_and_pq(
            input.privacy_set_size,
            input.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        self.consume_nullifier(&input.claim_nullifier)?;

        let sequence = self.next_sequence();
        let intent_id = deterministic_id(
            "LIQUIDITY-INSURANCE-CLAIM-INTENT",
            &[
                HashPart::Str(&input.series_id),
                HashPart::Str(&input.claimant_commitment),
                HashPart::Str(&input.option_note_commitment),
                HashPart::Str(&input.claim_nullifier),
                HashPart::U64(sequence),
            ],
        );
        let intent = SealedClaimIntent {
            intent_id: intent_id.clone(),
            series_id: input.series_id,
            vault_id,
            status: ClaimIntentStatus::PrivacyChecked,
            claimant_commitment: input.claimant_commitment,
            option_note_commitment: input.option_note_commitment,
            claim_nullifier: input.claim_nullifier,
            encrypted_claim_payload_root: input.encrypted_claim_payload_root,
            observed_liquidity_root: input.observed_liquidity_root,
            requested_payout_commitment: input.requested_payout_commitment,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            max_claim_fee_bps: input.max_claim_fee_bps,
            created_l2_height: self.config.l2_height,
            expires_l2_height: self
                .config
                .l2_height
                .saturating_add(self.config.claim_ttl_blocks),
        };
        self.claim_intents.insert(intent_id.clone(), intent.clone());
        self.counters.claim_intents = self.claim_intents.len() as u64;
        self.record_public("claim_intent_sealed", &intent.public_record())?;
        Ok(intent_id)
    }

    pub fn sign_claim_coupon(&mut self, input: SignClaimCouponInput) -> Result<String> {
        require(
            self.claim_coupons.len() < self.config.max_coupons,
            "claim coupon limit reached",
        )?;
        let intent = self
            .claim_intents
            .get(&input.intent_id)
            .ok_or_else(|| "unknown claim intent".to_string())?
            .clone();
        require(intent.status.is_nettable(), "claim intent is not nettable")?;
        require(
            self.collateral_accounts
                .get(&input.collateral_account_id)
                .map(|account| account.active && account.vault_id == intent.vault_id)
                .unwrap_or(false),
            "collateral account is unavailable",
        )?;
        require(
            self.premium_accounts
                .get(&input.premium_account_id)
                .map(|account| account.active && account.vault_id == intent.vault_id)
                .unwrap_or(false),
            "premium account is unavailable",
        )?;
        require_root("signer committee root", &input.signer_committee_root)?;
        require_root(
            "encrypted coupon payload root",
            &input.encrypted_coupon_payload_root,
        )?;
        require_root("payout commitment", &input.payout_commitment)?;
        require_root("collateral root before", &input.collateral_root_before)?;
        require_root("premium root before", &input.premium_root_before)?;
        require_root("pq signature root", &input.pq_signature_root)?;

        let net_claim_fee_micro_units = bps_amount(
            input.gross_claim_fee_micro_units,
            self.config.target_net_claim_fee_bps,
        );
        let premium_rebate_micro_units = premium_rebate_for_fee(
            input.gross_claim_fee_micro_units,
            net_claim_fee_micro_units,
            self.config.premium_rebate_share_bps,
        );
        let sequence = self.next_sequence();
        let coupon_id = deterministic_id(
            "LIQUIDITY-INSURANCE-CLAIM-COUPON",
            &[
                HashPart::Str(&input.intent_id),
                HashPart::Str(&input.signer_committee_root),
                HashPart::Str(&input.pq_signature_root),
                HashPart::U64(input.coupon_round),
                HashPart::U64(sequence),
            ],
        );
        let coupon = PqClaimCoupon {
            coupon_id: coupon_id.clone(),
            intent_id: input.intent_id.clone(),
            series_id: intent.series_id.clone(),
            vault_id: intent.vault_id.clone(),
            status: CouponStatus::PqSigned,
            signer_committee_root: input.signer_committee_root,
            encrypted_coupon_payload_root: input.encrypted_coupon_payload_root,
            payout_commitment: input.payout_commitment,
            gross_claim_fee_micro_units: input.gross_claim_fee_micro_units,
            net_claim_fee_micro_units,
            premium_rebate_micro_units,
            collateral_account_id: input.collateral_account_id,
            premium_account_id: input.premium_account_id,
            collateral_root_before: input.collateral_root_before,
            premium_root_before: input.premium_root_before,
            coupon_round: input.coupon_round,
            pq_signature_root: input.pq_signature_root,
            expires_l2_height: intent.expires_l2_height,
        };
        self.claim_coupons.insert(coupon_id.clone(), coupon.clone());
        if let Some(intent) = self.claim_intents.get_mut(&input.intent_id) {
            intent.status = ClaimIntentStatus::CouponSigned;
        }
        self.counters.claim_coupons = self.claim_coupons.len() as u64;
        self.record_public("claim_coupon_pq_signed", &coupon.public_record())?;
        Ok(coupon_id)
    }

    pub fn net_low_fee_claim_coupons(&mut self, input: NetClaimCouponsInput) -> Result<String> {
        require(
            self.netting_windows.len() < self.config.max_coupons,
            "netting window limit reached",
        )?;
        require(self.vaults.contains_key(&input.vault_id), "unknown vault")?;
        require(!input.coupon_ids.is_empty(), "coupon list is empty")?;
        require(
            input.coupon_ids.len() <= self.config.max_netting_items,
            "too many coupons for netting window",
        )?;
        require_unique("coupon ids", &input.coupon_ids)?;
        require_root("settlement root", &input.settlement_root)?;
        require_root("netting proof root", &input.netting_proof_root)?;
        require_root("collateral root after", &input.collateral_root_after)?;
        require_root("premium root after", &input.premium_root_after)?;

        let mut gross_claim_fee_micro_units = 0_u128;
        let mut net_claim_fee_micro_units = 0_u128;
        let mut premium_rebate_micro_units = 0_u128;
        for coupon_id in &input.coupon_ids {
            let coupon = self
                .claim_coupons
                .get(coupon_id)
                .ok_or_else(|| format!("unknown claim coupon {coupon_id}"))?;
            require(coupon.vault_id == input.vault_id, "coupon vault mismatch")?;
            require(
                matches!(
                    coupon.status,
                    CouponStatus::PqSigned | CouponStatus::Admitted
                ),
                "coupon is not eligible for netting",
            )?;
            gross_claim_fee_micro_units =
                gross_claim_fee_micro_units.saturating_add(coupon.gross_claim_fee_micro_units);
            net_claim_fee_micro_units =
                net_claim_fee_micro_units.saturating_add(coupon.net_claim_fee_micro_units);
            premium_rebate_micro_units =
                premium_rebate_micro_units.saturating_add(coupon.premium_rebate_micro_units);
        }

        let sequence = self.next_sequence();
        let window_id = deterministic_id(
            "LIQUIDITY-INSURANCE-LOW-FEE-NETTING-WINDOW",
            &[
                HashPart::Str(&input.vault_id),
                HashPart::Json(&json!(input.coupon_ids)),
                HashPart::Str(&input.settlement_root),
                HashPart::Str(&input.netting_proof_root),
                HashPart::U64(sequence),
            ],
        );
        let window = LowFeeClaimNettingWindow {
            window_id: window_id.clone(),
            vault_id: input.vault_id,
            status: NettingStatus::Settled,
            coupon_ids: input.coupon_ids.clone(),
            gross_claim_fee_micro_units,
            net_claim_fee_micro_units,
            premium_rebate_micro_units,
            settlement_root: input.settlement_root,
            netting_proof_root: input.netting_proof_root,
            collateral_root_after: input.collateral_root_after,
            premium_root_after: input.premium_root_after,
            opened_l2_height: self.config.l2_height,
            closed_l2_height: self
                .config
                .l2_height
                .saturating_add(self.config.netting_window_blocks),
        };
        for coupon_id in &input.coupon_ids {
            if let Some(coupon) = self.claim_coupons.get_mut(coupon_id) {
                coupon.status = CouponStatus::Netted;
                if let Some(intent) = self.claim_intents.get_mut(&coupon.intent_id) {
                    intent.status = ClaimIntentStatus::Netted;
                }
            }
        }
        self.netting_windows
            .insert(window_id.clone(), window.clone());
        self.counters.netting_windows = self.netting_windows.len() as u64;
        self.record_public("low_fee_claim_coupons_netted", &window.public_record())?;
        Ok(window_id)
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "runtime": "private_l2_pq_confidential_tokenized_liquidity_insurance_options_vault",
            "privacy_model": {
                "record_policy": "roots_only",
                "claim_payloads": "encrypted",
                "option_terms": "confidential",
                "pq_claim_coupons": "signature_roots_only",
                "collateral": "commitment_roots_only",
                "premiums": "commitment_roots_only"
            },
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.state_root(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn roots(&self) -> Roots {
        let counters = self.current_counters();
        let mut roots = Roots {
            config_root: self.config.state_root(),
            counters_root: counters.state_root(),
            vaults_root: merkle_root(
                INSURANCE_VAULT_SUITE,
                &self
                    .vaults
                    .values()
                    .map(InsuranceVault::public_record)
                    .collect::<Vec<_>>(),
            ),
            option_series_root: merkle_root(
                CONFIDENTIAL_SERIES_SUITE,
                &self
                    .option_series
                    .values()
                    .map(ConfidentialOptionSeries::public_record)
                    .collect::<Vec<_>>(),
            ),
            collateral_accounts_root: merkle_root(
                "liquidity-insurance-collateral-account-record-root-v1",
                &self
                    .collateral_accounts
                    .values()
                    .map(CollateralAccount::public_record)
                    .collect::<Vec<_>>(),
            ),
            collateral_commitments_root: merkle_root(
                COLLATERAL_ROOT_SUITE,
                &self
                    .collateral_accounts
                    .values()
                    .map(|account| {
                        json!({
                            "account_id": account.account_id,
                            "vault_id": account.vault_id,
                            "collateral_commitment": account.collateral_commitment,
                            "liability_commitment": account.liability_commitment,
                            "locked_payout_commitment": account.locked_payout_commitment,
                            "coverage_bps": account.collateral_coverage_bps,
                        })
                    })
                    .collect::<Vec<_>>(),
            ),
            premium_accounts_root: merkle_root(
                "liquidity-insurance-premium-account-record-root-v1",
                &self
                    .premium_accounts
                    .values()
                    .map(PremiumAccount::public_record)
                    .collect::<Vec<_>>(),
            ),
            premium_commitments_root: merkle_root(
                PREMIUM_ROOT_SUITE,
                &self
                    .premium_accounts
                    .values()
                    .map(|account| {
                        json!({
                            "account_id": account.account_id,
                            "vault_id": account.vault_id,
                            "premium_commitment": account.premium_commitment,
                            "accrued_fee_commitment": account.accrued_fee_commitment,
                            "refund_commitment": account.refund_commitment,
                            "coverage_bps": account.premium_coverage_bps,
                        })
                    })
                    .collect::<Vec<_>>(),
            ),
            claim_intents_root: merkle_root(
                CLAIM_INTENT_SUITE,
                &self
                    .claim_intents
                    .values()
                    .map(SealedClaimIntent::public_record)
                    .collect::<Vec<_>>(),
            ),
            claim_coupons_root: merkle_root(
                CLAIM_COUPON_ROOT_SUITE,
                &self
                    .claim_coupons
                    .values()
                    .map(PqClaimCoupon::public_record)
                    .collect::<Vec<_>>(),
            ),
            low_fee_netting_root: merkle_root(
                LOW_FEE_NETTING_SUITE,
                &self
                    .netting_windows
                    .values()
                    .map(LowFeeClaimNettingWindow::public_record)
                    .collect::<Vec<_>>(),
            ),
            nullifier_root: merkle_root(
                "liquidity-insurance-consumed-claim-nullifier-root-v1",
                &self
                    .consumed_nullifiers
                    .iter()
                    .map(|nullifier| json!({ "claim_nullifier": nullifier }))
                    .collect::<Vec<_>>(),
            ),
            public_records_root: merkle_root(
                PUBLIC_RECORD_SUITE,
                &self
                    .public_records
                    .values()
                    .map(DeterministicPublicRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            state_root: String::new(),
        };
        roots.state_root = domain_hash(
            STATE_ROOT_SUITE,
            &[
                HashPart::Str(&self.config.protocol_version),
                HashPart::U64(self.config.schema_version),
                HashPart::Str(&self.config.chain_id),
                HashPart::Str(&self.config.vault_runtime_id),
                HashPart::U64(self.config.l2_height),
                HashPart::U64(self.config.monero_height),
                HashPart::Str(&roots.config_root),
                HashPart::Str(&roots.counters_root),
                HashPart::Str(&roots.vaults_root),
                HashPart::Str(&roots.option_series_root),
                HashPart::Str(&roots.collateral_accounts_root),
                HashPart::Str(&roots.collateral_commitments_root),
                HashPart::Str(&roots.premium_accounts_root),
                HashPart::Str(&roots.premium_commitments_root),
                HashPart::Str(&roots.claim_intents_root),
                HashPart::Str(&roots.claim_coupons_root),
                HashPart::Str(&roots.low_fee_netting_root),
                HashPart::Str(&roots.nullifier_root),
                HashPart::Str(&roots.public_records_root),
            ],
            32,
        );
        roots
    }

    fn current_counters(&self) -> Counters {
        let mut counters = self.counters.clone();
        counters.vaults = self.vaults.len() as u64;
        counters.option_series = self.option_series.len() as u64;
        counters.collateral_accounts = self.collateral_accounts.len() as u64;
        counters.premium_accounts = self.premium_accounts.len() as u64;
        counters.claim_intents = self.claim_intents.len() as u64;
        counters.claim_coupons = self.claim_coupons.len() as u64;
        counters.netting_windows = self.netting_windows.len() as u64;
        counters.consumed_nullifiers = self.consumed_nullifiers.len() as u64;
        counters.public_records = self.public_records.len() as u64;
        counters
    }

    fn refresh_roots(&mut self) {
        self.counters = self.current_counters();
        self.roots = self.roots();
    }

    fn next_sequence(&mut self) -> u64 {
        self.counters.sequence = self.counters.sequence.saturating_add(1);
        self.counters.sequence
    }

    fn record_public(&mut self, record_kind: &str, record: &Value) -> Result<()> {
        self.refresh_roots();
        let next_state_root = self.roots.state_root.clone();
        let sequence = self.next_sequence();
        let public_record =
            DeterministicPublicRecord::new(record_kind, sequence, record, &next_state_root);
        require(
            !self.public_records.contains_key(&public_record.record_id),
            "public record collision",
        )?;
        self.public_records
            .insert(public_record.record_id.clone(), public_record);
        self.counters.public_records = self.public_records.len() as u64;
        self.refresh_roots();
        Ok(())
    }

    fn consume_nullifier(&mut self, nullifier: &str) -> Result<()> {
        let nullifier_hash = deterministic_id(
            "LIQUIDITY-INSURANCE-CLAIM-NULLIFIER",
            &[HashPart::Str(nullifier)],
        );
        require(
            self.consumed_nullifiers.insert(nullifier_hash),
            "claim nullifier replay detected",
        )?;
        self.counters.consumed_nullifiers = self.consumed_nullifiers.len() as u64;
        Ok(())
    }

    fn install_devnet_fixtures(&mut self) {
        let vault_id = self
            .register_vault(RegisterVaultInput {
                vault_id: "liquidity-insurance-options-pxmr-dusd-devnet".to_string(),
                operator_commitment: hex_root("devnet-vault-operator", 1),
                insured_liquidity_commitment: hex_root("devnet-insured-liquidity", 1),
                reserved_collateral_commitment: hex_root("devnet-reserved-collateral", 1),
                premium_reserve_commitment: hex_root("devnet-premium-reserve", 1),
                collateral_root: hex_root("devnet-vault-collateral-root", 1),
                premium_root: hex_root("devnet-vault-premium-root", 1),
                liability_root: hex_root("devnet-vault-liability-root", 1),
                inventory_root: hex_root("devnet-vault-inventory-root", 1),
                risk_curve_root: hex_root("devnet-vault-risk-curve", 1),
                delta_bps: 2_250,
                gamma_bps: 410,
                utilization_bps: 6_450,
                collateral_coverage_bps: 11_800,
                premium_coverage_bps: 1_180,
            })
            .expect("devnet vault");
        let series_id = self
            .open_confidential_series(OpenSeriesInput {
                vault_id: vault_id.clone(),
                option_kind: InsuranceOptionKind::DrawdownBinary,
                exercise_style: ExerciseStyle::European,
                strike_liquidity_bps: 7_200,
                expiry_l2_height: DEVNET_L2_HEIGHT + 21_600,
                barrier_liquidity_bps: Some(8_350),
                confidential_terms_root: hex_root("devnet-series-terms", 1),
                option_token_supply_commitment: hex_root("devnet-series-supply", 1),
                writer_inventory_commitment: hex_root("devnet-writer-inventory", 1),
                premium_curve_root: hex_root("devnet-premium-curve", 1),
                payout_schedule_root: hex_root("devnet-payout-schedule", 1),
                oracle_committee_root: hex_root("devnet-oracle-committee", 1),
                max_payout_bps: 7_250,
            })
            .expect("devnet series");
        let collateral_account_id = self
            .upsert_collateral_account(CollateralAccount {
                account_id: String::new(),
                vault_id: vault_id.clone(),
                controller_commitment: hex_root("devnet-collateral-controller", 1),
                collateral_asset_id: DEVNET_COLLATERAL_ASSET_ID.to_string(),
                collateral_commitment: hex_root("devnet-collateral", 1),
                liability_commitment: hex_root("devnet-collateral-liability", 1),
                locked_payout_commitment: hex_root("devnet-locked-payout", 1),
                withdrawal_nullifier_root: hex_root("devnet-withdrawal-nullifiers", 1),
                collateral_coverage_bps: 11_900,
                active: true,
            })
            .expect("devnet collateral account");
        let premium_account_id = self
            .upsert_premium_account(PremiumAccount {
                account_id: String::new(),
                vault_id: vault_id.clone(),
                payer_commitment: hex_root("devnet-premium-payer", 1),
                premium_asset_id: DEVNET_PREMIUM_ASSET_ID.to_string(),
                premium_commitment: hex_root("devnet-premium", 1),
                accrued_fee_commitment: hex_root("devnet-premium-accrued-fee", 1),
                refund_commitment: hex_root("devnet-premium-refund", 1),
                premium_nullifier_root: hex_root("devnet-premium-nullifiers", 1),
                premium_coverage_bps: 1_240,
                active: true,
            })
            .expect("devnet premium account");
        let intent_id = self
            .seal_claim_intent(SealClaimIntentInput {
                series_id,
                claimant_commitment: hex_root("devnet-claimant", 1),
                option_note_commitment: hex_root("devnet-option-note", 1),
                claim_nullifier: hex_root("devnet-claim-nullifier", 1),
                encrypted_claim_payload_root: hex_root("devnet-claim-payload", 1),
                observed_liquidity_root: hex_root("devnet-observed-liquidity", 1),
                requested_payout_commitment: hex_root("devnet-requested-payout", 1),
                privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
                pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                max_claim_fee_bps: 12,
            })
            .expect("devnet claim intent");
        let coupon_id = self
            .sign_claim_coupon(SignClaimCouponInput {
                intent_id,
                signer_committee_root: hex_root("devnet-coupon-committee", 1),
                encrypted_coupon_payload_root: hex_root("devnet-coupon-payload", 1),
                payout_commitment: hex_root("devnet-coupon-payout", 1),
                gross_claim_fee_micro_units: 1_740_000,
                collateral_account_id,
                premium_account_id,
                collateral_root_before: hex_root("devnet-collateral-root-before", 1),
                premium_root_before: hex_root("devnet-premium-root-before", 1),
                coupon_round: 91,
                pq_signature_root: hex_root("devnet-coupon-pq-signature", 1),
            })
            .expect("devnet claim coupon");
        self.net_low_fee_claim_coupons(NetClaimCouponsInput {
            vault_id,
            coupon_ids: vec![coupon_id],
            settlement_root: hex_root("devnet-low-fee-settlement", 1),
            netting_proof_root: hex_root("devnet-low-fee-netting-proof", 1),
            collateral_root_after: hex_root("devnet-collateral-root-after", 1),
            premium_root_after: hex_root("devnet-premium-root-after", 1),
        })
        .expect("devnet low-fee claim netting");
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

pub fn private_l2_pq_confidential_tokenized_liquidity_insurance_options_vault_runtime_public_record(
) -> Value {
    State::devnet().public_record()
}

pub fn private_l2_pq_confidential_tokenized_liquidity_insurance_options_vault_runtime_state_root(
) -> String {
    State::devnet().state_root()
}

fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    format!(
        "{}:{}",
        domain.to_ascii_lowercase().replace('_', "-"),
        domain_hash(
            &format!(
                "{}:{}",
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_LIQUIDITY_INSURANCE_OPTIONS_VAULT_RUNTIME_PROTOCOL_VERSION,
                domain
            ),
            parts,
            16,
        )
    )
}

fn payload_root(label: &str, value: &Value) -> String {
    domain_hash(
        PAYLOAD_ROOT_SUITE,
        &[HashPart::Str(label), HashPart::Json(value)],
        32,
    )
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    require(
        value <= MAX_BPS,
        &format!("{label} exceeds basis point maximum"),
    )
}

fn require_root(label: &str, value: &str) -> Result<()> {
    require(
        value.len() >= 32 && value.chars().all(|ch| ch.is_ascii_hexdigit()),
        &format!("{label} must be a hex commitment/root of at least 32 chars"),
    )
}

fn require_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> Result<()> {
    require(
        privacy_set_size >= min_privacy_set_size,
        "privacy set is below configured anonymity threshold",
    )?;
    require(
        pq_security_bits >= min_pq_security_bits,
        "PQ claim authorization security bits below configured minimum",
    )
}

fn require_unique(label: &str, values: &[String]) -> Result<()> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    require(
        unique.len() == values.len(),
        &format!("{label} must be unique"),
    )
}

fn bps_amount(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn premium_rebate_for_fee(gross_fee: u128, net_fee: u128, rebate_share_bps: u64) -> u128 {
    gross_fee
        .saturating_sub(net_fee)
        .saturating_mul(rebate_share_bps as u128)
        / MAX_BPS as u128
}

fn hex_root(label: &str, index: u64) -> String {
    domain_hash(
        "private-l2-pq-confidential-tokenized-liquidity-insurance-options-vault-devnet-root-v1",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}
