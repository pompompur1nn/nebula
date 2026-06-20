use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedLiquidityReceiptPerpAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_LIQUIDITY_RECEIPT_PERP_AMM_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-liquidity-receipt-perp-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_LIQUIDITY_RECEIPT_PERP_AMM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ORACLE_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-liquidity-receipt-perp-oracle-v1";
pub const RECEIPT_NOTE_SUITE: &str = "confidential-tokenized-liquidity-receipt-note-v1";
pub const AMM_POOL_SUITE: &str = "sealed-liquidity-receipt-perp-amm-v1";
pub const FUNDING_SUITE: &str = "private-liquidity-receipt-funding-accrual-v1";
pub const INSURANCE_SUITE: &str = "private-liquidity-receipt-insurance-accrual-v1";
pub const NETTING_SUITE: &str = "low-fee-liquidity-receipt-perp-batch-netting-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-redacted-liquidity-receipt-perp-amm-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MARKET_ID: &str = "private-l2-pq-liquidity-receipt-perp-amm-devnet";
pub const DEVNET_HEIGHT: u64 = 2_912_400;
pub const DEVNET_EPOCH: u64 = 512;
pub const DEVNET_RECEIPT_TOKEN: &str = "tlr";
pub const DEVNET_QUOTE_TOKEN: &str = "dusd";
pub const DEVNET_FEE_TOKEN: &str = "dxmr";
pub const DEFAULT_EPOCH_SECONDS: u64 = 600;
pub const DEFAULT_FUNDING_INTERVAL_EPOCHS: u64 = 3;
pub const DEFAULT_INSURANCE_INTERVAL_EPOCHS: u64 = 12;
pub const DEFAULT_SETTLEMENT_WINDOW_EPOCHS: u64 = 18;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_POOL_FEE_BPS: u64 = 9;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 2;
pub const DEFAULT_NETTING_FEE_BPS: u64 = 1;
pub const DEFAULT_INSURANCE_PREMIUM_BPS: u64 = 14;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 700;
pub const DEFAULT_MAX_FUNDING_RATE_BPS: i64 = 90;
pub const DEFAULT_MAX_INSURANCE_ACCRUAL_BPS: u64 = 125;
pub const DEFAULT_ORACLE_QUORUM: u16 = 9;
pub const DEFAULT_ORACLE_MAX_STALENESS_EPOCHS: u64 = 2;
pub const DEFAULT_MIN_RECEIPT_LIQUIDITY_UNITS: u128 = 75_000_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    LongReceipt,
    ShortReceipt,
    LpReceipt,
}

impl PositionSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LongReceipt => "long_receipt",
            Self::ShortReceipt => "short_receipt",
            Self::LpReceipt => "lp_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolKind {
    ReceiptWeighted,
    ConstantProduct,
    ConcentratedReceipt,
    InsuranceBalanced,
}

impl PoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptWeighted => "receipt_weighted",
            Self::ConstantProduct => "constant_product",
            Self::ConcentratedReceipt => "concentrated_receipt",
            Self::InsuranceBalanced => "insurance_balanced",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    ReceiptNav,
    FundingRate,
    InsuranceSolvency,
    LiquidityDepth,
    BatchNetting,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReceiptNav => "receipt_nav",
            Self::FundingRate => "funding_rate",
            Self::InsuranceSolvency => "insurance_solvency",
            Self::LiquidityDepth => "liquidity_depth",
            Self::BatchNetting => "batch_netting",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccrualStatus {
    Pending,
    Accruing,
    Netted,
    Applied,
    Rebated,
    Disputed,
}

impl AccrualStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accruing => "accruing",
            Self::Netted => "netted",
            Self::Applied => "applied",
            Self::Rebated => "rebated",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub l2_network: String,
    pub market_id: String,
    pub hash_suite: String,
    pub pq_oracle_suite: String,
    pub receipt_note_suite: String,
    pub amm_pool_suite: String,
    pub funding_suite: String,
    pub insurance_suite: String,
    pub netting_suite: String,
    pub receipt_token: String,
    pub quote_token: String,
    pub fee_token: String,
    pub epoch_seconds: u64,
    pub funding_interval_epochs: u64,
    pub insurance_interval_epochs: u64,
    pub settlement_window_epochs: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub pool_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub netting_fee_bps: u64,
    pub insurance_premium_bps: u64,
    pub maintenance_margin_bps: u64,
    pub max_funding_rate_bps: i64,
    pub max_insurance_accrual_bps: u64,
    pub oracle_quorum: u16,
    pub oracle_max_staleness_epochs: u64,
    pub min_receipt_liquidity_units: u128,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            market_id: DEVNET_MARKET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_oracle_suite: PQ_ORACLE_SUITE.to_string(),
            receipt_note_suite: RECEIPT_NOTE_SUITE.to_string(),
            amm_pool_suite: AMM_POOL_SUITE.to_string(),
            funding_suite: FUNDING_SUITE.to_string(),
            insurance_suite: INSURANCE_SUITE.to_string(),
            netting_suite: NETTING_SUITE.to_string(),
            receipt_token: DEVNET_RECEIPT_TOKEN.to_string(),
            quote_token: DEVNET_QUOTE_TOKEN.to_string(),
            fee_token: DEVNET_FEE_TOKEN.to_string(),
            epoch_seconds: DEFAULT_EPOCH_SECONDS,
            funding_interval_epochs: DEFAULT_FUNDING_INTERVAL_EPOCHS,
            insurance_interval_epochs: DEFAULT_INSURANCE_INTERVAL_EPOCHS,
            settlement_window_epochs: DEFAULT_SETTLEMENT_WINDOW_EPOCHS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            pool_fee_bps: DEFAULT_POOL_FEE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            netting_fee_bps: DEFAULT_NETTING_FEE_BPS,
            insurance_premium_bps: DEFAULT_INSURANCE_PREMIUM_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            max_funding_rate_bps: DEFAULT_MAX_FUNDING_RATE_BPS,
            max_insurance_accrual_bps: DEFAULT_MAX_INSURANCE_ACCRUAL_BPS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            oracle_max_staleness_epochs: DEFAULT_ORACLE_MAX_STALENESS_EPOCHS,
            min_receipt_liquidity_units: DEFAULT_MIN_RECEIPT_LIQUIDITY_UNITS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol mismatch",
        )?;
        require(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        require(!self.market_id.trim().is_empty(), "market id required")?;
        require(self.epoch_seconds > 0, "epoch seconds required")?;
        require(
            self.funding_interval_epochs > 0,
            "funding interval required",
        )?;
        require(
            self.insurance_interval_epochs > 0,
            "insurance interval required",
        )?;
        require(
            self.min_privacy_set_size <= self.target_privacy_set_size,
            "privacy target below minimum",
        )?;
        require(self.min_pq_security_bits >= 192, "pq security below floor")?;
        require(self.oracle_quorum > 0, "oracle quorum required")?;
        require(
            self.pool_fee_bps
                + self.protocol_fee_bps
                + self.netting_fee_bps
                + self.insurance_premium_bps
                <= MAX_BPS
                && self.maintenance_margin_bps <= MAX_BPS
                && self.max_insurance_accrual_bps <= MAX_BPS,
            "invalid bps config",
        )?;
        require(
            self.max_funding_rate_bps.unsigned_abs() <= MAX_BPS,
            "invalid funding rate cap",
        )
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub receipt_notes: u64,
    pub amm_pools: u64,
    pub pq_oracle_roots: u64,
    pub funding_accruals: u64,
    pub insurance_accruals: u64,
    pub netting_batches: u64,
    pub settlement_receipts: u64,
    pub privacy_redactions: u64,
    pub consumed_nullifiers: u64,
    pub total_receipt_notional_units: u128,
    pub total_net_funding_units: i128,
    pub total_insurance_accrued_units: u128,
    pub total_netted_fee_units: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub receipt_note_root: String,
    pub amm_pool_root: String,
    pub pq_oracle_root: String,
    pub funding_accrual_root: String,
    pub insurance_accrual_root: String,
    pub netting_batch_root: String,
    pub settlement_receipt_root: String,
    pub privacy_redaction_root: String,
    pub nullifier_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityReceiptNote {
    pub note_id: String,
    pub owner_commitment: String,
    pub pool_id: String,
    pub side: PositionSide,
    pub receipt_asset_id: String,
    pub receipt_notional_units: u128,
    pub entry_receipt_nav_root: String,
    pub collateral_commitment_root: String,
    pub leverage_bps: u64,
    pub opened_epoch: u64,
    pub last_accrual_epoch: u64,
    pub status: AccrualStatus,
    pub encrypted_terms_root: String,
    pub nullifier_commitment: String,
}

impl LiquidityReceiptNote {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "owner_commitment": redacted_label(&self.owner_commitment),
            "pool_id": self.pool_id,
            "side": self.side.as_str(),
            "receipt_asset_id": self.receipt_asset_id,
            "receipt_notional_units": self.receipt_notional_units,
            "entry_receipt_nav_root": self.entry_receipt_nav_root,
            "collateral_commitment_root": self.collateral_commitment_root,
            "leverage_bps": self.leverage_bps,
            "opened_epoch": self.opened_epoch,
            "last_accrual_epoch": self.last_accrual_epoch,
            "status": self.status.as_str(),
            "encrypted_terms_root": self.encrypted_terms_root,
            "nullifier_commitment": self.nullifier_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptAmmPool {
    pub pool_id: String,
    pub kind: PoolKind,
    pub receipt_asset_id: String,
    pub quote_token: String,
    pub sealed_receipt_reserve_root: String,
    pub sealed_quote_reserve_root: String,
    pub lp_receipt_commitment_root: String,
    pub invariant_root: String,
    pub funding_index_root: String,
    pub insurance_buffer_root: String,
    pub fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub active: bool,
}

impl ReceiptAmmPool {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqOracleRoot {
    pub oracle_root_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub pool_id: String,
    pub epoch: u64,
    pub receipt_nav_root: String,
    pub funding_rate_root: String,
    pub funding_rate_bps: i64,
    pub insurance_solvency_root: String,
    pub liquidity_depth_root: String,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub issued_height: u64,
}

impl PqOracleRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "oracle_root_id": self.oracle_root_id,
            "kind": self.kind.as_str(),
            "committee_root": self.committee_root,
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "receipt_nav_root": self.receipt_nav_root,
            "funding_rate_root": self.funding_rate_root,
            "funding_rate_bps": self.funding_rate_bps,
            "insurance_solvency_root": self.insurance_solvency_root,
            "liquidity_depth_root": self.liquidity_depth_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_set_size": self.privacy_set_size,
            "issued_height": self.issued_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateFundingAccrual {
    pub accrual_id: String,
    pub note_id: String,
    pub pool_id: String,
    pub epoch: u64,
    pub side: PositionSide,
    pub receipt_notional_units: u128,
    pub funding_rate_bps: i64,
    pub funding_delta_units: i128,
    pub oracle_root_id: String,
    pub encrypted_accrual_root: String,
    pub status: AccrualStatus,
}

impl PrivateFundingAccrual {
    pub fn public_record(&self) -> Value {
        json!({
            "accrual_id": self.accrual_id,
            "note_id": self.note_id,
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "side": self.side.as_str(),
            "receipt_notional_units": self.receipt_notional_units,
            "funding_rate_bps": self.funding_rate_bps,
            "funding_delta_units": self.funding_delta_units,
            "oracle_root_id": self.oracle_root_id,
            "encrypted_accrual_root": self.encrypted_accrual_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateInsuranceAccrual {
    pub accrual_id: String,
    pub pool_id: String,
    pub epoch: u64,
    pub premium_bps: u64,
    pub accrued_units: u128,
    pub insurance_buffer_before_root: String,
    pub insurance_buffer_after_root: String,
    pub beneficiary_set_root: String,
    pub oracle_root_id: String,
    pub encrypted_accrual_root: String,
    pub status: AccrualStatus,
}

impl PrivateInsuranceAccrual {
    pub fn public_record(&self) -> Value {
        json!({
            "accrual_id": self.accrual_id,
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "premium_bps": self.premium_bps,
            "accrued_units": self.accrued_units,
            "insurance_buffer_before_root": self.insurance_buffer_before_root,
            "insurance_buffer_after_root": self.insurance_buffer_after_root,
            "beneficiary_set_root": self.beneficiary_set_root,
            "oracle_root_id": self.oracle_root_id,
            "encrypted_accrual_root": self.encrypted_accrual_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatchNetting {
    pub batch_id: String,
    pub pool_id: String,
    pub epoch: u64,
    pub funding_accrual_root: String,
    pub insurance_accrual_root: String,
    pub participant_set_root: String,
    pub net_funding_units: i128,
    pub net_insurance_units: u128,
    pub fee_units: u128,
    pub settlement_root: String,
    pub status: AccrualStatus,
}

impl LowFeeBatchNetting {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "funding_accrual_root": self.funding_accrual_root,
            "insurance_accrual_root": self.insurance_accrual_root,
            "participant_set_root": self.participant_set_root,
            "net_funding_units": self.net_funding_units,
            "net_insurance_units": self.net_insurance_units,
            "fee_units": self.fee_units,
            "settlement_root": self.settlement_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub note_id: String,
    pub netting_batch_id: String,
    pub paid_funding_units: i128,
    pub insurance_accrued_units: u128,
    pub fee_paid_units: u128,
    pub margin_after_root: String,
    pub receipt_balance_after_root: String,
    pub status: AccrualStatus,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "note_id": self.note_id,
            "netting_batch_id": self.netting_batch_id,
            "paid_funding_units": self.paid_funding_units,
            "insurance_accrued_units": self.insurance_accrued_units,
            "fee_paid_units": self.fee_paid_units,
            "margin_after_root": self.margin_after_root,
            "receipt_balance_after_root": self.receipt_balance_after_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedaction {
    pub redaction_id: String,
    pub record_kind: String,
    pub record_id: String,
    pub redacted_fields: Vec<String>,
    pub disclosure_root: String,
    pub privacy_set_size: u64,
}

impl PrivacyRedaction {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_l2_height: u64,
    pub current_epoch: u64,
    pub receipt_notes: BTreeMap<String, LiquidityReceiptNote>,
    pub amm_pools: BTreeMap<String, ReceiptAmmPool>,
    pub pq_oracle_roots: BTreeMap<String, PqOracleRoot>,
    pub funding_accruals: BTreeMap<String, PrivateFundingAccrual>,
    pub insurance_accruals: BTreeMap<String, PrivateInsuranceAccrual>,
    pub netting_batches: BTreeMap<String, LowFeeBatchNetting>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub privacy_redactions: BTreeMap<String, PrivacyRedaction>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, current_l2_height: u64, current_epoch: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            current_l2_height,
            current_epoch,
            receipt_notes: BTreeMap::new(),
            amm_pools: BTreeMap::new(),
            pq_oracle_roots: BTreeMap::new(),
            funding_accruals: BTreeMap::new(),
            insurance_accruals: BTreeMap::new(),
            netting_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state =
            Self::new(config.clone(), DEVNET_HEIGHT, DEVNET_EPOCH).expect("valid devnet config");
        let pool = demo_pool(&config, "liquidity-receipt-perp-pool-0", "0");
        let note = demo_note(&config, &pool.pool_id, "receipt-trader-alpha", "0");
        let oracle_root = demo_oracle_root(&config, &pool.pool_id, "0");
        let funding = demo_funding_accrual(&note, &oracle_root, "0");
        let insurance = demo_insurance_accrual(&config, &pool.pool_id, &oracle_root, "0");
        let batch = demo_netting_batch(&config, &pool.pool_id, &funding, &insurance, "0");
        let receipt = demo_settlement_receipt(&note, &batch, "0");
        let redaction = demo_redaction(
            "liquidity_receipt_note",
            &note.note_id,
            config.min_privacy_set_size,
            "0",
        );

        state.insert_amm_pool(pool).expect("devnet pool");
        state.insert_receipt_note(note).expect("devnet note");
        state
            .insert_pq_oracle_root(oracle_root)
            .expect("devnet oracle root");
        state
            .insert_funding_accrual(funding)
            .expect("devnet funding accrual");
        state
            .insert_insurance_accrual(insurance)
            .expect("devnet insurance accrual");
        state
            .insert_netting_batch(batch)
            .expect("devnet netting batch");
        state
            .insert_settlement_receipt(receipt)
            .expect("devnet receipt");
        state
            .insert_privacy_redaction(redaction)
            .expect("devnet redaction");
        state
    }

    pub fn insert_receipt_note(&mut self, note: LiquidityReceiptNote) -> Result<()> {
        require(self.amm_pools.contains_key(&note.pool_id), "unknown pool")?;
        require(note.receipt_notional_units > 0, "receipt notional required")?;
        require(note.leverage_bps >= MAX_BPS, "leverage below 1x")?;
        require(
            self.consumed_nullifiers
                .insert(note.nullifier_commitment.clone()),
            "duplicate nullifier commitment",
        )?;
        insert_unique(&mut self.receipt_notes, note.note_id.clone(), note)
    }

    pub fn insert_amm_pool(&mut self, pool: ReceiptAmmPool) -> Result<()> {
        require(
            pool.fee_bps + pool.protocol_fee_bps <= MAX_BPS,
            "invalid pool fees",
        )?;
        insert_unique(&mut self.amm_pools, pool.pool_id.clone(), pool)
    }

    pub fn insert_pq_oracle_root(&mut self, oracle_root: PqOracleRoot) -> Result<()> {
        require(
            self.amm_pools.contains_key(&oracle_root.pool_id),
            "unknown oracle pool",
        )?;
        require(
            oracle_root.privacy_set_size >= self.config.min_privacy_set_size,
            "oracle privacy set below minimum",
        )?;
        require(
            oracle_root.funding_rate_bps.unsigned_abs()
                <= self.config.max_funding_rate_bps.unsigned_abs(),
            "funding rate exceeds cap",
        )?;
        insert_unique(
            &mut self.pq_oracle_roots,
            oracle_root.oracle_root_id.clone(),
            oracle_root,
        )
    }

    pub fn insert_funding_accrual(&mut self, accrual: PrivateFundingAccrual) -> Result<()> {
        require(
            self.receipt_notes.contains_key(&accrual.note_id),
            "unknown receipt note",
        )?;
        require(
            self.pq_oracle_roots.contains_key(&accrual.oracle_root_id),
            "unknown oracle root",
        )?;
        insert_unique(
            &mut self.funding_accruals,
            accrual.accrual_id.clone(),
            accrual,
        )
    }

    pub fn insert_insurance_accrual(&mut self, accrual: PrivateInsuranceAccrual) -> Result<()> {
        require(
            self.amm_pools.contains_key(&accrual.pool_id),
            "unknown insurance pool",
        )?;
        require(
            self.pq_oracle_roots.contains_key(&accrual.oracle_root_id),
            "unknown oracle root",
        )?;
        require(
            accrual.premium_bps <= self.config.max_insurance_accrual_bps,
            "insurance accrual exceeds cap",
        )?;
        insert_unique(
            &mut self.insurance_accruals,
            accrual.accrual_id.clone(),
            accrual,
        )
    }

    pub fn insert_netting_batch(&mut self, batch: LowFeeBatchNetting) -> Result<()> {
        require(self.amm_pools.contains_key(&batch.pool_id), "unknown pool")?;
        insert_unique(&mut self.netting_batches, batch.batch_id.clone(), batch)
    }

    pub fn insert_settlement_receipt(&mut self, receipt: SettlementReceipt) -> Result<()> {
        require(
            self.receipt_notes.contains_key(&receipt.note_id),
            "unknown receipt note",
        )?;
        require(
            self.netting_batches.contains_key(&receipt.netting_batch_id),
            "unknown netting batch",
        )?;
        insert_unique(
            &mut self.settlement_receipts,
            receipt.receipt_id.clone(),
            receipt,
        )
    }

    pub fn insert_privacy_redaction(&mut self, redaction: PrivacyRedaction) -> Result<()> {
        require(
            redaction.privacy_set_size >= self.config.min_privacy_set_size,
            "redaction privacy set below minimum",
        )?;
        insert_unique(
            &mut self.privacy_redactions,
            redaction.redaction_id.clone(),
            redaction,
        )
    }

    pub fn counters(&self) -> Counters {
        Counters {
            receipt_notes: self.receipt_notes.len() as u64,
            amm_pools: self.amm_pools.len() as u64,
            pq_oracle_roots: self.pq_oracle_roots.len() as u64,
            funding_accruals: self.funding_accruals.len() as u64,
            insurance_accruals: self.insurance_accruals.len() as u64,
            netting_batches: self.netting_batches.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            privacy_redactions: self.privacy_redactions.len() as u64,
            consumed_nullifiers: self.consumed_nullifiers.len() as u64,
            total_receipt_notional_units: self
                .receipt_notes
                .values()
                .map(|note| note.receipt_notional_units)
                .sum(),
            total_net_funding_units: self
                .netting_batches
                .values()
                .map(|batch| batch.net_funding_units)
                .sum(),
            total_insurance_accrued_units: self
                .insurance_accruals
                .values()
                .map(|accrual| accrual.accrued_units)
                .sum(),
            total_netted_fee_units: self
                .netting_batches
                .values()
                .map(|batch| batch.fee_units)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        let counters = self.counters();
        let nullifier_records = self
            .consumed_nullifiers
            .iter()
            .map(|nullifier| json!({ "nullifier_commitment": nullifier }));
        let mut roots = Roots {
            config_root: record_root(
                "LIQUIDITY-RECEIPT-PERP-AMM-CONFIG",
                &self.config.public_record(),
            ),
            receipt_note_root: merkle_records(
                "LIQUIDITY-RECEIPT-PERP-AMM-NOTES",
                self.receipt_notes
                    .values()
                    .map(LiquidityReceiptNote::public_record),
            ),
            amm_pool_root: merkle_records(
                "LIQUIDITY-RECEIPT-PERP-AMM-POOLS",
                self.amm_pools.values().map(ReceiptAmmPool::public_record),
            ),
            pq_oracle_root: merkle_records(
                "LIQUIDITY-RECEIPT-PERP-AMM-PQ-ORACLE-ROOTS",
                self.pq_oracle_roots
                    .values()
                    .map(PqOracleRoot::public_record),
            ),
            funding_accrual_root: merkle_records(
                "LIQUIDITY-RECEIPT-PERP-AMM-FUNDING-ACCRUALS",
                self.funding_accruals
                    .values()
                    .map(PrivateFundingAccrual::public_record),
            ),
            insurance_accrual_root: merkle_records(
                "LIQUIDITY-RECEIPT-PERP-AMM-INSURANCE-ACCRUALS",
                self.insurance_accruals
                    .values()
                    .map(PrivateInsuranceAccrual::public_record),
            ),
            netting_batch_root: merkle_records(
                "LIQUIDITY-RECEIPT-PERP-AMM-NETTING-BATCHES",
                self.netting_batches
                    .values()
                    .map(LowFeeBatchNetting::public_record),
            ),
            settlement_receipt_root: merkle_records(
                "LIQUIDITY-RECEIPT-PERP-AMM-SETTLEMENT-RECEIPTS",
                self.settlement_receipts
                    .values()
                    .map(SettlementReceipt::public_record),
            ),
            privacy_redaction_root: merkle_records(
                "LIQUIDITY-RECEIPT-PERP-AMM-REDACTIONS",
                self.privacy_redactions
                    .values()
                    .map(PrivacyRedaction::public_record),
            ),
            nullifier_root: merkle_records(
                "LIQUIDITY-RECEIPT-PERP-AMM-NULLIFIERS",
                nullifier_records,
            ),
            counters_root: record_root(
                "LIQUIDITY-RECEIPT-PERP-AMM-COUNTERS",
                &counters.public_record(),
            ),
            state_root: String::new(),
        };
        roots.state_root = record_root("LIQUIDITY-RECEIPT-PERP-AMM-ROOTS", &roots.public_record());
        roots
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "current_l2_height": self.current_l2_height,
            "current_epoch": self.current_epoch,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_record(record: &Value) -> String {
    record_root("LIQUIDITY-RECEIPT-PERP-AMM-STATE", record)
}

fn demo_pool(config: &Config, pool_id: &str, salt: &str) -> ReceiptAmmPool {
    ReceiptAmmPool {
        pool_id: pool_id.to_string(),
        kind: PoolKind::ReceiptWeighted,
        receipt_asset_id: config.receipt_token.clone(),
        quote_token: config.quote_token.clone(),
        sealed_receipt_reserve_root: demo_root("sealed-receipt-reserve", salt),
        sealed_quote_reserve_root: demo_root("sealed-quote-reserve", salt),
        lp_receipt_commitment_root: demo_root("lp-receipt-commitments", salt),
        invariant_root: demo_root("receipt-weighted-invariant", salt),
        funding_index_root: demo_root("funding-index", salt),
        insurance_buffer_root: demo_root("insurance-buffer", salt),
        fee_bps: config.pool_fee_bps,
        protocol_fee_bps: config.protocol_fee_bps,
        active: true,
    }
}

fn demo_note(config: &Config, pool_id: &str, owner: &str, salt: &str) -> LiquidityReceiptNote {
    LiquidityReceiptNote {
        note_id: format!("devnet-liquidity-receipt-perp-note-{salt}"),
        owner_commitment: demo_root(owner, salt),
        pool_id: pool_id.to_string(),
        side: PositionSide::LongReceipt,
        receipt_asset_id: config.receipt_token.clone(),
        receipt_notional_units: 3_200_000_000,
        entry_receipt_nav_root: demo_root("entry-receipt-nav", salt),
        collateral_commitment_root: demo_root("collateral", salt),
        leverage_bps: 15_000,
        opened_epoch: DEVNET_EPOCH,
        last_accrual_epoch: DEVNET_EPOCH,
        status: AccrualStatus::Accruing,
        encrypted_terms_root: demo_root("encrypted-receipt-perp-terms", salt),
        nullifier_commitment: demo_root("receipt-perp-note-nullifier", salt),
    }
}

fn demo_oracle_root(config: &Config, pool_id: &str, salt: &str) -> PqOracleRoot {
    PqOracleRoot {
        oracle_root_id: format!("devnet-liquidity-receipt-pq-oracle-root-{salt}"),
        kind: AttestationKind::ReceiptNav,
        committee_root: record_root(
            "LIQUIDITY-RECEIPT-PERP-AMM-ORACLE-COMMITTEE",
            &json!({ "quorum": config.oracle_quorum }),
        ),
        pool_id: pool_id.to_string(),
        epoch: DEVNET_EPOCH,
        receipt_nav_root: demo_root("receipt-nav", salt),
        funding_rate_root: demo_root("funding-rate", salt),
        funding_rate_bps: 21,
        insurance_solvency_root: demo_root("insurance-solvency", salt),
        liquidity_depth_root: demo_root("liquidity-depth", salt),
        pq_signature_root: demo_root("pq-oracle-signature", salt),
        privacy_set_size: config.min_privacy_set_size,
        issued_height: DEVNET_HEIGHT + 1,
    }
}

fn demo_funding_accrual(
    note: &LiquidityReceiptNote,
    oracle_root: &PqOracleRoot,
    salt: &str,
) -> PrivateFundingAccrual {
    let delta = funding_delta(
        note.receipt_notional_units,
        oracle_root.funding_rate_bps,
        note.side,
    );
    PrivateFundingAccrual {
        accrual_id: format!("devnet-liquidity-receipt-funding-accrual-{salt}"),
        note_id: note.note_id.clone(),
        pool_id: note.pool_id.clone(),
        epoch: oracle_root.epoch,
        side: note.side,
        receipt_notional_units: note.receipt_notional_units,
        funding_rate_bps: oracle_root.funding_rate_bps,
        funding_delta_units: delta,
        oracle_root_id: oracle_root.oracle_root_id.clone(),
        encrypted_accrual_root: demo_root("encrypted-funding-accrual", salt),
        status: AccrualStatus::Accruing,
    }
}

fn demo_insurance_accrual(
    config: &Config,
    pool_id: &str,
    oracle_root: &PqOracleRoot,
    salt: &str,
) -> PrivateInsuranceAccrual {
    let accrued_units = config
        .min_receipt_liquidity_units
        .saturating_mul(config.insurance_premium_bps as u128)
        / MAX_BPS as u128;
    PrivateInsuranceAccrual {
        accrual_id: format!("devnet-liquidity-receipt-insurance-accrual-{salt}"),
        pool_id: pool_id.to_string(),
        epoch: oracle_root.epoch,
        premium_bps: config.insurance_premium_bps,
        accrued_units,
        insurance_buffer_before_root: demo_root("insurance-buffer-before", salt),
        insurance_buffer_after_root: demo_root("insurance-buffer-after", salt),
        beneficiary_set_root: demo_root("insurance-beneficiaries", salt),
        oracle_root_id: oracle_root.oracle_root_id.clone(),
        encrypted_accrual_root: demo_root("encrypted-insurance-accrual", salt),
        status: AccrualStatus::Accruing,
    }
}

fn demo_netting_batch(
    config: &Config,
    pool_id: &str,
    funding: &PrivateFundingAccrual,
    insurance: &PrivateInsuranceAccrual,
    salt: &str,
) -> LowFeeBatchNetting {
    let fee_units = funding
        .receipt_notional_units
        .saturating_mul(config.netting_fee_bps as u128)
        / MAX_BPS as u128;
    LowFeeBatchNetting {
        batch_id: format!("devnet-liquidity-receipt-low-fee-netting-batch-{salt}"),
        pool_id: pool_id.to_string(),
        epoch: funding.epoch,
        funding_accrual_root: demo_root("funding-accrual-set", salt),
        insurance_accrual_root: demo_root("insurance-accrual-set", salt),
        participant_set_root: demo_root("netting-participants", salt),
        net_funding_units: funding.funding_delta_units,
        net_insurance_units: insurance.accrued_units,
        fee_units,
        settlement_root: demo_root("netting-settlement", salt),
        status: AccrualStatus::Netted,
    }
}

fn demo_settlement_receipt(
    note: &LiquidityReceiptNote,
    batch: &LowFeeBatchNetting,
    salt: &str,
) -> SettlementReceipt {
    SettlementReceipt {
        receipt_id: format!("devnet-liquidity-receipt-settlement-receipt-{salt}"),
        note_id: note.note_id.clone(),
        netting_batch_id: batch.batch_id.clone(),
        paid_funding_units: batch.net_funding_units,
        insurance_accrued_units: batch.net_insurance_units,
        fee_paid_units: batch.fee_units,
        margin_after_root: demo_root("margin-after-netting", salt),
        receipt_balance_after_root: demo_root("receipt-balance-after-netting", salt),
        status: AccrualStatus::Applied,
    }
}

fn demo_redaction(
    record_kind: &str,
    record_id: &str,
    privacy_set_size: u64,
    salt: &str,
) -> PrivacyRedaction {
    PrivacyRedaction {
        redaction_id: format!("devnet-liquidity-receipt-redaction-{record_kind}-{salt}"),
        record_kind: record_kind.to_string(),
        record_id: record_id.to_string(),
        redacted_fields: vec![
            "owner_commitment".to_string(),
            "collateral_commitment_root".to_string(),
            "encrypted_terms_root".to_string(),
            "encrypted_accrual_root".to_string(),
        ],
        disclosure_root: demo_root("selective-disclosure", salt),
        privacy_set_size,
    }
}

fn funding_delta(notional_units: u128, funding_rate_bps: i64, side: PositionSide) -> i128 {
    let magnitude =
        notional_units.saturating_mul(funding_rate_bps.unsigned_abs() as u128) / MAX_BPS as u128;
    let signed = if funding_rate_bps >= 0 {
        magnitude as i128
    } else {
        -(magnitude as i128)
    };
    match side {
        PositionSide::LongReceipt => -signed,
        PositionSide::ShortReceipt | PositionSide::LpReceipt => signed,
    }
}

fn insert_unique<T>(map: &mut BTreeMap<String, T>, key: String, value: T) -> Result<()> {
    require(!key.trim().is_empty(), "id required")?;
    require(!map.contains_key(&key), "duplicate id")?;
    map.insert(key, value);
    Ok(())
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn redacted_label(value: &str) -> String {
    record_root(
        "LIQUIDITY-RECEIPT-PERP-AMM-REDACTED-LABEL",
        &json!({ "value": value }),
    )
}

fn demo_root(label: &str, salt: &str) -> String {
    record_root(
        "LIQUIDITY-RECEIPT-PERP-AMM-DEMO-FIXTURE",
        &json!({ "label": label, "salt": salt }),
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::from(
            serde_json::to_string(record).expect("canonical json record"),
        )],
    )
}

fn merkle_records<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records
        .into_iter()
        .map(|record| record_root(domain, &record))
        .collect::<Vec<_>>();
    merkle_root(domain, leaves)
}
