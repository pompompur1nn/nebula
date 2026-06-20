use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedRealYieldPerpAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_REAL_YIELD_PERP_AMM_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-real-yield-perp-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_REAL_YIELD_PERP_AMM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-real-yield-perp-v1";
pub const NOTE_COMMITMENT_SUITE: &str = "confidential-tokenized-real-yield-perp-note-v1";
pub const AMM_POOL_SUITE: &str = "sealed-real-yield-perp-amm-v1";
pub const FUNDING_SUITE: &str = "private-real-yield-funding-accrual-v1";
pub const ORACLE_ATTESTATION_SUITE: &str = "pq-real-yield-nav-and-income-attestation-v1";
pub const NETTING_SUITE: &str = "low-fee-real-yield-perp-funding-netting-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-redacted-real-yield-perp-amm-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MARKET_ID: &str = "private-l2-pq-real-yield-perp-amm-devnet";
pub const DEVNET_HEIGHT: u64 = 2_736_000;
pub const DEVNET_EPOCH: u64 = 384;
pub const DEVNET_QUOTE_TOKEN: &str = "dusd";
pub const DEVNET_FEE_TOKEN: &str = "dxmr";
pub const DEFAULT_EPOCH_SECONDS: u64 = 900;
pub const DEFAULT_FUNDING_INTERVAL_EPOCHS: u64 = 4;
pub const DEFAULT_SETTLEMENT_WINDOW_EPOCHS: u64 = 16;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_POOL_FEE_BPS: u64 = 18;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 3;
pub const DEFAULT_NETTING_FEE_BPS: u64 = 2;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 625;
pub const DEFAULT_MAX_FUNDING_RATE_BPS: i64 = 75;
pub const DEFAULT_ORACLE_QUORUM: u16 = 7;
pub const DEFAULT_ORACLE_MAX_STALENESS_EPOCHS: u64 = 2;
pub const DEFAULT_MIN_SEALED_LIQUIDITY_UNITS: u128 = 50_000_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    Long,
    Short,
    Lp,
}

impl PositionSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Long => "long",
            Self::Short => "short",
            Self::Lp => "lp",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolKind {
    ConstantProduct,
    YieldWeighted,
    StablePerp,
    ConcentratedYield,
}

impl PoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConstantProduct => "constant_product",
            Self::YieldWeighted => "yield_weighted",
            Self::StablePerp => "stable_perp",
            Self::ConcentratedYield => "concentrated_yield",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    Nav,
    RealYield,
    FundingRate,
    PoolSolvency,
    LiquidationBand,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nav => "nav",
            Self::RealYield => "real_yield",
            Self::FundingRate => "funding_rate",
            Self::PoolSolvency => "pool_solvency",
            Self::LiquidationBand => "liquidation_band",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    Accruing,
    Netted,
    Settled,
    Rebated,
    Liquidating,
    Disputed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accruing => "accruing",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Liquidating => "liquidating",
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
    pub pq_attestation_suite: String,
    pub note_commitment_suite: String,
    pub amm_pool_suite: String,
    pub funding_suite: String,
    pub oracle_attestation_suite: String,
    pub netting_suite: String,
    pub quote_token: String,
    pub fee_token: String,
    pub epoch_seconds: u64,
    pub funding_interval_epochs: u64,
    pub settlement_window_epochs: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub pool_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub netting_fee_bps: u64,
    pub maintenance_margin_bps: u64,
    pub max_funding_rate_bps: i64,
    pub oracle_quorum: u16,
    pub oracle_max_staleness_epochs: u64,
    pub min_sealed_liquidity_units: u128,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            market_id: DEVNET_MARKET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            note_commitment_suite: NOTE_COMMITMENT_SUITE.to_string(),
            amm_pool_suite: AMM_POOL_SUITE.to_string(),
            funding_suite: FUNDING_SUITE.to_string(),
            oracle_attestation_suite: ORACLE_ATTESTATION_SUITE.to_string(),
            netting_suite: NETTING_SUITE.to_string(),
            quote_token: DEVNET_QUOTE_TOKEN.to_string(),
            fee_token: DEVNET_FEE_TOKEN.to_string(),
            epoch_seconds: DEFAULT_EPOCH_SECONDS,
            funding_interval_epochs: DEFAULT_FUNDING_INTERVAL_EPOCHS,
            settlement_window_epochs: DEFAULT_SETTLEMENT_WINDOW_EPOCHS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            pool_fee_bps: DEFAULT_POOL_FEE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            netting_fee_bps: DEFAULT_NETTING_FEE_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            max_funding_rate_bps: DEFAULT_MAX_FUNDING_RATE_BPS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            oracle_max_staleness_epochs: DEFAULT_ORACLE_MAX_STALENESS_EPOCHS,
            min_sealed_liquidity_units: DEFAULT_MIN_SEALED_LIQUIDITY_UNITS,
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
            self.min_privacy_set_size <= self.target_privacy_set_size,
            "privacy target below minimum",
        )?;
        require(self.min_pq_security_bits >= 192, "pq security below floor")?;
        require(self.oracle_quorum > 0, "oracle quorum required")?;
        require(
            self.pool_fee_bps + self.protocol_fee_bps + self.netting_fee_bps <= MAX_BPS
                && self.maintenance_margin_bps <= MAX_BPS,
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
    pub perp_notes: u64,
    pub amm_pools: u64,
    pub oracle_attestations: u64,
    pub funding_accruals: u64,
    pub netting_batches: u64,
    pub sealed_liquidity: u64,
    pub settlement_receipts: u64,
    pub privacy_redactions: u64,
    pub consumed_nullifiers: u64,
    pub total_notional_units: u128,
    pub total_net_funding_units: i128,
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
    pub perp_note_root: String,
    pub amm_pool_root: String,
    pub oracle_attestation_root: String,
    pub funding_accrual_root: String,
    pub netting_batch_root: String,
    pub sealed_liquidity_root: String,
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
pub struct RealYieldPerpNote {
    pub note_id: String,
    pub owner_commitment: String,
    pub pool_id: String,
    pub side: PositionSide,
    pub asset_class: String,
    pub notional_units: u128,
    pub entry_nav_root: String,
    pub collateral_commitment_root: String,
    pub leverage_bps: u64,
    pub opened_epoch: u64,
    pub last_funding_epoch: u64,
    pub status: SettlementStatus,
    pub encrypted_terms_root: String,
    pub nullifier_commitment: String,
}

impl RealYieldPerpNote {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "owner_commitment": redacted_label(&self.owner_commitment),
            "pool_id": self.pool_id,
            "side": self.side.as_str(),
            "asset_class": self.asset_class,
            "notional_units": self.notional_units,
            "entry_nav_root": self.entry_nav_root,
            "collateral_commitment_root": self.collateral_commitment_root,
            "leverage_bps": self.leverage_bps,
            "opened_epoch": self.opened_epoch,
            "last_funding_epoch": self.last_funding_epoch,
            "status": self.status.as_str(),
            "encrypted_terms_root": self.encrypted_terms_root,
            "nullifier_commitment": self.nullifier_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AmmPool {
    pub pool_id: String,
    pub kind: PoolKind,
    pub base_asset_class: String,
    pub quote_token: String,
    pub sealed_long_reserve_root: String,
    pub sealed_short_reserve_root: String,
    pub sealed_quote_reserve_root: String,
    pub lp_commitment_root: String,
    pub invariant_root: String,
    pub funding_index_root: String,
    pub fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub active: bool,
}

impl AmmPool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "kind": self.kind.as_str(),
            "base_asset_class": self.base_asset_class,
            "quote_token": self.quote_token,
            "sealed_long_reserve_root": self.sealed_long_reserve_root,
            "sealed_short_reserve_root": self.sealed_short_reserve_root,
            "sealed_quote_reserve_root": self.sealed_quote_reserve_root,
            "lp_commitment_root": self.lp_commitment_root,
            "invariant_root": self.invariant_root,
            "funding_index_root": self.funding_index_root,
            "fee_bps": self.fee_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqOracleAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub oracle_committee_root: String,
    pub pool_id: String,
    pub epoch: u64,
    pub nav_commitment_root: String,
    pub realized_yield_root: String,
    pub funding_rate_bps: i64,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub issued_height: u64,
}

impl PqOracleAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "oracle_committee_root": self.oracle_committee_root,
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "nav_commitment_root": self.nav_commitment_root,
            "realized_yield_root": self.realized_yield_root,
            "funding_rate_bps": self.funding_rate_bps,
            "pq_signature_root": self.pq_signature_root,
            "privacy_set_size": self.privacy_set_size,
            "issued_height": self.issued_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FundingAccrual {
    pub accrual_id: String,
    pub note_id: String,
    pub pool_id: String,
    pub epoch: u64,
    pub side: PositionSide,
    pub notional_units: u128,
    pub funding_rate_bps: i64,
    pub funding_delta_units: i128,
    pub oracle_attestation_id: String,
    pub encrypted_accrual_root: String,
    pub status: SettlementStatus,
}

impl FundingAccrual {
    pub fn public_record(&self) -> Value {
        json!({
            "accrual_id": self.accrual_id,
            "note_id": self.note_id,
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "side": self.side.as_str(),
            "notional_units": self.notional_units,
            "funding_rate_bps": self.funding_rate_bps,
            "funding_delta_units": self.funding_delta_units,
            "oracle_attestation_id": self.oracle_attestation_id,
            "encrypted_accrual_root": self.encrypted_accrual_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeNettingBatch {
    pub batch_id: String,
    pub pool_id: String,
    pub epoch: u64,
    pub long_accrual_root: String,
    pub short_accrual_root: String,
    pub net_funding_units: i128,
    pub fee_units: u128,
    pub participant_set_root: String,
    pub settlement_root: String,
    pub status: SettlementStatus,
}

impl LowFeeNettingBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "long_accrual_root": self.long_accrual_root,
            "short_accrual_root": self.short_accrual_root,
            "net_funding_units": self.net_funding_units,
            "fee_units": self.fee_units,
            "participant_set_root": self.participant_set_root,
            "settlement_root": self.settlement_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedLiquidityPosition {
    pub position_id: String,
    pub pool_id: String,
    pub owner_commitment: String,
    pub sealed_base_units: u128,
    pub sealed_quote_units: u128,
    pub lp_note_root: String,
    pub locked_until_epoch: u64,
}

impl SealedLiquidityPosition {
    pub fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "pool_id": self.pool_id,
            "owner_commitment": redacted_label(&self.owner_commitment),
            "sealed_base_units": self.sealed_base_units,
            "sealed_quote_units": self.sealed_quote_units,
            "lp_note_root": self.lp_note_root,
            "locked_until_epoch": self.locked_until_epoch,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub note_id: String,
    pub netting_batch_id: String,
    pub paid_funding_units: i128,
    pub fee_paid_units: u128,
    pub margin_after_root: String,
    pub status: SettlementStatus,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "note_id": self.note_id,
            "netting_batch_id": self.netting_batch_id,
            "paid_funding_units": self.paid_funding_units,
            "fee_paid_units": self.fee_paid_units,
            "margin_after_root": self.margin_after_root,
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
    pub perp_notes: BTreeMap<String, RealYieldPerpNote>,
    pub amm_pools: BTreeMap<String, AmmPool>,
    pub oracle_attestations: BTreeMap<String, PqOracleAttestation>,
    pub funding_accruals: BTreeMap<String, FundingAccrual>,
    pub netting_batches: BTreeMap<String, LowFeeNettingBatch>,
    pub sealed_liquidity: BTreeMap<String, SealedLiquidityPosition>,
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
            perp_notes: BTreeMap::new(),
            amm_pools: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            funding_accruals: BTreeMap::new(),
            netting_batches: BTreeMap::new(),
            sealed_liquidity: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state =
            Self::new(config.clone(), DEVNET_HEIGHT, DEVNET_EPOCH).expect("valid devnet config");
        let pool = demo_pool(
            &config,
            "real-yield-perp-pool-0",
            PoolKind::YieldWeighted,
            "0",
        );
        let note = demo_note(&pool.pool_id, "yield-trader-alpha", PositionSide::Long, "0");
        let attestation = demo_attestation(&config, &pool.pool_id, "0");
        let accrual = demo_accrual(&note, &attestation, "0");
        let batch = demo_netting_batch(&config, &pool.pool_id, &accrual, "0");
        let liquidity = demo_liquidity(&pool.pool_id, "lp-alpha", "0");
        let receipt = demo_receipt(&note, &batch, "0");
        let redaction =
            demo_redaction("perp_note", &note.note_id, config.min_privacy_set_size, "0");

        state.insert_amm_pool(pool).expect("devnet pool");
        state.insert_perp_note(note).expect("devnet note");
        state
            .insert_oracle_attestation(attestation)
            .expect("devnet attestation");
        state
            .insert_funding_accrual(accrual)
            .expect("devnet accrual");
        state
            .insert_netting_batch(batch)
            .expect("devnet netting batch");
        state
            .insert_sealed_liquidity(liquidity)
            .expect("devnet sealed liquidity");
        state
            .insert_settlement_receipt(receipt)
            .expect("devnet receipt");
        state
            .insert_privacy_redaction(redaction)
            .expect("devnet redaction");
        state
    }

    pub fn insert_perp_note(&mut self, note: RealYieldPerpNote) -> Result<()> {
        require(self.amm_pools.contains_key(&note.pool_id), "unknown pool")?;
        require(note.notional_units > 0, "notional required")?;
        require(note.leverage_bps >= MAX_BPS, "leverage below 1x")?;
        require(
            self.consumed_nullifiers
                .insert(note.nullifier_commitment.clone()),
            "duplicate nullifier commitment",
        )?;
        insert_unique(&mut self.perp_notes, note.note_id.clone(), note)
    }

    pub fn insert_amm_pool(&mut self, pool: AmmPool) -> Result<()> {
        require(
            pool.fee_bps + pool.protocol_fee_bps <= MAX_BPS,
            "invalid pool fees",
        )?;
        insert_unique(&mut self.amm_pools, pool.pool_id.clone(), pool)
    }

    pub fn insert_oracle_attestation(&mut self, attestation: PqOracleAttestation) -> Result<()> {
        require(
            self.amm_pools.contains_key(&attestation.pool_id),
            "unknown attested pool",
        )?;
        require(
            attestation.privacy_set_size >= self.config.min_privacy_set_size,
            "attestation privacy set below minimum",
        )?;
        require(
            attestation.funding_rate_bps.unsigned_abs()
                <= self.config.max_funding_rate_bps.unsigned_abs(),
            "funding rate exceeds cap",
        )?;
        insert_unique(
            &mut self.oracle_attestations,
            attestation.attestation_id.clone(),
            attestation,
        )
    }

    pub fn insert_funding_accrual(&mut self, accrual: FundingAccrual) -> Result<()> {
        require(
            self.perp_notes.contains_key(&accrual.note_id),
            "unknown perp note",
        )?;
        require(
            self.oracle_attestations
                .contains_key(&accrual.oracle_attestation_id),
            "unknown oracle attestation",
        )?;
        insert_unique(
            &mut self.funding_accruals,
            accrual.accrual_id.clone(),
            accrual,
        )
    }

    pub fn insert_netting_batch(&mut self, batch: LowFeeNettingBatch) -> Result<()> {
        require(self.amm_pools.contains_key(&batch.pool_id), "unknown pool")?;
        insert_unique(&mut self.netting_batches, batch.batch_id.clone(), batch)
    }

    pub fn insert_sealed_liquidity(&mut self, position: SealedLiquidityPosition) -> Result<()> {
        require(
            self.amm_pools.contains_key(&position.pool_id),
            "unknown liquidity pool",
        )?;
        require(
            position.sealed_quote_units >= self.config.min_sealed_liquidity_units,
            "sealed liquidity below minimum",
        )?;
        insert_unique(
            &mut self.sealed_liquidity,
            position.position_id.clone(),
            position,
        )
    }

    pub fn insert_settlement_receipt(&mut self, receipt: SettlementReceipt) -> Result<()> {
        require(
            self.perp_notes.contains_key(&receipt.note_id),
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
            perp_notes: self.perp_notes.len() as u64,
            amm_pools: self.amm_pools.len() as u64,
            oracle_attestations: self.oracle_attestations.len() as u64,
            funding_accruals: self.funding_accruals.len() as u64,
            netting_batches: self.netting_batches.len() as u64,
            sealed_liquidity: self.sealed_liquidity.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            privacy_redactions: self.privacy_redactions.len() as u64,
            consumed_nullifiers: self.consumed_nullifiers.len() as u64,
            total_notional_units: self
                .perp_notes
                .values()
                .map(|note| note.notional_units)
                .sum(),
            total_net_funding_units: self
                .netting_batches
                .values()
                .map(|batch| batch.net_funding_units)
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
            config_root: record_root("REAL-YIELD-PERP-AMM-CONFIG", &self.config.public_record()),
            perp_note_root: merkle_records(
                "REAL-YIELD-PERP-AMM-NOTES",
                self.perp_notes
                    .values()
                    .map(RealYieldPerpNote::public_record),
            ),
            amm_pool_root: merkle_records(
                "REAL-YIELD-PERP-AMM-POOLS",
                self.amm_pools.values().map(AmmPool::public_record),
            ),
            oracle_attestation_root: merkle_records(
                "REAL-YIELD-PERP-AMM-ORACLE-ATTESTATIONS",
                self.oracle_attestations
                    .values()
                    .map(PqOracleAttestation::public_record),
            ),
            funding_accrual_root: merkle_records(
                "REAL-YIELD-PERP-AMM-FUNDING-ACCRUALS",
                self.funding_accruals
                    .values()
                    .map(FundingAccrual::public_record),
            ),
            netting_batch_root: merkle_records(
                "REAL-YIELD-PERP-AMM-NETTING-BATCHES",
                self.netting_batches
                    .values()
                    .map(LowFeeNettingBatch::public_record),
            ),
            sealed_liquidity_root: merkle_records(
                "REAL-YIELD-PERP-AMM-SEALED-LIQUIDITY",
                self.sealed_liquidity
                    .values()
                    .map(SealedLiquidityPosition::public_record),
            ),
            settlement_receipt_root: merkle_records(
                "REAL-YIELD-PERP-AMM-SETTLEMENT-RECEIPTS",
                self.settlement_receipts
                    .values()
                    .map(SettlementReceipt::public_record),
            ),
            privacy_redaction_root: merkle_records(
                "REAL-YIELD-PERP-AMM-REDACTIONS",
                self.privacy_redactions
                    .values()
                    .map(PrivacyRedaction::public_record),
            ),
            nullifier_root: merkle_records("REAL-YIELD-PERP-AMM-NULLIFIERS", nullifier_records),
            counters_root: record_root("REAL-YIELD-PERP-AMM-COUNTERS", &counters.public_record()),
            state_root: String::new(),
        };
        roots.state_root = record_root("REAL-YIELD-PERP-AMM-ROOTS", &roots.public_record());
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
    record_root("REAL-YIELD-PERP-AMM-STATE", record)
}

fn demo_pool(config: &Config, pool_id: &str, kind: PoolKind, salt: &str) -> AmmPool {
    AmmPool {
        pool_id: pool_id.to_string(),
        kind,
        base_asset_class: "tokenized-private-credit-real-yield-index".to_string(),
        quote_token: config.quote_token.clone(),
        sealed_long_reserve_root: demo_root("sealed-long-reserve", salt),
        sealed_short_reserve_root: demo_root("sealed-short-reserve", salt),
        sealed_quote_reserve_root: demo_root("sealed-quote-reserve", salt),
        lp_commitment_root: demo_root("lp-commitments", salt),
        invariant_root: demo_root("yield-weighted-invariant", salt),
        funding_index_root: demo_root("funding-index", salt),
        fee_bps: config.pool_fee_bps,
        protocol_fee_bps: config.protocol_fee_bps,
        active: true,
    }
}

fn demo_note(pool_id: &str, owner: &str, side: PositionSide, salt: &str) -> RealYieldPerpNote {
    RealYieldPerpNote {
        note_id: format!("devnet-real-yield-perp-note-{salt}"),
        owner_commitment: demo_root(owner, salt),
        pool_id: pool_id.to_string(),
        side,
        asset_class: "tokenized-private-credit-real-yield-index".to_string(),
        notional_units: 2_500_000_000,
        entry_nav_root: demo_root("entry-nav", salt),
        collateral_commitment_root: demo_root("collateral", salt),
        leverage_bps: 20_000,
        opened_epoch: DEVNET_EPOCH,
        last_funding_epoch: DEVNET_EPOCH,
        status: SettlementStatus::Accruing,
        encrypted_terms_root: demo_root("encrypted-perp-terms", salt),
        nullifier_commitment: demo_root("perp-note-nullifier", salt),
    }
}

fn demo_attestation(config: &Config, pool_id: &str, salt: &str) -> PqOracleAttestation {
    PqOracleAttestation {
        attestation_id: format!("devnet-real-yield-oracle-attestation-{salt}"),
        kind: AttestationKind::RealYield,
        oracle_committee_root: record_root(
            "REAL-YIELD-PERP-AMM-ORACLE-COMMITTEE",
            &json!({ "quorum": config.oracle_quorum }),
        ),
        pool_id: pool_id.to_string(),
        epoch: DEVNET_EPOCH,
        nav_commitment_root: demo_root("nav-commitment", salt),
        realized_yield_root: demo_root("realized-yield", salt),
        funding_rate_bps: 18,
        pq_signature_root: demo_root("pq-oracle-signature", salt),
        privacy_set_size: config.min_privacy_set_size,
        issued_height: DEVNET_HEIGHT + 1,
    }
}

fn demo_accrual(
    note: &RealYieldPerpNote,
    attestation: &PqOracleAttestation,
    salt: &str,
) -> FundingAccrual {
    let delta = funding_delta(note.notional_units, attestation.funding_rate_bps, note.side);
    FundingAccrual {
        accrual_id: format!("devnet-funding-accrual-{salt}"),
        note_id: note.note_id.clone(),
        pool_id: note.pool_id.clone(),
        epoch: attestation.epoch,
        side: note.side,
        notional_units: note.notional_units,
        funding_rate_bps: attestation.funding_rate_bps,
        funding_delta_units: delta,
        oracle_attestation_id: attestation.attestation_id.clone(),
        encrypted_accrual_root: demo_root("encrypted-funding-accrual", salt),
        status: SettlementStatus::Accruing,
    }
}

fn demo_netting_batch(
    config: &Config,
    pool_id: &str,
    accrual: &FundingAccrual,
    salt: &str,
) -> LowFeeNettingBatch {
    let fee_units = accrual
        .notional_units
        .saturating_mul(config.netting_fee_bps as u128)
        / MAX_BPS as u128;
    LowFeeNettingBatch {
        batch_id: format!("devnet-low-fee-netting-batch-{salt}"),
        pool_id: pool_id.to_string(),
        epoch: accrual.epoch,
        long_accrual_root: demo_root("long-accrual-set", salt),
        short_accrual_root: demo_root("short-accrual-set", salt),
        net_funding_units: accrual.funding_delta_units,
        fee_units,
        participant_set_root: demo_root("netting-participants", salt),
        settlement_root: demo_root("netting-settlement", salt),
        status: SettlementStatus::Netted,
    }
}

fn demo_liquidity(pool_id: &str, owner: &str, salt: &str) -> SealedLiquidityPosition {
    SealedLiquidityPosition {
        position_id: format!("devnet-real-yield-sealed-liquidity-{salt}"),
        pool_id: pool_id.to_string(),
        owner_commitment: demo_root(owner, salt),
        sealed_base_units: 75_000,
        sealed_quote_units: DEFAULT_MIN_SEALED_LIQUIDITY_UNITS + 10_000_000_000,
        lp_note_root: demo_root("lp-note", salt),
        locked_until_epoch: DEVNET_EPOCH + DEFAULT_SETTLEMENT_WINDOW_EPOCHS,
    }
}

fn demo_receipt(
    note: &RealYieldPerpNote,
    batch: &LowFeeNettingBatch,
    salt: &str,
) -> SettlementReceipt {
    SettlementReceipt {
        receipt_id: format!("devnet-real-yield-settlement-receipt-{salt}"),
        note_id: note.note_id.clone(),
        netting_batch_id: batch.batch_id.clone(),
        paid_funding_units: batch.net_funding_units,
        fee_paid_units: batch.fee_units,
        margin_after_root: demo_root("margin-after-netting", salt),
        status: SettlementStatus::Settled,
    }
}

fn demo_redaction(
    record_kind: &str,
    record_id: &str,
    privacy_set_size: u64,
    salt: &str,
) -> PrivacyRedaction {
    PrivacyRedaction {
        redaction_id: format!("devnet-real-yield-redaction-{record_kind}-{salt}"),
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
        PositionSide::Long => -signed,
        PositionSide::Short | PositionSide::Lp => signed,
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
        "REAL-YIELD-PERP-AMM-REDACTED-LABEL",
        &json!({ "value": value }),
    )
}

fn demo_root(label: &str, salt: &str) -> String {
    record_root(
        "REAL-YIELD-PERP-AMM-DEMO-FIXTURE",
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
