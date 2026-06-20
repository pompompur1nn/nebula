use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedBuilderMevSpreadAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_BUILDER_MEV_SPREAD_AMM_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-builder-mev-spread-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_BUILDER_MEV_SPREAD_AMM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ORACLE_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-builder-mev-spread-oracle-v1";
pub const NOTE_COMMITMENT_SUITE: &str = "confidential-tokenized-builder-mev-spread-note-v1";
pub const AMM_POOL_SUITE: &str = "sealed-builder-mev-spread-amm-v1";
pub const SPREAD_ACCRUAL_SUITE: &str = "private-builder-mev-spread-accrual-v1";
pub const BUILDER_SETTLEMENT_SUITE: &str = "private-tokenized-builder-spread-settlement-v1";
pub const NETTING_SUITE: &str = "low-fee-builder-mev-spread-batch-netting-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-redacted-builder-mev-spread-amm-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MARKET_ID: &str = "private-l2-pq-builder-mev-spread-amm-devnet";
pub const DEVNET_HEIGHT: u64 = 3_024_000;
pub const DEVNET_EPOCH: u64 = 640;
pub const DEVNET_SPREAD_TOKEN: &str = "tbms";
pub const DEVNET_QUOTE_TOKEN: &str = "dusd";
pub const DEVNET_FEE_TOKEN: &str = "dxmr";
pub const DEFAULT_EPOCH_SECONDS: u64 = 600;
pub const DEFAULT_SPREAD_INTERVAL_EPOCHS: u64 = 2;
pub const DEFAULT_SETTLEMENT_INTERVAL_EPOCHS: u64 = 6;
pub const DEFAULT_SETTLEMENT_WINDOW_EPOCHS: u64 = 18;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_POOL_FEE_BPS: u64 = 6;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 2;
pub const DEFAULT_NETTING_FEE_BPS: u64 = 1;
pub const DEFAULT_BUILDER_SHARE_BPS: u64 = 7_200;
pub const DEFAULT_LP_RESERVE_RATIO_BPS: u64 = 1_200;
pub const DEFAULT_MAX_SPREAD_RATE_BPS: u64 = 240;
pub const DEFAULT_MAX_ORACLE_DRIFT_BPS: i64 = 75;
pub const DEFAULT_ORACLE_QUORUM: u16 = 9;
pub const DEFAULT_ORACLE_MAX_STALENESS_EPOCHS: u64 = 2;
pub const DEFAULT_MIN_SPREAD_LIQUIDITY_UNITS: u128 = 100_000_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpreadSide {
    BuilderLongSpread,
    SearcherShortSpread,
    LpSpreadVault,
}

impl SpreadSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuilderLongSpread => "builder_long_spread",
            Self::SearcherShortSpread => "searcher_short_spread",
            Self::LpSpreadVault => "lp_spread_vault",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolKind {
    BuilderMevSpreadWeighted,
    ConstantProduct,
    ConcentratedSpread,
    NettedSettlement,
}

impl PoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuilderMevSpreadWeighted => "builder_mev_spread_weighted",
            Self::ConstantProduct => "constant_product",
            Self::ConcentratedSpread => "concentrated_spread",
            Self::NettedSettlement => "netted_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    BuilderMevSpread,
    BlockValueDelta,
    SearcherPaymentDelta,
    LiquidityDepth,
    BatchNetting,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuilderMevSpread => "builder_mev_spread",
            Self::BlockValueDelta => "block_value_delta",
            Self::SearcherPaymentDelta => "searcher_payment_delta",
            Self::LiquidityDepth => "liquidity_depth",
            Self::BatchNetting => "batch_netting",
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
    Distributed,
    Disputed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accruing => "accruing",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Distributed => "distributed",
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
    pub note_commitment_suite: String,
    pub amm_pool_suite: String,
    pub spread_accrual_suite: String,
    pub builder_settlement_suite: String,
    pub netting_suite: String,
    pub spread_token: String,
    pub quote_token: String,
    pub fee_token: String,
    pub epoch_seconds: u64,
    pub spread_interval_epochs: u64,
    pub settlement_interval_epochs: u64,
    pub settlement_window_epochs: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub pool_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub netting_fee_bps: u64,
    pub builder_share_bps: u64,
    pub lp_reserve_ratio_bps: u64,
    pub max_spread_rate_bps: u64,
    pub max_oracle_drift_bps: i64,
    pub oracle_quorum: u16,
    pub oracle_max_staleness_epochs: u64,
    pub min_spread_liquidity_units: u128,
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
            note_commitment_suite: NOTE_COMMITMENT_SUITE.to_string(),
            amm_pool_suite: AMM_POOL_SUITE.to_string(),
            spread_accrual_suite: SPREAD_ACCRUAL_SUITE.to_string(),
            builder_settlement_suite: BUILDER_SETTLEMENT_SUITE.to_string(),
            netting_suite: NETTING_SUITE.to_string(),
            spread_token: DEVNET_SPREAD_TOKEN.to_string(),
            quote_token: DEVNET_QUOTE_TOKEN.to_string(),
            fee_token: DEVNET_FEE_TOKEN.to_string(),
            epoch_seconds: DEFAULT_EPOCH_SECONDS,
            spread_interval_epochs: DEFAULT_SPREAD_INTERVAL_EPOCHS,
            settlement_interval_epochs: DEFAULT_SETTLEMENT_INTERVAL_EPOCHS,
            settlement_window_epochs: DEFAULT_SETTLEMENT_WINDOW_EPOCHS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            pool_fee_bps: DEFAULT_POOL_FEE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            netting_fee_bps: DEFAULT_NETTING_FEE_BPS,
            builder_share_bps: DEFAULT_BUILDER_SHARE_BPS,
            lp_reserve_ratio_bps: DEFAULT_LP_RESERVE_RATIO_BPS,
            max_spread_rate_bps: DEFAULT_MAX_SPREAD_RATE_BPS,
            max_oracle_drift_bps: DEFAULT_MAX_ORACLE_DRIFT_BPS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            oracle_max_staleness_epochs: DEFAULT_ORACLE_MAX_STALENESS_EPOCHS,
            min_spread_liquidity_units: DEFAULT_MIN_SPREAD_LIQUIDITY_UNITS,
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
        require(self.spread_interval_epochs > 0, "spread interval required")?;
        require(
            self.settlement_interval_epochs > 0,
            "settlement interval required",
        )?;
        require(
            self.min_privacy_set_size <= self.target_privacy_set_size,
            "privacy target below minimum",
        )?;
        require(self.min_pq_security_bits >= 192, "pq security below floor")?;
        require(self.oracle_quorum > 0, "oracle quorum required")?;
        require(
            self.pool_fee_bps + self.protocol_fee_bps + self.netting_fee_bps <= MAX_BPS
                && self.builder_share_bps <= MAX_BPS
                && self.lp_reserve_ratio_bps <= MAX_BPS
                && self.max_spread_rate_bps <= MAX_BPS,
            "invalid bps config",
        )?;
        require(
            self.max_oracle_drift_bps.unsigned_abs() <= MAX_BPS,
            "invalid oracle drift cap",
        )
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub spread_notes: u64,
    pub amm_pools: u64,
    pub pq_oracle_roots: u64,
    pub spread_accruals: u64,
    pub builder_settlements: u64,
    pub netting_batches: u64,
    pub settlement_receipts: u64,
    pub privacy_redactions: u64,
    pub consumed_nullifiers: u64,
    pub total_spread_notional_units: u128,
    pub total_private_spread_accrued_units: u128,
    pub total_builder_settlement_units: u128,
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
    pub spread_note_root: String,
    pub amm_pool_root: String,
    pub pq_oracle_root: String,
    pub spread_accrual_root: String,
    pub builder_settlement_root: String,
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
pub struct BuilderMevSpreadNote {
    pub note_id: String,
    pub owner_commitment: String,
    pub pool_id: String,
    pub side: SpreadSide,
    pub spread_asset_id: String,
    pub spread_notional_units: u128,
    pub entry_spread_index_root: String,
    pub builder_identity_commitment_root: String,
    pub reserve_commitment_root: String,
    pub opened_epoch: u64,
    pub last_accrual_epoch: u64,
    pub status: SettlementStatus,
    pub encrypted_terms_root: String,
    pub nullifier_commitment: String,
}

impl BuilderMevSpreadNote {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "owner_commitment": redacted_label(&self.owner_commitment),
            "pool_id": self.pool_id,
            "side": self.side.as_str(),
            "spread_asset_id": self.spread_asset_id,
            "spread_notional_units": self.spread_notional_units,
            "entry_spread_index_root": self.entry_spread_index_root,
            "builder_identity_commitment_root": redacted_label(&self.builder_identity_commitment_root),
            "reserve_commitment_root": self.reserve_commitment_root,
            "opened_epoch": self.opened_epoch,
            "last_accrual_epoch": self.last_accrual_epoch,
            "status": self.status.as_str(),
            "encrypted_terms_root": self.encrypted_terms_root,
            "nullifier_commitment": self.nullifier_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuilderMevSpreadAmmPool {
    pub pool_id: String,
    pub kind: PoolKind,
    pub spread_asset_id: String,
    pub quote_token: String,
    pub sealed_spread_reserve_root: String,
    pub sealed_quote_reserve_root: String,
    pub lp_spread_commitment_root: String,
    pub invariant_root: String,
    pub spread_index_root: String,
    pub builder_settlement_vault_root: String,
    pub fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub active: bool,
}

impl BuilderMevSpreadAmmPool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "kind": self.kind.as_str(),
            "spread_asset_id": self.spread_asset_id,
            "quote_token": self.quote_token,
            "sealed_spread_reserve_root": self.sealed_spread_reserve_root,
            "sealed_quote_reserve_root": self.sealed_quote_reserve_root,
            "lp_spread_commitment_root": self.lp_spread_commitment_root,
            "invariant_root": self.invariant_root,
            "spread_index_root": self.spread_index_root,
            "builder_settlement_vault_root": self.builder_settlement_vault_root,
            "fee_bps": self.fee_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqOracleRoot {
    pub oracle_root_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub pool_id: String,
    pub epoch: u64,
    pub builder_set_root: String,
    pub mev_value_root: String,
    pub searcher_payment_root: String,
    pub spread_rate_bps: u64,
    pub oracle_drift_bps: i64,
    pub liquidity_depth_root: String,
    pub settlement_obligation_root: String,
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
            "builder_set_root": self.builder_set_root,
            "mev_value_root": self.mev_value_root,
            "searcher_payment_root": self.searcher_payment_root,
            "spread_rate_bps": self.spread_rate_bps,
            "oracle_drift_bps": self.oracle_drift_bps,
            "liquidity_depth_root": self.liquidity_depth_root,
            "settlement_obligation_root": self.settlement_obligation_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_set_size": self.privacy_set_size,
            "issued_height": self.issued_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateSpreadAccrual {
    pub accrual_id: String,
    pub note_id: String,
    pub pool_id: String,
    pub epoch: u64,
    pub side: SpreadSide,
    pub spread_notional_units: u128,
    pub spread_rate_bps: u64,
    pub private_spread_accrued_units: u128,
    pub oracle_root_id: String,
    pub encrypted_accrual_root: String,
    pub status: SettlementStatus,
}

impl PrivateSpreadAccrual {
    pub fn public_record(&self) -> Value {
        json!({
            "accrual_id": self.accrual_id,
            "note_id": self.note_id,
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "side": self.side.as_str(),
            "spread_notional_units": self.spread_notional_units,
            "spread_rate_bps": self.spread_rate_bps,
            "private_spread_accrued_units": self.private_spread_accrued_units,
            "oracle_root_id": self.oracle_root_id,
            "encrypted_accrual_root": self.encrypted_accrual_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateBuilderSettlement {
    pub settlement_id: String,
    pub note_id: String,
    pub pool_id: String,
    pub epoch: u64,
    pub gross_mev_value_units: u128,
    pub builder_settlement_units: u128,
    pub builder_beneficiary_set_root: String,
    pub oracle_root_id: String,
    pub encrypted_settlement_root: String,
    pub status: SettlementStatus,
}

impl PrivateBuilderSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "note_id": self.note_id,
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "gross_mev_value_units": self.gross_mev_value_units,
            "builder_settlement_units": self.builder_settlement_units,
            "builder_beneficiary_set_root": self.builder_beneficiary_set_root,
            "oracle_root_id": self.oracle_root_id,
            "encrypted_settlement_root": self.encrypted_settlement_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatchNetting {
    pub batch_id: String,
    pub pool_id: String,
    pub epoch: u64,
    pub spread_accrual_root: String,
    pub builder_settlement_root: String,
    pub participant_set_root: String,
    pub net_private_spread_units: u128,
    pub net_builder_settlement_units: u128,
    pub fee_units: u128,
    pub settlement_root: String,
    pub status: SettlementStatus,
}

impl LowFeeBatchNetting {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "spread_accrual_root": self.spread_accrual_root,
            "builder_settlement_root": self.builder_settlement_root,
            "participant_set_root": self.participant_set_root,
            "net_private_spread_units": self.net_private_spread_units,
            "net_builder_settlement_units": self.net_builder_settlement_units,
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
    pub spread_paid_units: u128,
    pub builder_settlement_paid_units: u128,
    pub fee_paid_units: u128,
    pub spread_balance_after_root: String,
    pub builder_balance_after_root: String,
    pub status: SettlementStatus,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "note_id": self.note_id,
            "netting_batch_id": self.netting_batch_id,
            "spread_paid_units": self.spread_paid_units,
            "builder_settlement_paid_units": self.builder_settlement_paid_units,
            "fee_paid_units": self.fee_paid_units,
            "spread_balance_after_root": self.spread_balance_after_root,
            "builder_balance_after_root": self.builder_balance_after_root,
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
    pub spread_notes: BTreeMap<String, BuilderMevSpreadNote>,
    pub amm_pools: BTreeMap<String, BuilderMevSpreadAmmPool>,
    pub pq_oracle_roots: BTreeMap<String, PqOracleRoot>,
    pub spread_accruals: BTreeMap<String, PrivateSpreadAccrual>,
    pub builder_settlements: BTreeMap<String, PrivateBuilderSettlement>,
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
            spread_notes: BTreeMap::new(),
            amm_pools: BTreeMap::new(),
            pq_oracle_roots: BTreeMap::new(),
            spread_accruals: BTreeMap::new(),
            builder_settlements: BTreeMap::new(),
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
        let pool = demo_pool(&config, "builder-mev-spread-pool-0", "0");
        let note = demo_note(&config, &pool.pool_id, "private-builder-alpha", "0");
        let oracle_root = demo_oracle_root(&config, &pool.pool_id, "0");
        let spread_accrual = demo_spread_accrual(&note, &oracle_root, "0");
        let builder_settlement = demo_builder_settlement(&config, &note, &oracle_root, "0");
        let batch = demo_netting_batch(
            &config,
            &pool.pool_id,
            &spread_accrual,
            &builder_settlement,
            "0",
        );
        let receipt = demo_settlement_receipt(&note, &batch, "0");
        let redaction = demo_redaction(
            "builder_mev_spread_note",
            &note.note_id,
            config.min_privacy_set_size,
            "0",
        );

        state.insert_amm_pool(pool).expect("devnet pool");
        state.insert_spread_note(note).expect("devnet note");
        state
            .insert_pq_oracle_root(oracle_root)
            .expect("devnet oracle root");
        state
            .insert_spread_accrual(spread_accrual)
            .expect("devnet spread accrual");
        state
            .insert_builder_settlement(builder_settlement)
            .expect("devnet builder settlement");
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

    pub fn insert_spread_note(&mut self, note: BuilderMevSpreadNote) -> Result<()> {
        require(self.amm_pools.contains_key(&note.pool_id), "unknown pool")?;
        require(note.spread_notional_units > 0, "spread notional required")?;
        require(
            self.consumed_nullifiers
                .insert(note.nullifier_commitment.clone()),
            "duplicate nullifier commitment",
        )?;
        insert_unique(&mut self.spread_notes, note.note_id.clone(), note)
    }

    pub fn insert_amm_pool(&mut self, pool: BuilderMevSpreadAmmPool) -> Result<()> {
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
            oracle_root.spread_rate_bps <= self.config.max_spread_rate_bps,
            "spread rate exceeds cap",
        )?;
        require(
            oracle_root.oracle_drift_bps.unsigned_abs()
                <= self.config.max_oracle_drift_bps.unsigned_abs(),
            "oracle drift exceeds cap",
        )?;
        insert_unique(
            &mut self.pq_oracle_roots,
            oracle_root.oracle_root_id.clone(),
            oracle_root,
        )
    }

    pub fn insert_spread_accrual(&mut self, accrual: PrivateSpreadAccrual) -> Result<()> {
        require(
            self.spread_notes.contains_key(&accrual.note_id),
            "unknown spread note",
        )?;
        require(
            self.pq_oracle_roots.contains_key(&accrual.oracle_root_id),
            "unknown oracle root",
        )?;
        require(
            accrual.spread_rate_bps <= self.config.max_spread_rate_bps,
            "spread accrual exceeds cap",
        )?;
        insert_unique(
            &mut self.spread_accruals,
            accrual.accrual_id.clone(),
            accrual,
        )
    }

    pub fn insert_builder_settlement(
        &mut self,
        settlement: PrivateBuilderSettlement,
    ) -> Result<()> {
        require(
            self.spread_notes.contains_key(&settlement.note_id),
            "unknown spread note",
        )?;
        require(
            self.pq_oracle_roots
                .contains_key(&settlement.oracle_root_id),
            "unknown oracle root",
        )?;
        insert_unique(
            &mut self.builder_settlements,
            settlement.settlement_id.clone(),
            settlement,
        )
    }

    pub fn insert_netting_batch(&mut self, batch: LowFeeBatchNetting) -> Result<()> {
        require(self.amm_pools.contains_key(&batch.pool_id), "unknown pool")?;
        insert_unique(&mut self.netting_batches, batch.batch_id.clone(), batch)
    }

    pub fn insert_settlement_receipt(&mut self, receipt: SettlementReceipt) -> Result<()> {
        require(
            self.spread_notes.contains_key(&receipt.note_id),
            "unknown spread note",
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
            spread_notes: self.spread_notes.len() as u64,
            amm_pools: self.amm_pools.len() as u64,
            pq_oracle_roots: self.pq_oracle_roots.len() as u64,
            spread_accruals: self.spread_accruals.len() as u64,
            builder_settlements: self.builder_settlements.len() as u64,
            netting_batches: self.netting_batches.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            privacy_redactions: self.privacy_redactions.len() as u64,
            consumed_nullifiers: self.consumed_nullifiers.len() as u64,
            total_spread_notional_units: self
                .spread_notes
                .values()
                .map(|note| note.spread_notional_units)
                .sum(),
            total_private_spread_accrued_units: self
                .spread_accruals
                .values()
                .map(|accrual| accrual.private_spread_accrued_units)
                .sum(),
            total_builder_settlement_units: self
                .builder_settlements
                .values()
                .map(|settlement| settlement.builder_settlement_units)
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
                "BUILDER-MEV-SPREAD-AMM-CONFIG",
                &self.config.public_record(),
            ),
            spread_note_root: merkle_records(
                "BUILDER-MEV-SPREAD-AMM-NOTES",
                self.spread_notes
                    .values()
                    .map(BuilderMevSpreadNote::public_record),
            ),
            amm_pool_root: merkle_records(
                "BUILDER-MEV-SPREAD-AMM-POOLS",
                self.amm_pools
                    .values()
                    .map(BuilderMevSpreadAmmPool::public_record),
            ),
            pq_oracle_root: merkle_records(
                "BUILDER-MEV-SPREAD-AMM-PQ-ORACLE-ROOTS",
                self.pq_oracle_roots
                    .values()
                    .map(PqOracleRoot::public_record),
            ),
            spread_accrual_root: merkle_records(
                "BUILDER-MEV-SPREAD-AMM-SPREAD-ACCRUALS",
                self.spread_accruals
                    .values()
                    .map(PrivateSpreadAccrual::public_record),
            ),
            builder_settlement_root: merkle_records(
                "BUILDER-MEV-SPREAD-AMM-BUILDER-SETTLEMENTS",
                self.builder_settlements
                    .values()
                    .map(PrivateBuilderSettlement::public_record),
            ),
            netting_batch_root: merkle_records(
                "BUILDER-MEV-SPREAD-AMM-NETTING-BATCHES",
                self.netting_batches
                    .values()
                    .map(LowFeeBatchNetting::public_record),
            ),
            settlement_receipt_root: merkle_records(
                "BUILDER-MEV-SPREAD-AMM-SETTLEMENT-RECEIPTS",
                self.settlement_receipts
                    .values()
                    .map(SettlementReceipt::public_record),
            ),
            privacy_redaction_root: merkle_records(
                "BUILDER-MEV-SPREAD-AMM-REDACTIONS",
                self.privacy_redactions
                    .values()
                    .map(PrivacyRedaction::public_record),
            ),
            nullifier_root: merkle_records("BUILDER-MEV-SPREAD-AMM-NULLIFIERS", nullifier_records),
            counters_root: record_root(
                "BUILDER-MEV-SPREAD-AMM-COUNTERS",
                &counters.public_record(),
            ),
            state_root: String::new(),
        };
        roots.state_root = record_root("BUILDER-MEV-SPREAD-AMM-ROOTS", &roots.public_record());
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
    record_root("BUILDER-MEV-SPREAD-AMM-STATE", record)
}

fn demo_pool(config: &Config, pool_id: &str, salt: &str) -> BuilderMevSpreadAmmPool {
    BuilderMevSpreadAmmPool {
        pool_id: pool_id.to_string(),
        kind: PoolKind::BuilderMevSpreadWeighted,
        spread_asset_id: config.spread_token.clone(),
        quote_token: config.quote_token.clone(),
        sealed_spread_reserve_root: demo_root("sealed-spread-reserve", salt),
        sealed_quote_reserve_root: demo_root("sealed-quote-reserve", salt),
        lp_spread_commitment_root: demo_root("lp-spread-commitments", salt),
        invariant_root: demo_root("builder-mev-spread-weighted-invariant", salt),
        spread_index_root: demo_root("spread-index", salt),
        builder_settlement_vault_root: demo_root("builder-settlement-vault", salt),
        fee_bps: config.pool_fee_bps,
        protocol_fee_bps: config.protocol_fee_bps,
        active: true,
    }
}

fn demo_note(
    config: &Config,
    pool_id: &str,
    builder_identity: &str,
    salt: &str,
) -> BuilderMevSpreadNote {
    BuilderMevSpreadNote {
        note_id: format!("devnet-builder-mev-spread-note-{salt}"),
        owner_commitment: demo_root("spread-note-owner", salt),
        pool_id: pool_id.to_string(),
        side: SpreadSide::BuilderLongSpread,
        spread_asset_id: config.spread_token.clone(),
        spread_notional_units: 5_500_000_000,
        entry_spread_index_root: demo_root("entry-spread-index", salt),
        builder_identity_commitment_root: demo_root(builder_identity, salt),
        reserve_commitment_root: demo_root("spread-reserve-commitment", salt),
        opened_epoch: DEVNET_EPOCH,
        last_accrual_epoch: DEVNET_EPOCH,
        status: SettlementStatus::Accruing,
        encrypted_terms_root: demo_root("encrypted-builder-mev-spread-terms", salt),
        nullifier_commitment: demo_root("builder-mev-spread-note-nullifier", salt),
    }
}

fn demo_oracle_root(config: &Config, pool_id: &str, salt: &str) -> PqOracleRoot {
    PqOracleRoot {
        oracle_root_id: format!("devnet-builder-mev-spread-pq-oracle-root-{salt}"),
        kind: AttestationKind::BuilderMevSpread,
        committee_root: record_root(
            "BUILDER-MEV-SPREAD-AMM-ORACLE-COMMITTEE",
            &json!({ "quorum": config.oracle_quorum }),
        ),
        pool_id: pool_id.to_string(),
        epoch: DEVNET_EPOCH,
        builder_set_root: demo_root("builder-set", salt),
        mev_value_root: demo_root("builder-mev-value", salt),
        searcher_payment_root: demo_root("searcher-payment-delta", salt),
        spread_rate_bps: 96,
        oracle_drift_bps: 12,
        liquidity_depth_root: demo_root("spread-liquidity-depth", salt),
        settlement_obligation_root: demo_root("spread-settlement-obligations", salt),
        pq_signature_root: demo_root("pq-oracle-signature", salt),
        privacy_set_size: config.min_privacy_set_size,
        issued_height: DEVNET_HEIGHT + 1,
    }
}

fn demo_spread_accrual(
    note: &BuilderMevSpreadNote,
    oracle_root: &PqOracleRoot,
    salt: &str,
) -> PrivateSpreadAccrual {
    let private_spread_accrued_units =
        spread_accrual(note.spread_notional_units, oracle_root.spread_rate_bps);
    PrivateSpreadAccrual {
        accrual_id: format!("devnet-builder-mev-spread-accrual-{salt}"),
        note_id: note.note_id.clone(),
        pool_id: note.pool_id.clone(),
        epoch: oracle_root.epoch,
        side: note.side,
        spread_notional_units: note.spread_notional_units,
        spread_rate_bps: oracle_root.spread_rate_bps,
        private_spread_accrued_units,
        oracle_root_id: oracle_root.oracle_root_id.clone(),
        encrypted_accrual_root: demo_root("encrypted-builder-mev-spread-accrual", salt),
        status: SettlementStatus::Accruing,
    }
}

fn demo_builder_settlement(
    config: &Config,
    note: &BuilderMevSpreadNote,
    oracle_root: &PqOracleRoot,
    salt: &str,
) -> PrivateBuilderSettlement {
    let gross_mev_value_units = config
        .min_spread_liquidity_units
        .saturating_mul(oracle_root.spread_rate_bps as u128)
        / MAX_BPS as u128;
    let builder_settlement_units =
        gross_mev_value_units.saturating_mul(config.builder_share_bps as u128) / MAX_BPS as u128;
    PrivateBuilderSettlement {
        settlement_id: format!("devnet-builder-mev-spread-settlement-{salt}"),
        note_id: note.note_id.clone(),
        pool_id: note.pool_id.clone(),
        epoch: oracle_root.epoch,
        gross_mev_value_units,
        builder_settlement_units,
        builder_beneficiary_set_root: demo_root("builder-spread-beneficiaries", salt),
        oracle_root_id: oracle_root.oracle_root_id.clone(),
        encrypted_settlement_root: demo_root("encrypted-builder-spread-settlement", salt),
        status: SettlementStatus::Accruing,
    }
}

fn demo_netting_batch(
    config: &Config,
    pool_id: &str,
    spread_accrual: &PrivateSpreadAccrual,
    builder_settlement: &PrivateBuilderSettlement,
    salt: &str,
) -> LowFeeBatchNetting {
    let fee_units = spread_accrual
        .spread_notional_units
        .saturating_mul(config.netting_fee_bps as u128)
        / MAX_BPS as u128;
    LowFeeBatchNetting {
        batch_id: format!("devnet-builder-mev-spread-low-fee-netting-batch-{salt}"),
        pool_id: pool_id.to_string(),
        epoch: spread_accrual.epoch,
        spread_accrual_root: demo_root("spread-accrual-set", salt),
        builder_settlement_root: demo_root("builder-settlement-set", salt),
        participant_set_root: demo_root("netting-participants", salt),
        net_private_spread_units: spread_accrual.private_spread_accrued_units,
        net_builder_settlement_units: builder_settlement.builder_settlement_units,
        fee_units,
        settlement_root: demo_root("netting-settlement", salt),
        status: SettlementStatus::Netted,
    }
}

fn demo_settlement_receipt(
    note: &BuilderMevSpreadNote,
    batch: &LowFeeBatchNetting,
    salt: &str,
) -> SettlementReceipt {
    SettlementReceipt {
        receipt_id: format!("devnet-builder-mev-spread-settlement-receipt-{salt}"),
        note_id: note.note_id.clone(),
        netting_batch_id: batch.batch_id.clone(),
        spread_paid_units: batch.net_private_spread_units,
        builder_settlement_paid_units: batch.net_builder_settlement_units,
        fee_paid_units: batch.fee_units,
        spread_balance_after_root: demo_root("spread-balance-after-netting", salt),
        builder_balance_after_root: demo_root("builder-balance-after-netting", salt),
        status: SettlementStatus::Distributed,
    }
}

fn demo_redaction(
    record_kind: &str,
    record_id: &str,
    privacy_set_size: u64,
    salt: &str,
) -> PrivacyRedaction {
    PrivacyRedaction {
        redaction_id: format!("devnet-builder-mev-spread-redaction-{record_kind}-{salt}"),
        record_kind: record_kind.to_string(),
        record_id: record_id.to_string(),
        redacted_fields: vec![
            "owner_commitment".to_string(),
            "builder_identity_commitment_root".to_string(),
            "reserve_commitment_root".to_string(),
            "encrypted_terms_root".to_string(),
            "encrypted_accrual_root".to_string(),
            "encrypted_settlement_root".to_string(),
        ],
        disclosure_root: demo_root("selective-disclosure", salt),
        privacy_set_size,
    }
}

fn spread_accrual(notional_units: u128, spread_rate_bps: u64) -> u128 {
    notional_units.saturating_mul(spread_rate_bps as u128) / MAX_BPS as u128
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
        "BUILDER-MEV-SPREAD-AMM-REDACTED-LABEL",
        &json!({ "value": value }),
    )
}

fn demo_root(label: &str, salt: &str) -> String {
    record_root(
        "BUILDER-MEV-SPREAD-AMM-DEMO-FIXTURE",
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
