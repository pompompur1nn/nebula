use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedPriorityFeeRebateAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIORITY_FEE_REBATE_AMM_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-priority-fee-rebate-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PRIORITY_FEE_REBATE_AMM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ORACLE_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-priority-fee-rebate-oracle-v1";
pub const NOTE_COMMITMENT_SUITE: &str = "confidential-tokenized-priority-fee-rebate-note-v1";
pub const AMM_POOL_SUITE: &str = "sealed-priority-fee-rebate-amm-v1";
pub const PRIVATE_REBATE_ACCRUAL_SUITE: &str = "private-priority-fee-rebate-note-accrual-v1";
pub const REBATE_POOL_ACCRUAL_SUITE: &str = "private-tokenized-priority-fee-rebate-pool-accrual-v1";
pub const NETTING_SUITE: &str = "low-fee-priority-fee-rebate-batch-netting-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-redacted-priority-fee-rebate-amm-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MARKET_ID: &str = "private-l2-pq-priority-fee-rebate-amm-devnet";
pub const DEVNET_HEIGHT: u64 = 3_024_000;
pub const DEVNET_EPOCH: u64 = 640;
pub const DEVNET_PRIORITY_REBATE_TOKEN: &str = "tpfr";
pub const DEVNET_QUOTE_TOKEN: &str = "dusd";
pub const DEVNET_FEE_TOKEN: &str = "dxmr";
pub const DEFAULT_EPOCH_SECONDS: u64 = 600;
pub const DEFAULT_PRIORITY_FEE_INTERVAL_EPOCHS: u64 = 2;
pub const DEFAULT_REBATE_INTERVAL_EPOCHS: u64 = 6;
pub const DEFAULT_SETTLEMENT_WINDOW_EPOCHS: u64 = 18;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_POOL_FEE_BPS: u64 = 7;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 2;
pub const DEFAULT_NETTING_FEE_BPS: u64 = 1;
pub const DEFAULT_REBATE_SHARE_BPS: u64 = 7_000;
pub const DEFAULT_AMM_RESERVE_RATIO_BPS: u64 = 1_500;
pub const DEFAULT_MAX_PRIORITY_FEE_REBATE_RATE_BPS: u64 = 220;
pub const DEFAULT_MAX_ORACLE_DRIFT_BPS: i64 = 80;
pub const DEFAULT_ORACLE_QUORUM: u16 = 9;
pub const DEFAULT_ORACLE_MAX_STALENESS_EPOCHS: u64 = 2;
pub const DEFAULT_MIN_REBATE_LIQUIDITY_UNITS: u128 = 90_000_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateSide {
    SequencerEarn,
    UserRefund,
    LpRebateReserve,
}

impl RebateSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerEarn => "sequencer_earn",
            Self::UserRefund => "user_refund",
            Self::LpRebateReserve => "lp_rebate_reserve",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolKind {
    PriorityFeeRebateWeighted,
    ConstantProduct,
    ConcentratedRebate,
    NettedSettlement,
}

impl PoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PriorityFeeRebateWeighted => "priority_fee_rebate_weighted",
            Self::ConstantProduct => "constant_product",
            Self::ConcentratedRebate => "concentrated_rebate",
            Self::NettedSettlement => "netted_settlement",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PriorityFeeClearing,
    PriorityFeeRebateRate,
    RebateLiquidity,
    SettlementNetting,
    PrivateRebateDisclosure,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PriorityFeeClearing => "priority_fee_clearing",
            Self::PriorityFeeRebateRate => "priority_fee_rebate_rate",
            Self::RebateLiquidity => "rebate_liquidity",
            Self::SettlementNetting => "settlement_netting",
            Self::PrivateRebateDisclosure => "private_rebate_disclosure",
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
    pub private_rebate_accrual_suite: String,
    pub rebate_pool_accrual_suite: String,
    pub netting_suite: String,
    pub priority_rebate_token: String,
    pub quote_token: String,
    pub fee_token: String,
    pub epoch_seconds: u64,
    pub priority_fee_interval_epochs: u64,
    pub rebate_interval_epochs: u64,
    pub settlement_window_epochs: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub pool_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub netting_fee_bps: u64,
    pub rebate_share_bps: u64,
    pub amm_reserve_ratio_bps: u64,
    pub max_priority_fee_rebate_rate_bps: u64,
    pub max_oracle_drift_bps: i64,
    pub oracle_quorum: u16,
    pub oracle_max_staleness_epochs: u64,
    pub min_rebate_liquidity_units: u128,
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
            private_rebate_accrual_suite: PRIVATE_REBATE_ACCRUAL_SUITE.to_string(),
            rebate_pool_accrual_suite: REBATE_POOL_ACCRUAL_SUITE.to_string(),
            netting_suite: NETTING_SUITE.to_string(),
            priority_rebate_token: DEVNET_PRIORITY_REBATE_TOKEN.to_string(),
            quote_token: DEVNET_QUOTE_TOKEN.to_string(),
            fee_token: DEVNET_FEE_TOKEN.to_string(),
            epoch_seconds: DEFAULT_EPOCH_SECONDS,
            priority_fee_interval_epochs: DEFAULT_PRIORITY_FEE_INTERVAL_EPOCHS,
            rebate_interval_epochs: DEFAULT_REBATE_INTERVAL_EPOCHS,
            settlement_window_epochs: DEFAULT_SETTLEMENT_WINDOW_EPOCHS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            pool_fee_bps: DEFAULT_POOL_FEE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            netting_fee_bps: DEFAULT_NETTING_FEE_BPS,
            rebate_share_bps: DEFAULT_REBATE_SHARE_BPS,
            amm_reserve_ratio_bps: DEFAULT_AMM_RESERVE_RATIO_BPS,
            max_priority_fee_rebate_rate_bps: DEFAULT_MAX_PRIORITY_FEE_REBATE_RATE_BPS,
            max_oracle_drift_bps: DEFAULT_MAX_ORACLE_DRIFT_BPS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            oracle_max_staleness_epochs: DEFAULT_ORACLE_MAX_STALENESS_EPOCHS,
            min_rebate_liquidity_units: DEFAULT_MIN_REBATE_LIQUIDITY_UNITS,
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
            self.priority_fee_interval_epochs > 0,
            "sequencer interval required",
        )?;
        require(self.rebate_interval_epochs > 0, "rebate interval required")?;
        require(
            self.min_privacy_set_size <= self.target_privacy_set_size,
            "privacy target below minimum",
        )?;
        require(self.min_pq_security_bits >= 192, "pq security below floor")?;
        require(self.oracle_quorum > 0, "oracle quorum required")?;
        require(
            self.pool_fee_bps + self.protocol_fee_bps + self.netting_fee_bps <= MAX_BPS
                && self.rebate_share_bps <= MAX_BPS
                && self.amm_reserve_ratio_bps <= MAX_BPS
                && self.max_priority_fee_rebate_rate_bps <= MAX_BPS,
            "invalid bps config",
        )?;
        require(
            self.max_oracle_drift_bps.unsigned_abs() <= MAX_BPS,
            "invalid rebate drift cap",
        )
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub rebate_notes: u64,
    pub amm_pools: u64,
    pub pq_oracle_roots: u64,
    pub priority_fee_rebate_accruals: u64,
    pub rebate_pool_accruals: u64,
    pub netting_batches: u64,
    pub settlement_receipts: u64,
    pub privacy_redactions: u64,
    pub consumed_nullifiers: u64,
    pub total_priority_fee_notional_units: u128,
    pub total_net_private_rebate_units: u128,
    pub total_rebate_pool_accrued_units: u128,
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
    pub rebate_note_root: String,
    pub amm_pool_root: String,
    pub pq_oracle_root: String,
    pub priority_fee_rebate_accrual_root: String,
    pub rebate_pool_accrual_root: String,
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
pub struct PriorityFeeRebateNote {
    pub note_id: String,
    pub owner_commitment: String,
    pub pool_id: String,
    pub side: RebateSide,
    pub rebate_asset_id: String,
    pub priority_fee_notional_units: u128,
    pub entry_rebate_index_root: String,
    pub sequencer_identity_commitment_root: String,
    pub reserve_commitment_root: String,
    pub opened_epoch: u64,
    pub last_accrual_epoch: u64,
    pub status: SettlementStatus,
    pub encrypted_terms_root: String,
    pub nullifier_commitment: String,
}

impl PriorityFeeRebateNote {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "owner_commitment": redacted_label(&self.owner_commitment),
            "pool_id": self.pool_id,
            "side": self.side.as_str(),
            "rebate_asset_id": self.rebate_asset_id,
            "priority_fee_notional_units": self.priority_fee_notional_units,
            "entry_rebate_index_root": self.entry_rebate_index_root,
            "sequencer_identity_commitment_root": redacted_label(&self.sequencer_identity_commitment_root),
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
pub struct PriorityFeeRebateAmmPool {
    pub pool_id: String,
    pub kind: PoolKind,
    pub rebate_asset_id: String,
    pub quote_token: String,
    pub sealed_priority_rebate_reserve_root: String,
    pub sealed_quote_reserve_root: String,
    pub lp_rebate_reserve_commitment_root: String,
    pub invariant_root: String,
    pub rebate_index_root: String,
    pub priority_fee_rebate_pool_root: String,
    pub fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub active: bool,
}

impl PriorityFeeRebateAmmPool {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "kind": self.kind.as_str(),
            "rebate_asset_id": self.rebate_asset_id,
            "quote_token": self.quote_token,
            "sealed_priority_rebate_reserve_root": self.sealed_priority_rebate_reserve_root,
            "sealed_quote_reserve_root": self.sealed_quote_reserve_root,
            "lp_rebate_reserve_commitment_root": self.lp_rebate_reserve_commitment_root,
            "invariant_root": self.invariant_root,
            "rebate_index_root": self.rebate_index_root,
            "priority_fee_rebate_pool_root": self.priority_fee_rebate_pool_root,
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
    pub sequencer_set_root: String,
    pub priority_fee_clearing_root: String,
    pub rebate_liquidity_root: String,
    pub oracle_drift_bps: i64,
    pub priority_fee_rebate_rate_bps: u64,
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
            "sequencer_set_root": self.sequencer_set_root,
            "priority_fee_clearing_root": self.priority_fee_clearing_root,
            "rebate_liquidity_root": self.rebate_liquidity_root,
            "oracle_drift_bps": self.oracle_drift_bps,
            "priority_fee_rebate_rate_bps": self.priority_fee_rebate_rate_bps,
            "settlement_obligation_root": self.settlement_obligation_root,
            "pq_signature_root": self.pq_signature_root,
            "privacy_set_size": self.privacy_set_size,
            "issued_height": self.issued_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivatePriorityFeeRebateAccrual {
    pub accrual_id: String,
    pub note_id: String,
    pub pool_id: String,
    pub epoch: u64,
    pub side: RebateSide,
    pub priority_fee_notional_units: u128,
    pub priority_fee_rebate_rate_bps: u64,
    pub private_rebate_units: u128,
    pub oracle_root_id: String,
    pub encrypted_accrual_root: String,
    pub status: SettlementStatus,
}

impl PrivatePriorityFeeRebateAccrual {
    pub fn public_record(&self) -> Value {
        json!({
            "accrual_id": self.accrual_id,
            "note_id": self.note_id,
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "side": self.side.as_str(),
            "priority_fee_notional_units": self.priority_fee_notional_units,
            "priority_fee_rebate_rate_bps": self.priority_fee_rebate_rate_bps,
            "private_rebate_units": self.private_rebate_units,
            "oracle_root_id": self.oracle_root_id,
            "encrypted_accrual_root": self.encrypted_accrual_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateRebatePoolAccrual {
    pub accrual_id: String,
    pub note_id: String,
    pub pool_id: String,
    pub epoch: u64,
    pub gross_priority_fee_clearing_units: u128,
    pub rebate_pool_accrued_units: u128,
    pub rebate_beneficiary_set_root: String,
    pub oracle_root_id: String,
    pub encrypted_rebate_pool_root: String,
    pub status: SettlementStatus,
}

impl PrivateRebatePoolAccrual {
    pub fn public_record(&self) -> Value {
        json!({
            "accrual_id": self.accrual_id,
            "note_id": self.note_id,
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "gross_priority_fee_clearing_units": self.gross_priority_fee_clearing_units,
            "rebate_pool_accrued_units": self.rebate_pool_accrued_units,
            "rebate_beneficiary_set_root": self.rebate_beneficiary_set_root,
            "oracle_root_id": self.oracle_root_id,
            "encrypted_rebate_pool_root": self.encrypted_rebate_pool_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatchNetting {
    pub batch_id: String,
    pub pool_id: String,
    pub epoch: u64,
    pub priority_fee_rebate_accrual_root: String,
    pub rebate_pool_accrual_root: String,
    pub participant_set_root: String,
    pub net_private_rebate_units: u128,
    pub net_rebate_pool_units: u128,
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
            "priority_fee_rebate_accrual_root": self.priority_fee_rebate_accrual_root,
            "rebate_pool_accrual_root": self.rebate_pool_accrual_root,
            "participant_set_root": self.participant_set_root,
            "net_private_rebate_units": self.net_private_rebate_units,
            "net_rebate_pool_units": self.net_rebate_pool_units,
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
    pub private_rebate_paid_units: u128,
    pub rebate_pool_paid_units: u128,
    pub fee_paid_units: u128,
    pub rebate_balance_after_root: String,
    pub sequencer_balance_after_root: String,
    pub status: SettlementStatus,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "note_id": self.note_id,
            "netting_batch_id": self.netting_batch_id,
            "private_rebate_paid_units": self.private_rebate_paid_units,
            "rebate_pool_paid_units": self.rebate_pool_paid_units,
            "fee_paid_units": self.fee_paid_units,
            "rebate_balance_after_root": self.rebate_balance_after_root,
            "sequencer_balance_after_root": self.sequencer_balance_after_root,
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
    pub rebate_notes: BTreeMap<String, PriorityFeeRebateNote>,
    pub amm_pools: BTreeMap<String, PriorityFeeRebateAmmPool>,
    pub pq_oracle_roots: BTreeMap<String, PqOracleRoot>,
    pub priority_fee_rebate_accruals: BTreeMap<String, PrivatePriorityFeeRebateAccrual>,
    pub rebate_pool_accruals: BTreeMap<String, PrivateRebatePoolAccrual>,
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
            rebate_notes: BTreeMap::new(),
            amm_pools: BTreeMap::new(),
            pq_oracle_roots: BTreeMap::new(),
            priority_fee_rebate_accruals: BTreeMap::new(),
            rebate_pool_accruals: BTreeMap::new(),
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
        let pool = demo_pool(&config, "priority-fee-rebate-pool-0", "0");
        let note = demo_note(&config, &pool.pool_id, "private-sequencer-alpha", "0");
        let oracle_root = demo_oracle_root(&config, &pool.pool_id, "0");
        let priority_fee_rebate_accrual =
            demo_priority_fee_rebate_accrual(&note, &oracle_root, "0");
        let rebate_pool = demo_rebate_pool_accrual(&config, &note, &oracle_root, "0");
        let batch = demo_netting_batch(
            &config,
            &pool.pool_id,
            &priority_fee_rebate_accrual,
            &rebate_pool,
            "0",
        );
        let receipt = demo_settlement_receipt(&note, &batch, "0");
        let redaction = demo_redaction(
            "priority_fee_rebate_note",
            &note.note_id,
            config.min_privacy_set_size,
            "0",
        );

        state.insert_amm_pool(pool).expect("devnet pool");
        state.insert_rebate_note(note).expect("devnet note");
        state
            .insert_pq_oracle_root(oracle_root)
            .expect("devnet oracle root");
        state
            .insert_priority_fee_rebate_accrual(priority_fee_rebate_accrual)
            .expect("devnet priority fee rebate accrual");
        state
            .insert_rebate_pool_accrual(rebate_pool)
            .expect("devnet rebate pool accrual");
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

    pub fn insert_rebate_note(&mut self, note: PriorityFeeRebateNote) -> Result<()> {
        require(self.amm_pools.contains_key(&note.pool_id), "unknown pool")?;
        require(
            note.priority_fee_notional_units > 0,
            "priority fee notional required",
        )?;
        require(
            self.consumed_nullifiers
                .insert(note.nullifier_commitment.clone()),
            "duplicate nullifier commitment",
        )?;
        insert_unique(&mut self.rebate_notes, note.note_id.clone(), note)
    }

    pub fn insert_amm_pool(&mut self, pool: PriorityFeeRebateAmmPool) -> Result<()> {
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
            oracle_root.priority_fee_rebate_rate_bps
                <= self.config.max_priority_fee_rebate_rate_bps,
            "priority fee rebate rate exceeds cap",
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

    pub fn insert_priority_fee_rebate_accrual(
        &mut self,
        accrual: PrivatePriorityFeeRebateAccrual,
    ) -> Result<()> {
        require(
            self.rebate_notes.contains_key(&accrual.note_id),
            "unknown rebate note",
        )?;
        require(
            self.pq_oracle_roots.contains_key(&accrual.oracle_root_id),
            "unknown oracle root",
        )?;
        require(
            accrual.priority_fee_rebate_rate_bps <= self.config.max_priority_fee_rebate_rate_bps,
            "priority fee rebate accrual exceeds cap",
        )?;
        insert_unique(
            &mut self.priority_fee_rebate_accruals,
            accrual.accrual_id.clone(),
            accrual,
        )
    }

    pub fn insert_rebate_pool_accrual(&mut self, accrual: PrivateRebatePoolAccrual) -> Result<()> {
        require(
            self.rebate_notes.contains_key(&accrual.note_id),
            "unknown rebate note",
        )?;
        require(
            self.pq_oracle_roots.contains_key(&accrual.oracle_root_id),
            "unknown oracle root",
        )?;
        insert_unique(
            &mut self.rebate_pool_accruals,
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
            self.rebate_notes.contains_key(&receipt.note_id),
            "unknown rebate note",
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
            rebate_notes: self.rebate_notes.len() as u64,
            amm_pools: self.amm_pools.len() as u64,
            pq_oracle_roots: self.pq_oracle_roots.len() as u64,
            priority_fee_rebate_accruals: self.priority_fee_rebate_accruals.len() as u64,
            rebate_pool_accruals: self.rebate_pool_accruals.len() as u64,
            netting_batches: self.netting_batches.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            privacy_redactions: self.privacy_redactions.len() as u64,
            consumed_nullifiers: self.consumed_nullifiers.len() as u64,
            total_priority_fee_notional_units: self
                .rebate_notes
                .values()
                .map(|note| note.priority_fee_notional_units)
                .sum(),
            total_net_private_rebate_units: self
                .netting_batches
                .values()
                .map(|batch| batch.net_private_rebate_units)
                .sum(),
            total_rebate_pool_accrued_units: self
                .rebate_pool_accruals
                .values()
                .map(|accrual| accrual.rebate_pool_accrued_units)
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
                "PRIORITY-FEE-REBATE-AMM-CONFIG",
                &self.config.public_record(),
            ),
            rebate_note_root: merkle_records(
                "PRIORITY-FEE-REBATE-AMM-NOTES",
                self.rebate_notes
                    .values()
                    .map(PriorityFeeRebateNote::public_record),
            ),
            amm_pool_root: merkle_records(
                "PRIORITY-FEE-REBATE-AMM-POOLS",
                self.amm_pools
                    .values()
                    .map(PriorityFeeRebateAmmPool::public_record),
            ),
            pq_oracle_root: merkle_records(
                "PRIORITY-FEE-REBATE-AMM-PQ-ORACLE-ROOTS",
                self.pq_oracle_roots
                    .values()
                    .map(PqOracleRoot::public_record),
            ),
            priority_fee_rebate_accrual_root: merkle_records(
                "PRIORITY-FEE-REBATE-AMM-PRIVATE-REBATE-ACCRUALS",
                self.priority_fee_rebate_accruals
                    .values()
                    .map(PrivatePriorityFeeRebateAccrual::public_record),
            ),
            rebate_pool_accrual_root: merkle_records(
                "PRIORITY-FEE-REBATE-AMM-REBATE-POOL-ACCRUALS",
                self.rebate_pool_accruals
                    .values()
                    .map(PrivateRebatePoolAccrual::public_record),
            ),
            netting_batch_root: merkle_records(
                "PRIORITY-FEE-REBATE-AMM-NETTING-BATCHES",
                self.netting_batches
                    .values()
                    .map(LowFeeBatchNetting::public_record),
            ),
            settlement_receipt_root: merkle_records(
                "PRIORITY-FEE-REBATE-AMM-SETTLEMENT-RECEIPTS",
                self.settlement_receipts
                    .values()
                    .map(SettlementReceipt::public_record),
            ),
            privacy_redaction_root: merkle_records(
                "PRIORITY-FEE-REBATE-AMM-REDACTIONS",
                self.privacy_redactions
                    .values()
                    .map(PrivacyRedaction::public_record),
            ),
            nullifier_root: merkle_records("PRIORITY-FEE-REBATE-AMM-NULLIFIERS", nullifier_records),
            counters_root: record_root(
                "PRIORITY-FEE-REBATE-AMM-COUNTERS",
                &counters.public_record(),
            ),
            state_root: String::new(),
        };
        roots.state_root = record_root("PRIORITY-FEE-REBATE-AMM-ROOTS", &roots.public_record());
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
    record_root("PRIORITY-FEE-REBATE-AMM-STATE", record)
}

fn demo_pool(config: &Config, pool_id: &str, salt: &str) -> PriorityFeeRebateAmmPool {
    PriorityFeeRebateAmmPool {
        pool_id: pool_id.to_string(),
        kind: PoolKind::PriorityFeeRebateWeighted,
        rebate_asset_id: config.priority_rebate_token.clone(),
        quote_token: config.quote_token.clone(),
        sealed_priority_rebate_reserve_root: demo_root("sealed-priority-fee-rebate-reserve", salt),
        sealed_quote_reserve_root: demo_root("sealed-quote-reserve", salt),
        lp_rebate_reserve_commitment_root: demo_root("lp-rebate-commitments", salt),
        invariant_root: demo_root("priority-fee-rebate-weighted-invariant", salt),
        rebate_index_root: demo_root("rebate-index", salt),
        priority_fee_rebate_pool_root: demo_root("priority-fee-rebate", salt),
        fee_bps: config.pool_fee_bps,
        protocol_fee_bps: config.protocol_fee_bps,
        active: true,
    }
}

fn demo_note(
    config: &Config,
    pool_id: &str,
    sequencer_identity: &str,
    salt: &str,
) -> PriorityFeeRebateNote {
    PriorityFeeRebateNote {
        note_id: format!("devnet-priority-fee-rebate-note-{salt}"),
        owner_commitment: demo_root("rebate-note-owner", salt),
        pool_id: pool_id.to_string(),
        side: RebateSide::SequencerEarn,
        rebate_asset_id: config.priority_rebate_token.clone(),
        priority_fee_notional_units: 5_000_000_000,
        entry_rebate_index_root: demo_root("entry-rebate-index", salt),
        sequencer_identity_commitment_root: demo_root(sequencer_identity, salt),
        reserve_commitment_root: demo_root("rebate-reserve-commitment", salt),
        opened_epoch: DEVNET_EPOCH,
        last_accrual_epoch: DEVNET_EPOCH,
        status: SettlementStatus::Accruing,
        encrypted_terms_root: demo_root("encrypted-priority-fee-rebate-terms", salt),
        nullifier_commitment: demo_root("priority-fee-rebate-note-nullifier", salt),
    }
}

fn demo_oracle_root(config: &Config, pool_id: &str, salt: &str) -> PqOracleRoot {
    PqOracleRoot {
        oracle_root_id: format!("devnet-priority-fee-rebate-pq-oracle-root-{salt}"),
        kind: AttestationKind::PriorityFeeClearing,
        committee_root: record_root(
            "PRIORITY-FEE-REBATE-AMM-ORACLE-COMMITTEE",
            &json!({ "quorum": config.oracle_quorum }),
        ),
        pool_id: pool_id.to_string(),
        epoch: DEVNET_EPOCH,
        sequencer_set_root: demo_root("sequencer-set", salt),
        priority_fee_clearing_root: demo_root("sequencer-block-value", salt),
        rebate_liquidity_root: demo_root("rebate-liquidity", salt),
        oracle_drift_bps: 14,
        priority_fee_rebate_rate_bps: 88,
        settlement_obligation_root: demo_root("settlement-obligations", salt),
        pq_signature_root: demo_root("pq-oracle-signature", salt),
        privacy_set_size: config.min_privacy_set_size,
        issued_height: DEVNET_HEIGHT + 1,
    }
}

fn demo_priority_fee_rebate_accrual(
    note: &PriorityFeeRebateNote,
    oracle_root: &PqOracleRoot,
    salt: &str,
) -> PrivatePriorityFeeRebateAccrual {
    let private_rebate_units = priority_fee_rebate(
        note.priority_fee_notional_units,
        oracle_root.priority_fee_rebate_rate_bps,
    );
    PrivatePriorityFeeRebateAccrual {
        accrual_id: format!("devnet-priority-fee-rebate-accrual-{salt}"),
        note_id: note.note_id.clone(),
        pool_id: note.pool_id.clone(),
        epoch: oracle_root.epoch,
        side: note.side,
        priority_fee_notional_units: note.priority_fee_notional_units,
        priority_fee_rebate_rate_bps: oracle_root.priority_fee_rebate_rate_bps,
        private_rebate_units,
        oracle_root_id: oracle_root.oracle_root_id.clone(),
        encrypted_accrual_root: demo_root("encrypted-priority-fee-rebate-accrual", salt),
        status: SettlementStatus::Accruing,
    }
}

fn demo_rebate_pool_accrual(
    config: &Config,
    note: &PriorityFeeRebateNote,
    oracle_root: &PqOracleRoot,
    salt: &str,
) -> PrivateRebatePoolAccrual {
    let gross_priority_fee_clearing_units = config
        .min_rebate_liquidity_units
        .saturating_mul(oracle_root.priority_fee_rebate_rate_bps as u128)
        / MAX_BPS as u128;
    let rebate_pool_accrued_units = gross_priority_fee_clearing_units
        .saturating_mul(config.rebate_share_bps as u128)
        / MAX_BPS as u128;
    PrivateRebatePoolAccrual {
        accrual_id: format!("devnet-sequencer-rebate-pool-accrual-{salt}"),
        note_id: note.note_id.clone(),
        pool_id: note.pool_id.clone(),
        epoch: oracle_root.epoch,
        gross_priority_fee_clearing_units,
        rebate_pool_accrued_units,
        rebate_beneficiary_set_root: demo_root("rebate-pool-beneficiaries", salt),
        oracle_root_id: oracle_root.oracle_root_id.clone(),
        encrypted_rebate_pool_root: demo_root("encrypted-rebate-pool-accrual", salt),
        status: SettlementStatus::Accruing,
    }
}

fn demo_netting_batch(
    config: &Config,
    pool_id: &str,
    priority_fee_rebate_accrual: &PrivatePriorityFeeRebateAccrual,
    rebate_pool: &PrivateRebatePoolAccrual,
    salt: &str,
) -> LowFeeBatchNetting {
    let fee_units = priority_fee_rebate_accrual
        .priority_fee_notional_units
        .saturating_mul(config.netting_fee_bps as u128)
        / MAX_BPS as u128;
    LowFeeBatchNetting {
        batch_id: format!("devnet-priority-fee-rebate-low-fee-netting-batch-{salt}"),
        pool_id: pool_id.to_string(),
        epoch: priority_fee_rebate_accrual.epoch,
        priority_fee_rebate_accrual_root: demo_root("sequencer-accrual-set", salt),
        rebate_pool_accrual_root: demo_root("rebate-pool-accrual-set", salt),
        participant_set_root: demo_root("netting-participants", salt),
        net_private_rebate_units: priority_fee_rebate_accrual.private_rebate_units,
        net_rebate_pool_units: rebate_pool.rebate_pool_accrued_units,
        fee_units,
        settlement_root: demo_root("netting-settlement", salt),
        status: SettlementStatus::Netted,
    }
}

fn demo_settlement_receipt(
    note: &PriorityFeeRebateNote,
    batch: &LowFeeBatchNetting,
    salt: &str,
) -> SettlementReceipt {
    SettlementReceipt {
        receipt_id: format!("devnet-priority-fee-rebate-settlement-receipt-{salt}"),
        note_id: note.note_id.clone(),
        netting_batch_id: batch.batch_id.clone(),
        private_rebate_paid_units: batch.net_private_rebate_units,
        rebate_pool_paid_units: batch.net_rebate_pool_units,
        fee_paid_units: batch.fee_units,
        rebate_balance_after_root: demo_root("rebate-balance-after-netting", salt),
        sequencer_balance_after_root: demo_root("sequencer-balance-after-netting", salt),
        status: SettlementStatus::Rebated,
    }
}

fn demo_redaction(
    record_kind: &str,
    record_id: &str,
    privacy_set_size: u64,
    salt: &str,
) -> PrivacyRedaction {
    PrivacyRedaction {
        redaction_id: format!("devnet-priority-fee-rebate-redaction-{record_kind}-{salt}"),
        record_kind: record_kind.to_string(),
        record_id: record_id.to_string(),
        redacted_fields: vec![
            "owner_commitment".to_string(),
            "sequencer_identity_commitment_root".to_string(),
            "reserve_commitment_root".to_string(),
            "encrypted_terms_root".to_string(),
            "encrypted_accrual_root".to_string(),
            "encrypted_rebate_pool_root".to_string(),
        ],
        disclosure_root: demo_root("selective-disclosure", salt),
        privacy_set_size,
    }
}

fn priority_fee_rebate(notional_units: u128, priority_fee_rebate_rate_bps: u64) -> u128 {
    notional_units.saturating_mul(priority_fee_rebate_rate_bps as u128) / MAX_BPS as u128
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
        "PRIORITY-FEE-REBATE-AMM-REDACTED-LABEL",
        &json!({ "value": value }),
    )
}

fn demo_root(label: &str, salt: &str) -> String {
    record_root(
        "PRIORITY-FEE-REBATE-AMM-DEMO-FIXTURE",
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
