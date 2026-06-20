use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedLiquidityRebateBondAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_LIQUIDITY_REBATE_BOND_AMM_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-liquidity-rebate-bond-amm-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_LIQUIDITY_REBATE_BOND_AMM_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SETTLEMENT_COUPON_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-liquidity-rebate-coupon-v1";
pub const CONFIDENTIAL_BOND_NOTE_SUITE: &str =
    "confidential-tokenized-liquidity-rebate-bond-note-v1";
pub const AMM_CURVE_ACCOUNTING_SUITE: &str = "sealed-liquidity-rebate-bond-amm-curve-accounting-v1";
pub const REBATE_BUCKET_SUITE: &str = "tokenized-liquidity-rebate-bond-bucket-v1";
pub const NETTING_SUITE: &str = "low-fee-liquidity-rebate-bond-netting-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "privacy-preserving-roots-only-liquidity-rebate-bond-amm-record-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MARKET_ID: &str =
    "private-l2-pq-confidential-tokenized-liquidity-rebate-bond-amm-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_184_000;
pub const DEVNET_EPOCH: u64 = 704;
pub const DEVNET_BOND_TOKEN: &str = "dlrb";
pub const DEVNET_QUOTE_TOKEN: &str = "dusd";
pub const DEVNET_FEE_TOKEN: &str = "dxmr";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_EPOCH_SECONDS: u64 = 600;
pub const DEFAULT_COUPON_INTERVAL_EPOCHS: u64 = 6;
pub const DEFAULT_SETTLEMENT_WINDOW_EPOCHS: u64 = 24;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_POOL_FEE_BPS: u64 = 6;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 2;
pub const DEFAULT_NETTING_FEE_BPS: u64 = 1;
pub const DEFAULT_LIQUIDITY_REBATE_SHARE_BPS: u64 = 6_500;
pub const DEFAULT_RESERVE_REBATE_SHARE_BPS: u64 = 2_000;
pub const DEFAULT_CURVE_RESERVE_RATIO_BPS: u64 = 1_800;
pub const DEFAULT_MAX_REBATE_COUPON_RATE_BPS: u64 = 360;
pub const DEFAULT_MAX_ORACLE_DRIFT_BPS: i64 = 75;
pub const DEFAULT_ORACLE_QUORUM: u16 = 9;
pub const DEFAULT_COUPON_QUORUM: u16 = 7;
pub const DEFAULT_ORACLE_MAX_STALENESS_EPOCHS: u64 = 2;
pub const DEFAULT_MIN_SEALED_LIQUIDITY_UNITS: u128 = 120_000_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BondSide {
    LpRebateBond,
    MakerLiquidity,
    TakerFeeOffset,
    ProtocolReserve,
}

impl BondSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LpRebateBond => "lp_rebate_bond",
            Self::MakerLiquidity => "maker_liquidity",
            Self::TakerFeeOffset => "taker_fee_offset",
            Self::ProtocolReserve => "protocol_reserve",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolKind {
    ConfidentialConstantProduct,
    RebateWeighted,
    CouponNetted,
    ReserveBuffered,
}

impl PoolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialConstantProduct => "confidential_constant_product",
            Self::RebateWeighted => "rebate_weighted",
            Self::CouponNetted => "coupon_netted",
            Self::ReserveBuffered => "reserve_buffered",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Draft,
    PqSigned,
    Netted,
    Settled,
    Redeemed,
    Disputed,
    Expired,
}

impl CouponStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::PqSigned => "pq_signed",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Redeemed => "redeemed",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BondStatus {
    Minted,
    Bonded,
    Accruing,
    CouponReady,
    Netted,
    Redeemed,
    Frozen,
}

impl BondStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minted => "minted",
            Self::Bonded => "bonded",
            Self::Accruing => "accruing",
            Self::CouponReady => "coupon_ready",
            Self::Netted => "netted",
            Self::Redeemed => "redeemed",
            Self::Frozen => "frozen",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    CurveAccounting,
    RebateCouponRate,
    LiquidityUtilization,
    LowFeeNetting,
    PrivateDisclosure,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CurveAccounting => "curve_accounting",
            Self::RebateCouponRate => "rebate_coupon_rate",
            Self::LiquidityUtilization => "liquidity_utilization",
            Self::LowFeeNetting => "low_fee_netting",
            Self::PrivateDisclosure => "private_disclosure",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub market_id: String,
    pub hash_suite: String,
    pub pq_settlement_coupon_suite: String,
    pub confidential_bond_note_suite: String,
    pub amm_curve_accounting_suite: String,
    pub rebate_bucket_suite: String,
    pub netting_suite: String,
    pub bond_token: String,
    pub quote_token: String,
    pub fee_token: String,
    pub epoch_seconds: u64,
    pub coupon_interval_epochs: u64,
    pub settlement_window_epochs: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub oracle_quorum: u16,
    pub coupon_quorum: u16,
    pub oracle_max_staleness_epochs: u64,
    pub pool_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub netting_fee_bps: u64,
    pub liquidity_rebate_share_bps: u64,
    pub reserve_rebate_share_bps: u64,
    pub curve_reserve_ratio_bps: u64,
    pub max_rebate_coupon_rate_bps: u64,
    pub max_oracle_drift_bps: i64,
    pub min_sealed_liquidity_units: u128,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            market_id: DEVNET_MARKET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_settlement_coupon_suite: PQ_SETTLEMENT_COUPON_SUITE.to_string(),
            confidential_bond_note_suite: CONFIDENTIAL_BOND_NOTE_SUITE.to_string(),
            amm_curve_accounting_suite: AMM_CURVE_ACCOUNTING_SUITE.to_string(),
            rebate_bucket_suite: REBATE_BUCKET_SUITE.to_string(),
            netting_suite: NETTING_SUITE.to_string(),
            bond_token: DEVNET_BOND_TOKEN.to_string(),
            quote_token: DEVNET_QUOTE_TOKEN.to_string(),
            fee_token: DEVNET_FEE_TOKEN.to_string(),
            epoch_seconds: DEFAULT_EPOCH_SECONDS,
            coupon_interval_epochs: DEFAULT_COUPON_INTERVAL_EPOCHS,
            settlement_window_epochs: DEFAULT_SETTLEMENT_WINDOW_EPOCHS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            coupon_quorum: DEFAULT_COUPON_QUORUM,
            oracle_max_staleness_epochs: DEFAULT_ORACLE_MAX_STALENESS_EPOCHS,
            pool_fee_bps: DEFAULT_POOL_FEE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            netting_fee_bps: DEFAULT_NETTING_FEE_BPS,
            liquidity_rebate_share_bps: DEFAULT_LIQUIDITY_REBATE_SHARE_BPS,
            reserve_rebate_share_bps: DEFAULT_RESERVE_REBATE_SHARE_BPS,
            curve_reserve_ratio_bps: DEFAULT_CURVE_RESERVE_RATIO_BPS,
            max_rebate_coupon_rate_bps: DEFAULT_MAX_REBATE_COUPON_RATE_BPS,
            max_oracle_drift_bps: DEFAULT_MAX_ORACLE_DRIFT_BPS,
            min_sealed_liquidity_units: DEFAULT_MIN_SEALED_LIQUIDITY_UNITS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol mismatch",
        )?;
        require(self.schema_version == SCHEMA_VERSION, "schema mismatch")?;
        require(self.chain_id == CHAIN_ID, "chain id mismatch")?;
        require(!self.market_id.trim().is_empty(), "market id required")?;
        require(self.epoch_seconds > 0, "epoch seconds required")?;
        require(self.coupon_interval_epochs > 0, "coupon interval required")?;
        require(
            self.settlement_window_epochs >= self.coupon_interval_epochs,
            "settlement window below coupon interval",
        )?;
        require(
            self.min_privacy_set_size <= self.target_privacy_set_size,
            "privacy target below minimum",
        )?;
        require(self.min_pq_security_bits >= 192, "pq security below floor")?;
        require(self.oracle_quorum > 0, "oracle quorum required")?;
        require(self.coupon_quorum > 0, "coupon quorum required")?;
        require(
            self.pool_fee_bps + self.protocol_fee_bps + self.netting_fee_bps <= MAX_BPS,
            "fee bps exceeds max",
        )?;
        require(
            self.liquidity_rebate_share_bps + self.reserve_rebate_share_bps <= MAX_BPS,
            "rebate share exceeds max",
        )?;
        require(
            self.curve_reserve_ratio_bps <= MAX_BPS
                && self.max_rebate_coupon_rate_bps <= MAX_BPS
                && self.max_oracle_drift_bps.unsigned_abs() <= MAX_BPS,
            "invalid curve or oracle bps",
        )?;
        require(
            self.min_sealed_liquidity_units > 0,
            "minimum sealed liquidity required",
        )
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub bond_notes: u64,
    pub amm_pools: u64,
    pub curve_snapshots: u64,
    pub pq_coupon_attestations: u64,
    pub settlement_coupons: u64,
    pub rebate_accruals: u64,
    pub netting_batches: u64,
    pub settlement_receipts: u64,
    pub privacy_redactions: u64,
    pub consumed_nullifiers: u64,
    pub total_bond_notional_units: u128,
    pub total_sealed_liquidity_units: u128,
    pub total_rebate_coupon_units: u128,
    pub total_netted_quote_units: u128,
    pub total_low_fee_units: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub bond_note_root: String,
    pub amm_pool_root: String,
    pub curve_snapshot_root: String,
    pub pq_coupon_attestation_root: String,
    pub settlement_coupon_root: String,
    pub rebate_accrual_root: String,
    pub netting_batch_root: String,
    pub settlement_receipt_root: String,
    pub privacy_redaction_root: String,
    pub nullifier_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "bond_note_root": self.bond_note_root,
            "amm_pool_root": self.amm_pool_root,
            "curve_snapshot_root": self.curve_snapshot_root,
            "pq_coupon_attestation_root": self.pq_coupon_attestation_root,
            "settlement_coupon_root": self.settlement_coupon_root,
            "rebate_accrual_root": self.rebate_accrual_root,
            "netting_batch_root": self.netting_batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "privacy_redaction_root": self.privacy_redaction_root,
            "nullifier_root": self.nullifier_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BondMintInput {
    pub note_id: String,
    pub owner_commitment: String,
    pub pool_id: String,
    pub side: BondSide,
    pub bond_notional_units: u128,
    pub sealed_liquidity_units: u128,
    pub entry_curve_root: String,
    pub encrypted_terms_root: String,
    pub nullifier_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CurveSnapshotInput {
    pub snapshot_id: String,
    pub pool_id: String,
    pub epoch: u64,
    pub sealed_bond_reserve_root: String,
    pub sealed_quote_reserve_root: String,
    pub invariant_root: String,
    pub utilization_bps: u64,
    pub rebate_index_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CouponSettlementInput {
    pub coupon_id: String,
    pub note_id: String,
    pub pool_id: String,
    pub epoch: u64,
    pub coupon_rate_bps: u64,
    pub rebate_coupon_units: u128,
    pub pq_signature_root: String,
    pub settlement_coupon_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NettingInput {
    pub batch_id: String,
    pub pool_id: String,
    pub epoch: u64,
    pub coupon_root: String,
    pub participant_set_root: String,
    pub gross_rebate_coupon_units: u128,
    pub net_quote_units: u128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityRebateBondNote {
    pub note_id: String,
    pub owner_commitment: String,
    pub pool_id: String,
    pub side: BondSide,
    pub bond_token: String,
    pub quote_token: String,
    pub bond_notional_units: u128,
    pub sealed_liquidity_units: u128,
    pub entry_curve_root: String,
    pub entry_rebate_index_root: String,
    pub opened_epoch: u64,
    pub maturity_epoch: u64,
    pub last_coupon_epoch: u64,
    pub status: BondStatus,
    pub encrypted_terms_root: String,
    pub nullifier_commitment: String,
}

impl LiquidityRebateBondNote {
    pub fn from_input(input: BondMintInput, config: &Config, current_epoch: u64) -> Result<Self> {
        require(!input.note_id.trim().is_empty(), "note id required")?;
        require(!input.pool_id.trim().is_empty(), "pool id required")?;
        require(
            input.sealed_liquidity_units >= config.min_sealed_liquidity_units,
            "sealed liquidity below minimum",
        )?;
        require(input.bond_notional_units > 0, "bond notional required")?;
        Ok(Self {
            note_id: input.note_id,
            owner_commitment: input.owner_commitment,
            pool_id: input.pool_id,
            side: input.side,
            bond_token: config.bond_token.clone(),
            quote_token: config.quote_token.clone(),
            bond_notional_units: input.bond_notional_units,
            sealed_liquidity_units: input.sealed_liquidity_units,
            entry_curve_root: input.entry_curve_root.clone(),
            entry_rebate_index_root: domain_hash(
                "liquidity-rebate-entry-index",
                &[
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(&input.note_id),
                    HashPart::Str(&input.entry_curve_root),
                ],
                32,
            ),
            opened_epoch: current_epoch,
            maturity_epoch: current_epoch + config.settlement_window_epochs,
            last_coupon_epoch: current_epoch,
            status: BondStatus::Bonded,
            encrypted_terms_root: input.encrypted_terms_root,
            nullifier_commitment: input.nullifier_commitment,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "owner_commitment": redacted_label(&self.owner_commitment),
            "pool_id": self.pool_id,
            "side": self.side.as_str(),
            "bond_token": self.bond_token,
            "quote_token": self.quote_token,
            "bond_notional_units": self.bond_notional_units,
            "sealed_liquidity_units": self.sealed_liquidity_units,
            "entry_curve_root": self.entry_curve_root,
            "entry_rebate_index_root": self.entry_rebate_index_root,
            "opened_epoch": self.opened_epoch,
            "maturity_epoch": self.maturity_epoch,
            "last_coupon_epoch": self.last_coupon_epoch,
            "status": self.status.as_str(),
            "encrypted_terms_root": self.encrypted_terms_root,
            "nullifier_commitment": self.nullifier_commitment,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityRebateBondAmmPool {
    pub pool_id: String,
    pub kind: PoolKind,
    pub bond_token: String,
    pub quote_token: String,
    pub fee_token: String,
    pub sealed_bond_reserve_root: String,
    pub sealed_quote_reserve_root: String,
    pub sealed_rebate_reserve_root: String,
    pub curve_invariant_root: String,
    pub rebate_index_root: String,
    pub lp_commitment_root: String,
    pub reserve_buffer_root: String,
    pub fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub active: bool,
}

impl LiquidityRebateBondAmmPool {
    pub fn devnet(config: &Config) -> Self {
        Self {
            pool_id: "dlrb-dusd-confidential-rebate-curve".to_string(),
            kind: PoolKind::RebateWeighted,
            bond_token: config.bond_token.clone(),
            quote_token: config.quote_token.clone(),
            fee_token: config.fee_token.clone(),
            sealed_bond_reserve_root: seeded_root("sealed-bond-reserve", 1),
            sealed_quote_reserve_root: seeded_root("sealed-quote-reserve", 1),
            sealed_rebate_reserve_root: seeded_root("sealed-rebate-reserve", 1),
            curve_invariant_root: seeded_root("curve-invariant", 1),
            rebate_index_root: seeded_root("rebate-index", 1),
            lp_commitment_root: seeded_root("lp-commitment", 1),
            reserve_buffer_root: seeded_root("reserve-buffer", 1),
            fee_bps: config.pool_fee_bps,
            protocol_fee_bps: config.protocol_fee_bps,
            active: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "kind": self.kind.as_str(),
            "bond_token": self.bond_token,
            "quote_token": self.quote_token,
            "fee_token": self.fee_token,
            "sealed_bond_reserve_root": self.sealed_bond_reserve_root,
            "sealed_quote_reserve_root": self.sealed_quote_reserve_root,
            "sealed_rebate_reserve_root": self.sealed_rebate_reserve_root,
            "curve_invariant_root": self.curve_invariant_root,
            "rebate_index_root": self.rebate_index_root,
            "lp_commitment_root": redacted_label(&self.lp_commitment_root),
            "reserve_buffer_root": self.reserve_buffer_root,
            "fee_bps": self.fee_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialCurveSnapshot {
    pub snapshot_id: String,
    pub pool_id: String,
    pub epoch: u64,
    pub sealed_bond_reserve_root: String,
    pub sealed_quote_reserve_root: String,
    pub sealed_rebate_reserve_root: String,
    pub invariant_root: String,
    pub utilization_bps: u64,
    pub reserve_ratio_bps: u64,
    pub rebate_index_root: String,
    pub accounting_proof_root: String,
}

impl ConfidentialCurveSnapshot {
    pub fn from_input(input: CurveSnapshotInput, config: &Config) -> Result<Self> {
        require(input.utilization_bps <= MAX_BPS, "utilization exceeds max")?;
        Ok(Self {
            snapshot_id: input.snapshot_id,
            pool_id: input.pool_id,
            epoch: input.epoch,
            sealed_bond_reserve_root: input.sealed_bond_reserve_root,
            sealed_quote_reserve_root: input.sealed_quote_reserve_root,
            sealed_rebate_reserve_root: domain_hash(
                "sealed-rebate-reserve",
                &[
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(&input.pool_id),
                    HashPart::U64(input.epoch),
                    HashPart::Int(input.utilization_bps as i128),
                ],
                32,
            ),
            invariant_root: input.invariant_root,
            utilization_bps: input.utilization_bps,
            reserve_ratio_bps: config.curve_reserve_ratio_bps,
            rebate_index_root: input.rebate_index_root,
            accounting_proof_root: domain_hash(
                "curve-accounting-proof",
                &[
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(&input.snapshot_id),
                    HashPart::Str(AMM_CURVE_ACCOUNTING_SUITE),
                ],
                32,
            ),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "sealed_bond_reserve_root": self.sealed_bond_reserve_root,
            "sealed_quote_reserve_root": self.sealed_quote_reserve_root,
            "sealed_rebate_reserve_root": self.sealed_rebate_reserve_root,
            "invariant_root": self.invariant_root,
            "utilization_bps": self.utilization_bps,
            "reserve_ratio_bps": self.reserve_ratio_bps,
            "rebate_index_root": self.rebate_index_root,
            "accounting_proof_root": self.accounting_proof_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCouponAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub committee_root: String,
    pub pool_id: String,
    pub epoch: u64,
    pub curve_snapshot_root: String,
    pub liquidity_utilization_root: String,
    pub coupon_rate_bps: u64,
    pub oracle_drift_bps: i64,
    pub pq_signature_root: String,
    pub privacy_set_size: u64,
    pub issued_height: u64,
}

impl PqCouponAttestation {
    pub fn devnet(pool_id: &str, epoch: u64, config: &Config) -> Self {
        Self {
            attestation_id: format!("pq-coupon-attestation-{epoch}"),
            kind: AttestationKind::RebateCouponRate,
            committee_root: seeded_root("coupon-committee", epoch),
            pool_id: pool_id.to_string(),
            epoch,
            curve_snapshot_root: seeded_root("curve-snapshot-root", epoch),
            liquidity_utilization_root: seeded_root("liquidity-utilization", epoch),
            coupon_rate_bps: 128,
            oracle_drift_bps: -9,
            pq_signature_root: seeded_root("pq-coupon-signature", epoch),
            privacy_set_size: config.target_privacy_set_size,
            issued_height: DEVNET_L2_HEIGHT,
        }
    }

    pub fn validate(&self, config: &Config, current_epoch: u64) -> Result<()> {
        require(
            self.coupon_rate_bps <= config.max_rebate_coupon_rate_bps,
            "coupon rate exceeds cap",
        )?;
        require(
            self.oracle_drift_bps.unsigned_abs() <= config.max_oracle_drift_bps.unsigned_abs(),
            "coupon oracle drift exceeds cap",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "coupon privacy set below minimum",
        )?;
        require(
            self.epoch + config.oracle_max_staleness_epochs >= current_epoch,
            "coupon attestation stale",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "committee_root": self.committee_root,
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "curve_snapshot_root": self.curve_snapshot_root,
            "liquidity_utilization_root": self.liquidity_utilization_root,
            "coupon_rate_bps": self.coupon_rate_bps,
            "oracle_drift_bps": self.oracle_drift_bps,
            "pq_signature_root": self.pq_signature_root,
            "privacy_set_size": self.privacy_set_size,
            "issued_height": self.issued_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSignedSettlementCoupon {
    pub coupon_id: String,
    pub note_id: String,
    pub pool_id: String,
    pub epoch: u64,
    pub coupon_rate_bps: u64,
    pub rebate_coupon_units: u128,
    pub settlement_coupon_root: String,
    pub pq_signature_root: String,
    pub attestation_id: String,
    pub status: CouponStatus,
}

impl PqSignedSettlementCoupon {
    pub fn from_input(input: CouponSettlementInput, attestation_id: String) -> Result<Self> {
        require(input.coupon_rate_bps <= MAX_BPS, "coupon rate exceeds max")?;
        require(
            input.rebate_coupon_units > 0,
            "rebate coupon units required",
        )?;
        Ok(Self {
            coupon_id: input.coupon_id,
            note_id: input.note_id,
            pool_id: input.pool_id,
            epoch: input.epoch,
            coupon_rate_bps: input.coupon_rate_bps,
            rebate_coupon_units: input.rebate_coupon_units,
            settlement_coupon_root: input.settlement_coupon_root,
            pq_signature_root: input.pq_signature_root,
            attestation_id,
            status: CouponStatus::PqSigned,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "note_id": self.note_id,
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "coupon_rate_bps": self.coupon_rate_bps,
            "rebate_coupon_units": self.rebate_coupon_units,
            "settlement_coupon_root": self.settlement_coupon_root,
            "pq_signature_root": self.pq_signature_root,
            "attestation_id": self.attestation_id,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateRebateAccrual {
    pub accrual_id: String,
    pub note_id: String,
    pub pool_id: String,
    pub epoch: u64,
    pub side: BondSide,
    pub sealed_liquidity_units: u128,
    pub coupon_rate_bps: u64,
    pub liquidity_rebate_units: u128,
    pub reserve_rebate_units: u128,
    pub encrypted_accrual_root: String,
    pub status: CouponStatus,
}

impl PrivateRebateAccrual {
    pub fn from_note(
        note: &LiquidityRebateBondNote,
        coupon: &PqSignedSettlementCoupon,
        config: &Config,
    ) -> Self {
        let gross = bps(note.sealed_liquidity_units, coupon.coupon_rate_bps);
        let liquidity_rebate_units = bps(gross, config.liquidity_rebate_share_bps);
        let reserve_rebate_units = bps(gross, config.reserve_rebate_share_bps);
        Self {
            accrual_id: format!("accrual-{}-{}", note.note_id, coupon.epoch),
            note_id: note.note_id.clone(),
            pool_id: note.pool_id.clone(),
            epoch: coupon.epoch,
            side: note.side,
            sealed_liquidity_units: note.sealed_liquidity_units,
            coupon_rate_bps: coupon.coupon_rate_bps,
            liquidity_rebate_units,
            reserve_rebate_units,
            encrypted_accrual_root: domain_hash(
                "private-liquidity-rebate-accrual",
                &[
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(&note.note_id),
                    HashPart::Str(&coupon.coupon_id),
                ],
                32,
            ),
            status: CouponStatus::PqSigned,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "accrual_id": self.accrual_id,
            "note_id": self.note_id,
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "side": self.side.as_str(),
            "sealed_liquidity_units": self.sealed_liquidity_units,
            "coupon_rate_bps": self.coupon_rate_bps,
            "liquidity_rebate_units": self.liquidity_rebate_units,
            "reserve_rebate_units": self.reserve_rebate_units,
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
    pub coupon_root: String,
    pub accrual_root: String,
    pub participant_set_root: String,
    pub gross_rebate_coupon_units: u128,
    pub net_quote_units: u128,
    pub low_fee_units: u128,
    pub settlement_root: String,
    pub status: CouponStatus,
}

impl LowFeeNettingBatch {
    pub fn from_input(input: NettingInput, accrual_root: String, config: &Config) -> Self {
        let low_fee_units = bps(input.net_quote_units, config.netting_fee_bps);
        Self {
            batch_id: input.batch_id,
            pool_id: input.pool_id,
            epoch: input.epoch,
            coupon_root: input.coupon_root,
            accrual_root,
            participant_set_root: input.participant_set_root,
            gross_rebate_coupon_units: input.gross_rebate_coupon_units,
            net_quote_units: input.net_quote_units,
            low_fee_units,
            settlement_root: domain_hash(
                "low-fee-netting-settlement",
                &[
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(NETTING_SUITE),
                    HashPart::Str(&input.batch_id),
                    HashPart::Int(input.net_quote_units as i128),
                ],
                32,
            ),
            status: CouponStatus::Netted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "pool_id": self.pool_id,
            "epoch": self.epoch,
            "coupon_root": self.coupon_root,
            "accrual_root": self.accrual_root,
            "participant_set_root": self.participant_set_root,
            "gross_rebate_coupon_units": self.gross_rebate_coupon_units,
            "net_quote_units": self.net_quote_units,
            "low_fee_units": self.low_fee_units,
            "settlement_root": self.settlement_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub note_id: String,
    pub coupon_id: String,
    pub netting_batch_id: String,
    pub paid_rebate_units: u128,
    pub paid_quote_units: u128,
    pub low_fee_units: u128,
    pub owner_balance_after_root: String,
    pub reserve_balance_after_root: String,
    pub status: CouponStatus,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "note_id": self.note_id,
            "coupon_id": self.coupon_id,
            "netting_batch_id": self.netting_batch_id,
            "paid_rebate_units": self.paid_rebate_units,
            "paid_quote_units": self.paid_quote_units,
            "low_fee_units": self.low_fee_units,
            "owner_balance_after_root": redacted_label(&self.owner_balance_after_root),
            "reserve_balance_after_root": self.reserve_balance_after_root,
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
    pub bond_notes: BTreeMap<String, LiquidityRebateBondNote>,
    pub amm_pools: BTreeMap<String, LiquidityRebateBondAmmPool>,
    pub curve_snapshots: BTreeMap<String, ConfidentialCurveSnapshot>,
    pub pq_coupon_attestations: BTreeMap<String, PqCouponAttestation>,
    pub settlement_coupons: BTreeMap<String, PqSignedSettlementCoupon>,
    pub rebate_accruals: BTreeMap<String, PrivateRebateAccrual>,
    pub netting_batches: BTreeMap<String, LowFeeNettingBatch>,
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
            bond_notes: BTreeMap::new(),
            amm_pools: BTreeMap::new(),
            curve_snapshots: BTreeMap::new(),
            pq_coupon_attestations: BTreeMap::new(),
            settlement_coupons: BTreeMap::new(),
            rebate_accruals: BTreeMap::new(),
            netting_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::new(config.clone(), DEVNET_L2_HEIGHT, DEVNET_EPOCH)
            .expect("devnet config must be valid");
        let pool = LiquidityRebateBondAmmPool::devnet(&config);
        let pool_id = pool.pool_id.clone();
        state.amm_pools.insert(pool_id.clone(), pool);

        let note = LiquidityRebateBondNote::from_input(
            BondMintInput {
                note_id: "dlrb-note-alpha".to_string(),
                owner_commitment: seeded_root("owner-alpha", 1),
                pool_id: pool_id.clone(),
                side: BondSide::LpRebateBond,
                bond_notional_units: 4_000_000_000,
                sealed_liquidity_units: 220_000_000_000,
                entry_curve_root: seeded_root("entry-curve-alpha", 1),
                encrypted_terms_root: seeded_root("encrypted-terms-alpha", 1),
                nullifier_commitment: seeded_root("nullifier-alpha", 1),
            },
            &config,
            DEVNET_EPOCH,
        )
        .expect("devnet note must be valid");
        let note_id = note.note_id.clone();
        state.bond_notes.insert(note_id.clone(), note.clone());

        let snapshot = ConfidentialCurveSnapshot::from_input(
            CurveSnapshotInput {
                snapshot_id: "curve-snapshot-alpha".to_string(),
                pool_id: pool_id.clone(),
                epoch: DEVNET_EPOCH,
                sealed_bond_reserve_root: seeded_root("snapshot-bond-reserve", 1),
                sealed_quote_reserve_root: seeded_root("snapshot-quote-reserve", 1),
                invariant_root: seeded_root("snapshot-invariant", 1),
                utilization_bps: 4_250,
                rebate_index_root: seeded_root("snapshot-rebate-index", 1),
            },
            &config,
        )
        .expect("devnet snapshot must be valid");
        state
            .curve_snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot);

        let attestation = PqCouponAttestation::devnet(&pool_id, DEVNET_EPOCH, &config);
        let attestation_id = attestation.attestation_id.clone();
        state
            .pq_coupon_attestations
            .insert(attestation_id.clone(), attestation);

        let coupon = PqSignedSettlementCoupon::from_input(
            CouponSettlementInput {
                coupon_id: "coupon-alpha-704".to_string(),
                note_id: note_id.clone(),
                pool_id: pool_id.clone(),
                epoch: DEVNET_EPOCH,
                coupon_rate_bps: 128,
                rebate_coupon_units: 2_816_000_000,
                pq_signature_root: seeded_root("coupon-pq-signature-alpha", 1),
                settlement_coupon_root: seeded_root("settlement-coupon-alpha", 1),
            },
            attestation_id,
        )
        .expect("devnet coupon must be valid");
        let coupon_id = coupon.coupon_id.clone();
        state
            .settlement_coupons
            .insert(coupon_id.clone(), coupon.clone());

        let accrual = PrivateRebateAccrual::from_note(&note, &coupon, &config);
        let accrual_id = accrual.accrual_id.clone();
        state.rebate_accruals.insert(accrual_id, accrual);

        let coupon_root = merkle_root_for_records(
            "devnet-coupon-root",
            state
                .settlement_coupons
                .values()
                .map(PqSignedSettlementCoupon::public_record),
        );
        let accrual_root = merkle_root_for_records(
            "devnet-accrual-root",
            state
                .rebate_accruals
                .values()
                .map(PrivateRebateAccrual::public_record),
        );
        let netting = LowFeeNettingBatch::from_input(
            NettingInput {
                batch_id: "low-fee-netting-alpha".to_string(),
                pool_id: pool_id.clone(),
                epoch: DEVNET_EPOCH,
                coupon_root,
                participant_set_root: seeded_root("participants-alpha", 1),
                gross_rebate_coupon_units: 2_816_000_000,
                net_quote_units: 2_807_552_000,
            },
            accrual_root,
            &config,
        );
        let batch_id = netting.batch_id.clone();
        state
            .netting_batches
            .insert(batch_id.clone(), netting.clone());

        state.settlement_receipts.insert(
            "receipt-alpha-704".to_string(),
            SettlementReceipt {
                receipt_id: "receipt-alpha-704".to_string(),
                note_id,
                coupon_id,
                netting_batch_id: batch_id,
                paid_rebate_units: 2_816_000_000,
                paid_quote_units: netting.net_quote_units,
                low_fee_units: netting.low_fee_units,
                owner_balance_after_root: seeded_root("owner-balance-alpha", 1),
                reserve_balance_after_root: seeded_root("reserve-balance-alpha", 1),
                status: CouponStatus::Settled,
            },
        );
        state.privacy_redactions.insert(
            "redaction-alpha".to_string(),
            PrivacyRedaction {
                redaction_id: "redaction-alpha".to_string(),
                record_kind: "liquidity_rebate_bond_note".to_string(),
                record_id: "dlrb-note-alpha".to_string(),
                redacted_fields: vec![
                    "owner_commitment".to_string(),
                    "owner_balance_after_root".to_string(),
                ],
                disclosure_root: seeded_root("disclosure-alpha", 1),
                privacy_set_size: config.target_privacy_set_size,
            },
        );
        state
            .consumed_nullifiers
            .insert(seeded_root("spent-nullifier-alpha", 1));
        state
    }

    pub fn mint_bond(&mut self, input: BondMintInput) -> Result<()> {
        require(
            !self.bond_notes.contains_key(&input.note_id),
            "bond note already exists",
        )?;
        require(
            !self
                .consumed_nullifiers
                .contains(&input.nullifier_commitment),
            "nullifier already consumed",
        )?;
        let note = LiquidityRebateBondNote::from_input(input, &self.config, self.current_epoch)?;
        self.bond_notes.insert(note.note_id.clone(), note);
        Ok(())
    }

    pub fn record_curve_snapshot(&mut self, input: CurveSnapshotInput) -> Result<()> {
        require(
            self.amm_pools.contains_key(&input.pool_id),
            "pool not found for curve snapshot",
        )?;
        require(
            !self.curve_snapshots.contains_key(&input.snapshot_id),
            "curve snapshot already exists",
        )?;
        let snapshot = ConfidentialCurveSnapshot::from_input(input, &self.config)?;
        self.curve_snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot);
        Ok(())
    }

    pub fn add_coupon_attestation(&mut self, attestation: PqCouponAttestation) -> Result<()> {
        require(
            self.amm_pools.contains_key(&attestation.pool_id),
            "pool not found for coupon attestation",
        )?;
        attestation.validate(&self.config, self.current_epoch)?;
        self.pq_coupon_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn settle_coupon(
        &mut self,
        input: CouponSettlementInput,
        attestation_id: String,
    ) -> Result<()> {
        let note = self
            .bond_notes
            .get(&input.note_id)
            .ok_or_else(|| "bond note not found for coupon".to_string())?
            .clone();
        let attestation = self
            .pq_coupon_attestations
            .get(&attestation_id)
            .ok_or_else(|| "pq coupon attestation not found".to_string())?;
        require(
            attestation.pool_id == input.pool_id,
            "attestation pool mismatch",
        )?;
        require(
            attestation.coupon_rate_bps == input.coupon_rate_bps,
            "coupon rate mismatch",
        )?;
        let coupon = PqSignedSettlementCoupon::from_input(input, attestation_id)?;
        let accrual = PrivateRebateAccrual::from_note(&note, &coupon, &self.config);
        self.settlement_coupons
            .insert(coupon.coupon_id.clone(), coupon);
        self.rebate_accruals
            .insert(accrual.accrual_id.clone(), accrual);
        Ok(())
    }

    pub fn net_coupons(&mut self, input: NettingInput) -> Result<()> {
        require(
            self.amm_pools.contains_key(&input.pool_id),
            "pool not found for netting",
        )?;
        require(
            input.gross_rebate_coupon_units >= input.net_quote_units,
            "net quote exceeds gross coupon",
        )?;
        let accrual_root = self.roots().rebate_accrual_root;
        let batch = LowFeeNettingBatch::from_input(input, accrual_root, &self.config);
        self.netting_batches.insert(batch.batch_id.clone(), batch);
        Ok(())
    }

    pub fn counters(&self) -> Counters {
        Counters {
            bond_notes: self.bond_notes.len() as u64,
            amm_pools: self.amm_pools.len() as u64,
            curve_snapshots: self.curve_snapshots.len() as u64,
            pq_coupon_attestations: self.pq_coupon_attestations.len() as u64,
            settlement_coupons: self.settlement_coupons.len() as u64,
            rebate_accruals: self.rebate_accruals.len() as u64,
            netting_batches: self.netting_batches.len() as u64,
            settlement_receipts: self.settlement_receipts.len() as u64,
            privacy_redactions: self.privacy_redactions.len() as u64,
            consumed_nullifiers: self.consumed_nullifiers.len() as u64,
            total_bond_notional_units: self
                .bond_notes
                .values()
                .map(|note| note.bond_notional_units)
                .sum(),
            total_sealed_liquidity_units: self
                .bond_notes
                .values()
                .map(|note| note.sealed_liquidity_units)
                .sum(),
            total_rebate_coupon_units: self
                .settlement_coupons
                .values()
                .map(|coupon| coupon.rebate_coupon_units)
                .sum(),
            total_netted_quote_units: self
                .netting_batches
                .values()
                .map(|batch| batch.net_quote_units)
                .sum(),
            total_low_fee_units: self
                .netting_batches
                .values()
                .map(|batch| batch.low_fee_units)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        let counters = self.counters();
        let mut roots = Roots {
            config_root: record_root("config", &self.config.public_record()),
            bond_note_root: merkle_root_for_records(
                "bond-notes",
                self.bond_notes
                    .values()
                    .map(LiquidityRebateBondNote::public_record),
            ),
            amm_pool_root: merkle_root_for_records(
                "amm-pools",
                self.amm_pools
                    .values()
                    .map(LiquidityRebateBondAmmPool::public_record),
            ),
            curve_snapshot_root: merkle_root_for_records(
                "curve-snapshots",
                self.curve_snapshots
                    .values()
                    .map(ConfidentialCurveSnapshot::public_record),
            ),
            pq_coupon_attestation_root: merkle_root_for_records(
                "pq-coupon-attestations",
                self.pq_coupon_attestations
                    .values()
                    .map(PqCouponAttestation::public_record),
            ),
            settlement_coupon_root: merkle_root_for_records(
                "settlement-coupons",
                self.settlement_coupons
                    .values()
                    .map(PqSignedSettlementCoupon::public_record),
            ),
            rebate_accrual_root: merkle_root_for_records(
                "rebate-accruals",
                self.rebate_accruals
                    .values()
                    .map(PrivateRebateAccrual::public_record),
            ),
            netting_batch_root: merkle_root_for_records(
                "netting-batches",
                self.netting_batches
                    .values()
                    .map(LowFeeNettingBatch::public_record),
            ),
            settlement_receipt_root: merkle_root_for_records(
                "settlement-receipts",
                self.settlement_receipts
                    .values()
                    .map(SettlementReceipt::public_record),
            ),
            privacy_redaction_root: merkle_root_for_records(
                "privacy-redactions",
                self.privacy_redactions
                    .values()
                    .map(PrivacyRedaction::public_record),
            ),
            nullifier_root: merkle_root_for_strings("nullifiers", &self.consumed_nullifiers),
            counters_root: record_root("counters", &counters.public_record()),
            state_root: String::new(),
        };
        roots.state_root = domain_hash(
            "liquidity-rebate-bond-state-root",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&roots.config_root),
                HashPart::Str(&roots.bond_note_root),
                HashPart::Str(&roots.amm_pool_root),
                HashPart::Str(&roots.curve_snapshot_root),
                HashPart::Str(&roots.pq_coupon_attestation_root),
                HashPart::Str(&roots.settlement_coupon_root),
                HashPart::Str(&roots.rebate_accrual_root),
                HashPart::Str(&roots.netting_batch_root),
                HashPart::Str(&roots.settlement_receipt_root),
                HashPart::Str(&roots.privacy_redaction_root),
                HashPart::Str(&roots.nullifier_root),
                HashPart::Str(&roots.counters_root),
            ],
            32,
        );
        roots
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "current_l2_height": self.current_l2_height,
            "current_epoch": self.current_epoch,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "records": {
                "amm_pools": records(self.amm_pools.values().map(LiquidityRebateBondAmmPool::public_record)),
                "bond_notes": records(self.bond_notes.values().map(LiquidityRebateBondNote::public_record)),
                "curve_snapshots": records(self.curve_snapshots.values().map(ConfidentialCurveSnapshot::public_record)),
                "pq_coupon_attestations": records(self.pq_coupon_attestations.values().map(PqCouponAttestation::public_record)),
                "settlement_coupons": records(self.settlement_coupons.values().map(PqSignedSettlementCoupon::public_record)),
                "rebate_accruals": records(self.rebate_accruals.values().map(PrivateRebateAccrual::public_record)),
                "netting_batches": records(self.netting_batches.values().map(LowFeeNettingBatch::public_record)),
                "settlement_receipts": records(self.settlement_receipts.values().map(SettlementReceipt::public_record)),
                "privacy_redactions": records(self.privacy_redactions.values().map(PrivacyRedaction::public_record)),
            }
        })
    }

    pub fn public_record_roots_only(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "current_l2_height": self.current_l2_height,
            "current_epoch": self.current_epoch,
            "config_root": roots.config_root,
            "counters": self.counters().public_record(),
            "roots": roots.without_state_root(),
            "state_root": roots.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
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

pub fn state_root_from_record(record: &Value) -> String {
    record_root("state-root-from-record", record)
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn bps(amount: u128, rate_bps: u64) -> u128 {
    amount.saturating_mul(rate_bps as u128) / MAX_BPS as u128
}

fn records<I>(values: I) -> Vec<Value>
where
    I: IntoIterator<Item = Value>,
{
    values.into_iter().collect()
}

fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

fn record_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&canonical_json(value)),
        ],
        32,
    )
}

fn merkle_root_for_records<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves: Vec<String> = records
        .into_iter()
        .map(|record| record_root(domain, &record))
        .collect();
    merkle_root(
        &format!("{PROTOCOL_VERSION}:{domain}"),
        &leaves.into_iter().map(Value::String).collect::<Vec<_>>(),
    )
}

fn merkle_root_for_strings(domain: &str, records: &BTreeSet<String>) -> String {
    merkle_root(
        &format!("{PROTOCOL_VERSION}:{domain}"),
        &records
            .iter()
            .cloned()
            .map(Value::String)
            .collect::<Vec<_>>(),
    )
}

fn seeded_root(domain: &str, sequence: u64) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn redacted_label(value: &str) -> String {
    if value.is_empty() {
        "redacted:empty".to_string()
    } else {
        domain_hash(
            "redacted-liquidity-rebate-bond-label",
            &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(value)],
            32,
        )
    }
}
