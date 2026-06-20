use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedMinerFeeRevenueStreamAmmRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-miner-fee-revenue-stream-amm-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_SCHEMA_VERSION:
    u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_HASH_SUITE:
    &str = "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_DEVNET_HEIGHT:
    u64 = 12_480;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_MAX_BPS: u64 =
    10_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_DEFAULT_EPOCH_BLOCKS:
    u64 = 720;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_DEFAULT_MATURITY_BLOCKS:
    u64 = 2_160;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_DEFAULT_SETTLEMENT_GRACE_BLOCKS:
    u64 = 144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_DEFAULT_HAIRCUT_BPS:
    u64 = 450;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_DEFAULT_LOW_FEE_REBATE_BPS:
    u64 = 90;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_DEFAULT_MIN_PRIVACY_SET:
    u64 = 48;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    Issued,
    Locked,
    Matured,
    Settled,
    Defaulted,
    Redeemed,
    Voided,
}

impl NoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Locked => "locked",
            Self::Matured => "matured",
            Self::Settled => "settled",
            Self::Defaulted => "defaulted",
            Self::Redeemed => "redeemed",
            Self::Voided => "voided",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Issued | Self::Locked | Self::Matured)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Open,
    Sealed,
    Maturing,
    Settling,
    Settled,
    Defaulted,
    Paused,
}

impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Maturing => "maturing",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Defaulted => "defaulted",
            Self::Paused => "paused",
        }
    }

    pub fn accepts_liquidity(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Accruing,
    Attested,
    Sealed,
    Matured,
    Settled,
    Defaulted,
    Haircut,
}

impl BucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accruing => "accruing",
            Self::Attested => "attested",
            Self::Sealed => "sealed",
            Self::Matured => "matured",
            Self::Settled => "settled",
            Self::Defaulted => "defaulted",
            Self::Haircut => "haircut",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Accruing | Self::Attested)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    Proving,
    Posted,
    Finalized,
    Disputed,
    Defaulted,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Proving => "proving",
            Self::Posted => "posted",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Defaulted => "defaulted",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub settlement_asset_id: String,
    pub fee_revenue_asset_id: String,
    pub epoch_blocks: u64,
    pub maturity_blocks: u64,
    pub settlement_grace_blocks: u64,
    pub default_haircut_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub oracle_quorum: u64,
    pub enable_demo_fixtures: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            settlement_asset_id: "dxmr-devnet".to_string(),
            fee_revenue_asset_id: "tokenized-miner-fee-revenue-devnet".to_string(),
            epoch_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_DEFAULT_EPOCH_BLOCKS,
            maturity_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_DEFAULT_MATURITY_BLOCKS,
            settlement_grace_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_DEFAULT_SETTLEMENT_GRACE_BLOCKS,
            default_haircut_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_DEFAULT_HAIRCUT_BPS,
            low_fee_rebate_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_DEFAULT_LOW_FEE_REBATE_BPS,
            min_privacy_set:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_quorum: 3,
            enable_demo_fixtures: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_tokenized_miner_fee_revenue_stream_amm_config",
            "protocol_version": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_PROTOCOL_VERSION,
            "chain_id": self.chain_id,
            "settlement_asset_id": self.settlement_asset_id,
            "fee_revenue_asset_id": self.fee_revenue_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "maturity_blocks": self.maturity_blocks,
            "settlement_grace_blocks": self.settlement_grace_blocks,
            "default_haircut_bps": self.default_haircut_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "oracle_quorum": self.oracle_quorum,
            "enable_demo_fixtures": self.enable_demo_fixtures
        })
    }

    pub fn root(&self) -> String {
        payload_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("Config.chain_id", &self.chain_id)?;
        ensure_non_empty("Config.settlement_asset_id", &self.settlement_asset_id)?;
        ensure_non_empty("Config.fee_revenue_asset_id", &self.fee_revenue_asset_id)?;
        ensure_positive("Config.epoch_blocks", self.epoch_blocks)?;
        ensure_positive("Config.maturity_blocks", self.maturity_blocks)?;
        ensure_bps("Config.default_haircut_bps", self.default_haircut_bps)?;
        ensure_bps("Config.low_fee_rebate_bps", self.low_fee_rebate_bps)?;
        ensure_positive("Config.min_privacy_set", self.min_privacy_set)?;
        ensure_positive("Config.oracle_quorum", self.oracle_quorum)?;
        if self.min_pq_security_bits < 128 {
            return Err("Config.min_pq_security_bits below 128".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevenueStreamNote {
    pub note_id: String,
    pub owner_view_tag: String,
    pub epoch_id: String,
    pub pool_id: String,
    pub commitment: String,
    pub nullifier_hash: String,
    pub encrypted_terms_hash: String,
    pub face_value_commitment: String,
    pub maturity_height: u64,
    pub status: NoteStatus,
}

impl RevenueStreamNote {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "tokenized_miner_fee_revenue_stream_note",
            "note_id": self.note_id,
            "owner_view_tag": self.owner_view_tag,
            "epoch_id": self.epoch_id,
            "pool_id": self.pool_id,
            "commitment": self.commitment,
            "nullifier_hash": self.nullifier_hash,
            "encrypted_terms_hash": self.encrypted_terms_hash,
            "face_value_commitment": self.face_value_commitment,
            "maturity_height": self.maturity_height,
            "status": self.status.as_str()
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("RevenueStreamNote.note_id", &self.note_id)?;
        ensure_non_empty("RevenueStreamNote.epoch_id", &self.epoch_id)?;
        ensure_non_empty("RevenueStreamNote.pool_id", &self.pool_id)?;
        ensure_non_empty("RevenueStreamNote.commitment", &self.commitment)?;
        ensure_non_empty("RevenueStreamNote.nullifier_hash", &self.nullifier_hash)?;
        ensure_positive("RevenueStreamNote.maturity_height", self.maturity_height)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmmPool {
    pub pool_id: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub invariant_commitment: String,
    pub sealed_liquidity_root: String,
    pub lp_supply_commitment: String,
    pub fee_bps: u64,
    pub status: PoolStatus,
}

impl AmmPool {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_revenue_stream_amm_pool",
            "pool_id": self.pool_id,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "invariant_commitment": self.invariant_commitment,
            "sealed_liquidity_root": self.sealed_liquidity_root,
            "lp_supply_commitment": self.lp_supply_commitment,
            "fee_bps": self.fee_bps,
            "status": self.status.as_str()
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("AmmPool.pool_id", &self.pool_id)?;
        ensure_non_empty("AmmPool.base_asset_id", &self.base_asset_id)?;
        ensure_non_empty("AmmPool.quote_asset_id", &self.quote_asset_id)?;
        ensure_non_empty("AmmPool.invariant_commitment", &self.invariant_commitment)?;
        ensure_non_empty("AmmPool.sealed_liquidity_root", &self.sealed_liquidity_root)?;
        ensure_bps("AmmPool.fee_bps", self.fee_bps)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleAttestation {
    pub attestation_id: String,
    pub oracle_set_id: String,
    pub epoch_id: String,
    pub revenue_bucket_id: String,
    pub observed_fee_commitment: String,
    pub price_root: String,
    pub pq_signature_root: String,
    pub attested_at_height: u64,
}

impl OracleAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_fee_revenue_attestation",
            "attestation_id": self.attestation_id,
            "oracle_set_id": self.oracle_set_id,
            "epoch_id": self.epoch_id,
            "revenue_bucket_id": self.revenue_bucket_id,
            "observed_fee_commitment": self.observed_fee_commitment,
            "price_root": self.price_root,
            "pq_signature_root": self.pq_signature_root,
            "attested_at_height": self.attested_at_height
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("OracleAttestation.attestation_id", &self.attestation_id)?;
        ensure_non_empty("OracleAttestation.epoch_id", &self.epoch_id)?;
        ensure_non_empty(
            "OracleAttestation.revenue_bucket_id",
            &self.revenue_bucket_id,
        )?;
        ensure_non_empty(
            "OracleAttestation.observed_fee_commitment",
            &self.observed_fee_commitment,
        )?;
        ensure_positive(
            "OracleAttestation.attested_at_height",
            self.attested_at_height,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRevenueBucket {
    pub bucket_id: String,
    pub epoch_id: String,
    pub block_range_start: u64,
    pub block_range_end: u64,
    pub gross_revenue_commitment: String,
    pub low_fee_rebate_commitment: String,
    pub haircut_bps: u64,
    pub status: BucketStatus,
}

impl EpochRevenueBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "epoch_miner_fee_revenue_bucket",
            "bucket_id": self.bucket_id,
            "epoch_id": self.epoch_id,
            "block_range_start": self.block_range_start,
            "block_range_end": self.block_range_end,
            "gross_revenue_commitment": self.gross_revenue_commitment,
            "low_fee_rebate_commitment": self.low_fee_rebate_commitment,
            "haircut_bps": self.haircut_bps,
            "status": self.status.as_str()
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("EpochRevenueBucket.bucket_id", &self.bucket_id)?;
        ensure_non_empty("EpochRevenueBucket.epoch_id", &self.epoch_id)?;
        ensure_non_empty(
            "EpochRevenueBucket.gross_revenue_commitment",
            &self.gross_revenue_commitment,
        )?;
        ensure_bps("EpochRevenueBucket.haircut_bps", self.haircut_bps)?;
        if self.block_range_end < self.block_range_start {
            return Err(format!(
                "EpochRevenueBucket {} has inverted block range",
                self.bucket_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedLiquidityPosition {
    pub position_id: String,
    pub pool_id: String,
    pub owner_view_tag: String,
    pub liquidity_commitment: String,
    pub range_commitment: String,
    pub lock_height: u64,
    pub unlock_height: u64,
}

impl SealedLiquidityPosition {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_liquidity_position",
            "position_id": self.position_id,
            "pool_id": self.pool_id,
            "owner_view_tag": self.owner_view_tag,
            "liquidity_commitment": self.liquidity_commitment,
            "range_commitment": self.range_commitment,
            "lock_height": self.lock_height,
            "unlock_height": self.unlock_height
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("SealedLiquidityPosition.position_id", &self.position_id)?;
        ensure_non_empty("SealedLiquidityPosition.pool_id", &self.pool_id)?;
        ensure_non_empty(
            "SealedLiquidityPosition.liquidity_commitment",
            &self.liquidity_commitment,
        )?;
        if self.unlock_height <= self.lock_height {
            return Err(format!(
                "SealedLiquidityPosition {} unlocks before lock height",
                self.position_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaturitySettlement {
    pub settlement_id: String,
    pub note_id: String,
    pub bucket_id: String,
    pub maturity_height: u64,
    pub settlement_height: u64,
    pub payout_commitment: String,
    pub default_haircut_bps: u64,
    pub status: SettlementStatus,
}

impl MaturitySettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "maturity_settlement",
            "settlement_id": self.settlement_id,
            "note_id": self.note_id,
            "bucket_id": self.bucket_id,
            "maturity_height": self.maturity_height,
            "settlement_height": self.settlement_height,
            "payout_commitment": self.payout_commitment,
            "default_haircut_bps": self.default_haircut_bps,
            "status": self.status.as_str()
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("MaturitySettlement.settlement_id", &self.settlement_id)?;
        ensure_non_empty("MaturitySettlement.note_id", &self.note_id)?;
        ensure_non_empty("MaturitySettlement.bucket_id", &self.bucket_id)?;
        ensure_non_empty(
            "MaturitySettlement.payout_commitment",
            &self.payout_commitment,
        )?;
        ensure_bps(
            "MaturitySettlement.default_haircut_bps",
            self.default_haircut_bps,
        )?;
        if self.settlement_height < self.maturity_height {
            return Err(format!(
                "MaturitySettlement {} settles before maturity",
                self.settlement_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub bucket_id: String,
    pub beneficiary_view_tag: String,
    pub rebate_commitment: String,
    pub rebate_bps: u64,
    pub expires_at_height: u64,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_rebate",
            "rebate_id": self.rebate_id,
            "bucket_id": self.bucket_id,
            "beneficiary_view_tag": self.beneficiary_view_tag,
            "rebate_commitment": self.rebate_commitment,
            "rebate_bps": self.rebate_bps,
            "expires_at_height": self.expires_at_height
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("LowFeeRebate.rebate_id", &self.rebate_id)?;
        ensure_non_empty("LowFeeRebate.bucket_id", &self.bucket_id)?;
        ensure_non_empty("LowFeeRebate.rebate_commitment", &self.rebate_commitment)?;
        ensure_bps("LowFeeRebate.rebate_bps", self.rebate_bps)?;
        ensure_positive("LowFeeRebate.expires_at_height", self.expires_at_height)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyRedaction {
    pub redaction_id: String,
    pub target_kind: String,
    pub target_id: String,
    pub redacted_fields: Vec<String>,
    pub disclosure_root: String,
}

impl PrivacyRedaction {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "privacy_redaction",
            "redaction_id": self.redaction_id,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "redacted_fields": self.redacted_fields,
            "disclosure_root": self.disclosure_root
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("PrivacyRedaction.redaction_id", &self.redaction_id)?;
        ensure_non_empty("PrivacyRedaction.target_kind", &self.target_kind)?;
        ensure_non_empty("PrivacyRedaction.target_id", &self.target_id)?;
        ensure_non_empty("PrivacyRedaction.disclosure_root", &self.disclosure_root)?;
        if self.redacted_fields.is_empty() {
            return Err(format!(
                "PrivacyRedaction {} has no fields",
                self.redaction_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub note_root: String,
    pub amm_pool_root: String,
    pub oracle_attestation_root: String,
    pub epoch_revenue_bucket_root: String,
    pub sealed_liquidity_root: String,
    pub maturity_settlement_root: String,
    pub low_fee_rebate_root: String,
    pub privacy_redaction_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_tokenized_miner_fee_revenue_stream_amm_roots",
            "protocol_version": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "note_root": self.note_root,
            "amm_pool_root": self.amm_pool_root,
            "oracle_attestation_root": self.oracle_attestation_root,
            "epoch_revenue_bucket_root": self.epoch_revenue_bucket_root,
            "sealed_liquidity_root": self.sealed_liquidity_root,
            "maturity_settlement_root": self.maturity_settlement_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "privacy_redaction_root": self.privacy_redaction_root
        })
    }

    pub fn root(&self) -> String {
        payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub note_count: u64,
    pub live_note_count: u64,
    pub amm_pool_count: u64,
    pub open_pool_count: u64,
    pub oracle_attestation_count: u64,
    pub epoch_revenue_bucket_count: u64,
    pub open_bucket_count: u64,
    pub sealed_liquidity_count: u64,
    pub maturity_settlement_count: u64,
    pub low_fee_rebate_count: u64,
    pub privacy_redaction_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_tokenized_miner_fee_revenue_stream_amm_counters",
            "protocol_version": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_PROTOCOL_VERSION,
            "note_count": self.note_count,
            "live_note_count": self.live_note_count,
            "amm_pool_count": self.amm_pool_count,
            "open_pool_count": self.open_pool_count,
            "oracle_attestation_count": self.oracle_attestation_count,
            "epoch_revenue_bucket_count": self.epoch_revenue_bucket_count,
            "open_bucket_count": self.open_bucket_count,
            "sealed_liquidity_count": self.sealed_liquidity_count,
            "maturity_settlement_count": self.maturity_settlement_count,
            "low_fee_rebate_count": self.low_fee_rebate_count,
            "privacy_redaction_count": self.privacy_redaction_count
        })
    }

    pub fn root(&self) -> String {
        payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub notes: BTreeMap<String, RevenueStreamNote>,
    pub amm_pools: BTreeMap<String, AmmPool>,
    pub oracle_attestations: BTreeMap<String, OracleAttestation>,
    pub epoch_revenue_buckets: BTreeMap<String, EpochRevenueBucket>,
    pub sealed_liquidity: BTreeMap<String, SealedLiquidityPosition>,
    pub maturity_settlements: BTreeMap<String, MaturitySettlement>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub privacy_redactions: BTreeMap<String, PrivacyRedaction>,
}

impl State {
    pub fn new(height: u64, config: Config) -> Self {
        Self {
            height,
            config,
            notes: BTreeMap::new(),
            amm_pools: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            epoch_revenue_buckets: BTreeMap::new(),
            sealed_liquidity: BTreeMap::new(),
            maturity_settlements: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_DEVNET_HEIGHT,
            Config::devnet(),
        );
        state.seed_devnet_records()?;
        state.validate()?;
        Ok(state)
    }

    pub fn demo() -> Result<Self> {
        let mut state = Self::devnet()?;
        state.height += 36;
        state.seed_demo_records()?;
        state.validate()?;
        Ok(state)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            note_root: map_root("NOTE", &self.notes, RevenueStreamNote::public_record),
            amm_pool_root: map_root("AMM-POOL", &self.amm_pools, AmmPool::public_record),
            oracle_attestation_root: map_root(
                "ORACLE-ATTESTATION",
                &self.oracle_attestations,
                OracleAttestation::public_record,
            ),
            epoch_revenue_bucket_root: map_root(
                "EPOCH-REVENUE-BUCKET",
                &self.epoch_revenue_buckets,
                EpochRevenueBucket::public_record,
            ),
            sealed_liquidity_root: map_root(
                "SEALED-LIQUIDITY",
                &self.sealed_liquidity,
                SealedLiquidityPosition::public_record,
            ),
            maturity_settlement_root: map_root(
                "MATURITY-SETTLEMENT",
                &self.maturity_settlements,
                MaturitySettlement::public_record,
            ),
            low_fee_rebate_root: map_root(
                "LOW-FEE-REBATE",
                &self.low_fee_rebates,
                LowFeeRebate::public_record,
            ),
            privacy_redaction_root: map_root(
                "PRIVACY-REDACTION",
                &self.privacy_redactions,
                PrivacyRedaction::public_record,
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            note_count: self.notes.len() as u64,
            live_note_count: self
                .notes
                .values()
                .filter(|note| note.status.live())
                .count() as u64,
            amm_pool_count: self.amm_pools.len() as u64,
            open_pool_count: self
                .amm_pools
                .values()
                .filter(|pool| pool.status.accepts_liquidity())
                .count() as u64,
            oracle_attestation_count: self.oracle_attestations.len() as u64,
            epoch_revenue_bucket_count: self.epoch_revenue_buckets.len() as u64,
            open_bucket_count: self
                .epoch_revenue_buckets
                .values()
                .filter(|bucket| bucket.status.open())
                .count() as u64,
            sealed_liquidity_count: self.sealed_liquidity.len() as u64,
            maturity_settlement_count: self.maturity_settlements.len() as u64,
            low_fee_rebate_count: self.low_fee_rebates.len() as u64,
            privacy_redaction_count: self.privacy_redactions.len() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        let root = root_from_record(&record);
        if let Value::Object(fields) = &mut record {
            fields.insert("state_root".to_string(), Value::String(root));
        }
        record
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record_without_state_root())
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        validate_map("notes", &self.notes, RevenueStreamNote::validate)?;
        validate_map("amm_pools", &self.amm_pools, AmmPool::validate)?;
        validate_map(
            "oracle_attestations",
            &self.oracle_attestations,
            OracleAttestation::validate,
        )?;
        validate_map(
            "epoch_revenue_buckets",
            &self.epoch_revenue_buckets,
            EpochRevenueBucket::validate,
        )?;
        validate_map(
            "sealed_liquidity",
            &self.sealed_liquidity,
            SealedLiquidityPosition::validate,
        )?;
        validate_map(
            "maturity_settlements",
            &self.maturity_settlements,
            MaturitySettlement::validate,
        )?;
        validate_map(
            "low_fee_rebates",
            &self.low_fee_rebates,
            LowFeeRebate::validate,
        )?;
        validate_map(
            "privacy_redactions",
            &self.privacy_redactions,
            PrivacyRedaction::validate,
        )?;
        self.validate_references()
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_l2_pq_confidential_tokenized_miner_fee_revenue_stream_amm_state",
            "protocol_version": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_HASH_SUITE,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "notes": values_record(&self.notes, RevenueStreamNote::public_record),
            "amm_pools": values_record(&self.amm_pools, AmmPool::public_record),
            "oracle_attestations": values_record(&self.oracle_attestations, OracleAttestation::public_record),
            "epoch_revenue_buckets": values_record(&self.epoch_revenue_buckets, EpochRevenueBucket::public_record),
            "sealed_liquidity": values_record(&self.sealed_liquidity, SealedLiquidityPosition::public_record),
            "maturity_settlements": values_record(&self.maturity_settlements, MaturitySettlement::public_record),
            "low_fee_rebates": values_record(&self.low_fee_rebates, LowFeeRebate::public_record),
            "privacy_redactions": values_record(&self.privacy_redactions, PrivacyRedaction::public_record)
        })
    }

    fn validate_references(&self) -> Result<()> {
        for (note_id, note) in &self.notes {
            ensure_key("note.pool_id", &self.amm_pools, &note.pool_id, note_id)?;
            ensure_key(
                "note.epoch_id",
                &self.epoch_revenue_buckets,
                &note.epoch_id,
                note_id,
            )?;
        }
        for (position_id, position) in &self.sealed_liquidity {
            ensure_key(
                "sealed_liquidity.pool_id",
                &self.amm_pools,
                &position.pool_id,
                position_id,
            )?;
        }
        for (attestation_id, attestation) in &self.oracle_attestations {
            ensure_key(
                "oracle_attestation.revenue_bucket_id",
                &self.epoch_revenue_buckets,
                &attestation.revenue_bucket_id,
                attestation_id,
            )?;
        }
        for (settlement_id, settlement) in &self.maturity_settlements {
            ensure_key(
                "maturity_settlement.note_id",
                &self.notes,
                &settlement.note_id,
                settlement_id,
            )?;
            ensure_key(
                "maturity_settlement.bucket_id",
                &self.epoch_revenue_buckets,
                &settlement.bucket_id,
                settlement_id,
            )?;
        }
        for (rebate_id, rebate) in &self.low_fee_rebates {
            ensure_key(
                "low_fee_rebate.bucket_id",
                &self.epoch_revenue_buckets,
                &rebate.bucket_id,
                rebate_id,
            )?;
        }
        Ok(())
    }

    fn seed_devnet_records(&mut self) -> Result<()> {
        let pool_id = "amm:miner-fee-revenue:dxmr:devnet".to_string();
        let bucket_id = "epoch:fee-revenue:12480".to_string();
        let note_id = "note:miner-fee-stream:devnet:0001".to_string();

        self.amm_pools.insert(
            pool_id.clone(),
            AmmPool {
                pool_id: pool_id.clone(),
                base_asset_id: self.config.fee_revenue_asset_id.clone(),
                quote_asset_id: self.config.settlement_asset_id.clone(),
                invariant_commitment: fixture_root("pool-invariant", "devnet"),
                sealed_liquidity_root: fixture_root("sealed-liquidity", "devnet"),
                lp_supply_commitment: fixture_root("lp-supply", "devnet"),
                fee_bps: 18,
                status: PoolStatus::Open,
            },
        );
        self.epoch_revenue_buckets.insert(
            bucket_id.clone(),
            EpochRevenueBucket {
                bucket_id: bucket_id.clone(),
                epoch_id: bucket_id.clone(),
                block_range_start: 12_240,
                block_range_end: 12_959,
                gross_revenue_commitment: fixture_root("gross-revenue", "devnet"),
                low_fee_rebate_commitment: fixture_root("low-fee-rebate", "devnet"),
                haircut_bps: self.config.default_haircut_bps,
                status: BucketStatus::Attested,
            },
        );
        self.notes.insert(
            note_id.clone(),
            RevenueStreamNote {
                note_id: note_id.clone(),
                owner_view_tag: "view:devnet:alpha".to_string(),
                epoch_id: bucket_id.clone(),
                pool_id: pool_id.clone(),
                commitment: fixture_root("note-commitment", "devnet"),
                nullifier_hash: fixture_root("note-nullifier", "devnet"),
                encrypted_terms_hash: fixture_root("encrypted-terms", "devnet"),
                face_value_commitment: fixture_root("face-value", "devnet"),
                maturity_height: self.height + self.config.maturity_blocks,
                status: NoteStatus::Issued,
            },
        );
        self.oracle_attestations.insert(
            "attestation:oracle-set-a:12480".to_string(),
            OracleAttestation {
                attestation_id: "attestation:oracle-set-a:12480".to_string(),
                oracle_set_id: "oracle-set:devnet:a".to_string(),
                epoch_id: bucket_id.clone(),
                revenue_bucket_id: bucket_id.clone(),
                observed_fee_commitment: fixture_root("observed-fees", "devnet"),
                price_root: fixture_root("oracle-price", "devnet"),
                pq_signature_root: fixture_root("ml-dsa-quorum", "devnet"),
                attested_at_height: self.height,
            },
        );
        self.sealed_liquidity.insert(
            "lp:sealed:devnet:0001".to_string(),
            SealedLiquidityPosition {
                position_id: "lp:sealed:devnet:0001".to_string(),
                pool_id,
                owner_view_tag: "view:lp:alpha".to_string(),
                liquidity_commitment: fixture_root("liquidity", "devnet"),
                range_commitment: fixture_root("range", "devnet"),
                lock_height: self.height,
                unlock_height: self.height + self.config.maturity_blocks,
            },
        );
        self.low_fee_rebates.insert(
            "rebate:devnet:0001".to_string(),
            LowFeeRebate {
                rebate_id: "rebate:devnet:0001".to_string(),
                bucket_id: bucket_id.clone(),
                beneficiary_view_tag: "view:rebate:alpha".to_string(),
                rebate_commitment: fixture_root("rebate-commitment", "devnet"),
                rebate_bps: self.config.low_fee_rebate_bps,
                expires_at_height: self.height + self.config.maturity_blocks,
            },
        );
        self.privacy_redactions.insert(
            "redaction:note:0001".to_string(),
            PrivacyRedaction {
                redaction_id: "redaction:note:0001".to_string(),
                target_kind: "tokenized_miner_fee_revenue_stream_note".to_string(),
                target_id: note_id,
                redacted_fields: vec![
                    "owner_spend_key".to_string(),
                    "face_value".to_string(),
                    "settlement_address".to_string(),
                ],
                disclosure_root: fixture_root("redaction-disclosure", "devnet"),
            },
        );
        Ok(())
    }

    fn seed_demo_records(&mut self) -> Result<()> {
        self.maturity_settlements.insert(
            "settlement:devnet:0001".to_string(),
            MaturitySettlement {
                settlement_id: "settlement:devnet:0001".to_string(),
                note_id: "note:miner-fee-stream:devnet:0001".to_string(),
                bucket_id: "epoch:fee-revenue:12480".to_string(),
                maturity_height: self.height,
                settlement_height: self.height + self.config.settlement_grace_blocks,
                payout_commitment: fixture_root("payout", "demo"),
                default_haircut_bps: self.config.default_haircut_bps,
                status: SettlementStatus::Posted,
            },
        );
        Ok(())
    }
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

pub fn demo() -> Result<State> {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn payload_root(label: &str, record: &Value) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-MINER-FEE-REVENUE-STREAM-AMM-RUNTIME-{label}"
        ),
        &[HashPart::Json(record)],
        32,
    )
}

fn root_from_record(record: &Value) -> String {
    payload_root("STATE", record)
}

fn map_root<T, F>(label: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, item)| json!({ "key": key, "value": public_record(item) }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!(
            "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-MINER-FEE-REVENUE-STREAM-AMM-RUNTIME-{label}"
        ),
        &leaves,
    )
}

fn values_record<T, F>(map: &BTreeMap<String, T>, public_record: F) -> Value
where
    F: Fn(&T) -> Value,
{
    Value::Array(map.values().map(public_record).collect())
}

fn fixture_root(label: &str, scope: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKENIZED-MINER-FEE-REVENUE-STREAM-AMM-RUNTIME-FIXTURE",
        &[HashPart::Str(label), HashPart::Str(scope)],
        32,
    )
}

fn validate_map<T, F>(name: &str, map: &BTreeMap<String, T>, validate: F) -> Result<()>
where
    F: Fn(&T) -> Result<()>,
{
    for (key, value) in map {
        validate(value).map_err(|err| format!("{name}.{key}: {err}"))?;
    }
    Ok(())
}

fn ensure_key<T>(field: &str, map: &BTreeMap<String, T>, key: &str, owner_id: &str) -> Result<()> {
    if map.contains_key(key) {
        Ok(())
    } else {
        Err(format!("{field} {key} referenced by {owner_id} is missing"))
    }
}

fn ensure_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} is empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(field: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_MINER_FEE_REVENUE_STREAM_AMM_RUNTIME_MAX_BPS {
        Err(format!("{field} exceeds max bps"))
    } else {
        Ok(())
    }
}
