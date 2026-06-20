use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2LowFeePqConfidentialBlobFeeFuturesRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_FEE_FUTURES_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-blob-fee-futures-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BLOB_FEE_FUTURES_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 482_000;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_BLOB_FEE_ORACLE_ID: &str = "devnet-confidential-blob-fee-oracle";
pub const DEVNET_MARKET_ID: &str = "devnet-low-fee-pq-blob-fee-futures";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const BUCKET_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024-encrypted-confidential-blob-demand-bucket-root-v1";
pub const PQ_MARKET_ATTESTATION_SCHEME: &str =
    "ml-dsa-87-confidential-blob-fee-futures-market-attestation-root-v1";
pub const FUTURES_SETTLEMENT_SCHEME: &str =
    "roots-only-confidential-blob-fee-futures-settlement-window-root-v1";
pub const REBATE_ACCOUNTING_SCHEME: &str =
    "low-fee-confidential-blob-demand-rebate-accounting-root-v1";
pub const RISK_LIMIT_SCHEME: &str = "confidential-blob-fee-futures-risk-limit-root-v1";
pub const ORACLE_QUARANTINE_SCHEME: &str = "stale-blob-fee-oracle-quarantine-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "deterministic-redaction-budget-root-v1";
pub const REPLAY_DOMAIN: &str = "private-l2-low-fee-pq-confidential-blob-fee-futures-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_BUCKET_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_SETTLEMENT_WINDOW_BLOCKS: u64 = 48;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_ORACLE_STALE_AFTER_BLOCKS: u64 = 12;
pub const DEFAULT_ORACLE_QUARANTINE_BLOCKS: u64 = 72;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LOW_FEE_BPS: u64 = 4;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_400;
pub const DEFAULT_REBATE_BPS: u64 = 600;
pub const DEFAULT_INITIAL_MARGIN_BPS: u64 = 1_250;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 875;
pub const DEFAULT_MAX_LEVERAGE_BPS: u64 = 350;
pub const DEFAULT_MAX_MARKET_NOTIONAL_PICONERO: u128 = 25_000_000_000_000;
pub const DEFAULT_MAX_ACCOUNT_NOTIONAL_PICONERO: u128 = 1_250_000_000_000;
pub const DEFAULT_MAX_BUCKET_BLOB_GAS: u128 = 4_000_000;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 128;
pub const MAX_DEMAND_BUCKETS: usize = 1_048_576;
pub const MAX_SPONSOR_POOLS: usize = 262_144;
pub const MAX_ATTESTATIONS: usize = 1_048_576;
pub const MAX_SETTLEMENT_WINDOWS: usize = 262_144;
pub const MAX_REBATE_ACCOUNTS: usize = 1_048_576;
pub const MAX_RISK_LIMITS: usize = 1_048_576;
pub const MAX_ORACLE_QUARANTINES: usize = 262_144;
pub const MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const MAX_PUBLIC_RECORDS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DemandClass {
    RetailBatch,
    ExchangeBatch,
    DefiSettlement,
    BridgeExit,
    EmergencyWithdrawal,
}

impl DemandClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetailBatch => "retail_batch",
            Self::ExchangeBatch => "exchange_batch",
            Self::DefiSettlement => "defi_settlement",
            Self::BridgeExit => "bridge_exit",
            Self::EmergencyWithdrawal => "emergency_withdrawal",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyWithdrawal => 10_000,
            Self::BridgeExit => 9_200,
            Self::DefiSettlement => 8_600,
            Self::ExchangeBatch => 7_800,
            Self::RetailBatch => 7_200,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Open,
    Attested,
    Sponsored,
    Windowed,
    Settled,
    Rebated,
    Rejected,
    Expired,
}

impl BucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Attested => "attested",
            Self::Sponsored => "sponsored",
            Self::Windowed => "windowed",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Attested | Self::Sponsored | Self::Windowed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPoolStatus {
    Funding,
    Active,
    Draining,
    Settling,
    Exhausted,
    Frozen,
}

impl SponsorPoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Funding => "funding",
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Settling => "settling",
            Self::Exhausted => "exhausted",
            Self::Frozen => "frozen",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Funding | Self::Active | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Quarantined,
    Revoked,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Quarantined => "quarantined",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuturesSide {
    LongBlobFee,
    ShortBlobFee,
    SponsorHedge,
    RebateHedge,
}

impl FuturesSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LongBlobFee => "long_blob_fee",
            Self::ShortBlobFee => "short_blob_fee",
            Self::SponsorHedge => "sponsor_hedge",
            Self::RebateHedge => "rebate_hedge",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Open,
    Pricing,
    Settling,
    Settled,
    Disputed,
    Quarantined,
    Expired,
}

impl WindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Pricing => "pricing",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Quarantined => "quarantined",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Pricing | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accruing,
    Claimable,
    Claimed,
    Settled,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accruing => "accruing",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskStatus {
    Healthy,
    AtLimit,
    ReduceOnly,
    MarginCall,
    Liquidating,
    Halted,
}

impl RiskStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::AtLimit => "at_limit",
            Self::ReduceOnly => "reduce_only",
            Self::MarginCall => "margin_call",
            Self::Liquidating => "liquidating",
            Self::Halted => "halted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    StaleOracle,
    PqSignatureMismatch,
    PriceBandBreach,
    PrivacySetTooSmall,
    RedactionBudgetExceeded,
    ManualHalt,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleOracle => "stale_oracle",
            Self::PqSignatureMismatch => "pq_signature_mismatch",
            Self::PriceBandBreach => "price_band_breach",
            Self::PrivacySetTooSmall => "privacy_set_too_small",
            Self::RedactionBudgetExceeded => "redaction_budget_exceeded",
            Self::ManualHalt => "manual_halt",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub market_id: String,
    pub oracle_id: String,
    pub hash_suite: String,
    pub bucket_encryption_scheme: String,
    pub pq_market_attestation_scheme: String,
    pub futures_settlement_scheme: String,
    pub rebate_accounting_scheme: String,
    pub risk_limit_scheme: String,
    pub oracle_quarantine_scheme: String,
    pub redaction_budget_scheme: String,
    pub replay_domain: String,
    pub bucket_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub settlement_window_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub oracle_stale_after_blocks: u64,
    pub oracle_quarantine_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub rebate_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub max_leverage_bps: u64,
    pub max_market_notional_piconero: u128,
    pub max_account_notional_piconero: u128,
    pub max_bucket_blob_gas: u128,
    pub default_redaction_budget_units: u64,
    pub max_demand_buckets: usize,
    pub max_sponsor_pools: usize,
    pub max_attestations: usize,
    pub max_settlement_windows: usize,
    pub max_rebate_accounts: usize,
    pub max_risk_limits: usize,
    pub max_oracle_quarantines: usize,
    pub max_redaction_budgets: usize,
    pub max_public_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            market_id: DEVNET_MARKET_ID.to_string(),
            oracle_id: DEVNET_BLOB_FEE_ORACLE_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            bucket_encryption_scheme: BUCKET_ENCRYPTION_SCHEME.to_string(),
            pq_market_attestation_scheme: PQ_MARKET_ATTESTATION_SCHEME.to_string(),
            futures_settlement_scheme: FUTURES_SETTLEMENT_SCHEME.to_string(),
            rebate_accounting_scheme: REBATE_ACCOUNTING_SCHEME.to_string(),
            risk_limit_scheme: RISK_LIMIT_SCHEME.to_string(),
            oracle_quarantine_scheme: ORACLE_QUARANTINE_SCHEME.to_string(),
            redaction_budget_scheme: REDACTION_BUDGET_SCHEME.to_string(),
            replay_domain: REPLAY_DOMAIN.to_string(),
            bucket_ttl_blocks: DEFAULT_BUCKET_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            settlement_window_blocks: DEFAULT_SETTLEMENT_WINDOW_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            oracle_stale_after_blocks: DEFAULT_ORACLE_STALE_AFTER_BLOCKS,
            oracle_quarantine_blocks: DEFAULT_ORACLE_QUARANTINE_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            initial_margin_bps: DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            max_leverage_bps: DEFAULT_MAX_LEVERAGE_BPS,
            max_market_notional_piconero: DEFAULT_MAX_MARKET_NOTIONAL_PICONERO,
            max_account_notional_piconero: DEFAULT_MAX_ACCOUNT_NOTIONAL_PICONERO,
            max_bucket_blob_gas: DEFAULT_MAX_BUCKET_BLOB_GAS,
            default_redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            max_demand_buckets: MAX_DEMAND_BUCKETS,
            max_sponsor_pools: MAX_SPONSOR_POOLS,
            max_attestations: MAX_ATTESTATIONS,
            max_settlement_windows: MAX_SETTLEMENT_WINDOWS,
            max_rebate_accounts: MAX_REBATE_ACCOUNTS,
            max_risk_limits: MAX_RISK_LIMITS,
            max_oracle_quarantines: MAX_ORACLE_QUARANTINES,
            max_redaction_budgets: MAX_REDACTION_BUDGETS,
            max_public_records: MAX_PUBLIC_RECORDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "market_id": self.market_id,
            "oracle_id": self.oracle_id,
            "hash_suite": self.hash_suite,
            "bucket_encryption_scheme": self.bucket_encryption_scheme,
            "pq_market_attestation_scheme": self.pq_market_attestation_scheme,
            "futures_settlement_scheme": self.futures_settlement_scheme,
            "rebate_accounting_scheme": self.rebate_accounting_scheme,
            "risk_limit_scheme": self.risk_limit_scheme,
            "oracle_quarantine_scheme": self.oracle_quarantine_scheme,
            "redaction_budget_scheme": self.redaction_budget_scheme,
            "replay_domain": self.replay_domain,
            "bucket_ttl_blocks": self.bucket_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "settlement_window_blocks": self.settlement_window_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "oracle_stale_after_blocks": self.oracle_stale_after_blocks,
            "oracle_quarantine_blocks": self.oracle_quarantine_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "low_fee_bps": self.low_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "rebate_bps": self.rebate_bps,
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "max_leverage_bps": self.max_leverage_bps,
            "max_market_notional_piconero": self.max_market_notional_piconero.to_string(),
            "max_account_notional_piconero": self.max_account_notional_piconero.to_string(),
            "max_bucket_blob_gas": self.max_bucket_blob_gas.to_string(),
            "default_redaction_budget_units": self.default_redaction_budget_units,
            "max_demand_buckets": self.max_demand_buckets,
            "max_sponsor_pools": self.max_sponsor_pools,
            "max_attestations": self.max_attestations,
            "max_settlement_windows": self.max_settlement_windows,
            "max_rebate_accounts": self.max_rebate_accounts,
            "max_risk_limits": self.max_risk_limits,
            "max_oracle_quarantines": self.max_oracle_quarantines,
            "max_redaction_budgets": self.max_redaction_budgets,
            "max_public_records": self.max_public_records,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub encrypted_blob_demand_buckets: u64,
    pub live_demand_buckets: u64,
    pub sponsored_demand_buckets: u64,
    pub settled_demand_buckets: u64,
    pub sponsor_pools: u64,
    pub active_sponsor_pools: u64,
    pub pq_market_attestations: u64,
    pub accepted_pq_market_attestations: u64,
    pub quarantined_attestations: u64,
    pub settlement_windows: u64,
    pub live_settlement_windows: u64,
    pub settled_settlement_windows: u64,
    pub rebate_accounts: u64,
    pub claimable_rebate_accounts: u64,
    pub settled_rebate_accounts: u64,
    pub risk_limits: u64,
    pub risk_limits_at_or_above_limit: u64,
    pub oracle_quarantines: u64,
    pub active_oracle_quarantines: u64,
    pub redaction_budgets: u64,
    pub redaction_budget_units_used: u64,
    pub encrypted_blob_gas_committed: u128,
    pub encrypted_blob_gas_settled: u128,
    pub sponsored_fee_piconero: u128,
    pub user_fee_piconero: u128,
    pub rebate_amount_piconero: u128,
    pub futures_notional_piconero: u128,
    pub futures_pnl_piconero: i128,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "encrypted_blob_demand_buckets": self.encrypted_blob_demand_buckets,
            "live_demand_buckets": self.live_demand_buckets,
            "sponsored_demand_buckets": self.sponsored_demand_buckets,
            "settled_demand_buckets": self.settled_demand_buckets,
            "sponsor_pools": self.sponsor_pools,
            "active_sponsor_pools": self.active_sponsor_pools,
            "pq_market_attestations": self.pq_market_attestations,
            "accepted_pq_market_attestations": self.accepted_pq_market_attestations,
            "quarantined_attestations": self.quarantined_attestations,
            "settlement_windows": self.settlement_windows,
            "live_settlement_windows": self.live_settlement_windows,
            "settled_settlement_windows": self.settled_settlement_windows,
            "rebate_accounts": self.rebate_accounts,
            "claimable_rebate_accounts": self.claimable_rebate_accounts,
            "settled_rebate_accounts": self.settled_rebate_accounts,
            "risk_limits": self.risk_limits,
            "risk_limits_at_or_above_limit": self.risk_limits_at_or_above_limit,
            "oracle_quarantines": self.oracle_quarantines,
            "active_oracle_quarantines": self.active_oracle_quarantines,
            "redaction_budgets": self.redaction_budgets,
            "redaction_budget_units_used": self.redaction_budget_units_used,
            "encrypted_blob_gas_committed": self.encrypted_blob_gas_committed.to_string(),
            "encrypted_blob_gas_settled": self.encrypted_blob_gas_settled.to_string(),
            "sponsored_fee_piconero": self.sponsored_fee_piconero.to_string(),
            "user_fee_piconero": self.user_fee_piconero.to_string(),
            "rebate_amount_piconero": self.rebate_amount_piconero.to_string(),
            "futures_notional_piconero": self.futures_notional_piconero.to_string(),
            "futures_pnl_piconero": self.futures_pnl_piconero.to_string(),
            "public_records": self.public_records,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBlobDemandBucket {
    pub bucket_id: String,
    pub account_commitment: String,
    pub demand_class: DemandClass,
    pub futures_side: FuturesSide,
    pub encrypted_blob_gas_commitment: String,
    pub encrypted_max_fee_commitment: String,
    pub bucket_ciphertext_root: String,
    pub nullifier_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub committed_blob_gas: u128,
    pub fee_budget_piconero: u128,
    pub user_fee_bps: u64,
    pub sponsor_pool_id: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: BucketStatus,
}

impl EncryptedBlobDemandBucket {
    pub fn new(
        account_commitment: &str,
        demand_class: DemandClass,
        futures_side: FuturesSide,
        committed_blob_gas: u128,
        fee_budget_piconero: u128,
        sponsor_pool_id: &str,
        config: &Config,
        height: u64,
    ) -> Self {
        let user_fee_bps = match demand_class {
            DemandClass::EmergencyWithdrawal => config.max_user_fee_bps,
            DemandClass::BridgeExit => config.max_user_fee_bps.saturating_mul(3) / 4,
            _ => config.low_fee_bps,
        };
        let body = json!({
            "account_commitment": account_commitment,
            "demand_class": demand_class.as_str(),
            "futures_side": futures_side.as_str(),
            "committed_blob_gas": committed_blob_gas.to_string(),
            "fee_budget_piconero": fee_budget_piconero.to_string(),
            "sponsor_pool_id": sponsor_pool_id,
            "height": height,
        });
        let bucket_id = id_from_record("DEMAND-BUCKET-ID", &body);
        Self {
            bucket_id: bucket_id.clone(),
            account_commitment: account_commitment.to_string(),
            demand_class,
            futures_side,
            encrypted_blob_gas_commitment: root_from_record("ENCRYPTED-BLOB-GAS-COMMITMENT", &body),
            encrypted_max_fee_commitment: root_from_record("ENCRYPTED-MAX-FEE-COMMITMENT", &body),
            bucket_ciphertext_root: root_from_record("BUCKET-CIPHERTEXT", &body),
            nullifier_root: root_from_record(
                "BUCKET-NULLIFIER",
                &json!({ "bucket_id": bucket_id }),
            ),
            privacy_set_size: config.min_privacy_set_size,
            pq_security_bits: config.target_pq_security_bits,
            committed_blob_gas,
            fee_budget_piconero,
            user_fee_bps,
            sponsor_pool_id: sponsor_pool_id.to_string(),
            submitted_at_height: height,
            expires_at_height: height.saturating_add(config.bucket_ttl_blocks),
            status: BucketStatus::Open,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "account_commitment": self.account_commitment,
            "demand_class": self.demand_class.as_str(),
            "futures_side": self.futures_side.as_str(),
            "encrypted_blob_gas_commitment": self.encrypted_blob_gas_commitment,
            "encrypted_max_fee_commitment": self.encrypted_max_fee_commitment,
            "bucket_ciphertext_root": self.bucket_ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "committed_blob_gas": self.committed_blob_gas.to_string(),
            "fee_budget_piconero": self.fee_budget_piconero.to_string(),
            "user_fee_bps": self.user_fee_bps,
            "sponsor_pool_id": self.sponsor_pool_id,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorPool {
    pub pool_id: String,
    pub sponsor_commitment: String,
    pub reserve_commitment_root: String,
    pub available_fee_piconero: u128,
    pub reserved_fee_piconero: u128,
    pub paid_fee_piconero: u128,
    pub rebate_liability_piconero: u128,
    pub cover_bps: u64,
    pub min_privacy_set_size: u64,
    pub opened_at_height: u64,
    pub status: SponsorPoolStatus,
}

impl SponsorPool {
    pub fn new(
        pool_label: &str,
        sponsor_commitment: &str,
        available_fee_piconero: u128,
        config: &Config,
        height: u64,
    ) -> Self {
        let body = json!({
            "pool_label": pool_label,
            "sponsor_commitment": sponsor_commitment,
            "available_fee_piconero": available_fee_piconero.to_string(),
            "height": height,
        });
        let pool_id = id_from_record("SPONSOR-POOL-ID", &body);
        Self {
            pool_id: pool_id.clone(),
            sponsor_commitment: sponsor_commitment.to_string(),
            reserve_commitment_root: root_from_record("SPONSOR-POOL-RESERVE", &body),
            available_fee_piconero,
            reserved_fee_piconero: 0,
            paid_fee_piconero: 0,
            rebate_liability_piconero: 0,
            cover_bps: config.sponsor_cover_bps,
            min_privacy_set_size: config.min_privacy_set_size,
            opened_at_height: height,
            status: SponsorPoolStatus::Active,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "sponsor_commitment": self.sponsor_commitment,
            "reserve_commitment_root": self.reserve_commitment_root,
            "available_fee_piconero": self.available_fee_piconero.to_string(),
            "reserved_fee_piconero": self.reserved_fee_piconero.to_string(),
            "paid_fee_piconero": self.paid_fee_piconero.to_string(),
            "rebate_liability_piconero": self.rebate_liability_piconero.to_string(),
            "cover_bps": self.cover_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqMarketAttestation {
    pub attestation_id: String,
    pub bucket_id: String,
    pub oracle_id: String,
    pub market_id: String,
    pub attester_commitment: String,
    pub blob_fee_price_commitment: String,
    pub price_band_root: String,
    pub signature_root: String,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: AttestationStatus,
}

impl PqMarketAttestation {
    pub fn new(bucket: &EncryptedBlobDemandBucket, config: &Config, height: u64) -> Self {
        let body = json!({
            "bucket_id": bucket.bucket_id,
            "oracle_id": config.oracle_id,
            "market_id": config.market_id,
            "height": height,
        });
        Self {
            attestation_id: id_from_record("PQ-MARKET-ATTESTATION-ID", &body),
            bucket_id: bucket.bucket_id.clone(),
            oracle_id: config.oracle_id.clone(),
            market_id: config.market_id.clone(),
            attester_commitment: root_from_record("PQ-ATTESTER-COMMITMENT", &body),
            blob_fee_price_commitment: root_from_record("BLOB-FEE-PRICE-COMMITMENT", &body),
            price_band_root: root_from_record("PRICE-BAND", &body),
            signature_root: root_from_record("PQ-MARKET-SIGNATURE", &body),
            observed_at_height: height,
            expires_at_height: height.saturating_add(config.attestation_ttl_blocks),
            privacy_set_size: bucket.privacy_set_size,
            pq_security_bits: config.target_pq_security_bits,
            status: AttestationStatus::Accepted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "bucket_id": self.bucket_id,
            "oracle_id": self.oracle_id,
            "market_id": self.market_id,
            "attester_commitment": self.attester_commitment,
            "blob_fee_price_commitment": self.blob_fee_price_commitment,
            "price_band_root": self.price_band_root,
            "signature_root": self.signature_root,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementWindow {
    pub window_id: String,
    pub window_index: u64,
    pub bucket_root: String,
    pub attestation_root: String,
    pub sponsor_pool_root: String,
    pub settlement_price_commitment: String,
    pub start_height: u64,
    pub end_height: u64,
    pub total_blob_gas: u128,
    pub total_user_fee_piconero: u128,
    pub total_sponsored_fee_piconero: u128,
    pub futures_notional_piconero: u128,
    pub futures_pnl_piconero: i128,
    pub status: WindowStatus,
}

impl SettlementWindow {
    pub fn new(
        window_index: u64,
        buckets: &[EncryptedBlobDemandBucket],
        attestations: &[PqMarketAttestation],
        pools: &[SponsorPool],
        config: &Config,
        height: u64,
    ) -> Self {
        let bucket_records = buckets.iter().map(Self::bucket_leaf).collect::<Vec<_>>();
        let attestation_records = attestations
            .iter()
            .map(|attestation| attestation.public_record())
            .collect::<Vec<_>>();
        let pool_records = pools
            .iter()
            .map(SponsorPool::public_record)
            .collect::<Vec<_>>();
        let total_blob_gas = buckets.iter().map(|bucket| bucket.committed_blob_gas).sum();
        let total_user_fee_piconero = buckets
            .iter()
            .map(|bucket| bps_amount(bucket.fee_budget_piconero, bucket.user_fee_bps))
            .sum();
        let total_sponsored_fee_piconero = buckets
            .iter()
            .map(|bucket| bps_amount(bucket.fee_budget_piconero, config.sponsor_cover_bps))
            .sum();
        let futures_notional_piconero = buckets
            .iter()
            .map(|bucket| bucket.fee_budget_piconero)
            .sum::<u128>();
        let futures_pnl_piconero = signed_pnl_from_notional(futures_notional_piconero, 37);
        let body = json!({
            "window_index": window_index,
            "height": height,
            "bucket_count": buckets.len(),
            "attestation_count": attestations.len(),
            "total_blob_gas": total_blob_gas.to_string(),
        });
        Self {
            window_id: id_from_record("SETTLEMENT-WINDOW-ID", &body),
            window_index,
            bucket_root: merkle_root("PRIVATE-L2-BLOB-FUTURES-WINDOW-BUCKETS", &bucket_records),
            attestation_root: merkle_root(
                "PRIVATE-L2-BLOB-FUTURES-WINDOW-ATTESTATIONS",
                &attestation_records,
            ),
            sponsor_pool_root: merkle_root("PRIVATE-L2-BLOB-FUTURES-WINDOW-POOLS", &pool_records),
            settlement_price_commitment: root_from_record("SETTLEMENT-PRICE", &body),
            start_height: height,
            end_height: height.saturating_add(config.settlement_window_blocks),
            total_blob_gas,
            total_user_fee_piconero,
            total_sponsored_fee_piconero,
            futures_notional_piconero,
            futures_pnl_piconero,
            status: WindowStatus::Settling,
        }
    }

    fn bucket_leaf(bucket: &EncryptedBlobDemandBucket) -> Value {
        json!({
            "bucket_id": bucket.bucket_id,
            "demand_class": bucket.demand_class.as_str(),
            "futures_side": bucket.futures_side.as_str(),
            "bucket_ciphertext_root": bucket.bucket_ciphertext_root,
            "committed_blob_gas": bucket.committed_blob_gas.to_string(),
            "fee_budget_piconero": bucket.fee_budget_piconero.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "window_index": self.window_index,
            "bucket_root": self.bucket_root,
            "attestation_root": self.attestation_root,
            "sponsor_pool_root": self.sponsor_pool_root,
            "settlement_price_commitment": self.settlement_price_commitment,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "total_blob_gas": self.total_blob_gas.to_string(),
            "total_user_fee_piconero": self.total_user_fee_piconero.to_string(),
            "total_sponsored_fee_piconero": self.total_sponsored_fee_piconero.to_string(),
            "futures_notional_piconero": self.futures_notional_piconero.to_string(),
            "futures_pnl_piconero": self.futures_pnl_piconero.to_string(),
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateAccount {
    pub rebate_id: String,
    pub bucket_id: String,
    pub sponsor_pool_id: String,
    pub account_commitment: String,
    pub rebate_commitment_root: String,
    pub rebate_amount_piconero: u128,
    pub accrued_at_height: u64,
    pub claimable_after_height: u64,
    pub expires_at_height: u64,
    pub status: RebateStatus,
}

impl RebateAccount {
    pub fn new(bucket: &EncryptedBlobDemandBucket, config: &Config, height: u64) -> Self {
        let rebate_amount_piconero = bps_amount(bucket.fee_budget_piconero, config.rebate_bps);
        let body = json!({
            "bucket_id": bucket.bucket_id,
            "sponsor_pool_id": bucket.sponsor_pool_id,
            "rebate_amount_piconero": rebate_amount_piconero.to_string(),
            "height": height,
        });
        Self {
            rebate_id: id_from_record("REBATE-ACCOUNT-ID", &body),
            bucket_id: bucket.bucket_id.clone(),
            sponsor_pool_id: bucket.sponsor_pool_id.clone(),
            account_commitment: bucket.account_commitment.clone(),
            rebate_commitment_root: root_from_record("REBATE-COMMITMENT", &body),
            rebate_amount_piconero,
            accrued_at_height: height,
            claimable_after_height: height.saturating_add(1),
            expires_at_height: height.saturating_add(config.rebate_ttl_blocks),
            status: RebateStatus::Claimable,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "bucket_id": self.bucket_id,
            "sponsor_pool_id": self.sponsor_pool_id,
            "account_commitment": self.account_commitment,
            "rebate_commitment_root": self.rebate_commitment_root,
            "rebate_amount_piconero": self.rebate_amount_piconero.to_string(),
            "accrued_at_height": self.accrued_at_height,
            "claimable_after_height": self.claimable_after_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskLimit {
    pub risk_id: String,
    pub account_commitment: String,
    pub sponsor_pool_id: String,
    pub margin_commitment_root: String,
    pub notional_piconero: u128,
    pub initial_margin_piconero: u128,
    pub maintenance_margin_piconero: u128,
    pub max_account_notional_piconero: u128,
    pub leverage_bps: u64,
    pub updated_at_height: u64,
    pub status: RiskStatus,
}

impl RiskLimit {
    pub fn new(bucket: &EncryptedBlobDemandBucket, config: &Config, height: u64) -> Self {
        let notional_piconero = bucket.fee_budget_piconero;
        let initial_margin_piconero = bps_amount(notional_piconero, config.initial_margin_bps);
        let maintenance_margin_piconero =
            bps_amount(notional_piconero, config.maintenance_margin_bps);
        let leverage_bps = if initial_margin_piconero == 0 {
            0
        } else {
            notional_piconero.saturating_mul(MAX_BPS as u128) as u64
                / initial_margin_piconero as u64
        };
        let status = if notional_piconero >= config.max_account_notional_piconero {
            RiskStatus::AtLimit
        } else if leverage_bps > config.max_leverage_bps {
            RiskStatus::ReduceOnly
        } else {
            RiskStatus::Healthy
        };
        let body = json!({
            "bucket_id": bucket.bucket_id,
            "account_commitment": bucket.account_commitment,
            "notional_piconero": notional_piconero.to_string(),
            "height": height,
        });
        Self {
            risk_id: id_from_record("RISK-LIMIT-ID", &body),
            account_commitment: bucket.account_commitment.clone(),
            sponsor_pool_id: bucket.sponsor_pool_id.clone(),
            margin_commitment_root: root_from_record("RISK-MARGIN-COMMITMENT", &body),
            notional_piconero,
            initial_margin_piconero,
            maintenance_margin_piconero,
            max_account_notional_piconero: config.max_account_notional_piconero,
            leverage_bps,
            updated_at_height: height,
            status,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "risk_id": self.risk_id,
            "account_commitment": self.account_commitment,
            "sponsor_pool_id": self.sponsor_pool_id,
            "margin_commitment_root": self.margin_commitment_root,
            "notional_piconero": self.notional_piconero.to_string(),
            "initial_margin_piconero": self.initial_margin_piconero.to_string(),
            "maintenance_margin_piconero": self.maintenance_margin_piconero.to_string(),
            "max_account_notional_piconero": self.max_account_notional_piconero.to_string(),
            "leverage_bps": self.leverage_bps,
            "updated_at_height": self.updated_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleQuarantine {
    pub quarantine_id: String,
    pub oracle_id: String,
    pub attestation_id: String,
    pub reason: QuarantineReason,
    pub last_observed_height: u64,
    pub quarantined_at_height: u64,
    pub release_after_height: u64,
    pub evidence_root: String,
    pub active: bool,
}

impl OracleQuarantine {
    pub fn new(
        oracle_id: &str,
        attestation_id: &str,
        reason: QuarantineReason,
        last_observed_height: u64,
        config: &Config,
        height: u64,
    ) -> Self {
        let body = json!({
            "oracle_id": oracle_id,
            "attestation_id": attestation_id,
            "reason": reason.as_str(),
            "last_observed_height": last_observed_height,
            "height": height,
        });
        Self {
            quarantine_id: id_from_record("ORACLE-QUARANTINE-ID", &body),
            oracle_id: oracle_id.to_string(),
            attestation_id: attestation_id.to_string(),
            reason,
            last_observed_height,
            quarantined_at_height: height,
            release_after_height: height.saturating_add(config.oracle_quarantine_blocks),
            evidence_root: root_from_record("ORACLE-QUARANTINE-EVIDENCE", &body),
            active: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "oracle_id": self.oracle_id,
            "attestation_id": self.attestation_id,
            "reason": self.reason.as_str(),
            "last_observed_height": self.last_observed_height,
            "quarantined_at_height": self.quarantined_at_height,
            "release_after_height": self.release_after_height,
            "evidence_root": self.evidence_root,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub redaction_policy_root: String,
    pub allowed_units: u64,
    pub used_units: u64,
    pub last_redacted_at_height: u64,
}

impl RedactionBudget {
    pub fn new(subject_kind: &str, subject_id: &str, config: &Config, height: u64) -> Self {
        let body = json!({
            "subject_kind": subject_kind,
            "subject_id": subject_id,
            "allowed_units": config.default_redaction_budget_units,
            "height": height,
        });
        Self {
            budget_id: id_from_record("REDACTION-BUDGET-ID", &body),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            redaction_policy_root: root_from_record("REDACTION-POLICY", &body),
            allowed_units: config.default_redaction_budget_units,
            used_units: 0,
            last_redacted_at_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "redaction_policy_root": self.redaction_policy_root,
            "allowed_units": self.allowed_units,
            "used_units": self.used_units,
            "remaining_units": self.allowed_units.saturating_sub(self.used_units),
            "last_redacted_at_height": self.last_redacted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub disclosed_fields: Vec<String>,
    pub redaction_budget_id: String,
    pub emitted_at_height: u64,
}

impl DeterministicPublicRecord {
    pub fn new(
        subject_kind: &str,
        subject_id: &str,
        subject_record: &Value,
        disclosed_fields: &[&str],
        redaction_budget_id: &str,
        height: u64,
    ) -> Self {
        let field_list = disclosed_fields
            .iter()
            .map(|field| (*field).to_string())
            .collect::<Vec<_>>();
        let body = json!({
            "subject_kind": subject_kind,
            "subject_id": subject_id,
            "subject_root": public_record_root(subject_record),
            "disclosed_fields": field_list,
            "redaction_budget_id": redaction_budget_id,
            "height": height,
        });
        Self {
            record_id: id_from_record("PUBLIC-RECORD-ID", &body),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: public_record_root(subject_record),
            disclosed_fields: field_list,
            redaction_budget_id: redaction_budget_id.to_string(),
            emitted_at_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "disclosed_fields": self.disclosed_fields,
            "redaction_budget_id": self.redaction_budget_id,
            "emitted_at_height": self.emitted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub encrypted_blob_demand_bucket_root: String,
    pub live_demand_bucket_root: String,
    pub sponsor_pool_root: String,
    pub active_sponsor_pool_root: String,
    pub pq_market_attestation_root: String,
    pub accepted_pq_market_attestation_root: String,
    pub settlement_window_root: String,
    pub live_settlement_window_root: String,
    pub rebate_accounting_root: String,
    pub claimable_rebate_root: String,
    pub risk_limit_root: String,
    pub elevated_risk_root: String,
    pub stale_oracle_quarantine_root: String,
    pub active_quarantine_root: String,
    pub redaction_budget_root: String,
    pub deterministic_public_record_root: String,
    pub consumed_nullifier_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "encrypted_blob_demand_bucket_root": self.encrypted_blob_demand_bucket_root,
            "live_demand_bucket_root": self.live_demand_bucket_root,
            "sponsor_pool_root": self.sponsor_pool_root,
            "active_sponsor_pool_root": self.active_sponsor_pool_root,
            "pq_market_attestation_root": self.pq_market_attestation_root,
            "accepted_pq_market_attestation_root": self.accepted_pq_market_attestation_root,
            "settlement_window_root": self.settlement_window_root,
            "live_settlement_window_root": self.live_settlement_window_root,
            "rebate_accounting_root": self.rebate_accounting_root,
            "claimable_rebate_root": self.claimable_rebate_root,
            "risk_limit_root": self.risk_limit_root,
            "elevated_risk_root": self.elevated_risk_root,
            "stale_oracle_quarantine_root": self.stale_oracle_quarantine_root,
            "active_quarantine_root": self.active_quarantine_root,
            "redaction_budget_root": self.redaction_budget_root,
            "deterministic_public_record_root": self.deterministic_public_record_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "event_root": self.event_root,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub height: u64,
    pub demand_buckets: BTreeMap<String, EncryptedBlobDemandBucket>,
    pub sponsor_pools: BTreeMap<String, SponsorPool>,
    pub pq_market_attestations: BTreeMap<String, PqMarketAttestation>,
    pub settlement_windows: BTreeMap<String, SettlementWindow>,
    pub rebate_accounts: BTreeMap<String, RebateAccount>,
    pub risk_limits: BTreeMap<String, RiskLimit>,
    pub oracle_quarantines: BTreeMap<String, OracleQuarantine>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub public_records: BTreeMap<String, DeterministicPublicRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub events: Vec<Value>,
}

pub type Runtime = State;

impl State {
    pub fn empty(config: Config, height: u64) -> Self {
        Self {
            config,
            counters: Counters::default(),
            height,
            demand_buckets: BTreeMap::new(),
            sponsor_pools: BTreeMap::new(),
            pq_market_attestations: BTreeMap::new(),
            settlement_windows: BTreeMap::new(),
            rebate_accounts: BTreeMap::new(),
            risk_limits: BTreeMap::new(),
            oracle_quarantines: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            public_records: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            events: Vec::new(),
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self::empty(config, DEVNET_HEIGHT);
        let pool = SponsorPool::new(
            "devnet-low-fee-sponsor-pool-a",
            "sponsor-commitment-devnet-a",
            4_500_000_000_000,
            &state.config,
            state.height,
        );
        let pool_id = pool.pool_id.clone();
        state.sponsor_pools.insert(pool_id.clone(), pool);

        let bucket = EncryptedBlobDemandBucket::new(
            "account-commitment-devnet-a",
            DemandClass::RetailBatch,
            FuturesSide::SponsorHedge,
            1_250_000,
            85_000_000,
            &pool_id,
            &state.config,
            state.height,
        );
        let bucket_id = bucket.bucket_id.clone();
        state
            .consumed_nullifiers
            .insert(bucket.nullifier_root.clone());
        state.demand_buckets.insert(bucket_id.clone(), bucket);

        let bucket_ref = state
            .demand_buckets
            .get(&bucket_id)
            .cloned()
            .expect("bucket");
        let attestation = PqMarketAttestation::new(&bucket_ref, &state.config, state.height + 1);
        state
            .pq_market_attestations
            .insert(attestation.attestation_id.clone(), attestation);

        let risk = RiskLimit::new(&bucket_ref, &state.config, state.height + 1);
        state.risk_limits.insert(risk.risk_id.clone(), risk);
        let rebate = RebateAccount::new(&bucket_ref, &state.config, state.height + 2);
        state
            .rebate_accounts
            .insert(rebate.rebate_id.clone(), rebate);
        state.refresh_settlement_window();
        state.refresh_counters();
        state.refresh_public_records();
        state.push_event(
            "devnet_initialized",
            "state",
            json!({ "height": state.height }),
        );
        state.refresh_counters();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        state.height = state.height.saturating_add(8);
        let second_pool = SponsorPool::new(
            "devnet-low-fee-sponsor-pool-b",
            "sponsor-commitment-devnet-b",
            7_250_000_000_000,
            &state.config,
            state.height,
        );
        let pool_id = second_pool.pool_id.clone();
        state.sponsor_pools.insert(pool_id.clone(), second_pool);
        let demo_specs = [
            (
                "account-commitment-demo-bridge",
                DemandClass::BridgeExit,
                FuturesSide::LongBlobFee,
                2_750_000,
                145_000_000,
            ),
            (
                "account-commitment-demo-defi",
                DemandClass::DefiSettlement,
                FuturesSide::ShortBlobFee,
                3_300_000,
                190_000_000,
            ),
        ];
        for (account, class, side, blob_gas, fee_budget) in demo_specs {
            let bucket = EncryptedBlobDemandBucket::new(
                account,
                class,
                side,
                blob_gas,
                fee_budget,
                &pool_id,
                &state.config,
                state.height,
            );
            let bucket_id = bucket.bucket_id.clone();
            state
                .consumed_nullifiers
                .insert(bucket.nullifier_root.clone());
            state.demand_buckets.insert(bucket_id.clone(), bucket);
            let bucket_ref = state
                .demand_buckets
                .get(&bucket_id)
                .cloned()
                .expect("bucket");
            let attestation =
                PqMarketAttestation::new(&bucket_ref, &state.config, state.height + 1);
            state
                .pq_market_attestations
                .insert(attestation.attestation_id.clone(), attestation);
            let risk = RiskLimit::new(&bucket_ref, &state.config, state.height + 1);
            state.risk_limits.insert(risk.risk_id.clone(), risk);
            let rebate = RebateAccount::new(&bucket_ref, &state.config, state.height + 2);
            state
                .rebate_accounts
                .insert(rebate.rebate_id.clone(), rebate);
        }

        if let Some(first_attestation) = state.pq_market_attestations.values().next().cloned() {
            let quarantine = OracleQuarantine::new(
                &first_attestation.oracle_id,
                &first_attestation.attestation_id,
                QuarantineReason::StaleOracle,
                first_attestation.observed_at_height,
                &state.config,
                state.height,
            );
            state
                .oracle_quarantines
                .insert(quarantine.quarantine_id.clone(), quarantine);
        }

        state.refresh_settlement_window();
        state.refresh_counters();
        state.refresh_public_records();
        state.push_event("demo_populated", "state", json!({ "height": state.height }));
        state.refresh_counters();
        state
    }

    pub fn roots(&self) -> Roots {
        let bucket_records = map_records(
            &self.demand_buckets,
            EncryptedBlobDemandBucket::public_record,
        );
        let live_bucket_records = self
            .demand_buckets
            .iter()
            .filter(|(_, bucket)| bucket.status.live())
            .map(|(key, bucket)| json!({ "key": key, "record": bucket.public_record() }))
            .collect::<Vec<_>>();
        let pool_records = map_records(&self.sponsor_pools, SponsorPool::public_record);
        let active_pool_records = self
            .sponsor_pools
            .iter()
            .filter(|(_, pool)| pool.status.usable())
            .map(|(key, pool)| json!({ "key": key, "record": pool.public_record() }))
            .collect::<Vec<_>>();
        let attestation_records = map_records(
            &self.pq_market_attestations,
            PqMarketAttestation::public_record,
        );
        let accepted_attestation_records = self
            .pq_market_attestations
            .iter()
            .filter(|(_, attestation)| attestation.status.usable())
            .map(|(key, attestation)| json!({ "key": key, "record": attestation.public_record() }))
            .collect::<Vec<_>>();
        let window_records = map_records(&self.settlement_windows, SettlementWindow::public_record);
        let live_window_records = self
            .settlement_windows
            .iter()
            .filter(|(_, window)| window.status.live())
            .map(|(key, window)| json!({ "key": key, "record": window.public_record() }))
            .collect::<Vec<_>>();
        let rebate_records = map_records(&self.rebate_accounts, RebateAccount::public_record);
        let claimable_rebate_records = self
            .rebate_accounts
            .iter()
            .filter(|(_, rebate)| rebate.status == RebateStatus::Claimable)
            .map(|(key, rebate)| json!({ "key": key, "record": rebate.public_record() }))
            .collect::<Vec<_>>();
        let risk_records = map_records(&self.risk_limits, RiskLimit::public_record);
        let elevated_risk_records = self
            .risk_limits
            .iter()
            .filter(|(_, risk)| risk.status != RiskStatus::Healthy)
            .map(|(key, risk)| json!({ "key": key, "record": risk.public_record() }))
            .collect::<Vec<_>>();
        let quarantine_records =
            map_records(&self.oracle_quarantines, OracleQuarantine::public_record);
        let active_quarantine_records = self
            .oracle_quarantines
            .iter()
            .filter(|(_, quarantine)| quarantine.active)
            .map(|(key, quarantine)| json!({ "key": key, "record": quarantine.public_record() }))
            .collect::<Vec<_>>();
        let redaction_records =
            map_records(&self.redaction_budgets, RedactionBudget::public_record);
        let public_records = map_records(
            &self.public_records,
            DeterministicPublicRecord::public_record,
        );
        Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            encrypted_blob_demand_bucket_root: merkle_root(
                "PRIVATE-L2-BLOB-FUTURES-DEMAND-BUCKETS",
                &bucket_records,
            ),
            live_demand_bucket_root: merkle_root(
                "PRIVATE-L2-BLOB-FUTURES-LIVE-DEMAND-BUCKETS",
                &live_bucket_records,
            ),
            sponsor_pool_root: merkle_root("PRIVATE-L2-BLOB-FUTURES-SPONSOR-POOLS", &pool_records),
            active_sponsor_pool_root: merkle_root(
                "PRIVATE-L2-BLOB-FUTURES-ACTIVE-SPONSOR-POOLS",
                &active_pool_records,
            ),
            pq_market_attestation_root: merkle_root(
                "PRIVATE-L2-BLOB-FUTURES-PQ-MARKET-ATTESTATIONS",
                &attestation_records,
            ),
            accepted_pq_market_attestation_root: merkle_root(
                "PRIVATE-L2-BLOB-FUTURES-ACCEPTED-PQ-MARKET-ATTESTATIONS",
                &accepted_attestation_records,
            ),
            settlement_window_root: merkle_root(
                "PRIVATE-L2-BLOB-FUTURES-SETTLEMENT-WINDOWS",
                &window_records,
            ),
            live_settlement_window_root: merkle_root(
                "PRIVATE-L2-BLOB-FUTURES-LIVE-SETTLEMENT-WINDOWS",
                &live_window_records,
            ),
            rebate_accounting_root: merkle_root(
                "PRIVATE-L2-BLOB-FUTURES-REBATE-ACCOUNTING",
                &rebate_records,
            ),
            claimable_rebate_root: merkle_root(
                "PRIVATE-L2-BLOB-FUTURES-CLAIMABLE-REBATES",
                &claimable_rebate_records,
            ),
            risk_limit_root: merkle_root("PRIVATE-L2-BLOB-FUTURES-RISK-LIMITS", &risk_records),
            elevated_risk_root: merkle_root(
                "PRIVATE-L2-BLOB-FUTURES-ELEVATED-RISK",
                &elevated_risk_records,
            ),
            stale_oracle_quarantine_root: merkle_root(
                "PRIVATE-L2-BLOB-FUTURES-STALE-ORACLE-QUARANTINE",
                &quarantine_records,
            ),
            active_quarantine_root: merkle_root(
                "PRIVATE-L2-BLOB-FUTURES-ACTIVE-QUARANTINE",
                &active_quarantine_records,
            ),
            redaction_budget_root: merkle_root(
                "PRIVATE-L2-BLOB-FUTURES-REDACTION-BUDGETS",
                &redaction_records,
            ),
            deterministic_public_record_root: merkle_root(
                "PRIVATE-L2-BLOB-FUTURES-DETERMINISTIC-PUBLIC-RECORDS",
                &public_records,
            ),
            consumed_nullifier_root: set_root(
                "PRIVATE-L2-BLOB-FUTURES-CONSUMED-NULLIFIERS",
                &self.consumed_nullifiers,
            ),
            event_root: merkle_root("PRIVATE-L2-BLOB-FUTURES-EVENTS", &self.events),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "market_id": self.config.market_id,
            "oracle_id": self.config.oracle_id,
            "config_root": roots.config_root,
            "counters_root": roots.counters_root,
            "roots_root": roots.state_root(),
            "roots": roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn refresh_settlement_window(&mut self) {
        let buckets = self.demand_buckets.values().cloned().collect::<Vec<_>>();
        let attestations = self
            .pq_market_attestations
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let pools = self.sponsor_pools.values().cloned().collect::<Vec<_>>();
        if buckets.is_empty() {
            return;
        }
        let window = SettlementWindow::new(
            self.settlement_windows.len() as u64,
            &buckets,
            &attestations,
            &pools,
            &self.config,
            self.height,
        );
        for bucket in self.demand_buckets.values_mut() {
            if bucket.status.live() {
                bucket.status = BucketStatus::Windowed;
            }
        }
        for pool in self.sponsor_pools.values_mut() {
            let reserved = buckets
                .iter()
                .filter(|bucket| bucket.sponsor_pool_id == pool.pool_id)
                .map(|bucket| bps_amount(bucket.fee_budget_piconero, self.config.sponsor_cover_bps))
                .sum::<u128>();
            let rebate = buckets
                .iter()
                .filter(|bucket| bucket.sponsor_pool_id == pool.pool_id)
                .map(|bucket| bps_amount(bucket.fee_budget_piconero, self.config.rebate_bps))
                .sum::<u128>();
            pool.reserved_fee_piconero = reserved;
            pool.rebate_liability_piconero = rebate;
            if reserved >= pool.available_fee_piconero {
                pool.status = SponsorPoolStatus::Exhausted;
            }
        }
        self.settlement_windows
            .insert(window.window_id.clone(), window);
    }

    fn refresh_counters(&mut self) {
        let encrypted_blob_gas_committed = self
            .demand_buckets
            .values()
            .map(|bucket| bucket.committed_blob_gas)
            .sum();
        let encrypted_blob_gas_settled = self
            .demand_buckets
            .values()
            .filter(|bucket| matches!(bucket.status, BucketStatus::Settled | BucketStatus::Rebated))
            .map(|bucket| bucket.committed_blob_gas)
            .sum();
        let sponsored_fee_piconero = self
            .settlement_windows
            .values()
            .map(|window| window.total_sponsored_fee_piconero)
            .sum();
        let user_fee_piconero = self
            .settlement_windows
            .values()
            .map(|window| window.total_user_fee_piconero)
            .sum();
        let rebate_amount_piconero = self
            .rebate_accounts
            .values()
            .map(|rebate| rebate.rebate_amount_piconero)
            .sum();
        let futures_notional_piconero = self
            .settlement_windows
            .values()
            .map(|window| window.futures_notional_piconero)
            .sum();
        let futures_pnl_piconero = self
            .settlement_windows
            .values()
            .map(|window| window.futures_pnl_piconero)
            .sum();
        self.counters = Counters {
            encrypted_blob_demand_buckets: self.demand_buckets.len() as u64,
            live_demand_buckets: self
                .demand_buckets
                .values()
                .filter(|bucket| bucket.status.live())
                .count() as u64,
            sponsored_demand_buckets: self
                .demand_buckets
                .values()
                .filter(|bucket| {
                    matches!(
                        bucket.status,
                        BucketStatus::Sponsored | BucketStatus::Windowed
                    )
                })
                .count() as u64,
            settled_demand_buckets: self
                .demand_buckets
                .values()
                .filter(|bucket| {
                    matches!(bucket.status, BucketStatus::Settled | BucketStatus::Rebated)
                })
                .count() as u64,
            sponsor_pools: self.sponsor_pools.len() as u64,
            active_sponsor_pools: self
                .sponsor_pools
                .values()
                .filter(|pool| pool.status.usable())
                .count() as u64,
            pq_market_attestations: self.pq_market_attestations.len() as u64,
            accepted_pq_market_attestations: self
                .pq_market_attestations
                .values()
                .filter(|attestation| attestation.status == AttestationStatus::Accepted)
                .count() as u64,
            quarantined_attestations: self
                .pq_market_attestations
                .values()
                .filter(|attestation| attestation.status == AttestationStatus::Quarantined)
                .count() as u64,
            settlement_windows: self.settlement_windows.len() as u64,
            live_settlement_windows: self
                .settlement_windows
                .values()
                .filter(|window| window.status.live())
                .count() as u64,
            settled_settlement_windows: self
                .settlement_windows
                .values()
                .filter(|window| window.status == WindowStatus::Settled)
                .count() as u64,
            rebate_accounts: self.rebate_accounts.len() as u64,
            claimable_rebate_accounts: self
                .rebate_accounts
                .values()
                .filter(|rebate| rebate.status == RebateStatus::Claimable)
                .count() as u64,
            settled_rebate_accounts: self
                .rebate_accounts
                .values()
                .filter(|rebate| rebate.status == RebateStatus::Settled)
                .count() as u64,
            risk_limits: self.risk_limits.len() as u64,
            risk_limits_at_or_above_limit: self
                .risk_limits
                .values()
                .filter(|risk| risk.status != RiskStatus::Healthy)
                .count() as u64,
            oracle_quarantines: self.oracle_quarantines.len() as u64,
            active_oracle_quarantines: self
                .oracle_quarantines
                .values()
                .filter(|quarantine| quarantine.active)
                .count() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            redaction_budget_units_used: self
                .redaction_budgets
                .values()
                .map(|budget| budget.used_units)
                .sum(),
            encrypted_blob_gas_committed,
            encrypted_blob_gas_settled,
            sponsored_fee_piconero,
            user_fee_piconero,
            rebate_amount_piconero,
            futures_notional_piconero,
            futures_pnl_piconero,
            public_records: self.public_records.len() as u64,
        };
    }

    fn refresh_public_records(&mut self) {
        self.public_records.clear();
        self.redaction_budgets.clear();
        self.insert_public_record(
            "config",
            "config",
            &self.config.public_record(),
            &["protocol_version", "market_id", "oracle_id", "low_fee_bps"],
        );
        let buckets = self.demand_buckets.values().cloned().collect::<Vec<_>>();
        for bucket in buckets {
            self.insert_public_record(
                "encrypted_blob_demand_bucket",
                &bucket.bucket_id,
                &bucket.public_record(),
                &[
                    "demand_class",
                    "futures_side",
                    "bucket_ciphertext_root",
                    "privacy_set_size",
                    "pq_security_bits",
                    "user_fee_bps",
                    "expires_at_height",
                    "status",
                ],
            );
        }
        let pools = self.sponsor_pools.values().cloned().collect::<Vec<_>>();
        for pool in pools {
            self.insert_public_record(
                "sponsor_pool",
                &pool.pool_id,
                &pool.public_record(),
                &[
                    "reserve_commitment_root",
                    "cover_bps",
                    "min_privacy_set_size",
                    "status",
                ],
            );
        }
        let attestations = self
            .pq_market_attestations
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for attestation in attestations {
            self.insert_public_record(
                "pq_market_attestation",
                &attestation.attestation_id,
                &attestation.public_record(),
                &[
                    "bucket_id",
                    "oracle_id",
                    "price_band_root",
                    "privacy_set_size",
                    "pq_security_bits",
                    "status",
                ],
            );
        }
        let windows = self
            .settlement_windows
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for window in windows {
            self.insert_public_record(
                "futures_settlement_window",
                &window.window_id,
                &window.public_record(),
                &[
                    "window_index",
                    "bucket_root",
                    "attestation_root",
                    "total_blob_gas",
                    "futures_notional_piconero",
                    "status",
                ],
            );
        }
        let rebates = self.rebate_accounts.values().cloned().collect::<Vec<_>>();
        for rebate in rebates {
            self.insert_public_record(
                "rebate_account",
                &rebate.rebate_id,
                &rebate.public_record(),
                &[
                    "bucket_id",
                    "sponsor_pool_id",
                    "rebate_commitment_root",
                    "rebate_amount_piconero",
                    "status",
                ],
            );
        }
        let risks = self.risk_limits.values().cloned().collect::<Vec<_>>();
        for risk in risks {
            self.insert_public_record(
                "risk_limit",
                &risk.risk_id,
                &risk.public_record(),
                &[
                    "sponsor_pool_id",
                    "margin_commitment_root",
                    "notional_piconero",
                    "leverage_bps",
                    "status",
                ],
            );
        }
        let quarantines = self
            .oracle_quarantines
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for quarantine in quarantines {
            self.insert_public_record(
                "oracle_quarantine",
                &quarantine.quarantine_id,
                &quarantine.public_record(),
                &[
                    "oracle_id",
                    "attestation_id",
                    "reason",
                    "release_after_height",
                    "active",
                ],
            );
        }
        self.counters.public_records = self.public_records.len() as u64;
    }

    fn insert_public_record(
        &mut self,
        subject_kind: &str,
        subject_id: &str,
        subject_record: &Value,
        disclosed_fields: &[&str],
    ) {
        if self.public_records.len() >= self.config.max_public_records {
            return;
        }
        let mut budget = RedactionBudget::new(subject_kind, subject_id, &self.config, self.height);
        budget.used_units = disclosed_fields.len() as u64;
        let budget_id = budget.budget_id.clone();
        self.redaction_budgets.insert(budget_id.clone(), budget);
        let record = DeterministicPublicRecord::new(
            subject_kind,
            subject_id,
            subject_record,
            disclosed_fields,
            &budget_id,
            self.height,
        );
        self.public_records.insert(record.record_id.clone(), record);
    }

    fn push_event(&mut self, kind: &str, record_id: &str, payload: Value) {
        let event_id = domain_hash(
            "PRIVATE-L2-BLOB-FUTURES-EVENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind),
                HashPart::Str(record_id),
                HashPart::Int(self.events.len() as i128),
            ],
            32,
        );
        self.events.push(json!({
            "event_id": event_id,
            "kind": kind,
            "record_id": record_id,
            "payload_root": root_from_record("EVENT-PAYLOAD", &payload),
        }));
    }
}

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

pub fn roots(state: &State) -> Roots {
    state.roots()
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root("STATE", record)
}

pub fn public_record_root(record: &Value) -> String {
    root_from_record("PUBLIC-RECORD", record)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-FEE-FUTURES:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-FEE-FUTURES:{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-BLOB-FEE-FUTURES:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn map_records<T, F>(map: &BTreeMap<String, T>, public_record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    map.iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>()
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_json_field(record: &mut Value, field: &str, value: Value) {
    if let Some(object) = record.as_object_mut() {
        object.insert(field.to_string(), value);
    }
}

fn bps_amount(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn signed_pnl_from_notional(notional: u128, bps: u64) -> i128 {
    let pnl = bps_amount(notional, bps);
    if pnl > i128::MAX as u128 {
        i128::MAX
    } else {
        pnl as i128
    }
}
