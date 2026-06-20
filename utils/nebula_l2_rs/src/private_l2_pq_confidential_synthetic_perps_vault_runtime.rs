use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialSyntheticPerpsVaultRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-synthetic-perps-vault-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_PQ_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-risk-attestation-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_VAULT_SCHEME: &str =
    "private-l2-confidential-synthetic-perps-vault-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_COLLATERAL_SCHEME: &str =
    "private-l2-confidential-perps-collateral-note-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_POSITION_SCHEME: &str =
    "private-l2-sealed-synthetic-perps-position-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_RISK_SCHEME: &str =
    "post-quantum-confidential-perps-risk-attestation-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_FUNDING_SCHEME: &str =
    "confidential-synthetic-perps-funding-receipt-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_LIQUIDATION_SCHEME: &str =
    "confidential-liquidation-guard-band-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_REBATE_SCHEME: &str =
    "private-l2-low-fee-perps-rebate-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_ORACLE_SCHEME: &str =
    "stale-oracle-quarantine-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_REDACTION_SCHEME: &str =
    "privacy-redaction-budget-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEVNET_HEIGHT: u64 = 1_144_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MONERO_NETWORK: &str =
    "monero-private-l2-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "private-l2-confidential-synthetic-perps-low-fee";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_VAULTS: usize =
    131_072;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_COLLATERAL_NOTES:
    usize = 8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_POSITIONS: usize =
    4_194_304;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS:
    usize = 4_194_304;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_FUNDING_RECEIPTS:
    usize = 8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_GUARD_BANDS: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_REBATES: usize =
    4_194_304;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_ORACLE_QUARANTINES:
    usize = 524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_REDACTION_BUDGETS:
    usize = 524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE:
    u64 = 8_192;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_TARGET_PRIVACY_SET_SIZE:
    u64 = 65_536;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 =
    12;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_REBATE_BPS: u64 = 6;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MIN_MARGIN_BPS: u64 =
    650;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAINTENANCE_MARGIN_BPS:
    u64 = 420;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_LIQUIDATION_BUFFER_BPS:
    u64 = 180;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_LEVERAGE_BPS: u64 =
    1_500;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_ORACLE_TTL_BLOCKS: u64 =
    18;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_FUNDING_EPOCH_BLOCKS:
    u64 = 60;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_REDACTION_EPOCH_BLOCKS:
    u64 = 720;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntheticVaultKind {
    XmrUsdPerp,
    BtcUsdPerp,
    EthUsdPerp,
    StableBasketPerp,
    RatePerp,
    CustomIndexPerp,
}

impl SyntheticVaultKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::XmrUsdPerp => "xmr_usd_perp",
            Self::BtcUsdPerp => "btc_usd_perp",
            Self::EthUsdPerp => "eth_usd_perp",
            Self::StableBasketPerp => "stable_basket_perp",
            Self::RatePerp => "rate_perp",
            Self::CustomIndexPerp => "custom_index_perp",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Draft,
    Active,
    DepositOnly,
    ReduceOnly,
    Paused,
    Quarantined,
    Retired,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::DepositOnly => "deposit_only",
            Self::ReduceOnly => "reduce_only",
            Self::Paused => "paused",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_new_risk(self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn accepts_collateral(self) -> bool {
        matches!(self, Self::Active | Self::DepositOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralNoteStatus {
    Pending,
    Locked,
    Released,
    Slashed,
    Expired,
    Rejected,
}

impl CollateralNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Locked => "locked",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    Long,
    Short,
}

impl PositionSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Long => "long",
            Self::Short => "short",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    PendingOpen,
    Open,
    ReduceOnly,
    LiquidationGuarded,
    Closed,
    Rejected,
}

impl PositionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingOpen => "pending_open",
            Self::Open => "open",
            Self::ReduceOnly => "reduce_only",
            Self::LiquidationGuarded => "liquidation_guarded",
            Self::Closed => "closed",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskVerdict {
    Pass,
    Warn,
    Guarded,
    Reject,
}

impl RiskVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Guarded => "guarded",
            Self::Reject => "reject",
        }
    }

    pub fn allows_open(self) -> bool {
        matches!(self, Self::Pass | Self::Warn | Self::Guarded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FundingDirection {
    LongPaysShort,
    ShortPaysLong,
    Neutral,
}

impl FundingDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LongPaysShort => "long_pays_short",
            Self::ShortPaysLong => "short_pays_long",
            Self::Neutral => "neutral",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardBandStatus {
    Proposed,
    Active,
    Triggered,
    Released,
    Disputed,
}

impl GuardBandStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Triggered => "triggered",
            Self::Released => "released",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleQuarantineStatus {
    Watching,
    Quarantined,
    Cleared,
    Slashed,
}

impl OracleQuarantineStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Watching => "watching",
            Self::Quarantined => "quarantined",
            Self::Cleared => "cleared",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    Position,
    Collateral,
    Funding,
    Liquidation,
    Oracle,
    Aggregate,
}

impl RedactionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Position => "position",
            Self::Collateral => "collateral",
            Self::Funding => "funding",
            Self::Liquidation => "liquidation",
            Self::Oracle => "oracle",
            Self::Aggregate => "aggregate",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub low_fee_lane: String,
    pub max_vaults: usize,
    pub max_collateral_notes: usize,
    pub max_positions: usize,
    pub max_risk_attestations: usize,
    pub max_funding_receipts: usize,
    pub max_guard_bands: usize,
    pub max_rebates: usize,
    pub max_oracle_quarantines: usize,
    pub max_redaction_budgets: usize,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub min_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_buffer_bps: u64,
    pub max_leverage_bps: u64,
    pub oracle_ttl_blocks: u64,
    pub funding_epoch_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub require_pq_risk_attestation: bool,
    pub require_low_fee_rebate_receipt: bool,
    pub quarantine_stale_oracles: bool,
    pub enforce_redaction_budget: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            schema_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MONERO_NETWORK
                    .to_string(),
            low_fee_lane:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_LOW_FEE_LANE
                    .to_string(),
            max_vaults:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_VAULTS,
            max_collateral_notes:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_COLLATERAL_NOTES,
            max_positions:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_POSITIONS,
            max_risk_attestations:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS,
            max_funding_receipts:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_FUNDING_RECEIPTS,
            max_guard_bands:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_GUARD_BANDS,
            max_rebates:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_REBATES,
            max_oracle_quarantines:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_ORACLE_QUARANTINES,
            max_redaction_budgets:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_REDACTION_BUDGETS,
            min_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            rebate_bps: PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_REBATE_BPS,
            min_margin_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MIN_MARGIN_BPS,
            maintenance_margin_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAINTENANCE_MARGIN_BPS,
            liquidation_buffer_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_LIQUIDATION_BUFFER_BPS,
            max_leverage_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_MAX_LEVERAGE_BPS,
            oracle_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_ORACLE_TTL_BLOCKS,
            funding_epoch_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_FUNDING_EPOCH_BLOCKS,
            redaction_epoch_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEFAULT_REDACTION_EPOCH_BLOCKS,
            require_pq_risk_attestation: true,
            require_low_fee_rebate_receipt: true,
            quarantine_stale_oracles: true,
            enforce_redaction_budget: true,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("synthetic perps config public record must serialize")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub vault_counter: u64,
    pub collateral_note_counter: u64,
    pub position_counter: u64,
    pub risk_attestation_counter: u64,
    pub funding_receipt_counter: u64,
    pub guard_band_counter: u64,
    pub rebate_counter: u64,
    pub oracle_quarantine_counter: u64,
    pub redaction_budget_counter: u64,
    pub consumed_nullifier_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("synthetic perps counters public record must serialize")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub synthetic_vault_root: String,
    pub collateral_note_root: String,
    pub sealed_position_root: String,
    pub pq_risk_attestation_root: String,
    pub funding_receipt_root: String,
    pub liquidation_guard_band_root: String,
    pub low_fee_rebate_root: String,
    pub stale_oracle_quarantine_root: String,
    pub redaction_budget_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("synthetic perps roots public record must serialize")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntheticVault {
    pub vault_id: String,
    pub vault_kind: SyntheticVaultKind,
    pub status: VaultStatus,
    pub asset_pair_root: String,
    pub synthetic_asset_root: String,
    pub collateral_token_root: String,
    pub vault_commitment: String,
    pub operator_commitment: String,
    pub oracle_committee_root: String,
    pub funding_model_root: String,
    pub risk_engine_root: String,
    pub privacy_policy_root: String,
    pub max_leverage_bps: u64,
    pub min_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_buffer_bps: u64,
    pub opened_at_height: u64,
    pub latest_oracle_height: u64,
    pub latest_funding_epoch: u64,
    pub vault_state_root: String,
}

impl SyntheticVault {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("synthetic vault public record must serialize")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralNote {
    pub collateral_note_id: String,
    pub vault_id: String,
    pub status: CollateralNoteStatus,
    pub depositor_commitment: String,
    pub collateral_note_root: String,
    pub collateral_token_root: String,
    pub encrypted_amount_root: String,
    pub margin_bucket_root: String,
    pub note_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub fee_bps: u64,
    pub deposited_at_height: u64,
    pub expires_at_height: u64,
}

impl CollateralNote {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("collateral note public record must serialize")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedPerpsPosition {
    pub position_id: String,
    pub vault_id: String,
    pub collateral_note_id: String,
    pub status: PositionStatus,
    pub side: PositionSide,
    pub trader_commitment: String,
    pub sealed_position_root: String,
    pub notional_commitment_root: String,
    pub entry_price_root: String,
    pub leverage_bps: u64,
    pub margin_requirement_bps: u64,
    pub liquidation_price_band_root: String,
    pub risk_attestation_id: String,
    pub position_nullifier: String,
    pub opened_at_height: u64,
    pub last_funding_epoch: u64,
}

impl SealedPerpsPosition {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("sealed perps position public record must serialize")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRiskAttestation {
    pub risk_attestation_id: String,
    pub vault_id: String,
    pub collateral_note_id: String,
    pub verdict: RiskVerdict,
    pub risk_engine_root: String,
    pub pq_attestation_root: String,
    pub oracle_snapshot_root: String,
    pub margin_check_root: String,
    pub liquidation_check_root: String,
    pub attester_commitment: String,
    pub attestation_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
    pub valid_until_height: u64,
}

impl PqRiskAttestation {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("PQ risk attestation public record must serialize")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundingReceipt {
    pub funding_receipt_id: String,
    pub vault_id: String,
    pub position_id: String,
    pub funding_epoch: u64,
    pub direction: FundingDirection,
    pub funding_rate_root: String,
    pub payment_commitment_root: String,
    pub funding_index_root_before: String,
    pub funding_index_root_after: String,
    pub settlement_tx_root: String,
    pub receipt_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub settled_at_height: u64,
}

impl FundingReceipt {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("funding receipt public record must serialize")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationGuardBand {
    pub guard_band_id: String,
    pub vault_id: String,
    pub position_id: String,
    pub status: GuardBandStatus,
    pub lower_band_root: String,
    pub upper_band_root: String,
    pub maintenance_margin_root: String,
    pub liquidation_buffer_bps: u64,
    pub keeper_commitment: String,
    pub guard_proof_root: String,
    pub guard_nullifier: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl LiquidationGuardBand {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("liquidation guard band public record must serialize")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub vault_id: String,
    pub subject_id: String,
    pub sponsor_commitment: String,
    pub low_fee_lane: String,
    pub eligible_fee_bps: u64,
    pub rebate_bps: u64,
    pub rebate_output_root: String,
    pub rebate_proof_root: String,
    pub rebate_nullifier: String,
    pub issued_at_height: u64,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("low-fee rebate public record must serialize")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleOracleQuarantine {
    pub oracle_quarantine_id: String,
    pub vault_id: String,
    pub status: OracleQuarantineStatus,
    pub oracle_committee_root: String,
    pub stale_price_root: String,
    pub replacement_price_root: String,
    pub evidence_root: String,
    pub watcher_commitment: String,
    pub quarantine_nullifier: String,
    pub observed_at_height: u64,
    pub stale_after_height: u64,
    pub cleared_at_height: Option<u64>,
}

impl StaleOracleQuarantine {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("stale oracle quarantine public record must serialize")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyRedactionBudget {
    pub redaction_budget_id: String,
    pub vault_id: String,
    pub scope: RedactionScope,
    pub budget_commitment: String,
    pub spent_commitment: String,
    pub remaining_commitment: String,
    pub redaction_policy_root: String,
    pub auditor_commitment: String,
    pub budget_nullifier: String,
    pub epoch: u64,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("privacy redaction budget public record must serialize")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterSyntheticVaultRequest {
    pub vault_kind: SyntheticVaultKind,
    pub asset_pair_root: String,
    pub synthetic_asset_root: String,
    pub collateral_token_root: String,
    pub vault_commitment: String,
    pub operator_commitment: String,
    pub oracle_committee_root: String,
    pub funding_model_root: String,
    pub risk_engine_root: String,
    pub privacy_policy_root: String,
    pub max_leverage_bps: u64,
    pub min_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_buffer_bps: u64,
    pub opened_at_height: u64,
    pub initial_vault_state_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitCollateralNoteRequest {
    pub vault_id: String,
    pub depositor_commitment: String,
    pub collateral_note_root: String,
    pub collateral_token_root: String,
    pub encrypted_amount_root: String,
    pub margin_bucket_root: String,
    pub note_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub fee_bps: u64,
    pub deposited_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishPqRiskAttestationRequest {
    pub vault_id: String,
    pub collateral_note_id: String,
    pub verdict: RiskVerdict,
    pub risk_engine_root: String,
    pub pq_attestation_root: String,
    pub oracle_snapshot_root: String,
    pub margin_check_root: String,
    pub liquidation_check_root: String,
    pub attester_commitment: String,
    pub attestation_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
    pub valid_until_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenSealedPositionRequest {
    pub vault_id: String,
    pub collateral_note_id: String,
    pub risk_attestation_id: String,
    pub side: PositionSide,
    pub trader_commitment: String,
    pub sealed_position_root: String,
    pub notional_commitment_root: String,
    pub entry_price_root: String,
    pub leverage_bps: u64,
    pub margin_requirement_bps: u64,
    pub liquidation_price_band_root: String,
    pub position_nullifier: String,
    pub opened_at_height: u64,
    pub last_funding_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishFundingReceiptRequest {
    pub vault_id: String,
    pub position_id: String,
    pub funding_epoch: u64,
    pub direction: FundingDirection,
    pub funding_rate_root: String,
    pub payment_commitment_root: String,
    pub funding_index_root_before: String,
    pub funding_index_root_after: String,
    pub settlement_tx_root: String,
    pub receipt_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub settled_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenLiquidationGuardBandRequest {
    pub vault_id: String,
    pub position_id: String,
    pub status: GuardBandStatus,
    pub lower_band_root: String,
    pub upper_band_root: String,
    pub maintenance_margin_root: String,
    pub liquidation_buffer_bps: u64,
    pub keeper_commitment: String,
    pub guard_proof_root: String,
    pub guard_nullifier: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishLowFeeRebateRequest {
    pub vault_id: String,
    pub subject_id: String,
    pub sponsor_commitment: String,
    pub eligible_fee_bps: u64,
    pub rebate_bps: u64,
    pub rebate_output_root: String,
    pub rebate_proof_root: String,
    pub rebate_nullifier: String,
    pub issued_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineStaleOracleRequest {
    pub vault_id: String,
    pub status: OracleQuarantineStatus,
    pub oracle_committee_root: String,
    pub stale_price_root: String,
    pub replacement_price_root: String,
    pub evidence_root: String,
    pub watcher_commitment: String,
    pub quarantine_nullifier: String,
    pub observed_at_height: u64,
    pub stale_after_height: u64,
    pub cleared_at_height: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocateRedactionBudgetRequest {
    pub vault_id: String,
    pub scope: RedactionScope,
    pub budget_commitment: String,
    pub spent_commitment: String,
    pub remaining_commitment: String,
    pub redaction_policy_root: String,
    pub auditor_commitment: String,
    pub budget_nullifier: String,
    pub epoch: u64,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub synthetic_vaults: BTreeMap<String, SyntheticVault>,
    pub collateral_notes: BTreeMap<String, CollateralNote>,
    pub sealed_positions: BTreeMap<String, SealedPerpsPosition>,
    pub pq_risk_attestations: BTreeMap<String, PqRiskAttestation>,
    pub funding_receipts: BTreeMap<String, FundingReceipt>,
    pub liquidation_guard_bands: BTreeMap<String, LiquidationGuardBand>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub stale_oracle_quarantines: BTreeMap<String, StaleOracleQuarantine>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            current_height: PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEVNET_HEIGHT,
            synthetic_vaults: BTreeMap::new(),
            collateral_notes: BTreeMap::new(),
            sealed_positions: BTreeMap::new(),
            pq_risk_attestations: BTreeMap::new(),
            funding_receipts: BTreeMap::new(),
            liquidation_guard_bands: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            stale_oracle_quarantines: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        }
    }
}

impl State {
    pub fn register_synthetic_vault(
        &mut self,
        request: RegisterSyntheticVaultRequest,
    ) -> PrivateL2PqConfidentialSyntheticPerpsVaultRuntimeResult<SyntheticVault> {
        require(
            self.synthetic_vaults.len() < self.config.max_vaults,
            "confidential synthetic perps vault capacity exceeded",
        )?;
        require_non_empty("asset_pair_root", &request.asset_pair_root)?;
        require_non_empty("synthetic_asset_root", &request.synthetic_asset_root)?;
        require_non_empty("collateral_token_root", &request.collateral_token_root)?;
        require_non_empty("vault_commitment", &request.vault_commitment)?;
        require_non_empty("operator_commitment", &request.operator_commitment)?;
        require_non_empty("oracle_committee_root", &request.oracle_committee_root)?;
        require_non_empty("funding_model_root", &request.funding_model_root)?;
        require_non_empty("risk_engine_root", &request.risk_engine_root)?;
        require_non_empty("privacy_policy_root", &request.privacy_policy_root)?;
        require_non_empty(
            "initial_vault_state_root",
            &request.initial_vault_state_root,
        )?;
        require_bps("max_leverage_bps", request.max_leverage_bps)?;
        require_bps("min_margin_bps", request.min_margin_bps)?;
        require_bps("maintenance_margin_bps", request.maintenance_margin_bps)?;
        require_bps("liquidation_buffer_bps", request.liquidation_buffer_bps)?;
        require(
            request.max_leverage_bps <= self.config.max_leverage_bps,
            "confidential synthetic perps leverage exceeds configured maximum",
        )?;
        require(
            request.min_margin_bps >= self.config.min_margin_bps,
            "confidential synthetic perps margin below configured minimum",
        )?;
        require(
            request.maintenance_margin_bps >= self.config.maintenance_margin_bps,
            "confidential synthetic perps maintenance margin below configured minimum",
        )?;
        require(
            request.liquidation_buffer_bps >= self.config.liquidation_buffer_bps,
            "confidential synthetic perps liquidation buffer below configured minimum",
        )?;
        self.counters.vault_counter = self.counters.vault_counter.saturating_add(1);
        let vault_id = synthetic_vault_id(&request, self.counters.vault_counter);
        let vault = SyntheticVault {
            vault_id: vault_id.clone(),
            vault_kind: request.vault_kind,
            status: VaultStatus::Active,
            asset_pair_root: request.asset_pair_root,
            synthetic_asset_root: request.synthetic_asset_root,
            collateral_token_root: request.collateral_token_root,
            vault_commitment: request.vault_commitment,
            operator_commitment: request.operator_commitment,
            oracle_committee_root: request.oracle_committee_root,
            funding_model_root: request.funding_model_root,
            risk_engine_root: request.risk_engine_root,
            privacy_policy_root: request.privacy_policy_root,
            max_leverage_bps: request.max_leverage_bps,
            min_margin_bps: request.min_margin_bps,
            maintenance_margin_bps: request.maintenance_margin_bps,
            liquidation_buffer_bps: request.liquidation_buffer_bps,
            opened_at_height: request.opened_at_height,
            latest_oracle_height: request.opened_at_height,
            latest_funding_epoch: 0,
            vault_state_root: request.initial_vault_state_root,
        };
        self.current_height = self.current_height.max(vault.opened_at_height);
        self.synthetic_vaults.insert(vault_id, vault.clone());
        Ok(vault)
    }

    pub fn submit_collateral_note(
        &mut self,
        request: SubmitCollateralNoteRequest,
    ) -> PrivateL2PqConfidentialSyntheticPerpsVaultRuntimeResult<CollateralNote> {
        require(
            self.collateral_notes.len() < self.config.max_collateral_notes,
            "confidential synthetic perps collateral note capacity exceeded",
        )?;
        let vault = self.require_vault(&request.vault_id)?;
        require(
            vault.status.accepts_collateral(),
            "confidential synthetic perps vault does not accept collateral",
        )?;
        require_non_empty("depositor_commitment", &request.depositor_commitment)?;
        require_non_empty("collateral_note_root", &request.collateral_note_root)?;
        require_non_empty("collateral_token_root", &request.collateral_token_root)?;
        require_non_empty("encrypted_amount_root", &request.encrypted_amount_root)?;
        require_non_empty("margin_bucket_root", &request.margin_bucket_root)?;
        require_non_empty("note_nullifier", &request.note_nullifier)?;
        require_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        require(
            request.fee_bps <= self.config.max_user_fee_bps,
            "confidential synthetic perps collateral fee above low-fee lane maximum",
        )?;
        require(
            request.expires_at_height > request.deposited_at_height,
            "confidential synthetic perps collateral note expiry must follow deposit height",
        )?;
        self.consume_nullifier(&request.note_nullifier)?;
        self.counters.collateral_note_counter =
            self.counters.collateral_note_counter.saturating_add(1);
        let collateral_note_id =
            collateral_note_id(&request, self.counters.collateral_note_counter);
        let note = CollateralNote {
            collateral_note_id: collateral_note_id.clone(),
            vault_id: request.vault_id,
            status: CollateralNoteStatus::Pending,
            depositor_commitment: request.depositor_commitment,
            collateral_note_root: request.collateral_note_root,
            collateral_token_root: request.collateral_token_root,
            encrypted_amount_root: request.encrypted_amount_root,
            margin_bucket_root: request.margin_bucket_root,
            note_nullifier: request.note_nullifier,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            fee_bps: request.fee_bps,
            deposited_at_height: request.deposited_at_height,
            expires_at_height: request.expires_at_height,
        };
        self.current_height = self.current_height.max(note.deposited_at_height);
        self.collateral_notes
            .insert(collateral_note_id, note.clone());
        Ok(note)
    }

    pub fn publish_pq_risk_attestation(
        &mut self,
        request: PublishPqRiskAttestationRequest,
    ) -> PrivateL2PqConfidentialSyntheticPerpsVaultRuntimeResult<PqRiskAttestation> {
        require(
            self.pq_risk_attestations.len() < self.config.max_risk_attestations,
            "confidential synthetic perps risk attestation capacity exceeded",
        )?;
        let vault = self.require_vault(&request.vault_id)?;
        require(
            vault.status.accepts_new_risk(),
            "confidential synthetic perps vault does not accept new risk",
        )?;
        require(
            self.collateral_notes
                .contains_key(&request.collateral_note_id),
            "confidential synthetic perps collateral note is unknown",
        )?;
        require_non_empty("risk_engine_root", &request.risk_engine_root)?;
        require_non_empty("pq_attestation_root", &request.pq_attestation_root)?;
        require_non_empty("oracle_snapshot_root", &request.oracle_snapshot_root)?;
        require_non_empty("margin_check_root", &request.margin_check_root)?;
        require_non_empty("liquidation_check_root", &request.liquidation_check_root)?;
        require_non_empty("attester_commitment", &request.attester_commitment)?;
        require_non_empty("attestation_nullifier", &request.attestation_nullifier)?;
        require_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        require(
            request.valid_until_height > request.attested_at_height,
            "confidential synthetic perps risk attestation expiry must follow attestation height",
        )?;
        self.consume_nullifier(&request.attestation_nullifier)?;
        self.counters.risk_attestation_counter =
            self.counters.risk_attestation_counter.saturating_add(1);
        let risk_attestation_id =
            pq_risk_attestation_id(&request, self.counters.risk_attestation_counter);
        let attestation = PqRiskAttestation {
            risk_attestation_id: risk_attestation_id.clone(),
            vault_id: request.vault_id,
            collateral_note_id: request.collateral_note_id,
            verdict: request.verdict,
            risk_engine_root: request.risk_engine_root,
            pq_attestation_root: request.pq_attestation_root,
            oracle_snapshot_root: request.oracle_snapshot_root,
            margin_check_root: request.margin_check_root,
            liquidation_check_root: request.liquidation_check_root,
            attester_commitment: request.attester_commitment,
            attestation_nullifier: request.attestation_nullifier,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            attested_at_height: request.attested_at_height,
            valid_until_height: request.valid_until_height,
        };
        self.current_height = self.current_height.max(attestation.attested_at_height);
        self.pq_risk_attestations
            .insert(risk_attestation_id, attestation.clone());
        Ok(attestation)
    }

    pub fn open_sealed_position(
        &mut self,
        request: OpenSealedPositionRequest,
    ) -> PrivateL2PqConfidentialSyntheticPerpsVaultRuntimeResult<SealedPerpsPosition> {
        require(
            self.sealed_positions.len() < self.config.max_positions,
            "confidential synthetic perps position capacity exceeded",
        )?;
        let vault = self.require_vault(&request.vault_id)?;
        require(
            vault.status.accepts_new_risk(),
            "confidential synthetic perps vault does not accept positions",
        )?;
        let collateral_note = self
            .collateral_notes
            .get(&request.collateral_note_id)
            .ok_or_else(|| "confidential synthetic perps collateral note is unknown".to_string())?;
        require(
            collateral_note.vault_id == request.vault_id,
            "confidential synthetic perps collateral note belongs to a different vault",
        )?;
        let attestation = self
            .pq_risk_attestations
            .get(&request.risk_attestation_id)
            .ok_or_else(|| {
                "confidential synthetic perps PQ risk attestation is unknown".to_string()
            })?;
        require(
            attestation.vault_id == request.vault_id
                && attestation.collateral_note_id == request.collateral_note_id,
            "confidential synthetic perps risk attestation does not bind requested collateral",
        )?;
        require(
            attestation.verdict.allows_open(),
            "confidential synthetic perps risk attestation rejects position",
        )?;
        require(
            request.opened_at_height <= attestation.valid_until_height,
            "confidential synthetic perps risk attestation is stale",
        )?;
        require_non_empty("trader_commitment", &request.trader_commitment)?;
        require_non_empty("sealed_position_root", &request.sealed_position_root)?;
        require_non_empty(
            "notional_commitment_root",
            &request.notional_commitment_root,
        )?;
        require_non_empty("entry_price_root", &request.entry_price_root)?;
        require_non_empty(
            "liquidation_price_band_root",
            &request.liquidation_price_band_root,
        )?;
        require_non_empty("position_nullifier", &request.position_nullifier)?;
        require_bps("leverage_bps", request.leverage_bps)?;
        require_bps("margin_requirement_bps", request.margin_requirement_bps)?;
        require(
            request.leverage_bps <= vault.max_leverage_bps,
            "confidential synthetic perps position leverage exceeds vault maximum",
        )?;
        require(
            request.margin_requirement_bps >= vault.min_margin_bps,
            "confidential synthetic perps position margin below vault minimum",
        )?;
        self.consume_nullifier(&request.position_nullifier)?;
        self.counters.position_counter = self.counters.position_counter.saturating_add(1);
        let position_id = sealed_position_id(&request, self.counters.position_counter);
        let status = if attestation.verdict == RiskVerdict::Guarded {
            PositionStatus::LiquidationGuarded
        } else {
            PositionStatus::Open
        };
        let position = SealedPerpsPosition {
            position_id: position_id.clone(),
            vault_id: request.vault_id,
            collateral_note_id: request.collateral_note_id,
            status,
            side: request.side,
            trader_commitment: request.trader_commitment,
            sealed_position_root: request.sealed_position_root,
            notional_commitment_root: request.notional_commitment_root,
            entry_price_root: request.entry_price_root,
            leverage_bps: request.leverage_bps,
            margin_requirement_bps: request.margin_requirement_bps,
            liquidation_price_band_root: request.liquidation_price_band_root,
            risk_attestation_id: request.risk_attestation_id,
            position_nullifier: request.position_nullifier,
            opened_at_height: request.opened_at_height,
            last_funding_epoch: request.last_funding_epoch,
        };
        if let Some(note) = self.collateral_notes.get_mut(&position.collateral_note_id) {
            note.status = CollateralNoteStatus::Locked;
        }
        self.current_height = self.current_height.max(position.opened_at_height);
        self.sealed_positions.insert(position_id, position.clone());
        Ok(position)
    }

    pub fn publish_funding_receipt(
        &mut self,
        request: PublishFundingReceiptRequest,
    ) -> PrivateL2PqConfidentialSyntheticPerpsVaultRuntimeResult<FundingReceipt> {
        require(
            self.funding_receipts.len() < self.config.max_funding_receipts,
            "confidential synthetic perps funding receipt capacity exceeded",
        )?;
        self.require_vault(&request.vault_id)?;
        require(
            self.sealed_positions.contains_key(&request.position_id),
            "confidential synthetic perps position is unknown",
        )?;
        require_non_empty("funding_rate_root", &request.funding_rate_root)?;
        require_non_empty("payment_commitment_root", &request.payment_commitment_root)?;
        require_non_empty(
            "funding_index_root_before",
            &request.funding_index_root_before,
        )?;
        require_non_empty(
            "funding_index_root_after",
            &request.funding_index_root_after,
        )?;
        require_non_empty("settlement_tx_root", &request.settlement_tx_root)?;
        require_non_empty("receipt_nullifier", &request.receipt_nullifier)?;
        require_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            self.config.min_privacy_set_size,
            self.config.min_pq_security_bits,
        )?;
        self.consume_nullifier(&request.receipt_nullifier)?;
        self.counters.funding_receipt_counter =
            self.counters.funding_receipt_counter.saturating_add(1);
        let funding_receipt_id =
            funding_receipt_id(&request, self.counters.funding_receipt_counter);
        let receipt = FundingReceipt {
            funding_receipt_id: funding_receipt_id.clone(),
            vault_id: request.vault_id,
            position_id: request.position_id,
            funding_epoch: request.funding_epoch,
            direction: request.direction,
            funding_rate_root: request.funding_rate_root,
            payment_commitment_root: request.payment_commitment_root,
            funding_index_root_before: request.funding_index_root_before,
            funding_index_root_after: request.funding_index_root_after,
            settlement_tx_root: request.settlement_tx_root,
            receipt_nullifier: request.receipt_nullifier,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            settled_at_height: request.settled_at_height,
        };
        if let Some(position) = self.sealed_positions.get_mut(&receipt.position_id) {
            position.last_funding_epoch = position.last_funding_epoch.max(receipt.funding_epoch);
        }
        if let Some(vault) = self.synthetic_vaults.get_mut(&receipt.vault_id) {
            vault.latest_funding_epoch = vault.latest_funding_epoch.max(receipt.funding_epoch);
        }
        self.current_height = self.current_height.max(receipt.settled_at_height);
        self.funding_receipts
            .insert(funding_receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn open_liquidation_guard_band(
        &mut self,
        request: OpenLiquidationGuardBandRequest,
    ) -> PrivateL2PqConfidentialSyntheticPerpsVaultRuntimeResult<LiquidationGuardBand> {
        require(
            self.liquidation_guard_bands.len() < self.config.max_guard_bands,
            "confidential synthetic perps guard band capacity exceeded",
        )?;
        let vault = self.require_vault(&request.vault_id)?;
        require(
            self.sealed_positions.contains_key(&request.position_id),
            "confidential synthetic perps position is unknown",
        )?;
        require_non_empty("lower_band_root", &request.lower_band_root)?;
        require_non_empty("upper_band_root", &request.upper_band_root)?;
        require_non_empty("maintenance_margin_root", &request.maintenance_margin_root)?;
        require_non_empty("keeper_commitment", &request.keeper_commitment)?;
        require_non_empty("guard_proof_root", &request.guard_proof_root)?;
        require_non_empty("guard_nullifier", &request.guard_nullifier)?;
        require_bps("liquidation_buffer_bps", request.liquidation_buffer_bps)?;
        require(
            request.liquidation_buffer_bps >= vault.liquidation_buffer_bps,
            "confidential synthetic perps guard band buffer below vault minimum",
        )?;
        require(
            request.expires_at_height > request.opened_at_height,
            "confidential synthetic perps guard band expiry must follow open height",
        )?;
        self.consume_nullifier(&request.guard_nullifier)?;
        self.counters.guard_band_counter = self.counters.guard_band_counter.saturating_add(1);
        let guard_band_id = liquidation_guard_band_id(&request, self.counters.guard_band_counter);
        let guard = LiquidationGuardBand {
            guard_band_id: guard_band_id.clone(),
            vault_id: request.vault_id,
            position_id: request.position_id,
            status: request.status,
            lower_band_root: request.lower_band_root,
            upper_band_root: request.upper_band_root,
            maintenance_margin_root: request.maintenance_margin_root,
            liquidation_buffer_bps: request.liquidation_buffer_bps,
            keeper_commitment: request.keeper_commitment,
            guard_proof_root: request.guard_proof_root,
            guard_nullifier: request.guard_nullifier,
            opened_at_height: request.opened_at_height,
            expires_at_height: request.expires_at_height,
        };
        if let Some(position) = self.sealed_positions.get_mut(&guard.position_id) {
            position.status = PositionStatus::LiquidationGuarded;
        }
        self.current_height = self.current_height.max(guard.opened_at_height);
        self.liquidation_guard_bands
            .insert(guard_band_id, guard.clone());
        Ok(guard)
    }

    pub fn publish_low_fee_rebate(
        &mut self,
        request: PublishLowFeeRebateRequest,
    ) -> PrivateL2PqConfidentialSyntheticPerpsVaultRuntimeResult<LowFeeRebate> {
        require(
            self.low_fee_rebates.len() < self.config.max_rebates,
            "confidential synthetic perps low-fee rebate capacity exceeded",
        )?;
        self.require_vault(&request.vault_id)?;
        require_non_empty("subject_id", &request.subject_id)?;
        require_non_empty("sponsor_commitment", &request.sponsor_commitment)?;
        require_non_empty("rebate_output_root", &request.rebate_output_root)?;
        require_non_empty("rebate_proof_root", &request.rebate_proof_root)?;
        require_non_empty("rebate_nullifier", &request.rebate_nullifier)?;
        require(
            request.eligible_fee_bps <= self.config.max_user_fee_bps,
            "confidential synthetic perps rebate subject fee exceeds low-fee lane maximum",
        )?;
        require(
            request.rebate_bps <= self.config.rebate_bps,
            "confidential synthetic perps rebate bps exceeds configured rebate",
        )?;
        self.consume_nullifier(&request.rebate_nullifier)?;
        self.counters.rebate_counter = self.counters.rebate_counter.saturating_add(1);
        let rebate_id = low_fee_rebate_id(&request, self.counters.rebate_counter);
        let rebate = LowFeeRebate {
            rebate_id: rebate_id.clone(),
            vault_id: request.vault_id,
            subject_id: request.subject_id,
            sponsor_commitment: request.sponsor_commitment,
            low_fee_lane: self.config.low_fee_lane.clone(),
            eligible_fee_bps: request.eligible_fee_bps,
            rebate_bps: request.rebate_bps,
            rebate_output_root: request.rebate_output_root,
            rebate_proof_root: request.rebate_proof_root,
            rebate_nullifier: request.rebate_nullifier,
            issued_at_height: request.issued_at_height,
        };
        self.current_height = self.current_height.max(rebate.issued_at_height);
        self.low_fee_rebates.insert(rebate_id, rebate.clone());
        Ok(rebate)
    }

    pub fn quarantine_stale_oracle(
        &mut self,
        request: QuarantineStaleOracleRequest,
    ) -> PrivateL2PqConfidentialSyntheticPerpsVaultRuntimeResult<StaleOracleQuarantine> {
        require(
            self.stale_oracle_quarantines.len() < self.config.max_oracle_quarantines,
            "confidential synthetic perps stale oracle quarantine capacity exceeded",
        )?;
        self.require_vault(&request.vault_id)?;
        require_non_empty("oracle_committee_root", &request.oracle_committee_root)?;
        require_non_empty("stale_price_root", &request.stale_price_root)?;
        require_non_empty("replacement_price_root", &request.replacement_price_root)?;
        require_non_empty("evidence_root", &request.evidence_root)?;
        require_non_empty("watcher_commitment", &request.watcher_commitment)?;
        require_non_empty("quarantine_nullifier", &request.quarantine_nullifier)?;
        require(
            request.stale_after_height <= request.observed_at_height,
            "confidential synthetic perps stale oracle quarantine must observe stale height",
        )?;
        self.consume_nullifier(&request.quarantine_nullifier)?;
        self.counters.oracle_quarantine_counter =
            self.counters.oracle_quarantine_counter.saturating_add(1);
        let oracle_quarantine_id =
            stale_oracle_quarantine_id(&request, self.counters.oracle_quarantine_counter);
        let quarantine = StaleOracleQuarantine {
            oracle_quarantine_id: oracle_quarantine_id.clone(),
            vault_id: request.vault_id,
            status: request.status,
            oracle_committee_root: request.oracle_committee_root,
            stale_price_root: request.stale_price_root,
            replacement_price_root: request.replacement_price_root,
            evidence_root: request.evidence_root,
            watcher_commitment: request.watcher_commitment,
            quarantine_nullifier: request.quarantine_nullifier,
            observed_at_height: request.observed_at_height,
            stale_after_height: request.stale_after_height,
            cleared_at_height: request.cleared_at_height,
        };
        if quarantine.status == OracleQuarantineStatus::Quarantined {
            if let Some(vault) = self.synthetic_vaults.get_mut(&quarantine.vault_id) {
                vault.status = VaultStatus::Quarantined;
            }
        }
        self.current_height = self.current_height.max(quarantine.observed_at_height);
        self.stale_oracle_quarantines
            .insert(oracle_quarantine_id, quarantine.clone());
        Ok(quarantine)
    }

    pub fn allocate_redaction_budget(
        &mut self,
        request: AllocateRedactionBudgetRequest,
    ) -> PrivateL2PqConfidentialSyntheticPerpsVaultRuntimeResult<PrivacyRedactionBudget> {
        require(
            self.privacy_redaction_budgets.len() < self.config.max_redaction_budgets,
            "confidential synthetic perps privacy redaction budget capacity exceeded",
        )?;
        self.require_vault(&request.vault_id)?;
        require_non_empty("budget_commitment", &request.budget_commitment)?;
        require_non_empty("spent_commitment", &request.spent_commitment)?;
        require_non_empty("remaining_commitment", &request.remaining_commitment)?;
        require_non_empty("redaction_policy_root", &request.redaction_policy_root)?;
        require_non_empty("auditor_commitment", &request.auditor_commitment)?;
        require_non_empty("budget_nullifier", &request.budget_nullifier)?;
        require(
            request.closes_at_height > request.opened_at_height,
            "confidential synthetic perps redaction budget close height must follow open height",
        )?;
        self.consume_nullifier(&request.budget_nullifier)?;
        self.counters.redaction_budget_counter =
            self.counters.redaction_budget_counter.saturating_add(1);
        let redaction_budget_id =
            privacy_redaction_budget_id(&request, self.counters.redaction_budget_counter);
        let budget = PrivacyRedactionBudget {
            redaction_budget_id: redaction_budget_id.clone(),
            vault_id: request.vault_id,
            scope: request.scope,
            budget_commitment: request.budget_commitment,
            spent_commitment: request.spent_commitment,
            remaining_commitment: request.remaining_commitment,
            redaction_policy_root: request.redaction_policy_root,
            auditor_commitment: request.auditor_commitment,
            budget_nullifier: request.budget_nullifier,
            epoch: request.epoch,
            opened_at_height: request.opened_at_height,
            closes_at_height: request.closes_at_height,
        };
        self.current_height = self.current_height.max(budget.opened_at_height);
        self.privacy_redaction_budgets
            .insert(redaction_budget_id, budget.clone());
        Ok(budget)
    }

    pub fn roots(&self) -> Roots {
        let synthetic_vault_root = public_record_root(
            PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_VAULT_SCHEME,
            &self
                .synthetic_vaults
                .values()
                .map(SyntheticVault::public_record)
                .collect::<Vec<_>>(),
        );
        let collateral_note_root = public_record_root(
            PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_COLLATERAL_SCHEME,
            &self
                .collateral_notes
                .values()
                .map(CollateralNote::public_record)
                .collect::<Vec<_>>(),
        );
        let sealed_position_root = public_record_root(
            PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_POSITION_SCHEME,
            &self
                .sealed_positions
                .values()
                .map(SealedPerpsPosition::public_record)
                .collect::<Vec<_>>(),
        );
        let pq_risk_attestation_root = public_record_root(
            PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_RISK_SCHEME,
            &self
                .pq_risk_attestations
                .values()
                .map(PqRiskAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        let funding_receipt_root = public_record_root(
            PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_FUNDING_SCHEME,
            &self
                .funding_receipts
                .values()
                .map(FundingReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let liquidation_guard_band_root = public_record_root(
            PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_LIQUIDATION_SCHEME,
            &self
                .liquidation_guard_bands
                .values()
                .map(LiquidationGuardBand::public_record)
                .collect::<Vec<_>>(),
        );
        let low_fee_rebate_root = public_record_root(
            PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_REBATE_SCHEME,
            &self
                .low_fee_rebates
                .values()
                .map(LowFeeRebate::public_record)
                .collect::<Vec<_>>(),
        );
        let stale_oracle_quarantine_root = public_record_root(
            PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_ORACLE_SCHEME,
            &self
                .stale_oracle_quarantines
                .values()
                .map(StaleOracleQuarantine::public_record)
                .collect::<Vec<_>>(),
        );
        let redaction_budget_root = public_record_root(
            PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_REDACTION_SCHEME,
            &self
                .privacy_redaction_budgets
                .values()
                .map(PrivacyRedactionBudget::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SYNTHETIC-PERPS-VAULT-NULLIFIER-ROOT",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_root = state_root_from_record(&json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "current_height": self.current_height,
            "counters": self.counters.public_record(),
            "synthetic_vault_root": synthetic_vault_root,
            "collateral_note_root": collateral_note_root,
            "sealed_position_root": sealed_position_root,
            "pq_risk_attestation_root": pq_risk_attestation_root,
            "funding_receipt_root": funding_receipt_root,
            "liquidation_guard_band_root": liquidation_guard_band_root,
            "low_fee_rebate_root": low_fee_rebate_root,
            "stale_oracle_quarantine_root": stale_oracle_quarantine_root,
            "redaction_budget_root": redaction_budget_root,
            "nullifier_root": nullifier_root,
        }));
        Roots {
            synthetic_vault_root,
            collateral_note_root,
            sealed_position_root,
            pq_risk_attestation_root,
            funding_receipt_root,
            liquidation_guard_band_root,
            low_fee_rebate_root,
            stale_oracle_quarantine_root,
            redaction_budget_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "hash_suite": PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_HASH_SUITE,
            "pq_suite": PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_PQ_SUITE,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "synthetic_vault_ids": self.synthetic_vaults.keys().cloned().collect::<Vec<_>>(),
            "collateral_note_ids": self.collateral_notes.keys().cloned().collect::<Vec<_>>(),
            "sealed_position_ids": self.sealed_positions.keys().cloned().collect::<Vec<_>>(),
            "pq_risk_attestation_ids": self.pq_risk_attestations.keys().cloned().collect::<Vec<_>>(),
            "funding_receipt_ids": self.funding_receipts.keys().cloned().collect::<Vec<_>>(),
            "liquidation_guard_band_ids": self.liquidation_guard_bands.keys().cloned().collect::<Vec<_>>(),
            "low_fee_rebate_ids": self.low_fee_rebates.keys().cloned().collect::<Vec<_>>(),
            "stale_oracle_quarantine_ids": self.stale_oracle_quarantines.keys().cloned().collect::<Vec<_>>(),
            "privacy_redaction_budget_ids": self.privacy_redaction_budgets.keys().cloned().collect::<Vec<_>>(),
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

    fn require_vault(
        &self,
        vault_id: &str,
    ) -> PrivateL2PqConfidentialSyntheticPerpsVaultRuntimeResult<&SyntheticVault> {
        self.synthetic_vaults.get(vault_id).ok_or_else(|| {
            "confidential synthetic perps vault is unknown or unavailable".to_string()
        })
    }

    fn consume_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2PqConfidentialSyntheticPerpsVaultRuntimeResult<()> {
        let nullifier_hash = payload_id(
            "PRIVATE-L2-PQ-CONFIDENTIAL-SYNTHETIC-PERPS-VAULT-NULLIFIER-ID",
            &[HashPart::Str(nullifier)],
        );
        require(
            self.consumed_nullifiers.insert(nullifier_hash),
            "confidential synthetic perps nullifier replay detected",
        )?;
        self.counters.consumed_nullifier_counter =
            self.counters.consumed_nullifier_counter.saturating_add(1);
        Ok(())
    }
}

pub type Runtime = State;

pub fn devnet() -> State {
    let mut state = State::default();
    let vault = state
        .register_synthetic_vault(RegisterSyntheticVaultRequest {
            vault_kind: SyntheticVaultKind::XmrUsdPerp,
            asset_pair_root: fixture_root("devnet-xmr-usd-asset-pair"),
            synthetic_asset_root: fixture_root("devnet-synthetic-xmr-usd"),
            collateral_token_root: fixture_root("devnet-private-usdc-note-token"),
            vault_commitment: fixture_root("devnet-vault-commitment"),
            operator_commitment: fixture_root("devnet-operator-commitment"),
            oracle_committee_root: fixture_root("devnet-oracle-committee"),
            funding_model_root: fixture_root("devnet-funding-model"),
            risk_engine_root: fixture_root("devnet-pq-risk-engine"),
            privacy_policy_root: fixture_root("devnet-redaction-policy"),
            max_leverage_bps: 1_250,
            min_margin_bps: 700,
            maintenance_margin_bps: 450,
            liquidation_buffer_bps: 200,
            opened_at_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEVNET_HEIGHT,
            initial_vault_state_root: fixture_root("devnet-initial-vault-state"),
        })
        .expect("devnet confidential synthetic perps vault fixture must register");
    let collateral = state
        .submit_collateral_note(SubmitCollateralNoteRequest {
            vault_id: vault.vault_id.clone(),
            depositor_commitment: fixture_root("devnet-depositor-commitment"),
            collateral_note_root: fixture_root("devnet-collateral-note"),
            collateral_token_root: fixture_root("devnet-private-usdc-note-token"),
            encrypted_amount_root: fixture_root("devnet-encrypted-collateral-amount"),
            margin_bucket_root: fixture_root("devnet-margin-bucket"),
            note_nullifier: "devnet-collateral-note-nullifier".to_string(),
            privacy_set_size: 65_536,
            pq_security_bits: 256,
            fee_bps: 8,
            deposited_at_height: vault.opened_at_height + 2,
            expires_at_height: vault.opened_at_height + 720,
        })
        .expect("devnet confidential synthetic perps collateral fixture must submit");
    let attestation = state
        .publish_pq_risk_attestation(PublishPqRiskAttestationRequest {
            vault_id: vault.vault_id.clone(),
            collateral_note_id: collateral.collateral_note_id.clone(),
            verdict: RiskVerdict::Pass,
            risk_engine_root: fixture_root("devnet-pq-risk-engine"),
            pq_attestation_root: fixture_root("devnet-pq-risk-attestation"),
            oracle_snapshot_root: fixture_root("devnet-oracle-snapshot"),
            margin_check_root: fixture_root("devnet-margin-check"),
            liquidation_check_root: fixture_root("devnet-liquidation-check"),
            attester_commitment: fixture_root("devnet-risk-attester"),
            attestation_nullifier: "devnet-risk-attestation-nullifier".to_string(),
            privacy_set_size: 65_536,
            pq_security_bits: 256,
            attested_at_height: vault.opened_at_height + 3,
            valid_until_height: vault.opened_at_height + 36,
        })
        .expect("devnet confidential synthetic perps PQ risk fixture must attest");
    let position = state
        .open_sealed_position(OpenSealedPositionRequest {
            vault_id: vault.vault_id.clone(),
            collateral_note_id: collateral.collateral_note_id.clone(),
            risk_attestation_id: attestation.risk_attestation_id.clone(),
            side: PositionSide::Long,
            trader_commitment: fixture_root("devnet-trader-commitment"),
            sealed_position_root: fixture_root("devnet-sealed-position"),
            notional_commitment_root: fixture_root("devnet-notional-commitment"),
            entry_price_root: fixture_root("devnet-entry-price"),
            leverage_bps: 950,
            margin_requirement_bps: 760,
            liquidation_price_band_root: fixture_root("devnet-liquidation-price-band"),
            position_nullifier: "devnet-position-nullifier".to_string(),
            opened_at_height: vault.opened_at_height + 4,
            last_funding_epoch: 0,
        })
        .expect("devnet confidential synthetic perps position fixture must open");
    state
        .publish_funding_receipt(PublishFundingReceiptRequest {
            vault_id: vault.vault_id.clone(),
            position_id: position.position_id.clone(),
            funding_epoch: 1,
            direction: FundingDirection::ShortPaysLong,
            funding_rate_root: fixture_root("devnet-funding-rate"),
            payment_commitment_root: fixture_root("devnet-funding-payment"),
            funding_index_root_before: fixture_root("devnet-funding-index-before"),
            funding_index_root_after: fixture_root("devnet-funding-index-after"),
            settlement_tx_root: fixture_root("devnet-funding-settlement-tx"),
            receipt_nullifier: "devnet-funding-receipt-nullifier".to_string(),
            privacy_set_size: 65_536,
            pq_security_bits: 256,
            settled_at_height: vault.opened_at_height + 60,
        })
        .expect("devnet confidential synthetic perps funding fixture must publish");
    state
        .open_liquidation_guard_band(OpenLiquidationGuardBandRequest {
            vault_id: vault.vault_id.clone(),
            position_id: position.position_id.clone(),
            status: GuardBandStatus::Active,
            lower_band_root: fixture_root("devnet-guard-lower-band"),
            upper_band_root: fixture_root("devnet-guard-upper-band"),
            maintenance_margin_root: fixture_root("devnet-maintenance-margin"),
            liquidation_buffer_bps: 225,
            keeper_commitment: fixture_root("devnet-keeper-commitment"),
            guard_proof_root: fixture_root("devnet-guard-proof"),
            guard_nullifier: "devnet-guard-nullifier".to_string(),
            opened_at_height: vault.opened_at_height + 62,
            expires_at_height: vault.opened_at_height + 140,
        })
        .expect("devnet confidential synthetic perps guard band fixture must open");
    state
        .publish_low_fee_rebate(PublishLowFeeRebateRequest {
            vault_id: vault.vault_id.clone(),
            subject_id: position.position_id.clone(),
            sponsor_commitment: fixture_root("devnet-low-fee-sponsor"),
            eligible_fee_bps: 8,
            rebate_bps: 4,
            rebate_output_root: fixture_root("devnet-rebate-output"),
            rebate_proof_root: fixture_root("devnet-rebate-proof"),
            rebate_nullifier: "devnet-rebate-nullifier".to_string(),
            issued_at_height: vault.opened_at_height + 63,
        })
        .expect("devnet confidential synthetic perps rebate fixture must publish");
    state
        .allocate_redaction_budget(AllocateRedactionBudgetRequest {
            vault_id: vault.vault_id.clone(),
            scope: RedactionScope::Aggregate,
            budget_commitment: fixture_root("devnet-redaction-budget"),
            spent_commitment: fixture_root("devnet-redaction-spent"),
            remaining_commitment: fixture_root("devnet-redaction-remaining"),
            redaction_policy_root: fixture_root("devnet-redaction-policy"),
            auditor_commitment: fixture_root("devnet-auditor-commitment"),
            budget_nullifier: "devnet-redaction-budget-nullifier".to_string(),
            epoch: 1,
            opened_at_height: vault.opened_at_height,
            closes_at_height: vault.opened_at_height + 720,
        })
        .expect("devnet confidential synthetic perps redaction fixture must allocate");
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let vault = state
        .register_synthetic_vault(RegisterSyntheticVaultRequest {
            vault_kind: SyntheticVaultKind::BtcUsdPerp,
            asset_pair_root: fixture_root("demo-btc-usd-asset-pair"),
            synthetic_asset_root: fixture_root("demo-synthetic-btc-usd"),
            collateral_token_root: fixture_root("demo-private-dusd-note-token"),
            vault_commitment: fixture_root("demo-vault-commitment"),
            operator_commitment: fixture_root("demo-operator-commitment"),
            oracle_committee_root: fixture_root("demo-oracle-committee"),
            funding_model_root: fixture_root("demo-funding-model"),
            risk_engine_root: fixture_root("demo-pq-risk-engine"),
            privacy_policy_root: fixture_root("demo-redaction-policy"),
            max_leverage_bps: 1_100,
            min_margin_bps: 720,
            maintenance_margin_bps: 470,
            liquidation_buffer_bps: 210,
            opened_at_height: PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_DEVNET_HEIGHT
                + 100,
            initial_vault_state_root: fixture_root("demo-initial-vault-state"),
        })
        .expect("demo confidential synthetic perps vault fixture must register");
    state
        .quarantine_stale_oracle(QuarantineStaleOracleRequest {
            vault_id: vault.vault_id.clone(),
            status: OracleQuarantineStatus::Quarantined,
            oracle_committee_root: fixture_root("demo-oracle-committee"),
            stale_price_root: fixture_root("demo-stale-price"),
            replacement_price_root: fixture_root("demo-replacement-price"),
            evidence_root: fixture_root("demo-stale-oracle-evidence"),
            watcher_commitment: fixture_root("demo-oracle-watcher"),
            quarantine_nullifier: "demo-oracle-quarantine-nullifier".to_string(),
            observed_at_height: vault.opened_at_height + 24,
            stale_after_height: vault.opened_at_height + 18,
            cleared_at_height: None,
        })
        .expect("demo confidential synthetic perps stale oracle fixture must quarantine");
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn synthetic_vault_id(request: &RegisterSyntheticVaultRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SYNTHETIC-PERPS-VAULT-ID",
        &[
            HashPart::Str(request.vault_kind.as_str()),
            HashPart::Str(&request.asset_pair_root),
            HashPart::Str(&request.synthetic_asset_root),
            HashPart::Str(&request.vault_commitment),
            HashPart::Str(&request.operator_commitment),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn collateral_note_id(request: &SubmitCollateralNoteRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SYNTHETIC-PERPS-COLLATERAL-NOTE-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.depositor_commitment),
            HashPart::Str(&request.collateral_note_root),
            HashPart::Str(&request.note_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn pq_risk_attestation_id(request: &PublishPqRiskAttestationRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SYNTHETIC-PERPS-RISK-ATTESTATION-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.collateral_note_id),
            HashPart::Str(request.verdict.as_str()),
            HashPart::Str(&request.pq_attestation_root),
            HashPart::Str(&request.attestation_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn sealed_position_id(request: &OpenSealedPositionRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SYNTHETIC-PERPS-SEALED-POSITION-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.collateral_note_id),
            HashPart::Str(&request.risk_attestation_id),
            HashPart::Str(request.side.as_str()),
            HashPart::Str(&request.sealed_position_root),
            HashPart::Str(&request.position_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn funding_receipt_id(request: &PublishFundingReceiptRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SYNTHETIC-PERPS-FUNDING-RECEIPT-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.position_id),
            HashPart::Int(request.funding_epoch as i128),
            HashPart::Str(request.direction.as_str()),
            HashPart::Str(&request.receipt_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn liquidation_guard_band_id(
    request: &OpenLiquidationGuardBandRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SYNTHETIC-PERPS-LIQUIDATION-GUARD-BAND-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.position_id),
            HashPart::Str(request.status.as_str()),
            HashPart::Str(&request.guard_proof_root),
            HashPart::Str(&request.guard_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn low_fee_rebate_id(request: &PublishLowFeeRebateRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SYNTHETIC-PERPS-LOW-FEE-REBATE-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.rebate_output_root),
            HashPart::Str(&request.rebate_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn stale_oracle_quarantine_id(request: &QuarantineStaleOracleRequest, sequence: u64) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SYNTHETIC-PERPS-STALE-ORACLE-QUARANTINE-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Str(request.status.as_str()),
            HashPart::Str(&request.stale_price_root),
            HashPart::Str(&request.evidence_root),
            HashPart::Str(&request.quarantine_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn privacy_redaction_budget_id(
    request: &AllocateRedactionBudgetRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SYNTHETIC-PERPS-PRIVACY-REDACTION-BUDGET-ID",
        &[
            HashPart::Str(&request.vault_id),
            HashPart::Str(request.scope.as_str()),
            HashPart::Str(&request.budget_commitment),
            HashPart::Str(&request.redaction_policy_root),
            HashPart::Str(&request.budget_nullifier),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!(
            "{}:{}:{}",
            PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_PROTOCOL_VERSION,
            CHAIN_ID,
            domain
        ),
        parts,
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .map(|record| json!(root_from_record(domain, record)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SYNTHETIC-PERPS-VAULT-STATE-ROOT",
        record,
    )
}

pub fn fixture_root(label: &str) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-SYNTHETIC-PERPS-VAULT-FIXTURE-ROOT",
        &[HashPart::Str(label)],
    )
}

fn require(
    condition: bool,
    message: &str,
) -> PrivateL2PqConfidentialSyntheticPerpsVaultRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2PqConfidentialSyntheticPerpsVaultRuntimeResult<()> {
    require(
        !value.trim().is_empty(),
        &format!("confidential synthetic perps field {label} is required"),
    )
}

fn require_bps(
    label: &str,
    value: u64,
) -> PrivateL2PqConfidentialSyntheticPerpsVaultRuntimeResult<()> {
    require(
        value <= PRIVATE_L2_PQ_CONFIDENTIAL_SYNTHETIC_PERPS_VAULT_RUNTIME_MAX_BPS,
        &format!("confidential synthetic perps bps field {label} exceeds max bps"),
    )
}

fn require_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2PqConfidentialSyntheticPerpsVaultRuntimeResult<()> {
    require(
        privacy_set_size >= min_privacy_set_size,
        "confidential synthetic perps privacy set is below minimum",
    )?;
    require(
        pq_security_bits >= min_pq_security_bits,
        "confidential synthetic perps PQ security bits below minimum",
    )
}
