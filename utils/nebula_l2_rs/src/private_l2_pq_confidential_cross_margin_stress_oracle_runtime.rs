use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialCrossMarginStressOracleRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_STRESS_ORACLE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-cross-margin-stress-oracle-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-cross-margin-stress-oracle-v1";
pub const PQ_KEM_SUITE: &str = "ML-KEM-1024-sealed-stress-feed-v1";
pub const PORTFOLIO_BUCKET_SCHEME: &str = "shielded-cross-margin-portfolio-bucket-root-v1";
pub const STRESS_SCENARIO_SCHEME: &str = "confidential-stress-scenario-root-commitment-v1";
pub const LIQUIDATION_GUARD_SCHEME: &str = "confidential-liquidation-guard-hint-v1";
pub const LOW_FEE_SUBSCRIPTION_SCHEME: &str = "low-fee-stress-oracle-subscription-credit-v1";
pub const PRIVACY_REDACTION_BUDGET_SCHEME: &str =
    "privacy-redaction-and-query-budget-ledger-root-v1";
pub const STALE_ORACLE_QUARANTINE_SCHEME: &str = "stale-stress-scenario-quarantine-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_COMMITTEE_ID: &str = "cross-margin-stress-oracle-devnet-committee";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 4_080_000;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MARGIN_BUCKET_TTL_BLOCKS: u64 = 240;
pub const DEFAULT_ORACLE_ATTESTATION_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_SURFACE_TTL_BLOCKS: u64 = 240;
pub const DEFAULT_GUARD_HINT_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_SUBSCRIPTION_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_ORACLE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ORACLE_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MAX_PRICE_DEVIATION_BPS: u64 = 850;
pub const DEFAULT_MAX_VOL_DEVIATION_BPS: u64 = 1_200;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 750;
pub const DEFAULT_INITIAL_MARGIN_BPS: u64 = 1_500;
pub const DEFAULT_LIQUIDATION_BUFFER_BPS: u64 = 250;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 1_000_000;
pub const DEFAULT_MAX_REDACTION_UNITS_PER_QUERY: u64 = 10_000;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_BUCKETS: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_SURFACES: usize = 524_288;
pub const MAX_GUARD_HINTS: usize = 1_048_576;
pub const MAX_SUBSCRIPTIONS: usize = 2_097_152;
pub const MAX_REDACTION_BUDGETS: usize = 1_048_576;
pub const MAX_QUARANTINES: usize = 524_288;
pub const MAX_EVENTS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StressOracleMarketKind {
    PrivateUsdPerp,
    PrivateBtcPerp,
    PrivateXmrPerp,
    PrivateEthPerp,
    PrivateCommoditySwap,
    PrivateIndexSwap,
    PrivateRateFuture,
    PrivateVolatilityFuture,
}

impl StressOracleMarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateUsdPerp => "private_usd_perp",
            Self::PrivateBtcPerp => "private_btc_perp",
            Self::PrivateXmrPerp => "private_xmr_perp",
            Self::PrivateEthPerp => "private_eth_perp",
            Self::PrivateCommoditySwap => "private_commodity_swap",
            Self::PrivateIndexSwap => "private_index_swap",
            Self::PrivateRateFuture => "private_rate_future",
            Self::PrivateVolatilityFuture => "private_volatility_future",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginBucketStatus {
    Proposed,
    Active,
    RiskRaised,
    LiquidationWatch,
    Quarantined,
    Settled,
    Retired,
}

impl MarginBucketStatus {
    pub fn accepts_oracle_updates(self) -> bool {
        matches!(
            self,
            Self::Active | Self::RiskRaised | Self::LiquidationWatch
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::RiskRaised => "risk_raised",
            Self::LiquidationWatch => "liquidation_watch",
            Self::Quarantined => "quarantined",
            Self::Settled => "settled",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleAttestationStatus {
    Submitted,
    QuorumChecked,
    Applied,
    Superseded,
    Quarantined,
    Rejected,
    Expired,
}

impl OracleAttestationStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::QuorumChecked | Self::Applied | Self::Superseded
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::QuorumChecked => "quorum_checked",
            Self::Applied => "applied",
            Self::Superseded => "superseded",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceStatus {
    Draft,
    Active,
    Guarded,
    Quarantined,
    Expired,
    Retired,
}

impl SurfaceStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Guarded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardSeverity {
    Informational,
    RaiseInitialMargin,
    RaiseMaintenanceMargin,
    ClampOracle,
    PauseLiquidations,
    QuarantineFeed,
    EmergencyHalt,
}

impl GuardSeverity {
    pub fn from_pressure_bps(value: u64) -> Self {
        if value >= 9_500 {
            Self::EmergencyHalt
        } else if value >= 8_500 {
            Self::QuarantineFeed
        } else if value >= 7_500 {
            Self::PauseLiquidations
        } else if value >= 6_500 {
            Self::ClampOracle
        } else if value >= 5_000 {
            Self::RaiseMaintenanceMargin
        } else if value >= 3_000 {
            Self::RaiseInitialMargin
        } else {
            Self::Informational
        }
    }

    pub fn quarantines(self) -> bool {
        matches!(self, Self::QuarantineFeed | Self::EmergencyHalt)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::RaiseInitialMargin => "raise_initial_margin",
            Self::RaiseMaintenanceMargin => "raise_maintenance_margin",
            Self::ClampOracle => "clamp_oracle",
            Self::PauseLiquidations => "pause_liquidations",
            Self::QuarantineFeed => "quarantine_feed",
            Self::EmergencyHalt => "emergency_halt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Active,
    Sponsored,
    RebateQueued,
    Paused,
    Expired,
    Cancelled,
}

impl SubscriptionStatus {
    pub fn open(self) -> bool {
        matches!(self, Self::Active | Self::Sponsored | Self::RebateQueued)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStatus {
    Open,
    Capped,
    Exhausted,
    Revoked,
    Expired,
}

impl BudgetStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Open | Self::Capped)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    StaleOracle,
    LowQuorum,
    ExcessPriceDeviation,
    ExcessVolatilityDeviation,
    PrivacySetRegression,
    PqSignatureFailure,
    LiquidationGuardEscalation,
    OperatorChallenge,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleOracle => "stale_oracle",
            Self::LowQuorum => "low_quorum",
            Self::ExcessPriceDeviation => "excess_price_deviation",
            Self::ExcessVolatilityDeviation => "excess_volatility_deviation",
            Self::PrivacySetRegression => "privacy_set_regression",
            Self::PqSignatureFailure => "pq_signature_failure",
            Self::LiquidationGuardEscalation => "liquidation_guard_escalation",
            Self::OperatorChallenge => "operator_challenge",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub pq_kem_suite: String,
    pub l2_network: String,
    pub monero_network: String,
    pub committee_id: String,
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub margin_bucket_ttl_blocks: u64,
    pub oracle_attestation_ttl_blocks: u64,
    pub surface_ttl_blocks: u64,
    pub guard_hint_ttl_blocks: u64,
    pub subscription_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub min_oracle_quorum_bps: u64,
    pub strong_oracle_quorum_bps: u64,
    pub max_price_deviation_bps: u64,
    pub max_vol_deviation_bps: u64,
    pub maintenance_margin_bps: u64,
    pub initial_margin_bps: u64,
    pub liquidation_buffer_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub redaction_budget_units: u64,
    pub max_redaction_units_per_query: u64,
    pub devnet_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_STRESS_ORACLE_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            pq_kem_suite: PQ_KEM_SUITE.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            committee_id: DEVNET_COMMITTEE_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            margin_bucket_ttl_blocks: DEFAULT_MARGIN_BUCKET_TTL_BLOCKS,
            oracle_attestation_ttl_blocks: DEFAULT_ORACLE_ATTESTATION_TTL_BLOCKS,
            surface_ttl_blocks: DEFAULT_SURFACE_TTL_BLOCKS,
            guard_hint_ttl_blocks: DEFAULT_GUARD_HINT_TTL_BLOCKS,
            subscription_ttl_blocks: DEFAULT_SUBSCRIPTION_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_oracle_quorum_bps: DEFAULT_MIN_ORACLE_QUORUM_BPS,
            strong_oracle_quorum_bps: DEFAULT_STRONG_ORACLE_QUORUM_BPS,
            max_price_deviation_bps: DEFAULT_MAX_PRICE_DEVIATION_BPS,
            max_vol_deviation_bps: DEFAULT_MAX_VOL_DEVIATION_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            initial_margin_bps: DEFAULT_INITIAL_MARGIN_BPS,
            liquidation_buffer_bps: DEFAULT_LIQUIDATION_BUFFER_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            max_redaction_units_per_query: DEFAULT_MAX_REDACTION_UNITS_PER_QUERY,
            devnet_height: DEVNET_HEIGHT,
        }
    }

    pub fn validate(&self) -> PrivateL2PqConfidentialCrossMarginStressOracleRuntimeResult<()> {
        ensure(!self.chain_id.is_empty(), "chain id is empty")?;
        ensure(
            self.protocol_version
                == PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_STRESS_ORACLE_RUNTIME_PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        ensure(
            self.schema_version == SCHEMA_VERSION,
            "schema version mismatch",
        )?;
        ensure(self.hash_suite == HASH_SUITE, "hash suite mismatch")?;
        ensure(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security floor too low",
        )?;
        ensure(self.min_privacy_set_size >= 128, "privacy set size too low")?;
        ensure_bps("min_oracle_quorum_bps", self.min_oracle_quorum_bps)?;
        ensure_bps("strong_oracle_quorum_bps", self.strong_oracle_quorum_bps)?;
        ensure_bps("max_price_deviation_bps", self.max_price_deviation_bps)?;
        ensure_bps("max_vol_deviation_bps", self.max_vol_deviation_bps)?;
        ensure_bps("maintenance_margin_bps", self.maintenance_margin_bps)?;
        ensure_bps("initial_margin_bps", self.initial_margin_bps)?;
        ensure_bps("liquidation_buffer_bps", self.liquidation_buffer_bps)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("target_rebate_bps", self.target_rebate_bps)?;
        ensure(
            self.initial_margin_bps >= self.maintenance_margin_bps,
            "initial margin must cover maintenance margin",
        )?;
        ensure(
            self.max_redaction_units_per_query <= self.redaction_budget_units,
            "per query redaction cap exceeds budget",
        )
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub margin_buckets: u64,
    pub active_margin_buckets: u64,
    pub oracle_attestations: u64,
    pub applied_attestations: u64,
    pub volatility_surfaces: u64,
    pub active_surfaces: u64,
    pub liquidation_guard_hints: u64,
    pub feed_subscriptions: u64,
    pub active_feed_subscriptions: u64,
    pub privacy_redaction_budgets: u64,
    pub redaction_units_spent: u64,
    pub stale_oracle_quarantines: u64,
    pub public_events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "active_feed_subscriptions": self.active_feed_subscriptions,
            "active_margin_buckets": self.active_margin_buckets,
            "active_surfaces": self.active_surfaces,
            "applied_attestations": self.applied_attestations,
            "feed_subscriptions": self.feed_subscriptions,
            "liquidation_guard_hints": self.liquidation_guard_hints,
            "margin_buckets": self.margin_buckets,
            "oracle_attestations": self.oracle_attestations,
            "privacy_redaction_budgets": self.privacy_redaction_budgets,
            "public_events": self.public_events,
            "redaction_units_spent": self.redaction_units_spent,
            "stale_oracle_quarantines": self.stale_oracle_quarantines,
            "volatility_surfaces": self.volatility_surfaces,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub margin_bucket_root: String,
    pub oracle_attestation_root: String,
    pub volatility_surface_root: String,
    pub liquidation_guard_hint_root: String,
    pub feed_subscription_root: String,
    pub privacy_redaction_budget_root: String,
    pub stale_oracle_quarantine_root: String,
    pub active_feed_root: String,
    pub event_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            margin_bucket_root: empty_root("margin_bucket"),
            oracle_attestation_root: empty_root("oracle_attestation"),
            volatility_surface_root: empty_root("volatility_surface"),
            liquidation_guard_hint_root: empty_root("liquidation_guard_hint"),
            feed_subscription_root: empty_root("feed_subscription"),
            privacy_redaction_budget_root: empty_root("privacy_redaction_budget"),
            stale_oracle_quarantine_root: empty_root("stale_oracle_quarantine"),
            active_feed_root: empty_root("active_feed"),
            event_root: empty_root("event"),
            counters_root: record_root("counters", &json!({})),
            state_root: empty_root("state"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "active_feed_root": self.active_feed_root,
            "counters_root": self.counters_root,
            "event_root": self.event_root,
            "feed_subscription_root": self.feed_subscription_root,
            "liquidation_guard_hint_root": self.liquidation_guard_hint_root,
            "margin_bucket_root": self.margin_bucket_root,
            "oracle_attestation_root": self.oracle_attestation_root,
            "privacy_redaction_budget_root": self.privacy_redaction_budget_root,
            "stale_oracle_quarantine_root": self.stale_oracle_quarantine_root,
            "state_root": self.state_root,
            "volatility_surface_root": self.volatility_surface_root,
        })
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MarginBucketRecord {
    pub bucket_id: String,
    pub market_id: String,
    pub account_commitment: String,
    pub asset_kind: StressOracleMarketKind,
    pub collateral_note_root: String,
    pub debt_note_root: String,
    pub bucket_commitment_root: String,
    pub notional_bucket: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub privacy_set_size: u64,
    pub status: MarginBucketStatus,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
    pub bucket_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleAttestationRecord {
    pub attestation_id: String,
    pub bucket_id: String,
    pub feed_id: String,
    pub committee_id: String,
    pub signer_set_root: String,
    pub pq_signature_root: String,
    pub encrypted_payload_root: String,
    pub price_commitment_root: String,
    pub confidence_bps: u64,
    pub price_deviation_bps: u64,
    pub quorum_bps: u64,
    pub privacy_set_size: u64,
    pub status: OracleAttestationStatus,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub attestation_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VolatilitySurfaceRecord {
    pub surface_id: String,
    pub market_id: String,
    pub feed_id: String,
    pub tenor_grid_root: String,
    pub strike_grid_root: String,
    pub surface_commitment_root: String,
    pub implied_vol_floor_bps: u64,
    pub implied_vol_ceiling_bps: u64,
    pub confidence_bps: u64,
    pub deviation_bps: u64,
    pub status: SurfaceStatus,
    pub committed_at_height: u64,
    pub expires_at_height: u64,
    pub surface_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidationGuardHintRecord {
    pub hint_id: String,
    pub bucket_id: String,
    pub attestation_id: String,
    pub surface_id: String,
    pub redacted_liquidation_band_root: String,
    pub margin_pressure_bps: u64,
    pub recommended_initial_margin_bps: u64,
    pub recommended_maintenance_margin_bps: u64,
    pub severity: GuardSeverity,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub hint_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeedSubscriptionRecord {
    pub subscription_id: String,
    pub subscriber_commitment: String,
    pub feed_id: String,
    pub market_id: String,
    pub max_fee_bps: u64,
    pub sponsor_commitment: String,
    pub rebate_bps: u64,
    pub status: SubscriptionStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub subscription_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudgetRecord {
    pub budget_id: String,
    pub owner_commitment: String,
    pub scope_root: String,
    pub total_units: u64,
    pub spent_units: u64,
    pub remaining_units: u64,
    pub query_count: u64,
    pub status: BudgetStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub budget_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StaleOracleQuarantineRecord {
    pub quarantine_id: String,
    pub feed_id: String,
    pub subject_id: String,
    pub reason: QuarantineReason,
    pub last_good_root: String,
    pub challenged_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub quarantine_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventRecord {
    pub event_id: String,
    pub kind: String,
    pub subject_id: String,
    pub height: u64,
    pub root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterMarginBucketRequest {
    pub bucket_id: String,
    pub market_id: String,
    pub account_commitment: String,
    pub asset_kind: StressOracleMarketKind,
    pub collateral_note_root: String,
    pub debt_note_root: String,
    pub bucket_commitment_root: String,
    pub notional_bucket: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitOracleAttestationRequest {
    pub attestation_id: String,
    pub bucket_id: String,
    pub feed_id: String,
    pub committee_id: String,
    pub signer_set_root: String,
    pub pq_signature_root: String,
    pub encrypted_payload_root: String,
    pub price_commitment_root: String,
    pub confidence_bps: u64,
    pub price_deviation_bps: u64,
    pub quorum_bps: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitVolatilitySurfaceRequest {
    pub surface_id: String,
    pub market_id: String,
    pub feed_id: String,
    pub tenor_grid_root: String,
    pub strike_grid_root: String,
    pub surface_commitment_root: String,
    pub implied_vol_floor_bps: u64,
    pub implied_vol_ceiling_bps: u64,
    pub confidence_bps: u64,
    pub deviation_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishLiquidationGuardHintRequest {
    pub hint_id: String,
    pub bucket_id: String,
    pub attestation_id: String,
    pub surface_id: String,
    pub redacted_liquidation_band_root: String,
    pub margin_pressure_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenFeedSubscriptionRequest {
    pub subscription_id: String,
    pub subscriber_commitment: String,
    pub feed_id: String,
    pub market_id: String,
    pub max_fee_bps: u64,
    pub sponsor_commitment: String,
    pub rebate_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenPrivacyRedactionBudgetRequest {
    pub budget_id: String,
    pub owner_commitment: String,
    pub scope_root: String,
    pub total_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpendPrivacyRedactionBudgetRequest {
    pub budget_id: String,
    pub query_scope_root: String,
    pub units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineOracleRequest {
    pub quarantine_id: String,
    pub feed_id: String,
    pub subject_id: String,
    pub reason: QuarantineReason,
    pub last_good_root: String,
    pub challenged_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub epoch: u64,
    pub margin_buckets: BTreeMap<String, MarginBucketRecord>,
    pub oracle_attestations: BTreeMap<String, OracleAttestationRecord>,
    pub volatility_surfaces: BTreeMap<String, VolatilitySurfaceRecord>,
    pub liquidation_guard_hints: BTreeMap<String, LiquidationGuardHintRecord>,
    pub feed_subscriptions: BTreeMap<String, FeedSubscriptionRecord>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudgetRecord>,
    pub stale_oracle_quarantines: BTreeMap<String, StaleOracleQuarantineRecord>,
    pub active_feeds: BTreeSet<String>,
    pub events: VecDeque<EventRecord>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            height: config.devnet_height,
            epoch: config.devnet_height / config.epoch_blocks.max(1),
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            margin_buckets: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            volatility_surfaces: BTreeMap::new(),
            liquidation_guard_hints: BTreeMap::new(),
            feed_subscriptions: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            stale_oracle_quarantines: BTreeMap::new(),
            active_feeds: BTreeSet::new(),
            events: VecDeque::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn register_margin_bucket(
        &mut self,
        request: RegisterMarginBucketRequest,
    ) -> PrivateL2PqConfidentialCrossMarginStressOracleRuntimeResult<String> {
        self.config.validate()?;
        ensure(
            self.margin_buckets.len() < MAX_BUCKETS,
            "bucket capacity reached",
        )?;
        ensure(
            !self.margin_buckets.contains_key(&request.bucket_id),
            "bucket already exists",
        )?;
        ensure_id("bucket_id", &request.bucket_id)?;
        ensure_id("market_id", &request.market_id)?;
        ensure_root("account_commitment", &request.account_commitment)?;
        ensure_root("collateral_note_root", &request.collateral_note_root)?;
        ensure_root("debt_note_root", &request.debt_note_root)?;
        ensure_root("bucket_commitment_root", &request.bucket_commitment_root)?;
        ensure(
            request.notional_bucket > 0,
            "notional bucket must be positive",
        )?;
        ensure(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below configured floor",
        )?;
        let bucket_root = record_root(
            "margin_bucket",
            &json!({
                "account_commitment": request.account_commitment,
                "asset_kind": request.asset_kind.as_str(),
                "bucket_commitment_root": request.bucket_commitment_root,
                "bucket_id": request.bucket_id,
                "collateral_note_root": request.collateral_note_root,
                "debt_note_root": request.debt_note_root,
                "initial_margin_bps": self.config.initial_margin_bps,
                "maintenance_margin_bps": self.config.maintenance_margin_bps,
                "market_id": request.market_id,
                "notional_bucket": request.notional_bucket,
                "privacy_set_size": request.privacy_set_size,
            }),
        );
        let record = MarginBucketRecord {
            bucket_id: request.bucket_id.clone(),
            market_id: request.market_id,
            account_commitment: request.account_commitment,
            asset_kind: request.asset_kind,
            collateral_note_root: request.collateral_note_root,
            debt_note_root: request.debt_note_root,
            bucket_commitment_root: request.bucket_commitment_root,
            notional_bucket: request.notional_bucket,
            initial_margin_bps: self.config.initial_margin_bps,
            maintenance_margin_bps: self.config.maintenance_margin_bps,
            privacy_set_size: request.privacy_set_size,
            status: MarginBucketStatus::Active,
            opened_at_height: self.height,
            updated_at_height: self.height,
            bucket_root,
        };
        self.margin_buckets.insert(record.bucket_id.clone(), record);
        self.counters.margin_buckets = self.counters.margin_buckets.saturating_add(1);
        self.counters.active_margin_buckets = self.counters.active_margin_buckets.saturating_add(1);
        self.push_event("margin_bucket_registered", &request.bucket_id);
        self.refresh_roots();
        Ok(request.bucket_id)
    }

    pub fn submit_oracle_attestation(
        &mut self,
        request: SubmitOracleAttestationRequest,
    ) -> PrivateL2PqConfidentialCrossMarginStressOracleRuntimeResult<String> {
        self.config.validate()?;
        ensure(
            self.oracle_attestations.len() < MAX_ATTESTATIONS,
            "attestation capacity reached",
        )?;
        ensure(
            !self
                .oracle_attestations
                .contains_key(&request.attestation_id),
            "attestation already exists",
        )?;
        ensure(
            self.margin_buckets
                .get(&request.bucket_id)
                .map(|bucket| bucket.status.accepts_oracle_updates())
                .unwrap_or(false),
            "bucket cannot accept oracle update",
        )?;
        ensure_id("feed_id", &request.feed_id)?;
        ensure_root("signer_set_root", &request.signer_set_root)?;
        ensure_root("pq_signature_root", &request.pq_signature_root)?;
        ensure_root("encrypted_payload_root", &request.encrypted_payload_root)?;
        ensure_root("price_commitment_root", &request.price_commitment_root)?;
        ensure_bps("confidence_bps", request.confidence_bps)?;
        ensure_bps("price_deviation_bps", request.price_deviation_bps)?;
        ensure_bps("quorum_bps", request.quorum_bps)?;
        ensure(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "attestation privacy set below floor",
        )?;
        let mut status = OracleAttestationStatus::QuorumChecked;
        let mut quarantine_reason = None;
        if request.quorum_bps < self.config.min_oracle_quorum_bps {
            status = OracleAttestationStatus::Quarantined;
            quarantine_reason = Some(QuarantineReason::LowQuorum);
        } else if request.price_deviation_bps > self.config.max_price_deviation_bps {
            status = OracleAttestationStatus::Quarantined;
            quarantine_reason = Some(QuarantineReason::ExcessPriceDeviation);
        }
        let attestation_root = record_root(
            "oracle_attestation",
            &json!({
                "attestation_id": request.attestation_id,
                "bucket_id": request.bucket_id,
                "committee_id": request.committee_id,
                "confidence_bps": request.confidence_bps,
                "encrypted_payload_root": request.encrypted_payload_root,
                "feed_id": request.feed_id,
                "pq_signature_root": request.pq_signature_root,
                "price_commitment_root": request.price_commitment_root,
                "price_deviation_bps": request.price_deviation_bps,
                "privacy_set_size": request.privacy_set_size,
                "quorum_bps": request.quorum_bps,
                "signer_set_root": request.signer_set_root,
            }),
        );
        let record = OracleAttestationRecord {
            attestation_id: request.attestation_id.clone(),
            bucket_id: request.bucket_id.clone(),
            feed_id: request.feed_id.clone(),
            committee_id: request.committee_id,
            signer_set_root: request.signer_set_root,
            pq_signature_root: request.pq_signature_root,
            encrypted_payload_root: request.encrypted_payload_root,
            price_commitment_root: request.price_commitment_root,
            confidence_bps: request.confidence_bps,
            price_deviation_bps: request.price_deviation_bps,
            quorum_bps: request.quorum_bps,
            privacy_set_size: request.privacy_set_size,
            status,
            submitted_at_height: self.height,
            expires_at_height: self
                .height
                .saturating_add(self.config.oracle_attestation_ttl_blocks),
            attestation_root,
        };
        self.oracle_attestations
            .insert(record.attestation_id.clone(), record);
        self.active_feeds.insert(request.feed_id.clone());
        self.counters.oracle_attestations = self.counters.oracle_attestations.saturating_add(1);
        if status == OracleAttestationStatus::QuorumChecked {
            self.apply_attestation(&request.attestation_id)?;
        } else if let Some(reason) = quarantine_reason {
            self.open_quarantine(QuarantineOracleRequest {
                quarantine_id: deterministic_id(
                    "quarantine",
                    &[
                        HashPart::Str(&request.feed_id),
                        HashPart::Str(&request.attestation_id),
                        HashPart::Str(reason.as_str()),
                    ],
                ),
                feed_id: request.feed_id,
                subject_id: request.attestation_id.clone(),
                reason,
                last_good_root: empty_root("last_good_oracle"),
                challenged_root: request.attestation_id.clone(),
            })?;
        }
        self.push_event("oracle_attestation_submitted", &request.attestation_id);
        self.refresh_roots();
        Ok(request.attestation_id)
    }

    pub fn commit_volatility_surface(
        &mut self,
        request: CommitVolatilitySurfaceRequest,
    ) -> PrivateL2PqConfidentialCrossMarginStressOracleRuntimeResult<String> {
        self.config.validate()?;
        ensure(
            self.volatility_surfaces.len() < MAX_SURFACES,
            "surface capacity reached",
        )?;
        ensure(
            !self.volatility_surfaces.contains_key(&request.surface_id),
            "surface already exists",
        )?;
        ensure_root("tenor_grid_root", &request.tenor_grid_root)?;
        ensure_root("strike_grid_root", &request.strike_grid_root)?;
        ensure_root("surface_commitment_root", &request.surface_commitment_root)?;
        ensure_bps("implied_vol_floor_bps", request.implied_vol_floor_bps)?;
        ensure_bps("implied_vol_ceiling_bps", request.implied_vol_ceiling_bps)?;
        ensure_bps("confidence_bps", request.confidence_bps)?;
        ensure_bps("deviation_bps", request.deviation_bps)?;
        ensure(
            request.implied_vol_ceiling_bps >= request.implied_vol_floor_bps,
            "volatility ceiling below floor",
        )?;
        let status = if request.deviation_bps > self.config.max_vol_deviation_bps {
            SurfaceStatus::Quarantined
        } else if request.confidence_bps < self.config.min_oracle_quorum_bps {
            SurfaceStatus::Guarded
        } else {
            SurfaceStatus::Active
        };
        let surface_root = record_root(
            "volatility_surface",
            &json!({
                "confidence_bps": request.confidence_bps,
                "deviation_bps": request.deviation_bps,
                "feed_id": request.feed_id,
                "implied_vol_ceiling_bps": request.implied_vol_ceiling_bps,
                "implied_vol_floor_bps": request.implied_vol_floor_bps,
                "market_id": request.market_id,
                "strike_grid_root": request.strike_grid_root,
                "surface_commitment_root": request.surface_commitment_root,
                "surface_id": request.surface_id,
                "tenor_grid_root": request.tenor_grid_root,
            }),
        );
        let record = VolatilitySurfaceRecord {
            surface_id: request.surface_id.clone(),
            market_id: request.market_id,
            feed_id: request.feed_id.clone(),
            tenor_grid_root: request.tenor_grid_root,
            strike_grid_root: request.strike_grid_root,
            surface_commitment_root: request.surface_commitment_root,
            implied_vol_floor_bps: request.implied_vol_floor_bps,
            implied_vol_ceiling_bps: request.implied_vol_ceiling_bps,
            confidence_bps: request.confidence_bps,
            deviation_bps: request.deviation_bps,
            status,
            committed_at_height: self.height,
            expires_at_height: self.height.saturating_add(self.config.surface_ttl_blocks),
            surface_root,
        };
        self.volatility_surfaces
            .insert(record.surface_id.clone(), record);
        self.active_feeds.insert(request.feed_id.clone());
        self.counters.volatility_surfaces = self.counters.volatility_surfaces.saturating_add(1);
        if status.usable() {
            self.counters.active_surfaces = self.counters.active_surfaces.saturating_add(1);
        } else {
            self.open_quarantine(QuarantineOracleRequest {
                quarantine_id: deterministic_id(
                    "surface-quarantine",
                    &[
                        HashPart::Str(&request.feed_id),
                        HashPart::Str(&request.surface_id),
                    ],
                ),
                feed_id: request.feed_id,
                subject_id: request.surface_id.clone(),
                reason: QuarantineReason::ExcessVolatilityDeviation,
                last_good_root: empty_root("last_good_surface"),
                challenged_root: request.surface_id.clone(),
            })?;
        }
        self.push_event("volatility_surface_committed", &request.surface_id);
        self.refresh_roots();
        Ok(request.surface_id)
    }

    pub fn publish_liquidation_guard_hint(
        &mut self,
        request: PublishLiquidationGuardHintRequest,
    ) -> PrivateL2PqConfidentialCrossMarginStressOracleRuntimeResult<String> {
        ensure(
            self.liquidation_guard_hints.len() < MAX_GUARD_HINTS,
            "guard hint capacity reached",
        )?;
        ensure(
            self.margin_buckets.contains_key(&request.bucket_id),
            "unknown margin bucket",
        )?;
        ensure(
            self.oracle_attestations
                .contains_key(&request.attestation_id),
            "unknown attestation",
        )?;
        ensure(
            self.volatility_surfaces
                .get(&request.surface_id)
                .map(|surface| surface.status.usable())
                .unwrap_or(false),
            "surface is not usable",
        )?;
        ensure_root(
            "redacted_liquidation_band_root",
            &request.redacted_liquidation_band_root,
        )?;
        ensure_bps("margin_pressure_bps", request.margin_pressure_bps)?;
        let severity = GuardSeverity::from_pressure_bps(request.margin_pressure_bps);
        let recommended_maintenance_margin_bps = self
            .config
            .maintenance_margin_bps
            .saturating_add(request.margin_pressure_bps / 20)
            .min(MAX_BPS);
        let recommended_initial_margin_bps = self
            .config
            .initial_margin_bps
            .saturating_add(request.margin_pressure_bps / 10)
            .min(MAX_BPS);
        let hint_root = record_root(
            "liquidation_guard_hint",
            &json!({
                "attestation_id": request.attestation_id,
                "bucket_id": request.bucket_id,
                "hint_id": request.hint_id,
                "margin_pressure_bps": request.margin_pressure_bps,
                "redacted_liquidation_band_root": request.redacted_liquidation_band_root,
                "severity": severity.as_str(),
                "surface_id": request.surface_id,
            }),
        );
        let record = LiquidationGuardHintRecord {
            hint_id: request.hint_id.clone(),
            bucket_id: request.bucket_id.clone(),
            attestation_id: request.attestation_id.clone(),
            surface_id: request.surface_id.clone(),
            redacted_liquidation_band_root: request.redacted_liquidation_band_root,
            margin_pressure_bps: request.margin_pressure_bps,
            recommended_initial_margin_bps,
            recommended_maintenance_margin_bps,
            severity,
            opened_at_height: self.height,
            expires_at_height: self
                .height
                .saturating_add(self.config.guard_hint_ttl_blocks),
            hint_root,
        };
        self.liquidation_guard_hints
            .insert(record.hint_id.clone(), record);
        if let Some(bucket) = self.margin_buckets.get_mut(&request.bucket_id) {
            bucket.status = if severity.quarantines() {
                MarginBucketStatus::Quarantined
            } else {
                MarginBucketStatus::LiquidationWatch
            };
            bucket.initial_margin_bps = recommended_initial_margin_bps;
            bucket.maintenance_margin_bps = recommended_maintenance_margin_bps;
            bucket.updated_at_height = self.height;
        }
        self.counters.liquidation_guard_hints =
            self.counters.liquidation_guard_hints.saturating_add(1);
        if severity.quarantines() {
            self.open_quarantine(QuarantineOracleRequest {
                quarantine_id: deterministic_id(
                    "guard-quarantine",
                    &[
                        HashPart::Str(&request.bucket_id),
                        HashPart::Str(&request.hint_id),
                    ],
                ),
                feed_id: request.surface_id,
                subject_id: request.bucket_id,
                reason: QuarantineReason::LiquidationGuardEscalation,
                last_good_root: request.attestation_id,
                challenged_root: request.hint_id.clone(),
            })?;
        }
        self.push_event("liquidation_guard_hint_published", &request.hint_id);
        self.refresh_roots();
        Ok(request.hint_id)
    }

    pub fn open_feed_subscription(
        &mut self,
        request: OpenFeedSubscriptionRequest,
    ) -> PrivateL2PqConfidentialCrossMarginStressOracleRuntimeResult<String> {
        ensure(
            self.feed_subscriptions.len() < MAX_SUBSCRIPTIONS,
            "subscription capacity reached",
        )?;
        ensure_bps("max_fee_bps", request.max_fee_bps)?;
        ensure_bps("rebate_bps", request.rebate_bps)?;
        ensure(
            request.max_fee_bps <= self.config.max_user_fee_bps,
            "subscription fee exceeds cap",
        )?;
        ensure(
            request.rebate_bps <= self.config.target_rebate_bps,
            "rebate exceeds target",
        )?;
        ensure_root("subscriber_commitment", &request.subscriber_commitment)?;
        ensure_root("sponsor_commitment", &request.sponsor_commitment)?;
        let status = if request.rebate_bps > 0 {
            SubscriptionStatus::Sponsored
        } else {
            SubscriptionStatus::Active
        };
        let subscription_root = record_root(
            "feed_subscription",
            &json!({
                "feed_id": request.feed_id,
                "market_id": request.market_id,
                "max_fee_bps": request.max_fee_bps,
                "rebate_bps": request.rebate_bps,
                "sponsor_commitment": request.sponsor_commitment,
                "subscriber_commitment": request.subscriber_commitment,
                "subscription_id": request.subscription_id,
            }),
        );
        let record = FeedSubscriptionRecord {
            subscription_id: request.subscription_id.clone(),
            subscriber_commitment: request.subscriber_commitment,
            feed_id: request.feed_id.clone(),
            market_id: request.market_id,
            max_fee_bps: request.max_fee_bps,
            sponsor_commitment: request.sponsor_commitment,
            rebate_bps: request.rebate_bps,
            status,
            opened_at_height: self.height,
            expires_at_height: self
                .height
                .saturating_add(self.config.subscription_ttl_blocks),
            subscription_root,
        };
        self.feed_subscriptions
            .insert(record.subscription_id.clone(), record);
        self.active_feeds.insert(request.feed_id);
        self.counters.feed_subscriptions = self.counters.feed_subscriptions.saturating_add(1);
        self.counters.active_feed_subscriptions =
            self.counters.active_feed_subscriptions.saturating_add(1);
        self.push_event("feed_subscription_opened", &request.subscription_id);
        self.refresh_roots();
        Ok(request.subscription_id)
    }

    pub fn open_privacy_redaction_budget(
        &mut self,
        request: OpenPrivacyRedactionBudgetRequest,
    ) -> PrivateL2PqConfidentialCrossMarginStressOracleRuntimeResult<String> {
        ensure(
            self.privacy_redaction_budgets.len() < MAX_REDACTION_BUDGETS,
            "redaction budget capacity reached",
        )?;
        ensure_root("owner_commitment", &request.owner_commitment)?;
        ensure_root("scope_root", &request.scope_root)?;
        ensure(request.total_units > 0, "redaction budget must be positive")?;
        ensure(
            request.total_units <= self.config.redaction_budget_units,
            "redaction budget exceeds configured maximum",
        )?;
        let budget_root = record_root(
            "privacy_redaction_budget",
            &json!({
                "budget_id": request.budget_id,
                "owner_commitment": request.owner_commitment,
                "scope_root": request.scope_root,
                "total_units": request.total_units,
            }),
        );
        let record = PrivacyRedactionBudgetRecord {
            budget_id: request.budget_id.clone(),
            owner_commitment: request.owner_commitment,
            scope_root: request.scope_root,
            total_units: request.total_units,
            spent_units: 0,
            remaining_units: request.total_units,
            query_count: 0,
            status: BudgetStatus::Open,
            opened_at_height: self.height,
            expires_at_height: self
                .height
                .saturating_add(self.config.subscription_ttl_blocks),
            budget_root,
        };
        self.privacy_redaction_budgets
            .insert(record.budget_id.clone(), record);
        self.counters.privacy_redaction_budgets =
            self.counters.privacy_redaction_budgets.saturating_add(1);
        self.push_event("privacy_redaction_budget_opened", &request.budget_id);
        self.refresh_roots();
        Ok(request.budget_id)
    }

    pub fn spend_privacy_redaction_budget(
        &mut self,
        request: SpendPrivacyRedactionBudgetRequest,
    ) -> PrivateL2PqConfidentialCrossMarginStressOracleRuntimeResult<()> {
        ensure_root("query_scope_root", &request.query_scope_root)?;
        ensure(request.units > 0, "redaction spend must be positive")?;
        ensure(
            request.units <= self.config.max_redaction_units_per_query,
            "redaction spend exceeds per query cap",
        )?;
        let budget = self
            .privacy_redaction_budgets
            .get_mut(&request.budget_id)
            .ok_or_else(|| "unknown redaction budget".to_string())?;
        ensure(
            budget.status.spendable(),
            "redaction budget is not spendable",
        )?;
        ensure(
            budget.remaining_units >= request.units,
            "insufficient redaction budget",
        )?;
        budget.spent_units = budget.spent_units.saturating_add(request.units);
        budget.remaining_units = budget.remaining_units.saturating_sub(request.units);
        budget.query_count = budget.query_count.saturating_add(1);
        budget.status = if budget.remaining_units == 0 {
            BudgetStatus::Exhausted
        } else if request.units == self.config.max_redaction_units_per_query {
            BudgetStatus::Capped
        } else {
            BudgetStatus::Open
        };
        budget.budget_root = record_root("privacy_redaction_budget_spent", &json!(budget));
        self.counters.redaction_units_spent = self
            .counters
            .redaction_units_spent
            .saturating_add(request.units);
        self.push_event("privacy_redaction_budget_spent", &request.budget_id);
        self.refresh_roots();
        Ok(())
    }

    pub fn quarantine_stale_oracles(
        &mut self,
    ) -> PrivateL2PqConfidentialCrossMarginStressOracleRuntimeResult<usize> {
        let stale = self
            .oracle_attestations
            .values()
            .filter(|record| record.status.live() && record.expires_at_height <= self.height)
            .map(|record| {
                (
                    record.attestation_id.clone(),
                    record.feed_id.clone(),
                    record.attestation_root.clone(),
                )
            })
            .collect::<Vec<_>>();
        for (attestation_id, feed_id, root) in &stale {
            if let Some(record) = self.oracle_attestations.get_mut(attestation_id) {
                record.status = OracleAttestationStatus::Expired;
            }
            self.open_quarantine(QuarantineOracleRequest {
                quarantine_id: deterministic_id(
                    "stale-quarantine",
                    &[HashPart::Str(feed_id), HashPart::Str(attestation_id)],
                ),
                feed_id: feed_id.clone(),
                subject_id: attestation_id.clone(),
                reason: QuarantineReason::StaleOracle,
                last_good_root: empty_root("last_good_before_stale"),
                challenged_root: root.clone(),
            })?;
        }
        self.refresh_roots();
        Ok(stale.len())
    }

    pub fn advance_height(&mut self, blocks: u64) {
        self.height = self.height.saturating_add(blocks);
        self.epoch = self.height / self.config.epoch_blocks.max(1);
        self.push_event("height_advanced", &self.height.to_string());
        self.refresh_roots();
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "config": {
                "hash_suite": self.config.hash_suite,
                "liquidation_guard_scheme": LIQUIDATION_GUARD_SCHEME,
                "low_fee_subscription_scheme": LOW_FEE_SUBSCRIPTION_SCHEME,
                "PORTFOLIO_BUCKET_SCHEME": PORTFOLIO_BUCKET_SCHEME,
                "max_user_fee_bps": self.config.max_user_fee_bps,
                "min_oracle_quorum_bps": self.config.min_oracle_quorum_bps,
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "pq_attestation_suite": self.config.pq_attestation_suite,
                "pq_kem_suite": self.config.pq_kem_suite,
                "privacy_redaction_budget_scheme": PRIVACY_REDACTION_BUDGET_SCHEME,
                "stale_oracle_quarantine_scheme": STALE_ORACLE_QUARANTINE_SCHEME,
                "STRESS_SCENARIO_SCHEME": STRESS_SCENARIO_SCHEME,
            },
            "counters": self.counters.public_record(),
            "epoch": self.epoch,
            "height": self.height,
            "limits": {
                "max_attestations": MAX_ATTESTATIONS,
                "max_buckets": MAX_BUCKETS,
                "max_guard_hints": MAX_GUARD_HINTS,
                "max_quarantines": MAX_QUARANTINES,
                "max_redaction_budgets": MAX_REDACTION_BUDGETS,
                "max_subscriptions": MAX_SUBSCRIPTIONS,
                "max_surfaces": MAX_SURFACES,
            },
            "protocol_version":
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_STRESS_ORACLE_RUNTIME_PROTOCOL_VERSION,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn refresh_roots(&mut self) {
        self.counters_root_refresh();
        self.roots.margin_bucket_root = map_root("margin_bucket", &self.margin_buckets);
        self.roots.oracle_attestation_root =
            map_root("oracle_attestation", &self.oracle_attestations);
        self.roots.volatility_surface_root =
            map_root("volatility_surface", &self.volatility_surfaces);
        self.roots.liquidation_guard_hint_root =
            map_root("liquidation_guard_hint", &self.liquidation_guard_hints);
        self.roots.feed_subscription_root = map_root("feed_subscription", &self.feed_subscriptions);
        self.roots.privacy_redaction_budget_root =
            map_root("privacy_redaction_budget", &self.privacy_redaction_budgets);
        self.roots.stale_oracle_quarantine_root =
            map_root("stale_oracle_quarantine", &self.stale_oracle_quarantines);
        self.roots.active_feed_root = set_root("active_feed", &self.active_feeds);
        self.roots.event_root = deque_root("event", &self.events);
        self.roots.state_root = record_root(
            "state",
            &json!({
                "active_feed_root": self.roots.active_feed_root,
                "chain_id": self.config.chain_id,
                "counters_root": self.roots.counters_root,
                "event_root": self.roots.event_root,
                "feed_subscription_root": self.roots.feed_subscription_root,
                "height": self.height,
                "liquidation_guard_hint_root": self.roots.liquidation_guard_hint_root,
                "margin_bucket_root": self.roots.margin_bucket_root,
                "oracle_attestation_root": self.roots.oracle_attestation_root,
                "privacy_redaction_budget_root": self.roots.privacy_redaction_budget_root,
                "protocol_version":
                    PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_MARGIN_STRESS_ORACLE_RUNTIME_PROTOCOL_VERSION,
                "stale_oracle_quarantine_root": self.roots.stale_oracle_quarantine_root,
                "volatility_surface_root": self.roots.volatility_surface_root,
            }),
        );
    }

    fn counters_root_refresh(&mut self) {
        self.roots.counters_root = record_root("counters", &self.counters.public_record());
    }

    fn apply_attestation(
        &mut self,
        attestation_id: &str,
    ) -> PrivateL2PqConfidentialCrossMarginStressOracleRuntimeResult<()> {
        let (bucket_id, confidence_bps, price_deviation_bps) = {
            let attestation = self
                .oracle_attestations
                .get_mut(attestation_id)
                .ok_or_else(|| "unknown attestation".to_string())?;
            attestation.status = OracleAttestationStatus::Applied;
            (
                attestation.bucket_id.clone(),
                attestation.confidence_bps,
                attestation.price_deviation_bps,
            )
        };
        if let Some(bucket) = self.margin_buckets.get_mut(&bucket_id) {
            if confidence_bps >= self.config.strong_oracle_quorum_bps
                && price_deviation_bps <= self.config.max_price_deviation_bps / 2
            {
                bucket.status = MarginBucketStatus::Active;
            } else {
                bucket.status = MarginBucketStatus::RiskRaised;
            }
            bucket.updated_at_height = self.height;
        }
        self.counters.applied_attestations = self.counters.applied_attestations.saturating_add(1);
        Ok(())
    }

    fn open_quarantine(
        &mut self,
        request: QuarantineOracleRequest,
    ) -> PrivateL2PqConfidentialCrossMarginStressOracleRuntimeResult<String> {
        ensure(
            self.stale_oracle_quarantines.len() < MAX_QUARANTINES,
            "quarantine capacity reached",
        )?;
        if self
            .stale_oracle_quarantines
            .contains_key(&request.quarantine_id)
        {
            return Ok(request.quarantine_id);
        }
        let quarantine_root = record_root(
            "stale_oracle_quarantine",
            &json!({
                "challenged_root": request.challenged_root,
                "feed_id": request.feed_id,
                "last_good_root": request.last_good_root,
                "quarantine_id": request.quarantine_id,
                "reason": request.reason.as_str(),
                "subject_id": request.subject_id,
            }),
        );
        let record = StaleOracleQuarantineRecord {
            quarantine_id: request.quarantine_id.clone(),
            feed_id: request.feed_id.clone(),
            subject_id: request.subject_id,
            reason: request.reason,
            last_good_root: request.last_good_root,
            challenged_root: request.challenged_root,
            opened_at_height: self.height,
            expires_at_height: self
                .height
                .saturating_add(self.config.quarantine_ttl_blocks),
            quarantine_root,
        };
        self.active_feeds.remove(&request.feed_id);
        self.stale_oracle_quarantines
            .insert(record.quarantine_id.clone(), record);
        self.counters.stale_oracle_quarantines =
            self.counters.stale_oracle_quarantines.saturating_add(1);
        self.push_event("stale_oracle_quarantine_opened", &request.quarantine_id);
        Ok(request.quarantine_id)
    }

    fn push_event(&mut self, kind: &str, subject_id: &str) {
        if self.events.len() >= MAX_EVENTS {
            let _ = self.events.pop_front();
        }
        let root = deterministic_id(
            "event-root",
            &[
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::U64(self.height),
                HashPart::U64(self.counters.public_events.saturating_add(1)),
            ],
        );
        let event_id = deterministic_id(
            "event",
            &[
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::Str(&root),
            ],
        );
        self.events.push_back(EventRecord {
            event_id,
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            height: self.height,
            root,
        });
        self.counters.public_events = self.counters.public_events.saturating_add(1);
    }
}

pub fn devnet() -> State {
    State::default()
}

pub fn demo() -> State {
    let mut state = devnet();
    let _ = state.register_margin_bucket(RegisterMarginBucketRequest {
        bucket_id: "xmr-usd-private-margin-bucket-0".to_string(),
        market_id: "xmr-usd-private-perp".to_string(),
        account_commitment: deterministic_id("account", &[HashPart::Str("demo-account")]),
        asset_kind: StressOracleMarketKind::PrivateXmrPerp,
        collateral_note_root: deterministic_id("collateral", &[HashPart::Str("demo")]),
        debt_note_root: deterministic_id("debt", &[HashPart::Str("demo")]),
        bucket_commitment_root: deterministic_id("bucket", &[HashPart::Str("demo")]),
        notional_bucket: 2_048,
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE.saturating_mul(2),
    });
    let _ = state.open_feed_subscription(OpenFeedSubscriptionRequest {
        subscription_id: "low-fee-margin-feed-subscription-0".to_string(),
        subscriber_commitment: deterministic_id("subscriber", &[HashPart::Str("demo")]),
        feed_id: "xmr-usd-margin-oracle-feed".to_string(),
        market_id: "xmr-usd-private-perp".to_string(),
        max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
        sponsor_commitment: deterministic_id("sponsor", &[HashPart::Str("demo")]),
        rebate_bps: DEFAULT_TARGET_REBATE_BPS,
    });
    let _ = state.submit_oracle_attestation(SubmitOracleAttestationRequest {
        attestation_id: "pq-margin-oracle-attestation-0".to_string(),
        bucket_id: "xmr-usd-private-margin-bucket-0".to_string(),
        feed_id: "xmr-usd-margin-oracle-feed".to_string(),
        committee_id: DEVNET_COMMITTEE_ID.to_string(),
        signer_set_root: deterministic_id("signers", &[HashPart::Str("demo")]),
        pq_signature_root: deterministic_id("pq-sig", &[HashPart::Str("demo")]),
        encrypted_payload_root: deterministic_id("sealed-payload", &[HashPart::Str("demo")]),
        price_commitment_root: deterministic_id("price", &[HashPart::Str("demo")]),
        confidence_bps: 8_600,
        price_deviation_bps: 210,
        quorum_bps: 8_200,
        privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE.saturating_mul(2),
    });
    let _ = state.commit_volatility_surface(CommitVolatilitySurfaceRequest {
        surface_id: "xmr-usd-private-vol-surface-0".to_string(),
        market_id: "xmr-usd-private-perp".to_string(),
        feed_id: "xmr-usd-margin-oracle-feed".to_string(),
        tenor_grid_root: deterministic_id("tenor-grid", &[HashPart::Str("demo")]),
        strike_grid_root: deterministic_id("strike-grid", &[HashPart::Str("demo")]),
        surface_commitment_root: deterministic_id("surface", &[HashPart::Str("demo")]),
        implied_vol_floor_bps: 3_800,
        implied_vol_ceiling_bps: 8_900,
        confidence_bps: 8_400,
        deviation_bps: 360,
    });
    let _ = state.publish_liquidation_guard_hint(PublishLiquidationGuardHintRequest {
        hint_id: "liquidation-guard-hint-0".to_string(),
        bucket_id: "xmr-usd-private-margin-bucket-0".to_string(),
        attestation_id: "pq-margin-oracle-attestation-0".to_string(),
        surface_id: "xmr-usd-private-vol-surface-0".to_string(),
        redacted_liquidation_band_root: deterministic_id(
            "liquidation-band",
            &[HashPart::Str("demo")],
        ),
        margin_pressure_bps: 4_200,
    });
    let _ = state.open_privacy_redaction_budget(OpenPrivacyRedactionBudgetRequest {
        budget_id: "redaction-budget-0".to_string(),
        owner_commitment: deterministic_id("redaction-owner", &[HashPart::Str("demo")]),
        scope_root: deterministic_id("redaction-scope", &[HashPart::Str("demo")]),
        total_units: 100_000,
    });
    let _ = state.spend_privacy_redaction_budget(SpendPrivacyRedactionBudgetRequest {
        budget_id: "redaction-budget-0".to_string(),
        query_scope_root: deterministic_id("query-scope", &[HashPart::Str("demo")]),
        units: 4_096,
    });
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn ensure(
    condition: bool,
    message: &str,
) -> PrivateL2PqConfidentialCrossMarginStressOracleRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn ensure_id(
    field: &str,
    value: &str,
) -> PrivateL2PqConfidentialCrossMarginStressOracleRuntimeResult<()> {
    ensure(!value.trim().is_empty(), &format!("{field} is empty"))
}

fn ensure_root(
    field: &str,
    value: &str,
) -> PrivateL2PqConfidentialCrossMarginStressOracleRuntimeResult<()> {
    ensure_id(field, value)?;
    ensure(value.len() <= 256, &format!("{field} root is too long"))?;
    ensure(value.len() >= 16, &format!("{field} must look like a root"))
}

fn ensure_bps(
    field: &str,
    value: u64,
) -> PrivateL2PqConfidentialCrossMarginStressOracleRuntimeResult<()> {
    ensure(
        value <= MAX_BPS,
        &format!("{field} exceeds basis point maximum"),
    )
}

fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("private_l2_pq_confidential_cross_margin_stress_oracle_runtime/{domain}"),
        parts,
        32,
    )
}

fn record_root(domain: &str, value: &Value) -> String {
    deterministic_id(domain, &[HashPart::Str(CHAIN_ID), HashPart::Json(value)])
}

fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("private_l2_pq_confidential_cross_margin_stress_oracle_runtime/{domain}"),
        &[],
    )
}

fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let records = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private_l2_pq_confidential_cross_margin_stress_oracle_runtime/{domain}"),
        &records,
    )
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private_l2_pq_confidential_cross_margin_stress_oracle_runtime/{domain}"),
        &records,
    )
}

fn deque_root<T: Serialize>(domain: &str, values: &VecDeque<T>) -> String {
    let records = values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            json!({
                "index": index,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private_l2_pq_confidential_cross_margin_stress_oracle_runtime/{domain}"),
        &records,
    )
}
