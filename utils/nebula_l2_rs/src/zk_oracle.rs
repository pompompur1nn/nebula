use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub const PROTOCOL_VERSION: &str = "nebula-l2-zk-oracle-v1";
pub const ZK_ORACLE_PROTOCOL_VERSION: &str = PROTOCOL_VERSION;
pub const ZK_ORACLE_SECURITY_MODEL: &str = "deterministic-devnet-transcript-model-not-real-crypto";
pub const ZK_ORACLE_COMMITMENT_SCHEME: &str = "shake256-domain-separated-devnet-commitment";
pub const ZK_ORACLE_TRANSCRIPT_SCHEME: &str = "shake256-canonical-json-pq-transcript";
pub const ZK_ORACLE_PRICE_PROOF_SYSTEM: &str = "devnet-zk-weighted-median-price-v1";
pub const ZK_ORACLE_RESERVE_PROOF_SYSTEM: &str = "devnet-zk-reserve-solvency-v1";
pub const ZK_ORACLE_RISK_PROOF_SYSTEM: &str = "devnet-zk-defi-risk-attestation-v1";
pub const ZK_ORACLE_PRIVATE_UPDATE_SYSTEM: &str = "devnet-private-oracle-update-v1";
pub const ZK_ORACLE_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const ZK_ORACLE_PQ_RECOVERY_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const ZK_ORACLE_PQ_HYBRID_SCHEME: &str = "ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const ZK_ORACLE_DEVNET_HEIGHT: u64 = 128;
pub const ZK_ORACLE_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const ZK_ORACLE_MAX_BPS: u64 = 10_000;
pub const ZK_ORACLE_DEFAULT_DECIMALS: u8 = 12;
pub const ZK_ORACLE_DEFAULT_MIN_SOURCES: u64 = 2;
pub const ZK_ORACLE_DEFAULT_HEARTBEAT_BLOCKS: u64 = 12;
pub const ZK_ORACLE_DEFAULT_TWAP_WINDOW_BLOCKS: u64 = 96;
pub const ZK_ORACLE_DEFAULT_MAX_DEVIATION_BPS: u64 = 750;
pub const ZK_ORACLE_DEFAULT_RESERVE_REFRESH_BLOCKS: u64 = 24;
pub const ZK_ORACLE_DEFAULT_RESERVE_GRACE_BLOCKS: u64 = 8;
pub const ZK_ORACLE_DEFAULT_MIN_SOLVENCY_BPS: u64 = 10_500;
pub const ZK_ORACLE_DEFAULT_MIN_COVERAGE_BPS: u64 = 12_000;
pub const ZK_ORACLE_DEFAULT_TRANSCRIPT_TTL_BLOCKS: u64 = 144;
pub const ZK_ORACLE_DEFAULT_UPDATE_TTL_BLOCKS: u64 = 24;
pub const ZK_ORACLE_DEFAULT_RISK_TTL_BLOCKS: u64 = 36;
pub const ZK_ORACLE_DEFAULT_CIRCUIT_COOLDOWN_BLOCKS: u64 = 30;
pub const ZK_ORACLE_DEFAULT_LATENCY_LANE_MS: u64 = 1_500;
pub const ZK_ORACLE_DEFAULT_SLOW_LANE_MS: u64 = 10_000;
pub const ZK_ORACLE_DEFAULT_LOW_FEE_UNITS: u64 = 2;
pub const ZK_ORACLE_DEFAULT_RESERVE_FEE_UNITS: u64 = 4;
pub const ZK_ORACLE_DEFAULT_RISK_FEE_UNITS: u64 = 3;
pub const ZK_ORACLE_MAX_OBSERVATIONS_PER_FEED: usize = 512;
pub const ZK_ORACLE_MAX_PRIVATE_UPDATES: usize = 1_024;
pub const ZK_ORACLE_MAX_TRANSCRIPTS: usize = 2_048;
pub const ZK_ORACLE_MAX_AUDIT_EVENTS: usize = 512;
pub const ZK_ORACLE_DEVNET_WXMR_ASSET_ID: &str = "wxmr-devnet";
pub const ZK_ORACLE_DEVNET_USDD_ASSET_ID: &str = "usdd-devnet";
pub const ZK_ORACLE_DEVNET_BTC_ASSET_ID: &str = "xbtc-devnet";
pub const ZK_ORACLE_DEVNET_ETH_ASSET_ID: &str = "xeth-devnet";
pub const ZK_ORACLE_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const ZK_ORACLE_FAST_PRICE_LANE: &str = "zk-oracle-fast-price";
pub const ZK_ORACLE_RESERVE_LANE: &str = "zk-oracle-reserve";
pub const ZK_ORACLE_RISK_LANE: &str = "zk-oracle-risk";
pub const ZK_ORACLE_BACKFILL_LANE: &str = "zk-oracle-backfill";

pub type ZkOracleResult<T> = Result<T, String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyLaneKind {
    FastPrice,
    Reserve,
    Risk,
    Backfill,
    Emergency,
}

impl LatencyLaneKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FastPrice => "fast_price",
            Self::Reserve => "reserve",
            Self::Risk => "risk",
            Self::Backfill => "backfill",
            Self::Emergency => "emergency",
        }
    }

    pub fn default_lane_id(&self) -> &'static str {
        match self {
            Self::FastPrice => ZK_ORACLE_FAST_PRICE_LANE,
            Self::Reserve => ZK_ORACLE_RESERVE_LANE,
            Self::Risk => ZK_ORACLE_RISK_LANE,
            Self::Backfill => ZK_ORACLE_BACKFILL_LANE,
            Self::Emergency => "zk-oracle-emergency",
        }
    }

    pub fn default_display_name(&self) -> &'static str {
        match self {
            Self::FastPrice => "Private fast price lane",
            Self::Reserve => "Reserve proof lane",
            Self::Risk => "Risk attestation lane",
            Self::Backfill => "Historical backfill lane",
            Self::Emergency => "Emergency oracle lane",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriceFeedKind {
    Spot,
    Twap,
    ReserveRate,
    Volatility,
    Funding,
    LiquidityIndex,
}

impl PriceFeedKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Spot => "spot",
            Self::Twap => "twap",
            Self::ReserveRate => "reserve_rate",
            Self::Volatility => "volatility",
            Self::Funding => "funding",
            Self::LiquidityIndex => "liquidity_index",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherRole {
    Oracle,
    ReserveAttester,
    RiskCommittee,
    Sequencer,
    Watchtower,
    EmergencyCouncil,
}

impl PublisherRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Oracle => "oracle",
            Self::ReserveAttester => "reserve_attester",
            Self::RiskCommittee => "risk_committee",
            Self::Sequencer => "sequencer",
            Self::Watchtower => "watchtower",
            Self::EmergencyCouncil => "emergency_council",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateVisibility {
    Public,
    Shielded,
    Private,
    AggregateOnly,
}

impl UpdateVisibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Shielded => "shielded",
            Self::Private => "private",
            Self::AggregateOnly => "aggregate_only",
        }
    }

    pub fn reveals_value(&self) -> bool {
        matches!(self, Self::Public)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateUpdateKind {
    PriceTick,
    ReserveSnapshot,
    LiabilitySnapshot,
    SolvencyAttestation,
    RiskAssessment,
    SponsorBudget,
    EmergencyOverride,
}

impl PrivateUpdateKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PriceTick => "price_tick",
            Self::ReserveSnapshot => "reserve_snapshot",
            Self::LiabilitySnapshot => "liability_snapshot",
            Self::SolvencyAttestation => "solvency_attestation",
            Self::RiskAssessment => "risk_assessment",
            Self::SponsorBudget => "sponsor_budget",
            Self::EmergencyOverride => "emergency_override",
        }
    }

    pub fn default_fee_units(&self) -> u64 {
        match self {
            Self::PriceTick => ZK_ORACLE_DEFAULT_LOW_FEE_UNITS,
            Self::ReserveSnapshot | Self::LiabilitySnapshot | Self::SolvencyAttestation => {
                ZK_ORACLE_DEFAULT_RESERVE_FEE_UNITS
            }
            Self::RiskAssessment | Self::EmergencyOverride => ZK_ORACLE_DEFAULT_RISK_FEE_UNITS,
            Self::SponsorBudget => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStatus {
    Pending,
    Accepted,
    Rejected,
    Aggregated,
    Stale,
    Revoked,
}

impl UpdateStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Aggregated => "aggregated",
            Self::Stale => "stale",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(self, Self::Pending | Self::Accepted | Self::Aggregated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSignatureScheme {
    MlDsa65,
    SlhDsaShake128s,
    Hybrid,
}

impl PqSignatureScheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MlDsa65 => ZK_ORACLE_PQ_SIGNATURE_SCHEME,
            Self::SlhDsaShake128s => ZK_ORACLE_PQ_RECOVERY_SCHEME,
            Self::Hybrid => ZK_ORACLE_PQ_HYBRID_SCHEME,
        }
    }

    pub fn requires_recovery_signature(&self) -> bool {
        matches!(self, Self::SlhDsaShake128s | Self::Hybrid)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptKind {
    PriceUpdate,
    ReserveDisclosure,
    ReserveAttestation,
    RiskAttestation,
    SponsorGrant,
    CircuitBreaker,
    EmergencyOverride,
}

impl TranscriptKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PriceUpdate => "price_update",
            Self::ReserveDisclosure => "reserve_disclosure",
            Self::ReserveAttestation => "reserve_attestation",
            Self::RiskAttestation => "risk_attestation",
            Self::SponsorGrant => "sponsor_grant",
            Self::CircuitBreaker => "circuit_breaker",
            Self::EmergencyOverride => "emergency_override",
        }
    }

    pub fn default_scheme(&self) -> PqSignatureScheme {
        match self {
            Self::EmergencyOverride | Self::CircuitBreaker => PqSignatureScheme::Hybrid,
            Self::ReserveAttestation => PqSignatureScheme::SlhDsaShake128s,
            _ => PqSignatureScheme::MlDsa65,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveSubjectKind {
    WrappedXmrReserve,
    StablecoinReserve,
    ExchangeReserve,
    AmmPool,
    LendingMarket,
    InsuranceFund,
    PrivateLiabilitySet,
}

impl ReserveSubjectKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WrappedXmrReserve => "wrapped_xmr_reserve",
            Self::StablecoinReserve => "stablecoin_reserve",
            Self::ExchangeReserve => "exchange_reserve",
            Self::AmmPool => "amm_pool",
            Self::LendingMarket => "lending_market",
            Self::InsuranceFund => "insurance_fund",
            Self::PrivateLiabilitySet => "private_liability_set",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Active,
    QuorumReached,
    Expired,
    Challenged,
    Revoked,
}

impl AttestationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::QuorumReached => "quorum_reached",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(self, Self::Pending | Self::Active | Self::QuorumReached)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskSeverity {
    Healthy,
    Watch,
    Warn,
    Critical,
}

impl RiskSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::Warn => "warn",
            Self::Critical => "critical",
        }
    }

    pub fn score_floor_bps(&self) -> u64 {
        match self {
            Self::Healthy => 0,
            Self::Watch => 2_500,
            Self::Warn => 5_500,
            Self::Critical => 8_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAction {
    Allow,
    Watch,
    Throttle,
    BlockLiquidation,
    FreezeMarket,
    PauseOracle,
}

impl RiskAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Watch => "watch",
            Self::Throttle => "throttle",
            Self::BlockLiquidation => "block_liquidation",
            Self::FreezeMarket => "freeze_market",
            Self::PauseOracle => "pause_oracle",
        }
    }

    pub fn is_blocking(&self) -> bool {
        matches!(
            self,
            Self::BlockLiquidation | Self::FreezeMarket | Self::PauseOracle
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPolicyStatus {
    Active,
    Exhausted,
    Expired,
    Paused,
    Revoked,
}

impl SponsorPolicyStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Paused => "paused",
            Self::Revoked => "revoked",
        }
    }

    pub fn can_spend(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipReceiptStatus {
    Reserved,
    Applied,
    Reclaimed,
    Expired,
    Slashed,
}

impl SponsorshipReceiptStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Reclaimed => "reclaimed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitDecisionStatus {
    Open,
    CoolingDown,
    Closed,
    Retired,
}

impl CircuitDecisionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::CoolingDown => "cooling_down",
            Self::Closed => "closed",
            Self::Retired => "retired",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Open | Self::CoolingDown)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkOracleConfig {
    pub protocol_version: String,
    pub price_scale: u64,
    pub default_decimals: u8,
    pub default_min_sources: u64,
    pub default_heartbeat_blocks: u64,
    pub default_twap_window_blocks: u64,
    pub default_max_deviation_bps: u64,
    pub default_update_ttl_blocks: u64,
    pub default_transcript_ttl_blocks: u64,
    pub default_risk_ttl_blocks: u64,
    pub default_circuit_cooldown_blocks: u64,
    pub default_reserve_refresh_blocks: u64,
    pub default_reserve_grace_blocks: u64,
    pub default_min_solvency_bps: u64,
    pub max_observations_per_feed: usize,
    pub max_private_updates: usize,
    pub max_transcripts: usize,
    pub low_fee_updates_enabled: bool,
    pub pq_required: bool,
    pub private_updates_required: bool,
}

impl Default for ZkOracleConfig {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            price_scale: ZK_ORACLE_PRICE_SCALE,
            default_decimals: ZK_ORACLE_DEFAULT_DECIMALS,
            default_min_sources: ZK_ORACLE_DEFAULT_MIN_SOURCES,
            default_heartbeat_blocks: ZK_ORACLE_DEFAULT_HEARTBEAT_BLOCKS,
            default_twap_window_blocks: ZK_ORACLE_DEFAULT_TWAP_WINDOW_BLOCKS,
            default_max_deviation_bps: ZK_ORACLE_DEFAULT_MAX_DEVIATION_BPS,
            default_update_ttl_blocks: ZK_ORACLE_DEFAULT_UPDATE_TTL_BLOCKS,
            default_transcript_ttl_blocks: ZK_ORACLE_DEFAULT_TRANSCRIPT_TTL_BLOCKS,
            default_risk_ttl_blocks: ZK_ORACLE_DEFAULT_RISK_TTL_BLOCKS,
            default_circuit_cooldown_blocks: ZK_ORACLE_DEFAULT_CIRCUIT_COOLDOWN_BLOCKS,
            default_reserve_refresh_blocks: ZK_ORACLE_DEFAULT_RESERVE_REFRESH_BLOCKS,
            default_reserve_grace_blocks: ZK_ORACLE_DEFAULT_RESERVE_GRACE_BLOCKS,
            default_min_solvency_bps: ZK_ORACLE_DEFAULT_MIN_SOLVENCY_BPS,
            max_observations_per_feed: ZK_ORACLE_MAX_OBSERVATIONS_PER_FEED,
            max_private_updates: ZK_ORACLE_MAX_PRIVATE_UPDATES,
            max_transcripts: ZK_ORACLE_MAX_TRANSCRIPTS,
            low_fee_updates_enabled: true,
            pq_required: true,
            private_updates_required: true,
        }
    }
}

impl ZkOracleConfig {
    pub fn validate(&self) -> ZkOracleResult<()> {
        ensure_non_empty(&self.protocol_version, "zk oracle protocol version")?;
        ensure_positive(self.price_scale, "zk oracle price scale")?;
        ensure_positive(self.default_min_sources, "zk oracle default min sources")?;
        ensure_positive(
            self.default_heartbeat_blocks,
            "zk oracle default heartbeat blocks",
        )?;
        ensure_positive(
            self.default_twap_window_blocks,
            "zk oracle default twap window blocks",
        )?;
        ensure_positive(
            self.default_update_ttl_blocks,
            "zk oracle default update ttl blocks",
        )?;
        ensure_positive(
            self.default_transcript_ttl_blocks,
            "zk oracle default transcript ttl blocks",
        )?;
        ensure_positive(
            self.default_reserve_refresh_blocks,
            "zk oracle reserve refresh blocks",
        )?;
        if self.max_observations_per_feed == 0 {
            return Err("zk oracle max observations per feed must be positive".to_string());
        }
        if self.max_private_updates == 0 || self.max_transcripts == 0 {
            return Err(
                "zk oracle private update and transcript caps must be positive".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "security_model": ZK_ORACLE_SECURITY_MODEL,
            "commitment_scheme": ZK_ORACLE_COMMITMENT_SCHEME,
            "transcript_scheme": ZK_ORACLE_TRANSCRIPT_SCHEME,
            "price_scale": self.price_scale,
            "default_decimals": self.default_decimals,
            "default_min_sources": self.default_min_sources,
            "default_heartbeat_blocks": self.default_heartbeat_blocks,
            "default_twap_window_blocks": self.default_twap_window_blocks,
            "default_max_deviation_bps": self.default_max_deviation_bps,
            "default_update_ttl_blocks": self.default_update_ttl_blocks,
            "default_transcript_ttl_blocks": self.default_transcript_ttl_blocks,
            "default_risk_ttl_blocks": self.default_risk_ttl_blocks,
            "default_circuit_cooldown_blocks": self.default_circuit_cooldown_blocks,
            "default_reserve_refresh_blocks": self.default_reserve_refresh_blocks,
            "default_reserve_grace_blocks": self.default_reserve_grace_blocks,
            "default_min_solvency_bps": self.default_min_solvency_bps,
            "max_observations_per_feed": self.max_observations_per_feed as u64,
            "max_private_updates": self.max_private_updates as u64,
            "max_transcripts": self.max_transcripts as u64,
            "low_fee_updates_enabled": self.low_fee_updates_enabled,
            "pq_required": self.pq_required,
            "private_updates_required": self.private_updates_required,
        })
    }

    pub fn config_root(&self) -> String {
        zk_oracle_payload_root("ZK-ORACLE-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyLane {
    pub lane_id: String,
    pub lane_key: String,
    pub kind: LatencyLaneKind,
    pub display_name: String,
    pub max_latency_ms: u64,
    pub max_staleness_blocks: u64,
    pub priority_weight: u64,
    pub base_fee_units: u64,
    pub proof_budget_bytes: u64,
    pub sponsor_pool_id: String,
    pub active: bool,
}

impl LatencyLane {
    pub fn new(
        kind: LatencyLaneKind,
        lane_key: &str,
        max_latency_ms: u64,
        max_staleness_blocks: u64,
        priority_weight: u64,
        base_fee_units: u64,
        proof_budget_bytes: u64,
    ) -> ZkOracleResult<Self> {
        ensure_non_empty(lane_key, "zk oracle latency lane key")?;
        ensure_positive(max_latency_ms, "zk oracle lane latency")?;
        ensure_positive(max_staleness_blocks, "zk oracle lane staleness")?;
        ensure_positive(priority_weight, "zk oracle lane priority")?;
        let sponsor_pool_id = zk_oracle_string_commitment(
            "ZK-ORACLE-LANE-SPONSOR-POOL",
            &format!("{}:{lane_key}", kind.as_str()),
        );
        let lane_id = zk_oracle_latency_lane_id(
            kind.as_str(),
            lane_key,
            max_latency_ms,
            max_staleness_blocks,
            priority_weight,
            base_fee_units,
            proof_budget_bytes,
            &sponsor_pool_id,
        );
        let lane = Self {
            lane_id,
            lane_key: lane_key.to_string(),
            kind,
            display_name: kind.default_display_name().to_string(),
            max_latency_ms,
            max_staleness_blocks,
            priority_weight,
            base_fee_units,
            proof_budget_bytes,
            sponsor_pool_id,
            active: true,
        };
        lane.validate()?;
        Ok(lane)
    }

    pub fn validate(&self) -> ZkOracleResult<()> {
        ensure_non_empty(&self.lane_id, "zk oracle lane id")?;
        ensure_non_empty(&self.lane_key, "zk oracle lane key")?;
        ensure_non_empty(&self.display_name, "zk oracle lane display name")?;
        ensure_positive(self.max_latency_ms, "zk oracle lane latency")?;
        ensure_positive(self.max_staleness_blocks, "zk oracle lane staleness")?;
        ensure_positive(self.priority_weight, "zk oracle lane priority")?;
        ensure_non_empty(&self.sponsor_pool_id, "zk oracle lane sponsor pool")?;
        let expected = zk_oracle_latency_lane_id(
            self.kind.as_str(),
            &self.lane_key,
            self.max_latency_ms,
            self.max_staleness_blocks,
            self.priority_weight,
            self.base_fee_units,
            self.proof_budget_bytes,
            &self.sponsor_pool_id,
        );
        if self.lane_id != expected {
            return Err("zk oracle lane id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_latency_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "lane_key": self.lane_key,
            "lane_kind": self.kind.as_str(),
            "display_name": self.display_name,
            "max_latency_ms": self.max_latency_ms,
            "max_staleness_blocks": self.max_staleness_blocks,
            "priority_weight": self.priority_weight,
            "base_fee_units": self.base_fee_units,
            "proof_budget_bytes": self.proof_budget_bytes,
            "sponsor_pool_id": self.sponsor_pool_id,
            "active": self.active,
        })
    }

    pub fn lane_root(&self) -> String {
        zk_oracle_payload_root("ZK-ORACLE-LANE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceFeed {
    pub feed_id: String,
    pub feed_key: String,
    pub feed_kind: PriceFeedKind,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub decimals: u8,
    pub min_sources: u64,
    pub heartbeat_blocks: u64,
    pub twap_window_blocks: u64,
    pub max_deviation_bps: u64,
    pub lane_id: String,
    pub default_visibility: UpdateVisibility,
    pub proof_system: String,
    pub metadata_root: String,
    pub active: bool,
}

impl PriceFeed {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        feed_kind: PriceFeedKind,
        base_asset_id: &str,
        quote_asset_id: &str,
        decimals: u8,
        min_sources: u64,
        heartbeat_blocks: u64,
        twap_window_blocks: u64,
        max_deviation_bps: u64,
        lane_id: &str,
        default_visibility: UpdateVisibility,
        metadata: &Value,
    ) -> ZkOracleResult<Self> {
        ensure_non_empty(base_asset_id, "zk oracle feed base asset")?;
        ensure_non_empty(quote_asset_id, "zk oracle feed quote asset")?;
        ensure_non_empty(lane_id, "zk oracle feed lane id")?;
        if base_asset_id == quote_asset_id {
            return Err("zk oracle feed requires distinct base and quote assets".to_string());
        }
        ensure_positive(min_sources, "zk oracle feed min sources")?;
        ensure_positive(heartbeat_blocks, "zk oracle feed heartbeat blocks")?;
        ensure_positive(twap_window_blocks, "zk oracle feed twap window blocks")?;
        validate_percent_bps(max_deviation_bps, "zk oracle feed max deviation")?;
        let metadata_root = zk_oracle_metadata_root(metadata);
        let feed_key = format!(
            "{}:{}:{}",
            feed_kind.as_str(),
            base_asset_id,
            quote_asset_id
        );
        let feed_id = zk_oracle_price_feed_id(
            feed_kind.as_str(),
            base_asset_id,
            quote_asset_id,
            decimals,
            min_sources,
            heartbeat_blocks,
            twap_window_blocks,
            max_deviation_bps,
            lane_id,
            default_visibility.as_str(),
            &metadata_root,
        );
        let feed = Self {
            feed_id,
            feed_key,
            feed_kind,
            base_asset_id: base_asset_id.to_string(),
            quote_asset_id: quote_asset_id.to_string(),
            decimals,
            min_sources,
            heartbeat_blocks,
            twap_window_blocks,
            max_deviation_bps,
            lane_id: lane_id.to_string(),
            default_visibility,
            proof_system: ZK_ORACLE_PRICE_PROOF_SYSTEM.to_string(),
            metadata_root,
            active: true,
        };
        feed.validate()?;
        Ok(feed)
    }

    pub fn validate(&self) -> ZkOracleResult<()> {
        ensure_non_empty(&self.feed_id, "zk oracle feed id")?;
        ensure_non_empty(&self.feed_key, "zk oracle feed key")?;
        ensure_non_empty(&self.base_asset_id, "zk oracle feed base asset")?;
        ensure_non_empty(&self.quote_asset_id, "zk oracle feed quote asset")?;
        ensure_non_empty(&self.lane_id, "zk oracle feed lane id")?;
        ensure_non_empty(&self.proof_system, "zk oracle feed proof system")?;
        ensure_non_empty(&self.metadata_root, "zk oracle feed metadata root")?;
        if self.base_asset_id == self.quote_asset_id {
            return Err("zk oracle feed requires distinct assets".to_string());
        }
        ensure_positive(self.min_sources, "zk oracle feed min sources")?;
        ensure_positive(self.heartbeat_blocks, "zk oracle feed heartbeat blocks")?;
        ensure_positive(self.twap_window_blocks, "zk oracle feed twap window blocks")?;
        validate_percent_bps(self.max_deviation_bps, "zk oracle feed max deviation")?;
        let expected = zk_oracle_price_feed_id(
            self.feed_kind.as_str(),
            &self.base_asset_id,
            &self.quote_asset_id,
            self.decimals,
            self.min_sources,
            self.heartbeat_blocks,
            self.twap_window_blocks,
            self.max_deviation_bps,
            &self.lane_id,
            self.default_visibility.as_str(),
            &self.metadata_root,
        );
        if self.feed_id != expected {
            return Err("zk oracle feed id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_price_feed",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "feed_id": self.feed_id,
            "feed_key": self.feed_key,
            "feed_kind": self.feed_kind.as_str(),
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "decimals": self.decimals,
            "min_sources": self.min_sources,
            "heartbeat_blocks": self.heartbeat_blocks,
            "twap_window_blocks": self.twap_window_blocks,
            "max_deviation_bps": self.max_deviation_bps,
            "lane_id": self.lane_id,
            "default_visibility": self.default_visibility.as_str(),
            "proof_system": self.proof_system,
            "metadata_root": self.metadata_root,
            "active": self.active,
        })
    }

    pub fn pair(&self) -> String {
        format!("{}/{}", self.base_asset_id, self.quote_asset_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OraclePublisher {
    pub publisher_id: String,
    pub label: String,
    pub label_commitment: String,
    pub role: PublisherRole,
    pub pq_public_key_root: String,
    pub stake_units: u64,
    pub weight_bps: u64,
    pub max_updates_per_epoch: u64,
    pub lane_permissions: BTreeSet<String>,
    pub metadata_root: String,
    pub active: bool,
}

impl OraclePublisher {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        role: PublisherRole,
        pq_public_key_root: &str,
        stake_units: u64,
        weight_bps: u64,
        max_updates_per_epoch: u64,
        lane_permissions: BTreeSet<String>,
        metadata: &Value,
    ) -> ZkOracleResult<Self> {
        ensure_non_empty(label, "zk oracle publisher label")?;
        ensure_non_empty(pq_public_key_root, "zk oracle publisher pq public key root")?;
        ensure_positive(weight_bps, "zk oracle publisher weight")?;
        ensure_positive(
            max_updates_per_epoch,
            "zk oracle publisher max updates per epoch",
        )?;
        if lane_permissions.is_empty() {
            return Err("zk oracle publisher must have at least one lane permission".to_string());
        }
        let label_commitment = zk_oracle_string_commitment("ZK-ORACLE-PUBLISHER", label);
        let metadata_root = zk_oracle_metadata_root(metadata);
        let publisher_id = zk_oracle_publisher_id(
            &label_commitment,
            role.as_str(),
            pq_public_key_root,
            stake_units,
            weight_bps,
            max_updates_per_epoch,
            &zk_oracle_string_set_root("ZK-ORACLE-PUBLISHER-LANES", &lane_permissions),
            &metadata_root,
        );
        let publisher = Self {
            publisher_id,
            label: label.to_string(),
            label_commitment,
            role,
            pq_public_key_root: pq_public_key_root.to_string(),
            stake_units,
            weight_bps,
            max_updates_per_epoch,
            lane_permissions,
            metadata_root,
            active: true,
        };
        publisher.validate()?;
        Ok(publisher)
    }

    pub fn validate(&self) -> ZkOracleResult<()> {
        ensure_non_empty(&self.publisher_id, "zk oracle publisher id")?;
        ensure_non_empty(&self.label, "zk oracle publisher label")?;
        ensure_non_empty(
            &self.label_commitment,
            "zk oracle publisher label commitment",
        )?;
        ensure_non_empty(
            &self.pq_public_key_root,
            "zk oracle publisher pq public key root",
        )?;
        ensure_positive(self.weight_bps, "zk oracle publisher weight")?;
        ensure_positive(
            self.max_updates_per_epoch,
            "zk oracle publisher max updates per epoch",
        )?;
        if self.lane_permissions.is_empty() {
            return Err("zk oracle publisher has no lane permissions".to_string());
        }
        if self.label_commitment != zk_oracle_string_commitment("ZK-ORACLE-PUBLISHER", &self.label)
        {
            return Err("zk oracle publisher label commitment mismatch".to_string());
        }
        let expected = zk_oracle_publisher_id(
            &self.label_commitment,
            self.role.as_str(),
            &self.pq_public_key_root,
            self.stake_units,
            self.weight_bps,
            self.max_updates_per_epoch,
            &zk_oracle_string_set_root("ZK-ORACLE-PUBLISHER-LANES", &self.lane_permissions),
            &self.metadata_root,
        );
        if self.publisher_id != expected {
            return Err("zk oracle publisher id mismatch".to_string());
        }
        Ok(())
    }

    pub fn can_publish_to_lane(&self, lane_id: &str) -> bool {
        self.active && self.lane_permissions.contains(lane_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_publisher",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "publisher_id": self.publisher_id,
            "label_commitment": self.label_commitment,
            "role": self.role.as_str(),
            "pq_public_key_root": self.pq_public_key_root,
            "stake_units": self.stake_units,
            "weight_bps": self.weight_bps,
            "max_updates_per_epoch": self.max_updates_per_epoch,
            "lane_permissions": self.lane_permissions.iter().cloned().collect::<Vec<_>>(),
            "metadata_root": self.metadata_root,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignatureTranscript {
    pub transcript_id: String,
    pub transcript_kind: TranscriptKind,
    pub scheme: PqSignatureScheme,
    pub signer_id: String,
    pub signer_key_root: String,
    pub subject_root: String,
    pub context_root: String,
    pub challenge_root: String,
    pub signature_commitment: String,
    pub recovery_signature_commitment: Option<String>,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub status: UpdateStatus,
}

impl PqSignatureTranscript {
    pub fn deterministic(
        transcript_kind: TranscriptKind,
        signer_id: &str,
        signer_key_root: &str,
        subject: &Value,
        context: &Value,
        signed_at_height: u64,
        expires_at_height: u64,
    ) -> ZkOracleResult<Self> {
        ensure_non_empty(signer_id, "zk oracle transcript signer id")?;
        ensure_non_empty(signer_key_root, "zk oracle transcript signer key root")?;
        if expires_at_height <= signed_at_height {
            return Err("zk oracle transcript expiry must be after signing height".to_string());
        }
        let scheme = transcript_kind.default_scheme();
        let subject_root = zk_oracle_payload_root("ZK-ORACLE-PQ-SUBJECT", subject);
        let context_root = zk_oracle_payload_root("ZK-ORACLE-PQ-CONTEXT", context);
        let challenge_root = zk_oracle_pq_challenge_root(
            transcript_kind.as_str(),
            scheme.as_str(),
            signer_id,
            signer_key_root,
            &subject_root,
            &context_root,
            signed_at_height,
        );
        let signature_commitment = zk_oracle_pq_signature_commitment(
            scheme.as_str(),
            signer_id,
            signer_key_root,
            &challenge_root,
            signed_at_height,
        );
        let recovery_signature_commitment = if scheme.requires_recovery_signature() {
            Some(zk_oracle_pq_signature_commitment(
                ZK_ORACLE_PQ_RECOVERY_SCHEME,
                signer_id,
                signer_key_root,
                &challenge_root,
                signed_at_height.saturating_add(1),
            ))
        } else {
            None
        };
        let transcript_id = zk_oracle_pq_transcript_id(
            transcript_kind.as_str(),
            scheme.as_str(),
            signer_id,
            &challenge_root,
            &signature_commitment,
            recovery_signature_commitment.as_deref().unwrap_or("none"),
        );
        let transcript = Self {
            transcript_id,
            transcript_kind,
            scheme,
            signer_id: signer_id.to_string(),
            signer_key_root: signer_key_root.to_string(),
            subject_root,
            context_root,
            challenge_root,
            signature_commitment,
            recovery_signature_commitment,
            signed_at_height,
            expires_at_height,
            status: UpdateStatus::Accepted,
        };
        transcript.validate()?;
        Ok(transcript)
    }

    pub fn validate(&self) -> ZkOracleResult<()> {
        ensure_non_empty(&self.transcript_id, "zk oracle transcript id")?;
        ensure_non_empty(&self.signer_id, "zk oracle transcript signer id")?;
        ensure_non_empty(
            &self.signer_key_root,
            "zk oracle transcript signer key root",
        )?;
        ensure_non_empty(&self.subject_root, "zk oracle transcript subject root")?;
        ensure_non_empty(&self.context_root, "zk oracle transcript context root")?;
        ensure_non_empty(&self.challenge_root, "zk oracle transcript challenge root")?;
        ensure_non_empty(
            &self.signature_commitment,
            "zk oracle transcript signature commitment",
        )?;
        if self.expires_at_height <= self.signed_at_height {
            return Err("zk oracle transcript expiry must be after signing height".to_string());
        }
        if self.scheme.requires_recovery_signature() && self.recovery_signature_commitment.is_none()
        {
            return Err("zk oracle transcript missing recovery signature".to_string());
        }
        let expected = zk_oracle_pq_transcript_id(
            self.transcript_kind.as_str(),
            self.scheme.as_str(),
            &self.signer_id,
            &self.challenge_root,
            &self.signature_commitment,
            self.recovery_signature_commitment
                .as_deref()
                .unwrap_or("none"),
        );
        if self.transcript_id != expected {
            return Err("zk oracle transcript id mismatch".to_string());
        }
        Ok(())
    }

    pub fn is_valid_at(&self, height: u64) -> bool {
        self.status.is_live() && self.signed_at_height <= height && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        let mut record = json!({
            "kind": "zk_oracle_pq_signature_transcript",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "security_model": ZK_ORACLE_SECURITY_MODEL,
            "transcript_id": self.transcript_id,
            "transcript_kind": self.transcript_kind.as_str(),
            "scheme": self.scheme.as_str(),
            "signer_id": self.signer_id,
            "signer_key_root": self.signer_key_root,
            "subject_root": self.subject_root,
            "context_root": self.context_root,
            "challenge_root": self.challenge_root,
            "signature_commitment": self.signature_commitment,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        });
        if let Some(commitment) = &self.recovery_signature_commitment {
            record
                .as_object_mut()
                .expect("zk oracle transcript record object")
                .insert(
                    "recovery_signature_commitment".to_string(),
                    Value::String(commitment.clone()),
                );
        }
        record
    }

    pub fn transcript_root(&self) -> String {
        zk_oracle_payload_root("ZK-ORACLE-PQ-TRANSCRIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateUpdateEnvelope {
    pub envelope_id: String,
    pub update_kind: PrivateUpdateKind,
    pub subject_id: String,
    pub lane_id: String,
    pub submitter_commitment: String,
    pub payload_commitment: String,
    pub encrypted_payload_root: String,
    pub disclosure_root: String,
    pub nullifier: String,
    pub blinding_root: String,
    pub proof_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: UpdateStatus,
}

impl PrivateUpdateEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        update_kind: PrivateUpdateKind,
        subject_id: &str,
        lane_id: &str,
        submitter_label: &str,
        payload: &Value,
        disclosure: &Value,
        submitted_at_height: u64,
        expires_at_height: u64,
    ) -> ZkOracleResult<Self> {
        ensure_non_empty(subject_id, "zk oracle private envelope subject")?;
        ensure_non_empty(lane_id, "zk oracle private envelope lane")?;
        ensure_non_empty(submitter_label, "zk oracle private envelope submitter")?;
        if expires_at_height <= submitted_at_height {
            return Err(
                "zk oracle private envelope expiry must be after submit height".to_string(),
            );
        }
        let submitter_commitment =
            zk_oracle_string_commitment("ZK-ORACLE-PRIVATE-SUBMITTER", submitter_label);
        let payload_commitment = zk_oracle_payload_root("ZK-ORACLE-PRIVATE-PAYLOAD", payload);
        let encrypted_payload_root =
            zk_oracle_payload_root("ZK-ORACLE-PRIVATE-ENCRYPTED-PAYLOAD", payload);
        let disclosure_root = zk_oracle_payload_root("ZK-ORACLE-PRIVATE-DISCLOSURE", disclosure);
        let blinding_root = zk_oracle_blinding_root(
            update_kind.as_str(),
            subject_id,
            lane_id,
            &submitter_commitment,
            &payload_commitment,
            submitted_at_height,
        );
        let nullifier = zk_oracle_nullifier(
            update_kind.as_str(),
            subject_id,
            lane_id,
            &submitter_commitment,
            &blinding_root,
            submitted_at_height,
        );
        let proof_root = zk_oracle_private_update_proof_root(
            update_kind.as_str(),
            subject_id,
            &payload_commitment,
            &disclosure_root,
            &nullifier,
            &blinding_root,
        );
        let envelope_id = zk_oracle_private_envelope_id(
            update_kind.as_str(),
            subject_id,
            lane_id,
            &submitter_commitment,
            &payload_commitment,
            &nullifier,
            submitted_at_height,
        );
        let envelope = Self {
            envelope_id,
            update_kind,
            subject_id: subject_id.to_string(),
            lane_id: lane_id.to_string(),
            submitter_commitment,
            payload_commitment,
            encrypted_payload_root,
            disclosure_root,
            nullifier,
            blinding_root,
            proof_root,
            submitted_at_height,
            expires_at_height,
            status: UpdateStatus::Accepted,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn validate(&self) -> ZkOracleResult<()> {
        ensure_non_empty(&self.envelope_id, "zk oracle private envelope id")?;
        ensure_non_empty(&self.subject_id, "zk oracle private envelope subject")?;
        ensure_non_empty(&self.lane_id, "zk oracle private envelope lane")?;
        ensure_non_empty(
            &self.submitter_commitment,
            "zk oracle private envelope submitter commitment",
        )?;
        ensure_non_empty(
            &self.payload_commitment,
            "zk oracle private envelope payload commitment",
        )?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "zk oracle private envelope encrypted payload root",
        )?;
        ensure_non_empty(
            &self.disclosure_root,
            "zk oracle private envelope disclosure root",
        )?;
        ensure_non_empty(&self.nullifier, "zk oracle private envelope nullifier")?;
        ensure_non_empty(
            &self.blinding_root,
            "zk oracle private envelope blinding root",
        )?;
        ensure_non_empty(&self.proof_root, "zk oracle private envelope proof root")?;
        if self.expires_at_height <= self.submitted_at_height {
            return Err(
                "zk oracle private envelope expiry must be after submit height".to_string(),
            );
        }
        let expected = zk_oracle_private_envelope_id(
            self.update_kind.as_str(),
            &self.subject_id,
            &self.lane_id,
            &self.submitter_commitment,
            &self.payload_commitment,
            &self.nullifier,
            self.submitted_at_height,
        );
        if self.envelope_id != expected {
            return Err("zk oracle private envelope id mismatch".to_string());
        }
        Ok(())
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.is_live()
            && self.submitted_at_height <= height
            && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_private_update_envelope",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "private_update_system": ZK_ORACLE_PRIVATE_UPDATE_SYSTEM,
            "envelope_id": self.envelope_id,
            "update_kind": self.update_kind.as_str(),
            "subject_id": self.subject_id,
            "lane_id": self.lane_id,
            "submitter_commitment": self.submitter_commitment,
            "payload_commitment": self.payload_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "disclosure_root": self.disclosure_root,
            "nullifier": self.nullifier,
            "blinding_root": self.blinding_root,
            "proof_root": self.proof_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceObservation {
    pub observation_id: String,
    pub feed_id: String,
    pub publisher_id: String,
    pub round: u64,
    pub price_units: u64,
    pub price_commitment: String,
    pub exponent: i32,
    pub confidence_bps: u64,
    pub observed_at_height: u64,
    pub observed_at_ms: u64,
    pub latency_ms: u64,
    pub visibility: UpdateVisibility,
    pub private_envelope_id: String,
    pub signature_transcript_id: String,
    pub lane_id: String,
    pub payload_root: String,
    pub status: UpdateStatus,
}

impl PriceObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        feed_id: &str,
        publisher_id: &str,
        round: u64,
        price_units: u64,
        exponent: i32,
        confidence_bps: u64,
        observed_at_height: u64,
        observed_at_ms: u64,
        latency_ms: u64,
        visibility: UpdateVisibility,
        private_envelope_id: &str,
        signature_transcript_id: &str,
        lane_id: &str,
        blinding_root: &str,
    ) -> ZkOracleResult<Self> {
        ensure_non_empty(feed_id, "zk oracle observation feed id")?;
        ensure_non_empty(publisher_id, "zk oracle observation publisher id")?;
        ensure_positive(price_units, "zk oracle observation price")?;
        validate_percent_bps(confidence_bps, "zk oracle observation confidence")?;
        ensure_non_empty(
            private_envelope_id,
            "zk oracle observation private envelope id",
        )?;
        ensure_non_empty(
            signature_transcript_id,
            "zk oracle observation transcript id",
        )?;
        ensure_non_empty(lane_id, "zk oracle observation lane id")?;
        ensure_non_empty(blinding_root, "zk oracle observation blinding root")?;
        let price_commitment =
            zk_oracle_number_commitment("ZK-ORACLE-PRICE", price_units, blinding_root);
        let payload_root = zk_oracle_price_payload_root(
            feed_id,
            publisher_id,
            round,
            &price_commitment,
            exponent,
            confidence_bps,
            observed_at_height,
            observed_at_ms,
            latency_ms,
            visibility.as_str(),
        );
        let observation_id = zk_oracle_price_observation_id(
            feed_id,
            publisher_id,
            round,
            &payload_root,
            private_envelope_id,
            signature_transcript_id,
        );
        let observation = Self {
            observation_id,
            feed_id: feed_id.to_string(),
            publisher_id: publisher_id.to_string(),
            round,
            price_units,
            price_commitment,
            exponent,
            confidence_bps,
            observed_at_height,
            observed_at_ms,
            latency_ms,
            visibility,
            private_envelope_id: private_envelope_id.to_string(),
            signature_transcript_id: signature_transcript_id.to_string(),
            lane_id: lane_id.to_string(),
            payload_root,
            status: UpdateStatus::Accepted,
        };
        observation.validate()?;
        Ok(observation)
    }

    pub fn validate(&self) -> ZkOracleResult<()> {
        ensure_non_empty(&self.observation_id, "zk oracle observation id")?;
        ensure_non_empty(&self.feed_id, "zk oracle observation feed id")?;
        ensure_non_empty(&self.publisher_id, "zk oracle observation publisher id")?;
        ensure_positive(self.price_units, "zk oracle observation price")?;
        ensure_non_empty(&self.price_commitment, "zk oracle price commitment")?;
        validate_percent_bps(self.confidence_bps, "zk oracle observation confidence")?;
        ensure_non_empty(
            &self.private_envelope_id,
            "zk oracle observation private envelope",
        )?;
        ensure_non_empty(
            &self.signature_transcript_id,
            "zk oracle observation transcript",
        )?;
        ensure_non_empty(&self.lane_id, "zk oracle observation lane")?;
        ensure_non_empty(&self.payload_root, "zk oracle observation payload root")?;
        let expected_payload = zk_oracle_price_payload_root(
            &self.feed_id,
            &self.publisher_id,
            self.round,
            &self.price_commitment,
            self.exponent,
            self.confidence_bps,
            self.observed_at_height,
            self.observed_at_ms,
            self.latency_ms,
            self.visibility.as_str(),
        );
        if self.payload_root != expected_payload {
            return Err("zk oracle observation payload root mismatch".to_string());
        }
        let expected_id = zk_oracle_price_observation_id(
            &self.feed_id,
            &self.publisher_id,
            self.round,
            &self.payload_root,
            &self.private_envelope_id,
            &self.signature_transcript_id,
        );
        if self.observation_id != expected_id {
            return Err("zk oracle observation id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        let mut record = json!({
            "kind": "zk_oracle_price_observation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "observation_id": self.observation_id,
            "feed_id": self.feed_id,
            "publisher_id": self.publisher_id,
            "round": self.round,
            "price_commitment": self.price_commitment,
            "exponent": self.exponent,
            "confidence_bps": self.confidence_bps,
            "observed_at_height": self.observed_at_height,
            "observed_at_ms": self.observed_at_ms,
            "latency_ms": self.latency_ms,
            "visibility": self.visibility.as_str(),
            "private_envelope_id": self.private_envelope_id,
            "signature_transcript_id": self.signature_transcript_id,
            "lane_id": self.lane_id,
            "payload_root": self.payload_root,
            "status": self.status.as_str(),
        });
        if self.visibility.reveals_value() {
            record
                .as_object_mut()
                .expect("zk oracle observation record object")
                .insert(
                    "disclosed_price_units".to_string(),
                    Value::Number(self.price_units.into()),
                );
        }
        record
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceAggregate {
    pub aggregate_id: String,
    pub feed_id: String,
    pub round: u64,
    pub median_price_units: u64,
    pub weighted_price_units: u64,
    pub twap_price_units: u64,
    pub min_price_units: u64,
    pub max_price_units: u64,
    pub exponent: i32,
    pub confidence_bps: u64,
    pub observation_root: String,
    pub publisher_weight_root: String,
    pub private_envelope_root: String,
    pub transcript_root: String,
    pub proof_root: String,
    pub lane_id: String,
    pub published_at_height: u64,
    pub stale_after_height: u64,
    pub status: UpdateStatus,
}

impl PriceAggregate {
    pub fn is_stale(&self, height: u64) -> bool {
        height >= self.stale_after_height || !self.status.is_live()
    }

    pub fn validate(&self) -> ZkOracleResult<()> {
        ensure_non_empty(&self.aggregate_id, "zk oracle aggregate id")?;
        ensure_non_empty(&self.feed_id, "zk oracle aggregate feed id")?;
        ensure_positive(
            self.weighted_price_units,
            "zk oracle aggregate weighted price",
        )?;
        ensure_non_empty(
            &self.observation_root,
            "zk oracle aggregate observation root",
        )?;
        ensure_non_empty(
            &self.publisher_weight_root,
            "zk oracle aggregate publisher weight root",
        )?;
        ensure_non_empty(
            &self.private_envelope_root,
            "zk oracle aggregate private envelope root",
        )?;
        ensure_non_empty(&self.transcript_root, "zk oracle aggregate transcript root")?;
        ensure_non_empty(&self.proof_root, "zk oracle aggregate proof root")?;
        ensure_non_empty(&self.lane_id, "zk oracle aggregate lane")?;
        if self.published_at_height >= self.stale_after_height {
            return Err(
                "zk oracle aggregate stale height must be after publish height".to_string(),
            );
        }
        let expected = zk_oracle_price_aggregate_id(
            &self.feed_id,
            self.round,
            self.median_price_units,
            self.weighted_price_units,
            self.twap_price_units,
            self.exponent,
            &self.observation_root,
            &self.publisher_weight_root,
            &self.private_envelope_root,
            &self.transcript_root,
            self.published_at_height,
            self.stale_after_height,
        );
        if self.aggregate_id != expected {
            return Err("zk oracle aggregate id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_price_aggregate",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "proof_system": ZK_ORACLE_PRICE_PROOF_SYSTEM,
            "aggregate_id": self.aggregate_id,
            "feed_id": self.feed_id,
            "round": self.round,
            "median_price_units": self.median_price_units,
            "weighted_price_units": self.weighted_price_units,
            "twap_price_units": self.twap_price_units,
            "min_price_units": self.min_price_units,
            "max_price_units": self.max_price_units,
            "exponent": self.exponent,
            "confidence_bps": self.confidence_bps,
            "observation_root": self.observation_root,
            "publisher_weight_root": self.publisher_weight_root,
            "private_envelope_root": self.private_envelope_root,
            "transcript_root": self.transcript_root,
            "proof_root": self.proof_root,
            "lane_id": self.lane_id,
            "published_at_height": self.published_at_height,
            "stale_after_height": self.stale_after_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkOracleUpdateReceipt {
    pub receipt_id: String,
    pub update_kind: PrivateUpdateKind,
    pub subject_id: String,
    pub lane_id: String,
    pub private_envelope_id: String,
    pub signature_transcript_id: String,
    pub observation_id: Option<String>,
    pub aggregate_id: Option<String>,
    pub sponsorship_receipt_id: Option<String>,
    pub gross_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub accepted: bool,
    pub reason: String,
    pub recorded_at_height: u64,
}

impl ZkOracleUpdateReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_update_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "update_kind": self.update_kind.as_str(),
            "subject_id": self.subject_id,
            "lane_id": self.lane_id,
            "private_envelope_id": self.private_envelope_id,
            "signature_transcript_id": self.signature_transcript_id,
            "observation_id": self.observation_id,
            "aggregate_id": self.aggregate_id,
            "sponsorship_receipt_id": self.sponsorship_receipt_id,
            "gross_fee_units": self.gross_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "net_fee_units": self.gross_fee_units.saturating_sub(self.sponsored_fee_units),
            "accepted": self.accepted,
            "reason": self.reason,
            "recorded_at_height": self.recorded_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveSubject {
    pub subject_id: String,
    pub subject_key: String,
    pub subject_kind: ReserveSubjectKind,
    pub operator_commitment: String,
    pub reserve_asset_id: String,
    pub liability_asset_id: String,
    pub price_feed_id: String,
    pub min_solvency_bps: u64,
    pub min_coverage_bps: u64,
    pub max_staleness_blocks: u64,
    pub refresh_cadence_blocks: u64,
    pub refresh_grace_blocks: u64,
    pub attester_set_id: String,
    pub lane_id: String,
    pub metadata_root: String,
    pub active: bool,
}

impl ReserveSubject {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_kind: ReserveSubjectKind,
        subject_key: &str,
        operator_label: &str,
        reserve_asset_id: &str,
        liability_asset_id: &str,
        price_feed_id: &str,
        min_solvency_bps: u64,
        min_coverage_bps: u64,
        max_staleness_blocks: u64,
        refresh_cadence_blocks: u64,
        refresh_grace_blocks: u64,
        attester_set_id: &str,
        lane_id: &str,
        metadata: &Value,
    ) -> ZkOracleResult<Self> {
        ensure_non_empty(subject_key, "zk oracle reserve subject key")?;
        ensure_non_empty(operator_label, "zk oracle reserve operator")?;
        ensure_non_empty(reserve_asset_id, "zk oracle reserve asset")?;
        ensure_non_empty(liability_asset_id, "zk oracle liability asset")?;
        ensure_non_empty(price_feed_id, "zk oracle reserve price feed")?;
        ensure_non_empty(attester_set_id, "zk oracle reserve attester set")?;
        ensure_non_empty(lane_id, "zk oracle reserve lane")?;
        ensure_positive(min_solvency_bps, "zk oracle reserve min solvency")?;
        ensure_positive(min_coverage_bps, "zk oracle reserve min coverage")?;
        ensure_positive(max_staleness_blocks, "zk oracle reserve max staleness")?;
        ensure_positive(refresh_cadence_blocks, "zk oracle reserve refresh cadence")?;
        let operator_commitment =
            zk_oracle_string_commitment("ZK-ORACLE-RESERVE-OPERATOR", operator_label);
        let metadata_root = zk_oracle_metadata_root(metadata);
        let subject_id = zk_oracle_reserve_subject_id(
            subject_kind.as_str(),
            subject_key,
            &operator_commitment,
            reserve_asset_id,
            liability_asset_id,
            price_feed_id,
            min_solvency_bps,
            min_coverage_bps,
            attester_set_id,
            lane_id,
            &metadata_root,
        );
        let subject = Self {
            subject_id,
            subject_key: subject_key.to_string(),
            subject_kind,
            operator_commitment,
            reserve_asset_id: reserve_asset_id.to_string(),
            liability_asset_id: liability_asset_id.to_string(),
            price_feed_id: price_feed_id.to_string(),
            min_solvency_bps,
            min_coverage_bps,
            max_staleness_blocks,
            refresh_cadence_blocks,
            refresh_grace_blocks,
            attester_set_id: attester_set_id.to_string(),
            lane_id: lane_id.to_string(),
            metadata_root,
            active: true,
        };
        subject.validate()?;
        Ok(subject)
    }

    pub fn validate(&self) -> ZkOracleResult<()> {
        ensure_non_empty(&self.subject_id, "zk oracle reserve subject id")?;
        ensure_non_empty(&self.subject_key, "zk oracle reserve subject key")?;
        ensure_non_empty(
            &self.operator_commitment,
            "zk oracle reserve operator commitment",
        )?;
        ensure_non_empty(&self.reserve_asset_id, "zk oracle reserve asset")?;
        ensure_non_empty(&self.liability_asset_id, "zk oracle liability asset")?;
        ensure_non_empty(&self.price_feed_id, "zk oracle reserve price feed")?;
        ensure_positive(self.min_solvency_bps, "zk oracle reserve min solvency")?;
        ensure_positive(self.min_coverage_bps, "zk oracle reserve min coverage")?;
        ensure_positive(self.max_staleness_blocks, "zk oracle reserve max staleness")?;
        ensure_positive(self.refresh_cadence_blocks, "zk oracle reserve cadence")?;
        ensure_non_empty(&self.attester_set_id, "zk oracle reserve attester set")?;
        ensure_non_empty(&self.lane_id, "zk oracle reserve lane")?;
        let expected = zk_oracle_reserve_subject_id(
            self.subject_kind.as_str(),
            &self.subject_key,
            &self.operator_commitment,
            &self.reserve_asset_id,
            &self.liability_asset_id,
            &self.price_feed_id,
            self.min_solvency_bps,
            self.min_coverage_bps,
            &self.attester_set_id,
            &self.lane_id,
            &self.metadata_root,
        );
        if self.subject_id != expected {
            return Err("zk oracle reserve subject id mismatch".to_string());
        }
        Ok(())
    }

    pub fn next_due_height(&self, last_height: u64) -> u64 {
        last_height.saturating_add(self.refresh_cadence_blocks)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_reserve_subject",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "subject_id": self.subject_id,
            "subject_key": self.subject_key,
            "subject_kind": self.subject_kind.as_str(),
            "operator_commitment": self.operator_commitment,
            "reserve_asset_id": self.reserve_asset_id,
            "liability_asset_id": self.liability_asset_id,
            "price_feed_id": self.price_feed_id,
            "min_solvency_bps": self.min_solvency_bps,
            "min_coverage_bps": self.min_coverage_bps,
            "max_staleness_blocks": self.max_staleness_blocks,
            "refresh_cadence_blocks": self.refresh_cadence_blocks,
            "refresh_grace_blocks": self.refresh_grace_blocks,
            "attester_set_id": self.attester_set_id,
            "lane_id": self.lane_id,
            "metadata_root": self.metadata_root,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveAttester {
    pub attester_id: String,
    pub label: String,
    pub label_commitment: String,
    pub role: PublisherRole,
    pub pq_public_key_root: String,
    pub weight: u64,
    pub active: bool,
}

impl ReserveAttester {
    pub fn new(
        label: &str,
        role: PublisherRole,
        pq_public_key_root: &str,
        weight: u64,
    ) -> ZkOracleResult<Self> {
        ensure_non_empty(label, "zk oracle reserve attester label")?;
        ensure_non_empty(pq_public_key_root, "zk oracle reserve attester pq key")?;
        ensure_positive(weight, "zk oracle reserve attester weight")?;
        let label_commitment = zk_oracle_string_commitment("ZK-ORACLE-ATTESTER", label);
        let attester_id = zk_oracle_reserve_attester_id(
            &label_commitment,
            role.as_str(),
            pq_public_key_root,
            weight,
        );
        let attester = Self {
            attester_id,
            label: label.to_string(),
            label_commitment,
            role,
            pq_public_key_root: pq_public_key_root.to_string(),
            weight,
            active: true,
        };
        attester.validate()?;
        Ok(attester)
    }

    pub fn validate(&self) -> ZkOracleResult<()> {
        ensure_non_empty(&self.attester_id, "zk oracle reserve attester id")?;
        ensure_non_empty(&self.label, "zk oracle reserve attester label")?;
        ensure_non_empty(
            &self.label_commitment,
            "zk oracle reserve attester label commitment",
        )?;
        ensure_non_empty(
            &self.pq_public_key_root,
            "zk oracle reserve attester pq key root",
        )?;
        ensure_positive(self.weight, "zk oracle reserve attester weight")?;
        if self.label_commitment != zk_oracle_string_commitment("ZK-ORACLE-ATTESTER", &self.label) {
            return Err("zk oracle reserve attester label commitment mismatch".to_string());
        }
        let expected = zk_oracle_reserve_attester_id(
            &self.label_commitment,
            self.role.as_str(),
            &self.pq_public_key_root,
            self.weight,
        );
        if self.attester_id != expected {
            return Err("zk oracle reserve attester id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_reserve_attester",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "attester_id": self.attester_id,
            "label_commitment": self.label_commitment,
            "role": self.role.as_str(),
            "pq_public_key_root": self.pq_public_key_root,
            "weight": self.weight,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveAttesterSet {
    pub attester_set_id: String,
    pub set_label: String,
    pub attester_ids: BTreeSet<String>,
    pub threshold_weight: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
    pub active: bool,
}

impl ReserveAttesterSet {
    pub fn new(
        set_label: &str,
        attester_ids: BTreeSet<String>,
        threshold_weight: u64,
        created_at_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> ZkOracleResult<Self> {
        ensure_non_empty(set_label, "zk oracle reserve attester set label")?;
        if attester_ids.is_empty() {
            return Err("zk oracle reserve attester set cannot be empty".to_string());
        }
        ensure_positive(threshold_weight, "zk oracle reserve attester threshold")?;
        if expires_at_height <= created_at_height {
            return Err("zk oracle reserve attester set expiry must follow creation".to_string());
        }
        let metadata_root = zk_oracle_metadata_root(metadata);
        let attester_root =
            zk_oracle_string_set_root("ZK-ORACLE-ATTESTER-SET-MEMBERS", &attester_ids);
        let attester_set_id = zk_oracle_reserve_attester_set_id(
            set_label,
            &attester_root,
            threshold_weight,
            created_at_height,
            expires_at_height,
            &metadata_root,
        );
        let set = Self {
            attester_set_id,
            set_label: set_label.to_string(),
            attester_ids,
            threshold_weight,
            created_at_height,
            expires_at_height,
            metadata_root,
            active: true,
        };
        set.validate()?;
        Ok(set)
    }

    pub fn validate(&self) -> ZkOracleResult<()> {
        ensure_non_empty(&self.attester_set_id, "zk oracle reserve attester set id")?;
        ensure_non_empty(&self.set_label, "zk oracle reserve attester set label")?;
        if self.attester_ids.is_empty() {
            return Err("zk oracle reserve attester set cannot be empty".to_string());
        }
        ensure_positive(
            self.threshold_weight,
            "zk oracle reserve attester threshold",
        )?;
        if self.expires_at_height <= self.created_at_height {
            return Err("zk oracle reserve attester set expiry must follow creation".to_string());
        }
        let attester_root =
            zk_oracle_string_set_root("ZK-ORACLE-ATTESTER-SET-MEMBERS", &self.attester_ids);
        let expected = zk_oracle_reserve_attester_set_id(
            &self.set_label,
            &attester_root,
            self.threshold_weight,
            self.created_at_height,
            self.expires_at_height,
            &self.metadata_root,
        );
        if self.attester_set_id != expected {
            return Err("zk oracle reserve attester set id mismatch".to_string());
        }
        Ok(())
    }

    pub fn is_valid_at(&self, height: u64) -> bool {
        self.active && self.created_at_height <= height && height < self.expires_at_height
    }

    pub fn has_quorum_weight(&self, weight: u64) -> bool {
        weight >= self.threshold_weight
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_reserve_attester_set",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "attester_set_id": self.attester_set_id,
            "set_label": self.set_label,
            "attester_ids": self.attester_ids.iter().cloned().collect::<Vec<_>>(),
            "threshold_weight": self.threshold_weight,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveDisclosure {
    pub disclosure_id: String,
    pub subject_id: String,
    pub private_envelope_id: String,
    pub signature_transcript_id: String,
    pub reserve_commitment_root: String,
    pub liability_commitment_root: String,
    pub private_liability_root: String,
    pub reserve_value_units: u64,
    pub liability_value_units: u64,
    pub coverage_value_units: u64,
    pub price_feed_id: String,
    pub price_aggregate_id: String,
    pub solvency_bps: u64,
    pub coverage_bps: u64,
    pub proof_root: String,
    pub published_at_height: u64,
    pub expires_at_height: u64,
    pub status: AttestationStatus,
}

impl ReserveDisclosure {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_id: &str,
        private_envelope_id: &str,
        signature_transcript_id: &str,
        reserve_commitment_root: &str,
        liability_commitment_root: &str,
        private_liability_root: &str,
        reserve_value_units: u64,
        liability_value_units: u64,
        coverage_value_units: u64,
        price_feed_id: &str,
        price_aggregate_id: &str,
        published_at_height: u64,
        expires_at_height: u64,
    ) -> ZkOracleResult<Self> {
        ensure_non_empty(subject_id, "zk oracle reserve disclosure subject")?;
        ensure_non_empty(
            private_envelope_id,
            "zk oracle reserve disclosure private envelope",
        )?;
        ensure_non_empty(
            signature_transcript_id,
            "zk oracle reserve disclosure transcript",
        )?;
        ensure_non_empty(
            reserve_commitment_root,
            "zk oracle reserve disclosure reserve root",
        )?;
        ensure_non_empty(
            liability_commitment_root,
            "zk oracle reserve disclosure liability root",
        )?;
        ensure_non_empty(
            private_liability_root,
            "zk oracle reserve disclosure private liability root",
        )?;
        ensure_positive(reserve_value_units, "zk oracle reserve disclosed value")?;
        ensure_positive(liability_value_units, "zk oracle liability disclosed value")?;
        ensure_non_empty(price_feed_id, "zk oracle reserve disclosure price feed")?;
        ensure_non_empty(
            price_aggregate_id,
            "zk oracle reserve disclosure price aggregate",
        )?;
        if expires_at_height <= published_at_height {
            return Err(
                "zk oracle reserve disclosure expiry must follow publish height".to_string(),
            );
        }
        let solvency_bps = ratio_bps(reserve_value_units, liability_value_units);
        let coverage_bps = ratio_bps(coverage_value_units, liability_value_units);
        let proof_root = zk_oracle_reserve_disclosure_proof_root(
            subject_id,
            reserve_commitment_root,
            liability_commitment_root,
            private_liability_root,
            reserve_value_units,
            liability_value_units,
            coverage_value_units,
            price_feed_id,
            price_aggregate_id,
        );
        let disclosure_id = zk_oracle_reserve_disclosure_id(
            subject_id,
            private_envelope_id,
            signature_transcript_id,
            &proof_root,
            published_at_height,
        );
        let disclosure = Self {
            disclosure_id,
            subject_id: subject_id.to_string(),
            private_envelope_id: private_envelope_id.to_string(),
            signature_transcript_id: signature_transcript_id.to_string(),
            reserve_commitment_root: reserve_commitment_root.to_string(),
            liability_commitment_root: liability_commitment_root.to_string(),
            private_liability_root: private_liability_root.to_string(),
            reserve_value_units,
            liability_value_units,
            coverage_value_units,
            price_feed_id: price_feed_id.to_string(),
            price_aggregate_id: price_aggregate_id.to_string(),
            solvency_bps,
            coverage_bps,
            proof_root,
            published_at_height,
            expires_at_height,
            status: AttestationStatus::Active,
        };
        disclosure.validate()?;
        Ok(disclosure)
    }

    pub fn validate(&self) -> ZkOracleResult<()> {
        ensure_non_empty(&self.disclosure_id, "zk oracle reserve disclosure id")?;
        ensure_non_empty(&self.subject_id, "zk oracle reserve disclosure subject")?;
        ensure_non_empty(
            &self.private_envelope_id,
            "zk oracle reserve disclosure private envelope",
        )?;
        ensure_non_empty(
            &self.signature_transcript_id,
            "zk oracle reserve disclosure transcript",
        )?;
        ensure_positive(
            self.reserve_value_units,
            "zk oracle reserve disclosed value",
        )?;
        ensure_positive(
            self.liability_value_units,
            "zk oracle liability disclosed value",
        )?;
        ensure_non_empty(&self.proof_root, "zk oracle reserve disclosure proof")?;
        if self.expires_at_height <= self.published_at_height {
            return Err(
                "zk oracle reserve disclosure expiry must follow publish height".to_string(),
            );
        }
        if self.solvency_bps != ratio_bps(self.reserve_value_units, self.liability_value_units) {
            return Err("zk oracle reserve disclosure solvency mismatch".to_string());
        }
        if self.coverage_bps != ratio_bps(self.coverage_value_units, self.liability_value_units) {
            return Err("zk oracle reserve disclosure coverage mismatch".to_string());
        }
        let expected_proof = zk_oracle_reserve_disclosure_proof_root(
            &self.subject_id,
            &self.reserve_commitment_root,
            &self.liability_commitment_root,
            &self.private_liability_root,
            self.reserve_value_units,
            self.liability_value_units,
            self.coverage_value_units,
            &self.price_feed_id,
            &self.price_aggregate_id,
        );
        if self.proof_root != expected_proof {
            return Err("zk oracle reserve disclosure proof root mismatch".to_string());
        }
        let expected = zk_oracle_reserve_disclosure_id(
            &self.subject_id,
            &self.private_envelope_id,
            &self.signature_transcript_id,
            &self.proof_root,
            self.published_at_height,
        );
        if self.disclosure_id != expected {
            return Err("zk oracle reserve disclosure id mismatch".to_string());
        }
        Ok(())
    }

    pub fn is_fresh_at(&self, height: u64) -> bool {
        self.status.is_live()
            && self.published_at_height <= height
            && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_reserve_disclosure",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "proof_system": ZK_ORACLE_RESERVE_PROOF_SYSTEM,
            "disclosure_id": self.disclosure_id,
            "subject_id": self.subject_id,
            "private_envelope_id": self.private_envelope_id,
            "signature_transcript_id": self.signature_transcript_id,
            "reserve_commitment_root": self.reserve_commitment_root,
            "liability_commitment_root": self.liability_commitment_root,
            "private_liability_root": self.private_liability_root,
            "reserve_value_units": self.reserve_value_units,
            "liability_value_units": self.liability_value_units,
            "coverage_value_units": self.coverage_value_units,
            "price_feed_id": self.price_feed_id,
            "price_aggregate_id": self.price_aggregate_id,
            "solvency_bps": self.solvency_bps,
            "coverage_bps": self.coverage_bps,
            "proof_root": self.proof_root,
            "published_at_height": self.published_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub disclosure_id: String,
    pub attester_set_id: String,
    pub attester_id: String,
    pub attester_weight: u64,
    pub disclosure_root: String,
    pub signature_transcript_id: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub status: AttestationStatus,
}

impl ReserveAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_id: &str,
        disclosure_id: &str,
        attester_set_id: &str,
        attester_id: &str,
        attester_weight: u64,
        disclosure_root: &str,
        signature_transcript_id: &str,
        signed_at_height: u64,
        expires_at_height: u64,
    ) -> ZkOracleResult<Self> {
        ensure_non_empty(subject_id, "zk oracle reserve attestation subject")?;
        ensure_non_empty(disclosure_id, "zk oracle reserve attestation disclosure")?;
        ensure_non_empty(attester_set_id, "zk oracle reserve attestation set")?;
        ensure_non_empty(attester_id, "zk oracle reserve attestation attester")?;
        ensure_positive(attester_weight, "zk oracle reserve attestation weight")?;
        ensure_non_empty(
            disclosure_root,
            "zk oracle reserve attestation disclosure root",
        )?;
        ensure_non_empty(
            signature_transcript_id,
            "zk oracle reserve attestation transcript",
        )?;
        if expires_at_height <= signed_at_height {
            return Err("zk oracle reserve attestation expiry must follow signing".to_string());
        }
        let attestation_id = zk_oracle_reserve_attestation_id(
            subject_id,
            disclosure_id,
            attester_set_id,
            attester_id,
            attester_weight,
            disclosure_root,
            signature_transcript_id,
            signed_at_height,
        );
        let attestation = Self {
            attestation_id,
            subject_id: subject_id.to_string(),
            disclosure_id: disclosure_id.to_string(),
            attester_set_id: attester_set_id.to_string(),
            attester_id: attester_id.to_string(),
            attester_weight,
            disclosure_root: disclosure_root.to_string(),
            signature_transcript_id: signature_transcript_id.to_string(),
            signed_at_height,
            expires_at_height,
            status: AttestationStatus::Active,
        };
        attestation.validate()?;
        Ok(attestation)
    }

    pub fn validate(&self) -> ZkOracleResult<()> {
        ensure_non_empty(&self.attestation_id, "zk oracle reserve attestation id")?;
        ensure_non_empty(&self.subject_id, "zk oracle reserve attestation subject")?;
        ensure_non_empty(
            &self.disclosure_id,
            "zk oracle reserve attestation disclosure",
        )?;
        ensure_non_empty(&self.attester_set_id, "zk oracle reserve attestation set")?;
        ensure_non_empty(&self.attester_id, "zk oracle reserve attestation attester")?;
        ensure_positive(self.attester_weight, "zk oracle reserve attestation weight")?;
        ensure_non_empty(
            &self.disclosure_root,
            "zk oracle reserve attestation disclosure root",
        )?;
        ensure_non_empty(
            &self.signature_transcript_id,
            "zk oracle reserve attestation transcript",
        )?;
        if self.expires_at_height <= self.signed_at_height {
            return Err("zk oracle reserve attestation expiry must follow signing".to_string());
        }
        let expected = zk_oracle_reserve_attestation_id(
            &self.subject_id,
            &self.disclosure_id,
            &self.attester_set_id,
            &self.attester_id,
            self.attester_weight,
            &self.disclosure_root,
            &self.signature_transcript_id,
            self.signed_at_height,
        );
        if self.attestation_id != expected {
            return Err("zk oracle reserve attestation id mismatch".to_string());
        }
        Ok(())
    }

    pub fn is_valid_at(&self, height: u64) -> bool {
        self.status.is_live() && self.signed_at_height <= height && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_reserve_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "subject_id": self.subject_id,
            "disclosure_id": self.disclosure_id,
            "attester_set_id": self.attester_set_id,
            "attester_id": self.attester_id,
            "attester_weight": self.attester_weight,
            "disclosure_root": self.disclosure_root,
            "signature_transcript_id": self.signature_transcript_id,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskPolicy {
    pub policy_id: String,
    pub market_id: String,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub price_feed_id: String,
    pub reserve_subject_id: String,
    pub collateral_factor_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub max_oracle_deviation_bps: u64,
    pub max_twap_deviation_bps: u64,
    pub max_reserve_staleness_blocks: u64,
    pub min_solvency_bps: u64,
    pub circuit_cooldown_blocks: u64,
    pub lane_id: String,
    pub metadata_root: String,
    pub active: bool,
}

impl RiskPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        collateral_asset_id: &str,
        debt_asset_id: &str,
        price_feed_id: &str,
        reserve_subject_id: &str,
        collateral_factor_bps: u64,
        liquidation_threshold_bps: u64,
        max_oracle_deviation_bps: u64,
        max_twap_deviation_bps: u64,
        max_reserve_staleness_blocks: u64,
        min_solvency_bps: u64,
        circuit_cooldown_blocks: u64,
        lane_id: &str,
        metadata: &Value,
    ) -> ZkOracleResult<Self> {
        ensure_non_empty(market_id, "zk oracle risk policy market")?;
        ensure_non_empty(collateral_asset_id, "zk oracle risk collateral asset")?;
        ensure_non_empty(debt_asset_id, "zk oracle risk debt asset")?;
        ensure_non_empty(price_feed_id, "zk oracle risk price feed")?;
        ensure_non_empty(reserve_subject_id, "zk oracle risk reserve subject")?;
        ensure_non_empty(lane_id, "zk oracle risk lane")?;
        validate_percent_bps(collateral_factor_bps, "zk oracle collateral factor")?;
        validate_percent_bps(liquidation_threshold_bps, "zk oracle liquidation threshold")?;
        validate_percent_bps(max_oracle_deviation_bps, "zk oracle max oracle deviation")?;
        validate_percent_bps(max_twap_deviation_bps, "zk oracle max twap deviation")?;
        ensure_positive(
            max_reserve_staleness_blocks,
            "zk oracle risk max reserve staleness",
        )?;
        ensure_positive(min_solvency_bps, "zk oracle risk min solvency")?;
        ensure_positive(circuit_cooldown_blocks, "zk oracle risk circuit cooldown")?;
        let metadata_root = zk_oracle_metadata_root(metadata);
        let policy_id = zk_oracle_risk_policy_id(
            market_id,
            collateral_asset_id,
            debt_asset_id,
            price_feed_id,
            reserve_subject_id,
            collateral_factor_bps,
            liquidation_threshold_bps,
            max_oracle_deviation_bps,
            max_twap_deviation_bps,
            max_reserve_staleness_blocks,
            min_solvency_bps,
            circuit_cooldown_blocks,
            lane_id,
            &metadata_root,
        );
        let policy = Self {
            policy_id,
            market_id: market_id.to_string(),
            collateral_asset_id: collateral_asset_id.to_string(),
            debt_asset_id: debt_asset_id.to_string(),
            price_feed_id: price_feed_id.to_string(),
            reserve_subject_id: reserve_subject_id.to_string(),
            collateral_factor_bps,
            liquidation_threshold_bps,
            max_oracle_deviation_bps,
            max_twap_deviation_bps,
            max_reserve_staleness_blocks,
            min_solvency_bps,
            circuit_cooldown_blocks,
            lane_id: lane_id.to_string(),
            metadata_root,
            active: true,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> ZkOracleResult<()> {
        ensure_non_empty(&self.policy_id, "zk oracle risk policy id")?;
        ensure_non_empty(&self.market_id, "zk oracle risk policy market")?;
        ensure_non_empty(&self.collateral_asset_id, "zk oracle risk collateral")?;
        ensure_non_empty(&self.debt_asset_id, "zk oracle risk debt")?;
        ensure_non_empty(&self.price_feed_id, "zk oracle risk price feed")?;
        ensure_non_empty(&self.reserve_subject_id, "zk oracle risk reserve subject")?;
        validate_percent_bps(self.collateral_factor_bps, "zk oracle collateral factor")?;
        validate_percent_bps(
            self.liquidation_threshold_bps,
            "zk oracle liquidation threshold",
        )?;
        validate_percent_bps(
            self.max_oracle_deviation_bps,
            "zk oracle max oracle deviation",
        )?;
        validate_percent_bps(self.max_twap_deviation_bps, "zk oracle max twap deviation")?;
        ensure_positive(
            self.max_reserve_staleness_blocks,
            "zk oracle reserve staleness",
        )?;
        ensure_positive(self.min_solvency_bps, "zk oracle min solvency")?;
        ensure_positive(self.circuit_cooldown_blocks, "zk oracle circuit cooldown")?;
        ensure_non_empty(&self.lane_id, "zk oracle risk lane")?;
        let expected = zk_oracle_risk_policy_id(
            &self.market_id,
            &self.collateral_asset_id,
            &self.debt_asset_id,
            &self.price_feed_id,
            &self.reserve_subject_id,
            self.collateral_factor_bps,
            self.liquidation_threshold_bps,
            self.max_oracle_deviation_bps,
            self.max_twap_deviation_bps,
            self.max_reserve_staleness_blocks,
            self.min_solvency_bps,
            self.circuit_cooldown_blocks,
            &self.lane_id,
            &self.metadata_root,
        );
        if self.policy_id != expected {
            return Err("zk oracle risk policy id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_risk_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "market_id": self.market_id,
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "price_feed_id": self.price_feed_id,
            "reserve_subject_id": self.reserve_subject_id,
            "collateral_factor_bps": self.collateral_factor_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "max_oracle_deviation_bps": self.max_oracle_deviation_bps,
            "max_twap_deviation_bps": self.max_twap_deviation_bps,
            "max_reserve_staleness_blocks": self.max_reserve_staleness_blocks,
            "min_solvency_bps": self.min_solvency_bps,
            "circuit_cooldown_blocks": self.circuit_cooldown_blocks,
            "lane_id": self.lane_id,
            "metadata_root": self.metadata_root,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub assessment_id: String,
    pub policy_id: String,
    pub market_id: String,
    pub feed_id: String,
    pub reserve_subject_id: String,
    pub aggregate_id: String,
    pub reserve_disclosure_id: String,
    pub price_deviation_bps: u64,
    pub twap_deviation_bps: u64,
    pub reserve_staleness_blocks: u64,
    pub reserve_solvency_bps: u64,
    pub health_score_bps: u64,
    pub severity: RiskSeverity,
    pub action: RiskAction,
    pub proof_root: String,
    pub assessed_at_height: u64,
    pub expires_at_height: u64,
}

impl RiskAssessment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_id: &str,
        market_id: &str,
        feed_id: &str,
        reserve_subject_id: &str,
        aggregate_id: &str,
        reserve_disclosure_id: &str,
        price_deviation_bps: u64,
        twap_deviation_bps: u64,
        reserve_staleness_blocks: u64,
        reserve_solvency_bps: u64,
        assessed_at_height: u64,
        expires_at_height: u64,
    ) -> ZkOracleResult<Self> {
        ensure_non_empty(policy_id, "zk oracle risk assessment policy")?;
        ensure_non_empty(market_id, "zk oracle risk assessment market")?;
        ensure_non_empty(feed_id, "zk oracle risk assessment feed")?;
        ensure_non_empty(
            reserve_subject_id,
            "zk oracle risk assessment reserve subject",
        )?;
        ensure_non_empty(aggregate_id, "zk oracle risk assessment aggregate")?;
        ensure_non_empty(
            reserve_disclosure_id,
            "zk oracle risk assessment reserve disclosure",
        )?;
        if expires_at_height <= assessed_at_height {
            return Err("zk oracle risk assessment expiry must follow assessment".to_string());
        }
        let health_score_bps = risk_score_bps(
            price_deviation_bps,
            twap_deviation_bps,
            reserve_staleness_blocks,
            reserve_solvency_bps,
        );
        let severity = severity_from_score(health_score_bps);
        let action = action_from_severity(severity);
        let proof_root = zk_oracle_risk_assessment_proof_root(
            policy_id,
            aggregate_id,
            reserve_disclosure_id,
            price_deviation_bps,
            twap_deviation_bps,
            reserve_staleness_blocks,
            reserve_solvency_bps,
            health_score_bps,
            severity.as_str(),
            action.as_str(),
        );
        let assessment_id = zk_oracle_risk_assessment_id(
            policy_id,
            market_id,
            aggregate_id,
            reserve_disclosure_id,
            &proof_root,
            assessed_at_height,
        );
        let assessment = Self {
            assessment_id,
            policy_id: policy_id.to_string(),
            market_id: market_id.to_string(),
            feed_id: feed_id.to_string(),
            reserve_subject_id: reserve_subject_id.to_string(),
            aggregate_id: aggregate_id.to_string(),
            reserve_disclosure_id: reserve_disclosure_id.to_string(),
            price_deviation_bps,
            twap_deviation_bps,
            reserve_staleness_blocks,
            reserve_solvency_bps,
            health_score_bps,
            severity,
            action,
            proof_root,
            assessed_at_height,
            expires_at_height,
        };
        assessment.validate()?;
        Ok(assessment)
    }

    pub fn validate(&self) -> ZkOracleResult<()> {
        ensure_non_empty(&self.assessment_id, "zk oracle risk assessment id")?;
        ensure_non_empty(&self.policy_id, "zk oracle risk assessment policy")?;
        ensure_non_empty(&self.market_id, "zk oracle risk assessment market")?;
        ensure_non_empty(&self.feed_id, "zk oracle risk assessment feed")?;
        ensure_non_empty(
            &self.reserve_subject_id,
            "zk oracle risk assessment reserve subject",
        )?;
        ensure_non_empty(&self.aggregate_id, "zk oracle risk assessment aggregate")?;
        ensure_non_empty(
            &self.reserve_disclosure_id,
            "zk oracle risk assessment disclosure",
        )?;
        ensure_non_empty(&self.proof_root, "zk oracle risk assessment proof")?;
        if self.expires_at_height <= self.assessed_at_height {
            return Err("zk oracle risk assessment expiry must follow assessment".to_string());
        }
        let expected_score = risk_score_bps(
            self.price_deviation_bps,
            self.twap_deviation_bps,
            self.reserve_staleness_blocks,
            self.reserve_solvency_bps,
        );
        if self.health_score_bps != expected_score {
            return Err("zk oracle risk assessment score mismatch".to_string());
        }
        let expected_proof = zk_oracle_risk_assessment_proof_root(
            &self.policy_id,
            &self.aggregate_id,
            &self.reserve_disclosure_id,
            self.price_deviation_bps,
            self.twap_deviation_bps,
            self.reserve_staleness_blocks,
            self.reserve_solvency_bps,
            self.health_score_bps,
            self.severity.as_str(),
            self.action.as_str(),
        );
        if self.proof_root != expected_proof {
            return Err("zk oracle risk assessment proof mismatch".to_string());
        }
        let expected_id = zk_oracle_risk_assessment_id(
            &self.policy_id,
            &self.market_id,
            &self.aggregate_id,
            &self.reserve_disclosure_id,
            &self.proof_root,
            self.assessed_at_height,
        );
        if self.assessment_id != expected_id {
            return Err("zk oracle risk assessment id mismatch".to_string());
        }
        Ok(())
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.assessed_at_height <= height && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_risk_assessment",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "proof_system": ZK_ORACLE_RISK_PROOF_SYSTEM,
            "assessment_id": self.assessment_id,
            "policy_id": self.policy_id,
            "market_id": self.market_id,
            "feed_id": self.feed_id,
            "reserve_subject_id": self.reserve_subject_id,
            "aggregate_id": self.aggregate_id,
            "reserve_disclosure_id": self.reserve_disclosure_id,
            "price_deviation_bps": self.price_deviation_bps,
            "twap_deviation_bps": self.twap_deviation_bps,
            "reserve_staleness_blocks": self.reserve_staleness_blocks,
            "reserve_solvency_bps": self.reserve_solvency_bps,
            "health_score_bps": self.health_score_bps,
            "severity": self.severity.as_str(),
            "action": self.action.as_str(),
            "proof_root": self.proof_root,
            "assessed_at_height": self.assessed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorPolicy {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub lane_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_per_update_units: u64,
    pub start_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
    pub status: SponsorPolicyStatus,
}

impl LowFeeSponsorPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_label: &str,
        fee_asset_id: &str,
        lane_id: &str,
        budget_units: u64,
        max_per_update_units: u64,
        start_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> ZkOracleResult<Self> {
        ensure_non_empty(sponsor_label, "zk oracle sponsor label")?;
        ensure_non_empty(fee_asset_id, "zk oracle sponsor fee asset")?;
        ensure_non_empty(lane_id, "zk oracle sponsor lane")?;
        ensure_positive(budget_units, "zk oracle sponsor budget")?;
        ensure_positive(max_per_update_units, "zk oracle sponsor per-update cap")?;
        if expires_at_height <= start_height {
            return Err("zk oracle sponsor expiry must follow start".to_string());
        }
        let sponsor_commitment = zk_oracle_string_commitment("ZK-ORACLE-SPONSOR", sponsor_label);
        let metadata_root = zk_oracle_metadata_root(metadata);
        let sponsor_id = zk_oracle_sponsor_policy_id(
            &sponsor_commitment,
            fee_asset_id,
            lane_id,
            budget_units,
            max_per_update_units,
            start_height,
            expires_at_height,
            &metadata_root,
        );
        let policy = Self {
            sponsor_id,
            sponsor_commitment,
            fee_asset_id: fee_asset_id.to_string(),
            lane_id: lane_id.to_string(),
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            max_per_update_units,
            start_height,
            expires_at_height,
            metadata_root,
            status: SponsorPolicyStatus::Active,
        };
        policy.validate_static()?;
        Ok(policy)
    }

    pub fn validate_static(&self) -> ZkOracleResult<()> {
        ensure_non_empty(&self.sponsor_id, "zk oracle sponsor id")?;
        ensure_non_empty(&self.sponsor_commitment, "zk oracle sponsor commitment")?;
        ensure_non_empty(&self.fee_asset_id, "zk oracle sponsor fee asset")?;
        ensure_non_empty(&self.lane_id, "zk oracle sponsor lane")?;
        ensure_positive(self.budget_units, "zk oracle sponsor budget")?;
        ensure_positive(
            self.max_per_update_units,
            "zk oracle sponsor per-update cap",
        )?;
        if self.expires_at_height <= self.start_height {
            return Err("zk oracle sponsor expiry must follow start".to_string());
        }
        if self.reserved_units.saturating_add(self.spent_units) > self.budget_units {
            return Err("zk oracle sponsor accounting exceeds budget".to_string());
        }
        let expected = zk_oracle_sponsor_policy_id(
            &self.sponsor_commitment,
            &self.fee_asset_id,
            &self.lane_id,
            self.budget_units,
            self.max_per_update_units,
            self.start_height,
            self.expires_at_height,
            &self.metadata_root,
        );
        if self.sponsor_id != expected {
            return Err("zk oracle sponsor id mismatch".to_string());
        }
        Ok(())
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn can_sponsor_at(&self, height: u64) -> bool {
        self.status.can_spend()
            && self.start_height <= height
            && height < self.expires_at_height
            && self.available_units() > 0
    }

    pub fn utilization_bps(&self) -> u64 {
        ratio_bps(
            self.reserved_units.saturating_add(self.spent_units),
            self.budget_units,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_low_fee_sponsor_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "lane_id": self.lane_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "max_per_update_units": self.max_per_update_units,
            "start_height": self.start_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
            "status": self.status.as_str(),
            "utilization_bps": self.utilization_bps(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorshipReceipt {
    pub receipt_id: String,
    pub sponsor_id: String,
    pub lane_id: String,
    pub subject_id: String,
    pub update_kind: PrivateUpdateKind,
    pub caller_commitment: String,
    pub private_envelope_id: String,
    pub gross_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorshipReceiptStatus,
}

impl SponsorshipReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_id: &str,
        lane_id: &str,
        subject_id: &str,
        update_kind: PrivateUpdateKind,
        caller_label: &str,
        private_envelope_id: &str,
        gross_fee_units: u64,
        sponsored_fee_units: u64,
        issued_at_height: u64,
        expires_at_height: u64,
    ) -> ZkOracleResult<Self> {
        ensure_non_empty(sponsor_id, "zk oracle sponsorship sponsor")?;
        ensure_non_empty(lane_id, "zk oracle sponsorship lane")?;
        ensure_non_empty(subject_id, "zk oracle sponsorship subject")?;
        ensure_non_empty(caller_label, "zk oracle sponsorship caller")?;
        ensure_non_empty(
            private_envelope_id,
            "zk oracle sponsorship private envelope",
        )?;
        ensure_positive(gross_fee_units, "zk oracle sponsorship gross fee")?;
        if sponsored_fee_units > gross_fee_units {
            return Err("zk oracle sponsorship cannot exceed gross fee".to_string());
        }
        if expires_at_height <= issued_at_height {
            return Err("zk oracle sponsorship expiry must follow issue height".to_string());
        }
        let caller_commitment =
            zk_oracle_string_commitment("ZK-ORACLE-SPONSORED-CALLER", caller_label);
        let receipt_id = zk_oracle_sponsorship_receipt_id(
            sponsor_id,
            lane_id,
            subject_id,
            update_kind.as_str(),
            &caller_commitment,
            private_envelope_id,
            gross_fee_units,
            sponsored_fee_units,
            issued_at_height,
        );
        let receipt = Self {
            receipt_id,
            sponsor_id: sponsor_id.to_string(),
            lane_id: lane_id.to_string(),
            subject_id: subject_id.to_string(),
            update_kind,
            caller_commitment,
            private_envelope_id: private_envelope_id.to_string(),
            gross_fee_units,
            sponsored_fee_units,
            issued_at_height,
            expires_at_height,
            status: SponsorshipReceiptStatus::Applied,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> ZkOracleResult<()> {
        ensure_non_empty(&self.receipt_id, "zk oracle sponsorship receipt id")?;
        ensure_non_empty(&self.sponsor_id, "zk oracle sponsorship sponsor")?;
        ensure_non_empty(&self.lane_id, "zk oracle sponsorship lane")?;
        ensure_non_empty(&self.subject_id, "zk oracle sponsorship subject")?;
        ensure_non_empty(&self.caller_commitment, "zk oracle sponsorship caller")?;
        ensure_non_empty(
            &self.private_envelope_id,
            "zk oracle sponsorship private envelope",
        )?;
        ensure_positive(self.gross_fee_units, "zk oracle sponsorship gross fee")?;
        if self.sponsored_fee_units > self.gross_fee_units {
            return Err("zk oracle sponsorship cannot exceed gross fee".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("zk oracle sponsorship expiry must follow issue height".to_string());
        }
        let expected = zk_oracle_sponsorship_receipt_id(
            &self.sponsor_id,
            &self.lane_id,
            &self.subject_id,
            self.update_kind.as_str(),
            &self.caller_commitment,
            &self.private_envelope_id,
            self.gross_fee_units,
            self.sponsored_fee_units,
            self.issued_at_height,
        );
        if self.receipt_id != expected {
            return Err("zk oracle sponsorship receipt id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_sponsorship_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "sponsor_id": self.sponsor_id,
            "lane_id": self.lane_id,
            "subject_id": self.subject_id,
            "update_kind": self.update_kind.as_str(),
            "caller_commitment": self.caller_commitment,
            "private_envelope_id": self.private_envelope_id,
            "gross_fee_units": self.gross_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "net_fee_units": self.gross_fee_units.saturating_sub(self.sponsored_fee_units),
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitDecision {
    pub decision_id: String,
    pub market_id: String,
    pub subject_id: String,
    pub assessment_id: String,
    pub action: RiskAction,
    pub severity: RiskSeverity,
    pub reason_root: String,
    pub opened_at_height: u64,
    pub cooldown_until_height: u64,
    pub status: CircuitDecisionStatus,
}

impl CircuitDecision {
    pub fn new(
        market_id: &str,
        subject_id: &str,
        assessment_id: &str,
        action: RiskAction,
        severity: RiskSeverity,
        reason: &Value,
        opened_at_height: u64,
        cooldown_blocks: u64,
    ) -> ZkOracleResult<Self> {
        ensure_non_empty(market_id, "zk oracle circuit market")?;
        ensure_non_empty(subject_id, "zk oracle circuit subject")?;
        ensure_non_empty(assessment_id, "zk oracle circuit assessment")?;
        ensure_positive(cooldown_blocks, "zk oracle circuit cooldown")?;
        let reason_root = zk_oracle_payload_root("ZK-ORACLE-CIRCUIT-REASON", reason);
        let cooldown_until_height = opened_at_height.saturating_add(cooldown_blocks);
        let decision_id = zk_oracle_circuit_decision_id(
            market_id,
            subject_id,
            assessment_id,
            action.as_str(),
            severity.as_str(),
            &reason_root,
            opened_at_height,
            cooldown_until_height,
        );
        let decision = Self {
            decision_id,
            market_id: market_id.to_string(),
            subject_id: subject_id.to_string(),
            assessment_id: assessment_id.to_string(),
            action,
            severity,
            reason_root,
            opened_at_height,
            cooldown_until_height,
            status: CircuitDecisionStatus::Open,
        };
        decision.validate()?;
        Ok(decision)
    }

    pub fn validate(&self) -> ZkOracleResult<()> {
        ensure_non_empty(&self.decision_id, "zk oracle circuit decision id")?;
        ensure_non_empty(&self.market_id, "zk oracle circuit market")?;
        ensure_non_empty(&self.subject_id, "zk oracle circuit subject")?;
        ensure_non_empty(&self.assessment_id, "zk oracle circuit assessment")?;
        ensure_non_empty(&self.reason_root, "zk oracle circuit reason root")?;
        if self.cooldown_until_height <= self.opened_at_height {
            return Err("zk oracle circuit cooldown must follow open height".to_string());
        }
        let expected = zk_oracle_circuit_decision_id(
            &self.market_id,
            &self.subject_id,
            &self.assessment_id,
            self.action.as_str(),
            self.severity.as_str(),
            &self.reason_root,
            self.opened_at_height,
            self.cooldown_until_height,
        );
        if self.decision_id != expected {
            return Err("zk oracle circuit decision id mismatch".to_string());
        }
        Ok(())
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.is_active() && height < self.cooldown_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_circuit_decision",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "decision_id": self.decision_id,
            "market_id": self.market_id,
            "subject_id": self.subject_id,
            "assessment_id": self.assessment_id,
            "action": self.action.as_str(),
            "severity": self.severity.as_str(),
            "reason_root": self.reason_root,
            "opened_at_height": self.opened_at_height,
            "cooldown_until_height": self.cooldown_until_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleAuditEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub event_root: String,
    pub emitted_at_height: u64,
}

impl OracleAuditEvent {
    pub fn new(
        event_kind: &str,
        subject_id: &str,
        event: &Value,
        height: u64,
    ) -> ZkOracleResult<Self> {
        ensure_non_empty(event_kind, "zk oracle audit event kind")?;
        ensure_non_empty(subject_id, "zk oracle audit subject")?;
        let event_root = zk_oracle_payload_root("ZK-ORACLE-AUDIT-EVENT", event);
        let event_id = zk_oracle_audit_event_id(event_kind, subject_id, &event_root, height);
        Ok(Self {
            event_id,
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            event_root,
            emitted_at_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_audit_event",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "event_root": self.event_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkOracleStateRoots {
    pub config_root: String,
    pub lane_root: String,
    pub feed_root: String,
    pub publisher_root: String,
    pub transcript_root: String,
    pub private_envelope_root: String,
    pub observation_root: String,
    pub aggregate_root: String,
    pub update_receipt_root: String,
    pub reserve_subject_root: String,
    pub reserve_attester_root: String,
    pub reserve_attester_set_root: String,
    pub reserve_disclosure_root: String,
    pub reserve_attestation_root: String,
    pub risk_policy_root: String,
    pub risk_assessment_root: String,
    pub sponsor_policy_root: String,
    pub sponsorship_receipt_root: String,
    pub circuit_decision_root: String,
    pub audit_event_root: String,
}

impl ZkOracleStateRoots {
    pub fn state_root(&self) -> String {
        zk_oracle_payload_root("ZK-ORACLE-STATE-ROOTS", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_oracle_state_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "feed_root": self.feed_root,
            "publisher_root": self.publisher_root,
            "transcript_root": self.transcript_root,
            "private_envelope_root": self.private_envelope_root,
            "observation_root": self.observation_root,
            "aggregate_root": self.aggregate_root,
            "update_receipt_root": self.update_receipt_root,
            "reserve_subject_root": self.reserve_subject_root,
            "reserve_attester_root": self.reserve_attester_root,
            "reserve_attester_set_root": self.reserve_attester_set_root,
            "reserve_disclosure_root": self.reserve_disclosure_root,
            "reserve_attestation_root": self.reserve_attestation_root,
            "risk_policy_root": self.risk_policy_root,
            "risk_assessment_root": self.risk_assessment_root,
            "sponsor_policy_root": self.sponsor_policy_root,
            "sponsorship_receipt_root": self.sponsorship_receipt_root,
            "circuit_decision_root": self.circuit_decision_root,
            "audit_event_root": self.audit_event_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkOracleState {
    pub config: ZkOracleConfig,
    pub height: u64,
    pub lanes: BTreeMap<String, LatencyLane>,
    pub feeds: BTreeMap<String, PriceFeed>,
    pub publishers: BTreeMap<String, OraclePublisher>,
    pub transcripts: BTreeMap<String, PqSignatureTranscript>,
    pub private_envelopes: BTreeMap<String, PrivateUpdateEnvelope>,
    pub observations: BTreeMap<String, Vec<PriceObservation>>,
    pub aggregates: BTreeMap<String, PriceAggregate>,
    pub update_receipts: BTreeMap<String, ZkOracleUpdateReceipt>,
    pub reserve_subjects: BTreeMap<String, ReserveSubject>,
    pub reserve_attesters: BTreeMap<String, ReserveAttester>,
    pub reserve_attester_sets: BTreeMap<String, ReserveAttesterSet>,
    pub reserve_disclosures: BTreeMap<String, ReserveDisclosure>,
    pub reserve_attestations: BTreeMap<String, ReserveAttestation>,
    pub risk_policies: BTreeMap<String, RiskPolicy>,
    pub risk_assessments: BTreeMap<String, RiskAssessment>,
    pub sponsor_policies: BTreeMap<String, LowFeeSponsorPolicy>,
    pub sponsorship_receipts: BTreeMap<String, SponsorshipReceipt>,
    pub circuit_decisions: BTreeMap<String, CircuitDecision>,
    pub audit_events: BTreeMap<String, OracleAuditEvent>,
}

impl Default for ZkOracleState {
    fn default() -> Self {
        Self::new(ZkOracleConfig::default())
    }
}

impl ZkOracleState {
    pub fn new(config: ZkOracleConfig) -> Self {
        Self {
            config,
            height: 0,
            lanes: BTreeMap::new(),
            feeds: BTreeMap::new(),
            publishers: BTreeMap::new(),
            transcripts: BTreeMap::new(),
            private_envelopes: BTreeMap::new(),
            observations: BTreeMap::new(),
            aggregates: BTreeMap::new(),
            update_receipts: BTreeMap::new(),
            reserve_subjects: BTreeMap::new(),
            reserve_attesters: BTreeMap::new(),
            reserve_attester_sets: BTreeMap::new(),
            reserve_disclosures: BTreeMap::new(),
            reserve_attestations: BTreeMap::new(),
            risk_policies: BTreeMap::new(),
            risk_assessments: BTreeMap::new(),
            sponsor_policies: BTreeMap::new(),
            sponsorship_receipts: BTreeMap::new(),
            circuit_decisions: BTreeMap::new(),
            audit_events: BTreeMap::new(),
        }
    }

    pub fn devnet() -> ZkOracleResult<Self> {
        let mut state = Self::new(ZkOracleConfig::default());
        state.config.validate()?;
        state.set_height(ZK_ORACLE_DEVNET_HEIGHT);

        let fast_lane = LatencyLane::new(
            LatencyLaneKind::FastPrice,
            ZK_ORACLE_FAST_PRICE_LANE,
            1_500,
            8,
            100,
            ZK_ORACLE_DEFAULT_LOW_FEE_UNITS,
            1_024,
        )?;
        let reserve_lane = LatencyLane::new(
            LatencyLaneKind::Reserve,
            ZK_ORACLE_RESERVE_LANE,
            6_000,
            32,
            50,
            ZK_ORACLE_DEFAULT_RESERVE_FEE_UNITS,
            2_048,
        )?;
        let risk_lane = LatencyLane::new(
            LatencyLaneKind::Risk,
            ZK_ORACLE_RISK_LANE,
            2_500,
            16,
            80,
            ZK_ORACLE_DEFAULT_RISK_FEE_UNITS,
            1_536,
        )?;
        let backfill_lane = LatencyLane::new(
            LatencyLaneKind::Backfill,
            ZK_ORACLE_BACKFILL_LANE,
            ZK_ORACLE_DEFAULT_SLOW_LANE_MS,
            128,
            10,
            1,
            512,
        )?;
        state.insert_lane(fast_lane.clone())?;
        state.insert_lane(reserve_lane.clone())?;
        state.insert_lane(risk_lane.clone())?;
        state.insert_lane(backfill_lane.clone())?;

        let mut fast_permissions = BTreeSet::new();
        fast_permissions.insert(fast_lane.lane_id.clone());
        fast_permissions.insert(backfill_lane.lane_id.clone());
        let mut reserve_permissions = BTreeSet::new();
        reserve_permissions.insert(reserve_lane.lane_id.clone());
        reserve_permissions.insert(risk_lane.lane_id.clone());
        let mut committee_permissions = BTreeSet::new();
        committee_permissions.insert(risk_lane.lane_id.clone());
        committee_permissions.insert(reserve_lane.lane_id.clone());

        let publisher_a = OraclePublisher::new(
            "devnet-pyth-xmr",
            PublisherRole::Oracle,
            &zk_oracle_string_commitment("DEVNET-PQ-KEY", "pyth-xmr-ml-dsa"),
            2_500_000,
            4_000,
            512,
            fast_permissions.clone(),
            &json!({"region": "devnet-a", "feed_coverage": ["wxmr/usdd", "xbtc/usdd"]}),
        )?;
        let publisher_b = OraclePublisher::new(
            "devnet-chainlink-xmr",
            PublisherRole::Oracle,
            &zk_oracle_string_commitment("DEVNET-PQ-KEY", "chainlink-xmr-ml-dsa"),
            2_000_000,
            3_500,
            512,
            fast_permissions.clone(),
            &json!({"region": "devnet-b", "feed_coverage": ["wxmr/usdd", "xeth/usdd"]}),
        )?;
        let publisher_c = OraclePublisher::new(
            "devnet-nebula-watch",
            PublisherRole::Watchtower,
            &zk_oracle_string_commitment("DEVNET-PQ-KEY", "nebula-watch-ml-dsa"),
            1_500_000,
            2_500,
            512,
            fast_permissions.clone(),
            &json!({"region": "devnet-c", "feed_coverage": ["wxmr/usdd", "xbtc/usdd", "xeth/usdd"]}),
        )?;
        state.insert_publisher(publisher_a.clone())?;
        state.insert_publisher(publisher_b.clone())?;
        state.insert_publisher(publisher_c.clone())?;

        let wxmr_feed = PriceFeed::new(
            PriceFeedKind::Spot,
            ZK_ORACLE_DEVNET_WXMR_ASSET_ID,
            ZK_ORACLE_DEVNET_USDD_ASSET_ID,
            ZK_ORACLE_DEFAULT_DECIMALS,
            2,
            ZK_ORACLE_DEFAULT_HEARTBEAT_BLOCKS,
            ZK_ORACLE_DEFAULT_TWAP_WINDOW_BLOCKS,
            800,
            &fast_lane.lane_id,
            UpdateVisibility::Private,
            &json!({"pair": "WXMR/USDD", "venue_set": "devnet-private-oracles"}),
        )?;
        let btc_feed = PriceFeed::new(
            PriceFeedKind::Spot,
            ZK_ORACLE_DEVNET_BTC_ASSET_ID,
            ZK_ORACLE_DEVNET_USDD_ASSET_ID,
            ZK_ORACLE_DEFAULT_DECIMALS,
            2,
            ZK_ORACLE_DEFAULT_HEARTBEAT_BLOCKS,
            144,
            650,
            &fast_lane.lane_id,
            UpdateVisibility::Shielded,
            &json!({"pair": "XBTC/USDD", "venue_set": "devnet-blue-chip"}),
        )?;
        let eth_feed = PriceFeed::new(
            PriceFeedKind::Spot,
            ZK_ORACLE_DEVNET_ETH_ASSET_ID,
            ZK_ORACLE_DEVNET_USDD_ASSET_ID,
            ZK_ORACLE_DEFAULT_DECIMALS,
            2,
            ZK_ORACLE_DEFAULT_HEARTBEAT_BLOCKS,
            144,
            700,
            &fast_lane.lane_id,
            UpdateVisibility::AggregateOnly,
            &json!({"pair": "XETH/USDD", "venue_set": "devnet-blue-chip"}),
        )?;
        state.insert_price_feed(wxmr_feed.clone())?;
        state.insert_price_feed(btc_feed.clone())?;
        state.insert_price_feed(eth_feed.clone())?;

        let sponsor_fast = LowFeeSponsorPolicy::new(
            "devnet-oracle-sponsor",
            ZK_ORACLE_DEVNET_FEE_ASSET_ID,
            &fast_lane.lane_id,
            1_000,
            3,
            state.height,
            state.height + 720,
            &json!({"purpose": "sponsor private price ticks for small DeFi accounts"}),
        )?;
        let sponsor_reserve = LowFeeSponsorPolicy::new(
            "devnet-reserve-sponsor",
            ZK_ORACLE_DEVNET_FEE_ASSET_ID,
            &reserve_lane.lane_id,
            700,
            5,
            state.height,
            state.height + 720,
            &json!({"purpose": "sponsor reserve and solvency attestations"}),
        )?;
        let sponsor_risk = LowFeeSponsorPolicy::new(
            "devnet-risk-sponsor",
            ZK_ORACLE_DEVNET_FEE_ASSET_ID,
            &risk_lane.lane_id,
            400,
            4,
            state.height,
            state.height + 720,
            &json!({"purpose": "sponsor private liquidation guard checks"}),
        )?;
        state.insert_sponsor_policy(sponsor_fast)?;
        state.insert_sponsor_policy(sponsor_reserve)?;
        state.insert_sponsor_policy(sponsor_risk)?;

        state.submit_private_price_update(
            &wxmr_feed.feed_id,
            &publisher_a.publisher_id,
            1,
            173_250_000_000_000,
            9_600,
            state.height,
            1_718_000_010_000,
            720,
            "devnet-price-caller-a",
        )?;
        state.submit_private_price_update(
            &wxmr_feed.feed_id,
            &publisher_b.publisher_id,
            1,
            173_900_000_000_000,
            9_450,
            state.height,
            1_718_000_010_250,
            860,
            "devnet-price-caller-b",
        )?;
        state.submit_private_price_update(
            &wxmr_feed.feed_id,
            &publisher_c.publisher_id,
            1,
            172_800_000_000_000,
            9_500,
            state.height,
            1_718_000_010_480,
            930,
            "devnet-price-caller-c",
        )?;
        state.submit_private_price_update(
            &btc_feed.feed_id,
            &publisher_a.publisher_id,
            1,
            68_250_000_000_000_000,
            9_700,
            state.height,
            1_718_000_011_000,
            940,
            "devnet-price-caller-a",
        )?;
        state.submit_private_price_update(
            &btc_feed.feed_id,
            &publisher_c.publisher_id,
            1,
            68_190_000_000_000_000,
            9_650,
            state.height,
            1_718_000_011_300,
            1_020,
            "devnet-price-caller-c",
        )?;
        state.submit_private_price_update(
            &eth_feed.feed_id,
            &publisher_b.publisher_id,
            1,
            3_580_000_000_000_000,
            9_500,
            state.height,
            1_718_000_011_600,
            1_110,
            "devnet-price-caller-b",
        )?;
        state.submit_private_price_update(
            &eth_feed.feed_id,
            &publisher_c.publisher_id,
            1,
            3_575_000_000_000_000,
            9_540,
            state.height,
            1_718_000_011_820,
            1_200,
            "devnet-price-caller-c",
        )?;

        let attester_a = ReserveAttester::new(
            "devnet-custodian-a",
            PublisherRole::ReserveAttester,
            &zk_oracle_string_commitment("DEVNET-PQ-KEY", "custodian-a-slh-dsa"),
            2,
        )?;
        let attester_b = ReserveAttester::new(
            "devnet-watchtower-b",
            PublisherRole::Watchtower,
            &zk_oracle_string_commitment("DEVNET-PQ-KEY", "watchtower-b-slh-dsa"),
            2,
        )?;
        let attester_c = ReserveAttester::new(
            "devnet-auditor-c",
            PublisherRole::RiskCommittee,
            &zk_oracle_string_commitment("DEVNET-PQ-KEY", "auditor-c-slh-dsa"),
            1,
        )?;
        state.insert_reserve_attester(attester_a.clone())?;
        state.insert_reserve_attester(attester_b.clone())?;
        state.insert_reserve_attester(attester_c.clone())?;
        let mut set_members = BTreeSet::new();
        set_members.insert(attester_a.attester_id.clone());
        set_members.insert(attester_b.attester_id.clone());
        set_members.insert(attester_c.attester_id.clone());
        let attester_set = ReserveAttesterSet::new(
            "devnet-reserve-set-0",
            set_members,
            3,
            state.height,
            state.height + 1_440,
            &json!({"rotation": "devnet-initial", "quorum": "2-of-3-weighted"}),
        )?;
        state.insert_reserve_attester_set(attester_set.clone())?;

        let reserve_subject = ReserveSubject::new(
            ReserveSubjectKind::WrappedXmrReserve,
            "wxmr-bridge-reserve",
            "nebula-devnet-bridge-operator",
            ZK_ORACLE_DEVNET_WXMR_ASSET_ID,
            ZK_ORACLE_DEVNET_WXMR_ASSET_ID,
            &wxmr_feed.feed_id,
            10_800,
            12_000,
            36,
            24,
            8,
            &attester_set.attester_set_id,
            &reserve_lane.lane_id,
            &json!({"reserve_account": "devnet-hidden-view-key", "liability_scope": "wrapped-xmr"}),
        )?;
        state.insert_reserve_subject(reserve_subject.clone())?;
        let disclosure = state.publish_reserve_disclosure(
            &reserve_subject.subject_id,
            5_820_000_000_000_000,
            5_250_000_000_000_000,
            6_400_000_000_000_000,
            "devnet-reserve-publisher",
        )?;
        state.attest_reserve_disclosure(
            &attester_set.attester_set_id,
            &attester_a.attester_id,
            &disclosure.disclosure_id,
        )?;
        state.attest_reserve_disclosure(
            &attester_set.attester_set_id,
            &attester_b.attester_id,
            &disclosure.disclosure_id,
        )?;

        let risk_policy = RiskPolicy::new(
            "lending-wxmr-usdd-devnet",
            ZK_ORACLE_DEVNET_WXMR_ASSET_ID,
            ZK_ORACLE_DEVNET_USDD_ASSET_ID,
            &wxmr_feed.feed_id,
            &reserve_subject.subject_id,
            7_500,
            8_250,
            800,
            600,
            36,
            10_800,
            24,
            &risk_lane.lane_id,
            &json!({"market": "private lending", "liquidation_guard": true}),
        )?;
        state.insert_risk_policy(risk_policy.clone())?;
        state.assess_market(
            &risk_policy.policy_id,
            &wxmr_feed.feed_id,
            &reserve_subject.subject_id,
            &disclosure.disclosure_id,
        )?;

        state.emit_audit_event(
            "devnet_seeded",
            "zk_oracle_state",
            &json!({
                "lanes": state.lanes.len(),
                "feeds": state.feeds.len(),
                "publishers": state.publishers.len(),
                "reserve_subjects": state.reserve_subjects.len(),
                "risk_policies": state.risk_policies.len(),
            }),
        )?;

        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for sponsor in self.sponsor_policies.values_mut() {
            if height >= sponsor.expires_at_height && sponsor.status == SponsorPolicyStatus::Active
            {
                sponsor.status = SponsorPolicyStatus::Expired;
            } else if sponsor.available_units() == 0
                && sponsor.status == SponsorPolicyStatus::Active
            {
                sponsor.status = SponsorPolicyStatus::Exhausted;
            }
        }
        for decision in self.circuit_decisions.values_mut() {
            if decision.status == CircuitDecisionStatus::Open
                && height >= decision.cooldown_until_height
            {
                decision.status = CircuitDecisionStatus::CoolingDown;
            }
        }
    }

    pub fn insert_lane(&mut self, lane: LatencyLane) -> ZkOracleResult<LatencyLane> {
        lane.validate()?;
        if self.lanes.contains_key(&lane.lane_id) {
            return Err("zk oracle lane already exists".to_string());
        }
        self.lanes.insert(lane.lane_id.clone(), lane.clone());
        Ok(lane)
    }

    pub fn insert_price_feed(&mut self, feed: PriceFeed) -> ZkOracleResult<PriceFeed> {
        feed.validate()?;
        self.require_lane(&feed.lane_id)?;
        if self.feeds.contains_key(&feed.feed_id) {
            return Err("zk oracle price feed already exists".to_string());
        }
        self.feeds.insert(feed.feed_id.clone(), feed.clone());
        Ok(feed)
    }

    pub fn insert_publisher(
        &mut self,
        publisher: OraclePublisher,
    ) -> ZkOracleResult<OraclePublisher> {
        publisher.validate()?;
        for lane_id in &publisher.lane_permissions {
            self.require_lane(lane_id)?;
        }
        if self.publishers.contains_key(&publisher.publisher_id) {
            return Err("zk oracle publisher already exists".to_string());
        }
        self.publishers
            .insert(publisher.publisher_id.clone(), publisher.clone());
        Ok(publisher)
    }

    pub fn insert_reserve_attester(
        &mut self,
        attester: ReserveAttester,
    ) -> ZkOracleResult<ReserveAttester> {
        attester.validate()?;
        if self.reserve_attesters.contains_key(&attester.attester_id) {
            return Err("zk oracle reserve attester already exists".to_string());
        }
        self.reserve_attesters
            .insert(attester.attester_id.clone(), attester.clone());
        Ok(attester)
    }

    pub fn insert_reserve_attester_set(
        &mut self,
        attester_set: ReserveAttesterSet,
    ) -> ZkOracleResult<ReserveAttesterSet> {
        attester_set.validate()?;
        for attester_id in &attester_set.attester_ids {
            if !self.reserve_attesters.contains_key(attester_id) {
                return Err(format!(
                    "zk oracle reserve attester {attester_id} is unknown"
                ));
            }
        }
        if self
            .reserve_attester_sets
            .contains_key(&attester_set.attester_set_id)
        {
            return Err("zk oracle reserve attester set already exists".to_string());
        }
        self.reserve_attester_sets
            .insert(attester_set.attester_set_id.clone(), attester_set.clone());
        Ok(attester_set)
    }

    pub fn insert_reserve_subject(
        &mut self,
        subject: ReserveSubject,
    ) -> ZkOracleResult<ReserveSubject> {
        subject.validate()?;
        self.require_lane(&subject.lane_id)?;
        self.require_feed(&subject.price_feed_id)?;
        self.require_attester_set(&subject.attester_set_id)?;
        if self.reserve_subjects.contains_key(&subject.subject_id) {
            return Err("zk oracle reserve subject already exists".to_string());
        }
        self.reserve_subjects
            .insert(subject.subject_id.clone(), subject.clone());
        Ok(subject)
    }

    pub fn insert_risk_policy(&mut self, policy: RiskPolicy) -> ZkOracleResult<RiskPolicy> {
        policy.validate()?;
        self.require_lane(&policy.lane_id)?;
        self.require_feed(&policy.price_feed_id)?;
        self.require_reserve_subject(&policy.reserve_subject_id)?;
        if self.risk_policies.contains_key(&policy.policy_id) {
            return Err("zk oracle risk policy already exists".to_string());
        }
        self.risk_policies
            .insert(policy.policy_id.clone(), policy.clone());
        Ok(policy)
    }

    pub fn insert_sponsor_policy(
        &mut self,
        policy: LowFeeSponsorPolicy,
    ) -> ZkOracleResult<LowFeeSponsorPolicy> {
        policy.validate_static()?;
        self.require_lane(&policy.lane_id)?;
        if self.sponsor_policies.contains_key(&policy.sponsor_id) {
            return Err("zk oracle sponsor policy already exists".to_string());
        }
        self.sponsor_policies
            .insert(policy.sponsor_id.clone(), policy.clone());
        Ok(policy)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_private_price_update(
        &mut self,
        feed_id: &str,
        publisher_id: &str,
        round: u64,
        price_units: u64,
        confidence_bps: u64,
        observed_at_height: u64,
        observed_at_ms: u64,
        latency_ms: u64,
        caller_label: &str,
    ) -> ZkOracleResult<ZkOracleUpdateReceipt> {
        let feed = self.require_feed(feed_id)?.clone();
        if !feed.active {
            return Err("zk oracle price feed is inactive".to_string());
        }
        let lane = self.require_lane(&feed.lane_id)?.clone();
        if !lane.active {
            return Err("zk oracle price lane is inactive".to_string());
        }
        let publisher = self.require_publisher(publisher_id)?.clone();
        if !publisher.can_publish_to_lane(&feed.lane_id) {
            return Err("zk oracle publisher is not permitted for this lane".to_string());
        }
        if latency_ms > lane.max_latency_ms {
            return Err("zk oracle private price update exceeded lane latency".to_string());
        }
        let payload = json!({
            "feed_id": feed_id,
            "publisher_id": publisher_id,
            "round": round,
            "price_units": price_units,
            "confidence_bps": confidence_bps,
            "observed_at_height": observed_at_height,
            "observed_at_ms": observed_at_ms,
            "latency_ms": latency_ms,
        });
        let disclosure = json!({
            "feed_id": feed_id,
            "round": round,
            "price_commitment_only": !feed.default_visibility.reveals_value(),
            "publisher_id": publisher_id,
            "lane_id": feed.lane_id,
        });
        let envelope = PrivateUpdateEnvelope::new(
            PrivateUpdateKind::PriceTick,
            feed_id,
            &feed.lane_id,
            caller_label,
            &payload,
            &disclosure,
            self.height,
            self.height
                .saturating_add(self.config.default_update_ttl_blocks),
        )?;
        self.insert_private_envelope(envelope.clone())?;

        let subject = json!({
            "feed_id": feed_id,
            "publisher_id": publisher_id,
            "round": round,
            "private_envelope_id": envelope.envelope_id,
            "payload_commitment": envelope.payload_commitment,
        });
        let context = json!({
            "lane_id": feed.lane_id,
            "height": self.height,
            "visibility": feed.default_visibility.as_str(),
            "proof_system": ZK_ORACLE_PRIVATE_UPDATE_SYSTEM,
        });
        let transcript = PqSignatureTranscript::deterministic(
            TranscriptKind::PriceUpdate,
            publisher_id,
            &publisher.pq_public_key_root,
            &subject,
            &context,
            self.height,
            self.height
                .saturating_add(self.config.default_transcript_ttl_blocks),
        )?;
        self.insert_transcript(transcript.clone())?;

        let observation = PriceObservation::new(
            feed_id,
            publisher_id,
            round,
            price_units,
            -(feed.decimals as i32),
            confidence_bps,
            observed_at_height,
            observed_at_ms,
            latency_ms,
            feed.default_visibility,
            &envelope.envelope_id,
            &transcript.transcript_id,
            &feed.lane_id,
            &envelope.blinding_root,
        )?;
        self.insert_observation(observation.clone())?;

        let aggregate =
            if self.round_observations(feed_id, round).len() >= feed.min_sources as usize {
                Some(self.aggregate_feed(feed_id, round)?)
            } else {
                None
            };
        let gross_fee_units = PrivateUpdateKind::PriceTick
            .default_fee_units()
            .max(lane.base_fee_units);
        let sponsorship = self.apply_sponsorship(
            &feed.lane_id,
            feed_id,
            PrivateUpdateKind::PriceTick,
            &envelope.envelope_id,
            caller_label,
            gross_fee_units,
        )?;
        let sponsored_fee_units = sponsorship
            .as_ref()
            .map(|receipt| receipt.sponsored_fee_units)
            .unwrap_or(0);
        let sponsorship_receipt_id = sponsorship
            .as_ref()
            .map(|receipt| receipt.receipt_id.clone());
        if let Some(receipt) = sponsorship {
            self.sponsorship_receipts
                .insert(receipt.receipt_id.clone(), receipt);
        }
        let receipt_id = zk_oracle_update_receipt_id(
            PrivateUpdateKind::PriceTick.as_str(),
            feed_id,
            &feed.lane_id,
            &envelope.envelope_id,
            &transcript.transcript_id,
            observation.observation_id.as_str(),
            aggregate
                .as_ref()
                .map(|item| item.aggregate_id.as_str())
                .unwrap_or("pending"),
            self.height,
        );
        let receipt = ZkOracleUpdateReceipt {
            receipt_id,
            update_kind: PrivateUpdateKind::PriceTick,
            subject_id: feed_id.to_string(),
            lane_id: feed.lane_id,
            private_envelope_id: envelope.envelope_id,
            signature_transcript_id: transcript.transcript_id,
            observation_id: Some(observation.observation_id),
            aggregate_id: aggregate.map(|item| item.aggregate_id),
            sponsorship_receipt_id,
            gross_fee_units,
            sponsored_fee_units,
            accepted: true,
            reason: "accepted_private_price_update".to_string(),
            recorded_at_height: self.height,
        };
        self.update_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.emit_audit_event(
            "price_update",
            feed_id,
            &json!({
                "receipt_id": receipt.receipt_id,
                "publisher_id": publisher_id,
                "round": round,
                "aggregate_id": receipt.aggregate_id,
            }),
        )?;
        Ok(receipt)
    }

    pub fn publish_reserve_disclosure(
        &mut self,
        subject_id: &str,
        reserve_value_units: u64,
        liability_value_units: u64,
        coverage_value_units: u64,
        caller_label: &str,
    ) -> ZkOracleResult<ReserveDisclosure> {
        let subject = self.require_reserve_subject(subject_id)?.clone();
        if !subject.active {
            return Err("zk oracle reserve subject is inactive".to_string());
        }
        let aggregate = self
            .aggregates
            .get(&subject.price_feed_id)
            .ok_or_else(|| "zk oracle reserve disclosure requires price aggregate".to_string())?
            .clone();
        if aggregate.is_stale(self.height) {
            return Err("zk oracle reserve disclosure requires fresh price aggregate".to_string());
        }
        let payload = json!({
            "subject_id": subject_id,
            "reserve_value_units": reserve_value_units,
            "liability_value_units": liability_value_units,
            "coverage_value_units": coverage_value_units,
            "price_aggregate_id": aggregate.aggregate_id,
        });
        let reserve_commitment_root =
            zk_oracle_number_commitment("ZK-ORACLE-RESERVE-VALUE", reserve_value_units, subject_id);
        let liability_commitment_root = zk_oracle_number_commitment(
            "ZK-ORACLE-LIABILITY-VALUE",
            liability_value_units,
            subject_id,
        );
        let private_liability_root = zk_oracle_payload_root(
            "ZK-ORACLE-PRIVATE-LIABILITY-SET",
            &json!({
                "subject_id": subject_id,
                "liability_commitment_root": liability_commitment_root,
                "liability_note_count": 37,
                "privacy_pool_epoch": self.height / 24,
            }),
        );
        let disclosure = json!({
            "subject_id": subject_id,
            "reserve_commitment_root": reserve_commitment_root,
            "liability_commitment_root": liability_commitment_root,
            "private_liability_root": private_liability_root,
            "price_aggregate_id": aggregate.aggregate_id,
        });
        let envelope = PrivateUpdateEnvelope::new(
            PrivateUpdateKind::ReserveSnapshot,
            subject_id,
            &subject.lane_id,
            caller_label,
            &payload,
            &disclosure,
            self.height,
            self.height
                .saturating_add(self.config.default_reserve_refresh_blocks)
                .saturating_add(subject.refresh_grace_blocks),
        )?;
        self.insert_private_envelope(envelope.clone())?;

        let transcript = PqSignatureTranscript::deterministic(
            TranscriptKind::ReserveDisclosure,
            &subject.operator_commitment,
            &subject.operator_commitment,
            &json!({
                "subject_id": subject_id,
                "private_envelope_id": envelope.envelope_id,
                "payload_commitment": envelope.payload_commitment,
            }),
            &json!({
                "lane_id": subject.lane_id,
                "price_aggregate_id": aggregate.aggregate_id,
                "reserve_proof_system": ZK_ORACLE_RESERVE_PROOF_SYSTEM,
            }),
            self.height,
            self.height
                .saturating_add(self.config.default_transcript_ttl_blocks),
        )?;
        self.insert_transcript(transcript.clone())?;

        let disclosure = ReserveDisclosure::new(
            subject_id,
            &envelope.envelope_id,
            &transcript.transcript_id,
            &reserve_commitment_root,
            &liability_commitment_root,
            &private_liability_root,
            reserve_value_units,
            liability_value_units,
            coverage_value_units,
            &subject.price_feed_id,
            &aggregate.aggregate_id,
            self.height,
            self.height
                .saturating_add(subject.refresh_cadence_blocks)
                .saturating_add(subject.refresh_grace_blocks),
        )?;
        self.reserve_disclosures
            .insert(disclosure.disclosure_id.clone(), disclosure.clone());
        let sponsorship = self.apply_sponsorship(
            &subject.lane_id,
            subject_id,
            PrivateUpdateKind::ReserveSnapshot,
            &envelope.envelope_id,
            caller_label,
            PrivateUpdateKind::ReserveSnapshot.default_fee_units(),
        )?;
        if let Some(receipt) = sponsorship {
            self.sponsorship_receipts
                .insert(receipt.receipt_id.clone(), receipt);
        }
        self.emit_audit_event(
            "reserve_disclosure",
            subject_id,
            &json!({
                "disclosure_id": disclosure.disclosure_id,
                "solvency_bps": disclosure.solvency_bps,
                "coverage_bps": disclosure.coverage_bps,
            }),
        )?;
        Ok(disclosure)
    }

    pub fn attest_reserve_disclosure(
        &mut self,
        attester_set_id: &str,
        attester_id: &str,
        disclosure_id: &str,
    ) -> ZkOracleResult<ReserveAttestation> {
        let attester_set = self.require_attester_set(attester_set_id)?.clone();
        if !attester_set.is_valid_at(self.height) {
            return Err(
                "zk oracle reserve attester set is not valid at current height".to_string(),
            );
        }
        if !attester_set.attester_ids.contains(attester_id) {
            return Err("zk oracle reserve attester is not in attester set".to_string());
        }
        let attester = self
            .reserve_attesters
            .get(attester_id)
            .ok_or_else(|| "zk oracle reserve attester unknown".to_string())?
            .clone();
        if !attester.active {
            return Err("zk oracle reserve attester inactive".to_string());
        }
        let disclosure = self
            .reserve_disclosures
            .get(disclosure_id)
            .ok_or_else(|| "zk oracle reserve disclosure unknown".to_string())?
            .clone();
        if !disclosure.is_fresh_at(self.height) {
            return Err("zk oracle reserve disclosure is not fresh".to_string());
        }
        let disclosure_root =
            zk_oracle_payload_root("ZK-ORACLE-RESERVE-DISCLOSURE", &disclosure.public_record());
        let transcript = PqSignatureTranscript::deterministic(
            TranscriptKind::ReserveAttestation,
            attester_id,
            &attester.pq_public_key_root,
            &json!({
                "disclosure_id": disclosure_id,
                "disclosure_root": disclosure_root,
                "attester_set_id": attester_set_id,
            }),
            &json!({
                "subject_id": disclosure.subject_id,
                "solvency_bps": disclosure.solvency_bps,
                "coverage_bps": disclosure.coverage_bps,
            }),
            self.height,
            self.height
                .saturating_add(self.config.default_transcript_ttl_blocks),
        )?;
        self.insert_transcript(transcript.clone())?;
        let attestation = ReserveAttestation::new(
            &disclosure.subject_id,
            disclosure_id,
            attester_set_id,
            attester_id,
            attester.weight,
            &disclosure_root,
            &transcript.transcript_id,
            self.height,
            self.height
                .saturating_add(self.config.default_transcript_ttl_blocks),
        )?;
        self.reserve_attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        self.refresh_disclosure_quorum(disclosure_id)?;
        self.emit_audit_event(
            "reserve_attestation",
            disclosure_id,
            &json!({
                "attestation_id": attestation.attestation_id,
                "attester_id": attester_id,
                "attester_weight": attester.weight,
            }),
        )?;
        Ok(attestation)
    }

    pub fn assess_market(
        &mut self,
        policy_id: &str,
        feed_id: &str,
        reserve_subject_id: &str,
        reserve_disclosure_id: &str,
    ) -> ZkOracleResult<RiskAssessment> {
        let policy = self
            .risk_policies
            .get(policy_id)
            .ok_or_else(|| "zk oracle risk policy unknown".to_string())?
            .clone();
        if !policy.active {
            return Err("zk oracle risk policy inactive".to_string());
        }
        if policy.price_feed_id != feed_id || policy.reserve_subject_id != reserve_subject_id {
            return Err("zk oracle risk policy subject mismatch".to_string());
        }
        let aggregate = self
            .aggregates
            .get(feed_id)
            .ok_or_else(|| "zk oracle risk assessment requires aggregate".to_string())?
            .clone();
        let disclosure = self
            .reserve_disclosures
            .get(reserve_disclosure_id)
            .ok_or_else(|| "zk oracle risk assessment requires reserve disclosure".to_string())?
            .clone();
        if disclosure.subject_id != reserve_subject_id {
            return Err("zk oracle reserve disclosure subject mismatch".to_string());
        }
        let observed_price_deviation_bps =
            price_deviation_bps(aggregate.weighted_price_units, aggregate.median_price_units);
        let observed_twap_deviation_bps =
            price_deviation_bps(aggregate.weighted_price_units, aggregate.twap_price_units);
        let reserve_staleness_blocks = self.height.saturating_sub(disclosure.published_at_height);
        let assessment = RiskAssessment::new(
            policy_id,
            &policy.market_id,
            feed_id,
            reserve_subject_id,
            &aggregate.aggregate_id,
            reserve_disclosure_id,
            observed_price_deviation_bps,
            observed_twap_deviation_bps,
            reserve_staleness_blocks,
            disclosure.solvency_bps,
            self.height,
            self.height
                .saturating_add(self.config.default_risk_ttl_blocks),
        )?;
        self.risk_assessments
            .insert(assessment.assessment_id.clone(), assessment.clone());
        if assessment.action.is_blocking() {
            let decision = CircuitDecision::new(
                &policy.market_id,
                reserve_subject_id,
                &assessment.assessment_id,
                assessment.action,
                assessment.severity,
                &json!({
                    "assessment_id": assessment.assessment_id,
                    "price_deviation_bps": assessment.price_deviation_bps,
                    "twap_deviation_bps": assessment.twap_deviation_bps,
                    "reserve_solvency_bps": assessment.reserve_solvency_bps,
                    "reserve_staleness_blocks": assessment.reserve_staleness_blocks,
                }),
                self.height,
                policy.circuit_cooldown_blocks,
            )?;
            self.circuit_decisions
                .insert(decision.decision_id.clone(), decision);
        }
        self.emit_audit_event(
            "risk_assessment",
            &policy.market_id,
            &json!({
                "assessment_id": assessment.assessment_id,
                "severity": assessment.severity.as_str(),
                "action": assessment.action.as_str(),
                "health_score_bps": assessment.health_score_bps,
            }),
        )?;
        Ok(assessment)
    }

    pub fn aggregate_feed(&mut self, feed_id: &str, round: u64) -> ZkOracleResult<PriceAggregate> {
        let feed = self.require_feed(feed_id)?.clone();
        let observations = self.round_observations(feed_id, round);
        if observations.len() < feed.min_sources as usize {
            return Err("zk oracle aggregate has insufficient observations".to_string());
        }
        let distinct_publishers = observations
            .iter()
            .map(|item| item.publisher_id.clone())
            .collect::<BTreeSet<_>>();
        if distinct_publishers.len() < feed.min_sources as usize {
            return Err("zk oracle aggregate has insufficient distinct publishers".to_string());
        }
        let publisher_weights = self.publisher_weight_map(&observations);
        let median_price_units = median_price_units(&observations);
        let weighted_price_units = weighted_price_units(&observations, &publisher_weights);
        let twap_price_units =
            self.twap_price(feed_id, feed.twap_window_blocks, weighted_price_units);
        let min_price_units = observations
            .iter()
            .map(|item| item.price_units)
            .min()
            .unwrap_or(weighted_price_units);
        let max_price_units = observations
            .iter()
            .map(|item| item.price_units)
            .max()
            .unwrap_or(weighted_price_units);
        let confidence_bps = weighted_confidence_bps(&observations, &publisher_weights);
        let observation_root = zk_oracle_price_observation_root(&observations);
        let private_envelope_ids = observations
            .iter()
            .filter_map(|item| self.private_envelopes.get(&item.private_envelope_id))
            .cloned()
            .collect::<Vec<_>>();
        let transcript_ids = observations
            .iter()
            .filter_map(|item| self.transcripts.get(&item.signature_transcript_id))
            .cloned()
            .collect::<Vec<_>>();
        let private_envelope_root = zk_oracle_private_envelope_root(&private_envelope_ids);
        let transcript_root = zk_oracle_pq_transcript_root(&transcript_ids);
        let publisher_weight_root = zk_oracle_publisher_weight_root(&publisher_weights);
        let published_at_height = observations
            .iter()
            .map(|item| item.observed_at_height)
            .max()
            .unwrap_or(self.height);
        let stale_after_height = published_at_height.saturating_add(feed.heartbeat_blocks);
        let proof_root = zk_oracle_price_aggregate_proof_root(
            feed_id,
            round,
            median_price_units,
            weighted_price_units,
            twap_price_units,
            &observation_root,
            &publisher_weight_root,
            &private_envelope_root,
            &transcript_root,
        );
        let aggregate_id = zk_oracle_price_aggregate_id(
            feed_id,
            round,
            median_price_units,
            weighted_price_units,
            twap_price_units,
            -(feed.decimals as i32),
            &observation_root,
            &publisher_weight_root,
            &private_envelope_root,
            &transcript_root,
            published_at_height,
            stale_after_height,
        );
        let aggregate = PriceAggregate {
            aggregate_id,
            feed_id: feed_id.to_string(),
            round,
            median_price_units,
            weighted_price_units,
            twap_price_units,
            min_price_units,
            max_price_units,
            exponent: -(feed.decimals as i32),
            confidence_bps,
            observation_root,
            publisher_weight_root,
            private_envelope_root,
            transcript_root,
            proof_root,
            lane_id: feed.lane_id,
            published_at_height,
            stale_after_height,
            status: UpdateStatus::Aggregated,
        };
        aggregate.validate()?;
        self.aggregates
            .insert(feed_id.to_string(), aggregate.clone());
        Ok(aggregate)
    }

    pub fn validate_reserve_quorum(
        &self,
        disclosure_id: &str,
    ) -> ZkOracleResult<(u64, BTreeSet<String>)> {
        let disclosure = self
            .reserve_disclosures
            .get(disclosure_id)
            .ok_or_else(|| "zk oracle reserve disclosure unknown".to_string())?;
        let subject = self.require_reserve_subject(&disclosure.subject_id)?;
        let attester_set = self.require_attester_set(&subject.attester_set_id)?;
        let mut seen = BTreeSet::new();
        let mut weight = 0_u64;
        for attestation in self
            .reserve_attestations
            .values()
            .filter(|item| item.disclosure_id == disclosure_id && item.is_valid_at(self.height))
        {
            if attestation.attester_set_id != attester_set.attester_set_id {
                continue;
            }
            if !attester_set.attester_ids.contains(&attestation.attester_id) {
                return Err("zk oracle reserve attestation from non-member".to_string());
            }
            if !seen.insert(attestation.attester_id.clone()) {
                return Err("zk oracle duplicate reserve attestation".to_string());
            }
            weight = weight.saturating_add(attestation.attester_weight);
        }
        if !attester_set.has_quorum_weight(weight) {
            return Err("zk oracle reserve attestation quorum insufficient".to_string());
        }
        Ok((weight, seen))
    }

    pub fn stale_feed_ids(&self) -> Vec<String> {
        self.aggregates
            .values()
            .filter(|aggregate| aggregate.is_stale(self.height))
            .map(|aggregate| aggregate.feed_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn reserve_subjects_due(&self) -> Vec<String> {
        self.reserve_subjects
            .values()
            .filter(|subject| {
                self.latest_reserve_disclosure(&subject.subject_id)
                    .map(|disclosure| {
                        self.height
                            >= disclosure
                                .published_at_height
                                .saturating_add(subject.refresh_cadence_blocks)
                    })
                    .unwrap_or(true)
            })
            .map(|subject| subject.subject_id.clone())
            .collect()
    }

    pub fn active_circuit_subjects(&self) -> Vec<String> {
        self.circuit_decisions
            .values()
            .filter(|decision| decision.is_active_at(self.height))
            .map(|decision| decision.subject_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn lane_pressure_bps(&self, lane_id: &str) -> u64 {
        let lane_updates = self
            .private_envelopes
            .values()
            .filter(|envelope| envelope.lane_id == lane_id && envelope.is_live_at(self.height))
            .count() as u64;
        let sponsored = self
            .sponsorship_receipts
            .values()
            .filter(|receipt| receipt.lane_id == lane_id)
            .map(|receipt| receipt.sponsored_fee_units)
            .sum::<u64>();
        let lane_weight = self
            .lanes
            .get(lane_id)
            .map(|lane| lane.priority_weight.max(1))
            .unwrap_or(1);
        (lane_updates.saturating_mul(250))
            .saturating_add(sponsored.saturating_mul(50))
            .saturating_div(lane_weight)
            .min(ZK_ORACLE_MAX_BPS)
    }

    pub fn aggregate_risk_score_bps(&self) -> u64 {
        self.risk_assessments
            .values()
            .filter(|assessment| assessment.is_live_at(self.height))
            .map(|assessment| assessment.health_score_bps)
            .max()
            .unwrap_or(0)
            .max(self.stale_feed_ids().len() as u64 * 1_000)
            .max(self.reserve_subjects_due().len() as u64 * 750)
            .min(ZK_ORACLE_MAX_BPS)
    }

    pub fn roots(&self) -> ZkOracleStateRoots {
        ZkOracleStateRoots {
            config_root: self.config.config_root(),
            lane_root: zk_oracle_latency_lane_root(
                &self.lanes.values().cloned().collect::<Vec<_>>(),
            ),
            feed_root: zk_oracle_price_feed_root(&self.feeds.values().cloned().collect::<Vec<_>>()),
            publisher_root: zk_oracle_publisher_root(
                &self.publishers.values().cloned().collect::<Vec<_>>(),
            ),
            transcript_root: zk_oracle_pq_transcript_root(
                &self.transcripts.values().cloned().collect::<Vec<_>>(),
            ),
            private_envelope_root: zk_oracle_private_envelope_root(
                &self.private_envelopes.values().cloned().collect::<Vec<_>>(),
            ),
            observation_root: zk_oracle_price_observation_root(
                &self
                    .observations
                    .values()
                    .flat_map(|items| items.clone())
                    .collect::<Vec<_>>(),
            ),
            aggregate_root: zk_oracle_price_aggregate_root(
                &self.aggregates.values().cloned().collect::<Vec<_>>(),
            ),
            update_receipt_root: zk_oracle_update_receipt_root(
                &self.update_receipts.values().cloned().collect::<Vec<_>>(),
            ),
            reserve_subject_root: zk_oracle_reserve_subject_root(
                &self.reserve_subjects.values().cloned().collect::<Vec<_>>(),
            ),
            reserve_attester_root: zk_oracle_reserve_attester_root(
                &self.reserve_attesters.values().cloned().collect::<Vec<_>>(),
            ),
            reserve_attester_set_root: zk_oracle_reserve_attester_set_root(
                &self
                    .reserve_attester_sets
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            reserve_disclosure_root: zk_oracle_reserve_disclosure_root(
                &self
                    .reserve_disclosures
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            reserve_attestation_root: zk_oracle_reserve_attestation_root(
                &self
                    .reserve_attestations
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            risk_policy_root: zk_oracle_risk_policy_root(
                &self.risk_policies.values().cloned().collect::<Vec<_>>(),
            ),
            risk_assessment_root: zk_oracle_risk_assessment_root(
                &self.risk_assessments.values().cloned().collect::<Vec<_>>(),
            ),
            sponsor_policy_root: zk_oracle_sponsor_policy_root(
                &self.sponsor_policies.values().cloned().collect::<Vec<_>>(),
            ),
            sponsorship_receipt_root: zk_oracle_sponsorship_receipt_root(
                &self
                    .sponsorship_receipts
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            circuit_decision_root: zk_oracle_circuit_decision_root(
                &self.circuit_decisions.values().cloned().collect::<Vec<_>>(),
            ),
            audit_event_root: zk_oracle_audit_event_root(
                &self.audit_events.values().cloned().collect::<Vec<_>>(),
            ),
        }
    }

    pub fn state_root(&self) -> String {
        zk_oracle_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("zk oracle state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "zk_oracle_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "root_commitment": roots.state_root(),
            "lane_count": self.lanes.len() as u64,
            "feed_count": self.feeds.len() as u64,
            "publisher_count": self.publishers.len() as u64,
            "transcript_count": self.transcripts.len() as u64,
            "private_envelope_count": self.private_envelopes.len() as u64,
            "observation_count": self.observations.values().map(Vec::len).sum::<usize>() as u64,
            "aggregate_count": self.aggregates.len() as u64,
            "reserve_subject_count": self.reserve_subjects.len() as u64,
            "reserve_disclosure_count": self.reserve_disclosures.len() as u64,
            "reserve_attestation_count": self.reserve_attestations.len() as u64,
            "risk_policy_count": self.risk_policies.len() as u64,
            "risk_assessment_count": self.risk_assessments.len() as u64,
            "sponsor_policy_count": self.sponsor_policies.len() as u64,
            "sponsorship_receipt_count": self.sponsorship_receipts.len() as u64,
            "circuit_decision_count": self.circuit_decisions.len() as u64,
            "stale_feed_ids": self.stale_feed_ids(),
            "reserve_subjects_due": self.reserve_subjects_due(),
            "active_circuit_subjects": self.active_circuit_subjects(),
            "total_sponsored_fee_units": self.total_sponsored_fee_units(),
            "aggregate_risk_score_bps": self.aggregate_risk_score_bps(),
            "risk_status": severity_from_score(self.aggregate_risk_score_bps()).as_str(),
        })
    }

    fn insert_private_envelope(
        &mut self,
        envelope: PrivateUpdateEnvelope,
    ) -> ZkOracleResult<PrivateUpdateEnvelope> {
        envelope.validate()?;
        if self.private_envelopes.contains_key(&envelope.envelope_id) {
            return Err("zk oracle private envelope already exists".to_string());
        }
        self.private_envelopes
            .insert(envelope.envelope_id.clone(), envelope.clone());
        if self.private_envelopes.len() > self.config.max_private_updates {
            let first_key = self.private_envelopes.keys().next().cloned();
            if let Some(key) = first_key {
                self.private_envelopes.remove(&key);
            }
        }
        Ok(envelope)
    }

    fn insert_transcript(
        &mut self,
        transcript: PqSignatureTranscript,
    ) -> ZkOracleResult<PqSignatureTranscript> {
        transcript.validate()?;
        if self.transcripts.contains_key(&transcript.transcript_id) {
            return Err("zk oracle pq transcript already exists".to_string());
        }
        self.transcripts
            .insert(transcript.transcript_id.clone(), transcript.clone());
        if self.transcripts.len() > self.config.max_transcripts {
            let first_key = self.transcripts.keys().next().cloned();
            if let Some(key) = first_key {
                self.transcripts.remove(&key);
            }
        }
        Ok(transcript)
    }

    fn insert_observation(
        &mut self,
        observation: PriceObservation,
    ) -> ZkOracleResult<PriceObservation> {
        observation.validate()?;
        self.require_feed(&observation.feed_id)?;
        self.require_publisher(&observation.publisher_id)?;
        self.require_lane(&observation.lane_id)?;
        if !self
            .private_envelopes
            .contains_key(&observation.private_envelope_id)
        {
            return Err("zk oracle observation references unknown private envelope".to_string());
        }
        if !self
            .transcripts
            .contains_key(&observation.signature_transcript_id)
        {
            return Err("zk oracle observation references unknown transcript".to_string());
        }
        let observations = self
            .observations
            .entry(observation.feed_id.clone())
            .or_default();
        observations.push(observation.clone());
        observations.sort_by_key(|item| {
            (
                item.round,
                item.observed_at_height,
                item.publisher_id.clone(),
                item.observation_id.clone(),
            )
        });
        if observations.len() > self.config.max_observations_per_feed {
            let excess = observations.len() - self.config.max_observations_per_feed;
            observations.drain(0..excess);
        }
        Ok(observation)
    }

    fn apply_sponsorship(
        &mut self,
        lane_id: &str,
        subject_id: &str,
        update_kind: PrivateUpdateKind,
        private_envelope_id: &str,
        caller_label: &str,
        gross_fee_units: u64,
    ) -> ZkOracleResult<Option<SponsorshipReceipt>> {
        if !self.config.low_fee_updates_enabled {
            return Ok(None);
        }
        let sponsor_id = self
            .sponsor_policies
            .iter()
            .find(|(_, sponsor)| {
                sponsor.lane_id == lane_id
                    && sponsor.can_sponsor_at(self.height)
                    && sponsor.max_per_update_units > 0
            })
            .map(|(id, _)| id.clone());
        let Some(sponsor_id) = sponsor_id else {
            return Ok(None);
        };
        let sponsor = self
            .sponsor_policies
            .get_mut(&sponsor_id)
            .ok_or_else(|| "zk oracle sponsor disappeared during sponsorship".to_string())?;
        let sponsored_fee_units = gross_fee_units
            .min(sponsor.max_per_update_units)
            .min(sponsor.available_units());
        if sponsored_fee_units == 0 {
            sponsor.status = SponsorPolicyStatus::Exhausted;
            return Ok(None);
        }
        sponsor.reserved_units = sponsor.reserved_units.saturating_add(sponsored_fee_units);
        sponsor.spent_units = sponsor.spent_units.saturating_add(sponsored_fee_units);
        sponsor.reserved_units = sponsor.reserved_units.saturating_sub(sponsored_fee_units);
        if sponsor.available_units() == 0 {
            sponsor.status = SponsorPolicyStatus::Exhausted;
        }
        let receipt = SponsorshipReceipt::new(
            &sponsor_id,
            lane_id,
            subject_id,
            update_kind,
            caller_label,
            private_envelope_id,
            gross_fee_units,
            sponsored_fee_units,
            self.height,
            self.height
                .saturating_add(self.config.default_update_ttl_blocks),
        )?;
        Ok(Some(receipt))
    }

    fn refresh_disclosure_quorum(&mut self, disclosure_id: &str) -> ZkOracleResult<()> {
        let quorum = self.validate_reserve_quorum(disclosure_id);
        if quorum.is_ok() {
            if let Some(disclosure) = self.reserve_disclosures.get_mut(disclosure_id) {
                disclosure.status = AttestationStatus::QuorumReached;
            }
        }
        Ok(())
    }

    fn emit_audit_event(
        &mut self,
        event_kind: &str,
        subject_id: &str,
        event: &Value,
    ) -> ZkOracleResult<OracleAuditEvent> {
        let audit_event = OracleAuditEvent::new(event_kind, subject_id, event, self.height)?;
        self.audit_events
            .insert(audit_event.event_id.clone(), audit_event.clone());
        if self.audit_events.len() > ZK_ORACLE_MAX_AUDIT_EVENTS {
            let first_key = self.audit_events.keys().next().cloned();
            if let Some(key) = first_key {
                self.audit_events.remove(&key);
            }
        }
        Ok(audit_event)
    }

    fn require_lane(&self, lane_id: &str) -> ZkOracleResult<&LatencyLane> {
        self.lanes
            .get(lane_id)
            .ok_or_else(|| "zk oracle lane unknown".to_string())
    }

    fn require_feed(&self, feed_id: &str) -> ZkOracleResult<&PriceFeed> {
        self.feeds
            .get(feed_id)
            .ok_or_else(|| "zk oracle price feed unknown".to_string())
    }

    fn require_publisher(&self, publisher_id: &str) -> ZkOracleResult<&OraclePublisher> {
        self.publishers
            .get(publisher_id)
            .ok_or_else(|| "zk oracle publisher unknown".to_string())
    }

    fn require_attester_set(&self, attester_set_id: &str) -> ZkOracleResult<&ReserveAttesterSet> {
        self.reserve_attester_sets
            .get(attester_set_id)
            .ok_or_else(|| "zk oracle reserve attester set unknown".to_string())
    }

    fn require_reserve_subject(&self, subject_id: &str) -> ZkOracleResult<&ReserveSubject> {
        self.reserve_subjects
            .get(subject_id)
            .ok_or_else(|| "zk oracle reserve subject unknown".to_string())
    }

    fn round_observations(&self, feed_id: &str, round: u64) -> Vec<PriceObservation> {
        let mut latest_by_publisher = BTreeMap::<String, PriceObservation>::new();
        for observation in self
            .observations
            .get(feed_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|item| item.round == round && item.status.is_live())
        {
            latest_by_publisher.insert(observation.publisher_id.clone(), observation);
        }
        latest_by_publisher.into_values().collect()
    }

    fn publisher_weight_map(&self, observations: &[PriceObservation]) -> BTreeMap<String, u64> {
        observations
            .iter()
            .filter_map(|observation| {
                self.publishers
                    .get(&observation.publisher_id)
                    .map(|publisher| (observation.publisher_id.clone(), publisher.weight_bps))
            })
            .collect()
    }

    fn twap_price(&self, feed_id: &str, window_blocks: u64, fallback_price: u64) -> u64 {
        let from_height = self.height.saturating_sub(window_blocks);
        let mut samples = self
            .aggregates
            .values()
            .filter(|aggregate| {
                aggregate.feed_id == feed_id && aggregate.published_at_height >= from_height
            })
            .map(|aggregate| aggregate.weighted_price_units)
            .collect::<Vec<_>>();
        samples.push(fallback_price);
        bounded_u128_to_u64(
            samples.iter().map(|price| *price as u128).sum::<u128>() / samples.len() as u128,
        )
    }

    fn latest_reserve_disclosure(&self, subject_id: &str) -> Option<&ReserveDisclosure> {
        self.reserve_disclosures
            .values()
            .filter(|disclosure| disclosure.subject_id == subject_id)
            .max_by_key(|disclosure| disclosure.published_at_height)
    }

    fn total_sponsored_fee_units(&self) -> u64 {
        self.sponsorship_receipts
            .values()
            .map(|receipt| receipt.sponsored_fee_units)
            .sum()
    }
}

pub fn zk_oracle_latency_lane_id(
    lane_kind: &str,
    lane_key: &str,
    max_latency_ms: u64,
    max_staleness_blocks: u64,
    priority_weight: u64,
    base_fee_units: u64,
    proof_budget_bytes: u64,
    sponsor_pool_id: &str,
) -> String {
    domain_hash(
        "ZK-ORACLE-LATENCY-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_kind),
            HashPart::Str(lane_key),
            HashPart::Int(max_latency_ms as i128),
            HashPart::Int(max_staleness_blocks as i128),
            HashPart::Int(priority_weight as i128),
            HashPart::Int(base_fee_units as i128),
            HashPart::Int(proof_budget_bytes as i128),
            HashPart::Str(sponsor_pool_id),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn zk_oracle_price_feed_id(
    feed_kind: &str,
    base_asset_id: &str,
    quote_asset_id: &str,
    decimals: u8,
    min_sources: u64,
    heartbeat_blocks: u64,
    twap_window_blocks: u64,
    max_deviation_bps: u64,
    lane_id: &str,
    visibility: &str,
    metadata_root: &str,
) -> String {
    domain_hash(
        "ZK-ORACLE-PRICE-FEED-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(feed_kind),
            HashPart::Str(base_asset_id),
            HashPart::Str(quote_asset_id),
            HashPart::Int(decimals as i128),
            HashPart::Int(min_sources as i128),
            HashPart::Int(heartbeat_blocks as i128),
            HashPart::Int(twap_window_blocks as i128),
            HashPart::Int(max_deviation_bps as i128),
            HashPart::Str(lane_id),
            HashPart::Str(visibility),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn zk_oracle_publisher_id(
    label_commitment: &str,
    role: &str,
    pq_public_key_root: &str,
    stake_units: u64,
    weight_bps: u64,
    max_updates_per_epoch: u64,
    lane_permission_root: &str,
    metadata_root: &str,
) -> String {
    domain_hash(
        "ZK-ORACLE-PUBLISHER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label_commitment),
            HashPart::Str(role),
            HashPart::Str(pq_public_key_root),
            HashPart::Int(stake_units as i128),
            HashPart::Int(weight_bps as i128),
            HashPart::Int(max_updates_per_epoch as i128),
            HashPart::Str(lane_permission_root),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn zk_oracle_pq_challenge_root(
    transcript_kind: &str,
    scheme: &str,
    signer_id: &str,
    signer_key_root: &str,
    subject_root: &str,
    context_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "ZK-ORACLE-PQ-CHALLENGE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(transcript_kind),
            HashPart::Str(scheme),
            HashPart::Str(signer_id),
            HashPart::Str(signer_key_root),
            HashPart::Str(subject_root),
            HashPart::Str(context_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn zk_oracle_pq_signature_commitment(
    scheme: &str,
    signer_id: &str,
    signer_key_root: &str,
    challenge_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "ZK-ORACLE-PQ-SIGNATURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scheme),
            HashPart::Str(signer_id),
            HashPart::Str(signer_key_root),
            HashPart::Str(challenge_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn zk_oracle_pq_transcript_id(
    transcript_kind: &str,
    scheme: &str,
    signer_id: &str,
    challenge_root: &str,
    signature_commitment: &str,
    recovery_signature_commitment: &str,
) -> String {
    domain_hash(
        "ZK-ORACLE-PQ-TRANSCRIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(transcript_kind),
            HashPart::Str(scheme),
            HashPart::Str(signer_id),
            HashPart::Str(challenge_root),
            HashPart::Str(signature_commitment),
            HashPart::Str(recovery_signature_commitment),
        ],
        32,
    )
}

pub fn zk_oracle_blinding_root(
    update_kind: &str,
    subject_id: &str,
    lane_id: &str,
    submitter_commitment: &str,
    payload_commitment: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "ZK-ORACLE-BLINDING-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(update_kind),
            HashPart::Str(subject_id),
            HashPart::Str(lane_id),
            HashPart::Str(submitter_commitment),
            HashPart::Str(payload_commitment),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn zk_oracle_nullifier(
    update_kind: &str,
    subject_id: &str,
    lane_id: &str,
    submitter_commitment: &str,
    blinding_root: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "ZK-ORACLE-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(update_kind),
            HashPart::Str(subject_id),
            HashPart::Str(lane_id),
            HashPart::Str(submitter_commitment),
            HashPart::Str(blinding_root),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn zk_oracle_private_update_proof_root(
    update_kind: &str,
    subject_id: &str,
    payload_commitment: &str,
    disclosure_root: &str,
    nullifier: &str,
    blinding_root: &str,
) -> String {
    zk_oracle_payload_root(
        "ZK-ORACLE-PRIVATE-UPDATE-PROOF",
        &json!({
            "update_kind": update_kind,
            "subject_id": subject_id,
            "payload_commitment": payload_commitment,
            "disclosure_root": disclosure_root,
            "nullifier": nullifier,
            "blinding_root": blinding_root,
            "private_update_system": ZK_ORACLE_PRIVATE_UPDATE_SYSTEM,
        }),
    )
}

pub fn zk_oracle_private_envelope_id(
    update_kind: &str,
    subject_id: &str,
    lane_id: &str,
    submitter_commitment: &str,
    payload_commitment: &str,
    nullifier: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "ZK-ORACLE-PRIVATE-ENVELOPE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(update_kind),
            HashPart::Str(subject_id),
            HashPart::Str(lane_id),
            HashPart::Str(submitter_commitment),
            HashPart::Str(payload_commitment),
            HashPart::Str(nullifier),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn zk_oracle_price_payload_root(
    feed_id: &str,
    publisher_id: &str,
    round: u64,
    price_commitment: &str,
    exponent: i32,
    confidence_bps: u64,
    observed_at_height: u64,
    observed_at_ms: u64,
    latency_ms: u64,
    visibility: &str,
) -> String {
    domain_hash(
        "ZK-ORACLE-PRICE-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(feed_id),
            HashPart::Str(publisher_id),
            HashPart::Int(round as i128),
            HashPart::Str(price_commitment),
            HashPart::Int(exponent as i128),
            HashPart::Int(confidence_bps as i128),
            HashPart::Int(observed_at_height as i128),
            HashPart::Int(observed_at_ms as i128),
            HashPart::Int(latency_ms as i128),
            HashPart::Str(visibility),
        ],
        32,
    )
}

pub fn zk_oracle_price_observation_id(
    feed_id: &str,
    publisher_id: &str,
    round: u64,
    payload_root: &str,
    private_envelope_id: &str,
    signature_transcript_id: &str,
) -> String {
    domain_hash(
        "ZK-ORACLE-PRICE-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(feed_id),
            HashPart::Str(publisher_id),
            HashPart::Int(round as i128),
            HashPart::Str(payload_root),
            HashPart::Str(private_envelope_id),
            HashPart::Str(signature_transcript_id),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn zk_oracle_price_aggregate_id(
    feed_id: &str,
    round: u64,
    median_price_units: u64,
    weighted_price_units: u64,
    twap_price_units: u64,
    exponent: i32,
    observation_root: &str,
    publisher_weight_root: &str,
    private_envelope_root: &str,
    transcript_root: &str,
    published_at_height: u64,
    stale_after_height: u64,
) -> String {
    domain_hash(
        "ZK-ORACLE-PRICE-AGGREGATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(feed_id),
            HashPart::Int(round as i128),
            HashPart::Int(median_price_units as i128),
            HashPart::Int(weighted_price_units as i128),
            HashPart::Int(twap_price_units as i128),
            HashPart::Int(exponent as i128),
            HashPart::Str(observation_root),
            HashPart::Str(publisher_weight_root),
            HashPart::Str(private_envelope_root),
            HashPart::Str(transcript_root),
            HashPart::Int(published_at_height as i128),
            HashPart::Int(stale_after_height as i128),
        ],
        32,
    )
}

pub fn zk_oracle_price_aggregate_proof_root(
    feed_id: &str,
    round: u64,
    median_price_units: u64,
    weighted_price_units: u64,
    twap_price_units: u64,
    observation_root: &str,
    publisher_weight_root: &str,
    private_envelope_root: &str,
    transcript_root: &str,
) -> String {
    zk_oracle_payload_root(
        "ZK-ORACLE-PRICE-AGGREGATE-PROOF",
        &json!({
            "feed_id": feed_id,
            "round": round,
            "median_price_units": median_price_units,
            "weighted_price_units": weighted_price_units,
            "twap_price_units": twap_price_units,
            "observation_root": observation_root,
            "publisher_weight_root": publisher_weight_root,
            "private_envelope_root": private_envelope_root,
            "transcript_root": transcript_root,
            "proof_system": ZK_ORACLE_PRICE_PROOF_SYSTEM,
        }),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn zk_oracle_update_receipt_id(
    update_kind: &str,
    subject_id: &str,
    lane_id: &str,
    private_envelope_id: &str,
    signature_transcript_id: &str,
    observation_id: &str,
    aggregate_id: &str,
    recorded_at_height: u64,
) -> String {
    domain_hash(
        "ZK-ORACLE-UPDATE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(update_kind),
            HashPart::Str(subject_id),
            HashPart::Str(lane_id),
            HashPart::Str(private_envelope_id),
            HashPart::Str(signature_transcript_id),
            HashPart::Str(observation_id),
            HashPart::Str(aggregate_id),
            HashPart::Int(recorded_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn zk_oracle_reserve_subject_id(
    subject_kind: &str,
    subject_key: &str,
    operator_commitment: &str,
    reserve_asset_id: &str,
    liability_asset_id: &str,
    price_feed_id: &str,
    min_solvency_bps: u64,
    min_coverage_bps: u64,
    attester_set_id: &str,
    lane_id: &str,
    metadata_root: &str,
) -> String {
    domain_hash(
        "ZK-ORACLE-RESERVE-SUBJECT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_key),
            HashPart::Str(operator_commitment),
            HashPart::Str(reserve_asset_id),
            HashPart::Str(liability_asset_id),
            HashPart::Str(price_feed_id),
            HashPart::Int(min_solvency_bps as i128),
            HashPart::Int(min_coverage_bps as i128),
            HashPart::Str(attester_set_id),
            HashPart::Str(lane_id),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn zk_oracle_reserve_attester_id(
    label_commitment: &str,
    role: &str,
    pq_public_key_root: &str,
    weight: u64,
) -> String {
    domain_hash(
        "ZK-ORACLE-RESERVE-ATTESTER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label_commitment),
            HashPart::Str(role),
            HashPart::Str(pq_public_key_root),
            HashPart::Int(weight as i128),
        ],
        32,
    )
}

pub fn zk_oracle_reserve_attester_set_id(
    set_label: &str,
    attester_root: &str,
    threshold_weight: u64,
    created_at_height: u64,
    expires_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "ZK-ORACLE-RESERVE-ATTESTER-SET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(set_label),
            HashPart::Str(attester_root),
            HashPart::Int(threshold_weight as i128),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn zk_oracle_reserve_disclosure_proof_root(
    subject_id: &str,
    reserve_commitment_root: &str,
    liability_commitment_root: &str,
    private_liability_root: &str,
    reserve_value_units: u64,
    liability_value_units: u64,
    coverage_value_units: u64,
    price_feed_id: &str,
    price_aggregate_id: &str,
) -> String {
    zk_oracle_payload_root(
        "ZK-ORACLE-RESERVE-DISCLOSURE-PROOF",
        &json!({
            "subject_id": subject_id,
            "reserve_commitment_root": reserve_commitment_root,
            "liability_commitment_root": liability_commitment_root,
            "private_liability_root": private_liability_root,
            "reserve_value_units": reserve_value_units,
            "liability_value_units": liability_value_units,
            "coverage_value_units": coverage_value_units,
            "price_feed_id": price_feed_id,
            "price_aggregate_id": price_aggregate_id,
            "proof_system": ZK_ORACLE_RESERVE_PROOF_SYSTEM,
        }),
    )
}

pub fn zk_oracle_reserve_disclosure_id(
    subject_id: &str,
    private_envelope_id: &str,
    signature_transcript_id: &str,
    proof_root: &str,
    published_at_height: u64,
) -> String {
    domain_hash(
        "ZK-ORACLE-RESERVE-DISCLOSURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_id),
            HashPart::Str(private_envelope_id),
            HashPart::Str(signature_transcript_id),
            HashPart::Str(proof_root),
            HashPart::Int(published_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn zk_oracle_reserve_attestation_id(
    subject_id: &str,
    disclosure_id: &str,
    attester_set_id: &str,
    attester_id: &str,
    attester_weight: u64,
    disclosure_root: &str,
    signature_transcript_id: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "ZK-ORACLE-RESERVE-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_id),
            HashPart::Str(disclosure_id),
            HashPart::Str(attester_set_id),
            HashPart::Str(attester_id),
            HashPart::Int(attester_weight as i128),
            HashPart::Str(disclosure_root),
            HashPart::Str(signature_transcript_id),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn zk_oracle_risk_policy_id(
    market_id: &str,
    collateral_asset_id: &str,
    debt_asset_id: &str,
    price_feed_id: &str,
    reserve_subject_id: &str,
    collateral_factor_bps: u64,
    liquidation_threshold_bps: u64,
    max_oracle_deviation_bps: u64,
    max_twap_deviation_bps: u64,
    max_reserve_staleness_blocks: u64,
    min_solvency_bps: u64,
    circuit_cooldown_blocks: u64,
    lane_id: &str,
    metadata_root: &str,
) -> String {
    domain_hash(
        "ZK-ORACLE-RISK-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(collateral_asset_id),
            HashPart::Str(debt_asset_id),
            HashPart::Str(price_feed_id),
            HashPart::Str(reserve_subject_id),
            HashPart::Int(collateral_factor_bps as i128),
            HashPart::Int(liquidation_threshold_bps as i128),
            HashPart::Int(max_oracle_deviation_bps as i128),
            HashPart::Int(max_twap_deviation_bps as i128),
            HashPart::Int(max_reserve_staleness_blocks as i128),
            HashPart::Int(min_solvency_bps as i128),
            HashPart::Int(circuit_cooldown_blocks as i128),
            HashPart::Str(lane_id),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn zk_oracle_risk_assessment_proof_root(
    policy_id: &str,
    aggregate_id: &str,
    reserve_disclosure_id: &str,
    price_deviation_bps: u64,
    twap_deviation_bps: u64,
    reserve_staleness_blocks: u64,
    reserve_solvency_bps: u64,
    health_score_bps: u64,
    severity: &str,
    action: &str,
) -> String {
    zk_oracle_payload_root(
        "ZK-ORACLE-RISK-ASSESSMENT-PROOF",
        &json!({
            "policy_id": policy_id,
            "aggregate_id": aggregate_id,
            "reserve_disclosure_id": reserve_disclosure_id,
            "price_deviation_bps": price_deviation_bps,
            "twap_deviation_bps": twap_deviation_bps,
            "reserve_staleness_blocks": reserve_staleness_blocks,
            "reserve_solvency_bps": reserve_solvency_bps,
            "health_score_bps": health_score_bps,
            "severity": severity,
            "action": action,
            "proof_system": ZK_ORACLE_RISK_PROOF_SYSTEM,
        }),
    )
}

pub fn zk_oracle_risk_assessment_id(
    policy_id: &str,
    market_id: &str,
    aggregate_id: &str,
    reserve_disclosure_id: &str,
    proof_root: &str,
    assessed_at_height: u64,
) -> String {
    domain_hash(
        "ZK-ORACLE-RISK-ASSESSMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(policy_id),
            HashPart::Str(market_id),
            HashPart::Str(aggregate_id),
            HashPart::Str(reserve_disclosure_id),
            HashPart::Str(proof_root),
            HashPart::Int(assessed_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn zk_oracle_sponsor_policy_id(
    sponsor_commitment: &str,
    fee_asset_id: &str,
    lane_id: &str,
    budget_units: u64,
    max_per_update_units: u64,
    start_height: u64,
    expires_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "ZK-ORACLE-SPONSOR-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Str(lane_id),
            HashPart::Int(budget_units as i128),
            HashPart::Int(max_per_update_units as i128),
            HashPart::Int(start_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn zk_oracle_sponsorship_receipt_id(
    sponsor_id: &str,
    lane_id: &str,
    subject_id: &str,
    update_kind: &str,
    caller_commitment: &str,
    private_envelope_id: &str,
    gross_fee_units: u64,
    sponsored_fee_units: u64,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "ZK-ORACLE-SPONSORSHIP-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(lane_id),
            HashPart::Str(subject_id),
            HashPart::Str(update_kind),
            HashPart::Str(caller_commitment),
            HashPart::Str(private_envelope_id),
            HashPart::Int(gross_fee_units as i128),
            HashPart::Int(sponsored_fee_units as i128),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn zk_oracle_circuit_decision_id(
    market_id: &str,
    subject_id: &str,
    assessment_id: &str,
    action: &str,
    severity: &str,
    reason_root: &str,
    opened_at_height: u64,
    cooldown_until_height: u64,
) -> String {
    domain_hash(
        "ZK-ORACLE-CIRCUIT-DECISION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(subject_id),
            HashPart::Str(assessment_id),
            HashPart::Str(action),
            HashPart::Str(severity),
            HashPart::Str(reason_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(cooldown_until_height as i128),
        ],
        32,
    )
}

pub fn zk_oracle_audit_event_id(
    event_kind: &str,
    subject_id: &str,
    event_root: &str,
    emitted_at_height: u64,
) -> String {
    domain_hash(
        "ZK-ORACLE-AUDIT-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Str(event_root),
            HashPart::Int(emitted_at_height as i128),
        ],
        32,
    )
}

pub fn zk_oracle_latency_lane_root(lanes: &[LatencyLane]) -> String {
    keyed_record_root(
        "ZK-ORACLE-LATENCY-LANE",
        lanes
            .iter()
            .map(|lane| (lane.lane_id.clone(), lane.public_record()))
            .collect(),
    )
}

pub fn zk_oracle_price_feed_root(feeds: &[PriceFeed]) -> String {
    keyed_record_root(
        "ZK-ORACLE-PRICE-FEED",
        feeds
            .iter()
            .map(|feed| (feed.feed_id.clone(), feed.public_record()))
            .collect(),
    )
}

pub fn zk_oracle_publisher_root(publishers: &[OraclePublisher]) -> String {
    keyed_record_root(
        "ZK-ORACLE-PUBLISHER",
        publishers
            .iter()
            .map(|publisher| (publisher.publisher_id.clone(), publisher.public_record()))
            .collect(),
    )
}

pub fn zk_oracle_pq_transcript_root(transcripts: &[PqSignatureTranscript]) -> String {
    keyed_record_root(
        "ZK-ORACLE-PQ-TRANSCRIPT",
        transcripts
            .iter()
            .map(|transcript| (transcript.transcript_id.clone(), transcript.public_record()))
            .collect(),
    )
}

pub fn zk_oracle_private_envelope_root(envelopes: &[PrivateUpdateEnvelope]) -> String {
    keyed_record_root(
        "ZK-ORACLE-PRIVATE-ENVELOPE",
        envelopes
            .iter()
            .map(|envelope| (envelope.envelope_id.clone(), envelope.public_record()))
            .collect(),
    )
}

pub fn zk_oracle_price_observation_root(observations: &[PriceObservation]) -> String {
    keyed_record_root(
        "ZK-ORACLE-PRICE-OBSERVATION",
        observations
            .iter()
            .map(|observation| {
                (
                    observation.observation_id.clone(),
                    observation.public_record(),
                )
            })
            .collect(),
    )
}

pub fn zk_oracle_price_aggregate_root(aggregates: &[PriceAggregate]) -> String {
    keyed_record_root(
        "ZK-ORACLE-PRICE-AGGREGATE",
        aggregates
            .iter()
            .map(|aggregate| (aggregate.aggregate_id.clone(), aggregate.public_record()))
            .collect(),
    )
}

pub fn zk_oracle_update_receipt_root(receipts: &[ZkOracleUpdateReceipt]) -> String {
    keyed_record_root(
        "ZK-ORACLE-UPDATE-RECEIPT",
        receipts
            .iter()
            .map(|receipt| (receipt.receipt_id.clone(), receipt.public_record()))
            .collect(),
    )
}

pub fn zk_oracle_reserve_subject_root(subjects: &[ReserveSubject]) -> String {
    keyed_record_root(
        "ZK-ORACLE-RESERVE-SUBJECT",
        subjects
            .iter()
            .map(|subject| (subject.subject_id.clone(), subject.public_record()))
            .collect(),
    )
}

pub fn zk_oracle_reserve_attester_root(attesters: &[ReserveAttester]) -> String {
    keyed_record_root(
        "ZK-ORACLE-RESERVE-ATTESTER",
        attesters
            .iter()
            .map(|attester| (attester.attester_id.clone(), attester.public_record()))
            .collect(),
    )
}

pub fn zk_oracle_reserve_attester_set_root(attester_sets: &[ReserveAttesterSet]) -> String {
    keyed_record_root(
        "ZK-ORACLE-RESERVE-ATTESTER-SET",
        attester_sets
            .iter()
            .map(|set| (set.attester_set_id.clone(), set.public_record()))
            .collect(),
    )
}

pub fn zk_oracle_reserve_disclosure_root(disclosures: &[ReserveDisclosure]) -> String {
    keyed_record_root(
        "ZK-ORACLE-RESERVE-DISCLOSURE",
        disclosures
            .iter()
            .map(|disclosure| (disclosure.disclosure_id.clone(), disclosure.public_record()))
            .collect(),
    )
}

pub fn zk_oracle_reserve_attestation_root(attestations: &[ReserveAttestation]) -> String {
    keyed_record_root(
        "ZK-ORACLE-RESERVE-ATTESTATION",
        attestations
            .iter()
            .map(|attestation| {
                (
                    attestation.attestation_id.clone(),
                    attestation.public_record(),
                )
            })
            .collect(),
    )
}

pub fn zk_oracle_risk_policy_root(policies: &[RiskPolicy]) -> String {
    keyed_record_root(
        "ZK-ORACLE-RISK-POLICY",
        policies
            .iter()
            .map(|policy| (policy.policy_id.clone(), policy.public_record()))
            .collect(),
    )
}

pub fn zk_oracle_risk_assessment_root(assessments: &[RiskAssessment]) -> String {
    keyed_record_root(
        "ZK-ORACLE-RISK-ASSESSMENT",
        assessments
            .iter()
            .map(|assessment| (assessment.assessment_id.clone(), assessment.public_record()))
            .collect(),
    )
}

pub fn zk_oracle_sponsor_policy_root(policies: &[LowFeeSponsorPolicy]) -> String {
    keyed_record_root(
        "ZK-ORACLE-SPONSOR-POLICY",
        policies
            .iter()
            .map(|policy| (policy.sponsor_id.clone(), policy.public_record()))
            .collect(),
    )
}

pub fn zk_oracle_sponsorship_receipt_root(receipts: &[SponsorshipReceipt]) -> String {
    keyed_record_root(
        "ZK-ORACLE-SPONSORSHIP-RECEIPT",
        receipts
            .iter()
            .map(|receipt| (receipt.receipt_id.clone(), receipt.public_record()))
            .collect(),
    )
}

pub fn zk_oracle_circuit_decision_root(decisions: &[CircuitDecision]) -> String {
    keyed_record_root(
        "ZK-ORACLE-CIRCUIT-DECISION",
        decisions
            .iter()
            .map(|decision| (decision.decision_id.clone(), decision.public_record()))
            .collect(),
    )
}

pub fn zk_oracle_audit_event_root(events: &[OracleAuditEvent]) -> String {
    keyed_record_root(
        "ZK-ORACLE-AUDIT-EVENT",
        events
            .iter()
            .map(|event| (event.event_id.clone(), event.public_record()))
            .collect(),
    )
}

pub fn zk_oracle_state_root_from_record(record: &Value) -> String {
    zk_oracle_payload_root("ZK-ORACLE-STATE", record)
}

pub fn zk_oracle_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn zk_oracle_metadata_root(metadata: &Value) -> String {
    zk_oracle_payload_root("ZK-ORACLE-METADATA", metadata)
}

pub fn zk_oracle_string_commitment(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn zk_oracle_number_commitment(domain: &str, value: u64, blinding_root: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(value as i128),
            HashPart::Str(blinding_root),
        ],
        32,
    )
}

pub fn zk_oracle_string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    merkle_root(
        domain,
        &values
            .iter()
            .map(|value| Value::String(value.clone()))
            .collect::<Vec<_>>(),
    )
}

pub fn zk_oracle_publisher_weight_root(weights: &BTreeMap<String, u64>) -> String {
    let mut records = weights
        .iter()
        .map(|(publisher_id, weight)| {
            (
                publisher_id.clone(),
                json!({
                    "publisher_id": publisher_id,
                    "weight_bps": weight,
                }),
            )
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "ZK-ORACLE-PUBLISHER-WEIGHT",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn price_deviation_bps(left: u64, right: u64) -> u64 {
    if left == right {
        return 0;
    }
    let max = left.max(right);
    let min = left.min(right);
    if min == 0 {
        return ZK_ORACLE_MAX_BPS;
    }
    bounded_u128_to_u64(((max - min) as u128 * ZK_ORACLE_MAX_BPS as u128) / min as u128)
        .min(ZK_ORACLE_MAX_BPS)
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    bounded_u128_to_u64((numerator as u128 * ZK_ORACLE_MAX_BPS as u128) / denominator as u128)
}

pub fn risk_score_bps(
    price_deviation_bps: u64,
    twap_deviation_bps: u64,
    reserve_staleness_blocks: u64,
    reserve_solvency_bps: u64,
) -> u64 {
    let deviation_score = price_deviation_bps
        .max(twap_deviation_bps)
        .min(ZK_ORACLE_MAX_BPS);
    let stale_score = reserve_staleness_blocks
        .saturating_mul(250)
        .min(ZK_ORACLE_MAX_BPS);
    let solvency_score = if reserve_solvency_bps >= ZK_ORACLE_DEFAULT_MIN_SOLVENCY_BPS {
        0
    } else {
        ZK_ORACLE_DEFAULT_MIN_SOLVENCY_BPS
            .saturating_sub(reserve_solvency_bps)
            .saturating_mul(2)
            .min(ZK_ORACLE_MAX_BPS)
    };
    deviation_score.max(stale_score).max(solvency_score)
}

pub fn severity_from_score(score_bps: u64) -> RiskSeverity {
    if score_bps >= RiskSeverity::Critical.score_floor_bps() {
        RiskSeverity::Critical
    } else if score_bps >= RiskSeverity::Warn.score_floor_bps() {
        RiskSeverity::Warn
    } else if score_bps >= RiskSeverity::Watch.score_floor_bps() {
        RiskSeverity::Watch
    } else {
        RiskSeverity::Healthy
    }
}

pub fn action_from_severity(severity: RiskSeverity) -> RiskAction {
    match severity {
        RiskSeverity::Healthy => RiskAction::Allow,
        RiskSeverity::Watch => RiskAction::Watch,
        RiskSeverity::Warn => RiskAction::Throttle,
        RiskSeverity::Critical => RiskAction::BlockLiquidation,
    }
}

fn median_price_units(observations: &[PriceObservation]) -> u64 {
    let mut prices = observations
        .iter()
        .map(|observation| observation.price_units)
        .collect::<Vec<_>>();
    prices.sort_unstable();
    if prices.is_empty() {
        return 0;
    }
    if prices.len() % 2 == 1 {
        prices[prices.len() / 2]
    } else {
        let right = prices.len() / 2;
        bounded_u128_to_u64((prices[right - 1] as u128 + prices[right] as u128) / 2)
    }
}

fn weighted_price_units(observations: &[PriceObservation], weights: &BTreeMap<String, u64>) -> u64 {
    let mut numerator = 0_u128;
    let mut denominator = 0_u128;
    for observation in observations {
        let weight = weights
            .get(&observation.publisher_id)
            .copied()
            .unwrap_or(1)
            .max(1);
        numerator = numerator.saturating_add(observation.price_units as u128 * weight as u128);
        denominator = denominator.saturating_add(weight as u128);
    }
    if denominator == 0 {
        return median_price_units(observations);
    }
    bounded_u128_to_u64(numerator / denominator)
}

fn weighted_confidence_bps(
    observations: &[PriceObservation],
    weights: &BTreeMap<String, u64>,
) -> u64 {
    let mut numerator = 0_u128;
    let mut denominator = 0_u128;
    for observation in observations {
        let weight = weights
            .get(&observation.publisher_id)
            .copied()
            .unwrap_or(1)
            .max(1);
        numerator = numerator.saturating_add(observation.confidence_bps as u128 * weight as u128);
        denominator = denominator.saturating_add(weight as u128);
    }
    if denominator == 0 {
        return 0;
    }
    bounded_u128_to_u64(numerator / denominator).min(ZK_ORACLE_MAX_BPS)
}

fn bounded_u128_to_u64(value: u128) -> u64 {
    value.min(u64::MAX as u128) as u64
}

fn validate_percent_bps(value: u64, label: &str) -> ZkOracleResult<()> {
    if value > ZK_ORACLE_MAX_BPS {
        return Err(format!("{label} cannot exceed {ZK_ORACLE_MAX_BPS} bps"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> ZkOracleResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_non_empty(value: &str, label: &str) -> ZkOracleResult<()> {
    if value.is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn keyed_record_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        domain,
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_has_private_updates_and_roots() {
        let state = ZkOracleState::devnet().expect("devnet state");
        assert!(state.state_root().len() == 64);
        assert!(state.public_record().get("state_root").is_some());
        assert!(state.private_envelopes.len() >= 7);
        assert!(state.transcripts.len() >= 10);
        assert!(state.aggregates.len() >= 3);
        assert!(state.reserve_disclosures.len() == 1);
        assert!(state.reserve_attestations.len() >= 2);
        assert!(state.total_sponsored_fee_units() > 0);
    }

    #[test]
    fn reserve_quorum_is_weighted() {
        let state = ZkOracleState::devnet().expect("devnet state");
        let disclosure_id = state
            .reserve_disclosures
            .keys()
            .next()
            .expect("disclosure")
            .clone();
        let (weight, signers) = state
            .validate_reserve_quorum(&disclosure_id)
            .expect("weighted quorum");
        assert!(weight >= 3);
        assert_eq!(signers.len(), 2);
    }

    #[test]
    fn state_root_changes_with_height() {
        let mut state = ZkOracleState::devnet().expect("devnet state");
        let before = state.state_root();
        state.set_height(state.height + 1);
        let after = state.state_root();
        assert_ne!(before, after);
    }
}
