use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateTreasuryRiskSentinelResult<T> = Result<T, String>;

pub const PRIVATE_TREASURY_RISK_SENTINEL_PROTOCOL_ID: &str =
    "nebula-private-treasury-risk-sentinel-v1";
pub const PRIVATE_TREASURY_RISK_SENTINEL_PUBLIC_RECORD_SCHEMA: &str =
    "private-treasury-risk-sentinel-public-record-v1";
pub const PRIVATE_TREASURY_RISK_SENTINEL_PROTOCOL_VERSION: u32 = 1;
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEVNET_HEIGHT: u64 = 2_048;
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEVNET_NETWORK: &str = "monero-devnet";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEVNET_TREASURY_ASSET_ID: &str = "dxmr-devnet";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const PRIVATE_TREASURY_RISK_SENTINEL_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_TREASURY_RISK_SENTINEL_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PRIVATE_TREASURY_RISK_SENTINEL_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PRIVATE_TREASURY_RISK_SENTINEL_ALERT_ENVELOPE_SCHEME: &str =
    "ml-kem-1024+xchacha20poly1305-private-risk-alert-v1";
pub const PRIVATE_TREASURY_RISK_SENTINEL_EXPOSURE_COMMITMENT_SCHEME: &str =
    "shielded-treasury-exposure-commitment-v1";
pub const PRIVATE_TREASURY_RISK_SENTINEL_AUDIT_RECEIPT_SCHEMA: &str =
    "private-treasury-audit-receipt-v1";
pub const PRIVATE_TREASURY_RISK_SENTINEL_CHALLENGE_PROOF_SYSTEM: &str =
    "pq-treasury-risk-sentinel-challenge-proof-v1";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_ORACLE_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_ALERT_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_RECOMMENDATION_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 216;
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_AUDIT_TTL_BLOCKS: u64 = 1_440;
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 1_024;
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_MAX_VAULT_EXPOSURE_BPS: u64 = 6_500;
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_WARNING_EXPOSURE_BPS: u64 = 5_000;
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_HALT_EXPOSURE_BPS: u64 = 8_000;
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_MIN_LIQUIDATION_RESERVE_UNITS: u64 = 250_000;
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_LOW_FEE_RESERVE_TARGET_BPS: u64 = 1_250;
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_LOW_FEE_RESERVE_WARN_BPS: u64 = 850;
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_SLASH_BPS: u64 = 2_500;
pub const PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_REPORTER_REWARD_BPS: u64 = 1_000;
pub const PRIVATE_TREASURY_RISK_SENTINEL_MAX_BPS: u64 = 10_000;
pub const PRIVATE_TREASURY_RISK_SENTINEL_MAX_VAULTS: usize = 65_536;
pub const PRIVATE_TREASURY_RISK_SENTINEL_MAX_FEEDS: usize = 262_144;
pub const PRIVATE_TREASURY_RISK_SENTINEL_MAX_BUDGETS: usize = 65_536;
pub const PRIVATE_TREASURY_RISK_SENTINEL_MAX_SENTINELS: usize = 16_384;
pub const PRIVATE_TREASURY_RISK_SENTINEL_MAX_SIGNATURES: usize = 524_288;
pub const PRIVATE_TREASURY_RISK_SENTINEL_MAX_ALERTS: usize = 262_144;
pub const PRIVATE_TREASURY_RISK_SENTINEL_MAX_RECOMMENDATIONS: usize = 131_072;
pub const PRIVATE_TREASURY_RISK_SENTINEL_MAX_RECEIPTS: usize = 262_144;
pub const PRIVATE_TREASURY_RISK_SENTINEL_MAX_CHALLENGES: usize = 65_536;
pub const PRIVATE_TREASURY_RISK_SENTINEL_MAX_EVENTS: usize = 524_288;
pub const PRIVATE_TREASURY_RISK_SENTINEL_DOMAIN_CONFIG: &str = "CONFIG";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DOMAIN_CONFIG_METADATA: &str = "CONFIG-METADATA";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DOMAIN_VAULT_EXPOSURE: &str = "VAULT-EXPOSURE";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DOMAIN_ORACLE_FEED: &str = "ORACLE-RISK-FEED";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DOMAIN_RESERVE_BUDGET: &str = "LIQUIDATION-RESERVE-BUDGET";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DOMAIN_SENTINEL_MEMBER: &str = "SENTINEL-MEMBER";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DOMAIN_PQ_SIGNATURE: &str = "PQ-SENTINEL-SIGNATURE";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DOMAIN_ENCRYPTED_ALERT: &str = "ENCRYPTED-RISK-ALERT";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DOMAIN_CIRCUIT_RECOMMENDATION: &str =
    "CIRCUIT-BREAKER-RECOMMENDATION";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DOMAIN_AUDIT_RECEIPT: &str = "PRIVATE-AUDIT-RECEIPT";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DOMAIN_CHALLENGE_EVIDENCE: &str =
    "SLASHING-CHALLENGE-EVIDENCE";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DOMAIN_COUNTERS: &str = "COUNTERS";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DOMAIN_ROOTS: &str = "ROOTS";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DOMAIN_STATE: &str = "STATE";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DOMAIN_EVENT: &str = "EVENT";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DOMAIN_NULLIFIERS: &str = "NULLIFIERS";
pub const PRIVATE_TREASURY_RISK_SENTINEL_DOMAIN_COLLECTION_LEAF: &str = "COLLECTION-LEAF";

macro_rules! impl_as_str {
    ($name:ident { $($variant:ident => $value:expr),+ $(,)? }) => {
        impl $name {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value,)+
                }
            }
        }
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreasuryVaultKind {
    ProtocolReserve,
    InsuranceFund,
    LiquidationBackstop,
    FeeAccumulator,
    BridgeBuffer,
    StablecoinReserve,
    YieldBuffer,
    EmergencyMultisig,
    GovernanceEscrow,
    SlashingVault,
}

impl_as_str!(TreasuryVaultKind {
    ProtocolReserve => "protocol_reserve",
    InsuranceFund => "insurance_fund",
    LiquidationBackstop => "liquidation_backstop",
    FeeAccumulator => "fee_accumulator",
    BridgeBuffer => "bridge_buffer",
    StablecoinReserve => "stablecoin_reserve",
    YieldBuffer => "yield_buffer",
    EmergencyMultisig => "emergency_multisig",
    GovernanceEscrow => "governance_escrow",
    SlashingVault => "slashing_vault",
});

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreasuryVaultStatus {
    Draft,
    Active,
    Watching,
    Constrained,
    Frozen,
    Draining,
    Retired,
}

impl_as_str!(TreasuryVaultStatus {
    Draft => "draft",
    Active => "active",
    Watching => "watching",
    Constrained => "constrained",
    Frozen => "frozen",
    Draining => "draining",
    Retired => "retired",
});

impl TreasuryVaultStatus {
    pub fn accepts_exposure(self) -> bool {
        matches!(self, Self::Active | Self::Watching | Self::Constrained)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExposureRiskBand {
    Green,
    Watch,
    Caution,
    Critical,
    CircuitOpen,
    Retired,
}

impl_as_str!(ExposureRiskBand {
    Green => "green",
    Watch => "watch",
    Caution => "caution",
    Critical => "critical",
    CircuitOpen => "circuit_open",
    Retired => "retired",
});

impl ExposureRiskBand {
    pub fn score_bps(self) -> u64 {
        match self {
            Self::Green => 500,
            Self::Watch => 2_000,
            Self::Caution => 5_000,
            Self::Critical => 8_000,
            Self::CircuitOpen | Self::Retired => 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateRiskFeedKind {
    Volatility,
    LiquidityDepth,
    OracleDeviation,
    BridgeReserve,
    WithdrawalPressure,
    LiquidationQueue,
    FeeMarketStress,
    SequencerLatency,
    GovernanceSignal,
    PrivacySetHealth,
}

impl_as_str!(PrivateRiskFeedKind {
    Volatility => "volatility",
    LiquidityDepth => "liquidity_depth",
    OracleDeviation => "oracle_deviation",
    BridgeReserve => "bridge_reserve",
    WithdrawalPressure => "withdrawal_pressure",
    LiquidationQueue => "liquidation_queue",
    FeeMarketStress => "fee_market_stress",
    SequencerLatency => "sequencer_latency",
    GovernanceSignal => "governance_signal",
    PrivacySetHealth => "privacy_set_health",
});

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskFeedStatus {
    Submitted,
    Verified,
    Counted,
    Stale,
    Rejected,
    Challenged,
}

impl_as_str!(RiskFeedStatus {
    Submitted => "submitted",
    Verified => "verified",
    Counted => "counted",
    Stale => "stale",
    Rejected => "rejected",
    Challenged => "challenged",
});

impl RiskFeedStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Verified | Self::Counted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveBudgetStatus {
    Planned,
    Funded,
    Spending,
    Low,
    Exhausted,
    Refilled,
    Closed,
}

impl_as_str!(ReserveBudgetStatus {
    Planned => "planned",
    Funded => "funded",
    Spending => "spending",
    Low => "low",
    Exhausted => "exhausted",
    Refilled => "refilled",
    Closed => "closed",
});

impl ReserveBudgetStatus {
    pub fn spendable(self) -> bool {
        matches!(
            self,
            Self::Funded | Self::Spending | Self::Low | Self::Refilled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SentinelRole {
    TreasuryObserver,
    RiskOracleSigner,
    LiquidationBudgetAuditor,
    CircuitBreakerSigner,
    AlertRelayer,
    ReceiptAuditor,
    ChallengeReporter,
}

impl_as_str!(SentinelRole {
    TreasuryObserver => "treasury_observer",
    RiskOracleSigner => "risk_oracle_signer",
    LiquidationBudgetAuditor => "liquidation_budget_auditor",
    CircuitBreakerSigner => "circuit_breaker_signer",
    AlertRelayer => "alert_relayer",
    ReceiptAuditor => "receipt_auditor",
    ChallengeReporter => "challenge_reporter",
});

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SentinelStatus {
    Candidate,
    Active,
    Rotating,
    Suspended,
    Slashed,
    Retired,
}

impl_as_str!(SentinelStatus {
    Candidate => "candidate",
    Active => "active",
    Rotating => "rotating",
    Suspended => "suspended",
    Slashed => "slashed",
    Retired => "retired",
});

impl SentinelStatus {
    pub fn signing(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSentinelSignatureKind {
    ExposureSnapshot,
    OracleRiskFeed,
    ReserveBudget,
    AlertEnvelope,
    CircuitRecommendation,
    AuditReceipt,
    ChallengeEvidence,
    SlashingDecision,
}

impl_as_str!(PqSentinelSignatureKind {
    ExposureSnapshot => "exposure_snapshot",
    OracleRiskFeed => "oracle_risk_feed",
    ReserveBudget => "reserve_budget",
    AlertEnvelope => "alert_envelope",
    CircuitRecommendation => "circuit_recommendation",
    AuditReceipt => "audit_receipt",
    ChallengeEvidence => "challenge_evidence",
    SlashingDecision => "slashing_decision",
});

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAlertSeverity {
    Info,
    Watch,
    Warn,
    Critical,
    Emergency,
}

impl_as_str!(RiskAlertSeverity {
    Info => "info",
    Watch => "watch",
    Warn => "warn",
    Critical => "critical",
    Emergency => "emergency",
});

impl RiskAlertSeverity {
    pub fn score_bps(self) -> u64 {
        match self {
            Self::Info => 500,
            Self::Watch => 2_500,
            Self::Warn => 5_500,
            Self::Critical => 8_500,
            Self::Emergency => 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAlertStatus {
    Sealed,
    Routed,
    Acknowledged,
    Escalated,
    Expired,
    Challenged,
}

impl_as_str!(RiskAlertStatus {
    Sealed => "sealed",
    Routed => "routed",
    Acknowledged => "acknowledged",
    Escalated => "escalated",
    Expired => "expired",
    Challenged => "challenged",
});

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitBreakerAction {
    Observe,
    TightenLimits,
    ThrottleWithdrawals,
    RaiseLiquidationBuffer,
    PauseRiskyVault,
    PauseLiquidations,
    PauseTreasuryOutflow,
    EmergencyHalt,
}

impl_as_str!(CircuitBreakerAction {
    Observe => "observe",
    TightenLimits => "tighten_limits",
    ThrottleWithdrawals => "throttle_withdrawals",
    RaiseLiquidationBuffer => "raise_liquidation_buffer",
    PauseRiskyVault => "pause_risky_vault",
    PauseLiquidations => "pause_liquidations",
    PauseTreasuryOutflow => "pause_treasury_outflow",
    EmergencyHalt => "emergency_halt",
});

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitRecommendationStatus {
    Draft,
    Signed,
    QuorumMet,
    Published,
    Executed,
    Rejected,
    Expired,
}

impl_as_str!(CircuitRecommendationStatus {
    Draft => "draft",
    Signed => "signed",
    QuorumMet => "quorum_met",
    Published => "published",
    Executed => "executed",
    Rejected => "rejected",
    Expired => "expired",
});

impl CircuitRecommendationStatus {
    pub fn accepted(self) -> bool {
        matches!(self, Self::QuorumMet | Self::Published | Self::Executed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditReceiptKind {
    ExposureReconciliation,
    ReserveBudgetSpend,
    AlertDelivery,
    CircuitDecision,
    OracleFeedSampling,
    SentinelRotation,
    ChallengeResolution,
}

impl_as_str!(AuditReceiptKind {
    ExposureReconciliation => "exposure_reconciliation",
    ReserveBudgetSpend => "reserve_budget_spend",
    AlertDelivery => "alert_delivery",
    CircuitDecision => "circuit_decision",
    OracleFeedSampling => "oracle_feed_sampling",
    SentinelRotation => "sentinel_rotation",
    ChallengeResolution => "challenge_resolution",
});

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    StaleOracleFeed,
    InvalidExposureCommitment,
    MisreportedReserveBudget,
    MissingAlertDelivery,
    BadCircuitRecommendation,
    InvalidAuditReceipt,
    EquivocatedSignature,
    PrivacyLeakage,
}

impl_as_str!(ChallengeKind {
    StaleOracleFeed => "stale_oracle_feed",
    InvalidExposureCommitment => "invalid_exposure_commitment",
    MisreportedReserveBudget => "misreported_reserve_budget",
    MissingAlertDelivery => "missing_alert_delivery",
    BadCircuitRecommendation => "bad_circuit_recommendation",
    InvalidAuditReceipt => "invalid_audit_receipt",
    EquivocatedSignature => "equivocated_signature",
    PrivacyLeakage => "privacy_leakage",
});

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Opened,
    EvidenceSubmitted,
    UnderReview,
    Sustained,
    Rejected,
    Slashed,
    Expired,
}

impl_as_str!(ChallengeStatus {
    Opened => "opened",
    EvidenceSubmitted => "evidence_submitted",
    UnderReview => "under_review",
    Sustained => "sustained",
    Rejected => "rejected",
    Slashed => "slashed",
    Expired => "expired",
});

impl ChallengeStatus {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Sustained | Self::Rejected | Self::Slashed | Self::Expired
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTreasuryRiskSentinelConfig {
    pub protocol_id: String,
    pub network: String,
    pub treasury_asset_id: String,
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub oracle_ttl_blocks: u64,
    pub alert_ttl_blocks: u64,
    pub recommendation_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub audit_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_vault_exposure_bps: u64,
    pub warning_exposure_bps: u64,
    pub halt_exposure_bps: u64,
    pub min_liquidation_reserve_units: u64,
    pub low_fee_reserve_target_bps: u64,
    pub low_fee_reserve_warn_bps: u64,
    pub slash_bps: u64,
    pub reporter_reward_bps: u64,
    pub created_at_height: u64,
    pub metadata_root: String,
}

impl PrivateTreasuryRiskSentinelConfig {
    pub fn devnet(created_at_height: u64) -> Self {
        Self::new(
            PRIVATE_TREASURY_RISK_SENTINEL_DEVNET_NETWORK,
            PRIVATE_TREASURY_RISK_SENTINEL_DEVNET_TREASURY_ASSET_ID,
            PRIVATE_TREASURY_RISK_SENTINEL_DEVNET_FEE_ASSET_ID,
            created_at_height,
            &json!({"mode": "devnet", "privacy": "shielded-treasury-risk"}),
        )
    }

    pub fn new(
        network: &str,
        treasury_asset_id: &str,
        fee_asset_id: &str,
        created_at_height: u64,
        metadata: &Value,
    ) -> Self {
        Self {
            protocol_id: PRIVATE_TREASURY_RISK_SENTINEL_PROTOCOL_ID.to_string(),
            network: network.to_string(),
            treasury_asset_id: treasury_asset_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            epoch_blocks: PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_EPOCH_BLOCKS,
            oracle_ttl_blocks: PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_ORACLE_TTL_BLOCKS,
            alert_ttl_blocks: PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_ALERT_TTL_BLOCKS,
            recommendation_ttl_blocks:
                PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_RECOMMENDATION_TTL_BLOCKS,
            challenge_window_blocks: PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            audit_ttl_blocks: PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_AUDIT_TTL_BLOCKS,
            min_privacy_set_size: PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_vault_exposure_bps: PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_MAX_VAULT_EXPOSURE_BPS,
            warning_exposure_bps: PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_WARNING_EXPOSURE_BPS,
            halt_exposure_bps: PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_HALT_EXPOSURE_BPS,
            min_liquidation_reserve_units:
                PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_MIN_LIQUIDATION_RESERVE_UNITS,
            low_fee_reserve_target_bps:
                PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_LOW_FEE_RESERVE_TARGET_BPS,
            low_fee_reserve_warn_bps:
                PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_LOW_FEE_RESERVE_WARN_BPS,
            slash_bps: PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_SLASH_BPS,
            reporter_reward_bps: PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_REPORTER_REWARD_BPS,
            created_at_height,
            metadata_root: payload_root("CONFIG-METADATA", metadata),
        }
    }

    pub fn validate(&self) -> PrivateTreasuryRiskSentinelResult<()> {
        require_non_empty("protocol_id", &self.protocol_id)?;
        require_non_empty("network", &self.network)?;
        require_non_empty("treasury_asset_id", &self.treasury_asset_id)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_positive("epoch_blocks", self.epoch_blocks)?;
        require_bps("max_vault_exposure_bps", self.max_vault_exposure_bps)?;
        require_bps("warning_exposure_bps", self.warning_exposure_bps)?;
        require_bps("halt_exposure_bps", self.halt_exposure_bps)?;
        require_bps(
            "low_fee_reserve_target_bps",
            self.low_fee_reserve_target_bps,
        )?;
        require_bps("low_fee_reserve_warn_bps", self.low_fee_reserve_warn_bps)?;
        require_bps("slash_bps", self.slash_bps)?;
        require_bps("reporter_reward_bps", self.reporter_reward_bps)?;
        if self.warning_exposure_bps > self.max_vault_exposure_bps {
            return Err("warning_exposure_bps exceeds max_vault_exposure_bps".to_string());
        }
        if self.max_vault_exposure_bps > self.halt_exposure_bps {
            return Err("max_vault_exposure_bps exceeds halt_exposure_bps".to_string());
        }
        if self.low_fee_reserve_warn_bps > self.low_fee_reserve_target_bps {
            return Err("low_fee_reserve_warn_bps exceeds low_fee_reserve_target_bps".to_string());
        }
        if self.reporter_reward_bps > self.slash_bps {
            return Err("reporter_reward_bps exceeds slash_bps".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_treasury_risk_sentinel_config",
            "schema": PRIVATE_TREASURY_RISK_SENTINEL_PUBLIC_RECORD_SCHEMA,
            "chain_id": CHAIN_ID,
            "protocol_id": self.protocol_id,
            "protocol_version": PRIVATE_TREASURY_RISK_SENTINEL_PROTOCOL_VERSION,
            "network": self.network,
            "treasury_asset_id": self.treasury_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "oracle_ttl_blocks": self.oracle_ttl_blocks,
            "alert_ttl_blocks": self.alert_ttl_blocks,
            "recommendation_ttl_blocks": self.recommendation_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "audit_ttl_blocks": self.audit_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_vault_exposure_bps": self.max_vault_exposure_bps,
            "warning_exposure_bps": self.warning_exposure_bps,
            "halt_exposure_bps": self.halt_exposure_bps,
            "min_liquidation_reserve_units": self.min_liquidation_reserve_units,
            "low_fee_reserve_target_bps": self.low_fee_reserve_target_bps,
            "low_fee_reserve_warn_bps": self.low_fee_reserve_warn_bps,
            "slash_bps": self.slash_bps,
            "reporter_reward_bps": self.reporter_reward_bps,
            "created_at_height": self.created_at_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        sentinel_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }
}

macro_rules! record_struct {
    ($name:ident, $root_domain:expr, { $($field:ident : $type:ty),+ $(,)? }) => {
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $name {
            $(pub $field: $type,)+
        }

        impl $name {
            pub fn public_record(&self) -> Value {
                json!({
                    "kind": stringify!($name),
                    "chain_id": CHAIN_ID,
                    $(stringify!($field): self.$field,)+
                })
            }

            pub fn root(&self) -> String {
                sentinel_hash($root_domain, &[HashPart::Json(&self.public_record())])
            }
        }
    };
}

record_struct!(ShieldedTreasuryVaultExposure, "VAULT-EXPOSURE", {
    vault_id: String,
    vault_kind: TreasuryVaultKind,
    status: TreasuryVaultStatus,
    asset_id: String,
    controller_commitment: String,
    view_key_commitment_root: String,
    exposure_commitment_root: String,
    liability_commitment_root: String,
    reserve_commitment_root: String,
    max_exposure_bps: u64,
    observed_exposure_bps: u64,
    risk_band: ExposureRiskBand,
    last_observed_height: u64,
    privacy_set_size: u64,
    nonce: u64,
});

record_struct!(PrivateOracleRiskFeed, "ORACLE-RISK-FEED", {
    feed_id: String,
    feed_kind: PrivateRiskFeedKind,
    status: RiskFeedStatus,
    source_committee_id: String,
    subject_id: String,
    risk_value_bps: u64,
    confidence_bps: u64,
    sealed_payload_root: String,
    range_proof_root: String,
    pq_signature_root: String,
    observed_at_height: u64,
    expires_at_height: u64,
    nonce: u64,
});

record_struct!(LowFeeLiquidationReserveBudget, "LIQUIDATION-RESERVE-BUDGET", {
    budget_id: String,
    vault_id: String,
    sponsor_commitment: String,
    fee_asset_id: String,
    total_budget_units: u64,
    spent_budget_units: u64,
    max_fee_per_liquidation_units: u64,
    target_reserve_bps: u64,
    status: ReserveBudgetStatus,
    proof_root: String,
    opened_at_height: u64,
    expires_at_height: u64,
    nonce: u64,
});

record_struct!(SentinelMember, "SENTINEL-MEMBER", {
    sentinel_id: String,
    operator_commitment: String,
    role: SentinelRole,
    status: SentinelStatus,
    pq_public_key_commitment: String,
    kem_public_key_commitment: String,
    bond_commitment_root: String,
    weight: u64,
    joined_at_height: u64,
    rotation_nonce: u64,
});

record_struct!(PqSentinelSignature, "PQ-SENTINEL-SIGNATURE", {
    signature_id: String,
    sentinel_id: String,
    signature_kind: PqSentinelSignatureKind,
    subject_id: String,
    subject_root: String,
    signature_root: String,
    transcript_root: String,
    signed_at_height: u64,
    expires_at_height: u64,
    nonce: u64,
});

record_struct!(EncryptedRiskAlert, "ENCRYPTED-RISK-ALERT", {
    alert_id: String,
    severity: RiskAlertSeverity,
    status: RiskAlertStatus,
    vault_id: String,
    subject_root: String,
    recipient_commitment: String,
    ciphertext_root: String,
    kem_ciphertext_root: String,
    aad_root: String,
    created_at_height: u64,
    expires_at_height: u64,
    nonce: u64,
});

record_struct!(CircuitBreakerRecommendation, "CIRCUIT-BREAKER-RECOMMENDATION", {
    recommendation_id: String,
    action: CircuitBreakerAction,
    status: CircuitRecommendationStatus,
    vault_id: String,
    triggering_feed_id: String,
    risk_score_bps: u64,
    rationale_root: String,
    signature_set_root: String,
    created_at_height: u64,
    expires_at_height: u64,
    nonce: u64,
});

record_struct!(PrivateAuditReceipt, "PRIVATE-AUDIT-RECEIPT", {
    receipt_id: String,
    receipt_kind: AuditReceiptKind,
    subject_id: String,
    subject_root: String,
    auditor_commitment: String,
    encrypted_notes_root: String,
    public_findings_root: String,
    pq_signature_root: String,
    issued_at_height: u64,
    expires_at_height: u64,
    nonce: u64,
});

record_struct!(SlashingChallengeEvidence, "SLASHING-CHALLENGE-EVIDENCE", {
    challenge_id: String,
    challenge_kind: ChallengeKind,
    status: ChallengeStatus,
    accused_sentinel_id: String,
    reporter_commitment: String,
    subject_id: String,
    evidence_root: String,
    encrypted_witness_root: String,
    challenge_bond_units: u64,
    slash_units: u64,
    reporter_reward_units: u64,
    opened_at_height: u64,
    expires_at_height: u64,
    nonce: u64,
});

impl ShieldedTreasuryVaultExposure {
    pub fn devnet(height: u64) -> Self {
        Self {
            vault_id: id_hash("VAULT-ID", "devnet-protocol-reserve", height, 0),
            vault_kind: TreasuryVaultKind::ProtocolReserve,
            status: TreasuryVaultStatus::Active,
            asset_id: PRIVATE_TREASURY_RISK_SENTINEL_DEVNET_TREASURY_ASSET_ID.to_string(),
            controller_commitment: "devnet-protocol-reserve-controller".to_string(),
            view_key_commitment_root: "devnet-protocol-reserve-view-key-root".to_string(),
            exposure_commitment_root: "devnet-protocol-reserve-exposure-root".to_string(),
            liability_commitment_root: "devnet-protocol-reserve-liability-root".to_string(),
            reserve_commitment_root: "devnet-protocol-reserve-commitment-root".to_string(),
            max_exposure_bps: PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_MAX_VAULT_EXPOSURE_BPS,
            observed_exposure_bps: 1_250,
            risk_band: ExposureRiskBand::Green,
            last_observed_height: height,
            privacy_set_size: PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_MIN_PRIVACY_SET_SIZE,
            nonce: 0,
        }
    }

    pub fn validate(
        &self,
        config: &PrivateTreasuryRiskSentinelConfig,
    ) -> PrivateTreasuryRiskSentinelResult<()> {
        require_non_empty("vault_id", &self.vault_id)?;
        require_non_empty("asset_id", &self.asset_id)?;
        require_non_empty("controller_commitment", &self.controller_commitment)?;
        require_non_empty("view_key_commitment_root", &self.view_key_commitment_root)?;
        require_non_empty("exposure_commitment_root", &self.exposure_commitment_root)?;
        require_non_empty("liability_commitment_root", &self.liability_commitment_root)?;
        require_non_empty("reserve_commitment_root", &self.reserve_commitment_root)?;
        require_bps("max_exposure_bps", self.max_exposure_bps)?;
        require_bps("observed_exposure_bps", self.observed_exposure_bps)?;
        if self.max_exposure_bps > config.halt_exposure_bps {
            return Err("vault max_exposure_bps exceeds halt_exposure_bps".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("vault privacy_set_size below config minimum".to_string());
        }
        Ok(())
    }
}

impl PrivateOracleRiskFeed {
    pub fn validate(&self) -> PrivateTreasuryRiskSentinelResult<()> {
        require_non_empty("feed_id", &self.feed_id)?;
        require_non_empty("source_committee_id", &self.source_committee_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_non_empty("sealed_payload_root", &self.sealed_payload_root)?;
        require_non_empty("range_proof_root", &self.range_proof_root)?;
        require_non_empty("pq_signature_root", &self.pq_signature_root)?;
        require_bps("risk_value_bps", self.risk_value_bps)?;
        require_bps("confidence_bps", self.confidence_bps)?;
        require_after(
            "expires_at_height",
            self.expires_at_height,
            self.observed_at_height,
        )
    }

    pub fn stale_at(&self, height: u64) -> bool {
        height > self.expires_at_height || matches!(self.status, RiskFeedStatus::Stale)
    }
}

impl LowFeeLiquidationReserveBudget {
    pub fn devnet(vault_id: &str, height: u64) -> Self {
        Self {
            budget_id: id_hash("RESERVE-BUDGET-ID", vault_id, height, 0),
            vault_id: vault_id.to_string(),
            sponsor_commitment: "devnet-liquidation-reserve-sponsor".to_string(),
            fee_asset_id: PRIVATE_TREASURY_RISK_SENTINEL_DEVNET_FEE_ASSET_ID.to_string(),
            total_budget_units:
                PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_MIN_LIQUIDATION_RESERVE_UNITS,
            spent_budget_units: 0,
            max_fee_per_liquidation_units: 8_000,
            target_reserve_bps: PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_LOW_FEE_RESERVE_TARGET_BPS,
            status: ReserveBudgetStatus::Funded,
            proof_root: "devnet-liquidation-reserve-proof-root".to_string(),
            opened_at_height: height,
            expires_at_height: height
                .saturating_add(PRIVATE_TREASURY_RISK_SENTINEL_DEFAULT_AUDIT_TTL_BLOCKS),
            nonce: 0,
        }
    }

    pub fn validate(&self) -> PrivateTreasuryRiskSentinelResult<()> {
        require_non_empty("budget_id", &self.budget_id)?;
        require_non_empty("vault_id", &self.vault_id)?;
        require_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("proof_root", &self.proof_root)?;
        require_positive("total_budget_units", self.total_budget_units)?;
        require_positive(
            "max_fee_per_liquidation_units",
            self.max_fee_per_liquidation_units,
        )?;
        require_bps("target_reserve_bps", self.target_reserve_bps)?;
        if self.spent_budget_units > self.total_budget_units {
            return Err("spent_budget_units exceeds total_budget_units".to_string());
        }
        require_after(
            "expires_at_height",
            self.expires_at_height,
            self.opened_at_height,
        )
    }

    pub fn remaining_units(&self) -> u64 {
        self.total_budget_units
            .saturating_sub(self.spent_budget_units)
    }

    pub fn remaining_bps(&self) -> u64 {
        if self.total_budget_units == 0 {
            0
        } else {
            self.remaining_units()
                .saturating_mul(PRIVATE_TREASURY_RISK_SENTINEL_MAX_BPS)
                / self.total_budget_units
        }
    }
}

impl SentinelMember {
    pub fn devnet(height: u64) -> Self {
        Self {
            sentinel_id: id_hash("SENTINEL-ID", "devnet-treasury-sentinel", height, 0),
            operator_commitment: "devnet-treasury-sentinel-operator".to_string(),
            role: SentinelRole::TreasuryObserver,
            status: SentinelStatus::Active,
            pq_public_key_commitment: "devnet-treasury-sentinel-pq-key".to_string(),
            kem_public_key_commitment: "devnet-treasury-sentinel-kem-key".to_string(),
            bond_commitment_root: "devnet-treasury-sentinel-bond-root".to_string(),
            weight: 1,
            joined_at_height: height,
            rotation_nonce: 0,
        }
    }

    pub fn validate(&self) -> PrivateTreasuryRiskSentinelResult<()> {
        require_non_empty("sentinel_id", &self.sentinel_id)?;
        require_non_empty("operator_commitment", &self.operator_commitment)?;
        require_non_empty("pq_public_key_commitment", &self.pq_public_key_commitment)?;
        require_non_empty("kem_public_key_commitment", &self.kem_public_key_commitment)?;
        require_non_empty("bond_commitment_root", &self.bond_commitment_root)?;
        require_positive("weight", self.weight)
    }
}

impl PqSentinelSignature {
    pub fn validate(&self) -> PrivateTreasuryRiskSentinelResult<()> {
        require_non_empty("signature_id", &self.signature_id)?;
        require_non_empty("sentinel_id", &self.sentinel_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_non_empty("subject_root", &self.subject_root)?;
        require_non_empty("signature_root", &self.signature_root)?;
        require_non_empty("transcript_root", &self.transcript_root)?;
        require_after(
            "expires_at_height",
            self.expires_at_height,
            self.signed_at_height,
        )
    }
}

impl EncryptedRiskAlert {
    pub fn validate(&self) -> PrivateTreasuryRiskSentinelResult<()> {
        require_non_empty("alert_id", &self.alert_id)?;
        require_non_empty("vault_id", &self.vault_id)?;
        require_non_empty("subject_root", &self.subject_root)?;
        require_non_empty("recipient_commitment", &self.recipient_commitment)?;
        require_non_empty("ciphertext_root", &self.ciphertext_root)?;
        require_non_empty("kem_ciphertext_root", &self.kem_ciphertext_root)?;
        require_non_empty("aad_root", &self.aad_root)?;
        require_after(
            "expires_at_height",
            self.expires_at_height,
            self.created_at_height,
        )
    }
}

impl CircuitBreakerRecommendation {
    pub fn validate(&self) -> PrivateTreasuryRiskSentinelResult<()> {
        require_non_empty("recommendation_id", &self.recommendation_id)?;
        require_non_empty("vault_id", &self.vault_id)?;
        require_non_empty("triggering_feed_id", &self.triggering_feed_id)?;
        require_non_empty("rationale_root", &self.rationale_root)?;
        require_non_empty("signature_set_root", &self.signature_set_root)?;
        require_bps("risk_score_bps", self.risk_score_bps)?;
        require_after(
            "expires_at_height",
            self.expires_at_height,
            self.created_at_height,
        )
    }
}

impl PrivateAuditReceipt {
    pub fn validate(&self) -> PrivateTreasuryRiskSentinelResult<()> {
        require_non_empty("receipt_id", &self.receipt_id)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_non_empty("subject_root", &self.subject_root)?;
        require_non_empty("auditor_commitment", &self.auditor_commitment)?;
        require_non_empty("encrypted_notes_root", &self.encrypted_notes_root)?;
        require_non_empty("public_findings_root", &self.public_findings_root)?;
        require_non_empty("pq_signature_root", &self.pq_signature_root)?;
        require_after(
            "expires_at_height",
            self.expires_at_height,
            self.issued_at_height,
        )
    }
}

impl SlashingChallengeEvidence {
    pub fn validate(&self) -> PrivateTreasuryRiskSentinelResult<()> {
        require_non_empty("challenge_id", &self.challenge_id)?;
        require_non_empty("accused_sentinel_id", &self.accused_sentinel_id)?;
        require_non_empty("reporter_commitment", &self.reporter_commitment)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_non_empty("evidence_root", &self.evidence_root)?;
        require_non_empty("encrypted_witness_root", &self.encrypted_witness_root)?;
        require_positive("challenge_bond_units", self.challenge_bond_units)?;
        if self.reporter_reward_units > self.slash_units {
            return Err("reporter_reward_units exceeds slash_units".to_string());
        }
        require_after(
            "expires_at_height",
            self.expires_at_height,
            self.opened_at_height,
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTreasuryRiskSentinelCounters {
    pub vault_count: u64,
    pub active_vault_count: u64,
    pub oracle_feed_count: u64,
    pub usable_oracle_feed_count: u64,
    pub reserve_budget_count: u64,
    pub spendable_reserve_budget_count: u64,
    pub sentinel_count: u64,
    pub signing_sentinel_count: u64,
    pub pq_signature_count: u64,
    pub alert_count: u64,
    pub open_alert_count: u64,
    pub recommendation_count: u64,
    pub accepted_recommendation_count: u64,
    pub audit_receipt_count: u64,
    pub challenge_count: u64,
    pub open_challenge_count: u64,
    pub total_liquidation_reserve_units: u64,
    pub remaining_liquidation_reserve_units: u64,
    pub max_observed_exposure_bps: u64,
    pub max_risk_score_bps: u64,
}

impl PrivateTreasuryRiskSentinelCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_treasury_risk_sentinel_counters",
            "chain_id": CHAIN_ID,
            "vault_count": self.vault_count,
            "active_vault_count": self.active_vault_count,
            "oracle_feed_count": self.oracle_feed_count,
            "usable_oracle_feed_count": self.usable_oracle_feed_count,
            "reserve_budget_count": self.reserve_budget_count,
            "spendable_reserve_budget_count": self.spendable_reserve_budget_count,
            "sentinel_count": self.sentinel_count,
            "signing_sentinel_count": self.signing_sentinel_count,
            "pq_signature_count": self.pq_signature_count,
            "alert_count": self.alert_count,
            "open_alert_count": self.open_alert_count,
            "recommendation_count": self.recommendation_count,
            "accepted_recommendation_count": self.accepted_recommendation_count,
            "audit_receipt_count": self.audit_receipt_count,
            "challenge_count": self.challenge_count,
            "open_challenge_count": self.open_challenge_count,
            "total_liquidation_reserve_units": self.total_liquidation_reserve_units,
            "remaining_liquidation_reserve_units": self.remaining_liquidation_reserve_units,
            "max_observed_exposure_bps": self.max_observed_exposure_bps,
            "max_risk_score_bps": self.max_risk_score_bps,
        })
    }

    pub fn root(&self) -> String {
        sentinel_hash("COUNTERS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTreasuryRiskSentinelRoots {
    pub config_root: String,
    pub vault_exposure_root: String,
    pub oracle_feed_root: String,
    pub reserve_budget_root: String,
    pub sentinel_member_root: String,
    pub pq_signature_root: String,
    pub encrypted_alert_root: String,
    pub circuit_recommendation_root: String,
    pub audit_receipt_root: String,
    pub challenge_evidence_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub counters_root: String,
}

impl PrivateTreasuryRiskSentinelRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_treasury_risk_sentinel_roots",
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "vault_exposure_root": self.vault_exposure_root,
            "oracle_feed_root": self.oracle_feed_root,
            "reserve_budget_root": self.reserve_budget_root,
            "sentinel_member_root": self.sentinel_member_root,
            "pq_signature_root": self.pq_signature_root,
            "encrypted_alert_root": self.encrypted_alert_root,
            "circuit_recommendation_root": self.circuit_recommendation_root,
            "audit_receipt_root": self.audit_receipt_root,
            "challenge_evidence_root": self.challenge_evidence_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn root(&self) -> String {
        sentinel_hash("ROOTS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTreasuryRiskSentinelState {
    pub config: PrivateTreasuryRiskSentinelConfig,
    pub height: u64,
    pub vault_exposures: BTreeMap<String, ShieldedTreasuryVaultExposure>,
    pub oracle_feeds: BTreeMap<String, PrivateOracleRiskFeed>,
    pub reserve_budgets: BTreeMap<String, LowFeeLiquidationReserveBudget>,
    pub sentinel_members: BTreeMap<String, SentinelMember>,
    pub pq_signatures: BTreeMap<String, PqSentinelSignature>,
    pub encrypted_alerts: BTreeMap<String, EncryptedRiskAlert>,
    pub circuit_recommendations: BTreeMap<String, CircuitBreakerRecommendation>,
    pub audit_receipts: BTreeMap<String, PrivateAuditReceipt>,
    pub challenge_evidence: BTreeMap<String, SlashingChallengeEvidence>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub events: Vec<String>,
}

impl PrivateTreasuryRiskSentinelState {
    pub fn new(config: PrivateTreasuryRiskSentinelConfig, height: u64) -> Self {
        Self {
            config,
            height,
            vault_exposures: BTreeMap::new(),
            oracle_feeds: BTreeMap::new(),
            reserve_budgets: BTreeMap::new(),
            sentinel_members: BTreeMap::new(),
            pq_signatures: BTreeMap::new(),
            encrypted_alerts: BTreeMap::new(),
            circuit_recommendations: BTreeMap::new(),
            audit_receipts: BTreeMap::new(),
            challenge_evidence: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            events: Vec::new(),
        }
    }

    pub fn devnet() -> Self {
        let height = PRIVATE_TREASURY_RISK_SENTINEL_DEVNET_HEIGHT;
        let config = PrivateTreasuryRiskSentinelConfig::devnet(height);
        let mut state = Self::new(config, height);
        let sentinel = SentinelMember::devnet(height);
        let vault = ShieldedTreasuryVaultExposure::devnet(height);
        let budget = LowFeeLiquidationReserveBudget::devnet(&vault.vault_id, height);
        state
            .sentinel_members
            .insert(sentinel.sentinel_id.clone(), sentinel);
        state.vault_exposures.insert(vault.vault_id.clone(), vault);
        state
            .reserve_budgets
            .insert(budget.budget_id.clone(), budget);
        state.events.push(event_root(
            "devnet-private-treasury-risk-sentinel-initialized",
            PRIVATE_TREASURY_RISK_SENTINEL_PROTOCOL_ID,
            height,
        ));
        state
    }

    pub fn update_height(&mut self, next_height: u64) -> PrivateTreasuryRiskSentinelResult<()> {
        if next_height < self.height {
            return Err("height update must be monotonic".to_string());
        }
        self.height = next_height;
        Ok(())
    }

    pub fn register_vault_exposure(
        &mut self,
        vault: ShieldedTreasuryVaultExposure,
    ) -> PrivateTreasuryRiskSentinelResult<()> {
        vault.validate(&self.config)?;
        require_insert_capacity(
            "vault_exposures",
            self.vault_exposures.len(),
            self.vault_exposures.contains_key(&vault.vault_id),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_VAULTS,
        )?;
        self.events.push(event_root(
            "vault_exposure_registered",
            &vault.vault_id,
            vault.last_observed_height,
        ));
        self.vault_exposures.insert(vault.vault_id.clone(), vault);
        Ok(())
    }

    pub fn submit_oracle_feed(
        &mut self,
        feed: PrivateOracleRiskFeed,
    ) -> PrivateTreasuryRiskSentinelResult<()> {
        feed.validate()?;
        require_insert_capacity(
            "oracle_feeds",
            self.oracle_feeds.len(),
            self.oracle_feeds.contains_key(&feed.feed_id),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_FEEDS,
        )?;
        self.events.push(event_root(
            "oracle_feed_submitted",
            &feed.feed_id,
            feed.observed_at_height,
        ));
        self.oracle_feeds.insert(feed.feed_id.clone(), feed);
        Ok(())
    }

    pub fn fund_reserve_budget(
        &mut self,
        budget: LowFeeLiquidationReserveBudget,
    ) -> PrivateTreasuryRiskSentinelResult<()> {
        budget.validate()?;
        require_insert_capacity(
            "reserve_budgets",
            self.reserve_budgets.len(),
            self.reserve_budgets.contains_key(&budget.budget_id),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_BUDGETS,
        )?;
        self.events.push(event_root(
            "reserve_budget_funded",
            &budget.budget_id,
            budget.opened_at_height,
        ));
        self.reserve_budgets
            .insert(budget.budget_id.clone(), budget);
        Ok(())
    }

    pub fn register_sentinel(
        &mut self,
        sentinel: SentinelMember,
    ) -> PrivateTreasuryRiskSentinelResult<()> {
        sentinel.validate()?;
        require_insert_capacity(
            "sentinel_members",
            self.sentinel_members.len(),
            self.sentinel_members.contains_key(&sentinel.sentinel_id),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_SENTINELS,
        )?;
        self.events.push(event_root(
            "sentinel_registered",
            &sentinel.sentinel_id,
            sentinel.joined_at_height,
        ));
        self.sentinel_members
            .insert(sentinel.sentinel_id.clone(), sentinel);
        Ok(())
    }

    pub fn add_pq_signature(
        &mut self,
        signature: PqSentinelSignature,
    ) -> PrivateTreasuryRiskSentinelResult<()> {
        signature.validate()?;
        if !self.sentinel_members.contains_key(&signature.sentinel_id) {
            return Err("signature references unknown sentinel".to_string());
        }
        require_insert_capacity(
            "pq_signatures",
            self.pq_signatures.len(),
            self.pq_signatures.contains_key(&signature.signature_id),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_SIGNATURES,
        )?;
        self.events.push(event_root(
            "pq_signature_added",
            &signature.signature_id,
            signature.signed_at_height,
        ));
        self.pq_signatures
            .insert(signature.signature_id.clone(), signature);
        Ok(())
    }

    pub fn route_encrypted_alert(
        &mut self,
        alert: EncryptedRiskAlert,
    ) -> PrivateTreasuryRiskSentinelResult<()> {
        alert.validate()?;
        require_insert_capacity(
            "encrypted_alerts",
            self.encrypted_alerts.len(),
            self.encrypted_alerts.contains_key(&alert.alert_id),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_ALERTS,
        )?;
        self.events.push(event_root(
            "encrypted_alert_routed",
            &alert.alert_id,
            alert.created_at_height,
        ));
        self.encrypted_alerts.insert(alert.alert_id.clone(), alert);
        Ok(())
    }

    pub fn publish_circuit_recommendation(
        &mut self,
        recommendation: CircuitBreakerRecommendation,
    ) -> PrivateTreasuryRiskSentinelResult<()> {
        recommendation.validate()?;
        require_insert_capacity(
            "circuit_recommendations",
            self.circuit_recommendations.len(),
            self.circuit_recommendations
                .contains_key(&recommendation.recommendation_id),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_RECOMMENDATIONS,
        )?;
        self.events.push(event_root(
            "circuit_recommendation_published",
            &recommendation.recommendation_id,
            recommendation.created_at_height,
        ));
        self.circuit_recommendations
            .insert(recommendation.recommendation_id.clone(), recommendation);
        Ok(())
    }

    pub fn issue_audit_receipt(
        &mut self,
        receipt: PrivateAuditReceipt,
    ) -> PrivateTreasuryRiskSentinelResult<()> {
        receipt.validate()?;
        require_insert_capacity(
            "audit_receipts",
            self.audit_receipts.len(),
            self.audit_receipts.contains_key(&receipt.receipt_id),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_RECEIPTS,
        )?;
        self.events.push(event_root(
            "audit_receipt_issued",
            &receipt.receipt_id,
            receipt.issued_at_height,
        ));
        self.audit_receipts
            .insert(receipt.receipt_id.clone(), receipt);
        Ok(())
    }

    pub fn open_challenge(
        &mut self,
        challenge: SlashingChallengeEvidence,
    ) -> PrivateTreasuryRiskSentinelResult<()> {
        challenge.validate()?;
        require_insert_capacity(
            "challenge_evidence",
            self.challenge_evidence.len(),
            self.challenge_evidence
                .contains_key(&challenge.challenge_id),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_CHALLENGES,
        )?;
        self.events.push(event_root(
            "challenge_opened",
            &challenge.challenge_id,
            challenge.opened_at_height,
        ));
        self.challenge_evidence
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(())
    }

    pub fn add_nullifier(&mut self, nullifier: &str) -> PrivateTreasuryRiskSentinelResult<()> {
        require_non_empty("nullifier", nullifier)?;
        if !self.consumed_nullifiers.insert(nullifier.to_string()) {
            return Err("nullifier already consumed".to_string());
        }
        self.events
            .push(event_root("nullifier_consumed", nullifier, self.height));
        Ok(())
    }

    pub fn counters(&self) -> PrivateTreasuryRiskSentinelCounters {
        let mut counters = PrivateTreasuryRiskSentinelCounters::default();
        counters.vault_count = self.vault_exposures.len() as u64;
        counters.active_vault_count = self
            .vault_exposures
            .values()
            .filter(|vault| vault.status.accepts_exposure())
            .count() as u64;
        counters.oracle_feed_count = self.oracle_feeds.len() as u64;
        counters.usable_oracle_feed_count = self
            .oracle_feeds
            .values()
            .filter(|feed| feed.status.usable() && !feed.stale_at(self.height))
            .count() as u64;
        counters.reserve_budget_count = self.reserve_budgets.len() as u64;
        counters.spendable_reserve_budget_count = self
            .reserve_budgets
            .values()
            .filter(|budget| budget.status.spendable())
            .count() as u64;
        counters.sentinel_count = self.sentinel_members.len() as u64;
        counters.signing_sentinel_count = self
            .sentinel_members
            .values()
            .filter(|sentinel| sentinel.status.signing())
            .count() as u64;
        counters.pq_signature_count = self.pq_signatures.len() as u64;
        counters.alert_count = self.encrypted_alerts.len() as u64;
        counters.open_alert_count = self
            .encrypted_alerts
            .values()
            .filter(|alert| {
                !matches!(
                    alert.status,
                    RiskAlertStatus::Expired | RiskAlertStatus::Challenged
                )
            })
            .count() as u64;
        counters.recommendation_count = self.circuit_recommendations.len() as u64;
        counters.accepted_recommendation_count = self
            .circuit_recommendations
            .values()
            .filter(|recommendation| recommendation.status.accepted())
            .count() as u64;
        counters.audit_receipt_count = self.audit_receipts.len() as u64;
        counters.challenge_count = self.challenge_evidence.len() as u64;
        counters.open_challenge_count = self
            .challenge_evidence
            .values()
            .filter(|challenge| !challenge.status.terminal())
            .count() as u64;
        counters.total_liquidation_reserve_units = self
            .reserve_budgets
            .values()
            .map(|budget| budget.total_budget_units)
            .sum();
        counters.remaining_liquidation_reserve_units = self
            .reserve_budgets
            .values()
            .map(LowFeeLiquidationReserveBudget::remaining_units)
            .sum();
        counters.max_observed_exposure_bps = self
            .vault_exposures
            .values()
            .map(|vault| vault.observed_exposure_bps)
            .fold(0, u64::max);
        counters.max_risk_score_bps = self
            .oracle_feeds
            .values()
            .map(|feed| feed.risk_value_bps)
            .chain(
                self.encrypted_alerts
                    .values()
                    .map(|alert| alert.severity.score_bps()),
            )
            .chain(
                self.circuit_recommendations
                    .values()
                    .map(|recommendation| recommendation.risk_score_bps),
            )
            .fold(0, u64::max);
        counters
    }

    pub fn roots(&self) -> PrivateTreasuryRiskSentinelRoots {
        let counters = self.counters();
        PrivateTreasuryRiskSentinelRoots {
            config_root: self.config.root(),
            vault_exposure_root: collection_root(
                "VAULT-EXPOSURES",
                self.vault_exposures
                    .values()
                    .map(ShieldedTreasuryVaultExposure::root),
            ),
            oracle_feed_root: collection_root(
                "ORACLE-FEEDS",
                self.oracle_feeds.values().map(PrivateOracleRiskFeed::root),
            ),
            reserve_budget_root: collection_root(
                "RESERVE-BUDGETS",
                self.reserve_budgets
                    .values()
                    .map(LowFeeLiquidationReserveBudget::root),
            ),
            sentinel_member_root: collection_root(
                "SENTINEL-MEMBERS",
                self.sentinel_members.values().map(SentinelMember::root),
            ),
            pq_signature_root: collection_root(
                "PQ-SIGNATURES",
                self.pq_signatures.values().map(PqSentinelSignature::root),
            ),
            encrypted_alert_root: collection_root(
                "ENCRYPTED-ALERTS",
                self.encrypted_alerts.values().map(EncryptedRiskAlert::root),
            ),
            circuit_recommendation_root: collection_root(
                "CIRCUIT-RECOMMENDATIONS",
                self.circuit_recommendations
                    .values()
                    .map(CircuitBreakerRecommendation::root),
            ),
            audit_receipt_root: collection_root(
                "AUDIT-RECEIPTS",
                self.audit_receipts.values().map(PrivateAuditReceipt::root),
            ),
            challenge_evidence_root: collection_root(
                "CHALLENGE-EVIDENCE",
                self.challenge_evidence
                    .values()
                    .map(SlashingChallengeEvidence::root),
            ),
            nullifier_root: collection_root("NULLIFIERS", self.consumed_nullifiers.iter().cloned()),
            event_root: collection_root("EVENTS", self.events.iter().cloned()),
            counters_root: counters.root(),
        }
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        sentinel_hash(
            "STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(PRIVATE_TREASURY_RISK_SENTINEL_PROTOCOL_VERSION as i128),
                HashPart::Int(self.height as i128),
                HashPart::Json(&roots.public_record()),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_treasury_risk_sentinel_state",
            "schema": PRIVATE_TREASURY_RISK_SENTINEL_PUBLIC_RECORD_SCHEMA,
            "chain_id": CHAIN_ID,
            "protocol_id": PRIVATE_TREASURY_RISK_SENTINEL_PROTOCOL_ID,
            "protocol_version": PRIVATE_TREASURY_RISK_SENTINEL_PROTOCOL_VERSION,
            "height": self.height,
            "hash_suite": PRIVATE_TREASURY_RISK_SENTINEL_HASH_SUITE,
            "pq_signature_scheme": PRIVATE_TREASURY_RISK_SENTINEL_PQ_SIGNATURE_SCHEME,
            "pq_kem_scheme": PRIVATE_TREASURY_RISK_SENTINEL_PQ_KEM_SCHEME,
            "alert_envelope_scheme": PRIVATE_TREASURY_RISK_SENTINEL_ALERT_ENVELOPE_SCHEME,
            "exposure_commitment_scheme": PRIVATE_TREASURY_RISK_SENTINEL_EXPOSURE_COMMITMENT_SCHEME,
            "challenge_proof_system": PRIVATE_TREASURY_RISK_SENTINEL_CHALLENGE_PROOF_SYSTEM,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn validate(&self) -> PrivateTreasuryRiskSentinelResult<()> {
        self.config.validate()?;
        require_capacity(
            "vault_exposures",
            self.vault_exposures.len(),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_VAULTS,
        )?;
        require_capacity(
            "oracle_feeds",
            self.oracle_feeds.len(),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_FEEDS,
        )?;
        require_capacity(
            "reserve_budgets",
            self.reserve_budgets.len(),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_BUDGETS,
        )?;
        require_capacity(
            "sentinel_members",
            self.sentinel_members.len(),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_SENTINELS,
        )?;
        require_capacity(
            "pq_signatures",
            self.pq_signatures.len(),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_SIGNATURES,
        )?;
        require_capacity(
            "encrypted_alerts",
            self.encrypted_alerts.len(),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_ALERTS,
        )?;
        require_capacity(
            "circuit_recommendations",
            self.circuit_recommendations.len(),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_RECOMMENDATIONS,
        )?;
        require_capacity(
            "audit_receipts",
            self.audit_receipts.len(),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_RECEIPTS,
        )?;
        require_capacity(
            "challenge_evidence",
            self.challenge_evidence.len(),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_CHALLENGES,
        )?;
        require_capacity(
            "events",
            self.events.len(),
            PRIVATE_TREASURY_RISK_SENTINEL_MAX_EVENTS,
        )?;
        for vault in self.vault_exposures.values() {
            vault.validate(&self.config)?;
        }
        for feed in self.oracle_feeds.values() {
            feed.validate()?;
        }
        for budget in self.reserve_budgets.values() {
            budget.validate()?;
            if !self.vault_exposures.contains_key(&budget.vault_id) {
                return Err(format!(
                    "reserve budget references unknown vault {}",
                    budget.vault_id
                ));
            }
        }
        for sentinel in self.sentinel_members.values() {
            sentinel.validate()?;
        }
        for signature in self.pq_signatures.values() {
            signature.validate()?;
            if !self.sentinel_members.contains_key(&signature.sentinel_id) {
                return Err(format!(
                    "signature references unknown sentinel {}",
                    signature.sentinel_id
                ));
            }
        }
        for alert in self.encrypted_alerts.values() {
            alert.validate()?;
            if !self.vault_exposures.contains_key(&alert.vault_id) {
                return Err(format!("alert references unknown vault {}", alert.vault_id));
            }
        }
        for recommendation in self.circuit_recommendations.values() {
            recommendation.validate()?;
            if !self.vault_exposures.contains_key(&recommendation.vault_id) {
                return Err(format!(
                    "recommendation references unknown vault {}",
                    recommendation.vault_id
                ));
            }
        }
        for receipt in self.audit_receipts.values() {
            receipt.validate()?;
        }
        for challenge in self.challenge_evidence.values() {
            challenge.validate()?;
            if !self
                .sentinel_members
                .contains_key(&challenge.accused_sentinel_id)
            {
                return Err(format!(
                    "challenge references unknown sentinel {}",
                    challenge.accused_sentinel_id
                ));
            }
        }
        Ok(())
    }
}

fn require_non_empty(field: &str, value: &str) -> PrivateTreasuryRiskSentinelResult<()> {
    if value.trim().is_empty() {
        Err(format!("{} must not be empty", field))
    } else {
        Ok(())
    }
}

fn require_positive(field: &str, value: u64) -> PrivateTreasuryRiskSentinelResult<()> {
    if value == 0 {
        Err(format!("{} must be positive", field))
    } else {
        Ok(())
    }
}

fn require_bps(field: &str, value: u64) -> PrivateTreasuryRiskSentinelResult<()> {
    if value > PRIVATE_TREASURY_RISK_SENTINEL_MAX_BPS {
        Err(format!("{} exceeds max bps", field))
    } else {
        Ok(())
    }
}

fn require_after(field: &str, later: u64, earlier: u64) -> PrivateTreasuryRiskSentinelResult<()> {
    if later <= earlier {
        Err(format!("{} must be greater than prior height", field))
    } else {
        Ok(())
    }
}

fn require_capacity(field: &str, len: usize, max: usize) -> PrivateTreasuryRiskSentinelResult<()> {
    if len > max {
        Err(format!("{} exceeds capacity", field))
    } else {
        Ok(())
    }
}

fn require_insert_capacity(
    field: &str,
    len: usize,
    replacing: bool,
    max: usize,
) -> PrivateTreasuryRiskSentinelResult<()> {
    if len >= max && !replacing {
        Err(format!("{} capacity reached", field))
    } else {
        Ok(())
    }
}

fn sentinel_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn payload_root(domain: &str, payload: &Value) -> String {
    sentinel_hash(domain, &[HashPart::Json(payload)])
}

fn collection_root<I>(domain: &str, roots: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let leaves = roots
        .into_iter()
        .map(|root| sentinel_hash("COLLECTION-LEAF", &[HashPart::Str(&root)]))
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn id_hash(domain: &str, label: &str, height: u64, nonce: u64) -> String {
    sentinel_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(height as i128),
            HashPart::Int(nonce as i128),
        ],
    )
}

fn event_root(event_kind: &str, subject_id: &str, height: u64) -> String {
    sentinel_hash(
        "EVENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Int(height as i128),
        ],
    )
}
