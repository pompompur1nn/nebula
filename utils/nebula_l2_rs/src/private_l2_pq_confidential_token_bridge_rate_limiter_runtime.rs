use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenBridgeRateLimiterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_BRIDGE_RATE_LIMITER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-token-bridge-rate-limiter-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_BRIDGE_RATE_LIMITER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const BUCKET_SUITE: &str = "shielded-confidential-token-bridge-bucket-root-v1";
pub const LANE_COMMITMENT_SUITE: &str = "Pedersen+RingCT-token-lane-commitment+nullifier-budget-v1";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-token-bridge-rate-attestation-v1";
pub const DYNAMIC_LIMIT_SUITE: &str =
    "deterministic-confidential-bridge-dynamic-rate-limit-root-v1";
pub const LOW_FEE_QUOTA_SUITE: &str = "low-fee-confidential-bridge-quota-credit-root-v1";
pub const ABUSE_QUARANTINE_SUITE: &str =
    "privacy-preserving-confidential-bridge-abuse-quarantine-root-v1";
pub const PRIVACY_REDACTION_SUITE: &str = "selective-disclosure-privacy-redaction-budget-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-confidential-token-bridge-rate-limiter-public-record-v1";
pub const DEVNET_RUNTIME_ID: &str = "private-l2-pq-confidential-token-bridge-rate-limiter-devnet";
pub const DEVNET_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-confidential-token-bridge-rate-limiter-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_028_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_642_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_WINDOW_BLOCKS: u64 = 60;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_BUCKET_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 360;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 8_640;
pub const DEFAULT_PRIVACY_REDACTION_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_BASE_LIMIT_UNITS: u64 = 50_000_000;
pub const DEFAULT_BURST_LIMIT_UNITS: u64 = 125_000_000;
pub const DEFAULT_LOW_FEE_LIMIT_SHARE_BPS: u64 = 1_250;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_ABUSE_SCORE_QUARANTINE_THRESHOLD: u64 = 700;
pub const DEFAULT_PRIVACY_BUDGET_PER_EPOCH: u64 = 32;
pub const DEFAULT_MIN_ATTESTATION_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_EMERGENCY_DRAIN_BPS: u64 = 2_500;
pub const DEFAULT_MAX_BUCKETS: usize = 262_144;
pub const DEFAULT_MAX_TOKEN_LANES: usize = 262_144;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_DYNAMIC_LIMITS: usize = 262_144;
pub const DEFAULT_MAX_LOW_FEE_CREDITS: usize = 524_288;
pub const DEFAULT_MAX_QUARANTINES: usize = 262_144;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 262_144;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Canary => "canary",
            Self::MainnetCandidate => "mainnet_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeDirection {
    MoneroToPrivateL2,
    PrivateL2ToMonero,
    PrivateL2ToExternal,
    ExternalToPrivateL2,
    Rebalance,
    EmergencyExit,
}

impl BridgeDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroToPrivateL2 => "monero_to_private_l2",
            Self::PrivateL2ToMonero => "private_l2_to_monero",
            Self::PrivateL2ToExternal => "private_l2_to_external",
            Self::ExternalToPrivateL2 => "external_to_private_l2",
            Self::Rebalance => "rebalance",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn is_exit(self) -> bool {
        matches!(
            self,
            Self::PrivateL2ToMonero | Self::PrivateL2ToExternal | Self::EmergencyExit
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Open,
    Throttled,
    Saturated,
    Draining,
    Paused,
    Quarantined,
    Retired,
}

impl BucketStatus {
    pub fn accepts_flow(self) -> bool {
        matches!(self, Self::Open | Self::Throttled | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Active,
    CoolingDown,
    LowFeeOnly,
    Suspended,
    Quarantined,
    Retired,
}

impl LaneStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::CoolingDown | Self::LowFeeOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Approved,
    RateLimited,
    PrivacyInsufficient,
    FeeOverCap,
    InvalidPqSignature,
    ReplayDetected,
    Quarantined,
}

impl AttestationVerdict {
    pub fn positive(self) -> bool {
        matches!(self, Self::Approved | Self::RateLimited)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitPolicyKind {
    FixedWindow,
    RollingWindow,
    VolatilityAdaptive,
    PrivacyAdaptive,
    LiquidityAdaptive,
    EmergencyDrain,
}

impl LimitPolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FixedWindow => "fixed_window",
            Self::RollingWindow => "rolling_window",
            Self::VolatilityAdaptive => "volatility_adaptive",
            Self::PrivacyAdaptive => "privacy_adaptive",
            Self::LiquidityAdaptive => "liquidity_adaptive",
            Self::EmergencyDrain => "emergency_drain",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditStatus {
    Minted,
    Reserved,
    Applied,
    Expired,
    Revoked,
}

impl CreditStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Minted | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    BucketSaturation,
    NullifierReplay,
    PqAttestationFailure,
    PrivacyBudgetExhausted,
    FeeEvasion,
    LaneCommitmentMismatch,
    VelocityAnomaly,
    EmergencyCircuitBreaker,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BucketSaturation => "bucket_saturation",
            Self::NullifierReplay => "nullifier_replay",
            Self::PqAttestationFailure => "pq_attestation_failure",
            Self::PrivacyBudgetExhausted => "privacy_budget_exhausted",
            Self::FeeEvasion => "fee_evasion",
            Self::LaneCommitmentMismatch => "lane_commitment_mismatch",
            Self::VelocityAnomaly => "velocity_anomaly",
            Self::EmergencyCircuitBreaker => "emergency_circuit_breaker",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    Amount,
    Asset,
    Counterparty,
    Route,
    Timing,
    AttestorSet,
    ComplianceDisclosure,
}

impl RedactionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Amount => "amount",
            Self::Asset => "asset",
            Self::Counterparty => "counterparty",
            Self::Route => "route",
            Self::Timing => "timing",
            Self::AttestorSet => "attestor_set",
            Self::ComplianceDisclosure => "compliance_disclosure",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub runtime_id: String,
    pub replay_domain: String,
    pub mode: RuntimeMode,
    pub l2_height: u64,
    pub monero_height: u64,
    pub fee_asset_id: String,
    pub window_blocks: u64,
    pub epoch_blocks: u64,
    pub bucket_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub privacy_redaction_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub base_limit_units: u64,
    pub burst_limit_units: u64,
    pub low_fee_limit_share_bps: u64,
    pub max_user_fee_bps: u64,
    pub abuse_score_quarantine_threshold: u64,
    pub privacy_budget_per_epoch: u64,
    pub min_attestation_quorum_bps: u64,
    pub emergency_drain_bps: u64,
    pub max_buckets: usize,
    pub max_token_lanes: usize,
    pub max_attestations: usize,
    pub max_dynamic_limits: usize,
    pub max_low_fee_credits: usize,
    pub max_quarantines: usize,
    pub max_redaction_budgets: usize,
    pub max_public_records: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            runtime_id: DEVNET_RUNTIME_ID.to_string(),
            replay_domain: DEVNET_REPLAY_DOMAIN.to_string(),
            mode: RuntimeMode::Devnet,
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            window_blocks: DEFAULT_WINDOW_BLOCKS,
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            bucket_ttl_blocks: DEFAULT_BUCKET_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            privacy_redaction_ttl_blocks: DEFAULT_PRIVACY_REDACTION_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            base_limit_units: DEFAULT_BASE_LIMIT_UNITS,
            burst_limit_units: DEFAULT_BURST_LIMIT_UNITS,
            low_fee_limit_share_bps: DEFAULT_LOW_FEE_LIMIT_SHARE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            abuse_score_quarantine_threshold: DEFAULT_ABUSE_SCORE_QUARANTINE_THRESHOLD,
            privacy_budget_per_epoch: DEFAULT_PRIVACY_BUDGET_PER_EPOCH,
            min_attestation_quorum_bps: DEFAULT_MIN_ATTESTATION_QUORUM_BPS,
            emergency_drain_bps: DEFAULT_EMERGENCY_DRAIN_BPS,
            max_buckets: DEFAULT_MAX_BUCKETS,
            max_token_lanes: DEFAULT_MAX_TOKEN_LANES,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_dynamic_limits: DEFAULT_MAX_DYNAMIC_LIMITS,
            max_low_fee_credits: DEFAULT_MAX_LOW_FEE_CREDITS,
            max_quarantines: DEFAULT_MAX_QUARANTINES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_eq("protocol_version", &self.protocol_version, PROTOCOL_VERSION)?;
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("runtime_id", &self.runtime_id)?;
        ensure_non_empty("replay_domain", &self.replay_domain)?;
        ensure_non_empty("fee_asset_id", &self.fee_asset_id)?;
        ensure_positive("window_blocks", self.window_blocks)?;
        ensure_positive("epoch_blocks", self.epoch_blocks)?;
        ensure_positive("bucket_ttl_blocks", self.bucket_ttl_blocks)?;
        ensure_positive("attestation_ttl_blocks", self.attestation_ttl_blocks)?;
        ensure_positive("quarantine_ttl_blocks", self.quarantine_ttl_blocks)?;
        ensure_positive(
            "privacy_redaction_ttl_blocks",
            self.privacy_redaction_ttl_blocks,
        )?;
        ensure_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_at_least(
            "target_privacy_set_size",
            self.target_privacy_set_size,
            self.min_privacy_set_size,
        )?;
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err(format!(
                "min_pq_security_bits must be at least {}",
                DEFAULT_MIN_PQ_SECURITY_BITS
            ));
        }
        ensure_positive("base_limit_units", self.base_limit_units)?;
        ensure_at_least(
            "burst_limit_units",
            self.burst_limit_units,
            self.base_limit_units,
        )?;
        ensure_bps("low_fee_limit_share_bps", self.low_fee_limit_share_bps)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps(
            "min_attestation_quorum_bps",
            self.min_attestation_quorum_bps,
        )?;
        ensure_bps("emergency_drain_bps", self.emergency_drain_bps)?;
        ensure_usize_positive("max_buckets", self.max_buckets)?;
        ensure_usize_positive("max_token_lanes", self.max_token_lanes)?;
        ensure_usize_positive("max_attestations", self.max_attestations)?;
        ensure_usize_positive("max_dynamic_limits", self.max_dynamic_limits)?;
        ensure_usize_positive("max_low_fee_credits", self.max_low_fee_credits)?;
        ensure_usize_positive("max_quarantines", self.max_quarantines)?;
        ensure_usize_positive("max_redaction_budgets", self.max_redaction_budgets)?;
        ensure_usize_positive("max_public_records", self.max_public_records)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "runtime_id": self.runtime_id,
            "replay_domain": self.replay_domain,
            "mode": self.mode.as_str(),
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "fee_asset_id": self.fee_asset_id,
            "window_blocks": self.window_blocks,
            "epoch_blocks": self.epoch_blocks,
            "bucket_ttl_blocks": self.bucket_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "privacy_redaction_ttl_blocks": self.privacy_redaction_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "base_limit_units": self.base_limit_units,
            "burst_limit_units": self.burst_limit_units,
            "low_fee_limit_share_bps": self.low_fee_limit_share_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "abuse_score_quarantine_threshold": self.abuse_score_quarantine_threshold,
            "privacy_budget_per_epoch": self.privacy_budget_per_epoch,
            "min_attestation_quorum_bps": self.min_attestation_quorum_bps,
            "emergency_drain_bps": self.emergency_drain_bps,
            "max_buckets": self.max_buckets,
            "max_token_lanes": self.max_token_lanes,
            "max_attestations": self.max_attestations,
            "max_dynamic_limits": self.max_dynamic_limits,
            "max_low_fee_credits": self.max_low_fee_credits,
            "max_quarantines": self.max_quarantines,
            "max_redaction_budgets": self.max_redaction_budgets,
            "max_public_records": self.max_public_records
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub buckets: u64,
    pub token_lanes: u64,
    pub attestations: u64,
    pub dynamic_limits: u64,
    pub low_fee_credits: u64,
    pub quarantines: u64,
    pub redaction_budgets: u64,
    pub public_records: u64,
    pub admitted_units: u64,
    pub throttled_units: u64,
    pub quarantined_units: u64,
    pub redacted_disclosures: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "buckets": self.buckets,
            "token_lanes": self.token_lanes,
            "attestations": self.attestations,
            "dynamic_limits": self.dynamic_limits,
            "low_fee_credits": self.low_fee_credits,
            "quarantines": self.quarantines,
            "redaction_budgets": self.redaction_budgets,
            "public_records": self.public_records,
            "admitted_units": self.admitted_units,
            "throttled_units": self.throttled_units,
            "quarantined_units": self.quarantined_units,
            "redacted_disclosures": self.redacted_disclosures
        })
    }

    pub fn state_root(&self) -> String {
        record_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub bucket_root: String,
    pub token_lane_root: String,
    pub pq_attestation_root: String,
    pub dynamic_limit_root: String,
    pub low_fee_credit_root: String,
    pub abuse_quarantine_root: String,
    pub privacy_redaction_root: String,
    pub public_record_root: String,
    pub counters_root: String,
    pub replay_filter_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            config_root: empty_root("config"),
            bucket_root: empty_root("buckets"),
            token_lane_root: empty_root("token_lanes"),
            pq_attestation_root: empty_root("pq_attestations"),
            dynamic_limit_root: empty_root("dynamic_limits"),
            low_fee_credit_root: empty_root("low_fee_credits"),
            abuse_quarantine_root: empty_root("abuse_quarantines"),
            privacy_redaction_root: empty_root("privacy_redaction_budgets"),
            public_record_root: empty_root("public_records"),
            counters_root: empty_root("counters"),
            replay_filter_root: empty_root("replay_filter"),
            state_root: empty_root("state"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "bucket_root": self.bucket_root,
            "token_lane_root": self.token_lane_root,
            "pq_attestation_root": self.pq_attestation_root,
            "dynamic_limit_root": self.dynamic_limit_root,
            "low_fee_credit_root": self.low_fee_credit_root,
            "abuse_quarantine_root": self.abuse_quarantine_root,
            "privacy_redaction_root": self.privacy_redaction_root,
            "public_record_root": self.public_record_root,
            "counters_root": self.counters_root,
            "replay_filter_root": self.replay_filter_root,
            "state_root": self.state_root
        })
    }

    pub fn root(&self) -> String {
        record_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShieldedBridgeBucket {
    pub bucket_id: String,
    pub asset_id: String,
    pub direction: BridgeDirection,
    pub epoch: u64,
    pub window_start_block: u64,
    pub window_end_block: u64,
    pub shielded_capacity_commitment: String,
    pub consumed_units_commitment: String,
    pub remaining_units_commitment: String,
    pub privacy_set_size: u64,
    pub low_fee_reserved_units: u64,
    pub abuse_score: u64,
    pub status: BucketStatus,
    pub last_limit_root: String,
}

impl ShieldedBridgeBucket {
    pub fn new(
        bucket_id: impl Into<String>,
        asset_id: impl Into<String>,
        direction: BridgeDirection,
        epoch: u64,
        window_start_block: u64,
        capacity_units: u64,
        config: &Config,
    ) -> Self {
        let bucket_id = bucket_id.into();
        let asset_id = asset_id.into();
        let window_end_block = window_start_block + config.window_blocks.saturating_sub(1);
        let low_fee_reserved_units =
            capacity_units.saturating_mul(config.low_fee_limit_share_bps) / MAX_BPS;
        let capacity_commitment = commitment(
            "bucket-capacity",
            &[&bucket_id, &asset_id, direction.as_str()],
            capacity_units,
        );
        let consumed_commitment = commitment(
            "bucket-consumed",
            &[&bucket_id, &asset_id, direction.as_str()],
            0,
        );
        let remaining_commitment = commitment(
            "bucket-remaining",
            &[&bucket_id, &asset_id, direction.as_str()],
            capacity_units,
        );
        Self {
            bucket_id,
            asset_id,
            direction,
            epoch,
            window_start_block,
            window_end_block,
            shielded_capacity_commitment: capacity_commitment,
            consumed_units_commitment: consumed_commitment,
            remaining_units_commitment: remaining_commitment,
            privacy_set_size: config.target_privacy_set_size,
            low_fee_reserved_units,
            abuse_score: 0,
            status: BucketStatus::Open,
            last_limit_root: empty_root("dynamic_limit"),
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("bucket_id", &self.bucket_id)?;
        ensure_non_empty("asset_id", &self.asset_id)?;
        ensure_non_empty(
            "shielded_capacity_commitment",
            &self.shielded_capacity_commitment,
        )?;
        ensure_non_empty("consumed_units_commitment", &self.consumed_units_commitment)?;
        ensure_non_empty(
            "remaining_units_commitment",
            &self.remaining_units_commitment,
        )?;
        ensure_at_least(
            "privacy_set_size",
            self.privacy_set_size,
            config.min_privacy_set_size,
        )?;
        if self.window_end_block < self.window_start_block {
            return Err("window_end_block must be >= window_start_block".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "asset_id": self.asset_id,
            "direction": self.direction.as_str(),
            "epoch": self.epoch,
            "window_start_block": self.window_start_block,
            "window_end_block": self.window_end_block,
            "shielded_capacity_commitment": self.shielded_capacity_commitment,
            "consumed_units_commitment": self.consumed_units_commitment,
            "remaining_units_commitment": self.remaining_units_commitment,
            "privacy_set_size": self.privacy_set_size,
            "low_fee_reserved_units": self.low_fee_reserved_units,
            "abuse_score": self.abuse_score,
            "status": format!("{:?}", self.status).to_ascii_lowercase(),
            "last_limit_root": self.last_limit_root
        })
    }

    pub fn root(&self) -> String {
        record_root("SHIELDED-BRIDGE-BUCKET", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenLaneCommitment {
    pub lane_id: String,
    pub bucket_id: String,
    pub token_class_id: String,
    pub lane_commitment: String,
    pub lane_nullifier_root: String,
    pub bridge_note_root: String,
    pub pending_units_commitment: String,
    pub admitted_units_commitment: String,
    pub max_fee_bps: u64,
    pub status: LaneStatus,
    pub priority: u64,
}

impl TokenLaneCommitment {
    pub fn new(
        lane_id: impl Into<String>,
        bucket_id: impl Into<String>,
        token_class_id: impl Into<String>,
        max_fee_bps: u64,
        priority: u64,
    ) -> Self {
        let lane_id = lane_id.into();
        let bucket_id = bucket_id.into();
        let token_class_id = token_class_id.into();
        let lane_commitment = commitment("token-lane", &[&lane_id, &bucket_id, &token_class_id], 0);
        Self {
            lane_id: lane_id.clone(),
            bucket_id,
            token_class_id,
            lane_commitment,
            lane_nullifier_root: empty_root(&format!("lane-nullifiers-{lane_id}")),
            bridge_note_root: empty_root(&format!("bridge-notes-{lane_id}")),
            pending_units_commitment: commitment("lane-pending", &[&lane_id], 0),
            admitted_units_commitment: commitment("lane-admitted", &[&lane_id], 0),
            max_fee_bps,
            status: LaneStatus::Active,
            priority,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("lane_id", &self.lane_id)?;
        ensure_non_empty("bucket_id", &self.bucket_id)?;
        ensure_non_empty("token_class_id", &self.token_class_id)?;
        ensure_non_empty("lane_commitment", &self.lane_commitment)?;
        ensure_non_empty("lane_nullifier_root", &self.lane_nullifier_root)?;
        ensure_non_empty("bridge_note_root", &self.bridge_note_root)?;
        ensure_bps("max_fee_bps", self.max_fee_bps)?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("max_fee_bps exceeds runtime user fee cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "bucket_id": self.bucket_id,
            "token_class_id": self.token_class_id,
            "lane_commitment": self.lane_commitment,
            "lane_nullifier_root": self.lane_nullifier_root,
            "bridge_note_root": self.bridge_note_root,
            "pending_units_commitment": self.pending_units_commitment,
            "admitted_units_commitment": self.admitted_units_commitment,
            "max_fee_bps": self.max_fee_bps,
            "status": lane_status_str(self.status),
            "priority": self.priority
        })
    }

    pub fn root(&self) -> String {
        record_root("TOKEN-LANE-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqBridgeAttestation {
    pub attestation_id: String,
    pub bucket_id: String,
    pub lane_id: String,
    pub attestor_set_id: String,
    pub pq_signature_root: String,
    pub attested_limit_root: String,
    pub attested_nullifier_root: String,
    pub privacy_set_size: u64,
    pub quorum_weight_bps: u64,
    pub pq_security_bits: u16,
    pub issued_at_block: u64,
    pub expires_at_block: u64,
    pub verdict: AttestationVerdict,
}

impl PqBridgeAttestation {
    pub fn new(
        attestation_id: impl Into<String>,
        bucket_id: impl Into<String>,
        lane_id: impl Into<String>,
        attestor_set_id: impl Into<String>,
        issued_at_block: u64,
        config: &Config,
    ) -> Self {
        let attestation_id = attestation_id.into();
        let bucket_id = bucket_id.into();
        let lane_id = lane_id.into();
        let attestor_set_id = attestor_set_id.into();
        Self {
            pq_signature_root: domain_hash(
                "PQ-BRIDGE-ATTESTATION-SIGNATURE",
                &[
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(&attestation_id),
                    HashPart::Str(&bucket_id),
                    HashPart::Str(&lane_id),
                    HashPart::Str(&attestor_set_id),
                ],
                32,
            ),
            attested_limit_root: empty_root("attested-limit"),
            attested_nullifier_root: empty_root("attested-nullifiers"),
            privacy_set_size: config.target_privacy_set_size,
            quorum_weight_bps: config.min_attestation_quorum_bps,
            pq_security_bits: config.min_pq_security_bits,
            expires_at_block: issued_at_block + config.attestation_ttl_blocks,
            issued_at_block,
            attestation_id,
            bucket_id,
            lane_id,
            attestor_set_id,
            verdict: AttestationVerdict::Approved,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("attestation_id", &self.attestation_id)?;
        ensure_non_empty("bucket_id", &self.bucket_id)?;
        ensure_non_empty("lane_id", &self.lane_id)?;
        ensure_non_empty("attestor_set_id", &self.attestor_set_id)?;
        ensure_non_empty("pq_signature_root", &self.pq_signature_root)?;
        ensure_bps("quorum_weight_bps", self.quorum_weight_bps)?;
        ensure_at_least(
            "quorum_weight_bps",
            self.quorum_weight_bps,
            config.min_attestation_quorum_bps,
        )?;
        ensure_at_least(
            "privacy_set_size",
            self.privacy_set_size,
            config.min_privacy_set_size,
        )?;
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("pq_security_bits below runtime minimum".to_string());
        }
        if self.expires_at_block <= self.issued_at_block {
            return Err("expires_at_block must be greater than issued_at_block".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "bucket_id": self.bucket_id,
            "lane_id": self.lane_id,
            "attestor_set_id": self.attestor_set_id,
            "pq_signature_root": self.pq_signature_root,
            "attested_limit_root": self.attested_limit_root,
            "attested_nullifier_root": self.attested_nullifier_root,
            "privacy_set_size": self.privacy_set_size,
            "quorum_weight_bps": self.quorum_weight_bps,
            "pq_security_bits": self.pq_security_bits,
            "issued_at_block": self.issued_at_block,
            "expires_at_block": self.expires_at_block,
            "verdict": attestation_verdict_str(self.verdict)
        })
    }

    pub fn root(&self) -> String {
        record_root("PQ-BRIDGE-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DynamicRateLimit {
    pub limit_id: String,
    pub bucket_id: String,
    pub policy: LimitPolicyKind,
    pub base_limit_units: u64,
    pub burst_limit_units: u64,
    pub effective_limit_units: u64,
    pub replenishment_units_per_block: u64,
    pub congestion_bps: u64,
    pub liquidity_headroom_bps: u64,
    pub privacy_pressure_bps: u64,
    pub low_fee_share_bps: u64,
    pub effective_from_block: u64,
    pub effective_until_block: u64,
}

impl DynamicRateLimit {
    pub fn new(
        limit_id: impl Into<String>,
        bucket_id: impl Into<String>,
        policy: LimitPolicyKind,
        effective_from_block: u64,
        config: &Config,
    ) -> Self {
        let base_limit_units = config.base_limit_units;
        let burst_limit_units = config.burst_limit_units;
        let effective_limit_units = match policy {
            LimitPolicyKind::EmergencyDrain => {
                burst_limit_units.saturating_mul(config.emergency_drain_bps) / MAX_BPS
            }
            LimitPolicyKind::PrivacyAdaptive => base_limit_units.saturating_mul(8_750) / MAX_BPS,
            LimitPolicyKind::LiquidityAdaptive => burst_limit_units.saturating_mul(9_250) / MAX_BPS,
            _ => base_limit_units,
        };
        Self {
            limit_id: limit_id.into(),
            bucket_id: bucket_id.into(),
            policy,
            base_limit_units,
            burst_limit_units,
            effective_limit_units,
            replenishment_units_per_block: base_limit_units / config.window_blocks.max(1),
            congestion_bps: 0,
            liquidity_headroom_bps: 1_250,
            privacy_pressure_bps: 0,
            low_fee_share_bps: config.low_fee_limit_share_bps,
            effective_from_block,
            effective_until_block: effective_from_block + config.window_blocks,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("limit_id", &self.limit_id)?;
        ensure_non_empty("bucket_id", &self.bucket_id)?;
        ensure_positive("base_limit_units", self.base_limit_units)?;
        ensure_at_least(
            "burst_limit_units",
            self.burst_limit_units,
            self.base_limit_units,
        )?;
        ensure_bps("congestion_bps", self.congestion_bps)?;
        ensure_bps("liquidity_headroom_bps", self.liquidity_headroom_bps)?;
        ensure_bps("privacy_pressure_bps", self.privacy_pressure_bps)?;
        ensure_bps("low_fee_share_bps", self.low_fee_share_bps)?;
        if self.effective_until_block <= self.effective_from_block {
            return Err(
                "effective_until_block must be greater than effective_from_block".to_string(),
            );
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "limit_id": self.limit_id,
            "bucket_id": self.bucket_id,
            "policy": self.policy.as_str(),
            "base_limit_units": self.base_limit_units,
            "burst_limit_units": self.burst_limit_units,
            "effective_limit_units": self.effective_limit_units,
            "replenishment_units_per_block": self.replenishment_units_per_block,
            "congestion_bps": self.congestion_bps,
            "liquidity_headroom_bps": self.liquidity_headroom_bps,
            "privacy_pressure_bps": self.privacy_pressure_bps,
            "low_fee_share_bps": self.low_fee_share_bps,
            "effective_from_block": self.effective_from_block,
            "effective_until_block": self.effective_until_block
        })
    }

    pub fn root(&self) -> String {
        record_root("DYNAMIC-RATE-LIMIT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeQuotaCredit {
    pub credit_id: String,
    pub bucket_id: String,
    pub lane_id: String,
    pub account_commitment: String,
    pub quota_units: u64,
    pub fee_discount_bps: u64,
    pub minted_at_block: u64,
    pub expires_at_block: u64,
    pub status: CreditStatus,
}

impl LowFeeQuotaCredit {
    pub fn new(
        credit_id: impl Into<String>,
        bucket_id: impl Into<String>,
        lane_id: impl Into<String>,
        quota_units: u64,
        minted_at_block: u64,
        config: &Config,
    ) -> Self {
        let credit_id = credit_id.into();
        let bucket_id = bucket_id.into();
        let lane_id = lane_id.into();
        Self {
            account_commitment: commitment("quota-account", &[&credit_id, &bucket_id, &lane_id], 0),
            credit_id,
            bucket_id,
            lane_id,
            quota_units,
            fee_discount_bps: config.low_fee_limit_share_bps,
            minted_at_block,
            expires_at_block: minted_at_block + config.bucket_ttl_blocks,
            status: CreditStatus::Minted,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("credit_id", &self.credit_id)?;
        ensure_non_empty("bucket_id", &self.bucket_id)?;
        ensure_non_empty("lane_id", &self.lane_id)?;
        ensure_non_empty("account_commitment", &self.account_commitment)?;
        ensure_positive("quota_units", self.quota_units)?;
        ensure_bps("fee_discount_bps", self.fee_discount_bps)?;
        if self.expires_at_block <= self.minted_at_block {
            return Err("expires_at_block must be greater than minted_at_block".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "bucket_id": self.bucket_id,
            "lane_id": self.lane_id,
            "account_commitment": self.account_commitment,
            "quota_units": self.quota_units,
            "fee_discount_bps": self.fee_discount_bps,
            "minted_at_block": self.minted_at_block,
            "expires_at_block": self.expires_at_block,
            "status": credit_status_str(self.status)
        })
    }

    pub fn root(&self) -> String {
        record_root("LOW-FEE-QUOTA-CREDIT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbuseQuarantine {
    pub quarantine_id: String,
    pub subject_commitment: String,
    pub bucket_id: String,
    pub lane_id: String,
    pub reason: QuarantineReason,
    pub abuse_score: u64,
    pub evidence_root: String,
    pub redacted_evidence_root: String,
    pub opened_at_block: u64,
    pub releases_at_block: u64,
    pub active: bool,
}

impl AbuseQuarantine {
    pub fn new(
        quarantine_id: impl Into<String>,
        bucket_id: impl Into<String>,
        lane_id: impl Into<String>,
        reason: QuarantineReason,
        abuse_score: u64,
        opened_at_block: u64,
        config: &Config,
    ) -> Self {
        let quarantine_id = quarantine_id.into();
        let bucket_id = bucket_id.into();
        let lane_id = lane_id.into();
        Self {
            subject_commitment: commitment(
                "quarantine-subject",
                &[&quarantine_id, &bucket_id, &lane_id],
                abuse_score,
            ),
            evidence_root: empty_root("abuse-evidence"),
            redacted_evidence_root: empty_root("redacted-abuse-evidence"),
            quarantine_id,
            bucket_id,
            lane_id,
            reason,
            abuse_score,
            opened_at_block,
            releases_at_block: opened_at_block + config.quarantine_ttl_blocks,
            active: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("quarantine_id", &self.quarantine_id)?;
        ensure_non_empty("subject_commitment", &self.subject_commitment)?;
        ensure_non_empty("bucket_id", &self.bucket_id)?;
        ensure_non_empty("lane_id", &self.lane_id)?;
        ensure_non_empty("evidence_root", &self.evidence_root)?;
        ensure_non_empty("redacted_evidence_root", &self.redacted_evidence_root)?;
        if self.releases_at_block <= self.opened_at_block {
            return Err("releases_at_block must be greater than opened_at_block".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "subject_commitment": self.subject_commitment,
            "bucket_id": self.bucket_id,
            "lane_id": self.lane_id,
            "reason": self.reason.as_str(),
            "abuse_score": self.abuse_score,
            "evidence_root": self.evidence_root,
            "redacted_evidence_root": self.redacted_evidence_root,
            "opened_at_block": self.opened_at_block,
            "releases_at_block": self.releases_at_block,
            "active": self.active
        })
    }

    pub fn root(&self) -> String {
        record_root("ABUSE-QUARANTINE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub bucket_id: String,
    pub scope: RedactionScope,
    pub epoch: u64,
    pub budget_units: u64,
    pub spent_units: u64,
    pub remaining_units: u64,
    pub disclosure_policy_root: String,
    pub auditor_committee_root: String,
    pub expires_at_block: u64,
}

impl PrivacyRedactionBudget {
    pub fn new(
        budget_id: impl Into<String>,
        bucket_id: impl Into<String>,
        scope: RedactionScope,
        epoch: u64,
        created_at_block: u64,
        config: &Config,
    ) -> Self {
        let budget_id = budget_id.into();
        let bucket_id = bucket_id.into();
        Self {
            disclosure_policy_root: domain_hash(
                "PRIVACY-REDACTION-POLICY",
                &[
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(&budget_id),
                    HashPart::Str(&bucket_id),
                    HashPart::Str(scope.as_str()),
                ],
                32,
            ),
            auditor_committee_root: empty_root("auditor-committee"),
            budget_id,
            bucket_id,
            scope,
            epoch,
            budget_units: config.privacy_budget_per_epoch,
            spent_units: 0,
            remaining_units: config.privacy_budget_per_epoch,
            expires_at_block: created_at_block + config.privacy_redaction_ttl_blocks,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("budget_id", &self.budget_id)?;
        ensure_non_empty("bucket_id", &self.bucket_id)?;
        ensure_non_empty("disclosure_policy_root", &self.disclosure_policy_root)?;
        ensure_non_empty("auditor_committee_root", &self.auditor_committee_root)?;
        if self.spent_units + self.remaining_units != self.budget_units {
            return Err("redaction budget accounting must balance".to_string());
        }
        ensure_positive("expires_at_block", self.expires_at_block)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "bucket_id": self.bucket_id,
            "scope": self.scope.as_str(),
            "epoch": self.epoch,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units,
            "disclosure_policy_root": self.disclosure_policy_root,
            "auditor_committee_root": self.auditor_committee_root,
            "expires_at_block": self.expires_at_block
        })
    }

    pub fn root(&self) -> String {
        record_root("PRIVACY-REDACTION-BUDGET", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub buckets: BTreeMap<String, ShieldedBridgeBucket>,
    pub token_lanes: BTreeMap<String, TokenLaneCommitment>,
    pub pq_attestations: BTreeMap<String, PqBridgeAttestation>,
    pub dynamic_limits: BTreeMap<String, DynamicRateLimit>,
    pub low_fee_credits: BTreeMap<String, LowFeeQuotaCredit>,
    pub abuse_quarantines: BTreeMap<String, AbuseQuarantine>,
    pub privacy_redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub replay_filter: BTreeSet<String>,
    pub public_records: Vec<Value>,
}

impl State {
    pub fn empty(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            buckets: BTreeMap::new(),
            token_lanes: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            dynamic_limits: BTreeMap::new(),
            low_fee_credits: BTreeMap::new(),
            abuse_quarantines: BTreeMap::new(),
            privacy_redaction_budgets: BTreeMap::new(),
            replay_filter: BTreeSet::new(),
            public_records: Vec::new(),
        }
        .refreshed()
    }

    pub fn devnet() -> Self {
        Self::empty(Config::devnet())
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure_len("buckets", self.buckets.len(), self.config.max_buckets)?;
        ensure_len(
            "token_lanes",
            self.token_lanes.len(),
            self.config.max_token_lanes,
        )?;
        ensure_len(
            "pq_attestations",
            self.pq_attestations.len(),
            self.config.max_attestations,
        )?;
        ensure_len(
            "dynamic_limits",
            self.dynamic_limits.len(),
            self.config.max_dynamic_limits,
        )?;
        ensure_len(
            "low_fee_credits",
            self.low_fee_credits.len(),
            self.config.max_low_fee_credits,
        )?;
        ensure_len(
            "abuse_quarantines",
            self.abuse_quarantines.len(),
            self.config.max_quarantines,
        )?;
        ensure_len(
            "privacy_redaction_budgets",
            self.privacy_redaction_budgets.len(),
            self.config.max_redaction_budgets,
        )?;
        ensure_len(
            "public_records",
            self.public_records.len(),
            self.config.max_public_records,
        )?;
        for (id, bucket) in &self.buckets {
            ensure_eq("bucket map key", id, &bucket.bucket_id)?;
            bucket.validate(&self.config)?;
        }
        for (id, lane) in &self.token_lanes {
            ensure_eq("token lane map key", id, &lane.lane_id)?;
            if !self.buckets.contains_key(&lane.bucket_id) {
                return Err(format!("lane {} references missing bucket", lane.lane_id));
            }
            lane.validate(&self.config)?;
        }
        for (id, attestation) in &self.pq_attestations {
            ensure_eq("attestation map key", id, &attestation.attestation_id)?;
            if !self.buckets.contains_key(&attestation.bucket_id) {
                return Err(format!(
                    "attestation {} references missing bucket",
                    attestation.attestation_id
                ));
            }
            if !self.token_lanes.contains_key(&attestation.lane_id) {
                return Err(format!(
                    "attestation {} references missing lane",
                    attestation.attestation_id
                ));
            }
            attestation.validate(&self.config)?;
        }
        for (id, limit) in &self.dynamic_limits {
            ensure_eq("dynamic limit map key", id, &limit.limit_id)?;
            if !self.buckets.contains_key(&limit.bucket_id) {
                return Err(format!(
                    "limit {} references missing bucket",
                    limit.limit_id
                ));
            }
            limit.validate()?;
        }
        for (id, credit) in &self.low_fee_credits {
            ensure_eq("low fee credit map key", id, &credit.credit_id)?;
            if !self.buckets.contains_key(&credit.bucket_id) {
                return Err(format!(
                    "credit {} references missing bucket",
                    credit.credit_id
                ));
            }
            if !self.token_lanes.contains_key(&credit.lane_id) {
                return Err(format!(
                    "credit {} references missing lane",
                    credit.credit_id
                ));
            }
            credit.validate()?;
        }
        for (id, quarantine) in &self.abuse_quarantines {
            ensure_eq("quarantine map key", id, &quarantine.quarantine_id)?;
            quarantine.validate()?;
        }
        for (id, budget) in &self.privacy_redaction_budgets {
            ensure_eq("redaction budget map key", id, &budget.budget_id)?;
            budget.validate()?;
        }
        Ok(())
    }

    pub fn upsert_bucket(&mut self, bucket: ShieldedBridgeBucket) -> Result<String> {
        bucket.validate(&self.config)?;
        if !self
            .replay_filter
            .insert(replay_key("bucket", &bucket.bucket_id))
        {
            return Err(format!("bucket replay detected: {}", bucket.bucket_id));
        }
        let id = bucket.bucket_id.clone();
        self.append_public_record(bucket.public_record());
        self.buckets.insert(id, bucket);
        self.refresh();
        Ok(self.state_root())
    }

    pub fn upsert_token_lane(&mut self, lane: TokenLaneCommitment) -> Result<String> {
        lane.validate(&self.config)?;
        if !self.buckets.contains_key(&lane.bucket_id) {
            return Err(format!("lane {} references missing bucket", lane.lane_id));
        }
        if !self.replay_filter.insert(replay_key("lane", &lane.lane_id)) {
            return Err(format!("lane replay detected: {}", lane.lane_id));
        }
        let id = lane.lane_id.clone();
        self.append_public_record(lane.public_record());
        self.token_lanes.insert(id, lane);
        self.refresh();
        Ok(self.state_root())
    }

    pub fn attest_bridge(&mut self, attestation: PqBridgeAttestation) -> Result<String> {
        attestation.validate(&self.config)?;
        if !self.buckets.contains_key(&attestation.bucket_id) {
            return Err("attestation bucket missing".to_string());
        }
        if !self.token_lanes.contains_key(&attestation.lane_id) {
            return Err("attestation lane missing".to_string());
        }
        if !self
            .replay_filter
            .insert(replay_key("attestation", &attestation.attestation_id))
        {
            return Err(format!(
                "attestation replay detected: {}",
                attestation.attestation_id
            ));
        }
        let id = attestation.attestation_id.clone();
        self.append_public_record(attestation.public_record());
        self.pq_attestations.insert(id, attestation);
        self.refresh();
        Ok(self.state_root())
    }

    pub fn install_dynamic_limit(&mut self, limit: DynamicRateLimit) -> Result<String> {
        limit.validate()?;
        if !self.buckets.contains_key(&limit.bucket_id) {
            return Err("dynamic limit bucket missing".to_string());
        }
        if !self
            .replay_filter
            .insert(replay_key("dynamic-limit", &limit.limit_id))
        {
            return Err(format!("dynamic limit replay detected: {}", limit.limit_id));
        }
        let id = limit.limit_id.clone();
        if let Some(bucket) = self.buckets.get_mut(&limit.bucket_id) {
            bucket.last_limit_root = limit.root();
            if limit.congestion_bps >= 8_500 {
                bucket.status = BucketStatus::Throttled;
            }
        }
        self.append_public_record(limit.public_record());
        self.dynamic_limits.insert(id, limit);
        self.refresh();
        Ok(self.state_root())
    }

    pub fn mint_low_fee_credit(&mut self, credit: LowFeeQuotaCredit) -> Result<String> {
        credit.validate()?;
        if !self.buckets.contains_key(&credit.bucket_id) {
            return Err("low fee credit bucket missing".to_string());
        }
        if !self.token_lanes.contains_key(&credit.lane_id) {
            return Err("low fee credit lane missing".to_string());
        }
        if !self
            .replay_filter
            .insert(replay_key("low-fee-credit", &credit.credit_id))
        {
            return Err(format!(
                "low fee credit replay detected: {}",
                credit.credit_id
            ));
        }
        let id = credit.credit_id.clone();
        self.append_public_record(credit.public_record());
        self.low_fee_credits.insert(id, credit);
        self.refresh();
        Ok(self.state_root())
    }

    pub fn quarantine_abuse(&mut self, quarantine: AbuseQuarantine) -> Result<String> {
        quarantine.validate()?;
        if !self
            .replay_filter
            .insert(replay_key("quarantine", &quarantine.quarantine_id))
        {
            return Err(format!(
                "quarantine replay detected: {}",
                quarantine.quarantine_id
            ));
        }
        if let Some(bucket) = self.buckets.get_mut(&quarantine.bucket_id) {
            bucket.abuse_score = bucket.abuse_score.max(quarantine.abuse_score);
            if bucket.abuse_score >= self.config.abuse_score_quarantine_threshold {
                bucket.status = BucketStatus::Quarantined;
            }
        }
        if let Some(lane) = self.token_lanes.get_mut(&quarantine.lane_id) {
            lane.status = LaneStatus::Quarantined;
        }
        let id = quarantine.quarantine_id.clone();
        self.append_public_record(quarantine.public_record());
        self.abuse_quarantines.insert(id, quarantine);
        self.refresh();
        Ok(self.state_root())
    }

    pub fn allocate_redaction_budget(&mut self, budget: PrivacyRedactionBudget) -> Result<String> {
        budget.validate()?;
        if !self.buckets.contains_key(&budget.bucket_id) {
            return Err("redaction budget bucket missing".to_string());
        }
        if !self
            .replay_filter
            .insert(replay_key("redaction-budget", &budget.budget_id))
        {
            return Err(format!(
                "redaction budget replay detected: {}",
                budget.budget_id
            ));
        }
        let id = budget.budget_id.clone();
        self.append_public_record(budget.public_record());
        self.privacy_redaction_budgets.insert(id, budget);
        self.refresh();
        Ok(self.state_root())
    }

    pub fn admit_units(
        &mut self,
        bucket_id: &str,
        lane_id: &str,
        unit_commitment: &str,
        units: u64,
        low_fee_credit_id: Option<&str>,
    ) -> Result<String> {
        ensure_positive("units", units)?;
        ensure_non_empty("unit_commitment", unit_commitment)?;
        let bucket = self
            .buckets
            .get_mut(bucket_id)
            .ok_or_else(|| format!("missing bucket {bucket_id}"))?;
        if !bucket.status.accepts_flow() {
            return Err(format!("bucket {bucket_id} does not accept flow"));
        }
        let lane = self
            .token_lanes
            .get_mut(lane_id)
            .ok_or_else(|| format!("missing lane {lane_id}"))?;
        if lane.bucket_id != bucket_id {
            return Err("lane bucket mismatch".to_string());
        }
        if !lane.status.usable() {
            return Err(format!("lane {lane_id} is not usable"));
        }
        if let Some(credit_id) = low_fee_credit_id {
            let credit = self
                .low_fee_credits
                .get_mut(credit_id)
                .ok_or_else(|| format!("missing low fee credit {credit_id}"))?;
            if !credit.status.live() || credit.quota_units < units {
                return Err(format!("low fee credit {credit_id} cannot cover units"));
            }
            credit.quota_units -= units;
            credit.status = if credit.quota_units == 0 {
                CreditStatus::Applied
            } else {
                CreditStatus::Reserved
            };
        }
        bucket.consumed_units_commitment = commitment(
            "bucket-consumed",
            &[bucket_id, lane_id, unit_commitment],
            units,
        );
        bucket.remaining_units_commitment = commitment(
            "bucket-remaining",
            &[bucket_id, lane_id, unit_commitment],
            units,
        );
        lane.admitted_units_commitment = commitment(
            "lane-admitted",
            &[bucket_id, lane_id, unit_commitment],
            units,
        );
        self.counters.admitted_units = self.counters.admitted_units.saturating_add(units);
        self.append_public_record(json!({
            "record_type": "admitted_units",
            "bucket_id": bucket_id,
            "lane_id": lane_id,
            "unit_commitment": unit_commitment,
            "units_commitment": commitment("admitted-units", &[bucket_id, lane_id, unit_commitment], units)
        }));
        self.refresh();
        Ok(self.state_root())
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots::empty();
        roots.config_root = self.config.state_root();
        roots.bucket_root = merkle_root(
            BUCKET_SUITE,
            &sorted_records(
                self.buckets
                    .values()
                    .map(ShieldedBridgeBucket::public_record),
            ),
        );
        roots.token_lane_root = merkle_root(
            LANE_COMMITMENT_SUITE,
            &sorted_records(
                self.token_lanes
                    .values()
                    .map(TokenLaneCommitment::public_record),
            ),
        );
        roots.pq_attestation_root = merkle_root(
            PQ_ATTESTATION_SUITE,
            &sorted_records(
                self.pq_attestations
                    .values()
                    .map(PqBridgeAttestation::public_record),
            ),
        );
        roots.dynamic_limit_root = merkle_root(
            DYNAMIC_LIMIT_SUITE,
            &sorted_records(
                self.dynamic_limits
                    .values()
                    .map(DynamicRateLimit::public_record),
            ),
        );
        roots.low_fee_credit_root = merkle_root(
            LOW_FEE_QUOTA_SUITE,
            &sorted_records(
                self.low_fee_credits
                    .values()
                    .map(LowFeeQuotaCredit::public_record),
            ),
        );
        roots.abuse_quarantine_root = merkle_root(
            ABUSE_QUARANTINE_SUITE,
            &sorted_records(
                self.abuse_quarantines
                    .values()
                    .map(AbuseQuarantine::public_record),
            ),
        );
        roots.privacy_redaction_root = merkle_root(
            PRIVACY_REDACTION_SUITE,
            &sorted_records(
                self.privacy_redaction_budgets
                    .values()
                    .map(PrivacyRedactionBudget::public_record),
            ),
        );
        roots.public_record_root = merkle_root(PUBLIC_RECORD_SUITE, &self.public_records);
        roots.counters_root = self.counters.state_root();
        roots.replay_filter_root = merkle_root(
            "confidential-token-bridge-rate-limiter-replay-filter-v1",
            &self
                .replay_filter
                .iter()
                .map(|key| json!({ "replay_key": key }))
                .collect::<Vec<_>>(),
        );
        roots.state_root = state_root_from_parts(&self.config, &self.counters, &roots);
        roots
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "bucket_suite": BUCKET_SUITE,
            "lane_commitment_suite": LANE_COMMITMENT_SUITE,
            "pq_attestation_suite": PQ_ATTESTATION_SUITE,
            "dynamic_limit_suite": DYNAMIC_LIMIT_SUITE,
            "low_fee_quota_suite": LOW_FEE_QUOTA_SUITE,
            "abuse_quarantine_suite": ABUSE_QUARANTINE_SUITE,
            "privacy_redaction_suite": PRIVACY_REDACTION_SUITE,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": {
                "config_root": roots.config_root,
                "bucket_root": roots.bucket_root,
                "token_lane_root": roots.token_lane_root,
                "pq_attestation_root": roots.pq_attestation_root,
                "dynamic_limit_root": roots.dynamic_limit_root,
                "low_fee_credit_root": roots.low_fee_credit_root,
                "abuse_quarantine_root": roots.abuse_quarantine_root,
                "privacy_redaction_root": roots.privacy_redaction_root,
                "public_record_root": roots.public_record_root,
                "counters_root": roots.counters_root,
                "replay_filter_root": roots.replay_filter_root
            },
            "bucket_count": self.buckets.len(),
            "token_lane_count": self.token_lanes.len(),
            "pq_attestation_count": self.pq_attestations.len(),
            "dynamic_limit_count": self.dynamic_limits.len(),
            "low_fee_credit_count": self.low_fee_credits.len(),
            "abuse_quarantine_count": self.abuse_quarantines.len(),
            "privacy_redaction_budget_count": self.privacy_redaction_budgets.len()
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    pub fn refresh(&mut self) {
        self.counters = self.compute_counters();
        self.roots = self.roots();
    }

    fn refreshed(mut self) -> Self {
        self.refresh();
        self
    }

    fn compute_counters(&self) -> Counters {
        Counters {
            buckets: self.buckets.len() as u64,
            token_lanes: self.token_lanes.len() as u64,
            attestations: self.pq_attestations.len() as u64,
            dynamic_limits: self.dynamic_limits.len() as u64,
            low_fee_credits: self.low_fee_credits.len() as u64,
            quarantines: self.abuse_quarantines.len() as u64,
            redaction_budgets: self.privacy_redaction_budgets.len() as u64,
            public_records: self.public_records.len() as u64,
            admitted_units: self.counters.admitted_units,
            throttled_units: self.counters.throttled_units,
            quarantined_units: self
                .abuse_quarantines
                .values()
                .map(|quarantine| quarantine.abuse_score)
                .sum(),
            redacted_disclosures: self
                .privacy_redaction_budgets
                .values()
                .map(|budget| budget.spent_units)
                .sum(),
        }
    }

    fn append_public_record(&mut self, record: Value) {
        self.public_records.push(record);
        trim_vec(&mut self.public_records, self.config.max_public_records);
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let config = state.config.clone();
    let monero_bucket = ShieldedBridgeBucket::new(
        "bucket-xmr-in-devnet-0001",
        "confidential-xmr",
        BridgeDirection::MoneroToPrivateL2,
        2_816,
        config.l2_height,
        config.base_limit_units,
        &config,
    );
    state
        .upsert_bucket(monero_bucket)
        .expect("demo bucket must validate");
    let exit_bucket = ShieldedBridgeBucket::new(
        "bucket-xmr-out-devnet-0001",
        "confidential-xmr",
        BridgeDirection::PrivateL2ToMonero,
        2_816,
        config.l2_height,
        config.base_limit_units / 2,
        &config,
    );
    state
        .upsert_bucket(exit_bucket)
        .expect("demo exit bucket must validate");
    let lane = TokenLaneCommitment::new(
        "lane-confidential-xmr-retail-low-fee",
        "bucket-xmr-in-devnet-0001",
        "confidential-xmr",
        12,
        9_200,
    );
    state
        .upsert_token_lane(lane)
        .expect("demo lane must validate");
    let exit_lane = TokenLaneCommitment::new(
        "lane-confidential-xmr-exit-standard",
        "bucket-xmr-out-devnet-0001",
        "confidential-xmr",
        16,
        8_200,
    );
    state
        .upsert_token_lane(exit_lane)
        .expect("demo exit lane must validate");
    let limit = DynamicRateLimit::new(
        "limit-xmr-in-rolling-devnet-0001",
        "bucket-xmr-in-devnet-0001",
        LimitPolicyKind::PrivacyAdaptive,
        config.l2_height,
        &config,
    );
    state
        .install_dynamic_limit(limit)
        .expect("demo limit must validate");
    let exit_limit = DynamicRateLimit::new(
        "limit-xmr-out-liquidity-devnet-0001",
        "bucket-xmr-out-devnet-0001",
        LimitPolicyKind::LiquidityAdaptive,
        config.l2_height,
        &config,
    );
    state
        .install_dynamic_limit(exit_limit)
        .expect("demo exit limit must validate");
    let attestation = PqBridgeAttestation::new(
        "attestation-xmr-in-devnet-0001",
        "bucket-xmr-in-devnet-0001",
        "lane-confidential-xmr-retail-low-fee",
        "attestors-devnet-ml-dsa-slh-001",
        config.l2_height + 3,
        &config,
    );
    state
        .attest_bridge(attestation)
        .expect("demo attestation must validate");
    let credit = LowFeeQuotaCredit::new(
        "credit-retail-low-fee-devnet-0001",
        "bucket-xmr-in-devnet-0001",
        "lane-confidential-xmr-retail-low-fee",
        1_250_000,
        config.l2_height + 4,
        &config,
    );
    state
        .mint_low_fee_credit(credit)
        .expect("demo low fee credit must validate");
    let budget = PrivacyRedactionBudget::new(
        "redaction-budget-xmr-in-amount-devnet-0001",
        "bucket-xmr-in-devnet-0001",
        RedactionScope::Amount,
        2_816,
        config.l2_height + 5,
        &config,
    );
    state
        .allocate_redaction_budget(budget)
        .expect("demo redaction budget must validate");
    let quarantine = AbuseQuarantine::new(
        "quarantine-exit-velocity-devnet-0001",
        "bucket-xmr-out-devnet-0001",
        "lane-confidential-xmr-exit-standard",
        QuarantineReason::VelocityAnomaly,
        740,
        config.l2_height + 8,
        &config,
    );
    state
        .quarantine_abuse(quarantine)
        .expect("demo quarantine must validate");
    state
        .admit_units(
            "bucket-xmr-in-devnet-0001",
            "lane-confidential-xmr-retail-low-fee",
            "unit-commitment-demo-0001",
            250_000,
            Some("credit-retail-low-fee-devnet-0001"),
        )
        .expect("demo admission must validate");
    state.refresh();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    record_root(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKEN-BRIDGE-RATE-LIMITER-STATE",
        record,
    )
}

fn state_root_from_parts(config: &Config, counters: &Counters, roots: &Roots) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKEN-BRIDGE-RATE-LIMITER-STATE-PARTS",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&config.public_record()),
            HashPart::Json(&counters.public_record()),
            HashPart::Str(&roots.config_root),
            HashPart::Str(&roots.bucket_root),
            HashPart::Str(&roots.token_lane_root),
            HashPart::Str(&roots.pq_attestation_root),
            HashPart::Str(&roots.dynamic_limit_root),
            HashPart::Str(&roots.low_fee_credit_root),
            HashPart::Str(&roots.abuse_quarantine_root),
            HashPart::Str(&roots.privacy_redaction_root),
            HashPart::Str(&roots.public_record_root),
            HashPart::Str(&roots.replay_filter_root),
        ],
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn empty_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKEN-BRIDGE-RATE-LIMITER-EMPTY",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}

fn commitment(domain: &str, labels: &[&str], amount: u64) -> String {
    let label_record: Vec<Value> = labels.iter().map(|label| json!(label)).collect();
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&json!(label_record)),
            HashPart::U64(amount),
        ],
        32,
    )
}

fn replay_key(kind: &str, id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKEN-BRIDGE-RATE-LIMITER-REPLAY",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(id),
        ],
        32,
    )
}

fn sorted_records<I>(records: I) -> Vec<Value>
where
    I: IntoIterator<Item = Value>,
{
    let mut records: Vec<Value> = records.into_iter().collect();
    records.sort_by_key(canonical_json);
    records
}

fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

fn trim_vec<T>(values: &mut Vec<T>, max_len: usize) {
    if values.len() > max_len {
        let drain_len = values.len() - max_len;
        values.drain(0..drain_len);
    }
}

fn lane_status_str(status: LaneStatus) -> &'static str {
    match status {
        LaneStatus::Active => "active",
        LaneStatus::CoolingDown => "cooling_down",
        LaneStatus::LowFeeOnly => "low_fee_only",
        LaneStatus::Suspended => "suspended",
        LaneStatus::Quarantined => "quarantined",
        LaneStatus::Retired => "retired",
    }
}

fn attestation_verdict_str(verdict: AttestationVerdict) -> &'static str {
    match verdict {
        AttestationVerdict::Approved => "approved",
        AttestationVerdict::RateLimited => "rate_limited",
        AttestationVerdict::PrivacyInsufficient => "privacy_insufficient",
        AttestationVerdict::FeeOverCap => "fee_over_cap",
        AttestationVerdict::InvalidPqSignature => "invalid_pq_signature",
        AttestationVerdict::ReplayDetected => "replay_detected",
        AttestationVerdict::Quarantined => "quarantined",
    }
}

fn credit_status_str(status: CreditStatus) -> &'static str {
    match status {
        CreditStatus::Minted => "minted",
        CreditStatus::Reserved => "reserved",
        CreditStatus::Applied => "applied",
        CreditStatus::Expired => "expired",
        CreditStatus::Revoked => "revoked",
    }
}

fn ensure_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_eq<T>(name: &str, left: &T, right: &T) -> Result<()>
where
    T: std::fmt::Debug + PartialEq,
{
    if left != right {
        Err(format!("{name} mismatch: left={left:?} right={right:?}"))
    } else {
        Ok(())
    }
}

fn ensure_positive(name: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{name} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_at_least(name: &str, value: u64, min: u64) -> Result<()> {
    if value < min {
        Err(format!("{name} must be at least {min}"))
    } else {
        Ok(())
    }
}

fn ensure_bps(name: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{name} must be <= {MAX_BPS}"))
    } else {
        Ok(())
    }
}

fn ensure_usize_positive(name: &str, value: usize) -> Result<()> {
    if value == 0 {
        Err(format!("{name} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_len(name: &str, len: usize, max_len: usize) -> Result<()> {
    if len > max_len {
        Err(format!("{name} length {len} exceeds max {max_len}"))
    } else {
        Ok(())
    }
}
