use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroBridgeRuntimeManifestResult<T> = Result<T, String>;

pub const MONERO_BRIDGE_RUNTIME_MANIFEST_PROTOCOL_VERSION: &str =
    "nebula-monero-bridge-runtime-manifest-v1";
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_PUBLIC_RECORD_SCHEMA: &str =
    "monero-bridge-runtime-manifest-public-record-v1";
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEVNET_HEIGHT: u64 = 32_640;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_HEADER_SOURCE_SCHEME: &str =
    "monero-header-source-runtime-v1";
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_REORG_WINDOW_SCHEME: &str =
    "monero-reorg-window-runtime-v1";
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_WITHDRAWAL_BATCH_SCHEME: &str =
    "monero-withdrawal-proof-batch-runtime-v1";
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_RESERVE_ATTESTATION_SCHEME: &str =
    "monero-reserve-attestation-runtime-v1";
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_WATCHTOWER_MESH_SCHEME: &str =
    "monero-watchtower-runtime-mesh-v1";
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_EMERGENCY_EXIT_SCHEME: &str =
    "monero-emergency-exit-lane-runtime-v1";
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_LIQUIDITY_PROVIDER_SCHEME: &str =
    "monero-liquidity-provider-runtime-v1";
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_FEE_CAP_SCHEME: &str = "monero-fee-cap-runtime-v1";
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_PRIVACY_BOUNDARY_SCHEME: &str =
    "monero-privacy-disclosure-boundary-v1";
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_FINALITY_DEPTH: u64 = 20;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_SOFT_REORG_WINDOW: u64 = 8;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_HARD_REORG_WINDOW: u64 = 48;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_EMERGENCY_REORG_WINDOW: u64 = 120;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_WITHDRAWAL_BATCH_LIMIT: u64 = 128;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_WITHDRAWAL_BATCH_BYTES: u64 = 4_000_000;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_250;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_TARGET_RESERVE_COVERAGE_BPS: u64 = 11_000;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_WATCHTOWER_QUORUM: u64 = 3;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_RESERVE_QUORUM: u64 = 2;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_LIQUIDITY_QUORUM: u64 = 2;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_EXIT_TTL_BLOCKS: u64 = 96;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_EMERGENCY_EXIT_TTL_BLOCKS: u64 = 288;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MAX_USER_FEE_BPS: u64 = 45;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MAX_PROVIDER_FEE_BPS: u64 = 70;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MAX_SPONSOR_FEE_PICONERO: u64 = 80_000_000;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_DISCLOSURE_RETENTION_BLOCKS: u64 = 7_200;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 256;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MAX_HEADER_LAG_BLOCKS: u64 = 6;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_PROVIDER_SCORE: u64 = 8_500;
pub const MONERO_BRIDGE_RUNTIME_MANIFEST_MAX_BPS: u64 = 10_000;

const ROOT_EMPTY: &str = "MONERO-BRIDGE-RUNTIME-MANIFEST-EMPTY";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderSourceKind {
    PrimaryDaemon,
    SecondaryDaemon,
    CompactBlockRelay,
    LightClientCommittee,
    WatchtowerQuorum,
    ManualRecovery,
}

impl HeaderSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrimaryDaemon => "primary_daemon",
            Self::SecondaryDaemon => "secondary_daemon",
            Self::CompactBlockRelay => "compact_block_relay",
            Self::LightClientCommittee => "light_client_committee",
            Self::WatchtowerQuorum => "watchtower_quorum",
            Self::ManualRecovery => "manual_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSourceStatus {
    Active,
    Standby,
    Lagging,
    Divergent,
    Paused,
    Retired,
}

impl RuntimeSourceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Standby => "standby",
            Self::Lagging => "lagging",
            Self::Divergent => "divergent",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Active | Self::Standby | Self::Lagging)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgWindowKind {
    Soft,
    Hard,
    Emergency,
    GovernanceOverride,
}

impl ReorgWindowKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Soft => "soft",
            Self::Hard => "hard",
            Self::Emergency => "emergency",
            Self::GovernanceOverride => "governance_override",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalBatchStatus {
    Open,
    Sealed,
    Proving,
    WatchtowerAttested,
    FinalityHeld,
    ReadyForRelease,
    Released,
    Challenged,
    Cancelled,
}

impl WithdrawalBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Proving => "proving",
            Self::WatchtowerAttested => "watchtower_attested",
            Self::FinalityHeld => "finality_held",
            Self::ReadyForRelease => "ready_for_release",
            Self::Released => "released",
            Self::Challenged => "challenged",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::Sealed
                | Self::Proving
                | Self::WatchtowerAttested
                | Self::FinalityHeld
                | Self::ReadyForRelease
                | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveAttestationStatus {
    Draft,
    Observed,
    QuorumSigned,
    Disputed,
    Finalized,
    Superseded,
}

impl ReserveAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Observed => "observed",
            Self::QuorumSigned => "quorum_signed",
            Self::Disputed => "disputed",
            Self::Finalized => "finalized",
            Self::Superseded => "superseded",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::QuorumSigned | Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchtowerMeshStatus {
    Healthy,
    Degraded,
    SplitView,
    Alerting,
    Paused,
}

impl WatchtowerMeshStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::SplitView => "split_view",
            Self::Alerting => "alerting",
            Self::Paused => "paused",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyExitStatus {
    Armed,
    Open,
    Throttled,
    CouncilReview,
    Executed,
    Closed,
}

impl EmergencyExitStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Open => "open",
            Self::Throttled => "throttled",
            Self::CouncilReview => "council_review",
            Self::Executed => "executed",
            Self::Closed => "closed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Armed | Self::Open | Self::Throttled | Self::CouncilReview
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityProviderStatus {
    Active,
    Standby,
    RateLimited,
    UnderCollateralized,
    Suspended,
    Retired,
}

impl LiquidityProviderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Standby => "standby",
            Self::RateLimited => "rate_limited",
            Self::UnderCollateralized => "under_collateralized",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Active | Self::Standby | Self::RateLimited)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBoundaryKind {
    ViewKeyDisclosure,
    ReserveProof,
    WithdrawalNullifier,
    WatchtowerEvidence,
    FeeSponsorReceipt,
    EmergencyCouncilPacket,
}

impl PrivacyBoundaryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewKeyDisclosure => "view_key_disclosure",
            Self::ReserveProof => "reserve_proof",
            Self::WithdrawalNullifier => "withdrawal_nullifier",
            Self::WatchtowerEvidence => "watchtower_evidence",
            Self::FeeSponsorReceipt => "fee_sponsor_receipt",
            Self::EmergencyCouncilPacket => "emergency_council_packet",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeInvariantKind {
    HeaderFreshness,
    ReserveCoverage,
    WatchtowerQuorum,
    WithdrawalBatchBound,
    EmergencyExitBound,
    LiquidityFeeBound,
    PrivacyDisclosureBound,
    ReorgHoldBound,
}

impl RuntimeInvariantKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeaderFreshness => "header_freshness",
            Self::ReserveCoverage => "reserve_coverage",
            Self::WatchtowerQuorum => "watchtower_quorum",
            Self::WithdrawalBatchBound => "withdrawal_batch_bound",
            Self::EmergencyExitBound => "emergency_exit_bound",
            Self::LiquidityFeeBound => "liquidity_fee_bound",
            Self::PrivacyDisclosureBound => "privacy_disclosure_bound",
            Self::ReorgHoldBound => "reorg_hold_bound",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeInvariantStatus {
    Enforced,
    Monitoring,
    Breached,
    Waived,
}

impl RuntimeInvariantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforced => "enforced",
            Self::Monitoring => "monitoring",
            Self::Breached => "breached",
            Self::Waived => "waived",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Enforced | Self::Monitoring | Self::Breached)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeInvariant {
    pub invariant_id: String,
    pub kind: RuntimeInvariantKind,
    pub status: RuntimeInvariantStatus,
    pub scope_root: String,
    pub threshold_root: String,
    pub observation_root: String,
    pub response_root: String,
    pub opened_height: u64,
    pub last_checked_height: u64,
    pub breach_count: u64,
    pub metadata_root: String,
}

impl RuntimeInvariant {
    pub fn validate(&self) -> MoneroBridgeRuntimeManifestResult<()> {
        require_non_empty("invariant_id", &self.invariant_id)?;
        require_non_empty("scope_root", &self.scope_root)?;
        require_non_empty("threshold_root", &self.threshold_root)?;
        require_non_empty("observation_root", &self.observation_root)?;
        require_non_empty("response_root", &self.response_root)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        if self.last_checked_height < self.opened_height {
            return Err("runtime invariant checked before opened height".to_string());
        }
        if self.status == RuntimeInvariantStatus::Enforced && self.breach_count != 0 {
            return Err("enforced runtime invariant cannot carry unresolved breaches".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "invariant_id": self.invariant_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "scope_root": self.scope_root,
            "threshold_root": self.threshold_root,
            "observation_root": self.observation_root,
            "response_root": self.response_root,
            "opened_height": self.opened_height.to_string(),
            "last_checked_height": self.last_checked_height.to_string(),
            "breach_count": self.breach_count.to_string(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        manifest_hash(
            "RUNTIME-INVARIANT",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub public_record_schema: String,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub finality_depth: u64,
    pub soft_reorg_window_blocks: u64,
    pub hard_reorg_window_blocks: u64,
    pub emergency_reorg_window_blocks: u64,
    pub withdrawal_batch_limit: u64,
    pub withdrawal_batch_bytes: u64,
    pub min_reserve_coverage_bps: u64,
    pub target_reserve_coverage_bps: u64,
    pub watchtower_quorum: u64,
    pub reserve_quorum: u64,
    pub liquidity_quorum: u64,
    pub exit_ttl_blocks: u64,
    pub emergency_exit_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub max_provider_fee_bps: u64,
    pub max_sponsor_fee_piconero: u64,
    pub disclosure_retention_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u64,
    pub max_header_lag_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: MONERO_BRIDGE_RUNTIME_MANIFEST_PROTOCOL_VERSION.to_string(),
            public_record_schema: MONERO_BRIDGE_RUNTIME_MANIFEST_PUBLIC_RECORD_SCHEMA.to_string(),
            monero_network: MONERO_BRIDGE_RUNTIME_MANIFEST_DEVNET_MONERO_NETWORK.to_string(),
            l2_network: MONERO_BRIDGE_RUNTIME_MANIFEST_DEVNET_L2_NETWORK.to_string(),
            asset_id: MONERO_BRIDGE_RUNTIME_MANIFEST_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_BRIDGE_RUNTIME_MANIFEST_DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: MONERO_BRIDGE_RUNTIME_MANIFEST_HASH_SUITE.to_string(),
            finality_depth: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_FINALITY_DEPTH,
            soft_reorg_window_blocks: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_SOFT_REORG_WINDOW,
            hard_reorg_window_blocks: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_HARD_REORG_WINDOW,
            emergency_reorg_window_blocks:
                MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_EMERGENCY_REORG_WINDOW,
            withdrawal_batch_limit: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_WITHDRAWAL_BATCH_LIMIT,
            withdrawal_batch_bytes: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_WITHDRAWAL_BATCH_BYTES,
            min_reserve_coverage_bps:
                MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            target_reserve_coverage_bps:
                MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
            watchtower_quorum: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_WATCHTOWER_QUORUM,
            reserve_quorum: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_RESERVE_QUORUM,
            liquidity_quorum: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_LIQUIDITY_QUORUM,
            exit_ttl_blocks: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_EXIT_TTL_BLOCKS,
            emergency_exit_ttl_blocks:
                MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_EMERGENCY_EXIT_TTL_BLOCKS,
            max_user_fee_bps: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MAX_USER_FEE_BPS,
            max_provider_fee_bps: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MAX_PROVIDER_FEE_BPS,
            max_sponsor_fee_piconero:
                MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MAX_SPONSOR_FEE_PICONERO,
            disclosure_retention_blocks:
                MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_DISCLOSURE_RETENTION_BLOCKS,
            min_privacy_set_size: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_header_lag_blocks: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MAX_HEADER_LAG_BLOCKS,
        }
    }

    pub fn validate(&self) -> MoneroBridgeRuntimeManifestResult<()> {
        if self.protocol_version != MONERO_BRIDGE_RUNTIME_MANIFEST_PROTOCOL_VERSION {
            return Err("monero bridge runtime manifest protocol version mismatch".to_string());
        }
        require_non_empty("monero_network", &self.monero_network)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("asset_id", &self.asset_id)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_positive("finality_depth", self.finality_depth)?;
        require_positive("soft_reorg_window_blocks", self.soft_reorg_window_blocks)?;
        require_positive("hard_reorg_window_blocks", self.hard_reorg_window_blocks)?;
        require_positive(
            "emergency_reorg_window_blocks",
            self.emergency_reorg_window_blocks,
        )?;
        require_ordered_window(
            self.soft_reorg_window_blocks,
            self.hard_reorg_window_blocks,
            self.emergency_reorg_window_blocks,
        )?;
        require_positive("withdrawal_batch_limit", self.withdrawal_batch_limit)?;
        require_positive("withdrawal_batch_bytes", self.withdrawal_batch_bytes)?;
        require_bps(
            "min_reserve_coverage_bps",
            self.min_reserve_coverage_bps,
            false,
        )?;
        require_bps(
            "target_reserve_coverage_bps",
            self.target_reserve_coverage_bps,
            false,
        )?;
        if self.target_reserve_coverage_bps < self.min_reserve_coverage_bps {
            return Err(
                "target reserve coverage must be at least minimum reserve coverage".to_string(),
            );
        }
        require_positive("watchtower_quorum", self.watchtower_quorum)?;
        require_positive("reserve_quorum", self.reserve_quorum)?;
        require_positive("liquidity_quorum", self.liquidity_quorum)?;
        require_positive("exit_ttl_blocks", self.exit_ttl_blocks)?;
        require_positive("emergency_exit_ttl_blocks", self.emergency_exit_ttl_blocks)?;
        if self.emergency_exit_ttl_blocks < self.exit_ttl_blocks {
            return Err("emergency exit ttl must be at least normal exit ttl".to_string());
        }
        require_bps("max_user_fee_bps", self.max_user_fee_bps, true)?;
        require_bps("max_provider_fee_bps", self.max_provider_fee_bps, true)?;
        require_positive(
            "disclosure_retention_blocks",
            self.disclosure_retention_blocks,
        )?;
        require_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        require_positive("min_pq_security_bits", self.min_pq_security_bits)?;
        require_positive("max_header_lag_blocks", self.max_header_lag_blocks)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "public_record_schema": self.public_record_schema,
            "chain_id": CHAIN_ID,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "finality_depth": self.finality_depth.to_string(),
            "soft_reorg_window_blocks": self.soft_reorg_window_blocks.to_string(),
            "hard_reorg_window_blocks": self.hard_reorg_window_blocks.to_string(),
            "emergency_reorg_window_blocks": self.emergency_reorg_window_blocks.to_string(),
            "withdrawal_batch_limit": self.withdrawal_batch_limit.to_string(),
            "withdrawal_batch_bytes": self.withdrawal_batch_bytes.to_string(),
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps.to_string(),
            "target_reserve_coverage_bps": self.target_reserve_coverage_bps.to_string(),
            "watchtower_quorum": self.watchtower_quorum.to_string(),
            "reserve_quorum": self.reserve_quorum.to_string(),
            "liquidity_quorum": self.liquidity_quorum.to_string(),
            "exit_ttl_blocks": self.exit_ttl_blocks.to_string(),
            "emergency_exit_ttl_blocks": self.emergency_exit_ttl_blocks.to_string(),
            "max_user_fee_bps": self.max_user_fee_bps.to_string(),
            "max_provider_fee_bps": self.max_provider_fee_bps.to_string(),
            "max_sponsor_fee_piconero": self.max_sponsor_fee_piconero.to_string(),
            "disclosure_retention_blocks": self.disclosure_retention_blocks.to_string(),
            "min_privacy_set_size": self.min_privacy_set_size.to_string(),
            "min_pq_security_bits": self.min_pq_security_bits.to_string(),
            "max_header_lag_blocks": self.max_header_lag_blocks.to_string(),
        })
    }

    pub fn root(&self) -> String {
        manifest_hash("CONFIG", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderSource {
    pub source_id: String,
    pub kind: HeaderSourceKind,
    pub status: RuntimeSourceStatus,
    pub endpoint_commitment: String,
    pub operator_commitment: String,
    pub header_tip_hash: String,
    pub header_tip_height: u64,
    pub finalized_height: u64,
    pub weight: u64,
    pub max_lag_blocks: u64,
    pub evidence_root: String,
    pub metadata_root: String,
}

impl HeaderSource {
    pub fn validate(&self) -> MoneroBridgeRuntimeManifestResult<()> {
        require_non_empty("source_id", &self.source_id)?;
        require_non_empty("endpoint_commitment", &self.endpoint_commitment)?;
        require_non_empty("operator_commitment", &self.operator_commitment)?;
        require_non_empty("header_tip_hash", &self.header_tip_hash)?;
        require_positive("header source weight", self.weight)?;
        require_positive("header source max lag", self.max_lag_blocks)?;
        require_non_empty("evidence_root", &self.evidence_root)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        if self.finalized_height > self.header_tip_height {
            return Err("header source finalized height exceeds tip height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "source_id": self.source_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "endpoint_commitment": self.endpoint_commitment,
            "operator_commitment": self.operator_commitment,
            "header_tip_hash": self.header_tip_hash,
            "header_tip_height": self.header_tip_height.to_string(),
            "finalized_height": self.finalized_height.to_string(),
            "weight": self.weight.to_string(),
            "max_lag_blocks": self.max_lag_blocks.to_string(),
            "evidence_root": self.evidence_root,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        manifest_hash("HEADER-SOURCE", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgWindow {
    pub window_id: String,
    pub kind: ReorgWindowKind,
    pub anchor_height: u64,
    pub observed_height: u64,
    pub depth_blocks: u64,
    pub hold_blocks: u64,
    pub source_root: String,
    pub watchtower_vote_root: String,
    pub insurance_claim_root: String,
    pub metadata_root: String,
}

impl ReorgWindow {
    pub fn validate(&self) -> MoneroBridgeRuntimeManifestResult<()> {
        require_non_empty("window_id", &self.window_id)?;
        require_positive("depth_blocks", self.depth_blocks)?;
        require_positive("hold_blocks", self.hold_blocks)?;
        require_non_empty("source_root", &self.source_root)?;
        require_non_empty("watchtower_vote_root", &self.watchtower_vote_root)?;
        require_non_empty("insurance_claim_root", &self.insurance_claim_root)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        if self.observed_height < self.anchor_height {
            return Err("reorg window observed height is below anchor height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "kind": self.kind.as_str(),
            "anchor_height": self.anchor_height.to_string(),
            "observed_height": self.observed_height.to_string(),
            "depth_blocks": self.depth_blocks.to_string(),
            "hold_blocks": self.hold_blocks.to_string(),
            "source_root": self.source_root,
            "watchtower_vote_root": self.watchtower_vote_root,
            "insurance_claim_root": self.insurance_claim_root,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        manifest_hash("REORG-WINDOW", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalProofBatch {
    pub batch_id: String,
    pub status: WithdrawalBatchStatus,
    pub opened_height: u64,
    pub sealed_height: u64,
    pub proof_count: u64,
    pub max_proof_count: u64,
    pub aggregate_proof_root: String,
    pub membership_root: String,
    pub nullifier_root: String,
    pub recipient_commitment_root: String,
    pub watchtower_attestation_root: String,
    pub fee_sponsor_root: String,
    pub metadata_root: String,
}

impl WithdrawalProofBatch {
    pub fn validate(&self) -> MoneroBridgeRuntimeManifestResult<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_positive("max_proof_count", self.max_proof_count)?;
        require_non_empty("aggregate_proof_root", &self.aggregate_proof_root)?;
        require_non_empty("membership_root", &self.membership_root)?;
        require_non_empty("nullifier_root", &self.nullifier_root)?;
        require_non_empty("recipient_commitment_root", &self.recipient_commitment_root)?;
        require_non_empty(
            "watchtower_attestation_root",
            &self.watchtower_attestation_root,
        )?;
        require_non_empty("fee_sponsor_root", &self.fee_sponsor_root)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        if self.proof_count > self.max_proof_count {
            return Err("withdrawal proof batch exceeds maximum proof count".to_string());
        }
        if self.sealed_height != 0 && self.sealed_height < self.opened_height {
            return Err("withdrawal proof batch sealed before opened height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "opened_height": self.opened_height.to_string(),
            "sealed_height": self.sealed_height.to_string(),
            "proof_count": self.proof_count.to_string(),
            "max_proof_count": self.max_proof_count.to_string(),
            "aggregate_proof_root": self.aggregate_proof_root,
            "membership_root": self.membership_root,
            "nullifier_root": self.nullifier_root,
            "recipient_commitment_root": self.recipient_commitment_root,
            "watchtower_attestation_root": self.watchtower_attestation_root,
            "fee_sponsor_root": self.fee_sponsor_root,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        manifest_hash(
            "WITHDRAWAL-PROOF-BATCH",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveAttestation {
    pub attestation_id: String,
    pub status: ReserveAttestationStatus,
    pub reserve_operator: String,
    pub observed_height: u64,
    pub attested_height: u64,
    pub reserve_commitment_root: String,
    pub liabilities_commitment_root: String,
    pub coverage_bps: u64,
    pub attestor_root: String,
    pub watchtower_evidence_root: String,
    pub disclosure_boundary_root: String,
    pub metadata_root: String,
}

impl ReserveAttestation {
    pub fn validate(&self) -> MoneroBridgeRuntimeManifestResult<()> {
        require_non_empty("attestation_id", &self.attestation_id)?;
        require_non_empty("reserve_operator", &self.reserve_operator)?;
        require_non_empty("reserve_commitment_root", &self.reserve_commitment_root)?;
        require_non_empty(
            "liabilities_commitment_root",
            &self.liabilities_commitment_root,
        )?;
        require_bps("coverage_bps", self.coverage_bps, false)?;
        require_non_empty("attestor_root", &self.attestor_root)?;
        require_non_empty("watchtower_evidence_root", &self.watchtower_evidence_root)?;
        require_non_empty("disclosure_boundary_root", &self.disclosure_boundary_root)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        if self.attested_height != 0 && self.attested_height < self.observed_height {
            return Err("reserve attestation signed before observed height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "status": self.status.as_str(),
            "reserve_operator": self.reserve_operator,
            "observed_height": self.observed_height.to_string(),
            "attested_height": self.attested_height.to_string(),
            "reserve_commitment_root": self.reserve_commitment_root,
            "liabilities_commitment_root": self.liabilities_commitment_root,
            "coverage_bps": self.coverage_bps.to_string(),
            "attestor_root": self.attestor_root,
            "watchtower_evidence_root": self.watchtower_evidence_root,
            "disclosure_boundary_root": self.disclosure_boundary_root,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        manifest_hash(
            "RESERVE-ATTESTATION",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerMesh {
    pub mesh_id: String,
    pub status: WatchtowerMeshStatus,
    pub watcher_root: String,
    pub alert_root: String,
    pub slashing_root: String,
    pub quorum_weight: u64,
    pub live_weight: u64,
    pub last_heartbeat_height: u64,
    pub split_view_root: String,
    pub metadata_root: String,
}

impl WatchtowerMesh {
    pub fn validate(&self) -> MoneroBridgeRuntimeManifestResult<()> {
        require_non_empty("mesh_id", &self.mesh_id)?;
        require_non_empty("watcher_root", &self.watcher_root)?;
        require_non_empty("alert_root", &self.alert_root)?;
        require_non_empty("slashing_root", &self.slashing_root)?;
        require_positive("quorum_weight", self.quorum_weight)?;
        require_non_empty("split_view_root", &self.split_view_root)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        if self.live_weight < self.quorum_weight && self.status == WatchtowerMeshStatus::Healthy {
            return Err("healthy watchtower mesh does not meet quorum weight".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "mesh_id": self.mesh_id,
            "status": self.status.as_str(),
            "watcher_root": self.watcher_root,
            "alert_root": self.alert_root,
            "slashing_root": self.slashing_root,
            "quorum_weight": self.quorum_weight.to_string(),
            "live_weight": self.live_weight.to_string(),
            "last_heartbeat_height": self.last_heartbeat_height.to_string(),
            "split_view_root": self.split_view_root,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        manifest_hash("WATCHTOWER-MESH", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyExitLane {
    pub lane_id: String,
    pub status: EmergencyExitStatus,
    pub trigger_root: String,
    pub council_root: String,
    pub allowed_claim_root: String,
    pub nullifier_root: String,
    pub rate_limit_root: String,
    pub opened_height: u64,
    pub expires_height: u64,
    pub max_claims: u64,
    pub submitted_claims: u64,
    pub metadata_root: String,
}

impl EmergencyExitLane {
    pub fn validate(&self) -> MoneroBridgeRuntimeManifestResult<()> {
        require_non_empty("lane_id", &self.lane_id)?;
        require_non_empty("trigger_root", &self.trigger_root)?;
        require_non_empty("council_root", &self.council_root)?;
        require_non_empty("allowed_claim_root", &self.allowed_claim_root)?;
        require_non_empty("nullifier_root", &self.nullifier_root)?;
        require_non_empty("rate_limit_root", &self.rate_limit_root)?;
        require_positive("max_claims", self.max_claims)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        if self.expires_height <= self.opened_height {
            return Err("emergency exit lane expires before it can be used".to_string());
        }
        if self.submitted_claims > self.max_claims {
            return Err("emergency exit lane exceeds max claims".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "trigger_root": self.trigger_root,
            "council_root": self.council_root,
            "allowed_claim_root": self.allowed_claim_root,
            "nullifier_root": self.nullifier_root,
            "rate_limit_root": self.rate_limit_root,
            "opened_height": self.opened_height.to_string(),
            "expires_height": self.expires_height.to_string(),
            "max_claims": self.max_claims.to_string(),
            "submitted_claims": self.submitted_claims.to_string(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        manifest_hash(
            "EMERGENCY-EXIT-LANE",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityProvider {
    pub provider_id: String,
    pub status: LiquidityProviderStatus,
    pub operator_commitment: String,
    pub reserve_commitment_root: String,
    pub settlement_address_commitment: String,
    pub available_liquidity_piconero: u128,
    pub locked_liquidity_piconero: u128,
    pub max_ticket_piconero: u128,
    pub fee_cap_bps: u64,
    pub reputation_score: u64,
    pub last_quote_height: u64,
    pub metadata_root: String,
}

impl LiquidityProvider {
    pub fn validate(&self) -> MoneroBridgeRuntimeManifestResult<()> {
        require_non_empty("provider_id", &self.provider_id)?;
        require_non_empty("operator_commitment", &self.operator_commitment)?;
        require_non_empty("reserve_commitment_root", &self.reserve_commitment_root)?;
        require_non_empty(
            "settlement_address_commitment",
            &self.settlement_address_commitment,
        )?;
        require_bps("fee_cap_bps", self.fee_cap_bps, true)?;
        require_bps("reputation_score", self.reputation_score, true)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        if self.max_ticket_piconero > self.available_liquidity_piconero {
            return Err("provider max ticket exceeds available liquidity".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "provider_id": self.provider_id,
            "status": self.status.as_str(),
            "operator_commitment": self.operator_commitment,
            "reserve_commitment_root": self.reserve_commitment_root,
            "settlement_address_commitment": self.settlement_address_commitment,
            "available_liquidity_piconero": self.available_liquidity_piconero.to_string(),
            "locked_liquidity_piconero": self.locked_liquidity_piconero.to_string(),
            "max_ticket_piconero": self.max_ticket_piconero.to_string(),
            "fee_cap_bps": self.fee_cap_bps.to_string(),
            "reputation_score": self.reputation_score.to_string(),
            "last_quote_height": self.last_quote_height.to_string(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        manifest_hash(
            "LIQUIDITY-PROVIDER",
            &[HashPart::Json(&self.public_record())],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCap {
    pub cap_id: String,
    pub lane_id: String,
    pub user_fee_bps: u64,
    pub provider_fee_bps: u64,
    pub sponsor_fee_piconero: u64,
    pub effective_height: u64,
    pub expires_height: u64,
    pub oracle_root: String,
    pub metadata_root: String,
}

impl FeeCap {
    pub fn validate(&self) -> MoneroBridgeRuntimeManifestResult<()> {
        require_non_empty("cap_id", &self.cap_id)?;
        require_non_empty("lane_id", &self.lane_id)?;
        require_bps("user_fee_bps", self.user_fee_bps, true)?;
        require_bps("provider_fee_bps", self.provider_fee_bps, true)?;
        require_non_empty("oracle_root", &self.oracle_root)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        if self.expires_height <= self.effective_height {
            return Err("fee cap expires before effective height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "lane_id": self.lane_id,
            "user_fee_bps": self.user_fee_bps.to_string(),
            "provider_fee_bps": self.provider_fee_bps.to_string(),
            "sponsor_fee_piconero": self.sponsor_fee_piconero.to_string(),
            "effective_height": self.effective_height.to_string(),
            "expires_height": self.expires_height.to_string(),
            "oracle_root": self.oracle_root,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        manifest_hash("FEE-CAP", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyDisclosureBoundary {
    pub boundary_id: String,
    pub kind: PrivacyBoundaryKind,
    pub subject_commitment: String,
    pub allowed_viewer_root: String,
    pub disclosed_field_root: String,
    pub retention_blocks: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub revocation_root: String,
    pub audit_receipt_root: String,
    pub metadata_root: String,
}

impl PrivacyDisclosureBoundary {
    pub fn validate(&self) -> MoneroBridgeRuntimeManifestResult<()> {
        require_non_empty("boundary_id", &self.boundary_id)?;
        require_non_empty("subject_commitment", &self.subject_commitment)?;
        require_non_empty("allowed_viewer_root", &self.allowed_viewer_root)?;
        require_non_empty("disclosed_field_root", &self.disclosed_field_root)?;
        require_positive("retention_blocks", self.retention_blocks)?;
        require_non_empty("revocation_root", &self.revocation_root)?;
        require_non_empty("audit_receipt_root", &self.audit_receipt_root)?;
        require_non_empty("metadata_root", &self.metadata_root)?;
        if self.expires_height <= self.opened_height {
            return Err("privacy disclosure boundary expires before opened height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "boundary_id": self.boundary_id,
            "kind": self.kind.as_str(),
            "subject_commitment": self.subject_commitment,
            "allowed_viewer_root": self.allowed_viewer_root,
            "disclosed_field_root": self.disclosed_field_root,
            "retention_blocks": self.retention_blocks.to_string(),
            "opened_height": self.opened_height.to_string(),
            "expires_height": self.expires_height.to_string(),
            "revocation_root": self.revocation_root,
            "audit_receipt_root": self.audit_receipt_root,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        manifest_hash("PRIVACY-BOUNDARY", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub header_source_root: String,
    pub reorg_window_root: String,
    pub withdrawal_batch_root: String,
    pub reserve_attestation_root: String,
    pub watchtower_mesh_root: String,
    pub emergency_exit_lane_root: String,
    pub liquidity_provider_root: String,
    pub fee_cap_root: String,
    pub privacy_boundary_root: String,
    pub runtime_invariant_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "header_source_root": self.header_source_root,
            "reorg_window_root": self.reorg_window_root,
            "withdrawal_batch_root": self.withdrawal_batch_root,
            "reserve_attestation_root": self.reserve_attestation_root,
            "watchtower_mesh_root": self.watchtower_mesh_root,
            "emergency_exit_lane_root": self.emergency_exit_lane_root,
            "liquidity_provider_root": self.liquidity_provider_root,
            "fee_cap_root": self.fee_cap_root,
            "privacy_boundary_root": self.privacy_boundary_root,
            "runtime_invariant_root": self.runtime_invariant_root,
        })
    }

    pub fn root(&self) -> String {
        manifest_hash("ROOTS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub header_sources: u64,
    pub live_header_sources: u64,
    pub reorg_windows: u64,
    pub withdrawal_batches: u64,
    pub live_withdrawal_batches: u64,
    pub reserve_attestations: u64,
    pub usable_reserve_attestations: u64,
    pub watchtower_meshes: u64,
    pub emergency_exit_lanes: u64,
    pub live_emergency_exit_lanes: u64,
    pub liquidity_providers: u64,
    pub live_liquidity_providers: u64,
    pub fee_caps: u64,
    pub privacy_boundaries: u64,
    pub runtime_invariants: u64,
    pub live_runtime_invariants: u64,
    pub total_available_liquidity_piconero: u128,
    pub total_locked_liquidity_piconero: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "header_sources": self.header_sources.to_string(),
            "live_header_sources": self.live_header_sources.to_string(),
            "reorg_windows": self.reorg_windows.to_string(),
            "withdrawal_batches": self.withdrawal_batches.to_string(),
            "live_withdrawal_batches": self.live_withdrawal_batches.to_string(),
            "reserve_attestations": self.reserve_attestations.to_string(),
            "usable_reserve_attestations": self.usable_reserve_attestations.to_string(),
            "watchtower_meshes": self.watchtower_meshes.to_string(),
            "emergency_exit_lanes": self.emergency_exit_lanes.to_string(),
            "live_emergency_exit_lanes": self.live_emergency_exit_lanes.to_string(),
            "liquidity_providers": self.liquidity_providers.to_string(),
            "live_liquidity_providers": self.live_liquidity_providers.to_string(),
            "fee_caps": self.fee_caps.to_string(),
            "privacy_boundaries": self.privacy_boundaries.to_string(),
            "runtime_invariants": self.runtime_invariants.to_string(),
            "live_runtime_invariants": self.live_runtime_invariants.to_string(),
            "total_available_liquidity_piconero": self.total_available_liquidity_piconero.to_string(),
            "total_locked_liquidity_piconero": self.total_locked_liquidity_piconero.to_string(),
        })
    }

    pub fn root(&self) -> String {
        manifest_hash("COUNTERS", &[HashPart::Json(&self.public_record())])
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub header_sources: Vec<HeaderSource>,
    pub reorg_windows: Vec<ReorgWindow>,
    pub withdrawal_batches: Vec<WithdrawalProofBatch>,
    pub reserve_attestations: Vec<ReserveAttestation>,
    pub watchtower_meshes: Vec<WatchtowerMesh>,
    pub emergency_exit_lanes: Vec<EmergencyExitLane>,
    pub liquidity_providers: Vec<LiquidityProvider>,
    pub fee_caps: Vec<FeeCap>,
    pub privacy_boundaries: Vec<PrivacyDisclosureBoundary>,
    pub runtime_invariants: Vec<RuntimeInvariant>,
}

impl State {
    pub fn devnet() -> MoneroBridgeRuntimeManifestResult<Self> {
        let config = Config::devnet();
        let empty = empty_root();
        let height = MONERO_BRIDGE_RUNTIME_MANIFEST_DEVNET_HEIGHT;
        let state = Self {
            height,
            config,
            header_sources: vec![
                HeaderSource {
                    source_id: "monero-devnet-primary-daemon".to_string(),
                    kind: HeaderSourceKind::PrimaryDaemon,
                    status: RuntimeSourceStatus::Active,
                    endpoint_commitment: manifest_hash(
                        "DEVNET-ENDPOINT",
                        &[HashPart::Str("primary-daemon")],
                    ),
                    operator_commitment: manifest_hash(
                        "DEVNET-OPERATOR",
                        &[HashPart::Str("bridge-ops-a")],
                    ),
                    header_tip_hash: manifest_hash("DEVNET-HEADER", &[HashPart::Str("tip-a")]),
                    header_tip_height: height,
                    finalized_height: height
                        - MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_FINALITY_DEPTH,
                    weight: 2,
                    max_lag_blocks: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MAX_HEADER_LAG_BLOCKS,
                    evidence_root: empty.clone(),
                    metadata_root: manifest_hash(
                        "DEVNET-METADATA",
                        &[HashPart::Str("primary-header-source")],
                    ),
                },
                HeaderSource {
                    source_id: "monero-devnet-watchtower-quorum".to_string(),
                    kind: HeaderSourceKind::WatchtowerQuorum,
                    status: RuntimeSourceStatus::Standby,
                    endpoint_commitment: manifest_hash(
                        "DEVNET-ENDPOINT",
                        &[HashPart::Str("watchtower-quorum")],
                    ),
                    operator_commitment: manifest_hash(
                        "DEVNET-OPERATOR",
                        &[HashPart::Str("watchtower-mesh")],
                    ),
                    header_tip_hash: manifest_hash("DEVNET-HEADER", &[HashPart::Str("tip-b")]),
                    header_tip_height: height - 1,
                    finalized_height: height
                        - MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_FINALITY_DEPTH,
                    weight: 2,
                    max_lag_blocks: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MAX_HEADER_LAG_BLOCKS,
                    evidence_root: empty.clone(),
                    metadata_root: manifest_hash(
                        "DEVNET-METADATA",
                        &[HashPart::Str("watchtower-header-source")],
                    ),
                },
            ],
            reorg_windows: vec![
                ReorgWindow {
                    window_id: "monero-devnet-soft-reorg-window".to_string(),
                    kind: ReorgWindowKind::Soft,
                    anchor_height: height - 8,
                    observed_height: height,
                    depth_blocks: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_SOFT_REORG_WINDOW,
                    hold_blocks: 4,
                    source_root: empty.clone(),
                    watchtower_vote_root: empty.clone(),
                    insurance_claim_root: empty.clone(),
                    metadata_root: manifest_hash("DEVNET-METADATA", &[HashPart::Str("soft-reorg")]),
                },
                ReorgWindow {
                    window_id: "monero-devnet-hard-reorg-window".to_string(),
                    kind: ReorgWindowKind::Hard,
                    anchor_height: height - 48,
                    observed_height: height,
                    depth_blocks: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_HARD_REORG_WINDOW,
                    hold_blocks: 24,
                    source_root: empty.clone(),
                    watchtower_vote_root: empty.clone(),
                    insurance_claim_root: empty.clone(),
                    metadata_root: manifest_hash("DEVNET-METADATA", &[HashPart::Str("hard-reorg")]),
                },
            ],
            withdrawal_batches: vec![WithdrawalProofBatch {
                batch_id: "monero-devnet-withdrawal-batch-0001".to_string(),
                status: WithdrawalBatchStatus::WatchtowerAttested,
                opened_height: height - 6,
                sealed_height: height - 2,
                proof_count: 32,
                max_proof_count: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_WITHDRAWAL_BATCH_LIMIT,
                aggregate_proof_root: manifest_hash(
                    "DEVNET-WITHDRAWAL-PROOF",
                    &[HashPart::Str("batch-0001")],
                ),
                membership_root: manifest_hash("DEVNET-MEMBERSHIP", &[HashPart::Str("batch-0001")]),
                nullifier_root: manifest_hash("DEVNET-NULLIFIER", &[HashPart::Str("batch-0001")]),
                recipient_commitment_root: manifest_hash(
                    "DEVNET-RECIPIENTS",
                    &[HashPart::Str("batch-0001")],
                ),
                watchtower_attestation_root: manifest_hash(
                    "DEVNET-WATCHTOWER-ATTESTATION",
                    &[HashPart::Str("batch-0001")],
                ),
                fee_sponsor_root: empty.clone(),
                metadata_root: manifest_hash(
                    "DEVNET-METADATA",
                    &[HashPart::Str("withdrawal-batch-0001")],
                ),
            }],
            reserve_attestations: vec![ReserveAttestation {
                attestation_id: "monero-devnet-reserve-attestation-0001".to_string(),
                status: ReserveAttestationStatus::QuorumSigned,
                reserve_operator: "reserve-operator-a".to_string(),
                observed_height: height - 3,
                attested_height: height - 1,
                reserve_commitment_root: manifest_hash(
                    "DEVNET-RESERVE",
                    &[HashPart::Str("operator-a")],
                ),
                liabilities_commitment_root: manifest_hash(
                    "DEVNET-LIABILITIES",
                    &[HashPart::Str("operator-a")],
                ),
                coverage_bps: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
                attestor_root: manifest_hash("DEVNET-ATTESTORS", &[HashPart::Str("reserve")]),
                watchtower_evidence_root: empty.clone(),
                disclosure_boundary_root: empty.clone(),
                metadata_root: manifest_hash(
                    "DEVNET-METADATA",
                    &[HashPart::Str("reserve-attestation-0001")],
                ),
            }],
            watchtower_meshes: vec![WatchtowerMesh {
                mesh_id: "monero-devnet-watchtower-mesh".to_string(),
                status: WatchtowerMeshStatus::Healthy,
                watcher_root: manifest_hash("DEVNET-WATCHERS", &[HashPart::Str("mesh-a")]),
                alert_root: empty.clone(),
                slashing_root: empty.clone(),
                quorum_weight: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_WATCHTOWER_QUORUM,
                live_weight: 4,
                last_heartbeat_height: height,
                split_view_root: empty.clone(),
                metadata_root: manifest_hash(
                    "DEVNET-METADATA",
                    &[HashPart::Str("watchtower-mesh")],
                ),
            }],
            emergency_exit_lanes: vec![EmergencyExitLane {
                lane_id: "monero-devnet-emergency-exit-lane".to_string(),
                status: EmergencyExitStatus::Armed,
                trigger_root: manifest_hash("DEVNET-TRIGGER", &[HashPart::Str("armed")]),
                council_root: manifest_hash("DEVNET-COUNCIL", &[HashPart::Str("bridge")]),
                allowed_claim_root: empty.clone(),
                nullifier_root: empty.clone(),
                rate_limit_root: manifest_hash("DEVNET-RATE-LIMIT", &[HashPart::Str("exit")]),
                opened_height: height,
                expires_height: height
                    + MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_EMERGENCY_EXIT_TTL_BLOCKS,
                max_claims: 512,
                submitted_claims: 0,
                metadata_root: manifest_hash("DEVNET-METADATA", &[HashPart::Str("emergency-exit")]),
            }],
            liquidity_providers: vec![
                LiquidityProvider {
                    provider_id: "monero-devnet-lp-a".to_string(),
                    status: LiquidityProviderStatus::Active,
                    operator_commitment: manifest_hash("DEVNET-LP", &[HashPart::Str("a")]),
                    reserve_commitment_root: manifest_hash(
                        "DEVNET-LP-RESERVE",
                        &[HashPart::Str("a")],
                    ),
                    settlement_address_commitment: manifest_hash(
                        "DEVNET-SETTLEMENT-ADDRESS",
                        &[HashPart::Str("a")],
                    ),
                    available_liquidity_piconero: 25_000_000_000_000,
                    locked_liquidity_piconero: 3_000_000_000_000,
                    max_ticket_piconero: 2_500_000_000_000,
                    fee_cap_bps: 35,
                    reputation_score: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_PROVIDER_SCORE,
                    last_quote_height: height,
                    metadata_root: manifest_hash("DEVNET-METADATA", &[HashPart::Str("lp-a")]),
                },
                LiquidityProvider {
                    provider_id: "monero-devnet-lp-b".to_string(),
                    status: LiquidityProviderStatus::Standby,
                    operator_commitment: manifest_hash("DEVNET-LP", &[HashPart::Str("b")]),
                    reserve_commitment_root: manifest_hash(
                        "DEVNET-LP-RESERVE",
                        &[HashPart::Str("b")],
                    ),
                    settlement_address_commitment: manifest_hash(
                        "DEVNET-SETTLEMENT-ADDRESS",
                        &[HashPart::Str("b")],
                    ),
                    available_liquidity_piconero: 12_000_000_000_000,
                    locked_liquidity_piconero: 500_000_000_000,
                    max_ticket_piconero: 1_000_000_000_000,
                    fee_cap_bps: 40,
                    reputation_score: 8_000,
                    last_quote_height: height - 1,
                    metadata_root: manifest_hash("DEVNET-METADATA", &[HashPart::Str("lp-b")]),
                },
            ],
            fee_caps: vec![FeeCap {
                cap_id: "monero-devnet-default-fee-cap".to_string(),
                lane_id: "monero-devnet-standard-exit".to_string(),
                user_fee_bps: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MAX_USER_FEE_BPS,
                provider_fee_bps: MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MAX_PROVIDER_FEE_BPS,
                sponsor_fee_piconero:
                    MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_MAX_SPONSOR_FEE_PICONERO,
                effective_height: height,
                expires_height: height + 720,
                oracle_root: manifest_hash("DEVNET-FEE-ORACLE", &[HashPart::Str("default")]),
                metadata_root: manifest_hash("DEVNET-METADATA", &[HashPart::Str("fee-cap")]),
            }],
            privacy_boundaries: vec![PrivacyDisclosureBoundary {
                boundary_id: "monero-devnet-reserve-proof-boundary".to_string(),
                kind: PrivacyBoundaryKind::ReserveProof,
                subject_commitment: manifest_hash("DEVNET-SUBJECT", &[HashPart::Str("reserve")]),
                allowed_viewer_root: manifest_hash("DEVNET-VIEWERS", &[HashPart::Str("auditors")]),
                disclosed_field_root: manifest_hash(
                    "DEVNET-DISCLOSED-FIELDS",
                    &[HashPart::Str("reserve-proof")],
                ),
                retention_blocks:
                    MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_DISCLOSURE_RETENTION_BLOCKS,
                opened_height: height,
                expires_height: height
                    + MONERO_BRIDGE_RUNTIME_MANIFEST_DEFAULT_DISCLOSURE_RETENTION_BLOCKS,
                revocation_root: empty.clone(),
                audit_receipt_root: empty,
                metadata_root: manifest_hash(
                    "DEVNET-METADATA",
                    &[HashPart::Str("privacy-boundary")],
                ),
            }],
            runtime_invariants: vec![
                RuntimeInvariant {
                    invariant_id: "monero-devnet-header-freshness".to_string(),
                    kind: RuntimeInvariantKind::HeaderFreshness,
                    status: RuntimeInvariantStatus::Enforced,
                    scope_root: manifest_hash(
                        "DEVNET-INVARIANT-SCOPE",
                        &[HashPart::Str("headers")],
                    ),
                    threshold_root: manifest_hash(
                        "DEVNET-INVARIANT-THRESHOLD",
                        &[HashPart::Str("max-header-lag")],
                    ),
                    observation_root: manifest_hash(
                        "DEVNET-INVARIANT-OBSERVATION",
                        &[HashPart::Str("headers")],
                    ),
                    response_root: manifest_hash(
                        "DEVNET-INVARIANT-RESPONSE",
                        &[HashPart::Str("pause-withdrawals")],
                    ),
                    opened_height: height,
                    last_checked_height: height,
                    breach_count: 0,
                    metadata_root: manifest_hash(
                        "DEVNET-METADATA",
                        &[HashPart::Str("header-freshness-invariant")],
                    ),
                },
                RuntimeInvariant {
                    invariant_id: "monero-devnet-reserve-coverage".to_string(),
                    kind: RuntimeInvariantKind::ReserveCoverage,
                    status: RuntimeInvariantStatus::Monitoring,
                    scope_root: manifest_hash(
                        "DEVNET-INVARIANT-SCOPE",
                        &[HashPart::Str("reserve")],
                    ),
                    threshold_root: manifest_hash(
                        "DEVNET-INVARIANT-THRESHOLD",
                        &[HashPart::Str("reserve-coverage")],
                    ),
                    observation_root: manifest_hash(
                        "DEVNET-INVARIANT-OBSERVATION",
                        &[HashPart::Str("reserve")],
                    ),
                    response_root: manifest_hash(
                        "DEVNET-INVARIANT-RESPONSE",
                        &[HashPart::Str("throttle-liquidity")],
                    ),
                    opened_height: height,
                    last_checked_height: height,
                    breach_count: 0,
                    metadata_root: manifest_hash(
                        "DEVNET-METADATA",
                        &[HashPart::Str("reserve-coverage-invariant")],
                    ),
                },
            ],
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> MoneroBridgeRuntimeManifestResult<()> {
        self.config.validate()?;
        require_unique(
            "header source",
            self.header_sources
                .iter()
                .map(|source| source.source_id.as_str()),
        )?;
        require_unique(
            "reorg window",
            self.reorg_windows
                .iter()
                .map(|window| window.window_id.as_str()),
        )?;
        require_unique(
            "withdrawal batch",
            self.withdrawal_batches
                .iter()
                .map(|batch| batch.batch_id.as_str()),
        )?;
        require_unique(
            "reserve attestation",
            self.reserve_attestations
                .iter()
                .map(|attestation| attestation.attestation_id.as_str()),
        )?;
        require_unique(
            "watchtower mesh",
            self.watchtower_meshes
                .iter()
                .map(|mesh| mesh.mesh_id.as_str()),
        )?;
        require_unique(
            "emergency exit lane",
            self.emergency_exit_lanes
                .iter()
                .map(|lane| lane.lane_id.as_str()),
        )?;
        require_unique(
            "liquidity provider",
            self.liquidity_providers
                .iter()
                .map(|provider| provider.provider_id.as_str()),
        )?;
        require_unique(
            "fee cap",
            self.fee_caps.iter().map(|cap| cap.cap_id.as_str()),
        )?;
        require_unique(
            "privacy boundary",
            self.privacy_boundaries
                .iter()
                .map(|boundary| boundary.boundary_id.as_str()),
        )?;
        require_unique(
            "runtime invariant",
            self.runtime_invariants
                .iter()
                .map(|invariant| invariant.invariant_id.as_str()),
        )?;
        for source in &self.header_sources {
            source.validate()?;
            if source.header_tip_height + self.config.max_header_lag_blocks < self.height {
                return Err(format!(
                    "header source {} exceeds max lag",
                    source.source_id
                ));
            }
        }
        for window in &self.reorg_windows {
            window.validate()?;
        }
        for batch in &self.withdrawal_batches {
            batch.validate()?;
            if batch.max_proof_count > self.config.withdrawal_batch_limit {
                return Err(format!(
                    "withdrawal batch {} exceeds configured limit",
                    batch.batch_id
                ));
            }
        }
        for attestation in &self.reserve_attestations {
            attestation.validate()?;
            if attestation.coverage_bps < self.config.min_reserve_coverage_bps {
                return Err(format!(
                    "reserve attestation {} below coverage floor",
                    attestation.attestation_id
                ));
            }
        }
        for mesh in &self.watchtower_meshes {
            mesh.validate()?;
        }
        for lane in &self.emergency_exit_lanes {
            lane.validate()?;
        }
        for provider in &self.liquidity_providers {
            provider.validate()?;
            if provider.fee_cap_bps > self.config.max_provider_fee_bps {
                return Err(format!(
                    "liquidity provider {} exceeds provider fee cap",
                    provider.provider_id
                ));
            }
        }
        for cap in &self.fee_caps {
            cap.validate()?;
            if cap.user_fee_bps > self.config.max_user_fee_bps {
                return Err(format!("fee cap {} exceeds user fee ceiling", cap.cap_id));
            }
            if cap.provider_fee_bps > self.config.max_provider_fee_bps {
                return Err(format!(
                    "fee cap {} exceeds provider fee ceiling",
                    cap.cap_id
                ));
            }
            if cap.sponsor_fee_piconero > self.config.max_sponsor_fee_piconero {
                return Err(format!(
                    "fee cap {} exceeds sponsor fee ceiling",
                    cap.cap_id
                ));
            }
        }
        for boundary in &self.privacy_boundaries {
            boundary.validate()?;
            if boundary.retention_blocks > self.config.disclosure_retention_blocks {
                return Err(format!(
                    "privacy boundary {} exceeds disclosure retention",
                    boundary.boundary_id
                ));
            }
        }
        for invariant in &self.runtime_invariants {
            invariant.validate()?;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> MoneroBridgeRuntimeManifestResult<()> {
        self.height = height;
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> MoneroBridgeRuntimeManifestResult<()> {
        self.set_height(height)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            header_source_root: root_for_records(
                "HEADER-SOURCES",
                self.header_sources
                    .iter()
                    .map(HeaderSource::public_record)
                    .collect(),
            ),
            reorg_window_root: root_for_records(
                "REORG-WINDOWS",
                self.reorg_windows
                    .iter()
                    .map(ReorgWindow::public_record)
                    .collect(),
            ),
            withdrawal_batch_root: root_for_records(
                "WITHDRAWAL-BATCHES",
                self.withdrawal_batches
                    .iter()
                    .map(WithdrawalProofBatch::public_record)
                    .collect(),
            ),
            reserve_attestation_root: root_for_records(
                "RESERVE-ATTESTATIONS",
                self.reserve_attestations
                    .iter()
                    .map(ReserveAttestation::public_record)
                    .collect(),
            ),
            watchtower_mesh_root: root_for_records(
                "WATCHTOWER-MESHES",
                self.watchtower_meshes
                    .iter()
                    .map(WatchtowerMesh::public_record)
                    .collect(),
            ),
            emergency_exit_lane_root: root_for_records(
                "EMERGENCY-EXIT-LANES",
                self.emergency_exit_lanes
                    .iter()
                    .map(EmergencyExitLane::public_record)
                    .collect(),
            ),
            liquidity_provider_root: root_for_records(
                "LIQUIDITY-PROVIDERS",
                self.liquidity_providers
                    .iter()
                    .map(LiquidityProvider::public_record)
                    .collect(),
            ),
            fee_cap_root: root_for_records(
                "FEE-CAPS",
                self.fee_caps.iter().map(FeeCap::public_record).collect(),
            ),
            privacy_boundary_root: root_for_records(
                "PRIVACY-BOUNDARIES",
                self.privacy_boundaries
                    .iter()
                    .map(PrivacyDisclosureBoundary::public_record)
                    .collect(),
            ),
            runtime_invariant_root: root_for_records(
                "RUNTIME-INVARIANTS",
                self.runtime_invariants
                    .iter()
                    .map(RuntimeInvariant::public_record)
                    .collect(),
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            header_sources: self.header_sources.len() as u64,
            live_header_sources: self
                .header_sources
                .iter()
                .filter(|source| source.status.live())
                .count() as u64,
            reorg_windows: self.reorg_windows.len() as u64,
            withdrawal_batches: self.withdrawal_batches.len() as u64,
            live_withdrawal_batches: self
                .withdrawal_batches
                .iter()
                .filter(|batch| batch.status.live())
                .count() as u64,
            reserve_attestations: self.reserve_attestations.len() as u64,
            usable_reserve_attestations: self
                .reserve_attestations
                .iter()
                .filter(|attestation| attestation.status.usable())
                .count() as u64,
            watchtower_meshes: self.watchtower_meshes.len() as u64,
            emergency_exit_lanes: self.emergency_exit_lanes.len() as u64,
            live_emergency_exit_lanes: self
                .emergency_exit_lanes
                .iter()
                .filter(|lane| lane.status.live())
                .count() as u64,
            liquidity_providers: self.liquidity_providers.len() as u64,
            live_liquidity_providers: self
                .liquidity_providers
                .iter()
                .filter(|provider| provider.status.live())
                .count() as u64,
            fee_caps: self.fee_caps.len() as u64,
            privacy_boundaries: self.privacy_boundaries.len() as u64,
            runtime_invariants: self.runtime_invariants.len() as u64,
            live_runtime_invariants: self
                .runtime_invariants
                .iter()
                .filter(|invariant| invariant.status.live())
                .count() as u64,
            total_available_liquidity_piconero: self
                .liquidity_providers
                .iter()
                .map(|provider| provider.available_liquidity_piconero)
                .sum(),
            total_locked_liquidity_piconero: self
                .liquidity_providers
                .iter()
                .map(|provider| provider.locked_liquidity_piconero)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record["state_root"] = json!(root_from_record(&record));
        record
    }

    fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": MONERO_BRIDGE_RUNTIME_MANIFEST_PROTOCOL_VERSION,
            "public_record_schema": MONERO_BRIDGE_RUNTIME_MANIFEST_PUBLIC_RECORD_SCHEMA,
            "chain_id": CHAIN_ID,
            "height": self.height.to_string(),
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.root(),
            "counters": counters.public_record(),
            "counters_root": counters.root(),
            "header_sources": sorted_records(self.header_sources.iter().map(HeaderSource::public_record).collect()),
            "reorg_windows": sorted_records(self.reorg_windows.iter().map(ReorgWindow::public_record).collect()),
            "withdrawal_batches": sorted_records(self.withdrawal_batches.iter().map(WithdrawalProofBatch::public_record).collect()),
            "reserve_attestations": sorted_records(self.reserve_attestations.iter().map(ReserveAttestation::public_record).collect()),
            "watchtower_meshes": sorted_records(self.watchtower_meshes.iter().map(WatchtowerMesh::public_record).collect()),
            "emergency_exit_lanes": sorted_records(self.emergency_exit_lanes.iter().map(EmergencyExitLane::public_record).collect()),
            "liquidity_providers": sorted_records(self.liquidity_providers.iter().map(LiquidityProvider::public_record).collect()),
            "fee_caps": sorted_records(self.fee_caps.iter().map(FeeCap::public_record).collect()),
            "privacy_boundaries": sorted_records(self.privacy_boundaries.iter().map(PrivacyDisclosureBoundary::public_record).collect()),
            "runtime_invariants": sorted_records(self.runtime_invariants.iter().map(RuntimeInvariant::public_record).collect()),
        })
    }
}

pub fn root_from_record(record: &Value) -> String {
    manifest_hash("STATE", &[HashPart::Json(record)])
}

pub fn devnet() -> MoneroBridgeRuntimeManifestResult<State> {
    State::devnet()
}

fn manifest_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("MONERO-BRIDGE-RUNTIME-MANIFEST-{domain}"),
        parts,
        32,
    )
}

fn root_for_records(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!("MONERO-BRIDGE-RUNTIME-MANIFEST-{domain}"),
        &sorted_records(records),
    )
}

fn empty_root() -> String {
    merkle_root(ROOT_EMPTY, &[])
}

fn sorted_records(records: Vec<Value>) -> Vec<Value> {
    let mut keyed = BTreeMap::new();
    for (index, record) in records.into_iter().enumerate() {
        let key = manifest_hash(
            "SORT-KEY",
            &[HashPart::Str(&index.to_string()), HashPart::Json(&record)],
        );
        keyed.insert(key, record);
    }
    keyed.into_values().collect()
}

fn require_non_empty(name: &str, value: &str) -> MoneroBridgeRuntimeManifestResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

fn require_positive(name: &str, value: u64) -> MoneroBridgeRuntimeManifestResult<()> {
    if value == 0 {
        return Err(format!("{name} must be positive"));
    }
    Ok(())
}

fn require_bps(
    name: &str,
    value: u64,
    allow_equal_max: bool,
) -> MoneroBridgeRuntimeManifestResult<()> {
    if allow_equal_max {
        if value > MONERO_BRIDGE_RUNTIME_MANIFEST_MAX_BPS {
            return Err(format!("{name} exceeds basis point maximum"));
        }
    } else if value <= MONERO_BRIDGE_RUNTIME_MANIFEST_MAX_BPS {
        return Err(format!("{name} must exceed one hundred percent coverage"));
    }
    Ok(())
}

fn require_ordered_window(
    soft: u64,
    hard: u64,
    emergency: u64,
) -> MoneroBridgeRuntimeManifestResult<()> {
    if soft >= hard {
        return Err("soft reorg window must be below hard reorg window".to_string());
    }
    if hard >= emergency {
        return Err("hard reorg window must be below emergency reorg window".to_string());
    }
    Ok(())
}

fn require_unique<'a, I>(name: &str, ids: I) -> MoneroBridgeRuntimeManifestResult<()>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut seen = BTreeSet::new();
    for id in ids {
        if id.trim().is_empty() {
            return Err(format!("{name} id cannot be empty"));
        }
        if !seen.insert(id.to_string()) {
            return Err(format!("duplicate {name} id: {id}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_manifest_validates_and_roots_are_stable() {
        let state = State::devnet().map_err(|err| format!("devnet failed: {err}"));
        assert!(state.is_ok());
        let state = match state {
            Ok(state) => state,
            Err(err) => {
                assert!(err.is_empty());
                return;
            }
        };
        assert_eq!(state.height, MONERO_BRIDGE_RUNTIME_MANIFEST_DEVNET_HEIGHT);
        assert_eq!(
            state.state_root(),
            root_from_record(&state.public_record_without_root())
        );
        assert_eq!(
            state.public_record()["protocol_version"],
            MONERO_BRIDGE_RUNTIME_MANIFEST_PROTOCOL_VERSION
        );
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let state = State::devnet().map_err(|err| format!("devnet failed: {err}"));
        assert!(state.is_ok());
        let mut state = match state {
            Ok(state) => state,
            Err(err) => {
                assert!(err.is_empty());
                return;
            }
        };
        let duplicate = state.header_sources.first().cloned();
        if let Some(source) = duplicate {
            state.header_sources.push(source);
        }
        let result = state.validate();
        assert!(result.is_err());
    }
}
