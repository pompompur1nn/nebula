use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroAdaptiveFeePrivacyRouterResult<T> = Result<T, String>;

pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_PROTOCOL_VERSION: &str =
    "nebula-monero-adaptive-fee-privacy-router-v1";
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_SCHEMA_VERSION: u64 = 1;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEVNET_HEIGHT: u64 = 1_536;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_FEE_ORACLE_SCHEME: &str =
    "monero-fee-bucket-oracle-v1";
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DECOY_SCHEME: &str =
    "decoy-preserving-route-choice-v1";
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_SPONSOR_SCHEME: &str =
    "low-fee-private-sponsor-routing-v1";
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_SCAN_HINT_SCHEME: &str =
    "stealth-address-scan-hint-commitment-v1";
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_REORG_SCHEME: &str = "reorg-safe-exit-timing-v1";
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_PQ_WATCHER_SCHEME: &str =
    "ml-dsa-65+slh-dsa-shake-128s-watchtower-attestation-v1";
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_EPOCH_BLOCKS: u64 = 24;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_BUCKET_TTL_BLOCKS: u64 = 96;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_ROUTE_TTL_BLOCKS: u64 = 72;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_MIN_DECOYS: u64 = 16;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_MIN_PRIVACY_SCORE: u64 = 7_500;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_MIN_WATCHERS: u64 = 2;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_REORG_DEPTH: u64 = 12;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_EXIT_HOLD_BLOCKS: u64 = 18;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_MAX_FEE_BPS: u64 = 45;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_LOW_FEE_TARGET_BPS: u64 = 8;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_SPONSOR_REBATE_BPS: u64 = 8_500;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_SCAN_HINT_TTL_BLOCKS: u64 = 180;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 120;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_BPS: u64 = 10_000;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_BUCKETS: usize = 4_096;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_ROUTES: usize = 65_536;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_SPONSORSHIPS: usize = 32_768;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_SCAN_HINTS: usize = 131_072;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_EXIT_WINDOWS: usize = 65_536;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_ATTESTATIONS: usize = 262_144;
pub const MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_EVENTS: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdaptiveFeeBucketKind {
    Dust,
    Economy,
    Standard,
    Fast,
    Priority,
    Emergency,
}

impl AdaptiveFeeBucketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dust => "dust",
            Self::Economy => "economy",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::Priority => "priority",
            Self::Emergency => "emergency",
        }
    }

    pub fn urgency_score(self) -> u64 {
        match self {
            Self::Dust => 100,
            Self::Economy => 250,
            Self::Standard => 500,
            Self::Fast => 750,
            Self::Priority => 900,
            Self::Emergency => 1_000,
        }
    }

    pub fn default_fee_bps(self, config: &MoneroAdaptiveFeePrivacyRouterConfig) -> u64 {
        match self {
            Self::Dust => config.low_fee_target_bps.saturating_div(2).max(1),
            Self::Economy => config.low_fee_target_bps,
            Self::Standard => config.max_fee_bps.saturating_mul(45).saturating_div(100),
            Self::Fast => config.max_fee_bps.saturating_mul(70).saturating_div(100),
            Self::Priority => config.max_fee_bps,
            Self::Emergency => config.max_fee_bps.saturating_add(20),
        }
        .min(MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_BPS)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyRouteIntent {
    WalletTransfer,
    MoneroExit,
    PrivateSwap,
    ContractCall,
    LiquidityRebalance,
    Recovery,
    ForcedInclusion,
}

impl PrivacyRouteIntent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletTransfer => "wallet_transfer",
            Self::MoneroExit => "monero_exit",
            Self::PrivateSwap => "private_swap",
            Self::ContractCall => "contract_call",
            Self::LiquidityRebalance => "liquidity_rebalance",
            Self::Recovery => "recovery",
            Self::ForcedInclusion => "forced_inclusion",
        }
    }

    pub fn requires_scan_hint(self) -> bool {
        matches!(
            self,
            Self::WalletTransfer | Self::MoneroExit | Self::Recovery | Self::ForcedInclusion
        )
    }

    pub fn exit_like(self) -> bool {
        matches!(
            self,
            Self::MoneroExit | Self::Recovery | Self::ForcedInclusion
        )
    }

    pub fn default_bucket(self) -> AdaptiveFeeBucketKind {
        match self {
            Self::WalletTransfer => AdaptiveFeeBucketKind::Economy,
            Self::PrivateSwap => AdaptiveFeeBucketKind::Standard,
            Self::ContractCall => AdaptiveFeeBucketKind::Standard,
            Self::LiquidityRebalance => AdaptiveFeeBucketKind::Fast,
            Self::MoneroExit => AdaptiveFeeBucketKind::Fast,
            Self::Recovery => AdaptiveFeeBucketKind::Priority,
            Self::ForcedInclusion => AdaptiveFeeBucketKind::Emergency,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyRouteStatus {
    Requested,
    Quoted,
    Sponsored,
    ScanHintPublished,
    WatcherCertified,
    ExitWindowOpen,
    ReorgHeld,
    Routed,
    Settled,
    Cancelled,
    Expired,
    Disputed,
}

impl PrivacyRouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Quoted => "quoted",
            Self::Sponsored => "sponsored",
            Self::ScanHintPublished => "scan_hint_published",
            Self::WatcherCertified => "watcher_certified",
            Self::ExitWindowOpen => "exit_window_open",
            Self::ReorgHeld => "reorg_held",
            Self::Routed => "routed",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Requested
                | Self::Quoted
                | Self::Sponsored
                | Self::ScanHintPublished
                | Self::WatcherCertified
                | Self::ExitWindowOpen
                | Self::ReorgHeld
                | Self::Routed
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Cancelled | Self::Expired | Self::Disputed
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Offered,
    Reserved,
    Applied,
    Exhausted,
    Revoked,
    Expired,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanHintStatus {
    Pending,
    Published,
    Matched,
    FalsePositive,
    QuorumCertified,
    Disputed,
    Expired,
}

impl ScanHintStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Published => "published",
            Self::Matched => "matched",
            Self::FalsePositive => "false_positive",
            Self::QuorumCertified => "quorum_certified",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitTimingStatus {
    Planned,
    Holding,
    WatcherCertified,
    BroadcastReady,
    Broadcast,
    Confirmed,
    Final,
    ReorgHeld,
    Cancelled,
}

impl ExitTimingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Holding => "holding",
            Self::WatcherCertified => "watcher_certified",
            Self::BroadcastReady => "broadcast_ready",
            Self::Broadcast => "broadcast",
            Self::Confirmed => "confirmed",
            Self::Final => "final",
            Self::ReorgHeld => "reorg_held",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqWatcherAttestationKind {
    FeeBucket,
    DecoySet,
    SponsorEligibility,
    ScanHint,
    ExitTiming,
    ReorgRisk,
}

impl PqWatcherAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeeBucket => "fee_bucket",
            Self::DecoySet => "decoy_set",
            Self::SponsorEligibility => "sponsor_eligibility",
            Self::ScanHint => "scan_hint",
            Self::ExitTiming => "exit_timing",
            Self::ReorgRisk => "reorg_risk",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqWatcherAttestationStatus {
    Submitted,
    Counted,
    Duplicate,
    Invalid,
    Expired,
    Slashed,
}

impl PqWatcherAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Counted => "counted",
            Self::Duplicate => "duplicate",
            Self::Invalid => "invalid",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoneroAdaptiveFeePrivacyRouterConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub epoch_blocks: u64,
    pub bucket_ttl_blocks: u64,
    pub route_ttl_blocks: u64,
    pub min_decoys: u64,
    pub min_privacy_score: u64,
    pub min_watchers: u64,
    pub reorg_depth: u64,
    pub exit_hold_blocks: u64,
    pub max_fee_bps: u64,
    pub low_fee_target_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub scan_hint_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub fee_oracle_scheme: String,
    pub decoy_scheme: String,
    pub sponsor_scheme: String,
    pub scan_hint_scheme: String,
    pub reorg_scheme: String,
    pub pq_watcher_scheme: String,
}

impl MoneroAdaptiveFeePrivacyRouterConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_SCHEMA_VERSION,
            monero_network: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MONERO_NETWORK.to_string(),
            asset_id: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_ASSET_ID.to_string(),
            fee_asset_id: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_FEE_ASSET_ID.to_string(),
            epoch_blocks: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_EPOCH_BLOCKS,
            bucket_ttl_blocks: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_BUCKET_TTL_BLOCKS,
            route_ttl_blocks: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_ROUTE_TTL_BLOCKS,
            min_decoys: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_MIN_DECOYS,
            min_privacy_score: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_MIN_PRIVACY_SCORE,
            min_watchers: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_MIN_WATCHERS,
            reorg_depth: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_REORG_DEPTH,
            exit_hold_blocks: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_EXIT_HOLD_BLOCKS,
            max_fee_bps: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_MAX_FEE_BPS,
            low_fee_target_bps: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_LOW_FEE_TARGET_BPS,
            sponsor_rebate_bps: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_SPONSOR_REBATE_BPS,
            scan_hint_ttl_blocks: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_SCAN_HINT_TTL_BLOCKS,
            attestation_ttl_blocks:
                MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_ATTESTATION_TTL_BLOCKS,
            min_pq_security_bits: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEFAULT_MIN_PQ_SECURITY_BITS,
            fee_oracle_scheme: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_FEE_ORACLE_SCHEME.to_string(),
            decoy_scheme: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DECOY_SCHEME.to_string(),
            sponsor_scheme: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_SPONSOR_SCHEME.to_string(),
            scan_hint_scheme: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_SCAN_HINT_SCHEME.to_string(),
            reorg_scheme: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_REORG_SCHEME.to_string(),
            pq_watcher_scheme: MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_PQ_WATCHER_SCHEME.to_string(),
        }
    }

    pub fn validate(&self) -> MoneroAdaptiveFeePrivacyRouterResult<()> {
        ensure_non_empty(&self.protocol_version, "protocol version")?;
        ensure_non_empty(&self.monero_network, "monero network")?;
        ensure_non_empty(&self.asset_id, "asset id")?;
        ensure_non_empty(&self.fee_asset_id, "fee asset id")?;
        ensure_non_zero(self.epoch_blocks, "epoch blocks")?;
        ensure_non_zero(self.bucket_ttl_blocks, "bucket ttl blocks")?;
        ensure_non_zero(self.route_ttl_blocks, "route ttl blocks")?;
        ensure_non_zero(self.min_decoys, "minimum decoys")?;
        ensure_non_zero(self.min_privacy_score, "minimum privacy score")?;
        ensure_non_zero(self.min_watchers, "minimum watchers")?;
        ensure_non_zero(self.reorg_depth, "reorg depth")?;
        ensure_non_zero(self.exit_hold_blocks, "exit hold blocks")?;
        ensure_bps(self.max_fee_bps, "maximum fee bps")?;
        ensure_bps(self.low_fee_target_bps, "low fee target bps")?;
        ensure_bps(self.sponsor_rebate_bps, "sponsor rebate bps")?;
        if self.low_fee_target_bps > self.max_fee_bps {
            return Err("low fee target cannot exceed maximum fee".to_string());
        }
        ensure_non_zero(self.scan_hint_ttl_blocks, "scan hint ttl blocks")?;
        ensure_non_zero(self.attestation_ttl_blocks, "attestation ttl blocks")?;
        if self.min_pq_security_bits < 128 {
            return Err("minimum pq security bits must be at least 128".to_string());
        }
        ensure_non_empty(&self.fee_oracle_scheme, "fee oracle scheme")?;
        ensure_non_empty(&self.decoy_scheme, "decoy scheme")?;
        ensure_non_empty(&self.sponsor_scheme, "sponsor scheme")?;
        ensure_non_empty(&self.scan_hint_scheme, "scan hint scheme")?;
        ensure_non_empty(&self.reorg_scheme, "reorg scheme")?;
        ensure_non_empty(&self.pq_watcher_scheme, "pq watcher scheme")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "epoch_blocks": self.epoch_blocks,
            "bucket_ttl_blocks": self.bucket_ttl_blocks,
            "route_ttl_blocks": self.route_ttl_blocks,
            "min_decoys": self.min_decoys,
            "min_privacy_score": self.min_privacy_score,
            "min_watchers": self.min_watchers,
            "reorg_depth": self.reorg_depth,
            "exit_hold_blocks": self.exit_hold_blocks,
            "max_fee_bps": self.max_fee_bps,
            "low_fee_target_bps": self.low_fee_target_bps,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "scan_hint_ttl_blocks": self.scan_hint_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "fee_oracle_scheme": self.fee_oracle_scheme,
            "decoy_scheme": self.decoy_scheme,
            "sponsor_scheme": self.sponsor_scheme,
            "scan_hint_scheme": self.scan_hint_scheme,
            "reorg_scheme": self.reorg_scheme,
            "pq_watcher_scheme": self.pq_watcher_scheme,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeOracleBucket {
    pub bucket_id: String,
    pub kind: AdaptiveFeeBucketKind,
    pub epoch: u64,
    pub first_height: u64,
    pub last_height: u64,
    pub sample_count: u64,
    pub median_fee_per_kb: u64,
    pub p90_fee_per_kb: u64,
    pub p99_fee_per_kb: u64,
    pub recommended_fee_per_kb: u64,
    pub max_fee_bps: u64,
    pub low_fee_eligible: bool,
    pub pressure_score_bps: u64,
    pub publisher_set_root: String,
    pub sample_root: String,
    pub watcher_attestation_root: String,
    pub expires_at_height: u64,
}

impl FeeOracleBucket {
    pub fn new(
        kind: AdaptiveFeeBucketKind,
        epoch: u64,
        first_height: u64,
        median_fee_per_kb: u64,
        p90_fee_per_kb: u64,
        p99_fee_per_kb: u64,
        config: &MoneroAdaptiveFeePrivacyRouterConfig,
    ) -> Self {
        let last_height = first_height.saturating_add(config.epoch_blocks.saturating_sub(1));
        let recommended_fee_per_kb = median_fee_per_kb
            .saturating_mul(60)
            .saturating_add(p90_fee_per_kb.saturating_mul(30))
            .saturating_add(p99_fee_per_kb.saturating_mul(10))
            .saturating_div(100)
            .max(1);
        let bucket_id = fee_privacy_hash(
            "MONERO-ADAPTIVE-FEE-BUCKET-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Int(epoch as i128),
                HashPart::Int(first_height as i128),
                HashPart::Int(recommended_fee_per_kb as i128),
            ],
        );
        Self {
            bucket_id,
            kind,
            epoch,
            first_height,
            last_height,
            sample_count: 0,
            median_fee_per_kb,
            p90_fee_per_kb,
            p99_fee_per_kb,
            recommended_fee_per_kb,
            max_fee_bps: kind.default_fee_bps(config),
            low_fee_eligible: matches!(
                kind,
                AdaptiveFeeBucketKind::Dust | AdaptiveFeeBucketKind::Economy
            ),
            pressure_score_bps: kind.urgency_score().saturating_mul(10),
            publisher_set_root: empty_root("MONERO-ADAPTIVE-FEE-BUCKET-PUBLISHERS"),
            sample_root: empty_root("MONERO-ADAPTIVE-FEE-BUCKET-SAMPLES"),
            watcher_attestation_root: empty_root("MONERO-ADAPTIVE-FEE-BUCKET-WATCHERS"),
            expires_at_height: last_height.saturating_add(config.bucket_ttl_blocks),
        }
    }

    pub fn with_samples(mut self, sample_count: u64, sample_root: impl Into<String>) -> Self {
        self.sample_count = sample_count;
        self.sample_root = sample_root.into();
        self
    }

    pub fn validate(
        &self,
        config: &MoneroAdaptiveFeePrivacyRouterConfig,
    ) -> MoneroAdaptiveFeePrivacyRouterResult<()> {
        ensure_non_empty(&self.bucket_id, "fee bucket id")?;
        ensure_non_zero(self.sample_count, "fee bucket sample count")?;
        ensure_ordered_heights(self.first_height, self.last_height, "fee bucket")?;
        ensure_non_zero(self.median_fee_per_kb, "median fee per kb")?;
        ensure_non_zero(self.p90_fee_per_kb, "p90 fee per kb")?;
        ensure_non_zero(self.p99_fee_per_kb, "p99 fee per kb")?;
        ensure_non_zero(self.recommended_fee_per_kb, "recommended fee per kb")?;
        ensure_bps(self.max_fee_bps, "fee bucket max fee bps")?;
        ensure_bps(self.pressure_score_bps, "fee bucket pressure score")?;
        ensure_non_empty(&self.publisher_set_root, "fee bucket publisher root")?;
        ensure_non_empty(&self.sample_root, "fee bucket sample root")?;
        ensure_non_empty(&self.watcher_attestation_root, "fee bucket watcher root")?;
        if self.expires_at_height < self.last_height {
            return Err("fee bucket expiry cannot be before last height".to_string());
        }
        if self.max_fee_bps > config.max_fee_bps.saturating_add(20) {
            return Err("fee bucket max fee exceeds configured emergency ceiling".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "bucket_id": self.bucket_id,
            "kind": self.kind.as_str(),
            "epoch": self.epoch,
            "first_height": self.first_height,
            "last_height": self.last_height,
            "sample_count": self.sample_count,
            "median_fee_per_kb": self.median_fee_per_kb,
            "p90_fee_per_kb": self.p90_fee_per_kb,
            "p99_fee_per_kb": self.p99_fee_per_kb,
            "recommended_fee_per_kb": self.recommended_fee_per_kb,
            "max_fee_bps": self.max_fee_bps,
            "low_fee_eligible": self.low_fee_eligible,
            "pressure_score_bps": self.pressure_score_bps,
            "publisher_set_root": self.publisher_set_root,
            "sample_root": self.sample_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        fee_privacy_json_root("MONERO-ADAPTIVE-FEE-BUCKET", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecoyRouteChoice {
    pub route_id: String,
    pub request_commitment: String,
    pub intent: PrivacyRouteIntent,
    pub status: PrivacyRouteStatus,
    pub fee_bucket_id: String,
    pub sponsor_id: Option<String>,
    pub scan_hint_id: Option<String>,
    pub exit_window_id: Option<String>,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub amount_bucket: String,
    pub fee_cap_bps: u64,
    pub quoted_fee_per_kb: u64,
    pub decoy_count: u64,
    pub decoy_set_root: String,
    pub decoy_entropy_root: String,
    pub privacy_score: u64,
    pub route_preference_commitment: String,
    pub nullifier_commitment: String,
    pub watcher_quorum: u64,
    pub pq_attestation_root: String,
}

impl DecoyRouteChoice {
    pub fn new(
        request_commitment: impl Into<String>,
        intent: PrivacyRouteIntent,
        fee_bucket_id: impl Into<String>,
        requested_at_height: u64,
        amount_bucket: impl Into<String>,
        config: &MoneroAdaptiveFeePrivacyRouterConfig,
    ) -> Self {
        let request_commitment = request_commitment.into();
        let fee_bucket_id = fee_bucket_id.into();
        let amount_bucket = amount_bucket.into();
        let route_id = fee_privacy_hash(
            "MONERO-ADAPTIVE-FEE-ROUTE-ID",
            &[
                HashPart::Str(&request_commitment),
                HashPart::Str(intent.as_str()),
                HashPart::Str(&fee_bucket_id),
                HashPart::Int(requested_at_height as i128),
            ],
        );
        let route_preference_commitment = fee_privacy_hash(
            "MONERO-ADAPTIVE-FEE-ROUTE-PREFERENCE",
            &[HashPart::Str(&route_id), HashPart::Str(&amount_bucket)],
        );
        let nullifier_commitment = fee_privacy_hash(
            "MONERO-ADAPTIVE-FEE-ROUTE-NULLIFIER",
            &[HashPart::Str(&request_commitment), HashPart::Str(&route_id)],
        );
        Self {
            route_id,
            request_commitment,
            intent,
            status: PrivacyRouteStatus::Requested,
            fee_bucket_id,
            sponsor_id: None,
            scan_hint_id: None,
            exit_window_id: None,
            requested_at_height,
            expires_at_height: requested_at_height.saturating_add(config.route_ttl_blocks),
            amount_bucket,
            fee_cap_bps: intent.default_bucket().default_fee_bps(config),
            quoted_fee_per_kb: 0,
            decoy_count: config.min_decoys,
            decoy_set_root: empty_root("MONERO-ADAPTIVE-FEE-ROUTE-DECOYS"),
            decoy_entropy_root: empty_root("MONERO-ADAPTIVE-FEE-ROUTE-ENTROPY"),
            privacy_score: config.min_privacy_score,
            route_preference_commitment,
            nullifier_commitment,
            watcher_quorum: 0,
            pq_attestation_root: empty_root("MONERO-ADAPTIVE-FEE-ROUTE-WATCHERS"),
        }
    }

    pub fn quote(mut self, quoted_fee_per_kb: u64, decoy_set_root: impl Into<String>) -> Self {
        self.quoted_fee_per_kb = quoted_fee_per_kb;
        self.decoy_set_root = decoy_set_root.into();
        self.status = PrivacyRouteStatus::Quoted;
        self
    }

    pub fn validate(
        &self,
        config: &MoneroAdaptiveFeePrivacyRouterConfig,
    ) -> MoneroAdaptiveFeePrivacyRouterResult<()> {
        ensure_non_empty(&self.route_id, "route id")?;
        ensure_non_empty(&self.request_commitment, "route request commitment")?;
        ensure_non_empty(&self.fee_bucket_id, "route fee bucket id")?;
        ensure_ordered_heights(
            self.requested_at_height,
            self.expires_at_height,
            "route ttl",
        )?;
        ensure_non_empty(&self.amount_bucket, "route amount bucket")?;
        ensure_bps(self.fee_cap_bps, "route fee cap bps")?;
        ensure_non_zero(self.quoted_fee_per_kb.max(1), "route quoted fee per kb")?;
        if self.decoy_count < config.min_decoys {
            return Err("route decoy count is below configured privacy floor".to_string());
        }
        if self.privacy_score < config.min_privacy_score {
            return Err("route privacy score is below configured floor".to_string());
        }
        ensure_non_empty(&self.decoy_set_root, "route decoy set root")?;
        ensure_non_empty(&self.decoy_entropy_root, "route decoy entropy root")?;
        ensure_non_empty(
            &self.route_preference_commitment,
            "route preference commitment",
        )?;
        ensure_non_empty(&self.nullifier_commitment, "route nullifier commitment")?;
        ensure_non_empty(&self.pq_attestation_root, "route pq attestation root")?;
        if self.status.terminal() && self.watcher_quorum < config.min_watchers {
            return Err("terminal route lacks watcher quorum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "route_id": self.route_id,
            "request_commitment": self.request_commitment,
            "intent": self.intent.as_str(),
            "status": self.status.as_str(),
            "fee_bucket_id": self.fee_bucket_id,
            "sponsor_id": self.sponsor_id,
            "scan_hint_id": self.scan_hint_id,
            "exit_window_id": self.exit_window_id,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "amount_bucket": self.amount_bucket,
            "fee_cap_bps": self.fee_cap_bps,
            "quoted_fee_per_kb": self.quoted_fee_per_kb,
            "decoy_count": self.decoy_count,
            "decoy_set_root": self.decoy_set_root,
            "decoy_entropy_root": self.decoy_entropy_root,
            "privacy_score": self.privacy_score,
            "route_preference_commitment": self.route_preference_commitment,
            "nullifier_commitment": self.nullifier_commitment,
            "watcher_quorum": self.watcher_quorum,
            "pq_attestation_root": self.pq_attestation_root,
        })
    }

    pub fn record_root(&self) -> String {
        fee_privacy_json_root("MONERO-ADAPTIVE-FEE-ROUTE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LowFeeSponsorshipRoute {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub route_id: String,
    pub status: SponsorshipStatus,
    pub reserved_fee_units: u64,
    pub max_rebate_bps: u64,
    pub privacy_budget_units: u64,
    pub sponsor_nullifier_root: String,
    pub eligibility_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeSponsorshipRoute {
    pub fn new(
        sponsor_commitment: impl Into<String>,
        route_id: impl Into<String>,
        reserved_fee_units: u64,
        reserved_at_height: u64,
        config: &MoneroAdaptiveFeePrivacyRouterConfig,
    ) -> Self {
        let sponsor_commitment = sponsor_commitment.into();
        let route_id = route_id.into();
        let sponsor_id = fee_privacy_hash(
            "MONERO-ADAPTIVE-FEE-SPONSOR-ID",
            &[
                HashPart::Str(&sponsor_commitment),
                HashPart::Str(&route_id),
                HashPart::Int(reserved_at_height as i128),
            ],
        );
        Self {
            sponsor_id,
            sponsor_commitment,
            route_id,
            status: SponsorshipStatus::Offered,
            reserved_fee_units,
            max_rebate_bps: config.sponsor_rebate_bps,
            privacy_budget_units: reserved_fee_units.saturating_mul(8),
            sponsor_nullifier_root: empty_root("MONERO-ADAPTIVE-FEE-SPONSOR-NULLIFIERS"),
            eligibility_root: empty_root("MONERO-ADAPTIVE-FEE-SPONSOR-ELIGIBILITY"),
            reserved_at_height,
            expires_at_height: reserved_at_height.saturating_add(config.route_ttl_blocks),
        }
    }

    pub fn validate(&self) -> MoneroAdaptiveFeePrivacyRouterResult<()> {
        ensure_non_empty(&self.sponsor_id, "sponsor id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsor commitment")?;
        ensure_non_empty(&self.route_id, "sponsor route id")?;
        ensure_non_zero(self.reserved_fee_units, "reserved fee units")?;
        ensure_bps(self.max_rebate_bps, "sponsor rebate bps")?;
        ensure_non_zero(self.privacy_budget_units, "sponsor privacy budget")?;
        ensure_non_empty(&self.sponsor_nullifier_root, "sponsor nullifier root")?;
        ensure_non_empty(&self.eligibility_root, "sponsor eligibility root")?;
        ensure_ordered_heights(
            self.reserved_at_height,
            self.expires_at_height,
            "sponsor ttl",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "route_id": self.route_id,
            "status": self.status.as_str(),
            "reserved_fee_units": self.reserved_fee_units,
            "max_rebate_bps": self.max_rebate_bps,
            "privacy_budget_units": self.privacy_budget_units,
            "sponsor_nullifier_root": self.sponsor_nullifier_root,
            "eligibility_root": self.eligibility_root,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn record_root(&self) -> String {
        fee_privacy_json_root("MONERO-ADAPTIVE-FEE-SPONSOR", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StealthAddressScanHint {
    pub hint_id: String,
    pub route_id: String,
    pub status: ScanHintStatus,
    pub view_tag_prefix: String,
    pub stealth_address_commitment: String,
    pub encrypted_scan_hint_root: String,
    pub subaddress_domain_root: String,
    pub hint_epoch: u64,
    pub published_at_height: u64,
    pub expires_at_height: u64,
    pub watcher_quorum: u64,
    pub false_positive_budget: u64,
}

impl StealthAddressScanHint {
    pub fn new(
        route_id: impl Into<String>,
        view_tag_prefix: impl Into<String>,
        stealth_address_commitment: impl Into<String>,
        published_at_height: u64,
        config: &MoneroAdaptiveFeePrivacyRouterConfig,
    ) -> Self {
        let route_id = route_id.into();
        let view_tag_prefix = view_tag_prefix.into();
        let stealth_address_commitment = stealth_address_commitment.into();
        let hint_epoch = epoch_for_height(published_at_height, config.epoch_blocks);
        let hint_id = fee_privacy_hash(
            "MONERO-ADAPTIVE-FEE-SCAN-HINT-ID",
            &[
                HashPart::Str(&route_id),
                HashPart::Str(&view_tag_prefix),
                HashPart::Str(&stealth_address_commitment),
                HashPart::Int(published_at_height as i128),
            ],
        );
        Self {
            hint_id,
            route_id,
            status: ScanHintStatus::Pending,
            view_tag_prefix,
            stealth_address_commitment,
            encrypted_scan_hint_root: empty_root("MONERO-ADAPTIVE-FEE-SCAN-HINT-CIPHERTEXT"),
            subaddress_domain_root: empty_root("MONERO-ADAPTIVE-FEE-SCAN-HINT-SUBADDRESS"),
            hint_epoch,
            published_at_height,
            expires_at_height: published_at_height.saturating_add(config.scan_hint_ttl_blocks),
            watcher_quorum: 0,
            false_positive_budget: config.min_decoys.saturating_mul(2),
        }
    }

    pub fn validate(&self) -> MoneroAdaptiveFeePrivacyRouterResult<()> {
        ensure_non_empty(&self.hint_id, "scan hint id")?;
        ensure_non_empty(&self.route_id, "scan hint route id")?;
        ensure_non_empty(&self.view_tag_prefix, "scan hint view tag prefix")?;
        ensure_non_empty(
            &self.stealth_address_commitment,
            "scan hint stealth address commitment",
        )?;
        ensure_non_empty(&self.encrypted_scan_hint_root, "encrypted scan hint root")?;
        ensure_non_empty(
            &self.subaddress_domain_root,
            "scan hint subaddress domain root",
        )?;
        ensure_ordered_heights(
            self.published_at_height,
            self.expires_at_height,
            "scan hint ttl",
        )?;
        ensure_non_zero(
            self.false_positive_budget,
            "scan hint false positive budget",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "hint_id": self.hint_id,
            "route_id": self.route_id,
            "status": self.status.as_str(),
            "view_tag_prefix": self.view_tag_prefix,
            "stealth_address_commitment": self.stealth_address_commitment,
            "encrypted_scan_hint_root": self.encrypted_scan_hint_root,
            "subaddress_domain_root": self.subaddress_domain_root,
            "hint_epoch": self.hint_epoch,
            "published_at_height": self.published_at_height,
            "expires_at_height": self.expires_at_height,
            "watcher_quorum": self.watcher_quorum,
            "false_positive_budget": self.false_positive_budget,
        })
    }

    pub fn record_root(&self) -> String {
        fee_privacy_json_root("MONERO-ADAPTIVE-FEE-SCAN-HINT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReorgSafeExitTiming {
    pub exit_window_id: String,
    pub route_id: String,
    pub status: ExitTimingStatus,
    pub anchor_block_hash: String,
    pub anchor_height: u64,
    pub earliest_broadcast_height: u64,
    pub safe_finality_height: u64,
    pub reorg_depth: u64,
    pub hold_blocks: u64,
    pub watcher_quorum: u64,
    pub risk_score_bps: u64,
    pub fallback_route_commitment: String,
}

impl ReorgSafeExitTiming {
    pub fn new(
        route_id: impl Into<String>,
        anchor_block_hash: impl Into<String>,
        anchor_height: u64,
        config: &MoneroAdaptiveFeePrivacyRouterConfig,
    ) -> Self {
        let route_id = route_id.into();
        let anchor_block_hash = anchor_block_hash.into();
        let earliest_broadcast_height = anchor_height.saturating_add(config.exit_hold_blocks);
        let safe_finality_height = earliest_broadcast_height.saturating_add(config.reorg_depth);
        let exit_window_id = fee_privacy_hash(
            "MONERO-ADAPTIVE-FEE-EXIT-WINDOW-ID",
            &[
                HashPart::Str(&route_id),
                HashPart::Str(&anchor_block_hash),
                HashPart::Int(anchor_height as i128),
            ],
        );
        let fallback_route_commitment = fee_privacy_hash(
            "MONERO-ADAPTIVE-FEE-EXIT-FALLBACK",
            &[HashPart::Str(&exit_window_id), HashPart::Str(&route_id)],
        );
        Self {
            exit_window_id,
            route_id,
            status: ExitTimingStatus::Planned,
            anchor_block_hash,
            anchor_height,
            earliest_broadcast_height,
            safe_finality_height,
            reorg_depth: config.reorg_depth,
            hold_blocks: config.exit_hold_blocks,
            watcher_quorum: 0,
            risk_score_bps: 0,
            fallback_route_commitment,
        }
    }

    pub fn validate(&self) -> MoneroAdaptiveFeePrivacyRouterResult<()> {
        ensure_non_empty(&self.exit_window_id, "exit window id")?;
        ensure_non_empty(&self.route_id, "exit window route id")?;
        ensure_non_empty(&self.anchor_block_hash, "exit anchor block hash")?;
        ensure_ordered_heights(
            self.anchor_height,
            self.earliest_broadcast_height,
            "exit hold",
        )?;
        ensure_ordered_heights(
            self.earliest_broadcast_height,
            self.safe_finality_height,
            "exit finality",
        )?;
        ensure_non_zero(self.reorg_depth, "exit reorg depth")?;
        ensure_non_zero(self.hold_blocks, "exit hold blocks")?;
        ensure_bps(self.risk_score_bps, "exit reorg risk score")?;
        ensure_non_empty(
            &self.fallback_route_commitment,
            "exit fallback route commitment",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "exit_window_id": self.exit_window_id,
            "route_id": self.route_id,
            "status": self.status.as_str(),
            "anchor_block_hash": self.anchor_block_hash,
            "anchor_height": self.anchor_height,
            "earliest_broadcast_height": self.earliest_broadcast_height,
            "safe_finality_height": self.safe_finality_height,
            "reorg_depth": self.reorg_depth,
            "hold_blocks": self.hold_blocks,
            "watcher_quorum": self.watcher_quorum,
            "risk_score_bps": self.risk_score_bps,
            "fallback_route_commitment": self.fallback_route_commitment,
        })
    }

    pub fn record_root(&self) -> String {
        fee_privacy_json_root("MONERO-ADAPTIVE-FEE-EXIT-TIMING", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqWatcherAttestation {
    pub attestation_id: String,
    pub watcher_id: String,
    pub subject_id: String,
    pub kind: PqWatcherAttestationKind,
    pub status: PqWatcherAttestationStatus,
    pub observed_height: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub pq_scheme: String,
    pub pq_security_bits: u16,
    pub statement_root: String,
    pub signature_commitment: String,
    pub evidence_root: String,
}

impl PqWatcherAttestation {
    pub fn new(
        watcher_id: impl Into<String>,
        subject_id: impl Into<String>,
        kind: PqWatcherAttestationKind,
        observed_height: u64,
        submitted_at_height: u64,
        statement_root: impl Into<String>,
        config: &MoneroAdaptiveFeePrivacyRouterConfig,
    ) -> Self {
        let watcher_id = watcher_id.into();
        let subject_id = subject_id.into();
        let statement_root = statement_root.into();
        let attestation_id = fee_privacy_hash(
            "MONERO-ADAPTIVE-FEE-PQ-WATCHER-ID",
            &[
                HashPart::Str(&watcher_id),
                HashPart::Str(&subject_id),
                HashPart::Str(kind.as_str()),
                HashPart::Int(observed_height as i128),
                HashPart::Str(&statement_root),
            ],
        );
        let signature_commitment = fee_privacy_hash(
            "MONERO-ADAPTIVE-FEE-PQ-SIGNATURE",
            &[HashPart::Str(&attestation_id), HashPart::Str(&watcher_id)],
        );
        Self {
            attestation_id,
            watcher_id,
            subject_id,
            kind,
            status: PqWatcherAttestationStatus::Submitted,
            observed_height,
            submitted_at_height,
            expires_at_height: submitted_at_height.saturating_add(config.attestation_ttl_blocks),
            pq_scheme: config.pq_watcher_scheme.clone(),
            pq_security_bits: config.min_pq_security_bits,
            statement_root,
            signature_commitment,
            evidence_root: empty_root("MONERO-ADAPTIVE-FEE-PQ-WATCHER-EVIDENCE"),
        }
    }

    pub fn validate(
        &self,
        config: &MoneroAdaptiveFeePrivacyRouterConfig,
    ) -> MoneroAdaptiveFeePrivacyRouterResult<()> {
        ensure_non_empty(&self.attestation_id, "attestation id")?;
        ensure_non_empty(&self.watcher_id, "attestation watcher id")?;
        ensure_non_empty(&self.subject_id, "attestation subject id")?;
        ensure_ordered_heights(
            self.observed_height,
            self.submitted_at_height,
            "attestation submission",
        )?;
        ensure_ordered_heights(
            self.submitted_at_height,
            self.expires_at_height,
            "attestation ttl",
        )?;
        ensure_non_empty(&self.pq_scheme, "attestation pq scheme")?;
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("attestation pq security bits below configured minimum".to_string());
        }
        ensure_non_empty(&self.statement_root, "attestation statement root")?;
        ensure_non_empty(
            &self.signature_commitment,
            "attestation signature commitment",
        )?;
        ensure_non_empty(&self.evidence_root, "attestation evidence root")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "attestation_id": self.attestation_id,
            "watcher_id": self.watcher_id,
            "subject_id": self.subject_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "observed_height": self.observed_height,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "pq_scheme": self.pq_scheme,
            "pq_security_bits": self.pq_security_bits,
            "statement_root": self.statement_root,
            "signature_commitment": self.signature_commitment,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn record_root(&self) -> String {
        fee_privacy_json_root("MONERO-ADAPTIVE-FEE-PQ-WATCHER", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouterEvent {
    pub event_id: String,
    pub height: u64,
    pub kind: String,
    pub subject_id: String,
    pub record_root: String,
}

impl RouterEvent {
    pub fn new(
        height: u64,
        kind: impl Into<String>,
        subject_id: impl Into<String>,
        record_root: impl Into<String>,
    ) -> Self {
        let kind = kind.into();
        let subject_id = subject_id.into();
        let record_root = record_root.into();
        let event_id = fee_privacy_hash(
            "MONERO-ADAPTIVE-FEE-EVENT-ID",
            &[
                HashPart::Int(height as i128),
                HashPart::Str(&kind),
                HashPart::Str(&subject_id),
                HashPart::Str(&record_root),
            ],
        );
        Self {
            event_id,
            height,
            kind,
            subject_id,
            record_root,
        }
    }

    pub fn validate(&self) -> MoneroAdaptiveFeePrivacyRouterResult<()> {
        ensure_non_empty(&self.event_id, "event id")?;
        ensure_non_empty(&self.kind, "event kind")?;
        ensure_non_empty(&self.subject_id, "event subject id")?;
        ensure_non_empty(&self.record_root, "event record root")?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "event_id": self.event_id,
            "height": self.height,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "record_root": self.record_root,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MoneroAdaptiveFeePrivacyRouterRoots {
    pub config_root: String,
    pub fee_bucket_root: String,
    pub route_root: String,
    pub sponsorship_root: String,
    pub scan_hint_root: String,
    pub exit_timing_root: String,
    pub pq_attestation_root: String,
    pub event_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl MoneroAdaptiveFeePrivacyRouterRoots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "fee_bucket_root": self.fee_bucket_root,
            "route_root": self.route_root,
            "sponsorship_root": self.sponsorship_root,
            "scan_hint_root": self.scan_hint_root,
            "exit_timing_root": self.exit_timing_root,
            "pq_attestation_root": self.pq_attestation_root,
            "event_root": self.event_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert(
                "state_root".to_string(),
                Value::String(self.state_root.clone()),
            );
        }
        record
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MoneroAdaptiveFeePrivacyRouterCounters {
    pub fee_buckets: u64,
    pub routes: u64,
    pub live_routes: u64,
    pub sponsored_routes: u64,
    pub scan_hints: u64,
    pub exit_windows: u64,
    pub pq_attestations: u64,
    pub counted_attestations: u64,
    pub watchers: u64,
    pub events: u64,
}

impl MoneroAdaptiveFeePrivacyRouterCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "fee_buckets": self.fee_buckets,
            "routes": self.routes,
            "live_routes": self.live_routes,
            "sponsored_routes": self.sponsored_routes,
            "scan_hints": self.scan_hints,
            "exit_windows": self.exit_windows,
            "pq_attestations": self.pq_attestations,
            "counted_attestations": self.counted_attestations,
            "watchers": self.watchers,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoneroAdaptiveFeePrivacyRouterState {
    pub height: u64,
    pub config: MoneroAdaptiveFeePrivacyRouterConfig,
    pub fee_buckets: BTreeMap<String, FeeOracleBucket>,
    pub routes: BTreeMap<String, DecoyRouteChoice>,
    pub sponsorships: BTreeMap<String, LowFeeSponsorshipRoute>,
    pub scan_hints: BTreeMap<String, StealthAddressScanHint>,
    pub exit_windows: BTreeMap<String, ReorgSafeExitTiming>,
    pub pq_attestations: BTreeMap<String, PqWatcherAttestation>,
    pub watcher_index: BTreeMap<String, BTreeSet<String>>,
    pub route_nullifier_index: BTreeMap<String, String>,
    pub bucket_epoch_index: BTreeMap<u64, BTreeSet<String>>,
    pub public_records: BTreeMap<String, Value>,
    pub events: BTreeMap<String, RouterEvent>,
}

impl MoneroAdaptiveFeePrivacyRouterState {
    pub fn new(
        height: u64,
        config: MoneroAdaptiveFeePrivacyRouterConfig,
    ) -> MoneroAdaptiveFeePrivacyRouterResult<Self> {
        config.validate()?;
        let mut state = Self {
            height,
            config,
            fee_buckets: BTreeMap::new(),
            routes: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            scan_hints: BTreeMap::new(),
            exit_windows: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            watcher_index: BTreeMap::new(),
            route_nullifier_index: BTreeMap::new(),
            bucket_epoch_index: BTreeMap::new(),
            public_records: BTreeMap::new(),
            events: BTreeMap::new(),
        };
        state.refresh_public_records();
        Ok(state)
    }

    pub fn devnet() -> MoneroAdaptiveFeePrivacyRouterResult<Self> {
        let config = MoneroAdaptiveFeePrivacyRouterConfig::devnet();
        let mut state = Self::new(MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_DEVNET_HEIGHT, config)?;
        let economy = FeeOracleBucket::new(
            AdaptiveFeeBucketKind::Economy,
            epoch_for_height(state.height, state.config.epoch_blocks),
            state.height.saturating_sub(23),
            24_000,
            31_000,
            42_000,
            &state.config,
        )
        .with_samples(
            96,
            seeded_root("MONERO-ADAPTIVE-FEE-DEVNET-SAMPLES", "economy"),
        );
        let standard = FeeOracleBucket::new(
            AdaptiveFeeBucketKind::Standard,
            epoch_for_height(state.height, state.config.epoch_blocks),
            state.height.saturating_sub(23),
            32_000,
            45_000,
            62_000,
            &state.config,
        )
        .with_samples(
            128,
            seeded_root("MONERO-ADAPTIVE-FEE-DEVNET-SAMPLES", "standard"),
        );
        state.insert_fee_bucket(economy)?;
        state.insert_fee_bucket(standard)?;
        let selected_bucket = state
            .latest_bucket_for_kind(AdaptiveFeeBucketKind::Economy)
            .ok_or_else(|| "devnet economy bucket missing".to_string())?;
        let mut route = DecoyRouteChoice::new(
            seeded_root("MONERO-ADAPTIVE-FEE-DEVNET-REQUEST", "wallet-transfer"),
            PrivacyRouteIntent::WalletTransfer,
            selected_bucket.bucket_id.clone(),
            state.height,
            "amount_bucket_0_1_xmr",
            &state.config,
        )
        .quote(
            selected_bucket.recommended_fee_per_kb,
            seeded_root("MONERO-ADAPTIVE-FEE-DEVNET-DECOYS", "wallet-transfer"),
        );
        route.decoy_count = state.config.min_decoys.saturating_add(10);
        route.privacy_score = 8_650;
        let route_id = route.route_id.clone();
        state.insert_route(route)?;
        let sponsor = LowFeeSponsorshipRoute::new(
            seeded_root("MONERO-ADAPTIVE-FEE-DEVNET-SPONSOR", "fee-relay"),
            route_id.clone(),
            12_000_000,
            state.height,
            &state.config,
        );
        state.insert_sponsorship(sponsor)?;
        let hint = StealthAddressScanHint::new(
            route_id.clone(),
            "7a",
            seeded_root("MONERO-ADAPTIVE-FEE-DEVNET-STEALTH", "wallet-transfer"),
            state.height,
            &state.config,
        );
        state.insert_scan_hint(hint)?;
        let exit = ReorgSafeExitTiming::new(
            route_id.clone(),
            seeded_root("MONERO-ADAPTIVE-FEE-DEVNET-ANCHOR", "block"),
            state.height,
            &state.config,
        );
        state.insert_exit_timing(exit)?;
        let statement_root = state
            .routes
            .get(&route_id)
            .map(DecoyRouteChoice::record_root)
            .ok_or_else(|| "devnet route disappeared before watcher attestation".to_string())?;
        let watcher = PqWatcherAttestation::new(
            "devnet-pq-watcher-0",
            route_id,
            PqWatcherAttestationKind::DecoySet,
            state.height,
            state.height,
            statement_root,
            &state.config,
        );
        state.insert_pq_attestation(watcher)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> MoneroAdaptiveFeePrivacyRouterResult<String> {
        if height < self.height {
            return Err("router height cannot move backwards".to_string());
        }
        self.height = height;
        self.expire_records();
        self.refresh_public_records();
        Ok(self.state_root())
    }

    pub fn insert_fee_bucket(
        &mut self,
        bucket: FeeOracleBucket,
    ) -> MoneroAdaptiveFeePrivacyRouterResult<String> {
        if self.fee_buckets.len() >= MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_BUCKETS
            && !self.fee_buckets.contains_key(&bucket.bucket_id)
        {
            return Err("fee bucket limit reached".to_string());
        }
        bucket.validate(&self.config)?;
        self.bucket_epoch_index
            .entry(bucket.epoch)
            .or_default()
            .insert(bucket.bucket_id.clone());
        self.record_event(
            "fee_bucket_upserted",
            &bucket.bucket_id,
            bucket.record_root(),
        );
        self.fee_buckets.insert(bucket.bucket_id.clone(), bucket);
        self.refresh_public_records();
        Ok(self.state_root())
    }

    pub fn insert_route(
        &mut self,
        route: DecoyRouteChoice,
    ) -> MoneroAdaptiveFeePrivacyRouterResult<String> {
        if self.routes.len() >= MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_ROUTES
            && !self.routes.contains_key(&route.route_id)
        {
            return Err("route limit reached".to_string());
        }
        route.validate(&self.config)?;
        if !self.fee_buckets.contains_key(&route.fee_bucket_id) {
            return Err("route references unknown fee bucket".to_string());
        }
        if let Some(existing) = self.route_nullifier_index.get(&route.nullifier_commitment) {
            if existing != &route.route_id {
                return Err("route nullifier commitment already indexed".to_string());
            }
        }
        self.route_nullifier_index
            .insert(route.nullifier_commitment.clone(), route.route_id.clone());
        self.record_event("route_upserted", &route.route_id, route.record_root());
        self.routes.insert(route.route_id.clone(), route);
        self.refresh_public_records();
        Ok(self.state_root())
    }

    pub fn insert_sponsorship(
        &mut self,
        sponsorship: LowFeeSponsorshipRoute,
    ) -> MoneroAdaptiveFeePrivacyRouterResult<String> {
        if self.sponsorships.len() >= MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_SPONSORSHIPS
            && !self.sponsorships.contains_key(&sponsorship.sponsor_id)
        {
            return Err("sponsorship limit reached".to_string());
        }
        sponsorship.validate()?;
        let route = self
            .routes
            .get_mut(&sponsorship.route_id)
            .ok_or_else(|| "sponsorship references unknown route".to_string())?;
        if !sponsorship.status.spendable() {
            return Err("sponsorship is not spendable".to_string());
        }
        route.sponsor_id = Some(sponsorship.sponsor_id.clone());
        route.status = PrivacyRouteStatus::Sponsored;
        self.record_event(
            "sponsorship_upserted",
            &sponsorship.sponsor_id,
            sponsorship.record_root(),
        );
        self.sponsorships
            .insert(sponsorship.sponsor_id.clone(), sponsorship);
        self.refresh_public_records();
        Ok(self.state_root())
    }

    pub fn insert_scan_hint(
        &mut self,
        hint: StealthAddressScanHint,
    ) -> MoneroAdaptiveFeePrivacyRouterResult<String> {
        if self.scan_hints.len() >= MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_SCAN_HINTS
            && !self.scan_hints.contains_key(&hint.hint_id)
        {
            return Err("scan hint limit reached".to_string());
        }
        hint.validate()?;
        let route = self
            .routes
            .get_mut(&hint.route_id)
            .ok_or_else(|| "scan hint references unknown route".to_string())?;
        route.scan_hint_id = Some(hint.hint_id.clone());
        route.status = PrivacyRouteStatus::ScanHintPublished;
        self.record_event("scan_hint_upserted", &hint.hint_id, hint.record_root());
        self.scan_hints.insert(hint.hint_id.clone(), hint);
        self.refresh_public_records();
        Ok(self.state_root())
    }

    pub fn insert_exit_timing(
        &mut self,
        exit: ReorgSafeExitTiming,
    ) -> MoneroAdaptiveFeePrivacyRouterResult<String> {
        if self.exit_windows.len() >= MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_EXIT_WINDOWS
            && !self.exit_windows.contains_key(&exit.exit_window_id)
        {
            return Err("exit timing limit reached".to_string());
        }
        exit.validate()?;
        let route = self
            .routes
            .get_mut(&exit.route_id)
            .ok_or_else(|| "exit timing references unknown route".to_string())?;
        route.exit_window_id = Some(exit.exit_window_id.clone());
        route.status = PrivacyRouteStatus::ExitWindowOpen;
        self.record_event(
            "exit_timing_upserted",
            &exit.exit_window_id,
            exit.record_root(),
        );
        self.exit_windows.insert(exit.exit_window_id.clone(), exit);
        self.refresh_public_records();
        Ok(self.state_root())
    }

    pub fn insert_pq_attestation(
        &mut self,
        mut attestation: PqWatcherAttestation,
    ) -> MoneroAdaptiveFeePrivacyRouterResult<String> {
        if self.pq_attestations.len() >= MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_ATTESTATIONS
            && !self
                .pq_attestations
                .contains_key(&attestation.attestation_id)
        {
            return Err("pq attestation limit reached".to_string());
        }
        attestation.validate(&self.config)?;
        let watcher_subjects = self
            .watcher_index
            .entry(attestation.watcher_id.clone())
            .or_default();
        if watcher_subjects.contains(&attestation.subject_id) {
            attestation.status = PqWatcherAttestationStatus::Duplicate;
        } else {
            watcher_subjects.insert(attestation.subject_id.clone());
            attestation.status = PqWatcherAttestationStatus::Counted;
        }
        self.apply_attestation_to_subject(&attestation)?;
        self.record_event(
            "pq_attestation_upserted",
            &attestation.attestation_id,
            attestation.record_root(),
        );
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_public_records();
        Ok(self.state_root())
    }

    pub fn certify_route_ready(
        &mut self,
        route_id: &str,
    ) -> MoneroAdaptiveFeePrivacyRouterResult<String> {
        let route = self
            .routes
            .get_mut(route_id)
            .ok_or_else(|| "route not found for certification".to_string())?;
        if route.watcher_quorum < self.config.min_watchers {
            return Err("route lacks pq watcher quorum".to_string());
        }
        if route.intent.requires_scan_hint() && route.scan_hint_id.is_none() {
            return Err("route requires stealth scan hint before certification".to_string());
        }
        if route.intent.exit_like() && route.exit_window_id.is_none() {
            return Err("exit-like route requires reorg-safe exit window".to_string());
        }
        route.status = PrivacyRouteStatus::WatcherCertified;
        let root = route.record_root();
        self.record_event("route_certified", route_id, root);
        self.refresh_public_records();
        Ok(self.state_root())
    }

    pub fn mark_route_settled(
        &mut self,
        route_id: &str,
    ) -> MoneroAdaptiveFeePrivacyRouterResult<String> {
        let route = self
            .routes
            .get_mut(route_id)
            .ok_or_else(|| "route not found for settlement".to_string())?;
        if route.watcher_quorum < self.config.min_watchers {
            return Err("cannot settle route without watcher quorum".to_string());
        }
        route.status = PrivacyRouteStatus::Settled;
        let root = route.record_root();
        self.record_event("route_settled", route_id, root);
        self.refresh_public_records();
        Ok(self.state_root())
    }

    pub fn latest_bucket_for_kind(&self, kind: AdaptiveFeeBucketKind) -> Option<&FeeOracleBucket> {
        self.fee_buckets
            .values()
            .filter(|bucket| bucket.kind == kind)
            .max_by_key(|bucket| (bucket.epoch, bucket.last_height))
    }

    pub fn roots(&self) -> MoneroAdaptiveFeePrivacyRouterRoots {
        let public_record_root = keyed_json_root(
            "MONERO-ADAPTIVE-FEE-PUBLIC-RECORDS",
            self.public_records
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        let mut roots = MoneroAdaptiveFeePrivacyRouterRoots {
            config_root: fee_privacy_json_root(
                "MONERO-ADAPTIVE-FEE-CONFIG",
                &self.config.public_record(),
            ),
            fee_bucket_root: keyed_json_root(
                "MONERO-ADAPTIVE-FEE-BUCKETS",
                self.fee_buckets
                    .iter()
                    .map(|(key, value)| (key.clone(), value.public_record())),
            ),
            route_root: keyed_json_root(
                "MONERO-ADAPTIVE-FEE-ROUTES",
                self.routes
                    .iter()
                    .map(|(key, value)| (key.clone(), value.public_record())),
            ),
            sponsorship_root: keyed_json_root(
                "MONERO-ADAPTIVE-FEE-SPONSORSHIPS",
                self.sponsorships
                    .iter()
                    .map(|(key, value)| (key.clone(), value.public_record())),
            ),
            scan_hint_root: keyed_json_root(
                "MONERO-ADAPTIVE-FEE-SCAN-HINTS",
                self.scan_hints
                    .iter()
                    .map(|(key, value)| (key.clone(), value.public_record())),
            ),
            exit_timing_root: keyed_json_root(
                "MONERO-ADAPTIVE-FEE-EXIT-WINDOWS",
                self.exit_windows
                    .iter()
                    .map(|(key, value)| (key.clone(), value.public_record())),
            ),
            pq_attestation_root: keyed_json_root(
                "MONERO-ADAPTIVE-FEE-PQ-ATTESTATIONS",
                self.pq_attestations
                    .iter()
                    .map(|(key, value)| (key.clone(), value.public_record())),
            ),
            event_root: keyed_json_root(
                "MONERO-ADAPTIVE-FEE-EVENTS",
                self.events
                    .iter()
                    .map(|(key, value)| (key.clone(), value.public_record())),
            ),
            public_record_root,
            state_root: String::new(),
        };
        roots.state_root = fee_privacy_json_root(
            "MONERO-ADAPTIVE-FEE-ROOTS",
            &roots.public_record_without_state_root(),
        );
        roots
    }

    pub fn counters(&self) -> MoneroAdaptiveFeePrivacyRouterCounters {
        MoneroAdaptiveFeePrivacyRouterCounters {
            fee_buckets: self.fee_buckets.len() as u64,
            routes: self.routes.len() as u64,
            live_routes: self
                .routes
                .values()
                .filter(|route| route.status.is_live())
                .count() as u64,
            sponsored_routes: self
                .routes
                .values()
                .filter(|route| route.sponsor_id.is_some())
                .count() as u64,
            scan_hints: self.scan_hints.len() as u64,
            exit_windows: self.exit_windows.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            counted_attestations: self
                .pq_attestations
                .values()
                .filter(|attestation| attestation.status == PqWatcherAttestationStatus::Counted)
                .count() as u64,
            watchers: self.watcher_index.len() as u64,
            events: self.events.len() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "height": self.height,
            "hash_suite": MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_HASH_SUITE,
            "config": self.config.public_record(),
            "roots": roots.public_record_without_state_root(),
            "counters": counters.public_record(),
            "fee_buckets": self.fee_buckets.values().map(FeeOracleBucket::public_record).collect::<Vec<_>>(),
            "routes": self.routes.values().map(DecoyRouteChoice::public_record).collect::<Vec<_>>(),
            "sponsorships": self.sponsorships.values().map(LowFeeSponsorshipRoute::public_record).collect::<Vec<_>>(),
            "scan_hints": self.scan_hints.values().map(StealthAddressScanHint::public_record).collect::<Vec<_>>(),
            "exit_windows": self.exit_windows.values().map(ReorgSafeExitTiming::public_record).collect::<Vec<_>>(),
            "pq_attestations": self.pq_attestations.values().map(PqWatcherAttestation::public_record).collect::<Vec<_>>(),
            "watcher_index": self.watcher_index.iter().map(|(watcher, subjects)| {
                json!({"watcher_id": watcher, "subjects": subjects.iter().cloned().collect::<Vec<_>>()})
            }).collect::<Vec<_>>(),
            "route_nullifier_index": self.route_nullifier_index,
            "bucket_epoch_index": self.bucket_epoch_index.iter().map(|(epoch, buckets)| {
                json!({"epoch": epoch, "bucket_ids": buckets.iter().cloned().collect::<Vec<_>>()})
            }).collect::<Vec<_>>(),
            "public_records": self.public_records,
            "events": self.events.values().map(RouterEvent::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        fee_privacy_json_root(
            "MONERO-ADAPTIVE-FEE-STATE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record_root(&self) -> String {
        keyed_json_root(
            "MONERO-ADAPTIVE-FEE-PUBLIC-RECORDS",
            self.public_records
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        )
    }

    pub fn validate(&self) -> MoneroAdaptiveFeePrivacyRouterResult<()> {
        self.config.validate()?;
        ensure_map_limit(
            self.fee_buckets.len(),
            MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_BUCKETS,
            "fee buckets",
        )?;
        ensure_map_limit(
            self.routes.len(),
            MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_ROUTES,
            "routes",
        )?;
        ensure_map_limit(
            self.sponsorships.len(),
            MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_SPONSORSHIPS,
            "sponsorships",
        )?;
        ensure_map_limit(
            self.scan_hints.len(),
            MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_SCAN_HINTS,
            "scan hints",
        )?;
        ensure_map_limit(
            self.exit_windows.len(),
            MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_EXIT_WINDOWS,
            "exit windows",
        )?;
        ensure_map_limit(
            self.pq_attestations.len(),
            MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_ATTESTATIONS,
            "pq attestations",
        )?;
        ensure_map_limit(
            self.events.len(),
            MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_EVENTS,
            "events",
        )?;
        for (key, bucket) in &self.fee_buckets {
            if key != &bucket.bucket_id {
                return Err("fee bucket map key mismatch".to_string());
            }
            bucket.validate(&self.config)?;
        }
        for (key, route) in &self.routes {
            if key != &route.route_id {
                return Err("route map key mismatch".to_string());
            }
            route.validate(&self.config)?;
            if !self.fee_buckets.contains_key(&route.fee_bucket_id) {
                return Err("route references missing fee bucket".to_string());
            }
        }
        for (key, sponsorship) in &self.sponsorships {
            if key != &sponsorship.sponsor_id {
                return Err("sponsorship map key mismatch".to_string());
            }
            sponsorship.validate()?;
            if !self.routes.contains_key(&sponsorship.route_id) {
                return Err("sponsorship references missing route".to_string());
            }
        }
        for (key, hint) in &self.scan_hints {
            if key != &hint.hint_id {
                return Err("scan hint map key mismatch".to_string());
            }
            hint.validate()?;
            if !self.routes.contains_key(&hint.route_id) {
                return Err("scan hint references missing route".to_string());
            }
        }
        for (key, exit) in &self.exit_windows {
            if key != &exit.exit_window_id {
                return Err("exit window map key mismatch".to_string());
            }
            exit.validate()?;
            if !self.routes.contains_key(&exit.route_id) {
                return Err("exit window references missing route".to_string());
            }
        }
        for (key, attestation) in &self.pq_attestations {
            if key != &attestation.attestation_id {
                return Err("pq attestation map key mismatch".to_string());
            }
            attestation.validate(&self.config)?;
        }
        for (nullifier, route_id) in &self.route_nullifier_index {
            ensure_non_empty(nullifier, "route nullifier index key")?;
            if !self.routes.contains_key(route_id) {
                return Err("route nullifier index references missing route".to_string());
            }
        }
        for event in self.events.values() {
            event.validate()?;
        }
        Ok(())
    }

    fn apply_attestation_to_subject(
        &mut self,
        attestation: &PqWatcherAttestation,
    ) -> MoneroAdaptiveFeePrivacyRouterResult<()> {
        if attestation.status != PqWatcherAttestationStatus::Counted {
            return Ok(());
        }
        match attestation.kind {
            PqWatcherAttestationKind::FeeBucket => {
                if let Some(bucket) = self.fee_buckets.get_mut(&attestation.subject_id) {
                    bucket.watcher_attestation_root = attestation.statement_root.clone();
                }
            }
            PqWatcherAttestationKind::DecoySet | PqWatcherAttestationKind::SponsorEligibility => {
                if let Some(route) = self.routes.get_mut(&attestation.subject_id) {
                    route.watcher_quorum = route.watcher_quorum.saturating_add(1);
                    route.pq_attestation_root = attestation.statement_root.clone();
                    if route.watcher_quorum >= self.config.min_watchers {
                        route.status = PrivacyRouteStatus::WatcherCertified;
                    }
                }
            }
            PqWatcherAttestationKind::ScanHint => {
                if let Some(hint) = self.scan_hints.get_mut(&attestation.subject_id) {
                    hint.watcher_quorum = hint.watcher_quorum.saturating_add(1);
                    if hint.watcher_quorum >= self.config.min_watchers {
                        hint.status = ScanHintStatus::QuorumCertified;
                    }
                }
            }
            PqWatcherAttestationKind::ExitTiming | PqWatcherAttestationKind::ReorgRisk => {
                if let Some(exit) = self.exit_windows.get_mut(&attestation.subject_id) {
                    exit.watcher_quorum = exit.watcher_quorum.saturating_add(1);
                    exit.risk_score_bps = exit
                        .risk_score_bps
                        .saturating_add(50)
                        .min(MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_BPS);
                    if exit.watcher_quorum >= self.config.min_watchers {
                        exit.status = ExitTimingStatus::WatcherCertified;
                    }
                }
            }
        }
        Ok(())
    }

    fn expire_records(&mut self) {
        for bucket in self.fee_buckets.values_mut() {
            if self.height > bucket.expires_at_height {
                bucket.low_fee_eligible = false;
            }
        }
        for route in self.routes.values_mut() {
            if route.status.is_live() && self.height > route.expires_at_height {
                route.status = PrivacyRouteStatus::Expired;
            }
        }
        for sponsorship in self.sponsorships.values_mut() {
            if sponsorship.status.spendable() && self.height > sponsorship.expires_at_height {
                sponsorship.status = SponsorshipStatus::Expired;
            }
        }
        for hint in self.scan_hints.values_mut() {
            if self.height > hint.expires_at_height
                && hint.status != ScanHintStatus::QuorumCertified
            {
                hint.status = ScanHintStatus::Expired;
            }
        }
        for attestation in self.pq_attestations.values_mut() {
            if self.height > attestation.expires_at_height
                && attestation.status == PqWatcherAttestationStatus::Submitted
            {
                attestation.status = PqWatcherAttestationStatus::Expired;
            }
        }
    }

    fn record_event(&mut self, kind: &str, subject_id: &str, record_root: String) {
        if self.events.len() >= MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_EVENTS {
            return;
        }
        let event = RouterEvent::new(self.height, kind, subject_id, record_root);
        self.events.insert(event.event_id.clone(), event);
    }

    fn refresh_public_records(&mut self) {
        let mut records = BTreeMap::new();
        records.insert("config".to_string(), self.config.public_record());
        for (key, bucket) in &self.fee_buckets {
            records.insert(format!("fee_bucket:{key}"), bucket.public_record());
        }
        for (key, route) in &self.routes {
            records.insert(format!("route:{key}"), route.public_record());
        }
        for (key, sponsorship) in &self.sponsorships {
            records.insert(format!("sponsorship:{key}"), sponsorship.public_record());
        }
        for (key, hint) in &self.scan_hints {
            records.insert(format!("scan_hint:{key}"), hint.public_record());
        }
        for (key, exit) in &self.exit_windows {
            records.insert(format!("exit_window:{key}"), exit.public_record());
        }
        for (key, attestation) in &self.pq_attestations {
            records.insert(format!("pq_attestation:{key}"), attestation.public_record());
        }
        for (key, event) in &self.events {
            records.insert(format!("event:{key}"), event.public_record());
        }
        self.public_records = records;
    }
}

pub fn adaptive_fee_for_route(
    bucket: &FeeOracleBucket,
    route: &DecoyRouteChoice,
    sponsorship: Option<&LowFeeSponsorshipRoute>,
) -> u64 {
    let fee = bucket
        .recommended_fee_per_kb
        .min(route.quoted_fee_per_kb.max(bucket.recommended_fee_per_kb));
    match sponsorship {
        Some(sponsor) if sponsor.status.spendable() => {
            let rebate = fee
                .saturating_mul(sponsor.max_rebate_bps)
                .saturating_div(MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_BPS);
            fee.saturating_sub(rebate).max(1)
        }
        _ => fee,
    }
}

pub fn decoy_preserving_score(
    route: &DecoyRouteChoice,
    config: &MoneroAdaptiveFeePrivacyRouterConfig,
) -> u64 {
    let decoy_score = route
        .decoy_count
        .saturating_mul(5_000)
        .saturating_div(config.min_decoys.max(1))
        .min(5_000);
    let privacy_score = route.privacy_score.min(5_000);
    decoy_score
        .saturating_add(privacy_score)
        .min(MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_BPS)
}

pub fn reorg_safe_broadcast_height(
    anchor_height: u64,
    config: &MoneroAdaptiveFeePrivacyRouterConfig,
) -> u64 {
    anchor_height
        .saturating_add(config.exit_hold_blocks)
        .saturating_add(config.reorg_depth)
}

fn epoch_for_height(height: u64, epoch_blocks: u64) -> u64 {
    if epoch_blocks == 0 {
        0
    } else {
        height / epoch_blocks
    }
}

fn keyed_json_root<I>(domain: &str, entries: I) -> String
where
    I: IntoIterator<Item = (String, Value)>,
{
    let leaves = entries
        .into_iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn seeded_root(domain: &str, seed: &str) -> String {
    fee_privacy_hash(domain, &[HashPart::Str(seed)])
}

fn fee_privacy_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    let mut scoped_parts = Vec::with_capacity(parts.len().saturating_add(2));
    scoped_parts.push(HashPart::Str(CHAIN_ID));
    scoped_parts.push(HashPart::Str(
        MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_PROTOCOL_VERSION,
    ));
    for part in parts {
        match part {
            HashPart::Bytes(value) => scoped_parts.push(HashPart::Bytes(value)),
            HashPart::Str(value) => scoped_parts.push(HashPart::Str(value)),
            HashPart::U64(value) => scoped_parts.push(HashPart::U64(*value)),
            HashPart::Int(value) => scoped_parts.push(HashPart::Int(*value)),
            HashPart::Json(value) => scoped_parts.push(HashPart::Json(value)),
        }
    }
    domain_hash(domain, &scoped_parts, 32)
}

fn fee_privacy_json_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_PROTOCOL_VERSION),
            HashPart::Json(value),
        ],
        32,
    )
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroAdaptiveFeePrivacyRouterResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_non_zero(value: u64, label: &str) -> MoneroAdaptiveFeePrivacyRouterResult<()> {
    if value == 0 {
        Err(format!("{label} cannot be zero"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> MoneroAdaptiveFeePrivacyRouterResult<()> {
    if value > MONERO_ADAPTIVE_FEE_PRIVACY_ROUTER_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_ordered_heights(
    start: u64,
    end: u64,
    label: &str,
) -> MoneroAdaptiveFeePrivacyRouterResult<()> {
    if end < start {
        Err(format!("{label} end height cannot be before start height"))
    } else {
        Ok(())
    }
}

fn ensure_map_limit(
    len: usize,
    max: usize,
    label: &str,
) -> MoneroAdaptiveFeePrivacyRouterResult<()> {
    if len > max {
        Err(format!("{label} exceeds maximum record limit"))
    } else {
        Ok(())
    }
}
