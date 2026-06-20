use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroFeeSponsoredExitAggregatorResult<T> = Result<T, String>;

pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_PROTOCOL_VERSION: &str =
    "nebula-monero-fee-sponsored-exit-aggregator-v1";
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_SCHEMA_VERSION: u64 = 1;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEVNET_HEIGHT: u64 = 320;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEVNET_FEE_ASSET_ID: &str = "dxmr-devnet";
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_PQ_SUITE: &str =
    "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s-sponsored-exit-devnet";
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_COMMITMENT_SCHEME: &str =
    "monero-sponsored-exit-nullifier-commitment-v1";
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MANIFEST_SCHEME: &str =
    "compact-private-exit-manifest-v1";
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_RELEASE_SCHEME: &str =
    "delayed-release-window-attested-v1";
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_SLASHING_SCHEME: &str =
    "pq-watcher-slashing-evidence-v1";
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_LANES: usize = 32;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_SPONSORS: usize = 512;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_TICKETS: usize = 16_384;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_RESERVATIONS: usize = 32_768;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_MANIFESTS: usize = 2_048;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_ATTESTATIONS: usize = 65_536;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_RELEASE_WINDOWS: usize = 8_192;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_EVIDENCE: usize = 8_192;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_TICKETS_PER_MANIFEST: usize = 256;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_MANIFEST_FEE_UNITS: u64 = 3_000_000;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MIN_EXIT_UNITS: u64 = 1;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_EXIT_UNITS: u64 = 5_000_000_000;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MIN_RING_SIZE: u64 = 16;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_TARGET_RING_SIZE: u64 = 32;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 24;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 6;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_RELEASE_DELAY_BLOCKS: u64 = 12;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 36;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_FINALITY_DEPTH_BLOCKS: u64 = 10;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_REORG_GRACE_BLOCKS: u64 = 8;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_PQ_QUORUM_WEIGHT: u64 = 2;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_WATCHER_BOND_UNITS: u64 = 1_000_000;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_SPONSOR_BOND_UNITS: u64 = 100_000;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_FEE_CAP_MICRO_UNITS: u64 = 1_500;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_PRIVACY_FLOOR_BPS: u64 = 9_500;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_SPONSOR_REBATE_BPS: u64 = 8_750;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_SLASHING_REWARD_BPS: u64 = 2_000;
pub const MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitLaneKind {
    WalletExit,
    DefiSettlement,
    ContractWithdrawal,
    LiquidityMigration,
    EmergencyEscape,
    RecoveryPayout,
}

impl ExitLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletExit => "wallet_exit",
            Self::DefiSettlement => "defi_settlement",
            Self::ContractWithdrawal => "contract_withdrawal",
            Self::LiquidityMigration => "liquidity_migration",
            Self::EmergencyEscape => "emergency_escape",
            Self::RecoveryPayout => "recovery_payout",
        }
    }

    pub fn default_lane_id(self) -> &'static str {
        match self {
            Self::WalletExit => "wallet-private-exit",
            Self::DefiSettlement => "defi-private-settlement",
            Self::ContractWithdrawal => "contract-private-withdrawal",
            Self::LiquidityMigration => "liquidity-private-migration",
            Self::EmergencyEscape => "emergency-private-escape",
            Self::RecoveryPayout => "pq-recovery-payout",
        }
    }

    pub fn default_fee_cap_micro_units(self) -> u64 {
        match self {
            Self::EmergencyEscape => 500,
            Self::RecoveryPayout => 750,
            Self::WalletExit => 1_000,
            Self::DefiSettlement => 1_500,
            Self::ContractWithdrawal => 2_000,
            Self::LiquidityMigration => 2_500,
        }
    }

    pub fn default_priority_weight(self) -> u64 {
        match self {
            Self::EmergencyEscape => 100,
            Self::RecoveryPayout => 95,
            Self::WalletExit => 85,
            Self::DefiSettlement => 75,
            Self::ContractWithdrawal => 70,
            Self::LiquidityMigration => 65,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Active,
    Throttled,
    Paused,
    Draining,
    Closed,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_tickets(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitTicketStatus {
    Submitted,
    Sponsored,
    Manifested,
    Attested,
    ReleasePending,
    Released,
    Challenged,
    Slashed,
    Cancelled,
    Expired,
}

impl ExitTicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Sponsored => "sponsored",
            Self::Manifested => "manifested",
            Self::Attested => "attested",
            Self::ReleasePending => "release_pending",
            Self::Released => "released",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Sponsored
                | Self::Manifested
                | Self::Attested
                | Self::ReleasePending
                | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorAccountStatus {
    Active,
    RateLimited,
    Paused,
    Exhausted,
    Slashed,
    Closed,
}

impl SponsorAccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::RateLimited => "rate_limited",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Slashed => "slashed",
            Self::Closed => "closed",
        }
    }

    pub fn can_reserve(self) -> bool {
        matches!(self, Self::Active | Self::RateLimited)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipReservationStatus {
    Held,
    BoundToTicket,
    Consumed,
    Released,
    Expired,
    Slashed,
    Revoked,
}

impl SponsorshipReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::BoundToTicket => "bound_to_ticket",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
            Self::Revoked => "revoked",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Held | Self::BoundToTicket)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestStatus {
    Collecting,
    Sealed,
    PqAttested,
    ReleaseScheduled,
    Released,
    Challenged,
    Slashed,
    Cancelled,
    Expired,
}

impl ManifestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::PqAttested => "pq_attested",
            Self::ReleaseScheduled => "release_scheduled",
            Self::Released => "released",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_attestations(self) -> bool {
        matches!(self, Self::Sealed | Self::PqAttested)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherAttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Challenged,
    Slashed,
    Expired,
}

impl WatcherAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseWindowStatus {
    Scheduled,
    Open,
    Released,
    Challenged,
    Frozen,
    Expired,
    Cancelled,
}

impl ReleaseWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Open => "open",
            Self::Released => "released",
            Self::Challenged => "challenged",
            Self::Frozen => "frozen",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingEvidenceKind {
    InvalidManifestRoot,
    DoubleSponsoredNullifier,
    FeeCommitmentMismatch,
    WatcherEquivocation,
    EarlyRelease,
    WithheldRelease,
    InvalidPqSignature,
    PrivacyFloorViolation,
    LaneCapacityFraud,
    SponsorInsolvency,
}

impl SlashingEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidManifestRoot => "invalid_manifest_root",
            Self::DoubleSponsoredNullifier => "double_sponsored_nullifier",
            Self::FeeCommitmentMismatch => "fee_commitment_mismatch",
            Self::WatcherEquivocation => "watcher_equivocation",
            Self::EarlyRelease => "early_release",
            Self::WithheldRelease => "withheld_release",
            Self::InvalidPqSignature => "invalid_pq_signature",
            Self::PrivacyFloorViolation => "privacy_floor_violation",
            Self::LaneCapacityFraud => "lane_capacity_fraud",
            Self::SponsorInsolvency => "sponsor_insolvency",
        }
    }

    pub fn default_slash_bps(self) -> u64 {
        match self {
            Self::InvalidManifestRoot => 7_500,
            Self::DoubleSponsoredNullifier => 8_000,
            Self::FeeCommitmentMismatch => 6_500,
            Self::WatcherEquivocation => 5_000,
            Self::EarlyRelease => 6_000,
            Self::WithheldRelease => 4_000,
            Self::InvalidPqSignature => 9_000,
            Self::PrivacyFloorViolation => 7_000,
            Self::LaneCapacityFraud => 5_500,
            Self::SponsorInsolvency => 6_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroFeeSponsoredExitAggregatorConfig {
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub max_lanes: usize,
    pub max_sponsors: usize,
    pub max_tickets: usize,
    pub max_reservations: usize,
    pub max_manifests: usize,
    pub max_attestations: usize,
    pub max_release_windows: usize,
    pub max_evidence: usize,
    pub max_tickets_per_manifest: usize,
    pub max_manifest_fee_units: u64,
    pub min_exit_units: u64,
    pub max_exit_units: u64,
    pub min_ring_size: u64,
    pub target_ring_size: u64,
    pub reservation_ttl_blocks: u64,
    pub batch_window_blocks: u64,
    pub release_delay_blocks: u64,
    pub challenge_window_blocks: u64,
    pub finality_depth_blocks: u64,
    pub reorg_grace_blocks: u64,
    pub pq_quorum_weight: u64,
    pub watcher_bond_units: u64,
    pub sponsor_bond_units: u64,
    pub default_fee_cap_micro_units: u64,
    pub privacy_floor_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub slashing_reward_bps: u64,
    pub hash_suite: String,
    pub pq_suite: String,
    pub commitment_scheme: String,
    pub manifest_scheme: String,
    pub release_scheme: String,
    pub slashing_scheme: String,
}

impl Default for MoneroFeeSponsoredExitAggregatorConfig {
    fn default() -> Self {
        Self {
            monero_network: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEVNET_MONERO_NETWORK.to_string(),
            l2_network: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEVNET_L2_NETWORK.to_string(),
            asset_id: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEVNET_FEE_ASSET_ID.to_string(),
            max_lanes: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_LANES,
            max_sponsors: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_SPONSORS,
            max_tickets: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_TICKETS,
            max_reservations: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_RESERVATIONS,
            max_manifests: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_MANIFESTS,
            max_attestations: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_ATTESTATIONS,
            max_release_windows: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_RELEASE_WINDOWS,
            max_evidence: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_EVIDENCE,
            max_tickets_per_manifest:
                MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_TICKETS_PER_MANIFEST,
            max_manifest_fee_units:
                MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_MANIFEST_FEE_UNITS,
            min_exit_units: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MIN_EXIT_UNITS,
            max_exit_units: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MAX_EXIT_UNITS,
            min_ring_size: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MIN_RING_SIZE,
            target_ring_size: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_TARGET_RING_SIZE,
            reservation_ttl_blocks:
                MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_RESERVATION_TTL_BLOCKS,
            batch_window_blocks: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_BATCH_WINDOW_BLOCKS,
            release_delay_blocks: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_RELEASE_DELAY_BLOCKS,
            challenge_window_blocks:
                MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            finality_depth_blocks:
                MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_FINALITY_DEPTH_BLOCKS,
            reorg_grace_blocks: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_REORG_GRACE_BLOCKS,
            pq_quorum_weight: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_PQ_QUORUM_WEIGHT,
            watcher_bond_units: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_WATCHER_BOND_UNITS,
            sponsor_bond_units: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_SPONSOR_BOND_UNITS,
            default_fee_cap_micro_units:
                MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_FEE_CAP_MICRO_UNITS,
            privacy_floor_bps: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_PRIVACY_FLOOR_BPS,
            sponsor_rebate_bps: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_SPONSOR_REBATE_BPS,
            slashing_reward_bps: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_SLASHING_REWARD_BPS,
            hash_suite: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_HASH_SUITE.to_string(),
            pq_suite: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_PQ_SUITE.to_string(),
            commitment_scheme: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_COMMITMENT_SCHEME.to_string(),
            manifest_scheme: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MANIFEST_SCHEME.to_string(),
            release_scheme: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_RELEASE_SCHEME.to_string(),
            slashing_scheme: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_SLASHING_SCHEME.to_string(),
        }
    }
}

impl MoneroFeeSponsoredExitAggregatorConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        ensure_non_empty("config.monero_network", &self.monero_network)?;
        ensure_non_empty("config.l2_network", &self.l2_network)?;
        ensure_non_empty("config.asset_id", &self.asset_id)?;
        ensure_non_empty("config.fee_asset_id", &self.fee_asset_id)?;
        ensure_non_empty("config.hash_suite", &self.hash_suite)?;
        ensure_non_empty("config.pq_suite", &self.pq_suite)?;
        ensure_non_empty("config.commitment_scheme", &self.commitment_scheme)?;
        ensure_non_empty("config.manifest_scheme", &self.manifest_scheme)?;
        ensure_non_empty("config.release_scheme", &self.release_scheme)?;
        ensure_non_empty("config.slashing_scheme", &self.slashing_scheme)?;
        ensure_positive_usize("config.max_lanes", self.max_lanes)?;
        ensure_positive_usize("config.max_sponsors", self.max_sponsors)?;
        ensure_positive_usize("config.max_tickets", self.max_tickets)?;
        ensure_positive_usize("config.max_reservations", self.max_reservations)?;
        ensure_positive_usize("config.max_manifests", self.max_manifests)?;
        ensure_positive_usize("config.max_attestations", self.max_attestations)?;
        ensure_positive_usize("config.max_release_windows", self.max_release_windows)?;
        ensure_positive_usize("config.max_evidence", self.max_evidence)?;
        ensure_positive_usize(
            "config.max_tickets_per_manifest",
            self.max_tickets_per_manifest,
        )?;
        ensure_positive("config.max_manifest_fee_units", self.max_manifest_fee_units)?;
        ensure_positive("config.min_exit_units", self.min_exit_units)?;
        ensure_positive("config.max_exit_units", self.max_exit_units)?;
        ensure_positive("config.min_ring_size", self.min_ring_size)?;
        ensure_positive("config.target_ring_size", self.target_ring_size)?;
        ensure_positive("config.reservation_ttl_blocks", self.reservation_ttl_blocks)?;
        ensure_positive("config.batch_window_blocks", self.batch_window_blocks)?;
        ensure_positive("config.release_delay_blocks", self.release_delay_blocks)?;
        ensure_positive(
            "config.challenge_window_blocks",
            self.challenge_window_blocks,
        )?;
        ensure_positive("config.finality_depth_blocks", self.finality_depth_blocks)?;
        ensure_positive("config.pq_quorum_weight", self.pq_quorum_weight)?;
        ensure_positive("config.watcher_bond_units", self.watcher_bond_units)?;
        ensure_positive("config.sponsor_bond_units", self.sponsor_bond_units)?;
        if self.min_exit_units > self.max_exit_units {
            return Err("config min exit units exceeds max exit units".to_string());
        }
        if self.min_ring_size > self.target_ring_size {
            return Err("config min ring size exceeds target ring size".to_string());
        }
        if self.privacy_floor_bps > MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MAX_BPS {
            return Err("config privacy floor exceeds bps cap".to_string());
        }
        if self.sponsor_rebate_bps > MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MAX_BPS {
            return Err("config sponsor rebate exceeds bps cap".to_string());
        }
        if self.slashing_reward_bps > MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MAX_BPS {
            return Err("config slashing reward exceeds bps cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_sponsored_exit_aggregator_config",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_PROTOCOL_VERSION,
            "schema_version": MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_SCHEMA_VERSION,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "max_lanes": self.max_lanes,
            "max_sponsors": self.max_sponsors,
            "max_tickets": self.max_tickets,
            "max_reservations": self.max_reservations,
            "max_manifests": self.max_manifests,
            "max_attestations": self.max_attestations,
            "max_release_windows": self.max_release_windows,
            "max_evidence": self.max_evidence,
            "max_tickets_per_manifest": self.max_tickets_per_manifest,
            "max_manifest_fee_units": self.max_manifest_fee_units,
            "min_exit_units": self.min_exit_units,
            "max_exit_units": self.max_exit_units,
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "batch_window_blocks": self.batch_window_blocks,
            "release_delay_blocks": self.release_delay_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "finality_depth_blocks": self.finality_depth_blocks,
            "reorg_grace_blocks": self.reorg_grace_blocks,
            "pq_quorum_weight": self.pq_quorum_weight,
            "watcher_bond_units": self.watcher_bond_units,
            "sponsor_bond_units": self.sponsor_bond_units,
            "default_fee_cap_micro_units": self.default_fee_cap_micro_units,
            "privacy_floor_bps": self.privacy_floor_bps,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "slashing_reward_bps": self.slashing_reward_bps,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "commitment_scheme": self.commitment_scheme,
            "manifest_scheme": self.manifest_scheme,
            "release_scheme": self.release_scheme,
            "slashing_scheme": self.slashing_scheme,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitLane {
    pub lane_id: String,
    pub lane_kind: ExitLaneKind,
    pub display_name: String,
    pub status: LaneStatus,
    pub fee_cap_micro_units: u64,
    pub priority_weight: u64,
    pub max_ticket_units: u64,
    pub max_open_tickets: usize,
    pub privacy_floor_bps: u64,
    pub min_ring_size: u64,
    pub ticket_ttl_blocks: u64,
    pub created_height: u64,
    pub updated_height: u64,
    pub sponsor_allowlist_root: String,
    pub policy_root: String,
    pub notes: String,
}

impl ExitLane {
    pub fn devnet(kind: ExitLaneKind, height: u64) -> Self {
        let lane_id = kind.default_lane_id().to_string();
        let policy_root = record_root(&json!({
            "kind": "exit_lane_policy_seed",
            "lane_id": lane_id,
            "lane_kind": kind.as_str(),
            "mode": "low_fee_private_exit",
        }));
        Self {
            lane_id,
            lane_kind: kind,
            display_name: kind.as_str().replace('_', " "),
            status: LaneStatus::Active,
            fee_cap_micro_units: kind.default_fee_cap_micro_units(),
            priority_weight: kind.default_priority_weight(),
            max_ticket_units: 1_000_000_000,
            max_open_tickets: 1_024,
            privacy_floor_bps: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_PRIVACY_FLOOR_BPS,
            min_ring_size: MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEFAULT_MIN_RING_SIZE,
            ticket_ttl_blocks: 72,
            created_height: height,
            updated_height: height,
            sponsor_allowlist_root: empty_root("LANE-SPONSOR-ALLOWLIST"),
            policy_root,
            notes: "devnet sponsored exit lane".to_string(),
        }
    }

    pub fn validate(&self) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        ensure_non_empty("lane.lane_id", &self.lane_id)?;
        ensure_non_empty("lane.display_name", &self.display_name)?;
        ensure_non_empty("lane.sponsor_allowlist_root", &self.sponsor_allowlist_root)?;
        ensure_non_empty("lane.policy_root", &self.policy_root)?;
        ensure_positive("lane.fee_cap_micro_units", self.fee_cap_micro_units)?;
        ensure_positive("lane.priority_weight", self.priority_weight)?;
        ensure_positive("lane.max_ticket_units", self.max_ticket_units)?;
        ensure_positive_usize("lane.max_open_tickets", self.max_open_tickets)?;
        ensure_positive("lane.min_ring_size", self.min_ring_size)?;
        ensure_positive("lane.ticket_ttl_blocks", self.ticket_ttl_blocks)?;
        if self.privacy_floor_bps > MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MAX_BPS {
            return Err(format!(
                "lane {} privacy floor exceeds bps cap",
                self.lane_id
            ));
        }
        if self.updated_height < self.created_height {
            return Err(format!("lane {} updated before created", self.lane_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_sponsored_exit_lane",
            "lane_id": self.lane_id,
            "lane_kind": self.lane_kind.as_str(),
            "display_name": self.display_name,
            "status": self.status.as_str(),
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "priority_weight": self.priority_weight,
            "max_ticket_units": self.max_ticket_units,
            "max_open_tickets": self.max_open_tickets,
            "privacy_floor_bps": self.privacy_floor_bps,
            "min_ring_size": self.min_ring_size,
            "ticket_ttl_blocks": self.ticket_ttl_blocks,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
            "sponsor_allowlist_root": self.sponsor_allowlist_root,
            "policy_root": self.policy_root,
            "notes": self.notes,
        })
    }

    pub fn root(&self) -> String {
        record_root(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitTicket {
    pub ticket_id: String,
    pub lane_id: String,
    pub status: ExitTicketStatus,
    pub exit_nullifier: String,
    pub recipient_commitment: String,
    pub amount_commitment: String,
    pub fee_commitment: String,
    pub view_tag_root: String,
    pub key_image_root: String,
    pub stealth_address_root: String,
    pub sponsor_reservation_id: Option<String>,
    pub manifest_id: Option<String>,
    pub release_window_id: Option<String>,
    pub requested_units: u64,
    pub max_fee_micro_units: u64,
    pub ring_size: u64,
    pub priority_score: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub updated_height: u64,
    pub metadata_root: String,
}

impl ExitTicket {
    pub fn new(
        lane_id: &str,
        exit_nullifier: &str,
        recipient_commitment: &str,
        amount_commitment: &str,
        fee_commitment: &str,
        requested_units: u64,
        max_fee_micro_units: u64,
        ring_size: u64,
        submitted_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let ticket_id = ticket_id(
            lane_id,
            exit_nullifier,
            recipient_commitment,
            amount_commitment,
            submitted_height,
        );
        Self {
            ticket_id,
            lane_id: lane_id.to_string(),
            status: ExitTicketStatus::Submitted,
            exit_nullifier: exit_nullifier.to_string(),
            recipient_commitment: recipient_commitment.to_string(),
            amount_commitment: amount_commitment.to_string(),
            fee_commitment: fee_commitment.to_string(),
            view_tag_root: string_root("TICKET-VIEW-TAG", recipient_commitment),
            key_image_root: string_root("TICKET-KEY-IMAGE", exit_nullifier),
            stealth_address_root: string_root("TICKET-STEALTH-ADDRESS", recipient_commitment),
            sponsor_reservation_id: None,
            manifest_id: None,
            release_window_id: None,
            requested_units,
            max_fee_micro_units,
            ring_size,
            priority_score: 0,
            submitted_height,
            expires_height: submitted_height.saturating_add(ttl_blocks),
            updated_height: submitted_height,
            metadata_root: empty_root("TICKET-METADATA"),
        }
    }

    pub fn validate(&self) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        ensure_non_empty("ticket.ticket_id", &self.ticket_id)?;
        ensure_non_empty("ticket.lane_id", &self.lane_id)?;
        ensure_non_empty("ticket.exit_nullifier", &self.exit_nullifier)?;
        ensure_non_empty("ticket.recipient_commitment", &self.recipient_commitment)?;
        ensure_non_empty("ticket.amount_commitment", &self.amount_commitment)?;
        ensure_non_empty("ticket.fee_commitment", &self.fee_commitment)?;
        ensure_non_empty("ticket.view_tag_root", &self.view_tag_root)?;
        ensure_non_empty("ticket.key_image_root", &self.key_image_root)?;
        ensure_non_empty("ticket.stealth_address_root", &self.stealth_address_root)?;
        ensure_non_empty("ticket.metadata_root", &self.metadata_root)?;
        ensure_positive("ticket.requested_units", self.requested_units)?;
        ensure_positive("ticket.max_fee_micro_units", self.max_fee_micro_units)?;
        ensure_positive("ticket.ring_size", self.ring_size)?;
        if self.expires_height <= self.submitted_height {
            return Err(format!(
                "ticket {} expiry is not after submission",
                self.ticket_id
            ));
        }
        if self.updated_height < self.submitted_height {
            return Err(format!(
                "ticket {} updated before submission",
                self.ticket_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_sponsored_exit_ticket",
            "ticket_id": self.ticket_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "exit_nullifier": self.exit_nullifier,
            "recipient_commitment": self.recipient_commitment,
            "amount_commitment": self.amount_commitment,
            "fee_commitment": self.fee_commitment,
            "view_tag_root": self.view_tag_root,
            "key_image_root": self.key_image_root,
            "stealth_address_root": self.stealth_address_root,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "manifest_id": self.manifest_id,
            "release_window_id": self.release_window_id,
            "requested_units": self.requested_units,
            "max_fee_micro_units": self.max_fee_micro_units,
            "ring_size": self.ring_size,
            "priority_score": self.priority_score,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "updated_height": self.updated_height,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn root(&self) -> String {
        record_root(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorAccount {
    pub sponsor_id: String,
    pub status: SponsorAccountStatus,
    pub operator_commitment: String,
    pub pq_verification_key_root: String,
    pub reserve_commitment: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub slashed_units: u64,
    pub lane_allowance_bps: BTreeMap<String, u64>,
    pub fee_cap_micro_units: u64,
    pub rebate_bps: u64,
    pub bond_units: u64,
    pub created_height: u64,
    pub updated_height: u64,
    pub expiry_height: u64,
    pub policy_root: String,
}

impl SponsorAccount {
    pub fn new(
        operator_commitment: &str,
        pq_verification_key_root: &str,
        reserve_commitment: &str,
        budget_units: u64,
        fee_cap_micro_units: u64,
        rebate_bps: u64,
        bond_units: u64,
        height: u64,
        expiry_height: u64,
    ) -> Self {
        let sponsor_id = sponsor_id(operator_commitment, pq_verification_key_root, height);
        Self {
            sponsor_id,
            status: SponsorAccountStatus::Active,
            operator_commitment: operator_commitment.to_string(),
            pq_verification_key_root: pq_verification_key_root.to_string(),
            reserve_commitment: reserve_commitment.to_string(),
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            slashed_units: 0,
            lane_allowance_bps: BTreeMap::new(),
            fee_cap_micro_units,
            rebate_bps,
            bond_units,
            created_height: height,
            updated_height: height,
            expiry_height,
            policy_root: empty_root("SPONSOR-POLICY"),
        }
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
            .saturating_sub(self.slashed_units)
    }

    pub fn validate(&self) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        ensure_non_empty("sponsor.sponsor_id", &self.sponsor_id)?;
        ensure_non_empty("sponsor.operator_commitment", &self.operator_commitment)?;
        ensure_non_empty(
            "sponsor.pq_verification_key_root",
            &self.pq_verification_key_root,
        )?;
        ensure_non_empty("sponsor.reserve_commitment", &self.reserve_commitment)?;
        ensure_non_empty("sponsor.policy_root", &self.policy_root)?;
        ensure_positive("sponsor.budget_units", self.budget_units)?;
        ensure_positive("sponsor.fee_cap_micro_units", self.fee_cap_micro_units)?;
        ensure_positive("sponsor.bond_units", self.bond_units)?;
        if self.rebate_bps > MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MAX_BPS {
            return Err(format!(
                "sponsor {} rebate exceeds bps cap",
                self.sponsor_id
            ));
        }
        for (lane_id, bps) in &self.lane_allowance_bps {
            ensure_non_empty("sponsor.lane_allowance.lane_id", lane_id)?;
            if *bps > MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MAX_BPS {
                return Err(format!(
                    "sponsor {} lane allowance exceeds bps cap",
                    self.sponsor_id
                ));
            }
        }
        if self.updated_height < self.created_height {
            return Err(format!(
                "sponsor {} updated before created",
                self.sponsor_id
            ));
        }
        if self.expiry_height <= self.created_height {
            return Err(format!(
                "sponsor {} expiry is not after creation",
                self.sponsor_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_sponsored_exit_sponsor_account",
            "sponsor_id": self.sponsor_id,
            "status": self.status.as_str(),
            "operator_commitment": self.operator_commitment,
            "pq_verification_key_root": self.pq_verification_key_root,
            "reserve_commitment": self.reserve_commitment,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "slashed_units": self.slashed_units,
            "lane_allowance_bps": self.lane_allowance_bps,
            "fee_cap_micro_units": self.fee_cap_micro_units,
            "rebate_bps": self.rebate_bps,
            "bond_units": self.bond_units,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
            "expiry_height": self.expiry_height,
            "policy_root": self.policy_root,
            "available_units": self.available_units(),
        })
    }

    pub fn root(&self) -> String {
        record_root(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorshipReservation {
    pub reservation_id: String,
    pub sponsor_id: String,
    pub lane_id: String,
    pub ticket_id: Option<String>,
    pub status: SponsorshipReservationStatus,
    pub reserved_fee_units: u64,
    pub max_fee_micro_units: u64,
    pub commitment_root: String,
    pub credential_nullifier: String,
    pub created_height: u64,
    pub expires_height: u64,
    pub consumed_height: Option<u64>,
    pub updated_height: u64,
}

impl SponsorshipReservation {
    pub fn new(
        sponsor_id: &str,
        lane_id: &str,
        credential_nullifier: &str,
        reserved_fee_units: u64,
        max_fee_micro_units: u64,
        created_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let reservation_id = reservation_id(
            sponsor_id,
            lane_id,
            credential_nullifier,
            reserved_fee_units,
            created_height,
        );
        let commitment_root = record_root(&json!({
            "kind": "sponsorship_commitment",
            "sponsor_id": sponsor_id,
            "lane_id": lane_id,
            "credential_nullifier": credential_nullifier,
            "reserved_fee_units": reserved_fee_units,
            "created_height": created_height,
        }));
        Self {
            reservation_id,
            sponsor_id: sponsor_id.to_string(),
            lane_id: lane_id.to_string(),
            ticket_id: None,
            status: SponsorshipReservationStatus::Held,
            reserved_fee_units,
            max_fee_micro_units,
            commitment_root,
            credential_nullifier: credential_nullifier.to_string(),
            created_height,
            expires_height: created_height.saturating_add(ttl_blocks),
            consumed_height: None,
            updated_height: created_height,
        }
    }

    pub fn validate(&self) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        ensure_non_empty("reservation.reservation_id", &self.reservation_id)?;
        ensure_non_empty("reservation.sponsor_id", &self.sponsor_id)?;
        ensure_non_empty("reservation.lane_id", &self.lane_id)?;
        ensure_non_empty("reservation.commitment_root", &self.commitment_root)?;
        ensure_non_empty(
            "reservation.credential_nullifier",
            &self.credential_nullifier,
        )?;
        ensure_positive("reservation.reserved_fee_units", self.reserved_fee_units)?;
        ensure_positive("reservation.max_fee_micro_units", self.max_fee_micro_units)?;
        if self.expires_height <= self.created_height {
            return Err(format!(
                "reservation {} expiry is not after creation",
                self.reservation_id
            ));
        }
        if self.updated_height < self.created_height {
            return Err(format!(
                "reservation {} updated before created",
                self.reservation_id
            ));
        }
        if let Some(consumed_height) = self.consumed_height {
            if consumed_height < self.created_height {
                return Err(format!(
                    "reservation {} consumed before created",
                    self.reservation_id
                ));
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_sponsored_exit_reservation",
            "reservation_id": self.reservation_id,
            "sponsor_id": self.sponsor_id,
            "lane_id": self.lane_id,
            "ticket_id": self.ticket_id,
            "status": self.status.as_str(),
            "reserved_fee_units": self.reserved_fee_units,
            "max_fee_micro_units": self.max_fee_micro_units,
            "commitment_root": self.commitment_root,
            "credential_nullifier": self.credential_nullifier,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "consumed_height": self.consumed_height,
            "updated_height": self.updated_height,
        })
    }

    pub fn root(&self) -> String {
        record_root(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchedExitManifest {
    pub manifest_id: String,
    pub lane_id: String,
    pub status: ManifestStatus,
    pub ticket_ids: Vec<String>,
    pub ticket_root: String,
    pub reservation_root: String,
    pub fee_commitment_root: String,
    pub exit_nullifier_root: String,
    pub compact_payload_root: String,
    pub aggregate_amount_commitment: String,
    pub aggregate_fee_units: u64,
    pub total_exit_units: u64,
    pub privacy_score_bps: u64,
    pub pq_attestation_weight: u64,
    pub min_release_height: u64,
    pub challenge_deadline_height: u64,
    pub created_height: u64,
    pub sealed_height: Option<u64>,
    pub updated_height: u64,
}

impl BatchedExitManifest {
    pub fn new(
        lane_id: &str,
        ticket_records: &[Value],
        reservation_records: &[Value],
        total_exit_units: u64,
        aggregate_fee_units: u64,
        privacy_score_bps: u64,
        height: u64,
        release_delay_blocks: u64,
        challenge_window_blocks: u64,
    ) -> Self {
        let ticket_ids = ticket_records
            .iter()
            .filter_map(|record| {
                record
                    .get("ticket_id")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect::<Vec<_>>();
        let ticket_root = merkle_root("MONERO-FEE-SPONSORED-EXIT-TICKETS", ticket_records);
        let reservation_root = merkle_root(
            "MONERO-FEE-SPONSORED-EXIT-RESERVATIONS",
            reservation_records,
        );
        let fee_commitment_root = record_root(&json!({
            "kind": "manifest_fee_commitments",
            "lane_id": lane_id,
            "ticket_root": ticket_root,
            "aggregate_fee_units": aggregate_fee_units,
        }));
        let exit_nullifier_root = record_root(&json!({
            "kind": "manifest_exit_nullifiers",
            "lane_id": lane_id,
            "ticket_root": ticket_root,
        }));
        let compact_payload_root = record_root(&json!({
            "kind": "compact_manifest_payload",
            "lane_id": lane_id,
            "ticket_root": ticket_root,
            "reservation_root": reservation_root,
            "total_exit_units": total_exit_units,
        }));
        let manifest_id = manifest_id(lane_id, &ticket_root, height);
        Self {
            manifest_id,
            lane_id: lane_id.to_string(),
            status: ManifestStatus::Collecting,
            ticket_ids,
            ticket_root,
            reservation_root,
            fee_commitment_root,
            exit_nullifier_root,
            compact_payload_root,
            aggregate_amount_commitment: string_root("MANIFEST-AMOUNT", lane_id),
            aggregate_fee_units,
            total_exit_units,
            privacy_score_bps,
            pq_attestation_weight: 0,
            min_release_height: height.saturating_add(release_delay_blocks),
            challenge_deadline_height: height
                .saturating_add(release_delay_blocks)
                .saturating_add(challenge_window_blocks),
            created_height: height,
            sealed_height: None,
            updated_height: height,
        }
    }

    pub fn validate(&self) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        ensure_non_empty("manifest.manifest_id", &self.manifest_id)?;
        ensure_non_empty("manifest.lane_id", &self.lane_id)?;
        ensure_non_empty("manifest.ticket_root", &self.ticket_root)?;
        ensure_non_empty("manifest.reservation_root", &self.reservation_root)?;
        ensure_non_empty("manifest.fee_commitment_root", &self.fee_commitment_root)?;
        ensure_non_empty("manifest.exit_nullifier_root", &self.exit_nullifier_root)?;
        ensure_non_empty("manifest.compact_payload_root", &self.compact_payload_root)?;
        ensure_non_empty(
            "manifest.aggregate_amount_commitment",
            &self.aggregate_amount_commitment,
        )?;
        ensure_positive("manifest.aggregate_fee_units", self.aggregate_fee_units)?;
        ensure_positive("manifest.total_exit_units", self.total_exit_units)?;
        if self.ticket_ids.is_empty() {
            return Err(format!("manifest {} has no tickets", self.manifest_id));
        }
        if self.privacy_score_bps > MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MAX_BPS {
            return Err(format!(
                "manifest {} privacy score exceeds bps cap",
                self.manifest_id
            ));
        }
        if self.min_release_height <= self.created_height {
            return Err(format!(
                "manifest {} release height too early",
                self.manifest_id
            ));
        }
        if self.challenge_deadline_height <= self.min_release_height {
            return Err(format!(
                "manifest {} challenge deadline too early",
                self.manifest_id
            ));
        }
        if self.updated_height < self.created_height {
            return Err(format!(
                "manifest {} updated before created",
                self.manifest_id
            ));
        }
        if let Some(sealed_height) = self.sealed_height {
            if sealed_height < self.created_height {
                return Err(format!(
                    "manifest {} sealed before created",
                    self.manifest_id
                ));
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_sponsored_exit_manifest",
            "manifest_id": self.manifest_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "ticket_ids": self.ticket_ids,
            "ticket_root": self.ticket_root,
            "reservation_root": self.reservation_root,
            "fee_commitment_root": self.fee_commitment_root,
            "exit_nullifier_root": self.exit_nullifier_root,
            "compact_payload_root": self.compact_payload_root,
            "aggregate_amount_commitment": self.aggregate_amount_commitment,
            "aggregate_fee_units": self.aggregate_fee_units,
            "total_exit_units": self.total_exit_units,
            "privacy_score_bps": self.privacy_score_bps,
            "pq_attestation_weight": self.pq_attestation_weight,
            "min_release_height": self.min_release_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "created_height": self.created_height,
            "sealed_height": self.sealed_height,
            "updated_height": self.updated_height,
        })
    }

    pub fn root(&self) -> String {
        record_root(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWatcherAttestation {
    pub attestation_id: String,
    pub watcher_id: String,
    pub manifest_id: String,
    pub status: WatcherAttestationStatus,
    pub attested_manifest_root: String,
    pub pq_signature_root: String,
    pub watcher_key_root: String,
    pub quorum_weight: u64,
    pub latency_micros: u64,
    pub privacy_score_bps: u64,
    pub observed_height: u64,
    pub submitted_height: u64,
    pub supersedes_attestation_id: Option<String>,
    pub notes_root: String,
}

impl PqWatcherAttestation {
    pub fn new(
        watcher_id: &str,
        manifest_id: &str,
        attested_manifest_root: &str,
        watcher_key_root: &str,
        quorum_weight: u64,
        latency_micros: u64,
        privacy_score_bps: u64,
        observed_height: u64,
        submitted_height: u64,
    ) -> Self {
        let pq_signature_root = record_root(&json!({
            "kind": "pq_watcher_signature_seed",
            "watcher_id": watcher_id,
            "manifest_id": manifest_id,
            "attested_manifest_root": attested_manifest_root,
            "submitted_height": submitted_height,
        }));
        let attestation_id = attestation_id(watcher_id, manifest_id, &pq_signature_root);
        Self {
            attestation_id,
            watcher_id: watcher_id.to_string(),
            manifest_id: manifest_id.to_string(),
            status: WatcherAttestationStatus::Submitted,
            attested_manifest_root: attested_manifest_root.to_string(),
            pq_signature_root,
            watcher_key_root: watcher_key_root.to_string(),
            quorum_weight,
            latency_micros,
            privacy_score_bps,
            observed_height,
            submitted_height,
            supersedes_attestation_id: None,
            notes_root: empty_root("WATCHER-ATTESTATION-NOTES"),
        }
    }

    pub fn validate(&self) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        ensure_non_empty("attestation.attestation_id", &self.attestation_id)?;
        ensure_non_empty("attestation.watcher_id", &self.watcher_id)?;
        ensure_non_empty("attestation.manifest_id", &self.manifest_id)?;
        ensure_non_empty(
            "attestation.attested_manifest_root",
            &self.attested_manifest_root,
        )?;
        ensure_non_empty("attestation.pq_signature_root", &self.pq_signature_root)?;
        ensure_non_empty("attestation.watcher_key_root", &self.watcher_key_root)?;
        ensure_non_empty("attestation.notes_root", &self.notes_root)?;
        ensure_positive("attestation.quorum_weight", self.quorum_weight)?;
        if self.privacy_score_bps > MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MAX_BPS {
            return Err(format!(
                "attestation {} privacy score exceeds bps cap",
                self.attestation_id
            ));
        }
        if self.submitted_height < self.observed_height {
            return Err(format!(
                "attestation {} submitted before observed",
                self.attestation_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_sponsored_exit_pq_watcher_attestation",
            "attestation_id": self.attestation_id,
            "watcher_id": self.watcher_id,
            "manifest_id": self.manifest_id,
            "status": self.status.as_str(),
            "attested_manifest_root": self.attested_manifest_root,
            "pq_signature_root": self.pq_signature_root,
            "watcher_key_root": self.watcher_key_root,
            "quorum_weight": self.quorum_weight,
            "latency_micros": self.latency_micros,
            "privacy_score_bps": self.privacy_score_bps,
            "observed_height": self.observed_height,
            "submitted_height": self.submitted_height,
            "supersedes_attestation_id": self.supersedes_attestation_id,
            "notes_root": self.notes_root,
        })
    }

    pub fn root(&self) -> String {
        record_root(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseWindow {
    pub release_window_id: String,
    pub manifest_id: String,
    pub status: ReleaseWindowStatus,
    pub scheduled_height: u64,
    pub opens_height: u64,
    pub closes_height: u64,
    pub challenge_deadline_height: u64,
    pub release_root: String,
    pub payout_commitment_root: String,
    pub watcher_attestation_root: String,
    pub released_ticket_count: usize,
    pub released_fee_units: u64,
    pub created_height: u64,
    pub updated_height: u64,
}

impl ReleaseWindow {
    pub fn new(
        manifest_id: &str,
        release_root: &str,
        payout_commitment_root: &str,
        watcher_attestation_root: &str,
        scheduled_height: u64,
        release_delay_blocks: u64,
        challenge_window_blocks: u64,
    ) -> Self {
        let opens_height = scheduled_height.saturating_add(release_delay_blocks);
        let closes_height = opens_height.saturating_add(challenge_window_blocks);
        let challenge_deadline_height = closes_height;
        let release_window_id = release_window_id(manifest_id, release_root, opens_height);
        Self {
            release_window_id,
            manifest_id: manifest_id.to_string(),
            status: ReleaseWindowStatus::Scheduled,
            scheduled_height,
            opens_height,
            closes_height,
            challenge_deadline_height,
            release_root: release_root.to_string(),
            payout_commitment_root: payout_commitment_root.to_string(),
            watcher_attestation_root: watcher_attestation_root.to_string(),
            released_ticket_count: 0,
            released_fee_units: 0,
            created_height: scheduled_height,
            updated_height: scheduled_height,
        }
    }

    pub fn validate(&self) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        ensure_non_empty("release_window.release_window_id", &self.release_window_id)?;
        ensure_non_empty("release_window.manifest_id", &self.manifest_id)?;
        ensure_non_empty("release_window.release_root", &self.release_root)?;
        ensure_non_empty(
            "release_window.payout_commitment_root",
            &self.payout_commitment_root,
        )?;
        ensure_non_empty(
            "release_window.watcher_attestation_root",
            &self.watcher_attestation_root,
        )?;
        if self.opens_height <= self.scheduled_height {
            return Err(format!(
                "release window {} opens too early",
                self.release_window_id
            ));
        }
        if self.closes_height <= self.opens_height {
            return Err(format!(
                "release window {} closes too early",
                self.release_window_id
            ));
        }
        if self.challenge_deadline_height < self.closes_height {
            return Err(format!(
                "release window {} challenge deadline before close",
                self.release_window_id
            ));
        }
        if self.updated_height < self.created_height {
            return Err(format!(
                "release window {} updated before created",
                self.release_window_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_sponsored_exit_release_window",
            "release_window_id": self.release_window_id,
            "manifest_id": self.manifest_id,
            "status": self.status.as_str(),
            "scheduled_height": self.scheduled_height,
            "opens_height": self.opens_height,
            "closes_height": self.closes_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "release_root": self.release_root,
            "payout_commitment_root": self.payout_commitment_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "released_ticket_count": self.released_ticket_count,
            "released_fee_units": self.released_fee_units,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }

    pub fn root(&self) -> String {
        record_root(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub evidence_kind: SlashingEvidenceKind,
    pub status: String,
    pub accused_id: String,
    pub reporter_id: String,
    pub manifest_id: Option<String>,
    pub ticket_id: Option<String>,
    pub reservation_id: Option<String>,
    pub attestation_id: Option<String>,
    pub release_window_id: Option<String>,
    pub claim_root: String,
    pub encrypted_payload_root: String,
    pub public_payload_root: String,
    pub requested_slash_bps: u64,
    pub reward_bps: u64,
    pub submitted_height: u64,
    pub challenge_deadline_height: u64,
    pub resolved_height: Option<u64>,
}

impl SlashingEvidence {
    pub fn new(
        evidence_kind: SlashingEvidenceKind,
        accused_id: &str,
        reporter_id: &str,
        claim_root: &str,
        submitted_height: u64,
        challenge_window_blocks: u64,
        reward_bps: u64,
    ) -> Self {
        let evidence_id = evidence_id(evidence_kind, accused_id, reporter_id, claim_root);
        Self {
            evidence_id,
            evidence_kind,
            status: "submitted".to_string(),
            accused_id: accused_id.to_string(),
            reporter_id: reporter_id.to_string(),
            manifest_id: None,
            ticket_id: None,
            reservation_id: None,
            attestation_id: None,
            release_window_id: None,
            claim_root: claim_root.to_string(),
            encrypted_payload_root: empty_root("SLASHING-ENCRYPTED-PAYLOAD"),
            public_payload_root: empty_root("SLASHING-PUBLIC-PAYLOAD"),
            requested_slash_bps: evidence_kind.default_slash_bps(),
            reward_bps,
            submitted_height,
            challenge_deadline_height: submitted_height.saturating_add(challenge_window_blocks),
            resolved_height: None,
        }
    }

    pub fn validate(&self) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        ensure_non_empty("evidence.evidence_id", &self.evidence_id)?;
        ensure_non_empty("evidence.status", &self.status)?;
        ensure_non_empty("evidence.accused_id", &self.accused_id)?;
        ensure_non_empty("evidence.reporter_id", &self.reporter_id)?;
        ensure_non_empty("evidence.claim_root", &self.claim_root)?;
        ensure_non_empty(
            "evidence.encrypted_payload_root",
            &self.encrypted_payload_root,
        )?;
        ensure_non_empty("evidence.public_payload_root", &self.public_payload_root)?;
        if self.requested_slash_bps > MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MAX_BPS {
            return Err(format!(
                "evidence {} slash exceeds bps cap",
                self.evidence_id
            ));
        }
        if self.reward_bps > MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MAX_BPS {
            return Err(format!(
                "evidence {} reward exceeds bps cap",
                self.evidence_id
            ));
        }
        if self.challenge_deadline_height <= self.submitted_height {
            return Err(format!(
                "evidence {} challenge deadline is not after submission",
                self.evidence_id
            ));
        }
        if let Some(resolved_height) = self.resolved_height {
            if resolved_height < self.submitted_height {
                return Err(format!(
                    "evidence {} resolved before submission",
                    self.evidence_id
                ));
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_sponsored_exit_slashing_evidence",
            "evidence_id": self.evidence_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "status": self.status,
            "accused_id": self.accused_id,
            "reporter_id": self.reporter_id,
            "manifest_id": self.manifest_id,
            "ticket_id": self.ticket_id,
            "reservation_id": self.reservation_id,
            "attestation_id": self.attestation_id,
            "release_window_id": self.release_window_id,
            "claim_root": self.claim_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "public_payload_root": self.public_payload_root,
            "requested_slash_bps": self.requested_slash_bps,
            "reward_bps": self.reward_bps,
            "submitted_height": self.submitted_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "resolved_height": self.resolved_height,
        })
    }

    pub fn root(&self) -> String {
        record_root(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroFeeSponsoredExitAggregatorRoots {
    pub config_root: String,
    pub lane_root: String,
    pub ticket_root: String,
    pub sponsor_root: String,
    pub reservation_root: String,
    pub manifest_root: String,
    pub attestation_root: String,
    pub release_window_root: String,
    pub slashing_evidence_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl MoneroFeeSponsoredExitAggregatorRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_sponsored_exit_aggregator_roots",
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "ticket_root": self.ticket_root,
            "sponsor_root": self.sponsor_root,
            "reservation_root": self.reservation_root,
            "manifest_root": self.manifest_root,
            "attestation_root": self.attestation_root,
            "release_window_root": self.release_window_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroFeeSponsoredExitAggregatorCounters {
    pub lanes: usize,
    pub active_lanes: usize,
    pub tickets: usize,
    pub live_tickets: usize,
    pub sponsors: usize,
    pub active_sponsors: usize,
    pub reservations: usize,
    pub spendable_reservations: usize,
    pub manifests: usize,
    pub attestations: usize,
    pub release_windows: usize,
    pub slashing_evidence: usize,
    pub total_reserved_units: u64,
    pub total_spent_units: u64,
    pub total_slashed_units: u64,
    pub total_exit_units_manifested: u64,
    pub total_fee_units_manifested: u64,
}

impl MoneroFeeSponsoredExitAggregatorCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_sponsored_exit_aggregator_counters",
            "lanes": self.lanes,
            "active_lanes": self.active_lanes,
            "tickets": self.tickets,
            "live_tickets": self.live_tickets,
            "sponsors": self.sponsors,
            "active_sponsors": self.active_sponsors,
            "reservations": self.reservations,
            "spendable_reservations": self.spendable_reservations,
            "manifests": self.manifests,
            "attestations": self.attestations,
            "release_windows": self.release_windows,
            "slashing_evidence": self.slashing_evidence,
            "total_reserved_units": self.total_reserved_units,
            "total_spent_units": self.total_spent_units,
            "total_slashed_units": self.total_slashed_units,
            "total_exit_units_manifested": self.total_exit_units_manifested,
            "total_fee_units_manifested": self.total_fee_units_manifested,
        })
    }
}

pub type Config = MoneroFeeSponsoredExitAggregatorConfig;
pub type State = MoneroFeeSponsoredExitAggregatorState;
pub type Roots = MoneroFeeSponsoredExitAggregatorRoots;
pub type Counters = MoneroFeeSponsoredExitAggregatorCounters;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroFeeSponsoredExitAggregatorState {
    pub config: MoneroFeeSponsoredExitAggregatorConfig,
    pub height: u64,
    pub lanes: BTreeMap<String, ExitLane>,
    pub tickets: BTreeMap<String, ExitTicket>,
    pub sponsors: BTreeMap<String, SponsorAccount>,
    pub reservations: BTreeMap<String, SponsorshipReservation>,
    pub manifests: BTreeMap<String, BatchedExitManifest>,
    pub attestations: BTreeMap<String, PqWatcherAttestation>,
    pub release_windows: BTreeMap<String, ReleaseWindow>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl MoneroFeeSponsoredExitAggregatorState {
    pub fn devnet() -> MoneroFeeSponsoredExitAggregatorResult<Self> {
        let config = MoneroFeeSponsoredExitAggregatorConfig::devnet();
        config.validate()?;
        let height = MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_DEVNET_HEIGHT;
        let mut state = Self {
            config,
            height,
            lanes: BTreeMap::new(),
            tickets: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            reservations: BTreeMap::new(),
            manifests: BTreeMap::new(),
            attestations: BTreeMap::new(),
            release_windows: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        };
        for kind in [
            ExitLaneKind::WalletExit,
            ExitLaneKind::DefiSettlement,
            ExitLaneKind::ContractWithdrawal,
            ExitLaneKind::LiquidityMigration,
            ExitLaneKind::EmergencyEscape,
            ExitLaneKind::RecoveryPayout,
        ] {
            state.register_lane(ExitLane::devnet(kind, height))?;
        }
        Ok(state)
    }

    pub fn update_height(&mut self, height: u64) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        if height < self.height {
            return Err(format!(
                "height regression from {} to {} is not allowed",
                self.height, height
            ));
        }
        self.height = height;
        self.expire_stale_records();
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        self.update_height(height)
    }

    pub fn register_lane(
        &mut self,
        lane: ExitLane,
    ) -> MoneroFeeSponsoredExitAggregatorResult<String> {
        self.ensure_capacity("lanes", self.lanes.len(), self.config.max_lanes)?;
        lane.validate()?;
        if self.lanes.contains_key(&lane.lane_id) {
            return Err(format!("lane {} already exists", lane.lane_id));
        }
        if lane.created_height > self.height {
            return Err(format!("lane {} created in future", lane.lane_id));
        }
        let lane_id = lane.lane_id.clone();
        self.lanes.insert(lane_id.clone(), lane);
        Ok(lane_id)
    }

    pub fn update_lane_status(
        &mut self,
        lane_id: &str,
        status: LaneStatus,
    ) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| format!("lane {lane_id} not found"))?;
        lane.status = status;
        lane.updated_height = self.height;
        Ok(())
    }

    pub fn register_sponsor(
        &mut self,
        sponsor: SponsorAccount,
    ) -> MoneroFeeSponsoredExitAggregatorResult<String> {
        self.ensure_capacity("sponsors", self.sponsors.len(), self.config.max_sponsors)?;
        sponsor.validate()?;
        if self.sponsors.contains_key(&sponsor.sponsor_id) {
            return Err(format!("sponsor {} already exists", sponsor.sponsor_id));
        }
        if sponsor.created_height > self.height {
            return Err(format!("sponsor {} created in future", sponsor.sponsor_id));
        }
        let sponsor_id = sponsor.sponsor_id.clone();
        self.sponsors.insert(sponsor_id.clone(), sponsor);
        Ok(sponsor_id)
    }

    pub fn set_sponsor_lane_allowance(
        &mut self,
        sponsor_id: &str,
        lane_id: &str,
        allowance_bps: u64,
    ) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        if allowance_bps > MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MAX_BPS {
            return Err("sponsor lane allowance exceeds bps cap".to_string());
        }
        if !self.lanes.contains_key(lane_id) {
            return Err(format!("lane {lane_id} not found"));
        }
        let sponsor = self
            .sponsors
            .get_mut(sponsor_id)
            .ok_or_else(|| format!("sponsor {sponsor_id} not found"))?;
        sponsor
            .lane_allowance_bps
            .insert(lane_id.to_string(), allowance_bps);
        sponsor.updated_height = self.height;
        Ok(())
    }

    pub fn submit_ticket(
        &mut self,
        mut ticket: ExitTicket,
    ) -> MoneroFeeSponsoredExitAggregatorResult<String> {
        self.ensure_capacity("tickets", self.tickets.len(), self.config.max_tickets)?;
        ticket.validate()?;
        let lane = self
            .lanes
            .get(&ticket.lane_id)
            .ok_or_else(|| format!("lane {} not found", ticket.lane_id))?;
        if !lane.status.accepts_tickets() {
            return Err(format!("lane {} does not accept tickets", lane.lane_id));
        }
        if ticket.requested_units < self.config.min_exit_units
            || ticket.requested_units > self.config.max_exit_units
        {
            return Err(format!(
                "ticket {} requested units outside limits",
                ticket.ticket_id
            ));
        }
        if ticket.requested_units > lane.max_ticket_units {
            return Err(format!(
                "ticket {} exceeds lane max units",
                ticket.ticket_id
            ));
        }
        if ticket.max_fee_micro_units > lane.fee_cap_micro_units {
            return Err(format!("ticket {} exceeds lane fee cap", ticket.ticket_id));
        }
        if ticket.ring_size < lane.min_ring_size || ticket.ring_size < self.config.min_ring_size {
            return Err(format!(
                "ticket {} ring size below privacy floor",
                ticket.ticket_id
            ));
        }
        if self.spent_nullifiers.contains(&ticket.exit_nullifier)
            || self
                .tickets
                .values()
                .any(|known| known.exit_nullifier == ticket.exit_nullifier)
        {
            return Err(format!(
                "ticket {} has duplicate nullifier",
                ticket.ticket_id
            ));
        }
        if self.tickets.contains_key(&ticket.ticket_id) {
            return Err(format!("ticket {} already exists", ticket.ticket_id));
        }
        let open_for_lane = self
            .tickets
            .values()
            .filter(|known| known.lane_id == ticket.lane_id && known.status.is_live())
            .count();
        if open_for_lane >= lane.max_open_tickets {
            return Err(format!(
                "lane {} open ticket capacity reached",
                lane.lane_id
            ));
        }
        ticket.priority_score = lane.priority_weight.saturating_mul(ticket.ring_size);
        ticket.updated_height = self.height;
        let ticket_id = ticket.ticket_id.clone();
        self.tickets.insert(ticket_id.clone(), ticket);
        Ok(ticket_id)
    }

    pub fn reserve_sponsorship(
        &mut self,
        mut reservation: SponsorshipReservation,
    ) -> MoneroFeeSponsoredExitAggregatorResult<String> {
        self.ensure_capacity(
            "reservations",
            self.reservations.len(),
            self.config.max_reservations,
        )?;
        reservation.validate()?;
        if self.reservations.contains_key(&reservation.reservation_id) {
            return Err(format!(
                "reservation {} already exists",
                reservation.reservation_id
            ));
        }
        if !self.lanes.contains_key(&reservation.lane_id) {
            return Err(format!("lane {} not found", reservation.lane_id));
        }
        let sponsor = self
            .sponsors
            .get_mut(&reservation.sponsor_id)
            .ok_or_else(|| format!("sponsor {} not found", reservation.sponsor_id))?;
        if !sponsor.status.can_reserve() {
            return Err(format!("sponsor {} cannot reserve", sponsor.sponsor_id));
        }
        if sponsor.expiry_height <= self.height {
            return Err(format!("sponsor {} expired", sponsor.sponsor_id));
        }
        if reservation.max_fee_micro_units > sponsor.fee_cap_micro_units {
            return Err(format!(
                "reservation {} exceeds sponsor fee cap",
                reservation.reservation_id
            ));
        }
        let allowance_bps = match sponsor.lane_allowance_bps.get(&reservation.lane_id) {
            Some(value) => *value,
            None => MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MAX_BPS,
        };
        let lane_budget = sponsor.budget_units.saturating_mul(allowance_bps)
            / MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MAX_BPS;
        let lane_reserved = self
            .reservations
            .values()
            .filter(|known| {
                known.sponsor_id == sponsor.sponsor_id
                    && known.lane_id == reservation.lane_id
                    && known.status.spendable()
            })
            .map(|known| known.reserved_fee_units)
            .sum::<u64>();
        if lane_reserved.saturating_add(reservation.reserved_fee_units) > lane_budget {
            return Err(format!(
                "reservation {} exceeds sponsor lane allowance",
                reservation.reservation_id
            ));
        }
        if reservation.reserved_fee_units > sponsor.available_units() {
            return Err(format!(
                "reservation {} exceeds sponsor available units",
                reservation.reservation_id
            ));
        }
        sponsor.reserved_units = sponsor
            .reserved_units
            .saturating_add(reservation.reserved_fee_units);
        sponsor.updated_height = self.height;
        reservation.updated_height = self.height;
        let reservation_id = reservation.reservation_id.clone();
        self.reservations
            .insert(reservation_id.clone(), reservation);
        Ok(reservation_id)
    }

    pub fn bind_reservation_to_ticket(
        &mut self,
        reservation_id: &str,
        ticket_id: &str,
    ) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        let ticket_lane_id = self
            .tickets
            .get(ticket_id)
            .map(|ticket| ticket.lane_id.clone())
            .ok_or_else(|| format!("ticket {ticket_id} not found"))?;
        let reservation = self
            .reservations
            .get_mut(reservation_id)
            .ok_or_else(|| format!("reservation {reservation_id} not found"))?;
        if !reservation.status.spendable() {
            return Err(format!("reservation {reservation_id} is not spendable"));
        }
        if reservation.lane_id != ticket_lane_id {
            return Err(format!("reservation {reservation_id} lane mismatch"));
        }
        if reservation.expires_height <= self.height {
            reservation.status = SponsorshipReservationStatus::Expired;
            reservation.updated_height = self.height;
            return Err(format!("reservation {reservation_id} expired"));
        }
        reservation.ticket_id = Some(ticket_id.to_string());
        reservation.status = SponsorshipReservationStatus::BoundToTicket;
        reservation.updated_height = self.height;
        let ticket = self
            .tickets
            .get_mut(ticket_id)
            .ok_or_else(|| format!("ticket {ticket_id} not found"))?;
        ticket.sponsor_reservation_id = Some(reservation_id.to_string());
        ticket.status = ExitTicketStatus::Sponsored;
        ticket.updated_height = self.height;
        Ok(())
    }

    pub fn build_manifest(
        &mut self,
        lane_id: &str,
        ticket_ids: &[String],
    ) -> MoneroFeeSponsoredExitAggregatorResult<String> {
        self.ensure_capacity("manifests", self.manifests.len(), self.config.max_manifests)?;
        if ticket_ids.is_empty() {
            return Err("manifest requires at least one ticket".to_string());
        }
        if ticket_ids.len() > self.config.max_tickets_per_manifest {
            return Err("manifest ticket count exceeds capacity".to_string());
        }
        let lane = self
            .lanes
            .get(lane_id)
            .ok_or_else(|| format!("lane {lane_id} not found"))?;
        if !lane.status.accepts_tickets() && lane.status != LaneStatus::Draining {
            return Err(format!("lane {lane_id} is not batchable"));
        }
        let mut seen = BTreeSet::new();
        let mut ticket_records = Vec::with_capacity(ticket_ids.len());
        let mut reservation_records = Vec::with_capacity(ticket_ids.len());
        let mut total_exit_units = 0_u64;
        let mut aggregate_fee_units = 0_u64;
        let mut min_privacy = MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MAX_BPS;
        for ticket_id in ticket_ids {
            if !seen.insert(ticket_id.clone()) {
                return Err(format!("ticket {ticket_id} appears twice in manifest"));
            }
            let ticket = self
                .tickets
                .get(ticket_id)
                .ok_or_else(|| format!("ticket {ticket_id} not found"))?;
            if ticket.lane_id != lane_id {
                return Err(format!("ticket {ticket_id} lane mismatch"));
            }
            if !matches!(
                ticket.status,
                ExitTicketStatus::Sponsored | ExitTicketStatus::Submitted
            ) {
                return Err(format!("ticket {ticket_id} is not manifestable"));
            }
            if ticket.expires_height <= self.height {
                return Err(format!("ticket {ticket_id} expired"));
            }
            total_exit_units = total_exit_units.saturating_add(ticket.requested_units);
            aggregate_fee_units = aggregate_fee_units.saturating_add(ticket.max_fee_micro_units);
            let ticket_privacy = privacy_score(ticket.ring_size, self.config.target_ring_size);
            min_privacy = min_privacy.min(ticket_privacy);
            ticket_records.push(ticket.public_record());
            if let Some(reservation_id) = &ticket.sponsor_reservation_id {
                let reservation = self
                    .reservations
                    .get(reservation_id)
                    .ok_or_else(|| format!("reservation {reservation_id} not found"))?;
                if !reservation.status.spendable() {
                    return Err(format!("reservation {reservation_id} is not spendable"));
                }
                reservation_records.push(reservation.public_record());
            }
        }
        if aggregate_fee_units > self.config.max_manifest_fee_units {
            return Err("manifest aggregate fee exceeds capacity".to_string());
        }
        if min_privacy < self.config.privacy_floor_bps || min_privacy < lane.privacy_floor_bps {
            return Err("manifest privacy score below floor".to_string());
        }
        let mut manifest = BatchedExitManifest::new(
            lane_id,
            &ticket_records,
            &reservation_records,
            total_exit_units,
            aggregate_fee_units,
            min_privacy,
            self.height,
            self.config.release_delay_blocks,
            self.config.challenge_window_blocks,
        );
        manifest.status = ManifestStatus::Sealed;
        manifest.sealed_height = Some(self.height);
        manifest.validate()?;
        let manifest_id = manifest.manifest_id.clone();
        for ticket_id in ticket_ids {
            let ticket = self
                .tickets
                .get_mut(ticket_id)
                .ok_or_else(|| format!("ticket {ticket_id} not found"))?;
            ticket.manifest_id = Some(manifest_id.clone());
            ticket.status = ExitTicketStatus::Manifested;
            ticket.updated_height = self.height;
            if let Some(reservation_id) = &ticket.sponsor_reservation_id {
                if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                    reservation.status = SponsorshipReservationStatus::BoundToTicket;
                    reservation.updated_height = self.height;
                }
            }
        }
        self.manifests.insert(manifest_id.clone(), manifest);
        Ok(manifest_id)
    }

    pub fn submit_watcher_attestation(
        &mut self,
        mut attestation: PqWatcherAttestation,
    ) -> MoneroFeeSponsoredExitAggregatorResult<String> {
        self.ensure_capacity(
            "attestations",
            self.attestations.len(),
            self.config.max_attestations,
        )?;
        attestation.validate()?;
        if self.attestations.contains_key(&attestation.attestation_id) {
            return Err(format!(
                "attestation {} already exists",
                attestation.attestation_id
            ));
        }
        let manifest = self
            .manifests
            .get_mut(&attestation.manifest_id)
            .ok_or_else(|| format!("manifest {} not found", attestation.manifest_id))?;
        if !manifest.status.accepts_attestations() {
            return Err(format!(
                "manifest {} does not accept attestations",
                manifest.manifest_id
            ));
        }
        let required_root = manifest.root();
        if attestation.attested_manifest_root != required_root {
            return Err(format!(
                "attestation {} manifest root mismatch",
                attestation.attestation_id
            ));
        }
        if attestation.privacy_score_bps < self.config.privacy_floor_bps {
            return Err(format!(
                "attestation {} privacy score below floor",
                attestation.attestation_id
            ));
        }
        attestation.status = WatcherAttestationStatus::Accepted;
        manifest.pq_attestation_weight = manifest
            .pq_attestation_weight
            .saturating_add(attestation.quorum_weight);
        if manifest.pq_attestation_weight >= self.config.pq_quorum_weight {
            manifest.status = ManifestStatus::PqAttested;
        }
        manifest.updated_height = self.height;
        let attestation_id = attestation.attestation_id.clone();
        self.attestations
            .insert(attestation_id.clone(), attestation);
        Ok(attestation_id)
    }

    pub fn schedule_release_window(
        &mut self,
        manifest_id: &str,
    ) -> MoneroFeeSponsoredExitAggregatorResult<String> {
        self.ensure_capacity(
            "release_windows",
            self.release_windows.len(),
            self.config.max_release_windows,
        )?;
        let (release_root, payout_commitment_root, watcher_attestation_root) = {
            let manifest = self
                .manifests
                .get(manifest_id)
                .ok_or_else(|| format!("manifest {manifest_id} not found"))?;
            if manifest.status != ManifestStatus::PqAttested {
                return Err(format!("manifest {manifest_id} is not pq attested"));
            }
            let attestation_records = self
                .attestations
                .values()
                .filter(|attestation| attestation.manifest_id == manifest_id)
                .map(PqWatcherAttestation::public_record)
                .collect::<Vec<_>>();
            (
                record_root(&json!({
                    "kind": "release_root",
                    "manifest_id": manifest_id,
                    "manifest_root": manifest.root(),
                })),
                record_root(&json!({
                    "kind": "payout_commitment_root",
                    "manifest_id": manifest_id,
                    "ticket_root": manifest.ticket_root,
                })),
                merkle_root(
                    "MONERO-FEE-SPONSORED-EXIT-WATCHER-ATTESTATIONS",
                    &attestation_records,
                ),
            )
        };
        let mut window = ReleaseWindow::new(
            manifest_id,
            &release_root,
            &payout_commitment_root,
            &watcher_attestation_root,
            self.height,
            self.config.release_delay_blocks,
            self.config.challenge_window_blocks,
        );
        window.validate()?;
        let window_id = window.release_window_id.clone();
        let manifest = self
            .manifests
            .get_mut(manifest_id)
            .ok_or_else(|| format!("manifest {manifest_id} not found"))?;
        manifest.status = ManifestStatus::ReleaseScheduled;
        manifest.updated_height = self.height;
        for ticket_id in &manifest.ticket_ids {
            if let Some(ticket) = self.tickets.get_mut(ticket_id) {
                ticket.release_window_id = Some(window_id.clone());
                ticket.status = ExitTicketStatus::ReleasePending;
                ticket.updated_height = self.height;
            }
        }
        window.updated_height = self.height;
        self.release_windows.insert(window_id.clone(), window);
        Ok(window_id)
    }

    pub fn open_release_window(
        &mut self,
        release_window_id: &str,
    ) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        let window = self
            .release_windows
            .get_mut(release_window_id)
            .ok_or_else(|| format!("release window {release_window_id} not found"))?;
        if self.height < window.opens_height {
            return Err(format!(
                "release window {release_window_id} is not open yet"
            ));
        }
        if window.status == ReleaseWindowStatus::Scheduled {
            window.status = ReleaseWindowStatus::Open;
            window.updated_height = self.height;
        }
        Ok(())
    }

    pub fn release_manifest(
        &mut self,
        release_window_id: &str,
    ) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        self.open_release_window(release_window_id)?;
        let manifest_id = self
            .release_windows
            .get(release_window_id)
            .map(|window| window.manifest_id.clone())
            .ok_or_else(|| format!("release window {release_window_id} not found"))?;
        let ticket_ids = self
            .manifests
            .get(&manifest_id)
            .map(|manifest| manifest.ticket_ids.clone())
            .ok_or_else(|| format!("manifest {manifest_id} not found"))?;
        let mut released_ticket_count = 0_usize;
        let mut released_fee_units = 0_u64;
        for ticket_id in &ticket_ids {
            let (reservation_id, ticket_fee_units) = {
                let ticket = self
                    .tickets
                    .get_mut(ticket_id)
                    .ok_or_else(|| format!("ticket {ticket_id} not found"))?;
                if ticket.status == ExitTicketStatus::Slashed {
                    return Err(format!("ticket {ticket_id} is slashed"));
                }
                ticket.status = ExitTicketStatus::Released;
                ticket.updated_height = self.height;
                self.spent_nullifiers.insert(ticket.exit_nullifier.clone());
                (
                    ticket.sponsor_reservation_id.clone(),
                    ticket.max_fee_micro_units,
                )
            };
            released_ticket_count = released_ticket_count.saturating_add(1);
            released_fee_units = released_fee_units.saturating_add(ticket_fee_units);
            if let Some(reservation_id) = reservation_id {
                self.consume_reservation(&reservation_id, ticket_fee_units)?;
            }
        }
        let manifest = self
            .manifests
            .get_mut(&manifest_id)
            .ok_or_else(|| format!("manifest {manifest_id} not found"))?;
        manifest.status = ManifestStatus::Released;
        manifest.updated_height = self.height;
        let window = self
            .release_windows
            .get_mut(release_window_id)
            .ok_or_else(|| format!("release window {release_window_id} not found"))?;
        window.status = ReleaseWindowStatus::Released;
        window.released_ticket_count = released_ticket_count;
        window.released_fee_units = released_fee_units;
        window.updated_height = self.height;
        Ok(())
    }

    pub fn submit_slashing_evidence(
        &mut self,
        evidence: SlashingEvidence,
    ) -> MoneroFeeSponsoredExitAggregatorResult<String> {
        self.ensure_capacity(
            "slashing_evidence",
            self.slashing_evidence.len(),
            self.config.max_evidence,
        )?;
        evidence.validate()?;
        if self.slashing_evidence.contains_key(&evidence.evidence_id) {
            return Err(format!("evidence {} already exists", evidence.evidence_id));
        }
        if evidence.submitted_height > self.height {
            return Err(format!(
                "evidence {} submitted in future",
                evidence.evidence_id
            ));
        }
        self.freeze_linked_records(&evidence);
        let evidence_id = evidence.evidence_id.clone();
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn sustain_slashing_evidence(
        &mut self,
        evidence_id: &str,
    ) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        let evidence = self
            .slashing_evidence
            .get_mut(evidence_id)
            .ok_or_else(|| format!("evidence {evidence_id} not found"))?;
        evidence.status = "sustained".to_string();
        evidence.resolved_height = Some(self.height);
        if let Some(manifest_id) = &evidence.manifest_id {
            if let Some(manifest) = self.manifests.get_mut(manifest_id) {
                manifest.status = ManifestStatus::Slashed;
                manifest.updated_height = self.height;
            }
        }
        if let Some(ticket_id) = &evidence.ticket_id {
            if let Some(ticket) = self.tickets.get_mut(ticket_id) {
                ticket.status = ExitTicketStatus::Slashed;
                ticket.updated_height = self.height;
            }
        }
        if let Some(reservation_id) = &evidence.reservation_id {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = SponsorshipReservationStatus::Slashed;
                reservation.updated_height = self.height;
            }
        }
        if let Some(attestation_id) = &evidence.attestation_id {
            if let Some(attestation) = self.attestations.get_mut(attestation_id) {
                attestation.status = WatcherAttestationStatus::Slashed;
            }
        }
        if let Some(window_id) = &evidence.release_window_id {
            if let Some(window) = self.release_windows.get_mut(window_id) {
                window.status = ReleaseWindowStatus::Frozen;
                window.updated_height = self.height;
            }
        }
        if let Some(sponsor) = self.sponsors.get_mut(&evidence.accused_id) {
            let slash_units = sponsor
                .bond_units
                .saturating_mul(evidence.requested_slash_bps)
                / MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MAX_BPS;
            sponsor.slashed_units = sponsor.slashed_units.saturating_add(slash_units);
            sponsor.status = SponsorAccountStatus::Slashed;
            sponsor.updated_height = self.height;
        }
        Ok(())
    }

    pub fn dismiss_slashing_evidence(
        &mut self,
        evidence_id: &str,
    ) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        let evidence = self
            .slashing_evidence
            .get_mut(evidence_id)
            .ok_or_else(|| format!("evidence {evidence_id} not found"))?;
        evidence.status = "dismissed".to_string();
        evidence.resolved_height = Some(self.height);
        Ok(())
    }

    pub fn validate(&self) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        self.config.validate()?;
        if self.lanes.len() > self.config.max_lanes {
            return Err("state lane capacity exceeded".to_string());
        }
        if self.sponsors.len() > self.config.max_sponsors {
            return Err("state sponsor capacity exceeded".to_string());
        }
        if self.tickets.len() > self.config.max_tickets {
            return Err("state ticket capacity exceeded".to_string());
        }
        if self.reservations.len() > self.config.max_reservations {
            return Err("state reservation capacity exceeded".to_string());
        }
        if self.manifests.len() > self.config.max_manifests {
            return Err("state manifest capacity exceeded".to_string());
        }
        if self.attestations.len() > self.config.max_attestations {
            return Err("state attestation capacity exceeded".to_string());
        }
        if self.release_windows.len() > self.config.max_release_windows {
            return Err("state release window capacity exceeded".to_string());
        }
        if self.slashing_evidence.len() > self.config.max_evidence {
            return Err("state slashing evidence capacity exceeded".to_string());
        }
        for lane in self.lanes.values() {
            lane.validate()?;
        }
        for sponsor in self.sponsors.values() {
            sponsor.validate()?;
        }
        let mut nullifiers = BTreeSet::new();
        for ticket in self.tickets.values() {
            ticket.validate()?;
            if !self.lanes.contains_key(&ticket.lane_id) {
                return Err(format!(
                    "ticket {} references missing lane",
                    ticket.ticket_id
                ));
            }
            if !nullifiers.insert(ticket.exit_nullifier.clone()) {
                return Err(format!("ticket {} duplicate nullifier", ticket.ticket_id));
            }
        }
        for reservation in self.reservations.values() {
            reservation.validate()?;
            if !self.sponsors.contains_key(&reservation.sponsor_id) {
                return Err(format!(
                    "reservation {} references missing sponsor",
                    reservation.reservation_id
                ));
            }
            if !self.lanes.contains_key(&reservation.lane_id) {
                return Err(format!(
                    "reservation {} references missing lane",
                    reservation.reservation_id
                ));
            }
            if let Some(ticket_id) = &reservation.ticket_id {
                if !self.tickets.contains_key(ticket_id) {
                    return Err(format!(
                        "reservation {} references missing ticket",
                        reservation.reservation_id
                    ));
                }
            }
        }
        for manifest in self.manifests.values() {
            manifest.validate()?;
            if !self.lanes.contains_key(&manifest.lane_id) {
                return Err(format!(
                    "manifest {} references missing lane",
                    manifest.manifest_id
                ));
            }
            if manifest.ticket_ids.len() > self.config.max_tickets_per_manifest {
                return Err(format!(
                    "manifest {} exceeds ticket capacity",
                    manifest.manifest_id
                ));
            }
            for ticket_id in &manifest.ticket_ids {
                if !self.tickets.contains_key(ticket_id) {
                    return Err(format!(
                        "manifest {} references missing ticket",
                        manifest.manifest_id
                    ));
                }
            }
        }
        for attestation in self.attestations.values() {
            attestation.validate()?;
            if !self.manifests.contains_key(&attestation.manifest_id) {
                return Err(format!(
                    "attestation {} references missing manifest",
                    attestation.attestation_id
                ));
            }
        }
        for window in self.release_windows.values() {
            window.validate()?;
            if !self.manifests.contains_key(&window.manifest_id) {
                return Err(format!(
                    "release window {} references missing manifest",
                    window.release_window_id
                ));
            }
        }
        for evidence in self.slashing_evidence.values() {
            evidence.validate()?;
        }
        Ok(())
    }

    pub fn counters(&self) -> MoneroFeeSponsoredExitAggregatorCounters {
        MoneroFeeSponsoredExitAggregatorCounters {
            lanes: self.lanes.len(),
            active_lanes: self
                .lanes
                .values()
                .filter(|lane| lane.status.accepts_tickets())
                .count(),
            tickets: self.tickets.len(),
            live_tickets: self
                .tickets
                .values()
                .filter(|ticket| ticket.status.is_live())
                .count(),
            sponsors: self.sponsors.len(),
            active_sponsors: self
                .sponsors
                .values()
                .filter(|sponsor| sponsor.status.can_reserve())
                .count(),
            reservations: self.reservations.len(),
            spendable_reservations: self
                .reservations
                .values()
                .filter(|reservation| reservation.status.spendable())
                .count(),
            manifests: self.manifests.len(),
            attestations: self.attestations.len(),
            release_windows: self.release_windows.len(),
            slashing_evidence: self.slashing_evidence.len(),
            total_reserved_units: self.sponsors.values().map(|s| s.reserved_units).sum(),
            total_spent_units: self.sponsors.values().map(|s| s.spent_units).sum(),
            total_slashed_units: self.sponsors.values().map(|s| s.slashed_units).sum(),
            total_exit_units_manifested: self
                .manifests
                .values()
                .map(|manifest| manifest.total_exit_units)
                .sum(),
            total_fee_units_manifested: self
                .manifests
                .values()
                .map(|manifest| manifest.aggregate_fee_units)
                .sum(),
        }
    }

    pub fn roots(&self) -> MoneroFeeSponsoredExitAggregatorRoots {
        let config_root = record_root(&self.config.public_record());
        let lane_root = map_root(
            "MONERO-FEE-SPONSORED-EXIT-LANES",
            self.lanes.values().map(ExitLane::public_record).collect(),
        );
        let ticket_root = map_root(
            "MONERO-FEE-SPONSORED-EXIT-TICKETS",
            self.tickets
                .values()
                .map(ExitTicket::public_record)
                .collect(),
        );
        let sponsor_root = map_root(
            "MONERO-FEE-SPONSORED-EXIT-SPONSORS",
            self.sponsors
                .values()
                .map(SponsorAccount::public_record)
                .collect(),
        );
        let reservation_root = map_root(
            "MONERO-FEE-SPONSORED-EXIT-RESERVATIONS",
            self.reservations
                .values()
                .map(SponsorshipReservation::public_record)
                .collect(),
        );
        let manifest_root = map_root(
            "MONERO-FEE-SPONSORED-EXIT-MANIFESTS",
            self.manifests
                .values()
                .map(BatchedExitManifest::public_record)
                .collect(),
        );
        let attestation_root = map_root(
            "MONERO-FEE-SPONSORED-EXIT-ATTESTATIONS",
            self.attestations
                .values()
                .map(PqWatcherAttestation::public_record)
                .collect(),
        );
        let release_window_root = map_root(
            "MONERO-FEE-SPONSORED-EXIT-RELEASE-WINDOWS",
            self.release_windows
                .values()
                .map(ReleaseWindow::public_record)
                .collect(),
        );
        let slashing_evidence_root = map_root(
            "MONERO-FEE-SPONSORED-EXIT-SLASHING-EVIDENCE",
            self.slashing_evidence
                .values()
                .map(SlashingEvidence::public_record)
                .collect(),
        );
        let nullifier_values = self
            .spent_nullifiers
            .iter()
            .map(|nullifier| json!({ "nullifier": nullifier }))
            .collect::<Vec<_>>();
        let nullifier_root = merkle_root(
            "MONERO-FEE-SPONSORED-EXIT-SPENT-NULLIFIERS",
            &nullifier_values,
        );
        let state_record = json!({
            "kind": "monero_fee_sponsored_exit_aggregator_state_root",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_PROTOCOL_VERSION,
            "height": self.height,
            "config_root": config_root,
            "lane_root": lane_root,
            "ticket_root": ticket_root,
            "sponsor_root": sponsor_root,
            "reservation_root": reservation_root,
            "manifest_root": manifest_root,
            "attestation_root": attestation_root,
            "release_window_root": release_window_root,
            "slashing_evidence_root": slashing_evidence_root,
            "nullifier_root": nullifier_root,
        });
        let state_root = record_root(&state_record);
        MoneroFeeSponsoredExitAggregatorRoots {
            config_root,
            lane_root,
            ticket_root,
            sponsor_root,
            reservation_root,
            manifest_root,
            attestation_root,
            release_window_root,
            slashing_evidence_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_fee_sponsored_exit_aggregator_state",
            "chain_id": CHAIN_ID,
            "protocol_version": MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_PROTOCOL_VERSION,
            "schema_version": MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        })
    }

    fn ensure_capacity(
        &self,
        label: &str,
        current_len: usize,
        max_len: usize,
    ) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        if current_len >= max_len {
            return Err(format!("{label} capacity reached"));
        }
        Ok(())
    }

    fn consume_reservation(
        &mut self,
        reservation_id: &str,
        spent_units: u64,
    ) -> MoneroFeeSponsoredExitAggregatorResult<()> {
        let (sponsor_id, reserved_fee_units) = {
            let reservation = self
                .reservations
                .get_mut(reservation_id)
                .ok_or_else(|| format!("reservation {reservation_id} not found"))?;
            if !reservation.status.spendable() {
                return Err(format!("reservation {reservation_id} is not spendable"));
            }
            reservation.status = SponsorshipReservationStatus::Consumed;
            reservation.consumed_height = Some(self.height);
            reservation.updated_height = self.height;
            (
                reservation.sponsor_id.clone(),
                reservation.reserved_fee_units,
            )
        };
        let sponsor = self
            .sponsors
            .get_mut(&sponsor_id)
            .ok_or_else(|| format!("sponsor {sponsor_id} not found"))?;
        sponsor.reserved_units = sponsor.reserved_units.saturating_sub(reserved_fee_units);
        sponsor.spent_units = sponsor.spent_units.saturating_add(spent_units);
        if sponsor.available_units() == 0 {
            sponsor.status = SponsorAccountStatus::Exhausted;
        }
        sponsor.updated_height = self.height;
        Ok(())
    }

    fn freeze_linked_records(&mut self, evidence: &SlashingEvidence) {
        if let Some(manifest_id) = &evidence.manifest_id {
            if let Some(manifest) = self.manifests.get_mut(manifest_id) {
                manifest.status = ManifestStatus::Challenged;
                manifest.updated_height = self.height;
            }
        }
        if let Some(ticket_id) = &evidence.ticket_id {
            if let Some(ticket) = self.tickets.get_mut(ticket_id) {
                ticket.status = ExitTicketStatus::Challenged;
                ticket.updated_height = self.height;
            }
        }
        if let Some(attestation_id) = &evidence.attestation_id {
            if let Some(attestation) = self.attestations.get_mut(attestation_id) {
                attestation.status = WatcherAttestationStatus::Challenged;
            }
        }
        if let Some(window_id) = &evidence.release_window_id {
            if let Some(window) = self.release_windows.get_mut(window_id) {
                window.status = ReleaseWindowStatus::Challenged;
                window.updated_height = self.height;
            }
        }
    }

    fn expire_stale_records(&mut self) {
        for ticket in self.tickets.values_mut() {
            if ticket.status.is_live() && ticket.expires_height <= self.height {
                ticket.status = ExitTicketStatus::Expired;
                ticket.updated_height = self.height;
            }
        }
        for reservation in self.reservations.values_mut() {
            if reservation.status.spendable() && reservation.expires_height <= self.height {
                reservation.status = SponsorshipReservationStatus::Expired;
                reservation.updated_height = self.height;
            }
        }
        for manifest in self.manifests.values_mut() {
            if matches!(
                manifest.status,
                ManifestStatus::Sealed
                    | ManifestStatus::PqAttested
                    | ManifestStatus::ReleaseScheduled
            ) && manifest
                .challenge_deadline_height
                .saturating_add(self.config.reorg_grace_blocks)
                <= self.height
            {
                manifest.status = ManifestStatus::Expired;
                manifest.updated_height = self.height;
            }
        }
        for window in self.release_windows.values_mut() {
            if matches!(
                window.status,
                ReleaseWindowStatus::Scheduled | ReleaseWindowStatus::Open
            ) && window
                .challenge_deadline_height
                .saturating_add(self.config.reorg_grace_blocks)
                <= self.height
            {
                window.status = ReleaseWindowStatus::Expired;
                window.updated_height = self.height;
            }
        }
    }
}

pub fn devnet() -> MoneroFeeSponsoredExitAggregatorResult<MoneroFeeSponsoredExitAggregatorState> {
    MoneroFeeSponsoredExitAggregatorState::devnet()
}

pub fn root_from_record(record: &Value) -> String {
    record_root(record)
}

pub fn compact_manifest_record(
    manifest: &BatchedExitManifest,
    tickets: &BTreeMap<String, ExitTicket>,
) -> Value {
    let compact_tickets = manifest
        .ticket_ids
        .iter()
        .filter_map(|ticket_id| tickets.get(ticket_id))
        .map(|ticket| {
            json!({
                "ticket_id": ticket.ticket_id,
                "lane_id": ticket.lane_id,
                "exit_nullifier": ticket.exit_nullifier,
                "recipient_commitment": ticket.recipient_commitment,
                "amount_commitment": ticket.amount_commitment,
                "fee_commitment": ticket.fee_commitment,
                "max_fee_micro_units": ticket.max_fee_micro_units,
                "ring_size": ticket.ring_size,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "kind": "compact_monero_fee_sponsored_exit_manifest",
        "manifest_id": manifest.manifest_id,
        "lane_id": manifest.lane_id,
        "ticket_root": manifest.ticket_root,
        "reservation_root": manifest.reservation_root,
        "compact_payload_root": manifest.compact_payload_root,
        "tickets": compact_tickets,
    })
}

pub fn ticket_id(
    lane_id: &str,
    exit_nullifier: &str,
    recipient_commitment: &str,
    amount_commitment: &str,
    submitted_height: u64,
) -> String {
    domain_hash(
        "MONERO-FEE-SPONSORED-EXIT-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(exit_nullifier),
            HashPart::Str(recipient_commitment),
            HashPart::Str(amount_commitment),
            HashPart::Int(submitted_height as i128),
        ],
        16,
    )
}

pub fn sponsor_id(
    operator_commitment: &str,
    pq_verification_key_root: &str,
    created_height: u64,
) -> String {
    domain_hash(
        "MONERO-FEE-SPONSORED-EXIT-SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_commitment),
            HashPart::Str(pq_verification_key_root),
            HashPart::Int(created_height as i128),
        ],
        16,
    )
}

pub fn reservation_id(
    sponsor_id: &str,
    lane_id: &str,
    credential_nullifier: &str,
    reserved_fee_units: u64,
    created_height: u64,
) -> String {
    domain_hash(
        "MONERO-FEE-SPONSORED-EXIT-RESERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(lane_id),
            HashPart::Str(credential_nullifier),
            HashPart::Int(reserved_fee_units as i128),
            HashPart::Int(created_height as i128),
        ],
        16,
    )
}

pub fn manifest_id(lane_id: &str, ticket_root: &str, created_height: u64) -> String {
    domain_hash(
        "MONERO-FEE-SPONSORED-EXIT-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(ticket_root),
            HashPart::Int(created_height as i128),
        ],
        16,
    )
}

pub fn attestation_id(watcher_id: &str, manifest_id: &str, pq_signature_root: &str) -> String {
    domain_hash(
        "MONERO-FEE-SPONSORED-EXIT-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(watcher_id),
            HashPart::Str(manifest_id),
            HashPart::Str(pq_signature_root),
        ],
        16,
    )
}

pub fn release_window_id(manifest_id: &str, release_root: &str, opens_height: u64) -> String {
    domain_hash(
        "MONERO-FEE-SPONSORED-EXIT-RELEASE-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(manifest_id),
            HashPart::Str(release_root),
            HashPart::Int(opens_height as i128),
        ],
        16,
    )
}

pub fn evidence_id(
    evidence_kind: SlashingEvidenceKind,
    accused_id: &str,
    reporter_id: &str,
    claim_root: &str,
) -> String {
    domain_hash(
        "MONERO-FEE-SPONSORED-EXIT-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(accused_id),
            HashPart::Str(reporter_id),
            HashPart::Str(claim_root),
        ],
        16,
    )
}

pub fn string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn record_root(record: &Value) -> String {
    domain_hash(
        "MONERO-FEE-SPONSORED-EXIT-RECORD",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn empty_root(domain: &str) -> String {
    let empty = json!({
        "kind": "empty",
        "domain": domain,
        "chain_id": CHAIN_ID,
    });
    domain_hash(
        "MONERO-FEE-SPONSORED-EXIT-EMPTY",
        &[HashPart::Str(domain), HashPart::Json(&empty)],
        32,
    )
}

fn map_root(domain: &str, values: Vec<Value>) -> String {
    merkle_root(domain, &values)
}

fn privacy_score(ring_size: u64, target_ring_size: u64) -> u64 {
    if target_ring_size == 0 {
        return 0;
    }
    let score =
        ring_size.saturating_mul(MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MAX_BPS) / target_ring_size;
    score.min(MONERO_FEE_SPONSORED_EXIT_AGGREGATOR_MAX_BPS)
}

fn ensure_non_empty(label: &str, value: &str) -> MoneroFeeSponsoredExitAggregatorResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn ensure_positive(label: &str, value: u64) -> MoneroFeeSponsoredExitAggregatorResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_positive_usize(label: &str, value: usize) -> MoneroFeeSponsoredExitAggregatorResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}
