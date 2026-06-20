use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroBridgePrivateExitCovenantResult<T> = Result<T, String>;

pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_PROTOCOL_VERSION: &str =
    "nebula-monero-bridge-private-exit-covenant-v1";
pub const PROTOCOL_VERSION: &str = MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_PROTOCOL_VERSION;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_SCHEMA_VERSION: u64 = 1;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEVNET_HEIGHT: u64 = 384;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_PQ_SUITE: &str =
    "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s-private-exit-covenant-devnet";
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_SHIELDED_POLICY_SCHEME: &str =
    "shielded-exit-policy-nullifier-set-v1";
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_STEALTH_PAYOUT_SCHEME: &str =
    "monero-stealth-payout-commitment-v1";
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_PQ_APPROVAL_SCHEME: &str =
    "pq-reserve-approval-ml-dsa-slh-dsa-v1";
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAKER_COVENANT_SCHEME: &str =
    "maker-liquidity-covenant-coverage-v1";
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_REORG_SCHEDULE_SCHEME: &str =
    "monero-reorg-delay-schedule-v1";
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_SPONSORSHIP_SCHEME: &str =
    "low-fee-private-exit-sponsorship-v1";
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_RECEIPT_SCHEME: &str =
    "private-withdrawal-receipt-v1";
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_CHALLENGE_SCHEME: &str =
    "private-exit-challenge-slash-evidence-v1";
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_FREEZE_SCHEME: &str =
    "emergency-freeze-council-pq-threshold-v1";
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_EXIT_TTL_BLOCKS: u64 = 72;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_REVEAL_DELAY_BLOCKS: u64 = 8;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 96;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 32;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_FREEZE_TTL_BLOCKS: u64 = 16;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_REORG_FINALITY_BLOCKS: u64 = 12;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 512;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 2_048;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_MIN_RING_SIZE: u64 = 16;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_TARGET_RING_SIZE: u64 = 32;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_750;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_WARN_RESERVE_COVERAGE_BPS: u64 = 11_500;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_MAX_MAKER_EXPOSURE_UNITS: u64 = 2_000_000;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_MAX_POLICY_EXPOSURE_UNITS: u64 = 8_000_000;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_BASE_FEE_BPS: u64 = 16;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_FAST_FEE_BPS: u64 = 42;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_EMERGENCY_FEE_BPS: u64 = 95;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_FEE_FLOOR_PICONERO: u64 = 2_000;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_SPONSOR_POOL_PICONERO: u64 = 90_000_000;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8_000;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_MAX_SPONSOR_REBATE_BPS: u64 = 9_500;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_MIN_PQ_APPROVAL_WEIGHT: u64 = 3;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_MIN_FREEZE_WEIGHT: u64 = 4;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_BPS: u64 = 10_000;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_POLICIES: usize = 131_072;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_PAYOUTS: usize = 262_144;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_APPROVALS: usize = 524_288;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_MAKERS: usize = 65_536;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_REORG_SCHEDULES: usize = 512;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_SPONSORSHIPS: usize = 131_072;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_RECEIPTS: usize = 262_144;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_FREEZES: usize = 65_536;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_CHALLENGES: usize = 131_072;
pub const MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_EVENTS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateExitSpeed {
    LowFee,
    Normal,
    Fast,
    Emergency,
}

impl PrivateExitSpeed {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Normal => "normal",
            Self::Fast => "fast",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &MoneroBridgePrivateExitCovenantConfig) -> u64 {
        match self {
            Self::LowFee => config.base_fee_bps / 2,
            Self::Normal => config.base_fee_bps,
            Self::Fast => config.fast_fee_bps,
            Self::Emergency => config.emergency_fee_bps,
        }
    }

    pub fn ttl_blocks(self, config: &MoneroBridgePrivateExitCovenantConfig) -> u64 {
        match self {
            Self::LowFee => config.exit_ttl_blocks.saturating_mul(2).max(1),
            Self::Normal => config.exit_ttl_blocks.max(1),
            Self::Fast => config.exit_ttl_blocks.min(24).max(1),
            Self::Emergency => config.freeze_ttl_blocks.max(1),
        }
    }

    pub fn risk_weight_bps(self) -> u64 {
        match self {
            Self::LowFee => 9_500,
            Self::Normal => 10_000,
            Self::Fast => 11_500,
            Self::Emergency => 16_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldedExitClass {
    FullyShielded,
    AmountBucketed,
    MakerScoped,
    SponsoredLowFee,
    EmergencyRecovery,
}

impl ShieldedExitClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullyShielded => "fully_shielded",
            Self::AmountBucketed => "amount_bucketed",
            Self::MakerScoped => "maker_scoped",
            Self::SponsoredLowFee => "sponsored_low_fee",
            Self::EmergencyRecovery => "emergency_recovery",
        }
    }

    pub fn requires_sponsor(self) -> bool {
        matches!(self, Self::SponsoredLowFee)
    }

    pub fn requires_freeze_clearance(self) -> bool {
        matches!(self, Self::EmergencyRecovery)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitPolicyStatus {
    Draft,
    Open,
    PayoutCommitted,
    PqApproved,
    MakerBound,
    ReorgDelayed,
    ReceiptPending,
    Completed,
    Frozen,
    Challenged,
    Slashed,
    Expired,
    Cancelled,
    Rejected,
}

impl ExitPolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::PayoutCommitted => "payout_committed",
            Self::PqApproved => "pq_approved",
            Self::MakerBound => "maker_bound",
            Self::ReorgDelayed => "reorg_delayed",
            Self::ReceiptPending => "receipt_pending",
            Self::Completed => "completed",
            Self::Frozen => "frozen",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Draft
                | Self::Open
                | Self::PayoutCommitted
                | Self::PqApproved
                | Self::MakerBound
                | Self::ReorgDelayed
                | Self::ReceiptPending
                | Self::Frozen
                | Self::Challenged
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Slashed | Self::Expired | Self::Cancelled | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutCommitmentStatus {
    Reserved,
    Bound,
    BroadcastReady,
    Observed,
    Confirmed,
    ReorgDelayed,
    Spent,
    Cancelled,
    Expired,
    Challenged,
}

impl PayoutCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Bound => "bound",
            Self::BroadcastReady => "broadcast_ready",
            Self::Observed => "observed",
            Self::Confirmed => "confirmed",
            Self::ReorgDelayed => "reorg_delayed",
            Self::Spent => "spent",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }

    pub fn counts_as_live(self) -> bool {
        matches!(
            self,
            Self::Reserved
                | Self::Bound
                | Self::BroadcastReady
                | Self::Observed
                | Self::Confirmed
                | Self::ReorgDelayed
                | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqApprovalStatus {
    Submitted,
    Accepted,
    Superseded,
    Challenged,
    Slashed,
    Expired,
}

impl PqApprovalStatus {
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

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MakerCovenantStatus {
    Offered,
    Active,
    Bound,
    Draining,
    Frozen,
    Slashed,
    Retired,
}

impl MakerCovenantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Active => "active",
            Self::Bound => "bound",
            Self::Draining => "draining",
            Self::Frozen => "frozen",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_bind(self) -> bool {
        matches!(self, Self::Offered | Self::Active | Self::Bound)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgDelayStatus {
    Draft,
    Active,
    Triggered,
    Extended,
    Released,
    Retired,
}

impl ReorgDelayStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Triggered => "triggered",
            Self::Extended => "extended",
            Self::Released => "released",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Offered,
    Reserved,
    Applied,
    Exhausted,
    Expired,
    Slashed,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalReceiptStatus {
    PendingReveal,
    Revealed,
    ReorgDelayed,
    Accepted,
    Challenged,
    Finalized,
    Expired,
    Slashed,
}

impl WithdrawalReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingReveal => "pending_reveal",
            Self::Revealed => "revealed",
            Self::ReorgDelayed => "reorg_delayed",
            Self::Accepted => "accepted",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyFreezeStatus {
    Proposed,
    Active,
    Extended,
    Released,
    Expired,
    Slashed,
}

impl EmergencyFreezeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Extended => "extended",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn blocks_exit(self) -> bool {
        matches!(self, Self::Proposed | Self::Active | Self::Extended)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceSubmitted,
    Accepted,
    Rejected,
    Slashed,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::EvidenceSubmitted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgePrivateExitCovenantConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_suite: String,
    pub shielded_policy_scheme: String,
    pub stealth_payout_scheme: String,
    pub pq_approval_scheme: String,
    pub maker_covenant_scheme: String,
    pub reorg_schedule_scheme: String,
    pub sponsorship_scheme: String,
    pub receipt_scheme: String,
    pub challenge_scheme: String,
    pub freeze_scheme: String,
    pub exit_ttl_blocks: u64,
    pub reveal_delay_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub freeze_ttl_blocks: u64,
    pub reorg_finality_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_ring_size: u64,
    pub target_ring_size: u64,
    pub min_reserve_coverage_bps: u64,
    pub warn_reserve_coverage_bps: u64,
    pub max_maker_exposure_units: u64,
    pub max_policy_exposure_units: u64,
    pub base_fee_bps: u64,
    pub fast_fee_bps: u64,
    pub emergency_fee_bps: u64,
    pub fee_floor_piconero: u64,
    pub sponsor_pool_piconero: u64,
    pub low_fee_rebate_bps: u64,
    pub max_sponsor_rebate_bps: u64,
    pub min_pq_approval_weight: u64,
    pub min_freeze_weight: u64,
}

impl Default for MoneroBridgePrivateExitCovenantConfig {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEVNET_MONERO_NETWORK.to_string(),
            asset_id: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_HASH_SUITE.to_string(),
            pq_suite: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_PQ_SUITE.to_string(),
            shielded_policy_scheme: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_SHIELDED_POLICY_SCHEME
                .to_string(),
            stealth_payout_scheme: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_STEALTH_PAYOUT_SCHEME
                .to_string(),
            pq_approval_scheme: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_PQ_APPROVAL_SCHEME.to_string(),
            maker_covenant_scheme: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAKER_COVENANT_SCHEME
                .to_string(),
            reorg_schedule_scheme: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_REORG_SCHEDULE_SCHEME
                .to_string(),
            sponsorship_scheme: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_SPONSORSHIP_SCHEME.to_string(),
            receipt_scheme: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_RECEIPT_SCHEME.to_string(),
            challenge_scheme: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_CHALLENGE_SCHEME.to_string(),
            freeze_scheme: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_FREEZE_SCHEME.to_string(),
            exit_ttl_blocks: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_EXIT_TTL_BLOCKS,
            reveal_delay_blocks: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_REVEAL_DELAY_BLOCKS,
            receipt_ttl_blocks: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_RECEIPT_TTL_BLOCKS,
            challenge_window_blocks:
                MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            freeze_ttl_blocks: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_FREEZE_TTL_BLOCKS,
            reorg_finality_blocks:
                MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_REORG_FINALITY_BLOCKS,
            min_privacy_set_size: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size:
                MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_ring_size: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_MIN_RING_SIZE,
            target_ring_size: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_TARGET_RING_SIZE,
            min_reserve_coverage_bps:
                MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            warn_reserve_coverage_bps:
                MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_WARN_RESERVE_COVERAGE_BPS,
            max_maker_exposure_units:
                MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_MAX_MAKER_EXPOSURE_UNITS,
            max_policy_exposure_units:
                MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_MAX_POLICY_EXPOSURE_UNITS,
            base_fee_bps: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_BASE_FEE_BPS,
            fast_fee_bps: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_FAST_FEE_BPS,
            emergency_fee_bps: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_EMERGENCY_FEE_BPS,
            fee_floor_piconero: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_FEE_FLOOR_PICONERO,
            sponsor_pool_piconero:
                MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_SPONSOR_POOL_PICONERO,
            low_fee_rebate_bps: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_LOW_FEE_REBATE_BPS,
            max_sponsor_rebate_bps:
                MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_MAX_SPONSOR_REBATE_BPS,
            min_pq_approval_weight:
                MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_MIN_PQ_APPROVAL_WEIGHT,
            min_freeze_weight: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEFAULT_MIN_FREEZE_WEIGHT,
        }
    }
}

impl MoneroBridgePrivateExitCovenantConfig {
    pub fn validate(&self) -> MoneroBridgePrivateExitCovenantResult<()> {
        validate_non_empty("protocol version", &self.protocol_version)?;
        validate_non_empty("monero network", &self.monero_network)?;
        validate_non_empty("asset id", &self.asset_id)?;
        validate_non_empty("fee asset id", &self.fee_asset_id)?;
        validate_non_empty("hash suite", &self.hash_suite)?;
        validate_non_empty("pq suite", &self.pq_suite)?;
        validate_bps(self.base_fee_bps, "base fee")?;
        validate_bps(self.fast_fee_bps, "fast fee")?;
        validate_bps(self.emergency_fee_bps, "emergency fee")?;
        validate_bps(self.low_fee_rebate_bps, "low fee rebate")?;
        validate_bps(self.max_sponsor_rebate_bps, "max sponsor rebate")?;
        if self.exit_ttl_blocks == 0 {
            return Err("exit ttl must be non-zero".to_string());
        }
        if self.reveal_delay_blocks == 0 {
            return Err("reveal delay must be non-zero".to_string());
        }
        if self.receipt_ttl_blocks <= self.reveal_delay_blocks {
            return Err("receipt ttl must exceed reveal delay".to_string());
        }
        if self.challenge_window_blocks == 0 {
            return Err("challenge window must be non-zero".to_string());
        }
        if self.freeze_ttl_blocks == 0 {
            return Err("freeze ttl must be non-zero".to_string());
        }
        if self.reorg_finality_blocks == 0 {
            return Err("reorg finality must be non-zero".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target privacy set cannot be below minimum".to_string());
        }
        if self.target_ring_size < self.min_ring_size {
            return Err("target ring size cannot be below minimum".to_string());
        }
        if self.min_reserve_coverage_bps < MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_BPS {
            return Err("min reserve coverage must be at least 100%".to_string());
        }
        if self.warn_reserve_coverage_bps < self.min_reserve_coverage_bps {
            return Err("warn reserve coverage cannot be below minimum".to_string());
        }
        if self.max_maker_exposure_units == 0 || self.max_policy_exposure_units == 0 {
            return Err("exposure limits must be non-zero".to_string());
        }
        if self.min_pq_approval_weight == 0 {
            return Err("pq approval weight must be non-zero".to_string());
        }
        if self.min_freeze_weight == 0 {
            return Err("freeze weight must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "shielded_policy_scheme": self.shielded_policy_scheme,
            "stealth_payout_scheme": self.stealth_payout_scheme,
            "pq_approval_scheme": self.pq_approval_scheme,
            "maker_covenant_scheme": self.maker_covenant_scheme,
            "reorg_schedule_scheme": self.reorg_schedule_scheme,
            "sponsorship_scheme": self.sponsorship_scheme,
            "receipt_scheme": self.receipt_scheme,
            "challenge_scheme": self.challenge_scheme,
            "freeze_scheme": self.freeze_scheme,
            "exit_ttl_blocks": self.exit_ttl_blocks,
            "reveal_delay_blocks": self.reveal_delay_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "freeze_ttl_blocks": self.freeze_ttl_blocks,
            "reorg_finality_blocks": self.reorg_finality_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "warn_reserve_coverage_bps": self.warn_reserve_coverage_bps,
            "max_maker_exposure_units": self.max_maker_exposure_units,
            "max_policy_exposure_units": self.max_policy_exposure_units,
            "base_fee_bps": self.base_fee_bps,
            "fast_fee_bps": self.fast_fee_bps,
            "emergency_fee_bps": self.emergency_fee_bps,
            "fee_floor_piconero": self.fee_floor_piconero,
            "sponsor_pool_piconero": self.sponsor_pool_piconero,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "max_sponsor_rebate_bps": self.max_sponsor_rebate_bps,
            "min_pq_approval_weight": self.min_pq_approval_weight,
            "min_freeze_weight": self.min_freeze_weight
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedExitPolicy {
    pub policy_id: String,
    pub owner_commitment: String,
    pub nullifier_root: String,
    pub spend_auth_root: String,
    pub amount_commitment: String,
    pub amount_bucket: u64,
    pub max_amount_units: u64,
    pub fee_cap_piconero: u64,
    pub speed: PrivateExitSpeed,
    pub exit_class: ShieldedExitClass,
    pub status: ExitPolicyStatus,
    pub created_height: u64,
    pub expires_height: u64,
    pub min_privacy_set_size: u64,
    pub target_ring_size: u64,
    pub maker_id: Option<String>,
    pub payout_id: Option<String>,
    pub sponsorship_id: Option<String>,
    pub freeze_id: Option<String>,
    pub challenge_ids: BTreeSet<String>,
    pub tag_commitments: BTreeSet<String>,
    pub metadata_hash: String,
}

impl ShieldedExitPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        seed: &str,
        owner_commitment: &str,
        nullifier_root: &str,
        spend_auth_root: &str,
        amount_commitment: &str,
        amount_bucket: u64,
        max_amount_units: u64,
        fee_cap_piconero: u64,
        speed: PrivateExitSpeed,
        exit_class: ShieldedExitClass,
        created_height: u64,
        config: &MoneroBridgePrivateExitCovenantConfig,
    ) -> Self {
        let policy_id = private_exit_id(
            "POLICY",
            &[
                owner_commitment,
                nullifier_root,
                spend_auth_root,
                amount_commitment,
                seed,
            ],
        );
        let metadata_hash = domain_hash(
            "MONERO-BRIDGE-PRIVATE-EXIT-POLICY-METADATA",
            &[
                HashPart::Str(seed),
                HashPart::Str(exit_class.as_str()),
                HashPart::Str(speed.as_str()),
                HashPart::Int(amount_bucket as i128),
            ],
            32,
        );
        Self {
            policy_id,
            owner_commitment: owner_commitment.to_string(),
            nullifier_root: nullifier_root.to_string(),
            spend_auth_root: spend_auth_root.to_string(),
            amount_commitment: amount_commitment.to_string(),
            amount_bucket,
            max_amount_units,
            fee_cap_piconero,
            speed,
            exit_class,
            status: ExitPolicyStatus::Open,
            created_height,
            expires_height: created_height.saturating_add(speed.ttl_blocks(config)),
            min_privacy_set_size: config.min_privacy_set_size,
            target_ring_size: config.target_ring_size,
            maker_id: None,
            payout_id: None,
            sponsorship_id: None,
            freeze_id: None,
            challenge_ids: BTreeSet::new(),
            tag_commitments: BTreeSet::new(),
            metadata_hash,
        }
    }

    pub fn validate(&self) -> MoneroBridgePrivateExitCovenantResult<()> {
        validate_id("policy id", &self.policy_id)?;
        validate_non_empty("owner commitment", &self.owner_commitment)?;
        validate_non_empty("nullifier root", &self.nullifier_root)?;
        validate_non_empty("spend auth root", &self.spend_auth_root)?;
        validate_non_empty("amount commitment", &self.amount_commitment)?;
        validate_non_empty("metadata hash", &self.metadata_hash)?;
        if self.max_amount_units == 0 {
            return Err("policy max amount must be non-zero".to_string());
        }
        if self.expires_height <= self.created_height {
            return Err("policy expiry must be after creation".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("policy privacy set must be non-zero".to_string());
        }
        if self.target_ring_size == 0 {
            return Err("policy ring size must be non-zero".to_string());
        }
        if self.exit_class.requires_sponsor() && self.sponsorship_id.is_none() {
            return Err("sponsored policy requires sponsorship".to_string());
        }
        if self.exit_class.requires_freeze_clearance() && self.freeze_id.is_none() {
            return Err("emergency recovery policy requires freeze clearance".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "owner_commitment": self.owner_commitment,
            "nullifier_root": self.nullifier_root,
            "spend_auth_root": self.spend_auth_root,
            "amount_commitment": self.amount_commitment,
            "amount_bucket": self.amount_bucket,
            "max_amount_units": self.max_amount_units,
            "fee_cap_piconero": self.fee_cap_piconero,
            "speed": self.speed.as_str(),
            "exit_class": self.exit_class.as_str(),
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_ring_size": self.target_ring_size,
            "maker_id": self.maker_id,
            "payout_id": self.payout_id,
            "sponsorship_id": self.sponsorship_id,
            "freeze_id": self.freeze_id,
            "challenge_ids": self.challenge_ids.iter().cloned().collect::<Vec<_>>(),
            "tag_commitments": self.tag_commitments.iter().cloned().collect::<Vec<_>>(),
            "metadata_hash": self.metadata_hash
        })
    }

    pub fn commitment_root(&self) -> String {
        domain_hash(
            "MONERO-BRIDGE-PRIVATE-EXIT-POLICY-ROOT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthPayoutCommitment {
    pub payout_id: String,
    pub policy_id: String,
    pub maker_id: String,
    pub stealth_address_commitment: String,
    pub tx_public_key_commitment: String,
    pub encrypted_view_tag_root: String,
    pub amount_commitment: String,
    pub fee_commitment: String,
    pub status: PayoutCommitmentStatus,
    pub created_height: u64,
    pub reveal_height: u64,
    pub observed_height: Option<u64>,
    pub confirmation_height: Option<u64>,
    pub monero_txid_commitment: Option<String>,
    pub reorg_schedule_id: Option<String>,
    pub receipt_id: Option<String>,
}

impl StealthPayoutCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_id: &str,
        maker_id: &str,
        stealth_address_commitment: &str,
        tx_public_key_commitment: &str,
        encrypted_view_tag_root: &str,
        amount_commitment: &str,
        fee_commitment: &str,
        created_height: u64,
        config: &MoneroBridgePrivateExitCovenantConfig,
    ) -> Self {
        let payout_id = private_exit_id(
            "PAYOUT",
            &[
                policy_id,
                maker_id,
                stealth_address_commitment,
                tx_public_key_commitment,
                encrypted_view_tag_root,
            ],
        );
        Self {
            payout_id,
            policy_id: policy_id.to_string(),
            maker_id: maker_id.to_string(),
            stealth_address_commitment: stealth_address_commitment.to_string(),
            tx_public_key_commitment: tx_public_key_commitment.to_string(),
            encrypted_view_tag_root: encrypted_view_tag_root.to_string(),
            amount_commitment: amount_commitment.to_string(),
            fee_commitment: fee_commitment.to_string(),
            status: PayoutCommitmentStatus::Reserved,
            created_height,
            reveal_height: created_height.saturating_add(config.reveal_delay_blocks),
            observed_height: None,
            confirmation_height: None,
            monero_txid_commitment: None,
            reorg_schedule_id: None,
            receipt_id: None,
        }
    }

    pub fn validate(&self) -> MoneroBridgePrivateExitCovenantResult<()> {
        validate_id("payout id", &self.payout_id)?;
        validate_id("policy id", &self.policy_id)?;
        validate_id("maker id", &self.maker_id)?;
        validate_non_empty(
            "stealth address commitment",
            &self.stealth_address_commitment,
        )?;
        validate_non_empty("tx public key commitment", &self.tx_public_key_commitment)?;
        validate_non_empty("encrypted view tag root", &self.encrypted_view_tag_root)?;
        validate_non_empty("amount commitment", &self.amount_commitment)?;
        validate_non_empty("fee commitment", &self.fee_commitment)?;
        if self.reveal_height <= self.created_height {
            return Err("payout reveal height must be after creation".to_string());
        }
        if let (Some(observed), Some(confirmed)) = (self.observed_height, self.confirmation_height)
        {
            if confirmed < observed {
                return Err("payout confirmation cannot precede observation".to_string());
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "payout_id": self.payout_id,
            "policy_id": self.policy_id,
            "maker_id": self.maker_id,
            "stealth_address_commitment": self.stealth_address_commitment,
            "tx_public_key_commitment": self.tx_public_key_commitment,
            "encrypted_view_tag_root": self.encrypted_view_tag_root,
            "amount_commitment": self.amount_commitment,
            "fee_commitment": self.fee_commitment,
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "reveal_height": self.reveal_height,
            "observed_height": self.observed_height,
            "confirmation_height": self.confirmation_height,
            "monero_txid_commitment": self.monero_txid_commitment,
            "reorg_schedule_id": self.reorg_schedule_id,
            "receipt_id": self.receipt_id
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqReserveApproval {
    pub approval_id: String,
    pub policy_id: String,
    pub reserve_epoch: u64,
    pub attestor_id: String,
    pub attestor_weight: u64,
    pub reserve_root: String,
    pub coverage_bps: u64,
    pub pq_signature_commitment: String,
    pub status: PqApprovalStatus,
    pub created_height: u64,
}

impl PqReserveApproval {
    pub fn new(
        policy_id: &str,
        reserve_epoch: u64,
        attestor_id: &str,
        attestor_weight: u64,
        reserve_root: &str,
        coverage_bps: u64,
        created_height: u64,
    ) -> Self {
        let approval_id = private_exit_id(
            "PQ-APPROVAL",
            &[
                policy_id,
                attestor_id,
                reserve_root,
                &reserve_epoch.to_string(),
            ],
        );
        let pq_signature_commitment = domain_hash(
            "MONERO-BRIDGE-PRIVATE-EXIT-PQ-APPROVAL-SIGNATURE",
            &[
                HashPart::Str(policy_id),
                HashPart::Str(attestor_id),
                HashPart::Str(reserve_root),
                HashPart::Int(reserve_epoch as i128),
            ],
            32,
        );
        Self {
            approval_id,
            policy_id: policy_id.to_string(),
            reserve_epoch,
            attestor_id: attestor_id.to_string(),
            attestor_weight,
            reserve_root: reserve_root.to_string(),
            coverage_bps,
            pq_signature_commitment,
            status: PqApprovalStatus::Submitted,
            created_height,
        }
    }

    pub fn validate(&self) -> MoneroBridgePrivateExitCovenantResult<()> {
        validate_id("approval id", &self.approval_id)?;
        validate_id("policy id", &self.policy_id)?;
        validate_non_empty("attestor id", &self.attestor_id)?;
        validate_non_empty("reserve root", &self.reserve_root)?;
        validate_non_empty("pq signature commitment", &self.pq_signature_commitment)?;
        if self.attestor_weight == 0 {
            return Err("approval weight must be non-zero".to_string());
        }
        if self.coverage_bps < MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_BPS {
            return Err("approval coverage must cover at least 100%".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "approval_id": self.approval_id,
            "policy_id": self.policy_id,
            "reserve_epoch": self.reserve_epoch,
            "attestor_id": self.attestor_id,
            "attestor_weight": self.attestor_weight,
            "reserve_root": self.reserve_root,
            "coverage_bps": self.coverage_bps,
            "pq_signature_commitment": self.pq_signature_commitment,
            "status": self.status.as_str(),
            "created_height": self.created_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MakerLiquidityCovenant {
    pub maker_id: String,
    pub maker_commitment: String,
    pub reserve_root: String,
    pub available_units: u64,
    pub reserved_units: u64,
    pub max_exposure_units: u64,
    pub fee_bps: u64,
    pub coverage_bps: u64,
    pub status: MakerCovenantStatus,
    pub active_policy_ids: BTreeSet<String>,
    pub slash_evidence_ids: BTreeSet<String>,
    pub created_height: u64,
    pub updated_height: u64,
}

impl MakerLiquidityCovenant {
    pub fn new(
        maker_commitment: &str,
        reserve_root: &str,
        available_units: u64,
        fee_bps: u64,
        coverage_bps: u64,
        created_height: u64,
        config: &MoneroBridgePrivateExitCovenantConfig,
    ) -> Self {
        let maker_id = private_exit_id("MAKER", &[maker_commitment, reserve_root]);
        Self {
            maker_id,
            maker_commitment: maker_commitment.to_string(),
            reserve_root: reserve_root.to_string(),
            available_units,
            reserved_units: 0,
            max_exposure_units: config.max_maker_exposure_units,
            fee_bps,
            coverage_bps,
            status: MakerCovenantStatus::Active,
            active_policy_ids: BTreeSet::new(),
            slash_evidence_ids: BTreeSet::new(),
            created_height,
            updated_height: created_height,
        }
    }

    pub fn free_units(&self) -> u64 {
        self.available_units.saturating_sub(self.reserved_units)
    }

    pub fn can_reserve(&self, amount: u64) -> bool {
        self.status.can_bind()
            && self.free_units() >= amount
            && self.reserved_units.saturating_add(amount) <= self.max_exposure_units
    }

    pub fn validate(&self) -> MoneroBridgePrivateExitCovenantResult<()> {
        validate_id("maker id", &self.maker_id)?;
        validate_non_empty("maker commitment", &self.maker_commitment)?;
        validate_non_empty("reserve root", &self.reserve_root)?;
        validate_bps(self.fee_bps, "maker fee")?;
        if self.coverage_bps < MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_BPS {
            return Err("maker coverage must cover at least 100%".to_string());
        }
        if self.reserved_units > self.available_units {
            return Err("maker reserved units exceed available units".to_string());
        }
        if self.max_exposure_units == 0 {
            return Err("maker max exposure must be non-zero".to_string());
        }
        if self.updated_height < self.created_height {
            return Err("maker updated height cannot precede creation".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "maker_id": self.maker_id,
            "maker_commitment": self.maker_commitment,
            "reserve_root": self.reserve_root,
            "available_units": self.available_units,
            "reserved_units": self.reserved_units,
            "free_units": self.free_units(),
            "max_exposure_units": self.max_exposure_units,
            "fee_bps": self.fee_bps,
            "coverage_bps": self.coverage_bps,
            "status": self.status.as_str(),
            "active_policy_ids": self.active_policy_ids.iter().cloned().collect::<Vec<_>>(),
            "slash_evidence_ids": self.slash_evidence_ids.iter().cloned().collect::<Vec<_>>(),
            "created_height": self.created_height,
            "updated_height": self.updated_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgDelayBand {
    pub depth: u64,
    pub delay_blocks: u64,
    pub fee_surcharge_bps: u64,
}

impl ReorgDelayBand {
    pub fn public_record(&self) -> Value {
        json!({
            "depth": self.depth,
            "delay_blocks": self.delay_blocks,
            "fee_surcharge_bps": self.fee_surcharge_bps
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgDelaySchedule {
    pub schedule_id: String,
    pub policy_id: String,
    pub payout_id: String,
    pub status: ReorgDelayStatus,
    pub observed_depth: u64,
    pub release_height: u64,
    pub bands: Vec<ReorgDelayBand>,
    pub created_height: u64,
    pub updated_height: u64,
}

impl ReorgDelaySchedule {
    pub fn new(
        policy_id: &str,
        payout_id: &str,
        observed_depth: u64,
        created_height: u64,
        config: &MoneroBridgePrivateExitCovenantConfig,
    ) -> Self {
        let bands = vec![
            ReorgDelayBand {
                depth: 1,
                delay_blocks: config.reorg_finality_blocks,
                fee_surcharge_bps: 0,
            },
            ReorgDelayBand {
                depth: 2,
                delay_blocks: config.reorg_finality_blocks.saturating_mul(2),
                fee_surcharge_bps: 25,
            },
            ReorgDelayBand {
                depth: 4,
                delay_blocks: config.reorg_finality_blocks.saturating_mul(4),
                fee_surcharge_bps: 75,
            },
        ];
        let schedule_id = private_exit_id(
            "REORG-SCHEDULE",
            &[policy_id, payout_id, &observed_depth.to_string()],
        );
        let delay = reorg_delay_for_depth(observed_depth, &bands);
        Self {
            schedule_id,
            policy_id: policy_id.to_string(),
            payout_id: payout_id.to_string(),
            status: ReorgDelayStatus::Active,
            observed_depth,
            release_height: created_height.saturating_add(delay),
            bands,
            created_height,
            updated_height: created_height,
        }
    }

    pub fn validate(&self) -> MoneroBridgePrivateExitCovenantResult<()> {
        validate_id("schedule id", &self.schedule_id)?;
        validate_id("policy id", &self.policy_id)?;
        validate_id("payout id", &self.payout_id)?;
        if self.bands.is_empty() {
            return Err("reorg schedule must contain at least one band".to_string());
        }
        let mut previous_depth = 0;
        for band in &self.bands {
            if band.depth == 0 || band.delay_blocks == 0 {
                return Err("reorg bands require non-zero depth and delay".to_string());
            }
            if band.depth <= previous_depth {
                return Err("reorg bands must be ordered by increasing depth".to_string());
            }
            validate_bps(band.fee_surcharge_bps, "reorg fee surcharge")?;
            previous_depth = band.depth;
        }
        if self.release_height < self.created_height {
            return Err("reorg release height cannot precede creation".to_string());
        }
        if self.updated_height < self.created_height {
            return Err("reorg update height cannot precede creation".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schedule_id": self.schedule_id,
            "policy_id": self.policy_id,
            "payout_id": self.payout_id,
            "status": self.status.as_str(),
            "observed_depth": self.observed_depth,
            "release_height": self.release_height,
            "bands": self.bands.iter().map(ReorgDelayBand::public_record).collect::<Vec<_>>(),
            "created_height": self.created_height,
            "updated_height": self.updated_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeExitSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub policy_id: Option<String>,
    pub budget_piconero: u64,
    pub spent_piconero: u64,
    pub max_rebate_bps: u64,
    pub min_privacy_set_size: u64,
    pub status: SponsorshipStatus,
    pub created_height: u64,
    pub expires_height: u64,
}

impl LowFeeExitSponsorship {
    pub fn new(
        seed: &str,
        sponsor_commitment: &str,
        budget_piconero: u64,
        created_height: u64,
        config: &MoneroBridgePrivateExitCovenantConfig,
    ) -> Self {
        let sponsorship_id = private_exit_id("SPONSORSHIP", &[seed, sponsor_commitment]);
        Self {
            sponsorship_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            policy_id: None,
            budget_piconero,
            spent_piconero: 0,
            max_rebate_bps: config.max_sponsor_rebate_bps,
            min_privacy_set_size: config.min_privacy_set_size,
            status: SponsorshipStatus::Offered,
            created_height,
            expires_height: created_height.saturating_add(config.exit_ttl_blocks),
        }
    }

    pub fn remaining_piconero(&self) -> u64 {
        self.budget_piconero.saturating_sub(self.spent_piconero)
    }

    pub fn validate(&self) -> MoneroBridgePrivateExitCovenantResult<()> {
        validate_id("sponsorship id", &self.sponsorship_id)?;
        validate_non_empty("sponsor commitment", &self.sponsor_commitment)?;
        validate_bps(self.max_rebate_bps, "sponsorship rebate")?;
        if self.budget_piconero == 0 {
            return Err("sponsorship budget must be non-zero".to_string());
        }
        if self.spent_piconero > self.budget_piconero {
            return Err("sponsorship spent budget exceeds budget".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("sponsorship privacy set must be non-zero".to_string());
        }
        if self.expires_height <= self.created_height {
            return Err("sponsorship expiry must be after creation".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "policy_id": self.policy_id,
            "budget_piconero": self.budget_piconero,
            "spent_piconero": self.spent_piconero,
            "remaining_piconero": self.remaining_piconero(),
            "max_rebate_bps": self.max_rebate_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalReceipt {
    pub receipt_id: String,
    pub policy_id: String,
    pub payout_id: String,
    pub maker_id: String,
    pub receipt_nullifier: String,
    pub monero_txid_commitment: String,
    pub observed_height: u64,
    pub finalizable_height: u64,
    pub fee_paid_piconero: u64,
    pub sponsor_rebate_piconero: u64,
    pub status: WithdrawalReceiptStatus,
    pub challenge_ids: BTreeSet<String>,
}

impl WithdrawalReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_id: &str,
        payout_id: &str,
        maker_id: &str,
        receipt_nullifier: &str,
        monero_txid_commitment: &str,
        observed_height: u64,
        fee_paid_piconero: u64,
        sponsor_rebate_piconero: u64,
        config: &MoneroBridgePrivateExitCovenantConfig,
    ) -> Self {
        let receipt_id = private_exit_id(
            "RECEIPT",
            &[
                policy_id,
                payout_id,
                maker_id,
                receipt_nullifier,
                monero_txid_commitment,
            ],
        );
        Self {
            receipt_id,
            policy_id: policy_id.to_string(),
            payout_id: payout_id.to_string(),
            maker_id: maker_id.to_string(),
            receipt_nullifier: receipt_nullifier.to_string(),
            monero_txid_commitment: monero_txid_commitment.to_string(),
            observed_height,
            finalizable_height: observed_height
                .saturating_add(config.reorg_finality_blocks)
                .saturating_add(config.challenge_window_blocks),
            fee_paid_piconero,
            sponsor_rebate_piconero,
            status: WithdrawalReceiptStatus::PendingReveal,
            challenge_ids: BTreeSet::new(),
        }
    }

    pub fn validate(&self) -> MoneroBridgePrivateExitCovenantResult<()> {
        validate_id("receipt id", &self.receipt_id)?;
        validate_id("policy id", &self.policy_id)?;
        validate_id("payout id", &self.payout_id)?;
        validate_id("maker id", &self.maker_id)?;
        validate_non_empty("receipt nullifier", &self.receipt_nullifier)?;
        validate_non_empty("monero txid commitment", &self.monero_txid_commitment)?;
        if self.finalizable_height <= self.observed_height {
            return Err("receipt finalizable height must follow observation".to_string());
        }
        if self.sponsor_rebate_piconero > self.fee_paid_piconero {
            return Err("receipt sponsor rebate cannot exceed fee paid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "policy_id": self.policy_id,
            "payout_id": self.payout_id,
            "maker_id": self.maker_id,
            "receipt_nullifier": self.receipt_nullifier,
            "monero_txid_commitment": self.monero_txid_commitment,
            "observed_height": self.observed_height,
            "finalizable_height": self.finalizable_height,
            "fee_paid_piconero": self.fee_paid_piconero,
            "sponsor_rebate_piconero": self.sponsor_rebate_piconero,
            "status": self.status.as_str(),
            "challenge_ids": self.challenge_ids.iter().cloned().collect::<Vec<_>>()
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyFreeze {
    pub freeze_id: String,
    pub target_policy_id: Option<String>,
    pub target_maker_id: Option<String>,
    pub reason_code: String,
    pub evidence_root: String,
    pub council_weight: u64,
    pub status: EmergencyFreezeStatus,
    pub created_height: u64,
    pub expires_height: u64,
    pub release_height: Option<u64>,
}

impl EmergencyFreeze {
    pub fn new(
        seed: &str,
        target_policy_id: Option<String>,
        target_maker_id: Option<String>,
        reason_code: &str,
        evidence_root: &str,
        council_weight: u64,
        created_height: u64,
        config: &MoneroBridgePrivateExitCovenantConfig,
    ) -> Self {
        let policy_part = target_policy_id.as_deref().unwrap_or("all-policies");
        let maker_part = target_maker_id.as_deref().unwrap_or("all-makers");
        let freeze_id = private_exit_id(
            "FREEZE",
            &[seed, policy_part, maker_part, reason_code, evidence_root],
        );
        Self {
            freeze_id,
            target_policy_id,
            target_maker_id,
            reason_code: reason_code.to_string(),
            evidence_root: evidence_root.to_string(),
            council_weight,
            status: EmergencyFreezeStatus::Proposed,
            created_height,
            expires_height: created_height.saturating_add(config.freeze_ttl_blocks),
            release_height: None,
        }
    }

    pub fn validate(&self) -> MoneroBridgePrivateExitCovenantResult<()> {
        validate_id("freeze id", &self.freeze_id)?;
        validate_non_empty("freeze reason", &self.reason_code)?;
        validate_non_empty("freeze evidence root", &self.evidence_root)?;
        if self.target_policy_id.is_none() && self.target_maker_id.is_none() {
            return Err("freeze must target a policy or maker".to_string());
        }
        if self.council_weight == 0 {
            return Err("freeze council weight must be non-zero".to_string());
        }
        if self.expires_height <= self.created_height {
            return Err("freeze expiry must be after creation".to_string());
        }
        if let Some(release_height) = self.release_height {
            if release_height < self.created_height {
                return Err("freeze release cannot precede creation".to_string());
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "freeze_id": self.freeze_id,
            "target_policy_id": self.target_policy_id,
            "target_maker_id": self.target_maker_id,
            "reason_code": self.reason_code,
            "evidence_root": self.evidence_root,
            "council_weight": self.council_weight,
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "release_height": self.release_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeSlashEvidence {
    pub challenge_id: String,
    pub policy_id: String,
    pub accused_maker_id: Option<String>,
    pub accused_attestor_id: Option<String>,
    pub receipt_id: Option<String>,
    pub evidence_root: String,
    pub evidence_kind: String,
    pub slash_amount_units: u64,
    pub challenger_commitment: String,
    pub status: ChallengeStatus,
    pub created_height: u64,
    pub expires_height: u64,
}

impl ChallengeSlashEvidence {
    pub fn new(
        seed: &str,
        policy_id: &str,
        accused_maker_id: Option<String>,
        accused_attestor_id: Option<String>,
        receipt_id: Option<String>,
        evidence_kind: &str,
        slash_amount_units: u64,
        challenger_commitment: &str,
        created_height: u64,
        config: &MoneroBridgePrivateExitCovenantConfig,
    ) -> Self {
        let maker_part = accused_maker_id.as_deref().unwrap_or("no-maker");
        let attestor_part = accused_attestor_id.as_deref().unwrap_or("no-attestor");
        let receipt_part = receipt_id.as_deref().unwrap_or("no-receipt");
        let evidence_root = domain_hash(
            "MONERO-BRIDGE-PRIVATE-EXIT-CHALLENGE-EVIDENCE",
            &[
                HashPart::Str(seed),
                HashPart::Str(policy_id),
                HashPart::Str(maker_part),
                HashPart::Str(attestor_part),
                HashPart::Str(receipt_part),
                HashPart::Str(evidence_kind),
            ],
            32,
        );
        let challenge_id = private_exit_id(
            "CHALLENGE",
            &[
                policy_id,
                maker_part,
                attestor_part,
                receipt_part,
                &evidence_root,
            ],
        );
        Self {
            challenge_id,
            policy_id: policy_id.to_string(),
            accused_maker_id,
            accused_attestor_id,
            receipt_id,
            evidence_root,
            evidence_kind: evidence_kind.to_string(),
            slash_amount_units,
            challenger_commitment: challenger_commitment.to_string(),
            status: ChallengeStatus::Open,
            created_height,
            expires_height: created_height.saturating_add(config.challenge_window_blocks),
        }
    }

    pub fn validate(&self) -> MoneroBridgePrivateExitCovenantResult<()> {
        validate_id("challenge id", &self.challenge_id)?;
        validate_id("policy id", &self.policy_id)?;
        validate_non_empty("evidence root", &self.evidence_root)?;
        validate_non_empty("evidence kind", &self.evidence_kind)?;
        validate_non_empty("challenger commitment", &self.challenger_commitment)?;
        if self.accused_maker_id.is_none() && self.accused_attestor_id.is_none() {
            return Err("challenge must accuse a maker or attestor".to_string());
        }
        if self.slash_amount_units == 0 {
            return Err("challenge slash amount must be non-zero".to_string());
        }
        if self.expires_height <= self.created_height {
            return Err("challenge expiry must follow creation".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "policy_id": self.policy_id,
            "accused_maker_id": self.accused_maker_id,
            "accused_attestor_id": self.accused_attestor_id,
            "receipt_id": self.receipt_id,
            "evidence_root": self.evidence_root,
            "evidence_kind": self.evidence_kind,
            "slash_amount_units": self.slash_amount_units,
            "challenger_commitment": self.challenger_commitment,
            "status": self.status.as_str(),
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateExitCovenantEvent {
    pub event_id: String,
    pub height: u64,
    pub kind: String,
    pub subject_id: String,
    pub state_root: String,
    pub payload_root: String,
}

impl PrivateExitCovenantEvent {
    pub fn new(
        height: u64,
        kind: &str,
        subject_id: &str,
        state_root: &str,
        payload: Value,
    ) -> Self {
        let payload_root = domain_hash(
            "MONERO-BRIDGE-PRIVATE-EXIT-EVENT-PAYLOAD",
            &[HashPart::Json(&payload)],
            32,
        );
        let event_id = private_exit_id(
            "EVENT",
            &[
                kind,
                subject_id,
                state_root,
                &height.to_string(),
                &payload_root,
            ],
        );
        Self {
            event_id,
            height,
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            state_root: state_root.to_string(),
            payload_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "height": self.height,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "state_root": self.state_root,
            "payload_root": self.payload_root
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgePrivateExitCovenantRoots {
    pub config_root: String,
    pub policy_root: String,
    pub payout_root: String,
    pub pq_approval_root: String,
    pub maker_root: String,
    pub reorg_schedule_root: String,
    pub sponsorship_root: String,
    pub receipt_root: String,
    pub freeze_root: String,
    pub challenge_root: String,
    pub event_root: String,
    pub public_nullifier_root: String,
}

impl MoneroBridgePrivateExitCovenantRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "policy_root": self.policy_root,
            "payout_root": self.payout_root,
            "pq_approval_root": self.pq_approval_root,
            "maker_root": self.maker_root,
            "reorg_schedule_root": self.reorg_schedule_root,
            "sponsorship_root": self.sponsorship_root,
            "receipt_root": self.receipt_root,
            "freeze_root": self.freeze_root,
            "challenge_root": self.challenge_root,
            "event_root": self.event_root,
            "public_nullifier_root": self.public_nullifier_root
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgePrivateExitCovenantCounters {
    pub policies: u64,
    pub live_policies: u64,
    pub completed_policies: u64,
    pub payouts: u64,
    pub live_payouts: u64,
    pub pq_approvals: u64,
    pub accepted_pq_approvals: u64,
    pub makers: u64,
    pub active_makers: u64,
    pub reorg_schedules: u64,
    pub sponsorships: u64,
    pub live_sponsorships: u64,
    pub receipts: u64,
    pub finalized_receipts: u64,
    pub freezes: u64,
    pub active_freezes: u64,
    pub challenges: u64,
    pub live_challenges: u64,
    pub events: u64,
    pub reserved_units: u64,
    pub sponsored_piconero: u64,
}

impl MoneroBridgePrivateExitCovenantCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "policies": self.policies,
            "live_policies": self.live_policies,
            "completed_policies": self.completed_policies,
            "payouts": self.payouts,
            "live_payouts": self.live_payouts,
            "pq_approvals": self.pq_approvals,
            "accepted_pq_approvals": self.accepted_pq_approvals,
            "makers": self.makers,
            "active_makers": self.active_makers,
            "reorg_schedules": self.reorg_schedules,
            "sponsorships": self.sponsorships,
            "live_sponsorships": self.live_sponsorships,
            "receipts": self.receipts,
            "finalized_receipts": self.finalized_receipts,
            "freezes": self.freezes,
            "active_freezes": self.active_freezes,
            "challenges": self.challenges,
            "live_challenges": self.live_challenges,
            "events": self.events,
            "reserved_units": self.reserved_units,
            "sponsored_piconero": self.sponsored_piconero
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgePrivateExitCovenantState {
    pub config: MoneroBridgePrivateExitCovenantConfig,
    pub height: u64,
    pub policies: BTreeMap<String, ShieldedExitPolicy>,
    pub payouts: BTreeMap<String, StealthPayoutCommitment>,
    pub pq_approvals: BTreeMap<String, PqReserveApproval>,
    pub maker_covenants: BTreeMap<String, MakerLiquidityCovenant>,
    pub reorg_schedules: BTreeMap<String, ReorgDelaySchedule>,
    pub sponsorships: BTreeMap<String, LowFeeExitSponsorship>,
    pub withdrawal_receipts: BTreeMap<String, WithdrawalReceipt>,
    pub emergency_freezes: BTreeMap<String, EmergencyFreeze>,
    pub challenges: BTreeMap<String, ChallengeSlashEvidence>,
    pub public_nullifiers: BTreeSet<String>,
    pub events: BTreeMap<String, PrivateExitCovenantEvent>,
}

impl Default for MoneroBridgePrivateExitCovenantState {
    fn default() -> Self {
        Self::new(MoneroBridgePrivateExitCovenantConfig::default())
    }
}

impl MoneroBridgePrivateExitCovenantState {
    pub fn new(config: MoneroBridgePrivateExitCovenantConfig) -> Self {
        Self {
            config,
            height: MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_DEVNET_HEIGHT,
            policies: BTreeMap::new(),
            payouts: BTreeMap::new(),
            pq_approvals: BTreeMap::new(),
            maker_covenants: BTreeMap::new(),
            reorg_schedules: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            withdrawal_receipts: BTreeMap::new(),
            emergency_freezes: BTreeMap::new(),
            challenges: BTreeMap::new(),
            public_nullifiers: BTreeSet::new(),
            events: BTreeMap::new(),
        }
    }

    pub fn devnet() -> MoneroBridgePrivateExitCovenantResult<Self> {
        let mut state = Self::default();
        state.config.validate()?;
        let maker_a = state.register_maker_covenant(
            "devnet-maker-a-commitment",
            "devnet-reserve-root-a",
            3_500_000,
            14,
            12_000,
        )?;
        let maker_b = state.register_maker_covenant(
            "devnet-maker-b-commitment",
            "devnet-reserve-root-b",
            2_400_000,
            18,
            11_500,
        )?;
        let sponsor = state.offer_low_fee_sponsorship(
            "devnet-sponsor-1",
            "devnet-sponsor-commitment",
            state.config.sponsor_pool_piconero,
        )?;
        let policy = state.open_policy(
            "devnet-policy-1",
            "owner-commitment-a",
            "nullifier-root-a",
            "spend-auth-root-a",
            "amount-commitment-a",
            10_000,
            650_000,
            35_000,
            PrivateExitSpeed::LowFee,
            ShieldedExitClass::SponsoredLowFee,
        )?;
        state.attach_sponsorship(&policy.policy_id, &sponsor.sponsorship_id)?;
        let policy_b = state.open_policy(
            "devnet-policy-2",
            "owner-commitment-b",
            "nullifier-root-b",
            "spend-auth-root-b",
            "amount-commitment-b",
            25_000,
            1_100_000,
            70_000,
            PrivateExitSpeed::Fast,
            ShieldedExitClass::FullyShielded,
        )?;
        state.approve_policy_pq(
            &policy.policy_id,
            7,
            "reserve-attestor-a",
            2,
            "devnet-reserve-root-a",
            12_000,
        )?;
        state.approve_policy_pq(
            &policy.policy_id,
            7,
            "reserve-attestor-b",
            2,
            "devnet-reserve-root-a",
            12_200,
        )?;
        state.approve_policy_pq(
            &policy_b.policy_id,
            7,
            "reserve-attestor-c",
            3,
            "devnet-reserve-root-b",
            11_800,
        )?;
        let payout = state.commit_stealth_payout(
            &policy.policy_id,
            &maker_a.maker_id,
            "stealth-address-commitment-a",
            "tx-public-key-commitment-a",
            "encrypted-view-tag-root-a",
            "amount-commitment-a",
            "fee-commitment-a",
        )?;
        let payout_b = state.commit_stealth_payout(
            &policy_b.policy_id,
            &maker_b.maker_id,
            "stealth-address-commitment-b",
            "tx-public-key-commitment-b",
            "encrypted-view-tag-root-b",
            "amount-commitment-b",
            "fee-commitment-b",
        )?;
        state.schedule_reorg_delay(&policy.policy_id, &payout.payout_id, 1)?;
        state.observe_withdrawal_receipt(
            &policy.policy_id,
            &payout.payout_id,
            &maker_a.maker_id,
            "receipt-nullifier-a",
            "monero-txid-commitment-a",
            18_000,
            12_000,
        )?;
        state.observe_withdrawal_receipt(
            &policy_b.policy_id,
            &payout_b.payout_id,
            &maker_b.maker_id,
            "receipt-nullifier-b",
            "monero-txid-commitment-b",
            42_000,
            0,
        )?;
        state.open_challenge(
            "devnet-challenge-1",
            &policy_b.policy_id,
            Some(maker_b.maker_id.clone()),
            None,
            None,
            "late-broadcast-risk",
            75_000,
            "challenger-commitment-a",
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn advance_height(&mut self, blocks: u64) {
        self.height = self.height.saturating_add(blocks);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_policy(
        &mut self,
        seed: &str,
        owner_commitment: &str,
        nullifier_root: &str,
        spend_auth_root: &str,
        amount_commitment: &str,
        amount_bucket: u64,
        max_amount_units: u64,
        fee_cap_piconero: u64,
        speed: PrivateExitSpeed,
        exit_class: ShieldedExitClass,
    ) -> MoneroBridgePrivateExitCovenantResult<ShieldedExitPolicy> {
        if self.policies.len() >= MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_POLICIES {
            return Err("policy capacity reached".to_string());
        }
        if self
            .policy_exposure_units()
            .saturating_add(max_amount_units)
            > self.config.max_policy_exposure_units
        {
            return Err("policy exposure limit exceeded".to_string());
        }
        let policy = ShieldedExitPolicy::new(
            seed,
            owner_commitment,
            nullifier_root,
            spend_auth_root,
            amount_commitment,
            amount_bucket,
            max_amount_units,
            fee_cap_piconero,
            speed,
            exit_class,
            self.height,
            &self.config,
        );
        policy.validate()?;
        if self.policies.contains_key(&policy.policy_id) {
            return Err("policy already exists".to_string());
        }
        self.public_nullifiers.insert(policy.nullifier_root.clone());
        self.policies
            .insert(policy.policy_id.clone(), policy.clone());
        self.record_event("policy_opened", &policy.policy_id, policy.public_record())?;
        Ok(policy)
    }

    pub fn register_maker_covenant(
        &mut self,
        maker_commitment: &str,
        reserve_root: &str,
        available_units: u64,
        fee_bps: u64,
        coverage_bps: u64,
    ) -> MoneroBridgePrivateExitCovenantResult<MakerLiquidityCovenant> {
        if self.maker_covenants.len() >= MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_MAKERS {
            return Err("maker capacity reached".to_string());
        }
        let maker = MakerLiquidityCovenant::new(
            maker_commitment,
            reserve_root,
            available_units,
            fee_bps,
            coverage_bps,
            self.height,
            &self.config,
        );
        maker.validate()?;
        if self.maker_covenants.contains_key(&maker.maker_id) {
            return Err("maker covenant already exists".to_string());
        }
        self.maker_covenants
            .insert(maker.maker_id.clone(), maker.clone());
        self.record_event("maker_registered", &maker.maker_id, maker.public_record())?;
        Ok(maker)
    }

    pub fn offer_low_fee_sponsorship(
        &mut self,
        seed: &str,
        sponsor_commitment: &str,
        budget_piconero: u64,
    ) -> MoneroBridgePrivateExitCovenantResult<LowFeeExitSponsorship> {
        if self.sponsorships.len() >= MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_SPONSORSHIPS {
            return Err("sponsorship capacity reached".to_string());
        }
        let sponsorship = LowFeeExitSponsorship::new(
            seed,
            sponsor_commitment,
            budget_piconero,
            self.height,
            &self.config,
        );
        sponsorship.validate()?;
        if self.sponsorships.contains_key(&sponsorship.sponsorship_id) {
            return Err("sponsorship already exists".to_string());
        }
        self.sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship.clone());
        self.record_event(
            "sponsorship_offered",
            &sponsorship.sponsorship_id,
            sponsorship.public_record(),
        )?;
        Ok(sponsorship)
    }

    pub fn attach_sponsorship(
        &mut self,
        policy_id: &str,
        sponsorship_id: &str,
    ) -> MoneroBridgePrivateExitCovenantResult<()> {
        let policy = self
            .policies
            .get_mut(policy_id)
            .ok_or_else(|| "policy not found".to_string())?;
        if !policy.status.live() {
            return Err("policy is not live".to_string());
        }
        let sponsorship = self
            .sponsorships
            .get_mut(sponsorship_id)
            .ok_or_else(|| "sponsorship not found".to_string())?;
        if !sponsorship.status.live() {
            return Err("sponsorship is not live".to_string());
        }
        if sponsorship.remaining_piconero() == 0 {
            return Err("sponsorship has no remaining budget".to_string());
        }
        sponsorship.policy_id = Some(policy_id.to_string());
        sponsorship.status = SponsorshipStatus::Reserved;
        policy.sponsorship_id = Some(sponsorship_id.to_string());
        policy.status = ExitPolicyStatus::Open;
        let payload = json!({
            "policy_id": policy_id,
            "sponsorship_id": sponsorship_id
        });
        self.record_event("sponsorship_attached", policy_id, payload)
    }

    pub fn approve_policy_pq(
        &mut self,
        policy_id: &str,
        reserve_epoch: u64,
        attestor_id: &str,
        attestor_weight: u64,
        reserve_root: &str,
        coverage_bps: u64,
    ) -> MoneroBridgePrivateExitCovenantResult<PqReserveApproval> {
        if self.pq_approvals.len() >= MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_APPROVALS {
            return Err("pq approval capacity reached".to_string());
        }
        if !self.policies.contains_key(policy_id) {
            return Err("policy not found".to_string());
        }
        let approval = PqReserveApproval::new(
            policy_id,
            reserve_epoch,
            attestor_id,
            attestor_weight,
            reserve_root,
            coverage_bps,
            self.height,
        );
        approval.validate()?;
        if self.pq_approvals.contains_key(&approval.approval_id) {
            return Err("pq approval already exists".to_string());
        }
        self.pq_approvals
            .insert(approval.approval_id.clone(), approval.clone());
        let weight = self.pq_weight_for_policy(policy_id);
        if weight >= self.config.min_pq_approval_weight {
            if let Some(policy) = self.policies.get_mut(policy_id) {
                if matches!(policy.status, ExitPolicyStatus::Open) {
                    policy.status = ExitPolicyStatus::PqApproved;
                }
            }
        }
        self.record_event(
            "pq_approval_submitted",
            &approval.approval_id,
            approval.public_record(),
        )?;
        Ok(approval)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_stealth_payout(
        &mut self,
        policy_id: &str,
        maker_id: &str,
        stealth_address_commitment: &str,
        tx_public_key_commitment: &str,
        encrypted_view_tag_root: &str,
        amount_commitment: &str,
        fee_commitment: &str,
    ) -> MoneroBridgePrivateExitCovenantResult<StealthPayoutCommitment> {
        if self.payouts.len() >= MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_PAYOUTS {
            return Err("payout capacity reached".to_string());
        }
        let amount = self
            .policies
            .get(policy_id)
            .map(|policy| policy.max_amount_units)
            .ok_or_else(|| "policy not found".to_string())?;
        let maker = self
            .maker_covenants
            .get_mut(maker_id)
            .ok_or_else(|| "maker covenant not found".to_string())?;
        if !maker.can_reserve(amount) {
            return Err("maker cannot reserve requested amount".to_string());
        }
        let payout = StealthPayoutCommitment::new(
            policy_id,
            maker_id,
            stealth_address_commitment,
            tx_public_key_commitment,
            encrypted_view_tag_root,
            amount_commitment,
            fee_commitment,
            self.height,
            &self.config,
        );
        payout.validate()?;
        if self.payouts.contains_key(&payout.payout_id) {
            return Err("payout already exists".to_string());
        }
        maker.reserved_units = maker.reserved_units.saturating_add(amount);
        maker.active_policy_ids.insert(policy_id.to_string());
        maker.status = MakerCovenantStatus::Bound;
        maker.updated_height = self.height;
        let policy = self
            .policies
            .get_mut(policy_id)
            .ok_or_else(|| "policy not found".to_string())?;
        policy.maker_id = Some(maker_id.to_string());
        policy.payout_id = Some(payout.payout_id.clone());
        policy.status = ExitPolicyStatus::PayoutCommitted;
        self.payouts
            .insert(payout.payout_id.clone(), payout.clone());
        self.record_event(
            "payout_committed",
            &payout.payout_id,
            payout.public_record(),
        )?;
        Ok(payout)
    }

    pub fn schedule_reorg_delay(
        &mut self,
        policy_id: &str,
        payout_id: &str,
        observed_depth: u64,
    ) -> MoneroBridgePrivateExitCovenantResult<ReorgDelaySchedule> {
        if self.reorg_schedules.len() >= MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_REORG_SCHEDULES {
            return Err("reorg schedule capacity reached".to_string());
        }
        if !self.policies.contains_key(policy_id) {
            return Err("policy not found".to_string());
        }
        if !self.payouts.contains_key(payout_id) {
            return Err("payout not found".to_string());
        }
        let schedule = ReorgDelaySchedule::new(
            policy_id,
            payout_id,
            observed_depth,
            self.height,
            &self.config,
        );
        schedule.validate()?;
        if self.reorg_schedules.contains_key(&schedule.schedule_id) {
            return Err("reorg schedule already exists".to_string());
        }
        if let Some(policy) = self.policies.get_mut(policy_id) {
            policy.status = ExitPolicyStatus::ReorgDelayed;
        }
        if let Some(payout) = self.payouts.get_mut(payout_id) {
            payout.status = PayoutCommitmentStatus::ReorgDelayed;
            payout.reorg_schedule_id = Some(schedule.schedule_id.clone());
        }
        self.reorg_schedules
            .insert(schedule.schedule_id.clone(), schedule.clone());
        self.record_event(
            "reorg_delay_scheduled",
            &schedule.schedule_id,
            schedule.public_record(),
        )?;
        Ok(schedule)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_withdrawal_receipt(
        &mut self,
        policy_id: &str,
        payout_id: &str,
        maker_id: &str,
        receipt_nullifier: &str,
        monero_txid_commitment: &str,
        fee_paid_piconero: u64,
        sponsor_rebate_piconero: u64,
    ) -> MoneroBridgePrivateExitCovenantResult<WithdrawalReceipt> {
        if self.withdrawal_receipts.len() >= MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_RECEIPTS {
            return Err("receipt capacity reached".to_string());
        }
        if self.public_nullifiers.contains(receipt_nullifier) {
            return Err("receipt nullifier already used".to_string());
        }
        let receipt = WithdrawalReceipt::new(
            policy_id,
            payout_id,
            maker_id,
            receipt_nullifier,
            monero_txid_commitment,
            self.height,
            fee_paid_piconero,
            sponsor_rebate_piconero,
            &self.config,
        );
        receipt.validate()?;
        if self.withdrawal_receipts.contains_key(&receipt.receipt_id) {
            return Err("receipt already exists".to_string());
        }
        self.public_nullifiers.insert(receipt_nullifier.to_string());
        self.apply_sponsor_spend(policy_id, sponsor_rebate_piconero)?;
        if let Some(policy) = self.policies.get_mut(policy_id) {
            policy.status = ExitPolicyStatus::ReceiptPending;
        }
        if let Some(payout) = self.payouts.get_mut(payout_id) {
            payout.status = PayoutCommitmentStatus::Observed;
            payout.observed_height = Some(self.height);
            payout.monero_txid_commitment = Some(monero_txid_commitment.to_string());
            payout.receipt_id = Some(receipt.receipt_id.clone());
        }
        self.withdrawal_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.record_event(
            "receipt_observed",
            &receipt.receipt_id,
            receipt.public_record(),
        )?;
        Ok(receipt)
    }

    pub fn propose_emergency_freeze(
        &mut self,
        seed: &str,
        target_policy_id: Option<String>,
        target_maker_id: Option<String>,
        reason_code: &str,
        evidence_root: &str,
        council_weight: u64,
    ) -> MoneroBridgePrivateExitCovenantResult<EmergencyFreeze> {
        if self.emergency_freezes.len() >= MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_FREEZES {
            return Err("freeze capacity reached".to_string());
        }
        let mut freeze = EmergencyFreeze::new(
            seed,
            target_policy_id,
            target_maker_id,
            reason_code,
            evidence_root,
            council_weight,
            self.height,
            &self.config,
        );
        freeze.validate()?;
        if freeze.council_weight >= self.config.min_freeze_weight {
            freeze.status = EmergencyFreezeStatus::Active;
        }
        if self.emergency_freezes.contains_key(&freeze.freeze_id) {
            return Err("freeze already exists".to_string());
        }
        if let Some(policy_id) = &freeze.target_policy_id {
            if let Some(policy) = self.policies.get_mut(policy_id) {
                policy.status = ExitPolicyStatus::Frozen;
                policy.freeze_id = Some(freeze.freeze_id.clone());
            }
        }
        if let Some(maker_id) = &freeze.target_maker_id {
            if let Some(maker) = self.maker_covenants.get_mut(maker_id) {
                maker.status = MakerCovenantStatus::Frozen;
                maker.updated_height = self.height;
            }
        }
        self.emergency_freezes
            .insert(freeze.freeze_id.clone(), freeze.clone());
        self.record_event("freeze_proposed", &freeze.freeze_id, freeze.public_record())?;
        Ok(freeze)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_challenge(
        &mut self,
        seed: &str,
        policy_id: &str,
        accused_maker_id: Option<String>,
        accused_attestor_id: Option<String>,
        receipt_id: Option<String>,
        evidence_kind: &str,
        slash_amount_units: u64,
        challenger_commitment: &str,
    ) -> MoneroBridgePrivateExitCovenantResult<ChallengeSlashEvidence> {
        if self.challenges.len() >= MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_CHALLENGES {
            return Err("challenge capacity reached".to_string());
        }
        if !self.policies.contains_key(policy_id) {
            return Err("policy not found".to_string());
        }
        let challenge = ChallengeSlashEvidence::new(
            seed,
            policy_id,
            accused_maker_id,
            accused_attestor_id,
            receipt_id,
            evidence_kind,
            slash_amount_units,
            challenger_commitment,
            self.height,
            &self.config,
        );
        challenge.validate()?;
        if self.challenges.contains_key(&challenge.challenge_id) {
            return Err("challenge already exists".to_string());
        }
        if let Some(policy) = self.policies.get_mut(policy_id) {
            policy.status = ExitPolicyStatus::Challenged;
            policy.challenge_ids.insert(challenge.challenge_id.clone());
        }
        if let Some(maker_id) = &challenge.accused_maker_id {
            if let Some(maker) = self.maker_covenants.get_mut(maker_id) {
                maker
                    .slash_evidence_ids
                    .insert(challenge.challenge_id.clone());
                maker.updated_height = self.height;
            }
        }
        if let Some(receipt_id) = &challenge.receipt_id {
            if let Some(receipt) = self.withdrawal_receipts.get_mut(receipt_id) {
                receipt.status = WithdrawalReceiptStatus::Challenged;
                receipt.challenge_ids.insert(challenge.challenge_id.clone());
            }
        }
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge.clone());
        self.record_event(
            "challenge_opened",
            &challenge.challenge_id,
            challenge.public_record(),
        )?;
        Ok(challenge)
    }

    pub fn finalize_receipts(&mut self) -> MoneroBridgePrivateExitCovenantResult<Vec<String>> {
        let ready_ids = self
            .withdrawal_receipts
            .iter()
            .filter(|(_, receipt)| {
                matches!(
                    receipt.status,
                    WithdrawalReceiptStatus::PendingReveal
                        | WithdrawalReceiptStatus::Revealed
                        | WithdrawalReceiptStatus::Accepted
                ) && receipt.finalizable_height <= self.height
            })
            .map(|(receipt_id, _)| receipt_id.clone())
            .collect::<Vec<_>>();
        for receipt_id in &ready_ids {
            let mut policy_id = String::new();
            let mut payout_id = String::new();
            if let Some(receipt) = self.withdrawal_receipts.get_mut(receipt_id) {
                receipt.status = WithdrawalReceiptStatus::Finalized;
                policy_id = receipt.policy_id.clone();
                payout_id = receipt.payout_id.clone();
            }
            if let Some(policy) = self.policies.get_mut(&policy_id) {
                policy.status = ExitPolicyStatus::Completed;
            }
            if let Some(payout) = self.payouts.get_mut(&payout_id) {
                payout.status = PayoutCommitmentStatus::Spent;
                payout.confirmation_height = Some(self.height);
            }
            self.record_event(
                "receipt_finalized",
                receipt_id,
                json!({ "receipt_id": receipt_id, "height": self.height }),
            )?;
        }
        Ok(ready_ids)
    }

    pub fn expire_stale(&mut self) -> MoneroBridgePrivateExitCovenantResult<Vec<String>> {
        let mut expired = Vec::new();
        let policy_ids = self
            .policies
            .iter()
            .filter(|(_, policy)| policy.status.live() && policy.expires_height <= self.height)
            .map(|(policy_id, _)| policy_id.clone())
            .collect::<Vec<_>>();
        for policy_id in policy_ids {
            if let Some(policy) = self.policies.get_mut(&policy_id) {
                policy.status = ExitPolicyStatus::Expired;
                expired.push(policy_id.clone());
            }
            self.record_event(
                "policy_expired",
                &policy_id,
                json!({ "policy_id": policy_id, "height": self.height }),
            )?;
        }
        let sponsorship_ids = self
            .sponsorships
            .iter()
            .filter(|(_, item)| item.status.live() && item.expires_height <= self.height)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for sponsorship_id in sponsorship_ids {
            if let Some(sponsorship) = self.sponsorships.get_mut(&sponsorship_id) {
                sponsorship.status = SponsorshipStatus::Expired;
                expired.push(sponsorship_id.clone());
            }
            self.record_event(
                "sponsorship_expired",
                &sponsorship_id,
                json!({ "sponsorship_id": sponsorship_id, "height": self.height }),
            )?;
        }
        let freeze_ids = self
            .emergency_freezes
            .iter()
            .filter(|(_, item)| item.status.blocks_exit() && item.expires_height <= self.height)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for freeze_id in freeze_ids {
            if let Some(freeze) = self.emergency_freezes.get_mut(&freeze_id) {
                freeze.status = EmergencyFreezeStatus::Expired;
                expired.push(freeze_id.clone());
            }
            self.record_event(
                "freeze_expired",
                &freeze_id,
                json!({ "freeze_id": freeze_id, "height": self.height }),
            )?;
        }
        Ok(expired)
    }

    pub fn roots(&self) -> MoneroBridgePrivateExitCovenantRoots {
        let policy_records = self
            .policies
            .values()
            .map(ShieldedExitPolicy::public_record)
            .collect::<Vec<_>>();
        let payout_records = self
            .payouts
            .values()
            .map(StealthPayoutCommitment::public_record)
            .collect::<Vec<_>>();
        let approval_records = self
            .pq_approvals
            .values()
            .map(PqReserveApproval::public_record)
            .collect::<Vec<_>>();
        let maker_records = self
            .maker_covenants
            .values()
            .map(MakerLiquidityCovenant::public_record)
            .collect::<Vec<_>>();
        let reorg_records = self
            .reorg_schedules
            .values()
            .map(ReorgDelaySchedule::public_record)
            .collect::<Vec<_>>();
        let sponsor_records = self
            .sponsorships
            .values()
            .map(LowFeeExitSponsorship::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .withdrawal_receipts
            .values()
            .map(WithdrawalReceipt::public_record)
            .collect::<Vec<_>>();
        let freeze_records = self
            .emergency_freezes
            .values()
            .map(EmergencyFreeze::public_record)
            .collect::<Vec<_>>();
        let challenge_records = self
            .challenges
            .values()
            .map(ChallengeSlashEvidence::public_record)
            .collect::<Vec<_>>();
        let event_records = self
            .events
            .values()
            .map(PrivateExitCovenantEvent::public_record)
            .collect::<Vec<_>>();
        let nullifier_records = self
            .public_nullifiers
            .iter()
            .map(|value| json!({ "nullifier": value }))
            .collect::<Vec<_>>();
        MoneroBridgePrivateExitCovenantRoots {
            config_root: domain_hash(
                "MONERO-BRIDGE-PRIVATE-EXIT-CONFIG",
                &[HashPart::Json(&self.config.public_record())],
                32,
            ),
            policy_root: merkle_root("MONERO-BRIDGE-PRIVATE-EXIT-POLICY", &policy_records),
            payout_root: merkle_root("MONERO-BRIDGE-PRIVATE-EXIT-PAYOUT", &payout_records),
            pq_approval_root: merkle_root(
                "MONERO-BRIDGE-PRIVATE-EXIT-PQ-APPROVAL",
                &approval_records,
            ),
            maker_root: merkle_root("MONERO-BRIDGE-PRIVATE-EXIT-MAKER", &maker_records),
            reorg_schedule_root: merkle_root(
                "MONERO-BRIDGE-PRIVATE-EXIT-REORG-SCHEDULE",
                &reorg_records,
            ),
            sponsorship_root: merkle_root(
                "MONERO-BRIDGE-PRIVATE-EXIT-SPONSORSHIP",
                &sponsor_records,
            ),
            receipt_root: merkle_root("MONERO-BRIDGE-PRIVATE-EXIT-RECEIPT", &receipt_records),
            freeze_root: merkle_root("MONERO-BRIDGE-PRIVATE-EXIT-FREEZE", &freeze_records),
            challenge_root: merkle_root("MONERO-BRIDGE-PRIVATE-EXIT-CHALLENGE", &challenge_records),
            event_root: merkle_root("MONERO-BRIDGE-PRIVATE-EXIT-EVENT", &event_records),
            public_nullifier_root: merkle_root(
                "MONERO-BRIDGE-PRIVATE-EXIT-PUBLIC-NULLIFIER",
                &nullifier_records,
            ),
        }
    }

    pub fn counters(&self) -> MoneroBridgePrivateExitCovenantCounters {
        MoneroBridgePrivateExitCovenantCounters {
            policies: self.policies.len() as u64,
            live_policies: self
                .policies
                .values()
                .filter(|policy| policy.status.live())
                .count() as u64,
            completed_policies: self
                .policies
                .values()
                .filter(|policy| matches!(policy.status, ExitPolicyStatus::Completed))
                .count() as u64,
            payouts: self.payouts.len() as u64,
            live_payouts: self
                .payouts
                .values()
                .filter(|payout| payout.status.counts_as_live())
                .count() as u64,
            pq_approvals: self.pq_approvals.len() as u64,
            accepted_pq_approvals: self
                .pq_approvals
                .values()
                .filter(|approval| approval.status.counts_for_quorum())
                .count() as u64,
            makers: self.maker_covenants.len() as u64,
            active_makers: self
                .maker_covenants
                .values()
                .filter(|maker| maker.status.can_bind())
                .count() as u64,
            reorg_schedules: self.reorg_schedules.len() as u64,
            sponsorships: self.sponsorships.len() as u64,
            live_sponsorships: self
                .sponsorships
                .values()
                .filter(|item| item.status.live())
                .count() as u64,
            receipts: self.withdrawal_receipts.len() as u64,
            finalized_receipts: self
                .withdrawal_receipts
                .values()
                .filter(|receipt| matches!(receipt.status, WithdrawalReceiptStatus::Finalized))
                .count() as u64,
            freezes: self.emergency_freezes.len() as u64,
            active_freezes: self
                .emergency_freezes
                .values()
                .filter(|freeze| freeze.status.blocks_exit())
                .count() as u64,
            challenges: self.challenges.len() as u64,
            live_challenges: self
                .challenges
                .values()
                .filter(|challenge| challenge.status.live())
                .count() as u64,
            events: self.events.len() as u64,
            reserved_units: self
                .maker_covenants
                .values()
                .map(|maker| maker.reserved_units)
                .sum(),
            sponsored_piconero: self
                .sponsorships
                .values()
                .map(|item| item.spent_piconero)
                .sum(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "monero_bridge_private_exit_covenant_state",
            "height": self.height,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root": self.state_root()
        })
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        let counters = self.counters();
        domain_hash(
            "MONERO-BRIDGE-PRIVATE-EXIT-COVENANT-STATE",
            &[
                HashPart::Int(self.height as i128),
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&roots.public_record()),
                HashPart::Json(&counters.public_record()),
            ],
            32,
        )
    }

    pub fn validate(&self) -> MoneroBridgePrivateExitCovenantResult<()> {
        self.config.validate()?;
        validate_len(
            self.policies.len(),
            MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_POLICIES,
            "policies",
        )?;
        validate_len(
            self.payouts.len(),
            MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_PAYOUTS,
            "payouts",
        )?;
        validate_len(
            self.pq_approvals.len(),
            MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_APPROVALS,
            "pq approvals",
        )?;
        validate_len(
            self.maker_covenants.len(),
            MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_MAKERS,
            "maker covenants",
        )?;
        validate_len(
            self.reorg_schedules.len(),
            MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_REORG_SCHEDULES,
            "reorg schedules",
        )?;
        validate_len(
            self.sponsorships.len(),
            MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_SPONSORSHIPS,
            "sponsorships",
        )?;
        validate_len(
            self.withdrawal_receipts.len(),
            MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_RECEIPTS,
            "withdrawal receipts",
        )?;
        validate_len(
            self.emergency_freezes.len(),
            MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_FREEZES,
            "emergency freezes",
        )?;
        validate_len(
            self.challenges.len(),
            MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_CHALLENGES,
            "challenges",
        )?;
        validate_len(
            self.events.len(),
            MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_EVENTS,
            "events",
        )?;
        for (policy_id, policy) in &self.policies {
            policy.validate()?;
            if policy_id != &policy.policy_id {
                return Err("policy map key mismatch".to_string());
            }
            if let Some(maker_id) = &policy.maker_id {
                if !self.maker_covenants.contains_key(maker_id) {
                    return Err(format!("policy references missing maker {maker_id}"));
                }
            }
            if let Some(payout_id) = &policy.payout_id {
                if !self.payouts.contains_key(payout_id) {
                    return Err(format!("policy references missing payout {payout_id}"));
                }
            }
            if let Some(sponsorship_id) = &policy.sponsorship_id {
                if !self.sponsorships.contains_key(sponsorship_id) {
                    return Err(format!(
                        "policy references missing sponsorship {sponsorship_id}"
                    ));
                }
            }
        }
        for (payout_id, payout) in &self.payouts {
            payout.validate()?;
            if payout_id != &payout.payout_id {
                return Err("payout map key mismatch".to_string());
            }
            if !self.policies.contains_key(&payout.policy_id) {
                return Err("payout references missing policy".to_string());
            }
            if !self.maker_covenants.contains_key(&payout.maker_id) {
                return Err("payout references missing maker".to_string());
            }
        }
        for (approval_id, approval) in &self.pq_approvals {
            approval.validate()?;
            if approval_id != &approval.approval_id {
                return Err("approval map key mismatch".to_string());
            }
            if !self.policies.contains_key(&approval.policy_id) {
                return Err("approval references missing policy".to_string());
            }
        }
        for (maker_id, maker) in &self.maker_covenants {
            maker.validate()?;
            if maker_id != &maker.maker_id {
                return Err("maker map key mismatch".to_string());
            }
        }
        for (schedule_id, schedule) in &self.reorg_schedules {
            schedule.validate()?;
            if schedule_id != &schedule.schedule_id {
                return Err("reorg schedule map key mismatch".to_string());
            }
        }
        for (sponsorship_id, sponsorship) in &self.sponsorships {
            sponsorship.validate()?;
            if sponsorship_id != &sponsorship.sponsorship_id {
                return Err("sponsorship map key mismatch".to_string());
            }
        }
        for (receipt_id, receipt) in &self.withdrawal_receipts {
            receipt.validate()?;
            if receipt_id != &receipt.receipt_id {
                return Err("receipt map key mismatch".to_string());
            }
        }
        for (freeze_id, freeze) in &self.emergency_freezes {
            freeze.validate()?;
            if freeze_id != &freeze.freeze_id {
                return Err("freeze map key mismatch".to_string());
            }
        }
        for (challenge_id, challenge) in &self.challenges {
            challenge.validate()?;
            if challenge_id != &challenge.challenge_id {
                return Err("challenge map key mismatch".to_string());
            }
        }
        Ok(())
    }

    fn pq_weight_for_policy(&self, policy_id: &str) -> u64 {
        self.pq_approvals
            .values()
            .filter(|approval| {
                approval.policy_id == policy_id && approval.status.counts_for_quorum()
            })
            .map(|approval| approval.attestor_weight)
            .sum()
    }

    fn policy_exposure_units(&self) -> u64 {
        self.policies
            .values()
            .filter(|policy| policy.status.live())
            .map(|policy| policy.max_amount_units)
            .sum()
    }

    fn apply_sponsor_spend(
        &mut self,
        policy_id: &str,
        sponsor_rebate_piconero: u64,
    ) -> MoneroBridgePrivateExitCovenantResult<()> {
        if sponsor_rebate_piconero == 0 {
            return Ok(());
        }
        let sponsorship_id = self
            .policies
            .get(policy_id)
            .and_then(|policy| policy.sponsorship_id.clone())
            .ok_or_else(|| "policy has no sponsorship for rebate".to_string())?;
        let sponsorship = self
            .sponsorships
            .get_mut(&sponsorship_id)
            .ok_or_else(|| "sponsorship not found".to_string())?;
        if sponsorship.remaining_piconero() < sponsor_rebate_piconero {
            return Err("sponsorship budget insufficient".to_string());
        }
        sponsorship.spent_piconero = sponsorship
            .spent_piconero
            .saturating_add(sponsor_rebate_piconero);
        sponsorship.status = if sponsorship.remaining_piconero() == 0 {
            SponsorshipStatus::Exhausted
        } else {
            SponsorshipStatus::Applied
        };
        Ok(())
    }

    fn record_event(
        &mut self,
        kind: &str,
        subject_id: &str,
        payload: Value,
    ) -> MoneroBridgePrivateExitCovenantResult<()> {
        if self.events.len() >= MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_EVENTS {
            return Err("event capacity reached".to_string());
        }
        let event = PrivateExitCovenantEvent::new(
            self.height,
            kind,
            subject_id,
            &self.state_root(),
            payload,
        );
        self.events.insert(event.event_id.clone(), event);
        Ok(())
    }
}

pub fn private_exit_id(domain: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .enumerate()
        .map(|(index, value)| json!({ "index": index, "value": value }))
        .collect::<Vec<_>>();
    let root = merkle_root(&format!("MONERO-BRIDGE-PRIVATE-EXIT-ID-{domain}"), &leaves);
    domain_hash(
        "MONERO-BRIDGE-PRIVATE-EXIT-ID",
        &[HashPart::Str(domain), HashPart::Str(&root)],
        16,
    )
}

pub fn deterministic_commitment(domain: &str, seed: &str, label: &str) -> String {
    domain_hash(
        "MONERO-BRIDGE-PRIVATE-EXIT-DETERMINISTIC-COMMITMENT",
        &[
            HashPart::Str(domain),
            HashPart::Str(seed),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn fee_quote_piconero(
    amount_units: u64,
    speed: PrivateExitSpeed,
    config: &MoneroBridgePrivateExitCovenantConfig,
) -> u64 {
    let percentage_fee = amount_units
        .saturating_mul(speed.fee_bps(config))
        .saturating_div(MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_BPS);
    percentage_fee.max(config.fee_floor_piconero)
}

pub fn sponsored_fee_quote_piconero(
    amount_units: u64,
    speed: PrivateExitSpeed,
    config: &MoneroBridgePrivateExitCovenantConfig,
) -> u64 {
    let fee = fee_quote_piconero(amount_units, speed, config);
    let rebate = fee
        .saturating_mul(config.low_fee_rebate_bps.min(config.max_sponsor_rebate_bps))
        .saturating_div(MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_BPS);
    fee.saturating_sub(rebate).max(config.fee_floor_piconero)
}

pub fn reorg_delay_for_depth(depth: u64, bands: &[ReorgDelayBand]) -> u64 {
    let mut selected_delay = 1;
    for band in bands {
        if depth >= band.depth {
            selected_delay = band.delay_blocks;
        }
    }
    selected_delay
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

fn validate_non_empty(label: &str, value: &str) -> MoneroBridgePrivateExitCovenantResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must be non-empty"))
    } else {
        Ok(())
    }
}

fn validate_id(label: &str, value: &str) -> MoneroBridgePrivateExitCovenantResult<()> {
    validate_non_empty(label, value)?;
    if value.len() < 16 {
        return Err(format!("{label} is too short"));
    }
    Ok(())
}

fn validate_bps(value: u64, label: &str) -> MoneroBridgePrivateExitCovenantResult<()> {
    if value > MONERO_BRIDGE_PRIVATE_EXIT_COVENANT_MAX_BPS {
        Err(format!("{label} bps exceeds maximum"))
    } else {
        Ok(())
    }
}

fn validate_len(len: usize, max: usize, label: &str) -> MoneroBridgePrivateExitCovenantResult<()> {
    if len > max {
        Err(format!("{label} exceeds capacity"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_validates_and_has_deterministic_root() {
        let state = MoneroBridgePrivateExitCovenantState::devnet();
        assert!(state.is_ok());
        let state = match state {
            Ok(state) => state,
            Err(error) => {
                assert!(error.is_empty());
                return;
            }
        };
        assert!(state.validate().is_ok());
        assert_eq!(state.state_root(), state.state_root());
        assert!(state.counters().policies >= 2);
    }

    #[test]
    fn sponsored_fee_never_under_floor() {
        let config = MoneroBridgePrivateExitCovenantConfig::default();
        let fee = sponsored_fee_quote_piconero(1, PrivateExitSpeed::LowFee, &config);
        assert_eq!(fee, config.fee_floor_piconero);
    }
}
