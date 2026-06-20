use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash as stable_hash_hex, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroExitBatchSchedulerResult<T> = Result<T, String>;

pub const MONERO_EXIT_BATCH_SCHEDULER_PROTOCOL_VERSION: &str =
    "nebula-monero-exit-batch-scheduler-v1";
pub const PROTOCOL_VERSION: &str = MONERO_EXIT_BATCH_SCHEDULER_PROTOCOL_VERSION;
pub const MONERO_EXIT_BATCH_SCHEDULER_SCHEMA_VERSION: u64 = 1;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEVNET_HEIGHT: u64 = 160;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_EXIT_BATCH_SCHEDULER_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_EXIT_BATCH_SCHEDULER_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_EXIT_BATCH_SCHEDULER_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const MONERO_EXIT_BATCH_SCHEDULER_PQ_SUITE: &str =
    "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s-devnet";
pub const MONERO_EXIT_BATCH_SCHEDULER_WATCHTOWER_SCHEME: &str =
    "ML-DSA-65+SLH-DSA-watchtower-batch-scheduler-v1";
pub const MONERO_EXIT_BATCH_SCHEDULER_STEALTH_SCHEME: &str =
    "monero-stealth-payout-plan-commitment-v1";
pub const MONERO_EXIT_BATCH_SCHEDULER_REVEAL_SCHEME: &str = "delayed-reveal-view-key-window-v1";
pub const MONERO_EXIT_BATCH_SCHEDULER_RECEIPT_SCHEME: &str =
    "private-nullifier-settlement-receipt-v1";
pub const MONERO_EXIT_BATCH_SCHEDULER_RESERVE_SCHEME: &str = "monero-maker-reserve-coverage-v1";
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_WINDOW_BLOCKS: u64 = 8;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_REVEAL_DELAY_BLOCKS: u64 = 6;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_REVEAL_TTL_BLOCKS: u64 = 24;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_EMERGENCY_TTL_BLOCKS: u64 = 4;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_BATCH_TTL_BLOCKS: u64 = 48;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_MAX_EXITS_PER_BATCH: usize = 96;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_MAX_BUCKETS_PER_BATCH: usize = 16;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_MAX_BATCH_UNITS: u64 = 1_500_000;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_AMOUNT_BUCKET_UNITS: u64 = 10_000;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_DUST_FLOOR_UNITS: u64 = 1;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_BASE_FEE_BPS: u64 = 20;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_FAST_FEE_BPS: u64 = 60;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_EMERGENCY_FEE_BPS: u64 = 120;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_FEE_FLOOR_UNITS: u64 = 2;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_SPONSOR_POOL_UNITS: u64 = 100_000;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 7_500;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_PRIVACY_REBATE_BPS: u64 = 2_500;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_MAX_REBATE_BPS: u64 = 9_500;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_WARN_RESERVE_COVERAGE_BPS: u64 = 11_000;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_MAKER_QUORUM: u64 = 1;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_WATCHTOWER_QUORUM: u64 = 2;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_MIN_WATCHTOWER_WEIGHT: u64 = 2;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_MIN_RING_SIZE: u64 = 16;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_TARGET_RING_SIZE: u64 = 32;
pub const MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_MAX_RING_SIZE: u64 = 128;
pub const MONERO_EXIT_BATCH_SCHEDULER_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitIntentPriority {
    LowFee,
    Normal,
    Fast,
    Sponsored,
    Emergency,
}

impl ExitIntentPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Normal => "normal",
            Self::Fast => "fast",
            Self::Sponsored => "sponsored",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &MoneroExitBatchSchedulerConfig) -> u64 {
        match self {
            Self::LowFee => config.base_fee_bps / 2,
            Self::Normal | Self::Sponsored => config.base_fee_bps,
            Self::Fast => config.fast_fee_bps,
            Self::Emergency => config.emergency_fee_bps,
        }
    }

    pub fn score(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::Fast => 850,
            Self::Sponsored => 700,
            Self::Normal => 500,
            Self::LowFee => 300,
        }
    }

    pub fn ttl_blocks(self, config: &MoneroExitBatchSchedulerConfig) -> u64 {
        match self {
            Self::Emergency => config.emergency_exit_ttl_blocks.max(1),
            Self::Fast => config.batch_ttl_blocks.min(24).max(1),
            Self::LowFee => config.batch_ttl_blocks.saturating_mul(2).max(1),
            Self::Normal | Self::Sponsored => config.batch_ttl_blocks.max(1),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitIntentStatus {
    Submitted,
    Bucketed,
    Planned,
    Assigned,
    Batched,
    RevealPending,
    RevealOpen,
    Settling,
    Settled,
    EmergencyQueued,
    EmergencySettled,
    Cancelled,
    Expired,
    Rejected,
}

impl ExitIntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Bucketed => "bucketed",
            Self::Planned => "planned",
            Self::Assigned => "assigned",
            Self::Batched => "batched",
            Self::RevealPending => "reveal_pending",
            Self::RevealOpen => "reveal_open",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::EmergencyQueued => "emergency_queued",
            Self::EmergencySettled => "emergency_settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::Bucketed
                | Self::Planned
                | Self::Assigned
                | Self::Batched
                | Self::RevealPending
                | Self::RevealOpen
                | Self::Settling
                | Self::EmergencyQueued
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Settled
                | Self::EmergencySettled
                | Self::Cancelled
                | Self::Expired
                | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RingBucketStatus {
    Open,
    Sealed,
    Planned,
    Assigned,
    Settling,
    Settled,
    Expired,
    Cancelled,
}

impl RingBucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Planned => "planned",
            Self::Assigned => "assigned",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn accepts_intents(self) -> bool {
        matches!(self, Self::Open)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchWindowStatus {
    Collecting,
    Sealed,
    Planned,
    WatchtowerApproved,
    Revealing,
    Settling,
    Settled,
    Expired,
    Cancelled,
}

impl BatchWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::Planned => "planned",
            Self::WatchtowerApproved => "watchtower_approved",
            Self::Revealing => "revealing",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Collecting
                | Self::Sealed
                | Self::Planned
                | Self::WatchtowerApproved
                | Self::Revealing
                | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MakerStatus {
    Candidate,
    Active,
    Throttled,
    Paused,
    Draining,
    Suspended,
    Retired,
}

impl MakerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }

    pub fn is_assignable(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MakerAssignmentStatus {
    Proposed,
    Reserved,
    WatchtowerApproved,
    Submitted,
    Settled,
    Failed,
    Slashed,
    Expired,
    Cancelled,
}

impl MakerAssignmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Reserved => "reserved",
            Self::WatchtowerApproved => "watchtower_approved",
            Self::Submitted => "submitted",
            Self::Settled => "settled",
            Self::Failed => "failed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Proposed | Self::Reserved | Self::WatchtowerApproved | Self::Submitted
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevealWindowStatus {
    Locked,
    Open,
    Acknowledged,
    Expired,
    Cancelled,
}

impl RevealWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::Open => "open",
            Self::Acknowledged => "acknowledged",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmergencyExitStatus {
    Open,
    WatchtowerApproved,
    Reserved,
    Submitted,
    Settled,
    Expired,
    Cancelled,
}

impl EmergencyExitStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::WatchtowerApproved => "watchtower_approved",
            Self::Reserved => "reserved",
            Self::Submitted => "submitted",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReceiptStatus {
    Draft,
    Observed,
    WatchtowerSigned,
    Final,
    Challenged,
    Reorged,
    Cancelled,
}

impl SettlementReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Observed => "observed",
            Self::WatchtowerSigned => "watchtower_signed",
            Self::Final => "final",
            Self::Challenged => "challenged",
            Self::Reorged => "reorged",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerEventKind {
    IntentSubmitted,
    BucketOpened,
    BucketSealed,
    WindowOpened,
    WindowSealed,
    StealthPlanCreated,
    MakerRegistered,
    MakerAssigned,
    FeeRebateIssued,
    WatchtowerSignatureRecorded,
    ReserveCheckRecorded,
    RevealWindowOpened,
    EmergencyExitQueued,
    SettlementReceiptRecorded,
    StateValidated,
}

impl SchedulerEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IntentSubmitted => "intent_submitted",
            Self::BucketOpened => "bucket_opened",
            Self::BucketSealed => "bucket_sealed",
            Self::WindowOpened => "window_opened",
            Self::WindowSealed => "window_sealed",
            Self::StealthPlanCreated => "stealth_plan_created",
            Self::MakerRegistered => "maker_registered",
            Self::MakerAssigned => "maker_assigned",
            Self::FeeRebateIssued => "fee_rebate_issued",
            Self::WatchtowerSignatureRecorded => "watchtower_signature_recorded",
            Self::ReserveCheckRecorded => "reserve_check_recorded",
            Self::RevealWindowOpened => "reveal_window_opened",
            Self::EmergencyExitQueued => "emergency_exit_queued",
            Self::SettlementReceiptRecorded => "settlement_receipt_recorded",
            Self::StateValidated => "state_validated",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroExitBatchSchedulerConfig {
    pub schema_version: u64,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub batch_window_blocks: u64,
    pub reveal_delay_blocks: u64,
    pub reveal_ttl_blocks: u64,
    pub emergency_exit_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub max_exits_per_batch: usize,
    pub max_buckets_per_batch: usize,
    pub max_batch_units: u64,
    pub amount_bucket_units: u64,
    pub dust_floor_units: u64,
    pub base_fee_bps: u64,
    pub fast_fee_bps: u64,
    pub emergency_fee_bps: u64,
    pub fee_floor_units: u64,
    pub sponsor_pool_units: u64,
    pub low_fee_rebate_bps: u64,
    pub privacy_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub warn_reserve_coverage_bps: u64,
    pub maker_quorum: u64,
    pub watchtower_quorum: u64,
    pub min_watchtower_weight: u64,
    pub min_ring_size: u64,
    pub target_ring_size: u64,
    pub max_ring_size: u64,
    pub pq_suite: String,
    pub watchtower_signature_scheme: String,
    pub stealth_payout_scheme: String,
    pub delayed_reveal_scheme: String,
    pub settlement_receipt_scheme: String,
    pub reserve_proof_scheme: String,
}

impl Default for MoneroExitBatchSchedulerConfig {
    fn default() -> Self {
        Self {
            schema_version: MONERO_EXIT_BATCH_SCHEDULER_SCHEMA_VERSION,
            monero_network: MONERO_EXIT_BATCH_SCHEDULER_DEVNET_MONERO_NETWORK.to_string(),
            asset_id: MONERO_EXIT_BATCH_SCHEDULER_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_EXIT_BATCH_SCHEDULER_DEVNET_FEE_ASSET_ID.to_string(),
            batch_window_blocks: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_WINDOW_BLOCKS,
            reveal_delay_blocks: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_REVEAL_DELAY_BLOCKS,
            reveal_ttl_blocks: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_REVEAL_TTL_BLOCKS,
            emergency_exit_ttl_blocks: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_EMERGENCY_TTL_BLOCKS,
            batch_ttl_blocks: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_BATCH_TTL_BLOCKS,
            max_exits_per_batch: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_MAX_EXITS_PER_BATCH,
            max_buckets_per_batch: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_MAX_BUCKETS_PER_BATCH,
            max_batch_units: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_MAX_BATCH_UNITS,
            amount_bucket_units: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_AMOUNT_BUCKET_UNITS,
            dust_floor_units: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_DUST_FLOOR_UNITS,
            base_fee_bps: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_BASE_FEE_BPS,
            fast_fee_bps: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_FAST_FEE_BPS,
            emergency_fee_bps: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_EMERGENCY_FEE_BPS,
            fee_floor_units: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_FEE_FLOOR_UNITS,
            sponsor_pool_units: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_SPONSOR_POOL_UNITS,
            low_fee_rebate_bps: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_LOW_FEE_REBATE_BPS,
            privacy_rebate_bps: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_PRIVACY_REBATE_BPS,
            max_rebate_bps: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_MAX_REBATE_BPS,
            min_reserve_coverage_bps: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            warn_reserve_coverage_bps:
                MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_WARN_RESERVE_COVERAGE_BPS,
            maker_quorum: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_MAKER_QUORUM,
            watchtower_quorum: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_WATCHTOWER_QUORUM,
            min_watchtower_weight: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_MIN_WATCHTOWER_WEIGHT,
            min_ring_size: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_MIN_RING_SIZE,
            target_ring_size: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_TARGET_RING_SIZE,
            max_ring_size: MONERO_EXIT_BATCH_SCHEDULER_DEFAULT_MAX_RING_SIZE,
            pq_suite: MONERO_EXIT_BATCH_SCHEDULER_PQ_SUITE.to_string(),
            watchtower_signature_scheme: MONERO_EXIT_BATCH_SCHEDULER_WATCHTOWER_SCHEME.to_string(),
            stealth_payout_scheme: MONERO_EXIT_BATCH_SCHEDULER_STEALTH_SCHEME.to_string(),
            delayed_reveal_scheme: MONERO_EXIT_BATCH_SCHEDULER_REVEAL_SCHEME.to_string(),
            settlement_receipt_scheme: MONERO_EXIT_BATCH_SCHEDULER_RECEIPT_SCHEME.to_string(),
            reserve_proof_scheme: MONERO_EXIT_BATCH_SCHEDULER_RESERVE_SCHEME.to_string(),
        }
    }
}

impl MoneroExitBatchSchedulerConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> MoneroExitBatchSchedulerResult<()> {
        ensure_non_empty(&self.monero_network, "scheduler monero network")?;
        ensure_non_empty(&self.asset_id, "scheduler asset id")?;
        ensure_non_empty(&self.fee_asset_id, "scheduler fee asset id")?;
        ensure_positive(self.batch_window_blocks, "scheduler batch window")?;
        ensure_positive(self.reveal_delay_blocks, "scheduler reveal delay")?;
        ensure_positive(self.reveal_ttl_blocks, "scheduler reveal ttl")?;
        ensure_positive(self.emergency_exit_ttl_blocks, "scheduler emergency ttl")?;
        ensure_positive(self.batch_ttl_blocks, "scheduler batch ttl")?;
        ensure_positive_usize(self.max_exits_per_batch, "scheduler max exits")?;
        ensure_positive_usize(self.max_buckets_per_batch, "scheduler max buckets")?;
        ensure_positive(self.max_batch_units, "scheduler max batch units")?;
        ensure_positive(self.amount_bucket_units, "scheduler amount bucket")?;
        ensure_bps(self.base_fee_bps, "scheduler base fee bps")?;
        ensure_bps(self.fast_fee_bps, "scheduler fast fee bps")?;
        ensure_bps(self.emergency_fee_bps, "scheduler emergency fee bps")?;
        ensure_bps(self.low_fee_rebate_bps, "scheduler low fee rebate bps")?;
        ensure_bps(self.privacy_rebate_bps, "scheduler privacy rebate bps")?;
        ensure_bps(self.max_rebate_bps, "scheduler max rebate bps")?;
        ensure_positive(
            self.min_reserve_coverage_bps,
            "scheduler min reserve coverage bps",
        )?;
        ensure_positive(
            self.warn_reserve_coverage_bps,
            "scheduler warn reserve coverage bps",
        )?;
        ensure_positive(self.maker_quorum, "scheduler maker quorum")?;
        ensure_positive(self.watchtower_quorum, "scheduler watchtower quorum")?;
        ensure_positive(
            self.min_watchtower_weight,
            "scheduler min watchtower weight",
        )?;
        ensure_positive(self.min_ring_size, "scheduler min ring size")?;
        if self.min_ring_size > self.target_ring_size || self.target_ring_size > self.max_ring_size
        {
            return Err("scheduler ring size bounds are inconsistent".to_string());
        }
        ensure_non_empty(&self.pq_suite, "scheduler pq suite")?;
        ensure_non_empty(
            &self.watchtower_signature_scheme,
            "scheduler watchtower signature scheme",
        )?;
        ensure_non_empty(
            &self.stealth_payout_scheme,
            "scheduler stealth payout scheme",
        )?;
        ensure_non_empty(
            &self.delayed_reveal_scheme,
            "scheduler delayed reveal scheme",
        )?;
        ensure_non_empty(
            &self.settlement_receipt_scheme,
            "scheduler settlement receipt scheme",
        )?;
        ensure_non_empty(&self.reserve_proof_scheme, "scheduler reserve proof scheme")?;
        Ok(())
    }

    pub fn fee_for(&self, amount_units: u64, priority: ExitIntentPriority) -> u64 {
        mul_bps(amount_units, priority.fee_bps(self)).max(self.fee_floor_units)
    }

    pub fn rebate_for(&self, fee_units: u64, priority: ExitIntentPriority, ring_size: u64) -> u64 {
        let priority_bps = match priority {
            ExitIntentPriority::LowFee | ExitIntentPriority::Sponsored => self.low_fee_rebate_bps,
            _ => 0,
        };
        let privacy_bps = if ring_size >= self.target_ring_size {
            self.privacy_rebate_bps
        } else {
            0
        };
        let rebate_bps = priority_bps
            .saturating_add(privacy_bps)
            .min(self.max_rebate_bps);
        mul_bps(fee_units, rebate_bps)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": self.schema_version,
            "hash_suite": MONERO_EXIT_BATCH_SCHEDULER_HASH_SUITE,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "batch_window_blocks": self.batch_window_blocks,
            "reveal_delay_blocks": self.reveal_delay_blocks,
            "reveal_ttl_blocks": self.reveal_ttl_blocks,
            "emergency_exit_ttl_blocks": self.emergency_exit_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "max_exits_per_batch": self.max_exits_per_batch as u64,
            "max_buckets_per_batch": self.max_buckets_per_batch as u64,
            "max_batch_units": self.max_batch_units,
            "amount_bucket_units": self.amount_bucket_units,
            "dust_floor_units": self.dust_floor_units,
            "base_fee_bps": self.base_fee_bps,
            "fast_fee_bps": self.fast_fee_bps,
            "emergency_fee_bps": self.emergency_fee_bps,
            "fee_floor_units": self.fee_floor_units,
            "sponsor_pool_units": self.sponsor_pool_units,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "privacy_rebate_bps": self.privacy_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "warn_reserve_coverage_bps": self.warn_reserve_coverage_bps,
            "maker_quorum": self.maker_quorum,
            "watchtower_quorum": self.watchtower_quorum,
            "min_watchtower_weight": self.min_watchtower_weight,
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "max_ring_size": self.max_ring_size,
            "pq_suite": self.pq_suite,
            "watchtower_signature_scheme": self.watchtower_signature_scheme,
            "stealth_payout_scheme": self.stealth_payout_scheme,
            "delayed_reveal_scheme": self.delayed_reveal_scheme,
            "settlement_receipt_scheme": self.settlement_receipt_scheme,
            "reserve_proof_scheme": self.reserve_proof_scheme,
        })
    }

    pub fn config_root(&self) -> String {
        scheduler_payload_root("MONERO-EXIT-BATCH-SCHEDULER-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitIntent {
    pub intent_id: String,
    pub owner_commitment: String,
    pub account_commitment: String,
    pub recipient_address_hash: String,
    pub recipient_view_tag_root: String,
    pub stealth_address_commitment: String,
    pub amount_units: u64,
    pub amount_bucket: u64,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub expected_rebate_units: u64,
    pub net_amount_units: u64,
    pub priority: ExitIntentPriority,
    pub nullifier_hash: String,
    pub key_image_hash: String,
    pub contract_call_root: String,
    pub token_scope_root: String,
    pub privacy_hint_root: String,
    pub memo_commitment: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub bucket_id: Option<String>,
    pub plan_id: Option<String>,
    pub assignment_id: Option<String>,
    pub receipt_id: Option<String>,
    pub status: ExitIntentStatus,
}

impl ExitIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_commitment: &str,
        account_commitment: &str,
        recipient_address: &str,
        recipient_view_tag: &str,
        amount_units: u64,
        fee_asset_id: &str,
        priority: ExitIntentPriority,
        nullifier: &str,
        key_image: &str,
        contract_call: &Value,
        token_scope: &Value,
        privacy_hint: &Value,
        memo: &str,
        submitted_at_height: u64,
        config: &MoneroExitBatchSchedulerConfig,
    ) -> MoneroExitBatchSchedulerResult<Self> {
        ensure_non_empty(owner_commitment, "exit intent owner commitment")?;
        ensure_non_empty(account_commitment, "exit intent account commitment")?;
        ensure_non_empty(recipient_address, "exit intent recipient address")?;
        ensure_non_empty(recipient_view_tag, "exit intent recipient view tag")?;
        ensure_positive(amount_units, "exit intent amount")?;
        ensure_non_empty(fee_asset_id, "exit intent fee asset id")?;
        ensure_non_empty(nullifier, "exit intent nullifier")?;
        ensure_non_empty(key_image, "exit intent key image")?;
        let amount_bucket = bucket_amount(amount_units, config.amount_bucket_units);
        let max_fee_units = config.fee_for(amount_units, priority);
        let expected_rebate_units =
            config.rebate_for(max_fee_units, priority, config.target_ring_size);
        let charged_fee_units = max_fee_units.saturating_sub(expected_rebate_units);
        let net_amount_units = amount_units.saturating_sub(charged_fee_units);
        let recipient_address_hash = scheduler_domain_hash(
            "MONERO-EXIT-SCHEDULER-RECIPIENT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(recipient_address),
                HashPart::Str(recipient_view_tag),
            ],
        );
        let recipient_view_tag_root = scheduler_domain_hash(
            "MONERO-EXIT-SCHEDULER-VIEW-TAG",
            &[HashPart::Str(CHAIN_ID), HashPart::Str(recipient_view_tag)],
        );
        let stealth_address_commitment = scheduler_domain_hash(
            "MONERO-EXIT-SCHEDULER-STEALTH-ADDRESS-COMMITMENT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&recipient_address_hash),
                HashPart::Int(amount_bucket as i128),
            ],
        );
        let contract_call_root =
            scheduler_payload_root("MONERO-EXIT-SCHEDULER-CONTRACT-CALL", contract_call);
        let token_scope_root =
            scheduler_payload_root("MONERO-EXIT-SCHEDULER-TOKEN-SCOPE", token_scope);
        let privacy_hint_root =
            scheduler_payload_root("MONERO-EXIT-SCHEDULER-PRIVACY-HINT", privacy_hint);
        let memo_commitment = scheduler_domain_hash(
            "MONERO-EXIT-SCHEDULER-MEMO",
            &[HashPart::Str(CHAIN_ID), HashPart::Str(memo)],
        );
        let expires_at_height = submitted_at_height.saturating_add(priority.ttl_blocks(config));
        let mut intent = Self {
            intent_id: String::new(),
            owner_commitment: owner_commitment.to_string(),
            account_commitment: account_commitment.to_string(),
            recipient_address_hash,
            recipient_view_tag_root,
            stealth_address_commitment,
            amount_units,
            amount_bucket,
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_units,
            expected_rebate_units,
            net_amount_units,
            priority,
            nullifier_hash: scheduler_domain_hash(
                "MONERO-EXIT-SCHEDULER-NULLIFIER",
                &[HashPart::Str(CHAIN_ID), HashPart::Str(nullifier)],
            ),
            key_image_hash: scheduler_domain_hash(
                "MONERO-EXIT-SCHEDULER-KEY-IMAGE",
                &[HashPart::Str(CHAIN_ID), HashPart::Str(key_image)],
            ),
            contract_call_root,
            token_scope_root,
            privacy_hint_root,
            memo_commitment,
            submitted_at_height,
            expires_at_height,
            bucket_id: None,
            plan_id: None,
            assignment_id: None,
            receipt_id: None,
            status: ExitIntentStatus::Submitted,
        };
        intent.intent_id = monero_exit_batch_scheduler_intent_id(&intent.identity_record());
        intent.validate()?;
        Ok(intent)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_intent_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "owner_commitment": self.owner_commitment,
            "account_commitment": self.account_commitment,
            "recipient_address_hash": self.recipient_address_hash,
            "stealth_address_commitment": self.stealth_address_commitment,
            "amount_units": self.amount_units,
            "amount_bucket": self.amount_bucket,
            "nullifier_hash": self.nullifier_hash,
            "key_image_hash": self.key_image_hash,
            "submitted_at_height": self.submitted_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "owner_commitment": self.owner_commitment,
            "account_commitment": self.account_commitment,
            "recipient_address_hash": self.recipient_address_hash,
            "recipient_view_tag_root": self.recipient_view_tag_root,
            "stealth_address_commitment": self.stealth_address_commitment,
            "amount_units": self.amount_units,
            "amount_bucket": self.amount_bucket,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "expected_rebate_units": self.expected_rebate_units,
            "net_amount_units": self.net_amount_units,
            "priority": self.priority.as_str(),
            "nullifier_hash": self.nullifier_hash,
            "key_image_hash": self.key_image_hash,
            "contract_call_root": self.contract_call_root,
            "token_scope_root": self.token_scope_root,
            "privacy_hint_root": self.privacy_hint_root,
            "memo_commitment": self.memo_commitment,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "bucket_id": self.bucket_id,
            "plan_id": self.plan_id,
            "assignment_id": self.assignment_id,
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
        })
    }

    pub fn intent_root(&self) -> String {
        scheduler_payload_root(
            "MONERO-EXIT-BATCH-SCHEDULER-INTENT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "intent_root",
            self.intent_root(),
        )
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.is_open() {
            self.status = ExitIntentStatus::Expired;
        }
    }

    pub fn validate(&self) -> MoneroExitBatchSchedulerResult<String> {
        ensure_non_empty(&self.intent_id, "exit intent id")?;
        ensure_non_empty(&self.owner_commitment, "exit intent owner commitment")?;
        ensure_non_empty(&self.account_commitment, "exit intent account commitment")?;
        ensure_non_empty(&self.recipient_address_hash, "exit intent recipient hash")?;
        ensure_non_empty(
            &self.stealth_address_commitment,
            "exit intent stealth commitment",
        )?;
        ensure_positive(self.amount_units, "exit intent amount")?;
        ensure_non_empty(&self.fee_asset_id, "exit intent fee asset id")?;
        ensure_non_empty(&self.nullifier_hash, "exit intent nullifier hash")?;
        ensure_non_empty(&self.key_image_hash, "exit intent key image hash")?;
        ensure_expiry(
            self.submitted_at_height,
            self.expires_at_height,
            "exit intent",
        )?;
        if self.expected_rebate_units > self.max_fee_units {
            return Err("exit intent rebate exceeds fee".to_string());
        }
        if self.net_amount_units > self.amount_units {
            return Err("exit intent net amount exceeds gross amount".to_string());
        }
        let computed = monero_exit_batch_scheduler_intent_id(&self.identity_record());
        if self.intent_id != computed {
            return Err("exit intent id mismatch".to_string());
        }
        Ok(self.intent_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingOutputBucket {
    pub bucket_id: String,
    pub window_id: String,
    pub amount_bucket: u64,
    pub priority_band: ExitIntentPriority,
    pub min_ring_size: u64,
    pub target_ring_size: u64,
    pub decoy_output_root: String,
    pub intent_ids: BTreeSet<String>,
    pub total_amount_units: u64,
    pub total_fee_units: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: Option<u64>,
    pub status: RingBucketStatus,
}

impl RingOutputBucket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        window_id: &str,
        amount_bucket: u64,
        priority_band: ExitIntentPriority,
        decoy_outputs: &[Value],
        opened_at_height: u64,
        config: &MoneroExitBatchSchedulerConfig,
    ) -> MoneroExitBatchSchedulerResult<Self> {
        ensure_non_empty(window_id, "ring bucket window id")?;
        ensure_positive(amount_bucket, "ring bucket amount bucket")?;
        let decoy_output_root = merkle_root("MONERO-EXIT-SCHEDULER-DECOY-OUTPUT", decoy_outputs);
        let mut bucket = Self {
            bucket_id: String::new(),
            window_id: window_id.to_string(),
            amount_bucket,
            priority_band,
            min_ring_size: config.min_ring_size,
            target_ring_size: config.target_ring_size,
            decoy_output_root,
            intent_ids: BTreeSet::new(),
            total_amount_units: 0,
            total_fee_units: 0,
            opened_at_height,
            sealed_at_height: None,
            status: RingBucketStatus::Open,
        };
        bucket.bucket_id = monero_exit_batch_scheduler_bucket_id(&bucket.identity_record());
        bucket.validate()?;
        Ok(bucket)
    }

    pub fn add_intent(&mut self, intent: &ExitIntent) -> MoneroExitBatchSchedulerResult<()> {
        if !self.status.accepts_intents() {
            return Err("ring bucket is not accepting intents".to_string());
        }
        if intent.amount_bucket != self.amount_bucket {
            return Err("ring bucket amount mismatch".to_string());
        }
        self.intent_ids.insert(intent.intent_id.clone());
        self.total_amount_units = self.total_amount_units.saturating_add(intent.amount_units);
        self.total_fee_units = self.total_fee_units.saturating_add(intent.max_fee_units);
        Ok(())
    }

    pub fn seal(&mut self, height: u64) -> MoneroExitBatchSchedulerResult<()> {
        if self.intent_ids.is_empty() {
            return Err("ring bucket cannot seal with no intents".to_string());
        }
        self.sealed_at_height = Some(height);
        self.status = RingBucketStatus::Sealed;
        Ok(())
    }

    pub fn ring_size(&self) -> u64 {
        (self.intent_ids.len() as u64)
            .max(self.min_ring_size)
            .min(self.target_ring_size)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_bucket_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "window_id": self.window_id,
            "amount_bucket": self.amount_bucket,
            "priority_band": self.priority_band.as_str(),
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_bucket",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "bucket_id": self.bucket_id,
            "window_id": self.window_id,
            "amount_bucket": self.amount_bucket,
            "priority_band": self.priority_band.as_str(),
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "ring_size": self.ring_size(),
            "decoy_output_root": self.decoy_output_root,
            "intent_ids": self.intent_ids.iter().cloned().collect::<Vec<_>>(),
            "intent_count": self.intent_ids.len() as u64,
            "total_amount_units": self.total_amount_units,
            "total_fee_units": self.total_fee_units,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn bucket_root(&self) -> String {
        scheduler_payload_root(
            "MONERO-EXIT-BATCH-SCHEDULER-BUCKET",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "bucket_root",
            self.bucket_root(),
        )
    }

    pub fn validate(&self) -> MoneroExitBatchSchedulerResult<String> {
        ensure_non_empty(&self.bucket_id, "ring bucket id")?;
        ensure_non_empty(&self.window_id, "ring bucket window id")?;
        ensure_positive(self.amount_bucket, "ring bucket amount bucket")?;
        ensure_positive(self.min_ring_size, "ring bucket min ring size")?;
        ensure_positive(self.target_ring_size, "ring bucket target ring size")?;
        ensure_non_empty(&self.decoy_output_root, "ring bucket decoy root")?;
        if self.min_ring_size > self.target_ring_size {
            return Err("ring bucket ring size bounds mismatch".to_string());
        }
        let computed = monero_exit_batch_scheduler_bucket_id(&self.identity_record());
        if self.bucket_id != computed {
            return Err("ring bucket id mismatch".to_string());
        }
        Ok(self.bucket_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchWindow {
    pub window_id: String,
    pub sequence: u64,
    pub opened_at_height: u64,
    pub collect_until_height: u64,
    pub reveal_starts_at_height: u64,
    pub reveal_expires_at_height: u64,
    pub expires_at_height: u64,
    pub bucket_ids: BTreeSet<String>,
    pub intent_ids: BTreeSet<String>,
    pub stealth_plan_ids: BTreeSet<String>,
    pub assignment_ids: BTreeSet<String>,
    pub total_amount_units: u64,
    pub total_fee_units: u64,
    pub status: BatchWindowStatus,
}

impl BatchWindow {
    pub fn new(
        sequence: u64,
        opened_at_height: u64,
        config: &MoneroExitBatchSchedulerConfig,
    ) -> MoneroExitBatchSchedulerResult<Self> {
        let collect_until_height = opened_at_height.saturating_add(config.batch_window_blocks);
        let reveal_starts_at_height =
            collect_until_height.saturating_add(config.reveal_delay_blocks);
        let reveal_expires_at_height =
            reveal_starts_at_height.saturating_add(config.reveal_ttl_blocks);
        let expires_at_height = opened_at_height.saturating_add(config.batch_ttl_blocks);
        let mut window = Self {
            window_id: String::new(),
            sequence,
            opened_at_height,
            collect_until_height,
            reveal_starts_at_height,
            reveal_expires_at_height,
            expires_at_height: expires_at_height.max(reveal_expires_at_height),
            bucket_ids: BTreeSet::new(),
            intent_ids: BTreeSet::new(),
            stealth_plan_ids: BTreeSet::new(),
            assignment_ids: BTreeSet::new(),
            total_amount_units: 0,
            total_fee_units: 0,
            status: BatchWindowStatus::Collecting,
        };
        window.window_id = monero_exit_batch_scheduler_window_id(&window.identity_record());
        window.validate()?;
        Ok(window)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_window_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "sequence": self.sequence,
            "opened_at_height": self.opened_at_height,
            "collect_until_height": self.collect_until_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_window",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "window_id": self.window_id,
            "sequence": self.sequence,
            "opened_at_height": self.opened_at_height,
            "collect_until_height": self.collect_until_height,
            "reveal_starts_at_height": self.reveal_starts_at_height,
            "reveal_expires_at_height": self.reveal_expires_at_height,
            "expires_at_height": self.expires_at_height,
            "bucket_ids": self.bucket_ids.iter().cloned().collect::<Vec<_>>(),
            "intent_ids": self.intent_ids.iter().cloned().collect::<Vec<_>>(),
            "stealth_plan_ids": self.stealth_plan_ids.iter().cloned().collect::<Vec<_>>(),
            "assignment_ids": self.assignment_ids.iter().cloned().collect::<Vec<_>>(),
            "bucket_count": self.bucket_ids.len() as u64,
            "intent_count": self.intent_ids.len() as u64,
            "total_amount_units": self.total_amount_units,
            "total_fee_units": self.total_fee_units,
            "status": self.status.as_str(),
        })
    }

    pub fn window_root(&self) -> String {
        scheduler_payload_root(
            "MONERO-EXIT-BATCH-SCHEDULER-WINDOW",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "window_root",
            self.window_root(),
        )
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.is_open() {
            self.status = BatchWindowStatus::Expired;
        } else if height >= self.reveal_starts_at_height
            && matches!(
                self.status,
                BatchWindowStatus::Planned | BatchWindowStatus::WatchtowerApproved
            )
        {
            self.status = BatchWindowStatus::Revealing;
        } else if height >= self.collect_until_height
            && self.status == BatchWindowStatus::Collecting
        {
            self.status = BatchWindowStatus::Sealed;
        }
    }

    pub fn validate(&self) -> MoneroExitBatchSchedulerResult<String> {
        ensure_non_empty(&self.window_id, "batch window id")?;
        ensure_expiry(
            self.opened_at_height,
            self.collect_until_height,
            "batch window collection",
        )?;
        ensure_expiry(
            self.collect_until_height,
            self.reveal_starts_at_height,
            "batch window reveal delay",
        )?;
        ensure_expiry(
            self.reveal_starts_at_height,
            self.reveal_expires_at_height,
            "batch window reveal",
        )?;
        ensure_expiry(
            self.opened_at_height,
            self.expires_at_height,
            "batch window ttl",
        )?;
        let computed = monero_exit_batch_scheduler_window_id(&self.identity_record());
        if self.window_id != computed {
            return Err("batch window id mismatch".to_string());
        }
        Ok(self.window_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthPayoutPlan {
    pub plan_id: String,
    pub window_id: String,
    pub bucket_id: String,
    pub intent_ids: Vec<String>,
    pub stealth_output_root: String,
    pub one_time_key_root: String,
    pub encrypted_payload_root: String,
    pub view_tag_root: String,
    pub amount_commitment_root: String,
    pub decoy_output_root: String,
    pub ring_size: u64,
    pub total_amount_units: u64,
    pub total_fee_units: u64,
    pub reveal_window_id: Option<String>,
    pub created_at_height: u64,
}

impl StealthPayoutPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        window_id: &str,
        bucket: &RingOutputBucket,
        stealth_outputs: &[Value],
        one_time_keys: &[String],
        encrypted_payload: &Value,
        created_at_height: u64,
    ) -> MoneroExitBatchSchedulerResult<Self> {
        ensure_non_empty(window_id, "stealth payout window id")?;
        let intent_ids = bucket.intent_ids.iter().cloned().collect::<Vec<_>>();
        if intent_ids.is_empty() {
            return Err("stealth payout plan requires intents".to_string());
        }
        let stealth_output_root =
            merkle_root("MONERO-EXIT-SCHEDULER-STEALTH-OUTPUT", stealth_outputs);
        let one_time_key_root = string_set_root(
            "MONERO-EXIT-SCHEDULER-ONE-TIME-KEY",
            one_time_keys.iter().cloned().collect(),
        );
        let encrypted_payload_root =
            scheduler_payload_root("MONERO-EXIT-SCHEDULER-ENCRYPTED-PAYOUT", encrypted_payload);
        let view_tag_root = scheduler_payload_root(
            "MONERO-EXIT-SCHEDULER-PLAN-VIEW-TAGS",
            &json!({"bucket_id": bucket.bucket_id, "intent_ids": intent_ids}),
        );
        let amount_commitment_root = scheduler_payload_root(
            "MONERO-EXIT-SCHEDULER-PLAN-AMOUNTS",
            &json!({
                "amount_bucket": bucket.amount_bucket,
                "total_amount_units": bucket.total_amount_units,
                "total_fee_units": bucket.total_fee_units,
            }),
        );
        let mut plan = Self {
            plan_id: String::new(),
            window_id: window_id.to_string(),
            bucket_id: bucket.bucket_id.clone(),
            intent_ids,
            stealth_output_root,
            one_time_key_root,
            encrypted_payload_root,
            view_tag_root,
            amount_commitment_root,
            decoy_output_root: bucket.decoy_output_root.clone(),
            ring_size: bucket.ring_size(),
            total_amount_units: bucket.total_amount_units,
            total_fee_units: bucket.total_fee_units,
            reveal_window_id: None,
            created_at_height,
        };
        plan.plan_id = monero_exit_batch_scheduler_plan_id(&plan.identity_record());
        plan.validate()?;
        Ok(plan)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_stealth_plan_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "window_id": self.window_id,
            "bucket_id": self.bucket_id,
            "stealth_output_root": self.stealth_output_root,
            "one_time_key_root": self.one_time_key_root,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_stealth_plan",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "plan_id": self.plan_id,
            "window_id": self.window_id,
            "bucket_id": self.bucket_id,
            "intent_ids": self.intent_ids,
            "stealth_output_root": self.stealth_output_root,
            "one_time_key_root": self.one_time_key_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "view_tag_root": self.view_tag_root,
            "amount_commitment_root": self.amount_commitment_root,
            "decoy_output_root": self.decoy_output_root,
            "ring_size": self.ring_size,
            "total_amount_units": self.total_amount_units,
            "total_fee_units": self.total_fee_units,
            "reveal_window_id": self.reveal_window_id,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn plan_root(&self) -> String {
        scheduler_payload_root(
            "MONERO-EXIT-BATCH-SCHEDULER-STEALTH-PLAN",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "plan_root",
            self.plan_root(),
        )
    }

    pub fn validate(&self) -> MoneroExitBatchSchedulerResult<String> {
        ensure_non_empty(&self.plan_id, "stealth plan id")?;
        ensure_non_empty(&self.window_id, "stealth plan window id")?;
        ensure_non_empty(&self.bucket_id, "stealth plan bucket id")?;
        ensure_non_empty(&self.stealth_output_root, "stealth plan output root")?;
        ensure_non_empty(&self.one_time_key_root, "stealth plan one time key root")?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "stealth plan encrypted payload root",
        )?;
        ensure_positive(self.ring_size, "stealth plan ring size")?;
        if self.intent_ids.is_empty() {
            return Err("stealth plan has no intents".to_string());
        }
        let computed = monero_exit_batch_scheduler_plan_id(&self.identity_record());
        if self.plan_id != computed {
            return Err("stealth plan id mismatch".to_string());
        }
        Ok(self.plan_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityMaker {
    pub maker_id: String,
    pub operator_commitment: String,
    pub monero_reserve_commitment: String,
    pub payout_key_root: String,
    pub pq_identity_root: String,
    pub supported_bucket_root: String,
    pub max_exposure_units: u64,
    pub available_liquidity_units: u64,
    pub reserved_liquidity_units: u64,
    pub fee_quote_bps: u64,
    pub reliability_score_bps: u64,
    pub status: MakerStatus,
    pub registered_at_height: u64,
}

impl LiquidityMaker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_commitment: &str,
        monero_reserve_commitment: &str,
        payout_key_payload: &Value,
        pq_identity_payload: &Value,
        supported_buckets: &[u64],
        max_exposure_units: u64,
        available_liquidity_units: u64,
        fee_quote_bps: u64,
        registered_at_height: u64,
    ) -> MoneroExitBatchSchedulerResult<Self> {
        ensure_non_empty(operator_commitment, "maker operator commitment")?;
        ensure_non_empty(monero_reserve_commitment, "maker reserve commitment")?;
        ensure_positive(max_exposure_units, "maker max exposure")?;
        ensure_bps(fee_quote_bps, "maker fee quote")?;
        let payout_key_root =
            scheduler_payload_root("MONERO-EXIT-SCHEDULER-MAKER-PAYOUT-KEY", payout_key_payload);
        let pq_identity_root = scheduler_payload_root(
            "MONERO-EXIT-SCHEDULER-MAKER-PQ-IDENTITY",
            pq_identity_payload,
        );
        let supported_bucket_root = u64_set_root(
            "MONERO-EXIT-SCHEDULER-MAKER-SUPPORTED-BUCKET",
            supported_buckets.to_vec(),
        );
        let mut maker = Self {
            maker_id: String::new(),
            operator_commitment: operator_commitment.to_string(),
            monero_reserve_commitment: monero_reserve_commitment.to_string(),
            payout_key_root,
            pq_identity_root,
            supported_bucket_root,
            max_exposure_units,
            available_liquidity_units,
            reserved_liquidity_units: 0,
            fee_quote_bps,
            reliability_score_bps: MONERO_EXIT_BATCH_SCHEDULER_MAX_BPS,
            status: MakerStatus::Active,
            registered_at_height,
        };
        maker.maker_id = monero_exit_batch_scheduler_maker_id(&maker.identity_record());
        maker.validate()?;
        Ok(maker)
    }

    pub fn can_reserve(&self, amount_units: u64) -> bool {
        self.status.is_assignable()
            && self.available_liquidity_units >= amount_units
            && self.reserved_liquidity_units.saturating_add(amount_units) <= self.max_exposure_units
    }

    pub fn reserve(&mut self, amount_units: u64) -> MoneroExitBatchSchedulerResult<()> {
        if !self.can_reserve(amount_units) {
            return Err("maker cannot reserve requested amount".to_string());
        }
        self.available_liquidity_units =
            self.available_liquidity_units.saturating_sub(amount_units);
        self.reserved_liquidity_units = self.reserved_liquidity_units.saturating_add(amount_units);
        Ok(())
    }

    pub fn release(&mut self, amount_units: u64) {
        let released = amount_units.min(self.reserved_liquidity_units);
        self.reserved_liquidity_units = self.reserved_liquidity_units.saturating_sub(released);
        self.available_liquidity_units = self.available_liquidity_units.saturating_add(released);
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_maker_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "operator_commitment": self.operator_commitment,
            "monero_reserve_commitment": self.monero_reserve_commitment,
            "payout_key_root": self.payout_key_root,
            "pq_identity_root": self.pq_identity_root,
            "registered_at_height": self.registered_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_maker",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "maker_id": self.maker_id,
            "operator_commitment": self.operator_commitment,
            "monero_reserve_commitment": self.monero_reserve_commitment,
            "payout_key_root": self.payout_key_root,
            "pq_identity_root": self.pq_identity_root,
            "supported_bucket_root": self.supported_bucket_root,
            "max_exposure_units": self.max_exposure_units,
            "available_liquidity_units": self.available_liquidity_units,
            "reserved_liquidity_units": self.reserved_liquidity_units,
            "fee_quote_bps": self.fee_quote_bps,
            "reliability_score_bps": self.reliability_score_bps,
            "status": self.status.as_str(),
            "registered_at_height": self.registered_at_height,
        })
    }

    pub fn maker_root(&self) -> String {
        scheduler_payload_root(
            "MONERO-EXIT-BATCH-SCHEDULER-MAKER",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "maker_root",
            self.maker_root(),
        )
    }

    pub fn validate(&self) -> MoneroExitBatchSchedulerResult<String> {
        ensure_non_empty(&self.maker_id, "maker id")?;
        ensure_non_empty(&self.operator_commitment, "maker operator commitment")?;
        ensure_non_empty(
            &self.monero_reserve_commitment,
            "maker monero reserve commitment",
        )?;
        ensure_non_empty(&self.payout_key_root, "maker payout key root")?;
        ensure_non_empty(&self.pq_identity_root, "maker pq identity root")?;
        ensure_positive(self.max_exposure_units, "maker max exposure")?;
        ensure_bps(self.fee_quote_bps, "maker fee quote bps")?;
        ensure_bps(self.reliability_score_bps, "maker reliability bps")?;
        if self.reserved_liquidity_units > self.max_exposure_units {
            return Err("maker reserved liquidity exceeds exposure cap".to_string());
        }
        let computed = monero_exit_batch_scheduler_maker_id(&self.identity_record());
        if self.maker_id != computed {
            return Err("maker id mismatch".to_string());
        }
        Ok(self.maker_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MakerAssignment {
    pub assignment_id: String,
    pub maker_id: String,
    pub window_id: String,
    pub plan_id: String,
    pub bucket_id: String,
    pub intent_ids: Vec<String>,
    pub reserved_amount_units: u64,
    pub maker_fee_units: u64,
    pub plan_root: String,
    pub reserve_check_id: Option<String>,
    pub watchtower_signature_id: Option<String>,
    pub assigned_at_height: u64,
    pub expires_at_height: u64,
    pub status: MakerAssignmentStatus,
}

impl MakerAssignment {
    pub fn new(
        maker: &LiquidityMaker,
        plan: &StealthPayoutPlan,
        assigned_at_height: u64,
        config: &MoneroExitBatchSchedulerConfig,
    ) -> MoneroExitBatchSchedulerResult<Self> {
        ensure_non_empty(&maker.maker_id, "assignment maker id")?;
        ensure_non_empty(&plan.plan_id, "assignment plan id")?;
        let maker_fee_units = mul_bps(plan.total_amount_units, maker.fee_quote_bps);
        let mut assignment = Self {
            assignment_id: String::new(),
            maker_id: maker.maker_id.clone(),
            window_id: plan.window_id.clone(),
            plan_id: plan.plan_id.clone(),
            bucket_id: plan.bucket_id.clone(),
            intent_ids: plan.intent_ids.clone(),
            reserved_amount_units: plan.total_amount_units,
            maker_fee_units,
            plan_root: plan.plan_root(),
            reserve_check_id: None,
            watchtower_signature_id: None,
            assigned_at_height,
            expires_at_height: assigned_at_height.saturating_add(config.batch_ttl_blocks),
            status: MakerAssignmentStatus::Proposed,
        };
        assignment.assignment_id =
            monero_exit_batch_scheduler_assignment_id(&assignment.identity_record());
        assignment.validate()?;
        Ok(assignment)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_assignment_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "maker_id": self.maker_id,
            "window_id": self.window_id,
            "plan_id": self.plan_id,
            "bucket_id": self.bucket_id,
            "plan_root": self.plan_root,
            "assigned_at_height": self.assigned_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_assignment",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "assignment_id": self.assignment_id,
            "maker_id": self.maker_id,
            "window_id": self.window_id,
            "plan_id": self.plan_id,
            "bucket_id": self.bucket_id,
            "intent_ids": self.intent_ids,
            "reserved_amount_units": self.reserved_amount_units,
            "maker_fee_units": self.maker_fee_units,
            "plan_root": self.plan_root,
            "reserve_check_id": self.reserve_check_id,
            "watchtower_signature_id": self.watchtower_signature_id,
            "assigned_at_height": self.assigned_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn assignment_root(&self) -> String {
        scheduler_payload_root(
            "MONERO-EXIT-BATCH-SCHEDULER-ASSIGNMENT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "assignment_root",
            self.assignment_root(),
        )
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status.is_live() {
            self.status = MakerAssignmentStatus::Expired;
        }
    }

    pub fn validate(&self) -> MoneroExitBatchSchedulerResult<String> {
        ensure_non_empty(&self.assignment_id, "assignment id")?;
        ensure_non_empty(&self.maker_id, "assignment maker id")?;
        ensure_non_empty(&self.window_id, "assignment window id")?;
        ensure_non_empty(&self.plan_id, "assignment plan id")?;
        ensure_non_empty(&self.bucket_id, "assignment bucket id")?;
        ensure_positive(self.reserved_amount_units, "assignment reserved amount")?;
        ensure_expiry(
            self.assigned_at_height,
            self.expires_at_height,
            "maker assignment",
        )?;
        if self.intent_ids.is_empty() {
            return Err("assignment has no intents".to_string());
        }
        let computed = monero_exit_batch_scheduler_assignment_id(&self.identity_record());
        if self.assignment_id != computed {
            return Err("assignment id mismatch".to_string());
        }
        Ok(self.assignment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub intent_id: String,
    pub window_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub eligible_fee_units: u64,
    pub rebate_units: u64,
    pub rebate_bps: u64,
    pub reason_root: String,
    pub issued_at_height: u64,
}

impl FeeRebate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent: &ExitIntent,
        window_id: &str,
        sponsor_commitment: &str,
        reason: &Value,
        issued_at_height: u64,
        config: &MoneroExitBatchSchedulerConfig,
    ) -> MoneroExitBatchSchedulerResult<Self> {
        ensure_non_empty(&intent.intent_id, "rebate intent id")?;
        ensure_non_empty(window_id, "rebate window id")?;
        ensure_non_empty(sponsor_commitment, "rebate sponsor commitment")?;
        let rebate_units = config.rebate_for(
            intent.max_fee_units,
            intent.priority,
            config.target_ring_size,
        );
        let rebate_bps = if intent.max_fee_units == 0 {
            0
        } else {
            rebate_units.saturating_mul(MONERO_EXIT_BATCH_SCHEDULER_MAX_BPS) / intent.max_fee_units
        };
        let reason_root = scheduler_payload_root("MONERO-EXIT-SCHEDULER-REBATE-REASON", reason);
        let mut rebate = Self {
            rebate_id: String::new(),
            intent_id: intent.intent_id.clone(),
            window_id: window_id.to_string(),
            sponsor_commitment: sponsor_commitment.to_string(),
            fee_asset_id: intent.fee_asset_id.clone(),
            eligible_fee_units: intent.max_fee_units,
            rebate_units,
            rebate_bps,
            reason_root,
            issued_at_height,
        };
        rebate.rebate_id = monero_exit_batch_scheduler_rebate_id(&rebate.identity_record());
        rebate.validate()?;
        Ok(rebate)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_rebate_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "window_id": self.window_id,
            "sponsor_commitment": self.sponsor_commitment,
            "rebate_units": self.rebate_units,
            "issued_at_height": self.issued_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_rebate",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "rebate_id": self.rebate_id,
            "intent_id": self.intent_id,
            "window_id": self.window_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "eligible_fee_units": self.eligible_fee_units,
            "rebate_units": self.rebate_units,
            "rebate_bps": self.rebate_bps,
            "reason_root": self.reason_root,
            "issued_at_height": self.issued_at_height,
        })
    }

    pub fn rebate_root(&self) -> String {
        scheduler_payload_root(
            "MONERO-EXIT-BATCH-SCHEDULER-REBATE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "rebate_root",
            self.rebate_root(),
        )
    }

    pub fn validate(&self) -> MoneroExitBatchSchedulerResult<String> {
        ensure_non_empty(&self.rebate_id, "rebate id")?;
        ensure_non_empty(&self.intent_id, "rebate intent id")?;
        ensure_non_empty(&self.window_id, "rebate window id")?;
        ensure_non_empty(&self.sponsor_commitment, "rebate sponsor commitment")?;
        ensure_non_empty(&self.fee_asset_id, "rebate fee asset")?;
        ensure_bps(self.rebate_bps, "rebate bps")?;
        ensure_non_empty(&self.reason_root, "rebate reason root")?;
        if self.rebate_units > self.eligible_fee_units {
            return Err("rebate exceeds eligible fee".to_string());
        }
        let computed = monero_exit_batch_scheduler_rebate_id(&self.identity_record());
        if self.rebate_id != computed {
            return Err("rebate id mismatch".to_string());
        }
        Ok(self.rebate_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchtowerSignature {
    pub signature_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub signer_commitments: Vec<String>,
    pub signer_weight: u64,
    pub required_weight: u64,
    pub aggregate_signature_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
}

impl WatchtowerSignature {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        signer_commitments: &[String],
        signer_weight: u64,
        required_weight: u64,
        aggregate_signature_payload: &Value,
        signed_at_height: u64,
        expires_at_height: u64,
    ) -> MoneroExitBatchSchedulerResult<Self> {
        ensure_non_empty(subject_kind, "watchtower subject kind")?;
        ensure_non_empty(subject_id, "watchtower subject id")?;
        ensure_non_empty(subject_root, "watchtower subject root")?;
        if signer_commitments.is_empty() {
            return Err("watchtower signature has no signers".to_string());
        }
        ensure_positive(signer_weight, "watchtower signer weight")?;
        ensure_positive(required_weight, "watchtower required weight")?;
        ensure_expiry(signed_at_height, expires_at_height, "watchtower signature")?;
        let aggregate_signature_root = scheduler_payload_root(
            "MONERO-EXIT-SCHEDULER-WATCHTOWER-AGGREGATE-SIGNATURE",
            aggregate_signature_payload,
        );
        let mut signature = Self {
            signature_id: String::new(),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            signer_commitments: signer_commitments.to_vec(),
            signer_weight,
            required_weight,
            aggregate_signature_root,
            signed_at_height,
            expires_at_height,
        };
        signature.signature_id =
            monero_exit_batch_scheduler_watchtower_signature_id(&signature.identity_record());
        signature.validate()?;
        Ok(signature)
    }

    pub fn quorum_met(&self) -> bool {
        self.signer_weight >= self.required_weight
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_watchtower_signature_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "signer_root": string_set_root("MONERO-EXIT-SCHEDULER-WATCHTOWER-SIGNER", self.signer_commitments.clone()),
            "signed_at_height": self.signed_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_watchtower_signature",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "signature_id": self.signature_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "signer_commitments": self.signer_commitments,
            "signer_count": self.signer_commitments.len() as u64,
            "signer_weight": self.signer_weight,
            "required_weight": self.required_weight,
            "quorum_met": self.quorum_met(),
            "aggregate_signature_root": self.aggregate_signature_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn signature_root(&self) -> String {
        scheduler_payload_root(
            "MONERO-EXIT-BATCH-SCHEDULER-WATCHTOWER-SIGNATURE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "signature_root",
            self.signature_root(),
        )
    }

    pub fn validate(&self) -> MoneroExitBatchSchedulerResult<String> {
        ensure_non_empty(&self.signature_id, "watchtower signature id")?;
        ensure_non_empty(&self.subject_kind, "watchtower subject kind")?;
        ensure_non_empty(&self.subject_id, "watchtower subject id")?;
        ensure_non_empty(&self.subject_root, "watchtower subject root")?;
        ensure_positive(self.signer_weight, "watchtower signer weight")?;
        ensure_positive(self.required_weight, "watchtower required weight")?;
        ensure_non_empty(
            &self.aggregate_signature_root,
            "watchtower aggregate signature root",
        )?;
        ensure_expiry(
            self.signed_at_height,
            self.expires_at_height,
            "watchtower signature",
        )?;
        if self.signer_commitments.is_empty() {
            return Err("watchtower signature signer set is empty".to_string());
        }
        let computed = monero_exit_batch_scheduler_watchtower_signature_id(&self.identity_record());
        if self.signature_id != computed {
            return Err("watchtower signature id mismatch".to_string());
        }
        Ok(self.signature_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveCheck {
    pub reserve_check_id: String,
    pub maker_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub liability_units: u64,
    pub available_reserve_units: u64,
    pub pending_reserve_units: u64,
    pub coverage_bps: u64,
    pub min_coverage_bps: u64,
    pub proof_root: String,
    pub checked_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveCheck {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        maker_id: &str,
        subject_kind: &str,
        subject_id: &str,
        liability_units: u64,
        available_reserve_units: u64,
        pending_reserve_units: u64,
        proof_payload: &Value,
        checked_at_height: u64,
        expires_at_height: u64,
        config: &MoneroExitBatchSchedulerConfig,
    ) -> MoneroExitBatchSchedulerResult<Self> {
        ensure_non_empty(maker_id, "reserve check maker id")?;
        ensure_non_empty(subject_kind, "reserve check subject kind")?;
        ensure_non_empty(subject_id, "reserve check subject id")?;
        ensure_positive(liability_units, "reserve check liability")?;
        ensure_expiry(checked_at_height, expires_at_height, "reserve check")?;
        let coverage_bps = available_reserve_units
            .saturating_sub(pending_reserve_units)
            .saturating_mul(MONERO_EXIT_BATCH_SCHEDULER_MAX_BPS)
            / liability_units;
        let proof_root =
            scheduler_payload_root("MONERO-EXIT-SCHEDULER-RESERVE-PROOF", proof_payload);
        let mut check = Self {
            reserve_check_id: String::new(),
            maker_id: maker_id.to_string(),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            liability_units,
            available_reserve_units,
            pending_reserve_units,
            coverage_bps,
            min_coverage_bps: config.min_reserve_coverage_bps,
            proof_root,
            checked_at_height,
            expires_at_height,
        };
        check.reserve_check_id =
            monero_exit_batch_scheduler_reserve_check_id(&check.identity_record());
        check.validate()?;
        Ok(check)
    }

    pub fn is_sufficient(&self) -> bool {
        self.coverage_bps >= self.min_coverage_bps
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_reserve_check_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "maker_id": self.maker_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "liability_units": self.liability_units,
            "proof_root": self.proof_root,
            "checked_at_height": self.checked_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_reserve_check",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "reserve_check_id": self.reserve_check_id,
            "maker_id": self.maker_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "liability_units": self.liability_units,
            "available_reserve_units": self.available_reserve_units,
            "pending_reserve_units": self.pending_reserve_units,
            "coverage_bps": self.coverage_bps,
            "min_coverage_bps": self.min_coverage_bps,
            "sufficient": self.is_sufficient(),
            "proof_root": self.proof_root,
            "checked_at_height": self.checked_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn reserve_check_root(&self) -> String {
        scheduler_payload_root(
            "MONERO-EXIT-BATCH-SCHEDULER-RESERVE-CHECK",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "reserve_check_root",
            self.reserve_check_root(),
        )
    }

    pub fn validate(&self) -> MoneroExitBatchSchedulerResult<String> {
        ensure_non_empty(&self.reserve_check_id, "reserve check id")?;
        ensure_non_empty(&self.maker_id, "reserve check maker id")?;
        ensure_non_empty(&self.subject_kind, "reserve check subject kind")?;
        ensure_non_empty(&self.subject_id, "reserve check subject id")?;
        ensure_positive(self.liability_units, "reserve check liability")?;
        ensure_positive(self.min_coverage_bps, "reserve check min coverage")?;
        ensure_non_empty(&self.proof_root, "reserve check proof root")?;
        ensure_expiry(
            self.checked_at_height,
            self.expires_at_height,
            "reserve check",
        )?;
        let computed = monero_exit_batch_scheduler_reserve_check_id(&self.identity_record());
        if self.reserve_check_id != computed {
            return Err("reserve check id mismatch".to_string());
        }
        Ok(self.reserve_check_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelayedRevealWindow {
    pub reveal_window_id: String,
    pub window_id: String,
    pub plan_id: String,
    pub encrypted_payload_root: String,
    pub reveal_commitment_root: String,
    pub opened_at_height: u64,
    pub reveal_at_height: u64,
    pub expires_at_height: u64,
    pub watchtower_signature_id: Option<String>,
    pub status: RevealWindowStatus,
}

impl DelayedRevealWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        window_id: &str,
        plan: &StealthPayoutPlan,
        reveal_commitment_payload: &Value,
        opened_at_height: u64,
        config: &MoneroExitBatchSchedulerConfig,
    ) -> MoneroExitBatchSchedulerResult<Self> {
        ensure_non_empty(window_id, "delayed reveal window id")?;
        let reveal_commitment_root = scheduler_payload_root(
            "MONERO-EXIT-SCHEDULER-DELAYED-REVEAL-COMMITMENT",
            reveal_commitment_payload,
        );
        let reveal_at_height = opened_at_height.saturating_add(config.reveal_delay_blocks);
        let expires_at_height = reveal_at_height.saturating_add(config.reveal_ttl_blocks);
        let mut window = Self {
            reveal_window_id: String::new(),
            window_id: window_id.to_string(),
            plan_id: plan.plan_id.clone(),
            encrypted_payload_root: plan.encrypted_payload_root.clone(),
            reveal_commitment_root,
            opened_at_height,
            reveal_at_height,
            expires_at_height,
            watchtower_signature_id: None,
            status: RevealWindowStatus::Locked,
        };
        window.reveal_window_id =
            monero_exit_batch_scheduler_reveal_window_id(&window.identity_record());
        window.validate()?;
        Ok(window)
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height
            && matches!(
                self.status,
                RevealWindowStatus::Locked | RevealWindowStatus::Open
            )
        {
            self.status = RevealWindowStatus::Expired;
        } else if height >= self.reveal_at_height && self.status == RevealWindowStatus::Locked {
            self.status = RevealWindowStatus::Open;
        }
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_reveal_window_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "window_id": self.window_id,
            "plan_id": self.plan_id,
            "encrypted_payload_root": self.encrypted_payload_root,
            "opened_at_height": self.opened_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_reveal_window",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "reveal_window_id": self.reveal_window_id,
            "window_id": self.window_id,
            "plan_id": self.plan_id,
            "encrypted_payload_root": self.encrypted_payload_root,
            "reveal_commitment_root": self.reveal_commitment_root,
            "opened_at_height": self.opened_at_height,
            "reveal_at_height": self.reveal_at_height,
            "expires_at_height": self.expires_at_height,
            "watchtower_signature_id": self.watchtower_signature_id,
            "status": self.status.as_str(),
        })
    }

    pub fn reveal_window_root(&self) -> String {
        scheduler_payload_root(
            "MONERO-EXIT-BATCH-SCHEDULER-REVEAL-WINDOW",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "reveal_window_root",
            self.reveal_window_root(),
        )
    }

    pub fn validate(&self) -> MoneroExitBatchSchedulerResult<String> {
        ensure_non_empty(&self.reveal_window_id, "reveal window id")?;
        ensure_non_empty(&self.window_id, "reveal window window id")?;
        ensure_non_empty(&self.plan_id, "reveal window plan id")?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "reveal window encrypted payload",
        )?;
        ensure_non_empty(
            &self.reveal_commitment_root,
            "reveal window commitment root",
        )?;
        ensure_expiry(
            self.opened_at_height,
            self.reveal_at_height,
            "reveal window delay",
        )?;
        ensure_expiry(
            self.reveal_at_height,
            self.expires_at_height,
            "reveal window ttl",
        )?;
        let computed = monero_exit_batch_scheduler_reveal_window_id(&self.identity_record());
        if self.reveal_window_id != computed {
            return Err("reveal window id mismatch".to_string());
        }
        Ok(self.reveal_window_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyExit {
    pub emergency_exit_id: String,
    pub intent_id: String,
    pub maker_id: Option<String>,
    pub reason_root: String,
    pub reserve_check_id: Option<String>,
    pub watchtower_signature_id: Option<String>,
    pub requested_amount_units: u64,
    pub emergency_fee_units: u64,
    pub queued_at_height: u64,
    pub expires_at_height: u64,
    pub status: EmergencyExitStatus,
}

impl EmergencyExit {
    pub fn new(
        intent: &ExitIntent,
        reason: &Value,
        queued_at_height: u64,
        config: &MoneroExitBatchSchedulerConfig,
    ) -> MoneroExitBatchSchedulerResult<Self> {
        ensure_non_empty(&intent.intent_id, "emergency exit intent id")?;
        let reason_root = scheduler_payload_root("MONERO-EXIT-SCHEDULER-EMERGENCY-REASON", reason);
        let emergency_fee_units =
            config.fee_for(intent.amount_units, ExitIntentPriority::Emergency);
        let mut emergency = Self {
            emergency_exit_id: String::new(),
            intent_id: intent.intent_id.clone(),
            maker_id: None,
            reason_root,
            reserve_check_id: None,
            watchtower_signature_id: None,
            requested_amount_units: intent.amount_units,
            emergency_fee_units,
            queued_at_height,
            expires_at_height: queued_at_height.saturating_add(config.emergency_exit_ttl_blocks),
            status: EmergencyExitStatus::Open,
        };
        emergency.emergency_exit_id =
            monero_exit_batch_scheduler_emergency_exit_id(&emergency.identity_record());
        emergency.validate()?;
        Ok(emergency)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_emergency_exit_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "reason_root": self.reason_root,
            "requested_amount_units": self.requested_amount_units,
            "queued_at_height": self.queued_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_emergency_exit",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "emergency_exit_id": self.emergency_exit_id,
            "intent_id": self.intent_id,
            "maker_id": self.maker_id,
            "reason_root": self.reason_root,
            "reserve_check_id": self.reserve_check_id,
            "watchtower_signature_id": self.watchtower_signature_id,
            "requested_amount_units": self.requested_amount_units,
            "emergency_fee_units": self.emergency_fee_units,
            "queued_at_height": self.queued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn emergency_exit_root(&self) -> String {
        scheduler_payload_root(
            "MONERO-EXIT-BATCH-SCHEDULER-EMERGENCY-EXIT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "emergency_exit_root",
            self.emergency_exit_root(),
        )
    }

    pub fn set_height(&mut self, height: u64) {
        if height >= self.expires_at_height && self.status == EmergencyExitStatus::Open {
            self.status = EmergencyExitStatus::Expired;
        }
    }

    pub fn validate(&self) -> MoneroExitBatchSchedulerResult<String> {
        ensure_non_empty(&self.emergency_exit_id, "emergency exit id")?;
        ensure_non_empty(&self.intent_id, "emergency exit intent id")?;
        ensure_non_empty(&self.reason_root, "emergency exit reason root")?;
        ensure_positive(self.requested_amount_units, "emergency exit amount")?;
        ensure_expiry(
            self.queued_at_height,
            self.expires_at_height,
            "emergency exit",
        )?;
        let computed = monero_exit_batch_scheduler_emergency_exit_id(&self.identity_record());
        if self.emergency_exit_id != computed {
            return Err("emergency exit id mismatch".to_string());
        }
        Ok(self.emergency_exit_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub intent_id: String,
    pub window_id: Option<String>,
    pub plan_id: Option<String>,
    pub assignment_id: Option<String>,
    pub emergency_exit_id: Option<String>,
    pub monero_txid_hash: String,
    pub output_commitment_root: String,
    pub key_image_root: String,
    pub fee_paid_units: u64,
    pub rebate_units: u64,
    pub settlement_height: u64,
    pub finality_height: u64,
    pub watchtower_signature_id: Option<String>,
    pub receipt_nullifier: String,
    pub status: SettlementReceiptStatus,
}

impl SettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: &str,
        window_id: Option<String>,
        plan_id: Option<String>,
        assignment_id: Option<String>,
        emergency_exit_id: Option<String>,
        monero_txid: &str,
        output_commitments: &[Value],
        key_images: &[String],
        fee_paid_units: u64,
        rebate_units: u64,
        settlement_height: u64,
        finality_height: u64,
    ) -> MoneroExitBatchSchedulerResult<Self> {
        ensure_non_empty(intent_id, "settlement receipt intent id")?;
        ensure_non_empty(monero_txid, "settlement receipt monero txid")?;
        if finality_height < settlement_height {
            return Err("settlement receipt finality precedes settlement".to_string());
        }
        let monero_txid_hash = scheduler_domain_hash(
            "MONERO-EXIT-SCHEDULER-TXID",
            &[HashPart::Str(CHAIN_ID), HashPart::Str(monero_txid)],
        );
        let output_commitment_root = merkle_root(
            "MONERO-EXIT-SCHEDULER-SETTLEMENT-OUTPUT",
            output_commitments,
        );
        let key_image_root = string_set_root(
            "MONERO-EXIT-SCHEDULER-SETTLEMENT-KEY-IMAGE",
            key_images.to_vec(),
        );
        let receipt_nullifier = scheduler_domain_hash(
            "MONERO-EXIT-SCHEDULER-RECEIPT-NULLIFIER",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(intent_id),
                HashPart::Str(&monero_txid_hash),
                HashPart::Int(settlement_height as i128),
            ],
        );
        let mut receipt = Self {
            receipt_id: String::new(),
            intent_id: intent_id.to_string(),
            window_id,
            plan_id,
            assignment_id,
            emergency_exit_id,
            monero_txid_hash,
            output_commitment_root,
            key_image_root,
            fee_paid_units,
            rebate_units,
            settlement_height,
            finality_height,
            watchtower_signature_id: None,
            receipt_nullifier,
            status: SettlementReceiptStatus::Observed,
        };
        receipt.receipt_id = monero_exit_batch_scheduler_receipt_id(&receipt.identity_record());
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_receipt_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "monero_txid_hash": self.monero_txid_hash,
            "output_commitment_root": self.output_commitment_root,
            "receipt_nullifier": self.receipt_nullifier,
            "settlement_height": self.settlement_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "intent_id": self.intent_id,
            "window_id": self.window_id,
            "plan_id": self.plan_id,
            "assignment_id": self.assignment_id,
            "emergency_exit_id": self.emergency_exit_id,
            "monero_txid_hash": self.monero_txid_hash,
            "output_commitment_root": self.output_commitment_root,
            "key_image_root": self.key_image_root,
            "fee_paid_units": self.fee_paid_units,
            "rebate_units": self.rebate_units,
            "settlement_height": self.settlement_height,
            "finality_height": self.finality_height,
            "watchtower_signature_id": self.watchtower_signature_id,
            "receipt_nullifier": self.receipt_nullifier,
            "status": self.status.as_str(),
        })
    }

    pub fn receipt_root(&self) -> String {
        scheduler_payload_root(
            "MONERO-EXIT-BATCH-SCHEDULER-RECEIPT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "receipt_root",
            self.receipt_root(),
        )
    }

    pub fn validate(&self) -> MoneroExitBatchSchedulerResult<String> {
        ensure_non_empty(&self.receipt_id, "settlement receipt id")?;
        ensure_non_empty(&self.intent_id, "settlement receipt intent id")?;
        ensure_non_empty(&self.monero_txid_hash, "settlement receipt txid hash")?;
        ensure_non_empty(
            &self.output_commitment_root,
            "settlement receipt output root",
        )?;
        ensure_non_empty(&self.key_image_root, "settlement receipt key image root")?;
        ensure_non_empty(
            &self.receipt_nullifier,
            "settlement receipt receipt nullifier",
        )?;
        if self.finality_height < self.settlement_height {
            return Err("settlement receipt finality height mismatch".to_string());
        }
        let computed = monero_exit_batch_scheduler_receipt_id(&self.identity_record());
        if self.receipt_id != computed {
            return Err("settlement receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerEvent {
    pub event_id: String,
    pub sequence: u64,
    pub event_kind: SchedulerEventKind,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
}

impl SchedulerEvent {
    pub fn new(
        sequence: u64,
        event_kind: SchedulerEventKind,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        payload: &Value,
        emitted_at_height: u64,
    ) -> MoneroExitBatchSchedulerResult<Self> {
        ensure_non_empty(subject_kind, "scheduler event subject kind")?;
        ensure_non_empty(subject_id, "scheduler event subject id")?;
        ensure_non_empty(subject_root, "scheduler event subject root")?;
        let payload_root = scheduler_payload_root("MONERO-EXIT-SCHEDULER-EVENT-PAYLOAD", payload);
        let mut event = Self {
            event_id: String::new(),
            sequence,
            event_kind,
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root: subject_root.to_string(),
            payload_root,
            emitted_at_height,
        };
        event.event_id = monero_exit_batch_scheduler_event_id(&event.identity_record());
        event.validate()?;
        Ok(event)
    }

    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_event_identity",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "sequence": self.sequence,
            "event_kind": self.event_kind.as_str(),
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "emitted_at_height": self.emitted_at_height,
        })
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_event",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "event_id": self.event_id,
            "sequence": self.sequence,
            "event_kind": self.event_kind.as_str(),
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }

    pub fn event_root(&self) -> String {
        scheduler_payload_root(
            "MONERO-EXIT-BATCH-SCHEDULER-EVENT",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "event_root",
            self.event_root(),
        )
    }

    pub fn validate(&self) -> MoneroExitBatchSchedulerResult<String> {
        ensure_non_empty(&self.event_id, "scheduler event id")?;
        ensure_non_empty(&self.subject_kind, "scheduler event subject kind")?;
        ensure_non_empty(&self.subject_id, "scheduler event subject id")?;
        ensure_non_empty(&self.subject_root, "scheduler event subject root")?;
        ensure_non_empty(&self.payload_root, "scheduler event payload root")?;
        let computed = monero_exit_batch_scheduler_event_id(&self.identity_record());
        if self.event_id != computed {
            return Err("scheduler event id mismatch".to_string());
        }
        Ok(self.event_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroExitBatchSchedulerRoots {
    pub config_root: String,
    pub intent_root: String,
    pub bucket_root: String,
    pub window_root: String,
    pub stealth_plan_root: String,
    pub maker_root: String,
    pub assignment_root: String,
    pub rebate_root: String,
    pub watchtower_signature_root: String,
    pub reserve_check_root: String,
    pub reveal_window_root: String,
    pub emergency_exit_root: String,
    pub settlement_receipt_root: String,
    pub event_root: String,
    pub public_record_root: String,
}

impl MoneroExitBatchSchedulerRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config_root": self.config_root,
            "intent_root": self.intent_root,
            "bucket_root": self.bucket_root,
            "window_root": self.window_root,
            "stealth_plan_root": self.stealth_plan_root,
            "maker_root": self.maker_root,
            "assignment_root": self.assignment_root,
            "rebate_root": self.rebate_root,
            "watchtower_signature_root": self.watchtower_signature_root,
            "reserve_check_root": self.reserve_check_root,
            "reveal_window_root": self.reveal_window_root,
            "emergency_exit_root": self.emergency_exit_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "event_root": self.event_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        scheduler_payload_root(
            "MONERO-EXIT-BATCH-SCHEDULER-ROOT-VECTOR",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroExitBatchSchedulerCounters {
    pub intent_count: u64,
    pub open_intent_count: u64,
    pub bucket_count: u64,
    pub window_count: u64,
    pub stealth_plan_count: u64,
    pub maker_count: u64,
    pub assignment_count: u64,
    pub rebate_count: u64,
    pub watchtower_signature_count: u64,
    pub reserve_check_count: u64,
    pub reveal_window_count: u64,
    pub emergency_exit_count: u64,
    pub settlement_receipt_count: u64,
    pub event_count: u64,
    pub pending_exit_units: u64,
    pub reserved_maker_units: u64,
    pub issued_rebate_units: u64,
}

impl MoneroExitBatchSchedulerCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_exit_batch_scheduler_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "intent_count": self.intent_count,
            "open_intent_count": self.open_intent_count,
            "bucket_count": self.bucket_count,
            "window_count": self.window_count,
            "stealth_plan_count": self.stealth_plan_count,
            "maker_count": self.maker_count,
            "assignment_count": self.assignment_count,
            "rebate_count": self.rebate_count,
            "watchtower_signature_count": self.watchtower_signature_count,
            "reserve_check_count": self.reserve_check_count,
            "reveal_window_count": self.reveal_window_count,
            "emergency_exit_count": self.emergency_exit_count,
            "settlement_receipt_count": self.settlement_receipt_count,
            "event_count": self.event_count,
            "pending_exit_units": self.pending_exit_units,
            "reserved_maker_units": self.reserved_maker_units,
            "issued_rebate_units": self.issued_rebate_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroExitBatchSchedulerState {
    pub height: u64,
    pub monero_network: String,
    pub asset_id: String,
    pub config: MoneroExitBatchSchedulerConfig,
    pub intents: BTreeMap<String, ExitIntent>,
    pub buckets: BTreeMap<String, RingOutputBucket>,
    pub windows: BTreeMap<String, BatchWindow>,
    pub stealth_plans: BTreeMap<String, StealthPayoutPlan>,
    pub makers: BTreeMap<String, LiquidityMaker>,
    pub assignments: BTreeMap<String, MakerAssignment>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub watchtower_signatures: BTreeMap<String, WatchtowerSignature>,
    pub reserve_checks: BTreeMap<String, ReserveCheck>,
    pub reveal_windows: BTreeMap<String, DelayedRevealWindow>,
    pub emergency_exits: BTreeMap<String, EmergencyExit>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub nullifier_index: BTreeMap<String, String>,
    pub key_image_index: BTreeMap<String, String>,
    pub public_records: BTreeMap<String, Value>,
    pub events: BTreeMap<String, SchedulerEvent>,
}

impl Default for MoneroExitBatchSchedulerState {
    fn default() -> Self {
        let config = MoneroExitBatchSchedulerConfig::default();
        Self {
            height: 0,
            monero_network: config.monero_network.clone(),
            asset_id: config.asset_id.clone(),
            config,
            intents: BTreeMap::new(),
            buckets: BTreeMap::new(),
            windows: BTreeMap::new(),
            stealth_plans: BTreeMap::new(),
            makers: BTreeMap::new(),
            assignments: BTreeMap::new(),
            rebates: BTreeMap::new(),
            watchtower_signatures: BTreeMap::new(),
            reserve_checks: BTreeMap::new(),
            reveal_windows: BTreeMap::new(),
            emergency_exits: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            nullifier_index: BTreeMap::new(),
            key_image_index: BTreeMap::new(),
            public_records: BTreeMap::new(),
            events: BTreeMap::new(),
        }
    }
}

impl MoneroExitBatchSchedulerState {
    pub fn new(config: MoneroExitBatchSchedulerConfig) -> MoneroExitBatchSchedulerResult<Self> {
        config.validate()?;
        Ok(Self {
            height: 0,
            monero_network: config.monero_network.clone(),
            asset_id: config.asset_id.clone(),
            config,
            ..Self::default()
        })
    }

    pub fn devnet() -> MoneroExitBatchSchedulerResult<Self> {
        let config = MoneroExitBatchSchedulerConfig::devnet();
        let mut state = Self::new(config)?;
        state.set_height(MONERO_EXIT_BATCH_SCHEDULER_DEVNET_HEIGHT);

        let mut window = BatchWindow::new(0, state.height, &state.config)?;
        let window_id = window.window_id.clone();
        window.status = BatchWindowStatus::Collecting;
        state.windows.insert(window_id.clone(), window.clone());
        state.record_event(
            SchedulerEventKind::WindowOpened,
            "window",
            &window_id,
            &window.window_root(),
            &window.public_record(),
        )?;

        let maker_a = LiquidityMaker::new(
            "devnet-scheduler-maker-a",
            "devnet-maker-a-reserve-commitment",
            &json!({"monero_payout_key": "devnet-maker-a-payout-key"}),
            &json!({"pq_suite": state.config.pq_suite, "identity": "devnet-maker-a"}),
            &[10_000, 20_000, 50_000, 100_000],
            1_000_000,
            900_000,
            12,
            state.height,
        )?;
        let maker_b = LiquidityMaker::new(
            "devnet-scheduler-maker-b",
            "devnet-maker-b-reserve-commitment",
            &json!({"monero_payout_key": "devnet-maker-b-payout-key"}),
            &json!({"pq_suite": state.config.pq_suite, "identity": "devnet-maker-b"}),
            &[10_000, 20_000, 50_000],
            750_000,
            700_000,
            16,
            state.height,
        )?;
        state.add_maker(maker_a)?;
        state.add_maker(maker_b)?;

        let intent = ExitIntent::new(
            "devnet-owner-commitment-a",
            "devnet-account-commitment-a",
            "devnet-monero-address-a",
            "devnet-view-tag-a",
            50_000,
            &state.config.fee_asset_id,
            ExitIntentPriority::Sponsored,
            "devnet-nullifier-a",
            "devnet-key-image-a",
            &json!({"contract": "swap-router", "method": "exit_to_monero"}),
            &json!({"token": state.asset_id, "scope": "wrapped-xmr"}),
            &json!({"privacy_set": "devnet-sponsored-ring"}),
            "devnet memo",
            state.height,
            &state.config,
        )?;
        state.submit_intent(intent)?;
        state.refresh_public_records();
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for intent in self.intents.values_mut() {
            intent.set_height(height);
        }
        for window in self.windows.values_mut() {
            window.set_height(height);
        }
        for assignment in self.assignments.values_mut() {
            assignment.set_height(height);
        }
        for reveal in self.reveal_windows.values_mut() {
            reveal.set_height(height);
        }
        for emergency in self.emergency_exits.values_mut() {
            emergency.set_height(height);
        }
        self.refresh_public_records();
    }

    pub fn submit_intent(
        &mut self,
        mut intent: ExitIntent,
    ) -> MoneroExitBatchSchedulerResult<String> {
        self.config.validate()?;
        intent.validate()?;
        if intent.fee_asset_id != self.config.fee_asset_id {
            return Err("scheduler intent fee asset mismatch".to_string());
        }
        if self.nullifier_index.contains_key(&intent.nullifier_hash) {
            return Err("scheduler nullifier replay detected".to_string());
        }
        if self.key_image_index.contains_key(&intent.key_image_hash) {
            return Err("scheduler key image replay detected".to_string());
        }
        let window_id = self.ensure_collecting_window()?;
        let bucket_id = self.ensure_bucket_for_intent(&window_id, &intent)?;
        {
            let bucket = self
                .buckets
                .get_mut(&bucket_id)
                .ok_or_else(|| "scheduler bucket disappeared".to_string())?;
            bucket.add_intent(&intent)?;
        }
        {
            let window = self
                .windows
                .get_mut(&window_id)
                .ok_or_else(|| "scheduler window disappeared".to_string())?;
            window.intent_ids.insert(intent.intent_id.clone());
            window.bucket_ids.insert(bucket_id.clone());
            window.total_amount_units = window
                .total_amount_units
                .saturating_add(intent.amount_units);
            window.total_fee_units = window.total_fee_units.saturating_add(intent.max_fee_units);
        }
        intent.bucket_id = Some(bucket_id);
        intent.status = ExitIntentStatus::Bucketed;
        let intent_id = intent.intent_id.clone();
        self.nullifier_index
            .insert(intent.nullifier_hash.clone(), intent_id.clone());
        self.key_image_index
            .insert(intent.key_image_hash.clone(), intent_id.clone());
        self.record_event(
            SchedulerEventKind::IntentSubmitted,
            "intent",
            &intent_id,
            &intent.intent_root(),
            &intent.public_record(),
        )?;
        self.intents.insert(intent_id.clone(), intent);
        self.refresh_public_records();
        Ok(intent_id)
    }

    pub fn add_maker(&mut self, maker: LiquidityMaker) -> MoneroExitBatchSchedulerResult<String> {
        maker.validate()?;
        let maker_id = maker.maker_id.clone();
        self.record_event(
            SchedulerEventKind::MakerRegistered,
            "maker",
            &maker_id,
            &maker.maker_root(),
            &maker.public_record(),
        )?;
        self.makers.insert(maker_id.clone(), maker);
        self.refresh_public_records();
        Ok(maker_id)
    }

    pub fn seal_window(&mut self, window_id: &str) -> MoneroExitBatchSchedulerResult<String> {
        let bucket_ids = self
            .windows
            .get(window_id)
            .ok_or_else(|| "scheduler window missing".to_string())?
            .bucket_ids
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        for bucket_id in bucket_ids {
            if let Some(bucket) = self.buckets.get_mut(&bucket_id) {
                if bucket.status == RingBucketStatus::Open && !bucket.intent_ids.is_empty() {
                    bucket.seal(self.height)?;
                }
            }
        }
        let (subject_root, payload) = {
            let window = self
                .windows
                .get_mut(window_id)
                .ok_or_else(|| "scheduler window missing".to_string())?;
            window.status = BatchWindowStatus::Sealed;
            (window.window_root(), window.public_record())
        };
        self.record_event(
            SchedulerEventKind::WindowSealed,
            "window",
            window_id,
            &subject_root,
            &payload,
        )?;
        self.refresh_public_records();
        Ok(subject_root)
    }

    pub fn create_stealth_plan(
        &mut self,
        bucket_id: &str,
        stealth_outputs: &[Value],
        one_time_keys: &[String],
        encrypted_payload: &Value,
    ) -> MoneroExitBatchSchedulerResult<String> {
        let bucket = self
            .buckets
            .get(bucket_id)
            .ok_or_else(|| "scheduler bucket missing".to_string())?
            .clone();
        let window_id = bucket.window_id.clone();
        let plan = StealthPayoutPlan::new(
            &window_id,
            &bucket,
            stealth_outputs,
            one_time_keys,
            encrypted_payload,
            self.height,
        )?;
        let plan_id = plan.plan_id.clone();
        for intent_id in &plan.intent_ids {
            let intent = self
                .intents
                .get_mut(intent_id)
                .ok_or_else(|| "scheduler plan references missing intent".to_string())?;
            intent.plan_id = Some(plan_id.clone());
            intent.status = ExitIntentStatus::Planned;
        }
        {
            let window = self
                .windows
                .get_mut(&window_id)
                .ok_or_else(|| "scheduler plan references missing window".to_string())?;
            window.stealth_plan_ids.insert(plan_id.clone());
            if matches!(
                window.status,
                BatchWindowStatus::Sealed | BatchWindowStatus::Collecting
            ) {
                window.status = BatchWindowStatus::Planned;
            }
        }
        if let Some(bucket) = self.buckets.get_mut(bucket_id) {
            bucket.status = RingBucketStatus::Planned;
        }
        self.record_event(
            SchedulerEventKind::StealthPlanCreated,
            "stealth_plan",
            &plan_id,
            &plan.plan_root(),
            &plan.public_record(),
        )?;
        self.stealth_plans.insert(plan_id.clone(), plan);
        self.refresh_public_records();
        Ok(plan_id)
    }

    pub fn assign_maker(
        &mut self,
        plan_id: &str,
        maker_id: &str,
    ) -> MoneroExitBatchSchedulerResult<String> {
        let plan = self
            .stealth_plans
            .get(plan_id)
            .ok_or_else(|| "scheduler plan missing".to_string())?
            .clone();
        let maker = self
            .makers
            .get_mut(maker_id)
            .ok_or_else(|| "scheduler maker missing".to_string())?;
        maker.reserve(plan.total_amount_units)?;
        let assignment = MakerAssignment::new(maker, &plan, self.height, &self.config)?;
        let assignment_id = assignment.assignment_id.clone();
        for intent_id in &assignment.intent_ids {
            let intent = self
                .intents
                .get_mut(intent_id)
                .ok_or_else(|| "scheduler assignment references missing intent".to_string())?;
            intent.assignment_id = Some(assignment_id.clone());
            intent.status = ExitIntentStatus::Assigned;
        }
        {
            let window = self
                .windows
                .get_mut(&assignment.window_id)
                .ok_or_else(|| "scheduler assignment references missing window".to_string())?;
            window.assignment_ids.insert(assignment_id.clone());
        }
        if let Some(bucket) = self.buckets.get_mut(&assignment.bucket_id) {
            bucket.status = RingBucketStatus::Assigned;
        }
        self.record_event(
            SchedulerEventKind::MakerAssigned,
            "assignment",
            &assignment_id,
            &assignment.assignment_root(),
            &assignment.public_record(),
        )?;
        self.assignments.insert(assignment_id.clone(), assignment);
        self.refresh_public_records();
        Ok(assignment_id)
    }

    pub fn issue_fee_rebate(
        &mut self,
        intent_id: &str,
        sponsor_commitment: &str,
        reason: &Value,
    ) -> MoneroExitBatchSchedulerResult<String> {
        let intent = self
            .intents
            .get(intent_id)
            .ok_or_else(|| "scheduler rebate intent missing".to_string())?
            .clone();
        let window_id = intent
            .bucket_id
            .as_ref()
            .and_then(|bucket_id| self.buckets.get(bucket_id))
            .map(|bucket| bucket.window_id.clone())
            .ok_or_else(|| "scheduler rebate intent is not bucketed".to_string())?;
        let rebate = FeeRebate::new(
            &intent,
            &window_id,
            sponsor_commitment,
            reason,
            self.height,
            &self.config,
        )?;
        let rebate_id = rebate.rebate_id.clone();
        self.record_event(
            SchedulerEventKind::FeeRebateIssued,
            "rebate",
            &rebate_id,
            &rebate.rebate_root(),
            &rebate.public_record(),
        )?;
        self.rebates.insert(rebate_id.clone(), rebate);
        self.refresh_public_records();
        Ok(rebate_id)
    }

    pub fn record_reserve_check(
        &mut self,
        check: ReserveCheck,
    ) -> MoneroExitBatchSchedulerResult<String> {
        check.validate()?;
        if !self.makers.contains_key(&check.maker_id) {
            return Err("scheduler reserve check references missing maker".to_string());
        }
        let check_id = check.reserve_check_id.clone();
        if check.subject_kind == "assignment" {
            let assignment = self
                .assignments
                .get_mut(&check.subject_id)
                .ok_or_else(|| "scheduler reserve check assignment missing".to_string())?;
            assignment.reserve_check_id = Some(check_id.clone());
            if check.is_sufficient() {
                assignment.status = MakerAssignmentStatus::Reserved;
            }
        }
        self.record_event(
            SchedulerEventKind::ReserveCheckRecorded,
            "reserve_check",
            &check_id,
            &check.reserve_check_root(),
            &check.public_record(),
        )?;
        self.reserve_checks.insert(check_id.clone(), check);
        self.refresh_public_records();
        Ok(check_id)
    }

    pub fn record_watchtower_signature(
        &mut self,
        signature: WatchtowerSignature,
    ) -> MoneroExitBatchSchedulerResult<String> {
        signature.validate()?;
        let signature_id = signature.signature_id.clone();
        if signature.subject_kind == "assignment" {
            if let Some(assignment) = self.assignments.get_mut(&signature.subject_id) {
                assignment.watchtower_signature_id = Some(signature_id.clone());
                if signature.quorum_met() {
                    assignment.status = MakerAssignmentStatus::WatchtowerApproved;
                }
            }
        } else if signature.subject_kind == "window" {
            if let Some(window) = self.windows.get_mut(&signature.subject_id) {
                if signature.quorum_met() {
                    window.status = BatchWindowStatus::WatchtowerApproved;
                }
            }
        } else if signature.subject_kind == "reveal_window" {
            if let Some(window) = self.reveal_windows.get_mut(&signature.subject_id) {
                window.watchtower_signature_id = Some(signature_id.clone());
                if signature.quorum_met() {
                    window.status = RevealWindowStatus::Acknowledged;
                }
            }
        } else if signature.subject_kind == "emergency_exit" {
            if let Some(exit) = self.emergency_exits.get_mut(&signature.subject_id) {
                exit.watchtower_signature_id = Some(signature_id.clone());
                if signature.quorum_met() {
                    exit.status = EmergencyExitStatus::WatchtowerApproved;
                }
            }
        }
        self.record_event(
            SchedulerEventKind::WatchtowerSignatureRecorded,
            "watchtower_signature",
            &signature_id,
            &signature.signature_root(),
            &signature.public_record(),
        )?;
        self.watchtower_signatures
            .insert(signature_id.clone(), signature);
        self.refresh_public_records();
        Ok(signature_id)
    }

    pub fn open_reveal_window(
        &mut self,
        plan_id: &str,
        reveal_commitment_payload: &Value,
    ) -> MoneroExitBatchSchedulerResult<String> {
        let plan = self
            .stealth_plans
            .get(plan_id)
            .ok_or_else(|| "scheduler reveal plan missing".to_string())?
            .clone();
        let reveal = DelayedRevealWindow::new(
            &plan.window_id,
            &plan,
            reveal_commitment_payload,
            self.height,
            &self.config,
        )?;
        let reveal_id = reveal.reveal_window_id.clone();
        for intent_id in &plan.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = ExitIntentStatus::RevealPending;
            }
        }
        if let Some(plan) = self.stealth_plans.get_mut(plan_id) {
            plan.reveal_window_id = Some(reveal_id.clone());
        }
        self.record_event(
            SchedulerEventKind::RevealWindowOpened,
            "reveal_window",
            &reveal_id,
            &reveal.reveal_window_root(),
            &reveal.public_record(),
        )?;
        self.reveal_windows.insert(reveal_id.clone(), reveal);
        self.refresh_public_records();
        Ok(reveal_id)
    }

    pub fn queue_emergency_exit(
        &mut self,
        intent_id: &str,
        reason: &Value,
    ) -> MoneroExitBatchSchedulerResult<String> {
        let intent = self
            .intents
            .get(intent_id)
            .ok_or_else(|| "scheduler emergency intent missing".to_string())?
            .clone();
        let emergency = EmergencyExit::new(&intent, reason, self.height, &self.config)?;
        let emergency_id = emergency.emergency_exit_id.clone();
        if let Some(intent) = self.intents.get_mut(intent_id) {
            intent.status = ExitIntentStatus::EmergencyQueued;
        }
        self.record_event(
            SchedulerEventKind::EmergencyExitQueued,
            "emergency_exit",
            &emergency_id,
            &emergency.emergency_exit_root(),
            &emergency.public_record(),
        )?;
        self.emergency_exits.insert(emergency_id.clone(), emergency);
        self.refresh_public_records();
        Ok(emergency_id)
    }

    pub fn record_settlement_receipt(
        &mut self,
        receipt: SettlementReceipt,
    ) -> MoneroExitBatchSchedulerResult<String> {
        receipt.validate()?;
        if !self.intents.contains_key(&receipt.intent_id) {
            return Err("scheduler receipt references missing intent".to_string());
        }
        let receipt_id = receipt.receipt_id.clone();
        if let Some(intent) = self.intents.get_mut(&receipt.intent_id) {
            intent.receipt_id = Some(receipt_id.clone());
            intent.status = if receipt.emergency_exit_id.is_some() {
                ExitIntentStatus::EmergencySettled
            } else {
                ExitIntentStatus::Settled
            };
        }
        if let Some(assignment_id) = &receipt.assignment_id {
            if let Some(assignment) = self.assignments.get_mut(assignment_id) {
                assignment.status = MakerAssignmentStatus::Settled;
            }
        }
        if let Some(emergency_id) = &receipt.emergency_exit_id {
            if let Some(emergency) = self.emergency_exits.get_mut(emergency_id) {
                emergency.status = EmergencyExitStatus::Settled;
            }
        }
        self.record_event(
            SchedulerEventKind::SettlementReceiptRecorded,
            "settlement_receipt",
            &receipt_id,
            &receipt.receipt_root(),
            &receipt.public_record(),
        )?;
        self.settlement_receipts.insert(receipt_id.clone(), receipt);
        self.refresh_public_records();
        Ok(receipt_id)
    }

    pub fn roots(&self) -> MoneroExitBatchSchedulerRoots {
        MoneroExitBatchSchedulerRoots {
            config_root: self.config.config_root(),
            intent_root: typed_record_root(
                "MONERO-EXIT-BATCH-SCHEDULER-INTENT-SET",
                self.intents
                    .values()
                    .map(ExitIntent::public_record)
                    .collect(),
            ),
            bucket_root: typed_record_root(
                "MONERO-EXIT-BATCH-SCHEDULER-BUCKET-SET",
                self.buckets
                    .values()
                    .map(RingOutputBucket::public_record)
                    .collect(),
            ),
            window_root: typed_record_root(
                "MONERO-EXIT-BATCH-SCHEDULER-WINDOW-SET",
                self.windows
                    .values()
                    .map(BatchWindow::public_record)
                    .collect(),
            ),
            stealth_plan_root: typed_record_root(
                "MONERO-EXIT-BATCH-SCHEDULER-PLAN-SET",
                self.stealth_plans
                    .values()
                    .map(StealthPayoutPlan::public_record)
                    .collect(),
            ),
            maker_root: typed_record_root(
                "MONERO-EXIT-BATCH-SCHEDULER-MAKER-SET",
                self.makers
                    .values()
                    .map(LiquidityMaker::public_record)
                    .collect(),
            ),
            assignment_root: typed_record_root(
                "MONERO-EXIT-BATCH-SCHEDULER-ASSIGNMENT-SET",
                self.assignments
                    .values()
                    .map(MakerAssignment::public_record)
                    .collect(),
            ),
            rebate_root: typed_record_root(
                "MONERO-EXIT-BATCH-SCHEDULER-REBATE-SET",
                self.rebates
                    .values()
                    .map(FeeRebate::public_record)
                    .collect(),
            ),
            watchtower_signature_root: typed_record_root(
                "MONERO-EXIT-BATCH-SCHEDULER-WATCHTOWER-SIGNATURE-SET",
                self.watchtower_signatures
                    .values()
                    .map(WatchtowerSignature::public_record)
                    .collect(),
            ),
            reserve_check_root: typed_record_root(
                "MONERO-EXIT-BATCH-SCHEDULER-RESERVE-CHECK-SET",
                self.reserve_checks
                    .values()
                    .map(ReserveCheck::public_record)
                    .collect(),
            ),
            reveal_window_root: typed_record_root(
                "MONERO-EXIT-BATCH-SCHEDULER-REVEAL-WINDOW-SET",
                self.reveal_windows
                    .values()
                    .map(DelayedRevealWindow::public_record)
                    .collect(),
            ),
            emergency_exit_root: typed_record_root(
                "MONERO-EXIT-BATCH-SCHEDULER-EMERGENCY-EXIT-SET",
                self.emergency_exits
                    .values()
                    .map(EmergencyExit::public_record)
                    .collect(),
            ),
            settlement_receipt_root: typed_record_root(
                "MONERO-EXIT-BATCH-SCHEDULER-SETTLEMENT-RECEIPT-SET",
                self.settlement_receipts
                    .values()
                    .map(SettlementReceipt::public_record)
                    .collect(),
            ),
            event_root: typed_record_root(
                "MONERO-EXIT-BATCH-SCHEDULER-EVENT-SET",
                self.events
                    .values()
                    .map(SchedulerEvent::public_record)
                    .collect(),
            ),
            public_record_root: keyed_record_root(
                "MONERO-EXIT-BATCH-SCHEDULER-PUBLIC-RECORD-SET",
                self.public_records
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            ),
        }
    }

    pub fn counters(&self) -> MoneroExitBatchSchedulerCounters {
        MoneroExitBatchSchedulerCounters {
            intent_count: self.intents.len() as u64,
            open_intent_count: self
                .intents
                .values()
                .filter(|intent| intent.status.is_open())
                .count() as u64,
            bucket_count: self.buckets.len() as u64,
            window_count: self.windows.len() as u64,
            stealth_plan_count: self.stealth_plans.len() as u64,
            maker_count: self.makers.len() as u64,
            assignment_count: self.assignments.len() as u64,
            rebate_count: self.rebates.len() as u64,
            watchtower_signature_count: self.watchtower_signatures.len() as u64,
            reserve_check_count: self.reserve_checks.len() as u64,
            reveal_window_count: self.reveal_windows.len() as u64,
            emergency_exit_count: self.emergency_exits.len() as u64,
            settlement_receipt_count: self.settlement_receipts.len() as u64,
            event_count: self.events.len() as u64,
            pending_exit_units: self.pending_exit_units(),
            reserved_maker_units: self
                .makers
                .values()
                .map(|maker| maker.reserved_liquidity_units)
                .sum(),
            issued_rebate_units: self
                .rebates
                .values()
                .map(|rebate| rebate.rebate_units)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        scheduler_payload_root(
            "MONERO-EXIT-BATCH-SCHEDULER-STATE",
            &self.public_record_without_root(),
        )
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "monero_exit_batch_scheduler_state_root",
            self.state_root(),
        )
    }

    pub fn validate(&self) -> MoneroExitBatchSchedulerResult<String> {
        self.config.validate()?;
        if self.monero_network != self.config.monero_network {
            return Err("scheduler state monero network mismatch".to_string());
        }
        if self.asset_id != self.config.asset_id {
            return Err("scheduler state asset mismatch".to_string());
        }
        for intent in self.intents.values() {
            intent.validate()?;
            if intent.fee_asset_id != self.config.fee_asset_id {
                return Err("scheduler intent fee asset mismatch".to_string());
            }
            if let Some(bucket_id) = &intent.bucket_id {
                let bucket = self
                    .buckets
                    .get(bucket_id)
                    .ok_or_else(|| "scheduler intent references missing bucket".to_string())?;
                if !bucket.intent_ids.contains(&intent.intent_id) {
                    return Err("scheduler intent bucket reverse link mismatch".to_string());
                }
            }
            if let Some(plan_id) = &intent.plan_id {
                let plan = self
                    .stealth_plans
                    .get(plan_id)
                    .ok_or_else(|| "scheduler intent references missing plan".to_string())?;
                if !plan.intent_ids.contains(&intent.intent_id) {
                    return Err("scheduler intent plan reverse link mismatch".to_string());
                }
            }
        }
        for bucket in self.buckets.values() {
            bucket.validate()?;
            if !self.windows.contains_key(&bucket.window_id) {
                return Err("scheduler bucket references missing window".to_string());
            }
            for intent_id in &bucket.intent_ids {
                if !self.intents.contains_key(intent_id) {
                    return Err("scheduler bucket references missing intent".to_string());
                }
            }
        }
        for window in self.windows.values() {
            window.validate()?;
            for bucket_id in &window.bucket_ids {
                if !self.buckets.contains_key(bucket_id) {
                    return Err("scheduler window references missing bucket".to_string());
                }
            }
            for assignment_id in &window.assignment_ids {
                if !self.assignments.contains_key(assignment_id) {
                    return Err("scheduler window references missing assignment".to_string());
                }
            }
        }
        for plan in self.stealth_plans.values() {
            plan.validate()?;
            if !self.buckets.contains_key(&plan.bucket_id) {
                return Err("scheduler plan references missing bucket".to_string());
            }
            if !self.windows.contains_key(&plan.window_id) {
                return Err("scheduler plan references missing window".to_string());
            }
        }
        for maker in self.makers.values() {
            maker.validate()?;
        }
        for assignment in self.assignments.values() {
            assignment.validate()?;
            if !self.makers.contains_key(&assignment.maker_id) {
                return Err("scheduler assignment references missing maker".to_string());
            }
            if !self.stealth_plans.contains_key(&assignment.plan_id) {
                return Err("scheduler assignment references missing plan".to_string());
            }
        }
        for rebate in self.rebates.values() {
            rebate.validate()?;
            if !self.intents.contains_key(&rebate.intent_id) {
                return Err("scheduler rebate references missing intent".to_string());
            }
        }
        for signature in self.watchtower_signatures.values() {
            signature.validate()?;
        }
        for check in self.reserve_checks.values() {
            check.validate()?;
            if !self.makers.contains_key(&check.maker_id) {
                return Err("scheduler reserve check references missing maker".to_string());
            }
        }
        for reveal in self.reveal_windows.values() {
            reveal.validate()?;
            if !self.stealth_plans.contains_key(&reveal.plan_id) {
                return Err("scheduler reveal references missing plan".to_string());
            }
        }
        for emergency in self.emergency_exits.values() {
            emergency.validate()?;
            if !self.intents.contains_key(&emergency.intent_id) {
                return Err("scheduler emergency exit references missing intent".to_string());
            }
        }
        for receipt in self.settlement_receipts.values() {
            receipt.validate()?;
            if !self.intents.contains_key(&receipt.intent_id) {
                return Err("scheduler receipt references missing intent".to_string());
            }
        }
        Ok(self.state_root())
    }

    fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "monero_exit_batch_scheduler_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": MONERO_EXIT_BATCH_SCHEDULER_SCHEMA_VERSION,
            "height": self.height,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "root_commitment": roots.state_root(),
            "counters": counters.public_record(),
        })
    }

    fn pending_exit_units(&self) -> u64 {
        self.intents
            .values()
            .filter(|intent| intent.status.is_open())
            .map(|intent| intent.amount_units)
            .sum()
    }

    fn ensure_collecting_window(&mut self) -> MoneroExitBatchSchedulerResult<String> {
        if let Some(window) = self
            .windows
            .values()
            .filter(|window| window.status == BatchWindowStatus::Collecting)
            .max_by_key(|window| window.sequence)
        {
            if self.height < window.collect_until_height {
                return Ok(window.window_id.clone());
            }
        }
        let sequence = self.windows.len() as u64;
        let window = BatchWindow::new(sequence, self.height, &self.config)?;
        let window_id = window.window_id.clone();
        self.record_event(
            SchedulerEventKind::WindowOpened,
            "window",
            &window_id,
            &window.window_root(),
            &window.public_record(),
        )?;
        self.windows.insert(window_id.clone(), window);
        Ok(window_id)
    }

    fn ensure_bucket_for_intent(
        &mut self,
        window_id: &str,
        intent: &ExitIntent,
    ) -> MoneroExitBatchSchedulerResult<String> {
        if let Some(bucket) = self.buckets.values().find(|bucket| {
            bucket.window_id == window_id
                && bucket.amount_bucket == intent.amount_bucket
                && bucket.priority_band == intent.priority
                && bucket.status.accepts_intents()
        }) {
            return Ok(bucket.bucket_id.clone());
        }
        let decoy_record = json!({
            "intent_privacy_hint_root": intent.privacy_hint_root,
            "amount_bucket": intent.amount_bucket,
            "target_ring_size": self.config.target_ring_size,
        });
        let bucket = RingOutputBucket::new(
            window_id,
            intent.amount_bucket,
            intent.priority,
            &[decoy_record],
            self.height,
            &self.config,
        )?;
        let bucket_id = bucket.bucket_id.clone();
        self.record_event(
            SchedulerEventKind::BucketOpened,
            "bucket",
            &bucket_id,
            &bucket.bucket_root(),
            &bucket.public_record(),
        )?;
        self.buckets.insert(bucket_id.clone(), bucket);
        Ok(bucket_id)
    }

    fn record_event(
        &mut self,
        event_kind: SchedulerEventKind,
        subject_kind: &str,
        subject_id: &str,
        subject_root: &str,
        payload: &Value,
    ) -> MoneroExitBatchSchedulerResult<String> {
        let sequence = self.events.len() as u64;
        let event = SchedulerEvent::new(
            sequence,
            event_kind,
            subject_kind,
            subject_id,
            subject_root,
            payload,
            self.height,
        )?;
        let event_id = event.event_id.clone();
        self.events.insert(event_id.clone(), event);
        Ok(event_id)
    }

    fn refresh_public_records(&mut self) {
        self.public_records.clear();
        self.public_records
            .insert("config".to_string(), self.config.public_record());
        for intent in self.intents.values() {
            self.public_records.insert(
                format!("intent:{}", intent.intent_id),
                intent.public_record(),
            );
        }
        for bucket in self.buckets.values() {
            self.public_records.insert(
                format!("bucket:{}", bucket.bucket_id),
                bucket.public_record(),
            );
        }
        for window in self.windows.values() {
            self.public_records.insert(
                format!("window:{}", window.window_id),
                window.public_record(),
            );
        }
        for plan in self.stealth_plans.values() {
            self.public_records.insert(
                format!("stealth_plan:{}", plan.plan_id),
                plan.public_record(),
            );
        }
        for maker in self.makers.values() {
            self.public_records
                .insert(format!("maker:{}", maker.maker_id), maker.public_record());
        }
        for assignment in self.assignments.values() {
            self.public_records.insert(
                format!("assignment:{}", assignment.assignment_id),
                assignment.public_record(),
            );
        }
        for rebate in self.rebates.values() {
            self.public_records.insert(
                format!("rebate:{}", rebate.rebate_id),
                rebate.public_record(),
            );
        }
        for signature in self.watchtower_signatures.values() {
            self.public_records.insert(
                format!("watchtower_signature:{}", signature.signature_id),
                signature.public_record(),
            );
        }
        for check in self.reserve_checks.values() {
            self.public_records.insert(
                format!("reserve_check:{}", check.reserve_check_id),
                check.public_record(),
            );
        }
        for reveal in self.reveal_windows.values() {
            self.public_records.insert(
                format!("reveal_window:{}", reveal.reveal_window_id),
                reveal.public_record(),
            );
        }
        for emergency in self.emergency_exits.values() {
            self.public_records.insert(
                format!("emergency_exit:{}", emergency.emergency_exit_id),
                emergency.public_record(),
            );
        }
        for receipt in self.settlement_receipts.values() {
            self.public_records.insert(
                format!("settlement_receipt:{}", receipt.receipt_id),
                receipt.public_record(),
            );
        }
    }
}

pub fn monero_exit_batch_scheduler_intent_id(record: &Value) -> String {
    scheduler_payload_root("MONERO-EXIT-BATCH-SCHEDULER-INTENT-ID", record)
}

pub fn monero_exit_batch_scheduler_bucket_id(record: &Value) -> String {
    scheduler_payload_root("MONERO-EXIT-BATCH-SCHEDULER-BUCKET-ID", record)
}

pub fn monero_exit_batch_scheduler_window_id(record: &Value) -> String {
    scheduler_payload_root("MONERO-EXIT-BATCH-SCHEDULER-WINDOW-ID", record)
}

pub fn monero_exit_batch_scheduler_plan_id(record: &Value) -> String {
    scheduler_payload_root("MONERO-EXIT-BATCH-SCHEDULER-PLAN-ID", record)
}

pub fn monero_exit_batch_scheduler_maker_id(record: &Value) -> String {
    scheduler_payload_root("MONERO-EXIT-BATCH-SCHEDULER-MAKER-ID", record)
}

pub fn monero_exit_batch_scheduler_assignment_id(record: &Value) -> String {
    scheduler_payload_root("MONERO-EXIT-BATCH-SCHEDULER-ASSIGNMENT-ID", record)
}

pub fn monero_exit_batch_scheduler_rebate_id(record: &Value) -> String {
    scheduler_payload_root("MONERO-EXIT-BATCH-SCHEDULER-REBATE-ID", record)
}

pub fn monero_exit_batch_scheduler_watchtower_signature_id(record: &Value) -> String {
    scheduler_payload_root(
        "MONERO-EXIT-BATCH-SCHEDULER-WATCHTOWER-SIGNATURE-ID",
        record,
    )
}

pub fn monero_exit_batch_scheduler_reserve_check_id(record: &Value) -> String {
    scheduler_payload_root("MONERO-EXIT-BATCH-SCHEDULER-RESERVE-CHECK-ID", record)
}

pub fn monero_exit_batch_scheduler_reveal_window_id(record: &Value) -> String {
    scheduler_payload_root("MONERO-EXIT-BATCH-SCHEDULER-REVEAL-WINDOW-ID", record)
}

pub fn monero_exit_batch_scheduler_emergency_exit_id(record: &Value) -> String {
    scheduler_payload_root("MONERO-EXIT-BATCH-SCHEDULER-EMERGENCY-EXIT-ID", record)
}

pub fn monero_exit_batch_scheduler_receipt_id(record: &Value) -> String {
    scheduler_payload_root("MONERO-EXIT-BATCH-SCHEDULER-RECEIPT-ID", record)
}

pub fn monero_exit_batch_scheduler_event_id(record: &Value) -> String {
    scheduler_payload_root("MONERO-EXIT-BATCH-SCHEDULER-EVENT-ID", record)
}

fn scheduler_domain_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    stable_hash_hex(domain, parts, 32)
}

fn scheduler_payload_root(domain: &str, payload: &Value) -> String {
    stable_hash_hex(domain, &[HashPart::Json(payload)], 32)
}

fn typed_record_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn keyed_record_root(domain: &str, records: Vec<(String, Value)>) -> String {
    let leaves = records
        .into_iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn string_set_root(domain: &str, values: Vec<String>) -> String {
    let leaves = values.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn u64_set_root(domain: &str, values: Vec<u64>) -> String {
    let leaves = values
        .into_iter()
        .map(|value| json!(value))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn bucket_amount(amount_units: u64, bucket_units: u64) -> u64 {
    if bucket_units == 0 {
        amount_units
    } else {
        amount_units
            .div_ceil(bucket_units)
            .saturating_mul(bucket_units)
    }
}

fn mul_bps(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / MONERO_EXIT_BATCH_SCHEDULER_MAX_BPS
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroExitBatchSchedulerResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> MoneroExitBatchSchedulerResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_positive_usize(value: usize, label: &str) -> MoneroExitBatchSchedulerResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> MoneroExitBatchSchedulerResult<()> {
    if value > MONERO_EXIT_BATCH_SCHEDULER_MAX_BPS {
        Err(format!("{label} exceeds bps maximum"))
    } else {
        Ok(())
    }
}

fn ensure_expiry(
    start_height: u64,
    expires_at_height: u64,
    label: &str,
) -> MoneroExitBatchSchedulerResult<()> {
    if expires_at_height <= start_height {
        Err(format!("{label} expiry must be after start"))
    } else {
        Ok(())
    }
}

fn with_root_field(mut record: Value, field: &str, root: String) -> Value {
    if let Value::Object(map) = &mut record {
        map.insert(field.to_string(), Value::String(root));
    }
    record
}
