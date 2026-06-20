use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2FastExitExecutionLaneResult<T> = Result<T, String>;

pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-fast-exit-execution-lane-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_FAST_EXIT_EXECUTION_LANE_PROTOCOL_VERSION;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEVNET_HEIGHT: u64 = 128_000;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_EXIT_COMMITMENT_SCHEME: &str =
    "private-monero-fast-exit-request-root-v1";
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_PQ_AUTHORIZATION_SCHEME: &str =
    "pq-fast-exit-authorization-root-v1";
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_LIQUIDITY_COMMITMENT_SCHEME: &str =
    "fast-exit-liquidity-provider-commitment-root-v1";
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_WATCHER_ANCHOR_SCHEME: &str =
    "watcher-pq-anchor-safety-root-v1";
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_PAYOUT_COMMITMENT_SCHEME: &str =
    "monero-payout-commitment-root-v1";
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_LOW_FEE_SPONSOR_SCHEME: &str =
    "low-fee-fast-exit-sponsor-root-v1";
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_SETTLEMENT_RECEIPT_SCHEME: &str =
    "fast-exit-settlement-receipt-root-v1";
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_RESERVE_SAFETY_SCHEME: &str =
    "roots-only-fast-exit-reserve-safety-v1";
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 2_048;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 8_192;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MIN_WATCHER_WEIGHT: u64 = 3;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MIN_WATCHER_COUNT: u64 = 2;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MIN_ANCHOR_DEPTH: u64 = 6;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_FAST_FINALITY_DEPTH: u64 = 6;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_SETTLEMENT_FINALITY_DEPTH: u64 = 12;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_EXECUTION_TTL_BLOCKS: u64 = 32;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 192;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_REPLAY_FENCE_TTL_BLOCKS: u64 = 384;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MAX_OPEN_EXITS: usize = 262_144;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MAX_EXECUTION_SLOTS: usize = 262_144;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MAX_RECEIPTS: usize = 262_144;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MIN_RESERVE_COVER_BPS: u64 = 10_500;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MAX_PROVIDER_EXPOSURE_BPS: u64 = 2_500;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MAX_LANE_EXPOSURE_BPS: u64 = 7_500;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_BASE_FEE_BPS: u64 = 35;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_LOW_FEE_BPS: u64 = 8;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_SPONSOR_REBATE_BPS: u64 = 8_000;
pub const MONERO_L2_FAST_EXIT_EXECUTION_LANE_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitPriority {
    LowFeeSponsored,
    StandardFast,
    EmergencySafety,
}

impl ExitPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFeeSponsored => "low_fee_sponsored",
            Self::StandardFast => "standard_fast",
            Self::EmergencySafety => "emergency_safety",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFeeSponsored => config.low_fee_bps,
            Self::StandardFast | Self::EmergencySafety => config.base_fee_bps,
        }
    }

    pub fn requires_sponsor(self) -> bool {
        matches!(self, Self::LowFeeSponsored)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitStatus {
    Submitted,
    Authorized,
    LiquidityReserved,
    Scheduled,
    Executed,
    SettlementPending,
    Settled,
    Expired,
    Rejected,
}

impl ExitStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Authorized => "authorized",
            Self::LiquidityReserved => "liquidity_reserved",
            Self::Scheduled => "scheduled",
            Self::Executed => "executed",
            Self::SettlementPending => "settlement_pending",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Expired | Self::Rejected)
    }

    pub fn executable(self) -> bool {
        matches!(
            self,
            Self::Authorized | Self::LiquidityReserved | Self::Scheduled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotStatus {
    Reserved,
    Executed,
    SettlementPending,
    Settled,
    Expired,
    Rejected,
}

impl SlotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Executed => "executed",
            Self::SettlementPending => "settlement_pending",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Expired | Self::Rejected)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub exit_commitment_scheme: String,
    pub pq_authorization_scheme: String,
    pub liquidity_commitment_scheme: String,
    pub watcher_anchor_scheme: String,
    pub payout_commitment_scheme: String,
    pub low_fee_sponsor_scheme: String,
    pub settlement_receipt_scheme: String,
    pub reserve_safety_scheme: String,
    pub genesis_height: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_watcher_weight: u64,
    pub min_watcher_count: u64,
    pub min_anchor_depth: u64,
    pub fast_finality_depth: u64,
    pub settlement_finality_depth: u64,
    pub execution_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub replay_fence_ttl_blocks: u64,
    pub max_open_exits: usize,
    pub max_execution_slots: usize,
    pub max_receipts: usize,
    pub min_reserve_cover_bps: u64,
    pub max_provider_exposure_bps: u64,
    pub max_lane_exposure_bps: u64,
    pub base_fee_bps: u64,
    pub low_fee_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub roots_only: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_L2_FAST_EXIT_EXECUTION_LANE_SCHEMA_VERSION,
            monero_network: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEVNET_MONERO_NETWORK.to_string(),
            l2_network: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEVNET_L2_NETWORK.to_string(),
            asset_id: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: MONERO_L2_FAST_EXIT_EXECUTION_LANE_HASH_SUITE.to_string(),
            exit_commitment_scheme: MONERO_L2_FAST_EXIT_EXECUTION_LANE_EXIT_COMMITMENT_SCHEME
                .to_string(),
            pq_authorization_scheme: MONERO_L2_FAST_EXIT_EXECUTION_LANE_PQ_AUTHORIZATION_SCHEME
                .to_string(),
            liquidity_commitment_scheme:
                MONERO_L2_FAST_EXIT_EXECUTION_LANE_LIQUIDITY_COMMITMENT_SCHEME.to_string(),
            watcher_anchor_scheme: MONERO_L2_FAST_EXIT_EXECUTION_LANE_WATCHER_ANCHOR_SCHEME
                .to_string(),
            payout_commitment_scheme: MONERO_L2_FAST_EXIT_EXECUTION_LANE_PAYOUT_COMMITMENT_SCHEME
                .to_string(),
            low_fee_sponsor_scheme: MONERO_L2_FAST_EXIT_EXECUTION_LANE_LOW_FEE_SPONSOR_SCHEME
                .to_string(),
            settlement_receipt_scheme: MONERO_L2_FAST_EXIT_EXECUTION_LANE_SETTLEMENT_RECEIPT_SCHEME
                .to_string(),
            reserve_safety_scheme: MONERO_L2_FAST_EXIT_EXECUTION_LANE_RESERVE_SAFETY_SCHEME
                .to_string(),
            genesis_height: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEVNET_HEIGHT,
            min_privacy_set_size: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size:
                MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_watcher_weight: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MIN_WATCHER_WEIGHT,
            min_watcher_count: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MIN_WATCHER_COUNT,
            min_anchor_depth: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MIN_ANCHOR_DEPTH,
            fast_finality_depth: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_FAST_FINALITY_DEPTH,
            settlement_finality_depth:
                MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_SETTLEMENT_FINALITY_DEPTH,
            execution_ttl_blocks: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_EXECUTION_TTL_BLOCKS,
            settlement_ttl_blocks: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            replay_fence_ttl_blocks:
                MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_REPLAY_FENCE_TTL_BLOCKS,
            max_open_exits: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MAX_OPEN_EXITS,
            max_execution_slots: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MAX_EXECUTION_SLOTS,
            max_receipts: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MAX_RECEIPTS,
            min_reserve_cover_bps: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MIN_RESERVE_COVER_BPS,
            max_provider_exposure_bps:
                MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MAX_PROVIDER_EXPOSURE_BPS,
            max_lane_exposure_bps: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_MAX_LANE_EXPOSURE_BPS,
            base_fee_bps: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_BASE_FEE_BPS,
            low_fee_bps: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_LOW_FEE_BPS,
            sponsor_rebate_bps: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEFAULT_SPONSOR_REBATE_BPS,
            roots_only: true,
        }
    }

    pub fn validate(&self) -> MoneroL2FastExitExecutionLaneResult<()> {
        if self.chain_id != CHAIN_ID {
            return Err("fast exit execution lane chain id mismatch".to_string());
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported fast exit execution lane protocol version".to_string());
        }
        if self.schema_version != MONERO_L2_FAST_EXIT_EXECUTION_LANE_SCHEMA_VERSION {
            return Err("unsupported fast exit execution lane schema version".to_string());
        }
        if !self.roots_only {
            return Err("fast exit execution lane must remain roots-only".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("privacy set configuration is invalid".to_string());
        }
        if self.min_pq_security_bits == 0
            || self.min_watcher_weight == 0
            || self.min_watcher_count == 0
        {
            return Err("fast exit quorum thresholds must be nonzero".to_string());
        }
        if self.min_anchor_depth == 0
            || self.fast_finality_depth == 0
            || self.settlement_finality_depth == 0
            || self.execution_ttl_blocks == 0
            || self.settlement_ttl_blocks == 0
            || self.replay_fence_ttl_blocks == 0
        {
            return Err("fast exit timing thresholds must be nonzero".to_string());
        }
        if self.max_open_exits == 0 || self.max_execution_slots == 0 || self.max_receipts == 0 {
            return Err("fast exit capacities must be nonzero".to_string());
        }
        if self.min_reserve_cover_bps < MONERO_L2_FAST_EXIT_EXECUTION_LANE_MAX_BPS {
            return Err("reserve cover must be at least 100%".to_string());
        }
        if self.max_provider_exposure_bps == 0
            || self.max_provider_exposure_bps > MONERO_L2_FAST_EXIT_EXECUTION_LANE_MAX_BPS
            || self.max_lane_exposure_bps == 0
            || self.max_lane_exposure_bps > MONERO_L2_FAST_EXIT_EXECUTION_LANE_MAX_BPS
            || self.base_fee_bps > MONERO_L2_FAST_EXIT_EXECUTION_LANE_MAX_BPS
            || self.low_fee_bps > self.base_fee_bps
            || self.sponsor_rebate_bps > MONERO_L2_FAST_EXIT_EXECUTION_LANE_MAX_BPS
        {
            return Err("fast exit bps configuration is out of range".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_fast_exit_execution_lane_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "exit_commitment_scheme": self.exit_commitment_scheme,
            "pq_authorization_scheme": self.pq_authorization_scheme,
            "liquidity_commitment_scheme": self.liquidity_commitment_scheme,
            "watcher_anchor_scheme": self.watcher_anchor_scheme,
            "payout_commitment_scheme": self.payout_commitment_scheme,
            "low_fee_sponsor_scheme": self.low_fee_sponsor_scheme,
            "settlement_receipt_scheme": self.settlement_receipt_scheme,
            "reserve_safety_scheme": self.reserve_safety_scheme,
            "genesis_height": self.genesis_height,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_watcher_weight": self.min_watcher_weight,
            "min_watcher_count": self.min_watcher_count,
            "min_anchor_depth": self.min_anchor_depth,
            "fast_finality_depth": self.fast_finality_depth,
            "settlement_finality_depth": self.settlement_finality_depth,
            "execution_ttl_blocks": self.execution_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "replay_fence_ttl_blocks": self.replay_fence_ttl_blocks,
            "max_open_exits": self.max_open_exits,
            "max_execution_slots": self.max_execution_slots,
            "max_receipts": self.max_receipts,
            "min_reserve_cover_bps": self.min_reserve_cover_bps,
            "max_provider_exposure_bps": self.max_provider_exposure_bps,
            "max_lane_exposure_bps": self.max_lane_exposure_bps,
            "base_fee_bps": self.base_fee_bps,
            "low_fee_bps": self.low_fee_bps,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "roots_only": self.roots_only,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-FAST-EXIT-EXECUTION-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub submitted_exits: u64,
    pub authorized_exits: u64,
    pub liquidity_reserved_exits: u64,
    pub scheduled_exits: u64,
    pub executed_slots: u64,
    pub settled_exits: u64,
    pub expired_exits: u64,
    pub rejected_exits: u64,
    pub sponsored_exits: u64,
    pub reserve_rejections: u64,
    pub replay_rejections: u64,
    pub settlement_rejections: u64,
    pub receipts_issued: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_fast_exit_execution_lane_counters",
            "submitted_exits": self.submitted_exits,
            "authorized_exits": self.authorized_exits,
            "liquidity_reserved_exits": self.liquidity_reserved_exits,
            "scheduled_exits": self.scheduled_exits,
            "executed_slots": self.executed_slots,
            "settled_exits": self.settled_exits,
            "expired_exits": self.expired_exits,
            "rejected_exits": self.rejected_exits,
            "sponsored_exits": self.sponsored_exits,
            "reserve_rejections": self.reserve_rejections,
            "replay_rejections": self.replay_rejections,
            "settlement_rejections": self.settlement_rejections,
            "receipts_issued": self.receipts_issued,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitExitRequest {
    pub exit_commitment: String,
    pub private_note_commitment_root: String,
    pub amount_bucket_root: String,
    pub destination_subaddress_root: String,
    pub claimant_set_root: String,
    pub nullifier: String,
    pub replay_fence: String,
    pub pq_authorization_root: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub watcher_anchor_root: String,
    pub watcher_weight: u64,
    pub watcher_count: u64,
    pub liquidity_provider_id: String,
    pub liquidity_commitment_root: String,
    pub provider_reserve_root: String,
    pub provider_available_liquidity: u64,
    pub lane_total_reserve: u64,
    pub lane_locked_liquidity: u64,
    pub amount_bucket_upper_bound: u64,
    pub max_fee_bps: u64,
    pub priority: ExitPriority,
    pub low_fee_sponsor_root: Option<String>,
    pub sponsor_fee_budget: u64,
    pub privacy_set_size: u64,
    pub l2_burn_height: u64,
    pub observed_monero_height: u64,
    pub submitted_at_height: u64,
    pub request_nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecuteSlotRequest {
    pub exit_id: String,
    pub executor_id: String,
    pub execution_height: u64,
    pub monero_observed_height: u64,
    pub execution_batch_root: String,
    pub payout_commitment_root: String,
    pub payout_address_commitment_root: String,
    pub payout_amount_bucket_root: String,
    pub liquidity_release_root: String,
    pub reserve_safety_root: String,
    pub watcher_anchor_root: String,
    pub watcher_weight: u64,
    pub watcher_count: u64,
    pub pq_authorization_root: String,
    pub pq_signature_root: String,
    pub low_fee_sponsor_root: Option<String>,
    pub fee_commitment_root: String,
    pub execution_nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleExitRequest {
    pub exit_id: String,
    pub slot_id: String,
    pub settlement_height: u64,
    pub settled_monero_height: u64,
    pub settlement_tx_root: String,
    pub settlement_batch_root: String,
    pub settlement_receipt_root: String,
    pub payout_confirmation_root: String,
    pub reserve_release_root: String,
    pub pq_settlement_root: String,
    pub watcher_settlement_root: String,
    pub settlement_nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateExitRequest {
    pub exit_id: String,
    pub sequence: u64,
    pub status: ExitStatus,
    pub exit_commitment: String,
    pub private_note_commitment_root: String,
    pub amount_bucket_root: String,
    pub destination_subaddress_root: String,
    pub claimant_set_root: String,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub pq_authorization_root: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub watcher_anchor_root: String,
    pub watcher_weight: u64,
    pub watcher_count: u64,
    pub liquidity_provider_id: String,
    pub liquidity_commitment_root: String,
    pub provider_reserve_root: String,
    pub provider_available_liquidity: u64,
    pub lane_total_reserve: u64,
    pub lane_locked_liquidity: u64,
    pub amount_bucket_upper_bound: u64,
    pub max_fee_bps: u64,
    pub charged_fee_bps: u64,
    pub priority: ExitPriority,
    pub low_fee_sponsor_root: String,
    pub sponsor_fee_budget: u64,
    pub privacy_set_size: u64,
    pub l2_burn_height: u64,
    pub observed_monero_height: u64,
    pub submitted_at_height: u64,
    pub updated_at_height: u64,
    pub execution_deadline_height: u64,
    pub settlement_deadline_height: u64,
    pub request_nonce_root: String,
    pub slot_id: Option<String>,
    pub receipt_id: Option<String>,
}

impl PrivateExitRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_fast_exit_private_request",
            "exit_id": self.exit_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "exit_commitment": self.exit_commitment,
            "private_note_commitment_root": self.private_note_commitment_root,
            "amount_bucket_root": self.amount_bucket_root,
            "destination_subaddress_root": self.destination_subaddress_root,
            "claimant_set_root": self.claimant_set_root,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "pq_authorization_root": self.pq_authorization_root,
            "pq_signature_root": self.pq_signature_root,
            "pq_security_bits": self.pq_security_bits,
            "watcher_anchor_root": self.watcher_anchor_root,
            "watcher_weight": self.watcher_weight,
            "watcher_count": self.watcher_count,
            "liquidity_provider_id": self.liquidity_provider_id,
            "liquidity_commitment_root": self.liquidity_commitment_root,
            "provider_reserve_root": self.provider_reserve_root,
            "provider_available_liquidity": self.provider_available_liquidity,
            "lane_total_reserve": self.lane_total_reserve,
            "lane_locked_liquidity": self.lane_locked_liquidity,
            "amount_bucket_upper_bound": self.amount_bucket_upper_bound,
            "max_fee_bps": self.max_fee_bps,
            "charged_fee_bps": self.charged_fee_bps,
            "priority": self.priority.as_str(),
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "sponsor_fee_budget": self.sponsor_fee_budget,
            "privacy_set_size": self.privacy_set_size,
            "l2_burn_height": self.l2_burn_height,
            "observed_monero_height": self.observed_monero_height,
            "submitted_at_height": self.submitted_at_height,
            "updated_at_height": self.updated_at_height,
            "execution_deadline_height": self.execution_deadline_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "request_nonce_root": self.request_nonce_root,
            "slot_id": self.slot_id,
            "receipt_id": self.receipt_id,
        })
    }

    pub fn root(&self) -> String {
        lane_root("MONERO-L2-FAST-EXIT-REQUEST", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionSlot {
    pub slot_id: String,
    pub exit_id: String,
    pub sequence: u64,
    pub status: SlotStatus,
    pub executor_id: String,
    pub execution_height: u64,
    pub monero_observed_height: u64,
    pub execution_batch_root: String,
    pub payout_commitment_root: String,
    pub payout_address_commitment_root: String,
    pub payout_amount_bucket_root: String,
    pub liquidity_release_root: String,
    pub reserve_safety_root: String,
    pub watcher_anchor_root: String,
    pub watcher_weight: u64,
    pub watcher_count: u64,
    pub pq_authorization_root: String,
    pub pq_signature_root: String,
    pub low_fee_sponsor_root: String,
    pub fee_commitment_root: String,
    pub execution_nonce_root: String,
    pub settlement_deadline_height: u64,
    pub receipt_id: Option<String>,
}

impl ExecutionSlot {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_fast_exit_execution_slot",
            "slot_id": self.slot_id,
            "exit_id": self.exit_id,
            "sequence": self.sequence,
            "status": self.status.as_str(),
            "executor_id": self.executor_id,
            "execution_height": self.execution_height,
            "monero_observed_height": self.monero_observed_height,
            "execution_batch_root": self.execution_batch_root,
            "payout_commitment_root": self.payout_commitment_root,
            "payout_address_commitment_root": self.payout_address_commitment_root,
            "payout_amount_bucket_root": self.payout_amount_bucket_root,
            "liquidity_release_root": self.liquidity_release_root,
            "reserve_safety_root": self.reserve_safety_root,
            "watcher_anchor_root": self.watcher_anchor_root,
            "watcher_weight": self.watcher_weight,
            "watcher_count": self.watcher_count,
            "pq_authorization_root": self.pq_authorization_root,
            "pq_signature_root": self.pq_signature_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "fee_commitment_root": self.fee_commitment_root,
            "execution_nonce_root": self.execution_nonce_root,
            "settlement_deadline_height": self.settlement_deadline_height,
            "receipt_id": self.receipt_id,
        })
    }

    pub fn root(&self) -> String {
        lane_root("MONERO-L2-FAST-EXIT-EXECUTION-SLOT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub exit_id: String,
    pub slot_id: String,
    pub sequence: u64,
    pub settlement_height: u64,
    pub settled_monero_height: u64,
    pub settlement_tx_root: String,
    pub settlement_batch_root: String,
    pub settlement_receipt_root: String,
    pub payout_confirmation_root: String,
    pub reserve_release_root: String,
    pub pq_settlement_root: String,
    pub watcher_settlement_root: String,
    pub settlement_nonce_root: String,
    pub final_exit_root: String,
    pub final_slot_root: String,
}

impl SettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_fast_exit_settlement_receipt",
            "receipt_id": self.receipt_id,
            "exit_id": self.exit_id,
            "slot_id": self.slot_id,
            "sequence": self.sequence,
            "settlement_height": self.settlement_height,
            "settled_monero_height": self.settled_monero_height,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_batch_root": self.settlement_batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "payout_confirmation_root": self.payout_confirmation_root,
            "reserve_release_root": self.reserve_release_root,
            "pq_settlement_root": self.pq_settlement_root,
            "watcher_settlement_root": self.watcher_settlement_root,
            "settlement_nonce_root": self.settlement_nonce_root,
            "final_exit_root": self.final_exit_root,
            "final_slot_root": self.final_slot_root,
        })
    }

    pub fn root(&self) -> String {
        lane_root(
            "MONERO-L2-FAST-EXIT-SETTLEMENT-RECEIPT",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayFence {
    pub fence_id: String,
    pub exit_id: String,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub consumed_at_height: Option<u64>,
}

impl ReplayFence {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_fast_exit_replay_fence",
            "fence_id": self.fence_id,
            "exit_id": self.exit_id,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "consumed_at_height": self.consumed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityProviderCommitment {
    pub provider_id: String,
    pub commitment_root: String,
    pub reserve_root: String,
    pub committed_upper_bound: u64,
    pub locked_upper_bound: u64,
    pub executed_upper_bound: u64,
    pub settled_upper_bound: u64,
    pub latest_exit_id: String,
    pub latest_slot_id: String,
    pub latest_updated_height: u64,
}

impl LiquidityProviderCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_fast_exit_liquidity_provider_commitment",
            "provider_id": self.provider_id,
            "commitment_root": self.commitment_root,
            "reserve_root": self.reserve_root,
            "committed_upper_bound": self.committed_upper_bound,
            "locked_upper_bound": self.locked_upper_bound,
            "executed_upper_bound": self.executed_upper_bound,
            "settled_upper_bound": self.settled_upper_bound,
            "latest_exit_id": self.latest_exit_id,
            "latest_slot_id": self.latest_slot_id,
            "latest_updated_height": self.latest_updated_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveSafetySnapshot {
    pub snapshot_id: String,
    pub exit_id: String,
    pub provider_id: String,
    pub amount_bucket_upper_bound: u64,
    pub provider_available_liquidity: u64,
    pub lane_total_reserve: u64,
    pub lane_locked_liquidity: u64,
    pub required_provider_cover: u64,
    pub required_lane_cover: u64,
    pub provider_exposure_bps: u64,
    pub lane_exposure_bps: u64,
    pub reserve_safety_root: String,
    pub accepted: bool,
    pub created_at_height: u64,
}

impl ReserveSafetySnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_fast_exit_reserve_safety_snapshot",
            "snapshot_id": self.snapshot_id,
            "exit_id": self.exit_id,
            "provider_id": self.provider_id,
            "amount_bucket_upper_bound": self.amount_bucket_upper_bound,
            "provider_available_liquidity": self.provider_available_liquidity,
            "lane_total_reserve": self.lane_total_reserve,
            "lane_locked_liquidity": self.lane_locked_liquidity,
            "required_provider_cover": self.required_provider_cover,
            "required_lane_cover": self.required_lane_cover,
            "provider_exposure_bps": self.provider_exposure_bps,
            "lane_exposure_bps": self.lane_exposure_bps,
            "reserve_safety_root": self.reserve_safety_root,
            "accepted": self.accepted,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneRoots {
    pub config_root: String,
    pub request_root: String,
    pub open_request_root: String,
    pub slot_root: String,
    pub executed_slot_root: String,
    pub payout_commitment_root: String,
    pub pq_authorization_root: String,
    pub liquidity_commitment_root: String,
    pub watcher_anchor_root: String,
    pub low_fee_sponsor_root: String,
    pub settlement_receipt_root: String,
    pub reserve_safety_root: String,
    pub nullifier_root: String,
    pub replay_fence_root: String,
    pub provider_root: String,
    pub event_root: String,
    pub counter_root: String,
    pub state_root: String,
}

impl LaneRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_fast_exit_execution_lane_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config_root": self.config_root,
            "request_root": self.request_root,
            "open_request_root": self.open_request_root,
            "slot_root": self.slot_root,
            "executed_slot_root": self.executed_slot_root,
            "payout_commitment_root": self.payout_commitment_root,
            "pq_authorization_root": self.pq_authorization_root,
            "liquidity_commitment_root": self.liquidity_commitment_root,
            "watcher_anchor_root": self.watcher_anchor_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "reserve_safety_root": self.reserve_safety_root,
            "nullifier_root": self.nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "provider_root": self.provider_root,
            "event_root": self.event_root,
            "counter_root": self.counter_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub exits: BTreeMap<String, PrivateExitRequest>,
    pub slots: BTreeMap<String, ExecutionSlot>,
    pub receipts: BTreeMap<String, SettlementReceipt>,
    pub replay_fences: BTreeMap<String, ReplayFence>,
    pub providers: BTreeMap<String, LiquidityProviderCommitment>,
    pub reserve_snapshots: BTreeMap<String, ReserveSafetySnapshot>,
    pub nullifier_index: BTreeSet<String>,
    pub slot_by_exit: BTreeMap<String, String>,
    pub receipt_by_exit: BTreeMap<String, String>,
    pub events: Vec<Value>,
    pub counters: Counters,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            height: MONERO_L2_FAST_EXIT_EXECUTION_LANE_DEVNET_HEIGHT,
            exits: BTreeMap::new(),
            slots: BTreeMap::new(),
            receipts: BTreeMap::new(),
            replay_fences: BTreeMap::new(),
            providers: BTreeMap::new(),
            reserve_snapshots: BTreeMap::new(),
            nullifier_index: BTreeSet::new(),
            slot_by_exit: BTreeMap::new(),
            receipt_by_exit: BTreeMap::new(),
            events: Vec::new(),
            counters: Counters::default(),
        }
    }

    pub fn new(config: Config, height: u64) -> MoneroL2FastExitExecutionLaneResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            exits: BTreeMap::new(),
            slots: BTreeMap::new(),
            receipts: BTreeMap::new(),
            replay_fences: BTreeMap::new(),
            providers: BTreeMap::new(),
            reserve_snapshots: BTreeMap::new(),
            nullifier_index: BTreeSet::new(),
            slot_by_exit: BTreeMap::new(),
            receipt_by_exit: BTreeMap::new(),
            events: Vec::new(),
            counters: Counters::default(),
        })
    }

    pub fn submit_exit(
        &mut self,
        request: SubmitExitRequest,
    ) -> MoneroL2FastExitExecutionLaneResult<PrivateExitRequest> {
        self.config.validate()?;
        self.validate_submit_request(&request)?;
        self.expire_stale(request.submitted_at_height);

        let nullifier_root = private_root("MONERO-L2-FAST-EXIT-NULLIFIER", &request.nullifier);
        let replay_fence_root =
            private_root("MONERO-L2-FAST-EXIT-REPLAY-FENCE", &request.replay_fence);
        if self.nullifier_index.contains(&nullifier_root) {
            self.counters.replay_rejections = self.counters.replay_rejections.saturating_add(1);
            return Err("fast exit nullifier has already been submitted".to_string());
        }
        if self
            .replay_fences
            .values()
            .any(|fence| fence.replay_fence_root == replay_fence_root)
        {
            self.counters.replay_rejections = self.counters.replay_rejections.saturating_add(1);
            return Err("fast exit replay fence has already been submitted".to_string());
        }

        let sequence = self.counters.submitted_exits.saturating_add(1);
        let charged_fee_bps = request.priority.fee_bps(&self.config);
        if charged_fee_bps > request.max_fee_bps {
            return Err("fast exit fee exceeds request cap".to_string());
        }

        let exit_id = exit_id(
            sequence,
            &request.exit_commitment,
            &nullifier_root,
            &replay_fence_root,
            request.priority,
            request.submitted_at_height,
            &request.request_nonce,
        );
        let reserve_snapshot = self.reserve_snapshot_for_submit(&exit_id, &request)?;
        if !reserve_snapshot.accepted {
            self.counters.reserve_rejections = self.counters.reserve_rejections.saturating_add(1);
            self.reserve_snapshots
                .insert(reserve_snapshot.snapshot_id.clone(), reserve_snapshot);
            return Err("fast exit reserve safety check failed".to_string());
        }

        let low_fee_sponsor_root = request
            .low_fee_sponsor_root
            .clone()
            .unwrap_or_else(empty_low_fee_sponsor_root);
        let status = if request.watcher_weight >= self.config.min_watcher_weight
            && request.watcher_count >= self.config.min_watcher_count
        {
            ExitStatus::LiquidityReserved
        } else {
            ExitStatus::Submitted
        };
        let exit = PrivateExitRequest {
            exit_id: exit_id.clone(),
            sequence,
            status,
            exit_commitment: request.exit_commitment,
            private_note_commitment_root: request.private_note_commitment_root,
            amount_bucket_root: request.amount_bucket_root,
            destination_subaddress_root: request.destination_subaddress_root,
            claimant_set_root: request.claimant_set_root,
            nullifier_root: nullifier_root.clone(),
            replay_fence_root: replay_fence_root.clone(),
            pq_authorization_root: request.pq_authorization_root,
            pq_signature_root: request.pq_signature_root,
            pq_security_bits: request.pq_security_bits,
            watcher_anchor_root: request.watcher_anchor_root,
            watcher_weight: request.watcher_weight,
            watcher_count: request.watcher_count,
            liquidity_provider_id: request.liquidity_provider_id,
            liquidity_commitment_root: request.liquidity_commitment_root,
            provider_reserve_root: request.provider_reserve_root,
            provider_available_liquidity: request.provider_available_liquidity,
            lane_total_reserve: request.lane_total_reserve,
            lane_locked_liquidity: request.lane_locked_liquidity,
            amount_bucket_upper_bound: request.amount_bucket_upper_bound,
            max_fee_bps: request.max_fee_bps,
            charged_fee_bps,
            priority: request.priority,
            low_fee_sponsor_root,
            sponsor_fee_budget: request.sponsor_fee_budget,
            privacy_set_size: request.privacy_set_size,
            l2_burn_height: request.l2_burn_height,
            observed_monero_height: request.observed_monero_height,
            submitted_at_height: request.submitted_at_height,
            updated_at_height: request.submitted_at_height,
            execution_deadline_height: request
                .submitted_at_height
                .saturating_add(self.config.execution_ttl_blocks),
            settlement_deadline_height: request
                .submitted_at_height
                .saturating_add(self.config.settlement_ttl_blocks),
            request_nonce_root: private_root(
                "MONERO-L2-FAST-EXIT-REQUEST-NONCE",
                &request.request_nonce,
            ),
            slot_id: None,
            receipt_id: None,
        };
        let fence_id = replay_fence_id(&exit_id, &nullifier_root, &replay_fence_root);
        let fence = ReplayFence {
            fence_id: fence_id.clone(),
            exit_id: exit_id.clone(),
            nullifier_root: nullifier_root.clone(),
            replay_fence_root,
            opened_at_height: exit.submitted_at_height,
            expires_at_height: exit
                .submitted_at_height
                .saturating_add(self.config.replay_fence_ttl_blocks),
            consumed_at_height: None,
        };

        self.upsert_provider_for_submit(&exit);
        self.nullifier_index.insert(nullifier_root);
        self.replay_fences.insert(fence_id, fence);
        self.reserve_snapshots
            .insert(reserve_snapshot.snapshot_id.clone(), reserve_snapshot);
        self.exits.insert(exit_id.clone(), exit.clone());
        self.counters.submitted_exits = sequence;
        if exit.status == ExitStatus::LiquidityReserved {
            self.counters.authorized_exits = self.counters.authorized_exits.saturating_add(1);
            self.counters.liquidity_reserved_exits =
                self.counters.liquidity_reserved_exits.saturating_add(1);
        }
        if exit.priority == ExitPriority::LowFeeSponsored {
            self.counters.sponsored_exits = self.counters.sponsored_exits.saturating_add(1);
        }
        self.height = self.height.max(exit.submitted_at_height);
        self.push_event(
            "fast_exit_submitted",
            exit.submitted_at_height,
            json!({
                "exit_id": exit.exit_id,
                "status": exit.status.as_str(),
                "priority": exit.priority.as_str(),
                "exit_root": exit.root(),
            }),
        );
        Ok(exit)
    }

    pub fn execute_slot(
        &mut self,
        request: ExecuteSlotRequest,
    ) -> MoneroL2FastExitExecutionLaneResult<ExecutionSlot> {
        self.config.validate()?;
        self.validate_execute_request(&request)?;
        self.expire_stale(request.execution_height);
        if self.slots.len() >= self.config.max_execution_slots {
            return Err("fast exit execution slot capacity reached".to_string());
        }
        if self.slot_by_exit.contains_key(&request.exit_id) {
            return Err("fast exit already has an execution slot".to_string());
        }
        let mut exit = self
            .exits
            .get(&request.exit_id)
            .cloned()
            .ok_or_else(|| format!("unknown fast exit {}", request.exit_id))?;
        if !exit.status.executable() {
            return Err("fast exit is not executable".to_string());
        }
        if request.execution_height < exit.submitted_at_height {
            return Err("fast exit execution height precedes submission".to_string());
        }
        if request.execution_height > exit.execution_deadline_height {
            exit.status = ExitStatus::Expired;
            exit.updated_at_height = request.execution_height;
            self.exits.insert(exit.exit_id.clone(), exit);
            self.counters.expired_exits = self.counters.expired_exits.saturating_add(1);
            return Err("fast exit execution deadline has expired".to_string());
        }
        if request
            .monero_observed_height
            .saturating_sub(exit.l2_burn_height)
            < self.config.fast_finality_depth
        {
            return Err("fast exit lacks required fast finality depth".to_string());
        }
        if request.pq_authorization_root != exit.pq_authorization_root {
            return Err("fast exit pq authorization root mismatch".to_string());
        }
        if request.watcher_weight < self.config.min_watcher_weight
            || request.watcher_count < self.config.min_watcher_count
        {
            return Err("fast exit execution lacks watcher quorum".to_string());
        }
        let expected_sponsor_root = exit.low_fee_sponsor_root.clone();
        let slot_sponsor_root = request
            .low_fee_sponsor_root
            .clone()
            .unwrap_or_else(empty_low_fee_sponsor_root);
        if expected_sponsor_root != slot_sponsor_root {
            return Err("fast exit low-fee sponsor root mismatch".to_string());
        }

        let sequence = self.counters.executed_slots.saturating_add(1);
        let slot_id = execution_slot_id(
            sequence,
            &exit.exit_id,
            &request.execution_batch_root,
            &request.payout_commitment_root,
            request.execution_height,
            &request.execution_nonce,
        );
        let slot = ExecutionSlot {
            slot_id: slot_id.clone(),
            exit_id: exit.exit_id.clone(),
            sequence,
            status: SlotStatus::SettlementPending,
            executor_id: request.executor_id,
            execution_height: request.execution_height,
            monero_observed_height: request.monero_observed_height,
            execution_batch_root: request.execution_batch_root,
            payout_commitment_root: request.payout_commitment_root,
            payout_address_commitment_root: request.payout_address_commitment_root,
            payout_amount_bucket_root: request.payout_amount_bucket_root,
            liquidity_release_root: request.liquidity_release_root,
            reserve_safety_root: request.reserve_safety_root,
            watcher_anchor_root: request.watcher_anchor_root,
            watcher_weight: request.watcher_weight,
            watcher_count: request.watcher_count,
            pq_authorization_root: request.pq_authorization_root,
            pq_signature_root: request.pq_signature_root,
            low_fee_sponsor_root: slot_sponsor_root,
            fee_commitment_root: request.fee_commitment_root,
            execution_nonce_root: private_root(
                "MONERO-L2-FAST-EXIT-EXECUTION-NONCE",
                &request.execution_nonce,
            ),
            settlement_deadline_height: exit.settlement_deadline_height,
            receipt_id: None,
        };
        exit.status = ExitStatus::SettlementPending;
        exit.updated_at_height = slot.execution_height;
        exit.observed_monero_height = exit.observed_monero_height.max(slot.monero_observed_height);
        exit.slot_id = Some(slot_id.clone());
        self.upsert_provider_for_execution(&exit, &slot);
        self.slot_by_exit
            .insert(exit.exit_id.clone(), slot_id.clone());
        self.slots.insert(slot_id.clone(), slot.clone());
        self.exits.insert(exit.exit_id.clone(), exit.clone());
        self.counters.executed_slots = sequence;
        self.counters.scheduled_exits = self.counters.scheduled_exits.saturating_add(1);
        self.height = self.height.max(slot.execution_height);
        self.push_event(
            "fast_exit_executed",
            slot.execution_height,
            json!({
                "exit_id": exit.exit_id,
                "slot_id": slot.slot_id,
                "slot_root": slot.root(),
            }),
        );
        Ok(slot)
    }

    pub fn settle_exit(
        &mut self,
        request: SettleExitRequest,
    ) -> MoneroL2FastExitExecutionLaneResult<SettlementReceipt> {
        self.config.validate()?;
        self.validate_settle_request(&request)?;
        self.expire_stale(request.settlement_height);
        if self.receipts.len() >= self.config.max_receipts {
            return Err("fast exit settlement receipt capacity reached".to_string());
        }
        if self.receipt_by_exit.contains_key(&request.exit_id) {
            return Err("fast exit already settled".to_string());
        }
        let mut exit = self
            .exits
            .get(&request.exit_id)
            .cloned()
            .ok_or_else(|| format!("unknown fast exit {}", request.exit_id))?;
        let mut slot = self
            .slots
            .get(&request.slot_id)
            .cloned()
            .ok_or_else(|| format!("unknown fast exit slot {}", request.slot_id))?;
        if slot.exit_id != exit.exit_id {
            self.counters.settlement_rejections =
                self.counters.settlement_rejections.saturating_add(1);
            return Err("fast exit settlement slot mismatch".to_string());
        }
        if exit.status != ExitStatus::SettlementPending
            || slot.status != SlotStatus::SettlementPending
        {
            self.counters.settlement_rejections =
                self.counters.settlement_rejections.saturating_add(1);
            return Err("fast exit is not pending settlement".to_string());
        }
        if request.settlement_height < slot.execution_height {
            return Err("fast exit settlement height precedes execution".to_string());
        }
        if request.settlement_height > exit.settlement_deadline_height {
            exit.status = ExitStatus::Expired;
            slot.status = SlotStatus::Expired;
            exit.updated_at_height = request.settlement_height;
            self.exits.insert(exit.exit_id.clone(), exit);
            self.slots.insert(slot.slot_id.clone(), slot);
            self.counters.expired_exits = self.counters.expired_exits.saturating_add(1);
            return Err("fast exit settlement deadline has expired".to_string());
        }
        if request.settled_monero_height < slot.monero_observed_height {
            return Err("settled monero height cannot precede executed observation".to_string());
        }
        if request
            .settled_monero_height
            .saturating_sub(exit.l2_burn_height)
            < self.config.settlement_finality_depth
        {
            return Err("fast exit settlement lacks finality depth".to_string());
        }

        exit.status = ExitStatus::Settled;
        exit.updated_at_height = request.settlement_height;
        slot.status = SlotStatus::Settled;
        let final_exit_root = exit.root();
        let final_slot_root = slot.root();
        let sequence = self.counters.receipts_issued.saturating_add(1);
        let receipt_id = settlement_receipt_id(
            sequence,
            &exit.exit_id,
            &slot.slot_id,
            &request.settlement_receipt_root,
            &request.settlement_nonce,
        );
        let receipt = SettlementReceipt {
            receipt_id: receipt_id.clone(),
            exit_id: exit.exit_id.clone(),
            slot_id: slot.slot_id.clone(),
            sequence,
            settlement_height: request.settlement_height,
            settled_monero_height: request.settled_monero_height,
            settlement_tx_root: request.settlement_tx_root,
            settlement_batch_root: request.settlement_batch_root,
            settlement_receipt_root: request.settlement_receipt_root,
            payout_confirmation_root: request.payout_confirmation_root,
            reserve_release_root: request.reserve_release_root,
            pq_settlement_root: request.pq_settlement_root,
            watcher_settlement_root: request.watcher_settlement_root,
            settlement_nonce_root: private_root(
                "MONERO-L2-FAST-EXIT-SETTLEMENT-NONCE",
                &request.settlement_nonce,
            ),
            final_exit_root,
            final_slot_root,
        };
        exit.receipt_id = Some(receipt_id.clone());
        slot.receipt_id = Some(receipt_id.clone());
        self.mark_replay_fence_consumed(&exit.exit_id, request.settlement_height);
        self.upsert_provider_for_settlement(&exit, &slot);
        self.receipt_by_exit
            .insert(exit.exit_id.clone(), receipt_id.clone());
        self.receipts.insert(receipt_id.clone(), receipt.clone());
        self.exits.insert(exit.exit_id.clone(), exit.clone());
        self.slots.insert(slot.slot_id.clone(), slot.clone());
        self.counters.receipts_issued = sequence;
        self.counters.settled_exits = self.counters.settled_exits.saturating_add(1);
        self.height = self.height.max(receipt.settlement_height);
        self.push_event(
            "fast_exit_settled",
            receipt.settlement_height,
            json!({
                "exit_id": exit.exit_id,
                "slot_id": slot.slot_id,
                "receipt_id": receipt.receipt_id,
                "receipt_root": receipt.root(),
            }),
        );
        Ok(receipt)
    }

    pub fn roots(&self) -> LaneRoots {
        let request_records = map_records(&self.exits, PrivateExitRequest::public_record);
        let open_request_records = self
            .exits
            .values()
            .filter(|exit| !exit.status.terminal())
            .map(PrivateExitRequest::public_record)
            .collect::<Vec<_>>();
        let slot_records = map_records(&self.slots, ExecutionSlot::public_record);
        let executed_slot_records = self
            .slots
            .values()
            .filter(|slot| {
                matches!(
                    slot.status,
                    SlotStatus::SettlementPending | SlotStatus::Settled
                )
            })
            .map(ExecutionSlot::public_record)
            .collect::<Vec<_>>();
        let payout_roots = self
            .slots
            .values()
            .map(|slot| slot.payout_commitment_root.clone())
            .collect::<Vec<_>>();
        let pq_roots = self
            .exits
            .values()
            .map(|exit| exit.pq_authorization_root.clone())
            .chain(
                self.slots
                    .values()
                    .map(|slot| slot.pq_authorization_root.clone()),
            )
            .collect::<Vec<_>>();
        let liquidity_roots = self
            .exits
            .values()
            .map(|exit| exit.liquidity_commitment_root.clone())
            .collect::<Vec<_>>();
        let watcher_roots = self
            .exits
            .values()
            .map(|exit| exit.watcher_anchor_root.clone())
            .chain(
                self.slots
                    .values()
                    .map(|slot| slot.watcher_anchor_root.clone()),
            )
            .collect::<Vec<_>>();
        let sponsor_roots = self
            .exits
            .values()
            .map(|exit| exit.low_fee_sponsor_root.clone())
            .collect::<Vec<_>>();
        let reserve_records = map_records(
            &self.reserve_snapshots,
            ReserveSafetySnapshot::public_record,
        );
        let receipt_records = map_records(&self.receipts, SettlementReceipt::public_record);
        let replay_records = map_records(&self.replay_fences, ReplayFence::public_record);
        let provider_records =
            map_records(&self.providers, LiquidityProviderCommitment::public_record);
        let config_root = self.config.root();
        let request_root = merkle_root("MONERO-L2-FAST-EXIT-REQUESTS", &request_records);
        let open_request_root =
            merkle_root("MONERO-L2-FAST-EXIT-OPEN-REQUESTS", &open_request_records);
        let slot_root = merkle_root("MONERO-L2-FAST-EXIT-SLOTS", &slot_records);
        let executed_slot_root =
            merkle_root("MONERO-L2-FAST-EXIT-EXECUTED-SLOTS", &executed_slot_records);
        let payout_commitment_root =
            merkle_string_root("MONERO-L2-FAST-EXIT-PAYOUT-COMMITMENT-ROOTS", payout_roots);
        let pq_authorization_root =
            merkle_string_root("MONERO-L2-FAST-EXIT-PQ-AUTHORIZATION-ROOTS", pq_roots);
        let liquidity_commitment_root = merkle_string_root(
            "MONERO-L2-FAST-EXIT-LIQUIDITY-COMMITMENT-ROOTS",
            liquidity_roots,
        );
        let watcher_anchor_root =
            merkle_string_root("MONERO-L2-FAST-EXIT-WATCHER-ANCHOR-ROOTS", watcher_roots);
        let low_fee_sponsor_root =
            merkle_string_root("MONERO-L2-FAST-EXIT-LOW-FEE-SPONSOR-ROOTS", sponsor_roots);
        let settlement_receipt_root =
            merkle_root("MONERO-L2-FAST-EXIT-SETTLEMENT-RECEIPTS", &receipt_records);
        let reserve_safety_root =
            merkle_root("MONERO-L2-FAST-EXIT-RESERVE-SAFETY", &reserve_records);
        let nullifier_root = merkle_string_root(
            "MONERO-L2-FAST-EXIT-NULLIFIERS",
            self.nullifier_index.iter().cloned().collect(),
        );
        let replay_fence_root = merkle_root("MONERO-L2-FAST-EXIT-REPLAY-FENCES", &replay_records);
        let provider_root = merkle_root("MONERO-L2-FAST-EXIT-PROVIDERS", &provider_records);
        let event_root = merkle_root("MONERO-L2-FAST-EXIT-EVENTS", &self.events);
        let counter_root = lane_root(
            "MONERO-L2-FAST-EXIT-COUNTERS",
            &self.counters.public_record(),
        );
        let state_record = json!({
            "kind": "monero_l2_fast_exit_execution_lane_state_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "config_root": config_root,
            "request_root": request_root,
            "open_request_root": open_request_root,
            "slot_root": slot_root,
            "executed_slot_root": executed_slot_root,
            "payout_commitment_root": payout_commitment_root,
            "pq_authorization_root": pq_authorization_root,
            "liquidity_commitment_root": liquidity_commitment_root,
            "watcher_anchor_root": watcher_anchor_root,
            "low_fee_sponsor_root": low_fee_sponsor_root,
            "settlement_receipt_root": settlement_receipt_root,
            "reserve_safety_root": reserve_safety_root,
            "nullifier_root": nullifier_root,
            "replay_fence_root": replay_fence_root,
            "provider_root": provider_root,
            "event_root": event_root,
            "counter_root": counter_root,
        });
        let state_root = lane_root("MONERO-L2-FAST-EXIT-STATE", &state_record);
        LaneRoots {
            config_root,
            request_root,
            open_request_root,
            slot_root,
            executed_slot_root,
            payout_commitment_root,
            pq_authorization_root,
            liquidity_commitment_root,
            watcher_anchor_root,
            low_fee_sponsor_root,
            settlement_receipt_root,
            reserve_safety_root,
            nullifier_root,
            replay_fence_root,
            provider_root,
            event_root,
            counter_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "monero_l2_fast_exit_execution_lane_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": MONERO_L2_FAST_EXIT_EXECUTION_LANE_SCHEMA_VERSION,
            "privacy_boundary": "roots_only_no_plaintext_monero_addresses_no_amounts_no_view_keys",
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters.public_record(),
            "exit_count": self.exits.len(),
            "slot_count": self.slots.len(),
            "receipt_count": self.receipts.len(),
            "provider_count": self.providers.len(),
            "reserve_snapshot_count": self.reserve_snapshots.len(),
            "replay_fence_count": self.replay_fences.len(),
            "exits": map_records(&self.exits, PrivateExitRequest::public_record),
            "slots": map_records(&self.slots, ExecutionSlot::public_record),
            "receipts": map_records(&self.receipts, SettlementReceipt::public_record),
            "providers": map_records(&self.providers, LiquidityProviderCommitment::public_record),
            "reserve_snapshots": map_records(
                &self.reserve_snapshots,
                ReserveSafetySnapshot::public_record,
            ),
            "replay_fences": map_records(&self.replay_fences, ReplayFence::public_record),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn validate_submit_request(
        &self,
        request: &SubmitExitRequest,
    ) -> MoneroL2FastExitExecutionLaneResult<()> {
        if self
            .exits
            .values()
            .filter(|exit| !exit.status.terminal())
            .count()
            >= self.config.max_open_exits
        {
            return Err("fast exit open request capacity reached".to_string());
        }
        validate_root("exit_commitment", &request.exit_commitment)?;
        validate_root(
            "private_note_commitment_root",
            &request.private_note_commitment_root,
        )?;
        validate_root("amount_bucket_root", &request.amount_bucket_root)?;
        validate_root(
            "destination_subaddress_root",
            &request.destination_subaddress_root,
        )?;
        validate_root("claimant_set_root", &request.claimant_set_root)?;
        validate_secret("nullifier", &request.nullifier)?;
        validate_secret("replay_fence", &request.replay_fence)?;
        validate_root("pq_authorization_root", &request.pq_authorization_root)?;
        validate_root("pq_signature_root", &request.pq_signature_root)?;
        validate_root("watcher_anchor_root", &request.watcher_anchor_root)?;
        validate_root(
            "liquidity_commitment_root",
            &request.liquidity_commitment_root,
        )?;
        validate_root("provider_reserve_root", &request.provider_reserve_root)?;
        validate_secret("request_nonce", &request.request_nonce)?;
        if request.liquidity_provider_id.trim().is_empty() {
            return Err("liquidity_provider_id is required".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("fast exit pq authorization below security floor".to_string());
        }
        if request.watcher_weight < self.config.min_watcher_weight
            || request.watcher_count < self.config.min_watcher_count
        {
            return Err("fast exit submit request lacks watcher quorum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("fast exit privacy set below configured floor".to_string());
        }
        if request.amount_bucket_upper_bound == 0 {
            return Err("amount bucket upper bound must be nonzero".to_string());
        }
        if request.max_fee_bps > MONERO_L2_FAST_EXIT_EXECUTION_LANE_MAX_BPS {
            return Err("max fee bps exceeds 100%".to_string());
        }
        if request.priority.requires_sponsor() {
            match &request.low_fee_sponsor_root {
                Some(root) => validate_root("low_fee_sponsor_root", root)?,
                None => return Err("low-fee fast exits require sponsor root".to_string()),
            }
            if request.sponsor_fee_budget == 0 {
                return Err("low-fee fast exits require sponsor fee budget".to_string());
            }
        }
        if request
            .observed_monero_height
            .saturating_sub(request.l2_burn_height)
            < self.config.min_anchor_depth
        {
            return Err("fast exit request lacks watcher/pq anchor depth".to_string());
        }
        Ok(())
    }

    fn validate_execute_request(
        &self,
        request: &ExecuteSlotRequest,
    ) -> MoneroL2FastExitExecutionLaneResult<()> {
        if request.executor_id.trim().is_empty() {
            return Err("executor_id is required".to_string());
        }
        validate_root("execution_batch_root", &request.execution_batch_root)?;
        validate_root("payout_commitment_root", &request.payout_commitment_root)?;
        validate_root(
            "payout_address_commitment_root",
            &request.payout_address_commitment_root,
        )?;
        validate_root(
            "payout_amount_bucket_root",
            &request.payout_amount_bucket_root,
        )?;
        validate_root("liquidity_release_root", &request.liquidity_release_root)?;
        validate_root("reserve_safety_root", &request.reserve_safety_root)?;
        validate_root("watcher_anchor_root", &request.watcher_anchor_root)?;
        validate_root("pq_authorization_root", &request.pq_authorization_root)?;
        validate_root("pq_signature_root", &request.pq_signature_root)?;
        validate_root("fee_commitment_root", &request.fee_commitment_root)?;
        validate_secret("execution_nonce", &request.execution_nonce)?;
        if request.watcher_weight < self.config.min_watcher_weight
            || request.watcher_count < self.config.min_watcher_count
        {
            return Err("fast exit execute request lacks watcher quorum".to_string());
        }
        Ok(())
    }

    fn validate_settle_request(
        &self,
        request: &SettleExitRequest,
    ) -> MoneroL2FastExitExecutionLaneResult<()> {
        validate_root("settlement_tx_root", &request.settlement_tx_root)?;
        validate_root("settlement_batch_root", &request.settlement_batch_root)?;
        validate_root("settlement_receipt_root", &request.settlement_receipt_root)?;
        validate_root(
            "payout_confirmation_root",
            &request.payout_confirmation_root,
        )?;
        validate_root("reserve_release_root", &request.reserve_release_root)?;
        validate_root("pq_settlement_root", &request.pq_settlement_root)?;
        validate_root("watcher_settlement_root", &request.watcher_settlement_root)?;
        validate_secret("settlement_nonce", &request.settlement_nonce)?;
        Ok(())
    }

    fn reserve_snapshot_for_submit(
        &self,
        exit_id: &str,
        request: &SubmitExitRequest,
    ) -> MoneroL2FastExitExecutionLaneResult<ReserveSafetySnapshot> {
        let required_provider_cover = mul_bps_ceil(
            request.amount_bucket_upper_bound,
            self.config.min_reserve_cover_bps,
        );
        let required_lane_cover = request
            .lane_locked_liquidity
            .saturating_add(required_provider_cover);
        let provider_exposure_bps = bps(
            request.amount_bucket_upper_bound,
            request.provider_available_liquidity,
        );
        let lane_exposure_bps = bps(required_lane_cover, request.lane_total_reserve);
        let accepted = request.provider_available_liquidity >= required_provider_cover
            && request.lane_total_reserve >= required_lane_cover
            && provider_exposure_bps <= self.config.max_provider_exposure_bps
            && lane_exposure_bps <= self.config.max_lane_exposure_bps;
        let reserve_safety_root = lane_root(
            "MONERO-L2-FAST-EXIT-RESERVE-SAFETY-SNAPSHOT-ROOT",
            &json!({
                "exit_id": exit_id,
                "provider_id": request.liquidity_provider_id,
                "amount_bucket_upper_bound": request.amount_bucket_upper_bound,
                "provider_available_liquidity": request.provider_available_liquidity,
                "lane_total_reserve": request.lane_total_reserve,
                "lane_locked_liquidity": request.lane_locked_liquidity,
                "required_provider_cover": required_provider_cover,
                "required_lane_cover": required_lane_cover,
                "provider_exposure_bps": provider_exposure_bps,
                "lane_exposure_bps": lane_exposure_bps,
                "accepted": accepted,
            }),
        );
        let snapshot_id = reserve_snapshot_id(
            exit_id,
            &request.liquidity_provider_id,
            &reserve_safety_root,
            request.submitted_at_height,
        );
        Ok(ReserveSafetySnapshot {
            snapshot_id,
            exit_id: exit_id.to_string(),
            provider_id: request.liquidity_provider_id.clone(),
            amount_bucket_upper_bound: request.amount_bucket_upper_bound,
            provider_available_liquidity: request.provider_available_liquidity,
            lane_total_reserve: request.lane_total_reserve,
            lane_locked_liquidity: request.lane_locked_liquidity,
            required_provider_cover,
            required_lane_cover,
            provider_exposure_bps,
            lane_exposure_bps,
            reserve_safety_root,
            accepted,
            created_at_height: request.submitted_at_height,
        })
    }

    fn upsert_provider_for_submit(&mut self, exit: &PrivateExitRequest) {
        let provider = self
            .providers
            .entry(exit.liquidity_provider_id.clone())
            .or_insert(LiquidityProviderCommitment {
                provider_id: exit.liquidity_provider_id.clone(),
                commitment_root: exit.liquidity_commitment_root.clone(),
                reserve_root: exit.provider_reserve_root.clone(),
                committed_upper_bound: 0,
                locked_upper_bound: 0,
                executed_upper_bound: 0,
                settled_upper_bound: 0,
                latest_exit_id: String::new(),
                latest_slot_id: String::new(),
                latest_updated_height: 0,
            });
        provider.commitment_root = exit.liquidity_commitment_root.clone();
        provider.reserve_root = exit.provider_reserve_root.clone();
        provider.committed_upper_bound = provider
            .committed_upper_bound
            .saturating_add(exit.amount_bucket_upper_bound);
        provider.locked_upper_bound = provider
            .locked_upper_bound
            .saturating_add(exit.amount_bucket_upper_bound);
        provider.latest_exit_id = exit.exit_id.clone();
        provider.latest_updated_height = exit.updated_at_height;
    }

    fn upsert_provider_for_execution(&mut self, exit: &PrivateExitRequest, slot: &ExecutionSlot) {
        if let Some(provider) = self.providers.get_mut(&exit.liquidity_provider_id) {
            provider.executed_upper_bound = provider
                .executed_upper_bound
                .saturating_add(exit.amount_bucket_upper_bound);
            provider.latest_exit_id = exit.exit_id.clone();
            provider.latest_slot_id = slot.slot_id.clone();
            provider.latest_updated_height = slot.execution_height;
        }
    }

    fn upsert_provider_for_settlement(&mut self, exit: &PrivateExitRequest, slot: &ExecutionSlot) {
        if let Some(provider) = self.providers.get_mut(&exit.liquidity_provider_id) {
            provider.settled_upper_bound = provider
                .settled_upper_bound
                .saturating_add(exit.amount_bucket_upper_bound);
            provider.locked_upper_bound = provider
                .locked_upper_bound
                .saturating_sub(exit.amount_bucket_upper_bound);
            provider.latest_exit_id = exit.exit_id.clone();
            provider.latest_slot_id = slot.slot_id.clone();
            provider.latest_updated_height = slot.execution_height;
        }
    }

    fn mark_replay_fence_consumed(&mut self, exit_id: &str, height: u64) {
        for fence in self.replay_fences.values_mut() {
            if fence.exit_id == exit_id {
                fence.consumed_at_height = Some(height);
            }
        }
    }

    fn expire_stale(&mut self, current_height: u64) {
        let exit_ids = self
            .exits
            .iter()
            .filter_map(|(exit_id, exit)| {
                (!exit.status.terminal()
                    && exit.slot_id.is_none()
                    && current_height > exit.execution_deadline_height)
                    .then(|| exit_id.clone())
            })
            .collect::<Vec<_>>();
        for exit_id in exit_ids {
            if let Some(exit) = self.exits.get_mut(&exit_id) {
                exit.status = ExitStatus::Expired;
                exit.updated_at_height = current_height;
                self.counters.expired_exits = self.counters.expired_exits.saturating_add(1);
            }
        }

        let slot_ids = self
            .slots
            .iter()
            .filter_map(|(slot_id, slot)| {
                (!slot.status.terminal() && current_height > slot.settlement_deadline_height)
                    .then(|| slot_id.clone())
            })
            .collect::<Vec<_>>();
        for slot_id in slot_ids {
            if let Some(slot) = self.slots.get_mut(&slot_id) {
                slot.status = SlotStatus::Expired;
                if let Some(exit) = self.exits.get_mut(&slot.exit_id) {
                    if !exit.status.terminal() {
                        exit.status = ExitStatus::Expired;
                        exit.updated_at_height = current_height;
                        self.counters.expired_exits = self.counters.expired_exits.saturating_add(1);
                    }
                }
            }
        }
        self.height = self.height.max(current_height);
    }

    fn push_event(&mut self, event_type: &str, height: u64, payload: Value) {
        let event_id = domain_hash(
            "MONERO-L2-FAST-EXIT-EVENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(event_type),
                HashPart::Int(height as i128),
                HashPart::Int(self.counters.events.saturating_add(1) as i128),
                HashPart::Json(&payload),
            ],
            32,
        );
        self.events.push(json!({
            "kind": "monero_l2_fast_exit_execution_lane_event",
            "event_id": event_id,
            "event_type": event_type,
            "height": height,
            "payload": payload,
        }));
        self.counters.events = self.counters.events.saturating_add(1);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn exit_id(
    sequence: u64,
    exit_commitment: &str,
    nullifier_root: &str,
    replay_fence_root: &str,
    priority: ExitPriority,
    submitted_at_height: u64,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-FAST-EXIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(exit_commitment),
            HashPart::Str(nullifier_root),
            HashPart::Str(replay_fence_root),
            HashPart::Str(priority.as_str()),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Str(nonce),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execution_slot_id(
    sequence: u64,
    exit_id: &str,
    execution_batch_root: &str,
    payout_commitment_root: &str,
    execution_height: u64,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-FAST-EXIT-EXECUTION-SLOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(exit_id),
            HashPart::Str(execution_batch_root),
            HashPart::Str(payout_commitment_root),
            HashPart::Int(execution_height as i128),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn settlement_receipt_id(
    sequence: u64,
    exit_id: &str,
    slot_id: &str,
    settlement_receipt_root: &str,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-FAST-EXIT-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(exit_id),
            HashPart::Str(slot_id),
            HashPart::Str(settlement_receipt_root),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn replay_fence_id(exit_id: &str, nullifier_root: &str, replay_fence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-FAST-EXIT-REPLAY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(exit_id),
            HashPart::Str(nullifier_root),
            HashPart::Str(replay_fence_root),
        ],
        32,
    )
}

pub fn reserve_snapshot_id(
    exit_id: &str,
    provider_id: &str,
    reserve_safety_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-FAST-EXIT-RESERVE-SNAPSHOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(exit_id),
            HashPart::Str(provider_id),
            HashPart::Str(reserve_safety_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn private_root(domain: &str, secret: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(secret),
        ],
        32,
    )
}

pub fn lane_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn empty_low_fee_sponsor_root() -> String {
    merkle_root("MONERO-L2-FAST-EXIT-EMPTY-LOW-FEE-SPONSORS", &[])
}

pub fn empty_payout_commitment_root() -> String {
    merkle_root("MONERO-L2-FAST-EXIT-EMPTY-PAYOUT-COMMITMENTS", &[])
}

fn validate_root(name: &str, root: &str) -> MoneroL2FastExitExecutionLaneResult<()> {
    if root.trim().is_empty() {
        return Err(format!("{name} is required"));
    }
    Ok(())
}

fn validate_secret(name: &str, secret: &str) -> MoneroL2FastExitExecutionLaneResult<()> {
    if secret.trim().is_empty() {
        return Err(format!("{name} is required"));
    }
    Ok(())
}

fn merkle_string_root(domain: &str, values: Vec<String>) -> String {
    let leaves = values.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_records<T, F>(items: &BTreeMap<String, T>, record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    items.values().map(record).collect()
}

fn bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return MONERO_L2_FAST_EXIT_EXECUTION_LANE_MAX_BPS;
    }
    numerator.saturating_mul(MONERO_L2_FAST_EXIT_EXECUTION_LANE_MAX_BPS) / denominator
}

fn mul_bps_ceil(value: u64, bps: u64) -> u64 {
    let denominator = MONERO_L2_FAST_EXIT_EXECUTION_LANE_MAX_BPS;
    value
        .saturating_mul(bps)
        .saturating_add(denominator.saturating_sub(1))
        / denominator
}
