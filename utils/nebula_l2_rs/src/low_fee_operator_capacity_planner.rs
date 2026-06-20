use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type LowFeeOperatorCapacityPlannerResult<T> = Result<T, String>;

pub const LOW_FEE_OPERATOR_CAPACITY_PLANNER_PROTOCOL_VERSION: &str =
    "nebula-low-fee-operator-capacity-planner-v1";
pub const LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEVNET_HEIGHT: u64 = 1_760;
pub const LOW_FEE_OPERATOR_CAPACITY_PLANNER_MAX_BPS: u64 = 10_000;
pub const LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_WINDOW_BLOCKS: u64 = 12;
pub const LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_TICKET_TTL_BLOCKS: u64 = 48;
pub const LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_RUNBOOK_TTL_BLOCKS: u64 = 96;
pub const LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_TARGET_UTILIZATION_BPS: u64 = 7_200;
pub const LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_BACKPRESSURE_BPS: u64 = 8_500;
pub const LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_RECOVERY_BPS: u64 = 6_500;
pub const LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_MAX_FEE_CEILING_BPS: u64 = 42;
pub const LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_DA_SAMPLE_QUORUM_BPS: u64 = 6_700;
pub const LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_SPONSOR_RESERVE_BPS: u64 = 12_000;
pub const LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_PROOF_MARKET_RESERVE_BPS: u64 = 11_000;
pub const LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_MONERO_EXIT_RESERVE_BPS: u64 = 10_500;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityLaneKind {
    PublicLowFeeTransfer,
    PrivateLowFeeTransfer,
    PrivateContractGas,
    ProofMarket,
    DaSampling,
    MoneroBridgeExit,
    SponsoredFee,
    OperatorMaintenance,
}

impl CapacityLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicLowFeeTransfer => "public_low_fee_transfer",
            Self::PrivateLowFeeTransfer => "private_low_fee_transfer",
            Self::PrivateContractGas => "private_contract_gas",
            Self::ProofMarket => "proof_market",
            Self::DaSampling => "da_sampling",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::SponsoredFee => "sponsored_fee",
            Self::OperatorMaintenance => "operator_maintenance",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::MoneroBridgeExit => 1_000,
            Self::PrivateContractGas => 920,
            Self::ProofMarket => 880,
            Self::DaSampling => 840,
            Self::PrivateLowFeeTransfer => 760,
            Self::PublicLowFeeTransfer => 700,
            Self::SponsoredFee => 640,
            Self::OperatorMaintenance => 420,
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::PrivateLowFeeTransfer
                | Self::PrivateContractGas
                | Self::MoneroBridgeExit
                | Self::SponsoredFee
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityWindowStatus {
    Planned,
    Open,
    Backpressured,
    Draining,
    Sealed,
    Cancelled,
}

impl CapacityWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Open => "open",
            Self::Backpressured => "backpressured",
            Self::Draining => "draining",
            Self::Sealed => "sealed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Planned | Self::Open | Self::Backpressured | Self::Draining
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Pending,
    Issued,
    Consumed,
    Deferred,
    Expired,
    Revoked,
}

impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Issued => "issued",
            Self::Consumed => "consumed",
            Self::Deferred => "deferred",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Pending | Self::Issued | Self::Deferred)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunbookHookKind {
    ScaleSequencer,
    IncreaseProofBid,
    ExpandDaSampling,
    SlowMoneroExits,
    TightenFeeCeiling,
    DrainSponsorPool,
    PageOperator,
    PublishStatus,
}

impl RunbookHookKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScaleSequencer => "scale_sequencer",
            Self::IncreaseProofBid => "increase_proof_bid",
            Self::ExpandDaSampling => "expand_da_sampling",
            Self::SlowMoneroExits => "slow_monero_exits",
            Self::TightenFeeCeiling => "tighten_fee_ceiling",
            Self::DrainSponsorPool => "drain_sponsor_pool",
            Self::PageOperator => "page_operator",
            Self::PublishStatus => "publish_status",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunbookHookStatus {
    Armed,
    Triggered,
    Acknowledged,
    Resolved,
    Suppressed,
}

impl RunbookHookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Triggered => "triggered",
            Self::Acknowledged => "acknowledged",
            Self::Resolved => "resolved",
            Self::Suppressed => "suppressed",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Armed | Self::Triggered | Self::Acknowledged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCeilingStatus {
    Nominal,
    Tightened,
    Emergency,
    Released,
}

impl FeeCeilingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nominal => "nominal",
            Self::Tightened => "tightened",
            Self::Emergency => "emergency",
            Self::Released => "released",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub operator_set_root: String,
    pub planning_horizon_blocks: u64,
    pub default_window_blocks: u64,
    pub ticket_ttl_blocks: u64,
    pub runbook_ttl_blocks: u64,
    pub target_utilization_bps: u64,
    pub backpressure_threshold_bps: u64,
    pub recovery_threshold_bps: u64,
    pub max_fee_ceiling_bps: u64,
    pub da_sample_quorum_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub proof_market_reserve_bps: u64,
    pub monero_exit_reserve_bps: u64,
    pub min_privacy_set_size: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: LOW_FEE_OPERATOR_CAPACITY_PLANNER_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            operator_set_root: string_root("DEVNET-OPERATOR-SET", "low-fee-operator-devnet"),
            planning_horizon_blocks: 144,
            default_window_blocks: LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_WINDOW_BLOCKS,
            ticket_ttl_blocks: LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_TICKET_TTL_BLOCKS,
            runbook_ttl_blocks: LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_RUNBOOK_TTL_BLOCKS,
            target_utilization_bps:
                LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_TARGET_UTILIZATION_BPS,
            backpressure_threshold_bps: LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_BACKPRESSURE_BPS,
            recovery_threshold_bps: LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_RECOVERY_BPS,
            max_fee_ceiling_bps: LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_MAX_FEE_CEILING_BPS,
            da_sample_quorum_bps: LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_DA_SAMPLE_QUORUM_BPS,
            sponsor_reserve_bps: LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_SPONSOR_RESERVE_BPS,
            proof_market_reserve_bps:
                LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_PROOF_MARKET_RESERVE_BPS,
            monero_exit_reserve_bps:
                LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_MONERO_EXIT_RESERVE_BPS,
            min_privacy_set_size: LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_MIN_PRIVACY_SET_SIZE,
        }
    }
}

impl Config {
    pub fn validate(&self) -> LowFeeOperatorCapacityPlannerResult<()> {
        if self.protocol_version != LOW_FEE_OPERATOR_CAPACITY_PLANNER_PROTOCOL_VERSION {
            return Err("low fee operator capacity planner protocol version mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("low fee operator capacity planner chain id mismatch".to_string());
        }
        if self.planning_horizon_blocks == 0 || self.default_window_blocks == 0 {
            return Err("capacity planner windows must be non-zero".to_string());
        }
        if self.ticket_ttl_blocks == 0 || self.runbook_ttl_blocks == 0 {
            return Err("capacity planner ttl values must be non-zero".to_string());
        }
        validate_bps("target utilization", self.target_utilization_bps)?;
        validate_bps("backpressure threshold", self.backpressure_threshold_bps)?;
        validate_bps("recovery threshold", self.recovery_threshold_bps)?;
        validate_bps("max fee ceiling", self.max_fee_ceiling_bps)?;
        validate_bps("da sample quorum", self.da_sample_quorum_bps)?;
        if self.sponsor_reserve_bps < LOW_FEE_OPERATOR_CAPACITY_PLANNER_MAX_BPS {
            return Err("sponsor reserve must cover at least one full low fee window".to_string());
        }
        if self.proof_market_reserve_bps < LOW_FEE_OPERATOR_CAPACITY_PLANNER_MAX_BPS {
            return Err(
                "proof market reserve must cover at least one full proof window".to_string(),
            );
        }
        if self.monero_exit_reserve_bps < LOW_FEE_OPERATOR_CAPACITY_PLANNER_MAX_BPS {
            return Err("monero exit reserve must cover at least one full exit window".to_string());
        }
        if self.recovery_threshold_bps >= self.backpressure_threshold_bps {
            return Err("recovery threshold must be below backpressure threshold".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("minimum privacy set size must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "operator_set_root": self.operator_set_root,
            "planning_horizon_blocks": self.planning_horizon_blocks,
            "default_window_blocks": self.default_window_blocks,
            "ticket_ttl_blocks": self.ticket_ttl_blocks,
            "runbook_ttl_blocks": self.runbook_ttl_blocks,
            "target_utilization_bps": self.target_utilization_bps,
            "backpressure_threshold_bps": self.backpressure_threshold_bps,
            "recovery_threshold_bps": self.recovery_threshold_bps,
            "max_fee_ceiling_bps": self.max_fee_ceiling_bps,
            "da_sample_quorum_bps": self.da_sample_quorum_bps,
            "sponsor_reserve_bps": self.sponsor_reserve_bps,
            "proof_market_reserve_bps": self.proof_market_reserve_bps,
            "monero_exit_reserve_bps": self.monero_exit_reserve_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
        })
    }

    pub fn root(&self) -> String {
        payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencerLane {
    pub lane_id: String,
    pub label: String,
    pub lane_kind: CapacityLaneKind,
    pub operator_commitment: String,
    pub max_ops_per_block: u64,
    pub max_gas_per_block: u64,
    pub reserved_gas_per_block: u64,
    pub current_queue_depth: u64,
    pub target_latency_ms: u64,
    pub fee_ceiling_bps: u64,
    pub priority: u64,
    pub privacy_set_size: u64,
    pub opened_at_height: u64,
    pub paused: bool,
}

impl SequencerLane {
    pub fn new(
        label: &str,
        lane_kind: CapacityLaneKind,
        operator_commitment: &str,
        max_ops_per_block: u64,
        max_gas_per_block: u64,
        opened_at_height: u64,
    ) -> Self {
        let lane_id = capacity_id(
            "SEQUENCER-LANE-ID",
            &[
                label,
                lane_kind.as_str(),
                operator_commitment,
                &opened_at_height.to_string(),
            ],
        );
        Self {
            lane_id,
            label: label.to_string(),
            lane_kind,
            operator_commitment: operator_commitment.to_string(),
            max_ops_per_block,
            max_gas_per_block,
            reserved_gas_per_block: max_gas_per_block / 5,
            current_queue_depth: 0,
            target_latency_ms: 650,
            fee_ceiling_bps: lane_kind_fee_ceiling_bps(lane_kind),
            priority: lane_kind.priority(),
            privacy_set_size: if lane_kind.privacy_sensitive() {
                256
            } else {
                1
            },
            opened_at_height,
            paused: false,
        }
    }

    pub fn available_gas_per_block(&self) -> u64 {
        self.max_gas_per_block
            .saturating_sub(self.reserved_gas_per_block)
    }

    pub fn utilization_bps(&self) -> u64 {
        utilization_bps(self.current_queue_depth, self.max_ops_per_block)
    }

    pub fn validate(&self, config: &Config) -> LowFeeOperatorCapacityPlannerResult<()> {
        if self.lane_id.is_empty() || self.label.is_empty() {
            return Err("sequencer lane id and label must be present".to_string());
        }
        if self.max_ops_per_block == 0 || self.max_gas_per_block == 0 {
            return Err("sequencer lane capacity must be non-zero".to_string());
        }
        if self.reserved_gas_per_block > self.max_gas_per_block {
            return Err("sequencer lane reserved gas exceeds maximum".to_string());
        }
        validate_bps("sequencer lane fee ceiling", self.fee_ceiling_bps)?;
        if self.fee_ceiling_bps > config.max_fee_ceiling_bps {
            return Err("sequencer lane fee ceiling exceeds config maximum".to_string());
        }
        if self.lane_kind.privacy_sensitive() && self.privacy_set_size < config.min_privacy_set_size
        {
            return Err("sequencer lane privacy set below configured minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "label": self.label,
            "lane_kind": self.lane_kind.as_str(),
            "operator_commitment": self.operator_commitment,
            "max_ops_per_block": self.max_ops_per_block,
            "max_gas_per_block": self.max_gas_per_block,
            "reserved_gas_per_block": self.reserved_gas_per_block,
            "available_gas_per_block": self.available_gas_per_block(),
            "current_queue_depth": self.current_queue_depth,
            "target_latency_ms": self.target_latency_ms,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "priority": self.priority,
            "privacy_set_size": self.privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "paused": self.paused,
            "utilization_bps": self.utilization_bps(),
        })
    }

    pub fn root(&self) -> String {
        payload_root("SEQUENCER-LANE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofMarketCapacity {
    pub market_id: String,
    pub label: String,
    pub proof_system: String,
    pub lane_id: String,
    pub open_jobs: u64,
    pub max_parallel_jobs: u64,
    pub max_bid_units: u64,
    pub reserve_units: u64,
    pub proving_latency_ms: u64,
    pub verifier_gas_limit: u64,
    pub settlement_root: String,
}

impl ProofMarketCapacity {
    pub fn new(label: &str, proof_system: &str, lane_id: &str, max_parallel_jobs: u64) -> Self {
        let market_id = capacity_id(
            "PROOF-MARKET-ID",
            &[label, proof_system, lane_id, &max_parallel_jobs.to_string()],
        );
        Self {
            market_id,
            label: label.to_string(),
            proof_system: proof_system.to_string(),
            lane_id: lane_id.to_string(),
            open_jobs: 0,
            max_parallel_jobs,
            max_bid_units: 4_200_000,
            reserve_units: 48_000_000,
            proving_latency_ms: 1_800,
            verifier_gas_limit: 3_500_000,
            settlement_root: string_root("PROOF-SETTLEMENT", label),
        }
    }

    pub fn utilization_bps(&self) -> u64 {
        utilization_bps(self.open_jobs, self.max_parallel_jobs)
    }

    pub fn validate(&self) -> LowFeeOperatorCapacityPlannerResult<()> {
        if self.market_id.is_empty() || self.label.is_empty() || self.proof_system.is_empty() {
            return Err("proof market identity fields must be present".to_string());
        }
        if self.lane_id.is_empty() || self.max_parallel_jobs == 0 {
            return Err("proof market lane and capacity must be present".to_string());
        }
        if self.open_jobs > self.max_parallel_jobs.saturating_mul(4) {
            return Err("proof market open jobs exceed burst-safe queue".to_string());
        }
        if self.max_bid_units == 0 || self.reserve_units == 0 {
            return Err("proof market bids and reserve must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "label": self.label,
            "proof_system": self.proof_system,
            "lane_id": self.lane_id,
            "open_jobs": self.open_jobs,
            "max_parallel_jobs": self.max_parallel_jobs,
            "max_bid_units": self.max_bid_units,
            "reserve_units": self.reserve_units,
            "proving_latency_ms": self.proving_latency_ms,
            "verifier_gas_limit": self.verifier_gas_limit,
            "settlement_root": self.settlement_root,
            "utilization_bps": self.utilization_bps(),
        })
    }

    pub fn root(&self) -> String {
        payload_root("PROOF-MARKET", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaSamplingPlan {
    pub plan_id: String,
    pub label: String,
    pub lane_id: String,
    pub samples_per_block: u64,
    pub min_quorum_bps: u64,
    pub erasure_shard_count: u64,
    pub witness_bytes_per_sample: u64,
    pub sampling_committee_root: String,
    pub fallback_relay_root: String,
}

impl DaSamplingPlan {
    pub fn new(label: &str, lane_id: &str, samples_per_block: u64) -> Self {
        let plan_id = capacity_id(
            "DA-SAMPLING-PLAN-ID",
            &[label, lane_id, &samples_per_block.to_string()],
        );
        Self {
            plan_id,
            label: label.to_string(),
            lane_id: lane_id.to_string(),
            samples_per_block,
            min_quorum_bps: LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEFAULT_DA_SAMPLE_QUORUM_BPS,
            erasure_shard_count: 64,
            witness_bytes_per_sample: 1_536,
            sampling_committee_root: string_root("DA-SAMPLING-COMMITTEE", label),
            fallback_relay_root: string_root("DA-FALLBACK-RELAY", label),
        }
    }

    pub fn validate(&self, config: &Config) -> LowFeeOperatorCapacityPlannerResult<()> {
        if self.plan_id.is_empty() || self.lane_id.is_empty() {
            return Err("da sampling plan identity must be present".to_string());
        }
        if self.samples_per_block == 0 || self.erasure_shard_count == 0 {
            return Err("da sampling plan sample and shard counts must be non-zero".to_string());
        }
        validate_bps("da sampling quorum", self.min_quorum_bps)?;
        if self.min_quorum_bps < config.da_sample_quorum_bps {
            return Err("da sampling quorum below configured minimum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "plan_id": self.plan_id,
            "label": self.label,
            "lane_id": self.lane_id,
            "samples_per_block": self.samples_per_block,
            "min_quorum_bps": self.min_quorum_bps,
            "erasure_shard_count": self.erasure_shard_count,
            "witness_bytes_per_sample": self.witness_bytes_per_sample,
            "sampling_committee_root": self.sampling_committee_root,
            "fallback_relay_root": self.fallback_relay_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("DA-SAMPLING-PLAN", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgeExitCapacity {
    pub exit_id: String,
    pub label: String,
    pub lane_id: String,
    pub subaddress_rotation_root: String,
    pub max_exits_per_window: u64,
    pub pending_exits: u64,
    pub liquidity_units: u64,
    pub minimum_liquidity_units: u64,
    pub privacy_batch_size: u64,
    pub confirmation_target_blocks: u64,
    pub exit_fee_ceiling_bps: u64,
}

impl MoneroBridgeExitCapacity {
    pub fn new(label: &str, lane_id: &str, liquidity_units: u64) -> Self {
        let exit_id = capacity_id(
            "MONERO-BRIDGE-EXIT-ID",
            &[label, lane_id, &liquidity_units.to_string()],
        );
        Self {
            exit_id,
            label: label.to_string(),
            lane_id: lane_id.to_string(),
            subaddress_rotation_root: string_root("MONERO-SUBADDRESS-ROTATION", label),
            max_exits_per_window: 320,
            pending_exits: 0,
            liquidity_units,
            minimum_liquidity_units: liquidity_units / 3,
            privacy_batch_size: 64,
            confirmation_target_blocks: 18,
            exit_fee_ceiling_bps: 35,
        }
    }

    pub fn utilization_bps(&self) -> u64 {
        utilization_bps(self.pending_exits, self.max_exits_per_window)
    }

    pub fn liquidity_coverage_bps(&self) -> u64 {
        utilization_bps(self.liquidity_units, self.minimum_liquidity_units)
    }

    pub fn validate(&self, config: &Config) -> LowFeeOperatorCapacityPlannerResult<()> {
        if self.exit_id.is_empty() || self.lane_id.is_empty() {
            return Err("monero bridge exit identity must be present".to_string());
        }
        if self.max_exits_per_window == 0 || self.privacy_batch_size == 0 {
            return Err("monero bridge exit counts must be non-zero".to_string());
        }
        if self.privacy_batch_size < config.min_privacy_set_size / 2 {
            return Err("monero bridge exit privacy batch below half configured set".to_string());
        }
        if self.liquidity_units < self.minimum_liquidity_units {
            return Err("monero bridge exit liquidity below minimum".to_string());
        }
        validate_bps("monero bridge exit fee ceiling", self.exit_fee_ceiling_bps)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "exit_id": self.exit_id,
            "label": self.label,
            "lane_id": self.lane_id,
            "subaddress_rotation_root": self.subaddress_rotation_root,
            "max_exits_per_window": self.max_exits_per_window,
            "pending_exits": self.pending_exits,
            "liquidity_units": self.liquidity_units,
            "minimum_liquidity_units": self.minimum_liquidity_units,
            "privacy_batch_size": self.privacy_batch_size,
            "confirmation_target_blocks": self.confirmation_target_blocks,
            "exit_fee_ceiling_bps": self.exit_fee_ceiling_bps,
            "utilization_bps": self.utilization_bps(),
            "liquidity_coverage_bps": self.liquidity_coverage_bps(),
        })
    }

    pub fn root(&self) -> String {
        payload_root("MONERO-BRIDGE-EXIT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractGasPlan {
    pub plan_id: String,
    pub lane_id: String,
    pub contract_class_root: String,
    pub max_calls_per_window: u64,
    pub reserved_gas_units: u64,
    pub calldata_budget_bytes: u64,
    pub witness_budget_bytes: u64,
    pub max_sponsor_share_bps: u64,
    pub gas_oracle_root: String,
}

impl PrivateContractGasPlan {
    pub fn new(lane_id: &str, contract_class_root: &str, max_calls_per_window: u64) -> Self {
        let plan_id = capacity_id(
            "PRIVATE-CONTRACT-GAS-PLAN-ID",
            &[
                lane_id,
                contract_class_root,
                &max_calls_per_window.to_string(),
            ],
        );
        Self {
            plan_id,
            lane_id: lane_id.to_string(),
            contract_class_root: contract_class_root.to_string(),
            max_calls_per_window,
            reserved_gas_units: 48_000_000,
            calldata_budget_bytes: 786_432,
            witness_budget_bytes: 2_097_152,
            max_sponsor_share_bps: 8_000,
            gas_oracle_root: string_root("PRIVATE-CONTRACT-GAS-ORACLE", lane_id),
        }
    }

    pub fn validate(&self) -> LowFeeOperatorCapacityPlannerResult<()> {
        if self.plan_id.is_empty() || self.lane_id.is_empty() || self.contract_class_root.is_empty()
        {
            return Err("private contract gas plan identity must be present".to_string());
        }
        if self.max_calls_per_window == 0 || self.reserved_gas_units == 0 {
            return Err("private contract gas plan capacity must be non-zero".to_string());
        }
        validate_bps("private contract sponsor share", self.max_sponsor_share_bps)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "plan_id": self.plan_id,
            "lane_id": self.lane_id,
            "contract_class_root": self.contract_class_root,
            "max_calls_per_window": self.max_calls_per_window,
            "reserved_gas_units": self.reserved_gas_units,
            "calldata_budget_bytes": self.calldata_budget_bytes,
            "witness_budget_bytes": self.witness_budget_bytes,
            "max_sponsor_share_bps": self.max_sponsor_share_bps,
            "gas_oracle_root": self.gas_oracle_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PRIVATE-CONTRACT-GAS-PLAN", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsoredFeePool {
    pub sponsor_id: String,
    pub label: String,
    pub lane_allowlist_root: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub consumed_units: u64,
    pub max_fee_ceiling_bps: u64,
    pub refill_rate_units_per_block: u64,
    pub policy_root: String,
}

impl SponsoredFeePool {
    pub fn new(label: &str, lanes: &[String], budget_units: u64) -> Self {
        let lane_allowlist_root = string_set_root("SPONSORED-FEE-LANES", lanes);
        let sponsor_id = capacity_id(
            "SPONSORED-FEE-POOL-ID",
            &[label, &lane_allowlist_root, &budget_units.to_string()],
        );
        Self {
            sponsor_id,
            label: label.to_string(),
            lane_allowlist_root,
            budget_units,
            reserved_units: 0,
            consumed_units: 0,
            max_fee_ceiling_bps: 28,
            refill_rate_units_per_block: 75_000,
            policy_root: string_root("SPONSORED-FEE-POLICY", label),
        }
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.consumed_units)
    }

    pub fn reserve(&mut self, units: u64) -> LowFeeOperatorCapacityPlannerResult<()> {
        if units > self.available_units() {
            return Err("sponsored fee pool budget unavailable".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(())
    }

    pub fn consume(&mut self, units: u64) -> LowFeeOperatorCapacityPlannerResult<()> {
        if units > self.reserved_units {
            return Err("sponsored fee pool reserved budget unavailable".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(units);
        self.consumed_units = self.consumed_units.saturating_add(units);
        Ok(())
    }

    pub fn validate(&self) -> LowFeeOperatorCapacityPlannerResult<()> {
        if self.sponsor_id.is_empty() || self.label.is_empty() {
            return Err("sponsored fee pool identity must be present".to_string());
        }
        if self.reserved_units.saturating_add(self.consumed_units) > self.budget_units {
            return Err("sponsored fee pool accounting exceeds budget".to_string());
        }
        validate_bps("sponsored fee ceiling", self.max_fee_ceiling_bps)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "label": self.label,
            "lane_allowlist_root": self.lane_allowlist_root,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "consumed_units": self.consumed_units,
            "available_units": self.available_units(),
            "max_fee_ceiling_bps": self.max_fee_ceiling_bps,
            "refill_rate_units_per_block": self.refill_rate_units_per_block,
            "policy_root": self.policy_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SPONSORED-FEE-POOL", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurstWindow {
    pub window_id: String,
    pub label: String,
    pub lane_id: String,
    pub start_height: u64,
    pub end_height: u64,
    pub status: CapacityWindowStatus,
    pub planned_ops: u64,
    pub planned_gas_units: u64,
    pub consumed_ops: u64,
    pub consumed_gas_units: u64,
    pub backpressure_ticket_root: String,
}

impl BurstWindow {
    pub fn new(label: &str, lane_id: &str, start_height: u64, end_height: u64) -> Self {
        let window_id = capacity_id(
            "BURST-WINDOW-ID",
            &[
                label,
                lane_id,
                &start_height.to_string(),
                &end_height.to_string(),
            ],
        );
        Self {
            window_id,
            label: label.to_string(),
            lane_id: lane_id.to_string(),
            start_height,
            end_height,
            status: CapacityWindowStatus::Planned,
            planned_ops: 0,
            planned_gas_units: 0,
            consumed_ops: 0,
            consumed_gas_units: 0,
            backpressure_ticket_root: merkle_root("LOW-FEE-OPERATOR-BACKPRESSURE-TICKET", &[]),
        }
    }

    pub fn duration_blocks(&self) -> u64 {
        self.end_height.saturating_sub(self.start_height)
    }

    pub fn utilization_bps(&self) -> u64 {
        utilization_bps(self.consumed_ops, self.planned_ops)
    }

    pub fn set_ticket_root(&mut self, ticket_records: &[Value]) {
        self.backpressure_ticket_root = record_merkle_root("BACKPRESSURE-TICKET", ticket_records);
    }

    pub fn validate(&self) -> LowFeeOperatorCapacityPlannerResult<()> {
        if self.window_id.is_empty() || self.lane_id.is_empty() {
            return Err("burst window identity must be present".to_string());
        }
        if self.end_height <= self.start_height {
            return Err("burst window end height must be greater than start height".to_string());
        }
        if self.consumed_ops > self.planned_ops
            && self.status != CapacityWindowStatus::Backpressured
        {
            return Err("burst window over plan without backpressure status".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "label": self.label,
            "lane_id": self.lane_id,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "duration_blocks": self.duration_blocks(),
            "status": self.status.as_str(),
            "planned_ops": self.planned_ops,
            "planned_gas_units": self.planned_gas_units,
            "consumed_ops": self.consumed_ops,
            "consumed_gas_units": self.consumed_gas_units,
            "backpressure_ticket_root": self.backpressure_ticket_root,
            "utilization_bps": self.utilization_bps(),
        })
    }

    pub fn root(&self) -> String {
        payload_root("BURST-WINDOW", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCeiling {
    pub ceiling_id: String,
    pub lane_id: String,
    pub asset_id: String,
    pub max_fee_bps: u64,
    pub low_fee_target_bps: u64,
    pub status: FeeCeilingStatus,
    pub oracle_root: String,
    pub effective_from_height: u64,
    pub expires_at_height: u64,
}

impl FeeCeiling {
    pub fn new(
        lane_id: &str,
        asset_id: &str,
        max_fee_bps: u64,
        effective_from_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let ceiling_id = capacity_id(
            "FEE-CEILING-ID",
            &[
                lane_id,
                asset_id,
                &max_fee_bps.to_string(),
                &effective_from_height.to_string(),
            ],
        );
        Self {
            ceiling_id,
            lane_id: lane_id.to_string(),
            asset_id: asset_id.to_string(),
            max_fee_bps,
            low_fee_target_bps: max_fee_bps / 3,
            status: FeeCeilingStatus::Nominal,
            oracle_root: string_root("FEE-CEILING-ORACLE", lane_id),
            effective_from_height,
            expires_at_height,
        }
    }

    pub fn active_at(&self, height: u64) -> bool {
        height >= self.effective_from_height && height < self.expires_at_height
    }

    pub fn validate(&self, config: &Config) -> LowFeeOperatorCapacityPlannerResult<()> {
        if self.ceiling_id.is_empty() || self.lane_id.is_empty() || self.asset_id.is_empty() {
            return Err("fee ceiling identity must be present".to_string());
        }
        validate_bps("fee ceiling maximum", self.max_fee_bps)?;
        validate_bps("fee ceiling target", self.low_fee_target_bps)?;
        if self.max_fee_bps > config.max_fee_ceiling_bps {
            return Err("fee ceiling exceeds configured maximum".to_string());
        }
        if self.low_fee_target_bps > self.max_fee_bps {
            return Err("fee ceiling target exceeds maximum".to_string());
        }
        if self.expires_at_height <= self.effective_from_height {
            return Err("fee ceiling expiry must be after effective height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ceiling_id": self.ceiling_id,
            "lane_id": self.lane_id,
            "asset_id": self.asset_id,
            "max_fee_bps": self.max_fee_bps,
            "low_fee_target_bps": self.low_fee_target_bps,
            "status": self.status.as_str(),
            "oracle_root": self.oracle_root,
            "effective_from_height": self.effective_from_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("FEE-CEILING", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackpressureTicket {
    pub ticket_id: String,
    pub lane_id: String,
    pub window_id: String,
    pub reason_root: String,
    pub status: TicketStatus,
    pub requested_capacity_units: u64,
    pub granted_capacity_units: u64,
    pub fee_ceiling_bps: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl BackpressureTicket {
    pub fn new(
        lane_id: &str,
        window_id: &str,
        reason: &str,
        requested_capacity_units: u64,
        issued_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let reason_root = string_root("BACKPRESSURE-REASON", reason);
        let ticket_id = capacity_id(
            "BACKPRESSURE-TICKET-ID",
            &[
                lane_id,
                window_id,
                &reason_root,
                &issued_at_height.to_string(),
            ],
        );
        Self {
            ticket_id,
            lane_id: lane_id.to_string(),
            window_id: window_id.to_string(),
            reason_root,
            status: TicketStatus::Pending,
            requested_capacity_units,
            granted_capacity_units: 0,
            fee_ceiling_bps: 0,
            issued_at_height,
            expires_at_height: issued_at_height.saturating_add(ttl_blocks),
        }
    }

    pub fn grant(
        &mut self,
        granted_capacity_units: u64,
        fee_ceiling_bps: u64,
    ) -> LowFeeOperatorCapacityPlannerResult<()> {
        if granted_capacity_units > self.requested_capacity_units {
            return Err("backpressure ticket grant exceeds request".to_string());
        }
        validate_bps("backpressure ticket fee ceiling", fee_ceiling_bps)?;
        self.granted_capacity_units = granted_capacity_units;
        self.fee_ceiling_bps = fee_ceiling_bps;
        self.status = TicketStatus::Issued;
        Ok(())
    }

    pub fn validate(&self) -> LowFeeOperatorCapacityPlannerResult<()> {
        if self.ticket_id.is_empty() || self.lane_id.is_empty() || self.window_id.is_empty() {
            return Err("backpressure ticket identity must be present".to_string());
        }
        if self.requested_capacity_units == 0 {
            return Err("backpressure ticket request must be non-zero".to_string());
        }
        if self.granted_capacity_units > self.requested_capacity_units {
            return Err("backpressure ticket grant exceeds request".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("backpressure ticket expiry must be after issue height".to_string());
        }
        validate_bps("backpressure ticket fee ceiling", self.fee_ceiling_bps)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "lane_id": self.lane_id,
            "window_id": self.window_id,
            "reason_root": self.reason_root,
            "status": self.status.as_str(),
            "requested_capacity_units": self.requested_capacity_units,
            "granted_capacity_units": self.granted_capacity_units,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("BACKPRESSURE-TICKET", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorRunbookHook {
    pub hook_id: String,
    pub hook_kind: RunbookHookKind,
    pub lane_id: String,
    pub trigger_root: String,
    pub action_root: String,
    pub status: RunbookHookStatus,
    pub severity: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub ack_commitment: String,
}

impl OperatorRunbookHook {
    pub fn new(
        hook_kind: RunbookHookKind,
        lane_id: &str,
        trigger: &str,
        action: &str,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let trigger_root = string_root("RUNBOOK-TRIGGER", trigger);
        let action_root = string_root("RUNBOOK-ACTION", action);
        let hook_id = capacity_id(
            "RUNBOOK-HOOK-ID",
            &[
                hook_kind.as_str(),
                lane_id,
                &trigger_root,
                &opened_at_height.to_string(),
            ],
        );
        Self {
            hook_id,
            hook_kind,
            lane_id: lane_id.to_string(),
            trigger_root,
            action_root,
            status: RunbookHookStatus::Armed,
            severity: hook_kind_severity(hook_kind),
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            ack_commitment: String::new(),
        }
    }

    pub fn acknowledge(&mut self, ack_commitment: &str) -> LowFeeOperatorCapacityPlannerResult<()> {
        if ack_commitment.is_empty() {
            return Err("runbook hook acknowledgement commitment required".to_string());
        }
        self.ack_commitment = ack_commitment.to_string();
        self.status = RunbookHookStatus::Acknowledged;
        Ok(())
    }

    pub fn validate(&self) -> LowFeeOperatorCapacityPlannerResult<()> {
        if self.hook_id.is_empty() || self.lane_id.is_empty() {
            return Err("runbook hook identity must be present".to_string());
        }
        if self.severity == 0 {
            return Err("runbook hook severity must be non-zero".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("runbook hook expiry must be after opened height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hook_id": self.hook_id,
            "hook_kind": self.hook_kind.as_str(),
            "lane_id": self.lane_id,
            "trigger_root": self.trigger_root,
            "action_root": self.action_root,
            "status": self.status.as_str(),
            "severity": self.severity,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "ack_commitment": self.ack_commitment,
        })
    }

    pub fn root(&self) -> String {
        payload_root("RUNBOOK-HOOK", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacitySnapshot {
    pub snapshot_id: String,
    pub height: u64,
    pub lane_root: String,
    pub proof_market_root: String,
    pub da_sampling_root: String,
    pub monero_exit_root: String,
    pub private_contract_gas_root: String,
    pub sponsor_pool_root: String,
    pub burst_window_root: String,
    pub fee_ceiling_root: String,
    pub backpressure_ticket_root: String,
    pub runbook_hook_root: String,
    pub total_available_gas_per_block: u64,
    pub total_queue_depth: u64,
    pub max_lane_utilization_bps: u64,
    pub status_root: String,
}

impl CapacitySnapshot {
    pub fn from_state(state: &State) -> Self {
        let roots = state.roots();
        let total_available_gas_per_block = state
            .lanes
            .values()
            .map(SequencerLane::available_gas_per_block)
            .sum();
        let total_queue_depth = state
            .lanes
            .values()
            .map(|lane| lane.current_queue_depth)
            .sum();
        let max_lane_utilization_bps = state
            .lanes
            .values()
            .map(SequencerLane::utilization_bps)
            .fold(0, u64::max);
        let status_root = string_set_root(
            "CAPACITY-SNAPSHOT-STATUS",
            &state
                .runbook_hooks
                .values()
                .filter(|hook| hook.status.open())
                .map(|hook| hook.hook_id.clone())
                .collect::<Vec<_>>(),
        );
        let snapshot_id = capacity_id(
            "CAPACITY-SNAPSHOT-ID",
            &[
                &state.height.to_string(),
                &roots.lane_root,
                &roots.backpressure_ticket_root,
                &status_root,
            ],
        );
        Self {
            snapshot_id,
            height: state.height,
            lane_root: roots.lane_root,
            proof_market_root: roots.proof_market_root,
            da_sampling_root: roots.da_sampling_root,
            monero_exit_root: roots.monero_exit_root,
            private_contract_gas_root: roots.private_contract_gas_root,
            sponsor_pool_root: roots.sponsor_pool_root,
            burst_window_root: roots.burst_window_root,
            fee_ceiling_root: roots.fee_ceiling_root,
            backpressure_ticket_root: roots.backpressure_ticket_root,
            runbook_hook_root: roots.runbook_hook_root,
            total_available_gas_per_block,
            total_queue_depth,
            max_lane_utilization_bps,
            status_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "height": self.height,
            "lane_root": self.lane_root,
            "proof_market_root": self.proof_market_root,
            "da_sampling_root": self.da_sampling_root,
            "monero_exit_root": self.monero_exit_root,
            "private_contract_gas_root": self.private_contract_gas_root,
            "sponsor_pool_root": self.sponsor_pool_root,
            "burst_window_root": self.burst_window_root,
            "fee_ceiling_root": self.fee_ceiling_root,
            "backpressure_ticket_root": self.backpressure_ticket_root,
            "runbook_hook_root": self.runbook_hook_root,
            "total_available_gas_per_block": self.total_available_gas_per_block,
            "total_queue_depth": self.total_queue_depth,
            "max_lane_utilization_bps": self.max_lane_utilization_bps,
            "status_root": self.status_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("CAPACITY-SNAPSHOT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub lane_root: String,
    pub proof_market_root: String,
    pub da_sampling_root: String,
    pub monero_exit_root: String,
    pub private_contract_gas_root: String,
    pub sponsor_pool_root: String,
    pub burst_window_root: String,
    pub fee_ceiling_root: String,
    pub backpressure_ticket_root: String,
    pub runbook_hook_root: String,
    pub snapshot_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "proof_market_root": self.proof_market_root,
            "da_sampling_root": self.da_sampling_root,
            "monero_exit_root": self.monero_exit_root,
            "private_contract_gas_root": self.private_contract_gas_root,
            "sponsor_pool_root": self.sponsor_pool_root,
            "burst_window_root": self.burst_window_root,
            "fee_ceiling_root": self.fee_ceiling_root,
            "backpressure_ticket_root": self.backpressure_ticket_root,
            "runbook_hook_root": self.runbook_hook_root,
            "snapshot_root": self.snapshot_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub lane_count: u64,
    pub paused_lane_count: u64,
    pub proof_market_count: u64,
    pub da_sampling_plan_count: u64,
    pub monero_exit_capacity_count: u64,
    pub private_contract_gas_plan_count: u64,
    pub sponsor_pool_count: u64,
    pub live_burst_window_count: u64,
    pub active_fee_ceiling_count: u64,
    pub active_backpressure_ticket_count: u64,
    pub open_runbook_hook_count: u64,
    pub snapshot_count: u64,
    pub total_queue_depth: u64,
    pub total_sponsor_budget_units: u64,
    pub total_sponsor_available_units: u64,
    pub max_lane_utilization_bps: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_count": self.lane_count,
            "paused_lane_count": self.paused_lane_count,
            "proof_market_count": self.proof_market_count,
            "da_sampling_plan_count": self.da_sampling_plan_count,
            "monero_exit_capacity_count": self.monero_exit_capacity_count,
            "private_contract_gas_plan_count": self.private_contract_gas_plan_count,
            "sponsor_pool_count": self.sponsor_pool_count,
            "live_burst_window_count": self.live_burst_window_count,
            "active_fee_ceiling_count": self.active_fee_ceiling_count,
            "active_backpressure_ticket_count": self.active_backpressure_ticket_count,
            "open_runbook_hook_count": self.open_runbook_hook_count,
            "snapshot_count": self.snapshot_count,
            "total_queue_depth": self.total_queue_depth,
            "total_sponsor_budget_units": self.total_sponsor_budget_units,
            "total_sponsor_available_units": self.total_sponsor_available_units,
            "max_lane_utilization_bps": self.max_lane_utilization_bps,
        })
    }

    pub fn root(&self) -> String {
        payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub lanes: BTreeMap<String, SequencerLane>,
    pub proof_markets: BTreeMap<String, ProofMarketCapacity>,
    pub da_sampling_plans: BTreeMap<String, DaSamplingPlan>,
    pub monero_exits: BTreeMap<String, MoneroBridgeExitCapacity>,
    pub private_contract_gas_plans: BTreeMap<String, PrivateContractGasPlan>,
    pub sponsor_pools: BTreeMap<String, SponsoredFeePool>,
    pub burst_windows: BTreeMap<String, BurstWindow>,
    pub fee_ceilings: BTreeMap<String, FeeCeiling>,
    pub backpressure_tickets: BTreeMap<String, BackpressureTicket>,
    pub runbook_hooks: BTreeMap<String, OperatorRunbookHook>,
    pub snapshots: BTreeMap<String, CapacitySnapshot>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            height: 0,
            config: Config::default(),
            lanes: BTreeMap::new(),
            proof_markets: BTreeMap::new(),
            da_sampling_plans: BTreeMap::new(),
            monero_exits: BTreeMap::new(),
            private_contract_gas_plans: BTreeMap::new(),
            sponsor_pools: BTreeMap::new(),
            burst_windows: BTreeMap::new(),
            fee_ceilings: BTreeMap::new(),
            backpressure_tickets: BTreeMap::new(),
            runbook_hooks: BTreeMap::new(),
            snapshots: BTreeMap::new(),
        }
    }
}

impl State {
    pub fn devnet() -> LowFeeOperatorCapacityPlannerResult<Self> {
        let mut state = Self {
            height: LOW_FEE_OPERATOR_CAPACITY_PLANNER_DEVNET_HEIGHT,
            ..Self::default()
        };

        let operator = string_root("OPERATOR", "devnet-low-fee-capacity-operator");
        let public_lane = SequencerLane::new(
            "public-low-fee",
            CapacityLaneKind::PublicLowFeeTransfer,
            &operator,
            18_000,
            120_000_000,
            state.height,
        );
        let private_lane = SequencerLane::new(
            "private-low-fee",
            CapacityLaneKind::PrivateLowFeeTransfer,
            &operator,
            12_000,
            160_000_000,
            state.height,
        );
        let contract_lane = SequencerLane::new(
            "private-contract-gas",
            CapacityLaneKind::PrivateContractGas,
            &operator,
            2_400,
            240_000_000,
            state.height,
        );
        let proof_lane = SequencerLane::new(
            "proof-market",
            CapacityLaneKind::ProofMarket,
            &operator,
            1_200,
            80_000_000,
            state.height,
        );
        let da_lane = SequencerLane::new(
            "da-sampling",
            CapacityLaneKind::DaSampling,
            &operator,
            3_200,
            64_000_000,
            state.height,
        );
        let monero_lane = SequencerLane::new(
            "monero-bridge-exit",
            CapacityLaneKind::MoneroBridgeExit,
            &operator,
            860,
            96_000_000,
            state.height,
        );
        let sponsor_lane = SequencerLane::new(
            "sponsored-low-fee",
            CapacityLaneKind::SponsoredFee,
            &operator,
            6_400,
            72_000_000,
            state.height,
        );

        state.insert_lane(public_lane)?;
        state.insert_lane(private_lane)?;
        state.insert_lane(contract_lane)?;
        state.insert_lane(proof_lane)?;
        state.insert_lane(da_lane)?;
        state.insert_lane(monero_lane)?;
        state.insert_lane(sponsor_lane)?;

        let proof_lane_id = state
            .lane_by_label("proof-market")
            .ok_or_else(|| "devnet proof lane missing".to_string())?
            .lane_id
            .clone();
        let da_lane_id = state
            .lane_by_label("da-sampling")
            .ok_or_else(|| "devnet da lane missing".to_string())?
            .lane_id
            .clone();
        let monero_lane_id = state
            .lane_by_label("monero-bridge-exit")
            .ok_or_else(|| "devnet monero lane missing".to_string())?
            .lane_id
            .clone();
        let contract_lane_id = state
            .lane_by_label("private-contract-gas")
            .ok_or_else(|| "devnet contract lane missing".to_string())?
            .lane_id
            .clone();
        let sponsor_lane_id = state
            .lane_by_label("sponsored-low-fee")
            .ok_or_else(|| "devnet sponsor lane missing".to_string())?
            .lane_id
            .clone();

        state.insert_proof_market(ProofMarketCapacity::new(
            "recursive-low-fee-proof",
            "plonkish-recursive-capacity-v1",
            &proof_lane_id,
            96,
        ))?;
        state.insert_da_sampling_plan(DaSamplingPlan::new("low-fee-da-quorum", &da_lane_id, 96))?;
        state.insert_monero_exit(MoneroBridgeExitCapacity::new(
            "monero-devnet-fast-exits",
            &monero_lane_id,
            18_000_000_000,
        ))?;
        state.insert_private_contract_gas_plan(PrivateContractGasPlan::new(
            &contract_lane_id,
            &string_root("CONTRACT-CLASS", "private-contract-low-fee-devnet"),
            1_200,
        ))?;
        state.insert_sponsor_pool(SponsoredFeePool::new(
            "devnet-sponsored-low-fee",
            &[sponsor_lane_id.clone(), contract_lane_id.clone()],
            42_000_000_000,
        ))?;

        state.open_burst_window("public-low-fee-window", "public-low-fee")?;
        state.open_burst_window("private-low-fee-window", "private-low-fee")?;
        state.open_burst_window("contract-gas-window", "private-contract-gas")?;
        state.open_burst_window("monero-exit-window", "monero-bridge-exit")?;

        state.insert_fee_ceiling(FeeCeiling::new(
            &sponsor_lane_id,
            "piconero-devnet",
            28,
            state.height,
            state.height.saturating_add(144),
        ))?;
        state.insert_fee_ceiling(FeeCeiling::new(
            &monero_lane_id,
            "wxmr-devnet",
            35,
            state.height,
            state.height.saturating_add(144),
        ))?;

        state.insert_runbook_hook(OperatorRunbookHook::new(
            RunbookHookKind::ScaleSequencer,
            &contract_lane_id,
            "private contract gas lane utilization above target",
            "scale contract executor replicas and publish fee ceiling status",
            state.height,
            state.config.runbook_ttl_blocks,
        ))?;
        state.insert_runbook_hook(OperatorRunbookHook::new(
            RunbookHookKind::ExpandDaSampling,
            &da_lane_id,
            "da sample quorum approaching recovery threshold",
            "increase light client sample workers and pin fallback relay",
            state.height,
            state.config.runbook_ttl_blocks,
        ))?;

        state.refresh_burst_window_ticket_roots();
        state.record_snapshot()?;
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> LowFeeOperatorCapacityPlannerResult<()> {
        self.config.validate()?;
        for lane in self.lanes.values() {
            lane.validate(&self.config)?;
        }
        for market in self.proof_markets.values() {
            market.validate()?;
            self.require_lane(&market.lane_id)?;
        }
        for plan in self.da_sampling_plans.values() {
            plan.validate(&self.config)?;
            self.require_lane(&plan.lane_id)?;
        }
        for exit in self.monero_exits.values() {
            exit.validate(&self.config)?;
            self.require_lane(&exit.lane_id)?;
        }
        for plan in self.private_contract_gas_plans.values() {
            plan.validate()?;
            self.require_lane(&plan.lane_id)?;
        }
        for pool in self.sponsor_pools.values() {
            pool.validate()?;
        }
        for window in self.burst_windows.values() {
            window.validate()?;
            self.require_lane(&window.lane_id)?;
        }
        for ceiling in self.fee_ceilings.values() {
            ceiling.validate(&self.config)?;
            self.require_lane(&ceiling.lane_id)?;
        }
        for ticket in self.backpressure_tickets.values() {
            ticket.validate()?;
            self.require_lane(&ticket.lane_id)?;
            if !self.burst_windows.contains_key(&ticket.window_id) {
                return Err("backpressure ticket references missing burst window".to_string());
            }
        }
        for hook in self.runbook_hooks.values() {
            hook.validate()?;
            self.require_lane(&hook.lane_id)?;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> LowFeeOperatorCapacityPlannerResult<()> {
        if height < self.height {
            return Err("capacity planner height cannot move backwards".to_string());
        }
        self.height = height;
        self.expire_records();
        self.refresh_burst_window_ticket_roots();
        Ok(())
    }

    pub fn update_height(&mut self, height: u64) -> LowFeeOperatorCapacityPlannerResult<()> {
        self.set_height(height)
    }

    pub fn insert_lane(&mut self, lane: SequencerLane) -> LowFeeOperatorCapacityPlannerResult<()> {
        lane.validate(&self.config)?;
        if self.lanes.contains_key(&lane.lane_id) {
            return Err("sequencer lane already exists".to_string());
        }
        self.lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    pub fn insert_proof_market(
        &mut self,
        market: ProofMarketCapacity,
    ) -> LowFeeOperatorCapacityPlannerResult<()> {
        market.validate()?;
        self.require_lane(&market.lane_id)?;
        self.proof_markets.insert(market.market_id.clone(), market);
        Ok(())
    }

    pub fn insert_da_sampling_plan(
        &mut self,
        plan: DaSamplingPlan,
    ) -> LowFeeOperatorCapacityPlannerResult<()> {
        plan.validate(&self.config)?;
        self.require_lane(&plan.lane_id)?;
        self.da_sampling_plans.insert(plan.plan_id.clone(), plan);
        Ok(())
    }

    pub fn insert_monero_exit(
        &mut self,
        exit: MoneroBridgeExitCapacity,
    ) -> LowFeeOperatorCapacityPlannerResult<()> {
        exit.validate(&self.config)?;
        self.require_lane(&exit.lane_id)?;
        self.monero_exits.insert(exit.exit_id.clone(), exit);
        Ok(())
    }

    pub fn insert_private_contract_gas_plan(
        &mut self,
        plan: PrivateContractGasPlan,
    ) -> LowFeeOperatorCapacityPlannerResult<()> {
        plan.validate()?;
        self.require_lane(&plan.lane_id)?;
        self.private_contract_gas_plans
            .insert(plan.plan_id.clone(), plan);
        Ok(())
    }

    pub fn insert_sponsor_pool(
        &mut self,
        pool: SponsoredFeePool,
    ) -> LowFeeOperatorCapacityPlannerResult<()> {
        pool.validate()?;
        self.sponsor_pools.insert(pool.sponsor_id.clone(), pool);
        Ok(())
    }

    pub fn insert_fee_ceiling(
        &mut self,
        ceiling: FeeCeiling,
    ) -> LowFeeOperatorCapacityPlannerResult<()> {
        ceiling.validate(&self.config)?;
        self.require_lane(&ceiling.lane_id)?;
        self.fee_ceilings
            .insert(ceiling.ceiling_id.clone(), ceiling);
        Ok(())
    }

    pub fn insert_runbook_hook(
        &mut self,
        hook: OperatorRunbookHook,
    ) -> LowFeeOperatorCapacityPlannerResult<()> {
        hook.validate()?;
        self.require_lane(&hook.lane_id)?;
        self.runbook_hooks.insert(hook.hook_id.clone(), hook);
        Ok(())
    }

    pub fn open_burst_window(
        &mut self,
        label: &str,
        lane_label: &str,
    ) -> LowFeeOperatorCapacityPlannerResult<String> {
        let lane = self
            .lane_by_label(lane_label)
            .ok_or_else(|| "burst window lane label not found".to_string())?;
        let start_height = self.height;
        let end_height = self
            .height
            .saturating_add(self.config.default_window_blocks);
        let mut window = BurstWindow::new(label, &lane.lane_id, start_height, end_height);
        window.status = CapacityWindowStatus::Open;
        window.planned_ops = lane
            .max_ops_per_block
            .saturating_mul(self.config.default_window_blocks);
        window.planned_gas_units = lane
            .available_gas_per_block()
            .saturating_mul(self.config.default_window_blocks);
        let window_id = window.window_id.clone();
        window.validate()?;
        self.burst_windows.insert(window_id.clone(), window);
        Ok(window_id)
    }

    pub fn issue_backpressure_ticket(
        &mut self,
        lane_id: &str,
        window_id: &str,
        reason: &str,
        requested_capacity_units: u64,
    ) -> LowFeeOperatorCapacityPlannerResult<String> {
        self.require_lane(lane_id)?;
        if !self.burst_windows.contains_key(window_id) {
            return Err("backpressure ticket window not found".to_string());
        }
        let mut ticket = BackpressureTicket::new(
            lane_id,
            window_id,
            reason,
            requested_capacity_units,
            self.height,
            self.config.ticket_ttl_blocks,
        );
        let grant = requested_capacity_units / 2;
        ticket.grant(grant, self.config.max_fee_ceiling_bps)?;
        let ticket_id = ticket.ticket_id.clone();
        self.backpressure_tickets.insert(ticket_id.clone(), ticket);
        self.refresh_burst_window_ticket_roots();
        Ok(ticket_id)
    }

    pub fn consume_sponsor_budget(
        &mut self,
        sponsor_id: &str,
        units: u64,
    ) -> LowFeeOperatorCapacityPlannerResult<()> {
        let sponsor = self
            .sponsor_pools
            .get_mut(sponsor_id)
            .ok_or_else(|| "sponsor pool not found".to_string())?;
        sponsor.reserve(units)?;
        sponsor.consume(units)?;
        Ok(())
    }

    pub fn record_snapshot(&mut self) -> LowFeeOperatorCapacityPlannerResult<String> {
        self.validate()?;
        let snapshot = CapacitySnapshot::from_state(self);
        let snapshot_id = snapshot.snapshot_id.clone();
        self.snapshots.insert(snapshot_id.clone(), snapshot);
        Ok(snapshot_id)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.root(),
            lane_root: record_map_root(
                "LANE",
                self.lanes.values().map(SequencerLane::public_record),
            ),
            proof_market_root: record_map_root(
                "PROOF-MARKET",
                self.proof_markets
                    .values()
                    .map(ProofMarketCapacity::public_record),
            ),
            da_sampling_root: record_map_root(
                "DA-SAMPLING",
                self.da_sampling_plans
                    .values()
                    .map(DaSamplingPlan::public_record),
            ),
            monero_exit_root: record_map_root(
                "MONERO-EXIT",
                self.monero_exits
                    .values()
                    .map(MoneroBridgeExitCapacity::public_record),
            ),
            private_contract_gas_root: record_map_root(
                "PRIVATE-CONTRACT-GAS",
                self.private_contract_gas_plans
                    .values()
                    .map(PrivateContractGasPlan::public_record),
            ),
            sponsor_pool_root: record_map_root(
                "SPONSOR-POOL",
                self.sponsor_pools
                    .values()
                    .map(SponsoredFeePool::public_record),
            ),
            burst_window_root: record_map_root(
                "BURST-WINDOW",
                self.burst_windows.values().map(BurstWindow::public_record),
            ),
            fee_ceiling_root: record_map_root(
                "FEE-CEILING",
                self.fee_ceilings.values().map(FeeCeiling::public_record),
            ),
            backpressure_ticket_root: record_map_root(
                "BACKPRESSURE-TICKET",
                self.backpressure_tickets
                    .values()
                    .map(BackpressureTicket::public_record),
            ),
            runbook_hook_root: record_map_root(
                "RUNBOOK-HOOK",
                self.runbook_hooks
                    .values()
                    .map(OperatorRunbookHook::public_record),
            ),
            snapshot_root: record_map_root(
                "CAPACITY-SNAPSHOT",
                self.snapshots.values().map(CapacitySnapshot::public_record),
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            lane_count: self.lanes.len() as u64,
            paused_lane_count: self.lanes.values().filter(|lane| lane.paused).count() as u64,
            proof_market_count: self.proof_markets.len() as u64,
            da_sampling_plan_count: self.da_sampling_plans.len() as u64,
            monero_exit_capacity_count: self.monero_exits.len() as u64,
            private_contract_gas_plan_count: self.private_contract_gas_plans.len() as u64,
            sponsor_pool_count: self.sponsor_pools.len() as u64,
            live_burst_window_count: self
                .burst_windows
                .values()
                .filter(|window| window.status.live())
                .count() as u64,
            active_fee_ceiling_count: self
                .fee_ceilings
                .values()
                .filter(|ceiling| ceiling.active_at(self.height))
                .count() as u64,
            active_backpressure_ticket_count: self
                .backpressure_tickets
                .values()
                .filter(|ticket| ticket.status.active())
                .count() as u64,
            open_runbook_hook_count: self
                .runbook_hooks
                .values()
                .filter(|hook| hook.status.open())
                .count() as u64,
            snapshot_count: self.snapshots.len() as u64,
            total_queue_depth: self
                .lanes
                .values()
                .map(|lane| lane.current_queue_depth)
                .sum(),
            total_sponsor_budget_units: self
                .sponsor_pools
                .values()
                .map(|pool| pool.budget_units)
                .sum(),
            total_sponsor_available_units: self
                .sponsor_pools
                .values()
                .map(SponsoredFeePool::available_units)
                .sum(),
            max_lane_utilization_bps: self
                .lanes
                .values()
                .map(SequencerLane::utilization_bps)
                .fold(0, u64::max),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": LOW_FEE_OPERATOR_CAPACITY_PLANNER_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "lanes": self.lanes.values().map(SequencerLane::public_record).collect::<Vec<_>>(),
            "proof_markets": self.proof_markets.values().map(ProofMarketCapacity::public_record).collect::<Vec<_>>(),
            "da_sampling_plans": self.da_sampling_plans.values().map(DaSamplingPlan::public_record).collect::<Vec<_>>(),
            "monero_exits": self.monero_exits.values().map(MoneroBridgeExitCapacity::public_record).collect::<Vec<_>>(),
            "private_contract_gas_plans": self.private_contract_gas_plans.values().map(PrivateContractGasPlan::public_record).collect::<Vec<_>>(),
            "sponsor_pools": self.sponsor_pools.values().map(SponsoredFeePool::public_record).collect::<Vec<_>>(),
            "burst_windows": self.burst_windows.values().map(BurstWindow::public_record).collect::<Vec<_>>(),
            "fee_ceilings": self.fee_ceilings.values().map(FeeCeiling::public_record).collect::<Vec<_>>(),
            "backpressure_tickets": self.backpressure_tickets.values().map(BackpressureTicket::public_record).collect::<Vec<_>>(),
            "runbook_hooks": self.runbook_hooks.values().map(OperatorRunbookHook::public_record).collect::<Vec<_>>(),
            "snapshots": self.snapshots.values().map(CapacitySnapshot::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(&self.public_record())
    }

    fn require_lane(&self, lane_id: &str) -> LowFeeOperatorCapacityPlannerResult<()> {
        if self.lanes.contains_key(lane_id) {
            Ok(())
        } else {
            Err("referenced sequencer lane not found".to_string())
        }
    }

    fn lane_by_label(&self, label: &str) -> Option<&SequencerLane> {
        self.lanes.values().find(|lane| lane.label == label)
    }

    fn refresh_burst_window_ticket_roots(&mut self) {
        let window_ids = self.burst_windows.keys().cloned().collect::<Vec<_>>();
        for window_id in window_ids {
            let records = self
                .backpressure_tickets
                .values()
                .filter(|ticket| ticket.window_id == window_id)
                .map(BackpressureTicket::public_record)
                .collect::<Vec<_>>();
            if let Some(window) = self.burst_windows.get_mut(&window_id) {
                window.set_ticket_root(&records);
            }
        }
    }

    fn expire_records(&mut self) {
        for ticket in self.backpressure_tickets.values_mut() {
            if self.height >= ticket.expires_at_height && ticket.status.active() {
                ticket.status = TicketStatus::Expired;
            }
        }
        for hook in self.runbook_hooks.values_mut() {
            if self.height >= hook.expires_at_height && hook.status.open() {
                hook.status = RunbookHookStatus::Suppressed;
            }
        }
        for window in self.burst_windows.values_mut() {
            if self.height >= window.end_height && window.status.live() {
                window.status = CapacityWindowStatus::Sealed;
            }
        }
        for ceiling in self.fee_ceilings.values_mut() {
            if self.height >= ceiling.expires_at_height
                && ceiling.status != FeeCeilingStatus::Released
            {
                ceiling.status = FeeCeilingStatus::Released;
            }
        }
    }
}

pub fn root_from_record(record: &Value) -> String {
    payload_root("STATE", record)
}

pub fn devnet() -> LowFeeOperatorCapacityPlannerResult<State> {
    State::devnet()
}

pub fn lane_capacity_score(lane: &SequencerLane, config: &Config) -> u64 {
    let utilization = lane.utilization_bps();
    if utilization >= config.backpressure_threshold_bps {
        lane.priority.saturating_add(2_000)
    } else if utilization >= config.target_utilization_bps {
        lane.priority.saturating_add(1_000)
    } else {
        lane.priority
    }
}

pub fn planning_pressure_root(lanes: &BTreeMap<String, SequencerLane>, config: &Config) -> String {
    let mut pressure = lanes
        .values()
        .map(|lane| {
            json!({
                "lane_id": lane.lane_id,
                "lane_kind": lane.lane_kind.as_str(),
                "score": lane_capacity_score(lane, config),
                "utilization_bps": lane.utilization_bps(),
                "paused": lane.paused,
            })
        })
        .collect::<Vec<_>>();
    pressure.sort_by(|left, right| {
        value_sort_key(&left["lane_id"]).cmp(value_sort_key(&right["lane_id"]))
    });
    record_merkle_root("PLANNING-PRESSURE", &pressure)
}

fn validate_bps(label: &str, value: u64) -> LowFeeOperatorCapacityPlannerResult<()> {
    if value > LOW_FEE_OPERATOR_CAPACITY_PLANNER_MAX_BPS {
        Err(format!("{label} basis points exceed maximum"))
    } else {
        Ok(())
    }
}

fn utilization_bps(used: u64, capacity: u64) -> u64 {
    if capacity == 0 {
        0
    } else {
        used.saturating_mul(LOW_FEE_OPERATOR_CAPACITY_PLANNER_MAX_BPS) / capacity
    }
}

fn lane_kind_fee_ceiling_bps(lane_kind: CapacityLaneKind) -> u64 {
    match lane_kind {
        CapacityLaneKind::PublicLowFeeTransfer => 18,
        CapacityLaneKind::PrivateLowFeeTransfer => 24,
        CapacityLaneKind::PrivateContractGas => 32,
        CapacityLaneKind::ProofMarket => 30,
        CapacityLaneKind::DaSampling => 14,
        CapacityLaneKind::MoneroBridgeExit => 35,
        CapacityLaneKind::SponsoredFee => 20,
        CapacityLaneKind::OperatorMaintenance => 8,
    }
}

fn hook_kind_severity(kind: RunbookHookKind) -> u64 {
    match kind {
        RunbookHookKind::PageOperator => 100,
        RunbookHookKind::SlowMoneroExits => 92,
        RunbookHookKind::TightenFeeCeiling => 86,
        RunbookHookKind::IncreaseProofBid => 80,
        RunbookHookKind::ScaleSequencer => 76,
        RunbookHookKind::ExpandDaSampling => 72,
        RunbookHookKind::DrainSponsorPool => 68,
        RunbookHookKind::PublishStatus => 48,
    }
}

fn capacity_id(domain: &str, values: &[&str]) -> String {
    domain_hash(
        &format!("LOW-FEE-OPERATOR-CAPACITY-PLANNER-{domain}"),
        &values
            .iter()
            .map(|value| HashPart::Str(value))
            .collect::<Vec<_>>(),
        32,
    )
}

fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("LOW-FEE-OPERATOR-CAPACITY-PLANNER-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

fn string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("LOW-FEE-OPERATOR-CAPACITY-PLANNER-{domain}"),
        &[HashPart::Str(value)],
        32,
    )
}

fn string_set_root(domain: &str, values: &[String]) -> String {
    let mut unique = values.iter().cloned().collect::<BTreeSet<_>>();
    let ordered = unique.split_off("");
    domain_hash(
        &format!("LOW-FEE-OPERATOR-CAPACITY-PLANNER-{domain}"),
        &ordered
            .iter()
            .map(|value| HashPart::Str(value))
            .collect::<Vec<_>>(),
        32,
    )
}

fn record_merkle_root(domain: &str, records: &[Value]) -> String {
    let mut leaves = records
        .iter()
        .map(|record| payload_root("RECORD", record))
        .map(Value::String)
        .collect::<Vec<_>>();
    leaves.sort_by(|left, right| value_sort_key(left).cmp(value_sort_key(right)));
    merkle_root(
        &format!("LOW-FEE-OPERATOR-CAPACITY-PLANNER-{domain}"),
        &leaves,
    )
}

fn record_map_root<I>(domain: &str, records: I) -> String
where
    I: Iterator<Item = Value>,
{
    let values = records.collect::<Vec<_>>();
    record_merkle_root(domain, &values)
}

fn value_sort_key(value: &Value) -> &str {
    match value {
        Value::String(inner) => inner.as_str(),
        _ => "",
    }
}
