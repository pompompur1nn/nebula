use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type LowFeeLaneStressControllerResult<T> = Result<T, String>;

pub const LOW_FEE_LANE_STRESS_CONTROLLER_PROTOCOL_VERSION: &str =
    "nebula-low-fee-lane-stress-controller-v1";
pub const LOW_FEE_LANE_STRESS_CONTROLLER_DEVNET_HEIGHT: u64 = 2_426;
pub const LOW_FEE_LANE_STRESS_CONTROLLER_MAX_BPS: u64 = 10_000;
pub const LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_BURST_WINDOW_BLOCKS: u64 = 16;
pub const LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_TICKET_TTL_BLOCKS: u64 = 64;
pub const LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_MAX_QUEUE_DEPTH: u64 = 18_000;
pub const LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_LOW_FEE_CEILING_MICRO_DENOM: u64 = 42;
pub const LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_PROOF_CONGESTION_BPS: u64 = 7_400;
pub const LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_EXIT_CONGESTION_BPS: u64 = 6_900;
pub const LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_CONTRACT_GAS_CONGESTION_BPS: u64 = 7_700;
pub const LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_SPONSOR_DRAIN_BPS: u64 = 8_200;
pub const LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_THROTTLE_BPS: u64 = 6_600;
pub const LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_RELEASE_BPS: u64 = 5_200;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    PublicTransfer,
    PrivateTransfer,
    PrivateContractGas,
    ProofMarket,
    MoneroExit,
    SponsoredFee,
    BatchNetting,
    OperatorRecovery,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicTransfer => "public_transfer",
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateContractGas => "private_contract_gas",
            Self::ProofMarket => "proof_market",
            Self::MoneroExit => "monero_exit",
            Self::SponsoredFee => "sponsored_fee",
            Self::BatchNetting => "batch_netting",
            Self::OperatorRecovery => "operator_recovery",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::MoneroExit => 1_000,
            Self::PrivateContractGas => 940,
            Self::ProofMarket => 910,
            Self::PrivateTransfer => 820,
            Self::BatchNetting => 760,
            Self::SponsoredFee => 690,
            Self::PublicTransfer => 640,
            Self::OperatorRecovery => 520,
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::PrivateTransfer
                | Self::PrivateContractGas
                | Self::MoneroExit
                | Self::SponsoredFee
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StressBand {
    Idle,
    Nominal,
    Elevated,
    Congested,
    Critical,
}

impl StressBand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Nominal => "nominal",
            Self::Elevated => "elevated",
            Self::Congested => "congested",
            Self::Critical => "critical",
        }
    }

    pub fn from_bps(value: u64) -> Self {
        if value >= 9_000 {
            Self::Critical
        } else if value >= 7_500 {
            Self::Congested
        } else if value >= 5_500 {
            Self::Elevated
        } else if value == 0 {
            Self::Idle
        } else {
            Self::Nominal
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThrottleAction {
    Admit,
    Shape,
    Defer,
    Reroute,
    Shed,
    EmergencyHold,
}

impl ThrottleAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Shape => "shape",
            Self::Defer => "defer",
            Self::Reroute => "reroute",
            Self::Shed => "shed",
            Self::EmergencyHold => "emergency_hold",
        }
    }

    pub fn blocks_liveness(self) -> bool {
        matches!(self, Self::Shed | Self::EmergencyHold)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Open,
    Reserved,
    Consumed,
    Deferred,
    Expired,
    Revoked,
}

impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Deferred => "deferred",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Reserved | Self::Deferred)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Planned,
    Open,
    Saturated,
    Draining,
    Sealed,
    Cancelled,
}

impl WindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Open => "open",
            Self::Saturated => "saturated",
            Self::Draining => "draining",
            Self::Sealed => "sealed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Planned | Self::Open | Self::Saturated | Self::Draining
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeCeilingMode {
    Baseline,
    Tightened,
    Emergency,
    SponsorOnly,
    Released,
}

impl FeeCeilingMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Tightened => "tightened",
            Self::Emergency => "emergency",
            Self::SponsorOnly => "sponsor_only",
            Self::Released => "released",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CongestionSource {
    SequencerCpu,
    DaBytes,
    ProofBids,
    MoneroLiquidity,
    PrivateGas,
    SponsorBudget,
    NettingBacklog,
}

impl CongestionSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerCpu => "sequencer_cpu",
            Self::DaBytes => "da_bytes",
            Self::ProofBids => "proof_bids",
            Self::MoneroLiquidity => "monero_liquidity",
            Self::PrivateGas => "private_gas",
            Self::SponsorBudget => "sponsor_budget",
            Self::NettingBacklog => "netting_backlog",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingStatus {
    Open,
    Balancing,
    Posted,
    Settled,
    Disputed,
    Expired,
}

impl NettingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Balancing => "balancing",
            Self::Posted => "posted",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Balancing | Self::Posted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Active,
    Guarded,
    Draining,
    Exhausted,
    Paused,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Guarded => "guarded",
            Self::Draining => "draining",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
        }
    }

    pub fn can_pay(self) -> bool {
        matches!(self, Self::Active | Self::Guarded | Self::Draining)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub epoch_blocks: u64,
    pub burst_window_blocks: u64,
    pub fairness_ticket_ttl_blocks: u64,
    pub max_queue_depth: u64,
    pub low_fee_ceiling_micro_denom: u64,
    pub min_privacy_set_size: u64,
    pub proof_congestion_bps: u64,
    pub monero_exit_congestion_bps: u64,
    pub contract_gas_congestion_bps: u64,
    pub sponsor_drain_bps: u64,
    pub throttle_bps: u64,
    pub release_bps: u64,
    pub fairness_seed_root: String,
    pub operator_set_root: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: LOW_FEE_LANE_STRESS_CONTROLLER_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            epoch_blocks: LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_EPOCH_BLOCKS,
            burst_window_blocks: LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_BURST_WINDOW_BLOCKS,
            fairness_ticket_ttl_blocks: LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_TICKET_TTL_BLOCKS,
            max_queue_depth: LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_MAX_QUEUE_DEPTH,
            low_fee_ceiling_micro_denom:
                LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_LOW_FEE_CEILING_MICRO_DENOM,
            min_privacy_set_size: LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            proof_congestion_bps: LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_PROOF_CONGESTION_BPS,
            monero_exit_congestion_bps: LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_EXIT_CONGESTION_BPS,
            contract_gas_congestion_bps:
                LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_CONTRACT_GAS_CONGESTION_BPS,
            sponsor_drain_bps: LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_SPONSOR_DRAIN_BPS,
            throttle_bps: LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_THROTTLE_BPS,
            release_bps: LOW_FEE_LANE_STRESS_CONTROLLER_DEFAULT_RELEASE_BPS,
            fairness_seed_root: scoped_seed("fairness-seed-root"),
            operator_set_root: scoped_seed("operator-set-root"),
        }
    }
}

impl Config {
    pub fn validate(&self) -> LowFeeLaneStressControllerResult<()> {
        if self.protocol_version != LOW_FEE_LANE_STRESS_CONTROLLER_PROTOCOL_VERSION {
            return Err("low fee lane stress controller protocol version mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("low fee lane stress controller chain id mismatch".to_string());
        }
        if self.epoch_blocks == 0 {
            return Err("low fee lane stress controller epoch_blocks must be positive".to_string());
        }
        if self.burst_window_blocks == 0 {
            return Err(
                "low fee lane stress controller burst_window_blocks must be positive".to_string(),
            );
        }
        if self.fairness_ticket_ttl_blocks == 0 {
            return Err(
                "low fee lane stress controller fairness_ticket_ttl_blocks must be positive"
                    .to_string(),
            );
        }
        if self.release_bps > self.throttle_bps {
            return Err(
                "low fee lane stress controller release_bps must not exceed throttle_bps"
                    .to_string(),
            );
        }
        for (label, value) in [
            ("proof_congestion_bps", self.proof_congestion_bps),
            (
                "monero_exit_congestion_bps",
                self.monero_exit_congestion_bps,
            ),
            (
                "contract_gas_congestion_bps",
                self.contract_gas_congestion_bps,
            ),
            ("sponsor_drain_bps", self.sponsor_drain_bps),
            ("throttle_bps", self.throttle_bps),
            ("release_bps", self.release_bps),
        ] {
            if value > LOW_FEE_LANE_STRESS_CONTROLLER_MAX_BPS {
                return Err(format!(
                    "low fee lane stress controller {label} exceeds max bps"
                ));
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "epoch_blocks": self.epoch_blocks.to_string(),
            "burst_window_blocks": self.burst_window_blocks.to_string(),
            "fairness_ticket_ttl_blocks": self.fairness_ticket_ttl_blocks.to_string(),
            "max_queue_depth": self.max_queue_depth.to_string(),
            "low_fee_ceiling_micro_denom": self.low_fee_ceiling_micro_denom.to_string(),
            "min_privacy_set_size": self.min_privacy_set_size.to_string(),
            "proof_congestion_bps": self.proof_congestion_bps.to_string(),
            "monero_exit_congestion_bps": self.monero_exit_congestion_bps.to_string(),
            "contract_gas_congestion_bps": self.contract_gas_congestion_bps.to_string(),
            "sponsor_drain_bps": self.sponsor_drain_bps.to_string(),
            "throttle_bps": self.throttle_bps.to_string(),
            "release_bps": self.release_bps.to_string(),
            "fairness_seed_root": self.fairness_seed_root,
            "operator_set_root": self.operator_set_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneMeter {
    pub lane_id: String,
    pub kind: LaneKind,
    pub sequencer_id: String,
    pub capacity_units: u64,
    pub queued_units: u64,
    pub admitted_units: u64,
    pub deferred_units: u64,
    pub shed_units: u64,
    pub max_fee_micro_denom: u64,
    pub observed_fee_micro_denom: u64,
    pub privacy_set_size: u64,
    pub stress_bps: u64,
    pub last_updated_height: u64,
}

impl LaneMeter {
    pub fn stress_band(&self) -> StressBand {
        StressBand::from_bps(self.stress_bps)
    }

    pub fn queue_bps(&self) -> u64 {
        ratio_bps(self.queued_units, self.capacity_units)
    }

    pub fn remaining_capacity(&self) -> u64 {
        self.capacity_units.saturating_sub(self.admitted_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "sequencer_id": self.sequencer_id,
            "capacity_units": self.capacity_units.to_string(),
            "queued_units": self.queued_units.to_string(),
            "admitted_units": self.admitted_units.to_string(),
            "deferred_units": self.deferred_units.to_string(),
            "shed_units": self.shed_units.to_string(),
            "max_fee_micro_denom": self.max_fee_micro_denom.to_string(),
            "observed_fee_micro_denom": self.observed_fee_micro_denom.to_string(),
            "privacy_set_size": self.privacy_set_size.to_string(),
            "stress_bps": self.stress_bps.to_string(),
            "stress_band": self.stress_band().as_str(),
            "queue_bps": self.queue_bps().to_string(),
            "remaining_capacity": self.remaining_capacity().to_string(),
            "priority_weight": self.kind.priority_weight().to_string(),
            "privacy_sensitive": self.kind.privacy_sensitive(),
            "last_updated_height": self.last_updated_height.to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofMarketPressure {
    pub market_id: String,
    pub circuit_family: String,
    pub pending_proofs: u64,
    pub available_provers: u64,
    pub median_bid_micro_denom: u64,
    pub max_low_fee_bid_micro_denom: u64,
    pub congestion_bps: u64,
    pub proof_deadline_height: u64,
    pub settlement_lane_id: String,
}

impl ProofMarketPressure {
    pub fn bid_over_ceiling(&self) -> bool {
        self.median_bid_micro_denom > self.max_low_fee_bid_micro_denom
    }

    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "circuit_family": self.circuit_family,
            "pending_proofs": self.pending_proofs.to_string(),
            "available_provers": self.available_provers.to_string(),
            "median_bid_micro_denom": self.median_bid_micro_denom.to_string(),
            "max_low_fee_bid_micro_denom": self.max_low_fee_bid_micro_denom.to_string(),
            "congestion_bps": self.congestion_bps.to_string(),
            "stress_band": StressBand::from_bps(self.congestion_bps).as_str(),
            "bid_over_ceiling": self.bid_over_ceiling(),
            "proof_deadline_height": self.proof_deadline_height.to_string(),
            "settlement_lane_id": self.settlement_lane_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroExitPressure {
    pub exit_id: String,
    pub lane_id: String,
    pub bridge_liquidity_commitment: String,
    pub pending_exits: u64,
    pub spendable_outputs: u64,
    pub reorg_buffer_blocks: u64,
    pub privacy_set_size: u64,
    pub congestion_bps: u64,
    pub next_release_height: u64,
}

impl MoneroExitPressure {
    pub fn liquidity_gap(&self) -> u64 {
        self.pending_exits.saturating_sub(self.spendable_outputs)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "exit_id": self.exit_id,
            "lane_id": self.lane_id,
            "bridge_liquidity_commitment": self.bridge_liquidity_commitment,
            "pending_exits": self.pending_exits.to_string(),
            "spendable_outputs": self.spendable_outputs.to_string(),
            "liquidity_gap": self.liquidity_gap().to_string(),
            "reorg_buffer_blocks": self.reorg_buffer_blocks.to_string(),
            "privacy_set_size": self.privacy_set_size.to_string(),
            "congestion_bps": self.congestion_bps.to_string(),
            "stress_band": StressBand::from_bps(self.congestion_bps).as_str(),
            "next_release_height": self.next_release_height.to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractGasPressure {
    pub gas_market_id: String,
    pub lane_id: String,
    pub contract_family: String,
    pub encrypted_call_count: u64,
    pub witness_bytes: u64,
    pub recursive_proof_depth: u64,
    pub target_gas_units: u64,
    pub consumed_gas_units: u64,
    pub congestion_bps: u64,
}

impl PrivateContractGasPressure {
    pub fn gas_bps(&self) -> u64 {
        ratio_bps(self.consumed_gas_units, self.target_gas_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "gas_market_id": self.gas_market_id,
            "lane_id": self.lane_id,
            "contract_family": self.contract_family,
            "encrypted_call_count": self.encrypted_call_count.to_string(),
            "witness_bytes": self.witness_bytes.to_string(),
            "recursive_proof_depth": self.recursive_proof_depth.to_string(),
            "target_gas_units": self.target_gas_units.to_string(),
            "consumed_gas_units": self.consumed_gas_units.to_string(),
            "gas_bps": self.gas_bps().to_string(),
            "congestion_bps": self.congestion_bps.to_string(),
            "stress_band": StressBand::from_bps(self.congestion_bps).as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsoredFeePool {
    pub sponsor_id: String,
    pub lane_id: String,
    pub status: SponsorStatus,
    pub budget_micro_denom: u64,
    pub reserved_micro_denom: u64,
    pub spent_micro_denom: u64,
    pub max_per_ticket_micro_denom: u64,
    pub drain_bps: u64,
    pub credential_root: String,
}

impl SponsoredFeePool {
    pub fn remaining_budget(&self) -> u64 {
        self.budget_micro_denom
            .saturating_sub(self.reserved_micro_denom)
            .saturating_sub(self.spent_micro_denom)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "can_pay": self.status.can_pay(),
            "budget_micro_denom": self.budget_micro_denom.to_string(),
            "reserved_micro_denom": self.reserved_micro_denom.to_string(),
            "spent_micro_denom": self.spent_micro_denom.to_string(),
            "remaining_budget": self.remaining_budget().to_string(),
            "max_per_ticket_micro_denom": self.max_per_ticket_micro_denom.to_string(),
            "drain_bps": self.drain_bps.to_string(),
            "credential_root": self.credential_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurstWindow {
    pub window_id: String,
    pub lane_id: String,
    pub status: WindowStatus,
    pub start_height: u64,
    pub end_height: u64,
    pub target_units: u64,
    pub consumed_units: u64,
    pub reserved_tickets: u64,
    pub fairness_salt_root: String,
}

impl BurstWindow {
    pub fn utilization_bps(&self) -> u64 {
        ratio_bps(self.consumed_units, self.target_units)
    }

    pub fn contains_height(&self, height: u64) -> bool {
        height >= self.start_height && height <= self.end_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "active": self.status.active(),
            "start_height": self.start_height.to_string(),
            "end_height": self.end_height.to_string(),
            "target_units": self.target_units.to_string(),
            "consumed_units": self.consumed_units.to_string(),
            "utilization_bps": self.utilization_bps().to_string(),
            "reserved_tickets": self.reserved_tickets.to_string(),
            "fairness_salt_root": self.fairness_salt_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeCeiling {
    pub ceiling_id: String,
    pub lane_id: String,
    pub mode: FeeCeilingMode,
    pub baseline_micro_denom: u64,
    pub current_micro_denom: u64,
    pub min_micro_denom: u64,
    pub max_micro_denom: u64,
    pub sponsor_discount_bps: u64,
    pub expires_at_height: u64,
}

impl FeeCeiling {
    pub fn tightened_bps(&self) -> u64 {
        let reduction = self
            .baseline_micro_denom
            .saturating_sub(self.current_micro_denom);
        ratio_bps(reduction, self.baseline_micro_denom)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ceiling_id": self.ceiling_id,
            "lane_id": self.lane_id,
            "mode": self.mode.as_str(),
            "baseline_micro_denom": self.baseline_micro_denom.to_string(),
            "current_micro_denom": self.current_micro_denom.to_string(),
            "min_micro_denom": self.min_micro_denom.to_string(),
            "max_micro_denom": self.max_micro_denom.to_string(),
            "tightened_bps": self.tightened_bps().to_string(),
            "sponsor_discount_bps": self.sponsor_discount_bps.to_string(),
            "expires_at_height": self.expires_at_height.to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FairnessTicket {
    pub ticket_id: String,
    pub lane_id: String,
    pub account_commitment: String,
    pub status: TicketStatus,
    pub priority_weight: u64,
    pub max_fee_micro_denom: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub nullifier_commitment: String,
}

impl FairnessTicket {
    pub fn expired_at(&self, height: u64) -> bool {
        height > self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "lane_id": self.lane_id,
            "account_commitment": self.account_commitment,
            "status": self.status.as_str(),
            "live": self.status.live(),
            "priority_weight": self.priority_weight.to_string(),
            "max_fee_micro_denom": self.max_fee_micro_denom.to_string(),
            "issued_at_height": self.issued_at_height.to_string(),
            "expires_at_height": self.expires_at_height.to_string(),
            "nullifier_commitment": self.nullifier_commitment,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchNettingPosition {
    pub batch_id: String,
    pub lane_id: String,
    pub status: NettingStatus,
    pub debit_units: u64,
    pub credit_units: u64,
    pub participants: u64,
    pub proof_commitment: String,
    pub settlement_height: u64,
}

impl BatchNettingPosition {
    pub fn imbalance_units(&self) -> u64 {
        if self.debit_units >= self.credit_units {
            self.debit_units.saturating_sub(self.credit_units)
        } else {
            self.credit_units.saturating_sub(self.debit_units)
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "live": self.status.live(),
            "debit_units": self.debit_units.to_string(),
            "credit_units": self.credit_units.to_string(),
            "imbalance_units": self.imbalance_units().to_string(),
            "participants": self.participants.to_string(),
            "proof_commitment": self.proof_commitment,
            "settlement_height": self.settlement_height.to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CongestionSignal {
    pub signal_id: String,
    pub lane_id: String,
    pub source: CongestionSource,
    pub observed_bps: u64,
    pub threshold_bps: u64,
    pub sample_count: u64,
    pub evidence_root: String,
    pub height: u64,
}

impl CongestionSignal {
    pub fn exceeds_threshold(&self) -> bool {
        self.observed_bps >= self.threshold_bps
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signal_id": self.signal_id,
            "lane_id": self.lane_id,
            "source": self.source.as_str(),
            "observed_bps": self.observed_bps.to_string(),
            "threshold_bps": self.threshold_bps.to_string(),
            "sample_count": self.sample_count.to_string(),
            "exceeds_threshold": self.exceeds_threshold(),
            "stress_band": StressBand::from_bps(self.observed_bps).as_str(),
            "evidence_root": self.evidence_root,
            "height": self.height.to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThrottlingDecision {
    pub decision_id: String,
    pub lane_id: String,
    pub action: ThrottleAction,
    pub reason: String,
    pub stress_bps: u64,
    pub allowed_units: u64,
    pub deferred_units: u64,
    pub fee_ceiling_micro_denom: u64,
    pub fairness_ticket_root: String,
    pub valid_until_height: u64,
}

impl ThrottlingDecision {
    pub fn public_record(&self) -> Value {
        json!({
            "decision_id": self.decision_id,
            "lane_id": self.lane_id,
            "action": self.action.as_str(),
            "blocks_liveness": self.action.blocks_liveness(),
            "reason": self.reason,
            "stress_bps": self.stress_bps.to_string(),
            "stress_band": StressBand::from_bps(self.stress_bps).as_str(),
            "allowed_units": self.allowed_units.to_string(),
            "deferred_units": self.deferred_units.to_string(),
            "fee_ceiling_micro_denom": self.fee_ceiling_micro_denom.to_string(),
            "fairness_ticket_root": self.fairness_ticket_root,
            "valid_until_height": self.valid_until_height.to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StressAuditEvent {
    pub event_id: String,
    pub lane_id: String,
    pub label: String,
    pub subject_root: String,
    pub before_root: String,
    pub after_root: String,
    pub height: u64,
}

impl StressAuditEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "lane_id": self.lane_id,
            "label": self.label,
            "subject_root": self.subject_root,
            "before_root": self.before_root,
            "after_root": self.after_root,
            "height": self.height.to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub lane_meter_root: String,
    pub proof_market_root: String,
    pub monero_exit_root: String,
    pub private_contract_gas_root: String,
    pub sponsor_pool_root: String,
    pub burst_window_root: String,
    pub fee_ceiling_root: String,
    pub fairness_ticket_root: String,
    pub batch_netting_root: String,
    pub congestion_signal_root: String,
    pub throttling_decision_root: String,
    pub audit_event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_meter_root": self.lane_meter_root,
            "proof_market_root": self.proof_market_root,
            "monero_exit_root": self.monero_exit_root,
            "private_contract_gas_root": self.private_contract_gas_root,
            "sponsor_pool_root": self.sponsor_pool_root,
            "burst_window_root": self.burst_window_root,
            "fee_ceiling_root": self.fee_ceiling_root,
            "fairness_ticket_root": self.fairness_ticket_root,
            "batch_netting_root": self.batch_netting_root,
            "congestion_signal_root": self.congestion_signal_root,
            "throttling_decision_root": self.throttling_decision_root,
            "audit_event_root": self.audit_event_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub lane_count: u64,
    pub active_lane_count: u64,
    pub proof_market_count: u64,
    pub congested_proof_market_count: u64,
    pub monero_exit_count: u64,
    pub congested_monero_exit_count: u64,
    pub private_contract_gas_count: u64,
    pub sponsor_pool_count: u64,
    pub draining_sponsor_pool_count: u64,
    pub burst_window_count: u64,
    pub active_burst_window_count: u64,
    pub fee_ceiling_count: u64,
    pub tightened_fee_ceiling_count: u64,
    pub fairness_ticket_count: u64,
    pub live_fairness_ticket_count: u64,
    pub batch_netting_count: u64,
    pub live_batch_netting_count: u64,
    pub congestion_signal_count: u64,
    pub triggered_congestion_signal_count: u64,
    pub throttling_decision_count: u64,
    pub liveness_blocking_decision_count: u64,
    pub audit_event_count: u64,
    pub total_queued_units: u64,
    pub total_admitted_units: u64,
    pub total_deferred_units: u64,
    pub total_shed_units: u64,
    pub max_lane_stress_bps: u64,
    pub weighted_lane_stress_bps: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_count": self.lane_count.to_string(),
            "active_lane_count": self.active_lane_count.to_string(),
            "proof_market_count": self.proof_market_count.to_string(),
            "congested_proof_market_count": self.congested_proof_market_count.to_string(),
            "monero_exit_count": self.monero_exit_count.to_string(),
            "congested_monero_exit_count": self.congested_monero_exit_count.to_string(),
            "private_contract_gas_count": self.private_contract_gas_count.to_string(),
            "sponsor_pool_count": self.sponsor_pool_count.to_string(),
            "draining_sponsor_pool_count": self.draining_sponsor_pool_count.to_string(),
            "burst_window_count": self.burst_window_count.to_string(),
            "active_burst_window_count": self.active_burst_window_count.to_string(),
            "fee_ceiling_count": self.fee_ceiling_count.to_string(),
            "tightened_fee_ceiling_count": self.tightened_fee_ceiling_count.to_string(),
            "fairness_ticket_count": self.fairness_ticket_count.to_string(),
            "live_fairness_ticket_count": self.live_fairness_ticket_count.to_string(),
            "batch_netting_count": self.batch_netting_count.to_string(),
            "live_batch_netting_count": self.live_batch_netting_count.to_string(),
            "congestion_signal_count": self.congestion_signal_count.to_string(),
            "triggered_congestion_signal_count": self.triggered_congestion_signal_count.to_string(),
            "throttling_decision_count": self.throttling_decision_count.to_string(),
            "liveness_blocking_decision_count": self.liveness_blocking_decision_count.to_string(),
            "audit_event_count": self.audit_event_count.to_string(),
            "total_queued_units": self.total_queued_units.to_string(),
            "total_admitted_units": self.total_admitted_units.to_string(),
            "total_deferred_units": self.total_deferred_units.to_string(),
            "total_shed_units": self.total_shed_units.to_string(),
            "max_lane_stress_bps": self.max_lane_stress_bps.to_string(),
            "weighted_lane_stress_bps": self.weighted_lane_stress_bps.to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub lane_meters: BTreeMap<String, LaneMeter>,
    pub proof_markets: BTreeMap<String, ProofMarketPressure>,
    pub monero_exits: BTreeMap<String, MoneroExitPressure>,
    pub private_contract_gas: BTreeMap<String, PrivateContractGasPressure>,
    pub sponsor_pools: BTreeMap<String, SponsoredFeePool>,
    pub burst_windows: BTreeMap<String, BurstWindow>,
    pub fee_ceilings: BTreeMap<String, FeeCeiling>,
    pub fairness_tickets: BTreeMap<String, FairnessTicket>,
    pub batch_netting: BTreeMap<String, BatchNettingPosition>,
    pub congestion_signals: BTreeMap<String, CongestionSignal>,
    pub throttling_decisions: BTreeMap<String, ThrottlingDecision>,
    pub audit_events: BTreeMap<String, StressAuditEvent>,
}

impl State {
    pub fn devnet() -> LowFeeLaneStressControllerResult<Self> {
        let height = LOW_FEE_LANE_STRESS_CONTROLLER_DEVNET_HEIGHT;
        let mut state = Self {
            height,
            config: Config::default(),
            lane_meters: BTreeMap::new(),
            proof_markets: BTreeMap::new(),
            monero_exits: BTreeMap::new(),
            private_contract_gas: BTreeMap::new(),
            sponsor_pools: BTreeMap::new(),
            burst_windows: BTreeMap::new(),
            fee_ceilings: BTreeMap::new(),
            fairness_tickets: BTreeMap::new(),
            batch_netting: BTreeMap::new(),
            congestion_signals: BTreeMap::new(),
            throttling_decisions: BTreeMap::new(),
            audit_events: BTreeMap::new(),
        };
        state.install_devnet_lanes();
        state.install_devnet_pressures();
        state.install_devnet_windows();
        state.install_devnet_tickets();
        state.install_devnet_decisions();
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> LowFeeLaneStressControllerResult<()> {
        self.config.validate()?;
        for (key, lane) in &self.lane_meters {
            require_key(key, &lane.lane_id, "lane meter")?;
            if lane.capacity_units == 0 {
                return Err(format!("lane meter {key} capacity_units must be positive"));
            }
            if lane.queued_units > self.config.max_queue_depth {
                return Err(format!(
                    "lane meter {key} queued_units exceeds max queue depth"
                ));
            }
            if lane.stress_bps > LOW_FEE_LANE_STRESS_CONTROLLER_MAX_BPS {
                return Err(format!("lane meter {key} stress_bps exceeds max bps"));
            }
            if lane.privacy_set_size < self.config.min_privacy_set_size
                && lane.kind.privacy_sensitive()
            {
                return Err(format!(
                    "lane meter {key} privacy set below controller minimum"
                ));
            }
        }
        for (key, market) in &self.proof_markets {
            require_key(key, &market.market_id, "proof market")?;
            require_lane(
                &self.lane_meters,
                &market.settlement_lane_id,
                "proof market",
            )?;
            require_bps(market.congestion_bps, "proof market congestion")?;
        }
        for (key, exit) in &self.monero_exits {
            require_key(key, &exit.exit_id, "monero exit")?;
            require_lane(&self.lane_meters, &exit.lane_id, "monero exit")?;
            require_bps(exit.congestion_bps, "monero exit congestion")?;
        }
        for (key, gas) in &self.private_contract_gas {
            require_key(key, &gas.gas_market_id, "private contract gas")?;
            require_lane(&self.lane_meters, &gas.lane_id, "private contract gas")?;
            require_bps(gas.congestion_bps, "private contract gas congestion")?;
            if gas.target_gas_units == 0 {
                return Err(format!(
                    "private contract gas {key} target_gas_units must be positive"
                ));
            }
        }
        for (key, pool) in &self.sponsor_pools {
            require_key(key, &pool.sponsor_id, "sponsor pool")?;
            require_lane(&self.lane_meters, &pool.lane_id, "sponsor pool")?;
            require_bps(pool.drain_bps, "sponsor drain")?;
            if pool
                .reserved_micro_denom
                .saturating_add(pool.spent_micro_denom)
                > pool.budget_micro_denom
            {
                return Err(format!("sponsor pool {key} exceeds budget"));
            }
        }
        for (key, window) in &self.burst_windows {
            require_key(key, &window.window_id, "burst window")?;
            require_lane(&self.lane_meters, &window.lane_id, "burst window")?;
            if window.start_height > window.end_height {
                return Err(format!(
                    "burst window {key} start height exceeds end height"
                ));
            }
            if window.target_units == 0 {
                return Err(format!("burst window {key} target_units must be positive"));
            }
        }
        for (key, ceiling) in &self.fee_ceilings {
            require_key(key, &ceiling.ceiling_id, "fee ceiling")?;
            require_lane(&self.lane_meters, &ceiling.lane_id, "fee ceiling")?;
            require_bps(ceiling.sponsor_discount_bps, "fee ceiling sponsor discount")?;
            if ceiling.min_micro_denom > ceiling.current_micro_denom
                || ceiling.current_micro_denom > ceiling.max_micro_denom
            {
                return Err(format!("fee ceiling {key} current value outside bounds"));
            }
        }
        for (key, ticket) in &self.fairness_tickets {
            require_key(key, &ticket.ticket_id, "fairness ticket")?;
            require_lane(&self.lane_meters, &ticket.lane_id, "fairness ticket")?;
            if ticket.issued_at_height > ticket.expires_at_height {
                return Err(format!("fairness ticket {key} expires before issue height"));
            }
        }
        for (key, batch) in &self.batch_netting {
            require_key(key, &batch.batch_id, "batch netting")?;
            require_lane(&self.lane_meters, &batch.lane_id, "batch netting")?;
            if batch.participants == 0 {
                return Err(format!("batch netting {key} participants must be positive"));
            }
        }
        for (key, signal) in &self.congestion_signals {
            require_key(key, &signal.signal_id, "congestion signal")?;
            require_lane(&self.lane_meters, &signal.lane_id, "congestion signal")?;
            require_bps(signal.observed_bps, "congestion signal observed")?;
            require_bps(signal.threshold_bps, "congestion signal threshold")?;
        }
        for (key, decision) in &self.throttling_decisions {
            require_key(key, &decision.decision_id, "throttling decision")?;
            require_lane(&self.lane_meters, &decision.lane_id, "throttling decision")?;
            require_bps(decision.stress_bps, "throttling decision stress")?;
        }
        for (key, event) in &self.audit_events {
            require_key(key, &event.event_id, "audit event")?;
            require_lane(&self.lane_meters, &event.lane_id, "audit event")?;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> LowFeeLaneStressControllerResult<()> {
        self.height = height;
        self.refresh_height_sensitive_status();
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> LowFeeLaneStressControllerResult<()> {
        self.set_height(height)
    }

    pub fn roots(&self) -> Roots {
        let config_root = root_from_record(&self.config.public_record());
        let lane_meter_root = map_root(
            "LOW-FEE-LANE-STRESS-LANE-METER",
            &self.lane_meters,
            LaneMeter::public_record,
        );
        let proof_market_root = map_root(
            "LOW-FEE-LANE-STRESS-PROOF-MARKET",
            &self.proof_markets,
            ProofMarketPressure::public_record,
        );
        let monero_exit_root = map_root(
            "LOW-FEE-LANE-STRESS-MONERO-EXIT",
            &self.monero_exits,
            MoneroExitPressure::public_record,
        );
        let private_contract_gas_root = map_root(
            "LOW-FEE-LANE-STRESS-PRIVATE-CONTRACT-GAS",
            &self.private_contract_gas,
            PrivateContractGasPressure::public_record,
        );
        let sponsor_pool_root = map_root(
            "LOW-FEE-LANE-STRESS-SPONSOR-POOL",
            &self.sponsor_pools,
            SponsoredFeePool::public_record,
        );
        let burst_window_root = map_root(
            "LOW-FEE-LANE-STRESS-BURST-WINDOW",
            &self.burst_windows,
            BurstWindow::public_record,
        );
        let fee_ceiling_root = map_root(
            "LOW-FEE-LANE-STRESS-FEE-CEILING",
            &self.fee_ceilings,
            FeeCeiling::public_record,
        );
        let fairness_ticket_root = map_root(
            "LOW-FEE-LANE-STRESS-FAIRNESS-TICKET",
            &self.fairness_tickets,
            FairnessTicket::public_record,
        );
        let batch_netting_root = map_root(
            "LOW-FEE-LANE-STRESS-BATCH-NETTING",
            &self.batch_netting,
            BatchNettingPosition::public_record,
        );
        let congestion_signal_root = map_root(
            "LOW-FEE-LANE-STRESS-CONGESTION-SIGNAL",
            &self.congestion_signals,
            CongestionSignal::public_record,
        );
        let throttling_decision_root = map_root(
            "LOW-FEE-LANE-STRESS-THROTTLING-DECISION",
            &self.throttling_decisions,
            ThrottlingDecision::public_record,
        );
        let audit_event_root = map_root(
            "LOW-FEE-LANE-STRESS-AUDIT-EVENT",
            &self.audit_events,
            StressAuditEvent::public_record,
        );
        let state_payload = json!({
            "height": self.height.to_string(),
            "config_root": config_root,
            "lane_meter_root": lane_meter_root,
            "proof_market_root": proof_market_root,
            "monero_exit_root": monero_exit_root,
            "private_contract_gas_root": private_contract_gas_root,
            "sponsor_pool_root": sponsor_pool_root,
            "burst_window_root": burst_window_root,
            "fee_ceiling_root": fee_ceiling_root,
            "fairness_ticket_root": fairness_ticket_root,
            "batch_netting_root": batch_netting_root,
            "congestion_signal_root": congestion_signal_root,
            "throttling_decision_root": throttling_decision_root,
            "audit_event_root": audit_event_root,
        });
        let state_root = root_from_record(&state_payload);
        Roots {
            config_root,
            lane_meter_root,
            proof_market_root,
            monero_exit_root,
            private_contract_gas_root,
            sponsor_pool_root,
            burst_window_root,
            fee_ceiling_root,
            fairness_ticket_root,
            batch_netting_root,
            congestion_signal_root,
            throttling_decision_root,
            audit_event_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        let total_queued_units = self
            .lane_meters
            .values()
            .map(|lane| lane.queued_units)
            .sum::<u64>();
        let total_admitted_units = self
            .lane_meters
            .values()
            .map(|lane| lane.admitted_units)
            .sum::<u64>();
        let total_deferred_units = self
            .lane_meters
            .values()
            .map(|lane| lane.deferred_units)
            .sum::<u64>();
        let total_shed_units = self
            .lane_meters
            .values()
            .map(|lane| lane.shed_units)
            .sum::<u64>();
        let max_lane_stress_bps = self
            .lane_meters
            .values()
            .map(|lane| lane.stress_bps)
            .fold(0, u64::max);
        let weighted_numerator = self
            .lane_meters
            .values()
            .map(|lane| lane.stress_bps.saturating_mul(lane.kind.priority_weight()))
            .sum::<u64>();
        let weighted_denominator = self
            .lane_meters
            .values()
            .map(|lane| lane.kind.priority_weight())
            .sum::<u64>();
        Counters {
            lane_count: self.lane_meters.len() as u64,
            active_lane_count: self
                .lane_meters
                .values()
                .filter(|lane| lane.remaining_capacity() > 0)
                .count() as u64,
            proof_market_count: self.proof_markets.len() as u64,
            congested_proof_market_count: self
                .proof_markets
                .values()
                .filter(|market| market.congestion_bps >= self.config.proof_congestion_bps)
                .count() as u64,
            monero_exit_count: self.monero_exits.len() as u64,
            congested_monero_exit_count: self
                .monero_exits
                .values()
                .filter(|exit| exit.congestion_bps >= self.config.monero_exit_congestion_bps)
                .count() as u64,
            private_contract_gas_count: self.private_contract_gas.len() as u64,
            sponsor_pool_count: self.sponsor_pools.len() as u64,
            draining_sponsor_pool_count: self
                .sponsor_pools
                .values()
                .filter(|pool| pool.drain_bps >= self.config.sponsor_drain_bps)
                .count() as u64,
            burst_window_count: self.burst_windows.len() as u64,
            active_burst_window_count: self
                .burst_windows
                .values()
                .filter(|window| window.status.active() && window.contains_height(self.height))
                .count() as u64,
            fee_ceiling_count: self.fee_ceilings.len() as u64,
            tightened_fee_ceiling_count: self
                .fee_ceilings
                .values()
                .filter(|ceiling| {
                    matches!(
                        ceiling.mode,
                        FeeCeilingMode::Tightened
                            | FeeCeilingMode::Emergency
                            | FeeCeilingMode::SponsorOnly
                    )
                })
                .count() as u64,
            fairness_ticket_count: self.fairness_tickets.len() as u64,
            live_fairness_ticket_count: self
                .fairness_tickets
                .values()
                .filter(|ticket| ticket.status.live() && !ticket.expired_at(self.height))
                .count() as u64,
            batch_netting_count: self.batch_netting.len() as u64,
            live_batch_netting_count: self
                .batch_netting
                .values()
                .filter(|batch| batch.status.live())
                .count() as u64,
            congestion_signal_count: self.congestion_signals.len() as u64,
            triggered_congestion_signal_count: self
                .congestion_signals
                .values()
                .filter(|signal| signal.exceeds_threshold())
                .count() as u64,
            throttling_decision_count: self.throttling_decisions.len() as u64,
            liveness_blocking_decision_count: self
                .throttling_decisions
                .values()
                .filter(|decision| decision.action.blocks_liveness())
                .count() as u64,
            audit_event_count: self.audit_events.len() as u64,
            total_queued_units,
            total_admitted_units,
            total_deferred_units,
            total_shed_units,
            max_lane_stress_bps,
            weighted_lane_stress_bps: divide_or_zero(weighted_numerator, weighted_denominator),
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": LOW_FEE_LANE_STRESS_CONTROLLER_PROTOCOL_VERSION,
            "height": self.height.to_string(),
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "lane_meters": records_from_map(&self.lane_meters, LaneMeter::public_record),
            "proof_markets": records_from_map(&self.proof_markets, ProofMarketPressure::public_record),
            "monero_exits": records_from_map(&self.monero_exits, MoneroExitPressure::public_record),
            "private_contract_gas": records_from_map(&self.private_contract_gas, PrivateContractGasPressure::public_record),
            "sponsor_pools": records_from_map(&self.sponsor_pools, SponsoredFeePool::public_record),
            "burst_windows": records_from_map(&self.burst_windows, BurstWindow::public_record),
            "fee_ceilings": records_from_map(&self.fee_ceilings, FeeCeiling::public_record),
            "fairness_tickets": records_from_map(&self.fairness_tickets, FairnessTicket::public_record),
            "batch_netting": records_from_map(&self.batch_netting, BatchNettingPosition::public_record),
            "congestion_signals": records_from_map(&self.congestion_signals, CongestionSignal::public_record),
            "throttling_decisions": records_from_map(&self.throttling_decisions, ThrottlingDecision::public_record),
            "audit_events": records_from_map(&self.audit_events, StressAuditEvent::public_record),
        })
    }

    fn install_devnet_lanes(&mut self) {
        for (lane_id, kind, capacity, queued, admitted, deferred, shed, fee, stress, privacy) in [
            (
                "lane:public:low-fee-transfer",
                LaneKind::PublicTransfer,
                14_000,
                4_200,
                7_800,
                160,
                0,
                28,
                3_200,
                512,
            ),
            (
                "lane:private:low-fee-transfer",
                LaneKind::PrivateTransfer,
                9_000,
                6_700,
                5_900,
                900,
                20,
                35,
                7_200,
                384,
            ),
            (
                "lane:private:contract-gas",
                LaneKind::PrivateContractGas,
                7_500,
                7_200,
                6_500,
                1_100,
                80,
                42,
                8_600,
                256,
            ),
            (
                "lane:proof:market",
                LaneKind::ProofMarket,
                5_600,
                5_100,
                4_800,
                700,
                40,
                39,
                8_100,
                256,
            ),
            (
                "lane:monero:exit",
                LaneKind::MoneroExit,
                3_200,
                2_900,
                2_400,
                520,
                0,
                41,
                7_900,
                320,
            ),
            (
                "lane:sponsored:fees",
                LaneKind::SponsoredFee,
                6_400,
                4_800,
                4_200,
                460,
                0,
                19,
                6_700,
                192,
            ),
            (
                "lane:batch:netting",
                LaneKind::BatchNetting,
                8_800,
                5_300,
                6_100,
                380,
                0,
                24,
                5_900,
                512,
            ),
            (
                "lane:operator:recovery",
                LaneKind::OperatorRecovery,
                2_200,
                420,
                1_200,
                0,
                0,
                12,
                1_800,
                128,
            ),
        ] {
            self.lane_meters.insert(
                lane_id.to_string(),
                LaneMeter {
                    lane_id: lane_id.to_string(),
                    kind,
                    sequencer_id: scoped_id("sequencer", lane_id),
                    capacity_units: capacity,
                    queued_units: queued,
                    admitted_units: admitted,
                    deferred_units: deferred,
                    shed_units: shed,
                    max_fee_micro_denom: self.config.low_fee_ceiling_micro_denom,
                    observed_fee_micro_denom: fee,
                    privacy_set_size: privacy,
                    stress_bps: stress,
                    last_updated_height: self.height,
                },
            );
        }
    }

    fn install_devnet_pressures(&mut self) {
        self.proof_markets.insert(
            "proof-market:recursive-private-contract".to_string(),
            ProofMarketPressure {
                market_id: "proof-market:recursive-private-contract".to_string(),
                circuit_family: "recursive-private-contract-execution".to_string(),
                pending_proofs: 1_280,
                available_provers: 42,
                median_bid_micro_denom: 48,
                max_low_fee_bid_micro_denom: self.config.low_fee_ceiling_micro_denom,
                congestion_bps: 8_400,
                proof_deadline_height: self.height.saturating_add(9),
                settlement_lane_id: "lane:proof:market".to_string(),
            },
        );
        self.proof_markets.insert(
            "proof-market:monero-exit-batch".to_string(),
            ProofMarketPressure {
                market_id: "proof-market:monero-exit-batch".to_string(),
                circuit_family: "monero-exit-membership-and-reserve".to_string(),
                pending_proofs: 640,
                available_provers: 27,
                median_bid_micro_denom: 39,
                max_low_fee_bid_micro_denom: self.config.low_fee_ceiling_micro_denom,
                congestion_bps: 7_600,
                proof_deadline_height: self.height.saturating_add(12),
                settlement_lane_id: "lane:proof:market".to_string(),
            },
        );
        self.monero_exits.insert(
            "monero-exit:devnet-fast-lane".to_string(),
            MoneroExitPressure {
                exit_id: "monero-exit:devnet-fast-lane".to_string(),
                lane_id: "lane:monero:exit".to_string(),
                bridge_liquidity_commitment: scoped_seed("monero-bridge-liquidity"),
                pending_exits: 430,
                spendable_outputs: 318,
                reorg_buffer_blocks: 18,
                privacy_set_size: 320,
                congestion_bps: 7_900,
                next_release_height: self.height.saturating_add(6),
            },
        );
        self.private_contract_gas.insert(
            "private-gas:swap-router".to_string(),
            PrivateContractGasPressure {
                gas_market_id: "private-gas:swap-router".to_string(),
                lane_id: "lane:private:contract-gas".to_string(),
                contract_family: "confidential-stable-swap-router".to_string(),
                encrypted_call_count: 920,
                witness_bytes: 8_912_000,
                recursive_proof_depth: 4,
                target_gas_units: 8_000_000,
                consumed_gas_units: 7_360_000,
                congestion_bps: 8_700,
            },
        );
        self.sponsor_pools.insert(
            "sponsor:wallet-onboarding".to_string(),
            SponsoredFeePool {
                sponsor_id: "sponsor:wallet-onboarding".to_string(),
                lane_id: "lane:sponsored:fees".to_string(),
                status: SponsorStatus::Guarded,
                budget_micro_denom: 4_800_000,
                reserved_micro_denom: 2_100_000,
                spent_micro_denom: 1_720_000,
                max_per_ticket_micro_denom: 18,
                drain_bps: 7_958,
                credential_root: scoped_seed("wallet-onboarding-sponsor-credentials"),
            },
        );
        self.sponsor_pools.insert(
            "sponsor:monero-exit-relief".to_string(),
            SponsoredFeePool {
                sponsor_id: "sponsor:monero-exit-relief".to_string(),
                lane_id: "lane:monero:exit".to_string(),
                status: SponsorStatus::Draining,
                budget_micro_denom: 3_200_000,
                reserved_micro_denom: 1_880_000,
                spent_micro_denom: 1_030_000,
                max_per_ticket_micro_denom: 29,
                drain_bps: 9_093,
                credential_root: scoped_seed("monero-exit-relief-sponsor-credentials"),
            },
        );
        self.batch_netting.insert(
            "netting:private-transfer-epoch".to_string(),
            BatchNettingPosition {
                batch_id: "netting:private-transfer-epoch".to_string(),
                lane_id: "lane:batch:netting".to_string(),
                status: NettingStatus::Balancing,
                debit_units: 91_200,
                credit_units: 89_940,
                participants: 1_024,
                proof_commitment: scoped_seed("private-transfer-netting-proof"),
                settlement_height: self.height.saturating_add(3),
            },
        );
    }

    fn install_devnet_windows(&mut self) {
        for (window_id, lane_id, status, offset, target, consumed, tickets) in [
            (
                "burst:private-contract:current",
                "lane:private:contract-gas",
                WindowStatus::Saturated,
                0,
                2_400,
                2_360,
                480,
            ),
            (
                "burst:proof-market:current",
                "lane:proof:market",
                WindowStatus::Saturated,
                0,
                1_600,
                1_530,
                312,
            ),
            (
                "burst:monero-exit:current",
                "lane:monero:exit",
                WindowStatus::Draining,
                0,
                940,
                780,
                184,
            ),
            (
                "burst:sponsored-fees:next",
                "lane:sponsored:fees",
                WindowStatus::Planned,
                16,
                1_800,
                0,
                0,
            ),
        ] {
            let start_height = self.height.saturating_add(offset);
            self.burst_windows.insert(
                window_id.to_string(),
                BurstWindow {
                    window_id: window_id.to_string(),
                    lane_id: lane_id.to_string(),
                    status,
                    start_height,
                    end_height: start_height
                        .saturating_add(self.config.burst_window_blocks)
                        .saturating_sub(1),
                    target_units: target,
                    consumed_units: consumed,
                    reserved_tickets: tickets,
                    fairness_salt_root: scoped_id("burst-window-salt", window_id),
                },
            );
        }
        for (ceiling_id, lane_id, mode, current, discount, expiry) in [
            (
                "ceiling:private-contract-gas",
                "lane:private:contract-gas",
                FeeCeilingMode::Emergency,
                31,
                0,
                8,
            ),
            (
                "ceiling:proof-market",
                "lane:proof:market",
                FeeCeilingMode::Tightened,
                35,
                0,
                12,
            ),
            (
                "ceiling:monero-exit",
                "lane:monero:exit",
                FeeCeilingMode::SponsorOnly,
                29,
                2_500,
                18,
            ),
            (
                "ceiling:public-transfer",
                "lane:public:low-fee-transfer",
                FeeCeilingMode::Baseline,
                42,
                500,
                32,
            ),
        ] {
            self.fee_ceilings.insert(
                ceiling_id.to_string(),
                FeeCeiling {
                    ceiling_id: ceiling_id.to_string(),
                    lane_id: lane_id.to_string(),
                    mode,
                    baseline_micro_denom: self.config.low_fee_ceiling_micro_denom,
                    current_micro_denom: current,
                    min_micro_denom: 10,
                    max_micro_denom: self.config.low_fee_ceiling_micro_denom,
                    sponsor_discount_bps: discount,
                    expires_at_height: self.height.saturating_add(expiry),
                },
            );
        }
    }

    fn install_devnet_tickets(&mut self) {
        for index in 0..18_u64 {
            let lane_id = match index % 4 {
                0 => "lane:private:contract-gas",
                1 => "lane:proof:market",
                2 => "lane:monero:exit",
                _ => "lane:sponsored:fees",
            };
            let ticket_id = format!("ticket:stress:{index:02}");
            let status = if index % 7 == 0 {
                TicketStatus::Deferred
            } else if index % 5 == 0 {
                TicketStatus::Reserved
            } else {
                TicketStatus::Open
            };
            self.fairness_tickets.insert(
                ticket_id.clone(),
                FairnessTicket {
                    ticket_id: ticket_id.clone(),
                    lane_id: lane_id.to_string(),
                    account_commitment: scoped_id("ticket-account", &ticket_id),
                    status,
                    priority_weight: 700_u64.saturating_add(index.saturating_mul(17)),
                    max_fee_micro_denom: self.config.low_fee_ceiling_micro_denom,
                    issued_at_height: self.height.saturating_sub(index),
                    expires_at_height: self
                        .height
                        .saturating_add(self.config.fairness_ticket_ttl_blocks)
                        .saturating_sub(index),
                    nullifier_commitment: scoped_id("ticket-nullifier", &ticket_id),
                },
            );
        }
    }

    fn install_devnet_decisions(&mut self) {
        for (signal_id, lane_id, source, observed, threshold, samples) in [
            (
                "signal:private-gas:recursive-depth",
                "lane:private:contract-gas",
                CongestionSource::PrivateGas,
                8_700,
                self.config.contract_gas_congestion_bps,
                96,
            ),
            (
                "signal:proof-market:bids",
                "lane:proof:market",
                CongestionSource::ProofBids,
                8_400,
                self.config.proof_congestion_bps,
                88,
            ),
            (
                "signal:monero-exit:liquidity",
                "lane:monero:exit",
                CongestionSource::MoneroLiquidity,
                7_900,
                self.config.monero_exit_congestion_bps,
                72,
            ),
            (
                "signal:sponsor-budget:drain",
                "lane:sponsored:fees",
                CongestionSource::SponsorBudget,
                7_958,
                self.config.sponsor_drain_bps,
                64,
            ),
        ] {
            self.congestion_signals.insert(
                signal_id.to_string(),
                CongestionSignal {
                    signal_id: signal_id.to_string(),
                    lane_id: lane_id.to_string(),
                    source,
                    observed_bps: observed,
                    threshold_bps: threshold,
                    sample_count: samples,
                    evidence_root: scoped_id("congestion-evidence", signal_id),
                    height: self.height,
                },
            );
        }
        for (decision_id, lane_id, action, reason, stress, allowed, deferred, ceiling, ttl) in [
            (
                "decision:private-gas:shape",
                "lane:private:contract-gas",
                ThrottleAction::Shape,
                "recursive proof depth exceeded burst target",
                8_700,
                1_440,
                520,
                31,
                8,
            ),
            (
                "decision:proof-market:defer",
                "lane:proof:market",
                ThrottleAction::Defer,
                "median proof bid crossed low-fee ceiling",
                8_400,
                980,
                420,
                35,
                10,
            ),
            (
                "decision:monero-exit:reroute",
                "lane:monero:exit",
                ThrottleAction::Reroute,
                "exit liquidity gap requires reserve-aware pacing",
                7_900,
                620,
                240,
                29,
                12,
            ),
            (
                "decision:public-transfer:admit",
                "lane:public:low-fee-transfer",
                ThrottleAction::Admit,
                "lane below stress threshold",
                3_200,
                3_800,
                0,
                42,
                16,
            ),
        ] {
            let ticket_root = map_root(
                "LOW-FEE-LANE-STRESS-DECISION-TICKET-SUBSET",
                &self
                    .fairness_tickets
                    .iter()
                    .filter(|(_, ticket)| ticket.lane_id == lane_id)
                    .map(|(key, ticket)| (key.clone(), ticket.clone()))
                    .collect::<BTreeMap<_, _>>(),
                FairnessTicket::public_record,
            );
            self.throttling_decisions.insert(
                decision_id.to_string(),
                ThrottlingDecision {
                    decision_id: decision_id.to_string(),
                    lane_id: lane_id.to_string(),
                    action,
                    reason: reason.to_string(),
                    stress_bps: stress,
                    allowed_units: allowed,
                    deferred_units: deferred,
                    fee_ceiling_micro_denom: ceiling,
                    fairness_ticket_root: ticket_root,
                    valid_until_height: self.height.saturating_add(ttl),
                },
            );
        }
        for (event_id, lane_id, label) in [
            (
                "event:private-gas:ceiling-tightened",
                "lane:private:contract-gas",
                "fee_ceiling_tightened",
            ),
            (
                "event:proof-market:burst-saturated",
                "lane:proof:market",
                "burst_window_saturated",
            ),
            (
                "event:monero-exit:sponsor-draining",
                "lane:monero:exit",
                "sponsor_pool_draining",
            ),
        ] {
            let before_root = scoped_id("audit-before", event_id);
            let after_root = scoped_id("audit-after", event_id);
            self.audit_events.insert(
                event_id.to_string(),
                StressAuditEvent {
                    event_id: event_id.to_string(),
                    lane_id: lane_id.to_string(),
                    label: label.to_string(),
                    subject_root: scoped_id("audit-subject", event_id),
                    before_root,
                    after_root,
                    height: self.height,
                },
            );
        }
    }

    fn refresh_height_sensitive_status(&mut self) {
        for ticket in self.fairness_tickets.values_mut() {
            if ticket.status.live() && ticket.expired_at(self.height) {
                ticket.status = TicketStatus::Expired;
            }
        }
        for window in self.burst_windows.values_mut() {
            if window.status.active() && self.height > window.end_height {
                window.status = WindowStatus::Sealed;
            } else if window.status == WindowStatus::Planned && window.contains_height(self.height)
            {
                window.status = WindowStatus::Open;
            }
        }
        for ceiling in self.fee_ceilings.values_mut() {
            if self.height > ceiling.expires_at_height {
                ceiling.mode = FeeCeilingMode::Released;
                ceiling.current_micro_denom = ceiling.baseline_micro_denom;
            }
        }
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "LOW-FEE-LANE-STRESS-CONTROLLER-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(LOW_FEE_LANE_STRESS_CONTROLLER_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> LowFeeLaneStressControllerResult<State> {
    State::devnet()
}

fn require_key(actual: &str, wanted: &str, label: &str) -> LowFeeLaneStressControllerResult<()> {
    if actual != wanted {
        return Err(format!(
            "low fee lane stress controller {label} map key mismatch"
        ));
    }
    Ok(())
}

fn require_lane(
    lanes: &BTreeMap<String, LaneMeter>,
    lane_id: &str,
    label: &str,
) -> LowFeeLaneStressControllerResult<()> {
    if !lanes.contains_key(lane_id) {
        return Err(format!(
            "low fee lane stress controller {label} references missing lane {lane_id}"
        ));
    }
    Ok(())
}

fn require_bps(value: u64, label: &str) -> LowFeeLaneStressControllerResult<()> {
    if value > LOW_FEE_LANE_STRESS_CONTROLLER_MAX_BPS {
        return Err(format!(
            "low fee lane stress controller {label} exceeds max bps"
        ));
    }
    Ok(())
}

fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(LOW_FEE_LANE_STRESS_CONTROLLER_MAX_BPS)
        .saturating_div(denominator)
}

fn divide_or_zero(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_div(denominator)
    }
}

fn scoped_seed(label: &str) -> String {
    domain_hash(
        "LOW-FEE-LANE-STRESS-SEED",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(LOW_FEE_LANE_STRESS_CONTROLLER_PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn scoped_id(domain: &str, label: &str) -> String {
    domain_hash(
        "LOW-FEE-LANE-STRESS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(LOW_FEE_LANE_STRESS_CONTROLLER_PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}

fn map_root<T>(domain: &str, values: &BTreeMap<String, T>, record: fn(&T) -> Value) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record": record(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn records_from_map<T>(values: &BTreeMap<String, T>, record: fn(&T) -> Value) -> Vec<Value> {
    values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record": record(value),
            })
        })
        .collect::<Vec<_>>()
}
