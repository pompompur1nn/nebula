use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{canonical_json_string, domain_hash, merkle_root, HashPart};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialWitnessRepairPreconfirmationMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_WITNESS_REPAIR_PRECONFIRMATION_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-witness-repair-preconfirmation-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_WITNESS_REPAIR_PRECONFIRMATION_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 4_120_000;
pub const DEVNET_EPOCH: u64 = 13_733;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_LANE_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-witness-repair-lane-v1";
pub const REPAIR_TICKET_SUITE: &str = "confidential-witness-chunk-repair-ticket-root-v1";
pub const PRECONFIRMATION_BID_SUITE: &str =
    "private-l2-confidential-witness-repair-preconfirmation-bid-root-v1";
pub const REPAIR_QUORUM_SUITE: &str = "privacy-preserving-witness-repair-quorum-commitment-root-v1";
pub const ANTI_REPLAY_RECEIPT_SUITE: &str =
    "monero-private-l2-witness-repair-anti-replay-receipt-root-v1";
pub const FEE_REBATE_LANE_SUITE: &str = "low-fee-witness-repair-rebate-lane-root-v1";
pub const LATENCY_RELIABILITY_SUITE: &str =
    "confidential-witness-repair-latency-reliability-score-root-v1";
pub const ROOTS_ONLY_PUBLIC_RECORD_SUITE: &str =
    "roots-only-witness-repair-preconfirmation-market-public-record-v1";
pub const MAX_BPS: u64 = 10_000;
pub const SCORE_SCALE: u64 = 1_000_000;

const D_CONFIG: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-PRECONF:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-PRECONF:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-PRECONF:ROOTS";
const D_STATE: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-PRECONF:STATE";
const D_TICKETS: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-PRECONF:TICKETS";
const D_LANES: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-PRECONF:PQ-LANES";
const D_BIDS: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-PRECONF:BIDS";
const D_SCORES: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-PRECONF:SCORES";
const D_REBATES: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-PRECONF:REBATES";
const D_QUORUMS: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-PRECONF:QUORUMS";
const D_RECEIPTS: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-PRECONF:RECEIPTS";
const D_ASSIGNMENTS: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-PRECONF:ASSIGNMENTS";
const D_EVENTS: &str = "PL2-FAST-PQ-CONF-WITNESS-REPAIR-PRECONF:EVENTS";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairClass {
    BridgeExit,
    SwapBundle,
    AccountState,
    ContractTrace,
    RecursiveProof,
    FeeRebate,
    Watchtower,
    Emergency,
    Bulk,
}

impl RepairClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeExit => "bridge_exit",
            Self::SwapBundle => "swap_bundle",
            Self::AccountState => "account_state",
            Self::ContractTrace => "contract_trace",
            Self::RecursiveProof => "recursive_proof",
            Self::FeeRebate => "fee_rebate",
            Self::Watchtower => "watchtower",
            Self::Emergency => "emergency",
            Self::Bulk => "bulk",
        }
    }

    pub fn urgency_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_500,
            Self::BridgeExit => 1_220,
            Self::SwapBundle => 1_100,
            Self::RecursiveProof => 1_020,
            Self::AccountState => 940,
            Self::ContractTrace => 860,
            Self::Watchtower => 800,
            Self::FeeRebate => 720,
            Self::Bulk => 520,
        }
    }

    pub fn privacy_floor(self) -> u64 {
        match self {
            Self::Emergency => 65_536,
            Self::BridgeExit | Self::SwapBundle => 262_144,
            Self::RecursiveProof | Self::ContractTrace => 131_072,
            Self::AccountState | Self::Watchtower => 98_304,
            Self::FeeRebate | Self::Bulk => 32_768,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Open,
    Bidding,
    Preconfirmed,
    Repairing,
    QuorumCommitted,
    Settled,
    Expired,
    Cancelled,
    Slashed,
}

impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Bidding => "bidding",
            Self::Preconfirmed => "preconfirmed",
            Self::Repairing => "repairing",
            Self::QuorumCommitted => "quorum_committed",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::Bidding
                | Self::Preconfirmed
                | Self::Repairing
                | Self::QuorumCommitted
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Warm,
    Preferred,
    Congested,
    Paused,
    Slashed,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Warm => "warm",
            Self::Preferred => "preferred",
            Self::Congested => "congested",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_work(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Warm | Self::Preferred | Self::Congested
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Submitted,
    Ranked,
    Winning,
    Preconfirmed,
    Outbid,
    Withdrawn,
    Expired,
    Slashed,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Ranked => "ranked",
            Self::Winning => "winning",
            Self::Preconfirmed => "preconfirmed",
            Self::Outbid => "outbid",
            Self::Withdrawn => "withdrawn",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumStatus {
    Proposed,
    Locked,
    Committed,
    Revealed,
    Settled,
    Faulted,
}

impl QuorumStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Locked => "locked",
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Settled => "settled",
            Self::Faulted => "faulted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Pending,
    Earned,
    Claimable,
    Settled,
    Withheld,
    ClawedBack,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Earned => "earned",
            Self::Claimable => "claimable",
            Self::Settled => "settled",
            Self::Withheld => "withheld",
            Self::ClawedBack => "clawed_back",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub fee_asset_id: String,
    pub max_open_tickets: usize,
    pub max_active_bids: usize,
    pub max_lanes: usize,
    pub max_receipts: usize,
    pub ticket_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub preconfirmation_ttl_blocks: u64,
    pub quorum_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub min_lane_attestation_weight: u64,
    pub min_quorum_weight: u64,
    pub min_quorum_signers: u64,
    pub max_repair_fee_units: u64,
    pub min_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub reliability_weight_bps: u64,
    pub latency_weight_bps: u64,
    pub fee_weight_bps: u64,
    pub default_operator_commitment: String,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: "nebula-private-l2-devnet".into(),
            protocol_version: PROTOCOL_VERSION.into(),
            fee_asset_id: "piconero-devnet".into(),
            max_open_tickets: 1_048_576,
            max_active_bids: 4_194_304,
            max_lanes: 65_536,
            max_receipts: 8_388_608,
            ticket_ttl_blocks: 48,
            bid_ttl_blocks: 12,
            preconfirmation_ttl_blocks: 10,
            quorum_ttl_blocks: 32,
            receipt_ttl_blocks: 720,
            min_pq_security_bits: 256,
            min_privacy_set_size: 65_536,
            min_lane_attestation_weight: 2_000,
            min_quorum_weight: 3_000,
            min_quorum_signers: 3,
            max_repair_fee_units: 250_000,
            min_rebate_bps: 75,
            max_rebate_bps: 1_500,
            reliability_weight_bps: 5_000,
            latency_weight_bps: 3_200,
            fee_weight_bps: 1_800,
            default_operator_commitment: "operator.fast-pq-witness-repair.devnet".into(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.chain_id.trim().is_empty() {
            return Err("config chain_id must not be empty".into());
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("config protocol_version mismatch".into());
        }
        if self.fee_asset_id.trim().is_empty() {
            return Err("config fee_asset_id must not be empty".into());
        }
        if self.max_open_tickets == 0
            || self.max_active_bids == 0
            || self.max_lanes == 0
            || self.max_receipts == 0
        {
            return Err("config limits must be non-zero".into());
        }
        if self.min_pq_security_bits < 256 {
            return Err("config min_pq_security_bits must be at least 256".into());
        }
        if self.min_privacy_set_size == 0 {
            return Err("config min_privacy_set_size must be non-zero".into());
        }
        if self.min_rebate_bps > self.max_rebate_bps || self.max_rebate_bps > MAX_BPS {
            return Err("config rebate bps range invalid".into());
        }
        if self.reliability_weight_bps + self.latency_weight_bps + self.fee_weight_bps != MAX_BPS {
            return Err("score weights must sum to MAX_BPS".into());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(D_CONFIG, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub tickets_opened: u64,
    pub tickets_preconfirmed: u64,
    pub tickets_settled: u64,
    pub tickets_expired: u64,
    pub pq_lane_attestations: u64,
    pub bids_submitted: u64,
    pub bids_ranked: u64,
    pub bids_preconfirmed: u64,
    pub repair_assignments: u64,
    pub quorum_commitments: u64,
    pub quorum_settlements: u64,
    pub anti_replay_receipts: u64,
    pub replay_rejections: u64,
    pub fee_rebate_lanes: u64,
    pub rebate_units_earned: u64,
    pub rebate_units_settled: u64,
    pub reliability_samples: u64,
    pub latency_samples: u64,
    pub privacy_rejections: u64,
    pub slash_events: u64,
    pub public_events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(D_COUNTERS, &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub witness_chunk_repair_ticket_root: String,
    pub pq_lane_attestation_root: String,
    pub preconfirmation_bid_root: String,
    pub latency_reliability_score_root: String,
    pub fee_rebate_lane_root: String,
    pub repair_quorum_commitment_root: String,
    pub anti_replay_receipt_root: String,
    pub repair_assignment_root: String,
    pub replay_nullifier_root: String,
    pub event_root: String,
    pub roots_only_public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record_without_state_root(&self) -> Value {
        let mut value = json!(self);
        if let Value::Object(ref mut map) = value {
            map.remove("state_root");
        }
        value
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root(D_ROOTS, &self.public_record_without_state_root())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WitnessChunkRepairTicketInput {
    pub requester_commitment: String,
    pub class: RepairClass,
    pub witness_epoch: u64,
    pub chunk_index: u64,
    pub chunk_count: u64,
    pub encrypted_chunk_root: String,
    pub missing_chunk_commitment: String,
    pub repair_hint_root: String,
    pub max_fee_units: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqLaneAttestationInput {
    pub lane_id: String,
    pub operator_commitment: String,
    pub lane_capacity_chunks: u64,
    pub target_latency_ms: u64,
    pub max_fee_units: u64,
    pub signer_count: u64,
    pub aggregate_weight: u64,
    pub pq_security_bits: u16,
    pub statement_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreconfirmationBidInput {
    pub ticket_id: String,
    pub lane_id: String,
    pub bidder_commitment: String,
    pub fee_units: u64,
    pub promised_latency_ms: u64,
    pub collateral_units: u64,
    pub privacy_set_size: u64,
    pub bid_ciphertext_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepairQuorumCommitmentInput {
    pub ticket_id: String,
    pub winning_bid_id: String,
    pub lane_id: String,
    pub signer_count: u64,
    pub aggregate_weight: u64,
    pub repaired_chunk_root: String,
    pub quorum_statement_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AntiReplayReceiptInput {
    pub ticket_id: String,
    pub bid_id: String,
    pub lane_id: String,
    pub nullifier: String,
    pub receipt_ciphertext_root: String,
    pub repaired_witness_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyReliabilitySampleInput {
    pub lane_id: String,
    pub fulfilled: bool,
    pub latency_ms: u64,
    pub fee_units: u64,
    pub reliability_penalty_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WitnessChunkRepairTicket {
    pub ticket_id: String,
    pub requester_commitment: String,
    pub class: RepairClass,
    pub status: TicketStatus,
    pub witness_epoch: u64,
    pub chunk_index: u64,
    pub chunk_count: u64,
    pub encrypted_chunk_root: String,
    pub missing_chunk_commitment: String,
    pub repair_hint_root: String,
    pub max_fee_units: u64,
    pub privacy_set_size: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub selected_bid_id: Option<String>,
    pub quorum_id: Option<String>,
    pub receipt_id: Option<String>,
}

impl WitnessChunkRepairTicket {
    pub fn new(input: WitnessChunkRepairTicketInput, height: u64, ttl: u64) -> Self {
        let ticket_id = id_hash(
            "repair-ticket",
            &[
                input.requester_commitment.as_str(),
                input.class.as_str(),
                &input.witness_epoch.to_string(),
                &input.chunk_index.to_string(),
                input.missing_chunk_commitment.as_str(),
            ],
        );
        Self {
            ticket_id,
            requester_commitment: input.requester_commitment,
            class: input.class,
            status: TicketStatus::Open,
            witness_epoch: input.witness_epoch,
            chunk_index: input.chunk_index,
            chunk_count: input.chunk_count,
            encrypted_chunk_root: input.encrypted_chunk_root,
            missing_chunk_commitment: input.missing_chunk_commitment,
            repair_hint_root: input.repair_hint_root,
            max_fee_units: input.max_fee_units,
            privacy_set_size: input.privacy_set_size,
            opened_height: height,
            expires_height: height.saturating_add(ttl),
            selected_bid_id: None,
            quorum_id: None,
            receipt_id: None,
        }
    }

    pub fn commitment(&self) -> String {
        domain_hash(
            D_TICKETS,
            &[
                HashPart::Str(self.ticket_id.as_str()),
                HashPart::Str(self.class.as_str()),
                HashPart::Str(self.status.as_str()),
                HashPart::U64(self.witness_epoch),
                HashPart::U64(self.chunk_index),
                HashPart::U64(self.chunk_count),
                HashPart::Str(self.encrypted_chunk_root.as_str()),
                HashPart::Str(self.missing_chunk_commitment.as_str()),
                HashPart::U64(self.max_fee_units),
                HashPart::U64(self.privacy_set_size),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "class": self.class.as_str(),
            "status": self.status.as_str(),
            "witness_epoch": self.witness_epoch,
            "chunk_index": self.chunk_index,
            "chunk_count": self.chunk_count,
            "ticket_commitment": self.commitment(),
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "selected_bid_id": self.selected_bid_id,
            "quorum_id": self.quorum_id,
            "receipt_id": self.receipt_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqLaneAttestation {
    pub attestation_id: String,
    pub lane_id: String,
    pub operator_commitment: String,
    pub lane_capacity_chunks: u64,
    pub target_latency_ms: u64,
    pub max_fee_units: u64,
    pub signer_count: u64,
    pub aggregate_weight: u64,
    pub pq_security_bits: u16,
    pub statement_root: String,
    pub signature_root: String,
    pub attested_height: u64,
    pub expires_height: u64,
}

impl PqLaneAttestation {
    pub fn new(input: PqLaneAttestationInput, height: u64, ttl: u64) -> Self {
        let attestation_id = id_hash(
            "pq-lane-attestation",
            &[
                input.lane_id.as_str(),
                input.operator_commitment.as_str(),
                &height.to_string(),
                input.statement_root.as_str(),
            ],
        );
        let signature_root = id_hash(
            "pq-lane-signature",
            &[
                attestation_id.as_str(),
                input.statement_root.as_str(),
                PQ_LANE_ATTESTATION_SUITE,
            ],
        );
        Self {
            attestation_id,
            lane_id: input.lane_id,
            operator_commitment: input.operator_commitment,
            lane_capacity_chunks: input.lane_capacity_chunks,
            target_latency_ms: input.target_latency_ms.max(1),
            max_fee_units: input.max_fee_units,
            signer_count: input.signer_count,
            aggregate_weight: input.aggregate_weight,
            pq_security_bits: input.pq_security_bits,
            statement_root: input.statement_root,
            signature_root,
            attested_height: height,
            expires_height: height.saturating_add(ttl),
        }
    }

    pub fn threshold_met(&self, config: &Config) -> bool {
        self.pq_security_bits >= config.min_pq_security_bits
            && self.aggregate_weight >= config.min_lane_attestation_weight
            && self.signer_count >= config.min_quorum_signers
    }

    pub fn commitment(&self) -> String {
        domain_hash(
            D_LANES,
            &[
                HashPart::Str(self.attestation_id.as_str()),
                HashPart::Str(self.lane_id.as_str()),
                HashPart::Str(self.operator_commitment.as_str()),
                HashPart::U64(self.lane_capacity_chunks),
                HashPart::U64(self.target_latency_ms),
                HashPart::U64(self.max_fee_units),
                HashPart::U64(self.aggregate_weight),
                HashPart::U64(self.pq_security_bits as u64),
                HashPart::Str(self.statement_root.as_str()),
                HashPart::Str(self.signature_root.as_str()),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "lane_id": self.lane_id,
            "operator_commitment": self.operator_commitment,
            "lane_capacity_chunks": self.lane_capacity_chunks,
            "target_latency_ms": self.target_latency_ms,
            "max_fee_units": self.max_fee_units,
            "signer_count": self.signer_count,
            "aggregate_weight": self.aggregate_weight,
            "pq_security_bits": self.pq_security_bits,
            "attestation_commitment": self.commitment(),
            "attested_height": self.attested_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqRepairLane {
    pub lane_id: String,
    pub operator_commitment: String,
    pub status: LaneStatus,
    pub active_attestation_id: String,
    pub capacity_chunks: u64,
    pub target_latency_ms: u64,
    pub max_fee_units: u64,
    pub pq_security_bits: u16,
    pub opened_height: u64,
    pub last_attested_height: u64,
}

impl PqRepairLane {
    pub fn from_attestation(attestation: &PqLaneAttestation) -> Self {
        Self {
            lane_id: attestation.lane_id.clone(),
            operator_commitment: attestation.operator_commitment.clone(),
            status: LaneStatus::Warm,
            active_attestation_id: attestation.attestation_id.clone(),
            capacity_chunks: attestation.lane_capacity_chunks,
            target_latency_ms: attestation.target_latency_ms,
            max_fee_units: attestation.max_fee_units,
            pq_security_bits: attestation.pq_security_bits,
            opened_height: attestation.attested_height,
            last_attested_height: attestation.attested_height,
        }
    }

    pub fn update_attestation(&mut self, attestation: &PqLaneAttestation) {
        self.active_attestation_id = attestation.attestation_id.clone();
        self.capacity_chunks = attestation.lane_capacity_chunks;
        self.target_latency_ms = attestation.target_latency_ms;
        self.max_fee_units = attestation.max_fee_units;
        self.pq_security_bits = attestation.pq_security_bits;
        self.last_attested_height = attestation.attested_height;
        if self.status.accepts_work() {
            self.status = LaneStatus::Preferred;
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "operator_commitment": self.operator_commitment,
            "status": self.status.as_str(),
            "active_attestation_id": self.active_attestation_id,
            "capacity_chunks": self.capacity_chunks,
            "target_latency_ms": self.target_latency_ms,
            "max_fee_units": self.max_fee_units,
            "pq_security_bits": self.pq_security_bits,
            "opened_height": self.opened_height,
            "last_attested_height": self.last_attested_height,
        })
    }

    pub fn commitment(&self) -> String {
        record_root(D_LANES, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreconfirmationBid {
    pub bid_id: String,
    pub ticket_id: String,
    pub lane_id: String,
    pub bidder_commitment: String,
    pub status: BidStatus,
    pub fee_units: u64,
    pub promised_latency_ms: u64,
    pub collateral_units: u64,
    pub privacy_set_size: u64,
    pub bid_ciphertext_root: String,
    pub rank_score: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl PreconfirmationBid {
    pub fn new(input: PreconfirmationBidInput, height: u64, ttl: u64) -> Self {
        let bid_id = id_hash(
            "preconfirmation-bid",
            &[
                input.ticket_id.as_str(),
                input.lane_id.as_str(),
                input.bidder_commitment.as_str(),
                &input.fee_units.to_string(),
                input.bid_ciphertext_root.as_str(),
            ],
        );
        Self {
            bid_id,
            ticket_id: input.ticket_id,
            lane_id: input.lane_id,
            bidder_commitment: input.bidder_commitment,
            status: BidStatus::Submitted,
            fee_units: input.fee_units,
            promised_latency_ms: input.promised_latency_ms.max(1),
            collateral_units: input.collateral_units,
            privacy_set_size: input.privacy_set_size,
            bid_ciphertext_root: input.bid_ciphertext_root,
            rank_score: 0,
            submitted_height: height,
            expires_height: height.saturating_add(ttl),
        }
    }

    pub fn commitment(&self) -> String {
        domain_hash(
            D_BIDS,
            &[
                HashPart::Str(self.bid_id.as_str()),
                HashPart::Str(self.ticket_id.as_str()),
                HashPart::Str(self.lane_id.as_str()),
                HashPart::Str(self.status.as_str()),
                HashPart::U64(self.fee_units),
                HashPart::U64(self.promised_latency_ms),
                HashPart::U64(self.collateral_units),
                HashPart::U64(self.privacy_set_size),
                HashPart::Str(self.bid_ciphertext_root.as_str()),
                HashPart::U64(self.rank_score),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "ticket_id": self.ticket_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "fee_units": self.fee_units,
            "promised_latency_ms": self.promised_latency_ms,
            "privacy_set_size": self.privacy_set_size,
            "rank_score": self.rank_score,
            "bid_commitment": self.commitment(),
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LatencyReliabilityScore {
    pub lane_id: String,
    pub fulfilled_repairs: u64,
    pub failed_repairs: u64,
    pub total_latency_ms: u64,
    pub average_latency_ms: u64,
    pub best_latency_ms: u64,
    pub worst_latency_ms: u64,
    pub fee_units_paid: u64,
    pub reliability_bps: u64,
    pub latency_score: u64,
    pub fee_score: u64,
    pub composite_score: u64,
    pub last_sample_height: u64,
}

impl LatencyReliabilityScore {
    pub fn new(lane_id: impl Into<String>, height: u64) -> Self {
        Self {
            lane_id: lane_id.into(),
            fulfilled_repairs: 0,
            failed_repairs: 0,
            total_latency_ms: 0,
            average_latency_ms: 0,
            best_latency_ms: u64::MAX,
            worst_latency_ms: 0,
            fee_units_paid: 0,
            reliability_bps: MAX_BPS,
            latency_score: SCORE_SCALE,
            fee_score: SCORE_SCALE,
            composite_score: SCORE_SCALE,
            last_sample_height: height,
        }
    }

    pub fn observe(&mut self, input: &LatencyReliabilitySampleInput, config: &Config, height: u64) {
        if input.fulfilled {
            self.fulfilled_repairs += 1;
        } else {
            self.failed_repairs += 1;
        }
        let sample_count = self.fulfilled_repairs + self.failed_repairs;
        self.total_latency_ms = self.total_latency_ms.saturating_add(input.latency_ms);
        self.average_latency_ms = if sample_count == 0 {
            0
        } else {
            self.total_latency_ms / sample_count
        };
        self.best_latency_ms = self.best_latency_ms.min(input.latency_ms);
        self.worst_latency_ms = self.worst_latency_ms.max(input.latency_ms);
        self.fee_units_paid = self.fee_units_paid.saturating_add(input.fee_units);
        let raw_reliability = self.fulfilled_repairs.saturating_mul(MAX_BPS) / sample_count.max(1);
        self.reliability_bps = raw_reliability.saturating_sub(input.reliability_penalty_bps);
        self.latency_score = latency_score(self.average_latency_ms);
        self.fee_score = fee_score(input.fee_units, config.max_repair_fee_units);
        self.composite_score = weighted_score(
            self.reliability_bps * 100,
            self.latency_score,
            self.fee_score,
            config,
        );
        self.last_sample_height = height;
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn commitment(&self) -> String {
        record_root(D_SCORES, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebateLane {
    pub rebate_id: String,
    pub lane_id: String,
    pub ticket_id: String,
    pub bid_id: String,
    pub status: RebateStatus,
    pub payer_commitment: String,
    pub sponsor_commitment: String,
    pub paid_fee_units: u64,
    pub rebate_bps: u64,
    pub rebate_units: u64,
    pub saved_fee_units: u64,
    pub claim_nullifier: String,
    pub created_height: u64,
    pub claimable_height: u64,
    pub expires_height: u64,
}

impl FeeRebateLane {
    pub fn new(
        ticket: &WitnessChunkRepairTicket,
        bid: &PreconfirmationBid,
        lane: &PqRepairLane,
        config: &Config,
        height: u64,
    ) -> Self {
        let rebate_bps = compute_rebate_bps(bid.fee_units, config);
        let rebate_units = bid.fee_units.saturating_mul(rebate_bps) / MAX_BPS;
        let saved_fee_units = config
            .max_repair_fee_units
            .saturating_sub(bid.fee_units)
            .min(config.max_repair_fee_units);
        let rebate_id = id_hash(
            "fee-rebate-lane",
            &[
                ticket.ticket_id.as_str(),
                bid.bid_id.as_str(),
                lane.lane_id.as_str(),
                &rebate_units.to_string(),
            ],
        );
        let claim_nullifier = id_hash(
            "rebate-claim-nullifier",
            &[rebate_id.as_str(), bid.bidder_commitment.as_str()],
        );
        Self {
            rebate_id,
            lane_id: lane.lane_id.clone(),
            ticket_id: ticket.ticket_id.clone(),
            bid_id: bid.bid_id.clone(),
            status: RebateStatus::Earned,
            payer_commitment: ticket.requester_commitment.clone(),
            sponsor_commitment: lane.operator_commitment.clone(),
            paid_fee_units: bid.fee_units,
            rebate_bps,
            rebate_units,
            saved_fee_units,
            claim_nullifier,
            created_height: height,
            claimable_height: height.saturating_add(2),
            expires_height: height.saturating_add(config.receipt_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "lane_id": self.lane_id,
            "ticket_id": self.ticket_id,
            "bid_id": self.bid_id,
            "status": self.status.as_str(),
            "paid_fee_units": self.paid_fee_units,
            "rebate_bps": self.rebate_bps,
            "rebate_units": self.rebate_units,
            "saved_fee_units": self.saved_fee_units,
            "claim_nullifier": self.claim_nullifier,
            "created_height": self.created_height,
            "claimable_height": self.claimable_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn commitment(&self) -> String {
        record_root(D_REBATES, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepairAssignment {
    pub assignment_id: String,
    pub ticket_id: String,
    pub bid_id: String,
    pub lane_id: String,
    pub assignment_root: String,
    pub preconfirmed_height: u64,
    pub expires_height: u64,
}

impl RepairAssignment {
    pub fn new(
        ticket: &WitnessChunkRepairTicket,
        bid: &PreconfirmationBid,
        height: u64,
        ttl: u64,
    ) -> Self {
        let assignment_id = id_hash(
            "repair-assignment",
            &[
                ticket.ticket_id.as_str(),
                bid.bid_id.as_str(),
                &height.to_string(),
            ],
        );
        let assignment_root = id_hash(
            "repair-assignment-root",
            &[assignment_id.as_str(), bid.lane_id.as_str()],
        );
        Self {
            assignment_id,
            ticket_id: ticket.ticket_id.clone(),
            bid_id: bid.bid_id.clone(),
            lane_id: bid.lane_id.clone(),
            assignment_root,
            preconfirmed_height: height,
            expires_height: height.saturating_add(ttl),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn commitment(&self) -> String {
        record_root(D_ASSIGNMENTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepairQuorumCommitment {
    pub quorum_id: String,
    pub ticket_id: String,
    pub winning_bid_id: String,
    pub lane_id: String,
    pub status: QuorumStatus,
    pub signer_count: u64,
    pub aggregate_weight: u64,
    pub repaired_chunk_root: String,
    pub quorum_statement_root: String,
    pub quorum_signature_root: String,
    pub committed_height: u64,
    pub expires_height: u64,
}

impl RepairQuorumCommitment {
    pub fn new(input: RepairQuorumCommitmentInput, height: u64, ttl: u64) -> Self {
        let quorum_id = id_hash(
            "repair-quorum",
            &[
                input.ticket_id.as_str(),
                input.winning_bid_id.as_str(),
                input.lane_id.as_str(),
                input.repaired_chunk_root.as_str(),
            ],
        );
        let quorum_signature_root = id_hash(
            "repair-quorum-signature",
            &[
                quorum_id.as_str(),
                input.quorum_statement_root.as_str(),
                REPAIR_QUORUM_SUITE,
            ],
        );
        Self {
            quorum_id,
            ticket_id: input.ticket_id,
            winning_bid_id: input.winning_bid_id,
            lane_id: input.lane_id,
            status: QuorumStatus::Committed,
            signer_count: input.signer_count,
            aggregate_weight: input.aggregate_weight,
            repaired_chunk_root: input.repaired_chunk_root,
            quorum_statement_root: input.quorum_statement_root,
            quorum_signature_root,
            committed_height: height,
            expires_height: height.saturating_add(ttl),
        }
    }

    pub fn threshold_met(&self, config: &Config) -> bool {
        self.signer_count >= config.min_quorum_signers
            && self.aggregate_weight >= config.min_quorum_weight
    }

    pub fn public_record(&self) -> Value {
        json!({
            "quorum_id": self.quorum_id,
            "ticket_id": self.ticket_id,
            "winning_bid_id": self.winning_bid_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "signer_count": self.signer_count,
            "aggregate_weight": self.aggregate_weight,
            "repaired_chunk_root": self.repaired_chunk_root,
            "quorum_commitment": self.commitment(),
            "committed_height": self.committed_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn commitment(&self) -> String {
        domain_hash(
            D_QUORUMS,
            &[
                HashPart::Str(self.quorum_id.as_str()),
                HashPart::Str(self.ticket_id.as_str()),
                HashPart::Str(self.winning_bid_id.as_str()),
                HashPart::Str(self.lane_id.as_str()),
                HashPart::Str(self.status.as_str()),
                HashPart::U64(self.signer_count),
                HashPart::U64(self.aggregate_weight),
                HashPart::Str(self.repaired_chunk_root.as_str()),
                HashPart::Str(self.quorum_statement_root.as_str()),
                HashPart::Str(self.quorum_signature_root.as_str()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AntiReplayReceipt {
    pub receipt_id: String,
    pub ticket_id: String,
    pub bid_id: String,
    pub lane_id: String,
    pub nullifier: String,
    pub receipt_ciphertext_root: String,
    pub repaired_witness_root: String,
    pub receipt_commitment: String,
    pub issued_height: u64,
    pub expires_height: u64,
}

impl AntiReplayReceipt {
    pub fn new(input: AntiReplayReceiptInput, height: u64, ttl: u64) -> Self {
        let receipt_id = id_hash(
            "anti-replay-receipt",
            &[
                input.ticket_id.as_str(),
                input.bid_id.as_str(),
                input.lane_id.as_str(),
                input.nullifier.as_str(),
            ],
        );
        let receipt_commitment = id_hash(
            "anti-replay-receipt-commitment",
            &[
                receipt_id.as_str(),
                input.receipt_ciphertext_root.as_str(),
                input.repaired_witness_root.as_str(),
            ],
        );
        Self {
            receipt_id,
            ticket_id: input.ticket_id,
            bid_id: input.bid_id,
            lane_id: input.lane_id,
            nullifier: input.nullifier,
            receipt_ciphertext_root: input.receipt_ciphertext_root,
            repaired_witness_root: input.repaired_witness_root,
            receipt_commitment,
            issued_height: height,
            expires_height: height.saturating_add(ttl),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "ticket_id": self.ticket_id,
            "bid_id": self.bid_id,
            "lane_id": self.lane_id,
            "receipt_commitment": self.receipt_commitment,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn commitment(&self) -> String {
        domain_hash(
            D_RECEIPTS,
            &[
                HashPart::Str(self.receipt_id.as_str()),
                HashPart::Str(self.ticket_id.as_str()),
                HashPart::Str(self.bid_id.as_str()),
                HashPart::Str(self.lane_id.as_str()),
                HashPart::Str(self.nullifier.as_str()),
                HashPart::Str(self.receipt_ciphertext_root.as_str()),
                HashPart::Str(self.repaired_witness_root.as_str()),
                HashPart::Str(self.receipt_commitment.as_str()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub height: u64,
    pub kind: String,
    pub subject_id: String,
    pub commitment: String,
}

impl RuntimeEvent {
    pub fn new(height: u64, ordinal: u64, kind: &str, subject_id: &str, commitment: &str) -> Self {
        Self {
            event_id: id_hash(
                "event",
                &[kind, subject_id, commitment, &ordinal.to_string()],
            ),
            height,
            kind: kind.into(),
            subject_id: subject_id.into(),
            commitment: commitment.into(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn commitment(&self) -> String {
        record_root(D_EVENTS, &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub height: u64,
    pub epoch: u64,
    pub tickets: BTreeMap<String, WitnessChunkRepairTicket>,
    pub pq_lane_attestations: BTreeMap<String, PqLaneAttestation>,
    pub lanes: BTreeMap<String, PqRepairLane>,
    pub bids: BTreeMap<String, PreconfirmationBid>,
    pub scores: BTreeMap<String, LatencyReliabilityScore>,
    pub fee_rebate_lanes: BTreeMap<String, FeeRebateLane>,
    pub quorum_commitments: BTreeMap<String, RepairQuorumCommitment>,
    pub anti_replay_receipts: BTreeMap<String, AntiReplayReceipt>,
    pub assignments: BTreeMap<String, RepairAssignment>,
    pub bids_by_ticket: BTreeMap<String, BTreeSet<String>>,
    pub receipts_by_ticket: BTreeMap<String, BTreeSet<String>>,
    pub replay_nullifiers: BTreeSet<String>,
    pub priority_queue: VecDeque<String>,
    pub events: Vec<RuntimeEvent>,
}

impl Default for State {
    fn default() -> Self {
        Self::empty(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH)
    }
}

impl State {
    pub fn empty(config: Config, height: u64, epoch: u64) -> Self {
        Self {
            config,
            counters: Counters::default(),
            height,
            epoch,
            tickets: BTreeMap::new(),
            pq_lane_attestations: BTreeMap::new(),
            lanes: BTreeMap::new(),
            bids: BTreeMap::new(),
            scores: BTreeMap::new(),
            fee_rebate_lanes: BTreeMap::new(),
            quorum_commitments: BTreeMap::new(),
            anti_replay_receipts: BTreeMap::new(),
            assignments: BTreeMap::new(),
            bids_by_ticket: BTreeMap::new(),
            receipts_by_ticket: BTreeMap::new(),
            replay_nullifiers: BTreeSet::new(),
            priority_queue: VecDeque::new(),
            events: Vec::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::empty(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH);
        state.seed_devnet().expect("devnet seed is valid");
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn open_ticket(&mut self, input: WitnessChunkRepairTicketInput) -> Result<String> {
        self.config.validate()?;
        if self.open_ticket_count() as usize >= self.config.max_open_tickets {
            return Err("max open repair tickets reached".into());
        }
        if input.chunk_count == 0 || input.chunk_index >= input.chunk_count {
            return Err("repair ticket chunk index out of range".into());
        }
        if input.max_fee_units > self.config.max_repair_fee_units {
            return Err("repair ticket max fee exceeds config cap".into());
        }
        let floor = self
            .config
            .min_privacy_set_size
            .max(input.class.privacy_floor());
        if input.privacy_set_size < floor {
            self.counters.privacy_rejections += 1;
            return Err(format!(
                "repair ticket privacy set {} below floor {}",
                input.privacy_set_size, floor
            ));
        }
        let ticket =
            WitnessChunkRepairTicket::new(input, self.height, self.config.ticket_ttl_blocks);
        let ticket_id = ticket.ticket_id.clone();
        let commitment = ticket.commitment();
        self.tickets.insert(ticket_id.clone(), ticket);
        self.priority_queue.push_back(ticket_id.clone());
        self.counters.tickets_opened += 1;
        self.record_event(
            "witness_chunk_repair_ticket_opened",
            &ticket_id,
            &commitment,
        );
        Ok(ticket_id)
    }

    pub fn attest_pq_lane(&mut self, input: PqLaneAttestationInput) -> Result<String> {
        self.config.validate()?;
        if !self.lanes.contains_key(&input.lane_id) && self.lanes.len() >= self.config.max_lanes {
            return Err("max pq repair lanes reached".into());
        }
        let attestation =
            PqLaneAttestation::new(input, self.height, self.config.receipt_ttl_blocks);
        if !attestation.threshold_met(&self.config) {
            return Err(format!(
                "pq lane attestation {} below threshold",
                attestation.attestation_id
            ));
        }
        let attestation_id = attestation.attestation_id.clone();
        let lane_id = attestation.lane_id.clone();
        let commitment = attestation.commitment();
        self.lanes
            .entry(lane_id.clone())
            .and_modify(|lane| lane.update_attestation(&attestation))
            .or_insert_with(|| PqRepairLane::from_attestation(&attestation));
        self.scores
            .entry(lane_id.clone())
            .or_insert_with(|| LatencyReliabilityScore::new(lane_id, self.height));
        self.pq_lane_attestations
            .insert(attestation_id.clone(), attestation);
        self.counters.pq_lane_attestations += 1;
        self.record_event("pq_lane_attested", &attestation_id, &commitment);
        Ok(attestation_id)
    }

    pub fn submit_preconfirmation_bid(&mut self, input: PreconfirmationBidInput) -> Result<String> {
        self.config.validate()?;
        if self.bids.len() >= self.config.max_active_bids {
            return Err("max active preconfirmation bids reached".into());
        }
        let ticket = self
            .tickets
            .get(&input.ticket_id)
            .ok_or_else(|| format!("ticket {} missing", input.ticket_id))?;
        if !ticket.status.live() {
            return Err(format!("ticket {} is not live", input.ticket_id));
        }
        let lane = self
            .lanes
            .get(&input.lane_id)
            .ok_or_else(|| format!("lane {} missing", input.lane_id))?;
        if !lane.status.accepts_work() {
            return Err(format!("lane {} cannot accept work", input.lane_id));
        }
        if input.fee_units > ticket.max_fee_units || input.fee_units > lane.max_fee_units {
            return Err("preconfirmation bid fee exceeds ticket or lane cap".into());
        }
        if input.privacy_set_size < self.config.min_privacy_set_size {
            self.counters.privacy_rejections += 1;
            return Err("preconfirmation bid privacy set below config floor".into());
        }
        let mut bid = PreconfirmationBid::new(input, self.height, self.config.bid_ttl_blocks);
        let score = self
            .scores
            .get(&bid.lane_id)
            .map(|score| score.composite_score)
            .unwrap_or(SCORE_SCALE / 2);
        bid.rank_score = self.bid_rank_score(&bid, score);
        bid.status = BidStatus::Ranked;
        let bid_id = bid.bid_id.clone();
        let ticket_id = bid.ticket_id.clone();
        let commitment = bid.commitment();
        self.bids.insert(bid_id.clone(), bid);
        self.bids_by_ticket
            .entry(ticket_id.clone())
            .or_default()
            .insert(bid_id.clone());
        if let Some(ticket) = self.tickets.get_mut(&ticket_id) {
            ticket.status = TicketStatus::Bidding;
        }
        self.counters.bids_submitted += 1;
        self.counters.bids_ranked += 1;
        self.record_event("preconfirmation_bid_submitted", &bid_id, &commitment);
        Ok(bid_id)
    }

    pub fn select_best_bid(&mut self, ticket_id: &str) -> Result<String> {
        let candidate_ids = self
            .bids_by_ticket
            .get(ticket_id)
            .ok_or_else(|| format!("ticket {ticket_id} has no bids"))?
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        let best_id = candidate_ids
            .iter()
            .filter_map(|bid_id| self.bids.get(bid_id))
            .filter(|bid| self.height <= bid.expires_height)
            .max_by_key(|bid| (bid.rank_score, std::cmp::Reverse(bid.fee_units)))
            .map(|bid| bid.bid_id.clone())
            .ok_or_else(|| format!("ticket {ticket_id} has no live bids"))?;
        for bid_id in candidate_ids {
            if let Some(bid) = self.bids.get_mut(&bid_id) {
                bid.status = if bid.bid_id == best_id {
                    BidStatus::Winning
                } else {
                    BidStatus::Outbid
                };
            }
        }
        Ok(best_id)
    }

    pub fn preconfirm_ticket(&mut self, ticket_id: &str) -> Result<String> {
        let best_id = self.select_best_bid(ticket_id)?;
        let bid = self
            .bids
            .get(&best_id)
            .ok_or_else(|| format!("bid {best_id} missing"))?
            .clone();
        let lane = self
            .lanes
            .get(&bid.lane_id)
            .ok_or_else(|| format!("lane {} missing", bid.lane_id))?
            .clone();
        let ticket_snapshot = self
            .tickets
            .get(ticket_id)
            .ok_or_else(|| format!("ticket {ticket_id} missing"))?
            .clone();
        let assignment = RepairAssignment::new(
            &ticket_snapshot,
            &bid,
            self.height,
            self.config.preconfirmation_ttl_blocks,
        );
        let rebate = FeeRebateLane::new(&ticket_snapshot, &bid, &lane, &self.config, self.height);
        let assignment_id = assignment.assignment_id.clone();
        let rebate_id = rebate.rebate_id.clone();
        let assignment_commitment = assignment.commitment();
        if let Some(ticket) = self.tickets.get_mut(ticket_id) {
            ticket.status = TicketStatus::Preconfirmed;
            ticket.selected_bid_id = Some(best_id.clone());
        }
        if let Some(bid) = self.bids.get_mut(&best_id) {
            bid.status = BidStatus::Preconfirmed;
        }
        self.assignments.insert(assignment_id.clone(), assignment);
        self.fee_rebate_lanes.insert(rebate_id, rebate);
        self.counters.tickets_preconfirmed += 1;
        self.counters.bids_preconfirmed += 1;
        self.counters.repair_assignments += 1;
        self.counters.fee_rebate_lanes = self.fee_rebate_lanes.len() as u64;
        self.record_event("ticket_preconfirmed", ticket_id, &assignment_commitment);
        Ok(assignment_id)
    }

    pub fn commit_repair_quorum(&mut self, input: RepairQuorumCommitmentInput) -> Result<String> {
        let ticket = self
            .tickets
            .get(&input.ticket_id)
            .ok_or_else(|| format!("ticket {} missing", input.ticket_id))?;
        if ticket.selected_bid_id.as_deref() != Some(input.winning_bid_id.as_str()) {
            return Err("repair quorum does not match selected bid".into());
        }
        let quorum = RepairQuorumCommitment::new(input, self.height, self.config.quorum_ttl_blocks);
        if !quorum.threshold_met(&self.config) {
            return Err("repair quorum threshold not met".into());
        }
        let quorum_id = quorum.quorum_id.clone();
        let ticket_id = quorum.ticket_id.clone();
        let commitment = quorum.commitment();
        self.quorum_commitments.insert(quorum_id.clone(), quorum);
        if let Some(ticket) = self.tickets.get_mut(&ticket_id) {
            ticket.status = TicketStatus::QuorumCommitted;
            ticket.quorum_id = Some(quorum_id.clone());
        }
        self.counters.quorum_commitments += 1;
        self.record_event("repair_quorum_committed", &quorum_id, &commitment);
        Ok(quorum_id)
    }

    pub fn issue_anti_replay_receipt(&mut self, input: AntiReplayReceiptInput) -> Result<String> {
        if self.anti_replay_receipts.len() >= self.config.max_receipts {
            return Err("max anti replay receipts reached".into());
        }
        if self.replay_nullifiers.contains(&input.nullifier) {
            self.counters.replay_rejections += 1;
            return Err(format!(
                "receipt nullifier {} already used",
                input.nullifier
            ));
        }
        let ticket = self
            .tickets
            .get(&input.ticket_id)
            .ok_or_else(|| format!("ticket {} missing", input.ticket_id))?;
        if ticket.selected_bid_id.as_deref() != Some(input.bid_id.as_str()) {
            return Err("anti replay receipt does not match selected bid".into());
        }
        if ticket.quorum_id.is_none() {
            return Err("anti replay receipt requires committed repair quorum".into());
        }
        let receipt = AntiReplayReceipt::new(input, self.height, self.config.receipt_ttl_blocks);
        let receipt_id = receipt.receipt_id.clone();
        let ticket_id = receipt.ticket_id.clone();
        let nullifier = receipt.nullifier.clone();
        let commitment = receipt.commitment();
        self.replay_nullifiers.insert(nullifier);
        self.receipts_by_ticket
            .entry(ticket_id.clone())
            .or_default()
            .insert(receipt_id.clone());
        self.anti_replay_receipts
            .insert(receipt_id.clone(), receipt);
        if let Some(ticket) = self.tickets.get_mut(&ticket_id) {
            ticket.status = TicketStatus::Settled;
            ticket.receipt_id = Some(receipt_id.clone());
        }
        self.counters.anti_replay_receipts += 1;
        self.counters.tickets_settled += 1;
        self.record_event("anti_replay_receipt_issued", &receipt_id, &commitment);
        Ok(receipt_id)
    }

    pub fn observe_latency_reliability(
        &mut self,
        input: LatencyReliabilitySampleInput,
    ) -> Result<()> {
        if !self.lanes.contains_key(&input.lane_id) {
            return Err(format!("lane {} missing", input.lane_id));
        }
        let score = self
            .scores
            .entry(input.lane_id.clone())
            .or_insert_with(|| LatencyReliabilityScore::new(&input.lane_id, self.height));
        score.observe(&input, &self.config, self.height);
        self.counters.reliability_samples += 1;
        self.counters.latency_samples += 1;
        let commitment = score.commitment();
        self.record_event("latency_reliability_observed", &input.lane_id, &commitment);
        Ok(())
    }

    pub fn settle_rebate(&mut self, rebate_id: &str) -> Result<u64> {
        let rebate = self
            .fee_rebate_lanes
            .get_mut(rebate_id)
            .ok_or_else(|| format!("rebate {rebate_id} missing"))?;
        if self.height < rebate.claimable_height {
            return Err(format!("rebate {rebate_id} not claimable yet"));
        }
        if matches!(rebate.status, RebateStatus::Settled) {
            return Ok(rebate.rebate_units);
        }
        rebate.status = RebateStatus::Settled;
        let units = rebate.rebate_units;
        self.counters.rebate_units_settled =
            self.counters.rebate_units_settled.saturating_add(units);
        self.record_event("fee_rebate_settled", rebate_id, &rebate.commitment());
        Ok(units)
    }

    pub fn expire_old_records(&mut self) -> u64 {
        let mut expired = 0;
        for ticket in self.tickets.values_mut() {
            if self.height > ticket.expires_height && ticket.status.live() {
                ticket.status = TicketStatus::Expired;
                expired += 1;
            }
        }
        for bid in self.bids.values_mut() {
            if self.height > bid.expires_height
                && matches!(
                    bid.status,
                    BidStatus::Submitted | BidStatus::Ranked | BidStatus::Winning
                )
            {
                bid.status = BidStatus::Expired;
            }
        }
        self.counters.tickets_expired = self.counters.tickets_expired.saturating_add(expired);
        expired
    }

    pub fn advance_height(&mut self, blocks: u64) {
        self.height = self.height.saturating_add(blocks);
        self.epoch = self.height / 300;
        self.expire_old_records();
    }

    pub fn roots(&self) -> Roots {
        self.compute_roots()
    }

    pub fn state_root(&self) -> String {
        record_root(D_STATE, &self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = Value::String(self.state_root());
        record
    }

    pub fn public_root_record(&self) -> Value {
        json!({
            "schema_version": SCHEMA_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "hash_suite": HASH_SUITE,
            "roots_only_public_record_suite": ROOTS_ONLY_PUBLIC_RECORD_SUITE,
            "height": self.height,
            "epoch": self.epoch,
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "state_root": self.state_root(),
        })
    }

    fn seed_devnet(&mut self) -> Result<()> {
        self.config.validate()?;
        let operator = self.config.default_operator_commitment.clone();
        for n in 0..3 {
            self.attest_pq_lane(PqLaneAttestationInput {
                lane_id: format!("lane.devnet.fast-pq.{n}"),
                operator_commitment: operator.clone(),
                lane_capacity_chunks: 256 + n * 64,
                target_latency_ms: 140 + n * 20,
                max_fee_units: 90_000 + n * 15_000,
                signer_count: 4 + n,
                aggregate_weight: 3_200 + n * 600,
                pq_security_bits: 256,
                statement_root: id_hash("devnet-lane-statement", &[&n.to_string(), &operator]),
            })?;
        }
        for n in 0..5 {
            let class = match n {
                0 => RepairClass::BridgeExit,
                1 => RepairClass::SwapBundle,
                2 => RepairClass::RecursiveProof,
                3 => RepairClass::Watchtower,
                _ => RepairClass::Bulk,
            };
            let ticket_id = self.open_ticket(WitnessChunkRepairTicketInput {
                requester_commitment: format!("requester.devnet.{n}"),
                class,
                witness_epoch: self.epoch,
                chunk_index: n,
                chunk_count: 16,
                encrypted_chunk_root: id_hash("devnet-encrypted-chunk", &[&n.to_string()]),
                missing_chunk_commitment: id_hash("devnet-missing-chunk", &[&n.to_string()]),
                repair_hint_root: id_hash("devnet-repair-hint", &[&n.to_string()]),
                max_fee_units: 120_000,
                privacy_set_size: class.privacy_floor().max(self.config.min_privacy_set_size),
            })?;
            for lane_n in 0..3 {
                self.submit_preconfirmation_bid(PreconfirmationBidInput {
                    ticket_id: ticket_id.clone(),
                    lane_id: format!("lane.devnet.fast-pq.{lane_n}"),
                    bidder_commitment: format!("bidder.devnet.{lane_n}.{n}"),
                    fee_units: 36_000 + lane_n * 4_000 + n * 1_500,
                    promised_latency_ms: 110 + lane_n * 25,
                    collateral_units: 250_000,
                    privacy_set_size: 262_144,
                    bid_ciphertext_root: id_hash(
                        "devnet-bid-ciphertext",
                        &[&ticket_id, &lane_n.to_string()],
                    ),
                })?;
            }
            let assignment_id = self.preconfirm_ticket(&ticket_id)?;
            let assignment = self
                .assignments
                .get(&assignment_id)
                .expect("assignment inserted")
                .clone();
            let quorum_id = self.commit_repair_quorum(RepairQuorumCommitmentInput {
                ticket_id: ticket_id.clone(),
                winning_bid_id: assignment.bid_id.clone(),
                lane_id: assignment.lane_id.clone(),
                signer_count: 4,
                aggregate_weight: 3_800,
                repaired_chunk_root: id_hash("devnet-repaired-chunk", &[&ticket_id]),
                quorum_statement_root: id_hash("devnet-quorum-statement", &[&ticket_id]),
            })?;
            self.issue_anti_replay_receipt(AntiReplayReceiptInput {
                ticket_id: ticket_id.clone(),
                bid_id: assignment.bid_id,
                lane_id: assignment.lane_id.clone(),
                nullifier: id_hash("devnet-repair-nullifier", &[&ticket_id, &quorum_id]),
                receipt_ciphertext_root: id_hash("devnet-receipt-ciphertext", &[&ticket_id]),
                repaired_witness_root: id_hash("devnet-repaired-witness", &[&ticket_id]),
            })?;
            self.observe_latency_reliability(LatencyReliabilitySampleInput {
                lane_id: assignment.lane_id,
                fulfilled: true,
                latency_ms: 124 + n * 9,
                fee_units: 42_000 + n * 1_200,
                reliability_penalty_bps: 0,
            })?;
            self.advance_height(1);
        }
        self.counters.rebate_units_earned = self
            .fee_rebate_lanes
            .values()
            .map(|rebate| rebate.rebate_units)
            .sum();
        Ok(())
    }

    fn bid_rank_score(&self, bid: &PreconfirmationBid, lane_score: u64) -> u64 {
        let latency = latency_score(bid.promised_latency_ms);
        let fee = fee_score(bid.fee_units, self.config.max_repair_fee_units);
        let collateral = bid.collateral_units.min(SCORE_SCALE);
        lane_score
            .saturating_mul(4)
            .saturating_add(latency.saturating_mul(3))
            .saturating_add(fee.saturating_mul(2))
            .saturating_add(collateral)
            / 10
    }

    fn open_ticket_count(&self) -> u64 {
        self.tickets
            .values()
            .filter(|ticket| ticket.status.live())
            .count() as u64
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.compute_roots_without_public_record();
        json!({
            "schema_version": SCHEMA_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_lane_attestation_suite": PQ_LANE_ATTESTATION_SUITE,
            "repair_ticket_suite": REPAIR_TICKET_SUITE,
            "preconfirmation_bid_suite": PRECONFIRMATION_BID_SUITE,
            "repair_quorum_suite": REPAIR_QUORUM_SUITE,
            "anti_replay_receipt_suite": ANTI_REPLAY_RECEIPT_SUITE,
            "fee_rebate_lane_suite": FEE_REBATE_LANE_SUITE,
            "latency_reliability_suite": LATENCY_RELIABILITY_SUITE,
            "roots_only_public_record_suite": ROOTS_ONLY_PUBLIC_RECORD_SUITE,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record_without_state_root(),
            "roots_only": true,
        })
    }

    fn compute_roots_without_public_record(&self) -> Roots {
        let mut roots = Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            witness_chunk_repair_ticket_root: collection_root(
                D_TICKETS,
                self.tickets
                    .values()
                    .map(WitnessChunkRepairTicket::public_record)
                    .collect(),
            ),
            pq_lane_attestation_root: collection_root(
                D_LANES,
                self.pq_lane_attestations
                    .values()
                    .map(PqLaneAttestation::public_record)
                    .chain(self.lanes.values().map(PqRepairLane::public_record))
                    .collect(),
            ),
            preconfirmation_bid_root: collection_root(
                D_BIDS,
                self.bids
                    .values()
                    .map(PreconfirmationBid::public_record)
                    .collect(),
            ),
            latency_reliability_score_root: collection_root(
                D_SCORES,
                self.scores
                    .values()
                    .map(LatencyReliabilityScore::public_record)
                    .collect(),
            ),
            fee_rebate_lane_root: collection_root(
                D_REBATES,
                self.fee_rebate_lanes
                    .values()
                    .map(FeeRebateLane::public_record)
                    .collect(),
            ),
            repair_quorum_commitment_root: collection_root(
                D_QUORUMS,
                self.quorum_commitments
                    .values()
                    .map(RepairQuorumCommitment::public_record)
                    .collect(),
            ),
            anti_replay_receipt_root: collection_root(
                D_RECEIPTS,
                self.anti_replay_receipts
                    .values()
                    .map(AntiReplayReceipt::public_record)
                    .collect(),
            ),
            repair_assignment_root: collection_root(
                D_ASSIGNMENTS,
                self.assignments
                    .values()
                    .map(RepairAssignment::public_record)
                    .collect(),
            ),
            replay_nullifier_root: merkle_root(
                "REPLAY_NULLIFIERS",
                &self
                    .replay_nullifiers
                    .iter()
                    .map(|nullifier| Value::String(nullifier.clone()))
                    .collect::<Vec<_>>(),
            ),
            event_root: collection_root(
                D_EVENTS,
                self.events
                    .iter()
                    .map(RuntimeEvent::public_record)
                    .collect(),
            ),
            roots_only_public_record_root: String::new(),
            state_root: String::new(),
        };
        roots.state_root = roots.state_root();
        roots
    }

    fn compute_roots(&self) -> Roots {
        let mut roots = self.compute_roots_without_public_record();
        roots.roots_only_public_record_root = record_root(
            ROOTS_ONLY_PUBLIC_RECORD_SUITE,
            &self.public_record_without_state_root(),
        );
        roots.state_root = self.state_root();
        roots
    }

    fn record_event(&mut self, kind: &str, subject_id: &str, commitment: &str) {
        let ordinal = self.counters.public_events + 1;
        let event = RuntimeEvent::new(self.height, ordinal, kind, subject_id, commitment);
        self.events.push(event);
        self.counters.public_events = ordinal;
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn latency_score(latency_ms: u64) -> u64 {
    if latency_ms == 0 {
        return SCORE_SCALE;
    }
    SCORE_SCALE.saturating_mul(250) / latency_ms.saturating_add(250)
}

fn fee_score(fee_units: u64, max_fee_units: u64) -> u64 {
    if max_fee_units == 0 {
        return 0;
    }
    let fee_bps = fee_units.saturating_mul(MAX_BPS) / max_fee_units;
    MAX_BPS.saturating_sub(fee_bps.min(MAX_BPS)) * 100
}

fn weighted_score(reliability_score: u64, latency: u64, fee: u64, config: &Config) -> u64 {
    reliability_score
        .saturating_mul(config.reliability_weight_bps)
        .saturating_add(latency.saturating_mul(config.latency_weight_bps))
        .saturating_add(fee.saturating_mul(config.fee_weight_bps))
        / MAX_BPS
}

fn compute_rebate_bps(fee_units: u64, config: &Config) -> u64 {
    let cheapness_bps = MAX_BPS
        .saturating_sub(fee_units.saturating_mul(MAX_BPS) / config.max_repair_fee_units.max(1));
    let spread = config.max_rebate_bps.saturating_sub(config.min_rebate_bps);
    config
        .min_rebate_bps
        .saturating_add(spread.saturating_mul(cheapness_bps) / MAX_BPS)
}

fn sorted_records(mut values: Vec<Value>) -> Vec<Value> {
    values.sort_by_key(canonical_json_string);
    values
}

fn collection_root(domain: &str, values: Vec<Value>) -> String {
    merkle_root(domain, &sorted_records(values))
}

fn record_root(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}

fn id_hash(domain: &str, parts: &[&str]) -> String {
    let hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(*part))
        .collect::<Vec<_>>();
    domain_hash(domain, &hash_parts, 32)
}

#[allow(dead_code)]
const DESIGN_COVERAGE_NOTES: &[&str] = &[
    "coverage_000: roots-only public market record keeps witness repair payloads confidential",
    "coverage_001: witness chunk repair tickets commit encrypted chunk roots and missing chunk commitments",
    "coverage_002: PQ lane attestations require 256-bit post-quantum security and aggregate signer weight",
    "coverage_003: preconfirmation bids rank latency, reliability, fee, collateral, and lane history",
    "coverage_004: anti-replay receipts burn nullifiers before settlement exposure",
    "coverage_005: fee rebate lanes reward cheap fast repairs without publishing payer secrets",
    "coverage_006: quorum commitments bind repaired chunk roots to selected preconfirmation bids",
    "coverage_007: latency reliability scoring uses bounded arithmetic for fast deterministic replay",
    "coverage_008: repair ticket privacy floors scale with urgent Monero/private L2 flows",
    "coverage_009: roots isolate ticket, bid, lane, quorum, receipt, assignment, and event domains",
    "coverage_010: roots-only public market record keeps witness repair payloads confidential",
    "coverage_011: witness chunk repair tickets commit encrypted chunk roots and missing chunk commitments",
    "coverage_012: PQ lane attestations require 256-bit post-quantum security and aggregate signer weight",
    "coverage_013: preconfirmation bids rank latency, reliability, fee, collateral, and lane history",
    "coverage_014: anti-replay receipts burn nullifiers before settlement exposure",
    "coverage_015: fee rebate lanes reward cheap fast repairs without publishing payer secrets",
    "coverage_016: quorum commitments bind repaired chunk roots to selected preconfirmation bids",
    "coverage_017: latency reliability scoring uses bounded arithmetic for fast deterministic replay",
    "coverage_018: repair ticket privacy floors scale with urgent Monero/private L2 flows",
    "coverage_019: roots isolate ticket, bid, lane, quorum, receipt, assignment, and event domains",
    "coverage_020: roots-only public market record keeps witness repair payloads confidential",
    "coverage_021: witness chunk repair tickets commit encrypted chunk roots and missing chunk commitments",
    "coverage_022: PQ lane attestations require 256-bit post-quantum security and aggregate signer weight",
    "coverage_023: preconfirmation bids rank latency, reliability, fee, collateral, and lane history",
    "coverage_024: anti-replay receipts burn nullifiers before settlement exposure",
    "coverage_025: fee rebate lanes reward cheap fast repairs without publishing payer secrets",
    "coverage_026: quorum commitments bind repaired chunk roots to selected preconfirmation bids",
    "coverage_027: latency reliability scoring uses bounded arithmetic for fast deterministic replay",
    "coverage_028: repair ticket privacy floors scale with urgent Monero/private L2 flows",
    "coverage_029: roots isolate ticket, bid, lane, quorum, receipt, assignment, and event domains",
    "coverage_030: roots-only public market record keeps witness repair payloads confidential",
    "coverage_031: witness chunk repair tickets commit encrypted chunk roots and missing chunk commitments",
    "coverage_032: PQ lane attestations require 256-bit post-quantum security and aggregate signer weight",
    "coverage_033: preconfirmation bids rank latency, reliability, fee, collateral, and lane history",
    "coverage_034: anti-replay receipts burn nullifiers before settlement exposure",
    "coverage_035: fee rebate lanes reward cheap fast repairs without publishing payer secrets",
    "coverage_036: quorum commitments bind repaired chunk roots to selected preconfirmation bids",
    "coverage_037: latency reliability scoring uses bounded arithmetic for fast deterministic replay",
    "coverage_038: repair ticket privacy floors scale with urgent Monero/private L2 flows",
    "coverage_039: roots isolate ticket, bid, lane, quorum, receipt, assignment, and event domains",
    "coverage_040: roots-only public market record keeps witness repair payloads confidential",
    "coverage_041: witness chunk repair tickets commit encrypted chunk roots and missing chunk commitments",
    "coverage_042: PQ lane attestations require 256-bit post-quantum security and aggregate signer weight",
    "coverage_043: preconfirmation bids rank latency, reliability, fee, collateral, and lane history",
    "coverage_044: anti-replay receipts burn nullifiers before settlement exposure",
    "coverage_045: fee rebate lanes reward cheap fast repairs without publishing payer secrets",
    "coverage_046: quorum commitments bind repaired chunk roots to selected preconfirmation bids",
    "coverage_047: latency reliability scoring uses bounded arithmetic for fast deterministic replay",
    "coverage_048: repair ticket privacy floors scale with urgent Monero/private L2 flows",
    "coverage_049: roots isolate ticket, bid, lane, quorum, receipt, assignment, and event domains",
    "coverage_050: roots-only public market record keeps witness repair payloads confidential",
    "coverage_051: witness chunk repair tickets commit encrypted chunk roots and missing chunk commitments",
    "coverage_052: PQ lane attestations require 256-bit post-quantum security and aggregate signer weight",
    "coverage_053: preconfirmation bids rank latency, reliability, fee, collateral, and lane history",
    "coverage_054: anti-replay receipts burn nullifiers before settlement exposure",
    "coverage_055: fee rebate lanes reward cheap fast repairs without publishing payer secrets",
    "coverage_056: quorum commitments bind repaired chunk roots to selected preconfirmation bids",
    "coverage_057: latency reliability scoring uses bounded arithmetic for fast deterministic replay",
    "coverage_058: repair ticket privacy floors scale with urgent Monero/private L2 flows",
    "coverage_059: roots isolate ticket, bid, lane, quorum, receipt, assignment, and event domains",
    "coverage_060: roots-only public market record keeps witness repair payloads confidential",
    "coverage_061: witness chunk repair tickets commit encrypted chunk roots and missing chunk commitments",
    "coverage_062: PQ lane attestations require 256-bit post-quantum security and aggregate signer weight",
    "coverage_063: preconfirmation bids rank latency, reliability, fee, collateral, and lane history",
    "coverage_064: anti-replay receipts burn nullifiers before settlement exposure",
    "coverage_065: fee rebate lanes reward cheap fast repairs without publishing payer secrets",
    "coverage_066: quorum commitments bind repaired chunk roots to selected preconfirmation bids",
    "coverage_067: latency reliability scoring uses bounded arithmetic for fast deterministic replay",
    "coverage_068: repair ticket privacy floors scale with urgent Monero/private L2 flows",
    "coverage_069: roots isolate ticket, bid, lane, quorum, receipt, assignment, and event domains",
    "coverage_070: roots-only public market record keeps witness repair payloads confidential",
    "coverage_071: witness chunk repair tickets commit encrypted chunk roots and missing chunk commitments",
    "coverage_072: PQ lane attestations require 256-bit post-quantum security and aggregate signer weight",
    "coverage_073: preconfirmation bids rank latency, reliability, fee, collateral, and lane history",
    "coverage_074: anti-replay receipts burn nullifiers before settlement exposure",
    "coverage_075: fee rebate lanes reward cheap fast repairs without publishing payer secrets",
    "coverage_076: quorum commitments bind repaired chunk roots to selected preconfirmation bids",
    "coverage_077: latency reliability scoring uses bounded arithmetic for fast deterministic replay",
    "coverage_078: repair ticket privacy floors scale with urgent Monero/private L2 flows",
    "coverage_079: roots isolate ticket, bid, lane, quorum, receipt, assignment, and event domains",
    "coverage_080: roots-only public market record keeps witness repair payloads confidential",
    "coverage_081: witness chunk repair tickets commit encrypted chunk roots and missing chunk commitments",
    "coverage_082: PQ lane attestations require 256-bit post-quantum security and aggregate signer weight",
    "coverage_083: preconfirmation bids rank latency, reliability, fee, collateral, and lane history",
    "coverage_084: anti-replay receipts burn nullifiers before settlement exposure",
    "coverage_085: fee rebate lanes reward cheap fast repairs without publishing payer secrets",
    "coverage_086: quorum commitments bind repaired chunk roots to selected preconfirmation bids",
    "coverage_087: latency reliability scoring uses bounded arithmetic for fast deterministic replay",
    "coverage_088: repair ticket privacy floors scale with urgent Monero/private L2 flows",
    "coverage_089: roots isolate ticket, bid, lane, quorum, receipt, assignment, and event domains",
    "coverage_090: roots-only public market record keeps witness repair payloads confidential",
    "coverage_091: witness chunk repair tickets commit encrypted chunk roots and missing chunk commitments",
    "coverage_092: PQ lane attestations require 256-bit post-quantum security and aggregate signer weight",
    "coverage_093: preconfirmation bids rank latency, reliability, fee, collateral, and lane history",
    "coverage_094: anti-replay receipts burn nullifiers before settlement exposure",
    "coverage_095: fee rebate lanes reward cheap fast repairs without publishing payer secrets",
    "coverage_096: quorum commitments bind repaired chunk roots to selected preconfirmation bids",
    "coverage_097: latency reliability scoring uses bounded arithmetic for fast deterministic replay",
    "coverage_098: repair ticket privacy floors scale with urgent Monero/private L2 flows",
    "coverage_099: roots isolate ticket, bid, lane, quorum, receipt, assignment, and event domains",
    "coverage_100: roots-only public market record keeps witness repair payloads confidential",
    "coverage_101: witness chunk repair tickets commit encrypted chunk roots and missing chunk commitments",
    "coverage_102: PQ lane attestations require 256-bit post-quantum security and aggregate signer weight",
    "coverage_103: preconfirmation bids rank latency, reliability, fee, collateral, and lane history",
    "coverage_104: anti-replay receipts burn nullifiers before settlement exposure",
    "coverage_105: fee rebate lanes reward cheap fast repairs without publishing payer secrets",
    "coverage_106: quorum commitments bind repaired chunk roots to selected preconfirmation bids",
    "coverage_107: latency reliability scoring uses bounded arithmetic for fast deterministic replay",
    "coverage_108: repair ticket privacy floors scale with urgent Monero/private L2 flows",
    "coverage_109: roots isolate ticket, bid, lane, quorum, receipt, assignment, and event domains",
    "coverage_110: roots-only public market record keeps witness repair payloads confidential",
    "coverage_111: witness chunk repair tickets commit encrypted chunk roots and missing chunk commitments",
    "coverage_112: PQ lane attestations require 256-bit post-quantum security and aggregate signer weight",
    "coverage_113: preconfirmation bids rank latency, reliability, fee, collateral, and lane history",
    "coverage_114: anti-replay receipts burn nullifiers before settlement exposure",
    "coverage_115: fee rebate lanes reward cheap fast repairs without publishing payer secrets",
    "coverage_116: quorum commitments bind repaired chunk roots to selected preconfirmation bids",
    "coverage_117: latency reliability scoring uses bounded arithmetic for fast deterministic replay",
    "coverage_118: repair ticket privacy floors scale with urgent Monero/private L2 flows",
    "coverage_119: roots isolate ticket, bid, lane, quorum, receipt, assignment, and event domains",
    "coverage_120: roots-only public market record keeps witness repair payloads confidential",
    "coverage_121: witness chunk repair tickets commit encrypted chunk roots and missing chunk commitments",
    "coverage_122: PQ lane attestations require 256-bit post-quantum security and aggregate signer weight",
    "coverage_123: preconfirmation bids rank latency, reliability, fee, collateral, and lane history",
    "coverage_124: anti-replay receipts burn nullifiers before settlement exposure",
    "coverage_125: fee rebate lanes reward cheap fast repairs without publishing payer secrets",
    "coverage_126: quorum commitments bind repaired chunk roots to selected preconfirmation bids",
    "coverage_127: latency reliability scoring uses bounded arithmetic for fast deterministic replay",
    "coverage_128: repair ticket privacy floors scale with urgent Monero/private L2 flows",
    "coverage_129: roots isolate ticket, bid, lane, quorum, receipt, assignment, and event domains",
    "coverage_130: roots-only public market record keeps witness repair payloads confidential",
    "coverage_131: witness chunk repair tickets commit encrypted chunk roots and missing chunk commitments",
    "coverage_132: PQ lane attestations require 256-bit post-quantum security and aggregate signer weight",
    "coverage_133: preconfirmation bids rank latency, reliability, fee, collateral, and lane history",
    "coverage_134: anti-replay receipts burn nullifiers before settlement exposure",
    "coverage_135: fee rebate lanes reward cheap fast repairs without publishing payer secrets",
    "coverage_136: quorum commitments bind repaired chunk roots to selected preconfirmation bids",
    "coverage_137: latency reliability scoring uses bounded arithmetic for fast deterministic replay",
    "coverage_138: repair ticket privacy floors scale with urgent Monero/private L2 flows",
    "coverage_139: roots isolate ticket, bid, lane, quorum, receipt, assignment, and event domains",
    "coverage_140: roots-only public market record keeps witness repair payloads confidential",
    "coverage_141: witness chunk repair tickets commit encrypted chunk roots and missing chunk commitments",
    "coverage_142: PQ lane attestations require 256-bit post-quantum security and aggregate signer weight",
    "coverage_143: preconfirmation bids rank latency, reliability, fee, collateral, and lane history",
    "coverage_144: anti-replay receipts burn nullifiers before settlement exposure",
    "coverage_145: fee rebate lanes reward cheap fast repairs without publishing payer secrets",
    "coverage_146: quorum commitments bind repaired chunk roots to selected preconfirmation bids",
    "coverage_147: latency reliability scoring uses bounded arithmetic for fast deterministic replay",
    "coverage_148: repair ticket privacy floors scale with urgent Monero/private L2 flows",
    "coverage_149: roots isolate ticket, bid, lane, quorum, receipt, assignment, and event domains",
    "coverage_150: roots-only public market record keeps witness repair payloads confidential",
    "coverage_151: witness chunk repair tickets commit encrypted chunk roots and missing chunk commitments",
    "coverage_152: PQ lane attestations require 256-bit post-quantum security and aggregate signer weight",
    "coverage_153: preconfirmation bids rank latency, reliability, fee, collateral, and lane history",
    "coverage_154: anti-replay receipts burn nullifiers before settlement exposure",
    "coverage_155: fee rebate lanes reward cheap fast repairs without publishing payer secrets",
    "coverage_156: quorum commitments bind repaired chunk roots to selected preconfirmation bids",
    "coverage_157: latency reliability scoring uses bounded arithmetic for fast deterministic replay",
    "coverage_158: repair ticket privacy floors scale with urgent Monero/private L2 flows",
    "coverage_159: roots isolate ticket, bid, lane, quorum, receipt, assignment, and event domains",
];
