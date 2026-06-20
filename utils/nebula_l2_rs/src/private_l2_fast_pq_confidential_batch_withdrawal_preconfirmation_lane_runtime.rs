use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialBatchWithdrawalPreconfirmationLaneRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_BATCH_WITHDRAWAL_PRECONFIRMATION_LANE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-batch-withdrawal-preconfirmation-lane-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_BATCH_WITHDRAWAL_PRECONFIRMATION_LANE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_RECEIPT_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-withdrawal-preconfirmation-v1";
pub const ENCRYPTED_BATCH_SUITE: &str =
    "ml-kem-threshold-confidential-withdrawal-batch-envelope-v1";
pub const LANE_COMMITTEE_SUITE: &str =
    "weighted-confidential-withdrawal-preconfirmation-lane-committee-v1";
pub const WITNESS_COMMITMENT_SUITE: &str =
    "monero-private-l2-withdrawal-witness-commitment-root-v1";
pub const SLA_WINDOW_SUITE: &str = "fast-confidential-withdrawal-sla-window-root-v1";
pub const BACKPRESSURE_SUITE: &str = "withdrawal-lane-backpressure-control-root-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-confidential-withdrawal-lane-rebate-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 2_940_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_560_000;
pub const DEVNET_EPOCH: u64 = 22_176;
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "piconero-devnet-rebate";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_BATCH_MAX_WITHDRAWALS: u32 = 512;
pub const DEFAULT_BATCH_MAX_BYTES: u64 = 1_048_576;
pub const DEFAULT_TARGET_PRECONFIRMATION_MS: u64 = 180;
pub const DEFAULT_SOFT_SLA_MS: u64 = 350;
pub const DEFAULT_HARD_SLA_MS: u64 = 900;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 8;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_COMMITTEE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 32;
pub const DEFAULT_BACKPRESSURE_HIGH_WATERMARK_BPS: u64 = 8_500;
pub const DEFAULT_BACKPRESSURE_LOW_WATERMARK_BPS: u64 = 5_500;
pub const DEFAULT_MIN_LANE_BOND_MICRO_UNITS: u64 = 75_000_000;
pub const DEFAULT_MAX_LANES: usize = 8_192;
pub const DEFAULT_MAX_BATCHES: usize = 1_048_576;
pub const DEFAULT_MAX_COMMITTEES: usize = 262_144;
pub const DEFAULT_MAX_WITNESSES: usize = 2_097_152;
pub const DEFAULT_MAX_RECEIPTS: usize = 2_097_152;
pub const DEFAULT_MAX_SLA_WINDOWS: usize = 2_097_152;
pub const DEFAULT_MAX_BACKPRESSURE_CONTROLS: usize = 524_288;
pub const DEFAULT_MAX_REBATES: usize = 1_048_576;
pub const DEFAULT_MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalLaneKind {
    StandardExit,
    MerchantPayout,
    LiquidityProviderExit,
    EmergencyExit,
    ReserveRebalance,
}

impl WithdrawalLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StandardExit => "standard_exit",
            Self::MerchantPayout => "merchant_payout",
            Self::LiquidityProviderExit => "liquidity_provider_exit",
            Self::EmergencyExit => "emergency_exit",
            Self::ReserveRebalance => "reserve_rebalance",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Registered,
    Open,
    Congested,
    Backpressured,
    Draining,
    Paused,
    Slashed,
    Retired,
}

impl LaneStatus {
    pub fn accepts_batches(self) -> bool {
        matches!(self, Self::Registered | Self::Open | Self::Congested)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Encrypted,
    WitnessCommitted,
    CommitteeAssigned,
    Preconfirmed,
    Receipted,
    SubmittedToMonero,
    Settled,
    Expired,
    Challenged,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Registered,
    Assigned,
    Attesting,
    QuorumReached,
    StrongQuorum,
    Rotating,
    Challenged,
    Slashed,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlaWindowStatus {
    Open,
    SoftBreached,
    HardBreached,
    Satisfied,
    Challenged,
    Closed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackpressureMode {
    Observe,
    SlowAdmission,
    QueueOnly,
    RebateOnly,
    Drain,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub hash_suite: String,
    pub pq_receipt_suite: String,
    pub encrypted_batch_suite: String,
    pub lane_committee_suite: String,
    pub witness_commitment_suite: String,
    pub sla_window_suite: String,
    pub backpressure_suite: String,
    pub low_fee_rebate_suite: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub batch_max_withdrawals: u32,
    pub batch_max_bytes: u64,
    pub target_preconfirmation_ms: u64,
    pub soft_sla_ms: u64,
    pub hard_sla_ms: u64,
    pub batch_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub committee_quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub backpressure_high_watermark_bps: u64,
    pub backpressure_low_watermark_bps: u64,
    pub min_lane_bond_micro_units: u64,
    pub max_lanes: usize,
    pub max_batches: usize,
    pub max_committees: usize,
    pub max_witnesses: usize,
    pub max_receipts: usize,
    pub max_sla_windows: usize,
    pub max_backpressure_controls: usize,
    pub max_rebates: usize,
    pub max_events: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_receipt_suite: PQ_RECEIPT_SUITE.to_string(),
            encrypted_batch_suite: ENCRYPTED_BATCH_SUITE.to_string(),
            lane_committee_suite: LANE_COMMITTEE_SUITE.to_string(),
            witness_commitment_suite: WITNESS_COMMITMENT_SUITE.to_string(),
            sla_window_suite: SLA_WINDOW_SUITE.to_string(),
            backpressure_suite: BACKPRESSURE_SUITE.to_string(),
            low_fee_rebate_suite: LOW_FEE_REBATE_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            batch_max_withdrawals: DEFAULT_BATCH_MAX_WITHDRAWALS,
            batch_max_bytes: DEFAULT_BATCH_MAX_BYTES,
            target_preconfirmation_ms: DEFAULT_TARGET_PRECONFIRMATION_MS,
            soft_sla_ms: DEFAULT_SOFT_SLA_MS,
            hard_sla_ms: DEFAULT_HARD_SLA_MS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            committee_quorum_bps: DEFAULT_COMMITTEE_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            backpressure_high_watermark_bps: DEFAULT_BACKPRESSURE_HIGH_WATERMARK_BPS,
            backpressure_low_watermark_bps: DEFAULT_BACKPRESSURE_LOW_WATERMARK_BPS,
            min_lane_bond_micro_units: DEFAULT_MIN_LANE_BOND_MICRO_UNITS,
            max_lanes: DEFAULT_MAX_LANES,
            max_batches: DEFAULT_MAX_BATCHES,
            max_committees: DEFAULT_MAX_COMMITTEES,
            max_witnesses: DEFAULT_MAX_WITNESSES,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_sla_windows: DEFAULT_MAX_SLA_WINDOWS,
            max_backpressure_controls: DEFAULT_MAX_BACKPRESSURE_CONTROLS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_events: DEFAULT_MAX_EVENTS,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_nonempty("rebate_asset_id", &self.rebate_asset_id)?;
        ensure_bps("committee_quorum_bps", self.committee_quorum_bps)?;
        ensure_bps("strong_quorum_bps", self.strong_quorum_bps)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("target_rebate_bps", self.target_rebate_bps)?;
        ensure_bps("max_rebate_bps", self.max_rebate_bps)?;
        ensure_bps(
            "backpressure_high_watermark_bps",
            self.backpressure_high_watermark_bps,
        )?;
        ensure_bps(
            "backpressure_low_watermark_bps",
            self.backpressure_low_watermark_bps,
        )?;
        if self.strong_quorum_bps < self.committee_quorum_bps {
            return Err("withdrawal preconfirmation strong quorum below quorum".to_string());
        }
        if self.hard_sla_ms < self.soft_sla_ms {
            return Err("withdrawal preconfirmation hard SLA below soft SLA".to_string());
        }
        if self.backpressure_high_watermark_bps <= self.backpressure_low_watermark_bps {
            return Err("withdrawal preconfirmation backpressure watermarks inverted".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub lane_count: u64,
    pub batch_count: u64,
    pub committee_count: u64,
    pub witness_count: u64,
    pub receipt_count: u64,
    pub sla_window_count: u64,
    pub backpressure_control_count: u64,
    pub rebate_count: u64,
    pub event_count: u64,
    pub total_withdrawal_micro_units: u64,
    pub total_fee_charged_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub total_backpressured_batches: u64,
}

impl Counters {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub lanes_root: String,
    pub batches_root: String,
    pub committees_root: String,
    pub witness_commitments_root: String,
    pub receipts_root: String,
    pub sla_windows_root: String,
    pub backpressure_controls_root: String,
    pub rebates_root: String,
    pub events_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            lanes_root: empty_root("lanes"),
            batches_root: empty_root("batches"),
            committees_root: empty_root("committees"),
            witness_commitments_root: empty_root("witness-commitments"),
            receipts_root: empty_root("receipts"),
            sla_windows_root: empty_root("sla-windows"),
            backpressure_controls_root: empty_root("backpressure-controls"),
            rebates_root: empty_root("rebates"),
            events_root: empty_root("events"),
            state_root: empty_root("state"),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawalLane {
    pub lane_id: String,
    pub lane_index: u64,
    pub kind: WithdrawalLaneKind,
    pub status: LaneStatus,
    pub operator_commitment: String,
    pub committee_roster_root: String,
    pub pq_verifying_key_root: String,
    pub reserve_commitment_root: String,
    pub capacity_micro_units: u64,
    pub queued_micro_units: u64,
    pub max_fee_bps: u64,
    pub bond_micro_units: u64,
    pub privacy_set_size: u64,
    pub opened_l2_height: u64,
    pub metadata_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedWithdrawalBatch {
    pub batch_id: String,
    pub batch_index: u64,
    pub lane_id: String,
    pub status: BatchStatus,
    pub encrypted_payload_root: String,
    pub withdrawal_count: u32,
    pub total_amount_commitment: String,
    pub fee_commitment: String,
    pub output_commitment_root: String,
    pub nullifier_fence_root: String,
    pub witness_commitment_id: String,
    pub committee_id: String,
    pub receipt_id: String,
    pub user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub submitted_l2_height: u64,
    pub expires_l2_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneCommittee {
    pub committee_id: String,
    pub committee_index: u64,
    pub lane_id: String,
    pub status: CommitteeStatus,
    pub member_set_root: String,
    pub aggregate_pq_key_root: String,
    pub quorum_weight_bps: u64,
    pub strong_quorum_weight_bps: u64,
    pub epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessCommitment {
    pub witness_id: String,
    pub witness_index: u64,
    pub batch_id: String,
    pub lane_id: String,
    pub monero_anchor_height: u64,
    pub ring_member_root: String,
    pub range_proof_root: String,
    pub key_image_commitment_root: String,
    pub view_tag_root: String,
    pub deterministic_witness_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqPreconfirmationReceipt {
    pub receipt_id: String,
    pub receipt_index: u64,
    pub batch_id: String,
    pub lane_id: String,
    pub committee_id: String,
    pub status: BatchStatus,
    pub preconfirmed_l2_height: u64,
    pub preconfirmation_latency_ms: u64,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub public_receipt_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlaWindow {
    pub window_id: String,
    pub window_index: u64,
    pub lane_id: String,
    pub batch_id: String,
    pub status: SlaWindowStatus,
    pub opened_l2_height: u64,
    pub target_ms: u64,
    pub soft_deadline_ms: u64,
    pub hard_deadline_ms: u64,
    pub observed_latency_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackpressureControl {
    pub control_id: String,
    pub control_index: u64,
    pub lane_id: String,
    pub mode: BackpressureMode,
    pub queued_batches: u64,
    pub queue_watermark_bps: u64,
    pub admission_cut_bps: u64,
    pub reason_root: String,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeLaneRebate {
    pub rebate_id: String,
    pub rebate_index: u64,
    pub lane_id: String,
    pub batch_id: String,
    pub recipient_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_amount_micro_units: u64,
    pub rebate_bps: u64,
    pub expires_l2_height: u64,
    pub settled: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_index: u64,
    pub kind: String,
    pub subject_id: String,
    pub l2_height: u64,
    pub record_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub lanes: BTreeMap<String, WithdrawalLane>,
    pub batches: BTreeMap<String, EncryptedWithdrawalBatch>,
    pub committees: BTreeMap<String, LaneCommittee>,
    pub witness_commitments: BTreeMap<String, WitnessCommitment>,
    pub receipts: BTreeMap<String, PqPreconfirmationReceipt>,
    pub sla_windows: BTreeMap<String, SlaWindow>,
    pub backpressure_controls: BTreeMap<String, BackpressureControl>,
    pub rebates: BTreeMap<String, LowFeeLaneRebate>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            lanes: BTreeMap::new(),
            batches: BTreeMap::new(),
            committees: BTreeMap::new(),
            witness_commitments: BTreeMap::new(),
            receipts: BTreeMap::new(),
            sla_windows: BTreeMap::new(),
            backpressure_controls: BTreeMap::new(),
            rebates: BTreeMap::new(),
            events: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        state.seed_devnet_records();
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_batch_withdrawal_preconfirmation_lane_runtime",
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "fee_asset_id": self.config.fee_asset_id,
            "rebate_asset_id": self.config.rebate_asset_id,
            "hash_suite": self.config.hash_suite,
            "pq_receipt_suite": self.config.pq_receipt_suite,
            "encrypted_batch_suite": self.config.encrypted_batch_suite,
            "lane_committee_suite": self.config.lane_committee_suite,
            "witness_commitment_suite": self.config.witness_commitment_suite,
            "sla_window_suite": self.config.sla_window_suite,
            "backpressure_suite": self.config.backpressure_suite,
            "low_fee_rebate_suite": self.config.low_fee_rebate_suite,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure_capacity("lanes", self.lanes.len(), self.config.max_lanes)?;
        ensure_capacity("batches", self.batches.len(), self.config.max_batches)?;
        ensure_capacity(
            "committees",
            self.committees.len(),
            self.config.max_committees,
        )?;
        ensure_capacity(
            "witness_commitments",
            self.witness_commitments.len(),
            self.config.max_witnesses,
        )?;
        ensure_capacity("receipts", self.receipts.len(), self.config.max_receipts)?;
        ensure_capacity(
            "sla_windows",
            self.sla_windows.len(),
            self.config.max_sla_windows,
        )?;
        ensure_capacity(
            "backpressure_controls",
            self.backpressure_controls.len(),
            self.config.max_backpressure_controls,
        )?;
        ensure_capacity("rebates", self.rebates.len(), self.config.max_rebates)?;
        ensure_capacity("events", self.events.len(), self.config.max_events)?;
        Ok(())
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            lanes_root: map_root("lanes", &self.lanes),
            batches_root: map_root("batches", &self.batches),
            committees_root: map_root("committees", &self.committees),
            witness_commitments_root: map_root("witness-commitments", &self.witness_commitments),
            receipts_root: map_root("receipts", &self.receipts),
            sla_windows_root: map_root("sla-windows", &self.sla_windows),
            backpressure_controls_root: map_root(
                "backpressure-controls",
                &self.backpressure_controls,
            ),
            rebates_root: map_root("rebates", &self.rebates),
            events_root: map_root("events", &self.events),
            state_root: empty_root("state"),
        };
        self.roots.state_root = self.state_root();
    }

    fn seed_devnet_records(&mut self) {
        let lane = WithdrawalLane {
            lane_id: deterministic_id("lane", 1, "devnet-withdrawal-operator"),
            lane_index: 1,
            kind: WithdrawalLaneKind::StandardExit,
            status: LaneStatus::Open,
            operator_commitment: "devnet-withdrawal-operator-commitment".to_string(),
            committee_roster_root: "devnet-withdrawal-committee-roster-root".to_string(),
            pq_verifying_key_root: "devnet-withdrawal-pq-verifying-key-root".to_string(),
            reserve_commitment_root: "devnet-withdrawal-reserve-commitment-root".to_string(),
            capacity_micro_units: 12_000_000_000,
            queued_micro_units: 240_000_000,
            max_fee_bps: 9,
            bond_micro_units: DEFAULT_MIN_LANE_BOND_MICRO_UNITS,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            opened_l2_height: DEVNET_L2_HEIGHT,
            metadata_root: "devnet-withdrawal-lane-metadata-root".to_string(),
        };
        let committee = LaneCommittee {
            committee_id: deterministic_id("committee", 1, &lane.lane_id),
            committee_index: 1,
            lane_id: lane.lane_id.clone(),
            status: CommitteeStatus::StrongQuorum,
            member_set_root: lane.committee_roster_root.clone(),
            aggregate_pq_key_root: lane.pq_verifying_key_root.clone(),
            quorum_weight_bps: DEFAULT_COMMITTEE_QUORUM_BPS,
            strong_quorum_weight_bps: DEFAULT_STRONG_QUORUM_BPS,
            epoch: DEVNET_EPOCH,
        };
        let batch_id = deterministic_id("batch", 1, &lane.lane_id);
        let witness = WitnessCommitment {
            witness_id: deterministic_id("witness", 1, &batch_id),
            witness_index: 1,
            batch_id: batch_id.clone(),
            lane_id: lane.lane_id.clone(),
            monero_anchor_height: DEVNET_MONERO_HEIGHT,
            ring_member_root: "devnet-ring-member-root".to_string(),
            range_proof_root: "devnet-bulletproof-plus-range-root".to_string(),
            key_image_commitment_root: "devnet-key-image-commitment-root".to_string(),
            view_tag_root: "devnet-view-tag-root".to_string(),
            deterministic_witness_root: deterministic_record_root(
                "witness",
                &json!({
                    "batch_id": batch_id,
                    "lane_id": lane.lane_id,
                    "monero_anchor_height": DEVNET_MONERO_HEIGHT,
                }),
            ),
        };
        let receipt = PqPreconfirmationReceipt {
            receipt_id: deterministic_id("receipt", 1, &batch_id),
            receipt_index: 1,
            batch_id: batch_id.clone(),
            lane_id: lane.lane_id.clone(),
            committee_id: committee.committee_id.clone(),
            status: BatchStatus::Preconfirmed,
            preconfirmed_l2_height: DEVNET_L2_HEIGHT + 1,
            preconfirmation_latency_ms: 142,
            pq_signature_root: "devnet-withdrawal-pq-signature-root".to_string(),
            transcript_root: "devnet-withdrawal-transcript-root".to_string(),
            public_receipt_root: deterministic_record_root(
                "receipt",
                &json!({ "batch_id": batch_id, "committee_id": committee.committee_id }),
            ),
        };
        let batch = EncryptedWithdrawalBatch {
            batch_id: batch_id.clone(),
            batch_index: 1,
            lane_id: lane.lane_id.clone(),
            status: BatchStatus::Preconfirmed,
            encrypted_payload_root: "devnet-encrypted-withdrawal-batch-root".to_string(),
            withdrawal_count: 64,
            total_amount_commitment: "devnet-total-withdrawal-amount-commitment".to_string(),
            fee_commitment: "devnet-withdrawal-fee-commitment".to_string(),
            output_commitment_root: "devnet-withdrawal-output-commitment-root".to_string(),
            nullifier_fence_root: "devnet-withdrawal-nullifier-fence-root".to_string(),
            witness_commitment_id: witness.witness_id.clone(),
            committee_id: committee.committee_id.clone(),
            receipt_id: receipt.receipt_id.clone(),
            user_fee_bps: 6,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            submitted_l2_height: DEVNET_L2_HEIGHT,
            expires_l2_height: DEVNET_L2_HEIGHT + DEFAULT_BATCH_TTL_BLOCKS,
        };
        let sla = SlaWindow {
            window_id: deterministic_id("sla", 1, &batch_id),
            window_index: 1,
            lane_id: lane.lane_id.clone(),
            batch_id: batch_id.clone(),
            status: SlaWindowStatus::Satisfied,
            opened_l2_height: DEVNET_L2_HEIGHT,
            target_ms: DEFAULT_TARGET_PRECONFIRMATION_MS,
            soft_deadline_ms: DEFAULT_SOFT_SLA_MS,
            hard_deadline_ms: DEFAULT_HARD_SLA_MS,
            observed_latency_ms: receipt.preconfirmation_latency_ms,
        };
        let backpressure = BackpressureControl {
            control_id: deterministic_id("backpressure", 1, &lane.lane_id),
            control_index: 1,
            lane_id: lane.lane_id.clone(),
            mode: BackpressureMode::Observe,
            queued_batches: 3,
            queue_watermark_bps: 2_000,
            admission_cut_bps: 0,
            reason_root: "devnet-withdrawal-backpressure-reason-root".to_string(),
            active: false,
        };
        let rebate = LowFeeLaneRebate {
            rebate_id: deterministic_id("rebate", 1, &batch_id),
            rebate_index: 1,
            lane_id: lane.lane_id.clone(),
            batch_id: batch_id.clone(),
            recipient_commitment: "devnet-withdrawal-rebate-recipient-commitment".to_string(),
            rebate_asset_id: self.config.rebate_asset_id.clone(),
            rebate_amount_micro_units: 18_000,
            rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            expires_l2_height: DEVNET_L2_HEIGHT + DEFAULT_REBATE_TTL_BLOCKS,
            settled: false,
        };
        self.lanes.insert(lane.lane_id.clone(), lane);
        self.committees
            .insert(committee.committee_id.clone(), committee);
        self.witness_commitments
            .insert(witness.witness_id.clone(), witness);
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        self.batches.insert(batch.batch_id.clone(), batch);
        self.sla_windows.insert(sla.window_id.clone(), sla);
        self.backpressure_controls
            .insert(backpressure.control_id.clone(), backpressure);
        self.rebates.insert(rebate.rebate_id.clone(), rebate);
        self.events.insert(
            deterministic_id("event", 1, &batch_id),
            RuntimeEvent {
                event_id: deterministic_id("event", 1, &batch_id),
                event_index: 1,
                kind: "withdrawal_batch_preconfirmed".to_string(),
                subject_id: batch_id,
                l2_height: DEVNET_L2_HEIGHT + 1,
                record_root: "devnet-withdrawal-preconfirmation-event-root".to_string(),
            },
        );
        self.counters = Counters {
            lane_count: self.lanes.len() as u64,
            batch_count: self.batches.len() as u64,
            committee_count: self.committees.len() as u64,
            witness_count: self.witness_commitments.len() as u64,
            receipt_count: self.receipts.len() as u64,
            sla_window_count: self.sla_windows.len() as u64,
            backpressure_control_count: self.backpressure_controls.len() as u64,
            rebate_count: self.rebates.len() as u64,
            event_count: self.events.len() as u64,
            total_withdrawal_micro_units: 240_000_000,
            total_fee_charged_micro_units: 14_400,
            total_rebate_micro_units: 18_000,
            total_backpressured_batches: 0,
        };
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> Value {
    State::devnet().public_record()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-batch-withdrawal-preconfirmation-lane:state-root",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn empty_root(name: &str) -> String {
    merkle_root(
        &format!("private-l2-fast-pq-confidential-batch-withdrawal-preconfirmation-lane:{name}"),
        &Vec::<Value>::new(),
    )
}

fn map_root<T: Serialize>(name: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-fast-pq-confidential-batch-withdrawal-preconfirmation-lane:{name}"),
        &leaves,
    )
}

fn deterministic_id(kind: &str, index: u64, seed: &str) -> String {
    format!(
        "{kind}-{}",
        domain_hash(
            "private-l2-fast-pq-confidential-batch-withdrawal-preconfirmation-lane:id",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind),
                HashPart::U64(index),
                HashPart::Str(seed),
            ],
            16,
        )
    )
}

fn deterministic_record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "private-l2-fast-pq-confidential-batch-withdrawal-preconfirmation-lane:record-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn ensure_nonempty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!(
            "withdrawal preconfirmation lane {label} must be non-empty"
        ))
    } else {
        Ok(())
    }
}

fn ensure_bps(label: &str, value: u64) -> Result<()> {
    if value <= MAX_BPS {
        Ok(())
    } else {
        Err(format!(
            "withdrawal preconfirmation lane {label} exceeds {MAX_BPS} bps"
        ))
    }
}

fn ensure_capacity(label: &str, len: usize, max: usize) -> Result<()> {
    if len <= max {
        Ok(())
    } else {
        Err(format!(
            "withdrawal preconfirmation lane {label} capacity exceeded: {len} > {max}"
        ))
    }
}

fn _deterministic_set_root(name: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("private-l2-fast-pq-confidential-batch-withdrawal-preconfirmation-lane:{name}"),
        &leaves,
    )
}
