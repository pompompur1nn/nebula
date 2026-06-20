use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2FastPqConfidentialParallelExitAuctionRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_EXIT_AUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-parallel-exit-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PARALLEL_EXIT_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUCTIONEER_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-auctioneer-attestation-v1";
pub const SEALED_EXIT_LOT_SUITE: &str = "ML-KEM-1024+xwing-sealed-confidential-exit-lot-v1";
pub const PARALLEL_SETTLEMENT_SUITE: &str =
    "recursive-confidential-parallel-exit-auction-settlement-v1";
pub const FAST_WITHDRAWAL_RECEIPT_SUITE: &str = "monero-private-l2-fast-withdrawal-receipt-v1";
pub const PRIVACY_REDACTION_SUITE: &str = "roots-only-exit-auction-public-redaction-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_EXIT_ASSET_ID: &str = "wxmr-devnet";
pub const DEFAULT_QUOTE_ASSET_ID: &str = "dusd-devnet";
pub const DEFAULT_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_911_040;
pub const DEVNET_EPOCH: u64 = 7_320;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_TARGET_FEE_BPS: u64 = 5;
pub const DEFAULT_MAX_FEE_BPS: u64 = 14;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 7_500;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 16;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 1_000_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_PARALLELISM: u64 = 16;
pub const DEFAULT_MAX_LOTS_PER_BATCH: u64 = 4_096;
pub const DEFAULT_QUARANTINE_BLOCKS: u64 = 12;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitLaneKind {
    MoneroFastExit,
    MoneroStandardExit,
    ConfidentialTokenExit,
    DappReceiptExit,
    EmergencyExit,
    MarketMakerBackstop,
    RebateOnly,
}

impl ExitLaneKind {
    pub fn default_priority(self) -> SettlementPriority {
        match self {
            Self::EmergencyExit => SettlementPriority::Critical,
            Self::MoneroFastExit | Self::DappReceiptExit => SettlementPriority::Fast,
            Self::ConfidentialTokenExit | Self::MarketMakerBackstop => SettlementPriority::Normal,
            Self::MoneroStandardExit | Self::RebateOnly => SettlementPriority::LowFee,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Congested,
    Quarantined,
    Draining,
    Paused,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LotStatus {
    Sealed,
    Admitted,
    Attested,
    BatchBound,
    Settled,
    Withdrawn,
    Expired,
    Quarantined,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctioneerStatus {
    Candidate,
    Active,
    Rotating,
    Suspended,
    Slashed,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationScope {
    LaneOpen,
    LotAdmission,
    FeeCap,
    PrivacyBudget,
    SettlementBatch,
    FastWithdrawal,
    QuarantineRelease,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementPriority {
    LowFee,
    Normal,
    Fast,
    Critical,
}

impl SettlementPriority {
    pub fn batch_weight(self) -> u64 {
        match self {
            Self::LowFee => 1,
            Self::Normal => 4,
            Self::Fast => 12,
            Self::Critical => 36,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Proposed,
    Attested,
    Parallelizing,
    Submitted,
    Settled,
    Rebated,
    Challenged,
    Quarantined,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Reserved,
    Proved,
    Broadcast,
    Confirmed,
    Rebated,
    Expired,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    CongestionSpike,
    FeeCapBreach,
    PrivacyBudgetExhausted,
    AuctioneerDisagreement,
    DuplicateNullifier,
    WithheldSettlementRoot,
    DemoFault,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionClass {
    UserIdentifier,
    AmountBucket,
    MoneroAddressHint,
    TimingHint,
    SolverIdentity,
    AuctionTranscript,
    WitnessPath,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub current_height: u64,
    pub epoch: u64,
    pub fee_asset_id: String,
    pub exit_asset_id: String,
    pub quote_asset_id: String,
    pub target_fee_bps: u64,
    pub max_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub auction_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub max_lots_per_batch: u64,
    pub max_parallel_batches: u64,
    pub quarantine_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub privacy_redaction_budget_units: u64,
    pub min_pq_security_bits: u16,
    pub hash_suite: String,
    pub pq_auctioneer_suite: String,
    pub sealed_exit_lot_suite: String,
    pub settlement_suite: String,
    pub receipt_suite: String,
    pub public_state_scheme: String,
    pub enabled_lane_kinds: BTreeSet<ExitLaneKind>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub ticks: u64,
    pub epochs: u64,
    pub lanes: u64,
    pub sealed_lots: u64,
    pub admitted_lots: u64,
    pub auctioneers: u64,
    pub attestations: u64,
    pub settlement_batches: u64,
    pub settled_batches: u64,
    pub withdrawal_receipts: u64,
    pub confirmed_withdrawals: u64,
    pub fee_caps: u64,
    pub rebate_allocations: u64,
    pub quarantine_records: u64,
    pub redaction_budgets: u64,
    pub deterministic_checkpoints: u64,
    pub public_events: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub lane_root: String,
    pub sealed_lot_root: String,
    pub auctioneer_root: String,
    pub attestation_root: String,
    pub settlement_batch_root: String,
    pub withdrawal_receipt_root: String,
    pub fee_cap_root: String,
    pub rebate_root: String,
    pub quarantine_root: String,
    pub redaction_budget_root: String,
    pub deterministic_checkpoint_root: String,
    pub public_event_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExitAuctionLane {
    pub lane_id: String,
    pub kind: ExitLaneKind,
    pub status: LaneStatus,
    pub priority: SettlementPriority,
    pub operator_committee: BTreeSet<String>,
    pub auctioneer_ids: BTreeSet<String>,
    pub lot_ids: BTreeSet<String>,
    pub settlement_batch_ids: BTreeSet<String>,
    pub min_lot_amount_piconero: u128,
    pub max_lot_amount_piconero: u128,
    pub target_fee_bps: u64,
    pub max_fee_bps: u64,
    pub current_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub congestion_score: u64,
    pub privacy_set_size: u64,
    pub redaction_budget_id: String,
    pub lane_root: String,
    pub opened_height: u64,
    pub updated_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedExitLot {
    pub lot_id: String,
    pub lane_id: String,
    pub owner_commitment: String,
    pub sealed_payload_commitment: String,
    pub amount_commitment: String,
    pub amount_upper_bound_piconero: u128,
    pub reserve_price_commitment: String,
    pub fee_cap_id: String,
    pub nullifier_commitment: String,
    pub destination_view_tag_commitment: String,
    pub rebate_hint_commitment: String,
    pub privacy_set_size: u64,
    pub redaction_classes: BTreeSet<RedactionClass>,
    pub auctioneer_attestation_ids: BTreeSet<String>,
    pub batch_id: Option<String>,
    pub receipt_id: Option<String>,
    pub status: LotStatus,
    pub submitted_height: u64,
    pub expiry_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Auctioneer {
    pub auctioneer_id: String,
    pub operator_commitment: String,
    pub pq_verifier_key_commitment: String,
    pub status: AuctioneerStatus,
    pub lane_ids: BTreeSet<String>,
    pub bond_piconero: u128,
    pub attestation_count: u64,
    pub slashing_count: u64,
    pub last_attested_height: u64,
    pub metadata_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAuctioneerAttestation {
    pub attestation_id: String,
    pub auctioneer_id: String,
    pub scope: AttestationScope,
    pub lane_id: Option<String>,
    pub lot_id: Option<String>,
    pub batch_id: Option<String>,
    pub receipt_id: Option<String>,
    pub statement_root: String,
    pub transcript_root: String,
    pub pq_signature_commitment: String,
    pub security_bits: u16,
    pub quorum_weight_bps: u64,
    pub attested_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParallelSettlementBatch {
    pub batch_id: String,
    pub lane_id: String,
    pub priority: SettlementPriority,
    pub lot_ids: BTreeSet<String>,
    pub worker_shards: BTreeSet<String>,
    pub auctioneer_attestation_ids: BTreeSet<String>,
    pub sealed_lot_root: String,
    pub fee_cap_root: String,
    pub rebate_root: String,
    pub settlement_proof_root: String,
    pub deterministic_output_root: String,
    pub max_fee_bps: u64,
    pub charged_fee_bps: u64,
    pub total_upper_bound_piconero: u128,
    pub status: BatchStatus,
    pub opened_height: u64,
    pub settlement_height: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FastWithdrawalReceipt {
    pub receipt_id: String,
    pub lot_id: String,
    pub batch_id: String,
    pub lane_id: String,
    pub owner_receipt_commitment: String,
    pub monero_tx_commitment: String,
    pub view_key_hint_commitment: String,
    pub fee_paid_piconero: u128,
    pub rebate_id: Option<String>,
    pub finality_height: u64,
    pub status: ReceiptStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCap {
    pub fee_cap_id: String,
    pub lane_id: String,
    pub max_fee_bps: u64,
    pub max_fee_piconero: u128,
    pub quote_asset_id: String,
    pub quote_commitment: String,
    pub expires_height: u64,
    pub consumed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub rebate_id: String,
    pub lane_id: String,
    pub batch_id: Option<String>,
    pub lot_id: Option<String>,
    pub sponsor_commitment: String,
    pub rebate_bps: u64,
    pub rebate_amount_piconero: u128,
    pub budget_root: String,
    pub paid: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CongestionQuarantine {
    pub quarantine_id: String,
    pub lane_id: String,
    pub lot_id: Option<String>,
    pub batch_id: Option<String>,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub release_height: u64,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub lane_id: String,
    pub total_units: u64,
    pub spent_units: u64,
    pub redaction_classes: BTreeMap<RedactionClass, u64>,
    pub public_hint_floor: u64,
    pub privacy_set_floor: u64,
    pub budget_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicCheckpoint {
    pub checkpoint_id: String,
    pub height: u64,
    pub epoch: u64,
    pub lane_root: String,
    pub lot_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicEvent {
    pub event_id: String,
    pub height: u64,
    pub kind: String,
    pub record_root: String,
    pub redacted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub lanes: BTreeMap<String, ExitAuctionLane>,
    pub sealed_lots: BTreeMap<String, SealedExitLot>,
    pub auctioneers: BTreeMap<String, Auctioneer>,
    pub attestations: BTreeMap<String, PqAuctioneerAttestation>,
    pub settlement_batches: BTreeMap<String, ParallelSettlementBatch>,
    pub withdrawal_receipts: BTreeMap<String, FastWithdrawalReceipt>,
    pub fee_caps: BTreeMap<String, FeeCap>,
    pub rebates: BTreeMap<String, LowFeeRebate>,
    pub quarantines: BTreeMap<String, CongestionQuarantine>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub checkpoints: BTreeMap<String, DeterministicCheckpoint>,
    pub public_events: BTreeMap<String, PublicEvent>,
}

impl Default for Config {
    fn default() -> Self {
        let enabled_lane_kinds = [
            ExitLaneKind::MoneroFastExit,
            ExitLaneKind::MoneroStandardExit,
            ExitLaneKind::ConfidentialTokenExit,
            ExitLaneKind::DappReceiptExit,
            ExitLaneKind::EmergencyExit,
            ExitLaneKind::MarketMakerBackstop,
            ExitLaneKind::RebateOnly,
        ]
        .into_iter()
        .collect();
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEFAULT_L2_NETWORK.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            current_height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            exit_asset_id: DEFAULT_EXIT_ASSET_ID.to_string(),
            quote_asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
            target_fee_bps: DEFAULT_TARGET_FEE_BPS,
            max_fee_bps: DEFAULT_MAX_FEE_BPS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            max_lots_per_batch: DEFAULT_MAX_LOTS_PER_BATCH,
            max_parallel_batches: DEFAULT_PARALLELISM,
            quarantine_blocks: DEFAULT_QUARANTINE_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            privacy_redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            hash_suite: HASH_SUITE.to_string(),
            pq_auctioneer_suite: PQ_AUCTIONEER_SUITE.to_string(),
            sealed_exit_lot_suite: SEALED_EXIT_LOT_SUITE.to_string(),
            settlement_suite: PARALLEL_SETTLEMENT_SUITE.to_string(),
            receipt_suite: FAST_WITHDRAWAL_RECEIPT_SUITE.to_string(),
            public_state_scheme: PRIVACY_REDACTION_SUITE.to_string(),
            enabled_lane_kinds,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "current_height": self.current_height,
            "epoch": self.epoch,
            "fee_asset_id": self.fee_asset_id,
            "exit_asset_id": self.exit_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "target_fee_bps": self.target_fee_bps,
            "max_fee_bps": self.max_fee_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "auction_ttl_blocks": self.auction_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "max_lots_per_batch": self.max_lots_per_batch,
            "max_parallel_batches": self.max_parallel_batches,
            "quarantine_blocks": self.quarantine_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "privacy_redaction_budget_units": self.privacy_redaction_budget_units,
            "min_pq_security_bits": self.min_pq_security_bits,
            "hash_suite": self.hash_suite,
            "pq_auctioneer_suite": self.pq_auctioneer_suite,
            "sealed_exit_lot_suite": self.sealed_exit_lot_suite,
            "settlement_suite": self.settlement_suite,
            "receipt_suite": self.receipt_suite,
            "public_state_scheme": self.public_state_scheme,
            "enabled_lane_kinds": self.enabled_lane_kinds
        })
    }
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "ticks": self.ticks,
            "epochs": self.epochs,
            "lanes": self.lanes,
            "sealed_lots": self.sealed_lots,
            "admitted_lots": self.admitted_lots,
            "auctioneers": self.auctioneers,
            "attestations": self.attestations,
            "settlement_batches": self.settlement_batches,
            "settled_batches": self.settled_batches,
            "withdrawal_receipts": self.withdrawal_receipts,
            "confirmed_withdrawals": self.confirmed_withdrawals,
            "fee_caps": self.fee_caps,
            "rebate_allocations": self.rebate_allocations,
            "quarantine_records": self.quarantine_records,
            "redaction_budgets": self.redaction_budgets,
            "deterministic_checkpoints": self.deterministic_checkpoints,
            "public_events": self.public_events
        })
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "lane_root": self.lane_root,
            "sealed_lot_root": self.sealed_lot_root,
            "auctioneer_root": self.auctioneer_root,
            "attestation_root": self.attestation_root,
            "settlement_batch_root": self.settlement_batch_root,
            "withdrawal_receipt_root": self.withdrawal_receipt_root,
            "fee_cap_root": self.fee_cap_root,
            "rebate_root": self.rebate_root,
            "quarantine_root": self.quarantine_root,
            "redaction_budget_root": self.redaction_budget_root,
            "deterministic_checkpoint_root": self.deterministic_checkpoint_root,
            "public_event_root": self.public_event_root,
            "state_root": self.state_root
        })
    }
}

impl ExitAuctionLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind,
            "status": self.status,
            "priority": self.priority,
            "operator_committee": self.operator_committee,
            "auctioneer_ids": self.auctioneer_ids,
            "lot_count": self.lot_ids.len(),
            "settlement_batch_count": self.settlement_batch_ids.len(),
            "min_lot_amount_piconero": self.min_lot_amount_piconero.to_string(),
            "max_lot_amount_piconero": self.max_lot_amount_piconero.to_string(),
            "target_fee_bps": self.target_fee_bps,
            "max_fee_bps": self.max_fee_bps,
            "current_fee_bps": self.current_fee_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "congestion_score": self.congestion_score,
            "privacy_set_size": self.privacy_set_size,
            "redaction_budget_id": self.redaction_budget_id,
            "lane_root": self.lane_root,
            "opened_height": self.opened_height,
            "updated_height": self.updated_height
        })
    }
}

impl SealedExitLot {
    pub fn public_record(&self) -> Value {
        json!({
            "lot_id": self.lot_id,
            "lane_id": self.lane_id,
            "owner_commitment": self.owner_commitment,
            "sealed_payload_commitment": self.sealed_payload_commitment,
            "amount_commitment": self.amount_commitment,
            "amount_upper_bound_piconero": self.amount_upper_bound_piconero.to_string(),
            "reserve_price_commitment": self.reserve_price_commitment,
            "fee_cap_id": self.fee_cap_id,
            "nullifier_commitment": self.nullifier_commitment,
            "destination_view_tag_commitment": self.destination_view_tag_commitment,
            "rebate_hint_commitment": self.rebate_hint_commitment,
            "privacy_set_size": self.privacy_set_size,
            "redaction_classes": self.redaction_classes,
            "auctioneer_attestation_ids": self.auctioneer_attestation_ids,
            "batch_id": self.batch_id,
            "receipt_id": self.receipt_id,
            "status": self.status,
            "submitted_height": self.submitted_height,
            "expiry_height": self.expiry_height
        })
    }
}

impl Auctioneer {
    pub fn public_record(&self) -> Value {
        json!({
            "auctioneer_id": self.auctioneer_id,
            "operator_commitment": self.operator_commitment,
            "pq_verifier_key_commitment": self.pq_verifier_key_commitment,
            "status": self.status,
            "lane_ids": self.lane_ids,
            "bond_piconero": self.bond_piconero.to_string(),
            "attestation_count": self.attestation_count,
            "slashing_count": self.slashing_count,
            "last_attested_height": self.last_attested_height,
            "metadata_root": self.metadata_root
        })
    }
}

impl PqAuctioneerAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "auctioneer_id": self.auctioneer_id,
            "scope": self.scope,
            "lane_id": self.lane_id,
            "lot_id": self.lot_id,
            "batch_id": self.batch_id,
            "receipt_id": self.receipt_id,
            "statement_root": self.statement_root,
            "transcript_root": self.transcript_root,
            "pq_signature_commitment": self.pq_signature_commitment,
            "security_bits": self.security_bits,
            "quorum_weight_bps": self.quorum_weight_bps,
            "attested_height": self.attested_height
        })
    }
}

impl ParallelSettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "priority": self.priority,
            "lot_ids": self.lot_ids,
            "worker_shards": self.worker_shards,
            "auctioneer_attestation_ids": self.auctioneer_attestation_ids,
            "sealed_lot_root": self.sealed_lot_root,
            "fee_cap_root": self.fee_cap_root,
            "rebate_root": self.rebate_root,
            "settlement_proof_root": self.settlement_proof_root,
            "deterministic_output_root": self.deterministic_output_root,
            "max_fee_bps": self.max_fee_bps,
            "charged_fee_bps": self.charged_fee_bps,
            "total_upper_bound_piconero": self.total_upper_bound_piconero.to_string(),
            "status": self.status,
            "opened_height": self.opened_height,
            "settlement_height": self.settlement_height
        })
    }
}

impl FastWithdrawalReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "lot_id": self.lot_id,
            "batch_id": self.batch_id,
            "lane_id": self.lane_id,
            "owner_receipt_commitment": self.owner_receipt_commitment,
            "monero_tx_commitment": self.monero_tx_commitment,
            "view_key_hint_commitment": self.view_key_hint_commitment,
            "fee_paid_piconero": self.fee_paid_piconero.to_string(),
            "rebate_id": self.rebate_id,
            "finality_height": self.finality_height,
            "status": self.status
        })
    }
}

impl FeeCap {
    pub fn public_record(&self) -> Value {
        json!({
            "fee_cap_id": self.fee_cap_id,
            "lane_id": self.lane_id,
            "max_fee_bps": self.max_fee_bps,
            "max_fee_piconero": self.max_fee_piconero.to_string(),
            "quote_asset_id": self.quote_asset_id,
            "quote_commitment": self.quote_commitment,
            "expires_height": self.expires_height,
            "consumed": self.consumed
        })
    }
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "lane_id": self.lane_id,
            "batch_id": self.batch_id,
            "lot_id": self.lot_id,
            "sponsor_commitment": self.sponsor_commitment,
            "rebate_bps": self.rebate_bps,
            "rebate_amount_piconero": self.rebate_amount_piconero.to_string(),
            "budget_root": self.budget_root,
            "paid": self.paid
        })
    }
}

impl CongestionQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "lane_id": self.lane_id,
            "lot_id": self.lot_id,
            "batch_id": self.batch_id,
            "reason": self.reason,
            "evidence_root": self.evidence_root,
            "release_height": self.release_height,
            "active": self.active
        })
    }
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "lane_id": self.lane_id,
            "total_units": self.total_units,
            "spent_units": self.spent_units,
            "redaction_classes": self.redaction_classes,
            "public_hint_floor": self.public_hint_floor,
            "privacy_set_floor": self.privacy_set_floor,
            "budget_root": self.budget_root
        })
    }

    pub fn remaining_units(&self) -> u64 {
        self.total_units.saturating_sub(self.spent_units)
    }
}

impl DeterministicCheckpoint {
    pub fn public_record(&self) -> Value {
        json!({
            "checkpoint_id": self.checkpoint_id,
            "height": self.height,
            "epoch": self.epoch,
            "lane_root": self.lane_root,
            "lot_root": self.lot_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "state_root": self.state_root
        })
    }
}

impl PublicEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "height": self.height,
            "kind": self.kind,
            "record_root": self.record_root,
            "redacted": self.redacted
        })
    }
}

impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            lanes: BTreeMap::new(),
            sealed_lots: BTreeMap::new(),
            auctioneers: BTreeMap::new(),
            attestations: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            withdrawal_receipts: BTreeMap::new(),
            fee_caps: BTreeMap::new(),
            rebates: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            public_events: BTreeMap::new(),
        }
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        state
            .register_auctioneer(
                "auctioneer-alpha",
                "operator:alpha:commitment",
                "pqvk:alpha",
                50_000_000_000,
            )
            .expect("devnet auctioneer alpha");
        state
            .register_auctioneer(
                "auctioneer-beta",
                "operator:beta:commitment",
                "pqvk:beta",
                50_000_000_000,
            )
            .expect("devnet auctioneer beta");
        state
            .open_lane(
                "lane-xmr-fast",
                ExitLaneKind::MoneroFastExit,
                [
                    "committee:sequencer-a".to_string(),
                    "committee:auctioneer-a".to_string(),
                ]
                .into_iter()
                .collect(),
                [
                    "auctioneer-alpha".to_string(),
                    "auctioneer-beta".to_string(),
                ]
                .into_iter()
                .collect(),
                100_000,
                25_000_000_000,
            )
            .expect("devnet fast lane");
        state
            .open_lane(
                "lane-low-fee",
                ExitLaneKind::MoneroStandardExit,
                ["committee:low-fee".to_string()].into_iter().collect(),
                ["auctioneer-alpha".to_string()].into_iter().collect(),
                10_000,
                10_000_000_000,
            )
            .expect("devnet low fee lane");
        state
            .open_lane(
                "lane-emergency",
                ExitLaneKind::EmergencyExit,
                ["committee:escape".to_string()].into_iter().collect(),
                ["auctioneer-beta".to_string()].into_iter().collect(),
                1_000,
                100_000_000_000,
            )
            .expect("devnet emergency lane");
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let lot_a = state
            .submit_sealed_lot(
                "lane-xmr-fast",
                "owner:demo:alice",
                "sealed:payload:alice-fast",
                "amount:commitment:alice",
                6_500_000_000,
                "reserve:commitment:alice",
                "nullifier:alice:001",
                "viewtag:alice:redacted",
                "rebate:hint:alice",
                [
                    RedactionClass::UserIdentifier,
                    RedactionClass::MoneroAddressHint,
                    RedactionClass::AmountBucket,
                ]
                .into_iter()
                .collect(),
            )
            .expect("demo lot alice");
        let lot_b = state
            .submit_sealed_lot(
                "lane-xmr-fast",
                "owner:demo:bob",
                "sealed:payload:bob-fast",
                "amount:commitment:bob",
                3_250_000_000,
                "reserve:commitment:bob",
                "nullifier:bob:001",
                "viewtag:bob:redacted",
                "rebate:hint:bob",
                [
                    RedactionClass::UserIdentifier,
                    RedactionClass::TimingHint,
                    RedactionClass::AuctionTranscript,
                ]
                .into_iter()
                .collect(),
            )
            .expect("demo lot bob");
        let lot_c = state
            .submit_sealed_lot(
                "lane-low-fee",
                "owner:demo:carol",
                "sealed:payload:carol-low-fee",
                "amount:commitment:carol",
                1_125_000_000,
                "reserve:commitment:carol",
                "nullifier:carol:001",
                "viewtag:carol:redacted",
                "rebate:hint:carol",
                [
                    RedactionClass::UserIdentifier,
                    RedactionClass::SolverIdentity,
                    RedactionClass::WitnessPath,
                ]
                .into_iter()
                .collect(),
            )
            .expect("demo lot carol");
        let att_a = state
            .attest_lot("auctioneer-alpha", &lot_a)
            .expect("demo attestation alice");
        let att_b = state
            .attest_lot("auctioneer-beta", &lot_b)
            .expect("demo attestation bob");
        state
            .attest_lot("auctioneer-alpha", &lot_c)
            .expect("demo attestation carol");
        let batch = state
            .open_settlement_batch(
                "lane-xmr-fast",
                [lot_a.clone(), lot_b.clone()].into_iter().collect(),
                ["shard-fast-0".to_string(), "shard-fast-1".to_string()]
                    .into_iter()
                    .collect(),
                [att_a, att_b].into_iter().collect(),
            )
            .expect("demo batch");
        state
            .settle_batch(&batch, 6)
            .expect("demo settle fast batch");
        state
            .issue_fast_withdrawal_receipt(&lot_a, "monero-tx:alice:commitment")
            .expect("demo receipt alice");
        state
            .issue_fast_withdrawal_receipt(&lot_b, "monero-tx:bob:commitment")
            .expect("demo receipt bob");
        state
            .quarantine_lane(
                "lane-emergency",
                QuarantineReason::DemoFault,
                "demo:quarantine:evidence",
            )
            .expect("demo quarantine");
        state
    }

    pub fn register_auctioneer(
        &mut self,
        auctioneer_id: impl Into<String>,
        operator_commitment: impl Into<String>,
        pq_verifier_key_commitment: impl Into<String>,
        bond_piconero: u128,
    ) -> PrivateL2FastPqConfidentialParallelExitAuctionRuntimeResult<String> {
        let auctioneer_id = auctioneer_id.into();
        ensure!(
            !self.auctioneers.contains_key(&auctioneer_id),
            "auctioneer already registered: {auctioneer_id}"
        );
        let metadata = json!({
            "auctioneer_id": auctioneer_id,
            "operator_commitment": operator_commitment.into(),
            "pq_verifier_key_commitment": pq_verifier_key_commitment.into(),
            "height": self.config.current_height
        });
        let auctioneer = Auctioneer {
            auctioneer_id: auctioneer_id.clone(),
            operator_commitment: metadata["operator_commitment"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            pq_verifier_key_commitment: metadata["pq_verifier_key_commitment"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            status: AuctioneerStatus::Active,
            lane_ids: BTreeSet::new(),
            bond_piconero,
            attestation_count: 0,
            slashing_count: 0,
            last_attested_height: self.config.current_height,
            metadata_root: record_root("AUCTIONEER-METADATA", &metadata),
        };
        let root = record_root("AUCTIONEER", &auctioneer.public_record());
        self.auctioneers.insert(auctioneer_id.clone(), auctioneer);
        self.counters.auctioneers = self.auctioneers.len() as u64;
        self.emit_public_event("auctioneer_registered", root, true);
        Ok(auctioneer_id)
    }

    pub fn open_lane(
        &mut self,
        lane_id: impl Into<String>,
        kind: ExitLaneKind,
        operator_committee: BTreeSet<String>,
        auctioneer_ids: BTreeSet<String>,
        min_lot_amount_piconero: u128,
        max_lot_amount_piconero: u128,
    ) -> PrivateL2FastPqConfidentialParallelExitAuctionRuntimeResult<String> {
        let lane_id = lane_id.into();
        ensure!(
            !self.lanes.contains_key(&lane_id),
            "lane already exists: {lane_id}"
        );
        ensure!(
            self.config.enabled_lane_kinds.contains(&kind),
            "lane kind disabled: {kind:?}"
        );
        ensure!(
            min_lot_amount_piconero <= max_lot_amount_piconero,
            "invalid lot bounds for lane {lane_id}"
        );
        for auctioneer_id in &auctioneer_ids {
            ensure!(
                self.auctioneers
                    .get(auctioneer_id)
                    .map(|auctioneer| {
                        matches!(
                            auctioneer.status,
                            AuctioneerStatus::Active | AuctioneerStatus::Rotating
                        )
                    })
                    .unwrap_or(false),
                "inactive auctioneer for lane {lane_id}: {auctioneer_id}"
            );
        }
        let budget_id = format!("{lane_id}:redaction-budget:0");
        let mut redaction_classes = BTreeMap::new();
        redaction_classes.insert(RedactionClass::UserIdentifier, 220_000);
        redaction_classes.insert(RedactionClass::AmountBucket, 180_000);
        redaction_classes.insert(RedactionClass::MoneroAddressHint, 180_000);
        redaction_classes.insert(RedactionClass::TimingHint, 140_000);
        redaction_classes.insert(RedactionClass::SolverIdentity, 120_000);
        redaction_classes.insert(RedactionClass::AuctionTranscript, 100_000);
        redaction_classes.insert(RedactionClass::WitnessPath, 60_000);
        let budget_root = record_root(
            "REDACTION-BUDGET-SEED",
            &json!({
                "budget_id": budget_id,
                "lane_id": lane_id,
                "height": self.config.current_height,
                "redaction_classes": redaction_classes
            }),
        );
        let budget = PrivacyRedactionBudget {
            budget_id: budget_id.clone(),
            lane_id: lane_id.clone(),
            total_units: self.config.privacy_redaction_budget_units,
            spent_units: 0,
            redaction_classes,
            public_hint_floor: 2,
            privacy_set_floor: self.config.min_privacy_set_size,
            budget_root,
        };
        let mut lane = ExitAuctionLane {
            lane_id: lane_id.clone(),
            kind,
            status: LaneStatus::Open,
            priority: kind.default_priority(),
            operator_committee,
            auctioneer_ids: auctioneer_ids.clone(),
            lot_ids: BTreeSet::new(),
            settlement_batch_ids: BTreeSet::new(),
            min_lot_amount_piconero,
            max_lot_amount_piconero,
            target_fee_bps: self.config.target_fee_bps,
            max_fee_bps: self.config.max_fee_bps,
            current_fee_bps: kind
                .default_priority()
                .batch_weight()
                .min(self.config.max_fee_bps),
            low_fee_rebate_bps: self.config.low_fee_rebate_bps,
            congestion_score: 0,
            privacy_set_size: self.config.target_privacy_set_size,
            redaction_budget_id: budget_id.clone(),
            lane_root: String::new(),
            opened_height: self.config.current_height,
            updated_height: self.config.current_height,
        };
        lane.lane_root = record_root("EXIT-AUCTION-LANE", &lane.public_record());
        self.redaction_budgets.insert(budget_id, budget);
        self.lanes.insert(lane_id.clone(), lane);
        for auctioneer_id in auctioneer_ids {
            if let Some(auctioneer) = self.auctioneers.get_mut(&auctioneer_id) {
                auctioneer.lane_ids.insert(lane_id.clone());
            }
        }
        self.counters.lanes = self.lanes.len() as u64;
        self.counters.redaction_budgets = self.redaction_budgets.len() as u64;
        self.emit_public_event(
            "exit_auction_lane_opened",
            record_root("LANE-OPEN", &json!({"lane_id": lane_id, "kind": kind})),
            true,
        );
        Ok(lane_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_sealed_lot(
        &mut self,
        lane_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        sealed_payload_commitment: impl Into<String>,
        amount_commitment: impl Into<String>,
        amount_upper_bound_piconero: u128,
        reserve_price_commitment: impl Into<String>,
        nullifier_commitment: impl Into<String>,
        destination_view_tag_commitment: impl Into<String>,
        rebate_hint_commitment: impl Into<String>,
        redaction_classes: BTreeSet<RedactionClass>,
    ) -> PrivateL2FastPqConfidentialParallelExitAuctionRuntimeResult<String> {
        let lane_id = lane_id.into();
        let height = self.config.current_height;
        let lane = self
            .lanes
            .get(&lane_id)
            .ok_or_else(|| format!("missing lane: {lane_id}"))?;
        ensure!(
            matches!(
                lane.status,
                LaneStatus::Open | LaneStatus::Congested | LaneStatus::Draining
            ),
            "lane does not accept lots: {lane_id}"
        );
        ensure!(
            amount_upper_bound_piconero >= lane.min_lot_amount_piconero
                && amount_upper_bound_piconero <= lane.max_lot_amount_piconero,
            "lot amount outside lane bounds for {lane_id}"
        );
        ensure!(
            lane.privacy_set_size >= self.config.min_privacy_set_size,
            "lane privacy set below floor: {lane_id}"
        );
        let amount_commitment = amount_commitment.into();
        let nullifier_commitment = nullifier_commitment.into();
        let lot_id = next_id(
            "lot",
            self.counters.sealed_lots + 1,
            &[lane_id.as_str(), &amount_commitment, &nullifier_commitment],
        );
        ensure!(
            !self.sealed_lots.contains_key(&lot_id),
            "sealed lot collision: {lot_id}"
        );
        let fee_cap_id = next_id("fee-cap", self.counters.fee_caps + 1, &[&lane_id, &lot_id]);
        let fee_cap = FeeCap {
            fee_cap_id: fee_cap_id.clone(),
            lane_id: lane_id.clone(),
            max_fee_bps: lane.max_fee_bps,
            max_fee_piconero: amount_upper_bound_piconero.saturating_mul(lane.max_fee_bps as u128)
                / MAX_BPS as u128,
            quote_asset_id: self.config.quote_asset_id.clone(),
            quote_commitment: commitment("fee-cap-quote", &[&lane_id, &lot_id]),
            expires_height: height.saturating_add(self.config.auction_ttl_blocks),
            consumed: false,
        };
        let lot = SealedExitLot {
            lot_id: lot_id.clone(),
            lane_id: lane_id.clone(),
            owner_commitment: owner_commitment.into(),
            sealed_payload_commitment: sealed_payload_commitment.into(),
            amount_commitment,
            amount_upper_bound_piconero,
            reserve_price_commitment: reserve_price_commitment.into(),
            fee_cap_id: fee_cap_id.clone(),
            nullifier_commitment,
            destination_view_tag_commitment: destination_view_tag_commitment.into(),
            rebate_hint_commitment: rebate_hint_commitment.into(),
            privacy_set_size: lane.privacy_set_size,
            redaction_classes,
            auctioneer_attestation_ids: BTreeSet::new(),
            batch_id: None,
            receipt_id: None,
            status: LotStatus::Sealed,
            submitted_height: height,
            expiry_height: height.saturating_add(self.config.auction_ttl_blocks),
        };
        self.fee_caps.insert(fee_cap_id, fee_cap);
        self.sealed_lots.insert(lot_id.clone(), lot);
        if let Some(lane) = self.lanes.get_mut(&lane_id) {
            lane.lot_ids.insert(lot_id.clone());
            lane.congestion_score =
                lane.lot_ids
                    .len()
                    .saturating_mul(lane.priority.batch_weight() as usize) as u64;
            lane.updated_height = height;
            if lane.congestion_score > self.config.max_lots_per_batch {
                lane.status = LaneStatus::Congested;
            }
            lane.lane_root = record_root("EXIT-AUCTION-LANE", &lane.public_record());
        }
        self.spend_redaction_units(&lane_id, 1_000)?;
        self.counters.sealed_lots = self.sealed_lots.len() as u64;
        self.counters.fee_caps = self.fee_caps.len() as u64;
        self.emit_public_event(
            "sealed_exit_lot_submitted",
            record_root(
                "LOT-SUBMITTED",
                &json!({"lot_id": lot_id, "lane_id": lane_id}),
            ),
            true,
        );
        Ok(lot_id)
    }

    pub fn attest_lot(
        &mut self,
        auctioneer_id: impl Into<String>,
        lot_id: impl Into<String>,
    ) -> PrivateL2FastPqConfidentialParallelExitAuctionRuntimeResult<String> {
        let auctioneer_id = auctioneer_id.into();
        let lot_id = lot_id.into();
        let height = self.config.current_height;
        let lot = self
            .sealed_lots
            .get(&lot_id)
            .ok_or_else(|| format!("missing lot: {lot_id}"))?
            .clone();
        ensure!(
            matches!(
                lot.status,
                LotStatus::Sealed
                    | LotStatus::Admitted
                    | LotStatus::Attested
                    | LotStatus::BatchBound
            ),
            "lot is not live: {lot_id}"
        );
        let auctioneer = self
            .auctioneers
            .get(&auctioneer_id)
            .ok_or_else(|| format!("missing auctioneer: {auctioneer_id}"))?;
        ensure!(
            matches!(
                auctioneer.status,
                AuctioneerStatus::Active | AuctioneerStatus::Rotating
            ),
            "auctioneer cannot attest: {auctioneer_id}"
        );
        ensure!(
            auctioneer.lane_ids.contains(&lot.lane_id),
            "auctioneer not assigned to lane {}",
            lot.lane_id
        );
        let statement_root = record_root(
            "LOT-ADMISSION-STATEMENT",
            &json!({
                "lot_id": lot_id,
                "lane_id": lot.lane_id,
                "fee_cap_id": lot.fee_cap_id,
                "privacy_set_size": lot.privacy_set_size,
                "status": lot.status
            }),
        );
        let attestation_id = next_id(
            "attestation",
            self.counters.attestations + 1,
            &[&auctioneer_id, &lot_id, &statement_root],
        );
        let attestation = PqAuctioneerAttestation {
            attestation_id: attestation_id.clone(),
            auctioneer_id: auctioneer_id.clone(),
            scope: AttestationScope::LotAdmission,
            lane_id: Some(lot.lane_id.clone()),
            lot_id: Some(lot_id.clone()),
            batch_id: None,
            receipt_id: None,
            statement_root,
            transcript_root: commitment("lot-attestation-transcript", &[&auctioneer_id, &lot_id]),
            pq_signature_commitment: commitment(
                "lot-attestation-signature",
                &[&auctioneer_id, &lot_id],
            ),
            security_bits: self.config.min_pq_security_bits,
            quorum_weight_bps: 5_000,
            attested_height: height,
        };
        self.attestations
            .insert(attestation_id.clone(), attestation);
        if let Some(lot) = self.sealed_lots.get_mut(&lot_id) {
            lot.auctioneer_attestation_ids
                .insert(attestation_id.clone());
            lot.status = LotStatus::Attested;
        }
        if let Some(auctioneer) = self.auctioneers.get_mut(&auctioneer_id) {
            auctioneer.attestation_count = auctioneer.attestation_count.saturating_add(1);
            auctioneer.last_attested_height = height;
        }
        self.counters.attestations = self.attestations.len() as u64;
        self.counters.admitted_lots = self
            .sealed_lots
            .values()
            .filter(|lot| matches!(lot.status, LotStatus::Admitted | LotStatus::Attested))
            .count() as u64;
        self.emit_public_event(
            "pq_auctioneer_lot_attested",
            record_root(
                "LOT-ATTESTED",
                &json!({"lot_id": lot_id, "auctioneer_id": auctioneer_id}),
            ),
            true,
        );
        Ok(attestation_id)
    }

    pub fn open_settlement_batch(
        &mut self,
        lane_id: impl Into<String>,
        lot_ids: BTreeSet<String>,
        worker_shards: BTreeSet<String>,
        auctioneer_attestation_ids: BTreeSet<String>,
    ) -> PrivateL2FastPqConfidentialParallelExitAuctionRuntimeResult<String> {
        let lane_id = lane_id.into();
        ensure!(
            !lot_ids.is_empty(),
            "settlement batch requires at least one lot"
        );
        ensure!(
            lot_ids.len() as u64 <= self.config.max_lots_per_batch,
            "settlement batch exceeds max lots"
        );
        let lane = self
            .lanes
            .get(&lane_id)
            .ok_or_else(|| format!("missing lane: {lane_id}"))?
            .clone();
        let mut total_upper_bound_piconero = 0_u128;
        for lot_id in &lot_ids {
            let lot = self
                .sealed_lots
                .get(lot_id)
                .ok_or_else(|| format!("missing lot: {lot_id}"))?;
            ensure!(lot.lane_id == lane_id, "lot lane mismatch: {lot_id}");
            ensure!(
                matches!(
                    lot.status,
                    LotStatus::Sealed
                        | LotStatus::Admitted
                        | LotStatus::Attested
                        | LotStatus::BatchBound
                ),
                "lot not batchable: {lot_id}"
            );
            ensure!(
                !lot.auctioneer_attestation_ids.is_empty(),
                "lot lacks attestation: {lot_id}"
            );
            total_upper_bound_piconero =
                total_upper_bound_piconero.saturating_add(lot.amount_upper_bound_piconero);
        }
        for attestation_id in &auctioneer_attestation_ids {
            ensure!(
                self.attestations.contains_key(attestation_id),
                "missing attestation: {attestation_id}"
            );
        }
        let batch_id = next_id(
            "batch",
            self.counters.settlement_batches + 1,
            &[
                &lane_id,
                &records_root("BATCH-LOTS", &self.sealed_lots, |lot| lot.public_record()),
            ],
        );
        let sealed_lot_root =
            selected_records_root("BATCH-SEALED-LOTS", &self.sealed_lots, &lot_ids, |lot| {
                lot.public_record()
            });
        let fee_cap_ids = lot_ids
            .iter()
            .filter_map(|lot_id| {
                self.sealed_lots
                    .get(lot_id)
                    .map(|lot| lot.fee_cap_id.clone())
            })
            .collect::<BTreeSet<_>>();
        let fee_cap_root =
            selected_records_root("BATCH-FEE-CAPS", &self.fee_caps, &fee_cap_ids, |fee_cap| {
                fee_cap.public_record()
            });
        let rebate_root = record_root(
            "BATCH-REBATE-SEED",
            &json!({
                "batch_id": batch_id,
                "lane_id": lane_id,
                "low_fee_rebate_bps": lane.low_fee_rebate_bps
            }),
        );
        let batch = ParallelSettlementBatch {
            batch_id: batch_id.clone(),
            lane_id: lane_id.clone(),
            priority: lane.priority,
            lot_ids: lot_ids.clone(),
            worker_shards,
            auctioneer_attestation_ids,
            sealed_lot_root,
            fee_cap_root,
            rebate_root,
            settlement_proof_root: commitment("settlement-proof", &[&batch_id, &lane_id]),
            deterministic_output_root: commitment("settlement-output", &[&batch_id, &lane_id]),
            max_fee_bps: lane.max_fee_bps,
            charged_fee_bps: lane.current_fee_bps.min(lane.max_fee_bps),
            total_upper_bound_piconero,
            status: BatchStatus::Attested,
            opened_height: self.config.current_height,
            settlement_height: None,
        };
        self.settlement_batches.insert(batch_id.clone(), batch);
        for lot_id in lot_ids {
            if let Some(lot) = self.sealed_lots.get_mut(&lot_id) {
                lot.batch_id = Some(batch_id.clone());
                lot.status = LotStatus::BatchBound;
            }
        }
        if let Some(lane) = self.lanes.get_mut(&lane_id) {
            lane.settlement_batch_ids.insert(batch_id.clone());
            lane.updated_height = self.config.current_height;
            lane.lane_root = record_root("EXIT-AUCTION-LANE", &lane.public_record());
        }
        self.counters.settlement_batches = self.settlement_batches.len() as u64;
        self.emit_public_event(
            "parallel_settlement_batch_opened",
            record_root(
                "BATCH-OPENED",
                &json!({"batch_id": batch_id, "lane_id": lane_id}),
            ),
            true,
        );
        Ok(batch_id)
    }

    pub fn settle_batch(
        &mut self,
        batch_id: impl Into<String>,
        charged_fee_bps: u64,
    ) -> PrivateL2FastPqConfidentialParallelExitAuctionRuntimeResult<()> {
        let batch_id = batch_id.into();
        let height = self.config.current_height;
        let lot_ids = {
            let batch = self
                .settlement_batches
                .get(&batch_id)
                .ok_or_else(|| format!("missing batch: {batch_id}"))?;
            ensure!(
                charged_fee_bps <= batch.max_fee_bps,
                "charged fee exceeds cap for batch {batch_id}"
            );
            batch.lot_ids.clone()
        };
        if let Some(batch) = self.settlement_batches.get_mut(&batch_id) {
            batch.charged_fee_bps = charged_fee_bps;
            batch.status = BatchStatus::Settled;
            batch.settlement_height = Some(height);
            batch.deterministic_output_root = record_root(
                "SETTLED-BATCH-OUTPUT",
                &json!({
                    "batch_id": batch_id,
                    "charged_fee_bps": charged_fee_bps,
                    "height": height,
                    "lot_ids": lot_ids
                }),
            );
        }
        for lot_id in &lot_ids {
            if let Some(lot) = self.sealed_lots.get_mut(lot_id) {
                lot.status = LotStatus::Settled;
            }
            let fee_cap_id = self
                .sealed_lots
                .get(lot_id)
                .map(|lot| lot.fee_cap_id.clone())
                .unwrap_or_default();
            if let Some(fee_cap) = self.fee_caps.get_mut(&fee_cap_id) {
                fee_cap.consumed = true;
            }
        }
        self.counters.settled_batches = self
            .settlement_batches
            .values()
            .filter(|batch| matches!(batch.status, BatchStatus::Settled | BatchStatus::Rebated))
            .count() as u64;
        self.emit_public_event(
            "parallel_settlement_batch_settled",
            record_root(
                "BATCH-SETTLED",
                &json!({"batch_id": batch_id, "charged_fee_bps": charged_fee_bps}),
            ),
            true,
        );
        Ok(())
    }

    pub fn issue_fast_withdrawal_receipt(
        &mut self,
        lot_id: impl Into<String>,
        monero_tx_commitment: impl Into<String>,
    ) -> PrivateL2FastPqConfidentialParallelExitAuctionRuntimeResult<String> {
        let lot_id = lot_id.into();
        let monero_tx_commitment = monero_tx_commitment.into();
        let lot = self
            .sealed_lots
            .get(&lot_id)
            .ok_or_else(|| format!("missing lot: {lot_id}"))?
            .clone();
        ensure!(
            lot.status == LotStatus::Settled,
            "lot is not settled: {lot_id}"
        );
        let batch_id = lot
            .batch_id
            .clone()
            .ok_or_else(|| format!("lot missing batch: {lot_id}"))?;
        let batch = self
            .settlement_batches
            .get(&batch_id)
            .ok_or_else(|| format!("missing batch for lot {lot_id}: {batch_id}"))?;
        ensure!(
            matches!(
                batch.status,
                BatchStatus::Submitted | BatchStatus::Settled | BatchStatus::Rebated
            ),
            "batch cannot issue receipts: {batch_id}"
        );
        let fee_paid_piconero = lot
            .amount_upper_bound_piconero
            .saturating_mul(batch.charged_fee_bps as u128)
            / MAX_BPS as u128;
        let rebate_id = if batch.charged_fee_bps <= self.config.target_fee_bps {
            Some(self.allocate_rebate(
                &lot.lane_id,
                Some(&batch_id),
                Some(&lot_id),
                fee_paid_piconero,
            )?)
        } else {
            None
        };
        let receipt_id = next_id(
            "receipt",
            self.counters.withdrawal_receipts + 1,
            &[&lot_id, &batch_id, &monero_tx_commitment],
        );
        let receipt = FastWithdrawalReceipt {
            receipt_id: receipt_id.clone(),
            lot_id: lot_id.clone(),
            batch_id,
            lane_id: lot.lane_id.clone(),
            owner_receipt_commitment: commitment(
                "owner-receipt",
                &[&lot.owner_commitment, &receipt_id],
            ),
            monero_tx_commitment,
            view_key_hint_commitment: commitment(
                "view-key-hint",
                &[&lot.destination_view_tag_commitment, &receipt_id],
            ),
            fee_paid_piconero,
            rebate_id,
            finality_height: self
                .config
                .current_height
                .saturating_add(self.config.receipt_ttl_blocks),
            status: ReceiptStatus::Broadcast,
        };
        self.withdrawal_receipts
            .insert(receipt_id.clone(), receipt.clone());
        if let Some(lot) = self.sealed_lots.get_mut(&lot_id) {
            lot.receipt_id = Some(receipt_id.clone());
            lot.status = LotStatus::Withdrawn;
        }
        self.counters.withdrawal_receipts = self.withdrawal_receipts.len() as u64;
        self.emit_public_event(
            "fast_withdrawal_receipt_issued",
            record_root("FAST-WITHDRAWAL-RECEIPT", &receipt.public_record()),
            true,
        );
        Ok(receipt_id)
    }

    pub fn quarantine_lane(
        &mut self,
        lane_id: impl Into<String>,
        reason: QuarantineReason,
        evidence: impl Into<String>,
    ) -> PrivateL2FastPqConfidentialParallelExitAuctionRuntimeResult<String> {
        let lane_id = lane_id.into();
        ensure!(self.lanes.contains_key(&lane_id), "missing lane: {lane_id}");
        let quarantine_id = next_id(
            "quarantine",
            self.counters.quarantine_records + 1,
            &[&lane_id, &format!("{reason:?}")],
        );
        let quarantine = CongestionQuarantine {
            quarantine_id: quarantine_id.clone(),
            lane_id: lane_id.clone(),
            lot_id: None,
            batch_id: None,
            reason,
            evidence_root: record_root(
                "QUARANTINE-EVIDENCE",
                &json!({"evidence": evidence.into()}),
            ),
            release_height: self
                .config
                .current_height
                .saturating_add(self.config.quarantine_blocks),
            active: true,
        };
        self.quarantines.insert(quarantine_id.clone(), quarantine);
        if let Some(lane) = self.lanes.get_mut(&lane_id) {
            lane.status = LaneStatus::Quarantined;
            lane.updated_height = self.config.current_height;
            lane.lane_root = record_root("EXIT-AUCTION-LANE", &lane.public_record());
        }
        self.counters.quarantine_records = self.quarantines.len() as u64;
        self.emit_public_event(
            "congestion_quarantine_started",
            record_root(
                "QUARANTINE-STARTED",
                &json!({"quarantine_id": quarantine_id}),
            ),
            true,
        );
        Ok(quarantine_id)
    }

    pub fn roots(&self) -> Roots {
        let mut roots = self.roots_without_state_root();
        let public = self.public_record_without_state_root_with_roots(&roots);
        roots.state_root = state_root_from_public_record(&public);
        roots
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let mut record = self.public_record_without_state_root_with_roots(&roots);
        if let Value::Object(ref mut map) = record {
            map.insert("state_root".to_string(), Value::String(roots.state_root));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn roots_without_state_root(&self) -> Roots {
        Roots {
            config_root: record_root("CONFIG", &self.config.public_record()),
            counters_root: record_root("COUNTERS", &self.counters.public_record()),
            lane_root: records_root("EXIT-AUCTION-LANES", &self.lanes, |lane| {
                lane.public_record()
            }),
            sealed_lot_root: records_root("SEALED-EXIT-LOTS", &self.sealed_lots, |lot| {
                lot.public_record()
            }),
            auctioneer_root: records_root("AUCTIONEERS", &self.auctioneers, |auctioneer| {
                auctioneer.public_record()
            }),
            attestation_root: records_root(
                "PQ-AUCTIONEER-ATTESTATIONS",
                &self.attestations,
                |att| att.public_record(),
            ),
            settlement_batch_root: records_root(
                "PARALLEL-SETTLEMENT-BATCHES",
                &self.settlement_batches,
                |batch| batch.public_record(),
            ),
            withdrawal_receipt_root: records_root(
                "FAST-WITHDRAWAL-RECEIPTS",
                &self.withdrawal_receipts,
                |receipt| receipt.public_record(),
            ),
            fee_cap_root: records_root("FEE-CAPS", &self.fee_caps, |fee_cap| {
                fee_cap.public_record()
            }),
            rebate_root: records_root("LOW-FEE-REBATES", &self.rebates, |rebate| {
                rebate.public_record()
            }),
            quarantine_root: records_root("CONGESTION-QUARANTINES", &self.quarantines, |q| {
                q.public_record()
            }),
            redaction_budget_root: records_root(
                "PRIVACY-REDACTION-BUDGETS",
                &self.redaction_budgets,
                |budget| budget.public_record(),
            ),
            deterministic_checkpoint_root: records_root(
                "DETERMINISTIC-CHECKPOINTS",
                &self.checkpoints,
                |checkpoint| checkpoint.public_record(),
            ),
            public_event_root: records_root("PUBLIC-EVENTS", &self.public_events, |event| {
                event.public_record()
            }),
            state_root: String::new(),
        }
    }

    fn public_record_without_state_root_with_roots(&self, roots: &Roots) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "runtime": "private_l2_fast_pq_confidential_parallel_exit_auction",
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "public_counts": {
                "lanes": self.lanes.len(),
                "sealed_lots": self.sealed_lots.len(),
                "auctioneers": self.auctioneers.len(),
                "attestations": self.attestations.len(),
                "settlement_batches": self.settlement_batches.len(),
                "withdrawal_receipts": self.withdrawal_receipts.len(),
                "fee_caps": self.fee_caps.len(),
                "rebates": self.rebates.len(),
                "quarantines": self.quarantines.len(),
                "redaction_budgets": self.redaction_budgets.len(),
                "checkpoints": self.checkpoints.len(),
                "public_events": self.public_events.len()
            }
        })
    }

    fn allocate_rebate(
        &mut self,
        lane_id: &str,
        batch_id: Option<&str>,
        lot_id: Option<&str>,
        fee_paid_piconero: u128,
    ) -> PrivateL2FastPqConfidentialParallelExitAuctionRuntimeResult<String> {
        ensure!(self.lanes.contains_key(lane_id), "missing lane: {lane_id}");
        let rebate_id = next_id(
            "rebate",
            self.counters.rebate_allocations + 1,
            &[lane_id, batch_id.unwrap_or(""), lot_id.unwrap_or("")],
        );
        let rebate_bps = self
            .lanes
            .get(lane_id)
            .map(|lane| lane.low_fee_rebate_bps)
            .unwrap_or(self.config.low_fee_rebate_bps);
        let rebate = LowFeeRebate {
            rebate_id: rebate_id.clone(),
            lane_id: lane_id.to_string(),
            batch_id: batch_id.map(str::to_string),
            lot_id: lot_id.map(str::to_string),
            sponsor_commitment: commitment("low-fee-rebate-sponsor", &[lane_id, &rebate_id]),
            rebate_bps,
            rebate_amount_piconero: fee_paid_piconero.saturating_mul(rebate_bps as u128)
                / MAX_BPS as u128,
            budget_root: record_root(
                "LOW-FEE-REBATE-BUDGET",
                &json!({"lane_id": lane_id, "rebate_id": rebate_id, "fee_paid": fee_paid_piconero.to_string()}),
            ),
            paid: false,
        };
        self.rebates.insert(rebate_id.clone(), rebate);
        self.counters.rebate_allocations = self.rebates.len() as u64;
        Ok(rebate_id)
    }

    fn spend_redaction_units(
        &mut self,
        lane_id: &str,
        units: u64,
    ) -> PrivateL2FastPqConfidentialParallelExitAuctionRuntimeResult<()> {
        let budget_id = self
            .lanes
            .get(lane_id)
            .map(|lane| lane.redaction_budget_id.clone())
            .ok_or_else(|| format!("missing lane: {lane_id}"))?;
        let budget = self
            .redaction_budgets
            .get_mut(&budget_id)
            .ok_or_else(|| format!("missing redaction budget: {budget_id}"))?;
        ensure!(
            budget.remaining_units() >= units,
            "redaction budget exhausted for lane {lane_id}"
        );
        budget.spent_units = budget.spent_units.saturating_add(units);
        budget.budget_root = record_root(
            "PRIVACY-REDACTION-BUDGET-SPEND",
            &json!({
                "budget_id": budget_id,
                "spent_units": budget.spent_units,
                "remaining_units": budget.remaining_units()
            }),
        );
        Ok(())
    }

    fn emit_public_event(&mut self, kind: impl Into<String>, record_root: String, redacted: bool) {
        let kind = kind.into();
        let event_id = next_id(
            "event",
            self.counters.public_events + 1,
            &[kind.as_str(), record_root.as_str()],
        );
        let event = PublicEvent {
            event_id: event_id.clone(),
            height: self.config.current_height,
            kind,
            record_root,
            redacted,
        };
        self.public_events.insert(event_id, event);
        self.counters.public_events = self.public_events.len() as u64;
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

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PARALLEL-EXIT-AUCTION-STATE",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(SCHEMA_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FAST-PQ-EXIT-AUCTION-{domain}"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(SCHEMA_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn records_root<T, F>(domain: &str, records: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = records
        .iter()
        .map(|(id, record)| json!({"id": id, "record": public_record(record)}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-FAST-PQ-EXIT-AUCTION-{domain}"),
        &leaves,
    )
}

fn selected_records_root<T, F>(
    domain: &str,
    records: &BTreeMap<String, T>,
    ids: &BTreeSet<String>,
    public_record: F,
) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = ids
        .iter()
        .filter_map(|id| {
            records
                .get(id)
                .map(|record| json!({"id": id, "record": public_record(record)}))
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-FAST-PQ-EXIT-AUCTION-{domain}"),
        &leaves,
    )
}

fn next_id(prefix: &str, sequence: u64, parts: &[&str]) -> String {
    let hash = domain_hash(
        &format!("PRIVATE-L2-FAST-PQ-EXIT-AUCTION-ID-{prefix}"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&parts.join("|")),
        ],
        12,
    );
    format!("{prefix}-{sequence:08}-{hash}")
}

fn commitment(domain: &str, parts: &[&str]) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FAST-PQ-EXIT-AUCTION-COMMITMENT-{domain}"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&parts.join("|")),
        ],
        32,
    )
}
