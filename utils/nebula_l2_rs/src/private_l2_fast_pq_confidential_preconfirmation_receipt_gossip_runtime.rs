use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2FastPqConfidentialPreconfirmationReceiptGossipRuntimeResult<T> =
    Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PRECONFIRMATION_RECEIPT_GOSSIP_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-fast-pq-confidential-preconfirmation-receipt-gossip-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_PRECONFIRMATION_RECEIPT_GOSSIP_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_720_000;
pub const DEVNET_EPOCH: u64 = 9_600;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_RECEIPT_SUITE: &str = "ml-kem-1024+xwing-sealed-preconfirmation-receipt-v1";
pub const PQ_SIGNER_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256s-preconfirmation-gossip-attestation-v1";
pub const GOSSIP_COMMITTEE_SUITE: &str = "weighted-private-l2-receipt-gossip-committee-v1";
pub const ANTI_EQUIVOCATION_SUITE: &str = "receipt-lane-nullifier-quarantine-v1";
pub const DELTA_BROADCAST_SUITE: &str = "roots-only-confidential-receipt-delta-broadcast-v1";
pub const REDACTION_BUDGET_SUITE: &str = "privacy-redaction-budget-ledger-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MIN_COMMITTEE_WEIGHT: u64 = 67;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MAX_RELAY_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_RELAY_FEE_BPS: u64 = 5;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_DELTA_TTL_SLOTS: u64 = 12;
pub const DEFAULT_QUARANTINE_BLOCKS: u64 = 144;
pub const DEFAULT_MAX_REDATION_UNITS_PER_EPOCH: u64 = 4_096;
pub const DEFAULT_MAX_RECEIPTS_PER_DELTA: usize = 2_048;
pub const DEFAULT_MAX_DELTA_BYTES: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptLane {
    SwapIntent,
    BridgeEntry,
    BridgeExit,
    Payment,
    DexFill,
    LiquidityUpdate,
    Watchtower,
    Emergency,
}

impl ReceiptLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SwapIntent => "swap_intent",
            Self::BridgeEntry => "bridge_entry",
            Self::BridgeExit => "bridge_exit",
            Self::Payment => "payment",
            Self::DexFill => "dex_fill",
            Self::LiquidityUpdate => "liquidity_update",
            Self::Watchtower => "watchtower",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_cap_bps(self, config: &Config) -> u64 {
        match self {
            Self::Payment => config.target_relay_fee_bps,
            Self::SwapIntent | Self::DexFill => config.target_relay_fee_bps + 2,
            Self::BridgeEntry | Self::BridgeExit => config.target_relay_fee_bps + 4,
            Self::LiquidityUpdate | Self::Watchtower => config.target_relay_fee_bps + 6,
            Self::Emergency => config.max_relay_fee_bps,
        }
        .min(config.max_relay_fee_bps)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    Ingress,
    Relay,
    Witness,
    Aggregator,
    Quarantine,
}

impl CommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Relay => "relay",
            Self::Witness => "witness",
            Self::Aggregator => "aggregator",
            Self::Quarantine => "quarantine",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Sealed,
    Gossiped,
    Attested,
    DeltaIncluded,
    Quarantined,
    Expired,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Gossiped => "gossiped",
            Self::Attested => "attested",
            Self::DeltaIncluded => "delta_included",
            Self::Quarantined => "quarantined",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Accepted,
    Rejected,
    Superseded,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyBucket {
    SubSecond,
    OneToTwoSeconds,
    TwoToFiveSeconds,
    FiveToTenSeconds,
    OverTenSeconds,
}

impl LatencyBucket {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SubSecond => "sub_second",
            Self::OneToTwoSeconds => "one_to_two_seconds",
            Self::TwoToFiveSeconds => "two_to_five_seconds",
            Self::FiveToTenSeconds => "five_to_ten_seconds",
            Self::OverTenSeconds => "over_ten_seconds",
        }
    }

    pub fn from_millis(millis: u64) -> Self {
        match millis {
            0..=999 => Self::SubSecond,
            1_000..=1_999 => Self::OneToTwoSeconds,
            2_000..=4_999 => Self::TwoToFiveSeconds,
            5_000..=9_999 => Self::FiveToTenSeconds,
            _ => Self::OverTenSeconds,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BroadcastStatus {
    Open,
    Sent,
    Acknowledged,
    Expired,
}

impl BroadcastStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sent => "sent",
            Self::Acknowledged => "acknowledged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    ConflictingPayloadRoot,
    ConflictingLane,
    DuplicateNullifier,
    FeeCapExceeded,
    StaleReceipt,
    InvalidPqSignature,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConflictingPayloadRoot => "conflicting_payload_root",
            Self::ConflictingLane => "conflicting_lane",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::FeeCapExceeded => "fee_cap_exceeded",
            Self::StaleReceipt => "stale_receipt",
            Self::InvalidPqSignature => "invalid_pq_signature",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub encrypted_receipt_suite: String,
    pub pq_signer_suite: String,
    pub gossip_committee_suite: String,
    pub anti_equivocation_suite: String,
    pub delta_broadcast_suite: String,
    pub redaction_budget_suite: String,
    pub min_committee_weight: u64,
    pub quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub max_relay_fee_bps: u64,
    pub target_relay_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub receipt_ttl_blocks: u64,
    pub delta_ttl_slots: u64,
    pub quarantine_blocks: u64,
    pub max_redaction_units_per_epoch: u64,
    pub max_receipts_per_delta: usize,
    pub max_delta_bytes: u64,
    pub min_pq_security_bits: u16,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: "monero-devnet".to_string(),
            l2_network: "nebula-devnet".to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            encrypted_receipt_suite: ENCRYPTED_RECEIPT_SUITE.to_string(),
            pq_signer_suite: PQ_SIGNER_SUITE.to_string(),
            gossip_committee_suite: GOSSIP_COMMITTEE_SUITE.to_string(),
            anti_equivocation_suite: ANTI_EQUIVOCATION_SUITE.to_string(),
            delta_broadcast_suite: DELTA_BROADCAST_SUITE.to_string(),
            redaction_budget_suite: REDACTION_BUDGET_SUITE.to_string(),
            min_committee_weight: DEFAULT_MIN_COMMITTEE_WEIGHT,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            max_relay_fee_bps: DEFAULT_MAX_RELAY_FEE_BPS,
            target_relay_fee_bps: DEFAULT_TARGET_RELAY_FEE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            delta_ttl_slots: DEFAULT_DELTA_TTL_SLOTS,
            quarantine_blocks: DEFAULT_QUARANTINE_BLOCKS,
            max_redaction_units_per_epoch: DEFAULT_MAX_REDATION_UNITS_PER_EPOCH,
            max_receipts_per_delta: DEFAULT_MAX_RECEIPTS_PER_DELTA,
            max_delta_bytes: DEFAULT_MAX_DELTA_BYTES,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub committees: u64,
    pub members: u64,
    pub lanes: u64,
    pub receipts: u64,
    pub attestations: u64,
    pub quarantines: u64,
    pub broadcasts: u64,
    pub redaction_budgets: u64,
    pub latency_observations: u64,
    pub fixtures: u64,
    pub events: u64,
}

impl Counters {
    pub fn next_committee(&mut self) -> u64 {
        self.committees += 1;
        self.committees
    }

    pub fn next_member(&mut self) -> u64 {
        self.members += 1;
        self.members
    }

    pub fn next_lane(&mut self) -> u64 {
        self.lanes += 1;
        self.lanes
    }

    pub fn next_receipt(&mut self) -> u64 {
        self.receipts += 1;
        self.receipts
    }

    pub fn next_attestation(&mut self) -> u64 {
        self.attestations += 1;
        self.attestations
    }

    pub fn next_quarantine(&mut self) -> u64 {
        self.quarantines += 1;
        self.quarantines
    }

    pub fn next_broadcast(&mut self) -> u64 {
        self.broadcasts += 1;
        self.broadcasts
    }

    pub fn next_redaction_budget(&mut self) -> u64 {
        self.redaction_budgets += 1;
        self.redaction_budgets
    }

    pub fn next_latency_observation(&mut self) -> u64 {
        self.latency_observations += 1;
        self.latency_observations
    }

    pub fn next_fixture(&mut self) -> u64 {
        self.fixtures += 1;
        self.fixtures
    }

    pub fn next_event(&mut self) -> u64 {
        self.events += 1;
        self.events
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub committee_root: String,
    pub member_root: String,
    pub lane_root: String,
    pub receipt_root: String,
    pub attestation_root: String,
    pub quarantine_root: String,
    pub broadcast_root: String,
    pub redaction_budget_root: String,
    pub latency_root: String,
    pub fixture_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GossipCommittee {
    pub committee_id: String,
    pub lane: ReceiptLane,
    pub epoch: u64,
    pub role: CommitteeRole,
    pub member_ids: BTreeSet<String>,
    pub threshold_weight: u64,
    pub total_weight: u64,
    pub region_hint_root: String,
    pub privacy_set_size: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl GossipCommittee {
    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "role": self.role.as_str(),
            "member_ids": self.member_ids,
            "threshold_weight": self.threshold_weight,
            "total_weight": self.total_weight,
            "region_hint_root": self.region_hint_root,
            "privacy_set_size": self.privacy_set_size,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CommitteeMember {
    pub member_id: String,
    pub operator_commitment: String,
    pub committee_id: String,
    pub roles: BTreeSet<CommitteeRole>,
    pub pq_public_key_root: String,
    pub relay_weight: u64,
    pub stake_commitment: String,
    pub max_fee_bps: u64,
    pub latency_floor_ms: u64,
    pub active: bool,
    pub joined_at_height: u64,
}

impl CommitteeMember {
    pub fn public_record(&self) -> Value {
        json!({
            "member_id": self.member_id,
            "operator_commitment": self.operator_commitment,
            "committee_id": self.committee_id,
            "roles": self.roles.iter().map(|role| role.as_str()).collect::<Vec<_>>(),
            "pq_public_key_root": self.pq_public_key_root,
            "relay_weight": self.relay_weight,
            "stake_commitment": self.stake_commitment,
            "max_fee_bps": self.max_fee_bps,
            "latency_floor_ms": self.latency_floor_ms,
            "active": self.active,
            "joined_at_height": self.joined_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptLaneState {
    pub lane_id: String,
    pub lane: ReceiptLane,
    pub ingress_committee_id: String,
    pub relay_committee_id: String,
    pub aggregator_committee_id: String,
    pub encrypted_mempool_root: String,
    pub nullifier_root: String,
    pub fee_cap_bps: u64,
    pub open_receipts: u64,
    pub gossiped_receipts: u64,
    pub quarantined_receipts: u64,
    pub last_delta_slot: u64,
    pub created_at_height: u64,
}

impl ReceiptLaneState {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane": self.lane.as_str(),
            "ingress_committee_id": self.ingress_committee_id,
            "relay_committee_id": self.relay_committee_id,
            "aggregator_committee_id": self.aggregator_committee_id,
            "encrypted_mempool_root": self.encrypted_mempool_root,
            "nullifier_root": self.nullifier_root,
            "fee_cap_bps": self.fee_cap_bps,
            "open_receipts": self.open_receipts,
            "gossiped_receipts": self.gossiped_receipts,
            "quarantined_receipts": self.quarantined_receipts,
            "last_delta_slot": self.last_delta_slot,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedPreconfirmationReceipt {
    pub receipt_id: String,
    pub lane: ReceiptLane,
    pub sender_commitment: String,
    pub recipient_hint_root: String,
    pub nullifier_commitment: String,
    pub encrypted_payload_root: String,
    pub redacted_public_payload: Value,
    pub relay_fee_bps: u64,
    pub relay_fee_asset_id: String,
    pub privacy_set_size: u64,
    pub status: ReceiptStatus,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub latency_bucket: LatencyBucket,
    pub attestation_ids: BTreeSet<String>,
    pub delta_broadcast_ids: BTreeSet<String>,
}

impl EncryptedPreconfirmationReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "lane": self.lane.as_str(),
            "sender_commitment": self.sender_commitment,
            "recipient_hint_root": self.recipient_hint_root,
            "nullifier_commitment": self.nullifier_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "redacted_public_payload": self.redacted_public_payload,
            "relay_fee_bps": self.relay_fee_bps,
            "relay_fee_asset_id": self.relay_fee_asset_id,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
            "first_seen_height": self.first_seen_height,
            "expires_at_height": self.expires_at_height,
            "latency_bucket": self.latency_bucket.as_str(),
            "attestation_ids": self.attestation_ids,
            "delta_broadcast_ids": self.delta_broadcast_ids,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqSignerAttestation {
    pub attestation_id: String,
    pub receipt_id: String,
    pub committee_id: String,
    pub signer_member_id: String,
    pub lane: ReceiptLane,
    pub signed_receipt_root: String,
    pub signature_root: String,
    pub pq_security_bits: u16,
    pub signer_weight: u64,
    pub aggregate_weight_after: u64,
    pub status: AttestationStatus,
    pub attested_at_height: u64,
}

impl PqSignerAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "receipt_id": self.receipt_id,
            "committee_id": self.committee_id,
            "signer_member_id": self.signer_member_id,
            "lane": self.lane.as_str(),
            "signed_receipt_root": self.signed_receipt_root,
            "signature_root": self.signature_root,
            "pq_security_bits": self.pq_security_bits,
            "signer_weight": self.signer_weight,
            "aggregate_weight_after": self.aggregate_weight_after,
            "status": self.status.as_str(),
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AntiEquivocationQuarantine {
    pub quarantine_id: String,
    pub receipt_id: String,
    pub lane: ReceiptLane,
    pub nullifier_commitment: String,
    pub conflicting_receipt_ids: BTreeSet<String>,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub released: bool,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl AntiEquivocationQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "receipt_id": self.receipt_id,
            "lane": self.lane.as_str(),
            "nullifier_commitment": self.nullifier_commitment,
            "conflicting_receipt_ids": self.conflicting_receipt_ids,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "released": self.released,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeltaBroadcast {
    pub broadcast_id: String,
    pub lane: ReceiptLane,
    pub slot: u64,
    pub receipt_ids: BTreeSet<String>,
    pub receipt_root: String,
    pub attestation_root: String,
    pub quarantine_root: String,
    pub redaction_root: String,
    pub byte_size: u64,
    pub relay_fee_cap_bps: u64,
    pub status: BroadcastStatus,
    pub sent_at_height: u64,
    pub expires_at_slot: u64,
}

impl DeltaBroadcast {
    pub fn public_record(&self) -> Value {
        json!({
            "broadcast_id": self.broadcast_id,
            "lane": self.lane.as_str(),
            "slot": self.slot,
            "receipt_ids": self.receipt_ids,
            "receipt_root": self.receipt_root,
            "attestation_root": self.attestation_root,
            "quarantine_root": self.quarantine_root,
            "redaction_root": self.redaction_root,
            "byte_size": self.byte_size,
            "relay_fee_cap_bps": self.relay_fee_cap_bps,
            "status": self.status.as_str(),
            "sent_at_height": self.sent_at_height,
            "expires_at_slot": self.expires_at_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudget {
    pub budget_id: String,
    pub lane: ReceiptLane,
    pub epoch: u64,
    pub units_available: u64,
    pub units_spent: u64,
    pub redacted_field_roots: BTreeSet<String>,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub created_at_height: u64,
}

impl PrivacyRedactionBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "units_available": self.units_available,
            "units_spent": self.units_spent,
            "redacted_field_roots": self.redacted_field_roots,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencyObservation {
    pub observation_id: String,
    pub receipt_id: String,
    pub lane: ReceiptLane,
    pub member_id: String,
    pub ingress_millis: u64,
    pub relay_millis: u64,
    pub aggregate_millis: u64,
    pub bucket: LatencyBucket,
    pub recorded_at_height: u64,
}

impl LatencyObservation {
    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "receipt_id": self.receipt_id,
            "lane": self.lane.as_str(),
            "member_id": self.member_id,
            "ingress_millis": self.ingress_millis,
            "relay_millis": self.relay_millis,
            "aggregate_millis": self.aggregate_millis,
            "bucket": self.bucket.as_str(),
            "recorded_at_height": self.recorded_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DevnetDemoFixture {
    pub fixture_id: String,
    pub label: String,
    pub lane: ReceiptLane,
    pub receipt_id: String,
    pub committee_id: String,
    pub broadcast_id: String,
    pub deterministic_root: String,
    pub created_at_height: u64,
}

impl DevnetDemoFixture {
    pub fn public_record(&self) -> Value {
        json!({
            "fixture_id": self.fixture_id,
            "label": self.label,
            "lane": self.lane.as_str(),
            "receipt_id": self.receipt_id,
            "committee_id": self.committee_id,
            "broadcast_id": self.broadcast_id,
            "deterministic_root": self.deterministic_root,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub epoch: u64,
    pub slot: u64,
    pub committees: BTreeMap<String, GossipCommittee>,
    pub members: BTreeMap<String, CommitteeMember>,
    pub lanes: BTreeMap<String, ReceiptLaneState>,
    pub receipts: BTreeMap<String, EncryptedPreconfirmationReceipt>,
    pub attestations: BTreeMap<String, PqSignerAttestation>,
    pub quarantines: BTreeMap<String, AntiEquivocationQuarantine>,
    pub broadcasts: BTreeMap<String, DeltaBroadcast>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudget>,
    pub latency_observations: BTreeMap<String, LatencyObservation>,
    pub fixtures: BTreeMap<String, DevnetDemoFixture>,
    pub nullifier_index: BTreeMap<String, String>,
    pub events: Vec<Value>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64, slot: u64) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            height,
            epoch,
            slot,
            committees: BTreeMap::new(),
            members: BTreeMap::new(),
            lanes: BTreeMap::new(),
            receipts: BTreeMap::new(),
            attestations: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            broadcasts: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            latency_observations: BTreeMap::new(),
            fixtures: BTreeMap::new(),
            nullifier_index: BTreeMap::new(),
            events: Vec::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH, 42_000);
        state.install_devnet_lanes();
        state.install_devnet_receipts();
        state.install_devnet_fixture("devnet-fast-gossip");
        state.recompute_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        state.height += 3;
        state.slot += 3;
        let receipt_id = state
            .open_receipt(
                ReceiptLane::Payment,
                "demo-sender-commitment",
                "demo-recipient-hint-root",
                json!({
                    "amount_commitment": "redacted",
                    "asset_hint": "wxmr",
                    "speed": "sub_second",
                }),
                4,
                700,
            )
            .expect("demo receipt fee cap");
        state
            .attest_receipt(&receipt_id, "demo-pq-signature-root", 840)
            .expect("demo attestation");
        state
            .broadcast_delta(ReceiptLane::Payment)
            .expect("demo delta broadcast");
        state.install_devnet_fixture("demo-fast-preconfirmation");
        state.recompute_roots();
        state
    }

    pub fn open_receipt(
        &mut self,
        lane: ReceiptLane,
        sender_commitment: &str,
        recipient_hint_root: &str,
        redacted_public_payload: Value,
        relay_fee_bps: u64,
        observed_latency_millis: u64,
    ) -> PrivateL2FastPqConfidentialPreconfirmationReceiptGossipRuntimeResult<String> {
        if relay_fee_bps > lane.fee_cap_bps(&self.config) {
            return Err(format!(
                "relay fee {relay_fee_bps} bps exceeds lane cap {} bps",
                lane.fee_cap_bps(&self.config)
            ));
        }

        let sequence = self.counters.next_receipt();
        let encrypted_payload_root =
            payload_root("ENCRYPTED-RECEIPT-PAYLOAD", &redacted_public_payload);
        let nullifier_commitment =
            receipt_nullifier(lane, sender_commitment, &encrypted_payload_root);
        let receipt_id = receipt_id(lane, sender_commitment, &encrypted_payload_root, sequence);

        if let Some(conflicting_receipt_id) =
            self.nullifier_index.get(&nullifier_commitment).cloned()
        {
            let mut conflicts = BTreeSet::new();
            conflicts.insert(conflicting_receipt_id);
            conflicts.insert(receipt_id.clone());
            self.open_quarantine(
                &receipt_id,
                lane,
                &nullifier_commitment,
                conflicts,
                QuarantineReason::DuplicateNullifier,
            );
        } else {
            self.nullifier_index
                .insert(nullifier_commitment.clone(), receipt_id.clone());
        }

        let receipt = EncryptedPreconfirmationReceipt {
            receipt_id: receipt_id.clone(),
            lane,
            sender_commitment: sender_commitment.to_string(),
            recipient_hint_root: recipient_hint_root.to_string(),
            nullifier_commitment,
            encrypted_payload_root,
            redacted_public_payload,
            relay_fee_bps,
            relay_fee_asset_id: self.config.fee_asset_id.clone(),
            privacy_set_size: self.config.target_privacy_set_size,
            status: ReceiptStatus::Sealed,
            first_seen_height: self.height,
            expires_at_height: self.height + self.config.receipt_ttl_blocks,
            latency_bucket: LatencyBucket::from_millis(observed_latency_millis),
            attestation_ids: BTreeSet::new(),
            delta_broadcast_ids: BTreeSet::new(),
        };

        self.receipts.insert(receipt_id.clone(), receipt.clone());
        self.bump_lane_open(lane);
        self.record_latency(&receipt, observed_latency_millis);
        self.emit_event("receipt_opened", &receipt.public_record());
        self.recompute_roots();
        Ok(receipt_id)
    }

    pub fn attest_receipt(
        &mut self,
        receipt_id: &str,
        signature_root: &str,
        observed_latency_millis: u64,
    ) -> PrivateL2FastPqConfidentialPreconfirmationReceiptGossipRuntimeResult<String> {
        let receipt = self
            .receipts
            .get(receipt_id)
            .cloned()
            .ok_or_else(|| format!("unknown receipt {receipt_id}"))?;
        let committee_id = self
            .committee_for_lane(receipt.lane, CommitteeRole::Aggregator)
            .ok_or_else(|| format!("missing aggregator committee for {}", receipt.lane.as_str()))?;
        let member = self
            .members
            .values()
            .find(|member| member.committee_id == committee_id && member.active)
            .cloned()
            .ok_or_else(|| format!("missing active signer for committee {committee_id}"))?;
        let current_weight = receipt
            .attestation_ids
            .iter()
            .filter_map(|id| self.attestations.get(id))
            .map(|attestation| attestation.signer_weight)
            .sum::<u64>();
        let aggregate_weight_after = current_weight + member.relay_weight;
        let sequence = self.counters.next_attestation();
        let attestation = PqSignerAttestation {
            attestation_id: attestation_id(receipt_id, &member.member_id, sequence),
            receipt_id: receipt_id.to_string(),
            committee_id,
            signer_member_id: member.member_id,
            lane: receipt.lane,
            signed_receipt_root: root_from_record("SIGNED-RECEIPT", &receipt.public_record()),
            signature_root: signature_root.to_string(),
            pq_security_bits: self.config.min_pq_security_bits,
            signer_weight: member.relay_weight,
            aggregate_weight_after,
            status: AttestationStatus::Accepted,
            attested_at_height: self.height,
        };

        if let Some(receipt) = self.receipts.get_mut(receipt_id) {
            receipt
                .attestation_ids
                .insert(attestation.attestation_id.clone());
            receipt.status = if aggregate_weight_after >= self.config.min_committee_weight {
                ReceiptStatus::Attested
            } else {
                ReceiptStatus::Gossiped
            };
            receipt.latency_bucket = LatencyBucket::from_millis(observed_latency_millis);
        }
        self.attestations
            .insert(attestation.attestation_id.clone(), attestation.clone());
        self.emit_event("pq_signer_attested", &attestation.public_record());
        self.recompute_roots();
        Ok(attestation.attestation_id)
    }

    pub fn broadcast_delta(
        &mut self,
        lane: ReceiptLane,
    ) -> PrivateL2FastPqConfidentialPreconfirmationReceiptGossipRuntimeResult<String> {
        let receipt_ids = self
            .receipts
            .iter()
            .filter(|(_, receipt)| {
                receipt.lane == lane
                    && matches!(
                        receipt.status,
                        ReceiptStatus::Gossiped | ReceiptStatus::Attested
                    )
            })
            .take(self.config.max_receipts_per_delta)
            .map(|(id, _)| id.clone())
            .collect::<BTreeSet<_>>();
        if receipt_ids.is_empty() {
            return Err(format!("no receipts ready for lane {}", lane.as_str()));
        }

        let sequence = self.counters.next_broadcast();
        let receipt_records = receipt_ids
            .iter()
            .filter_map(|id| self.receipts.get(id))
            .map(EncryptedPreconfirmationReceipt::public_record)
            .collect::<Vec<_>>();
        let attestation_records = self
            .attestations
            .values()
            .filter(|attestation| receipt_ids.contains(&attestation.receipt_id))
            .map(PqSignerAttestation::public_record)
            .collect::<Vec<_>>();
        let broadcast = DeltaBroadcast {
            broadcast_id: broadcast_id(lane, self.slot, sequence),
            lane,
            slot: self.slot,
            receipt_ids: receipt_ids.clone(),
            receipt_root: records_root("DELTA-RECEIPTS", receipt_records),
            attestation_root: records_root("DELTA-ATTESTATIONS", attestation_records),
            quarantine_root: self.roots.quarantine_root.clone(),
            redaction_root: self.roots.redaction_budget_root.clone(),
            byte_size: estimate_delta_bytes(receipt_ids.len()),
            relay_fee_cap_bps: lane.fee_cap_bps(&self.config),
            status: BroadcastStatus::Sent,
            sent_at_height: self.height,
            expires_at_slot: self.slot + self.config.delta_ttl_slots,
        };

        for id in &receipt_ids {
            if let Some(receipt) = self.receipts.get_mut(id) {
                receipt.status = ReceiptStatus::DeltaIncluded;
                receipt
                    .delta_broadcast_ids
                    .insert(broadcast.broadcast_id.clone());
            }
        }
        if let Some(lane_state) = self.lane_state_mut(lane) {
            lane_state.last_delta_slot = self.slot;
            lane_state.gossiped_receipts += receipt_ids.len() as u64;
        }
        self.broadcasts
            .insert(broadcast.broadcast_id.clone(), broadcast.clone());
        self.emit_event("delta_broadcast_sent", &broadcast.public_record());
        self.recompute_roots();
        Ok(broadcast.broadcast_id)
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn roots(&self) -> &Roots {
        &self.roots
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    fn install_devnet_lanes(&mut self) {
        for lane in [
            ReceiptLane::Payment,
            ReceiptLane::SwapIntent,
            ReceiptLane::BridgeEntry,
            ReceiptLane::BridgeExit,
            ReceiptLane::Watchtower,
        ] {
            let ingress = self.create_committee(lane, CommitteeRole::Ingress);
            let relay = self.create_committee(lane, CommitteeRole::Relay);
            let aggregator = self.create_committee(lane, CommitteeRole::Aggregator);
            self.create_lane_state(lane, &ingress, &relay, &aggregator);
        }
    }

    fn install_devnet_receipts(&mut self) {
        let payment = self
            .open_receipt(
                ReceiptLane::Payment,
                "devnet-payment-sender-commitment",
                "devnet-payment-recipient-hint-root",
                json!({"asset_hint": "wxmr", "amount_bucket": "small", "route": "redacted"}),
                3,
                640,
            )
            .expect("payment receipt");
        self.attest_receipt(&payment, "devnet-payment-pq-signature-root", 820)
            .expect("payment attestation");

        let swap = self
            .open_receipt(
                ReceiptLane::SwapIntent,
                "devnet-swap-sender-commitment",
                "devnet-swap-recipient-hint-root",
                json!({"pair_hint": "xmr/usdc", "side": "redacted", "slippage_bucket": "tight"}),
                6,
                1_420,
            )
            .expect("swap receipt");
        self.attest_receipt(&swap, "devnet-swap-pq-signature-root", 1_720)
            .expect("swap attestation");

        let bridge = self
            .open_receipt(
                ReceiptLane::BridgeExit,
                "devnet-bridge-exit-sender-commitment",
                "devnet-bridge-exit-recipient-hint-root",
                json!({"exit_asset": "xmr", "destination": "redacted", "urgency": "fast"}),
                7,
                2_180,
            )
            .expect("bridge receipt");
        self.attest_receipt(&bridge, "devnet-bridge-exit-pq-signature-root", 2_500)
            .expect("bridge attestation");

        self.broadcast_delta(ReceiptLane::Payment)
            .expect("payment delta");
        self.broadcast_delta(ReceiptLane::SwapIntent)
            .expect("swap delta");
        self.broadcast_delta(ReceiptLane::BridgeExit)
            .expect("bridge delta");
    }

    fn install_devnet_fixture(&mut self, label: &str) {
        let sequence = self.counters.next_fixture();
        let lane = ReceiptLane::Payment;
        let receipt_id = self
            .receipts
            .values()
            .find(|receipt| receipt.lane == lane)
            .map(|receipt| receipt.receipt_id.clone())
            .unwrap_or_else(|| "missing-receipt".to_string());
        let committee_id = self
            .committee_for_lane(lane, CommitteeRole::Aggregator)
            .unwrap_or_else(|| "missing-committee".to_string());
        let broadcast_id = self
            .broadcasts
            .values()
            .find(|broadcast| broadcast.lane == lane)
            .map(|broadcast| broadcast.broadcast_id.clone())
            .unwrap_or_else(|| "missing-broadcast".to_string());
        let deterministic_root = domain_hash(
            "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PRECONFIRMATION-RECEIPT-GOSSIP:FIXTURE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(label),
                HashPart::Str(&receipt_id),
                HashPart::Str(&committee_id),
                HashPart::Str(&broadcast_id),
                HashPart::U64(sequence),
            ],
            32,
        );
        let fixture = DevnetDemoFixture {
            fixture_id: fixture_id(label, sequence),
            label: label.to_string(),
            lane,
            receipt_id,
            committee_id,
            broadcast_id,
            deterministic_root,
            created_at_height: self.height,
        };
        self.fixtures
            .insert(fixture.fixture_id.clone(), fixture.clone());
        self.emit_event("fixture_installed", &fixture.public_record());
    }

    fn create_committee(&mut self, lane: ReceiptLane, role: CommitteeRole) -> String {
        let sequence = self.counters.next_committee();
        let committee_id = committee_id(lane, role, self.epoch, sequence);
        let mut member_ids = BTreeSet::new();
        let mut total_weight = 0;
        for index in 0..3 {
            let member_sequence = self.counters.next_member();
            let operator_commitment = format!(
                "devnet-{}-{}-operator-commitment-{}",
                lane.as_str(),
                role.as_str(),
                index + 1
            );
            let member_id = member_id(&committee_id, &operator_commitment, member_sequence);
            let relay_weight = 24 + (index as u64 * 8);
            let mut roles = BTreeSet::new();
            roles.insert(role);
            roles.insert(CommitteeRole::Witness);
            let member = CommitteeMember {
                member_id: member_id.clone(),
                operator_commitment: operator_commitment.clone(),
                committee_id: committee_id.clone(),
                roles,
                pq_public_key_root: payload_root(
                    "PQ-PUBLIC-KEY",
                    &json!({"operator_commitment": operator_commitment, "suite": PQ_SIGNER_SUITE}),
                ),
                relay_weight,
                stake_commitment: stake_commitment(&member_id, relay_weight),
                max_fee_bps: lane.fee_cap_bps(&self.config),
                latency_floor_ms: 180 + (index as u64 * 70),
                active: true,
                joined_at_height: self.height,
            };
            total_weight += relay_weight;
            member_ids.insert(member_id.clone());
            self.members.insert(member_id, member);
        }
        let committee = GossipCommittee {
            committee_id: committee_id.clone(),
            lane,
            epoch: self.epoch,
            role,
            member_ids,
            threshold_weight: self.config.min_committee_weight,
            total_weight,
            region_hint_root: payload_root(
                "REGION-HINT",
                &json!({"lane": lane.as_str(), "role": role.as_str(), "regions": ["na", "eu"]}),
            ),
            privacy_set_size: self.config.target_privacy_set_size,
            created_at_height: self.height,
            expires_at_height: self.height + self.config.receipt_ttl_blocks * 32,
        };
        self.committees
            .insert(committee_id.clone(), committee.clone());
        self.emit_event("committee_created", &committee.public_record());
        committee_id
    }

    fn create_lane_state(
        &mut self,
        lane: ReceiptLane,
        ingress_committee_id: &str,
        relay_committee_id: &str,
        aggregator_committee_id: &str,
    ) {
        let sequence = self.counters.next_lane();
        let lane_state = ReceiptLaneState {
            lane_id: lane_id(lane, self.epoch, sequence),
            lane,
            ingress_committee_id: ingress_committee_id.to_string(),
            relay_committee_id: relay_committee_id.to_string(),
            aggregator_committee_id: aggregator_committee_id.to_string(),
            encrypted_mempool_root: empty_root("LANE-ENCRYPTED-MEMPOOL"),
            nullifier_root: empty_root("LANE-NULLIFIERS"),
            fee_cap_bps: lane.fee_cap_bps(&self.config),
            open_receipts: 0,
            gossiped_receipts: 0,
            quarantined_receipts: 0,
            last_delta_slot: self.slot,
            created_at_height: self.height,
        };
        self.lanes
            .insert(lane_state.lane_id.clone(), lane_state.clone());
        let budget = PrivacyRedactionBudget {
            budget_id: redaction_budget_id(lane, self.epoch, self.counters.next_redaction_budget()),
            lane,
            epoch: self.epoch,
            units_available: self.config.max_redaction_units_per_epoch,
            units_spent: 0,
            redacted_field_roots: BTreeSet::from([
                payload_root(
                    "REDACTED-FIELD",
                    &json!({"lane": lane.as_str(), "field": "amount"}),
                ),
                payload_root(
                    "REDACTED-FIELD",
                    &json!({"lane": lane.as_str(), "field": "route"}),
                ),
            ]),
            min_privacy_set_size: self.config.min_privacy_set_size,
            target_privacy_set_size: self.config.target_privacy_set_size,
            created_at_height: self.height,
        };
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget.clone());
        self.emit_event("lane_opened", &lane_state.public_record());
        self.emit_event("redaction_budget_opened", &budget.public_record());
    }

    fn record_latency(&mut self, receipt: &EncryptedPreconfirmationReceipt, millis: u64) {
        let member_id = self
            .members
            .values()
            .find(|member| member.active)
            .map(|member| member.member_id.clone())
            .unwrap_or_else(|| "no-active-member".to_string());
        let sequence = self.counters.next_latency_observation();
        let observation = LatencyObservation {
            observation_id: latency_observation_id(&receipt.receipt_id, &member_id, sequence),
            receipt_id: receipt.receipt_id.clone(),
            lane: receipt.lane,
            member_id,
            ingress_millis: millis / 3,
            relay_millis: millis / 3,
            aggregate_millis: millis,
            bucket: LatencyBucket::from_millis(millis),
            recorded_at_height: self.height,
        };
        self.latency_observations
            .insert(observation.observation_id.clone(), observation.clone());
        self.emit_event("latency_observed", &observation.public_record());
    }

    fn open_quarantine(
        &mut self,
        receipt_id: &str,
        lane: ReceiptLane,
        nullifier_commitment: &str,
        conflicting_receipt_ids: BTreeSet<String>,
        reason: QuarantineReason,
    ) {
        let sequence = self.counters.next_quarantine();
        let evidence = json!({
            "receipt_id": receipt_id,
            "lane": lane.as_str(),
            "nullifier_commitment": nullifier_commitment,
            "conflicting_receipt_ids": conflicting_receipt_ids,
            "reason": reason.as_str(),
        });
        let quarantine = AntiEquivocationQuarantine {
            quarantine_id: quarantine_id(lane, nullifier_commitment, sequence),
            receipt_id: receipt_id.to_string(),
            lane,
            nullifier_commitment: nullifier_commitment.to_string(),
            conflicting_receipt_ids,
            reason,
            evidence_root: payload_root("QUARANTINE-EVIDENCE", &evidence),
            released: false,
            opened_at_height: self.height,
            expires_at_height: self.height + self.config.quarantine_blocks,
        };
        if let Some(lane_state) = self.lane_state_mut(lane) {
            lane_state.quarantined_receipts += 1;
        }
        self.quarantines
            .insert(quarantine.quarantine_id.clone(), quarantine.clone());
        self.emit_event(
            "anti_equivocation_quarantine_opened",
            &quarantine.public_record(),
        );
    }

    fn bump_lane_open(&mut self, lane: ReceiptLane) {
        let nullifier_root = records_root(
            "LANE-NULLIFIERS",
            self.receipts
                .values()
                .filter(|receipt| receipt.lane == lane)
                .map(|receipt| json!(receipt.nullifier_commitment))
                .collect(),
        );
        let encrypted_mempool_root = records_root(
            "LANE-ENCRYPTED-MEMPOOL",
            self.receipts
                .values()
                .filter(|receipt| receipt.lane == lane)
                .map(EncryptedPreconfirmationReceipt::public_record)
                .collect(),
        );
        if let Some(lane_state) = self.lane_state_mut(lane) {
            lane_state.open_receipts += 1;
            lane_state.nullifier_root = nullifier_root;
            lane_state.encrypted_mempool_root = encrypted_mempool_root;
        }
    }

    fn lane_state_mut(&mut self, lane: ReceiptLane) -> Option<&mut ReceiptLaneState> {
        self.lanes
            .values_mut()
            .find(|lane_state| lane_state.lane == lane)
    }

    fn committee_for_lane(&self, lane: ReceiptLane, role: CommitteeRole) -> Option<String> {
        self.committees
            .values()
            .find(|committee| committee.lane == lane && committee.role == role)
            .map(|committee| committee.committee_id.clone())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_fast_pq_confidential_preconfirmation_receipt_gossip_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "encrypted_receipt_suite": ENCRYPTED_RECEIPT_SUITE,
            "pq_signer_suite": PQ_SIGNER_SUITE,
            "gossip_committee_suite": GOSSIP_COMMITTEE_SUITE,
            "anti_equivocation_suite": ANTI_EQUIVOCATION_SUITE,
            "delta_broadcast_suite": DELTA_BROADCAST_SUITE,
            "redaction_budget_suite": REDACTION_BUDGET_SUITE,
            "height": self.height,
            "epoch": self.epoch,
            "slot": self.slot,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots_without_self_reference(&self.roots),
            "committees": self.committees.values().map(GossipCommittee::public_record).collect::<Vec<_>>(),
            "members": self.members.values().map(CommitteeMember::public_record).collect::<Vec<_>>(),
            "lanes": self.lanes.values().map(ReceiptLaneState::public_record).collect::<Vec<_>>(),
            "receipts": self.receipts.values().map(EncryptedPreconfirmationReceipt::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(PqSignerAttestation::public_record).collect::<Vec<_>>(),
            "quarantines": self.quarantines.values().map(AntiEquivocationQuarantine::public_record).collect::<Vec<_>>(),
            "broadcasts": self.broadcasts.values().map(DeltaBroadcast::public_record).collect::<Vec<_>>(),
            "redaction_budgets": self.redaction_budgets.values().map(PrivacyRedactionBudget::public_record).collect::<Vec<_>>(),
            "latency_observations": self.latency_observations.values().map(LatencyObservation::public_record).collect::<Vec<_>>(),
            "fixtures": self.fixtures.values().map(DevnetDemoFixture::public_record).collect::<Vec<_>>(),
            "nullifier_index_root": records_root("NULLIFIER-INDEX", self.nullifier_index.iter().map(|(nullifier, receipt_id)| json!({"nullifier": nullifier, "receipt_id": receipt_id})).collect()),
            "events": self.events,
        })
    }

    fn emit_event(&mut self, event_kind: &str, payload: &Value) {
        let sequence = self.counters.next_event();
        self.events.push(json!({
            "event_id": event_id(event_kind, self.height, sequence),
            "kind": event_kind,
            "height": self.height,
            "slot": self.slot,
            "sequence": sequence,
            "payload_root": payload_root("EVENT-PAYLOAD", payload),
        }));
    }

    fn recompute_roots(&mut self) {
        self.roots.config_root = payload_root("CONFIG", &self.config.public_record());
        self.roots.counter_root = payload_root("COUNTERS", &self.counters.public_record());
        self.roots.committee_root = records_root(
            "COMMITTEES",
            self.committees
                .values()
                .map(GossipCommittee::public_record)
                .collect(),
        );
        self.roots.member_root = records_root(
            "MEMBERS",
            self.members
                .values()
                .map(CommitteeMember::public_record)
                .collect(),
        );
        self.roots.lane_root = records_root(
            "LANES",
            self.lanes
                .values()
                .map(ReceiptLaneState::public_record)
                .collect(),
        );
        self.roots.receipt_root = records_root(
            "RECEIPTS",
            self.receipts
                .values()
                .map(EncryptedPreconfirmationReceipt::public_record)
                .collect(),
        );
        self.roots.attestation_root = records_root(
            "ATTESTATIONS",
            self.attestations
                .values()
                .map(PqSignerAttestation::public_record)
                .collect(),
        );
        self.roots.quarantine_root = records_root(
            "QUARANTINES",
            self.quarantines
                .values()
                .map(AntiEquivocationQuarantine::public_record)
                .collect(),
        );
        self.roots.broadcast_root = records_root(
            "BROADCASTS",
            self.broadcasts
                .values()
                .map(DeltaBroadcast::public_record)
                .collect(),
        );
        self.roots.redaction_budget_root = records_root(
            "REDACTION-BUDGETS",
            self.redaction_budgets
                .values()
                .map(PrivacyRedactionBudget::public_record)
                .collect(),
        );
        self.roots.latency_root = records_root(
            "LATENCY-OBSERVATIONS",
            self.latency_observations
                .values()
                .map(LatencyObservation::public_record)
                .collect(),
        );
        self.roots.fixture_root = records_root(
            "FIXTURES",
            self.fixtures
                .values()
                .map(DevnetDemoFixture::public_record)
                .collect(),
        );
        self.roots.event_root = records_root("EVENTS", self.events.clone());
        self.roots.state_root = self.state_root();
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

pub fn committee_id(lane: ReceiptLane, role: CommitteeRole, epoch: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PRECONFIRMATION-RECEIPT-GOSSIP:COMMITTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(role.as_str()),
            HashPart::U64(epoch),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn member_id(committee_id: &str, operator_commitment: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PRECONFIRMATION-RECEIPT-GOSSIP:MEMBER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(committee_id),
            HashPart::Str(operator_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn lane_id(lane: ReceiptLane, epoch: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PRECONFIRMATION-RECEIPT-GOSSIP:LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::U64(epoch),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn receipt_id(
    lane: ReceiptLane,
    sender_commitment: &str,
    encrypted_payload_root: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PRECONFIRMATION-RECEIPT-GOSSIP:RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(sender_commitment),
            HashPart::Str(encrypted_payload_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn receipt_nullifier(
    lane: ReceiptLane,
    sender_commitment: &str,
    encrypted_payload_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PRECONFIRMATION-RECEIPT-GOSSIP:RECEIPT-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(sender_commitment),
            HashPart::Str(encrypted_payload_root),
        ],
        32,
    )
}

pub fn attestation_id(receipt_id: &str, member_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PRECONFIRMATION-RECEIPT-GOSSIP:ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(member_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn quarantine_id(lane: ReceiptLane, nullifier_commitment: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PRECONFIRMATION-RECEIPT-GOSSIP:QUARANTINE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(nullifier_commitment),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn broadcast_id(lane: ReceiptLane, slot: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PRECONFIRMATION-RECEIPT-GOSSIP:BROADCAST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::U64(slot),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn redaction_budget_id(lane: ReceiptLane, epoch: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PRECONFIRMATION-RECEIPT-GOSSIP:REDACTION-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::U64(epoch),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn latency_observation_id(receipt_id: &str, member_id: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PRECONFIRMATION-RECEIPT-GOSSIP:LATENCY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(member_id),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn fixture_id(label: &str, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PRECONFIRMATION-RECEIPT-GOSSIP:FIXTURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn event_id(event_kind: &str, height: u64, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PRECONFIRMATION-RECEIPT-GOSSIP:EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn stake_commitment(member_id: &str, relay_weight: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PRECONFIRMATION-RECEIPT-GOSSIP:STAKE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(member_id),
            HashPart::U64(relay_weight),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PRECONFIRMATION-RECEIPT-GOSSIP:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PRECONFIRMATION-RECEIPT-GOSSIP:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("STATE-ROOT", record)
}

fn empty_root(domain: &str) -> String {
    records_root(domain, Vec::new())
}

fn records_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!("PRIVATE-L2-FAST-PQ-CONFIDENTIAL-PRECONFIRMATION-RECEIPT-GOSSIP:{domain}"),
        &records,
    )
}

fn estimate_delta_bytes(receipt_count: usize) -> u64 {
    512 + receipt_count as u64 * 384
}

fn roots_without_self_reference(roots: &Roots) -> Value {
    json!({
        "config_root": roots.config_root,
        "counter_root": roots.counter_root,
        "committee_root": roots.committee_root,
        "member_root": roots.member_root,
        "lane_root": roots.lane_root,
        "receipt_root": roots.receipt_root,
        "attestation_root": roots.attestation_root,
        "quarantine_root": roots.quarantine_root,
        "broadcast_root": roots.broadcast_root,
        "redaction_budget_root": roots.redaction_budget_root,
        "latency_root": roots.latency_root,
        "fixture_root": roots.fixture_root,
        "event_root": roots.event_root,
    })
}
