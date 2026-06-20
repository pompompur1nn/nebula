use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedEventSubscriptionFeeRouterRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> =
    PrivateL2PqConfidentialContractSealedEventSubscriptionFeeRouterRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_EVENT_SUBSCRIPTION_FEE_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-sealed-event-subscription-fee-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_EVENT_SUBSCRIPTION_FEE_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEALED_EVENT_SUBSCRIPTION_FEE_ROUTER_SUITE: &str =
    "sealed-confidential-smart-contract-event-subscription-fee-router-v1";
pub const PRIVATE_SUBSCRIPTION_FEE_BID_SUITE: &str =
    "private-event-subscription-fee-bid-commitment-v1";
pub const PQ_EVENT_SUBSCRIPTION_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-event-subscription-commitment-attestation-v1";
pub const LOW_FEE_BATCHING_SUITE: &str = "low-fee-confidential-event-subscription-batching-v1";
pub const REPLAY_RESISTANCE_SUITE: &str = "sealed-event-subscription-router-replay-nullifier-v1";
pub const PRIVACY_PRESERVING_STATE_SUITE: &str =
    "privacy-preserving-event-subscription-router-public-state-root-v1";
pub const SUBSCRIPTION_WINDOW_SCHEME: &str = "sealed-event-subscription-window-root-v1";
pub const PRIVATE_SUBSCRIPTION_FEE_BID_SCHEME: &str = "private-event-subscription-fee-bid-root-v1";
pub const SUBSCRIPTION_COMMITMENT_SCHEME: &str =
    "pq-attested-event-subscription-commitment-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str = "pq-event-subscription-attestation-root-v1";
pub const REPLAY_NULLIFIER_SCHEME: &str = "sealed-event-subscription-replay-nullifier-root-v1";
pub const LOW_FEE_BATCH_SCHEME: &str = "low-fee-event-subscription-router-batch-root-v1";
pub const SUBSCRIPTION_SETTLEMENT_SCHEME: &str =
    "sealed-event-subscription-router-settlement-root-v1";
pub const PUBLIC_STATE_SNAPSHOT_SCHEME: &str =
    "privacy-preserving-event-subscription-router-state-snapshot-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_337_728;
pub const DEVNET_EPOCH: u64 = 10_426;
pub const DEFAULT_SUBSCRIPTION_WINDOW_BLOCKS: u64 = 32;
pub const DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_BIDS_PER_SUBSCRIPTION: usize = 12_288;
pub const DEFAULT_MAX_EVENTS_PER_BID: u64 = 8_192;
pub const DEFAULT_MAX_COMMITMENTS_PER_BATCH: usize = 4_096;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 3;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 6;
pub const DEFAULT_CONGESTION_SURCHARGE_BPS: u64 = 10;
pub const DEFAULT_BASE_SUBSCRIPTION_MICRO_FEE: u64 = 5;
pub const DEFAULT_MIN_SUBSCRIPTION_MICRO_FEE_PER_EVENT: u64 = 1;
pub const DEFAULT_MAX_EVENT_BYTES_PER_BATCH: u64 = 24_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventStreamFamily {
    ContractLog,
    StateDiff,
    Receipt,
    Heartbeat,
    OracleUpdate,
    BridgeMessage,
    GovernanceSignal,
    VaultNotice,
    RiskAlert,
    PqAttestedFeed,
    ConfidentialTransferEvent,
    SealedContractTopic,
}

impl EventStreamFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractLog => "contract_log",
            Self::StateDiff => "state_diff",
            Self::Receipt => "receipt",
            Self::Heartbeat => "heartbeat",
            Self::OracleUpdate => "oracle_update",
            Self::BridgeMessage => "bridge_message",
            Self::GovernanceSignal => "governance_signal",
            Self::VaultNotice => "vault_notice",
            Self::RiskAlert => "risk_alert",
            Self::PqAttestedFeed => "pq_attested_feed",
            Self::ConfidentialTransferEvent => "confidential_transfer_event",
            Self::SealedContractTopic => "sealed_contract_topic",
        }
    }

    pub fn base_weight(self) -> u64 {
        match self {
            Self::SealedContractTopic => 10_000,
            Self::ConfidentialTransferEvent => 9_700,
            Self::PqAttestedFeed => 9_400,
            Self::VaultNotice => 8_800,
            Self::OracleUpdate => 8_200,
            Self::GovernanceSignal => 7_600,
            Self::BridgeMessage => 7_200,
            Self::RiskAlert => 6_700,
            Self::StateDiff => 6_300,
            Self::Receipt => 5_900,
            Self::ContractLog => 5_500,
            Self::Heartbeat => 5_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionClass {
    Interactive,
    LowFeeBatch,
    OracleWebhook,
    BridgeProof,
    Governance,
    Recovery,
    Emergency,
}

impl SubscriptionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::LowFeeBatch => "low_fee_batch",
            Self::OracleWebhook => "oracle_webhook",
            Self::BridgeProof => "bridge_proof",
            Self::Governance => "governance",
            Self::Recovery => "recovery",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::Recovery => 9_600,
            Self::Governance => 9_000,
            Self::BridgeProof => 8_600,
            Self::OracleWebhook => 8_100,
            Self::Interactive => 7_400,
            Self::LowFeeBatch => 6_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Announced,
    CommitOpen,
    PqAttested,
    BatchReady,
    Delivering,
    Settled,
    Cancelled,
    Expired,
}

impl SubscriptionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::CommitOpen => "commit_open",
            Self::PqAttested => "pq_attested",
            Self::BatchReady => "batch_ready",
            Self::Delivering => "delivering",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Sealed,
    ReplayGuarded,
    PqCommitted,
    BatchQueued,
    Delivered,
    Repriced,
    Outbid,
    Refunded,
    DuplicateRejected,
    Expired,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::ReplayGuarded => "replay_guarded",
            Self::PqCommitted => "pq_committed",
            Self::BatchQueued => "batch_queued",
            Self::Delivered => "delivered",
            Self::Repriced => "repriced",
            Self::Outbid => "outbid",
            Self::Refunded => "refunded",
            Self::DuplicateRejected => "duplicate_rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Proposed,
    Authenticated,
    QuorumSigned,
    Applied,
    Challenged,
    Rejected,
}

impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Authenticated => "authenticated",
            Self::QuorumSigned => "quorum_signed",
            Self::Applied => "applied",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStatus {
    Reserved,
    Armed,
    Consumed,
    DuplicateRejected,
    Expired,
}

impl ReplayStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Armed => "armed",
            Self::Consumed => "consumed",
            Self::DuplicateRejected => "duplicate_rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    PqAttested,
    Delivered,
    Repriced,
    Cancelled,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::PqAttested => "pq_attested",
            Self::Delivered => "delivered",
            Self::Repriced => "repriced",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub subscription_window_blocks: u64,
    pub replay_window_blocks: u64,
    pub batch_window_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_bids_per_subscription: usize,
    pub max_event_subscription_events_per_bid: u64,
    pub max_commitments_per_batch: usize,
    pub max_user_fee_bps: u64,
    pub operator_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub congestion_surcharge_bps: u64,
    pub base_event_subscription_micro_fee: u64,
    pub min_subscription_micro_fee_per_event: u64,
    pub max_event_bytes_per_batch: u64,
    pub require_pq_attestation: bool,
    pub require_replay_nullifier: bool,
    pub privacy_preserving_public_apis: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            subscription_window_blocks: DEFAULT_SUBSCRIPTION_WINDOW_BLOCKS,
            replay_window_blocks: DEFAULT_REPLAY_WINDOW_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_bids_per_subscription: DEFAULT_MAX_BIDS_PER_SUBSCRIPTION,
            max_event_subscription_events_per_bid: DEFAULT_MAX_EVENTS_PER_BID,
            max_commitments_per_batch: DEFAULT_MAX_COMMITMENTS_PER_BATCH,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            congestion_surcharge_bps: DEFAULT_CONGESTION_SURCHARGE_BPS,
            base_event_subscription_micro_fee: DEFAULT_BASE_SUBSCRIPTION_MICRO_FEE,
            min_subscription_micro_fee_per_event: DEFAULT_MIN_SUBSCRIPTION_MICRO_FEE_PER_EVENT,
            max_event_bytes_per_batch: DEFAULT_MAX_EVENT_BYTES_PER_BATCH,
            require_pq_attestation: true,
            require_replay_nullifier: true,
            privacy_preserving_public_apis: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(format!(
                "unsupported protocol version: {}",
                self.protocol_version
            ));
        }
        if self.subscription_window_blocks == 0 {
            return Err("subscription window must be non-zero".to_string());
        }
        if self.replay_window_blocks < self.subscription_window_blocks {
            return Err("replay window must cover subscription window".to_string());
        }
        if self.batch_window_blocks == 0 {
            return Err("batch window must be non-zero".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below runtime floor".to_string());
        }
        if self.min_privacy_set_size < 1_024 {
            return Err("privacy set size below anonymity floor".to_string());
        }
        if self.max_bids_per_subscription == 0 || self.max_commitments_per_batch == 0 {
            return Err("subscription and batch limits must be non-zero".to_string());
        }
        if self.max_user_fee_bps + self.operator_fee_bps > MAX_BPS {
            return Err("fee bps exceeds max basis points".to_string());
        }
        if self.base_event_subscription_micro_fee < self.min_subscription_micro_fee_per_event {
            return Err("base fee must not be below min subscription fee".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "subscription_window_blocks": self.subscription_window_blocks,
            "replay_window_blocks": self.replay_window_blocks,
            "batch_window_blocks": self.batch_window_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_bids_per_subscription": self.max_bids_per_subscription,
            "max_event_subscription_events_per_bid": self.max_event_subscription_events_per_bid,
            "max_commitments_per_batch": self.max_commitments_per_batch,
            "max_user_fee_bps": self.max_user_fee_bps,
            "operator_fee_bps": self.operator_fee_bps,
            "batch_rebate_bps": self.batch_rebate_bps,
            "congestion_surcharge_bps": self.congestion_surcharge_bps,
            "base_event_subscription_micro_fee": self.base_event_subscription_micro_fee,
            "min_subscription_micro_fee_per_event": self.min_subscription_micro_fee_per_event,
            "max_event_bytes_per_batch": self.max_event_bytes_per_batch,
            "require_pq_attestation": self.require_pq_attestation,
            "require_replay_nullifier": self.require_replay_nullifier,
            "privacy_preserving_public_apis": self.privacy_preserving_public_apis,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub subscription_windows: u64,
    pub private_fee_bids: u64,
    pub event_subscription_commitments: u64,
    pub pq_attestations: u64,
    pub replay_nullifiers: u64,
    pub low_fee_batches: u64,
    pub subscription_settlements: u64,
    pub public_state_snapshots: u64,
    pub duplicate_replay_rejections: u64,
    pub repriced_bids: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "subscription_windows": self.subscription_windows,
            "private_fee_bids": self.private_fee_bids,
            "event_subscription_commitments": self.event_subscription_commitments,
            "pq_attestations": self.pq_attestations,
            "replay_nullifiers": self.replay_nullifiers,
            "low_fee_batches": self.low_fee_batches,
            "subscription_settlements": self.subscription_settlements,
            "public_state_snapshots": self.public_state_snapshots,
            "duplicate_replay_rejections": self.duplicate_replay_rejections,
            "repriced_bids": self.repriced_bids,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub subscription_window_root: String,
    pub private_fee_bid_root: String,
    pub event_subscription_commitment_root: String,
    pub pq_attestation_root: String,
    pub replay_nullifier_root: String,
    pub low_fee_batch_root: String,
    pub subscription_settlement_root: String,
    pub public_state_snapshot_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "subscription_window_root": self.subscription_window_root,
            "private_fee_bid_root": self.private_fee_bid_root,
            "event_subscription_commitment_root": self.event_subscription_commitment_root,
            "pq_attestation_root": self.pq_attestation_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "low_fee_batch_root": self.low_fee_batch_root,
            "subscription_settlement_root": self.subscription_settlement_root,
            "public_state_snapshot_root": self.public_state_snapshot_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubscriptionWindowInput {
    pub stream_family: EventStreamFamily,
    pub subscription_class: SubscriptionClass,
    pub contract_id: String,
    pub event_subscription_filter_commitment: String,
    pub epoch: u64,
    pub start_height: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateEventSubscriptionFeeBidInput {
    pub subscription_id: String,
    pub bidder_commitment: String,
    pub sealed_fee_bid_root: String,
    pub max_micro_fee_per_event: u64,
    pub event_count_commitment: String,
    pub submitted_height: u64,
    pub expiry_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqEventSubscriptionCommitmentInput {
    pub subscription_id: String,
    pub bid_id: String,
    pub event_subscription_commitment_root: String,
    pub transcript_root: String,
    pub pq_public_key_commitment: String,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatchInput {
    pub subscription_id: String,
    pub bid_ids: Vec<String>,
    pub opened_height: u64,
    pub congestion_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubscriptionSettlementInput {
    pub subscription_id: String,
    pub batch_id: String,
    pub accepted_bid_ids: Vec<String>,
    pub settlement_height: u64,
    pub state_transition_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubscriptionWindow {
    pub subscription_id: String,
    pub stream_family: EventStreamFamily,
    pub subscription_class: SubscriptionClass,
    pub contract_id: String,
    pub event_subscription_filter_commitment: String,
    pub status: SubscriptionStatus,
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub privacy_set_size: u64,
    pub subscription_capacity_events: u64,
    pub base_micro_fee_per_event: u64,
    pub priority_weight: u64,
    pub bid_commitment_root: String,
    pub replay_nullifier_root: String,
    pub pq_attestation_root: String,
    pub public_state_root: String,
}

impl SubscriptionWindow {
    pub fn from_input(config: &Config, input: SubscriptionWindowInput) -> Result<Self> {
        if input.contract_id.is_empty() {
            return Err("contract id must be non-empty".to_string());
        }
        if input.event_subscription_filter_commitment.is_empty() {
            return Err("event subscription filter commitment must be non-empty".to_string());
        }
        if input.privacy_set_size < config.min_privacy_set_size {
            return Err("subscription privacy set below configured floor".to_string());
        }
        let subscription_id = subscription_window_id(
            input.stream_family,
            input.subscription_class,
            &input.contract_id,
            &input.event_subscription_filter_commitment,
            input.epoch,
            input.start_height,
        );
        let subscription_capacity_events = config
            .max_event_subscription_events_per_bid
            .saturating_mul(config.max_bids_per_subscription as u64);
        let priority_weight = input
            .stream_family
            .base_weight()
            .saturating_add(input.subscription_class.priority_weight())
            .saturating_div(2);
        Ok(Self {
            subscription_id,
            stream_family: input.stream_family,
            subscription_class: input.subscription_class,
            contract_id: input.contract_id,
            event_subscription_filter_commitment: input.event_subscription_filter_commitment,
            status: SubscriptionStatus::CommitOpen,
            epoch: input.epoch,
            start_height: input.start_height,
            end_height: input
                .start_height
                .saturating_add(config.subscription_window_blocks),
            privacy_set_size: input.privacy_set_size,
            subscription_capacity_events,
            base_micro_fee_per_event: config.base_event_subscription_micro_fee,
            priority_weight,
            bid_commitment_root: record_root(PRIVATE_SUBSCRIPTION_FEE_BID_SCHEME, &[]),
            replay_nullifier_root: record_root(REPLAY_NULLIFIER_SCHEME, &[]),
            pq_attestation_root: record_root(PQ_ATTESTATION_SCHEME, &[]),
            public_state_root: empty_root("subscription-public-state"),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "subscription_id": self.subscription_id,
            "stream_family": self.stream_family.as_str(),
            "subscription_class": self.subscription_class.as_str(),
            "contract_id": self.contract_id,
            "event_subscription_filter_commitment": self.event_subscription_filter_commitment,
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "privacy_set_size": self.privacy_set_size,
            "subscription_capacity_events": self.subscription_capacity_events,
            "base_micro_fee_per_event": self.base_micro_fee_per_event,
            "priority_weight": self.priority_weight,
            "bid_commitment_root": self.bid_commitment_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "pq_attestation_root": self.pq_attestation_root,
            "public_state_root": self.public_state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateEventSubscriptionFeeBid {
    pub bid_id: String,
    pub subscription_id: String,
    pub bidder_commitment: String,
    pub sealed_fee_bid_root: String,
    pub event_count_commitment: String,
    pub status: BidStatus,
    pub max_micro_fee_per_event: u64,
    pub effective_micro_fee_cap: u64,
    pub submitted_height: u64,
    pub expiry_height: u64,
    pub replay_nullifier: String,
    pub pq_commitment_id: Option<String>,
    pub batch_id: Option<String>,
}

impl PrivateEventSubscriptionFeeBid {
    pub fn from_input(config: &Config, input: PrivateEventSubscriptionFeeBidInput) -> Result<Self> {
        if input.subscription_id.is_empty() {
            return Err("subscription id must be non-empty".to_string());
        }
        if input.bidder_commitment.is_empty() || input.sealed_fee_bid_root.is_empty() {
            return Err("bid commitments must be non-empty".to_string());
        }
        if input.max_micro_fee_per_event < config.min_subscription_micro_fee_per_event {
            return Err("bid fee cap below subscription minimum".to_string());
        }
        if input.expiry_height <= input.submitted_height {
            return Err("bid expiry must be after submission".to_string());
        }
        let bid_id = private_event_subscription_fee_bid_id(
            &input.subscription_id,
            &input.bidder_commitment,
            &input.sealed_fee_bid_root,
            input.submitted_height,
        );
        let replay_nullifier = replay_nullifier_id(
            &input.subscription_id,
            &bid_id,
            &input.bidder_commitment,
            &input.sealed_fee_bid_root,
        );
        Ok(Self {
            bid_id,
            subscription_id: input.subscription_id,
            bidder_commitment: input.bidder_commitment,
            sealed_fee_bid_root: input.sealed_fee_bid_root,
            event_count_commitment: input.event_count_commitment,
            status: BidStatus::ReplayGuarded,
            max_micro_fee_per_event: input.max_micro_fee_per_event,
            effective_micro_fee_cap: input.max_micro_fee_per_event,
            submitted_height: input.submitted_height,
            expiry_height: input.expiry_height,
            replay_nullifier,
            pq_commitment_id: None,
            batch_id: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "subscription_id": self.subscription_id,
            "bidder_commitment": self.bidder_commitment,
            "sealed_fee_bid_root": self.sealed_fee_bid_root,
            "event_count_commitment": self.event_count_commitment,
            "status": self.status.as_str(),
            "max_micro_fee_per_event": self.max_micro_fee_per_event,
            "effective_micro_fee_cap": self.effective_micro_fee_cap,
            "submitted_height": self.submitted_height,
            "expiry_height": self.expiry_height,
            "replay_nullifier": self.replay_nullifier,
            "pq_commitment_id": self.pq_commitment_id,
            "batch_id": self.batch_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventSubscriptionCommitment {
    pub commitment_id: String,
    pub subscription_id: String,
    pub bid_id: String,
    pub event_subscription_commitment_root: String,
    pub transcript_root: String,
    pub pq_public_key_commitment: String,
    pub status: CommitmentStatus,
    pub pq_security_bits: u16,
    pub height: u64,
    pub attestation_id: String,
}

impl EventSubscriptionCommitment {
    pub fn from_input(config: &Config, input: PqEventSubscriptionCommitmentInput) -> Result<Self> {
        if input.subscription_id.is_empty() || input.bid_id.is_empty() {
            return Err("subscription id and bid id must be non-empty".to_string());
        }
        if input.event_subscription_commitment_root.is_empty()
            || input.transcript_root.is_empty()
            || input.pq_public_key_commitment.is_empty()
        {
            return Err("event subscription commitment material must be non-empty".to_string());
        }
        let commitment_id = event_subscription_commitment_id(
            &input.subscription_id,
            &input.bid_id,
            &input.event_subscription_commitment_root,
            input.height,
        );
        let attestation_id = pq_event_subscription_attestation_id(
            &commitment_id,
            &input.subscription_id,
            &input.bid_id,
            input.height,
        );
        Ok(Self {
            commitment_id,
            subscription_id: input.subscription_id,
            bid_id: input.bid_id,
            event_subscription_commitment_root: input.event_subscription_commitment_root,
            transcript_root: input.transcript_root,
            pq_public_key_commitment: input.pq_public_key_commitment,
            status: CommitmentStatus::QuorumSigned,
            pq_security_bits: config.min_pq_security_bits,
            height: input.height,
            attestation_id,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "subscription_id": self.subscription_id,
            "bid_id": self.bid_id,
            "event_subscription_commitment_root": self.event_subscription_commitment_root,
            "transcript_root": self.transcript_root,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "status": self.status.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "height": self.height,
            "attestation_id": self.attestation_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqEventSubscriptionAttestation {
    pub attestation_id: String,
    pub commitment_id: String,
    pub subscription_id: String,
    pub bid_id: String,
    pub attestor_set_root: String,
    pub signature_root: String,
    pub status: CommitmentStatus,
    pub pq_security_bits: u16,
    pub height: u64,
}

impl PqEventSubscriptionAttestation {
    pub fn from_commitment(commitment: &EventSubscriptionCommitment) -> Self {
        let attestor_set_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-SUBSCRIPTION-FEE-ROUTER:ATTESTOR-SET",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(&commitment.pq_public_key_commitment),
            ],
            32,
        );
        let signature_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-SUBSCRIPTION-FEE-ROUTER:ATTESTATION-SIGNATURE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(&commitment.transcript_root),
            ],
            32,
        );
        Self {
            attestation_id: commitment.attestation_id.clone(),
            commitment_id: commitment.commitment_id.clone(),
            subscription_id: commitment.subscription_id.clone(),
            bid_id: commitment.bid_id.clone(),
            attestor_set_root,
            signature_root,
            status: CommitmentStatus::Applied,
            pq_security_bits: commitment.pq_security_bits,
            height: commitment.height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "commitment_id": self.commitment_id,
            "subscription_id": self.subscription_id,
            "bid_id": self.bid_id,
            "attestor_set_root": self.attestor_set_root,
            "signature_root": self.signature_root,
            "status": self.status.as_str(),
            "pq_security_bits": self.pq_security_bits,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayNullifier {
    pub nullifier_id: String,
    pub subscription_id: String,
    pub bid_id: String,
    pub bidder_commitment: String,
    pub sealed_fee_bid_root: String,
    pub status: ReplayStatus,
    pub reserved_height: u64,
    pub expiry_height: u64,
}

impl ReplayNullifier {
    pub fn from_bid(config: &Config, bid: &PrivateEventSubscriptionFeeBid) -> Self {
        Self {
            nullifier_id: bid.replay_nullifier.clone(),
            subscription_id: bid.subscription_id.clone(),
            bid_id: bid.bid_id.clone(),
            bidder_commitment: bid.bidder_commitment.clone(),
            sealed_fee_bid_root: bid.sealed_fee_bid_root.clone(),
            status: ReplayStatus::Armed,
            reserved_height: bid.submitted_height,
            expiry_height: bid
                .submitted_height
                .saturating_add(config.replay_window_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "subscription_id": self.subscription_id,
            "bid_id": self.bid_id,
            "bidder_commitment": self.bidder_commitment,
            "sealed_fee_bid_root": self.sealed_fee_bid_root,
            "status": self.status.as_str(),
            "reserved_height": self.reserved_height,
            "expiry_height": self.expiry_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatch {
    pub batch_id: String,
    pub subscription_id: String,
    pub bid_ids: Vec<String>,
    pub status: BatchStatus,
    pub opened_height: u64,
    pub sealed_height: u64,
    pub congestion_bps: u64,
    pub aggregate_micro_fee_cap: u64,
    pub batch_rebate_micro_fee: u64,
    pub bid_root: String,
    pub pq_attestation_root: String,
    pub replay_nullifier_root: String,
}

impl LowFeeBatch {
    pub fn from_input(
        config: &Config,
        input: LowFeeBatchInput,
        bids: &[PrivateEventSubscriptionFeeBid],
    ) -> Result<Self> {
        if input.subscription_id.is_empty() {
            return Err("subscription id must be non-empty".to_string());
        }
        if input.bid_ids.is_empty() {
            return Err("batch requires at least one bid".to_string());
        }
        if input.bid_ids.len() > config.max_commitments_per_batch {
            return Err("batch exceeds commitment limit".to_string());
        }
        let bid_ids = input.bid_ids;
        let bid_set = bid_ids.iter().cloned().collect::<BTreeSet<_>>();
        let aggregate_micro_fee_cap = bids
            .iter()
            .filter(|bid| bid_set.contains(&bid.bid_id))
            .map(|bid| effective_micro_fee_cap(config, bid, input.congestion_bps))
            .sum::<u64>();
        let batch_id = low_fee_batch_id(&input.subscription_id, &bid_ids, input.opened_height);
        let bid_root = merkle_root(
            "sealed-event-subscription-fee-router-low-fee-batch-bid-id-root-v1",
            &bid_ids.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        let batch_rebate_micro_fee = aggregate_micro_fee_cap
            .saturating_mul(config.batch_rebate_bps)
            .saturating_div(MAX_BPS);
        Ok(Self {
            batch_id,
            subscription_id: input.subscription_id,
            bid_ids,
            status: BatchStatus::Sealed,
            opened_height: input.opened_height,
            sealed_height: input
                .opened_height
                .saturating_add(config.batch_window_blocks),
            congestion_bps: input.congestion_bps.min(config.congestion_surcharge_bps),
            aggregate_micro_fee_cap,
            batch_rebate_micro_fee,
            bid_root,
            pq_attestation_root: record_root(PQ_ATTESTATION_SCHEME, &[]),
            replay_nullifier_root: record_root(REPLAY_NULLIFIER_SCHEME, &[]),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "subscription_id": self.subscription_id,
            "bid_count": self.bid_ids.len(),
            "bid_root": self.bid_root,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "sealed_height": self.sealed_height,
            "congestion_bps": self.congestion_bps,
            "aggregate_micro_fee_cap": self.aggregate_micro_fee_cap,
            "batch_rebate_micro_fee": self.batch_rebate_micro_fee,
            "pq_attestation_root": self.pq_attestation_root,
            "replay_nullifier_root": self.replay_nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubscriptionSettlement {
    pub settlement_id: String,
    pub subscription_id: String,
    pub batch_id: String,
    pub accepted_bid_root: String,
    pub accepted_bid_count: usize,
    pub settlement_height: u64,
    pub state_transition_root: String,
    pub public_state_root: String,
    pub operator_fee_micro: u64,
    pub user_rebate_micro: u64,
}

impl SubscriptionSettlement {
    pub fn from_input(
        config: &Config,
        input: SubscriptionSettlementInput,
        batch: &LowFeeBatch,
    ) -> Result<Self> {
        if input.subscription_id != batch.subscription_id || input.batch_id != batch.batch_id {
            return Err("settlement input does not match batch".to_string());
        }
        if input.accepted_bid_ids.is_empty() {
            return Err("settlement requires accepted bids".to_string());
        }
        let settlement_id = subscription_settlement_id(
            &input.subscription_id,
            &input.batch_id,
            input.settlement_height,
        );
        let accepted_bid_root = merkle_root(
            "sealed-event-subscription-fee-router-accepted-bid-id-root-v1",
            &input
                .accepted_bid_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        let operator_fee_micro = batch
            .aggregate_micro_fee_cap
            .saturating_mul(config.operator_fee_bps)
            .saturating_div(MAX_BPS);
        let user_rebate_micro = batch.batch_rebate_micro_fee;
        let public_state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-SUBSCRIPTION-FEE-ROUTER:SETTLEMENT-PUBLIC-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&settlement_id),
                HashPart::Str(&accepted_bid_root),
                HashPart::Str(&input.state_transition_root),
            ],
            32,
        );
        Ok(Self {
            settlement_id,
            subscription_id: input.subscription_id,
            batch_id: input.batch_id,
            accepted_bid_root,
            accepted_bid_count: input.accepted_bid_ids.len(),
            settlement_height: input.settlement_height,
            state_transition_root: input.state_transition_root,
            public_state_root,
            operator_fee_micro,
            user_rebate_micro,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "subscription_id": self.subscription_id,
            "batch_id": self.batch_id,
            "accepted_bid_root": self.accepted_bid_root,
            "accepted_bid_count": self.accepted_bid_count,
            "settlement_height": self.settlement_height,
            "state_transition_root": self.state_transition_root,
            "public_state_root": self.public_state_root,
            "operator_fee_micro": self.operator_fee_micro,
            "user_rebate_micro": self.user_rebate_micro,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicStateSnapshot {
    pub snapshot_id: String,
    pub subscription_id: String,
    pub height: u64,
    pub subscription_status: SubscriptionStatus,
    pub active_bid_count: usize,
    pub low_fee_batch_count: usize,
    pub public_state_root: String,
    pub privacy_budget_root: String,
}

impl PublicStateSnapshot {
    pub fn new(
        subscription: &SubscriptionWindow,
        active_bid_count: usize,
        low_fee_batch_count: usize,
        height: u64,
    ) -> Self {
        let snapshot_id = public_state_snapshot_id(&subscription.subscription_id, height);
        let privacy_budget_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-SUBSCRIPTION-FEE-ROUTER:PRIVACY-BUDGET",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&subscription.subscription_id),
                HashPart::U64(subscription.privacy_set_size),
                HashPart::U64(active_bid_count as u64),
            ],
            32,
        );
        let public_state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-SUBSCRIPTION-FEE-ROUTER:SNAPSHOT-PUBLIC-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&snapshot_id),
                HashPart::Json(&subscription.public_record()),
                HashPart::U64(low_fee_batch_count as u64),
            ],
            32,
        );
        Self {
            snapshot_id,
            subscription_id: subscription.subscription_id.clone(),
            height,
            subscription_status: subscription.status,
            active_bid_count,
            low_fee_batch_count,
            public_state_root,
            privacy_budget_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "subscription_id": self.subscription_id,
            "height": self.height,
            "subscription_status": self.subscription_status.as_str(),
            "active_bid_count": self.active_bid_count,
            "low_fee_batch_count": self.low_fee_batch_count,
            "public_state_root": self.public_state_root,
            "privacy_budget_root": self.privacy_budget_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub subscription_windows: Vec<SubscriptionWindow>,
    pub private_fee_bids: Vec<PrivateEventSubscriptionFeeBid>,
    pub event_subscription_commitments: Vec<EventSubscriptionCommitment>,
    pub pq_attestations: Vec<PqEventSubscriptionAttestation>,
    pub replay_nullifiers: Vec<ReplayNullifier>,
    pub low_fee_batches: Vec<LowFeeBatch>,
    pub subscription_settlements: Vec<SubscriptionSettlement>,
    pub public_state_snapshots: Vec<PublicStateSnapshot>,
}

impl State {
    pub fn devnet() -> Self {
        Self::demo()
    }

    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            subscription_windows: Vec::new(),
            private_fee_bids: Vec::new(),
            event_subscription_commitments: Vec::new(),
            pq_attestations: Vec::new(),
            replay_nullifiers: Vec::new(),
            low_fee_batches: Vec::new(),
            subscription_settlements: Vec::new(),
            public_state_snapshots: Vec::new(),
        };
        state.refresh_roots_and_counters();
        Ok(state)
    }

    pub fn demo() -> Self {
        let config = Config::devnet();
        let mut state = Self::new(config).expect("devnet config is valid");
        let subscription = SubscriptionWindow::from_input(
            &state.config,
            SubscriptionWindowInput {
                stream_family: EventStreamFamily::PqAttestedFeed,
                subscription_class: SubscriptionClass::LowFeeBatch,
                contract_id: demo_hash("router-demo-contract"),
                event_subscription_filter_commitment: demo_hash("pq-verify-filter"),
                epoch: DEVNET_EPOCH,
                start_height: DEVNET_HEIGHT,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            },
        )
        .expect("demo subscription is valid");
        state.subscription_windows.push(subscription.clone());

        let bid_inputs = [
            ("alpha", 8, 0),
            ("bravo", 7, 1),
            ("charlie", 6, 2),
            ("delta", 5, 3),
        ];
        for (label, fee, offset) in bid_inputs {
            let bid = PrivateEventSubscriptionFeeBid::from_input(
                &state.config,
                PrivateEventSubscriptionFeeBidInput {
                    subscription_id: subscription.subscription_id.clone(),
                    bidder_commitment: demo_hash(&format!("{label}-bidder")),
                    sealed_fee_bid_root: demo_hash(&format!("{label}-sealed-fee")),
                    max_micro_fee_per_event: fee,
                    event_count_commitment: demo_hash(&format!("{label}-event-count")),
                    submitted_height: DEVNET_HEIGHT + offset,
                    expiry_height: DEVNET_HEIGHT + DEFAULT_REPLAY_WINDOW_BLOCKS,
                },
            )
            .expect("demo bid is valid");
            state
                .replay_nullifiers
                .push(ReplayNullifier::from_bid(&state.config, &bid));
            state.private_fee_bids.push(bid);
        }

        let first_bid = state.private_fee_bids[0].clone();
        let commitment = EventSubscriptionCommitment::from_input(
            &state.config,
            PqEventSubscriptionCommitmentInput {
                subscription_id: subscription.subscription_id.clone(),
                bid_id: first_bid.bid_id.clone(),
                event_subscription_commitment_root: demo_hash("event-subscription-commitment-root"),
                transcript_root: demo_hash("event-subscription-transcript-root"),
                pq_public_key_commitment: demo_hash("pq-public-key-commitment"),
                height: DEVNET_HEIGHT + 6,
            },
        )
        .expect("demo commitment is valid");
        state
            .pq_attestations
            .push(PqEventSubscriptionAttestation::from_commitment(&commitment));
        state
            .event_subscription_commitments
            .push(commitment.clone());
        if let Some(bid) = state
            .private_fee_bids
            .iter_mut()
            .find(|bid| bid.bid_id == first_bid.bid_id)
        {
            bid.status = BidStatus::PqCommitted;
            bid.pq_commitment_id = Some(commitment.commitment_id.clone());
        }

        let bid_ids = state
            .private_fee_bids
            .iter()
            .map(|bid| bid.bid_id.clone())
            .collect::<Vec<_>>();
        let batch = LowFeeBatch::from_input(
            &state.config,
            LowFeeBatchInput {
                subscription_id: subscription.subscription_id.clone(),
                bid_ids: bid_ids.clone(),
                opened_height: DEVNET_HEIGHT + 8,
                congestion_bps: 4,
            },
            &state.private_fee_bids,
        )
        .expect("demo batch is valid");
        for bid in &mut state.private_fee_bids {
            if bid_ids.contains(&bid.bid_id) {
                bid.status = BidStatus::BatchQueued;
                bid.batch_id = Some(batch.batch_id.clone());
            }
        }
        state.low_fee_batches.push(batch.clone());

        let settlement = SubscriptionSettlement::from_input(
            &state.config,
            SubscriptionSettlementInput {
                subscription_id: subscription.subscription_id.clone(),
                batch_id: batch.batch_id.clone(),
                accepted_bid_ids: bid_ids,
                settlement_height: DEVNET_HEIGHT + 12,
                state_transition_root: demo_hash("event-subscription-router-transition-root"),
            },
            &batch,
        )
        .expect("demo settlement is valid");
        state.subscription_settlements.push(settlement);

        if let Some(subscription) = state.subscription_windows.first_mut() {
            subscription.status = SubscriptionStatus::Settled;
        }
        let snapshot = PublicStateSnapshot::new(
            state
                .subscription_windows
                .first()
                .expect("demo subscription exists"),
            0,
            state.low_fee_batches.len(),
            DEVNET_HEIGHT + 13,
        );
        state.public_state_snapshots.push(snapshot);
        state.refresh_roots_and_counters();
        state
    }

    pub fn refresh_roots_and_counters(&mut self) {
        self.counters = Counters {
            subscription_windows: self.subscription_windows.len() as u64,
            private_fee_bids: self.private_fee_bids.len() as u64,
            event_subscription_commitments: self.event_subscription_commitments.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            replay_nullifiers: self.replay_nullifiers.len() as u64,
            low_fee_batches: self.low_fee_batches.len() as u64,
            subscription_settlements: self.subscription_settlements.len() as u64,
            public_state_snapshots: self.public_state_snapshots.len() as u64,
            duplicate_replay_rejections: self.counters.duplicate_replay_rejections,
            repriced_bids: self
                .private_fee_bids
                .iter()
                .filter(|bid| bid.status == BidStatus::Repriced)
                .count() as u64,
        };
        self.roots = Roots {
            subscription_window_root: record_root(
                SUBSCRIPTION_WINDOW_SCHEME,
                &self
                    .subscription_windows
                    .iter()
                    .map(SubscriptionWindow::public_record)
                    .collect::<Vec<_>>(),
            ),
            private_fee_bid_root: record_root(
                PRIVATE_SUBSCRIPTION_FEE_BID_SCHEME,
                &self
                    .private_fee_bids
                    .iter()
                    .map(PrivateEventSubscriptionFeeBid::public_record)
                    .collect::<Vec<_>>(),
            ),
            event_subscription_commitment_root: record_root(
                SUBSCRIPTION_COMMITMENT_SCHEME,
                &self
                    .event_subscription_commitments
                    .iter()
                    .map(EventSubscriptionCommitment::public_record)
                    .collect::<Vec<_>>(),
            ),
            pq_attestation_root: record_root(
                PQ_ATTESTATION_SCHEME,
                &self
                    .pq_attestations
                    .iter()
                    .map(PqEventSubscriptionAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            replay_nullifier_root: record_root(
                REPLAY_NULLIFIER_SCHEME,
                &self
                    .replay_nullifiers
                    .iter()
                    .map(ReplayNullifier::public_record)
                    .collect::<Vec<_>>(),
            ),
            low_fee_batch_root: record_root(
                LOW_FEE_BATCH_SCHEME,
                &self
                    .low_fee_batches
                    .iter()
                    .map(LowFeeBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            subscription_settlement_root: record_root(
                SUBSCRIPTION_SETTLEMENT_SCHEME,
                &self
                    .subscription_settlements
                    .iter()
                    .map(SubscriptionSettlement::public_record)
                    .collect::<Vec<_>>(),
            ),
            public_state_snapshot_root: record_root(
                PUBLIC_STATE_SNAPSHOT_SCHEME,
                &self
                    .public_state_snapshots
                    .iter()
                    .map(PublicStateSnapshot::public_record)
                    .collect::<Vec<_>>(),
            ),
        };
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "suite": SEALED_EVENT_SUBSCRIPTION_FEE_ROUTER_SUITE,
            "private_event_subscription_fee_bid_suite": PRIVATE_SUBSCRIPTION_FEE_BID_SUITE,
            "pq_event_subscription_attestation_suite": PQ_EVENT_SUBSCRIPTION_ATTESTATION_SUITE,
            "low_fee_batching_suite": LOW_FEE_BATCHING_SUITE,
            "replay_resistance_suite": REPLAY_RESISTANCE_SUITE,
            "privacy_preserving_state_suite": PRIVACY_PRESERVING_STATE_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }
}

pub fn subscription_window_id(
    stream_family: EventStreamFamily,
    subscription_class: SubscriptionClass,
    contract_id: &str,
    event_subscription_filter_commitment: &str,
    epoch: u64,
    start_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-SUBSCRIPTION-FEE-ROUTER:ROUTE-EPOCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(stream_family.as_str()),
            HashPart::Str(subscription_class.as_str()),
            HashPart::Str(contract_id),
            HashPart::Str(event_subscription_filter_commitment),
            HashPart::U64(epoch),
            HashPart::U64(start_height),
        ],
        32,
    )
}

pub fn private_event_subscription_fee_bid_id(
    subscription_id: &str,
    bidder_commitment: &str,
    sealed_fee_bid_root: &str,
    submitted_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-SUBSCRIPTION-FEE-ROUTER:BID-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subscription_id),
            HashPart::Str(bidder_commitment),
            HashPart::Str(sealed_fee_bid_root),
            HashPart::U64(submitted_height),
        ],
        32,
    )
}

pub fn event_subscription_commitment_id(
    subscription_id: &str,
    bid_id: &str,
    event_subscription_commitment_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-SUBSCRIPTION-FEE-ROUTER:COMMITMENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subscription_id),
            HashPart::Str(bid_id),
            HashPart::Str(event_subscription_commitment_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn pq_event_subscription_attestation_id(
    commitment_id: &str,
    subscription_id: &str,
    bid_id: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-SUBSCRIPTION-FEE-ROUTER:PQ-ATTESTATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(commitment_id),
            HashPart::Str(subscription_id),
            HashPart::Str(bid_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn replay_nullifier_id(
    subscription_id: &str,
    bid_id: &str,
    bidder_commitment: &str,
    sealed_fee_bid_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-SUBSCRIPTION-FEE-ROUTER:REPLAY-NULLIFIER-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subscription_id),
            HashPart::Str(bid_id),
            HashPart::Str(bidder_commitment),
            HashPart::Str(sealed_fee_bid_root),
        ],
        32,
    )
}

pub fn low_fee_batch_id(subscription_id: &str, bid_ids: &[String], opened_height: u64) -> String {
    let bid_root = merkle_root(
        "sealed-event-subscription-fee-router-low-fee-batch-id-root-v1",
        &bid_ids.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-SUBSCRIPTION-FEE-ROUTER:LOW-FEE-BATCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subscription_id),
            HashPart::Str(&bid_root),
            HashPart::U64(opened_height),
        ],
        32,
    )
}

pub fn subscription_settlement_id(subscription_id: &str, batch_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-SUBSCRIPTION-FEE-ROUTER:SETTLEMENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subscription_id),
            HashPart::Str(batch_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn public_state_snapshot_id(subscription_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-SUBSCRIPTION-FEE-ROUTER:PUBLIC-STATE-SNAPSHOT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subscription_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn effective_micro_fee_cap(
    config: &Config,
    bid: &PrivateEventSubscriptionFeeBid,
    congestion_bps: u64,
) -> u64 {
    let congestion = congestion_bps.min(config.congestion_surcharge_bps);
    let surcharge = bid
        .max_micro_fee_per_event
        .saturating_mul(congestion)
        .saturating_div(MAX_BPS);
    bid.max_micro_fee_per_event.saturating_add(surcharge)
}

pub fn privacy_preserving_public_state_root(
    subscription: &SubscriptionWindow,
    settlement: Option<&SubscriptionSettlement>,
    snapshot: Option<&PublicStateSnapshot>,
) -> String {
    let settlement_record = settlement
        .map(SubscriptionSettlement::public_record)
        .unwrap_or(Value::Null);
    let snapshot_record = snapshot
        .map(PublicStateSnapshot::public_record)
        .unwrap_or(Value::Null);
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-SUBSCRIPTION-FEE-ROUTER:PUBLIC-STATE-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&subscription.public_record()),
            HashPart::Json(&settlement_record),
            HashPart::Json(&snapshot_record),
        ],
        32,
    )
}

pub fn record_root(scheme: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .map(|record| {
            domain_hash(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-SUBSCRIPTION-FEE-ROUTER:RECORD-LEAF",
                &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
                32,
            )
        })
        .collect::<Vec<_>>();
    merkle_root(
        scheme,
        &leaves.iter().map(String::as_str).collect::<Vec<_>>(),
    )
}

pub fn empty_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-SUBSCRIPTION-FEE-ROUTER:EMPTY-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-SUBSCRIPTION-FEE-ROUTER:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
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

fn demo_hash(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-SUBSCRIPTION-FEE-ROUTER:DEMO-HASH",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}
