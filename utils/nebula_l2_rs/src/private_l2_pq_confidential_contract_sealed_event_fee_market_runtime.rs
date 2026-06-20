use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedEventFeeMarketRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractSealedEventFeeMarketRuntimeResult<T>;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_EVENT_FEE_MARKET_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-sealed-event-fee-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_EVENT_FEE_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEALED_EVENT_FEE_MARKET_SUITE: &str =
    "sealed-confidential-smart-contract-event-fee-market-v1";
pub const PRIVATE_EVENT_FEE_BID_SUITE: &str = "private-event-fee-bid-commitment-v1";
pub const PQ_EVENT_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-event-commitment-attestation-v1";
pub const LOW_FEE_BATCHING_SUITE: &str = "low-fee-confidential-event-log-batching-v1";
pub const REPLAY_RESISTANCE_SUITE: &str = "sealed-event-fee-market-replay-nullifier-v1";
pub const PRIVACY_PRESERVING_STATE_SUITE: &str =
    "privacy-preserving-event-fee-market-public-state-root-v1";
pub const EVENT_WINDOW_SCHEME: &str = "sealed-contract-event-window-root-v1";
pub const PRIVATE_EVENT_BID_SCHEME: &str = "private-contract-event-fee-bid-root-v1";
pub const EVENT_COMMITMENT_SCHEME: &str = "pq-attested-contract-event-commitment-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str = "pq-contract-event-attestation-root-v1";
pub const REPLAY_NULLIFIER_SCHEME: &str = "sealed-contract-event-replay-nullifier-root-v1";
pub const LOW_FEE_BATCH_SCHEME: &str = "low-fee-contract-event-batch-root-v1";
pub const EVENT_SETTLEMENT_SCHEME: &str = "sealed-contract-event-settlement-root-v1";
pub const PUBLIC_STATE_SNAPSHOT_SCHEME: &str =
    "privacy-preserving-contract-event-state-snapshot-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_356_416;
pub const DEVNET_EPOCH: u64 = 10_463;
pub const DEFAULT_EVENT_WINDOW_BLOCKS: u64 = 48;
pub const DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 128;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_BIDS_PER_WINDOW: usize = 16_384;
pub const DEFAULT_MAX_EVENTS_PER_BID: u64 = 32_768;
pub const DEFAULT_MAX_COMMITMENTS_PER_BATCH: usize = 4_096;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 3;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 6;
pub const DEFAULT_CONGESTION_SURCHARGE_BPS: u64 = 10;
pub const DEFAULT_BASE_EVENT_MICRO_FEE: u64 = 4;
pub const DEFAULT_MIN_EVENT_MICRO_FEE: u64 = 1;
pub const DEFAULT_MAX_EVENT_BYTES_PER_BATCH: u64 = 8_388_608;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventClass {
    ContractLog,
    ConfidentialTransfer,
    OracleEmission,
    BridgeReceipt,
    GovernanceSignal,
    VaultMutation,
    AccountRecovery,
    EmergencyNotice,
}

impl EventClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractLog => "contract_log",
            Self::ConfidentialTransfer => "confidential_transfer",
            Self::OracleEmission => "oracle_emission",
            Self::BridgeReceipt => "bridge_receipt",
            Self::GovernanceSignal => "governance_signal",
            Self::VaultMutation => "vault_mutation",
            Self::AccountRecovery => "account_recovery",
            Self::EmergencyNotice => "emergency_notice",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyNotice => 10_000,
            Self::AccountRecovery => 9_600,
            Self::BridgeReceipt => 9_100,
            Self::OracleEmission => 8_700,
            Self::VaultMutation => 8_300,
            Self::ConfidentialTransfer => 7_900,
            Self::GovernanceSignal => 7_300,
            Self::ContractLog => 6_800,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventWindowStatus {
    Announced,
    CommitOpen,
    PqAttested,
    BatchReady,
    Settling,
    Settled,
    Cancelled,
    Expired,
}

impl EventWindowStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Announced
                | Self::CommitOpen
                | Self::PqAttested
                | Self::BatchReady
                | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Sealed,
    ReplayGuarded,
    PqCommitted,
    BatchQueued,
    Accepted,
    Repriced,
    Outbid,
    Refunded,
    DuplicateRejected,
    Expired,
}

impl BidStatus {
    pub fn pending(self) -> bool {
        matches!(
            self,
            Self::Sealed
                | Self::ReplayGuarded
                | Self::PqCommitted
                | Self::BatchQueued
                | Self::Repriced
        )
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
    pub fn authenticated(self) -> bool {
        matches!(
            self,
            Self::Authenticated | Self::QuorumSigned | Self::Applied
        )
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    PqAttested,
    Settled,
    Repriced,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub sealed_event_fee_market_suite: String,
    pub private_event_fee_bid_suite: String,
    pub pq_event_attestation_suite: String,
    pub low_fee_batching_suite: String,
    pub replay_resistance_suite: String,
    pub privacy_preserving_state_suite: String,
    pub event_window_blocks: u64,
    pub replay_window_blocks: u64,
    pub batch_window_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_bids_per_window: usize,
    pub max_events_per_bid: u64,
    pub max_commitments_per_batch: usize,
    pub operator_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub congestion_surcharge_bps: u64,
    pub base_event_micro_fee: u64,
    pub min_event_micro_fee: u64,
    pub max_event_bytes_per_batch: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            sealed_event_fee_market_suite: SEALED_EVENT_FEE_MARKET_SUITE.to_string(),
            private_event_fee_bid_suite: PRIVATE_EVENT_FEE_BID_SUITE.to_string(),
            pq_event_attestation_suite: PQ_EVENT_ATTESTATION_SUITE.to_string(),
            low_fee_batching_suite: LOW_FEE_BATCHING_SUITE.to_string(),
            replay_resistance_suite: REPLAY_RESISTANCE_SUITE.to_string(),
            privacy_preserving_state_suite: PRIVACY_PRESERVING_STATE_SUITE.to_string(),
            event_window_blocks: DEFAULT_EVENT_WINDOW_BLOCKS,
            replay_window_blocks: DEFAULT_REPLAY_WINDOW_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_bids_per_window: DEFAULT_MAX_BIDS_PER_WINDOW,
            max_events_per_bid: DEFAULT_MAX_EVENTS_PER_BID,
            max_commitments_per_batch: DEFAULT_MAX_COMMITMENTS_PER_BATCH,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            congestion_surcharge_bps: DEFAULT_CONGESTION_SURCHARGE_BPS,
            base_event_micro_fee: DEFAULT_BASE_EVENT_MICRO_FEE,
            min_event_micro_fee: DEFAULT_MIN_EVENT_MICRO_FEE,
            max_event_bytes_per_batch: DEFAULT_MAX_EVENT_BYTES_PER_BATCH,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("event fee market protocol version mismatch".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("event fee market schema version mismatch".to_string());
        }
        if self.event_window_blocks == 0
            || self.replay_window_blocks == 0
            || self.batch_window_blocks == 0
        {
            return Err("event fee market windows must be non-zero".to_string());
        }
        if self.replay_window_blocks < self.event_window_blocks {
            return Err("event replay window must cover event window".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("event commitment pq security bits below floor".to_string());
        }
        if self.min_privacy_set_size < DEFAULT_MIN_PRIVACY_SET_SIZE {
            return Err("event privacy set below floor".to_string());
        }
        if self.max_bids_per_window == 0
            || self.max_events_per_bid == 0
            || self.max_commitments_per_batch == 0
            || self.max_event_bytes_per_batch == 0
        {
            return Err("event bid and batch limits must be non-zero".to_string());
        }
        if self.operator_fee_bps > MAX_BPS
            || self.batch_rebate_bps > MAX_BPS
            || self.congestion_surcharge_bps > MAX_BPS
        {
            return Err("event fee market basis points exceed MAX_BPS".to_string());
        }
        if self.base_event_micro_fee < self.min_event_micro_fee {
            return Err("base event micro fee below configured event floor".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub event_windows: u64,
    pub active_event_windows: u64,
    pub private_event_fee_bids: u64,
    pub pending_private_event_fee_bids: u64,
    pub accepted_private_event_fee_bids: u64,
    pub event_commitments: u64,
    pub applied_event_commitments: u64,
    pub pq_attestations: u64,
    pub authenticated_pq_attestations: u64,
    pub replay_nullifiers: u64,
    pub consumed_replay_nullifiers: u64,
    pub duplicate_replay_nullifiers: u64,
    pub low_fee_batches: u64,
    pub settled_low_fee_batches: u64,
    pub event_settlements: u64,
    pub public_state_snapshots: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub event_window_root: String,
    pub private_event_bid_root: String,
    pub event_commitment_root: String,
    pub pq_attestation_root: String,
    pub replay_nullifier_root: String,
    pub low_fee_batch_root: String,
    pub event_settlement_root: String,
    pub public_state_snapshot_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            event_window_root: merkle_root(EVENT_WINDOW_SCHEME, &[]),
            private_event_bid_root: merkle_root(PRIVATE_EVENT_BID_SCHEME, &[]),
            event_commitment_root: merkle_root(EVENT_COMMITMENT_SCHEME, &[]),
            pq_attestation_root: merkle_root(PQ_ATTESTATION_SCHEME, &[]),
            replay_nullifier_root: merkle_root(REPLAY_NULLIFIER_SCHEME, &[]),
            low_fee_batch_root: merkle_root(LOW_FEE_BATCH_SCHEME, &[]),
            event_settlement_root: merkle_root(EVENT_SETTLEMENT_SCHEME, &[]),
            public_state_snapshot_root: merkle_root(PUBLIC_STATE_SNAPSHOT_SCHEME, &[]),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct EventWindowInput {
    pub event_class: EventClass,
    pub contract_id: String,
    pub event_topic_commitment: String,
    pub prior_state_root: String,
    pub target_state_root: String,
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub capacity_events: u64,
    pub reserve_micro_fee_per_event: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivateEventFeeBidInput {
    pub window_id: String,
    pub bidder_commitment: String,
    pub sealed_fee_bid_root: String,
    pub sealed_event_filter_root: String,
    pub event_payload_commitment_root: String,
    pub max_micro_fee_per_event: u64,
    pub event_count_commitment: String,
    pub event_byte_count_commitment: String,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqEventCommitmentInput {
    pub window_id: String,
    pub bid_id: String,
    pub event_commitment_root: String,
    pub transcript_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub predecessor_state_root: String,
    pub successor_state_root: String,
    pub pq_security_bits: u16,
    pub attested_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LowFeeEventBatchInput {
    pub window_id: String,
    pub operator_commitment: String,
    pub batch_epoch: u64,
    pub bid_ids: Vec<String>,
    pub opened_height: u64,
    pub congestion_bps: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct EventSettlementInput {
    pub window_id: String,
    pub batch_id: String,
    pub accepted_bid_ids: Vec<String>,
    pub settlement_height: u64,
    pub event_log_root: String,
    pub fee_distribution_root: String,
    pub post_state_root: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct EventWindow {
    pub window_id: String,
    pub event_class: EventClass,
    pub contract_id: String,
    pub event_topic_commitment: String,
    pub prior_state_root: String,
    pub target_state_root: String,
    pub bid_commitment_root: String,
    pub event_commitment_root: String,
    pub pq_attestation_root: String,
    pub replay_nullifier_root: String,
    pub public_state_root: String,
    pub epoch: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub capacity_events: u64,
    pub reserve_micro_fee_per_event: u64,
    pub clearing_micro_fee_per_event: Option<u64>,
    pub privacy_set_size: u64,
    pub priority_weight: u64,
    pub status: EventWindowStatus,
}

impl EventWindow {
    pub fn from_input(config: &Config, input: EventWindowInput) -> Result<Self> {
        config.validate()?;
        if input.contract_id.is_empty() {
            return Err("event window contract id must be non-empty".to_string());
        }
        if input.event_topic_commitment.is_empty() {
            return Err("event topic commitment must be non-empty".to_string());
        }
        if input.end_height <= input.start_height {
            return Err("event window end height must exceed start height".to_string());
        }
        if input.end_height - input.start_height > config.event_window_blocks {
            return Err("event window exceeds configured window".to_string());
        }
        if input.capacity_events == 0 {
            return Err("event window capacity must be non-zero".to_string());
        }
        if input.reserve_micro_fee_per_event < config.min_event_micro_fee {
            return Err("event reserve fee below configured floor".to_string());
        }
        if input.privacy_set_size < config.min_privacy_set_size {
            return Err("event window privacy set below configured floor".to_string());
        }
        let window_id = event_window_id(
            input.event_class,
            &input.contract_id,
            &input.event_topic_commitment,
            input.epoch,
            input.start_height,
        );
        let public_state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-FEE-MARKET:WINDOW-PUBLIC-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&window_id),
                HashPart::Str(&input.prior_state_root),
                HashPart::Str(&input.target_state_root),
                HashPart::U64(input.privacy_set_size),
            ],
            32,
        );
        Ok(Self {
            window_id,
            event_class: input.event_class,
            contract_id: input.contract_id,
            event_topic_commitment: input.event_topic_commitment,
            prior_state_root: input.prior_state_root,
            target_state_root: input.target_state_root,
            bid_commitment_root: merkle_root(PRIVATE_EVENT_BID_SCHEME, &[]),
            event_commitment_root: merkle_root(EVENT_COMMITMENT_SCHEME, &[]),
            pq_attestation_root: merkle_root(PQ_ATTESTATION_SCHEME, &[]),
            replay_nullifier_root: merkle_root(REPLAY_NULLIFIER_SCHEME, &[]),
            public_state_root,
            epoch: input.epoch,
            start_height: input.start_height,
            end_height: input.end_height,
            capacity_events: input.capacity_events,
            reserve_micro_fee_per_event: input.reserve_micro_fee_per_event,
            clearing_micro_fee_per_event: None,
            privacy_set_size: input.privacy_set_size,
            priority_weight: input.event_class.priority_weight(),
            status: EventWindowStatus::CommitOpen,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivateEventFeeBid {
    pub bid_id: String,
    pub window_id: String,
    pub bidder_commitment: String,
    pub sealed_fee_bid_root: String,
    pub sealed_event_filter_root: String,
    pub event_payload_commitment_root: String,
    pub replay_nullifier_id: String,
    pub max_micro_fee_per_event: u64,
    pub event_count_commitment: String,
    pub event_byte_count_commitment: String,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub privacy_set_size: u64,
    pub status: BidStatus,
    pub pq_commitment_id: Option<String>,
    pub batch_id: Option<String>,
}

impl PrivateEventFeeBid {
    pub fn from_input(config: &Config, input: PrivateEventFeeBidInput) -> Result<Self> {
        config.validate()?;
        if input.window_id.is_empty()
            || input.bidder_commitment.is_empty()
            || input.sealed_fee_bid_root.is_empty()
            || input.sealed_event_filter_root.is_empty()
            || input.event_payload_commitment_root.is_empty()
        {
            return Err("event bid commitments must be non-empty".to_string());
        }
        if input.expires_height <= input.submitted_height {
            return Err("event bid expiry must exceed submitted height".to_string());
        }
        if input.expires_height - input.submitted_height > config.replay_window_blocks {
            return Err("event bid expiry exceeds replay window".to_string());
        }
        if input.max_micro_fee_per_event < config.min_event_micro_fee {
            return Err("event bid fee cap below configured floor".to_string());
        }
        if input.privacy_set_size < config.min_privacy_set_size {
            return Err("event bid privacy set below configured floor".to_string());
        }
        let bid_id = private_event_fee_bid_id(
            &input.window_id,
            &input.bidder_commitment,
            &input.sealed_fee_bid_root,
            input.submitted_height,
        );
        let replay_nullifier_id = replay_nullifier_id(
            &input.window_id,
            &bid_id,
            &input.bidder_commitment,
            &input.sealed_fee_bid_root,
        );
        Ok(Self {
            bid_id,
            window_id: input.window_id,
            bidder_commitment: input.bidder_commitment,
            sealed_fee_bid_root: input.sealed_fee_bid_root,
            sealed_event_filter_root: input.sealed_event_filter_root,
            event_payload_commitment_root: input.event_payload_commitment_root,
            replay_nullifier_id,
            max_micro_fee_per_event: input.max_micro_fee_per_event,
            event_count_commitment: input.event_count_commitment,
            event_byte_count_commitment: input.event_byte_count_commitment,
            submitted_height: input.submitted_height,
            expires_height: input.expires_height,
            privacy_set_size: input.privacy_set_size,
            status: BidStatus::Sealed,
            pq_commitment_id: None,
            batch_id: None,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct EventCommitment {
    pub commitment_id: String,
    pub window_id: String,
    pub bid_id: String,
    pub event_commitment_root: String,
    pub transcript_root: String,
    pub pq_public_key_root: String,
    pub predecessor_state_root: String,
    pub successor_state_root: String,
    pub status: CommitmentStatus,
    pub pq_security_bits: u16,
    pub attested_height: u64,
}

impl EventCommitment {
    pub fn from_input(config: &Config, input: PqEventCommitmentInput) -> Result<Self> {
        config.validate()?;
        if input.window_id.is_empty()
            || input.bid_id.is_empty()
            || input.event_commitment_root.is_empty()
            || input.transcript_root.is_empty()
            || input.pq_public_key_root.is_empty()
        {
            return Err("event commitment inputs must be non-empty".to_string());
        }
        if input.pq_security_bits < config.min_pq_security_bits {
            return Err("event commitment pq security below configured floor".to_string());
        }
        let commitment_id = event_commitment_id(
            &input.window_id,
            &input.bid_id,
            &input.event_commitment_root,
            input.attested_height,
        );
        Ok(Self {
            commitment_id,
            window_id: input.window_id,
            bid_id: input.bid_id,
            event_commitment_root: input.event_commitment_root,
            transcript_root: input.transcript_root,
            pq_public_key_root: input.pq_public_key_root,
            predecessor_state_root: input.predecessor_state_root,
            successor_state_root: input.successor_state_root,
            status: CommitmentStatus::Authenticated,
            pq_security_bits: input.pq_security_bits,
            attested_height: input.attested_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqEventAttestation {
    pub attestation_id: String,
    pub commitment_id: String,
    pub window_id: String,
    pub bid_id: String,
    pub event_commitment_root: String,
    pub transcript_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub min_pq_security_bits: u16,
    pub status: CommitmentStatus,
    pub authenticated_height: u64,
}

impl PqEventAttestation {
    pub fn from_commitment(input: &PqEventCommitmentInput, commitment: &EventCommitment) -> Self {
        Self {
            attestation_id: pq_event_attestation_id(
                &commitment.commitment_id,
                &commitment.window_id,
                &commitment.bid_id,
                commitment.attested_height,
            ),
            commitment_id: commitment.commitment_id.clone(),
            window_id: commitment.window_id.clone(),
            bid_id: commitment.bid_id.clone(),
            event_commitment_root: commitment.event_commitment_root.clone(),
            transcript_root: commitment.transcript_root.clone(),
            pq_public_key_root: commitment.pq_public_key_root.clone(),
            pq_signature_root: input.pq_signature_root.clone(),
            min_pq_security_bits: commitment.pq_security_bits,
            status: CommitmentStatus::QuorumSigned,
            authenticated_height: commitment.attested_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReplayNullifier {
    pub nullifier_id: String,
    pub window_id: String,
    pub bid_id: String,
    pub bidder_commitment: String,
    pub sealed_fee_bid_root: String,
    pub epoch_root: String,
    pub status: ReplayStatus,
    pub armed_height: u64,
    pub expires_height: u64,
    pub consumed_height: Option<u64>,
}

impl ReplayNullifier {
    pub fn from_bid(config: &Config, bid: &PrivateEventFeeBid) -> Self {
        Self {
            nullifier_id: bid.replay_nullifier_id.clone(),
            window_id: bid.window_id.clone(),
            bid_id: bid.bid_id.clone(),
            bidder_commitment: bid.bidder_commitment.clone(),
            sealed_fee_bid_root: bid.sealed_fee_bid_root.clone(),
            epoch_root: deterministic_root(
                "event-replay-epoch",
                &bid.window_id,
                bid.submitted_height,
            ),
            status: ReplayStatus::Armed,
            armed_height: bid.submitted_height,
            expires_height: bid
                .submitted_height
                .saturating_add(config.replay_window_blocks),
            consumed_height: None,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LowFeeEventBatch {
    pub batch_id: String,
    pub window_id: String,
    pub operator_commitment: String,
    pub batch_epoch: u64,
    pub bid_root: String,
    pub event_commitment_root: String,
    pub replay_nullifier_root: String,
    pub aggregate_micro_fee_cap: u64,
    pub estimated_event_count: u64,
    pub estimated_event_bytes: u64,
    pub congestion_bps: u64,
    pub operator_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub status: BatchStatus,
    pub opened_height: u64,
    pub sealed_height: u64,
}

impl LowFeeEventBatch {
    pub fn from_input(
        config: &Config,
        input: LowFeeEventBatchInput,
        bids: &BTreeMap<String, PrivateEventFeeBid>,
    ) -> Result<Self> {
        config.validate()?;
        if input.bid_ids.is_empty() {
            return Err("low-fee event batch must include bids".to_string());
        }
        if input.bid_ids.len() > config.max_commitments_per_batch {
            return Err("low-fee event batch exceeds commitment cap".to_string());
        }
        if input.congestion_bps > config.congestion_surcharge_bps {
            return Err("low-fee event batch congestion exceeds cap".to_string());
        }
        let mut seen = BTreeSet::new();
        let mut aggregate_micro_fee_cap = 0u64;
        let mut estimated_event_count = 0u64;
        let mut estimated_event_bytes = 0u64;
        let mut commitment_leaves = Vec::new();
        let mut replay_leaves = Vec::new();
        for bid_id in &input.bid_ids {
            if !seen.insert(bid_id.clone()) {
                return Err("low-fee event batch contains duplicate bid id".to_string());
            }
            let bid = bids
                .get(bid_id)
                .ok_or_else(|| "low-fee event batch references unknown bid".to_string())?;
            if bid.window_id != input.window_id {
                return Err("low-fee event batch mixes event windows".to_string());
            }
            aggregate_micro_fee_cap = aggregate_micro_fee_cap
                .saturating_add(effective_micro_fee_cap(config, bid, input.congestion_bps));
            let count =
                estimate_event_count(&bid.event_count_commitment, config.max_events_per_bid);
            let bytes = estimate_event_bytes(&bid.event_byte_count_commitment);
            estimated_event_count = estimated_event_count.saturating_add(count);
            estimated_event_bytes = estimated_event_bytes.saturating_add(bytes);
            commitment_leaves.push(json!({
                "bid_id": bid.bid_id,
                "event_payload_commitment_root": bid.event_payload_commitment_root,
            }));
            replay_leaves.push(json!(bid.replay_nullifier_id));
        }
        if estimated_event_bytes > config.max_event_bytes_per_batch {
            return Err("low-fee event batch exceeds event byte cap".to_string());
        }
        let batch_id = low_fee_event_batch_id(
            &input.window_id,
            &input.operator_commitment,
            input.batch_epoch,
            input.opened_height,
        );
        Ok(Self {
            batch_id,
            window_id: input.window_id,
            operator_commitment: input.operator_commitment,
            batch_epoch: input.batch_epoch,
            bid_root: root_for_values(
                "low-fee-event-batch-bid-root-v1",
                &bid_ids_to_values(&input.bid_ids),
            ),
            event_commitment_root: root_for_values(EVENT_COMMITMENT_SCHEME, &commitment_leaves),
            replay_nullifier_root: root_for_values(REPLAY_NULLIFIER_SCHEME, &replay_leaves),
            aggregate_micro_fee_cap,
            estimated_event_count,
            estimated_event_bytes,
            congestion_bps: input.congestion_bps,
            operator_fee_bps: config.operator_fee_bps,
            batch_rebate_bps: config.batch_rebate_bps,
            status: BatchStatus::Sealed,
            opened_height: input.opened_height,
            sealed_height: input
                .opened_height
                .saturating_add(config.batch_window_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct EventSettlement {
    pub settlement_id: String,
    pub window_id: String,
    pub batch_id: String,
    pub accepted_bid_root: String,
    pub event_log_root: String,
    pub fee_distribution_root: String,
    pub replay_nullifier_root: String,
    pub public_state_root: String,
    pub aggregate_micro_fee_cap: u64,
    pub operator_fee_micro: u64,
    pub user_rebate_micro: u64,
    pub settlement_height: u64,
    pub post_state_root: String,
}

impl EventSettlement {
    pub fn from_input(
        config: &Config,
        input: EventSettlementInput,
        batch: &LowFeeEventBatch,
    ) -> Result<Self> {
        config.validate()?;
        if input.window_id != batch.window_id || input.batch_id != batch.batch_id {
            return Err("event settlement does not match low-fee batch".to_string());
        }
        if input.accepted_bid_ids.is_empty() {
            return Err("event settlement requires accepted bids".to_string());
        }
        let accepted_bid_root = root_for_values(
            "event-settlement-accepted-bid-root-v1",
            &bid_ids_to_values(&input.accepted_bid_ids),
        );
        let operator_fee_micro = batch
            .aggregate_micro_fee_cap
            .saturating_mul(config.operator_fee_bps)
            .saturating_div(MAX_BPS);
        let user_rebate_micro = batch
            .aggregate_micro_fee_cap
            .saturating_mul(config.batch_rebate_bps)
            .saturating_div(MAX_BPS);
        let settlement_id =
            event_settlement_id(&input.window_id, &input.batch_id, input.settlement_height);
        let public_state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-FEE-MARKET:SETTLEMENT-PUBLIC-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&settlement_id),
                HashPart::Str(&accepted_bid_root),
                HashPart::Str(&input.event_log_root),
                HashPart::Str(&input.post_state_root),
            ],
            32,
        );
        Ok(Self {
            settlement_id,
            window_id: input.window_id,
            batch_id: input.batch_id,
            accepted_bid_root,
            event_log_root: input.event_log_root,
            fee_distribution_root: input.fee_distribution_root,
            replay_nullifier_root: batch.replay_nullifier_root.clone(),
            public_state_root,
            aggregate_micro_fee_cap: batch.aggregate_micro_fee_cap,
            operator_fee_micro,
            user_rebate_micro,
            settlement_height: input.settlement_height,
            post_state_root: input.post_state_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PublicStateSnapshot {
    pub snapshot_id: String,
    pub window_id: String,
    pub height: u64,
    pub event_window_status: EventWindowStatus,
    pub active_bid_count: usize,
    pub low_fee_batch_count: usize,
    pub public_state_root: String,
    pub redaction_root: String,
}

impl PublicStateSnapshot {
    pub fn new(
        window: &EventWindow,
        active_bid_count: usize,
        low_fee_batch_count: usize,
        height: u64,
    ) -> Self {
        let snapshot_id = public_state_snapshot_id(&window.window_id, height);
        let redaction_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-FEE-MARKET:SNAPSHOT-REDACTION",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&window.window_id),
                HashPart::U64(window.privacy_set_size),
                HashPart::U64(active_bid_count as u64),
            ],
            32,
        );
        let public_state_root = domain_hash(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-FEE-MARKET:SNAPSHOT-PUBLIC-STATE",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&snapshot_id),
                HashPart::Json(&window.public_record()),
                HashPart::U64(low_fee_batch_count as u64),
            ],
            32,
        );
        Self {
            snapshot_id,
            window_id: window.window_id.clone(),
            height,
            event_window_status: window.status,
            active_bid_count,
            low_fee_batch_count,
            public_state_root,
            redaction_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub event_windows: BTreeMap<String, EventWindow>,
    pub private_event_fee_bids: BTreeMap<String, PrivateEventFeeBid>,
    pub event_commitments: BTreeMap<String, EventCommitment>,
    pub pq_attestations: BTreeMap<String, PqEventAttestation>,
    pub replay_nullifiers: BTreeMap<String, ReplayNullifier>,
    pub low_fee_batches: BTreeMap<String, LowFeeEventBatch>,
    pub event_settlements: BTreeMap<String, EventSettlement>,
    pub public_state_snapshots: BTreeMap<String, PublicStateSnapshot>,
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
            event_windows: BTreeMap::new(),
            private_event_fee_bids: BTreeMap::new(),
            event_commitments: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            replay_nullifiers: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            event_settlements: BTreeMap::new(),
            public_state_snapshots: BTreeMap::new(),
        };
        state.recompute_counters();
        state.recompute_roots();
        Ok(state)
    }

    pub fn demo() -> Self {
        let config = Config::devnet();
        let mut state = Self::new(config).expect("devnet event fee market config is valid");
        let window = EventWindow::from_input(
            &state.config,
            EventWindowInput {
                event_class: EventClass::ConfidentialTransfer,
                contract_id: deterministic_root("contract", "sealed-event-vault", 0),
                event_topic_commitment: deterministic_root("topic", "transfer-event", 0),
                prior_state_root: deterministic_root("prior-state", "sealed-event-vault", 0),
                target_state_root: deterministic_root("target-state", "sealed-event-vault", 1),
                epoch: DEVNET_EPOCH,
                start_height: DEVNET_HEIGHT,
                end_height: DEVNET_HEIGHT + DEFAULT_EVENT_WINDOW_BLOCKS,
                capacity_events: 196_608,
                reserve_micro_fee_per_event: DEFAULT_BASE_EVENT_MICRO_FEE,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            },
        )
        .expect("demo event window is valid");
        let window_id = window.window_id.clone();
        state
            .event_windows
            .insert(window.window_id.clone(), window.clone());

        for (label, fee, offset) in [
            ("alpha", 5, 0),
            ("bravo", 4, 1),
            ("charlie", 3, 2),
            ("delta", 2, 3),
        ] {
            let bid = PrivateEventFeeBid::from_input(
                &state.config,
                PrivateEventFeeBidInput {
                    window_id: window_id.clone(),
                    bidder_commitment: deterministic_root("bidder", label, 0),
                    sealed_fee_bid_root: deterministic_root("sealed-fee-bid", label, 0),
                    sealed_event_filter_root: deterministic_root("sealed-event-filter", label, 0),
                    event_payload_commitment_root: deterministic_root("event-payload", label, 0),
                    max_micro_fee_per_event: fee,
                    event_count_commitment: deterministic_root("event-count", label, 0),
                    event_byte_count_commitment: deterministic_root("event-bytes", label, 0),
                    submitted_height: DEVNET_HEIGHT + offset,
                    expires_height: DEVNET_HEIGHT + DEFAULT_REPLAY_WINDOW_BLOCKS,
                    privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                },
            )
            .expect("demo private event fee bid is valid");
            let replay = ReplayNullifier::from_bid(&state.config, &bid);
            state
                .replay_nullifiers
                .insert(replay.nullifier_id.clone(), replay);
            state.private_event_fee_bids.insert(bid.bid_id.clone(), bid);
        }

        let first_bid = state
            .private_event_fee_bids
            .values()
            .next()
            .expect("demo bid exists")
            .clone();
        let commitment_input = PqEventCommitmentInput {
            window_id: window_id.clone(),
            bid_id: first_bid.bid_id.clone(),
            event_commitment_root: deterministic_root("event-commitment", "alpha", 0),
            transcript_root: deterministic_root("pq-transcript", "alpha", 0),
            pq_public_key_root: deterministic_root("pq-public-key", "event-operator", 0),
            pq_signature_root: deterministic_root("pq-signature", "event-operator", 0),
            predecessor_state_root: deterministic_root(
                "predecessor-state",
                "sealed-event-vault",
                0,
            ),
            successor_state_root: deterministic_root("successor-state", "sealed-event-vault", 1),
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            attested_height: DEVNET_HEIGHT + 6,
        };
        let commitment = EventCommitment::from_input(&state.config, commitment_input.clone())
            .expect("demo event commitment is valid");
        let attestation = PqEventAttestation::from_commitment(&commitment_input, &commitment);
        state
            .pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        state
            .event_commitments
            .insert(commitment.commitment_id.clone(), commitment.clone());
        if let Some(bid) = state.private_event_fee_bids.get_mut(&first_bid.bid_id) {
            bid.status = BidStatus::PqCommitted;
            bid.pq_commitment_id = Some(commitment.commitment_id.clone());
        }

        let bid_ids = state
            .private_event_fee_bids
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let batch = LowFeeEventBatch::from_input(
            &state.config,
            LowFeeEventBatchInput {
                window_id: window_id.clone(),
                operator_commitment: deterministic_root("operator", "low-fee-event-batcher", 0),
                batch_epoch: DEVNET_EPOCH,
                bid_ids: bid_ids.clone(),
                opened_height: DEVNET_HEIGHT + 8,
                congestion_bps: 4,
            },
            &state.private_event_fee_bids,
        )
        .expect("demo low-fee event batch is valid");
        for bid_id in &bid_ids {
            if let Some(bid) = state.private_event_fee_bids.get_mut(bid_id) {
                bid.status = BidStatus::BatchQueued;
                bid.batch_id = Some(batch.batch_id.clone());
            }
        }
        state
            .low_fee_batches
            .insert(batch.batch_id.clone(), batch.clone());

        let settlement = EventSettlement::from_input(
            &state.config,
            EventSettlementInput {
                window_id: window_id.clone(),
                batch_id: batch.batch_id.clone(),
                accepted_bid_ids: bid_ids,
                settlement_height: DEVNET_HEIGHT + 12,
                event_log_root: deterministic_root("event-log", "confidential-transfer", 0),
                fee_distribution_root: deterministic_root("fee-distribution", "event-batch", 0),
                post_state_root: deterministic_root("post-state", "sealed-event-vault", 1),
            },
            &batch,
        )
        .expect("demo event settlement is valid");
        state
            .event_settlements
            .insert(settlement.settlement_id.clone(), settlement.clone());
        if let Some(window) = state.event_windows.get_mut(&window_id) {
            window.status = EventWindowStatus::Settled;
            window.clearing_micro_fee_per_event = Some(DEFAULT_BASE_EVENT_MICRO_FEE);
            window.public_state_root =
                privacy_preserving_public_state_root(window, Some(&settlement), None);
        }
        let snapshot = PublicStateSnapshot::new(
            state
                .event_windows
                .get(&window_id)
                .expect("demo event window exists"),
            0,
            state.low_fee_batches.len(),
            DEVNET_HEIGHT + 13,
        );
        state
            .public_state_snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot);
        for replay in state.replay_nullifiers.values_mut() {
            replay.status = ReplayStatus::Consumed;
            replay.consumed_height = Some(DEVNET_HEIGHT + 12);
        }
        state.recompute_counters();
        state.recompute_roots();
        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_sealed_event_fee_market_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "sealed_event_fee_market_suite": SEALED_EVENT_FEE_MARKET_SUITE,
            "private_event_fee_bid_suite": PRIVATE_EVENT_FEE_BID_SUITE,
            "pq_event_attestation_suite": PQ_EVENT_ATTESTATION_SUITE,
            "low_fee_batching_suite": LOW_FEE_BATCHING_SUITE,
            "replay_resistance_suite": REPLAY_RESISTANCE_SUITE,
            "privacy_preserving_state_suite": PRIVACY_PRESERVING_STATE_SUITE,
            "config": self.config,
            "counters": self.counters,
            "roots": self.roots,
            "event_windows": self.event_windows.values().map(EventWindow::public_record).collect::<Vec<_>>(),
            "private_event_fee_bids": self.private_event_fee_bids.values().map(PrivateEventFeeBid::public_record).collect::<Vec<_>>(),
            "event_commitments": self.event_commitments.values().map(EventCommitment::public_record).collect::<Vec<_>>(),
            "pq_attestations": self.pq_attestations.values().map(PqEventAttestation::public_record).collect::<Vec<_>>(),
            "replay_nullifiers": self.replay_nullifiers.values().map(ReplayNullifier::public_record).collect::<Vec<_>>(),
            "low_fee_batches": self.low_fee_batches.values().map(LowFeeEventBatch::public_record).collect::<Vec<_>>(),
            "event_settlements": self.event_settlements.values().map(EventSettlement::public_record).collect::<Vec<_>>(),
            "public_state_snapshots": self.public_state_snapshots.values().map(PublicStateSnapshot::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        let state_root = state_root_from_record(&record);
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(state_root));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn recompute_counters(&mut self) {
        self.counters = Counters {
            event_windows: self.event_windows.len() as u64,
            active_event_windows: self
                .event_windows
                .values()
                .filter(|window| window.status.active())
                .count() as u64,
            private_event_fee_bids: self.private_event_fee_bids.len() as u64,
            pending_private_event_fee_bids: self
                .private_event_fee_bids
                .values()
                .filter(|bid| bid.status.pending())
                .count() as u64,
            accepted_private_event_fee_bids: self
                .private_event_fee_bids
                .values()
                .filter(|bid| bid.status == BidStatus::Accepted)
                .count() as u64,
            event_commitments: self.event_commitments.len() as u64,
            applied_event_commitments: self
                .event_commitments
                .values()
                .filter(|commitment| commitment.status == CommitmentStatus::Applied)
                .count() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            authenticated_pq_attestations: self
                .pq_attestations
                .values()
                .filter(|attestation| attestation.status.authenticated())
                .count() as u64,
            replay_nullifiers: self.replay_nullifiers.len() as u64,
            consumed_replay_nullifiers: self
                .replay_nullifiers
                .values()
                .filter(|nullifier| nullifier.status == ReplayStatus::Consumed)
                .count() as u64,
            duplicate_replay_nullifiers: self
                .replay_nullifiers
                .values()
                .filter(|nullifier| nullifier.status == ReplayStatus::DuplicateRejected)
                .count() as u64,
            low_fee_batches: self.low_fee_batches.len() as u64,
            settled_low_fee_batches: self
                .low_fee_batches
                .values()
                .filter(|batch| batch.status == BatchStatus::Settled)
                .count() as u64,
            event_settlements: self.event_settlements.len() as u64,
            public_state_snapshots: self.public_state_snapshots.len() as u64,
        };
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            event_window_root: record_root(
                EVENT_WINDOW_SCHEME,
                &self
                    .event_windows
                    .values()
                    .map(EventWindow::public_record)
                    .collect::<Vec<_>>(),
            ),
            private_event_bid_root: record_root(
                PRIVATE_EVENT_BID_SCHEME,
                &self
                    .private_event_fee_bids
                    .values()
                    .map(PrivateEventFeeBid::public_record)
                    .collect::<Vec<_>>(),
            ),
            event_commitment_root: record_root(
                EVENT_COMMITMENT_SCHEME,
                &self
                    .event_commitments
                    .values()
                    .map(EventCommitment::public_record)
                    .collect::<Vec<_>>(),
            ),
            pq_attestation_root: record_root(
                PQ_ATTESTATION_SCHEME,
                &self
                    .pq_attestations
                    .values()
                    .map(PqEventAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            replay_nullifier_root: record_root(
                REPLAY_NULLIFIER_SCHEME,
                &self
                    .replay_nullifiers
                    .values()
                    .map(ReplayNullifier::public_record)
                    .collect::<Vec<_>>(),
            ),
            low_fee_batch_root: record_root(
                LOW_FEE_BATCH_SCHEME,
                &self
                    .low_fee_batches
                    .values()
                    .map(LowFeeEventBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            event_settlement_root: record_root(
                EVENT_SETTLEMENT_SCHEME,
                &self
                    .event_settlements
                    .values()
                    .map(EventSettlement::public_record)
                    .collect::<Vec<_>>(),
            ),
            public_state_snapshot_root: record_root(
                PUBLIC_STATE_SNAPSHOT_SCHEME,
                &self
                    .public_state_snapshots
                    .values()
                    .map(PublicStateSnapshot::public_record)
                    .collect::<Vec<_>>(),
            ),
        };
    }
}

pub fn event_window_id(
    event_class: EventClass,
    contract_id: &str,
    event_topic_commitment: &str,
    epoch: u64,
    start_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-FEE-MARKET:WINDOW-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(event_class.as_str()),
            HashPart::Str(contract_id),
            HashPart::Str(event_topic_commitment),
            HashPart::U64(epoch),
            HashPart::U64(start_height),
        ],
        32,
    )
}

pub fn private_event_fee_bid_id(
    window_id: &str,
    bidder_commitment: &str,
    sealed_fee_bid_root: &str,
    submitted_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-FEE-MARKET:BID-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(window_id),
            HashPart::Str(bidder_commitment),
            HashPart::Str(sealed_fee_bid_root),
            HashPart::U64(submitted_height),
        ],
        32,
    )
}

pub fn event_commitment_id(
    window_id: &str,
    bid_id: &str,
    event_commitment_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-FEE-MARKET:COMMITMENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(window_id),
            HashPart::Str(bid_id),
            HashPart::Str(event_commitment_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn pq_event_attestation_id(
    commitment_id: &str,
    window_id: &str,
    bid_id: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-FEE-MARKET:PQ-ATTESTATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(commitment_id),
            HashPart::Str(window_id),
            HashPart::Str(bid_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn replay_nullifier_id(
    window_id: &str,
    bid_id: &str,
    bidder_commitment: &str,
    sealed_fee_bid_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-FEE-MARKET:REPLAY-NULLIFIER-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(window_id),
            HashPart::Str(bid_id),
            HashPart::Str(bidder_commitment),
            HashPart::Str(sealed_fee_bid_root),
        ],
        32,
    )
}

pub fn low_fee_event_batch_id(
    window_id: &str,
    operator_commitment: &str,
    epoch: u64,
    opened_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-FEE-MARKET:LOW-FEE-BATCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(window_id),
            HashPart::Str(operator_commitment),
            HashPart::U64(epoch),
            HashPart::U64(opened_height),
        ],
        32,
    )
}

pub fn event_settlement_id(window_id: &str, batch_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-FEE-MARKET:SETTLEMENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(window_id),
            HashPart::Str(batch_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn public_state_snapshot_id(window_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-FEE-MARKET:PUBLIC-STATE-SNAPSHOT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(window_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn effective_micro_fee_cap(
    config: &Config,
    bid: &PrivateEventFeeBid,
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
    window: &EventWindow,
    settlement: Option<&EventSettlement>,
    snapshot: Option<&PublicStateSnapshot>,
) -> String {
    let settlement_record = settlement
        .map(EventSettlement::public_record)
        .unwrap_or(Value::Null);
    let snapshot_record = snapshot
        .map(PublicStateSnapshot::public_record)
        .unwrap_or(Value::Null);
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-FEE-MARKET:PUBLIC-STATE-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&window.public_record()),
            HashPart::Json(&settlement_record),
            HashPart::Json(&snapshot_record),
        ],
        32,
    )
}

pub fn estimate_event_count(event_count_commitment: &str, max_events_per_bid: u64) -> u64 {
    let ceiling = max_events_per_bid.max(1);
    let score = event_count_commitment
        .as_bytes()
        .iter()
        .fold(0u64, |acc, byte| acc.wrapping_add(*byte as u64));
    1 + (score % ceiling)
}

pub fn estimate_event_bytes(event_byte_count_commitment: &str) -> u64 {
    let score = event_byte_count_commitment
        .as_bytes()
        .iter()
        .fold(0u64, |acc, byte| {
            acc.wrapping_mul(33).wrapping_add(*byte as u64)
        });
    128 + (score % 16_384)
}

pub fn bid_ids_to_values(bid_ids: &[String]) -> Vec<Value> {
    bid_ids.iter().map(|bid_id| json!(bid_id)).collect()
}

pub fn root_for_values(domain: &str, values: &[Value]) -> String {
    merkle_root(domain, values)
}

pub fn record_root(scheme: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .map(|record| {
            domain_hash(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-FEE-MARKET:RECORD-LEAF",
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

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-FEE-MARKET:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn deterministic_root(label: &str, subject: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-EVENT-FEE-MARKET:DETERMINISTIC-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(subject),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}
