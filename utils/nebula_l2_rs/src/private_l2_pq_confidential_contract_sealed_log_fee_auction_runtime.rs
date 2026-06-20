use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedLogFeeAuctionRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractSealedLogFeeAuctionRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_LOG_FEE_AUCTION_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-sealed-log-fee-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_LOG_FEE_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEALED_LOG_FEE_AUCTION_SUITE: &str =
    "sealed-confidential-smart-contract-log-fee-auction-v1";
pub const PRIVATE_LOG_FEE_BID_SUITE: &str = "private-log-fee-bid-commitment-v1";
pub const PQ_LOG_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-log-commitment-attestation-v1";
pub const LOW_FEE_BATCHING_SUITE: &str = "low-fee-confidential-contract-log-batching-v1";
pub const REPLAY_RESISTANCE_SUITE: &str = "sealed-contract-log-replay-nullifier-v1";
pub const PRIVACY_PRESERVING_STATE_SUITE: &str =
    "privacy-preserving-log-auction-public-state-root-v1";
pub const LOG_AUCTION_ROUND_SCHEME: &str = "sealed-log-fee-auction-round-root-v1";
pub const LOG_FEE_BID_SCHEME: &str = "private-log-fee-bid-root-v1";
pub const LOG_COMMITMENT_SCHEME: &str = "pq-attested-log-commitment-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str = "pq-log-attestation-root-v1";
pub const REPLAY_NULLIFIER_SCHEME: &str = "sealed-log-replay-nullifier-root-v1";
pub const LOW_FEE_BATCH_SCHEME: &str = "low-fee-log-auction-batch-root-v1";
pub const AUCTION_SETTLEMENT_SCHEME: &str = "sealed-log-auction-settlement-root-v1";
pub const PUBLIC_STATE_SNAPSHOT_SCHEME: &str = "privacy-preserving-log-state-snapshot-root-v1";
pub const FIXTURE_SCHEME: &str = "sealed-log-fee-auction-devnet-fixture-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_325_184;
pub const DEVNET_EPOCH: u64 = 10_402;
pub const DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 64;
pub const DEFAULT_LOG_EPOCH_BLOCKS: u64 = 7_200;
pub const DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 128;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_BIDS_PER_AUCTION: usize = 16_384;
pub const DEFAULT_MAX_LOGS_PER_BID: u64 = 65_536;
pub const DEFAULT_MAX_COMMITMENTS_PER_BATCH: usize = 4_096;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 3;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 5;
pub const DEFAULT_CONGESTION_SURCHARGE_BPS: u64 = 12;
pub const DEFAULT_BASE_LOG_MICRO_FEE: u64 = 9;
pub const DEFAULT_MIN_LOG_MICRO_FEE_PER_ENTRY: u64 = 2;
pub const DEFAULT_MAX_LOG_BYTES_PER_BATCH: u64 = 28_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogAuctionDomain {
    ContractLog,
    ConfidentialTopic,
    ExecutionTrace,
    OracleLog,
    GovernanceLog,
    RecoveryLog,
    EmergencyLog,
    LowFeeArchiveLog,
}

impl LogAuctionDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractLog => "contract_log",
            Self::ConfidentialTopic => "confidential_topic",
            Self::ExecutionTrace => "execution_trace",
            Self::OracleLog => "oracle_log",
            Self::GovernanceLog => "governance_log",
            Self::RecoveryLog => "recovery_log",
            Self::EmergencyLog => "emergency_log",
            Self::LowFeeArchiveLog => "low_fee_archive_log",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyLog => 10_000,
            Self::RecoveryLog => 9_600,
            Self::GovernanceLog => 9_100,
            Self::OracleLog => 8_700,
            Self::ConfidentialTopic => 8_400,
            Self::ExecutionTrace => 8_000,
            Self::ContractLog => 7_500,
            Self::LowFeeArchiveLog => 5_900,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Announced,
    CommitOpen,
    RevealOpen,
    PqAttested,
    BatchReady,
    Settled,
    Cancelled,
    Expired,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::CommitOpen => "commit_open",
            Self::RevealOpen => "reveal_open",
            Self::PqAttested => "pq_attested",
            Self::BatchReady => "batch_ready",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Announced
                | Self::CommitOpen
                | Self::RevealOpen
                | Self::PqAttested
                | Self::BatchReady
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
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::ReplayGuarded => "replay_guarded",
            Self::PqCommitted => "pq_committed",
            Self::BatchQueued => "batch_queued",
            Self::Accepted => "accepted",
            Self::Repriced => "repriced",
            Self::Outbid => "outbid",
            Self::Refunded => "refunded",
            Self::DuplicateRejected => "duplicate_rejected",
            Self::Expired => "expired",
        }
    }

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
    Settled,
    Repriced,
    Cancelled,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::PqAttested => "pq_attested",
            Self::Settled => "settled",
            Self::Repriced => "repriced",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub sealed_log_fee_auction_suite: String,
    pub private_log_fee_bid_suite: String,
    pub pq_log_attestation_suite: String,
    pub low_fee_batching_suite: String,
    pub replay_resistance_suite: String,
    pub privacy_preserving_state_suite: String,
    pub auction_window_blocks: u64,
    pub log_epoch_blocks: u64,
    pub replay_window_blocks: u64,
    pub batch_window_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_bids_per_auction: usize,
    pub max_logs_per_bid: u64,
    pub max_commitments_per_batch: usize,
    pub max_user_fee_bps: u64,
    pub operator_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub congestion_surcharge_bps: u64,
    pub base_log_micro_fee: u64,
    pub min_log_micro_fee_per_entry: u64,
    pub max_log_bytes_per_batch: u64,
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
            sealed_log_fee_auction_suite: SEALED_LOG_FEE_AUCTION_SUITE.to_string(),
            private_log_fee_bid_suite: PRIVATE_LOG_FEE_BID_SUITE.to_string(),
            pq_log_attestation_suite: PQ_LOG_ATTESTATION_SUITE.to_string(),
            low_fee_batching_suite: LOW_FEE_BATCHING_SUITE.to_string(),
            replay_resistance_suite: REPLAY_RESISTANCE_SUITE.to_string(),
            privacy_preserving_state_suite: PRIVACY_PRESERVING_STATE_SUITE.to_string(),
            auction_window_blocks: DEFAULT_AUCTION_WINDOW_BLOCKS,
            log_epoch_blocks: DEFAULT_LOG_EPOCH_BLOCKS,
            replay_window_blocks: DEFAULT_REPLAY_WINDOW_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_bids_per_auction: DEFAULT_MAX_BIDS_PER_AUCTION,
            max_logs_per_bid: DEFAULT_MAX_LOGS_PER_BID,
            max_commitments_per_batch: DEFAULT_MAX_COMMITMENTS_PER_BATCH,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            congestion_surcharge_bps: DEFAULT_CONGESTION_SURCHARGE_BPS,
            base_log_micro_fee: DEFAULT_BASE_LOG_MICRO_FEE,
            min_log_micro_fee_per_entry: DEFAULT_MIN_LOG_MICRO_FEE_PER_ENTRY,
            max_log_bytes_per_batch: DEFAULT_MAX_LOG_BYTES_PER_BATCH,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("log fee auction protocol version mismatch".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("log fee auction schema version mismatch".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("log fee auction pq security bits below floor".to_string());
        }
        if self.min_privacy_set_size < DEFAULT_MIN_PRIVACY_SET_SIZE {
            return Err("log fee auction privacy set below floor".to_string());
        }
        if self.max_user_fee_bps > MAX_BPS
            || self.operator_fee_bps > MAX_BPS
            || self.batch_rebate_bps > MAX_BPS
            || self.congestion_surcharge_bps > MAX_BPS
        {
            return Err("log fee auction basis points exceed MAX_BPS".to_string());
        }
        if self.auction_window_blocks == 0
            || self.log_epoch_blocks == 0
            || self.replay_window_blocks == 0
            || self.batch_window_blocks == 0
        {
            return Err("log fee auction windows must be non-zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub auction_rounds: u64,
    pub active_auction_rounds: u64,
    pub log_fee_bids: u64,
    pub pending_log_fee_bids: u64,
    pub accepted_log_fee_bids: u64,
    pub log_commitments: u64,
    pub applied_log_commitments: u64,
    pub pq_attestations: u64,
    pub authenticated_pq_attestations: u64,
    pub replay_nullifiers: u64,
    pub consumed_replay_nullifiers: u64,
    pub duplicate_replay_nullifiers: u64,
    pub low_fee_batches: u64,
    pub settled_low_fee_batches: u64,
    pub auction_settlements: u64,
    pub public_state_snapshots: u64,
    pub devnet_fixtures: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub auction_round_root: String,
    pub log_fee_bid_root: String,
    pub log_commitment_root: String,
    pub pq_attestation_root: String,
    pub replay_nullifier_root: String,
    pub low_fee_batch_root: String,
    pub auction_settlement_root: String,
    pub public_state_snapshot_root: String,
    pub fixture_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            auction_round_root: merkle_root(LOG_AUCTION_ROUND_SCHEME, &[]),
            log_fee_bid_root: merkle_root(LOG_FEE_BID_SCHEME, &[]),
            log_commitment_root: merkle_root(LOG_COMMITMENT_SCHEME, &[]),
            pq_attestation_root: merkle_root(PQ_ATTESTATION_SCHEME, &[]),
            replay_nullifier_root: merkle_root(REPLAY_NULLIFIER_SCHEME, &[]),
            low_fee_batch_root: merkle_root(LOW_FEE_BATCH_SCHEME, &[]),
            auction_settlement_root: merkle_root(AUCTION_SETTLEMENT_SCHEME, &[]),
            public_state_snapshot_root: merkle_root(PUBLIC_STATE_SNAPSHOT_SCHEME, &[]),
            fixture_root: merkle_root(FIXTURE_SCHEME, &[]),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AuctionRoundInput {
    pub domain: LogAuctionDomain,
    pub contract_id: String,
    pub log_class_commitment: String,
    pub prior_state_root: String,
    pub target_state_root: String,
    pub start_height: u64,
    pub end_height: u64,
    pub fee_epoch: u64,
    pub capacity_entries: u64,
    pub reserve_micro_fee_per_entry: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AuctionRound {
    pub auction_id: String,
    pub domain: LogAuctionDomain,
    pub contract_id: String,
    pub log_class_commitment: String,
    pub prior_state_root: String,
    pub target_state_root: String,
    pub bid_commitment_root: String,
    pub pq_commitment_root: String,
    pub replay_nullifier_root: String,
    pub start_height: u64,
    pub end_height: u64,
    pub fee_epoch: u64,
    pub capacity_entries: u64,
    pub reserve_micro_fee_per_entry: u64,
    pub clearing_micro_fee_per_entry: Option<u64>,
    pub privacy_set_size: u64,
    pub status: AuctionStatus,
}

impl AuctionRound {
    pub fn from_input(config: &Config, input: AuctionRoundInput) -> Result<Self> {
        config.validate()?;
        if input.end_height <= input.start_height {
            return Err("auction round end height must exceed start height".to_string());
        }
        if input.end_height - input.start_height > config.auction_window_blocks {
            return Err("auction round exceeds configured auction window".to_string());
        }
        if input.capacity_entries == 0 {
            return Err("auction round capacity must be non-zero".to_string());
        }
        if input.reserve_micro_fee_per_entry < config.min_log_micro_fee_per_entry {
            return Err("auction reserve fee is below configured floor".to_string());
        }
        if input.privacy_set_size < config.min_privacy_set_size {
            return Err("auction round privacy set below configured floor".to_string());
        }
        let auction_id = auction_round_id(
            input.domain,
            &input.contract_id,
            &input.log_class_commitment,
            input.fee_epoch,
            input.start_height,
        );
        Ok(Self {
            auction_id,
            domain: input.domain,
            contract_id: input.contract_id,
            log_class_commitment: input.log_class_commitment,
            prior_state_root: input.prior_state_root,
            target_state_root: input.target_state_root,
            bid_commitment_root: merkle_root(LOG_FEE_BID_SCHEME, &[]),
            pq_commitment_root: merkle_root(LOG_COMMITMENT_SCHEME, &[]),
            replay_nullifier_root: merkle_root(REPLAY_NULLIFIER_SCHEME, &[]),
            start_height: input.start_height,
            end_height: input.end_height,
            fee_epoch: input.fee_epoch,
            capacity_entries: input.capacity_entries,
            reserve_micro_fee_per_entry: input.reserve_micro_fee_per_entry,
            clearing_micro_fee_per_entry: None,
            privacy_set_size: input.privacy_set_size,
            status: AuctionStatus::CommitOpen,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "domain": self.domain.as_str(),
            "contract_id": self.contract_id,
            "log_class_commitment": self.log_class_commitment,
            "prior_state_root": self.prior_state_root,
            "target_state_root": self.target_state_root,
            "bid_commitment_root": self.bid_commitment_root,
            "pq_commitment_root": self.pq_commitment_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "fee_epoch": self.fee_epoch,
            "capacity_entries": self.capacity_entries,
            "reserve_micro_fee_per_entry": self.reserve_micro_fee_per_entry,
            "clearing_micro_fee_per_entry": self.clearing_micro_fee_per_entry,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LogFeeBidInput {
    pub auction_id: String,
    pub bidder_commitment: String,
    pub contract_id: String,
    pub sealed_bid_root: String,
    pub sealed_entry_set_root: String,
    pub log_commitment_root: String,
    pub replay_nullifier_root: String,
    pub max_micro_fee_per_entry: u64,
    pub requested_entries: u64,
    pub fee_epochs: u64,
    pub max_user_fee_bps: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LogFeeBid {
    pub bid_id: String,
    pub auction_id: String,
    pub bidder_commitment: String,
    pub contract_id: String,
    pub sealed_bid_root: String,
    pub sealed_entry_set_root: String,
    pub log_commitment_root: String,
    pub replay_nullifier_root: String,
    pub clearing_receipt_root: Option<String>,
    pub max_micro_fee_per_entry: u64,
    pub requested_entries: u64,
    pub fee_epochs: u64,
    pub max_user_fee_bps: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub privacy_set_size: u64,
    pub status: BidStatus,
}

impl LogFeeBid {
    pub fn from_input(config: &Config, input: LogFeeBidInput) -> Result<Self> {
        config.validate()?;
        if input.requested_entries == 0 || input.requested_entries > config.max_logs_per_bid {
            return Err("log fee bid requested entry count out of range".to_string());
        }
        if input.fee_epochs == 0 {
            return Err("log fee bid must request at least one fee epoch".to_string());
        }
        if input.max_micro_fee_per_entry < config.min_log_micro_fee_per_entry {
            return Err("log fee bid max fee below fee floor".to_string());
        }
        if input.max_user_fee_bps > config.max_user_fee_bps {
            return Err("log fee bid user fee exceeds configured cap".to_string());
        }
        if input.expires_height <= input.submitted_height {
            return Err("log fee bid expiry must exceed submitted height".to_string());
        }
        if input.expires_height - input.submitted_height > config.replay_window_blocks {
            return Err("log fee bid replay window exceeds configured limit".to_string());
        }
        if input.privacy_set_size < config.min_privacy_set_size {
            return Err("log fee bid privacy set below configured floor".to_string());
        }
        let bid_id = log_fee_bid_id(
            &input.auction_id,
            &input.bidder_commitment,
            &input.sealed_bid_root,
            input.submitted_height,
        );
        Ok(Self {
            bid_id,
            auction_id: input.auction_id,
            bidder_commitment: input.bidder_commitment,
            contract_id: input.contract_id,
            sealed_bid_root: input.sealed_bid_root,
            sealed_entry_set_root: input.sealed_entry_set_root,
            log_commitment_root: input.log_commitment_root,
            replay_nullifier_root: input.replay_nullifier_root,
            clearing_receipt_root: None,
            max_micro_fee_per_entry: input.max_micro_fee_per_entry,
            requested_entries: input.requested_entries,
            fee_epochs: input.fee_epochs,
            max_user_fee_bps: input.max_user_fee_bps,
            submitted_height: input.submitted_height,
            expires_height: input.expires_height,
            privacy_set_size: input.privacy_set_size,
            status: BidStatus::Sealed,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "bidder_commitment": self.bidder_commitment,
            "contract_id": self.contract_id,
            "sealed_bid_root": self.sealed_bid_root,
            "sealed_entry_set_root": self.sealed_entry_set_root,
            "log_commitment_root": self.log_commitment_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "clearing_receipt_root": self.clearing_receipt_root,
            "max_micro_fee_per_entry": self.max_micro_fee_per_entry,
            "requested_entries": self.requested_entries,
            "fee_epochs": self.fee_epochs,
            "max_user_fee_bps": self.max_user_fee_bps,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LogCommitment {
    pub commitment_id: String,
    pub auction_id: String,
    pub bid_id: String,
    pub contract_id: String,
    pub log_root_before: String,
    pub log_root_after: String,
    pub sealed_entry_delta_root: String,
    pub fee_obligation_root: String,
    pub pq_attestation_id: String,
    pub attestor_quorum_root: String,
    pub pq_security_bits: u16,
    pub status: CommitmentStatus,
}

impl LogCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "contract_id": self.contract_id,
            "log_root_before": self.log_root_before,
            "log_root_after": self.log_root_after,
            "sealed_entry_delta_root": self.sealed_entry_delta_root,
            "fee_obligation_root": self.fee_obligation_root,
            "pq_attestation_id": self.pq_attestation_id,
            "attestor_quorum_root": self.attestor_quorum_root,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqLogAttestation {
    pub attestation_id: String,
    pub commitment_id: String,
    pub auction_id: String,
    pub bid_id: String,
    pub attestor_set_root: String,
    pub transcript_root: String,
    pub signature_bundle_root: String,
    pub log_commitment_root: String,
    pub min_pq_security_bits: u16,
    pub attested_height: u64,
    pub status: CommitmentStatus,
}

impl PqLogAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "commitment_id": self.commitment_id,
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "attestor_set_root": self.attestor_set_root,
            "transcript_root": self.transcript_root,
            "signature_bundle_root": self.signature_bundle_root,
            "log_commitment_root": self.log_commitment_root,
            "min_pq_security_bits": self.min_pq_security_bits,
            "attested_height": self.attested_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReplayNullifier {
    pub nullifier_id: String,
    pub auction_id: String,
    pub bid_id: String,
    pub bidder_commitment: String,
    pub sealed_bid_root: String,
    pub first_seen_height: u64,
    pub expires_height: u64,
    pub duplicate_evidence_root: Option<String>,
    pub status: ReplayStatus,
}

impl ReplayNullifier {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "bidder_commitment": self.bidder_commitment,
            "sealed_bid_root": self.sealed_bid_root,
            "first_seen_height": self.first_seen_height,
            "expires_height": self.expires_height,
            "duplicate_evidence_root": self.duplicate_evidence_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LowFeeBatch {
    pub batch_id: String,
    pub auction_id: String,
    pub bid_ids: Vec<String>,
    pub bid_commitment_root: String,
    pub replay_nullifier_root: String,
    pub pq_attestation_root: String,
    pub aggregate_requested_entries: u64,
    pub aggregate_fee_epochs: u64,
    pub aggregate_micro_fee_cap: u64,
    pub batch_rebate_bps: u64,
    pub operator_fee_bps: u64,
    pub opened_height: u64,
    pub sealed_height: Option<u64>,
    pub status: BatchStatus,
}

impl LowFeeBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "auction_id": self.auction_id,
            "bid_ids": self.bid_ids,
            "bid_commitment_root": self.bid_commitment_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "pq_attestation_root": self.pq_attestation_root,
            "aggregate_requested_entries": self.aggregate_requested_entries,
            "aggregate_fee_epochs": self.aggregate_fee_epochs,
            "aggregate_micro_fee_cap": self.aggregate_micro_fee_cap,
            "batch_rebate_bps": self.batch_rebate_bps,
            "operator_fee_bps": self.operator_fee_bps,
            "opened_height": self.opened_height,
            "sealed_height": self.sealed_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AuctionSettlement {
    pub settlement_id: String,
    pub auction_id: String,
    pub batch_id: String,
    pub accepted_bid_root: String,
    pub refunded_bid_root: String,
    pub clearing_micro_fee_per_entry: u64,
    pub settled_entries: u64,
    pub fee_obligation_root: String,
    pub post_state_root: String,
    pub settlement_height: u64,
}

impl AuctionSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "auction_id": self.auction_id,
            "batch_id": self.batch_id,
            "accepted_bid_root": self.accepted_bid_root,
            "refunded_bid_root": self.refunded_bid_root,
            "clearing_micro_fee_per_entry": self.clearing_micro_fee_per_entry,
            "settled_entries": self.settled_entries,
            "fee_obligation_root": self.fee_obligation_root,
            "post_state_root": self.post_state_root,
            "settlement_height": self.settlement_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PublicStateSnapshot {
    pub snapshot_id: String,
    pub auction_id: String,
    pub public_state_root: String,
    pub private_log_commitment_root: String,
    pub fee_liability_root: String,
    pub replay_guard_root: String,
    pub accepted_bid_count: u64,
    pub settled_entries: u64,
    pub height: u64,
}

impl PublicStateSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "auction_id": self.auction_id,
            "public_state_root": self.public_state_root,
            "private_log_commitment_root": self.private_log_commitment_root,
            "fee_liability_root": self.fee_liability_root,
            "replay_guard_root": self.replay_guard_root,
            "accepted_bid_count": self.accepted_bid_count,
            "settled_entries": self.settled_entries,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct DevnetFixture {
    pub fixture_id: String,
    pub description: String,
    pub auction_id: String,
    pub bid_id: String,
    pub batch_id: String,
    pub expected_state_root: String,
}

impl DevnetFixture {
    pub fn public_record(&self) -> Value {
        json!({
            "fixture_id": self.fixture_id,
            "description": self.description,
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "batch_id": self.batch_id,
            "expected_state_root": self.expected_state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub auction_rounds: BTreeMap<String, AuctionRound>,
    pub log_fee_bids: BTreeMap<String, LogFeeBid>,
    pub log_commitments: BTreeMap<String, LogCommitment>,
    pub pq_attestations: BTreeMap<String, PqLogAttestation>,
    pub replay_nullifiers: BTreeMap<String, ReplayNullifier>,
    pub low_fee_batches: BTreeMap<String, LowFeeBatch>,
    pub auction_settlements: BTreeMap<String, AuctionSettlement>,
    pub public_state_snapshots: BTreeMap<String, PublicStateSnapshot>,
    pub devnet_fixtures: BTreeMap<String, DevnetFixture>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            auction_rounds: BTreeMap::new(),
            log_fee_bids: BTreeMap::new(),
            log_commitments: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            replay_nullifiers: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            auction_settlements: BTreeMap::new(),
            public_state_snapshots: BTreeMap::new(),
            devnet_fixtures: BTreeMap::new(),
        };
        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn insert_auction_round(&mut self, auction: AuctionRound) -> Result<()> {
        self.config.validate()?;
        if self.auction_rounds.contains_key(&auction.auction_id) {
            return Err("duplicate log auction round".to_string());
        }
        self.auction_rounds
            .insert(auction.auction_id.clone(), auction);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_log_fee_bid(&mut self, bid: LogFeeBid) -> Result<()> {
        self.config.validate()?;
        if !self.auction_rounds.contains_key(&bid.auction_id) {
            return Err("log fee bid references unknown auction".to_string());
        }
        if self.log_fee_bids.contains_key(&bid.bid_id) {
            return Err("duplicate log fee bid".to_string());
        }
        let auction_bid_count = self
            .log_fee_bids
            .values()
            .filter(|existing| existing.auction_id == bid.auction_id)
            .count();
        if auction_bid_count >= self.config.max_bids_per_auction {
            return Err("log fee auction bid cap reached".to_string());
        }
        self.log_fee_bids.insert(bid.bid_id.clone(), bid);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_log_commitment(&mut self, commitment: LogCommitment) -> Result<()> {
        if commitment.pq_security_bits < self.config.min_pq_security_bits {
            return Err("log commitment pq security bits below configured floor".to_string());
        }
        if !self.log_fee_bids.contains_key(&commitment.bid_id) {
            return Err("log commitment references unknown bid".to_string());
        }
        self.log_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_pq_attestation(&mut self, attestation: PqLogAttestation) -> Result<()> {
        if attestation.min_pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq log attestation security bits below configured floor".to_string());
        }
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_replay_nullifier(&mut self, nullifier: ReplayNullifier) -> Result<()> {
        if self.replay_nullifiers.contains_key(&nullifier.nullifier_id) {
            return Err("duplicate replay nullifier".to_string());
        }
        self.replay_nullifiers
            .insert(nullifier.nullifier_id.clone(), nullifier);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_low_fee_batch(&mut self, batch: LowFeeBatch) -> Result<()> {
        if batch.bid_ids.len() > self.config.max_commitments_per_batch {
            return Err("low-fee log batch exceeds commitment cap".to_string());
        }
        if batch.operator_fee_bps > self.config.operator_fee_bps {
            return Err("low-fee log batch operator fee exceeds cap".to_string());
        }
        if batch.batch_rebate_bps > MAX_BPS {
            return Err("low-fee log batch rebate exceeds MAX_BPS".to_string());
        }
        self.low_fee_batches.insert(batch.batch_id.clone(), batch);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_auction_settlement(&mut self, settlement: AuctionSettlement) -> Result<()> {
        if !self.auction_rounds.contains_key(&settlement.auction_id) {
            return Err("auction settlement references unknown auction".to_string());
        }
        self.auction_settlements
            .insert(settlement.settlement_id.clone(), settlement);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_public_state_snapshot(&mut self, snapshot: PublicStateSnapshot) -> Result<()> {
        self.public_state_snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_sealed_log_fee_auction_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "sealed_log_fee_auction_suite": SEALED_LOG_FEE_AUCTION_SUITE,
            "private_log_fee_bid_suite": PRIVATE_LOG_FEE_BID_SUITE,
            "pq_log_attestation_suite": PQ_LOG_ATTESTATION_SUITE,
            "low_fee_batching_suite": LOW_FEE_BATCHING_SUITE,
            "replay_resistance_suite": REPLAY_RESISTANCE_SUITE,
            "privacy_preserving_state_suite": PRIVACY_PRESERVING_STATE_SUITE,
            "config": self.config,
            "counters": self.counters,
            "roots": self.roots,
            "auction_rounds": self.auction_rounds.values().map(AuctionRound::public_record).collect::<Vec<_>>(),
            "log_fee_bids": self.log_fee_bids.values().map(LogFeeBid::public_record).collect::<Vec<_>>(),
            "log_commitments": self.log_commitments.values().map(LogCommitment::public_record).collect::<Vec<_>>(),
            "pq_attestations": self.pq_attestations.values().map(PqLogAttestation::public_record).collect::<Vec<_>>(),
            "replay_nullifiers": self.replay_nullifiers.values().map(ReplayNullifier::public_record).collect::<Vec<_>>(),
            "low_fee_batches": self.low_fee_batches.values().map(LowFeeBatch::public_record).collect::<Vec<_>>(),
            "auction_settlements": self.auction_settlements.values().map(AuctionSettlement::public_record).collect::<Vec<_>>(),
            "public_state_snapshots": self.public_state_snapshots.values().map(PublicStateSnapshot::public_record).collect::<Vec<_>>(),
            "devnet_fixtures": self.devnet_fixtures.values().map(DevnetFixture::public_record).collect::<Vec<_>>(),
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
            auction_rounds: self.auction_rounds.len() as u64,
            active_auction_rounds: self
                .auction_rounds
                .values()
                .filter(|auction| auction.status.active())
                .count() as u64,
            log_fee_bids: self.log_fee_bids.len() as u64,
            pending_log_fee_bids: self
                .log_fee_bids
                .values()
                .filter(|bid| bid.status.pending())
                .count() as u64,
            accepted_log_fee_bids: self
                .log_fee_bids
                .values()
                .filter(|bid| bid.status == BidStatus::Accepted)
                .count() as u64,
            log_commitments: self.log_commitments.len() as u64,
            applied_log_commitments: self
                .log_commitments
                .values()
                .filter(|commitment| commitment.status == CommitmentStatus::Applied)
                .count() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            authenticated_pq_attestations: self
                .pq_attestations
                .values()
                .filter(|attestation| {
                    matches!(
                        attestation.status,
                        CommitmentStatus::Authenticated
                            | CommitmentStatus::QuorumSigned
                            | CommitmentStatus::Applied
                    )
                })
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
            auction_settlements: self.auction_settlements.len() as u64,
            public_state_snapshots: self.public_state_snapshots.len() as u64,
            devnet_fixtures: self.devnet_fixtures.len() as u64,
        };
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            auction_round_root: record_root(
                LOG_AUCTION_ROUND_SCHEME,
                self.auction_rounds
                    .values()
                    .map(AuctionRound::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            log_fee_bid_root: record_root(
                LOG_FEE_BID_SCHEME,
                self.log_fee_bids
                    .values()
                    .map(LogFeeBid::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            log_commitment_root: record_root(
                LOG_COMMITMENT_SCHEME,
                self.log_commitments
                    .values()
                    .map(LogCommitment::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            pq_attestation_root: record_root(
                PQ_ATTESTATION_SCHEME,
                self.pq_attestations
                    .values()
                    .map(PqLogAttestation::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            replay_nullifier_root: record_root(
                REPLAY_NULLIFIER_SCHEME,
                self.replay_nullifiers
                    .values()
                    .map(ReplayNullifier::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            low_fee_batch_root: record_root(
                LOW_FEE_BATCH_SCHEME,
                self.low_fee_batches
                    .values()
                    .map(LowFeeBatch::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            auction_settlement_root: record_root(
                AUCTION_SETTLEMENT_SCHEME,
                self.auction_settlements
                    .values()
                    .map(AuctionSettlement::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            public_state_snapshot_root: record_root(
                PUBLIC_STATE_SNAPSHOT_SCHEME,
                self.public_state_snapshots
                    .values()
                    .map(PublicStateSnapshot::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            fixture_root: record_root(
                FIXTURE_SCHEME,
                self.devnet_fixtures
                    .values()
                    .map(DevnetFixture::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
        };
    }
}

pub fn auction_round_id(
    domain: LogAuctionDomain,
    contract_id: &str,
    log_class_commitment: &str,
    fee_epoch: u64,
    start_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-LOG-FEE-AUCTION:AUCTION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain.as_str()),
            HashPart::Str(contract_id),
            HashPart::Str(log_class_commitment),
            HashPart::U64(fee_epoch),
            HashPart::U64(start_height),
        ],
        32,
    )
}

pub fn log_fee_bid_id(
    auction_id: &str,
    bidder_commitment: &str,
    sealed_bid_root: &str,
    submitted_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-LOG-FEE-AUCTION:BID-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(auction_id),
            HashPart::Str(bidder_commitment),
            HashPart::Str(sealed_bid_root),
            HashPart::U64(submitted_height),
        ],
        32,
    )
}

pub fn log_commitment_id(
    auction_id: &str,
    bid_id: &str,
    log_commitment_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-LOG-FEE-AUCTION:COMMITMENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(auction_id),
            HashPart::Str(bid_id),
            HashPart::Str(log_commitment_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn pq_log_attestation_id(
    commitment_id: &str,
    auction_id: &str,
    bid_id: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-LOG-FEE-AUCTION:PQ-ATTESTATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(commitment_id),
            HashPart::Str(auction_id),
            HashPart::Str(bid_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn replay_nullifier_id(
    auction_id: &str,
    bid_id: &str,
    bidder_commitment: &str,
    sealed_bid_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-LOG-FEE-AUCTION:REPLAY-NULLIFIER-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(auction_id),
            HashPart::Str(bid_id),
            HashPart::Str(bidder_commitment),
            HashPart::Str(sealed_bid_root),
        ],
        32,
    )
}

pub fn low_fee_batch_id(auction_id: &str, bid_ids: &[String], opened_height: u64) -> String {
    let bid_root = merkle_root(
        "sealed-log-fee-auction-low-fee-batch-bid-id-root-v1",
        &bid_ids.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-LOG-FEE-AUCTION:LOW-FEE-BATCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(auction_id),
            HashPart::Str(&bid_root),
            HashPart::U64(opened_height),
        ],
        32,
    )
}

pub fn auction_settlement_id(auction_id: &str, batch_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-LOG-FEE-AUCTION:SETTLEMENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(auction_id),
            HashPart::Str(batch_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn public_state_snapshot_id(auction_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-LOG-FEE-AUCTION:PUBLIC-STATE-SNAPSHOT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(auction_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn devnet_fixture_id(label: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-LOG-FEE-AUCTION:DEVNET-FIXTURE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn detect_replay_conflicts(bids: &[LogFeeBid]) -> BTreeSet<String> {
    let mut seen = BTreeMap::<String, String>::new();
    let mut conflicts = BTreeSet::<String>::new();
    for bid in bids {
        let key = replay_nullifier_id(
            &bid.auction_id,
            &bid.bid_id,
            &bid.bidder_commitment,
            &bid.sealed_bid_root,
        );
        if let Some(previous_bid_id) = seen.insert(key, bid.bid_id.clone()) {
            conflicts.insert(previous_bid_id);
            conflicts.insert(bid.bid_id.clone());
        }
    }
    conflicts
}

pub fn effective_micro_fee_cap(config: &Config, bid: &LogFeeBid, congestion_bps: u64) -> u64 {
    let congestion = congestion_bps.min(config.congestion_surcharge_bps);
    let surcharge = bid
        .max_micro_fee_per_entry
        .saturating_mul(congestion)
        .saturating_div(MAX_BPS);
    bid.max_micro_fee_per_entry.saturating_add(surcharge)
}

pub fn low_fee_batch_savings_micro(config: &Config, batch: &LowFeeBatch) -> u64 {
    batch
        .aggregate_micro_fee_cap
        .saturating_mul(config.batch_rebate_bps)
        .saturating_div(MAX_BPS)
}

pub fn privacy_preserving_public_state_root(
    auction: &AuctionRound,
    settlement: Option<&AuctionSettlement>,
    snapshot: Option<&PublicStateSnapshot>,
) -> String {
    let settlement_record = settlement
        .map(AuctionSettlement::public_record)
        .unwrap_or(Value::Null);
    let snapshot_record = snapshot
        .map(PublicStateSnapshot::public_record)
        .unwrap_or(Value::Null);
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-LOG-FEE-AUCTION:PUBLIC-STATE-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&auction.public_record()),
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
                "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-LOG-FEE-AUCTION:RECORD-LEAF",
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-LOG-FEE-AUCTION:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
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

fn demo_hash(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-LOG-FEE-AUCTION:DEMO-HASH",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}
