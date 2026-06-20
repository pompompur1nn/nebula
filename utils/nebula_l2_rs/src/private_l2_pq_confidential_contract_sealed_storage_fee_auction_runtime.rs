use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedStorageFeeAuctionRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractSealedStorageFeeAuctionRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STORAGE_FEE_AUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-sealed-storage-fee-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STORAGE_FEE_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEALED_STORAGE_FEE_AUCTION_SUITE: &str =
    "sealed-confidential-smart-contract-storage-fee-auction-v1";
pub const PRIVATE_STORAGE_RENT_BID_SUITE: &str = "private-storage-rent-bid-commitment-v1";
pub const PQ_STORAGE_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-storage-commitment-attestation-v1";
pub const LOW_FEE_BATCHING_SUITE: &str = "low-fee-confidential-storage-rent-batching-v1";
pub const REPLAY_RESISTANCE_SUITE: &str = "sealed-storage-rent-replay-nullifier-v1";
pub const PRIVACY_PRESERVING_STATE_SUITE: &str =
    "privacy-preserving-storage-auction-public-state-root-v1";
pub const AUCTION_ROUND_SCHEME: &str = "sealed-storage-fee-auction-round-root-v1";
pub const STORAGE_RENT_BID_SCHEME: &str = "private-storage-rent-bid-root-v1";
pub const STORAGE_COMMITMENT_SCHEME: &str = "pq-attested-storage-commitment-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str = "pq-storage-attestation-root-v1";
pub const REPLAY_NULLIFIER_SCHEME: &str = "sealed-storage-replay-nullifier-root-v1";
pub const LOW_FEE_BATCH_SCHEME: &str = "low-fee-storage-auction-batch-root-v1";
pub const AUCTION_SETTLEMENT_SCHEME: &str = "sealed-storage-auction-settlement-root-v1";
pub const PUBLIC_STATE_SNAPSHOT_SCHEME: &str = "privacy-preserving-storage-state-snapshot-root-v1";
pub const FIXTURE_SCHEME: &str = "sealed-storage-fee-auction-devnet-fixture-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_325_184;
pub const DEVNET_EPOCH: u64 = 10_402;
pub const DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 64;
pub const DEFAULT_RENT_EPOCH_BLOCKS: u64 = 7_200;
pub const DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 128;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MAX_BIDS_PER_AUCTION: usize = 16_384;
pub const DEFAULT_MAX_STORAGE_SLOTS_PER_BID: u64 = 65_536;
pub const DEFAULT_MAX_COMMITMENTS_PER_BATCH: usize = 4_096;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 3;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 5;
pub const DEFAULT_CONGESTION_SURCHARGE_BPS: u64 = 12;
pub const DEFAULT_BASE_STORAGE_MICRO_FEE: u64 = 9;
pub const DEFAULT_MIN_RENT_MICRO_FEE_PER_SLOT: u64 = 2;
pub const DEFAULT_MAX_VM_STEPS_PER_BATCH: u64 = 28_000_000;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageAuctionDomain {
    ContractStorage,
    ConfidentialVault,
    RollupInbox,
    OracleCache,
    GovernanceTimelock,
    AccountRecovery,
    EmergencyRetention,
    ExpiringArchive,
}

impl StorageAuctionDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractStorage => "contract_storage",
            Self::ConfidentialVault => "confidential_vault",
            Self::RollupInbox => "rollup_inbox",
            Self::OracleCache => "oracle_cache",
            Self::GovernanceTimelock => "governance_timelock",
            Self::AccountRecovery => "account_recovery",
            Self::EmergencyRetention => "emergency_retention",
            Self::ExpiringArchive => "expiring_archive",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyRetention => 10_000,
            Self::AccountRecovery => 9_600,
            Self::GovernanceTimelock => 9_100,
            Self::OracleCache => 8_700,
            Self::ConfidentialVault => 8_400,
            Self::RollupInbox => 8_000,
            Self::ContractStorage => 7_500,
            Self::ExpiringArchive => 5_900,
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
    pub sealed_storage_fee_auction_suite: String,
    pub private_storage_rent_bid_suite: String,
    pub pq_storage_attestation_suite: String,
    pub low_fee_batching_suite: String,
    pub replay_resistance_suite: String,
    pub privacy_preserving_state_suite: String,
    pub auction_window_blocks: u64,
    pub rent_epoch_blocks: u64,
    pub replay_window_blocks: u64,
    pub batch_window_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub max_bids_per_auction: usize,
    pub max_storage_slots_per_bid: u64,
    pub max_commitments_per_batch: usize,
    pub max_user_fee_bps: u64,
    pub operator_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub congestion_surcharge_bps: u64,
    pub base_storage_micro_fee: u64,
    pub min_rent_micro_fee_per_slot: u64,
    pub max_vm_steps_per_batch: u64,
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
            sealed_storage_fee_auction_suite: SEALED_STORAGE_FEE_AUCTION_SUITE.to_string(),
            private_storage_rent_bid_suite: PRIVATE_STORAGE_RENT_BID_SUITE.to_string(),
            pq_storage_attestation_suite: PQ_STORAGE_ATTESTATION_SUITE.to_string(),
            low_fee_batching_suite: LOW_FEE_BATCHING_SUITE.to_string(),
            replay_resistance_suite: REPLAY_RESISTANCE_SUITE.to_string(),
            privacy_preserving_state_suite: PRIVACY_PRESERVING_STATE_SUITE.to_string(),
            auction_window_blocks: DEFAULT_AUCTION_WINDOW_BLOCKS,
            rent_epoch_blocks: DEFAULT_RENT_EPOCH_BLOCKS,
            replay_window_blocks: DEFAULT_REPLAY_WINDOW_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_bids_per_auction: DEFAULT_MAX_BIDS_PER_AUCTION,
            max_storage_slots_per_bid: DEFAULT_MAX_STORAGE_SLOTS_PER_BID,
            max_commitments_per_batch: DEFAULT_MAX_COMMITMENTS_PER_BATCH,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            congestion_surcharge_bps: DEFAULT_CONGESTION_SURCHARGE_BPS,
            base_storage_micro_fee: DEFAULT_BASE_STORAGE_MICRO_FEE,
            min_rent_micro_fee_per_slot: DEFAULT_MIN_RENT_MICRO_FEE_PER_SLOT,
            max_vm_steps_per_batch: DEFAULT_MAX_VM_STEPS_PER_BATCH,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("storage fee auction protocol version mismatch".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("storage fee auction schema version mismatch".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("storage fee auction pq security bits below floor".to_string());
        }
        if self.min_privacy_set_size < DEFAULT_MIN_PRIVACY_SET_SIZE {
            return Err("storage fee auction privacy set below floor".to_string());
        }
        if self.max_user_fee_bps > MAX_BPS
            || self.operator_fee_bps > MAX_BPS
            || self.batch_rebate_bps > MAX_BPS
            || self.congestion_surcharge_bps > MAX_BPS
        {
            return Err("storage fee auction basis points exceed MAX_BPS".to_string());
        }
        if self.auction_window_blocks == 0
            || self.rent_epoch_blocks == 0
            || self.replay_window_blocks == 0
            || self.batch_window_blocks == 0
        {
            return Err("storage fee auction windows must be non-zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub auction_rounds: u64,
    pub active_auction_rounds: u64,
    pub storage_rent_bids: u64,
    pub pending_storage_rent_bids: u64,
    pub accepted_storage_rent_bids: u64,
    pub storage_commitments: u64,
    pub applied_storage_commitments: u64,
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
    pub storage_rent_bid_root: String,
    pub storage_commitment_root: String,
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
            auction_round_root: merkle_root(AUCTION_ROUND_SCHEME, &[]),
            storage_rent_bid_root: merkle_root(STORAGE_RENT_BID_SCHEME, &[]),
            storage_commitment_root: merkle_root(STORAGE_COMMITMENT_SCHEME, &[]),
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
    pub domain: StorageAuctionDomain,
    pub contract_id: String,
    pub storage_class_commitment: String,
    pub prior_state_root: String,
    pub target_state_root: String,
    pub start_height: u64,
    pub end_height: u64,
    pub rent_epoch: u64,
    pub capacity_slots: u64,
    pub reserve_micro_fee_per_slot: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AuctionRound {
    pub auction_id: String,
    pub domain: StorageAuctionDomain,
    pub contract_id: String,
    pub storage_class_commitment: String,
    pub prior_state_root: String,
    pub target_state_root: String,
    pub bid_commitment_root: String,
    pub pq_commitment_root: String,
    pub replay_nullifier_root: String,
    pub start_height: u64,
    pub end_height: u64,
    pub rent_epoch: u64,
    pub capacity_slots: u64,
    pub reserve_micro_fee_per_slot: u64,
    pub clearing_micro_fee_per_slot: Option<u64>,
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
        if input.capacity_slots == 0 {
            return Err("auction round capacity must be non-zero".to_string());
        }
        if input.reserve_micro_fee_per_slot < config.min_rent_micro_fee_per_slot {
            return Err("auction reserve rent is below configured floor".to_string());
        }
        if input.privacy_set_size < config.min_privacy_set_size {
            return Err("auction round privacy set below configured floor".to_string());
        }
        let auction_id = auction_round_id(
            input.domain,
            &input.contract_id,
            &input.storage_class_commitment,
            input.rent_epoch,
            input.start_height,
        );
        Ok(Self {
            auction_id,
            domain: input.domain,
            contract_id: input.contract_id,
            storage_class_commitment: input.storage_class_commitment,
            prior_state_root: input.prior_state_root,
            target_state_root: input.target_state_root,
            bid_commitment_root: merkle_root(STORAGE_RENT_BID_SCHEME, &[]),
            pq_commitment_root: merkle_root(STORAGE_COMMITMENT_SCHEME, &[]),
            replay_nullifier_root: merkle_root(REPLAY_NULLIFIER_SCHEME, &[]),
            start_height: input.start_height,
            end_height: input.end_height,
            rent_epoch: input.rent_epoch,
            capacity_slots: input.capacity_slots,
            reserve_micro_fee_per_slot: input.reserve_micro_fee_per_slot,
            clearing_micro_fee_per_slot: None,
            privacy_set_size: input.privacy_set_size,
            status: AuctionStatus::CommitOpen,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "domain": self.domain.as_str(),
            "contract_id": self.contract_id,
            "storage_class_commitment": self.storage_class_commitment,
            "prior_state_root": self.prior_state_root,
            "target_state_root": self.target_state_root,
            "bid_commitment_root": self.bid_commitment_root,
            "pq_commitment_root": self.pq_commitment_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "rent_epoch": self.rent_epoch,
            "capacity_slots": self.capacity_slots,
            "reserve_micro_fee_per_slot": self.reserve_micro_fee_per_slot,
            "clearing_micro_fee_per_slot": self.clearing_micro_fee_per_slot,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct StorageRentBidInput {
    pub auction_id: String,
    pub bidder_commitment: String,
    pub contract_id: String,
    pub sealed_bid_root: String,
    pub sealed_slot_set_root: String,
    pub storage_commitment_root: String,
    pub replay_nullifier_root: String,
    pub max_micro_fee_per_slot: u64,
    pub requested_slots: u64,
    pub rent_epochs: u64,
    pub max_user_fee_bps: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct StorageRentBid {
    pub bid_id: String,
    pub auction_id: String,
    pub bidder_commitment: String,
    pub contract_id: String,
    pub sealed_bid_root: String,
    pub sealed_slot_set_root: String,
    pub storage_commitment_root: String,
    pub replay_nullifier_root: String,
    pub clearing_receipt_root: Option<String>,
    pub max_micro_fee_per_slot: u64,
    pub requested_slots: u64,
    pub rent_epochs: u64,
    pub max_user_fee_bps: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
    pub privacy_set_size: u64,
    pub status: BidStatus,
}

impl StorageRentBid {
    pub fn from_input(config: &Config, input: StorageRentBidInput) -> Result<Self> {
        config.validate()?;
        if input.requested_slots == 0 || input.requested_slots > config.max_storage_slots_per_bid {
            return Err("storage rent bid requested slot count out of range".to_string());
        }
        if input.rent_epochs == 0 {
            return Err("storage rent bid must request at least one rent epoch".to_string());
        }
        if input.max_micro_fee_per_slot < config.min_rent_micro_fee_per_slot {
            return Err("storage rent bid max fee below rent floor".to_string());
        }
        if input.max_user_fee_bps > config.max_user_fee_bps {
            return Err("storage rent bid user fee exceeds configured cap".to_string());
        }
        if input.expires_height <= input.submitted_height {
            return Err("storage rent bid expiry must exceed submitted height".to_string());
        }
        if input.expires_height - input.submitted_height > config.replay_window_blocks {
            return Err("storage rent bid replay window exceeds configured limit".to_string());
        }
        if input.privacy_set_size < config.min_privacy_set_size {
            return Err("storage rent bid privacy set below configured floor".to_string());
        }
        let bid_id = storage_rent_bid_id(
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
            sealed_slot_set_root: input.sealed_slot_set_root,
            storage_commitment_root: input.storage_commitment_root,
            replay_nullifier_root: input.replay_nullifier_root,
            clearing_receipt_root: None,
            max_micro_fee_per_slot: input.max_micro_fee_per_slot,
            requested_slots: input.requested_slots,
            rent_epochs: input.rent_epochs,
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
            "sealed_slot_set_root": self.sealed_slot_set_root,
            "storage_commitment_root": self.storage_commitment_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "clearing_receipt_root": self.clearing_receipt_root,
            "max_micro_fee_per_slot": self.max_micro_fee_per_slot,
            "requested_slots": self.requested_slots,
            "rent_epochs": self.rent_epochs,
            "max_user_fee_bps": self.max_user_fee_bps,
            "submitted_height": self.submitted_height,
            "expires_height": self.expires_height,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct StorageCommitment {
    pub commitment_id: String,
    pub auction_id: String,
    pub bid_id: String,
    pub contract_id: String,
    pub storage_root_before: String,
    pub storage_root_after: String,
    pub sealed_slot_delta_root: String,
    pub rent_obligation_root: String,
    pub pq_attestation_id: String,
    pub attestor_quorum_root: String,
    pub pq_security_bits: u16,
    pub status: CommitmentStatus,
}

impl StorageCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "contract_id": self.contract_id,
            "storage_root_before": self.storage_root_before,
            "storage_root_after": self.storage_root_after,
            "sealed_slot_delta_root": self.sealed_slot_delta_root,
            "rent_obligation_root": self.rent_obligation_root,
            "pq_attestation_id": self.pq_attestation_id,
            "attestor_quorum_root": self.attestor_quorum_root,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqStorageAttestation {
    pub attestation_id: String,
    pub commitment_id: String,
    pub auction_id: String,
    pub bid_id: String,
    pub attestor_set_root: String,
    pub transcript_root: String,
    pub signature_bundle_root: String,
    pub storage_commitment_root: String,
    pub min_pq_security_bits: u16,
    pub attested_height: u64,
    pub status: CommitmentStatus,
}

impl PqStorageAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "commitment_id": self.commitment_id,
            "auction_id": self.auction_id,
            "bid_id": self.bid_id,
            "attestor_set_root": self.attestor_set_root,
            "transcript_root": self.transcript_root,
            "signature_bundle_root": self.signature_bundle_root,
            "storage_commitment_root": self.storage_commitment_root,
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
    pub aggregate_requested_slots: u64,
    pub aggregate_rent_epochs: u64,
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
            "aggregate_requested_slots": self.aggregate_requested_slots,
            "aggregate_rent_epochs": self.aggregate_rent_epochs,
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
    pub clearing_micro_fee_per_slot: u64,
    pub settled_slots: u64,
    pub rent_obligation_root: String,
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
            "clearing_micro_fee_per_slot": self.clearing_micro_fee_per_slot,
            "settled_slots": self.settled_slots,
            "rent_obligation_root": self.rent_obligation_root,
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
    pub private_storage_commitment_root: String,
    pub rent_liability_root: String,
    pub replay_guard_root: String,
    pub accepted_bid_count: u64,
    pub settled_slots: u64,
    pub height: u64,
}

impl PublicStateSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "auction_id": self.auction_id,
            "public_state_root": self.public_state_root,
            "private_storage_commitment_root": self.private_storage_commitment_root,
            "rent_liability_root": self.rent_liability_root,
            "replay_guard_root": self.replay_guard_root,
            "accepted_bid_count": self.accepted_bid_count,
            "settled_slots": self.settled_slots,
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
    pub storage_rent_bids: BTreeMap<String, StorageRentBid>,
    pub storage_commitments: BTreeMap<String, StorageCommitment>,
    pub pq_attestations: BTreeMap<String, PqStorageAttestation>,
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
            storage_rent_bids: BTreeMap::new(),
            storage_commitments: BTreeMap::new(),
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

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let auction = AuctionRound::from_input(
            &state.config,
            AuctionRoundInput {
                domain: StorageAuctionDomain::ConfidentialVault,
                contract_id: "contract-private-vault".to_string(),
                storage_class_commitment: demo_hash("storage-class-hot-confidential"),
                prior_state_root: demo_hash("prior-storage-state"),
                target_state_root: demo_hash("target-storage-state"),
                start_height: DEVNET_HEIGHT,
                end_height: DEVNET_HEIGHT + 32,
                rent_epoch: DEVNET_EPOCH,
                capacity_slots: 24_576,
                reserve_micro_fee_per_slot: 4,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            },
        )
        .expect("devnet auction fixture must be valid");
        let bid = StorageRentBid::from_input(
            &state.config,
            StorageRentBidInput {
                auction_id: auction.auction_id.clone(),
                bidder_commitment: demo_hash("bidder-alpha"),
                contract_id: auction.contract_id.clone(),
                sealed_bid_root: demo_hash("sealed-bid-alpha"),
                sealed_slot_set_root: demo_hash("sealed-slot-set-alpha"),
                storage_commitment_root: demo_hash("storage-commitment-alpha"),
                replay_nullifier_root: demo_hash("replay-nullifier-alpha"),
                max_micro_fee_per_slot: 7,
                requested_slots: 8_192,
                rent_epochs: 3,
                max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
                submitted_height: DEVNET_HEIGHT + 1,
                expires_height: DEVNET_HEIGHT + 65,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            },
        )
        .expect("devnet bid fixture must be valid");
        let commitment_id = storage_commitment_id(
            &auction.auction_id,
            &bid.bid_id,
            &bid.storage_commitment_root,
            DEVNET_HEIGHT + 2,
        );
        let attestation_id = pq_storage_attestation_id(
            &commitment_id,
            &auction.auction_id,
            &bid.bid_id,
            DEVNET_HEIGHT + 3,
        );
        let replay = ReplayNullifier {
            nullifier_id: replay_nullifier_id(
                &auction.auction_id,
                &bid.bid_id,
                &bid.bidder_commitment,
                &bid.sealed_bid_root,
            ),
            auction_id: auction.auction_id.clone(),
            bid_id: bid.bid_id.clone(),
            bidder_commitment: bid.bidder_commitment.clone(),
            sealed_bid_root: bid.sealed_bid_root.clone(),
            first_seen_height: DEVNET_HEIGHT + 1,
            expires_height: DEVNET_HEIGHT + DEFAULT_REPLAY_WINDOW_BLOCKS,
            duplicate_evidence_root: None,
            status: ReplayStatus::Consumed,
        };
        let commitment = StorageCommitment {
            commitment_id: commitment_id.clone(),
            auction_id: auction.auction_id.clone(),
            bid_id: bid.bid_id.clone(),
            contract_id: auction.contract_id.clone(),
            storage_root_before: auction.prior_state_root.clone(),
            storage_root_after: auction.target_state_root.clone(),
            sealed_slot_delta_root: demo_hash("sealed-slot-delta-alpha"),
            rent_obligation_root: demo_hash("rent-obligation-alpha"),
            pq_attestation_id: attestation_id.clone(),
            attestor_quorum_root: demo_hash("attestor-quorum-alpha"),
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            status: CommitmentStatus::Applied,
        };
        let attestation = PqStorageAttestation {
            attestation_id: attestation_id.clone(),
            commitment_id: commitment_id.clone(),
            auction_id: auction.auction_id.clone(),
            bid_id: bid.bid_id.clone(),
            attestor_set_root: demo_hash("attestor-set-alpha"),
            transcript_root: demo_hash("pq-transcript-alpha"),
            signature_bundle_root: demo_hash("pq-signature-bundle-alpha"),
            storage_commitment_root: bid.storage_commitment_root.clone(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            attested_height: DEVNET_HEIGHT + 3,
            status: CommitmentStatus::Applied,
        };
        let batch_id = low_fee_batch_id(
            &auction.auction_id,
            &[bid.bid_id.clone()],
            DEVNET_HEIGHT + 4,
        );
        let batch = LowFeeBatch {
            batch_id: batch_id.clone(),
            auction_id: auction.auction_id.clone(),
            bid_ids: vec![bid.bid_id.clone()],
            bid_commitment_root: record_root(STORAGE_RENT_BID_SCHEME, &[bid.public_record()]),
            replay_nullifier_root: record_root(REPLAY_NULLIFIER_SCHEME, &[replay.public_record()]),
            pq_attestation_root: record_root(PQ_ATTESTATION_SCHEME, &[attestation.public_record()]),
            aggregate_requested_slots: bid.requested_slots,
            aggregate_rent_epochs: bid.rent_epochs,
            aggregate_micro_fee_cap: bid.max_micro_fee_per_slot
                * bid.requested_slots
                * bid.rent_epochs,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            opened_height: DEVNET_HEIGHT + 2,
            sealed_height: Some(DEVNET_HEIGHT + 4),
            status: BatchStatus::Settled,
        };
        let settlement = AuctionSettlement {
            settlement_id: auction_settlement_id(&auction.auction_id, &batch_id, DEVNET_HEIGHT + 5),
            auction_id: auction.auction_id.clone(),
            batch_id: batch_id.clone(),
            accepted_bid_root: record_root(STORAGE_RENT_BID_SCHEME, &[bid.public_record()]),
            refunded_bid_root: merkle_root(STORAGE_RENT_BID_SCHEME, &[]),
            clearing_micro_fee_per_slot: 6,
            settled_slots: bid.requested_slots,
            rent_obligation_root: commitment.rent_obligation_root.clone(),
            post_state_root: auction.target_state_root.clone(),
            settlement_height: DEVNET_HEIGHT + 5,
        };
        let snapshot = PublicStateSnapshot {
            snapshot_id: public_state_snapshot_id(&auction.auction_id, DEVNET_HEIGHT + 5),
            auction_id: auction.auction_id.clone(),
            public_state_root: demo_hash("privacy-preserving-public-storage-state"),
            private_storage_commitment_root: commitment.storage_root_after.clone(),
            rent_liability_root: commitment.rent_obligation_root.clone(),
            replay_guard_root: replay.nullifier_id.clone(),
            accepted_bid_count: 1,
            settled_slots: bid.requested_slots,
            height: DEVNET_HEIGHT + 5,
        };
        let mut accepted_bid = bid;
        accepted_bid.status = BidStatus::Accepted;
        accepted_bid.clearing_receipt_root = Some(settlement.settlement_id.clone());
        let mut settled_auction = auction;
        settled_auction.status = AuctionStatus::Settled;
        settled_auction.clearing_micro_fee_per_slot = Some(settlement.clearing_micro_fee_per_slot);
        state.insert_auction_round(settled_auction).unwrap();
        state.insert_storage_rent_bid(accepted_bid).unwrap();
        state.insert_replay_nullifier(replay).unwrap();
        state.insert_storage_commitment(commitment).unwrap();
        state.insert_pq_attestation(attestation).unwrap();
        state.insert_low_fee_batch(batch).unwrap();
        state.insert_auction_settlement(settlement).unwrap();
        state.insert_public_state_snapshot(snapshot).unwrap();
        let fixture_id = devnet_fixture_id("sealed-storage-fee-auction-demo", DEVNET_HEIGHT);
        let expected_state_root = state.state_root();
        state.devnet_fixtures.insert(
            fixture_id.clone(),
            DevnetFixture {
                fixture_id,
                description: "sealed storage fee auction with private rent bid and pq commitment"
                    .to_string(),
                auction_id: state
                    .auction_rounds
                    .keys()
                    .next()
                    .cloned()
                    .unwrap_or_default(),
                bid_id: state
                    .storage_rent_bids
                    .keys()
                    .next()
                    .cloned()
                    .unwrap_or_default(),
                batch_id,
                expected_state_root,
            },
        );
        state.recompute_counters();
        state.recompute_roots();
        state
    }

    pub fn insert_auction_round(&mut self, auction: AuctionRound) -> Result<()> {
        self.config.validate()?;
        if self.auction_rounds.contains_key(&auction.auction_id) {
            return Err("duplicate storage auction round".to_string());
        }
        self.auction_rounds
            .insert(auction.auction_id.clone(), auction);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_storage_rent_bid(&mut self, bid: StorageRentBid) -> Result<()> {
        self.config.validate()?;
        if !self.auction_rounds.contains_key(&bid.auction_id) {
            return Err("storage rent bid references unknown auction".to_string());
        }
        if self.storage_rent_bids.contains_key(&bid.bid_id) {
            return Err("duplicate storage rent bid".to_string());
        }
        let auction_bid_count = self
            .storage_rent_bids
            .values()
            .filter(|existing| existing.auction_id == bid.auction_id)
            .count();
        if auction_bid_count >= self.config.max_bids_per_auction {
            return Err("storage rent auction bid cap reached".to_string());
        }
        self.storage_rent_bids.insert(bid.bid_id.clone(), bid);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_storage_commitment(&mut self, commitment: StorageCommitment) -> Result<()> {
        if commitment.pq_security_bits < self.config.min_pq_security_bits {
            return Err("storage commitment pq security bits below configured floor".to_string());
        }
        if !self.storage_rent_bids.contains_key(&commitment.bid_id) {
            return Err("storage commitment references unknown bid".to_string());
        }
        self.storage_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        self.recompute_counters();
        self.recompute_roots();
        Ok(())
    }

    pub fn insert_pq_attestation(&mut self, attestation: PqStorageAttestation) -> Result<()> {
        if attestation.min_pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq storage attestation security bits below configured floor".to_string());
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
            return Err("low-fee storage batch exceeds commitment cap".to_string());
        }
        if batch.operator_fee_bps > self.config.operator_fee_bps {
            return Err("low-fee storage batch operator fee exceeds cap".to_string());
        }
        if batch.batch_rebate_bps > MAX_BPS {
            return Err("low-fee storage batch rebate exceeds MAX_BPS".to_string());
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
            "kind": "private_l2_pq_confidential_contract_sealed_storage_fee_auction_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "sealed_storage_fee_auction_suite": SEALED_STORAGE_FEE_AUCTION_SUITE,
            "private_storage_rent_bid_suite": PRIVATE_STORAGE_RENT_BID_SUITE,
            "pq_storage_attestation_suite": PQ_STORAGE_ATTESTATION_SUITE,
            "low_fee_batching_suite": LOW_FEE_BATCHING_SUITE,
            "replay_resistance_suite": REPLAY_RESISTANCE_SUITE,
            "privacy_preserving_state_suite": PRIVACY_PRESERVING_STATE_SUITE,
            "config": self.config,
            "counters": self.counters,
            "roots": self.roots,
            "auction_rounds": self.auction_rounds.values().map(AuctionRound::public_record).collect::<Vec<_>>(),
            "storage_rent_bids": self.storage_rent_bids.values().map(StorageRentBid::public_record).collect::<Vec<_>>(),
            "storage_commitments": self.storage_commitments.values().map(StorageCommitment::public_record).collect::<Vec<_>>(),
            "pq_attestations": self.pq_attestations.values().map(PqStorageAttestation::public_record).collect::<Vec<_>>(),
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
            storage_rent_bids: self.storage_rent_bids.len() as u64,
            pending_storage_rent_bids: self
                .storage_rent_bids
                .values()
                .filter(|bid| bid.status.pending())
                .count() as u64,
            accepted_storage_rent_bids: self
                .storage_rent_bids
                .values()
                .filter(|bid| bid.status == BidStatus::Accepted)
                .count() as u64,
            storage_commitments: self.storage_commitments.len() as u64,
            applied_storage_commitments: self
                .storage_commitments
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
                AUCTION_ROUND_SCHEME,
                self.auction_rounds
                    .values()
                    .map(AuctionRound::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            storage_rent_bid_root: record_root(
                STORAGE_RENT_BID_SCHEME,
                self.storage_rent_bids
                    .values()
                    .map(StorageRentBid::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            storage_commitment_root: record_root(
                STORAGE_COMMITMENT_SCHEME,
                self.storage_commitments
                    .values()
                    .map(StorageCommitment::public_record)
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            pq_attestation_root: record_root(
                PQ_ATTESTATION_SCHEME,
                self.pq_attestations
                    .values()
                    .map(PqStorageAttestation::public_record)
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
    domain: StorageAuctionDomain,
    contract_id: &str,
    storage_class_commitment: &str,
    rent_epoch: u64,
    start_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-FEE-AUCTION:AUCTION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain.as_str()),
            HashPart::Str(contract_id),
            HashPart::Str(storage_class_commitment),
            HashPart::U64(rent_epoch),
            HashPart::U64(start_height),
        ],
        32,
    )
}

pub fn storage_rent_bid_id(
    auction_id: &str,
    bidder_commitment: &str,
    sealed_bid_root: &str,
    submitted_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-FEE-AUCTION:BID-ID",
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

pub fn storage_commitment_id(
    auction_id: &str,
    bid_id: &str,
    storage_commitment_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-FEE-AUCTION:COMMITMENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(auction_id),
            HashPart::Str(bid_id),
            HashPart::Str(storage_commitment_root),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn pq_storage_attestation_id(
    commitment_id: &str,
    auction_id: &str,
    bid_id: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-FEE-AUCTION:PQ-ATTESTATION-ID",
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-FEE-AUCTION:REPLAY-NULLIFIER-ID",
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
        "sealed-storage-fee-auction-low-fee-batch-bid-id-root-v1",
        &bid_ids.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-FEE-AUCTION:LOW-FEE-BATCH-ID",
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-FEE-AUCTION:SETTLEMENT-ID",
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-FEE-AUCTION:PUBLIC-STATE-SNAPSHOT-ID",
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-FEE-AUCTION:DEVNET-FIXTURE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn detect_replay_conflicts(bids: &[StorageRentBid]) -> BTreeSet<String> {
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

pub fn effective_micro_fee_cap(config: &Config, bid: &StorageRentBid, congestion_bps: u64) -> u64 {
    let congestion = congestion_bps.min(config.congestion_surcharge_bps);
    let surcharge = bid
        .max_micro_fee_per_slot
        .saturating_mul(congestion)
        .saturating_div(MAX_BPS);
    bid.max_micro_fee_per_slot.saturating_add(surcharge)
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-FEE-AUCTION:PUBLIC-STATE-ROOT",
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
                "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-FEE-AUCTION:RECORD-LEAF",
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-FEE-AUCTION:STATE-ROOT",
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
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-FEE-AUCTION:DEMO-HASH",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}
