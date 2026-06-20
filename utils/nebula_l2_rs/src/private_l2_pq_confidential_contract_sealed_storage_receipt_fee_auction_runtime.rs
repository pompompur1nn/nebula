use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedStorageReceiptFeeAuctionRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractSealedStorageReceiptFeeAuctionRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STORAGE_RECEIPT_FEE_AUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-sealed-storage-receipt-fee-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STORAGE_RECEIPT_FEE_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const STORAGE_RECEIPT_FEE_AUCTION_SUITE: &str =
    "sealed-confidential-smart-contract-storage-receipt-fee-auction-v1";
pub const ROOTS_ONLY_PUBLIC_RECORD_SUITE: &str =
    "roots-only-public-storage-receipt-fee-auction-record-v1";
pub const AUCTION_ROUND_SCHEME: &str = "sealed-storage-receipt-fee-auction-round-root-v1";
pub const SEALED_BID_SCHEME: &str = "sealed-storage-receipt-fee-auction-bid-root-v1";
pub const RECEIPT_LOT_SCHEME: &str = "encrypted-storage-receipt-lot-root-v1";
pub const PQ_ATTESTATION_SCHEME: &str = "pq-storage-auction-attestation-root-v1";
pub const NULLIFIER_SCHEME: &str = "storage-auction-replay-nullifier-root-v1";
pub const SETTLEMENT_SCHEME: &str = "fast-storage-auction-settlement-root-v1";
pub const ACCOUNTING_SCHEME: &str = "storage-auction-accounting-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "storage-auction-roots-only-public-record-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 5_811_456;
pub const DEVNET_EPOCH: u64 = 11_350;
pub const DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 32;
pub const DEFAULT_REVEAL_GRACE_BLOCKS: u64 = 4;
pub const DEFAULT_FAST_SETTLEMENT_BLOCKS: u64 = 2;
pub const DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 128;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_BIDS_PER_ROUND: usize = 12_288;
pub const DEFAULT_MAX_LOTS_PER_SETTLEMENT: usize = 4_096;
pub const DEFAULT_MAX_RECEIPT_BYTES_PER_SETTLEMENT: u64 = 8_388_608;
pub const DEFAULT_RESERVE_MICRO_FEE: u64 = 1;
pub const DEFAULT_CLEARING_REBATE_BPS: u64 = 12;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 3;
pub const DEFAULT_CONGESTION_SURCHARGE_BPS: u64 = 8;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_FAST_FINALITY_QUORUM_BPS: u64 = 8_100;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionLane {
    DefiHotPath,
    LendingCollateral,
    OracleRefresh,
    BridgeEscrow,
    GovernanceTimelock,
    AccountRecovery,
    EmergencyRetention,
}

impl AuctionLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DefiHotPath => "defi_hot_path",
            Self::LendingCollateral => "lending_collateral",
            Self::OracleRefresh => "oracle_refresh",
            Self::BridgeEscrow => "bridge_escrow",
            Self::GovernanceTimelock => "governance_timelock",
            Self::AccountRecovery => "account_recovery",
            Self::EmergencyRetention => "emergency_retention",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyRetention => 10_000,
            Self::AccountRecovery => 9_650,
            Self::BridgeEscrow => 9_250,
            Self::OracleRefresh => 8_900,
            Self::LendingCollateral => 8_450,
            Self::DefiHotPath => 8_250,
            Self::GovernanceTimelock => 7_200,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundStatus {
    Announced,
    CommitOpen,
    CommitClosed,
    PqAttested,
    Settling,
    Settled,
    Cancelled,
    Expired,
}

impl RoundStatus {
    pub fn accepts_bids(self) -> bool {
        matches!(self, Self::Announced | Self::CommitOpen)
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Announced
                | Self::CommitOpen
                | Self::CommitClosed
                | Self::PqAttested
                | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Sealed,
    NullifierReserved,
    LotBound,
    Attested,
    Accepted,
    Outbid,
    Refunded,
    DuplicateRejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LotStatus {
    Encrypted,
    BidBound,
    ExecutorAttested,
    VerifierAttested,
    SettlementQueued,
    Settled,
    Challenged,
    Rejected,
}

impl LotStatus {
    pub fn settleable(self) -> bool {
        matches!(
            self,
            Self::BidBound | Self::ExecutorAttested | Self::VerifierAttested
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationRole {
    Executor,
    Verifier,
    Watchtower,
    FeeAuctioneer,
}

impl AttestationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Executor => "executor",
            Self::Verifier => "verifier",
            Self::Watchtower => "watchtower",
            Self::FeeAuctioneer => "fee_auctioneer",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Queued,
    PqQuorum,
    FastFinal,
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
    pub auction_suite: String,
    pub roots_only_public_record_suite: String,
    pub auction_window_blocks: u64,
    pub reveal_grace_blocks: u64,
    pub fast_settlement_blocks: u64,
    pub replay_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_bids_per_round: usize,
    pub max_lots_per_settlement: usize,
    pub max_receipt_bytes_per_settlement: u64,
    pub reserve_micro_fee: u64,
    pub clearing_rebate_bps: u64,
    pub operator_fee_bps: u64,
    pub congestion_surcharge_bps: u64,
    pub quorum_bps: u64,
    pub fast_finality_quorum_bps: u64,
    pub require_roots_only_public_records: bool,
    pub require_replay_nullifier: bool,
    pub require_pq_attestation: bool,
    pub prefer_low_fee_clearing: bool,
    pub prefer_fast_receipt_settlement: bool,
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
            auction_suite: STORAGE_RECEIPT_FEE_AUCTION_SUITE.to_string(),
            roots_only_public_record_suite: ROOTS_ONLY_PUBLIC_RECORD_SUITE.to_string(),
            auction_window_blocks: DEFAULT_AUCTION_WINDOW_BLOCKS,
            reveal_grace_blocks: DEFAULT_REVEAL_GRACE_BLOCKS,
            fast_settlement_blocks: DEFAULT_FAST_SETTLEMENT_BLOCKS,
            replay_window_blocks: DEFAULT_REPLAY_WINDOW_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_bids_per_round: DEFAULT_MAX_BIDS_PER_ROUND,
            max_lots_per_settlement: DEFAULT_MAX_LOTS_PER_SETTLEMENT,
            max_receipt_bytes_per_settlement: DEFAULT_MAX_RECEIPT_BYTES_PER_SETTLEMENT,
            reserve_micro_fee: DEFAULT_RESERVE_MICRO_FEE,
            clearing_rebate_bps: DEFAULT_CLEARING_REBATE_BPS,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            congestion_surcharge_bps: DEFAULT_CONGESTION_SURCHARGE_BPS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            fast_finality_quorum_bps: DEFAULT_FAST_FINALITY_QUORUM_BPS,
            require_roots_only_public_records: true,
            require_replay_nullifier: true,
            require_pq_attestation: true,
            prefer_low_fee_clearing: true,
            prefer_fast_receipt_settlement: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unsupported sealed storage receipt fee auction protocol".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("unsupported sealed storage receipt fee auction schema".to_string());
        }
        if self.auction_window_blocks == 0 || self.fast_settlement_blocks == 0 {
            return Err("auction and settlement windows must be non-zero".to_string());
        }
        if self.replay_window_blocks < self.auction_window_blocks {
            return Err("replay window must cover the auction window".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("privacy set bounds are invalid".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("post-quantum security floor is too low".to_string());
        }
        if self.max_bids_per_round == 0 || self.max_lots_per_settlement == 0 {
            return Err("auction capacity limits must be non-zero".to_string());
        }
        if self.clearing_rebate_bps > MAX_BPS
            || self.operator_fee_bps > MAX_BPS
            || self.congestion_surcharge_bps > MAX_BPS
            || self.quorum_bps > MAX_BPS
            || self.fast_finality_quorum_bps > MAX_BPS
        {
            return Err("basis point value exceeds MAX_BPS".to_string());
        }
        if self.fast_finality_quorum_bps < self.quorum_bps {
            return Err("fast finality quorum cannot be below base quorum".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("config serializes")
    }

    pub fn root(&self) -> String {
        payload_root("CONFIG", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub next_round_index: u64,
    pub next_bid_index: u64,
    pub next_lot_index: u64,
    pub next_attestation_index: u64,
    pub next_settlement_index: u64,
    pub rounds_opened: u64,
    pub sealed_bids_submitted: u64,
    pub encrypted_lots_committed: u64,
    pub pq_attestations: u64,
    pub duplicate_nullifiers_rejected: u64,
    pub settlements_finalized: u64,
    pub accepted_bids: u64,
    pub outbid_refunds: u64,
    pub total_receipt_bytes_settled: u64,
    pub total_fee_micro_units: u128,
    pub total_rebate_micro_units: u128,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            next_round_index: 1,
            next_bid_index: 1,
            next_lot_index: 1,
            next_attestation_index: 1,
            next_settlement_index: 1,
            rounds_opened: 0,
            sealed_bids_submitted: 0,
            encrypted_lots_committed: 0,
            pq_attestations: 0,
            duplicate_nullifiers_rejected: 0,
            settlements_finalized: 0,
            accepted_bids: 0,
            outbid_refunds: 0,
            total_receipt_bytes_settled: 0,
            total_fee_micro_units: 0,
            total_rebate_micro_units: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("counters serialize")
    }

    pub fn root(&self) -> String {
        payload_root("COUNTERS", &self.public_record())
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub auction_round_root: String,
    pub sealed_bid_root: String,
    pub encrypted_lot_root: String,
    pub pq_attestation_root: String,
    pub replay_nullifier_root: String,
    pub settlement_root: String,
    pub accounting_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("roots serialize")
    }

    pub fn root(&self) -> String {
        payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AuctionRoundInput {
    pub lane: AuctionLane,
    pub storage_namespace_root: String,
    pub eligible_contract_set_root: String,
    pub capacity_receipt_bytes: u64,
    pub capacity_storage_keys: u64,
    pub reserve_micro_fee: u64,
    pub pq_policy_root: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AuctionRound {
    pub round_id: String,
    pub round_index: u64,
    pub lane: AuctionLane,
    pub start_height: u64,
    pub commit_end_height: u64,
    pub settlement_deadline_height: u64,
    pub status: RoundStatus,
    pub storage_namespace_root: String,
    pub eligible_contract_set_root: String,
    pub capacity_receipt_bytes: u64,
    pub capacity_storage_keys: u64,
    pub reserve_micro_fee: u64,
    pub privacy_set_size: u64,
    pub pq_policy_root: String,
}

impl AuctionRound {
    pub fn from_input(
        round_index: u64,
        height: u64,
        config: &Config,
        input: AuctionRoundInput,
    ) -> Result<Self> {
        require_non_empty("storage_namespace_root", &input.storage_namespace_root)?;
        require_non_empty(
            "eligible_contract_set_root",
            &input.eligible_contract_set_root,
        )?;
        require_non_empty("pq_policy_root", &input.pq_policy_root)?;
        let round_id = auction_round_id(
            input.lane,
            &input.storage_namespace_root,
            &input.eligible_contract_set_root,
            round_index,
        );
        Ok(Self {
            round_id,
            round_index,
            lane: input.lane,
            start_height: height,
            commit_end_height: height.saturating_add(config.auction_window_blocks),
            settlement_deadline_height: height
                .saturating_add(config.auction_window_blocks)
                .saturating_add(config.reveal_grace_blocks)
                .saturating_add(config.fast_settlement_blocks),
            status: RoundStatus::CommitOpen,
            storage_namespace_root: input.storage_namespace_root,
            eligible_contract_set_root: input.eligible_contract_set_root,
            capacity_receipt_bytes: input.capacity_receipt_bytes,
            capacity_storage_keys: input.capacity_storage_keys,
            reserve_micro_fee: input.reserve_micro_fee.max(config.reserve_micro_fee),
            privacy_set_size: input
                .capacity_storage_keys
                .saturating_mul(input.capacity_receipt_bytes.max(1))
                .max(config.min_privacy_set_size),
            pq_policy_root: input.pq_policy_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "round_id": self.round_id,
            "round_index": self.round_index,
            "lane": self.lane.as_str(),
            "start_height": self.start_height,
            "commit_end_height": self.commit_end_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "status": self.status,
            "storage_namespace_root": self.storage_namespace_root,
            "eligible_contract_set_root": self.eligible_contract_set_root,
            "capacity_receipt_bytes": self.capacity_receipt_bytes,
            "capacity_storage_keys": self.capacity_storage_keys,
            "reserve_micro_fee": self.reserve_micro_fee,
            "privacy_set_size": self.privacy_set_size,
            "pq_policy_root": self.pq_policy_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedBidInput {
    pub round_id: String,
    pub contract_commitment: String,
    pub bidder_note_commitment: String,
    pub sealed_bid_root: String,
    pub max_micro_fee: u64,
    pub receipt_bytes_upper_bound: u64,
    pub storage_keys_upper_bound: u64,
    pub replay_nullifier_root: String,
    pub settlement_preference_root: String,
    pub bid_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedStorageReceiptFeeBid {
    pub bid_id: String,
    pub bid_index: u64,
    pub round_id: String,
    pub contract_commitment: String,
    pub bidder_note_commitment: String,
    pub sealed_bid_root: String,
    pub max_micro_fee: u64,
    pub quoted_micro_fee: u64,
    pub receipt_bytes_upper_bound: u64,
    pub storage_keys_upper_bound: u64,
    pub privacy_set_size: u64,
    pub replay_nullifier_root: String,
    pub settlement_preference_root: String,
    pub status: BidStatus,
    pub expires_height: u64,
}

impl SealedStorageReceiptFeeBid {
    pub fn from_input(
        bid_index: u64,
        round: &AuctionRound,
        config: &Config,
        input: SealedBidInput,
    ) -> Result<Self> {
        require_non_empty("contract_commitment", &input.contract_commitment)?;
        require_non_empty("bidder_note_commitment", &input.bidder_note_commitment)?;
        require_non_empty("sealed_bid_root", &input.sealed_bid_root)?;
        require_non_empty("replay_nullifier_root", &input.replay_nullifier_root)?;
        require_non_empty(
            "settlement_preference_root",
            &input.settlement_preference_root,
        )?;
        if input.max_micro_fee < round.reserve_micro_fee {
            return Err("sealed bid is below reserve fee".to_string());
        }
        let privacy_set_size = input
            .receipt_bytes_upper_bound
            .saturating_mul(input.storage_keys_upper_bound.max(1))
            .max(config.min_privacy_set_size);
        let quoted_micro_fee = estimate_clearing_fee_micro_units(
            config,
            round.lane,
            input.max_micro_fee,
            input.receipt_bytes_upper_bound,
        );
        Ok(Self {
            bid_id: sealed_bid_id(
                &input.round_id,
                &input.contract_commitment,
                &input.sealed_bid_root,
                input.bid_nonce,
            ),
            bid_index,
            round_id: input.round_id,
            contract_commitment: input.contract_commitment,
            bidder_note_commitment: input.bidder_note_commitment,
            sealed_bid_root: input.sealed_bid_root,
            max_micro_fee: input.max_micro_fee,
            quoted_micro_fee,
            receipt_bytes_upper_bound: input.receipt_bytes_upper_bound,
            storage_keys_upper_bound: input.storage_keys_upper_bound,
            privacy_set_size,
            replay_nullifier_root: input.replay_nullifier_root,
            settlement_preference_root: input.settlement_preference_root,
            status: BidStatus::NullifierReserved,
            expires_height: round.settlement_deadline_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "bid_index": self.bid_index,
            "round_id": self.round_id,
            "contract_commitment": self.contract_commitment,
            "bidder_note_commitment": self.bidder_note_commitment,
            "sealed_bid_root": self.sealed_bid_root,
            "max_micro_fee": self.max_micro_fee,
            "quoted_micro_fee": self.quoted_micro_fee,
            "receipt_bytes_upper_bound": self.receipt_bytes_upper_bound,
            "storage_keys_upper_bound": self.storage_keys_upper_bound,
            "privacy_set_size": self.privacy_set_size,
            "replay_nullifier_root": self.replay_nullifier_root,
            "settlement_preference_root": self.settlement_preference_root,
            "status": self.status,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReceiptLotInput {
    pub round_id: String,
    pub bid_id: String,
    pub encrypted_receipt_root: String,
    pub encrypted_storage_delta_root: String,
    pub pre_storage_root: String,
    pub post_storage_root: String,
    pub receipt_bytes: u64,
    pub storage_keys_touched: u64,
    pub lot_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct EncryptedStorageReceiptLot {
    pub lot_id: String,
    pub lot_index: u64,
    pub round_id: String,
    pub bid_id: String,
    pub encrypted_receipt_root: String,
    pub encrypted_storage_delta_root: String,
    pub pre_storage_root: String,
    pub post_storage_root: String,
    pub receipt_bytes: u64,
    pub storage_keys_touched: u64,
    pub status: LotStatus,
}

impl EncryptedStorageReceiptLot {
    pub fn from_input(lot_index: u64, input: ReceiptLotInput) -> Result<Self> {
        require_non_empty("encrypted_receipt_root", &input.encrypted_receipt_root)?;
        require_non_empty(
            "encrypted_storage_delta_root",
            &input.encrypted_storage_delta_root,
        )?;
        require_non_empty("pre_storage_root", &input.pre_storage_root)?;
        require_non_empty("post_storage_root", &input.post_storage_root)?;
        Ok(Self {
            lot_id: receipt_lot_id(
                &input.round_id,
                &input.bid_id,
                &input.post_storage_root,
                input.lot_nonce,
            ),
            lot_index,
            round_id: input.round_id,
            bid_id: input.bid_id,
            encrypted_receipt_root: input.encrypted_receipt_root,
            encrypted_storage_delta_root: input.encrypted_storage_delta_root,
            pre_storage_root: input.pre_storage_root,
            post_storage_root: input.post_storage_root,
            receipt_bytes: input.receipt_bytes,
            storage_keys_touched: input.storage_keys_touched,
            status: LotStatus::BidBound,
        })
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("receipt lot serializes")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqAuctionAttestationInput {
    pub lot_id: String,
    pub role: AttestationRole,
    pub committee_id: String,
    pub signer_set_root: String,
    pub attested_receipt_root: String,
    pub pq_public_key_digest: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub attestation_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqAuctionAttestation {
    pub attestation_id: String,
    pub attestation_index: u64,
    pub lot_id: String,
    pub role: AttestationRole,
    pub committee_id: String,
    pub signer_set_root: String,
    pub attested_receipt_root: String,
    pub pq_public_key_digest: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub issued_height: u64,
}

impl PqAuctionAttestation {
    pub fn from_input(
        attestation_index: u64,
        height: u64,
        config: &Config,
        input: PqAuctionAttestationInput,
    ) -> Result<Self> {
        require_non_empty("committee_id", &input.committee_id)?;
        require_non_empty("signer_set_root", &input.signer_set_root)?;
        require_non_empty("attested_receipt_root", &input.attested_receipt_root)?;
        require_non_empty("pq_public_key_digest", &input.pq_public_key_digest)?;
        require_non_empty("pq_signature_root", &input.pq_signature_root)?;
        if input.pq_security_bits < config.min_pq_security_bits {
            return Err("PQ attestation security is below runtime floor".to_string());
        }
        if input.quorum_weight_bps < config.quorum_bps {
            return Err("PQ attestation quorum is below runtime floor".to_string());
        }
        Ok(Self {
            attestation_id: pq_auction_attestation_id(
                &input.lot_id,
                &input.committee_id,
                input.role,
                input.attestation_nonce,
            ),
            attestation_index,
            lot_id: input.lot_id,
            role: input.role,
            committee_id: input.committee_id,
            signer_set_root: input.signer_set_root,
            attested_receipt_root: input.attested_receipt_root,
            pq_public_key_digest: input.pq_public_key_digest,
            pq_signature_root: input.pq_signature_root,
            pq_security_bits: input.pq_security_bits,
            quorum_weight_bps: input.quorum_weight_bps,
            issued_height: height,
        })
    }

    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("attestation serializes")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FastSettlementInput {
    pub round_id: String,
    pub lot_ids: Vec<String>,
    pub operator_commitment: String,
    pub clearing_price_root: String,
    pub settlement_lane_root: String,
    pub accounting_delta_root: String,
    pub settlement_nonce: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct FastStorageReceiptSettlement {
    pub settlement_id: String,
    pub settlement_index: u64,
    pub round_id: String,
    pub lot_ids: Vec<String>,
    pub operator_commitment: String,
    pub clearing_price_root: String,
    pub settlement_lane_root: String,
    pub accounting_delta_root: String,
    pub total_receipt_bytes: u64,
    pub total_storage_keys: u64,
    pub total_fee_micro_units: u128,
    pub total_rebate_micro_units: u128,
    pub status: SettlementStatus,
    pub settled_height: u64,
}

impl FastStorageReceiptSettlement {
    pub fn public_record(&self) -> Value {
        serde_json::to_value(self).expect("settlement serializes")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub epoch: u64,
    pub auction_rounds: BTreeMap<String, AuctionRound>,
    pub sealed_bids: BTreeMap<String, SealedStorageReceiptFeeBid>,
    pub encrypted_lots: BTreeMap<String, EncryptedStorageReceiptLot>,
    pub pq_attestations: BTreeMap<String, PqAuctionAttestation>,
    pub consumed_nullifier_roots: BTreeSet<String>,
    pub fast_settlements: BTreeMap<String, FastStorageReceiptSettlement>,
    pub accounting_roots: BTreeMap<String, String>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::new(),
            roots: Roots::default(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            auction_rounds: BTreeMap::new(),
            sealed_bids: BTreeMap::new(),
            encrypted_lots: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            consumed_nullifier_roots: BTreeSet::new(),
            fast_settlements: BTreeMap::new(),
            accounting_roots: BTreeMap::new(),
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).expect("devnet auction config is valid");
        let round_id = state
            .open_auction_round(AuctionRoundInput {
                lane: AuctionLane::DefiHotPath,
                storage_namespace_root: "storage:namespace:root:private-defi-hot-path".to_string(),
                eligible_contract_set_root: "contract:set:root:sealed-storage-auction".to_string(),
                capacity_receipt_bytes: 1_048_576,
                capacity_storage_keys: 65_536,
                reserve_micro_fee: 2,
                pq_policy_root: "pq:policy:root:ml-dsa-slh-dsa-devnet".to_string(),
            })
            .expect("devnet auction round opens");
        let bid_id = state
            .submit_sealed_bid(SealedBidInput {
                round_id: round_id.clone(),
                contract_commitment: "contract:commitment:confidential-dex-vault".to_string(),
                bidder_note_commitment: "note:commitment:sealed-auction-bidder-001".to_string(),
                sealed_bid_root: "sealed:bid:root:ml-kem-auction-001".to_string(),
                max_micro_fee: 9,
                receipt_bytes_upper_bound: 262_144,
                storage_keys_upper_bound: 16_384,
                replay_nullifier_root: "nullifier:root:storage-auction-bid-001".to_string(),
                settlement_preference_root: "settlement:preference:root:fast-low-fee".to_string(),
                bid_nonce: 1,
            })
            .expect("devnet bid accepted");
        let lot_id = state
            .commit_receipt_lot(ReceiptLotInput {
                round_id: round_id.clone(),
                bid_id: bid_id.clone(),
                encrypted_receipt_root: "encrypted:receipt:root:auction-lot-001".to_string(),
                encrypted_storage_delta_root: "encrypted:storage-delta:root:auction-lot-001"
                    .to_string(),
                pre_storage_root: "storage:root:before:auction-lot-001".to_string(),
                post_storage_root: "storage:root:after:auction-lot-001".to_string(),
                receipt_bytes: 131_072,
                storage_keys_touched: 8_192,
                lot_nonce: 1,
            })
            .expect("devnet lot commits");
        let _executor = state
            .attest_lot(PqAuctionAttestationInput {
                lot_id: lot_id.clone(),
                role: AttestationRole::Executor,
                committee_id: "committee:pq-storage-auction-executors:devnet:01".to_string(),
                signer_set_root: "signer:set:root:auction-executor:devnet:01".to_string(),
                attested_receipt_root: "encrypted:receipt:root:auction-lot-001".to_string(),
                pq_public_key_digest: "pq-key:digest:auction-executor:001".to_string(),
                pq_signature_root: "pq-signature:root:auction-executor:001".to_string(),
                pq_security_bits: 256,
                quorum_weight_bps: DEFAULT_FAST_FINALITY_QUORUM_BPS,
                attestation_nonce: 1,
            })
            .expect("devnet executor attests");
        let _settlement = state
            .settle_fast(FastSettlementInput {
                round_id,
                lot_ids: vec![lot_id],
                operator_commitment: "operator:commitment:fast-auction-settler-001".to_string(),
                clearing_price_root: "clearing:price:root:auction-devnet-001".to_string(),
                settlement_lane_root: "settlement:lane:root:fast-receipt-devnet".to_string(),
                accounting_delta_root: "accounting:delta:root:auction-devnet-001".to_string(),
                settlement_nonce: 1,
            })
            .expect("devnet settlement finalizes");
        state
    }

    pub fn open_auction_round(&mut self, input: AuctionRoundInput) -> Result<String> {
        let round = AuctionRound::from_input(
            self.counters.next_round_index,
            self.height,
            &self.config,
            input,
        )?;
        let round_id = round.round_id.clone();
        if self.auction_rounds.contains_key(&round_id) {
            return Err("duplicate auction round".to_string());
        }
        self.counters.next_round_index = self.counters.next_round_index.saturating_add(1);
        self.counters.rounds_opened = self.counters.rounds_opened.saturating_add(1);
        self.auction_rounds.insert(round_id.clone(), round);
        self.recompute_roots();
        Ok(round_id)
    }

    pub fn submit_sealed_bid(&mut self, input: SealedBidInput) -> Result<String> {
        let round = self
            .auction_rounds
            .get(&input.round_id)
            .ok_or_else(|| "unknown auction round".to_string())?;
        if !round.status.accepts_bids() || self.height > round.commit_end_height {
            return Err("auction round is not accepting sealed bids".to_string());
        }
        if self
            .consumed_nullifier_roots
            .contains(&input.replay_nullifier_root)
        {
            self.counters.duplicate_nullifiers_rejected = self
                .counters
                .duplicate_nullifiers_rejected
                .saturating_add(1);
            return Err("duplicate auction replay nullifier".to_string());
        }
        let bids_in_round = self
            .sealed_bids
            .values()
            .filter(|bid| bid.round_id == input.round_id)
            .count();
        if bids_in_round >= self.config.max_bids_per_round {
            return Err("auction round bid capacity reached".to_string());
        }
        let bid = SealedStorageReceiptFeeBid::from_input(
            self.counters.next_bid_index,
            round,
            &self.config,
            input,
        )?;
        let bid_id = bid.bid_id.clone();
        if self.sealed_bids.contains_key(&bid_id) {
            return Err("duplicate sealed auction bid".to_string());
        }
        self.consumed_nullifier_roots
            .insert(bid.replay_nullifier_root.clone());
        self.counters.next_bid_index = self.counters.next_bid_index.saturating_add(1);
        self.counters.sealed_bids_submitted = self.counters.sealed_bids_submitted.saturating_add(1);
        self.sealed_bids.insert(bid_id.clone(), bid);
        self.recompute_roots();
        Ok(bid_id)
    }

    pub fn commit_receipt_lot(&mut self, input: ReceiptLotInput) -> Result<String> {
        let bid = self
            .sealed_bids
            .get_mut(&input.bid_id)
            .ok_or_else(|| "unknown sealed auction bid".to_string())?;
        if bid.round_id != input.round_id {
            return Err("receipt lot round does not match bid".to_string());
        }
        if input.receipt_bytes > bid.receipt_bytes_upper_bound
            || input.storage_keys_touched > bid.storage_keys_upper_bound
        {
            return Err("receipt lot exceeds sealed bid bounds".to_string());
        }
        let lot = EncryptedStorageReceiptLot::from_input(self.counters.next_lot_index, input)?;
        let lot_id = lot.lot_id.clone();
        if self.encrypted_lots.contains_key(&lot_id) {
            return Err("duplicate encrypted receipt lot".to_string());
        }
        bid.status = BidStatus::LotBound;
        self.counters.next_lot_index = self.counters.next_lot_index.saturating_add(1);
        self.counters.encrypted_lots_committed =
            self.counters.encrypted_lots_committed.saturating_add(1);
        self.encrypted_lots.insert(lot_id.clone(), lot);
        self.recompute_roots();
        Ok(lot_id)
    }

    pub fn attest_lot(&mut self, input: PqAuctionAttestationInput) -> Result<String> {
        let lot = self
            .encrypted_lots
            .get_mut(&input.lot_id)
            .ok_or_else(|| "unknown encrypted receipt lot".to_string())?;
        let attestation = PqAuctionAttestation::from_input(
            self.counters.next_attestation_index,
            self.height,
            &self.config,
            input,
        )?;
        match attestation.role {
            AttestationRole::Executor => lot.status = LotStatus::ExecutorAttested,
            AttestationRole::Verifier
            | AttestationRole::Watchtower
            | AttestationRole::FeeAuctioneer => {
                lot.status = LotStatus::VerifierAttested;
            }
        }
        if let Some(bid) = self.sealed_bids.get_mut(&lot.bid_id) {
            bid.status = BidStatus::Attested;
        }
        let attestation_id = attestation.attestation_id.clone();
        if self.pq_attestations.contains_key(&attestation_id) {
            return Err("duplicate PQ auction attestation".to_string());
        }
        self.counters.next_attestation_index =
            self.counters.next_attestation_index.saturating_add(1);
        self.counters.pq_attestations = self.counters.pq_attestations.saturating_add(1);
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        self.recompute_roots();
        Ok(attestation_id)
    }

    pub fn settle_fast(&mut self, input: FastSettlementInput) -> Result<String> {
        require_non_empty("operator_commitment", &input.operator_commitment)?;
        require_non_empty("clearing_price_root", &input.clearing_price_root)?;
        require_non_empty("settlement_lane_root", &input.settlement_lane_root)?;
        require_non_empty("accounting_delta_root", &input.accounting_delta_root)?;
        if input.lot_ids.is_empty() {
            return Err("settlement requires at least one receipt lot".to_string());
        }
        if input.lot_ids.len() > self.config.max_lots_per_settlement {
            return Err("settlement lot capacity exceeded".to_string());
        }
        let mut total_receipt_bytes = 0_u64;
        let mut total_storage_keys = 0_u64;
        let mut total_fee_micro_units = 0_u128;
        let mut seen_lots = BTreeSet::new();
        for lot_id in &input.lot_ids {
            if !seen_lots.insert(lot_id.clone()) {
                return Err("duplicate receipt lot in settlement".to_string());
            }
            let lot = self
                .encrypted_lots
                .get(lot_id)
                .ok_or_else(|| format!("unknown receipt lot in settlement: {lot_id}"))?;
            if lot.round_id != input.round_id {
                return Err("settlement lot round mismatch".to_string());
            }
            if !lot.status.settleable() {
                return Err("receipt lot is not settleable".to_string());
            }
            let bid = self
                .sealed_bids
                .get(&lot.bid_id)
                .ok_or_else(|| "settlement lot references unknown bid".to_string())?;
            total_receipt_bytes = total_receipt_bytes.saturating_add(lot.receipt_bytes);
            total_storage_keys = total_storage_keys.saturating_add(lot.storage_keys_touched);
            total_fee_micro_units =
                total_fee_micro_units.saturating_add(bid.quoted_micro_fee as u128);
        }
        if total_receipt_bytes > self.config.max_receipt_bytes_per_settlement {
            return Err("settlement receipt byte capacity exceeded".to_string());
        }
        let total_rebate_micro_units = total_fee_micro_units
            .saturating_mul(self.config.clearing_rebate_bps as u128)
            / MAX_BPS as u128;
        let settlement_id = fast_settlement_id(
            &input.operator_commitment,
            &input.settlement_lane_root,
            self.height,
            input.settlement_nonce,
        );
        if self.fast_settlements.contains_key(&settlement_id) {
            return Err("duplicate fast settlement".to_string());
        }
        let settlement = FastStorageReceiptSettlement {
            settlement_id: settlement_id.clone(),
            settlement_index: self.counters.next_settlement_index,
            round_id: input.round_id.clone(),
            lot_ids: input.lot_ids.clone(),
            operator_commitment: input.operator_commitment,
            clearing_price_root: input.clearing_price_root,
            settlement_lane_root: input.settlement_lane_root,
            accounting_delta_root: input.accounting_delta_root.clone(),
            total_receipt_bytes,
            total_storage_keys,
            total_fee_micro_units,
            total_rebate_micro_units,
            status: SettlementStatus::FastFinal,
            settled_height: self.height,
        };
        for lot_id in &input.lot_ids {
            if let Some(lot) = self.encrypted_lots.get_mut(lot_id) {
                lot.status = LotStatus::Settled;
                if let Some(bid) = self.sealed_bids.get_mut(&lot.bid_id) {
                    bid.status = BidStatus::Accepted;
                    self.counters.accepted_bids = self.counters.accepted_bids.saturating_add(1);
                }
            }
        }
        if let Some(round) = self.auction_rounds.get_mut(&input.round_id) {
            round.status = RoundStatus::Settled;
        }
        self.accounting_roots
            .insert(settlement_id.clone(), input.accounting_delta_root);
        self.counters.next_settlement_index = self.counters.next_settlement_index.saturating_add(1);
        self.counters.settlements_finalized = self.counters.settlements_finalized.saturating_add(1);
        self.counters.total_receipt_bytes_settled = self
            .counters
            .total_receipt_bytes_settled
            .saturating_add(total_receipt_bytes);
        self.counters.total_fee_micro_units = self
            .counters
            .total_fee_micro_units
            .saturating_add(total_fee_micro_units);
        self.counters.total_rebate_micro_units = self
            .counters
            .total_rebate_micro_units
            .saturating_add(total_rebate_micro_units);
        self.fast_settlements
            .insert(settlement_id.clone(), settlement);
        self.recompute_roots();
        Ok(settlement_id)
    }

    pub fn advance_height(&mut self, next_height: u64) -> Result<()> {
        if next_height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = next_height;
        self.epoch = next_height / self.config.auction_window_blocks.max(1);
        self.expire_stale_records();
        self.recompute_roots();
        Ok(())
    }

    pub fn roots(&self) -> Roots {
        self.roots.clone()
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "epoch": self.epoch,
            "roots": self.roots.public_record(),
        }))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "suite": ROOTS_ONLY_PUBLIC_RECORD_SUITE,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "fee_asset_id": self.config.fee_asset_id,
            "height": self.height,
            "epoch": self.epoch,
            "state_root": self.state_root(),
            "roots": self.roots.public_record(),
            "privacy_policy": {
                "roots_only_public_records": self.config.require_roots_only_public_records,
                "sealed_bid_payloads_redacted": true,
                "encrypted_receipt_payloads_redacted": true,
                "contract_identity_commitments_only": true,
                "pq_attestation_roots_only": true,
                "nullifier_preimages_redacted": true,
            },
        })
    }

    pub fn recompute_roots(&mut self) {
        let mut roots = Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            auction_round_root: record_root(
                AUCTION_ROUND_SCHEME,
                &self
                    .auction_rounds
                    .values()
                    .map(AuctionRound::public_record)
                    .collect::<Vec<_>>(),
            ),
            sealed_bid_root: record_root(
                SEALED_BID_SCHEME,
                &self
                    .sealed_bids
                    .values()
                    .map(SealedStorageReceiptFeeBid::public_record)
                    .collect::<Vec<_>>(),
            ),
            encrypted_lot_root: record_root(
                RECEIPT_LOT_SCHEME,
                &self
                    .encrypted_lots
                    .values()
                    .map(EncryptedStorageReceiptLot::public_record)
                    .collect::<Vec<_>>(),
            ),
            pq_attestation_root: record_root(
                PQ_ATTESTATION_SCHEME,
                &self
                    .pq_attestations
                    .values()
                    .map(PqAuctionAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            replay_nullifier_root: record_root(
                NULLIFIER_SCHEME,
                &self
                    .consumed_nullifier_roots
                    .iter()
                    .map(|root| json!({ "nullifier_root": root }))
                    .collect::<Vec<_>>(),
            ),
            settlement_root: record_root(
                SETTLEMENT_SCHEME,
                &self
                    .fast_settlements
                    .values()
                    .map(FastStorageReceiptSettlement::public_record)
                    .collect::<Vec<_>>(),
            ),
            accounting_root: record_root(
                ACCOUNTING_SCHEME,
                &self
                    .accounting_roots
                    .iter()
                    .map(|(settlement_id, accounting_root)| {
                        json!({
                            "settlement_id": settlement_id,
                            "accounting_root": accounting_root,
                        })
                    })
                    .collect::<Vec<_>>(),
            ),
            public_record_root: String::new(),
        };
        roots.public_record_root = payload_root(
            PUBLIC_RECORD_SCHEME,
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "height": self.height,
                "epoch": self.epoch,
                "roots_without_public_record_root": {
                    "config_root": roots.config_root,
                    "counters_root": roots.counters_root,
                    "auction_round_root": roots.auction_round_root,
                    "sealed_bid_root": roots.sealed_bid_root,
                    "encrypted_lot_root": roots.encrypted_lot_root,
                    "pq_attestation_root": roots.pq_attestation_root,
                    "replay_nullifier_root": roots.replay_nullifier_root,
                    "settlement_root": roots.settlement_root,
                    "accounting_root": roots.accounting_root,
                },
            }),
        );
        self.roots = roots;
    }

    fn expire_stale_records(&mut self) {
        for round in self.auction_rounds.values_mut() {
            if round.status.active() && self.height > round.settlement_deadline_height {
                round.status = RoundStatus::Expired;
            }
        }
        for bid in self.sealed_bids.values_mut() {
            if matches!(
                bid.status,
                BidStatus::Sealed
                    | BidStatus::NullifierReserved
                    | BidStatus::LotBound
                    | BidStatus::Attested
            ) && self.height > bid.expires_height
            {
                bid.status = BidStatus::Expired;
            }
        }
    }
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

pub fn auction_round_id(
    lane: AuctionLane,
    storage_namespace_root: &str,
    eligible_contract_set_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-AUCTION:ROUND-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(storage_namespace_root),
            HashPart::Str(eligible_contract_set_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn sealed_bid_id(
    round_id: &str,
    contract_commitment: &str,
    sealed_bid_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-AUCTION:BID-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(round_id),
            HashPart::Str(contract_commitment),
            HashPart::Str(sealed_bid_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn receipt_lot_id(round_id: &str, bid_id: &str, post_storage_root: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-AUCTION:LOT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(round_id),
            HashPart::Str(bid_id),
            HashPart::Str(post_storage_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn pq_auction_attestation_id(
    lot_id: &str,
    committee_id: &str,
    role: AttestationRole,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-AUCTION:ATTESTATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lot_id),
            HashPart::Str(committee_id),
            HashPart::Str(role.as_str()),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn fast_settlement_id(
    operator_commitment: &str,
    settlement_lane_root: &str,
    height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-AUCTION:SETTLEMENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(operator_commitment),
            HashPart::Str(settlement_lane_root),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn estimate_clearing_fee_micro_units(
    config: &Config,
    lane: AuctionLane,
    max_micro_fee: u64,
    receipt_bytes: u64,
) -> u64 {
    let byte_component = receipt_bytes.saturating_add(1023) / 1024;
    let priority_discount = lane.priority_weight() / 1_250;
    let mut fee = max_micro_fee
        .max(config.reserve_micro_fee)
        .saturating_add(byte_component)
        .saturating_add(config.operator_fee_bps)
        .saturating_add(config.congestion_surcharge_bps)
        .saturating_sub(priority_discount);
    fee = fee.saturating_sub(fee.saturating_mul(config.clearing_rebate_bps) / MAX_BPS);
    fee.max(config.reserve_micro_fee)
}

pub fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-AUCTION:PAYLOAD-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn record_root(domain: &str, records: &[Value]) -> String {
    if records.is_empty() {
        payload_root(domain, &json!({ "empty": true }))
    } else {
        merkle_root(domain, records)
    }
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-AUCTION:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn require_non_empty(label: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}
