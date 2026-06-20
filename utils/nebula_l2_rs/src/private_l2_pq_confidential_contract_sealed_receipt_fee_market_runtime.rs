use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedReceiptFeeMarketRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractSealedReceiptFeeMarketRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_RECEIPT_FEE_MARKET_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-sealed-receipt-fee-market-runtime-v1";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEALED_RECEIPT_FEE_MARKET_SUITE: &str =
    "sealed-confidential-smart-contract-receipt-fee-market-v1";
pub const PRIVATE_RECEIPT_FEE_BID_SUITE: &str = "private-receipt-fee-bid-commitment-v1";
pub const ENCRYPTED_RECEIPT_COMMITMENT_SUITE: &str =
    "ml-kem-1024-sealed-contract-receipt-commitment-v1";
pub const PQ_VERIFIER_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-receipt-verifier-attestation-v1";
pub const REPLAY_NULLIFIER_SUITE: &str = "sealed-contract-receipt-replay-nullifier-v1";
pub const LOW_FEE_SETTLEMENT_BATCH_SUITE: &str =
    "low-fee-confidential-contract-receipt-settlement-batch-v1";
pub const SUBSCRIPTION_ACCOUNTING_SUITE: &str = "sealed-receipt-subscription-accounting-root-v1";
pub const ROOTS_ONLY_PUBLIC_RECORD_SUITE: &str =
    "roots-only-public-record-confidential-contract-receipt-fee-market-v1";
pub const RECEIPT_WINDOW_SCHEME: &str = "sealed-contract-receipt-window-root-v1";
pub const PRIVATE_RECEIPT_BID_SCHEME: &str = "private-contract-receipt-fee-bid-root-v1";
pub const ENCRYPTED_RECEIPT_COMMITMENT_SCHEME: &str =
    "encrypted-contract-receipt-commitment-root-v1";
pub const PQ_VERIFIER_ATTESTATION_SCHEME: &str = "pq-contract-receipt-verifier-attestation-root-v1";
pub const REPLAY_NULLIFIER_SCHEME: &str = "sealed-contract-receipt-replay-nullifier-root-v1";
pub const LOW_FEE_SETTLEMENT_BATCH_SCHEME: &str =
    "low-fee-contract-receipt-settlement-batch-root-v1";
pub const SUBSCRIPTION_ROOT_SCHEME: &str = "private-contract-receipt-subscription-root-v1";
pub const ACCOUNTING_ROOT_SCHEME: &str = "private-contract-receipt-accounting-root-v1";
pub const PUBLIC_RECORD_ROOT_SCHEME: &str = "private-contract-receipt-public-record-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_RECEIPT_FEE_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 5_402_112;
pub const DEVNET_EPOCH: u64 = 10_551;
pub const DEFAULT_RECEIPT_WINDOW_BLOCKS: u64 = 48;
pub const DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 144;
pub const DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_SUBSCRIPTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_ACCOUNTING_EPOCH_BLOCKS: u64 = 360;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MAX_RECEIPTS_PER_BID: u64 = 65_536;
pub const DEFAULT_OPERATOR_FEE_BPS: u64 = 3;
pub const DEFAULT_BATCH_REBATE_BPS: u64 = 7;
pub const DEFAULT_CONGESTION_SURCHARGE_BPS: u64 = 10;
pub const DEFAULT_BASE_RECEIPT_MICRO_FEE: u64 = 3;
pub const DEFAULT_MIN_RECEIPT_MICRO_FEE: u64 = 1;
pub const DEFAULT_MAX_RECEIPT_BYTES_PER_BATCH: u64 = 12_582_912;
pub const DEFAULT_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRICT_QUORUM_BPS: u64 = 8_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_BIDS_PER_WINDOW: usize = 16_384;
pub const DEFAULT_MAX_COMMITMENTS_PER_BATCH: usize = 4_096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptDomain {
    DexSwap,
    Lending,
    Perps,
    Options,
    Vault,
    Bridge,
    Oracle,
    Governance,
    AccountRecovery,
    Emergency,
}
impl ReceiptDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DexSwap => "dex_swap",
            Self::Lending => "lending",
            Self::Perps => "perps",
            Self::Options => "options",
            Self::Vault => "vault",
            Self::Bridge => "bridge",
            Self::Oracle => "oracle",
            Self::Governance => "governance",
            Self::AccountRecovery => "account_recovery",
            Self::Emergency => "emergency",
        }
    }
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::AccountRecovery => 9_700,
            Self::Bridge => 9_200,
            Self::Oracle => 8_800,
            Self::Perps => 8_450,
            Self::Options => 8_250,
            Self::Vault => 8_000,
            Self::Lending => 7_850,
            Self::DexSwap => 7_700,
            Self::Governance => 6_700,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    Execution,
    Settlement,
    EventLog,
    Payment,
    Liquidation,
    OracleAnswer,
    SubscriptionDelivery,
    Upgrade,
    Emergency,
}
impl ReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Execution => "execution",
            Self::Settlement => "settlement",
            Self::EventLog => "event_log",
            Self::Payment => "payment",
            Self::Liquidation => "liquidation",
            Self::OracleAnswer => "oracle_answer",
            Self::SubscriptionDelivery => "subscription_delivery",
            Self::Upgrade => "upgrade",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowStatus {
    Announced,
    CommitOpen,
    PqAttested,
    BatchReady,
    Settling,
    Settled,
    Cancelled,
    Expired,
}
impl WindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::CommitOpen => "commit_open",
            Self::PqAttested => "pq_attested",
            Self::BatchReady => "batch_ready",
            Self::Settling => "settling",
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
    pub fn accepted(self) -> bool {
        matches!(
            self,
            Self::Authenticated | Self::QuorumSigned | Self::Applied
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Proposed,
    Authenticated,
    QuorumSigned,
    Applied,
    Challenged,
    Rejected,
}
impl AttestationStatus {
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
pub enum NullifierStatus {
    Reserved,
    Armed,
    Consumed,
    DuplicateRejected,
    Expired,
}
impl NullifierStatus {
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Drafted,
    Active,
    Paused,
    Exhausted,
    Expired,
    Revoked,
}
impl SubscriptionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Drafted => "drafted",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountingSide {
    Debit,
    Credit,
    Rebate,
    Escrow,
    Slash,
}
impl AccountingSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debit => "debit",
            Self::Credit => "credit",
            Self::Rebate => "rebate",
            Self::Escrow => "escrow",
            Self::Slash => "slash",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEventKind {
    WindowOpened,
    BidSubmitted,
    CommitmentSealed,
    AttestationAccepted,
    NullifierArmed,
    BatchSettled,
    SubscriptionUpdated,
    AccountingPosted,
}
impl RuntimeEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WindowOpened => "window_opened",
            Self::BidSubmitted => "bid_submitted",
            Self::CommitmentSealed => "commitment_sealed",
            Self::AttestationAccepted => "attestation_accepted",
            Self::NullifierArmed => "nullifier_armed",
            Self::BatchSettled => "batch_settled",
            Self::SubscriptionUpdated => "subscription_updated",
            Self::AccountingPosted => "accounting_posted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementLane {
    Bulk,
    LowFee,
    Standard,
    Fast,
    OracleGuarded,
    Emergency,
}
impl SettlementLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bulk => "bulk",
            Self::LowFee => "low_fee",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::OracleGuarded => "oracle_guarded",
            Self::Emergency => "emergency",
        }
    }
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 1_000,
            Self::Fast => 940,
            Self::OracleGuarded => 900,
            Self::Standard => 780,
            Self::LowFee => 720,
            Self::Bulk => 650,
        }
    }
    pub fn fee_multiplier_bps(self) -> u64 {
        match self {
            Self::Bulk => 7_500,
            Self::LowFee => 8_500,
            Self::Standard => 10_000,
            Self::Fast => 13_000,
            Self::OracleGuarded => 11_500,
            Self::Emergency => 20_000,
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
    pub sealed_receipt_fee_market_suite: String,
    pub private_receipt_fee_bid_suite: String,
    pub encrypted_receipt_commitment_suite: String,
    pub pq_verifier_attestation_suite: String,
    pub replay_nullifier_suite: String,
    pub low_fee_settlement_batch_suite: String,
    pub subscription_accounting_suite: String,
    pub roots_only_public_record_suite: String,
    pub receipt_window_blocks: u64,
    pub replay_window_blocks: u64,
    pub batch_window_blocks: u64,
    pub subscription_epoch_blocks: u64,
    pub accounting_epoch_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub max_bids_per_window: usize,
    pub max_receipts_per_bid: u64,
    pub max_commitments_per_batch: usize,
    pub operator_fee_bps: u64,
    pub batch_rebate_bps: u64,
    pub congestion_surcharge_bps: u64,
    pub base_receipt_micro_fee: u64,
    pub min_receipt_micro_fee: u64,
    pub max_receipt_bytes_per_batch: u64,
    pub quorum_bps: u64,
    pub strict_quorum_bps: u64,
}
impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "sealed_receipt_fee_market_suite": self.sealed_receipt_fee_market_suite,
            "private_receipt_fee_bid_suite": self.private_receipt_fee_bid_suite,
            "encrypted_receipt_commitment_suite": self.encrypted_receipt_commitment_suite,
            "pq_verifier_attestation_suite": self.pq_verifier_attestation_suite,
            "replay_nullifier_suite": self.replay_nullifier_suite,
            "low_fee_settlement_batch_suite": self.low_fee_settlement_batch_suite,
            "subscription_accounting_suite": self.subscription_accounting_suite,
            "roots_only_public_record_suite": self.roots_only_public_record_suite,
            "receipt_window_blocks": self.receipt_window_blocks,
            "replay_window_blocks": self.replay_window_blocks,
            "batch_window_blocks": self.batch_window_blocks,
            "subscription_epoch_blocks": self.subscription_epoch_blocks,
            "accounting_epoch_blocks": self.accounting_epoch_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "max_bids_per_window": self.max_bids_per_window,
            "max_receipts_per_bid": self.max_receipts_per_bid,
            "max_commitments_per_batch": self.max_commitments_per_batch,
            "operator_fee_bps": self.operator_fee_bps,
            "batch_rebate_bps": self.batch_rebate_bps,
            "congestion_surcharge_bps": self.congestion_surcharge_bps,
            "base_receipt_micro_fee": self.base_receipt_micro_fee,
            "min_receipt_micro_fee": self.min_receipt_micro_fee,
            "max_receipt_bytes_per_batch": self.max_receipt_bytes_per_batch,
            "quorum_bps": self.quorum_bps,
            "strict_quorum_bps": self.strict_quorum_bps,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            sealed_receipt_fee_market_suite: SEALED_RECEIPT_FEE_MARKET_SUITE.to_string(),
            private_receipt_fee_bid_suite: PRIVATE_RECEIPT_FEE_BID_SUITE.to_string(),
            encrypted_receipt_commitment_suite: ENCRYPTED_RECEIPT_COMMITMENT_SUITE.to_string(),
            pq_verifier_attestation_suite: PQ_VERIFIER_ATTESTATION_SUITE.to_string(),
            replay_nullifier_suite: REPLAY_NULLIFIER_SUITE.to_string(),
            low_fee_settlement_batch_suite: LOW_FEE_SETTLEMENT_BATCH_SUITE.to_string(),
            subscription_accounting_suite: SUBSCRIPTION_ACCOUNTING_SUITE.to_string(),
            roots_only_public_record_suite: ROOTS_ONLY_PUBLIC_RECORD_SUITE.to_string(),
            receipt_window_blocks: DEFAULT_RECEIPT_WINDOW_BLOCKS,
            replay_window_blocks: DEFAULT_REPLAY_WINDOW_BLOCKS,
            batch_window_blocks: DEFAULT_BATCH_WINDOW_BLOCKS,
            subscription_epoch_blocks: DEFAULT_SUBSCRIPTION_EPOCH_BLOCKS,
            accounting_epoch_blocks: DEFAULT_ACCOUNTING_EPOCH_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            max_bids_per_window: DEFAULT_MAX_BIDS_PER_WINDOW,
            max_receipts_per_bid: DEFAULT_MAX_RECEIPTS_PER_BID,
            max_commitments_per_batch: DEFAULT_MAX_COMMITMENTS_PER_BATCH,
            operator_fee_bps: DEFAULT_OPERATOR_FEE_BPS,
            batch_rebate_bps: DEFAULT_BATCH_REBATE_BPS,
            congestion_surcharge_bps: DEFAULT_CONGESTION_SURCHARGE_BPS,
            base_receipt_micro_fee: DEFAULT_BASE_RECEIPT_MICRO_FEE,
            min_receipt_micro_fee: DEFAULT_MIN_RECEIPT_MICRO_FEE,
            max_receipt_bytes_per_batch: DEFAULT_MAX_RECEIPT_BYTES_PER_BATCH,
            quorum_bps: DEFAULT_QUORUM_BPS,
            strict_quorum_bps: DEFAULT_STRICT_QUORUM_BPS,
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("pq security below floor".to_string());
        }
        if self.min_privacy_set_size < 65_536 {
            return Err("privacy set below floor".to_string());
        }
        if self.operator_fee_bps + self.batch_rebate_bps + self.congestion_surcharge_bps > MAX_BPS {
            return Err("fee bps exceed max".to_string());
        }
        if self.base_receipt_micro_fee < self.min_receipt_micro_fee {
            return Err("base fee below min fee".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub receipt_windows: u64,
    pub private_fee_bids: u64,
    pub encrypted_receipt_commitments: u64,
    pub pq_verifier_attestations: u64,
    pub replay_nullifiers: u64,
    pub low_fee_settlement_batches: u64,
    pub subscriptions: u64,
    pub accounting_entries: u64,
    pub runtime_events: u64,
    pub accepted_bids: u64,
    pub rejected_duplicates: u64,
    pub settled_receipts: u64,
    pub total_bid_micro_fee: u64,
    pub total_settled_micro_fee: u64,
    pub total_rebate_micro_fee: u64,
    pub total_operator_micro_fee: u64,
    pub total_receipt_bytes: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_windows": self.receipt_windows,
            "private_fee_bids": self.private_fee_bids,
            "encrypted_receipt_commitments": self.encrypted_receipt_commitments,
            "pq_verifier_attestations": self.pq_verifier_attestations,
            "replay_nullifiers": self.replay_nullifiers,
            "low_fee_settlement_batches": self.low_fee_settlement_batches,
            "subscriptions": self.subscriptions,
            "accounting_entries": self.accounting_entries,
            "runtime_events": self.runtime_events,
            "accepted_bids": self.accepted_bids,
            "rejected_duplicates": self.rejected_duplicates,
            "settled_receipts": self.settled_receipts,
            "total_bid_micro_fee": self.total_bid_micro_fee,
            "total_settled_micro_fee": self.total_settled_micro_fee,
            "total_rebate_micro_fee": self.total_rebate_micro_fee,
            "total_operator_micro_fee": self.total_operator_micro_fee,
            "total_receipt_bytes": self.total_receipt_bytes,
        })
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            receipt_windows: 0,
            private_fee_bids: 0,
            encrypted_receipt_commitments: 0,
            pq_verifier_attestations: 0,
            replay_nullifiers: 0,
            low_fee_settlement_batches: 0,
            subscriptions: 0,
            accounting_entries: 0,
            runtime_events: 0,
            accepted_bids: 0,
            rejected_duplicates: 0,
            settled_receipts: 0,
            total_bid_micro_fee: 0,
            total_settled_micro_fee: 0,
            total_rebate_micro_fee: 0,
            total_operator_micro_fee: 0,
            total_receipt_bytes: 0,
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub receipt_window_root: String,
    pub private_fee_bid_root: String,
    pub encrypted_receipt_commitment_root: String,
    pub pq_verifier_attestation_root: String,
    pub replay_nullifier_root: String,
    pub low_fee_settlement_batch_root: String,
    pub subscription_root: String,
    pub accounting_root: String,
    pub runtime_event_root: String,
    pub public_record_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "receipt_window_root": self.receipt_window_root,
            "private_fee_bid_root": self.private_fee_bid_root,
            "encrypted_receipt_commitment_root": self.encrypted_receipt_commitment_root,
            "pq_verifier_attestation_root": self.pq_verifier_attestation_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "low_fee_settlement_batch_root": self.low_fee_settlement_batch_root,
            "subscription_root": self.subscription_root,
            "accounting_root": self.accounting_root,
            "runtime_event_root": self.runtime_event_root,
            "public_record_root": self.public_record_root,
        })
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: String::new(),
            receipt_window_root: String::new(),
            private_fee_bid_root: String::new(),
            encrypted_receipt_commitment_root: String::new(),
            pq_verifier_attestation_root: String::new(),
            replay_nullifier_root: String::new(),
            low_fee_settlement_batch_root: String::new(),
            subscription_root: String::new(),
            accounting_root: String::new(),
            runtime_event_root: String::new(),
            public_record_root: String::new(),
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReceiptWindow {
    pub window_id: String,
    pub epoch: u64,
    pub opened_height: u64,
    pub closes_height: u64,
    pub settlement_height: u64,
    pub domain: ReceiptDomain,
    pub lane: SettlementLane,
    pub status: WindowStatus,
    pub privacy_set_size: u64,
    pub min_micro_fee: u64,
    pub target_batch_bytes: u64,
    pub sealed_window_commitment: String,
    pub operator_commitment: String,
    pub replay_domain: String,
}
impl ReceiptWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "epoch": self.epoch,
            "opened_height": self.opened_height,
            "closes_height": self.closes_height,
            "settlement_height": self.settlement_height,
            "domain": self.domain.as_str(),
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "min_micro_fee": self.min_micro_fee,
            "target_batch_bytes": self.target_batch_bytes,
            "sealed_window_commitment": self.sealed_window_commitment,
            "operator_commitment": self.operator_commitment,
            "replay_domain": self.replay_domain,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivateReceiptFeeBid {
    pub bid_id: String,
    pub window_id: String,
    pub bidder_commitment: String,
    pub contract_id: String,
    pub domain: ReceiptDomain,
    pub receipt_kind: ReceiptKind,
    pub lane: SettlementLane,
    pub status: BidStatus,
    pub encrypted_bid_commitment: String,
    pub bid_value_commitment: String,
    pub max_receipts: u64,
    pub max_receipt_bytes: u64,
    pub max_micro_fee: u64,
    pub priority_hint: u64,
    pub replay_nullifier: String,
    pub pq_bid_proof: String,
    pub created_height: u64,
    pub expires_height: u64,
}
impl PrivateReceiptFeeBid {
    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "window_id": self.window_id,
            "bidder_commitment": self.bidder_commitment,
            "contract_id": self.contract_id,
            "domain": self.domain.as_str(),
            "receipt_kind": self.receipt_kind.as_str(),
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "encrypted_bid_commitment": self.encrypted_bid_commitment,
            "bid_value_commitment": self.bid_value_commitment,
            "max_receipts": self.max_receipts,
            "max_receipt_bytes": self.max_receipt_bytes,
            "max_micro_fee": self.max_micro_fee,
            "priority_hint": self.priority_hint,
            "replay_nullifier": self.replay_nullifier,
            "pq_bid_proof": self.pq_bid_proof,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct EncryptedReceiptCommitment {
    pub commitment_id: String,
    pub bid_id: String,
    pub window_id: String,
    pub contract_id: String,
    pub receipt_kind: ReceiptKind,
    pub status: CommitmentStatus,
    pub ciphertext_commitment: String,
    pub receipt_body_root: String,
    pub receipt_metadata_root: String,
    pub fee_payload_commitment: String,
    pub subscriber_tag_root: String,
    pub pq_ciphertext_capsule: String,
    pub receipt_count: u64,
    pub receipt_bytes: u64,
    pub privacy_set_size: u64,
    pub created_height: u64,
}
impl EncryptedReceiptCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "bid_id": self.bid_id,
            "window_id": self.window_id,
            "contract_id": self.contract_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "status": self.status.as_str(),
            "ciphertext_commitment": self.ciphertext_commitment,
            "receipt_body_root": self.receipt_body_root,
            "receipt_metadata_root": self.receipt_metadata_root,
            "fee_payload_commitment": self.fee_payload_commitment,
            "subscriber_tag_root": self.subscriber_tag_root,
            "pq_ciphertext_capsule": self.pq_ciphertext_capsule,
            "receipt_count": self.receipt_count,
            "receipt_bytes": self.receipt_bytes,
            "privacy_set_size": self.privacy_set_size,
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqVerifierAttestation {
    pub attestation_id: String,
    pub commitment_id: String,
    pub verifier_committee_id: String,
    pub verifier_key_root: String,
    pub status: AttestationStatus,
    pub scheme: String,
    pub pq_security_bits: u16,
    pub quorum_bps: u64,
    pub verified_receipt_count: u64,
    pub verified_receipt_bytes: u64,
    pub transcript_root: String,
    pub signature_root: String,
    pub signed_height: u64,
    pub expires_height: u64,
}
impl PqVerifierAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "commitment_id": self.commitment_id,
            "verifier_committee_id": self.verifier_committee_id,
            "verifier_key_root": self.verifier_key_root,
            "status": self.status.as_str(),
            "scheme": self.scheme,
            "pq_security_bits": self.pq_security_bits,
            "quorum_bps": self.quorum_bps,
            "verified_receipt_count": self.verified_receipt_count,
            "verified_receipt_bytes": self.verified_receipt_bytes,
            "transcript_root": self.transcript_root,
            "signature_root": self.signature_root,
            "signed_height": self.signed_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReplayNullifier {
    pub nullifier_id: String,
    pub window_id: String,
    pub bid_id: String,
    pub commitment_id: String,
    pub nullifier_root: String,
    pub replay_domain: String,
    pub status: NullifierStatus,
    pub first_seen_height: u64,
    pub expires_height: u64,
}
impl ReplayNullifier {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "window_id": self.window_id,
            "bid_id": self.bid_id,
            "commitment_id": self.commitment_id,
            "nullifier_root": self.nullifier_root,
            "replay_domain": self.replay_domain,
            "status": self.status.as_str(),
            "first_seen_height": self.first_seen_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LowFeeSettlementBatch {
    pub batch_id: String,
    pub window_id: String,
    pub operator_id: String,
    pub lane: SettlementLane,
    pub status: BatchStatus,
    pub commitment_ids: Vec<String>,
    pub attestation_ids: Vec<String>,
    pub nullifier_ids: Vec<String>,
    pub receipt_count: u64,
    pub receipt_bytes: u64,
    pub gross_micro_fee: u64,
    pub operator_micro_fee: u64,
    pub rebate_micro_fee: u64,
    pub settled_micro_fee: u64,
    pub batch_root: String,
    pub created_height: u64,
    pub settled_height: u64,
}
impl LowFeeSettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "window_id": self.window_id,
            "operator_id": self.operator_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "commitment_ids": self.commitment_ids,
            "attestation_ids": self.attestation_ids,
            "nullifier_ids": self.nullifier_ids,
            "receipt_count": self.receipt_count,
            "receipt_bytes": self.receipt_bytes,
            "gross_micro_fee": self.gross_micro_fee,
            "operator_micro_fee": self.operator_micro_fee,
            "rebate_micro_fee": self.rebate_micro_fee,
            "settled_micro_fee": self.settled_micro_fee,
            "batch_root": self.batch_root,
            "created_height": self.created_height,
            "settled_height": self.settled_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SubscriptionRoot {
    pub subscription_id: String,
    pub subscriber_commitment: String,
    pub namespace_id: String,
    pub status: SubscriptionStatus,
    pub filter_root: String,
    pub accounting_root: String,
    pub prepaid_micro_fee: u64,
    pub spent_micro_fee: u64,
    pub delivered_receipts: u64,
    pub privacy_set_size: u64,
    pub created_height: u64,
    pub expires_height: u64,
}
impl SubscriptionRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "subscription_id": self.subscription_id,
            "subscriber_commitment": self.subscriber_commitment,
            "namespace_id": self.namespace_id,
            "status": self.status.as_str(),
            "filter_root": self.filter_root,
            "accounting_root": self.accounting_root,
            "prepaid_micro_fee": self.prepaid_micro_fee,
            "spent_micro_fee": self.spent_micro_fee,
            "delivered_receipts": self.delivered_receipts,
            "privacy_set_size": self.privacy_set_size,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AccountingRoot {
    pub entry_id: String,
    pub subject_id: String,
    pub batch_id: String,
    pub subscription_id: String,
    pub side: AccountingSide,
    pub asset_id: String,
    pub amount_micro_fee: u64,
    pub counterparty_commitment: String,
    pub accounting_root: String,
    pub posted_height: u64,
}
impl AccountingRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "entry_id": self.entry_id,
            "subject_id": self.subject_id,
            "batch_id": self.batch_id,
            "subscription_id": self.subscription_id,
            "side": self.side.as_str(),
            "asset_id": self.asset_id,
            "amount_micro_fee": self.amount_micro_fee,
            "counterparty_commitment": self.counterparty_commitment,
            "accounting_root": self.accounting_root,
            "posted_height": self.posted_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub height: u64,
    pub kind: RuntimeEventKind,
    pub subject_id: String,
    pub public_root: String,
    pub details: Value,
}
impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "height": self.height,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "public_root": self.public_root,
            "details": self.details,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct OpenWindowInput {
    pub domain: ReceiptDomain,
    pub lane: SettlementLane,
    pub opened_height: u64,
    pub operator_commitment: String,
    pub min_micro_fee: u64,
    pub target_batch_bytes: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SubmitBidInput {
    pub window_id: String,
    pub bidder_commitment: String,
    pub contract_id: String,
    pub receipt_kind: ReceiptKind,
    pub encrypted_bid_commitment: String,
    pub bid_value_commitment: String,
    pub max_receipts: u64,
    pub max_receipt_bytes: u64,
    pub max_micro_fee: u64,
    pub replay_nullifier: String,
    pub pq_bid_proof: String,
    pub created_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CommitReceiptInput {
    pub bid_id: String,
    pub ciphertext_commitment: String,
    pub receipt_body_root: String,
    pub receipt_metadata_root: String,
    pub fee_payload_commitment: String,
    pub subscriber_tag_root: String,
    pub pq_ciphertext_capsule: String,
    pub receipt_count: u64,
    pub receipt_bytes: u64,
    pub privacy_set_size: u64,
    pub created_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AttestReceiptInput {
    pub commitment_id: String,
    pub verifier_committee_id: String,
    pub verifier_key_root: String,
    pub pq_security_bits: u16,
    pub quorum_bps: u64,
    pub verified_receipt_count: u64,
    pub verified_receipt_bytes: u64,
    pub transcript_root: String,
    pub signature_root: String,
    pub signed_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CreateSubscriptionInput {
    pub subscriber_commitment: String,
    pub namespace_id: String,
    pub filter_root: String,
    pub prepaid_micro_fee: u64,
    pub privacy_set_size: u64,
    pub created_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettleBatchInput {
    pub window_id: String,
    pub operator_id: String,
    pub lane: SettlementLane,
    pub commitment_ids: Vec<String>,
    pub settled_height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub receipt_windows: BTreeMap<String, ReceiptWindow>,
    pub private_fee_bids: BTreeMap<String, PrivateReceiptFeeBid>,
    pub encrypted_receipt_commitments: BTreeMap<String, EncryptedReceiptCommitment>,
    pub pq_verifier_attestations: BTreeMap<String, PqVerifierAttestation>,
    pub replay_nullifiers: BTreeMap<String, ReplayNullifier>,
    pub low_fee_settlement_batches: BTreeMap<String, LowFeeSettlementBatch>,
    pub subscriptions: BTreeMap<String, SubscriptionRoot>,
    pub accounting_roots: BTreeMap<String, AccountingRoot>,
    pub runtime_events: BTreeMap<String, RuntimeEvent>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}
impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            receipt_windows: BTreeMap::new(),
            private_fee_bids: BTreeMap::new(),
            encrypted_receipt_commitments: BTreeMap::new(),
            pq_verifier_attestations: BTreeMap::new(),
            replay_nullifiers: BTreeMap::new(),
            low_fee_settlement_batches: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            accounting_roots: BTreeMap::new(),
            runtime_events: BTreeMap::new(),
        };
        state.refresh();
        state
    }
    pub fn devnet() -> Self {
        let mut s = Self::new(Config::default());
        s.install_devnet_fixture();
        s
    }
    pub fn demo() -> Self {
        Self::devnet()
    }
    fn install_devnet_fixture(&mut self) {
        let w = self
            .open_window(OpenWindowInput {
                domain: ReceiptDomain::DexSwap,
                lane: SettlementLane::LowFee,
                opened_height: DEVNET_HEIGHT,
                operator_commitment: "operator:sealed-receipt-devnet".to_string(),
                min_micro_fee: 1,
                target_batch_bytes: 262_144,
                privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            })
            .expect("devnet window");
        let b = self
            .submit_private_fee_bid(SubmitBidInput {
                window_id: w.clone(),
                bidder_commitment: "bidder:commitment:alpha".to_string(),
                contract_id: "contract:confidential-stableswap".to_string(),
                receipt_kind: ReceiptKind::Settlement,
                encrypted_bid_commitment: "encbid:ml-kem:alpha".to_string(),
                bid_value_commitment: "fee:pedersen:alpha".to_string(),
                max_receipts: 128,
                max_receipt_bytes: 65_536,
                max_micro_fee: 384,
                replay_nullifier: "nullifier:alpha".to_string(),
                pq_bid_proof: "ml-dsa-proof:alpha".to_string(),
                created_height: DEVNET_HEIGHT + 1,
            })
            .expect("devnet bid");
        let c = self
            .commit_encrypted_receipts(CommitReceiptInput {
                bid_id: b,
                ciphertext_commitment: "ciphertext:receipt:alpha".to_string(),
                receipt_body_root: "receipt-body-root:alpha".to_string(),
                receipt_metadata_root: "receipt-meta-root:alpha".to_string(),
                fee_payload_commitment: "fee-payload:alpha".to_string(),
                subscriber_tag_root: "subscriber-tags:alpha".to_string(),
                pq_ciphertext_capsule: "ml-kem-capsule:alpha".to_string(),
                receipt_count: 96,
                receipt_bytes: 48_512,
                privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
                created_height: DEVNET_HEIGHT + 2,
            })
            .expect("devnet commitment");
        self.attest_receipt_commitment(AttestReceiptInput {
            commitment_id: c.clone(),
            verifier_committee_id: "committee:pq-receipt-devnet".to_string(),
            verifier_key_root: "verifier-key-root:devnet".to_string(),
            pq_security_bits: 256,
            quorum_bps: DEFAULT_STRICT_QUORUM_BPS,
            verified_receipt_count: 96,
            verified_receipt_bytes: 48_512,
            transcript_root: "transcript:alpha".to_string(),
            signature_root: "ml-dsa-slh-signature-root:alpha".to_string(),
            signed_height: DEVNET_HEIGHT + 3,
        })
        .expect("devnet attestation");
        let sub = self
            .create_subscription(CreateSubscriptionInput {
                subscriber_commitment: "subscriber:private-defi-indexer".to_string(),
                namespace_id: "namespace:defi-receipts".to_string(),
                filter_root: "filter:low-fee-dex-and-lending".to_string(),
                prepaid_micro_fee: 10_000,
                privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
                created_height: DEVNET_HEIGHT + 2,
            })
            .expect("devnet subscription");
        self.settle_low_fee_batch(SettleBatchInput {
            window_id: w,
            operator_id: "operator:sealed-receipt-devnet".to_string(),
            lane: SettlementLane::LowFee,
            commitment_ids: vec![c],
            settled_height: DEVNET_HEIGHT + 4,
        })
        .expect("devnet settle");
        self.post_accounting(
            "devnet-subscription-prepay",
            &sub,
            "",
            AccountingSide::Escrow,
            10_000,
            DEVNET_HEIGHT + 5,
        )
        .expect("devnet accounting");
        self.refresh();
    }

    pub fn open_window(&mut self, input: OpenWindowInput) -> Result<String> {
        self.config.validate()?;
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set too small".to_string());
        }
        let window_id = id(
            "receipt-window",
            &[
                HashPart::U64(input.opened_height),
                HashPart::Str(input.domain.as_str()),
                HashPart::Str(input.lane.as_str()),
                HashPart::Str(&input.operator_commitment),
            ],
        );
        let record = ReceiptWindow {
            window_id: window_id.clone(),
            epoch: DEVNET_EPOCH + self.counters.receipt_windows,
            opened_height: input.opened_height,
            closes_height: input.opened_height + self.config.receipt_window_blocks,
            settlement_height: input.opened_height
                + self.config.receipt_window_blocks
                + self.config.batch_window_blocks,
            domain: input.domain,
            lane: input.lane,
            status: WindowStatus::CommitOpen,
            privacy_set_size: input.privacy_set_size,
            min_micro_fee: input.min_micro_fee.max(self.config.min_receipt_micro_fee),
            target_batch_bytes: input.target_batch_bytes,
            sealed_window_commitment: id("sealed-window", &[HashPart::Str(&window_id)]),
            operator_commitment: input.operator_commitment,
            replay_domain: format!("{}:{}", REPLAY_NULLIFIER_SUITE, window_id),
        };
        let root = record_root("SEALED-RECEIPT-WINDOW", &record.public_record());
        self.receipt_windows.insert(window_id.clone(), record);
        self.counters.receipt_windows += 1;
        self.push_event(
            input.opened_height,
            RuntimeEventKind::WindowOpened,
            &window_id,
            &root,
            json!({"lane": input.lane.as_str()}),
        );
        self.refresh();
        Ok(window_id)
    }
    pub fn submit_private_fee_bid(&mut self, input: SubmitBidInput) -> Result<String> {
        let window = self
            .receipt_windows
            .get(&input.window_id)
            .ok_or_else(|| "window missing".to_string())?
            .clone();
        if !window.status.active() {
            return Err("window inactive".to_string());
        }
        if input.max_receipts == 0 || input.max_receipts > self.config.max_receipts_per_bid {
            return Err("invalid receipt count".to_string());
        }
        if input.max_micro_fee < window.min_micro_fee {
            return Err("bid below window minimum".to_string());
        }
        if self.replay_nullifiers.contains_key(&input.replay_nullifier) {
            self.counters.rejected_duplicates += 1;
            return Err("duplicate replay nullifier".to_string());
        }
        let bid_id = id(
            "private-receipt-bid",
            &[
                HashPart::Str(&input.window_id),
                HashPart::Str(&input.bidder_commitment),
                HashPart::Str(&input.encrypted_bid_commitment),
            ],
        );
        let priority_hint = window
            .domain
            .priority_weight()
            .saturating_add(window.lane.priority_weight())
            .saturating_add(input.max_micro_fee);
        let record = PrivateReceiptFeeBid {
            bid_id: bid_id.clone(),
            window_id: input.window_id.clone(),
            bidder_commitment: input.bidder_commitment,
            contract_id: input.contract_id,
            domain: window.domain,
            receipt_kind: input.receipt_kind,
            lane: window.lane,
            status: BidStatus::ReplayGuarded,
            encrypted_bid_commitment: input.encrypted_bid_commitment,
            bid_value_commitment: input.bid_value_commitment,
            max_receipts: input.max_receipts,
            max_receipt_bytes: input.max_receipt_bytes,
            max_micro_fee: input.max_micro_fee,
            priority_hint,
            replay_nullifier: input.replay_nullifier.clone(),
            pq_bid_proof: input.pq_bid_proof,
            created_height: input.created_height,
            expires_height: window.closes_height,
        };
        let nullifier = ReplayNullifier {
            nullifier_id: input.replay_nullifier.clone(),
            window_id: input.window_id.clone(),
            bid_id: bid_id.clone(),
            commitment_id: String::new(),
            nullifier_root: id(
                "replay-nullifier-root",
                &[HashPart::Str(&input.replay_nullifier)],
            ),
            replay_domain: window.replay_domain,
            status: NullifierStatus::Armed,
            first_seen_height: input.created_height,
            expires_height: input.created_height + self.config.replay_window_blocks,
        };
        let root = record_root("PRIVATE-RECEIPT-FEE-BID", &record.public_record());
        self.private_fee_bids.insert(bid_id.clone(), record);
        self.replay_nullifiers
            .insert(input.replay_nullifier, nullifier);
        self.counters.private_fee_bids += 1;
        self.counters.replay_nullifiers += 1;
        self.counters.total_bid_micro_fee = self
            .counters
            .total_bid_micro_fee
            .saturating_add(input.max_micro_fee);
        self.push_event(
            input.created_height,
            RuntimeEventKind::BidSubmitted,
            &bid_id,
            &root,
            json!({"window_id": input.window_id}),
        );
        self.refresh();
        Ok(bid_id)
    }
    pub fn commit_encrypted_receipts(&mut self, input: CommitReceiptInput) -> Result<String> {
        let bid = self
            .private_fee_bids
            .get(&input.bid_id)
            .ok_or_else(|| "bid missing".to_string())?
            .clone();
        if !bid.status.pending() {
            return Err("bid not pending".to_string());
        }
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set too small".to_string());
        }
        if input.receipt_count == 0 || input.receipt_count > bid.max_receipts {
            return Err("receipt count outside bid".to_string());
        }
        if input.receipt_bytes > bid.max_receipt_bytes
            || input.receipt_bytes > self.config.max_receipt_bytes_per_batch
        {
            return Err("receipt bytes outside limit".to_string());
        }
        let commitment_id = id(
            "encrypted-receipt-commitment",
            &[
                HashPart::Str(&input.bid_id),
                HashPart::Str(&input.ciphertext_commitment),
                HashPart::Str(&input.receipt_body_root),
            ],
        );
        let record = EncryptedReceiptCommitment {
            commitment_id: commitment_id.clone(),
            bid_id: input.bid_id.clone(),
            window_id: bid.window_id.clone(),
            contract_id: bid.contract_id.clone(),
            receipt_kind: bid.receipt_kind,
            status: CommitmentStatus::Authenticated,
            ciphertext_commitment: input.ciphertext_commitment,
            receipt_body_root: input.receipt_body_root,
            receipt_metadata_root: input.receipt_metadata_root,
            fee_payload_commitment: input.fee_payload_commitment,
            subscriber_tag_root: input.subscriber_tag_root,
            pq_ciphertext_capsule: input.pq_ciphertext_capsule,
            receipt_count: input.receipt_count,
            receipt_bytes: input.receipt_bytes,
            privacy_set_size: input.privacy_set_size,
            created_height: input.created_height,
        };
        if let Some(b) = self.private_fee_bids.get_mut(&input.bid_id) {
            b.status = BidStatus::PqCommitted;
        }
        if let Some(n) = self.replay_nullifiers.get_mut(&bid.replay_nullifier) {
            n.commitment_id = commitment_id.clone();
            n.status = NullifierStatus::Armed;
        }
        let root = record_root("ENCRYPTED-RECEIPT-COMMITMENT", &record.public_record());
        self.encrypted_receipt_commitments
            .insert(commitment_id.clone(), record);
        self.counters.encrypted_receipt_commitments += 1;
        self.counters.total_receipt_bytes = self
            .counters
            .total_receipt_bytes
            .saturating_add(input.receipt_bytes);
        self.push_event(
            input.created_height,
            RuntimeEventKind::CommitmentSealed,
            &commitment_id,
            &root,
            json!({"bid_id": input.bid_id}),
        );
        self.refresh();
        Ok(commitment_id)
    }
    pub fn attest_receipt_commitment(&mut self, input: AttestReceiptInput) -> Result<String> {
        let commitment = self
            .encrypted_receipt_commitments
            .get(&input.commitment_id)
            .ok_or_else(|| "commitment missing".to_string())?
            .clone();
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq security below configured floor".to_string());
        }
        if input.quorum_bps < self.config.quorum_bps {
            return Err("quorum below configured floor".to_string());
        }
        if input.verified_receipt_count != commitment.receipt_count
            || input.verified_receipt_bytes != commitment.receipt_bytes
        {
            return Err("attestation does not match commitment".to_string());
        }
        let attestation_id = id(
            "pq-receipt-attestation",
            &[
                HashPart::Str(&input.commitment_id),
                HashPart::Str(&input.verifier_committee_id),
                HashPart::Str(&input.signature_root),
            ],
        );
        let record = PqVerifierAttestation {
            attestation_id: attestation_id.clone(),
            commitment_id: input.commitment_id.clone(),
            verifier_committee_id: input.verifier_committee_id,
            verifier_key_root: input.verifier_key_root,
            status: if input.quorum_bps >= self.config.strict_quorum_bps {
                AttestationStatus::QuorumSigned
            } else {
                AttestationStatus::Authenticated
            },
            scheme: PQ_VERIFIER_ATTESTATION_SUITE.to_string(),
            pq_security_bits: input.pq_security_bits,
            quorum_bps: input.quorum_bps,
            verified_receipt_count: input.verified_receipt_count,
            verified_receipt_bytes: input.verified_receipt_bytes,
            transcript_root: input.transcript_root,
            signature_root: input.signature_root,
            signed_height: input.signed_height,
            expires_height: input.signed_height + self.config.replay_window_blocks,
        };
        if let Some(c) = self
            .encrypted_receipt_commitments
            .get_mut(&input.commitment_id)
        {
            c.status = CommitmentStatus::QuorumSigned;
        }
        let root = record_root("PQ-RECEIPT-VERIFIER-ATTESTATION", &record.public_record());
        self.pq_verifier_attestations
            .insert(attestation_id.clone(), record);
        self.counters.pq_verifier_attestations += 1;
        self.push_event(
            input.signed_height,
            RuntimeEventKind::AttestationAccepted,
            &attestation_id,
            &root,
            json!({"commitment_id": input.commitment_id}),
        );
        self.refresh();
        Ok(attestation_id)
    }
    pub fn create_subscription(&mut self, input: CreateSubscriptionInput) -> Result<String> {
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set too small".to_string());
        }
        let subscription_id = id(
            "receipt-subscription",
            &[
                HashPart::Str(&input.subscriber_commitment),
                HashPart::Str(&input.namespace_id),
                HashPart::Str(&input.filter_root),
            ],
        );
        let record = SubscriptionRoot {
            subscription_id: subscription_id.clone(),
            subscriber_commitment: input.subscriber_commitment,
            namespace_id: input.namespace_id,
            status: SubscriptionStatus::Active,
            filter_root: input.filter_root,
            accounting_root: id(
                "subscription-accounting",
                &[HashPart::Str(&subscription_id)],
            ),
            prepaid_micro_fee: input.prepaid_micro_fee,
            spent_micro_fee: 0,
            delivered_receipts: 0,
            privacy_set_size: input.privacy_set_size,
            created_height: input.created_height,
            expires_height: input.created_height + self.config.subscription_epoch_blocks,
        };
        let root = record_root("SUBSCRIPTION-ROOT", &record.public_record());
        self.subscriptions.insert(subscription_id.clone(), record);
        self.counters.subscriptions += 1;
        self.push_event(
            input.created_height,
            RuntimeEventKind::SubscriptionUpdated,
            &subscription_id,
            &root,
            json!({"status":"active"}),
        );
        self.refresh();
        Ok(subscription_id)
    }
    pub fn settle_low_fee_batch(&mut self, input: SettleBatchInput) -> Result<String> {
        let mut seen = BTreeSet::new();
        let mut attestation_ids = Vec::new();
        let mut nullifier_ids = Vec::new();
        let mut receipt_count = 0u64;
        let mut receipt_bytes = 0u64;
        let mut gross = 0u64;
        for commitment_id in &input.commitment_ids {
            if !seen.insert(commitment_id.clone()) {
                return Err("duplicate commitment in batch".to_string());
            }
            let commitment = self
                .encrypted_receipt_commitments
                .get(commitment_id)
                .ok_or_else(|| "commitment missing".to_string())?;
            if commitment.window_id != input.window_id {
                return Err("commitment belongs to different window".to_string());
            }
            if !commitment.status.accepted() {
                return Err("commitment is not accepted".to_string());
            }
            let attestation = self
                .pq_verifier_attestations
                .values()
                .find(|a| {
                    a.commitment_id == *commitment_id
                        && matches!(
                            a.status,
                            AttestationStatus::Authenticated
                                | AttestationStatus::QuorumSigned
                                | AttestationStatus::Applied
                        )
                })
                .ok_or_else(|| "attestation missing".to_string())?;
            attestation_ids.push(attestation.attestation_id.clone());
            if let Some(bid) = self.private_fee_bids.get(&commitment.bid_id) {
                nullifier_ids.push(bid.replay_nullifier.clone());
                gross = gross.saturating_add(
                    bid.max_micro_fee.min(
                        commitment
                            .receipt_count
                            .saturating_mul(self.config.base_receipt_micro_fee),
                    ),
                );
            }
            receipt_count = receipt_count.saturating_add(commitment.receipt_count);
            receipt_bytes = receipt_bytes.saturating_add(commitment.receipt_bytes);
        }
        if input.commitment_ids.len() > self.config.max_commitments_per_batch {
            return Err("too many commitments".to_string());
        }
        if receipt_bytes > self.config.max_receipt_bytes_per_batch {
            return Err("batch bytes outside limit".to_string());
        }
        let operator_fee = bps(gross, self.config.operator_fee_bps);
        let rebate = bps(gross, self.config.batch_rebate_bps);
        let settled = gross.saturating_sub(rebate).saturating_add(operator_fee);
        let batch_id = id(
            "low-fee-receipt-batch",
            &[
                HashPart::Str(&input.window_id),
                HashPart::Str(&input.operator_id),
                HashPart::U64(input.settled_height),
            ],
        );
        let batch_root = merkle_root(
            "LOW-FEE-RECEIPT-BATCH-COMMITMENTS",
            &input
                .commitment_ids
                .iter()
                .map(|v| json!(v))
                .collect::<Vec<_>>(),
        );
        let record = LowFeeSettlementBatch {
            batch_id: batch_id.clone(),
            window_id: input.window_id.clone(),
            operator_id: input.operator_id,
            lane: input.lane,
            status: BatchStatus::Settled,
            commitment_ids: input.commitment_ids.clone(),
            attestation_ids,
            nullifier_ids: nullifier_ids.clone(),
            receipt_count,
            receipt_bytes,
            gross_micro_fee: gross,
            operator_micro_fee: operator_fee,
            rebate_micro_fee: rebate,
            settled_micro_fee: settled,
            batch_root,
            created_height: input
                .settled_height
                .saturating_sub(self.config.batch_window_blocks),
            settled_height: input.settled_height,
        };
        for idv in &input.commitment_ids {
            if let Some(c) = self.encrypted_receipt_commitments.get_mut(idv) {
                c.status = CommitmentStatus::Applied;
            }
        }
        for idv in &nullifier_ids {
            if let Some(n) = self.replay_nullifiers.get_mut(idv) {
                n.status = NullifierStatus::Consumed;
            }
        }
        if let Some(w) = self.receipt_windows.get_mut(&input.window_id) {
            w.status = WindowStatus::Settled;
        }
        let root = record_root("LOW-FEE-SETTLEMENT-BATCH", &record.public_record());
        self.low_fee_settlement_batches
            .insert(batch_id.clone(), record);
        self.counters.low_fee_settlement_batches += 1;
        self.counters.settled_receipts =
            self.counters.settled_receipts.saturating_add(receipt_count);
        self.counters.total_settled_micro_fee = self
            .counters
            .total_settled_micro_fee
            .saturating_add(settled);
        self.counters.total_rebate_micro_fee =
            self.counters.total_rebate_micro_fee.saturating_add(rebate);
        self.counters.total_operator_micro_fee = self
            .counters
            .total_operator_micro_fee
            .saturating_add(operator_fee);
        self.push_event(
            input.settled_height,
            RuntimeEventKind::BatchSettled,
            &batch_id,
            &root,
            json!({"receipt_count": receipt_count, "settled_micro_fee": settled}),
        );
        self.refresh();
        Ok(batch_id)
    }
    pub fn post_accounting(
        &mut self,
        subject_id: &str,
        subscription_id: &str,
        batch_id: &str,
        side: AccountingSide,
        amount_micro_fee: u64,
        height: u64,
    ) -> Result<String> {
        let entry_id = id(
            "receipt-accounting",
            &[
                HashPart::Str(subject_id),
                HashPart::Str(subscription_id),
                HashPart::Str(batch_id),
                HashPart::Str(side.as_str()),
                HashPart::U64(height),
            ],
        );
        let accounting_root = id(
            "receipt-accounting-root",
            &[HashPart::Str(&entry_id), HashPart::U64(amount_micro_fee)],
        );
        let record = AccountingRoot {
            entry_id: entry_id.clone(),
            subject_id: subject_id.to_string(),
            batch_id: batch_id.to_string(),
            subscription_id: subscription_id.to_string(),
            side,
            asset_id: self.config.fee_asset_id.clone(),
            amount_micro_fee,
            counterparty_commitment: subject_id.to_string(),
            accounting_root,
            posted_height: height,
        };
        if let Some(sub) = self.subscriptions.get_mut(subscription_id) {
            match side {
                AccountingSide::Debit => {
                    sub.spent_micro_fee = sub.spent_micro_fee.saturating_add(amount_micro_fee)
                }
                AccountingSide::Credit | AccountingSide::Escrow => {
                    sub.prepaid_micro_fee = sub.prepaid_micro_fee.saturating_add(amount_micro_fee)
                }
                _ => {}
            }
        }
        let root = record_root("ACCOUNTING-ROOT", &record.public_record());
        self.accounting_roots.insert(entry_id.clone(), record);
        self.counters.accounting_entries += 1;
        self.push_event(
            height,
            RuntimeEventKind::AccountingPosted,
            &entry_id,
            &root,
            json!({"amount_micro_fee": amount_micro_fee}),
        );
        self.refresh();
        Ok(entry_id)
    }
    fn push_event(
        &mut self,
        height: u64,
        kind: RuntimeEventKind,
        subject_id: &str,
        public_root: &str,
        details: Value,
    ) {
        let event_id = id(
            "sealed-receipt-runtime-event",
            &[
                HashPart::U64(height),
                HashPart::Str(kind.as_str()),
                HashPart::Str(subject_id),
                HashPart::Str(public_root),
            ],
        );
        self.runtime_events.insert(
            event_id.clone(),
            RuntimeEvent {
                event_id,
                height,
                kind,
                subject_id: subject_id.to_string(),
                public_root: public_root.to_string(),
                details,
            },
        );
        self.counters.runtime_events = self.runtime_events.len() as u64;
    }
    pub fn public_record_without_state_root(&self) -> Value {
        json!({ "kind": "private_l2_pq_confidential_contract_sealed_receipt_fee_market_runtime_state", "protocol_version": PROTOCOL_VERSION, "schema_version": SCHEMA_VERSION, "chain_id": CHAIN_ID, "config": self.config.public_record(), "counters": self.counters.public_record(), "roots": self.roots.public_record() })
    }
    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        let root = state_root_from_record(&record);
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(root));
        }
        record
    }
    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }
    pub fn refresh(&mut self) {
        self.recompute_counters();
        self.roots = self.compute_roots();
    }
    pub fn recompute_counters(&mut self) {
        self.counters.receipt_windows = self.receipt_windows.len() as u64;
        self.counters.private_fee_bids = self.private_fee_bids.len() as u64;
        self.counters.encrypted_receipt_commitments =
            self.encrypted_receipt_commitments.len() as u64;
        self.counters.pq_verifier_attestations = self.pq_verifier_attestations.len() as u64;
        self.counters.replay_nullifiers = self.replay_nullifiers.len() as u64;
        self.counters.low_fee_settlement_batches = self.low_fee_settlement_batches.len() as u64;
        self.counters.subscriptions = self.subscriptions.len() as u64;
        self.counters.accounting_entries = self.accounting_roots.len() as u64;
        self.counters.runtime_events = self.runtime_events.len() as u64;
        self.counters.accepted_bids = self
            .private_fee_bids
            .values()
            .filter(|b| {
                matches!(
                    b.status,
                    BidStatus::Accepted | BidStatus::PqCommitted | BidStatus::BatchQueued
                )
            })
            .count() as u64;
    }
    pub fn compute_roots(&self) -> Roots {
        Roots {
            config_root: record_root("SEALED-RECEIPT-CONFIG", &self.config.public_record()),
            receipt_window_root: map_root(
                RECEIPT_WINDOW_SCHEME,
                self.receipt_windows
                    .values()
                    .map(ReceiptWindow::public_record),
            ),
            private_fee_bid_root: map_root(
                PRIVATE_RECEIPT_BID_SCHEME,
                self.private_fee_bids
                    .values()
                    .map(PrivateReceiptFeeBid::public_record),
            ),
            encrypted_receipt_commitment_root: map_root(
                ENCRYPTED_RECEIPT_COMMITMENT_SCHEME,
                self.encrypted_receipt_commitments
                    .values()
                    .map(EncryptedReceiptCommitment::public_record),
            ),
            pq_verifier_attestation_root: map_root(
                PQ_VERIFIER_ATTESTATION_SCHEME,
                self.pq_verifier_attestations
                    .values()
                    .map(PqVerifierAttestation::public_record),
            ),
            replay_nullifier_root: map_root(
                REPLAY_NULLIFIER_SCHEME,
                self.replay_nullifiers
                    .values()
                    .map(ReplayNullifier::public_record),
            ),
            low_fee_settlement_batch_root: map_root(
                LOW_FEE_SETTLEMENT_BATCH_SCHEME,
                self.low_fee_settlement_batches
                    .values()
                    .map(LowFeeSettlementBatch::public_record),
            ),
            subscription_root: map_root(
                SUBSCRIPTION_ROOT_SCHEME,
                self.subscriptions
                    .values()
                    .map(SubscriptionRoot::public_record),
            ),
            accounting_root: map_root(
                ACCOUNTING_ROOT_SCHEME,
                self.accounting_roots
                    .values()
                    .map(AccountingRoot::public_record),
            ),
            runtime_event_root: map_root(
                "SEALED-RECEIPT-RUNTIME-EVENTS",
                self.runtime_events
                    .values()
                    .map(RuntimeEvent::public_record),
            ),
            public_record_root: record_root(
                PUBLIC_RECORD_ROOT_SCHEME,
                &self.public_record_without_state_root(),
            ),
        }
    }
}

pub fn bps(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / MAX_BPS
}
pub fn id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}
pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}
pub fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    merkle_root(domain, &records.into_iter().collect::<Vec<_>>())
}
pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-RECEIPT-FEE-MARKET:STATE-ROOT",
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
pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}
pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}
