use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractSealedStorageReceiptFeeNettingClearinghouseRuntimeResult<
    T,
> = std::result::Result<T, String>;
pub type Result<T> =
    PrivateL2PqConfidentialContractSealedStorageReceiptFeeNettingClearinghouseRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STORAGE_RECEIPT_FEE_NETTING_CLEARINGHOUSE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-sealed-storage-receipt-fee-netting-clearinghouse-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_SEALED_STORAGE_RECEIPT_FEE_NETTING_CLEARINGHOUSE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CLEARINGHOUSE_SUITE: &str =
    "pq-confidential-contract-sealed-storage-receipt-fee-netting-clearinghouse-v1";
pub const ROOTS_ONLY_PUBLIC_RECORD_SUITE: &str =
    "roots-only-confidential-storage-receipt-fee-netting-clearinghouse-public-record-v1";
pub const CLEARING_ROUND_SCHEME: &str = "sealed-storage-receipt-clearinghouse-round-root-v1";
pub const SEALED_CLAIM_SCHEME: &str = "sealed-storage-receipt-clearinghouse-claim-root-v1";
pub const NETTABLE_OBLIGATION_SCHEME: &str =
    "confidential-contract-clearinghouse-nettable-obligation-root-v1";
pub const CLEARING_QUOTE_SCHEME: &str = "low-fee-clearinghouse-quote-root-v1";
pub const CLEARING_AUCTION_SCHEME: &str = "fast-clearinghouse-auction-root-v1";
pub const SETTLEMENT_TICKET_SCHEME: &str =
    "confidential-contract-clearinghouse-settlement-ticket-root-v1";
pub const PQ_WITNESS_SCHEME: &str = "pq-clearinghouse-witness-root-v1";
pub const REPLAY_FILTER_SCHEME: &str = "clearinghouse-replay-filter-root-v1";
pub const FEE_BOOK_SCHEME: &str = "clearinghouse-fee-book-root-v1";
pub const RISK_BUCKET_SCHEME: &str = "clearinghouse-risk-bucket-root-v1";
pub const CONTRACT_SHARD_SCHEME: &str = "clearinghouse-contract-shard-root-v1";
pub const POLICY_ROOT_SCHEME: &str = "clearinghouse-privacy-pq-policy-root-v1";
pub const PUBLIC_RECORD_ROOT_SCHEME: &str = "clearinghouse-roots-only-public-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 6_104_064;
pub const DEVNET_EPOCH: u64 = 11_922;
pub const DEFAULT_CLEARING_WINDOW_BLOCKS: u64 = 10;
pub const DEFAULT_FAST_SETTLEMENT_BLOCKS: u64 = 2;
pub const DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 4;
pub const DEFAULT_MAX_CLAIMS_PER_ROUND: usize = 36_864;
pub const DEFAULT_MAX_OBLIGATIONS_PER_ROUND: usize = 24_576;
pub const DEFAULT_MAX_QUOTES_PER_AUCTION: usize = 12_288;
pub const DEFAULT_MAX_SETTLEMENT_TICKETS: usize = 16_384;
pub const DEFAULT_MAX_RECEIPT_BYTES_PER_ROUND: u64 = 10_485_760;
pub const DEFAULT_MAX_STORAGE_KEYS_PER_CLAIM: u64 = 131_072;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 2_097_152;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_MICRO_FEE: u64 = 1;
pub const DEFAULT_BASE_MICRO_FEE: u64 = 2;
pub const DEFAULT_CLEARING_OPERATOR_FEE_BPS: u64 = 2;
pub const DEFAULT_CROSS_CONTRACT_REBATE_BPS: u64 = 24;
pub const DEFAULT_LIQUIDITY_REBATE_BPS: u64 = 13;
pub const DEFAULT_DUST_SWEEP_BPS: u64 = 3;
pub const DEFAULT_CONGESTION_FEE_BPS: u64 = 4;
pub const DEFAULT_QUORUM_BPS: u64 = 6_800;
pub const DEFAULT_FAST_FINALITY_QUORUM_BPS: u64 = 8_500;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingLane {
    ContractCall,
    DefiSettlement,
    BridgeNetting,
    OracleDelivery,
    GovernanceExecution,
    AccountRecovery,
    EmergencyUnlock,
    PayrollBatch,
    CrossShardCommit,
    SponsoredStorage,
    MaintenanceSweep,
}

impl ClearingLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractCall => "contract_call",
            Self::DefiSettlement => "defi_settlement",
            Self::BridgeNetting => "bridge_netting",
            Self::OracleDelivery => "oracle_delivery",
            Self::GovernanceExecution => "governance_execution",
            Self::AccountRecovery => "account_recovery",
            Self::EmergencyUnlock => "emergency_unlock",
            Self::PayrollBatch => "payroll_batch",
            Self::CrossShardCommit => "cross_shard_commit",
            Self::SponsoredStorage => "sponsored_storage",
            Self::MaintenanceSweep => "maintenance_sweep",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyUnlock => 10_000,
            Self::AccountRecovery => 9_900,
            Self::BridgeNetting => 9_600,
            Self::CrossShardCommit => 9_300,
            Self::OracleDelivery => 9_050,
            Self::DefiSettlement => 8_850,
            Self::ContractCall => 8_650,
            Self::SponsoredStorage => 8_350,
            Self::PayrollBatch => 8_150,
            Self::GovernanceExecution => 7_950,
            Self::MaintenanceSweep => 7_600,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingRoundStatus {
    Announced,
    AcceptingClaims,
    LockingObligations,
    AuctioningLiquidity,
    PqWitnessed,
    FastSettling,
    Settled,
    Cancelled,
    Expired,
}

impl ClearingRoundStatus {
    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Announced | Self::AcceptingClaims)
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Announced
                | Self::AcceptingClaims
                | Self::LockingObligations
                | Self::AuctioningLiquidity
                | Self::PqWitnessed
                | Self::FastSettling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSide {
    Payable,
    Receivable,
    Rebate,
    Sponsor,
    Refund,
}

impl ClaimSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Payable => "payable",
            Self::Receivable => "receivable",
            Self::Rebate => "rebate",
            Self::Sponsor => "sponsor",
            Self::Refund => "refund",
        }
    }

    pub fn sign(self) -> i8 {
        match self {
            Self::Payable | Self::Sponsor => -1,
            Self::Receivable | Self::Rebate | Self::Refund => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedClaimStatus {
    Sealed,
    ReplayFiltered,
    ObligationBound,
    QuoteReady,
    Netted,
    Ticketed,
    Settled,
    Repriced,
    Refunded,
    DuplicateRejected,
    Expired,
}

impl SealedClaimStatus {
    pub fn nettable(self) -> bool {
        matches!(
            self,
            Self::ReplayFiltered | Self::ObligationBound | Self::QuoteReady
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationStatus {
    Pending,
    Balanced,
    PartiallyCleared,
    FullyCleared,
    DustSweep,
    Challenged,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Proposed,
    FeeBound,
    LiquidityChecked,
    RiskChecked,
    Accepted,
    Outbid,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Open,
    Selecting,
    Clearing,
    Witnessed,
    Settled,
    Cancelled,
    Expired,
}

impl AuctionStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Selecting | Self::Clearing | Self::Witnessed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    PendingWitness,
    Witnessed,
    FastFinalityReady,
    Included,
    Settled,
    Refunded,
    Challenged,
    Expired,
}

impl TicketStatus {
    pub fn finalizable(self) -> bool {
        matches!(
            self,
            Self::Witnessed | Self::FastFinalityReady | Self::Included
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub clearinghouse_suite: String,
    pub roots_only_public_record_suite: String,
    pub clearing_window_blocks: u64,
    pub fast_settlement_blocks: u64,
    pub replay_window_blocks: u64,
    pub auction_window_blocks: u64,
    pub max_claims_per_round: usize,
    pub max_obligations_per_round: usize,
    pub max_quotes_per_auction: usize,
    pub max_settlement_tickets: usize,
    pub max_receipt_bytes_per_round: u64,
    pub max_storage_keys_per_claim: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub min_micro_fee: u64,
    pub base_micro_fee: u64,
    pub clearing_operator_fee_bps: u64,
    pub cross_contract_rebate_bps: u64,
    pub liquidity_rebate_bps: u64,
    pub dust_sweep_bps: u64,
    pub congestion_fee_bps: u64,
    pub quorum_bps: u64,
    pub fast_finality_quorum_bps: u64,
    pub require_roots_only_public_records: bool,
    pub require_replay_filter: bool,
    pub require_pq_witness: bool,
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
            clearinghouse_suite: CLEARINGHOUSE_SUITE.to_string(),
            roots_only_public_record_suite: ROOTS_ONLY_PUBLIC_RECORD_SUITE.to_string(),
            clearing_window_blocks: DEFAULT_CLEARING_WINDOW_BLOCKS,
            fast_settlement_blocks: DEFAULT_FAST_SETTLEMENT_BLOCKS,
            replay_window_blocks: DEFAULT_REPLAY_WINDOW_BLOCKS,
            auction_window_blocks: DEFAULT_AUCTION_WINDOW_BLOCKS,
            max_claims_per_round: DEFAULT_MAX_CLAIMS_PER_ROUND,
            max_obligations_per_round: DEFAULT_MAX_OBLIGATIONS_PER_ROUND,
            max_quotes_per_auction: DEFAULT_MAX_QUOTES_PER_AUCTION,
            max_settlement_tickets: DEFAULT_MAX_SETTLEMENT_TICKETS,
            max_receipt_bytes_per_round: DEFAULT_MAX_RECEIPT_BYTES_PER_ROUND,
            max_storage_keys_per_claim: DEFAULT_MAX_STORAGE_KEYS_PER_CLAIM,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_micro_fee: DEFAULT_MIN_MICRO_FEE,
            base_micro_fee: DEFAULT_BASE_MICRO_FEE,
            clearing_operator_fee_bps: DEFAULT_CLEARING_OPERATOR_FEE_BPS,
            cross_contract_rebate_bps: DEFAULT_CROSS_CONTRACT_REBATE_BPS,
            liquidity_rebate_bps: DEFAULT_LIQUIDITY_REBATE_BPS,
            dust_sweep_bps: DEFAULT_DUST_SWEEP_BPS,
            congestion_fee_bps: DEFAULT_CONGESTION_FEE_BPS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            fast_finality_quorum_bps: DEFAULT_FAST_FINALITY_QUORUM_BPS,
            require_roots_only_public_records: true,
            require_replay_filter: true,
            require_pq_witness: true,
            prefer_low_fee_clearing: true,
            prefer_fast_receipt_settlement: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("min_pq_security_bits below clearinghouse floor".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.target_privacy_set_size < self.min_privacy_set_size
        {
            return Err("invalid privacy set sizing".to_string());
        }
        for (name, value) in [
            ("clearing_operator_fee_bps", self.clearing_operator_fee_bps),
            ("cross_contract_rebate_bps", self.cross_contract_rebate_bps),
            ("liquidity_rebate_bps", self.liquidity_rebate_bps),
            ("dust_sweep_bps", self.dust_sweep_bps),
            ("congestion_fee_bps", self.congestion_fee_bps),
            ("quorum_bps", self.quorum_bps),
            ("fast_finality_quorum_bps", self.fast_finality_quorum_bps),
        ] {
            if value > MAX_BPS {
                return Err(format!("{name} exceeds MAX_BPS"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub clearing_rounds_opened: u64,
    pub sealed_claims_accepted: u64,
    pub duplicate_claims_rejected: u64,
    pub obligations_locked: u64,
    pub quotes_recorded: u64,
    pub auctions_opened: u64,
    pub auctions_cleared: u64,
    pub settlement_tickets_issued: u64,
    pub settlement_tickets_finalized: u64,
    pub pq_witnesses_recorded: u64,
    pub replay_filters_recorded: u64,
    pub risk_buckets_updated: u64,
    pub fee_book_updates: u64,
    pub low_fee_rebates_applied: u64,
    pub fast_settlements: u64,
    pub expired_records: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub clearing_round_root: String,
    pub sealed_claim_root: String,
    pub nettable_obligation_root: String,
    pub clearing_quote_root: String,
    pub clearing_auction_root: String,
    pub settlement_ticket_root: String,
    pub pq_witness_root: String,
    pub replay_filter_root: String,
    pub fee_book_root: String,
    pub risk_bucket_root: String,
    pub contract_shard_root: String,
    pub policy_root: String,
    pub public_record_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            clearing_round_root: empty_root(CLEARING_ROUND_SCHEME),
            sealed_claim_root: empty_root(SEALED_CLAIM_SCHEME),
            nettable_obligation_root: empty_root(NETTABLE_OBLIGATION_SCHEME),
            clearing_quote_root: empty_root(CLEARING_QUOTE_SCHEME),
            clearing_auction_root: empty_root(CLEARING_AUCTION_SCHEME),
            settlement_ticket_root: empty_root(SETTLEMENT_TICKET_SCHEME),
            pq_witness_root: empty_root(PQ_WITNESS_SCHEME),
            replay_filter_root: empty_root(REPLAY_FILTER_SCHEME),
            fee_book_root: empty_root(FEE_BOOK_SCHEME),
            risk_bucket_root: empty_root(RISK_BUCKET_SCHEME),
            contract_shard_root: empty_root(CONTRACT_SHARD_SCHEME),
            policy_root: empty_root(POLICY_ROOT_SCHEME),
            public_record_root: empty_root(PUBLIC_RECORD_ROOT_SCHEME),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClearingRoundInput {
    pub lane: ClearingLane,
    pub storage_namespace_root: String,
    pub participant_set_root: String,
    pub clearing_committee_root: String,
    pub fee_policy_root: String,
    pub settlement_asset_root: String,
    pub privacy_pool_root: String,
    pub opens_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedClaimInput {
    pub round_id: String,
    pub contract_commitment: String,
    pub sealed_receipt_root: String,
    pub storage_delta_root: String,
    pub fee_commitment_root: String,
    pub replay_nullifier: String,
    pub side: ClaimSide,
    pub receipt_bytes: u64,
    pub storage_keys: u64,
    pub max_micro_fee: u64,
    pub priority_micro_fee: u64,
    pub expires_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObligationInput {
    pub round_id: String,
    pub contract_commitment: String,
    pub obligation_commitment_root: String,
    pub payable_claim_root: String,
    pub receivable_claim_root: String,
    pub liquidity_hint_root: String,
    pub risk_bucket_id: String,
    pub gross_micro_fee: u64,
    pub nettable_micro_fee: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuoteInput {
    pub auction_id: String,
    pub obligation_id: String,
    pub liquidity_provider_commitment: String,
    pub quote_commitment_root: String,
    pub fee_delta_root: String,
    pub capacity_micro_fee: u64,
    pub requested_rebate_bps: u64,
    pub pq_security_bits: u16,
    pub expires_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuctionInput {
    pub round_id: String,
    pub obligation_root: String,
    pub liquidity_pool_root: String,
    pub clearing_price_root: String,
    pub opens_height: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementTicketInput {
    pub round_id: String,
    pub auction_id: String,
    pub obligation_id: String,
    pub quote_id: String,
    pub netted_claim_root: String,
    pub settlement_path_root: String,
    pub final_fee_commitment_root: String,
    pub fast_finality_votes: u64,
    pub quorum_weight: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqWitnessInput {
    pub subject_id: String,
    pub witness_committee_root: String,
    pub transcript_root: String,
    pub signature_bundle_root: String,
    pub pq_security_bits: u16,
    pub quorum_bps: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClearingRound {
    pub id: String,
    pub lane: ClearingLane,
    pub status: ClearingRoundStatus,
    pub storage_namespace_root: String,
    pub participant_set_root: String,
    pub clearing_committee_root: String,
    pub fee_policy_root: String,
    pub settlement_asset_root: String,
    pub privacy_pool_root: String,
    pub opens_height: u64,
    pub claim_deadline_height: u64,
    pub settlement_deadline_height: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub nonce: u64,
    pub claim_count: u64,
    pub obligation_count: u64,
    pub ticket_count: u64,
    pub aggregate_claim_root: String,
    pub aggregate_obligation_root: String,
    pub aggregate_ticket_root: String,
}

impl ClearingRound {
    pub fn record(&self) -> Value {
        json!({
            "id": self.id,
            "lane": self.lane,
            "status": self.status,
            "storage_namespace_root": self.storage_namespace_root,
            "participant_set_root": self.participant_set_root,
            "clearing_committee_root": self.clearing_committee_root,
            "fee_policy_root": self.fee_policy_root,
            "settlement_asset_root": self.settlement_asset_root,
            "privacy_pool_root": self.privacy_pool_root,
            "opens_height": self.opens_height,
            "claim_deadline_height": self.claim_deadline_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "nonce": self.nonce,
            "claim_count": self.claim_count,
            "obligation_count": self.obligation_count,
            "ticket_count": self.ticket_count,
            "aggregate_claim_root": self.aggregate_claim_root,
            "aggregate_obligation_root": self.aggregate_obligation_root,
            "aggregate_ticket_root": self.aggregate_ticket_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedClaim {
    pub id: String,
    pub round_id: String,
    pub status: SealedClaimStatus,
    pub contract_commitment: String,
    pub sealed_receipt_root: String,
    pub storage_delta_root: String,
    pub fee_commitment_root: String,
    pub replay_nullifier: String,
    pub side: ClaimSide,
    pub receipt_bytes: u64,
    pub storage_keys: u64,
    pub max_micro_fee: u64,
    pub priority_micro_fee: u64,
    pub accepted_height: u64,
    pub expires_height: u64,
    pub nonce: u64,
}

impl SealedClaim {
    pub fn record(&self) -> Value {
        json!({
            "id": self.id,
            "round_id": self.round_id,
            "status": self.status,
            "contract_commitment": self.contract_commitment,
            "sealed_receipt_root": self.sealed_receipt_root,
            "storage_delta_root": self.storage_delta_root,
            "fee_commitment_root": self.fee_commitment_root,
            "replay_nullifier": self.replay_nullifier,
            "side": self.side,
            "receipt_bytes": self.receipt_bytes,
            "storage_keys": self.storage_keys,
            "max_micro_fee": self.max_micro_fee,
            "priority_micro_fee": self.priority_micro_fee,
            "accepted_height": self.accepted_height,
            "expires_height": self.expires_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NettableObligation {
    pub id: String,
    pub round_id: String,
    pub status: ObligationStatus,
    pub contract_commitment: String,
    pub obligation_commitment_root: String,
    pub payable_claim_root: String,
    pub receivable_claim_root: String,
    pub liquidity_hint_root: String,
    pub risk_bucket_id: String,
    pub gross_micro_fee: u64,
    pub nettable_micro_fee: u64,
    pub operator_micro_fee: u64,
    pub rebate_micro_fee: u64,
    pub dust_micro_fee: u64,
    pub created_height: u64,
    pub nonce: u64,
}

impl NettableObligation {
    pub fn record(&self) -> Value {
        json!({
            "id": self.id,
            "round_id": self.round_id,
            "status": self.status,
            "contract_commitment": self.contract_commitment,
            "obligation_commitment_root": self.obligation_commitment_root,
            "payable_claim_root": self.payable_claim_root,
            "receivable_claim_root": self.receivable_claim_root,
            "liquidity_hint_root": self.liquidity_hint_root,
            "risk_bucket_id": self.risk_bucket_id,
            "gross_micro_fee": self.gross_micro_fee,
            "nettable_micro_fee": self.nettable_micro_fee,
            "operator_micro_fee": self.operator_micro_fee,
            "rebate_micro_fee": self.rebate_micro_fee,
            "dust_micro_fee": self.dust_micro_fee,
            "created_height": self.created_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClearingAuction {
    pub id: String,
    pub round_id: String,
    pub status: AuctionStatus,
    pub obligation_root: String,
    pub liquidity_pool_root: String,
    pub clearing_price_root: String,
    pub opens_height: u64,
    pub quote_deadline_height: u64,
    pub settlement_deadline_height: u64,
    pub quote_count: u64,
    pub accepted_quote_root: String,
    pub nonce: u64,
}

impl ClearingAuction {
    pub fn record(&self) -> Value {
        json!({
            "id": self.id,
            "round_id": self.round_id,
            "status": self.status,
            "obligation_root": self.obligation_root,
            "liquidity_pool_root": self.liquidity_pool_root,
            "clearing_price_root": self.clearing_price_root,
            "opens_height": self.opens_height,
            "quote_deadline_height": self.quote_deadline_height,
            "settlement_deadline_height": self.settlement_deadline_height,
            "quote_count": self.quote_count,
            "accepted_quote_root": self.accepted_quote_root,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClearingQuote {
    pub id: String,
    pub auction_id: String,
    pub obligation_id: String,
    pub status: QuoteStatus,
    pub liquidity_provider_commitment: String,
    pub quote_commitment_root: String,
    pub fee_delta_root: String,
    pub capacity_micro_fee: u64,
    pub requested_rebate_bps: u64,
    pub effective_micro_fee: u64,
    pub pq_security_bits: u16,
    pub accepted_height: u64,
    pub expires_height: u64,
    pub nonce: u64,
}

impl ClearingQuote {
    pub fn record(&self) -> Value {
        json!({
            "id": self.id,
            "auction_id": self.auction_id,
            "obligation_id": self.obligation_id,
            "status": self.status,
            "liquidity_provider_commitment": self.liquidity_provider_commitment,
            "quote_commitment_root": self.quote_commitment_root,
            "fee_delta_root": self.fee_delta_root,
            "capacity_micro_fee": self.capacity_micro_fee,
            "requested_rebate_bps": self.requested_rebate_bps,
            "effective_micro_fee": self.effective_micro_fee,
            "pq_security_bits": self.pq_security_bits,
            "accepted_height": self.accepted_height,
            "expires_height": self.expires_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementTicket {
    pub id: String,
    pub round_id: String,
    pub auction_id: String,
    pub obligation_id: String,
    pub quote_id: String,
    pub status: TicketStatus,
    pub netted_claim_root: String,
    pub settlement_path_root: String,
    pub final_fee_commitment_root: String,
    pub fast_finality_votes: u64,
    pub quorum_weight: u64,
    pub issued_height: u64,
    pub finality_height: u64,
    pub nonce: u64,
}

impl SettlementTicket {
    pub fn record(&self) -> Value {
        json!({
            "id": self.id,
            "round_id": self.round_id,
            "auction_id": self.auction_id,
            "obligation_id": self.obligation_id,
            "quote_id": self.quote_id,
            "status": self.status,
            "netted_claim_root": self.netted_claim_root,
            "settlement_path_root": self.settlement_path_root,
            "final_fee_commitment_root": self.final_fee_commitment_root,
            "fast_finality_votes": self.fast_finality_votes,
            "quorum_weight": self.quorum_weight,
            "issued_height": self.issued_height,
            "finality_height": self.finality_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqWitness {
    pub id: String,
    pub subject_id: String,
    pub witness_committee_root: String,
    pub transcript_root: String,
    pub signature_bundle_root: String,
    pub pq_security_bits: u16,
    pub quorum_bps: u64,
    pub recorded_height: u64,
    pub nonce: u64,
}

impl PqWitness {
    pub fn record(&self) -> Value {
        json!({
            "id": self.id,
            "subject_id": self.subject_id,
            "witness_committee_root": self.witness_committee_root,
            "transcript_root": self.transcript_root,
            "signature_bundle_root": self.signature_bundle_root,
            "pq_security_bits": self.pq_security_bits,
            "quorum_bps": self.quorum_bps,
            "recorded_height": self.recorded_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeBookEntry {
    pub id: String,
    pub round_id: String,
    pub contract_commitment: String,
    pub gross_micro_fee: u64,
    pub net_micro_fee: u64,
    pub rebate_micro_fee: u64,
    pub operator_micro_fee: u64,
    pub updated_height: u64,
}

impl FeeBookEntry {
    pub fn record(&self) -> Value {
        json!({
            "id": self.id,
            "round_id": self.round_id,
            "contract_commitment": self.contract_commitment,
            "gross_micro_fee": self.gross_micro_fee,
            "net_micro_fee": self.net_micro_fee,
            "rebate_micro_fee": self.rebate_micro_fee,
            "operator_micro_fee": self.operator_micro_fee,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiskBucket {
    pub id: String,
    pub lane: ClearingLane,
    pub bucket_commitment_root: String,
    pub max_exposure_micro_fee: u64,
    pub current_exposure_micro_fee: u64,
    pub settlement_sla_blocks: u64,
    pub updated_height: u64,
}

impl RiskBucket {
    pub fn record(&self) -> Value {
        json!({
            "id": self.id,
            "lane": self.lane,
            "bucket_commitment_root": self.bucket_commitment_root,
            "max_exposure_micro_fee": self.max_exposure_micro_fee,
            "current_exposure_micro_fee": self.current_exposure_micro_fee,
            "settlement_sla_blocks": self.settlement_sla_blocks,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractShard {
    pub id: String,
    pub shard_commitment_root: String,
    pub contract_count: u64,
    pub sealed_storage_root: String,
    pub receipt_accumulator_root: String,
    pub updated_height: u64,
}

impl ContractShard {
    pub fn record(&self) -> Value {
        json!({
            "id": self.id,
            "shard_commitment_root": self.shard_commitment_root,
            "contract_count": self.contract_count,
            "sealed_storage_root": self.sealed_storage_root,
            "receipt_accumulator_root": self.receipt_accumulator_root,
            "updated_height": self.updated_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub clearing_rounds: BTreeMap<String, ClearingRound>,
    pub sealed_claims: BTreeMap<String, SealedClaim>,
    pub nettable_obligations: BTreeMap<String, NettableObligation>,
    pub clearing_auctions: BTreeMap<String, ClearingAuction>,
    pub clearing_quotes: BTreeMap<String, ClearingQuote>,
    pub settlement_tickets: BTreeMap<String, SettlementTicket>,
    pub pq_witnesses: BTreeMap<String, PqWitness>,
    pub replay_filters: BTreeSet<String>,
    pub fee_book: BTreeMap<String, FeeBookEntry>,
    pub risk_buckets: BTreeMap<String, RiskBucket>,
    pub contract_shards: BTreeMap<String, ContractShard>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            height,
            epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            clearing_rounds: BTreeMap::new(),
            sealed_claims: BTreeMap::new(),
            nettable_obligations: BTreeMap::new(),
            clearing_auctions: BTreeMap::new(),
            clearing_quotes: BTreeMap::new(),
            settlement_tickets: BTreeMap::new(),
            pq_witnesses: BTreeMap::new(),
            replay_filters: BTreeSet::new(),
            fee_book: BTreeMap::new(),
            risk_buckets: BTreeMap::new(),
            contract_shards: BTreeMap::new(),
        };
        state.recompute_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet(), DEVNET_HEIGHT, DEVNET_EPOCH)
            .expect("devnet clearinghouse config must be valid")
    }

    pub fn open_round(&mut self, input: ClearingRoundInput) -> Result<String> {
        self.config.validate()?;
        require_non_empty("storage_namespace_root", &input.storage_namespace_root)?;
        require_non_empty("participant_set_root", &input.participant_set_root)?;
        require_non_empty("clearing_committee_root", &input.clearing_committee_root)?;
        require_non_empty("fee_policy_root", &input.fee_policy_root)?;
        require_non_empty("settlement_asset_root", &input.settlement_asset_root)?;
        require_non_empty("privacy_pool_root", &input.privacy_pool_root)?;
        let id = clearing_round_id(
            input.lane,
            &input.storage_namespace_root,
            &input.participant_set_root,
            &input.clearing_committee_root,
            input.nonce,
        );
        if self.clearing_rounds.contains_key(&id) {
            return Err("clearing round already exists".to_string());
        }
        let claim_deadline_height = input
            .opens_height
            .saturating_add(self.config.clearing_window_blocks);
        let settlement_deadline_height = claim_deadline_height
            .saturating_add(self.config.auction_window_blocks)
            .saturating_add(self.config.fast_settlement_blocks);
        let round = ClearingRound {
            id: id.clone(),
            lane: input.lane,
            status: ClearingRoundStatus::Announced,
            storage_namespace_root: input.storage_namespace_root,
            participant_set_root: input.participant_set_root,
            clearing_committee_root: input.clearing_committee_root,
            fee_policy_root: input.fee_policy_root,
            settlement_asset_root: input.settlement_asset_root,
            privacy_pool_root: input.privacy_pool_root,
            opens_height: input.opens_height,
            claim_deadline_height,
            settlement_deadline_height,
            min_privacy_set_size: self.config.min_privacy_set_size,
            target_privacy_set_size: self.config.target_privacy_set_size,
            nonce: input.nonce,
            claim_count: 0,
            obligation_count: 0,
            ticket_count: 0,
            aggregate_claim_root: empty_root(SEALED_CLAIM_SCHEME),
            aggregate_obligation_root: empty_root(NETTABLE_OBLIGATION_SCHEME),
            aggregate_ticket_root: empty_root(SETTLEMENT_TICKET_SCHEME),
        };
        self.clearing_rounds.insert(id.clone(), round);
        self.counters.clearing_rounds_opened =
            self.counters.clearing_rounds_opened.saturating_add(1);
        self.recompute_roots();
        Ok(id)
    }

    pub fn accept_claim(&mut self, input: SealedClaimInput) -> Result<String> {
        require_non_empty("round_id", &input.round_id)?;
        require_non_empty("contract_commitment", &input.contract_commitment)?;
        require_non_empty("sealed_receipt_root", &input.sealed_receipt_root)?;
        require_non_empty("storage_delta_root", &input.storage_delta_root)?;
        require_non_empty("fee_commitment_root", &input.fee_commitment_root)?;
        require_non_empty("replay_nullifier", &input.replay_nullifier)?;
        if self.replay_filters.contains(&input.replay_nullifier) {
            self.counters.duplicate_claims_rejected =
                self.counters.duplicate_claims_rejected.saturating_add(1);
            return Err("duplicate replay nullifier".to_string());
        }
        if input.receipt_bytes > self.config.max_receipt_bytes_per_round {
            return Err("receipt bytes exceed clearing round limit".to_string());
        }
        if input.storage_keys > self.config.max_storage_keys_per_claim {
            return Err("storage keys exceed claim limit".to_string());
        }
        if input.max_micro_fee < self.config.min_micro_fee {
            return Err("max_micro_fee below minimum".to_string());
        }
        {
            let round = self
                .clearing_rounds
                .get(&input.round_id)
                .ok_or_else(|| "clearing round not found".to_string())?;
            if !round.status.accepts_claims() {
                return Err("clearing round is not accepting claims".to_string());
            }
            if self.height > round.claim_deadline_height || self.height > input.expires_height {
                return Err("claim expired before clearinghouse acceptance".to_string());
            }
            if round.claim_count as usize >= self.config.max_claims_per_round {
                return Err("clearing round claim capacity exhausted".to_string());
            }
        }
        let id = sealed_claim_id(
            &input.round_id,
            &input.contract_commitment,
            &input.sealed_receipt_root,
            input.nonce,
        );
        if self.sealed_claims.contains_key(&id) {
            self.counters.duplicate_claims_rejected =
                self.counters.duplicate_claims_rejected.saturating_add(1);
            return Err("sealed claim already exists".to_string());
        }
        let claim = SealedClaim {
            id: id.clone(),
            round_id: input.round_id.clone(),
            status: SealedClaimStatus::ReplayFiltered,
            contract_commitment: input.contract_commitment,
            sealed_receipt_root: input.sealed_receipt_root,
            storage_delta_root: input.storage_delta_root,
            fee_commitment_root: input.fee_commitment_root,
            replay_nullifier: input.replay_nullifier.clone(),
            side: input.side,
            receipt_bytes: input.receipt_bytes,
            storage_keys: input.storage_keys,
            max_micro_fee: input.max_micro_fee,
            priority_micro_fee: input.priority_micro_fee,
            accepted_height: self.height,
            expires_height: input.expires_height,
            nonce: input.nonce,
        };
        self.replay_filters.insert(input.replay_nullifier);
        self.sealed_claims.insert(id.clone(), claim);
        let aggregate_claim_root = self.round_claim_root(&input.round_id);
        if let Some(round) = self.clearing_rounds.get_mut(&input.round_id) {
            round.status = ClearingRoundStatus::AcceptingClaims;
            round.claim_count = round.claim_count.saturating_add(1);
            round.aggregate_claim_root = aggregate_claim_root;
        }
        self.counters.sealed_claims_accepted =
            self.counters.sealed_claims_accepted.saturating_add(1);
        self.counters.replay_filters_recorded =
            self.counters.replay_filters_recorded.saturating_add(1);
        self.recompute_roots();
        Ok(id)
    }

    pub fn lock_obligation(&mut self, input: ObligationInput) -> Result<String> {
        require_non_empty("round_id", &input.round_id)?;
        require_non_empty("contract_commitment", &input.contract_commitment)?;
        require_non_empty(
            "obligation_commitment_root",
            &input.obligation_commitment_root,
        )?;
        require_non_empty("payable_claim_root", &input.payable_claim_root)?;
        require_non_empty("receivable_claim_root", &input.receivable_claim_root)?;
        require_non_empty("liquidity_hint_root", &input.liquidity_hint_root)?;
        require_non_empty("risk_bucket_id", &input.risk_bucket_id)?;
        if input.gross_micro_fee < input.nettable_micro_fee {
            return Err("gross fee cannot be below nettable fee".to_string());
        }
        let round_lane = {
            let round = self
                .clearing_rounds
                .get(&input.round_id)
                .ok_or_else(|| "clearing round not found".to_string())?;
            if round.obligation_count as usize >= self.config.max_obligations_per_round {
                return Err("obligation capacity exhausted".to_string());
            }
            round.lane
        };
        let id = obligation_id(
            &input.round_id,
            &input.contract_commitment,
            &input.obligation_commitment_root,
            input.nonce,
        );
        if self.nettable_obligations.contains_key(&id) {
            return Err("nettable obligation already exists".to_string());
        }
        let operator_micro_fee = bps(
            input.nettable_micro_fee,
            self.config.clearing_operator_fee_bps,
        )
        .max(self.config.min_micro_fee);
        let cross_contract_rebate = bps(
            input.nettable_micro_fee,
            self.config.cross_contract_rebate_bps,
        );
        let liquidity_rebate = bps(input.nettable_micro_fee, self.config.liquidity_rebate_bps);
        let rebate_micro_fee = cross_contract_rebate.saturating_add(liquidity_rebate);
        let dust_micro_fee = bps(input.gross_micro_fee, self.config.dust_sweep_bps);
        let obligation = NettableObligation {
            id: id.clone(),
            round_id: input.round_id.clone(),
            status: ObligationStatus::Pending,
            contract_commitment: input.contract_commitment.clone(),
            obligation_commitment_root: input.obligation_commitment_root,
            payable_claim_root: input.payable_claim_root,
            receivable_claim_root: input.receivable_claim_root,
            liquidity_hint_root: input.liquidity_hint_root,
            risk_bucket_id: input.risk_bucket_id.clone(),
            gross_micro_fee: input.gross_micro_fee,
            nettable_micro_fee: input.nettable_micro_fee,
            operator_micro_fee,
            rebate_micro_fee,
            dust_micro_fee,
            created_height: self.height,
            nonce: input.nonce,
        };
        self.nettable_obligations.insert(id.clone(), obligation);
        self.update_fee_book(
            &input.round_id,
            &input.contract_commitment,
            input.gross_micro_fee,
            input.nettable_micro_fee,
            rebate_micro_fee,
            operator_micro_fee,
        );
        self.touch_risk_bucket(
            &input.risk_bucket_id,
            round_lane,
            input.nettable_micro_fee,
            DEFAULT_MAX_RECEIPT_BYTES_PER_ROUND,
        );
        let aggregate_obligation_root = self.round_obligation_root(&input.round_id);
        if let Some(round) = self.clearing_rounds.get_mut(&input.round_id) {
            round.status = ClearingRoundStatus::LockingObligations;
            round.obligation_count = round.obligation_count.saturating_add(1);
            round.aggregate_obligation_root = aggregate_obligation_root;
        }
        self.counters.obligations_locked = self.counters.obligations_locked.saturating_add(1);
        self.recompute_roots();
        Ok(id)
    }

    pub fn open_auction(&mut self, input: AuctionInput) -> Result<String> {
        require_non_empty("round_id", &input.round_id)?;
        require_non_empty("obligation_root", &input.obligation_root)?;
        require_non_empty("liquidity_pool_root", &input.liquidity_pool_root)?;
        require_non_empty("clearing_price_root", &input.clearing_price_root)?;
        if !self.clearing_rounds.contains_key(&input.round_id) {
            return Err("clearing round not found".to_string());
        }
        let id = auction_id(
            &input.round_id,
            &input.obligation_root,
            &input.liquidity_pool_root,
            input.nonce,
        );
        if self.clearing_auctions.contains_key(&id) {
            return Err("clearing auction already exists".to_string());
        }
        let quote_deadline_height = input
            .opens_height
            .saturating_add(self.config.auction_window_blocks);
        let settlement_deadline_height =
            quote_deadline_height.saturating_add(self.config.fast_settlement_blocks);
        let auction = ClearingAuction {
            id: id.clone(),
            round_id: input.round_id.clone(),
            status: AuctionStatus::Open,
            obligation_root: input.obligation_root,
            liquidity_pool_root: input.liquidity_pool_root,
            clearing_price_root: input.clearing_price_root,
            opens_height: input.opens_height,
            quote_deadline_height,
            settlement_deadline_height,
            quote_count: 0,
            accepted_quote_root: empty_root(CLEARING_QUOTE_SCHEME),
            nonce: input.nonce,
        };
        self.clearing_auctions.insert(id.clone(), auction);
        if let Some(round) = self.clearing_rounds.get_mut(&input.round_id) {
            round.status = ClearingRoundStatus::AuctioningLiquidity;
        }
        self.counters.auctions_opened = self.counters.auctions_opened.saturating_add(1);
        self.recompute_roots();
        Ok(id)
    }

    pub fn record_quote(&mut self, input: QuoteInput) -> Result<String> {
        require_non_empty("auction_id", &input.auction_id)?;
        require_non_empty("obligation_id", &input.obligation_id)?;
        require_non_empty(
            "liquidity_provider_commitment",
            &input.liquidity_provider_commitment,
        )?;
        require_non_empty("quote_commitment_root", &input.quote_commitment_root)?;
        require_non_empty("fee_delta_root", &input.fee_delta_root)?;
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("quote pq security below clearinghouse floor".to_string());
        }
        if input.requested_rebate_bps > MAX_BPS {
            return Err("requested rebate exceeds MAX_BPS".to_string());
        }
        let auction = self
            .clearing_auctions
            .get_mut(&input.auction_id)
            .ok_or_else(|| "clearing auction not found".to_string())?;
        if auction.quote_count as usize >= self.config.max_quotes_per_auction {
            return Err("quote capacity exhausted".to_string());
        }
        if self.height > auction.quote_deadline_height || self.height > input.expires_height {
            return Err("quote expired".to_string());
        }
        let obligation = self
            .nettable_obligations
            .get(&input.obligation_id)
            .ok_or_else(|| "nettable obligation not found".to_string())?;
        let id = quote_id(
            &input.auction_id,
            &input.obligation_id,
            &input.quote_commitment_root,
            input.nonce,
        );
        if self.clearing_quotes.contains_key(&id) {
            return Err("clearing quote already exists".to_string());
        }
        let rebate = bps(obligation.nettable_micro_fee, input.requested_rebate_bps);
        let congestion = bps(
            obligation.nettable_micro_fee,
            self.config.congestion_fee_bps,
        );
        let effective_micro_fee = self
            .config
            .base_micro_fee
            .saturating_add(congestion)
            .saturating_add(obligation.operator_micro_fee)
            .saturating_sub(rebate)
            .max(self.config.min_micro_fee);
        let quote = ClearingQuote {
            id: id.clone(),
            auction_id: input.auction_id.clone(),
            obligation_id: input.obligation_id,
            status: QuoteStatus::LiquidityChecked,
            liquidity_provider_commitment: input.liquidity_provider_commitment,
            quote_commitment_root: input.quote_commitment_root,
            fee_delta_root: input.fee_delta_root,
            capacity_micro_fee: input.capacity_micro_fee,
            requested_rebate_bps: input.requested_rebate_bps,
            effective_micro_fee,
            pq_security_bits: input.pq_security_bits,
            accepted_height: self.height,
            expires_height: input.expires_height,
            nonce: input.nonce,
        };
        self.clearing_quotes.insert(id.clone(), quote);
        auction.status = AuctionStatus::Selecting;
        auction.quote_count = auction.quote_count.saturating_add(1);
        auction.accepted_quote_root = self.auction_quote_root(&input.auction_id);
        self.counters.quotes_recorded = self.counters.quotes_recorded.saturating_add(1);
        self.recompute_roots();
        Ok(id)
    }

    pub fn issue_ticket(&mut self, input: SettlementTicketInput) -> Result<String> {
        require_non_empty("round_id", &input.round_id)?;
        require_non_empty("auction_id", &input.auction_id)?;
        require_non_empty("obligation_id", &input.obligation_id)?;
        require_non_empty("quote_id", &input.quote_id)?;
        require_non_empty("netted_claim_root", &input.netted_claim_root)?;
        require_non_empty("settlement_path_root", &input.settlement_path_root)?;
        require_non_empty(
            "final_fee_commitment_root",
            &input.final_fee_commitment_root,
        )?;
        if self.settlement_tickets.len() >= self.config.max_settlement_tickets {
            return Err("settlement ticket capacity exhausted".to_string());
        }
        if !self.clearing_rounds.contains_key(&input.round_id) {
            return Err("clearing round not found".to_string());
        }
        let auction = self
            .clearing_auctions
            .get_mut(&input.auction_id)
            .ok_or_else(|| "clearing auction not found".to_string())?;
        let obligation = self
            .nettable_obligations
            .get_mut(&input.obligation_id)
            .ok_or_else(|| "nettable obligation not found".to_string())?;
        let quote = self
            .clearing_quotes
            .get_mut(&input.quote_id)
            .ok_or_else(|| "clearing quote not found".to_string())?;
        let id = settlement_ticket_id(
            &input.round_id,
            &input.auction_id,
            &input.obligation_id,
            &input.netted_claim_root,
            input.nonce,
        );
        if self.settlement_tickets.contains_key(&id) {
            return Err("settlement ticket already exists".to_string());
        }
        let fast_ready = quorum_ready(
            input.fast_finality_votes,
            input.quorum_weight,
            self.config.fast_finality_quorum_bps,
        );
        let status = if fast_ready {
            TicketStatus::FastFinalityReady
        } else {
            TicketStatus::PendingWitness
        };
        let ticket = SettlementTicket {
            id: id.clone(),
            round_id: input.round_id.clone(),
            auction_id: input.auction_id.clone(),
            obligation_id: input.obligation_id.clone(),
            quote_id: input.quote_id.clone(),
            status,
            netted_claim_root: input.netted_claim_root,
            settlement_path_root: input.settlement_path_root,
            final_fee_commitment_root: input.final_fee_commitment_root,
            fast_finality_votes: input.fast_finality_votes,
            quorum_weight: input.quorum_weight,
            issued_height: self.height,
            finality_height: self
                .height
                .saturating_add(self.config.fast_settlement_blocks),
            nonce: input.nonce,
        };
        self.settlement_tickets.insert(id.clone(), ticket);
        obligation.status = ObligationStatus::PartiallyCleared;
        quote.status = QuoteStatus::Accepted;
        auction.status = AuctionStatus::Clearing;
        let aggregate_ticket_root = self.round_ticket_root(&input.round_id);
        if let Some(round) = self.clearing_rounds.get_mut(&input.round_id) {
            round.status = ClearingRoundStatus::FastSettling;
            round.ticket_count = round.ticket_count.saturating_add(1);
            round.aggregate_ticket_root = aggregate_ticket_root;
        }
        self.counters.settlement_tickets_issued =
            self.counters.settlement_tickets_issued.saturating_add(1);
        if fast_ready {
            self.counters.fast_settlements = self.counters.fast_settlements.saturating_add(1);
        }
        self.recompute_roots();
        Ok(id)
    }

    pub fn record_pq_witness(&mut self, input: PqWitnessInput) -> Result<String> {
        require_non_empty("subject_id", &input.subject_id)?;
        require_non_empty("witness_committee_root", &input.witness_committee_root)?;
        require_non_empty("transcript_root", &input.transcript_root)?;
        require_non_empty("signature_bundle_root", &input.signature_bundle_root)?;
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq witness security below clearinghouse floor".to_string());
        }
        if input.quorum_bps < self.config.quorum_bps {
            return Err("pq witness quorum below clearinghouse requirement".to_string());
        }
        let id = pq_witness_id(
            &input.subject_id,
            &input.transcript_root,
            &input.signature_bundle_root,
            input.nonce,
        );
        if self.pq_witnesses.contains_key(&id) {
            return Err("pq witness already exists".to_string());
        }
        let witness = PqWitness {
            id: id.clone(),
            subject_id: input.subject_id.clone(),
            witness_committee_root: input.witness_committee_root,
            transcript_root: input.transcript_root,
            signature_bundle_root: input.signature_bundle_root,
            pq_security_bits: input.pq_security_bits,
            quorum_bps: input.quorum_bps,
            recorded_height: self.height,
            nonce: input.nonce,
        };
        self.pq_witnesses.insert(id.clone(), witness);
        if let Some(round) = self.clearing_rounds.get_mut(&input.subject_id) {
            round.status = ClearingRoundStatus::PqWitnessed;
        }
        if let Some(auction) = self.clearing_auctions.get_mut(&input.subject_id) {
            auction.status = AuctionStatus::Witnessed;
        }
        if let Some(ticket) = self.settlement_tickets.get_mut(&input.subject_id) {
            ticket.status = TicketStatus::Witnessed;
        }
        self.counters.pq_witnesses_recorded = self.counters.pq_witnesses_recorded.saturating_add(1);
        self.recompute_roots();
        Ok(id)
    }

    pub fn finalize_ticket(&mut self, ticket_id: &str) -> Result<()> {
        require_non_empty("ticket_id", ticket_id)?;
        let ticket = self
            .settlement_tickets
            .get_mut(ticket_id)
            .ok_or_else(|| "settlement ticket not found".to_string())?;
        if !ticket.status.finalizable() {
            return Err("settlement ticket is not finalizable".to_string());
        }
        if self.height < ticket.finality_height {
            return Err("settlement finality height not reached".to_string());
        }
        ticket.status = TicketStatus::Settled;
        if let Some(obligation) = self.nettable_obligations.get_mut(&ticket.obligation_id) {
            obligation.status = ObligationStatus::FullyCleared;
        }
        if let Some(auction) = self.clearing_auctions.get_mut(&ticket.auction_id) {
            auction.status = AuctionStatus::Settled;
        }
        if let Some(round) = self.clearing_rounds.get_mut(&ticket.round_id) {
            round.status = ClearingRoundStatus::Settled;
        }
        self.counters.settlement_tickets_finalized =
            self.counters.settlement_tickets_finalized.saturating_add(1);
        self.recompute_roots();
        Ok(())
    }

    pub fn advance_height(&mut self, height: u64, epoch: u64) {
        self.height = self.height.max(height);
        self.epoch = self.epoch.max(epoch);
        self.expire_stale_records();
        self.recompute_roots();
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "l2_network": self.config.l2_network,
            "height": self.height,
            "epoch": self.epoch,
            "suite": self.config.roots_only_public_record_suite,
            "privacy": {
                "roots_only": self.config.require_roots_only_public_records,
                "min_privacy_set_size": self.config.min_privacy_set_size,
                "target_privacy_set_size": self.config.target_privacy_set_size,
                "min_pq_security_bits": self.config.min_pq_security_bits,
                "replay_filter_required": self.config.require_replay_filter,
                "pq_witness_required": self.config.require_pq_witness,
            },
            "priorities": {
                "smart_contracts": true,
                "privacy": true,
                "quantum_resistance": true,
                "low_fees": self.config.prefer_low_fee_clearing,
                "fast_receipt_settlement": self.config.prefer_fast_receipt_settlement,
            },
            "counters": self.counters,
            "roots": self.roots,
            "state_root": state_root_from_roots(&self.roots),
        })
    }

    fn update_fee_book(
        &mut self,
        round_id: &str,
        contract_commitment: &str,
        gross_micro_fee: u64,
        net_micro_fee: u64,
        rebate_micro_fee: u64,
        operator_micro_fee: u64,
    ) {
        let id = fee_book_id(round_id, contract_commitment);
        let entry = FeeBookEntry {
            id: id.clone(),
            round_id: round_id.to_string(),
            contract_commitment: contract_commitment.to_string(),
            gross_micro_fee,
            net_micro_fee,
            rebate_micro_fee,
            operator_micro_fee,
            updated_height: self.height,
        };
        self.fee_book.insert(id, entry);
        self.counters.fee_book_updates = self.counters.fee_book_updates.saturating_add(1);
        self.counters.low_fee_rebates_applied =
            self.counters.low_fee_rebates_applied.saturating_add(1);
    }

    fn touch_risk_bucket(
        &mut self,
        bucket_id: &str,
        lane: ClearingLane,
        exposure_micro_fee: u64,
        max_exposure_micro_fee: u64,
    ) {
        let settlement_sla_blocks = self.config.fast_settlement_blocks;
        let height = self.height;
        let bucket = self
            .risk_buckets
            .entry(bucket_id.to_string())
            .or_insert_with(|| RiskBucket {
                id: bucket_id.to_string(),
                lane,
                bucket_commitment_root: payload_root(
                    RISK_BUCKET_SCHEME,
                    &json!({ "bucket_id": bucket_id }),
                ),
                max_exposure_micro_fee,
                current_exposure_micro_fee: 0,
                settlement_sla_blocks,
                updated_height: height,
            });
        bucket.current_exposure_micro_fee = bucket
            .current_exposure_micro_fee
            .saturating_add(exposure_micro_fee);
        bucket.updated_height = height;
        self.counters.risk_buckets_updated = self.counters.risk_buckets_updated.saturating_add(1);
    }

    fn round_claim_root(&self, round_id: &str) -> String {
        record_root(
            SEALED_CLAIM_SCHEME,
            &self
                .sealed_claims
                .values()
                .filter(|claim| claim.round_id == round_id)
                .map(SealedClaim::record)
                .collect::<Vec<_>>(),
        )
    }

    fn round_obligation_root(&self, round_id: &str) -> String {
        record_root(
            NETTABLE_OBLIGATION_SCHEME,
            &self
                .nettable_obligations
                .values()
                .filter(|obligation| obligation.round_id == round_id)
                .map(NettableObligation::record)
                .collect::<Vec<_>>(),
        )
    }

    fn round_ticket_root(&self, round_id: &str) -> String {
        record_root(
            SETTLEMENT_TICKET_SCHEME,
            &self
                .settlement_tickets
                .values()
                .filter(|ticket| ticket.round_id == round_id)
                .map(SettlementTicket::record)
                .collect::<Vec<_>>(),
        )
    }

    fn auction_quote_root(&self, auction_id: &str) -> String {
        record_root(
            CLEARING_QUOTE_SCHEME,
            &self
                .clearing_quotes
                .values()
                .filter(|quote| quote.auction_id == auction_id)
                .map(ClearingQuote::record)
                .collect::<Vec<_>>(),
        )
    }

    fn recompute_roots(&mut self) {
        let mut roots = Roots {
            clearing_round_root: record_root(
                CLEARING_ROUND_SCHEME,
                &self
                    .clearing_rounds
                    .values()
                    .map(ClearingRound::record)
                    .collect::<Vec<_>>(),
            ),
            sealed_claim_root: record_root(
                SEALED_CLAIM_SCHEME,
                &self
                    .sealed_claims
                    .values()
                    .map(SealedClaim::record)
                    .collect::<Vec<_>>(),
            ),
            nettable_obligation_root: record_root(
                NETTABLE_OBLIGATION_SCHEME,
                &self
                    .nettable_obligations
                    .values()
                    .map(NettableObligation::record)
                    .collect::<Vec<_>>(),
            ),
            clearing_quote_root: record_root(
                CLEARING_QUOTE_SCHEME,
                &self
                    .clearing_quotes
                    .values()
                    .map(ClearingQuote::record)
                    .collect::<Vec<_>>(),
            ),
            clearing_auction_root: record_root(
                CLEARING_AUCTION_SCHEME,
                &self
                    .clearing_auctions
                    .values()
                    .map(ClearingAuction::record)
                    .collect::<Vec<_>>(),
            ),
            settlement_ticket_root: record_root(
                SETTLEMENT_TICKET_SCHEME,
                &self
                    .settlement_tickets
                    .values()
                    .map(SettlementTicket::record)
                    .collect::<Vec<_>>(),
            ),
            pq_witness_root: record_root(
                PQ_WITNESS_SCHEME,
                &self
                    .pq_witnesses
                    .values()
                    .map(PqWitness::record)
                    .collect::<Vec<_>>(),
            ),
            replay_filter_root: string_set_root(REPLAY_FILTER_SCHEME, &self.replay_filters),
            fee_book_root: record_root(
                FEE_BOOK_SCHEME,
                &self
                    .fee_book
                    .values()
                    .map(FeeBookEntry::record)
                    .collect::<Vec<_>>(),
            ),
            risk_bucket_root: record_root(
                RISK_BUCKET_SCHEME,
                &self
                    .risk_buckets
                    .values()
                    .map(RiskBucket::record)
                    .collect::<Vec<_>>(),
            ),
            contract_shard_root: record_root(
                CONTRACT_SHARD_SCHEME,
                &self
                    .contract_shards
                    .values()
                    .map(ContractShard::record)
                    .collect::<Vec<_>>(),
            ),
            policy_root: payload_root(
                POLICY_ROOT_SCHEME,
                &json!({
                    "protocol_version": self.config.protocol_version,
                    "hash_suite": self.config.hash_suite,
                    "clearinghouse_suite": self.config.clearinghouse_suite,
                    "min_privacy_set_size": self.config.min_privacy_set_size,
                    "target_privacy_set_size": self.config.target_privacy_set_size,
                    "min_pq_security_bits": self.config.min_pq_security_bits,
                    "low_fee": self.config.prefer_low_fee_clearing,
                    "fast_settlement": self.config.prefer_fast_receipt_settlement,
                }),
            ),
            public_record_root: empty_root(PUBLIC_RECORD_ROOT_SCHEME),
        };
        roots.public_record_root = payload_root(
            PUBLIC_RECORD_ROOT_SCHEME,
            &json!({
                "protocol_version": self.config.protocol_version,
                "height": self.height,
                "epoch": self.epoch,
                "roots": {
                    "clearing_round_root": roots.clearing_round_root,
                    "sealed_claim_root": roots.sealed_claim_root,
                    "nettable_obligation_root": roots.nettable_obligation_root,
                    "clearing_quote_root": roots.clearing_quote_root,
                    "clearing_auction_root": roots.clearing_auction_root,
                    "settlement_ticket_root": roots.settlement_ticket_root,
                    "pq_witness_root": roots.pq_witness_root,
                    "replay_filter_root": roots.replay_filter_root,
                    "fee_book_root": roots.fee_book_root,
                    "risk_bucket_root": roots.risk_bucket_root,
                    "contract_shard_root": roots.contract_shard_root,
                    "policy_root": roots.policy_root,
                },
            }),
        );
        self.roots = roots;
    }

    fn expire_stale_records(&mut self) {
        let mut expired = 0_u64;
        for round in self.clearing_rounds.values_mut() {
            if round.status.active() && self.height > round.settlement_deadline_height {
                round.status = ClearingRoundStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for claim in self.sealed_claims.values_mut() {
            if matches!(
                claim.status,
                SealedClaimStatus::Sealed
                    | SealedClaimStatus::ReplayFiltered
                    | SealedClaimStatus::ObligationBound
                    | SealedClaimStatus::QuoteReady
            ) && self.height > claim.expires_height
            {
                claim.status = SealedClaimStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for auction in self.clearing_auctions.values_mut() {
            if auction.status.active() && self.height > auction.settlement_deadline_height {
                auction.status = AuctionStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for quote in self.clearing_quotes.values_mut() {
            if !matches!(
                quote.status,
                QuoteStatus::Accepted | QuoteStatus::Outbid | QuoteStatus::Rejected
            ) && self.height > quote.expires_height
            {
                quote.status = QuoteStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        for ticket in self.settlement_tickets.values_mut() {
            if !matches!(
                ticket.status,
                TicketStatus::Settled | TicketStatus::Refunded
            ) && self.height
                > ticket
                    .finality_height
                    .saturating_add(self.config.replay_window_blocks)
            {
                ticket.status = TicketStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        self.counters.expired_records = self.counters.expired_records.saturating_add(expired);
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

pub fn clearing_round_id(
    lane: ClearingLane,
    storage_namespace_root: &str,
    participant_set_root: &str,
    clearing_committee_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-CLEARINGHOUSE:ROUND-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str(storage_namespace_root),
            HashPart::Str(participant_set_root),
            HashPart::Str(clearing_committee_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn sealed_claim_id(
    round_id: &str,
    contract_commitment: &str,
    sealed_receipt_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-CLEARINGHOUSE:CLAIM-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(round_id),
            HashPart::Str(contract_commitment),
            HashPart::Str(sealed_receipt_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn obligation_id(
    round_id: &str,
    contract_commitment: &str,
    obligation_commitment_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-CLEARINGHOUSE:OBLIGATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(round_id),
            HashPart::Str(contract_commitment),
            HashPart::Str(obligation_commitment_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn auction_id(
    round_id: &str,
    obligation_root: &str,
    liquidity_pool_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-CLEARINGHOUSE:AUCTION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(round_id),
            HashPart::Str(obligation_root),
            HashPart::Str(liquidity_pool_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn quote_id(
    auction_id: &str,
    obligation_id: &str,
    quote_commitment_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-CLEARINGHOUSE:QUOTE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(auction_id),
            HashPart::Str(obligation_id),
            HashPart::Str(quote_commitment_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn settlement_ticket_id(
    round_id: &str,
    auction_id: &str,
    obligation_id: &str,
    netted_claim_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-CLEARINGHOUSE:TICKET-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(round_id),
            HashPart::Str(auction_id),
            HashPart::Str(obligation_id),
            HashPart::Str(netted_claim_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn pq_witness_id(
    subject_id: &str,
    transcript_root: &str,
    signature_bundle_root: &str,
    nonce: u64,
) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-CLEARINGHOUSE:PQ-WITNESS-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(subject_id),
            HashPart::Str(transcript_root),
            HashPart::Str(signature_bundle_root),
            HashPart::U64(nonce),
        ],
    )
}

pub fn fee_book_id(round_id: &str, contract_commitment: &str) -> String {
    deterministic_id(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-CLEARINGHOUSE:FEE-BOOK-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(round_id),
            HashPart::Str(contract_commitment),
        ],
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-CLEARINGHOUSE:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn record_root(domain: &str, records: &[Value]) -> String {
    if records.is_empty() {
        empty_root(domain)
    } else {
        merkle_root(domain, records)
    }
}

pub fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(value)],
        32,
    )
}

fn state_root_from_roots(roots: &Roots) -> String {
    payload_root(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-SEALED-STORAGE-RECEIPT-FEE-NETTING-CLEARINGHOUSE:ROOTS",
        &json!(roots),
    )
}

fn empty_root(domain: &str) -> String {
    payload_root(domain, &json!({ "empty": true }))
}

fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    if values.is_empty() {
        empty_root(domain)
    } else {
        let records = values
            .iter()
            .map(|value| json!({ "commitment": value }))
            .collect::<Vec<_>>();
        merkle_root(domain, &records)
    }
}

fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn bps(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / MAX_BPS
}

fn quorum_ready(votes: u64, total: u64, threshold_bps: u64) -> bool {
    total > 0 && votes.saturating_mul(MAX_BPS) >= total.saturating_mul(threshold_bps)
}

fn require_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{name} must be non-empty"))
    } else {
        Ok(())
    }
}
