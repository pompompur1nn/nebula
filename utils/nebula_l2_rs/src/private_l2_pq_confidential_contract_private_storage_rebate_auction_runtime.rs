use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_STORAGE_REBATE_AUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-private-storage-rebate-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_PRIVATE_STORAGE_REBATE_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_STORAGE_COMMITMENT_SUITE: &str =
    "ml-kem-1024+xwing-tfhe-private-storage-commitment-v1";
pub const PQ_EXECUTION_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-private-storage-rebate-execution-v1";
pub const REBATE_AUCTION_SUITE: &str =
    "sealed-bid-private-storage-rent-reduction-rebate-auction-v1";
pub const LOW_FEE_STATE_REUSE_SUITE: &str = "private-l2-low-fee-confidential-state-reuse-credit-v1";
pub const SELECTIVE_DISCLOSURE_SUITE: &str =
    "private-storage-rebate-selective-disclosure-view-ticket-v1";
pub const REDACTION_BUDGET_SUITE: &str = "private-storage-rebate-auction-redaction-budget-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "redacted-private-storage-rebate-operator-summary-v1";
pub const DETERMINISTIC_ROOT_SUITE: &str =
    "deterministic-private-storage-rebate-auction-roots-and-public-records-v1";
pub const DEVNET_HEIGHT: u64 = 2_336_400;
pub const DEVNET_EPOCH: u64 = 3_245;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MARKET_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_SLOT_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_REDACTIONS_PER_EPOCH: u64 = 32;
pub const DEFAULT_LOW_FEE_TARGET_BPS: u64 = 8;
pub const DEFAULT_MAX_RENT_BPS: u64 = 30;
pub const DEFAULT_REBATE_CAP_BPS: u64 = 2_500;
pub const DEFAULT_STATE_REUSE_DISCOUNT_BPS: u64 = 7_500;
pub const DEFAULT_MAX_MARKETS: usize = 1_048_576;
pub const DEFAULT_MAX_SLOTS: usize = 16_777_216;
pub const DEFAULT_MAX_AUCTIONS: usize = 4_194_304;
pub const DEFAULT_MAX_BIDS: usize = 33_554_432;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 33_554_432;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 8_388_608;
pub const DEFAULT_MAX_REBATES: usize = 33_554_432;
pub const DEFAULT_MAX_DISCLOSURES: usize = 16_777_216;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageMarketKind {
    ContractStorageRent,
    HotSlotReuse,
    ColdSlotPruning,
    NamespaceCompaction,
    EncryptedWitnessReuse,
    FheSlotPacking,
    OracleCacheStorage,
    GovernanceStateArchive,
    Custom,
}

impl StorageMarketKind {
    pub fn rent_reduction_weight_bps(self) -> u64 {
        match self {
            Self::NamespaceCompaction => 9_900,
            Self::FheSlotPacking => 9_600,
            Self::HotSlotReuse => 9_200,
            Self::ContractStorageRent => 8_800,
            Self::EncryptedWitnessReuse => 8_500,
            Self::ColdSlotPruning => 8_200,
            Self::OracleCacheStorage => 7_600,
            Self::GovernanceStateArchive => 7_200,
            Self::Custom => 6_500,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Proposed,
    Open,
    Auctioning,
    Settling,
    Rebating,
    Paused,
    Closed,
    Slashed,
}

impl MarketStatus {
    pub fn accepts_slots(self) -> bool {
        matches!(self, Self::Open | Self::Auctioning | Self::Rebating)
    }

    pub fn accepts_bids(self) -> bool {
        matches!(self, Self::Open | Self::Auctioning)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotClass {
    Balance,
    Allowance,
    OrderState,
    RiskVector,
    OracleMemo,
    GovernanceSecret,
    ContractScratch,
    WitnessCache,
    Custom,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotStatus {
    Committed,
    Attested,
    AuctionEligible,
    Reused,
    Compacted,
    Disclosed,
    Settled,
    Rebated,
    Quarantined,
    Expired,
}

impl SlotStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Committed
                | Self::Attested
                | Self::AuctionEligible
                | Self::Reused
                | Self::Compacted
                | Self::Disclosed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionKind {
    LowestRent,
    HighestRebate,
    ReuseCredit,
    NamespaceBatch,
    ProofCacheSponsored,
    EmergencyRentRelief,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Draft,
    Open,
    CommitPhase,
    RevealPhase,
    Clearing,
    Settled,
    Rebated,
    Cancelled,
    Expired,
}

impl AuctionStatus {
    pub fn accepts_bids(self) -> bool {
        matches!(self, Self::Open | Self::CommitPhase)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Committed,
    Attested,
    Eligible,
    Winning,
    Outbid,
    Settled,
    Rebated,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    StorageCommitment,
    ExecutionTrace,
    RentReductionProof,
    StateReuseProof,
    RebateEligibility,
    SelectiveDisclosure,
    RedactionBudget,
    OperatorSummary,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Disputed,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Proposed,
    Clearing,
    Settled,
    RebatesQueued,
    RebatesPaid,
    Challenged,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Reserved,
    Earned,
    Claimable,
    Paid,
    DonatedToMarket,
    ClawedBack,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureScope {
    SlotCommitment,
    RentDelta,
    ReuseCredit,
    AuctionClearing,
    RebateReceipt,
    OperatorAudit,
    EmergencyRecovery,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureStatus {
    Reserved,
    Issued,
    Redeemed,
    Attested,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorSummaryStatus {
    Draft,
    Published,
    Attested,
    Redacted,
    Superseded,
    Disputed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub encrypted_storage_commitment_suite: String,
    pub pq_execution_attestation_suite: String,
    pub rebate_auction_suite: String,
    pub low_fee_state_reuse_suite: String,
    pub selective_disclosure_suite: String,
    pub redaction_budget_suite: String,
    pub operator_summary_suite: String,
    pub deterministic_root_suite: String,
    pub fee_asset_id: String,
    pub devnet_height: u64,
    pub devnet_epoch: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub market_epoch_blocks: u64,
    pub auction_ttl_blocks: u64,
    pub slot_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub max_redactions_per_epoch: u64,
    pub low_fee_target_bps: u64,
    pub max_rent_bps: u64,
    pub rebate_cap_bps: u64,
    pub state_reuse_discount_bps: u64,
    pub max_markets: usize,
    pub max_slots: usize,
    pub max_auctions: usize,
    pub max_bids: usize,
    pub max_attestations: usize,
    pub max_settlements: usize,
    pub max_rebates: usize,
    pub max_disclosures: usize,
    pub deterministic_roots_required: bool,
    pub redact_operator_metadata_by_default: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            encrypted_storage_commitment_suite: ENCRYPTED_STORAGE_COMMITMENT_SUITE.to_string(),
            pq_execution_attestation_suite: PQ_EXECUTION_ATTESTATION_SUITE.to_string(),
            rebate_auction_suite: REBATE_AUCTION_SUITE.to_string(),
            low_fee_state_reuse_suite: LOW_FEE_STATE_REUSE_SUITE.to_string(),
            selective_disclosure_suite: SELECTIVE_DISCLOSURE_SUITE.to_string(),
            redaction_budget_suite: REDACTION_BUDGET_SUITE.to_string(),
            operator_summary_suite: OPERATOR_SUMMARY_SUITE.to_string(),
            deterministic_root_suite: DETERMINISTIC_ROOT_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            devnet_height: DEVNET_HEIGHT,
            devnet_epoch: DEVNET_EPOCH,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            market_epoch_blocks: DEFAULT_MARKET_EPOCH_BLOCKS,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            slot_ttl_blocks: DEFAULT_SLOT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            max_redactions_per_epoch: DEFAULT_MAX_REDACTIONS_PER_EPOCH,
            low_fee_target_bps: DEFAULT_LOW_FEE_TARGET_BPS,
            max_rent_bps: DEFAULT_MAX_RENT_BPS,
            rebate_cap_bps: DEFAULT_REBATE_CAP_BPS,
            state_reuse_discount_bps: DEFAULT_STATE_REUSE_DISCOUNT_BPS,
            max_markets: DEFAULT_MAX_MARKETS,
            max_slots: DEFAULT_MAX_SLOTS,
            max_auctions: DEFAULT_MAX_AUCTIONS,
            max_bids: DEFAULT_MAX_BIDS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_disclosures: DEFAULT_MAX_DISCLOSURES,
            deterministic_roots_required: true,
            redact_operator_metadata_by_default: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(
        &self,
    ) -> PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<()> {
        required("chain_id", &self.chain_id)?;
        required("protocol_version", &self.protocol_version)?;
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "unsupported private storage rebate auction protocol version"
        );
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported schema version"
        );
        ensure!(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security floor violated"
        );
        ensure!(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy set must be at least the minimum privacy set"
        );
        ensure!(
            self.max_rent_bps <= MAX_BPS
                && self.rebate_cap_bps <= MAX_BPS
                && self.state_reuse_discount_bps <= MAX_BPS,
            "configured basis points exceed max bps"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub market_sequence: u64,
    pub slot_sequence: u64,
    pub auction_sequence: u64,
    pub bid_sequence: u64,
    pub attestation_sequence: u64,
    pub settlement_sequence: u64,
    pub rebate_sequence: u64,
    pub disclosure_sequence: u64,
    pub redaction_budget_sequence: u64,
    pub operator_summary_sequence: u64,
    pub public_record_sequence: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub market_root: String,
    pub encrypted_slot_root: String,
    pub auction_root: String,
    pub bid_root: String,
    pub pq_attestation_root: String,
    pub settlement_root: String,
    pub rebate_root: String,
    pub disclosure_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub public_record_root: String,
    pub nullifier_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("CONFIG"),
            market_root: empty_root("MARKET"),
            encrypted_slot_root: empty_root("ENCRYPTED-SLOT"),
            auction_root: empty_root("AUCTION"),
            bid_root: empty_root("BID"),
            pq_attestation_root: empty_root("PQ-ATTESTATION"),
            settlement_root: empty_root("SETTLEMENT"),
            rebate_root: empty_root("REBATE"),
            disclosure_root: empty_root("DISCLOSURE"),
            redaction_budget_root: empty_root("REDACTION-BUDGET"),
            operator_summary_root: empty_root("OPERATOR-SUMMARY"),
            public_record_root: empty_root("PUBLIC-RECORD"),
            nullifier_root: empty_root("NULLIFIER"),
            counters_root: empty_root("COUNTERS"),
            state_root: empty_root("STATE"),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageMarket {
    pub market_id: String,
    pub market_kind: StorageMarketKind,
    pub status: MarketStatus,
    pub operator_commitment: String,
    pub namespace_root: String,
    pub rent_curve_root: String,
    pub encrypted_policy_root: String,
    pub rebate_pool_root: String,
    pub fee_asset_id: String,
    pub max_rent_bps: u64,
    pub target_rebate_bps: u64,
    pub min_reuse_score: u64,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub active_slots: u64,
    pub active_auctions: u64,
    pub total_rebate_reserved: u128,
    pub metadata_commitment: String,
}

impl StorageMarket {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedStorageSlot {
    pub slot_id: String,
    pub market_id: String,
    pub slot_class: SlotClass,
    pub status: SlotStatus,
    pub contract_commitment: String,
    pub account_commitment: String,
    pub slot_key_commitment: String,
    pub encrypted_value_root: String,
    pub ciphertext_index_root: String,
    pub reuse_hint_root: String,
    pub rent_nullifier_root: String,
    pub storage_bytes_before: u64,
    pub storage_bytes_after: u64,
    pub rent_before_micro_units: u64,
    pub rent_after_micro_units: u64,
    pub reuse_score: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub committed_at_height: u64,
    pub expires_at_height: u64,
    pub attestation_ids: BTreeSet<String>,
}

impl EncryptedStorageSlot {
    pub fn rent_reduction_micro_units(&self) -> u64 {
        self.rent_before_micro_units
            .saturating_sub(self.rent_after_micro_units)
    }

    pub fn compression_ratio_bps(&self) -> u64 {
        if self.storage_bytes_before == 0 {
            return MAX_BPS;
        }
        self.storage_bytes_before
            .saturating_sub(self.storage_bytes_after)
            .saturating_mul(MAX_BPS)
            / self.storage_bytes_before
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateAuction {
    pub auction_id: String,
    pub market_id: String,
    pub auction_kind: AuctionKind,
    pub status: AuctionStatus,
    pub slot_ids: BTreeSet<String>,
    pub sealed_bid_root: String,
    pub clearing_policy_root: String,
    pub eligible_reuse_root: String,
    pub max_clearing_fee_bps: u64,
    pub reserve_rebate_micro_units: u64,
    pub opens_at_height: u64,
    pub commit_ends_at_height: u64,
    pub reveal_ends_at_height: u64,
    pub min_privacy_set_size: u64,
    pub winning_bid_ids: BTreeSet<String>,
}

impl RebateAuction {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuctionBid {
    pub bid_id: String,
    pub auction_id: String,
    pub market_id: String,
    pub bidder_commitment: String,
    pub bid_commitment_root: String,
    pub requested_slot_ids: BTreeSet<String>,
    pub offered_reuse_score: u64,
    pub requested_rebate_bps: u64,
    pub max_fee_bps: u64,
    pub proof_cache_root: String,
    pub disclosure_ticket_root: String,
    pub status: BidStatus,
    pub submitted_at_height: u64,
    pub attestation_ids: BTreeSet<String>,
}

impl AuctionBid {
    pub fn score(&self, market_kind: StorageMarketKind) -> u128 {
        let reuse = self.offered_reuse_score as u128;
        let reduction_weight = market_kind.rent_reduction_weight_bps() as u128;
        let rebate_discount = MAX_BPS.saturating_sub(self.requested_rebate_bps) as u128;
        reuse
            .saturating_mul(reduction_weight)
            .saturating_mul(rebate_discount.max(1))
            / MAX_BPS as u128
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqExecutionAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub status: AttestationStatus,
    pub market_id: String,
    pub slot_id: Option<String>,
    pub auction_id: Option<String>,
    pub bid_id: Option<String>,
    pub settlement_id: Option<String>,
    pub attestor_commitment: String,
    pub pq_key_commitment: String,
    pub transcript_root: String,
    pub execution_trace_root: String,
    pub signature_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl PqExecutionAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuctionSettlement {
    pub settlement_id: String,
    pub auction_id: String,
    pub market_id: String,
    pub status: SettlementStatus,
    pub winning_bid_ids: BTreeSet<String>,
    pub settled_slot_ids: BTreeSet<String>,
    pub clearing_root: String,
    pub rebate_manifest_root: String,
    pub state_reuse_root: String,
    pub operator_summary_id: Option<String>,
    pub total_rent_reduction_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub clearing_fee_bps: u64,
    pub settled_at_height: u64,
}

impl AuctionSettlement {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageRebate {
    pub rebate_id: String,
    pub settlement_id: String,
    pub auction_id: String,
    pub bid_id: String,
    pub slot_id: String,
    pub status: RebateStatus,
    pub beneficiary_commitment: String,
    pub rebate_destination_root: String,
    pub rent_reduction_micro_units: u64,
    pub rebate_micro_units: u64,
    pub state_reuse_discount_bps: u64,
    pub low_fee_credit_root: String,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl StorageRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectiveDisclosureTicket {
    pub disclosure_id: String,
    pub scope: DisclosureScope,
    pub status: DisclosureStatus,
    pub market_id: String,
    pub slot_id: Option<String>,
    pub auction_id: Option<String>,
    pub rebate_id: Option<String>,
    pub auditor_commitment: String,
    pub disclosed_field_root: String,
    pub redacted_payload_root: String,
    pub view_nullifier: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl SelectiveDisclosureTicket {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub market_id: String,
    pub operator_commitment: String,
    pub redaction_epoch: u64,
    pub max_redactions: u64,
    pub used_redactions: u64,
    pub field_policy_root: String,
    pub summary_policy_root: String,
    pub attestation_id: Option<String>,
}

impl RedactionBudget {
    pub fn remaining_redactions(&self) -> u64 {
        self.max_redactions.saturating_sub(self.used_redactions)
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub market_id: String,
    pub status: OperatorSummaryStatus,
    pub operator_commitment: String,
    pub redaction_budget_id: String,
    pub reporting_epoch: u64,
    pub market_count: u64,
    pub auction_count: u64,
    pub encrypted_slot_count: u64,
    pub settled_slot_count: u64,
    pub total_rent_reduction_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub low_fee_reuse_credit_micro_units: u64,
    pub redacted_summary_root: String,
    pub disclosure_root: String,
    pub pq_attestation_id: Option<String>,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub record_root: String,
    pub emitted_at_height: u64,
}

impl DeterministicPublicRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub markets: BTreeMap<String, StorageMarket>,
    pub encrypted_slots: BTreeMap<String, EncryptedStorageSlot>,
    pub auctions: BTreeMap<String, RebateAuction>,
    pub bids: BTreeMap<String, AuctionBid>,
    pub pq_attestations: BTreeMap<String, PqExecutionAttestation>,
    pub settlements: BTreeMap<String, AuctionSettlement>,
    pub rebates: BTreeMap<String, StorageRebate>,
    pub disclosures: BTreeMap<String, SelectiveDisclosureTicket>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub public_records: BTreeMap<String, DeterministicPublicRecord>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        let mut state = Self {
            config,
            height,
            epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            markets: BTreeMap::new(),
            encrypted_slots: BTreeMap::new(),
            auctions: BTreeMap::new(),
            bids: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            settlements: BTreeMap::new(),
            rebates: BTreeMap::new(),
            disclosures: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            public_records: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn open_market(
        &mut self,
        mut market: StorageMarket,
    ) -> PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<String> {
        self.config.validate()?;
        ensure!(
            self.markets.len() < self.config.max_markets,
            "market limit reached"
        );
        required("operator_commitment", &market.operator_commitment)?;
        required("namespace_root", &market.namespace_root)?;
        required("rent_curve_root", &market.rent_curve_root)?;
        ensure!(
            market.fee_asset_id == self.config.fee_asset_id,
            "unsupported fee asset"
        );
        ensure!(
            market.max_rent_bps <= self.config.max_rent_bps,
            "market rent bps exceeds config"
        );
        ensure!(
            market.target_rebate_bps <= self.config.rebate_cap_bps,
            "rebate bps exceeds cap"
        );
        ensure!(
            market.min_privacy_set_size >= self.config.min_privacy_set_size
                && market.pq_security_bits >= self.config.min_pq_security_bits,
            "privacy or pq security floor violated"
        );
        self.counters.market_sequence = self.counters.market_sequence.saturating_add(1);
        if market.market_id.trim().is_empty() {
            market.market_id = deterministic_id(
                "MARKET",
                self.counters.market_sequence,
                &market.public_record(),
            );
        }
        let market_id = market.market_id.clone();
        ensure!(
            !self.markets.contains_key(&market_id),
            "duplicate market {market_id}"
        );
        self.markets.insert(market_id.clone(), market);
        self.emit_public_record("market", &market_id)?;
        self.refresh_roots();
        Ok(market_id)
    }

    pub fn commit_encrypted_slot(
        &mut self,
        mut slot: EncryptedStorageSlot,
    ) -> PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<String> {
        ensure!(
            self.encrypted_slots.len() < self.config.max_slots,
            "slot limit reached"
        );
        let market = self.require_market(&slot.market_id)?;
        ensure!(
            market.status.accepts_slots(),
            "market does not accept encrypted storage slots"
        );
        required("contract_commitment", &slot.contract_commitment)?;
        required("slot_key_commitment", &slot.slot_key_commitment)?;
        required("encrypted_value_root", &slot.encrypted_value_root)?;
        required("rent_nullifier_root", &slot.rent_nullifier_root)?;
        ensure!(
            slot.privacy_set_size >= market.min_privacy_set_size
                && slot.pq_security_bits >= market.pq_security_bits,
            "slot privacy or pq security floor violated"
        );
        ensure!(
            slot.rent_after_micro_units <= slot.rent_before_micro_units,
            "private storage rent must not increase"
        );
        self.counters.slot_sequence = self.counters.slot_sequence.saturating_add(1);
        if slot.slot_id.trim().is_empty() {
            slot.slot_id =
                deterministic_id("SLOT", self.counters.slot_sequence, &slot.public_record());
        }
        let slot_id = slot.slot_id.clone();
        ensure!(
            !self.encrypted_slots.contains_key(&slot_id),
            "duplicate encrypted slot {slot_id}"
        );
        self.spent_nullifiers
            .insert(slot.rent_nullifier_root.clone());
        self.encrypted_slots.insert(slot_id.clone(), slot);
        if let Some(market) = self
            .markets
            .get_mut(&self.encrypted_slots[&slot_id].market_id)
        {
            market.active_slots = market.active_slots.saturating_add(1);
        }
        self.emit_public_record("encrypted_slot", &slot_id)?;
        self.refresh_roots();
        Ok(slot_id)
    }

    pub fn open_rebate_auction(
        &mut self,
        mut auction: RebateAuction,
    ) -> PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<String> {
        ensure!(
            self.auctions.len() < self.config.max_auctions,
            "auction limit reached"
        );
        let market = self.require_market(&auction.market_id)?;
        ensure!(
            market.status.accepts_bids(),
            "market does not accept auction bids"
        );
        ensure!(
            !auction.slot_ids.is_empty(),
            "auction requires at least one slot"
        );
        ensure!(
            auction.max_clearing_fee_bps <= self.config.low_fee_target_bps,
            "auction clearing fee exceeds low-fee target"
        );
        for slot_id in &auction.slot_ids {
            let slot = self.require_slot(slot_id)?;
            ensure!(
                slot.market_id == auction.market_id,
                "slot {slot_id} belongs to a different market"
            );
            ensure!(slot.status.live(), "slot {slot_id} is not live");
        }
        self.counters.auction_sequence = self.counters.auction_sequence.saturating_add(1);
        if auction.auction_id.trim().is_empty() {
            auction.auction_id = deterministic_id(
                "AUCTION",
                self.counters.auction_sequence,
                &auction.public_record(),
            );
        }
        let auction_id = auction.auction_id.clone();
        ensure!(
            !self.auctions.contains_key(&auction_id),
            "duplicate auction {auction_id}"
        );
        self.auctions.insert(auction_id.clone(), auction);
        if let Some(market) = self.markets.get_mut(&self.auctions[&auction_id].market_id) {
            market.active_auctions = market.active_auctions.saturating_add(1);
        }
        self.emit_public_record("auction", &auction_id)?;
        self.refresh_roots();
        Ok(auction_id)
    }

    pub fn submit_bid(
        &mut self,
        mut bid: AuctionBid,
    ) -> PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<String> {
        ensure!(self.bids.len() < self.config.max_bids, "bid limit reached");
        let auction = self.require_auction(&bid.auction_id)?;
        ensure!(
            auction.status.accepts_bids(),
            "auction does not accept bids"
        );
        ensure!(bid.market_id == auction.market_id, "bid market mismatch");
        ensure!(
            !bid.requested_slot_ids.is_empty(),
            "bid requires at least one slot"
        );
        ensure!(
            bid.requested_rebate_bps <= self.config.rebate_cap_bps,
            "requested rebate exceeds cap"
        );
        ensure!(
            bid.max_fee_bps <= self.config.low_fee_target_bps,
            "bid fee exceeds low-fee target"
        );
        required("bidder_commitment", &bid.bidder_commitment)?;
        required("bid_commitment_root", &bid.bid_commitment_root)?;
        for slot_id in &bid.requested_slot_ids {
            ensure!(
                auction.slot_ids.contains(slot_id),
                "bid slot {slot_id} is outside auction"
            );
        }
        self.counters.bid_sequence = self.counters.bid_sequence.saturating_add(1);
        if bid.bid_id.trim().is_empty() {
            bid.bid_id = deterministic_id("BID", self.counters.bid_sequence, &bid.public_record());
        }
        let bid_id = bid.bid_id.clone();
        ensure!(!self.bids.contains_key(&bid_id), "duplicate bid {bid_id}");
        self.bids.insert(bid_id.clone(), bid);
        self.emit_public_record("bid", &bid_id)?;
        self.refresh_roots();
        Ok(bid_id)
    }

    pub fn submit_pq_attestation(
        &mut self,
        mut attestation: PqExecutionAttestation,
    ) -> PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<String> {
        ensure!(
            self.pq_attestations.len() < self.config.max_attestations,
            "attestation limit reached"
        );
        required("attestor_commitment", &attestation.attestor_commitment)?;
        required("pq_key_commitment", &attestation.pq_key_commitment)?;
        required("transcript_root", &attestation.transcript_root)?;
        required("signature_commitment", &attestation.signature_commitment)?;
        ensure!(
            attestation.privacy_set_size >= self.config.min_privacy_set_size
                && attestation.pq_security_bits >= self.config.min_pq_security_bits,
            "attestation privacy or pq security floor violated"
        );
        self.require_market(&attestation.market_id)?;
        self.counters.attestation_sequence = self.counters.attestation_sequence.saturating_add(1);
        if attestation.attestation_id.trim().is_empty() {
            attestation.attestation_id = deterministic_id(
                "PQ-ATTESTATION",
                self.counters.attestation_sequence,
                &attestation.public_record(),
            );
        }
        let attestation_id = attestation.attestation_id.clone();
        ensure!(
            !self.pq_attestations.contains_key(&attestation_id),
            "duplicate pq attestation {attestation_id}"
        );
        if let Some(slot_id) = &attestation.slot_id {
            self.require_slot(slot_id)?;
        }
        if let Some(bid_id) = &attestation.bid_id {
            self.require_bid(bid_id)?;
        }
        self.pq_attestations
            .insert(attestation_id.clone(), attestation);
        let slot_id = self.pq_attestations[&attestation_id].slot_id.clone();
        if let Some(slot_id) = slot_id {
            if let Some(slot) = self.encrypted_slots.get_mut(&slot_id) {
                slot.attestation_ids.insert(attestation_id.clone());
                if slot.status == SlotStatus::Committed {
                    slot.status = SlotStatus::Attested;
                }
            }
        }
        let bid_id = self.pq_attestations[&attestation_id].bid_id.clone();
        if let Some(bid_id) = bid_id {
            if let Some(bid) = self.bids.get_mut(&bid_id) {
                bid.attestation_ids.insert(attestation_id.clone());
                if bid.status == BidStatus::Committed {
                    bid.status = BidStatus::Attested;
                }
            }
        }
        self.emit_public_record("pq_attestation", &attestation_id)?;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn settle_auction(
        &mut self,
        mut settlement: AuctionSettlement,
    ) -> PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<String> {
        ensure!(
            self.settlements.len() < self.config.max_settlements,
            "settlement limit reached"
        );
        let auction = self.require_auction(&settlement.auction_id)?;
        ensure!(
            settlement.market_id == auction.market_id,
            "settlement market mismatch"
        );
        ensure!(
            !settlement.winning_bid_ids.is_empty(),
            "settlement requires winning bids"
        );
        ensure!(
            settlement.clearing_fee_bps <= self.config.low_fee_target_bps,
            "clearing fee exceeds target"
        );
        for bid_id in &settlement.winning_bid_ids {
            let bid = self.require_bid(bid_id)?;
            ensure!(
                bid.auction_id == settlement.auction_id,
                "winning bid {bid_id} outside auction"
            );
        }
        for slot_id in &settlement.settled_slot_ids {
            let slot = self.require_slot(slot_id)?;
            ensure!(
                slot.market_id == settlement.market_id,
                "settled slot {slot_id} market mismatch"
            );
        }
        self.counters.settlement_sequence = self.counters.settlement_sequence.saturating_add(1);
        if settlement.settlement_id.trim().is_empty() {
            settlement.settlement_id = deterministic_id(
                "SETTLEMENT",
                self.counters.settlement_sequence,
                &settlement.public_record(),
            );
        }
        let settlement_id = settlement.settlement_id.clone();
        ensure!(
            !self.settlements.contains_key(&settlement_id),
            "duplicate settlement {settlement_id}"
        );
        for bid_id in &settlement.winning_bid_ids {
            if let Some(bid) = self.bids.get_mut(bid_id) {
                bid.status = BidStatus::Winning;
            }
        }
        for slot_id in &settlement.settled_slot_ids {
            if let Some(slot) = self.encrypted_slots.get_mut(slot_id) {
                slot.status = SlotStatus::Settled;
            }
        }
        if let Some(auction) = self.auctions.get_mut(&settlement.auction_id) {
            auction.status = AuctionStatus::Settled;
            auction.winning_bid_ids = settlement.winning_bid_ids.clone();
        }
        self.settlements.insert(settlement_id.clone(), settlement);
        self.emit_public_record("settlement", &settlement_id)?;
        self.refresh_roots();
        Ok(settlement_id)
    }

    pub fn reserve_rebate(
        &mut self,
        mut rebate: StorageRebate,
    ) -> PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<String> {
        ensure!(
            self.rebates.len() < self.config.max_rebates,
            "rebate limit reached"
        );
        let market_id = self
            .require_settlement(&rebate.settlement_id)?
            .market_id
            .clone();
        self.require_bid(&rebate.bid_id)?;
        let slot = self.require_slot(&rebate.slot_id)?;
        ensure!(
            rebate.rebate_micro_units <= slot.rent_reduction_micro_units(),
            "rebate exceeds rent reduction"
        );
        ensure!(
            rebate.state_reuse_discount_bps <= self.config.state_reuse_discount_bps,
            "state reuse discount exceeds configured cap"
        );
        required("beneficiary_commitment", &rebate.beneficiary_commitment)?;
        required("rebate_destination_root", &rebate.rebate_destination_root)?;
        self.counters.rebate_sequence = self.counters.rebate_sequence.saturating_add(1);
        if rebate.rebate_id.trim().is_empty() {
            rebate.rebate_id = deterministic_id(
                "REBATE",
                self.counters.rebate_sequence,
                &rebate.public_record(),
            );
        }
        let rebate_id = rebate.rebate_id.clone();
        ensure!(
            !self.rebates.contains_key(&rebate_id),
            "duplicate rebate {rebate_id}"
        );
        self.rebates.insert(rebate_id.clone(), rebate);
        if let Some(slot) = self
            .encrypted_slots
            .get_mut(&self.rebates[&rebate_id].slot_id)
        {
            slot.status = SlotStatus::Rebated;
        }
        if let Some(market) = self.markets.get_mut(&market_id) {
            market.total_rebate_reserved = market
                .total_rebate_reserved
                .saturating_add(self.rebates[&rebate_id].rebate_micro_units as u128);
        }
        self.emit_public_record("rebate", &rebate_id)?;
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn issue_disclosure(
        &mut self,
        mut ticket: SelectiveDisclosureTicket,
    ) -> PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<String> {
        ensure!(
            self.disclosures.len() < self.config.max_disclosures,
            "disclosure limit reached"
        );
        self.require_market(&ticket.market_id)?;
        required("auditor_commitment", &ticket.auditor_commitment)?;
        required("disclosed_field_root", &ticket.disclosed_field_root)?;
        required("redacted_payload_root", &ticket.redacted_payload_root)?;
        required("view_nullifier", &ticket.view_nullifier)?;
        ensure!(
            !self.spent_nullifiers.contains(&ticket.view_nullifier),
            "disclosure nullifier already spent"
        );
        self.counters.disclosure_sequence = self.counters.disclosure_sequence.saturating_add(1);
        if ticket.disclosure_id.trim().is_empty() {
            ticket.disclosure_id = deterministic_id(
                "DISCLOSURE",
                self.counters.disclosure_sequence,
                &ticket.public_record(),
            );
        }
        let disclosure_id = ticket.disclosure_id.clone();
        ensure!(
            !self.disclosures.contains_key(&disclosure_id),
            "duplicate disclosure {disclosure_id}"
        );
        self.spent_nullifiers.insert(ticket.view_nullifier.clone());
        self.disclosures.insert(disclosure_id.clone(), ticket);
        self.emit_public_record("disclosure", &disclosure_id)?;
        self.refresh_roots();
        Ok(disclosure_id)
    }

    pub fn allocate_redaction_budget(
        &mut self,
        mut budget: RedactionBudget,
    ) -> PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<String> {
        self.require_market(&budget.market_id)?;
        required("operator_commitment", &budget.operator_commitment)?;
        required("field_policy_root", &budget.field_policy_root)?;
        required("summary_policy_root", &budget.summary_policy_root)?;
        ensure!(
            budget.max_redactions <= self.config.max_redactions_per_epoch,
            "redaction budget exceeds epoch limit"
        );
        self.counters.redaction_budget_sequence =
            self.counters.redaction_budget_sequence.saturating_add(1);
        if budget.budget_id.trim().is_empty() {
            budget.budget_id = deterministic_id(
                "REDACTION-BUDGET",
                self.counters.redaction_budget_sequence,
                &budget.public_record(),
            );
        }
        let budget_id = budget.budget_id.clone();
        ensure!(
            !self.redaction_budgets.contains_key(&budget_id),
            "duplicate redaction budget {budget_id}"
        );
        self.redaction_budgets.insert(budget_id.clone(), budget);
        self.emit_public_record("redaction_budget", &budget_id)?;
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn publish_operator_summary(
        &mut self,
        mut summary: OperatorSummary,
    ) -> PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<String> {
        self.require_market(&summary.market_id)?;
        let budget = self
            .redaction_budgets
            .get_mut(&summary.redaction_budget_id)
            .ok_or_else(|| format!("unknown redaction budget {}", summary.redaction_budget_id))?;
        ensure!(
            budget.remaining_redactions() > 0,
            "redaction budget exhausted"
        );
        required("operator_commitment", &summary.operator_commitment)?;
        required("redacted_summary_root", &summary.redacted_summary_root)?;
        required("disclosure_root", &summary.disclosure_root)?;
        budget.used_redactions = budget.used_redactions.saturating_add(1);
        self.counters.operator_summary_sequence =
            self.counters.operator_summary_sequence.saturating_add(1);
        if summary.summary_id.trim().is_empty() {
            summary.summary_id = deterministic_id(
                "OPERATOR-SUMMARY",
                self.counters.operator_summary_sequence,
                &summary.public_record(),
            );
        }
        let summary_id = summary.summary_id.clone();
        ensure!(
            !self.operator_summaries.contains_key(&summary_id),
            "duplicate operator summary {summary_id}"
        );
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.emit_public_record("operator_summary", &summary_id)?;
        self.refresh_roots();
        Ok(summary_id)
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: deterministic_record_root(
                "PRIVATE-STORAGE-REBATE-AUCTION-CONFIG",
                &self.config.public_record(),
            ),
            market_root: public_record_root(
                "MARKET",
                &values_record(&self.markets, StorageMarket::public_record),
            ),
            encrypted_slot_root: public_record_root(
                "ENCRYPTED-SLOT",
                &values_record(&self.encrypted_slots, EncryptedStorageSlot::public_record),
            ),
            auction_root: public_record_root(
                "AUCTION",
                &values_record(&self.auctions, RebateAuction::public_record),
            ),
            bid_root: public_record_root(
                "BID",
                &values_record(&self.bids, AuctionBid::public_record),
            ),
            pq_attestation_root: public_record_root(
                "PQ-ATTESTATION",
                &values_record(&self.pq_attestations, PqExecutionAttestation::public_record),
            ),
            settlement_root: public_record_root(
                "SETTLEMENT",
                &values_record(&self.settlements, AuctionSettlement::public_record),
            ),
            rebate_root: public_record_root(
                "REBATE",
                &values_record(&self.rebates, StorageRebate::public_record),
            ),
            disclosure_root: public_record_root(
                "DISCLOSURE",
                &values_record(&self.disclosures, SelectiveDisclosureTicket::public_record),
            ),
            redaction_budget_root: public_record_root(
                "REDACTION-BUDGET",
                &values_record(&self.redaction_budgets, RedactionBudget::public_record),
            ),
            operator_summary_root: public_record_root(
                "OPERATOR-SUMMARY",
                &values_record(&self.operator_summaries, OperatorSummary::public_record),
            ),
            public_record_root: public_record_root(
                "PUBLIC-RECORD",
                &values_record(
                    &self.public_records,
                    DeterministicPublicRecord::public_record,
                ),
            ),
            nullifier_root: public_record_root(
                "NULLIFIER",
                &self
                    .spent_nullifiers
                    .iter()
                    .map(|nullifier| json!(nullifier))
                    .collect::<Vec<_>>(),
            ),
            counters_root: deterministic_record_root("COUNTERS", &self.counters.public_record()),
            state_root: empty_root("STATE"),
        };
        roots.state_root = state_root_from_record(&json!({
            "config_root": roots.config_root,
            "market_root": roots.market_root,
            "encrypted_slot_root": roots.encrypted_slot_root,
            "auction_root": roots.auction_root,
            "bid_root": roots.bid_root,
            "pq_attestation_root": roots.pq_attestation_root,
            "settlement_root": roots.settlement_root,
            "rebate_root": roots.rebate_root,
            "disclosure_root": roots.disclosure_root,
            "redaction_budget_root": roots.redaction_budget_root,
            "operator_summary_root": roots.operator_summary_root,
            "public_record_root": roots.public_record_root,
            "nullifier_root": roots.nullifier_root,
            "counters_root": roots.counters_root,
            "height": self.height,
            "epoch": self.epoch,
        }));
        roots
    }

    pub fn refresh_roots(&mut self) {
        self.roots = self.roots();
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_contract_private_storage_rebate_auction_runtime_state",
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "epoch": self.epoch,
            "hash_suite": self.config.hash_suite,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "counts": {
                "markets": self.markets.len(),
                "encrypted_slots": self.encrypted_slots.len(),
                "auctions": self.auctions.len(),
                "bids": self.bids.len(),
                "pq_attestations": self.pq_attestations.len(),
                "settlements": self.settlements.len(),
                "rebates": self.rebates.len(),
                "disclosures": self.disclosures.len(),
                "redaction_budgets": self.redaction_budgets.len(),
                "operator_summaries": self.operator_summaries.len(),
                "spent_nullifiers": self.spent_nullifiers.len(),
            },
            "live_encrypted_slot_count": self.encrypted_slots.values().filter(|slot| slot.status.live()).count(),
            "open_auction_count": self.auctions.values().filter(|auction| auction.status.accepts_bids()).count(),
            "operator_summaries": self.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), json!(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn emit_public_record(
        &mut self,
        record_kind: &str,
        record_root: &str,
    ) -> PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<String> {
        self.counters.public_record_sequence =
            self.counters.public_record_sequence.saturating_add(1);
        let record = json!({
            "record_kind": record_kind,
            "record_root": record_root,
            "height": self.height,
            "sequence": self.counters.public_record_sequence,
        });
        let record_id = deterministic_id(
            "PUBLIC-RECORD",
            self.counters.public_record_sequence,
            &record,
        );
        self.public_records.insert(
            record_id.clone(),
            DeterministicPublicRecord {
                record_id: record_id.clone(),
                record_kind: record_kind.to_string(),
                record_root: record_root.to_string(),
                emitted_at_height: self.height,
            },
        );
        Ok(record_id)
    }

    fn require_market(
        &self,
        market_id: &str,
    ) -> PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<&StorageMarket>
    {
        self.markets
            .get(market_id)
            .ok_or_else(|| format!("unknown storage market {market_id}"))
    }

    fn require_slot(
        &self,
        slot_id: &str,
    ) -> PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<
        &EncryptedStorageSlot,
    > {
        self.encrypted_slots
            .get(slot_id)
            .ok_or_else(|| format!("unknown encrypted storage slot {slot_id}"))
    }

    fn require_auction(
        &self,
        auction_id: &str,
    ) -> PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<&RebateAuction>
    {
        self.auctions
            .get(auction_id)
            .ok_or_else(|| format!("unknown rebate auction {auction_id}"))
    }

    fn require_bid(
        &self,
        bid_id: &str,
    ) -> PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<&AuctionBid> {
        self.bids
            .get(bid_id)
            .ok_or_else(|| format!("unknown auction bid {bid_id}"))
    }

    fn require_settlement(
        &self,
        settlement_id: &str,
    ) -> PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<&AuctionSettlement>
    {
        self.settlements
            .get(settlement_id)
            .ok_or_else(|| format!("unknown auction settlement {settlement_id}"))
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    State::new(config.clone(), config.devnet_height, config.devnet_epoch)
}

pub fn demo() -> State {
    let mut state = devnet();
    let market = StorageMarket {
        market_id: "devnet-private-storage-rent-rebate-market".to_string(),
        market_kind: StorageMarketKind::NamespaceCompaction,
        status: MarketStatus::Auctioning,
        operator_commitment: "operator:rebate-auction:devnet".to_string(),
        namespace_root: sample_root("namespace"),
        rent_curve_root: sample_root("rent-curve"),
        encrypted_policy_root: sample_root("encrypted-policy"),
        rebate_pool_root: sample_root("rebate-pool"),
        fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
        max_rent_bps: 18,
        target_rebate_bps: 1_200,
        min_reuse_score: 8_000,
        min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        opened_at_height: DEVNET_HEIGHT,
        closes_at_height: DEVNET_HEIGHT + DEFAULT_MARKET_EPOCH_BLOCKS,
        active_slots: 0,
        active_auctions: 0,
        total_rebate_reserved: 0,
        metadata_commitment: sample_root("market-metadata"),
    };
    let market_id = state
        .open_market(market)
        .expect("demo market must validate");

    let slot = EncryptedStorageSlot {
        slot_id: "devnet-private-storage-slot-0001".to_string(),
        market_id: market_id.clone(),
        slot_class: SlotClass::ContractScratch,
        status: SlotStatus::AuctionEligible,
        contract_commitment: "contract:confidential-storage-demo".to_string(),
        account_commitment: "account:redacted-demo".to_string(),
        slot_key_commitment: sample_root("slot-key"),
        encrypted_value_root: sample_root("encrypted-value"),
        ciphertext_index_root: sample_root("ciphertext-index"),
        reuse_hint_root: sample_root("reuse-hint"),
        rent_nullifier_root: sample_root("rent-nullifier"),
        storage_bytes_before: 16_384,
        storage_bytes_after: 3_072,
        rent_before_micro_units: 42_000,
        rent_after_micro_units: 7_800,
        reuse_score: 9_240,
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        committed_at_height: DEVNET_HEIGHT + 3,
        expires_at_height: DEVNET_HEIGHT + DEFAULT_SLOT_TTL_BLOCKS,
        attestation_ids: BTreeSet::new(),
    };
    let slot_id = state
        .commit_encrypted_slot(slot)
        .expect("demo encrypted slot must validate");

    let mut slot_ids = BTreeSet::new();
    slot_ids.insert(slot_id.clone());
    let auction = RebateAuction {
        auction_id: "devnet-private-storage-rebate-auction-0001".to_string(),
        market_id: market_id.clone(),
        auction_kind: AuctionKind::ReuseCredit,
        status: AuctionStatus::CommitPhase,
        slot_ids: slot_ids.clone(),
        sealed_bid_root: sample_root("sealed-bids"),
        clearing_policy_root: sample_root("clearing-policy"),
        eligible_reuse_root: sample_root("eligible-reuse"),
        max_clearing_fee_bps: DEFAULT_LOW_FEE_TARGET_BPS,
        reserve_rebate_micro_units: 25_000,
        opens_at_height: DEVNET_HEIGHT + 4,
        commit_ends_at_height: DEVNET_HEIGHT + 40,
        reveal_ends_at_height: DEVNET_HEIGHT + 88,
        min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
        winning_bid_ids: BTreeSet::new(),
    };
    let auction_id = state
        .open_rebate_auction(auction)
        .expect("demo auction must validate");

    let bid = AuctionBid {
        bid_id: "devnet-private-storage-rebate-bid-0001".to_string(),
        auction_id: auction_id.clone(),
        market_id: market_id.clone(),
        bidder_commitment: "bidder:state-reuse-solver-demo".to_string(),
        bid_commitment_root: sample_root("bid-commitment"),
        requested_slot_ids: slot_ids.clone(),
        offered_reuse_score: 9_600,
        requested_rebate_bps: 1_100,
        max_fee_bps: DEFAULT_LOW_FEE_TARGET_BPS,
        proof_cache_root: sample_root("proof-cache"),
        disclosure_ticket_root: sample_root("disclosure-ticket"),
        status: BidStatus::Committed,
        submitted_at_height: DEVNET_HEIGHT + 5,
        attestation_ids: BTreeSet::new(),
    };
    state.submit_bid(bid).expect("demo bid must validate");
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn deterministic_id(kind: &str, sequence: u64, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STORAGE-REBATE-AUCTION:{kind}"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STORAGE-REBATE-AUCTION:{domain}-ROOT"
        ),
        records,
    )
}

pub fn deterministic_record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STORAGE-REBATE-AUCTION:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    public_record_root(domain, &[])
}

fn values_record<T, F>(records: &BTreeMap<String, T>, public_record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    records.values().map(public_record).collect()
}

fn sample_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CONTRACT-PRIVATE-STORAGE-REBATE-AUCTION:SAMPLE",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}

fn required(
    field: &str,
    value: &str,
) -> PrivateL2PqConfidentialContractPrivateStorageRebateAuctionRuntimeResult<()> {
    ensure!(!value.trim().is_empty(), "{field} is required");
    Ok(())
}
