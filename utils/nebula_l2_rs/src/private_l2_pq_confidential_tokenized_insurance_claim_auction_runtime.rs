use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedInsuranceClaimAuctionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INSURANCE_CLAIM_AUCTION_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-tokenized-insurance-claim-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_INSURANCE_CLAIM_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CLAIM_NOTE_SUITE: &str = "ringct-compatible-confidential-tokenized-claim-note-v1";
pub const SEALED_AUCTION_SUITE: &str = "ml-kem-1024-sealed-insurance-claim-auction-bid-v1";
pub const PQ_ASSESSOR_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-claim-assessor-attestation-v1";
pub const PAYOUT_TRANCHE_SUITE: &str = "confidential-tokenized-claim-payout-tranche-v1";
pub const FRAUD_GUARD_SUITE: &str = "zk-pq-confidential-claim-fraud-guard-root-v1";
pub const SETTLEMENT_BATCH_SUITE: &str = "low-fee-private-insurance-claim-batch-auction-v1";
pub const FEE_REBATE_SUITE: &str = "confidential-claim-auction-low-fee-rebate-v1";
pub const COMPLIANCE_VIEW_SUITE: &str = "redacted-tokenized-claim-compliance-view-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "operator-safe-insurance-claim-auction-summary-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 3_014_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 4_002_000;
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_RESERVE_ASSET_ID: &str = "xmr-insurance-claim-reserve-devnet";
pub const DEVNET_CLAIM_TOKEN_ASSET_ID: &str = "claim-note-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_ASSESSOR_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_SUPERMAJORITY_BPS: u64 = 8_000;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 18;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 7;
pub const DEFAULT_MAX_REBATE_BPS: u64 = 36;
pub const DEFAULT_MIN_RESERVE_RATIO_BPS: u64 = 8_800;
pub const DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 8;
pub const DEFAULT_CLAIM_NOTE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 72;
pub const DEFAULT_FRAUD_GUARD_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_SETTLEMENT_FINALITY_BLOCKS: u64 = 18;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 160;
pub const DEFAULT_MAX_CLAIM_NOTES: usize = 2_097_152;
pub const DEFAULT_MAX_AUCTIONS: usize = 1_048_576;
pub const DEFAULT_MAX_BIDS: usize = 8_388_608;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 4_194_304;
pub const DEFAULT_MAX_TRANCHES: usize = 4_194_304;
pub const DEFAULT_MAX_FRAUD_GUARDS: usize = 1_048_576;
pub const DEFAULT_MAX_SETTLEMENT_BATCHES: usize = 524_288;
pub const DEFAULT_MAX_REBATES: usize = 2_097_152;
pub const DEFAULT_MAX_COMPLIANCE_VIEWS: usize = 524_288;
pub const DEFAULT_MAX_OPERATOR_SUMMARIES: usize = 262_144;
pub const DEFAULT_MAX_EVENTS: usize = 8_388_608;
pub const DEFAULT_MAX_BIDS_PER_AUCTION: usize = 256;
pub const DEFAULT_MAX_CLAIMS_PER_BATCH: usize = 2_048;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    SmartContractExploit,
    BridgeLoss,
    StablecoinDepeg,
    LiquidationFailure,
    OracleFailure,
    ValidatorSlashing,
    WithdrawalDelay,
    ParametricEvent,
}

impl ClaimKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SmartContractExploit => "smart_contract_exploit",
            Self::BridgeLoss => "bridge_loss",
            Self::StablecoinDepeg => "stablecoin_depeg",
            Self::LiquidationFailure => "liquidation_failure",
            Self::OracleFailure => "oracle_failure",
            Self::ValidatorSlashing => "validator_slashing",
            Self::WithdrawalDelay => "withdrawal_delay",
            Self::ParametricEvent => "parametric_event",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimNoteStatus {
    Submitted,
    Attesting,
    AuctionOpen,
    Guarded,
    Batched,
    Settled,
    Rejected,
    Expired,
}

impl ClaimNoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Attesting => "attesting",
            Self::AuctionOpen => "auction_open",
            Self::Guarded => "guarded",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn auctionable(self) -> bool {
        matches!(self, Self::Submitted | Self::Attesting | Self::AuctionOpen)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Sealed,
    Reveal,
    Clearing,
    Batched,
    Settled,
    Cancelled,
    Expired,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Reveal => "reveal",
            Self::Clearing => "clearing",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_bids(self) -> bool {
        matches!(self, Self::Sealed | Self::Reveal)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Sealed,
    Revealed,
    Selected,
    PartiallyFilled,
    Refunded,
    Rejected,
    Expired,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Revealed => "revealed",
            Self::Selected => "selected",
            Self::PartiallyFilled => "partially_filled",
            Self::Refunded => "refunded",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Pending,
    ClaimLikely,
    ClaimValid,
    NeedsReview,
    FraudSuspected,
    Rejected,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::ClaimLikely => "claim_likely",
            Self::ClaimValid => "claim_valid",
            Self::NeedsReview => "needs_review",
            Self::FraudSuspected => "fraud_suspected",
            Self::Rejected => "rejected",
        }
    }

    pub fn supports_settlement(self) -> bool {
        matches!(self, Self::ClaimLikely | Self::ClaimValid)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrancheSeniority {
    FirstLoss,
    Junior,
    Mezzanine,
    Senior,
    Catastrophe,
}

impl TrancheSeniority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FirstLoss => "first_loss",
            Self::Junior => "junior",
            Self::Mezzanine => "mezzanine",
            Self::Senior => "senior",
            Self::Catastrophe => "catastrophe",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FraudSignal {
    None,
    DuplicateNullifier,
    InconsistentOracleWindow,
    ReusedEvidenceCommitment,
    ExcessiveSeverity,
    SanctionsMatch,
    AssessorConflict,
}

impl FraudSignal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::InconsistentOracleWindow => "inconsistent_oracle_window",
            Self::ReusedEvidenceCommitment => "reused_evidence_commitment",
            Self::ExcessiveSeverity => "excessive_severity",
            Self::SanctionsMatch => "sanctions_match",
            Self::AssessorConflict => "assessor_conflict",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Building,
    Committed,
    Proved,
    Finalized,
    Disputed,
    Reverted,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Building => "building",
            Self::Committed => "committed",
            Self::Proved => "proved",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub reserve_asset_id: String,
    pub claim_token_asset_id: String,
    pub hash_suite: String,
    pub claim_note_suite: String,
    pub sealed_auction_suite: String,
    pub pq_assessor_attestation_suite: String,
    pub payout_tranche_suite: String,
    pub fraud_guard_suite: String,
    pub settlement_batch_suite: String,
    pub fee_rebate_suite: String,
    pub compliance_view_suite: String,
    pub operator_summary_suite: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub assessor_quorum_bps: u64,
    pub supermajority_bps: u64,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub min_reserve_ratio_bps: u64,
    pub auction_window_blocks: u64,
    pub claim_note_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub fraud_guard_ttl_blocks: u64,
    pub settlement_finality_blocks: u64,
    pub redaction_budget_units: u64,
    pub max_claim_notes: usize,
    pub max_auctions: usize,
    pub max_bids: usize,
    pub max_attestations: usize,
    pub max_tranches: usize,
    pub max_fraud_guards: usize,
    pub max_settlement_batches: usize,
    pub max_rebates: usize,
    pub max_compliance_views: usize,
    pub max_operator_summaries: usize,
    pub max_events: usize,
    pub max_bids_per_auction: usize,
    pub max_claims_per_batch: usize,
    pub require_private_claim_notes: bool,
    pub require_pq_assessor_attestations: bool,
    pub enable_low_fee_rebates: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            reserve_asset_id: DEVNET_RESERVE_ASSET_ID.to_string(),
            claim_token_asset_id: DEVNET_CLAIM_TOKEN_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            claim_note_suite: CLAIM_NOTE_SUITE.to_string(),
            sealed_auction_suite: SEALED_AUCTION_SUITE.to_string(),
            pq_assessor_attestation_suite: PQ_ASSESSOR_ATTESTATION_SUITE.to_string(),
            payout_tranche_suite: PAYOUT_TRANCHE_SUITE.to_string(),
            fraud_guard_suite: FRAUD_GUARD_SUITE.to_string(),
            settlement_batch_suite: SETTLEMENT_BATCH_SUITE.to_string(),
            fee_rebate_suite: FEE_REBATE_SUITE.to_string(),
            compliance_view_suite: COMPLIANCE_VIEW_SUITE.to_string(),
            operator_summary_suite: OPERATOR_SUMMARY_SUITE.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            assessor_quorum_bps: DEFAULT_ASSESSOR_QUORUM_BPS,
            supermajority_bps: DEFAULT_SUPERMAJORITY_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_solver_fee_bps: DEFAULT_MAX_SOLVER_FEE_BPS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            max_rebate_bps: DEFAULT_MAX_REBATE_BPS,
            min_reserve_ratio_bps: DEFAULT_MIN_RESERVE_RATIO_BPS,
            auction_window_blocks: DEFAULT_AUCTION_WINDOW_BLOCKS,
            claim_note_ttl_blocks: DEFAULT_CLAIM_NOTE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            fraud_guard_ttl_blocks: DEFAULT_FRAUD_GUARD_TTL_BLOCKS,
            settlement_finality_blocks: DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            max_claim_notes: DEFAULT_MAX_CLAIM_NOTES,
            max_auctions: DEFAULT_MAX_AUCTIONS,
            max_bids: DEFAULT_MAX_BIDS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_tranches: DEFAULT_MAX_TRANCHES,
            max_fraud_guards: DEFAULT_MAX_FRAUD_GUARDS,
            max_settlement_batches: DEFAULT_MAX_SETTLEMENT_BATCHES,
            max_rebates: DEFAULT_MAX_REBATES,
            max_compliance_views: DEFAULT_MAX_COMPLIANCE_VIEWS,
            max_operator_summaries: DEFAULT_MAX_OPERATOR_SUMMARIES,
            max_events: DEFAULT_MAX_EVENTS,
            max_bids_per_auction: DEFAULT_MAX_BIDS_PER_AUCTION,
            max_claims_per_batch: DEFAULT_MAX_CLAIMS_PER_BATCH,
            require_private_claim_notes: true,
            require_pq_assessor_attestations: true,
            enable_low_fee_rebates: true,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_tokenized_insurance_claim_auction_config",
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "reserve_asset_id": self.reserve_asset_id,
            "claim_token_asset_id": self.claim_token_asset_id,
            "hash_suite": self.hash_suite,
            "claim_note_suite": self.claim_note_suite,
            "sealed_auction_suite": self.sealed_auction_suite,
            "pq_assessor_attestation_suite": self.pq_assessor_attestation_suite,
            "payout_tranche_suite": self.payout_tranche_suite,
            "fraud_guard_suite": self.fraud_guard_suite,
            "settlement_batch_suite": self.settlement_batch_suite,
            "fee_rebate_suite": self.fee_rebate_suite,
            "compliance_view_suite": self.compliance_view_suite,
            "operator_summary_suite": self.operator_summary_suite,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "assessor_quorum_bps": self.assessor_quorum_bps,
            "supermajority_bps": self.supermajority_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "min_reserve_ratio_bps": self.min_reserve_ratio_bps,
            "auction_window_blocks": self.auction_window_blocks,
            "claim_note_ttl_blocks": self.claim_note_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "fraud_guard_ttl_blocks": self.fraud_guard_ttl_blocks,
            "settlement_finality_blocks": self.settlement_finality_blocks,
            "redaction_budget_units": self.redaction_budget_units,
            "max_claim_notes": self.max_claim_notes,
            "max_auctions": self.max_auctions,
            "max_bids": self.max_bids,
            "max_attestations": self.max_attestations,
            "max_tranches": self.max_tranches,
            "max_fraud_guards": self.max_fraud_guards,
            "max_settlement_batches": self.max_settlement_batches,
            "max_rebates": self.max_rebates,
            "max_compliance_views": self.max_compliance_views,
            "max_operator_summaries": self.max_operator_summaries,
            "max_events": self.max_events,
            "max_bids_per_auction": self.max_bids_per_auction,
            "max_claims_per_batch": self.max_claims_per_batch,
            "require_private_claim_notes": self.require_private_claim_notes,
            "require_pq_assessor_attestations": self.require_pq_assessor_attestations,
            "enable_low_fee_rebates": self.enable_low_fee_rebates,
        })
    }

    pub fn state_root(&self) -> String {
        value_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require(
            self.schema_version == SCHEMA_VERSION,
            "schema version mismatch",
        )?;
        require(self.min_pq_security_bits >= 192, "pq security too low")?;
        require(self.min_privacy_set_size > 0, "privacy set is zero")?;
        require(
            self.batch_privacy_set_size >= self.min_privacy_set_size,
            "batch privacy set below minimum",
        )?;
        require(
            self.assessor_quorum_bps <= MAX_BPS,
            "assessor quorum exceeds bps",
        )?;
        require(
            self.supermajority_bps <= MAX_BPS,
            "supermajority exceeds bps",
        )?;
        require(self.max_user_fee_bps <= MAX_BPS, "user fee cap exceeds bps")?;
        require(
            self.max_solver_fee_bps <= MAX_BPS,
            "solver fee cap exceeds bps",
        )?;
        require(self.max_rebate_bps <= MAX_BPS, "rebate cap exceeds bps")?;
        require(
            self.low_fee_rebate_bps <= self.max_rebate_bps,
            "rebate exceeds cap",
        )?;
        require(
            self.min_reserve_ratio_bps <= MAX_BPS,
            "reserve ratio exceeds bps",
        )?;
        require(self.auction_window_blocks > 0, "auction window is zero")?;
        require(
            self.claim_note_ttl_blocks > self.auction_window_blocks,
            "claim ttl too short",
        )?;
        require(self.max_claim_notes > 0, "max claim notes is zero")?;
        require(self.max_auctions > 0, "max auctions is zero")?;
        require(self.max_bids > 0, "max bids is zero")?;
        require(
            self.max_claims_per_batch > 0,
            "max claims per batch is zero",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_claim_nonce: u64,
    pub next_auction_nonce: u64,
    pub next_bid_nonce: u64,
    pub next_attestation_nonce: u64,
    pub next_tranche_nonce: u64,
    pub next_fraud_guard_nonce: u64,
    pub next_batch_nonce: u64,
    pub next_rebate_nonce: u64,
    pub next_compliance_view_nonce: u64,
    pub next_operator_summary_nonce: u64,
    pub claim_notes_submitted: u64,
    pub auctions_opened: u64,
    pub bids_submitted: u64,
    pub attestations_posted: u64,
    pub tranches_issued: u64,
    pub fraud_guards_posted: u64,
    pub settlement_batches_committed: u64,
    pub claim_notes_settled: u64,
    pub rebates_issued: u64,
    pub compliance_views_published: u64,
    pub operator_summaries_published: u64,
    pub fees_charged_micro_units: u64,
    pub rebates_paid_micro_units: u64,
    pub confidential_payout_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_tokenized_insurance_claim_auction_counters",
            "next_claim_nonce": self.next_claim_nonce,
            "next_auction_nonce": self.next_auction_nonce,
            "next_bid_nonce": self.next_bid_nonce,
            "next_attestation_nonce": self.next_attestation_nonce,
            "next_tranche_nonce": self.next_tranche_nonce,
            "next_fraud_guard_nonce": self.next_fraud_guard_nonce,
            "next_batch_nonce": self.next_batch_nonce,
            "next_rebate_nonce": self.next_rebate_nonce,
            "next_compliance_view_nonce": self.next_compliance_view_nonce,
            "next_operator_summary_nonce": self.next_operator_summary_nonce,
            "claim_notes_submitted": self.claim_notes_submitted,
            "auctions_opened": self.auctions_opened,
            "bids_submitted": self.bids_submitted,
            "attestations_posted": self.attestations_posted,
            "tranches_issued": self.tranches_issued,
            "fraud_guards_posted": self.fraud_guards_posted,
            "settlement_batches_committed": self.settlement_batches_committed,
            "claim_notes_settled": self.claim_notes_settled,
            "rebates_issued": self.rebates_issued,
            "compliance_views_published": self.compliance_views_published,
            "operator_summaries_published": self.operator_summaries_published,
            "fees_charged_micro_units": self.fees_charged_micro_units,
            "rebates_paid_micro_units": self.rebates_paid_micro_units,
            "confidential_payout_micro_units": self.confidential_payout_micro_units,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateClaimNote {
    pub claim_id: String,
    pub policy_commitment: String,
    pub claimant_commitment: String,
    pub claim_kind: ClaimKind,
    pub status: ClaimNoteStatus,
    pub claim_token_asset_id: String,
    pub loss_commitment_root: String,
    pub requested_payout_commitment_root: String,
    pub evidence_commitment_root: String,
    pub reserve_bucket_root: String,
    pub nullifier_root: String,
    pub refund_address_commitment: String,
    pub privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub auction_id: Option<String>,
    pub settlement_batch_id: Option<String>,
}

impl PrivateClaimNote {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_insurance_claim_note",
            "claim_id": self.claim_id,
            "policy_commitment": self.policy_commitment,
            "claimant_commitment": self.claimant_commitment,
            "claim_kind": self.claim_kind.as_str(),
            "status": self.status.as_str(),
            "claim_token_asset_id": self.claim_token_asset_id,
            "loss_commitment_root": self.loss_commitment_root,
            "requested_payout_commitment_root": self.requested_payout_commitment_root,
            "evidence_commitment_root": self.evidence_commitment_root,
            "reserve_bucket_root": self.reserve_bucket_root,
            "nullifier_root": self.nullifier_root,
            "refund_address_commitment": self.refund_address_commitment,
            "privacy_set_size": self.privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "auction_id": self.auction_id,
            "settlement_batch_id": self.settlement_batch_id,
        })
    }

    pub fn state_root(&self) -> String {
        value_root("CLAIM-NOTE", &self.public_record())
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require(!self.claim_id.is_empty(), "claim id is empty")?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "claim privacy set too small",
        )?;
        require(
            self.max_user_fee_bps <= config.max_user_fee_bps,
            "claim user fee too high",
        )?;
        require(
            self.expires_at_height > self.submitted_at_height,
            "claim expires before submit",
        )?;
        require(!self.nullifier_root.is_empty(), "claim nullifier is empty")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedClaimAuction {
    pub auction_id: String,
    pub claim_id: String,
    pub status: AuctionStatus,
    pub reserve_asset_id: String,
    pub claim_token_asset_id: String,
    pub sealed_claim_root: String,
    pub bid_book_root: String,
    pub clearing_price_commitment_root: String,
    pub selected_bid_root: String,
    pub min_settlement_ratio_bps: u64,
    pub max_solver_fee_bps: u64,
    pub opened_at_height: u64,
    pub reveal_at_height: u64,
    pub expires_at_height: u64,
    pub bid_ids: Vec<String>,
}

impl SealedClaimAuction {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_insurance_claim_auction",
            "auction_id": self.auction_id,
            "claim_id": self.claim_id,
            "status": self.status.as_str(),
            "reserve_asset_id": self.reserve_asset_id,
            "claim_token_asset_id": self.claim_token_asset_id,
            "sealed_claim_root": self.sealed_claim_root,
            "bid_book_root": self.bid_book_root,
            "clearing_price_commitment_root": self.clearing_price_commitment_root,
            "selected_bid_root": self.selected_bid_root,
            "min_settlement_ratio_bps": self.min_settlement_ratio_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "opened_at_height": self.opened_at_height,
            "reveal_at_height": self.reveal_at_height,
            "expires_at_height": self.expires_at_height,
            "bid_ids": self.bid_ids,
        })
    }

    pub fn state_root(&self) -> String {
        value_root("SEALED-AUCTION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedAuctionBid {
    pub bid_id: String,
    pub auction_id: String,
    pub bidder_commitment: String,
    pub status: BidStatus,
    pub sealed_bid_root: String,
    pub liquidity_commitment_root: String,
    pub price_commitment_root: String,
    pub fill_commitment_root: String,
    pub refund_commitment_root: String,
    pub solver_fee_bps: u64,
    pub requested_rebate_bps: u64,
    pub submitted_at_height: u64,
    pub pq_attestation_root: String,
}

impl SealedAuctionBid {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_insurance_claim_auction_bid",
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "bidder_commitment": self.bidder_commitment,
            "status": self.status.as_str(),
            "sealed_bid_root": self.sealed_bid_root,
            "liquidity_commitment_root": self.liquidity_commitment_root,
            "price_commitment_root": self.price_commitment_root,
            "fill_commitment_root": self.fill_commitment_root,
            "refund_commitment_root": self.refund_commitment_root,
            "solver_fee_bps": self.solver_fee_bps,
            "requested_rebate_bps": self.requested_rebate_bps,
            "submitted_at_height": self.submitted_at_height,
            "pq_attestation_root": self.pq_attestation_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssessorAttestation {
    pub attestation_id: String,
    pub claim_id: String,
    pub assessor_commitment: String,
    pub verdict: AttestationVerdict,
    pub severity_bps: u64,
    pub confidence_bps: u64,
    pub event_window_root: String,
    pub evidence_digest_root: String,
    pub policy_terms_root: String,
    pub pq_signature_root: String,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
}

impl AssessorAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_claim_assessor_attestation",
            "attestation_id": self.attestation_id,
            "claim_id": self.claim_id,
            "assessor_commitment": self.assessor_commitment,
            "verdict": self.verdict.as_str(),
            "severity_bps": self.severity_bps,
            "confidence_bps": self.confidence_bps,
            "event_window_root": self.event_window_root,
            "evidence_digest_root": self.evidence_digest_root,
            "policy_terms_root": self.policy_terms_root,
            "pq_signature_root": self.pq_signature_root,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn supports_settlement(&self, config: &Config) -> bool {
        self.verdict.supports_settlement() && self.confidence_bps >= config.assessor_quorum_bps
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PayoutTranche {
    pub tranche_id: String,
    pub claim_id: String,
    pub auction_id: String,
    pub seniority: TrancheSeniority,
    pub token_asset_id: String,
    pub tranche_commitment_root: String,
    pub payout_commitment_root: String,
    pub recipient_commitment_root: String,
    pub attachment_bps: u64,
    pub detachment_bps: u64,
    pub fee_bps: u64,
    pub issued_at_height: u64,
}

impl PayoutTranche {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_claim_payout_tranche",
            "tranche_id": self.tranche_id,
            "claim_id": self.claim_id,
            "auction_id": self.auction_id,
            "seniority": self.seniority.as_str(),
            "token_asset_id": self.token_asset_id,
            "tranche_commitment_root": self.tranche_commitment_root,
            "payout_commitment_root": self.payout_commitment_root,
            "recipient_commitment_root": self.recipient_commitment_root,
            "attachment_bps": self.attachment_bps,
            "detachment_bps": self.detachment_bps,
            "fee_bps": self.fee_bps,
            "issued_at_height": self.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClaimFraudGuard {
    pub guard_id: String,
    pub claim_id: String,
    pub signal: FraudSignal,
    pub risk_score_bps: u64,
    pub duplicate_nullifier_seen: bool,
    pub sanctions_screen_root: String,
    pub evidence_reuse_root: String,
    pub assessor_conflict_root: String,
    pub mitigation_root: String,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
}

impl ClaimFraudGuard {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "claim_fraud_guard",
            "guard_id": self.guard_id,
            "claim_id": self.claim_id,
            "signal": self.signal.as_str(),
            "risk_score_bps": self.risk_score_bps,
            "duplicate_nullifier_seen": self.duplicate_nullifier_seen,
            "sanctions_screen_root": self.sanctions_screen_root,
            "evidence_reuse_root": self.evidence_reuse_root,
            "assessor_conflict_root": self.assessor_conflict_root,
            "mitigation_root": self.mitigation_root,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn blocks_settlement(&self) -> bool {
        self.duplicate_nullifier_seen || self.risk_score_bps >= 7_500
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub status: BatchStatus,
    pub claim_ids: Vec<String>,
    pub auction_ids: Vec<String>,
    pub selected_bid_ids: Vec<String>,
    pub tranche_ids: Vec<String>,
    pub claim_note_root_before: String,
    pub claim_note_root_after: String,
    pub nullifier_spend_root: String,
    pub payout_distribution_root: String,
    pub fee_rebate_root: String,
    pub batch_proof_root: String,
    pub state_root_before: String,
    pub state_root_after: String,
    pub committed_at_height: u64,
    pub finalized_at_height: u64,
}

impl SettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_insurance_claim_settlement_batch",
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "claim_ids": self.claim_ids,
            "auction_ids": self.auction_ids,
            "selected_bid_ids": self.selected_bid_ids,
            "tranche_ids": self.tranche_ids,
            "claim_note_root_before": self.claim_note_root_before,
            "claim_note_root_after": self.claim_note_root_after,
            "nullifier_spend_root": self.nullifier_spend_root,
            "payout_distribution_root": self.payout_distribution_root,
            "fee_rebate_root": self.fee_rebate_root,
            "batch_proof_root": self.batch_proof_root,
            "state_root_before": self.state_root_before,
            "state_root_after": self.state_root_after,
            "committed_at_height": self.committed_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub subject_id: String,
    pub beneficiary_commitment: String,
    pub rebate_commitment_root: String,
    pub rebate_bps: u64,
    pub fee_paid_micro_units: u64,
    pub rebate_micro_units: u64,
    pub issued_at_height: u64,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_claim_auction_fee_rebate",
            "rebate_id": self.rebate_id,
            "subject_id": self.subject_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_commitment_root": self.rebate_commitment_root,
            "rebate_bps": self.rebate_bps,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "issued_at_height": self.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactedComplianceView {
    pub view_id: String,
    pub subject_id: String,
    pub view_kind: String,
    pub regulator_commitment: String,
    pub redacted_claim_root: String,
    pub jurisdiction_root: String,
    pub sanctions_result_root: String,
    pub audit_scope_root: String,
    pub disclosure_budget_remaining: u64,
    pub published_at_height: u64,
}

impl RedactedComplianceView {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "redacted_claim_auction_compliance_view",
            "view_id": self.view_id,
            "subject_id": self.subject_id,
            "view_kind": self.view_kind,
            "regulator_commitment": self.regulator_commitment,
            "redacted_claim_root": self.redacted_claim_root,
            "jurisdiction_root": self.jurisdiction_root,
            "sanctions_result_root": self.sanctions_result_root,
            "audit_scope_root": self.audit_scope_root,
            "disclosure_budget_remaining": self.disclosure_budget_remaining,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_commitment: String,
    pub height: u64,
    pub live_claim_count: u64,
    pub open_auction_count: u64,
    pub settlement_batch_count: u64,
    pub total_confidential_payout_micro_units: u64,
    pub total_fee_rebate_micro_units: u64,
    pub reserve_ratio_bps: u64,
    pub fraud_guard_count: u64,
    pub public_roots: Roots,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_claim_auction_summary",
            "summary_id": self.summary_id,
            "operator_commitment": self.operator_commitment,
            "height": self.height,
            "live_claim_count": self.live_claim_count,
            "open_auction_count": self.open_auction_count,
            "settlement_batch_count": self.settlement_batch_count,
            "total_confidential_payout_micro_units": self.total_confidential_payout_micro_units,
            "total_fee_rebate_micro_units": self.total_fee_rebate_micro_units,
            "reserve_ratio_bps": self.reserve_ratio_bps,
            "fraud_guard_count": self.fraud_guard_count,
            "public_roots": self.public_roots.public_record(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub claim_note_root: String,
    pub auction_root: String,
    pub bid_root: String,
    pub attestation_root: String,
    pub tranche_root: String,
    pub fraud_guard_root: String,
    pub settlement_batch_root: String,
    pub fee_rebate_root: String,
    pub compliance_view_root: String,
    pub operator_summary_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "claim_note_root": self.claim_note_root,
            "auction_root": self.auction_root,
            "bid_root": self.bid_root,
            "attestation_root": self.attestation_root,
            "tranche_root": self.tranche_root,
            "fraud_guard_root": self.fraud_guard_root,
            "settlement_batch_root": self.settlement_batch_root,
            "fee_rebate_root": self.fee_rebate_root,
            "compliance_view_root": self.compliance_view_root,
            "operator_summary_root": self.operator_summary_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub monero_height: u64,
    pub roots: Roots,
    pub claim_notes: BTreeMap<String, PrivateClaimNote>,
    pub auctions: BTreeMap<String, SealedClaimAuction>,
    pub bids: BTreeMap<String, SealedAuctionBid>,
    pub attestations: BTreeMap<String, AssessorAttestation>,
    pub payout_tranches: BTreeMap<String, PayoutTranche>,
    pub fraud_guards: BTreeMap<String, ClaimFraudGuard>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub fee_rebates: BTreeMap<String, FeeRebate>,
    pub compliance_views: BTreeMap<String, RedactedComplianceView>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub events: BTreeMap<String, Value>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            current_height: DEVNET_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            roots: Roots::default(),
            claim_notes: BTreeMap::new(),
            auctions: BTreeMap::new(),
            bids: BTreeMap::new(),
            attestations: BTreeMap::new(),
            payout_tranches: BTreeMap::new(),
            fraud_guards: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            compliance_views: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            events: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.recompute_roots();
        state.publish_public_record("config", "devnet", state.config.public_record());
        state
    }

    pub fn devnet() -> Self {
        Self::new(Config::default())
    }

    pub fn submit_claim_note(
        &mut self,
        claim_kind: ClaimKind,
        policy_commitment: impl Into<String>,
        claimant_commitment: impl Into<String>,
        loss_commitment_root: impl Into<String>,
        requested_payout_commitment_root: impl Into<String>,
        evidence_commitment_root: impl Into<String>,
        reserve_bucket_root: impl Into<String>,
        nullifier_root: impl Into<String>,
        refund_address_commitment: impl Into<String>,
        max_user_fee_bps: u64,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        require(
            self.claim_notes.len() < self.config.max_claim_notes,
            "claim note capacity full",
        )?;
        require(
            max_user_fee_bps <= self.config.max_user_fee_bps,
            "claim user fee too high",
        )?;
        require(height >= self.current_height, "claim height before runtime")?;
        let nullifier_root = nullifier_root.into();
        require(
            !self.consumed_nullifiers.contains(&nullifier_root),
            "claim nullifier already consumed",
        )?;
        let nonce = self.counters.next_claim_nonce;
        self.counters.next_claim_nonce += 1;
        let record = json!({
            "nonce": nonce,
            "claim_kind": claim_kind.as_str(),
            "policy_commitment": policy_commitment.into(),
            "claimant_commitment": claimant_commitment.into(),
            "height": height,
            "nullifier_root": nullifier_root,
        });
        let claim_id = id_from_record("CLAIM-ID", &record);
        let note = PrivateClaimNote {
            claim_id: claim_id.clone(),
            policy_commitment: record["policy_commitment"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            claimant_commitment: record["claimant_commitment"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            claim_kind,
            status: ClaimNoteStatus::Submitted,
            claim_token_asset_id: self.config.claim_token_asset_id.clone(),
            loss_commitment_root: loss_commitment_root.into(),
            requested_payout_commitment_root: requested_payout_commitment_root.into(),
            evidence_commitment_root: evidence_commitment_root.into(),
            reserve_bucket_root: reserve_bucket_root.into(),
            nullifier_root,
            refund_address_commitment: refund_address_commitment.into(),
            privacy_set_size: self.config.batch_privacy_set_size,
            max_user_fee_bps,
            submitted_at_height: height,
            expires_at_height: height + self.config.claim_note_ttl_blocks,
            auction_id: None,
            settlement_batch_id: None,
        };
        note.validate(&self.config)?;
        self.counters.claim_notes_submitted += 1;
        self.current_height = self.current_height.max(height);
        self.publish_public_record("claim_note", &claim_id, note.public_record());
        self.claim_notes.insert(claim_id.clone(), note);
        self.recompute_roots();
        Ok(claim_id)
    }

    pub fn open_sealed_auction(
        &mut self,
        claim_id: impl Into<String>,
        min_settlement_ratio_bps: u64,
        max_solver_fee_bps: u64,
        height: u64,
    ) -> Result<String> {
        let claim_id = claim_id.into();
        require(
            self.auctions.len() < self.config.max_auctions,
            "auction capacity full",
        )?;
        require(
            min_settlement_ratio_bps <= MAX_BPS,
            "settlement ratio exceeds bps",
        )?;
        require(
            max_solver_fee_bps <= self.config.max_solver_fee_bps,
            "solver fee too high",
        )?;
        let note = self
            .claim_notes
            .get_mut(&claim_id)
            .ok_or_else(|| "claim note not found".to_string())?;
        require(note.status.auctionable(), "claim note is not auctionable")?;
        require(height <= note.expires_at_height, "claim note expired")?;
        let nonce = self.counters.next_auction_nonce;
        self.counters.next_auction_nonce += 1;
        let auction_id = id_from_record(
            "CLAIM-AUCTION-ID",
            &json!({ "claim_id": &claim_id, "nonce": nonce }),
        );
        let auction = SealedClaimAuction {
            auction_id: auction_id.clone(),
            claim_id: claim_id.clone(),
            status: AuctionStatus::Sealed,
            reserve_asset_id: self.config.reserve_asset_id.clone(),
            claim_token_asset_id: self.config.claim_token_asset_id.clone(),
            sealed_claim_root: note.state_root(),
            bid_book_root: empty_root("AUCTION-BID-BOOK"),
            clearing_price_commitment_root: empty_root("CLEARING-PRICE"),
            selected_bid_root: empty_root("SELECTED-BIDS"),
            min_settlement_ratio_bps,
            max_solver_fee_bps,
            opened_at_height: height,
            reveal_at_height: height + self.config.auction_window_blocks,
            expires_at_height: height + self.config.auction_window_blocks * 2,
            bid_ids: Vec::new(),
        };
        note.status = ClaimNoteStatus::AuctionOpen;
        note.auction_id = Some(auction_id.clone());
        self.counters.auctions_opened += 1;
        self.current_height = self.current_height.max(height);
        self.publish_public_record("auction", &auction_id, auction.public_record());
        self.auctions.insert(auction_id.clone(), auction);
        self.recompute_roots();
        Ok(auction_id)
    }

    pub fn submit_sealed_bid(
        &mut self,
        auction_id: impl Into<String>,
        bidder_commitment: impl Into<String>,
        sealed_bid_root: impl Into<String>,
        liquidity_commitment_root: impl Into<String>,
        price_commitment_root: impl Into<String>,
        fill_commitment_root: impl Into<String>,
        refund_commitment_root: impl Into<String>,
        solver_fee_bps: u64,
        requested_rebate_bps: u64,
        pq_attestation_root: impl Into<String>,
        height: u64,
    ) -> Result<String> {
        let auction_id = auction_id.into();
        require(self.bids.len() < self.config.max_bids, "bid capacity full")?;
        require(
            solver_fee_bps <= self.config.max_solver_fee_bps,
            "solver fee too high",
        )?;
        require(
            requested_rebate_bps <= self.config.max_rebate_bps,
            "rebate too high",
        )?;
        let auction = self
            .auctions
            .get_mut(&auction_id)
            .ok_or_else(|| "auction not found".to_string())?;
        require(
            auction.status.accepts_bids(),
            "auction no longer accepts bids",
        )?;
        require(
            auction.bid_ids.len() < self.config.max_bids_per_auction,
            "auction bid book full",
        )?;
        require(height <= auction.expires_at_height, "auction expired")?;
        let nonce = self.counters.next_bid_nonce;
        self.counters.next_bid_nonce += 1;
        let bid_id = id_from_record(
            "CLAIM-AUCTION-BID-ID",
            &json!({ "auction_id": &auction_id, "nonce": nonce }),
        );
        let bid = SealedAuctionBid {
            bid_id: bid_id.clone(),
            auction_id: auction_id.clone(),
            bidder_commitment: bidder_commitment.into(),
            status: BidStatus::Sealed,
            sealed_bid_root: sealed_bid_root.into(),
            liquidity_commitment_root: liquidity_commitment_root.into(),
            price_commitment_root: price_commitment_root.into(),
            fill_commitment_root: fill_commitment_root.into(),
            refund_commitment_root: refund_commitment_root.into(),
            solver_fee_bps,
            requested_rebate_bps,
            submitted_at_height: height,
            pq_attestation_root: pq_attestation_root.into(),
        };
        auction.bid_ids.push(bid_id.clone());
        auction.bid_book_root = merkle_string_root("AUCTION-BID-BOOK", &auction.bid_ids);
        self.counters.bids_submitted += 1;
        self.current_height = self.current_height.max(height);
        self.publish_public_record("bid", &bid_id, bid.public_record());
        self.bids.insert(bid_id.clone(), bid);
        self.recompute_roots();
        Ok(bid_id)
    }

    pub fn post_assessor_attestation(
        &mut self,
        claim_id: impl Into<String>,
        assessor_commitment: impl Into<String>,
        verdict: AttestationVerdict,
        severity_bps: u64,
        confidence_bps: u64,
        event_window_root: impl Into<String>,
        evidence_digest_root: impl Into<String>,
        policy_terms_root: impl Into<String>,
        pq_signature_root: impl Into<String>,
        height: u64,
    ) -> Result<String> {
        let claim_id = claim_id.into();
        require(
            self.attestations.len() < self.config.max_attestations,
            "attestation capacity full",
        )?;
        require(
            self.claim_notes.contains_key(&claim_id),
            "claim note not found",
        )?;
        require(severity_bps <= MAX_BPS, "severity exceeds bps")?;
        require(confidence_bps <= MAX_BPS, "confidence exceeds bps")?;
        let nonce = self.counters.next_attestation_nonce;
        self.counters.next_attestation_nonce += 1;
        let attestation_id = id_from_record(
            "CLAIM-ATTESTATION-ID",
            &json!({ "claim_id": &claim_id, "nonce": nonce }),
        );
        let attestation = AssessorAttestation {
            attestation_id: attestation_id.clone(),
            claim_id: claim_id.clone(),
            assessor_commitment: assessor_commitment.into(),
            verdict,
            severity_bps,
            confidence_bps,
            event_window_root: event_window_root.into(),
            evidence_digest_root: evidence_digest_root.into(),
            policy_terms_root: policy_terms_root.into(),
            pq_signature_root: pq_signature_root.into(),
            posted_at_height: height,
            expires_at_height: height + self.config.attestation_ttl_blocks,
        };
        if let Some(note) = self.claim_notes.get_mut(&claim_id) {
            if verdict.supports_settlement() {
                note.status = ClaimNoteStatus::Attesting;
            }
        }
        self.counters.attestations_posted += 1;
        self.current_height = self.current_height.max(height);
        self.publish_public_record("attestation", &attestation_id, attestation.public_record());
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.recompute_roots();
        Ok(attestation_id)
    }

    pub fn issue_payout_tranche(
        &mut self,
        claim_id: impl Into<String>,
        auction_id: impl Into<String>,
        seniority: TrancheSeniority,
        tranche_commitment_root: impl Into<String>,
        payout_commitment_root: impl Into<String>,
        recipient_commitment_root: impl Into<String>,
        attachment_bps: u64,
        detachment_bps: u64,
        fee_bps: u64,
        height: u64,
    ) -> Result<String> {
        let claim_id = claim_id.into();
        let auction_id = auction_id.into();
        require(
            self.payout_tranches.len() < self.config.max_tranches,
            "tranche capacity full",
        )?;
        require(
            self.claim_notes.contains_key(&claim_id),
            "claim note not found",
        )?;
        require(self.auctions.contains_key(&auction_id), "auction not found")?;
        require(
            attachment_bps <= detachment_bps && detachment_bps <= MAX_BPS,
            "invalid tranche bounds",
        )?;
        require(
            fee_bps <= self.config.max_solver_fee_bps,
            "tranche fee too high",
        )?;
        let nonce = self.counters.next_tranche_nonce;
        self.counters.next_tranche_nonce += 1;
        let tranche_id = id_from_record(
            "CLAIM-PAYOUT-TRANCHE-ID",
            &json!({ "claim_id": &claim_id, "auction_id": &auction_id, "nonce": nonce }),
        );
        let tranche = PayoutTranche {
            tranche_id: tranche_id.clone(),
            claim_id,
            auction_id,
            seniority,
            token_asset_id: self.config.claim_token_asset_id.clone(),
            tranche_commitment_root: tranche_commitment_root.into(),
            payout_commitment_root: payout_commitment_root.into(),
            recipient_commitment_root: recipient_commitment_root.into(),
            attachment_bps,
            detachment_bps,
            fee_bps,
            issued_at_height: height,
        };
        self.counters.tranches_issued += 1;
        self.current_height = self.current_height.max(height);
        self.publish_public_record("tranche", &tranche_id, tranche.public_record());
        self.payout_tranches.insert(tranche_id.clone(), tranche);
        self.recompute_roots();
        Ok(tranche_id)
    }

    pub fn post_fraud_guard(
        &mut self,
        claim_id: impl Into<String>,
        signal: FraudSignal,
        risk_score_bps: u64,
        duplicate_nullifier_seen: bool,
        sanctions_screen_root: impl Into<String>,
        evidence_reuse_root: impl Into<String>,
        assessor_conflict_root: impl Into<String>,
        mitigation_root: impl Into<String>,
        height: u64,
    ) -> Result<String> {
        let claim_id = claim_id.into();
        require(
            self.fraud_guards.len() < self.config.max_fraud_guards,
            "fraud guard capacity full",
        )?;
        require(
            self.claim_notes.contains_key(&claim_id),
            "claim note not found",
        )?;
        require(risk_score_bps <= MAX_BPS, "risk score exceeds bps")?;
        let nonce = self.counters.next_fraud_guard_nonce;
        self.counters.next_fraud_guard_nonce += 1;
        let guard_id = id_from_record(
            "CLAIM-FRAUD-GUARD-ID",
            &json!({ "claim_id": &claim_id, "nonce": nonce }),
        );
        let guard = ClaimFraudGuard {
            guard_id: guard_id.clone(),
            claim_id: claim_id.clone(),
            signal,
            risk_score_bps,
            duplicate_nullifier_seen,
            sanctions_screen_root: sanctions_screen_root.into(),
            evidence_reuse_root: evidence_reuse_root.into(),
            assessor_conflict_root: assessor_conflict_root.into(),
            mitigation_root: mitigation_root.into(),
            posted_at_height: height,
            expires_at_height: height + self.config.fraud_guard_ttl_blocks,
        };
        if guard.blocks_settlement() {
            if let Some(note) = self.claim_notes.get_mut(&claim_id) {
                note.status = ClaimNoteStatus::Guarded;
            }
        }
        self.counters.fraud_guards_posted += 1;
        self.current_height = self.current_height.max(height);
        self.publish_public_record("fraud_guard", &guard_id, guard.public_record());
        self.fraud_guards.insert(guard_id.clone(), guard);
        self.recompute_roots();
        Ok(guard_id)
    }

    pub fn commit_settlement_batch(
        &mut self,
        claim_ids: Vec<String>,
        auction_ids: Vec<String>,
        selected_bid_ids: Vec<String>,
        tranche_ids: Vec<String>,
        payout_distribution_root: impl Into<String>,
        batch_proof_root: impl Into<String>,
        height: u64,
    ) -> Result<String> {
        require(
            self.settlement_batches.len() < self.config.max_settlement_batches,
            "settlement batch capacity full",
        )?;
        require(!claim_ids.is_empty(), "settlement batch is empty")?;
        require(
            claim_ids.len() <= self.config.max_claims_per_batch,
            "too many claims in batch",
        )?;
        for claim_id in &claim_ids {
            let note = self
                .claim_notes
                .get(claim_id)
                .ok_or_else(|| "claim note not found".to_string())?;
            require(
                !self.consumed_nullifiers.contains(&note.nullifier_root),
                "claim nullifier consumed",
            )?;
            require(
                !self.claim_has_blocking_guard(claim_id),
                "claim has blocking fraud guard",
            )?;
            require(
                self.claim_has_supporting_attestation(claim_id),
                "claim missing supporting attestation",
            )?;
        }
        let state_root_before = self.state_root();
        let claim_note_root_before = self.roots.claim_note_root.clone();
        let nonce = self.counters.next_batch_nonce;
        self.counters.next_batch_nonce += 1;
        let batch_id = id_from_record(
            "CLAIM-SETTLEMENT-BATCH-ID",
            &json!({ "nonce": nonce, "claim_ids": &claim_ids }),
        );
        for claim_id in &claim_ids {
            if let Some(note) = self.claim_notes.get_mut(claim_id) {
                note.status = ClaimNoteStatus::Settled;
                note.settlement_batch_id = Some(batch_id.clone());
                self.consumed_nullifiers.insert(note.nullifier_root.clone());
                self.counters.confidential_payout_micro_units += 1;
            }
        }
        for auction_id in &auction_ids {
            if let Some(auction) = self.auctions.get_mut(auction_id) {
                auction.status = AuctionStatus::Settled;
            }
        }
        for bid_id in &selected_bid_ids {
            if let Some(bid) = self.bids.get_mut(bid_id) {
                bid.status = BidStatus::Selected;
            }
        }
        self.recompute_roots();
        let batch = SettlementBatch {
            batch_id: batch_id.clone(),
            status: BatchStatus::Committed,
            claim_ids: claim_ids.clone(),
            auction_ids,
            selected_bid_ids,
            tranche_ids,
            claim_note_root_before,
            claim_note_root_after: self.roots.claim_note_root.clone(),
            nullifier_spend_root: self.roots.nullifier_root.clone(),
            payout_distribution_root: payout_distribution_root.into(),
            fee_rebate_root: self.roots.fee_rebate_root.clone(),
            batch_proof_root: batch_proof_root.into(),
            state_root_before,
            state_root_after: self.state_root(),
            committed_at_height: height,
            finalized_at_height: height + self.config.settlement_finality_blocks,
        };
        self.counters.settlement_batches_committed += 1;
        self.counters.claim_notes_settled += claim_ids.len() as u64;
        self.current_height = self.current_height.max(height);
        self.publish_public_record("settlement_batch", &batch_id, batch.public_record());
        self.settlement_batches.insert(batch_id.clone(), batch);
        self.recompute_roots();
        Ok(batch_id)
    }

    pub fn issue_fee_rebate(
        &mut self,
        subject_id: impl Into<String>,
        beneficiary_commitment: impl Into<String>,
        fee_paid_micro_units: u64,
        rebate_bps: u64,
        height: u64,
    ) -> Result<String> {
        require(self.config.enable_low_fee_rebates, "fee rebates disabled")?;
        require(
            self.fee_rebates.len() < self.config.max_rebates,
            "rebate capacity full",
        )?;
        require(
            rebate_bps <= self.config.max_rebate_bps,
            "rebate exceeds cap",
        )?;
        let subject_id = subject_id.into();
        let rebate_micro_units = fee_paid_micro_units.saturating_mul(rebate_bps) / MAX_BPS;
        let nonce = self.counters.next_rebate_nonce;
        self.counters.next_rebate_nonce += 1;
        let rebate_id = id_from_record(
            "CLAIM-FEE-REBATE-ID",
            &json!({ "subject_id": subject_id, "nonce": nonce }),
        );
        let rebate = FeeRebate {
            rebate_id: rebate_id.clone(),
            subject_id,
            beneficiary_commitment: beneficiary_commitment.into(),
            rebate_commitment_root: commitment(
                "FEE-REBATE-COMMITMENT",
                &[HashPart::U64(rebate_micro_units), HashPart::U64(height)],
            ),
            rebate_bps,
            fee_paid_micro_units,
            rebate_micro_units,
            issued_at_height: height,
        };
        self.counters.rebates_issued += 1;
        self.counters.fees_charged_micro_units += fee_paid_micro_units;
        self.counters.rebates_paid_micro_units += rebate_micro_units;
        self.current_height = self.current_height.max(height);
        self.publish_public_record("fee_rebate", &rebate_id, rebate.public_record());
        self.fee_rebates.insert(rebate_id.clone(), rebate);
        self.recompute_roots();
        Ok(rebate_id)
    }

    pub fn publish_compliance_view(
        &mut self,
        subject_id: impl Into<String>,
        view_kind: impl Into<String>,
        regulator_commitment: impl Into<String>,
        redacted_claim_root: impl Into<String>,
        jurisdiction_root: impl Into<String>,
        sanctions_result_root: impl Into<String>,
        audit_scope_root: impl Into<String>,
        height: u64,
    ) -> Result<String> {
        require(
            self.compliance_views.len() < self.config.max_compliance_views,
            "compliance view capacity full",
        )?;
        let subject_id = subject_id.into();
        let nonce = self.counters.next_compliance_view_nonce;
        self.counters.next_compliance_view_nonce += 1;
        let view_id = id_from_record(
            "CLAIM-COMPLIANCE-VIEW-ID",
            &json!({ "subject_id": subject_id, "nonce": nonce }),
        );
        let view = RedactedComplianceView {
            view_id: view_id.clone(),
            subject_id,
            view_kind: view_kind.into(),
            regulator_commitment: regulator_commitment.into(),
            redacted_claim_root: redacted_claim_root.into(),
            jurisdiction_root: jurisdiction_root.into(),
            sanctions_result_root: sanctions_result_root.into(),
            audit_scope_root: audit_scope_root.into(),
            disclosure_budget_remaining: self.config.redaction_budget_units.saturating_sub(1),
            published_at_height: height,
        };
        self.counters.compliance_views_published += 1;
        self.current_height = self.current_height.max(height);
        self.publish_public_record("compliance_view", &view_id, view.public_record());
        self.compliance_views.insert(view_id.clone(), view);
        self.recompute_roots();
        Ok(view_id)
    }

    pub fn publish_operator_summary(
        &mut self,
        operator_commitment: impl Into<String>,
        reserve_ratio_bps: u64,
        height: u64,
    ) -> Result<String> {
        require(
            self.operator_summaries.len() < self.config.max_operator_summaries,
            "operator summary capacity full",
        )?;
        require(reserve_ratio_bps <= MAX_BPS, "reserve ratio exceeds bps")?;
        let nonce = self.counters.next_operator_summary_nonce;
        self.counters.next_operator_summary_nonce += 1;
        self.recompute_roots();
        let summary_id = id_from_record(
            "CLAIM-OPERATOR-SUMMARY-ID",
            &json!({ "nonce": nonce, "height": height }),
        );
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            operator_commitment: operator_commitment.into(),
            height,
            live_claim_count: self
                .claim_notes
                .values()
                .filter(|note| note.status.auctionable())
                .count() as u64,
            open_auction_count: self
                .auctions
                .values()
                .filter(|auction| auction.status.accepts_bids())
                .count() as u64,
            settlement_batch_count: self.settlement_batches.len() as u64,
            total_confidential_payout_micro_units: self.counters.confidential_payout_micro_units,
            total_fee_rebate_micro_units: self.counters.rebates_paid_micro_units,
            reserve_ratio_bps,
            fraud_guard_count: self.fraud_guards.len() as u64,
            public_roots: self.roots.clone(),
        };
        self.counters.operator_summaries_published += 1;
        self.current_height = self.current_height.max(height);
        self.publish_public_record("operator_summary", &summary_id, summary.public_record());
        self.operator_summaries.insert(summary_id.clone(), summary);
        self.recompute_roots();
        Ok(summary_id)
    }

    pub fn roots(&self) -> Roots {
        let mut clone = self.clone();
        clone.recompute_roots();
        clone.roots
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_tokenized_insurance_claim_auction_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "current_height": self.current_height,
            "monero_height": self.monero_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        json!({
            "state_root": value_root("STATE", &record),
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        value_root("STATE", &self.public_record_without_state_root())
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        require(
            self.claim_notes.len() <= self.config.max_claim_notes,
            "too many claim notes",
        )?;
        require(
            self.auctions.len() <= self.config.max_auctions,
            "too many auctions",
        )?;
        require(self.bids.len() <= self.config.max_bids, "too many bids")?;
        require(
            self.attestations.len() <= self.config.max_attestations,
            "too many attestations",
        )?;
        require(
            self.payout_tranches.len() <= self.config.max_tranches,
            "too many tranches",
        )?;
        require(
            self.fraud_guards.len() <= self.config.max_fraud_guards,
            "too many fraud guards",
        )?;
        require(
            self.settlement_batches.len() <= self.config.max_settlement_batches,
            "too many batches",
        )?;
        require(
            self.fee_rebates.len() <= self.config.max_rebates,
            "too many rebates",
        )?;
        for note in self.claim_notes.values() {
            note.validate(&self.config)?;
        }
        Ok(())
    }

    fn claim_has_supporting_attestation(&self, claim_id: &str) -> bool {
        self.attestations.values().any(|attestation| {
            attestation.claim_id == claim_id && attestation.supports_settlement(&self.config)
        })
    }

    fn claim_has_blocking_guard(&self, claim_id: &str) -> bool {
        self.fraud_guards
            .values()
            .any(|guard| guard.claim_id == claim_id && guard.blocks_settlement())
    }

    fn recompute_roots(&mut self) {
        self.roots = Roots {
            config_root: self.config.state_root(),
            counters_root: value_root("COUNTERS", &self.counters.public_record()),
            claim_note_root: map_root(
                "CLAIM-NOTES",
                &self.claim_notes,
                PrivateClaimNote::public_record,
            ),
            auction_root: map_root(
                "AUCTIONS",
                &self.auctions,
                SealedClaimAuction::public_record,
            ),
            bid_root: map_root("BIDS", &self.bids, SealedAuctionBid::public_record),
            attestation_root: map_root(
                "ATTESTATIONS",
                &self.attestations,
                AssessorAttestation::public_record,
            ),
            tranche_root: map_root(
                "PAYOUT-TRANCHES",
                &self.payout_tranches,
                PayoutTranche::public_record,
            ),
            fraud_guard_root: map_root(
                "FRAUD-GUARDS",
                &self.fraud_guards,
                ClaimFraudGuard::public_record,
            ),
            settlement_batch_root: map_root(
                "SETTLEMENT-BATCHES",
                &self.settlement_batches,
                SettlementBatch::public_record,
            ),
            fee_rebate_root: map_root("FEE-REBATES", &self.fee_rebates, FeeRebate::public_record),
            compliance_view_root: map_root(
                "COMPLIANCE-VIEWS",
                &self.compliance_views,
                RedactedComplianceView::public_record,
            ),
            operator_summary_root: map_root(
                "OPERATOR-SUMMARIES",
                &self.operator_summaries,
                OperatorSummary::public_record,
            ),
            nullifier_root: set_root("NULLIFIERS", &self.consumed_nullifiers),
            event_root: map_root("EVENTS", &self.events, Clone::clone),
            public_record_root: map_root("PUBLIC-RECORDS", &self.public_records, Clone::clone),
        };
    }

    fn publish_public_record(&mut self, record_kind: &str, subject_id: &str, payload: Value) {
        if self.public_records.len() >= self.config.max_events {
            return;
        }
        let record_id = public_record_id(record_kind, subject_id, &payload);
        self.public_records.insert(
            record_id,
            json!({
                "record_kind": record_kind,
                "subject_id": subject_id,
                "payload_root": value_root("PUBLIC-PAYLOAD", &payload),
                "payload": payload,
            }),
        );
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let mut state = State::devnet();
    let claim_id = state
        .submit_claim_note(
            ClaimKind::BridgeLoss,
            "policy:shielded-bridge-cover-alpha",
            "claimant:private-market-maker-alpha",
            "loss:commitment:bridge-outage-window-0",
            "payout:commitment:sealed-amount-0",
            "evidence:root:oracle-and-watchtower-bundle-0",
            "reserve:bucket:xmr-insurance-0",
            "nullifier:claim-note-demo-0",
            "refund:subaddress-commitment-0",
            8,
            DEVNET_HEIGHT + 1,
        )
        .expect("demo claim note");
    let attestation_id = state
        .post_assessor_attestation(
            claim_id.clone(),
            "assessor:pq-committee-0",
            AttestationVerdict::ClaimValid,
            7_200,
            8_600,
            "event-window:bridge-loss-0",
            "evidence-digest:bridge-watchtower-0",
            "policy-terms:bridge-cover-0",
            "pq-signature:assessor-committee-0",
            DEVNET_HEIGHT + 2,
        )
        .expect("demo attestation");
    let auction_id = state
        .open_sealed_auction(claim_id.clone(), 8_000, 12, DEVNET_HEIGHT + 3)
        .expect("demo auction");
    let bid_id = state
        .submit_sealed_bid(
            auction_id.clone(),
            "bidder:confidential-liquidity-solver-0",
            "sealed-bid:ml-kem-ciphertext-root-0",
            "liquidity:commitment:xmr-reserve-0",
            "price:commitment:discount-0",
            "fill:commitment:full-claim-0",
            "refund:commitment:solver-0",
            9,
            7,
            "pq-attestation:solver-0",
            DEVNET_HEIGHT + 4,
        )
        .expect("demo bid");
    let tranche_id = state
        .issue_payout_tranche(
            claim_id.clone(),
            auction_id.clone(),
            TrancheSeniority::Mezzanine,
            "tranche:commitment:claim-0",
            "payout:distribution:claim-0",
            "recipient:commitment:claimant-0",
            1_500,
            4_000,
            9,
            DEVNET_HEIGHT + 5,
        )
        .expect("demo tranche");
    state
        .post_fraud_guard(
            claim_id.clone(),
            FraudSignal::None,
            900,
            false,
            "sanctions:clear-root-0",
            "evidence-reuse:none-root-0",
            "assessor-conflict:none-root-0",
            "mitigation:standard-root-0",
            DEVNET_HEIGHT + 6,
        )
        .expect("demo fraud guard");
    let batch_id = state
        .commit_settlement_batch(
            vec![claim_id.clone()],
            vec![auction_id.clone()],
            vec![bid_id.clone()],
            vec![tranche_id.clone()],
            "payout-distribution:batch-0",
            "recursive-proof:batch-0",
            DEVNET_HEIGHT + 7,
        )
        .expect("demo settlement batch");
    state
        .issue_fee_rebate(bid_id, "beneficiary:solver-0", 10_000, 7, DEVNET_HEIGHT + 8)
        .expect("demo rebate");
    state
        .publish_compliance_view(
            batch_id,
            "settlement_batch",
            "regulator:viewkey-commitment-0",
            "redacted-claim:root-0",
            "jurisdiction:root-0",
            "sanctions:clear-root-0",
            "audit-scope:batch-only-root-0",
            DEVNET_HEIGHT + 9,
        )
        .expect("demo compliance view");
    state
        .publish_operator_summary(
            "operator:claim-auction-runtime-0",
            9_100,
            DEVNET_HEIGHT + 10,
        )
        .expect("demo operator summary");
    state.publish_public_record(
        "demo_attestation",
        &attestation_id,
        json!({ "attestation_id": attestation_id }),
    );
    state.recompute_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn hash_json(domain: &str, payload: &Value) -> String {
    value_root(domain, payload)
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn commitment(domain: &str, parts: &[HashPart<'_>]) -> String {
    let copied = parts.iter().map(hash_part_ref).collect::<Vec<_>>();
    domain_hash(domain, &copied, 32)
}

fn hash_part_ref<'a>(part: &HashPart<'a>) -> HashPart<'a> {
    match part {
        HashPart::Bytes(value) => HashPart::Bytes(value),
        HashPart::Str(value) => HashPart::Str(value),
        HashPart::U64(value) => HashPart::U64(*value),
        HashPart::Int(value) => HashPart::Int(*value),
        HashPart::Json(value) => HashPart::Json(value),
    }
}

fn value_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 20)
}

fn empty_root(domain: &str) -> String {
    domain_hash(&format!("{domain}:empty"), &[], 32)
}

fn public_record_id(record_kind: &str, subject_id: &str, payload: &Value) -> String {
    domain_hash(
        "CLAIM-AUCTION-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Json(payload),
        ],
        20,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": public_record(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn merkle_string_root(domain: &str, values: &[String]) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
