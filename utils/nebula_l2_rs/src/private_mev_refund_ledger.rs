use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateMevRefundLedgerResult<T> = Result<T, String>;

pub const PRIVATE_MEV_REFUND_LEDGER_PROTOCOL_VERSION: &str = "nebula-private-mev-refund-ledger-v1";
pub const PRIVATE_MEV_REFUND_LEDGER_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_MEV_REFUND_LEDGER_HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_MEV_REFUND_LEDGER_COMMITMENT_SCHEME: &str =
    "pedersen-shake256-refund-commitment-v1";
pub const PRIVATE_MEV_REFUND_LEDGER_NULLIFIER_SCHEME: &str =
    "shake256-anonymous-refund-nullifier-v1";
pub const PRIVATE_MEV_REFUND_LEDGER_SURPLUS_RECEIPT_SCHEME: &str = "zk-solver-surplus-receipt-v1";
pub const PRIVATE_MEV_REFUND_LEDGER_PQ_ATTESTATION_SCHEME: &str =
    "ml-dsa-87-slh-dsa-shake-refund-attestation-v1";
pub const PRIVATE_MEV_REFUND_LEDGER_REBATE_PROOF_SCHEME: &str = "zk-low-fee-rebate-range-proof-v1";
pub const PRIVATE_MEV_REFUND_LEDGER_MONERO_EXIT_SCHEME: &str =
    "monero-view-tag-private-exit-refund-v1";
pub const PRIVATE_MEV_REFUND_LEDGER_BATCH_AUCTION_SCHEME: &str =
    "threshold-encrypted-batch-auction-surplus-v1";
pub const PRIVATE_MEV_REFUND_LEDGER_DEVNET_REFUND_ASSET_ID: &str = "dxmr";
pub const PRIVATE_MEV_REFUND_LEDGER_DEVNET_OPERATOR_LABEL: &str =
    "devnet-private-mev-refund-operator";
pub const PRIVATE_MEV_REFUND_LEDGER_DEVNET_GOVERNANCE_KEY: &str =
    "nebula-devnet-private-mev-refund-governance";
pub const PRIVATE_MEV_REFUND_LEDGER_DEFAULT_EPOCH_BLOCKS: u64 = 120;
pub const PRIVATE_MEV_REFUND_LEDGER_DEFAULT_CLAIM_TTL_BLOCKS: u64 = 3_600;
pub const PRIVATE_MEV_REFUND_LEDGER_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const PRIVATE_MEV_REFUND_LEDGER_DEFAULT_REBATE_SETTLEMENT_BLOCKS: u64 = 180;
pub const PRIVATE_MEV_REFUND_LEDGER_DEFAULT_MAX_DISCLOSURE_BPS: u64 = 1_500;
pub const PRIVATE_MEV_REFUND_LEDGER_DEFAULT_MIN_REFUND_BPS: u64 = 7_000;
pub const PRIVATE_MEV_REFUND_LEDGER_DEFAULT_SOLVER_SHARE_BPS: u64 = 1_500;
pub const PRIVATE_MEV_REFUND_LEDGER_DEFAULT_PROTOCOL_SHARE_BPS: u64 = 1_000;
pub const PRIVATE_MEV_REFUND_LEDGER_DEFAULT_WATCHER_SHARE_BPS: u64 = 500;
pub const PRIVATE_MEV_REFUND_LEDGER_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_MEV_REFUND_LEDGER_DEFAULT_LOW_FEE_CAP_MICRO_UNITS: u64 = 1_200;
pub const PRIVATE_MEV_REFUND_LEDGER_DEFAULT_MAX_CLAIMS_PER_BATCH: u64 = 2_048;
pub const PRIVATE_MEV_REFUND_LEDGER_DEFAULT_MAX_RECEIPTS_PER_BATCH: u64 = 4_096;
pub const PRIVATE_MEV_REFUND_LEDGER_MAX_BPS: u64 = 10_000;
pub const PRIVATE_MEV_REFUND_LEDGER_MAX_LANES: usize = 64;
pub const PRIVATE_MEV_REFUND_LEDGER_MAX_COMMITMENTS: usize = 32_768;
pub const PRIVATE_MEV_REFUND_LEDGER_MAX_RECEIPTS: usize = 32_768;
pub const PRIVATE_MEV_REFUND_LEDGER_MAX_NULLIFIERS: usize = 32_768;
pub const PRIVATE_MEV_REFUND_LEDGER_MAX_ATTESTATIONS: usize = 32_768;
pub const PRIVATE_MEV_REFUND_LEDGER_MAX_REBATES: usize = 32_768;
pub const PRIVATE_MEV_REFUND_LEDGER_MAX_CHALLENGES: usize = 8_192;
pub const PRIVATE_MEV_REFUND_LEDGER_MAX_PUBLIC_RECORDS: usize = 196_608;

const STATE_STATUS_ACTIVE: &str = "active";
const STATE_STATUS_CHALLENGED: &str = "challenged";
const STATE_STATUS_HALTED: &str = "halted";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefundLane {
    PrivateSwap,
    MoneroExit,
    PrivateLiquidation,
    BatchAuction,
    ContractCall,
    TokenMint,
    TokenRedeem,
    LowFeeSwap,
    LowFeeTransfer,
    EmergencyExit,
}

impl RefundLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateSwap => "private_swap",
            Self::MoneroExit => "monero_exit",
            Self::PrivateLiquidation => "private_liquidation",
            Self::BatchAuction => "batch_auction",
            Self::ContractCall => "contract_call",
            Self::TokenMint => "token_mint",
            Self::TokenRedeem => "token_redeem",
            Self::LowFeeSwap => "low_fee_swap",
            Self::LowFeeTransfer => "low_fee_transfer",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn private_defi(self) -> bool {
        matches!(
            self,
            Self::PrivateSwap
                | Self::PrivateLiquidation
                | Self::BatchAuction
                | Self::ContractCall
                | Self::TokenMint
                | Self::TokenRedeem
        )
    }

    pub fn monero_exit(self) -> bool {
        matches!(self, Self::MoneroExit | Self::EmergencyExit)
    }

    pub fn low_fee(self) -> bool {
        matches!(
            self,
            Self::LowFeeSwap | Self::LowFeeTransfer | Self::EmergencyExit
        )
    }

    pub fn default_priority_weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 100,
            Self::MoneroExit => 95,
            Self::PrivateLiquidation => 90,
            Self::LowFeeTransfer => 84,
            Self::LowFeeSwap => 80,
            Self::BatchAuction => 76,
            Self::PrivateSwap => 72,
            Self::ContractCall => 66,
            Self::TokenRedeem => 62,
            Self::TokenMint => 58,
        }
    }

    pub fn default_fee_cap_micro_units(self) -> u64 {
        match self {
            Self::EmergencyExit => 250,
            Self::LowFeeTransfer => 500,
            Self::MoneroExit => 700,
            Self::LowFeeSwap => 1_000,
            Self::PrivateSwap => 1_200,
            Self::BatchAuction => 1_400,
            Self::PrivateLiquidation => 1_700,
            Self::ContractCall => 1_800,
            Self::TokenRedeem => 900,
            Self::TokenMint => 900,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefundCommitmentStatus {
    Open,
    Matched,
    Claimable,
    Claimed,
    Expired,
    Challenged,
    Slashed,
}

impl RefundCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Matched => "matched",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }

    pub fn claimable(self) -> bool {
        matches!(self, Self::Matched | Self::Claimable)
    }

    pub fn final_status(self) -> bool {
        matches!(self, Self::Claimed | Self::Expired | Self::Slashed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurplusReceiptStatus {
    Quoted,
    Settled,
    PartiallyRefunded,
    FullyRefunded,
    Rejected,
    Challenged,
}

impl SurplusReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Settled => "settled",
            Self::PartiallyRefunded => "partially_refunded",
            Self::FullyRefunded => "fully_refunded",
            Self::Rejected => "rejected",
            Self::Challenged => "challenged",
        }
    }

    pub fn settled(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::PartiallyRefunded | Self::FullyRefunded
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Pending,
    Accepted,
    Rejected,
    Settled,
    Challenged,
    Expired,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }

    pub fn final_status(self) -> bool {
        matches!(self, Self::Rejected | Self::Settled | Self::Expired)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationRole {
    Solver,
    Sequencer,
    Watcher,
    Prover,
    BridgeWatchtower,
    Governance,
}

impl PqAttestationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Solver => "solver",
            Self::Sequencer => "sequencer",
            Self::Watcher => "watcher",
            Self::Prover => "prover",
            Self::BridgeWatchtower => "bridge_watchtower",
            Self::Governance => "governance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateLaneStatus {
    Active,
    Reserved,
    Exhausted,
    Paused,
    Expired,
    Revoked,
}

impl RebateLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::Active | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    MissingRefund,
    SolverOvercharge,
    InvalidNullifier,
    DuplicateClaim,
    InvalidPqAttestation,
    MoneroExitMismatch,
    BatchAuctionClearingError,
    LowFeeLaneAbuse,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingRefund => "missing_refund",
            Self::SolverOvercharge => "solver_overcharge",
            Self::InvalidNullifier => "invalid_nullifier",
            Self::DuplicateClaim => "duplicate_claim",
            Self::InvalidPqAttestation => "invalid_pq_attestation",
            Self::MoneroExitMismatch => "monero_exit_mismatch",
            Self::BatchAuctionClearingError => "batch_auction_clearing_error",
            Self::LowFeeLaneAbuse => "low_fee_lane_abuse",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    UnderReview,
    Proven,
    Rejected,
    Remediated,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::UnderReview => "under_review",
            Self::Proven => "proven",
            Self::Rejected => "rejected",
            Self::Remediated => "remediated",
            Self::Expired => "expired",
        }
    }

    pub fn final_status(self) -> bool {
        matches!(
            self,
            Self::Proven | Self::Rejected | Self::Remediated | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosurePolicy {
    None,
    LaneOnly,
    AggregateOnly,
    WatcherView,
    RegulatorView,
}

impl DisclosurePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::LaneOnly => "lane_only",
            Self::AggregateOnly => "aggregate_only",
            Self::WatcherView => "watcher_view",
            Self::RegulatorView => "regulator_view",
        }
    }

    pub fn public_solver_allowed(self) -> bool {
        matches!(self, Self::WatcherView | Self::RegulatorView)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMevRefundLedgerConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub refund_asset_id: String,
    pub operator_label: String,
    pub governance_key: String,
    pub epoch_blocks: u64,
    pub claim_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub rebate_settlement_blocks: u64,
    pub max_public_disclosure_bps: u64,
    pub min_refund_bps: u64,
    pub solver_share_bps: u64,
    pub protocol_share_bps: u64,
    pub watcher_share_bps: u64,
    pub min_pq_security_bits: u16,
    pub low_fee_cap_micro_units: u64,
    pub max_claims_per_batch: u64,
    pub max_receipts_per_batch: u64,
    pub commitment_scheme: String,
    pub nullifier_scheme: String,
    pub surplus_receipt_scheme: String,
    pub pq_attestation_scheme: String,
    pub rebate_proof_scheme: String,
    pub monero_exit_scheme: String,
    pub batch_auction_scheme: String,
    pub hash_suite: String,
}

impl PrivateMevRefundLedgerConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_MEV_REFUND_LEDGER_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_MEV_REFUND_LEDGER_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            refund_asset_id: PRIVATE_MEV_REFUND_LEDGER_DEVNET_REFUND_ASSET_ID.to_string(),
            operator_label: PRIVATE_MEV_REFUND_LEDGER_DEVNET_OPERATOR_LABEL.to_string(),
            governance_key: PRIVATE_MEV_REFUND_LEDGER_DEVNET_GOVERNANCE_KEY.to_string(),
            epoch_blocks: PRIVATE_MEV_REFUND_LEDGER_DEFAULT_EPOCH_BLOCKS,
            claim_ttl_blocks: PRIVATE_MEV_REFUND_LEDGER_DEFAULT_CLAIM_TTL_BLOCKS,
            challenge_window_blocks: PRIVATE_MEV_REFUND_LEDGER_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            rebate_settlement_blocks: PRIVATE_MEV_REFUND_LEDGER_DEFAULT_REBATE_SETTLEMENT_BLOCKS,
            max_public_disclosure_bps: PRIVATE_MEV_REFUND_LEDGER_DEFAULT_MAX_DISCLOSURE_BPS,
            min_refund_bps: PRIVATE_MEV_REFUND_LEDGER_DEFAULT_MIN_REFUND_BPS,
            solver_share_bps: PRIVATE_MEV_REFUND_LEDGER_DEFAULT_SOLVER_SHARE_BPS,
            protocol_share_bps: PRIVATE_MEV_REFUND_LEDGER_DEFAULT_PROTOCOL_SHARE_BPS,
            watcher_share_bps: PRIVATE_MEV_REFUND_LEDGER_DEFAULT_WATCHER_SHARE_BPS,
            min_pq_security_bits: PRIVATE_MEV_REFUND_LEDGER_DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_cap_micro_units: PRIVATE_MEV_REFUND_LEDGER_DEFAULT_LOW_FEE_CAP_MICRO_UNITS,
            max_claims_per_batch: PRIVATE_MEV_REFUND_LEDGER_DEFAULT_MAX_CLAIMS_PER_BATCH,
            max_receipts_per_batch: PRIVATE_MEV_REFUND_LEDGER_DEFAULT_MAX_RECEIPTS_PER_BATCH,
            commitment_scheme: PRIVATE_MEV_REFUND_LEDGER_COMMITMENT_SCHEME.to_string(),
            nullifier_scheme: PRIVATE_MEV_REFUND_LEDGER_NULLIFIER_SCHEME.to_string(),
            surplus_receipt_scheme: PRIVATE_MEV_REFUND_LEDGER_SURPLUS_RECEIPT_SCHEME.to_string(),
            pq_attestation_scheme: PRIVATE_MEV_REFUND_LEDGER_PQ_ATTESTATION_SCHEME.to_string(),
            rebate_proof_scheme: PRIVATE_MEV_REFUND_LEDGER_REBATE_PROOF_SCHEME.to_string(),
            monero_exit_scheme: PRIVATE_MEV_REFUND_LEDGER_MONERO_EXIT_SCHEME.to_string(),
            batch_auction_scheme: PRIVATE_MEV_REFUND_LEDGER_BATCH_AUCTION_SCHEME.to_string(),
            hash_suite: PRIVATE_MEV_REFUND_LEDGER_HASH_SUITE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "refund_asset_id": self.refund_asset_id,
            "operator_label": self.operator_label,
            "governance_key": self.governance_key,
            "epoch_blocks": self.epoch_blocks,
            "claim_ttl_blocks": self.claim_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "rebate_settlement_blocks": self.rebate_settlement_blocks,
            "max_public_disclosure_bps": self.max_public_disclosure_bps,
            "min_refund_bps": self.min_refund_bps,
            "solver_share_bps": self.solver_share_bps,
            "protocol_share_bps": self.protocol_share_bps,
            "watcher_share_bps": self.watcher_share_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "low_fee_cap_micro_units": self.low_fee_cap_micro_units,
            "max_claims_per_batch": self.max_claims_per_batch,
            "max_receipts_per_batch": self.max_receipts_per_batch,
            "commitment_scheme": self.commitment_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "surplus_receipt_scheme": self.surplus_receipt_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "rebate_proof_scheme": self.rebate_proof_scheme,
            "monero_exit_scheme": self.monero_exit_scheme,
            "batch_auction_scheme": self.batch_auction_scheme,
            "hash_suite": self.hash_suite,
        })
    }

    pub fn state_root(&self) -> String {
        pmrl_payload_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateMevRefundLedgerResult<String> {
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_nonempty("refund_asset_id", &self.refund_asset_id)?;
        ensure_nonempty("operator_label", &self.operator_label)?;
        ensure_nonempty("governance_key", &self.governance_key)?;
        ensure_positive("epoch_blocks", self.epoch_blocks)?;
        ensure_positive("claim_ttl_blocks", self.claim_ttl_blocks)?;
        ensure_positive("challenge_window_blocks", self.challenge_window_blocks)?;
        ensure_positive("rebate_settlement_blocks", self.rebate_settlement_blocks)?;
        ensure_bps("max_public_disclosure_bps", self.max_public_disclosure_bps)?;
        ensure_bps("min_refund_bps", self.min_refund_bps)?;
        ensure_bps("solver_share_bps", self.solver_share_bps)?;
        ensure_bps("protocol_share_bps", self.protocol_share_bps)?;
        ensure_bps("watcher_share_bps", self.watcher_share_bps)?;
        if self.min_refund_bps + self.solver_share_bps + self.protocol_share_bps
            > PRIVATE_MEV_REFUND_LEDGER_MAX_BPS
        {
            return Err("refund, solver, and protocol shares exceed 100%".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("min_pq_security_bits must be at least 128".to_string());
        }
        ensure_nonempty("commitment_scheme", &self.commitment_scheme)?;
        ensure_nonempty("nullifier_scheme", &self.nullifier_scheme)?;
        ensure_nonempty("surplus_receipt_scheme", &self.surplus_receipt_scheme)?;
        ensure_nonempty("pq_attestation_scheme", &self.pq_attestation_scheme)?;
        ensure_nonempty("rebate_proof_scheme", &self.rebate_proof_scheme)?;
        ensure_nonempty("hash_suite", &self.hash_suite)?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebateLane {
    pub lane_id: String,
    pub lane: RefundLane,
    pub status: RebateLaneStatus,
    pub sponsor_commitment: String,
    pub reserve_commitment: String,
    pub max_fee_micro_units: u64,
    pub rebate_bps: u64,
    pub priority_weight: u64,
    pub start_height: u64,
    pub expiry_height: u64,
    pub disclosure_policy: DisclosurePolicy,
}

impl LowFeeRebateLane {
    pub fn devnet(lane: RefundLane, index: u64, current_height: u64) -> Self {
        let lane_id = label_hash("REBATE-LANE-ID", &[lane.as_str(), &index.to_string()]);
        Self {
            lane_id,
            lane,
            status: RebateLaneStatus::Active,
            sponsor_commitment: label_hash("REBATE-SPONSOR", &[lane.as_str(), "sponsor"]),
            reserve_commitment: label_hash("REBATE-RESERVE", &[lane.as_str(), "reserve"]),
            max_fee_micro_units: lane.default_fee_cap_micro_units(),
            rebate_bps: if lane.low_fee() { 8_000 } else { 3_000 },
            priority_weight: lane.default_priority_weight(),
            start_height: current_height,
            expiry_height: current_height + PRIVATE_MEV_REFUND_LEDGER_DEFAULT_CLAIM_TTL_BLOCKS,
            disclosure_policy: if lane.low_fee() {
                DisclosurePolicy::LaneOnly
            } else {
                DisclosurePolicy::AggregateOnly
            },
        }
    }

    pub fn set_height(&mut self, height: u64) {
        self.start_height = height;
        self.expiry_height = height + PRIVATE_MEV_REFUND_LEDGER_DEFAULT_CLAIM_TTL_BLOCKS;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "reserve_commitment": self.reserve_commitment,
            "max_fee_micro_units": self.max_fee_micro_units,
            "rebate_bps": self.rebate_bps,
            "priority_weight": self.priority_weight,
            "start_height": self.start_height,
            "expiry_height": self.expiry_height,
            "disclosure_policy": self.disclosure_policy.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        pmrl_payload_root("LOW-FEE-REBATE-LANE", &self.public_record())
    }

    pub fn validate(&self) -> PrivateMevRefundLedgerResult<String> {
        ensure_nonempty("lane_id", &self.lane_id)?;
        ensure_nonempty("sponsor_commitment", &self.sponsor_commitment)?;
        ensure_nonempty("reserve_commitment", &self.reserve_commitment)?;
        ensure_positive("max_fee_micro_units", self.max_fee_micro_units)?;
        ensure_bps("rebate_bps", self.rebate_bps)?;
        ensure_positive("priority_weight", self.priority_weight)?;
        ensure_ordered_heights("rebate_lane", self.start_height, self.expiry_height)?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefundCommitment {
    pub commitment_id: String,
    pub lane: RefundLane,
    pub status: RefundCommitmentStatus,
    pub batch_id: String,
    pub encrypted_claimant_hint: String,
    pub refund_commitment: String,
    pub surplus_commitment: String,
    pub min_refund_commitment: String,
    pub asset_id: String,
    pub created_height: u64,
    pub claim_deadline_height: u64,
    pub mev_source_commitment: String,
    pub solver_receipt_id: Option<String>,
    pub low_fee_lane_id: Option<String>,
    pub pq_attestation_id: Option<String>,
}

impl RefundCommitment {
    pub fn devnet(lane: RefundLane, index: u64, height: u64) -> Self {
        let seed = format!("{}:{index}", lane.as_str());
        Self {
            commitment_id: label_hash("REFUND-COMMITMENT-ID", &[&seed]),
            lane,
            status: RefundCommitmentStatus::Claimable,
            batch_id: label_hash("REFUND-BATCH", &[lane.as_str(), "devnet"]),
            encrypted_claimant_hint: label_hash("CLAIMANT-HINT", &[&seed]),
            refund_commitment: label_hash("REFUND-COMMITMENT", &[&seed]),
            surplus_commitment: label_hash("SURPLUS-COMMITMENT", &[&seed]),
            min_refund_commitment: label_hash("MIN-REFUND-COMMITMENT", &[&seed]),
            asset_id: PRIVATE_MEV_REFUND_LEDGER_DEVNET_REFUND_ASSET_ID.to_string(),
            created_height: height,
            claim_deadline_height: height + PRIVATE_MEV_REFUND_LEDGER_DEFAULT_CLAIM_TTL_BLOCKS,
            mev_source_commitment: label_hash("MEV-SOURCE", &[&seed]),
            solver_receipt_id: Some(label_hash("SURPLUS-RECEIPT-ID", &[&seed])),
            low_fee_lane_id: if lane.low_fee() {
                Some(label_hash("REBATE-LANE-ID", &[lane.as_str(), "0"]))
            } else {
                None
            },
            pq_attestation_id: Some(label_hash("PQ-ATTESTATION-ID", &[&seed])),
        }
    }

    pub fn set_height(&mut self, height: u64) {
        self.created_height = height;
        self.claim_deadline_height = height + PRIVATE_MEV_REFUND_LEDGER_DEFAULT_CLAIM_TTL_BLOCKS;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "batch_id": self.batch_id,
            "encrypted_claimant_hint": self.encrypted_claimant_hint,
            "refund_commitment": self.refund_commitment,
            "surplus_commitment": self.surplus_commitment,
            "min_refund_commitment": self.min_refund_commitment,
            "asset_id": self.asset_id,
            "created_height": self.created_height,
            "claim_deadline_height": self.claim_deadline_height,
            "mev_source_commitment": self.mev_source_commitment,
            "solver_receipt_id": self.solver_receipt_id,
            "low_fee_lane_id": self.low_fee_lane_id,
            "pq_attestation_id": self.pq_attestation_id,
        })
    }

    pub fn state_root(&self) -> String {
        pmrl_payload_root("REFUND-COMMITMENT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateMevRefundLedgerResult<String> {
        ensure_nonempty("commitment_id", &self.commitment_id)?;
        ensure_nonempty("batch_id", &self.batch_id)?;
        ensure_nonempty("encrypted_claimant_hint", &self.encrypted_claimant_hint)?;
        ensure_nonempty("refund_commitment", &self.refund_commitment)?;
        ensure_nonempty("surplus_commitment", &self.surplus_commitment)?;
        ensure_nonempty("min_refund_commitment", &self.min_refund_commitment)?;
        ensure_nonempty("asset_id", &self.asset_id)?;
        ensure_ordered_heights(
            "refund_commitment",
            self.created_height,
            self.claim_deadline_height,
        )?;
        ensure_nonempty("mev_source_commitment", &self.mev_source_commitment)?;
        if self.status.claimable() && self.solver_receipt_id.is_none() {
            return Err(format!(
                "claimable commitment {} missing solver receipt",
                self.commitment_id
            ));
        }
        if self.lane.low_fee() && self.low_fee_lane_id.is_none() {
            return Err(format!(
                "low fee commitment {} missing low fee lane",
                self.commitment_id
            ));
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverSurplusReceipt {
    pub receipt_id: String,
    pub solver_commitment: String,
    pub lane: RefundLane,
    pub status: SurplusReceiptStatus,
    pub batch_id: String,
    pub clearing_price_commitment: String,
    pub user_limit_commitment: String,
    pub surplus_commitment: String,
    pub refund_floor_commitment: String,
    pub solver_share_commitment: String,
    pub protocol_share_commitment: String,
    pub encrypted_route_digest: String,
    pub created_height: u64,
    pub settled_height: Option<u64>,
    pub pq_attestation_id: String,
}

impl SolverSurplusReceipt {
    pub fn devnet(lane: RefundLane, index: u64, height: u64) -> Self {
        let seed = format!("{}:{index}", lane.as_str());
        Self {
            receipt_id: label_hash("SURPLUS-RECEIPT-ID", &[&seed]),
            solver_commitment: label_hash("SOLVER-COMMITMENT", &[&seed]),
            lane,
            status: SurplusReceiptStatus::Settled,
            batch_id: label_hash("REFUND-BATCH", &[lane.as_str(), "devnet"]),
            clearing_price_commitment: label_hash("CLEARING-PRICE", &[&seed]),
            user_limit_commitment: label_hash("USER-LIMIT", &[&seed]),
            surplus_commitment: label_hash("SURPLUS-COMMITMENT", &[&seed]),
            refund_floor_commitment: label_hash("REFUND-FLOOR", &[&seed]),
            solver_share_commitment: label_hash("SOLVER-SHARE", &[&seed]),
            protocol_share_commitment: label_hash("PROTOCOL-SHARE", &[&seed]),
            encrypted_route_digest: label_hash("ENCRYPTED-ROUTE", &[&seed]),
            created_height: height,
            settled_height: Some(height + 1),
            pq_attestation_id: label_hash("PQ-ATTESTATION-ID", &[&seed]),
        }
    }

    pub fn set_height(&mut self, height: u64) {
        self.created_height = height;
        self.settled_height = Some(height + 1);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "solver_commitment": self.solver_commitment,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "batch_id": self.batch_id,
            "clearing_price_commitment": self.clearing_price_commitment,
            "user_limit_commitment": self.user_limit_commitment,
            "surplus_commitment": self.surplus_commitment,
            "refund_floor_commitment": self.refund_floor_commitment,
            "solver_share_commitment": self.solver_share_commitment,
            "protocol_share_commitment": self.protocol_share_commitment,
            "encrypted_route_digest": self.encrypted_route_digest,
            "created_height": self.created_height,
            "settled_height": self.settled_height,
            "pq_attestation_id": self.pq_attestation_id,
        })
    }

    pub fn state_root(&self) -> String {
        pmrl_payload_root("SOLVER-SURPLUS-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateMevRefundLedgerResult<String> {
        ensure_nonempty("receipt_id", &self.receipt_id)?;
        ensure_nonempty("solver_commitment", &self.solver_commitment)?;
        ensure_nonempty("batch_id", &self.batch_id)?;
        ensure_nonempty("clearing_price_commitment", &self.clearing_price_commitment)?;
        ensure_nonempty("user_limit_commitment", &self.user_limit_commitment)?;
        ensure_nonempty("surplus_commitment", &self.surplus_commitment)?;
        ensure_nonempty("refund_floor_commitment", &self.refund_floor_commitment)?;
        ensure_nonempty("solver_share_commitment", &self.solver_share_commitment)?;
        ensure_nonempty("protocol_share_commitment", &self.protocol_share_commitment)?;
        ensure_nonempty("encrypted_route_digest", &self.encrypted_route_digest)?;
        ensure_nonempty("pq_attestation_id", &self.pq_attestation_id)?;
        if self.status.settled() && self.settled_height.is_none() {
            return Err(format!(
                "settled receipt {} missing height",
                self.receipt_id
            ));
        }
        if let Some(settled_height) = self.settled_height {
            if settled_height < self.created_height {
                return Err(format!(
                    "receipt {} settled before creation",
                    self.receipt_id
                ));
            }
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnonymousClaimNullifier {
    pub nullifier_id: String,
    pub commitment_id: String,
    pub lane: RefundLane,
    pub status: ClaimStatus,
    pub nullifier: String,
    pub claim_commitment: String,
    pub encrypted_payout_address: String,
    pub membership_root: String,
    pub proof_digest: String,
    pub submitted_height: u64,
    pub settled_height: Option<u64>,
    pub rebate_lane_id: Option<String>,
}

impl AnonymousClaimNullifier {
    pub fn devnet(lane: RefundLane, index: u64, height: u64) -> Self {
        let seed = format!("{}:{index}", lane.as_str());
        Self {
            nullifier_id: label_hash("NULLIFIER-ID", &[&seed]),
            commitment_id: label_hash("REFUND-COMMITMENT-ID", &[&seed]),
            lane,
            status: ClaimStatus::Accepted,
            nullifier: label_hash("ANON-NULLIFIER", &[&seed]),
            claim_commitment: label_hash("CLAIM-COMMITMENT", &[&seed]),
            encrypted_payout_address: label_hash("ENCRYPTED-PAYOUT", &[&seed]),
            membership_root: label_hash("MEMBERSHIP-ROOT", &[lane.as_str(), "devnet"]),
            proof_digest: label_hash("CLAIM-PROOF", &[&seed]),
            submitted_height: height + 2,
            settled_height: Some(height + 3),
            rebate_lane_id: if lane.low_fee() {
                Some(label_hash("REBATE-LANE-ID", &[lane.as_str(), "0"]))
            } else {
                None
            },
        }
    }

    pub fn set_height(&mut self, height: u64) {
        self.submitted_height = height + 2;
        self.settled_height = Some(height + 3);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "nullifier_id": self.nullifier_id,
            "commitment_id": self.commitment_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "nullifier": self.nullifier,
            "claim_commitment": self.claim_commitment,
            "encrypted_payout_address": self.encrypted_payout_address,
            "membership_root": self.membership_root,
            "proof_digest": self.proof_digest,
            "submitted_height": self.submitted_height,
            "settled_height": self.settled_height,
            "rebate_lane_id": self.rebate_lane_id,
        })
    }

    pub fn state_root(&self) -> String {
        pmrl_payload_root("ANONYMOUS-CLAIM-NULLIFIER", &self.public_record())
    }

    pub fn validate(&self) -> PrivateMevRefundLedgerResult<String> {
        ensure_nonempty("nullifier_id", &self.nullifier_id)?;
        ensure_nonempty("commitment_id", &self.commitment_id)?;
        ensure_nonempty("nullifier", &self.nullifier)?;
        ensure_nonempty("claim_commitment", &self.claim_commitment)?;
        ensure_nonempty("encrypted_payout_address", &self.encrypted_payout_address)?;
        ensure_nonempty("membership_root", &self.membership_root)?;
        ensure_nonempty("proof_digest", &self.proof_digest)?;
        if self.status == ClaimStatus::Settled && self.settled_height.is_none() {
            return Err(format!(
                "settled claim {} missing height",
                self.nullifier_id
            ));
        }
        if let Some(settled_height) = self.settled_height {
            if settled_height < self.submitted_height {
                return Err(format!(
                    "claim {} settled before submission",
                    self.nullifier_id
                ));
            }
        }
        if self.lane.low_fee() && self.rebate_lane_id.is_none() {
            return Err(format!(
                "low fee claim {} missing rebate lane",
                self.nullifier_id
            ));
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRefundAttestation {
    pub attestation_id: String,
    pub role: PqAttestationRole,
    pub subject_id: String,
    pub epoch: u64,
    pub height: u64,
    pub public_key_commitment: String,
    pub signature_digest: String,
    pub transcript_digest: String,
    pub security_bits: u16,
    pub backup_signature_digest: Option<String>,
    pub valid_until_height: u64,
}

impl PqRefundAttestation {
    pub fn devnet(role: PqAttestationRole, subject_id: &str, epoch: u64, height: u64) -> Self {
        Self {
            attestation_id: label_hash("PQ-ATTESTATION-ID", &[role.as_str(), subject_id]),
            role,
            subject_id: subject_id.to_string(),
            epoch,
            height,
            public_key_commitment: label_hash("PQ-PUBLIC-KEY", &[role.as_str(), subject_id]),
            signature_digest: label_hash("PQ-SIGNATURE", &[role.as_str(), subject_id]),
            transcript_digest: label_hash("PQ-TRANSCRIPT", &[role.as_str(), subject_id]),
            security_bits: PRIVATE_MEV_REFUND_LEDGER_DEFAULT_MIN_PQ_SECURITY_BITS,
            backup_signature_digest: Some(label_hash(
                "PQ-BACKUP-SIGNATURE",
                &[role.as_str(), subject_id],
            )),
            valid_until_height: height + PRIVATE_MEV_REFUND_LEDGER_DEFAULT_CLAIM_TTL_BLOCKS,
        }
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        self.valid_until_height = height + PRIVATE_MEV_REFUND_LEDGER_DEFAULT_CLAIM_TTL_BLOCKS;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "role": self.role.as_str(),
            "subject_id": self.subject_id,
            "epoch": self.epoch,
            "height": self.height,
            "public_key_commitment": self.public_key_commitment,
            "signature_digest": self.signature_digest,
            "transcript_digest": self.transcript_digest,
            "security_bits": self.security_bits,
            "backup_signature_digest": self.backup_signature_digest,
            "valid_until_height": self.valid_until_height,
        })
    }

    pub fn state_root(&self) -> String {
        pmrl_payload_root("PQ-REFUND-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> PrivateMevRefundLedgerResult<String> {
        ensure_nonempty("attestation_id", &self.attestation_id)?;
        ensure_nonempty("subject_id", &self.subject_id)?;
        ensure_nonempty("public_key_commitment", &self.public_key_commitment)?;
        ensure_nonempty("signature_digest", &self.signature_digest)?;
        ensure_nonempty("transcript_digest", &self.transcript_digest)?;
        if self.security_bits < 128 {
            return Err(format!(
                "attestation {} below minimum security bits",
                self.attestation_id
            ));
        }
        ensure_ordered_heights("pq_attestation", self.height, self.valid_until_height)?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebateSettlement {
    pub rebate_id: String,
    pub lane_id: String,
    pub nullifier_id: String,
    pub status: ClaimStatus,
    pub fee_paid_commitment: String,
    pub fee_cap_commitment: String,
    pub rebate_commitment: String,
    pub proof_digest: String,
    pub settled_height: u64,
    pub sponsor_debit_commitment: String,
}

impl LowFeeRebateSettlement {
    pub fn devnet(lane: RefundLane, index: u64, height: u64) -> Self {
        let seed = format!("{}:{index}", lane.as_str());
        Self {
            rebate_id: label_hash("LOW-FEE-REBATE-ID", &[&seed]),
            lane_id: label_hash("REBATE-LANE-ID", &[lane.as_str(), "0"]),
            nullifier_id: label_hash("NULLIFIER-ID", &[&seed]),
            status: ClaimStatus::Settled,
            fee_paid_commitment: label_hash("FEE-PAID", &[&seed]),
            fee_cap_commitment: label_hash("FEE-CAP", &[&seed]),
            rebate_commitment: label_hash("REBATE-COMMITMENT", &[&seed]),
            proof_digest: label_hash("REBATE-PROOF", &[&seed]),
            settled_height: height + 4,
            sponsor_debit_commitment: label_hash("SPONSOR-DEBIT", &[&seed]),
        }
    }

    pub fn set_height(&mut self, height: u64) {
        self.settled_height = height + 4;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "lane_id": self.lane_id,
            "nullifier_id": self.nullifier_id,
            "status": self.status.as_str(),
            "fee_paid_commitment": self.fee_paid_commitment,
            "fee_cap_commitment": self.fee_cap_commitment,
            "rebate_commitment": self.rebate_commitment,
            "proof_digest": self.proof_digest,
            "settled_height": self.settled_height,
            "sponsor_debit_commitment": self.sponsor_debit_commitment,
        })
    }

    pub fn state_root(&self) -> String {
        pmrl_payload_root("LOW-FEE-REBATE-SETTLEMENT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateMevRefundLedgerResult<String> {
        ensure_nonempty("rebate_id", &self.rebate_id)?;
        ensure_nonempty("lane_id", &self.lane_id)?;
        ensure_nonempty("nullifier_id", &self.nullifier_id)?;
        ensure_nonempty("fee_paid_commitment", &self.fee_paid_commitment)?;
        ensure_nonempty("fee_cap_commitment", &self.fee_cap_commitment)?;
        ensure_nonempty("rebate_commitment", &self.rebate_commitment)?;
        ensure_nonempty("proof_digest", &self.proof_digest)?;
        ensure_nonempty("sponsor_debit_commitment", &self.sponsor_debit_commitment)?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefundChallengeRecord {
    pub challenge_id: String,
    pub kind: ChallengeKind,
    pub status: ChallengeStatus,
    pub target_id: String,
    pub challenger_nullifier: String,
    pub evidence_root: String,
    pub bond_commitment: String,
    pub remediation_commitment: Option<String>,
    pub opened_height: u64,
    pub deadline_height: u64,
    pub resolved_height: Option<u64>,
}

impl RefundChallengeRecord {
    pub fn devnet(kind: ChallengeKind, target_id: &str, index: u64, height: u64) -> Self {
        let seed = format!("{}:{target_id}:{index}", kind.as_str());
        Self {
            challenge_id: label_hash("REFUND-CHALLENGE-ID", &[&seed]),
            kind,
            status: ChallengeStatus::Open,
            target_id: target_id.to_string(),
            challenger_nullifier: label_hash("CHALLENGER-NULLIFIER", &[&seed]),
            evidence_root: label_hash("CHALLENGE-EVIDENCE", &[&seed]),
            bond_commitment: label_hash("CHALLENGE-BOND", &[&seed]),
            remediation_commitment: None,
            opened_height: height + 5,
            deadline_height: height + 5 + PRIVATE_MEV_REFUND_LEDGER_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            resolved_height: None,
        }
    }

    pub fn set_height(&mut self, height: u64) {
        self.opened_height = height + 5;
        self.deadline_height =
            height + 5 + PRIVATE_MEV_REFUND_LEDGER_DEFAULT_CHALLENGE_WINDOW_BLOCKS;
        self.resolved_height = self.resolved_height.map(|_| height + 6);
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "target_id": self.target_id,
            "challenger_nullifier": self.challenger_nullifier,
            "evidence_root": self.evidence_root,
            "bond_commitment": self.bond_commitment,
            "remediation_commitment": self.remediation_commitment,
            "opened_height": self.opened_height,
            "deadline_height": self.deadline_height,
            "resolved_height": self.resolved_height,
        })
    }

    pub fn state_root(&self) -> String {
        pmrl_payload_root("REFUND-CHALLENGE-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> PrivateMevRefundLedgerResult<String> {
        ensure_nonempty("challenge_id", &self.challenge_id)?;
        ensure_nonempty("target_id", &self.target_id)?;
        ensure_nonempty("challenger_nullifier", &self.challenger_nullifier)?;
        ensure_nonempty("evidence_root", &self.evidence_root)?;
        ensure_nonempty("bond_commitment", &self.bond_commitment)?;
        ensure_ordered_heights("refund_challenge", self.opened_height, self.deadline_height)?;
        if self.status.final_status() && self.resolved_height.is_none() {
            return Err(format!(
                "final challenge {} missing resolved height",
                self.challenge_id
            ));
        }
        if let Some(resolved_height) = self.resolved_height {
            if resolved_height < self.opened_height {
                return Err(format!(
                    "challenge {} resolved before opening",
                    self.challenge_id
                ));
            }
        }
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMevRefundLedgerRoots {
    pub config_root: String,
    pub rebate_lane_root: String,
    pub refund_commitment_root: String,
    pub surplus_receipt_root: String,
    pub claim_nullifier_root: String,
    pub pq_attestation_root: String,
    pub rebate_settlement_root: String,
    pub challenge_root: String,
}

impl PrivateMevRefundLedgerRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "rebate_lane_root": self.rebate_lane_root,
            "refund_commitment_root": self.refund_commitment_root,
            "surplus_receipt_root": self.surplus_receipt_root,
            "claim_nullifier_root": self.claim_nullifier_root,
            "pq_attestation_root": self.pq_attestation_root,
            "rebate_settlement_root": self.rebate_settlement_root,
            "challenge_root": self.challenge_root,
        })
    }

    pub fn state_root(&self) -> String {
        pmrl_payload_root("ROOTS", &self.public_record())
    }

    pub fn validate(&self) -> PrivateMevRefundLedgerResult<String> {
        ensure_nonempty("config_root", &self.config_root)?;
        ensure_nonempty("rebate_lane_root", &self.rebate_lane_root)?;
        ensure_nonempty("refund_commitment_root", &self.refund_commitment_root)?;
        ensure_nonempty("surplus_receipt_root", &self.surplus_receipt_root)?;
        ensure_nonempty("claim_nullifier_root", &self.claim_nullifier_root)?;
        ensure_nonempty("pq_attestation_root", &self.pq_attestation_root)?;
        ensure_nonempty("rebate_settlement_root", &self.rebate_settlement_root)?;
        ensure_nonempty("challenge_root", &self.challenge_root)?;
        Ok(self.state_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMevRefundLedgerCounters {
    pub rebate_lanes: usize,
    pub refund_commitments: usize,
    pub surplus_receipts: usize,
    pub claim_nullifiers: usize,
    pub pq_attestations: usize,
    pub rebate_settlements: usize,
    pub challenges: usize,
    pub open_challenges: usize,
    pub claimable_commitments: usize,
    pub low_fee_rebates: usize,
}

impl PrivateMevRefundLedgerCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_lanes": self.rebate_lanes,
            "refund_commitments": self.refund_commitments,
            "surplus_receipts": self.surplus_receipts,
            "claim_nullifiers": self.claim_nullifiers,
            "pq_attestations": self.pq_attestations,
            "rebate_settlements": self.rebate_settlements,
            "challenges": self.challenges,
            "open_challenges": self.open_challenges,
            "claimable_commitments": self.claimable_commitments,
            "low_fee_rebates": self.low_fee_rebates,
        })
    }

    pub fn state_root(&self) -> String {
        pmrl_payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateMevRefundLedger {
    pub config: PrivateMevRefundLedgerConfig,
    pub height: u64,
    pub epoch: u64,
    pub status: String,
    pub rebate_lanes: BTreeMap<String, LowFeeRebateLane>,
    pub refund_commitments: BTreeMap<String, RefundCommitment>,
    pub surplus_receipts: BTreeMap<String, SolverSurplusReceipt>,
    pub claim_nullifiers: BTreeMap<String, AnonymousClaimNullifier>,
    pub pq_attestations: BTreeMap<String, PqRefundAttestation>,
    pub rebate_settlements: BTreeMap<String, LowFeeRebateSettlement>,
    pub challenges: BTreeMap<String, RefundChallengeRecord>,
    pub used_nullifiers: BTreeSet<String>,
}

impl PrivateMevRefundLedger {
    pub fn devnet() -> PrivateMevRefundLedgerResult<Self> {
        let height = 88;
        let mut state = Self {
            config: PrivateMevRefundLedgerConfig::devnet(),
            height,
            epoch: 0,
            status: STATE_STATUS_ACTIVE.to_string(),
            rebate_lanes: BTreeMap::new(),
            refund_commitments: BTreeMap::new(),
            surplus_receipts: BTreeMap::new(),
            claim_nullifiers: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            rebate_settlements: BTreeMap::new(),
            challenges: BTreeMap::new(),
            used_nullifiers: BTreeSet::new(),
        };

        for (index, lane) in [
            RefundLane::PrivateSwap,
            RefundLane::MoneroExit,
            RefundLane::PrivateLiquidation,
            RefundLane::BatchAuction,
            RefundLane::LowFeeSwap,
            RefundLane::LowFeeTransfer,
            RefundLane::EmergencyExit,
        ]
        .into_iter()
        .enumerate()
        {
            let index = index as u64;
            let rebate_lane = LowFeeRebateLane::devnet(lane, 0, height);
            state.add_rebate_lane(rebate_lane)?;

            let commitment = RefundCommitment::devnet(lane, index, height);
            let commitment_id = commitment.commitment_id.clone();
            let receipt = SolverSurplusReceipt::devnet(lane, index, height);
            let receipt_id = receipt.receipt_id.clone();
            let claim = AnonymousClaimNullifier::devnet(lane, index, height);
            let claim_id = claim.nullifier_id.clone();
            let attestation = PqRefundAttestation::devnet(
                PqAttestationRole::Solver,
                &receipt_id,
                state.epoch,
                height,
            );
            state.add_surplus_receipt(receipt)?;
            state.add_refund_commitment(commitment)?;
            state.add_claim_nullifier(claim)?;
            state.add_pq_attestation(attestation)?;

            if lane.low_fee() {
                state.add_rebate_settlement(LowFeeRebateSettlement::devnet(lane, index, height))?;
            }

            if index == 2 {
                state.add_challenge(RefundChallengeRecord::devnet(
                    ChallengeKind::SolverOvercharge,
                    &commitment_id,
                    index,
                    height,
                ))?;
            }

            if index == 1 {
                state.add_pq_attestation(PqRefundAttestation::devnet(
                    PqAttestationRole::BridgeWatchtower,
                    &claim_id,
                    state.epoch,
                    height,
                ))?;
            }
        }

        state.set_height(height)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateMevRefundLedgerResult<()> {
        self.height = height;
        self.epoch = height / self.config.epoch_blocks.max(1);
        for lane in self.rebate_lanes.values_mut() {
            lane.set_height(height);
        }
        for commitment in self.refund_commitments.values_mut() {
            commitment.set_height(height);
        }
        for receipt in self.surplus_receipts.values_mut() {
            receipt.set_height(height);
        }
        for claim in self.claim_nullifiers.values_mut() {
            claim.set_height(height);
        }
        for attestation in self.pq_attestations.values_mut() {
            attestation.set_height(height);
        }
        for rebate in self.rebate_settlements.values_mut() {
            rebate.set_height(height);
        }
        for challenge in self.challenges.values_mut() {
            challenge.set_height(height);
        }
        self.validate().map(|_| ())
    }

    pub fn roots(&self) -> PrivateMevRefundLedgerRoots {
        PrivateMevRefundLedgerRoots {
            config_root: self.config.state_root(),
            rebate_lane_root: merkle_root(
                "PRIVATE-MEV-REFUND-LEDGER:REBATE-LANES",
                &records_from_map(&self.rebate_lanes),
            ),
            refund_commitment_root: merkle_root(
                "PRIVATE-MEV-REFUND-LEDGER:REFUND-COMMITMENTS",
                &records_from_map(&self.refund_commitments),
            ),
            surplus_receipt_root: merkle_root(
                "PRIVATE-MEV-REFUND-LEDGER:SURPLUS-RECEIPTS",
                &records_from_map(&self.surplus_receipts),
            ),
            claim_nullifier_root: merkle_root(
                "PRIVATE-MEV-REFUND-LEDGER:CLAIM-NULLIFIERS",
                &records_from_map(&self.claim_nullifiers),
            ),
            pq_attestation_root: merkle_root(
                "PRIVATE-MEV-REFUND-LEDGER:PQ-ATTESTATIONS",
                &records_from_map(&self.pq_attestations),
            ),
            rebate_settlement_root: merkle_root(
                "PRIVATE-MEV-REFUND-LEDGER:REBATE-SETTLEMENTS",
                &records_from_map(&self.rebate_settlements),
            ),
            challenge_root: merkle_root(
                "PRIVATE-MEV-REFUND-LEDGER:CHALLENGES",
                &records_from_map(&self.challenges),
            ),
        }
    }

    pub fn counters(&self) -> PrivateMevRefundLedgerCounters {
        PrivateMevRefundLedgerCounters {
            rebate_lanes: self.rebate_lanes.len(),
            refund_commitments: self.refund_commitments.len(),
            surplus_receipts: self.surplus_receipts.len(),
            claim_nullifiers: self.claim_nullifiers.len(),
            pq_attestations: self.pq_attestations.len(),
            rebate_settlements: self.rebate_settlements.len(),
            challenges: self.challenges.len(),
            open_challenges: self
                .challenges
                .values()
                .filter(|challenge| !challenge.status.final_status())
                .count(),
            claimable_commitments: self
                .refund_commitments
                .values()
                .filter(|commitment| commitment.status.claimable())
                .count(),
            low_fee_rebates: self
                .rebate_settlements
                .values()
                .filter(|rebate| rebate.status == ClaimStatus::Settled)
                .count(),
        }
    }

    pub fn state_root(&self) -> String {
        pmrl_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(object) = &mut record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> PrivateMevRefundLedgerResult<String> {
        self.config.validate()?;
        if !matches!(
            self.status.as_str(),
            STATE_STATUS_ACTIVE | STATE_STATUS_CHALLENGED | STATE_STATUS_HALTED
        ) {
            return Err(format!("unsupported ledger status {}", self.status));
        }
        ensure_limit(
            "rebate_lanes",
            self.rebate_lanes.len(),
            PRIVATE_MEV_REFUND_LEDGER_MAX_LANES,
        )?;
        ensure_limit(
            "refund_commitments",
            self.refund_commitments.len(),
            PRIVATE_MEV_REFUND_LEDGER_MAX_COMMITMENTS,
        )?;
        ensure_limit(
            "surplus_receipts",
            self.surplus_receipts.len(),
            PRIVATE_MEV_REFUND_LEDGER_MAX_RECEIPTS,
        )?;
        ensure_limit(
            "claim_nullifiers",
            self.claim_nullifiers.len(),
            PRIVATE_MEV_REFUND_LEDGER_MAX_NULLIFIERS,
        )?;
        ensure_limit(
            "pq_attestations",
            self.pq_attestations.len(),
            PRIVATE_MEV_REFUND_LEDGER_MAX_ATTESTATIONS,
        )?;
        ensure_limit(
            "rebate_settlements",
            self.rebate_settlements.len(),
            PRIVATE_MEV_REFUND_LEDGER_MAX_REBATES,
        )?;
        ensure_limit(
            "challenges",
            self.challenges.len(),
            PRIVATE_MEV_REFUND_LEDGER_MAX_CHALLENGES,
        )?;

        let mut seen_nullifiers = BTreeSet::new();
        for (id, lane) in &self.rebate_lanes {
            if id != &lane.lane_id {
                return Err(format!("rebate lane key mismatch {id}"));
            }
            lane.validate()?;
        }
        for (id, receipt) in &self.surplus_receipts {
            if id != &receipt.receipt_id {
                return Err(format!("surplus receipt key mismatch {id}"));
            }
            receipt.validate()?;
        }
        for (id, commitment) in &self.refund_commitments {
            if id != &commitment.commitment_id {
                return Err(format!("refund commitment key mismatch {id}"));
            }
            commitment.validate()?;
            if let Some(receipt_id) = &commitment.solver_receipt_id {
                if !self.surplus_receipts.contains_key(receipt_id) {
                    return Err(format!(
                        "commitment {} references missing receipt {}",
                        id, receipt_id
                    ));
                }
            }
            if let Some(lane_id) = &commitment.low_fee_lane_id {
                if !self.rebate_lanes.contains_key(lane_id) {
                    return Err(format!(
                        "commitment {} references missing rebate lane {}",
                        id, lane_id
                    ));
                }
            }
        }
        for (id, claim) in &self.claim_nullifiers {
            if id != &claim.nullifier_id {
                return Err(format!("claim nullifier key mismatch {id}"));
            }
            claim.validate()?;
            if !self.refund_commitments.contains_key(&claim.commitment_id) {
                return Err(format!(
                    "claim {} references missing commitment {}",
                    id, claim.commitment_id
                ));
            }
            if !seen_nullifiers.insert(claim.nullifier.clone()) {
                return Err(format!("duplicate anonymous nullifier {}", claim.nullifier));
            }
        }
        for nullifier in &self.used_nullifiers {
            if !seen_nullifiers.contains(nullifier) {
                return Err(format!(
                    "used nullifier set contains unknown nullifier {}",
                    nullifier
                ));
            }
        }
        for (id, attestation) in &self.pq_attestations {
            if id != &attestation.attestation_id {
                return Err(format!("pq attestation key mismatch {id}"));
            }
            attestation.validate()?;
            if attestation.security_bits < self.config.min_pq_security_bits {
                return Err(format!(
                    "attestation {} below configured pq security bits",
                    id
                ));
            }
        }
        for (id, rebate) in &self.rebate_settlements {
            if id != &rebate.rebate_id {
                return Err(format!("rebate settlement key mismatch {id}"));
            }
            rebate.validate()?;
            if !self.rebate_lanes.contains_key(&rebate.lane_id) {
                return Err(format!(
                    "rebate {} references missing lane {}",
                    id, rebate.lane_id
                ));
            }
            if !self.claim_nullifiers.contains_key(&rebate.nullifier_id) {
                return Err(format!(
                    "rebate {} references missing claim {}",
                    id, rebate.nullifier_id
                ));
            }
        }
        for (id, challenge) in &self.challenges {
            if id != &challenge.challenge_id {
                return Err(format!("challenge key mismatch {id}"));
            }
            challenge.validate()?;
            if !self.refund_commitments.contains_key(&challenge.target_id)
                && !self.surplus_receipts.contains_key(&challenge.target_id)
                && !self.claim_nullifiers.contains_key(&challenge.target_id)
                && !self.pq_attestations.contains_key(&challenge.target_id)
                && !self.rebate_settlements.contains_key(&challenge.target_id)
            {
                return Err(format!(
                    "challenge {} references unknown target {}",
                    id, challenge.target_id
                ));
            }
        }
        self.roots().validate()?;
        Ok(self.state_root())
    }

    pub fn add_rebate_lane(
        &mut self,
        lane: LowFeeRebateLane,
    ) -> PrivateMevRefundLedgerResult<String> {
        lane.validate()?;
        let id = lane.lane_id.clone();
        self.rebate_lanes.insert(id.clone(), lane);
        Ok(id)
    }

    pub fn add_refund_commitment(
        &mut self,
        commitment: RefundCommitment,
    ) -> PrivateMevRefundLedgerResult<String> {
        commitment.validate()?;
        let id = commitment.commitment_id.clone();
        self.refund_commitments.insert(id.clone(), commitment);
        Ok(id)
    }

    pub fn add_surplus_receipt(
        &mut self,
        receipt: SolverSurplusReceipt,
    ) -> PrivateMevRefundLedgerResult<String> {
        receipt.validate()?;
        let id = receipt.receipt_id.clone();
        self.surplus_receipts.insert(id.clone(), receipt);
        Ok(id)
    }

    pub fn add_claim_nullifier(
        &mut self,
        claim: AnonymousClaimNullifier,
    ) -> PrivateMevRefundLedgerResult<String> {
        claim.validate()?;
        if self.used_nullifiers.contains(&claim.nullifier) {
            return Err(format!("nullifier {} already used", claim.nullifier));
        }
        let id = claim.nullifier_id.clone();
        self.used_nullifiers.insert(claim.nullifier.clone());
        self.claim_nullifiers.insert(id.clone(), claim);
        Ok(id)
    }

    pub fn add_pq_attestation(
        &mut self,
        attestation: PqRefundAttestation,
    ) -> PrivateMevRefundLedgerResult<String> {
        attestation.validate()?;
        let id = attestation.attestation_id.clone();
        self.pq_attestations.insert(id.clone(), attestation);
        Ok(id)
    }

    pub fn add_rebate_settlement(
        &mut self,
        rebate: LowFeeRebateSettlement,
    ) -> PrivateMevRefundLedgerResult<String> {
        rebate.validate()?;
        let id = rebate.rebate_id.clone();
        self.rebate_settlements.insert(id.clone(), rebate);
        Ok(id)
    }

    pub fn add_challenge(
        &mut self,
        challenge: RefundChallengeRecord,
    ) -> PrivateMevRefundLedgerResult<String> {
        challenge.validate()?;
        let id = challenge.challenge_id.clone();
        self.status = STATE_STATUS_CHALLENGED.to_string();
        self.challenges.insert(id.clone(), challenge);
        Ok(id)
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "config": self.config.public_record(),
            "height": self.height,
            "epoch": self.epoch,
            "status": self.status,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "rebate_lanes": keyed_records(&self.rebate_lanes),
            "refund_commitments": keyed_records(&self.refund_commitments),
            "surplus_receipts": keyed_records(&self.surplus_receipts),
            "claim_nullifiers": keyed_records(&self.claim_nullifiers),
            "pq_attestations": keyed_records(&self.pq_attestations),
            "rebate_settlements": keyed_records(&self.rebate_settlements),
            "challenges": keyed_records(&self.challenges),
            "used_nullifier_root": merkle_root(
                "PRIVATE-MEV-REFUND-LEDGER:USED-NULLIFIERS",
                &self
                    .used_nullifiers
                    .iter()
                    .map(|nullifier| Value::String(nullifier.clone()))
                    .collect::<Vec<_>>()
            ),
        })
    }
}

trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for LowFeeRebateLane {
    fn public_record(&self) -> Value {
        LowFeeRebateLane::public_record(self)
    }
}

impl PublicRecord for RefundCommitment {
    fn public_record(&self) -> Value {
        RefundCommitment::public_record(self)
    }
}

impl PublicRecord for SolverSurplusReceipt {
    fn public_record(&self) -> Value {
        SolverSurplusReceipt::public_record(self)
    }
}

impl PublicRecord for AnonymousClaimNullifier {
    fn public_record(&self) -> Value {
        AnonymousClaimNullifier::public_record(self)
    }
}

impl PublicRecord for PqRefundAttestation {
    fn public_record(&self) -> Value {
        PqRefundAttestation::public_record(self)
    }
}

impl PublicRecord for LowFeeRebateSettlement {
    fn public_record(&self) -> Value {
        LowFeeRebateSettlement::public_record(self)
    }
}

impl PublicRecord for RefundChallengeRecord {
    fn public_record(&self) -> Value {
        RefundChallengeRecord::public_record(self)
    }
}

fn records_from_map<T: PublicRecord>(map: &BTreeMap<String, T>) -> Vec<Value> {
    map.iter()
        .map(|(id, record)| json!({ "id": id, "record": record.public_record() }))
        .collect()
}

fn keyed_records<T: PublicRecord>(map: &BTreeMap<String, T>) -> Value {
    Value::Object(
        map.iter()
            .map(|(id, record)| (id.clone(), record.public_record()))
            .collect(),
    )
}

fn pmrl_payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-MEV-REFUND-LEDGER:{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}

fn pmrl_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-MEV-REFUND-LEDGER:STATE",
        &[HashPart::Json(record)],
        32,
    )
}

fn label_hash(domain: &str, parts: &[&str]) -> String {
    let values = parts
        .iter()
        .map(|part| HashPart::Str(*part))
        .collect::<Vec<_>>();
    domain_hash(&format!("PRIVATE-MEV-REFUND-LEDGER:{domain}"), &values, 32)
}

fn ensure_nonempty(field: &str, value: &str) -> PrivateMevRefundLedgerResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(field: &str, value: u64) -> PrivateMevRefundLedgerResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(field: &str, value: u64) -> PrivateMevRefundLedgerResult<()> {
    if value > PRIVATE_MEV_REFUND_LEDGER_MAX_BPS {
        Err(format!("{field} exceeds max bps"))
    } else {
        Ok(())
    }
}

fn ensure_limit(field: &str, actual: usize, max: usize) -> PrivateMevRefundLedgerResult<()> {
    if actual > max {
        Err(format!("{field} count {actual} exceeds max {max}"))
    } else {
        Ok(())
    }
}

fn ensure_ordered_heights(
    label: &str,
    start_height: u64,
    end_height: u64,
) -> PrivateMevRefundLedgerResult<()> {
    if end_height <= start_height {
        Err(format!("{label} end height must be after start height"))
    } else {
        Ok(())
    }
}
