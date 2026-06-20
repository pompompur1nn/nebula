use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateProofBatchMarketMakerResult<T> = Result<T, String>;

pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_PROTOCOL_VERSION: &str =
    "nebula-l2-private-proof-batch-market-maker-v1";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_HASH_SUITE: &str = "SHAKE256";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_PQ_RECOVERY_SCHEME: &str = "SLH-DSA-SHAKE-256s";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_RECURSION_SCHEME: &str =
    "nebula-devnet-private-proof-batch-recursive-folding-v1";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_AGGREGATION_COMMITMENT_SCHEME: &str =
    "nebula-devnet-private-proof-batch-aggregation-commitments-v1";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_WITNESS_BUNDLE_SCHEME: &str =
    "nebula-devnet-threshold-encrypted-witness-bundle-slots-v1";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_CHALLENGE_PROOF_SYSTEM: &str =
    "nebula-devnet-private-proof-batch-failure-challenge-v1";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_REBATE_ACCOUNTING_PROOF_SYSTEM: &str =
    "nebula-devnet-private-proof-batch-fee-rebate-accounting-v1";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_FEE_ASSET_ID: &str = "asset:wxmr";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_SECURITY_BITS: u64 = 192;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_EPOCH_BLOCKS: u64 = 96;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 4;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_PROOF_SLA_BLOCKS: u64 = 8;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_AGGREGATION_SLA_BLOCKS: u64 = 3;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_MIN_PROVER_STAKE_UNITS: u64 = 25_000;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_MIN_SPONSOR_DEPOSIT_UNITS: u64 = 50_000;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_MAX_BASE_FEE_MICRO_UNITS: u64 = 2_500;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_MAX_RECURSIVE_FEE_MICRO_UNITS: u64 = 950;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_MIN_BATCH_SIZE: u64 = 2;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_MAX_BATCH_SIZE: u64 = 128;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_MAX_WITNESS_SLOTS: u64 = 256;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_SLASHING_BPS: u64 = 5_000;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_LATE_SLASHING_BPS: u64 = 1_500;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_PROTOCOL_FEE_BPS: u64 = 150;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_REBATE_BPS: u64 = 4_000;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_RECURSIVE_DISCOUNT_BPS: u64 = 1_500;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_COMMITTEE_THRESHOLD_BPS: u64 = 6_700;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_MAX_BPS: u64 = 10_000;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_MAX_RECURSION_DEPTH: u64 = 8;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_MAX_CHILD_PROOFS: u64 = 128;
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_MAX_RECORDS: usize = 4_096;

pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_OPEN: &str = "open";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_LOCKED: &str = "locked";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_QUOTED: &str = "quoted";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_ASSIGNED: &str = "assigned";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_PROVING: &str = "proving";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_PROVED: &str = "proved";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_AGGREGATED: &str = "aggregated";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_REBATED: &str = "rebated";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_SETTLED: &str = "settled";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_CHALLENGED: &str = "challenged";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_SLASHED: &str = "slashed";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_EXPIRED: &str = "expired";
pub const PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_CANCELLED: &str = "cancelled";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateBatchWorkload {
    PrivateTransfer,
    PrivateSwap,
    PrivateLending,
    PrivatePerps,
    PrivateVault,
    SmartContractCall,
    TokenMint,
    TokenBurn,
    MoneroBridgeDeposit,
    MoneroBridgeExit,
    RecursiveAggregation,
    RebateAccounting,
    BatchFailureChallenge,
}

impl PrivateBatchWorkload {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateSwap => "private_swap",
            Self::PrivateLending => "private_lending",
            Self::PrivatePerps => "private_perps",
            Self::PrivateVault => "private_vault",
            Self::SmartContractCall => "smart_contract_call",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::MoneroBridgeDeposit => "monero_bridge_deposit",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::RecursiveAggregation => "recursive_aggregation",
            Self::RebateAccounting => "rebate_accounting",
            Self::BatchFailureChallenge => "batch_failure_challenge",
        }
    }

    pub fn default_fee_cap_micro_units(self) -> u64 {
        match self {
            Self::PrivateTransfer => 850,
            Self::PrivateSwap => 1_200,
            Self::PrivateLending => 1_450,
            Self::PrivatePerps => 1_700,
            Self::PrivateVault => 1_350,
            Self::SmartContractCall => 1_800,
            Self::TokenMint | Self::TokenBurn => 1_050,
            Self::MoneroBridgeDeposit | Self::MoneroBridgeExit => 2_200,
            Self::RecursiveAggregation => {
                PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_MAX_RECURSIVE_FEE_MICRO_UNITS
            }
            Self::RebateAccounting => 700,
            Self::BatchFailureChallenge => 2_500,
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::BatchFailureChallenge => 10_000,
            Self::MoneroBridgeDeposit | Self::MoneroBridgeExit => 9_200,
            Self::PrivatePerps => 8_600,
            Self::SmartContractCall => 7_900,
            Self::PrivateSwap | Self::PrivateLending => 7_200,
            Self::PrivateVault => 6_700,
            Self::TokenMint | Self::TokenBurn => 6_000,
            Self::PrivateTransfer => 5_400,
            Self::RecursiveAggregation => 5_000,
            Self::RebateAccounting => 4_700,
        }
    }

    pub fn recursive(self) -> bool {
        matches!(self, Self::RecursiveAggregation | Self::RebateAccounting)
    }

    pub fn challenge(self) -> bool {
        matches!(self, Self::BatchFailureChallenge)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateBatchLane {
    LowFeeRetail,
    DefiExecution,
    SmartContracts,
    TokenWorkloads,
    MoneroBridge,
    RecursiveFastLane,
    SponsoredPublicGood,
    EmergencyChallenge,
    Maintenance,
}

impl PrivateBatchLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFeeRetail => "low_fee_retail",
            Self::DefiExecution => "defi_execution",
            Self::SmartContracts => "smart_contracts",
            Self::TokenWorkloads => "token_workloads",
            Self::MoneroBridge => "monero_bridge",
            Self::RecursiveFastLane => "recursive_fast_lane",
            Self::SponsoredPublicGood => "sponsored_public_good",
            Self::EmergencyChallenge => "emergency_challenge",
            Self::Maintenance => "maintenance",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::EmergencyChallenge => 10_000,
            Self::MoneroBridge => 9_000,
            Self::DefiExecution => 8_400,
            Self::SmartContracts => 7_700,
            Self::TokenWorkloads => 6_400,
            Self::RecursiveFastLane => 6_100,
            Self::LowFeeRetail => 5_600,
            Self::SponsoredPublicGood => 5_300,
            Self::Maintenance => 2_000,
        }
    }

    pub fn low_fee(self) -> bool {
        matches!(self, Self::LowFeeRetail | Self::SponsoredPublicGood)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateBatchAuctionStatus {
    Open,
    Locked,
    Assigned,
    Proving,
    Proved,
    Aggregated,
    Settled,
    Challenged,
    Slashed,
    Expired,
    Cancelled,
}

impl PrivateBatchAuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_OPEN,
            Self::Locked => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_LOCKED,
            Self::Assigned => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_ASSIGNED,
            Self::Proving => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_PROVING,
            Self::Proved => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_PROVED,
            Self::Aggregated => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_AGGREGATED,
            Self::Settled => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_SETTLED,
            Self::Challenged => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_CHALLENGED,
            Self::Slashed => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_SLASHED,
            Self::Expired => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_EXPIRED,
            Self::Cancelled => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_CANCELLED,
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::Locked
                | Self::Assigned
                | Self::Proving
                | Self::Proved
                | Self::Aggregated
                | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqProverQuoteStatus {
    Open,
    Accepted,
    Lost,
    Expired,
    Slashed,
}

impl PqProverQuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_OPEN,
            Self::Accepted => "accepted",
            Self::Lost => "lost",
            Self::Expired => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_EXPIRED,
            Self::Slashed => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_SLASHED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessBundleSlotStatus {
    Reserved,
    Filled,
    Revealed,
    Expired,
    Slashed,
}

impl WitnessBundleSlotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Filled => "filled",
            Self::Revealed => "revealed",
            Self::Expired => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_EXPIRED,
            Self::Slashed => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_SLASHED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationCommitmentStatus {
    Pending,
    Submitted,
    Verified,
    Rejected,
    Challenged,
    Slashed,
}

impl AggregationCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
            Self::Challenged => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_CHALLENGED,
            Self::Slashed => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_SLASHED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeRebateLaneStatus {
    Active,
    Paused,
    Depleted,
    Retired,
}

impl FeeRebateLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Depleted => "depleted",
            Self::Retired => "retired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPoolStatus {
    Active,
    Paused,
    Depleted,
    Slashed,
    Retired,
}

impl SponsorPoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Depleted => "depleted",
            Self::Slashed => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_SLASHED,
            Self::Retired => "retired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchFailureChallengeStatus {
    Open,
    EvidenceSubmitted,
    Upheld,
    Rejected,
    Expired,
}

impl BatchFailureChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_OPEN,
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::Expired => PRIVATE_PROOF_BATCH_MARKET_MAKER_STATUS_EXPIRED,
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Open | Self::EvidenceSubmitted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchSlashingReason {
    LateProof,
    InvalidProof,
    MissingWitnessBundle,
    InvalidAggregation,
    RebateFraud,
    SponsorPoolFraud,
    LivenessFailure,
}

impl BatchSlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LateProof => "late_proof",
            Self::InvalidProof => "invalid_proof",
            Self::MissingWitnessBundle => "missing_witness_bundle",
            Self::InvalidAggregation => "invalid_aggregation",
            Self::RebateFraud => "rebate_fraud",
            Self::SponsorPoolFraud => "sponsor_pool_fraud",
            Self::LivenessFailure => "liveness_failure",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateProofBatchMarketMakerConfig {
    pub chain_id: String,
    pub default_fee_asset_id: String,
    pub security_bits: u64,
    pub epoch_blocks: u64,
    pub auction_window_blocks: u64,
    pub proof_sla_blocks: u64,
    pub aggregation_sla_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_prover_stake_units: u64,
    pub min_sponsor_deposit_units: u64,
    pub max_base_fee_micro_units: u64,
    pub max_recursive_fee_micro_units: u64,
    pub min_batch_size: u64,
    pub max_batch_size: u64,
    pub max_witness_slots: u64,
    pub slashing_bps: u64,
    pub late_slashing_bps: u64,
    pub protocol_fee_bps: u64,
    pub default_rebate_bps: u64,
    pub recursive_discount_bps: u64,
    pub committee_threshold_bps: u64,
    pub max_records: usize,
}

impl PrivateProofBatchMarketMakerConfig {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            default_fee_asset_id: PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_FEE_ASSET_ID.to_string(),
            security_bits: PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_SECURITY_BITS,
            epoch_blocks: PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_EPOCH_BLOCKS,
            auction_window_blocks: PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_AUCTION_WINDOW_BLOCKS,
            proof_sla_blocks: PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_PROOF_SLA_BLOCKS,
            aggregation_sla_blocks: PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_AGGREGATION_SLA_BLOCKS,
            challenge_window_blocks:
                PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_prover_stake_units: PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_MIN_PROVER_STAKE_UNITS,
            min_sponsor_deposit_units:
                PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_MIN_SPONSOR_DEPOSIT_UNITS,
            max_base_fee_micro_units:
                PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_MAX_BASE_FEE_MICRO_UNITS,
            max_recursive_fee_micro_units:
                PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_MAX_RECURSIVE_FEE_MICRO_UNITS,
            min_batch_size: PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_MIN_BATCH_SIZE,
            max_batch_size: PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_MAX_BATCH_SIZE,
            max_witness_slots: PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_MAX_WITNESS_SLOTS,
            slashing_bps: PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_SLASHING_BPS,
            late_slashing_bps: PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_LATE_SLASHING_BPS,
            protocol_fee_bps: PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_PROTOCOL_FEE_BPS,
            default_rebate_bps: PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_REBATE_BPS,
            recursive_discount_bps: PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_RECURSIVE_DISCOUNT_BPS,
            committee_threshold_bps:
                PRIVATE_PROOF_BATCH_MARKET_MAKER_DEFAULT_COMMITTEE_THRESHOLD_BPS,
            max_records: PRIVATE_PROOF_BATCH_MARKET_MAKER_MAX_RECORDS,
        }
    }

    pub fn fee_cap_for(&self, workload: PrivateBatchWorkload) -> u64 {
        if workload.recursive() {
            self.max_recursive_fee_micro_units
                .min(workload.default_fee_cap_micro_units())
        } else {
            self.max_base_fee_micro_units
                .min(workload.default_fee_cap_micro_units())
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_proof_batch_market_maker_config",
            "chain_id": self.chain_id,
            "protocol_version": PRIVATE_PROOF_BATCH_MARKET_MAKER_PROTOCOL_VERSION,
            "schema_version": PRIVATE_PROOF_BATCH_MARKET_MAKER_SCHEMA_VERSION,
            "hash_suite": PRIVATE_PROOF_BATCH_MARKET_MAKER_HASH_SUITE,
            "pq_signature_scheme": PRIVATE_PROOF_BATCH_MARKET_MAKER_PQ_SIGNATURE_SCHEME,
            "pq_recovery_scheme": PRIVATE_PROOF_BATCH_MARKET_MAKER_PQ_RECOVERY_SCHEME,
            "pq_kem_scheme": PRIVATE_PROOF_BATCH_MARKET_MAKER_PQ_KEM_SCHEME,
            "recursion_scheme": PRIVATE_PROOF_BATCH_MARKET_MAKER_RECURSION_SCHEME,
            "aggregation_commitment_scheme": PRIVATE_PROOF_BATCH_MARKET_MAKER_AGGREGATION_COMMITMENT_SCHEME,
            "witness_bundle_scheme": PRIVATE_PROOF_BATCH_MARKET_MAKER_WITNESS_BUNDLE_SCHEME,
            "challenge_proof_system": PRIVATE_PROOF_BATCH_MARKET_MAKER_CHALLENGE_PROOF_SYSTEM,
            "rebate_accounting_proof_system": PRIVATE_PROOF_BATCH_MARKET_MAKER_REBATE_ACCOUNTING_PROOF_SYSTEM,
            "default_fee_asset_id": self.default_fee_asset_id,
            "security_bits": self.security_bits,
            "epoch_blocks": self.epoch_blocks,
            "auction_window_blocks": self.auction_window_blocks,
            "proof_sla_blocks": self.proof_sla_blocks,
            "aggregation_sla_blocks": self.aggregation_sla_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_prover_stake_units": self.min_prover_stake_units,
            "min_sponsor_deposit_units": self.min_sponsor_deposit_units,
            "max_base_fee_micro_units": self.max_base_fee_micro_units,
            "max_recursive_fee_micro_units": self.max_recursive_fee_micro_units,
            "min_batch_size": self.min_batch_size,
            "max_batch_size": self.max_batch_size,
            "max_witness_slots": self.max_witness_slots,
            "slashing_bps": self.slashing_bps,
            "late_slashing_bps": self.late_slashing_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "default_rebate_bps": self.default_rebate_bps,
            "recursive_discount_bps": self.recursive_discount_bps,
            "committee_threshold_bps": self.committee_threshold_bps,
            "max_records": self.max_records,
        })
    }

    pub fn state_root(&self) -> String {
        private_proof_batch_payload_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateProofBatchMarketMakerResult<()> {
        ensure_nonempty("chain_id", &self.chain_id)?;
        if self.chain_id != CHAIN_ID {
            return Err("private proof batch market maker chain id mismatch".to_string());
        }
        ensure_nonempty("default_fee_asset_id", &self.default_fee_asset_id)?;
        ensure_positive("security_bits", self.security_bits)?;
        ensure_positive("epoch_blocks", self.epoch_blocks)?;
        ensure_positive("auction_window_blocks", self.auction_window_blocks)?;
        ensure_positive("proof_sla_blocks", self.proof_sla_blocks)?;
        ensure_positive("aggregation_sla_blocks", self.aggregation_sla_blocks)?;
        ensure_positive("challenge_window_blocks", self.challenge_window_blocks)?;
        ensure_positive("min_prover_stake_units", self.min_prover_stake_units)?;
        ensure_positive("min_sponsor_deposit_units", self.min_sponsor_deposit_units)?;
        ensure_positive("max_base_fee_micro_units", self.max_base_fee_micro_units)?;
        ensure_positive(
            "max_recursive_fee_micro_units",
            self.max_recursive_fee_micro_units,
        )?;
        ensure_positive("min_batch_size", self.min_batch_size)?;
        ensure_positive("max_batch_size", self.max_batch_size)?;
        ensure_positive("max_witness_slots", self.max_witness_slots)?;
        if self.min_batch_size > self.max_batch_size {
            return Err("private proof batch min batch size exceeds max".to_string());
        }
        ensure_bps("slashing_bps", self.slashing_bps)?;
        ensure_bps("late_slashing_bps", self.late_slashing_bps)?;
        ensure_bps("protocol_fee_bps", self.protocol_fee_bps)?;
        ensure_bps("default_rebate_bps", self.default_rebate_bps)?;
        ensure_bps("recursive_discount_bps", self.recursive_discount_bps)?;
        ensure_bps("committee_threshold_bps", self.committee_threshold_bps)?;
        if self.max_records == 0 {
            return Err("private proof batch max records must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateBatchAuction {
    pub auction_id: String,
    pub maker_id: String,
    pub lane: PrivateBatchLane,
    pub workload: PrivateBatchWorkload,
    pub fee_asset_id: String,
    pub batch_size: u64,
    pub min_security_bits: u64,
    pub max_fee_micro_units: u64,
    pub opened_height: u64,
    pub quote_deadline_height: u64,
    pub proof_deadline_height: u64,
    pub aggregation_deadline_height: u64,
    pub witness_bundle_root: String,
    pub nullifier_root: String,
    pub public_input_root: String,
    pub selected_quote_id: Option<String>,
    pub aggregation_commitment_id: Option<String>,
    pub sponsor_pool_id: Option<String>,
    pub rebate_lane_id: Option<String>,
    pub challenge_ids: BTreeSet<String>,
    pub status: PrivateBatchAuctionStatus,
}

impl PrivateBatchAuction {
    pub fn new(
        maker_id: &str,
        lane: PrivateBatchLane,
        workload: PrivateBatchWorkload,
        fee_asset_id: &str,
        batch_size: u64,
        max_fee_micro_units: u64,
        witness_bundle_root: &str,
        nullifier_root: &str,
        public_input_root: &str,
        opened_height: u64,
        config: &PrivateProofBatchMarketMakerConfig,
        nonce: u64,
    ) -> PrivateProofBatchMarketMakerResult<Self> {
        ensure_nonempty("maker_id", maker_id)?;
        ensure_nonempty("fee_asset_id", fee_asset_id)?;
        ensure_nonempty("witness_bundle_root", witness_bundle_root)?;
        ensure_nonempty("nullifier_root", nullifier_root)?;
        ensure_nonempty("public_input_root", public_input_root)?;
        ensure_positive("batch_size", batch_size)?;
        ensure_positive("max_fee_micro_units", max_fee_micro_units)?;
        if batch_size < config.min_batch_size || batch_size > config.max_batch_size {
            return Err("private proof batch auction batch size outside config".to_string());
        }
        if max_fee_micro_units > config.fee_cap_for(workload) {
            return Err("private proof batch auction fee cap exceeds workload cap".to_string());
        }
        let quote_deadline_height = opened_height.saturating_add(config.auction_window_blocks);
        let proof_deadline_height = quote_deadline_height.saturating_add(config.proof_sla_blocks);
        let aggregation_deadline_height =
            proof_deadline_height.saturating_add(config.aggregation_sla_blocks);
        let seed = json!({
            "maker_id": maker_id,
            "lane": lane.as_str(),
            "workload": workload.as_str(),
            "fee_asset_id": fee_asset_id,
            "batch_size": batch_size,
            "max_fee_micro_units": max_fee_micro_units,
            "witness_bundle_root": witness_bundle_root,
            "nullifier_root": nullifier_root,
            "public_input_root": public_input_root,
            "opened_height": opened_height,
            "nonce": nonce,
        });
        let auction_id = private_proof_batch_payload_root("AUCTION_ID", &seed);
        let auction = Self {
            auction_id,
            maker_id: maker_id.to_string(),
            lane,
            workload,
            fee_asset_id: fee_asset_id.to_string(),
            batch_size,
            min_security_bits: config.security_bits,
            max_fee_micro_units,
            opened_height,
            quote_deadline_height,
            proof_deadline_height,
            aggregation_deadline_height,
            witness_bundle_root: witness_bundle_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            public_input_root: public_input_root.to_string(),
            selected_quote_id: None,
            aggregation_commitment_id: None,
            sponsor_pool_id: None,
            rebate_lane_id: None,
            challenge_ids: BTreeSet::new(),
            status: PrivateBatchAuctionStatus::Open,
        };
        auction.validate(config)?;
        Ok(auction)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_batch_auction",
            "auction_id": self.auction_id,
            "maker_id": self.maker_id,
            "lane": self.lane.as_str(),
            "workload": self.workload.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "batch_size": self.batch_size,
            "min_security_bits": self.min_security_bits,
            "max_fee_micro_units": self.max_fee_micro_units,
            "opened_height": self.opened_height,
            "quote_deadline_height": self.quote_deadline_height,
            "proof_deadline_height": self.proof_deadline_height,
            "aggregation_deadline_height": self.aggregation_deadline_height,
            "witness_bundle_root": self.witness_bundle_root,
            "nullifier_root": self.nullifier_root,
            "public_input_root": self.public_input_root,
            "selected_quote_id": self.selected_quote_id,
            "aggregation_commitment_id": self.aggregation_commitment_id,
            "sponsor_pool_id": self.sponsor_pool_id,
            "rebate_lane_id": self.rebate_lane_id,
            "challenge_ids": self.challenge_ids.iter().cloned().collect::<Vec<_>>(),
            "status": self.status.as_str(),
        })
    }

    pub fn validate(
        &self,
        config: &PrivateProofBatchMarketMakerConfig,
    ) -> PrivateProofBatchMarketMakerResult<()> {
        ensure_nonempty("auction_id", &self.auction_id)?;
        ensure_nonempty("maker_id", &self.maker_id)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_nonempty("witness_bundle_root", &self.witness_bundle_root)?;
        ensure_nonempty("nullifier_root", &self.nullifier_root)?;
        ensure_nonempty("public_input_root", &self.public_input_root)?;
        ensure_positive("batch_size", self.batch_size)?;
        ensure_positive("min_security_bits", self.min_security_bits)?;
        ensure_positive("max_fee_micro_units", self.max_fee_micro_units)?;
        if self.batch_size < config.min_batch_size || self.batch_size > config.max_batch_size {
            return Err(format!(
                "auction {} batch size outside config",
                self.auction_id
            ));
        }
        if self.min_security_bits > config.security_bits {
            return Err(format!(
                "auction {} security bits exceed config",
                self.auction_id
            ));
        }
        if self.max_fee_micro_units > config.fee_cap_for(self.workload) {
            return Err(format!(
                "auction {} fee cap exceeds config",
                self.auction_id
            ));
        }
        if self.quote_deadline_height < self.opened_height
            || self.proof_deadline_height < self.quote_deadline_height
            || self.aggregation_deadline_height < self.proof_deadline_height
        {
            return Err(format!("auction {} deadlines are invalid", self.auction_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqProverQuote {
    pub quote_id: String,
    pub auction_id: String,
    pub prover_id: String,
    pub pq_public_key: String,
    pub attestation_root: String,
    pub fee_asset_id: String,
    pub fee_micro_units: u64,
    pub collateral_units: u64,
    pub max_batch_size: u64,
    pub capacity_weight: u64,
    pub recursion_depth_supported: u64,
    pub witness_slot_capacity: u64,
    pub quote_height: u64,
    pub expires_height: u64,
    pub status: PqProverQuoteStatus,
}

impl PqProverQuote {
    pub fn new(
        auction: &PrivateBatchAuction,
        prover_id: &str,
        pq_public_key: &str,
        attestation_root: &str,
        fee_micro_units: u64,
        collateral_units: u64,
        max_batch_size: u64,
        capacity_weight: u64,
        recursion_depth_supported: u64,
        witness_slot_capacity: u64,
        quote_height: u64,
        config: &PrivateProofBatchMarketMakerConfig,
    ) -> PrivateProofBatchMarketMakerResult<Self> {
        ensure_nonempty("prover_id", prover_id)?;
        ensure_nonempty("pq_public_key", pq_public_key)?;
        ensure_nonempty("attestation_root", attestation_root)?;
        ensure_positive("fee_micro_units", fee_micro_units)?;
        ensure_positive("collateral_units", collateral_units)?;
        ensure_positive("max_batch_size", max_batch_size)?;
        ensure_positive("capacity_weight", capacity_weight)?;
        ensure_positive("witness_slot_capacity", witness_slot_capacity)?;
        if fee_micro_units > auction.max_fee_micro_units {
            return Err("pq prover quote exceeds auction fee cap".to_string());
        }
        if collateral_units < config.min_prover_stake_units {
            return Err("pq prover quote collateral below minimum".to_string());
        }
        if max_batch_size < auction.batch_size {
            return Err("pq prover quote cannot cover auction batch size".to_string());
        }
        let seed = json!({
            "auction_id": auction.auction_id,
            "prover_id": prover_id,
            "pq_public_key": pq_public_key,
            "attestation_root": attestation_root,
            "fee_micro_units": fee_micro_units,
            "collateral_units": collateral_units,
            "max_batch_size": max_batch_size,
            "capacity_weight": capacity_weight,
            "recursion_depth_supported": recursion_depth_supported,
            "witness_slot_capacity": witness_slot_capacity,
            "quote_height": quote_height,
        });
        let quote_id = private_proof_batch_payload_root("QUOTE_ID", &seed);
        let quote = Self {
            quote_id,
            auction_id: auction.auction_id.clone(),
            prover_id: prover_id.to_string(),
            pq_public_key: pq_public_key.to_string(),
            attestation_root: attestation_root.to_string(),
            fee_asset_id: auction.fee_asset_id.clone(),
            fee_micro_units,
            collateral_units,
            max_batch_size,
            capacity_weight,
            recursion_depth_supported,
            witness_slot_capacity,
            quote_height,
            expires_height: auction.quote_deadline_height,
            status: PqProverQuoteStatus::Open,
        };
        quote.validate(config)?;
        Ok(quote)
    }

    pub fn score(&self) -> u64 {
        let capacity_bonus = self.capacity_weight.saturating_mul(10);
        let fee_penalty = self.fee_micro_units.min(10_000);
        capacity_bonus
            .saturating_add(self.witness_slot_capacity)
            .saturating_add(self.recursion_depth_supported.saturating_mul(50))
            .saturating_add(10_000_u64.saturating_sub(fee_penalty))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_prover_quote",
            "quote_id": self.quote_id,
            "auction_id": self.auction_id,
            "prover_id": self.prover_id,
            "pq_public_key": self.pq_public_key,
            "attestation_root": self.attestation_root,
            "fee_asset_id": self.fee_asset_id,
            "fee_micro_units": self.fee_micro_units,
            "collateral_units": self.collateral_units,
            "max_batch_size": self.max_batch_size,
            "capacity_weight": self.capacity_weight,
            "recursion_depth_supported": self.recursion_depth_supported,
            "witness_slot_capacity": self.witness_slot_capacity,
            "quote_height": self.quote_height,
            "expires_height": self.expires_height,
            "score": self.score(),
            "status": self.status.as_str(),
        })
    }

    pub fn validate(
        &self,
        config: &PrivateProofBatchMarketMakerConfig,
    ) -> PrivateProofBatchMarketMakerResult<()> {
        ensure_nonempty("quote_id", &self.quote_id)?;
        ensure_nonempty("auction_id", &self.auction_id)?;
        ensure_nonempty("prover_id", &self.prover_id)?;
        ensure_nonempty("pq_public_key", &self.pq_public_key)?;
        ensure_nonempty("attestation_root", &self.attestation_root)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_positive("fee_micro_units", self.fee_micro_units)?;
        ensure_positive("collateral_units", self.collateral_units)?;
        ensure_positive("max_batch_size", self.max_batch_size)?;
        ensure_positive("capacity_weight", self.capacity_weight)?;
        ensure_positive("witness_slot_capacity", self.witness_slot_capacity)?;
        if self.collateral_units < config.min_prover_stake_units {
            return Err(format!("quote {} collateral below minimum", self.quote_id));
        }
        if self.recursion_depth_supported > PRIVATE_PROOF_BATCH_MARKET_MAKER_MAX_RECURSION_DEPTH {
            return Err(format!(
                "quote {} recursion depth exceeds maximum",
                self.quote_id
            ));
        }
        if self.expires_height < self.quote_height {
            return Err(format!(
                "quote {} expires before quote height",
                self.quote_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedWitnessBundleSlot {
    pub slot_id: String,
    pub auction_id: String,
    pub slot_index: u64,
    pub owner_commitment: String,
    pub encrypted_bundle_root: String,
    pub access_policy_root: String,
    pub nullifier: String,
    pub byte_size: u64,
    pub reserved_height: u64,
    pub reveal_deadline_height: u64,
    pub filled_height: Option<u64>,
    pub status: WitnessBundleSlotStatus,
}

impl EncryptedWitnessBundleSlot {
    pub fn new(
        auction_id: &str,
        slot_index: u64,
        owner_commitment: &str,
        encrypted_bundle_root: &str,
        access_policy_root: &str,
        nullifier: &str,
        byte_size: u64,
        reserved_height: u64,
        reveal_deadline_height: u64,
    ) -> PrivateProofBatchMarketMakerResult<Self> {
        ensure_nonempty("auction_id", auction_id)?;
        ensure_nonempty("owner_commitment", owner_commitment)?;
        ensure_nonempty("encrypted_bundle_root", encrypted_bundle_root)?;
        ensure_nonempty("access_policy_root", access_policy_root)?;
        ensure_nonempty("nullifier", nullifier)?;
        ensure_positive("byte_size", byte_size)?;
        if reveal_deadline_height < reserved_height {
            return Err("witness bundle slot reveal deadline before reserve height".to_string());
        }
        let seed = json!({
            "auction_id": auction_id,
            "slot_index": slot_index,
            "owner_commitment": owner_commitment,
            "encrypted_bundle_root": encrypted_bundle_root,
            "access_policy_root": access_policy_root,
            "nullifier": nullifier,
            "reserved_height": reserved_height,
        });
        let slot_id = private_proof_batch_payload_root("WITNESS_SLOT_ID", &seed);
        let slot = Self {
            slot_id,
            auction_id: auction_id.to_string(),
            slot_index,
            owner_commitment: owner_commitment.to_string(),
            encrypted_bundle_root: encrypted_bundle_root.to_string(),
            access_policy_root: access_policy_root.to_string(),
            nullifier: nullifier.to_string(),
            byte_size,
            reserved_height,
            reveal_deadline_height,
            filled_height: None,
            status: WitnessBundleSlotStatus::Reserved,
        };
        slot.validate()?;
        Ok(slot)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_witness_bundle_slot",
            "slot_id": self.slot_id,
            "auction_id": self.auction_id,
            "slot_index": self.slot_index,
            "owner_commitment": self.owner_commitment,
            "encrypted_bundle_root": self.encrypted_bundle_root,
            "access_policy_root": self.access_policy_root,
            "nullifier": self.nullifier,
            "byte_size": self.byte_size,
            "reserved_height": self.reserved_height,
            "reveal_deadline_height": self.reveal_deadline_height,
            "filled_height": self.filled_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateProofBatchMarketMakerResult<()> {
        ensure_nonempty("slot_id", &self.slot_id)?;
        ensure_nonempty("auction_id", &self.auction_id)?;
        ensure_nonempty("owner_commitment", &self.owner_commitment)?;
        ensure_nonempty("encrypted_bundle_root", &self.encrypted_bundle_root)?;
        ensure_nonempty("access_policy_root", &self.access_policy_root)?;
        ensure_nonempty("nullifier", &self.nullifier)?;
        ensure_positive("byte_size", self.byte_size)?;
        if self.reveal_deadline_height < self.reserved_height {
            return Err(format!("witness slot {} deadline invalid", self.slot_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveAggregationCommitment {
    pub commitment_id: String,
    pub auction_id: String,
    pub quote_id: String,
    pub prover_id: String,
    pub child_proof_root: String,
    pub recursive_proof_root: String,
    pub aggregation_public_input_root: String,
    pub witness_slots_root: String,
    pub recursion_depth: u64,
    pub child_proof_count: u64,
    pub submitted_height: u64,
    pub verified_height: Option<u64>,
    pub status: AggregationCommitmentStatus,
}

impl RecursiveAggregationCommitment {
    pub fn new(
        auction_id: &str,
        quote_id: &str,
        prover_id: &str,
        child_proof_root: &str,
        recursive_proof_root: &str,
        aggregation_public_input_root: &str,
        witness_slots_root: &str,
        recursion_depth: u64,
        child_proof_count: u64,
        submitted_height: u64,
    ) -> PrivateProofBatchMarketMakerResult<Self> {
        ensure_nonempty("auction_id", auction_id)?;
        ensure_nonempty("quote_id", quote_id)?;
        ensure_nonempty("prover_id", prover_id)?;
        ensure_nonempty("child_proof_root", child_proof_root)?;
        ensure_nonempty("recursive_proof_root", recursive_proof_root)?;
        ensure_nonempty(
            "aggregation_public_input_root",
            aggregation_public_input_root,
        )?;
        ensure_nonempty("witness_slots_root", witness_slots_root)?;
        ensure_positive("child_proof_count", child_proof_count)?;
        if recursion_depth > PRIVATE_PROOF_BATCH_MARKET_MAKER_MAX_RECURSION_DEPTH {
            return Err("aggregation commitment recursion depth exceeds maximum".to_string());
        }
        if child_proof_count > PRIVATE_PROOF_BATCH_MARKET_MAKER_MAX_CHILD_PROOFS {
            return Err("aggregation commitment child proof count exceeds maximum".to_string());
        }
        let seed = json!({
            "auction_id": auction_id,
            "quote_id": quote_id,
            "prover_id": prover_id,
            "child_proof_root": child_proof_root,
            "recursive_proof_root": recursive_proof_root,
            "aggregation_public_input_root": aggregation_public_input_root,
            "witness_slots_root": witness_slots_root,
            "recursion_depth": recursion_depth,
            "child_proof_count": child_proof_count,
            "submitted_height": submitted_height,
        });
        let commitment_id = private_proof_batch_payload_root("AGGREGATION_COMMITMENT_ID", &seed);
        let commitment = Self {
            commitment_id,
            auction_id: auction_id.to_string(),
            quote_id: quote_id.to_string(),
            prover_id: prover_id.to_string(),
            child_proof_root: child_proof_root.to_string(),
            recursive_proof_root: recursive_proof_root.to_string(),
            aggregation_public_input_root: aggregation_public_input_root.to_string(),
            witness_slots_root: witness_slots_root.to_string(),
            recursion_depth,
            child_proof_count,
            submitted_height,
            verified_height: None,
            status: AggregationCommitmentStatus::Submitted,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_aggregation_commitment",
            "commitment_id": self.commitment_id,
            "auction_id": self.auction_id,
            "quote_id": self.quote_id,
            "prover_id": self.prover_id,
            "child_proof_root": self.child_proof_root,
            "recursive_proof_root": self.recursive_proof_root,
            "aggregation_public_input_root": self.aggregation_public_input_root,
            "witness_slots_root": self.witness_slots_root,
            "recursion_depth": self.recursion_depth,
            "child_proof_count": self.child_proof_count,
            "submitted_height": self.submitted_height,
            "verified_height": self.verified_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateProofBatchMarketMakerResult<()> {
        ensure_nonempty("commitment_id", &self.commitment_id)?;
        ensure_nonempty("auction_id", &self.auction_id)?;
        ensure_nonempty("quote_id", &self.quote_id)?;
        ensure_nonempty("prover_id", &self.prover_id)?;
        ensure_nonempty("child_proof_root", &self.child_proof_root)?;
        ensure_nonempty("recursive_proof_root", &self.recursive_proof_root)?;
        ensure_nonempty(
            "aggregation_public_input_root",
            &self.aggregation_public_input_root,
        )?;
        ensure_nonempty("witness_slots_root", &self.witness_slots_root)?;
        ensure_positive("child_proof_count", self.child_proof_count)?;
        if self.recursion_depth > PRIVATE_PROOF_BATCH_MARKET_MAKER_MAX_RECURSION_DEPTH {
            return Err(format!(
                "aggregation commitment {} recursion depth exceeds maximum",
                self.commitment_id
            ));
        }
        if self.child_proof_count > PRIVATE_PROOF_BATCH_MARKET_MAKER_MAX_CHILD_PROOFS {
            return Err(format!(
                "aggregation commitment {} child count exceeds maximum",
                self.commitment_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRebateLane {
    pub rebate_lane_id: String,
    pub sponsor_pool_id: Option<String>,
    pub lane: PrivateBatchLane,
    pub eligible_workloads: BTreeSet<PrivateBatchWorkload>,
    pub fee_asset_id: String,
    pub rebate_bps: u64,
    pub max_rebate_units_per_batch: u64,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub created_height: u64,
    pub status: FeeRebateLaneStatus,
}

impl FeeRebateLane {
    pub fn new(
        rebate_lane_id: &str,
        sponsor_pool_id: Option<String>,
        lane: PrivateBatchLane,
        eligible_workloads: BTreeSet<PrivateBatchWorkload>,
        fee_asset_id: &str,
        rebate_bps: u64,
        max_rebate_units_per_batch: u64,
        budget_units: u64,
        created_height: u64,
    ) -> Self {
        Self {
            rebate_lane_id: rebate_lane_id.to_string(),
            sponsor_pool_id,
            lane,
            eligible_workloads,
            fee_asset_id: fee_asset_id.to_string(),
            rebate_bps,
            max_rebate_units_per_batch,
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            created_height,
            status: FeeRebateLaneStatus::Active,
        }
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn can_rebate(&self, auction: &PrivateBatchAuction) -> bool {
        self.status.usable()
            && self.lane == auction.lane
            && self.fee_asset_id == auction.fee_asset_id
            && self.eligible_workloads.contains(&auction.workload)
            && self.available_units() > 0
    }

    pub fn quote_rebate_units(&self, fee_units: u64) -> u64 {
        bps_amount(fee_units, self.rebate_bps).min(self.max_rebate_units_per_batch)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_rebate_lane",
            "rebate_lane_id": self.rebate_lane_id,
            "sponsor_pool_id": self.sponsor_pool_id,
            "lane": self.lane.as_str(),
            "eligible_workloads": self.eligible_workloads.iter().map(|workload| workload.as_str()).collect::<Vec<_>>(),
            "fee_asset_id": self.fee_asset_id,
            "rebate_bps": self.rebate_bps,
            "max_rebate_units_per_batch": self.max_rebate_units_per_batch,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "created_height": self.created_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(
        &self,
        config: &PrivateProofBatchMarketMakerConfig,
    ) -> PrivateProofBatchMarketMakerResult<()> {
        ensure_nonempty("rebate_lane_id", &self.rebate_lane_id)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_bps("rebate_bps", self.rebate_bps)?;
        ensure_positive(
            "max_rebate_units_per_batch",
            self.max_rebate_units_per_batch,
        )?;
        ensure_positive("budget_units", self.budget_units)?;
        if self.eligible_workloads.is_empty() {
            return Err(format!(
                "rebate lane {} requires workloads",
                self.rebate_lane_id
            ));
        }
        if self.rebate_bps > config.default_rebate_bps {
            return Err(format!(
                "rebate lane {} exceeds default rebate cap",
                self.rebate_lane_id
            ));
        }
        if self.reserved_units.saturating_add(self.spent_units) > self.budget_units {
            return Err(format!("rebate lane {} over-reserved", self.rebate_lane_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorPool {
    pub sponsor_pool_id: String,
    pub sponsor_id: String,
    pub fee_asset_id: String,
    pub eligible_lanes: BTreeSet<PrivateBatchLane>,
    pub eligible_workloads: BTreeSet<PrivateBatchWorkload>,
    pub deposit_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub slashed_units: u64,
    pub max_fee_micro_units: u64,
    pub max_rebate_bps: u64,
    pub created_height: u64,
    pub last_accounted_height: u64,
    pub status: SponsorPoolStatus,
}

impl SponsorPool {
    pub fn new(
        sponsor_pool_id: &str,
        sponsor_id: &str,
        fee_asset_id: &str,
        eligible_lanes: BTreeSet<PrivateBatchLane>,
        eligible_workloads: BTreeSet<PrivateBatchWorkload>,
        deposit_units: u64,
        max_fee_micro_units: u64,
        max_rebate_bps: u64,
        created_height: u64,
    ) -> Self {
        Self {
            sponsor_pool_id: sponsor_pool_id.to_string(),
            sponsor_id: sponsor_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            eligible_lanes,
            eligible_workloads,
            deposit_units,
            reserved_units: 0,
            spent_units: 0,
            slashed_units: 0,
            max_fee_micro_units,
            max_rebate_bps,
            created_height,
            last_accounted_height: created_height,
            status: SponsorPoolStatus::Active,
        }
    }

    pub fn available_units(&self) -> u64 {
        self.deposit_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
            .saturating_sub(self.slashed_units)
    }

    pub fn can_sponsor(&self, auction: &PrivateBatchAuction) -> bool {
        self.status.usable()
            && self.fee_asset_id == auction.fee_asset_id
            && self.eligible_lanes.contains(&auction.lane)
            && self.eligible_workloads.contains(&auction.workload)
            && auction.max_fee_micro_units <= self.max_fee_micro_units
            && self.available_units() > 0
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sponsor_pool",
            "sponsor_pool_id": self.sponsor_pool_id,
            "sponsor_id": self.sponsor_id,
            "fee_asset_id": self.fee_asset_id,
            "eligible_lanes": self.eligible_lanes.iter().map(|lane| lane.as_str()).collect::<Vec<_>>(),
            "eligible_workloads": self.eligible_workloads.iter().map(|workload| workload.as_str()).collect::<Vec<_>>(),
            "deposit_units": self.deposit_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "slashed_units": self.slashed_units,
            "available_units": self.available_units(),
            "max_fee_micro_units": self.max_fee_micro_units,
            "max_rebate_bps": self.max_rebate_bps,
            "created_height": self.created_height,
            "last_accounted_height": self.last_accounted_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(
        &self,
        config: &PrivateProofBatchMarketMakerConfig,
    ) -> PrivateProofBatchMarketMakerResult<()> {
        ensure_nonempty("sponsor_pool_id", &self.sponsor_pool_id)?;
        ensure_nonempty("sponsor_id", &self.sponsor_id)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_positive("deposit_units", self.deposit_units)?;
        ensure_positive("max_fee_micro_units", self.max_fee_micro_units)?;
        ensure_bps("max_rebate_bps", self.max_rebate_bps)?;
        if self.deposit_units < config.min_sponsor_deposit_units {
            return Err(format!(
                "sponsor pool {} deposit below minimum",
                self.sponsor_pool_id
            ));
        }
        if self.max_rebate_bps > config.default_rebate_bps {
            return Err(format!(
                "sponsor pool {} rebate bps exceeds config",
                self.sponsor_pool_id
            ));
        }
        if self.eligible_lanes.is_empty() || self.eligible_workloads.is_empty() {
            return Err(format!(
                "sponsor pool {} requires lanes and workloads",
                self.sponsor_pool_id
            ));
        }
        if self
            .reserved_units
            .saturating_add(self.spent_units)
            .saturating_add(self.slashed_units)
            > self.deposit_units
        {
            return Err(format!("sponsor pool {} overdrawn", self.sponsor_pool_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchFailureChallenge {
    pub challenge_id: String,
    pub auction_id: String,
    pub target_quote_id: Option<String>,
    pub target_commitment_id: Option<String>,
    pub challenger_id: String,
    pub reason: BatchSlashingReason,
    pub evidence_root: String,
    pub opened_height: u64,
    pub deadline_height: u64,
    pub resolved_height: Option<u64>,
    pub slash_bps: u64,
    pub status: BatchFailureChallengeStatus,
}

impl BatchFailureChallenge {
    pub fn new(
        auction_id: &str,
        target_quote_id: Option<String>,
        target_commitment_id: Option<String>,
        challenger_id: &str,
        reason: BatchSlashingReason,
        evidence_root: &str,
        opened_height: u64,
        config: &PrivateProofBatchMarketMakerConfig,
    ) -> PrivateProofBatchMarketMakerResult<Self> {
        ensure_nonempty("auction_id", auction_id)?;
        ensure_nonempty("challenger_id", challenger_id)?;
        ensure_nonempty("evidence_root", evidence_root)?;
        let slash_bps = if reason == BatchSlashingReason::LateProof {
            config.late_slashing_bps
        } else {
            config.slashing_bps
        };
        let deadline_height = opened_height.saturating_add(config.challenge_window_blocks);
        let seed = json!({
            "auction_id": auction_id,
            "target_quote_id": target_quote_id,
            "target_commitment_id": target_commitment_id,
            "challenger_id": challenger_id,
            "reason": reason.as_str(),
            "evidence_root": evidence_root,
            "opened_height": opened_height,
        });
        let challenge_id = private_proof_batch_payload_root("BATCH_FAILURE_CHALLENGE_ID", &seed);
        let challenge = Self {
            challenge_id,
            auction_id: auction_id.to_string(),
            target_quote_id,
            target_commitment_id,
            challenger_id: challenger_id.to_string(),
            reason,
            evidence_root: evidence_root.to_string(),
            opened_height,
            deadline_height,
            resolved_height: None,
            slash_bps,
            status: BatchFailureChallengeStatus::Open,
        };
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "batch_failure_challenge",
            "challenge_id": self.challenge_id,
            "auction_id": self.auction_id,
            "target_quote_id": self.target_quote_id,
            "target_commitment_id": self.target_commitment_id,
            "challenger_id": self.challenger_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "opened_height": self.opened_height,
            "deadline_height": self.deadline_height,
            "resolved_height": self.resolved_height,
            "slash_bps": self.slash_bps,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> PrivateProofBatchMarketMakerResult<()> {
        ensure_nonempty("challenge_id", &self.challenge_id)?;
        ensure_nonempty("auction_id", &self.auction_id)?;
        ensure_nonempty("challenger_id", &self.challenger_id)?;
        ensure_nonempty("evidence_root", &self.evidence_root)?;
        ensure_bps("slash_bps", self.slash_bps)?;
        if self.deadline_height < self.opened_height {
            return Err(format!(
                "challenge {} deadline before open height",
                self.challenge_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchSlashingRecord {
    pub slashing_id: String,
    pub auction_id: String,
    pub quote_id: Option<String>,
    pub commitment_id: Option<String>,
    pub sponsor_pool_id: Option<String>,
    pub challenge_id: Option<String>,
    pub target_id: String,
    pub reason: BatchSlashingReason,
    pub base_amount_units: u64,
    pub slashed_units: u64,
    pub slash_bps: u64,
    pub evidence_root: String,
    pub slashed_height: u64,
}

impl BatchSlashingRecord {
    pub fn new(
        auction_id: &str,
        quote_id: Option<String>,
        commitment_id: Option<String>,
        sponsor_pool_id: Option<String>,
        challenge_id: Option<String>,
        target_id: &str,
        reason: BatchSlashingReason,
        base_amount_units: u64,
        slash_bps: u64,
        evidence_root: &str,
        slashed_height: u64,
    ) -> PrivateProofBatchMarketMakerResult<Self> {
        ensure_nonempty("auction_id", auction_id)?;
        ensure_nonempty("target_id", target_id)?;
        ensure_nonempty("evidence_root", evidence_root)?;
        ensure_positive("base_amount_units", base_amount_units)?;
        ensure_bps("slash_bps", slash_bps)?;
        let slashed_units = bps_amount(base_amount_units, slash_bps);
        ensure_positive("slashed_units", slashed_units)?;
        let seed = json!({
            "auction_id": auction_id,
            "quote_id": quote_id,
            "commitment_id": commitment_id,
            "sponsor_pool_id": sponsor_pool_id,
            "challenge_id": challenge_id,
            "target_id": target_id,
            "reason": reason.as_str(),
            "base_amount_units": base_amount_units,
            "slash_bps": slash_bps,
            "evidence_root": evidence_root,
            "slashed_height": slashed_height,
        });
        let slashing_id = private_proof_batch_payload_root("SLASHING_RECORD_ID", &seed);
        let record = Self {
            slashing_id,
            auction_id: auction_id.to_string(),
            quote_id,
            commitment_id,
            sponsor_pool_id,
            challenge_id,
            target_id: target_id.to_string(),
            reason,
            base_amount_units,
            slashed_units,
            slash_bps,
            evidence_root: evidence_root.to_string(),
            slashed_height,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "batch_slashing_record",
            "slashing_id": self.slashing_id,
            "auction_id": self.auction_id,
            "quote_id": self.quote_id,
            "commitment_id": self.commitment_id,
            "sponsor_pool_id": self.sponsor_pool_id,
            "challenge_id": self.challenge_id,
            "target_id": self.target_id,
            "reason": self.reason.as_str(),
            "base_amount_units": self.base_amount_units,
            "slashed_units": self.slashed_units,
            "slash_bps": self.slash_bps,
            "evidence_root": self.evidence_root,
            "slashed_height": self.slashed_height,
        })
    }

    pub fn validate(&self) -> PrivateProofBatchMarketMakerResult<()> {
        ensure_nonempty("slashing_id", &self.slashing_id)?;
        ensure_nonempty("auction_id", &self.auction_id)?;
        ensure_nonempty("target_id", &self.target_id)?;
        ensure_nonempty("evidence_root", &self.evidence_root)?;
        ensure_positive("base_amount_units", self.base_amount_units)?;
        ensure_positive("slashed_units", self.slashed_units)?;
        ensure_bps("slash_bps", self.slash_bps)?;
        if self.slashed_units > self.base_amount_units {
            return Err(format!("slashing {} exceeds base", self.slashing_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateProofBatchMarketMakerCounters {
    pub auctions: u64,
    pub live_auctions: u64,
    pub quotes: u64,
    pub open_quotes: u64,
    pub accepted_quotes: u64,
    pub witness_slots: u64,
    pub filled_witness_slots: u64,
    pub aggregation_commitments: u64,
    pub verified_aggregation_commitments: u64,
    pub rebate_lanes: u64,
    pub active_rebate_lanes: u64,
    pub sponsor_pools: u64,
    pub active_sponsor_pools: u64,
    pub challenges: u64,
    pub open_challenges: u64,
    pub slashing_records: u64,
    pub total_sponsor_deposit_units: u64,
    pub total_sponsor_reserved_units: u64,
    pub total_sponsor_spent_units: u64,
    pub total_rebate_budget_units: u64,
    pub total_rebate_spent_units: u64,
    pub total_slashed_units: u64,
}

impl PrivateProofBatchMarketMakerCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_proof_batch_market_maker_counters",
            "chain_id": CHAIN_ID,
            "auctions": self.auctions,
            "live_auctions": self.live_auctions,
            "quotes": self.quotes,
            "open_quotes": self.open_quotes,
            "accepted_quotes": self.accepted_quotes,
            "witness_slots": self.witness_slots,
            "filled_witness_slots": self.filled_witness_slots,
            "aggregation_commitments": self.aggregation_commitments,
            "verified_aggregation_commitments": self.verified_aggregation_commitments,
            "rebate_lanes": self.rebate_lanes,
            "active_rebate_lanes": self.active_rebate_lanes,
            "sponsor_pools": self.sponsor_pools,
            "active_sponsor_pools": self.active_sponsor_pools,
            "challenges": self.challenges,
            "open_challenges": self.open_challenges,
            "slashing_records": self.slashing_records,
            "total_sponsor_deposit_units": self.total_sponsor_deposit_units,
            "total_sponsor_reserved_units": self.total_sponsor_reserved_units,
            "total_sponsor_spent_units": self.total_sponsor_spent_units,
            "total_rebate_budget_units": self.total_rebate_budget_units,
            "total_rebate_spent_units": self.total_rebate_spent_units,
            "total_slashed_units": self.total_slashed_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateProofBatchMarketMakerRoots {
    pub config_root: String,
    pub auctions_root: String,
    pub quotes_root: String,
    pub witness_slots_root: String,
    pub aggregation_commitments_root: String,
    pub rebate_lanes_root: String,
    pub sponsor_pools_root: String,
    pub challenges_root: String,
    pub slashing_records_root: String,
    pub workload_fee_caps_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl PrivateProofBatchMarketMakerRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_proof_batch_market_maker_roots",
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "auctions_root": self.auctions_root,
            "quotes_root": self.quotes_root,
            "witness_slots_root": self.witness_slots_root,
            "aggregation_commitments_root": self.aggregation_commitments_root,
            "rebate_lanes_root": self.rebate_lanes_root,
            "sponsor_pools_root": self.sponsor_pools_root,
            "challenges_root": self.challenges_root,
            "slashing_records_root": self.slashing_records_root,
            "workload_fee_caps_root": self.workload_fee_caps_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateProofBatchMarketMakerState {
    pub chain_id: String,
    pub height: u64,
    pub epoch: u64,
    pub config: PrivateProofBatchMarketMakerConfig,
    pub auctions: BTreeMap<String, PrivateBatchAuction>,
    pub quotes: BTreeMap<String, PqProverQuote>,
    pub witness_slots: BTreeMap<String, EncryptedWitnessBundleSlot>,
    pub aggregation_commitments: BTreeMap<String, RecursiveAggregationCommitment>,
    pub rebate_lanes: BTreeMap<String, FeeRebateLane>,
    pub sponsor_pools: BTreeMap<String, SponsorPool>,
    pub challenges: BTreeMap<String, BatchFailureChallenge>,
    pub slashing_records: BTreeMap<String, BatchSlashingRecord>,
    pub workload_fee_caps: BTreeMap<PrivateBatchWorkload, u64>,
}

impl PrivateProofBatchMarketMakerState {
    pub fn new(height: u64, config: PrivateProofBatchMarketMakerConfig) -> Self {
        let epoch = if config.epoch_blocks == 0 {
            0
        } else {
            height / config.epoch_blocks
        };
        let mut workload_fee_caps = BTreeMap::new();
        for workload in private_batch_all_workloads() {
            workload_fee_caps.insert(workload, config.fee_cap_for(workload));
        }
        Self {
            chain_id: CHAIN_ID.to_string(),
            height,
            epoch,
            config,
            auctions: BTreeMap::new(),
            quotes: BTreeMap::new(),
            witness_slots: BTreeMap::new(),
            aggregation_commitments: BTreeMap::new(),
            rebate_lanes: BTreeMap::new(),
            sponsor_pools: BTreeMap::new(),
            challenges: BTreeMap::new(),
            slashing_records: BTreeMap::new(),
            workload_fee_caps,
        }
    }

    pub fn devnet() -> PrivateProofBatchMarketMakerResult<Self> {
        let mut state = Self::new(1, PrivateProofBatchMarketMakerConfig::devnet());
        let mut lanes = BTreeSet::new();
        lanes.insert(PrivateBatchLane::LowFeeRetail);
        lanes.insert(PrivateBatchLane::DefiExecution);
        lanes.insert(PrivateBatchLane::SmartContracts);
        lanes.insert(PrivateBatchLane::RecursiveFastLane);
        let mut workloads = BTreeSet::new();
        workloads.insert(PrivateBatchWorkload::PrivateTransfer);
        workloads.insert(PrivateBatchWorkload::PrivateSwap);
        workloads.insert(PrivateBatchWorkload::PrivateLending);
        workloads.insert(PrivateBatchWorkload::SmartContractCall);
        workloads.insert(PrivateBatchWorkload::RecursiveAggregation);
        workloads.insert(PrivateBatchWorkload::RebateAccounting);
        let sponsor_pool = SponsorPool::new(
            "sponsor-pool:devnet-low-fee-private-batches",
            "sponsor:devnet-low-fee-private-batches",
            &state.config.default_fee_asset_id,
            lanes.clone(),
            workloads.clone(),
            5_000_000,
            state.config.max_base_fee_micro_units,
            state.config.default_rebate_bps,
            state.height,
        );
        let rebate_lane = FeeRebateLane::new(
            "rebate-lane:devnet-low-fee-retail",
            Some(sponsor_pool.sponsor_pool_id.clone()),
            PrivateBatchLane::LowFeeRetail,
            workloads.clone(),
            &state.config.default_fee_asset_id,
            state.config.default_rebate_bps,
            2_000,
            1_000_000,
            state.height,
        );
        let sponsor_pool_id = state.register_sponsor_pool(sponsor_pool)?;
        let rebate_lane_id = state.register_rebate_lane(rebate_lane)?;
        let witness_root = private_proof_batch_string_root("DEVNET_WITNESS_ROOT", "retail-batch");
        let nullifier_root =
            private_proof_batch_string_root("DEVNET_NULLIFIER_ROOT", "retail-batch");
        let public_input_root =
            private_proof_batch_string_root("DEVNET_PUBLIC_INPUT_ROOT", "retail-batch");
        let auction = PrivateBatchAuction::new(
            "maker:devnet-low-fee-retail",
            PrivateBatchLane::LowFeeRetail,
            PrivateBatchWorkload::PrivateTransfer,
            &state.config.default_fee_asset_id,
            16,
            800,
            &witness_root,
            &nullifier_root,
            &public_input_root,
            state.height,
            &state.config,
            0,
        )?;
        let auction_id = state.open_auction(auction)?;
        state.attach_sponsor_pool(&auction_id, &sponsor_pool_id)?;
        state.attach_rebate_lane(&auction_id, &rebate_lane_id)?;
        for slot_index in 0..4 {
            let slot = EncryptedWitnessBundleSlot::new(
                &auction_id,
                slot_index,
                &private_proof_batch_string_root("DEVNET_WITNESS_OWNER", &slot_index.to_string()),
                &private_proof_batch_string_root(
                    "DEVNET_ENCRYPTED_WITNESS",
                    &slot_index.to_string(),
                ),
                &private_proof_batch_string_root("DEVNET_ACCESS_POLICY", "threshold"),
                &private_proof_batch_string_root(
                    "DEVNET_WITNESS_NULLIFIER",
                    &slot_index.to_string(),
                ),
                4096,
                state.height,
                state.height.saturating_add(12),
            )?;
            state.reserve_witness_slot(slot)?;
        }
        let auction_snapshot = state
            .auctions
            .get(&auction_id)
            .cloned()
            .ok_or_else(|| "devnet auction missing after insert".to_string())?;
        let quote = PqProverQuote::new(
            &auction_snapshot,
            "prover:devnet-pq-batch-fast-a",
            "pqpk:devnet-ml-dsa-87-batch-fast-a",
            &private_proof_batch_string_root("DEVNET_PROVER_ATTESTATION", "fast-a"),
            620,
            state.config.min_prover_stake_units,
            64,
            16,
            4,
            64,
            state.height,
            &state.config,
        )?;
        let quote_id = state.submit_quote(quote)?;
        state.accept_quote(&auction_id, &quote_id)?;
        state.mark_auction_proving(&auction_id)?;
        let slots_root = state.witness_slots_root_for_auction(&auction_id);
        let commitment = RecursiveAggregationCommitment::new(
            &auction_id,
            &quote_id,
            "prover:devnet-pq-batch-fast-a",
            &private_proof_batch_string_root("DEVNET_CHILD_PROOFS", "retail-batch"),
            &private_proof_batch_string_root("DEVNET_RECURSIVE_PROOF", "retail-batch"),
            &private_proof_batch_string_root("DEVNET_AGGREGATION_INPUT", "retail-batch"),
            &slots_root,
            2,
            16,
            state.height,
        )?;
        let commitment_id = state.submit_aggregation_commitment(commitment)?;
        state.verify_aggregation_commitment(&commitment_id)?;
        state.issue_rebate(&auction_id, 620)?;
        state.settle_auction(&auction_id)?;
        state.validate()?;
        Ok(state)
    }

    pub fn update_height(&mut self, new_height: u64) -> PrivateProofBatchMarketMakerResult<()> {
        if new_height < self.height {
            return Err("private proof batch market maker height cannot decrease".to_string());
        }
        self.height = new_height;
        self.epoch = self.height / self.config.epoch_blocks;
        self.expire_stale_records();
        Ok(())
    }

    pub fn open_auction(
        &mut self,
        auction: PrivateBatchAuction,
    ) -> PrivateProofBatchMarketMakerResult<String> {
        self.ensure_capacity()?;
        auction.validate(&self.config)?;
        if self.auctions.contains_key(&auction.auction_id) {
            return Err(format!("auction {} already exists", auction.auction_id));
        }
        if auction.opened_height > self.height {
            return Err(format!(
                "auction {} opens in the future",
                auction.auction_id
            ));
        }
        let auction_id = auction.auction_id.clone();
        self.auctions.insert(auction_id.clone(), auction);
        Ok(auction_id)
    }

    pub fn submit_quote(
        &mut self,
        quote: PqProverQuote,
    ) -> PrivateProofBatchMarketMakerResult<String> {
        self.ensure_capacity()?;
        quote.validate(&self.config)?;
        if self.quotes.contains_key(&quote.quote_id) {
            return Err(format!("quote {} already exists", quote.quote_id));
        }
        let auction = self
            .auctions
            .get(&quote.auction_id)
            .ok_or_else(|| format!("unknown auction {}", quote.auction_id))?;
        if auction.status != PrivateBatchAuctionStatus::Open {
            return Err(format!("auction {} is not open", auction.auction_id));
        }
        if self.height > auction.quote_deadline_height {
            return Err(format!(
                "auction {} quote window closed",
                auction.auction_id
            ));
        }
        if quote.fee_asset_id != auction.fee_asset_id {
            return Err(format!("quote {} fee asset mismatch", quote.quote_id));
        }
        if quote.fee_micro_units > auction.max_fee_micro_units {
            return Err(format!("quote {} exceeds auction cap", quote.quote_id));
        }
        let quote_id = quote.quote_id.clone();
        self.quotes.insert(quote_id.clone(), quote);
        Ok(quote_id)
    }

    pub fn accept_quote(
        &mut self,
        auction_id: &str,
        quote_id: &str,
    ) -> PrivateProofBatchMarketMakerResult<()> {
        let quote_snapshot = self
            .quotes
            .get(quote_id)
            .cloned()
            .ok_or_else(|| format!("unknown quote {quote_id}"))?;
        let auction = self
            .auctions
            .get_mut(auction_id)
            .ok_or_else(|| format!("unknown auction {auction_id}"))?;
        if auction.status != PrivateBatchAuctionStatus::Open {
            return Err(format!("auction {auction_id} is not open"));
        }
        if quote_snapshot.auction_id != auction_id {
            return Err(format!(
                "quote {quote_id} does not belong to auction {auction_id}"
            ));
        }
        if self.height > quote_snapshot.expires_height {
            return Err(format!("quote {quote_id} expired"));
        }
        auction.selected_quote_id = Some(quote_id.to_string());
        auction.status = PrivateBatchAuctionStatus::Assigned;
        for quote in self.quotes.values_mut() {
            if quote.auction_id == auction_id {
                quote.status = if quote.quote_id == quote_id {
                    PqProverQuoteStatus::Accepted
                } else {
                    PqProverQuoteStatus::Lost
                };
            }
        }
        Ok(())
    }

    pub fn mark_auction_proving(
        &mut self,
        auction_id: &str,
    ) -> PrivateProofBatchMarketMakerResult<()> {
        let auction = self
            .auctions
            .get_mut(auction_id)
            .ok_or_else(|| format!("unknown auction {auction_id}"))?;
        if auction.status != PrivateBatchAuctionStatus::Assigned {
            return Err(format!("auction {auction_id} is not assigned"));
        }
        auction.status = PrivateBatchAuctionStatus::Proving;
        Ok(())
    }

    pub fn reserve_witness_slot(
        &mut self,
        slot: EncryptedWitnessBundleSlot,
    ) -> PrivateProofBatchMarketMakerResult<String> {
        self.ensure_capacity()?;
        slot.validate()?;
        if self.witness_slots.contains_key(&slot.slot_id) {
            return Err(format!("witness slot {} already exists", slot.slot_id));
        }
        let auction = self
            .auctions
            .get(&slot.auction_id)
            .ok_or_else(|| format!("unknown auction {}", slot.auction_id))?;
        let existing_slots = self
            .witness_slots
            .values()
            .filter(|stored| stored.auction_id == slot.auction_id)
            .count() as u64;
        if existing_slots >= self.config.max_witness_slots {
            return Err(format!(
                "auction {} witness slot cap reached",
                auction.auction_id
            ));
        }
        if slot.reveal_deadline_height < auction.opened_height {
            return Err(format!(
                "witness slot {} deadline before auction",
                slot.slot_id
            ));
        }
        let slot_id = slot.slot_id.clone();
        self.witness_slots.insert(slot_id.clone(), slot);
        Ok(slot_id)
    }

    pub fn fill_witness_slot(
        &mut self,
        slot_id: &str,
        encrypted_bundle_root: &str,
    ) -> PrivateProofBatchMarketMakerResult<()> {
        ensure_nonempty("encrypted_bundle_root", encrypted_bundle_root)?;
        let slot = self
            .witness_slots
            .get_mut(slot_id)
            .ok_or_else(|| format!("unknown witness slot {slot_id}"))?;
        if slot.status != WitnessBundleSlotStatus::Reserved {
            return Err(format!("witness slot {slot_id} is not reserved"));
        }
        if self.height > slot.reveal_deadline_height {
            slot.status = WitnessBundleSlotStatus::Expired;
            return Err(format!("witness slot {slot_id} expired"));
        }
        slot.encrypted_bundle_root = encrypted_bundle_root.to_string();
        slot.filled_height = Some(self.height);
        slot.status = WitnessBundleSlotStatus::Filled;
        Ok(())
    }

    pub fn submit_aggregation_commitment(
        &mut self,
        commitment: RecursiveAggregationCommitment,
    ) -> PrivateProofBatchMarketMakerResult<String> {
        self.ensure_capacity()?;
        commitment.validate()?;
        if self
            .aggregation_commitments
            .contains_key(&commitment.commitment_id)
        {
            return Err(format!(
                "aggregation commitment {} already exists",
                commitment.commitment_id
            ));
        }
        let auction = self
            .auctions
            .get_mut(&commitment.auction_id)
            .ok_or_else(|| format!("unknown auction {}", commitment.auction_id))?;
        if !matches!(
            auction.status,
            PrivateBatchAuctionStatus::Assigned | PrivateBatchAuctionStatus::Proving
        ) {
            return Err(format!("auction {} not awaiting proof", auction.auction_id));
        }
        if auction.selected_quote_id.as_deref() != Some(commitment.quote_id.as_str()) {
            return Err(format!(
                "aggregation commitment {} quote mismatch",
                commitment.commitment_id
            ));
        }
        if self.height > auction.proof_deadline_height {
            auction.status = PrivateBatchAuctionStatus::Expired;
            return Err(format!(
                "auction {} proof missed deadline",
                auction.auction_id
            ));
        }
        let commitment_id = commitment.commitment_id.clone();
        auction.aggregation_commitment_id = Some(commitment_id.clone());
        auction.status = PrivateBatchAuctionStatus::Proved;
        self.aggregation_commitments
            .insert(commitment_id.clone(), commitment);
        Ok(commitment_id)
    }

    pub fn verify_aggregation_commitment(
        &mut self,
        commitment_id: &str,
    ) -> PrivateProofBatchMarketMakerResult<()> {
        let commitment = self
            .aggregation_commitments
            .get_mut(commitment_id)
            .ok_or_else(|| format!("unknown aggregation commitment {commitment_id}"))?;
        if commitment.status != AggregationCommitmentStatus::Submitted {
            return Err(format!(
                "aggregation commitment {commitment_id} is not submitted"
            ));
        }
        let auction = self
            .auctions
            .get_mut(&commitment.auction_id)
            .ok_or_else(|| format!("unknown auction {}", commitment.auction_id))?;
        if self.height > auction.aggregation_deadline_height {
            auction.status = PrivateBatchAuctionStatus::Expired;
            return Err(format!(
                "auction {} aggregation missed deadline",
                auction.auction_id
            ));
        }
        commitment.verified_height = Some(self.height);
        commitment.status = AggregationCommitmentStatus::Verified;
        auction.status = PrivateBatchAuctionStatus::Aggregated;
        Ok(())
    }

    pub fn register_rebate_lane(
        &mut self,
        rebate_lane: FeeRebateLane,
    ) -> PrivateProofBatchMarketMakerResult<String> {
        self.ensure_capacity()?;
        rebate_lane.validate(&self.config)?;
        if self.rebate_lanes.contains_key(&rebate_lane.rebate_lane_id) {
            return Err(format!(
                "rebate lane {} already exists",
                rebate_lane.rebate_lane_id
            ));
        }
        let rebate_lane_id = rebate_lane.rebate_lane_id.clone();
        self.rebate_lanes
            .insert(rebate_lane_id.clone(), rebate_lane);
        Ok(rebate_lane_id)
    }

    pub fn register_sponsor_pool(
        &mut self,
        sponsor_pool: SponsorPool,
    ) -> PrivateProofBatchMarketMakerResult<String> {
        self.ensure_capacity()?;
        sponsor_pool.validate(&self.config)?;
        if self
            .sponsor_pools
            .contains_key(&sponsor_pool.sponsor_pool_id)
        {
            return Err(format!(
                "sponsor pool {} already exists",
                sponsor_pool.sponsor_pool_id
            ));
        }
        let sponsor_pool_id = sponsor_pool.sponsor_pool_id.clone();
        self.sponsor_pools
            .insert(sponsor_pool_id.clone(), sponsor_pool);
        Ok(sponsor_pool_id)
    }

    pub fn attach_sponsor_pool(
        &mut self,
        auction_id: &str,
        sponsor_pool_id: &str,
    ) -> PrivateProofBatchMarketMakerResult<()> {
        let auction_snapshot = self
            .auctions
            .get(auction_id)
            .cloned()
            .ok_or_else(|| format!("unknown auction {auction_id}"))?;
        let sponsor_pool = self
            .sponsor_pools
            .get_mut(sponsor_pool_id)
            .ok_or_else(|| format!("unknown sponsor pool {sponsor_pool_id}"))?;
        if !sponsor_pool.can_sponsor(&auction_snapshot) {
            return Err(format!(
                "sponsor pool {sponsor_pool_id} cannot sponsor auction {auction_id}"
            ));
        }
        let reserve_units = auction_snapshot
            .max_fee_micro_units
            .saturating_mul(auction_snapshot.batch_size);
        if sponsor_pool.available_units() < reserve_units {
            return Err(format!(
                "sponsor pool {sponsor_pool_id} lacks available balance"
            ));
        }
        sponsor_pool.reserved_units = sponsor_pool.reserved_units.saturating_add(reserve_units);
        sponsor_pool.last_accounted_height = self.height;
        let auction = self
            .auctions
            .get_mut(auction_id)
            .ok_or_else(|| format!("unknown auction {auction_id}"))?;
        auction.sponsor_pool_id = Some(sponsor_pool_id.to_string());
        Ok(())
    }

    pub fn attach_rebate_lane(
        &mut self,
        auction_id: &str,
        rebate_lane_id: &str,
    ) -> PrivateProofBatchMarketMakerResult<()> {
        let auction_snapshot = self
            .auctions
            .get(auction_id)
            .cloned()
            .ok_or_else(|| format!("unknown auction {auction_id}"))?;
        let rebate_lane = self
            .rebate_lanes
            .get(rebate_lane_id)
            .ok_or_else(|| format!("unknown rebate lane {rebate_lane_id}"))?;
        if !rebate_lane.can_rebate(&auction_snapshot) {
            return Err(format!(
                "rebate lane {rebate_lane_id} cannot rebate auction {auction_id}"
            ));
        }
        let auction = self
            .auctions
            .get_mut(auction_id)
            .ok_or_else(|| format!("unknown auction {auction_id}"))?;
        auction.rebate_lane_id = Some(rebate_lane_id.to_string());
        Ok(())
    }

    pub fn issue_rebate(
        &mut self,
        auction_id: &str,
        paid_fee_units: u64,
    ) -> PrivateProofBatchMarketMakerResult<u64> {
        ensure_positive("paid_fee_units", paid_fee_units)?;
        let auction_snapshot = self
            .auctions
            .get(auction_id)
            .cloned()
            .ok_or_else(|| format!("unknown auction {auction_id}"))?;
        if auction_snapshot.status != PrivateBatchAuctionStatus::Aggregated {
            return Err(format!("auction {auction_id} is not aggregated"));
        }
        let rebate_lane_id = auction_snapshot
            .rebate_lane_id
            .clone()
            .ok_or_else(|| format!("auction {auction_id} has no rebate lane"))?;
        let rebate_lane = self
            .rebate_lanes
            .get_mut(&rebate_lane_id)
            .ok_or_else(|| format!("unknown rebate lane {rebate_lane_id}"))?;
        if !rebate_lane.can_rebate(&auction_snapshot) {
            return Err(format!(
                "rebate lane {rebate_lane_id} cannot rebate auction {auction_id}"
            ));
        }
        let rebate_units = rebate_lane
            .quote_rebate_units(paid_fee_units)
            .min(rebate_lane.available_units());
        ensure_positive("rebate_units", rebate_units)?;
        rebate_lane.spent_units = rebate_lane.spent_units.saturating_add(rebate_units);
        if rebate_lane.available_units() == 0 {
            rebate_lane.status = FeeRebateLaneStatus::Depleted;
        }
        let auction = self
            .auctions
            .get_mut(auction_id)
            .ok_or_else(|| format!("unknown auction {auction_id}"))?;
        auction.status = PrivateBatchAuctionStatus::Aggregated;
        Ok(rebate_units)
    }

    pub fn settle_auction(&mut self, auction_id: &str) -> PrivateProofBatchMarketMakerResult<()> {
        let auction_snapshot = self
            .auctions
            .get(auction_id)
            .cloned()
            .ok_or_else(|| format!("unknown auction {auction_id}"))?;
        if auction_snapshot.status != PrivateBatchAuctionStatus::Aggregated {
            return Err(format!("auction {auction_id} is not aggregated"));
        }
        if let Some(sponsor_pool_id) = &auction_snapshot.sponsor_pool_id {
            let sponsor_pool = self
                .sponsor_pools
                .get_mut(sponsor_pool_id)
                .ok_or_else(|| format!("unknown sponsor pool {sponsor_pool_id}"))?;
            let reserve_units = auction_snapshot
                .max_fee_micro_units
                .saturating_mul(auction_snapshot.batch_size);
            let released_units = reserve_units.min(sponsor_pool.reserved_units);
            sponsor_pool.reserved_units =
                sponsor_pool.reserved_units.saturating_sub(released_units);
            sponsor_pool.spent_units = sponsor_pool
                .spent_units
                .saturating_add(released_units.min(sponsor_pool.available_units()));
            sponsor_pool.last_accounted_height = self.height;
            if sponsor_pool.available_units() == 0 {
                sponsor_pool.status = SponsorPoolStatus::Depleted;
            }
        }
        let auction = self
            .auctions
            .get_mut(auction_id)
            .ok_or_else(|| format!("unknown auction {auction_id}"))?;
        auction.status = PrivateBatchAuctionStatus::Settled;
        Ok(())
    }

    pub fn open_challenge(
        &mut self,
        challenge: BatchFailureChallenge,
    ) -> PrivateProofBatchMarketMakerResult<String> {
        self.ensure_capacity()?;
        challenge.validate()?;
        if self.challenges.contains_key(&challenge.challenge_id) {
            return Err(format!(
                "challenge {} already exists",
                challenge.challenge_id
            ));
        }
        let auction = self
            .auctions
            .get_mut(&challenge.auction_id)
            .ok_or_else(|| format!("unknown auction {}", challenge.auction_id))?;
        if let Some(quote_id) = &challenge.target_quote_id {
            if !self.quotes.contains_key(quote_id) {
                return Err(format!("unknown quote {quote_id}"));
            }
        }
        if let Some(commitment_id) = &challenge.target_commitment_id {
            if !self.aggregation_commitments.contains_key(commitment_id) {
                return Err(format!("unknown aggregation commitment {commitment_id}"));
            }
        }
        let challenge_id = challenge.challenge_id.clone();
        auction.challenge_ids.insert(challenge_id.clone());
        auction.status = PrivateBatchAuctionStatus::Challenged;
        self.challenges.insert(challenge_id.clone(), challenge);
        Ok(challenge_id)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        upheld: bool,
    ) -> PrivateProofBatchMarketMakerResult<Option<String>> {
        let challenge_snapshot = self
            .challenges
            .get(challenge_id)
            .cloned()
            .ok_or_else(|| format!("unknown challenge {challenge_id}"))?;
        if !challenge_snapshot.status.open() {
            return Err(format!("challenge {challenge_id} is not open"));
        }
        let slashing_id = if upheld {
            Some(self.apply_challenge_slash(&challenge_snapshot)?)
        } else {
            None
        };
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| format!("unknown challenge {challenge_id}"))?;
        challenge.resolved_height = Some(self.height);
        challenge.status = if upheld {
            BatchFailureChallengeStatus::Upheld
        } else {
            BatchFailureChallengeStatus::Rejected
        };
        if let Some(auction) = self.auctions.get_mut(&challenge.auction_id) {
            auction.status = if upheld {
                PrivateBatchAuctionStatus::Slashed
            } else {
                PrivateBatchAuctionStatus::Aggregated
            };
        }
        Ok(slashing_id)
    }

    pub fn witness_slots_root_for_auction(&self, auction_id: &str) -> String {
        private_proof_batch_records_root(
            "WITNESS_SLOTS_FOR_AUCTION",
            self.witness_slots
                .values()
                .filter(|slot| slot.auction_id == auction_id)
                .map(EncryptedWitnessBundleSlot::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_proof_batch_market_maker_state",
            "chain_id": self.chain_id,
            "height": self.height,
            "epoch": self.epoch,
            "protocol_version": PRIVATE_PROOF_BATCH_MARKET_MAKER_PROTOCOL_VERSION,
            "schema_version": PRIVATE_PROOF_BATCH_MARKET_MAKER_SCHEMA_VERSION,
            "hash_suite": PRIVATE_PROOF_BATCH_MARKET_MAKER_HASH_SUITE,
            "config": self.config.public_record(),
            "auctions": self.auctions.values().map(PrivateBatchAuction::public_record).collect::<Vec<_>>(),
            "quotes": self.quotes.values().map(PqProverQuote::public_record).collect::<Vec<_>>(),
            "witness_slots": self.witness_slots.values().map(EncryptedWitnessBundleSlot::public_record).collect::<Vec<_>>(),
            "aggregation_commitments": self.aggregation_commitments.values().map(RecursiveAggregationCommitment::public_record).collect::<Vec<_>>(),
            "rebate_lanes": self.rebate_lanes.values().map(FeeRebateLane::public_record).collect::<Vec<_>>(),
            "sponsor_pools": self.sponsor_pools.values().map(SponsorPool::public_record).collect::<Vec<_>>(),
            "challenges": self.challenges.values().map(BatchFailureChallenge::public_record).collect::<Vec<_>>(),
            "slashing_records": self.slashing_records.values().map(BatchSlashingRecord::public_record).collect::<Vec<_>>(),
            "workload_fee_caps": self.workload_fee_caps.iter().map(|(workload, cap)| json!({
                "workload": workload.as_str(),
                "fee_cap_micro_units": cap,
            })).collect::<Vec<_>>(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn counters(&self) -> PrivateProofBatchMarketMakerCounters {
        PrivateProofBatchMarketMakerCounters {
            auctions: self.auctions.len() as u64,
            live_auctions: self
                .auctions
                .values()
                .filter(|auction| auction.status.live())
                .count() as u64,
            quotes: self.quotes.len() as u64,
            open_quotes: self
                .quotes
                .values()
                .filter(|quote| quote.status == PqProverQuoteStatus::Open)
                .count() as u64,
            accepted_quotes: self
                .quotes
                .values()
                .filter(|quote| quote.status == PqProverQuoteStatus::Accepted)
                .count() as u64,
            witness_slots: self.witness_slots.len() as u64,
            filled_witness_slots: self
                .witness_slots
                .values()
                .filter(|slot| {
                    matches!(
                        slot.status,
                        WitnessBundleSlotStatus::Filled | WitnessBundleSlotStatus::Revealed
                    )
                })
                .count() as u64,
            aggregation_commitments: self.aggregation_commitments.len() as u64,
            verified_aggregation_commitments: self
                .aggregation_commitments
                .values()
                .filter(|commitment| commitment.status == AggregationCommitmentStatus::Verified)
                .count() as u64,
            rebate_lanes: self.rebate_lanes.len() as u64,
            active_rebate_lanes: self
                .rebate_lanes
                .values()
                .filter(|lane| lane.status.usable())
                .count() as u64,
            sponsor_pools: self.sponsor_pools.len() as u64,
            active_sponsor_pools: self
                .sponsor_pools
                .values()
                .filter(|pool| pool.status.usable())
                .count() as u64,
            challenges: self.challenges.len() as u64,
            open_challenges: self
                .challenges
                .values()
                .filter(|challenge| challenge.status.open())
                .count() as u64,
            slashing_records: self.slashing_records.len() as u64,
            total_sponsor_deposit_units: self
                .sponsor_pools
                .values()
                .map(|pool| pool.deposit_units)
                .sum(),
            total_sponsor_reserved_units: self
                .sponsor_pools
                .values()
                .map(|pool| pool.reserved_units)
                .sum(),
            total_sponsor_spent_units: self
                .sponsor_pools
                .values()
                .map(|pool| pool.spent_units)
                .sum(),
            total_rebate_budget_units: self
                .rebate_lanes
                .values()
                .map(|lane| lane.budget_units)
                .sum(),
            total_rebate_spent_units: self
                .rebate_lanes
                .values()
                .map(|lane| lane.spent_units)
                .sum(),
            total_slashed_units: self
                .slashing_records
                .values()
                .map(|record| record.slashed_units)
                .sum(),
        }
    }

    pub fn roots(&self) -> PrivateProofBatchMarketMakerRoots {
        let config_root = self.config.state_root();
        let auctions_root = private_proof_batch_records_root(
            "AUCTIONS",
            self.auctions
                .values()
                .map(PrivateBatchAuction::public_record)
                .collect::<Vec<_>>(),
        );
        let quotes_root = private_proof_batch_records_root(
            "QUOTES",
            self.quotes
                .values()
                .map(PqProverQuote::public_record)
                .collect::<Vec<_>>(),
        );
        let witness_slots_root = private_proof_batch_records_root(
            "WITNESS_SLOTS",
            self.witness_slots
                .values()
                .map(EncryptedWitnessBundleSlot::public_record)
                .collect::<Vec<_>>(),
        );
        let aggregation_commitments_root = private_proof_batch_records_root(
            "AGGREGATION_COMMITMENTS",
            self.aggregation_commitments
                .values()
                .map(RecursiveAggregationCommitment::public_record)
                .collect::<Vec<_>>(),
        );
        let rebate_lanes_root = private_proof_batch_records_root(
            "REBATE_LANES",
            self.rebate_lanes
                .values()
                .map(FeeRebateLane::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsor_pools_root = private_proof_batch_records_root(
            "SPONSOR_POOLS",
            self.sponsor_pools
                .values()
                .map(SponsorPool::public_record)
                .collect::<Vec<_>>(),
        );
        let challenges_root = private_proof_batch_records_root(
            "CHALLENGES",
            self.challenges
                .values()
                .map(BatchFailureChallenge::public_record)
                .collect::<Vec<_>>(),
        );
        let slashing_records_root = private_proof_batch_records_root(
            "SLASHING_RECORDS",
            self.slashing_records
                .values()
                .map(BatchSlashingRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let workload_fee_caps_root = private_proof_batch_records_root(
            "WORKLOAD_FEE_CAPS",
            self.workload_fee_caps
                .iter()
                .map(|(workload, cap)| {
                    json!({
                        "workload": workload.as_str(),
                        "fee_cap_micro_units": cap,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let counters_record = self.counters().public_record();
        let counters_root = private_proof_batch_payload_root("COUNTERS", &counters_record);
        let roots_record = json!({
            "chain_id": self.chain_id,
            "height": self.height,
            "epoch": self.epoch,
            "protocol_version": PRIVATE_PROOF_BATCH_MARKET_MAKER_PROTOCOL_VERSION,
            "schema_version": PRIVATE_PROOF_BATCH_MARKET_MAKER_SCHEMA_VERSION,
            "config_root": config_root,
            "auctions_root": auctions_root,
            "quotes_root": quotes_root,
            "witness_slots_root": witness_slots_root,
            "aggregation_commitments_root": aggregation_commitments_root,
            "rebate_lanes_root": rebate_lanes_root,
            "sponsor_pools_root": sponsor_pools_root,
            "challenges_root": challenges_root,
            "slashing_records_root": slashing_records_root,
            "workload_fee_caps_root": workload_fee_caps_root,
            "counters_root": counters_root,
        });
        let state_root = private_proof_batch_payload_root("STATE_ROOT", &roots_record);
        PrivateProofBatchMarketMakerRoots {
            config_root,
            auctions_root,
            quotes_root,
            witness_slots_root,
            aggregation_commitments_root,
            rebate_lanes_root,
            sponsor_pools_root,
            challenges_root,
            slashing_records_root,
            workload_fee_caps_root,
            counters_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn validate(&self) -> PrivateProofBatchMarketMakerResult<()> {
        ensure_nonempty("chain_id", &self.chain_id)?;
        if self.chain_id != CHAIN_ID {
            return Err("private proof batch market maker chain id mismatch".to_string());
        }
        self.config.validate()?;
        if self.epoch != self.height / self.config.epoch_blocks {
            return Err("private proof batch market maker epoch mismatch".to_string());
        }
        if self.record_count() > self.config.max_records {
            return Err("private proof batch market maker record cap reached".to_string());
        }
        for (workload, cap) in &self.workload_fee_caps {
            ensure_positive("workload_fee_cap", *cap)?;
            if *cap > self.config.fee_cap_for(*workload) {
                return Err(format!(
                    "workload fee cap for {} exceeds config",
                    workload.as_str()
                ));
            }
        }
        for auction in self.auctions.values() {
            auction.validate(&self.config)?;
            if let Some(quote_id) = &auction.selected_quote_id {
                if !self.quotes.contains_key(quote_id) {
                    return Err(format!(
                        "auction {} references unknown quote",
                        auction.auction_id
                    ));
                }
            }
            if let Some(commitment_id) = &auction.aggregation_commitment_id {
                if !self.aggregation_commitments.contains_key(commitment_id) {
                    return Err(format!(
                        "auction {} references unknown commitment",
                        auction.auction_id
                    ));
                }
            }
            if let Some(sponsor_pool_id) = &auction.sponsor_pool_id {
                if !self.sponsor_pools.contains_key(sponsor_pool_id) {
                    return Err(format!(
                        "auction {} references unknown sponsor pool",
                        auction.auction_id
                    ));
                }
            }
            if let Some(rebate_lane_id) = &auction.rebate_lane_id {
                if !self.rebate_lanes.contains_key(rebate_lane_id) {
                    return Err(format!(
                        "auction {} references unknown rebate lane",
                        auction.auction_id
                    ));
                }
            }
            for challenge_id in &auction.challenge_ids {
                if !self.challenges.contains_key(challenge_id) {
                    return Err(format!(
                        "auction {} references unknown challenge",
                        auction.auction_id
                    ));
                }
            }
        }
        for quote in self.quotes.values() {
            quote.validate(&self.config)?;
            if !self.auctions.contains_key(&quote.auction_id) {
                return Err(format!(
                    "quote {} references unknown auction",
                    quote.quote_id
                ));
            }
        }
        for slot in self.witness_slots.values() {
            slot.validate()?;
            if !self.auctions.contains_key(&slot.auction_id) {
                return Err(format!(
                    "witness slot {} references unknown auction",
                    slot.slot_id
                ));
            }
        }
        for commitment in self.aggregation_commitments.values() {
            commitment.validate()?;
            if !self.auctions.contains_key(&commitment.auction_id) {
                return Err(format!(
                    "commitment {} references unknown auction",
                    commitment.commitment_id
                ));
            }
            if !self.quotes.contains_key(&commitment.quote_id) {
                return Err(format!(
                    "commitment {} references unknown quote",
                    commitment.commitment_id
                ));
            }
        }
        for lane in self.rebate_lanes.values() {
            lane.validate(&self.config)?;
            if let Some(sponsor_pool_id) = &lane.sponsor_pool_id {
                if !self.sponsor_pools.contains_key(sponsor_pool_id) {
                    return Err(format!(
                        "rebate lane {} references unknown sponsor pool",
                        lane.rebate_lane_id
                    ));
                }
            }
        }
        for pool in self.sponsor_pools.values() {
            pool.validate(&self.config)?;
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
            if !self.auctions.contains_key(&challenge.auction_id) {
                return Err(format!(
                    "challenge {} references unknown auction",
                    challenge.challenge_id
                ));
            }
        }
        for record in self.slashing_records.values() {
            record.validate()?;
            if !self.auctions.contains_key(&record.auction_id) {
                return Err(format!(
                    "slashing record {} references unknown auction",
                    record.slashing_id
                ));
            }
        }
        Ok(())
    }

    fn ensure_capacity(&self) -> PrivateProofBatchMarketMakerResult<()> {
        if self.record_count() >= self.config.max_records {
            return Err("private proof batch market maker record cap reached".to_string());
        }
        Ok(())
    }

    fn record_count(&self) -> usize {
        self.auctions
            .len()
            .saturating_add(self.quotes.len())
            .saturating_add(self.witness_slots.len())
            .saturating_add(self.aggregation_commitments.len())
            .saturating_add(self.rebate_lanes.len())
            .saturating_add(self.sponsor_pools.len())
            .saturating_add(self.challenges.len())
            .saturating_add(self.slashing_records.len())
    }

    fn expire_stale_records(&mut self) {
        for auction in self.auctions.values_mut() {
            if auction.status == PrivateBatchAuctionStatus::Open
                && self.height > auction.quote_deadline_height
            {
                auction.status = PrivateBatchAuctionStatus::Expired;
            }
            if matches!(
                auction.status,
                PrivateBatchAuctionStatus::Assigned | PrivateBatchAuctionStatus::Proving
            ) && self.height > auction.proof_deadline_height
            {
                auction.status = PrivateBatchAuctionStatus::Expired;
            }
        }
        for quote in self.quotes.values_mut() {
            if quote.status == PqProverQuoteStatus::Open && self.height > quote.expires_height {
                quote.status = PqProverQuoteStatus::Expired;
            }
        }
        for slot in self.witness_slots.values_mut() {
            if matches!(
                slot.status,
                WitnessBundleSlotStatus::Reserved | WitnessBundleSlotStatus::Filled
            ) && self.height > slot.reveal_deadline_height
            {
                slot.status = WitnessBundleSlotStatus::Expired;
            }
        }
        for challenge in self.challenges.values_mut() {
            if challenge.status.open() && self.height > challenge.deadline_height {
                challenge.status = BatchFailureChallengeStatus::Expired;
            }
        }
    }

    fn apply_challenge_slash(
        &mut self,
        challenge: &BatchFailureChallenge,
    ) -> PrivateProofBatchMarketMakerResult<String> {
        let mut base_amount_units = 0;
        let mut target_id = challenge.auction_id.clone();
        if let Some(quote_id) = &challenge.target_quote_id {
            let quote = self
                .quotes
                .get_mut(quote_id)
                .ok_or_else(|| format!("unknown quote {quote_id}"))?;
            base_amount_units = quote.collateral_units;
            target_id = quote.prover_id.clone();
            quote.status = PqProverQuoteStatus::Slashed;
        }
        let sponsor_pool_id = self
            .auctions
            .get(&challenge.auction_id)
            .and_then(|auction| auction.sponsor_pool_id.clone());
        if base_amount_units == 0 {
            if let Some(pool_id) = &sponsor_pool_id {
                let pool = self
                    .sponsor_pools
                    .get(pool_id)
                    .ok_or_else(|| format!("unknown sponsor pool {pool_id}"))?;
                base_amount_units = pool.deposit_units;
                target_id = pool.sponsor_id.clone();
            }
        }
        ensure_positive("base_amount_units", base_amount_units)?;
        let record = BatchSlashingRecord::new(
            &challenge.auction_id,
            challenge.target_quote_id.clone(),
            challenge.target_commitment_id.clone(),
            sponsor_pool_id.clone(),
            Some(challenge.challenge_id.clone()),
            &target_id,
            challenge.reason,
            base_amount_units,
            challenge.slash_bps,
            &challenge.evidence_root,
            self.height,
        )?;
        if let Some(pool_id) = &sponsor_pool_id {
            if let Some(pool) = self.sponsor_pools.get_mut(pool_id) {
                pool.slashed_units = pool.slashed_units.saturating_add(record.slashed_units);
                pool.status = SponsorPoolStatus::Slashed;
                pool.last_accounted_height = self.height;
            }
        }
        if let Some(commitment_id) = &challenge.target_commitment_id {
            if let Some(commitment) = self.aggregation_commitments.get_mut(commitment_id) {
                commitment.status = AggregationCommitmentStatus::Slashed;
            }
        }
        let slashing_id = record.slashing_id.clone();
        self.slashing_records.insert(slashing_id.clone(), record);
        Ok(slashing_id)
    }
}

pub fn private_batch_all_workloads() -> Vec<PrivateBatchWorkload> {
    vec![
        PrivateBatchWorkload::PrivateTransfer,
        PrivateBatchWorkload::PrivateSwap,
        PrivateBatchWorkload::PrivateLending,
        PrivateBatchWorkload::PrivatePerps,
        PrivateBatchWorkload::PrivateVault,
        PrivateBatchWorkload::SmartContractCall,
        PrivateBatchWorkload::TokenMint,
        PrivateBatchWorkload::TokenBurn,
        PrivateBatchWorkload::MoneroBridgeDeposit,
        PrivateBatchWorkload::MoneroBridgeExit,
        PrivateBatchWorkload::RecursiveAggregation,
        PrivateBatchWorkload::RebateAccounting,
        PrivateBatchWorkload::BatchFailureChallenge,
    ]
}

pub fn private_proof_batch_state_root_from_record(record: &Value) -> String {
    private_proof_batch_payload_root("STATE_FROM_RECORD", record)
}

pub fn private_proof_batch_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-PROOF-BATCH-MARKET-MAKER-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn private_proof_batch_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        &format!("PRIVATE-PROOF-BATCH-MARKET-MAKER-{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Str(value)],
        32,
    )
}

pub fn private_proof_batch_records_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!("PRIVATE-PROOF-BATCH-MARKET-MAKER-{domain}"),
        &records,
    )
}

fn ensure_nonempty(name: &str, value: &str) -> PrivateProofBatchMarketMakerResult<()> {
    if value.is_empty() {
        return Err(format!("{name} is required"));
    }
    Ok(())
}

fn ensure_positive(name: &str, value: u64) -> PrivateProofBatchMarketMakerResult<()> {
    if value == 0 {
        return Err(format!("{name} must be positive"));
    }
    Ok(())
}

fn ensure_bps(name: &str, value: u64) -> PrivateProofBatchMarketMakerResult<()> {
    if value > PRIVATE_PROOF_BATCH_MARKET_MAKER_MAX_BPS {
        return Err(format!("{name} exceeds basis point maximum"));
    }
    Ok(())
}

fn bps_amount(amount: u64, bps: u64) -> u64 {
    amount
        .saturating_mul(bps)
        .saturating_div(PRIVATE_PROOF_BATCH_MARKET_MAKER_MAX_BPS)
}
