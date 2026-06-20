use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type RecursivePqProofMarketResult<T> = Result<T, String>;

pub const RECURSIVE_PQ_PROOF_MARKET_PROTOCOL_VERSION: &str =
    "nebula-l2-recursive-pq-proof-market-v1";
pub const RECURSIVE_PQ_PROOF_MARKET_SCHEMA_VERSION: u64 = 1;
pub const RECURSIVE_PQ_PROOF_MARKET_HASH_SUITE: &str = "SHAKE256";
pub const RECURSIVE_PQ_PROOF_MARKET_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const RECURSIVE_PQ_PROOF_MARKET_PQ_RECOVERY_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const RECURSIVE_PQ_PROOF_MARKET_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const RECURSIVE_PQ_PROOF_MARKET_RECURSION_SCHEME: &str = "nebula-devnet-recursive-folding-v1";
pub const RECURSIVE_PQ_PROOF_MARKET_COMPRESSION_SCHEME: &str =
    "shake256-recursive-pq-proof-compression-v1";
pub const RECURSIVE_PQ_PROOF_MARKET_FINALITY_RECEIPT_SCHEME: &str =
    "nebula-devnet-fast-finality-proof-receipt-v1";
pub const RECURSIVE_PQ_PROOF_MARKET_DEFAULT_FEE_ASSET_ID: &str = "asset:wxmr";
pub const RECURSIVE_PQ_PROOF_MARKET_DEFAULT_SECURITY_BITS: u64 = 128;
pub const RECURSIVE_PQ_PROOF_MARKET_DEFAULT_BID_WINDOW_BLOCKS: u64 = 3;
pub const RECURSIVE_PQ_PROOF_MARKET_DEFAULT_JOB_SLA_BLOCKS: u64 = 8;
pub const RECURSIVE_PQ_PROOF_MARKET_DEFAULT_FAST_FINALITY_BLOCKS: u64 = 2;
pub const RECURSIVE_PQ_PROOF_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const RECURSIVE_PQ_PROOF_MARKET_DEFAULT_COMMITTEE_SIZE: u64 = 7;
pub const RECURSIVE_PQ_PROOF_MARKET_DEFAULT_COMMITTEE_THRESHOLD_BPS: u64 = 6_700;
pub const RECURSIVE_PQ_PROOF_MARKET_DEFAULT_SLASHING_BPS: u64 = 5_000;
pub const RECURSIVE_PQ_PROOF_MARKET_DEFAULT_LATE_PENALTY_BPS: u64 = 1_500;
pub const RECURSIVE_PQ_PROOF_MARKET_DEFAULT_SPONSOR_REBATE_BPS: u64 = 4_000;
pub const RECURSIVE_PQ_PROOF_MARKET_MIN_BID_COLLATERAL_BPS: u64 = 2_500;
pub const RECURSIVE_PQ_PROOF_MARKET_MIN_PROVER_STAKE_UNITS: u64 = 5_000;
pub const RECURSIVE_PQ_PROOF_MARKET_LOW_FEE_FLOOR_UNITS: u64 = 4;
pub const RECURSIVE_PQ_PROOF_MARKET_MAX_BPS: u64 = 10_000;
pub const RECURSIVE_PQ_PROOF_MARKET_MAX_RECURSION_DEPTH: u64 = 8;
pub const RECURSIVE_PQ_PROOF_MARKET_MAX_CHILD_PROOFS: u64 = 128;
pub const RECURSIVE_PQ_PROOF_MARKET_MAX_RECORDS: usize = 4_096;

pub const RECURSIVE_PQ_PROOF_MARKET_STATUS_OPEN: &str = "open";
pub const RECURSIVE_PQ_PROOF_MARKET_STATUS_ACTIVE: &str = "active";
pub const RECURSIVE_PQ_PROOF_MARKET_STATUS_ASSIGNED: &str = "assigned";
pub const RECURSIVE_PQ_PROOF_MARKET_STATUS_PROVING: &str = "proving";
pub const RECURSIVE_PQ_PROOF_MARKET_STATUS_PROVED: &str = "proved";
pub const RECURSIVE_PQ_PROOF_MARKET_STATUS_VERIFIED: &str = "verified";
pub const RECURSIVE_PQ_PROOF_MARKET_STATUS_SPONSORED: &str = "sponsored";
pub const RECURSIVE_PQ_PROOF_MARKET_STATUS_FINALIZED: &str = "finalized";
pub const RECURSIVE_PQ_PROOF_MARKET_STATUS_REJECTED: &str = "rejected";
pub const RECURSIVE_PQ_PROOF_MARKET_STATUS_SLASHED: &str = "slashed";
pub const RECURSIVE_PQ_PROOF_MARKET_STATUS_EXPIRED: &str = "expired";
pub const RECURSIVE_PQ_PROOF_MARKET_STATUS_SETTLED: &str = "settled";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursivePqCircuitFamily {
    RollupState,
    MoneroBridge,
    PrivateContract,
    FeeAccounting,
    RecursiveAggregation,
    ReceiptFinality,
}

impl RecursivePqCircuitFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RollupState => "rollup_state",
            Self::MoneroBridge => "monero_bridge",
            Self::PrivateContract => "private_contract",
            Self::FeeAccounting => "fee_accounting",
            Self::RecursiveAggregation => "recursive_aggregation",
            Self::ReceiptFinality => "receipt_finality",
        }
    }

    pub fn default_proof_system(self) -> &'static str {
        match self {
            Self::RollupState => "nebula-devnet-pq-rollup-state-validity-v1",
            Self::MoneroBridge => "nebula-devnet-pq-monero-bridge-validity-v1",
            Self::PrivateContract => "nebula-devnet-pq-private-contract-validity-v1",
            Self::FeeAccounting => "nebula-devnet-pq-fee-accounting-validity-v1",
            Self::RecursiveAggregation => "nebula-devnet-pq-recursive-proof-market-v1",
            Self::ReceiptFinality => "nebula-devnet-pq-fast-finality-receipt-v1",
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::MoneroBridge | Self::PrivateContract | Self::FeeAccounting
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursivePqJobKind {
    BaseProof,
    RecursiveAggregate,
    Compression,
    CommitteeVerification,
    SponsoredProof,
    FinalityReceipt,
    WitnessFetch,
}

impl RecursivePqJobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BaseProof => "base_proof",
            Self::RecursiveAggregate => "recursive_aggregate",
            Self::Compression => "compression",
            Self::CommitteeVerification => "committee_verification",
            Self::SponsoredProof => "sponsored_proof",
            Self::FinalityReceipt => "finality_receipt",
            Self::WitnessFetch => "witness_fetch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursivePqLane {
    Bridge,
    PrivateExecution,
    PublicRollup,
    LowFeePublicGood,
    RecursiveBatch,
    Emergency,
    Maintenance,
}

impl RecursivePqLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bridge => "bridge",
            Self::PrivateExecution => "private_execution",
            Self::PublicRollup => "public_rollup",
            Self::LowFeePublicGood => "low_fee_public_good",
            Self::RecursiveBatch => "recursive_batch",
            Self::Emergency => "emergency",
            Self::Maintenance => "maintenance",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::Bridge => 9_200,
            Self::PrivateExecution => 8_500,
            Self::PublicRollup => 7_000,
            Self::RecursiveBatch => 6_200,
            Self::LowFeePublicGood => 5_800,
            Self::Maintenance => 2_500,
        }
    }

    pub fn low_fee_lane(self) -> bool {
        matches!(self, Self::LowFeePublicGood)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursivePqWorkerClass {
    Cpu,
    Gpu,
    Fpga,
    RecursiveCluster,
    Verifier,
    WitnessRelay,
}

impl RecursivePqWorkerClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
            Self::Fpga => "fpga",
            Self::RecursiveCluster => "recursive_cluster",
            Self::Verifier => "verifier",
            Self::WitnessRelay => "witness_relay",
        }
    }

    pub fn capacity_weight(self) -> u64 {
        match self {
            Self::Cpu => 1,
            Self::Gpu => 8,
            Self::Fpga => 12,
            Self::RecursiveCluster => 16,
            Self::Verifier => 4,
            Self::WitnessRelay => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursivePqBidStatus {
    Open,
    Assigned,
    Won,
    Lost,
    Expired,
    Slashed,
}

impl RecursivePqBidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => RECURSIVE_PQ_PROOF_MARKET_STATUS_OPEN,
            Self::Assigned => RECURSIVE_PQ_PROOF_MARKET_STATUS_ASSIGNED,
            Self::Won => "won",
            Self::Lost => "lost",
            Self::Expired => RECURSIVE_PQ_PROOF_MARKET_STATUS_EXPIRED,
            Self::Slashed => RECURSIVE_PQ_PROOF_MARKET_STATUS_SLASHED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursivePqJobStatus {
    Open,
    Assigned,
    Proving,
    Proved,
    Verified,
    Sponsored,
    Finalized,
    Rejected,
    Expired,
    Settled,
}

impl RecursivePqJobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => RECURSIVE_PQ_PROOF_MARKET_STATUS_OPEN,
            Self::Assigned => RECURSIVE_PQ_PROOF_MARKET_STATUS_ASSIGNED,
            Self::Proving => RECURSIVE_PQ_PROOF_MARKET_STATUS_PROVING,
            Self::Proved => RECURSIVE_PQ_PROOF_MARKET_STATUS_PROVED,
            Self::Verified => RECURSIVE_PQ_PROOF_MARKET_STATUS_VERIFIED,
            Self::Sponsored => RECURSIVE_PQ_PROOF_MARKET_STATUS_SPONSORED,
            Self::Finalized => RECURSIVE_PQ_PROOF_MARKET_STATUS_FINALIZED,
            Self::Rejected => RECURSIVE_PQ_PROOF_MARKET_STATUS_REJECTED,
            Self::Expired => RECURSIVE_PQ_PROOF_MARKET_STATUS_EXPIRED,
            Self::Settled => RECURSIVE_PQ_PROOF_MARKET_STATUS_SETTLED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursivePqCommitteePolicy {
    WeightedThreshold,
    RotatingSubset,
    EmergencyUnanimity,
}

impl RecursivePqCommitteePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WeightedThreshold => "weighted_threshold",
            Self::RotatingSubset => "rotating_subset",
            Self::EmergencyUnanimity => "emergency_unanimity",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursivePqVoteOutcome {
    Accept,
    Reject,
    Abstain,
    NeedsFallback,
}

impl RecursivePqVoteOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Reject => "reject",
            Self::Abstain => "abstain",
            Self::NeedsFallback => "needs_fallback",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursivePqPenaltyKind {
    LateProof,
    InvalidProof,
    MissingWitness,
    CommitteeFault,
    ReceiptMismatch,
}

impl RecursivePqPenaltyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LateProof => "late_proof",
            Self::InvalidProof => "invalid_proof",
            Self::MissingWitness => "missing_witness",
            Self::CommitteeFault => "committee_fault",
            Self::ReceiptMismatch => "receipt_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursivePqWitnessAccessMode {
    ViewKey,
    EncryptedBlob,
    ThresholdReveal,
    LocalNullifier,
}

impl RecursivePqWitnessAccessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewKey => "view_key",
            Self::EncryptedBlob => "encrypted_blob",
            Self::ThresholdReveal => "threshold_reveal",
            Self::LocalNullifier => "local_nullifier",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursivePqReceiptStatus {
    FastAccepted,
    CommitteeFinal,
    ChallengeOpen,
    Rejected,
}

impl RecursivePqReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FastAccepted => "fast_accepted",
            Self::CommitteeFinal => "committee_final",
            Self::ChallengeOpen => "challenge_open",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursivePqProofMarketConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_signature_scheme: String,
    pub pq_recovery_scheme: String,
    pub pq_kem_scheme: String,
    pub recursion_scheme: String,
    pub compression_scheme: String,
    pub finality_receipt_scheme: String,
    pub default_fee_asset_id: String,
    pub security_bits: u64,
    pub bid_window_blocks: u64,
    pub job_sla_blocks: u64,
    pub fast_finality_blocks: u64,
    pub challenge_window_blocks: u64,
    pub default_committee_size: u64,
    pub committee_threshold_bps: u64,
    pub slashing_bps: u64,
    pub late_penalty_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub min_bid_collateral_bps: u64,
    pub min_prover_stake_units: u64,
    pub low_fee_floor_units: u64,
    pub max_recursion_depth: u64,
    pub max_child_proofs: u64,
    pub max_records: usize,
}

impl Default for RecursivePqProofMarketConfig {
    fn default() -> Self {
        Self {
            protocol_version: RECURSIVE_PQ_PROOF_MARKET_PROTOCOL_VERSION.to_string(),
            schema_version: RECURSIVE_PQ_PROOF_MARKET_SCHEMA_VERSION,
            hash_suite: RECURSIVE_PQ_PROOF_MARKET_HASH_SUITE.to_string(),
            pq_signature_scheme: RECURSIVE_PQ_PROOF_MARKET_PQ_SIGNATURE_SCHEME.to_string(),
            pq_recovery_scheme: RECURSIVE_PQ_PROOF_MARKET_PQ_RECOVERY_SCHEME.to_string(),
            pq_kem_scheme: RECURSIVE_PQ_PROOF_MARKET_PQ_KEM_SCHEME.to_string(),
            recursion_scheme: RECURSIVE_PQ_PROOF_MARKET_RECURSION_SCHEME.to_string(),
            compression_scheme: RECURSIVE_PQ_PROOF_MARKET_COMPRESSION_SCHEME.to_string(),
            finality_receipt_scheme: RECURSIVE_PQ_PROOF_MARKET_FINALITY_RECEIPT_SCHEME.to_string(),
            default_fee_asset_id: RECURSIVE_PQ_PROOF_MARKET_DEFAULT_FEE_ASSET_ID.to_string(),
            security_bits: RECURSIVE_PQ_PROOF_MARKET_DEFAULT_SECURITY_BITS,
            bid_window_blocks: RECURSIVE_PQ_PROOF_MARKET_DEFAULT_BID_WINDOW_BLOCKS,
            job_sla_blocks: RECURSIVE_PQ_PROOF_MARKET_DEFAULT_JOB_SLA_BLOCKS,
            fast_finality_blocks: RECURSIVE_PQ_PROOF_MARKET_DEFAULT_FAST_FINALITY_BLOCKS,
            challenge_window_blocks: RECURSIVE_PQ_PROOF_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            default_committee_size: RECURSIVE_PQ_PROOF_MARKET_DEFAULT_COMMITTEE_SIZE,
            committee_threshold_bps: RECURSIVE_PQ_PROOF_MARKET_DEFAULT_COMMITTEE_THRESHOLD_BPS,
            slashing_bps: RECURSIVE_PQ_PROOF_MARKET_DEFAULT_SLASHING_BPS,
            late_penalty_bps: RECURSIVE_PQ_PROOF_MARKET_DEFAULT_LATE_PENALTY_BPS,
            sponsor_rebate_bps: RECURSIVE_PQ_PROOF_MARKET_DEFAULT_SPONSOR_REBATE_BPS,
            min_bid_collateral_bps: RECURSIVE_PQ_PROOF_MARKET_MIN_BID_COLLATERAL_BPS,
            min_prover_stake_units: RECURSIVE_PQ_PROOF_MARKET_MIN_PROVER_STAKE_UNITS,
            low_fee_floor_units: RECURSIVE_PQ_PROOF_MARKET_LOW_FEE_FLOOR_UNITS,
            max_recursion_depth: RECURSIVE_PQ_PROOF_MARKET_MAX_RECURSION_DEPTH,
            max_child_proofs: RECURSIVE_PQ_PROOF_MARKET_MAX_CHILD_PROOFS,
            max_records: RECURSIVE_PQ_PROOF_MARKET_MAX_RECORDS,
        }
    }
}

impl RecursivePqProofMarketConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> RecursivePqProofMarketResult<()> {
        if self.protocol_version.is_empty() {
            return Err("protocol version is required".to_string());
        }
        if self.security_bits < 128 {
            return Err("security bits below post quantum floor".to_string());
        }
        if self.bid_window_blocks == 0 || self.job_sla_blocks == 0 {
            return Err("bid and sla windows must be nonzero".to_string());
        }
        if self.fast_finality_blocks == 0 {
            return Err("fast finality window must be nonzero".to_string());
        }
        if self.committee_threshold_bps == 0
            || self.committee_threshold_bps > RECURSIVE_PQ_PROOF_MARKET_MAX_BPS
        {
            return Err("committee threshold bps is outside range".to_string());
        }
        if self.slashing_bps > RECURSIVE_PQ_PROOF_MARKET_MAX_BPS
            || self.late_penalty_bps > RECURSIVE_PQ_PROOF_MARKET_MAX_BPS
            || self.sponsor_rebate_bps > RECURSIVE_PQ_PROOF_MARKET_MAX_BPS
        {
            return Err("bps value is outside range".to_string());
        }
        if self.default_committee_size == 0 {
            return Err("committee size must be nonzero".to_string());
        }
        if self.max_child_proofs == 0 || self.max_recursion_depth == 0 {
            return Err("recursive proof limits must be nonzero".to_string());
        }
        if self.max_records == 0 {
            return Err("record cap must be nonzero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_pq_proof_market_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_recovery_scheme": self.pq_recovery_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "recursion_scheme": self.recursion_scheme,
            "compression_scheme": self.compression_scheme,
            "finality_receipt_scheme": self.finality_receipt_scheme,
            "default_fee_asset_id": self.default_fee_asset_id,
            "security_bits": self.security_bits,
            "bid_window_blocks": self.bid_window_blocks,
            "job_sla_blocks": self.job_sla_blocks,
            "fast_finality_blocks": self.fast_finality_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "default_committee_size": self.default_committee_size,
            "committee_threshold_bps": self.committee_threshold_bps,
            "slashing_bps": self.slashing_bps,
            "late_penalty_bps": self.late_penalty_bps,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "min_bid_collateral_bps": self.min_bid_collateral_bps,
            "min_prover_stake_units": self.min_prover_stake_units,
            "low_fee_floor_units": self.low_fee_floor_units,
            "max_recursion_depth": self.max_recursion_depth,
            "max_child_proofs": self.max_child_proofs,
            "max_records": self.max_records,
        })
    }

    pub fn config_root(&self) -> String {
        recursive_pq_payload_root("RECURSIVE-PQ-PROOF-MARKET-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursivePqProverBid {
    pub bid_id: String,
    pub prover_id: String,
    pub prover_label: String,
    pub worker_class: RecursivePqWorkerClass,
    pub supported_families: BTreeSet<RecursivePqCircuitFamily>,
    pub max_recursion_depth: u64,
    pub max_child_proofs: u64,
    pub price_per_million_cycles: u64,
    pub collateral_units: u64,
    pub stake_units: u64,
    pub available_from_height: u64,
    pub available_until_height: u64,
    pub nonce: u64,
    pub status: RecursivePqBidStatus,
    pub pq_public_key_root: String,
    pub metadata_root: String,
}

impl RecursivePqProverBid {
    pub fn new(
        prover_label: &str,
        worker_class: RecursivePqWorkerClass,
        supported_families: BTreeSet<RecursivePqCircuitFamily>,
        price_per_million_cycles: u64,
        collateral_units: u64,
        stake_units: u64,
        available_from_height: u64,
        available_until_height: u64,
        nonce: u64,
    ) -> RecursivePqProofMarketResult<Self> {
        if prover_label.is_empty() {
            return Err("prover label is required".to_string());
        }
        if price_per_million_cycles == 0 {
            return Err("bid price must be nonzero".to_string());
        }
        if stake_units < RECURSIVE_PQ_PROOF_MARKET_MIN_PROVER_STAKE_UNITS {
            return Err("prover stake below market minimum".to_string());
        }
        if collateral_units == 0 {
            return Err("bid collateral must be nonzero".to_string());
        }
        if available_until_height < available_from_height {
            return Err("bid availability ends before it starts".to_string());
        }
        let prover_id = recursive_pq_prover_id(prover_label);
        let bid_id = recursive_pq_bid_id(
            &prover_id,
            worker_class.as_str(),
            price_per_million_cycles,
            available_from_height,
            available_until_height,
            nonce,
        );
        Ok(Self {
            bid_id,
            prover_id: prover_id.clone(),
            prover_label: prover_label.to_string(),
            worker_class,
            supported_families,
            max_recursion_depth: RECURSIVE_PQ_PROOF_MARKET_MAX_RECURSION_DEPTH,
            max_child_proofs: RECURSIVE_PQ_PROOF_MARKET_MAX_CHILD_PROOFS,
            price_per_million_cycles,
            collateral_units,
            stake_units,
            available_from_height,
            available_until_height,
            nonce,
            status: RecursivePqBidStatus::Open,
            pq_public_key_root: recursive_pq_string_root(
                "RECURSIVE-PQ-PROVER-PUBLIC-KEY",
                &prover_id,
            ),
            metadata_root: recursive_pq_string_root("RECURSIVE-PQ-PROVER-METADATA", prover_label),
        })
    }

    pub fn supports(&self, family: RecursivePqCircuitFamily) -> bool {
        self.supported_families.is_empty() || self.supported_families.contains(&family)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status == RecursivePqBidStatus::Open
            && height >= self.available_from_height
            && height <= self.available_until_height
    }

    pub fn effective_capacity_units(&self) -> u64 {
        self.worker_class
            .capacity_weight()
            .saturating_mul(self.max_child_proofs)
            .saturating_mul(self.max_recursion_depth)
    }

    pub fn public_record(&self) -> Value {
        let families = self
            .supported_families
            .iter()
            .map(|family| family.as_str())
            .collect::<Vec<_>>();
        json!({
            "kind": "recursive_pq_prover_bid",
            "chain_id": CHAIN_ID,
            "bid_id": self.bid_id,
            "prover_id": self.prover_id,
            "prover_label": self.prover_label,
            "worker_class": self.worker_class.as_str(),
            "supported_families": families,
            "max_recursion_depth": self.max_recursion_depth,
            "max_child_proofs": self.max_child_proofs,
            "effective_capacity_units": self.effective_capacity_units(),
            "price_per_million_cycles": self.price_per_million_cycles,
            "collateral_units": self.collateral_units,
            "stake_units": self.stake_units,
            "available_from_height": self.available_from_height,
            "available_until_height": self.available_until_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "pq_public_key_root": self.pq_public_key_root,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn bid_root(&self) -> String {
        recursive_pq_payload_root("RECURSIVE-PQ-PROVER-BID", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursivePqAggregationJob {
    pub job_id: String,
    pub requester_commitment: String,
    pub job_kind: RecursivePqJobKind,
    pub circuit_family: RecursivePqCircuitFamily,
    pub lane: RecursivePqLane,
    pub proof_system: String,
    pub input_root: String,
    pub child_proof_root: String,
    pub witness_commitment_root: String,
    pub max_fee_units: u64,
    pub estimated_cycles: u64,
    pub recursion_depth: u64,
    pub child_proof_count: u64,
    pub created_at_height: u64,
    pub bid_close_height: u64,
    pub due_height: u64,
    pub assigned_bid_id: Option<String>,
    pub committee_id: Option<String>,
    pub sponsor_id: Option<String>,
    pub status: RecursivePqJobStatus,
    pub output_proof_root: Option<String>,
    pub finality_receipt_id: Option<String>,
}

impl RecursivePqAggregationJob {
    pub fn new(
        requester_commitment: &str,
        job_kind: RecursivePqJobKind,
        circuit_family: RecursivePqCircuitFamily,
        lane: RecursivePqLane,
        input_root: &str,
        child_proof_root: &str,
        witness_commitment_root: &str,
        max_fee_units: u64,
        estimated_cycles: u64,
        recursion_depth: u64,
        child_proof_count: u64,
        created_at_height: u64,
        config: &RecursivePqProofMarketConfig,
        nonce: u64,
    ) -> RecursivePqProofMarketResult<Self> {
        if requester_commitment.is_empty() {
            return Err("requester commitment is required".to_string());
        }
        if input_root.is_empty() || child_proof_root.is_empty() {
            return Err("job input and child proof roots are required".to_string());
        }
        if max_fee_units == 0 {
            return Err("job fee cap must be nonzero".to_string());
        }
        if estimated_cycles == 0 {
            return Err("job cycle estimate must be nonzero".to_string());
        }
        if recursion_depth == 0 || recursion_depth > config.max_recursion_depth {
            return Err("recursion depth is outside market limits".to_string());
        }
        if child_proof_count == 0 || child_proof_count > config.max_child_proofs {
            return Err("child proof count is outside market limits".to_string());
        }
        let bid_close_height = created_at_height.saturating_add(config.bid_window_blocks);
        let due_height = created_at_height.saturating_add(config.job_sla_blocks);
        let job_id = recursive_pq_job_id(
            requester_commitment,
            job_kind.as_str(),
            circuit_family.as_str(),
            input_root,
            child_proof_root,
            created_at_height,
            nonce,
        );
        Ok(Self {
            job_id,
            requester_commitment: requester_commitment.to_string(),
            job_kind,
            circuit_family,
            lane,
            proof_system: circuit_family.default_proof_system().to_string(),
            input_root: input_root.to_string(),
            child_proof_root: child_proof_root.to_string(),
            witness_commitment_root: witness_commitment_root.to_string(),
            max_fee_units,
            estimated_cycles,
            recursion_depth,
            child_proof_count,
            created_at_height,
            bid_close_height,
            due_height,
            assigned_bid_id: None,
            committee_id: None,
            sponsor_id: None,
            status: RecursivePqJobStatus::Open,
            output_proof_root: None,
            finality_receipt_id: None,
        })
    }

    pub fn fee_quote_units(&self, price_per_million_cycles: u64) -> u64 {
        self.estimated_cycles
            .saturating_mul(price_per_million_cycles)
            .saturating_add(999_999)
            / 1_000_000
    }

    pub fn can_accept_bid(&self, bid: &RecursivePqProverBid, height: u64) -> bool {
        self.status == RecursivePqJobStatus::Open
            && height <= self.bid_close_height
            && bid.active_at(height)
            && bid.supports(self.circuit_family)
            && bid.max_recursion_depth >= self.recursion_depth
            && bid.max_child_proofs >= self.child_proof_count
            && self.fee_quote_units(bid.price_per_million_cycles) <= self.max_fee_units
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_pq_aggregation_job",
            "chain_id": CHAIN_ID,
            "job_id": self.job_id,
            "requester_commitment": self.requester_commitment,
            "job_kind": self.job_kind.as_str(),
            "circuit_family": self.circuit_family.as_str(),
            "lane": self.lane.as_str(),
            "lane_weight": self.lane.default_weight(),
            "proof_system": self.proof_system,
            "input_root": self.input_root,
            "child_proof_root": self.child_proof_root,
            "witness_commitment_root": self.witness_commitment_root,
            "max_fee_units": self.max_fee_units,
            "estimated_cycles": self.estimated_cycles,
            "recursion_depth": self.recursion_depth,
            "child_proof_count": self.child_proof_count,
            "created_at_height": self.created_at_height,
            "bid_close_height": self.bid_close_height,
            "due_height": self.due_height,
            "assigned_bid_id": self.assigned_bid_id,
            "committee_id": self.committee_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status.as_str(),
            "output_proof_root": self.output_proof_root,
            "finality_receipt_id": self.finality_receipt_id,
        })
    }

    pub fn job_root(&self) -> String {
        recursive_pq_payload_root("RECURSIVE-PQ-AGGREGATION-JOB", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursivePqVerifierMember {
    pub member_id: String,
    pub operator_label: String,
    pub role: String,
    pub weight: u64,
    pub stake_units: u64,
    pub pq_public_key_root: String,
    pub active_from_height: u64,
    pub active_until_height: u64,
}

impl RecursivePqVerifierMember {
    pub fn new(
        operator_label: &str,
        role: &str,
        weight: u64,
        stake_units: u64,
        active_from_height: u64,
        active_until_height: u64,
        nonce: u64,
    ) -> RecursivePqProofMarketResult<Self> {
        if operator_label.is_empty() || role.is_empty() {
            return Err("verifier operator and role are required".to_string());
        }
        if weight == 0 {
            return Err("verifier weight must be nonzero".to_string());
        }
        if active_until_height < active_from_height {
            return Err("verifier membership ends before it starts".to_string());
        }
        let member_id = recursive_pq_verifier_id(operator_label, role, nonce);
        Ok(Self {
            member_id: member_id.clone(),
            operator_label: operator_label.to_string(),
            role: role.to_string(),
            weight,
            stake_units,
            pq_public_key_root: recursive_pq_string_root(
                "RECURSIVE-PQ-VERIFIER-PUBLIC-KEY",
                &member_id,
            ),
            active_from_height,
            active_until_height,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        height >= self.active_from_height && height <= self.active_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_pq_verifier_member",
            "chain_id": CHAIN_ID,
            "member_id": self.member_id,
            "operator_label": self.operator_label,
            "role": self.role,
            "weight": self.weight,
            "stake_units": self.stake_units,
            "pq_public_key_root": self.pq_public_key_root,
            "active_from_height": self.active_from_height,
            "active_until_height": self.active_until_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursivePqVerifierCommittee {
    pub committee_id: String,
    pub label: String,
    pub policy: RecursivePqCommitteePolicy,
    pub threshold_bps: u64,
    pub members: BTreeMap<String, RecursivePqVerifierMember>,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl RecursivePqVerifierCommittee {
    pub fn new(
        label: &str,
        policy: RecursivePqCommitteePolicy,
        threshold_bps: u64,
        members: Vec<RecursivePqVerifierMember>,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> RecursivePqProofMarketResult<Self> {
        if label.is_empty() {
            return Err("committee label is required".to_string());
        }
        if threshold_bps == 0 || threshold_bps > RECURSIVE_PQ_PROOF_MARKET_MAX_BPS {
            return Err("committee threshold bps is outside range".to_string());
        }
        if members.is_empty() {
            return Err("committee requires members".to_string());
        }
        if expires_at_height < created_at_height {
            return Err("committee expires before it starts".to_string());
        }
        let mut indexed = BTreeMap::new();
        for member in members {
            indexed.insert(member.member_id.clone(), member);
        }
        let member_root = recursive_pq_record_map_root(
            "RECURSIVE-PQ-COMMITTEE-MEMBER",
            indexed
                .iter()
                .map(|(id, member)| (id.clone(), member.public_record()))
                .collect(),
        );
        let committee_id = recursive_pq_committee_id(
            label,
            policy.as_str(),
            &member_root,
            threshold_bps,
            created_at_height,
            expires_at_height,
        );
        Ok(Self {
            committee_id,
            label: label.to_string(),
            policy,
            threshold_bps,
            members: indexed,
            created_at_height,
            expires_at_height,
            status: RECURSIVE_PQ_PROOF_MARKET_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status == RECURSIVE_PQ_PROOF_MARKET_STATUS_ACTIVE
            && height >= self.created_at_height
            && height <= self.expires_at_height
    }

    pub fn total_weight(&self) -> u64 {
        self.members
            .values()
            .fold(0_u64, |acc, member| acc.saturating_add(member.weight))
    }

    pub fn threshold_weight(&self) -> u64 {
        self.total_weight()
            .saturating_mul(self.threshold_bps)
            .saturating_add(RECURSIVE_PQ_PROOF_MARKET_MAX_BPS - 1)
            / RECURSIVE_PQ_PROOF_MARKET_MAX_BPS
    }

    pub fn member_root(&self) -> String {
        recursive_pq_record_map_root(
            "RECURSIVE-PQ-COMMITTEE-MEMBERS",
            self.members
                .iter()
                .map(|(id, member)| (id.clone(), member.public_record()))
                .collect(),
        )
    }

    pub fn public_record(&self) -> Value {
        let members = self
            .members
            .iter()
            .map(|(id, member)| (id.clone(), member.public_record()))
            .collect::<BTreeMap<_, _>>();
        json!({
            "kind": "recursive_pq_verifier_committee",
            "chain_id": CHAIN_ID,
            "committee_id": self.committee_id,
            "label": self.label,
            "policy": self.policy.as_str(),
            "threshold_bps": self.threshold_bps,
            "total_weight": self.total_weight(),
            "threshold_weight": self.threshold_weight(),
            "member_root": self.member_root(),
            "members": members,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn committee_root(&self) -> String {
        recursive_pq_payload_root("RECURSIVE-PQ-VERIFIER-COMMITTEE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursivePqCommitteeVote {
    pub vote_id: String,
    pub committee_id: String,
    pub job_id: String,
    pub member_id: String,
    pub outcome: RecursivePqVoteOutcome,
    pub proof_root: String,
    pub signed_transcript_root: String,
    pub weight: u64,
    pub voted_at_height: u64,
}

impl RecursivePqCommitteeVote {
    pub fn new(
        committee_id: &str,
        job_id: &str,
        member: &RecursivePqVerifierMember,
        outcome: RecursivePqVoteOutcome,
        proof_root: &str,
        voted_at_height: u64,
    ) -> RecursivePqProofMarketResult<Self> {
        if committee_id.is_empty() || job_id.is_empty() || proof_root.is_empty() {
            return Err("committee vote requires ids and proof root".to_string());
        }
        let signed_transcript_root = recursive_pq_vote_transcript_root(
            committee_id,
            job_id,
            &member.member_id,
            outcome.as_str(),
            proof_root,
            voted_at_height,
        );
        let vote_id = recursive_pq_vote_id(
            committee_id,
            job_id,
            &member.member_id,
            outcome.as_str(),
            &signed_transcript_root,
            voted_at_height,
        );
        Ok(Self {
            vote_id,
            committee_id: committee_id.to_string(),
            job_id: job_id.to_string(),
            member_id: member.member_id.clone(),
            outcome,
            proof_root: proof_root.to_string(),
            signed_transcript_root,
            weight: member.weight,
            voted_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_pq_committee_vote",
            "chain_id": CHAIN_ID,
            "vote_id": self.vote_id,
            "committee_id": self.committee_id,
            "job_id": self.job_id,
            "member_id": self.member_id,
            "outcome": self.outcome.as_str(),
            "proof_root": self.proof_root,
            "signed_transcript_root": self.signed_transcript_root,
            "weight": self.weight,
            "voted_at_height": self.voted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursivePqSponsorshipPolicy {
    pub sponsor_id: String,
    pub sponsor_commitment: String,
    pub lane: RecursivePqLane,
    pub fee_asset_id: String,
    pub budget_units: u64,
    pub remaining_units: u64,
    pub max_per_job_units: u64,
    pub rebate_bps: u64,
    pub active_from_height: u64,
    pub expires_at_height: u64,
    pub eligibility_root: String,
    pub status: String,
}

impl RecursivePqSponsorshipPolicy {
    pub fn new(
        sponsor_commitment: &str,
        lane: RecursivePqLane,
        fee_asset_id: &str,
        budget_units: u64,
        max_per_job_units: u64,
        rebate_bps: u64,
        active_from_height: u64,
        expires_at_height: u64,
        eligibility_root: &str,
    ) -> RecursivePqProofMarketResult<Self> {
        if sponsor_commitment.is_empty() || fee_asset_id.is_empty() || eligibility_root.is_empty() {
            return Err("sponsorship policy requires commitments".to_string());
        }
        if budget_units == 0 || max_per_job_units == 0 {
            return Err("sponsorship budget values must be nonzero".to_string());
        }
        if rebate_bps > RECURSIVE_PQ_PROOF_MARKET_MAX_BPS {
            return Err("sponsorship rebate bps is outside range".to_string());
        }
        if expires_at_height < active_from_height {
            return Err("sponsorship policy expires before it starts".to_string());
        }
        let sponsor_id = recursive_pq_sponsor_id(
            sponsor_commitment,
            lane.as_str(),
            fee_asset_id,
            budget_units,
            active_from_height,
            expires_at_height,
        );
        Ok(Self {
            sponsor_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            lane,
            fee_asset_id: fee_asset_id.to_string(),
            budget_units,
            remaining_units: budget_units,
            max_per_job_units,
            rebate_bps,
            active_from_height,
            expires_at_height,
            eligibility_root: eligibility_root.to_string(),
            status: RECURSIVE_PQ_PROOF_MARKET_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status == RECURSIVE_PQ_PROOF_MARKET_STATUS_ACTIVE
            && height >= self.active_from_height
            && height <= self.expires_at_height
            && self.remaining_units > 0
    }

    pub fn sponsorship_amount(&self, gross_fee_units: u64) -> u64 {
        let rebate =
            gross_fee_units.saturating_mul(self.rebate_bps) / RECURSIVE_PQ_PROOF_MARKET_MAX_BPS;
        rebate.min(self.max_per_job_units).min(self.remaining_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_pq_sponsorship_policy",
            "chain_id": CHAIN_ID,
            "sponsor_id": self.sponsor_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane": self.lane.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "budget_units": self.budget_units,
            "remaining_units": self.remaining_units,
            "max_per_job_units": self.max_per_job_units,
            "rebate_bps": self.rebate_bps,
            "active_from_height": self.active_from_height,
            "expires_at_height": self.expires_at_height,
            "eligibility_root": self.eligibility_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursivePqSponsorshipReceipt {
    pub receipt_id: String,
    pub sponsor_id: String,
    pub job_id: String,
    pub requester_commitment: String,
    pub gross_fee_units: u64,
    pub sponsored_fee_units: u64,
    pub net_fee_units: u64,
    pub issued_at_height: u64,
}

impl RecursivePqSponsorshipReceipt {
    pub fn new(
        policy: &RecursivePqSponsorshipPolicy,
        job: &RecursivePqAggregationJob,
        gross_fee_units: u64,
        issued_at_height: u64,
    ) -> RecursivePqProofMarketResult<Self> {
        let sponsored_fee_units = policy.sponsorship_amount(gross_fee_units);
        if sponsored_fee_units == 0 {
            return Err("sponsorship amount is zero".to_string());
        }
        let net_fee_units = gross_fee_units.saturating_sub(sponsored_fee_units);
        let receipt_id = recursive_pq_sponsorship_receipt_id(
            &policy.sponsor_id,
            &job.job_id,
            &job.requester_commitment,
            gross_fee_units,
            sponsored_fee_units,
            issued_at_height,
        );
        Ok(Self {
            receipt_id,
            sponsor_id: policy.sponsor_id.clone(),
            job_id: job.job_id.clone(),
            requester_commitment: job.requester_commitment.clone(),
            gross_fee_units,
            sponsored_fee_units,
            net_fee_units,
            issued_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_pq_sponsorship_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "sponsor_id": self.sponsor_id,
            "job_id": self.job_id,
            "requester_commitment": self.requester_commitment,
            "gross_fee_units": self.gross_fee_units,
            "sponsored_fee_units": self.sponsored_fee_units,
            "net_fee_units": self.net_fee_units,
            "issued_at_height": self.issued_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursivePqWitnessFetchCommitment {
    pub commitment_id: String,
    pub job_id: String,
    pub requester_commitment: String,
    pub access_mode: RecursivePqWitnessAccessMode,
    pub witness_root: String,
    pub nullifier_root: String,
    pub encrypted_payload_root: String,
    pub relay_committee_id: String,
    pub fee_units: u64,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub fulfilled_at_height: Option<u64>,
    pub status: String,
}

impl RecursivePqWitnessFetchCommitment {
    pub fn new(
        job_id: &str,
        requester_commitment: &str,
        access_mode: RecursivePqWitnessAccessMode,
        witness_root: &str,
        nullifier_root: &str,
        encrypted_payload_root: &str,
        relay_committee_id: &str,
        fee_units: u64,
        requested_at_height: u64,
        expires_at_height: u64,
    ) -> RecursivePqProofMarketResult<Self> {
        if job_id.is_empty()
            || requester_commitment.is_empty()
            || witness_root.is_empty()
            || nullifier_root.is_empty()
            || encrypted_payload_root.is_empty()
            || relay_committee_id.is_empty()
        {
            return Err("witness fetch commitment requires roots and ids".to_string());
        }
        if expires_at_height < requested_at_height {
            return Err("witness fetch expires before request height".to_string());
        }
        let commitment_id = recursive_pq_witness_commitment_id(
            job_id,
            requester_commitment,
            access_mode.as_str(),
            witness_root,
            nullifier_root,
            encrypted_payload_root,
            requested_at_height,
        );
        Ok(Self {
            commitment_id,
            job_id: job_id.to_string(),
            requester_commitment: requester_commitment.to_string(),
            access_mode,
            witness_root: witness_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            encrypted_payload_root: encrypted_payload_root.to_string(),
            relay_committee_id: relay_committee_id.to_string(),
            fee_units,
            requested_at_height,
            expires_at_height,
            fulfilled_at_height: None,
            status: RECURSIVE_PQ_PROOF_MARKET_STATUS_OPEN.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_pq_witness_fetch_commitment",
            "chain_id": CHAIN_ID,
            "commitment_id": self.commitment_id,
            "job_id": self.job_id,
            "requester_commitment": self.requester_commitment,
            "access_mode": self.access_mode.as_str(),
            "witness_root": self.witness_root,
            "nullifier_root": self.nullifier_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "relay_committee_id": self.relay_committee_id,
            "fee_units": self.fee_units,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "fulfilled_at_height": self.fulfilled_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursivePqSlaPenalty {
    pub penalty_id: String,
    pub job_id: String,
    pub bid_id: String,
    pub prover_id: String,
    pub penalty_kind: RecursivePqPenaltyKind,
    pub base_amount_units: u64,
    pub penalty_bps: u64,
    pub penalty_units: u64,
    pub reason_root: String,
    pub assessed_at_height: u64,
}

impl RecursivePqSlaPenalty {
    pub fn new(
        job_id: &str,
        bid: &RecursivePqProverBid,
        penalty_kind: RecursivePqPenaltyKind,
        base_amount_units: u64,
        penalty_bps: u64,
        reason_root: &str,
        assessed_at_height: u64,
    ) -> RecursivePqProofMarketResult<Self> {
        if job_id.is_empty() || reason_root.is_empty() {
            return Err("sla penalty requires job id and reason root".to_string());
        }
        if penalty_bps > RECURSIVE_PQ_PROOF_MARKET_MAX_BPS {
            return Err("sla penalty bps is outside range".to_string());
        }
        let penalty_units =
            base_amount_units.saturating_mul(penalty_bps) / RECURSIVE_PQ_PROOF_MARKET_MAX_BPS;
        let penalty_id = recursive_pq_penalty_id(
            job_id,
            &bid.bid_id,
            &bid.prover_id,
            penalty_kind.as_str(),
            reason_root,
            assessed_at_height,
        );
        Ok(Self {
            penalty_id,
            job_id: job_id.to_string(),
            bid_id: bid.bid_id.clone(),
            prover_id: bid.prover_id.clone(),
            penalty_kind,
            base_amount_units,
            penalty_bps,
            penalty_units,
            reason_root: reason_root.to_string(),
            assessed_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_pq_sla_penalty",
            "chain_id": CHAIN_ID,
            "penalty_id": self.penalty_id,
            "job_id": self.job_id,
            "bid_id": self.bid_id,
            "prover_id": self.prover_id,
            "penalty_kind": self.penalty_kind.as_str(),
            "base_amount_units": self.base_amount_units,
            "penalty_bps": self.penalty_bps,
            "penalty_units": self.penalty_units,
            "reason_root": self.reason_root,
            "assessed_at_height": self.assessed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursivePqFinalityProofReceipt {
    pub receipt_id: String,
    pub job_id: String,
    pub committee_id: String,
    pub proof_root: String,
    pub aggregate_vote_root: String,
    pub fast_finality_root: String,
    pub status: RecursivePqReceiptStatus,
    pub accepted_weight: u64,
    pub threshold_weight: u64,
    pub issued_at_height: u64,
    pub challenge_until_height: u64,
}

impl RecursivePqFinalityProofReceipt {
    pub fn new(
        job_id: &str,
        committee: &RecursivePqVerifierCommittee,
        proof_root: &str,
        votes: &BTreeMap<String, RecursivePqCommitteeVote>,
        status: RecursivePqReceiptStatus,
        issued_at_height: u64,
        challenge_until_height: u64,
    ) -> RecursivePqProofMarketResult<Self> {
        if job_id.is_empty() || proof_root.is_empty() {
            return Err("finality receipt requires job id and proof root".to_string());
        }
        let accepted_weight = votes
            .values()
            .filter(|vote| vote.outcome == RecursivePqVoteOutcome::Accept)
            .fold(0_u64, |acc, vote| acc.saturating_add(vote.weight));
        let threshold_weight = committee.threshold_weight();
        let aggregate_vote_root = recursive_pq_record_map_root(
            "RECURSIVE-PQ-FINALITY-VOTES",
            votes
                .iter()
                .map(|(id, vote)| (id.clone(), vote.public_record()))
                .collect(),
        );
        let fast_finality_root = recursive_pq_fast_finality_root(
            job_id,
            &committee.committee_id,
            proof_root,
            &aggregate_vote_root,
            accepted_weight,
            threshold_weight,
            issued_at_height,
        );
        let receipt_id = recursive_pq_finality_receipt_id(
            job_id,
            &committee.committee_id,
            proof_root,
            &fast_finality_root,
            issued_at_height,
        );
        Ok(Self {
            receipt_id,
            job_id: job_id.to_string(),
            committee_id: committee.committee_id.clone(),
            proof_root: proof_root.to_string(),
            aggregate_vote_root,
            fast_finality_root,
            status,
            accepted_weight,
            threshold_weight,
            issued_at_height,
            challenge_until_height,
        })
    }

    pub fn quorum_reached(&self) -> bool {
        self.accepted_weight >= self.threshold_weight
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_pq_finality_proof_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "job_id": self.job_id,
            "committee_id": self.committee_id,
            "proof_root": self.proof_root,
            "aggregate_vote_root": self.aggregate_vote_root,
            "fast_finality_root": self.fast_finality_root,
            "status": self.status.as_str(),
            "accepted_weight": self.accepted_weight,
            "threshold_weight": self.threshold_weight,
            "quorum_reached": self.quorum_reached(),
            "issued_at_height": self.issued_at_height,
            "challenge_until_height": self.challenge_until_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursivePqMarketEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub event_root: String,
    pub emitted_at_height: u64,
}

impl RecursivePqMarketEvent {
    pub fn new(event_kind: &str, subject_id: &str, event: &Value, emitted_at_height: u64) -> Self {
        let event_root = recursive_pq_payload_root("RECURSIVE-PQ-MARKET-EVENT-PAYLOAD", event);
        let event_id =
            recursive_pq_event_id(event_kind, subject_id, &event_root, emitted_at_height);
        Self {
            event_id,
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            event_root,
            emitted_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_pq_market_event",
            "chain_id": CHAIN_ID,
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "event_root": self.event_root,
            "emitted_at_height": self.emitted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursivePqProofMarketRoots {
    pub config_root: String,
    pub bid_root: String,
    pub job_root: String,
    pub committee_root: String,
    pub vote_root: String,
    pub sponsor_policy_root: String,
    pub sponsorship_receipt_root: String,
    pub witness_fetch_root: String,
    pub penalty_root: String,
    pub finality_receipt_root: String,
    pub event_root: String,
}

impl RecursivePqProofMarketRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_pq_proof_market_roots",
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "bid_root": self.bid_root,
            "job_root": self.job_root,
            "committee_root": self.committee_root,
            "vote_root": self.vote_root,
            "sponsor_policy_root": self.sponsor_policy_root,
            "sponsorship_receipt_root": self.sponsorship_receipt_root,
            "witness_fetch_root": self.witness_fetch_root,
            "penalty_root": self.penalty_root,
            "finality_receipt_root": self.finality_receipt_root,
            "event_root": self.event_root,
        })
    }

    pub fn state_root(&self) -> String {
        recursive_pq_payload_root("RECURSIVE-PQ-PROOF-MARKET-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursivePqProofMarketCounters {
    pub bids: u64,
    pub jobs: u64,
    pub committees: u64,
    pub committee_members: u64,
    pub votes: u64,
    pub sponsor_policies: u64,
    pub sponsorship_receipts: u64,
    pub witness_fetch_commitments: u64,
    pub penalties: u64,
    pub finality_receipts: u64,
    pub events: u64,
    pub active_jobs: u64,
    pub finalized_jobs: u64,
    pub sponsored_jobs: u64,
    pub slashed_bids: u64,
}

impl RecursivePqProofMarketCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_pq_proof_market_counters",
            "chain_id": CHAIN_ID,
            "bids": self.bids,
            "jobs": self.jobs,
            "committees": self.committees,
            "committee_members": self.committee_members,
            "votes": self.votes,
            "sponsor_policies": self.sponsor_policies,
            "sponsorship_receipts": self.sponsorship_receipts,
            "witness_fetch_commitments": self.witness_fetch_commitments,
            "penalties": self.penalties,
            "finality_receipts": self.finality_receipts,
            "events": self.events,
            "active_jobs": self.active_jobs,
            "finalized_jobs": self.finalized_jobs,
            "sponsored_jobs": self.sponsored_jobs,
            "slashed_bids": self.slashed_bids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursivePqProofMarketState {
    pub config: RecursivePqProofMarketConfig,
    pub height: u64,
    pub bids: BTreeMap<String, RecursivePqProverBid>,
    pub jobs: BTreeMap<String, RecursivePqAggregationJob>,
    pub committees: BTreeMap<String, RecursivePqVerifierCommittee>,
    pub votes: BTreeMap<String, RecursivePqCommitteeVote>,
    pub sponsor_policies: BTreeMap<String, RecursivePqSponsorshipPolicy>,
    pub sponsorship_receipts: BTreeMap<String, RecursivePqSponsorshipReceipt>,
    pub witness_fetch_commitments: BTreeMap<String, RecursivePqWitnessFetchCommitment>,
    pub penalties: BTreeMap<String, RecursivePqSlaPenalty>,
    pub finality_receipts: BTreeMap<String, RecursivePqFinalityProofReceipt>,
    pub events: BTreeMap<String, RecursivePqMarketEvent>,
}

impl RecursivePqProofMarketState {
    pub fn new(config: RecursivePqProofMarketConfig) -> RecursivePqProofMarketResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: 0,
            bids: BTreeMap::new(),
            jobs: BTreeMap::new(),
            committees: BTreeMap::new(),
            votes: BTreeMap::new(),
            sponsor_policies: BTreeMap::new(),
            sponsorship_receipts: BTreeMap::new(),
            witness_fetch_commitments: BTreeMap::new(),
            penalties: BTreeMap::new(),
            finality_receipts: BTreeMap::new(),
            events: BTreeMap::new(),
        })
    }

    pub fn devnet() -> RecursivePqProofMarketResult<Self> {
        let mut state = Self::new(RecursivePqProofMarketConfig::devnet())?;
        state.set_height(256);

        let mut base_families = BTreeSet::new();
        base_families.insert(RecursivePqCircuitFamily::RollupState);
        base_families.insert(RecursivePqCircuitFamily::MoneroBridge);
        base_families.insert(RecursivePqCircuitFamily::PrivateContract);

        let mut recursive_families = BTreeSet::new();
        recursive_families.insert(RecursivePqCircuitFamily::RecursiveAggregation);
        recursive_families.insert(RecursivePqCircuitFamily::ReceiptFinality);

        let bid_a = RecursivePqProverBid::new(
            "devnet-pq-prover-a",
            RecursivePqWorkerClass::Gpu,
            base_families,
            31,
            2_500,
            12_000,
            240,
            512,
            0,
        )?;
        let bid_b = RecursivePqProverBid::new(
            "devnet-recursive-cluster-b",
            RecursivePqWorkerClass::RecursiveCluster,
            recursive_families,
            45,
            5_000,
            25_000,
            240,
            512,
            1,
        )?;
        let bid_a_id = bid_a.bid_id.clone();
        let bid_b_id = bid_b.bid_id.clone();
        state.register_bid(bid_a)?;
        state.register_bid(bid_b)?;

        let witness_root = recursive_pq_string_root("RECURSIVE-PQ-DEVNET-WITNESS", "bridge");
        let child_root = recursive_pq_merkle_strings(
            "RECURSIVE-PQ-DEVNET-CHILD-PROOFS",
            &[
                recursive_pq_string_root("RECURSIVE-PQ-DEVNET-CHILD", "child-0"),
                recursive_pq_string_root("RECURSIVE-PQ-DEVNET-CHILD", "child-1"),
                recursive_pq_string_root("RECURSIVE-PQ-DEVNET-CHILD", "child-2"),
            ],
        );
        let job = RecursivePqAggregationJob::new(
            "requester:devnet-bridge-batch",
            RecursivePqJobKind::RecursiveAggregate,
            RecursivePqCircuitFamily::RecursiveAggregation,
            RecursivePqLane::RecursiveBatch,
            &recursive_pq_string_root("RECURSIVE-PQ-DEVNET-INPUT", "batch-256"),
            &child_root,
            &witness_root,
            250,
            4_500_000,
            2,
            3,
            state.height,
            &state.config,
            0,
        )?;
        let job_id = job.job_id.clone();
        state.submit_job(job)?;
        state.assign_bid_to_job(&job_id, &bid_b_id)?;

        let committee = RecursivePqVerifierCommittee::new(
            "devnet-recursive-pq-verifier-committee",
            RecursivePqCommitteePolicy::WeightedThreshold,
            state.config.committee_threshold_bps,
            vec![
                RecursivePqVerifierMember::new(
                    "devnet-verifier-a",
                    "pq_verifier",
                    4_000,
                    10_000,
                    200,
                    600,
                    0,
                )?,
                RecursivePqVerifierMember::new(
                    "devnet-verifier-b",
                    "recursion_auditor",
                    3_500,
                    10_000,
                    200,
                    600,
                    1,
                )?,
                RecursivePqVerifierMember::new(
                    "devnet-verifier-c",
                    "sponsor_auditor",
                    2_500,
                    8_000,
                    200,
                    600,
                    2,
                )?,
            ],
            240,
            600,
        )?;
        let committee_id = committee.committee_id.clone();
        let member_ids = committee.members.keys().cloned().collect::<Vec<_>>();
        state.add_committee(committee)?;
        state.attach_committee_to_job(&job_id, &committee_id)?;

        let policy = RecursivePqSponsorshipPolicy::new(
            "sponsor:devnet-low-fee-pq-proofs",
            RecursivePqLane::LowFeePublicGood,
            &state.config.default_fee_asset_id,
            10_000,
            50,
            state.config.sponsor_rebate_bps,
            240,
            512,
            &recursive_pq_string_root("RECURSIVE-PQ-DEVNET-ELIGIBILITY", "small-users"),
        )?;
        let sponsor_id = policy.sponsor_id.clone();
        state.add_sponsorship_policy(policy)?;

        let witness = RecursivePqWitnessFetchCommitment::new(
            &job_id,
            "requester:devnet-bridge-batch",
            RecursivePqWitnessAccessMode::ThresholdReveal,
            &witness_root,
            &recursive_pq_string_root("RECURSIVE-PQ-DEVNET-NULLIFIER", "batch-256"),
            &recursive_pq_string_root("RECURSIVE-PQ-DEVNET-ENCRYPTED-WITNESS", "batch-256"),
            &committee_id,
            7,
            state.height,
            state.height.saturating_add(12),
        )?;
        state.request_witness_fetch(witness)?;

        state.issue_sponsorship(&sponsor_id, &job_id, 140)?;

        let proof_root = recursive_pq_string_root("RECURSIVE-PQ-DEVNET-PROOF", "aggregate-256");
        for member_id in member_ids.iter().take(2) {
            state.record_vote(
                &committee_id,
                &job_id,
                member_id,
                RecursivePqVoteOutcome::Accept,
                &proof_root,
            )?;
        }
        state.mark_job_proved(&job_id, &proof_root)?;
        state.issue_finality_receipt(&job_id, RecursivePqReceiptStatus::FastAccepted)?;

        let late_reason = recursive_pq_string_root("RECURSIVE-PQ-DEVNET-PENALTY", "late-base-bid");
        state.apply_sla_penalty(
            &job_id,
            &bid_a_id,
            RecursivePqPenaltyKind::LateProof,
            100,
            state.config.late_penalty_bps,
            &late_reason,
        )?;

        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn validate(&self) -> RecursivePqProofMarketResult<()> {
        self.config.validate()?;
        if self.bids.len() > self.config.max_records
            || self.jobs.len() > self.config.max_records
            || self.committees.len() > self.config.max_records
            || self.votes.len() > self.config.max_records
            || self.finality_receipts.len() > self.config.max_records
        {
            return Err("recursive pq proof market record cap reached".to_string());
        }
        for job in self.jobs.values() {
            if let Some(bid_id) = &job.assigned_bid_id {
                if !self.bids.contains_key(bid_id) {
                    return Err("job references missing bid".to_string());
                }
            }
            if let Some(committee_id) = &job.committee_id {
                if !self.committees.contains_key(committee_id) {
                    return Err("job references missing committee".to_string());
                }
            }
        }
        for vote in self.votes.values() {
            if !self.committees.contains_key(&vote.committee_id) {
                return Err("vote references missing committee".to_string());
            }
            if !self.jobs.contains_key(&vote.job_id) {
                return Err("vote references missing job".to_string());
            }
        }
        Ok(())
    }

    pub fn register_bid(
        &mut self,
        bid: RecursivePqProverBid,
    ) -> RecursivePqProofMarketResult<String> {
        if self.bids.len() >= self.config.max_records {
            return Err("bid record cap reached".to_string());
        }
        let bid_id = bid.bid_id.clone();
        if self.bids.contains_key(&bid_id) {
            return Err("bid already exists".to_string());
        }
        let event = RecursivePqMarketEvent::new(
            "bid_registered",
            &bid_id,
            &bid.public_record(),
            self.height,
        );
        self.events.insert(event.event_id.clone(), event);
        self.bids.insert(bid_id.clone(), bid);
        Ok(bid_id)
    }

    pub fn submit_job(
        &mut self,
        job: RecursivePqAggregationJob,
    ) -> RecursivePqProofMarketResult<String> {
        if self.jobs.len() >= self.config.max_records {
            return Err("job record cap reached".to_string());
        }
        let job_id = job.job_id.clone();
        if self.jobs.contains_key(&job_id) {
            return Err("job already exists".to_string());
        }
        let event = RecursivePqMarketEvent::new(
            "job_submitted",
            &job_id,
            &job.public_record(),
            self.height,
        );
        self.events.insert(event.event_id.clone(), event);
        self.jobs.insert(job_id.clone(), job);
        Ok(job_id)
    }

    pub fn assign_bid_to_job(
        &mut self,
        job_id: &str,
        bid_id: &str,
    ) -> RecursivePqProofMarketResult<()> {
        let bid = match self.bids.get(bid_id) {
            Some(bid) => bid.clone(),
            None => return Err("bid not found".to_string()),
        };
        let job = match self.jobs.get_mut(job_id) {
            Some(job) => job,
            None => return Err("job not found".to_string()),
        };
        if !job.can_accept_bid(&bid, self.height) {
            return Err("bid cannot satisfy job at current height".to_string());
        }
        job.assigned_bid_id = Some(bid_id.to_string());
        job.status = RecursivePqJobStatus::Assigned;
        if let Some(stored_bid) = self.bids.get_mut(bid_id) {
            stored_bid.status = RecursivePqBidStatus::Assigned;
        }
        let event =
            RecursivePqMarketEvent::new("job_assigned", job_id, &job.public_record(), self.height);
        self.events.insert(event.event_id.clone(), event);
        Ok(())
    }

    pub fn add_committee(
        &mut self,
        committee: RecursivePqVerifierCommittee,
    ) -> RecursivePqProofMarketResult<String> {
        if self.committees.len() >= self.config.max_records {
            return Err("committee record cap reached".to_string());
        }
        let committee_id = committee.committee_id.clone();
        if self.committees.contains_key(&committee_id) {
            return Err("committee already exists".to_string());
        }
        let event = RecursivePqMarketEvent::new(
            "committee_added",
            &committee_id,
            &committee.public_record(),
            self.height,
        );
        self.events.insert(event.event_id.clone(), event);
        self.committees.insert(committee_id.clone(), committee);
        Ok(committee_id)
    }

    pub fn attach_committee_to_job(
        &mut self,
        job_id: &str,
        committee_id: &str,
    ) -> RecursivePqProofMarketResult<()> {
        let committee = match self.committees.get(committee_id) {
            Some(committee) => committee,
            None => return Err("committee not found".to_string()),
        };
        if !committee.active_at(self.height) {
            return Err("committee is inactive".to_string());
        }
        let job = match self.jobs.get_mut(job_id) {
            Some(job) => job,
            None => return Err("job not found".to_string()),
        };
        job.committee_id = Some(committee_id.to_string());
        let event = RecursivePqMarketEvent::new(
            "committee_attached",
            job_id,
            &job.public_record(),
            self.height,
        );
        self.events.insert(event.event_id.clone(), event);
        Ok(())
    }

    pub fn add_sponsorship_policy(
        &mut self,
        policy: RecursivePqSponsorshipPolicy,
    ) -> RecursivePqProofMarketResult<String> {
        if self.sponsor_policies.len() >= self.config.max_records {
            return Err("sponsorship policy cap reached".to_string());
        }
        let sponsor_id = policy.sponsor_id.clone();
        if self.sponsor_policies.contains_key(&sponsor_id) {
            return Err("sponsorship policy already exists".to_string());
        }
        let event = RecursivePqMarketEvent::new(
            "sponsorship_policy_added",
            &sponsor_id,
            &policy.public_record(),
            self.height,
        );
        self.events.insert(event.event_id.clone(), event);
        self.sponsor_policies.insert(sponsor_id.clone(), policy);
        Ok(sponsor_id)
    }

    pub fn issue_sponsorship(
        &mut self,
        sponsor_id: &str,
        job_id: &str,
        gross_fee_units: u64,
    ) -> RecursivePqProofMarketResult<String> {
        let job = match self.jobs.get(job_id) {
            Some(job) => job.clone(),
            None => return Err("job not found".to_string()),
        };
        let policy = match self.sponsor_policies.get(sponsor_id) {
            Some(policy) => policy.clone(),
            None => return Err("sponsorship policy not found".to_string()),
        };
        if !policy.active_at(self.height) {
            return Err("sponsorship policy is inactive".to_string());
        }
        if policy.lane != job.lane && !job.lane.low_fee_lane() {
            return Err("sponsorship lane does not match job".to_string());
        }
        let receipt =
            RecursivePqSponsorshipReceipt::new(&policy, &job, gross_fee_units, self.height)?;
        let receipt_id = receipt.receipt_id.clone();
        if let Some(stored_policy) = self.sponsor_policies.get_mut(sponsor_id) {
            stored_policy.remaining_units = stored_policy
                .remaining_units
                .saturating_sub(receipt.sponsored_fee_units);
        }
        if let Some(stored_job) = self.jobs.get_mut(job_id) {
            stored_job.sponsor_id = Some(sponsor_id.to_string());
            stored_job.status = RecursivePqJobStatus::Sponsored;
        }
        let event = RecursivePqMarketEvent::new(
            "sponsorship_issued",
            &receipt_id,
            &receipt.public_record(),
            self.height,
        );
        self.events.insert(event.event_id.clone(), event);
        self.sponsorship_receipts
            .insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn request_witness_fetch(
        &mut self,
        commitment: RecursivePqWitnessFetchCommitment,
    ) -> RecursivePqProofMarketResult<String> {
        if !self.jobs.contains_key(&commitment.job_id) {
            return Err("witness fetch references missing job".to_string());
        }
        let commitment_id = commitment.commitment_id.clone();
        if self.witness_fetch_commitments.contains_key(&commitment_id) {
            return Err("witness fetch commitment already exists".to_string());
        }
        let event = RecursivePqMarketEvent::new(
            "witness_fetch_requested",
            &commitment_id,
            &commitment.public_record(),
            self.height,
        );
        self.events.insert(event.event_id.clone(), event);
        self.witness_fetch_commitments
            .insert(commitment_id.clone(), commitment);
        Ok(commitment_id)
    }

    pub fn mark_witness_fetch_fulfilled(
        &mut self,
        commitment_id: &str,
    ) -> RecursivePqProofMarketResult<()> {
        let commitment = match self.witness_fetch_commitments.get_mut(commitment_id) {
            Some(commitment) => commitment,
            None => return Err("witness fetch commitment not found".to_string()),
        };
        commitment.fulfilled_at_height = Some(self.height);
        commitment.status = RECURSIVE_PQ_PROOF_MARKET_STATUS_VERIFIED.to_string();
        let event = RecursivePqMarketEvent::new(
            "witness_fetch_fulfilled",
            commitment_id,
            &commitment.public_record(),
            self.height,
        );
        self.events.insert(event.event_id.clone(), event);
        Ok(())
    }

    pub fn mark_job_proved(
        &mut self,
        job_id: &str,
        output_proof_root: &str,
    ) -> RecursivePqProofMarketResult<()> {
        if output_proof_root.is_empty() {
            return Err("output proof root is required".to_string());
        }
        let job = match self.jobs.get_mut(job_id) {
            Some(job) => job,
            None => return Err("job not found".to_string()),
        };
        job.output_proof_root = Some(output_proof_root.to_string());
        job.status = RecursivePqJobStatus::Proved;
        let event =
            RecursivePqMarketEvent::new("job_proved", job_id, &job.public_record(), self.height);
        self.events.insert(event.event_id.clone(), event);
        Ok(())
    }

    pub fn record_vote(
        &mut self,
        committee_id: &str,
        job_id: &str,
        member_id: &str,
        outcome: RecursivePqVoteOutcome,
        proof_root: &str,
    ) -> RecursivePqProofMarketResult<String> {
        let committee = match self.committees.get(committee_id) {
            Some(committee) => committee,
            None => return Err("committee not found".to_string()),
        };
        if !committee.active_at(self.height) {
            return Err("committee inactive at current height".to_string());
        }
        if !self.jobs.contains_key(job_id) {
            return Err("job not found".to_string());
        }
        let member = match committee.members.get(member_id) {
            Some(member) => member,
            None => return Err("committee member not found".to_string()),
        };
        if !member.active_at(self.height) {
            return Err("committee member inactive at current height".to_string());
        }
        let vote = RecursivePqCommitteeVote::new(
            committee_id,
            job_id,
            member,
            outcome,
            proof_root,
            self.height,
        )?;
        let vote_id = vote.vote_id.clone();
        if self.votes.contains_key(&vote_id) {
            return Err("committee vote already exists".to_string());
        }
        let event = RecursivePqMarketEvent::new(
            "committee_vote",
            &vote_id,
            &vote.public_record(),
            self.height,
        );
        self.events.insert(event.event_id.clone(), event);
        self.votes.insert(vote_id.clone(), vote);
        Ok(vote_id)
    }

    pub fn apply_sla_penalty(
        &mut self,
        job_id: &str,
        bid_id: &str,
        penalty_kind: RecursivePqPenaltyKind,
        base_amount_units: u64,
        penalty_bps: u64,
        reason_root: &str,
    ) -> RecursivePqProofMarketResult<String> {
        if !self.jobs.contains_key(job_id) {
            return Err("job not found".to_string());
        }
        let bid = match self.bids.get(bid_id) {
            Some(bid) => bid.clone(),
            None => return Err("bid not found".to_string()),
        };
        let penalty = RecursivePqSlaPenalty::new(
            job_id,
            &bid,
            penalty_kind,
            base_amount_units,
            penalty_bps,
            reason_root,
            self.height,
        )?;
        let penalty_id = penalty.penalty_id.clone();
        if let Some(stored_bid) = self.bids.get_mut(bid_id) {
            stored_bid.status = RecursivePqBidStatus::Slashed;
        }
        let event = RecursivePqMarketEvent::new(
            "sla_penalty_applied",
            &penalty_id,
            &penalty.public_record(),
            self.height,
        );
        self.events.insert(event.event_id.clone(), event);
        self.penalties.insert(penalty_id.clone(), penalty);
        Ok(penalty_id)
    }

    pub fn issue_finality_receipt(
        &mut self,
        job_id: &str,
        status: RecursivePqReceiptStatus,
    ) -> RecursivePqProofMarketResult<String> {
        let job = match self.jobs.get(job_id) {
            Some(job) => job.clone(),
            None => return Err("job not found".to_string()),
        };
        let committee_id = match &job.committee_id {
            Some(committee_id) => committee_id.clone(),
            None => return Err("job has no committee".to_string()),
        };
        let committee = match self.committees.get(&committee_id) {
            Some(committee) => committee.clone(),
            None => return Err("committee not found".to_string()),
        };
        let proof_root = match &job.output_proof_root {
            Some(proof_root) => proof_root.clone(),
            None => return Err("job has no output proof root".to_string()),
        };
        let job_votes = self
            .votes
            .iter()
            .filter(|(_, vote)| vote.job_id == job_id && vote.committee_id == committee_id)
            .map(|(id, vote)| (id.clone(), vote.clone()))
            .collect::<BTreeMap<_, _>>();
        let challenge_until_height = self
            .height
            .saturating_add(self.config.challenge_window_blocks);
        let receipt = RecursivePqFinalityProofReceipt::new(
            job_id,
            &committee,
            &proof_root,
            &job_votes,
            status,
            self.height,
            challenge_until_height,
        )?;
        if !receipt.quorum_reached() && status != RecursivePqReceiptStatus::ChallengeOpen {
            return Err("finality receipt lacks committee quorum".to_string());
        }
        let receipt_id = receipt.receipt_id.clone();
        if let Some(stored_job) = self.jobs.get_mut(job_id) {
            stored_job.status = RecursivePqJobStatus::Finalized;
            stored_job.finality_receipt_id = Some(receipt_id.clone());
        }
        let event = RecursivePqMarketEvent::new(
            "fast_finality_receipt_issued",
            &receipt_id,
            &receipt.public_record(),
            self.height,
        );
        self.events.insert(event.event_id.clone(), event);
        self.finality_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn roots(&self) -> RecursivePqProofMarketRoots {
        RecursivePqProofMarketRoots {
            config_root: self.config.config_root(),
            bid_root: recursive_pq_record_map_root(
                "RECURSIVE-PQ-MARKET-BIDS",
                self.bids
                    .iter()
                    .map(|(id, bid)| (id.clone(), bid.public_record()))
                    .collect(),
            ),
            job_root: recursive_pq_record_map_root(
                "RECURSIVE-PQ-MARKET-JOBS",
                self.jobs
                    .iter()
                    .map(|(id, job)| (id.clone(), job.public_record()))
                    .collect(),
            ),
            committee_root: recursive_pq_record_map_root(
                "RECURSIVE-PQ-MARKET-COMMITTEES",
                self.committees
                    .iter()
                    .map(|(id, committee)| (id.clone(), committee.public_record()))
                    .collect(),
            ),
            vote_root: recursive_pq_record_map_root(
                "RECURSIVE-PQ-MARKET-VOTES",
                self.votes
                    .iter()
                    .map(|(id, vote)| (id.clone(), vote.public_record()))
                    .collect(),
            ),
            sponsor_policy_root: recursive_pq_record_map_root(
                "RECURSIVE-PQ-MARKET-SPONSOR-POLICIES",
                self.sponsor_policies
                    .iter()
                    .map(|(id, policy)| (id.clone(), policy.public_record()))
                    .collect(),
            ),
            sponsorship_receipt_root: recursive_pq_record_map_root(
                "RECURSIVE-PQ-MARKET-SPONSOR-RECEIPTS",
                self.sponsorship_receipts
                    .iter()
                    .map(|(id, receipt)| (id.clone(), receipt.public_record()))
                    .collect(),
            ),
            witness_fetch_root: recursive_pq_record_map_root(
                "RECURSIVE-PQ-MARKET-WITNESS-FETCH",
                self.witness_fetch_commitments
                    .iter()
                    .map(|(id, commitment)| (id.clone(), commitment.public_record()))
                    .collect(),
            ),
            penalty_root: recursive_pq_record_map_root(
                "RECURSIVE-PQ-MARKET-PENALTIES",
                self.penalties
                    .iter()
                    .map(|(id, penalty)| (id.clone(), penalty.public_record()))
                    .collect(),
            ),
            finality_receipt_root: recursive_pq_record_map_root(
                "RECURSIVE-PQ-MARKET-FINALITY-RECEIPTS",
                self.finality_receipts
                    .iter()
                    .map(|(id, receipt)| (id.clone(), receipt.public_record()))
                    .collect(),
            ),
            event_root: recursive_pq_record_map_root(
                "RECURSIVE-PQ-MARKET-EVENTS",
                self.events
                    .iter()
                    .map(|(id, event)| (id.clone(), event.public_record()))
                    .collect(),
            ),
        }
    }

    pub fn counters(&self) -> RecursivePqProofMarketCounters {
        let committee_members = self.committees.values().fold(0_u64, |acc, committee| {
            acc.saturating_add(committee.members.len() as u64)
        });
        let active_jobs = self
            .jobs
            .values()
            .filter(|job| {
                matches!(
                    job.status,
                    RecursivePqJobStatus::Open
                        | RecursivePqJobStatus::Assigned
                        | RecursivePqJobStatus::Proving
                        | RecursivePqJobStatus::Proved
                        | RecursivePqJobStatus::Sponsored
                )
            })
            .count() as u64;
        let finalized_jobs = self
            .jobs
            .values()
            .filter(|job| job.status == RecursivePqJobStatus::Finalized)
            .count() as u64;
        let sponsored_jobs = self
            .jobs
            .values()
            .filter(|job| job.sponsor_id.is_some())
            .count() as u64;
        let slashed_bids = self
            .bids
            .values()
            .filter(|bid| bid.status == RecursivePqBidStatus::Slashed)
            .count() as u64;
        RecursivePqProofMarketCounters {
            bids: self.bids.len() as u64,
            jobs: self.jobs.len() as u64,
            committees: self.committees.len() as u64,
            committee_members,
            votes: self.votes.len() as u64,
            sponsor_policies: self.sponsor_policies.len() as u64,
            sponsorship_receipts: self.sponsorship_receipts.len() as u64,
            witness_fetch_commitments: self.witness_fetch_commitments.len() as u64,
            penalties: self.penalties.len() as u64,
            finality_receipts: self.finality_receipts.len() as u64,
            events: self.events.len() as u64,
            active_jobs,
            finalized_jobs,
            sponsored_jobs,
            slashed_bids,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "recursive_pq_proof_market_state",
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root": roots.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        recursive_pq_state_root_from_record(&self.public_record())
    }
}

pub fn recursive_pq_state_root_from_record(record: &Value) -> String {
    recursive_pq_payload_root("RECURSIVE-PQ-PROOF-MARKET-STATE", record)
}

pub fn recursive_pq_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn recursive_pq_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn recursive_pq_merkle_strings(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn recursive_pq_record_map_root(domain: &str, records: BTreeMap<String, Value>) -> String {
    let leaves = records
        .into_iter()
        .map(|(id, record)| {
            json!({
                "id": id,
                "record": record,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn recursive_pq_prover_id(prover_label: &str) -> String {
    domain_hash(
        "RECURSIVE-PQ-PROVER-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(prover_label)],
        32,
    )
}

pub fn recursive_pq_bid_id(
    prover_id: &str,
    worker_class: &str,
    price_per_million_cycles: u64,
    available_from_height: u64,
    available_until_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PQ-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(prover_id),
            HashPart::Str(worker_class),
            HashPart::Int(price_per_million_cycles as i128),
            HashPart::Int(available_from_height as i128),
            HashPart::Int(available_until_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn recursive_pq_job_id(
    requester_commitment: &str,
    job_kind: &str,
    circuit_family: &str,
    input_root: &str,
    child_proof_root: &str,
    created_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PQ-JOB-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(requester_commitment),
            HashPart::Str(job_kind),
            HashPart::Str(circuit_family),
            HashPart::Str(input_root),
            HashPart::Str(child_proof_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn recursive_pq_verifier_id(operator_label: &str, role: &str, nonce: u64) -> String {
    domain_hash(
        "RECURSIVE-PQ-VERIFIER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_label),
            HashPart::Str(role),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn recursive_pq_committee_id(
    label: &str,
    policy: &str,
    member_root: &str,
    threshold_bps: u64,
    created_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PQ-COMMITTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(policy),
            HashPart::Str(member_root),
            HashPart::Int(threshold_bps as i128),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn recursive_pq_vote_transcript_root(
    committee_id: &str,
    job_id: &str,
    member_id: &str,
    outcome: &str,
    proof_root: &str,
    voted_at_height: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PQ-VOTE-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(committee_id),
            HashPart::Str(job_id),
            HashPart::Str(member_id),
            HashPart::Str(outcome),
            HashPart::Str(proof_root),
            HashPart::Int(voted_at_height as i128),
        ],
        32,
    )
}

pub fn recursive_pq_vote_id(
    committee_id: &str,
    job_id: &str,
    member_id: &str,
    outcome: &str,
    signed_transcript_root: &str,
    voted_at_height: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PQ-VOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(committee_id),
            HashPart::Str(job_id),
            HashPart::Str(member_id),
            HashPart::Str(outcome),
            HashPart::Str(signed_transcript_root),
            HashPart::Int(voted_at_height as i128),
        ],
        32,
    )
}

pub fn recursive_pq_sponsor_id(
    sponsor_commitment: &str,
    lane: &str,
    fee_asset_id: &str,
    budget_units: u64,
    active_from_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PQ-SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane),
            HashPart::Str(fee_asset_id),
            HashPart::Int(budget_units as i128),
            HashPart::Int(active_from_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn recursive_pq_sponsorship_receipt_id(
    sponsor_id: &str,
    job_id: &str,
    requester_commitment: &str,
    gross_fee_units: u64,
    sponsored_fee_units: u64,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PQ-SPONSORSHIP-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(job_id),
            HashPart::Str(requester_commitment),
            HashPart::Int(gross_fee_units as i128),
            HashPart::Int(sponsored_fee_units as i128),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn recursive_pq_witness_commitment_id(
    job_id: &str,
    requester_commitment: &str,
    access_mode: &str,
    witness_root: &str,
    nullifier_root: &str,
    encrypted_payload_root: &str,
    requested_at_height: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PQ-WITNESS-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(requester_commitment),
            HashPart::Str(access_mode),
            HashPart::Str(witness_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(encrypted_payload_root),
            HashPart::Int(requested_at_height as i128),
        ],
        32,
    )
}

pub fn recursive_pq_penalty_id(
    job_id: &str,
    bid_id: &str,
    prover_id: &str,
    penalty_kind: &str,
    reason_root: &str,
    assessed_at_height: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PQ-PENALTY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(bid_id),
            HashPart::Str(prover_id),
            HashPart::Str(penalty_kind),
            HashPart::Str(reason_root),
            HashPart::Int(assessed_at_height as i128),
        ],
        32,
    )
}

pub fn recursive_pq_fast_finality_root(
    job_id: &str,
    committee_id: &str,
    proof_root: &str,
    aggregate_vote_root: &str,
    accepted_weight: u64,
    threshold_weight: u64,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PQ-FAST-FINALITY-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(committee_id),
            HashPart::Str(proof_root),
            HashPart::Str(aggregate_vote_root),
            HashPart::Int(accepted_weight as i128),
            HashPart::Int(threshold_weight as i128),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn recursive_pq_finality_receipt_id(
    job_id: &str,
    committee_id: &str,
    proof_root: &str,
    fast_finality_root: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PQ-FINALITY-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(committee_id),
            HashPart::Str(proof_root),
            HashPart::Str(fast_finality_root),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn recursive_pq_event_id(
    event_kind: &str,
    subject_id: &str,
    event_root: &str,
    emitted_at_height: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PQ-MARKET-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Str(event_root),
            HashPart::Int(emitted_at_height as i128),
        ],
        32,
    )
}
