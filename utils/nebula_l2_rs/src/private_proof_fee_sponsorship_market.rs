use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateProofFeeSponsorshipMarketResult<T> = Result<T, String>;

pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_PROTOCOL_VERSION: &str =
    "nebula-l2-private-proof-fee-sponsorship-market-v1";
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_HASH_SUITE: &str = "SHAKE256";
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-87";
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_PQ_RECOVERY_SCHEME: &str = "SLH-DSA-SHAKE-256s";
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_PQ_KEM_SCHEME: &str = "ML-KEM-1024";
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_RECURSION_SCHEME: &str =
    "nebula-devnet-private-recursive-proof-fee-folding-v1";
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_SETTLEMENT_RECEIPT_SCHEME: &str =
    "nebula-devnet-sponsored-private-proof-settlement-receipt-v1";
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_CHALLENGE_PROOF_SYSTEM: &str =
    "nebula-devnet-private-proof-fee-fraud-challenge-v1";
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_FEE_ASSET_ID: &str = "asset:wxmr";
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_SECURITY_BITS: u64 = 192;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_EPOCH_BLOCKS: u64 = 96;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_BID_WINDOW_BLOCKS: u64 = 4;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_PROOF_SLA_BLOCKS: u64 = 8;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_RECEIPT_SLA_BLOCKS: u64 = 3;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_MAX_FEE_CAP_MICRO_UNITS: u64 = 2_500;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_DEFI_FEE_CAP_MICRO_UNITS: u64 = 1_600;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_CONTRACT_FEE_CAP_MICRO_UNITS: u64 = 1_900;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_RECURSIVE_FEE_CAP_MICRO_UNITS: u64 = 950;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_MIN_SPONSOR_DEPOSIT_UNITS: u64 = 50_000;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_MIN_PROVER_STAKE_UNITS: u64 = 25_000;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_SLASHING_BPS: u64 = 5_000;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_PROTOCOL_FEE_BPS: u64 = 150;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_LOW_FEE_SUBSIDY_BPS: u64 = 4_000;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_RECURSIVE_DISCOUNT_BPS: u64 = 1_500;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_COMMITTEE_THRESHOLD_BPS: u64 = 6_700;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_MAX_BPS: u64 = 10_000;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_MAX_RECURSION_DEPTH: u64 = 8;
pub const PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_MAX_CHILD_PROOFS: u64 = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateProofWorkload {
    PrivateTransfer,
    PrivateSwap,
    PrivateLending,
    PrivatePerps,
    PrivateOptions,
    PrivateVault,
    SmartContractCall,
    TokenMint,
    TokenBurn,
    MoneroBridgeExit,
    MoneroBridgeDeposit,
    RecursiveAggregation,
    SettlementReceipt,
    FraudChallenge,
}

impl PrivateProofWorkload {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateSwap => "private_swap",
            Self::PrivateLending => "private_lending",
            Self::PrivatePerps => "private_perps",
            Self::PrivateOptions => "private_options",
            Self::PrivateVault => "private_vault",
            Self::SmartContractCall => "smart_contract_call",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::MoneroBridgeDeposit => "monero_bridge_deposit",
            Self::RecursiveAggregation => "recursive_aggregation",
            Self::SettlementReceipt => "settlement_receipt",
            Self::FraudChallenge => "fraud_challenge",
        }
    }

    pub fn default_fee_cap_micro_units(self) -> u64 {
        match self {
            Self::PrivateTransfer => 900,
            Self::PrivateSwap => 1_300,
            Self::PrivateLending => 1_500,
            Self::PrivatePerps => 1_700,
            Self::PrivateOptions => 1_800,
            Self::PrivateVault => 1_400,
            Self::SmartContractCall => {
                PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_CONTRACT_FEE_CAP_MICRO_UNITS
            }
            Self::TokenMint | Self::TokenBurn => 1_100,
            Self::MoneroBridgeExit | Self::MoneroBridgeDeposit => 2_200,
            Self::RecursiveAggregation => {
                PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_RECURSIVE_FEE_CAP_MICRO_UNITS
            }
            Self::SettlementReceipt => 700,
            Self::FraudChallenge => 2_500,
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::FraudChallenge => 10_000,
            Self::MoneroBridgeExit | Self::MoneroBridgeDeposit => 9_200,
            Self::PrivatePerps | Self::PrivateOptions => 8_300,
            Self::SmartContractCall => 7_800,
            Self::PrivateSwap | Self::PrivateLending => 7_200,
            Self::PrivateVault => 6_600,
            Self::TokenMint | Self::TokenBurn => 5_900,
            Self::PrivateTransfer => 5_400,
            Self::RecursiveAggregation => 4_800,
            Self::SettlementReceipt => 4_400,
        }
    }

    pub fn defi(self) -> bool {
        matches!(
            self,
            Self::PrivateSwap
                | Self::PrivateLending
                | Self::PrivatePerps
                | Self::PrivateOptions
                | Self::PrivateVault
        )
    }

    pub fn smart_contract(self) -> bool {
        matches!(
            self,
            Self::SmartContractCall
                | Self::TokenMint
                | Self::TokenBurn
                | Self::PrivateSwap
                | Self::PrivateLending
                | Self::PrivatePerps
                | Self::PrivateOptions
                | Self::PrivateVault
        )
    }

    pub fn recursive(self) -> bool {
        matches!(self, Self::RecursiveAggregation | Self::SettlementReceipt)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipLane {
    LowFeePublicGood,
    DefiExecution,
    SmartContracts,
    TokenWorkloads,
    MoneroBridge,
    RecursiveProofs,
    EmergencyChallenge,
    Maintenance,
}

impl SponsorshipLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFeePublicGood => "low_fee_public_good",
            Self::DefiExecution => "defi_execution",
            Self::SmartContracts => "smart_contracts",
            Self::TokenWorkloads => "token_workloads",
            Self::MoneroBridge => "monero_bridge",
            Self::RecursiveProofs => "recursive_proofs",
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
            Self::RecursiveProofs => 5_700,
            Self::LowFeePublicGood => 5_300,
            Self::Maintenance => 2_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialProofJobStatus {
    Open,
    Sponsored,
    Assigned,
    Proving,
    Proved,
    Aggregated,
    Receipted,
    Settled,
    Challenged,
    Slashed,
    Expired,
    Cancelled,
}

impl ConfidentialProofJobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sponsored => "sponsored",
            Self::Assigned => "assigned",
            Self::Proving => "proving",
            Self::Proved => "proved",
            Self::Aggregated => "aggregated",
            Self::Receipted => "receipted",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::Sponsored
                | Self::Assigned
                | Self::Proving
                | Self::Proved
                | Self::Aggregated
                | Self::Receipted
                | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProverAttestationStatus {
    Active,
    Suspended,
    Retired,
    Slashed,
}

impl ProverAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubsidyVaultStatus {
    Active,
    Paused,
    Depleted,
    Closed,
    Slashed,
}

impl SubsidyVaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Depleted => "depleted",
            Self::Closed => "closed",
            Self::Slashed => "slashed",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationBidStatus {
    Open,
    Accepted,
    Superseded,
    Completed,
    Rejected,
    Expired,
    Slashed,
}

impl AggregationBidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Completed => "completed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReceiptStatus {
    Pending,
    Verified,
    Paid,
    Rejected,
    Challenged,
    Slashed,
}

impl SettlementReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Paid => "paid",
            Self::Rejected => "rejected",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FraudChallengeStatus {
    Open,
    EvidenceCommitted,
    Upheld,
    Rejected,
    Expired,
    Slashed,
}

impl FraudChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceCommitted => "evidence_committed",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Open | Self::EvidenceCommitted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateProofFeeSponsorshipMarketConfig {
    pub epoch_blocks: u64,
    pub bid_window_blocks: u64,
    pub proof_sla_blocks: u64,
    pub receipt_sla_blocks: u64,
    pub challenge_window_blocks: u64,
    pub default_fee_asset_id: String,
    pub max_fee_cap_micro_units: u64,
    pub defi_fee_cap_micro_units: u64,
    pub contract_fee_cap_micro_units: u64,
    pub recursive_fee_cap_micro_units: u64,
    pub min_sponsor_deposit_units: u64,
    pub min_prover_stake_units: u64,
    pub min_pq_security_bits: u64,
    pub slashing_bps: u64,
    pub protocol_fee_bps: u64,
    pub low_fee_subsidy_bps: u64,
    pub recursive_discount_bps: u64,
    pub committee_threshold_bps: u64,
    pub pq_signature_scheme: String,
    pub pq_recovery_scheme: String,
    pub pq_kem_scheme: String,
    pub recursion_scheme: String,
    pub settlement_receipt_scheme: String,
    pub challenge_proof_system: String,
}

impl PrivateProofFeeSponsorshipMarketConfig {
    pub fn devnet() -> Self {
        Self {
            epoch_blocks: PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_EPOCH_BLOCKS,
            bid_window_blocks: PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_BID_WINDOW_BLOCKS,
            proof_sla_blocks: PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_PROOF_SLA_BLOCKS,
            receipt_sla_blocks: PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_RECEIPT_SLA_BLOCKS,
            challenge_window_blocks:
                PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            default_fee_asset_id: PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_FEE_ASSET_ID
                .to_string(),
            max_fee_cap_micro_units:
                PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_MAX_FEE_CAP_MICRO_UNITS,
            defi_fee_cap_micro_units:
                PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_DEFI_FEE_CAP_MICRO_UNITS,
            contract_fee_cap_micro_units:
                PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_CONTRACT_FEE_CAP_MICRO_UNITS,
            recursive_fee_cap_micro_units:
                PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_RECURSIVE_FEE_CAP_MICRO_UNITS,
            min_sponsor_deposit_units:
                PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_MIN_SPONSOR_DEPOSIT_UNITS,
            min_prover_stake_units:
                PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_MIN_PROVER_STAKE_UNITS,
            min_pq_security_bits: PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_SECURITY_BITS,
            slashing_bps: PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_SLASHING_BPS,
            protocol_fee_bps: PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_PROTOCOL_FEE_BPS,
            low_fee_subsidy_bps: PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_LOW_FEE_SUBSIDY_BPS,
            recursive_discount_bps:
                PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_RECURSIVE_DISCOUNT_BPS,
            committee_threshold_bps:
                PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_DEFAULT_COMMITTEE_THRESHOLD_BPS,
            pq_signature_scheme: PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_PQ_SIGNATURE_SCHEME
                .to_string(),
            pq_recovery_scheme: PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_PQ_RECOVERY_SCHEME.to_string(),
            pq_kem_scheme: PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_PQ_KEM_SCHEME.to_string(),
            recursion_scheme: PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_RECURSION_SCHEME.to_string(),
            settlement_receipt_scheme:
                PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_SETTLEMENT_RECEIPT_SCHEME.to_string(),
            challenge_proof_system: PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_CHALLENGE_PROOF_SYSTEM
                .to_string(),
        }
    }

    pub fn fee_cap_for(&self, workload: PrivateProofWorkload) -> u64 {
        if workload.recursive() {
            self.recursive_fee_cap_micro_units
        } else if workload.defi() {
            self.defi_fee_cap_micro_units
        } else if workload.smart_contract() {
            self.contract_fee_cap_micro_units
        } else {
            workload
                .default_fee_cap_micro_units()
                .min(self.max_fee_cap_micro_units)
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "epoch_blocks": self.epoch_blocks,
            "bid_window_blocks": self.bid_window_blocks,
            "proof_sla_blocks": self.proof_sla_blocks,
            "receipt_sla_blocks": self.receipt_sla_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "default_fee_asset_id": self.default_fee_asset_id,
            "max_fee_cap_micro_units": self.max_fee_cap_micro_units,
            "defi_fee_cap_micro_units": self.defi_fee_cap_micro_units,
            "contract_fee_cap_micro_units": self.contract_fee_cap_micro_units,
            "recursive_fee_cap_micro_units": self.recursive_fee_cap_micro_units,
            "min_sponsor_deposit_units": self.min_sponsor_deposit_units,
            "min_prover_stake_units": self.min_prover_stake_units,
            "min_pq_security_bits": self.min_pq_security_bits,
            "slashing_bps": self.slashing_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "low_fee_subsidy_bps": self.low_fee_subsidy_bps,
            "recursive_discount_bps": self.recursive_discount_bps,
            "committee_threshold_bps": self.committee_threshold_bps,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_recovery_scheme": self.pq_recovery_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "recursion_scheme": self.recursion_scheme,
            "settlement_receipt_scheme": self.settlement_receipt_scheme,
            "challenge_proof_system": self.challenge_proof_system,
        })
    }

    pub fn state_root(&self) -> String {
        private_proof_fee_sponsorship_payload_root("CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateProofFeeSponsorshipMarketResult<()> {
        ensure_positive("epoch_blocks", self.epoch_blocks)?;
        ensure_positive("bid_window_blocks", self.bid_window_blocks)?;
        ensure_positive("proof_sla_blocks", self.proof_sla_blocks)?;
        ensure_positive("receipt_sla_blocks", self.receipt_sla_blocks)?;
        ensure_positive("challenge_window_blocks", self.challenge_window_blocks)?;
        ensure_positive("max_fee_cap_micro_units", self.max_fee_cap_micro_units)?;
        ensure_positive("defi_fee_cap_micro_units", self.defi_fee_cap_micro_units)?;
        ensure_positive(
            "contract_fee_cap_micro_units",
            self.contract_fee_cap_micro_units,
        )?;
        ensure_positive(
            "recursive_fee_cap_micro_units",
            self.recursive_fee_cap_micro_units,
        )?;
        ensure_positive("min_sponsor_deposit_units", self.min_sponsor_deposit_units)?;
        ensure_positive("min_prover_stake_units", self.min_prover_stake_units)?;
        ensure_nonempty("default_fee_asset_id", &self.default_fee_asset_id)?;
        ensure_nonempty("pq_signature_scheme", &self.pq_signature_scheme)?;
        ensure_nonempty("pq_recovery_scheme", &self.pq_recovery_scheme)?;
        ensure_nonempty("pq_kem_scheme", &self.pq_kem_scheme)?;
        ensure_nonempty("recursion_scheme", &self.recursion_scheme)?;
        ensure_nonempty("settlement_receipt_scheme", &self.settlement_receipt_scheme)?;
        ensure_nonempty("challenge_proof_system", &self.challenge_proof_system)?;
        ensure_bps("slashing_bps", self.slashing_bps)?;
        ensure_bps("protocol_fee_bps", self.protocol_fee_bps)?;
        ensure_bps("low_fee_subsidy_bps", self.low_fee_subsidy_bps)?;
        ensure_bps("recursive_discount_bps", self.recursive_discount_bps)?;
        ensure_bps("committee_threshold_bps", self.committee_threshold_bps)?;
        if self.min_pq_security_bits < 128 {
            return Err("private proof sponsorship pq security below policy".to_string());
        }
        if self.defi_fee_cap_micro_units > self.max_fee_cap_micro_units {
            return Err("defi fee cap exceeds market maximum".to_string());
        }
        if self.contract_fee_cap_micro_units > self.max_fee_cap_micro_units {
            return Err("contract fee cap exceeds market maximum".to_string());
        }
        if self.recursive_fee_cap_micro_units > self.max_fee_cap_micro_units {
            return Err("recursive fee cap exceeds market maximum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialProofJob {
    pub job_id: String,
    pub requester_commitment: String,
    pub workload: PrivateProofWorkload,
    pub lane: SponsorshipLane,
    pub fee_asset_id: String,
    pub max_fee_micro_units: u64,
    pub subsidy_requested_units: u64,
    pub proof_system: String,
    pub encrypted_witness_commitment: String,
    pub nullifier_root: String,
    pub privacy_pool_root: String,
    pub contract_scope_commitment: String,
    pub child_proof_commitments: Vec<String>,
    pub recursion_depth: u64,
    pub min_pq_security_bits: u64,
    pub priority_weight: u64,
    pub opened_height: u64,
    pub bid_deadline_height: u64,
    pub proof_deadline_height: u64,
    pub status: ConfidentialProofJobStatus,
    pub assigned_prover_id: Option<String>,
    pub sponsor_vault_id: Option<String>,
    pub aggregation_bid_id: Option<String>,
    pub receipt_id: Option<String>,
    pub challenge_ids: BTreeSet<String>,
}

impl ConfidentialProofJob {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        requester_commitment: impl Into<String>,
        workload: PrivateProofWorkload,
        lane: SponsorshipLane,
        fee_asset_id: impl Into<String>,
        max_fee_micro_units: u64,
        subsidy_requested_units: u64,
        proof_system: impl Into<String>,
        encrypted_witness_commitment: impl Into<String>,
        nullifier_root: impl Into<String>,
        privacy_pool_root: impl Into<String>,
        contract_scope_commitment: impl Into<String>,
        child_proof_commitments: Vec<String>,
        recursion_depth: u64,
        min_pq_security_bits: u64,
        opened_height: u64,
        config: &PrivateProofFeeSponsorshipMarketConfig,
    ) -> Self {
        let requester_commitment = requester_commitment.into();
        let fee_asset_id = fee_asset_id.into();
        let proof_system = proof_system.into();
        let encrypted_witness_commitment = encrypted_witness_commitment.into();
        let nullifier_root = nullifier_root.into();
        let privacy_pool_root = privacy_pool_root.into();
        let contract_scope_commitment = contract_scope_commitment.into();
        let child_root =
            private_proof_fee_sponsorship_string_root("JOB_CHILD_PROOFS", &child_proof_commitments);
        let job_id = private_proof_fee_sponsorship_id(
            "JOB",
            &[
                HashPart::Str(&requester_commitment),
                HashPart::Str(workload.as_str()),
                HashPart::Str(lane.as_str()),
                HashPart::Str(&fee_asset_id),
                HashPart::Int(max_fee_micro_units as i128),
                HashPart::Int(subsidy_requested_units as i128),
                HashPart::Str(&proof_system),
                HashPart::Str(&encrypted_witness_commitment),
                HashPart::Str(&nullifier_root),
                HashPart::Str(&privacy_pool_root),
                HashPart::Str(&contract_scope_commitment),
                HashPart::Str(&child_root),
                HashPart::Int(recursion_depth as i128),
                HashPart::Int(opened_height as i128),
            ],
        );
        Self {
            job_id,
            requester_commitment,
            workload,
            lane,
            fee_asset_id,
            max_fee_micro_units,
            subsidy_requested_units,
            proof_system,
            encrypted_witness_commitment,
            nullifier_root,
            privacy_pool_root,
            contract_scope_commitment,
            child_proof_commitments,
            recursion_depth,
            min_pq_security_bits,
            priority_weight: workload.priority_weight() + lane.default_weight(),
            opened_height,
            bid_deadline_height: opened_height.saturating_add(config.bid_window_blocks),
            proof_deadline_height: opened_height
                .saturating_add(config.bid_window_blocks)
                .saturating_add(config.proof_sla_blocks),
            status: ConfidentialProofJobStatus::Open,
            assigned_prover_id: None,
            sponsor_vault_id: None,
            aggregation_bid_id: None,
            receipt_id: None,
            challenge_ids: BTreeSet::new(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "job_id": self.job_id,
            "requester_commitment": self.requester_commitment,
            "workload": self.workload.as_str(),
            "lane": self.lane.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "subsidy_requested_units": self.subsidy_requested_units,
            "proof_system": self.proof_system,
            "encrypted_witness_commitment": self.encrypted_witness_commitment,
            "nullifier_root": self.nullifier_root,
            "privacy_pool_root": self.privacy_pool_root,
            "contract_scope_commitment": self.contract_scope_commitment,
            "child_proof_commitments": self.child_proof_commitments,
            "recursion_depth": self.recursion_depth,
            "min_pq_security_bits": self.min_pq_security_bits,
            "priority_weight": self.priority_weight,
            "opened_height": self.opened_height,
            "bid_deadline_height": self.bid_deadline_height,
            "proof_deadline_height": self.proof_deadline_height,
            "status": self.status.as_str(),
            "assigned_prover_id": self.assigned_prover_id,
            "sponsor_vault_id": self.sponsor_vault_id,
            "aggregation_bid_id": self.aggregation_bid_id,
            "receipt_id": self.receipt_id,
            "challenge_ids": self.challenge_ids.iter().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        private_proof_fee_sponsorship_payload_root("JOB", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &PrivateProofFeeSponsorshipMarketConfig,
    ) -> PrivateProofFeeSponsorshipMarketResult<()> {
        ensure_nonempty("job_id", &self.job_id)?;
        ensure_nonempty("requester_commitment", &self.requester_commitment)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_nonempty("proof_system", &self.proof_system)?;
        ensure_nonempty(
            "encrypted_witness_commitment",
            &self.encrypted_witness_commitment,
        )?;
        ensure_nonempty("nullifier_root", &self.nullifier_root)?;
        ensure_nonempty("privacy_pool_root", &self.privacy_pool_root)?;
        ensure_nonempty("contract_scope_commitment", &self.contract_scope_commitment)?;
        ensure_positive("max_fee_micro_units", self.max_fee_micro_units)?;
        if self.max_fee_micro_units > config.fee_cap_for(self.workload) {
            return Err(format!(
                "job {} exceeds configured fee cap for {}",
                self.job_id,
                self.workload.as_str()
            ));
        }
        if self.min_pq_security_bits < config.min_pq_security_bits {
            return Err(format!(
                "job {} pq security below market floor",
                self.job_id
            ));
        }
        if self.recursion_depth > PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_MAX_RECURSION_DEPTH {
            return Err(format!("job {} recursion depth above policy", self.job_id));
        }
        if self.child_proof_commitments.len()
            > PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_MAX_CHILD_PROOFS as usize
        {
            return Err(format!("job {} has too many child proofs", self.job_id));
        }
        if self.bid_deadline_height < self.opened_height {
            return Err(format!("job {} bid deadline is not monotonic", self.job_id));
        }
        if self.proof_deadline_height < self.bid_deadline_height {
            return Err(format!(
                "job {} proof deadline before bid deadline",
                self.job_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqProverAttestation {
    pub prover_id: String,
    pub operator_commitment: String,
    pub pq_public_key_commitment: String,
    pub supported_workloads: BTreeSet<PrivateProofWorkload>,
    pub supported_lanes: BTreeSet<SponsorshipLane>,
    pub stake_asset_id: String,
    pub stake_units: u64,
    pub max_parallel_jobs: u64,
    pub fee_floor_micro_units: u64,
    pub pq_security_bits: u64,
    pub attestation_commitment: String,
    pub verifier_committee_root: String,
    pub registered_height: u64,
    pub last_seen_height: u64,
    pub slashed_units: u64,
    pub completed_jobs: u64,
    pub status: ProverAttestationStatus,
}

impl PqProverAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_commitment: impl Into<String>,
        pq_public_key_commitment: impl Into<String>,
        supported_workloads: BTreeSet<PrivateProofWorkload>,
        supported_lanes: BTreeSet<SponsorshipLane>,
        stake_asset_id: impl Into<String>,
        stake_units: u64,
        max_parallel_jobs: u64,
        fee_floor_micro_units: u64,
        pq_security_bits: u64,
        attestation_commitment: impl Into<String>,
        verifier_committee_root: impl Into<String>,
        registered_height: u64,
    ) -> Self {
        let operator_commitment = operator_commitment.into();
        let pq_public_key_commitment = pq_public_key_commitment.into();
        let stake_asset_id = stake_asset_id.into();
        let attestation_commitment = attestation_commitment.into();
        let verifier_committee_root = verifier_committee_root.into();
        let workload_root = private_proof_fee_sponsorship_workload_root(&supported_workloads);
        let lane_root = private_proof_fee_sponsorship_lane_root(&supported_lanes);
        let prover_id = private_proof_fee_sponsorship_id(
            "PROVER",
            &[
                HashPart::Str(&operator_commitment),
                HashPart::Str(&pq_public_key_commitment),
                HashPart::Str(&stake_asset_id),
                HashPart::Int(stake_units as i128),
                HashPart::Int(max_parallel_jobs as i128),
                HashPart::Int(fee_floor_micro_units as i128),
                HashPart::Int(pq_security_bits as i128),
                HashPart::Str(&attestation_commitment),
                HashPart::Str(&verifier_committee_root),
                HashPart::Str(&workload_root),
                HashPart::Str(&lane_root),
                HashPart::Int(registered_height as i128),
            ],
        );
        Self {
            prover_id,
            operator_commitment,
            pq_public_key_commitment,
            supported_workloads,
            supported_lanes,
            stake_asset_id,
            stake_units,
            max_parallel_jobs,
            fee_floor_micro_units,
            pq_security_bits,
            attestation_commitment,
            verifier_committee_root,
            registered_height,
            last_seen_height: registered_height,
            slashed_units: 0,
            completed_jobs: 0,
            status: ProverAttestationStatus::Active,
        }
    }

    pub fn can_prove(&self, job: &ConfidentialProofJob) -> bool {
        self.status.usable()
            && self.supported_workloads.contains(&job.workload)
            && self.supported_lanes.contains(&job.lane)
            && self.pq_security_bits >= job.min_pq_security_bits
            && self.fee_floor_micro_units <= job.max_fee_micro_units
    }

    pub fn public_record(&self) -> Value {
        json!({
            "prover_id": self.prover_id,
            "operator_commitment": self.operator_commitment,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "supported_workloads": self.supported_workloads.iter().map(|value| value.as_str()).collect::<Vec<_>>(),
            "supported_lanes": self.supported_lanes.iter().map(|value| value.as_str()).collect::<Vec<_>>(),
            "stake_asset_id": self.stake_asset_id,
            "stake_units": self.stake_units,
            "max_parallel_jobs": self.max_parallel_jobs,
            "fee_floor_micro_units": self.fee_floor_micro_units,
            "pq_security_bits": self.pq_security_bits,
            "attestation_commitment": self.attestation_commitment,
            "verifier_committee_root": self.verifier_committee_root,
            "registered_height": self.registered_height,
            "last_seen_height": self.last_seen_height,
            "slashed_units": self.slashed_units,
            "completed_jobs": self.completed_jobs,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        private_proof_fee_sponsorship_payload_root("PROVER", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &PrivateProofFeeSponsorshipMarketConfig,
    ) -> PrivateProofFeeSponsorshipMarketResult<()> {
        ensure_nonempty("prover_id", &self.prover_id)?;
        ensure_nonempty("operator_commitment", &self.operator_commitment)?;
        ensure_nonempty("pq_public_key_commitment", &self.pq_public_key_commitment)?;
        ensure_nonempty("stake_asset_id", &self.stake_asset_id)?;
        ensure_nonempty("attestation_commitment", &self.attestation_commitment)?;
        ensure_nonempty("verifier_committee_root", &self.verifier_committee_root)?;
        ensure_positive("stake_units", self.stake_units)?;
        ensure_positive("max_parallel_jobs", self.max_parallel_jobs)?;
        if self.supported_workloads.is_empty() {
            return Err(format!("prover {} has no workloads", self.prover_id));
        }
        if self.supported_lanes.is_empty() {
            return Err(format!("prover {} has no lanes", self.prover_id));
        }
        if self.stake_units < config.min_prover_stake_units {
            return Err(format!("prover {} stake below policy", self.prover_id));
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err(format!(
                "prover {} pq security below policy",
                self.prover_id
            ));
        }
        if self.last_seen_height < self.registered_height {
            return Err(format!(
                "prover {} last seen before registration",
                self.prover_id
            ));
        }
        if self.slashed_units > self.stake_units {
            return Err(format!("prover {} overslashed", self.prover_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSubsidyVault {
    pub vault_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub deposit_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub slashed_units: u64,
    pub eligible_lanes: BTreeSet<SponsorshipLane>,
    pub eligible_workloads: BTreeSet<PrivateProofWorkload>,
    pub max_fee_cap_micro_units: u64,
    pub per_job_subsidy_cap_units: u64,
    pub low_fee_subsidy_bps: u64,
    pub opened_height: u64,
    pub last_accounted_height: u64,
    pub status: SubsidyVaultStatus,
}

impl LowFeeSubsidyVault {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: impl Into<String>,
        fee_asset_id: impl Into<String>,
        deposit_units: u64,
        eligible_lanes: BTreeSet<SponsorshipLane>,
        eligible_workloads: BTreeSet<PrivateProofWorkload>,
        max_fee_cap_micro_units: u64,
        per_job_subsidy_cap_units: u64,
        low_fee_subsidy_bps: u64,
        opened_height: u64,
    ) -> Self {
        let sponsor_commitment = sponsor_commitment.into();
        let fee_asset_id = fee_asset_id.into();
        let lane_root = private_proof_fee_sponsorship_lane_root(&eligible_lanes);
        let workload_root = private_proof_fee_sponsorship_workload_root(&eligible_workloads);
        let vault_id = private_proof_fee_sponsorship_id(
            "VAULT",
            &[
                HashPart::Str(&sponsor_commitment),
                HashPart::Str(&fee_asset_id),
                HashPart::Int(deposit_units as i128),
                HashPart::Str(&lane_root),
                HashPart::Str(&workload_root),
                HashPart::Int(max_fee_cap_micro_units as i128),
                HashPart::Int(per_job_subsidy_cap_units as i128),
                HashPart::Int(low_fee_subsidy_bps as i128),
                HashPart::Int(opened_height as i128),
            ],
        );
        Self {
            vault_id,
            sponsor_commitment,
            fee_asset_id,
            deposit_units,
            reserved_units: 0,
            spent_units: 0,
            slashed_units: 0,
            eligible_lanes,
            eligible_workloads,
            max_fee_cap_micro_units,
            per_job_subsidy_cap_units,
            low_fee_subsidy_bps,
            opened_height,
            last_accounted_height: opened_height,
            status: SubsidyVaultStatus::Active,
        }
    }

    pub fn available_units(&self) -> u64 {
        self.deposit_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
            .saturating_sub(self.slashed_units)
    }

    pub fn can_sponsor(&self, job: &ConfidentialProofJob) -> bool {
        self.status.usable()
            && self.fee_asset_id == job.fee_asset_id
            && self.eligible_lanes.contains(&job.lane)
            && self.eligible_workloads.contains(&job.workload)
            && job.max_fee_micro_units <= self.max_fee_cap_micro_units
            && job.subsidy_requested_units <= self.per_job_subsidy_cap_units
            && self.available_units() >= job.subsidy_requested_units
    }

    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "deposit_units": self.deposit_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "slashed_units": self.slashed_units,
            "available_units": self.available_units(),
            "eligible_lanes": self.eligible_lanes.iter().map(|value| value.as_str()).collect::<Vec<_>>(),
            "eligible_workloads": self.eligible_workloads.iter().map(|value| value.as_str()).collect::<Vec<_>>(),
            "max_fee_cap_micro_units": self.max_fee_cap_micro_units,
            "per_job_subsidy_cap_units": self.per_job_subsidy_cap_units,
            "low_fee_subsidy_bps": self.low_fee_subsidy_bps,
            "opened_height": self.opened_height,
            "last_accounted_height": self.last_accounted_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        private_proof_fee_sponsorship_payload_root("VAULT", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &PrivateProofFeeSponsorshipMarketConfig,
    ) -> PrivateProofFeeSponsorshipMarketResult<()> {
        ensure_nonempty("vault_id", &self.vault_id)?;
        ensure_nonempty("sponsor_commitment", &self.sponsor_commitment)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_positive("deposit_units", self.deposit_units)?;
        ensure_positive("max_fee_cap_micro_units", self.max_fee_cap_micro_units)?;
        ensure_positive("per_job_subsidy_cap_units", self.per_job_subsidy_cap_units)?;
        ensure_bps("low_fee_subsidy_bps", self.low_fee_subsidy_bps)?;
        if self.eligible_lanes.is_empty() {
            return Err(format!("vault {} has no eligible lanes", self.vault_id));
        }
        if self.eligible_workloads.is_empty() {
            return Err(format!("vault {} has no eligible workloads", self.vault_id));
        }
        if self.deposit_units < config.min_sponsor_deposit_units {
            return Err(format!("vault {} deposit below policy", self.vault_id));
        }
        if self.max_fee_cap_micro_units > config.max_fee_cap_micro_units {
            return Err(format!("vault {} fee cap exceeds policy", self.vault_id));
        }
        if self
            .reserved_units
            .saturating_add(self.spent_units)
            .saturating_add(self.slashed_units)
            > self.deposit_units
        {
            return Err(format!(
                "vault {} accounting exceeds deposit",
                self.vault_id
            ));
        }
        if self.last_accounted_height < self.opened_height {
            return Err(format!(
                "vault {} last accounted before opened height",
                self.vault_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveAggregationBid {
    pub bid_id: String,
    pub job_ids: BTreeSet<String>,
    pub prover_id: String,
    pub fee_asset_id: String,
    pub bid_fee_micro_units: u64,
    pub aggregate_subsidy_units: u64,
    pub recursion_depth: u64,
    pub compression_savings_bps: u64,
    pub aggregate_proof_commitment: String,
    pub opened_height: u64,
    pub expires_height: u64,
    pub status: AggregationBidStatus,
}

impl RecursiveAggregationBid {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_ids: BTreeSet<String>,
        prover_id: impl Into<String>,
        fee_asset_id: impl Into<String>,
        bid_fee_micro_units: u64,
        aggregate_subsidy_units: u64,
        recursion_depth: u64,
        compression_savings_bps: u64,
        aggregate_proof_commitment: impl Into<String>,
        opened_height: u64,
        config: &PrivateProofFeeSponsorshipMarketConfig,
    ) -> Self {
        let prover_id = prover_id.into();
        let fee_asset_id = fee_asset_id.into();
        let aggregate_proof_commitment = aggregate_proof_commitment.into();
        let job_root = private_proof_fee_sponsorship_string_set_root("BID_JOBS", &job_ids);
        let bid_id = private_proof_fee_sponsorship_id(
            "AGGREGATION_BID",
            &[
                HashPart::Str(&job_root),
                HashPart::Str(&prover_id),
                HashPart::Str(&fee_asset_id),
                HashPart::Int(bid_fee_micro_units as i128),
                HashPart::Int(aggregate_subsidy_units as i128),
                HashPart::Int(recursion_depth as i128),
                HashPart::Int(compression_savings_bps as i128),
                HashPart::Str(&aggregate_proof_commitment),
                HashPart::Int(opened_height as i128),
            ],
        );
        Self {
            bid_id,
            job_ids,
            prover_id,
            fee_asset_id,
            bid_fee_micro_units,
            aggregate_subsidy_units,
            recursion_depth,
            compression_savings_bps,
            aggregate_proof_commitment,
            opened_height,
            expires_height: opened_height.saturating_add(config.bid_window_blocks),
            status: AggregationBidStatus::Open,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "job_ids": self.job_ids.iter().cloned().collect::<Vec<_>>(),
            "prover_id": self.prover_id,
            "fee_asset_id": self.fee_asset_id,
            "bid_fee_micro_units": self.bid_fee_micro_units,
            "aggregate_subsidy_units": self.aggregate_subsidy_units,
            "recursion_depth": self.recursion_depth,
            "compression_savings_bps": self.compression_savings_bps,
            "aggregate_proof_commitment": self.aggregate_proof_commitment,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        private_proof_fee_sponsorship_payload_root("AGGREGATION_BID", &self.public_record())
    }

    pub fn validate(&self) -> PrivateProofFeeSponsorshipMarketResult<()> {
        ensure_nonempty("bid_id", &self.bid_id)?;
        ensure_nonempty("prover_id", &self.prover_id)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_nonempty(
            "aggregate_proof_commitment",
            &self.aggregate_proof_commitment,
        )?;
        ensure_positive("bid_fee_micro_units", self.bid_fee_micro_units)?;
        ensure_bps("compression_savings_bps", self.compression_savings_bps)?;
        if self.job_ids.is_empty() {
            return Err(format!("aggregation bid {} has no jobs", self.bid_id));
        }
        if self.job_ids.len() > PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_MAX_CHILD_PROOFS as usize {
            return Err(format!("aggregation bid {} has too many jobs", self.bid_id));
        }
        if self.recursion_depth > PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_MAX_RECURSION_DEPTH {
            return Err(format!(
                "aggregation bid {} recursion depth above policy",
                self.bid_id
            ));
        }
        if self.expires_height < self.opened_height {
            return Err(format!(
                "aggregation bid {} expiry is not monotonic",
                self.bid_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsoredSettlementReceipt {
    pub receipt_id: String,
    pub job_id: String,
    pub prover_id: String,
    pub vault_id: String,
    pub aggregation_bid_id: Option<String>,
    pub fee_asset_id: String,
    pub prover_fee_units: u64,
    pub sponsor_paid_units: u64,
    pub protocol_fee_units: u64,
    pub subsidy_units: u64,
    pub proof_commitment: String,
    pub recursive_proof_commitment: String,
    pub settlement_nullifier: String,
    pub receipt_commitment: String,
    pub opened_height: u64,
    pub verified_height: Option<u64>,
    pub paid_height: Option<u64>,
    pub status: SettlementReceiptStatus,
}

impl SponsoredSettlementReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_id: impl Into<String>,
        prover_id: impl Into<String>,
        vault_id: impl Into<String>,
        aggregation_bid_id: Option<String>,
        fee_asset_id: impl Into<String>,
        prover_fee_units: u64,
        sponsor_paid_units: u64,
        protocol_fee_units: u64,
        subsidy_units: u64,
        proof_commitment: impl Into<String>,
        recursive_proof_commitment: impl Into<String>,
        settlement_nullifier: impl Into<String>,
        opened_height: u64,
    ) -> Self {
        let job_id = job_id.into();
        let prover_id = prover_id.into();
        let vault_id = vault_id.into();
        let fee_asset_id = fee_asset_id.into();
        let proof_commitment = proof_commitment.into();
        let recursive_proof_commitment = recursive_proof_commitment.into();
        let settlement_nullifier = settlement_nullifier.into();
        let aggregation_part = match aggregation_bid_id.as_ref() {
            Some(value) => value.as_str(),
            None => "none",
        };
        let receipt_commitment = private_proof_fee_sponsorship_id(
            "RECEIPT_COMMITMENT",
            &[
                HashPart::Str(&job_id),
                HashPart::Str(&prover_id),
                HashPart::Str(&vault_id),
                HashPart::Str(aggregation_part),
                HashPart::Str(&fee_asset_id),
                HashPart::Int(prover_fee_units as i128),
                HashPart::Int(sponsor_paid_units as i128),
                HashPart::Int(protocol_fee_units as i128),
                HashPart::Int(subsidy_units as i128),
                HashPart::Str(&proof_commitment),
                HashPart::Str(&recursive_proof_commitment),
                HashPart::Str(&settlement_nullifier),
                HashPart::Int(opened_height as i128),
            ],
        );
        let receipt_id = private_proof_fee_sponsorship_id(
            "RECEIPT",
            &[
                HashPart::Str(&job_id),
                HashPart::Str(&prover_id),
                HashPart::Str(&vault_id),
                HashPart::Str(&receipt_commitment),
            ],
        );
        Self {
            receipt_id,
            job_id,
            prover_id,
            vault_id,
            aggregation_bid_id,
            fee_asset_id,
            prover_fee_units,
            sponsor_paid_units,
            protocol_fee_units,
            subsidy_units,
            proof_commitment,
            recursive_proof_commitment,
            settlement_nullifier,
            receipt_commitment,
            opened_height,
            verified_height: None,
            paid_height: None,
            status: SettlementReceiptStatus::Pending,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "job_id": self.job_id,
            "prover_id": self.prover_id,
            "vault_id": self.vault_id,
            "aggregation_bid_id": self.aggregation_bid_id,
            "fee_asset_id": self.fee_asset_id,
            "prover_fee_units": self.prover_fee_units,
            "sponsor_paid_units": self.sponsor_paid_units,
            "protocol_fee_units": self.protocol_fee_units,
            "subsidy_units": self.subsidy_units,
            "proof_commitment": self.proof_commitment,
            "recursive_proof_commitment": self.recursive_proof_commitment,
            "settlement_nullifier": self.settlement_nullifier,
            "receipt_commitment": self.receipt_commitment,
            "opened_height": self.opened_height,
            "verified_height": self.verified_height,
            "paid_height": self.paid_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        private_proof_fee_sponsorship_payload_root("RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> PrivateProofFeeSponsorshipMarketResult<()> {
        ensure_nonempty("receipt_id", &self.receipt_id)?;
        ensure_nonempty("job_id", &self.job_id)?;
        ensure_nonempty("prover_id", &self.prover_id)?;
        ensure_nonempty("vault_id", &self.vault_id)?;
        ensure_nonempty("fee_asset_id", &self.fee_asset_id)?;
        ensure_nonempty("proof_commitment", &self.proof_commitment)?;
        ensure_nonempty(
            "recursive_proof_commitment",
            &self.recursive_proof_commitment,
        )?;
        ensure_nonempty("settlement_nullifier", &self.settlement_nullifier)?;
        ensure_nonempty("receipt_commitment", &self.receipt_commitment)?;
        ensure_positive("prover_fee_units", self.prover_fee_units)?;
        if let Some(verified_height) = self.verified_height {
            if verified_height < self.opened_height {
                return Err(format!("receipt {} verified before open", self.receipt_id));
            }
        }
        if let Some(paid_height) = self.paid_height {
            if paid_height < self.opened_height {
                return Err(format!("receipt {} paid before open", self.receipt_id));
            }
            if let Some(verified_height) = self.verified_height {
                if paid_height < verified_height {
                    return Err(format!(
                        "receipt {} paid before verification",
                        self.receipt_id
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFraudChallenge {
    pub challenge_id: String,
    pub job_id: String,
    pub receipt_id: Option<String>,
    pub challenger_commitment: String,
    pub target_prover_id: String,
    pub target_vault_id: Option<String>,
    pub evidence_commitment: String,
    pub challenge_proof_system: String,
    pub bond_asset_id: String,
    pub challenger_bond_units: u64,
    pub slash_bps: u64,
    pub opened_height: u64,
    pub response_deadline_height: u64,
    pub resolved_height: Option<u64>,
    pub status: FraudChallengeStatus,
}

impl ProofFraudChallenge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_id: impl Into<String>,
        receipt_id: Option<String>,
        challenger_commitment: impl Into<String>,
        target_prover_id: impl Into<String>,
        target_vault_id: Option<String>,
        evidence_commitment: impl Into<String>,
        challenge_proof_system: impl Into<String>,
        bond_asset_id: impl Into<String>,
        challenger_bond_units: u64,
        slash_bps: u64,
        opened_height: u64,
        config: &PrivateProofFeeSponsorshipMarketConfig,
    ) -> Self {
        let job_id = job_id.into();
        let challenger_commitment = challenger_commitment.into();
        let target_prover_id = target_prover_id.into();
        let evidence_commitment = evidence_commitment.into();
        let challenge_proof_system = challenge_proof_system.into();
        let bond_asset_id = bond_asset_id.into();
        let receipt_part = match receipt_id.as_ref() {
            Some(value) => value.as_str(),
            None => "none",
        };
        let vault_part = match target_vault_id.as_ref() {
            Some(value) => value.as_str(),
            None => "none",
        };
        let challenge_id = private_proof_fee_sponsorship_id(
            "CHALLENGE",
            &[
                HashPart::Str(&job_id),
                HashPart::Str(receipt_part),
                HashPart::Str(&challenger_commitment),
                HashPart::Str(&target_prover_id),
                HashPart::Str(vault_part),
                HashPart::Str(&evidence_commitment),
                HashPart::Str(&challenge_proof_system),
                HashPart::Str(&bond_asset_id),
                HashPart::Int(challenger_bond_units as i128),
                HashPart::Int(slash_bps as i128),
                HashPart::Int(opened_height as i128),
            ],
        );
        Self {
            challenge_id,
            job_id,
            receipt_id,
            challenger_commitment,
            target_prover_id,
            target_vault_id,
            evidence_commitment,
            challenge_proof_system,
            bond_asset_id,
            challenger_bond_units,
            slash_bps,
            opened_height,
            response_deadline_height: opened_height.saturating_add(config.challenge_window_blocks),
            resolved_height: None,
            status: FraudChallengeStatus::Open,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "job_id": self.job_id,
            "receipt_id": self.receipt_id,
            "challenger_commitment": self.challenger_commitment,
            "target_prover_id": self.target_prover_id,
            "target_vault_id": self.target_vault_id,
            "evidence_commitment": self.evidence_commitment,
            "challenge_proof_system": self.challenge_proof_system,
            "bond_asset_id": self.bond_asset_id,
            "challenger_bond_units": self.challenger_bond_units,
            "slash_bps": self.slash_bps,
            "opened_height": self.opened_height,
            "response_deadline_height": self.response_deadline_height,
            "resolved_height": self.resolved_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        private_proof_fee_sponsorship_payload_root("CHALLENGE", &self.public_record())
    }

    pub fn validate(&self) -> PrivateProofFeeSponsorshipMarketResult<()> {
        ensure_nonempty("challenge_id", &self.challenge_id)?;
        ensure_nonempty("job_id", &self.job_id)?;
        ensure_nonempty("challenger_commitment", &self.challenger_commitment)?;
        ensure_nonempty("target_prover_id", &self.target_prover_id)?;
        ensure_nonempty("evidence_commitment", &self.evidence_commitment)?;
        ensure_nonempty("challenge_proof_system", &self.challenge_proof_system)?;
        ensure_nonempty("bond_asset_id", &self.bond_asset_id)?;
        ensure_positive("challenger_bond_units", self.challenger_bond_units)?;
        ensure_bps("slash_bps", self.slash_bps)?;
        if self.response_deadline_height < self.opened_height {
            return Err(format!(
                "challenge {} response deadline is not monotonic",
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
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateProofFeeSponsorshipMarketCounters {
    pub jobs: usize,
    pub live_jobs: usize,
    pub provers: usize,
    pub active_provers: usize,
    pub subsidy_vaults: usize,
    pub active_vaults: usize,
    pub aggregation_bids: usize,
    pub open_aggregation_bids: usize,
    pub settlement_receipts: usize,
    pub paid_receipts: usize,
    pub fraud_challenges: usize,
    pub open_challenges: usize,
    pub total_subsidy_deposited_units: u64,
    pub total_subsidy_reserved_units: u64,
    pub total_subsidy_spent_units: u64,
    pub total_slashed_units: u64,
}

impl PrivateProofFeeSponsorshipMarketCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "jobs": self.jobs,
            "live_jobs": self.live_jobs,
            "provers": self.provers,
            "active_provers": self.active_provers,
            "subsidy_vaults": self.subsidy_vaults,
            "active_vaults": self.active_vaults,
            "aggregation_bids": self.aggregation_bids,
            "open_aggregation_bids": self.open_aggregation_bids,
            "settlement_receipts": self.settlement_receipts,
            "paid_receipts": self.paid_receipts,
            "fraud_challenges": self.fraud_challenges,
            "open_challenges": self.open_challenges,
            "total_subsidy_deposited_units": self.total_subsidy_deposited_units,
            "total_subsidy_reserved_units": self.total_subsidy_reserved_units,
            "total_subsidy_spent_units": self.total_subsidy_spent_units,
            "total_slashed_units": self.total_slashed_units,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateProofFeeSponsorshipMarketRoots {
    pub config_root: String,
    pub jobs_root: String,
    pub provers_root: String,
    pub subsidy_vaults_root: String,
    pub aggregation_bids_root: String,
    pub settlement_receipts_root: String,
    pub fraud_challenges_root: String,
    pub fee_caps_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl PrivateProofFeeSponsorshipMarketRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "jobs_root": self.jobs_root,
            "provers_root": self.provers_root,
            "subsidy_vaults_root": self.subsidy_vaults_root,
            "aggregation_bids_root": self.aggregation_bids_root,
            "settlement_receipts_root": self.settlement_receipts_root,
            "fraud_challenges_root": self.fraud_challenges_root,
            "fee_caps_root": self.fee_caps_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateProofFeeSponsorshipMarketState {
    pub chain_id: String,
    pub height: u64,
    pub epoch: u64,
    pub config: PrivateProofFeeSponsorshipMarketConfig,
    pub jobs: BTreeMap<String, ConfidentialProofJob>,
    pub provers: BTreeMap<String, PqProverAttestation>,
    pub subsidy_vaults: BTreeMap<String, LowFeeSubsidyVault>,
    pub aggregation_bids: BTreeMap<String, RecursiveAggregationBid>,
    pub settlement_receipts: BTreeMap<String, SponsoredSettlementReceipt>,
    pub fraud_challenges: BTreeMap<String, ProofFraudChallenge>,
    pub fee_caps: BTreeMap<PrivateProofWorkload, u64>,
}

impl PrivateProofFeeSponsorshipMarketState {
    pub fn new(height: u64, config: PrivateProofFeeSponsorshipMarketConfig) -> Self {
        let epoch = if config.epoch_blocks == 0 {
            0
        } else {
            height / config.epoch_blocks
        };
        let mut fee_caps = BTreeMap::new();
        for workload in private_proof_fee_sponsorship_all_workloads() {
            fee_caps.insert(workload, config.fee_cap_for(workload));
        }
        Self {
            chain_id: CHAIN_ID.to_string(),
            height,
            epoch,
            config,
            jobs: BTreeMap::new(),
            provers: BTreeMap::new(),
            subsidy_vaults: BTreeMap::new(),
            aggregation_bids: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            fraud_challenges: BTreeMap::new(),
            fee_caps,
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(1, PrivateProofFeeSponsorshipMarketConfig::devnet());
        let mut public_good_lanes = BTreeSet::new();
        public_good_lanes.insert(SponsorshipLane::LowFeePublicGood);
        public_good_lanes.insert(SponsorshipLane::SmartContracts);
        public_good_lanes.insert(SponsorshipLane::DefiExecution);
        public_good_lanes.insert(SponsorshipLane::RecursiveProofs);
        let mut public_good_workloads = BTreeSet::new();
        public_good_workloads.insert(PrivateProofWorkload::PrivateTransfer);
        public_good_workloads.insert(PrivateProofWorkload::PrivateSwap);
        public_good_workloads.insert(PrivateProofWorkload::PrivateLending);
        public_good_workloads.insert(PrivateProofWorkload::SmartContractCall);
        public_good_workloads.insert(PrivateProofWorkload::RecursiveAggregation);
        let vault = LowFeeSubsidyVault::new(
            "sponsor:devnet-low-fee-public-good",
            state.config.default_fee_asset_id.clone(),
            5_000_000,
            public_good_lanes.clone(),
            public_good_workloads.clone(),
            state.config.max_fee_cap_micro_units,
            100_000,
            state.config.low_fee_subsidy_bps,
            state.height,
        );
        let mut prover_workloads = public_good_workloads;
        prover_workloads.insert(PrivateProofWorkload::MoneroBridgeExit);
        prover_workloads.insert(PrivateProofWorkload::SettlementReceipt);
        prover_workloads.insert(PrivateProofWorkload::FraudChallenge);
        let mut prover_lanes = public_good_lanes;
        prover_lanes.insert(SponsorshipLane::MoneroBridge);
        prover_lanes.insert(SponsorshipLane::EmergencyChallenge);
        let prover = PqProverAttestation::new(
            "operator:devnet-pq-prover",
            "pqpk:devnet-ml-dsa-87-prover",
            prover_workloads,
            prover_lanes,
            state.config.default_fee_asset_id.clone(),
            250_000,
            16,
            500,
            256,
            "attestation:devnet-pq-prover-confidential-proof-fees",
            "committee:devnet-private-proof-fee-sponsors",
            state.height,
        );
        let _ = state.register_subsidy_vault(vault);
        let _ = state.register_pq_prover(prover);
        state
    }

    pub fn update_height(&mut self, new_height: u64) -> PrivateProofFeeSponsorshipMarketResult<()> {
        if new_height < self.height {
            return Err("private proof sponsorship height cannot decrease".to_string());
        }
        self.height = new_height;
        self.epoch = self.height / self.config.epoch_blocks;
        self.expire_stale_records();
        Ok(())
    }

    pub fn register_pq_prover(
        &mut self,
        prover: PqProverAttestation,
    ) -> PrivateProofFeeSponsorshipMarketResult<String> {
        prover.validate(&self.config)?;
        if self.provers.contains_key(&prover.prover_id) {
            return Err(format!("prover {} already registered", prover.prover_id));
        }
        let prover_id = prover.prover_id.clone();
        self.provers.insert(prover_id.clone(), prover);
        Ok(prover_id)
    }

    pub fn register_subsidy_vault(
        &mut self,
        vault: LowFeeSubsidyVault,
    ) -> PrivateProofFeeSponsorshipMarketResult<String> {
        vault.validate(&self.config)?;
        if self.subsidy_vaults.contains_key(&vault.vault_id) {
            return Err(format!("vault {} already registered", vault.vault_id));
        }
        let vault_id = vault.vault_id.clone();
        self.subsidy_vaults.insert(vault_id.clone(), vault);
        Ok(vault_id)
    }

    pub fn open_confidential_job(
        &mut self,
        job: ConfidentialProofJob,
    ) -> PrivateProofFeeSponsorshipMarketResult<String> {
        job.validate(&self.config)?;
        if self.jobs.contains_key(&job.job_id) {
            return Err(format!("job {} already exists", job.job_id));
        }
        if job.opened_height > self.height {
            return Err(format!("job {} opens in the future", job.job_id));
        }
        let job_id = job.job_id.clone();
        self.jobs.insert(job_id.clone(), job);
        Ok(job_id)
    }

    pub fn sponsor_job(
        &mut self,
        job_id: &str,
        vault_id: &str,
    ) -> PrivateProofFeeSponsorshipMarketResult<()> {
        let job_snapshot = self
            .jobs
            .get(job_id)
            .cloned()
            .ok_or_else(|| format!("unknown job {job_id}"))?;
        if job_snapshot.status != ConfidentialProofJobStatus::Open {
            return Err(format!("job {job_id} is not open"));
        }
        let vault = self
            .subsidy_vaults
            .get_mut(vault_id)
            .ok_or_else(|| format!("unknown vault {vault_id}"))?;
        if !vault.can_sponsor(&job_snapshot) {
            return Err(format!("vault {vault_id} cannot sponsor job {job_id}"));
        }
        vault.reserved_units = vault
            .reserved_units
            .saturating_add(job_snapshot.subsidy_requested_units);
        vault.last_accounted_height = self.height;
        let job = self
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| format!("unknown job {job_id}"))?;
        job.status = ConfidentialProofJobStatus::Sponsored;
        job.sponsor_vault_id = Some(vault_id.to_string());
        Ok(())
    }

    pub fn assign_prover(
        &mut self,
        job_id: &str,
        prover_id: &str,
    ) -> PrivateProofFeeSponsorshipMarketResult<()> {
        let job_snapshot = self
            .jobs
            .get(job_id)
            .cloned()
            .ok_or_else(|| format!("unknown job {job_id}"))?;
        if !matches!(
            job_snapshot.status,
            ConfidentialProofJobStatus::Open | ConfidentialProofJobStatus::Sponsored
        ) {
            return Err(format!("job {job_id} cannot be assigned"));
        }
        let active_count = self
            .jobs
            .values()
            .filter(|job| {
                job.assigned_prover_id.as_deref() == Some(prover_id)
                    && matches!(
                        job.status,
                        ConfidentialProofJobStatus::Assigned | ConfidentialProofJobStatus::Proving
                    )
            })
            .count() as u64;
        let prover = self
            .provers
            .get_mut(prover_id)
            .ok_or_else(|| format!("unknown prover {prover_id}"))?;
        if !prover.can_prove(&job_snapshot) {
            return Err(format!("prover {prover_id} cannot prove job {job_id}"));
        }
        if active_count >= prover.max_parallel_jobs {
            return Err(format!("prover {prover_id} has no spare capacity"));
        }
        prover.last_seen_height = self.height;
        let job = self
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| format!("unknown job {job_id}"))?;
        job.assigned_prover_id = Some(prover_id.to_string());
        job.status = ConfidentialProofJobStatus::Assigned;
        Ok(())
    }

    pub fn mark_proving(&mut self, job_id: &str) -> PrivateProofFeeSponsorshipMarketResult<()> {
        let job = self
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| format!("unknown job {job_id}"))?;
        if job.status != ConfidentialProofJobStatus::Assigned {
            return Err(format!("job {job_id} is not assigned"));
        }
        job.status = ConfidentialProofJobStatus::Proving;
        Ok(())
    }

    pub fn submit_proof(
        &mut self,
        job_id: &str,
        proof_commitment: &str,
    ) -> PrivateProofFeeSponsorshipMarketResult<String> {
        ensure_nonempty("proof_commitment", proof_commitment)?;
        let job = self
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| format!("unknown job {job_id}"))?;
        if !matches!(
            job.status,
            ConfidentialProofJobStatus::Assigned | ConfidentialProofJobStatus::Proving
        ) {
            return Err(format!("job {job_id} is not awaiting proof"));
        }
        if self.height > job.proof_deadline_height {
            job.status = ConfidentialProofJobStatus::Expired;
            return Err(format!("job {job_id} proof missed deadline"));
        }
        job.status = ConfidentialProofJobStatus::Proved;
        Ok(private_proof_fee_sponsorship_id(
            "PROOF_SUBMISSION",
            &[
                HashPart::Str(job_id),
                HashPart::Str(proof_commitment),
                HashPart::Int(self.height as i128),
            ],
        ))
    }

    pub fn place_aggregation_bid(
        &mut self,
        bid: RecursiveAggregationBid,
    ) -> PrivateProofFeeSponsorshipMarketResult<String> {
        bid.validate()?;
        if self.aggregation_bids.contains_key(&bid.bid_id) {
            return Err(format!("aggregation bid {} already exists", bid.bid_id));
        }
        let prover = self
            .provers
            .get(&bid.prover_id)
            .ok_or_else(|| format!("unknown prover {}", bid.prover_id))?;
        if !prover.status.usable() {
            return Err(format!("prover {} is not active", bid.prover_id));
        }
        for job_id in &bid.job_ids {
            let job = self
                .jobs
                .get(job_id)
                .ok_or_else(|| format!("unknown job {job_id}"))?;
            if job.status != ConfidentialProofJobStatus::Proved {
                return Err(format!("job {job_id} is not proved"));
            }
            if job.fee_asset_id != bid.fee_asset_id {
                return Err(format!("job {job_id} fee asset mismatches bid"));
            }
        }
        let bid_id = bid.bid_id.clone();
        self.aggregation_bids.insert(bid_id.clone(), bid);
        Ok(bid_id)
    }

    pub fn accept_aggregation_bid(
        &mut self,
        bid_id: &str,
    ) -> PrivateProofFeeSponsorshipMarketResult<()> {
        let bid_snapshot = self
            .aggregation_bids
            .get(bid_id)
            .cloned()
            .ok_or_else(|| format!("unknown aggregation bid {bid_id}"))?;
        if bid_snapshot.status != AggregationBidStatus::Open {
            return Err(format!("aggregation bid {bid_id} is not open"));
        }
        if self.height > bid_snapshot.expires_height {
            let bid = self
                .aggregation_bids
                .get_mut(bid_id)
                .ok_or_else(|| format!("unknown aggregation bid {bid_id}"))?;
            bid.status = AggregationBidStatus::Expired;
            return Err(format!("aggregation bid {bid_id} expired"));
        }
        for job_id in &bid_snapshot.job_ids {
            let job = self
                .jobs
                .get_mut(job_id)
                .ok_or_else(|| format!("unknown job {job_id}"))?;
            job.aggregation_bid_id = Some(bid_id.to_string());
            job.status = ConfidentialProofJobStatus::Aggregated;
        }
        let bid = self
            .aggregation_bids
            .get_mut(bid_id)
            .ok_or_else(|| format!("unknown aggregation bid {bid_id}"))?;
        bid.status = AggregationBidStatus::Accepted;
        Ok(())
    }

    pub fn settle_receipt(
        &mut self,
        receipt: SponsoredSettlementReceipt,
    ) -> PrivateProofFeeSponsorshipMarketResult<String> {
        receipt.validate()?;
        if self.settlement_receipts.contains_key(&receipt.receipt_id) {
            return Err(format!("receipt {} already exists", receipt.receipt_id));
        }
        let job = self
            .jobs
            .get(&receipt.job_id)
            .cloned()
            .ok_or_else(|| format!("unknown job {}", receipt.job_id))?;
        if !matches!(
            job.status,
            ConfidentialProofJobStatus::Proved | ConfidentialProofJobStatus::Aggregated
        ) {
            return Err(format!("job {} is not settleable", receipt.job_id));
        }
        if job.assigned_prover_id.as_deref() != Some(receipt.prover_id.as_str()) {
            return Err(format!("receipt {} prover mismatch", receipt.receipt_id));
        }
        if job.sponsor_vault_id.as_deref() != Some(receipt.vault_id.as_str()) {
            return Err(format!("receipt {} vault mismatch", receipt.receipt_id));
        }
        if job.subsidy_requested_units != receipt.subsidy_units {
            return Err(format!("receipt {} subsidy mismatch", receipt.receipt_id));
        }
        let vault = self
            .subsidy_vaults
            .get_mut(&receipt.vault_id)
            .ok_or_else(|| format!("unknown vault {}", receipt.vault_id))?;
        if vault.reserved_units < receipt.subsidy_units {
            return Err(format!("vault {} reserve below receipt", receipt.vault_id));
        }
        vault.reserved_units = vault.reserved_units.saturating_sub(receipt.subsidy_units);
        vault.spent_units = vault.spent_units.saturating_add(receipt.sponsor_paid_units);
        vault.last_accounted_height = self.height;
        if vault.available_units() == 0 {
            vault.status = SubsidyVaultStatus::Depleted;
        }
        let prover = self
            .provers
            .get_mut(&receipt.prover_id)
            .ok_or_else(|| format!("unknown prover {}", receipt.prover_id))?;
        prover.completed_jobs = prover.completed_jobs.saturating_add(1);
        prover.last_seen_height = self.height;
        let receipt_id = receipt.receipt_id.clone();
        self.settlement_receipts
            .insert(receipt_id.clone(), receipt.clone());
        let stored_job = self
            .jobs
            .get_mut(&receipt.job_id)
            .ok_or_else(|| format!("unknown job {}", receipt.job_id))?;
        stored_job.receipt_id = Some(receipt_id.clone());
        stored_job.status = ConfidentialProofJobStatus::Receipted;
        Ok(receipt_id)
    }

    pub fn verify_receipt(
        &mut self,
        receipt_id: &str,
    ) -> PrivateProofFeeSponsorshipMarketResult<()> {
        let receipt = self
            .settlement_receipts
            .get_mut(receipt_id)
            .ok_or_else(|| format!("unknown receipt {receipt_id}"))?;
        if receipt.status != SettlementReceiptStatus::Pending {
            return Err(format!("receipt {receipt_id} is not pending"));
        }
        receipt.verified_height = Some(self.height);
        receipt.status = SettlementReceiptStatus::Verified;
        Ok(())
    }

    pub fn pay_receipt(&mut self, receipt_id: &str) -> PrivateProofFeeSponsorshipMarketResult<()> {
        let receipt = self
            .settlement_receipts
            .get_mut(receipt_id)
            .ok_or_else(|| format!("unknown receipt {receipt_id}"))?;
        if receipt.status != SettlementReceiptStatus::Verified {
            return Err(format!("receipt {receipt_id} is not verified"));
        }
        receipt.paid_height = Some(self.height);
        receipt.status = SettlementReceiptStatus::Paid;
        let job = self
            .jobs
            .get_mut(&receipt.job_id)
            .ok_or_else(|| format!("unknown job {}", receipt.job_id))?;
        job.status = ConfidentialProofJobStatus::Settled;
        if let Some(bid_id) = &receipt.aggregation_bid_id {
            if let Some(bid) = self.aggregation_bids.get_mut(bid_id) {
                bid.status = AggregationBidStatus::Completed;
            }
        }
        Ok(())
    }

    pub fn open_fraud_challenge(
        &mut self,
        challenge: ProofFraudChallenge,
    ) -> PrivateProofFeeSponsorshipMarketResult<String> {
        challenge.validate()?;
        if self.fraud_challenges.contains_key(&challenge.challenge_id) {
            return Err(format!(
                "challenge {} already exists",
                challenge.challenge_id
            ));
        }
        if !self.jobs.contains_key(&challenge.job_id) {
            return Err(format!("unknown job {}", challenge.job_id));
        }
        if !self.provers.contains_key(&challenge.target_prover_id) {
            return Err(format!("unknown prover {}", challenge.target_prover_id));
        }
        if let Some(receipt_id) = &challenge.receipt_id {
            if !self.settlement_receipts.contains_key(receipt_id) {
                return Err(format!("unknown receipt {receipt_id}"));
            }
        }
        if let Some(vault_id) = &challenge.target_vault_id {
            if !self.subsidy_vaults.contains_key(vault_id) {
                return Err(format!("unknown vault {vault_id}"));
            }
        }
        let challenge_id = challenge.challenge_id.clone();
        let job = self
            .jobs
            .get_mut(&challenge.job_id)
            .ok_or_else(|| format!("unknown job {}", challenge.job_id))?;
        job.challenge_ids.insert(challenge_id.clone());
        job.status = ConfidentialProofJobStatus::Challenged;
        if let Some(receipt_id) = &challenge.receipt_id {
            if let Some(receipt) = self.settlement_receipts.get_mut(receipt_id) {
                receipt.status = SettlementReceiptStatus::Challenged;
            }
        }
        self.fraud_challenges
            .insert(challenge_id.clone(), challenge);
        Ok(challenge_id)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        upheld: bool,
    ) -> PrivateProofFeeSponsorshipMarketResult<()> {
        let challenge_snapshot = self
            .fraud_challenges
            .get(challenge_id)
            .cloned()
            .ok_or_else(|| format!("unknown challenge {challenge_id}"))?;
        if !challenge_snapshot.status.open() {
            return Err(format!("challenge {challenge_id} is not open"));
        }
        if upheld {
            self.apply_challenge_slash(&challenge_snapshot)?;
        }
        let challenge = self
            .fraud_challenges
            .get_mut(challenge_id)
            .ok_or_else(|| format!("unknown challenge {challenge_id}"))?;
        challenge.resolved_height = Some(self.height);
        challenge.status = if upheld {
            FraudChallengeStatus::Upheld
        } else {
            FraudChallengeStatus::Rejected
        };
        if !upheld {
            if let Some(job) = self.jobs.get_mut(&challenge.job_id) {
                if job.status == ConfidentialProofJobStatus::Challenged {
                    job.status = ConfidentialProofJobStatus::Receipted;
                }
            }
            if let Some(receipt_id) = &challenge.receipt_id {
                if let Some(receipt) = self.settlement_receipts.get_mut(receipt_id) {
                    if receipt.status == SettlementReceiptStatus::Challenged {
                        receipt.status = SettlementReceiptStatus::Verified;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "height": self.height,
            "epoch": self.epoch,
            "protocol_version": PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_PROTOCOL_VERSION,
            "schema_version": PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_SCHEMA_VERSION,
            "hash_suite": PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_HASH_SUITE,
            "config": self.config.public_record(),
            "jobs": self.jobs.values().map(ConfidentialProofJob::public_record).collect::<Vec<_>>(),
            "provers": self.provers.values().map(PqProverAttestation::public_record).collect::<Vec<_>>(),
            "subsidy_vaults": self.subsidy_vaults.values().map(LowFeeSubsidyVault::public_record).collect::<Vec<_>>(),
            "aggregation_bids": self.aggregation_bids.values().map(RecursiveAggregationBid::public_record).collect::<Vec<_>>(),
            "settlement_receipts": self.settlement_receipts.values().map(SponsoredSettlementReceipt::public_record).collect::<Vec<_>>(),
            "fraud_challenges": self.fraud_challenges.values().map(ProofFraudChallenge::public_record).collect::<Vec<_>>(),
            "fee_caps": self.fee_caps.iter().map(|(workload, cap)| json!({
                "workload": workload.as_str(),
                "fee_cap_micro_units": cap,
            })).collect::<Vec<_>>(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn counters(&self) -> PrivateProofFeeSponsorshipMarketCounters {
        PrivateProofFeeSponsorshipMarketCounters {
            jobs: self.jobs.len(),
            live_jobs: self.jobs.values().filter(|job| job.status.live()).count(),
            provers: self.provers.len(),
            active_provers: self
                .provers
                .values()
                .filter(|prover| prover.status.usable())
                .count(),
            subsidy_vaults: self.subsidy_vaults.len(),
            active_vaults: self
                .subsidy_vaults
                .values()
                .filter(|vault| vault.status.usable())
                .count(),
            aggregation_bids: self.aggregation_bids.len(),
            open_aggregation_bids: self
                .aggregation_bids
                .values()
                .filter(|bid| bid.status == AggregationBidStatus::Open)
                .count(),
            settlement_receipts: self.settlement_receipts.len(),
            paid_receipts: self
                .settlement_receipts
                .values()
                .filter(|receipt| receipt.status == SettlementReceiptStatus::Paid)
                .count(),
            fraud_challenges: self.fraud_challenges.len(),
            open_challenges: self
                .fraud_challenges
                .values()
                .filter(|challenge| challenge.status.open())
                .count(),
            total_subsidy_deposited_units: self
                .subsidy_vaults
                .values()
                .map(|vault| vault.deposit_units)
                .sum(),
            total_subsidy_reserved_units: self
                .subsidy_vaults
                .values()
                .map(|vault| vault.reserved_units)
                .sum(),
            total_subsidy_spent_units: self
                .subsidy_vaults
                .values()
                .map(|vault| vault.spent_units)
                .sum(),
            total_slashed_units: self
                .subsidy_vaults
                .values()
                .map(|vault| vault.slashed_units)
                .sum::<u64>()
                .saturating_add(
                    self.provers
                        .values()
                        .map(|prover| prover.slashed_units)
                        .sum::<u64>(),
                ),
        }
    }

    pub fn roots(&self) -> PrivateProofFeeSponsorshipMarketRoots {
        let config_root = self.config.state_root();
        let jobs_root = private_proof_fee_sponsorship_records_root(
            "JOBS",
            self.jobs
                .values()
                .map(ConfidentialProofJob::public_record)
                .collect::<Vec<_>>(),
        );
        let provers_root = private_proof_fee_sponsorship_records_root(
            "PROVERS",
            self.provers
                .values()
                .map(PqProverAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        let subsidy_vaults_root = private_proof_fee_sponsorship_records_root(
            "SUBSIDY_VAULTS",
            self.subsidy_vaults
                .values()
                .map(LowFeeSubsidyVault::public_record)
                .collect::<Vec<_>>(),
        );
        let aggregation_bids_root = private_proof_fee_sponsorship_records_root(
            "AGGREGATION_BIDS",
            self.aggregation_bids
                .values()
                .map(RecursiveAggregationBid::public_record)
                .collect::<Vec<_>>(),
        );
        let settlement_receipts_root = private_proof_fee_sponsorship_records_root(
            "SETTLEMENT_RECEIPTS",
            self.settlement_receipts
                .values()
                .map(SponsoredSettlementReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let fraud_challenges_root = private_proof_fee_sponsorship_records_root(
            "FRAUD_CHALLENGES",
            self.fraud_challenges
                .values()
                .map(ProofFraudChallenge::public_record)
                .collect::<Vec<_>>(),
        );
        let fee_caps_root = private_proof_fee_sponsorship_records_root(
            "FEE_CAPS",
            self.fee_caps
                .iter()
                .map(|(workload, cap)| {
                    json!({
                        "workload": workload.as_str(),
                        "fee_cap_micro_units": cap,
                    })
                })
                .collect::<Vec<_>>(),
        );
        let counters = self.counters().public_record();
        let counters_root = private_proof_fee_sponsorship_payload_root("COUNTERS", &counters);
        let roots_record = json!({
            "chain_id": self.chain_id,
            "height": self.height,
            "epoch": self.epoch,
            "protocol_version": PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_PROTOCOL_VERSION,
            "schema_version": PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_SCHEMA_VERSION,
            "config_root": config_root,
            "jobs_root": jobs_root,
            "provers_root": provers_root,
            "subsidy_vaults_root": subsidy_vaults_root,
            "aggregation_bids_root": aggregation_bids_root,
            "settlement_receipts_root": settlement_receipts_root,
            "fraud_challenges_root": fraud_challenges_root,
            "fee_caps_root": fee_caps_root,
            "counters_root": counters_root,
        });
        let state_root = private_proof_fee_sponsorship_payload_root("STATE_ROOT", &roots_record);
        PrivateProofFeeSponsorshipMarketRoots {
            config_root,
            jobs_root,
            provers_root,
            subsidy_vaults_root,
            aggregation_bids_root,
            settlement_receipts_root,
            fraud_challenges_root,
            fee_caps_root,
            counters_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn validate(&self) -> PrivateProofFeeSponsorshipMarketResult<()> {
        ensure_nonempty("chain_id", &self.chain_id)?;
        if self.chain_id != CHAIN_ID {
            return Err("private proof sponsorship chain id mismatch".to_string());
        }
        self.config.validate()?;
        if self.epoch != self.height / self.config.epoch_blocks {
            return Err("private proof sponsorship epoch mismatch".to_string());
        }
        for (workload, cap) in &self.fee_caps {
            ensure_positive("fee_cap", *cap)?;
            if *cap > self.config.fee_cap_for(*workload) {
                return Err(format!("fee cap for {} exceeds config", workload.as_str()));
            }
        }
        for job in self.jobs.values() {
            job.validate(&self.config)?;
            if let Some(prover_id) = &job.assigned_prover_id {
                if !self.provers.contains_key(prover_id) {
                    return Err(format!("job {} references unknown prover", job.job_id));
                }
            }
            if let Some(vault_id) = &job.sponsor_vault_id {
                if !self.subsidy_vaults.contains_key(vault_id) {
                    return Err(format!("job {} references unknown vault", job.job_id));
                }
            }
            if let Some(bid_id) = &job.aggregation_bid_id {
                if !self.aggregation_bids.contains_key(bid_id) {
                    return Err(format!(
                        "job {} references unknown aggregation bid",
                        job.job_id
                    ));
                }
            }
            if let Some(receipt_id) = &job.receipt_id {
                if !self.settlement_receipts.contains_key(receipt_id) {
                    return Err(format!("job {} references unknown receipt", job.job_id));
                }
            }
            for challenge_id in &job.challenge_ids {
                if !self.fraud_challenges.contains_key(challenge_id) {
                    return Err(format!("job {} references unknown challenge", job.job_id));
                }
            }
        }
        for prover in self.provers.values() {
            prover.validate(&self.config)?;
        }
        for vault in self.subsidy_vaults.values() {
            vault.validate(&self.config)?;
        }
        for bid in self.aggregation_bids.values() {
            bid.validate()?;
            if !self.provers.contains_key(&bid.prover_id) {
                return Err(format!("bid {} references unknown prover", bid.bid_id));
            }
            for job_id in &bid.job_ids {
                if !self.jobs.contains_key(job_id) {
                    return Err(format!("bid {} references unknown job", bid.bid_id));
                }
            }
        }
        for receipt in self.settlement_receipts.values() {
            receipt.validate()?;
            if !self.jobs.contains_key(&receipt.job_id) {
                return Err(format!(
                    "receipt {} references unknown job",
                    receipt.receipt_id
                ));
            }
            if !self.provers.contains_key(&receipt.prover_id) {
                return Err(format!(
                    "receipt {} references unknown prover",
                    receipt.receipt_id
                ));
            }
            if !self.subsidy_vaults.contains_key(&receipt.vault_id) {
                return Err(format!(
                    "receipt {} references unknown vault",
                    receipt.receipt_id
                ));
            }
        }
        for challenge in self.fraud_challenges.values() {
            challenge.validate()?;
            if !self.jobs.contains_key(&challenge.job_id) {
                return Err(format!(
                    "challenge {} references unknown job",
                    challenge.challenge_id
                ));
            }
            if !self.provers.contains_key(&challenge.target_prover_id) {
                return Err(format!(
                    "challenge {} references unknown prover",
                    challenge.challenge_id
                ));
            }
        }
        Ok(())
    }

    fn expire_stale_records(&mut self) {
        for job in self.jobs.values_mut() {
            if matches!(
                job.status,
                ConfidentialProofJobStatus::Open | ConfidentialProofJobStatus::Sponsored
            ) && self.height > job.bid_deadline_height
            {
                job.status = ConfidentialProofJobStatus::Expired;
            }
            if matches!(
                job.status,
                ConfidentialProofJobStatus::Assigned | ConfidentialProofJobStatus::Proving
            ) && self.height > job.proof_deadline_height
            {
                job.status = ConfidentialProofJobStatus::Expired;
            }
        }
        for bid in self.aggregation_bids.values_mut() {
            if bid.status == AggregationBidStatus::Open && self.height > bid.expires_height {
                bid.status = AggregationBidStatus::Expired;
            }
        }
        for challenge in self.fraud_challenges.values_mut() {
            if challenge.status.open() && self.height > challenge.response_deadline_height {
                challenge.status = FraudChallengeStatus::Expired;
            }
        }
    }

    fn apply_challenge_slash(
        &mut self,
        challenge: &ProofFraudChallenge,
    ) -> PrivateProofFeeSponsorshipMarketResult<()> {
        let prover = self
            .provers
            .get_mut(&challenge.target_prover_id)
            .ok_or_else(|| format!("unknown prover {}", challenge.target_prover_id))?;
        let prover_slash = mul_bps(prover.stake_units, challenge.slash_bps);
        prover.slashed_units = prover
            .slashed_units
            .saturating_add(prover_slash)
            .min(prover.stake_units);
        prover.status = ProverAttestationStatus::Slashed;
        if let Some(vault_id) = &challenge.target_vault_id {
            let vault = self
                .subsidy_vaults
                .get_mut(vault_id)
                .ok_or_else(|| format!("unknown vault {vault_id}"))?;
            let vault_slash = mul_bps(vault.deposit_units, challenge.slash_bps);
            vault.slashed_units = vault
                .slashed_units
                .saturating_add(vault_slash)
                .min(vault.deposit_units);
            vault.status = SubsidyVaultStatus::Slashed;
        }
        if let Some(job) = self.jobs.get_mut(&challenge.job_id) {
            job.status = ConfidentialProofJobStatus::Slashed;
        }
        if let Some(receipt_id) = &challenge.receipt_id {
            if let Some(receipt) = self.settlement_receipts.get_mut(receipt_id) {
                receipt.status = SettlementReceiptStatus::Slashed;
            }
        }
        Ok(())
    }
}

pub fn private_proof_fee_sponsorship_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET:{domain}"),
        &[
            HashPart::Str(PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_PROTOCOL_VERSION),
            HashPart::Int(PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_SCHEMA_VERSION as i128),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn private_proof_fee_sponsorship_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_ID:{domain}"),
        parts,
        16,
    )
}

pub fn private_proof_fee_sponsorship_records_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!("PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_RECORDS:{domain}"),
        &records,
    )
}

pub fn private_proof_fee_sponsorship_string_root(domain: &str, values: &[String]) -> String {
    let records = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    private_proof_fee_sponsorship_records_root(domain, records)
}

pub fn private_proof_fee_sponsorship_string_set_root(
    domain: &str,
    values: &BTreeSet<String>,
) -> String {
    let records = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    private_proof_fee_sponsorship_records_root(domain, records)
}

pub fn private_proof_fee_sponsorship_workload_root(
    values: &BTreeSet<PrivateProofWorkload>,
) -> String {
    let records = values
        .iter()
        .map(|value| json!({ "workload": value.as_str() }))
        .collect::<Vec<_>>();
    private_proof_fee_sponsorship_records_root("WORKLOAD_SET", records)
}

pub fn private_proof_fee_sponsorship_lane_root(values: &BTreeSet<SponsorshipLane>) -> String {
    let records = values
        .iter()
        .map(|value| json!({ "lane": value.as_str() }))
        .collect::<Vec<_>>();
    private_proof_fee_sponsorship_records_root("LANE_SET", records)
}

pub fn private_proof_fee_sponsorship_all_workloads() -> Vec<PrivateProofWorkload> {
    vec![
        PrivateProofWorkload::PrivateTransfer,
        PrivateProofWorkload::PrivateSwap,
        PrivateProofWorkload::PrivateLending,
        PrivateProofWorkload::PrivatePerps,
        PrivateProofWorkload::PrivateOptions,
        PrivateProofWorkload::PrivateVault,
        PrivateProofWorkload::SmartContractCall,
        PrivateProofWorkload::TokenMint,
        PrivateProofWorkload::TokenBurn,
        PrivateProofWorkload::MoneroBridgeExit,
        PrivateProofWorkload::MoneroBridgeDeposit,
        PrivateProofWorkload::RecursiveAggregation,
        PrivateProofWorkload::SettlementReceipt,
        PrivateProofWorkload::FraudChallenge,
    ]
}

pub fn private_proof_fee_sponsorship_all_lanes() -> Vec<SponsorshipLane> {
    vec![
        SponsorshipLane::LowFeePublicGood,
        SponsorshipLane::DefiExecution,
        SponsorshipLane::SmartContracts,
        SponsorshipLane::TokenWorkloads,
        SponsorshipLane::MoneroBridge,
        SponsorshipLane::RecursiveProofs,
        SponsorshipLane::EmergencyChallenge,
        SponsorshipLane::Maintenance,
    ]
}

fn ensure_nonempty(name: &str, value: &str) -> PrivateProofFeeSponsorshipMarketResult<()> {
    if value.trim().is_empty() {
        Err(format!("{name} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(name: &str, value: u64) -> PrivateProofFeeSponsorshipMarketResult<()> {
    if value == 0 {
        Err(format!("{name} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(name: &str, value: u64) -> PrivateProofFeeSponsorshipMarketResult<()> {
    if value > PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_MAX_BPS {
        Err(format!("{name} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn mul_bps(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / PRIVATE_PROOF_FEE_SPONSORSHIP_MARKET_MAX_BPS
}
