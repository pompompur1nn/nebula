use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqRecursiveSettlementCompressorResult<T> = Result<T, String>;

pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PROTOCOL_VERSION: &str =
    "nebula-l2-pq-recursive-settlement-compressor-v1";
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_SCHEMA_VERSION: u64 = 1;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PQ_RECOVERY_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_RECURSION_SCHEME: &str =
    "nebula-devnet-folded-pq-recursive-settlement-v1";
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_COMPRESSION_SCHEME: &str =
    "shake256-pq-settlement-proof-compression-v1";
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_SETTLEMENT_CERTIFICATE_SCHEME: &str =
    "monero-l2-recursive-settlement-certificate-v1";
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DA_BUDGET_SCHEME: &str =
    "namespace-erasure-da-byte-budget-v1";
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEVNET_OPERATOR_ID: &str =
    "pq-recursive-settlement-operator-devnet";
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEVNET_SPONSOR_ID: &str =
    "pq-recursive-settlement-sponsor-devnet";
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEVNET_COMMITTEE_ID: &str =
    "pq-recursive-settlement-committee-devnet";
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEVNET_HEIGHT: u64 = 432;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_MAX_JOBS_PER_AGGREGATE: usize = 96;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_MAX_RECURSION_DEPTH: u64 = 8;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_MAX_DA_BYTES_PER_EPOCH: u64 = 2_000_000;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_MAX_COMPRESSED_PROOF_BYTES: u64 = 48_000;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_TARGET_VERIFY_MICROS: u64 = 25_000;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_AGGREGATE_WINDOW_BLOCKS: u64 = 6;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_FINALITY_CONFIRMATIONS: u64 = 20;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_COMMITTEE_SIZE: u64 = 7;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_COMMITTEE_THRESHOLD_BPS: u64 = 6_667;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_LOW_FEE_FLOOR_MICRO_UNITS: u64 = 5;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_SPONSOR_REBATE_BPS: u64 = 8_000;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_SPONSOR_POOL_MICRO_UNITS: u64 = 250_000;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_DA_SPONSOR_BPS: u64 = 4_000;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_LATE_PENALTY_BPS: u64 = 1_500;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_SLASHING_BPS: u64 = 5_000;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_MAX_BPS: u64 = 10_000;
pub const PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_MAX_RECORDS: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementCircuitFamily {
    MoneroBridge,
    RollupState,
    PrivateTransfer,
    ContractExecution,
    FeeAccounting,
    RecursiveSettlement,
    DaAvailability,
}

impl SettlementCircuitFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroBridge => "monero_bridge",
            Self::RollupState => "rollup_state",
            Self::PrivateTransfer => "private_transfer",
            Self::ContractExecution => "contract_execution",
            Self::FeeAccounting => "fee_accounting",
            Self::RecursiveSettlement => "recursive_settlement",
            Self::DaAvailability => "da_availability",
        }
    }

    pub fn default_proof_system(self) -> &'static str {
        match self {
            Self::MoneroBridge => "nebula-devnet-pq-monero-bridge-settlement-v1",
            Self::RollupState => "nebula-devnet-pq-rollup-state-settlement-v1",
            Self::PrivateTransfer => "nebula-devnet-pq-private-transfer-settlement-v1",
            Self::ContractExecution => "nebula-devnet-pq-contract-execution-settlement-v1",
            Self::FeeAccounting => "nebula-devnet-pq-fee-accounting-settlement-v1",
            Self::RecursiveSettlement => "nebula-devnet-pq-recursive-settlement-v1",
            Self::DaAvailability => "nebula-devnet-pq-da-availability-v1",
        }
    }

    pub fn monero_sensitive(self) -> bool {
        matches!(self, Self::MoneroBridge | Self::PrivateTransfer)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofJobKind {
    BaseSettlement,
    RecursiveAggregate,
    ProofCompression,
    DaAvailability,
    CommitteeVerification,
    LowFeeSponsored,
    SettlementFinality,
}

impl ProofJobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BaseSettlement => "base_settlement",
            Self::RecursiveAggregate => "recursive_aggregate",
            Self::ProofCompression => "proof_compression",
            Self::DaAvailability => "da_availability",
            Self::CommitteeVerification => "committee_verification",
            Self::LowFeeSponsored => "low_fee_sponsored",
            Self::SettlementFinality => "settlement_finality",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementLane {
    MoneroExit,
    MoneroDeposit,
    PrivateRollup,
    PublicRollup,
    SponsoredLowFee,
    Emergency,
    Maintenance,
}

impl SettlementLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroExit => "monero_exit",
            Self::MoneroDeposit => "monero_deposit",
            Self::PrivateRollup => "private_rollup",
            Self::PublicRollup => "public_rollup",
            Self::SponsoredLowFee => "sponsored_low_fee",
            Self::Emergency => "emergency",
            Self::Maintenance => "maintenance",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::MoneroExit => 9_200,
            Self::MoneroDeposit => 8_800,
            Self::PrivateRollup => 8_000,
            Self::PublicRollup => 6_800,
            Self::SponsoredLowFee => 6_200,
            Self::Maintenance => 2_500,
        }
    }

    pub fn low_fee_lane(self) -> bool {
        matches!(self, Self::SponsoredLowFee)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofJobStatus {
    Queued,
    Aggregating,
    Proving,
    Compressed,
    DaBudgeted,
    Attested,
    Certified,
    SettlementReady,
    Settled,
    Rejected,
    Expired,
}

impl ProofJobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Aggregating => "aggregating",
            Self::Proving => "proving",
            Self::Compressed => "compressed",
            Self::DaBudgeted => "da_budgeted",
            Self::Attested => "attested",
            Self::Certified => "certified",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Queued
                | Self::Aggregating
                | Self::Proving
                | Self::Compressed
                | Self::DaBudgeted
                | Self::Attested
                | Self::Certified
                | Self::SettlementReady
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateStatus {
    Collecting,
    Sealed,
    Proving,
    Compressed,
    Attested,
    Certified,
    ChallengeOpen,
    SettlementReady,
    Settled,
    Rejected,
}

impl AggregateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::Proving => "proving",
            Self::Compressed => "compressed",
            Self::Attested => "attested",
            Self::Certified => "certified",
            Self::ChallengeOpen => "challenge_open",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
        }
    }

    pub fn accepts_jobs(self) -> bool {
        matches!(self, Self::Collecting)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateStatus {
    Pending,
    Verified,
    Attested,
    Finalized,
    Challenged,
    Revoked,
    Settled,
}

impl CertificateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Attested => "attested",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
            Self::Settled => "settled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Reserved,
    Applied,
    Reclaimed,
    Exhausted,
    Revoked,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Reclaimed => "reclaimed",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationRole {
    Prover,
    Aggregator,
    DaCommittee,
    SettlementCommittee,
    Sponsor,
    Watchtower,
}

impl PqAttestationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prover => "prover",
            Self::Aggregator => "aggregator",
            Self::DaCommittee => "da_committee",
            Self::SettlementCommittee => "settlement_committee",
            Self::Sponsor => "sponsor",
            Self::Watchtower => "watchtower",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRecursiveSettlementCompressorConfig {
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_signature_scheme: String,
    pub pq_recovery_scheme: String,
    pub pq_kem_scheme: String,
    pub recursion_scheme: String,
    pub compression_scheme: String,
    pub settlement_certificate_scheme: String,
    pub da_budget_scheme: String,
    pub max_jobs_per_aggregate: usize,
    pub max_recursion_depth: u64,
    pub max_da_bytes_per_epoch: u64,
    pub max_compressed_proof_bytes: u64,
    pub target_verify_micros: u64,
    pub aggregate_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub finality_confirmations: u64,
    pub committee_size: u64,
    pub committee_threshold_bps: u64,
    pub low_fee_floor_micro_units: u64,
    pub sponsor_rebate_bps: u64,
    pub sponsor_pool_micro_units: u64,
    pub da_sponsor_bps: u64,
    pub late_penalty_bps: u64,
    pub slashing_bps: u64,
}

impl Default for PqRecursiveSettlementCompressorConfig {
    fn default() -> Self {
        Self {
            monero_network: PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_MONERO_NETWORK.to_string(),
            l2_network: PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_L2_NETWORK.to_string(),
            fee_asset_id: PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_FEE_ASSET_ID.to_string(),
            hash_suite: PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_HASH_SUITE.to_string(),
            pq_signature_scheme: PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PQ_SIGNATURE_SCHEME.to_string(),
            pq_recovery_scheme: PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PQ_RECOVERY_SCHEME.to_string(),
            pq_kem_scheme: PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PQ_KEM_SCHEME.to_string(),
            recursion_scheme: PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_RECURSION_SCHEME.to_string(),
            compression_scheme: PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_COMPRESSION_SCHEME.to_string(),
            settlement_certificate_scheme:
                PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_SETTLEMENT_CERTIFICATE_SCHEME.to_string(),
            da_budget_scheme: PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DA_BUDGET_SCHEME.to_string(),
            max_jobs_per_aggregate:
                PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_MAX_JOBS_PER_AGGREGATE,
            max_recursion_depth: PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_MAX_RECURSION_DEPTH,
            max_da_bytes_per_epoch:
                PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_MAX_DA_BYTES_PER_EPOCH,
            max_compressed_proof_bytes:
                PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_MAX_COMPRESSED_PROOF_BYTES,
            target_verify_micros: PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_TARGET_VERIFY_MICROS,
            aggregate_window_blocks:
                PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_AGGREGATE_WINDOW_BLOCKS,
            challenge_window_blocks:
                PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            finality_confirmations:
                PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_FINALITY_CONFIRMATIONS,
            committee_size: PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_COMMITTEE_SIZE,
            committee_threshold_bps:
                PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_COMMITTEE_THRESHOLD_BPS,
            low_fee_floor_micro_units:
                PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_LOW_FEE_FLOOR_MICRO_UNITS,
            sponsor_rebate_bps: PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_SPONSOR_REBATE_BPS,
            sponsor_pool_micro_units:
                PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_SPONSOR_POOL_MICRO_UNITS,
            da_sponsor_bps: PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_DA_SPONSOR_BPS,
            late_penalty_bps: PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_LATE_PENALTY_BPS,
            slashing_bps: PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_SLASHING_BPS,
        }
    }
}

impl PqRecursiveSettlementCompressorConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_recursive_settlement_compressor_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PROTOCOL_VERSION,
            "schema_version": PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_SCHEMA_VERSION,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_signature_scheme": self.pq_signature_scheme,
            "pq_recovery_scheme": self.pq_recovery_scheme,
            "pq_kem_scheme": self.pq_kem_scheme,
            "recursion_scheme": self.recursion_scheme,
            "compression_scheme": self.compression_scheme,
            "settlement_certificate_scheme": self.settlement_certificate_scheme,
            "da_budget_scheme": self.da_budget_scheme,
            "max_jobs_per_aggregate": self.max_jobs_per_aggregate,
            "max_recursion_depth": self.max_recursion_depth,
            "max_da_bytes_per_epoch": self.max_da_bytes_per_epoch,
            "max_compressed_proof_bytes": self.max_compressed_proof_bytes,
            "target_verify_micros": self.target_verify_micros,
            "aggregate_window_blocks": self.aggregate_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "finality_confirmations": self.finality_confirmations,
            "committee_size": self.committee_size,
            "committee_threshold_bps": self.committee_threshold_bps,
            "low_fee_floor_micro_units": self.low_fee_floor_micro_units,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "sponsor_pool_micro_units": self.sponsor_pool_micro_units,
            "da_sponsor_bps": self.da_sponsor_bps,
            "late_penalty_bps": self.late_penalty_bps,
            "slashing_bps": self.slashing_bps,
        })
    }

    pub fn validate(&self) -> PqRecursiveSettlementCompressorResult<()> {
        ensure_non_empty("config.monero_network", &self.monero_network)?;
        ensure_non_empty("config.l2_network", &self.l2_network)?;
        ensure_non_empty("config.fee_asset_id", &self.fee_asset_id)?;
        ensure_non_empty("config.hash_suite", &self.hash_suite)?;
        ensure_non_empty("config.pq_signature_scheme", &self.pq_signature_scheme)?;
        ensure_non_empty("config.pq_recovery_scheme", &self.pq_recovery_scheme)?;
        ensure_non_empty("config.pq_kem_scheme", &self.pq_kem_scheme)?;
        ensure_non_empty("config.recursion_scheme", &self.recursion_scheme)?;
        ensure_non_empty("config.compression_scheme", &self.compression_scheme)?;
        ensure_non_empty(
            "config.settlement_certificate_scheme",
            &self.settlement_certificate_scheme,
        )?;
        ensure_non_empty("config.da_budget_scheme", &self.da_budget_scheme)?;
        ensure_positive_usize("config.max_jobs_per_aggregate", self.max_jobs_per_aggregate)?;
        ensure_positive("config.max_recursion_depth", self.max_recursion_depth)?;
        ensure_positive("config.max_da_bytes_per_epoch", self.max_da_bytes_per_epoch)?;
        ensure_positive(
            "config.max_compressed_proof_bytes",
            self.max_compressed_proof_bytes,
        )?;
        ensure_positive("config.target_verify_micros", self.target_verify_micros)?;
        ensure_positive(
            "config.aggregate_window_blocks",
            self.aggregate_window_blocks,
        )?;
        ensure_positive(
            "config.challenge_window_blocks",
            self.challenge_window_blocks,
        )?;
        ensure_positive("config.finality_confirmations", self.finality_confirmations)?;
        ensure_positive("config.committee_size", self.committee_size)?;
        ensure_bps(
            "config.committee_threshold_bps",
            self.committee_threshold_bps,
        )?;
        ensure_bps("config.sponsor_rebate_bps", self.sponsor_rebate_bps)?;
        ensure_bps("config.da_sponsor_bps", self.da_sponsor_bps)?;
        ensure_bps("config.late_penalty_bps", self.late_penalty_bps)?;
        ensure_bps("config.slashing_bps", self.slashing_bps)?;
        if self.committee_threshold_bps == 0 {
            return Err("config.committee_threshold_bps must be greater than zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitFamilyProfile {
    pub circuit_id: String,
    pub family: SettlementCircuitFamily,
    pub proof_system: String,
    pub verifier_key_root: String,
    pub proving_key_root: String,
    pub recursion_adapter_root: String,
    pub max_witness_bytes: u64,
    pub max_proof_bytes: u64,
    pub target_verify_micros: u64,
    pub security_bits: u64,
    pub active: bool,
}

impl CircuitFamilyProfile {
    pub fn new(
        family: SettlementCircuitFamily,
        verifier_key_root: &str,
        proving_key_root: &str,
        recursion_adapter_root: &str,
    ) -> Self {
        let circuit_id = pq_recursive_settlement_id(
            "CIRCUIT",
            &[
                family.as_str(),
                verifier_key_root,
                proving_key_root,
                recursion_adapter_root,
            ],
        );
        Self {
            circuit_id,
            family,
            proof_system: family.default_proof_system().to_string(),
            verifier_key_root: verifier_key_root.to_string(),
            proving_key_root: proving_key_root.to_string(),
            recursion_adapter_root: recursion_adapter_root.to_string(),
            max_witness_bytes: 1_500_000,
            max_proof_bytes: 180_000,
            target_verify_micros: PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEFAULT_TARGET_VERIFY_MICROS,
            security_bits: 128,
            active: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "circuit_family_profile",
            "circuit_id": self.circuit_id,
            "family": self.family.as_str(),
            "proof_system": self.proof_system,
            "verifier_key_root": self.verifier_key_root,
            "proving_key_root": self.proving_key_root,
            "recursion_adapter_root": self.recursion_adapter_root,
            "max_witness_bytes": self.max_witness_bytes,
            "max_proof_bytes": self.max_proof_bytes,
            "target_verify_micros": self.target_verify_micros,
            "security_bits": self.security_bits,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        pq_recursive_settlement_payload_root("CIRCUIT-FAMILY-PROFILE", &self.public_record())
    }

    pub fn validate(&self) -> PqRecursiveSettlementCompressorResult<()> {
        ensure_non_empty("circuit.circuit_id", &self.circuit_id)?;
        ensure_non_empty("circuit.proof_system", &self.proof_system)?;
        ensure_non_empty("circuit.verifier_key_root", &self.verifier_key_root)?;
        ensure_non_empty("circuit.proving_key_root", &self.proving_key_root)?;
        ensure_non_empty(
            "circuit.recursion_adapter_root",
            &self.recursion_adapter_root,
        )?;
        ensure_positive("circuit.max_witness_bytes", self.max_witness_bytes)?;
        ensure_positive("circuit.max_proof_bytes", self.max_proof_bytes)?;
        ensure_positive("circuit.target_verify_micros", self.target_verify_micros)?;
        ensure_positive("circuit.security_bits", self.security_bits)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJob {
    pub job_id: String,
    pub aggregate_id: Option<String>,
    pub kind: ProofJobKind,
    pub lane: SettlementLane,
    pub circuit_id: String,
    pub family: SettlementCircuitFamily,
    pub submitter_commitment: String,
    pub witness_root: String,
    pub public_input_root: String,
    pub monero_anchor_root: String,
    pub da_namespace: String,
    pub requested_da_bytes: u64,
    pub max_fee_micro_units: u64,
    pub priority_score: u64,
    pub recursion_depth: u64,
    pub created_at_height: u64,
    pub deadline_height: u64,
    pub status: ProofJobStatus,
    pub low_fee_eligible: bool,
}

impl ProofJob {
    pub fn new(request: ProofJobRequest, current_height: u64, deadline_height: u64) -> Self {
        let job_id = proof_job_id(&request, current_height, deadline_height);
        Self {
            job_id,
            aggregate_id: None,
            kind: request.kind,
            lane: request.lane,
            circuit_id: request.circuit_id,
            family: request.family,
            submitter_commitment: request.submitter_commitment,
            witness_root: request.witness_root,
            public_input_root: request.public_input_root,
            monero_anchor_root: request.monero_anchor_root,
            da_namespace: request.da_namespace,
            requested_da_bytes: request.requested_da_bytes,
            max_fee_micro_units: request.max_fee_micro_units,
            priority_score: request.priority_score,
            recursion_depth: request.recursion_depth,
            created_at_height: current_height,
            deadline_height,
            status: ProofJobStatus::Queued,
            low_fee_eligible: request.low_fee_eligible,
        }
    }

    pub fn set_height(&mut self, height: u64) {
        if self.status.live() && height > self.deadline_height {
            self.status = ProofJobStatus::Expired;
        }
    }

    pub fn assign_to_aggregate(&mut self, aggregate_id: &str) {
        self.aggregate_id = Some(aggregate_id.to_string());
        self.status = ProofJobStatus::Aggregating;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_job",
            "job_id": self.job_id,
            "aggregate_id": self.aggregate_id,
            "job_kind": self.kind.as_str(),
            "lane": self.lane.as_str(),
            "circuit_id": self.circuit_id,
            "family": self.family.as_str(),
            "submitter_commitment": self.submitter_commitment,
            "witness_root": self.witness_root,
            "public_input_root": self.public_input_root,
            "monero_anchor_root": self.monero_anchor_root,
            "da_namespace": self.da_namespace,
            "requested_da_bytes": self.requested_da_bytes,
            "max_fee_micro_units": self.max_fee_micro_units,
            "priority_score": self.priority_score,
            "recursion_depth": self.recursion_depth,
            "created_at_height": self.created_at_height,
            "deadline_height": self.deadline_height,
            "status": self.status.as_str(),
            "low_fee_eligible": self.low_fee_eligible,
        })
    }

    pub fn root(&self) -> String {
        pq_recursive_settlement_payload_root("PROOF-JOB", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &PqRecursiveSettlementCompressorConfig,
    ) -> PqRecursiveSettlementCompressorResult<()> {
        ensure_non_empty("job.job_id", &self.job_id)?;
        ensure_non_empty("job.circuit_id", &self.circuit_id)?;
        ensure_non_empty("job.submitter_commitment", &self.submitter_commitment)?;
        ensure_non_empty("job.witness_root", &self.witness_root)?;
        ensure_non_empty("job.public_input_root", &self.public_input_root)?;
        ensure_non_empty("job.monero_anchor_root", &self.monero_anchor_root)?;
        ensure_non_empty("job.da_namespace", &self.da_namespace)?;
        ensure_positive("job.requested_da_bytes", self.requested_da_bytes)?;
        if self.requested_da_bytes > config.max_da_bytes_per_epoch {
            return Err(format!(
                "job {} requests more DA bytes than an epoch budget",
                self.job_id
            ));
        }
        if self.recursion_depth > config.max_recursion_depth {
            return Err(format!("job {} exceeds max recursion depth", self.job_id));
        }
        if self.deadline_height <= self.created_at_height {
            return Err(format!(
                "job {} deadline must be after creation",
                self.job_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJobRequest {
    pub kind: ProofJobKind,
    pub lane: SettlementLane,
    pub circuit_id: String,
    pub family: SettlementCircuitFamily,
    pub submitter_commitment: String,
    pub witness_root: String,
    pub public_input_root: String,
    pub monero_anchor_root: String,
    pub da_namespace: String,
    pub requested_da_bytes: u64,
    pub max_fee_micro_units: u64,
    pub priority_score: u64,
    pub recursion_depth: u64,
    pub low_fee_eligible: bool,
}

impl ProofJobRequest {
    pub fn devnet(family: SettlementCircuitFamily, lane: SettlementLane, nonce: u64) -> Self {
        let circuit_id = pq_recursive_settlement_id("DEVNET-CIRCUIT-ID", &[family.as_str()]);
        Self {
            kind: if lane.low_fee_lane() {
                ProofJobKind::LowFeeSponsored
            } else {
                ProofJobKind::BaseSettlement
            },
            lane,
            circuit_id,
            family,
            submitter_commitment: devnet_root("submitter", &nonce.to_string()),
            witness_root: devnet_root("witness", &format!("{}:{nonce}", family.as_str())),
            public_input_root: devnet_root("public-input", &nonce.to_string()),
            monero_anchor_root: devnet_root("monero-anchor", &nonce.to_string()),
            da_namespace: format!("nebula.settlement.{}", family.as_str()),
            requested_da_bytes: 12_000 + nonce.saturating_mul(1_000),
            max_fee_micro_units: if lane.low_fee_lane() { 3 } else { 50 + nonce },
            priority_score: lane.priority_weight().saturating_add(nonce),
            recursion_depth: 0,
            low_fee_eligible: lane.low_fee_lane(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofAggregate {
    pub aggregate_id: String,
    pub lane: SettlementLane,
    pub job_ids: Vec<String>,
    pub circuit_root: String,
    pub job_root: String,
    pub compressed_proof_root: String,
    pub recursive_accumulator_root: String,
    pub da_budget_id: Option<String>,
    pub certificate_id: Option<String>,
    pub total_da_bytes: u64,
    pub compressed_proof_bytes: u64,
    pub recursion_depth: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: Option<u64>,
    pub status: AggregateStatus,
}

impl ProofAggregate {
    pub fn new(lane: SettlementLane, opened_at_height: u64) -> Self {
        let aggregate_id = aggregate_id(lane, opened_at_height);
        Self {
            aggregate_id,
            lane,
            job_ids: Vec::new(),
            circuit_root: devnet_root("aggregate-circuit-root", lane.as_str()),
            job_root: pq_recursive_settlement_empty_root("AGGREGATE-JOBS"),
            compressed_proof_root: pq_recursive_settlement_empty_root("COMPRESSED-PROOF"),
            recursive_accumulator_root: pq_recursive_settlement_empty_root("RECURSIVE-ACCUMULATOR"),
            da_budget_id: None,
            certificate_id: None,
            total_da_bytes: 0,
            compressed_proof_bytes: 0,
            recursion_depth: 0,
            opened_at_height,
            sealed_at_height: None,
            status: AggregateStatus::Collecting,
        }
    }

    pub fn add_job(
        &mut self,
        job: &ProofJob,
        config: &PqRecursiveSettlementCompressorConfig,
    ) -> PqRecursiveSettlementCompressorResult<()> {
        if !self.status.accepts_jobs() {
            return Err(format!("aggregate {} is not collecting", self.aggregate_id));
        }
        if self.job_ids.len() >= config.max_jobs_per_aggregate {
            return Err(format!("aggregate {} is full", self.aggregate_id));
        }
        if self.lane != job.lane {
            return Err(format!(
                "job {} lane does not match aggregate {}",
                job.job_id, self.aggregate_id
            ));
        }
        if self.job_ids.iter().any(|id| id == &job.job_id) {
            return Ok(());
        }
        self.job_ids.push(job.job_id.clone());
        self.total_da_bytes = self.total_da_bytes.saturating_add(job.requested_da_bytes);
        self.recursion_depth = self
            .recursion_depth
            .max(job.recursion_depth.saturating_add(1));
        self.recompute_job_root();
        Ok(())
    }

    pub fn seal(
        &mut self,
        jobs: &BTreeMap<String, ProofJob>,
        height: u64,
        compressed_proof_bytes: u64,
    ) -> PqRecursiveSettlementCompressorResult<()> {
        if self.job_ids.is_empty() {
            return Err(format!("aggregate {} has no jobs", self.aggregate_id));
        }
        let leaves = self
            .job_ids
            .iter()
            .filter_map(|job_id| jobs.get(job_id))
            .map(ProofJob::public_record)
            .collect::<Vec<_>>();
        if leaves.len() != self.job_ids.len() {
            return Err(format!(
                "aggregate {} references missing jobs",
                self.aggregate_id
            ));
        }
        self.job_root = merkle_root("PQ-RECURSIVE-SETTLEMENT-AGGREGATE-JOBS", &leaves);
        self.compressed_proof_bytes = compressed_proof_bytes;
        self.compressed_proof_root = domain_hash(
            "PQ-RECURSIVE-SETTLEMENT-COMPRESSED-PROOF",
            &[
                HashPart::Str(&self.aggregate_id),
                HashPart::Str(&self.job_root),
                HashPart::Int(compressed_proof_bytes as i128),
                HashPart::Int(height as i128),
            ],
            32,
        );
        self.recursive_accumulator_root = domain_hash(
            "PQ-RECURSIVE-SETTLEMENT-ACCUMULATOR",
            &[
                HashPart::Str(&self.aggregate_id),
                HashPart::Str(&self.compressed_proof_root),
                HashPart::Int(self.recursion_depth as i128),
            ],
            32,
        );
        self.sealed_at_height = Some(height);
        self.status = AggregateStatus::Compressed;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_aggregate",
            "aggregate_id": self.aggregate_id,
            "lane": self.lane.as_str(),
            "job_ids": self.job_ids,
            "circuit_root": self.circuit_root,
            "job_root": self.job_root,
            "compressed_proof_root": self.compressed_proof_root,
            "recursive_accumulator_root": self.recursive_accumulator_root,
            "da_budget_id": self.da_budget_id,
            "certificate_id": self.certificate_id,
            "total_da_bytes": self.total_da_bytes,
            "compressed_proof_bytes": self.compressed_proof_bytes,
            "recursion_depth": self.recursion_depth,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        pq_recursive_settlement_payload_root("PROOF-AGGREGATE", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &PqRecursiveSettlementCompressorConfig,
        jobs: &BTreeMap<String, ProofJob>,
    ) -> PqRecursiveSettlementCompressorResult<()> {
        ensure_non_empty("aggregate.aggregate_id", &self.aggregate_id)?;
        if self.job_ids.len() > config.max_jobs_per_aggregate {
            return Err(format!("aggregate {} has too many jobs", self.aggregate_id));
        }
        if self.recursion_depth > config.max_recursion_depth {
            return Err(format!(
                "aggregate {} exceeds recursion depth",
                self.aggregate_id
            ));
        }
        if self.compressed_proof_bytes > config.max_compressed_proof_bytes {
            return Err(format!(
                "aggregate {} compressed proof exceeds byte limit",
                self.aggregate_id
            ));
        }
        let mut seen = BTreeSet::new();
        for job_id in &self.job_ids {
            if !seen.insert(job_id.clone()) {
                return Err(format!("aggregate {} has duplicate job", self.aggregate_id));
            }
            let job = jobs
                .get(job_id)
                .ok_or_else(|| format!("aggregate {} references missing job", self.aggregate_id))?;
            if job.lane != self.lane {
                return Err(format!(
                    "aggregate {} contains wrong-lane job",
                    self.aggregate_id
                ));
            }
        }
        Ok(())
    }

    fn recompute_job_root(&mut self) {
        let leaves = self
            .job_ids
            .iter()
            .map(|job_id| json!(job_id))
            .collect::<Vec<_>>();
        self.job_root = merkle_root("PQ-RECURSIVE-SETTLEMENT-AGGREGATE-JOB-IDS", &leaves);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaByteBudget {
    pub budget_id: String,
    pub aggregate_id: String,
    pub namespace: String,
    pub epoch: u64,
    pub requested_bytes: u64,
    pub sponsored_bytes: u64,
    pub paid_bytes: u64,
    pub max_price_micro_units_per_byte: u64,
    pub commitment_root: String,
    pub receipt_root: String,
    pub opened_at_height: u64,
    pub settled: bool,
}

impl DaByteBudget {
    pub fn new(
        aggregate_id: &str,
        namespace: &str,
        epoch: u64,
        requested_bytes: u64,
        sponsored_bytes: u64,
        max_price_micro_units_per_byte: u64,
        opened_at_height: u64,
    ) -> Self {
        let paid_bytes = requested_bytes.saturating_sub(sponsored_bytes);
        let budget_id = da_budget_id(aggregate_id, namespace, epoch, requested_bytes);
        let commitment_root = domain_hash(
            "PQ-RECURSIVE-SETTLEMENT-DA-BUDGET-COMMITMENT",
            &[
                HashPart::Str(&budget_id),
                HashPart::Str(aggregate_id),
                HashPart::Str(namespace),
                HashPart::Int(epoch as i128),
                HashPart::Int(requested_bytes as i128),
                HashPart::Int(sponsored_bytes as i128),
            ],
            32,
        );
        Self {
            budget_id,
            aggregate_id: aggregate_id.to_string(),
            namespace: namespace.to_string(),
            epoch,
            requested_bytes,
            sponsored_bytes,
            paid_bytes,
            max_price_micro_units_per_byte,
            commitment_root,
            receipt_root: pq_recursive_settlement_empty_root("DA-BUDGET-RECEIPTS"),
            opened_at_height,
            settled: false,
        }
    }

    pub fn mark_settled(&mut self, receipt_root: &str) {
        self.receipt_root = receipt_root.to_string();
        self.settled = true;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "da_byte_budget",
            "budget_id": self.budget_id,
            "aggregate_id": self.aggregate_id,
            "namespace": self.namespace,
            "epoch": self.epoch,
            "requested_bytes": self.requested_bytes,
            "sponsored_bytes": self.sponsored_bytes,
            "paid_bytes": self.paid_bytes,
            "max_price_micro_units_per_byte": self.max_price_micro_units_per_byte,
            "commitment_root": self.commitment_root,
            "receipt_root": self.receipt_root,
            "opened_at_height": self.opened_at_height,
            "settled": self.settled,
        })
    }

    pub fn root(&self) -> String {
        pq_recursive_settlement_payload_root("DA-BYTE-BUDGET", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &PqRecursiveSettlementCompressorConfig,
    ) -> PqRecursiveSettlementCompressorResult<()> {
        ensure_non_empty("da_budget.budget_id", &self.budget_id)?;
        ensure_non_empty("da_budget.aggregate_id", &self.aggregate_id)?;
        ensure_non_empty("da_budget.namespace", &self.namespace)?;
        ensure_positive("da_budget.requested_bytes", self.requested_bytes)?;
        if self.requested_bytes > config.max_da_bytes_per_epoch {
            return Err(format!(
                "DA budget {} exceeds epoch byte cap",
                self.budget_id
            ));
        }
        if self.sponsored_bytes > self.requested_bytes {
            return Err(format!(
                "DA budget {} sponsors more bytes than requested",
                self.budget_id
            ));
        }
        if self.paid_bytes != self.requested_bytes.saturating_sub(self.sponsored_bytes) {
            return Err(format!("DA budget {} paid bytes mismatch", self.budget_id));
        }
        ensure_non_empty("da_budget.commitment_root", &self.commitment_root)?;
        ensure_non_empty("da_budget.receipt_root", &self.receipt_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementCertificate {
    pub certificate_id: String,
    pub aggregate_id: String,
    pub compressed_proof_root: String,
    pub recursive_accumulator_root: String,
    pub da_budget_root: String,
    pub monero_anchor_root: String,
    pub settlement_tx_commitment: String,
    pub attestation_root: String,
    pub issued_at_height: u64,
    pub finality_height: u64,
    pub status: CertificateStatus,
}

impl SettlementCertificate {
    pub fn new(
        aggregate: &ProofAggregate,
        da_budget_root: &str,
        monero_anchor_root: &str,
        settlement_tx_commitment: &str,
        issued_at_height: u64,
        finality_height: u64,
    ) -> Self {
        let certificate_id = settlement_certificate_id(
            &aggregate.aggregate_id,
            &aggregate.compressed_proof_root,
            settlement_tx_commitment,
            issued_at_height,
        );
        Self {
            certificate_id,
            aggregate_id: aggregate.aggregate_id.clone(),
            compressed_proof_root: aggregate.compressed_proof_root.clone(),
            recursive_accumulator_root: aggregate.recursive_accumulator_root.clone(),
            da_budget_root: da_budget_root.to_string(),
            monero_anchor_root: monero_anchor_root.to_string(),
            settlement_tx_commitment: settlement_tx_commitment.to_string(),
            attestation_root: pq_recursive_settlement_empty_root("CERTIFICATE-ATTESTATIONS"),
            issued_at_height,
            finality_height,
            status: CertificateStatus::Pending,
        }
    }

    pub fn attach_attestations(&mut self, attestation_root: &str) {
        self.attestation_root = attestation_root.to_string();
        self.status = CertificateStatus::Attested;
    }

    pub fn finalize(&mut self) {
        self.status = CertificateStatus::Finalized;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_certificate",
            "certificate_id": self.certificate_id,
            "aggregate_id": self.aggregate_id,
            "compressed_proof_root": self.compressed_proof_root,
            "recursive_accumulator_root": self.recursive_accumulator_root,
            "da_budget_root": self.da_budget_root,
            "monero_anchor_root": self.monero_anchor_root,
            "settlement_tx_commitment": self.settlement_tx_commitment,
            "attestation_root": self.attestation_root,
            "issued_at_height": self.issued_at_height,
            "finality_height": self.finality_height,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        pq_recursive_settlement_payload_root("SETTLEMENT-CERTIFICATE", &self.public_record())
    }

    pub fn validate(&self) -> PqRecursiveSettlementCompressorResult<()> {
        ensure_non_empty("certificate.certificate_id", &self.certificate_id)?;
        ensure_non_empty("certificate.aggregate_id", &self.aggregate_id)?;
        ensure_non_empty(
            "certificate.compressed_proof_root",
            &self.compressed_proof_root,
        )?;
        ensure_non_empty(
            "certificate.recursive_accumulator_root",
            &self.recursive_accumulator_root,
        )?;
        ensure_non_empty("certificate.da_budget_root", &self.da_budget_root)?;
        ensure_non_empty("certificate.monero_anchor_root", &self.monero_anchor_root)?;
        ensure_non_empty(
            "certificate.settlement_tx_commitment",
            &self.settlement_tx_commitment,
        )?;
        ensure_non_empty("certificate.attestation_root", &self.attestation_root)?;
        if self.finality_height <= self.issued_at_height {
            return Err(format!(
                "certificate {} finality height must be after issuance",
                self.certificate_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignatureAttestation {
    pub attestation_id: String,
    pub subject_id: String,
    pub role: PqAttestationRole,
    pub signer_id: String,
    pub pq_public_key_commitment: String,
    pub signed_payload_root: String,
    pub signature_root: String,
    pub recovery_signature_root: String,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
}

impl PqSignatureAttestation {
    pub fn new(
        subject_id: &str,
        role: PqAttestationRole,
        signer_id: &str,
        pq_public_key_commitment: &str,
        signed_payload_root: &str,
        signature_root: &str,
        signed_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let attestation_id = pq_attestation_id(
            subject_id,
            role,
            signer_id,
            signed_payload_root,
            signed_at_height,
        );
        Self {
            attestation_id,
            subject_id: subject_id.to_string(),
            role,
            signer_id: signer_id.to_string(),
            pq_public_key_commitment: pq_public_key_commitment.to_string(),
            signed_payload_root: signed_payload_root.to_string(),
            signature_root: signature_root.to_string(),
            recovery_signature_root: devnet_root("pq-recovery-signature", signature_root),
            signed_at_height,
            expires_at_height: signed_at_height.saturating_add(ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_signature_attestation",
            "attestation_id": self.attestation_id,
            "subject_id": self.subject_id,
            "role": self.role.as_str(),
            "signer_id": self.signer_id,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "signed_payload_root": self.signed_payload_root,
            "signature_root": self.signature_root,
            "recovery_signature_root": self.recovery_signature_root,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        pq_recursive_settlement_payload_root("PQ-SIGNATURE-ATTESTATION", &self.public_record())
    }

    pub fn validate(&self) -> PqRecursiveSettlementCompressorResult<()> {
        ensure_non_empty("attestation.attestation_id", &self.attestation_id)?;
        ensure_non_empty("attestation.subject_id", &self.subject_id)?;
        ensure_non_empty("attestation.signer_id", &self.signer_id)?;
        ensure_non_empty(
            "attestation.pq_public_key_commitment",
            &self.pq_public_key_commitment,
        )?;
        ensure_non_empty("attestation.signed_payload_root", &self.signed_payload_root)?;
        ensure_non_empty("attestation.signature_root", &self.signature_root)?;
        ensure_non_empty(
            "attestation.recovery_signature_root",
            &self.recovery_signature_root,
        )?;
        if self.expires_at_height <= self.signed_at_height {
            return Err(format!(
                "attestation {} expires before it can be used",
                self.attestation_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeProofSponsorship {
    pub sponsorship_id: String,
    pub sponsor_id: String,
    pub job_id: Option<String>,
    pub aggregate_id: Option<String>,
    pub beneficiary_commitment: String,
    pub reserved_micro_units: u64,
    pub applied_micro_units: u64,
    pub da_bytes_sponsored: u64,
    pub rebate_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorshipStatus,
}

impl LowFeeProofSponsorship {
    pub fn reserve_for_job(
        sponsor_id: &str,
        job: &ProofJob,
        reserved_micro_units: u64,
        da_bytes_sponsored: u64,
        rebate_bps: u64,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let sponsorship_id = sponsorship_id(sponsor_id, &job.job_id, opened_at_height);
        Self {
            sponsorship_id,
            sponsor_id: sponsor_id.to_string(),
            job_id: Some(job.job_id.clone()),
            aggregate_id: job.aggregate_id.clone(),
            beneficiary_commitment: job.submitter_commitment.clone(),
            reserved_micro_units,
            applied_micro_units: 0,
            da_bytes_sponsored,
            rebate_bps,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            status: SponsorshipStatus::Reserved,
        }
    }

    pub fn apply(&mut self, aggregate_id: &str, amount_micro_units: u64) {
        self.aggregate_id = Some(aggregate_id.to_string());
        self.applied_micro_units = self
            .applied_micro_units
            .saturating_add(amount_micro_units.min(self.remaining_micro_units()));
        self.status = if self.applied_micro_units >= self.reserved_micro_units {
            SponsorshipStatus::Exhausted
        } else {
            SponsorshipStatus::Applied
        };
    }

    pub fn remaining_micro_units(&self) -> u64 {
        self.reserved_micro_units
            .saturating_sub(self.applied_micro_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_proof_sponsorship",
            "sponsorship_id": self.sponsorship_id,
            "sponsor_id": self.sponsor_id,
            "job_id": self.job_id,
            "aggregate_id": self.aggregate_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "reserved_micro_units": self.reserved_micro_units,
            "applied_micro_units": self.applied_micro_units,
            "da_bytes_sponsored": self.da_bytes_sponsored,
            "rebate_bps": self.rebate_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "remaining_micro_units": self.remaining_micro_units(),
        })
    }

    pub fn root(&self) -> String {
        pq_recursive_settlement_payload_root("LOW-FEE-PROOF-SPONSORSHIP", &self.public_record())
    }

    pub fn validate(&self) -> PqRecursiveSettlementCompressorResult<()> {
        ensure_non_empty("sponsorship.sponsorship_id", &self.sponsorship_id)?;
        ensure_non_empty("sponsorship.sponsor_id", &self.sponsor_id)?;
        ensure_non_empty(
            "sponsorship.beneficiary_commitment",
            &self.beneficiary_commitment,
        )?;
        ensure_bps("sponsorship.rebate_bps", self.rebate_bps)?;
        if self.applied_micro_units > self.reserved_micro_units {
            return Err(format!(
                "sponsorship {} applied more than reserved",
                self.sponsorship_id
            ));
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!(
                "sponsorship {} expires before opening",
                self.sponsorship_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRecursiveSettlementCompressorRoots {
    pub config_root: String,
    pub circuit_root: String,
    pub job_root: String,
    pub aggregate_root: String,
    pub da_budget_root: String,
    pub certificate_root: String,
    pub attestation_root: String,
    pub sponsorship_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl PqRecursiveSettlementCompressorRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_recursive_settlement_compressor_roots",
            "config_root": self.config_root,
            "circuit_root": self.circuit_root,
            "job_root": self.job_root,
            "aggregate_root": self.aggregate_root,
            "da_budget_root": self.da_budget_root,
            "certificate_root": self.certificate_root,
            "attestation_root": self.attestation_root,
            "sponsorship_root": self.sponsorship_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRecursiveSettlementCompressorCounters {
    pub circuit_count: u64,
    pub job_count: u64,
    pub live_job_count: u64,
    pub aggregate_count: u64,
    pub da_budget_count: u64,
    pub certificate_count: u64,
    pub attestation_count: u64,
    pub sponsorship_count: u64,
    pub total_requested_da_bytes: u64,
    pub total_sponsored_da_bytes: u64,
    pub total_reserved_sponsor_micro_units: u64,
    pub total_applied_sponsor_micro_units: u64,
    pub public_record_count: u64,
}

impl PqRecursiveSettlementCompressorCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_recursive_settlement_compressor_counters",
            "circuit_count": self.circuit_count,
            "job_count": self.job_count,
            "live_job_count": self.live_job_count,
            "aggregate_count": self.aggregate_count,
            "da_budget_count": self.da_budget_count,
            "certificate_count": self.certificate_count,
            "attestation_count": self.attestation_count,
            "sponsorship_count": self.sponsorship_count,
            "total_requested_da_bytes": self.total_requested_da_bytes,
            "total_sponsored_da_bytes": self.total_sponsored_da_bytes,
            "total_reserved_sponsor_micro_units": self.total_reserved_sponsor_micro_units,
            "total_applied_sponsor_micro_units": self.total_applied_sponsor_micro_units,
            "public_record_count": self.public_record_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRecursiveSettlementPublicRecord {
    pub record_id: String,
    pub subject_id: String,
    pub record_kind: String,
    pub payload_root: String,
    pub published_at_height: u64,
}

impl PqRecursiveSettlementPublicRecord {
    pub fn new(
        subject_id: &str,
        record_kind: &str,
        payload_root: &str,
        published_at_height: u64,
    ) -> Self {
        let record_id =
            public_record_id(subject_id, record_kind, payload_root, published_at_height);
        Self {
            record_id,
            subject_id: subject_id.to_string(),
            record_kind: record_kind.to_string(),
            payload_root: payload_root.to_string(),
            published_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_recursive_settlement_public_record",
            "record_id": self.record_id,
            "subject_id": self.subject_id,
            "record_kind": self.record_kind,
            "payload_root": self.payload_root,
            "published_at_height": self.published_at_height,
        })
    }

    pub fn root(&self) -> String {
        pq_recursive_settlement_payload_root("PUBLIC-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> PqRecursiveSettlementCompressorResult<()> {
        ensure_non_empty("public_record.record_id", &self.record_id)?;
        ensure_non_empty("public_record.subject_id", &self.subject_id)?;
        ensure_non_empty("public_record.record_kind", &self.record_kind)?;
        ensure_non_empty("public_record.payload_root", &self.payload_root)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRecursiveSettlementCompressorState {
    pub config: PqRecursiveSettlementCompressorConfig,
    pub height: u64,
    pub circuits: BTreeMap<String, CircuitFamilyProfile>,
    pub jobs: BTreeMap<String, ProofJob>,
    pub aggregates: BTreeMap<String, ProofAggregate>,
    pub da_budgets: BTreeMap<String, DaByteBudget>,
    pub certificates: BTreeMap<String, SettlementCertificate>,
    pub attestations: BTreeMap<String, PqSignatureAttestation>,
    pub sponsorships: BTreeMap<String, LowFeeProofSponsorship>,
    pub public_records: BTreeMap<String, PqRecursiveSettlementPublicRecord>,
}

impl Default for PqRecursiveSettlementCompressorState {
    fn default() -> Self {
        Self {
            config: PqRecursiveSettlementCompressorConfig::default(),
            height: 0,
            circuits: BTreeMap::new(),
            jobs: BTreeMap::new(),
            aggregates: BTreeMap::new(),
            da_budgets: BTreeMap::new(),
            certificates: BTreeMap::new(),
            attestations: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }
}

impl PqRecursiveSettlementCompressorState {
    pub fn new(config: PqRecursiveSettlementCompressorConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    pub fn devnet() -> PqRecursiveSettlementCompressorResult<Self> {
        let mut state = Self::new(PqRecursiveSettlementCompressorConfig::devnet());
        state.set_height(PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEVNET_HEIGHT);

        let monero_circuit = CircuitFamilyProfile::new(
            SettlementCircuitFamily::MoneroBridge,
            &devnet_root("vk", "monero-bridge"),
            &devnet_root("pk", "monero-bridge"),
            &devnet_root("adapter", "monero-bridge"),
        );
        let private_circuit = CircuitFamilyProfile::new(
            SettlementCircuitFamily::PrivateTransfer,
            &devnet_root("vk", "private-transfer"),
            &devnet_root("pk", "private-transfer"),
            &devnet_root("adapter", "private-transfer"),
        );
        let recursive_circuit = CircuitFamilyProfile::new(
            SettlementCircuitFamily::RecursiveSettlement,
            &devnet_root("vk", "recursive-settlement"),
            &devnet_root("pk", "recursive-settlement"),
            &devnet_root("adapter", "recursive-settlement"),
        );

        state.register_circuit(monero_circuit)?;
        state.register_circuit(private_circuit)?;
        state.register_circuit(recursive_circuit)?;

        let job_a = state.submit_job(ProofJobRequest::devnet(
            SettlementCircuitFamily::MoneroBridge,
            SettlementLane::MoneroExit,
            1,
        ))?;
        let job_b = state.submit_job(ProofJobRequest::devnet(
            SettlementCircuitFamily::PrivateTransfer,
            SettlementLane::MoneroExit,
            2,
        ))?;
        let job_c = state.submit_job(ProofJobRequest::devnet(
            SettlementCircuitFamily::FeeAccounting,
            SettlementLane::SponsoredLowFee,
            3,
        ))?;

        let aggregate_id = state.open_aggregate(SettlementLane::MoneroExit)?;
        state.add_job_to_aggregate(&aggregate_id, &job_a)?;
        state.add_job_to_aggregate(&aggregate_id, &job_b)?;
        state.seal_aggregate(&aggregate_id, 36_000)?;
        let budget_id =
            state.reserve_da_budget(&aggregate_id, "nebula.settlement.monero", 42, 2)?;
        let certificate_id = state.issue_settlement_certificate(
            &aggregate_id,
            &budget_id,
            &devnet_root("monero-anchor", "certificate"),
            &devnet_root("settlement-tx", "monero-exit"),
        )?;
        state.attest_subject(
            &certificate_id,
            PqAttestationRole::SettlementCommittee,
            PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEVNET_COMMITTEE_ID,
        )?;
        state.finalize_certificate(&certificate_id)?;

        let low_fee_job = state
            .jobs
            .get(&job_c)
            .cloned()
            .ok_or_else(|| "devnet low fee job missing after insertion".to_string())?;
        let sponsorship = LowFeeProofSponsorship::reserve_for_job(
            PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_DEVNET_SPONSOR_ID,
            &low_fee_job,
            state.config.low_fee_floor_micro_units,
            4_000,
            state.config.sponsor_rebate_bps,
            state.height,
            state.config.challenge_window_blocks,
        );
        state.reserve_sponsorship(sponsorship)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for job in self.jobs.values_mut() {
            job.set_height(height);
        }
    }

    pub fn register_circuit(
        &mut self,
        circuit: CircuitFamilyProfile,
    ) -> PqRecursiveSettlementCompressorResult<String> {
        circuit.validate()?;
        let circuit_id = circuit.circuit_id.clone();
        self.circuits.insert(circuit_id.clone(), circuit);
        Ok(circuit_id)
    }

    pub fn submit_job(
        &mut self,
        request: ProofJobRequest,
    ) -> PqRecursiveSettlementCompressorResult<String> {
        ensure_non_empty("job_request.circuit_id", &request.circuit_id)?;
        ensure_non_empty(
            "job_request.submitter_commitment",
            &request.submitter_commitment,
        )?;
        let deadline = self
            .height
            .saturating_add(self.config.aggregate_window_blocks)
            .saturating_add(self.config.challenge_window_blocks);
        let job = ProofJob::new(request, self.height, deadline);
        job.validate(&self.config)?;
        let job_id = job.job_id.clone();
        self.jobs.insert(job_id.clone(), job);
        Ok(job_id)
    }

    pub fn open_aggregate(
        &mut self,
        lane: SettlementLane,
    ) -> PqRecursiveSettlementCompressorResult<String> {
        let aggregate = ProofAggregate::new(lane, self.height);
        let aggregate_id = aggregate.aggregate_id.clone();
        self.aggregates.insert(aggregate_id.clone(), aggregate);
        Ok(aggregate_id)
    }

    pub fn add_job_to_aggregate(
        &mut self,
        aggregate_id: &str,
        job_id: &str,
    ) -> PqRecursiveSettlementCompressorResult<()> {
        let job = self
            .jobs
            .get(job_id)
            .cloned()
            .ok_or_else(|| format!("missing job {job_id}"))?;
        let aggregate = self
            .aggregates
            .get_mut(aggregate_id)
            .ok_or_else(|| format!("missing aggregate {aggregate_id}"))?;
        aggregate.add_job(&job, &self.config)?;
        let stored_job = self
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| format!("missing job {job_id}"))?;
        stored_job.assign_to_aggregate(aggregate_id);
        Ok(())
    }

    pub fn seal_aggregate(
        &mut self,
        aggregate_id: &str,
        compressed_proof_bytes: u64,
    ) -> PqRecursiveSettlementCompressorResult<String> {
        if compressed_proof_bytes > self.config.max_compressed_proof_bytes {
            return Err(format!(
                "compressed proof for aggregate {aggregate_id} is too large"
            ));
        }
        let aggregate = self
            .aggregates
            .get_mut(aggregate_id)
            .ok_or_else(|| format!("missing aggregate {aggregate_id}"))?;
        aggregate.seal(&self.jobs, self.height, compressed_proof_bytes)?;
        for job_id in &aggregate.job_ids {
            if let Some(job) = self.jobs.get_mut(job_id) {
                job.status = ProofJobStatus::Compressed;
            }
        }
        Ok(aggregate.compressed_proof_root.clone())
    }

    pub fn reserve_da_budget(
        &mut self,
        aggregate_id: &str,
        namespace: &str,
        epoch: u64,
        max_price_micro_units_per_byte: u64,
    ) -> PqRecursiveSettlementCompressorResult<String> {
        let aggregate = self
            .aggregates
            .get_mut(aggregate_id)
            .ok_or_else(|| format!("missing aggregate {aggregate_id}"))?;
        let sponsored_bytes = bps_portion(aggregate.total_da_bytes, self.config.da_sponsor_bps);
        let budget = DaByteBudget::new(
            aggregate_id,
            namespace,
            epoch,
            aggregate.total_da_bytes,
            sponsored_bytes,
            max_price_micro_units_per_byte,
            self.height,
        );
        budget.validate(&self.config)?;
        let budget_id = budget.budget_id.clone();
        aggregate.da_budget_id = Some(budget_id.clone());
        self.da_budgets.insert(budget_id.clone(), budget);
        Ok(budget_id)
    }

    pub fn issue_settlement_certificate(
        &mut self,
        aggregate_id: &str,
        budget_id: &str,
        monero_anchor_root: &str,
        settlement_tx_commitment: &str,
    ) -> PqRecursiveSettlementCompressorResult<String> {
        let aggregate = self
            .aggregates
            .get(aggregate_id)
            .cloned()
            .ok_or_else(|| format!("missing aggregate {aggregate_id}"))?;
        let da_budget = self
            .da_budgets
            .get(budget_id)
            .ok_or_else(|| format!("missing DA budget {budget_id}"))?;
        let finality_height = self
            .height
            .saturating_add(self.config.finality_confirmations);
        let certificate = SettlementCertificate::new(
            &aggregate,
            &da_budget.root(),
            monero_anchor_root,
            settlement_tx_commitment,
            self.height,
            finality_height,
        );
        certificate.validate()?;
        let certificate_id = certificate.certificate_id.clone();
        self.certificates
            .insert(certificate_id.clone(), certificate.clone());
        if let Some(stored_aggregate) = self.aggregates.get_mut(aggregate_id) {
            stored_aggregate.certificate_id = Some(certificate_id.clone());
            stored_aggregate.status = AggregateStatus::Certified;
        }
        self.publish_public_record(
            &certificate_id,
            "settlement_certificate",
            &certificate.root(),
        )?;
        Ok(certificate_id)
    }

    pub fn attest_subject(
        &mut self,
        subject_id: &str,
        role: PqAttestationRole,
        signer_id: &str,
    ) -> PqRecursiveSettlementCompressorResult<String> {
        let subject_root = self
            .subject_root(subject_id)
            .ok_or_else(|| format!("cannot attest unknown subject {subject_id}"))?;
        let signature_root = domain_hash(
            "PQ-RECURSIVE-SETTLEMENT-DEVNET-SIGNATURE",
            &[
                HashPart::Str(subject_id),
                HashPart::Str(role.as_str()),
                HashPart::Str(signer_id),
                HashPart::Str(&subject_root),
                HashPart::Int(self.height as i128),
            ],
            32,
        );
        let attestation = PqSignatureAttestation::new(
            subject_id,
            role,
            signer_id,
            &devnet_root("pq-public-key", signer_id),
            &subject_root,
            &signature_root,
            self.height,
            self.config.challenge_window_blocks,
        );
        attestation.validate()?;
        let attestation_id = attestation.attestation_id.clone();
        self.attestations
            .insert(attestation_id.clone(), attestation.clone());
        self.attach_attestation_to_subject(subject_id)?;
        self.publish_public_record(
            &attestation_id,
            "pq_signature_attestation",
            &attestation.root(),
        )?;
        Ok(attestation_id)
    }

    pub fn reserve_sponsorship(
        &mut self,
        sponsorship: LowFeeProofSponsorship,
    ) -> PqRecursiveSettlementCompressorResult<String> {
        sponsorship.validate()?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        self.sponsorships
            .insert(sponsorship_id.clone(), sponsorship.clone());
        self.publish_public_record(&sponsorship_id, "low_fee_sponsorship", &sponsorship.root())?;
        Ok(sponsorship_id)
    }

    pub fn finalize_certificate(
        &mut self,
        certificate_id: &str,
    ) -> PqRecursiveSettlementCompressorResult<()> {
        let certificate = self
            .certificates
            .get_mut(certificate_id)
            .ok_or_else(|| format!("missing certificate {certificate_id}"))?;
        certificate.finalize();
        if let Some(aggregate) = self.aggregates.get_mut(&certificate.aggregate_id) {
            aggregate.status = AggregateStatus::SettlementReady;
        }
        for job in self.jobs.values_mut() {
            if job.aggregate_id.as_deref()
                == self
                    .certificates
                    .get(certificate_id)
                    .map(|certificate| certificate.aggregate_id.as_str())
            {
                job.status = ProofJobStatus::SettlementReady;
            }
        }
        Ok(())
    }

    pub fn publish_public_record(
        &mut self,
        subject_id: &str,
        record_kind: &str,
        payload_root: &str,
    ) -> PqRecursiveSettlementCompressorResult<String> {
        let record = PqRecursiveSettlementPublicRecord::new(
            subject_id,
            record_kind,
            payload_root,
            self.height,
        );
        record.validate()?;
        let record_id = record.record_id.clone();
        self.public_records.insert(record_id.clone(), record);
        Ok(record_id)
    }

    pub fn roots(&self) -> PqRecursiveSettlementCompressorRoots {
        let config_root =
            pq_recursive_settlement_payload_root("CONFIG", &self.config.public_record());
        let circuit_root = map_root(
            "PQ-RECURSIVE-SETTLEMENT-CIRCUITS",
            self.circuits
                .values()
                .map(CircuitFamilyProfile::public_record)
                .collect::<Vec<_>>(),
        );
        let job_root = map_root(
            "PQ-RECURSIVE-SETTLEMENT-JOBS",
            self.jobs
                .values()
                .map(ProofJob::public_record)
                .collect::<Vec<_>>(),
        );
        let aggregate_root = map_root(
            "PQ-RECURSIVE-SETTLEMENT-AGGREGATES",
            self.aggregates
                .values()
                .map(ProofAggregate::public_record)
                .collect::<Vec<_>>(),
        );
        let da_budget_root = map_root(
            "PQ-RECURSIVE-SETTLEMENT-DA-BUDGETS",
            self.da_budgets
                .values()
                .map(DaByteBudget::public_record)
                .collect::<Vec<_>>(),
        );
        let certificate_root = map_root(
            "PQ-RECURSIVE-SETTLEMENT-CERTIFICATES",
            self.certificates
                .values()
                .map(SettlementCertificate::public_record)
                .collect::<Vec<_>>(),
        );
        let attestation_root = map_root(
            "PQ-RECURSIVE-SETTLEMENT-ATTESTATIONS",
            self.attestations
                .values()
                .map(PqSignatureAttestation::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsorship_root = map_root(
            "PQ-RECURSIVE-SETTLEMENT-SPONSORSHIPS",
            self.sponsorships
                .values()
                .map(LowFeeProofSponsorship::public_record)
                .collect::<Vec<_>>(),
        );
        let public_record_root = map_root(
            "PQ-RECURSIVE-SETTLEMENT-PUBLIC-RECORDS",
            self.public_records
                .values()
                .map(PqRecursiveSettlementPublicRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let counters = self.counters();
        let state_record = json!({
            "kind": "pq_recursive_settlement_compressor_state_root_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PROTOCOL_VERSION,
            "schema_version": PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_SCHEMA_VERSION,
            "height": self.height,
            "config_root": config_root,
            "circuit_root": circuit_root,
            "job_root": job_root,
            "aggregate_root": aggregate_root,
            "da_budget_root": da_budget_root,
            "certificate_root": certificate_root,
            "attestation_root": attestation_root,
            "sponsorship_root": sponsorship_root,
            "public_record_root": public_record_root,
            "counters": counters.public_record(),
        });
        let state_root = pq_recursive_settlement_state_root_from_record(&state_record);
        PqRecursiveSettlementCompressorRoots {
            config_root,
            circuit_root,
            job_root,
            aggregate_root,
            da_budget_root,
            certificate_root,
            attestation_root,
            sponsorship_root,
            public_record_root,
            state_root,
        }
    }

    pub fn counters(&self) -> PqRecursiveSettlementCompressorCounters {
        let live_job_count = self.jobs.values().filter(|job| job.status.live()).count() as u64;
        let total_requested_da_bytes = self
            .da_budgets
            .values()
            .map(|budget| budget.requested_bytes)
            .sum();
        let total_sponsored_da_bytes = self
            .da_budgets
            .values()
            .map(|budget| budget.sponsored_bytes)
            .sum::<u64>()
            .saturating_add(
                self.sponsorships
                    .values()
                    .map(|sponsorship| sponsorship.da_bytes_sponsored)
                    .sum::<u64>(),
            );
        let total_reserved_sponsor_micro_units = self
            .sponsorships
            .values()
            .map(|sponsorship| sponsorship.reserved_micro_units)
            .sum();
        let total_applied_sponsor_micro_units = self
            .sponsorships
            .values()
            .map(|sponsorship| sponsorship.applied_micro_units)
            .sum();
        PqRecursiveSettlementCompressorCounters {
            circuit_count: self.circuits.len() as u64,
            job_count: self.jobs.len() as u64,
            live_job_count,
            aggregate_count: self.aggregates.len() as u64,
            da_budget_count: self.da_budgets.len() as u64,
            certificate_count: self.certificates.len() as u64,
            attestation_count: self.attestations.len() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            total_requested_da_bytes,
            total_sponsored_da_bytes,
            total_reserved_sponsor_micro_units,
            total_applied_sponsor_micro_units,
            public_record_count: self.public_records.len() as u64,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "pq_recursive_settlement_compressor_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PROTOCOL_VERSION,
            "schema_version": PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "circuits": self.circuits.values().map(CircuitFamilyProfile::public_record).collect::<Vec<_>>(),
            "jobs": self.jobs.values().map(ProofJob::public_record).collect::<Vec<_>>(),
            "aggregates": self.aggregates.values().map(ProofAggregate::public_record).collect::<Vec<_>>(),
            "da_budgets": self.da_budgets.values().map(DaByteBudget::public_record).collect::<Vec<_>>(),
            "certificates": self.certificates.values().map(SettlementCertificate::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(PqSignatureAttestation::public_record).collect::<Vec<_>>(),
            "sponsorships": self.sponsorships.values().map(LowFeeProofSponsorship::public_record).collect::<Vec<_>>(),
            "public_records": self.public_records.values().map(PqRecursiveSettlementPublicRecord::public_record).collect::<Vec<_>>(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn validate(&self) -> PqRecursiveSettlementCompressorResult<String> {
        self.config.validate()?;
        ensure_len("circuits", self.circuits.len())?;
        ensure_len("jobs", self.jobs.len())?;
        ensure_len("aggregates", self.aggregates.len())?;
        ensure_len("da_budgets", self.da_budgets.len())?;
        ensure_len("certificates", self.certificates.len())?;
        ensure_len("attestations", self.attestations.len())?;
        ensure_len("sponsorships", self.sponsorships.len())?;
        ensure_len("public_records", self.public_records.len())?;

        for circuit in self.circuits.values() {
            circuit.validate()?;
        }
        for job in self.jobs.values() {
            job.validate(&self.config)?;
        }
        for aggregate in self.aggregates.values() {
            aggregate.validate(&self.config, &self.jobs)?;
        }
        for budget in self.da_budgets.values() {
            budget.validate(&self.config)?;
            if !self.aggregates.contains_key(&budget.aggregate_id) {
                return Err(format!(
                    "DA budget {} references missing aggregate",
                    budget.budget_id
                ));
            }
        }
        for certificate in self.certificates.values() {
            certificate.validate()?;
            if !self.aggregates.contains_key(&certificate.aggregate_id) {
                return Err(format!(
                    "certificate {} references missing aggregate",
                    certificate.certificate_id
                ));
            }
        }
        for attestation in self.attestations.values() {
            attestation.validate()?;
            if self.subject_root(&attestation.subject_id).is_none() {
                return Err(format!(
                    "attestation {} references missing subject",
                    attestation.attestation_id
                ));
            }
        }
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate()?;
            if let Some(job_id) = &sponsorship.job_id {
                if !self.jobs.contains_key(job_id) {
                    return Err(format!(
                        "sponsorship {} references missing job",
                        sponsorship.sponsorship_id
                    ));
                }
            }
        }
        for public_record in self.public_records.values() {
            public_record.validate()?;
        }
        Ok(self.state_root())
    }

    fn subject_root(&self, subject_id: &str) -> Option<String> {
        self.jobs
            .get(subject_id)
            .map(ProofJob::root)
            .or_else(|| self.aggregates.get(subject_id).map(ProofAggregate::root))
            .or_else(|| self.da_budgets.get(subject_id).map(DaByteBudget::root))
            .or_else(|| {
                self.certificates
                    .get(subject_id)
                    .map(SettlementCertificate::root)
            })
            .or_else(|| {
                self.sponsorships
                    .get(subject_id)
                    .map(LowFeeProofSponsorship::root)
            })
    }

    fn attach_attestation_to_subject(
        &mut self,
        subject_id: &str,
    ) -> PqRecursiveSettlementCompressorResult<()> {
        let leaves = self
            .attestations
            .values()
            .filter(|attestation| attestation.subject_id == subject_id)
            .map(PqSignatureAttestation::public_record)
            .collect::<Vec<_>>();
        let attestation_root = merkle_root("PQ-RECURSIVE-SETTLEMENT-SUBJECT-ATTESTATIONS", &leaves);
        if let Some(certificate) = self.certificates.get_mut(subject_id) {
            certificate.attach_attestations(&attestation_root);
        }
        if let Some(aggregate) = self.aggregates.get_mut(subject_id) {
            aggregate.status = AggregateStatus::Attested;
        }
        if let Some(job) = self.jobs.get_mut(subject_id) {
            job.status = ProofJobStatus::Attested;
        }
        Ok(())
    }
}

pub fn pq_recursive_settlement_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PQ-RECURSIVE-SETTLEMENT-COMPRESSOR-STATE",
        &[
            HashPart::Str(PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn pq_recursive_settlement_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn pq_recursive_settlement_empty_root(label: &str) -> String {
    domain_hash(
        "PQ-RECURSIVE-SETTLEMENT-EMPTY",
        &[
            HashPart::Str(PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn pq_recursive_settlement_id(domain: &str, parts: &[&str]) -> String {
    let parts_root = merkle_root(
        &format!("PQ-RECURSIVE-SETTLEMENT-ID-PARTS:{domain}"),
        &parts.iter().map(|part| json!(part)).collect::<Vec<_>>(),
    );
    domain_hash(
        "PQ-RECURSIVE-SETTLEMENT-ID",
        &[
            HashPart::Str(PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(&parts_root),
        ],
        20,
    )
}

fn proof_job_id(request: &ProofJobRequest, current_height: u64, deadline_height: u64) -> String {
    domain_hash(
        "PQ-RECURSIVE-SETTLEMENT-PROOF-JOB-ID",
        &[
            HashPart::Str(PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(request.kind.as_str()),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.circuit_id),
            HashPart::Str(&request.submitter_commitment),
            HashPart::Str(&request.witness_root),
            HashPart::Str(&request.public_input_root),
            HashPart::Int(current_height as i128),
            HashPart::Int(deadline_height as i128),
        ],
        20,
    )
}

fn aggregate_id(lane: SettlementLane, opened_at_height: u64) -> String {
    domain_hash(
        "PQ-RECURSIVE-SETTLEMENT-AGGREGATE-ID",
        &[
            HashPart::Str(PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Int(opened_at_height as i128),
        ],
        20,
    )
}

fn da_budget_id(aggregate_id: &str, namespace: &str, epoch: u64, requested_bytes: u64) -> String {
    domain_hash(
        "PQ-RECURSIVE-SETTLEMENT-DA-BUDGET-ID",
        &[
            HashPart::Str(PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(aggregate_id),
            HashPart::Str(namespace),
            HashPart::Int(epoch as i128),
            HashPart::Int(requested_bytes as i128),
        ],
        20,
    )
}

fn settlement_certificate_id(
    aggregate_id: &str,
    compressed_proof_root: &str,
    settlement_tx_commitment: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "PQ-RECURSIVE-SETTLEMENT-CERTIFICATE-ID",
        &[
            HashPart::Str(PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(aggregate_id),
            HashPart::Str(compressed_proof_root),
            HashPart::Str(settlement_tx_commitment),
            HashPart::Int(issued_at_height as i128),
        ],
        20,
    )
}

fn pq_attestation_id(
    subject_id: &str,
    role: PqAttestationRole,
    signer_id: &str,
    signed_payload_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "PQ-RECURSIVE-SETTLEMENT-ATTESTATION-ID",
        &[
            HashPart::Str(PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_id),
            HashPart::Str(role.as_str()),
            HashPart::Str(signer_id),
            HashPart::Str(signed_payload_root),
            HashPart::Int(signed_at_height as i128),
        ],
        20,
    )
}

fn sponsorship_id(sponsor_id: &str, job_id: &str, opened_at_height: u64) -> String {
    domain_hash(
        "PQ-RECURSIVE-SETTLEMENT-SPONSORSHIP-ID",
        &[
            HashPart::Str(PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(job_id),
            HashPart::Int(opened_at_height as i128),
        ],
        20,
    )
}

fn public_record_id(
    subject_id: &str,
    record_kind: &str,
    payload_root: &str,
    published_at_height: u64,
) -> String {
    domain_hash(
        "PQ-RECURSIVE-SETTLEMENT-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_id),
            HashPart::Str(record_kind),
            HashPart::Str(payload_root),
            HashPart::Int(published_at_height as i128),
        ],
        20,
    )
}

fn map_root(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(domain, &leaves)
}

fn devnet_root(label: &str, value: &str) -> String {
    domain_hash(
        "PQ-RECURSIVE-SETTLEMENT-DEVNET-ROOT",
        &[
            HashPart::Str(PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
        ],
        32,
    )
}

fn bps_portion(value: u64, bps: u64) -> u64 {
    value.saturating_mul(bps) / PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_MAX_BPS
}

fn ensure_non_empty(field: &str, value: &str) -> PqRecursiveSettlementCompressorResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(())
}

fn ensure_positive(field: &str, value: u64) -> PqRecursiveSettlementCompressorResult<()> {
    if value == 0 {
        return Err(format!("{field} must be greater than zero"));
    }
    Ok(())
}

fn ensure_positive_usize(field: &str, value: usize) -> PqRecursiveSettlementCompressorResult<()> {
    if value == 0 {
        return Err(format!("{field} must be greater than zero"));
    }
    Ok(())
}

fn ensure_bps(field: &str, value: u64) -> PqRecursiveSettlementCompressorResult<()> {
    if value > PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_MAX_BPS {
        return Err(format!("{field} must be at most 10000 bps"));
    }
    Ok(())
}

fn ensure_len(field: &str, value: usize) -> PqRecursiveSettlementCompressorResult<()> {
    if value > PQ_RECURSIVE_SETTLEMENT_COMPRESSOR_MAX_RECORDS {
        return Err(format!("{field} exceeds max record count"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_validates_and_roots_are_stable() {
        let state = PqRecursiveSettlementCompressorState::devnet()
            .map_err(|error| format!("devnet failed: {error}"));
        assert!(state.is_ok());
        let state = match state {
            Ok(state) => state,
            Err(error) => {
                assert!(error.is_empty());
                return;
            }
        };
        let first = state.state_root();
        let second = state.state_root();
        assert_eq!(first, second);
    }

    #[test]
    fn low_fee_sponsorship_tracks_remaining_units() {
        let mut state = PqRecursiveSettlementCompressorState::default();
        state.set_height(10);
        let job_id = state
            .submit_job(ProofJobRequest::devnet(
                SettlementCircuitFamily::FeeAccounting,
                SettlementLane::SponsoredLowFee,
                9,
            ))
            .map_err(|error| format!("submit failed: {error}"));
        assert!(job_id.is_ok());
        let job_id = match job_id {
            Ok(job_id) => job_id,
            Err(error) => {
                assert!(error.is_empty());
                return;
            }
        };
        let job = state.jobs.get(&job_id).cloned();
        assert!(job.is_some());
        let job = match job {
            Some(job) => job,
            None => return,
        };
        let mut sponsorship = LowFeeProofSponsorship::reserve_for_job(
            "sponsor",
            &job,
            100,
            32,
            5_000,
            state.height,
            12,
        );
        sponsorship.apply("aggregate", 40);
        assert_eq!(sponsorship.remaining_micro_units(), 60);
    }
}
