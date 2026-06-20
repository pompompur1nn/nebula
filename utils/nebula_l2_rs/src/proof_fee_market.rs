use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ProofFeeMarketResult<T> = Result<T, String>;

pub const PROOF_FEE_MARKET_PROTOCOL_VERSION: &str = "nebula-l2-proof-fee-market-v1";
pub const PROOF_FEE_MARKET_SCHEMA_VERSION: u64 = 1;
pub const PROOF_FEE_MARKET_HASH_SUITE: &str = "SHAKE256";
pub const PROOF_FEE_MARKET_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const PROOF_FEE_MARKET_PQ_RECOVERY_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const PROOF_FEE_MARKET_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const PROOF_FEE_MARKET_RECURSION_SCHEME: &str = "nebula-devnet-recursive-folding-v1";
pub const PROOF_FEE_MARKET_COMPRESSION_SCHEME: &str = "shake256-recursive-proof-compression-sla-v1";
pub const PROOF_FEE_MARKET_DEFAULT_FEE_ASSET_ID: &str = "asset:wxmr";
pub const PROOF_FEE_MARKET_ROLLUP_PROOF_SYSTEM: &str = "nebula-devnet-pq-rollup-state-validity-v1";
pub const PROOF_FEE_MARKET_MONERO_BRIDGE_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-monero-bridge-validity-v1";
pub const PROOF_FEE_MARKET_PRIVATE_CONTRACT_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-private-contract-validity-v1";
pub const PROOF_FEE_MARKET_REBATE_PROOF_SYSTEM: &str = "nebula-devnet-pq-fee-rebate-validity-v1";
pub const PROOF_FEE_MARKET_RECURSIVE_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-recursive-proof-market-v1";
pub const PROOF_FEE_MARKET_PQ_VERIFICATION_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-verifier-committee-v1";
pub const PROOF_FEE_MARKET_FALLBACK_PROOF_SYSTEM: &str = "nebula-devnet-pq-fallback-challenge-v1";

pub const PROOF_FEE_MARKET_DEFAULT_BID_WINDOW_BLOCKS: u64 = 3;
pub const PROOF_FEE_MARKET_DEFAULT_PROOF_SLA_BLOCKS: u64 = 8;
pub const PROOF_FEE_MARKET_DEFAULT_COMPRESSION_SLA_BLOCKS: u64 = 4;
pub const PROOF_FEE_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const PROOF_FEE_MARKET_DEFAULT_PQ_SECURITY_BITS: u64 = 128;
pub const PROOF_FEE_MARKET_MIN_BID_COLLATERAL_BPS: u64 = 2_500;
pub const PROOF_FEE_MARKET_PROTOCOL_FEE_BPS: u64 = 250;
pub const PROOF_FEE_MARKET_MAX_REBATE_BPS: u64 = 4_000;
pub const PROOF_FEE_MARKET_DEFAULT_SLASHING_BPS: u64 = 5_000;
pub const PROOF_FEE_MARKET_MIN_COMMITTEE_THRESHOLD_BPS: u64 = 6_700;
pub const PROOF_FEE_MARKET_MAX_COMMITTEE_WEIGHT_BPS: u64 = 10_000;
pub const PROOF_FEE_MARKET_MAX_BPS: u64 = 10_000;
pub const PROOF_FEE_MARKET_LOW_FEE_FLOOR_UNITS: u64 = 4;
pub const PROOF_FEE_MARKET_MIN_COMPRESSION_SAVINGS_BPS: u64 = 1_500;

pub const PROOF_FEE_MARKET_STATUS_OPEN: &str = "open";
pub const PROOF_FEE_MARKET_STATUS_ACTIVE: &str = "active";
pub const PROOF_FEE_MARKET_STATUS_ASSIGNED: &str = "assigned";
pub const PROOF_FEE_MARKET_STATUS_ACCEPTED: &str = "accepted";
pub const PROOF_FEE_MARKET_STATUS_REJECTED: &str = "rejected";
pub const PROOF_FEE_MARKET_STATUS_PROVED: &str = "proved";
pub const PROOF_FEE_MARKET_STATUS_VERIFIED: &str = "verified";
pub const PROOF_FEE_MARKET_STATUS_COMPRESSED: &str = "compressed";
pub const PROOF_FEE_MARKET_STATUS_CHALLENGED: &str = "challenged";
pub const PROOF_FEE_MARKET_STATUS_SETTLED: &str = "settled";
pub const PROOF_FEE_MARKET_STATUS_EXPIRED: &str = "expired";
pub const PROOF_FEE_MARKET_STATUS_SLASHED: &str = "slashed";
pub const PROOF_FEE_MARKET_STATUS_PAUSED: &str = "paused";
pub const PROOF_FEE_MARKET_STATUS_SEALED: &str = "sealed";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofFeeJobKind {
    RollupValidity,
    MoneroBridge,
    PrivateContract,
    FeeRebateAccounting,
    RecursiveAggregation,
    ProofCompression,
    PqVerification,
    WatchtowerFallback,
}

impl ProofFeeJobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RollupValidity => "rollup_validity",
            Self::MoneroBridge => "monero_bridge",
            Self::PrivateContract => "private_contract",
            Self::FeeRebateAccounting => "fee_rebate_accounting",
            Self::RecursiveAggregation => "recursive_aggregation",
            Self::ProofCompression => "proof_compression",
            Self::PqVerification => "pq_verification",
            Self::WatchtowerFallback => "watchtower_fallback",
        }
    }

    pub fn default_proof_system(self) -> &'static str {
        match self {
            Self::RollupValidity => PROOF_FEE_MARKET_ROLLUP_PROOF_SYSTEM,
            Self::MoneroBridge => PROOF_FEE_MARKET_MONERO_BRIDGE_PROOF_SYSTEM,
            Self::PrivateContract => PROOF_FEE_MARKET_PRIVATE_CONTRACT_PROOF_SYSTEM,
            Self::FeeRebateAccounting => PROOF_FEE_MARKET_REBATE_PROOF_SYSTEM,
            Self::RecursiveAggregation | Self::ProofCompression => {
                PROOF_FEE_MARKET_RECURSIVE_PROOF_SYSTEM
            }
            Self::PqVerification => PROOF_FEE_MARKET_PQ_VERIFICATION_PROOF_SYSTEM,
            Self::WatchtowerFallback => PROOF_FEE_MARKET_FALLBACK_PROOF_SYSTEM,
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::MoneroBridge | Self::PrivateContract | Self::FeeRebateAccounting
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofFeeLane {
    PublicRollup,
    MoneroBridge,
    PrivateExecution,
    LowFeeRebates,
    RecursiveBatch,
    SponsoredPublicGood,
    EmergencyFallback,
    Maintenance,
}

impl ProofFeeLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicRollup => "public_rollup",
            Self::MoneroBridge => "monero_bridge",
            Self::PrivateExecution => "private_execution",
            Self::LowFeeRebates => "low_fee_rebates",
            Self::RecursiveBatch => "recursive_batch",
            Self::SponsoredPublicGood => "sponsored_public_good",
            Self::EmergencyFallback => "emergency_fallback",
            Self::Maintenance => "maintenance",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::EmergencyFallback => 10_000,
            Self::MoneroBridge => 9_200,
            Self::PrivateExecution => 8_400,
            Self::PublicRollup => 7_500,
            Self::LowFeeRebates => 7_000,
            Self::RecursiveBatch => 6_500,
            Self::SponsoredPublicGood => 5_800,
            Self::Maintenance => 2_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofWorkerClass {
    Cpu,
    Gpu,
    Fpga,
    VerifierCommittee,
    Watchtower,
}

impl ProofWorkerClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Gpu => "gpu",
            Self::Fpga => "fpga",
            Self::VerifierCommittee => "verifier_committee",
            Self::Watchtower => "watchtower",
        }
    }

    pub fn capacity_weight(self) -> u64 {
        match self {
            Self::Cpu => 1,
            Self::Gpu => 8,
            Self::Fpga => 12,
            Self::VerifierCommittee => 4,
            Self::Watchtower => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofVerifierRole {
    Scheduler,
    PqVerifier,
    RecursionAuditor,
    CompressionAuditor,
    Watchtower,
    SponsorAuditor,
}

impl ProofVerifierRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduler => "scheduler",
            Self::PqVerifier => "pq_verifier",
            Self::RecursionAuditor => "recursion_auditor",
            Self::CompressionAuditor => "compression_auditor",
            Self::Watchtower => "watchtower",
            Self::SponsorAuditor => "sponsor_auditor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofVerifierCommitteePolicy {
    WeightedThreshold,
    RotatingSubset,
    EmergencyUnanimity,
}

impl ProofVerifierCommitteePolicy {
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
pub enum ProofVerificationOutcome {
    Accepted,
    Rejected,
    FallbackRequired,
}

impl ProofVerificationOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::FallbackRequired => "fallback_required",
        }
    }

    pub fn status(self) -> &'static str {
        match self {
            Self::Accepted => PROOF_FEE_MARKET_STATUS_VERIFIED,
            Self::Rejected => PROOF_FEE_MARKET_STATUS_REJECTED,
            Self::FallbackRequired => PROOF_FEE_MARKET_STATUS_CHALLENGED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofLatencyBucket {
    Fast,
    Target,
    Delayed,
    Expired,
    Slashed,
}

impl ProofLatencyBucket {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Target => "target",
            Self::Delayed => "delayed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }

    pub fn rebate_weight_bps(self) -> u64 {
        match self {
            Self::Fast => 10_000,
            Self::Target => 5_000,
            Self::Delayed | Self::Expired | Self::Slashed => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofCompressionSlaTier {
    PublicGood,
    Standard,
    Fast,
    TinyRecursive,
    BridgeExit,
    Emergency,
}

impl ProofCompressionSlaTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicGood => "public_good",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::TinyRecursive => "tiny_recursive",
            Self::BridgeExit => "bridge_exit",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofSlashingKind {
    LateProof,
    InvalidProof,
    CompressionMismatch,
    CommitteeEquivocation,
    MissingFallbackResponse,
    SponsorFraud,
}

impl ProofSlashingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LateProof => "late_proof",
            Self::InvalidProof => "invalid_proof",
            Self::CompressionMismatch => "compression_mismatch",
            Self::CommitteeEquivocation => "committee_equivocation",
            Self::MissingFallbackResponse => "missing_fallback_response",
            Self::SponsorFraud => "sponsor_fraud",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofFallbackChallengeKind {
    MissingChildProof,
    InvalidPublicInput,
    PqSignatureMismatch,
    CompressionRatioMiss,
    RecursiveAccumulatorMismatch,
    CommitteeQuorumFailure,
    Timeout,
}

impl ProofFallbackChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingChildProof => "missing_child_proof",
            Self::InvalidPublicInput => "invalid_public_input",
            Self::PqSignatureMismatch => "pq_signature_mismatch",
            Self::CompressionRatioMiss => "compression_ratio_miss",
            Self::RecursiveAccumulatorMismatch => "recursive_accumulator_mismatch",
            Self::CommitteeQuorumFailure => "committee_quorum_failure",
            Self::Timeout => "timeout",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofFallbackChallengeOutcome {
    Pending,
    ProverWins,
    ChallengerWins,
    Escalated,
    Expired,
}

impl ProofFallbackChallengeOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::ProverWins => "prover_wins",
            Self::ChallengerWins => "challenger_wins",
            Self::Escalated => "escalated",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFeeMarketConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub default_fee_asset_id: String,
    pub default_bid_window_blocks: u64,
    pub default_proof_sla_blocks: u64,
    pub default_compression_sla_blocks: u64,
    pub default_challenge_window_blocks: u64,
    pub default_pq_security_bits: u64,
    pub min_bid_collateral_bps: u64,
    pub protocol_fee_bps: u64,
    pub max_rebate_bps: u64,
    pub default_slashing_bps: u64,
    pub min_committee_threshold_bps: u64,
    pub max_committee_weight_bps: u64,
    pub low_fee_floor_units: u64,
    pub allow_devnet_fixtures: bool,
}

impl Default for ProofFeeMarketConfig {
    fn default() -> Self {
        Self {
            protocol_version: PROOF_FEE_MARKET_PROTOCOL_VERSION.to_string(),
            schema_version: PROOF_FEE_MARKET_SCHEMA_VERSION,
            default_fee_asset_id: PROOF_FEE_MARKET_DEFAULT_FEE_ASSET_ID.to_string(),
            default_bid_window_blocks: PROOF_FEE_MARKET_DEFAULT_BID_WINDOW_BLOCKS,
            default_proof_sla_blocks: PROOF_FEE_MARKET_DEFAULT_PROOF_SLA_BLOCKS,
            default_compression_sla_blocks: PROOF_FEE_MARKET_DEFAULT_COMPRESSION_SLA_BLOCKS,
            default_challenge_window_blocks: PROOF_FEE_MARKET_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            default_pq_security_bits: PROOF_FEE_MARKET_DEFAULT_PQ_SECURITY_BITS,
            min_bid_collateral_bps: PROOF_FEE_MARKET_MIN_BID_COLLATERAL_BPS,
            protocol_fee_bps: PROOF_FEE_MARKET_PROTOCOL_FEE_BPS,
            max_rebate_bps: PROOF_FEE_MARKET_MAX_REBATE_BPS,
            default_slashing_bps: PROOF_FEE_MARKET_DEFAULT_SLASHING_BPS,
            min_committee_threshold_bps: PROOF_FEE_MARKET_MIN_COMMITTEE_THRESHOLD_BPS,
            max_committee_weight_bps: PROOF_FEE_MARKET_MAX_COMMITTEE_WEIGHT_BPS,
            low_fee_floor_units: PROOF_FEE_MARKET_LOW_FEE_FLOOR_UNITS,
            allow_devnet_fixtures: true,
        }
    }
}

impl ProofFeeMarketConfig {
    pub fn validate(&self) -> ProofFeeMarketResult<()> {
        ensure_non_empty(&self.protocol_version, "proof fee market protocol version")?;
        ensure_non_empty(&self.default_fee_asset_id, "proof fee market fee asset")?;
        ensure_positive(self.default_bid_window_blocks, "bid window blocks")?;
        ensure_positive(self.default_proof_sla_blocks, "proof SLA blocks")?;
        ensure_positive(
            self.default_compression_sla_blocks,
            "compression SLA blocks",
        )?;
        ensure_positive(
            self.default_challenge_window_blocks,
            "challenge window blocks",
        )?;
        ensure_positive(self.default_pq_security_bits, "PQ security bits")?;
        ensure_bps(self.min_bid_collateral_bps, "minimum bid collateral bps")?;
        ensure_bps(self.protocol_fee_bps, "protocol fee bps")?;
        ensure_bps(self.max_rebate_bps, "max rebate bps")?;
        ensure_bps(self.default_slashing_bps, "default slashing bps")?;
        ensure_bps(
            self.min_committee_threshold_bps,
            "minimum committee threshold bps",
        )?;
        ensure_bps(self.max_committee_weight_bps, "max committee weight bps")?;
        if self.min_committee_threshold_bps == 0 {
            return Err("minimum committee threshold must be nonzero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_fee_market_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": PROOF_FEE_MARKET_HASH_SUITE,
            "pq_signature_scheme": PROOF_FEE_MARKET_PQ_SIGNATURE_SCHEME,
            "pq_recovery_scheme": PROOF_FEE_MARKET_PQ_RECOVERY_SCHEME,
            "pq_kem_scheme": PROOF_FEE_MARKET_PQ_KEM_SCHEME,
            "recursion_scheme": PROOF_FEE_MARKET_RECURSION_SCHEME,
            "compression_scheme": PROOF_FEE_MARKET_COMPRESSION_SCHEME,
            "default_fee_asset_id": self.default_fee_asset_id,
            "default_bid_window_blocks": self.default_bid_window_blocks,
            "default_proof_sla_blocks": self.default_proof_sla_blocks,
            "default_compression_sla_blocks": self.default_compression_sla_blocks,
            "default_challenge_window_blocks": self.default_challenge_window_blocks,
            "default_pq_security_bits": self.default_pq_security_bits,
            "min_bid_collateral_bps": self.min_bid_collateral_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "default_slashing_bps": self.default_slashing_bps,
            "min_committee_threshold_bps": self.min_committee_threshold_bps,
            "max_committee_weight_bps": self.max_committee_weight_bps,
            "low_fee_floor_units": self.low_fee_floor_units,
            "allow_devnet_fixtures": self.allow_devnet_fixtures,
        })
    }

    pub fn config_root(&self) -> String {
        proof_fee_market_payload_root("PROOF-FEE-MARKET-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofWorkloadEnvelope {
    pub workload_id: String,
    pub job_kind: ProofFeeJobKind,
    pub proof_system: String,
    pub recursion_depth: u64,
    pub child_proof_count: u64,
    pub public_input_root: String,
    pub witness_commitment: String,
    pub source_payload_root: String,
    pub privacy_bucket_root: String,
    pub estimated_cycles: u64,
    pub source_bytes: u64,
    pub target_proof_bytes: u64,
    pub pq_security_bits: u64,
    pub requires_pq_verification: bool,
    pub nonce: u64,
}

impl ProofWorkloadEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_kind: ProofFeeJobKind,
        proof_system: impl Into<String>,
        recursion_depth: u64,
        child_proof_count: u64,
        public_input_root: impl Into<String>,
        witness_commitment: impl Into<String>,
        source_payload_root: impl Into<String>,
        privacy_bucket_root: impl Into<String>,
        estimated_cycles: u64,
        source_bytes: u64,
        target_proof_bytes: u64,
        pq_security_bits: u64,
        requires_pq_verification: bool,
        nonce: u64,
    ) -> ProofFeeMarketResult<Self> {
        let proof_system = proof_system.into();
        let public_input_root = public_input_root.into();
        let witness_commitment = witness_commitment.into();
        let source_payload_root = source_payload_root.into();
        let privacy_bucket_root = privacy_bucket_root.into();
        ensure_non_empty(&proof_system, "workload proof system")?;
        ensure_hash_like(&public_input_root, "workload public input root")?;
        ensure_hash_like(&witness_commitment, "workload witness commitment")?;
        ensure_hash_like(&source_payload_root, "workload source payload root")?;
        ensure_hash_like(&privacy_bucket_root, "workload privacy bucket root")?;
        ensure_positive(estimated_cycles, "workload estimated cycles")?;
        ensure_positive(source_bytes, "workload source bytes")?;
        ensure_positive(target_proof_bytes, "workload target proof bytes")?;
        ensure_positive(pq_security_bits, "workload PQ security bits")?;
        let workload_id = proof_workload_id(
            job_kind,
            &proof_system,
            &public_input_root,
            &source_payload_root,
            recursion_depth,
            child_proof_count,
            nonce,
        );
        let workload = Self {
            workload_id,
            job_kind,
            proof_system,
            recursion_depth,
            child_proof_count,
            public_input_root,
            witness_commitment,
            source_payload_root,
            privacy_bucket_root,
            estimated_cycles,
            source_bytes,
            target_proof_bytes,
            pq_security_bits,
            requires_pq_verification,
            nonce,
        };
        workload.validate()?;
        Ok(workload)
    }

    pub fn devnet(
        job_kind: ProofFeeJobKind,
        label: &str,
        nonce: u64,
    ) -> ProofFeeMarketResult<Self> {
        let base_cycles: u64 = match job_kind {
            ProofFeeJobKind::MoneroBridge => 18_000_000,
            ProofFeeJobKind::PrivateContract => 22_000_000,
            ProofFeeJobKind::FeeRebateAccounting => 8_000_000,
            ProofFeeJobKind::RecursiveAggregation => 14_000_000,
            ProofFeeJobKind::ProofCompression => 6_000_000,
            ProofFeeJobKind::PqVerification => 4_000_000,
            ProofFeeJobKind::WatchtowerFallback => 12_000_000,
            ProofFeeJobKind::RollupValidity => 26_000_000,
        };
        Self::new(
            job_kind,
            job_kind.default_proof_system(),
            if matches!(job_kind, ProofFeeJobKind::RecursiveAggregation) {
                2
            } else {
                0
            },
            if matches!(job_kind, ProofFeeJobKind::RecursiveAggregation) {
                8
            } else {
                1
            },
            proof_fee_market_deterministic_root(&format!("{label}:public-input")),
            proof_fee_market_deterministic_commitment(&format!("{label}:witness")),
            proof_fee_market_deterministic_root(&format!("{label}:source-payload")),
            proof_fee_market_deterministic_root(&format!("{label}:privacy-bucket")),
            base_cycles.saturating_add(nonce.saturating_mul(750_000)),
            380_000_u64.saturating_add(nonce.saturating_mul(32_000)),
            96_000_u64.saturating_add(nonce.saturating_mul(8_000)),
            PROOF_FEE_MARKET_DEFAULT_PQ_SECURITY_BITS,
            true,
            nonce,
        )
    }

    pub fn compute_units(&self) -> u64 {
        self.estimated_cycles
            .div_ceil(1_000_000)
            .saturating_add(self.child_proof_count.saturating_mul(20))
            .saturating_add(self.recursion_depth.saturating_mul(50))
    }

    pub fn validate(&self) -> ProofFeeMarketResult<String> {
        ensure_non_empty(&self.workload_id, "workload id")?;
        ensure_non_empty(&self.proof_system, "workload proof system")?;
        ensure_hash_like(&self.public_input_root, "workload public input root")?;
        ensure_hash_like(&self.witness_commitment, "workload witness commitment")?;
        ensure_hash_like(&self.source_payload_root, "workload source payload root")?;
        ensure_hash_like(&self.privacy_bucket_root, "workload privacy bucket root")?;
        ensure_positive(self.estimated_cycles, "workload estimated cycles")?;
        ensure_positive(self.source_bytes, "workload source bytes")?;
        ensure_positive(self.target_proof_bytes, "workload target proof bytes")?;
        ensure_positive(self.pq_security_bits, "workload PQ security bits")?;
        let expected_id = proof_workload_id(
            self.job_kind,
            &self.proof_system,
            &self.public_input_root,
            &self.source_payload_root,
            self.recursion_depth,
            self.child_proof_count,
            self.nonce,
        );
        if self.workload_id != expected_id {
            return Err("workload id mismatch".to_string());
        }
        Ok(proof_workload_root(self))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_workload_envelope",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "workload_id": self.workload_id,
            "job_kind": self.job_kind.as_str(),
            "proof_system": self.proof_system,
            "recursion_depth": self.recursion_depth,
            "child_proof_count": self.child_proof_count,
            "public_input_root": self.public_input_root,
            "witness_commitment": self.witness_commitment,
            "source_payload_root": self.source_payload_root,
            "privacy_bucket_root": self.privacy_bucket_root,
            "estimated_cycles": self.estimated_cycles,
            "compute_units": self.compute_units(),
            "source_bytes": self.source_bytes,
            "target_proof_bytes": self.target_proof_bytes,
            "pq_security_bits": self.pq_security_bits,
            "requires_pq_verification": self.requires_pq_verification,
            "privacy_sensitive": self.job_kind.privacy_sensitive(),
            "nonce": self.nonce,
        })
    }

    pub fn workload_root(&self) -> String {
        proof_workload_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFeeJob {
    pub job_id: String,
    pub requester_commitment: String,
    pub lane: ProofFeeLane,
    pub workload: ProofWorkloadEnvelope,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub reserve_fee_units: u64,
    pub sponsor_id: String,
    pub rebate_policy_id: String,
    pub posted_at_height: u64,
    pub bid_deadline_height: u64,
    pub proof_deadline_height: u64,
    pub compression_deadline_height: u64,
    pub challenge_deadline_height: u64,
    pub nonce: u64,
    pub status: String,
    pub assigned_bid_id: String,
    pub proof_receipt_id: String,
    pub verification_receipt_id: String,
    pub compression_receipt_id: String,
}

impl ProofFeeJob {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        requester_commitment: impl Into<String>,
        lane: ProofFeeLane,
        workload: ProofWorkloadEnvelope,
        fee_asset_id: impl Into<String>,
        max_fee_units: u64,
        reserve_fee_units: u64,
        sponsor_id: impl Into<String>,
        rebate_policy_id: impl Into<String>,
        posted_at_height: u64,
        bid_window_blocks: u64,
        proof_sla_blocks: u64,
        compression_sla_blocks: u64,
        challenge_window_blocks: u64,
        nonce: u64,
    ) -> ProofFeeMarketResult<Self> {
        let requester_commitment = requester_commitment.into();
        let fee_asset_id = fee_asset_id.into();
        let sponsor_id = sponsor_id.into();
        let rebate_policy_id = rebate_policy_id.into();
        ensure_hash_like(&requester_commitment, "job requester commitment")?;
        ensure_non_empty(&fee_asset_id, "job fee asset")?;
        ensure_positive(max_fee_units, "job max fee units")?;
        if reserve_fee_units > max_fee_units {
            return Err("job reserve fee exceeds max fee".to_string());
        }
        ensure_positive(bid_window_blocks, "job bid window")?;
        ensure_positive(proof_sla_blocks, "job proof SLA")?;
        ensure_positive(compression_sla_blocks, "job compression SLA")?;
        ensure_positive(challenge_window_blocks, "job challenge window")?;
        workload.validate()?;
        let bid_deadline_height = posted_at_height.saturating_add(bid_window_blocks);
        let proof_deadline_height = bid_deadline_height.saturating_add(proof_sla_blocks);
        let compression_deadline_height =
            proof_deadline_height.saturating_add(compression_sla_blocks);
        let challenge_deadline_height =
            compression_deadline_height.saturating_add(challenge_window_blocks);
        let job_id = proof_fee_job_id(
            &requester_commitment,
            lane,
            &workload.workload_id,
            &fee_asset_id,
            max_fee_units,
            posted_at_height,
            nonce,
        );
        let job = Self {
            job_id,
            requester_commitment,
            lane,
            workload,
            fee_asset_id,
            max_fee_units,
            reserve_fee_units,
            sponsor_id,
            rebate_policy_id,
            posted_at_height,
            bid_deadline_height,
            proof_deadline_height,
            compression_deadline_height,
            challenge_deadline_height,
            nonce,
            status: PROOF_FEE_MARKET_STATUS_OPEN.to_string(),
            assigned_bid_id: String::new(),
            proof_receipt_id: String::new(),
            verification_receipt_id: String::new(),
            compression_receipt_id: String::new(),
        };
        job.validate()?;
        Ok(job)
    }

    pub fn accepts_bids_at(&self, height: u64) -> bool {
        self.status == PROOF_FEE_MARKET_STATUS_OPEN
            && height >= self.posted_at_height
            && height <= self.bid_deadline_height
    }

    pub fn proof_latency_target_blocks(&self) -> u64 {
        self.proof_deadline_height
            .saturating_sub(self.posted_at_height)
            .max(1)
    }

    pub fn compression_latency_target_blocks(&self) -> u64 {
        self.compression_deadline_height
            .saturating_sub(self.proof_deadline_height)
            .max(1)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status.as_str(),
            PROOF_FEE_MARKET_STATUS_SETTLED
                | PROOF_FEE_MARKET_STATUS_EXPIRED
                | PROOF_FEE_MARKET_STATUS_REJECTED
                | PROOF_FEE_MARKET_STATUS_SLASHED
        )
    }

    pub fn validate(&self) -> ProofFeeMarketResult<String> {
        ensure_non_empty(&self.job_id, "job id")?;
        ensure_hash_like(&self.requester_commitment, "job requester commitment")?;
        self.workload.validate()?;
        ensure_non_empty(&self.fee_asset_id, "job fee asset")?;
        ensure_positive(self.max_fee_units, "job max fee units")?;
        if self.reserve_fee_units > self.max_fee_units {
            return Err("job reserve fee exceeds max fee".to_string());
        }
        if self.bid_deadline_height < self.posted_at_height {
            return Err("job bid deadline is before posting".to_string());
        }
        if self.proof_deadline_height < self.bid_deadline_height {
            return Err("job proof deadline is before bid deadline".to_string());
        }
        if self.compression_deadline_height < self.proof_deadline_height {
            return Err("job compression deadline is before proof deadline".to_string());
        }
        if self.challenge_deadline_height < self.compression_deadline_height {
            return Err("job challenge deadline is before compression deadline".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_FEE_MARKET_STATUS_OPEN,
                PROOF_FEE_MARKET_STATUS_ASSIGNED,
                PROOF_FEE_MARKET_STATUS_PROVED,
                PROOF_FEE_MARKET_STATUS_VERIFIED,
                PROOF_FEE_MARKET_STATUS_COMPRESSED,
                PROOF_FEE_MARKET_STATUS_CHALLENGED,
                PROOF_FEE_MARKET_STATUS_SETTLED,
                PROOF_FEE_MARKET_STATUS_EXPIRED,
                PROOF_FEE_MARKET_STATUS_REJECTED,
                PROOF_FEE_MARKET_STATUS_SLASHED,
            ],
            "job status",
        )?;
        let expected_id = proof_fee_job_id(
            &self.requester_commitment,
            self.lane,
            &self.workload.workload_id,
            &self.fee_asset_id,
            self.max_fee_units,
            self.posted_at_height,
            self.nonce,
        );
        if self.job_id != expected_id {
            return Err("proof fee job id mismatch".to_string());
        }
        Ok(proof_fee_job_root(self))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_fee_job",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "job_id": self.job_id,
            "requester_commitment": self.requester_commitment,
            "lane": self.lane.as_str(),
            "lane_weight": self.lane.default_weight(),
            "workload": self.workload.public_record(),
            "workload_root": self.workload.workload_root(),
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "reserve_fee_units": self.reserve_fee_units,
            "sponsor_id": self.sponsor_id,
            "rebate_policy_id": self.rebate_policy_id,
            "posted_at_height": self.posted_at_height,
            "bid_deadline_height": self.bid_deadline_height,
            "proof_deadline_height": self.proof_deadline_height,
            "compression_deadline_height": self.compression_deadline_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "nonce": self.nonce,
            "status": self.status,
            "assigned_bid_id": self.assigned_bid_id,
            "proof_receipt_id": self.proof_receipt_id,
            "verification_receipt_id": self.verification_receipt_id,
            "compression_receipt_id": self.compression_receipt_id,
        })
    }

    pub fn job_root(&self) -> String {
        proof_fee_job_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFeeProverBid {
    pub bid_id: String,
    pub job_id: String,
    pub prover_id: String,
    pub worker_class: ProofWorkerClass,
    pub bid_fee_units: u64,
    pub promised_proof_latency_blocks: u64,
    pub promised_compression_latency_blocks: u64,
    pub collateral_units: u64,
    pub pq_public_key_root: String,
    pub capacity_commitment_root: String,
    pub placed_at_height: u64,
    pub score: u64,
    pub status: String,
}

impl ProofFeeProverBid {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job: &ProofFeeJob,
        prover_id: impl Into<String>,
        worker_class: ProofWorkerClass,
        bid_fee_units: u64,
        promised_proof_latency_blocks: u64,
        promised_compression_latency_blocks: u64,
        collateral_units: u64,
        pq_public_key_root: impl Into<String>,
        capacity_commitment_root: impl Into<String>,
        placed_at_height: u64,
    ) -> ProofFeeMarketResult<Self> {
        let prover_id = prover_id.into();
        let pq_public_key_root = pq_public_key_root.into();
        let capacity_commitment_root = capacity_commitment_root.into();
        ensure_non_empty(&prover_id, "prover id")?;
        ensure_positive(bid_fee_units, "bid fee units")?;
        ensure_positive(
            promised_proof_latency_blocks,
            "promised proof latency blocks",
        )?;
        ensure_positive(
            promised_compression_latency_blocks,
            "promised compression latency blocks",
        )?;
        ensure_hash_like(&pq_public_key_root, "bid PQ public key root")?;
        ensure_hash_like(&capacity_commitment_root, "bid capacity commitment root")?;
        if bid_fee_units > job.max_fee_units {
            return Err("bid fee exceeds job max fee".to_string());
        }
        let required_collateral =
            required_bid_collateral_units(bid_fee_units, PROOF_FEE_MARKET_MIN_BID_COLLATERAL_BPS);
        if collateral_units < required_collateral {
            return Err("bid collateral is below market minimum".to_string());
        }
        let bid_id = proof_fee_bid_id(
            &job.job_id,
            &prover_id,
            worker_class,
            bid_fee_units,
            placed_at_height,
        );
        let score = proof_fee_bid_score(
            job,
            worker_class,
            bid_fee_units,
            promised_proof_latency_blocks,
            promised_compression_latency_blocks,
            collateral_units,
        );
        let bid = Self {
            bid_id,
            job_id: job.job_id.clone(),
            prover_id,
            worker_class,
            bid_fee_units,
            promised_proof_latency_blocks,
            promised_compression_latency_blocks,
            collateral_units,
            pq_public_key_root,
            capacity_commitment_root,
            placed_at_height,
            score,
            status: PROOF_FEE_MARKET_STATUS_OPEN.to_string(),
        };
        bid.validate()?;
        Ok(bid)
    }

    pub fn validate(&self) -> ProofFeeMarketResult<String> {
        ensure_non_empty(&self.bid_id, "bid id")?;
        ensure_non_empty(&self.job_id, "bid job id")?;
        ensure_non_empty(&self.prover_id, "bid prover id")?;
        ensure_positive(self.bid_fee_units, "bid fee units")?;
        ensure_positive(
            self.promised_proof_latency_blocks,
            "bid promised proof latency",
        )?;
        ensure_positive(
            self.promised_compression_latency_blocks,
            "bid promised compression latency",
        )?;
        ensure_hash_like(&self.pq_public_key_root, "bid PQ public key root")?;
        ensure_hash_like(
            &self.capacity_commitment_root,
            "bid capacity commitment root",
        )?;
        ensure_status(
            &self.status,
            &[
                PROOF_FEE_MARKET_STATUS_OPEN,
                PROOF_FEE_MARKET_STATUS_ACCEPTED,
                PROOF_FEE_MARKET_STATUS_REJECTED,
                PROOF_FEE_MARKET_STATUS_SETTLED,
                PROOF_FEE_MARKET_STATUS_SLASHED,
                PROOF_FEE_MARKET_STATUS_EXPIRED,
            ],
            "bid status",
        )?;
        let expected_id = proof_fee_bid_id(
            &self.job_id,
            &self.prover_id,
            self.worker_class,
            self.bid_fee_units,
            self.placed_at_height,
        );
        if self.bid_id != expected_id {
            return Err("proof fee bid id mismatch".to_string());
        }
        Ok(proof_fee_bid_root(self))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_fee_prover_bid",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "bid_id": self.bid_id,
            "job_id": self.job_id,
            "prover_id": self.prover_id,
            "worker_class": self.worker_class.as_str(),
            "bid_fee_units": self.bid_fee_units,
            "promised_proof_latency_blocks": self.promised_proof_latency_blocks,
            "promised_compression_latency_blocks": self.promised_compression_latency_blocks,
            "collateral_units": self.collateral_units,
            "pq_public_key_root": self.pq_public_key_root,
            "capacity_commitment_root": self.capacity_commitment_root,
            "placed_at_height": self.placed_at_height,
            "score": self.score,
            "status": self.status,
        })
    }

    pub fn bid_root(&self) -> String {
        proof_fee_bid_root(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofVerifierMember {
    pub member_id: String,
    pub operator_id: String,
    pub role: ProofVerifierRole,
    pub weight: u64,
    pub pq_public_key_root: String,
    pub recovery_key_root: String,
    pub stake_root: String,
    pub endpoint_commitment: String,
    pub joined_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl ProofVerifierMember {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operator_id: impl Into<String>,
        role: ProofVerifierRole,
        weight: u64,
        pq_public_key_root: impl Into<String>,
        recovery_key_root: impl Into<String>,
        stake_root: impl Into<String>,
        endpoint_commitment: impl Into<String>,
        joined_at_height: u64,
        expires_at_height: u64,
    ) -> ProofFeeMarketResult<Self> {
        let operator_id = operator_id.into();
        let pq_public_key_root = pq_public_key_root.into();
        let recovery_key_root = recovery_key_root.into();
        let stake_root = stake_root.into();
        let endpoint_commitment = endpoint_commitment.into();
        ensure_non_empty(&operator_id, "verifier operator id")?;
        ensure_positive(weight, "verifier member weight")?;
        ensure_hash_like(&pq_public_key_root, "verifier PQ public key root")?;
        ensure_hash_like(&recovery_key_root, "verifier recovery key root")?;
        ensure_hash_like(&stake_root, "verifier stake root")?;
        ensure_hash_like(&endpoint_commitment, "verifier endpoint commitment")?;
        if expires_at_height != 0 && expires_at_height < joined_at_height {
            return Err("verifier member expires before joining".to_string());
        }
        let member_id = proof_verifier_member_id(
            &operator_id,
            role,
            weight,
            &pq_public_key_root,
            joined_at_height,
        );
        let member = Self {
            member_id,
            operator_id,
            role,
            weight,
            pq_public_key_root,
            recovery_key_root,
            stake_root,
            endpoint_commitment,
            joined_at_height,
            expires_at_height,
            status: PROOF_FEE_MARKET_STATUS_ACTIVE.to_string(),
        };
        member.validate()?;
        Ok(member)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PROOF_FEE_MARKET_STATUS_ACTIVE
            && height >= self.joined_at_height
            && (self.expires_at_height == 0 || height <= self.expires_at_height)
    }

    pub fn validate(&self) -> ProofFeeMarketResult<String> {
        ensure_non_empty(&self.member_id, "verifier member id")?;
        ensure_non_empty(&self.operator_id, "verifier operator id")?;
        ensure_positive(self.weight, "verifier member weight")?;
        ensure_hash_like(&self.pq_public_key_root, "verifier PQ public key root")?;
        ensure_hash_like(&self.recovery_key_root, "verifier recovery key root")?;
        ensure_hash_like(&self.stake_root, "verifier stake root")?;
        ensure_hash_like(&self.endpoint_commitment, "verifier endpoint commitment")?;
        if self.expires_at_height != 0 && self.expires_at_height < self.joined_at_height {
            return Err("verifier member expires before joining".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_FEE_MARKET_STATUS_ACTIVE,
                PROOF_FEE_MARKET_STATUS_EXPIRED,
                PROOF_FEE_MARKET_STATUS_SLASHED,
                PROOF_FEE_MARKET_STATUS_PAUSED,
            ],
            "verifier member status",
        )?;
        let expected_id = proof_verifier_member_id(
            &self.operator_id,
            self.role,
            self.weight,
            &self.pq_public_key_root,
            self.joined_at_height,
        );
        if self.member_id != expected_id {
            return Err("verifier member id mismatch".to_string());
        }
        Ok(proof_verifier_member_root(self))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_verifier_member",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "member_id": self.member_id,
            "operator_id": self.operator_id,
            "role": self.role.as_str(),
            "weight": self.weight,
            "pq_public_key_root": self.pq_public_key_root,
            "recovery_key_root": self.recovery_key_root,
            "stake_root": self.stake_root,
            "endpoint_commitment": self.endpoint_commitment,
            "joined_at_height": self.joined_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofVerifierCommittee {
    pub committee_id: String,
    pub epoch: u64,
    pub policy: ProofVerifierCommitteePolicy,
    pub member_ids: Vec<String>,
    pub member_weight_root: String,
    pub threshold_bps: u64,
    pub challenge_window_blocks: u64,
    pub formed_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl ProofVerifierCommittee {
    #[allow(clippy::too_many_arguments)]
    pub fn from_members(
        epoch: u64,
        policy: ProofVerifierCommitteePolicy,
        members: &[ProofVerifierMember],
        threshold_bps: u64,
        challenge_window_blocks: u64,
        formed_at_height: u64,
        expires_at_height: u64,
    ) -> ProofFeeMarketResult<Self> {
        if members.is_empty() {
            return Err("verifier committee requires members".to_string());
        }
        ensure_bps(threshold_bps, "verifier committee threshold")?;
        ensure_positive(challenge_window_blocks, "verifier challenge window")?;
        if expires_at_height != 0 && expires_at_height < formed_at_height {
            return Err("verifier committee expires before formation".to_string());
        }
        let mut member_ids = members
            .iter()
            .map(|member| member.member_id.clone())
            .collect::<Vec<_>>();
        ensure_unique_strings(&member_ids, "verifier committee member")?;
        member_ids.sort();
        let member_weight_root = verifier_member_weight_root(members);
        let committee_id = proof_verifier_committee_id(
            epoch,
            policy,
            &member_weight_root,
            threshold_bps,
            formed_at_height,
        );
        let committee = Self {
            committee_id,
            epoch,
            policy,
            member_ids,
            member_weight_root,
            threshold_bps,
            challenge_window_blocks,
            formed_at_height,
            expires_at_height,
            status: PROOF_FEE_MARKET_STATUS_ACTIVE.to_string(),
        };
        committee.validate()?;
        Ok(committee)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PROOF_FEE_MARKET_STATUS_ACTIVE
            && height >= self.formed_at_height
            && (self.expires_at_height == 0 || height <= self.expires_at_height)
    }

    pub fn has_threshold(&self, accepted_weight: u64, total_weight: u64) -> bool {
        if total_weight == 0 {
            return false;
        }
        accepted_weight.saturating_mul(PROOF_FEE_MARKET_MAX_BPS)
            >= total_weight.saturating_mul(self.threshold_bps)
    }

    pub fn validate(&self) -> ProofFeeMarketResult<String> {
        ensure_non_empty(&self.committee_id, "verifier committee id")?;
        ensure_unique_strings(&self.member_ids, "verifier committee member")?;
        ensure_hash_like(
            &self.member_weight_root,
            "verifier committee member weight root",
        )?;
        ensure_bps(self.threshold_bps, "verifier committee threshold")?;
        ensure_positive(
            self.challenge_window_blocks,
            "verifier committee challenge window",
        )?;
        if self.expires_at_height != 0 && self.expires_at_height < self.formed_at_height {
            return Err("verifier committee expires before formation".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_FEE_MARKET_STATUS_ACTIVE,
                PROOF_FEE_MARKET_STATUS_EXPIRED,
                PROOF_FEE_MARKET_STATUS_SLASHED,
                PROOF_FEE_MARKET_STATUS_PAUSED,
            ],
            "verifier committee status",
        )?;
        let expected_id = proof_verifier_committee_id(
            self.epoch,
            self.policy,
            &self.member_weight_root,
            self.threshold_bps,
            self.formed_at_height,
        );
        if self.committee_id != expected_id {
            return Err("verifier committee id mismatch".to_string());
        }
        Ok(proof_verifier_committee_root(self))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_verifier_committee",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "committee_id": self.committee_id,
            "epoch": self.epoch,
            "policy": self.policy.as_str(),
            "member_ids": self.member_ids,
            "member_count": self.member_ids.len() as u64,
            "member_weight_root": self.member_weight_root,
            "threshold_bps": self.threshold_bps,
            "challenge_window_blocks": self.challenge_window_blocks,
            "formed_at_height": self.formed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFeeProofReceipt {
    pub receipt_id: String,
    pub job_id: String,
    pub bid_id: String,
    pub prover_id: String,
    pub proof_root: String,
    pub public_output_root: String,
    pub verification_key_root: String,
    pub proof_bytes: u64,
    pub completed_at_height: u64,
    pub latency_bucket: ProofLatencyBucket,
    pub status: String,
}

impl ProofFeeProofReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job: &ProofFeeJob,
        bid: &ProofFeeProverBid,
        proof_root: impl Into<String>,
        public_output_root: impl Into<String>,
        verification_key_root: impl Into<String>,
        proof_bytes: u64,
        completed_at_height: u64,
    ) -> ProofFeeMarketResult<Self> {
        let proof_root = proof_root.into();
        let public_output_root = public_output_root.into();
        let verification_key_root = verification_key_root.into();
        ensure_hash_like(&proof_root, "proof receipt proof root")?;
        ensure_hash_like(&public_output_root, "proof receipt public output root")?;
        ensure_hash_like(
            &verification_key_root,
            "proof receipt verification key root",
        )?;
        ensure_positive(proof_bytes, "proof receipt proof bytes")?;
        if bid.job_id != job.job_id {
            return Err("proof receipt bid does not match job".to_string());
        }
        let latency_bucket = classify_latency(
            job.posted_at_height,
            completed_at_height,
            bid.promised_proof_latency_blocks,
            job.proof_deadline_height,
        );
        let receipt_id = proof_fee_receipt_id(
            &job.job_id,
            &bid.bid_id,
            &proof_root,
            &public_output_root,
            completed_at_height,
        );
        let receipt = Self {
            receipt_id,
            job_id: job.job_id.clone(),
            bid_id: bid.bid_id.clone(),
            prover_id: bid.prover_id.clone(),
            proof_root,
            public_output_root,
            verification_key_root,
            proof_bytes,
            completed_at_height,
            latency_bucket,
            status: PROOF_FEE_MARKET_STATUS_PROVED.to_string(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> ProofFeeMarketResult<String> {
        ensure_non_empty(&self.receipt_id, "proof receipt id")?;
        ensure_non_empty(&self.job_id, "proof receipt job id")?;
        ensure_non_empty(&self.bid_id, "proof receipt bid id")?;
        ensure_non_empty(&self.prover_id, "proof receipt prover id")?;
        ensure_hash_like(&self.proof_root, "proof receipt proof root")?;
        ensure_hash_like(&self.public_output_root, "proof receipt public output root")?;
        ensure_hash_like(
            &self.verification_key_root,
            "proof receipt verification key root",
        )?;
        ensure_positive(self.proof_bytes, "proof receipt proof bytes")?;
        ensure_status(
            &self.status,
            &[
                PROOF_FEE_MARKET_STATUS_PROVED,
                PROOF_FEE_MARKET_STATUS_VERIFIED,
                PROOF_FEE_MARKET_STATUS_REJECTED,
                PROOF_FEE_MARKET_STATUS_CHALLENGED,
                PROOF_FEE_MARKET_STATUS_SLASHED,
            ],
            "proof receipt status",
        )?;
        let expected_id = proof_fee_receipt_id(
            &self.job_id,
            &self.bid_id,
            &self.proof_root,
            &self.public_output_root,
            self.completed_at_height,
        );
        if self.receipt_id != expected_id {
            return Err("proof receipt id mismatch".to_string());
        }
        Ok(proof_fee_receipt_root(self))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_fee_proof_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "job_id": self.job_id,
            "bid_id": self.bid_id,
            "prover_id": self.prover_id,
            "proof_root": self.proof_root,
            "public_output_root": self.public_output_root,
            "verification_key_root": self.verification_key_root,
            "proof_bytes": self.proof_bytes,
            "completed_at_height": self.completed_at_height,
            "latency_bucket": self.latency_bucket.as_str(),
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCommitteeVerificationReceipt {
    pub verification_receipt_id: String,
    pub job_id: String,
    pub proof_receipt_id: String,
    pub committee_id: String,
    pub outcome: ProofVerificationOutcome,
    pub accepted_weight: u64,
    pub rejected_weight: u64,
    pub total_weight: u64,
    pub verifier_response_root: String,
    pub sampled_at_height: u64,
    pub finalized_at_height: u64,
    pub status: String,
}

impl ProofCommitteeVerificationReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proof_receipt: &ProofFeeProofReceipt,
        committee: &ProofVerifierCommittee,
        outcome: ProofVerificationOutcome,
        accepted_weight: u64,
        rejected_weight: u64,
        total_weight: u64,
        verifier_response_root: impl Into<String>,
        sampled_at_height: u64,
        finalized_at_height: u64,
    ) -> ProofFeeMarketResult<Self> {
        let verifier_response_root = verifier_response_root.into();
        ensure_hash_like(&verifier_response_root, "verifier response root")?;
        ensure_positive(total_weight, "verifier total weight")?;
        if accepted_weight.saturating_add(rejected_weight) > total_weight {
            return Err("verifier weights exceed total committee weight".to_string());
        }
        if outcome == ProofVerificationOutcome::Accepted
            && !committee.has_threshold(accepted_weight, total_weight)
        {
            return Err("accepted proof does not meet committee threshold".to_string());
        }
        if finalized_at_height < sampled_at_height {
            return Err("verification receipt finalizes before sampling".to_string());
        }
        let verification_receipt_id = proof_verification_receipt_id(
            &proof_receipt.receipt_id,
            &committee.committee_id,
            outcome,
            &verifier_response_root,
            finalized_at_height,
        );
        let receipt = Self {
            verification_receipt_id,
            job_id: proof_receipt.job_id.clone(),
            proof_receipt_id: proof_receipt.receipt_id.clone(),
            committee_id: committee.committee_id.clone(),
            outcome,
            accepted_weight,
            rejected_weight,
            total_weight,
            verifier_response_root,
            sampled_at_height,
            finalized_at_height,
            status: outcome.status().to_string(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> ProofFeeMarketResult<String> {
        ensure_non_empty(&self.verification_receipt_id, "verification receipt id")?;
        ensure_non_empty(&self.job_id, "verification receipt job id")?;
        ensure_non_empty(&self.proof_receipt_id, "verification proof receipt id")?;
        ensure_non_empty(&self.committee_id, "verification committee id")?;
        ensure_positive(self.total_weight, "verification total weight")?;
        ensure_hash_like(&self.verifier_response_root, "verifier response root")?;
        if self.accepted_weight.saturating_add(self.rejected_weight) > self.total_weight {
            return Err("verification weights exceed total committee weight".to_string());
        }
        if self.finalized_at_height < self.sampled_at_height {
            return Err("verification finalizes before sampling".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_FEE_MARKET_STATUS_VERIFIED,
                PROOF_FEE_MARKET_STATUS_REJECTED,
                PROOF_FEE_MARKET_STATUS_CHALLENGED,
            ],
            "verification receipt status",
        )?;
        let expected_id = proof_verification_receipt_id(
            &self.proof_receipt_id,
            &self.committee_id,
            self.outcome,
            &self.verifier_response_root,
            self.finalized_at_height,
        );
        if self.verification_receipt_id != expected_id {
            return Err("verification receipt id mismatch".to_string());
        }
        Ok(proof_verification_receipt_root(self))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_committee_verification_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "verification_receipt_id": self.verification_receipt_id,
            "job_id": self.job_id,
            "proof_receipt_id": self.proof_receipt_id,
            "committee_id": self.committee_id,
            "outcome": self.outcome.as_str(),
            "accepted_weight": self.accepted_weight,
            "rejected_weight": self.rejected_weight,
            "total_weight": self.total_weight,
            "verifier_response_root": self.verifier_response_root,
            "sampled_at_height": self.sampled_at_height,
            "finalized_at_height": self.finalized_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCompressionSla {
    pub sla_id: String,
    pub job_kind: ProofFeeJobKind,
    pub tier: ProofCompressionSlaTier,
    pub target_compressed_bytes: u64,
    pub target_verify_micros: u64,
    pub target_latency_blocks: u64,
    pub min_savings_bps: u64,
    pub rebate_bps: u64,
    pub slash_bps: u64,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: String,
}

impl ProofCompressionSla {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_kind: ProofFeeJobKind,
        tier: ProofCompressionSlaTier,
        target_compressed_bytes: u64,
        target_verify_micros: u64,
        target_latency_blocks: u64,
        min_savings_bps: u64,
        rebate_bps: u64,
        slash_bps: u64,
        starts_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> ProofFeeMarketResult<Self> {
        ensure_positive(target_compressed_bytes, "compression SLA target bytes")?;
        ensure_positive(target_verify_micros, "compression SLA target verify micros")?;
        ensure_positive(target_latency_blocks, "compression SLA latency blocks")?;
        ensure_bps(min_savings_bps, "compression SLA savings bps")?;
        ensure_bps(rebate_bps, "compression SLA rebate bps")?;
        ensure_bps(slash_bps, "compression SLA slash bps")?;
        if expires_at_height != 0 && expires_at_height < starts_at_height {
            return Err("compression SLA expires before start".to_string());
        }
        let sla_id = proof_compression_sla_id(
            job_kind,
            tier,
            target_compressed_bytes,
            target_verify_micros,
            target_latency_blocks,
            starts_at_height,
            nonce,
        );
        let sla = Self {
            sla_id,
            job_kind,
            tier,
            target_compressed_bytes,
            target_verify_micros,
            target_latency_blocks,
            min_savings_bps,
            rebate_bps,
            slash_bps,
            starts_at_height,
            expires_at_height,
            nonce,
            status: PROOF_FEE_MARKET_STATUS_ACTIVE.to_string(),
        };
        sla.validate()?;
        Ok(sla)
    }

    pub fn devnet(
        job_kind: ProofFeeJobKind,
        tier: ProofCompressionSlaTier,
        nonce: u64,
    ) -> ProofFeeMarketResult<Self> {
        let (target_bytes, verify_micros, target_latency, rebate_bps, slash_bps) = match tier {
            ProofCompressionSlaTier::BridgeExit => (64_000, 24_000, 2, 1_500, 5_000),
            ProofCompressionSlaTier::TinyRecursive => (48_000, 18_000, 2, 1_800, 4_000),
            ProofCompressionSlaTier::Fast => (72_000, 22_000, 3, 1_250, 3_500),
            ProofCompressionSlaTier::Emergency => (96_000, 30_000, 1, 2_000, 7_500),
            ProofCompressionSlaTier::PublicGood => (88_000, 28_000, 4, 1_000, 2_500),
            ProofCompressionSlaTier::Standard => (96_000, 32_000, 4, 800, 2_000),
        };
        Self::new(
            job_kind,
            tier,
            target_bytes,
            verify_micros,
            target_latency,
            PROOF_FEE_MARKET_MIN_COMPRESSION_SAVINGS_BPS,
            rebate_bps,
            slash_bps,
            0,
            0,
            nonce,
        )
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PROOF_FEE_MARKET_STATUS_ACTIVE
            && height >= self.starts_at_height
            && (self.expires_at_height == 0 || height <= self.expires_at_height)
    }

    pub fn validate(&self) -> ProofFeeMarketResult<String> {
        ensure_non_empty(&self.sla_id, "compression SLA id")?;
        ensure_positive(self.target_compressed_bytes, "compression SLA target bytes")?;
        ensure_positive(
            self.target_verify_micros,
            "compression SLA target verify micros",
        )?;
        ensure_positive(self.target_latency_blocks, "compression SLA latency blocks")?;
        ensure_bps(self.min_savings_bps, "compression SLA savings bps")?;
        ensure_bps(self.rebate_bps, "compression SLA rebate bps")?;
        ensure_bps(self.slash_bps, "compression SLA slash bps")?;
        if self.expires_at_height != 0 && self.expires_at_height < self.starts_at_height {
            return Err("compression SLA expires before start".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_FEE_MARKET_STATUS_ACTIVE,
                PROOF_FEE_MARKET_STATUS_EXPIRED,
                PROOF_FEE_MARKET_STATUS_PAUSED,
            ],
            "compression SLA status",
        )?;
        let expected_id = proof_compression_sla_id(
            self.job_kind,
            self.tier,
            self.target_compressed_bytes,
            self.target_verify_micros,
            self.target_latency_blocks,
            self.starts_at_height,
            self.nonce,
        );
        if self.sla_id != expected_id {
            return Err("compression SLA id mismatch".to_string());
        }
        Ok(proof_compression_sla_root(self))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_compression_sla",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "sla_id": self.sla_id,
            "job_kind": self.job_kind.as_str(),
            "tier": self.tier.as_str(),
            "target_compressed_bytes": self.target_compressed_bytes,
            "target_verify_micros": self.target_verify_micros,
            "target_latency_blocks": self.target_latency_blocks,
            "min_savings_bps": self.min_savings_bps,
            "rebate_bps": self.rebate_bps,
            "slash_bps": self.slash_bps,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCompressionReceipt {
    pub compression_receipt_id: String,
    pub job_id: String,
    pub proof_receipt_id: String,
    pub sla_id: String,
    pub worker_id: String,
    pub compressed_proof_root: String,
    pub original_proof_bytes: u64,
    pub compressed_bytes: u64,
    pub verify_micros: u64,
    pub completed_at_height: u64,
    pub savings_bps: u64,
    pub latency_bucket: ProofLatencyBucket,
    pub rebate_units: u64,
    pub slash_units: u64,
    pub status: String,
}

impl ProofCompressionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job: &ProofFeeJob,
        proof_receipt: &ProofFeeProofReceipt,
        sla: &ProofCompressionSla,
        worker_id: impl Into<String>,
        compressed_proof_root: impl Into<String>,
        compressed_bytes: u64,
        verify_micros: u64,
        completed_at_height: u64,
    ) -> ProofFeeMarketResult<Self> {
        let worker_id = worker_id.into();
        let compressed_proof_root = compressed_proof_root.into();
        ensure_non_empty(&worker_id, "compression worker id")?;
        ensure_hash_like(&compressed_proof_root, "compressed proof root")?;
        ensure_positive(compressed_bytes, "compressed proof bytes")?;
        ensure_positive(verify_micros, "compressed proof verify micros")?;
        if proof_receipt.job_id != job.job_id {
            return Err("compression receipt proof does not match job".to_string());
        }
        if sla.job_kind != job.workload.job_kind {
            return Err("compression SLA job kind mismatch".to_string());
        }
        let savings_bps = compression_savings_bps(proof_receipt.proof_bytes, compressed_bytes);
        let latency_bucket = classify_latency(
            proof_receipt.completed_at_height,
            completed_at_height,
            sla.target_latency_blocks,
            job.compression_deadline_height,
        );
        let meets_sla = compressed_bytes <= sla.target_compressed_bytes
            && verify_micros <= sla.target_verify_micros
            && savings_bps >= sla.min_savings_bps
            && matches!(
                latency_bucket,
                ProofLatencyBucket::Fast | ProofLatencyBucket::Target
            );
        let rebate_units = if meets_sla {
            mul_bps_round_up(
                job.max_fee_units,
                sla.rebate_bps
                    .saturating_mul(latency_bucket.rebate_weight_bps())
                    / PROOF_FEE_MARKET_MAX_BPS,
            )
        } else {
            0
        };
        let slash_units = if meets_sla {
            0
        } else {
            mul_bps_round_up(job.max_fee_units, sla.slash_bps)
        };
        let status = if meets_sla {
            PROOF_FEE_MARKET_STATUS_COMPRESSED
        } else {
            PROOF_FEE_MARKET_STATUS_CHALLENGED
        }
        .to_string();
        let compression_receipt_id = proof_compression_receipt_id(
            &job.job_id,
            &proof_receipt.receipt_id,
            &sla.sla_id,
            &worker_id,
            &compressed_proof_root,
            completed_at_height,
        );
        let receipt = Self {
            compression_receipt_id,
            job_id: job.job_id.clone(),
            proof_receipt_id: proof_receipt.receipt_id.clone(),
            sla_id: sla.sla_id.clone(),
            worker_id,
            compressed_proof_root,
            original_proof_bytes: proof_receipt.proof_bytes,
            compressed_bytes,
            verify_micros,
            completed_at_height,
            savings_bps,
            latency_bucket,
            rebate_units,
            slash_units,
            status,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn bytes_saved(&self) -> u64 {
        self.original_proof_bytes
            .saturating_sub(self.compressed_bytes)
    }

    pub fn validate(&self) -> ProofFeeMarketResult<String> {
        ensure_non_empty(&self.compression_receipt_id, "compression receipt id")?;
        ensure_non_empty(&self.job_id, "compression receipt job id")?;
        ensure_non_empty(&self.proof_receipt_id, "compression proof receipt id")?;
        ensure_non_empty(&self.sla_id, "compression SLA id")?;
        ensure_non_empty(&self.worker_id, "compression worker id")?;
        ensure_hash_like(&self.compressed_proof_root, "compressed proof root")?;
        ensure_positive(
            self.original_proof_bytes,
            "compression original proof bytes",
        )?;
        ensure_positive(self.compressed_bytes, "compression compressed bytes")?;
        ensure_positive(self.verify_micros, "compression verify micros")?;
        ensure_bps(self.savings_bps, "compression savings bps")?;
        ensure_status(
            &self.status,
            &[
                PROOF_FEE_MARKET_STATUS_COMPRESSED,
                PROOF_FEE_MARKET_STATUS_CHALLENGED,
                PROOF_FEE_MARKET_STATUS_REJECTED,
                PROOF_FEE_MARKET_STATUS_SLASHED,
            ],
            "compression receipt status",
        )?;
        let expected_id = proof_compression_receipt_id(
            &self.job_id,
            &self.proof_receipt_id,
            &self.sla_id,
            &self.worker_id,
            &self.compressed_proof_root,
            self.completed_at_height,
        );
        if self.compression_receipt_id != expected_id {
            return Err("compression receipt id mismatch".to_string());
        }
        Ok(proof_compression_receipt_root(self))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_compression_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "compression_receipt_id": self.compression_receipt_id,
            "job_id": self.job_id,
            "proof_receipt_id": self.proof_receipt_id,
            "sla_id": self.sla_id,
            "worker_id": self.worker_id,
            "compressed_proof_root": self.compressed_proof_root,
            "original_proof_bytes": self.original_proof_bytes,
            "compressed_bytes": self.compressed_bytes,
            "bytes_saved": self.bytes_saved(),
            "verify_micros": self.verify_micros,
            "completed_at_height": self.completed_at_height,
            "savings_bps": self.savings_bps,
            "latency_bucket": self.latency_bucket.as_str(),
            "rebate_units": self.rebate_units,
            "slash_units": self.slash_units,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBatchSponsorship {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub lane: ProofFeeLane,
    pub fee_asset_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_fee_per_job_units: u64,
    pub eligible_job_kinds: Vec<ProofFeeJobKind>,
    pub eligible_job_kind_root: String,
    pub beneficiary_root: String,
    pub starts_at_height: u64,
    pub ends_at_height: u64,
    pub nonce: u64,
    pub status: String,
}

impl ProofBatchSponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: impl Into<String>,
        lane: ProofFeeLane,
        fee_asset_id: impl Into<String>,
        budget_units: u64,
        max_fee_per_job_units: u64,
        eligible_job_kinds: Vec<ProofFeeJobKind>,
        beneficiary_root: impl Into<String>,
        starts_at_height: u64,
        ends_at_height: u64,
        nonce: u64,
    ) -> ProofFeeMarketResult<Self> {
        let sponsor_commitment = sponsor_commitment.into();
        let fee_asset_id = fee_asset_id.into();
        let beneficiary_root = beneficiary_root.into();
        ensure_hash_like(&sponsor_commitment, "sponsor commitment")?;
        ensure_non_empty(&fee_asset_id, "sponsorship fee asset")?;
        ensure_positive(budget_units, "sponsorship budget")?;
        ensure_positive(max_fee_per_job_units, "sponsorship max fee per job")?;
        if max_fee_per_job_units > budget_units {
            return Err("sponsorship max fee per job exceeds budget".to_string());
        }
        if eligible_job_kinds.is_empty() {
            return Err("sponsorship requires eligible job kinds".to_string());
        }
        ensure_hash_like(&beneficiary_root, "sponsorship beneficiary root")?;
        if ends_at_height < starts_at_height {
            return Err("sponsorship ends before it starts".to_string());
        }
        let eligible_job_kind_root = proof_job_kind_set_root(&eligible_job_kinds);
        let sponsorship_id = proof_batch_sponsorship_id(
            &sponsor_commitment,
            lane,
            &fee_asset_id,
            &eligible_job_kind_root,
            &beneficiary_root,
            starts_at_height,
            nonce,
        );
        let sponsorship = Self {
            sponsorship_id,
            sponsor_commitment,
            lane,
            fee_asset_id,
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            max_fee_per_job_units,
            eligible_job_kinds,
            eligible_job_kind_root,
            beneficiary_root,
            starts_at_height,
            ends_at_height,
            nonce,
            status: PROOF_FEE_MARKET_STATUS_ACTIVE.to_string(),
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PROOF_FEE_MARKET_STATUS_ACTIVE
            && height >= self.starts_at_height
            && height <= self.ends_at_height
    }

    pub fn covers(&self, job: &ProofFeeJob, height: u64) -> bool {
        self.is_active_at(height)
            && self.lane == job.lane
            && self.fee_asset_id == job.fee_asset_id
            && job.max_fee_units <= self.max_fee_per_job_units
            && self
                .eligible_job_kinds
                .iter()
                .any(|kind| *kind == job.workload.job_kind)
    }

    pub fn reserve_for_job(&mut self, units: u64) -> ProofFeeMarketResult<()> {
        ensure_positive(units, "sponsorship reserved units")?;
        if units > self.max_fee_per_job_units {
            return Err("sponsorship reservation exceeds per-job max".to_string());
        }
        if self.available_units() < units {
            return Err("sponsorship budget exhausted".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_add(units);
        Ok(())
    }

    pub fn spend_reserved(
        &mut self,
        reserved_units: u64,
        spent_units: u64,
    ) -> ProofFeeMarketResult<()> {
        if reserved_units > self.reserved_units {
            return Err("sponsorship reserved spend exceeds reserved units".to_string());
        }
        if spent_units > reserved_units {
            return Err("sponsorship spend exceeds reservation".to_string());
        }
        self.reserved_units = self.reserved_units.saturating_sub(reserved_units);
        self.spent_units = self.spent_units.saturating_add(spent_units);
        if self.available_units() == 0 {
            self.status = PROOF_FEE_MARKET_STATUS_SETTLED.to_string();
        }
        Ok(())
    }

    pub fn validate(&self) -> ProofFeeMarketResult<String> {
        ensure_non_empty(&self.sponsorship_id, "sponsorship id")?;
        ensure_hash_like(&self.sponsor_commitment, "sponsor commitment")?;
        ensure_non_empty(&self.fee_asset_id, "sponsorship fee asset")?;
        ensure_positive(self.budget_units, "sponsorship budget")?;
        ensure_positive(self.max_fee_per_job_units, "sponsorship max fee per job")?;
        if self.max_fee_per_job_units > self.budget_units {
            return Err("sponsorship max fee per job exceeds budget".to_string());
        }
        if self.reserved_units.saturating_add(self.spent_units) > self.budget_units {
            return Err("sponsorship accounting exceeds budget".to_string());
        }
        if self.eligible_job_kinds.is_empty() {
            return Err("sponsorship requires eligible job kinds".to_string());
        }
        ensure_hash_like(
            &self.eligible_job_kind_root,
            "sponsorship eligible kind root",
        )?;
        ensure_hash_like(&self.beneficiary_root, "sponsorship beneficiary root")?;
        if self.ends_at_height < self.starts_at_height {
            return Err("sponsorship ends before it starts".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_FEE_MARKET_STATUS_ACTIVE,
                PROOF_FEE_MARKET_STATUS_SETTLED,
                PROOF_FEE_MARKET_STATUS_EXPIRED,
                PROOF_FEE_MARKET_STATUS_SLASHED,
                PROOF_FEE_MARKET_STATUS_PAUSED,
            ],
            "sponsorship status",
        )?;
        let expected_kind_root = proof_job_kind_set_root(&self.eligible_job_kinds);
        if self.eligible_job_kind_root != expected_kind_root {
            return Err("sponsorship eligible kind root mismatch".to_string());
        }
        let expected_id = proof_batch_sponsorship_id(
            &self.sponsor_commitment,
            self.lane,
            &self.fee_asset_id,
            &self.eligible_job_kind_root,
            &self.beneficiary_root,
            self.starts_at_height,
            self.nonce,
        );
        if self.sponsorship_id != expected_id {
            return Err("sponsorship id mismatch".to_string());
        }
        Ok(proof_batch_sponsorship_root(self))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_batch_sponsorship",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane": self.lane.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "max_fee_per_job_units": self.max_fee_per_job_units,
            "eligible_job_kinds": self.eligible_job_kinds.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "eligible_job_kind_root": self.eligible_job_kind_root,
            "beneficiary_root": self.beneficiary_root,
            "starts_at_height": self.starts_at_height,
            "ends_at_height": self.ends_at_height,
            "nonce": self.nonce,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFeeRebateSettlement {
    pub rebate_id: String,
    pub job_id: String,
    pub sponsorship_id: String,
    pub beneficiary_commitment: String,
    pub fee_asset_id: String,
    pub gross_fee_units: u64,
    pub sponsor_paid_units: u64,
    pub prover_discount_units: u64,
    pub protocol_fee_units: u64,
    pub latency_rebate_units: u64,
    pub settled_at_height: u64,
    pub status: String,
}

impl ProofFeeRebateSettlement {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job: &ProofFeeJob,
        sponsorship: &ProofBatchSponsorship,
        beneficiary_commitment: impl Into<String>,
        gross_fee_units: u64,
        sponsor_paid_units: u64,
        protocol_fee_bps: u64,
        latency_rebate_units: u64,
        settled_at_height: u64,
    ) -> ProofFeeMarketResult<Self> {
        let beneficiary_commitment = beneficiary_commitment.into();
        ensure_hash_like(&beneficiary_commitment, "rebate beneficiary commitment")?;
        ensure_positive(gross_fee_units, "rebate gross fee units")?;
        ensure_bps(protocol_fee_bps, "rebate protocol fee bps")?;
        if sponsorship.sponsorship_id != job.sponsor_id {
            return Err("rebate sponsorship does not match job".to_string());
        }
        if sponsor_paid_units > gross_fee_units {
            return Err("sponsor paid units exceed gross fee".to_string());
        }
        let protocol_fee_units = mul_bps_round_up(gross_fee_units, protocol_fee_bps);
        let sponsor_paid_units =
            sponsor_paid_units.min(gross_fee_units.saturating_sub(protocol_fee_units));
        let capped_latency_rebate_units = latency_rebate_units.min(
            gross_fee_units
                .saturating_sub(protocol_fee_units)
                .saturating_sub(sponsor_paid_units),
        );
        let prover_discount_units = sponsor_paid_units.saturating_add(capped_latency_rebate_units);
        let rebate_id = proof_fee_rebate_id(
            &job.job_id,
            &sponsorship.sponsorship_id,
            &beneficiary_commitment,
            gross_fee_units,
            sponsor_paid_units,
            settled_at_height,
        );
        let settlement = Self {
            rebate_id,
            job_id: job.job_id.clone(),
            sponsorship_id: sponsorship.sponsorship_id.clone(),
            beneficiary_commitment,
            fee_asset_id: job.fee_asset_id.clone(),
            gross_fee_units,
            sponsor_paid_units,
            prover_discount_units,
            protocol_fee_units,
            latency_rebate_units: capped_latency_rebate_units,
            settled_at_height,
            status: PROOF_FEE_MARKET_STATUS_SETTLED.to_string(),
        };
        settlement.validate()?;
        Ok(settlement)
    }

    pub fn net_prover_fee_units(&self) -> u64 {
        self.gross_fee_units
            .saturating_sub(self.prover_discount_units)
            .saturating_sub(self.protocol_fee_units)
    }

    pub fn validate(&self) -> ProofFeeMarketResult<String> {
        ensure_non_empty(&self.rebate_id, "rebate id")?;
        ensure_non_empty(&self.job_id, "rebate job id")?;
        ensure_non_empty(&self.sponsorship_id, "rebate sponsorship id")?;
        ensure_hash_like(
            &self.beneficiary_commitment,
            "rebate beneficiary commitment",
        )?;
        ensure_non_empty(&self.fee_asset_id, "rebate fee asset")?;
        ensure_positive(self.gross_fee_units, "rebate gross fee units")?;
        if self.sponsor_paid_units > self.gross_fee_units {
            return Err("rebate sponsor paid units exceed gross fee".to_string());
        }
        if self.prover_discount_units > self.gross_fee_units {
            return Err("rebate discount exceeds gross fee".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_FEE_MARKET_STATUS_SETTLED,
                PROOF_FEE_MARKET_STATUS_SLASHED,
            ],
            "rebate status",
        )?;
        let expected_id = proof_fee_rebate_id(
            &self.job_id,
            &self.sponsorship_id,
            &self.beneficiary_commitment,
            self.gross_fee_units,
            self.sponsor_paid_units,
            self.settled_at_height,
        );
        if self.rebate_id != expected_id {
            return Err("rebate id mismatch".to_string());
        }
        Ok(proof_fee_rebate_root(self))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_fee_rebate_settlement",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "rebate_id": self.rebate_id,
            "job_id": self.job_id,
            "sponsorship_id": self.sponsorship_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_units": self.gross_fee_units,
            "sponsor_paid_units": self.sponsor_paid_units,
            "prover_discount_units": self.prover_discount_units,
            "protocol_fee_units": self.protocol_fee_units,
            "latency_rebate_units": self.latency_rebate_units,
            "net_prover_fee_units": self.net_prover_fee_units(),
            "settled_at_height": self.settled_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofSlashingEvidence {
    pub evidence_id: String,
    pub target_kind: String,
    pub target_id: String,
    pub reporter_commitment: String,
    pub slashing_kind: ProofSlashingKind,
    pub evidence_root: String,
    pub stake_root: String,
    pub slash_units: u64,
    pub observed_at_height: u64,
    pub resolved_at_height: u64,
    pub status: String,
}

impl ProofSlashingEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target_kind: impl Into<String>,
        target_id: impl Into<String>,
        reporter_commitment: impl Into<String>,
        slashing_kind: ProofSlashingKind,
        evidence_root: impl Into<String>,
        stake_root: impl Into<String>,
        slash_units: u64,
        observed_at_height: u64,
    ) -> ProofFeeMarketResult<Self> {
        let target_kind = target_kind.into();
        let target_id = target_id.into();
        let reporter_commitment = reporter_commitment.into();
        let evidence_root = evidence_root.into();
        let stake_root = stake_root.into();
        ensure_non_empty(&target_kind, "slashing target kind")?;
        ensure_non_empty(&target_id, "slashing target id")?;
        ensure_hash_like(&reporter_commitment, "slashing reporter commitment")?;
        ensure_hash_like(&evidence_root, "slashing evidence root")?;
        ensure_hash_like(&stake_root, "slashing stake root")?;
        ensure_positive(slash_units, "slashing units")?;
        let evidence_id = proof_slashing_evidence_id(
            &target_kind,
            &target_id,
            slashing_kind,
            &evidence_root,
            observed_at_height,
        );
        let evidence = Self {
            evidence_id,
            target_kind,
            target_id,
            reporter_commitment,
            slashing_kind,
            evidence_root,
            stake_root,
            slash_units,
            observed_at_height,
            resolved_at_height: 0,
            status: PROOF_FEE_MARKET_STATUS_OPEN.to_string(),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn resolve(mut self, resolved_at_height: u64) -> ProofFeeMarketResult<Self> {
        if resolved_at_height < self.observed_at_height {
            return Err("slashing evidence resolves before observation".to_string());
        }
        self.resolved_at_height = resolved_at_height;
        self.status = PROOF_FEE_MARKET_STATUS_SLASHED.to_string();
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> ProofFeeMarketResult<String> {
        ensure_non_empty(&self.evidence_id, "slashing evidence id")?;
        ensure_non_empty(&self.target_kind, "slashing target kind")?;
        ensure_non_empty(&self.target_id, "slashing target id")?;
        ensure_hash_like(&self.reporter_commitment, "slashing reporter commitment")?;
        ensure_hash_like(&self.evidence_root, "slashing evidence root")?;
        ensure_hash_like(&self.stake_root, "slashing stake root")?;
        ensure_positive(self.slash_units, "slashing units")?;
        if self.resolved_at_height != 0 && self.resolved_at_height < self.observed_at_height {
            return Err("slashing evidence resolves before observation".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_FEE_MARKET_STATUS_OPEN,
                PROOF_FEE_MARKET_STATUS_SLASHED,
                PROOF_FEE_MARKET_STATUS_REJECTED,
            ],
            "slashing evidence status",
        )?;
        let expected_id = proof_slashing_evidence_id(
            &self.target_kind,
            &self.target_id,
            self.slashing_kind,
            &self.evidence_root,
            self.observed_at_height,
        );
        if self.evidence_id != expected_id {
            return Err("slashing evidence id mismatch".to_string());
        }
        Ok(proof_slashing_evidence_root(self))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_slashing_evidence",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "reporter_commitment": self.reporter_commitment,
            "slashing_kind": self.slashing_kind.as_str(),
            "evidence_root": self.evidence_root,
            "stake_root": self.stake_root,
            "slash_units": self.slash_units,
            "observed_at_height": self.observed_at_height,
            "resolved_at_height": self.resolved_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFallbackChallenge {
    pub challenge_id: String,
    pub job_id: String,
    pub target_kind: String,
    pub target_id: String,
    pub challenger_commitment: String,
    pub challenge_kind: ProofFallbackChallengeKind,
    pub evidence_root: String,
    pub fallback_circuit_root: String,
    pub bond_units: u64,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub resolved_at_height: u64,
    pub outcome: ProofFallbackChallengeOutcome,
    pub status: String,
}

impl ProofFallbackChallenge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_id: impl Into<String>,
        target_kind: impl Into<String>,
        target_id: impl Into<String>,
        challenger_commitment: impl Into<String>,
        challenge_kind: ProofFallbackChallengeKind,
        evidence_root: impl Into<String>,
        fallback_circuit_root: impl Into<String>,
        bond_units: u64,
        opened_at_height: u64,
        challenge_window_blocks: u64,
    ) -> ProofFeeMarketResult<Self> {
        let job_id = job_id.into();
        let target_kind = target_kind.into();
        let target_id = target_id.into();
        let challenger_commitment = challenger_commitment.into();
        let evidence_root = evidence_root.into();
        let fallback_circuit_root = fallback_circuit_root.into();
        ensure_non_empty(&job_id, "challenge job id")?;
        ensure_non_empty(&target_kind, "challenge target kind")?;
        ensure_non_empty(&target_id, "challenge target id")?;
        ensure_hash_like(&challenger_commitment, "challenge challenger commitment")?;
        ensure_hash_like(&evidence_root, "challenge evidence root")?;
        ensure_hash_like(&fallback_circuit_root, "challenge fallback circuit root")?;
        ensure_positive(bond_units, "challenge bond units")?;
        ensure_positive(challenge_window_blocks, "challenge window blocks")?;
        let deadline_height = opened_at_height.saturating_add(challenge_window_blocks);
        let challenge_id = proof_fallback_challenge_id(
            &job_id,
            &target_kind,
            &target_id,
            challenge_kind,
            &evidence_root,
            opened_at_height,
        );
        let challenge = Self {
            challenge_id,
            job_id,
            target_kind,
            target_id,
            challenger_commitment,
            challenge_kind,
            evidence_root,
            fallback_circuit_root,
            bond_units,
            opened_at_height,
            deadline_height,
            resolved_at_height: 0,
            outcome: ProofFallbackChallengeOutcome::Pending,
            status: PROOF_FEE_MARKET_STATUS_CHALLENGED.to_string(),
        };
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn is_open_at(&self, height: u64) -> bool {
        self.status == PROOF_FEE_MARKET_STATUS_CHALLENGED
            && self.outcome == ProofFallbackChallengeOutcome::Pending
            && height <= self.deadline_height
    }

    pub fn resolve(
        mut self,
        outcome: ProofFallbackChallengeOutcome,
        resolved_at_height: u64,
    ) -> ProofFeeMarketResult<Self> {
        if outcome == ProofFallbackChallengeOutcome::Pending {
            return Err("challenge resolution cannot remain pending".to_string());
        }
        if resolved_at_height < self.opened_at_height {
            return Err("challenge resolves before opening".to_string());
        }
        self.outcome = outcome;
        self.resolved_at_height = resolved_at_height;
        self.status = match outcome {
            ProofFallbackChallengeOutcome::ProverWins => PROOF_FEE_MARKET_STATUS_SETTLED,
            ProofFallbackChallengeOutcome::ChallengerWins => PROOF_FEE_MARKET_STATUS_SLASHED,
            ProofFallbackChallengeOutcome::Escalated => PROOF_FEE_MARKET_STATUS_ACTIVE,
            ProofFallbackChallengeOutcome::Expired => PROOF_FEE_MARKET_STATUS_EXPIRED,
            ProofFallbackChallengeOutcome::Pending => PROOF_FEE_MARKET_STATUS_CHALLENGED,
        }
        .to_string();
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> ProofFeeMarketResult<String> {
        ensure_non_empty(&self.challenge_id, "challenge id")?;
        ensure_non_empty(&self.job_id, "challenge job id")?;
        ensure_non_empty(&self.target_kind, "challenge target kind")?;
        ensure_non_empty(&self.target_id, "challenge target id")?;
        ensure_hash_like(
            &self.challenger_commitment,
            "challenge challenger commitment",
        )?;
        ensure_hash_like(&self.evidence_root, "challenge evidence root")?;
        ensure_hash_like(
            &self.fallback_circuit_root,
            "challenge fallback circuit root",
        )?;
        ensure_positive(self.bond_units, "challenge bond units")?;
        if self.deadline_height < self.opened_at_height {
            return Err("challenge deadline precedes opening".to_string());
        }
        if self.resolved_at_height != 0 && self.resolved_at_height < self.opened_at_height {
            return Err("challenge resolves before opening".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PROOF_FEE_MARKET_STATUS_CHALLENGED,
                PROOF_FEE_MARKET_STATUS_SETTLED,
                PROOF_FEE_MARKET_STATUS_SLASHED,
                PROOF_FEE_MARKET_STATUS_ACTIVE,
                PROOF_FEE_MARKET_STATUS_EXPIRED,
            ],
            "challenge status",
        )?;
        let expected_id = proof_fallback_challenge_id(
            &self.job_id,
            &self.target_kind,
            &self.target_id,
            self.challenge_kind,
            &self.evidence_root,
            self.opened_at_height,
        );
        if self.challenge_id != expected_id {
            return Err("fallback challenge id mismatch".to_string());
        }
        Ok(proof_fallback_challenge_root(self))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_fallback_challenge",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "job_id": self.job_id,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "challenger_commitment": self.challenger_commitment,
            "challenge_kind": self.challenge_kind.as_str(),
            "evidence_root": self.evidence_root,
            "fallback_circuit_root": self.fallback_circuit_root,
            "bond_units": self.bond_units,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "resolved_at_height": self.resolved_at_height,
            "outcome": self.outcome.as_str(),
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLatencyObservation {
    pub observation_id: String,
    pub job_id: String,
    pub proof_latency_blocks: u64,
    pub compression_latency_blocks: u64,
    pub latency_bucket: ProofLatencyBucket,
    pub fee_delta_units: u64,
    pub observed_at_height: u64,
    pub status: String,
}

impl ProofLatencyObservation {
    pub fn new(
        job: &ProofFeeJob,
        proof_receipt: &ProofFeeProofReceipt,
        compression_receipt: &ProofCompressionReceipt,
        observed_at_height: u64,
    ) -> ProofFeeMarketResult<Self> {
        if proof_receipt.job_id != job.job_id || compression_receipt.job_id != job.job_id {
            return Err("latency observation job mismatch".to_string());
        }
        let proof_latency_blocks = proof_receipt
            .completed_at_height
            .saturating_sub(job.posted_at_height);
        let compression_latency_blocks = compression_receipt
            .completed_at_height
            .saturating_sub(proof_receipt.completed_at_height);
        let latency_bucket = if matches!(
            compression_receipt.latency_bucket,
            ProofLatencyBucket::Slashed
        ) {
            ProofLatencyBucket::Slashed
        } else if matches!(proof_receipt.latency_bucket, ProofLatencyBucket::Expired)
            || matches!(
                compression_receipt.latency_bucket,
                ProofLatencyBucket::Expired
            )
        {
            ProofLatencyBucket::Expired
        } else if matches!(proof_receipt.latency_bucket, ProofLatencyBucket::Delayed)
            || matches!(
                compression_receipt.latency_bucket,
                ProofLatencyBucket::Delayed
            )
        {
            ProofLatencyBucket::Delayed
        } else if matches!(proof_receipt.latency_bucket, ProofLatencyBucket::Fast)
            && matches!(compression_receipt.latency_bucket, ProofLatencyBucket::Fast)
        {
            ProofLatencyBucket::Fast
        } else {
            ProofLatencyBucket::Target
        };
        let fee_delta_units = compression_receipt
            .rebate_units
            .saturating_sub(compression_receipt.slash_units);
        let observation_id = proof_latency_observation_id(
            &job.job_id,
            proof_latency_blocks,
            compression_latency_blocks,
            latency_bucket,
            observed_at_height,
        );
        let observation = Self {
            observation_id,
            job_id: job.job_id.clone(),
            proof_latency_blocks,
            compression_latency_blocks,
            latency_bucket,
            fee_delta_units,
            observed_at_height,
            status: PROOF_FEE_MARKET_STATUS_SEALED.to_string(),
        };
        observation.validate()?;
        Ok(observation)
    }

    pub fn validate(&self) -> ProofFeeMarketResult<String> {
        ensure_non_empty(&self.observation_id, "latency observation id")?;
        ensure_non_empty(&self.job_id, "latency observation job id")?;
        ensure_status(
            &self.status,
            &[PROOF_FEE_MARKET_STATUS_SEALED],
            "latency observation status",
        )?;
        let expected_id = proof_latency_observation_id(
            &self.job_id,
            self.proof_latency_blocks,
            self.compression_latency_blocks,
            self.latency_bucket,
            self.observed_at_height,
        );
        if self.observation_id != expected_id {
            return Err("latency observation id mismatch".to_string());
        }
        Ok(proof_latency_observation_root(self))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_latency_observation",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "observation_id": self.observation_id,
            "job_id": self.job_id,
            "proof_latency_blocks": self.proof_latency_blocks,
            "compression_latency_blocks": self.compression_latency_blocks,
            "latency_bucket": self.latency_bucket.as_str(),
            "fee_delta_units": self.fee_delta_units,
            "observed_at_height": self.observed_at_height,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFeeMarketDevnetFixture {
    pub fixture_id: String,
    pub label: String,
    pub height: u64,
    pub seed_root: String,
    pub roots_root: String,
    pub state_root: String,
    pub status: String,
}

impl ProofFeeMarketDevnetFixture {
    pub fn new(
        label: impl Into<String>,
        height: u64,
        seed_root: impl Into<String>,
        roots_root: impl Into<String>,
        state_root: impl Into<String>,
    ) -> ProofFeeMarketResult<Self> {
        let label = label.into();
        let seed_root = seed_root.into();
        let roots_root = roots_root.into();
        let state_root = state_root.into();
        ensure_non_empty(&label, "devnet fixture label")?;
        ensure_hash_like(&seed_root, "devnet fixture seed root")?;
        ensure_hash_like(&roots_root, "devnet fixture roots root")?;
        ensure_hash_like(&state_root, "devnet fixture state root")?;
        let fixture_id =
            proof_fee_market_devnet_fixture_id(&label, height, &seed_root, &state_root);
        let fixture = Self {
            fixture_id,
            label,
            height,
            seed_root,
            roots_root,
            state_root,
            status: PROOF_FEE_MARKET_STATUS_SEALED.to_string(),
        };
        fixture.validate()?;
        Ok(fixture)
    }

    pub fn validate(&self) -> ProofFeeMarketResult<String> {
        ensure_non_empty(&self.fixture_id, "devnet fixture id")?;
        ensure_non_empty(&self.label, "devnet fixture label")?;
        ensure_hash_like(&self.seed_root, "devnet fixture seed root")?;
        ensure_hash_like(&self.roots_root, "devnet fixture roots root")?;
        ensure_hash_like(&self.state_root, "devnet fixture state root")?;
        ensure_status(
            &self.status,
            &[PROOF_FEE_MARKET_STATUS_SEALED],
            "devnet fixture status",
        )?;
        let expected_id = proof_fee_market_devnet_fixture_id(
            &self.label,
            self.height,
            &self.seed_root,
            &self.state_root,
        );
        if self.fixture_id != expected_id {
            return Err("devnet fixture id mismatch".to_string());
        }
        Ok(proof_fee_market_devnet_fixture_root(self))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_fee_market_devnet_fixture",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "fixture_id": self.fixture_id,
            "label": self.label,
            "height": self.height,
            "seed_root": self.seed_root,
            "roots_root": self.roots_root,
            "state_root": self.state_root,
            "status": self.status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFeeMarketRoots {
    pub config_root: String,
    pub active_sla_root: String,
    pub active_committee_root: String,
    pub job_root: String,
    pub bid_root: String,
    pub verifier_member_root: String,
    pub verifier_committee_root: String,
    pub proof_receipt_root: String,
    pub verification_receipt_root: String,
    pub compression_sla_root: String,
    pub compression_receipt_root: String,
    pub fee_rebate_root: String,
    pub slashing_evidence_root: String,
    pub fallback_challenge_root: String,
    pub batch_sponsorship_root: String,
    pub latency_observation_root: String,
    pub devnet_fixture_root: String,
    pub state_root: String,
}

impl ProofFeeMarketRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_fee_market_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "active_sla_root": self.active_sla_root,
            "active_committee_root": self.active_committee_root,
            "job_root": self.job_root,
            "bid_root": self.bid_root,
            "verifier_member_root": self.verifier_member_root,
            "verifier_committee_root": self.verifier_committee_root,
            "proof_receipt_root": self.proof_receipt_root,
            "verification_receipt_root": self.verification_receipt_root,
            "compression_sla_root": self.compression_sla_root,
            "compression_receipt_root": self.compression_receipt_root,
            "fee_rebate_root": self.fee_rebate_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "fallback_challenge_root": self.fallback_challenge_root,
            "batch_sponsorship_root": self.batch_sponsorship_root,
            "latency_observation_root": self.latency_observation_root,
            "devnet_fixture_root": self.devnet_fixture_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFeeMarketCounters {
    pub jobs: u64,
    pub open_jobs: u64,
    pub assigned_jobs: u64,
    pub proved_jobs: u64,
    pub verified_jobs: u64,
    pub compressed_jobs: u64,
    pub challenged_jobs: u64,
    pub settled_jobs: u64,
    pub expired_jobs: u64,
    pub rejected_jobs: u64,
    pub slashed_jobs: u64,
    pub bids: u64,
    pub accepted_bids: u64,
    pub verifier_members: u64,
    pub verifier_committees: u64,
    pub proof_receipts: u64,
    pub verification_receipts: u64,
    pub compression_slas: u64,
    pub compression_receipts: u64,
    pub fee_rebates: u64,
    pub slashing_evidence: u64,
    pub fallback_challenges: u64,
    pub open_challenges: u64,
    pub batch_sponsorships: u64,
    pub latency_observations: u64,
    pub latency_fast: u64,
    pub latency_target: u64,
    pub latency_delayed: u64,
    pub latency_expired: u64,
    pub latency_slashed: u64,
    pub total_max_fee_units: u64,
    pub total_bid_fee_units: u64,
    pub total_protocol_fee_units: u64,
    pub total_rebate_units: u64,
    pub total_slash_units: u64,
    pub total_sponsor_available_units: u64,
    pub total_bytes_saved: u64,
}

impl ProofFeeMarketCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "proof_fee_market_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "jobs": self.jobs,
            "open_jobs": self.open_jobs,
            "assigned_jobs": self.assigned_jobs,
            "proved_jobs": self.proved_jobs,
            "verified_jobs": self.verified_jobs,
            "compressed_jobs": self.compressed_jobs,
            "challenged_jobs": self.challenged_jobs,
            "settled_jobs": self.settled_jobs,
            "expired_jobs": self.expired_jobs,
            "rejected_jobs": self.rejected_jobs,
            "slashed_jobs": self.slashed_jobs,
            "bids": self.bids,
            "accepted_bids": self.accepted_bids,
            "verifier_members": self.verifier_members,
            "verifier_committees": self.verifier_committees,
            "proof_receipts": self.proof_receipts,
            "verification_receipts": self.verification_receipts,
            "compression_slas": self.compression_slas,
            "compression_receipts": self.compression_receipts,
            "fee_rebates": self.fee_rebates,
            "slashing_evidence": self.slashing_evidence,
            "fallback_challenges": self.fallback_challenges,
            "open_challenges": self.open_challenges,
            "batch_sponsorships": self.batch_sponsorships,
            "latency_observations": self.latency_observations,
            "latency_fast": self.latency_fast,
            "latency_target": self.latency_target,
            "latency_delayed": self.latency_delayed,
            "latency_expired": self.latency_expired,
            "latency_slashed": self.latency_slashed,
            "total_max_fee_units": self.total_max_fee_units,
            "total_bid_fee_units": self.total_bid_fee_units,
            "total_protocol_fee_units": self.total_protocol_fee_units,
            "total_rebate_units": self.total_rebate_units,
            "total_slash_units": self.total_slash_units,
            "total_sponsor_available_units": self.total_sponsor_available_units,
            "total_bytes_saved": self.total_bytes_saved,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFeeMarketState {
    pub height: u64,
    pub market_label: String,
    pub config: ProofFeeMarketConfig,
    pub active_committee_id: String,
    pub active_sla_ids: BTreeMap<String, String>,
    pub jobs: BTreeMap<String, ProofFeeJob>,
    pub bids: BTreeMap<String, ProofFeeProverBid>,
    pub verifier_members: BTreeMap<String, ProofVerifierMember>,
    pub verifier_committees: BTreeMap<String, ProofVerifierCommittee>,
    pub proof_receipts: BTreeMap<String, ProofFeeProofReceipt>,
    pub verification_receipts: BTreeMap<String, ProofCommitteeVerificationReceipt>,
    pub compression_slas: BTreeMap<String, ProofCompressionSla>,
    pub compression_receipts: BTreeMap<String, ProofCompressionReceipt>,
    pub fee_rebates: BTreeMap<String, ProofFeeRebateSettlement>,
    pub slashing_evidence: BTreeMap<String, ProofSlashingEvidence>,
    pub fallback_challenges: BTreeMap<String, ProofFallbackChallenge>,
    pub batch_sponsorships: BTreeMap<String, ProofBatchSponsorship>,
    pub latency_observations: BTreeMap<String, ProofLatencyObservation>,
    pub devnet_fixtures: BTreeMap<String, ProofFeeMarketDevnetFixture>,
}

impl ProofFeeMarketState {
    pub fn new(
        market_label: impl Into<String>,
        config: ProofFeeMarketConfig,
    ) -> ProofFeeMarketResult<Self> {
        config.validate()?;
        let market_label = market_label.into();
        ensure_non_empty(&market_label, "proof fee market label")?;
        Ok(Self {
            height: 0,
            market_label,
            config,
            active_committee_id: String::new(),
            active_sla_ids: BTreeMap::new(),
            jobs: BTreeMap::new(),
            bids: BTreeMap::new(),
            verifier_members: BTreeMap::new(),
            verifier_committees: BTreeMap::new(),
            proof_receipts: BTreeMap::new(),
            verification_receipts: BTreeMap::new(),
            compression_slas: BTreeMap::new(),
            compression_receipts: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            fallback_challenges: BTreeMap::new(),
            batch_sponsorships: BTreeMap::new(),
            latency_observations: BTreeMap::new(),
            devnet_fixtures: BTreeMap::new(),
        })
    }

    pub fn devnet() -> ProofFeeMarketResult<Self> {
        let mut state = Self::new("devnet-proof-fee-market", ProofFeeMarketConfig::default())?;
        state.set_height(80);

        let sla_specs = vec![
            (
                ProofFeeJobKind::RollupValidity,
                ProofCompressionSlaTier::Fast,
            ),
            (
                ProofFeeJobKind::MoneroBridge,
                ProofCompressionSlaTier::BridgeExit,
            ),
            (
                ProofFeeJobKind::PrivateContract,
                ProofCompressionSlaTier::Standard,
            ),
            (
                ProofFeeJobKind::FeeRebateAccounting,
                ProofCompressionSlaTier::PublicGood,
            ),
            (
                ProofFeeJobKind::RecursiveAggregation,
                ProofCompressionSlaTier::TinyRecursive,
            ),
            (
                ProofFeeJobKind::WatchtowerFallback,
                ProofCompressionSlaTier::Emergency,
            ),
        ];
        for (index, (job_kind, tier)) in sla_specs.into_iter().enumerate() {
            let sla = ProofCompressionSla::devnet(job_kind, tier, index as u64)?;
            let sla_id = state.insert_compression_sla(sla)?;
            state.activate_sla(&sla_id)?;
        }

        let members = vec![
            devnet_verifier_member("devnet-proof-scheduler", ProofVerifierRole::Scheduler, 25)?,
            devnet_verifier_member("devnet-pq-verifier-a", ProofVerifierRole::PqVerifier, 30)?,
            devnet_verifier_member(
                "devnet-recursion-auditor",
                ProofVerifierRole::RecursionAuditor,
                20,
            )?,
            devnet_verifier_member(
                "devnet-compression-auditor",
                ProofVerifierRole::CompressionAuditor,
                20,
            )?,
            devnet_verifier_member("devnet-watchtower", ProofVerifierRole::Watchtower, 15)?,
            devnet_verifier_member(
                "devnet-sponsor-auditor",
                ProofVerifierRole::SponsorAuditor,
                10,
            )?,
        ];
        for member in &members {
            state.insert_verifier_member(member.clone())?;
        }
        let committee = ProofVerifierCommittee::from_members(
            0,
            ProofVerifierCommitteePolicy::WeightedThreshold,
            &members,
            6_700,
            state.config.default_challenge_window_blocks,
            64,
            0,
        )?;
        let committee_id = state.insert_verifier_committee(committee)?;
        state.activate_committee(&committee_id)?;

        let bridge_sponsorship = ProofBatchSponsorship::new(
            proof_fee_market_deterministic_commitment("devnet-bridge-proof-sponsor"),
            ProofFeeLane::MoneroBridge,
            state.config.default_fee_asset_id.clone(),
            250_000,
            70_000,
            vec![
                ProofFeeJobKind::MoneroBridge,
                ProofFeeJobKind::RecursiveAggregation,
            ],
            proof_fee_market_deterministic_root("devnet-bridge-beneficiary-root"),
            64,
            512,
            1,
        )?;
        let public_good_sponsorship = ProofBatchSponsorship::new(
            proof_fee_market_deterministic_commitment("devnet-public-good-proof-sponsor"),
            ProofFeeLane::SponsoredPublicGood,
            state.config.default_fee_asset_id.clone(),
            180_000,
            55_000,
            vec![
                ProofFeeJobKind::RollupValidity,
                ProofFeeJobKind::FeeRebateAccounting,
                ProofFeeJobKind::ProofCompression,
            ],
            proof_fee_market_deterministic_root("devnet-public-good-beneficiary-root"),
            64,
            512,
            2,
        )?;
        let bridge_sponsorship_id = state.insert_batch_sponsorship(bridge_sponsorship)?;
        let public_good_sponsorship_id = state.insert_batch_sponsorship(public_good_sponsorship)?;

        let job_specs = vec![
            (
                ProofFeeLane::MoneroBridge,
                ProofFeeJobKind::MoneroBridge,
                "devnet-bridge-exit-batch-0",
                bridge_sponsorship_id.clone(),
                68_000,
                28_000,
            ),
            (
                ProofFeeLane::SponsoredPublicGood,
                ProofFeeJobKind::RollupValidity,
                "devnet-rollup-state-batch-80",
                public_good_sponsorship_id.clone(),
                52_000,
                20_000,
            ),
            (
                ProofFeeLane::SponsoredPublicGood,
                ProofFeeJobKind::FeeRebateAccounting,
                "devnet-rebate-proof-epoch-0",
                public_good_sponsorship_id,
                34_000,
                12_000,
            ),
            (
                ProofFeeLane::RecursiveBatch,
                ProofFeeJobKind::RecursiveAggregation,
                "devnet-recursive-proof-pack-0",
                String::new(),
                44_000,
                16_000,
            ),
        ];

        let mut job_ids = Vec::new();
        for (index, (lane, kind, label, sponsor_id, max_fee, reserve_fee)) in
            job_specs.into_iter().enumerate()
        {
            let workload = ProofWorkloadEnvelope::devnet(kind, label, index as u64)?;
            let job = ProofFeeJob::new(
                proof_fee_market_deterministic_commitment(&format!("{label}:requester")),
                lane,
                workload,
                state.config.default_fee_asset_id.clone(),
                max_fee,
                reserve_fee,
                sponsor_id,
                proof_fee_market_deterministic_root(&format!("{label}:rebate-policy")),
                80,
                state.config.default_bid_window_blocks,
                state.config.default_proof_sla_blocks + index as u64,
                state.config.default_compression_sla_blocks,
                state.config.default_challenge_window_blocks,
                index as u64,
            )?;
            let job_id = state.open_job(job)?;
            job_ids.push(job_id);
        }

        state.set_height(81);
        for (index, job_id) in job_ids.clone().into_iter().enumerate() {
            state.place_bid(
                &job_id,
                format!("devnet-prover-{}", index % 3),
                if index % 2 == 0 {
                    ProofWorkerClass::Gpu
                } else {
                    ProofWorkerClass::Cpu
                },
                28_000 + index as u64 * 2_500,
                4 + index as u64,
                2,
                9_000 + index as u64 * 1_000,
                proof_fee_market_deterministic_root(&format!("devnet-prover-pq-key-{index}")),
                proof_fee_market_deterministic_root(&format!("devnet-prover-capacity-{index}")),
            )?;
            state.place_bid(
                &job_id,
                format!("devnet-alt-prover-{}", index % 2),
                ProofWorkerClass::Cpu,
                30_000 + index as u64 * 2_000,
                6 + index as u64,
                3,
                8_500 + index as u64 * 1_000,
                proof_fee_market_deterministic_root(&format!("devnet-alt-pq-key-{index}")),
                proof_fee_market_deterministic_root(&format!("devnet-alt-capacity-{index}")),
            )?;
        }

        state.set_height(84);
        let mut proof_receipt_ids = Vec::new();
        for (index, job_id) in job_ids.clone().into_iter().enumerate() {
            let winner = state.settle_job(&job_id)?;
            let proof_receipt = state.record_proof_receipt(
                &job_id,
                &winner.bid_id,
                proof_fee_market_deterministic_root(&format!("devnet-proof-root-{index}")),
                proof_fee_market_deterministic_root(&format!("devnet-public-output-{index}")),
                proof_fee_market_deterministic_root(&format!("devnet-vk-root-{index}")),
                120_000 + index as u64 * 14_000,
                88 + index as u64,
            )?;
            proof_receipt_ids.push(proof_receipt.receipt_id);
        }

        state.set_height(90);
        for (index, receipt_id) in proof_receipt_ids.clone().into_iter().enumerate() {
            state.verify_proof(
                &receipt_id,
                &committee_id,
                ProofVerificationOutcome::Accepted,
                85,
                5,
                100,
                proof_fee_market_deterministic_root(&format!("devnet-verifier-responses-{index}")),
                90 + index as u64,
                91 + index as u64,
            )?;
        }

        for (index, job_id) in job_ids.clone().into_iter().enumerate() {
            let job_kind = state
                .jobs
                .get(&job_id)
                .map(|job| job.workload.job_kind)
                .ok_or_else(|| "devnet job missing for SLA".to_string())?;
            let sla_id = state
                .active_sla_ids
                .get(job_kind.as_str())
                .cloned()
                .ok_or_else(|| "devnet active SLA missing".to_string())?;
            let proof_receipt_id = state
                .jobs
                .get(&job_id)
                .map(|job| job.proof_receipt_id.clone())
                .ok_or_else(|| "devnet job missing for compression".to_string())?;
            state.record_compression_receipt(
                &job_id,
                &proof_receipt_id,
                &sla_id,
                format!("devnet-compressor-{index}"),
                proof_fee_market_deterministic_root(&format!("devnet-compressed-proof-{index}")),
                54_000 + index as u64 * 2_000,
                18_000 + index as u64 * 1_500,
                90 + index as u64,
            )?;
        }

        for (index, job_id) in job_ids.clone().into_iter().enumerate() {
            let sponsor_id = state
                .jobs
                .get(&job_id)
                .map(|job| job.sponsor_id.clone())
                .unwrap_or_default();
            if !sponsor_id.is_empty() {
                state.settle_fee_rebate(
                    &job_id,
                    &sponsor_id,
                    proof_fee_market_deterministic_commitment(&format!(
                        "devnet-beneficiary-{index}"
                    )),
                    96 + index as u64,
                )?;
            }
        }

        let challenged_job_id = job_ids
            .last()
            .cloned()
            .ok_or_else(|| "devnet challenge job missing".to_string())?;
        let challenge = state.open_fallback_challenge(
            &challenged_job_id,
            "compression_receipt",
            state
                .jobs
                .get(&challenged_job_id)
                .map(|job| job.compression_receipt_id.clone())
                .ok_or_else(|| "devnet challenge target missing".to_string())?,
            proof_fee_market_deterministic_commitment("devnet-watchtower-challenger"),
            ProofFallbackChallengeKind::CompressionRatioMiss,
            proof_fee_market_deterministic_root("devnet-compression-challenge-evidence"),
            proof_fee_market_deterministic_root("devnet-fallback-circuit"),
            2_500,
        )?;
        let slashing = ProofSlashingEvidence::new(
            "compression_receipt",
            challenge.target_id.clone(),
            proof_fee_market_deterministic_commitment("devnet-watchtower-reporter"),
            ProofSlashingKind::CompressionMismatch,
            proof_fee_market_deterministic_root("devnet-slashing-evidence"),
            proof_fee_market_deterministic_root("devnet-slashed-stake"),
            3_000,
            97,
        )?
        .resolve(98)?;
        state.submit_slashing_evidence(slashing)?;
        state.resolve_fallback_challenge(
            &challenge.challenge_id,
            ProofFallbackChallengeOutcome::ChallengerWins,
            98,
        )?;

        let roots_root = proof_fee_market_payload_root(
            "PROOF-FEE-MARKET-DEVNET-ROOTS",
            &state.roots().public_record(),
        );
        let fixture = ProofFeeMarketDevnetFixture::new(
            "proof-fee-market-devnet",
            state.height,
            proof_fee_market_deterministic_root("proof-fee-market-devnet-seed"),
            roots_root,
            state.state_root(),
        )?;
        state.insert_devnet_fixture(fixture)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for sla in self.compression_slas.values_mut() {
            if sla.expires_at_height != 0
                && height > sla.expires_at_height
                && sla.status == PROOF_FEE_MARKET_STATUS_ACTIVE
            {
                sla.status = PROOF_FEE_MARKET_STATUS_EXPIRED.to_string();
            }
        }
        for committee in self.verifier_committees.values_mut() {
            if committee.expires_at_height != 0
                && height > committee.expires_at_height
                && committee.status == PROOF_FEE_MARKET_STATUS_ACTIVE
            {
                committee.status = PROOF_FEE_MARKET_STATUS_EXPIRED.to_string();
            }
        }
        for member in self.verifier_members.values_mut() {
            if member.expires_at_height != 0
                && height > member.expires_at_height
                && member.status == PROOF_FEE_MARKET_STATUS_ACTIVE
            {
                member.status = PROOF_FEE_MARKET_STATUS_EXPIRED.to_string();
            }
        }
        for sponsorship in self.batch_sponsorships.values_mut() {
            if height > sponsorship.ends_at_height
                && sponsorship.status == PROOF_FEE_MARKET_STATUS_ACTIVE
            {
                sponsorship.status = PROOF_FEE_MARKET_STATUS_EXPIRED.to_string();
            }
        }
        for job in self.jobs.values_mut() {
            if job.is_terminal() {
                continue;
            }
            if height > job.challenge_deadline_height
                && job.status == PROOF_FEE_MARKET_STATUS_CHALLENGED
            {
                job.status = PROOF_FEE_MARKET_STATUS_EXPIRED.to_string();
            } else if height > job.compression_deadline_height
                && matches!(
                    job.status.as_str(),
                    PROOF_FEE_MARKET_STATUS_PROVED | PROOF_FEE_MARKET_STATUS_VERIFIED
                )
            {
                job.status = PROOF_FEE_MARKET_STATUS_EXPIRED.to_string();
            } else if height > job.proof_deadline_height
                && matches!(
                    job.status.as_str(),
                    PROOF_FEE_MARKET_STATUS_OPEN | PROOF_FEE_MARKET_STATUS_ASSIGNED
                )
            {
                job.status = PROOF_FEE_MARKET_STATUS_EXPIRED.to_string();
            }
        }
        for challenge in self.fallback_challenges.values_mut() {
            if height > challenge.deadline_height
                && challenge.status == PROOF_FEE_MARKET_STATUS_CHALLENGED
                && challenge.outcome == ProofFallbackChallengeOutcome::Pending
            {
                challenge.status = PROOF_FEE_MARKET_STATUS_EXPIRED.to_string();
                challenge.outcome = ProofFallbackChallengeOutcome::Expired;
                challenge.resolved_at_height = height;
            }
        }
    }

    pub fn insert_compression_sla(
        &mut self,
        sla: ProofCompressionSla,
    ) -> ProofFeeMarketResult<String> {
        sla.validate()?;
        insert_unique_record(
            &mut self.compression_slas,
            sla.sla_id.clone(),
            sla,
            "compression SLA",
        )
    }

    pub fn activate_sla(&mut self, sla_id: &str) -> ProofFeeMarketResult<ProofCompressionSla> {
        let sla = self
            .compression_slas
            .get(sla_id)
            .cloned()
            .ok_or_else(|| "unknown compression SLA".to_string())?;
        if !sla.is_active_at(self.height) {
            return Err("compression SLA is not active".to_string());
        }
        self.active_sla_ids
            .insert(sla.job_kind.as_str().to_string(), sla_id.to_string());
        Ok(sla)
    }

    pub fn insert_verifier_member(
        &mut self,
        member: ProofVerifierMember,
    ) -> ProofFeeMarketResult<String> {
        member.validate()?;
        insert_unique_record(
            &mut self.verifier_members,
            member.member_id.clone(),
            member,
            "verifier member",
        )
    }

    pub fn insert_verifier_committee(
        &mut self,
        committee: ProofVerifierCommittee,
    ) -> ProofFeeMarketResult<String> {
        committee.validate()?;
        for member_id in &committee.member_ids {
            if !self.verifier_members.contains_key(member_id) {
                return Err("verifier committee references unknown member".to_string());
            }
        }
        insert_unique_record(
            &mut self.verifier_committees,
            committee.committee_id.clone(),
            committee,
            "verifier committee",
        )
    }

    pub fn activate_committee(
        &mut self,
        committee_id: &str,
    ) -> ProofFeeMarketResult<ProofVerifierCommittee> {
        let committee = self
            .verifier_committees
            .get(committee_id)
            .cloned()
            .ok_or_else(|| "unknown verifier committee".to_string())?;
        if !committee.is_active_at(self.height) {
            return Err("verifier committee is not active".to_string());
        }
        self.active_committee_id = committee_id.to_string();
        Ok(committee)
    }

    pub fn insert_batch_sponsorship(
        &mut self,
        sponsorship: ProofBatchSponsorship,
    ) -> ProofFeeMarketResult<String> {
        sponsorship.validate()?;
        insert_unique_record(
            &mut self.batch_sponsorships,
            sponsorship.sponsorship_id.clone(),
            sponsorship,
            "batch sponsorship",
        )
    }

    pub fn open_job(&mut self, job: ProofFeeJob) -> ProofFeeMarketResult<String> {
        job.validate()?;
        if !job.sponsor_id.is_empty() {
            let sponsorship = self
                .batch_sponsorships
                .get_mut(&job.sponsor_id)
                .ok_or_else(|| "job references unknown sponsorship".to_string())?;
            if !sponsorship.covers(&job, self.height) {
                return Err("sponsorship does not cover proof fee job".to_string());
            }
            sponsorship.reserve_for_job(job.max_fee_units)?;
        }
        insert_unique_record(&mut self.jobs, job.job_id.clone(), job, "proof fee job")
    }

    #[allow(clippy::too_many_arguments)]
    pub fn place_bid(
        &mut self,
        job_id: &str,
        prover_id: impl Into<String>,
        worker_class: ProofWorkerClass,
        bid_fee_units: u64,
        promised_proof_latency_blocks: u64,
        promised_compression_latency_blocks: u64,
        collateral_units: u64,
        pq_public_key_root: impl Into<String>,
        capacity_commitment_root: impl Into<String>,
    ) -> ProofFeeMarketResult<ProofFeeProverBid> {
        let job = self
            .jobs
            .get(job_id)
            .cloned()
            .ok_or_else(|| "unknown proof fee job".to_string())?;
        if !job.accepts_bids_at(self.height) {
            return Err("proof fee job is not accepting bids".to_string());
        }
        let required_collateral =
            required_bid_collateral_units(bid_fee_units, self.config.min_bid_collateral_bps);
        if collateral_units < required_collateral {
            return Err("bid collateral is below configured minimum".to_string());
        }
        let bid = ProofFeeProverBid::new(
            &job,
            prover_id,
            worker_class,
            bid_fee_units,
            promised_proof_latency_blocks,
            promised_compression_latency_blocks,
            collateral_units,
            pq_public_key_root,
            capacity_commitment_root,
            self.height,
        )?;
        self.bids.insert(bid.bid_id.clone(), bid.clone());
        Ok(bid)
    }

    pub fn settle_job(&mut self, job_id: &str) -> ProofFeeMarketResult<ProofFeeProverBid> {
        let job = self
            .jobs
            .get(job_id)
            .cloned()
            .ok_or_else(|| "unknown proof fee job".to_string())?;
        if job.status != PROOF_FEE_MARKET_STATUS_OPEN {
            return Err("proof fee job is not open".to_string());
        }
        if self.height <= job.bid_deadline_height {
            return Err("proof fee job bid window is still open".to_string());
        }
        let mut candidates = self
            .bids
            .values()
            .filter(|bid| bid.job_id == job.job_id && bid.status == PROOF_FEE_MARKET_STATUS_OPEN)
            .cloned()
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Err("proof fee job has no open bids".to_string());
        }
        candidates.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| left.bid_fee_units.cmp(&right.bid_fee_units))
                .then_with(|| {
                    left.promised_proof_latency_blocks
                        .cmp(&right.promised_proof_latency_blocks)
                })
                .then_with(|| left.bid_id.cmp(&right.bid_id))
        });
        let winner = candidates[0].clone();
        for candidate in candidates {
            if let Some(bid) = self.bids.get_mut(&candidate.bid_id) {
                bid.status = if candidate.bid_id == winner.bid_id {
                    PROOF_FEE_MARKET_STATUS_ACCEPTED.to_string()
                } else {
                    PROOF_FEE_MARKET_STATUS_REJECTED.to_string()
                };
            }
        }
        if let Some(stored_job) = self.jobs.get_mut(job_id) {
            stored_job.status = PROOF_FEE_MARKET_STATUS_ASSIGNED.to_string();
            stored_job.assigned_bid_id = winner.bid_id.clone();
        }
        Ok(self
            .bids
            .get(&winner.bid_id)
            .cloned()
            .ok_or_else(|| "winning bid missing after settlement".to_string())?)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_proof_receipt(
        &mut self,
        job_id: &str,
        bid_id: &str,
        proof_root: impl Into<String>,
        public_output_root: impl Into<String>,
        verification_key_root: impl Into<String>,
        proof_bytes: u64,
        completed_at_height: u64,
    ) -> ProofFeeMarketResult<ProofFeeProofReceipt> {
        let job = self
            .jobs
            .get(job_id)
            .cloned()
            .ok_or_else(|| "unknown proof fee job".to_string())?;
        if job.status != PROOF_FEE_MARKET_STATUS_ASSIGNED {
            return Err("proof fee job is not assigned".to_string());
        }
        if job.assigned_bid_id != bid_id {
            return Err("proof receipt bid is not assigned to job".to_string());
        }
        let bid = self
            .bids
            .get(bid_id)
            .cloned()
            .ok_or_else(|| "unknown proof fee bid".to_string())?;
        if bid.status != PROOF_FEE_MARKET_STATUS_ACCEPTED {
            return Err("proof receipt bid is not accepted".to_string());
        }
        let receipt = ProofFeeProofReceipt::new(
            &job,
            &bid,
            proof_root,
            public_output_root,
            verification_key_root,
            proof_bytes,
            completed_at_height,
        )?;
        if let Some(stored_job) = self.jobs.get_mut(job_id) {
            stored_job.status = PROOF_FEE_MARKET_STATUS_PROVED.to_string();
            stored_job.proof_receipt_id = receipt.receipt_id.clone();
        }
        self.proof_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        Ok(receipt)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_proof(
        &mut self,
        proof_receipt_id: &str,
        committee_id: &str,
        outcome: ProofVerificationOutcome,
        accepted_weight: u64,
        rejected_weight: u64,
        total_weight: u64,
        verifier_response_root: impl Into<String>,
        sampled_at_height: u64,
        finalized_at_height: u64,
    ) -> ProofFeeMarketResult<ProofCommitteeVerificationReceipt> {
        let proof_receipt = self
            .proof_receipts
            .get(proof_receipt_id)
            .cloned()
            .ok_or_else(|| "unknown proof receipt".to_string())?;
        let committee = self
            .verifier_committees
            .get(committee_id)
            .cloned()
            .ok_or_else(|| "unknown verifier committee".to_string())?;
        if !committee.is_active_at(self.height) {
            return Err("verifier committee is not active".to_string());
        }
        let verification = ProofCommitteeVerificationReceipt::new(
            &proof_receipt,
            &committee,
            outcome,
            accepted_weight,
            rejected_weight,
            total_weight,
            verifier_response_root,
            sampled_at_height,
            finalized_at_height,
        )?;
        if let Some(receipt) = self.proof_receipts.get_mut(proof_receipt_id) {
            receipt.status = outcome.status().to_string();
        }
        if let Some(job) = self.jobs.get_mut(&proof_receipt.job_id) {
            job.status = outcome.status().to_string();
            job.verification_receipt_id = verification.verification_receipt_id.clone();
        }
        self.verification_receipts.insert(
            verification.verification_receipt_id.clone(),
            verification.clone(),
        );
        Ok(verification)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_compression_receipt(
        &mut self,
        job_id: &str,
        proof_receipt_id: &str,
        sla_id: &str,
        worker_id: impl Into<String>,
        compressed_proof_root: impl Into<String>,
        compressed_bytes: u64,
        verify_micros: u64,
        completed_at_height: u64,
    ) -> ProofFeeMarketResult<ProofCompressionReceipt> {
        let job = self
            .jobs
            .get(job_id)
            .cloned()
            .ok_or_else(|| "unknown proof fee job".to_string())?;
        if job.status != PROOF_FEE_MARKET_STATUS_VERIFIED {
            return Err("proof fee job is not verified".to_string());
        }
        let proof_receipt = self
            .proof_receipts
            .get(proof_receipt_id)
            .cloned()
            .ok_or_else(|| "unknown proof receipt".to_string())?;
        let sla = self
            .compression_slas
            .get(sla_id)
            .cloned()
            .ok_or_else(|| "unknown compression SLA".to_string())?;
        if !sla.is_active_at(self.height) {
            return Err("compression SLA is not active".to_string());
        }
        let receipt = ProofCompressionReceipt::new(
            &job,
            &proof_receipt,
            &sla,
            worker_id,
            compressed_proof_root,
            compressed_bytes,
            verify_micros,
            completed_at_height,
        )?;
        let observation =
            ProofLatencyObservation::new(&job, &proof_receipt, &receipt, completed_at_height)?;
        if let Some(stored_job) = self.jobs.get_mut(job_id) {
            stored_job.status = receipt.status.clone();
            stored_job.compression_receipt_id = receipt.compression_receipt_id.clone();
        }
        self.compression_receipts
            .insert(receipt.compression_receipt_id.clone(), receipt.clone());
        self.latency_observations
            .insert(observation.observation_id.clone(), observation);
        Ok(receipt)
    }

    pub fn settle_fee_rebate(
        &mut self,
        job_id: &str,
        sponsorship_id: &str,
        beneficiary_commitment: impl Into<String>,
        settled_at_height: u64,
    ) -> ProofFeeMarketResult<ProofFeeRebateSettlement> {
        let job = self
            .jobs
            .get(job_id)
            .cloned()
            .ok_or_else(|| "unknown proof fee job".to_string())?;
        if job.sponsor_id != sponsorship_id {
            return Err("proof fee job sponsorship mismatch".to_string());
        }
        if job.status != PROOF_FEE_MARKET_STATUS_COMPRESSED {
            return Err("proof fee job is not compressed".to_string());
        }
        let bid = self
            .bids
            .get(&job.assigned_bid_id)
            .cloned()
            .ok_or_else(|| "proof fee job winning bid missing".to_string())?;
        let compression = self
            .compression_receipts
            .get(&job.compression_receipt_id)
            .cloned()
            .ok_or_else(|| "proof fee job compression receipt missing".to_string())?;
        let sponsorship = self
            .batch_sponsorships
            .get(sponsorship_id)
            .cloned()
            .ok_or_else(|| "unknown batch sponsorship".to_string())?;
        let gross_fee_units = bid.bid_fee_units.max(self.config.low_fee_floor_units);
        let sponsor_paid_units = gross_fee_units.min(sponsorship.max_fee_per_job_units);
        let settlement = ProofFeeRebateSettlement::new(
            &job,
            &sponsorship,
            beneficiary_commitment,
            gross_fee_units,
            sponsor_paid_units,
            self.config.protocol_fee_bps,
            compression.rebate_units,
            settled_at_height,
        )?;
        if let Some(stored_sponsorship) = self.batch_sponsorships.get_mut(sponsorship_id) {
            stored_sponsorship.spend_reserved(job.max_fee_units, sponsor_paid_units)?;
        }
        if let Some(stored_job) = self.jobs.get_mut(job_id) {
            stored_job.status = PROOF_FEE_MARKET_STATUS_SETTLED.to_string();
        }
        if let Some(stored_bid) = self.bids.get_mut(&job.assigned_bid_id) {
            stored_bid.status = PROOF_FEE_MARKET_STATUS_SETTLED.to_string();
        }
        self.fee_rebates
            .insert(settlement.rebate_id.clone(), settlement.clone());
        Ok(settlement)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_fallback_challenge(
        &mut self,
        job_id: &str,
        target_kind: impl Into<String>,
        target_id: impl Into<String>,
        challenger_commitment: impl Into<String>,
        challenge_kind: ProofFallbackChallengeKind,
        evidence_root: impl Into<String>,
        fallback_circuit_root: impl Into<String>,
        bond_units: u64,
    ) -> ProofFeeMarketResult<ProofFallbackChallenge> {
        if !self.jobs.contains_key(job_id) {
            return Err("unknown challenge job".to_string());
        }
        let challenge = ProofFallbackChallenge::new(
            job_id,
            target_kind,
            target_id,
            challenger_commitment,
            challenge_kind,
            evidence_root,
            fallback_circuit_root,
            bond_units,
            self.height,
            self.config.default_challenge_window_blocks,
        )?;
        self.ensure_challenge_target_exists(&challenge.target_kind, &challenge.target_id)?;
        if let Some(job) = self.jobs.get_mut(&challenge.job_id) {
            job.status = PROOF_FEE_MARKET_STATUS_CHALLENGED.to_string();
        }
        self.fallback_challenges
            .insert(challenge.challenge_id.clone(), challenge.clone());
        Ok(challenge)
    }

    pub fn resolve_fallback_challenge(
        &mut self,
        challenge_id: &str,
        outcome: ProofFallbackChallengeOutcome,
        resolved_at_height: u64,
    ) -> ProofFeeMarketResult<ProofFallbackChallenge> {
        let challenge = self
            .fallback_challenges
            .remove(challenge_id)
            .ok_or_else(|| "unknown fallback challenge".to_string())?;
        let resolved = challenge.resolve(outcome, resolved_at_height)?;
        if let Some(job) = self.jobs.get_mut(&resolved.job_id) {
            job.status = match outcome {
                ProofFallbackChallengeOutcome::ProverWins => {
                    PROOF_FEE_MARKET_STATUS_VERIFIED.to_string()
                }
                ProofFallbackChallengeOutcome::ChallengerWins => {
                    PROOF_FEE_MARKET_STATUS_SLASHED.to_string()
                }
                ProofFallbackChallengeOutcome::Escalated => {
                    PROOF_FEE_MARKET_STATUS_CHALLENGED.to_string()
                }
                ProofFallbackChallengeOutcome::Expired => {
                    PROOF_FEE_MARKET_STATUS_EXPIRED.to_string()
                }
                ProofFallbackChallengeOutcome::Pending => {
                    PROOF_FEE_MARKET_STATUS_CHALLENGED.to_string()
                }
            };
        }
        self.fallback_challenges
            .insert(resolved.challenge_id.clone(), resolved.clone());
        Ok(resolved)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        evidence: ProofSlashingEvidence,
    ) -> ProofFeeMarketResult<String> {
        evidence.validate()?;
        self.ensure_slashing_target_exists(&evidence.target_kind, &evidence.target_id)?;
        match evidence.target_kind.as_str() {
            "job" | "proof_fee_job" => {
                if let Some(job) = self.jobs.get_mut(&evidence.target_id) {
                    job.status = PROOF_FEE_MARKET_STATUS_SLASHED.to_string();
                }
            }
            "bid" | "prover_bid" => {
                if let Some(bid) = self.bids.get_mut(&evidence.target_id) {
                    bid.status = PROOF_FEE_MARKET_STATUS_SLASHED.to_string();
                }
            }
            "compression_receipt" => {
                if let Some(receipt) = self.compression_receipts.get_mut(&evidence.target_id) {
                    receipt.status = PROOF_FEE_MARKET_STATUS_SLASHED.to_string();
                }
            }
            "verifier_committee" => {
                if let Some(committee) = self.verifier_committees.get_mut(&evidence.target_id) {
                    committee.status = PROOF_FEE_MARKET_STATUS_SLASHED.to_string();
                }
            }
            _ => {}
        }
        insert_unique_record(
            &mut self.slashing_evidence,
            evidence.evidence_id.clone(),
            evidence,
            "slashing evidence",
        )
    }

    pub fn insert_devnet_fixture(
        &mut self,
        fixture: ProofFeeMarketDevnetFixture,
    ) -> ProofFeeMarketResult<String> {
        if !self.config.allow_devnet_fixtures {
            return Err("proof fee market devnet fixtures are disabled".to_string());
        }
        fixture.validate()?;
        insert_unique_record(
            &mut self.devnet_fixtures,
            fixture.fixture_id.clone(),
            fixture,
            "devnet fixture",
        )
    }

    fn ensure_challenge_target_exists(
        &self,
        target_kind: &str,
        target_id: &str,
    ) -> ProofFeeMarketResult<()> {
        let exists = match target_kind {
            "job" | "proof_fee_job" => self.jobs.contains_key(target_id),
            "proof_receipt" => self.proof_receipts.contains_key(target_id),
            "verification_receipt" => self.verification_receipts.contains_key(target_id),
            "compression_receipt" => self.compression_receipts.contains_key(target_id),
            "bid" | "prover_bid" => self.bids.contains_key(target_id),
            "verifier_committee" => self.verifier_committees.contains_key(target_id),
            _ => false,
        };
        if exists {
            Ok(())
        } else {
            Err("challenge target does not exist".to_string())
        }
    }

    fn ensure_slashing_target_exists(
        &self,
        target_kind: &str,
        target_id: &str,
    ) -> ProofFeeMarketResult<()> {
        let exists = match target_kind {
            "job" | "proof_fee_job" => self.jobs.contains_key(target_id),
            "bid" | "prover_bid" => self.bids.contains_key(target_id),
            "proof_receipt" => self.proof_receipts.contains_key(target_id),
            "verification_receipt" => self.verification_receipts.contains_key(target_id),
            "compression_receipt" => self.compression_receipts.contains_key(target_id),
            "verifier_committee" => self.verifier_committees.contains_key(target_id),
            "sponsorship" => self.batch_sponsorships.contains_key(target_id),
            _ => false,
        };
        if exists {
            Ok(())
        } else {
            Err("slashing target does not exist".to_string())
        }
    }

    pub fn job_root(&self) -> String {
        proof_fee_job_set_root(&self.jobs.values().cloned().collect::<Vec<_>>())
    }

    pub fn bid_root(&self) -> String {
        proof_fee_bid_set_root(&self.bids.values().cloned().collect::<Vec<_>>())
    }

    pub fn verifier_member_root(&self) -> String {
        proof_verifier_member_set_root(&self.verifier_members.values().cloned().collect::<Vec<_>>())
    }

    pub fn verifier_committee_root(&self) -> String {
        proof_verifier_committee_set_root(
            &self
                .verifier_committees
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn proof_receipt_root(&self) -> String {
        proof_fee_receipt_set_root(&self.proof_receipts.values().cloned().collect::<Vec<_>>())
    }

    pub fn verification_receipt_root(&self) -> String {
        proof_verification_receipt_set_root(
            &self
                .verification_receipts
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn compression_sla_root(&self) -> String {
        proof_compression_sla_set_root(&self.compression_slas.values().cloned().collect::<Vec<_>>())
    }

    pub fn compression_receipt_root(&self) -> String {
        proof_compression_receipt_set_root(
            &self
                .compression_receipts
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn fee_rebate_root(&self) -> String {
        proof_fee_rebate_set_root(&self.fee_rebates.values().cloned().collect::<Vec<_>>())
    }

    pub fn slashing_evidence_root(&self) -> String {
        proof_slashing_evidence_set_root(
            &self.slashing_evidence.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn fallback_challenge_root(&self) -> String {
        proof_fallback_challenge_set_root(
            &self
                .fallback_challenges
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn batch_sponsorship_root(&self) -> String {
        proof_batch_sponsorship_set_root(
            &self
                .batch_sponsorships
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn latency_observation_root(&self) -> String {
        proof_latency_observation_set_root(
            &self
                .latency_observations
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn devnet_fixture_root(&self) -> String {
        proof_fee_market_devnet_fixture_set_root(
            &self.devnet_fixtures.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn active_sla_root(&self) -> String {
        string_map_root("PROOF-FEE-MARKET-ACTIVE-SLA", &self.active_sla_ids)
    }

    pub fn active_committee_root(&self) -> String {
        proof_fee_market_payload_root(
            "PROOF-FEE-MARKET-ACTIVE-COMMITTEE",
            &json!({
                "kind": "proof_fee_market_active_committee",
                "chain_id": CHAIN_ID,
                "committee_id": self.active_committee_id,
            }),
        )
    }

    pub fn roots(&self) -> ProofFeeMarketRoots {
        let config_root = self.config.config_root();
        let active_sla_root = self.active_sla_root();
        let active_committee_root = self.active_committee_root();
        let job_root = self.job_root();
        let bid_root = self.bid_root();
        let verifier_member_root = self.verifier_member_root();
        let verifier_committee_root = self.verifier_committee_root();
        let proof_receipt_root = self.proof_receipt_root();
        let verification_receipt_root = self.verification_receipt_root();
        let compression_sla_root = self.compression_sla_root();
        let compression_receipt_root = self.compression_receipt_root();
        let fee_rebate_root = self.fee_rebate_root();
        let slashing_evidence_root = self.slashing_evidence_root();
        let fallback_challenge_root = self.fallback_challenge_root();
        let batch_sponsorship_root = self.batch_sponsorship_root();
        let latency_observation_root = self.latency_observation_root();
        let devnet_fixture_root = self.devnet_fixture_root();
        let state_record = json!({
            "kind": "proof_fee_market_state_root",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "schema_version": PROOF_FEE_MARKET_SCHEMA_VERSION,
            "height": self.height,
            "market_label_root": proof_fee_market_string_root("PROOF-FEE-MARKET-LABEL", &self.market_label),
            "config_root": config_root,
            "active_sla_root": active_sla_root,
            "active_committee_root": active_committee_root,
            "job_root": job_root,
            "bid_root": bid_root,
            "verifier_member_root": verifier_member_root,
            "verifier_committee_root": verifier_committee_root,
            "proof_receipt_root": proof_receipt_root,
            "verification_receipt_root": verification_receipt_root,
            "compression_sla_root": compression_sla_root,
            "compression_receipt_root": compression_receipt_root,
            "fee_rebate_root": fee_rebate_root,
            "slashing_evidence_root": slashing_evidence_root,
            "fallback_challenge_root": fallback_challenge_root,
            "batch_sponsorship_root": batch_sponsorship_root,
            "latency_observation_root": latency_observation_root,
            "devnet_fixture_root": devnet_fixture_root,
            "counters": self.counters().public_record(),
        });
        let state_root = proof_fee_market_state_root_from_record(&state_record);
        ProofFeeMarketRoots {
            config_root,
            active_sla_root,
            active_committee_root,
            job_root,
            bid_root,
            verifier_member_root,
            verifier_committee_root,
            proof_receipt_root,
            verification_receipt_root,
            compression_sla_root,
            compression_receipt_root,
            fee_rebate_root,
            slashing_evidence_root,
            fallback_challenge_root,
            batch_sponsorship_root,
            latency_observation_root,
            devnet_fixture_root,
            state_root,
        }
    }

    pub fn counters(&self) -> ProofFeeMarketCounters {
        let mut counters = ProofFeeMarketCounters {
            jobs: self.jobs.len() as u64,
            bids: self.bids.len() as u64,
            verifier_members: self.verifier_members.len() as u64,
            verifier_committees: self.verifier_committees.len() as u64,
            proof_receipts: self.proof_receipts.len() as u64,
            verification_receipts: self.verification_receipts.len() as u64,
            compression_slas: self.compression_slas.len() as u64,
            compression_receipts: self.compression_receipts.len() as u64,
            fee_rebates: self.fee_rebates.len() as u64,
            slashing_evidence: self.slashing_evidence.len() as u64,
            fallback_challenges: self.fallback_challenges.len() as u64,
            batch_sponsorships: self.batch_sponsorships.len() as u64,
            latency_observations: self.latency_observations.len() as u64,
            ..ProofFeeMarketCounters::default()
        };
        for job in self.jobs.values() {
            match job.status.as_str() {
                PROOF_FEE_MARKET_STATUS_OPEN => counters.open_jobs += 1,
                PROOF_FEE_MARKET_STATUS_ASSIGNED => counters.assigned_jobs += 1,
                PROOF_FEE_MARKET_STATUS_PROVED => counters.proved_jobs += 1,
                PROOF_FEE_MARKET_STATUS_VERIFIED => counters.verified_jobs += 1,
                PROOF_FEE_MARKET_STATUS_COMPRESSED => counters.compressed_jobs += 1,
                PROOF_FEE_MARKET_STATUS_CHALLENGED => counters.challenged_jobs += 1,
                PROOF_FEE_MARKET_STATUS_SETTLED => counters.settled_jobs += 1,
                PROOF_FEE_MARKET_STATUS_EXPIRED => counters.expired_jobs += 1,
                PROOF_FEE_MARKET_STATUS_REJECTED => counters.rejected_jobs += 1,
                PROOF_FEE_MARKET_STATUS_SLASHED => counters.slashed_jobs += 1,
                _ => {}
            }
            counters.total_max_fee_units = counters
                .total_max_fee_units
                .saturating_add(job.max_fee_units);
        }
        for bid in self.bids.values() {
            if bid.status == PROOF_FEE_MARKET_STATUS_ACCEPTED
                || bid.status == PROOF_FEE_MARKET_STATUS_SETTLED
            {
                counters.accepted_bids = counters.accepted_bids.saturating_add(1);
                counters.total_bid_fee_units = counters
                    .total_bid_fee_units
                    .saturating_add(bid.bid_fee_units);
            }
        }
        for rebate in self.fee_rebates.values() {
            counters.total_protocol_fee_units = counters
                .total_protocol_fee_units
                .saturating_add(rebate.protocol_fee_units);
            counters.total_rebate_units = counters
                .total_rebate_units
                .saturating_add(rebate.prover_discount_units);
        }
        for evidence in self.slashing_evidence.values() {
            counters.total_slash_units = counters
                .total_slash_units
                .saturating_add(evidence.slash_units);
        }
        for challenge in self.fallback_challenges.values() {
            if challenge.is_open_at(self.height) {
                counters.open_challenges = counters.open_challenges.saturating_add(1);
            }
        }
        for sponsorship in self.batch_sponsorships.values() {
            counters.total_sponsor_available_units = counters
                .total_sponsor_available_units
                .saturating_add(sponsorship.available_units());
        }
        for receipt in self.compression_receipts.values() {
            counters.total_bytes_saved = counters
                .total_bytes_saved
                .saturating_add(receipt.bytes_saved());
        }
        for observation in self.latency_observations.values() {
            match observation.latency_bucket {
                ProofLatencyBucket::Fast => counters.latency_fast += 1,
                ProofLatencyBucket::Target => counters.latency_target += 1,
                ProofLatencyBucket::Delayed => counters.latency_delayed += 1,
                ProofLatencyBucket::Expired => counters.latency_expired += 1,
                ProofLatencyBucket::Slashed => counters.latency_slashed += 1,
            }
        }
        counters
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "proof_fee_market_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROOF_FEE_MARKET_PROTOCOL_VERSION,
            "schema_version": PROOF_FEE_MARKET_SCHEMA_VERSION,
            "height": self.height,
            "market_label": self.market_label,
            "config": self.config.public_record(),
            "active_committee_id": self.active_committee_id,
            "active_sla_ids": self.active_sla_ids,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn validate(&self) -> ProofFeeMarketResult<String> {
        self.config.validate()?;
        ensure_non_empty(&self.market_label, "proof fee market label")?;
        if !self.active_committee_id.is_empty() {
            let committee = self
                .verifier_committees
                .get(&self.active_committee_id)
                .ok_or_else(|| "active committee is missing".to_string())?;
            if !committee.is_active_at(self.height) {
                return Err("active committee is not active at height".to_string());
            }
        }
        for (job_kind, sla_id) in &self.active_sla_ids {
            let sla = self
                .compression_slas
                .get(sla_id)
                .ok_or_else(|| "active SLA is missing".to_string())?;
            if sla.job_kind.as_str() != job_kind {
                return Err("active SLA job kind mismatch".to_string());
            }
            if !sla.is_active_at(self.height) {
                return Err("active SLA is not active at height".to_string());
            }
        }
        for sla in self.compression_slas.values() {
            sla.validate()?;
        }
        for member in self.verifier_members.values() {
            member.validate()?;
        }
        for committee in self.verifier_committees.values() {
            committee.validate()?;
            for member_id in &committee.member_ids {
                if !self.verifier_members.contains_key(member_id) {
                    return Err("committee references unknown member".to_string());
                }
            }
        }
        for sponsorship in self.batch_sponsorships.values() {
            sponsorship.validate()?;
        }
        for job in self.jobs.values() {
            job.validate()?;
            if !job.sponsor_id.is_empty() && !self.batch_sponsorships.contains_key(&job.sponsor_id)
            {
                return Err("job references unknown sponsorship".to_string());
            }
        }
        for bid in self.bids.values() {
            bid.validate()?;
            if !self.jobs.contains_key(&bid.job_id) {
                return Err("bid references unknown job".to_string());
            }
        }
        for receipt in self.proof_receipts.values() {
            receipt.validate()?;
            if !self.jobs.contains_key(&receipt.job_id) {
                return Err("proof receipt references unknown job".to_string());
            }
            if !self.bids.contains_key(&receipt.bid_id) {
                return Err("proof receipt references unknown bid".to_string());
            }
        }
        for receipt in self.verification_receipts.values() {
            receipt.validate()?;
            if !self.proof_receipts.contains_key(&receipt.proof_receipt_id) {
                return Err("verification receipt references unknown proof receipt".to_string());
            }
            if !self.verifier_committees.contains_key(&receipt.committee_id) {
                return Err("verification receipt references unknown committee".to_string());
            }
        }
        for receipt in self.compression_receipts.values() {
            receipt.validate()?;
            if !self.jobs.contains_key(&receipt.job_id) {
                return Err("compression receipt references unknown job".to_string());
            }
            if !self.proof_receipts.contains_key(&receipt.proof_receipt_id) {
                return Err("compression receipt references unknown proof receipt".to_string());
            }
            if !self.compression_slas.contains_key(&receipt.sla_id) {
                return Err("compression receipt references unknown SLA".to_string());
            }
        }
        for rebate in self.fee_rebates.values() {
            rebate.validate()?;
            if !self.jobs.contains_key(&rebate.job_id) {
                return Err("rebate references unknown job".to_string());
            }
            if !self.batch_sponsorships.contains_key(&rebate.sponsorship_id) {
                return Err("rebate references unknown sponsorship".to_string());
            }
        }
        for evidence in self.slashing_evidence.values() {
            evidence.validate()?;
            self.ensure_slashing_target_exists(&evidence.target_kind, &evidence.target_id)?;
        }
        for challenge in self.fallback_challenges.values() {
            challenge.validate()?;
            self.ensure_challenge_target_exists(&challenge.target_kind, &challenge.target_id)?;
        }
        for observation in self.latency_observations.values() {
            observation.validate()?;
            if !self.jobs.contains_key(&observation.job_id) {
                return Err("latency observation references unknown job".to_string());
            }
        }
        for fixture in self.devnet_fixtures.values() {
            fixture.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn proof_fee_market_state_root(state: &ProofFeeMarketState) -> String {
    state.state_root()
}

pub fn proof_fee_market_state_root_from_record(record: &Value) -> String {
    domain_hash("PROOF-FEE-MARKET-STATE", &[HashPart::Json(record)], 32)
}

pub fn proof_fee_market_payload_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

pub fn proof_fee_market_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn proof_fee_market_deterministic_root(label: &str) -> String {
    domain_hash(
        "PROOF-FEE-MARKET-DETERMINISTIC-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn proof_fee_market_deterministic_commitment(label: &str) -> String {
    domain_hash(
        "PROOF-FEE-MARKET-DETERMINISTIC-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn proof_workload_id(
    job_kind: ProofFeeJobKind,
    proof_system: &str,
    public_input_root: &str,
    source_payload_root: &str,
    recursion_depth: u64,
    child_proof_count: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-MARKET-WORKLOAD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_kind.as_str()),
            HashPart::Str(proof_system),
            HashPart::Str(public_input_root),
            HashPart::Str(source_payload_root),
            HashPart::Int(recursion_depth as i128),
            HashPart::Int(child_proof_count as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn proof_workload_root(workload: &ProofWorkloadEnvelope) -> String {
    proof_fee_market_payload_root("PROOF-FEE-MARKET-WORKLOAD", &workload.public_record())
}

pub fn proof_fee_job_id(
    requester_commitment: &str,
    lane: ProofFeeLane,
    workload_id: &str,
    fee_asset_id: &str,
    max_fee_units: u64,
    posted_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-MARKET-JOB-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(requester_commitment),
            HashPart::Str(lane.as_str()),
            HashPart::Str(workload_id),
            HashPart::Str(fee_asset_id),
            HashPart::Int(max_fee_units as i128),
            HashPart::Int(posted_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn proof_fee_job_root(job: &ProofFeeJob) -> String {
    proof_fee_market_payload_root("PROOF-FEE-MARKET-JOB", &job.public_record())
}

pub fn proof_fee_bid_id(
    job_id: &str,
    prover_id: &str,
    worker_class: ProofWorkerClass,
    bid_fee_units: u64,
    placed_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-MARKET-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(prover_id),
            HashPart::Str(worker_class.as_str()),
            HashPart::Int(bid_fee_units as i128),
            HashPart::Int(placed_at_height as i128),
        ],
        32,
    )
}

pub fn proof_fee_bid_root(bid: &ProofFeeProverBid) -> String {
    proof_fee_market_payload_root("PROOF-FEE-MARKET-BID", &bid.public_record())
}

pub fn proof_verifier_member_id(
    operator_id: &str,
    role: ProofVerifierRole,
    weight: u64,
    pq_public_key_root: &str,
    joined_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-MARKET-VERIFIER-MEMBER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_id),
            HashPart::Str(role.as_str()),
            HashPart::Int(weight as i128),
            HashPart::Str(pq_public_key_root),
            HashPart::Int(joined_at_height as i128),
        ],
        32,
    )
}

pub fn proof_verifier_member_root(member: &ProofVerifierMember) -> String {
    proof_fee_market_payload_root("PROOF-FEE-MARKET-VERIFIER-MEMBER", &member.public_record())
}

pub fn proof_verifier_committee_id(
    epoch: u64,
    policy: ProofVerifierCommitteePolicy,
    member_weight_root: &str,
    threshold_bps: u64,
    formed_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-MARKET-VERIFIER-COMMITTEE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(epoch as i128),
            HashPart::Str(policy.as_str()),
            HashPart::Str(member_weight_root),
            HashPart::Int(threshold_bps as i128),
            HashPart::Int(formed_at_height as i128),
        ],
        32,
    )
}

pub fn proof_verifier_committee_root(committee: &ProofVerifierCommittee) -> String {
    proof_fee_market_payload_root(
        "PROOF-FEE-MARKET-VERIFIER-COMMITTEE",
        &committee.public_record(),
    )
}

pub fn proof_fee_receipt_id(
    job_id: &str,
    bid_id: &str,
    proof_root: &str,
    public_output_root: &str,
    completed_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-MARKET-PROOF-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(bid_id),
            HashPart::Str(proof_root),
            HashPart::Str(public_output_root),
            HashPart::Int(completed_at_height as i128),
        ],
        32,
    )
}

pub fn proof_fee_receipt_root(receipt: &ProofFeeProofReceipt) -> String {
    proof_fee_market_payload_root("PROOF-FEE-MARKET-PROOF-RECEIPT", &receipt.public_record())
}

pub fn proof_verification_receipt_id(
    proof_receipt_id: &str,
    committee_id: &str,
    outcome: ProofVerificationOutcome,
    verifier_response_root: &str,
    finalized_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-MARKET-VERIFICATION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proof_receipt_id),
            HashPart::Str(committee_id),
            HashPart::Str(outcome.as_str()),
            HashPart::Str(verifier_response_root),
            HashPart::Int(finalized_at_height as i128),
        ],
        32,
    )
}

pub fn proof_verification_receipt_root(receipt: &ProofCommitteeVerificationReceipt) -> String {
    proof_fee_market_payload_root(
        "PROOF-FEE-MARKET-VERIFICATION-RECEIPT",
        &receipt.public_record(),
    )
}

pub fn proof_compression_sla_id(
    job_kind: ProofFeeJobKind,
    tier: ProofCompressionSlaTier,
    target_compressed_bytes: u64,
    target_verify_micros: u64,
    target_latency_blocks: u64,
    starts_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-MARKET-COMPRESSION-SLA-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_kind.as_str()),
            HashPart::Str(tier.as_str()),
            HashPart::Int(target_compressed_bytes as i128),
            HashPart::Int(target_verify_micros as i128),
            HashPart::Int(target_latency_blocks as i128),
            HashPart::Int(starts_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn proof_compression_sla_root(sla: &ProofCompressionSla) -> String {
    proof_fee_market_payload_root("PROOF-FEE-MARKET-COMPRESSION-SLA", &sla.public_record())
}

pub fn proof_compression_receipt_id(
    job_id: &str,
    proof_receipt_id: &str,
    sla_id: &str,
    worker_id: &str,
    compressed_proof_root: &str,
    completed_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-MARKET-COMPRESSION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(proof_receipt_id),
            HashPart::Str(sla_id),
            HashPart::Str(worker_id),
            HashPart::Str(compressed_proof_root),
            HashPart::Int(completed_at_height as i128),
        ],
        32,
    )
}

pub fn proof_compression_receipt_root(receipt: &ProofCompressionReceipt) -> String {
    proof_fee_market_payload_root(
        "PROOF-FEE-MARKET-COMPRESSION-RECEIPT",
        &receipt.public_record(),
    )
}

pub fn proof_batch_sponsorship_id(
    sponsor_commitment: &str,
    lane: ProofFeeLane,
    fee_asset_id: &str,
    eligible_job_kind_root: &str,
    beneficiary_root: &str,
    starts_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-MARKET-BATCH-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane.as_str()),
            HashPart::Str(fee_asset_id),
            HashPart::Str(eligible_job_kind_root),
            HashPart::Str(beneficiary_root),
            HashPart::Int(starts_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn proof_batch_sponsorship_root(sponsorship: &ProofBatchSponsorship) -> String {
    proof_fee_market_payload_root(
        "PROOF-FEE-MARKET-BATCH-SPONSORSHIP",
        &sponsorship.public_record(),
    )
}

pub fn proof_fee_rebate_id(
    job_id: &str,
    sponsorship_id: &str,
    beneficiary_commitment: &str,
    gross_fee_units: u64,
    sponsor_paid_units: u64,
    settled_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-MARKET-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(sponsorship_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Int(gross_fee_units as i128),
            HashPart::Int(sponsor_paid_units as i128),
            HashPart::Int(settled_at_height as i128),
        ],
        32,
    )
}

pub fn proof_fee_rebate_root(rebate: &ProofFeeRebateSettlement) -> String {
    proof_fee_market_payload_root("PROOF-FEE-MARKET-REBATE", &rebate.public_record())
}

pub fn proof_slashing_evidence_id(
    target_kind: &str,
    target_id: &str,
    slashing_kind: ProofSlashingKind,
    evidence_root: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-MARKET-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(target_kind),
            HashPart::Str(target_id),
            HashPart::Str(slashing_kind.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

pub fn proof_slashing_evidence_root(evidence: &ProofSlashingEvidence) -> String {
    proof_fee_market_payload_root(
        "PROOF-FEE-MARKET-SLASHING-EVIDENCE",
        &evidence.public_record(),
    )
}

pub fn proof_fallback_challenge_id(
    job_id: &str,
    target_kind: &str,
    target_id: &str,
    challenge_kind: ProofFallbackChallengeKind,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-MARKET-FALLBACK-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(target_kind),
            HashPart::Str(target_id),
            HashPart::Str(challenge_kind.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn proof_fallback_challenge_root(challenge: &ProofFallbackChallenge) -> String {
    proof_fee_market_payload_root(
        "PROOF-FEE-MARKET-FALLBACK-CHALLENGE",
        &challenge.public_record(),
    )
}

pub fn proof_latency_observation_id(
    job_id: &str,
    proof_latency_blocks: u64,
    compression_latency_blocks: u64,
    latency_bucket: ProofLatencyBucket,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "PROOF-FEE-MARKET-LATENCY-OBSERVATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Int(proof_latency_blocks as i128),
            HashPart::Int(compression_latency_blocks as i128),
            HashPart::Str(latency_bucket.as_str()),
            HashPart::Int(observed_at_height as i128),
        ],
        32,
    )
}

pub fn proof_latency_observation_root(observation: &ProofLatencyObservation) -> String {
    proof_fee_market_payload_root(
        "PROOF-FEE-MARKET-LATENCY-OBSERVATION",
        &observation.public_record(),
    )
}

pub fn proof_fee_market_devnet_fixture_id(
    label: &str,
    height: u64,
    seed_root: &str,
    state_root: &str,
) -> String {
    domain_hash(
        "PROOF-FEE-MARKET-DEVNET-FIXTURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(height as i128),
            HashPart::Str(seed_root),
            HashPart::Str(state_root),
        ],
        32,
    )
}

pub fn proof_fee_market_devnet_fixture_root(fixture: &ProofFeeMarketDevnetFixture) -> String {
    proof_fee_market_payload_root("PROOF-FEE-MARKET-DEVNET-FIXTURE", &fixture.public_record())
}

pub fn proof_fee_job_set_root(jobs: &[ProofFeeJob]) -> String {
    sorted_record_root(
        "PROOF-FEE-MARKET-JOB",
        jobs,
        |job| job.job_id.clone(),
        ProofFeeJob::public_record,
    )
}

pub fn proof_fee_bid_set_root(bids: &[ProofFeeProverBid]) -> String {
    sorted_record_root(
        "PROOF-FEE-MARKET-BID",
        bids,
        |bid| bid.bid_id.clone(),
        ProofFeeProverBid::public_record,
    )
}

pub fn proof_verifier_member_set_root(members: &[ProofVerifierMember]) -> String {
    sorted_record_root(
        "PROOF-FEE-MARKET-VERIFIER-MEMBER",
        members,
        |member| member.member_id.clone(),
        ProofVerifierMember::public_record,
    )
}

pub fn proof_verifier_committee_set_root(committees: &[ProofVerifierCommittee]) -> String {
    sorted_record_root(
        "PROOF-FEE-MARKET-VERIFIER-COMMITTEE",
        committees,
        |committee| committee.committee_id.clone(),
        ProofVerifierCommittee::public_record,
    )
}

pub fn proof_fee_receipt_set_root(receipts: &[ProofFeeProofReceipt]) -> String {
    sorted_record_root(
        "PROOF-FEE-MARKET-PROOF-RECEIPT",
        receipts,
        |receipt| receipt.receipt_id.clone(),
        ProofFeeProofReceipt::public_record,
    )
}

pub fn proof_verification_receipt_set_root(
    receipts: &[ProofCommitteeVerificationReceipt],
) -> String {
    sorted_record_root(
        "PROOF-FEE-MARKET-VERIFICATION-RECEIPT",
        receipts,
        |receipt| receipt.verification_receipt_id.clone(),
        ProofCommitteeVerificationReceipt::public_record,
    )
}

pub fn proof_compression_sla_set_root(slas: &[ProofCompressionSla]) -> String {
    sorted_record_root(
        "PROOF-FEE-MARKET-COMPRESSION-SLA",
        slas,
        |sla| sla.sla_id.clone(),
        ProofCompressionSla::public_record,
    )
}

pub fn proof_compression_receipt_set_root(receipts: &[ProofCompressionReceipt]) -> String {
    sorted_record_root(
        "PROOF-FEE-MARKET-COMPRESSION-RECEIPT",
        receipts,
        |receipt| receipt.compression_receipt_id.clone(),
        ProofCompressionReceipt::public_record,
    )
}

pub fn proof_fee_rebate_set_root(rebates: &[ProofFeeRebateSettlement]) -> String {
    sorted_record_root(
        "PROOF-FEE-MARKET-REBATE",
        rebates,
        |rebate| rebate.rebate_id.clone(),
        ProofFeeRebateSettlement::public_record,
    )
}

pub fn proof_slashing_evidence_set_root(evidence: &[ProofSlashingEvidence]) -> String {
    sorted_record_root(
        "PROOF-FEE-MARKET-SLASHING-EVIDENCE",
        evidence,
        |item| item.evidence_id.clone(),
        ProofSlashingEvidence::public_record,
    )
}

pub fn proof_fallback_challenge_set_root(challenges: &[ProofFallbackChallenge]) -> String {
    sorted_record_root(
        "PROOF-FEE-MARKET-FALLBACK-CHALLENGE",
        challenges,
        |challenge| challenge.challenge_id.clone(),
        ProofFallbackChallenge::public_record,
    )
}

pub fn proof_batch_sponsorship_set_root(sponsorships: &[ProofBatchSponsorship]) -> String {
    sorted_record_root(
        "PROOF-FEE-MARKET-BATCH-SPONSORSHIP",
        sponsorships,
        |sponsorship| sponsorship.sponsorship_id.clone(),
        ProofBatchSponsorship::public_record,
    )
}

pub fn proof_latency_observation_set_root(observations: &[ProofLatencyObservation]) -> String {
    sorted_record_root(
        "PROOF-FEE-MARKET-LATENCY-OBSERVATION",
        observations,
        |observation| observation.observation_id.clone(),
        ProofLatencyObservation::public_record,
    )
}

pub fn proof_fee_market_devnet_fixture_set_root(
    fixtures: &[ProofFeeMarketDevnetFixture],
) -> String {
    sorted_record_root(
        "PROOF-FEE-MARKET-DEVNET-FIXTURE",
        fixtures,
        |fixture| fixture.fixture_id.clone(),
        ProofFeeMarketDevnetFixture::public_record,
    )
}

pub fn proof_job_kind_set_root(job_kinds: &[ProofFeeJobKind]) -> String {
    let mut values = job_kinds
        .iter()
        .map(|kind| kind.as_str().to_string())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    string_set_root("PROOF-FEE-MARKET-ELIGIBLE-JOB-KIND", &values)
}

pub fn verifier_member_weight_root(members: &[ProofVerifierMember]) -> String {
    let mut records = members
        .iter()
        .map(|member| {
            (
                member.member_id.clone(),
                json!({
                    "member_id": member.member_id,
                    "operator_id": member.operator_id,
                    "role": member.role.as_str(),
                    "weight": member.weight,
                    "pq_public_key_root": member.pq_public_key_root,
                }),
            )
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "PROOF-FEE-MARKET-VERIFIER-MEMBER-WEIGHT",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn required_bid_collateral_units(bid_fee_units: u64, collateral_bps: u64) -> u64 {
    mul_bps_round_up(bid_fee_units, collateral_bps)
}

pub fn proof_fee_bid_score(
    job: &ProofFeeJob,
    worker_class: ProofWorkerClass,
    bid_fee_units: u64,
    promised_proof_latency_blocks: u64,
    promised_compression_latency_blocks: u64,
    collateral_units: u64,
) -> u64 {
    let price_component = job
        .max_fee_units
        .saturating_sub(bid_fee_units)
        .saturating_mul(30_000)
        / job.max_fee_units.max(1);
    let proof_latency_component = job
        .proof_latency_target_blocks()
        .saturating_sub(promised_proof_latency_blocks)
        .saturating_mul(2_500);
    let compression_latency_component = job
        .compression_latency_target_blocks()
        .saturating_sub(promised_compression_latency_blocks)
        .saturating_mul(1_500);
    let collateral_component =
        collateral_units.min(bid_fee_units).saturating_mul(3_000) / bid_fee_units.max(1);
    let worker_component = worker_class
        .capacity_weight()
        .saturating_mul(job.workload.compute_units())
        .min(20_000);
    price_component
        .saturating_add(proof_latency_component)
        .saturating_add(compression_latency_component)
        .saturating_add(collateral_component)
        .saturating_add(worker_component)
        .saturating_add(job.lane.default_weight())
}

pub fn compression_savings_bps(original_bytes: u64, compressed_bytes: u64) -> u64 {
    if original_bytes == 0 || compressed_bytes >= original_bytes {
        return 0;
    }
    original_bytes
        .saturating_sub(compressed_bytes)
        .saturating_mul(PROOF_FEE_MARKET_MAX_BPS)
        / original_bytes
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(PROOF_FEE_MARKET_MAX_BPS) / denominator
}

pub fn mul_bps_round_up(value: u64, bps: u64) -> u64 {
    if value == 0 || bps == 0 {
        return 0;
    }
    value
        .saturating_mul(bps)
        .saturating_add(PROOF_FEE_MARKET_MAX_BPS - 1)
        / PROOF_FEE_MARKET_MAX_BPS
}

pub fn classify_latency(
    started_at_height: u64,
    completed_at_height: u64,
    target_latency_blocks: u64,
    deadline_height: u64,
) -> ProofLatencyBucket {
    if completed_at_height > deadline_height {
        return ProofLatencyBucket::Expired;
    }
    let latency = completed_at_height.saturating_sub(started_at_height);
    if latency <= target_latency_blocks.saturating_div(2).max(1) {
        ProofLatencyBucket::Fast
    } else if latency <= target_latency_blocks {
        ProofLatencyBucket::Target
    } else {
        ProofLatencyBucket::Delayed
    }
}

fn devnet_verifier_member(
    operator_id: &str,
    role: ProofVerifierRole,
    weight: u64,
) -> ProofFeeMarketResult<ProofVerifierMember> {
    ProofVerifierMember::new(
        operator_id,
        role,
        weight,
        proof_fee_market_deterministic_root(&format!("{operator_id}:pq-key")),
        proof_fee_market_deterministic_root(&format!("{operator_id}:recovery-key")),
        proof_fee_market_deterministic_root(&format!("{operator_id}:stake")),
        proof_fee_market_deterministic_commitment(&format!("{operator_id}:endpoint")),
        64,
        0,
    )
}

fn sorted_record_root<T, Id, Record>(domain: &str, values: &[T], id: Id, record: Record) -> String
where
    Id: Fn(&T) -> String,
    Record: Fn(&T) -> Value,
{
    let mut records = values
        .iter()
        .map(|value| (id(value), record(value)))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        domain,
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

fn string_set_root(domain: &str, values: &[String]) -> String {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    merkle_root(
        domain,
        &values
            .into_iter()
            .map(|value| Value::String(value))
            .collect::<Vec<_>>(),
    )
}

fn string_map_root(domain: &str, values: &BTreeMap<String, String>) -> String {
    let records = values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn ensure_non_empty(value: &str, label: &str) -> ProofFeeMarketResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> ProofFeeMarketResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> ProofFeeMarketResult<()> {
    if value > PROOF_FEE_MARKET_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_hash_like(value: &str, label: &str) -> ProofFeeMarketResult<()> {
    ensure_non_empty(value, label)?;
    if value.len() < 32 {
        return Err(format!("{label} is too short"));
    }
    if !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} must be hex encoded"));
    }
    Ok(())
}

fn ensure_status(value: &str, allowed: &[&str], label: &str) -> ProofFeeMarketResult<()> {
    if allowed.iter().any(|candidate| candidate == &value) {
        Ok(())
    } else {
        Err(format!("{label} is not supported"))
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> ProofFeeMarketResult<()> {
    if values.is_empty() {
        return Err(format!("{label} list cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, label)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} values must be unique"));
        }
    }
    Ok(())
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    id: String,
    record: T,
    label: &str,
) -> ProofFeeMarketResult<String> {
    if records.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    records.insert(id.clone(), record);
    Ok(id)
}
