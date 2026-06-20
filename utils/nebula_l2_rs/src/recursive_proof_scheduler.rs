use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type RecursiveProofSchedulerResult<T> = Result<T, String>;

pub const RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION: &str =
    "nebula-l2-recursive-proof-scheduler-v1";
pub const RECURSIVE_PROOF_SCHEDULER_SCHEMA_VERSION: u64 = 1;
pub const RECURSIVE_PROOF_SCHEDULER_HASH_SUITE: &str = "SHAKE256";
pub const RECURSIVE_PROOF_SCHEDULER_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const RECURSIVE_PROOF_SCHEDULER_PQ_RECOVERY_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const RECURSIVE_PROOF_SCHEDULER_PQ_KEM_SCHEME: &str = "ML-KEM-768";
pub const RECURSIVE_PROOF_SCHEDULER_RECURSION_SCHEME: &str = "nebula-devnet-recursive-folding-v1";
pub const RECURSIVE_PROOF_SCHEDULER_COMPRESSION_SCHEME: &str =
    "shake256-recursive-proof-compression-receipt-v1";
pub const RECURSIVE_PROOF_SCHEDULER_STATE_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-state-transition-validity-v1";
pub const RECURSIVE_PROOF_SCHEDULER_BRIDGE_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-monero-bridge-validity-v1";
pub const RECURSIVE_PROOF_SCHEDULER_PRIVATE_CONTRACT_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-private-contract-validity-v1";
pub const RECURSIVE_PROOF_SCHEDULER_INTENT_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-intent-settlement-validity-v1";
pub const RECURSIVE_PROOF_SCHEDULER_FEE_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-fee-accounting-validity-v1";
pub const RECURSIVE_PROOF_SCHEDULER_RECURSIVE_PROOF_SYSTEM: &str =
    "nebula-devnet-pq-recursive-scheduler-validity-v1";

pub const RECURSIVE_PROOF_SCHEDULER_DEFAULT_SECURITY_BITS: u64 = 128;
pub const RECURSIVE_PROOF_SCHEDULER_DEFAULT_MAX_JOBS: usize = 1024;
pub const RECURSIVE_PROOF_SCHEDULER_DEFAULT_MAX_WINDOWS: usize = 128;
pub const RECURSIVE_PROOF_SCHEDULER_DEFAULT_MAX_ASSIGNMENTS: usize = 1024;
pub const RECURSIVE_PROOF_SCHEDULER_DEFAULT_MAX_ATTESTATIONS: usize = 2048;
pub const RECURSIVE_PROOF_SCHEDULER_DEFAULT_MAX_CHALLENGES: usize = 512;
pub const RECURSIVE_PROOF_SCHEDULER_DEFAULT_MAX_RECURSION_DEPTH: u64 = 4;
pub const RECURSIVE_PROOF_SCHEDULER_DEFAULT_MAX_CHILD_PROOFS: u64 = 64;
pub const RECURSIVE_PROOF_SCHEDULER_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const RECURSIVE_PROOF_SCHEDULER_DEFAULT_ASSIGNMENT_LEASE_BLOCKS: u64 = 12;
pub const RECURSIVE_PROOF_SCHEDULER_DEFAULT_COMPRESSION_TARGET_BYTES: u64 = 65_536;
pub const RECURSIVE_PROOF_SCHEDULER_DEFAULT_BASE_FEE_PER_MILLION_CYCLES: u64 = 25;
pub const RECURSIVE_PROOF_SCHEDULER_DEFAULT_PROTOCOL_FEE_BPS: u64 = 250;
pub const RECURSIVE_PROOF_SCHEDULER_DEFAULT_REBATE_BPS: u64 = 1_500;
pub const RECURSIVE_PROOF_SCHEDULER_DEFAULT_SLASHING_BPS: u64 = 5_000;
pub const RECURSIVE_PROOF_SCHEDULER_MAX_BPS: u64 = 10_000;
pub const RECURSIVE_PROOF_SCHEDULER_MIN_COMPRESSION_RATIO_BPS: u64 = 500;
pub const RECURSIVE_PROOF_SCHEDULER_MAX_LANE_WEIGHT: u64 = 10_000;

pub const RECURSIVE_PROOF_SCHEDULER_STATUS_PENDING: &str = "pending";
pub const RECURSIVE_PROOF_SCHEDULER_STATUS_ACTIVE: &str = "active";
pub const RECURSIVE_PROOF_SCHEDULER_STATUS_ASSIGNED: &str = "assigned";
pub const RECURSIVE_PROOF_SCHEDULER_STATUS_PROVING: &str = "proving";
pub const RECURSIVE_PROOF_SCHEDULER_STATUS_PROVED: &str = "proved";
pub const RECURSIVE_PROOF_SCHEDULER_STATUS_VERIFIED: &str = "verified";
pub const RECURSIVE_PROOF_SCHEDULER_STATUS_COMPRESSED: &str = "compressed";
pub const RECURSIVE_PROOF_SCHEDULER_STATUS_FAILED: &str = "failed";
pub const RECURSIVE_PROOF_SCHEDULER_STATUS_CHALLENGED: &str = "challenged";
pub const RECURSIVE_PROOF_SCHEDULER_STATUS_RESOLVED: &str = "resolved";
pub const RECURSIVE_PROOF_SCHEDULER_STATUS_SETTLED: &str = "settled";
pub const RECURSIVE_PROOF_SCHEDULER_STATUS_SLASHED: &str = "slashed";
pub const RECURSIVE_PROOF_SCHEDULER_STATUS_EXPIRED: &str = "expired";
pub const RECURSIVE_PROOF_SCHEDULER_STATUS_REJECTED: &str = "rejected";
pub const RECURSIVE_PROOF_SCHEDULER_STATUS_SEALED: &str = "sealed";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursiveCircuitFamily {
    RollupState,
    MoneroBridge,
    PrivateContract,
    IntentSettlement,
    FeeAccounting,
    RecursiveAggregation,
}

impl RecursiveCircuitFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RollupState => "rollup_state",
            Self::MoneroBridge => "monero_bridge",
            Self::PrivateContract => "private_contract",
            Self::IntentSettlement => "intent_settlement",
            Self::FeeAccounting => "fee_accounting",
            Self::RecursiveAggregation => "recursive_aggregation",
        }
    }

    pub fn default_circuit_name(self) -> &'static str {
        match self {
            Self::RollupState => "rollup_state_transition_batch",
            Self::MoneroBridge => "monero_bridge_finality_batch",
            Self::PrivateContract => "private_contract_execution_frame",
            Self::IntentSettlement => "private_intent_settlement_batch",
            Self::FeeAccounting => "fee_rebate_accounting_batch",
            Self::RecursiveAggregation => "recursive_proof_scheduler_batch",
        }
    }

    pub fn default_proof_system(self) -> &'static str {
        match self {
            Self::RollupState => RECURSIVE_PROOF_SCHEDULER_STATE_PROOF_SYSTEM,
            Self::MoneroBridge => RECURSIVE_PROOF_SCHEDULER_BRIDGE_PROOF_SYSTEM,
            Self::PrivateContract => RECURSIVE_PROOF_SCHEDULER_PRIVATE_CONTRACT_PROOF_SYSTEM,
            Self::IntentSettlement => RECURSIVE_PROOF_SCHEDULER_INTENT_PROOF_SYSTEM,
            Self::FeeAccounting => RECURSIVE_PROOF_SCHEDULER_FEE_PROOF_SYSTEM,
            Self::RecursiveAggregation => RECURSIVE_PROOF_SCHEDULER_RECURSIVE_PROOF_SYSTEM,
        }
    }

    pub fn is_recursive(self) -> bool {
        matches!(self, Self::RecursiveAggregation)
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::MoneroBridge
                | Self::PrivateContract
                | Self::IntentSettlement
                | Self::FeeAccounting
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofJobKind {
    StateTransition,
    BridgeFinality,
    PrivateContractCall,
    IntentSettlement,
    FeeRebateAccounting,
    RecursiveAggregate,
    Compression,
    WatchtowerFallback,
}

impl ProofJobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StateTransition => "state_transition",
            Self::BridgeFinality => "bridge_finality",
            Self::PrivateContractCall => "private_contract_call",
            Self::IntentSettlement => "intent_settlement",
            Self::FeeRebateAccounting => "fee_rebate_accounting",
            Self::RecursiveAggregate => "recursive_aggregate",
            Self::Compression => "compression",
            Self::WatchtowerFallback => "watchtower_fallback",
        }
    }

    pub fn default_family(self) -> RecursiveCircuitFamily {
        match self {
            Self::StateTransition => RecursiveCircuitFamily::RollupState,
            Self::BridgeFinality => RecursiveCircuitFamily::MoneroBridge,
            Self::PrivateContractCall => RecursiveCircuitFamily::PrivateContract,
            Self::IntentSettlement => RecursiveCircuitFamily::IntentSettlement,
            Self::FeeRebateAccounting => RecursiveCircuitFamily::FeeAccounting,
            Self::RecursiveAggregate | Self::Compression | Self::WatchtowerFallback => {
                RecursiveCircuitFamily::RecursiveAggregation
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofPriorityLane {
    Bridge,
    PrivateContracts,
    Intents,
    PublicRollup,
    FeeRebates,
    Emergency,
    Maintenance,
}

impl ProofPriorityLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bridge => "bridge",
            Self::PrivateContracts => "private_contracts",
            Self::Intents => "intents",
            Self::PublicRollup => "public_rollup",
            Self::FeeRebates => "fee_rebates",
            Self::Emergency => "emergency",
            Self::Maintenance => "maintenance",
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::Emergency => 10_000,
            Self::Bridge => 9_200,
            Self::PrivateContracts => 8_500,
            Self::Intents => 7_800,
            Self::PublicRollup => 6_500,
            Self::FeeRebates => 5_900,
            Self::Maintenance => 2_500,
        }
    }

    pub fn default_wait_blocks(self) -> u64 {
        match self {
            Self::Emergency => 1,
            Self::Bridge => 2,
            Self::PrivateContracts => 4,
            Self::Intents => 5,
            Self::PublicRollup => 8,
            Self::FeeRebates => 12,
            Self::Maintenance => 32,
        }
    }

    pub fn requires_private_inputs(self) -> bool {
        matches!(
            self,
            Self::Bridge | Self::PrivateContracts | Self::Intents | Self::FeeRebates
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofJobStatus {
    Pending,
    Assigned,
    Proving,
    Proved,
    Verified,
    Compressed,
    Failed,
    Challenged,
    Settled,
    Expired,
    Rejected,
}

impl ProofJobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => RECURSIVE_PROOF_SCHEDULER_STATUS_PENDING,
            Self::Assigned => RECURSIVE_PROOF_SCHEDULER_STATUS_ASSIGNED,
            Self::Proving => RECURSIVE_PROOF_SCHEDULER_STATUS_PROVING,
            Self::Proved => RECURSIVE_PROOF_SCHEDULER_STATUS_PROVED,
            Self::Verified => RECURSIVE_PROOF_SCHEDULER_STATUS_VERIFIED,
            Self::Compressed => RECURSIVE_PROOF_SCHEDULER_STATUS_COMPRESSED,
            Self::Failed => RECURSIVE_PROOF_SCHEDULER_STATUS_FAILED,
            Self::Challenged => RECURSIVE_PROOF_SCHEDULER_STATUS_CHALLENGED,
            Self::Settled => RECURSIVE_PROOF_SCHEDULER_STATUS_SETTLED,
            Self::Expired => RECURSIVE_PROOF_SCHEDULER_STATUS_EXPIRED,
            Self::Rejected => RECURSIVE_PROOF_SCHEDULER_STATUS_REJECTED,
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Compressed | Self::Failed | Self::Settled | Self::Expired | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursionNodeStatus {
    Open,
    Ready,
    Sealed,
    Verified,
    Challenged,
    Finalized,
}

impl RecursionNodeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Ready => "ready",
            Self::Sealed => RECURSIVE_PROOF_SCHEDULER_STATUS_SEALED,
            Self::Verified => RECURSIVE_PROOF_SCHEDULER_STATUS_VERIFIED,
            Self::Challenged => RECURSIVE_PROOF_SCHEDULER_STATUS_CHALLENGED,
            Self::Finalized => "finalized",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationWindowKind {
    BridgeFinality,
    PrivateContracts,
    IntentSettlement,
    PublicRollup,
    FeeRebates,
    RecursiveMaintenance,
}

impl AggregationWindowKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeFinality => "bridge_finality",
            Self::PrivateContracts => "private_contracts",
            Self::IntentSettlement => "intent_settlement",
            Self::PublicRollup => "public_rollup",
            Self::FeeRebates => "fee_rebates",
            Self::RecursiveMaintenance => "recursive_maintenance",
        }
    }

    pub fn default_lane(self) -> ProofPriorityLane {
        match self {
            Self::BridgeFinality => ProofPriorityLane::Bridge,
            Self::PrivateContracts => ProofPriorityLane::PrivateContracts,
            Self::IntentSettlement => ProofPriorityLane::Intents,
            Self::PublicRollup => ProofPriorityLane::PublicRollup,
            Self::FeeRebates => ProofPriorityLane::FeeRebates,
            Self::RecursiveMaintenance => ProofPriorityLane::Maintenance,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationWindowStatus {
    Open,
    Sealed,
    Assigned,
    Proved,
    Verified,
    Settled,
    Expired,
}

impl AggregationWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => RECURSIVE_PROOF_SCHEDULER_STATUS_SEALED,
            Self::Assigned => RECURSIVE_PROOF_SCHEDULER_STATUS_ASSIGNED,
            Self::Proved => RECURSIVE_PROOF_SCHEDULER_STATUS_PROVED,
            Self::Verified => RECURSIVE_PROOF_SCHEDULER_STATUS_VERIFIED,
            Self::Settled => RECURSIVE_PROOF_SCHEDULER_STATUS_SETTLED,
            Self::Expired => RECURSIVE_PROOF_SCHEDULER_STATUS_EXPIRED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketAssignmentStatus {
    Offered,
    Assigned,
    Accepted,
    Completed,
    Disputed,
    Settled,
    Slashed,
    Expired,
}

impl MarketAssignmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Assigned => RECURSIVE_PROOF_SCHEDULER_STATUS_ASSIGNED,
            Self::Accepted => "accepted",
            Self::Completed => "completed",
            Self::Disputed => "disputed",
            Self::Settled => RECURSIVE_PROOF_SCHEDULER_STATUS_SETTLED,
            Self::Slashed => RECURSIVE_PROOF_SCHEDULER_STATUS_SLASHED,
            Self::Expired => RECURSIVE_PROOF_SCHEDULER_STATUS_EXPIRED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqProverAttestationRole {
    Prover,
    Scheduler,
    Verifier,
    Watchtower,
    Challenger,
}

impl PqProverAttestationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prover => "prover",
            Self::Scheduler => "scheduler",
            Self::Verifier => "verifier",
            Self::Watchtower => "watchtower",
            Self::Challenger => "challenger",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionReceiptStatus {
    Pending,
    Accepted,
    Rejected,
    Challenged,
}

impl CompressionReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => RECURSIVE_PROOF_SCHEDULER_STATUS_PENDING,
            Self::Accepted => "accepted",
            Self::Rejected => RECURSIVE_PROOF_SCHEDULER_STATUS_REJECTED,
            Self::Challenged => RECURSIVE_PROOF_SCHEDULER_STATUS_CHALLENGED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeKind {
    MissingChildProof,
    InvalidPublicInput,
    RecursiveAccumulatorMismatch,
    CompressionMismatch,
    BadPqAttestation,
    MarketAssignmentTimeout,
    FeeAccountingMismatch,
    BridgeFinalityMismatch,
    PrivateContractTraceMismatch,
    IntentSettlementMismatch,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingChildProof => "missing_child_proof",
            Self::InvalidPublicInput => "invalid_public_input",
            Self::RecursiveAccumulatorMismatch => "recursive_accumulator_mismatch",
            Self::CompressionMismatch => "compression_mismatch",
            Self::BadPqAttestation => "bad_pq_attestation",
            Self::MarketAssignmentTimeout => "market_assignment_timeout",
            Self::FeeAccountingMismatch => "fee_accounting_mismatch",
            Self::BridgeFinalityMismatch => "bridge_finality_mismatch",
            Self::PrivateContractTraceMismatch => "private_contract_trace_mismatch",
            Self::IntentSettlementMismatch => "intent_settlement_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeOutcome {
    Open,
    ProofAccepted,
    ProofRejected,
    Reaggregate,
    SlashProver,
    RefundRequester,
    ExtendDeadline,
}

impl ChallengeOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::ProofAccepted => "proof_accepted",
            Self::ProofRejected => "proof_rejected",
            Self::Reaggregate => "reaggregate",
            Self::SlashProver => "slash_prover",
            Self::RefundRequester => "refund_requester",
            Self::ExtendDeadline => "extend_deadline",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeLedgerEntryKind {
    JobEscrow,
    ProverPayment,
    ProtocolFee,
    SponsorRebate,
    ChallengeBond,
    Slashing,
    Refund,
}

impl FeeLedgerEntryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JobEscrow => "job_escrow",
            Self::ProverPayment => "prover_payment",
            Self::ProtocolFee => "protocol_fee",
            Self::SponsorRebate => "sponsor_rebate",
            Self::ChallengeBond => "challenge_bond",
            Self::Slashing => "slashing",
            Self::Refund => "refund",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveProofSchedulerConfig {
    pub config_id: String,
    pub max_jobs: u64,
    pub max_windows: u64,
    pub max_assignments: u64,
    pub max_attestations: u64,
    pub max_challenges: u64,
    pub max_recursion_depth: u64,
    pub max_child_proofs_per_node: u64,
    pub challenge_window_blocks: u64,
    pub assignment_lease_blocks: u64,
    pub compression_target_bytes: u64,
    pub default_security_bits: u64,
    pub base_fee_per_million_cycles: u64,
    pub protocol_fee_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub slashing_bps: u64,
    pub bridge_lane_reserve_bps: u64,
    pub private_contract_lane_reserve_bps: u64,
    pub intent_lane_reserve_bps: u64,
    pub default_fee_asset_id: String,
    pub require_pq_attestations: bool,
    pub require_compression_receipts: bool,
    pub allow_devnet_fixtures: bool,
    pub deterministic_tie_breaker_root: String,
}

impl Default for RecursiveProofSchedulerConfig {
    fn default() -> Self {
        let mut config = Self {
            config_id: String::new(),
            max_jobs: RECURSIVE_PROOF_SCHEDULER_DEFAULT_MAX_JOBS as u64,
            max_windows: RECURSIVE_PROOF_SCHEDULER_DEFAULT_MAX_WINDOWS as u64,
            max_assignments: RECURSIVE_PROOF_SCHEDULER_DEFAULT_MAX_ASSIGNMENTS as u64,
            max_attestations: RECURSIVE_PROOF_SCHEDULER_DEFAULT_MAX_ATTESTATIONS as u64,
            max_challenges: RECURSIVE_PROOF_SCHEDULER_DEFAULT_MAX_CHALLENGES as u64,
            max_recursion_depth: RECURSIVE_PROOF_SCHEDULER_DEFAULT_MAX_RECURSION_DEPTH,
            max_child_proofs_per_node: RECURSIVE_PROOF_SCHEDULER_DEFAULT_MAX_CHILD_PROOFS,
            challenge_window_blocks: RECURSIVE_PROOF_SCHEDULER_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            assignment_lease_blocks: RECURSIVE_PROOF_SCHEDULER_DEFAULT_ASSIGNMENT_LEASE_BLOCKS,
            compression_target_bytes: RECURSIVE_PROOF_SCHEDULER_DEFAULT_COMPRESSION_TARGET_BYTES,
            default_security_bits: RECURSIVE_PROOF_SCHEDULER_DEFAULT_SECURITY_BITS,
            base_fee_per_million_cycles:
                RECURSIVE_PROOF_SCHEDULER_DEFAULT_BASE_FEE_PER_MILLION_CYCLES,
            protocol_fee_bps: RECURSIVE_PROOF_SCHEDULER_DEFAULT_PROTOCOL_FEE_BPS,
            sponsor_rebate_bps: RECURSIVE_PROOF_SCHEDULER_DEFAULT_REBATE_BPS,
            slashing_bps: RECURSIVE_PROOF_SCHEDULER_DEFAULT_SLASHING_BPS,
            bridge_lane_reserve_bps: 2_500,
            private_contract_lane_reserve_bps: 2_000,
            intent_lane_reserve_bps: 1_500,
            default_fee_asset_id: "asset:wxmr".to_string(),
            require_pq_attestations: true,
            require_compression_receipts: true,
            allow_devnet_fixtures: true,
            deterministic_tie_breaker_root: deterministic_root("scheduler-config-tie-breaker"),
        };
        config.config_id = recursive_proof_scheduler_config_id(&config.identity_record());
        config
    }
}

impl RecursiveProofSchedulerConfig {
    pub fn identity_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_scheduler_config",
            "chain_id": CHAIN_ID,
            "protocol_version": RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION,
            "schema_version": RECURSIVE_PROOF_SCHEDULER_SCHEMA_VERSION,
            "max_jobs": self.max_jobs,
            "max_windows": self.max_windows,
            "max_assignments": self.max_assignments,
            "max_attestations": self.max_attestations,
            "max_challenges": self.max_challenges,
            "max_recursion_depth": self.max_recursion_depth,
            "max_child_proofs_per_node": self.max_child_proofs_per_node,
            "challenge_window_blocks": self.challenge_window_blocks,
            "assignment_lease_blocks": self.assignment_lease_blocks,
            "compression_target_bytes": self.compression_target_bytes,
            "default_security_bits": self.default_security_bits,
            "base_fee_per_million_cycles": self.base_fee_per_million_cycles,
            "protocol_fee_bps": self.protocol_fee_bps,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "slashing_bps": self.slashing_bps,
            "bridge_lane_reserve_bps": self.bridge_lane_reserve_bps,
            "private_contract_lane_reserve_bps": self.private_contract_lane_reserve_bps,
            "intent_lane_reserve_bps": self.intent_lane_reserve_bps,
            "default_fee_asset_id": self.default_fee_asset_id,
            "require_pq_attestations": self.require_pq_attestations,
            "require_compression_receipts": self.require_compression_receipts,
            "allow_devnet_fixtures": self.allow_devnet_fixtures,
            "deterministic_tie_breaker_root": self.deterministic_tie_breaker_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("recursive proof scheduler config record object")
            .insert(
                "config_id".to_string(),
                Value::String(self.config_id.clone()),
            );
        record
    }

    pub fn config_root(&self) -> String {
        recursive_proof_scheduler_payload_root(
            "RECURSIVE-PROOF-SCHEDULER-CONFIG",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> RecursiveProofSchedulerResult<String> {
        ensure_non_empty(&self.config_id, "recursive scheduler config id")?;
        ensure_non_empty(
            &self.default_fee_asset_id,
            "recursive scheduler default fee asset",
        )?;
        ensure_hash(
            &self.deterministic_tie_breaker_root,
            "recursive scheduler tie breaker root",
        )?;
        if self.max_jobs == 0 || self.max_windows == 0 || self.max_assignments == 0 {
            return Err("recursive scheduler config limits must be non-zero".to_string());
        }
        if self.max_recursion_depth == 0 {
            return Err("recursive scheduler recursion depth must be non-zero".to_string());
        }
        if self.max_child_proofs_per_node == 0 {
            return Err("recursive scheduler child proof limit must be non-zero".to_string());
        }
        if self.challenge_window_blocks == 0 || self.assignment_lease_blocks == 0 {
            return Err("recursive scheduler windows must be non-zero".to_string());
        }
        ensure_bps(
            self.protocol_fee_bps,
            "recursive scheduler protocol fee bps",
        )?;
        ensure_bps(
            self.sponsor_rebate_bps,
            "recursive scheduler sponsor rebate bps",
        )?;
        ensure_bps(self.slashing_bps, "recursive scheduler slashing bps")?;
        ensure_bps(
            self.bridge_lane_reserve_bps,
            "recursive scheduler bridge reserve bps",
        )?;
        ensure_bps(
            self.private_contract_lane_reserve_bps,
            "recursive scheduler private contract reserve bps",
        )?;
        ensure_bps(
            self.intent_lane_reserve_bps,
            "recursive scheduler intent reserve bps",
        )?;
        let reserve_total = self
            .bridge_lane_reserve_bps
            .saturating_add(self.private_contract_lane_reserve_bps)
            .saturating_add(self.intent_lane_reserve_bps);
        if reserve_total > RECURSIVE_PROOF_SCHEDULER_MAX_BPS {
            return Err("recursive scheduler lane reserves exceed 100%".to_string());
        }
        if self.config_id != recursive_proof_scheduler_config_id(&self.identity_record()) {
            return Err("recursive scheduler config id mismatch".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitFamilyManifest {
    pub manifest_id: String,
    pub family: RecursiveCircuitFamily,
    pub circuit_name: String,
    pub manifest_version: u64,
    pub proof_system: String,
    pub verifier_key_root: String,
    pub public_input_schema_root: String,
    pub witness_schema_root: String,
    pub recursion_program_root: String,
    pub max_public_inputs: u64,
    pub max_witness_bytes: u64,
    pub target_proof_bytes: u64,
    pub target_verify_micros: u64,
    pub max_child_proofs: u64,
    pub security_bits: u64,
    pub activation_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
    pub status: String,
}

impl CircuitFamilyManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        family: RecursiveCircuitFamily,
        manifest_version: u64,
        circuit_name: impl Into<String>,
        proof_system: impl Into<String>,
        verifier_key_root: impl Into<String>,
        max_public_inputs: u64,
        max_witness_bytes: u64,
        target_proof_bytes: u64,
        target_verify_micros: u64,
        max_child_proofs: u64,
        security_bits: u64,
        activation_height: u64,
        expires_at_height: u64,
        metadata: &Value,
    ) -> RecursiveProofSchedulerResult<Self> {
        let circuit_name = circuit_name.into();
        let proof_system = proof_system.into();
        let verifier_key_root = verifier_key_root.into();
        ensure_non_empty(&circuit_name, "circuit family circuit name")?;
        ensure_non_empty(&proof_system, "circuit family proof system")?;
        ensure_hash(&verifier_key_root, "circuit family verifier key root")?;
        let metadata_root = recursive_proof_scheduler_payload_root(
            "RECURSIVE-PROOF-SCHEDULER-MANIFEST-METADATA",
            metadata,
        );
        let public_input_schema_root = circuit_public_input_schema_root(
            family.as_str(),
            &circuit_name,
            manifest_version,
            max_public_inputs,
            &metadata_root,
        );
        let witness_schema_root = circuit_witness_schema_root(
            family.as_str(),
            &circuit_name,
            manifest_version,
            max_witness_bytes,
            &metadata_root,
        );
        let recursion_program_root = recursion_program_root(
            family.as_str(),
            &circuit_name,
            manifest_version,
            &proof_system,
            &verifier_key_root,
        );
        let manifest_id = circuit_family_manifest_id(
            family.as_str(),
            &circuit_name,
            manifest_version,
            &proof_system,
            &verifier_key_root,
            &public_input_schema_root,
        );
        let manifest = Self {
            manifest_id,
            family,
            circuit_name,
            manifest_version,
            proof_system,
            verifier_key_root,
            public_input_schema_root,
            witness_schema_root,
            recursion_program_root,
            max_public_inputs,
            max_witness_bytes,
            target_proof_bytes,
            target_verify_micros,
            max_child_proofs,
            security_bits,
            activation_height,
            expires_at_height,
            metadata_root,
            status: RECURSIVE_PROOF_SCHEDULER_STATUS_ACTIVE.to_string(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == RECURSIVE_PROOF_SCHEDULER_STATUS_ACTIVE
            && height >= self.activation_height
            && (self.expires_at_height == 0 || height < self.expires_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_scheduler_circuit_family_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION,
            "manifest_id": self.manifest_id,
            "family": self.family.as_str(),
            "circuit_name": self.circuit_name,
            "manifest_version": self.manifest_version,
            "proof_system": self.proof_system,
            "verifier_key_root": self.verifier_key_root,
            "public_input_schema_root": self.public_input_schema_root,
            "witness_schema_root": self.witness_schema_root,
            "recursion_program_root": self.recursion_program_root,
            "max_public_inputs": self.max_public_inputs,
            "max_witness_bytes": self.max_witness_bytes,
            "target_proof_bytes": self.target_proof_bytes,
            "target_verify_micros": self.target_verify_micros,
            "max_child_proofs": self.max_child_proofs,
            "security_bits": self.security_bits,
            "activation_height": self.activation_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> RecursiveProofSchedulerResult<String> {
        ensure_hash(&self.manifest_id, "circuit family manifest id")?;
        ensure_non_empty(&self.circuit_name, "circuit family circuit name")?;
        ensure_non_empty(&self.proof_system, "circuit family proof system")?;
        ensure_hash(&self.verifier_key_root, "circuit family verifier key root")?;
        ensure_hash(
            &self.public_input_schema_root,
            "circuit family public input schema root",
        )?;
        ensure_hash(
            &self.witness_schema_root,
            "circuit family witness schema root",
        )?;
        ensure_hash(
            &self.recursion_program_root,
            "circuit family recursion program root",
        )?;
        ensure_hash(&self.metadata_root, "circuit family metadata root")?;
        if self.manifest_version == 0 {
            return Err("circuit family manifest version must be non-zero".to_string());
        }
        if self.max_public_inputs == 0 || self.max_witness_bytes == 0 {
            return Err("circuit family schema limits must be non-zero".to_string());
        }
        if self.target_proof_bytes == 0 || self.target_verify_micros == 0 {
            return Err("circuit family proof targets must be non-zero".to_string());
        }
        if self.security_bits < RECURSIVE_PROOF_SCHEDULER_DEFAULT_SECURITY_BITS {
            return Err("circuit family security bits below scheduler floor".to_string());
        }
        if self.family.is_recursive() && self.max_child_proofs == 0 {
            return Err("recursive circuit family must allow child proofs".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height <= self.activation_height {
            return Err("circuit family expiry must be after activation".to_string());
        }
        if self.manifest_id
            != circuit_family_manifest_id(
                self.family.as_str(),
                &self.circuit_name,
                self.manifest_version,
                &self.proof_system,
                &self.verifier_key_root,
                &self.public_input_schema_root,
            )
        {
            return Err("circuit family manifest id mismatch".to_string());
        }
        Ok(circuit_family_manifest_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorityLaneConfig {
    pub lane_id: String,
    pub lane: ProofPriorityLane,
    pub display_name: String,
    pub weight: u64,
    pub reserved_window_bps: u64,
    pub max_parallel_jobs: u64,
    pub max_wait_blocks: u64,
    pub sponsor_pool_id: String,
    pub fee_asset_id: String,
    pub allow_private_inputs: bool,
    pub requires_bridge_finality: bool,
    pub status: String,
}

impl PriorityLaneConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: ProofPriorityLane,
        display_name: impl Into<String>,
        reserved_window_bps: u64,
        max_parallel_jobs: u64,
        sponsor_pool_id: impl Into<String>,
        fee_asset_id: impl Into<String>,
        allow_private_inputs: bool,
        requires_bridge_finality: bool,
    ) -> RecursiveProofSchedulerResult<Self> {
        let display_name = display_name.into();
        let sponsor_pool_id = sponsor_pool_id.into();
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(&display_name, "priority lane display name")?;
        ensure_non_empty(&fee_asset_id, "priority lane fee asset")?;
        let lane_id = priority_lane_id(lane.as_str(), &display_name, reserved_window_bps);
        let record = Self {
            lane_id,
            lane,
            display_name,
            weight: lane.default_weight(),
            reserved_window_bps,
            max_parallel_jobs,
            max_wait_blocks: lane.default_wait_blocks(),
            sponsor_pool_id,
            fee_asset_id,
            allow_private_inputs,
            requires_bridge_finality,
            status: RECURSIVE_PROOF_SCHEDULER_STATUS_ACTIVE.to_string(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_scheduler_priority_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "lane": self.lane.as_str(),
            "display_name": self.display_name,
            "weight": self.weight,
            "reserved_window_bps": self.reserved_window_bps,
            "max_parallel_jobs": self.max_parallel_jobs,
            "max_wait_blocks": self.max_wait_blocks,
            "sponsor_pool_id": self.sponsor_pool_id,
            "fee_asset_id": self.fee_asset_id,
            "allow_private_inputs": self.allow_private_inputs,
            "requires_bridge_finality": self.requires_bridge_finality,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> RecursiveProofSchedulerResult<String> {
        ensure_hash(&self.lane_id, "priority lane id")?;
        ensure_non_empty(&self.display_name, "priority lane display name")?;
        ensure_non_empty(&self.fee_asset_id, "priority lane fee asset")?;
        ensure_bps(self.reserved_window_bps, "priority lane reserved bps")?;
        if self.weight == 0 || self.weight > RECURSIVE_PROOF_SCHEDULER_MAX_LANE_WEIGHT {
            return Err("priority lane weight is outside bounds".to_string());
        }
        if self.max_parallel_jobs == 0 {
            return Err("priority lane max parallel jobs must be non-zero".to_string());
        }
        if self.lane.requires_private_inputs() && !self.allow_private_inputs {
            return Err("privacy lane must allow private input roots".to_string());
        }
        if self.lane_id
            != priority_lane_id(
                self.lane.as_str(),
                &self.display_name,
                self.reserved_window_bps,
            )
        {
            return Err("priority lane id mismatch".to_string());
        }
        Ok(priority_lane_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationWindow {
    pub window_id: String,
    pub kind: AggregationWindowKind,
    pub lane: ProofPriorityLane,
    pub start_height: u64,
    pub end_height: u64,
    pub target_proof_count: u64,
    pub max_proof_count: u64,
    pub max_total_cycles: u64,
    pub min_fee_per_million_cycles: u64,
    pub sponsor_pool_id: String,
    pub eligible_family_root: String,
    pub admitted_job_ids: Vec<String>,
    pub admitted_job_root: String,
    pub sealed_at_height: u64,
    pub status: AggregationWindowStatus,
    pub metadata_root: String,
}

impl AggregationWindow {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: AggregationWindowKind,
        lane: ProofPriorityLane,
        start_height: u64,
        end_height: u64,
        target_proof_count: u64,
        max_proof_count: u64,
        max_total_cycles: u64,
        min_fee_per_million_cycles: u64,
        sponsor_pool_id: impl Into<String>,
        eligible_families: &[RecursiveCircuitFamily],
        metadata: &Value,
    ) -> RecursiveProofSchedulerResult<Self> {
        if end_height < start_height {
            return Err("aggregation window end height is before start height".to_string());
        }
        if target_proof_count == 0 || max_proof_count == 0 {
            return Err("aggregation window proof count limits must be non-zero".to_string());
        }
        if target_proof_count > max_proof_count {
            return Err("aggregation window target exceeds max proof count".to_string());
        }
        let sponsor_pool_id = sponsor_pool_id.into();
        let eligible_family_root = family_set_root(eligible_families);
        let metadata_root = recursive_proof_scheduler_payload_root(
            "RECURSIVE-PROOF-SCHEDULER-WINDOW-METADATA",
            metadata,
        );
        let admitted_job_ids = Vec::new();
        let admitted_job_root = string_set_root(
            "RECURSIVE-PROOF-SCHEDULER-WINDOW-ADMITTED-JOBS",
            &admitted_job_ids,
        );
        let window_id = aggregation_window_id(
            kind.as_str(),
            lane.as_str(),
            start_height,
            end_height,
            &eligible_family_root,
        );
        let record = Self {
            window_id,
            kind,
            lane,
            start_height,
            end_height,
            target_proof_count,
            max_proof_count,
            max_total_cycles,
            min_fee_per_million_cycles,
            sponsor_pool_id,
            eligible_family_root,
            admitted_job_ids,
            admitted_job_root,
            sealed_at_height: 0,
            status: AggregationWindowStatus::Open,
            metadata_root,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn contains_height(&self, height: u64) -> bool {
        height >= self.start_height && height <= self.end_height
    }

    pub fn remaining_capacity(&self) -> u64 {
        self.max_proof_count
            .saturating_sub(self.admitted_job_ids.len() as u64)
    }

    pub fn add_job(&mut self, job_id: impl Into<String>) -> RecursiveProofSchedulerResult<()> {
        if self.status != AggregationWindowStatus::Open {
            return Err("aggregation window is not open".to_string());
        }
        if self.remaining_capacity() == 0 {
            return Err("aggregation window is full".to_string());
        }
        let job_id = job_id.into();
        ensure_hash(&job_id, "aggregation window job id")?;
        if !self.admitted_job_ids.contains(&job_id) {
            self.admitted_job_ids.push(job_id);
            self.admitted_job_ids.sort();
            self.admitted_job_root = string_set_root(
                "RECURSIVE-PROOF-SCHEDULER-WINDOW-ADMITTED-JOBS",
                &self.admitted_job_ids,
            );
        }
        self.validate()?;
        Ok(())
    }

    pub fn seal(mut self, sealed_at_height: u64) -> RecursiveProofSchedulerResult<Self> {
        if sealed_at_height < self.start_height {
            return Err("aggregation window sealed before start height".to_string());
        }
        self.sealed_at_height = sealed_at_height;
        self.status = AggregationWindowStatus::Sealed;
        self.validate()?;
        Ok(self)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_scheduler_aggregation_window",
            "chain_id": CHAIN_ID,
            "protocol_version": RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "window_kind": self.kind.as_str(),
            "lane": self.lane.as_str(),
            "start_height": self.start_height,
            "end_height": self.end_height,
            "target_proof_count": self.target_proof_count,
            "max_proof_count": self.max_proof_count,
            "max_total_cycles": self.max_total_cycles,
            "min_fee_per_million_cycles": self.min_fee_per_million_cycles,
            "sponsor_pool_id": self.sponsor_pool_id,
            "eligible_family_root": self.eligible_family_root,
            "admitted_job_ids": self.admitted_job_ids,
            "admitted_job_root": self.admitted_job_root,
            "sealed_at_height": self.sealed_at_height,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn validate(&self) -> RecursiveProofSchedulerResult<String> {
        ensure_hash(&self.window_id, "aggregation window id")?;
        ensure_hash(
            &self.eligible_family_root,
            "aggregation window eligible family root",
        )?;
        ensure_hash(
            &self.admitted_job_root,
            "aggregation window admitted job root",
        )?;
        ensure_hash(&self.metadata_root, "aggregation window metadata root")?;
        if self.end_height < self.start_height {
            return Err("aggregation window end height is before start height".to_string());
        }
        if self.target_proof_count == 0 || self.max_proof_count == 0 {
            return Err("aggregation window proof count limits must be non-zero".to_string());
        }
        if self.target_proof_count > self.max_proof_count {
            return Err("aggregation window target proof count exceeds maximum".to_string());
        }
        if self.admitted_job_ids.len() as u64 > self.max_proof_count {
            return Err("aggregation window admitted jobs exceed max proof count".to_string());
        }
        ensure_hashes(
            &self.admitted_job_ids,
            "aggregation window admitted job ids",
        )?;
        let expected_admitted_root = string_set_root(
            "RECURSIVE-PROOF-SCHEDULER-WINDOW-ADMITTED-JOBS",
            &self.admitted_job_ids,
        );
        if self.admitted_job_root != expected_admitted_root {
            return Err("aggregation window admitted job root mismatch".to_string());
        }
        if self.status != AggregationWindowStatus::Open && self.sealed_at_height == 0 {
            return Err("sealed aggregation window must carry sealed height".to_string());
        }
        if self.window_id
            != aggregation_window_id(
                self.kind.as_str(),
                self.lane.as_str(),
                self.start_height,
                self.end_height,
                &self.eligible_family_root,
            )
        {
            return Err("aggregation window id mismatch".to_string());
        }
        Ok(aggregation_window_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofJob {
    pub job_id: String,
    pub job_kind: ProofJobKind,
    pub family: RecursiveCircuitFamily,
    pub lane: ProofPriorityLane,
    pub manifest_id: String,
    pub window_id: String,
    pub parent_node_id: String,
    pub requester_commitment: String,
    pub public_input_root: String,
    pub witness_commitment_root: String,
    pub source_payload_root: String,
    pub nullifier: String,
    pub required_security_bits: u64,
    pub estimated_cycles: u64,
    pub input_count: u64,
    pub source_bytes: u64,
    pub offered_fee_units: u64,
    pub max_fee_units: u64,
    pub rebate_eligible_units: u64,
    pub fee_asset_id: String,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub recursion_depth: u64,
    pub status: ProofJobStatus,
    pub assigned_prover_id: String,
    pub assignment_id: String,
    pub proof_commitment: String,
    pub proof_transcript_root: String,
    pub verified_at_height: u64,
    pub failure_root: String,
    pub metadata_root: String,
}

impl ProofJob {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_kind: ProofJobKind,
        family: RecursiveCircuitFamily,
        lane: ProofPriorityLane,
        manifest_id: impl Into<String>,
        window_id: impl Into<String>,
        parent_node_id: impl Into<String>,
        requester_commitment: impl Into<String>,
        public_input_root: impl Into<String>,
        witness_commitment_root: impl Into<String>,
        source_payload_root: impl Into<String>,
        required_security_bits: u64,
        estimated_cycles: u64,
        input_count: u64,
        source_bytes: u64,
        offered_fee_units: u64,
        max_fee_units: u64,
        rebate_eligible_units: u64,
        fee_asset_id: impl Into<String>,
        opened_at_height: u64,
        deadline_height: u64,
        recursion_depth: u64,
        nonce: u64,
        metadata: &Value,
    ) -> RecursiveProofSchedulerResult<Self> {
        let manifest_id = manifest_id.into();
        let window_id = window_id.into();
        let parent_node_id = parent_node_id.into();
        let requester_commitment = requester_commitment.into();
        let public_input_root = public_input_root.into();
        let witness_commitment_root = witness_commitment_root.into();
        let source_payload_root = source_payload_root.into();
        let fee_asset_id = fee_asset_id.into();
        ensure_hash(&manifest_id, "proof job manifest id")?;
        ensure_hash(&window_id, "proof job window id")?;
        ensure_hash_or_empty(&parent_node_id, "proof job parent node id")?;
        ensure_hash(&requester_commitment, "proof job requester commitment")?;
        ensure_hash(&public_input_root, "proof job public input root")?;
        ensure_hash(
            &witness_commitment_root,
            "proof job witness commitment root",
        )?;
        ensure_hash(&source_payload_root, "proof job source payload root")?;
        ensure_non_empty(&fee_asset_id, "proof job fee asset id")?;
        let metadata_root = recursive_proof_scheduler_payload_root(
            "RECURSIVE-PROOF-SCHEDULER-JOB-METADATA",
            metadata,
        );
        let nullifier = proof_job_nullifier(
            job_kind.as_str(),
            family.as_str(),
            &requester_commitment,
            &source_payload_root,
            opened_at_height,
            nonce,
        );
        let job_id = proof_job_id(
            job_kind.as_str(),
            family.as_str(),
            lane.as_str(),
            &manifest_id,
            &public_input_root,
            &source_payload_root,
            opened_at_height,
            nonce,
        );
        let record = Self {
            job_id,
            job_kind,
            family,
            lane,
            manifest_id,
            window_id,
            parent_node_id,
            requester_commitment,
            public_input_root,
            witness_commitment_root,
            source_payload_root,
            nullifier,
            required_security_bits,
            estimated_cycles,
            input_count,
            source_bytes,
            offered_fee_units,
            max_fee_units,
            rebate_eligible_units,
            fee_asset_id,
            opened_at_height,
            deadline_height,
            recursion_depth,
            status: ProofJobStatus::Pending,
            assigned_prover_id: String::new(),
            assignment_id: String::new(),
            proof_commitment: empty_root("RECURSIVE-PROOF-SCHEDULER-JOB-PROOF"),
            proof_transcript_root: empty_root("RECURSIVE-PROOF-SCHEDULER-JOB-TRANSCRIPT"),
            verified_at_height: 0,
            failure_root: empty_root("RECURSIVE-PROOF-SCHEDULER-JOB-FAILURE"),
            metadata_root,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn is_open_at(&self, height: u64) -> bool {
        !self.status.is_terminal() && height <= self.deadline_height
    }

    pub fn assign(
        &mut self,
        prover_id: impl Into<String>,
        assignment_id: impl Into<String>,
    ) -> RecursiveProofSchedulerResult<()> {
        if self.status != ProofJobStatus::Pending {
            return Err("proof job is not pending".to_string());
        }
        self.assigned_prover_id = prover_id.into();
        self.assignment_id = assignment_id.into();
        ensure_non_empty(&self.assigned_prover_id, "proof job assigned prover")?;
        ensure_hash(&self.assignment_id, "proof job assignment id")?;
        self.status = ProofJobStatus::Assigned;
        self.validate()?;
        Ok(())
    }

    pub fn mark_proving(&mut self) -> RecursiveProofSchedulerResult<()> {
        if self.status != ProofJobStatus::Assigned {
            return Err("proof job must be assigned before proving".to_string());
        }
        self.status = ProofJobStatus::Proving;
        self.validate()?;
        Ok(())
    }

    pub fn mark_proved(
        &mut self,
        proof_commitment: impl Into<String>,
        proof_transcript_root: impl Into<String>,
    ) -> RecursiveProofSchedulerResult<()> {
        if !matches!(
            self.status,
            ProofJobStatus::Assigned | ProofJobStatus::Proving
        ) {
            return Err("proof job must be assigned or proving before proved".to_string());
        }
        self.proof_commitment = proof_commitment.into();
        self.proof_transcript_root = proof_transcript_root.into();
        ensure_hash(&self.proof_commitment, "proof job proof commitment")?;
        ensure_hash(
            &self.proof_transcript_root,
            "proof job proof transcript root",
        )?;
        self.status = ProofJobStatus::Proved;
        self.validate()?;
        Ok(())
    }

    pub fn mark_verified(&mut self, verified_at_height: u64) -> RecursiveProofSchedulerResult<()> {
        if self.status != ProofJobStatus::Proved {
            return Err("proof job must be proved before verification".to_string());
        }
        if verified_at_height < self.opened_at_height {
            return Err("proof job verified before it opened".to_string());
        }
        self.verified_at_height = verified_at_height;
        self.status = ProofJobStatus::Verified;
        self.validate()?;
        Ok(())
    }

    pub fn mark_compressed(&mut self) -> RecursiveProofSchedulerResult<()> {
        if self.status != ProofJobStatus::Verified {
            return Err("proof job must be verified before compression".to_string());
        }
        self.status = ProofJobStatus::Compressed;
        self.validate()?;
        Ok(())
    }

    pub fn fail(
        &mut self,
        failure_root: impl Into<String>,
        rejected: bool,
    ) -> RecursiveProofSchedulerResult<()> {
        self.failure_root = failure_root.into();
        ensure_hash(&self.failure_root, "proof job failure root")?;
        self.status = if rejected {
            ProofJobStatus::Rejected
        } else {
            ProofJobStatus::Failed
        };
        self.validate()?;
        Ok(())
    }

    pub fn priority_score(&self, current_height: u64, lane_weight: u64) -> u64 {
        let age = current_height.saturating_sub(self.opened_at_height);
        let deadline_pressure = if current_height >= self.deadline_height {
            10_000
        } else {
            let remaining = self.deadline_height.saturating_sub(current_height).max(1);
            10_000_u64.saturating_sub(remaining.saturating_mul(100).min(9_500))
        };
        lane_weight
            .saturating_add(self.lane.default_weight())
            .saturating_add(age.saturating_mul(25))
            .saturating_add(deadline_pressure)
            .saturating_add(self.offered_fee_units / 1_000)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_scheduler_proof_job",
            "chain_id": CHAIN_ID,
            "protocol_version": RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION,
            "job_id": self.job_id,
            "job_kind": self.job_kind.as_str(),
            "family": self.family.as_str(),
            "lane": self.lane.as_str(),
            "manifest_id": self.manifest_id,
            "window_id": self.window_id,
            "parent_node_id": self.parent_node_id,
            "requester_commitment": self.requester_commitment,
            "public_input_root": self.public_input_root,
            "witness_commitment_root": self.witness_commitment_root,
            "source_payload_root": self.source_payload_root,
            "nullifier": self.nullifier,
            "required_security_bits": self.required_security_bits,
            "estimated_cycles": self.estimated_cycles,
            "input_count": self.input_count,
            "source_bytes": self.source_bytes,
            "offered_fee_units": self.offered_fee_units,
            "max_fee_units": self.max_fee_units,
            "rebate_eligible_units": self.rebate_eligible_units,
            "fee_asset_id": self.fee_asset_id,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "recursion_depth": self.recursion_depth,
            "status": self.status.as_str(),
            "assigned_prover_id": self.assigned_prover_id,
            "assignment_id": self.assignment_id,
            "proof_commitment": self.proof_commitment,
            "proof_transcript_root": self.proof_transcript_root,
            "verified_at_height": self.verified_at_height,
            "failure_root": self.failure_root,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn validate(&self) -> RecursiveProofSchedulerResult<String> {
        ensure_hash(&self.job_id, "proof job id")?;
        ensure_hash(&self.manifest_id, "proof job manifest id")?;
        ensure_hash(&self.window_id, "proof job window id")?;
        ensure_hash_or_empty(&self.parent_node_id, "proof job parent node id")?;
        ensure_hash(&self.requester_commitment, "proof job requester commitment")?;
        ensure_hash(&self.public_input_root, "proof job public input root")?;
        ensure_hash(
            &self.witness_commitment_root,
            "proof job witness commitment root",
        )?;
        ensure_hash(&self.source_payload_root, "proof job source payload root")?;
        ensure_hash(&self.nullifier, "proof job nullifier")?;
        ensure_hash(&self.proof_commitment, "proof job proof commitment")?;
        ensure_hash(&self.proof_transcript_root, "proof job transcript root")?;
        ensure_hash(&self.failure_root, "proof job failure root")?;
        ensure_hash(&self.metadata_root, "proof job metadata root")?;
        ensure_non_empty(&self.fee_asset_id, "proof job fee asset")?;
        if self.family != self.job_kind.default_family()
            && self.job_kind != ProofJobKind::Compression
        {
            return Err("proof job family does not match job kind".to_string());
        }
        if self.required_security_bits < RECURSIVE_PROOF_SCHEDULER_DEFAULT_SECURITY_BITS {
            return Err("proof job security bits below scheduler floor".to_string());
        }
        if self.estimated_cycles == 0 || self.input_count == 0 || self.source_bytes == 0 {
            return Err("proof job cycle/input/source estimates must be non-zero".to_string());
        }
        if self.offered_fee_units > self.max_fee_units {
            return Err("proof job offered fee exceeds max fee".to_string());
        }
        if self.rebate_eligible_units > self.offered_fee_units {
            return Err("proof job rebate exceeds offered fee".to_string());
        }
        if self.deadline_height <= self.opened_at_height {
            return Err("proof job deadline must be after opened height".to_string());
        }
        if self.recursion_depth > RECURSIVE_PROOF_SCHEDULER_DEFAULT_MAX_RECURSION_DEPTH + 64 {
            return Err("proof job recursion depth is unreasonably high".to_string());
        }
        if matches!(
            self.status,
            ProofJobStatus::Assigned
                | ProofJobStatus::Proving
                | ProofJobStatus::Proved
                | ProofJobStatus::Verified
                | ProofJobStatus::Compressed
                | ProofJobStatus::Settled
        ) {
            ensure_non_empty(&self.assigned_prover_id, "proof job assigned prover")?;
            ensure_hash(&self.assignment_id, "proof job assignment id")?;
        }
        if matches!(
            self.status,
            ProofJobStatus::Proved | ProofJobStatus::Verified | ProofJobStatus::Compressed
        ) && (self.proof_commitment == empty_root("RECURSIVE-PROOF-SCHEDULER-JOB-PROOF")
            || self.proof_transcript_root == empty_root("RECURSIVE-PROOF-SCHEDULER-JOB-TRANSCRIPT"))
        {
            return Err("proved proof job must carry proof commitment and transcript".to_string());
        }
        if matches!(
            self.status,
            ProofJobStatus::Verified | ProofJobStatus::Compressed
        ) && self.verified_at_height == 0
        {
            return Err("verified proof job must carry verification height".to_string());
        }
        Ok(proof_job_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursionTreeNode {
    pub node_id: String,
    pub tree_id: String,
    pub parent_node_id: String,
    pub depth: u64,
    pub lane: ProofPriorityLane,
    pub family: RecursiveCircuitFamily,
    pub child_job_ids: Vec<String>,
    pub child_node_ids: Vec<String>,
    pub child_proof_root: String,
    pub child_node_root: String,
    pub public_input_root: String,
    pub accumulator_root: String,
    pub recursion_program_root: String,
    pub batch_start_height: u64,
    pub batch_end_height: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub verified_at_height: u64,
    pub max_child_proofs: u64,
    pub status: RecursionNodeStatus,
    pub metadata_root: String,
}

impl RecursionTreeNode {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tree_id: impl Into<String>,
        parent_node_id: impl Into<String>,
        depth: u64,
        lane: ProofPriorityLane,
        family: RecursiveCircuitFamily,
        child_job_ids: Vec<String>,
        child_node_ids: Vec<String>,
        recursion_program_root: impl Into<String>,
        batch_start_height: u64,
        batch_end_height: u64,
        opened_at_height: u64,
        max_child_proofs: u64,
        metadata: &Value,
    ) -> RecursiveProofSchedulerResult<Self> {
        let tree_id = tree_id.into();
        let parent_node_id = parent_node_id.into();
        let recursion_program_root = recursion_program_root.into();
        ensure_hash(&tree_id, "recursion tree id")?;
        ensure_hash_or_empty(&parent_node_id, "recursion parent node id")?;
        ensure_hash(
            &recursion_program_root,
            "recursion tree node recursion program root",
        )?;
        ensure_hashes(&child_job_ids, "recursion tree child job ids")?;
        ensure_hashes(&child_node_ids, "recursion tree child node ids")?;
        if child_job_ids.is_empty() && child_node_ids.is_empty() {
            return Err("recursion tree node must reference a child job or node".to_string());
        }
        let child_proof_root = string_set_root(
            "RECURSIVE-PROOF-SCHEDULER-RECURSION-CHILD-JOBS",
            &child_job_ids,
        );
        let child_node_root = string_set_root(
            "RECURSIVE-PROOF-SCHEDULER-RECURSION-CHILD-NODES",
            &child_node_ids,
        );
        let public_input_root = recursion_node_public_input_root(
            &tree_id,
            depth,
            &child_proof_root,
            &child_node_root,
            batch_start_height,
            batch_end_height,
        );
        let accumulator_root = recursion_node_accumulator_root(
            &child_proof_root,
            &child_node_root,
            &public_input_root,
            depth,
            child_job_ids.len() as u64,
            child_node_ids.len() as u64,
        );
        let metadata_root = recursive_proof_scheduler_payload_root(
            "RECURSIVE-PROOF-SCHEDULER-RECURSION-NODE-METADATA",
            metadata,
        );
        let node_id = recursion_tree_node_id(
            &tree_id,
            depth,
            &child_proof_root,
            &child_node_root,
            &public_input_root,
            &accumulator_root,
        );
        let record = Self {
            node_id,
            tree_id,
            parent_node_id,
            depth,
            lane,
            family,
            child_job_ids,
            child_node_ids,
            child_proof_root,
            child_node_root,
            public_input_root,
            accumulator_root,
            recursion_program_root,
            batch_start_height,
            batch_end_height,
            opened_at_height,
            sealed_at_height: 0,
            verified_at_height: 0,
            max_child_proofs,
            status: RecursionNodeStatus::Open,
            metadata_root,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn seal(mut self, sealed_at_height: u64) -> RecursiveProofSchedulerResult<Self> {
        if sealed_at_height < self.opened_at_height {
            return Err("recursion node sealed before open height".to_string());
        }
        self.sealed_at_height = sealed_at_height;
        self.status = RecursionNodeStatus::Sealed;
        self.validate()?;
        Ok(self)
    }

    pub fn verify(mut self, verified_at_height: u64) -> RecursiveProofSchedulerResult<Self> {
        if self.status != RecursionNodeStatus::Sealed {
            return Err("recursion node must be sealed before verification".to_string());
        }
        if verified_at_height < self.sealed_at_height {
            return Err("recursion node verified before seal height".to_string());
        }
        self.verified_at_height = verified_at_height;
        self.status = RecursionNodeStatus::Verified;
        self.validate()?;
        Ok(self)
    }

    pub fn child_count(&self) -> u64 {
        self.child_job_ids
            .len()
            .saturating_add(self.child_node_ids.len()) as u64
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_scheduler_recursion_tree_node",
            "chain_id": CHAIN_ID,
            "protocol_version": RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION,
            "node_id": self.node_id,
            "tree_id": self.tree_id,
            "parent_node_id": self.parent_node_id,
            "depth": self.depth,
            "lane": self.lane.as_str(),
            "family": self.family.as_str(),
            "child_job_ids": self.child_job_ids,
            "child_node_ids": self.child_node_ids,
            "child_proof_root": self.child_proof_root,
            "child_node_root": self.child_node_root,
            "public_input_root": self.public_input_root,
            "accumulator_root": self.accumulator_root,
            "recursion_program_root": self.recursion_program_root,
            "batch_start_height": self.batch_start_height,
            "batch_end_height": self.batch_end_height,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "verified_at_height": self.verified_at_height,
            "max_child_proofs": self.max_child_proofs,
            "child_count": self.child_count(),
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn validate(&self) -> RecursiveProofSchedulerResult<String> {
        ensure_hash(&self.node_id, "recursion tree node id")?;
        ensure_hash(&self.tree_id, "recursion tree id")?;
        ensure_hash_or_empty(&self.parent_node_id, "recursion parent node id")?;
        ensure_hashes(&self.child_job_ids, "recursion tree child job ids")?;
        ensure_hashes(&self.child_node_ids, "recursion tree child node ids")?;
        ensure_hash(&self.child_proof_root, "recursion tree child proof root")?;
        ensure_hash(&self.child_node_root, "recursion tree child node root")?;
        ensure_hash(&self.public_input_root, "recursion tree public input root")?;
        ensure_hash(&self.accumulator_root, "recursion tree accumulator root")?;
        ensure_hash(
            &self.recursion_program_root,
            "recursion tree recursion program root",
        )?;
        ensure_hash(&self.metadata_root, "recursion tree metadata root")?;
        if self.child_count() == 0 {
            return Err("recursion tree node has no children".to_string());
        }
        if self.child_count() > self.max_child_proofs {
            return Err("recursion tree node exceeds max child proofs".to_string());
        }
        if self.batch_end_height < self.batch_start_height {
            return Err("recursion tree node batch range is invalid".to_string());
        }
        if self.max_child_proofs == 0 {
            return Err("recursion tree node max child proofs must be non-zero".to_string());
        }
        let expected_child_proof_root = string_set_root(
            "RECURSIVE-PROOF-SCHEDULER-RECURSION-CHILD-JOBS",
            &self.child_job_ids,
        );
        let expected_child_node_root = string_set_root(
            "RECURSIVE-PROOF-SCHEDULER-RECURSION-CHILD-NODES",
            &self.child_node_ids,
        );
        if self.child_proof_root != expected_child_proof_root {
            return Err("recursion tree child proof root mismatch".to_string());
        }
        if self.child_node_root != expected_child_node_root {
            return Err("recursion tree child node root mismatch".to_string());
        }
        let expected_public_input_root = recursion_node_public_input_root(
            &self.tree_id,
            self.depth,
            &self.child_proof_root,
            &self.child_node_root,
            self.batch_start_height,
            self.batch_end_height,
        );
        if self.public_input_root != expected_public_input_root {
            return Err("recursion tree public input root mismatch".to_string());
        }
        let expected_accumulator_root = recursion_node_accumulator_root(
            &self.child_proof_root,
            &self.child_node_root,
            &self.public_input_root,
            self.depth,
            self.child_job_ids.len() as u64,
            self.child_node_ids.len() as u64,
        );
        if self.accumulator_root != expected_accumulator_root {
            return Err("recursion tree accumulator root mismatch".to_string());
        }
        if matches!(
            self.status,
            RecursionNodeStatus::Sealed
                | RecursionNodeStatus::Verified
                | RecursionNodeStatus::Finalized
        ) && self.sealed_at_height == 0
        {
            return Err("sealed recursion tree node must carry sealed height".to_string());
        }
        if matches!(
            self.status,
            RecursionNodeStatus::Verified | RecursionNodeStatus::Finalized
        ) && self.verified_at_height == 0
        {
            return Err("verified recursion tree node must carry verified height".to_string());
        }
        if self.node_id
            != recursion_tree_node_id(
                &self.tree_id,
                self.depth,
                &self.child_proof_root,
                &self.child_node_root,
                &self.public_input_root,
                &self.accumulator_root,
            )
        {
            return Err("recursion tree node id mismatch".to_string());
        }
        Ok(recursion_tree_node_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofMarketAssignment {
    pub assignment_id: String,
    pub job_id: String,
    pub prover_id: String,
    pub worker_class: String,
    pub bid_id: String,
    pub bid_fee_units: u64,
    pub max_fee_units: u64,
    pub stake_units: u64,
    pub expected_cycles: u64,
    pub lease_start_height: u64,
    pub lease_end_height: u64,
    pub assigned_at_height: u64,
    pub completed_at_height: u64,
    pub pq_public_key_root: String,
    pub capacity_commitment_root: String,
    pub accepted_commitment_root: String,
    pub sla_tier: String,
    pub failure_count: u64,
    pub status: MarketAssignmentStatus,
}

impl ProofMarketAssignment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job: &ProofJob,
        prover_id: impl Into<String>,
        worker_class: impl Into<String>,
        bid_id: impl Into<String>,
        bid_fee_units: u64,
        stake_units: u64,
        lease_start_height: u64,
        lease_blocks: u64,
        pq_public_key_root: impl Into<String>,
        capacity_commitment_root: impl Into<String>,
        sla_tier: impl Into<String>,
    ) -> RecursiveProofSchedulerResult<Self> {
        job.validate()?;
        let prover_id = prover_id.into();
        let worker_class = worker_class.into();
        let bid_id = bid_id.into();
        let pq_public_key_root = pq_public_key_root.into();
        let capacity_commitment_root = capacity_commitment_root.into();
        let sla_tier = sla_tier.into();
        ensure_non_empty(&prover_id, "proof market prover id")?;
        ensure_non_empty(&worker_class, "proof market worker class")?;
        ensure_non_empty(&bid_id, "proof market bid id")?;
        ensure_hash(&pq_public_key_root, "proof market pq public key root")?;
        ensure_hash(
            &capacity_commitment_root,
            "proof market capacity commitment root",
        )?;
        ensure_non_empty(&sla_tier, "proof market sla tier")?;
        if bid_fee_units > job.max_fee_units {
            return Err("proof market bid exceeds job max fee".to_string());
        }
        if lease_blocks == 0 {
            return Err("proof market lease blocks must be non-zero".to_string());
        }
        let accepted_commitment_root = market_assignment_acceptance_root(
            &job.job_id,
            &prover_id,
            &bid_id,
            bid_fee_units,
            lease_start_height,
        );
        let assignment_id = proof_market_assignment_id(
            &job.job_id,
            &prover_id,
            &bid_id,
            bid_fee_units,
            lease_start_height,
        );
        let record = Self {
            assignment_id,
            job_id: job.job_id.clone(),
            prover_id,
            worker_class,
            bid_id,
            bid_fee_units,
            max_fee_units: job.max_fee_units,
            stake_units,
            expected_cycles: job.estimated_cycles,
            lease_start_height,
            lease_end_height: lease_start_height.saturating_add(lease_blocks),
            assigned_at_height: lease_start_height,
            completed_at_height: 0,
            pq_public_key_root,
            capacity_commitment_root,
            accepted_commitment_root,
            sla_tier,
            failure_count: 0,
            status: MarketAssignmentStatus::Assigned,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn complete(mut self, completed_at_height: u64) -> RecursiveProofSchedulerResult<Self> {
        if !matches!(
            self.status,
            MarketAssignmentStatus::Assigned | MarketAssignmentStatus::Accepted
        ) {
            return Err(
                "proof market assignment cannot be completed from current status".to_string(),
            );
        }
        self.completed_at_height = completed_at_height;
        self.status = MarketAssignmentStatus::Completed;
        self.validate()?;
        Ok(self)
    }

    pub fn settle(mut self) -> RecursiveProofSchedulerResult<Self> {
        if self.status != MarketAssignmentStatus::Completed {
            return Err("proof market assignment must be completed before settlement".to_string());
        }
        self.status = MarketAssignmentStatus::Settled;
        self.validate()?;
        Ok(self)
    }

    pub fn slash(mut self) -> RecursiveProofSchedulerResult<Self> {
        self.status = MarketAssignmentStatus::Slashed;
        self.failure_count = self.failure_count.saturating_add(1);
        self.validate()?;
        Ok(self)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        matches!(
            self.status,
            MarketAssignmentStatus::Assigned | MarketAssignmentStatus::Accepted
        ) && height <= self.lease_end_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_scheduler_market_assignment",
            "chain_id": CHAIN_ID,
            "protocol_version": RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION,
            "assignment_id": self.assignment_id,
            "job_id": self.job_id,
            "prover_id": self.prover_id,
            "worker_class": self.worker_class,
            "bid_id": self.bid_id,
            "bid_fee_units": self.bid_fee_units,
            "max_fee_units": self.max_fee_units,
            "stake_units": self.stake_units,
            "expected_cycles": self.expected_cycles,
            "lease_start_height": self.lease_start_height,
            "lease_end_height": self.lease_end_height,
            "assigned_at_height": self.assigned_at_height,
            "completed_at_height": self.completed_at_height,
            "pq_public_key_root": self.pq_public_key_root,
            "capacity_commitment_root": self.capacity_commitment_root,
            "accepted_commitment_root": self.accepted_commitment_root,
            "sla_tier": self.sla_tier,
            "failure_count": self.failure_count,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> RecursiveProofSchedulerResult<String> {
        ensure_hash(&self.assignment_id, "proof market assignment id")?;
        ensure_hash(&self.job_id, "proof market assignment job id")?;
        ensure_non_empty(&self.prover_id, "proof market assignment prover")?;
        ensure_non_empty(&self.worker_class, "proof market assignment worker class")?;
        ensure_non_empty(&self.bid_id, "proof market assignment bid id")?;
        ensure_hash(
            &self.pq_public_key_root,
            "proof market assignment pq public key root",
        )?;
        ensure_hash(
            &self.capacity_commitment_root,
            "proof market assignment capacity root",
        )?;
        ensure_hash(
            &self.accepted_commitment_root,
            "proof market assignment acceptance root",
        )?;
        ensure_non_empty(&self.sla_tier, "proof market assignment sla tier")?;
        if self.bid_fee_units > self.max_fee_units {
            return Err("proof market assignment bid exceeds max fee".to_string());
        }
        if self.expected_cycles == 0 {
            return Err("proof market assignment expected cycles must be non-zero".to_string());
        }
        if self.lease_end_height <= self.lease_start_height {
            return Err("proof market assignment lease range is invalid".to_string());
        }
        if matches!(
            self.status,
            MarketAssignmentStatus::Completed | MarketAssignmentStatus::Settled
        ) && self.completed_at_height == 0
        {
            return Err(
                "completed proof market assignment must carry completion height".to_string(),
            );
        }
        if self.assignment_id
            != proof_market_assignment_id(
                &self.job_id,
                &self.prover_id,
                &self.bid_id,
                self.bid_fee_units,
                self.lease_start_height,
            )
        {
            return Err("proof market assignment id mismatch".to_string());
        }
        Ok(proof_market_assignment_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqProverAttestation {
    pub attestation_id: String,
    pub prover_id: String,
    pub assignment_id: String,
    pub job_id: String,
    pub role: PqProverAttestationRole,
    pub pq_scheme: String,
    pub recovery_scheme: String,
    pub pq_public_key_root: String,
    pub statement_root: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub aggregate_signature_root: String,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub verified_weight: u64,
    pub status: String,
}

impl PqProverAttestation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        prover_id: impl Into<String>,
        assignment_id: impl Into<String>,
        job_id: impl Into<String>,
        role: PqProverAttestationRole,
        pq_public_key_root: impl Into<String>,
        statement_root: impl Into<String>,
        transcript_root: impl Into<String>,
        signature_root: impl Into<String>,
        aggregate_signature_root: impl Into<String>,
        attested_at_height: u64,
        expires_at_height: u64,
        verified_weight: u64,
    ) -> RecursiveProofSchedulerResult<Self> {
        let prover_id = prover_id.into();
        let assignment_id = assignment_id.into();
        let job_id = job_id.into();
        let pq_public_key_root = pq_public_key_root.into();
        let statement_root = statement_root.into();
        let transcript_root = transcript_root.into();
        let signature_root = signature_root.into();
        let aggregate_signature_root = aggregate_signature_root.into();
        ensure_non_empty(&prover_id, "PQ prover attestation prover")?;
        ensure_hash(&assignment_id, "PQ prover attestation assignment")?;
        ensure_hash(&job_id, "PQ prover attestation job")?;
        ensure_hash(&pq_public_key_root, "PQ prover attestation public key")?;
        ensure_hash(&statement_root, "PQ prover attestation statement")?;
        ensure_hash(&transcript_root, "PQ prover attestation transcript")?;
        ensure_hash(&signature_root, "PQ prover attestation signature")?;
        ensure_hash(
            &aggregate_signature_root,
            "PQ prover attestation aggregate signature",
        )?;
        let attestation_id = pq_prover_attestation_id(
            &prover_id,
            &assignment_id,
            &job_id,
            role.as_str(),
            &statement_root,
            attested_at_height,
        );
        let record = Self {
            attestation_id,
            prover_id,
            assignment_id,
            job_id,
            role,
            pq_scheme: RECURSIVE_PROOF_SCHEDULER_PQ_SIGNATURE_SCHEME.to_string(),
            recovery_scheme: RECURSIVE_PROOF_SCHEDULER_PQ_RECOVERY_SCHEME.to_string(),
            pq_public_key_root,
            statement_root,
            transcript_root,
            signature_root,
            aggregate_signature_root,
            attested_at_height,
            expires_at_height,
            verified_weight,
            status: RECURSIVE_PROOF_SCHEDULER_STATUS_VERIFIED.to_string(),
        };
        record.validate()?;
        Ok(record)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == RECURSIVE_PROOF_SCHEDULER_STATUS_VERIFIED
            && height >= self.attested_at_height
            && (self.expires_at_height == 0 || height < self.expires_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_scheduler_pq_prover_attestation",
            "chain_id": CHAIN_ID,
            "protocol_version": RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION,
            "attestation_id": self.attestation_id,
            "prover_id": self.prover_id,
            "assignment_id": self.assignment_id,
            "job_id": self.job_id,
            "role": self.role.as_str(),
            "pq_scheme": self.pq_scheme,
            "recovery_scheme": self.recovery_scheme,
            "pq_public_key_root": self.pq_public_key_root,
            "statement_root": self.statement_root,
            "transcript_root": self.transcript_root,
            "signature_root": self.signature_root,
            "aggregate_signature_root": self.aggregate_signature_root,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "verified_weight": self.verified_weight,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> RecursiveProofSchedulerResult<String> {
        ensure_hash(&self.attestation_id, "PQ prover attestation id")?;
        ensure_non_empty(&self.prover_id, "PQ prover attestation prover")?;
        ensure_hash(&self.assignment_id, "PQ prover attestation assignment")?;
        ensure_hash(&self.job_id, "PQ prover attestation job")?;
        ensure_non_empty(&self.pq_scheme, "PQ prover attestation scheme")?;
        ensure_non_empty(
            &self.recovery_scheme,
            "PQ prover attestation recovery scheme",
        )?;
        ensure_hash(&self.pq_public_key_root, "PQ prover attestation public key")?;
        ensure_hash(&self.statement_root, "PQ prover attestation statement")?;
        ensure_hash(&self.transcript_root, "PQ prover attestation transcript")?;
        ensure_hash(&self.signature_root, "PQ prover attestation signature")?;
        ensure_hash(
            &self.aggregate_signature_root,
            "PQ prover attestation aggregate signature",
        )?;
        if self.expires_at_height != 0 && self.expires_at_height <= self.attested_at_height {
            return Err(
                "PQ prover attestation expiry must be after attestation height".to_string(),
            );
        }
        if self.verified_weight == 0 {
            return Err("PQ prover attestation verified weight must be non-zero".to_string());
        }
        if self.attestation_id
            != pq_prover_attestation_id(
                &self.prover_id,
                &self.assignment_id,
                &self.job_id,
                self.role.as_str(),
                &self.statement_root,
                self.attested_at_height,
            )
        {
            return Err("PQ prover attestation id mismatch".to_string());
        }
        Ok(pq_prover_attestation_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCompressionReceipt {
    pub receipt_id: String,
    pub job_id: String,
    pub assignment_id: String,
    pub source_proof_commitment: String,
    pub source_proof_bytes: u64,
    pub compressed_proof_id: String,
    pub compressed_proof_commitment: String,
    pub compressed_proof_bytes: u64,
    pub compression_ratio_bps: u64,
    pub recursion_tree_root: String,
    pub verifier_key_root: String,
    pub transcript_root: String,
    pub created_at_height: u64,
    pub verified_at_height: u64,
    pub status: CompressionReceiptStatus,
}

impl ProofCompressionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_id: impl Into<String>,
        assignment_id: impl Into<String>,
        source_proof_commitment: impl Into<String>,
        source_proof_bytes: u64,
        compressed_proof_id: impl Into<String>,
        compressed_proof_commitment: impl Into<String>,
        compressed_proof_bytes: u64,
        recursion_tree_root: impl Into<String>,
        verifier_key_root: impl Into<String>,
        transcript_root: impl Into<String>,
        created_at_height: u64,
    ) -> RecursiveProofSchedulerResult<Self> {
        let job_id = job_id.into();
        let assignment_id = assignment_id.into();
        let source_proof_commitment = source_proof_commitment.into();
        let compressed_proof_id = compressed_proof_id.into();
        let compressed_proof_commitment = compressed_proof_commitment.into();
        let recursion_tree_root = recursion_tree_root.into();
        let verifier_key_root = verifier_key_root.into();
        let transcript_root = transcript_root.into();
        ensure_hash(&job_id, "proof compression receipt job id")?;
        ensure_hash(&assignment_id, "proof compression receipt assignment id")?;
        ensure_hash(
            &source_proof_commitment,
            "proof compression receipt source proof",
        )?;
        ensure_non_empty(
            &compressed_proof_id,
            "proof compression receipt compressed proof id",
        )?;
        ensure_hash(
            &compressed_proof_commitment,
            "proof compression receipt compressed proof commitment",
        )?;
        ensure_hash(&recursion_tree_root, "proof compression receipt tree root")?;
        ensure_hash(&verifier_key_root, "proof compression receipt verifier key")?;
        ensure_hash(&transcript_root, "proof compression receipt transcript")?;
        if source_proof_bytes == 0 || compressed_proof_bytes == 0 {
            return Err("proof compression receipt byte counts must be non-zero".to_string());
        }
        let compression_ratio_bps = ratio_bps(compressed_proof_bytes, source_proof_bytes);
        let receipt_id = proof_compression_receipt_id(
            &job_id,
            &assignment_id,
            &source_proof_commitment,
            &compressed_proof_id,
            &compressed_proof_commitment,
            compression_ratio_bps,
            created_at_height,
        );
        let record = Self {
            receipt_id,
            job_id,
            assignment_id,
            source_proof_commitment,
            source_proof_bytes,
            compressed_proof_id,
            compressed_proof_commitment,
            compressed_proof_bytes,
            compression_ratio_bps,
            recursion_tree_root,
            verifier_key_root,
            transcript_root,
            created_at_height,
            verified_at_height: 0,
            status: CompressionReceiptStatus::Pending,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn accept(mut self, verified_at_height: u64) -> RecursiveProofSchedulerResult<Self> {
        if verified_at_height < self.created_at_height {
            return Err("proof compression receipt verified before creation".to_string());
        }
        self.verified_at_height = verified_at_height;
        self.status = CompressionReceiptStatus::Accepted;
        self.validate()?;
        Ok(self)
    }

    pub fn bytes_saved(&self) -> u64 {
        self.source_proof_bytes
            .saturating_sub(self.compressed_proof_bytes)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_scheduler_compression_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "job_id": self.job_id,
            "assignment_id": self.assignment_id,
            "source_proof_commitment": self.source_proof_commitment,
            "source_proof_bytes": self.source_proof_bytes,
            "compressed_proof_id": self.compressed_proof_id,
            "compressed_proof_commitment": self.compressed_proof_commitment,
            "compressed_proof_bytes": self.compressed_proof_bytes,
            "compression_ratio_bps": self.compression_ratio_bps,
            "bytes_saved": self.bytes_saved(),
            "recursion_tree_root": self.recursion_tree_root,
            "verifier_key_root": self.verifier_key_root,
            "transcript_root": self.transcript_root,
            "created_at_height": self.created_at_height,
            "verified_at_height": self.verified_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> RecursiveProofSchedulerResult<String> {
        ensure_hash(&self.receipt_id, "proof compression receipt id")?;
        ensure_hash(&self.job_id, "proof compression receipt job id")?;
        ensure_hash(
            &self.assignment_id,
            "proof compression receipt assignment id",
        )?;
        ensure_hash(
            &self.source_proof_commitment,
            "proof compression receipt source proof",
        )?;
        ensure_non_empty(
            &self.compressed_proof_id,
            "proof compression receipt compressed proof id",
        )?;
        ensure_hash(
            &self.compressed_proof_commitment,
            "proof compression receipt compressed proof commitment",
        )?;
        ensure_hash(
            &self.recursion_tree_root,
            "proof compression receipt tree root",
        )?;
        ensure_hash(
            &self.verifier_key_root,
            "proof compression receipt verifier key",
        )?;
        ensure_hash(
            &self.transcript_root,
            "proof compression receipt transcript",
        )?;
        if self.source_proof_bytes == 0 || self.compressed_proof_bytes == 0 {
            return Err("proof compression receipt byte counts must be non-zero".to_string());
        }
        if self.compressed_proof_bytes > self.source_proof_bytes {
            return Err("proof compression receipt grew the proof".to_string());
        }
        let expected_ratio = ratio_bps(self.compressed_proof_bytes, self.source_proof_bytes);
        if self.compression_ratio_bps != expected_ratio {
            return Err("proof compression receipt ratio mismatch".to_string());
        }
        if self.compression_ratio_bps < RECURSIVE_PROOF_SCHEDULER_MIN_COMPRESSION_RATIO_BPS {
            return Err("proof compression receipt ratio below protocol minimum".to_string());
        }
        if self.status == CompressionReceiptStatus::Accepted && self.verified_at_height == 0 {
            return Err(
                "accepted proof compression receipt must carry verification height".to_string(),
            );
        }
        if self.receipt_id
            != proof_compression_receipt_id(
                &self.job_id,
                &self.assignment_id,
                &self.source_proof_commitment,
                &self.compressed_proof_id,
                &self.compressed_proof_commitment,
                self.compression_ratio_bps,
                self.created_at_height,
            )
        {
            return Err("proof compression receipt id mismatch".to_string());
        }
        Ok(proof_compression_receipt_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureChallengeRecord {
    pub challenge_id: String,
    pub challenge_kind: ChallengeKind,
    pub target_kind: String,
    pub target_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub expected_root: String,
    pub observed_root: String,
    pub opened_at_height: u64,
    pub deadline_height: u64,
    pub bond_units: u64,
    pub slash_units: u64,
    pub outcome: ChallengeOutcome,
    pub status: String,
    pub resolved_at_height: u64,
}

impl FailureChallengeRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        challenge_kind: ChallengeKind,
        target_kind: impl Into<String>,
        target_id: impl Into<String>,
        challenger_commitment: impl Into<String>,
        evidence_root: impl Into<String>,
        expected_root: impl Into<String>,
        observed_root: impl Into<String>,
        opened_at_height: u64,
        challenge_window_blocks: u64,
        bond_units: u64,
        slash_units: u64,
    ) -> RecursiveProofSchedulerResult<Self> {
        let target_kind = target_kind.into();
        let target_id = target_id.into();
        let challenger_commitment = challenger_commitment.into();
        let evidence_root = evidence_root.into();
        let expected_root = expected_root.into();
        let observed_root = observed_root.into();
        ensure_non_empty(&target_kind, "challenge target kind")?;
        ensure_hash(&target_id, "challenge target id")?;
        ensure_hash(&challenger_commitment, "challenge challenger commitment")?;
        ensure_hash(&evidence_root, "challenge evidence root")?;
        ensure_hash(&expected_root, "challenge expected root")?;
        ensure_hash(&observed_root, "challenge observed root")?;
        if challenge_window_blocks == 0 {
            return Err("challenge window blocks must be non-zero".to_string());
        }
        let challenge_id = failure_challenge_id(
            challenge_kind.as_str(),
            &target_kind,
            &target_id,
            &challenger_commitment,
            &evidence_root,
            opened_at_height,
        );
        let record = Self {
            challenge_id,
            challenge_kind,
            target_kind,
            target_id,
            challenger_commitment,
            evidence_root,
            expected_root,
            observed_root,
            opened_at_height,
            deadline_height: opened_at_height.saturating_add(challenge_window_blocks),
            bond_units,
            slash_units,
            outcome: ChallengeOutcome::Open,
            status: RECURSIVE_PROOF_SCHEDULER_STATUS_CHALLENGED.to_string(),
            resolved_at_height: 0,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn resolve(
        mut self,
        outcome: ChallengeOutcome,
        resolved_at_height: u64,
    ) -> RecursiveProofSchedulerResult<Self> {
        if outcome == ChallengeOutcome::Open {
            return Err("challenge cannot resolve to open".to_string());
        }
        if resolved_at_height < self.opened_at_height {
            return Err("challenge resolved before open height".to_string());
        }
        self.outcome = outcome;
        self.resolved_at_height = resolved_at_height;
        self.status = RECURSIVE_PROOF_SCHEDULER_STATUS_RESOLVED.to_string();
        self.validate()?;
        Ok(self)
    }

    pub fn is_open_at(&self, height: u64) -> bool {
        self.status == RECURSIVE_PROOF_SCHEDULER_STATUS_CHALLENGED && height <= self.deadline_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_scheduler_failure_challenge",
            "chain_id": CHAIN_ID,
            "protocol_version": RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "challenge_kind": self.challenge_kind.as_str(),
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "opened_at_height": self.opened_at_height,
            "deadline_height": self.deadline_height,
            "bond_units": self.bond_units,
            "slash_units": self.slash_units,
            "outcome": self.outcome.as_str(),
            "status": self.status,
            "resolved_at_height": self.resolved_at_height,
        })
    }

    pub fn validate(&self) -> RecursiveProofSchedulerResult<String> {
        ensure_hash(&self.challenge_id, "challenge id")?;
        ensure_non_empty(&self.target_kind, "challenge target kind")?;
        ensure_hash(&self.target_id, "challenge target id")?;
        ensure_hash(
            &self.challenger_commitment,
            "challenge challenger commitment",
        )?;
        ensure_hash(&self.evidence_root, "challenge evidence root")?;
        ensure_hash(&self.expected_root, "challenge expected root")?;
        ensure_hash(&self.observed_root, "challenge observed root")?;
        if self.deadline_height <= self.opened_at_height {
            return Err("challenge deadline must be after opened height".to_string());
        }
        if self.status == RECURSIVE_PROOF_SCHEDULER_STATUS_RESOLVED {
            if self.outcome == ChallengeOutcome::Open || self.resolved_at_height == 0 {
                return Err("resolved challenge must carry non-open outcome and height".to_string());
            }
        }
        if self.challenge_id
            != failure_challenge_id(
                self.challenge_kind.as_str(),
                &self.target_kind,
                &self.target_id,
                &self.challenger_commitment,
                &self.evidence_root,
                self.opened_at_height,
            )
        {
            return Err("challenge id mismatch".to_string());
        }
        Ok(failure_challenge_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofFeeLedgerEntry {
    pub entry_id: String,
    pub entry_kind: FeeLedgerEntryKind,
    pub job_id: String,
    pub assignment_id: String,
    pub account_commitment: String,
    pub asset_id: String,
    pub debit_units: u64,
    pub credit_units: u64,
    pub rebate_units: u64,
    pub protocol_fee_units: u64,
    pub height: u64,
    pub memo_root: String,
}

impl ProofFeeLedgerEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        entry_kind: FeeLedgerEntryKind,
        job_id: impl Into<String>,
        assignment_id: impl Into<String>,
        account_commitment: impl Into<String>,
        asset_id: impl Into<String>,
        debit_units: u64,
        credit_units: u64,
        rebate_units: u64,
        protocol_fee_units: u64,
        height: u64,
        memo: &Value,
    ) -> RecursiveProofSchedulerResult<Self> {
        let job_id = job_id.into();
        let assignment_id = assignment_id.into();
        let account_commitment = account_commitment.into();
        let asset_id = asset_id.into();
        ensure_hash_or_empty(&job_id, "fee ledger job id")?;
        ensure_hash_or_empty(&assignment_id, "fee ledger assignment id")?;
        ensure_hash(&account_commitment, "fee ledger account commitment")?;
        ensure_non_empty(&asset_id, "fee ledger asset id")?;
        let memo_root =
            recursive_proof_scheduler_payload_root("RECURSIVE-PROOF-SCHEDULER-FEE-MEMO", memo);
        let entry_id = proof_fee_ledger_entry_id(
            entry_kind.as_str(),
            &job_id,
            &assignment_id,
            &account_commitment,
            &asset_id,
            debit_units,
            credit_units,
            rebate_units,
            protocol_fee_units,
            height,
            &memo_root,
        );
        let record = Self {
            entry_id,
            entry_kind,
            job_id,
            assignment_id,
            account_commitment,
            asset_id,
            debit_units,
            credit_units,
            rebate_units,
            protocol_fee_units,
            height,
            memo_root,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn net_credit_units(&self) -> u64 {
        self.credit_units
            .saturating_add(self.rebate_units)
            .saturating_sub(self.debit_units)
            .saturating_sub(self.protocol_fee_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_scheduler_fee_ledger_entry",
            "chain_id": CHAIN_ID,
            "protocol_version": RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION,
            "entry_id": self.entry_id,
            "entry_kind": self.entry_kind.as_str(),
            "job_id": self.job_id,
            "assignment_id": self.assignment_id,
            "account_commitment": self.account_commitment,
            "asset_id": self.asset_id,
            "debit_units": self.debit_units,
            "credit_units": self.credit_units,
            "rebate_units": self.rebate_units,
            "protocol_fee_units": self.protocol_fee_units,
            "net_credit_units": self.net_credit_units(),
            "height": self.height,
            "memo_root": self.memo_root,
        })
    }

    pub fn validate(&self) -> RecursiveProofSchedulerResult<String> {
        ensure_hash(&self.entry_id, "fee ledger entry id")?;
        ensure_hash_or_empty(&self.job_id, "fee ledger job id")?;
        ensure_hash_or_empty(&self.assignment_id, "fee ledger assignment id")?;
        ensure_hash(&self.account_commitment, "fee ledger account commitment")?;
        ensure_non_empty(&self.asset_id, "fee ledger asset id")?;
        ensure_hash(&self.memo_root, "fee ledger memo root")?;
        if self.debit_units == 0
            && self.credit_units == 0
            && self.rebate_units == 0
            && self.protocol_fee_units == 0
        {
            return Err("fee ledger entry must move non-zero units".to_string());
        }
        if self.entry_id
            != proof_fee_ledger_entry_id(
                self.entry_kind.as_str(),
                &self.job_id,
                &self.assignment_id,
                &self.account_commitment,
                &self.asset_id,
                self.debit_units,
                self.credit_units,
                self.rebate_units,
                self.protocol_fee_units,
                self.height,
                &self.memo_root,
            )
        {
            return Err("fee ledger entry id mismatch".to_string());
        }
        Ok(proof_fee_ledger_entry_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveProofSchedulerDevnetFixture {
    pub fixture_id: String,
    pub label: String,
    pub height: u64,
    pub manifest_root: String,
    pub lane_root: String,
    pub window_root: String,
    pub job_root: String,
    pub recursion_tree_root: String,
    pub assignment_root: String,
    pub attestation_root: String,
    pub compression_receipt_root: String,
    pub fee_ledger_root: String,
    pub notes_root: String,
}

impl RecursiveProofSchedulerDevnetFixture {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: impl Into<String>,
        height: u64,
        manifest_root: impl Into<String>,
        lane_root: impl Into<String>,
        window_root: impl Into<String>,
        job_root: impl Into<String>,
        recursion_tree_root: impl Into<String>,
        assignment_root: impl Into<String>,
        attestation_root: impl Into<String>,
        compression_receipt_root: impl Into<String>,
        fee_ledger_root: impl Into<String>,
        notes: &Value,
    ) -> RecursiveProofSchedulerResult<Self> {
        let label = label.into();
        let manifest_root = manifest_root.into();
        let lane_root = lane_root.into();
        let window_root = window_root.into();
        let job_root = job_root.into();
        let recursion_tree_root = recursion_tree_root.into();
        let assignment_root = assignment_root.into();
        let attestation_root = attestation_root.into();
        let compression_receipt_root = compression_receipt_root.into();
        let fee_ledger_root = fee_ledger_root.into();
        ensure_non_empty(&label, "devnet fixture label")?;
        ensure_hash(&manifest_root, "devnet fixture manifest root")?;
        ensure_hash(&lane_root, "devnet fixture lane root")?;
        ensure_hash(&window_root, "devnet fixture window root")?;
        ensure_hash(&job_root, "devnet fixture job root")?;
        ensure_hash(&recursion_tree_root, "devnet fixture recursion tree root")?;
        ensure_hash(&assignment_root, "devnet fixture assignment root")?;
        ensure_hash(&attestation_root, "devnet fixture attestation root")?;
        ensure_hash(
            &compression_receipt_root,
            "devnet fixture compression receipt root",
        )?;
        ensure_hash(&fee_ledger_root, "devnet fixture fee ledger root")?;
        let notes_root = recursive_proof_scheduler_payload_root(
            "RECURSIVE-PROOF-SCHEDULER-DEVNET-FIXTURE-NOTES",
            notes,
        );
        let fixture_id = devnet_fixture_id(
            &label,
            height,
            &manifest_root,
            &lane_root,
            &window_root,
            &job_root,
            &recursion_tree_root,
        );
        let record = Self {
            fixture_id,
            label,
            height,
            manifest_root,
            lane_root,
            window_root,
            job_root,
            recursion_tree_root,
            assignment_root,
            attestation_root,
            compression_receipt_root,
            fee_ledger_root,
            notes_root,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_scheduler_devnet_fixture",
            "chain_id": CHAIN_ID,
            "protocol_version": RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION,
            "fixture_id": self.fixture_id,
            "label": self.label,
            "height": self.height,
            "manifest_root": self.manifest_root,
            "lane_root": self.lane_root,
            "window_root": self.window_root,
            "job_root": self.job_root,
            "recursion_tree_root": self.recursion_tree_root,
            "assignment_root": self.assignment_root,
            "attestation_root": self.attestation_root,
            "compression_receipt_root": self.compression_receipt_root,
            "fee_ledger_root": self.fee_ledger_root,
            "notes_root": self.notes_root,
        })
    }

    pub fn validate(&self) -> RecursiveProofSchedulerResult<String> {
        ensure_hash(&self.fixture_id, "devnet fixture id")?;
        ensure_non_empty(&self.label, "devnet fixture label")?;
        ensure_hash(&self.manifest_root, "devnet fixture manifest root")?;
        ensure_hash(&self.lane_root, "devnet fixture lane root")?;
        ensure_hash(&self.window_root, "devnet fixture window root")?;
        ensure_hash(&self.job_root, "devnet fixture job root")?;
        ensure_hash(
            &self.recursion_tree_root,
            "devnet fixture recursion tree root",
        )?;
        ensure_hash(&self.assignment_root, "devnet fixture assignment root")?;
        ensure_hash(&self.attestation_root, "devnet fixture attestation root")?;
        ensure_hash(
            &self.compression_receipt_root,
            "devnet fixture compression receipt root",
        )?;
        ensure_hash(&self.fee_ledger_root, "devnet fixture fee ledger root")?;
        ensure_hash(&self.notes_root, "devnet fixture notes root")?;
        if self.fixture_id
            != devnet_fixture_id(
                &self.label,
                self.height,
                &self.manifest_root,
                &self.lane_root,
                &self.window_root,
                &self.job_root,
                &self.recursion_tree_root,
            )
        {
            return Err("devnet fixture id mismatch".to_string());
        }
        Ok(devnet_fixture_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveProofSchedulerRoots {
    pub config_root: String,
    pub manifest_root: String,
    pub active_manifest_root: String,
    pub priority_lane_root: String,
    pub active_lane_root: String,
    pub aggregation_window_root: String,
    pub proof_job_root: String,
    pub recursion_tree_root: String,
    pub market_assignment_root: String,
    pub pq_attestation_root: String,
    pub compression_receipt_root: String,
    pub challenge_root: String,
    pub fee_ledger_root: String,
    pub queue_root: String,
    pub nullifier_root: String,
    pub devnet_fixture_root: String,
    pub state_root: String,
}

impl RecursiveProofSchedulerRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_scheduler_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "manifest_root": self.manifest_root,
            "active_manifest_root": self.active_manifest_root,
            "priority_lane_root": self.priority_lane_root,
            "active_lane_root": self.active_lane_root,
            "aggregation_window_root": self.aggregation_window_root,
            "proof_job_root": self.proof_job_root,
            "recursion_tree_root": self.recursion_tree_root,
            "market_assignment_root": self.market_assignment_root,
            "pq_attestation_root": self.pq_attestation_root,
            "compression_receipt_root": self.compression_receipt_root,
            "challenge_root": self.challenge_root,
            "fee_ledger_root": self.fee_ledger_root,
            "queue_root": self.queue_root,
            "nullifier_root": self.nullifier_root,
            "devnet_fixture_root": self.devnet_fixture_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveProofSchedulerCounters {
    pub circuit_manifests: u64,
    pub priority_lanes: u64,
    pub aggregation_windows: u64,
    pub open_windows: u64,
    pub proof_jobs: u64,
    pub pending_jobs: u64,
    pub assigned_jobs: u64,
    pub proved_jobs: u64,
    pub verified_jobs: u64,
    pub compressed_jobs: u64,
    pub failed_jobs: u64,
    pub recursion_nodes: u64,
    pub market_assignments: u64,
    pub active_assignments: u64,
    pub pq_attestations: u64,
    pub compression_receipts: u64,
    pub accepted_compression_receipts: u64,
    pub challenges: u64,
    pub open_challenges: u64,
    pub fee_ledger_entries: u64,
    pub total_estimated_cycles: u64,
    pub total_source_bytes: u64,
    pub total_offered_fee_units: u64,
    pub total_protocol_fee_units: u64,
    pub total_rebate_units: u64,
    pub total_bytes_saved: u64,
}

impl RecursiveProofSchedulerCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_scheduler_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION,
            "circuit_manifests": self.circuit_manifests,
            "priority_lanes": self.priority_lanes,
            "aggregation_windows": self.aggregation_windows,
            "open_windows": self.open_windows,
            "proof_jobs": self.proof_jobs,
            "pending_jobs": self.pending_jobs,
            "assigned_jobs": self.assigned_jobs,
            "proved_jobs": self.proved_jobs,
            "verified_jobs": self.verified_jobs,
            "compressed_jobs": self.compressed_jobs,
            "failed_jobs": self.failed_jobs,
            "recursion_nodes": self.recursion_nodes,
            "market_assignments": self.market_assignments,
            "active_assignments": self.active_assignments,
            "pq_attestations": self.pq_attestations,
            "compression_receipts": self.compression_receipts,
            "accepted_compression_receipts": self.accepted_compression_receipts,
            "challenges": self.challenges,
            "open_challenges": self.open_challenges,
            "fee_ledger_entries": self.fee_ledger_entries,
            "total_estimated_cycles": self.total_estimated_cycles,
            "total_source_bytes": self.total_source_bytes,
            "total_offered_fee_units": self.total_offered_fee_units,
            "total_protocol_fee_units": self.total_protocol_fee_units,
            "total_rebate_units": self.total_rebate_units,
            "total_bytes_saved": self.total_bytes_saved,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecursiveProofSchedulerState {
    pub height: u64,
    pub scheduler_label: String,
    pub config: RecursiveProofSchedulerConfig,
    pub active_manifest_ids: BTreeMap<String, String>,
    pub active_lane_ids: BTreeMap<String, String>,
    pub circuit_manifests: BTreeMap<String, CircuitFamilyManifest>,
    pub priority_lanes: BTreeMap<String, PriorityLaneConfig>,
    pub aggregation_windows: BTreeMap<String, AggregationWindow>,
    pub proof_jobs: BTreeMap<String, ProofJob>,
    pub recursion_nodes: BTreeMap<String, RecursionTreeNode>,
    pub market_assignments: BTreeMap<String, ProofMarketAssignment>,
    pub pq_attestations: BTreeMap<String, PqProverAttestation>,
    pub compression_receipts: BTreeMap<String, ProofCompressionReceipt>,
    pub challenges: BTreeMap<String, FailureChallengeRecord>,
    pub fee_ledger: BTreeMap<String, ProofFeeLedgerEntry>,
    pub queue_by_lane: BTreeMap<String, Vec<String>>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub devnet_fixtures: BTreeMap<String, RecursiveProofSchedulerDevnetFixture>,
}

impl RecursiveProofSchedulerState {
    pub fn new(
        scheduler_label: impl Into<String>,
        config: RecursiveProofSchedulerConfig,
    ) -> RecursiveProofSchedulerResult<Self> {
        config.validate()?;
        let scheduler_label = scheduler_label.into();
        ensure_non_empty(&scheduler_label, "recursive proof scheduler label")?;
        Ok(Self {
            height: 0,
            scheduler_label,
            config,
            active_manifest_ids: BTreeMap::new(),
            active_lane_ids: BTreeMap::new(),
            circuit_manifests: BTreeMap::new(),
            priority_lanes: BTreeMap::new(),
            aggregation_windows: BTreeMap::new(),
            proof_jobs: BTreeMap::new(),
            recursion_nodes: BTreeMap::new(),
            market_assignments: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            compression_receipts: BTreeMap::new(),
            challenges: BTreeMap::new(),
            fee_ledger: BTreeMap::new(),
            queue_by_lane: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            devnet_fixtures: BTreeMap::new(),
        })
    }

    pub fn devnet() -> RecursiveProofSchedulerResult<Self> {
        let config = RecursiveProofSchedulerConfig::default();
        let mut state = Self::new("devnet-recursive-proof-scheduler", config)?;
        state.set_height(96);

        let manifests = vec![
            devnet_manifest(
                RecursiveCircuitFamily::RollupState,
                128,
                14 * 1024 * 1024,
                196_608,
                0,
            )?,
            devnet_manifest(
                RecursiveCircuitFamily::MoneroBridge,
                96,
                6 * 1024 * 1024,
                131_072,
                0,
            )?,
            devnet_manifest(
                RecursiveCircuitFamily::PrivateContract,
                128,
                10 * 1024 * 1024,
                147_456,
                0,
            )?,
            devnet_manifest(
                RecursiveCircuitFamily::IntentSettlement,
                96,
                8 * 1024 * 1024,
                122_880,
                0,
            )?,
            devnet_manifest(
                RecursiveCircuitFamily::FeeAccounting,
                64,
                4 * 1024 * 1024,
                98_304,
                0,
            )?,
            devnet_manifest(
                RecursiveCircuitFamily::RecursiveAggregation,
                192,
                12 * 1024 * 1024,
                65_536,
                RECURSIVE_PROOF_SCHEDULER_DEFAULT_MAX_CHILD_PROOFS,
            )?,
        ];
        for manifest in manifests {
            let manifest_id = state.insert_circuit_manifest(manifest)?;
            state.publish_manifest(&manifest_id)?;
        }

        let lanes = vec![
            PriorityLaneConfig::new(
                ProofPriorityLane::Bridge,
                "Monero bridge exits",
                state.config.bridge_lane_reserve_bps,
                16,
                "devnet-bridge-proof-sponsors",
                &state.config.default_fee_asset_id,
                true,
                true,
            )?,
            PriorityLaneConfig::new(
                ProofPriorityLane::PrivateContracts,
                "Private contract calls",
                state.config.private_contract_lane_reserve_bps,
                24,
                "devnet-private-contract-sponsors",
                &state.config.default_fee_asset_id,
                true,
                false,
            )?,
            PriorityLaneConfig::new(
                ProofPriorityLane::Intents,
                "Private intent settlement",
                state.config.intent_lane_reserve_bps,
                24,
                "devnet-intent-sponsors",
                &state.config.default_fee_asset_id,
                true,
                false,
            )?,
            PriorityLaneConfig::new(
                ProofPriorityLane::PublicRollup,
                "Public rollup batches",
                1_500,
                32,
                "devnet-rollup-sponsors",
                &state.config.default_fee_asset_id,
                false,
                false,
            )?,
            PriorityLaneConfig::new(
                ProofPriorityLane::FeeRebates,
                "Fee rebate accounting",
                1_000,
                16,
                "devnet-rebate-sponsors",
                &state.config.default_fee_asset_id,
                true,
                false,
            )?,
            PriorityLaneConfig::new(
                ProofPriorityLane::Maintenance,
                "Recursive maintenance",
                500,
                8,
                "devnet-maintenance-sponsors",
                &state.config.default_fee_asset_id,
                false,
                false,
            )?,
        ];
        for lane in lanes {
            let lane_id = state.insert_priority_lane(lane)?;
            state.activate_lane(&lane_id)?;
        }

        let windows = vec![
            AggregationWindow::new(
                AggregationWindowKind::BridgeFinality,
                ProofPriorityLane::Bridge,
                80,
                104,
                2,
                16,
                30_000_000,
                state.config.base_fee_per_million_cycles,
                "devnet-bridge-proof-sponsors",
                &[RecursiveCircuitFamily::MoneroBridge],
                &json!({"fixture": "bridge finality jobs", "privacy": "amount buckets only"}),
            )?,
            AggregationWindow::new(
                AggregationWindowKind::PrivateContracts,
                ProofPriorityLane::PrivateContracts,
                80,
                108,
                2,
                24,
                42_000_000,
                state.config.base_fee_per_million_cycles,
                "devnet-private-contract-sponsors",
                &[RecursiveCircuitFamily::PrivateContract],
                &json!({"fixture": "private contract calls", "privacy": "trace roots only"}),
            )?,
            AggregationWindow::new(
                AggregationWindowKind::IntentSettlement,
                ProofPriorityLane::Intents,
                80,
                110,
                2,
                24,
                36_000_000,
                state.config.base_fee_per_million_cycles,
                "devnet-intent-sponsors",
                &[RecursiveCircuitFamily::IntentSettlement],
                &json!({"fixture": "intents", "privacy": "solver commitments only"}),
            )?,
            AggregationWindow::new(
                AggregationWindowKind::PublicRollup,
                ProofPriorityLane::PublicRollup,
                80,
                112,
                2,
                32,
                64_000_000,
                state.config.base_fee_per_million_cycles,
                "devnet-rollup-sponsors",
                &[RecursiveCircuitFamily::RollupState],
                &json!({"fixture": "rollup batches", "privacy": "public roots"}),
            )?,
            AggregationWindow::new(
                AggregationWindowKind::FeeRebates,
                ProofPriorityLane::FeeRebates,
                80,
                116,
                1,
                16,
                18_000_000,
                state.config.base_fee_per_million_cycles,
                "devnet-rebate-sponsors",
                &[RecursiveCircuitFamily::FeeAccounting],
                &json!({"fixture": "sponsor rebates", "privacy": "claim nullifier roots"}),
            )?,
        ];
        let mut window_ids = BTreeMap::new();
        for window in windows {
            let key = window.kind.as_str().to_string();
            let window_id = state.insert_aggregation_window(window)?;
            window_ids.insert(key, window_id);
        }

        let mut job_ids = Vec::new();
        let job_specs = vec![
            (
                ProofJobKind::BridgeFinality,
                ProofPriorityLane::Bridge,
                AggregationWindowKind::BridgeFinality,
                "devnet-bridge-exit-0",
                12_500_000,
                380_000,
            ),
            (
                ProofJobKind::BridgeFinality,
                ProofPriorityLane::Bridge,
                AggregationWindowKind::BridgeFinality,
                "devnet-bridge-exit-1",
                10_750_000,
                340_000,
            ),
            (
                ProofJobKind::PrivateContractCall,
                ProofPriorityLane::PrivateContracts,
                AggregationWindowKind::PrivateContracts,
                "devnet-private-vault-rebalance",
                18_000_000,
                420_000,
            ),
            (
                ProofJobKind::PrivateContractCall,
                ProofPriorityLane::PrivateContracts,
                AggregationWindowKind::PrivateContracts,
                "devnet-private-lending-liquidation",
                16_000_000,
                395_000,
            ),
            (
                ProofJobKind::IntentSettlement,
                ProofPriorityLane::Intents,
                AggregationWindowKind::IntentSettlement,
                "devnet-intent-swap-batch",
                14_000_000,
                310_000,
            ),
            (
                ProofJobKind::StateTransition,
                ProofPriorityLane::PublicRollup,
                AggregationWindowKind::PublicRollup,
                "devnet-rollup-batch-96",
                24_000_000,
                500_000,
            ),
            (
                ProofJobKind::FeeRebateAccounting,
                ProofPriorityLane::FeeRebates,
                AggregationWindowKind::FeeRebates,
                "devnet-rebate-epoch-0",
                6_000_000,
                125_000,
            ),
        ];
        for (nonce, (kind, lane, window_kind, label, cycles, fee)) in
            job_specs.into_iter().enumerate()
        {
            let family = kind.default_family();
            let manifest_id = state
                .active_manifest_ids
                .get(family.as_str())
                .cloned()
                .ok_or_else(|| "devnet active manifest missing".to_string())?;
            let window_id = window_ids
                .get(window_kind.as_str())
                .cloned()
                .ok_or_else(|| "devnet window missing".to_string())?;
            let job = ProofJob::new(
                kind,
                family,
                lane,
                manifest_id,
                window_id.clone(),
                "",
                deterministic_commitment(&format!("{label}:requester")),
                deterministic_root(&format!("{label}:public-input")),
                deterministic_root(&format!("{label}:witness")),
                deterministic_root(&format!("{label}:source-payload")),
                RECURSIVE_PROOF_SCHEDULER_DEFAULT_SECURITY_BITS,
                cycles,
                8 + nonce as u64,
                420_000 + (nonce as u64 * 18_000),
                fee,
                fee.saturating_add(75_000),
                fee / 10,
                &state.config.default_fee_asset_id,
                88,
                118 + nonce as u64,
                0,
                nonce as u64,
                &json!({"fixture_label": label, "privacy": "commitment_roots_only"}),
            )?;
            let job_id = state.insert_proof_job(job)?;
            state.add_job_to_window(&window_id, &job_id)?;
            job_ids.push(job_id);
        }

        let mut assignment_ids = Vec::new();
        for (index, job_id) in job_ids.clone().into_iter().enumerate() {
            let assignment_id = state.assign_job(
                &job_id,
                format!("devnet-prover-{}", index % 4),
                if index % 2 == 0 { "gpu" } else { "cpu" },
                format!("devnet-bid-{index}"),
                90 + index as u64,
                deterministic_root(&format!("devnet-prover-pq-key-{index}")),
                deterministic_root(&format!("devnet-prover-capacity-{index}")),
                if index <= 1 {
                    "bridge-fast"
                } else {
                    "standard"
                },
            )?;
            assignment_ids.push(assignment_id.clone());
            state.mark_job_proved_verified(
                &job_id,
                deterministic_root(&format!("devnet-proof-commitment-{index}")),
                deterministic_root(&format!("devnet-proof-transcript-{index}")),
                94 + index as u64,
            )?;
            let attestation = PqProverAttestation::new(
                format!("devnet-prover-{}", index % 4),
                assignment_id,
                job_id,
                PqProverAttestationRole::Prover,
                deterministic_root(&format!("devnet-prover-pq-key-{index}")),
                deterministic_root(&format!("devnet-attestation-statement-{index}")),
                deterministic_root(&format!("devnet-attestation-transcript-{index}")),
                deterministic_root(&format!("devnet-attestation-signature-{index}")),
                deterministic_root(&format!("devnet-attestation-aggregate-{index}")),
                95 + index as u64,
                128 + index as u64,
                1,
            )?;
            state.insert_pq_attestation(attestation)?;
        }

        for kind in [
            AggregationWindowKind::BridgeFinality,
            AggregationWindowKind::PrivateContracts,
            AggregationWindowKind::IntentSettlement,
            AggregationWindowKind::PublicRollup,
            AggregationWindowKind::FeeRebates,
        ] {
            let window_id = window_ids
                .get(kind.as_str())
                .cloned()
                .ok_or_else(|| "devnet window missing for seal".to_string())?;
            state.seal_window(&window_id, 100)?;
        }

        let tree_id = deterministic_root("devnet-recursive-proof-tree");
        let bridge_jobs = state.jobs_for_lane(ProofPriorityLane::Bridge);
        let contract_jobs = state.jobs_for_lane(ProofPriorityLane::PrivateContracts);
        let intent_jobs = state.jobs_for_lane(ProofPriorityLane::Intents);
        let rollup_jobs = state.jobs_for_lane(ProofPriorityLane::PublicRollup);
        let rebate_jobs = state.jobs_for_lane(ProofPriorityLane::FeeRebates);
        let recursion_manifest = state
            .active_manifest_ids
            .get(RecursiveCircuitFamily::RecursiveAggregation.as_str())
            .cloned()
            .ok_or_else(|| "devnet recursive manifest missing".to_string())?;
        let recursion_program_root = state
            .circuit_manifests
            .get(&recursion_manifest)
            .ok_or_else(|| "devnet recursive manifest record missing".to_string())?
            .recursion_program_root
            .clone();
        let leaf_specs = vec![
            (ProofPriorityLane::Bridge, bridge_jobs),
            (ProofPriorityLane::PrivateContracts, contract_jobs),
            (ProofPriorityLane::Intents, intent_jobs),
            (ProofPriorityLane::PublicRollup, rollup_jobs),
            (ProofPriorityLane::FeeRebates, rebate_jobs),
        ];
        let mut leaf_node_ids = Vec::new();
        for (index, (lane, lane_jobs)) in leaf_specs.into_iter().enumerate() {
            if lane_jobs.is_empty() {
                continue;
            }
            let node = RecursionTreeNode::new(
                tree_id.clone(),
                "",
                1,
                lane,
                RecursiveCircuitFamily::RecursiveAggregation,
                lane_jobs,
                Vec::new(),
                recursion_program_root.clone(),
                80,
                116,
                100 + index as u64,
                state.config.max_child_proofs_per_node,
                &json!({"fixture": "lane leaf", "lane": lane.as_str()}),
            )?
            .seal(106 + index as u64)?
            .verify(107 + index as u64)?;
            let node_id = state.insert_recursion_node(node)?;
            leaf_node_ids.push(node_id);
        }
        let root_node = RecursionTreeNode::new(
            tree_id,
            "",
            2,
            ProofPriorityLane::Maintenance,
            RecursiveCircuitFamily::RecursiveAggregation,
            Vec::new(),
            leaf_node_ids,
            recursion_program_root,
            80,
            116,
            112,
            state.config.max_child_proofs_per_node,
            &json!({"fixture": "devnet recursive root"}),
        )?
        .seal(114)?
        .verify(115)?;
        state.insert_recursion_node(root_node)?;

        let recursion_tree_root = state.recursion_tree_root();
        for (index, job_id) in job_ids.clone().into_iter().enumerate() {
            let job = state
                .proof_jobs
                .get(&job_id)
                .ok_or_else(|| "devnet compression job missing".to_string())?
                .clone();
            let receipt = ProofCompressionReceipt::new(
                job.job_id.clone(),
                job.assignment_id.clone(),
                job.proof_commitment.clone(),
                job.source_bytes,
                format!("devnet-compressed-proof-{index}"),
                deterministic_root(&format!("devnet-compressed-proof-commitment-{index}")),
                job.source_bytes / 4,
                recursion_tree_root.clone(),
                deterministic_root("devnet-recursive-verifier-key"),
                deterministic_root(&format!("devnet-compression-transcript-{index}")),
                116 + index as u64,
            )?
            .accept(117 + index as u64)?;
            state.insert_compression_receipt(receipt)?;
            state.mark_job_compressed(&job_id)?;
        }

        for (index, assignment_id) in assignment_ids.clone().into_iter().enumerate() {
            state.complete_assignment(&assignment_id, 118 + index as u64, true)?;
        }

        let challenge_target = state
            .compression_receipts
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "devnet compression receipt missing".to_string())?;
        let challenge = FailureChallengeRecord::new(
            ChallengeKind::CompressionMismatch,
            "compression_receipt",
            challenge_target,
            deterministic_commitment("devnet-watchtower"),
            deterministic_root("devnet-compression-challenge-evidence"),
            deterministic_root("devnet-expected-compression-root"),
            deterministic_root("devnet-observed-compression-root"),
            120,
            state.config.challenge_window_blocks,
            5_000,
            2_500,
        )?
        .resolve(ChallengeOutcome::ProofAccepted, 122)?;
        state.insert_challenge(challenge)?;

        for (index, assignment_id) in assignment_ids.into_iter().enumerate() {
            let assignment = state
                .market_assignments
                .get(&assignment_id)
                .ok_or_else(|| "devnet settlement assignment missing".to_string())?
                .clone();
            let job = state
                .proof_jobs
                .get(&assignment.job_id)
                .ok_or_else(|| "devnet settlement job missing".to_string())?
                .clone();
            let protocol_fee =
                mul_bps_round_up(job.offered_fee_units, state.config.protocol_fee_bps);
            let rebate =
                mul_bps_round_up(job.rebate_eligible_units, state.config.sponsor_rebate_bps);
            let prover_payment = assignment
                .bid_fee_units
                .saturating_sub(protocol_fee.min(assignment.bid_fee_units));
            state.insert_fee_ledger_entry(ProofFeeLedgerEntry::new(
                FeeLedgerEntryKind::JobEscrow,
                job.job_id.clone(),
                assignment.assignment_id.clone(),
                job.requester_commitment.clone(),
                job.fee_asset_id.clone(),
                job.offered_fee_units,
                0,
                0,
                0,
                118 + index as u64,
                &json!({"stage": "escrow"}),
            )?)?;
            state.insert_fee_ledger_entry(ProofFeeLedgerEntry::new(
                FeeLedgerEntryKind::ProverPayment,
                job.job_id.clone(),
                assignment.assignment_id.clone(),
                deterministic_commitment(&format!("{}:account", assignment.prover_id)),
                job.fee_asset_id.clone(),
                0,
                prover_payment,
                0,
                0,
                119 + index as u64,
                &json!({"stage": "prover_payment"}),
            )?)?;
            state.insert_fee_ledger_entry(ProofFeeLedgerEntry::new(
                FeeLedgerEntryKind::ProtocolFee,
                job.job_id.clone(),
                assignment.assignment_id.clone(),
                deterministic_commitment("devnet-protocol-fee-vault"),
                job.fee_asset_id.clone(),
                0,
                0,
                0,
                protocol_fee,
                119 + index as u64,
                &json!({"stage": "protocol_fee"}),
            )?)?;
            if rebate > 0 {
                state.insert_fee_ledger_entry(ProofFeeLedgerEntry::new(
                    FeeLedgerEntryKind::SponsorRebate,
                    job.job_id,
                    assignment.assignment_id,
                    job.requester_commitment,
                    job.fee_asset_id,
                    0,
                    0,
                    rebate,
                    0,
                    120 + index as u64,
                    &json!({"stage": "rebate"}),
                )?)?;
            }
        }

        let fixture = RecursiveProofSchedulerDevnetFixture::new(
            "devnet-recursive-proof-scheduler-fixture",
            state.height,
            state.manifest_root(),
            state.priority_lane_root(),
            state.aggregation_window_root(),
            state.proof_job_root(),
            state.recursion_tree_root(),
            state.market_assignment_root(),
            state.pq_attestation_root(),
            state.compression_receipt_root(),
            state.fee_ledger_root(),
            &json!({
                "purpose": "deterministic recursive proof scheduling fixture",
                "bridge_jobs": 2,
                "private_contract_jobs": 2,
                "intent_jobs": 1,
                "rollup_jobs": 1,
                "fee_rebate_jobs": 1,
            }),
        )?;
        state.insert_devnet_fixture(fixture)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for manifest in self.circuit_manifests.values_mut() {
            if manifest.expires_at_height != 0
                && height >= manifest.expires_at_height
                && manifest.status == RECURSIVE_PROOF_SCHEDULER_STATUS_ACTIVE
            {
                manifest.status = RECURSIVE_PROOF_SCHEDULER_STATUS_EXPIRED.to_string();
            }
        }
        for window in self.aggregation_windows.values_mut() {
            if height > window.end_height && window.status == AggregationWindowStatus::Open {
                window.status = AggregationWindowStatus::Expired;
            }
        }
        for job in self.proof_jobs.values_mut() {
            if height > job.deadline_height
                && matches!(
                    job.status,
                    ProofJobStatus::Pending | ProofJobStatus::Assigned | ProofJobStatus::Proving
                )
            {
                job.status = ProofJobStatus::Expired;
            }
        }
        for assignment in self.market_assignments.values_mut() {
            if height > assignment.lease_end_height
                && matches!(
                    assignment.status,
                    MarketAssignmentStatus::Assigned | MarketAssignmentStatus::Accepted
                )
            {
                assignment.status = MarketAssignmentStatus::Expired;
            }
        }
        for attestation in self.pq_attestations.values_mut() {
            if attestation.expires_at_height != 0
                && height >= attestation.expires_at_height
                && attestation.status == RECURSIVE_PROOF_SCHEDULER_STATUS_VERIFIED
            {
                attestation.status = RECURSIVE_PROOF_SCHEDULER_STATUS_EXPIRED.to_string();
            }
        }
        for challenge in self.challenges.values_mut() {
            if height > challenge.deadline_height
                && challenge.status == RECURSIVE_PROOF_SCHEDULER_STATUS_CHALLENGED
            {
                challenge.status = RECURSIVE_PROOF_SCHEDULER_STATUS_EXPIRED.to_string();
            }
        }
    }

    pub fn insert_circuit_manifest(
        &mut self,
        manifest: CircuitFamilyManifest,
    ) -> RecursiveProofSchedulerResult<String> {
        manifest.validate()?;
        insert_unique_record(
            &mut self.circuit_manifests,
            manifest.manifest_id.clone(),
            manifest,
            "recursive circuit manifest",
        )
    }

    pub fn publish_manifest(
        &mut self,
        manifest_id: &str,
    ) -> RecursiveProofSchedulerResult<CircuitFamilyManifest> {
        let manifest = self
            .circuit_manifests
            .get(manifest_id)
            .ok_or_else(|| "unknown recursive circuit manifest".to_string())?
            .clone();
        if !manifest.is_active_at(self.height) {
            return Err("recursive circuit manifest is not active at current height".to_string());
        }
        self.active_manifest_ids.insert(
            manifest.family.as_str().to_string(),
            manifest_id.to_string(),
        );
        Ok(manifest)
    }

    pub fn insert_priority_lane(
        &mut self,
        lane: PriorityLaneConfig,
    ) -> RecursiveProofSchedulerResult<String> {
        lane.validate()?;
        insert_unique_record(
            &mut self.priority_lanes,
            lane.lane_id.clone(),
            lane,
            "priority lane",
        )
    }

    pub fn activate_lane(
        &mut self,
        lane_id: &str,
    ) -> RecursiveProofSchedulerResult<PriorityLaneConfig> {
        let lane = self
            .priority_lanes
            .get(lane_id)
            .ok_or_else(|| "unknown priority lane".to_string())?
            .clone();
        if lane.status != RECURSIVE_PROOF_SCHEDULER_STATUS_ACTIVE {
            return Err("priority lane is not active".to_string());
        }
        self.active_lane_ids
            .insert(lane.lane.as_str().to_string(), lane_id.to_string());
        Ok(lane)
    }

    pub fn insert_aggregation_window(
        &mut self,
        window: AggregationWindow,
    ) -> RecursiveProofSchedulerResult<String> {
        window.validate()?;
        if !self.active_lane_ids.contains_key(window.lane.as_str()) {
            return Err("aggregation window references inactive lane".to_string());
        }
        insert_unique_record(
            &mut self.aggregation_windows,
            window.window_id.clone(),
            window,
            "aggregation window",
        )
    }

    pub fn insert_proof_job(&mut self, job: ProofJob) -> RecursiveProofSchedulerResult<String> {
        job.validate()?;
        if self.proof_jobs.len() as u64 >= self.config.max_jobs {
            return Err("recursive scheduler job limit reached".to_string());
        }
        if !self.circuit_manifests.contains_key(&job.manifest_id) {
            return Err("proof job references unknown manifest".to_string());
        }
        if !self.aggregation_windows.contains_key(&job.window_id) {
            return Err("proof job references unknown aggregation window".to_string());
        }
        if !self.active_lane_ids.contains_key(job.lane.as_str()) {
            return Err("proof job references inactive lane".to_string());
        }
        if self.consumed_nullifiers.contains(&job.nullifier) {
            return Err("proof job nullifier already consumed".to_string());
        }
        let lane_key = job.lane.as_str().to_string();
        let job_id = job.job_id.clone();
        self.consumed_nullifiers.insert(job.nullifier.clone());
        self.queue_by_lane
            .entry(lane_key)
            .or_default()
            .push(job_id.clone());
        self.proof_jobs.insert(job_id.clone(), job);
        Ok(job_id)
    }

    pub fn add_job_to_window(
        &mut self,
        window_id: &str,
        job_id: &str,
    ) -> RecursiveProofSchedulerResult<()> {
        let job = self
            .proof_jobs
            .get(job_id)
            .ok_or_else(|| "unknown proof job for window admission".to_string())?
            .clone();
        let window = self
            .aggregation_windows
            .get_mut(window_id)
            .ok_or_else(|| "unknown aggregation window".to_string())?;
        if window.window_id != job.window_id {
            return Err("proof job window id mismatch".to_string());
        }
        if window.lane != job.lane {
            return Err("proof job lane does not match aggregation window".to_string());
        }
        window.add_job(job_id.to_string())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assign_job(
        &mut self,
        job_id: &str,
        prover_id: impl Into<String>,
        worker_class: impl Into<String>,
        bid_id: impl Into<String>,
        assigned_at_height: u64,
        pq_public_key_root: impl Into<String>,
        capacity_commitment_root: impl Into<String>,
        sla_tier: impl Into<String>,
    ) -> RecursiveProofSchedulerResult<String> {
        let job = self
            .proof_jobs
            .get(job_id)
            .ok_or_else(|| "unknown proof job for assignment".to_string())?
            .clone();
        if job.status != ProofJobStatus::Pending {
            return Err("proof job is not pending assignment".to_string());
        }
        let assignment = ProofMarketAssignment::new(
            &job,
            prover_id,
            worker_class,
            bid_id,
            job.offered_fee_units,
            mul_bps_round_up(job.offered_fee_units, self.config.slashing_bps),
            assigned_at_height,
            self.config.assignment_lease_blocks,
            pq_public_key_root,
            capacity_commitment_root,
            sla_tier,
        )?;
        let assignment_id = assignment.assignment_id.clone();
        if let Some(stored) = self.proof_jobs.get_mut(job_id) {
            stored.assign(assignment.prover_id.clone(), assignment_id.clone())?;
        }
        self.market_assignments
            .insert(assignment_id.clone(), assignment);
        Ok(assignment_id)
    }

    pub fn mark_job_proved_verified(
        &mut self,
        job_id: &str,
        proof_commitment: impl Into<String>,
        proof_transcript_root: impl Into<String>,
        verified_at_height: u64,
    ) -> RecursiveProofSchedulerResult<()> {
        let job = self
            .proof_jobs
            .get_mut(job_id)
            .ok_or_else(|| "unknown proof job for proof update".to_string())?;
        if job.status == ProofJobStatus::Assigned {
            job.mark_proving()?;
        }
        job.mark_proved(proof_commitment, proof_transcript_root)?;
        job.mark_verified(verified_at_height)?;
        Ok(())
    }

    pub fn mark_job_compressed(&mut self, job_id: &str) -> RecursiveProofSchedulerResult<()> {
        let job = self
            .proof_jobs
            .get_mut(job_id)
            .ok_or_else(|| "unknown proof job for compression update".to_string())?;
        job.mark_compressed()
    }

    pub fn complete_assignment(
        &mut self,
        assignment_id: &str,
        completed_at_height: u64,
        settle: bool,
    ) -> RecursiveProofSchedulerResult<()> {
        let assignment = self
            .market_assignments
            .remove(assignment_id)
            .ok_or_else(|| "unknown market assignment".to_string())?;
        let assignment = assignment.complete(completed_at_height)?;
        let assignment = if settle {
            assignment.settle()?
        } else {
            assignment
        };
        self.market_assignments
            .insert(assignment.assignment_id.clone(), assignment);
        Ok(())
    }

    pub fn seal_window(
        &mut self,
        window_id: &str,
        sealed_at_height: u64,
    ) -> RecursiveProofSchedulerResult<()> {
        let window = self
            .aggregation_windows
            .remove(window_id)
            .ok_or_else(|| "unknown aggregation window".to_string())?;
        let sealed = window.seal(sealed_at_height)?;
        self.aggregation_windows
            .insert(sealed.window_id.clone(), sealed);
        Ok(())
    }

    pub fn insert_recursion_node(
        &mut self,
        node: RecursionTreeNode,
    ) -> RecursiveProofSchedulerResult<String> {
        node.validate()?;
        for job_id in &node.child_job_ids {
            if !self.proof_jobs.contains_key(job_id) {
                return Err("recursion node references unknown child job".to_string());
            }
        }
        for child_node_id in &node.child_node_ids {
            if !self.recursion_nodes.contains_key(child_node_id) {
                return Err("recursion node references unknown child node".to_string());
            }
        }
        if !node.parent_node_id.is_empty()
            && !self.recursion_nodes.contains_key(&node.parent_node_id)
        {
            return Err("recursion node references unknown parent node".to_string());
        }
        insert_unique_record(
            &mut self.recursion_nodes,
            node.node_id.clone(),
            node,
            "recursion node",
        )
    }

    pub fn insert_pq_attestation(
        &mut self,
        attestation: PqProverAttestation,
    ) -> RecursiveProofSchedulerResult<String> {
        attestation.validate()?;
        if !self.proof_jobs.contains_key(&attestation.job_id) {
            return Err("PQ attestation references unknown job".to_string());
        }
        if !self
            .market_assignments
            .contains_key(&attestation.assignment_id)
        {
            return Err("PQ attestation references unknown assignment".to_string());
        }
        insert_unique_record(
            &mut self.pq_attestations,
            attestation.attestation_id.clone(),
            attestation,
            "PQ prover attestation",
        )
    }

    pub fn insert_compression_receipt(
        &mut self,
        receipt: ProofCompressionReceipt,
    ) -> RecursiveProofSchedulerResult<String> {
        receipt.validate()?;
        if !self.proof_jobs.contains_key(&receipt.job_id) {
            return Err("compression receipt references unknown job".to_string());
        }
        if !self.market_assignments.contains_key(&receipt.assignment_id) {
            return Err("compression receipt references unknown assignment".to_string());
        }
        insert_unique_record(
            &mut self.compression_receipts,
            receipt.receipt_id.clone(),
            receipt,
            "proof compression receipt",
        )
    }

    pub fn insert_challenge(
        &mut self,
        challenge: FailureChallengeRecord,
    ) -> RecursiveProofSchedulerResult<String> {
        challenge.validate()?;
        self.ensure_challenge_target_exists(&challenge.target_kind, &challenge.target_id)?;
        insert_unique_record(
            &mut self.challenges,
            challenge.challenge_id.clone(),
            challenge,
            "failure challenge",
        )
    }

    pub fn insert_fee_ledger_entry(
        &mut self,
        entry: ProofFeeLedgerEntry,
    ) -> RecursiveProofSchedulerResult<String> {
        entry.validate()?;
        if !entry.job_id.is_empty() && !self.proof_jobs.contains_key(&entry.job_id) {
            return Err("fee ledger entry references unknown job".to_string());
        }
        if !entry.assignment_id.is_empty()
            && !self.market_assignments.contains_key(&entry.assignment_id)
        {
            return Err("fee ledger entry references unknown assignment".to_string());
        }
        insert_unique_record(
            &mut self.fee_ledger,
            entry.entry_id.clone(),
            entry,
            "fee ledger entry",
        )
    }

    pub fn insert_devnet_fixture(
        &mut self,
        fixture: RecursiveProofSchedulerDevnetFixture,
    ) -> RecursiveProofSchedulerResult<String> {
        if !self.config.allow_devnet_fixtures {
            return Err("devnet fixtures are disabled".to_string());
        }
        fixture.validate()?;
        insert_unique_record(
            &mut self.devnet_fixtures,
            fixture.fixture_id.clone(),
            fixture,
            "devnet fixture",
        )
    }

    pub fn jobs_for_lane(&self, lane: ProofPriorityLane) -> Vec<String> {
        self.proof_jobs
            .values()
            .filter(|job| job.lane == lane)
            .map(|job| job.job_id.clone())
            .collect()
    }

    fn ensure_challenge_target_exists(
        &self,
        target_kind: &str,
        target_id: &str,
    ) -> RecursiveProofSchedulerResult<()> {
        let exists = match target_kind {
            "proof_job" => self.proof_jobs.contains_key(target_id),
            "recursion_node" => self.recursion_nodes.contains_key(target_id),
            "market_assignment" => self.market_assignments.contains_key(target_id),
            "pq_attestation" => self.pq_attestations.contains_key(target_id),
            "compression_receipt" => self.compression_receipts.contains_key(target_id),
            "aggregation_window" => self.aggregation_windows.contains_key(target_id),
            _ => false,
        };
        if !exists {
            return Err("challenge target does not exist".to_string());
        }
        Ok(())
    }

    pub fn manifest_root(&self) -> String {
        circuit_family_manifest_set_root(
            &self.circuit_manifests.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn active_manifest_root(&self) -> String {
        map_root(
            "RECURSIVE-PROOF-SCHEDULER-ACTIVE-MANIFEST",
            &self.active_manifest_ids,
        )
    }

    pub fn priority_lane_root(&self) -> String {
        priority_lane_set_root(&self.priority_lanes.values().cloned().collect::<Vec<_>>())
    }

    pub fn active_lane_root(&self) -> String {
        map_root(
            "RECURSIVE-PROOF-SCHEDULER-ACTIVE-LANE",
            &self.active_lane_ids,
        )
    }

    pub fn aggregation_window_root(&self) -> String {
        aggregation_window_set_root(
            &self
                .aggregation_windows
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn proof_job_root(&self) -> String {
        proof_job_set_root(&self.proof_jobs.values().cloned().collect::<Vec<_>>())
    }

    pub fn recursion_tree_root(&self) -> String {
        recursion_tree_node_set_root(&self.recursion_nodes.values().cloned().collect::<Vec<_>>())
    }

    pub fn market_assignment_root(&self) -> String {
        proof_market_assignment_set_root(
            &self
                .market_assignments
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn pq_attestation_root(&self) -> String {
        pq_prover_attestation_set_root(&self.pq_attestations.values().cloned().collect::<Vec<_>>())
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

    pub fn challenge_root(&self) -> String {
        failure_challenge_set_root(&self.challenges.values().cloned().collect::<Vec<_>>())
    }

    pub fn fee_ledger_root(&self) -> String {
        proof_fee_ledger_entry_set_root(&self.fee_ledger.values().cloned().collect::<Vec<_>>())
    }

    pub fn queue_root(&self) -> String {
        let records = self
            .queue_by_lane
            .iter()
            .map(|(lane, job_ids)| {
                json!({
                    "lane": lane,
                    "job_ids": job_ids,
                    "job_count": job_ids.len() as u64,
                    "job_root": string_set_root("RECURSIVE-PROOF-SCHEDULER-QUEUE-JOBS", job_ids),
                })
            })
            .collect::<Vec<_>>();
        merkle_root("RECURSIVE-PROOF-SCHEDULER-QUEUE", &records)
    }

    pub fn nullifier_root(&self) -> String {
        let values = self.consumed_nullifiers.iter().cloned().collect::<Vec<_>>();
        string_set_root("RECURSIVE-PROOF-SCHEDULER-CONSUMED-NULLIFIERS", &values)
    }

    pub fn devnet_fixture_root(&self) -> String {
        devnet_fixture_set_root(&self.devnet_fixtures.values().cloned().collect::<Vec<_>>())
    }

    pub fn roots(&self) -> RecursiveProofSchedulerRoots {
        let config_root = self.config.config_root();
        let manifest_root = self.manifest_root();
        let active_manifest_root = self.active_manifest_root();
        let priority_lane_root = self.priority_lane_root();
        let active_lane_root = self.active_lane_root();
        let aggregation_window_root = self.aggregation_window_root();
        let proof_job_root = self.proof_job_root();
        let recursion_tree_root = self.recursion_tree_root();
        let market_assignment_root = self.market_assignment_root();
        let pq_attestation_root = self.pq_attestation_root();
        let compression_receipt_root = self.compression_receipt_root();
        let challenge_root = self.challenge_root();
        let fee_ledger_root = self.fee_ledger_root();
        let queue_root = self.queue_root();
        let nullifier_root = self.nullifier_root();
        let devnet_fixture_root = self.devnet_fixture_root();
        let state_record = json!({
            "kind": "recursive_proof_scheduler_state_root",
            "chain_id": CHAIN_ID,
            "protocol_version": RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION,
            "schema_version": RECURSIVE_PROOF_SCHEDULER_SCHEMA_VERSION,
            "height": self.height,
            "scheduler_label_root": recursive_proof_scheduler_string_root(
                "RECURSIVE-PROOF-SCHEDULER-LABEL",
                &self.scheduler_label
            ),
            "config_root": config_root,
            "manifest_root": manifest_root,
            "active_manifest_root": active_manifest_root,
            "priority_lane_root": priority_lane_root,
            "active_lane_root": active_lane_root,
            "aggregation_window_root": aggregation_window_root,
            "proof_job_root": proof_job_root,
            "recursion_tree_root": recursion_tree_root,
            "market_assignment_root": market_assignment_root,
            "pq_attestation_root": pq_attestation_root,
            "compression_receipt_root": compression_receipt_root,
            "challenge_root": challenge_root,
            "fee_ledger_root": fee_ledger_root,
            "queue_root": queue_root,
            "nullifier_root": nullifier_root,
            "devnet_fixture_root": devnet_fixture_root,
            "counters": self.counters().public_record(),
        });
        let state_root = recursive_proof_scheduler_state_root_from_record(&state_record);
        RecursiveProofSchedulerRoots {
            config_root,
            manifest_root,
            active_manifest_root,
            priority_lane_root,
            active_lane_root,
            aggregation_window_root,
            proof_job_root,
            recursion_tree_root,
            market_assignment_root,
            pq_attestation_root,
            compression_receipt_root,
            challenge_root,
            fee_ledger_root,
            queue_root,
            nullifier_root,
            devnet_fixture_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn counters(&self) -> RecursiveProofSchedulerCounters {
        let mut counters = RecursiveProofSchedulerCounters {
            circuit_manifests: self.circuit_manifests.len() as u64,
            priority_lanes: self.priority_lanes.len() as u64,
            aggregation_windows: self.aggregation_windows.len() as u64,
            proof_jobs: self.proof_jobs.len() as u64,
            recursion_nodes: self.recursion_nodes.len() as u64,
            market_assignments: self.market_assignments.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            compression_receipts: self.compression_receipts.len() as u64,
            challenges: self.challenges.len() as u64,
            fee_ledger_entries: self.fee_ledger.len() as u64,
            ..RecursiveProofSchedulerCounters::default()
        };
        for window in self.aggregation_windows.values() {
            if window.status == AggregationWindowStatus::Open {
                counters.open_windows = counters.open_windows.saturating_add(1);
            }
        }
        for job in self.proof_jobs.values() {
            match job.status {
                ProofJobStatus::Pending => counters.pending_jobs += 1,
                ProofJobStatus::Assigned | ProofJobStatus::Proving => counters.assigned_jobs += 1,
                ProofJobStatus::Proved => counters.proved_jobs += 1,
                ProofJobStatus::Verified => counters.verified_jobs += 1,
                ProofJobStatus::Compressed | ProofJobStatus::Settled => {
                    counters.compressed_jobs += 1
                }
                ProofJobStatus::Failed | ProofJobStatus::Rejected | ProofJobStatus::Expired => {
                    counters.failed_jobs += 1
                }
                ProofJobStatus::Challenged => {}
            }
            counters.total_estimated_cycles = counters
                .total_estimated_cycles
                .saturating_add(job.estimated_cycles);
            counters.total_source_bytes =
                counters.total_source_bytes.saturating_add(job.source_bytes);
            counters.total_offered_fee_units = counters
                .total_offered_fee_units
                .saturating_add(job.offered_fee_units);
        }
        for assignment in self.market_assignments.values() {
            if assignment.is_active_at(self.height) {
                counters.active_assignments = counters.active_assignments.saturating_add(1);
            }
        }
        for receipt in self.compression_receipts.values() {
            if receipt.status == CompressionReceiptStatus::Accepted {
                counters.accepted_compression_receipts =
                    counters.accepted_compression_receipts.saturating_add(1);
            }
            counters.total_bytes_saved = counters
                .total_bytes_saved
                .saturating_add(receipt.bytes_saved());
        }
        for challenge in self.challenges.values() {
            if challenge.is_open_at(self.height) {
                counters.open_challenges = counters.open_challenges.saturating_add(1);
            }
        }
        for entry in self.fee_ledger.values() {
            counters.total_protocol_fee_units = counters
                .total_protocol_fee_units
                .saturating_add(entry.protocol_fee_units);
            counters.total_rebate_units = counters
                .total_rebate_units
                .saturating_add(entry.rebate_units);
        }
        counters
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "recursive_proof_scheduler_state",
            "chain_id": CHAIN_ID,
            "protocol_version": RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION,
            "schema_version": RECURSIVE_PROOF_SCHEDULER_SCHEMA_VERSION,
            "height": self.height,
            "scheduler_label": self.scheduler_label,
            "config": self.config.public_record(),
            "active_manifest_ids": self.active_manifest_ids,
            "active_lane_ids": self.active_lane_ids,
            "circuit_manifests": self.circuit_manifests.values().map(CircuitFamilyManifest::public_record).collect::<Vec<_>>(),
            "priority_lanes": self.priority_lanes.values().map(PriorityLaneConfig::public_record).collect::<Vec<_>>(),
            "aggregation_windows": self.aggregation_windows.values().map(AggregationWindow::public_record).collect::<Vec<_>>(),
            "proof_jobs": self.proof_jobs.values().map(ProofJob::public_record).collect::<Vec<_>>(),
            "recursion_nodes": self.recursion_nodes.values().map(RecursionTreeNode::public_record).collect::<Vec<_>>(),
            "market_assignments": self.market_assignments.values().map(ProofMarketAssignment::public_record).collect::<Vec<_>>(),
            "pq_attestations": self.pq_attestations.values().map(PqProverAttestation::public_record).collect::<Vec<_>>(),
            "compression_receipts": self.compression_receipts.values().map(ProofCompressionReceipt::public_record).collect::<Vec<_>>(),
            "challenges": self.challenges.values().map(FailureChallengeRecord::public_record).collect::<Vec<_>>(),
            "fee_ledger": self.fee_ledger.values().map(ProofFeeLedgerEntry::public_record).collect::<Vec<_>>(),
            "queue_by_lane": self.queue_by_lane,
            "consumed_nullifiers": self.consumed_nullifiers.iter().cloned().collect::<Vec<_>>(),
            "devnet_fixtures": self.devnet_fixtures.values().map(RecursiveProofSchedulerDevnetFixture::public_record).collect::<Vec<_>>(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "state_root": roots.state_root,
        })
    }

    pub fn validate(&self) -> RecursiveProofSchedulerResult<String> {
        ensure_non_empty(&self.scheduler_label, "recursive proof scheduler label")?;
        self.config.validate()?;
        if self.proof_jobs.len() as u64 > self.config.max_jobs {
            return Err("recursive scheduler has too many proof jobs".to_string());
        }
        if self.aggregation_windows.len() as u64 > self.config.max_windows {
            return Err("recursive scheduler has too many aggregation windows".to_string());
        }
        if self.market_assignments.len() as u64 > self.config.max_assignments {
            return Err("recursive scheduler has too many market assignments".to_string());
        }
        if self.pq_attestations.len() as u64 > self.config.max_attestations {
            return Err("recursive scheduler has too many PQ attestations".to_string());
        }
        if self.challenges.len() as u64 > self.config.max_challenges {
            return Err("recursive scheduler has too many challenges".to_string());
        }
        for manifest in self.circuit_manifests.values() {
            manifest.validate()?;
        }
        for (family, manifest_id) in &self.active_manifest_ids {
            let manifest = self
                .circuit_manifests
                .get(manifest_id)
                .ok_or_else(|| "active recursive manifest is missing".to_string())?;
            if manifest.family.as_str() != family {
                return Err("active recursive manifest family mismatch".to_string());
            }
            if !manifest.is_active_at(self.height) {
                return Err("active recursive manifest is not active at height".to_string());
            }
        }
        for lane in self.priority_lanes.values() {
            lane.validate()?;
        }
        for (lane_kind, lane_id) in &self.active_lane_ids {
            let lane = self
                .priority_lanes
                .get(lane_id)
                .ok_or_else(|| "active priority lane missing".to_string())?;
            if lane.lane.as_str() != lane_kind {
                return Err("active priority lane kind mismatch".to_string());
            }
        }
        for window in self.aggregation_windows.values() {
            window.validate()?;
            if !self.active_lane_ids.contains_key(window.lane.as_str()) {
                return Err("aggregation window references inactive lane".to_string());
            }
            for job_id in &window.admitted_job_ids {
                if !self.proof_jobs.contains_key(job_id) {
                    return Err("aggregation window references unknown proof job".to_string());
                }
            }
        }
        let mut observed_nullifiers = BTreeSet::new();
        for job in self.proof_jobs.values() {
            job.validate()?;
            if !self.circuit_manifests.contains_key(&job.manifest_id) {
                return Err("proof job references unknown manifest".to_string());
            }
            if !self.aggregation_windows.contains_key(&job.window_id) {
                return Err("proof job references unknown aggregation window".to_string());
            }
            if !self.active_lane_ids.contains_key(job.lane.as_str()) {
                return Err("proof job references inactive lane".to_string());
            }
            if !observed_nullifiers.insert(job.nullifier.clone()) {
                return Err("duplicate proof job nullifier".to_string());
            }
            if matches!(
                job.status,
                ProofJobStatus::Assigned
                    | ProofJobStatus::Proving
                    | ProofJobStatus::Proved
                    | ProofJobStatus::Verified
                    | ProofJobStatus::Compressed
                    | ProofJobStatus::Settled
            ) && !self.market_assignments.contains_key(&job.assignment_id)
            {
                return Err("assigned proof job references unknown assignment".to_string());
            }
        }
        if observed_nullifiers != self.consumed_nullifiers {
            return Err("consumed nullifier set does not match proof jobs".to_string());
        }
        for node in self.recursion_nodes.values() {
            node.validate()?;
            for job_id in &node.child_job_ids {
                if !self.proof_jobs.contains_key(job_id) {
                    return Err("recursion node references unknown child job".to_string());
                }
            }
            for child_node_id in &node.child_node_ids {
                if !self.recursion_nodes.contains_key(child_node_id) {
                    return Err("recursion node references unknown child node".to_string());
                }
            }
        }
        for assignment in self.market_assignments.values() {
            assignment.validate()?;
            let job = self
                .proof_jobs
                .get(&assignment.job_id)
                .ok_or_else(|| "market assignment references unknown job".to_string())?;
            if job.assignment_id != assignment.assignment_id
                && matches!(
                    job.status,
                    ProofJobStatus::Assigned
                        | ProofJobStatus::Proving
                        | ProofJobStatus::Proved
                        | ProofJobStatus::Verified
                        | ProofJobStatus::Compressed
                        | ProofJobStatus::Settled
                )
            {
                return Err("market assignment does not match proof job assignment".to_string());
            }
        }
        for attestation in self.pq_attestations.values() {
            attestation.validate()?;
            if !self.proof_jobs.contains_key(&attestation.job_id) {
                return Err("PQ attestation references unknown job".to_string());
            }
            if !self
                .market_assignments
                .contains_key(&attestation.assignment_id)
            {
                return Err("PQ attestation references unknown assignment".to_string());
            }
        }
        if self.config.require_pq_attestations {
            for job in self.proof_jobs.values().filter(|job| {
                matches!(
                    job.status,
                    ProofJobStatus::Proved
                        | ProofJobStatus::Verified
                        | ProofJobStatus::Compressed
                        | ProofJobStatus::Settled
                )
            }) {
                let has_attestation = self
                    .pq_attestations
                    .values()
                    .any(|attestation| attestation.job_id == job.job_id);
                if !has_attestation {
                    return Err("proved job missing PQ prover attestation".to_string());
                }
            }
        }
        for receipt in self.compression_receipts.values() {
            receipt.validate()?;
            if !self.proof_jobs.contains_key(&receipt.job_id) {
                return Err("compression receipt references unknown job".to_string());
            }
            if !self.market_assignments.contains_key(&receipt.assignment_id) {
                return Err("compression receipt references unknown assignment".to_string());
            }
        }
        if self.config.require_compression_receipts {
            for job in self.proof_jobs.values().filter(|job| {
                matches!(
                    job.status,
                    ProofJobStatus::Compressed | ProofJobStatus::Settled
                )
            }) {
                let has_receipt = self
                    .compression_receipts
                    .values()
                    .any(|receipt| receipt.job_id == job.job_id);
                if !has_receipt {
                    return Err("compressed job missing compression receipt".to_string());
                }
            }
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
            self.ensure_challenge_target_exists(&challenge.target_kind, &challenge.target_id)?;
        }
        for entry in self.fee_ledger.values() {
            entry.validate()?;
            if !entry.job_id.is_empty() && !self.proof_jobs.contains_key(&entry.job_id) {
                return Err("fee ledger entry references unknown job".to_string());
            }
            if !entry.assignment_id.is_empty()
                && !self.market_assignments.contains_key(&entry.assignment_id)
            {
                return Err("fee ledger entry references unknown assignment".to_string());
            }
        }
        for (lane, job_ids) in &self.queue_by_lane {
            if !self.active_lane_ids.contains_key(lane) {
                return Err("queue references inactive lane".to_string());
            }
            for job_id in job_ids {
                let job = self
                    .proof_jobs
                    .get(job_id)
                    .ok_or_else(|| "queue references unknown job".to_string())?;
                if job.lane.as_str() != lane {
                    return Err("queue lane does not match job lane".to_string());
                }
            }
        }
        for fixture in self.devnet_fixtures.values() {
            fixture.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn recursive_proof_scheduler_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-STATE",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn recursive_proof_scheduler_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn recursive_proof_scheduler_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(RECURSIVE_PROOF_SCHEDULER_PROTOCOL_VERSION),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn deterministic_root(label: &str) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-DETERMINISTIC-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn deterministic_commitment(label: &str) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-DETERMINISTIC-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn recursive_proof_scheduler_config_id(record: &Value) -> String {
    recursive_proof_scheduler_payload_root("RECURSIVE-PROOF-SCHEDULER-CONFIG-ID", record)
}

pub fn circuit_public_input_schema_root(
    family: &str,
    circuit_name: &str,
    manifest_version: u64,
    max_public_inputs: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-PUBLIC-INPUT-SCHEMA",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Int(manifest_version as i128),
            HashPart::Int(max_public_inputs as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn circuit_witness_schema_root(
    family: &str,
    circuit_name: &str,
    manifest_version: u64,
    max_witness_bytes: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-WITNESS-SCHEMA",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Int(manifest_version as i128),
            HashPart::Int(max_witness_bytes as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn recursion_program_root(
    family: &str,
    circuit_name: &str,
    manifest_version: u64,
    proof_system: &str,
    verifier_key_root: &str,
) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-RECURSION-PROGRAM",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Int(manifest_version as i128),
            HashPart::Str(proof_system),
            HashPart::Str(verifier_key_root),
        ],
        32,
    )
}

pub fn circuit_family_manifest_id(
    family: &str,
    circuit_name: &str,
    manifest_version: u64,
    proof_system: &str,
    verifier_key_root: &str,
    public_input_schema_root: &str,
) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-CIRCUIT-FAMILY-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(family),
            HashPart::Str(circuit_name),
            HashPart::Int(manifest_version as i128),
            HashPart::Str(proof_system),
            HashPart::Str(verifier_key_root),
            HashPart::Str(public_input_schema_root),
        ],
        32,
    )
}

pub fn circuit_family_manifest_root(manifest: &CircuitFamilyManifest) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-CIRCUIT-FAMILY-MANIFEST",
        &[HashPart::Json(&manifest.public_record())],
        32,
    )
}

pub fn circuit_family_manifest_set_root(manifests: &[CircuitFamilyManifest]) -> String {
    let mut records = manifests
        .iter()
        .map(|manifest| (manifest.manifest_id.clone(), manifest.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "RECURSIVE-PROOF-SCHEDULER-CIRCUIT-FAMILY-MANIFEST",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn priority_lane_id(lane: &str, display_name: &str, reserved_window_bps: u64) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-PRIORITY-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane),
            HashPart::Str(display_name),
            HashPart::Int(reserved_window_bps as i128),
        ],
        32,
    )
}

pub fn priority_lane_root(lane: &PriorityLaneConfig) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-PRIORITY-LANE",
        &[HashPart::Json(&lane.public_record())],
        32,
    )
}

pub fn priority_lane_set_root(lanes: &[PriorityLaneConfig]) -> String {
    let mut records = lanes
        .iter()
        .map(|lane| (lane.lane_id.clone(), lane.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "RECURSIVE-PROOF-SCHEDULER-PRIORITY-LANE",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn family_set_root(families: &[RecursiveCircuitFamily]) -> String {
    let mut values = families
        .iter()
        .map(|family| family.as_str().to_string())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    let leaves = values.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root("RECURSIVE-PROOF-SCHEDULER-FAMILY-SET", &leaves)
}

pub fn aggregation_window_id(
    kind: &str,
    lane: &str,
    start_height: u64,
    end_height: u64,
    eligible_family_root: &str,
) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-AGGREGATION-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(lane),
            HashPart::Int(start_height as i128),
            HashPart::Int(end_height as i128),
            HashPart::Str(eligible_family_root),
        ],
        32,
    )
}

pub fn aggregation_window_root(window: &AggregationWindow) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-AGGREGATION-WINDOW",
        &[HashPart::Json(&window.public_record())],
        32,
    )
}

pub fn aggregation_window_set_root(windows: &[AggregationWindow]) -> String {
    let mut records = windows
        .iter()
        .map(|window| (window.window_id.clone(), window.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "RECURSIVE-PROOF-SCHEDULER-AGGREGATION-WINDOW",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn proof_job_nullifier(
    job_kind: &str,
    family: &str,
    requester_commitment: &str,
    source_payload_root: &str,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-PROOF-JOB-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_kind),
            HashPart::Str(family),
            HashPart::Str(requester_commitment),
            HashPart::Str(source_payload_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn proof_job_id(
    job_kind: &str,
    family: &str,
    lane: &str,
    manifest_id: &str,
    public_input_root: &str,
    source_payload_root: &str,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-PROOF-JOB-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_kind),
            HashPart::Str(family),
            HashPart::Str(lane),
            HashPart::Str(manifest_id),
            HashPart::Str(public_input_root),
            HashPart::Str(source_payload_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn proof_job_root(job: &ProofJob) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-PROOF-JOB",
        &[HashPart::Json(&job.public_record())],
        32,
    )
}

pub fn proof_job_set_root(jobs: &[ProofJob]) -> String {
    let mut records = jobs
        .iter()
        .map(|job| (job.job_id.clone(), job.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "RECURSIVE-PROOF-SCHEDULER-PROOF-JOB",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn recursion_node_public_input_root(
    tree_id: &str,
    depth: u64,
    child_proof_root: &str,
    child_node_root: &str,
    batch_start_height: u64,
    batch_end_height: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-RECURSION-PUBLIC-INPUT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(tree_id),
            HashPart::Int(depth as i128),
            HashPart::Str(child_proof_root),
            HashPart::Str(child_node_root),
            HashPart::Int(batch_start_height as i128),
            HashPart::Int(batch_end_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn recursion_node_accumulator_root(
    child_proof_root: &str,
    child_node_root: &str,
    public_input_root: &str,
    depth: u64,
    child_job_count: u64,
    child_node_count: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-RECURSION-ACCUMULATOR",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(child_proof_root),
            HashPart::Str(child_node_root),
            HashPart::Str(public_input_root),
            HashPart::Int(depth as i128),
            HashPart::Int(child_job_count as i128),
            HashPart::Int(child_node_count as i128),
        ],
        32,
    )
}

pub fn recursion_tree_node_id(
    tree_id: &str,
    depth: u64,
    child_proof_root: &str,
    child_node_root: &str,
    public_input_root: &str,
    accumulator_root: &str,
) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-RECURSION-NODE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(tree_id),
            HashPart::Int(depth as i128),
            HashPart::Str(child_proof_root),
            HashPart::Str(child_node_root),
            HashPart::Str(public_input_root),
            HashPart::Str(accumulator_root),
        ],
        32,
    )
}

pub fn recursion_tree_node_root(node: &RecursionTreeNode) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-RECURSION-NODE",
        &[HashPart::Json(&node.public_record())],
        32,
    )
}

pub fn recursion_tree_node_set_root(nodes: &[RecursionTreeNode]) -> String {
    let mut records = nodes
        .iter()
        .map(|node| (node.node_id.clone(), node.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "RECURSIVE-PROOF-SCHEDULER-RECURSION-NODE",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn market_assignment_acceptance_root(
    job_id: &str,
    prover_id: &str,
    bid_id: &str,
    bid_fee_units: u64,
    lease_start_height: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-MARKET-ACCEPTANCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(prover_id),
            HashPart::Str(bid_id),
            HashPart::Int(bid_fee_units as i128),
            HashPart::Int(lease_start_height as i128),
        ],
        32,
    )
}

pub fn proof_market_assignment_id(
    job_id: &str,
    prover_id: &str,
    bid_id: &str,
    bid_fee_units: u64,
    lease_start_height: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-MARKET-ASSIGNMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(prover_id),
            HashPart::Str(bid_id),
            HashPart::Int(bid_fee_units as i128),
            HashPart::Int(lease_start_height as i128),
        ],
        32,
    )
}

pub fn proof_market_assignment_root(assignment: &ProofMarketAssignment) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-MARKET-ASSIGNMENT",
        &[HashPart::Json(&assignment.public_record())],
        32,
    )
}

pub fn proof_market_assignment_set_root(assignments: &[ProofMarketAssignment]) -> String {
    let mut records = assignments
        .iter()
        .map(|assignment| (assignment.assignment_id.clone(), assignment.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "RECURSIVE-PROOF-SCHEDULER-MARKET-ASSIGNMENT",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn pq_prover_attestation_id(
    prover_id: &str,
    assignment_id: &str,
    job_id: &str,
    role: &str,
    statement_root: &str,
    attested_at_height: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-PQ-PROVER-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(prover_id),
            HashPart::Str(assignment_id),
            HashPart::Str(job_id),
            HashPart::Str(role),
            HashPart::Str(statement_root),
            HashPart::Int(attested_at_height as i128),
        ],
        32,
    )
}

pub fn pq_prover_attestation_root(attestation: &PqProverAttestation) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-PQ-PROVER-ATTESTATION",
        &[HashPart::Json(&attestation.public_record())],
        32,
    )
}

pub fn pq_prover_attestation_set_root(attestations: &[PqProverAttestation]) -> String {
    let mut records = attestations
        .iter()
        .map(|attestation| {
            (
                attestation.attestation_id.clone(),
                attestation.public_record(),
            )
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "RECURSIVE-PROOF-SCHEDULER-PQ-PROVER-ATTESTATION",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn proof_compression_receipt_id(
    job_id: &str,
    assignment_id: &str,
    source_proof_commitment: &str,
    compressed_proof_id: &str,
    compressed_proof_commitment: &str,
    compression_ratio_bps: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-COMPRESSION-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(job_id),
            HashPart::Str(assignment_id),
            HashPart::Str(source_proof_commitment),
            HashPart::Str(compressed_proof_id),
            HashPart::Str(compressed_proof_commitment),
            HashPart::Int(compression_ratio_bps as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn proof_compression_receipt_root(receipt: &ProofCompressionReceipt) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-COMPRESSION-RECEIPT",
        &[HashPart::Json(&receipt.public_record())],
        32,
    )
}

pub fn proof_compression_receipt_set_root(receipts: &[ProofCompressionReceipt]) -> String {
    let mut records = receipts
        .iter()
        .map(|receipt| (receipt.receipt_id.clone(), receipt.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "RECURSIVE-PROOF-SCHEDULER-COMPRESSION-RECEIPT",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn failure_challenge_id(
    challenge_kind: &str,
    target_kind: &str,
    target_id: &str,
    challenger_commitment: &str,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-FAILURE-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_kind),
            HashPart::Str(target_kind),
            HashPart::Str(target_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn failure_challenge_root(challenge: &FailureChallengeRecord) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-FAILURE-CHALLENGE",
        &[HashPart::Json(&challenge.public_record())],
        32,
    )
}

pub fn failure_challenge_set_root(challenges: &[FailureChallengeRecord]) -> String {
    let mut records = challenges
        .iter()
        .map(|challenge| (challenge.challenge_id.clone(), challenge.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "RECURSIVE-PROOF-SCHEDULER-FAILURE-CHALLENGE",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn proof_fee_ledger_entry_id(
    entry_kind: &str,
    job_id: &str,
    assignment_id: &str,
    account_commitment: &str,
    asset_id: &str,
    debit_units: u64,
    credit_units: u64,
    rebate_units: u64,
    protocol_fee_units: u64,
    height: u64,
    memo_root: &str,
) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-FEE-LEDGER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(entry_kind),
            HashPart::Str(job_id),
            HashPart::Str(assignment_id),
            HashPart::Str(account_commitment),
            HashPart::Str(asset_id),
            HashPart::Int(debit_units as i128),
            HashPart::Int(credit_units as i128),
            HashPart::Int(rebate_units as i128),
            HashPart::Int(protocol_fee_units as i128),
            HashPart::Int(height as i128),
            HashPart::Str(memo_root),
        ],
        32,
    )
}

pub fn proof_fee_ledger_entry_root(entry: &ProofFeeLedgerEntry) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-FEE-LEDGER",
        &[HashPart::Json(&entry.public_record())],
        32,
    )
}

pub fn proof_fee_ledger_entry_set_root(entries: &[ProofFeeLedgerEntry]) -> String {
    let mut records = entries
        .iter()
        .map(|entry| (entry.entry_id.clone(), entry.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "RECURSIVE-PROOF-SCHEDULER-FEE-LEDGER",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn devnet_fixture_id(
    label: &str,
    height: u64,
    manifest_root: &str,
    lane_root: &str,
    window_root: &str,
    job_root: &str,
    recursion_tree_root: &str,
) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-DEVNET-FIXTURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(height as i128),
            HashPart::Str(manifest_root),
            HashPart::Str(lane_root),
            HashPart::Str(window_root),
            HashPart::Str(job_root),
            HashPart::Str(recursion_tree_root),
        ],
        32,
    )
}

pub fn devnet_fixture_root(fixture: &RecursiveProofSchedulerDevnetFixture) -> String {
    domain_hash(
        "RECURSIVE-PROOF-SCHEDULER-DEVNET-FIXTURE",
        &[HashPart::Json(&fixture.public_record())],
        32,
    )
}

pub fn devnet_fixture_set_root(fixtures: &[RecursiveProofSchedulerDevnetFixture]) -> String {
    let mut records = fixtures
        .iter()
        .map(|fixture| (fixture.fixture_id.clone(), fixture.public_record()))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        "RECURSIVE-PROOF-SCHEDULER-DEVNET-FIXTURE",
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

pub fn string_set_root(domain: &str, values: &[String]) -> String {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    let leaves = values.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn map_root(domain: &str, values: &BTreeMap<String, String>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(RECURSIVE_PROOF_SCHEDULER_MAX_BPS)
        .checked_div(denominator)
        .unwrap_or(0)
}

pub fn mul_bps_round_up(value: u64, bps: u64) -> u64 {
    if value == 0 || bps == 0 {
        return 0;
    }
    value
        .saturating_mul(bps)
        .saturating_add(RECURSIVE_PROOF_SCHEDULER_MAX_BPS - 1)
        / RECURSIVE_PROOF_SCHEDULER_MAX_BPS
}

fn insert_unique_record<T>(
    map: &mut BTreeMap<String, T>,
    id: String,
    record: T,
    label: &str,
) -> RecursiveProofSchedulerResult<String> {
    if map.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    map.insert(id.clone(), record);
    Ok(id)
}

fn ensure_non_empty(value: &str, label: &str) -> RecursiveProofSchedulerResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn ensure_hash(value: &str, label: &str) -> RecursiveProofSchedulerResult<()> {
    if value.len() != 64 || !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(format!("{label} must be a 32-byte hex root"));
    }
    Ok(())
}

fn ensure_hash_or_empty(value: &str, label: &str) -> RecursiveProofSchedulerResult<()> {
    if value.is_empty() {
        return Ok(());
    }
    ensure_hash(value, label)
}

fn ensure_hashes(values: &[String], label: &str) -> RecursiveProofSchedulerResult<()> {
    for value in values {
        ensure_hash(value, label)?;
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> RecursiveProofSchedulerResult<()> {
    if value > RECURSIVE_PROOF_SCHEDULER_MAX_BPS {
        return Err(format!("{label} exceeds 100%"));
    }
    Ok(())
}

fn devnet_manifest(
    family: RecursiveCircuitFamily,
    max_public_inputs: u64,
    max_witness_bytes: u64,
    target_proof_bytes: u64,
    max_child_proofs: u64,
) -> RecursiveProofSchedulerResult<CircuitFamilyManifest> {
    CircuitFamilyManifest::new(
        family,
        1,
        family.default_circuit_name(),
        family.default_proof_system(),
        deterministic_root(&format!("devnet-verifier-key-{}", family.as_str())),
        max_public_inputs,
        max_witness_bytes,
        target_proof_bytes,
        25_000,
        max_child_proofs,
        RECURSIVE_PROOF_SCHEDULER_DEFAULT_SECURITY_BITS,
        0,
        0,
        &json!({
            "family": family.as_str(),
            "hash_suite": RECURSIVE_PROOF_SCHEDULER_HASH_SUITE,
            "pq_signature_scheme": RECURSIVE_PROOF_SCHEDULER_PQ_SIGNATURE_SCHEME,
            "pq_recovery_scheme": RECURSIVE_PROOF_SCHEDULER_PQ_RECOVERY_SCHEME,
            "pq_kem_scheme": RECURSIVE_PROOF_SCHEDULER_PQ_KEM_SCHEME,
            "recursion_scheme": RECURSIVE_PROOF_SCHEDULER_RECURSION_SCHEME,
            "compression_scheme": RECURSIVE_PROOF_SCHEDULER_COMPRESSION_SCHEME,
            "fixture": "devnet",
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_validates_and_is_stable() {
        let state = RecursiveProofSchedulerState::devnet().expect("devnet scheduler state");
        let root = state.validate().expect("valid scheduler state");
        assert_eq!(root.len(), 64);
        assert_eq!(root, state.state_root());
        assert_eq!(state.counters().proof_jobs, 7);
        assert_eq!(state.counters().compressed_jobs, 7);
    }

    #[test]
    fn config_id_is_bound_to_identity_record() {
        let config = RecursiveProofSchedulerConfig::default();
        assert_eq!(
            config.config_id,
            recursive_proof_scheduler_config_id(&config.identity_record())
        );
    }

    #[test]
    fn compression_receipt_rejects_growth() {
        let receipt = ProofCompressionReceipt::new(
            deterministic_root("job"),
            deterministic_root("assignment"),
            deterministic_root("source-proof"),
            1_000,
            "compressed",
            deterministic_root("compressed-proof"),
            1_200,
            deterministic_root("tree"),
            deterministic_root("verifier-key"),
            deterministic_root("transcript"),
            1,
        );
        assert!(receipt.is_err());
    }
}
