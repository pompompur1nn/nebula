use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_FORMAL_VERIFIER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-formal-verifier-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_FORMAL_VERIFIER_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_FORMAL_VERIFIER_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const SCHEMA_VERSION: u64 =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_FORMAL_VERIFIER_RUNTIME_SCHEMA_VERSION;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-contract-formal-verifier-v1";
pub const BYTECODE_COMMITMENT_SCHEME: &str =
    "private-l2-pq-confidential-contract-bytecode-commitment-v1";
pub const SPEC_COMMITMENT_SCHEME: &str =
    "private-l2-pq-confidential-contract-formal-spec-commitment-v1";
pub const SYMBOLIC_TRACE_SCHEME: &str =
    "private-l2-pq-confidential-symbolic-execution-trace-root-v1";
pub const PROOF_CARRYING_CODE_SCHEME: &str =
    "private-l2-pq-confidential-proof-carrying-code-receipt-v1";
pub const COMMITTEE_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-formal-verifier-committee-attestation-v1";
pub const INVARIANT_MANIFEST_SCHEME: &str =
    "private-l2-pq-confidential-contract-invariant-manifest-root-v1";
pub const SEALED_COUNTEREXAMPLE_SCHEME: &str =
    "private-l2-pq-confidential-sealed-counterexample-report-v1";
pub const UPGRADE_GATE_SCHEME: &str = "private-l2-pq-confidential-contract-upgrade-gate-root-v1";
pub const PRIVACY_NULLIFIER_FENCE_SCHEME: &str =
    "private-l2-pq-confidential-formal-verifier-nullifier-fence-root-v1";
pub const LOW_FEE_PROOF_CACHE_COUPON_SCHEME: &str =
    "private-l2-low-fee-pq-formal-verifier-proof-cache-coupon-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str =
    "private-l2-pq-confidential-formal-verifier-slashing-evidence-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_240_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_COMMITTEE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MAX_VERIFIER_FEE_BPS: u64 = 18;
pub const DEFAULT_TARGET_COUPON_REBATE_BPS: u64 = 10;
pub const DEFAULT_BYTECODE_TTL_BLOCKS: u64 = 86_400;
pub const DEFAULT_SPEC_TTL_BLOCKS: u64 = 86_400;
pub const DEFAULT_TRACE_TTL_BLOCKS: u64 = 2_880;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 20_160;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_COUNTEREXAMPLE_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_UPGRADE_GATE_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_FENCE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 1_024;
pub const MAX_BYTECODE_COMMITMENTS: usize = 1_048_576;
pub const MAX_SPEC_COMMITMENTS: usize = 1_048_576;
pub const MAX_SYMBOLIC_TRACES: usize = 4_194_304;
pub const MAX_PCC_RECEIPTS: usize = 4_194_304;
pub const MAX_COMMITTEE_ATTESTATIONS: usize = 4_194_304;
pub const MAX_INVARIANT_MANIFESTS: usize = 1_048_576;
pub const MAX_COUNTEREXAMPLE_REPORTS: usize = 1_048_576;
pub const MAX_UPGRADE_GATES: usize = 1_048_576;
pub const MAX_PRIVACY_FENCES: usize = 4_194_304;
pub const MAX_PROOF_CACHE_COUPONS: usize = 2_097_152;
pub const MAX_SLASHING_EVIDENCE: usize = 1_048_576;
pub const MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractDomain {
    Wallet,
    Token,
    Dex,
    Lending,
    Derivatives,
    Governance,
    Oracle,
    Bridge,
    Treasury,
    General,
}

impl ContractDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Token => "token",
            Self::Dex => "dex",
            Self::Lending => "lending",
            Self::Derivatives => "derivatives",
            Self::Governance => "governance",
            Self::Oracle => "oracle",
            Self::Bridge => "bridge",
            Self::Treasury => "treasury",
            Self::General => "general",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BytecodeVm {
    ConfidentialWasm,
    NoirAcir,
    Cairo,
    Miden,
    RiscZero,
    Sp1,
    Halo2Dsl,
    CustomPqVm,
}

impl BytecodeVm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialWasm => "confidential_wasm",
            Self::NoirAcir => "noir_acir",
            Self::Cairo => "cairo",
            Self::Miden => "miden",
            Self::RiscZero => "risc_zero",
            Self::Sp1 => "sp1",
            Self::Halo2Dsl => "halo2_dsl",
            Self::CustomPqVm => "custom_pq_vm",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BytecodeStatus {
    Proposed,
    SpecBound,
    TraceBound,
    FormallyVerified,
    UpgradeCandidate,
    Deprecated,
    Revoked,
}

impl BytecodeStatus {
    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::SpecBound | Self::TraceBound | Self::FormallyVerified | Self::UpgradeCandidate
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecLanguage {
    K,
    Dafny,
    Coq,
    Lean,
    TlaPlus,
    Alloy,
    Why3,
    CircomConstraints,
    CustomDsl,
}

impl SpecLanguage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::K => "k",
            Self::Dafny => "dafny",
            Self::Coq => "coq",
            Self::Lean => "lean",
            Self::TlaPlus => "tla_plus",
            Self::Alloy => "alloy",
            Self::Why3 => "why3",
            Self::CircomConstraints => "circom_constraints",
            Self::CustomDsl => "custom_dsl",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecStatus {
    Draft,
    Active,
    Frozen,
    Superseded,
    Revoked,
}

impl SpecStatus {
    pub fn accepts_traces(self) -> bool {
        matches!(self, Self::Active | Self::Frozen)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceStatus {
    Submitted,
    SymbolicallyExecuted,
    InvariantMatched,
    ReceiptBound,
    Attested,
    CounterexampleFound,
    Rejected,
    Expired,
}

impl TraceStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::SymbolicallyExecuted
                | Self::InvariantMatched
                | Self::ReceiptBound
                | Self::Attested
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Submitted,
    BytecodeMatched,
    SpecMatched,
    InvariantChecked,
    CommitteeQueued,
    Attested,
    Settled,
    Rejected,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeRole {
    FormalMethodsLead,
    PqVerifier,
    PrivacyAuditor,
    RuntimeEngineer,
    UpgradeCouncil,
    FeeSponsor,
}

impl CommitteeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FormalMethodsLead => "formal_methods_lead",
            Self::PqVerifier => "pq_verifier",
            Self::PrivacyAuditor => "privacy_auditor",
            Self::RuntimeEngineer => "runtime_engineer",
            Self::UpgradeCouncil => "upgrade_council",
            Self::FeeSponsor => "fee_sponsor",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Valid,
    ValidWithWarnings,
    NeedsMoreInvariants,
    CounterexamplePresent,
    Invalid,
    Revoked,
}

impl AttestationVerdict {
    pub fn accepting(self) -> bool {
        matches!(self, Self::Valid | Self::ValidWithWarnings)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    WeakQuorum,
    StrongQuorum,
    Rejected,
    Superseded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantKind {
    BalanceConservation,
    Authorization,
    Confidentiality,
    NullifierUniqueness,
    StorageSafety,
    ReentrancyFreedom,
    FeeBound,
    UpgradeMonotonicity,
    OracleFreshness,
    CrossContractAtomicity,
}

impl InvariantKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BalanceConservation => "balance_conservation",
            Self::Authorization => "authorization",
            Self::Confidentiality => "confidentiality",
            Self::NullifierUniqueness => "nullifier_uniqueness",
            Self::StorageSafety => "storage_safety",
            Self::ReentrancyFreedom => "reentrancy_freedom",
            Self::FeeBound => "fee_bound",
            Self::UpgradeMonotonicity => "upgrade_monotonicity",
            Self::OracleFreshness => "oracle_freshness",
            Self::CrossContractAtomicity => "cross_contract_atomicity",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantStatus {
    Draft,
    Active,
    Mandatory,
    Shadow,
    Frozen,
    Superseded,
    Revoked,
}

impl InvariantStatus {
    pub fn enforced(self) -> bool {
        matches!(self, Self::Active | Self::Mandatory | Self::Frozen)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterexampleSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterexampleStatus {
    Sealed,
    CommitteeOpened,
    Confirmed,
    Disputed,
    Remediated,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeGateStatus {
    Proposed,
    WaitingForQuorum,
    Open,
    GracePeriod,
    Executed,
    Blocked,
    Expired,
    Revoked,
}

impl UpgradeGateStatus {
    pub fn allows_upgrade(self) -> bool {
        matches!(self, Self::Open | Self::GracePeriod)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Open,
    Spent,
    Tombstoned,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Issued,
    Reserved,
    Consumed,
    RebateQueued,
    Settled,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    InvalidProofCarryingCode,
    FalseAttestation,
    HiddenCounterexample,
    PrivacyFenceViolation,
    UpgradeGateBypass,
    CouponDoubleSpend,
    CommitteeEquivocation,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidProofCarryingCode => "invalid_proof_carrying_code",
            Self::FalseAttestation => "false_attestation",
            Self::HiddenCounterexample => "hidden_counterexample",
            Self::PrivacyFenceViolation => "privacy_fence_violation",
            Self::UpgradeGateBypass => "upgrade_gate_bypass",
            Self::CouponDoubleSpend => "coupon_double_spend",
            Self::CommitteeEquivocation => "committee_equivocation",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Submitted,
    Accepted,
    QuorumConfirmed,
    Slashed,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    BytecodeCommitted,
    SpecCommitted,
    SymbolicTraceSubmitted,
    ProofCarryingCodeReceiptIssued,
    CommitteeAttested,
    InvariantManifestPublished,
    CounterexampleSealed,
    UpgradeGateOpened,
    PrivacyFenceRegistered,
    ProofCacheCouponIssued,
    SlashingEvidenceSubmitted,
    RuntimeRootPublished,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BytecodeCommitted => "bytecode_committed",
            Self::SpecCommitted => "spec_committed",
            Self::SymbolicTraceSubmitted => "symbolic_trace_submitted",
            Self::ProofCarryingCodeReceiptIssued => "proof_carrying_code_receipt_issued",
            Self::CommitteeAttested => "committee_attested",
            Self::InvariantManifestPublished => "invariant_manifest_published",
            Self::CounterexampleSealed => "counterexample_sealed",
            Self::UpgradeGateOpened => "upgrade_gate_opened",
            Self::PrivacyFenceRegistered => "privacy_fence_registered",
            Self::ProofCacheCouponIssued => "proof_cache_coupon_issued",
            Self::SlashingEvidenceSubmitted => "slashing_evidence_submitted",
            Self::RuntimeRootPublished => "runtime_root_published",
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
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub bytecode_commitment_scheme: String,
    pub spec_commitment_scheme: String,
    pub symbolic_trace_scheme: String,
    pub proof_carrying_code_scheme: String,
    pub committee_attestation_scheme: String,
    pub invariant_manifest_scheme: String,
    pub sealed_counterexample_scheme: String,
    pub upgrade_gate_scheme: String,
    pub privacy_nullifier_fence_scheme: String,
    pub low_fee_proof_cache_coupon_scheme: String,
    pub slashing_evidence_scheme: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub committee_quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub max_verifier_fee_bps: u64,
    pub target_coupon_rebate_bps: u64,
    pub bytecode_ttl_blocks: u64,
    pub spec_ttl_blocks: u64,
    pub trace_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub counterexample_ttl_blocks: u64,
    pub upgrade_gate_ttl_blocks: u64,
    pub fence_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub max_batch_items: usize,
    pub max_bytecode_commitments: usize,
    pub max_spec_commitments: usize,
    pub max_symbolic_traces: usize,
    pub max_pcc_receipts: usize,
    pub max_committee_attestations: usize,
    pub max_invariant_manifests: usize,
    pub max_counterexample_reports: usize,
    pub max_upgrade_gates: usize,
    pub max_privacy_fences: usize,
    pub max_proof_cache_coupons: usize,
    pub max_slashing_evidence: usize,
    pub max_events: usize,
    pub devnet_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            bytecode_commitment_scheme: BYTECODE_COMMITMENT_SCHEME.to_string(),
            spec_commitment_scheme: SPEC_COMMITMENT_SCHEME.to_string(),
            symbolic_trace_scheme: SYMBOLIC_TRACE_SCHEME.to_string(),
            proof_carrying_code_scheme: PROOF_CARRYING_CODE_SCHEME.to_string(),
            committee_attestation_scheme: COMMITTEE_ATTESTATION_SCHEME.to_string(),
            invariant_manifest_scheme: INVARIANT_MANIFEST_SCHEME.to_string(),
            sealed_counterexample_scheme: SEALED_COUNTEREXAMPLE_SCHEME.to_string(),
            upgrade_gate_scheme: UPGRADE_GATE_SCHEME.to_string(),
            privacy_nullifier_fence_scheme: PRIVACY_NULLIFIER_FENCE_SCHEME.to_string(),
            low_fee_proof_cache_coupon_scheme: LOW_FEE_PROOF_CACHE_COUPON_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            committee_quorum_bps: DEFAULT_COMMITTEE_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            max_verifier_fee_bps: DEFAULT_MAX_VERIFIER_FEE_BPS,
            target_coupon_rebate_bps: DEFAULT_TARGET_COUPON_REBATE_BPS,
            bytecode_ttl_blocks: DEFAULT_BYTECODE_TTL_BLOCKS,
            spec_ttl_blocks: DEFAULT_SPEC_TTL_BLOCKS,
            trace_ttl_blocks: DEFAULT_TRACE_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            counterexample_ttl_blocks: DEFAULT_COUNTEREXAMPLE_TTL_BLOCKS,
            upgrade_gate_ttl_blocks: DEFAULT_UPGRADE_GATE_TTL_BLOCKS,
            fence_ttl_blocks: DEFAULT_FENCE_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            max_bytecode_commitments: MAX_BYTECODE_COMMITMENTS,
            max_spec_commitments: MAX_SPEC_COMMITMENTS,
            max_symbolic_traces: MAX_SYMBOLIC_TRACES,
            max_pcc_receipts: MAX_PCC_RECEIPTS,
            max_committee_attestations: MAX_COMMITTEE_ATTESTATIONS,
            max_invariant_manifests: MAX_INVARIANT_MANIFESTS,
            max_counterexample_reports: MAX_COUNTEREXAMPLE_REPORTS,
            max_upgrade_gates: MAX_UPGRADE_GATES,
            max_privacy_fences: MAX_PRIVACY_FENCES,
            max_proof_cache_coupons: MAX_PROOF_CACHE_COUPONS,
            max_slashing_evidence: MAX_SLASHING_EVIDENCE,
            max_events: MAX_EVENTS,
            devnet_height: DEVNET_HEIGHT,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("monero_network", &self.monero_network)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("pq_auth_suite", &self.pq_auth_suite)?;
        require_bps("committee_quorum_bps", self.committee_quorum_bps)?;
        require_bps("strong_quorum_bps", self.strong_quorum_bps)?;
        require_bps("max_verifier_fee_bps", self.max_verifier_fee_bps)?;
        require_bps("target_coupon_rebate_bps", self.target_coupon_rebate_bps)?;
        if self.strong_quorum_bps < self.committee_quorum_bps {
            return Err("strong_quorum_bps cannot be below committee_quorum_bps".to_string());
        }
        if self.target_coupon_rebate_bps > self.max_verifier_fee_bps {
            return Err("target_coupon_rebate_bps cannot exceed max_verifier_fee_bps".to_string());
        }
        require_at_least(
            "batch_privacy_set_size",
            self.batch_privacy_set_size,
            self.min_privacy_set_size,
        )?;
        require_at_least_u16(
            "min_pq_security_bits",
            self.min_pq_security_bits,
            DEFAULT_MIN_PQ_SECURITY_BITS,
        )?;
        require_positive_u64("bytecode_ttl_blocks", self.bytecode_ttl_blocks)?;
        require_positive_u64("spec_ttl_blocks", self.spec_ttl_blocks)?;
        require_positive_u64("trace_ttl_blocks", self.trace_ttl_blocks)?;
        require_positive_u64("receipt_ttl_blocks", self.receipt_ttl_blocks)?;
        require_positive_u64("attestation_ttl_blocks", self.attestation_ttl_blocks)?;
        require_positive_u64("counterexample_ttl_blocks", self.counterexample_ttl_blocks)?;
        require_positive_u64("upgrade_gate_ttl_blocks", self.upgrade_gate_ttl_blocks)?;
        require_positive_u64("fence_ttl_blocks", self.fence_ttl_blocks)?;
        require_positive_u64("coupon_ttl_blocks", self.coupon_ttl_blocks)?;
        require_positive_usize("max_batch_items", self.max_batch_items)?;
        require_positive_usize("max_bytecode_commitments", self.max_bytecode_commitments)?;
        require_positive_usize("max_spec_commitments", self.max_spec_commitments)?;
        require_positive_usize("max_symbolic_traces", self.max_symbolic_traces)?;
        require_positive_usize("max_pcc_receipts", self.max_pcc_receipts)?;
        require_positive_usize(
            "max_committee_attestations",
            self.max_committee_attestations,
        )?;
        require_positive_usize("max_invariant_manifests", self.max_invariant_manifests)?;
        require_positive_usize(
            "max_counterexample_reports",
            self.max_counterexample_reports,
        )?;
        require_positive_usize("max_upgrade_gates", self.max_upgrade_gates)?;
        require_positive_usize("max_privacy_fences", self.max_privacy_fences)?;
        require_positive_usize("max_proof_cache_coupons", self.max_proof_cache_coupons)?;
        require_positive_usize("max_slashing_evidence", self.max_slashing_evidence)?;
        require_positive_usize("max_events", self.max_events)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub bytecode_commitments: u64,
    pub spec_commitments: u64,
    pub symbolic_traces: u64,
    pub pcc_receipts: u64,
    pub committee_attestations: u64,
    pub invariant_manifests: u64,
    pub counterexample_reports: u64,
    pub upgrade_gates: u64,
    pub privacy_fences: u64,
    pub proof_cache_coupons: u64,
    pub slashing_evidence: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub bytecode_commitment_root: String,
    pub spec_commitment_root: String,
    pub symbolic_trace_root: String,
    pub pcc_receipt_root: String,
    pub committee_attestation_root: String,
    pub invariant_manifest_root: String,
    pub counterexample_report_root: String,
    pub upgrade_gate_root: String,
    pub privacy_fence_root: String,
    pub proof_cache_coupon_root: String,
    pub slashing_evidence_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            bytecode_commitment_root: empty_root("formal_verifier_bytecode_commitments"),
            spec_commitment_root: empty_root("formal_verifier_spec_commitments"),
            symbolic_trace_root: empty_root("formal_verifier_symbolic_traces"),
            pcc_receipt_root: empty_root("formal_verifier_pcc_receipts"),
            committee_attestation_root: empty_root("formal_verifier_committee_attestations"),
            invariant_manifest_root: empty_root("formal_verifier_invariant_manifests"),
            counterexample_report_root: empty_root("formal_verifier_counterexample_reports"),
            upgrade_gate_root: empty_root("formal_verifier_upgrade_gates"),
            privacy_fence_root: empty_root("formal_verifier_privacy_fences"),
            proof_cache_coupon_root: empty_root("formal_verifier_proof_cache_coupons"),
            slashing_evidence_root: empty_root("formal_verifier_slashing_evidence"),
            event_root: empty_root("formal_verifier_events"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BytecodeCommitment {
    pub bytecode_id: String,
    pub contract_id: String,
    pub domain: ContractDomain,
    pub vm: BytecodeVm,
    pub bytecode_root: String,
    pub abi_root: String,
    pub storage_layout_root: String,
    pub deployer_commitment: String,
    pub compiler_commitment: String,
    pub pq_security_bits: u16,
    pub status: BytecodeStatus,
    pub linked_spec_ids: BTreeSet<String>,
    pub linked_invariant_manifest_ids: BTreeSet<String>,
    pub created_height: u64,
    pub expires_height: u64,
    pub sequence: u64,
    pub metadata: BTreeMap<String, String>,
}

impl BytecodeCommitment {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn record_root(&self) -> String {
        record_root(
            "formal_verifier_bytecode_commitment_record",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpecCommitment {
    pub spec_id: String,
    pub contract_id: String,
    pub bytecode_id: String,
    pub language: SpecLanguage,
    pub spec_root: String,
    pub precondition_root: String,
    pub postcondition_root: String,
    pub transition_relation_root: String,
    pub privacy_claim_root: String,
    pub author_commitment: String,
    pub status: SpecStatus,
    pub created_height: u64,
    pub expires_height: u64,
    pub sequence: u64,
    pub metadata: BTreeMap<String, String>,
}

impl SpecCommitment {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn record_root(&self) -> String {
        record_root(
            "formal_verifier_spec_commitment_record",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SymbolicExecutionTrace {
    pub trace_id: String,
    pub bytecode_id: String,
    pub spec_id: String,
    pub entrypoint: String,
    pub symbolic_input_root: String,
    pub path_condition_root: String,
    pub storage_read_root: String,
    pub storage_write_root: String,
    pub event_root: String,
    pub nullifier_root: String,
    pub call_graph_root: String,
    pub invariant_result_root: String,
    pub prover_commitment: String,
    pub step_count: u64,
    pub max_stack_depth: u64,
    pub privacy_set_size: u64,
    pub status: TraceStatus,
    pub created_height: u64,
    pub expires_height: u64,
    pub sequence: u64,
}

impl SymbolicExecutionTrace {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn record_root(&self) -> String {
        record_root(
            "formal_verifier_symbolic_trace_record",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofCarryingCodeReceipt {
    pub receipt_id: String,
    pub bytecode_id: String,
    pub spec_id: String,
    pub trace_id: String,
    pub proof_system: String,
    pub verifier_key_root: String,
    pub proof_root: String,
    pub assumptions_root: String,
    pub obligations_root: String,
    pub discharged_invariants_root: String,
    pub recursion_parent_receipt: Option<String>,
    pub verifier_committee_root: String,
    pub pcc_weight: u64,
    pub fee_paid: u64,
    pub status: ReceiptStatus,
    pub created_height: u64,
    pub expires_height: u64,
    pub sequence: u64,
}

impl ProofCarryingCodeReceipt {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn record_root(&self) -> String {
        record_root("formal_verifier_pcc_receipt_record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifierCommitteeAttestation {
    pub attestation_id: String,
    pub receipt_id: String,
    pub trace_id: String,
    pub committee_id: String,
    pub role: CommitteeRole,
    pub verdict: AttestationVerdict,
    pub status: AttestationStatus,
    pub committee_member_root: String,
    pub signature_root: String,
    pub dissent_root: String,
    pub quorum_bps: u64,
    pub privacy_set_size: u64,
    pub attested_height: u64,
    pub expires_height: u64,
    pub sequence: u64,
}

impl VerifierCommitteeAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn record_root(&self) -> String {
        record_root(
            "formal_verifier_committee_attestation_record",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvariantManifest {
    pub manifest_id: String,
    pub contract_id: String,
    pub bytecode_id: String,
    pub spec_id: String,
    pub kind: InvariantKind,
    pub status: InvariantStatus,
    pub manifest_root: String,
    pub invariant_root: String,
    pub witness_schema_root: String,
    pub prover_policy_root: String,
    pub severity_floor: CounterexampleSeverity,
    pub author_commitment: String,
    pub mandatory: bool,
    pub created_height: u64,
    pub expires_height: u64,
    pub sequence: u64,
}

impl InvariantManifest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn record_root(&self) -> String {
        record_root(
            "formal_verifier_invariant_manifest_record",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedCounterexampleReport {
    pub report_id: String,
    pub trace_id: String,
    pub receipt_id: Option<String>,
    pub invariant_manifest_id: String,
    pub sealed_payload_root: String,
    pub encrypted_witness_root: String,
    pub replay_hint_root: String,
    pub reporter_commitment: String,
    pub severity: CounterexampleSeverity,
    pub status: CounterexampleStatus,
    pub bond_amount: u64,
    pub privacy_set_size: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub sequence: u64,
}

impl SealedCounterexampleReport {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn record_root(&self) -> String {
        record_root(
            "formal_verifier_counterexample_report_record",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpgradeGate {
    pub gate_id: String,
    pub contract_id: String,
    pub current_bytecode_id: String,
    pub candidate_bytecode_id: String,
    pub required_spec_id: String,
    pub required_receipt_id: String,
    pub committee_attestation_root: String,
    pub counterexample_report_root: String,
    pub privacy_fence_root: String,
    pub status: UpgradeGateStatus,
    pub opens_height: u64,
    pub expires_height: u64,
    pub sequence: u64,
}

impl UpgradeGate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn record_root(&self) -> String {
        record_root("formal_verifier_upgrade_gate_record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyNullifierFence {
    pub fence_id: String,
    pub contract_id: String,
    pub bytecode_id: String,
    pub spec_id: String,
    pub nullifier_root: String,
    pub anonymity_set_root: String,
    pub view_tag_root: String,
    pub privacy_epoch: u64,
    pub min_privacy_set_size: u64,
    pub status: FenceStatus,
    pub created_height: u64,
    pub expires_height: u64,
    pub sequence: u64,
}

impl PrivacyNullifierFence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn record_root(&self) -> String {
        record_root(
            "formal_verifier_privacy_fence_record",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeProofCacheCoupon {
    pub coupon_id: String,
    pub receipt_id: String,
    pub trace_id: String,
    pub sponsor_id: String,
    pub beneficiary_commitment: String,
    pub cache_key_root: String,
    pub coupon_value: u64,
    pub verifier_fee_bps: u64,
    pub rebate_bps: u64,
    pub status: CouponStatus,
    pub issued_height: u64,
    pub expires_height: u64,
    pub sequence: u64,
}

impl LowFeeProofCacheCoupon {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn record_root(&self) -> String {
        record_root(
            "formal_verifier_proof_cache_coupon_record",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub subject_id: String,
    pub offender_commitment: String,
    pub evidence_root: String,
    pub transcript_root: String,
    pub committee_attestation_root: String,
    pub proposed_penalty: u64,
    pub status: EvidenceStatus,
    pub submitted_height: u64,
    pub sequence: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn record_root(&self) -> String {
        record_root(
            "formal_verifier_slashing_evidence_record",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: EventKind,
    pub subject_id: String,
    pub payload_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub bytecode_commitments: BTreeMap<String, BytecodeCommitment>,
    pub spec_commitments: BTreeMap<String, SpecCommitment>,
    pub symbolic_traces: BTreeMap<String, SymbolicExecutionTrace>,
    pub pcc_receipts: BTreeMap<String, ProofCarryingCodeReceipt>,
    pub committee_attestations: BTreeMap<String, VerifierCommitteeAttestation>,
    pub invariant_manifests: BTreeMap<String, InvariantManifest>,
    pub counterexample_reports: BTreeMap<String, SealedCounterexampleReport>,
    pub upgrade_gates: BTreeMap<String, UpgradeGate>,
    pub privacy_fences: BTreeMap<String, PrivacyNullifierFence>,
    pub proof_cache_coupons: BTreeMap<String, LowFeeProofCacheCoupon>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            bytecode_commitments: BTreeMap::new(),
            spec_commitments: BTreeMap::new(),
            symbolic_traces: BTreeMap::new(),
            pcc_receipts: BTreeMap::new(),
            committee_attestations: BTreeMap::new(),
            invariant_manifests: BTreeMap::new(),
            counterexample_reports: BTreeMap::new(),
            upgrade_gates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            proof_cache_coupons: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            events: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet()).unwrap_or_else(|error| State {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::empty(),
            bytecode_commitments: BTreeMap::new(),
            spec_commitments: BTreeMap::new(),
            symbolic_traces: BTreeMap::new(),
            pcc_receipts: BTreeMap::new(),
            committee_attestations: BTreeMap::new(),
            invariant_manifests: BTreeMap::new(),
            counterexample_reports: BTreeMap::new(),
            upgrade_gates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            proof_cache_coupons: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            events: BTreeMap::from([(
                domain_hash(
                    "formal_verifier_devnet_config_error_event",
                    &[HashPart::Str(CHAIN_ID), HashPart::Str(&error)],
                    32,
                ),
                RuntimeEvent {
                    event_id: domain_hash(
                        "formal_verifier_devnet_config_error_event",
                        &[HashPart::Str(CHAIN_ID), HashPart::Str(&error)],
                        32,
                    ),
                    kind: EventKind::RuntimeRootPublished,
                    subject_id: "devnet-config".to_string(),
                    payload_root: domain_hash(
                        "formal_verifier_devnet_config_error_payload",
                        &[HashPart::Str(CHAIN_ID), HashPart::Str(&error)],
                        32,
                    ),
                    height: DEVNET_HEIGHT,
                    sequence: 0,
                },
            )]),
        });

        state.seed_devnet_records();
        state.recompute_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        }))
    }

    pub fn recompute_roots(&mut self) {
        self.roots = Roots {
            bytecode_commitment_root: map_root(
                "formal_verifier_bytecode_commitments",
                &self.bytecode_commitments,
                BytecodeCommitment::public_record,
            ),
            spec_commitment_root: map_root(
                "formal_verifier_spec_commitments",
                &self.spec_commitments,
                SpecCommitment::public_record,
            ),
            symbolic_trace_root: map_root(
                "formal_verifier_symbolic_traces",
                &self.symbolic_traces,
                SymbolicExecutionTrace::public_record,
            ),
            pcc_receipt_root: map_root(
                "formal_verifier_pcc_receipts",
                &self.pcc_receipts,
                ProofCarryingCodeReceipt::public_record,
            ),
            committee_attestation_root: map_root(
                "formal_verifier_committee_attestations",
                &self.committee_attestations,
                VerifierCommitteeAttestation::public_record,
            ),
            invariant_manifest_root: map_root(
                "formal_verifier_invariant_manifests",
                &self.invariant_manifests,
                InvariantManifest::public_record,
            ),
            counterexample_report_root: map_root(
                "formal_verifier_counterexample_reports",
                &self.counterexample_reports,
                SealedCounterexampleReport::public_record,
            ),
            upgrade_gate_root: map_root(
                "formal_verifier_upgrade_gates",
                &self.upgrade_gates,
                UpgradeGate::public_record,
            ),
            privacy_fence_root: map_root(
                "formal_verifier_privacy_fences",
                &self.privacy_fences,
                PrivacyNullifierFence::public_record,
            ),
            proof_cache_coupon_root: map_root(
                "formal_verifier_proof_cache_coupons",
                &self.proof_cache_coupons,
                LowFeeProofCacheCoupon::public_record,
            ),
            slashing_evidence_root: map_root(
                "formal_verifier_slashing_evidence",
                &self.slashing_evidence,
                SlashingEvidence::public_record,
            ),
            event_root: map_root(
                "formal_verifier_events",
                &self.events,
                RuntimeEvent::public_record,
            ),
        };
    }

    pub fn commit_bytecode(
        &mut self,
        contract_id: &str,
        domain: ContractDomain,
        vm: BytecodeVm,
        bytecode_root_value: &str,
        abi_root: &str,
        storage_layout_root: &str,
        deployer_commitment: &str,
        compiler_commitment: &str,
        pq_security_bits: u16,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure_capacity(
            "bytecode_commitments",
            self.bytecode_commitments.len(),
            self.config.max_bytecode_commitments,
        )?;
        require_id("contract_id", contract_id)?;
        require_root("bytecode_root", bytecode_root_value)?;
        require_root("abi_root", abi_root)?;
        require_root("storage_layout_root", storage_layout_root)?;
        require_root("deployer_commitment", deployer_commitment)?;
        require_root("compiler_commitment", compiler_commitment)?;
        require_at_least_u16(
            "pq_security_bits",
            pq_security_bits,
            self.config.min_pq_security_bits,
        )?;
        let sequence = self.counters.bytecode_commitments + 1;
        let bytecode_id_value = bytecode_id(
            contract_id,
            domain,
            vm,
            bytecode_root_value,
            height,
            sequence,
        );
        let record = BytecodeCommitment {
            bytecode_id: bytecode_id_value.clone(),
            contract_id: contract_id.to_string(),
            domain,
            vm,
            bytecode_root: bytecode_root_value.to_string(),
            abi_root: abi_root.to_string(),
            storage_layout_root: storage_layout_root.to_string(),
            deployer_commitment: deployer_commitment.to_string(),
            compiler_commitment: compiler_commitment.to_string(),
            pq_security_bits,
            status: BytecodeStatus::Proposed,
            linked_spec_ids: BTreeSet::new(),
            linked_invariant_manifest_ids: BTreeSet::new(),
            created_height: height,
            expires_height: height.saturating_add(self.config.bytecode_ttl_blocks),
            sequence,
            metadata: BTreeMap::new(),
        };
        self.bytecode_commitments
            .insert(bytecode_id_value.clone(), record.clone());
        self.counters.bytecode_commitments = sequence;
        self.push_event(
            EventKind::BytecodeCommitted,
            &bytecode_id_value,
            &record.record_root(),
            height,
        )?;
        self.recompute_roots();
        Ok(bytecode_id_value)
    }

    pub fn commit_spec(
        &mut self,
        bytecode_id_value: &str,
        language: SpecLanguage,
        spec_root_value: &str,
        precondition_root: &str,
        postcondition_root: &str,
        transition_relation_root: &str,
        privacy_claim_root: &str,
        author_commitment: &str,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure_capacity(
            "spec_commitments",
            self.spec_commitments.len(),
            self.config.max_spec_commitments,
        )?;
        require_root("spec_root", spec_root_value)?;
        require_root("precondition_root", precondition_root)?;
        require_root("postcondition_root", postcondition_root)?;
        require_root("transition_relation_root", transition_relation_root)?;
        require_root("privacy_claim_root", privacy_claim_root)?;
        require_root("author_commitment", author_commitment)?;
        let bytecode = self
            .bytecode_commitments
            .get(bytecode_id_value)
            .ok_or_else(|| format!("unknown bytecode_id {bytecode_id_value}"))?;
        if !bytecode.status.usable() && bytecode.status != BytecodeStatus::Proposed {
            return Err("bytecode status cannot accept a spec commitment".to_string());
        }
        let contract_id = bytecode.contract_id.clone();
        let sequence = self.counters.spec_commitments + 1;
        let spec_id_value = spec_id(
            &contract_id,
            bytecode_id_value,
            language,
            spec_root_value,
            height,
            sequence,
        );
        let record = SpecCommitment {
            spec_id: spec_id_value.clone(),
            contract_id,
            bytecode_id: bytecode_id_value.to_string(),
            language,
            spec_root: spec_root_value.to_string(),
            precondition_root: precondition_root.to_string(),
            postcondition_root: postcondition_root.to_string(),
            transition_relation_root: transition_relation_root.to_string(),
            privacy_claim_root: privacy_claim_root.to_string(),
            author_commitment: author_commitment.to_string(),
            status: SpecStatus::Active,
            created_height: height,
            expires_height: height.saturating_add(self.config.spec_ttl_blocks),
            sequence,
            metadata: BTreeMap::new(),
        };
        self.spec_commitments
            .insert(spec_id_value.clone(), record.clone());
        if let Some(bytecode_record) = self.bytecode_commitments.get_mut(bytecode_id_value) {
            bytecode_record
                .linked_spec_ids
                .insert(spec_id_value.clone());
            bytecode_record.status = BytecodeStatus::SpecBound;
        }
        self.counters.spec_commitments = sequence;
        self.push_event(
            EventKind::SpecCommitted,
            &spec_id_value,
            &record.record_root(),
            height,
        )?;
        self.recompute_roots();
        Ok(spec_id_value)
    }

    pub fn publish_invariant_manifest(
        &mut self,
        bytecode_id_value: &str,
        spec_id_value: &str,
        kind: InvariantKind,
        manifest_root_value: &str,
        invariant_root: &str,
        witness_schema_root: &str,
        prover_policy_root: &str,
        severity_floor: CounterexampleSeverity,
        author_commitment: &str,
        mandatory: bool,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure_capacity(
            "invariant_manifests",
            self.invariant_manifests.len(),
            self.config.max_invariant_manifests,
        )?;
        require_root("manifest_root", manifest_root_value)?;
        require_root("invariant_root", invariant_root)?;
        require_root("witness_schema_root", witness_schema_root)?;
        require_root("prover_policy_root", prover_policy_root)?;
        require_root("author_commitment", author_commitment)?;
        let bytecode = self
            .bytecode_commitments
            .get(bytecode_id_value)
            .ok_or_else(|| format!("unknown bytecode_id {bytecode_id_value}"))?;
        let spec = self
            .spec_commitments
            .get(spec_id_value)
            .ok_or_else(|| format!("unknown spec_id {spec_id_value}"))?;
        if spec.bytecode_id != bytecode_id_value {
            return Err("spec_id is not bound to bytecode_id".to_string());
        }
        if !spec.status.accepts_traces() {
            return Err("spec status cannot accept invariant manifests".to_string());
        }
        let sequence = self.counters.invariant_manifests + 1;
        let manifest_id_value = invariant_manifest_id(
            &bytecode.contract_id,
            bytecode_id_value,
            spec_id_value,
            kind,
            manifest_root_value,
            height,
            sequence,
        );
        let status = if mandatory {
            InvariantStatus::Mandatory
        } else {
            InvariantStatus::Active
        };
        let record = InvariantManifest {
            manifest_id: manifest_id_value.clone(),
            contract_id: bytecode.contract_id.clone(),
            bytecode_id: bytecode_id_value.to_string(),
            spec_id: spec_id_value.to_string(),
            kind,
            status,
            manifest_root: manifest_root_value.to_string(),
            invariant_root: invariant_root.to_string(),
            witness_schema_root: witness_schema_root.to_string(),
            prover_policy_root: prover_policy_root.to_string(),
            severity_floor,
            author_commitment: author_commitment.to_string(),
            mandatory,
            created_height: height,
            expires_height: height.saturating_add(self.config.spec_ttl_blocks),
            sequence,
        };
        self.invariant_manifests
            .insert(manifest_id_value.clone(), record.clone());
        if let Some(bytecode_record) = self.bytecode_commitments.get_mut(bytecode_id_value) {
            bytecode_record
                .linked_invariant_manifest_ids
                .insert(manifest_id_value.clone());
        }
        self.counters.invariant_manifests = sequence;
        self.push_event(
            EventKind::InvariantManifestPublished,
            &manifest_id_value,
            &record.record_root(),
            height,
        )?;
        self.recompute_roots();
        Ok(manifest_id_value)
    }

    pub fn submit_symbolic_trace(
        &mut self,
        bytecode_id_value: &str,
        spec_id_value: &str,
        entrypoint: &str,
        symbolic_input_root: &str,
        path_condition_root: &str,
        storage_read_root: &str,
        storage_write_root: &str,
        event_root_value: &str,
        nullifier_root: &str,
        call_graph_root: &str,
        invariant_result_root: &str,
        prover_commitment: &str,
        step_count: u64,
        max_stack_depth: u64,
        privacy_set_size: u64,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure_capacity(
            "symbolic_traces",
            self.symbolic_traces.len(),
            self.config.max_symbolic_traces,
        )?;
        require_id("entrypoint", entrypoint)?;
        require_root("symbolic_input_root", symbolic_input_root)?;
        require_root("path_condition_root", path_condition_root)?;
        require_root("storage_read_root", storage_read_root)?;
        require_root("storage_write_root", storage_write_root)?;
        require_root("event_root", event_root_value)?;
        require_root("nullifier_root", nullifier_root)?;
        require_root("call_graph_root", call_graph_root)?;
        require_root("invariant_result_root", invariant_result_root)?;
        require_root("prover_commitment", prover_commitment)?;
        require_positive_u64("step_count", step_count)?;
        require_positive_u64("max_stack_depth", max_stack_depth)?;
        require_at_least(
            "privacy_set_size",
            privacy_set_size,
            self.config.min_privacy_set_size,
        )?;
        let bytecode = self
            .bytecode_commitments
            .get(bytecode_id_value)
            .ok_or_else(|| format!("unknown bytecode_id {bytecode_id_value}"))?;
        let spec = self
            .spec_commitments
            .get(spec_id_value)
            .ok_or_else(|| format!("unknown spec_id {spec_id_value}"))?;
        if spec.bytecode_id != bytecode_id_value {
            return Err("spec_id is not bound to bytecode_id".to_string());
        }
        if !spec.status.accepts_traces() {
            return Err("spec status cannot accept symbolic traces".to_string());
        }
        let sequence = self.counters.symbolic_traces + 1;
        let trace_id_value = symbolic_trace_id(
            bytecode_id_value,
            spec_id_value,
            entrypoint,
            path_condition_root,
            height,
            sequence,
        );
        let record = SymbolicExecutionTrace {
            trace_id: trace_id_value.clone(),
            bytecode_id: bytecode_id_value.to_string(),
            spec_id: spec_id_value.to_string(),
            entrypoint: entrypoint.to_string(),
            symbolic_input_root: symbolic_input_root.to_string(),
            path_condition_root: path_condition_root.to_string(),
            storage_read_root: storage_read_root.to_string(),
            storage_write_root: storage_write_root.to_string(),
            event_root: event_root_value.to_string(),
            nullifier_root: nullifier_root.to_string(),
            call_graph_root: call_graph_root.to_string(),
            invariant_result_root: invariant_result_root.to_string(),
            prover_commitment: prover_commitment.to_string(),
            step_count,
            max_stack_depth,
            privacy_set_size,
            status: TraceStatus::SymbolicallyExecuted,
            created_height: height,
            expires_height: height.saturating_add(self.config.trace_ttl_blocks),
            sequence,
        };
        self.symbolic_traces
            .insert(trace_id_value.clone(), record.clone());
        if let Some(bytecode_record) = self.bytecode_commitments.get_mut(bytecode_id_value) {
            bytecode_record.status = BytecodeStatus::TraceBound;
        }
        self.counters.symbolic_traces = sequence;
        self.push_event(
            EventKind::SymbolicTraceSubmitted,
            &trace_id_value,
            &record.record_root(),
            height,
        )?;
        self.recompute_roots();
        Ok(trace_id_value)
    }

    pub fn issue_pcc_receipt(
        &mut self,
        bytecode_id_value: &str,
        spec_id_value: &str,
        trace_id_value: &str,
        proof_system: &str,
        verifier_key_root: &str,
        proof_root_value: &str,
        assumptions_root: &str,
        obligations_root: &str,
        discharged_invariants_root: &str,
        recursion_parent_receipt: Option<String>,
        verifier_committee_root: &str,
        pcc_weight: u64,
        fee_paid: u64,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure_capacity(
            "pcc_receipts",
            self.pcc_receipts.len(),
            self.config.max_pcc_receipts,
        )?;
        require_id("proof_system", proof_system)?;
        require_root("verifier_key_root", verifier_key_root)?;
        require_root("proof_root", proof_root_value)?;
        require_root("assumptions_root", assumptions_root)?;
        require_root("obligations_root", obligations_root)?;
        require_root("discharged_invariants_root", discharged_invariants_root)?;
        require_root("verifier_committee_root", verifier_committee_root)?;
        require_positive_u64("pcc_weight", pcc_weight)?;
        let trace = self
            .symbolic_traces
            .get(trace_id_value)
            .ok_or_else(|| format!("unknown trace_id {trace_id_value}"))?;
        if trace.bytecode_id != bytecode_id_value || trace.spec_id != spec_id_value {
            return Err("trace is not bound to requested bytecode/spec pair".to_string());
        }
        if !trace.status.live() {
            return Err("trace status cannot receive a pcc receipt".to_string());
        }
        if let Some(parent) = &recursion_parent_receipt {
            require_id("recursion_parent_receipt", parent)?;
            if !self.pcc_receipts.contains_key(parent) {
                return Err("unknown recursion_parent_receipt".to_string());
            }
        }
        let sequence = self.counters.pcc_receipts + 1;
        let receipt_id_value = pcc_receipt_id(
            bytecode_id_value,
            spec_id_value,
            trace_id_value,
            proof_root_value,
            height,
            sequence,
        );
        let record = ProofCarryingCodeReceipt {
            receipt_id: receipt_id_value.clone(),
            bytecode_id: bytecode_id_value.to_string(),
            spec_id: spec_id_value.to_string(),
            trace_id: trace_id_value.to_string(),
            proof_system: proof_system.to_string(),
            verifier_key_root: verifier_key_root.to_string(),
            proof_root: proof_root_value.to_string(),
            assumptions_root: assumptions_root.to_string(),
            obligations_root: obligations_root.to_string(),
            discharged_invariants_root: discharged_invariants_root.to_string(),
            recursion_parent_receipt,
            verifier_committee_root: verifier_committee_root.to_string(),
            pcc_weight,
            fee_paid,
            status: ReceiptStatus::InvariantChecked,
            created_height: height,
            expires_height: height.saturating_add(self.config.receipt_ttl_blocks),
            sequence,
        };
        self.pcc_receipts
            .insert(receipt_id_value.clone(), record.clone());
        if let Some(trace_record) = self.symbolic_traces.get_mut(trace_id_value) {
            trace_record.status = TraceStatus::ReceiptBound;
        }
        self.counters.pcc_receipts = sequence;
        self.push_event(
            EventKind::ProofCarryingCodeReceiptIssued,
            &receipt_id_value,
            &record.record_root(),
            height,
        )?;
        self.recompute_roots();
        Ok(receipt_id_value)
    }

    pub fn attest_receipt(
        &mut self,
        receipt_id_value: &str,
        committee_id: &str,
        role: CommitteeRole,
        verdict: AttestationVerdict,
        committee_member_root: &str,
        signature_root: &str,
        dissent_root: &str,
        quorum_bps: u64,
        privacy_set_size: u64,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure_capacity(
            "committee_attestations",
            self.committee_attestations.len(),
            self.config.max_committee_attestations,
        )?;
        require_id("committee_id", committee_id)?;
        require_root("committee_member_root", committee_member_root)?;
        require_root("signature_root", signature_root)?;
        require_root("dissent_root", dissent_root)?;
        require_bps("quorum_bps", quorum_bps)?;
        require_at_least(
            "privacy_set_size",
            privacy_set_size,
            self.config.min_privacy_set_size,
        )?;
        let receipt = self
            .pcc_receipts
            .get(receipt_id_value)
            .ok_or_else(|| format!("unknown receipt_id {receipt_id_value}"))?;
        let trace_id_value = receipt.trace_id.clone();
        let status = if quorum_bps >= self.config.strong_quorum_bps {
            AttestationStatus::StrongQuorum
        } else if quorum_bps >= self.config.committee_quorum_bps {
            AttestationStatus::WeakQuorum
        } else if verdict.accepting() {
            AttestationStatus::Accepted
        } else {
            AttestationStatus::Rejected
        };
        let sequence = self.counters.committee_attestations + 1;
        let attestation_id_value = committee_attestation_id(
            receipt_id_value,
            committee_id,
            role,
            committee_member_root,
            height,
            sequence,
        );
        let record = VerifierCommitteeAttestation {
            attestation_id: attestation_id_value.clone(),
            receipt_id: receipt_id_value.to_string(),
            trace_id: trace_id_value.clone(),
            committee_id: committee_id.to_string(),
            role,
            verdict,
            status,
            committee_member_root: committee_member_root.to_string(),
            signature_root: signature_root.to_string(),
            dissent_root: dissent_root.to_string(),
            quorum_bps,
            privacy_set_size,
            attested_height: height,
            expires_height: height.saturating_add(self.config.attestation_ttl_blocks),
            sequence,
        };
        self.committee_attestations
            .insert(attestation_id_value.clone(), record.clone());
        if verdict.accepting() && quorum_bps >= self.config.committee_quorum_bps {
            if let Some(receipt_record) = self.pcc_receipts.get_mut(receipt_id_value) {
                receipt_record.status = ReceiptStatus::Attested;
            }
            if let Some(trace_record) = self.symbolic_traces.get_mut(&trace_id_value) {
                trace_record.status = TraceStatus::Attested;
            }
            if let Some(receipt_record) = self.pcc_receipts.get(receipt_id_value) {
                if let Some(bytecode_record) = self
                    .bytecode_commitments
                    .get_mut(&receipt_record.bytecode_id)
                {
                    bytecode_record.status = BytecodeStatus::FormallyVerified;
                }
            }
        }
        self.counters.committee_attestations = sequence;
        self.push_event(
            EventKind::CommitteeAttested,
            &attestation_id_value,
            &record.record_root(),
            height,
        )?;
        self.recompute_roots();
        Ok(attestation_id_value)
    }

    pub fn seal_counterexample(
        &mut self,
        trace_id_value: &str,
        receipt_id_value: Option<String>,
        invariant_manifest_id_value: &str,
        sealed_payload_root: &str,
        encrypted_witness_root: &str,
        replay_hint_root: &str,
        reporter_commitment: &str,
        severity: CounterexampleSeverity,
        bond_amount: u64,
        privacy_set_size: u64,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure_capacity(
            "counterexample_reports",
            self.counterexample_reports.len(),
            self.config.max_counterexample_reports,
        )?;
        require_root("sealed_payload_root", sealed_payload_root)?;
        require_root("encrypted_witness_root", encrypted_witness_root)?;
        require_root("replay_hint_root", replay_hint_root)?;
        require_root("reporter_commitment", reporter_commitment)?;
        require_positive_u64("bond_amount", bond_amount)?;
        require_at_least(
            "privacy_set_size",
            privacy_set_size,
            self.config.min_privacy_set_size,
        )?;
        if !self.symbolic_traces.contains_key(trace_id_value) {
            return Err(format!("unknown trace_id {trace_id_value}"));
        }
        if !self
            .invariant_manifests
            .contains_key(invariant_manifest_id_value)
        {
            return Err(format!(
                "unknown invariant_manifest_id {invariant_manifest_id_value}"
            ));
        }
        if let Some(receipt_id) = &receipt_id_value {
            require_id("receipt_id", receipt_id)?;
            if !self.pcc_receipts.contains_key(receipt_id) {
                return Err("unknown receipt_id".to_string());
            }
        }
        let sequence = self.counters.counterexample_reports + 1;
        let report_id_value = counterexample_report_id(
            trace_id_value,
            invariant_manifest_id_value,
            sealed_payload_root,
            height,
            sequence,
        );
        let record = SealedCounterexampleReport {
            report_id: report_id_value.clone(),
            trace_id: trace_id_value.to_string(),
            receipt_id: receipt_id_value,
            invariant_manifest_id: invariant_manifest_id_value.to_string(),
            sealed_payload_root: sealed_payload_root.to_string(),
            encrypted_witness_root: encrypted_witness_root.to_string(),
            replay_hint_root: replay_hint_root.to_string(),
            reporter_commitment: reporter_commitment.to_string(),
            severity,
            status: CounterexampleStatus::Sealed,
            bond_amount,
            privacy_set_size,
            created_height: height,
            expires_height: height.saturating_add(self.config.counterexample_ttl_blocks),
            sequence,
        };
        self.counterexample_reports
            .insert(report_id_value.clone(), record.clone());
        if let Some(trace_record) = self.symbolic_traces.get_mut(trace_id_value) {
            trace_record.status = TraceStatus::CounterexampleFound;
        }
        self.counters.counterexample_reports = sequence;
        self.push_event(
            EventKind::CounterexampleSealed,
            &report_id_value,
            &record.record_root(),
            height,
        )?;
        self.recompute_roots();
        Ok(report_id_value)
    }

    pub fn open_upgrade_gate(
        &mut self,
        contract_id: &str,
        current_bytecode_id: &str,
        candidate_bytecode_id: &str,
        required_spec_id: &str,
        required_receipt_id: &str,
        committee_attestation_root: &str,
        counterexample_report_root: &str,
        privacy_fence_root: &str,
        opens_height: u64,
        expires_height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure_capacity(
            "upgrade_gates",
            self.upgrade_gates.len(),
            self.config.max_upgrade_gates,
        )?;
        require_id("contract_id", contract_id)?;
        require_root("committee_attestation_root", committee_attestation_root)?;
        require_root("counterexample_report_root", counterexample_report_root)?;
        require_root("privacy_fence_root", privacy_fence_root)?;
        require_expiry(
            "upgrade_gate",
            opens_height,
            expires_height,
            self.config.upgrade_gate_ttl_blocks,
        )?;
        if !self.bytecode_commitments.contains_key(current_bytecode_id) {
            return Err("unknown current_bytecode_id".to_string());
        }
        if !self
            .bytecode_commitments
            .contains_key(candidate_bytecode_id)
        {
            return Err("unknown candidate_bytecode_id".to_string());
        }
        if !self.spec_commitments.contains_key(required_spec_id) {
            return Err("unknown required_spec_id".to_string());
        }
        if !self.pcc_receipts.contains_key(required_receipt_id) {
            return Err("unknown required_receipt_id".to_string());
        }
        let sequence = self.counters.upgrade_gates + 1;
        let gate_id_value = upgrade_gate_id(
            contract_id,
            current_bytecode_id,
            candidate_bytecode_id,
            required_receipt_id,
            opens_height,
            sequence,
        );
        let record = UpgradeGate {
            gate_id: gate_id_value.clone(),
            contract_id: contract_id.to_string(),
            current_bytecode_id: current_bytecode_id.to_string(),
            candidate_bytecode_id: candidate_bytecode_id.to_string(),
            required_spec_id: required_spec_id.to_string(),
            required_receipt_id: required_receipt_id.to_string(),
            committee_attestation_root: committee_attestation_root.to_string(),
            counterexample_report_root: counterexample_report_root.to_string(),
            privacy_fence_root: privacy_fence_root.to_string(),
            status: UpgradeGateStatus::Open,
            opens_height,
            expires_height,
            sequence,
        };
        self.upgrade_gates
            .insert(gate_id_value.clone(), record.clone());
        if let Some(bytecode_record) = self.bytecode_commitments.get_mut(candidate_bytecode_id) {
            bytecode_record.status = BytecodeStatus::UpgradeCandidate;
        }
        self.counters.upgrade_gates = sequence;
        self.push_event(
            EventKind::UpgradeGateOpened,
            &gate_id_value,
            &record.record_root(),
            opens_height,
        )?;
        self.recompute_roots();
        Ok(gate_id_value)
    }

    pub fn register_privacy_fence(
        &mut self,
        contract_id: &str,
        bytecode_id_value: &str,
        spec_id_value: &str,
        nullifier_root: &str,
        anonymity_set_root: &str,
        view_tag_root: &str,
        privacy_epoch: u64,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure_capacity(
            "privacy_fences",
            self.privacy_fences.len(),
            self.config.max_privacy_fences,
        )?;
        require_id("contract_id", contract_id)?;
        require_root("nullifier_root", nullifier_root)?;
        require_root("anonymity_set_root", anonymity_set_root)?;
        require_root("view_tag_root", view_tag_root)?;
        require_positive_u64("privacy_epoch", privacy_epoch)?;
        if !self.bytecode_commitments.contains_key(bytecode_id_value) {
            return Err("unknown bytecode_id".to_string());
        }
        if !self.spec_commitments.contains_key(spec_id_value) {
            return Err("unknown spec_id".to_string());
        }
        let sequence = self.counters.privacy_fences + 1;
        let fence_id_value = privacy_fence_id(
            contract_id,
            bytecode_id_value,
            spec_id_value,
            nullifier_root,
            privacy_epoch,
        );
        let record = PrivacyNullifierFence {
            fence_id: fence_id_value.clone(),
            contract_id: contract_id.to_string(),
            bytecode_id: bytecode_id_value.to_string(),
            spec_id: spec_id_value.to_string(),
            nullifier_root: nullifier_root.to_string(),
            anonymity_set_root: anonymity_set_root.to_string(),
            view_tag_root: view_tag_root.to_string(),
            privacy_epoch,
            min_privacy_set_size: self.config.min_privacy_set_size,
            status: FenceStatus::Open,
            created_height: height,
            expires_height: height.saturating_add(self.config.fence_ttl_blocks),
            sequence,
        };
        self.privacy_fences
            .insert(fence_id_value.clone(), record.clone());
        self.counters.privacy_fences = sequence;
        self.push_event(
            EventKind::PrivacyFenceRegistered,
            &fence_id_value,
            &record.record_root(),
            height,
        )?;
        self.recompute_roots();
        Ok(fence_id_value)
    }

    pub fn issue_proof_cache_coupon(
        &mut self,
        receipt_id_value: &str,
        sponsor_id: &str,
        beneficiary_commitment: &str,
        cache_key_root: &str,
        coupon_value: u64,
        verifier_fee_bps: u64,
        rebate_bps: u64,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure_capacity(
            "proof_cache_coupons",
            self.proof_cache_coupons.len(),
            self.config.max_proof_cache_coupons,
        )?;
        require_id("sponsor_id", sponsor_id)?;
        require_root("beneficiary_commitment", beneficiary_commitment)?;
        require_root("cache_key_root", cache_key_root)?;
        require_positive_u64("coupon_value", coupon_value)?;
        require_bps("verifier_fee_bps", verifier_fee_bps)?;
        require_bps("rebate_bps", rebate_bps)?;
        if verifier_fee_bps > self.config.max_verifier_fee_bps {
            return Err("verifier_fee_bps exceeds runtime max".to_string());
        }
        if rebate_bps > verifier_fee_bps {
            return Err("rebate_bps cannot exceed verifier_fee_bps".to_string());
        }
        let receipt = self
            .pcc_receipts
            .get(receipt_id_value)
            .ok_or_else(|| format!("unknown receipt_id {receipt_id_value}"))?;
        let trace_id_value = receipt.trace_id.clone();
        let sequence = self.counters.proof_cache_coupons + 1;
        let coupon_id_value = proof_cache_coupon_id(
            receipt_id_value,
            sponsor_id,
            beneficiary_commitment,
            cache_key_root,
            height,
            sequence,
        );
        let record = LowFeeProofCacheCoupon {
            coupon_id: coupon_id_value.clone(),
            receipt_id: receipt_id_value.to_string(),
            trace_id: trace_id_value,
            sponsor_id: sponsor_id.to_string(),
            beneficiary_commitment: beneficiary_commitment.to_string(),
            cache_key_root: cache_key_root.to_string(),
            coupon_value,
            verifier_fee_bps,
            rebate_bps,
            status: CouponStatus::Issued,
            issued_height: height,
            expires_height: height.saturating_add(self.config.coupon_ttl_blocks),
            sequence,
        };
        self.proof_cache_coupons
            .insert(coupon_id_value.clone(), record.clone());
        self.counters.proof_cache_coupons = sequence;
        self.push_event(
            EventKind::ProofCacheCouponIssued,
            &coupon_id_value,
            &record.record_root(),
            height,
        )?;
        self.recompute_roots();
        Ok(coupon_id_value)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        kind: EvidenceKind,
        subject_id: &str,
        offender_commitment: &str,
        evidence_root_value: &str,
        transcript_root: &str,
        committee_attestation_root: &str,
        proposed_penalty: u64,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure_capacity(
            "slashing_evidence",
            self.slashing_evidence.len(),
            self.config.max_slashing_evidence,
        )?;
        require_id("subject_id", subject_id)?;
        require_root("offender_commitment", offender_commitment)?;
        require_root("evidence_root", evidence_root_value)?;
        require_root("transcript_root", transcript_root)?;
        require_root("committee_attestation_root", committee_attestation_root)?;
        require_positive_u64("proposed_penalty", proposed_penalty)?;
        let sequence = self.counters.slashing_evidence + 1;
        let evidence_id_value = slashing_evidence_id(
            kind,
            subject_id,
            evidence_root_value,
            offender_commitment,
            height,
            sequence,
        );
        let record = SlashingEvidence {
            evidence_id: evidence_id_value.clone(),
            kind,
            subject_id: subject_id.to_string(),
            offender_commitment: offender_commitment.to_string(),
            evidence_root: evidence_root_value.to_string(),
            transcript_root: transcript_root.to_string(),
            committee_attestation_root: committee_attestation_root.to_string(),
            proposed_penalty,
            status: EvidenceStatus::Submitted,
            submitted_height: height,
            sequence,
        };
        self.slashing_evidence
            .insert(evidence_id_value.clone(), record.clone());
        self.counters.slashing_evidence = sequence;
        self.push_event(
            EventKind::SlashingEvidenceSubmitted,
            &evidence_id_value,
            &record.record_root(),
            height,
        )?;
        self.recompute_roots();
        Ok(evidence_id_value)
    }

    pub fn public_record_for_subject(&self, subject_id: &str) -> Option<Value> {
        self.bytecode_commitments
            .get(subject_id)
            .map(BytecodeCommitment::public_record)
            .or_else(|| {
                self.spec_commitments
                    .get(subject_id)
                    .map(SpecCommitment::public_record)
            })
            .or_else(|| {
                self.symbolic_traces
                    .get(subject_id)
                    .map(SymbolicExecutionTrace::public_record)
            })
            .or_else(|| {
                self.pcc_receipts
                    .get(subject_id)
                    .map(ProofCarryingCodeReceipt::public_record)
            })
            .or_else(|| {
                self.committee_attestations
                    .get(subject_id)
                    .map(VerifierCommitteeAttestation::public_record)
            })
            .or_else(|| {
                self.invariant_manifests
                    .get(subject_id)
                    .map(InvariantManifest::public_record)
            })
            .or_else(|| {
                self.counterexample_reports
                    .get(subject_id)
                    .map(SealedCounterexampleReport::public_record)
            })
            .or_else(|| {
                self.upgrade_gates
                    .get(subject_id)
                    .map(UpgradeGate::public_record)
            })
            .or_else(|| {
                self.privacy_fences
                    .get(subject_id)
                    .map(PrivacyNullifierFence::public_record)
            })
            .or_else(|| {
                self.proof_cache_coupons
                    .get(subject_id)
                    .map(LowFeeProofCacheCoupon::public_record)
            })
            .or_else(|| {
                self.slashing_evidence
                    .get(subject_id)
                    .map(SlashingEvidence::public_record)
            })
            .or_else(|| self.events.get(subject_id).map(RuntimeEvent::public_record))
    }

    fn push_event(
        &mut self,
        kind: EventKind,
        subject_id: &str,
        payload_root: &str,
        height: u64,
    ) -> Result<String> {
        ensure_capacity("events", self.events.len(), self.config.max_events)?;
        require_id("subject_id", subject_id)?;
        require_root("payload_root", payload_root)?;
        let sequence = self.counters.events + 1;
        let event_id_value = event_id(kind, subject_id, payload_root, height, sequence);
        let event = RuntimeEvent {
            event_id: event_id_value.clone(),
            kind,
            subject_id: subject_id.to_string(),
            payload_root: payload_root.to_string(),
            height,
            sequence,
        };
        self.events.insert(event_id_value.clone(), event);
        self.counters.events = sequence;
        Ok(event_id_value)
    }

    fn seed_devnet_records(&mut self) {
        let height = self.config.devnet_height;
        let bytecode_root_value = sample_root("devnet-bytecode", 1);
        let abi_root = sample_root("devnet-abi", 1);
        let storage_layout_root = sample_root("devnet-storage-layout", 1);
        let deployer_commitment = sample_root("devnet-deployer", 1);
        let compiler_commitment = sample_root("devnet-compiler", 1);
        let bytecode_id_value = self
            .commit_bytecode(
                "devnet-confidential-vault",
                ContractDomain::Treasury,
                BytecodeVm::ConfidentialWasm,
                &bytecode_root_value,
                &abi_root,
                &storage_layout_root,
                &deployer_commitment,
                &compiler_commitment,
                self.config.min_pq_security_bits,
                height,
            )
            .unwrap_or_else(|_| sample_root("devnet-bytecode-id-fallback", 1));

        let spec_root_value = sample_root("devnet-spec", 1);
        let spec_id_value = self
            .commit_spec(
                &bytecode_id_value,
                SpecLanguage::Lean,
                &spec_root_value,
                &sample_root("devnet-preconditions", 1),
                &sample_root("devnet-postconditions", 1),
                &sample_root("devnet-transition", 1),
                &sample_root("devnet-privacy-claims", 1),
                &sample_root("devnet-spec-author", 1),
                height + 1,
            )
            .unwrap_or_else(|_| sample_root("devnet-spec-id-fallback", 1));

        let invariant_id_value = self
            .publish_invariant_manifest(
                &bytecode_id_value,
                &spec_id_value,
                InvariantKind::BalanceConservation,
                &sample_root("devnet-invariant-manifest", 1),
                &sample_root("devnet-invariant", 1),
                &sample_root("devnet-witness-schema", 1),
                &sample_root("devnet-prover-policy", 1),
                CounterexampleSeverity::High,
                &sample_root("devnet-invariant-author", 1),
                true,
                height + 2,
            )
            .unwrap_or_else(|_| sample_root("devnet-invariant-id-fallback", 1));

        let trace_id_value = self
            .submit_symbolic_trace(
                &bytecode_id_value,
                &spec_id_value,
                "settle_private_vault_epoch",
                &sample_root("devnet-symbolic-inputs", 1),
                &sample_root("devnet-path-conditions", 1),
                &sample_root("devnet-storage-reads", 1),
                &sample_root("devnet-storage-writes", 1),
                &sample_root("devnet-trace-events", 1),
                &sample_root("devnet-nullifiers", 1),
                &sample_root("devnet-call-graph", 1),
                &sample_root("devnet-invariant-results", 1),
                &sample_root("devnet-prover", 1),
                8_192,
                64,
                self.config.batch_privacy_set_size,
                height + 3,
            )
            .unwrap_or_else(|_| sample_root("devnet-trace-id-fallback", 1));

        let receipt_id_value = self
            .issue_pcc_receipt(
                &bytecode_id_value,
                &spec_id_value,
                &trace_id_value,
                "lean-to-pq-recursive-stark",
                &sample_root("devnet-verifier-key", 1),
                &sample_root("devnet-proof", 1),
                &sample_root("devnet-assumptions", 1),
                &sample_root("devnet-obligations", 1),
                &sample_root("devnet-discharged-invariants", 1),
                None,
                &sample_root("devnet-committee", 1),
                2_048,
                1_200,
                height + 4,
            )
            .unwrap_or_else(|_| sample_root("devnet-receipt-id-fallback", 1));

        let attestation_root_value = self
            .attest_receipt(
                &receipt_id_value,
                "devnet-formal-verifier-committee",
                CommitteeRole::FormalMethodsLead,
                AttestationVerdict::Valid,
                &sample_root("devnet-committee-members", 1),
                &sample_root("devnet-signatures", 1),
                &sample_root("devnet-dissent", 1),
                self.config.strong_quorum_bps,
                self.config.batch_privacy_set_size,
                height + 5,
            )
            .map(|id| {
                self.committee_attestations
                    .get(&id)
                    .map(VerifierCommitteeAttestation::record_root)
                    .unwrap_or_else(|| sample_root("devnet-attestation-root-fallback", 1))
            })
            .unwrap_or_else(|_| sample_root("devnet-attestation-root-fallback", 1));

        let _ = self.register_privacy_fence(
            "devnet-confidential-vault",
            &bytecode_id_value,
            &spec_id_value,
            &sample_root("devnet-fence-nullifier", 1),
            &sample_root("devnet-fence-anonymity-set", 1),
            &sample_root("devnet-fence-view-tags", 1),
            7,
            height + 6,
        );

        let _ = self.issue_proof_cache_coupon(
            &receipt_id_value,
            "devnet-proof-cache-sponsor",
            &sample_root("devnet-beneficiary", 1),
            &sample_root("devnet-cache-key", 1),
            500,
            self.config.max_verifier_fee_bps,
            self.config.target_coupon_rebate_bps,
            height + 7,
        );

        let _ = self.seal_counterexample(
            &trace_id_value,
            Some(receipt_id_value.clone()),
            &invariant_id_value,
            &sample_root("devnet-sealed-counterexample", 1),
            &sample_root("devnet-encrypted-witness", 1),
            &sample_root("devnet-replay-hint", 1),
            &sample_root("devnet-reporter", 1),
            CounterexampleSeverity::Informational,
            1,
            self.config.batch_privacy_set_size,
            height + 8,
        );

        let _ = self.open_upgrade_gate(
            "devnet-confidential-vault",
            &bytecode_id_value,
            &bytecode_id_value,
            &spec_id_value,
            &receipt_id_value,
            &attestation_root_value,
            &self.roots.counterexample_report_root.clone(),
            &self.roots.privacy_fence_root.clone(),
            height + 9,
            height + 9 + self.config.upgrade_gate_ttl_blocks,
        );

        let _ = self.submit_slashing_evidence(
            EvidenceKind::CommitteeEquivocation,
            "devnet-formal-verifier-committee",
            &sample_root("devnet-offender", 1),
            &sample_root("devnet-evidence", 1),
            &sample_root("devnet-transcript", 1),
            &attestation_root_value,
            1,
            height + 10,
        );
    }
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(
        "private_l2_pq_confidential_contract_formal_verifier_state_root",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    domain_hash(
        "private_l2_pq_confidential_contract_formal_verifier_public_record_root",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn bytecode_id(
    contract_id: &str,
    domain: ContractDomain,
    vm: BytecodeVm,
    bytecode_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_formal_verifier_bytecode_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(domain.as_str()),
            HashPart::Str(vm.as_str()),
            HashPart::Str(bytecode_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn spec_id(
    contract_id: &str,
    bytecode_id: &str,
    language: SpecLanguage,
    spec_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_formal_verifier_spec_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(bytecode_id),
            HashPart::Str(language.as_str()),
            HashPart::Str(spec_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn invariant_manifest_id(
    contract_id: &str,
    bytecode_id: &str,
    spec_id: &str,
    kind: InvariantKind,
    manifest_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_formal_verifier_invariant_manifest_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(bytecode_id),
            HashPart::Str(spec_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(manifest_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn symbolic_trace_id(
    bytecode_id: &str,
    spec_id: &str,
    entrypoint: &str,
    path_condition_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_formal_verifier_symbolic_trace_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bytecode_id),
            HashPart::Str(spec_id),
            HashPart::Str(entrypoint),
            HashPart::Str(path_condition_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn pcc_receipt_id(
    bytecode_id: &str,
    spec_id: &str,
    trace_id: &str,
    proof_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_formal_verifier_pcc_receipt_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bytecode_id),
            HashPart::Str(spec_id),
            HashPart::Str(trace_id),
            HashPart::Str(proof_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn committee_attestation_id(
    receipt_id: &str,
    committee_id: &str,
    role: CommitteeRole,
    committee_member_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_formal_verifier_committee_attestation_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(committee_id),
            HashPart::Str(role.as_str()),
            HashPart::Str(committee_member_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn counterexample_report_id(
    trace_id: &str,
    invariant_manifest_id: &str,
    sealed_payload_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_formal_verifier_counterexample_report_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(trace_id),
            HashPart::Str(invariant_manifest_id),
            HashPart::Str(sealed_payload_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn upgrade_gate_id(
    contract_id: &str,
    current_bytecode_id: &str,
    candidate_bytecode_id: &str,
    required_receipt_id: &str,
    opens_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_formal_verifier_upgrade_gate_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(current_bytecode_id),
            HashPart::Str(candidate_bytecode_id),
            HashPart::Str(required_receipt_id),
            HashPart::U64(opens_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn privacy_fence_id(
    contract_id: &str,
    bytecode_id: &str,
    spec_id: &str,
    nullifier_root: &str,
    privacy_epoch: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_formal_verifier_privacy_fence_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(bytecode_id),
            HashPart::Str(spec_id),
            HashPart::Str(nullifier_root),
            HashPart::U64(privacy_epoch),
        ],
        32,
    )
}

pub fn proof_cache_coupon_id(
    receipt_id: &str,
    sponsor_id: &str,
    beneficiary_commitment: &str,
    cache_key_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_formal_verifier_proof_cache_coupon_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(sponsor_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(cache_key_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn slashing_evidence_id(
    kind: EvidenceKind,
    subject_id: &str,
    evidence_root: &str,
    offender_commitment: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_formal_verifier_slashing_evidence_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(evidence_root),
            HashPart::Str(offender_commitment),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn event_id(
    kind: EventKind,
    subject_id: &str,
    payload_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "private_l2_pq_confidential_formal_verifier_event_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn sample_root(label: &str, index: u64) -> String {
    domain_hash(
        "private_l2_pq_confidential_formal_verifier_devnet_sample_root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(index),
        ],
        32,
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn map_root<T, F>(domain: &str, records: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = records
        .iter()
        .map(|(id, record)| json!({ "id": id, "record": public_record(record) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn require_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(())
}

fn require_id(name: &str, value: &str) -> Result<()> {
    require_non_empty(name, value)?;
    if value.len() > 256 {
        return Err(format!("{name} is too long"));
    }
    Ok(())
}

fn require_root(name: &str, value: &str) -> Result<()> {
    require_non_empty(name, value)?;
    if value.len() < 16 {
        return Err(format!("{name} must be a commitment/root-like value"));
    }
    Ok(())
}

fn require_bps(name: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{name} exceeds {MAX_BPS} bps"));
    }
    Ok(())
}

fn require_at_least(name: &str, value: u64, min: u64) -> Result<()> {
    if value < min {
        return Err(format!("{name} must be at least {min}"));
    }
    Ok(())
}

fn require_at_least_u16(name: &str, value: u16, min: u16) -> Result<()> {
    if value < min {
        return Err(format!("{name} must be at least {min}"));
    }
    Ok(())
}

fn require_positive_u64(name: &str, value: u64) -> Result<()> {
    if value == 0 {
        return Err(format!("{name} must be positive"));
    }
    Ok(())
}

fn require_positive_usize(name: &str, value: usize) -> Result<()> {
    if value == 0 {
        return Err(format!("{name} must be positive"));
    }
    Ok(())
}

fn require_expiry(name: &str, start: u64, expiry: u64, max_ttl: u64) -> Result<()> {
    if expiry <= start {
        return Err(format!("{name} expiry must be after start"));
    }
    if expiry.saturating_sub(start) > max_ttl {
        return Err(format!("{name} ttl exceeds runtime limit"));
    }
    Ok(())
}

fn ensure_capacity(name: &str, len: usize, max: usize) -> Result<()> {
    if len >= max {
        return Err(format!("{name} capacity exhausted"));
    }
    Ok(())
}
