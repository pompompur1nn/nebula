use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_FORMAL_INVARIANT_REGISTRY_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-formal-invariant-registry-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_FORMAL_INVARIANT_REGISTRY_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "nebula-stable-fnv1a-contract-invariant-registry-v1";
pub const PQ_ATTESTATION_SUITE: &str =
    "ml-dsa-87+slh-dsa-shake-256f-contract-invariant-attestation-v1";
pub const CONFIDENTIAL_CONDITION_COMMITMENT_SCHEME: &str =
    "private-l2-confidential-contract-pre-post-condition-commitment-v1";
pub const FORMAL_INVARIANT_MANIFEST_SCHEME: &str =
    "private-l2-formal-contract-invariant-manifest-root-v1";
pub const RELEASE_GATE_SCHEME: &str =
    "private-l2-pq-confidential-contract-invariant-release-gate-v1";
pub const VIOLATION_QUARANTINE_SCHEME: &str =
    "private-l2-pq-confidential-contract-invariant-violation-quarantine-v1";
pub const LOW_FEE_BATCH_SCHEME: &str =
    "private-l2-low-fee-confidential-contract-invariant-proof-batch-v1";
pub const OPERATOR_PUBLIC_SUMMARY_SCHEME: &str =
    "private-l2-operator-contract-invariant-public-summary-v1";
pub const DEFAULT_CHAIN_ID: &str = "nebula-monero-private-l2-devnet";
pub const DEFAULT_RELEASE_ID: &str = "nebula-contract-invariant-registry-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_RELEASE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_RELEASE_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 512;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_TARGET_BATCH_REBATE_BPS: u64 = 8;
pub const DEFAULT_MAX_OPEN_VIOLATIONS: usize = 64;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractDomain {
    Token,
    Amm,
    Lending,
    Perpetuals,
    Vault,
    Governance,
    Oracle,
    Bridge,
    Treasury,
    General,
}

impl ContractDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Amm => "amm",
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Vault => "vault",
            Self::Governance => "governance",
            Self::Oracle => "oracle",
            Self::Bridge => "bridge",
            Self::Treasury => "treasury",
            Self::General => "general",
        }
    }

    pub fn release_weight(self) -> u64 {
        match self {
            Self::Lending | Self::Perpetuals => 1_200,
            Self::Amm => 1_100,
            Self::Token | Self::Bridge | Self::Treasury => 1_000,
            Self::Vault => 950,
            Self::Oracle => 850,
            Self::Governance => 800,
            Self::General => 700,
        }
    }

    pub fn default_invariant_classes(self) -> Vec<InvariantClass> {
        match self {
            Self::Token => vec![
                InvariantClass::TokenSupplyConservation,
                InvariantClass::TokenAllowanceBounded,
                InvariantClass::TokenMintBurnAuthority,
                InvariantClass::TokenFeeConservation,
                InvariantClass::ConfidentialBalanceConservation,
                InvariantClass::NullifierUniqueness,
            ],
            Self::Amm => vec![
                InvariantClass::AmmConstantProduct,
                InvariantClass::AmmStableSwapCurve,
                InvariantClass::AmmReserveNonNegative,
                InvariantClass::AmmLpShareAccounting,
                InvariantClass::ConfidentialBalanceConservation,
                InvariantClass::OracleFreshness,
            ],
            Self::Lending => vec![
                InvariantClass::LendingSolvency,
                InvariantClass::LendingCollateralization,
                InvariantClass::LendingInterestIndexMonotonic,
                InvariantClass::LendingLiquidationBounded,
                InvariantClass::OracleFreshness,
                InvariantClass::AccessControl,
            ],
            Self::Perpetuals => vec![
                InvariantClass::PerpsMarginSafety,
                InvariantClass::PerpsFundingRateBounded,
                InvariantClass::PerpsOpenInterestCap,
                InvariantClass::PerpsPnLConservation,
                InvariantClass::OracleFreshness,
                InvariantClass::AccessControl,
            ],
            Self::Bridge => vec![
                InvariantClass::BridgeReserveBacking,
                InvariantClass::NullifierUniqueness,
                InvariantClass::ConfidentialBalanceConservation,
                InvariantClass::AccessControl,
                InvariantClass::UpgradeTimelock,
            ],
            Self::Vault | Self::Treasury => vec![
                InvariantClass::ConfidentialBalanceConservation,
                InvariantClass::AccessControl,
                InvariantClass::UpgradeTimelock,
                InvariantClass::CrossContractAtomicity,
            ],
            Self::Governance => vec![
                InvariantClass::AccessControl,
                InvariantClass::UpgradeTimelock,
                InvariantClass::NullifierUniqueness,
            ],
            Self::Oracle => vec![
                InvariantClass::OracleFreshness,
                InvariantClass::AccessControl,
                InvariantClass::NullifierUniqueness,
            ],
            Self::General => vec![
                InvariantClass::CrossContractAtomicity,
                InvariantClass::AccessControl,
                InvariantClass::Custom,
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantClass {
    TokenSupplyConservation,
    TokenAllowanceBounded,
    TokenMintBurnAuthority,
    TokenFeeConservation,
    AmmConstantProduct,
    AmmStableSwapCurve,
    AmmReserveNonNegative,
    AmmLpShareAccounting,
    LendingSolvency,
    LendingCollateralization,
    LendingInterestIndexMonotonic,
    LendingLiquidationBounded,
    PerpsMarginSafety,
    PerpsFundingRateBounded,
    PerpsOpenInterestCap,
    PerpsPnLConservation,
    CrossContractAtomicity,
    ConfidentialBalanceConservation,
    NullifierUniqueness,
    AccessControl,
    UpgradeTimelock,
    OracleFreshness,
    BridgeReserveBacking,
    Custom,
}

impl InvariantClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenSupplyConservation => "token_supply_conservation",
            Self::TokenAllowanceBounded => "token_allowance_bounded",
            Self::TokenMintBurnAuthority => "token_mint_burn_authority",
            Self::TokenFeeConservation => "token_fee_conservation",
            Self::AmmConstantProduct => "amm_constant_product",
            Self::AmmStableSwapCurve => "amm_stable_swap_curve",
            Self::AmmReserveNonNegative => "amm_reserve_non_negative",
            Self::AmmLpShareAccounting => "amm_lp_share_accounting",
            Self::LendingSolvency => "lending_solvency",
            Self::LendingCollateralization => "lending_collateralization",
            Self::LendingInterestIndexMonotonic => "lending_interest_index_monotonic",
            Self::LendingLiquidationBounded => "lending_liquidation_bounded",
            Self::PerpsMarginSafety => "perps_margin_safety",
            Self::PerpsFundingRateBounded => "perps_funding_rate_bounded",
            Self::PerpsOpenInterestCap => "perps_open_interest_cap",
            Self::PerpsPnLConservation => "perps_pnl_conservation",
            Self::CrossContractAtomicity => "cross_contract_atomicity",
            Self::ConfidentialBalanceConservation => "confidential_balance_conservation",
            Self::NullifierUniqueness => "nullifier_uniqueness",
            Self::AccessControl => "access_control",
            Self::UpgradeTimelock => "upgrade_timelock",
            Self::OracleFreshness => "oracle_freshness",
            Self::BridgeReserveBacking => "bridge_reserve_backing",
            Self::Custom => "custom",
        }
    }

    pub fn default_severity(self) -> ViolationSeverity {
        match self {
            Self::TokenSupplyConservation
            | Self::AmmConstantProduct
            | Self::LendingSolvency
            | Self::PerpsMarginSafety
            | Self::BridgeReserveBacking
            | Self::ConfidentialBalanceConservation
            | Self::NullifierUniqueness => ViolationSeverity::Critical,
            Self::TokenMintBurnAuthority
            | Self::AmmReserveNonNegative
            | Self::LendingCollateralization
            | Self::PerpsPnLConservation
            | Self::CrossContractAtomicity
            | Self::AccessControl => ViolationSeverity::High,
            Self::TokenAllowanceBounded
            | Self::TokenFeeConservation
            | Self::AmmStableSwapCurve
            | Self::AmmLpShareAccounting
            | Self::LendingInterestIndexMonotonic
            | Self::LendingLiquidationBounded
            | Self::PerpsFundingRateBounded
            | Self::PerpsOpenInterestCap
            | Self::UpgradeTimelock
            | Self::OracleFreshness => ViolationSeverity::Medium,
            Self::Custom => ViolationSeverity::Low,
        }
    }

    pub fn release_blocker_by_default(self) -> bool {
        matches!(
            self,
            Self::TokenSupplyConservation
                | Self::AmmConstantProduct
                | Self::AmmReserveNonNegative
                | Self::LendingSolvency
                | Self::LendingCollateralization
                | Self::PerpsMarginSafety
                | Self::PerpsPnLConservation
                | Self::ConfidentialBalanceConservation
                | Self::NullifierUniqueness
                | Self::AccessControl
                | Self::BridgeReserveBacking
        )
    }

    pub fn suggested_minimum_attesters(self) -> u16 {
        match self.default_severity() {
            ViolationSeverity::Critical => 3,
            ViolationSeverity::High => 2,
            ViolationSeverity::Medium => 2,
            ViolationSeverity::Low => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionPhase {
    PreCondition,
    PostCondition,
    Both,
}

impl ConditionPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreCondition => "pre_condition",
            Self::PostCondition => "post_condition",
            Self::Both => "both",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantStatus {
    Draft,
    Registered,
    Attested,
    ReleaseCandidate,
    Released,
    Quarantined,
    Deprecated,
    Revoked,
}

impl InvariantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Registered => "registered",
            Self::Attested => "attested",
            Self::ReleaseCandidate => "release_candidate",
            Self::Released => "released",
            Self::Quarantined => "quarantined",
            Self::Deprecated => "deprecated",
            Self::Revoked => "revoked",
        }
    }

    pub fn release_eligible(self) -> bool {
        matches!(
            self,
            Self::Attested | Self::ReleaseCandidate | Self::Released
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Rejected,
    Slashed,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseGateStatus {
    Draft,
    AwaitingAttestations,
    Candidate,
    Ready,
    Blocked,
    Quarantined,
}

impl ReleaseGateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::AwaitingAttestations => "awaiting_attestations",
            Self::Candidate => "candidate",
            Self::Ready => "ready",
            Self::Blocked => "blocked",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl ViolationSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn score(self) -> u64 {
        match self {
            Self::Low => 1,
            Self::Medium => 3,
            Self::High => 7,
            Self::Critical => 13,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationStatus {
    Reported,
    Quarantined,
    Mitigated,
    Cleared,
    Slashed,
}

impl ViolationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reported => "reported",
            Self::Quarantined => "quarantined",
            Self::Mitigated => "mitigated",
            Self::Cleared => "cleared",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    Submitted,
    Proven,
    Rejected,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Submitted => "submitted",
            Self::Proven => "proven",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub release_id: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub release_quorum_bps: u64,
    pub strong_release_quorum_bps: u64,
    pub max_batch_items: usize,
    pub max_user_fee_bps: u64,
    pub target_batch_rebate_bps: u64,
    pub max_open_violations_per_contract: usize,
    pub require_pre_and_post_commitments: bool,
    pub require_operator_summary_for_release: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: DEFAULT_CHAIN_ID.to_string(),
            release_id: DEFAULT_RELEASE_ID.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            release_quorum_bps: DEFAULT_RELEASE_QUORUM_BPS,
            strong_release_quorum_bps: DEFAULT_STRONG_RELEASE_QUORUM_BPS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_batch_rebate_bps: DEFAULT_TARGET_BATCH_REBATE_BPS,
            max_open_violations_per_contract: DEFAULT_MAX_OPEN_VIOLATIONS,
            require_pre_and_post_commitments: true,
            require_operator_summary_for_release: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        if self.chain_id.is_empty() {
            return Err("chain_id must not be empty".to_string());
        }
        if self.release_id.is_empty() {
            return Err("release_id must not be empty".to_string());
        }
        if self.min_pq_security_bits < DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("min_pq_security_bits below module floor".to_string());
        }
        if self.min_privacy_set_size < DEFAULT_MIN_PRIVACY_SET_SIZE {
            return Err("min_privacy_set_size below module floor".to_string());
        }
        if self.release_quorum_bps > MAX_BPS || self.strong_release_quorum_bps > MAX_BPS {
            return Err("release quorum bps must be <= 10000".to_string());
        }
        if self.release_quorum_bps == 0 || self.strong_release_quorum_bps < self.release_quorum_bps
        {
            return Err("release quorum ordering invalid".to_string());
        }
        if self.max_batch_items == 0 {
            return Err("max_batch_items must be positive".to_string());
        }
        if self.max_user_fee_bps > MAX_BPS || self.target_batch_rebate_bps > MAX_BPS {
            return Err("fee bps must be <= 10000".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub contracts_registered: u64,
    pub invariants_registered: u64,
    pub condition_commitments_recorded: u64,
    pub attestations_recorded: u64,
    pub release_gates_opened: u64,
    pub release_gates_ready: u64,
    pub release_gates_blocked: u64,
    pub violations_reported: u64,
    pub violations_quarantined: u64,
    pub violations_cleared: u64,
    pub proof_batches_opened: u64,
    pub proof_batches_proven: u64,
    pub operator_summaries_published: u64,
    pub rejected_requests: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub contracts_root: String,
    pub invariants_root: String,
    pub condition_commitments_root: String,
    pub attestations_root: String,
    pub release_gates_root: String,
    pub violations_root: String,
    pub proof_batches_root: String,
    pub operator_summaries_root: String,
    pub quarantined_contracts_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractRegistrationRequest {
    pub contract_id: String,
    pub domain: ContractDomain,
    pub bytecode_commitment: String,
    pub state_commitment: String,
    pub deployer_pq_key_commitment: String,
    pub upgrade_authority_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub metadata_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractRecord {
    pub contract_id: String,
    pub domain: ContractDomain,
    pub bytecode_commitment: String,
    pub state_commitment: String,
    pub deployer_pq_key_commitment: String,
    pub upgrade_authority_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub metadata_commitment: String,
    pub invariant_ids: BTreeSet<String>,
    pub open_violation_ids: BTreeSet<String>,
    pub released_gate_ids: BTreeSet<String>,
    pub quarantined: bool,
}

impl ContractRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "contract_id": self.contract_id,
            "domain": self.domain.as_str(),
            "bytecode_commitment": self.bytecode_commitment,
            "state_commitment": self.state_commitment,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "invariant_count": self.invariant_ids.len(),
            "open_violation_count": self.open_violation_ids.len(),
            "released_gate_count": self.released_gate_ids.len(),
            "quarantined": self.quarantined
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvariantRegistrationRequest {
    pub invariant_id: String,
    pub contract_id: String,
    pub class: InvariantClass,
    pub title: String,
    pub formal_spec_commitment: String,
    pub witness_schema_commitment: String,
    pub prover_circuit_commitment: String,
    pub transition_scope_commitment: String,
    pub minimum_attesters: u16,
    pub release_blocker: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvariantRecord {
    pub invariant_id: String,
    pub contract_id: String,
    pub class: InvariantClass,
    pub title: String,
    pub formal_spec_commitment: String,
    pub witness_schema_commitment: String,
    pub prover_circuit_commitment: String,
    pub transition_scope_commitment: String,
    pub minimum_attesters: u16,
    pub release_blocker: bool,
    pub status: InvariantStatus,
    pub condition_commitment_ids: BTreeSet<String>,
    pub attestation_ids: BTreeSet<String>,
    pub violation_ids: BTreeSet<String>,
}

impl InvariantRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "invariant_id": self.invariant_id,
            "contract_id": self.contract_id,
            "class": self.class.as_str(),
            "title": self.title,
            "formal_spec_commitment": self.formal_spec_commitment,
            "witness_schema_commitment": self.witness_schema_commitment,
            "prover_circuit_commitment": self.prover_circuit_commitment,
            "transition_scope_commitment": self.transition_scope_commitment,
            "minimum_attesters": self.minimum_attesters,
            "release_blocker": self.release_blocker,
            "status": self.status.as_str(),
            "condition_commitment_count": self.condition_commitment_ids.len(),
            "attestation_count": self.attestation_ids.len(),
            "violation_count": self.violation_ids.len()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConditionCommitmentRequest {
    pub condition_id: String,
    pub invariant_id: String,
    pub phase: ConditionPhase,
    pub confidential_pre_state_commitment: String,
    pub confidential_post_state_commitment: String,
    pub encrypted_predicate_commitment: String,
    pub nullifier_set_commitment: String,
    pub view_key_policy_commitment: String,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConditionCommitmentRecord {
    pub condition_id: String,
    pub invariant_id: String,
    pub contract_id: String,
    pub phase: ConditionPhase,
    pub confidential_pre_state_commitment: String,
    pub confidential_post_state_commitment: String,
    pub encrypted_predicate_commitment: String,
    pub nullifier_set_commitment: String,
    pub view_key_policy_commitment: String,
    pub privacy_set_size: u64,
    pub commitment_scheme: String,
}

impl ConditionCommitmentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "condition_id": self.condition_id,
            "invariant_id": self.invariant_id,
            "contract_id": self.contract_id,
            "phase": self.phase.as_str(),
            "encrypted_predicate_commitment": self.encrypted_predicate_commitment,
            "nullifier_set_commitment": self.nullifier_set_commitment,
            "privacy_set_size": self.privacy_set_size,
            "commitment_scheme": self.commitment_scheme
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqInvariantAttestationRequest {
    pub attestation_id: String,
    pub invariant_id: String,
    pub attester_id: String,
    pub attester_pq_key_commitment: String,
    pub signed_manifest_commitment: String,
    pub signature_commitment: String,
    pub proof_system: String,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub covers_pre_conditions: bool,
    pub covers_post_conditions: bool,
    pub release_weight_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqInvariantAttestationRecord {
    pub attestation_id: String,
    pub invariant_id: String,
    pub contract_id: String,
    pub attester_id: String,
    pub attester_pq_key_commitment: String,
    pub signed_manifest_commitment: String,
    pub signature_commitment: String,
    pub proof_system: String,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub covers_pre_conditions: bool,
    pub covers_post_conditions: bool,
    pub release_weight_bps: u64,
    pub status: AttestationStatus,
}

impl PqInvariantAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "invariant_id": self.invariant_id,
            "contract_id": self.contract_id,
            "attester_id": self.attester_id,
            "signed_manifest_commitment": self.signed_manifest_commitment,
            "signature_commitment": self.signature_commitment,
            "proof_system": self.proof_system,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "covers_pre_conditions": self.covers_pre_conditions,
            "covers_post_conditions": self.covers_post_conditions,
            "release_weight_bps": self.release_weight_bps,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseGateRequest {
    pub gate_id: String,
    pub contract_id: String,
    pub release_label: String,
    pub required_invariant_ids: BTreeSet<String>,
    pub bytecode_commitment: String,
    pub state_transition_commitment: String,
    pub operator_summary_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseGateRecord {
    pub gate_id: String,
    pub contract_id: String,
    pub release_label: String,
    pub required_invariant_ids: BTreeSet<String>,
    pub bytecode_commitment: String,
    pub state_transition_commitment: String,
    pub operator_summary_id: String,
    pub quorum_bps: u64,
    pub blocker_count: u64,
    pub open_violation_count: u64,
    pub status: ReleaseGateStatus,
}

impl ReleaseGateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "contract_id": self.contract_id,
            "release_label": self.release_label,
            "required_invariant_count": self.required_invariant_ids.len(),
            "bytecode_commitment": self.bytecode_commitment,
            "state_transition_commitment": self.state_transition_commitment,
            "operator_summary_id": self.operator_summary_id,
            "quorum_bps": self.quorum_bps,
            "blocker_count": self.blocker_count,
            "open_violation_count": self.open_violation_count,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViolationReportRequest {
    pub violation_id: String,
    pub invariant_id: String,
    pub reporter_id: String,
    pub severity: ViolationSeverity,
    pub sealed_counterexample_commitment: String,
    pub impacted_state_commitment: String,
    pub mitigation_commitment: String,
    pub quarantine_contract: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViolationRecord {
    pub violation_id: String,
    pub invariant_id: String,
    pub contract_id: String,
    pub reporter_id: String,
    pub severity: ViolationSeverity,
    pub sealed_counterexample_commitment: String,
    pub impacted_state_commitment: String,
    pub mitigation_commitment: String,
    pub status: ViolationStatus,
}

impl ViolationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "violation_id": self.violation_id,
            "invariant_id": self.invariant_id,
            "contract_id": self.contract_id,
            "reporter_id": self.reporter_id,
            "severity": self.severity.as_str(),
            "sealed_counterexample_commitment": self.sealed_counterexample_commitment,
            "impacted_state_commitment": self.impacted_state_commitment,
            "mitigation_commitment": self.mitigation_commitment,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeProofBatchRequest {
    pub batch_id: String,
    pub sponsor_id: String,
    pub invariant_ids: BTreeSet<String>,
    pub aggregate_proof_commitment: String,
    pub fee_asset_id: String,
    pub user_fee_bps: u64,
    pub rebate_bps: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeProofBatchRecord {
    pub batch_id: String,
    pub sponsor_id: String,
    pub invariant_ids: BTreeSet<String>,
    pub aggregate_proof_commitment: String,
    pub fee_asset_id: String,
    pub user_fee_bps: u64,
    pub rebate_bps: u64,
    pub privacy_set_size: u64,
    pub status: BatchStatus,
}

impl LowFeeProofBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "sponsor_id": self.sponsor_id,
            "invariant_count": self.invariant_ids.len(),
            "aggregate_proof_commitment": self.aggregate_proof_commitment,
            "fee_asset_id": self.fee_asset_id,
            "user_fee_bps": self.user_fee_bps,
            "rebate_bps": self.rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRequest {
    pub summary_id: String,
    pub operator_id: String,
    pub contract_id: String,
    pub public_epoch: u64,
    pub covered_invariant_ids: BTreeSet<String>,
    pub summary_commitment: String,
    pub release_risk_score_bps: u64,
    pub open_issue_count: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRecord {
    pub summary_id: String,
    pub operator_id: String,
    pub contract_id: String,
    pub public_epoch: u64,
    pub covered_invariant_ids: BTreeSet<String>,
    pub summary_commitment: String,
    pub release_risk_score_bps: u64,
    pub open_issue_count: u64,
}

impl OperatorSummaryRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "contract_id": self.contract_id,
            "public_epoch": self.public_epoch,
            "covered_invariant_count": self.covered_invariant_ids.len(),
            "summary_commitment": self.summary_commitment,
            "release_risk_score_bps": self.release_risk_score_bps,
            "open_issue_count": self.open_issue_count
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub contracts: BTreeMap<String, ContractRecord>,
    pub invariants: BTreeMap<String, InvariantRecord>,
    pub condition_commitments: BTreeMap<String, ConditionCommitmentRecord>,
    pub attestations: BTreeMap<String, PqInvariantAttestationRecord>,
    pub release_gates: BTreeMap<String, ReleaseGateRecord>,
    pub violations: BTreeMap<String, ViolationRecord>,
    pub proof_batches: BTreeMap<String, LowFeeProofBatchRecord>,
    pub operator_summaries: BTreeMap<String, OperatorSummaryRecord>,
    pub quarantined_contracts: BTreeSet<String>,
    pub rejected_request_log: Vec<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            contracts: BTreeMap::new(),
            invariants: BTreeMap::new(),
            condition_commitments: BTreeMap::new(),
            attestations: BTreeMap::new(),
            release_gates: BTreeMap::new(),
            violations: BTreeMap::new(),
            proof_batches: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            quarantined_contracts: BTreeSet::new(),
            rejected_request_log: Vec::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        let _ = state.record_contract(ContractRegistrationRequest {
            contract_id: "devnet-token-vault".to_string(),
            domain: ContractDomain::Token,
            bytecode_commitment: "bytecode:token-vault:v1".to_string(),
            state_commitment: "state:token-vault:genesis".to_string(),
            deployer_pq_key_commitment: "pq-key:deployer:token-vault".to_string(),
            upgrade_authority_commitment: "upgrade:timelock:token-vault".to_string(),
            privacy_set_size: 262_144,
            pq_security_bits: 256,
            metadata_commitment: "metadata:token-vault".to_string(),
        });
        let _ = state.record_contract(ContractRegistrationRequest {
            contract_id: "devnet-amm-pool".to_string(),
            domain: ContractDomain::Amm,
            bytecode_commitment: "bytecode:amm-pool:v1".to_string(),
            state_commitment: "state:amm-pool:genesis".to_string(),
            deployer_pq_key_commitment: "pq-key:deployer:amm-pool".to_string(),
            upgrade_authority_commitment: "upgrade:timelock:amm-pool".to_string(),
            privacy_set_size: 262_144,
            pq_security_bits: 256,
            metadata_commitment: "metadata:amm-pool".to_string(),
        });
        let token_inv = InvariantRegistrationRequest {
            invariant_id: "inv-token-supply".to_string(),
            contract_id: "devnet-token-vault".to_string(),
            class: InvariantClass::TokenSupplyConservation,
            title: "confidential token supply remains conserved across mint burn transfer"
                .to_string(),
            formal_spec_commitment: "spec:token:supply".to_string(),
            witness_schema_commitment: "witness:token:supply".to_string(),
            prover_circuit_commitment: "circuit:token:supply".to_string(),
            transition_scope_commitment: "scope:token:supply".to_string(),
            minimum_attesters: 2,
            release_blocker: true,
        };
        let amm_inv = InvariantRegistrationRequest {
            invariant_id: "inv-amm-k".to_string(),
            contract_id: "devnet-amm-pool".to_string(),
            class: InvariantClass::AmmConstantProduct,
            title: "constant product is preserved after confidential swap fees".to_string(),
            formal_spec_commitment: "spec:amm:k".to_string(),
            witness_schema_commitment: "witness:amm:k".to_string(),
            prover_circuit_commitment: "circuit:amm:k".to_string(),
            transition_scope_commitment: "scope:amm:k".to_string(),
            minimum_attesters: 2,
            release_blocker: true,
        };
        let _ = state.register_invariant(token_inv);
        let _ = state.register_invariant(amm_inv);
        let _ = state.record_condition_commitment(ConditionCommitmentRequest {
            condition_id: "cond-token-supply-prepost".to_string(),
            invariant_id: "inv-token-supply".to_string(),
            phase: ConditionPhase::Both,
            confidential_pre_state_commitment: "pre:token:supply".to_string(),
            confidential_post_state_commitment: "post:token:supply".to_string(),
            encrypted_predicate_commitment: "predicate:token:supply".to_string(),
            nullifier_set_commitment: "nullifiers:token:supply".to_string(),
            view_key_policy_commitment: "view-policy:operator-only".to_string(),
            privacy_set_size: 262_144,
        });
        let _ = state.record_condition_commitment(ConditionCommitmentRequest {
            condition_id: "cond-amm-k-prepost".to_string(),
            invariant_id: "inv-amm-k".to_string(),
            phase: ConditionPhase::Both,
            confidential_pre_state_commitment: "pre:amm:k".to_string(),
            confidential_post_state_commitment: "post:amm:k".to_string(),
            encrypted_predicate_commitment: "predicate:amm:k".to_string(),
            nullifier_set_commitment: "nullifiers:amm:k".to_string(),
            view_key_policy_commitment: "view-policy:operator-only".to_string(),
            privacy_set_size: 262_144,
        });
        let _ = state.record_attestation(PqInvariantAttestationRequest {
            attestation_id: "att-token-supply-a".to_string(),
            invariant_id: "inv-token-supply".to_string(),
            attester_id: "formal-lab-a".to_string(),
            attester_pq_key_commitment: "pq-key:formal-lab-a".to_string(),
            signed_manifest_commitment: "manifest:token:supply:a".to_string(),
            signature_commitment: "sig:token:supply:a".to_string(),
            proof_system: "zkvm+ml-dsa".to_string(),
            pq_security_bits: 256,
            privacy_set_size: 262_144,
            covers_pre_conditions: true,
            covers_post_conditions: true,
            release_weight_bps: 3_400,
        });
        let _ = state.record_attestation(PqInvariantAttestationRequest {
            attestation_id: "att-token-supply-b".to_string(),
            invariant_id: "inv-token-supply".to_string(),
            attester_id: "formal-lab-b".to_string(),
            attester_pq_key_commitment: "pq-key:formal-lab-b".to_string(),
            signed_manifest_commitment: "manifest:token:supply:b".to_string(),
            signature_commitment: "sig:token:supply:b".to_string(),
            proof_system: "zkvm+slh-dsa".to_string(),
            pq_security_bits: 256,
            privacy_set_size: 262_144,
            covers_pre_conditions: true,
            covers_post_conditions: true,
            release_weight_bps: 3_400,
        });
        let _ = state.record_attestation(PqInvariantAttestationRequest {
            attestation_id: "att-amm-k-a".to_string(),
            invariant_id: "inv-amm-k".to_string(),
            attester_id: "formal-lab-a".to_string(),
            attester_pq_key_commitment: "pq-key:formal-lab-a".to_string(),
            signed_manifest_commitment: "manifest:amm:k:a".to_string(),
            signature_commitment: "sig:amm:k:a".to_string(),
            proof_system: "zkvm+ml-dsa".to_string(),
            pq_security_bits: 256,
            privacy_set_size: 262_144,
            covers_pre_conditions: true,
            covers_post_conditions: true,
            release_weight_bps: 6_800,
        });
        let mut covered = BTreeSet::new();
        covered.insert("inv-token-supply".to_string());
        let _ = state.publish_operator_summary(OperatorSummaryRequest {
            summary_id: "summary-token-vault-0".to_string(),
            operator_id: "devnet-operator".to_string(),
            contract_id: "devnet-token-vault".to_string(),
            public_epoch: 0,
            covered_invariant_ids: covered.clone(),
            summary_commitment: "summary:token-vault:0".to_string(),
            release_risk_score_bps: 550,
            open_issue_count: 0,
        });
        let _ = state.open_release_gate(ReleaseGateRequest {
            gate_id: "gate-token-vault-devnet".to_string(),
            contract_id: "devnet-token-vault".to_string(),
            release_label: "devnet-token-vault-v1".to_string(),
            required_invariant_ids: covered,
            bytecode_commitment: "bytecode:token-vault:v1".to_string(),
            state_transition_commitment: "transition:token-vault:v1".to_string(),
            operator_summary_id: "summary-token-vault-0".to_string(),
        });
        state.recompute_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let mut batch_invariants = BTreeSet::new();
        batch_invariants.insert("inv-token-supply".to_string());
        batch_invariants.insert("inv-amm-k".to_string());
        let _ = state.open_low_fee_proof_batch(LowFeeProofBatchRequest {
            batch_id: "batch-devnet-contract-invariants-0".to_string(),
            sponsor_id: "fee-sponsor-devnet".to_string(),
            invariant_ids: batch_invariants,
            aggregate_proof_commitment: "aggregate-proof:devnet:0".to_string(),
            fee_asset_id: "piconero-devnet".to_string(),
            user_fee_bps: 6,
            rebate_bps: 8,
            privacy_set_size: 524_288,
        });
        let _ = state.mark_batch_proven("batch-devnet-contract-invariants-0");
        state
    }

    pub fn record_contract(&mut self, request: ContractRegistrationRequest) -> Result<String> {
        self.config.validate()?;
        self.require_id("contract_id", &request.contract_id)?;
        self.require_commitment("bytecode_commitment", &request.bytecode_commitment)?;
        self.require_commitment("state_commitment", &request.state_commitment)?;
        self.require_commitment(
            "deployer_pq_key_commitment",
            &request.deployer_pq_key_commitment,
        )?;
        self.require_commitment(
            "upgrade_authority_commitment",
            &request.upgrade_authority_commitment,
        )?;
        if self.contracts.contains_key(&request.contract_id) {
            self.reject(format!(
                "contract already registered: {}",
                request.contract_id
            ));
            return Err("contract already registered".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            self.reject("contract privacy set below floor".to_string());
            return Err("contract privacy set below floor".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            self.reject("contract pq security below floor".to_string());
            return Err("contract pq security below floor".to_string());
        }
        let id = request.contract_id.clone();
        let record = ContractRecord {
            contract_id: request.contract_id,
            domain: request.domain,
            bytecode_commitment: request.bytecode_commitment,
            state_commitment: request.state_commitment,
            deployer_pq_key_commitment: request.deployer_pq_key_commitment,
            upgrade_authority_commitment: request.upgrade_authority_commitment,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            metadata_commitment: request.metadata_commitment,
            invariant_ids: BTreeSet::new(),
            open_violation_ids: BTreeSet::new(),
            released_gate_ids: BTreeSet::new(),
            quarantined: false,
        };
        self.contracts.insert(id.clone(), record);
        self.counters.contracts_registered = self.counters.contracts_registered.saturating_add(1);
        self.recompute_roots();
        Ok(id)
    }

    pub fn register_invariant(&mut self, request: InvariantRegistrationRequest) -> Result<String> {
        self.require_id("invariant_id", &request.invariant_id)?;
        self.require_id("contract_id", &request.contract_id)?;
        self.require_commitment("formal_spec_commitment", &request.formal_spec_commitment)?;
        self.require_commitment(
            "witness_schema_commitment",
            &request.witness_schema_commitment,
        )?;
        self.require_commitment(
            "prover_circuit_commitment",
            &request.prover_circuit_commitment,
        )?;
        if self.invariants.contains_key(&request.invariant_id) {
            self.reject(format!(
                "invariant already registered: {}",
                request.invariant_id
            ));
            return Err("invariant already registered".to_string());
        }
        if !self.contracts.contains_key(&request.contract_id) {
            self.reject(format!(
                "unknown contract for invariant: {}",
                request.contract_id
            ));
            return Err("unknown contract".to_string());
        }
        if request.minimum_attesters == 0 {
            self.reject("minimum_attesters must be positive".to_string());
            return Err("minimum_attesters must be positive".to_string());
        }
        let id = request.invariant_id.clone();
        let contract_id = request.contract_id.clone();
        let record = InvariantRecord {
            invariant_id: request.invariant_id,
            contract_id: request.contract_id,
            class: request.class,
            title: request.title,
            formal_spec_commitment: request.formal_spec_commitment,
            witness_schema_commitment: request.witness_schema_commitment,
            prover_circuit_commitment: request.prover_circuit_commitment,
            transition_scope_commitment: request.transition_scope_commitment,
            minimum_attesters: request.minimum_attesters,
            release_blocker: request.release_blocker,
            status: InvariantStatus::Registered,
            condition_commitment_ids: BTreeSet::new(),
            attestation_ids: BTreeSet::new(),
            violation_ids: BTreeSet::new(),
        };
        self.invariants.insert(id.clone(), record);
        if let Some(contract) = self.contracts.get_mut(&contract_id) {
            contract.invariant_ids.insert(id.clone());
        }
        self.counters.invariants_registered = self.counters.invariants_registered.saturating_add(1);
        self.recompute_roots();
        Ok(id)
    }

    pub fn record_condition_commitment(
        &mut self,
        request: ConditionCommitmentRequest,
    ) -> Result<String> {
        self.require_id("condition_id", &request.condition_id)?;
        self.require_id("invariant_id", &request.invariant_id)?;
        self.require_commitment(
            "encrypted_predicate_commitment",
            &request.encrypted_predicate_commitment,
        )?;
        self.require_commitment(
            "nullifier_set_commitment",
            &request.nullifier_set_commitment,
        )?;
        if self
            .condition_commitments
            .contains_key(&request.condition_id)
        {
            self.reject(format!(
                "condition commitment already recorded: {}",
                request.condition_id
            ));
            return Err("condition commitment already recorded".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            self.reject("condition privacy set below floor".to_string());
            return Err("condition privacy set below floor".to_string());
        }
        let invariant = match self.invariants.get(&request.invariant_id) {
            Some(record) => record.clone(),
            None => {
                self.reject(format!(
                    "unknown invariant for condition: {}",
                    request.invariant_id
                ));
                return Err("unknown invariant".to_string());
            }
        };
        if self.config.require_pre_and_post_commitments {
            if request.confidential_pre_state_commitment.is_empty()
                || request.confidential_post_state_commitment.is_empty()
            {
                self.reject("pre and post commitments required".to_string());
                return Err("pre and post commitments required".to_string());
            }
        }
        let id = request.condition_id.clone();
        let record = ConditionCommitmentRecord {
            condition_id: request.condition_id,
            invariant_id: request.invariant_id.clone(),
            contract_id: invariant.contract_id,
            phase: request.phase,
            confidential_pre_state_commitment: request.confidential_pre_state_commitment,
            confidential_post_state_commitment: request.confidential_post_state_commitment,
            encrypted_predicate_commitment: request.encrypted_predicate_commitment,
            nullifier_set_commitment: request.nullifier_set_commitment,
            view_key_policy_commitment: request.view_key_policy_commitment,
            privacy_set_size: request.privacy_set_size,
            commitment_scheme: CONFIDENTIAL_CONDITION_COMMITMENT_SCHEME.to_string(),
        };
        self.condition_commitments.insert(id.clone(), record);
        if let Some(inv) = self.invariants.get_mut(&request.invariant_id) {
            inv.condition_commitment_ids.insert(id.clone());
        }
        self.counters.condition_commitments_recorded = self
            .counters
            .condition_commitments_recorded
            .saturating_add(1);
        self.recompute_roots();
        Ok(id)
    }

    pub fn record_attestation(&mut self, request: PqInvariantAttestationRequest) -> Result<String> {
        self.require_id("attestation_id", &request.attestation_id)?;
        self.require_id("invariant_id", &request.invariant_id)?;
        self.require_id("attester_id", &request.attester_id)?;
        self.require_commitment(
            "signed_manifest_commitment",
            &request.signed_manifest_commitment,
        )?;
        self.require_commitment("signature_commitment", &request.signature_commitment)?;
        if self.attestations.contains_key(&request.attestation_id) {
            self.reject(format!(
                "attestation already recorded: {}",
                request.attestation_id
            ));
            return Err("attestation already recorded".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            self.reject("attestation pq security below floor".to_string());
            return Err("attestation pq security below floor".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            self.reject("attestation privacy set below floor".to_string());
            return Err("attestation privacy set below floor".to_string());
        }
        if request.release_weight_bps > MAX_BPS {
            self.reject("release_weight_bps exceeds max".to_string());
            return Err("release_weight_bps exceeds max".to_string());
        }
        if self.config.require_pre_and_post_commitments
            && (!request.covers_pre_conditions || !request.covers_post_conditions)
        {
            self.reject("attestation must cover pre and post conditions".to_string());
            return Err("attestation must cover pre and post conditions".to_string());
        }
        let invariant = match self.invariants.get(&request.invariant_id) {
            Some(record) => record.clone(),
            None => {
                self.reject(format!(
                    "unknown invariant for attestation: {}",
                    request.invariant_id
                ));
                return Err("unknown invariant".to_string());
            }
        };
        let id = request.attestation_id.clone();
        let record = PqInvariantAttestationRecord {
            attestation_id: request.attestation_id,
            invariant_id: request.invariant_id.clone(),
            contract_id: invariant.contract_id.clone(),
            attester_id: request.attester_id,
            attester_pq_key_commitment: request.attester_pq_key_commitment,
            signed_manifest_commitment: request.signed_manifest_commitment,
            signature_commitment: request.signature_commitment,
            proof_system: request.proof_system,
            pq_security_bits: request.pq_security_bits,
            privacy_set_size: request.privacy_set_size,
            covers_pre_conditions: request.covers_pre_conditions,
            covers_post_conditions: request.covers_post_conditions,
            release_weight_bps: request.release_weight_bps,
            status: AttestationStatus::Accepted,
        };
        self.attestations.insert(id.clone(), record);
        if let Some(inv) = self.invariants.get_mut(&request.invariant_id) {
            inv.attestation_ids.insert(id.clone());
            if inv.attestation_ids.len() as u64 >= u64::from(inv.minimum_attesters) {
                inv.status = InvariantStatus::Attested;
            }
        }
        self.counters.attestations_recorded = self.counters.attestations_recorded.saturating_add(1);
        self.recompute_roots();
        Ok(id)
    }

    pub fn publish_operator_summary(&mut self, request: OperatorSummaryRequest) -> Result<String> {
        self.require_id("summary_id", &request.summary_id)?;
        self.require_id("operator_id", &request.operator_id)?;
        self.require_id("contract_id", &request.contract_id)?;
        self.require_commitment("summary_commitment", &request.summary_commitment)?;
        if self.operator_summaries.contains_key(&request.summary_id) {
            self.reject(format!(
                "operator summary already published: {}",
                request.summary_id
            ));
            return Err("operator summary already published".to_string());
        }
        if !self.contracts.contains_key(&request.contract_id) {
            self.reject(format!(
                "unknown contract for operator summary: {}",
                request.contract_id
            ));
            return Err("unknown contract".to_string());
        }
        if request.release_risk_score_bps > MAX_BPS {
            self.reject("release_risk_score_bps exceeds max".to_string());
            return Err("release_risk_score_bps exceeds max".to_string());
        }
        for invariant_id in &request.covered_invariant_ids {
            if !self.invariant_belongs_to_contract(invariant_id, &request.contract_id) {
                self.reject(format!(
                    "operator summary invariant mismatch: {}",
                    invariant_id
                ));
                return Err("operator summary invariant mismatch".to_string());
            }
        }
        let id = request.summary_id.clone();
        let record = OperatorSummaryRecord {
            summary_id: request.summary_id,
            operator_id: request.operator_id,
            contract_id: request.contract_id,
            public_epoch: request.public_epoch,
            covered_invariant_ids: request.covered_invariant_ids,
            summary_commitment: request.summary_commitment,
            release_risk_score_bps: request.release_risk_score_bps,
            open_issue_count: request.open_issue_count,
        };
        self.operator_summaries.insert(id.clone(), record);
        self.counters.operator_summaries_published =
            self.counters.operator_summaries_published.saturating_add(1);
        self.recompute_roots();
        Ok(id)
    }

    pub fn open_release_gate(&mut self, request: ReleaseGateRequest) -> Result<String> {
        self.require_id("gate_id", &request.gate_id)?;
        self.require_id("contract_id", &request.contract_id)?;
        self.require_commitment("bytecode_commitment", &request.bytecode_commitment)?;
        self.require_commitment(
            "state_transition_commitment",
            &request.state_transition_commitment,
        )?;
        if self.release_gates.contains_key(&request.gate_id) {
            self.reject(format!("release gate already opened: {}", request.gate_id));
            return Err("release gate already opened".to_string());
        }
        let contract = match self.contracts.get(&request.contract_id) {
            Some(record) => record.clone(),
            None => {
                self.reject(format!(
                    "unknown contract for release gate: {}",
                    request.contract_id
                ));
                return Err("unknown contract".to_string());
            }
        };
        if contract.quarantined {
            self.reject(format!("contract quarantined: {}", request.contract_id));
            return Err("contract quarantined".to_string());
        }
        if self.config.require_operator_summary_for_release
            && !self
                .operator_summaries
                .contains_key(&request.operator_summary_id)
        {
            self.reject("release gate requires operator summary".to_string());
            return Err("release gate requires operator summary".to_string());
        }
        let mut blocker_count = 0_u64;
        let mut quorum_weight = 0_u64;
        for invariant_id in &request.required_invariant_ids {
            let invariant = match self.invariants.get(invariant_id) {
                Some(record) => record,
                None => {
                    self.reject(format!(
                        "unknown invariant for release gate: {}",
                        invariant_id
                    ));
                    return Err("unknown invariant".to_string());
                }
            };
            if invariant.contract_id != request.contract_id {
                self.reject(format!("invariant contract mismatch: {}", invariant_id));
                return Err("invariant contract mismatch".to_string());
            }
            if invariant.release_blocker && !invariant.status.release_eligible() {
                blocker_count = blocker_count.saturating_add(1);
            }
            quorum_weight =
                quorum_weight.saturating_add(self.accepted_attestation_weight(invariant_id));
        }
        let open_violation_count = contract.open_violation_ids.len() as u64;
        let status = if open_violation_count > 0 {
            ReleaseGateStatus::Quarantined
        } else if blocker_count > 0 {
            ReleaseGateStatus::Blocked
        } else if quorum_weight >= self.config.strong_release_quorum_bps {
            ReleaseGateStatus::Ready
        } else if quorum_weight >= self.config.release_quorum_bps {
            ReleaseGateStatus::Candidate
        } else {
            ReleaseGateStatus::AwaitingAttestations
        };
        let id = request.gate_id.clone();
        let record = ReleaseGateRecord {
            gate_id: request.gate_id,
            contract_id: request.contract_id.clone(),
            release_label: request.release_label,
            required_invariant_ids: request.required_invariant_ids,
            bytecode_commitment: request.bytecode_commitment,
            state_transition_commitment: request.state_transition_commitment,
            operator_summary_id: request.operator_summary_id,
            quorum_bps: quorum_weight.min(MAX_BPS),
            blocker_count,
            open_violation_count,
            status,
        };
        self.release_gates.insert(id.clone(), record);
        if let Some(contract_record) = self.contracts.get_mut(&request.contract_id) {
            if status == ReleaseGateStatus::Ready {
                contract_record.released_gate_ids.insert(id.clone());
                self.counters.release_gates_ready =
                    self.counters.release_gates_ready.saturating_add(1);
            } else if matches!(
                status,
                ReleaseGateStatus::Blocked | ReleaseGateStatus::Quarantined
            ) {
                self.counters.release_gates_blocked =
                    self.counters.release_gates_blocked.saturating_add(1);
            }
        }
        self.counters.release_gates_opened = self.counters.release_gates_opened.saturating_add(1);
        self.recompute_roots();
        Ok(id)
    }

    pub fn report_violation(&mut self, request: ViolationReportRequest) -> Result<String> {
        self.require_id("violation_id", &request.violation_id)?;
        self.require_id("invariant_id", &request.invariant_id)?;
        self.require_id("reporter_id", &request.reporter_id)?;
        self.require_commitment(
            "sealed_counterexample_commitment",
            &request.sealed_counterexample_commitment,
        )?;
        if self.violations.contains_key(&request.violation_id) {
            self.reject(format!(
                "violation already recorded: {}",
                request.violation_id
            ));
            return Err("violation already recorded".to_string());
        }
        let invariant = match self.invariants.get(&request.invariant_id) {
            Some(record) => record.clone(),
            None => {
                self.reject(format!(
                    "unknown invariant for violation: {}",
                    request.invariant_id
                ));
                return Err("unknown invariant".to_string());
            }
        };
        let contract_id = invariant.contract_id.clone();
        let status = if request.quarantine_contract
            || matches!(
                request.severity,
                ViolationSeverity::High | ViolationSeverity::Critical
            ) {
            ViolationStatus::Quarantined
        } else {
            ViolationStatus::Reported
        };
        let id = request.violation_id.clone();
        let record = ViolationRecord {
            violation_id: request.violation_id,
            invariant_id: request.invariant_id.clone(),
            contract_id: contract_id.clone(),
            reporter_id: request.reporter_id,
            severity: request.severity,
            sealed_counterexample_commitment: request.sealed_counterexample_commitment,
            impacted_state_commitment: request.impacted_state_commitment,
            mitigation_commitment: request.mitigation_commitment,
            status,
        };
        self.violations.insert(id.clone(), record);
        if let Some(inv) = self.invariants.get_mut(&request.invariant_id) {
            inv.violation_ids.insert(id.clone());
            if status == ViolationStatus::Quarantined {
                inv.status = InvariantStatus::Quarantined;
            }
        }
        if let Some(contract) = self.contracts.get_mut(&contract_id) {
            contract.open_violation_ids.insert(id.clone());
            if status == ViolationStatus::Quarantined
                || contract.open_violation_ids.len() > self.config.max_open_violations_per_contract
            {
                contract.quarantined = true;
                self.quarantined_contracts.insert(contract_id);
                self.counters.violations_quarantined =
                    self.counters.violations_quarantined.saturating_add(1);
            }
        }
        self.block_release_gates_for_invariant(&request.invariant_id);
        self.counters.violations_reported = self.counters.violations_reported.saturating_add(1);
        self.recompute_roots();
        Ok(id)
    }

    pub fn clear_violation(
        &mut self,
        violation_id: &str,
        mitigation_commitment: &str,
    ) -> Result<()> {
        self.require_id("violation_id", violation_id)?;
        self.require_commitment("mitigation_commitment", mitigation_commitment)?;
        let record = match self.violations.get_mut(violation_id) {
            Some(record) => record,
            None => {
                self.reject(format!("unknown violation: {}", violation_id));
                return Err("unknown violation".to_string());
            }
        };
        record.status = ViolationStatus::Cleared;
        record.mitigation_commitment = mitigation_commitment.to_string();
        let contract_id = record.contract_id.clone();
        let invariant_id = record.invariant_id.clone();
        if let Some(contract) = self.contracts.get_mut(&contract_id) {
            contract.open_violation_ids.remove(violation_id);
            if contract.open_violation_ids.is_empty() {
                contract.quarantined = false;
                self.quarantined_contracts.remove(&contract_id);
            }
        }
        if let Some(invariant) = self.invariants.get_mut(&invariant_id) {
            if invariant.status == InvariantStatus::Quarantined {
                invariant.status = InvariantStatus::Attested;
            }
        }
        self.counters.violations_cleared = self.counters.violations_cleared.saturating_add(1);
        self.recompute_release_gates_for_contract(&contract_id);
        self.recompute_roots();
        Ok(())
    }

    pub fn open_low_fee_proof_batch(&mut self, request: LowFeeProofBatchRequest) -> Result<String> {
        self.require_id("batch_id", &request.batch_id)?;
        self.require_id("sponsor_id", &request.sponsor_id)?;
        self.require_commitment(
            "aggregate_proof_commitment",
            &request.aggregate_proof_commitment,
        )?;
        if self.proof_batches.contains_key(&request.batch_id) {
            self.reject(format!("proof batch already opened: {}", request.batch_id));
            return Err("proof batch already opened".to_string());
        }
        if request.invariant_ids.is_empty() {
            self.reject("proof batch must include invariants".to_string());
            return Err("proof batch must include invariants".to_string());
        }
        if request.invariant_ids.len() > self.config.max_batch_items {
            self.reject("proof batch exceeds max_batch_items".to_string());
            return Err("proof batch exceeds max_batch_items".to_string());
        }
        if request.user_fee_bps > self.config.max_user_fee_bps {
            self.reject("proof batch user fee exceeds configured cap".to_string());
            return Err("proof batch user fee exceeds configured cap".to_string());
        }
        if request.rebate_bps < self.config.target_batch_rebate_bps {
            self.reject("proof batch rebate below target".to_string());
            return Err("proof batch rebate below target".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            self.reject("proof batch privacy set below floor".to_string());
            return Err("proof batch privacy set below floor".to_string());
        }
        for invariant_id in &request.invariant_ids {
            if !self.invariants.contains_key(invariant_id) {
                self.reject(format!(
                    "unknown invariant for proof batch: {}",
                    invariant_id
                ));
                return Err("unknown invariant".to_string());
            }
        }
        let id = request.batch_id.clone();
        let record = LowFeeProofBatchRecord {
            batch_id: request.batch_id,
            sponsor_id: request.sponsor_id,
            invariant_ids: request.invariant_ids,
            aggregate_proof_commitment: request.aggregate_proof_commitment,
            fee_asset_id: request.fee_asset_id,
            user_fee_bps: request.user_fee_bps,
            rebate_bps: request.rebate_bps,
            privacy_set_size: request.privacy_set_size,
            status: BatchStatus::Open,
        };
        self.proof_batches.insert(id.clone(), record);
        self.counters.proof_batches_opened = self.counters.proof_batches_opened.saturating_add(1);
        self.recompute_roots();
        Ok(id)
    }

    pub fn mark_batch_proven(&mut self, batch_id: &str) -> Result<()> {
        self.require_id("batch_id", batch_id)?;
        let batch = match self.proof_batches.get_mut(batch_id) {
            Some(record) => record,
            None => {
                self.reject(format!("unknown proof batch: {}", batch_id));
                return Err("unknown proof batch".to_string());
            }
        };
        batch.status = BatchStatus::Proven;
        self.counters.proof_batches_proven = self.counters.proof_batches_proven.saturating_add(1);
        self.recompute_roots();
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_attestation_suite": PQ_ATTESTATION_SUITE,
            "condition_commitment_scheme": CONFIDENTIAL_CONDITION_COMMITMENT_SCHEME,
            "formal_invariant_manifest_scheme": FORMAL_INVARIANT_MANIFEST_SCHEME,
            "release_gate_scheme": RELEASE_GATE_SCHEME,
            "violation_quarantine_scheme": VIOLATION_QUARANTINE_SCHEME,
            "low_fee_batch_scheme": LOW_FEE_BATCH_SCHEME,
            "operator_public_summary_scheme": OPERATOR_PUBLIC_SUMMARY_SCHEME,
            "config": self.config,
            "counters": self.counters,
            "roots": self.roots,
            "contracts": self.contracts.values().map(ContractRecord::public_record).collect::<Vec<_>>(),
            "invariants": self.invariants.values().map(InvariantRecord::public_record).collect::<Vec<_>>(),
            "condition_commitments": self.condition_commitments.values().map(ConditionCommitmentRecord::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(PqInvariantAttestationRecord::public_record).collect::<Vec<_>>(),
            "release_gates": self.release_gates.values().map(ReleaseGateRecord::public_record).collect::<Vec<_>>(),
            "violations": self.violations.values().map(ViolationRecord::public_record).collect::<Vec<_>>(),
            "proof_batches": self.proof_batches.values().map(LowFeeProofBatchRecord::public_record).collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().map(OperatorSummaryRecord::public_record).collect::<Vec<_>>(),
            "quarantined_contracts": self.quarantined_contracts.iter().cloned().collect::<Vec<_>>()
        })
    }

    pub fn state_root(&self) -> String {
        stable_hash_hex(&self.public_record())
    }

    pub fn recompute_roots(&mut self) {
        self.roots.contracts_root = map_root("contracts", &self.contracts);
        self.roots.invariants_root = map_root("invariants", &self.invariants);
        self.roots.condition_commitments_root =
            map_root("condition_commitments", &self.condition_commitments);
        self.roots.attestations_root = map_root("attestations", &self.attestations);
        self.roots.release_gates_root = map_root("release_gates", &self.release_gates);
        self.roots.violations_root = map_root("violations", &self.violations);
        self.roots.proof_batches_root = map_root("proof_batches", &self.proof_batches);
        self.roots.operator_summaries_root =
            map_root("operator_summaries", &self.operator_summaries);
        self.roots.quarantined_contracts_root =
            set_root("quarantined_contracts", &self.quarantined_contracts);
        let state_view = json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config,
            "counters": self.counters,
            "contracts_root": self.roots.contracts_root,
            "invariants_root": self.roots.invariants_root,
            "condition_commitments_root": self.roots.condition_commitments_root,
            "attestations_root": self.roots.attestations_root,
            "release_gates_root": self.roots.release_gates_root,
            "violations_root": self.roots.violations_root,
            "proof_batches_root": self.roots.proof_batches_root,
            "operator_summaries_root": self.roots.operator_summaries_root,
            "quarantined_contracts_root": self.roots.quarantined_contracts_root
        });
        self.roots.state_root = stable_hash_hex(&state_view);
    }

    pub fn invariant_attester_count(&self, invariant_id: &str) -> u64 {
        match self.invariants.get(invariant_id) {
            Some(invariant) => invariant
                .attestation_ids
                .iter()
                .filter(|id| {
                    self.attestations
                        .get(*id)
                        .map(|a| a.status == AttestationStatus::Accepted)
                        .unwrap_or(false)
                })
                .count() as u64,
            None => 0,
        }
    }

    pub fn accepted_attestation_weight(&self, invariant_id: &str) -> u64 {
        let mut weight = 0_u64;
        if let Some(invariant) = self.invariants.get(invariant_id) {
            for attestation_id in &invariant.attestation_ids {
                if let Some(attestation) = self.attestations.get(attestation_id) {
                    if attestation.status == AttestationStatus::Accepted {
                        weight = weight.saturating_add(attestation.release_weight_bps);
                    }
                }
            }
        }
        weight.min(MAX_BPS)
    }

    pub fn operator_release_summary(&self, contract_id: &str) -> Value {
        let mut invariant_count = 0_u64;
        let mut attested_count = 0_u64;
        let mut release_blocker_count = 0_u64;
        let mut open_violation_count = 0_u64;
        let mut severity_score = 0_u64;
        if let Some(contract) = self.contracts.get(contract_id) {
            invariant_count = contract.invariant_ids.len() as u64;
            open_violation_count = contract.open_violation_ids.len() as u64;
            for invariant_id in &contract.invariant_ids {
                if let Some(invariant) = self.invariants.get(invariant_id) {
                    if invariant.status.release_eligible() {
                        attested_count = attested_count.saturating_add(1);
                    }
                    if invariant.release_blocker {
                        release_blocker_count = release_blocker_count.saturating_add(1);
                    }
                    for violation_id in &invariant.violation_ids {
                        if let Some(violation) = self.violations.get(violation_id) {
                            if matches!(
                                violation.status,
                                ViolationStatus::Reported | ViolationStatus::Quarantined
                            ) {
                                severity_score =
                                    severity_score.saturating_add(violation.severity.score());
                            }
                        }
                    }
                }
            }
        }
        json!({
            "contract_id": contract_id,
            "invariant_count": invariant_count,
            "attested_count": attested_count,
            "release_blocker_count": release_blocker_count,
            "open_violation_count": open_violation_count,
            "severity_score": severity_score,
            "quarantined": self.quarantined_contracts.contains(contract_id),
            "state_root": self.roots.state_root
        })
    }

    fn require_id(&mut self, name: &str, value: &str) -> Result<()> {
        if value.is_empty() {
            self.reject(format!("{} must not be empty", name));
            return Err(format!("{} must not be empty", name));
        }
        if value.len() > 192 {
            self.reject(format!("{} too long", name));
            return Err(format!("{} too long", name));
        }
        Ok(())
    }

    fn require_commitment(&mut self, name: &str, value: &str) -> Result<()> {
        if value.is_empty() {
            self.reject(format!("{} must not be empty", name));
            return Err(format!("{} must not be empty", name));
        }
        if value.len() > 512 {
            self.reject(format!("{} too long", name));
            return Err(format!("{} too long", name));
        }
        Ok(())
    }

    fn reject(&mut self, reason: String) {
        self.counters.rejected_requests = self.counters.rejected_requests.saturating_add(1);
        self.rejected_request_log.push(reason);
        if self.rejected_request_log.len() > 256 {
            let _ = self.rejected_request_log.remove(0);
        }
    }

    fn invariant_belongs_to_contract(&self, invariant_id: &str, contract_id: &str) -> bool {
        self.invariants
            .get(invariant_id)
            .map(|record| record.contract_id == contract_id)
            .unwrap_or(false)
    }

    fn block_release_gates_for_invariant(&mut self, invariant_id: &str) {
        let gate_ids = self
            .release_gates
            .iter()
            .filter(|(_, gate)| gate.required_invariant_ids.contains(invariant_id))
            .map(|(gate_id, _)| gate_id.clone())
            .collect::<Vec<_>>();
        for gate_id in gate_ids {
            if let Some(gate) = self.release_gates.get_mut(&gate_id) {
                gate.status = ReleaseGateStatus::Quarantined;
                gate.open_violation_count = gate.open_violation_count.saturating_add(1);
            }
        }
    }

    fn recompute_release_gates_for_contract(&mut self, contract_id: &str) {
        let gate_ids = self
            .release_gates
            .iter()
            .filter(|(_, gate)| gate.contract_id == contract_id)
            .map(|(gate_id, _)| gate_id.clone())
            .collect::<Vec<_>>();
        let open_violation_count = self
            .contracts
            .get(contract_id)
            .map(|contract| contract.open_violation_ids.len() as u64)
            .unwrap_or(0);
        for gate_id in gate_ids {
            let required_ids = self
                .release_gates
                .get(&gate_id)
                .map(|gate| gate.required_invariant_ids.clone())
                .unwrap_or_default();
            let mut blocker_count = 0_u64;
            let mut quorum_weight = 0_u64;
            for invariant_id in &required_ids {
                if let Some(invariant) = self.invariants.get(invariant_id) {
                    if invariant.release_blocker && !invariant.status.release_eligible() {
                        blocker_count = blocker_count.saturating_add(1);
                    }
                    quorum_weight = quorum_weight
                        .saturating_add(self.accepted_attestation_weight(invariant_id));
                }
            }
            if let Some(gate) = self.release_gates.get_mut(&gate_id) {
                gate.blocker_count = blocker_count;
                gate.open_violation_count = open_violation_count;
                gate.quorum_bps = quorum_weight.min(MAX_BPS);
                gate.status = if open_violation_count > 0 {
                    ReleaseGateStatus::Quarantined
                } else if blocker_count > 0 {
                    ReleaseGateStatus::Blocked
                } else if gate.quorum_bps >= self.config.strong_release_quorum_bps {
                    ReleaseGateStatus::Ready
                } else if gate.quorum_bps >= self.config.release_quorum_bps {
                    ReleaseGateStatus::Candidate
                } else {
                    ReleaseGateStatus::AwaitingAttestations
                };
            }
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record() -> Value {
    demo().public_record()
}

pub fn state_root() -> String {
    demo().state_root()
}

fn map_root<T: Serialize>(label: &str, map: &BTreeMap<String, T>) -> String {
    let entries = map
        .iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    stable_hash_hex(&json!({"label": label, "entries": entries}))
}

fn set_root(label: &str, set: &BTreeSet<String>) -> String {
    let entries = set.iter().cloned().collect::<Vec<_>>();
    stable_hash_hex(&json!({"label": label, "entries": entries}))
}

fn stable_hash_hex(value: &Value) -> String {
    let canonical = canonical_json(value);
    let mut h0 = 0xcbf29ce484222325_u64;
    let mut h1 = 0x9e3779b97f4a7c15_u64;
    for byte in canonical.as_bytes() {
        h0 ^= u64::from(*byte);
        h0 = h0.wrapping_mul(0x100000001b3);
        h1 ^= h0.rotate_left(13).wrapping_add(u64::from(*byte));
        h1 = h1.wrapping_mul(0xff51afd7ed558ccd);
    }
    format!("{:016x}{:016x}", h0, h1)
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(v) => {
            if *v {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(n) => n.to_string(),
        Value::String(s) => canonical_string(s),
        Value::Array(items) => {
            let body = items
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{}]", body)
        }
        Value::Object(map) => {
            let mut entries = map
                .iter()
                .map(|(key, value)| format!("{}:{}", canonical_string(key), canonical_json(value)))
                .collect::<Vec<_>>();
            entries.sort();
            format!("{{{}}}", entries.join(","))
        }
    }
}

fn canonical_string(input: &str) -> String {
    let mut out = String::new();
    out.push('"');
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
