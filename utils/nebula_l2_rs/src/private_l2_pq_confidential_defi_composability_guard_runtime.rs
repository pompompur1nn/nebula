use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_COMPOSABILITY_GUARD_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-defi-composability-guard-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_COMPOSABILITY_GUARD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-defi-composability-guard-v1";
pub const POLICY_SCHEME: &str = "pq-confidential-defi-composability-policy-root-v1";
pub const ROUTE_MANIFEST_SCHEME: &str = "pq-confidential-defi-route-manifest-root-v1";
pub const INVARIANT_ATTESTATION_SCHEME: &str = "pq-confidential-defi-invariant-attestation-root-v1";
pub const ORACLE_RISK_FENCE_SCHEME: &str = "pq-confidential-defi-oracle-risk-fence-root-v1";
pub const LIQUIDITY_ISOLATION_SCHEME: &str =
    "pq-confidential-defi-liquidity-isolation-window-root-v1";
pub const CALL_APPROVAL_SCHEME: &str = "pq-confidential-defi-cross-contract-call-approval-root-v1";
pub const FEE_SPONSOR_SCHEME: &str = "pq-confidential-defi-fee-sponsor-constraint-root-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "pq-confidential-defi-privacy-nullifier-fence-root-v1";
pub const SETTLEMENT_BATCH_SCHEME: &str = "pq-confidential-defi-guard-settlement-batch-root-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "pq-confidential-defi-guard-slashing-evidence-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "asset:piconero";
pub const DEVNET_SETTLEMENT_ASSET_ID: &str = "asset:xusd-devnet";
pub const DEVNET_HEIGHT: u64 = 2_468_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_ROUTE_LEGS: usize = 32;
pub const DEFAULT_MAX_CALLS_PER_ROUTE: usize = 48;
pub const DEFAULT_MAX_POLICIES: usize = 262_144;
pub const DEFAULT_MAX_ROUTE_MANIFESTS: usize = 4_194_304;
pub const DEFAULT_MAX_INVARIANT_ATTESTATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_ORACLE_FENCES: usize = 2_097_152;
pub const DEFAULT_MAX_ISOLATION_WINDOWS: usize = 2_097_152;
pub const DEFAULT_MAX_CALL_APPROVALS: usize = 8_388_608;
pub const DEFAULT_MAX_FEE_SPONSOR_CONSTRAINTS: usize = 2_097_152;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 16_777_216;
pub const DEFAULT_MAX_SETTLEMENT_BATCHES: usize = 4_194_304;
pub const DEFAULT_MAX_SLASHING_EVIDENCE: usize = 1_048_576;
pub const DEFAULT_ROUTE_TTL_BLOCKS: u64 = 40;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_ORACLE_FENCE_TTL_BLOCKS: u64 = 18;
pub const DEFAULT_ISOLATION_WINDOW_BLOCKS: u64 = 12;
pub const DEFAULT_CALL_APPROVAL_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_FEE_SPONSOR_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_PRIVACY_FENCE_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_SETTLEMENT_FINALITY_BLOCKS: u64 = 10;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 15;
pub const DEFAULT_MAX_PROTOCOL_FEE_BPS: u64 = 9;
pub const DEFAULT_MAX_SPONSOR_REBATE_BPS: u64 = 6;
pub const DEFAULT_MAX_ORACLE_DRIFT_BPS: u64 = 75;
pub const DEFAULT_MAX_LEVERAGE_BPS: u64 = 300_000;
pub const DEFAULT_MIN_LIQUIDITY_COVER_BPS: u64 = 10_500;
pub const DEFAULT_MAX_SLIPPAGE_BPS: u64 = 35;
pub const DEFAULT_MAX_SLASH_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyKind {
    VaultComposable,
    AmmSwap,
    LendingBorrow,
    PerpsMargin,
    StableSwap,
    LiquidationBackstop,
    OracleRefresh,
    FeeSponsoredRoute,
    CrossContractAtomic,
    EmergencyExit,
}

impl PolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VaultComposable => "vault_composable",
            Self::AmmSwap => "amm_swap",
            Self::LendingBorrow => "lending_borrow",
            Self::PerpsMargin => "perps_margin",
            Self::StableSwap => "stable_swap",
            Self::LiquidationBackstop => "liquidation_backstop",
            Self::OracleRefresh => "oracle_refresh",
            Self::FeeSponsoredRoute => "fee_sponsored_route",
            Self::CrossContractAtomic => "cross_contract_atomic",
            Self::EmergencyExit => "emergency_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardStatus {
    Draft,
    Active,
    ObserveOnly,
    Paused,
    Frozen,
    Settled,
    Rejected,
    Slashed,
}

impl GuardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::ObserveOnly => "observe_only",
            Self::Paused => "paused",
            Self::Frozen => "frozen",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }

    pub fn admits_routes(self) -> bool {
        matches!(self, Self::Active | Self::ObserveOnly)
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Rejected | Self::Slashed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractDomain {
    Vault,
    Amm,
    Lending,
    Perps,
    Oracle,
    Paymaster,
    Liquidation,
    Insurance,
    Bridge,
    Treasury,
    Governance,
}

impl ContractDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::Amm => "amm",
            Self::Lending => "lending",
            Self::Perps => "perps",
            Self::Oracle => "oracle",
            Self::Paymaster => "paymaster",
            Self::Liquidation => "liquidation",
            Self::Insurance => "insurance",
            Self::Bridge => "bridge",
            Self::Treasury => "treasury",
            Self::Governance => "governance",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    VaultDepositSwap,
    VaultRebalance,
    AmmPrivateSwap,
    LendingLoop,
    LendingRepay,
    PerpsOpen,
    PerpsHedge,
    LiquidationAuction,
    OracleRefresh,
    EmergencyUnwind,
}

impl RouteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VaultDepositSwap => "vault_deposit_swap",
            Self::VaultRebalance => "vault_rebalance",
            Self::AmmPrivateSwap => "amm_private_swap",
            Self::LendingLoop => "lending_loop",
            Self::LendingRepay => "lending_repay",
            Self::PerpsOpen => "perps_open",
            Self::PerpsHedge => "perps_hedge",
            Self::LiquidationAuction => "liquidation_auction",
            Self::OracleRefresh => "oracle_refresh",
            Self::EmergencyUnwind => "emergency_unwind",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantKind {
    Solvency,
    Conservation,
    Collateralization,
    OracleFreshness,
    LiquidityCoverage,
    FeeBound,
    SlippageBound,
    PrivacySet,
    NullifierUniqueness,
    CallGraphAllowed,
}

impl InvariantKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Solvency => "solvency",
            Self::Conservation => "conservation",
            Self::Collateralization => "collateralization",
            Self::OracleFreshness => "oracle_freshness",
            Self::LiquidityCoverage => "liquidity_coverage",
            Self::FeeBound => "fee_bound",
            Self::SlippageBound => "slippage_bound",
            Self::PrivacySet => "privacy_set",
            Self::NullifierUniqueness => "nullifier_uniqueness",
            Self::CallGraphAllowed => "call_graph_allowed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementDecision {
    Accepted,
    AcceptedWithIsolation,
    Rejected,
    FrozenForReview,
    Slashed,
}

impl SettlementDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::AcceptedWithIsolation => "accepted_with_isolation",
            Self::Rejected => "rejected",
            Self::FrozenForReview => "frozen_for_review",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    InvalidPqAttestation,
    BrokenInvariant,
    OracleDriftExceeded,
    LiquidityLeakage,
    UnauthorizedCall,
    FeeSponsorOverdraw,
    PrivacyFenceViolation,
    NullifierReplay,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPqAttestation => "invalid_pq_attestation",
            Self::BrokenInvariant => "broken_invariant",
            Self::OracleDriftExceeded => "oracle_drift_exceeded",
            Self::LiquidityLeakage => "liquidity_leakage",
            Self::UnauthorizedCall => "unauthorized_call",
            Self::FeeSponsorOverdraw => "fee_sponsor_overdraw",
            Self::PrivacyFenceViolation => "privacy_fence_violation",
            Self::NullifierReplay => "nullifier_replay",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub settlement_asset_id: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_route_legs: usize,
    pub max_calls_per_route: usize,
    pub max_policies: usize,
    pub max_route_manifests: usize,
    pub max_invariant_attestations: usize,
    pub max_oracle_fences: usize,
    pub max_isolation_windows: usize,
    pub max_call_approvals: usize,
    pub max_fee_sponsor_constraints: usize,
    pub max_privacy_fences: usize,
    pub max_settlement_batches: usize,
    pub max_slashing_evidence: usize,
    pub route_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub oracle_fence_ttl_blocks: u64,
    pub isolation_window_blocks: u64,
    pub call_approval_ttl_blocks: u64,
    pub fee_sponsor_ttl_blocks: u64,
    pub privacy_fence_ttl_blocks: u64,
    pub settlement_finality_blocks: u64,
    pub max_user_fee_bps: u64,
    pub max_protocol_fee_bps: u64,
    pub max_sponsor_rebate_bps: u64,
    pub max_oracle_drift_bps: u64,
    pub max_leverage_bps: u64,
    pub min_liquidity_cover_bps: u64,
    pub max_slippage_bps: u64,
    pub max_slash_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            settlement_asset_id: DEVNET_SETTLEMENT_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_route_legs: DEFAULT_MAX_ROUTE_LEGS,
            max_calls_per_route: DEFAULT_MAX_CALLS_PER_ROUTE,
            max_policies: DEFAULT_MAX_POLICIES,
            max_route_manifests: DEFAULT_MAX_ROUTE_MANIFESTS,
            max_invariant_attestations: DEFAULT_MAX_INVARIANT_ATTESTATIONS,
            max_oracle_fences: DEFAULT_MAX_ORACLE_FENCES,
            max_isolation_windows: DEFAULT_MAX_ISOLATION_WINDOWS,
            max_call_approvals: DEFAULT_MAX_CALL_APPROVALS,
            max_fee_sponsor_constraints: DEFAULT_MAX_FEE_SPONSOR_CONSTRAINTS,
            max_privacy_fences: DEFAULT_MAX_PRIVACY_FENCES,
            max_settlement_batches: DEFAULT_MAX_SETTLEMENT_BATCHES,
            max_slashing_evidence: DEFAULT_MAX_SLASHING_EVIDENCE,
            route_ttl_blocks: DEFAULT_ROUTE_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            oracle_fence_ttl_blocks: DEFAULT_ORACLE_FENCE_TTL_BLOCKS,
            isolation_window_blocks: DEFAULT_ISOLATION_WINDOW_BLOCKS,
            call_approval_ttl_blocks: DEFAULT_CALL_APPROVAL_TTL_BLOCKS,
            fee_sponsor_ttl_blocks: DEFAULT_FEE_SPONSOR_TTL_BLOCKS,
            privacy_fence_ttl_blocks: DEFAULT_PRIVACY_FENCE_TTL_BLOCKS,
            settlement_finality_blocks: DEFAULT_SETTLEMENT_FINALITY_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_protocol_fee_bps: DEFAULT_MAX_PROTOCOL_FEE_BPS,
            max_sponsor_rebate_bps: DEFAULT_MAX_SPONSOR_REBATE_BPS,
            max_oracle_drift_bps: DEFAULT_MAX_ORACLE_DRIFT_BPS,
            max_leverage_bps: DEFAULT_MAX_LEVERAGE_BPS,
            min_liquidity_cover_bps: DEFAULT_MIN_LIQUIDITY_COVER_BPS,
            max_slippage_bps: DEFAULT_MAX_SLIPPAGE_BPS,
            max_slash_bps: DEFAULT_MAX_SLASH_BPS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "settlement_asset_id": self.settlement_asset_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_route_legs": self.max_route_legs,
            "max_calls_per_route": self.max_calls_per_route,
            "max_policies": self.max_policies,
            "max_route_manifests": self.max_route_manifests,
            "max_invariant_attestations": self.max_invariant_attestations,
            "max_oracle_fences": self.max_oracle_fences,
            "max_isolation_windows": self.max_isolation_windows,
            "max_call_approvals": self.max_call_approvals,
            "max_fee_sponsor_constraints": self.max_fee_sponsor_constraints,
            "max_privacy_fences": self.max_privacy_fences,
            "max_settlement_batches": self.max_settlement_batches,
            "max_slashing_evidence": self.max_slashing_evidence,
            "route_ttl_blocks": self.route_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "oracle_fence_ttl_blocks": self.oracle_fence_ttl_blocks,
            "isolation_window_blocks": self.isolation_window_blocks,
            "call_approval_ttl_blocks": self.call_approval_ttl_blocks,
            "fee_sponsor_ttl_blocks": self.fee_sponsor_ttl_blocks,
            "privacy_fence_ttl_blocks": self.privacy_fence_ttl_blocks,
            "settlement_finality_blocks": self.settlement_finality_blocks,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_protocol_fee_bps": self.max_protocol_fee_bps,
            "max_sponsor_rebate_bps": self.max_sponsor_rebate_bps,
            "max_oracle_drift_bps": self.max_oracle_drift_bps,
            "max_leverage_bps": self.max_leverage_bps,
            "min_liquidity_cover_bps": self.min_liquidity_cover_bps,
            "max_slippage_bps": self.max_slippage_bps,
            "max_slash_bps": self.max_slash_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub policy_count: u64,
    pub route_manifest_count: u64,
    pub invariant_attestation_count: u64,
    pub oracle_fence_count: u64,
    pub isolation_window_count: u64,
    pub call_approval_count: u64,
    pub fee_sponsor_constraint_count: u64,
    pub privacy_fence_count: u64,
    pub settlement_batch_count: u64,
    pub slashing_evidence_count: u64,
    pub accepted_route_count: u64,
    pub rejected_route_count: u64,
    pub slashed_route_count: u64,
    pub latest_height: u64,
    pub latest_sequence: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_count": self.policy_count,
            "route_manifest_count": self.route_manifest_count,
            "invariant_attestation_count": self.invariant_attestation_count,
            "oracle_fence_count": self.oracle_fence_count,
            "isolation_window_count": self.isolation_window_count,
            "call_approval_count": self.call_approval_count,
            "fee_sponsor_constraint_count": self.fee_sponsor_constraint_count,
            "privacy_fence_count": self.privacy_fence_count,
            "settlement_batch_count": self.settlement_batch_count,
            "slashing_evidence_count": self.slashing_evidence_count,
            "accepted_route_count": self.accepted_route_count,
            "rejected_route_count": self.rejected_route_count,
            "slashed_route_count": self.slashed_route_count,
            "latest_height": self.latest_height,
            "latest_sequence": self.latest_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub policy_root: String,
    pub route_manifest_root: String,
    pub invariant_attestation_root: String,
    pub oracle_fence_root: String,
    pub isolation_window_root: String,
    pub call_approval_root: String,
    pub fee_sponsor_constraint_root: String,
    pub privacy_fence_root: String,
    pub settlement_batch_root: String,
    pub slashing_evidence_root: String,
    pub active_policy_root: String,
    pub open_route_root: String,
    pub frozen_route_root: String,
    pub consumed_nullifier_root: String,
    pub public_event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_root": self.policy_root,
            "route_manifest_root": self.route_manifest_root,
            "invariant_attestation_root": self.invariant_attestation_root,
            "oracle_fence_root": self.oracle_fence_root,
            "isolation_window_root": self.isolation_window_root,
            "call_approval_root": self.call_approval_root,
            "fee_sponsor_constraint_root": self.fee_sponsor_constraint_root,
            "privacy_fence_root": self.privacy_fence_root,
            "settlement_batch_root": self.settlement_batch_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "active_policy_root": self.active_policy_root,
            "open_route_root": self.open_route_root,
            "frozen_route_root": self.frozen_route_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "public_event_root": self.public_event_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComposabilityPolicy {
    pub policy_id: String,
    pub kind: PolicyKind,
    pub status: GuardStatus,
    pub controller_commitment: String,
    pub permitted_domain_root: String,
    pub required_invariant_root: String,
    pub allowed_call_graph_root: String,
    pub pq_verification_key_root: String,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub max_protocol_fee_bps: u64,
    pub max_slippage_bps: u64,
    pub max_oracle_drift_bps: u64,
    pub max_leverage_bps: u64,
    pub min_liquidity_cover_bps: u64,
    pub created_height: u64,
    pub expires_height: u64,
    pub nonce: String,
}

impl ComposabilityPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "policy_id": self.policy_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "controller_commitment": self.controller_commitment,
            "permitted_domain_root": self.permitted_domain_root,
            "required_invariant_root": self.required_invariant_root,
            "allowed_call_graph_root": self.allowed_call_graph_root,
            "pq_verification_key_root": self.pq_verification_key_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_protocol_fee_bps": self.max_protocol_fee_bps,
            "max_slippage_bps": self.max_slippage_bps,
            "max_oracle_drift_bps": self.max_oracle_drift_bps,
            "max_leverage_bps": self.max_leverage_bps,
            "min_liquidity_cover_bps": self.min_liquidity_cover_bps,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteLeg {
    pub leg_index: u16,
    pub contract_domain: ContractDomain,
    pub contract_commitment: String,
    pub action_commitment: String,
    pub input_asset_commitment: String,
    pub output_asset_commitment: String,
    pub amount_commitment: String,
    pub witness_policy_root: String,
    pub max_fee_bps: u64,
}

impl RouteLeg {
    pub fn public_record(&self) -> Value {
        json!({
            "leg_index": self.leg_index,
            "contract_domain": self.contract_domain.as_str(),
            "contract_commitment": self.contract_commitment,
            "action_commitment": self.action_commitment,
            "input_asset_commitment": self.input_asset_commitment,
            "output_asset_commitment": self.output_asset_commitment,
            "amount_commitment": self.amount_commitment,
            "witness_policy_root": self.witness_policy_root,
            "max_fee_bps": self.max_fee_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteManifest {
    pub route_id: String,
    pub policy_id: String,
    pub route_kind: RouteKind,
    pub status: GuardStatus,
    pub owner_commitment: String,
    pub route_secret_commitment: String,
    pub call_graph_root: String,
    pub leg_root: String,
    pub oracle_fence_root: String,
    pub privacy_fence_root: String,
    pub fee_sponsor_constraint_id: String,
    pub requested_height: u64,
    pub expires_height: u64,
    pub max_user_fee_bps: u64,
    pub max_protocol_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub pq_attestation_root: String,
    pub legs: Vec<RouteLeg>,
}

impl RouteManifest {
    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "policy_id": self.policy_id,
            "route_kind": self.route_kind.as_str(),
            "status": self.status.as_str(),
            "owner_commitment": self.owner_commitment,
            "route_secret_commitment": self.route_secret_commitment,
            "call_graph_root": self.call_graph_root,
            "leg_root": self.leg_root,
            "oracle_fence_root": self.oracle_fence_root,
            "privacy_fence_root": self.privacy_fence_root,
            "fee_sponsor_constraint_id": self.fee_sponsor_constraint_id,
            "requested_height": self.requested_height,
            "expires_height": self.expires_height,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_protocol_fee_bps": self.max_protocol_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_attestation_root": self.pq_attestation_root,
            "legs": self.legs.iter().map(RouteLeg::public_record).collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvariantAttestation {
    pub attestation_id: String,
    pub route_id: String,
    pub policy_id: String,
    pub invariant_kind: InvariantKind,
    pub prover_commitment: String,
    pub claim_root: String,
    pub proof_commitment: String,
    pub pq_signature_root: String,
    pub observed_value_bps: u64,
    pub bound_value_bps: u64,
    pub privacy_set_size: u64,
    pub attested_height: u64,
    pub expires_height: u64,
}

impl InvariantAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "route_id": self.route_id,
            "policy_id": self.policy_id,
            "invariant_kind": self.invariant_kind.as_str(),
            "prover_commitment": self.prover_commitment,
            "claim_root": self.claim_root,
            "proof_commitment": self.proof_commitment,
            "pq_signature_root": self.pq_signature_root,
            "observed_value_bps": self.observed_value_bps,
            "bound_value_bps": self.bound_value_bps,
            "privacy_set_size": self.privacy_set_size,
            "attested_height": self.attested_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleRiskFence {
    pub fence_id: String,
    pub route_id: String,
    pub oracle_committee_root: String,
    pub price_feed_root: String,
    pub risk_model_root: String,
    pub max_drift_bps: u64,
    pub observed_drift_bps: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub pq_signature_root: String,
}

impl OracleRiskFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "route_id": self.route_id,
            "oracle_committee_root": self.oracle_committee_root,
            "price_feed_root": self.price_feed_root,
            "risk_model_root": self.risk_model_root,
            "max_drift_bps": self.max_drift_bps,
            "observed_drift_bps": self.observed_drift_bps,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "pq_signature_root": self.pq_signature_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityIsolationWindow {
    pub window_id: String,
    pub route_id: String,
    pub pool_commitment: String,
    pub isolated_liquidity_commitment: String,
    pub reserve_floor_commitment: String,
    pub min_cover_bps: u64,
    pub observed_cover_bps: u64,
    pub opened_height: u64,
    pub closes_height: u64,
    pub release_root: String,
}

impl LiquidityIsolationWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "route_id": self.route_id,
            "pool_commitment": self.pool_commitment,
            "isolated_liquidity_commitment": self.isolated_liquidity_commitment,
            "reserve_floor_commitment": self.reserve_floor_commitment,
            "min_cover_bps": self.min_cover_bps,
            "observed_cover_bps": self.observed_cover_bps,
            "opened_height": self.opened_height,
            "closes_height": self.closes_height,
            "release_root": self.release_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrossContractCallApproval {
    pub approval_id: String,
    pub route_id: String,
    pub caller_commitment: String,
    pub callee_commitment: String,
    pub function_selector_commitment: String,
    pub calldata_policy_root: String,
    pub state_access_root: String,
    pub max_gas_units: u64,
    pub max_fee_bps: u64,
    pub approved_height: u64,
    pub expires_height: u64,
    pub pq_signature_root: String,
}

impl CrossContractCallApproval {
    pub fn public_record(&self) -> Value {
        json!({
            "approval_id": self.approval_id,
            "route_id": self.route_id,
            "caller_commitment": self.caller_commitment,
            "callee_commitment": self.callee_commitment,
            "function_selector_commitment": self.function_selector_commitment,
            "calldata_policy_root": self.calldata_policy_root,
            "state_access_root": self.state_access_root,
            "max_gas_units": self.max_gas_units,
            "max_fee_bps": self.max_fee_bps,
            "approved_height": self.approved_height,
            "expires_height": self.expires_height,
            "pq_signature_root": self.pq_signature_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsorConstraint {
    pub constraint_id: String,
    pub sponsor_commitment: String,
    pub route_id: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub max_rebate_bps: u64,
    pub spend_nullifier_root: String,
    pub opened_height: u64,
    pub expires_height: u64,
    pub pq_signature_root: String,
}

impl FeeSponsorConstraint {
    pub fn public_record(&self) -> Value {
        json!({
            "constraint_id": self.constraint_id,
            "sponsor_commitment": self.sponsor_commitment,
            "route_id": self.route_id,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "max_rebate_bps": self.max_rebate_bps,
            "spend_nullifier_root": self.spend_nullifier_root,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "pq_signature_root": self.pq_signature_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyNullifierFence {
    pub fence_id: String,
    pub route_id: String,
    pub nullifier: String,
    pub account_set_root: String,
    pub decoy_set_root: String,
    pub min_privacy_set_size: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl PrivacyNullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "route_id": self.route_id,
            "nullifier": self.nullifier,
            "account_set_root": self.account_set_root,
            "decoy_set_root": self.decoy_set_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub sequence: u64,
    pub route_root: String,
    pub attestation_root: String,
    pub decision: SettlementDecision,
    pub accepted_count: u64,
    pub rejected_count: u64,
    pub slashed_count: u64,
    pub fee_units_charged: u64,
    pub settled_height: u64,
    pub finalizes_height: u64,
    pub pq_signature_root: String,
}

impl SettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "sequence": self.sequence,
            "route_root": self.route_root,
            "attestation_root": self.attestation_root,
            "decision": self.decision.as_str(),
            "accepted_count": self.accepted_count,
            "rejected_count": self.rejected_count,
            "slashed_count": self.slashed_count,
            "fee_units_charged": self.fee_units_charged,
            "settled_height": self.settled_height,
            "finalizes_height": self.finalizes_height,
            "pq_signature_root": self.pq_signature_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub route_id: String,
    pub accused_commitment: String,
    pub reporter_commitment: String,
    pub evidence_kind: EvidenceKind,
    pub claim_root: String,
    pub penalty_bps: u64,
    pub opened_height: u64,
    pub pq_signature_root: String,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "route_id": self.route_id,
            "accused_commitment": self.accused_commitment,
            "reporter_commitment": self.reporter_commitment,
            "evidence_kind": self.evidence_kind.as_str(),
            "claim_root": self.claim_root,
            "penalty_bps": self.penalty_bps,
            "opened_height": self.opened_height,
            "pq_signature_root": self.pq_signature_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub policies: BTreeMap<String, ComposabilityPolicy>,
    pub route_manifests: BTreeMap<String, RouteManifest>,
    pub invariant_attestations: BTreeMap<String, InvariantAttestation>,
    pub oracle_fences: BTreeMap<String, OracleRiskFence>,
    pub isolation_windows: BTreeMap<String, LiquidityIsolationWindow>,
    pub call_approvals: BTreeMap<String, CrossContractCallApproval>,
    pub fee_sponsor_constraints: BTreeMap<String, FeeSponsorConstraint>,
    pub privacy_fences: BTreeMap<String, PrivacyNullifierFence>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub active_policies: BTreeSet<String>,
    pub open_routes: BTreeSet<String>,
    pub frozen_routes: BTreeSet<String>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_events: Vec<Value>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            policies: BTreeMap::new(),
            route_manifests: BTreeMap::new(),
            invariant_attestations: BTreeMap::new(),
            oracle_fences: BTreeMap::new(),
            isolation_windows: BTreeMap::new(),
            call_approvals: BTreeMap::new(),
            fee_sponsor_constraints: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            active_policies: BTreeSet::new(),
            open_routes: BTreeSet::new(),
            frozen_routes: BTreeSet::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_events: Vec::new(),
        };
        state.seed_devnet();
        state
    }

    pub fn counters(&self) -> Counters {
        Counters {
            policy_count: self.policies.len() as u64,
            route_manifest_count: self.route_manifests.len() as u64,
            invariant_attestation_count: self.invariant_attestations.len() as u64,
            oracle_fence_count: self.oracle_fences.len() as u64,
            isolation_window_count: self.isolation_windows.len() as u64,
            call_approval_count: self.call_approvals.len() as u64,
            fee_sponsor_constraint_count: self.fee_sponsor_constraints.len() as u64,
            privacy_fence_count: self.privacy_fences.len() as u64,
            settlement_batch_count: self.settlement_batches.len() as u64,
            slashing_evidence_count: self.slashing_evidence.len() as u64,
            accepted_route_count: self
                .route_manifests
                .values()
                .filter(|route| route.status == GuardStatus::Settled)
                .count() as u64,
            rejected_route_count: self
                .route_manifests
                .values()
                .filter(|route| route.status == GuardStatus::Rejected)
                .count() as u64,
            slashed_route_count: self
                .route_manifests
                .values()
                .filter(|route| route.status == GuardStatus::Slashed)
                .count() as u64,
            latest_height: self.latest_height(),
            latest_sequence: self.settlement_batches.len() as u64,
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            policy_root: map_root(POLICY_SCHEME, &self.policies),
            route_manifest_root: map_root(ROUTE_MANIFEST_SCHEME, &self.route_manifests),
            invariant_attestation_root: map_root(
                INVARIANT_ATTESTATION_SCHEME,
                &self.invariant_attestations,
            ),
            oracle_fence_root: map_root(ORACLE_RISK_FENCE_SCHEME, &self.oracle_fences),
            isolation_window_root: map_root(LIQUIDITY_ISOLATION_SCHEME, &self.isolation_windows),
            call_approval_root: map_root(CALL_APPROVAL_SCHEME, &self.call_approvals),
            fee_sponsor_constraint_root: map_root(
                FEE_SPONSOR_SCHEME,
                &self.fee_sponsor_constraints,
            ),
            privacy_fence_root: map_root(PRIVACY_FENCE_SCHEME, &self.privacy_fences),
            settlement_batch_root: map_root(SETTLEMENT_BATCH_SCHEME, &self.settlement_batches),
            slashing_evidence_root: map_root(SLASHING_EVIDENCE_SCHEME, &self.slashing_evidence),
            active_policy_root: set_root("PQ-DEFI-GUARD-ACTIVE-POLICIES", &self.active_policies),
            open_route_root: set_root("PQ-DEFI-GUARD-OPEN-ROUTES", &self.open_routes),
            frozen_route_root: set_root("PQ-DEFI-GUARD-FROZEN-ROUTES", &self.frozen_routes),
            consumed_nullifier_root: set_root(
                "PQ-DEFI-GUARD-CONSUMED-NULLIFIERS",
                &self.consumed_nullifiers,
            ),
            public_event_root: merkle_root("PQ-DEFI-GUARD-PUBLIC-EVENTS", &self.public_events),
        }
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_attestation_suite": PQ_ATTESTATION_SUITE,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn register_policy(
        &mut self,
        kind: PolicyKind,
        controller_commitment: &str,
        permitted_domains: &[ContractDomain],
        required_invariants: &[InvariantKind],
        allowed_call_graph_root: &str,
        pq_verification_key_root: &str,
        created_height: u64,
        nonce: &str,
    ) -> Result<String> {
        ensure_capacity(
            self.policies.len(),
            self.config.max_policies,
            "policy registry",
        )?;
        require_nonempty(controller_commitment, "controller commitment")?;
        require_nonempty(allowed_call_graph_root, "allowed call graph root")?;
        require_nonempty(pq_verification_key_root, "pq verification key root")?;
        require_nonempty(nonce, "policy nonce")?;
        let permitted_domain_root = domain_list_root(permitted_domains);
        let required_invariant_root = invariant_list_root(required_invariants);
        let policy_id = policy_id(
            kind,
            controller_commitment,
            &permitted_domain_root,
            &required_invariant_root,
            allowed_call_graph_root,
            pq_verification_key_root,
            created_height,
            nonce,
        );
        if self.policies.contains_key(&policy_id) {
            return Err(format!("policy already registered: {policy_id}"));
        }
        let policy = ComposabilityPolicy {
            policy_id: policy_id.clone(),
            kind,
            status: GuardStatus::Active,
            controller_commitment: controller_commitment.to_string(),
            permitted_domain_root,
            required_invariant_root,
            allowed_call_graph_root: allowed_call_graph_root.to_string(),
            pq_verification_key_root: pq_verification_key_root.to_string(),
            min_privacy_set_size: self.config.min_privacy_set_size,
            max_user_fee_bps: self.config.max_user_fee_bps,
            max_protocol_fee_bps: self.config.max_protocol_fee_bps,
            max_slippage_bps: self.config.max_slippage_bps,
            max_oracle_drift_bps: self.config.max_oracle_drift_bps,
            max_leverage_bps: self.config.max_leverage_bps,
            min_liquidity_cover_bps: self.config.min_liquidity_cover_bps,
            created_height,
            expires_height: created_height + self.config.route_ttl_blocks * 4,
            nonce: nonce.to_string(),
        };
        self.policies.insert(policy_id.clone(), policy);
        self.active_policies.insert(policy_id.clone());
        self.push_event("policy_registered", &policy_id, created_height);
        Ok(policy_id)
    }

    pub fn authorize_composable_route(
        &mut self,
        policy_id: &str,
        route_kind: RouteKind,
        owner_commitment: &str,
        route_secret_commitment: &str,
        legs: Vec<RouteLeg>,
        requested_height: u64,
        pq_attestation_root: &str,
    ) -> Result<String> {
        ensure_capacity(
            self.route_manifests.len(),
            self.config.max_route_manifests,
            "route manifests",
        )?;
        require_nonempty(policy_id, "policy id")?;
        require_nonempty(owner_commitment, "owner commitment")?;
        require_nonempty(route_secret_commitment, "route secret commitment")?;
        require_nonempty(pq_attestation_root, "pq attestation root")?;
        let policy = self
            .policies
            .get(policy_id)
            .ok_or_else(|| format!("unknown policy: {policy_id}"))?;
        if !policy.status.admits_routes() {
            return Err(format!("policy does not admit routes: {policy_id}"));
        }
        if requested_height > policy.expires_height {
            return Err(format!(
                "policy expired at height {}",
                policy.expires_height
            ));
        }
        if legs.is_empty() || legs.len() > self.config.max_route_legs {
            return Err(format!(
                "route leg count must be between 1 and {}",
                self.config.max_route_legs
            ));
        }
        validate_legs(&legs, policy.max_user_fee_bps)?;
        let leg_root = merkle_root(
            "PQ-DEFI-GUARD-ROUTE-LEGS",
            &legs.iter().map(RouteLeg::public_record).collect::<Vec<_>>(),
        );
        let call_graph_root = route_call_graph_root(&legs);
        let route_id = route_manifest_id(
            policy_id,
            route_kind,
            owner_commitment,
            route_secret_commitment,
            &call_graph_root,
            &leg_root,
            requested_height,
            pq_attestation_root,
        );
        if self.route_manifests.contains_key(&route_id) {
            return Err(format!("route already registered: {route_id}"));
        }
        let manifest = RouteManifest {
            route_id: route_id.clone(),
            policy_id: policy_id.to_string(),
            route_kind,
            status: GuardStatus::Active,
            owner_commitment: owner_commitment.to_string(),
            route_secret_commitment: route_secret_commitment.to_string(),
            call_graph_root,
            leg_root,
            oracle_fence_root: empty_root("PQ-DEFI-GUARD-ROUTE-ORACLE-FENCE"),
            privacy_fence_root: empty_root("PQ-DEFI-GUARD-ROUTE-PRIVACY-FENCE"),
            fee_sponsor_constraint_id: String::new(),
            requested_height,
            expires_height: requested_height + self.config.route_ttl_blocks,
            max_user_fee_bps: policy.max_user_fee_bps,
            max_protocol_fee_bps: policy.max_protocol_fee_bps,
            min_privacy_set_size: policy.min_privacy_set_size,
            pq_attestation_root: pq_attestation_root.to_string(),
            legs,
        };
        self.route_manifests.insert(route_id.clone(), manifest);
        self.open_routes.insert(route_id.clone());
        self.push_event("route_authorized", &route_id, requested_height);
        Ok(route_id)
    }

    pub fn attest_invariant(
        &mut self,
        route_id: &str,
        invariant_kind: InvariantKind,
        prover_commitment: &str,
        claim_root: &str,
        proof_commitment: &str,
        pq_signature_root: &str,
        observed_value_bps: u64,
        bound_value_bps: u64,
        privacy_set_size: u64,
        attested_height: u64,
    ) -> Result<String> {
        ensure_capacity(
            self.invariant_attestations.len(),
            self.config.max_invariant_attestations,
            "invariant attestations",
        )?;
        let route = self.route(route_id)?;
        if attested_height > route.expires_height {
            return Err(format!("route expired at height {}", route.expires_height));
        }
        if privacy_set_size < route.min_privacy_set_size {
            return Err(format!(
                "privacy set too small: {privacy_set_size} < {}",
                route.min_privacy_set_size
            ));
        }
        require_nonempty(prover_commitment, "prover commitment")?;
        require_nonempty(claim_root, "claim root")?;
        require_nonempty(proof_commitment, "proof commitment")?;
        require_nonempty(pq_signature_root, "pq signature root")?;
        let attestation_id = invariant_attestation_id(
            route_id,
            &route.policy_id,
            invariant_kind,
            prover_commitment,
            claim_root,
            proof_commitment,
            attested_height,
        );
        let attestation = InvariantAttestation {
            attestation_id: attestation_id.clone(),
            route_id: route_id.to_string(),
            policy_id: route.policy_id.clone(),
            invariant_kind,
            prover_commitment: prover_commitment.to_string(),
            claim_root: claim_root.to_string(),
            proof_commitment: proof_commitment.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            observed_value_bps,
            bound_value_bps,
            privacy_set_size,
            attested_height,
            expires_height: attested_height + self.config.attestation_ttl_blocks,
        };
        self.invariant_attestations
            .insert(attestation_id.clone(), attestation);
        self.push_event("invariant_attested", &attestation_id, attested_height);
        Ok(attestation_id)
    }

    pub fn install_oracle_risk_fence(
        &mut self,
        route_id: &str,
        oracle_committee_root: &str,
        price_feed_root: &str,
        risk_model_root: &str,
        observed_drift_bps: u64,
        opened_height: u64,
        pq_signature_root: &str,
    ) -> Result<String> {
        ensure_capacity(
            self.oracle_fences.len(),
            self.config.max_oracle_fences,
            "oracle fences",
        )?;
        self.route(route_id)?;
        require_nonempty(oracle_committee_root, "oracle committee root")?;
        require_nonempty(price_feed_root, "price feed root")?;
        require_nonempty(risk_model_root, "risk model root")?;
        require_nonempty(pq_signature_root, "pq signature root")?;
        if observed_drift_bps > self.config.max_oracle_drift_bps {
            return Err(format!(
                "oracle drift exceeds guard bound: {observed_drift_bps} > {}",
                self.config.max_oracle_drift_bps
            ));
        }
        let fence_id = oracle_risk_fence_id(
            route_id,
            oracle_committee_root,
            price_feed_root,
            risk_model_root,
            observed_drift_bps,
            opened_height,
        );
        let fence = OracleRiskFence {
            fence_id: fence_id.clone(),
            route_id: route_id.to_string(),
            oracle_committee_root: oracle_committee_root.to_string(),
            price_feed_root: price_feed_root.to_string(),
            risk_model_root: risk_model_root.to_string(),
            max_drift_bps: self.config.max_oracle_drift_bps,
            observed_drift_bps,
            opened_height,
            expires_height: opened_height + self.config.oracle_fence_ttl_blocks,
            pq_signature_root: pq_signature_root.to_string(),
        };
        self.oracle_fences.insert(fence_id.clone(), fence);
        self.refresh_route_roots(route_id);
        self.push_event("oracle_fence_installed", &fence_id, opened_height);
        Ok(fence_id)
    }

    pub fn open_liquidity_isolation_window(
        &mut self,
        route_id: &str,
        pool_commitment: &str,
        isolated_liquidity_commitment: &str,
        reserve_floor_commitment: &str,
        observed_cover_bps: u64,
        opened_height: u64,
        release_root: &str,
    ) -> Result<String> {
        ensure_capacity(
            self.isolation_windows.len(),
            self.config.max_isolation_windows,
            "liquidity isolation windows",
        )?;
        self.route(route_id)?;
        require_nonempty(pool_commitment, "pool commitment")?;
        require_nonempty(
            isolated_liquidity_commitment,
            "isolated liquidity commitment",
        )?;
        require_nonempty(reserve_floor_commitment, "reserve floor commitment")?;
        require_nonempty(release_root, "release root")?;
        if observed_cover_bps < self.config.min_liquidity_cover_bps {
            return Err(format!(
                "liquidity coverage below guard floor: {observed_cover_bps} < {}",
                self.config.min_liquidity_cover_bps
            ));
        }
        let window_id = liquidity_isolation_window_id(
            route_id,
            pool_commitment,
            isolated_liquidity_commitment,
            reserve_floor_commitment,
            observed_cover_bps,
            opened_height,
        );
        let window = LiquidityIsolationWindow {
            window_id: window_id.clone(),
            route_id: route_id.to_string(),
            pool_commitment: pool_commitment.to_string(),
            isolated_liquidity_commitment: isolated_liquidity_commitment.to_string(),
            reserve_floor_commitment: reserve_floor_commitment.to_string(),
            min_cover_bps: self.config.min_liquidity_cover_bps,
            observed_cover_bps,
            opened_height,
            closes_height: opened_height + self.config.isolation_window_blocks,
            release_root: release_root.to_string(),
        };
        self.isolation_windows.insert(window_id.clone(), window);
        self.push_event("liquidity_isolation_opened", &window_id, opened_height);
        Ok(window_id)
    }

    pub fn approve_cross_contract_call(
        &mut self,
        route_id: &str,
        caller_commitment: &str,
        callee_commitment: &str,
        function_selector_commitment: &str,
        calldata_policy_root: &str,
        state_access_root: &str,
        max_gas_units: u64,
        max_fee_bps: u64,
        approved_height: u64,
        pq_signature_root: &str,
    ) -> Result<String> {
        ensure_capacity(
            self.call_approvals.len(),
            self.config.max_call_approvals,
            "call approvals",
        )?;
        let route = self.route(route_id)?;
        require_nonempty(caller_commitment, "caller commitment")?;
        require_nonempty(callee_commitment, "callee commitment")?;
        require_nonempty(function_selector_commitment, "function selector commitment")?;
        require_nonempty(calldata_policy_root, "calldata policy root")?;
        require_nonempty(state_access_root, "state access root")?;
        require_nonempty(pq_signature_root, "pq signature root")?;
        if max_fee_bps > route.max_user_fee_bps {
            return Err(format!(
                "call fee exceeds route bound: {max_fee_bps} > {}",
                route.max_user_fee_bps
            ));
        }
        let approval_id = cross_contract_call_approval_id(
            route_id,
            caller_commitment,
            callee_commitment,
            function_selector_commitment,
            calldata_policy_root,
            state_access_root,
            approved_height,
        );
        let approval = CrossContractCallApproval {
            approval_id: approval_id.clone(),
            route_id: route_id.to_string(),
            caller_commitment: caller_commitment.to_string(),
            callee_commitment: callee_commitment.to_string(),
            function_selector_commitment: function_selector_commitment.to_string(),
            calldata_policy_root: calldata_policy_root.to_string(),
            state_access_root: state_access_root.to_string(),
            max_gas_units,
            max_fee_bps,
            approved_height,
            expires_height: approved_height + self.config.call_approval_ttl_blocks,
            pq_signature_root: pq_signature_root.to_string(),
        };
        self.call_approvals.insert(approval_id.clone(), approval);
        self.push_event(
            "cross_contract_call_approved",
            &approval_id,
            approved_height,
        );
        Ok(approval_id)
    }

    pub fn constrain_fee_sponsor(
        &mut self,
        route_id: &str,
        sponsor_commitment: &str,
        max_fee_units: u64,
        max_rebate_bps: u64,
        spend_nullifier_root: &str,
        opened_height: u64,
        pq_signature_root: &str,
    ) -> Result<String> {
        ensure_capacity(
            self.fee_sponsor_constraints.len(),
            self.config.max_fee_sponsor_constraints,
            "fee sponsor constraints",
        )?;
        self.route(route_id)?;
        require_nonempty(sponsor_commitment, "sponsor commitment")?;
        require_nonempty(spend_nullifier_root, "spend nullifier root")?;
        require_nonempty(pq_signature_root, "pq signature root")?;
        if max_rebate_bps > self.config.max_sponsor_rebate_bps {
            return Err(format!(
                "sponsor rebate exceeds guard bound: {max_rebate_bps} > {}",
                self.config.max_sponsor_rebate_bps
            ));
        }
        let constraint_id = fee_sponsor_constraint_id(
            route_id,
            sponsor_commitment,
            max_fee_units,
            max_rebate_bps,
            spend_nullifier_root,
            opened_height,
        );
        let constraint = FeeSponsorConstraint {
            constraint_id: constraint_id.clone(),
            sponsor_commitment: sponsor_commitment.to_string(),
            route_id: route_id.to_string(),
            fee_asset_id: self.config.fee_asset_id.clone(),
            max_fee_units,
            max_rebate_bps,
            spend_nullifier_root: spend_nullifier_root.to_string(),
            opened_height,
            expires_height: opened_height + self.config.fee_sponsor_ttl_blocks,
            pq_signature_root: pq_signature_root.to_string(),
        };
        self.fee_sponsor_constraints
            .insert(constraint_id.clone(), constraint);
        if let Some(route) = self.route_manifests.get_mut(route_id) {
            route.fee_sponsor_constraint_id = constraint_id.clone();
        }
        self.push_event("fee_sponsor_constrained", &constraint_id, opened_height);
        Ok(constraint_id)
    }

    pub fn open_privacy_nullifier_fence(
        &mut self,
        route_id: &str,
        nullifier: &str,
        account_set_root: &str,
        decoy_set_root: &str,
        min_privacy_set_size: u64,
        opened_height: u64,
    ) -> Result<String> {
        ensure_capacity(
            self.privacy_fences.len(),
            self.config.max_privacy_fences,
            "privacy fences",
        )?;
        self.route(route_id)?;
        require_nonempty(nullifier, "nullifier")?;
        require_nonempty(account_set_root, "account set root")?;
        require_nonempty(decoy_set_root, "decoy set root")?;
        if self.consumed_nullifiers.contains(nullifier) {
            return Err(format!("nullifier already consumed: {nullifier}"));
        }
        if min_privacy_set_size < self.config.min_privacy_set_size {
            return Err(format!(
                "privacy fence set below guard floor: {min_privacy_set_size} < {}",
                self.config.min_privacy_set_size
            ));
        }
        let fence_id = privacy_nullifier_fence_id(
            route_id,
            nullifier,
            account_set_root,
            decoy_set_root,
            min_privacy_set_size,
            opened_height,
        );
        let fence = PrivacyNullifierFence {
            fence_id: fence_id.clone(),
            route_id: route_id.to_string(),
            nullifier: nullifier.to_string(),
            account_set_root: account_set_root.to_string(),
            decoy_set_root: decoy_set_root.to_string(),
            min_privacy_set_size,
            opened_height,
            expires_height: opened_height + self.config.privacy_fence_ttl_blocks,
        };
        self.privacy_fences.insert(fence_id.clone(), fence);
        self.consumed_nullifiers.insert(nullifier.to_string());
        self.refresh_route_roots(route_id);
        self.push_event("privacy_fence_opened", &fence_id, opened_height);
        Ok(fence_id)
    }

    pub fn settle_guard_batch(
        &mut self,
        route_ids: &[String],
        decision: SettlementDecision,
        fee_units_charged: u64,
        settled_height: u64,
        pq_signature_root: &str,
    ) -> Result<String> {
        ensure_capacity(
            self.settlement_batches.len(),
            self.config.max_settlement_batches,
            "settlement batches",
        )?;
        require_nonempty(pq_signature_root, "pq signature root")?;
        if route_ids.is_empty() {
            return Err("settlement batch must include at least one route".to_string());
        }
        let mut accepted_count = 0_u64;
        let mut rejected_count = 0_u64;
        let mut slashed_count = 0_u64;
        for route_id in route_ids {
            self.route(route_id)?;
        }
        for route_id in route_ids {
            if let Some(route) = self.route_manifests.get_mut(route_id) {
                route.status = match decision {
                    SettlementDecision::Accepted | SettlementDecision::AcceptedWithIsolation => {
                        accepted_count += 1;
                        GuardStatus::Settled
                    }
                    SettlementDecision::Rejected => {
                        rejected_count += 1;
                        GuardStatus::Rejected
                    }
                    SettlementDecision::FrozenForReview => {
                        self.frozen_routes.insert(route_id.clone());
                        GuardStatus::Frozen
                    }
                    SettlementDecision::Slashed => {
                        slashed_count += 1;
                        GuardStatus::Slashed
                    }
                };
            }
            if decision != SettlementDecision::FrozenForReview {
                self.open_routes.remove(route_id);
                self.frozen_routes.remove(route_id);
            }
        }
        let sequence = self.settlement_batches.len() as u64 + 1;
        let route_root = string_list_root("PQ-DEFI-GUARD-SETTLED-ROUTES", route_ids);
        let attestation_root =
            route_scoped_attestation_root("PQ-DEFI-GUARD-SETTLEMENT-ATTESTATIONS", route_ids, self);
        let batch_id = settlement_batch_id(
            sequence,
            &route_root,
            &attestation_root,
            decision,
            fee_units_charged,
            settled_height,
        );
        let batch = SettlementBatch {
            batch_id: batch_id.clone(),
            sequence,
            route_root,
            attestation_root,
            decision,
            accepted_count,
            rejected_count,
            slashed_count,
            fee_units_charged,
            settled_height,
            finalizes_height: settled_height + self.config.settlement_finality_blocks,
            pq_signature_root: pq_signature_root.to_string(),
        };
        self.settlement_batches.insert(batch_id.clone(), batch);
        self.push_event("guard_batch_settled", &batch_id, settled_height);
        Ok(batch_id)
    }

    pub fn submit_slashing_evidence(
        &mut self,
        route_id: &str,
        accused_commitment: &str,
        reporter_commitment: &str,
        evidence_kind: EvidenceKind,
        claim_root: &str,
        penalty_bps: u64,
        opened_height: u64,
        pq_signature_root: &str,
    ) -> Result<String> {
        ensure_capacity(
            self.slashing_evidence.len(),
            self.config.max_slashing_evidence,
            "slashing evidence",
        )?;
        self.route(route_id)?;
        require_nonempty(accused_commitment, "accused commitment")?;
        require_nonempty(reporter_commitment, "reporter commitment")?;
        require_nonempty(claim_root, "claim root")?;
        require_nonempty(pq_signature_root, "pq signature root")?;
        if penalty_bps > self.config.max_slash_bps {
            return Err(format!(
                "slash penalty exceeds guard bound: {penalty_bps} > {}",
                self.config.max_slash_bps
            ));
        }
        let evidence_id = slashing_evidence_id(
            route_id,
            accused_commitment,
            reporter_commitment,
            evidence_kind,
            claim_root,
            opened_height,
        );
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            route_id: route_id.to_string(),
            accused_commitment: accused_commitment.to_string(),
            reporter_commitment: reporter_commitment.to_string(),
            evidence_kind,
            claim_root: claim_root.to_string(),
            penalty_bps,
            opened_height,
            pq_signature_root: pq_signature_root.to_string(),
        };
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        if let Some(route) = self.route_manifests.get_mut(route_id) {
            route.status = GuardStatus::Slashed;
        }
        self.open_routes.remove(route_id);
        self.frozen_routes.remove(route_id);
        self.push_event("slashing_evidence_submitted", &evidence_id, opened_height);
        Ok(evidence_id)
    }

    pub fn policy(&self, policy_id: &str) -> Result<&ComposabilityPolicy> {
        self.policies
            .get(policy_id)
            .ok_or_else(|| format!("unknown policy: {policy_id}"))
    }

    pub fn route(&self, route_id: &str) -> Result<&RouteManifest> {
        self.route_manifests
            .get(route_id)
            .ok_or_else(|| format!("unknown route: {route_id}"))
    }

    pub fn route_is_authorized(&self, route_id: &str, height: u64) -> bool {
        self.route_manifests
            .get(route_id)
            .map(|route| route.status.admits_routes() && height <= route.expires_height)
            .unwrap_or(false)
    }

    pub fn route_guard_score_bps(&self, route_id: &str, height: u64) -> Result<u64> {
        let route = self.route(route_id)?;
        if !route.status.admits_routes() {
            return Ok(0);
        }
        let mut score = 10_000_u64;
        if height > route.expires_height {
            score = score.saturating_sub(4_000);
        }
        let attestations = self
            .invariant_attestations
            .values()
            .filter(|attestation| {
                attestation.route_id == route_id && height <= attestation.expires_height
            })
            .count() as u64;
        let approvals = self
            .call_approvals
            .values()
            .filter(|approval| approval.route_id == route_id && height <= approval.expires_height)
            .count() as u64;
        let fences = self
            .privacy_fences
            .values()
            .filter(|fence| fence.route_id == route_id && height <= fence.expires_height)
            .count() as u64;
        score = score.saturating_sub(2_000_u64.saturating_sub(attestations.min(4) * 500));
        score = score.saturating_sub(1_000_u64.saturating_sub(approvals.min(4) * 250));
        score = score.saturating_sub(1_000_u64.saturating_sub(fences.min(2) * 500));
        Ok(score)
    }

    fn latest_height(&self) -> u64 {
        let route_height = self
            .route_manifests
            .values()
            .map(|route| route.requested_height)
            .max()
            .unwrap_or(DEVNET_HEIGHT);
        let batch_height = self
            .settlement_batches
            .values()
            .map(|batch| batch.settled_height)
            .max()
            .unwrap_or(DEVNET_HEIGHT);
        route_height.max(batch_height)
    }

    fn refresh_route_roots(&mut self, route_id: &str) {
        let oracle_records = self
            .oracle_fences
            .values()
            .filter(|fence| fence.route_id == route_id)
            .map(OracleRiskFence::public_record)
            .collect::<Vec<_>>();
        let privacy_records = self
            .privacy_fences
            .values()
            .filter(|fence| fence.route_id == route_id)
            .map(PrivacyNullifierFence::public_record)
            .collect::<Vec<_>>();
        if let Some(route) = self.route_manifests.get_mut(route_id) {
            route.oracle_fence_root =
                merkle_root("PQ-DEFI-GUARD-ROUTE-ORACLE-FENCE", &oracle_records);
            route.privacy_fence_root =
                merkle_root("PQ-DEFI-GUARD-ROUTE-PRIVACY-FENCE", &privacy_records);
        }
    }

    fn push_event(&mut self, event_kind: &str, subject_id: &str, height: u64) {
        self.public_events.push(json!({
            "event_kind": event_kind,
            "subject_id": subject_id,
            "height": height,
        }));
    }

    fn seed_devnet(&mut self) {
        let policy_id = self
            .register_policy(
                PolicyKind::CrossContractAtomic,
                "controller:devnet-defi-safety-council",
                &[
                    ContractDomain::Vault,
                    ContractDomain::Amm,
                    ContractDomain::Lending,
                    ContractDomain::Perps,
                    ContractDomain::Oracle,
                    ContractDomain::Paymaster,
                ],
                &[
                    InvariantKind::Solvency,
                    InvariantKind::Conservation,
                    InvariantKind::OracleFreshness,
                    InvariantKind::PrivacySet,
                    InvariantKind::NullifierUniqueness,
                    InvariantKind::CallGraphAllowed,
                ],
                &deterministic_commitment("devnet-call-graph"),
                &deterministic_commitment("devnet-pq-verification-keys"),
                DEVNET_HEIGHT,
                "devnet-policy-0",
            )
            .unwrap_or_else(|error| deterministic_commitment(&error));
        let legs = vec![
            RouteLeg {
                leg_index: 0,
                contract_domain: ContractDomain::Vault,
                contract_commitment: deterministic_commitment("devnet-vault-router"),
                action_commitment: deterministic_commitment("deposit-confidential-note"),
                input_asset_commitment: deterministic_commitment(DEVNET_SETTLEMENT_ASSET_ID),
                output_asset_commitment: deterministic_commitment("vault-share-commitment"),
                amount_commitment: deterministic_commitment("amount-500-xusd"),
                witness_policy_root: deterministic_commitment("vault-witness-policy"),
                max_fee_bps: 5,
            },
            RouteLeg {
                leg_index: 1,
                contract_domain: ContractDomain::Amm,
                contract_commitment: deterministic_commitment("devnet-stableswap-amm"),
                action_commitment: deterministic_commitment("private-swap-leg"),
                input_asset_commitment: deterministic_commitment("vault-share-commitment"),
                output_asset_commitment: deterministic_commitment("hedge-collateral"),
                amount_commitment: deterministic_commitment("amount-hedge"),
                witness_policy_root: deterministic_commitment("amm-witness-policy"),
                max_fee_bps: 6,
            },
            RouteLeg {
                leg_index: 2,
                contract_domain: ContractDomain::Perps,
                contract_commitment: deterministic_commitment("devnet-perps-risk-engine"),
                action_commitment: deterministic_commitment("delta-neutral-hedge"),
                input_asset_commitment: deterministic_commitment("hedge-collateral"),
                output_asset_commitment: deterministic_commitment("perps-position"),
                amount_commitment: deterministic_commitment("amount-delta"),
                witness_policy_root: deterministic_commitment("perps-witness-policy"),
                max_fee_bps: 8,
            },
        ];
        let route_id = self
            .authorize_composable_route(
                &policy_id,
                RouteKind::VaultDepositSwap,
                "owner:devnet-private-vault-user",
                &deterministic_commitment("devnet-route-secret"),
                legs,
                DEVNET_HEIGHT + 1,
                &deterministic_commitment("devnet-route-pq-attestation"),
            )
            .unwrap_or_else(|error| deterministic_commitment(&error));
        let _ = self.install_oracle_risk_fence(
            &route_id,
            &deterministic_commitment("devnet-oracle-committee"),
            &deterministic_commitment("devnet-price-feed-root"),
            &deterministic_commitment("devnet-risk-model-root"),
            18,
            DEVNET_HEIGHT + 2,
            &deterministic_commitment("devnet-oracle-pq-sig"),
        );
        let _ = self.open_liquidity_isolation_window(
            &route_id,
            &deterministic_commitment("devnet-amm-pool"),
            &deterministic_commitment("devnet-isolated-liquidity"),
            &deterministic_commitment("devnet-reserve-floor"),
            11_200,
            DEVNET_HEIGHT + 2,
            &deterministic_commitment("devnet-liquidity-release"),
        );
        let _ = self.constrain_fee_sponsor(
            &route_id,
            "sponsor:devnet-low-fee-paymaster",
            25_000,
            4,
            &deterministic_commitment("devnet-sponsor-nullifier-root"),
            DEVNET_HEIGHT + 2,
            &deterministic_commitment("devnet-sponsor-pq-sig"),
        );
        let _ = self.open_privacy_nullifier_fence(
            &route_id,
            &deterministic_commitment("devnet-nullifier-0"),
            &deterministic_commitment("devnet-account-set"),
            &deterministic_commitment("devnet-decoy-set"),
            self.config.batch_privacy_set_size,
            DEVNET_HEIGHT + 2,
        );
        let _ = self.approve_cross_contract_call(
            &route_id,
            &deterministic_commitment("devnet-vault-router"),
            &deterministic_commitment("devnet-stableswap-amm"),
            &deterministic_commitment("swap-private-selector"),
            &deterministic_commitment("calldata-policy"),
            &deterministic_commitment("state-access-policy"),
            180_000,
            6,
            DEVNET_HEIGHT + 3,
            &deterministic_commitment("devnet-call-pq-sig"),
        );
        for invariant in [
            InvariantKind::Solvency,
            InvariantKind::Conservation,
            InvariantKind::OracleFreshness,
            InvariantKind::PrivacySet,
            InvariantKind::NullifierUniqueness,
            InvariantKind::CallGraphAllowed,
        ] {
            let _ = self.attest_invariant(
                &route_id,
                invariant,
                "prover:devnet-fast-pq-guard",
                &deterministic_commitment(invariant.as_str()),
                &deterministic_commitment("devnet-proof-commitment"),
                &deterministic_commitment("devnet-invariant-pq-sig"),
                5,
                10_000,
                self.config.batch_privacy_set_size,
                DEVNET_HEIGHT + 4,
            );
        }
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
        "PQ-CONFIDENTIAL-DEFI-COMPOSABILITY-GUARD-STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn deterministic_commitment(label: &str) -> String {
    domain_hash(
        "PQ-DEFI-GUARD-DETERMINISTIC-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn policy_id(
    kind: PolicyKind,
    controller_commitment: &str,
    permitted_domain_root: &str,
    required_invariant_root: &str,
    allowed_call_graph_root: &str,
    pq_verification_key_root: &str,
    created_height: u64,
    nonce: &str,
) -> String {
    domain_hash(
        "PQ-DEFI-GUARD-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(controller_commitment),
            HashPart::Str(permitted_domain_root),
            HashPart::Str(required_invariant_root),
            HashPart::Str(allowed_call_graph_root),
            HashPart::Str(pq_verification_key_root),
            HashPart::U64(created_height),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn route_manifest_id(
    policy_id: &str,
    route_kind: RouteKind,
    owner_commitment: &str,
    route_secret_commitment: &str,
    call_graph_root: &str,
    leg_root: &str,
    requested_height: u64,
    pq_attestation_root: &str,
) -> String {
    domain_hash(
        "PQ-DEFI-GUARD-ROUTE-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(policy_id),
            HashPart::Str(route_kind.as_str()),
            HashPart::Str(owner_commitment),
            HashPart::Str(route_secret_commitment),
            HashPart::Str(call_graph_root),
            HashPart::Str(leg_root),
            HashPart::U64(requested_height),
            HashPart::Str(pq_attestation_root),
        ],
        32,
    )
}

pub fn invariant_attestation_id(
    route_id: &str,
    policy_id: &str,
    invariant_kind: InvariantKind,
    prover_commitment: &str,
    claim_root: &str,
    proof_commitment: &str,
    attested_height: u64,
) -> String {
    domain_hash(
        "PQ-DEFI-GUARD-INVARIANT-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(route_id),
            HashPart::Str(policy_id),
            HashPart::Str(invariant_kind.as_str()),
            HashPart::Str(prover_commitment),
            HashPart::Str(claim_root),
            HashPart::Str(proof_commitment),
            HashPart::U64(attested_height),
        ],
        32,
    )
}

pub fn oracle_risk_fence_id(
    route_id: &str,
    oracle_committee_root: &str,
    price_feed_root: &str,
    risk_model_root: &str,
    observed_drift_bps: u64,
    opened_height: u64,
) -> String {
    domain_hash(
        "PQ-DEFI-GUARD-ORACLE-RISK-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(route_id),
            HashPart::Str(oracle_committee_root),
            HashPart::Str(price_feed_root),
            HashPart::Str(risk_model_root),
            HashPart::U64(observed_drift_bps),
            HashPart::U64(opened_height),
        ],
        32,
    )
}

pub fn liquidity_isolation_window_id(
    route_id: &str,
    pool_commitment: &str,
    isolated_liquidity_commitment: &str,
    reserve_floor_commitment: &str,
    observed_cover_bps: u64,
    opened_height: u64,
) -> String {
    domain_hash(
        "PQ-DEFI-GUARD-LIQUIDITY-ISOLATION-WINDOW-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(route_id),
            HashPart::Str(pool_commitment),
            HashPart::Str(isolated_liquidity_commitment),
            HashPart::Str(reserve_floor_commitment),
            HashPart::U64(observed_cover_bps),
            HashPart::U64(opened_height),
        ],
        32,
    )
}

pub fn cross_contract_call_approval_id(
    route_id: &str,
    caller_commitment: &str,
    callee_commitment: &str,
    function_selector_commitment: &str,
    calldata_policy_root: &str,
    state_access_root: &str,
    approved_height: u64,
) -> String {
    domain_hash(
        "PQ-DEFI-GUARD-CROSS-CONTRACT-CALL-APPROVAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(route_id),
            HashPart::Str(caller_commitment),
            HashPart::Str(callee_commitment),
            HashPart::Str(function_selector_commitment),
            HashPart::Str(calldata_policy_root),
            HashPart::Str(state_access_root),
            HashPart::U64(approved_height),
        ],
        32,
    )
}

pub fn fee_sponsor_constraint_id(
    route_id: &str,
    sponsor_commitment: &str,
    max_fee_units: u64,
    max_rebate_bps: u64,
    spend_nullifier_root: &str,
    opened_height: u64,
) -> String {
    domain_hash(
        "PQ-DEFI-GUARD-FEE-SPONSOR-CONSTRAINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(route_id),
            HashPart::Str(sponsor_commitment),
            HashPart::U64(max_fee_units),
            HashPart::U64(max_rebate_bps),
            HashPart::Str(spend_nullifier_root),
            HashPart::U64(opened_height),
        ],
        32,
    )
}

pub fn privacy_nullifier_fence_id(
    route_id: &str,
    nullifier: &str,
    account_set_root: &str,
    decoy_set_root: &str,
    min_privacy_set_size: u64,
    opened_height: u64,
) -> String {
    domain_hash(
        "PQ-DEFI-GUARD-PRIVACY-NULLIFIER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(route_id),
            HashPart::Str(nullifier),
            HashPart::Str(account_set_root),
            HashPart::Str(decoy_set_root),
            HashPart::U64(min_privacy_set_size),
            HashPart::U64(opened_height),
        ],
        32,
    )
}

pub fn settlement_batch_id(
    sequence: u64,
    route_root: &str,
    attestation_root: &str,
    decision: SettlementDecision,
    fee_units_charged: u64,
    settled_height: u64,
) -> String {
    domain_hash(
        "PQ-DEFI-GUARD-SETTLEMENT-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(route_root),
            HashPart::Str(attestation_root),
            HashPart::Str(decision.as_str()),
            HashPart::U64(fee_units_charged),
            HashPart::U64(settled_height),
        ],
        32,
    )
}

pub fn slashing_evidence_id(
    route_id: &str,
    accused_commitment: &str,
    reporter_commitment: &str,
    evidence_kind: EvidenceKind,
    claim_root: &str,
    opened_height: u64,
) -> String {
    domain_hash(
        "PQ-DEFI-GUARD-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(route_id),
            HashPart::Str(accused_commitment),
            HashPart::Str(reporter_commitment),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(claim_root),
            HashPart::U64(opened_height),
        ],
        32,
    )
}

pub fn domain_list_root(domains: &[ContractDomain]) -> String {
    let records = domains
        .iter()
        .map(|domain| json!({ "domain": domain.as_str() }))
        .collect::<Vec<_>>();
    merkle_root("PQ-DEFI-GUARD-CONTRACT-DOMAINS", &records)
}

pub fn invariant_list_root(invariants: &[InvariantKind]) -> String {
    let records = invariants
        .iter()
        .map(|invariant| json!({ "invariant": invariant.as_str() }))
        .collect::<Vec<_>>();
    merkle_root("PQ-DEFI-GUARD-INVARIANT-LIST", &records)
}

pub fn route_call_graph_root(legs: &[RouteLeg]) -> String {
    let mut edges = Vec::new();
    for pair in legs.windows(2) {
        edges.push(json!({
            "from": pair[0].contract_commitment,
            "from_domain": pair[0].contract_domain.as_str(),
            "to": pair[1].contract_commitment,
            "to_domain": pair[1].contract_domain.as_str(),
        }));
    }
    merkle_root("PQ-DEFI-GUARD-CALL-GRAPH", &edges)
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn validate_legs(legs: &[RouteLeg], max_user_fee_bps: u64) -> Result<()> {
    let mut indexes = BTreeSet::new();
    for (expected, leg) in legs.iter().enumerate() {
        if leg.leg_index as usize != expected {
            return Err(format!(
                "route leg index mismatch: expected {expected}, got {}",
                leg.leg_index
            ));
        }
        if !indexes.insert(leg.leg_index) {
            return Err(format!("duplicate route leg index: {}", leg.leg_index));
        }
        require_nonempty(&leg.contract_commitment, "leg contract commitment")?;
        require_nonempty(&leg.action_commitment, "leg action commitment")?;
        require_nonempty(&leg.input_asset_commitment, "leg input asset commitment")?;
        require_nonempty(&leg.output_asset_commitment, "leg output asset commitment")?;
        require_nonempty(&leg.amount_commitment, "leg amount commitment")?;
        require_nonempty(&leg.witness_policy_root, "leg witness policy root")?;
        if leg.max_fee_bps > max_user_fee_bps {
            return Err(format!(
                "leg fee exceeds route bound: {} > {max_user_fee_bps}",
                leg.max_fee_bps
            ));
        }
    }
    Ok(())
}

fn route_scoped_attestation_root(domain: &str, route_ids: &[String], state: &State) -> String {
    let route_set = route_ids.iter().cloned().collect::<BTreeSet<_>>();
    let records = state
        .invariant_attestations
        .values()
        .filter(|attestation| route_set.contains(&attestation.route_id))
        .map(InvariantAttestation::public_record)
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn map_root<T>(domain: &str, map: &BTreeMap<String, T>) -> String
where
    T: Serialize,
{
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn string_list_root(domain: &str, values: &[String]) -> String {
    let mut sorted = values.to_vec();
    sorted.sort();
    let records = sorted.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn require_nonempty(value: &str, label: &str) -> Result<()> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    if current >= max {
        return Err(format!("{label} capacity exhausted: {current} >= {max}"));
    }
    Ok(())
}
