use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqTokenComplianceRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-token-compliance-runtime-v1";
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-token-compliance-v1";
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_CONFIDENTIAL_PROOF_SCHEME: &str =
    "private-l2-confidential-token-compliance-proof-v1";
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DISCLOSURE_SCHEME: &str =
    "monero-viewkey-selective-disclosure-attestation-v1";
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_SPONSOR_SCHEME: &str =
    "roots-only-low-fee-compliance-sponsor-reservation-v1";
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_BATCH_SCHEME: &str =
    "private-l2-pq-token-transfer-policy-batch-v1";
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_SETTLEMENT_SCHEME: &str =
    "private-l2-pq-token-compliance-settlement-receipt-v1";
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEVNET_HEIGHT: u64 = 436_000;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_L2_NETWORK: &str = "nebula-devnet";
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 262_144;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS: u64 = 8;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_POLICY_TTL_BLOCKS: u64 = 7_200;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_PROOF_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 720;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_DISPUTE_TTL_BLOCKS: u64 = 144;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_POLICIES: usize = 262_144;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_PROOFS: usize = 2_097_152;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_DISCLOSURES: usize = 1_048_576;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize = 1_048_576;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_BATCHES: usize = 262_144;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_BATCH_ITEMS: usize = 16_384;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_DISPUTES: usize = 524_288;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_SETTLEMENTS: usize = 524_288;
pub const PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceTokenClass {
    ConfidentialAsset,
    WrappedMonero,
    StableAsset,
    VaultShare,
    LiquidityReceipt,
    GovernanceNote,
    SyntheticClaim,
    ContractBoundToken,
}

impl ComplianceTokenClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialAsset => "confidential_asset",
            Self::WrappedMonero => "wrapped_monero",
            Self::StableAsset => "stable_asset",
            Self::VaultShare => "vault_share",
            Self::LiquidityReceipt => "liquidity_receipt",
            Self::GovernanceNote => "governance_note",
            Self::SyntheticClaim => "synthetic_claim",
            Self::ContractBoundToken => "contract_bound_token",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyScope {
    Token,
    TransferLane,
    ContractCall,
    DefiPool,
    BridgeRoute,
    Issuer,
    Global,
}

impl PolicyScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::TransferLane => "transfer_lane",
            Self::ContractCall => "contract_call",
            Self::DefiPool => "defi_pool",
            Self::BridgeRoute => "bridge_route",
            Self::Issuer => "issuer",
            Self::Global => "global",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Draft,
    Active,
    GracePeriod,
    Paused,
    Superseded,
    Retired,
}

impl PolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::GracePeriod => "grace_period",
            Self::Paused => "paused",
            Self::Superseded => "superseded",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_proofs(self) -> bool {
        matches!(self, Self::Active | Self::GracePeriod)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferPolicyLane {
    RetailPrivate,
    DefiSettlement,
    ContractCall,
    LiquidityNetting,
    BridgeIn,
    BridgeOut,
    SponsorRebate,
    GovernanceAction,
}

impl TransferPolicyLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RetailPrivate => "retail_private",
            Self::DefiSettlement => "defi_settlement",
            Self::ContractCall => "contract_call",
            Self::LiquidityNetting => "liquidity_netting",
            Self::BridgeIn => "bridge_in",
            Self::BridgeOut => "bridge_out",
            Self::SponsorRebate => "sponsor_rebate",
            Self::GovernanceAction => "governance_action",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceProofKind {
    BalanceConservation,
    SanctionsSetNonMembership,
    JurisdictionRule,
    TravelRuleEnvelope,
    ContractAllowance,
    DefiRiskLimit,
    BridgeMintBurn,
    NullifierFreshness,
}

impl ComplianceProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BalanceConservation => "balance_conservation",
            Self::SanctionsSetNonMembership => "sanctions_set_non_membership",
            Self::JurisdictionRule => "jurisdiction_rule",
            Self::TravelRuleEnvelope => "travel_rule_envelope",
            Self::ContractAllowance => "contract_allowance",
            Self::DefiRiskLimit => "defi_risk_limit",
            Self::BridgeMintBurn => "bridge_mint_burn",
            Self::NullifierFreshness => "nullifier_freshness",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceVerdict {
    Allowed,
    AllowedWithDisclosure,
    Watch,
    Hold,
    Rejected,
}

impl ComplianceVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::AllowedWithDisclosure => "allowed_with_disclosure",
            Self::Watch => "watch",
            Self::Hold => "hold",
            Self::Rejected => "rejected",
        }
    }

    pub fn permits_settlement(self) -> bool {
        matches!(self, Self::Allowed | Self::AllowedWithDisclosure)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    Submitted,
    Verified,
    DisclosureRequired,
    Batched,
    Settled,
    Rejected,
    Expired,
}

impl ProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::DisclosureRequired => "disclosure_required",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Verified | Self::DisclosureRequired
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureAudience {
    IssuerAuditor,
    RegulatorViewKey,
    BridgeCommittee,
    DefiRiskCommittee,
    ContractCounterparty,
    CourtOrder,
}

impl DisclosureAudience {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IssuerAuditor => "issuer_auditor",
            Self::RegulatorViewKey => "regulator_view_key",
            Self::BridgeCommittee => "bridge_committee",
            Self::DefiRiskCommittee => "defi_risk_committee",
            Self::ContractCounterparty => "contract_counterparty",
            Self::CourtOrder => "court_order",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureStatus {
    Attested,
    Accepted,
    Revoked,
    Expired,
}

impl DisclosureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attested => "attested",
            Self::Accepted => "accepted",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
}

impl SponsorReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Proposed,
    PolicyChecked,
    Sponsored,
    Disputed,
    Settled,
    Rejected,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::PolicyChecked => "policy_checked",
            Self::Sponsored => "sponsored",
            Self::Disputed => "disputed",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::Proposed | Self::PolicyChecked | Self::Sponsored)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeReason {
    InvalidPolicyRoot,
    InvalidDisclosure,
    InvalidPqSignature,
    DoubleSpendNullifier,
    FeeOvercharge,
    UnauthorizedContractCall,
    PrivacySetTooSmall,
}

impl DisputeReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidPolicyRoot => "invalid_policy_root",
            Self::InvalidDisclosure => "invalid_disclosure",
            Self::InvalidPqSignature => "invalid_pq_signature",
            Self::DoubleSpendNullifier => "double_spend_nullifier",
            Self::FeeOvercharge => "fee_overcharge",
            Self::UnauthorizedContractCall => "unauthorized_contract_call",
            Self::PrivacySetTooSmall => "privacy_set_too_small",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeVerdict {
    Open,
    ChallengerWins,
    DefenderWins,
    Escalated,
    Expired,
}

impl DisputeVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::ChallengerWins => "challenger_wins",
            Self::DefenderWins => "defender_wins",
            Self::Escalated => "escalated",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Published,
    Finalized,
    Reverted,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Reverted => "reverted",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_sponsor_fee_bps: u64,
    pub policy_ttl_blocks: u64,
    pub proof_ttl_blocks: u64,
    pub disclosure_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub dispute_ttl_blocks: u64,
    pub max_policies: usize,
    pub max_proofs: usize,
    pub max_disclosures: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_batch_items: usize,
    pub max_disputes: usize,
    pub max_settlements: usize,
    pub require_pq_authorization: bool,
    pub require_selective_disclosure_for_watch: bool,
    pub enable_low_fee_sponsors: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_L2_NETWORK.to_string(),
            monero_network: PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MONERO_NETWORK
                .to_string(),
            fee_asset_id: PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_FEE_ASSET_ID.to_string(),
            min_privacy_set_size:
                PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_sponsor_fee_bps: PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_SPONSOR_FEE_BPS,
            policy_ttl_blocks: PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_POLICY_TTL_BLOCKS,
            proof_ttl_blocks: PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_PROOF_TTL_BLOCKS,
            disclosure_ttl_blocks:
                PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_DISCLOSURE_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            batch_ttl_blocks: PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            dispute_ttl_blocks: PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_DISPUTE_TTL_BLOCKS,
            max_policies: PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_POLICIES,
            max_proofs: PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_PROOFS,
            max_disclosures: PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_DISCLOSURES,
            max_reservations: PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_BATCHES,
            max_batch_items: PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            max_disputes: PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_DISPUTES,
            max_settlements: PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MAX_SETTLEMENTS,
            require_pq_authorization: true,
            require_selective_disclosure_for_watch: true,
            enable_low_fee_sponsors: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> PrivateL2PqTokenComplianceRuntimeResult<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("l2_network", &self.l2_network)?;
        ensure_non_empty("monero_network", &self.monero_network)?;
        ensure_non_empty("fee_asset_id", &self.fee_asset_id)?;
        ensure_min("min_privacy_set_size", self.min_privacy_set_size, 1)?;
        ensure_min(
            "batch_privacy_set_size",
            self.batch_privacy_set_size,
            self.min_privacy_set_size,
        )?;
        ensure_min(
            "min_pq_security_bits",
            self.min_pq_security_bits as u64,
            PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS as u64,
        )?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("max_sponsor_fee_bps", self.max_sponsor_fee_bps)?;
        ensure_min("policy_ttl_blocks", self.policy_ttl_blocks, 1)?;
        ensure_min("proof_ttl_blocks", self.proof_ttl_blocks, 1)?;
        ensure_min("disclosure_ttl_blocks", self.disclosure_ttl_blocks, 1)?;
        ensure_min("reservation_ttl_blocks", self.reservation_ttl_blocks, 1)?;
        ensure_min("batch_ttl_blocks", self.batch_ttl_blocks, 1)?;
        ensure_min("dispute_ttl_blocks", self.dispute_ttl_blocks, 1)?;
        ensure_capacity("max_policies", self.max_policies)?;
        ensure_capacity("max_proofs", self.max_proofs)?;
        ensure_capacity("max_disclosures", self.max_disclosures)?;
        ensure_capacity("max_reservations", self.max_reservations)?;
        ensure_capacity("max_batches", self.max_batches)?;
        ensure_capacity("max_batch_items", self.max_batch_items)?;
        ensure_capacity("max_disputes", self.max_disputes)?;
        ensure_capacity("max_settlements", self.max_settlements)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_token_compliance_config",
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "policy_ttl_blocks": self.policy_ttl_blocks,
            "proof_ttl_blocks": self.proof_ttl_blocks,
            "disclosure_ttl_blocks": self.disclosure_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "dispute_ttl_blocks": self.dispute_ttl_blocks,
            "max_policies": self.max_policies,
            "max_proofs": self.max_proofs,
            "max_disclosures": self.max_disclosures,
            "max_reservations": self.max_reservations,
            "max_batches": self.max_batches,
            "max_batch_items": self.max_batch_items,
            "max_disputes": self.max_disputes,
            "max_settlements": self.max_settlements,
            "require_pq_authorization": self.require_pq_authorization,
            "require_selective_disclosure_for_watch": self.require_selective_disclosure_for_watch,
            "enable_low_fee_sponsors": self.enable_low_fee_sponsors,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-PQ-TOKEN-COMPLIANCE-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub policy_count: u64,
    pub proof_count: u64,
    pub disclosure_count: u64,
    pub sponsor_reservation_count: u64,
    pub batch_count: u64,
    pub dispute_count: u64,
    pub settlement_count: u64,
    pub public_record_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_token_compliance_counters",
            "policy_count": self.policy_count,
            "proof_count": self.proof_count,
            "disclosure_count": self.disclosure_count,
            "sponsor_reservation_count": self.sponsor_reservation_count,
            "batch_count": self.batch_count,
            "dispute_count": self.dispute_count,
            "settlement_count": self.settlement_count,
            "public_record_count": self.public_record_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub policy_root: String,
    pub proof_root: String,
    pub disclosure_root: String,
    pub sponsor_reservation_root: String,
    pub batch_root: String,
    pub dispute_root: String,
    pub settlement_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_token_compliance_roots",
            "policy_root": self.policy_root,
            "proof_root": self.proof_root,
            "disclosure_root": self.disclosure_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "batch_root": self.batch_root,
            "dispute_root": self.dispute_root,
            "settlement_root": self.settlement_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-PQ-TOKEN-COMPLIANCE-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterPqTokenPolicyRequest {
    pub token_id: String,
    pub token_class: ComplianceTokenClass,
    pub scope: PolicyScope,
    pub scope_id: String,
    pub issuer_commitment: String,
    pub policy_commitment_root: String,
    pub allowed_lane_roots: Vec<String>,
    pub contract_policy_roots: Vec<String>,
    pub risk_rule_root: String,
    pub disclosure_rule_root: String,
    pub max_user_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub activation_height: u64,
    pub expires_at_height: u64,
    pub pq_authorization_root: String,
}

impl RegisterPqTokenPolicyRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "token_id": self.token_id,
            "token_class": self.token_class.as_str(),
            "scope": self.scope.as_str(),
            "scope_id": self.scope_id,
            "issuer_commitment": self.issuer_commitment,
            "policy_commitment_root": self.policy_commitment_root,
            "allowed_lane_roots": self.allowed_lane_roots,
            "contract_policy_roots": self.contract_policy_roots,
            "risk_rule_root": self.risk_rule_root,
            "disclosure_rule_root": self.disclosure_rule_root,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "activation_height": self.activation_height,
            "expires_at_height": self.expires_at_height,
            "pq_authorization_root": self.pq_authorization_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqTokenPolicyRecord {
    pub policy_id: String,
    pub request: RegisterPqTokenPolicyRequest,
    pub status: PolicyStatus,
    pub registered_at_height: u64,
}

impl PqTokenPolicyRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_token_policy_record",
            "policy_id": self.policy_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "registered_at_height": self.registered_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitConfidentialComplianceProofRequest {
    pub transfer_id: String,
    pub policy_id: String,
    pub token_id: String,
    pub lane: TransferPolicyLane,
    pub proof_kind: ComplianceProofKind,
    pub sender_commitment: String,
    pub receiver_commitment: String,
    pub contract_commitment: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub nullifier_root: String,
    pub amount_commitment_root: String,
    pub compliance_proof_root: String,
    pub pq_signature_root: String,
    pub disclosure_hint_root: String,
    pub privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub expires_at_height: u64,
}

impl SubmitConfidentialComplianceProofRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "transfer_id": self.transfer_id,
            "policy_id": self.policy_id,
            "token_id": self.token_id,
            "lane": self.lane.as_str(),
            "proof_kind": self.proof_kind.as_str(),
            "sender_commitment": self.sender_commitment,
            "receiver_commitment": self.receiver_commitment,
            "contract_commitment": self.contract_commitment,
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "nullifier_root": self.nullifier_root,
            "amount_commitment_root": self.amount_commitment_root,
            "compliance_proof_root": self.compliance_proof_root,
            "pq_signature_root": self.pq_signature_root,
            "disclosure_hint_root": self.disclosure_hint_root,
            "privacy_set_size": self.privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialComplianceProofRecord {
    pub proof_id: String,
    pub request: SubmitConfidentialComplianceProofRequest,
    pub verdict: ComplianceVerdict,
    pub status: ProofStatus,
    pub submitted_at_height: u64,
}

impl ConfidentialComplianceProofRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_compliance_proof_record",
            "proof_id": self.proof_id,
            "request": self.request.public_record(),
            "verdict": self.verdict.as_str(),
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestSelectiveDisclosureRequest {
    pub proof_id: String,
    pub audience: DisclosureAudience,
    pub auditor_commitment: String,
    pub view_tag_root: String,
    pub disclosed_field_root: String,
    pub encrypted_payload_root: String,
    pub warrant_or_policy_root: String,
    pub pq_attestation_root: String,
    pub expires_at_height: u64,
}

impl AttestSelectiveDisclosureRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "audience": self.audience.as_str(),
            "auditor_commitment": self.auditor_commitment,
            "view_tag_root": self.view_tag_root,
            "disclosed_field_root": self.disclosed_field_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "warrant_or_policy_root": self.warrant_or_policy_root,
            "pq_attestation_root": self.pq_attestation_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectiveDisclosureAttestationRecord {
    pub disclosure_id: String,
    pub request: AttestSelectiveDisclosureRequest,
    pub status: DisclosureStatus,
    pub attested_at_height: u64,
}

impl SelectiveDisclosureAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "selective_disclosure_attestation_record",
            "disclosure_id": self.disclosure_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveComplianceSponsorRequest {
    pub proof_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub budget_root: String,
    pub max_sponsor_fee_bps: u64,
    pub sponsored_gas_units: u64,
    pub refund_commitment_root: String,
    pub pq_authorization_root: String,
    pub expires_at_height: u64,
}

impl ReserveComplianceSponsorRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "proof_id": self.proof_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "budget_root": self.budget_root,
            "max_sponsor_fee_bps": self.max_sponsor_fee_bps,
            "sponsored_gas_units": self.sponsored_gas_units,
            "refund_commitment_root": self.refund_commitment_root,
            "pq_authorization_root": self.pq_authorization_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceSponsorReservationRecord {
    pub reservation_id: String,
    pub request: ReserveComplianceSponsorRequest,
    pub status: SponsorReservationStatus,
    pub reserved_at_height: u64,
}

impl ComplianceSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compliance_sponsor_reservation_record",
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "reserved_at_height": self.reserved_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildTransferPolicyBatchRequest {
    pub batch_operator_commitment: String,
    pub lane: TransferPolicyLane,
    pub proof_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub aggregate_policy_root: String,
    pub aggregate_disclosure_root: String,
    pub aggregate_nullifier_root: String,
    pub aggregate_fee_root: String,
    pub recursive_proof_root: String,
    pub pq_batch_signature_root: String,
    pub privacy_set_size: u64,
    pub expires_at_height: u64,
}

impl BuildTransferPolicyBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_operator_commitment": self.batch_operator_commitment,
            "lane": self.lane.as_str(),
            "proof_ids": self.proof_ids,
            "reservation_ids": self.reservation_ids,
            "aggregate_policy_root": self.aggregate_policy_root,
            "aggregate_disclosure_root": self.aggregate_disclosure_root,
            "aggregate_nullifier_root": self.aggregate_nullifier_root,
            "aggregate_fee_root": self.aggregate_fee_root,
            "recursive_proof_root": self.recursive_proof_root,
            "pq_batch_signature_root": self.pq_batch_signature_root,
            "privacy_set_size": self.privacy_set_size,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferPolicyBatchRecord {
    pub batch_id: String,
    pub request: BuildTransferPolicyBatchRequest,
    pub status: BatchStatus,
    pub built_at_height: u64,
}

impl TransferPolicyBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "transfer_policy_batch_record",
            "batch_id": self.batch_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "built_at_height": self.built_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenComplianceDisputeRequest {
    pub batch_id: String,
    pub challenger_commitment: String,
    pub reason: DisputeReason,
    pub disputed_proof_ids: Vec<String>,
    pub evidence_root: String,
    pub bond_commitment_root: String,
    pub pq_challenge_signature_root: String,
    pub expires_at_height: u64,
}

impl OpenComplianceDisputeRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "challenger_commitment": self.challenger_commitment,
            "reason": self.reason.as_str(),
            "disputed_proof_ids": self.disputed_proof_ids,
            "evidence_root": self.evidence_root,
            "bond_commitment_root": self.bond_commitment_root,
            "pq_challenge_signature_root": self.pq_challenge_signature_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceDisputeReceipt {
    pub dispute_id: String,
    pub request: OpenComplianceDisputeRequest,
    pub verdict: DisputeVerdict,
    pub opened_at_height: u64,
    pub resolved_at_height: Option<u64>,
}

impl ComplianceDisputeReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compliance_dispute_receipt",
            "dispute_id": self.dispute_id,
            "request": self.request.public_record(),
            "verdict": self.verdict.as_str(),
            "opened_at_height": self.opened_at_height,
            "resolved_at_height": self.resolved_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleComplianceBatchRequest {
    pub batch_id: String,
    pub settlement_operator_commitment: String,
    pub settled_proof_ids: Vec<String>,
    pub consumed_reservation_ids: Vec<String>,
    pub settlement_state_root: String,
    pub settlement_event_root: String,
    pub fee_debit_root: String,
    pub pq_finality_signature_root: String,
}

impl SettleComplianceBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "settlement_operator_commitment": self.settlement_operator_commitment,
            "settled_proof_ids": self.settled_proof_ids,
            "consumed_reservation_ids": self.consumed_reservation_ids,
            "settlement_state_root": self.settlement_state_root,
            "settlement_event_root": self.settlement_event_root,
            "fee_debit_root": self.fee_debit_root,
            "pq_finality_signature_root": self.pq_finality_signature_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceSettlementReceipt {
    pub settlement_id: String,
    pub request: SettleComplianceBatchRequest,
    pub status: SettlementStatus,
    pub settled_at_height: u64,
}

impl ComplianceSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compliance_settlement_receipt",
            "settlement_id": self.settlement_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicComplianceRecord {
    pub record_id: String,
    pub object_kind: String,
    pub object_id: String,
    pub sequence: u64,
    pub payload_root: String,
    pub payload: Value,
}

impl PublicComplianceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_token_compliance_public_record",
            "record_id": self.record_id,
            "object_kind": self.object_kind,
            "object_id": self.object_id,
            "sequence": self.sequence,
            "payload_root": self.payload_root,
            "payload": self.payload,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub policies: BTreeMap<String, PqTokenPolicyRecord>,
    pub proofs: BTreeMap<String, ConfidentialComplianceProofRecord>,
    pub disclosures: BTreeMap<String, SelectiveDisclosureAttestationRecord>,
    pub reservations: BTreeMap<String, ComplianceSponsorReservationRecord>,
    pub batches: BTreeMap<String, TransferPolicyBatchRecord>,
    pub disputes: BTreeMap<String, ComplianceDisputeReceipt>,
    pub settlements: BTreeMap<String, ComplianceSettlementReceipt>,
    pub seen_nullifier_roots: BTreeSet<String>,
    pub public_records: BTreeMap<String, PublicComplianceRecord>,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn devnet() -> Self {
        Self::new(
            Config::devnet(),
            PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DEVNET_HEIGHT,
        )
        .expect("devnet config is valid")
    }

    pub fn new(
        config: Config,
        current_height: u64,
    ) -> PrivateL2PqTokenComplianceRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            current_height,
            policies: BTreeMap::new(),
            proofs: BTreeMap::new(),
            disclosures: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            disputes: BTreeMap::new(),
            settlements: BTreeMap::new(),
            seen_nullifier_roots: BTreeSet::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn set_height(&mut self, current_height: u64) {
        self.current_height = current_height;
    }

    pub fn register_pq_token_policy(
        &mut self,
        request: RegisterPqTokenPolicyRequest,
    ) -> PrivateL2PqTokenComplianceRuntimeResult<PqTokenPolicyRecord> {
        if self.policies.len() >= self.config.max_policies {
            return Err("policy registry capacity exceeded".to_string());
        }
        validate_policy_request(&self.config, &request, self.current_height)?;
        let counter = self.policies.len() as u64;
        let policy_id = pq_token_policy_id(&request, counter);
        if self.policies.contains_key(&policy_id) {
            return Err("duplicate policy id".to_string());
        }
        let record = PqTokenPolicyRecord {
            policy_id,
            request,
            status: PolicyStatus::Active,
            registered_at_height: self.current_height,
        };
        self.publish_public_record("policy", &record.policy_id, &record.public_record())?;
        self.policies
            .insert(record.policy_id.clone(), record.clone());
        Ok(record)
    }

    pub fn submit_confidential_compliance_proof(
        &mut self,
        request: SubmitConfidentialComplianceProofRequest,
        verdict: ComplianceVerdict,
    ) -> PrivateL2PqTokenComplianceRuntimeResult<ConfidentialComplianceProofRecord> {
        if self.proofs.len() >= self.config.max_proofs {
            return Err("compliance proof capacity exceeded".to_string());
        }
        validate_proof_request(&self.config, &self.policies, &request, self.current_height)?;
        if self.seen_nullifier_roots.contains(&request.nullifier_root) {
            return Err("duplicate nullifier root".to_string());
        }
        let counter = self.proofs.len() as u64;
        let proof_id = confidential_compliance_proof_id(&request, counter);
        let status = if verdict == ComplianceVerdict::AllowedWithDisclosure
            || (verdict == ComplianceVerdict::Watch
                && self.config.require_selective_disclosure_for_watch)
        {
            ProofStatus::DisclosureRequired
        } else if verdict.permits_settlement() {
            ProofStatus::Verified
        } else {
            ProofStatus::Rejected
        };
        let record = ConfidentialComplianceProofRecord {
            proof_id,
            request,
            verdict,
            status,
            submitted_at_height: self.current_height,
        };
        self.seen_nullifier_roots
            .insert(record.request.nullifier_root.clone());
        self.publish_public_record("proof", &record.proof_id, &record.public_record())?;
        self.proofs.insert(record.proof_id.clone(), record.clone());
        Ok(record)
    }

    pub fn attest_selective_disclosure(
        &mut self,
        request: AttestSelectiveDisclosureRequest,
    ) -> PrivateL2PqTokenComplianceRuntimeResult<SelectiveDisclosureAttestationRecord> {
        if self.disclosures.len() >= self.config.max_disclosures {
            return Err("selective disclosure capacity exceeded".to_string());
        }
        validate_disclosure_request(&self.config, &self.proofs, &request, self.current_height)?;
        let counter = self.disclosures.len() as u64;
        let disclosure_id = selective_disclosure_attestation_id(&request, counter);
        let record = SelectiveDisclosureAttestationRecord {
            disclosure_id,
            request,
            status: DisclosureStatus::Attested,
            attested_at_height: self.current_height,
        };
        if let Some(proof) = self.proofs.get_mut(&record.request.proof_id) {
            if proof.status == ProofStatus::DisclosureRequired {
                proof.status = ProofStatus::Verified;
            }
        }
        self.publish_public_record("disclosure", &record.disclosure_id, &record.public_record())?;
        self.disclosures
            .insert(record.disclosure_id.clone(), record.clone());
        Ok(record)
    }

    pub fn reserve_compliance_sponsor(
        &mut self,
        request: ReserveComplianceSponsorRequest,
    ) -> PrivateL2PqTokenComplianceRuntimeResult<ComplianceSponsorReservationRecord> {
        if !self.config.enable_low_fee_sponsors {
            return Err("low-fee compliance sponsors are disabled".to_string());
        }
        if self.reservations.len() >= self.config.max_reservations {
            return Err("sponsor reservation capacity exceeded".to_string());
        }
        validate_sponsor_request(&self.config, &self.proofs, &request, self.current_height)?;
        let counter = self.reservations.len() as u64;
        let reservation_id = compliance_sponsor_reservation_id(&request, counter);
        let record = ComplianceSponsorReservationRecord {
            reservation_id,
            request,
            status: SponsorReservationStatus::Reserved,
            reserved_at_height: self.current_height,
        };
        self.publish_public_record(
            "sponsor_reservation",
            &record.reservation_id,
            &record.public_record(),
        )?;
        self.reservations
            .insert(record.reservation_id.clone(), record.clone());
        Ok(record)
    }

    pub fn build_transfer_policy_batch(
        &mut self,
        request: BuildTransferPolicyBatchRequest,
    ) -> PrivateL2PqTokenComplianceRuntimeResult<TransferPolicyBatchRecord> {
        if self.batches.len() >= self.config.max_batches {
            return Err("transfer policy batch capacity exceeded".to_string());
        }
        validate_batch_request(
            &self.config,
            &self.proofs,
            &self.reservations,
            &request,
            self.current_height,
        )?;
        let counter = self.batches.len() as u64;
        let batch_id = transfer_policy_batch_id(&request, counter);
        let has_sponsor = !request.reservation_ids.is_empty();
        let record = TransferPolicyBatchRecord {
            batch_id,
            request,
            status: if has_sponsor {
                BatchStatus::Sponsored
            } else {
                BatchStatus::PolicyChecked
            },
            built_at_height: self.current_height,
        };
        for proof_id in &record.request.proof_ids {
            if let Some(proof) = self.proofs.get_mut(proof_id) {
                proof.status = ProofStatus::Batched;
            }
        }
        self.publish_public_record("batch", &record.batch_id, &record.public_record())?;
        self.batches.insert(record.batch_id.clone(), record.clone());
        Ok(record)
    }

    pub fn open_compliance_dispute(
        &mut self,
        request: OpenComplianceDisputeRequest,
    ) -> PrivateL2PqTokenComplianceRuntimeResult<ComplianceDisputeReceipt> {
        if self.disputes.len() >= self.config.max_disputes {
            return Err("dispute receipt capacity exceeded".to_string());
        }
        validate_dispute_request(&self.config, &self.batches, &request, self.current_height)?;
        let counter = self.disputes.len() as u64;
        let dispute_id = compliance_dispute_receipt_id(&request, counter);
        let record = ComplianceDisputeReceipt {
            dispute_id,
            request,
            verdict: DisputeVerdict::Open,
            opened_at_height: self.current_height,
            resolved_at_height: None,
        };
        if let Some(batch) = self.batches.get_mut(&record.request.batch_id) {
            batch.status = BatchStatus::Disputed;
        }
        self.publish_public_record("dispute", &record.dispute_id, &record.public_record())?;
        self.disputes
            .insert(record.dispute_id.clone(), record.clone());
        Ok(record)
    }

    pub fn resolve_compliance_dispute(
        &mut self,
        dispute_id: &str,
        verdict: DisputeVerdict,
    ) -> PrivateL2PqTokenComplianceRuntimeResult<ComplianceDisputeReceipt> {
        if verdict == DisputeVerdict::Open {
            return Err("resolved dispute verdict cannot be open".to_string());
        }
        let mut record = self
            .disputes
            .get(dispute_id)
            .cloned()
            .ok_or_else(|| "unknown dispute id".to_string())?;
        record.verdict = verdict;
        record.resolved_at_height = Some(self.current_height);
        if let Some(batch) = self.batches.get_mut(&record.request.batch_id) {
            batch.status = match verdict {
                DisputeVerdict::ChallengerWins => BatchStatus::Rejected,
                DisputeVerdict::DefenderWins => BatchStatus::PolicyChecked,
                DisputeVerdict::Escalated | DisputeVerdict::Expired | DisputeVerdict::Open => {
                    BatchStatus::Disputed
                }
            };
        }
        self.publish_public_record(
            "dispute_resolution",
            &record.dispute_id,
            &record.public_record(),
        )?;
        self.disputes
            .insert(record.dispute_id.clone(), record.clone());
        Ok(record)
    }

    pub fn settle_compliance_batch(
        &mut self,
        request: SettleComplianceBatchRequest,
    ) -> PrivateL2PqTokenComplianceRuntimeResult<ComplianceSettlementReceipt> {
        if self.settlements.len() >= self.config.max_settlements {
            return Err("settlement receipt capacity exceeded".to_string());
        }
        validate_settlement_request(&self.batches, &self.proofs, &self.reservations, &request)?;
        let counter = self.settlements.len() as u64;
        let settlement_id = compliance_settlement_receipt_id(&request, counter);
        let record = ComplianceSettlementReceipt {
            settlement_id,
            request,
            status: SettlementStatus::Published,
            settled_at_height: self.current_height,
        };
        if let Some(batch) = self.batches.get_mut(&record.request.batch_id) {
            batch.status = BatchStatus::Settled;
        }
        for proof_id in &record.request.settled_proof_ids {
            if let Some(proof) = self.proofs.get_mut(proof_id) {
                proof.status = ProofStatus::Settled;
            }
        }
        for reservation_id in &record.request.consumed_reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = SponsorReservationStatus::Consumed;
            }
        }
        self.publish_public_record("settlement", &record.settlement_id, &record.public_record())?;
        self.settlements
            .insert(record.settlement_id.clone(), record.clone());
        Ok(record)
    }

    pub fn counters(&self) -> Counters {
        Counters {
            policy_count: self.policies.len() as u64,
            proof_count: self.proofs.len() as u64,
            disclosure_count: self.disclosures.len() as u64,
            sponsor_reservation_count: self.reservations.len() as u64,
            batch_count: self.batches.len() as u64,
            dispute_count: self.disputes.len() as u64,
            settlement_count: self.settlements.len() as u64,
            public_record_count: self.public_records.len() as u64,
        }
    }

    pub fn roots(&self) -> Roots {
        let policy_records = values_public_records(&self.policies);
        let proof_records = values_public_records(&self.proofs);
        let disclosure_records = values_public_records(&self.disclosures);
        let reservation_records = values_public_records(&self.reservations);
        let batch_records = values_public_records(&self.batches);
        let dispute_records = values_public_records(&self.disputes);
        let settlement_records = values_public_records(&self.settlements);
        let nullifier_records = self
            .seen_nullifier_roots
            .iter()
            .map(|root| json!({ "nullifier_root": root }))
            .collect::<Vec<_>>();
        let public_records = values_public_records(&self.public_records);
        Roots {
            policy_root: merkle_root("PRIVATE-L2-PQ-TOKEN-COMPLIANCE-POLICY", &policy_records),
            proof_root: merkle_root("PRIVATE-L2-PQ-TOKEN-COMPLIANCE-PROOF", &proof_records),
            disclosure_root: merkle_root(
                "PRIVATE-L2-PQ-TOKEN-COMPLIANCE-DISCLOSURE",
                &disclosure_records,
            ),
            sponsor_reservation_root: merkle_root(
                "PRIVATE-L2-PQ-TOKEN-COMPLIANCE-SPONSOR",
                &reservation_records,
            ),
            batch_root: merkle_root("PRIVATE-L2-PQ-TOKEN-COMPLIANCE-BATCH", &batch_records),
            dispute_root: merkle_root("PRIVATE-L2-PQ-TOKEN-COMPLIANCE-DISPUTE", &dispute_records),
            settlement_root: merkle_root(
                "PRIVATE-L2-PQ-TOKEN-COMPLIANCE-SETTLEMENT",
                &settlement_records,
            ),
            nullifier_root: merkle_root(
                "PRIVATE-L2-PQ-TOKEN-COMPLIANCE-NULLIFIER",
                &nullifier_records,
            ),
            public_record_root: merkle_root(
                "PRIVATE-L2-PQ-TOKEN-COMPLIANCE-PUBLIC-RECORD",
                &public_records,
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_pq_token_compliance_runtime",
            "protocol_version": PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_HASH_SUITE,
            "pq_auth_suite": PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_PQ_AUTH_SUITE,
            "confidential_proof_scheme": PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_CONFIDENTIAL_PROOF_SCHEME,
            "disclosure_scheme": PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_DISCLOSURE_SCHEME,
            "sponsor_scheme": PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_SPONSOR_SCHEME,
            "batch_scheme": PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_BATCH_SCHEME,
            "settlement_scheme": PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_SETTLEMENT_SCHEME,
            "config": self.config.public_record(),
            "config_root": self.config.state_root(),
            "counters": self.counters().public_record(),
            "current_height": self.current_height,
            "roots": roots.public_record(),
            "roots_state_root": roots.state_root(),
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        let state_root = root_from_record("PRIVATE-L2-PQ-TOKEN-COMPLIANCE-STATE", &record);
        json!({
            "state_root": state_root,
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "PRIVATE-L2-PQ-TOKEN-COMPLIANCE-STATE",
            &self.public_record_without_state_root(),
        )
    }

    fn publish_public_record(
        &mut self,
        object_kind: &str,
        object_id: &str,
        payload: &Value,
    ) -> PrivateL2PqTokenComplianceRuntimeResult<PublicComplianceRecord> {
        let sequence = self.public_records.len() as u64;
        let payload_root = payload_root("PRIVATE-L2-PQ-TOKEN-COMPLIANCE-PUBLIC-PAYLOAD", payload);
        let record_id =
            public_compliance_record_id(object_kind, object_id, sequence, &payload_root);
        let record = PublicComplianceRecord {
            record_id,
            object_kind: object_kind.to_string(),
            object_id: object_id.to_string(),
            sequence,
            payload_root,
            payload: payload.clone(),
        };
        self.public_records
            .insert(record.record_id.clone(), record.clone());
        Ok(record)
    }
}

pub type Runtime = State;

pub fn pq_token_policy_id(request: &RegisterPqTokenPolicyRequest, counter: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-TOKEN-COMPLIANCE-POLICY-ID",
        &[
            HashPart::Str(&request.token_id),
            HashPart::Str(request.token_class.as_str()),
            HashPart::Str(request.scope.as_str()),
            HashPart::Str(&request.scope_id),
            HashPart::Str(&request.policy_commitment_root),
            HashPart::Str(&request.pq_authorization_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn confidential_compliance_proof_id(
    request: &SubmitConfidentialComplianceProofRequest,
    counter: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-TOKEN-COMPLIANCE-PROOF-ID",
        &[
            HashPart::Str(&request.transfer_id),
            HashPart::Str(&request.policy_id),
            HashPart::Str(&request.token_id),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.nullifier_root),
            HashPart::Str(&request.compliance_proof_root),
            HashPart::Str(&request.pq_signature_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn selective_disclosure_attestation_id(
    request: &AttestSelectiveDisclosureRequest,
    counter: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-TOKEN-COMPLIANCE-DISCLOSURE-ID",
        &[
            HashPart::Str(&request.proof_id),
            HashPart::Str(request.audience.as_str()),
            HashPart::Str(&request.auditor_commitment),
            HashPart::Str(&request.view_tag_root),
            HashPart::Str(&request.encrypted_payload_root),
            HashPart::Str(&request.pq_attestation_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn compliance_sponsor_reservation_id(
    request: &ReserveComplianceSponsorRequest,
    counter: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-TOKEN-COMPLIANCE-SPONSOR-ID",
        &[
            HashPart::Str(&request.proof_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.fee_asset_id),
            HashPart::Str(&request.budget_root),
            HashPart::Str(&request.pq_authorization_root),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn transfer_policy_batch_id(request: &BuildTransferPolicyBatchRequest, counter: u64) -> String {
    let request_record = request.public_record();
    domain_hash(
        "PRIVATE-L2-PQ-TOKEN-COMPLIANCE-BATCH-ID",
        &[
            HashPart::Json(&request_record),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn compliance_dispute_receipt_id(
    request: &OpenComplianceDisputeRequest,
    counter: u64,
) -> String {
    let request_record = request.public_record();
    domain_hash(
        "PRIVATE-L2-PQ-TOKEN-COMPLIANCE-DISPUTE-ID",
        &[
            HashPart::Json(&request_record),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn compliance_settlement_receipt_id(
    request: &SettleComplianceBatchRequest,
    counter: u64,
) -> String {
    let request_record = request.public_record();
    domain_hash(
        "PRIVATE-L2-PQ-TOKEN-COMPLIANCE-SETTLEMENT-ID",
        &[
            HashPart::Json(&request_record),
            HashPart::Int(counter as i128),
        ],
        32,
    )
}

pub fn public_compliance_record_id(
    object_kind: &str,
    object_id: &str,
    sequence: u64,
    payload_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-TOKEN-COMPLIANCE-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(object_kind),
            HashPart::Str(object_id),
            HashPart::Int(sequence as i128),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

trait PublicRecordValue {
    fn as_public_record_value(&self) -> Value;
}

impl PublicRecordValue for PqTokenPolicyRecord {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecordValue for ConfidentialComplianceProofRecord {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecordValue for SelectiveDisclosureAttestationRecord {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecordValue for ComplianceSponsorReservationRecord {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecordValue for TransferPolicyBatchRecord {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecordValue for ComplianceDisputeReceipt {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecordValue for ComplianceSettlementReceipt {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecordValue for PublicComplianceRecord {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

fn values_public_records<T: PublicRecordValue>(values: &BTreeMap<String, T>) -> Vec<Value> {
    values
        .values()
        .map(PublicRecordValue::as_public_record_value)
        .collect()
}

fn validate_policy_request(
    config: &Config,
    request: &RegisterPqTokenPolicyRequest,
    current_height: u64,
) -> PrivateL2PqTokenComplianceRuntimeResult<()> {
    ensure_non_empty("token_id", &request.token_id)?;
    ensure_non_empty("scope_id", &request.scope_id)?;
    ensure_non_empty("issuer_commitment", &request.issuer_commitment)?;
    ensure_non_empty("policy_commitment_root", &request.policy_commitment_root)?;
    ensure_non_empty("risk_rule_root", &request.risk_rule_root)?;
    ensure_non_empty("disclosure_rule_root", &request.disclosure_rule_root)?;
    ensure_bps("max_user_fee_bps", request.max_user_fee_bps)?;
    if request.max_user_fee_bps > config.max_user_fee_bps {
        return Err("policy user fee exceeds configured cap".to_string());
    }
    ensure_min(
        "policy min_privacy_set_size",
        request.min_privacy_set_size,
        config.min_privacy_set_size,
    )?;
    ensure_min(
        "policy pq_security_bits",
        request.pq_security_bits as u64,
        config.min_pq_security_bits as u64,
    )?;
    if request.expires_at_height <= current_height {
        return Err("policy expiry must be in the future".to_string());
    }
    if request.expires_at_height < request.activation_height {
        return Err("policy expiry precedes activation".to_string());
    }
    if request.expires_at_height - current_height > config.policy_ttl_blocks {
        return Err("policy ttl exceeds configured bound".to_string());
    }
    if config.require_pq_authorization {
        ensure_non_empty("pq_authorization_root", &request.pq_authorization_root)?;
    }
    Ok(())
}

fn validate_proof_request(
    config: &Config,
    policies: &BTreeMap<String, PqTokenPolicyRecord>,
    request: &SubmitConfidentialComplianceProofRequest,
    current_height: u64,
) -> PrivateL2PqTokenComplianceRuntimeResult<()> {
    ensure_non_empty("transfer_id", &request.transfer_id)?;
    ensure_non_empty("policy_id", &request.policy_id)?;
    ensure_non_empty("token_id", &request.token_id)?;
    ensure_non_empty("sender_commitment", &request.sender_commitment)?;
    ensure_non_empty("receiver_commitment", &request.receiver_commitment)?;
    ensure_non_empty("input_note_root", &request.input_note_root)?;
    ensure_non_empty("output_note_root", &request.output_note_root)?;
    ensure_non_empty("nullifier_root", &request.nullifier_root)?;
    ensure_non_empty("amount_commitment_root", &request.amount_commitment_root)?;
    ensure_non_empty("compliance_proof_root", &request.compliance_proof_root)?;
    ensure_bps("max_fee_bps", request.max_fee_bps)?;
    if request.max_fee_bps > config.max_user_fee_bps {
        return Err("proof fee exceeds configured user cap".to_string());
    }
    ensure_min(
        "proof privacy_set_size",
        request.privacy_set_size,
        config.min_privacy_set_size,
    )?;
    if request.expires_at_height <= current_height {
        return Err("proof expiry must be in the future".to_string());
    }
    if request.expires_at_height - current_height > config.proof_ttl_blocks {
        return Err("proof ttl exceeds configured bound".to_string());
    }
    if config.require_pq_authorization {
        ensure_non_empty("pq_signature_root", &request.pq_signature_root)?;
    }
    let policy = policies
        .get(&request.policy_id)
        .ok_or_else(|| "unknown policy id".to_string())?;
    if !policy.status.accepts_proofs() {
        return Err("policy does not accept proofs".to_string());
    }
    if policy.request.token_id != request.token_id {
        return Err("proof token id does not match policy".to_string());
    }
    if policy.request.expires_at_height <= current_height {
        return Err("policy has expired".to_string());
    }
    Ok(())
}

fn validate_disclosure_request(
    config: &Config,
    proofs: &BTreeMap<String, ConfidentialComplianceProofRecord>,
    request: &AttestSelectiveDisclosureRequest,
    current_height: u64,
) -> PrivateL2PqTokenComplianceRuntimeResult<()> {
    ensure_non_empty("proof_id", &request.proof_id)?;
    ensure_non_empty("auditor_commitment", &request.auditor_commitment)?;
    ensure_non_empty("view_tag_root", &request.view_tag_root)?;
    ensure_non_empty("disclosed_field_root", &request.disclosed_field_root)?;
    ensure_non_empty("encrypted_payload_root", &request.encrypted_payload_root)?;
    ensure_non_empty("warrant_or_policy_root", &request.warrant_or_policy_root)?;
    if config.require_pq_authorization {
        ensure_non_empty("pq_attestation_root", &request.pq_attestation_root)?;
    }
    if request.expires_at_height <= current_height {
        return Err("disclosure expiry must be in the future".to_string());
    }
    if request.expires_at_height - current_height > config.disclosure_ttl_blocks {
        return Err("disclosure ttl exceeds configured bound".to_string());
    }
    let proof = proofs
        .get(&request.proof_id)
        .ok_or_else(|| "unknown proof id".to_string())?;
    if proof.status == ProofStatus::Rejected || proof.status == ProofStatus::Expired {
        return Err("proof cannot receive disclosures".to_string());
    }
    Ok(())
}

fn validate_sponsor_request(
    config: &Config,
    proofs: &BTreeMap<String, ConfidentialComplianceProofRecord>,
    request: &ReserveComplianceSponsorRequest,
    current_height: u64,
) -> PrivateL2PqTokenComplianceRuntimeResult<()> {
    ensure_non_empty("proof_id", &request.proof_id)?;
    ensure_non_empty("sponsor_commitment", &request.sponsor_commitment)?;
    ensure_non_empty("fee_asset_id", &request.fee_asset_id)?;
    ensure_non_empty("budget_root", &request.budget_root)?;
    ensure_non_empty("refund_commitment_root", &request.refund_commitment_root)?;
    ensure_bps("max_sponsor_fee_bps", request.max_sponsor_fee_bps)?;
    if request.max_sponsor_fee_bps > config.max_sponsor_fee_bps {
        return Err("sponsor fee exceeds configured cap".to_string());
    }
    ensure_min("sponsored_gas_units", request.sponsored_gas_units, 1)?;
    if config.require_pq_authorization {
        ensure_non_empty("pq_authorization_root", &request.pq_authorization_root)?;
    }
    if request.expires_at_height <= current_height {
        return Err("reservation expiry must be in the future".to_string());
    }
    if request.expires_at_height - current_height > config.reservation_ttl_blocks {
        return Err("reservation ttl exceeds configured bound".to_string());
    }
    let proof = proofs
        .get(&request.proof_id)
        .ok_or_else(|| "unknown proof id".to_string())?;
    if !proof.status.batchable() {
        return Err("proof is not sponsorable".to_string());
    }
    Ok(())
}

fn validate_batch_request(
    config: &Config,
    proofs: &BTreeMap<String, ConfidentialComplianceProofRecord>,
    reservations: &BTreeMap<String, ComplianceSponsorReservationRecord>,
    request: &BuildTransferPolicyBatchRequest,
    current_height: u64,
) -> PrivateL2PqTokenComplianceRuntimeResult<()> {
    ensure_non_empty(
        "batch_operator_commitment",
        &request.batch_operator_commitment,
    )?;
    ensure_non_empty("aggregate_policy_root", &request.aggregate_policy_root)?;
    ensure_non_empty(
        "aggregate_disclosure_root",
        &request.aggregate_disclosure_root,
    )?;
    ensure_non_empty(
        "aggregate_nullifier_root",
        &request.aggregate_nullifier_root,
    )?;
    ensure_non_empty("aggregate_fee_root", &request.aggregate_fee_root)?;
    ensure_non_empty("recursive_proof_root", &request.recursive_proof_root)?;
    if config.require_pq_authorization {
        ensure_non_empty("pq_batch_signature_root", &request.pq_batch_signature_root)?;
    }
    ensure_min(
        "batch privacy_set_size",
        request.privacy_set_size,
        config.batch_privacy_set_size,
    )?;
    if request.proof_ids.is_empty() {
        return Err("batch must include at least one proof".to_string());
    }
    if request.proof_ids.len() > config.max_batch_items {
        return Err("batch item capacity exceeded".to_string());
    }
    if request.expires_at_height <= current_height {
        return Err("batch expiry must be in the future".to_string());
    }
    if request.expires_at_height - current_height > config.batch_ttl_blocks {
        return Err("batch ttl exceeds configured bound".to_string());
    }
    for proof_id in &request.proof_ids {
        let proof = proofs
            .get(proof_id)
            .ok_or_else(|| format!("unknown proof id: {proof_id}"))?;
        if !proof.status.batchable() || !proof.verdict.permits_settlement() {
            return Err(format!("proof is not batchable: {proof_id}"));
        }
    }
    for reservation_id in &request.reservation_ids {
        let reservation = reservations
            .get(reservation_id)
            .ok_or_else(|| format!("unknown reservation id: {reservation_id}"))?;
        if reservation.status != SponsorReservationStatus::Reserved {
            return Err(format!("reservation is not active: {reservation_id}"));
        }
        if !request.proof_ids.contains(&reservation.request.proof_id) {
            return Err(format!(
                "reservation does not sponsor a batch proof: {reservation_id}"
            ));
        }
    }
    Ok(())
}

fn validate_dispute_request(
    config: &Config,
    batches: &BTreeMap<String, TransferPolicyBatchRecord>,
    request: &OpenComplianceDisputeRequest,
    current_height: u64,
) -> PrivateL2PqTokenComplianceRuntimeResult<()> {
    ensure_non_empty("batch_id", &request.batch_id)?;
    ensure_non_empty("challenger_commitment", &request.challenger_commitment)?;
    ensure_non_empty("evidence_root", &request.evidence_root)?;
    ensure_non_empty("bond_commitment_root", &request.bond_commitment_root)?;
    if config.require_pq_authorization {
        ensure_non_empty(
            "pq_challenge_signature_root",
            &request.pq_challenge_signature_root,
        )?;
    }
    if request.disputed_proof_ids.is_empty() {
        return Err("dispute must identify at least one proof".to_string());
    }
    if request.expires_at_height <= current_height {
        return Err("dispute expiry must be in the future".to_string());
    }
    if request.expires_at_height - current_height > config.dispute_ttl_blocks {
        return Err("dispute ttl exceeds configured bound".to_string());
    }
    let batch = batches
        .get(&request.batch_id)
        .ok_or_else(|| "unknown batch id".to_string())?;
    if !batch.status.can_settle() {
        return Err("batch cannot be disputed in its current status".to_string());
    }
    for proof_id in &request.disputed_proof_ids {
        if !batch.request.proof_ids.contains(proof_id) {
            return Err(format!("disputed proof is not in batch: {proof_id}"));
        }
    }
    Ok(())
}

fn validate_settlement_request(
    batches: &BTreeMap<String, TransferPolicyBatchRecord>,
    proofs: &BTreeMap<String, ConfidentialComplianceProofRecord>,
    reservations: &BTreeMap<String, ComplianceSponsorReservationRecord>,
    request: &SettleComplianceBatchRequest,
) -> PrivateL2PqTokenComplianceRuntimeResult<()> {
    ensure_non_empty("batch_id", &request.batch_id)?;
    ensure_non_empty(
        "settlement_operator_commitment",
        &request.settlement_operator_commitment,
    )?;
    ensure_non_empty("settlement_state_root", &request.settlement_state_root)?;
    ensure_non_empty("settlement_event_root", &request.settlement_event_root)?;
    ensure_non_empty("fee_debit_root", &request.fee_debit_root)?;
    ensure_non_empty(
        "pq_finality_signature_root",
        &request.pq_finality_signature_root,
    )?;
    let batch = batches
        .get(&request.batch_id)
        .ok_or_else(|| "unknown batch id".to_string())?;
    if !batch.status.can_settle() {
        return Err("batch is not settlement-ready".to_string());
    }
    if request.settled_proof_ids.is_empty() {
        return Err("settlement must include at least one proof".to_string());
    }
    for proof_id in &request.settled_proof_ids {
        if !batch.request.proof_ids.contains(proof_id) {
            return Err(format!("settled proof is not in batch: {proof_id}"));
        }
        let proof = proofs
            .get(proof_id)
            .ok_or_else(|| format!("unknown proof id: {proof_id}"))?;
        if !proof.verdict.permits_settlement() {
            return Err(format!(
                "proof verdict does not permit settlement: {proof_id}"
            ));
        }
    }
    for reservation_id in &request.consumed_reservation_ids {
        if !batch.request.reservation_ids.contains(reservation_id) {
            return Err(format!(
                "consumed reservation is not in batch: {reservation_id}"
            ));
        }
        let reservation = reservations
            .get(reservation_id)
            .ok_or_else(|| format!("unknown reservation id: {reservation_id}"))?;
        if reservation.status != SponsorReservationStatus::Reserved {
            return Err(format!("reservation is not consumable: {reservation_id}"));
        }
    }
    Ok(())
}

fn ensure_non_empty(name: &str, value: &str) -> PrivateL2PqTokenComplianceRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_min(name: &str, value: u64, min: u64) -> PrivateL2PqTokenComplianceRuntimeResult<()> {
    if value < min {
        Err(format!("{name} must be at least {min}"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(name: &str, value: usize) -> PrivateL2PqTokenComplianceRuntimeResult<()> {
    if value == 0 {
        Err(format!("{name} must be greater than zero"))
    } else {
        Ok(())
    }
}

fn ensure_bps(name: &str, value: u64) -> PrivateL2PqTokenComplianceRuntimeResult<()> {
    if value > PRIVATE_L2_PQ_TOKEN_COMPLIANCE_RUNTIME_MAX_BPS {
        Err(format!("{name} exceeds basis-point maximum"))
    } else {
        Ok(())
    }
}
