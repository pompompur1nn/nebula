use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_FACTORY_GOVERNANCE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-token-factory-governance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_FACTORY_GOVERNANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_568_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_GOVERNANCE_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-token-factory-governance-v1";
pub const CONFIDENTIAL_TOKEN_SUITE: &str =
    "RingCT-token-class+amount-policy-root+nullifier-fence-v1";
pub const SEALED_VOTE_SUITE: &str =
    "sealed-ballot-commitment+nullifier-keyed-tally+view-audit-share-v1";
pub const LOW_FEE_SPONSOR_SUITE: &str =
    "low-fee-launch-sponsor+recursive-proof-rebate+paymaster-lane-v1";
pub const DEFI_INTEGRATION_SUITE: &str =
    "amm+lending+perps+vault-router+intent-solver-confidential-token-v1";
pub const COVENANT_HOOK_SUITE: &str =
    "contract-governed-covenant-hook+compliance-proof-carrying-data-v1";
pub const TREASURY_TIMELOCK_SUITE: &str = "confidential-governed-treasury-timelock-v1";
pub const SLASHING_EVIDENCE_SUITE: &str =
    "pq-attestation-equivocation+sealed-vote-nullifier-double-use-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_PROPOSAL_TTL_BLOCKS: u64 = 86_400;
pub const DEFAULT_VOTING_PERIOD_BLOCKS: u64 = 21_600;
pub const DEFAULT_EXECUTION_DELAY_BLOCKS: u64 = 7_200;
pub const DEFAULT_TREASURY_TIMELOCK_BLOCKS: u64 = 14_400;
pub const DEFAULT_FEE_SPONSOR_TTL_BLOCKS: u64 = 10_800;
pub const DEFAULT_COVENANT_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_NULLIFIER_FENCE_TTL_BLOCKS: u64 = 172_800;
pub const DEFAULT_MAX_FACTORY_FEE_MICRONERO: u64 = 25_000;
pub const DEFAULT_MAX_LAUNCH_FEE_BPS: u64 = 12;
pub const DEFAULT_REQUIRED_ATTESTATION_WEIGHT: u64 = 67;
pub const DEFAULT_REQUIRED_VOTE_WEIGHT: u64 = 60;
pub const DEFAULT_SLASH_BPS: u64 = 1_500;
pub const DEFAULT_MAX_TOKEN_CLASSES: usize = 1_048_576;
pub const DEFAULT_MAX_PROPOSALS: usize = 2_097_152;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_VOTE_COMMITMENTS: usize = 16_777_216;
pub const DEFAULT_MAX_SPONSORSHIPS: usize = 4_194_304;
pub const DEFAULT_MAX_COVENANT_HOOKS: usize = 4_194_304;
pub const DEFAULT_MAX_TREASURY_TIMELOCKS: usize = 4_194_304;
pub const DEFAULT_MAX_NULLIFIER_FENCES: usize = 33_554_432;
pub const DEFAULT_MAX_SLASHING_EVENTS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenClassKind {
    ConfidentialAsset,
    WrappedMoneroDerivative,
    StableAsset,
    GovernanceNote,
    VaultShare,
    LiquidityReceipt,
    CreditNote,
    SyntheticClaim,
    RwaReceipt,
    SettlementCoupon,
    PrivateMeme,
    IntentReceipt,
}

impl TokenClassKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialAsset => "confidential_asset",
            Self::WrappedMoneroDerivative => "wrapped_monero_derivative",
            Self::StableAsset => "stable_asset",
            Self::GovernanceNote => "governance_note",
            Self::VaultShare => "vault_share",
            Self::LiquidityReceipt => "liquidity_receipt",
            Self::CreditNote => "credit_note",
            Self::SyntheticClaim => "synthetic_claim",
            Self::RwaReceipt => "rwa_receipt",
            Self::SettlementCoupon => "settlement_coupon",
            Self::PrivateMeme => "private_meme",
            Self::IntentReceipt => "intent_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Draft,
    Voting,
    Approved,
    Rejected,
    Timelocked,
    Launched,
    Cancelled,
    Slashed,
}

impl ProposalStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Voting => "voting",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Timelocked => "timelocked",
            Self::Launched => "launched",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }

    pub fn accepts_votes(self) -> bool {
        matches!(self, Self::Voting | Self::Draft)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceAction {
    CreateTokenClass,
    AmendTokenClass,
    AttachCovenantHook,
    ReplaceMintPolicy,
    ReplaceBurnPolicy,
    EnableAmm,
    EnableLending,
    EnablePerps,
    SponsorLaunchFee,
    ScheduleTreasurySpend,
    RotatePqCommittee,
    FreezeLaunch,
}

impl GovernanceAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CreateTokenClass => "create_token_class",
            Self::AmendTokenClass => "amend_token_class",
            Self::AttachCovenantHook => "attach_covenant_hook",
            Self::ReplaceMintPolicy => "replace_mint_policy",
            Self::ReplaceBurnPolicy => "replace_burn_policy",
            Self::EnableAmm => "enable_amm",
            Self::EnableLending => "enable_lending",
            Self::EnablePerps => "enable_perps",
            Self::SponsorLaunchFee => "sponsor_launch_fee",
            Self::ScheduleTreasurySpend => "schedule_treasury_spend",
            Self::RotatePqCommittee => "rotate_pq_committee",
            Self::FreezeLaunch => "freeze_launch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteDirection {
    Yes,
    No,
    Abstain,
    Veto,
}

impl VoteDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::Abstain => "abstain",
            Self::Veto => "veto",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationRole {
    Issuer,
    PqCommittee,
    PrivacyAuditor,
    ComplianceOracle,
    DefiRiskCouncil,
    FeeSponsor,
    Watchtower,
    TreasuryGuardian,
}

impl AttestationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issuer => "issuer",
            Self::PqCommittee => "pq_committee",
            Self::PrivacyAuditor => "privacy_auditor",
            Self::ComplianceOracle => "compliance_oracle",
            Self::DefiRiskCouncil => "defi_risk_council",
            Self::FeeSponsor => "fee_sponsor",
            Self::Watchtower => "watchtower",
            Self::TreasuryGuardian => "treasury_guardian",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookKind {
    KycCredential,
    SanctionsProof,
    TransferCovenant,
    MintCovenant,
    BurnCovenant,
    ContractAllowlist,
    JurisdictionFence,
    DefiRiskLimiter,
    TreasurySpendGuard,
    EmergencyPause,
}

impl HookKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KycCredential => "kyc_credential",
            Self::SanctionsProof => "sanctions_proof",
            Self::TransferCovenant => "transfer_covenant",
            Self::MintCovenant => "mint_covenant",
            Self::BurnCovenant => "burn_covenant",
            Self::ContractAllowlist => "contract_allowlist",
            Self::JurisdictionFence => "jurisdiction_fence",
            Self::DefiRiskLimiter => "defi_risk_limiter",
            Self::TreasurySpendGuard => "treasury_spend_guard",
            Self::EmergencyPause => "emergency_pause",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Offered,
    Reserved,
    PartiallyUsed,
    Exhausted,
    Expired,
    Revoked,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::PartiallyUsed => "partially_used",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationStatus {
    Disabled,
    Requested,
    Guarded,
    Enabled,
    Paused,
}

impl IntegrationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Requested => "requested",
            Self::Guarded => "guarded",
            Self::Enabled => "enabled",
            Self::Paused => "paused",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelockStatus {
    Scheduled,
    Executable,
    Executed,
    Cancelled,
}

impl TimelockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Executable => "executable",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    PqEquivocation,
    InvalidSignature,
    DoubleVoteNullifier,
    InvalidComplianceAttestation,
    FeeSponsorDefault,
    CovenantBypass,
    TreasuryTimelockBypass,
    DefiRiskMisreport,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqEquivocation => "pq_equivocation",
            Self::InvalidSignature => "invalid_signature",
            Self::DoubleVoteNullifier => "double_vote_nullifier",
            Self::InvalidComplianceAttestation => "invalid_compliance_attestation",
            Self::FeeSponsorDefault => "fee_sponsor_default",
            Self::CovenantBypass => "covenant_bypass",
            Self::TreasuryTimelockBypass => "treasury_timelock_bypass",
            Self::DefiRiskMisreport => "defi_risk_misreport",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub factory_domain: String,
    pub governance_domain: String,
    pub token_domain: String,
    pub pq_governance_suite: String,
    pub confidential_token_suite: String,
    pub sealed_vote_suite: String,
    pub low_fee_sponsor_suite: String,
    pub defi_integration_suite: String,
    pub covenant_hook_suite: String,
    pub treasury_timelock_suite: String,
    pub slashing_evidence_suite: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub proposal_ttl_blocks: u64,
    pub voting_period_blocks: u64,
    pub execution_delay_blocks: u64,
    pub treasury_timelock_blocks: u64,
    pub fee_sponsor_ttl_blocks: u64,
    pub covenant_ttl_blocks: u64,
    pub nullifier_fence_ttl_blocks: u64,
    pub max_factory_fee_micronero: u64,
    pub max_launch_fee_bps: u64,
    pub required_attestation_weight: u64,
    pub required_vote_weight: u64,
    pub slash_bps: u64,
    pub max_token_classes: usize,
    pub max_proposals: usize,
    pub max_attestations: usize,
    pub max_vote_commitments: usize,
    pub max_sponsorships: usize,
    pub max_covenant_hooks: usize,
    pub max_treasury_timelocks: usize,
    pub max_nullifier_fences: usize,
    pub max_slashing_events: usize,
    pub low_fee_lanes: BTreeSet<String>,
    pub allowed_defi_integrations: BTreeSet<String>,
    pub permitted_token_kinds: BTreeSet<TokenClassKind>,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            factory_domain: "nebula.private-l2.token-factory".to_string(),
            governance_domain: "nebula.private-l2.pq-governance".to_string(),
            token_domain: "nebula.private-l2.confidential-token".to_string(),
            pq_governance_suite: PQ_GOVERNANCE_SUITE.to_string(),
            confidential_token_suite: CONFIDENTIAL_TOKEN_SUITE.to_string(),
            sealed_vote_suite: SEALED_VOTE_SUITE.to_string(),
            low_fee_sponsor_suite: LOW_FEE_SPONSOR_SUITE.to_string(),
            defi_integration_suite: DEFI_INTEGRATION_SUITE.to_string(),
            covenant_hook_suite: COVENANT_HOOK_SUITE.to_string(),
            treasury_timelock_suite: TREASURY_TIMELOCK_SUITE.to_string(),
            slashing_evidence_suite: SLASHING_EVIDENCE_SUITE.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            proposal_ttl_blocks: DEFAULT_PROPOSAL_TTL_BLOCKS,
            voting_period_blocks: DEFAULT_VOTING_PERIOD_BLOCKS,
            execution_delay_blocks: DEFAULT_EXECUTION_DELAY_BLOCKS,
            treasury_timelock_blocks: DEFAULT_TREASURY_TIMELOCK_BLOCKS,
            fee_sponsor_ttl_blocks: DEFAULT_FEE_SPONSOR_TTL_BLOCKS,
            covenant_ttl_blocks: DEFAULT_COVENANT_TTL_BLOCKS,
            nullifier_fence_ttl_blocks: DEFAULT_NULLIFIER_FENCE_TTL_BLOCKS,
            max_factory_fee_micronero: DEFAULT_MAX_FACTORY_FEE_MICRONERO,
            max_launch_fee_bps: DEFAULT_MAX_LAUNCH_FEE_BPS,
            required_attestation_weight: DEFAULT_REQUIRED_ATTESTATION_WEIGHT,
            required_vote_weight: DEFAULT_REQUIRED_VOTE_WEIGHT,
            slash_bps: DEFAULT_SLASH_BPS,
            max_token_classes: DEFAULT_MAX_TOKEN_CLASSES,
            max_proposals: DEFAULT_MAX_PROPOSALS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_vote_commitments: DEFAULT_MAX_VOTE_COMMITMENTS,
            max_sponsorships: DEFAULT_MAX_SPONSORSHIPS,
            max_covenant_hooks: DEFAULT_MAX_COVENANT_HOOKS,
            max_treasury_timelocks: DEFAULT_MAX_TREASURY_TIMELOCKS,
            max_nullifier_fences: DEFAULT_MAX_NULLIFIER_FENCES,
            max_slashing_events: DEFAULT_MAX_SLASHING_EVENTS,
            low_fee_lanes: btree_set(&[
                "recursive-proof-rebate",
                "paymaster-sponsored-launch",
                "batch-call-netting",
                "confidential-calldata-dedup",
                "state-diff-compression",
            ]),
            allowed_defi_integrations: btree_set(&[
                "amm",
                "stable-swap",
                "lending",
                "perps",
                "vault-router",
                "intent-solver",
                "bridge-router",
            ]),
            permitted_token_kinds: [
                TokenClassKind::ConfidentialAsset,
                TokenClassKind::WrappedMoneroDerivative,
                TokenClassKind::StableAsset,
                TokenClassKind::GovernanceNote,
                TokenClassKind::VaultShare,
                TokenClassKind::LiquidityReceipt,
                TokenClassKind::CreditNote,
                TokenClassKind::SyntheticClaim,
                TokenClassKind::RwaReceipt,
                TokenClassKind::SettlementCoupon,
                TokenClassKind::PrivateMeme,
                TokenClassKind::IntentReceipt,
            ]
            .iter()
            .copied()
            .collect(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "factory_domain": self.factory_domain,
            "governance_domain": self.governance_domain,
            "token_domain": self.token_domain,
            "pq_governance_suite": self.pq_governance_suite,
            "confidential_token_suite": self.confidential_token_suite,
            "sealed_vote_suite": self.sealed_vote_suite,
            "low_fee_sponsor_suite": self.low_fee_sponsor_suite,
            "defi_integration_suite": self.defi_integration_suite,
            "covenant_hook_suite": self.covenant_hook_suite,
            "treasury_timelock_suite": self.treasury_timelock_suite,
            "slashing_evidence_suite": self.slashing_evidence_suite,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "proposal_ttl_blocks": self.proposal_ttl_blocks,
            "voting_period_blocks": self.voting_period_blocks,
            "execution_delay_blocks": self.execution_delay_blocks,
            "treasury_timelock_blocks": self.treasury_timelock_blocks,
            "fee_sponsor_ttl_blocks": self.fee_sponsor_ttl_blocks,
            "covenant_ttl_blocks": self.covenant_ttl_blocks,
            "nullifier_fence_ttl_blocks": self.nullifier_fence_ttl_blocks,
            "max_factory_fee_micronero": self.max_factory_fee_micronero,
            "max_launch_fee_bps": self.max_launch_fee_bps,
            "required_attestation_weight": self.required_attestation_weight,
            "required_vote_weight": self.required_vote_weight,
            "slash_bps": self.slash_bps,
            "max_token_classes": self.max_token_classes,
            "max_proposals": self.max_proposals,
            "max_attestations": self.max_attestations,
            "max_vote_commitments": self.max_vote_commitments,
            "max_sponsorships": self.max_sponsorships,
            "max_covenant_hooks": self.max_covenant_hooks,
            "max_treasury_timelocks": self.max_treasury_timelocks,
            "max_nullifier_fences": self.max_nullifier_fences,
            "max_slashing_events": self.max_slashing_events,
            "low_fee_lanes": self.low_fee_lanes,
            "allowed_defi_integrations": self.allowed_defi_integrations,
            "permitted_token_kinds": self.permitted_token_kinds
                .iter()
                .map(|kind| kind.as_str())
                .collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub token_classes: u64,
    pub proposals: u64,
    pub attestations: u64,
    pub vote_commitments: u64,
    pub fee_sponsorships: u64,
    pub covenant_hooks: u64,
    pub treasury_timelocks: u64,
    pub nullifier_fences: u64,
    pub slashing_events: u64,
    pub finalized_launches: u64,
    pub amendments: u64,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            token_classes: 0,
            proposals: 0,
            attestations: 0,
            vote_commitments: 0,
            fee_sponsorships: 0,
            covenant_hooks: 0,
            treasury_timelocks: 0,
            nullifier_fences: 0,
            slashing_events: 0,
            finalized_launches: 0,
            amendments: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "token_classes": self.token_classes,
            "proposals": self.proposals,
            "attestations": self.attestations,
            "vote_commitments": self.vote_commitments,
            "fee_sponsorships": self.fee_sponsorships,
            "covenant_hooks": self.covenant_hooks,
            "treasury_timelocks": self.treasury_timelocks,
            "nullifier_fences": self.nullifier_fences,
            "slashing_events": self.slashing_events,
            "finalized_launches": self.finalized_launches,
            "amendments": self.amendments,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub token_class_root: String,
    pub proposal_root: String,
    pub attestation_root: String,
    pub vote_commitment_root: String,
    pub fee_sponsorship_root: String,
    pub covenant_hook_root: String,
    pub treasury_timelock_root: String,
    pub nullifier_fence_root: String,
    pub slashing_evidence_root: String,
    pub integration_root: String,
    pub mint_policy_root: String,
    pub burn_policy_root: String,
    pub deterministic_id_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "token_class_root": self.token_class_root,
            "proposal_root": self.proposal_root,
            "attestation_root": self.attestation_root,
            "vote_commitment_root": self.vote_commitment_root,
            "fee_sponsorship_root": self.fee_sponsorship_root,
            "covenant_hook_root": self.covenant_hook_root,
            "treasury_timelock_root": self.treasury_timelock_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "integration_root": self.integration_root,
            "mint_policy_root": self.mint_policy_root,
            "burn_policy_root": self.burn_policy_root,
            "deterministic_id_root": self.deterministic_id_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialSupplyPolicy {
    pub mint_policy_root: String,
    pub burn_policy_root: String,
    pub supply_cap_commitment: String,
    pub amount_range_proof_root: String,
    pub authority_set_root: String,
    pub conservation_circuit_root: String,
    pub hidden_decimals: u8,
    pub capped: bool,
    pub burn_enabled: bool,
    pub mint_requires_governance: bool,
}

impl ConfidentialSupplyPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "mint_policy_root": self.mint_policy_root,
            "burn_policy_root": self.burn_policy_root,
            "supply_cap_commitment": self.supply_cap_commitment,
            "amount_range_proof_root": self.amount_range_proof_root,
            "authority_set_root": self.authority_set_root,
            "conservation_circuit_root": self.conservation_circuit_root,
            "hidden_decimals": self.hidden_decimals,
            "capped": self.capped,
            "burn_enabled": self.burn_enabled,
            "mint_requires_governance": self.mint_requires_governance,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyParameters {
    pub note_commitment_root: String,
    pub view_key_policy_root: String,
    pub auditor_share_root: String,
    pub nullifier_domain_root: String,
    pub decoy_distribution_root: String,
    pub min_anonymity_set: u64,
    pub target_anonymity_set: u64,
    pub encrypted_metadata: bool,
    pub private_balances: bool,
    pub private_governance: bool,
}

impl PrivacyParameters {
    pub fn public_record(&self) -> Value {
        json!({
            "note_commitment_root": self.note_commitment_root,
            "view_key_policy_root": self.view_key_policy_root,
            "auditor_share_root": self.auditor_share_root,
            "nullifier_domain_root": self.nullifier_domain_root,
            "decoy_distribution_root": self.decoy_distribution_root,
            "min_anonymity_set": self.min_anonymity_set,
            "target_anonymity_set": self.target_anonymity_set,
            "encrypted_metadata": self.encrypted_metadata,
            "private_balances": self.private_balances,
            "private_governance": self.private_governance,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuantumResistanceProfile {
    pub kem_root: String,
    pub signature_root: String,
    pub transcript_root: String,
    pub rotation_policy_root: String,
    pub recursive_aggregation_root: String,
    pub security_bits: u16,
    pub hybrid_classic_binding: bool,
    pub migration_ready: bool,
}

impl QuantumResistanceProfile {
    pub fn public_record(&self) -> Value {
        json!({
            "kem_root": self.kem_root,
            "signature_root": self.signature_root,
            "transcript_root": self.transcript_root,
            "rotation_policy_root": self.rotation_policy_root,
            "recursive_aggregation_root": self.recursive_aggregation_root,
            "security_bits": self.security_bits,
            "hybrid_classic_binding": self.hybrid_classic_binding,
            "migration_ready": self.migration_ready,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DefiIntegrationFlags {
    pub amm: IntegrationStatus,
    pub stable_swap: IntegrationStatus,
    pub lending: IntegrationStatus,
    pub perps: IntegrationStatus,
    pub vault_router: IntegrationStatus,
    pub intent_solver: IntegrationStatus,
    pub bridge_router: IntegrationStatus,
    pub oracle_risk_root: String,
    pub liquidity_guard_root: String,
    pub max_pool_fee_bps: u64,
    pub max_leverage_bps: u64,
}

impl DefiIntegrationFlags {
    pub fn public_record(&self) -> Value {
        json!({
            "amm": self.amm.as_str(),
            "stable_swap": self.stable_swap.as_str(),
            "lending": self.lending.as_str(),
            "perps": self.perps.as_str(),
            "vault_router": self.vault_router.as_str(),
            "intent_solver": self.intent_solver.as_str(),
            "bridge_router": self.bridge_router.as_str(),
            "oracle_risk_root": self.oracle_risk_root,
            "liquidity_guard_root": self.liquidity_guard_root,
            "max_pool_fee_bps": self.max_pool_fee_bps,
            "max_leverage_bps": self.max_leverage_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenClassProposal {
    pub proposal_id: String,
    pub token_class_id: String,
    pub class_kind: TokenClassKind,
    pub action: GovernanceAction,
    pub status: ProposalStatus,
    pub proposer_commitment: String,
    pub symbol_commitment: String,
    pub metadata_root: String,
    pub factory_salt_root: String,
    pub supply_policy: ConfidentialSupplyPolicy,
    pub privacy: PrivacyParameters,
    pub pq_profile: QuantumResistanceProfile,
    pub defi: DefiIntegrationFlags,
    pub covenant_hook_root: String,
    pub treasury_policy_root: String,
    pub compliance_policy_root: String,
    pub launch_fee_micronero: u64,
    pub launch_fee_bps: u64,
    pub created_at_height: u64,
    pub voting_starts_at_height: u64,
    pub voting_ends_at_height: u64,
    pub execution_height: u64,
    pub expires_at_height: u64,
    pub attestation_weight: u64,
    pub yes_weight: u64,
    pub no_weight: u64,
    pub abstain_weight: u64,
    pub veto_weight: u64,
}

impl TokenClassProposal {
    pub fn public_record(&self) -> Value {
        json!({
            "proposal_id": self.proposal_id,
            "token_class_id": self.token_class_id,
            "class_kind": self.class_kind.as_str(),
            "action": self.action.as_str(),
            "status": self.status.as_str(),
            "proposer_commitment": self.proposer_commitment,
            "symbol_commitment": self.symbol_commitment,
            "metadata_root": self.metadata_root,
            "factory_salt_root": self.factory_salt_root,
            "supply_policy": self.supply_policy.public_record(),
            "privacy": self.privacy.public_record(),
            "pq_profile": self.pq_profile.public_record(),
            "defi": self.defi.public_record(),
            "covenant_hook_root": self.covenant_hook_root,
            "treasury_policy_root": self.treasury_policy_root,
            "compliance_policy_root": self.compliance_policy_root,
            "launch_fee_micronero": self.launch_fee_micronero,
            "launch_fee_bps": self.launch_fee_bps,
            "created_at_height": self.created_at_height,
            "voting_starts_at_height": self.voting_starts_at_height,
            "voting_ends_at_height": self.voting_ends_at_height,
            "execution_height": self.execution_height,
            "expires_at_height": self.expires_at_height,
            "attestation_weight": self.attestation_weight,
            "yes_weight": self.yes_weight,
            "no_weight": self.no_weight,
            "abstain_weight": self.abstain_weight,
            "veto_weight": self.veto_weight,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenClass {
    pub token_class_id: String,
    pub launch_proposal_id: String,
    pub class_kind: TokenClassKind,
    pub issuer_commitment: String,
    pub symbol_commitment: String,
    pub metadata_root: String,
    pub supply_policy: ConfidentialSupplyPolicy,
    pub privacy: PrivacyParameters,
    pub pq_profile: QuantumResistanceProfile,
    pub defi: DefiIntegrationFlags,
    pub covenant_hook_root: String,
    pub treasury_policy_root: String,
    pub compliance_policy_root: String,
    pub launched_at_height: u64,
    pub launch_receipt_root: String,
    pub active: bool,
    pub frozen: bool,
}

impl TokenClass {
    pub fn public_record(&self) -> Value {
        json!({
            "token_class_id": self.token_class_id,
            "launch_proposal_id": self.launch_proposal_id,
            "class_kind": self.class_kind.as_str(),
            "issuer_commitment": self.issuer_commitment,
            "symbol_commitment": self.symbol_commitment,
            "metadata_root": self.metadata_root,
            "supply_policy": self.supply_policy.public_record(),
            "privacy": self.privacy.public_record(),
            "pq_profile": self.pq_profile.public_record(),
            "defi": self.defi.public_record(),
            "covenant_hook_root": self.covenant_hook_root,
            "treasury_policy_root": self.treasury_policy_root,
            "compliance_policy_root": self.compliance_policy_root,
            "launched_at_height": self.launched_at_height,
            "launch_receipt_root": self.launch_receipt_root,
            "active": self.active,
            "frozen": self.frozen,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqGovernanceAttestation {
    pub attestation_id: String,
    pub proposal_id: String,
    pub token_class_id: String,
    pub role: AttestationRole,
    pub signer_commitment: String,
    pub subject_root: String,
    pub transcript_root: String,
    pub pq_signature_root: String,
    pub verification_key_root: String,
    pub weight: u64,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub slashable: bool,
}

impl PqGovernanceAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "proposal_id": self.proposal_id,
            "token_class_id": self.token_class_id,
            "role": self.role.as_str(),
            "signer_commitment": self.signer_commitment,
            "subject_root": self.subject_root,
            "transcript_root": self.transcript_root,
            "pq_signature_root": self.pq_signature_root,
            "verification_key_root": self.verification_key_root,
            "weight": self.weight,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "slashable": self.slashable,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedVoteCommitment {
    pub vote_id: String,
    pub proposal_id: String,
    pub token_class_id: String,
    pub voter_commitment: String,
    pub vote_direction: VoteDirection,
    pub sealed_ballot_root: String,
    pub nullifier_hash: String,
    pub voting_power_commitment: String,
    pub eligibility_proof_root: String,
    pub tally_share_root: String,
    pub pq_signature_root: String,
    pub weight: u64,
    pub committed_at_height: u64,
    pub revealed_at_height: Option<u64>,
}

impl SealedVoteCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "vote_id": self.vote_id,
            "proposal_id": self.proposal_id,
            "token_class_id": self.token_class_id,
            "voter_commitment": self.voter_commitment,
            "vote_direction": self.vote_direction.as_str(),
            "sealed_ballot_root": self.sealed_ballot_root,
            "nullifier_hash": self.nullifier_hash,
            "voting_power_commitment": self.voting_power_commitment,
            "eligibility_proof_root": self.eligibility_proof_root,
            "tally_share_root": self.tally_share_root,
            "pq_signature_root": self.pq_signature_root,
            "weight": self.weight,
            "committed_at_height": self.committed_at_height,
            "revealed_at_height": self.revealed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaunchFeeSponsorship {
    pub sponsorship_id: String,
    pub proposal_id: String,
    pub token_class_id: String,
    pub sponsor_commitment: String,
    pub status: SponsorshipStatus,
    pub fee_asset_id: String,
    pub budget_micronero: u64,
    pub reserved_micronero: u64,
    pub spent_micronero: u64,
    pub max_rebate_bps: u64,
    pub low_fee_lane_root: String,
    pub paymaster_policy_root: String,
    pub proof_rebate_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl LaunchFeeSponsorship {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "proposal_id": self.proposal_id,
            "token_class_id": self.token_class_id,
            "sponsor_commitment": self.sponsor_commitment,
            "status": self.status.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "budget_micronero": self.budget_micronero,
            "reserved_micronero": self.reserved_micronero,
            "spent_micronero": self.spent_micronero,
            "max_rebate_bps": self.max_rebate_bps,
            "low_fee_lane_root": self.low_fee_lane_root,
            "paymaster_policy_root": self.paymaster_policy_root,
            "proof_rebate_root": self.proof_rebate_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CovenantHook {
    pub hook_id: String,
    pub token_class_id: String,
    pub proposal_id: String,
    pub hook_kind: HookKind,
    pub contract_commitment: String,
    pub hook_root: String,
    pub compliance_circuit_root: String,
    pub covenant_policy_root: String,
    pub jurisdiction_root: String,
    pub privacy_budget_root: String,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
    pub active: bool,
}

impl CovenantHook {
    pub fn public_record(&self) -> Value {
        json!({
            "hook_id": self.hook_id,
            "token_class_id": self.token_class_id,
            "proposal_id": self.proposal_id,
            "hook_kind": self.hook_kind.as_str(),
            "contract_commitment": self.contract_commitment,
            "hook_root": self.hook_root,
            "compliance_circuit_root": self.compliance_circuit_root,
            "covenant_policy_root": self.covenant_policy_root,
            "jurisdiction_root": self.jurisdiction_root,
            "privacy_budget_root": self.privacy_budget_root,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TreasuryTimelock {
    pub timelock_id: String,
    pub token_class_id: String,
    pub proposal_id: String,
    pub spend_commitment: String,
    pub beneficiary_commitment: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub guard_root: String,
    pub status: TimelockStatus,
    pub scheduled_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
    pub executed_at_height: Option<u64>,
}

impl TreasuryTimelock {
    pub fn public_record(&self) -> Value {
        json!({
            "timelock_id": self.timelock_id,
            "token_class_id": self.token_class_id,
            "proposal_id": self.proposal_id,
            "spend_commitment": self.spend_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "asset_id": self.asset_id,
            "amount_commitment": self.amount_commitment,
            "guard_root": self.guard_root,
            "status": self.status.as_str(),
            "scheduled_at_height": self.scheduled_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "executed_at_height": self.executed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub token_class_id: String,
    pub proposal_id: String,
    pub nullifier_domain: String,
    pub nullifier_root: String,
    pub spent_nullifier_count: u64,
    pub guard_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl NullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "token_class_id": self.token_class_id,
            "proposal_id": self.proposal_id,
            "nullifier_domain": self.nullifier_domain,
            "nullifier_root": self.nullifier_root,
            "spent_nullifier_count": self.spent_nullifier_count,
            "guard_root": self.guard_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub proposal_id: String,
    pub token_class_id: String,
    pub reason: SlashingReason,
    pub accused_commitment: String,
    pub reporter_commitment: String,
    pub evidence_root: String,
    pub conflicting_transcript_root: String,
    pub slash_amount_commitment: String,
    pub slashed_bps: u64,
    pub submitted_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "proposal_id": self.proposal_id,
            "token_class_id": self.token_class_id,
            "reason": self.reason.as_str(),
            "accused_commitment": self.accused_commitment,
            "reporter_commitment": self.reporter_commitment,
            "evidence_root": self.evidence_root,
            "conflicting_transcript_root": self.conflicting_transcript_root,
            "slash_amount_commitment": self.slash_amount_commitment,
            "slashed_bps": self.slashed_bps,
            "submitted_at_height": self.submitted_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub height: u64,
    pub token_classes: BTreeMap<String, TokenClass>,
    pub proposals: BTreeMap<String, TokenClassProposal>,
    pub attestations: BTreeMap<String, PqGovernanceAttestation>,
    pub vote_commitments: BTreeMap<String, SealedVoteCommitment>,
    pub fee_sponsorships: BTreeMap<String, LaunchFeeSponsorship>,
    pub covenant_hooks: BTreeMap<String, CovenantHook>,
    pub treasury_timelocks: BTreeMap<String, TreasuryTimelock>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub proposal_attestations: BTreeMap<String, BTreeSet<String>>,
    pub proposal_votes: BTreeMap<String, BTreeSet<String>>,
    pub token_hooks: BTreeMap<String, BTreeSet<String>>,
    pub token_sponsorships: BTreeMap<String, BTreeSet<String>>,
    pub token_timelocks: BTreeMap<String, BTreeSet<String>>,
    pub nullifier_index: BTreeSet<String>,
    pub deterministic_ids: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let counters = Counters::new();
        let mut state = Self {
            config,
            counters,
            height: DEVNET_HEIGHT,
            token_classes: BTreeMap::new(),
            proposals: BTreeMap::new(),
            attestations: BTreeMap::new(),
            vote_commitments: BTreeMap::new(),
            fee_sponsorships: BTreeMap::new(),
            covenant_hooks: BTreeMap::new(),
            treasury_timelocks: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            proposal_attestations: BTreeMap::new(),
            proposal_votes: BTreeMap::new(),
            token_hooks: BTreeMap::new(),
            token_sponsorships: BTreeMap::new(),
            token_timelocks: BTreeMap::new(),
            nullifier_index: BTreeSet::new(),
            deterministic_ids: BTreeSet::new(),
        };

        let proposal_id = state
            .propose_token_class(TokenClassProposalRequest {
                class_kind: TokenClassKind::ConfidentialAsset,
                action: GovernanceAction::CreateTokenClass,
                proposer_commitment: fixture_root("issuer-commitment", "nebula-labs"),
                symbol_commitment: fixture_root("symbol", "pXMR-GOV"),
                metadata_root: fixture_root("metadata", "private-xmr-governance-token"),
                factory_salt_root: fixture_root("factory-salt", "devnet-token-0"),
                supply_policy: devnet_supply_policy("pxmr-governance"),
                privacy: devnet_privacy_parameters("pxmr-governance"),
                pq_profile: devnet_pq_profile("pxmr-governance"),
                defi: devnet_defi_flags(true, true, true),
                covenant_hook_root: fixture_root("hook-bundle", "launch-covenants"),
                treasury_policy_root: fixture_root("treasury-policy", "slow-spend"),
                compliance_policy_root: fixture_root("compliance", "selective-disclosure"),
                launch_fee_micronero: 12_500,
                launch_fee_bps: 5,
                created_at_height: DEVNET_HEIGHT,
            })
            .unwrap_or_else(|_| identity_string());

        let token_class_id = state
            .proposals
            .get(&proposal_id)
            .map(|proposal| proposal.token_class_id.clone())
            .unwrap_or_else(identity_string);

        let attestation_id = state
            .attest_governance_vote(GovernanceAttestationRequest {
                proposal_id: proposal_id.clone(),
                role: AttestationRole::PqCommittee,
                signer_commitment: fixture_root("committee-signer", "alpha"),
                subject_root: fixture_root("proposal-review", "pq-ready"),
                transcript_root: fixture_root("attestation-transcript", "alpha-yes"),
                pq_signature_root: fixture_root("pq-signature", "alpha"),
                verification_key_root: fixture_root("pq-vk", "committee-alpha"),
                weight: 70,
                signed_at_height: DEVNET_HEIGHT + 8,
                expires_at_height: DEVNET_HEIGHT + DEFAULT_PROPOSAL_TTL_BLOCKS,
                slashable: true,
            })
            .unwrap_or_else(|_| identity_string());

        let _ = attestation_id;

        let _ = state.commit_sealed_vote(SealedVoteRequest {
            proposal_id: proposal_id.clone(),
            voter_commitment: fixture_root("voter", "shielded-dao-1"),
            vote_direction: VoteDirection::Yes,
            sealed_ballot_root: fixture_root("sealed-ballot", "yes-1"),
            nullifier_hash: deterministic_id("devnet-vote-nullifier", &["shielded-dao-1"]),
            voting_power_commitment: fixture_root("vote-power", "dao-1"),
            eligibility_proof_root: fixture_root("eligibility", "dao-1"),
            tally_share_root: fixture_root("tally-share", "dao-1"),
            pq_signature_root: fixture_root("vote-pq-sig", "dao-1"),
            weight: 66,
            committed_at_height: DEVNET_HEIGHT + 16,
        });

        let _ = state.issue_fee_sponsorship(FeeSponsorshipRequest {
            proposal_id: proposal_id.clone(),
            sponsor_commitment: fixture_root("sponsor", "low-fee-foundation"),
            fee_asset_id: "xmr-devnet-fee-credit".to_string(),
            budget_micronero: 1_500_000,
            reserved_micronero: 25_000,
            max_rebate_bps: 8,
            low_fee_lane_root: fixture_root("low-fee-lane", "recursive-proof-rebate"),
            paymaster_policy_root: fixture_root("paymaster", "launch"),
            proof_rebate_root: fixture_root("proof-rebate", "factory-batch"),
            opened_at_height: DEVNET_HEIGHT + 20,
        });

        let _ = state.update_covenant_hook(CovenantHookRequest {
            proposal_id: proposal_id.clone(),
            token_class_id: token_class_id.clone(),
            hook_kind: HookKind::TransferCovenant,
            contract_commitment: fixture_root("contract", "transfer-covenant"),
            hook_root: fixture_root("hook", "transfer-covenant-v1"),
            compliance_circuit_root: fixture_root("compliance-circuit", "selective-disclosure"),
            covenant_policy_root: fixture_root("covenant-policy", "private-transfer"),
            jurisdiction_root: fixture_root("jurisdiction", "global-sandbox"),
            privacy_budget_root: fixture_root("privacy-budget", "bounded-disclosure"),
            activated_at_height: DEVNET_HEIGHT + 24,
        });

        let _ = state.schedule_treasury_timelock(TreasuryTimelockRequest {
            proposal_id: proposal_id.clone(),
            token_class_id: token_class_id.clone(),
            spend_commitment: fixture_root("spend", "liquidity-bootstrap"),
            beneficiary_commitment: fixture_root("beneficiary", "amm-bootstrap"),
            asset_id: "pXMR-GOV".to_string(),
            amount_commitment: fixture_root("amount", "bootstrap-bucket"),
            guard_root: fixture_root("treasury-guard", "slow-spend"),
            scheduled_at_height: DEVNET_HEIGHT + 30,
        });

        let _ = state.open_nullifier_fence(NullifierFenceRequest {
            proposal_id: proposal_id.clone(),
            token_class_id: token_class_id.clone(),
            nullifier_domain: "launch-vote".to_string(),
            nullifier_root: fixture_root("nullifier-root", "launch-vote"),
            spent_nullifier_count: 1,
            guard_root: fixture_root("nullifier-guard", "no-double-use"),
            opened_at_height: DEVNET_HEIGHT + 32,
        });

        let _ = state.finalize_token_launch(&proposal_id, DEVNET_HEIGHT + 7_400);
        state
    }

    pub fn propose_token_class(&mut self, request: TokenClassProposalRequest) -> Result<String> {
        self.validate_token_class_request(&request)?;
        ensure_capacity(
            self.proposals.len(),
            self.config.max_proposals,
            "proposal capacity exhausted",
        )?;

        let token_class_id = token_class_id(
            request.class_kind,
            &request.proposer_commitment,
            &request.symbol_commitment,
            &request.metadata_root,
            &request.factory_salt_root,
        );
        let proposal_id = proposal_id(
            &token_class_id,
            request.action,
            &request.proposer_commitment,
            request.created_at_height,
            self.counters.proposals + 1,
        );
        ensure_unique(
            &self.deterministic_ids,
            &proposal_id,
            "duplicate proposal id",
        )?;
        ensure_unique(
            &self.deterministic_ids,
            &token_class_id,
            "duplicate token class id",
        )?;

        let voting_starts_at_height = request.created_at_height;
        let voting_ends_at_height = voting_starts_at_height + self.config.voting_period_blocks;
        let execution_height = voting_ends_at_height + self.config.execution_delay_blocks;
        let expires_at_height = request.created_at_height + self.config.proposal_ttl_blocks;
        let proposal = TokenClassProposal {
            proposal_id: proposal_id.clone(),
            token_class_id: token_class_id.clone(),
            class_kind: request.class_kind,
            action: request.action,
            status: ProposalStatus::Voting,
            proposer_commitment: request.proposer_commitment,
            symbol_commitment: request.symbol_commitment,
            metadata_root: request.metadata_root,
            factory_salt_root: request.factory_salt_root,
            supply_policy: request.supply_policy,
            privacy: request.privacy,
            pq_profile: request.pq_profile,
            defi: request.defi,
            covenant_hook_root: request.covenant_hook_root,
            treasury_policy_root: request.treasury_policy_root,
            compliance_policy_root: request.compliance_policy_root,
            launch_fee_micronero: request.launch_fee_micronero,
            launch_fee_bps: request.launch_fee_bps,
            created_at_height: request.created_at_height,
            voting_starts_at_height,
            voting_ends_at_height,
            execution_height,
            expires_at_height,
            attestation_weight: 0,
            yes_weight: 0,
            no_weight: 0,
            abstain_weight: 0,
            veto_weight: 0,
        };

        self.proposals.insert(proposal_id.clone(), proposal);
        self.proposal_attestations
            .insert(proposal_id.clone(), BTreeSet::new());
        self.proposal_votes
            .insert(proposal_id.clone(), BTreeSet::new());
        self.deterministic_ids.insert(proposal_id.clone());
        self.deterministic_ids.insert(token_class_id);
        self.counters.proposals += 1;
        Ok(proposal_id)
    }

    pub fn attest_governance_vote(
        &mut self,
        request: GovernanceAttestationRequest,
    ) -> Result<String> {
        ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "attestation capacity exhausted",
        )?;
        let proposal = self
            .proposals
            .get(&request.proposal_id)
            .ok_or_else(|| "proposal not found".to_string())?;
        ensure(
            proposal.status.accepts_votes(),
            "proposal does not accept attestations",
        )?;
        ensure(
            request.weight > 0 && request.weight <= MAX_BPS,
            "attestation weight out of range",
        )?;
        ensure(
            request.expires_at_height > request.signed_at_height,
            "attestation expiry must be after signing height",
        )?;

        let attestation_id = attestation_id(
            &request.proposal_id,
            request.role,
            &request.signer_commitment,
            &request.transcript_root,
            request.signed_at_height,
        );
        ensure_unique(
            &self.deterministic_ids,
            &attestation_id,
            "duplicate attestation id",
        )?;

        let attestation = PqGovernanceAttestation {
            attestation_id: attestation_id.clone(),
            proposal_id: request.proposal_id.clone(),
            token_class_id: proposal.token_class_id.clone(),
            role: request.role,
            signer_commitment: request.signer_commitment,
            subject_root: request.subject_root,
            transcript_root: request.transcript_root,
            pq_signature_root: request.pq_signature_root,
            verification_key_root: request.verification_key_root,
            weight: request.weight,
            signed_at_height: request.signed_at_height,
            expires_at_height: request.expires_at_height,
            slashable: request.slashable,
        };

        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.proposal_attestations
            .entry(request.proposal_id.clone())
            .or_default()
            .insert(attestation_id.clone());
        self.deterministic_ids.insert(attestation_id.clone());
        self.counters.attestations += 1;

        let proposal = self
            .proposals
            .get_mut(&request.proposal_id)
            .ok_or_else(|| "proposal disappeared while attesting".to_string())?;
        proposal.attestation_weight =
            saturating_add_bps(proposal.attestation_weight, request.weight);
        self.refresh_proposal_status(&request.proposal_id);
        Ok(attestation_id)
    }

    pub fn commit_sealed_vote(&mut self, request: SealedVoteRequest) -> Result<String> {
        ensure_capacity(
            self.vote_commitments.len(),
            self.config.max_vote_commitments,
            "vote commitment capacity exhausted",
        )?;
        ensure(
            !self.nullifier_index.contains(&request.nullifier_hash),
            "vote nullifier already used",
        )?;
        let proposal = self
            .proposals
            .get(&request.proposal_id)
            .ok_or_else(|| "proposal not found".to_string())?;
        ensure(
            proposal.status.accepts_votes(),
            "proposal does not accept votes",
        )?;
        ensure(
            request.committed_at_height >= proposal.voting_starts_at_height
                && request.committed_at_height <= proposal.voting_ends_at_height,
            "vote outside voting window",
        )?;
        ensure(
            request.weight > 0 && request.weight <= MAX_BPS,
            "vote weight out of range",
        )?;

        let vote_id = vote_id(
            &request.proposal_id,
            &request.voter_commitment,
            &request.nullifier_hash,
            request.committed_at_height,
        );
        ensure_unique(&self.deterministic_ids, &vote_id, "duplicate vote id")?;

        let vote = SealedVoteCommitment {
            vote_id: vote_id.clone(),
            proposal_id: request.proposal_id.clone(),
            token_class_id: proposal.token_class_id.clone(),
            voter_commitment: request.voter_commitment,
            vote_direction: request.vote_direction,
            sealed_ballot_root: request.sealed_ballot_root,
            nullifier_hash: request.nullifier_hash.clone(),
            voting_power_commitment: request.voting_power_commitment,
            eligibility_proof_root: request.eligibility_proof_root,
            tally_share_root: request.tally_share_root,
            pq_signature_root: request.pq_signature_root,
            weight: request.weight,
            committed_at_height: request.committed_at_height,
            revealed_at_height: None,
        };

        self.vote_commitments.insert(vote_id.clone(), vote);
        self.proposal_votes
            .entry(request.proposal_id.clone())
            .or_default()
            .insert(vote_id.clone());
        self.nullifier_index.insert(request.nullifier_hash);
        self.deterministic_ids.insert(vote_id.clone());
        self.counters.vote_commitments += 1;

        let proposal = self
            .proposals
            .get_mut(&request.proposal_id)
            .ok_or_else(|| "proposal disappeared while voting".to_string())?;
        match request.vote_direction {
            VoteDirection::Yes => {
                proposal.yes_weight = saturating_add_bps(proposal.yes_weight, request.weight)
            }
            VoteDirection::No => {
                proposal.no_weight = saturating_add_bps(proposal.no_weight, request.weight)
            }
            VoteDirection::Abstain => {
                proposal.abstain_weight =
                    saturating_add_bps(proposal.abstain_weight, request.weight)
            }
            VoteDirection::Veto => {
                proposal.veto_weight = saturating_add_bps(proposal.veto_weight, request.weight)
            }
        }
        self.refresh_proposal_status(&request.proposal_id);
        Ok(vote_id)
    }

    pub fn finalize_token_launch(
        &mut self,
        proposal_id: &str,
        finalized_at_height: u64,
    ) -> Result<String> {
        ensure_capacity(
            self.token_classes.len(),
            self.config.max_token_classes,
            "token class capacity exhausted",
        )?;
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or_else(|| "proposal not found".to_string())?
            .clone();
        ensure(
            finalized_at_height >= proposal.execution_height,
            "proposal execution delay still active",
        )?;
        ensure(
            proposal.attestation_weight >= self.config.required_attestation_weight,
            "insufficient governance attestation weight",
        )?;
        ensure(
            proposal.yes_weight >= self.config.required_vote_weight,
            "insufficient yes vote weight",
        )?;
        ensure(
            proposal.no_weight < proposal.yes_weight,
            "proposal rejected by no votes",
        )?;
        ensure(proposal.veto_weight == 0, "proposal vetoed")?;
        ensure(
            !self.token_classes.contains_key(&proposal.token_class_id),
            "token class already launched",
        )?;

        let receipt_root = launch_receipt_root(
            &proposal.proposal_id,
            &proposal.token_class_id,
            finalized_at_height,
            &self.roots().proposal_root,
        );
        let token_class = TokenClass {
            token_class_id: proposal.token_class_id.clone(),
            launch_proposal_id: proposal.proposal_id.clone(),
            class_kind: proposal.class_kind,
            issuer_commitment: proposal.proposer_commitment.clone(),
            symbol_commitment: proposal.symbol_commitment.clone(),
            metadata_root: proposal.metadata_root.clone(),
            supply_policy: proposal.supply_policy.clone(),
            privacy: proposal.privacy.clone(),
            pq_profile: proposal.pq_profile.clone(),
            defi: proposal.defi.clone(),
            covenant_hook_root: proposal.covenant_hook_root.clone(),
            treasury_policy_root: proposal.treasury_policy_root.clone(),
            compliance_policy_root: proposal.compliance_policy_root.clone(),
            launched_at_height: finalized_at_height,
            launch_receipt_root: receipt_root,
            active: true,
            frozen: false,
        };
        self.token_classes
            .insert(proposal.token_class_id.clone(), token_class);
        if let Some(proposal_mut) = self.proposals.get_mut(proposal_id) {
            proposal_mut.status = ProposalStatus::Launched;
        }
        self.counters.token_classes += 1;
        self.counters.finalized_launches += 1;
        Ok(proposal.token_class_id)
    }

    pub fn update_covenant_hook(&mut self, request: CovenantHookRequest) -> Result<String> {
        ensure_capacity(
            self.covenant_hooks.len(),
            self.config.max_covenant_hooks,
            "covenant hook capacity exhausted",
        )?;
        ensure(
            self.proposals.contains_key(&request.proposal_id),
            "proposal not found for covenant hook",
        )?;
        ensure_nonempty(&request.contract_commitment, "contract commitment required")?;
        let hook_id = covenant_hook_id(
            &request.token_class_id,
            request.hook_kind,
            &request.contract_commitment,
            &request.hook_root,
            request.activated_at_height,
        );
        ensure_unique(
            &self.deterministic_ids,
            &hook_id,
            "duplicate covenant hook id",
        )?;
        let hook = CovenantHook {
            hook_id: hook_id.clone(),
            token_class_id: request.token_class_id.clone(),
            proposal_id: request.proposal_id,
            hook_kind: request.hook_kind,
            contract_commitment: request.contract_commitment,
            hook_root: request.hook_root,
            compliance_circuit_root: request.compliance_circuit_root,
            covenant_policy_root: request.covenant_policy_root,
            jurisdiction_root: request.jurisdiction_root,
            privacy_budget_root: request.privacy_budget_root,
            activated_at_height: request.activated_at_height,
            expires_at_height: request.activated_at_height + self.config.covenant_ttl_blocks,
            active: true,
        };
        self.covenant_hooks.insert(hook_id.clone(), hook);
        self.token_hooks
            .entry(request.token_class_id.clone())
            .or_default()
            .insert(hook_id.clone());
        let token_hook_root = token_index_root(
            "TOKEN-COVENANT-HOOK-INDEX",
            &self.token_hooks,
            &request.token_class_id,
        );
        if let Some(token_class) = self.token_classes.get_mut(&request.token_class_id) {
            token_class.covenant_hook_root = token_hook_root;
        }
        self.deterministic_ids.insert(hook_id.clone());
        self.counters.covenant_hooks += 1;
        self.counters.amendments += 1;
        Ok(hook_id)
    }

    pub fn issue_fee_sponsorship(&mut self, request: FeeSponsorshipRequest) -> Result<String> {
        ensure_capacity(
            self.fee_sponsorships.len(),
            self.config.max_sponsorships,
            "fee sponsorship capacity exhausted",
        )?;
        let proposal = self
            .proposals
            .get(&request.proposal_id)
            .ok_or_else(|| "proposal not found".to_string())?;
        ensure(request.budget_micronero > 0, "sponsor budget required")?;
        ensure(
            request.reserved_micronero <= request.budget_micronero,
            "reserved fee exceeds budget",
        )?;
        ensure(
            request.max_rebate_bps <= self.config.max_launch_fee_bps,
            "rebate bps exceeds launch fee cap",
        )?;
        let sponsorship_id = sponsorship_id(
            &request.proposal_id,
            &request.sponsor_commitment,
            &request.low_fee_lane_root,
            request.opened_at_height,
        );
        ensure_unique(
            &self.deterministic_ids,
            &sponsorship_id,
            "duplicate sponsorship id",
        )?;
        let sponsorship = LaunchFeeSponsorship {
            sponsorship_id: sponsorship_id.clone(),
            proposal_id: request.proposal_id.clone(),
            token_class_id: proposal.token_class_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            status: SponsorshipStatus::Reserved,
            fee_asset_id: request.fee_asset_id,
            budget_micronero: request.budget_micronero,
            reserved_micronero: request.reserved_micronero,
            spent_micronero: 0,
            max_rebate_bps: request.max_rebate_bps,
            low_fee_lane_root: request.low_fee_lane_root,
            paymaster_policy_root: request.paymaster_policy_root,
            proof_rebate_root: request.proof_rebate_root,
            opened_at_height: request.opened_at_height,
            expires_at_height: request.opened_at_height + self.config.fee_sponsor_ttl_blocks,
        };
        self.fee_sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        self.token_sponsorships
            .entry(proposal.token_class_id.clone())
            .or_default()
            .insert(sponsorship_id.clone());
        self.deterministic_ids.insert(sponsorship_id.clone());
        self.counters.fee_sponsorships += 1;
        Ok(sponsorship_id)
    }

    pub fn schedule_treasury_timelock(
        &mut self,
        request: TreasuryTimelockRequest,
    ) -> Result<String> {
        ensure_capacity(
            self.treasury_timelocks.len(),
            self.config.max_treasury_timelocks,
            "treasury timelock capacity exhausted",
        )?;
        ensure(
            self.proposals.contains_key(&request.proposal_id),
            "proposal not found for treasury timelock",
        )?;
        let timelock_id = treasury_timelock_id(
            &request.token_class_id,
            &request.spend_commitment,
            &request.beneficiary_commitment,
            request.scheduled_at_height,
        );
        ensure_unique(
            &self.deterministic_ids,
            &timelock_id,
            "duplicate treasury timelock id",
        )?;
        let timelock = TreasuryTimelock {
            timelock_id: timelock_id.clone(),
            token_class_id: request.token_class_id.clone(),
            proposal_id: request.proposal_id,
            spend_commitment: request.spend_commitment,
            beneficiary_commitment: request.beneficiary_commitment,
            asset_id: request.asset_id,
            amount_commitment: request.amount_commitment,
            guard_root: request.guard_root,
            status: TimelockStatus::Scheduled,
            scheduled_at_height: request.scheduled_at_height,
            executable_at_height: request.scheduled_at_height
                + self.config.treasury_timelock_blocks,
            expires_at_height: request.scheduled_at_height + self.config.proposal_ttl_blocks,
            executed_at_height: None,
        };
        self.treasury_timelocks
            .insert(timelock_id.clone(), timelock);
        self.token_timelocks
            .entry(request.token_class_id)
            .or_default()
            .insert(timelock_id.clone());
        self.deterministic_ids.insert(timelock_id.clone());
        self.counters.treasury_timelocks += 1;
        Ok(timelock_id)
    }

    pub fn open_nullifier_fence(&mut self, request: NullifierFenceRequest) -> Result<String> {
        ensure_capacity(
            self.nullifier_fences.len(),
            self.config.max_nullifier_fences,
            "nullifier fence capacity exhausted",
        )?;
        ensure(
            self.proposals.contains_key(&request.proposal_id),
            "proposal not found for nullifier fence",
        )?;
        let fence_id = nullifier_fence_id(
            &request.token_class_id,
            &request.nullifier_domain,
            &request.nullifier_root,
            request.opened_at_height,
        );
        ensure_unique(
            &self.deterministic_ids,
            &fence_id,
            "duplicate nullifier fence id",
        )?;
        let fence = NullifierFence {
            fence_id: fence_id.clone(),
            token_class_id: request.token_class_id,
            proposal_id: request.proposal_id,
            nullifier_domain: request.nullifier_domain,
            nullifier_root: request.nullifier_root,
            spent_nullifier_count: request.spent_nullifier_count,
            guard_root: request.guard_root,
            opened_at_height: request.opened_at_height,
            expires_at_height: request.opened_at_height + self.config.nullifier_fence_ttl_blocks,
        };
        self.nullifier_fences.insert(fence_id.clone(), fence);
        self.deterministic_ids.insert(fence_id.clone());
        self.counters.nullifier_fences += 1;
        Ok(fence_id)
    }

    pub fn submit_slashing_evidence(&mut self, request: SlashingEvidenceRequest) -> Result<String> {
        ensure_capacity(
            self.slashing_evidence.len(),
            self.config.max_slashing_events,
            "slashing evidence capacity exhausted",
        )?;
        ensure(
            self.proposals.contains_key(&request.proposal_id),
            "proposal not found for slashing evidence",
        )?;
        let evidence_id = slashing_evidence_id(
            &request.proposal_id,
            request.reason,
            &request.accused_commitment,
            &request.evidence_root,
            request.submitted_at_height,
        );
        ensure_unique(
            &self.deterministic_ids,
            &evidence_id,
            "duplicate slashing evidence id",
        )?;
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            proposal_id: request.proposal_id.clone(),
            token_class_id: request.token_class_id,
            reason: request.reason,
            accused_commitment: request.accused_commitment,
            reporter_commitment: request.reporter_commitment,
            evidence_root: request.evidence_root,
            conflicting_transcript_root: request.conflicting_transcript_root,
            slash_amount_commitment: request.slash_amount_commitment,
            slashed_bps: request.slashed_bps,
            submitted_at_height: request.submitted_at_height,
            finalized_at_height: None,
        };
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        self.deterministic_ids.insert(evidence_id.clone());
        if let Some(proposal) = self.proposals.get_mut(&request.proposal_id) {
            proposal.status = ProposalStatus::Slashed;
        }
        self.counters.slashing_events += 1;
        Ok(evidence_id)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: payload_root("CONFIG", &self.config.public_record()),
            counters_root: payload_root("COUNTERS", &self.counters.public_record()),
            token_class_root: map_root("TOKEN-CLASSES", &self.token_classes),
            proposal_root: map_root("TOKEN-CLASS-PROPOSALS", &self.proposals),
            attestation_root: map_root("PQ-GOVERNANCE-ATTESTATIONS", &self.attestations),
            vote_commitment_root: map_root("SEALED-VOTE-COMMITMENTS", &self.vote_commitments),
            fee_sponsorship_root: map_root("LAUNCH-FEE-SPONSORSHIPS", &self.fee_sponsorships),
            covenant_hook_root: map_root("COVENANT-HOOKS", &self.covenant_hooks),
            treasury_timelock_root: map_root("TREASURY-TIMELOCKS", &self.treasury_timelocks),
            nullifier_fence_root: map_root("NULLIFIER-FENCES", &self.nullifier_fences),
            slashing_evidence_root: map_root("SLASHING-EVIDENCE", &self.slashing_evidence),
            integration_root: defi_integration_root(&self.proposals, &self.token_classes),
            mint_policy_root: policy_root("MINT-POLICY", &self.proposals, &self.token_classes),
            burn_policy_root: policy_root("BURN-POLICY", &self.proposals, &self.token_classes),
            deterministic_id_root: set_root("DETERMINISTIC-IDS", &self.deterministic_ids),
        }
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(values) = &mut record {
            values.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "token_classes": values_from_map(&self.token_classes),
            "proposals": values_from_map(&self.proposals),
            "attestations": values_from_map(&self.attestations),
            "vote_commitments": values_from_map(&self.vote_commitments),
            "fee_sponsorships": values_from_map(&self.fee_sponsorships),
            "covenant_hooks": values_from_map(&self.covenant_hooks),
            "treasury_timelocks": values_from_map(&self.treasury_timelocks),
            "nullifier_fences": values_from_map(&self.nullifier_fences),
            "slashing_evidence": values_from_map(&self.slashing_evidence),
            "proposal_attestations": indexed_sets_record(&self.proposal_attestations),
            "proposal_votes": indexed_sets_record(&self.proposal_votes),
            "token_hooks": indexed_sets_record(&self.token_hooks),
            "token_sponsorships": indexed_sets_record(&self.token_sponsorships),
            "token_timelocks": indexed_sets_record(&self.token_timelocks),
            "nullifier_index_root": set_root("NULLIFIER-INDEX", &self.nullifier_index),
        })
    }

    pub fn token_class_record(&self, token_class_id: &str) -> Option<Value> {
        self.token_classes
            .get(token_class_id)
            .map(TokenClass::public_record)
    }

    pub fn proposal_record(&self, proposal_id: &str) -> Option<Value> {
        self.proposals
            .get(proposal_id)
            .map(TokenClassProposal::public_record)
    }

    pub fn sponsorship_capacity_micronero(&self, token_class_id: &str) -> u64 {
        self.token_sponsorships
            .get(token_class_id)
            .into_iter()
            .flat_map(|ids| ids.iter())
            .filter_map(|id| self.fee_sponsorships.get(id))
            .filter(|sponsorship| {
                matches!(
                    sponsorship.status,
                    SponsorshipStatus::Offered
                        | SponsorshipStatus::Reserved
                        | SponsorshipStatus::PartiallyUsed
                )
            })
            .map(|sponsorship| {
                sponsorship
                    .budget_micronero
                    .saturating_sub(sponsorship.spent_micronero)
            })
            .sum()
    }

    pub fn proposal_vote_summary(&self, proposal_id: &str) -> Option<Value> {
        self.proposals.get(proposal_id).map(|proposal| {
            json!({
                "proposal_id": proposal.proposal_id,
                "token_class_id": proposal.token_class_id,
                "status": proposal.status.as_str(),
                "attestation_weight": proposal.attestation_weight,
                "yes_weight": proposal.yes_weight,
                "no_weight": proposal.no_weight,
                "abstain_weight": proposal.abstain_weight,
                "veto_weight": proposal.veto_weight,
                "required_attestation_weight": self.config.required_attestation_weight,
                "required_vote_weight": self.config.required_vote_weight,
            })
        })
    }

    fn validate_token_class_request(&self, request: &TokenClassProposalRequest) -> Result<()> {
        ensure(
            self.config
                .permitted_token_kinds
                .contains(&request.class_kind),
            "token class kind is not permitted",
        )?;
        ensure_nonempty(&request.proposer_commitment, "proposer commitment required")?;
        ensure_nonempty(&request.symbol_commitment, "symbol commitment required")?;
        ensure_nonempty(&request.metadata_root, "metadata root required")?;
        ensure_nonempty(&request.factory_salt_root, "factory salt root required")?;
        ensure(
            request.privacy.min_anonymity_set >= self.config.min_privacy_set_size,
            "privacy set is below runtime minimum",
        )?;
        ensure(
            request.pq_profile.security_bits >= self.config.min_pq_security_bits,
            "pq security bits below runtime minimum",
        )?;
        ensure(
            request.launch_fee_micronero <= self.config.max_factory_fee_micronero,
            "launch fee exceeds factory cap",
        )?;
        ensure(
            request.launch_fee_bps <= self.config.max_launch_fee_bps,
            "launch fee bps exceeds runtime cap",
        )?;
        ensure(
            request.defi.max_pool_fee_bps <= MAX_BPS,
            "pool fee bps out of range",
        )?;
        ensure(
            request.defi.max_leverage_bps <= 100_000,
            "leverage bps out of range",
        )?;
        Ok(())
    }

    fn refresh_proposal_status(&mut self, proposal_id: &str) {
        if let Some(proposal) = self.proposals.get_mut(proposal_id) {
            if proposal.veto_weight > 0 {
                proposal.status = ProposalStatus::Rejected;
            } else if proposal.attestation_weight >= self.config.required_attestation_weight
                && proposal.yes_weight >= self.config.required_vote_weight
                && proposal.yes_weight > proposal.no_weight
            {
                proposal.status = ProposalStatus::Approved;
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenClassProposalRequest {
    pub class_kind: TokenClassKind,
    pub action: GovernanceAction,
    pub proposer_commitment: String,
    pub symbol_commitment: String,
    pub metadata_root: String,
    pub factory_salt_root: String,
    pub supply_policy: ConfidentialSupplyPolicy,
    pub privacy: PrivacyParameters,
    pub pq_profile: QuantumResistanceProfile,
    pub defi: DefiIntegrationFlags,
    pub covenant_hook_root: String,
    pub treasury_policy_root: String,
    pub compliance_policy_root: String,
    pub launch_fee_micronero: u64,
    pub launch_fee_bps: u64,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GovernanceAttestationRequest {
    pub proposal_id: String,
    pub role: AttestationRole,
    pub signer_commitment: String,
    pub subject_root: String,
    pub transcript_root: String,
    pub pq_signature_root: String,
    pub verification_key_root: String,
    pub weight: u64,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub slashable: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedVoteRequest {
    pub proposal_id: String,
    pub voter_commitment: String,
    pub vote_direction: VoteDirection,
    pub sealed_ballot_root: String,
    pub nullifier_hash: String,
    pub voting_power_commitment: String,
    pub eligibility_proof_root: String,
    pub tally_share_root: String,
    pub pq_signature_root: String,
    pub weight: u64,
    pub committed_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsorshipRequest {
    pub proposal_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub budget_micronero: u64,
    pub reserved_micronero: u64,
    pub max_rebate_bps: u64,
    pub low_fee_lane_root: String,
    pub paymaster_policy_root: String,
    pub proof_rebate_root: String,
    pub opened_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CovenantHookRequest {
    pub proposal_id: String,
    pub token_class_id: String,
    pub hook_kind: HookKind,
    pub contract_commitment: String,
    pub hook_root: String,
    pub compliance_circuit_root: String,
    pub covenant_policy_root: String,
    pub jurisdiction_root: String,
    pub privacy_budget_root: String,
    pub activated_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TreasuryTimelockRequest {
    pub proposal_id: String,
    pub token_class_id: String,
    pub spend_commitment: String,
    pub beneficiary_commitment: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub guard_root: String,
    pub scheduled_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFenceRequest {
    pub proposal_id: String,
    pub token_class_id: String,
    pub nullifier_domain: String,
    pub nullifier_root: String,
    pub spent_nullifier_count: u64,
    pub guard_root: String,
    pub opened_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidenceRequest {
    pub proposal_id: String,
    pub token_class_id: String,
    pub reason: SlashingReason,
    pub accused_commitment: String,
    pub reporter_commitment: String,
    pub evidence_root: String,
    pub conflicting_transcript_root: String,
    pub slash_amount_commitment: String,
    pub slashed_bps: u64,
    pub submitted_at_height: u64,
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    let mut normalized = record.clone();
    if let Value::Object(values) = &mut normalized {
        values.remove("state_root");
    }
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-TOKEN-FACTORY-GOVERNANCE-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&normalized),
        ],
        32,
    )
}

pub fn token_class_id(
    class_kind: TokenClassKind,
    proposer_commitment: &str,
    symbol_commitment: &str,
    metadata_root: &str,
    factory_salt_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-CLASS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_kind.as_str()),
            HashPart::Str(proposer_commitment),
            HashPart::Str(symbol_commitment),
            HashPart::Str(metadata_root),
            HashPart::Str(factory_salt_root),
        ],
        32,
    )
}

pub fn proposal_id(
    token_class_id: &str,
    action: GovernanceAction,
    proposer_commitment: &str,
    created_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "TOKEN-FACTORY-GOVERNANCE-PROPOSAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(token_class_id),
            HashPart::Str(action.as_str()),
            HashPart::Str(proposer_commitment),
            HashPart::U64(created_at_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn attestation_id(
    proposal_id: &str,
    role: AttestationRole,
    signer_commitment: &str,
    transcript_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "PQ-GOVERNANCE-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proposal_id),
            HashPart::Str(role.as_str()),
            HashPart::Str(signer_commitment),
            HashPart::Str(transcript_root),
            HashPart::U64(signed_at_height),
        ],
        32,
    )
}

pub fn vote_id(
    proposal_id: &str,
    voter_commitment: &str,
    nullifier_hash: &str,
    committed_at_height: u64,
) -> String {
    domain_hash(
        "SEALED-GOVERNANCE-VOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proposal_id),
            HashPart::Str(voter_commitment),
            HashPart::Str(nullifier_hash),
            HashPart::U64(committed_at_height),
        ],
        32,
    )
}

pub fn sponsorship_id(
    proposal_id: &str,
    sponsor_commitment: &str,
    low_fee_lane_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "LAUNCH-FEE-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proposal_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(low_fee_lane_root),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn covenant_hook_id(
    token_class_id: &str,
    hook_kind: HookKind,
    contract_commitment: &str,
    hook_root: &str,
    activated_at_height: u64,
) -> String {
    domain_hash(
        "COVENANT-HOOK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(token_class_id),
            HashPart::Str(hook_kind.as_str()),
            HashPart::Str(contract_commitment),
            HashPart::Str(hook_root),
            HashPart::U64(activated_at_height),
        ],
        32,
    )
}

pub fn treasury_timelock_id(
    token_class_id: &str,
    spend_commitment: &str,
    beneficiary_commitment: &str,
    scheduled_at_height: u64,
) -> String {
    domain_hash(
        "TREASURY-TIMELOCK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(token_class_id),
            HashPart::Str(spend_commitment),
            HashPart::Str(beneficiary_commitment),
            HashPart::U64(scheduled_at_height),
        ],
        32,
    )
}

pub fn nullifier_fence_id(
    token_class_id: &str,
    nullifier_domain: &str,
    nullifier_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "NULLIFIER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(token_class_id),
            HashPart::Str(nullifier_domain),
            HashPart::Str(nullifier_root),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn slashing_evidence_id(
    proposal_id: &str,
    reason: SlashingReason,
    accused_commitment: &str,
    evidence_root: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proposal_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(accused_commitment),
            HashPart::Str(evidence_root),
            HashPart::U64(submitted_at_height),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("TOKEN-FACTORY-GOVERNANCE-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(value),
        ],
        32,
    )
}

pub fn launch_receipt_root(
    proposal_id: &str,
    token_class_id: &str,
    finalized_at_height: u64,
    proposal_root: &str,
) -> String {
    domain_hash(
        "TOKEN-LAUNCH-RECEIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proposal_id),
            HashPart::Str(token_class_id),
            HashPart::U64(finalized_at_height),
            HashPart::Str(proposal_root),
        ],
        32,
    )
}

pub fn deterministic_id(domain: &str, parts: &[&str]) -> String {
    let leaves = parts
        .iter()
        .map(|part| Value::String((*part).to_string()))
        .collect::<Vec<_>>();
    let parts_root = merkle_root(&format!("DETERMINISTIC-ID-{domain}"), &leaves);
    domain_hash(
        "TOKEN-FACTORY-DETERMINISTIC-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(&parts_root),
        ],
        32,
    )
}

fn map_root<T>(domain: &str, map: &BTreeMap<String, T>) -> String
where
    T: PublicRecord,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": value.public_record(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-PQ-TOKEN-FACTORY-GOVERNANCE-{domain}"),
        &leaves,
    )
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-PQ-TOKEN-FACTORY-GOVERNANCE-{domain}"),
        &leaves,
    )
}

fn indexed_sets_record(index: &BTreeMap<String, BTreeSet<String>>) -> Value {
    let entries = index
        .iter()
        .map(|(key, set)| {
            json!({
                "key": key,
                "ids": set.iter().cloned().collect::<Vec<_>>(),
                "root": set_root("INDEXED-SET", set),
            })
        })
        .collect::<Vec<_>>();
    Value::Array(entries)
}

fn token_index_root(
    domain: &str,
    index: &BTreeMap<String, BTreeSet<String>>,
    token_class_id: &str,
) -> String {
    index
        .get(token_class_id)
        .map(|set| set_root(domain, set))
        .unwrap_or_else(|| merkle_root(domain, &[]))
}

fn values_from_map<T>(map: &BTreeMap<String, T>) -> Vec<Value>
where
    T: PublicRecord,
{
    map.values().map(PublicRecord::public_record).collect()
}

fn defi_integration_root(
    proposals: &BTreeMap<String, TokenClassProposal>,
    token_classes: &BTreeMap<String, TokenClass>,
) -> String {
    let proposal_leaves = proposals.values().map(|proposal| {
        json!({
            "scope": "proposal",
            "token_class_id": proposal.token_class_id,
            "defi": proposal.defi.public_record(),
        })
    });
    let token_leaves = token_classes.values().map(|token| {
        json!({
            "scope": "token_class",
            "token_class_id": token.token_class_id,
            "defi": token.defi.public_record(),
        })
    });
    let leaves = proposal_leaves.chain(token_leaves).collect::<Vec<_>>();
    merkle_root("PRIVATE-L2-PQ-TOKEN-FACTORY-DEFI-INTEGRATIONS", &leaves)
}

fn policy_root(
    domain: &str,
    proposals: &BTreeMap<String, TokenClassProposal>,
    token_classes: &BTreeMap<String, TokenClass>,
) -> String {
    let proposal_leaves = proposals.values().map(|proposal| {
        let root = if domain == "MINT-POLICY" {
            &proposal.supply_policy.mint_policy_root
        } else {
            &proposal.supply_policy.burn_policy_root
        };
        json!({
            "scope": "proposal",
            "token_class_id": proposal.token_class_id,
            "policy_root": root,
        })
    });
    let token_leaves = token_classes.values().map(|token| {
        let root = if domain == "MINT-POLICY" {
            &token.supply_policy.mint_policy_root
        } else {
            &token.supply_policy.burn_policy_root
        };
        json!({
            "scope": "token_class",
            "token_class_id": token.token_class_id,
            "policy_root": root,
        })
    });
    let leaves = proposal_leaves.chain(token_leaves).collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-PQ-TOKEN-FACTORY-{domain}-ROOT"),
        &leaves,
    )
}

fn fixture_root(domain: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-TOKEN-FACTORY-DEVNET-FIXTURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}

fn devnet_supply_policy(label: &str) -> ConfidentialSupplyPolicy {
    ConfidentialSupplyPolicy {
        mint_policy_root: fixture_root("mint-policy", label),
        burn_policy_root: fixture_root("burn-policy", label),
        supply_cap_commitment: fixture_root("supply-cap", label),
        amount_range_proof_root: fixture_root("amount-range", label),
        authority_set_root: fixture_root("authority-set", label),
        conservation_circuit_root: fixture_root("conservation-circuit", label),
        hidden_decimals: 12,
        capped: true,
        burn_enabled: true,
        mint_requires_governance: true,
    }
}

fn devnet_privacy_parameters(label: &str) -> PrivacyParameters {
    PrivacyParameters {
        note_commitment_root: fixture_root("note-commitments", label),
        view_key_policy_root: fixture_root("view-key-policy", label),
        auditor_share_root: fixture_root("auditor-shares", label),
        nullifier_domain_root: fixture_root("nullifier-domain", label),
        decoy_distribution_root: fixture_root("decoy-distribution", label),
        min_anonymity_set: DEFAULT_MIN_PRIVACY_SET_SIZE,
        target_anonymity_set: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        encrypted_metadata: true,
        private_balances: true,
        private_governance: true,
    }
}

fn devnet_pq_profile(label: &str) -> QuantumResistanceProfile {
    QuantumResistanceProfile {
        kem_root: fixture_root("ml-kem-root", label),
        signature_root: fixture_root("ml-dsa-slh-dsa-root", label),
        transcript_root: fixture_root("pq-transcript", label),
        rotation_policy_root: fixture_root("pq-rotation-policy", label),
        recursive_aggregation_root: fixture_root("pq-recursive-aggregation", label),
        security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        hybrid_classic_binding: true,
        migration_ready: true,
    }
}

fn devnet_defi_flags(amm: bool, lending: bool, perps: bool) -> DefiIntegrationFlags {
    DefiIntegrationFlags {
        amm: if amm {
            IntegrationStatus::Guarded
        } else {
            IntegrationStatus::Disabled
        },
        stable_swap: IntegrationStatus::Requested,
        lending: if lending {
            IntegrationStatus::Guarded
        } else {
            IntegrationStatus::Disabled
        },
        perps: if perps {
            IntegrationStatus::Requested
        } else {
            IntegrationStatus::Disabled
        },
        vault_router: IntegrationStatus::Enabled,
        intent_solver: IntegrationStatus::Enabled,
        bridge_router: IntegrationStatus::Guarded,
        oracle_risk_root: fixture_root("oracle-risk", "devnet"),
        liquidity_guard_root: fixture_root("liquidity-guard", "devnet"),
        max_pool_fee_bps: 30,
        max_leverage_bps: 20_000,
    }
}

fn btree_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn ensure_capacity(current: usize, max: usize, message: &str) -> Result<()> {
    ensure(current < max, message)
}

fn ensure_unique(ids: &BTreeSet<String>, id: &str, message: &str) -> Result<()> {
    ensure(!ids.contains(id), message)
}

fn ensure_nonempty(value: &str, message: &str) -> Result<()> {
    ensure(!value.is_empty(), message)
}

fn saturating_add_bps(left: u64, right: u64) -> u64 {
    left.saturating_add(right).min(MAX_BPS)
}

fn identity_string() -> String {
    String::new()
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for TokenClassProposal {
    fn public_record(&self) -> Value {
        TokenClassProposal::public_record(self)
    }
}

impl PublicRecord for TokenClass {
    fn public_record(&self) -> Value {
        TokenClass::public_record(self)
    }
}

impl PublicRecord for PqGovernanceAttestation {
    fn public_record(&self) -> Value {
        PqGovernanceAttestation::public_record(self)
    }
}

impl PublicRecord for SealedVoteCommitment {
    fn public_record(&self) -> Value {
        SealedVoteCommitment::public_record(self)
    }
}

impl PublicRecord for LaunchFeeSponsorship {
    fn public_record(&self) -> Value {
        LaunchFeeSponsorship::public_record(self)
    }
}

impl PublicRecord for CovenantHook {
    fn public_record(&self) -> Value {
        CovenantHook::public_record(self)
    }
}

impl PublicRecord for TreasuryTimelock {
    fn public_record(&self) -> Value {
        TreasuryTimelock::public_record(self)
    }
}

impl PublicRecord for NullifierFence {
    fn public_record(&self) -> Value {
        NullifierFence::public_record(self)
    }
}

impl PublicRecord for SlashingEvidence {
    fn public_record(&self) -> Value {
        SlashingEvidence::public_record(self)
    }
}
